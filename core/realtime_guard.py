import os
import time
import stat
import json
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor


_DAEMON_PID_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".themeguard_daemon.pid")
_BLOCK_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".block_log.json")


class RealtimeGuard:

    def __init__(self, scan_path, scanner_factory, interval=2, auto_block=True, severity_threshold="critical"):
        self.scan_path = os.path.abspath(scan_path)
        self.scanner_factory = scanner_factory
        self.interval = interval
        self.auto_block = auto_block
        self.severity_threshold = severity_threshold
        self._running = False
        self._snapshots = {}
        self._blocked = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=4)
        self._block_log = []

    def start(self):
        self._running = True
        self._snapshots = self._snapshot()
        self._write_pid()
        print(f"[DAEMON] Real-time protection active on: {self.scan_path}")
        print(f"[DAEMON] Auto-block: {'ON' if self.auto_block else 'OFF'} | Threshold: {self.severity_threshold}")
        print(f"[DAEMON] Poll interval: {self.interval}s | Press Ctrl+C to stop")
        print()

        try:
            while self._running:
                current = self._snapshot()
                changed = self._diff(self._snapshots, current)

                if changed["created"] or changed["modified"]:
                    all_changed = changed["created"] + changed["modified"]
                    futures = []
                    for fpath in all_changed:
                        futures.append(self._pool.submit(self._scan_single, fpath))

                    for future in futures:
                        try:
                            findings = future.result(timeout=30)
                            if findings:
                                self._handle_findings(findings)
                        except Exception:
                            pass

                for fpath in changed["deleted"]:
                    rel = os.path.relpath(fpath, self.scan_path)
                    print(f"[DAEMON] File deleted: {rel}")

                self._snapshots = current
                time.sleep(self.interval)

        except KeyboardInterrupt:
            print("\n[DAEMON] Shutting down...")
        finally:
            self._running = False
            self._pool.shutdown(wait=False)
            self._remove_pid()

    def stop(self):
        self._running = False

    def _scan_single(self, fpath):
        if not fpath.endswith((".php", ".js", ".html", ".htm", ".phtml", ".inc")):
            return []

        rel = os.path.relpath(fpath, self.scan_path)
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            return []

        if not content.strip():
            return []

        scanner = self.scanner_factory(self.scan_path)
        return scanner._scan_file(fpath)

    def _handle_findings(self, findings):
        sev_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        threshold_val = sev_levels.get(self.severity_threshold, 3)

        for f in findings:
            sev = f.get("severity", "medium")
            sev_val = sev_levels.get(sev, 2)
            fpath = os.path.join(self.scan_path, f.get("file", ""))

            prefix = f"[{sev.upper()}]"
            print(f"  {prefix} {f.get('message', '')} ({f.get('file', '')}:{f.get('line', 0)})")

            if self.auto_block and sev_val >= threshold_val and os.path.isfile(fpath):
                self._block_file(fpath, f)

    def _block_file(self, fpath, finding):
        with self._lock:
            if fpath in self._blocked:
                return

            try:
                current_mode = os.stat(fpath).st_mode
                os.chmod(fpath, stat.S_IRUSR | stat.S_IRGRP)
                self._blocked.add(fpath)

                rel = os.path.relpath(fpath, self.scan_path)
                print(f"  [BLOCKED] {rel} (permissions set to read-only)")

                entry = {
                    "file": rel,
                    "original_mode": oct(current_mode),
                    "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "reason": finding.get("message", "")[:200],
                    "severity": finding.get("severity", ""),
                    "type": finding.get("type", ""),
                }
                self._block_log.append(entry)
                self._save_block_log()

            except OSError as e:
                print(f"  [WARN] Cannot block {fpath}: {e}")

    def unblock_file(self, filepath):
        fpath = os.path.join(self.scan_path, filepath)
        if fpath not in self._blocked:
            return False

        log_entry = None
        for entry in self._block_log:
            if entry["file"] == filepath:
                log_entry = entry
                break

        if log_entry:
            try:
                original = int(log_entry["original_mode"], 8)
                os.chmod(fpath, original)
            except (ValueError, OSError):
                os.chmod(fpath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        self._blocked.discard(fpath)
        print(f"  [UNBLOCKED] {filepath}")
        return True

    def get_blocked_files(self):
        return list(self._block_log)

    def _snapshot(self):
        snap = {}
        for root, _, files in os.walk(self.scan_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    st = os.stat(fpath)
                    snap[fpath] = {
                        "mtime": st.st_mtime,
                        "size": st.st_size,
                    }
                except OSError:
                    continue
        return snap

    def _diff(self, old, new):
        old_keys = set(old.keys())
        new_keys = set(new.keys())

        created = [k for k in new_keys - old_keys]
        deleted = [k for k in old_keys - new_keys]
        modified = []

        for k in old_keys & new_keys:
            if old[k]["mtime"] != new[k]["mtime"] or old[k]["size"] != new[k]["size"]:
                modified.append(k)

        return {"created": created, "deleted": deleted, "modified": modified}

    def _write_pid(self):
        try:
            with open(_DAEMON_PID_FILE, "w") as f:
                f.write(str(os.getpid()))
        except OSError:
            pass

    def _remove_pid(self):
        try:
            if os.path.isfile(_DAEMON_PID_FILE):
                os.remove(_DAEMON_PID_FILE)
        except OSError:
            pass

    def _save_block_log(self):
        try:
            with open(_BLOCK_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(self._block_log, f, indent=2)
        except OSError:
            pass
