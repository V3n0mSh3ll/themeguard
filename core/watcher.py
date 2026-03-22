import os
import time
import hashlib
import logging
from datetime import datetime
from collections import defaultdict

from core.scanner import Scanner
from utils.colors import info, bold, red, green, yellow, cyan

_log = logging.getLogger("themeguard.watcher")

_IGNORE_DIRS = {".git", "node_modules", ".scan_cache", "__pycache__", ".svn"}
_IGNORE_EXTS = {".map", ".lock", ".log"}


def watch(scan_path, interval=5, verbosity=1, scan_type="theme", auto_quarantine=False):
    state = _snapshot(scan_path)
    debounce = _Debouncer(cooldown=3.0)
    storm_guard = _StormGuard(max_events=50, window=10.0)
    error_count = 0
    max_errors = 20

    print(info(f"Watch mode active on: {bold(scan_path)}"))
    print(info(f"Polling every {interval}s | Debounce: 3s | Storm limit: 50/10s"))
    print(info(f"Auto-quarantine: {'ON' if auto_quarantine else 'OFF'}"))
    print(info("Press Ctrl+C to stop"))
    print()

    try:
        while True:
            time.sleep(interval)

            try:
                current = _snapshot(scan_path)
            except Exception as exc:
                error_count += 1
                _log.warning("Snapshot error (#%d): %s", error_count, exc)
                if error_count >= max_errors:
                    print(red(f"  [!] Too many errors ({max_errors}), stopping watch mode"))
                    break
                continue

            changes = _diff_state(state, current)

            if not changes:
                continue

            if storm_guard.is_storm(len(changes)):
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"  {yellow(f'[{ts}]')} {red('STORM')} {len(changes)} changes detected, throttling...")
                state = current
                continue

            ts = datetime.now().strftime("%H:%M:%S")
            for change_type, rel_path in changes:
                if change_type == "new":
                    print(f"  {yellow(f'[{ts}]')} {green('NEW')}      {rel_path}")
                elif change_type == "modified":
                    print(f"  {yellow(f'[{ts}]')} {cyan('MODIFIED')} {rel_path}")
                elif change_type == "deleted":
                    print(f"  {yellow(f'[{ts}]')} {red('DELETED')}  {rel_path}")

            modified_files = []
            for ct, rel in changes:
                if ct in ("new", "modified"):
                    fpath = os.path.join(scan_path, rel)
                    if debounce.should_process(fpath):
                        modified_files.append(fpath)

            if modified_files:
                print(f"  {yellow(f'[{ts}]')} Scanning {len(modified_files)} changed file(s)...")
                try:
                    scanner = Scanner(scan_path, verbosity=0, scan_type=scan_type)
                    all_hits = []
                    for fpath in modified_files:
                        try:
                            hits = scanner._scan_file(fpath)
                            if hits:
                                all_hits.extend(hits)
                                if verbosity > 0:
                                    for h in hits:
                                        scanner._print_finding(h)
                        except Exception as exc:
                            _log.warning("Scan error on %s: %s", fpath, exc)

                    if all_hits and auto_quarantine:
                        critical_hits = [h for h in all_hits if h.get("severity") == "critical"]
                        if critical_hits:
                            print(f"  {red('[!]')} {len(critical_hits)} critical findings, quarantine recommended")

                except Exception as exc:
                    error_count += 1
                    _log.warning("Scanner error (#%d): %s", error_count, exc)

                print()

            state = current
            error_count = max(0, error_count - 1)

    except KeyboardInterrupt:
        print(f"\n  {info('Watch mode stopped.')}\n")


def _snapshot(scan_path):
    state = {}
    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _IGNORE_EXTS:
                continue

            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, scan_path)
            try:
                stat = os.stat(fpath)
                state[rel] = {
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "hash": _quick_hash(fpath),
                }
            except OSError:
                continue
    return state


def _diff_state(old, new):
    changes = []
    for rel in sorted(new):
        if rel not in old:
            changes.append(("new", rel))
        elif new[rel]["hash"] != old[rel]["hash"]:
            changes.append(("modified", rel))

    for rel in sorted(old):
        if rel not in new:
            changes.append(("deleted", rel))

    return changes


def _quick_hash(fpath):
    h = hashlib.md5()
    try:
        with open(fpath, "rb") as f:
            h.update(f.read(65536))
        return h.hexdigest()
    except OSError:
        return ""


class _Debouncer:

    def __init__(self, cooldown=3.0):
        self.cooldown = cooldown
        self._last_seen = {}

    def should_process(self, fpath):
        now = time.time()
        last = self._last_seen.get(fpath, 0)
        if now - last < self.cooldown:
            return False
        self._last_seen[fpath] = now
        return True


class _StormGuard:

    def __init__(self, max_events=50, window=10.0):
        self.max_events = max_events
        self.window = window
        self._events = []

    def is_storm(self, count):
        now = time.time()
        self._events = [(t, c) for t, c in self._events if now - t < self.window]
        self._events.append((now, count))
        total = sum(c for _, c in self._events)
        return total > self.max_events
