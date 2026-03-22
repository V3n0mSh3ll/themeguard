import os
import json
import shutil
import hashlib
import time
from datetime import datetime

_MANIFEST_FILE = "manifest.json"
_AUDIT_FILE = "audit_trail.json"


def quarantine_files(findings, scan_path, quarantine_dir, threshold="high"):
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_rank = sev_rank.get(threshold, 1)
    moved = []

    targets = set()
    for f in findings:
        rank = sev_rank.get(f.get("severity", "low"), 3)
        if rank <= min_rank and f.get("file"):
            targets.add(f["file"])

    if not targets:
        return moved

    os.makedirs(quarantine_dir, exist_ok=True)
    manifest = _load_manifest(quarantine_dir)

    for rel_path in targets:
        src = os.path.join(scan_path, rel_path)
        if not os.path.isfile(src):
            continue

        dest_dir = os.path.join(quarantine_dir, os.path.dirname(rel_path))
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(quarantine_dir, rel_path)

        file_hash = _sha256(src)
        try:
            shutil.move(src, dest)
        except OSError:
            continue

        entry = {
            "original_path": src,
            "quarantine_path": dest,
            "relative_path": rel_path,
            "sha256": file_hash,
            "timestamp": datetime.now().isoformat(),
            "status": "quarantined",
            "reasons": [f.get("message", "") for f in findings if f.get("file") == rel_path],
        }
        manifest.append(entry)
        moved.append(entry)
        _audit_log(quarantine_dir, "quarantine", rel_path, file_hash)

    _save_manifest(quarantine_dir, manifest)
    return moved


def restore_files(quarantine_dir, rel_path=None):
    manifest = _load_manifest(quarantine_dir)
    restored = []

    for entry in list(manifest):
        if rel_path and entry.get("relative_path") != rel_path:
            continue

        src = entry.get("quarantine_path", "")
        dest = entry.get("original_path", "")

        if not os.path.isfile(src):
            continue

        current_hash = _sha256(src)
        original_hash = entry.get("sha256", "")
        if original_hash and current_hash != original_hash:
            entry["status"] = "tampered"
            entry["tamper_detected"] = datetime.now().isoformat()
            _audit_log(quarantine_dir, "tamper_detected", entry.get("relative_path", ""), current_hash)
            continue

        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            shutil.move(src, dest)
            entry["status"] = "restored"
            entry["restored_at"] = datetime.now().isoformat()
            manifest.remove(entry)
            restored.append(entry)
            _audit_log(quarantine_dir, "restore", entry.get("relative_path", ""), original_hash)
        except OSError:
            continue

    _save_manifest(quarantine_dir, manifest)
    return restored


def list_quarantined(quarantine_dir):
    return _load_manifest(quarantine_dir)


def _load_manifest(quarantine_dir):
    path = os.path.join(quarantine_dir, _MANIFEST_FILE)
    if not os.path.isfile(path):
        return []
    for enc in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            with open(path, "r", encoding=enc) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeError):
            continue
    return []


def _save_manifest(quarantine_dir, manifest):
    path = os.path.join(quarantine_dir, _MANIFEST_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)


def _sha256(fpath):
    sha = hashlib.sha256()
    try:
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except OSError:
        return ""


def _audit_log(quarantine_dir, action, filepath, file_hash):
    path = os.path.join(quarantine_dir, _AUDIT_FILE)
    trail = []
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                trail = json.load(f)
        except (json.JSONDecodeError, OSError):
            trail = []

    trail.append({
        "action": action,
        "file": filepath,
        "sha256": file_hash,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    })

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(trail[-1000:], f, indent=2)
    except OSError:
        pass


def get_audit_trail(quarantine_dir):
    path = os.path.join(quarantine_dir, _AUDIT_FILE)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
