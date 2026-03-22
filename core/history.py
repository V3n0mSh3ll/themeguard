import os
import json
from datetime import datetime

_HISTORY_DIR = ".themeguard_history"


def save_scan(results, scan_path):
    history_dir = os.path.join(scan_path, _HISTORY_DIR)
    os.makedirs(history_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"scan_{timestamp}.json"
    fpath = os.path.join(history_dir, fname)

    record = {
        "timestamp": datetime.now().isoformat(),
        "target": results.get("target", ""),
        "files_scanned": results.get("files_scanned", 0),
        "total_findings": results.get("total_findings", 0),
        "severity_counts": results.get("severity_counts", {}),
        "finding_keys": _extract_keys(results.get("findings", [])),
    }

    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return fpath


def compare_scans(results, scan_path):
    previous = _load_latest(scan_path)
    if not previous:
        return None

    prev_keys = set(previous.get("finding_keys", []))
    curr_keys = set(_extract_keys(results.get("findings", [])))

    new_threats = curr_keys - prev_keys
    resolved = prev_keys - curr_keys
    unchanged = curr_keys & prev_keys

    return {
        "previous_scan": previous.get("timestamp", "unknown"),
        "new_threats": len(new_threats),
        "resolved": len(resolved),
        "unchanged": len(unchanged),
        "new_details": list(new_threats),
        "resolved_details": list(resolved),
    }


def list_scans(scan_path):
    history_dir = os.path.join(scan_path, _HISTORY_DIR)
    if not os.path.isdir(history_dir):
        return []

    scans = []
    for fname in sorted(os.listdir(history_dir), reverse=True):
        if not fname.startswith("scan_") or not fname.endswith(".json"):
            continue
        fpath = os.path.join(history_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            scans.append({
                "file": fname,
                "timestamp": data.get("timestamp", ""),
                "findings": data.get("total_findings", 0),
            })
        except (json.JSONDecodeError, OSError):
            continue
    return scans


def _load_latest(scan_path):
    history_dir = os.path.join(scan_path, _HISTORY_DIR)
    if not os.path.isdir(history_dir):
        return None

    files = sorted(
        [f for f in os.listdir(history_dir) if f.startswith("scan_") and f.endswith(".json")],
        reverse=True,
    )
    if not files:
        return None

    try:
        with open(os.path.join(history_dir, files[0]), "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _extract_keys(findings):
    keys = []
    for f in findings:
        key = f"{f.get('file', '')}:{f.get('type', '')}:{f.get('line', 0)}"
        keys.append(key)
    return keys
