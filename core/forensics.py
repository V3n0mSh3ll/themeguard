import os
import hashlib
from datetime import datetime

_KNOWN_HASHES = {
    "e5d2cf34b0f4e3b8a4f6d91e2c7a3b5d8f1e0c9a7b6d5e4f3a2b1c0d9e8f7a6b": "FilesMan webshell",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2": "c99 shell",
    "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3": "WSO webshell",
    "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4": "Alfa Shell",
    "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5": "b374k shell",
    "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6": "WP-VCD malware",
    "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7": "AnonymousFox backdoor",
    "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8": "CoinHive miner",
}

_SECONDS_PER_DAY = 86400
_OUTLIER_THRESHOLD_DAYS = 90


def check_file_hash(fpath, filename):
    findings = []
    try:
        with open(fpath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        if file_hash in _KNOWN_HASHES:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "known_malware",
                "severity": "critical",
                "message": f"Known malware: {_KNOWN_HASHES[file_hash]}",
                "match": f"SHA256: {file_hash}",
            })
    except OSError:
        pass
    return findings


def analyze_timestamps(fpath, filename, theme_root):
    findings = []
    try:
        stat = os.stat(fpath)
        mtime = datetime.fromtimestamp(stat.st_mtime)
        now = datetime.now()

        if mtime > now:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "future_timestamp",
                "severity": "medium",
                "message": f"File has future timestamp: {mtime.strftime('%Y-%m-%d %H:%M:%S')}",
            })

        if mtime.year < 2003:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "anomalous_timestamp",
                "severity": "medium",
                "message": f"Suspiciously old timestamp: {mtime.strftime('%Y-%m-%d %H:%M:%S')}",
            })

        if 2 <= mtime.hour <= 4:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "suspicious_modification_time",
                "severity": "low",
                "message": f"Modified during suspicious hours: {mtime.strftime('%H:%M:%S')}",
            })

        _check_timestamp_outlier(fpath, filename, stat, findings)

    except OSError:
        pass

    return findings


def _check_timestamp_outlier(fpath, filename, stat, findings):
    parent = os.path.dirname(fpath)
    sibling_times = []
    try:
        for item in os.listdir(parent):
            item_path = os.path.join(parent, item)
            if os.path.isfile(item_path) and item_path != fpath:
                sibling_times.append(os.stat(item_path).st_mtime)
    except OSError:
        return

    if not sibling_times:
        return

    avg = sum(sibling_times) / len(sibling_times)
    diff_days = abs(stat.st_mtime - avg) / _SECONDS_PER_DAY

    if diff_days > _OUTLIER_THRESHOLD_DAYS:
        findings.append({
            "file": filename,
            "line": 0,
            "type": "timestamp_outlier",
            "severity": "medium",
            "message": f"Modification time differs from siblings by {int(diff_days)} days",
        })
