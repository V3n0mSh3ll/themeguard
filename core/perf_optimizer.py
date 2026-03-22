import os
import json
import hashlib
import time
import mmap

_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".scan_cache")


def load_scan_cache():
    cache_file = os.path.join(_CACHE_DIR, "file_hashes.json")
    if not os.path.isfile(cache_file):
        return {}
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_scan_cache(cache):
    os.makedirs(_CACHE_DIR, exist_ok=True)
    cache_file = os.path.join(_CACHE_DIR, "file_hashes.json")
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except OSError:
        pass


def should_skip_file(fpath, cache):
    try:
        st = os.stat(fpath)
        key = f"{fpath}|{st.st_size}|{st.st_mtime}"
        content_hash = hashlib.md5(key.encode()).hexdigest()
        return content_hash in cache, content_hash
    except OSError:
        return False, ""


def mark_file_scanned(content_hash, cache, had_findings):
    cache[content_hash] = {
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "clean": not had_findings,
    }


def read_file_fast(fpath, max_size=2097152):
    try:
        file_size = os.path.getsize(fpath)
    except OSError:
        return None

    if file_size == 0:
        return ""

    if file_size > max_size:
        return None

    if file_size > 65536:
        try:
            with open(fpath, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    raw = mm[:]
                    return raw.decode("utf-8", errors="ignore")
        except (OSError, ValueError):
            pass

    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return None


def prefilter_files(file_list, scan_path):
    prioritized = []
    deferred = []

    high_risk_names = {
        ".htaccess", "wp-config.php", "functions.php", "admin-ajax.php",
        "wp-login.php", "wp-settings.php",
    }

    high_risk_dirs = {"uploads", "mu-plugins", "drop-ins"}

    binary_exts = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".svg",
        ".zip", ".gz", ".tar", ".rar",
        ".mp3", ".mp4", ".avi", ".mov",
        ".pdf", ".doc", ".docx", ".xls",
    }

    for fpath in file_list:
        fname = os.path.basename(fpath).lower()
        ext = os.path.splitext(fname)[1]

        if ext in binary_exts:
            continue

        rel = os.path.relpath(fpath, scan_path).lower()

        if fname in high_risk_names:
            prioritized.insert(0, fpath)
        elif any(d in rel for d in high_risk_dirs):
            prioritized.append(fpath)
        else:
            deferred.append(fpath)

    return prioritized + deferred


def get_performance_stats(scan_time, files_scanned, findings_count):
    throughput = files_scanned / max(0.01, scan_time)
    findings_rate = findings_count / max(1, files_scanned)

    return {
        "scan_time_seconds": round(scan_time, 2),
        "files_scanned": files_scanned,
        "files_per_second": round(throughput, 1),
        "findings_count": findings_count,
        "findings_per_file": round(findings_rate, 3),
        "estimated_1k_files": round(1000 / max(0.1, throughput), 1),
    }
