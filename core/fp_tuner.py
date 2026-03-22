import os
import json
import re
import time
import hashlib


_FP_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".fp_tuning")
_WHITELIST_FILE = os.path.join(_FP_DIR, "whitelist.json")
_SUPPRESSION_FILE = os.path.join(_FP_DIR, "suppressions.json")
_FEEDBACK_FILE = os.path.join(_FP_DIR, "feedback.json")

_KNOWN_SAFE = {
    "wp-includes/class-phpass.php",
    "wp-includes/SimplePie",
    "wp-includes/Requests",
    "wp-includes/sodium_compat",
    "wp-includes/ID3",
    "wp-admin/includes/class-pclzip.php",
    "wp-admin/includes/upgrade.php",
}

_KNOWN_SAFE_PATTERNS = [
    re.compile(r'vendor/'),
    re.compile(r'node_modules/'),
    re.compile(r'\.min\.js$'),
    re.compile(r'\.min\.css$'),
]

_CONFIDENCE_ADJUSTMENTS = {
    "missing_sanitization": -0.3,
    "session_no_secure": -0.2,
    "wpconfig_default_prefix": -0.2,
    "wpconfig_no_ssl_admin": -0.3,
}


def load_whitelist():
    if not os.path.isfile(_WHITELIST_FILE):
        return {"files": [], "rules": [], "hashes": []}
    for enc in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            with open(_WHITELIST_FILE, "r", encoding=enc) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            continue
    return {"files": [], "rules": [], "hashes": []}


def save_whitelist(data):
    os.makedirs(_FP_DIR, exist_ok=True)
    with open(_WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def add_to_whitelist(entry_type, value):
    wl = load_whitelist()
    key = entry_type + "s"
    if key not in wl:
        wl[key] = []
    if value not in wl[key]:
        wl[key].append(value)
        save_whitelist(wl)
    return True


def load_suppressions():
    if not os.path.isfile(_SUPPRESSION_FILE):
        return {}
    for enc in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            with open(_SUPPRESSION_FILE, "r", encoding=enc) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            continue
    return {}


def suppress_rule(rule_type, reason="user_suppressed"):
    supps = load_suppressions()
    supps[rule_type] = {
        "reason": reason,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    os.makedirs(_FP_DIR, exist_ok=True)
    with open(_SUPPRESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(supps, f, indent=2)


def record_feedback(finding, is_fp):
    fb = []
    if os.path.isfile(_FEEDBACK_FILE):
        try:
            with open(_FEEDBACK_FILE, "r", encoding="utf-8") as f:
                fb = json.load(f)
        except (json.JSONDecodeError, OSError):
            fb = []

    fb.append({
        "type": finding.get("type", ""),
        "file": finding.get("file", ""),
        "is_false_positive": is_fp,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "message": finding.get("message", "")[:200],
    })

    os.makedirs(_FP_DIR, exist_ok=True)
    with open(_FEEDBACK_FILE, "w", encoding="utf-8") as f:
        json.dump(fb[-500:], f, indent=2)


def get_fp_rate(rule_type):
    if not os.path.isfile(_FEEDBACK_FILE):
        return 0.0
    fb = []
    for enc in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            with open(_FEEDBACK_FILE, "r", encoding=enc) as f:
                fb = json.load(f)
            break
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            continue
    if not fb:
        return 0.0

    relevant = [e for e in fb if e.get("type") == rule_type]
    if not relevant:
        return 0.0

    fps = sum(1 for e in relevant if e.get("is_false_positive"))
    return fps / len(relevant)


def filter_findings(findings):
    wl = load_whitelist()
    supps = load_suppressions()
    filtered = []

    wl_files = set(wl.get("files", []))
    wl_rules = set(wl.get("rules", []))
    wl_hashes = set(wl.get("hashes", []))

    for f in findings:
        ftype = f.get("type", "")
        ffile = f.get("file", "")

        if ftype in supps:
            continue

        if ffile in wl_files:
            continue

        if ftype in wl_rules:
            continue

        fhash = hashlib.md5(f.get("message", "").encode()).hexdigest()
        if fhash in wl_hashes:
            continue

        if _is_known_safe(ffile):
            if f.get("severity") not in ("critical",):
                continue

        adjustment = _CONFIDENCE_ADJUSTMENTS.get(ftype, 0.0)
        if adjustment != 0.0:
            original_sev = f.get("severity", "medium")
            if adjustment <= -0.3 and original_sev == "medium":
                f = dict(f)
                f["severity"] = "low"

        fp_rate = get_fp_rate(ftype)
        if fp_rate > 0.6:
            f = dict(f)
            f["severity"] = "low"
            f["message"] = f.get("message", "") + f" [FP rate: {fp_rate:.0%}]"

        filtered.append(f)

    return filtered


def _is_known_safe(filepath):
    norm = filepath.replace("\\", "/")

    for safe in _KNOWN_SAFE:
        if safe in norm:
            return True

    for pat in _KNOWN_SAFE_PATTERNS:
        if pat.search(norm):
            return True

    return False
