import os
import json
import re
import time


_SUPP_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_SUPP_FILE = os.path.join(_SUPP_DIR, "suppressions.json")
_ALLOW_FILE = os.path.join(_SUPP_DIR, "allowlists.json")


def load_suppressions():
    return _load_json(_SUPP_FILE, [])


def load_allowlists():
    return _load_json(_ALLOW_FILE, {"paths": [], "hashes": [], "rules": []})


def add_suppression(rule_id, path_contains="", reason=""):
    supps = load_suppressions()
    supps.append({
        "rule_id": rule_id,
        "path_contains": path_contains,
        "reason": reason,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    _save_json(_SUPP_FILE, supps)


def add_allowlist_entry(entry_type, value):
    al = load_allowlists()
    key = entry_type + "s" if not entry_type.endswith("s") else entry_type
    if key not in al:
        al[key] = []
    if value not in al[key]:
        al[key].append(value)
    _save_json(_ALLOW_FILE, al)


def apply_suppressions(findings):
    supps = load_suppressions()
    allows = load_allowlists()

    if not supps and not allows.get("paths") and not allows.get("rules"):
        return findings

    al_paths = set(allows.get("paths", []))
    al_rules = set(allows.get("rules", []))

    result = []
    suppressed_count = 0

    for f in findings:
        ftype = f.get("type", "")
        fpath = f.get("file", "").replace("\\", "/")

        if fpath in al_paths:
            suppressed_count += 1
            continue

        if ftype in al_rules:
            suppressed_count += 1
            continue

        matched = False
        for s in supps:
            rule_match = not s.get("rule_id") or s["rule_id"] == ftype
            path_match = not s.get("path_contains") or s["path_contains"] in fpath
            if rule_match and path_match:
                matched = True
                break

        if matched:
            suppressed_count += 1
            continue

        result.append(f)

    return result


def _load_json(path, default):
    if not os.path.isfile(path):
        return default
    for enc in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            with open(path, "r", encoding=enc) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            continue
    return default


def _save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
