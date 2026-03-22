import os
import json

_RC_FILENAME = ".themeguardrc"

_DEFAULTS = {
    "whitelist_paths": [],
    "whitelist_hashes": [],
    "severity_threshold": "low",
    "custom_signatures": [],
    "quarantine_enabled": False,
    "quarantine_threshold": "high",
    "watch_interval": 5,
    "network_enabled": False,
    "max_file_size_mb": 10,
    "thread_pool_size": 8,
}


def load_config(scan_path=None):
    config = dict(_DEFAULTS)

    paths = [
        os.path.join(scan_path, _RC_FILENAME) if scan_path else None,
        os.path.join(os.path.expanduser("~"), _RC_FILENAME),
    ]

    for path in paths:
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    user_config = json.load(f)
                config.update(user_config)
                config["_loaded_from"] = path
                return config
            except (json.JSONDecodeError, OSError):
                continue

    return config


def create_default_config(directory):
    fpath = os.path.join(directory, _RC_FILENAME)
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(_DEFAULTS, f, indent=2)
    return fpath


def is_whitelisted(rel_path, file_hash, config):
    if rel_path in config.get("whitelist_paths", []):
        return True
    if file_hash and file_hash in config.get("whitelist_hashes", []):
        return True
    return False


def meets_severity(severity, threshold):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(severity, 3) <= order.get(threshold, 3)
