_SEV_WEIGHTS = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.15}

_SIGNAL_WEIGHTS = {
    "eval_sink": 0.20,
    "exec_sink": 0.20,
    "base64_decode": 0.15,
    "network_callback": 0.20,
    "file_write": 0.15,
    "obfuscation": 0.12,
    "known_bad_domain": 0.30,
    "user_input_flow": 0.18,
    "dynamic_dispatch": 0.16,
    "error_suppression": 0.10,
    "reflection_abuse": 0.18,
    "dead_code": 0.15,
    "polyglot": 0.25,
    "c2_beacon": 0.28,
    "malware_family": 0.35,
}

_PENALTY = {
    "vendor_path": -0.20,
    "minified_js": -0.18,
    "well_commented": -0.08,
    "known_safe_path": -0.25,
    "low_evidence": -0.10,
}

_TYPE_TO_SIGNAL = {
    "taint_flow": "user_input_flow",
    "concat_obfuscation": "obfuscation",
    "dynamic_function_dispatch": "dynamic_dispatch",
    "xss_unescaped_output": "user_input_flow",
    "indirect_danger_chain": "eval_sink",
    "dead_code_backdoor": "dead_code",
    "error_suppressed_danger": "error_suppression",
    "reflection_abuse": "reflection_abuse",
    "polyglot_php_in_image": "polyglot",
    "c2_data_exfiltration": "c2_beacon",
    "c2_beacon": "c2_beacon",
    "cloud_url_malicious": "known_bad_domain",
    "cloud_hash_known_malware": "known_bad_domain",
    "ml_malicious": "obfuscation",
    "ml_suspicious": "obfuscation",
}


def score_finding(finding, file_context=None):
    finding = dict(finding)
    ftype = finding.get("type", "")
    severity = finding.get("severity", "medium")

    base = _SEV_WEIGHTS.get(severity, 0.4)

    signal = _TYPE_TO_SIGNAL.get(ftype, "")
    signal_boost = _SIGNAL_WEIGHTS.get(signal, 0.0)

    evidence = finding.get("evidence_count", 1)
    evidence_factor = min(1.0, 0.5 + (evidence * 0.1))

    penalty = 0.0
    fpath = finding.get("file", "")
    if "vendor/" in fpath or "node_modules/" in fpath:
        penalty += _PENALTY["vendor_path"]
    if fpath.endswith(".min.js"):
        penalty += _PENALTY["minified_js"]
    if evidence < 2 and severity not in ("critical",):
        penalty += _PENALTY["low_evidence"]

    confidence = min(1.0, max(0.0, base + signal_boost * evidence_factor + penalty))

    finding["confidence"] = round(confidence, 2)

    if confidence >= 0.85:
        finding["action"] = "quarantine"
    elif confidence >= 0.60:
        finding["action"] = "review"
    elif confidence >= 0.35:
        finding["action"] = "inspect"
    else:
        finding["action"] = "info"

    return finding


def score_file_bundle(findings):
    if not findings:
        return 0.0

    total = 0.0
    for f in findings:
        conf = f.get("confidence", 0.5)
        sev_w = _SEV_WEIGHTS.get(f.get("severity", "medium"), 0.4)
        total += conf * sev_w

    score = min(100.0, total * 20)
    return round(score, 1)
