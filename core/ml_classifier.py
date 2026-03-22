import re
import math
from collections import Counter


def ml_classify(content, filename):
    features = _extract_features(content)
    score, verdict, breakdown = _decision_model(features)
    findings = []

    if verdict == "malicious":
        findings.append({
            "file": filename,
            "line": 0,
            "type": "ml_malicious",
            "severity": "critical",
            "message": f"ML classifier: MALICIOUS ({score:.0f}%) - {_top_reasons(breakdown, 3)}",
        })
    elif verdict == "suspicious":
        findings.append({
            "file": filename,
            "line": 0,
            "type": "ml_suspicious",
            "severity": "high",
            "message": f"ML classifier: SUSPICIOUS ({score:.0f}%) - {_top_reasons(breakdown, 2)}",
        })

    return findings


def _extract_features(content):
    length = len(content)
    lines = content.split("\n")
    line_count = len(lines)

    char_freq = Counter(content)
    total_chars = max(1, length)

    alpha = sum(1 for c in content if c.isalpha())
    digits = sum(1 for c in content if c.isdigit())
    specials = sum(1 for c in content if not c.isalnum() and not c.isspace())
    whitespace = sum(1 for c in content if c.isspace())

    avg_line_len = length / max(1, line_count)
    max_line_len = max((len(l) for l in lines), default=0)
    long_lines = sum(1 for l in lines if len(l) > 500)

    entropy = _shannon(content)
    printable_ratio = sum(1 for c in content if 32 <= ord(c) <= 126) / max(1, total_chars)

    funcs_eval = len(re.findall(r'\b(eval|assert)\s*\(', content, re.I))
    funcs_exec = len(re.findall(r'\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(', content, re.I))
    funcs_encode = len(re.findall(r'\b(base64_decode|base64_encode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(', content, re.I))
    funcs_file = len(re.findall(r'\b(file_put_contents|fwrite|fopen|file_get_contents|curl_exec)\s*\(', content, re.I))
    funcs_dynamic = len(re.findall(r'\$\w+\s*\(', content))
    funcs_total = len(re.findall(r'\b\w+\s*\(', content))

    user_input = len(re.findall(r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[', content))
    string_concats = content.count(".")
    chr_calls = len(re.findall(r'\bchr\s*\(\s*\d+\s*\)', content))
    hex_strings = len(re.findall(r'\\x[0-9a-fA-F]{2}', content))
    long_strings = len(re.findall(r'["\'][^"\']{200,}["\']', content))

    comments = len(re.findall(r'(//.*?$|/\*.*?\*/|#.*?$)', content, re.M | re.S))
    func_defs = len(re.findall(r'\bfunction\s+\w+\s*\(', content))
    class_defs = len(re.findall(r'\bclass\s+\w+', content))

    code_ratio = (alpha + digits) / max(1, total_chars)
    obfuscation_score = (chr_calls + hex_strings + long_strings + funcs_encode * 3) / max(1, line_count) * 100
    danger_density = (funcs_eval + funcs_exec + funcs_dynamic) / max(1, line_count) * 100

    return {
        "entropy": entropy,
        "printable_ratio": printable_ratio,
        "avg_line_len": avg_line_len,
        "max_line_len": max_line_len,
        "long_lines_ratio": long_lines / max(1, line_count),
        "alpha_ratio": alpha / max(1, total_chars),
        "digit_ratio": digits / max(1, total_chars),
        "special_ratio": specials / max(1, total_chars),
        "code_ratio": code_ratio,
        "funcs_eval": funcs_eval,
        "funcs_exec": funcs_exec,
        "funcs_encode": funcs_encode,
        "funcs_file": funcs_file,
        "funcs_dynamic": funcs_dynamic,
        "user_input": user_input,
        "chr_calls": chr_calls,
        "hex_strings": hex_strings,
        "long_strings": long_strings,
        "obfuscation_score": obfuscation_score,
        "danger_density": danger_density,
        "comments": comments,
        "func_defs": func_defs,
        "class_defs": class_defs,
        "file_size": len(content),
        "line_count": line_count,
        "string_concats": string_concats,
    }


def _decision_model(f):
    breakdown = {}

    if f["funcs_eval"] > 0:
        breakdown["eval_calls"] = min(30, f["funcs_eval"] * 15)
    if f["funcs_exec"] > 0:
        breakdown["exec_calls"] = min(25, f["funcs_exec"] * 12)
    if f["funcs_dynamic"] > 2:
        breakdown["dynamic_calls"] = min(20, (f["funcs_dynamic"] - 2) * 5)
    if f["funcs_encode"] > 1:
        breakdown["encoding_funcs"] = min(20, f["funcs_encode"] * 8)
    if f["user_input"] > 0 and (f["funcs_eval"] > 0 or f["funcs_exec"] > 0):
        breakdown["input_to_exec"] = 25
    if f["entropy"] > 5.5:
        breakdown["high_entropy"] = min(20, int((f["entropy"] - 5.0) * 15))
    if f["obfuscation_score"] > 5:
        breakdown["obfuscation"] = min(20, int(f["obfuscation_score"] * 2))
    if f["chr_calls"] > 5:
        breakdown["chr_building"] = min(15, f["chr_calls"] * 2)
    if f["long_strings"] > 0:
        breakdown["long_encoded_strings"] = min(15, f["long_strings"] * 8)
    if f["max_line_len"] > 1000:
        breakdown["extreme_line_length"] = 10
    if f["long_lines_ratio"] > 0.3:
        breakdown["many_long_lines"] = 10
    if f["hex_strings"] > 10:
        breakdown["hex_obfuscation"] = min(12, f["hex_strings"])
    if f["danger_density"] > 3:
        breakdown["danger_density"] = min(15, int(f["danger_density"] * 3))

    mitigations = {}
    if f["comments"] > f["line_count"] * 0.1:
        mitigations["well_commented"] = -10
    if f["func_defs"] > 3 and f["class_defs"] > 0:
        mitigations["structured_code"] = -8
    if f["funcs_eval"] == 0 and f["funcs_exec"] == 0 and f["funcs_dynamic"] == 0:
        mitigations["no_dangerous_funcs"] = -15
    if f["entropy"] < 4.5 and f["obfuscation_score"] < 2:
        mitigations["clean_readable"] = -10

    raw = sum(breakdown.values()) + sum(mitigations.values())
    score = max(0, min(100, raw))

    if score >= 70:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    else:
        verdict = "clean"

    full = {**breakdown, **mitigations}
    return score, verdict, full


def _top_reasons(breakdown, n):
    positives = {k: v for k, v in breakdown.items() if v > 0}
    sorted_r = sorted(positives.items(), key=lambda x: x[1], reverse=True)
    names = [k.replace("_", " ") for k, _ in sorted_r[:n]]
    return ", ".join(names) if names else "multiple indicators"


def _shannon(data):
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())
