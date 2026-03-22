import math
import re

_ENCODING_CHAINS = [
    (r"eval\s*\(\s*base64_decode\s*\(", "eval(base64_decode()) chain", "critical"),
    (r"eval\s*\(\s*gzinflate\s*\(\s*base64_decode", "eval(gzinflate(base64_decode())) chain", "critical"),
    (r"eval\s*\(\s*gzuncompress\s*\(\s*base64_decode", "eval(gzuncompress(base64_decode())) chain", "critical"),
    (r"eval\s*\(\s*str_rot13\s*\(", "eval(str_rot13()) chain", "high"),
    (r"eval\s*\(\s*rawurldecode\s*\(", "eval(rawurldecode()) chain", "high"),
    (r"assert\s*\(\s*base64_decode\s*\(", "assert(base64_decode()) chain", "critical"),
]

_VAR_PATTERNS = [
    (r"\$[a-zA-Z_]\w*\s*\(", "variable_function_call", "Variable used as function call: $var()"),
    (r"\$\$[a-zA-Z_]\w*", "variable_variable", "Variable variable ($$var) usage"),
]

def analyze_obfuscation(content, rel_path):
    findings = []
    lines = content.split("\n")

    entropy = _shannon_entropy(content)
    if entropy > 6.0 and len(content) > 500:
        findings.append({
            "type": "high_entropy",
            "category": "obfuscation",
            "severity": "high",
            "message": f"Abnormally high entropy ({entropy:.2f})",
            "file": rel_path,
            "line": 0,
        })

    for line_num, line in enumerate(lines, 1):
        if len(line.strip()) > 1000 and not line.strip().startswith("//"):
            findings.append({
                "type": "long_line_obfuscation",
                "category": "obfuscation",
                "severity": "medium",
                "message": f"Suspicious long line ({len(line.strip())} chars)",
                "file": rel_path,
                "line": line_num,
            })
            break

    for pattern, desc, severity in _ENCODING_CHAINS:
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "type": "encoding_chain",
                    "category": "obfuscation",
                    "severity": severity,
                    "message": desc,
                    "file": rel_path,
                    "line": line_num,
                    "match": line.strip()[:200],
                })
                break

    for pattern, sig_type, desc in _VAR_PATTERNS:
        count = sum(1 for line in lines if re.search(pattern, line))
        if count > 10:
            findings.append({
                "type": sig_type,
                "category": "obfuscation",
                "severity": "medium",
                "message": f"{desc} - {count} occurrences",
                "file": rel_path,
                "line": 0,
            })

    hex_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", content))
    if hex_count > 20:
        findings.append({
            "type": "hex_encoding",
            "category": "obfuscation",
            "severity": "high",
            "message": f"Heavy hex-encoded strings ({hex_count} sequences)",
            "file": rel_path,
            "line": 0,
        })

    chr_count = len(re.findall(r"chr\s*\(\s*\d+\s*\)", content))
    if chr_count > 15:
        findings.append({
            "type": "chr_chain",
            "category": "obfuscation",
            "severity": "high",
            "message": f"Excessive chr() calls ({chr_count}) - string built char-by-char",
            "file": rel_path,
            "line": 0,
        })

    return findings


def _shannon_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())
