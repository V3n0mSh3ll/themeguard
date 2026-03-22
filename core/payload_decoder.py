import re
import base64
import binascii

_DANGEROUS_RE = re.compile(
    r"\b(eval|exec|system|passthru|shell_exec|popen|proc_open|assert|mail)\s*\(", re.IGNORECASE
)
_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_B64_FUNC_RE = re.compile(
    r'(?:base64_decode\s*\(\s*[\'"]|atob\s*\(\s*[\'"])([A-Za-z0-9+/=]{40,})[\'"]', re.IGNORECASE
)
_B64_STANDALONE_RE = re.compile(r'[\'"]([A-Za-z0-9+/]{80,}={0,2})[\'"]')
_HEX_BLOCK_RE = re.compile(r'((?:\\x[0-9a-fA-F]{2}){10,})')
_CHR_CHAIN_RE = re.compile(r'((?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){6,})', re.IGNORECASE)
_PHP_CODE_RE = re.compile(r'<\?php|eval|exec|system|function\s+\w+\s*\(')

def analyze_payload(content, filename):
    findings = []
    _decode_base64_in_calls(content, filename, findings)
    _decode_standalone_base64(content, filename, findings)
    _decode_hex_blocks(content, filename, findings)
    _decode_chr_chains(content, filename, findings)
    return findings

def _line_at(content, pos):
    return content[:pos].count("\n") + 1
def _decode_base64_in_calls(content, filename, findings):
    for match in _B64_FUNC_RE.finditer(content):
        encoded = match.group(1)
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
        except (binascii.Error, UnicodeDecodeError):
            continue

        funcs = _DANGEROUS_RE.findall(decoded)
        if funcs:
            findings.append({
                "file": filename,
                "line": _line_at(content, match.start()),
                "type": "decoded_payload",
                "severity": "critical",
                "message": f"Base64 payload contains: {', '.join(set(funcs))}",
                "match": decoded[:150],
            })

        urls = _URL_RE.findall(decoded)
        if urls:
            findings.append({
                "file": filename,
                "line": _line_at(content, match.start()),
                "type": "decoded_url",
                "severity": "high",
                "message": f"Base64 payload contains URLs: {', '.join(urls[:3])}",
                "match": decoded[:150],
            })

def _decode_standalone_base64(content, filename, findings):
    for match in _B64_STANDALONE_RE.finditer(content):
        try:
            decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="ignore")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if _PHP_CODE_RE.search(decoded):
            findings.append({
                "file": filename,
                "line": _line_at(content, match.start()),
                "type": "hidden_php_payload",
                "severity": "critical",
                "message": "Long base64 string decodes to PHP code",
                "match": decoded[:150],
            })

def _decode_hex_blocks(content, filename, findings):
    for block in _HEX_BLOCK_RE.findall(content):
        try:
            decoded = bytes.fromhex(block.replace("\\x", "")).decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError):
            continue
        if re.search(r"\b(eval|exec|system|passthru|shell_exec|assert)\b", decoded):
            findings.append({
                "file": filename,
                "line": _line_at(content, content.index(block)),
                "type": "hex_payload",
                "severity": "critical",
                "message": f"Hex-encoded payload decodes to: {decoded[:80]}",
                "match": block[:100],
            })

def _decode_chr_chains(content, filename, findings):
    for match in _CHR_CHAIN_RE.finditer(content):
        nums = re.findall(r"chr\s*\(\s*(\d+)\s*\)", match.group(0))
        try:
            decoded = "".join(chr(int(n)) for n in nums)
        except (ValueError, OverflowError):
            continue
        if re.search(r"\b(eval|exec|system|passthru|base64|assert)\b", decoded, re.IGNORECASE):
            findings.append({
                "file": filename,
                "line": _line_at(content, match.start()),
                "type": "chr_payload",
                "severity": "critical",
                "message": f"chr() chain builds: {decoded[:80]}",
                "match": match.group(0)[:100],
            })
