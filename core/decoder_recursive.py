import re
import base64
import binascii
import zlib


_MAX_DEPTH = 8
_MAX_OUTPUT = 50000

_B64_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
_HEX_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){8,}')
_HEX_PLAIN_RE = re.compile(r'\b[0-9a-fA-F]{64,}\b')
_CHR_RE = re.compile(r'chr\s*\(\s*(\d+)\s*\)', re.IGNORECASE)
_ROT13_RE = re.compile(r'\bstr_rot13\s*\(\s*["\'](.+?)["\']\s*\)', re.IGNORECASE)
_GZINFLATE_RE = re.compile(r'\bgzinflate\s*\(', re.IGNORECASE)
_GZUNCOMPRESS_RE = re.compile(r'\bgzuncompress\s*\(', re.IGNORECASE)
_GZDECODE_RE = re.compile(r'\bgzdecode\s*\(', re.IGNORECASE)
_STRREV_RE = re.compile(r'\bstrrev\s*\(\s*["\'](.+?)["\']\s*\)', re.IGNORECASE)

_DANGER_PATTERNS = re.compile(
    r'\b(eval|assert|system|exec|passthru|shell_exec|popen|'
    r'proc_open|base64_decode|file_put_contents|include|require)\b',
    re.IGNORECASE,
)


def recursive_decode(content, filename):
    findings = []
    _decode_recursive(content, filename, 0, findings, set())
    return findings


def _decode_recursive(blob, filename, depth, findings, seen):
    if depth >= _MAX_DEPTH:
        return
    if len(blob) > _MAX_OUTPUT:
        blob = blob[:_MAX_OUTPUT]

    blob_hash = hash(blob[:500])
    if blob_hash in seen:
        return
    seen.add(blob_hash)

    for m in _B64_RE.finditer(blob):
        raw = m.group(0)
        decoded = _try_b64(raw)
        if decoded:
            if _DANGER_PATTERNS.search(decoded):
                findings.append({
                    "file": filename,
                    "line": 0,
                    "type": "recursive_b64_payload",
                    "severity": "critical",
                    "message": f"Depth-{depth} base64 decode reveals: {decoded[:80]}",
                    "match": decoded[:120],
                })
            _decode_recursive(decoded, filename, depth + 1, findings, seen)

    for m in _HEX_RE.finditer(blob):
        decoded = _try_hex_escape(m.group(0))
        if decoded and _DANGER_PATTERNS.search(decoded):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "recursive_hex_payload",
                "severity": "critical",
                "message": f"Depth-{depth} hex decode reveals: {decoded[:80]}",
                "match": decoded[:120],
            })
            _decode_recursive(decoded, filename, depth + 1, findings, seen)

    for m in _HEX_PLAIN_RE.finditer(blob):
        decoded = _try_hex_plain(m.group(0))
        if decoded and _DANGER_PATTERNS.search(decoded):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "recursive_hex_plain_payload",
                "severity": "high",
                "message": f"Depth-{depth} hex-string decode reveals: {decoded[:80]}",
                "match": decoded[:120],
            })
            _decode_recursive(decoded, filename, depth + 1, findings, seen)

    chr_calls = _CHR_RE.findall(blob)
    if len(chr_calls) >= 5:
        decoded = "".join(chr(int(c)) for c in chr_calls if 0 < int(c) < 128)
        if decoded and _DANGER_PATTERNS.search(decoded):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "recursive_chr_payload",
                "severity": "critical",
                "message": f"Depth-{depth} chr() chain builds: {decoded[:80]}",
                "match": decoded[:120],
            })

    for m in _ROT13_RE.finditer(blob):
        decoded = _rot13(m.group(1))
        if _DANGER_PATTERNS.search(decoded):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "recursive_rot13_payload",
                "severity": "high",
                "message": f"Depth-{depth} rot13 reveals: {decoded[:80]}",
            })
            _decode_recursive(decoded, filename, depth + 1, findings, seen)

    for m in _STRREV_RE.finditer(blob):
        decoded = m.group(1)[::-1]
        if _DANGER_PATTERNS.search(decoded):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "recursive_strrev_payload",
                "severity": "high",
                "message": f"Depth-{depth} strrev reveals: {decoded[:80]}",
            })

    if _GZINFLATE_RE.search(blob) or _GZUNCOMPRESS_RE.search(blob) or _GZDECODE_RE.search(blob):
        for m in _B64_RE.finditer(blob):
            raw_b64 = _try_b64_raw(m.group(0))
            if raw_b64:
                decompressed = _try_decompress(raw_b64)
                if decompressed and _DANGER_PATTERNS.search(decompressed):
                    findings.append({
                        "file": filename,
                        "line": 0,
                        "type": "recursive_compressed_payload",
                        "severity": "critical",
                        "message": f"Depth-{depth} gzinflate+b64 reveals: {decompressed[:80]}",
                        "match": decompressed[:120],
                    })
                    _decode_recursive(decompressed, filename, depth + 1, findings, seen)


def _try_b64(s):
    try:
        pad = 4 - len(s) % 4
        if pad < 4:
            s += "=" * pad
        decoded = base64.b64decode(s)
        text = decoded.decode("utf-8", errors="strict")
        printable = sum(1 for c in text if c.isprintable() or c.isspace())
        if printable / max(1, len(text)) < 0.7:
            return None
        return text
    except Exception:
        return None


def _try_b64_raw(s):
    try:
        pad = 4 - len(s) % 4
        if pad < 4:
            s += "=" * pad
        return base64.b64decode(s)
    except Exception:
        return None


def _try_hex_escape(s):
    try:
        cleaned = s.replace("\\x", "")
        raw = bytes.fromhex(cleaned)
        return raw.decode("utf-8", errors="ignore")
    except (ValueError, binascii.Error):
        return None


def _try_hex_plain(s):
    try:
        raw = bytes.fromhex(s)
        text = raw.decode("utf-8", errors="ignore")
        printable = sum(1 for c in text if c.isprintable() or c.isspace())
        if printable / max(1, len(text)) < 0.5:
            return None
        return text
    except (ValueError, binascii.Error):
        return None


def _try_decompress(data):
    for func in (zlib.decompress, _try_raw_deflate):
        try:
            result = func(data)
            if isinstance(result, bytes):
                return result.decode("utf-8", errors="ignore")
        except Exception:
            continue
    return None


def _try_raw_deflate(data):
    return zlib.decompress(data, -zlib.MAX_WBITS)


def _rot13(s):
    result = []
    for c in s:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)
