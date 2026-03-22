import re
import base64
import binascii
import zlib

_MAX_DEPTH = 10

_LAYER_PATTERNS = [
    (re.compile(r"base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=]{20,})['\"]", re.IGNORECASE), "base64"),
    (re.compile(r"gzinflate\s*\(\s*base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=]{20,})['\"]", re.IGNORECASE), "gzinflate+base64"),
    (re.compile(r"gzuncompress\s*\(\s*base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=]{20,})['\"]", re.IGNORECASE), "gzuncompress+base64"),
    (re.compile(r"str_rot13\s*\(\s*['\"]([^'\"]{20,})['\"]", re.IGNORECASE), "rot13"),
    (re.compile(r"rawurldecode\s*\(\s*['\"]([^'\"]{20,})['\"]", re.IGNORECASE), "urldecode"),
    (re.compile(r"hex2bin\s*\(\s*['\"]([0-9a-fA-F]{20,})['\"]", re.IGNORECASE), "hex2bin"),
]

_DANGER_RE = re.compile(
    r"\b(eval|exec|system|passthru|shell_exec|popen|proc_open|assert|"
    r"base64_decode|gzinflate|file_put_contents|curl_exec|mail)\b",
    re.IGNORECASE,
)


def deobfuscate(content, filename):
    findings = []
    layers = _unwrap_layers(content, depth=0, seen=set())
    if not layers:
        return findings

    for layer in layers:
        dangerous = _DANGER_RE.findall(layer["decoded"])
        if dangerous or layer["depth"] > 1:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "obfuscated_payload",
                "severity": "critical" if dangerous else "high",
                "message": f"Decoded {layer['depth']} layer(s) [{layer['chain']}]: {', '.join(set(dangerous)) if dangerous else 'nested encoding'}",
                "match": layer["decoded"][:150],
            })

    return findings


def _unwrap_layers(content, depth, seen):
    if depth >= _MAX_DEPTH:
        return []

    content_hash = hash(content[:500])
    if content_hash in seen:
        return []
    seen.add(content_hash)

    results = []

    for pattern, method in _LAYER_PATTERNS:
        for match in pattern.finditer(content):
            encoded = match.group(1)
            decoded = _decode(encoded, method)
            if not decoded:
                continue

            chain = method
            results.append({
                "depth": depth + 1,
                "chain": chain,
                "decoded": decoded,
            })

            inner = _unwrap_layers(decoded, depth + 1, seen)
            for item in inner:
                item["chain"] = f"{chain} -> {item['chain']}"
                item["depth"] = depth + 1 + item["depth"]
            results.extend(inner)

    return results


def _decode(data, method):
    try:
        if method == "base64":
            return base64.b64decode(data).decode("utf-8", errors="ignore")
        if method == "gzinflate+base64":
            raw = base64.b64decode(data)
            return zlib.decompress(raw, -15).decode("utf-8", errors="ignore")
        if method == "gzuncompress+base64":
            raw = base64.b64decode(data)
            return zlib.decompress(raw).decode("utf-8", errors="ignore")
        if method == "rot13":
            return _rot13(data)
        if method == "urldecode":
            return _urldecode(data)
        if method == "hex2bin":
            return bytes.fromhex(data).decode("utf-8", errors="ignore")
    except (binascii.Error, zlib.error, ValueError, UnicodeDecodeError):
        return None
    return None


def _rot13(text):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def _urldecode(text):
    result = []
    i = 0
    while i < len(text):
        if text[i] == "%" and i + 2 < len(text):
            try:
                result.append(chr(int(text[i + 1:i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        result.append(text[i])
        i += 1
    return "".join(result)
