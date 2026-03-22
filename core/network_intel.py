import re

_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".su", ".ru", ".cn", ".buzz", ".icu",
}

_MALICIOUS_URL_PATTERNS = [
    r"pastebin\.com/raw",
    r"bit\.ly/",
    r"tinyurl\.com/",
    r"raw\.githubusercontent\.com",
    r"transfer\.sh",
    r"ngrok\.io",
    r"serveo\.net",
    r"\d+\.\d+\.\d+\.\d+",
]

_C2_SIGNATURES = [
    (r"file_get_contents\s*\(\s*['\"]https?://", "file_get_contents() fetching remote URL"),
    (r"curl_exec\s*\(", "curl_exec() - possible C2 callback"),
    (r"wp_remote_(?:get|post|request)\s*\(\s*['\"]https?://(?!api\.wordpress\.org)", "wp_remote call to non-WordPress API"),
    (r"fsockopen\s*\(", "fsockopen() - raw socket connection"),
    (r"stream_socket_client\s*\(", "stream_socket_client() - outbound connection"),
    (r"@?mail\s*\(\s*['\"][^'\"]*@", "mail() sending to hardcoded address"),
]

_URL_REGEX = re.compile(r"https?://[^\s'\"<>)}\]]{5,}", re.IGNORECASE)

def analyze_network(content, rel_path):
    findings = []
    lines = content.split("\n")

    urls = _URL_REGEX.findall(content)
    seen = set()

    for url in urls:
        domain = _extract_domain(url)
        if not domain or domain in seen:
            continue
        seen.add(domain)

        for tld in _SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append({
                    "type": "suspicious_domain",
                    "category": "network",
                    "severity": "high",
                    "message": f"URL with suspicious TLD: {url[:120]}",
                    "file": rel_path,
                    "line": _find_line(lines, url[:30]),
                })
                break

        for mp in _MALICIOUS_URL_PATTERNS:
            if re.search(mp, url, re.IGNORECASE):
                findings.append({
                    "type": "malicious_url",
                    "category": "network",
                    "severity": "critical",
                    "message": f"Known risky URL pattern: {url[:120]}",
                    "file": rel_path,
                    "line": _find_line(lines, url[:30]),
                })
                break

    for pattern, desc in _C2_SIGNATURES:
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "type": "c2_callback",
                    "category": "network",
                    "severity": "high",
                    "message": desc,
                    "file": rel_path,
                    "line": line_num,
                    "match": line.strip()[:200],
                })
                break

    b64_url = r"base64_decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]"
    for line_num, line in enumerate(lines, 1):
        if re.search(b64_url, line, re.IGNORECASE):
            findings.append({
                "type": "encoded_url",
                "category": "network",
                "severity": "critical",
                "message": "Base64-encoded string in network context",
                "file": rel_path,
                "line": line_num,
            })
            break

    return findings

def _extract_domain(url):
    match = re.search(r"https?://([^/:\s?#]+)", url)
    return match.group(1).lower() if match else None
def _find_line(lines, snippet):
    for i, line in enumerate(lines, 1):
        if snippet in line:
            return i
    return 0
