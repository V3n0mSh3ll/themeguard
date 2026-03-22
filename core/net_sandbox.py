import re
import socket
import ssl
from urllib.request import urlopen, Request
from urllib.error import URLError

_TIMEOUT = 5
_MAX_REDIRECTS = 5
_USER_AGENT = "ThemeGuard/1.0 Security Scanner"

_URL_RE = re.compile(r"https?://[^\s'\"<>)}\]]{5,}", re.IGNORECASE)

def sandbox_urls(content, filename):
    findings = []
    urls = list(set(_URL_RE.findall(content)))

    for url in urls[:20]:
        domain = _extract_domain(url)
        if not domain:
            continue

        dns_ok = _check_dns(domain)
        if not dns_ok:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "dead_domain",
                "severity": "medium",
                "message": f"Domain does not resolve: {domain}",
            })
            continue

        status, redirect_chain, ssl_valid = _probe_url(url)

        if redirect_chain and len(redirect_chain) > 2:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "redirect_chain",
                "severity": "high",
                "message": f"Suspicious redirect chain ({len(redirect_chain)} hops): {' -> '.join(redirect_chain[:4])}",
            })

        if url.startswith("https://") and not ssl_valid:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "invalid_ssl",
                "severity": "medium",
                "message": f"Invalid/expired SSL certificate: {domain}",
            })

        if status and status >= 400:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "dead_url",
                "severity": "low",
                "message": f"URL returns HTTP {status}: {url[:100]}",
            })

    return findings


def _extract_domain(url):
    match = re.search(r"https?://([^/:\s?#]+)", url)
    return match.group(1).lower() if match else None


def _check_dns(domain):
    try:
        socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        return False


def _probe_url(url):
    status = None
    chain = []
    ssl_valid = True

    try:
        current = url
        for _ in range(_MAX_REDIRECTS):
            chain.append(_extract_domain(current) or current[:50])
            req = Request(current, method="HEAD", headers={"User-Agent": _USER_AGENT})

            try:
                resp = urlopen(req, timeout=_TIMEOUT)
                status = resp.status
                if resp.url != current:
                    current = resp.url
                    continue
                break
            except URLError as e:
                if hasattr(e, "code"):
                    status = e.code
                if "CERTIFICATE_VERIFY_FAILED" in str(e) or "SSL" in str(e):
                    ssl_valid = False
                break
    except Exception:
        pass

    return status, chain, ssl_valid
