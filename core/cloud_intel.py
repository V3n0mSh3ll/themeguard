import json
import os
import hashlib
from urllib.request import urlopen, Request
from urllib.error import URLError

_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
_URLHAUS_HASH_API = "https://urlhaus-api.abuse.ch/v1/payload/"
_ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
_WPSCAN_API = "https://wpscan.com/api/v3/plugins/{slug}"

_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".threat_cache")
_CACHE_TTL = 3600


def query_url_reputation(urls, findings_out, filename=""):
    if not urls:
        return

    for url in urls[:10]:
        cached = _read_cache("url", hashlib.md5(url.encode()).hexdigest())
        if cached is not None:
            if cached.get("threat"):
                findings_out.append(cached["finding"])
            continue

        try:
            data = _post_request(_URLHAUS_API, {"url": url})
            if not data:
                continue

            status = data.get("query_status", "")
            if status == "listed":
                threat = data.get("threat", "unknown")
                tags = ", ".join(data.get("tags", [])[:3]) or "none"
                finding = {
                    "file": filename,
                    "line": 0,
                    "type": "cloud_url_malicious",
                    "severity": "critical",
                    "message": f"URLhaus: '{url[:60]}' listed as malicious (threat: {threat}, tags: {tags})",
                }
                findings_out.append(finding)
                _write_cache("url", hashlib.md5(url.encode()).hexdigest(), {"threat": True, "finding": finding})
            else:
                _write_cache("url", hashlib.md5(url.encode()).hexdigest(), {"threat": False})

        except (URLError, OSError, ValueError):
            continue


def query_hash_reputation(file_path, findings_out, filename=""):
    try:
        sha256 = _sha256_file(file_path)
    except OSError:
        return

    cached = _read_cache("hash", sha256)
    if cached is not None:
        if cached.get("threat"):
            findings_out.append(cached["finding"])
        return

    try:
        data = _post_request(_URLHAUS_HASH_API, {"sha256_hash": sha256})
        if not data:
            return

        status = data.get("query_status", "")
        if status == "hash_found":
            fnames = [s.get("filename", "") for s in data.get("urls", [])[:3]]
            finding = {
                "file": filename,
                "line": 0,
                "type": "cloud_hash_known_malware",
                "severity": "critical",
                "message": f"URLhaus: file hash {sha256[:16]}... matches known malware ({', '.join(fnames)})",
            }
            findings_out.append(finding)
            _write_cache("hash", sha256, {"threat": True, "finding": finding})
        else:
            _write_cache("hash", sha256, {"threat": False})

    except (URLError, OSError, ValueError):
        pass


def query_wpscan_vulns(slug, version, findings_out, filename=""):
    api_key = os.environ.get("WPSCAN_API_TOKEN", "")
    if not api_key:
        return

    cached = _read_cache("wpscan", f"{slug}_{version}")
    if cached is not None:
        findings_out.extend(cached.get("findings", []))
        return

    try:
        url = _WPSCAN_API.format(slug=slug)
        req = Request(url, headers={
            "Authorization": f"Token token={api_key}",
            "User-Agent": "ThemeGuard/1.0",
        })
        resp = urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8"))
    except (URLError, OSError, ValueError):
        return

    plugin_data = data.get(slug, {})
    vulns = plugin_data.get("vulnerabilities", [])
    result_findings = []

    for v in vulns:
        fixed = v.get("fixed_in")
        if fixed and version and _version_below(version, fixed):
            finding = {
                "file": filename,
                "line": 0,
                "type": "cloud_known_cve",
                "severity": "critical",
                "message": f"WPScan: {v.get('title', 'Unknown vulnerability')} (fixed in {fixed})",
            }
            result_findings.append(finding)
            findings_out.append(finding)

    _write_cache("wpscan", f"{slug}_{version}", {"findings": result_findings})


def cloud_scan_file(content, filename, file_path=None):
    findings = []

    import re
    urls = re.findall(r'https?://[^\s\'"<>]{10,}', content)
    external_urls = [u for u in urls if "wordpress.org" not in u and "w3.org" not in u]
    if external_urls:
        query_url_reputation(external_urls[:5], findings, filename)

    if file_path and os.path.isfile(file_path):
        query_hash_reputation(file_path, findings, filename)

    return findings


def _post_request(url, params):
    import urllib.parse
    encoded = urllib.parse.urlencode(params).encode("utf-8")
    req = Request(url, data=encoded, headers={
        "User-Agent": "ThemeGuard/1.0",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    resp = urlopen(req, timeout=8)
    return json.loads(resp.read().decode("utf-8"))


def _sha256_file(fpath):
    h = hashlib.sha256()
    with open(fpath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _version_below(current, target):
    try:
        c_parts = [int(x) for x in current.split(".")]
        t_parts = [int(x) for x in target.split(".")]
        return c_parts < t_parts
    except (ValueError, AttributeError):
        return False


def _read_cache(category, key):
    cache_file = os.path.join(_CACHE_DIR, category, f"{key}.json")
    if not os.path.isfile(cache_file):
        return None

    try:
        mtime = os.path.getmtime(cache_file)
        import time
        if time.time() - mtime > _CACHE_TTL:
            os.remove(cache_file)
            return None

        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(category, key, data):
    cache_dir = os.path.join(_CACHE_DIR, category)
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{key}.json")
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except OSError:
        pass
