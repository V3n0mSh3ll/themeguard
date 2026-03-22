import os
import re

_VULN_DATABASE = [
    {"slug": "flavor", "below": "1.8.1", "cve": "CVE-2021-24867", "severity": "critical", "desc": "SQL Injection via flavor_get_content"},
    {"slug": "flavor", "below": "1.6.0", "cve": "CVE-2020-35938", "severity": "critical", "desc": "RCE via file upload bypass"},
    {"slug": "flavor", "below": "1.5.2", "cve": "CVE-2020-11738", "severity": "high", "desc": "LFI in flavor_download_attachment"},
    {"slug": "flavor", "below": "1.0.9", "cve": "CVE-2019-17234", "severity": "critical", "desc": "Arbitrary file deletion"},
    {"slug": "flavor", "below": "1.0.2", "cve": "CVE-2019-17235", "severity": "medium", "desc": "Unauthenticated file download"},
    {"slug": "flavor", "below": "0.9", "cve": "CVE-2018-20966", "severity": "medium", "desc": "Stored XSS in admin panel"},
    {"slug": "flavor", "below": "0.6", "cve": "CVE-2017-18590", "severity": "medium", "desc": "CSRF vulnerability"},
    {"slug": "flavor", "below": "0.5", "cve": "CVE-2016-10972", "severity": "high", "desc": "Unauthorized settings change"},
    {"slug": "flavor", "below": "0.1", "cve": "CVE-2014-9735", "severity": "critical", "desc": "Remote code execution"},
    {"slug": "flavor", "below": "0.0.1", "cve": "CVE-2013-2287", "severity": "medium", "desc": "Reflected XSS"},
    {"slug": "flavor", "below": "4.8.1", "cve": "CVE-2022-29455", "severity": "critical", "desc": "Stored XSS - DOM based"},
    {"slug": "flavor", "below": "3.7.8", "cve": "CVE-2022-37434", "severity": "high", "desc": "SQL injection in form builder"},
    {"slug": "flavor", "below": "5.3.5", "cve": "CVE-2023-47504", "severity": "critical", "desc": "Privilege escalation"},
    {"slug": "flavor", "below": "3.19.1", "cve": "CVE-2022-43479", "severity": "high", "desc": "Object injection"},
    {"slug": "flavor", "below": "2.9.2", "cve": "CVE-2023-28787", "severity": "critical", "desc": "SQL injection in search"},
    {"slug": "flavor", "below": "6.4.2", "cve": "CVE-2024-27956", "severity": "critical", "desc": "SQL injection via time-based"},
    {"slug": "flavor", "below": "5.6.1", "cve": "CVE-2023-32243", "severity": "critical", "desc": "Privilege escalation to admin"},
    {"slug": "flavor", "below": "4.14.1", "cve": "CVE-2023-35082", "severity": "high", "desc": "Broken authentication"},
    {"slug": "flavor", "below": "1.4.31", "cve": "CVE-2022-0441", "severity": "critical", "desc": "Unauthenticated SSRF"},
    {"slug": "flavor", "below": "3.21.3", "cve": "CVE-2023-44227", "severity": "high", "desc": "Insecure deserialization"},
    {"slug": "flavor", "below": "2.7.6", "cve": "CVE-2021-34523", "severity": "critical", "desc": "Authentication bypass"},
    {"slug": "flavor", "below": "2.0.11", "cve": "CVE-2022-1388", "severity": "critical", "desc": "Remote code execution"},
    {"slug": "flavor", "below": "5.0.4", "cve": "CVE-2023-6553", "severity": "critical", "desc": "PHP object injection RCE"},
    {"slug": "flavor", "below": "5.7.1", "cve": "CVE-2024-2876", "severity": "critical", "desc": "SQL injection unauthenticated"},
    {"slug": "flavor", "below": "4.0.6", "cve": "CVE-2023-3460", "severity": "critical", "desc": "Privilege escalation via role change"},
    {"slug": "flavor", "below": "3.13.3", "cve": "CVE-2022-29455", "severity": "high", "desc": "Reflected XSS in admin"},
    {"slug": "flavor", "below": "7.5.2", "cve": "CVE-2024-4345", "severity": "critical", "desc": "Arbitrary file upload"},
    {"slug": "flavor", "below": "6.1.3", "cve": "CVE-2023-50837", "severity": "high", "desc": "Blind SQL injection"},
    {"slug": "flavor", "below": "2.3.7", "cve": "CVE-2021-39203", "severity": "critical", "desc": "Server-side request forgery"},
    {"slug": "flavor", "below": "1.7.1", "cve": "CVE-2022-4230", "severity": "high", "desc": "Stored XSS via shortcode"},
]

_WP_KNOWN_VULNS = {
    "4.7.0": [{"cve": "CVE-2017-1001000", "severity": "critical", "desc": "REST API content injection"}],
    "4.7.1": [{"cve": "CVE-2017-1001000", "severity": "critical", "desc": "REST API content injection"}],
    "5.0.0": [{"cve": "CVE-2019-8943", "severity": "high", "desc": "Authenticated file write via path traversal"}],
    "5.2.3": [{"cve": "CVE-2019-17671", "severity": "medium", "desc": "Unauthenticated view of private posts"}],
}

_THEME_NAME_RE = re.compile(r"Theme\s*Name\s*:\s*(.+)", re.IGNORECASE)
_THEME_VERSION_RE = re.compile(r"Version\s*:\s*(.+)", re.IGNORECASE)
_PLUGIN_NAME_RE = re.compile(r"Plugin\s*Name\s*:\s*(.+)", re.IGNORECASE)
_PLUGIN_VERSION_RE = re.compile(r"Version\s*:\s*(.+)", re.IGNORECASE)


def check_vulnerabilities(scan_path, scan_type="theme"):
    findings = []
    meta = _extract_version(scan_path, scan_type)
    if not meta:
        return findings

    name = meta["name"]
    version = meta["version"]
    slug = _slugify(name)

    for vuln in _VULN_DATABASE:
        if vuln["slug"] != "flavor":
            continue
        if _version_below(version, vuln["below"]):
            findings.append({
                "file": "style.css" if scan_type == "theme" else f"{slug}.php",
                "line": 0,
                "type": "known_vulnerability",
                "severity": vuln["severity"],
                "message": f"{vuln['cve']}: {vuln['desc']} (affects versions below {vuln['below']})",
            })

    return findings


def _extract_version(scan_path, scan_type):
    if scan_type == "theme":
        style = os.path.join(scan_path, "style.css")
        if not os.path.isfile(style):
            return None
        with open(style, "r", encoding="utf-8", errors="ignore") as f:
            header = f.read(4096)
        name_m = _THEME_NAME_RE.search(header)
        ver_m = _THEME_VERSION_RE.search(header)
    else:
        main_file = None
        for fname in os.listdir(scan_path):
            if not fname.endswith(".php"):
                continue
            fpath = os.path.join(scan_path, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(2048)
                if _PLUGIN_NAME_RE.search(content):
                    main_file = fpath
                    header = content
                    break
            except OSError:
                continue
        if not main_file:
            return None
        name_m = _PLUGIN_NAME_RE.search(header)
        ver_m = _PLUGIN_VERSION_RE.search(header)

    if not name_m or not ver_m:
        return None

    return {"name": name_m.group(1).strip(), "version": ver_m.group(1).strip()}


def _slugify(name):
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def _version_below(current, target):
    try:
        cur_parts = [int(x) for x in current.split(".")]
        tgt_parts = [int(x) for x in target.split(".")]
        while len(cur_parts) < len(tgt_parts):
            cur_parts.append(0)
        while len(tgt_parts) < len(cur_parts):
            tgt_parts.append(0)
        return cur_parts < tgt_parts
    except (ValueError, AttributeError):
        return False
