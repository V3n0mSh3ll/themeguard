import os
import re
import hashlib
from urllib.request import urlopen, Request
from urllib.error import URLError

_HTACCESS_REDIRECT_RE = re.compile(
    r'RewriteRule\s+.+?\s+(https?://[^\s\]]+)', re.IGNORECASE
)

_HTACCESS_COND_RE = re.compile(
    r'RewriteCond\s+%\{(HTTP_REFERER|HTTP_USER_AGENT|REQUEST_URI)\}\s+(.+)',
    re.IGNORECASE,
)

_HTACCESS_PHP_RE = re.compile(
    r'AddHandler\s+(application/x-httpd-php|php\d?-cgi)\s+\.(jpg|png|gif|ico|txt)',
    re.IGNORECASE,
)

_HTACCESS_DENY_RE = re.compile(r'(deny\s+from|allow\s+from)\s+(.+)', re.IGNORECASE)

_HTACCESS_AUTO_PREPEND = re.compile(
    r'php_value\s+auto_prepend_file\s+(.+)', re.IGNORECASE
)

_WPCONFIG_DEBUG_RE = re.compile(r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*(true|1)\s*\)", re.IGNORECASE)
_WPCONFIG_DISALLOW_EDIT_RE = re.compile(r"define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true\s*\)", re.IGNORECASE)
_WPCONFIG_DISALLOW_MODS_RE = re.compile(r"define\s*\(\s*['\"]DISALLOW_FILE_MODS['\"]\s*,\s*true\s*\)", re.IGNORECASE)
_WPCONFIG_SSL_RE = re.compile(r"define\s*\(\s*['\"]FORCE_SSL_ADMIN['\"]\s*,\s*true\s*\)", re.IGNORECASE)
_WPCONFIG_PREFIX_RE = re.compile(r"\$table_prefix\s*=\s*['\"](\w+)['\"]")
_WPCONFIG_SALT_RE = re.compile(r"define\s*\(\s*['\"](\w+_(?:KEY|SALT))['\"]\s*,\s*['\"](.+?)['\"]\s*\)")

_DB_CRED_RE = re.compile(
    r"define\s*\(\s*['\"]DB_(NAME|USER|PASSWORD|HOST)['\"]\s*,\s*['\"](.+?)['\"]\s*\)",
    re.IGNORECASE,
)

_SESSION_START_RE = re.compile(r'\bsession_start\s*\(', re.IGNORECASE)
_SESSION_REGEN_RE = re.compile(r'\bsession_regenerate_id\s*\(', re.IGNORECASE)

_CHECKSUM_API = "https://api.wordpress.org/core/checksums/1.0/?version={version}&locale=en_US"
_WP_VERSION_RE = re.compile(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]")


def scan_htaccess(scan_path):
    findings = []
    htaccess_path = os.path.join(scan_path, ".htaccess")
    if not os.path.isfile(htaccess_path):
        return findings

    with open(htaccess_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    for m in _HTACCESS_REDIRECT_RE.finditer(content):
        target = m.group(1)
        line_num = content[:m.start()].count("\n") + 1
        findings.append({
            "file": ".htaccess",
            "line": line_num,
            "type": "htaccess_redirect",
            "severity": "critical",
            "message": f"RewriteRule redirects to external URL: {target[:100]}",
        })

    for m in _HTACCESS_COND_RE.finditer(content):
        var = m.group(1)
        pattern = m.group(2)
        if any(s in pattern.lower() for s in ("google", "yahoo", "bing", "facebook", "bot")):
            line_num = content[:m.start()].count("\n") + 1
            findings.append({
                "file": ".htaccess",
                "line": line_num,
                "type": "htaccess_seo_cloak",
                "severity": "critical",
                "message": f"SEO cloaking: different content for {var} matching '{pattern[:60]}'",
            })

    for m in _HTACCESS_PHP_RE.finditer(content):
        ext = m.group(2)
        line_num = content[:m.start()].count("\n") + 1
        findings.append({
            "file": ".htaccess",
            "line": line_num,
            "type": "htaccess_php_disguise",
            "severity": "critical",
            "message": f".{ext} files set to execute as PHP (backdoor disguise)",
        })

    for m in _HTACCESS_AUTO_PREPEND.finditer(content):
        file_ref = m.group(1).strip()
        line_num = content[:m.start()].count("\n") + 1
        findings.append({
            "file": ".htaccess",
            "line": line_num,
            "type": "htaccess_auto_prepend",
            "severity": "critical",
            "message": f"auto_prepend_file injects '{file_ref}' into every PHP request",
        })

    return findings


def audit_wp_config(scan_path):
    findings = []
    config_path = os.path.join(scan_path, "wp-config.php")
    if not os.path.isfile(config_path):
        for parent in (os.path.dirname(scan_path), scan_path):
            candidate = os.path.join(parent, "wp-config.php")
            if os.path.isfile(candidate):
                config_path = candidate
                break
        else:
            return findings

    with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if _WPCONFIG_DEBUG_RE.search(content):
        findings.append({
            "file": "wp-config.php",
            "line": 0,
            "type": "wpconfig_debug_enabled",
            "severity": "high",
            "message": "WP_DEBUG is enabled - exposes error details to attackers",
        })

    if not _WPCONFIG_DISALLOW_EDIT_RE.search(content):
        findings.append({
            "file": "wp-config.php",
            "line": 0,
            "type": "wpconfig_file_edit_open",
            "severity": "high",
            "message": "DISALLOW_FILE_EDIT not set - admin can edit theme/plugin files from dashboard",
        })

    if not _WPCONFIG_SSL_RE.search(content):
        findings.append({
            "file": "wp-config.php",
            "line": 0,
            "type": "wpconfig_no_ssl_admin",
            "severity": "medium",
            "message": "FORCE_SSL_ADMIN not enabled",
        })

    prefix_m = _WPCONFIG_PREFIX_RE.search(content)
    if prefix_m and prefix_m.group(1) == "wp_":
        findings.append({
            "file": "wp-config.php",
            "line": 0,
            "type": "wpconfig_default_prefix",
            "severity": "medium",
            "message": "Default table prefix 'wp_' used - easier to target with SQL injection",
        })

    salts = _WPCONFIG_SALT_RE.findall(content)
    weak_salts = [name for name, val in salts if len(val) < 32 or val == "put your unique phrase here"]
    if weak_salts:
        findings.append({
            "file": "wp-config.php",
            "line": 0,
            "type": "wpconfig_weak_salts",
            "severity": "high",
            "message": f"Weak/default salt keys: {', '.join(weak_salts[:4])}",
        })

    return findings


def scan_db_credential_leaks(content, filename, scan_path):
    findings = []
    config_name = "wp-config.php"
    if filename == config_name or filename.endswith("/" + config_name):
        return findings

    for m in _DB_CRED_RE.finditer(content):
        cred_type = m.group(1)
        value = m.group(2)
        line_num = content[:m.start()].count("\n") + 1
        findings.append({
            "file": filename,
            "line": line_num,
            "type": "db_credential_leak",
            "severity": "critical",
            "message": f"DB_{cred_type} exposed outside wp-config.php (value: {value[:4]}****)",
        })

    password_patterns = [
        re.compile(r'["\']password["\']\s*=>\s*["\']([^"\']+)["\']', re.IGNORECASE),
        re.compile(r'\$db_pass(?:word)?\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
        re.compile(r'\$mysql_pass\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    ]

    for pat in password_patterns:
        for m in pat.finditer(content):
            line_num = content[:m.start()].count("\n") + 1
            findings.append({
                "file": filename,
                "line": line_num,
                "type": "hardcoded_db_password",
                "severity": "critical",
                "message": f"Database password hardcoded in source file",
            })

    return findings


def scan_session_security(content, filename):
    findings = []
    if not _SESSION_START_RE.search(content):
        return findings

    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        if "session_start" not in line:
            continue

        region = content[max(0, content.find(line) - 500):content.find(line) + 500]

        if "session.cookie_httponly" not in region and "httponly" not in region.lower():
            findings.append({
                "file": filename,
                "line": i,
                "type": "session_no_httponly",
                "severity": "high",
                "message": "session_start() without httponly flag - vulnerable to XSS session theft",
            })

        if "session.cookie_secure" not in region:
            findings.append({
                "file": filename,
                "line": i,
                "type": "session_no_secure",
                "severity": "medium",
                "message": "session_start() without secure flag - session sent over HTTP",
            })

        if not _SESSION_REGEN_RE.search(content):
            findings.append({
                "file": filename,
                "line": i,
                "type": "session_fixation_risk",
                "severity": "high",
                "message": "session_start() without session_regenerate_id() - fixation risk",
            })

        break

    return findings


def check_wp_core_integrity(scan_path):
    findings = []
    version_file = os.path.join(scan_path, "wp-includes", "version.php")
    if not os.path.isfile(version_file):
        return findings

    with open(version_file, "r", encoding="utf-8", errors="ignore") as f:
        ver_content = f.read()

    ver_m = _WP_VERSION_RE.search(ver_content)
    if not ver_m:
        return findings

    wp_version = ver_m.group(1)

    try:
        url = _CHECKSUM_API.format(version=wp_version)
        req = Request(url, headers={"User-Agent": "ThemeGuard/1.0"})
        resp = urlopen(req, timeout=10)
        import json
        data = json.loads(resp.read().decode("utf-8"))
    except (URLError, OSError, ValueError):
        findings.append({
            "file": "wp-includes/version.php",
            "line": 0,
            "type": "core_checksum_unavailable",
            "severity": "low",
            "message": f"Could not fetch checksums for WordPress {wp_version} (offline mode)",
        })
        return findings

    checksums = data.get("checksums", {})
    modified = []
    extra = []

    core_dirs = ("wp-admin", "wp-includes")
    for core_dir in core_dirs:
        dir_path = os.path.join(scan_path, core_dir)
        if not os.path.isdir(dir_path):
            continue

        for root, _, files in os.walk(dir_path):
            for fname in files:
                if not fname.endswith(".php"):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, scan_path).replace("\\", "/")

                if rel in checksums:
                    local_md5 = _md5_file(fpath)
                    if local_md5 != checksums[rel]:
                        modified.append(rel)
                else:
                    extra.append(rel)

    for f in modified[:10]:
        findings.append({
            "file": f,
            "line": 0,
            "type": "core_file_modified",
            "severity": "critical",
            "message": f"WordPress core file modified from official v{wp_version}",
        })

    for f in extra[:10]:
        findings.append({
            "file": f,
            "line": 0,
            "type": "core_file_injected",
            "severity": "critical",
            "message": f"Non-official file injected into WordPress core directory",
        })

    return findings


def _md5_file(fpath):
    md5 = hashlib.md5()
    try:
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
        return md5.hexdigest()
    except OSError:
        return ""
