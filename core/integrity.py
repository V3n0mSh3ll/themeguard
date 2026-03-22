import hashlib
import os
import re

_NON_THEME_FILES = {
    "wp-config.php", "wp-login.php", "wp-cron.php", "wp-settings.php",
    "wp-load.php", "wp-blog-header.php", "wp-mail.php", "wp-links-opml.php",
    "wp-signup.php", "wp-activate.php", "wp-trackback.php",
    "xmlrpc.php", "wp-comments-post.php",
}

_NON_THEME_DIRS = {"wp-admin", "wp-includes", "wp-content/plugins"}

_CORE_TAMPERING = [
    (r"remove_action\s*\(\s*['\"]wp_head['\"]", "Removing wp_head hooks"),
    (r"add_action\s*\(\s*['\"]init['\"].*(?:eval|base64|exec)", "Malicious code on init hook"),
    (r"add_action\s*\(\s*['\"]wp_footer['\"].*eval", "Eval injection in footer hook"),
    (r"wp_enqueue_script\s*\(.*https?://(?!.*(?:googleapis|cdnjs|cloudflare|wordpress))", "External script from non-CDN source"),
    (r"update_option\s*\(\s*['\"](?:siteurl|home|admin_email)['\"]", "Modifying critical WP options"),
    (r"wp_insert_user\s*\(", "Creating users programmatically"),
    (r"add_role\s*\(.*['\"]administrator['\"]", "Adding administrator role"),
]


def check_integrity(content, rel_path, fpath, theme_root):
    findings = []
    fname = os.path.basename(fpath).lower()

    if fname in _NON_THEME_FILES:
        findings.append({
            "type": "non_theme_file",
            "category": "integrity",
            "severity": "critical",
            "message": f"WordPress core file found in theme: {fname}",
            "file": rel_path,
            "line": 0,
        })

    for bad_dir in _NON_THEME_DIRS:
        if os.path.isdir(os.path.join(theme_root, bad_dir)):
            findings.append({
                "type": "non_theme_directory",
                "category": "integrity",
                "severity": "critical",
                "message": f"WordPress core directory inside theme: {bad_dir}/",
                "file": bad_dir,
                "line": 0,
            })

    lines = content.split("\n")
    for pattern, desc in _CORE_TAMPERING:
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "type": "core_tampering",
                    "category": "integrity",
                    "severity": "high",
                    "message": desc,
                    "file": rel_path,
                    "line": line_num,
                    "match": line.strip()[:200],
                })
                break

    return findings


def hash_file(fpath):
    sha = hashlib.sha256()
    try:
        with open(fpath, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except OSError:
        return None
