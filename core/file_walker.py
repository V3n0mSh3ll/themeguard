import os

from utils.config import SCAN_EXTENSIONS, SKIP_DIRS, MAX_FILE_SIZE

_BAD_FILENAMES = {
    "wp-tmp.php", "wp-vcd.php", "class.theme-modules.php",
    "wp-feed.php", "wp-conf.php", "db.php", "diff.php",
    "error_log.php", "admin.php", "shell.php", "cmd.php",
    "c99.php", "r57.php", "wso.php", "alfa.php", "b374k.php",
    "config.bak.php", "wp-config.bak", "xmlrpc.php",
}

_PHP_EXTENSIONS = {"php", "php3", "php4", "php5", "php7", "phtml"}
_IMG_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "ico", "bmp"}
_IMG_DIRS = {"images", "img", "assets/img", "assets/images", "uploads"}


def walk_theme(path):
    if not os.path.isdir(path):
        if _is_scannable(path):
            yield path
        return

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            if _is_scannable(fpath):
                yield fpath


def count_files(path):
    return sum(1 for _ in walk_theme(path))


def detect_suspicious_names(fpath, theme_root):
    findings = []
    fname = os.path.basename(fpath).lower()
    rel_path = os.path.relpath(fpath, theme_root)

    parts = fname.split(".")
    if len(parts) > 2:
        has_php = any(p in _PHP_EXTENSIONS for p in parts)
        has_img = any(p in _IMG_EXTENSIONS for p in parts)
        if has_php and has_img:
            findings.append({
                "type": "suspicious_filename",
                "severity": "high",
                "message": f"Double extension detected: {fname}",
                "file": rel_path,
                "detail": "PHP code hidden behind image extension",
            })

    if fname in _BAD_FILENAMES:
        findings.append({
            "type": "suspicious_filename",
            "severity": "high",
            "message": f"Known malicious filename: {fname}",
            "file": rel_path,
            "detail": "File matches known backdoor naming conventions",
        })

    if fname.startswith(".") and fname not in {".htaccess", ".htpasswd"}:
        findings.append({
            "type": "hidden_file",
            "severity": "medium",
            "message": f"Hidden file detected: {fname}",
            "file": rel_path,
            "detail": "Dot-prefixed file may hide malicious content",
        })

    dir_lower = os.path.dirname(rel_path).lower()
    if any(d in dir_lower for d in _IMG_DIRS) and fname.endswith(".php"):
        findings.append({
            "type": "misplaced_php",
            "severity": "critical",
            "message": f"PHP file in image/upload directory: {rel_path}",
            "file": rel_path,
            "detail": "PHP executable in non-code directory is a strong backdoor indicator",
        })

    return findings


def _is_scannable(fpath):
    ext = os.path.splitext(fpath)[1].lower()
    if ext not in SCAN_EXTENSIONS:
        return False
    try:
        size = os.path.getsize(fpath)
        return 0 < size <= MAX_FILE_SIZE
    except OSError:
        return False
