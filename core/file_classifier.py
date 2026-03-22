import os
import re

_TEXT_EXTS = {
    ".php", ".phtml", ".inc", ".module", ".install", ".profile",
    ".js", ".jsx", ".ts", ".tsx", ".mjs",
    ".html", ".htm", ".tpl", ".twig",
    ".css", ".scss", ".less",
    ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg",
    ".txt", ".md", ".csv", ".sql", ".sh", ".bat",
    ".htaccess", ".htpasswd",
}

_BINARY_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".gz", ".tar", ".rar", ".7z", ".bz2",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
    ".exe", ".dll", ".so", ".pyc", ".pyo",
    ".map",
}

_SCANNABLE_EXTS = {
    ".php", ".phtml", ".inc", ".module", ".install",
    ".js", ".jsx", ".mjs",
    ".html", ".htm", ".tpl", ".twig",
}

_MINIFIED_RE = re.compile(r'^.{500,}$', re.MULTILINE)


class FileClassifier:

    def classify(self, fpath):
        ext = os.path.splitext(fpath)[1].lower()
        fname = os.path.basename(fpath).lower()
        result = {
            "path": fpath,
            "extension": ext,
            "is_text": ext in _TEXT_EXTS or ext == "",
            "is_binary": ext in _BINARY_EXTS,
            "is_scannable": ext in _SCANNABLE_EXTS,
            "is_minified": False,
            "is_vendor": False,
            "is_config": False,
            "is_wp_core": False,
            "risk_priority": "normal",
        }

        rel = fpath.replace("\\", "/").lower()

        if "/vendor/" in rel or "/node_modules/" in rel:
            result["is_vendor"] = True
            result["risk_priority"] = "low"

        if fname in ("wp-config.php", ".htaccess", ".htpasswd"):
            result["is_config"] = True
            result["risk_priority"] = "critical"

        if "/wp-admin/" in rel or "/wp-includes/" in rel:
            result["is_wp_core"] = True

        if fname in ("functions.php", "admin-ajax.php", "wp-login.php"):
            result["risk_priority"] = "high"

        if "/uploads/" in rel or "/mu-plugins/" in rel:
            result["risk_priority"] = "high"

        if ext in (".min.js", ".min.css") or fname.endswith(".min.js") or fname.endswith(".min.css"):
            result["is_minified"] = True
            result["risk_priority"] = "low"

        return result

    def is_minified_content(self, content):
        if not content:
            return False

        lines = content.split("\n")
        if len(lines) < 5:
            long = sum(1 for l in lines if len(l) > 500)
            if long > 0:
                return True

        if _MINIFIED_RE.search(content[:5000]):
            avg_len = len(content) / max(1, len(lines))
            if avg_len > 300:
                return True

        return False

    def should_deep_scan(self, info):
        if info.get("is_binary"):
            return False
        if not info.get("is_scannable"):
            return False
        if info.get("is_vendor") and info.get("risk_priority") == "low":
            return False
        return True
