import os

SCAN_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phps",
    ".js", ".html", ".htm", ".htaccess", ".inc", ".tpl",
}

SKIP_DIRS = {
    "__pycache__", ".git", ".svn", "node_modules", ".idea", ".vscode",
}

MAX_FILE_SIZE = 10 * 1024 * 1024
THREAD_POOL_SIZE = min(8, (os.cpu_count() or 4))
SIGNATURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "signatures")
