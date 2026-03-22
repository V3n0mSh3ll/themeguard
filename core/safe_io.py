import os
import re
import json
import hashlib
import logging

_log = logging.getLogger("themeguard.safe_io")

MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_DECODE_OUTPUT = 65536
MAX_JSON_SIZE = 2 * 1024 * 1024
MAX_REGEX_LEN = 2000
REGEX_TIMEOUT_CHARS = 500000

_ENCODINGS = ("utf-8", "utf-8-sig", "utf-16", "latin-1")


def safe_read_text(fpath, max_size=MAX_FILE_SIZE):
    try:
        real = os.path.realpath(fpath)
        if os.path.islink(fpath) and not _symlink_safe(fpath, real):
            _log.warning("Symlink escape blocked: %s -> %s", fpath, real)
            return None

        size = os.path.getsize(real)
        if size == 0:
            return ""
        if size > max_size:
            _log.info("File too large (%d bytes), skipped: %s", size, fpath)
            return None

        with open(real, "rb") as f:
            raw = f.read(max_size)

        for enc in _ENCODINGS:
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, UnicodeError):
                continue

        return raw.decode("utf-8", errors="replace")

    except OSError as exc:
        _log.warning("Cannot read %s: %s", fpath, exc)
        return None


def safe_read_binary(fpath, max_size=MAX_FILE_SIZE):
    try:
        real = os.path.realpath(fpath)
        if os.path.islink(fpath) and not _symlink_safe(fpath, real):
            return None

        size = os.path.getsize(real)
        if size > max_size:
            return None

        with open(real, "rb") as f:
            return f.read(max_size)

    except OSError as exc:
        _log.warning("Cannot read binary %s: %s", fpath, exc)
        return None


def safe_load_json(fpath, default=None):
    if not os.path.isfile(fpath):
        return default

    try:
        size = os.path.getsize(fpath)
        if size > MAX_JSON_SIZE:
            _log.warning("JSON file too large (%d bytes): %s", size, fpath)
            return default
    except OSError:
        return default

    for enc in _ENCODINGS:
        try:
            with open(fpath, "r", encoding=enc) as f:
                return json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError, UnicodeError):
            continue
        except OSError as exc:
            _log.warning("Cannot read JSON %s: %s", fpath, exc)
            return default

    _log.warning("Failed to decode JSON with any encoding: %s", fpath)
    return default


def safe_write_json(fpath, data):
    try:
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        tmp = fpath + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        if os.path.isfile(fpath):
            os.replace(tmp, fpath)
        else:
            os.rename(tmp, fpath)
        return True
    except OSError as exc:
        _log.warning("Cannot write JSON %s: %s", fpath, exc)
        return False


def safe_compile_regex(pattern, flags=0):
    if len(pattern) > MAX_REGEX_LEN:
        _log.warning("Regex too long (%d chars), skipped", len(pattern))
        return None
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        _log.debug("Invalid regex '%s': %s", pattern[:60], exc)
        return None


def safe_regex_search(compiled, text, max_chars=REGEX_TIMEOUT_CHARS):
    if len(text) > max_chars:
        text = text[:max_chars]
    try:
        return compiled.search(text)
    except (re.error, RecursionError):
        return None


def safe_regex_findall(compiled, text, max_chars=REGEX_TIMEOUT_CHARS):
    if len(text) > max_chars:
        text = text[:max_chars]
    try:
        return compiled.findall(text)
    except (re.error, RecursionError):
        return []


def normalize_path(path):
    path = os.path.normpath(path)
    path = path.replace("\\", "/")
    parts = path.split("/")
    clean = []
    for part in parts:
        if part == "..":
            continue
        if part in (".", ""):
            continue
        clean.append(part)
    return "/".join(clean)


def is_path_traversal(path):
    norm = os.path.normpath(path)
    return ".." in norm.split(os.sep)


def check_decompression_bomb(data, max_ratio=100, max_output=MAX_DECODE_OUTPUT):
    if not data:
        return False
    if len(data) > max_output:
        return True
    return False


def file_sha256(fpath):
    h = hashlib.sha256()
    try:
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def content_sha256(content):
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def stable_finding_id(finding):
    parts = [
        finding.get("file", ""),
        str(finding.get("line", 0)),
        finding.get("type", ""),
        finding.get("message", "")[:100],
    ]
    raw = "|".join(parts)
    return "TG-" + hashlib.md5(raw.encode()).hexdigest()[:10].upper()


def _symlink_safe(link_path, real_path):
    link_dir = os.path.dirname(os.path.abspath(link_path))
    real_dir = os.path.dirname(os.path.abspath(real_path))
    common = os.path.commonpath([link_dir, real_dir])
    return real_dir.startswith(common)


class ErrorCollector:

    def __init__(self):
        self.errors = []
        self._max = 500

    def add(self, category, file_path, message, exc=None):
        if len(self.errors) >= self._max:
            return
        entry = {
            "category": category,
            "file": file_path,
            "message": message,
        }
        if exc:
            entry["exception"] = f"{type(exc).__name__}: {exc}"
        self.errors.append(entry)
        _log.warning("[%s] %s: %s", category, file_path, message)

    def get_summary(self):
        cats = {}
        for e in self.errors:
            c = e["category"]
            cats[c] = cats.get(c, 0) + 1
        return {
            "total_errors": len(self.errors),
            "categories": cats,
            "errors": self.errors[:50],
        }

    def clear(self):
        self.errors.clear()
