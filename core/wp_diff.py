import os
import re
import hashlib
import zipfile
import tempfile
from urllib.request import urlopen, Request
from urllib.error import URLError

_WP_API = "https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]={slug}"
_WP_DOWNLOAD = "https://downloads.wordpress.org/theme/{slug}.{version}.zip"
_PLUGIN_API = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"

_STYLE_NAME_RE = re.compile(r"Theme\s*Name\s*:\s*(.+)", re.IGNORECASE)
_STYLE_VERSION_RE = re.compile(r"Version\s*:\s*(.+)", re.IGNORECASE)
_PLUGIN_NAME_RE = re.compile(r"Plugin\s*Name\s*:\s*(.+)", re.IGNORECASE)
_PLUGIN_VERSION_RE = re.compile(r"Version\s*:\s*(.+)", re.IGNORECASE)


def diff_against_official(scan_path, scan_type="theme"):
    findings = []
    meta = _extract_meta(scan_path, scan_type)
    if not meta:
        return findings

    slug = _slugify(meta["name"])
    version = meta["version"]

    try:
        zip_data = _download_official(slug, version, scan_type)
    except (URLError, OSError, ValueError):
        findings.append({
            "file": "",
            "line": 0,
            "type": "wp_diff_unavailable",
            "severity": "low",
            "message": f"Could not download official {scan_type} '{slug}' v{version} for comparison",
        })
        return findings

    added, modified, missing = _compare_with_zip(scan_path, zip_data, slug)

    for f in added:
        findings.append({
            "file": f,
            "line": 0,
            "type": "wp_diff_added",
            "severity": "high",
            "message": f"File not in official release: {f}",
        })

    for f in modified:
        findings.append({
            "file": f,
            "line": 0,
            "type": "wp_diff_modified",
            "severity": "high",
            "message": f"File modified from official release: {f}",
        })

    for f in missing:
        findings.append({
            "file": f,
            "line": 0,
            "type": "wp_diff_missing",
            "severity": "medium",
            "message": f"Official file missing from this copy: {f}",
        })

    return findings


def _extract_meta(scan_path, scan_type):
    if scan_type == "theme":
        style = os.path.join(scan_path, "style.css")
        if not os.path.isfile(style):
            return None
        with open(style, "r", encoding="utf-8", errors="ignore") as f:
            header = f.read(4096)
        name_m = _STYLE_NAME_RE.search(header)
        ver_m = _STYLE_VERSION_RE.search(header)
    else:
        main_file = _find_plugin_header(scan_path)
        if not main_file:
            return None
        with open(main_file, "r", encoding="utf-8", errors="ignore") as f:
            header = f.read(4096)
        name_m = _PLUGIN_NAME_RE.search(header)
        ver_m = _PLUGIN_VERSION_RE.search(header)

    if not name_m or not ver_m:
        return None

    return {
        "name": name_m.group(1).strip(),
        "version": ver_m.group(1).strip(),
    }


def _find_plugin_header(scan_path):
    for fname in os.listdir(scan_path):
        if not fname.endswith(".php"):
            continue
        fpath = os.path.join(scan_path, fname)
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(2048)
            if _PLUGIN_NAME_RE.search(content):
                return fpath
        except OSError:
            continue
    return None


def _slugify(name):
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def _download_official(slug, version, scan_type):
    if scan_type == "theme":
        url = _WP_DOWNLOAD.format(slug=slug, version=version)
    else:
        url = f"https://downloads.wordpress.org/plugin/{slug}.{version}.zip"

    req = Request(url, headers={"User-Agent": "ThemeGuard/1.0"})
    response = urlopen(req, timeout=15)
    return response.read()


def _compare_with_zip(scan_path, zip_data, slug):
    added = []
    modified = []
    missing = []

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(zip_data)
        tmp_path = tmp.name

    try:
        official_hashes = {}
        with zipfile.ZipFile(tmp_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                rel = info.filename
                if rel.startswith(slug + "/"):
                    rel = rel[len(slug) + 1:]
                if not rel:
                    continue
                data = zf.read(info.filename)
                official_hashes[rel] = hashlib.sha256(data).hexdigest()

        local_hashes = {}
        for root, _, files in os.walk(scan_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, scan_path).replace("\\", "/")
                if rel.startswith("."):
                    continue
                try:
                    with open(fpath, "rb") as f:
                        local_hashes[rel] = hashlib.sha256(f.read()).hexdigest()
                except OSError:
                    continue

        for rel, h in local_hashes.items():
            if rel not in official_hashes:
                added.append(rel)
            elif official_hashes[rel] != h:
                modified.append(rel)

        for rel in official_hashes:
            if rel not in local_hashes:
                missing.append(rel)

    finally:
        os.unlink(tmp_path)

    return added, modified, missing
