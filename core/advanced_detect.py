import os
import re
import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict

_PHP_SIGS = (b"<?php", b"<?=", b"<? ", b"<?\\n")
_IMAGE_HEADERS = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"BM": "BMP",
    b"RIFF": "WEBP",
}

_C2_POST_RE = re.compile(
    r'(curl_setopt\s*\(.+?CURLOPT_POST\s*,\s*true|'
    r'curl_setopt\s*\(.+?CURLOPT_POSTFIELDS|'
    r'wp_remote_post\s*\(\s*[\'"]https?://|'
    r'file_get_contents\s*\(\s*[\'"]https?://.+?stream_context_create)',
    re.IGNORECASE | re.DOTALL,
)

_C2_DATA_EXFIL_RE = re.compile(
    r'(php_uname|phpinfo|get_current_user|getmypid|getmyuid|'
    r'gethostname|gethostbyname|disk_total_space|disk_free_space|'
    r'posix_getpwuid|posix_getgrgid)\s*\(',
    re.IGNORECASE,
)

_C2_ENCODE_SEND_RE = re.compile(
    r'base64_encode\s*\(.+?(curl_exec|fopen|file_get_contents|wp_remote)',
    re.IGNORECASE | re.DOTALL,
)

_MALWARE_FAMILIES = {
    "wp_vcd": {
        "indicators": ["wp-vcd.php", "class.theme-modules.php", "wp_cd_code", "install_flavor"],
        "min_matches": 2,
        "description": "WP-VCD Malware (theme/plugin dropper)",
    },
    "flavor": {
        "indicators": ["theme-flavor", "flavor_flavor", "flavor_flavor_hook", "flavor_flavor_plugin"],
        "min_matches": 2,
        "description": "Flavor Malware Distribution",
    },
    "anonymousfox": {
        "indicators": ["AnonymousFox", "Fox.php", "cpanel", "/home/", "passwd"],
        "min_matches": 3,
        "description": "AnonymousFox Backdoor Kit",
    },
    "filesman": {
        "indicators": ["FilesMan", "WSO ", "Web Shell", "wso_version"],
        "min_matches": 2,
        "description": "WSO FilesMan Webshell",
    },
    "c99": {
        "indicators": ["c99shell", "c99_buff_prepare", "c99sh_", "c99ftpbrutecheck"],
        "min_matches": 1,
        "description": "c99 Webshell",
    },
    "r57": {
        "indicators": ["r57shell", "r57_", "Safe_Mode Bypass"],
        "min_matches": 1,
        "description": "r57 Webshell",
    },
    "alfa": {
        "indicators": ["AlfaTeam", "Alfa Shell", "alfa_jb", "STARTER"],
        "min_matches": 2,
        "description": "Alfa Shell Webshell",
    },
    "b374k": {
        "indicators": ["b374k", "b374k shell", "b374k_config"],
        "min_matches": 1,
        "description": "b374k Mini Shell",
    },
    "leaf_mailer": {
        "indicators": ["LeafMailer", "Leaf Mailer", "leaf_mailer", "PHPMailer"],
        "min_matches": 2,
        "description": "Leaf Mailer Spam Tool",
    },
    "seo_spam": {
        "indicators": ["pharma", "viagra", "cialis", "casino spam", "poker"],
        "min_matches": 2,
        "description": "SEO Spam / Pharma Hack",
    },
}


def detect_polyglot_files(scan_path):
    findings = []
    image_exts = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico")

    for root, _, files in os.walk(scan_path):
        for fname in files:
            if not fname.lower().endswith(image_exts):
                continue

            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, scan_path)

            try:
                with open(fpath, "rb") as f:
                    data = f.read(min(os.path.getsize(fpath), 524288))
            except OSError:
                continue

            fmt = _identify_format(data[:8])
            if not fmt:
                continue

            php_found = False
            for sig in _PHP_SIGS:
                pos = data.find(sig)
                if pos > 0:
                    php_found = True
                    snippet_start = max(0, pos)
                    snippet = data[snippet_start:snippet_start + 80]
                    findings.append({
                        "file": rel,
                        "line": 0,
                        "type": "polyglot_php_in_image",
                        "severity": "critical",
                        "message": f"PHP code hidden inside {fmt} image at byte offset {pos}",
                        "match": snippet.decode("utf-8", errors="replace")[:80],
                    })
                    break

            if not php_found:
                php_check = data.lower()
                if b"eval(" in php_check or b"system(" in php_check or b"base64_decode(" in php_check:
                    findings.append({
                        "file": rel,
                        "line": 0,
                        "type": "suspicious_image_content",
                        "severity": "high",
                        "message": f"{fmt} image contains PHP function names in binary data",
                    })

    return findings


def build_infection_timeline(scan_path):
    findings = []
    timestamps = []

    for root, _, files in os.walk(scan_path):
        for fname in files:
            if not fname.endswith((".php", ".js", ".html", ".htm")):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, scan_path)
            try:
                stat = os.stat(fpath)
                mtime = datetime.fromtimestamp(stat.st_mtime)
                ctime = datetime.fromtimestamp(stat.st_ctime)
                timestamps.append({
                    "file": rel,
                    "mtime": mtime,
                    "ctime": ctime,
                    "size": stat.st_size,
                })
            except OSError:
                continue

    if not timestamps:
        return findings

    timestamps.sort(key=lambda x: x["mtime"])

    mtimes_only = [t["mtime"] for t in timestamps]
    if len(mtimes_only) < 3:
        return findings

    time_diffs = []
    for i in range(1, len(mtimes_only)):
        diff = (mtimes_only[i] - mtimes_only[i - 1]).total_seconds()
        time_diffs.append(diff)

    avg_gap = sum(time_diffs) / len(time_diffs)

    clusters = []
    current_cluster = [timestamps[0]]
    for i in range(1, len(timestamps)):
        gap = (timestamps[i]["mtime"] - timestamps[i - 1]["mtime"]).total_seconds()
        if gap < 60:
            current_cluster.append(timestamps[i])
        else:
            if len(current_cluster) >= 3:
                clusters.append(current_cluster)
            current_cluster = [timestamps[i]]
    if len(current_cluster) >= 3:
        clusters.append(current_cluster)

    for cluster in clusters:
        start = cluster[0]["mtime"]
        end = cluster[-1]["mtime"]
        duration = (end - start).total_seconds()

        if duration < 120 and len(cluster) >= 5:
            file_list = ", ".join(c["file"] for c in cluster[:5])
            findings.append({
                "file": cluster[0]["file"],
                "line": 0,
                "type": "infection_burst",
                "severity": "critical",
                "message": (
                    f"Infection burst: {len(cluster)} files modified in {int(duration)}s "
                    f"at {start.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"({file_list})"
                ),
            })

    night_mods = [t for t in timestamps if t["mtime"].hour >= 1 and t["mtime"].hour <= 5]
    if len(night_mods) >= 3:
        file_list = ", ".join(t["file"] for t in night_mods[:5])
        findings.append({
            "file": night_mods[0]["file"],
            "line": 0,
            "type": "offhours_modification",
            "severity": "high",
            "message": f"{len(night_mods)} files modified between 01:00-05:00 ({file_list})",
        })

    return findings


def detect_c2_channels(content, filename):
    findings = []

    if _C2_POST_RE.search(content):
        sysinfo = _C2_DATA_EXFIL_RE.findall(content)
        if sysinfo:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "c2_data_exfiltration",
                "severity": "critical",
                "message": f"Data exfil: collects {', '.join(set(sysinfo)[:4])} and sends via POST",
            })
        else:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "c2_outbound_post",
                "severity": "high",
                "message": "Outbound POST to external server detected",
            })

    if _C2_ENCODE_SEND_RE.search(content):
        findings.append({
            "file": filename,
            "line": 0,
            "type": "c2_encoded_exfil",
            "severity": "critical",
            "message": "Data encoded (base64) before sending to external server",
        })

    beacon_re = re.compile(
        r'(sleep|usleep|time_nanosleep)\s*\(.+?(curl|fopen|file_get_contents|wp_remote)',
        re.IGNORECASE | re.DOTALL,
    )
    if beacon_re.search(content):
        findings.append({
            "file": filename,
            "line": 0,
            "type": "c2_beacon",
            "severity": "critical",
            "message": "Timed beacon: sleep() followed by network call (C2 heartbeat)",
        })

    return findings


def classify_malware_family(content, filename):
    findings = []
    content_lower = content.lower()

    for family, info in _MALWARE_FAMILIES.items():
        matched = sum(1 for ind in info["indicators"] if ind.lower() in content_lower)
        if matched >= info["min_matches"]:
            confidence = min(100, int((matched / len(info["indicators"])) * 100))
            findings.append({
                "file": filename,
                "line": 0,
                "type": f"malware_family_{family}",
                "severity": "critical",
                "message": f"Malware identified: {info['description']} ({confidence}% confidence, {matched} indicators)",
            })

    return findings


def auto_generate_rule(findings, output_dir):
    if not findings:
        return 0

    grouped = defaultdict(list)
    for f in findings:
        if f.get("severity") in ("critical", "high") and f.get("match"):
            grouped[f["type"]].append(f)

    rules_written = 0
    output_path = os.path.join(output_dir, "auto_generated.tgr")
    lines = []

    for threat_type, matches in grouped.items():
        if not matches:
            continue

        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', threat_type)
        unique_strings = set()
        for m in matches:
            snippet = m.get("match", "")
            cleaned = snippet.strip()[:80]
            if len(cleaned) >= 6 and '"' not in cleaned:
                unique_strings.add(cleaned)

        if not unique_strings:
            continue

        lines.append(f"rule auto_{rule_name} : autogenerated {{")
        lines.append(f'    severity = "high"')
        lines.append(f'    description = "Auto-generated rule from scan findings: {threat_type}"')
        lines.append(f"    strings:")

        for i, s in enumerate(list(unique_strings)[:5]):
            safe = s.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'        $s{i + 1} = "{safe}" nocase')

        lines.append(f"    condition:")
        lines.append(f"        any of them")
        lines.append(f"}}")
        lines.append("")
        rules_written += 1

    if lines:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    return rules_written


def _identify_format(header_bytes):
    for sig, fmt in _IMAGE_HEADERS.items():
        if header_bytes[:len(sig)] == sig:
            return fmt
    return None
