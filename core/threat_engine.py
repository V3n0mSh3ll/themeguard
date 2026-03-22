import os
import re
import math
import hashlib
from collections import Counter

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


def load_rules(extra_dirs=None):
    rules = []
    dirs = [_RULES_DIR]
    if extra_dirs:
        dirs.extend(extra_dirs)

    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fname in sorted(os.listdir(d)):
            if not fname.endswith(".tgr"):
                continue
            fpath = os.path.join(d, fname)
            try:
                parsed = _parse_rule_file(fpath)
                rules.extend(parsed)
            except (OSError, ValueError):
                continue

    return rules


def scan_with_rules(content, filename, rules=None):
    if rules is None:
        rules = load_rules()

    findings = []
    content_bytes = content.encode("utf-8", errors="ignore")
    file_size = len(content_bytes)

    for rule in rules:
        if rule.get("private"):
            continue

        tags = rule.get("tags", [])
        hit, matched_strings = _evaluate_rule(content, content_bytes, file_size, rule)
        if not hit:
            continue

        msg = rule.get("description", f"Rule match: {rule['name']}")
        if matched_strings:
            msg += f" [{len(matched_strings)} string(s) matched]"

        findings.append({
            "file": filename,
            "line": _find_first_line(content, matched_strings),
            "type": f"tg_{rule['name']}",
            "severity": rule.get("severity", "high"),
            "message": msg,
            "match": "; ".join(matched_strings[:3]) if matched_strings else "",
        })

    return findings


def cross_file_scan(file_contents, rules=None):
    if rules is None:
        rules = load_rules()

    all_findings = []
    global_matches = {}

    for filename, content in file_contents.items():
        content_bytes = content.encode("utf-8", errors="ignore")
        for rule in rules:
            if not rule.get("global"):
                continue
            hit, matched = _evaluate_rule(content, content_bytes, len(content_bytes), rule)
            if hit:
                if rule["name"] not in global_matches:
                    global_matches[rule["name"]] = []
                global_matches[rule["name"]].append(filename)

    for rule_name, files in global_matches.items():
        if len(files) > 1:
            all_findings.append({
                "file": ", ".join(files[:5]),
                "line": 0,
                "type": "cross_file_correlation",
                "severity": "critical",
                "message": f"Rule '{rule_name}' triggered across {len(files)} files (coordinated backdoor)",
            })

    return all_findings


def behavioral_scan(content, filename):
    findings = []
    _check_taint_flow(content, filename, findings)
    _check_polymorphic(content, filename, findings)
    _check_entropy_blocks(content, filename, findings)
    _check_steganographic(content, filename, findings)
    _check_timing_attacks(content, filename, findings)
    return findings


def _evaluate_rule(content, content_bytes, file_size, rule):
    strings = rule.get("strings", [])
    condition = rule.get("condition", "any of them")
    matched = []
    match_counts = {}
    match_offsets = {}

    for s in strings:
        hits, count, offsets = _match_string(content, content_bytes, s)
        if hits:
            matched.extend(hits[:2])
        match_counts[s.get("id", "")] = count
        match_offsets[s.get("id", "")] = offsets

    return _eval_condition(condition, match_counts, match_offsets, file_size, len(strings)), matched


def _match_string(content, content_bytes, s):
    stype = s.get("type", "text")
    hits = []
    offsets = []

    if stype == "text":
        hits, offsets = _match_text(content, content_bytes, s)
    elif stype == "hex":
        hits, offsets = _match_hex(content_bytes, s)
    elif stype == "regex":
        hits, offsets = _match_regex(content, s)

    return hits, len(hits), offsets


def _match_text(content, content_bytes, s):
    pattern = s["pattern"]
    hits = []
    offsets = []
    nocase = s.get("nocase", False)
    wide = s.get("wide", False)
    fullword = s.get("fullword", False)
    xor_range = s.get("xor", None)
    b64 = s.get("base64", False)

    targets = [pattern]

    if xor_range:
        low, high = xor_range
        for key in range(low, high + 1):
            targets.append("".join(chr(ord(c) ^ key) for c in pattern))

    if b64:
        import base64
        encoded = base64.b64encode(pattern.encode()).decode()
        targets.append(encoded)

    for target in targets:
        if wide:
            wide_bytes = target.encode("utf-16-le")
            idx = 0
            while True:
                pos = content_bytes.find(wide_bytes, idx)
                if pos == -1:
                    break
                if fullword and not _is_fullword_bytes(content_bytes, pos, len(wide_bytes)):
                    idx = pos + 1
                    continue
                hits.append(target[:60])
                offsets.append(pos)
                idx = pos + 1
        else:
            search_in = content.lower() if nocase else content
            search_for = target.lower() if nocase else target
            idx = 0
            while True:
                pos = search_in.find(search_for, idx)
                if pos == -1:
                    break
                if fullword and not _is_fullword(content, pos, len(target)):
                    idx = pos + 1
                    continue
                hits.append(target[:60])
                offsets.append(pos)
                idx = pos + 1

    return hits, offsets


def _match_hex(content_bytes, s):
    hex_str = s["pattern"].replace(" ", "").replace("?", ".")
    hits = []
    offsets = []

    if "." in hex_str:
        regex_parts = []
        for i in range(0, len(hex_str), 2):
            pair = hex_str[i:i + 2]
            if "." in pair:
                regex_parts.append(b".")
            else:
                regex_parts.append(re.escape(bytes.fromhex(pair)))
        pattern = b"".join(regex_parts)
        for m in re.finditer(pattern, content_bytes):
            hits.append(m.group()[:30].hex())
            offsets.append(m.start())
    else:
        try:
            needle = bytes.fromhex(hex_str)
            idx = 0
            while True:
                pos = content_bytes.find(needle, idx)
                if pos == -1:
                    break
                hits.append(needle[:30].hex())
                offsets.append(pos)
                idx = pos + 1
        except ValueError:
            pass

    return hits, offsets


def _match_regex(content, s):
    flags = 0
    if "i" in s.get("flags", ""):
        flags |= re.IGNORECASE
    if "s" in s.get("flags", ""):
        flags |= re.DOTALL

    hits = []
    offsets = []
    try:
        for m in re.finditer(s["pattern"], content, flags):
            hits.append(m.group()[:60])
            offsets.append(m.start())
            if len(hits) >= 50:
                break
    except re.error:
        pass

    return hits, offsets


def _is_fullword(content, pos, length):
    if pos > 0 and (content[pos - 1].isalnum() or content[pos - 1] == "_"):
        return False
    end = pos + length
    if end < len(content) and (content[end].isalnum() or content[end] == "_"):
        return False
    return True


def _is_fullword_bytes(data, pos, length):
    if pos > 0 and (data[pos - 1:pos].isalnum() or data[pos - 1:pos] == b"_"):
        return False
    end = pos + length
    if end < len(data) and (data[end:end + 1].isalnum() or data[end:end + 1] == b"_"):
        return False
    return True


def _eval_condition(condition, counts, offsets, file_size, total_strings):
    condition = condition.strip()

    if "filesize" in condition:
        m = re.search(r"filesize\s*([<>=!]+)\s*(\d+)([KMG]?B?)", condition)
        if m:
            op, val, unit = m.group(1), int(m.group(2)), m.group(3).upper()
            multipliers = {"": 1, "B": 1, "KB": 1024, "MB": 1048576, "GB": 1073741824}
            val *= multipliers.get(unit, 1)
            if not _compare(file_size, op, val):
                return False
            remaining = condition.replace(m.group(), "").strip()
            if remaining.startswith("and"):
                condition = remaining[3:].strip()
            elif not remaining:
                return True

    for sid, count in counts.items():
        if not sid:
            continue
        pattern = rf"#{re.escape(sid)}\s*([<>=!]+)\s*(\d+)"
        m = re.search(pattern, condition)
        if m:
            if not _compare(count, m.group(1), int(m.group(2))):
                return False

        pattern = rf"@{re.escape(sid)}\s*([<>=!]+)\s*(\d+)"
        m = re.search(pattern, condition)
        if m:
            first_offset = offsets.get(sid, [None])[0]
            if first_offset is None or not _compare(first_offset, m.group(1), int(m.group(2))):
                return False

    active = [c for c in counts.values() if c > 0]

    if "all of them" in condition:
        return len(active) == total_strings and total_strings > 0

    if "any of them" in condition:
        return len(active) > 0

    m = re.search(r"(\d+)\s+of\s+them", condition)
    if m:
        return len(active) >= int(m.group(1))

    m = re.search(r"for\s+(\w+)\s+of\s+them\s*:\s*\(\s*#\s*([<>=!]+)\s*(\d+)\s*\)", condition)
    if m:
        quantifier, op, val = m.group(1), m.group(2), int(m.group(3))
        matching = [c for c in counts.values() if _compare(c, op, val)]
        if quantifier == "all":
            return len(matching) == total_strings
        if quantifier == "any":
            return len(matching) > 0
        try:
            return len(matching) >= int(quantifier)
        except ValueError:
            pass

    return len(active) > 0


def _compare(a, op, b):
    ops = {
        ">": lambda x, y: x > y,
        "<": lambda x, y: x < y,
        ">=": lambda x, y: x >= y,
        "<=": lambda x, y: x <= y,
        "==": lambda x, y: x == y,
        "!=": lambda x, y: x != y,
        "=": lambda x, y: x == y,
    }
    return ops.get(op, lambda x, y: False)(a, b)


def _find_first_line(content, matched_strings):
    if not matched_strings:
        return 0
    first = matched_strings[0]
    idx = content.find(first)
    if idx == -1:
        return 0
    return content[:idx].count("\n") + 1


def _parse_rule_file(fpath):
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()

    rules = []
    blocks = re.finditer(
        r"(private\s+|global\s+)?rule\s+(\w+)\s*(?::\s*([\w\s]+))?\s*\{"
        r"\s*(.*?)\bstrings\s*:\s*(.*?)\bcondition\s*:\s*(.*?)\}",
        content,
        re.DOTALL,
    )

    for block in blocks:
        prefix = (block.group(1) or "").strip()
        name = block.group(2)
        tags = block.group(3).split() if block.group(3) else []
        meta_raw = block.group(4)
        strings_raw = block.group(5)
        condition_raw = block.group(6).strip()

        severity = "high"
        description = f"Rule: {name}"
        for line in meta_raw.split("\n"):
            line = line.strip()
            if line.startswith("severity"):
                sev = re.search(r'["\'](\w+)["\']', line)
                if sev:
                    severity = sev.group(1)
            elif line.startswith("description"):
                desc = re.search(r'["\'](.+?)["\']', line)
                if desc:
                    description = desc.group(1)

        strings = _parse_strings(strings_raw)

        rules.append({
            "name": name,
            "severity": severity,
            "description": description,
            "strings": strings,
            "condition": condition_raw,
            "tags": tags,
            "private": prefix == "private",
            "global": prefix == "global",
        })

    return rules


def _parse_strings(raw):
    strings = []
    for line in raw.split("\n"):
        line = line.strip()
        if not line or line.startswith("//"):
            continue

        match = re.match(r'(\$\w+)\s*=\s*"(.+?)"\s*(.*)', line)
        if match:
            sid = match.group(1)
            pattern = match.group(2)
            mods = match.group(3).lower()
            strings.append({
                "id": sid,
                "type": "text",
                "pattern": pattern,
                "nocase": "nocase" in mods,
                "wide": "wide" in mods,
                "fullword": "fullword" in mods,
                "xor": _parse_xor(mods),
                "base64": "base64" in mods,
            })
            continue

        match = re.match(r'(\$\w+)\s*=\s*\{(.+?)\}', line)
        if match:
            strings.append({
                "id": match.group(1),
                "type": "hex",
                "pattern": match.group(2).strip(),
            })
            continue

        match = re.match(r'(\$\w+)\s*=\s*/(.+?)/([is]*)', line)
        if match:
            strings.append({
                "id": match.group(1),
                "type": "regex",
                "pattern": match.group(2),
                "flags": match.group(3),
            })

    return strings


def _parse_xor(mods):
    if "xor" not in mods:
        return None
    m = re.search(r"xor\s*\(\s*(\d+)\s*-\s*(\d+)\s*\)", mods)
    if m:
        return (int(m.group(1)), int(m.group(2)))
    return (0, 255)


def _check_taint_flow(content, filename, findings):
    sources = re.findall(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[\s*[\'"](\w+)[\'"]\s*\]', content)
    sinks = re.findall(
        r'\b(eval|exec|system|passthru|shell_exec|popen|proc_open|assert|'
        r'file_put_contents|fwrite|include|require|preg_replace|unserialize|'
        r'call_user_func|create_function|mysql_query|mysqli_query)\s*\(',
        content, re.IGNORECASE,
    )

    if not sources or not sinks:
        return

    for src_type, src_var in sources:
        for sink in sinks:
            var_pattern = re.compile(
                rf'\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[\s*[\'"]{re.escape(src_var)}[\'"]\s*\]'
                rf'.*?{re.escape(sink)}\s*\(',
                re.DOTALL | re.IGNORECASE,
            )
            if var_pattern.search(content):
                findings.append({
                    "file": filename,
                    "line": 0,
                    "type": "taint_flow",
                    "severity": "critical",
                    "message": f"User input ${src_type}['{src_var}'] flows to {sink}()",
                })
                return


def _check_polymorphic(content, filename, findings):
    indicators = 0

    if re.search(r'(\$\w+)\s*=\s*str_replace\s*\(.+?\1', content):
        indicators += 1
    if re.search(r'(\$\w+)\s*=\s*substr\s*\(.+?\..*?substr', content):
        indicators += 1
    if re.search(r'(\$\w+)\s*=\s*strrev\s*\(.+?\)', content):
        indicators += 1
    if re.search(r'(\$\w+)\s*=\s*str_rot13\s*\(.+?\)', content):
        indicators += 1
    if re.search(r'(\$\w+)\s*\.=\s*chr\s*\(\s*\d+\s*\)', content):
        indicators += 2
    if re.search(r'for\s*\(.+?\)\s*\{\s*\$\w+\s*\.=\s*', content):
        indicators += 2
    if re.search(r'array_map\s*\(\s*[\'"]chr[\'"]\s*,', content):
        indicators += 2

    if indicators >= 3:
        findings.append({
            "file": filename,
            "line": 0,
            "type": "polymorphic_code",
            "severity": "critical",
            "message": f"Polymorphic code construction detected ({indicators} indicators)",
        })


def _check_entropy_blocks(content, filename, findings):
    lines = content.split("\n")
    block_size = 20
    high_entropy_blocks = 0

    for i in range(0, len(lines), block_size):
        block = "\n".join(lines[i:i + block_size])
        if len(block) < 100:
            continue

        ent = _shannon_entropy(block)
        if ent > 5.5:
            high_entropy_blocks += 1

    ratio = high_entropy_blocks / max(1, len(lines) // block_size)

    if ratio > 0.4 and high_entropy_blocks >= 3:
        findings.append({
            "file": filename,
            "line": 0,
            "type": "high_entropy_distribution",
            "severity": "high",
            "message": f"{int(ratio * 100)}% of code blocks have high entropy (likely obfuscated)",
        })


def _check_steganographic(content, filename, findings):
    if not filename.lower().endswith((".php", ".inc", ".phtml")):
        return

    hidden = re.findall(r'<!--\s*([A-Za-z0-9+/=]{100,})\s*-->', content)
    if hidden:
        findings.append({
            "file": filename,
            "line": 0,
            "type": "steganographic_payload",
            "severity": "critical",
            "message": f"{len(hidden)} hidden base64 payload(s) in HTML comments",
        })

    if re.search(r'(\x00|\xff\xfe|\xfe\xff).{50,}(eval|exec|system)', content, re.DOTALL):
        findings.append({
            "file": filename,
            "line": 0,
            "type": "null_byte_injection",
            "severity": "critical",
            "message": "Code hidden after null bytes or BOM markers",
        })


def _check_timing_attacks(content, filename, findings):
    patterns = [
        (r'sleep\s*\(\s*\$', "Variable sleep delay (C2 beacon pattern)"),
        (r'time\s*\(\s*\)\s*%\s*\d+\s*==\s*0', "Time-based trigger (logic bomb)"),
        (r'date\s*\(\s*[\'"][^"\']+[\'"]\s*\)\s*==', "Date-based trigger condition"),
        (r'mktime\s*\(.+?\)\s*[<>=]', "Scheduled payload activation"),
        (r'strtotime\s*\(.+?\)\s*[<>=]', "Time-delayed execution trigger"),
    ]

    for pat, desc in patterns:
        if re.search(pat, content, re.IGNORECASE):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "timing_trigger",
                "severity": "high",
                "message": desc,
            })
            break


def _shannon_entropy(data):
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())
