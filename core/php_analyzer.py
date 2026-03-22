import re
from collections import Counter

_FUNCTIONS = {
    "code_execution": [
        "eval", "assert", "create_function", "call_user_func", "call_user_func_array",
        "preg_replace", "ob_start", "array_map", "array_filter", "array_walk",
        "usort", "uasort", "uksort", "register_shutdown_function", "register_tick_function",
    ],
    "command_execution": [
        "exec", "system", "passthru", "shell_exec", "popen", "proc_open",
        "pcntl_exec", "pcntl_fork",
    ],
    "file_operations": [
        "file_put_contents", "fwrite", "fputs", "file_get_contents", "fopen",
        "readfile", "include", "require", "include_once", "require_once",
        "move_uploaded_file", "copy", "rename", "unlink", "rmdir", "mkdir",
        "chmod", "chown", "symlink", "link", "tempnam",
    ],
    "network_operations": [
        "curl_init", "curl_exec", "fsockopen", "pfsockopen", "stream_socket_client",
        "socket_create", "socket_connect", "mail", "wp_remote_get", "wp_remote_post",
        "file_get_contents",
    ],
    "encoding_decoding": [
        "base64_decode", "base64_encode", "gzinflate", "gzuncompress", "gzdecode",
        "str_rot13", "convert_uudecode", "rawurldecode", "hex2bin", "pack",
    ],
    "information_disclosure": [
        "phpinfo", "php_uname", "getmyuid", "getmypid", "get_current_user",
        "getenv", "ini_get", "get_cfg_var", "disk_free_space", "disk_total_space",
    ],
    "variable_manipulation": [
        "extract", "parse_str", "putenv", "ini_set", "ini_alter",
        "dl", "set_include_path",
    ],
}

_CATEGORY_MAP = {}
for _cat, _funcs in _FUNCTIONS.items():
    for _fn in _funcs:
        _CATEGORY_MAP[_fn] = _cat

_FUNC_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(f) for f in _CATEGORY_MAP) + r")\s*\(",
    re.IGNORECASE,
)

_RISK_WEIGHTS = {
    "code_execution": 10,
    "command_execution": 15,
    "encoding_decoding": 5,
    "network_operations": 7,
    "file_operations": 3,
    "variable_manipulation": 8,
    "information_disclosure": 2,
}

_WRITE_FUNCS = {"file_put_contents", "fwrite", "fputs", "copy"}


def analyze_php_functions(content, filename):
    findings = []
    lines = content.split("\n")

    calls, locations = _collect_calls(lines)
    if not calls:
        return findings

    categories = {_CATEGORY_MAP[fn] for fn in calls if fn in _CATEGORY_MAP}

    _check_exec_plus_encoding(calls, categories, filename, findings)
    _check_reverse_shell(categories, filename, findings)
    _check_dropper(calls, categories, filename, findings)
    _check_excessive_calls(calls, locations, filename, findings)
    _check_variable_functions(content, filename, findings)
    _check_risk_score(calls, filename, findings)

    return findings


def _collect_calls(lines):
    calls = Counter()
    locations = {}
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        for match in _FUNC_REGEX.finditer(line):
            fn = match.group(1).lower()
            calls[fn] += 1
            if fn not in locations:
                locations[fn] = []
            locations[fn].append(i)
    return calls, locations


def _check_exec_plus_encoding(calls, categories, filename, findings):
    if "code_execution" not in categories or "encoding_decoding" not in categories:
        return
    exec_fns = [f for f in calls if _CATEGORY_MAP.get(f) == "code_execution"]
    enc_fns = [f for f in calls if _CATEGORY_MAP.get(f) == "encoding_decoding"]
    findings.append({
        "file": filename,
        "line": 0,
        "type": "dangerous_combination",
        "severity": "critical",
        "message": f"Code execution + encoding: {', '.join(exec_fns)} with {', '.join(enc_fns)}",
    })


def _check_reverse_shell(categories, filename, findings):
    if "command_execution" in categories and "network_operations" in categories:
        findings.append({
            "file": filename,
            "line": 0,
            "type": "reverse_shell_pattern",
            "severity": "critical",
            "message": "Command execution + network operations detected (reverse shell pattern)",
        })


def _check_dropper(calls, categories, filename, findings):
    if "file_operations" not in categories or "network_operations" not in categories:
        return
    file_fns = [f for f in calls if _CATEGORY_MAP.get(f) == "file_operations"]
    net_fns = [f for f in calls if _CATEGORY_MAP.get(f) == "network_operations"]
    if any(f in _WRITE_FUNCS for f in file_fns):
        findings.append({
            "file": filename,
            "line": 0,
            "type": "dropper_pattern",
            "severity": "critical",
            "message": f"File write + network fetch: dropper behavior ({', '.join(net_fns[:3])} -> {', '.join(file_fns[:3])})",
        })


def _check_excessive_calls(calls, locations, filename, findings):
    for fn, count in calls.items():
        if count >= 5 and _CATEGORY_MAP.get(fn) in ("code_execution", "command_execution"):
            findings.append({
                "file": filename,
                "line": locations[fn][0],
                "type": "excessive_dangerous_calls",
                "severity": "high",
                "message": f"{fn}() called {count} times",
            })


def _check_variable_functions(content, filename, findings):
    hits = re.findall(r"\$[a-zA-Z_]\w*\s*\(", content)
    if len(hits) >= 3:
        line = content[:content.index(hits[0])].count("\n") + 1 if hits else 0
        findings.append({
            "file": filename,
            "line": line,
            "type": "variable_function_calls",
            "severity": "high",
            "message": f"{len(hits)} variable function calls ($var()) detected",
        })


def _check_risk_score(calls, filename, findings):
    score = 0
    for fn, count in calls.items():
        cat = _CATEGORY_MAP.get(fn, "")
        score += count * _RISK_WEIGHTS.get(cat, 0)

    if score >= 50:
        sev = "critical" if score >= 100 else "high"
        findings.append({
            "file": filename,
            "line": 0,
            "type": "high_risk_score",
            "severity": sev,
            "message": f"Risk score: {score}/100+ ({len(calls)} dangerous functions, {sum(calls.values())} total calls)",
        })
