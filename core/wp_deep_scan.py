import re

_SINK_FUNCS = {
    "eval", "assert", "system", "exec", "passthru", "shell_exec",
    "popen", "proc_open", "pcntl_exec", "call_user_func",
    "call_user_func_array", "create_function", "preg_replace",
    "file_put_contents", "fwrite", "fputs", "fopen",
    "include", "include_once", "require", "require_once",
    "unserialize", "extract", "parse_str",
    "mysql_query", "mysqli_query", "pg_query",
}

_SOURCE_RE = re.compile(
    r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[\s*[\'"](\w+)[\'"]\s*\]'
)

_ASSIGN_RE = re.compile(
    r'(\$[a-zA-Z_]\w*)\s*=\s*(.+?);\s*$', re.MULTILINE
)

_FUNC_CALL_RE = re.compile(
    r'\b(' + '|'.join(re.escape(f) for f in _SINK_FUNCS) + r')\s*\(',
    re.IGNORECASE,
)

_WP_HOOK_RE = re.compile(
    r'\b(add_action|add_filter)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]?(\$?\w+)[\'"]?',
    re.IGNORECASE,
)

_WP_CRON_RE = re.compile(
    r'\b(wp_schedule_event|wp_schedule_single_event)\s*\(\s*(.+?)\s*,\s*[\'"]?(\w+)[\'"]?\s*,\s*[\'"](\w+)[\'"]',
    re.IGNORECASE,
)

_WP_OPTION_RE = re.compile(
    r'\b(update_option|add_option)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*(.+?)\s*\)',
    re.IGNORECASE,
)

_NONCE_CHECK_RE = re.compile(
    r'\b(wp_verify_nonce|check_ajax_referer|check_admin_referer)\b',
    re.IGNORECASE,
)

_AJAX_HANDLER_RE = re.compile(
    r'add_action\s*\(\s*[\'"]wp_ajax_(nopriv_)?(\w+)[\'"]\s*,\s*[\'"]?(\w+)[\'"]?',
    re.IGNORECASE,
)

_REST_ROUTE_RE = re.compile(
    r'register_rest_route\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*,\s*(.+?)\)',
    re.DOTALL | re.IGNORECASE,
)

_INCLUDE_RE = re.compile(
    r'\b(include|include_once|require|require_once)\s*[\(\s]+(.+?)[\)\s]*;',
    re.IGNORECASE,
)

_UPDATE_HIJACK_RE = re.compile(
    r'add_filter\s*\(\s*[\'"](pre_set_site_transient_update_|'
    r'site_transient_update_|auto_update_|'
    r'upgrader_package_options|upgrader_pre_download)[\'"]',
    re.IGNORECASE,
)

_CAP_ESCALATION_RE = re.compile(
    r'\b(add_cap|add_role|set_role|wp_insert_user|wp_update_user)\s*\(',
    re.IGNORECASE,
)

_SHORTCODE_RE = re.compile(
    r'\badd_shortcode\s*\(\s*[\'"](\w+)[\'"]\s*,\s*[\'"]?(\$?\w+)[\'"]?',
    re.IGNORECASE,
)


def wp_deep_scan(content, filename):
    findings = []
    _trace_variable_flow(content, filename, findings)
    _analyze_hook_chains(content, filename, findings)
    _detect_cron_persistence(content, filename, findings)
    _detect_option_poisoning(content, filename, findings)
    _check_nonce_bypass(content, filename, findings)
    _check_rest_exposure(content, filename, findings)
    _trace_include_chain(content, filename, findings)
    _detect_update_hijack(content, filename, findings)
    _detect_cap_escalation(content, filename, findings)
    _detect_shortcode_injection(content, filename, findings)
    return findings


def _trace_variable_flow(content, filename, findings):
    sources = {}
    for m in _SOURCE_RE.finditer(content):
        var_ref = m.group(0)
        src_type = m.group(1)
        src_key = m.group(2)
        sources[var_ref] = (src_type, src_key)

    if not sources:
        return

    assignments = {}
    for m in _ASSIGN_RE.finditer(content):
        var_name = m.group(1)
        value_expr = m.group(2)
        assignments[var_name] = value_expr

    tainted = set()
    for var_ref in sources:
        tainted.add(var_ref)
        for var_name, expr in assignments.items():
            if var_ref in expr:
                tainted.add(var_name)

    changed = True
    depth = 0
    while changed and depth < 8:
        changed = False
        depth += 1
        for var_name, expr in assignments.items():
            if var_name in tainted:
                continue
            for t in tainted:
                if t in expr:
                    tainted.add(var_name)
                    changed = True
                    break

    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        sink_match = _FUNC_CALL_RE.search(line)
        if not sink_match:
            continue
        func_name = sink_match.group(1)
        for t in tainted:
            if t in line:
                src_info = sources.get(t)
                if src_info:
                    origin = f"$_{src_info[0]}['{src_info[1]}']"
                else:
                    origin = t
                findings.append({
                    "file": filename,
                    "line": line_num,
                    "type": "variable_flow_to_sink",
                    "severity": "critical",
                    "message": f"Tainted data {origin} reaches {func_name}() via {t}",
                })
                return


def _analyze_hook_chains(content, filename, findings):
    hooks = list(_WP_HOOK_RE.finditer(content))
    if not hooks:
        return

    dangerous_hooks = {
        "init", "wp_loaded", "admin_init", "wp_head", "wp_footer",
        "login_init", "login_head", "shutdown", "plugins_loaded",
        "after_setup_theme", "template_redirect", "send_headers",
    }

    for m in hooks:
        hook_type = m.group(1)
        hook_name = m.group(2)
        callback = m.group(3)

        if callback.startswith("$"):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "dynamic_hook_callback",
                "severity": "critical",
                "message": f"{hook_type}('{hook_name}', {callback}) uses variable callback",
            })
            continue

        if hook_name in dangerous_hooks:
            func_body = _extract_function_body(content, callback)
            if func_body and _has_dangerous_call(func_body):
                findings.append({
                    "file": filename,
                    "line": 0,
                    "type": "malicious_hook_injection",
                    "severity": "critical",
                    "message": f"{hook_type}('{hook_name}', '{callback}') executes dangerous code",
                })


def _detect_cron_persistence(content, filename, findings):
    crons = list(_WP_CRON_RE.finditer(content))
    for m in crons:
        func = m.group(1)
        hook_name = m.group(4)

        callback_body = _extract_function_body(content, hook_name)
        if not callback_body:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "hidden_cron_job",
                "severity": "high",
                "message": f"{func}() schedules '{hook_name}' with no visible callback",
            })
            continue

        if _has_dangerous_call(callback_body) or _has_network_call(callback_body):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "malicious_cron_persistence",
                "severity": "critical",
                "message": f"Cron '{hook_name}' runs dangerous/network code on schedule",
            })


def _detect_option_poisoning(content, filename, findings):
    for m in _WP_OPTION_RE.finditer(content):
        func = m.group(1)
        key = m.group(2)
        value = m.group(3).strip()

        encoded = (
            "base64_decode" in value
            or "gzinflate" in value
            or "gzuncompress" in value
            or "str_rot13" in value
            or "unserialize" in value
        )

        from_input = bool(_SOURCE_RE.search(value))

        if encoded:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "encoded_option_storage",
                "severity": "critical",
                "message": f"{func}('{key}', ...) stores encoded/serialized payload in database",
            })
        elif from_input:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "unsanitized_option_write",
                "severity": "high",
                "message": f"{func}('{key}', ...) writes user input directly to options table",
            })


def _check_nonce_bypass(content, filename, findings):
    ajax_handlers = list(_AJAX_HANDLER_RE.finditer(content))
    for m in ajax_handlers:
        nopriv = m.group(1)
        action = m.group(2)
        callback = m.group(3)

        func_body = _extract_function_body(content, callback)
        if not func_body:
            continue

        has_nonce = bool(_NONCE_CHECK_RE.search(func_body))
        has_cap_check = bool(re.search(r'current_user_can\s*\(', func_body))

        if nopriv and not has_nonce:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "nopriv_no_nonce",
                "severity": "critical",
                "message": f"wp_ajax_nopriv_{action} ('{callback}') has no nonce verification",
            })
        elif not has_nonce and not has_cap_check:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "ajax_no_auth",
                "severity": "high",
                "message": f"AJAX handler '{callback}' missing nonce + capability check",
            })


def _check_rest_exposure(content, filename, findings):
    for m in _REST_ROUTE_RE.finditer(content):
        namespace = m.group(1)
        route = m.group(2)
        config = m.group(3)

        has_perm = "permission_callback" in config
        if not has_perm:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "open_rest_endpoint",
                "severity": "high",
                "message": f"REST route '{namespace}/{route}' has no permission_callback",
            })
            continue

        if "'__return_true'" in config or '"__return_true"' in config:
            if _has_dangerous_call(config):
                findings.append({
                    "file": filename,
                    "line": 0,
                    "type": "unauthenticated_rest_danger",
                    "severity": "critical",
                    "message": f"REST '{namespace}/{route}' open to all + runs dangerous code",
                })


def _trace_include_chain(content, filename, findings):
    includes = list(_INCLUDE_RE.finditer(content))
    for m in includes:
        keyword = m.group(1)
        path_expr = m.group(2).strip().strip("'\"")

        if "$" in path_expr and _SOURCE_RE.search(path_expr):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "user_controlled_include",
                "severity": "critical",
                "message": f"{keyword} path controlled by user input: {path_expr[:80]}",
            })
            continue

        suspicious_paths = ("..", "tmp", "/upload", "wp-content/uploads")
        for sp in suspicious_paths:
            if sp in path_expr.lower():
                findings.append({
                    "file": filename,
                    "line": 0,
                    "type": "suspicious_include_path",
                    "severity": "high",
                    "message": f"{keyword} loads from suspicious path: {path_expr[:80]}",
                })
                break


def _detect_update_hijack(content, filename, findings):
    for m in _UPDATE_HIJACK_RE.finditer(content):
        hook = m.group(1)

        after = content[m.end():]
        if re.search(r'(http|ftp|url|download|remote)', after[:300], re.IGNORECASE):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "update_hijack",
                "severity": "critical",
                "message": f"Auto-update hook '{hook}*' redirects downloads to external source",
            })
        else:
            findings.append({
                "file": filename,
                "line": 0,
                "type": "update_hook_modification",
                "severity": "high",
                "message": f"Update process modified via '{hook}*' filter",
            })


def _detect_cap_escalation(content, filename, findings):
    for m in _CAP_ESCALATION_RE.finditer(content):
        func = m.group(1)
        after = content[m.end():m.end() + 200]

        admin_indicators = ("administrator", "manage_options", "edit_users", "delete_plugins", "activate_plugins")
        for indicator in admin_indicators:
            if indicator in after.lower():
                from_input = bool(_SOURCE_RE.search(after))
                sev = "critical" if from_input else "high"
                findings.append({
                    "file": filename,
                    "line": 0,
                    "type": "capability_escalation",
                    "severity": sev,
                    "message": f"{func}() grants '{indicator}' privilege" + (" from user input" if from_input else ""),
                })
                break


def _detect_shortcode_injection(content, filename, findings):
    for m in _SHORTCODE_RE.finditer(content):
        tag = m.group(1)
        callback = m.group(2)

        if callback.startswith("$"):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "dynamic_shortcode",
                "severity": "critical",
                "message": f"add_shortcode('{tag}', {callback}) uses variable callback",
            })
            continue

        func_body = _extract_function_body(content, callback)
        if func_body and _has_dangerous_call(func_body):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "shortcode_code_execution",
                "severity": "critical",
                "message": f"Shortcode [{tag}] handler '{callback}' executes dangerous code",
            })


def _extract_function_body(content, func_name):
    pattern = re.compile(
        rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{',
        re.IGNORECASE,
    )
    m = pattern.search(content)
    if not m:
        return None

    start = m.end()
    depth = 1
    pos = start
    while pos < len(content) and depth > 0:
        if content[pos] == "{":
            depth += 1
        elif content[pos] == "}":
            depth -= 1
        pos += 1

    return content[start:pos - 1] if depth == 0 else None


def _has_dangerous_call(code):
    return bool(_FUNC_CALL_RE.search(code))


def _has_network_call(code):
    net_funcs = (
        "file_get_contents", "curl_exec", "curl_init",
        "wp_remote_get", "wp_remote_post", "wp_remote_request",
        "fsockopen", "stream_socket_client",
    )
    for f in net_funcs:
        if f in code:
            return True
    return False
