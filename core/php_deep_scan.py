import re
from collections import defaultdict

_TOKEN_RE = re.compile(
    r'(\$[a-zA-Z_]\w*)'
    r'|(\b\d+(?:\.\d+)?\b)'
    r'|(\'[^\']*\'|"[^"]*")'
    r'|(\b[a-zA-Z_]\w*\b)'
    r'|([\.\+\-\*\/\=\!\<\>\&\|\^\~\%]+)'
    r'|([{}()\[\];,@])'
    r'|(\s+)',
)

_SANITIZERS = {
    "sanitize_text_field", "sanitize_email", "sanitize_file_name",
    "sanitize_html_class", "sanitize_key", "sanitize_meta",
    "sanitize_mime_type", "sanitize_option", "sanitize_sql_orderby",
    "sanitize_title", "sanitize_user", "sanitize_url",
    "absint", "intval", "floatval", "wp_kses", "wp_kses_post",
    "esc_sql", "esc_html", "esc_attr", "esc_url", "esc_js",
    "esc_textarea", "wp_strip_all_tags",
}

_ESCAPE_FUNCS = {
    "esc_html", "esc_attr", "esc_url", "esc_js", "esc_textarea",
    "esc_html__", "esc_html_e", "esc_attr__", "esc_attr_e",
    "wp_kses", "wp_kses_post", "wp_kses_data",
}

_OUTPUT_FUNCS = {"echo", "print", "printf", "vprintf"}

_CONCAT_ASSIGN_RE = re.compile(
    r'(\$[a-zA-Z_]\w*)\s*\.?=\s*(.+?);\s*$', re.MULTILINE
)

_DYNAMIC_CALL_RE = re.compile(
    r'(\$[a-zA-Z_]\w*)\s*\(', re.MULTILINE
)

_FUNC_DEF_RE = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)\s*\{', re.IGNORECASE
)

_FUNC_CALL_RE = re.compile(
    r'\b(\w+)\s*\(', re.IGNORECASE
)

_CHMOD_RE = re.compile(
    r'\bchmod\s*\(\s*(.+?)\s*,\s*(0?\d{3,4})\s*\)', re.IGNORECASE
)

_WEAK_PERMS = {0o777, 0o776, 0o775, 0o766, 0o757, 0o666, 0o667}


def php_deep_analyze(content, filename):
    findings = []
    _resolve_concat_chains(content, filename, findings)
    _detect_dynamic_dispatch(content, filename, findings)
    _check_sanitization_gaps(content, filename, findings)
    _check_output_escaping(content, filename, findings)
    _build_call_graph(content, filename, findings)
    _detect_dead_code_blocks(content, filename, findings)
    _check_file_permissions(content, filename, findings)
    _detect_error_suppression(content, filename, findings)
    _detect_reflection_abuse(content, filename, findings)
    _calculate_risk_score(content, filename, findings)
    return findings


def _resolve_concat_chains(content, filename, findings):
    assignments = {}
    for m in _CONCAT_ASSIGN_RE.finditer(content):
        var = m.group(1)
        expr = m.group(2).strip()
        if var in assignments:
            assignments[var] += expr
        else:
            assignments[var] = expr

    for var, expr in assignments.items():
        resolved = _resolve_value(expr, assignments, depth=0)
        if not resolved:
            continue

        danger_funcs = (
            "eval", "assert", "system", "exec", "passthru",
            "shell_exec", "popen", "proc_open", "base64_decode",
        )
        resolved_lower = resolved.lower().replace(" ", "").replace("'", "").replace('"', "")
        for func in danger_funcs:
            if func in resolved_lower:
                line_num = _find_var_line(content, var)
                findings.append({
                    "file": filename,
                    "line": line_num,
                    "type": "concat_obfuscation",
                    "severity": "critical",
                    "message": f"String concat builds '{func}' via {var}: {resolved[:80]}",
                })
                break


def _resolve_value(expr, assignments, depth):
    if depth > 6:
        return expr

    parts = re.split(r'\s*\.\s*', expr)
    resolved = []

    for part in parts:
        part = part.strip()
        if part.startswith("$") and part in assignments:
            inner = _resolve_value(assignments[part], assignments, depth + 1)
            resolved.append(inner)
        elif (part.startswith("'") and part.endswith("'")) or \
             (part.startswith('"') and part.endswith('"')):
            resolved.append(part[1:-1])
        elif part.startswith("chr("):
            m = re.search(r'chr\s*\(\s*(\d+)\s*\)', part)
            if m:
                resolved.append(chr(int(m.group(1))))
        else:
            resolved.append(part)

    return "".join(resolved)


def _detect_dynamic_dispatch(content, filename, findings):
    for m in _DYNAMIC_CALL_RE.finditer(content):
        var = m.group(1)

        assign_re = re.compile(
            rf'{re.escape(var)}\s*=\s*(.+?)\s*;', re.MULTILINE
        )
        assigns = assign_re.findall(content)

        for val in assigns:
            val_clean = val.strip().strip("'\"").lower()
            dangerous = (
                "eval", "assert", "system", "exec", "passthru",
                "shell_exec", "base64_decode", "create_function",
            )
            for d in dangerous:
                if d in val_clean:
                    findings.append({
                        "file": filename,
                        "line": 0,
                        "type": "dynamic_function_dispatch",
                        "severity": "critical",
                        "message": f"Variable function call {var}() resolves to '{val_clean}'",
                    })
                    return


def _check_sanitization_gaps(content, filename, findings):
    source_re = re.compile(
        r'\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"]([\w]+)[\'"]\s*\]'
    )
    sources = list(source_re.finditer(content))
    if not sources:
        return

    lines = content.split("\n")
    for src in sources:
        src_type = src.group(1)
        src_key = src.group(2)
        src_start = src.start()

        region_start = max(0, src_start - 200)
        region_end = min(len(content), src_start + 300)
        region = content[region_start:region_end]

        has_sanitizer = any(s in region for s in _SANITIZERS)

        if not has_sanitizer:
            db_funcs = ("wpdb", "query", "insert", "update", "delete", "get_results", "get_var")
            near_db = any(d in region.lower() for d in db_funcs)

            if near_db:
                findings.append({
                    "file": filename,
                    "line": content[:src_start].count("\n") + 1,
                    "type": "unsanitized_db_input",
                    "severity": "critical",
                    "message": f"${src_type}['{src_key}'] used in DB query without sanitization",
                })
            else:
                findings.append({
                    "file": filename,
                    "line": content[:src_start].count("\n") + 1,
                    "type": "missing_sanitization",
                    "severity": "medium",
                    "message": f"${src_type}['{src_key}'] used without sanitize_*/intval/absint",
                })


def _check_output_escaping(content, filename, findings):
    for func in _OUTPUT_FUNCS:
        pattern = re.compile(
            rf'\b{func}\s+(.+?);\s*$', re.MULTILINE | re.IGNORECASE
        )
        for m in pattern.finditer(content):
            output_expr = m.group(1)
            if "$_" in output_expr:
                has_escape = any(e in output_expr for e in _ESCAPE_FUNCS)
                if not has_escape:
                    line_num = content[:m.start()].count("\n") + 1
                    findings.append({
                        "file": filename,
                        "line": line_num,
                        "type": "xss_unescaped_output",
                        "severity": "high",
                        "message": f"User input echoed without esc_html/esc_attr: {output_expr[:60]}",
                    })


def _build_call_graph(content, filename, findings):
    defined = {}
    for m in _FUNC_DEF_RE.finditer(content):
        func_name = m.group(1)
        start = m.end()
        body = _extract_body(content, start)
        if body:
            defined[func_name] = body

    for func_name, body in defined.items():
        calls = set(_FUNC_CALL_RE.findall(body))
        danger_chain = calls & {
            "eval", "assert", "system", "exec", "passthru",
            "shell_exec", "popen", "proc_open",
        }
        if danger_chain:
            callers = []
            for other_name, other_body in defined.items():
                if other_name == func_name:
                    continue
                if func_name in other_body:
                    callers.append(other_name)

            if callers:
                findings.append({
                    "file": filename,
                    "line": 0,
                    "type": "indirect_danger_chain",
                    "severity": "critical",
                    "message": f"Call chain: {' -> '.join(callers[:3])} -> {func_name}() -> {', '.join(danger_chain)}",
                })


def _detect_dead_code_blocks(content, filename, findings):
    lines = content.split("\n")
    after_return = False
    dead_start = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        if re.match(r'^(return|exit|die)\b', stripped):
            after_return = True
            dead_start = i + 1
            continue

        if after_return and stripped and not stripped.startswith(("}", "*/", "*", "//")):
            if re.match(r'\b(function|class|if|else|case)\b', stripped):
                after_return = False
                continue

            has_dangerous = any(d in stripped.lower() for d in (
                "eval", "exec", "system", "base64_decode", "file_put_contents",
                "shell_exec", "passthru",
            ))

            if has_dangerous:
                findings.append({
                    "file": filename,
                    "line": i + 1,
                    "type": "dead_code_backdoor",
                    "severity": "critical",
                    "message": f"Dangerous code hidden after return/exit/die at line {dead_start}",
                })
            after_return = False

        if stripped.startswith(("}", "function ", "class ")):
            after_return = False


def _check_file_permissions(content, filename, findings):
    for m in _CHMOD_RE.finditer(content):
        path_expr = m.group(1)
        perm_str = m.group(2)

        try:
            perm = int(perm_str, 8) if perm_str.startswith("0") else int(perm_str)
        except ValueError:
            continue

        if perm in _WEAK_PERMS:
            line_num = content[:m.start()].count("\n") + 1
            findings.append({
                "file": filename,
                "line": line_num,
                "type": "weak_file_permissions",
                "severity": "high",
                "message": f"chmod({path_expr}, {oct(perm)}) sets dangerously open permissions",
            })


def _detect_error_suppression(content, filename, findings):
    suppressed = re.findall(r'@\s*(eval|system|exec|passthru|shell_exec|include|require)\s*\(', content)
    if suppressed:
        findings.append({
            "file": filename,
            "line": 0,
            "type": "error_suppressed_danger",
            "severity": "critical",
            "message": f"Error suppression (@) on dangerous function: @{suppressed[0]}()",
        })

    ini_patterns = [
        (r"ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?0", "display_errors disabled"),
        (r"ini_set\s*\(\s*['\"]error_reporting['\"]\s*,\s*['\"]?0", "error_reporting set to 0"),
        (r"ini_set\s*\(\s*['\"]log_errors['\"]\s*,\s*['\"]?0", "error logging disabled"),
    ]
    count = sum(1 for pat, _ in ini_patterns if re.search(pat, content))
    if count >= 2:
        findings.append({
            "file": filename,
            "line": 0,
            "type": "full_error_suppression",
            "severity": "high",
            "message": f"All error reporting disabled ({count} ini_set calls) - hiding malicious activity",
        })


def _detect_reflection_abuse(content, filename, findings):
    patterns = [
        (r'new\s+ReflectionFunction\s*\(\s*\$', "ReflectionFunction with variable"),
        (r'call_user_func\s*\(\s*\$', "Variable passed to call_user_func"),
        (r'call_user_func_array\s*\(\s*\$', "Variable passed to call_user_func_array"),
        (r'array_map\s*\(\s*\$[^,]+,\s*\$_(GET|POST|REQUEST)', "array_map with user input"),
        (r'array_filter\s*\(\s*\$[^,]+,\s*\$', "array_filter with variable callback"),
        (r'usort\s*\(\s*\$[^,]+,\s*\$', "usort with variable callback"),
        (r'preg_replace\s*\(\s*[\'"][^"\']*e[\'"]', "preg_replace with /e modifier (code execution)"),
    ]

    for pat, desc in patterns:
        if re.search(pat, content, re.IGNORECASE):
            findings.append({
                "file": filename,
                "line": 0,
                "type": "reflection_abuse",
                "severity": "critical",
                "message": desc,
            })
            break


def _calculate_risk_score(content, filename, findings):
    score = 0
    weights = {
        "critical": 25,
        "high": 10,
        "medium": 3,
        "low": 1,
    }

    for f in findings:
        if f.get("file") == filename:
            score += weights.get(f.get("severity", "low"), 1)

    file_indicators = 0
    if len(content) > 50000:
        file_indicators += 5
    if content.count("eval") > 3:
        file_indicators += 10
    if content.count("base64_decode") > 2:
        file_indicators += 10
    if re.search(r'[\x00-\x08\x0e-\x1f]', content):
        file_indicators += 15

    score += file_indicators

    if score >= 50:
        findings.append({
            "file": filename,
            "line": 0,
            "type": "threat_score",
            "severity": "critical",
            "message": f"Threat score: {score}/100 - EXTREMELY SUSPICIOUS file",
        })
    elif score >= 25:
        findings.append({
            "file": filename,
            "line": 0,
            "type": "threat_score",
            "severity": "high",
            "message": f"Threat score: {score}/100 - highly suspicious file",
        })


def _find_var_line(content, var):
    idx = content.find(var)
    if idx == -1:
        return 0
    return content[:idx].count("\n") + 1


def _extract_body(content, start):
    depth = 1
    pos = start
    while pos < len(content) and depth > 0:
        if content[pos] == "{":
            depth += 1
        elif content[pos] == "}":
            depth -= 1
        pos += 1
    return content[start:pos - 1] if depth == 0 else None
