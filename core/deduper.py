import hashlib


def deduplicate(findings):
    seen = {}
    result = []

    for f in findings:
        key = _build_key(f)
        if key in seen:
            existing = seen[key]
            existing["evidence_count"] = existing.get("evidence_count", 1) + 1
            if _sev_rank(f.get("severity", "low")) > _sev_rank(existing.get("severity", "low")):
                existing["severity"] = f["severity"]
            sources = existing.get("source_modules", [])
            new_src = f.get("source_module", f.get("type", ""))
            if new_src and new_src not in sources:
                sources.append(new_src)
                existing["source_modules"] = sources
            continue

        entry = dict(f)
        entry["evidence_count"] = 1
        entry.setdefault("source_modules", [f.get("type", "")])
        seen[key] = entry
        result.append(entry)

    for entry in result:
        entry["id"] = _stable_id(entry)

    result.sort(key=lambda f: (-_sev_rank(f.get("severity", "low")), f.get("file", ""), f.get("line", 0)))

    return result


def _build_key(finding):
    path = finding.get("file", "")
    line = finding.get("line", 0)
    ftype = finding.get("type", "")
    msg_hash = hashlib.md5(finding.get("message", "").encode()).hexdigest()[:8]

    if line > 0:
        line_bucket = line // 5
    else:
        line_bucket = 0

    category = _normalize_type(ftype)
    return f"{path}|{line_bucket}|{category}|{msg_hash}"


def _normalize_type(ftype):
    prefixes = [
        "tg_", "ml_", "cloud_", "concat_", "dynamic_",
        "htaccess_", "wpconfig_", "core_file_", "malware_family_",
    ]
    for prefix in prefixes:
        if ftype.startswith(prefix):
            return prefix.rstrip("_")
    return ftype


_SEV_RANKS = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _sev_rank(sev):
    return _SEV_RANKS.get(sev, 0)


def _stable_id(finding):
    parts = [
        finding.get("file", ""),
        str(finding.get("line", 0)),
        finding.get("type", ""),
        finding.get("message", "")[:100],
    ]
    raw = "|".join(parts)
    return "TG-" + hashlib.md5(raw.encode()).hexdigest()[:10].upper()
