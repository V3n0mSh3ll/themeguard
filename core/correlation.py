import re
from collections import defaultdict


def correlate(findings):
    if not findings:
        return findings

    file_groups = defaultdict(list)
    for f in findings:
        file_groups[f.get("file", "")].append(f)

    url_map = defaultdict(list)
    domain_map = defaultdict(list)
    family_map = defaultdict(list)

    for f in findings:
        msg = f.get("message", "") + " " + f.get("match", "")

        urls = re.findall(r'https?://[^\s\'"<>]+', msg)
        for u in urls:
            url_map[u].append(f.get("file", ""))

        domains = re.findall(r'https?://([^/\s\'"<>:]+)', msg)
        for d in domains:
            domain_map[d.lower()].append(f.get("file", ""))

        ftype = f.get("type", "")
        if ftype.startswith("malware_family_"):
            family = ftype.replace("malware_family_", "")
            family_map[family].append(f.get("file", ""))

    correlated = list(findings)

    for url, files in url_map.items():
        unique = list(set(files))
        if len(unique) >= 2:
            correlated.append({
                "file": unique[0],
                "line": 0,
                "type": "correlation_shared_url",
                "severity": "critical",
                "message": f"Same malicious URL in {len(unique)} files: {url[:60]}",
                "evidence_count": len(unique),
                "correlated_files": unique[:5],
            })

    for domain, files in domain_map.items():
        unique = list(set(files))
        if len(unique) >= 3:
            correlated.append({
                "file": unique[0],
                "line": 0,
                "type": "correlation_shared_domain",
                "severity": "critical",
                "message": f"Same external domain in {len(unique)} files: {domain}",
                "evidence_count": len(unique),
                "correlated_files": unique[:5],
            })

    for family, files in family_map.items():
        unique = list(set(files))
        if len(unique) >= 2:
            correlated.append({
                "file": unique[0],
                "line": 0,
                "type": "correlation_malware_campaign",
                "severity": "critical",
                "message": f"Malware campaign: '{family}' detected in {len(unique)} files",
                "evidence_count": len(unique),
                "correlated_files": unique[:5],
            })

    for filepath, group in file_groups.items():
        if len(group) < 3:
            continue

        signals = set()
        for f in group:
            ftype = f.get("type", "")
            if "obfusc" in ftype or "entropy" in ftype:
                signals.add("obfuscation")
            if "eval" in ftype or "exec" in ftype or "taint" in ftype:
                signals.add("execution")
            if "network" in ftype or "c2_" in ftype or "url" in ftype:
                signals.add("network")
            if "file" in ftype or "include" in ftype or "dropper" in ftype:
                signals.add("file_ops")
            if "base64" in ftype or "decode" in ftype:
                signals.add("encoding")

        if len(signals) >= 3:
            correlated.append({
                "file": filepath,
                "line": 0,
                "type": "correlation_multi_signal",
                "severity": "critical",
                "message": f"Multi-vector threat: {' + '.join(sorted(signals))} ({len(group)} indicators)",
                "confidence": 0.95,
                "evidence_count": len(group),
            })

    return correlated
