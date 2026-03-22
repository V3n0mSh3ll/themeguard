import os
import time
from collections import defaultdict


def generate_triage(findings, scan_meta):
    sections = {
        "quarantine": [],
        "review": [],
        "inspect": [],
        "info": [],
    }

    for f in findings:
        action = f.get("action", "inspect")
        if action in sections:
            sections[action].append(f)
        else:
            sections["inspect"].append(f)

    file_risk = defaultdict(float)
    for f in findings:
        conf = f.get("confidence", 0.5)
        sev_w = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.15}.get(f.get("severity", "medium"), 0.4)
        file_risk[f.get("file", "")] += conf * sev_w

    top_files = sorted(file_risk.items(), key=lambda x: x[1], reverse=True)[:10]

    lines = []
    lines.append("=" * 60)
    lines.append("  THEMEGUARD TRIAGE REPORT")
    lines.append("=" * 60)
    lines.append(f"  Target:       {scan_meta.get('target', '')}")
    lines.append(f"  Scan time:    {scan_meta.get('scan_time', 0):.2f}s")
    lines.append(f"  Files:        {scan_meta.get('files_scanned', 0)}")
    lines.append(f"  Total finds:  {len(findings)}")
    lines.append("")

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.get("severity", "medium")] += 1

    lines.append("  SEVERITY BREAKDOWN")
    lines.append("  " + "-" * 40)
    for sev in ("critical", "high", "medium", "low"):
        count = sev_counts.get(sev, 0)
        if count:
            bar = "#" * min(30, count)
            lines.append(f"  {sev:10s} {count:4d} {bar}")
    lines.append("")

    if sections["quarantine"]:
        lines.append("  [!] IMMEDIATE ACTION REQUIRED - QUARANTINE")
        lines.append("  " + "-" * 40)
        for f in sections["quarantine"][:15]:
            conf = f.get("confidence", 0)
            lines.append(f"    {f.get('file', '')}:{f.get('line', 0)}")
            lines.append(f"      {f.get('message', '')[:100]}")
            lines.append(f"      Confidence: {conf:.0%} | Severity: {f.get('severity', '')}")
            lines.append("")
    else:
        lines.append("  [OK] No files require immediate quarantine")
        lines.append("")

    if sections["review"]:
        lines.append("  [?] MANUAL REVIEW RECOMMENDED")
        lines.append("  " + "-" * 40)
        for f in sections["review"][:10]:
            lines.append(f"    {f.get('file', '')}:{f.get('line', 0)}")
            lines.append(f"      {f.get('message', '')[:100]}")
            lines.append("")

    if top_files:
        lines.append("  TOP RISK FILES")
        lines.append("  " + "-" * 40)
        for fpath, score in top_files:
            bar = "#" * min(20, int(score * 5))
            lines.append(f"    {score:5.1f}  {fpath[:50]}  {bar}")
        lines.append("")

    correlated = [f for f in findings if f.get("type", "").startswith("correlation_")]
    if correlated:
        lines.append("  CORRELATED THREATS (CAMPAIGNS)")
        lines.append("  " + "-" * 40)
        for c in correlated[:5]:
            lines.append(f"    {c.get('message', '')[:100]}")
            cfiles = c.get("correlated_files", [])
            if cfiles:
                lines.append(f"      Files: {', '.join(cfiles[:3])}")
            lines.append("")

    if sections["inspect"]:
        lines.append(f"  LOWER PRIORITY ({len(sections['inspect'])} findings)")
        lines.append("  " + "-" * 40)
        type_counts = defaultdict(int)
        for f in sections["inspect"]:
            type_counts[f.get("type", "unknown")] += 1
        for t, c in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:8]:
            lines.append(f"    {c:3d}x  {t}")
        lines.append("")

    lines.append("  RECOMMENDED NEXT STEPS")
    lines.append("  " + "-" * 40)

    if sections["quarantine"]:
        lines.append("  1. Quarantine the files listed above IMMEDIATELY")
        lines.append("  2. Check if the site has been compromised")
        lines.append("  3. Reset all passwords and API keys")
        lines.append("  4. Review server access logs")
    elif sections["review"]:
        lines.append("  1. Review flagged files manually")
        lines.append("  2. Compare suspicious files against official sources")
        lines.append("  3. Run deep scan with --deep flag if not already done")
    else:
        lines.append("  1. No critical issues found")
        lines.append("  2. Consider periodic re-scans")

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)
