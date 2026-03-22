import json
import os
from datetime import datetime


def generate_json_report(results, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"themeguard_report_{timestamp}.json"
    fpath = os.path.join(output_dir, fname)

    report = {
        "tool": "ThemeGuard",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "target": results.get("target", ""),
        "summary": {
            "files_scanned": results.get("files_scanned", 0),
            "scan_time_seconds": results.get("scan_time", 0),
            "total_findings": results.get("total_findings", 0),
            "severity_counts": results.get("severity_counts", {}),
        },
        "signatures": results.get("signatures", {}),
        "findings": results.get("findings", []),
    }

    with open(fpath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return fpath
