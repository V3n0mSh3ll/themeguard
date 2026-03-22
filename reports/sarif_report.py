import os
import json
from datetime import datetime

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def generate_sarif_report(results, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"themeguard_report_{timestamp}.sarif"
    fpath = os.path.join(output_dir, fname)

    rules = {}
    sarif_results = []

    for f in results.get("findings", []):
        rule_id = f.get("type", "unknown")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f.get("message", rule_id)},
                "defaultConfiguration": {
                    "level": _SEVERITY_MAP.get(f.get("severity", "low"), "note"),
                },
            }

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.get("file", "").replace("\\", "/")},
            }
        }
        if f.get("line", 0) > 0:
            location["physicalLocation"]["region"] = {"startLine": f["line"]}

        sarif_results.append({
            "ruleId": rule_id,
            "level": _SEVERITY_MAP.get(f.get("severity", "low"), "note"),
            "message": {"text": f.get("message", "")},
            "locations": [location],
        })

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ThemeGuard",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/V3n0mSh3ll/themeguard",
                    "rules": list(rules.values()),
                },
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.utcnow().isoformat() + "Z",
            }],
        }],
    }

    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
    return fpath
