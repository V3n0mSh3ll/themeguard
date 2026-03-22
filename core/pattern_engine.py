import json
import os
import re

from core.aho_corasick import AhoCorasick
from utils.config import SIGNATURES_DIR


class PatternEngine:

    def __init__(self):
        self.signatures = {}
        self._compiled = {}
        self._ac = None
        self._ac_map = {}
        self._load_all()
        self._compile_all()

    def _load_all(self):
        if not os.path.isdir(SIGNATURES_DIR):
            return
        for fname in sorted(os.listdir(SIGNATURES_DIR)):
            if not fname.endswith(".json"):
                continue
            category = fname.replace(".json", "")
            fpath = os.path.join(SIGNATURES_DIR, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    self.signatures[category] = json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue

    def _compile_all(self):
        ac = AhoCorasick()
        text_count = 0

        for category, sigs in self.signatures.items():
            for sig in sigs:
                pattern = sig.get("pattern", "")
                if not pattern:
                    continue

                sig_id = sig.get("id", category)
                is_plain = not re.search(r'[\\.*+?^${}()|[\]]', pattern)

                if is_plain:
                    key = pattern.lower()
                    ac.add_pattern(key, sig_id)
                    self._ac_map[sig_id] = sig
                    text_count += 1
                else:
                    try:
                        self._compiled[sig_id] = (re.compile(pattern, re.IGNORECASE), sig)
                    except re.error:
                        continue

        if text_count > 0:
            ac.build()
            self._ac = ac

    def scan_content(self, content, rel_path):
        findings = []
        content_lower = content.lower()
        lines = content.split("\n")

        if self._ac:
            seen = set()
            for _, sig_id in self._ac.search(content_lower):
                if sig_id in seen:
                    continue
                seen.add(sig_id)
                sig = self._ac_map[sig_id]
                line_num = _find_line(content, sig.get("pattern", ""))
                findings.append({
                    "type": sig_id,
                    "category": sig.get("category", ""),
                    "severity": sig.get("severity", "medium"),
                    "message": sig.get("description", f"Pattern match: {sig_id}"),
                    "file": rel_path,
                    "line": line_num,
                    "match": lines[line_num - 1].strip()[:200] if 0 < line_num <= len(lines) else "",
                    "context": _extract_context(lines, line_num - 1) if line_num > 0 else "",
                })

        for sig_id, (regex, sig) in self._compiled.items():
            for line_num, line in enumerate(lines, 1):
                if regex.search(line):
                    findings.append({
                        "type": sig_id,
                        "category": sig.get("category", ""),
                        "severity": sig.get("severity", "medium"),
                        "message": sig.get("description", f"Pattern match: {sig_id}"),
                        "file": rel_path,
                        "line": line_num,
                        "match": line.strip()[:200],
                        "context": _extract_context(lines, line_num - 1),
                    })
                    break

        return findings

    def get_stats(self):
        total = sum(len(sigs) for sigs in self.signatures.values())
        ac_count = len(self._ac_map)
        regex_count = len(self._compiled)
        return {
            "categories": len(self.signatures),
            "total_signatures": total,
            "ac_patterns": ac_count,
            "regex_patterns": regex_count,
            "breakdown": {k: len(v) for k, v in self.signatures.items()},
        }


def _find_line(content, pattern):
    idx = content.lower().find(pattern.lower())
    if idx == -1:
        return 0
    return content[:idx].count("\n") + 1


def _extract_context(lines, idx, span=2):
    start = max(0, idx - span)
    end = min(len(lines), idx + span + 1)
    ctx = []
    for i in range(start, end):
        prefix = ">>>" if i == idx else "   "
        ctx.append(f"{prefix} {i + 1}: {lines[i].rstrip()[:150]}")
    return "\n".join(ctx)
