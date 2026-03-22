import os
import sys
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.file_walker import walk_theme, detect_suspicious_names, count_files
from core.pattern_engine import PatternEngine
from core.obfuscation import analyze_obfuscation
from core.network_intel import analyze_network
from core.integrity import check_integrity
from core.payload_decoder import analyze_payload
from core.forensics import check_file_hash, analyze_timestamps
from core.php_analyzer import analyze_php_functions
from core.deobfuscator import deobfuscate
from core.threat_engine import load_rules, scan_with_rules, behavioral_scan
from core.wp_deep_scan import wp_deep_scan
from core.php_deep_scan import php_deep_analyze
from core.wp_hardening import (
    scan_htaccess, audit_wp_config, scan_db_credential_leaks,
    scan_session_security, check_wp_core_integrity,
)
from core.advanced_detect import (
    detect_polyglot_files, build_infection_timeline, detect_c2_channels,
    classify_malware_family, auto_generate_rule,
)
from core.ml_classifier import ml_classify
from core.cloud_intel import cloud_scan_file
from core.decoder_recursive import recursive_decode
from core.file_classifier import FileClassifier
from core.deduper import deduplicate
from core.scorer import score_finding, score_file_bundle
from core.correlation import correlate
from core.suppression import apply_suppressions
from core.fp_tuner import filter_findings
from core.evidence_store import EvidenceStore
from core.triage_report import generate_triage
from core.perf_optimizer import (
    load_scan_cache, save_scan_cache, should_skip_file,
    mark_file_scanned, read_file_fast, prefilter_files,
    get_performance_stats,
)
from utils.config import THREAD_POOL_SIZE
from utils.colors import critical, high, medium, low, info, bold, green, red, yellow, cyan

_log = logging.getLogger("themeguard.scanner")
_SCAN_LABELS = {"theme": "Theme", "plugin": "Plugin", "full": "wp-content"}
_SEV_FORMATTERS = {"critical": critical, "high": high, "medium": medium, "low": low}


class Scanner:

    def __init__(self, path, deep=False, verbosity=1, scan_type="theme", network=False):
        self.path = os.path.abspath(path)
        self.deep = deep
        self.verbosity = verbosity
        self.scan_type = scan_type
        self.network = network
        self.engine = PatternEngine()
        self.threat_rules = load_rules()
        self.classifier = FileClassifier()
        self._cache = load_scan_cache()
        self.cloud = network
        self.findings = []
        self.files_scanned = 0
        self.cache_hits = 0
        self.errors = []
        self.scan_time = 0.0
        self._store = EvidenceStore()

    def run(self):
        start = time.time()
        stats = self.engine.get_stats()
        label = _SCAN_LABELS.get(self.scan_type, "Target")
        depth = "Deep" if self.deep else "Standard"
        rule_count = len(self.threat_rules)

        print(info(f"{label} target: {bold(self.path)}"))
        print(info(f"Scan type: {bold(self.scan_type)} | Depth: {bold(depth)}"))
        print(info(f"Signatures: {stats['total_signatures']} | Threat rules: {rule_count} | Modules: 30"))
        total = count_files(self.path)
        print(info(f"Files to scan: {total}"))
        if self.network:
            print(info(f"Network sandbox: {bold('enabled')}"))
        print()

        scan_id = self._store.start_scan(self.path, self.scan_type)

        file_list = prefilter_files(list(walk_theme(self.path)), self.path)
        with ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE) as pool:
            futures = {pool.submit(self._scan_file, fp): fp for fp in file_list}
            done = 0
            for future in as_completed(futures):
                done += 1
                fp = futures[future]
                try:
                    hits = future.result()
                    if hits:
                        self.findings.extend(hits)
                        if self.verbosity > 0:
                            for h in hits:
                                self._print_finding(h)
                except Exception as exc:
                    rel = os.path.relpath(fp, self.path)
                    self.errors.append({"file": rel, "error": str(exc)})
                    _log.warning("Scan error on %s: %s", rel, exc)
                self.files_scanned = done
                self._progress(done, total)

        print()

        self.findings.extend(scan_htaccess(self.path))
        self.findings.extend(audit_wp_config(self.path))
        self.findings.extend(detect_polyglot_files(self.path))
        self.findings.extend(build_infection_timeline(self.path))

        if self.deep:
            self.findings.extend(check_wp_core_integrity(self.path))

        rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
        generated = auto_generate_rule(self.findings, rules_dir)
        if generated:
            print(info(f"Auto-generated {generated} threat rule(s) from findings"))

        self.findings = deduplicate(self.findings)
        self.findings = correlate(self.findings)
        self.findings = [score_finding(f) for f in self.findings]
        self.findings = apply_suppressions(self.findings)
        self.findings = filter_findings(self.findings)

        self._store.store_findings(scan_id, self.findings)
        self._store.finish_scan(scan_id, self.files_scanned, len(self.findings))

        save_scan_cache(self._cache)

        self.scan_time = time.time() - start

        perf = get_performance_stats(self.scan_time, self.files_scanned, len(self.findings))
        if self.cache_hits > 0:
            print(info(f"Cache hits: {self.cache_hits} files skipped (unchanged)"))
        print(info(f"Throughput: {perf['files_per_second']} files/sec"))

        if self.errors:
            print(info(f"Scan errors: {len(self.errors)} (logged)"))

        self._summary()

        triage = generate_triage(self.findings, {
            "target": self.path,
            "scan_time": self.scan_time,
            "files_scanned": self.files_scanned,
        })
        print(triage)

        return self.findings

    def _scan_file(self, fpath):
        rel = os.path.relpath(fpath, self.path)
        out = []

        skip, chash = should_skip_file(fpath, self._cache)
        if skip:
            self.cache_hits += 1
            return out

        finfo = self.classifier.classify(fpath)

        out.extend(detect_suspicious_names(fpath, self.path))
        out.extend(check_file_hash(fpath, rel))
        out.extend(analyze_timestamps(fpath, rel, self.path))

        content = read_file_fast(fpath)
        if content is None or not content.strip():
            mark_file_scanned(chash, self._cache, False)
            return out

        if not self.classifier.should_deep_scan(finfo):
            mark_file_scanned(chash, self._cache, bool(out))
            return out

        out.extend(self.engine.scan_content(content, rel))
        out.extend(analyze_obfuscation(content, rel))
        out.extend(analyze_network(content, rel))
        out.extend(check_integrity(content, rel, fpath, self.path))
        out.extend(analyze_payload(content, rel))
        out.extend(analyze_php_functions(content, rel))
        out.extend(deobfuscate(content, rel))
        out.extend(scan_with_rules(content, rel, self.threat_rules))
        out.extend(behavioral_scan(content, rel))
        out.extend(wp_deep_scan(content, rel))
        out.extend(php_deep_analyze(content, rel))
        out.extend(scan_db_credential_leaks(content, rel, self.path))
        out.extend(scan_session_security(content, rel))
        out.extend(detect_c2_channels(content, rel))
        out.extend(classify_malware_family(content, rel))
        out.extend(ml_classify(content, rel))
        out.extend(recursive_decode(content, rel))

        if self.cloud:
            out.extend(cloud_scan_file(content, rel, fpath))

        if self.network:
            from core.net_sandbox import sandbox_urls
            out.extend(sandbox_urls(content, rel))

        mark_file_scanned(chash, self._cache, bool(out))
        return out

    def _print_finding(self, finding):
        sev = finding.get("severity", "medium")
        loc = finding.get("file", "")
        if finding.get("line"):
            loc += f":{finding['line']}"

        fmt = _SEV_FORMATTERS.get(sev, low)
        conf = finding.get("confidence")
        conf_str = f" [{conf:.0%}]" if conf is not None else ""
        print(f"  {fmt(finding.get('message', '') + conf_str)}")
        print(f"    {cyan(loc)}")
        if "match" in finding:
            print(f"    {finding['match'][:120]}")
        print()

    def _progress(self, done, total):
        pct = int((done / total) * 100) if total else 100
        filled = int(30 * done / total) if total else 30
        bar = "#" * filled + "-" * (30 - filled)
        print(f"\r  Scanning [{bar}] {pct}% ({done}/{total})", end="", flush=True)

    def _summary(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.get("severity", "low")] += 1

        total = len(self.findings)
        label = _SCAN_LABELS.get(self.scan_type, "target").lower()

        print(bold("\n  Scan Summary"))
        print(f"  {'=' * 40}")
        print(f"  Files scanned:  {self.files_scanned}")
        print(f"  Scan time:      {self.scan_time:.2f}s")
        print(f"  Total findings: {total}")
        print()

        if total == 0:
            print(green(f"  [OK] No threats detected. {label.title()} appears clean."))
        else:
            for sev in ("critical", "high", "medium", "low"):
                if counts[sev]:
                    print(_SEV_FORMATTERS[sev](f"  {counts[sev]} {sev}"))
            if counts["critical"] > 0:
                print(red(f"\n  [!] CRITICAL threats found. DO NOT use this {label}."))
            elif counts["high"] > 0:
                print(yellow(f"\n  [!] High-severity issues found. Manual review required."))
        print()

    def get_results(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.get("severity", "low")] += 1

        return {
            "target": self.path,
            "files_scanned": self.files_scanned,
            "scan_time": round(self.scan_time, 2),
            "total_findings": len(self.findings),
            "severity_counts": counts,
            "findings": self.findings,
            "signatures": self.engine.get_stats(),
            "errors": self.errors,
        }
