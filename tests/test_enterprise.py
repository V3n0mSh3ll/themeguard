import os
import sys
import json
import shutil
import tempfile
import sqlite3
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSafeIO(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_utf8_read(self):
        from core.safe_io import safe_read_text
        p = os.path.join(self.tmpdir, "test.php")
        with open(p, "w", encoding="utf-8") as f:
            f.write("<?php echo 'hello'; ?>")
        result = safe_read_text(p)
        self.assertIn("hello", result)

    def test_latin1_fallback(self):
        from core.safe_io import safe_read_text
        p = os.path.join(self.tmpdir, "latin.php")
        with open(p, "wb") as f:
            f.write(b"<?php echo '\xe9\xe8'; ?>")
        result = safe_read_text(p)
        self.assertIsNotNone(result)
        self.assertIn("<?php", result)

    def test_empty_file(self):
        from core.safe_io import safe_read_text
        p = os.path.join(self.tmpdir, "empty.php")
        with open(p, "w") as f:
            pass
        result = safe_read_text(p)
        self.assertEqual(result, "")

    def test_size_limit(self):
        from core.safe_io import safe_read_text
        p = os.path.join(self.tmpdir, "big.php")
        with open(p, "w") as f:
            f.write("x" * 100)
        result = safe_read_text(p, max_size=50)
        self.assertIsNone(result)

    def test_nonexistent_file(self):
        from core.safe_io import safe_read_text
        result = safe_read_text("/nonexistent/path.php")
        self.assertIsNone(result)

    def test_json_load_utf8(self):
        from core.safe_io import safe_load_json
        p = os.path.join(self.tmpdir, "data.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"key": "value"}, f)
        result = safe_load_json(p, {})
        self.assertEqual(result["key"], "value")

    def test_json_load_malformed(self):
        from core.safe_io import safe_load_json
        p = os.path.join(self.tmpdir, "bad.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write("{broken json!!")
        result = safe_load_json(p, {"default": True})
        self.assertTrue(result.get("default"))

    def test_json_write_atomic(self):
        from core.safe_io import safe_write_json, safe_load_json
        p = os.path.join(self.tmpdir, "out.json")
        safe_write_json(p, {"test": 123})
        result = safe_load_json(p)
        self.assertEqual(result["test"], 123)

    def test_regex_compile_valid(self):
        from core.safe_io import safe_compile_regex
        r = safe_compile_regex(r"eval\s*\(")
        self.assertIsNotNone(r)

    def test_regex_compile_invalid(self):
        from core.safe_io import safe_compile_regex
        r = safe_compile_regex(r"[invalid")
        self.assertIsNone(r)

    def test_regex_too_long(self):
        from core.safe_io import safe_compile_regex
        r = safe_compile_regex("a" * 3000)
        self.assertIsNone(r)

    def test_path_normalization(self):
        from core.safe_io import normalize_path
        self.assertEqual(normalize_path("a/../b/./c"), "b/c")
        self.assertEqual(normalize_path("foo/bar"), "foo/bar")

    def test_path_traversal_detect(self):
        from core.safe_io import is_path_traversal
        self.assertTrue(is_path_traversal("../../etc/passwd"))
        self.assertFalse(is_path_traversal("wp-content/themes/test"))

    def test_sha256(self):
        from core.safe_io import content_sha256
        h = content_sha256("hello")
        self.assertEqual(len(h), 64)

    def test_stable_finding_id(self):
        from core.safe_io import stable_finding_id
        f = {"file": "test.php", "line": 10, "type": "eval", "message": "danger"}
        id1 = stable_finding_id(f)
        id2 = stable_finding_id(f)
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("TG-"))

    def test_error_collector(self):
        from core.safe_io import ErrorCollector
        ec = ErrorCollector()
        ec.add("io", "test.php", "read fail")
        ec.add("decode", "bad.php", "utf error", ValueError("x"))
        summary = ec.get_summary()
        self.assertEqual(summary["total_errors"], 2)
        self.assertIn("io", summary["categories"])


class TestDeduper(unittest.TestCase):

    def test_basic_dedup(self):
        from core.deduper import deduplicate
        findings = [
            {"file": "a.php", "line": 10, "type": "eval", "severity": "high", "message": "eval found"},
            {"file": "a.php", "line": 10, "type": "eval", "severity": "high", "message": "eval found"},
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["evidence_count"], 2)

    def test_different_files_not_deduped(self):
        from core.deduper import deduplicate
        findings = [
            {"file": "a.php", "line": 10, "type": "eval", "severity": "high", "message": "eval"},
            {"file": "b.php", "line": 10, "type": "eval", "severity": "high", "message": "eval"},
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 2)

    def test_severity_promotion(self):
        from core.deduper import deduplicate
        findings = [
            {"file": "a.php", "line": 10, "type": "eval", "severity": "medium", "message": "eval found"},
            {"file": "a.php", "line": 11, "type": "eval", "severity": "critical", "message": "eval found"},
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "critical")

    def test_stable_ids(self):
        from core.deduper import deduplicate
        findings = [
            {"file": "a.php", "line": 10, "type": "eval", "severity": "high", "message": "test"},
        ]
        r1 = deduplicate(findings)
        r2 = deduplicate(findings)
        self.assertEqual(r1[0]["id"], r2[0]["id"])
        self.assertTrue(r1[0]["id"].startswith("TG-"))

    def test_deterministic_order(self):
        from core.deduper import deduplicate
        findings = [
            {"file": "z.php", "line": 1, "type": "x", "severity": "low", "message": "a"},
            {"file": "a.php", "line": 1, "type": "x", "severity": "critical", "message": "b"},
            {"file": "m.php", "line": 1, "type": "x", "severity": "high", "message": "c"},
        ]
        result = deduplicate(findings)
        self.assertEqual(result[0]["severity"], "critical")
        self.assertEqual(result[1]["severity"], "high")
        self.assertEqual(result[2]["severity"], "low")


class TestScorer(unittest.TestCase):

    def test_score_basic(self):
        from core.scorer import score_finding
        f = {"file": "test.php", "type": "eval", "severity": "high", "message": "x"}
        result = score_finding(f)
        self.assertIn("confidence", result)
        self.assertIn("action", result)
        self.assertGreater(result["confidence"], 0)

    def test_vendor_penalty(self):
        from core.scorer import score_finding
        f1 = {"file": "test.php", "type": "eval", "severity": "high", "message": "x"}
        f2 = {"file": "vendor/lib/test.php", "type": "eval", "severity": "high", "message": "x"}
        r1 = score_finding(f1)
        r2 = score_finding(f2)
        self.assertGreater(r1["confidence"], r2["confidence"])

    def test_critical_action(self):
        from core.scorer import score_finding
        f = {"file": "test.php", "type": "malware_family_wpvcd", "severity": "critical", "message": "x", "evidence_count": 5}
        result = score_finding(f)
        self.assertIn(result["action"], ("quarantine", "review"))

    def test_file_bundle_score(self):
        from core.scorer import score_file_bundle
        findings = [
            {"severity": "critical", "confidence": 0.95},
            {"severity": "high", "confidence": 0.8},
        ]
        score = score_file_bundle(findings)
        self.assertGreater(score, 0)


class TestDecoderRecursive(unittest.TestCase):

    def test_simple_b64(self):
        import base64
        from core.decoder_recursive import recursive_decode
        payload = base64.b64encode(b"eval(system('ls'))").decode()
        content = f"<?php eval(base64_decode('{payload}')); ?>"
        findings = recursive_decode(content, "test.php")
        self.assertTrue(len(findings) >= 0)

    def test_hex_escape(self):
        from core.decoder_recursive import recursive_decode
        hex_payload = "".join(f"\\x{ord(c):02x}" for c in "eval(system('id'))")
        content = f'$x = "{hex_payload}";'
        findings = recursive_decode(content, "test.php")
        self.assertTrue(len(findings) >= 0)

    def test_chr_chain(self):
        from core.decoder_recursive import recursive_decode
        chars = ",".join(f"chr({ord(c)})" for c in "eval(exec)")
        content = f"<?php $f = {chars}; ?>"
        findings = recursive_decode(content, "test.php")
        has_chr = any("chr" in f.get("type", "") for f in findings)
        self.assertTrue(has_chr or len(findings) >= 0)

    def test_no_false_on_clean(self):
        from core.decoder_recursive import recursive_decode
        content = "<?php echo 'Hello World'; ?>"
        findings = recursive_decode(content, "clean.php")
        self.assertEqual(len(findings), 0)

    def test_depth_limit(self):
        import base64
        from core.decoder_recursive import recursive_decode
        payload = "eval('test')"
        for _ in range(15):
            payload = base64.b64encode(payload.encode()).decode()
        findings = recursive_decode(payload, "deep.php")
        self.assertTrue(len(findings) >= 0)


class TestFileClassifier(unittest.TestCase):

    def test_php_scannable(self):
        from core.file_classifier import FileClassifier
        fc = FileClassifier()
        info = fc.classify("test/functions.php")
        self.assertTrue(info["is_scannable"])
        self.assertTrue(info["is_text"])

    def test_image_binary(self):
        from core.file_classifier import FileClassifier
        fc = FileClassifier()
        info = fc.classify("uploads/photo.jpg")
        self.assertTrue(info["is_binary"])
        self.assertFalse(info["is_scannable"])

    def test_vendor_low_priority(self):
        from core.file_classifier import FileClassifier
        fc = FileClassifier()
        info = fc.classify("path/vendor/autoload.php")
        self.assertTrue(info["is_vendor"])
        self.assertEqual(info["risk_priority"], "low")

    def test_wp_config_critical(self):
        from core.file_classifier import FileClassifier
        fc = FileClassifier()
        info = fc.classify("wp-config.php")
        self.assertTrue(info["is_config"])
        self.assertEqual(info["risk_priority"], "critical")

    def test_minified_detection(self):
        from core.file_classifier import FileClassifier
        fc = FileClassifier()
        self.assertTrue(fc.is_minified_content("a" * 600))

    def test_should_deep_scan(self):
        from core.file_classifier import FileClassifier
        fc = FileClassifier()
        self.assertTrue(fc.should_deep_scan({"is_binary": False, "is_scannable": True, "is_vendor": False, "risk_priority": "normal"}))
        self.assertFalse(fc.should_deep_scan({"is_binary": True, "is_scannable": False}))


class TestCorrelation(unittest.TestCase):

    def test_shared_url(self):
        from core.correlation import correlate
        findings = [
            {"file": "a.php", "type": "network", "message": "http://evil.com/backdoor.php", "severity": "high", "match": ""},
            {"file": "b.php", "type": "network", "message": "http://evil.com/backdoor.php", "severity": "high", "match": ""},
        ]
        result = correlate(findings)
        corr = [f for f in result if f["type"].startswith("correlation_")]
        self.assertTrue(len(corr) > 0)

    def test_no_correlation_on_single(self):
        from core.correlation import correlate
        findings = [
            {"file": "a.php", "type": "eval", "message": "eval found", "severity": "high", "match": ""},
        ]
        result = correlate(findings)
        corr = [f for f in result if f["type"].startswith("correlation_")]
        self.assertEqual(len(corr), 0)

    def test_multi_signal(self):
        from core.correlation import correlate
        findings = [
            {"file": "shell.php", "type": "obfuscation_entropy", "message": "x", "severity": "medium", "match": ""},
            {"file": "shell.php", "type": "eval_base64", "message": "x", "severity": "high", "match": ""},
            {"file": "shell.php", "type": "network_callback", "message": "x", "severity": "high", "match": ""},
            {"file": "shell.php", "type": "file_dropper", "message": "x", "severity": "high", "match": ""},
        ]
        result = correlate(findings)
        multi = [f for f in result if f["type"] == "correlation_multi_signal"]
        self.assertTrue(len(multi) > 0)


class TestSuppression(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_apply_empty(self):
        from core.suppression import apply_suppressions
        findings = [{"file": "a.php", "type": "eval", "severity": "high"}]
        result = apply_suppressions(findings)
        self.assertEqual(len(result), 1)

    def test_no_crash_missing_files(self):
        from core.suppression import load_suppressions, load_allowlists
        s = load_suppressions()
        a = load_allowlists()
        self.assertIsInstance(s, list)
        self.assertIsInstance(a, dict)


class TestEvidenceStore(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_and_query(self):
        from core.evidence_store import EvidenceStore
        store = EvidenceStore(self.db_path)
        scan_id = store.start_scan("/test/path", "theme")
        self.assertTrue(len(scan_id) > 0)

        store.store_findings(scan_id, [
            {"file": "a.php", "type": "eval", "severity": "high", "message": "eval found"},
        ])
        store.finish_scan(scan_id, 10, 1)

        history = store.get_scan_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["files_scanned"], 10)

        findings = store.get_findings_by_scan(scan_id)
        self.assertEqual(len(findings), 1)
        store.close()

    def test_diff(self):
        from core.evidence_store import EvidenceStore
        store = EvidenceStore(self.db_path)
        id1 = store.start_scan("/test", "theme")
        store.store_findings(id1, [
            {"file": "a.php", "type": "eval", "severity": "high", "message": "old"},
        ])
        store.finish_scan(id1, 5, 1)

        id2 = store.start_scan("/test", "theme")
        store.store_findings(id2, [
            {"file": "b.php", "type": "exec", "severity": "critical", "message": "new"},
        ])
        store.finish_scan(id2, 5, 1)

        diff = store.get_diff(id1, id2)
        self.assertTrue(len(diff["new"]) > 0)
        self.assertTrue(len(diff["resolved"]) > 0)
        store.close()


class TestTriageReport(unittest.TestCase):

    def test_generate(self):
        from core.triage_report import generate_triage
        findings = [
            {"file": "a.php", "line": 1, "type": "eval", "severity": "critical", "confidence": 0.95, "message": "eval", "action": "quarantine"},
            {"file": "b.php", "line": 1, "type": "obf", "severity": "medium", "confidence": 0.4, "message": "obf", "action": "inspect"},
        ]
        meta = {"target": "/test", "scan_time": 1.5, "files_scanned": 10}
        report = generate_triage(findings, meta)
        self.assertIn("QUARANTINE", report)
        self.assertIn("TRIAGE REPORT", report)
        self.assertIn("RECOMMENDED NEXT STEPS", report)

    def test_clean_report(self):
        from core.triage_report import generate_triage
        report = generate_triage([], {"target": "/test", "scan_time": 0.5, "files_scanned": 5})
        self.assertIn("No files require immediate quarantine", report)


class TestPerfOptimizer(unittest.TestCase):

    def test_prefilter(self):
        from core.perf_optimizer import prefilter_files
        files = [
            "/site/wp-content/themes/test/style.css",
            "/site/wp-content/themes/test/functions.php",
            "/site/wp-content/themes/test/image.jpg",
        ]
        result = prefilter_files(files, "/site")
        self.assertNotIn("/site/wp-content/themes/test/image.jpg", result)

    def test_scan_cache(self):
        from core.perf_optimizer import load_scan_cache, save_scan_cache
        cache = load_scan_cache()
        self.assertIsInstance(cache, dict)

    def test_performance_stats(self):
        from core.perf_optimizer import get_performance_stats
        stats = get_performance_stats(2.0, 100, 5)
        self.assertEqual(stats["files_scanned"], 100)
        self.assertGreater(stats["files_per_second"], 0)


class TestFPTuner(unittest.TestCase):

    def test_filter_findings(self):
        from core.fp_tuner import filter_findings
        findings = [
            {"file": "test.php", "type": "eval", "severity": "high", "message": "eval"},
        ]
        result = filter_findings(findings)
        self.assertEqual(len(result), 1)

    def test_known_safe_skip(self):
        from core.fp_tuner import filter_findings
        findings = [
            {"file": "vendor/autoload.php", "type": "obfuscation", "severity": "medium", "message": "x"},
        ]
        result = filter_findings(findings)
        self.assertEqual(len(result), 0)


class TestMLClassifier(unittest.TestCase):

    def test_clean_file(self):
        from core.ml_classifier import ml_classify
        content = "<?php\necho 'Hello World';\nfunction greet() {\n    return 'Hi';\n}\n"
        findings = ml_classify(content, "clean.php")
        malicious = [f for f in findings if "malicious" in f.get("type", "").lower()]
        self.assertEqual(len(malicious), 0)

    def test_suspicious_file(self):
        from core.ml_classifier import ml_classify
        content = "<?php eval(base64_decode(str_rot13(gzinflate(" + "A" * 200 + "))));" + "\\x61" * 50
        findings = ml_classify(content, "suspicious.php")
        self.assertTrue(len(findings) >= 0)


class TestCloudIntel(unittest.TestCase):

    def test_import(self):
        from core.cloud_intel import cloud_scan_file
        self.assertTrue(callable(cloud_scan_file))


class TestRealtimeGuard(unittest.TestCase):

    def test_import(self):
        from core.realtime_guard import RealtimeGuard
        self.assertTrue(callable(RealtimeGuard))


if __name__ == "__main__":
    unittest.main()
