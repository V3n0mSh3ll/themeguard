import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pattern_engine import PatternEngine
from core.obfuscation import analyze_obfuscation, _shannon_entropy
from core.network_intel import analyze_network
from core.integrity import check_integrity
from core.file_walker import walk_theme, detect_suspicious_names, count_files
from core.scanner import Scanner


class TestPatternEngine(unittest.TestCase):

    def setUp(self):
        self.engine = PatternEngine()

    def test_signatures_loaded(self):
        stats = self.engine.get_stats()
        self.assertGreater(stats["total_signatures"], 100)

    def test_eval_base64(self):
        r = self.engine.scan_content('<?php eval(base64_decode("x")); ?>', "t.php")
        self.assertGreater(len(r), 0)

    def test_c99_shell(self):
        r = self.engine.scan_content("<?php // c99shell v2 ?>", "t.php")
        self.assertGreater(len(r), 0)

    def test_coinhive(self):
        r = self.engine.scan_content('<script src="coinhive.min.js"></script>', "t.html")
        self.assertGreater(len(r), 0)

    def test_clean(self):
        r = self.engine.scan_content('<?php echo "Hello"; the_title(); ?>', "h.php")
        crits = [x for x in r if x["severity"] == "critical"]
        self.assertEqual(len(crits), 0)


class TestObfuscation(unittest.TestCase):

    def test_entropy_normal(self):
        self.assertLess(_shannon_entropy("Normal PHP file content"), 5.0)

    def test_encoding_chain(self):
        r = analyze_obfuscation('<?php eval(gzinflate(base64_decode("x"))); ?>', "t.php")
        self.assertIn("encoding_chain", [x["type"] for x in r])

    def test_long_line(self):
        r = analyze_obfuscation("<?php " + "a" * 1500 + " ?>", "t.php")
        self.assertIn("long_line_obfuscation", [x["type"] for x in r])

    def test_chr_chain(self):
        calls = " . ".join([f"chr({i})" for i in range(65, 90)])
        r = analyze_obfuscation(f"<?php $s = {calls}; ?>", "t.php")
        self.assertIn("chr_chain", [x["type"] for x in r])


class TestNetworkIntel(unittest.TestCase):

    def test_suspicious_tld(self):
        r = analyze_network('<?php file_get_contents("http://bad.tk/p"); ?>', "t.php")
        self.assertGreater(len(r), 0)


class TestIntegrity(unittest.TestCase):

    def test_core_file(self):
        tmp = tempfile.mkdtemp()
        try:
            fp = os.path.join(tmp, "wp-config.php")
            with open(fp, "w") as f:
                f.write("<?php ?>")
            r = check_integrity("<?php ?>", "wp-config.php", fp, tmp)
            self.assertIn("non_theme_file", [x["type"] for x in r])
        finally:
            shutil.rmtree(tmp)


class TestFileWalker(unittest.TestCase):

    def test_walk(self):
        tmp = tempfile.mkdtemp()
        try:
            for i in range(3):
                with open(os.path.join(tmp, f"f{i}.php"), "w") as f:
                    f.write("<?php ?>")
            self.assertEqual(count_files(tmp), 3)
        finally:
            shutil.rmtree(tmp)

    def test_suspicious_name(self):
        tmp = tempfile.mkdtemp()
        try:
            fp = os.path.join(tmp, "wp-tmp.php")
            with open(fp, "w") as f:
                f.write("<?php ?>")
            r = detect_suspicious_names(fp, tmp)
            self.assertGreater(len(r), 0)
        finally:
            shutil.rmtree(tmp)


class TestFullScan(unittest.TestCase):

    def test_clean(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "index.php"), "w") as f:
                f.write("<?php get_header(); ?>")
            s = Scanner(tmp, verbosity=0)
            s.run()
            r = s.get_results()
            self.assertEqual(r["severity_counts"]["critical"], 0)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
