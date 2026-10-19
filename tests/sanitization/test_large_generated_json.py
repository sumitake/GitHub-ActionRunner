"""Synthetic regression for bounded IP-context scanning of compact SBOMs."""
import subprocess
import sys
from pathlib import Path
import unittest


class LargeGeneratedJSON(unittest.TestCase):
    def test_labeled_ip_scan_is_linear_on_large_unlabeled_numeric_inventory(self):
        scripts = Path(__file__).resolve().parents[2] / 'scripts'
        code = """
import sys
sys.path.insert(0, sys.argv[1])
import sanitize_public as sp
text = '{' + ','.join('"build":12345' for _ in range(50000)) + '}'
ctx = sp.LineCtx('sbom/fixture.spdx.json', 1, False, 'fixture.spdx.json')
assert sp._check_ip_literals(text, ctx) == []
"""
        result = subprocess.run([sys.executable, '-c', code, str(scripts)], timeout=3, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
