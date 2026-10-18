"""Synthetic metadata substitutions must not acquire a snapshot's authority."""
import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'images/runner/verify-debian-cache.sh'


class OfflineSnapshotPins(unittest.TestCase):
    def fixture(self, root):
        source = SCRIPT.read_text()
        pins = re.findall(r'^verify ([0-9a-f]{64}) (\S+)$', source, re.M)
        self.assertEqual(len(pins), 3)
        for index, (expected, relative) in enumerate(pins):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            content = f'synthetic signed metadata {index}\n'.encode()
            path.write_bytes(content)
            source = source.replace(expected, hashlib.sha256(content).hexdigest())
        staged = root / 'verify.sh'
        staged.write_text(source)
        return staged, [root / p for _, p in pins]

    def invoke(self, script, root, snapshot='20261010T000000Z'):
        return subprocess.run(['/bin/sh', str(script), str(root), snapshot], capture_output=True).returncode

    def test_hashes_bind_content_instead_of_asserted_directory_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script, inputs = self.fixture(root)
            self.assertEqual(self.invoke(script, root), 0)
            inputs[0].write_bytes(b'other synthetically signed snapshot\n')
            self.assertNotEqual(self.invoke(script, root), 0)

    def test_missing_symlink_and_different_snapshot_fail_closed(self):
        for scenario in ('missing', 'symlink', 'snapshot'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                script, inputs = self.fixture(root)
                if scenario == 'missing':
                    inputs[0].unlink()
                elif scenario == 'symlink':
                    saved = root / 'saved'
                    inputs[0].rename(saved)
                    inputs[0].symlink_to(saved)
                snapshot = '20261011T000000Z' if scenario == 'snapshot' else '20261010T000000Z'
                self.assertNotEqual(self.invoke(script, root, snapshot), 0)
