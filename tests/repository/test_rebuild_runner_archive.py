"""Archive publication tests for the public runner rebuild recipe."""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import importlib.util
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class RebuildArchive(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "rebuild_runner", ROOT / "scripts/release/rebuild-runner.py"
        )
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.layout = self.root / "layout"
        (self.layout / "bin").mkdir(parents=True)
        (self.layout / "bin/runner").write_bytes(b"synthetic executable\n")
        (self.layout / "LICENSE").write_bytes(b"synthetic license\n")
        os.chmod(self.layout / "bin/runner", 0o755)

    def test_archive_ignores_filesystem_mtime_and_creation_order(self):
        first, second = self.root / "A.tar.gz", self.root / "B.tar.gz"
        self.module.package_archive(self.layout, first, 123)
        (self.layout / "LICENSE").unlink()
        (self.layout / "LICENSE").write_bytes(b"synthetic license\n")
        for item in self.layout.rglob("*"):
            os.utime(item, (456, 789))
        self.module.package_archive(self.layout, second, 123)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_links_are_refused_before_any_archive_is_published(self):
        (self.layout / "alias").symlink_to("LICENSE")
        target = self.root / "output.tar.gz"
        with self.assertRaises(ValueError):
            self.module.package_archive(self.layout, target, 123)
        self.assertFalse(target.exists())

    def test_wrong_digest_removes_partial_and_preserves_existing_target(self):
        partial = self.root / "partial"
        partial.write_bytes(b"unexpected bytes")
        destination = self.root / "archive.tar.gz"
        destination.write_bytes(b"existing evidence")
        with self.assertRaises(ValueError):
            self.module.publish_archive(
                partial, destination,
                {"archive_bytes": len(b"unexpected bytes"), "sha256": "a" * 64},
            )
        self.assertFalse(partial.exists())
        self.assertEqual(destination.read_bytes(), b"existing evidence")
