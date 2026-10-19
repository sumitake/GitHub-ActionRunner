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

    def test_sdk_timeout_removes_only_its_created_container(self):
        from unittest import mock
        import subprocess
        container_id = "b" * 64
        work = self.root / "build"
        work.mkdir()
        def timeout(arguments, cwd, env):
            cidfile = pathlib.Path(arguments[arguments.index("--cidfile") + 1])
            self.assertFalse(cidfile.is_relative_to(work))
            cidfile.write_text(container_id)
            raise subprocess.TimeoutExpired(arguments, 1)
        with mock.patch.object(self.module, "run", side_effect=timeout), mock.patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as cleanup:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.module.run_sdk(["docker", "run", "--rm", "synthetic-image", "dotnet"], work, {})
        self.assertEqual(cleanup.call_args.args[0], ["docker", "rm", "--force", container_id])

    def test_archive_uses_the_existing_strict_extractor_wire_format(self):
        import tarfile
        nested = self.layout / "bin/third-party-licenses" / ("synthetic-package-" + "x" * 48) / "1.2.3"
        nested.mkdir(parents=True)
        (nested / "producer-record.nuspec").write_bytes(b"synthetic producer metadata\n")
        target = self.root / "wire-format.tar.gz"
        self.module.package_archive(self.layout, target, 123)
        with tarfile.open(target) as archive:
            members = archive.getmembers()
        self.assertTrue(members[0].isdir())
        self.assertEqual(members[0].name, ".")
        self.assertTrue(all(m.name.startswith("./") for m in members[1:]))
        self.assertTrue(all(not m.pax_headers for m in members))

    def test_sealed_externals_can_move_without_carrying_the_old_bin(self):
        prepared = self.root / "prepared"
        (prepared / "externals").mkdir(parents=True)
        (prepared / "externals/public-tool").write_bytes(b"synthetic external\n")
        (prepared / "bin").mkdir()
        (prepared / "bin/old-runtime").write_bytes(b"old synthetic runtime\n")
        for path in prepared.rglob("*"):
            os.chmod(path, 0o555 if path.is_dir() else 0o444)
        destination = self.root / "externals"
        self.module.take_prepared_externals(prepared, destination)
        self.assertEqual((destination / "public-tool").read_bytes(), b"synthetic external\n")
        self.assertFalse(prepared.exists())
        self.assertFalse((destination / "old-runtime").exists())
