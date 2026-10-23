"""Bound scanner uploads without changing scan results or report bytes."""
# SPDX-License-Identifier: MPL-2.0
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "report_upload", ROOT / "scripts/ci/check-report-upload.py")
upload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upload)
sys.path.insert(0, str(ROOT / "scripts"))
import check_workflow_policy as policy


class ReportUpload(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.workspace = self.root / "workspace"
        self.scratch = self.root / "temporary"
        self.workspace.mkdir()
        self.scratch.mkdir()

    def tearDown(self):
        for folder in self.scratch.iterdir():
            if folder.is_dir() and not folder.is_symlink():
                folder.chmod(0o700)
        self.temp.cleanup()

    def test_snapshot_is_complete_read_only_and_independent_of_later_source_changes(self):
        source = self.workspace / "results.sarif"
        raw = b'{"runs": [{"results": []}]}\n'
        source.write_bytes(raw)
        target = upload.snapshot_report("gitleaks", self.workspace, self.scratch)
        self.assertEqual(target.read_bytes(), raw)
        self.assertEqual(target.name, "results.sarif")
        self.assertEqual(target.stat().st_mode & 0o777, 0o400)
        source.write_bytes(b"changed later")
        self.assertEqual(target.read_bytes(), raw)

    def test_oversize_missing_empty_and_indirect_reports_fail_before_snapshot(self):
        source = self.workspace / "results.sarif"
        cases = ("missing", "empty", "oversize", "symlink", "hardlink", "directory")
        for case in cases:
            with self.subTest(case=case):
                if source.is_dir(): source.rmdir()
                elif source.exists() or source.is_symlink(): source.unlink()
                if case == "empty": source.touch()
                elif case == "oversize":
                    with source.open("wb") as stream: stream.truncate(upload.REPORT_LIMIT + 1)
                elif case == "symlink": source.symlink_to(self.workspace / "other")
                elif case == "hardlink":
                    source.write_bytes(b"data"); os.link(source, self.workspace / "alias")
                elif case == "directory": source.mkdir()
                with self.assertRaises((OSError, ValueError)):
                    upload.snapshot_report("gitleaks", self.workspace, self.scratch)
                self.assertFalse((self.scratch / "pghar-report-upload-gitleaks").exists())

    def test_size_boundary_and_changed_input_and_reused_destination_fail_closed(self):
        source = self.workspace / "trivy-fs-results.json"
        source.write_bytes(b"x" * 64)
        with mock.patch.object(upload, "REPORT_LIMIT", 64):
            target = upload.snapshot_report("trivy", self.workspace, self.scratch)
        self.assertEqual(target.read_bytes(), b"x" * 64)
        with self.assertRaises(FileExistsError):
            upload.snapshot_report("trivy", self.workspace, self.scratch)
        source = self.workspace / "results.sarif"
        source.write_bytes(b"before")
        original_open = os.open
        def change_then_open(path, flags, *args, **kwargs):
            if path == source: source.write_bytes(b"after")
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(upload.os, "open", side_effect=change_then_open):
            with self.assertRaises(ValueError):
                upload.snapshot_report("gitleaks", self.workspace, self.scratch)

    def test_workflows_keep_scans_and_route_every_ordinary_upload_through_guard(self):
        ci = policy.parse_workflow((ROOT / ".github/workflows/ci.yml").read_text())
        sanitization = policy.parse_workflow((ROOT / ".github/workflows/sanitization.yml").read_text())
        steps = sanitization["jobs"]["sanitization"]["steps"]
        scan = next(step for step in steps if step.get("id") == "gitleaks")
        self.assertEqual(scan["uses"], "gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e")
        self.assertEqual(scan["env"]["GITLEAKS_ENABLE_UPLOAD_ARTIFACT"], "false")
        self.assertNotIn("continue-on-error", scan)
        guard = next(step for step in steps if step.get("id") == "gitleaks-report")
        self.assertIn("steps.gitleaks.outcome == 'failure'", guard["if"])
        self.assertIn("check-report-upload.py gitleaks", guard["run"])
        jobs = [ci["jobs"]["container"], sanitization["jobs"]["sanitization"]]
        for job, identity, retention in zip(jobs, ("trivy-report", "gitleaks-report"), (14, 90)):
            uploads = [s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")]
            self.assertEqual(len(uploads), 1)
            self.assertEqual(uploads[0]["with"]["path"], "${{ steps." + identity + ".outputs.path }}")
            self.assertEqual(uploads[0]["with"]["retention-days"], str(retention))
            self.assertEqual(uploads[0]["with"]["compression-level"], "0")
            self.assertEqual(uploads[0]["with"]["if-no-files-found"], "error")
        self.assertLess(upload.REPORT_LIMIT, 50 * 2**20)


if __name__ == "__main__":
    unittest.main()
