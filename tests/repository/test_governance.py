"""TDD suite for the Task 4 public governance baseline.

Covers: LICENSE verification (unchanged), the community/policy documents
(SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md,
THIRD_PARTY_NOTICES.md), the .github metadata (CODEOWNERS, PR template,
structured issue forms), and scripts/check_repository_metadata.py -- the
fail-closed checker that enforces all of the above in CI.

Run: python3 -m unittest tests.repository.test_governance -v
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_repository_metadata.py"

EXPECTED_LICENSE_SHA256 = (
    "3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04"
)
CANONICAL_CODEOWNERS_LINE = "* @sumitake"

GOVERNANCE_FILES = [
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "THIRD_PARTY_NOTICES.md",
    ".github/CODEOWNERS",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/feature.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
]

NO_PASTE_WARNING_RE = re.compile(
    r"(never|do not|don't)\s+paste\b.{0,80}\b(log|config|state)", re.IGNORECASE | re.DOTALL
)


def read(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8")


def run_checker(root: Path | None = None) -> subprocess.CompletedProcess:
    argv = [sys.executable, str(CHECKER)]
    if root is not None:
        argv += ["--root", str(root)]
    return subprocess.run(argv, capture_output=True, text=True)


class TestGovernanceFilesExist(unittest.TestCase):
    def test_all_governance_files_exist(self):
        for relpath in GOVERNANCE_FILES:
            with self.subTest(relpath=relpath):
                self.assertTrue(
                    (REPO_ROOT / relpath).is_file(), f"missing required file: {relpath}"
                )

    def test_checker_script_exists_and_executable_via_python3(self):
        self.assertTrue(CHECKER.is_file(), "missing scripts/check_repository_metadata.py")


class TestLicenseUnchanged(unittest.TestCase):
    def test_license_contains_mpl_header(self):
        text = read("LICENSE")
        self.assertIn("Mozilla Public License Version 2.0", text)

    def test_license_sha256_unchanged(self):
        raw = (REPO_ROOT / "LICENSE").read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(
            digest,
            EXPECTED_LICENSE_SHA256,
            "LICENSE bytes changed -- stop and reconcile rather than replacing it",
        )


class TestCodeowners(unittest.TestCase):
    def test_codeowners_is_exactly_the_canonical_wildcard_line(self):
        text = read(".github/CODEOWNERS")
        lines = [ln for ln in text.splitlines() if ln.strip() != ""]
        self.assertEqual(
            lines,
            [CANONICAL_CODEOWNERS_LINE],
            "CODEOWNERS must contain exactly one line: '* @sumitake'",
        )


class TestSecurityPolicy(unittest.TestCase):
    def test_routes_only_through_github_private_vulnerability_reporting(self):
        text = read("SECURITY.md")
        self.assertIn("private vulnerability reporting", text.lower())

    def test_does_not_offer_an_email_or_other_reporting_channel(self):
        text = read("SECURITY.md")
        self.assertNotIn("mailto:", text.lower())
        # No bare email address anywhere in the policy (the only sanctioned
        # channel is the GitHub private-reporting flow, not an inbox).
        self.assertIsNone(
            re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text),
            "SECURITY.md must not list an email reporting channel",
        )

    def test_states_pre_deployment_experimental_posture(self):
        text = read("SECURITY.md").lower()
        self.assertTrue(
            "pre-deployment" in text or "experimental" in text,
            "SECURITY.md must disclose the pre-deployment/experimental posture",
        )


class TestContributing(unittest.TestCase):
    def test_requires_tdd(self):
        text = read("CONTRIBUTING.md").lower()
        self.assertTrue("tdd" in text or "test-driven" in text)

    def test_requires_synthetic_fixtures_only(self):
        text = read("CONTRIBUTING.md").lower()
        self.assertIn("synthetic", text)

    def test_requires_signed_commits(self):
        text = read("CONTRIBUTING.md").lower()
        self.assertIn("signed commit", text)

    def test_requires_action_sha_pins(self):
        text = read("CONTRIBUTING.md").lower()
        self.assertTrue("sha" in text and "pin" in text)

    def test_requires_hosted_ci(self):
        text = read("CONTRIBUTING.md").lower()
        self.assertIn("hosted ci", text)

    def test_warns_never_to_paste_real_material(self):
        text = read("CONTRIBUTING.md")
        self.assertRegex(text, NO_PASTE_WARNING_RE)
        self.assertIn("secret", text.lower())


class TestPullRequestTemplate(unittest.TestCase):
    def test_has_public_safety_checklist(self):
        text = read(".github/PULL_REQUEST_TEMPLATE.md")
        self.assertIn("PUBLIC-SAFETY", text)

    def test_checklist_covers_required_items(self):
        text = read(".github/PULL_REQUEST_TEMPLATE.md").lower()
        for phrase in (
            "deployment identifier",
            "secret",
            "real log",
            "synthetic",
            "sanitize_public.py",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)


class TestIssueTemplates(unittest.TestCase):
    def _assert_structured_form(self, relpath: str):
        text = read(relpath)
        self.assertIn("name:", text)
        self.assertIn("description:", text)
        self.assertIn("body:", text)
        # Structured issue forms use typed fields, never the legacy
        # free-text `.md` template style.
        self.assertRegex(text, r"type:\s*(textarea|input|dropdown|checkboxes)")

    def test_bug_yml_is_structured(self):
        self._assert_structured_form(".github/ISSUE_TEMPLATE/bug.yml")

    def test_feature_yml_is_structured(self):
        self._assert_structured_form(".github/ISSUE_TEMPLATE/feature.yml")

    def test_bug_and_feature_carry_no_paste_warning(self):
        for relpath in (
            ".github/ISSUE_TEMPLATE/bug.yml",
            ".github/ISSUE_TEMPLATE/feature.yml",
        ):
            with self.subTest(relpath=relpath):
                text = read(relpath)
                self.assertRegex(text, NO_PASTE_WARNING_RE)

    def test_config_disables_blank_issues(self):
        text = read(".github/ISSUE_TEMPLATE/config.yml")
        self.assertRegex(text, r"blank_issues_enabled:\s*false")

    def test_config_points_contact_link_at_security(self):
        text = read(".github/ISSUE_TEMPLATE/config.yml").lower()
        self.assertTrue("security" in text)


class TestCodeOfConduct(unittest.TestCase):
    def test_is_contributor_covenant_style_with_no_deployment_specifics(self):
        text = read("CODE_OF_CONDUCT.md")
        self.assertIn("Contributor Covenant", text)
        lowered = text.lower()
        for forbidden in ("192.168", "rhotor", "rhonas", "johnosumi"):
            self.assertNotIn(forbidden, lowered)


class TestChangelogAndThirdPartyNotices(unittest.TestCase):
    def test_changelog_is_keep_a_changelog_style_with_unreleased_section(self):
        text = read("CHANGELOG.md")
        self.assertIn("Keep a Changelog", text)
        self.assertIn("Unreleased", text)
        self.assertIn("pre-deployment", text.lower())

    def test_third_party_notices_is_a_release_time_placeholder(self):
        text = read("THIRD_PARTY_NOTICES.md").lower()
        self.assertIn("no third-party dependencies are bundled yet", text)
        self.assertTrue("task 10" in text or "release" in text)


class TestCheckerPassesOnGoodTree(unittest.TestCase):
    def test_exits_zero_on_the_real_repo(self):
        result = run_checker()
        self.assertEqual(
            result.returncode,
            0,
            f"expected pass on the good tree, got rc={result.returncode}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}",
        )


class TestCheckerFailsClosedOnCorruption(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="governance-check-")
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        self.tmp_root = Path(self._tmp)
        for relpath in GOVERNANCE_FILES:
            src = REPO_ROOT / relpath
            dst = self.tmp_root / relpath
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)

    def test_passes_on_an_untouched_copy(self):
        result = run_checker(self.tmp_root)
        self.assertEqual(
            result.returncode,
            0,
            f"expected pass on untouched copy, got rc={result.returncode}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}",
        )

    def test_fails_when_a_governance_file_is_removed(self):
        (self.tmp_root / ".github" / "CODEOWNERS").unlink()
        result = run_checker(self.tmp_root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CODEOWNERS", result.stdout)

    def test_fails_when_codeowners_is_corrupted(self):
        (self.tmp_root / ".github" / "CODEOWNERS").write_text(
            "* @someone-else\n", encoding="utf-8"
        )
        result = run_checker(self.tmp_root)
        self.assertNotEqual(result.returncode, 0)

    def test_fails_when_security_md_offers_an_email_channel(self):
        text = read("SECURITY.md")
        text += "\nOr just email us at security@example.com.\n"
        (self.tmp_root / "SECURITY.md").write_text(text, encoding="utf-8")
        result = run_checker(self.tmp_root)
        self.assertNotEqual(result.returncode, 0)

    def test_fails_when_license_is_corrupted(self):
        (self.tmp_root / "LICENSE").write_text("not a license", encoding="utf-8")
        result = run_checker(self.tmp_root)
        self.assertNotEqual(result.returncode, 0)

    def test_fails_when_issue_form_loses_its_no_paste_warning(self):
        bug_path = self.tmp_root / ".github" / "ISSUE_TEMPLATE" / "bug.yml"
        text = read(".github/ISSUE_TEMPLATE/bug.yml")
        # Strip the markdown warning block's body line heuristically: remove
        # any line containing "paste" to simulate a de-fanged warning.
        stripped = "\n".join(
            ln for ln in text.splitlines() if "paste" not in ln.lower()
        )
        bug_path.write_text(stripped, encoding="utf-8")
        result = run_checker(self.tmp_root)
        self.assertNotEqual(result.returncode, 0)

    def test_diagnostics_use_path_colon_message_format(self):
        (self.tmp_root / ".github" / "CODEOWNERS").unlink()
        result = run_checker(self.tmp_root)
        self.assertRegex(result.stdout, r"^\S.*: .+$", "expected 'path: message' diagnostics on stdout")


if __name__ == "__main__":
    unittest.main()
