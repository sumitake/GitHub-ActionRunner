"""Closed source contracts for hosted-CI portability repairs."""

from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

GITLEAKS_FINGERPRINT = (
    "cf2fef5c4c8a156f6303311b040428620a2bbc95:"
    "internal/hostruntime/operation_receipt_test.go:generic-api-key:13"
)


class HostedCIPortabilityContractTest(unittest.TestCase):
    def test_gitleaks_exception_is_one_exact_historical_fingerprint(self) -> None:
        ignore = REPO_ROOT / ".gitleaksignore"
        self.assertTrue(ignore.is_file())
        self.assertEqual(
            ignore.read_text(encoding="utf-8").splitlines(),
            [GITLEAKS_FINGERPRINT],
        )
        self.assertEqual(
            (REPO_ROOT / ".gitleaks.toml").read_text(encoding="utf-8"),
            'title = "Portable GHAR public-source secret policy"\n'
            "\n"
            "[extend]\n"
            "useDefault = true\n",
        )

    def test_workflow_uses_version_stable_shell_and_gofmt_forms(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('&& test -z "$unformatted" ||', workflow)
        self.assertIn('git ls-files -z -- "*.sh"', workflow)
        self.assertIn("shellcheck --severity=warning", workflow)

    def test_local_source_gate_matches_shellcheck_severity_contract(self) -> None:
        gate = (REPO_ROOT / "scripts/test-controller-runtime.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(
            'shellcheck "$script_directory/test-controller-runtime.sh"',
            gate,
        )
        self.assertIn('shellcheck --severity=warning "${files[@]}"', gate)


if __name__ == "__main__":
    unittest.main()
