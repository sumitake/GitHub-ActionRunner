"""Closed source contracts for hosted-CI portability repairs."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

GITLEAKS_FINGERPRINTS = (
    (
        "cf2fef5c4c8a156f6303311b040428620a2bbc95:"
        "internal/hostruntime/operation_receipt_test.go:generic-api-key:13"
    ),
    (
        "8075e44d05b02bcdd117e60f057d624b37a0dcab:"
        "internal/hostruntime/operation_receipt_test.go:generic-api-key:13"
    ),
    (
        "cafa5cbaf5123c8e46028b535997f32e45db972e:"
        "tests/config/schema-validation.test.mjs:github-pat:89"
    ),
    (
        "cafa5cbaf5123c8e46028b535997f32e45db972e:"
        "tests/sanitization/test_sanitize_public.py:generic-api-key:361"
    ),
    (
        "cafa5cbaf5123c8e46028b535997f32e45db972e:"
        "tests/sanitization/test_sanitize_public.py:generic-api-key:580"
    ),
    (
        "cafa5cbaf5123c8e46028b535997f32e45db972e:"
        "tests/sanitization/test_sanitize_public.py:generic-api-key:788"
    ),
    (
        "e2d3059198a160ecfb0a65b06cf607678692e625:"
        "internal/state/sqlite_test.go:generic-api-key:1042"
    ),
    (
        "e2d3059198a160ecfb0a65b06cf607678692e625:"
        "internal/state/sqlite_test.go:generic-api-key:1070"
    ),
)


class HostedCIPortabilityContractTest(unittest.TestCase):
    def test_authority_chown_uses_native_int_parse_without_narrowing(self) -> None:
        source = (
            REPO_ROOT / "internal/networkjail/authority_manager_unix.go"
        ).read_text(encoding="utf-8")
        self.assertIn("strconv.Atoi(parts[0])", source)
        self.assertIn("strconv.Atoi(parts[1])", source)
        self.assertIn(
            "os.Chown(socketPath, user.nativeUID, user.nativeGID)",
            source,
        )
        self.assertNotIn("int(uid)", source)
        self.assertNotIn("int(gid)", source)
        self.assertNotIn("math.MaxInt", source)

    def test_legacy_layout_matches_docker_full_line_sort(self) -> None:
        path = REPO_ROOT / "scripts/_prepare_task6_context.py"
        spec = importlib.util.spec_from_file_location(
            "_prepare_task6_context",
            path,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        entries = [
            {
                "path": "z-file",
                "type": "file",
                "mode": "644",
                "sha256": "0" * 64,
            },
            {
                "path": "a-link",
                "type": "symlink",
                "mode": "777",
                "target": "target",
            },
            {"path": "m-dir", "type": "directory", "mode": "755"},
        ]
        self.assertEqual(
            module.canonical_layout(entries),
            (
                b"d 755 m-dir \n"
                b"f 644 z-file \n"
                b"l 777 a-link target\n"
            ),
        )

    def test_gitleaks_exceptions_are_exact_historical_fingerprints(self) -> None:
        ignore = REPO_ROOT / ".gitleaksignore"
        self.assertTrue(ignore.is_file())
        self.assertEqual(
            ignore.read_text(encoding="utf-8").splitlines(),
            list(GITLEAKS_FINGERPRINTS),
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
