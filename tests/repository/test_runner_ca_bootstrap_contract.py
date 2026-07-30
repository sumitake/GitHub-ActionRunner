"""Closed contract for the runner image's HTTPS snapshot trust bootstrap."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RunnerCABootstrapContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock_path = REPO_ROOT / "images/trust/ca-bundle.lock.json"
        cls.lock = json.loads(cls.lock_path.read_text(encoding="utf-8"))
        cls.task5 = (
            REPO_ROOT / "scripts/prepare-task5-images.sh"
        ).read_text(encoding="utf-8")
        cls.dockerfile = (
            REPO_ROOT / "images/runner/Dockerfile"
        ).read_text(encoding="utf-8")
        cls.dockerignore = (
            REPO_ROOT / "images/runner/.dockerignore"
        ).read_text(encoding="utf-8").splitlines()
        cls.workflow = (
            REPO_ROOT / ".github/workflows/ci.yml"
        ).read_text(encoding="utf-8")
        cls.rehearsal = (
            REPO_ROOT / "scripts/release/rehearse-runtime.sh"
        ).read_text(encoding="utf-8")

    def test_task5_requires_and_revalidates_the_locked_task6_bundle(self) -> None:
        required_fragments = (
            "--ca-bundle)",
            'ca_lock="$repository/images/trust/ca-bundle.lock.json"',
            "file_sha256()",
            '.schema_version == 1',
            '.context_path == "images/trust/build/ca-bundle.pem"',
            '.copied_path == "/etc/ssl/certs/ca-bundle.crt"',
            'expected_ca_path="$repository/$ca_context_path"',
            '[ "$ca_bundle" = "$expected_ca_path" ]',
            '[ "$(file_sha256 "$ca_bundle")" = "$expected_ca_sha" ]',
            'cp -p "$ca_bundle" "$runner_stage/ca-bundle.pem"',
            'canonical_existing_file "$runner_stage/ca-bundle.pem"',
            '[ "$(file_sha256 "$runner_stage/ca-bundle.pem")" = '
            '"$expected_ca_sha" ]',
            'cp -p "$ca_lock" "$runner_stage/ca-bundle.lock.json"',
            "printf '%s  %s\\n' \"$expected_ca_sha\" ca-bundle.pem",
            '>"$runner_stage/ca-bundle.sha256"',
            'canonical_existing_file "$runner_stage/$name"',
            'canonical_existing_file "$runner_build/$name"',
            '[ "$(file_sha256 "$runner_build/ca-bundle.pem")" = '
            '"$expected_ca_sha" ]',
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.task5)
        self.assertRegex(
            self.task5,
            r'\[ "\$seen_ca_bundle" = 1 \] \|\| die',
        )
        self.assertNotIn(
            'cp -p "$ca_bundle" "$runner_build/ca-bundle.pem"',
            self.task5,
        )

    def test_runner_context_admits_only_the_three_locked_trust_files(self) -> None:
        expected = {
            "!build/ca-bundle.pem",
            "!build/ca-bundle.lock.json",
            "!build/ca-bundle.sha256",
        }
        self.assertTrue(expected.issubset(set(self.dockerignore)))
        self.assertEqual(
            {
                line
                for line in self.dockerignore
                if line.startswith("!build/ca-bundle")
            },
            expected,
        )

    def test_context_audit_binds_bundle_lock_and_generated_checksum(self) -> None:
        bundle_match = re.search(
            r"expected_ca_sha=([0-9a-f]{64})",
            self.dockerfile,
        )
        lock_match = re.search(
            r"expected_ca_lock_sha=([0-9a-f]{64})",
            self.dockerfile,
        )
        self.assertIsNotNone(bundle_match)
        self.assertIsNotNone(lock_match)
        self.assertEqual(bundle_match.group(1), self.lock["sha256"])
        self.assertEqual(lock_match.group(1), _sha256(self.lock_path))

        required_fragments = (
            "build/ca-bundle.pem|build/ca-bundle.lock.json|"
            "build/ca-bundle.sha256",
            'sha256sum /context/build/ca-bundle.lock.json',
            'sha256sum /context/build/ca-bundle.pem',
            'printf \'%s  %s\\n\' "$expected_ca_sha" ca-bundle.pem',
            "cmp - ca-bundle.sha256",
            "sha256sum -c ca-bundle.sha256",
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.dockerfile)

    def test_final_stage_bootstraps_apt_only_from_the_completed_audit(self) -> None:
        audited_copy = (
            "COPY --from=context-audit --chown=0:0 --chmod=0444 "
            "/context/build/ca-bundle.pem /portable-ghar-bootstrap-ca.pem"
        )
        self.assertIn(audited_copy, self.dockerfile)
        self.assertLess(
            self.dockerfile.index(audited_copy),
            self.dockerfile.index("apt-get"),
        )
        self.assertNotIn(
            "COPY --chown=0:0 --chmod=0444 build/ca-bundle.pem",
            self.dockerfile,
        )
        for setting in (
            "Acquire::https::CaInfo=/portable-ghar-bootstrap-ca.pem",
            "Acquire::https::Verify-Peer=true",
            "Acquire::https::Verify-Host=true",
        ):
            with self.subTest(setting=setting):
                self.assertEqual(self.dockerfile.count(setting), 2)
        self.assertNotIn("Acquire::https::Verify-Peer=false", self.dockerfile)
        self.assertNotIn("Acquire::https::Verify-Host=false", self.dockerfile)
        self.assertNotIn("http://snapshot.debian.org", self.dockerfile)
        self.assertIn(
            "rm -f /portable-ghar-bootstrap-ca.pem",
            self.dockerfile,
        )
        absence_check = "test ! -e /portable-ghar-bootstrap-ca.pem"
        self.assertIn(absence_check, self.dockerfile)
        self.assertGreater(
            self.dockerfile.index(absence_check),
            self.dockerfile.rindex("COPY "),
        )

    def test_ci_and_rehearsal_prepare_task6_before_task5(self) -> None:
        ci_task6 = self.workflow.index("scripts/prepare-task6-images.sh")
        ci_task5 = self.workflow.index("scripts/prepare-task5-images.sh")
        ci_gate = self.workflow.index("scripts/ci/check-images.sh")
        self.assertLess(ci_task6, ci_task5)
        self.assertLess(ci_task5, ci_gate)
        self.assertIn('repository="$(pwd -P)"', self.workflow)
        self.assertIn(
            '--ca-bundle "$repository/images/trust/build/ca-bundle.pem"',
            self.workflow,
        )

        rehearsal_task6 = self.rehearsal.index(
            '["scripts/prepare-task6-images.sh"]'
        )
        rehearsal_task5 = self.rehearsal.index(
            '"scripts/prepare-task5-images.sh"'
        )
        rehearsal_gate = self.rehearsal.index(
            '"scripts/test-controller-runtime.sh", "--full"'
        )
        self.assertLess(rehearsal_task6, rehearsal_task5)
        self.assertLess(rehearsal_task5, rehearsal_gate)
        self.assertIn(").resolve(strict=True)", self.rehearsal)
        self.assertIn(
            'ca_bundle = clone / "images/trust/build/ca-bundle.pem"',
            self.rehearsal,
        )
        self.assertIn(
            "resolved_ca_bundle = ca_bundle.resolve(strict=True)",
            self.rehearsal,
        )
        self.assertIn(
            'if resolved_ca_bundle != ca_bundle or not ca_bundle.is_file():',
            self.rehearsal,
        )
        self.assertIn(
            '"--ca-bundle",\n'
            "                os.fspath(resolved_ca_bundle),",
            self.rehearsal,
        )

    def test_task5_readmes_show_the_required_order_and_canonical_path(self) -> None:
        for relative in (
            "images/runner/README.md",
            "images/network-adapter/README.md",
        ):
            with self.subTest(relative=relative):
                text = (REPO_ROOT / relative).read_text(encoding="utf-8")
                task6 = text.index("scripts/prepare-task6-images.sh")
                task5 = text.index("scripts/prepare-task5-images.sh")
                self.assertLess(task6, task5)
                self.assertIn('repository="$(pwd -P)"', text)
                self.assertIn(
                    '--ca-bundle "$repository/images/trust/build/ca-bundle.pem"',
                    text,
                )


if __name__ == "__main__":
    unittest.main()
