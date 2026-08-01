"""Closed contract for the runner base and Debian snapshot provenance tuple."""

from __future__ import annotations

import copy
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "scripts/ci/check_runner_debian_snapshot.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_runner_debian_snapshot",
        CHECKER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("checker unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RunnerDebianSnapshotContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = _load_checker()
        cls.lock_path = (
            REPO_ROOT / "images/runner/debian-snapshot.lock.json"
        )
        cls.lock = cls.checker.load_lock(cls.lock_path)

    def test_repository_tuple_is_closed_and_coherent(self) -> None:
        self.checker.validate_repository(REPO_ROOT)

    def test_lock_rejects_unknown_missing_reordered_or_mixed_sources(self) -> None:
        mutations = []

        unknown = copy.deepcopy(self.lock)
        unknown["unknown"] = True
        mutations.append(unknown)

        missing = copy.deepcopy(self.lock)
        del missing["base"]["source_epoch"]
        mutations.append(missing)

        reordered = copy.deepcopy(self.lock)
        reordered["sources"][0], reordered["sources"][1] = (
            reordered["sources"][1],
            reordered["sources"][0],
        )
        mutations.append(reordered)

        omitted = copy.deepcopy(self.lock)
        omitted["sources"].pop()
        mutations.append(omitted)

        component = copy.deepcopy(self.lock)
        component["sources"][0]["component"] = "main contrib"
        mutations.append(component)

        timestamp = copy.deepcopy(self.lock)
        timestamp["snapshot"] = "20250101T000000Z"
        mutations.append(timestamp)

        epoch = copy.deepcopy(self.lock)
        epoch["base"]["source_epoch"] += 1
        mutations.append(epoch)

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(self.checker.ContractError):
                    self.checker.validate_lock(mutation)

    def test_package_versions_have_one_source_and_equal_dependency_edge(self) -> None:
        duplicate = copy.deepcopy(self.lock)
        duplicate["direct_packages"][1]["name"] = duplicate[
            "direct_packages"
        ][0]["name"]

        overlap = copy.deepcopy(self.lock)
        overlap["additional_anchors"][0]["name"] = overlap[
            "direct_packages"
        ][0]["name"]

        perl_only = copy.deepcopy(self.lock)
        perl_only["additional_anchors"][0]["version"] = (
            "5.36.0-7+deb12u2"
        )

        perl_base_only = copy.deepcopy(self.lock)
        perl_base_only["additional_anchors"][1]["version"] = (
            "5.36.0-7+deb12u2"
        )

        second_direct_surface = copy.deepcopy(self.lock)
        second_direct_surface["direct_package_anchors"] = []

        for mutation in (
            duplicate,
            overlap,
            perl_only,
            perl_base_only,
            second_direct_surface,
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(self.checker.ContractError):
                    self.checker.validate_lock(mutation)

    def test_each_consumer_mutation_fails_the_shared_validator(self) -> None:
        cases = {
            "stale-base": (
                "debian:bookworm-slim@sha256:"
                "1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4",
                "debian:bookworm-slim@sha256:"
                "0def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4",
            ),
            "known-bad-snapshot": (
                "20260623T000000Z",
                "20250101T000000Z",
            ),
            "stale-package": (
                "git=1:2.39.5-0+deb12u3",
                "git=1:2.39.5-0+deb12u2",
            ),
            "stale-lock-digest": (
                "expected_debian_snapshot_lock_sha=",
                "expected_debian_snapshot_lock_sha=0",
            ),
        }

        for name, (old, new) in cases.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    for relative in (
                        "images/runner/Dockerfile",
                        "images/runner/.dockerignore",
                        "images/runner/README.md",
                        "images/runner/debian-snapshot.lock.json",
                        "images/runner/verify-debian-snapshot.sh",
                        "scripts/ci/check_runner_debian_snapshot.py",
                        "scripts/release/rehearse-runtime.sh",
                        "scripts/test-controller-runtime.sh",
                    ):
                        source = REPO_ROOT / relative
                        destination = root / relative
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(source, destination)
                    dockerfile = root / "images/runner/Dockerfile"
                    text = dockerfile.read_text(encoding="utf-8")
                    self.assertIn(old, text)
                    dockerfile.write_text(
                        text.replace(old, new, 1),
                        encoding="utf-8",
                    )
                    with self.assertRaises(self.checker.ContractError):
                        self.checker.validate_repository(root)

    def test_authoritative_gate_and_rehearsal_invoke_the_same_checker(self) -> None:
        gate = (
            REPO_ROOT / "scripts/test-controller-runtime.sh"
        ).read_text(encoding="utf-8")
        rehearsal = (
            REPO_ROOT / "scripts/release/rehearse-runtime.sh"
        ).read_text(encoding="utf-8")
        invocation = "scripts/ci/check_runner_debian_snapshot.py"
        self.assertIn(invocation, gate)
        self.assertIn(invocation, rehearsal)
        start = rehearsal.index("def validate_dockerfiles(")
        end = rehearsal.index("\ndef inspect_buildkit(", start)
        self.assertNotIn("20250101T000000Z", rehearsal[start:end])


if __name__ == "__main__":
    unittest.main()
