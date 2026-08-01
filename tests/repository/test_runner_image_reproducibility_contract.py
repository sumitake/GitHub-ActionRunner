"""Reproducibility cleanup contracts for runner-style Debian images."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_DOCKERFILES = (
    "images/runner/Dockerfile",
    "images/synthetic-listener/Dockerfile",
)


def _normalized_shell(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\\\n", " ")).strip()


class RunnerImageReproducibilityContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dockerfiles = {
            relative: _normalized_shell(
                (REPO_ROOT / relative).read_text(encoding="utf-8")
            )
            for relative in RUNNER_DOCKERFILES
        }

    def test_package_layers_remove_known_nondeterministic_state(self) -> None:
        required_cleanup = (
            "rm -rf /var/cache/apt/* /var/lib/apt/lists/* "
            "/var/log/apt/*"
        )
        required_files = (
            "rm -f /var/cache/ldconfig/aux-cache "
            "/var/log/alternatives.log /var/log/dpkg.log"
        )
        for relative, dockerfile in self.dockerfiles.items():
            with self.subTest(relative=relative):
                install = dockerfile.index(
                    "install -y --no-install-recommends"
                )
                cache_cleanup = dockerfile.index(required_cleanup)
                file_cleanup = dockerfile.index(required_files)
                self.assertLess(install, cache_cleanup)
                self.assertLess(cache_cleanup, file_cleanup)

    def test_listener_smoke_reseals_then_installs_exact_runtime_overlay(
        self,
    ) -> None:
        smoke = (
            "installed_version="
            "$(/opt/actions-runner/bin/Runner.Listener --version)"
        )
        cleanup = "rm -rf /opt/actions-runner/_diag"
        absence = "test ! -e /opt/actions-runner/_diag"
        strict_reverify = (
            'test "$(/usr/local/bin/portable-ghar-runner-gate verify-image)" '
            '= "$expected_version"'
        )
        diagnostics_overlay = (
            "ln -s /runner/_diag /opt/actions-runner/_diag"
        )
        work_overlay = "ln -s /runner/_work /opt/actions-runner/_work"
        overlay_verify = (
            "/usr/local/bin/portable-ghar-runner-gate verify-image-overlay"
        )
        for relative, dockerfile in self.dockerfiles.items():
            with self.subTest(relative=relative):
                smoke_index = dockerfile.index(smoke)
                cleanup_index = dockerfile.index(cleanup)
                absence_index = dockerfile.index(absence)
                strict_reverify_index = dockerfile.index(strict_reverify)
                diagnostics_overlay_index = dockerfile.index(
                    diagnostics_overlay
                )
                work_overlay_index = dockerfile.index(work_overlay)
                overlay_verify_index = dockerfile.index(overlay_verify)
                self.assertLess(smoke_index, cleanup_index)
                self.assertLess(cleanup_index, absence_index)
                self.assertLess(absence_index, strict_reverify_index)
                self.assertLess(
                    strict_reverify_index,
                    diagnostics_overlay_index,
                )
                self.assertLess(
                    diagnostics_overlay_index,
                    work_overlay_index,
                )
                self.assertLess(work_overlay_index, overlay_verify_index)
                self.assertNotIn(
                    "rm -rf /opt/actions-runner/_work",
                    dockerfile,
                )


if __name__ == "__main__":
    unittest.main()
