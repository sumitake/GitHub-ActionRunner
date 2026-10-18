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
    def test_runner_audit_does_not_persist_a_second_runner_payload(self):
        text = (REPO_ROOT / "images/runner/Dockerfile").read_text()
        audit, final = text.split(" AS context-audit\n", 1)[1].split("\nFROM ", 1)
        self.assertNotIn("COPY . /context", audit)
        self.assertIn("--mount=type=bind,source=.,target=/context,ro", audit)
        self.assertIn("cp /context/build/ca-bundle.pem /verified-ca-bundle.pem", audit)
        self.assertIn("/verified-ca-bundle.pem /portable-ghar-bootstrap-ca.pem", final)
        runner = "COPY --chown=0:0 build/runner /opt/actions-runner"
        self.assertIn(runner, final)
        self.assertNotIn("COPY ", final.split(runner, 1)[1])
        copies = [line for line in final.split(runner, 1)[0].splitlines() if line.startswith("COPY ")]
        self.assertEqual(len(copies), 1, "small metadata must share the package transaction, avoiding native snapshots")
        self.assertIn("--mount=type=bind,source=build,target=/inputs,ro", final)
        self.assertIn("install -m 0555 /inputs/portable-ghar-runner-gate", final)

    def test_jit_configuration_links_target_only_ephemeral_runner_root(self):
        for relative, dockerfile in self.dockerfiles.items():
            for name in (".runner", ".credentials", ".credentials_rsaparams"):
                with self.subTest(relative=relative, name=name):
                    link = f"ln -s /runner/{name} /opt/actions-runner/{name}"
                    self.assertIn(link, dockerfile)
                    self.assertLess(
                        dockerfile.index(link),
                        dockerfile.index(
                            "/usr/local/bin/portable-ghar-runner-gate verify-image-overlay"
                        ),
                    )

    def test_unused_root_home_is_absent_for_unprivileged_projection_probe(self):
        for relative, dockerfile in self.dockerfiles.items():
            with self.subTest(relative=relative):
                self.assertIn("rm -rf /root", dockerfile)
                self.assertLess(
                    dockerfile.index("verify-image-overlay"),
                    dockerfile.index("rm -rf /root"),
                )
                self.assertIn("ENV HOME=/runner", dockerfile)
                self.assertIn("USER 65532:65532", dockerfile)

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
