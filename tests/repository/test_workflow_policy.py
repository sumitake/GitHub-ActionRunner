"""TDD suite for the Task 8 workflow policy checker:
scripts/check_workflow_policy.py -- a fail-closed parser/policy engine that
validates every GitHub Actions workflow under a directory against the
project's supply-chain and least-privilege posture: reviewed action SHA
pins with a matching release comment, safe triggers, hosted non-expression
runners, least-privilege permissions, required timeout/concurrency,
`persist-credentials: false` on checkout, and unique stable job/context
names across the workflow set. YAML constructs the checker cannot prove
safe (anchors, aliases, tags, block scalars, flow collections other than
`{}`/`[]`) must fail closed rather than be silently accepted.

Run: python3 -m unittest tests.repository.test_workflow_policy -v
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_workflow_policy.py"
REAL_WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

EXPECTED_STABLE_CONTEXTS = {
    "go",
    "worker",
    "shell",
    "repository-metadata",
    "container",
    "sanitization",
    "dependency-review",
}

# The full set of job/context ids the real workflow set defines, including
# the CodeQL scan job (results go to the Security tab -- it is intentionally
# NOT one of the seven required PR status-check contexts above, but it is
# still a unique job id that must not collide with any of them).
EXPECTED_RUNTIME_RELEASE_CONTEXTS = {
    "release-admission",
    "release-build-a",
    "release-build-b",
    "release-compare-attest",
    "release",
    "runner-candidate-admission",
    "runner-candidate-build-a",
    "runner-candidate-build-b",
    "runner-candidate-compare-attest",
    "runner-candidate-publish",
}
CREATE_APP_TOKEN_ACTION = (
    "actions/create-github-app-token@"
    "bcd2ba49218906704ab6c1aa796996da409d3eb1"
)
# Scheduled vulnerability-watch jobs: not PR status checks and not release
# jobs; they run on a weekly schedule (plus manual dispatch) and alert by
# failing when the release-gate policy would newly fire.
EXPECTED_SCHEDULED_WATCH_CONTEXTS = {
    "source-full-policy",
    "base-image-fixable",
    "release-bats-diagnostic",
}
EXPECTED_ALL_CONTEXTS = (
    EXPECTED_STABLE_CONTEXTS
    | {"codeql"}
    | EXPECTED_RUNTIME_RELEASE_CONTEXTS
    | EXPECTED_SCHEDULED_WATCH_CONTEXTS
)

# A minimal workflow that should pass every check cleanly. Each negative
# test below takes this exact text and mutates ONE line to introduce ONE
# violation, so a failing assertion always isolates a single rejection
# class.
VALID_WORKFLOW = """\
name: Fixture
on:
  push:
  pull_request:
  workflow_dispatch:
permissions: {}
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      contents: read
    concurrency:
      group: fixture-build-${{ github.workflow }}-${{ github.ref }}
      cancel-in-progress: true
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Local action
        uses: ./local-action
      - name: Run something
        run: echo hello
"""


def run_checker(dirpath: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CHECKER), str(dirpath)],
        capture_output=True,
        text=True,
    )


def write_workflow(tmp_path: Path, text: str, name: str = "fixture.yml") -> Path:
    workflows_dir = tmp_path / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    (workflows_dir / name).write_text(text, encoding="utf-8")
    return workflows_dir


class CheckerExistsTest(unittest.TestCase):
    def test_checker_script_exists(self) -> None:
        self.assertTrue(CHECKER.is_file(), "missing scripts/check_workflow_policy.py")


class ValidWorkflowPassesTest(unittest.TestCase):
    def test_valid_fixture_passes_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), VALID_WORKFLOW)
            result = run_checker(workflows_dir)
            self.assertEqual(
                result.returncode, 0, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )

    def test_local_action_only_passes(self) -> None:
        text = VALID_WORKFLOW.replace(
            "      - name: Checkout\n"
            "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
            "        with:\n"
            "          persist-credentials: false\n",
            "",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout!r}")


class RejectActionRefTest(unittest.TestCase):
    def test_rejects_tag_ref(self) -> None:
        text = VALID_WORKFLOW.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            "actions/checkout@v7.0.1",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("40-character", result.stdout + result.stderr)

    def test_rejects_branch_ref(self) -> None:
        text = VALID_WORKFLOW.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            "actions/checkout@main",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("40-character", result.stdout + result.stderr)

    def test_rejects_39_char_sha(self) -> None:
        short_sha = "3d3c42e5aac5ba805825da76410c181273ba90b"  # 39 hex chars
        self.assertEqual(len(short_sha), 39)
        text = VALID_WORKFLOW.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            f"actions/checkout@{short_sha} # v7.0.1",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("40-character", result.stdout + result.stderr)

    def test_rejects_41_char_ref(self) -> None:
        long_sha = "3d3c42e5aac5ba805825da76410c181273ba90b10"  # 41 hex chars
        self.assertEqual(len(long_sha), 41)
        text = VALID_WORKFLOW.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            f"actions/checkout@{long_sha} # v7.0.1",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("40-character", result.stdout + result.stderr)

    def test_rejects_unknown_action_not_in_pin_table(self) -> None:
        text = VALID_WORKFLOW.replace(
            "      - name: Local action\n        uses: ./local-action\n",
            "      - name: Unreviewed\n"
            "        uses: someorg/unreviewed-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.0.0\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("reviewed pin table", result.stdout + result.stderr)

    def test_rejects_sha_not_matching_reviewed_pin(self) -> None:
        text = VALID_WORKFLOW.replace(
            "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v7.0.1",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match", result.stdout + result.stderr)

    def test_rejects_missing_release_comment(self) -> None:
        text = VALID_WORKFLOW.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release comment", result.stdout + result.stderr)

    def test_rejects_mismatched_release_comment(self) -> None:
        text = VALID_WORKFLOW.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6.0.0",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match", result.stdout + result.stderr)

    def test_rejects_docker_action_without_digest(self) -> None:
        text = VALID_WORKFLOW.replace(
            "      - name: Local action\n        uses: ./local-action\n",
            "      - name: Docker step\n        uses: docker://alpine:3.19\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("digest", result.stdout + result.stderr)


class RejectTriggerTest(unittest.TestCase):
    def test_rejects_pull_request_target(self) -> None:
        text = VALID_WORKFLOW.replace("  pull_request:\n", "  pull_request_target:\n")
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pull_request_target", result.stdout + result.stderr)


class RejectRunnerTest(unittest.TestCase):
    def test_rejects_self_hosted_runner(self) -> None:
        text = VALID_WORKFLOW.replace("runs-on: ubuntu-24.04", "runs-on: self-hosted")
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("self-hosted", result.stdout + result.stderr)

    def test_rejects_expression_runner(self) -> None:
        text = VALID_WORKFLOW.replace(
            "runs-on: ubuntu-24.04", "runs-on: ${{ matrix.os }}"
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expression", result.stdout + result.stderr)


class RejectPermissionsTest(unittest.TestCase):
    def test_rejects_missing_top_level_permissions(self) -> None:
        text = VALID_WORKFLOW.replace("permissions: {}\n", "")
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("permissions", result.stdout + result.stderr)

    def test_rejects_write_all_top_level_permissions(self) -> None:
        text = VALID_WORKFLOW.replace("permissions: {}\n", "permissions: write-all\n")
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("write-all", result.stdout + result.stderr)

    def test_rejects_write_all_job_permissions(self) -> None:
        # write-all is a blanket write-default grant and must always be
        # rejected, at either workflow or job scope.
        text = VALID_WORKFLOW.replace(
            "    permissions:\n      contents: read\n",
            "    permissions: write-all\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("write-all", result.stdout + result.stderr)

    def test_allows_scoped_write_job_permissions(self) -> None:
        # A job MAY grant itself a single scoped write permission (e.g. a
        # future release job needing contents: write) -- this is
        # least-privilege, not a write-default. Only a blanket/workflow-
        # level write is rejected.
        text = VALID_WORKFLOW.replace(
            "    permissions:\n      contents: read\n",
            "    permissions:\n      contents: write\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout!r}")


class RejectMissingTimeoutOrConcurrencyTest(unittest.TestCase):
    def test_rejects_missing_timeout(self) -> None:
        text = VALID_WORKFLOW.replace("    timeout-minutes: 10\n", "")
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("timeout-minutes", result.stdout + result.stderr)

    def test_rejects_missing_concurrency(self) -> None:
        text = VALID_WORKFLOW.replace(
            "    concurrency:\n"
            "      group: fixture-build-${{ github.workflow }}-${{ github.ref }}\n"
            "      cancel-in-progress: true\n",
            "",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("concurrency", result.stdout + result.stderr)

    def test_rejects_cancel_in_progress_false(self) -> None:
        text = VALID_WORKFLOW.replace(
            "cancel-in-progress: true", "cancel-in-progress: false"
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cancel-in-progress", result.stdout + result.stderr)


class RejectPersistCredentialsTest(unittest.TestCase):
    def test_rejects_missing_persist_credentials(self) -> None:
        text = VALID_WORKFLOW.replace("        with:\n          persist-credentials: false\n", "")
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("persist-credentials", result.stdout + result.stderr)

    def test_rejects_persist_credentials_true(self) -> None:
        text = VALID_WORKFLOW.replace(
            "persist-credentials: false", "persist-credentials: true"
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("persist-credentials", result.stdout + result.stderr)


class RejectUnsafeYamlTest(unittest.TestCase):
    def test_rejects_yaml_anchor(self) -> None:
        text = VALID_WORKFLOW.replace("name: Fixture\n", "name: &fixture-name Fixture\n")
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot safely parse", result.stdout + result.stderr)

    def test_rejects_yaml_alias(self) -> None:
        text = VALID_WORKFLOW.replace(
            "      - name: Run something\n        run: echo hello\n",
            "      - name: Run something\n        run: *some-alias\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot safely parse", result.stdout + result.stderr)

    def test_rejects_multiline_block_scalar(self) -> None:
        text = VALID_WORKFLOW.replace(
            "      - name: Run something\n        run: echo hello\n",
            "      - name: Run something\n        run: |\n          echo hello\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot safely parse", result.stdout + result.stderr)

    def test_rejects_flow_mapping_with_content(self) -> None:
        text = VALID_WORKFLOW.replace(
            "permissions:\n      contents: read\n",
            "permissions: { contents: read }\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot safely parse", result.stdout + result.stderr)


class RejectDuplicateContextTest(unittest.TestCase):
    def test_rejects_duplicate_job_context_across_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), VALID_WORKFLOW, name="a.yml")
            (workflows_dir / "b.yml").write_text(
                VALID_WORKFLOW.replace("name: Fixture", "name: Fixture Two"),
                encoding="utf-8",
            )
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate", (result.stdout + result.stderr).lower())
            self.assertIn("build", result.stdout + result.stderr)

    def test_distinct_job_names_across_files_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), VALID_WORKFLOW, name="a.yml")
            (workflows_dir / "b.yml").write_text(
                VALID_WORKFLOW.replace("name: Fixture", "name: Fixture Two").replace(
                    "  build:\n", "  build-two:\n"
                ),
                encoding="utf-8",
            )
            result = run_checker(workflows_dir)
            self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout!r}")


class MissingWorkflowsDirTest(unittest.TestCase):
    def test_missing_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist"
            result = run_checker(missing)
            self.assertNotEqual(result.returncode, 0)


class RealCiWorkflowTest(unittest.TestCase):
    @staticmethod
    def _load_real_workflow(name: str) -> dict:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import check_workflow_policy as cwp  # noqa: PLC0415

        path = REAL_WORKFLOWS_DIR / name
        if not path.is_file():
            raise AssertionError(f"missing {path}")
        return cwp.parse_workflow(path.read_text(encoding="utf-8"))

    @staticmethod
    def _run_text(job: dict) -> str:
        return "\n".join(
            str(step.get("run", "")) for step in job.get("steps", []) if isinstance(step, dict)
        )

    def test_real_ci_workflow_passes(self) -> None:
        self.assertTrue(REAL_WORKFLOWS_DIR.is_dir(), "missing .github/workflows")
        result = run_checker(REAL_WORKFLOWS_DIR)
        self.assertEqual(
            result.returncode, 0, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        self.assertIn("passed", result.stdout)

    def test_real_workflows_have_exactly_seven_stable_contexts_once_each(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import check_workflow_policy as cwp  # noqa: PLC0415

        context_sources: dict[str, list[str]] = {}
        for path in sorted(REAL_WORKFLOWS_DIR.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            root = cwp.parse_workflow(text)
            jobs = root.get("jobs", {})
            for job_id in jobs:
                context_sources.setdefault(job_id, []).append(path.name)

        # All seven stable/required contexts exist, and each exists exactly
        # once across the whole workflow set (no accidental duplication of a
        # job id across two files).
        for ctx in EXPECTED_STABLE_CONTEXTS:
            with self.subTest(context=ctx):
                self.assertIn(ctx, context_sources, f"missing stable context {ctx!r}")
                self.assertEqual(
                    len(context_sources[ctx]),
                    1,
                    f"stable context {ctx!r} defined more than once: {context_sources[ctx]}",
                )

        # The full job-id set across every workflow file is exactly the
        # seven stable contexts plus the CodeQL scan job -- nothing missing,
        # nothing stray.
        self.assertEqual(set(context_sources.keys()), EXPECTED_ALL_CONTEXTS)

    def test_candidate_release_workflow_has_closed_triggers_and_split_authority(self) -> None:
        root = self._load_real_workflow("runner-release-candidate.yml")
        triggers = root.get("on", {})
        self.assertEqual(set(triggers), {"workflow_dispatch", "repository_dispatch"})
        self.assertEqual(
            list(triggers["repository_dispatch"]["types"]),
            ["observe-runner-release"],
        )
        self.assertIn(triggers["workflow_dispatch"], ({}, None))
        self.assertEqual(
            set(root["jobs"]),
            {
                "runner-candidate-admission",
                "runner-candidate-build-a",
                "runner-candidate-build-b",
                "runner-candidate-compare-attest",
                "runner-candidate-publish",
            },
        )
        self.assertEqual(root["concurrency"]["cancel-in-progress"], "false")

        admission = root["jobs"]["runner-candidate-admission"]
        self.assertEqual(admission["steps"][0]["name"], "Validate trusted dispatch")
        self.assertNotIn("uses", admission["steps"][0])
        admission_text = self._run_text(admission)
        for required in (
            "PORTABLE_GHAR_RUNNER_OBSERVER_ACTOR",
            "GITHUB_ACTOR",
            "PORTABLE_GHAR_DEFAULT_BRANCH",
            "GITHUB_EVENT_PATH",
            "object_pairs_hook",
            "observe-runner-release.sh",
        ):
            self.assertIn(required, admission_text)
        self.assertNotIn("CLIENT_PAYLOAD", admission_text)

        admission_step = admission["steps"][0]
        with tempfile.TemporaryDirectory() as tmp:
            event_path = Path(tmp) / "event.json"
            base_environment = {
                "GITHUB_ACTOR": "trusted-observer",
                "GITHUB_REF": "refs/heads/main",
                "PORTABLE_GHAR_DEFAULT_BRANCH": "main",
                "PORTABLE_GHAR_RUNNER_OBSERVER_ACTOR": "trusted-observer",
            }
            valid_cases = (
                (
                    "repository_dispatch",
                    b'{"action":"observe-runner-release","client_payload":{}}\n',
                ),
                ("workflow_dispatch", b'{"inputs":{}}\n'),
            )
            for event_name, raw in valid_cases:
                with self.subTest(event_name=event_name, validity="valid"):
                    event_path.write_bytes(raw)
                    result = subprocess.run(
                        ["bash", "-c", admission_step["run"]],
                        capture_output=True,
                        env={
                            **base_environment,
                            "GITHUB_EVENT_NAME": event_name,
                            "GITHUB_EVENT_PATH": str(event_path),
                        },
                    )
                    self.assertEqual(
                        result.returncode,
                        0,
                        msg=f"stdout={result.stdout!r} stderr={result.stderr!r}",
                    )
            invalid_cases = (
                (
                    "repository_dispatch",
                    b'{"action":"observe-runner-release","client_payload":{"x":1}}\n',
                ),
                (
                    "repository_dispatch",
                    b'{"action":"other","client_payload":{}}\n',
                ),
                (
                    "repository_dispatch",
                    b'{"action":"observe-runner-release",'
                    b'"client_payload":{},"client_payload":{}}\n',
                ),
                ("workflow_dispatch", b'{"inputs":{"unexpected":"value"}}\n'),
                ("workflow_dispatch", b'{"client_payload":{}}\n'),
            )
            for event_name, raw in invalid_cases:
                with self.subTest(event_name=event_name, validity="invalid"):
                    event_path.write_bytes(raw)
                    result = subprocess.run(
                        ["bash", "-c", admission_step["run"]],
                        capture_output=True,
                        env={
                            **base_environment,
                            "GITHUB_EVENT_NAME": event_name,
                            "GITHUB_EVENT_PATH": str(event_path),
                        },
                    )
                    self.assertNotEqual(result.returncode, 0)

        compare = root["jobs"]["runner-candidate-compare-attest"]
        compare_text = self._run_text(compare)
        self.assertIn(r"\(.sha256)  \(.path)", compare_text)
        self.assertNotIn(r"a/\(.path)", compare_text)
        self.assertIn("provenance-subjects.json", compare_text)
        attest_steps = [
            step
            for step in compare["steps"]
            if str(step.get("uses", "")).startswith("actions/attest@")
        ]
        self.assertEqual(len(attest_steps), 1)
        self.assertIn("subject-checksums", attest_steps[0]["with"])
        self.assertEqual(
            compare["permissions"],
            {
                "actions": "read",
                "artifact-metadata": "write",
                "attestations": "write",
                "contents": "read",
                "id-token": "write",
            },
        )

        publish = root["jobs"]["runner-candidate-publish"]
        self.assertEqual(
            publish["permissions"],
            {"actions": "read", "contents": "write"},
        )
        publish_runs = [
            str(step.get("run", ""))
            for step in publish["steps"]
            if isinstance(step, dict)
        ]
        self.assertIn("publish-runtime-release.sh", publish_runs[-1])
        self.assertIn("runner-candidate-v", publish_runs[-1])
        self.assertIn("SOURCE_COMMIT", publish_runs[-1])
        self.assertNotIn("gh release create", "\n".join(publish_runs))
        self.assertIn("compare-runtime-rebuilds.sh", "\n".join(publish_runs))
        app_steps = [
            step
            for step in publish["steps"]
            if str(step.get("uses", "")).startswith(
                "actions/create-github-app-token@"
            )
        ]
        self.assertEqual(len(app_steps), 1)
        self.assertEqual(app_steps[0]["uses"], CREATE_APP_TOKEN_ACTION)
        self.assertEqual(
            app_steps[0]["with"],
            {
                "client-id": "${{ vars.PORTABLE_GHAR_RELEASE_APP_CLIENT_ID }}",
                "private-key": "${{ secrets.PORTABLE_GHAR_RELEASE_APP_PRIVATE_KEY }}",
                "permission-administration": "read",
            },
        )
        publish_step = publish["steps"][-1]
        self.assertEqual(
            publish_step["env"],
            {
                "PGHAR_RELEASE_SETTINGS_TOKEN": "${{ steps.release-settings-token.outputs.token }}",
                "PGHAR_RELEASE_TOKEN": "${{ github.token }}",
            },
        )
        self.assertNotIn("GITHUB_TOKEN", publish_step["env"])
        self.assertNotIn("GH_TOKEN", publish_step["env"])

        text = (REAL_WORKFLOWS_DIR / "runner-release-candidate.yml").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "schedule:",
            "pull_request:",
            "pull_request_target:",
            "--clobber",
            "release delete",
            "runner-candidate-latest",
        ):
            self.assertNotIn(forbidden, text)
        for job_id, job in root["jobs"].items():
            if job_id != "runner-candidate-publish":
                self.assertNotIn("gh release create", self._run_text(job))
                self.assertNotIn(
                    "actions/create-github-app-token@",
                    str(job),
                )

    def test_product_release_workflow_uses_two_rebuilds_and_publish_last(self) -> None:
        root = self._load_real_workflow("release.yml")
        self.assertEqual(set(root.get("on", {})), {"push"})
        self.assertEqual(list(root["on"]["push"]["tags"]), ["v*"])
        self.assertEqual(
            set(root["jobs"]),
            {
                "release-admission",
                "release-build-a",
                "release-build-b",
                "release-compare-attest",
                "release",
            },
        )
        self.assertEqual(root["concurrency"]["cancel-in-progress"], "false")

        admission = root["jobs"]["release-admission"]
        self.assertEqual(admission["steps"][0]["name"], "Checkout exact tag")
        self.assertIn("signed tag", self._run_text(admission))
        self.assertIn("tag_object", admission["outputs"])

        for job_id in ("release-build-a", "release-build-b"):
            job = root["jobs"][job_id]
            text = self._run_text(job)
            self.assertIn("--release-kind product", text)
            self.assertIn("rehearse-runtime.sh", text)
            self.assertIn("publication-tree.tar", text)
            self.assertIn("GOCACHE", text)
            self.assertIn("GOMODCACHE", text)
            self.assertNotIn("actions/cache@", str(job))

        compare = root["jobs"]["release-compare-attest"]
        compare_text = self._run_text(compare)
        self.assertIn("compare-runtime-rebuilds.sh", compare_text)
        self.assertIn("sha256sum", compare_text)
        self.assertIn("provenance-subjects.json", compare_text)
        self.assertIn(r"\(.sha256)  \(.path)", compare_text)
        self.assertNotIn(r"a/\(.path)", compare_text)
        attest_steps = [
            step
            for step in compare["steps"]
            if str(step.get("uses", "")).startswith("actions/attest@")
        ]
        self.assertEqual(len(attest_steps), 1)
        self.assertIn("subject-checksums", attest_steps[0]["with"])
        self.assertEqual(
            compare["permissions"],
            {
                "actions": "read",
                "artifact-metadata": "write",
                "attestations": "write",
                "contents": "read",
                "id-token": "write",
            },
        )

        publish = root["jobs"]["release"]
        self.assertEqual(
            publish["permissions"],
            {"actions": "read", "contents": "write"},
        )
        publish_runs = [
            str(step.get("run", ""))
            for step in publish["steps"]
            if isinstance(step, dict)
        ]
        self.assertIn("compare-runtime-rebuilds.sh", "\n".join(publish_runs))
        self.assertIn("publish-runtime-release.sh", publish_runs[-1])
        self.assertIn("TAG_OBJECT", publish_runs[-1])
        self.assertNotIn("gh release create", "\n".join(publish_runs))
        app_steps = [
            step
            for step in publish["steps"]
            if str(step.get("uses", "")).startswith(
                "actions/create-github-app-token@"
            )
        ]
        self.assertEqual(len(app_steps), 1)
        self.assertEqual(app_steps[0]["uses"], CREATE_APP_TOKEN_ACTION)
        self.assertEqual(
            app_steps[0]["with"],
            {
                "client-id": "${{ vars.PORTABLE_GHAR_RELEASE_APP_CLIENT_ID }}",
                "private-key": "${{ secrets.PORTABLE_GHAR_RELEASE_APP_PRIVATE_KEY }}",
                "permission-administration": "read",
            },
        )
        publish_step = publish["steps"][-1]
        self.assertEqual(
            publish_step["env"],
            {
                "PGHAR_RELEASE_SETTINGS_TOKEN": "${{ steps.release-settings-token.outputs.token }}",
                "PGHAR_RELEASE_TOKEN": "${{ github.token }}",
            },
        )
        self.assertNotIn("GITHUB_TOKEN", publish_step["env"])
        self.assertNotIn("GH_TOKEN", publish_step["env"])
        for job_id, job in root["jobs"].items():
            if job_id != "release":
                self.assertNotIn("gh release create", self._run_text(job))
                self.assertNotIn(
                    "actions/create-github-app-token@",
                    str(job),
                )

    def test_runtime_release_jobs_bind_exact_source_commit_and_tree(self) -> None:
        for workflow_name, admission_id, build_ids, compare_id, publish_id in (
            (
                "release.yml",
                "release-admission",
                ("release-build-a", "release-build-b"),
                "release-compare-attest",
                "release",
            ),
            (
                "runner-release-candidate.yml",
                "runner-candidate-admission",
                ("runner-candidate-build-a", "runner-candidate-build-b"),
                "runner-candidate-compare-attest",
                "runner-candidate-publish",
            ),
        ):
            with self.subTest(workflow=workflow_name):
                root = self._load_real_workflow(workflow_name)
                for job_id, job in root["jobs"].items():
                    checkout_steps = [
                        step
                        for step in job["steps"]
                        if str(step.get("uses", "")).startswith("actions/checkout@")
                    ]
                    self.assertEqual(len(checkout_steps), 1, msg=job_id)
                    self.assertIn("ref", checkout_steps[0]["with"], msg=job_id)
                    self.assertIn("git rev-parse HEAD", self._run_text(job), msg=job_id)
                    self.assertIn('git rev-parse "HEAD^{tree}"', self._run_text(job), msg=job_id)

                for build_id in build_ids:
                    self.assertEqual(list(root["jobs"][build_id]["needs"]), [admission_id])
                self.assertEqual(
                    set(root["jobs"][compare_id]["needs"]),
                    {admission_id, *build_ids},
                )
                self.assertEqual(
                    set(root["jobs"][publish_id]["needs"]),
                    {admission_id, compare_id},
                )
                self.assertIn(
                    "compare-runtime-rebuilds.sh",
                    self._run_text(root["jobs"][publish_id]),
                )

    def test_sanitization_workflow_triggers_and_job_shape(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import check_workflow_policy as cwp  # noqa: PLC0415

        path = REAL_WORKFLOWS_DIR / "sanitization.yml"
        self.assertTrue(path.is_file(), "missing .github/workflows/sanitization.yml")
        root = cwp.parse_workflow(path.read_text(encoding="utf-8"))
        triggers = set(root.get("on", {}).keys())
        self.assertEqual(triggers, {"push", "pull_request", "schedule", "workflow_dispatch"})
        jobs = root.get("jobs", {})
        self.assertIn("sanitization", jobs)

    def test_codeql_workflow_matrix_is_exactly_go_and_javascript_typescript(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import check_workflow_policy as cwp  # noqa: PLC0415

        path = REAL_WORKFLOWS_DIR / "codeql.yml"
        self.assertTrue(path.is_file(), "missing .github/workflows/codeql.yml")
        root = cwp.parse_workflow(path.read_text(encoding="utf-8"))
        triggers = set(root.get("on", {}).keys())
        self.assertEqual(triggers, {"push", "pull_request", "schedule", "workflow_dispatch"})
        job = root["jobs"]["codeql"]
        self.assertEqual(job["permissions"].get("security-events"), "write")
        languages = job["strategy"]["matrix"]["language"]
        self.assertEqual(list(languages), ["go", "javascript-typescript"])

    def test_dependency_review_workflow_is_pull_request_only(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import check_workflow_policy as cwp  # noqa: PLC0415

        path = REAL_WORKFLOWS_DIR / "dependency-review.yml"
        self.assertTrue(path.is_file(), "missing .github/workflows/dependency-review.yml")
        root = cwp.parse_workflow(path.read_text(encoding="utf-8"))
        triggers = set(root.get("on", {}).keys())
        self.assertEqual(triggers, {"pull_request"})
        self.assertIn("dependency-review", root.get("jobs", {}))

    def test_dependabot_config_covers_required_ecosystems_and_image_dirs(self) -> None:
        dependabot_path = REPO_ROOT / ".github" / "dependabot.yml"
        self.assertTrue(dependabot_path.is_file(), "missing .github/dependabot.yml")
        text = dependabot_path.read_text(encoding="utf-8")
        self.assertNotIn("renovate", text.lower(), "dependabot.yml must not coexist with Renovate config")
        self.assertIn('package-ecosystem: "github-actions"', text)
        self.assertIn('package-ecosystem: "gomod"', text)
        self.assertIn('package-ecosystem: "npm"', text)
        for image_dir in (
            "runner",
            "network-adapter",
            "network-broker-parser",
            "network-broker-dialer",
            "network-helper",
            "network-verifier",
        ):
            with self.subTest(image_dir=image_dir):
                self.assertIn(f'directory: "/images/{image_dir}"', text)

    def test_no_renovate_config_present(self) -> None:
        self.assertFalse((REPO_ROOT / "renovate.json").exists())
        self.assertFalse((REPO_ROOT / ".github" / "renovate.json").exists())


if __name__ == "__main__":
    unittest.main()
