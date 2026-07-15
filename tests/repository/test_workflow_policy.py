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
EXPECTED_ALL_CONTEXTS = EXPECTED_STABLE_CONTEXTS | {"codeql", "release"}

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
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
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
            "        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0\n"
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
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
            "actions/checkout@v7.0.0",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("40-character", result.stdout + result.stderr)

    def test_rejects_branch_ref(self) -> None:
        text = VALID_WORKFLOW.replace(
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
            "actions/checkout@main",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("40-character", result.stdout + result.stderr)

    def test_rejects_39_char_sha(self) -> None:
        short_sha = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e"  # 39 hex chars
        self.assertEqual(len(short_sha), 39)
        text = VALID_WORKFLOW.replace(
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
            f"actions/checkout@{short_sha} # v7.0.0",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("40-character", result.stdout + result.stderr)

    def test_rejects_41_char_ref(self) -> None:
        long_sha = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e00"  # 41 hex chars
        self.assertEqual(len(long_sha), 41)
        text = VALID_WORKFLOW.replace(
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
            f"actions/checkout@{long_sha} # v7.0.0",
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
            "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v7.0.0",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match", result.stdout + result.stderr)

    def test_rejects_missing_release_comment(self) -> None:
        text = VALID_WORKFLOW.replace(
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        )
        with tempfile.TemporaryDirectory() as tmp:
            workflows_dir = write_workflow(Path(tmp), text)
            result = run_checker(workflows_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release comment", result.stdout + result.stderr)

    def test_rejects_mismatched_release_comment(self) -> None:
        text = VALID_WORKFLOW.replace(
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v6.0.0",
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
