"""Contract tests for Portable GHAR's public docs (Phase 1, Tasks 5-7).

Asserts, per file: required level-2 headings appear in the required order,
and the file contains no unqualified claim that a live subsystem (the
controller, failover, notifications, migration, or rollback) is live or
verified. Also asserts the specific truthful statements each doc/README is
required to carry, and that the operations runbooks link back to the
architecture/trust docs.

Run: python3 -m unittest tests.repository.test_docs_contract -v
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Shared helpers (also the `assert_sections` helper referenced by the docs
# tooling design: a thin, dependency-free way to assert a required run of
# level-N ATX headings appears, in order, in a markdown file).
# ---------------------------------------------------------------------------


def extract_headings(text: str, level: int = 2) -> list[str]:
    """Return the text of every ATX heading at exactly `level` (1-6), in
    document order, ignoring anything inside fenced code blocks."""
    out: list[str] = []
    in_fence = False
    marker = ""
    for raw_line in text.split("\n"):
        stripped = raw_line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            fence = stripped[:3]
            if not in_fence:
                in_fence = True
                marker = fence
            elif stripped.startswith(marker):
                in_fence = False
            continue
        if in_fence:
            continue
        m = re.match(r"^(#{1,6})\s+(.+?)\s*$", raw_line)
        if not m:
            continue
        if len(m.group(1)) != level:
            continue
        out.append(m.group(2).strip())
    return out


def assert_sections_in_file(
    test_case: unittest.TestCase, path: Path, headings: list[str], *, level: int = 2
) -> None:
    """Assert every heading in `headings` appears in `path`, as a level-N ATX
    heading, in that exact relative order. Other headings (of any level) may
    interleave; this only enforces relative order of the required set."""
    test_case.assertTrue(path.is_file(), f"{path}: file does not exist")
    text = path.read_text(encoding="utf-8")
    found = extract_headings(text, level=level)
    cursor = 0
    for heading in headings:
        try:
            idx = found.index(heading, cursor)
        except ValueError:
            test_case.fail(
                f"{path}: missing required level-{level} heading {heading!r} "
                f"in order after position {cursor} in found headings: {found}"
            )
        cursor = idx + 1


def assert_sections(
    test_case: unittest.TestCase, relpath: str, headings: list[str], *, level: int = 2
) -> None:
    """Repo-root-relative convenience wrapper around `assert_sections_in_file`."""
    assert_sections_in_file(test_case, REPO_ROOT / relpath, headings, level=level)


# Phrases that would assert a subsystem is live/verified without
# qualification. Phase 1 ships no runtime code, so none of these may appear
# anywhere in the public docs or README.
UNQUALIFIED_LIVE_CLAIM_PHRASES = (
    "controller is live",
    "controller has been verified",
    "controller is production-ready",
    "controller is now live",
    "failover is live",
    "failover has been verified",
    "failover is production-ready",
    "failover is now live",
    "notifications are live",
    "notification is live",
    "notifications have been verified",
    "notifications are verified",
    "migration is live",
    "migration has been verified",
    "migration is complete",
    "rollback is live",
    "rollback has been verified",
    "rollback is verified",
    "is live in production",
    "is verified in production",
    "fully verified and live",
    "is currently live",
    "now live in production",
    "running in production",
)


def assert_no_unqualified_live_claims_in_file(test_case: unittest.TestCase, path: Path) -> None:
    text = path.read_text(encoding="utf-8").lower()
    hits = [p for p in UNQUALIFIED_LIVE_CLAIM_PHRASES if p in text]
    test_case.assertEqual(hits, [], f"{path}: contains unqualified live/verified claim(s): {hits}")


def assert_no_unqualified_live_claims(test_case: unittest.TestCase, relpath: str) -> None:
    assert_no_unqualified_live_claims_in_file(test_case, REPO_ROOT / relpath)


def _normalized(relpath: str) -> str:
    """Lowercased text with hyphens/underscores folded to spaces, so prose
    keyword checks are not brittle to punctuation choices."""
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    return re.sub(r"[-_]", " ", text.lower())


# ---------------------------------------------------------------------------
# Self-tests: prove the helpers above actually detect violations, so the
# assertions used against the real docs below are not silently vacuous.
# ---------------------------------------------------------------------------


class DocsHelperSelfTest(unittest.TestCase):
    def test_assert_sections_fails_on_missing_heading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.md"
            fixture.write_text("## Alpha\n\ntext\n", encoding="utf-8")
            with self.assertRaises(AssertionError):
                assert_sections_in_file(self, fixture, ["Alpha", "Beta"])

    def test_assert_sections_fails_on_out_of_order_heading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.md"
            fixture.write_text("## Beta\n\ntext\n\n## Alpha\n\ntext\n", encoding="utf-8")
            with self.assertRaises(AssertionError):
                assert_sections_in_file(self, fixture, ["Alpha", "Beta"])

    def test_assert_sections_ignores_headings_inside_fences(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.md"
            fixture.write_text(
                "## Alpha\n\n```text\n## Beta\n```\n\n## Beta\n", encoding="utf-8"
            )
            # "## Beta" only counts once it appears outside the fence.
            assert_sections_in_file(self, fixture, ["Alpha", "Beta"])

    def test_assert_sections_passes_for_matching_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.md"
            fixture.write_text("## Alpha\n\ntext\n\n## Beta\n\ntext\n", encoding="utf-8")
            assert_sections_in_file(self, fixture, ["Alpha", "Beta"])

    def test_claim_checker_detects_banned_phrase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.md"
            fixture.write_text("The failover is live today.\n", encoding="utf-8")
            with self.assertRaises(AssertionError):
                assert_no_unqualified_live_claims_in_file(self, fixture)

    def test_claim_checker_passes_for_qualified_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.md"
            fixture.write_text(
                "Failover is designed but not yet deployed; it is pre-deployment.\n",
                encoding="utf-8",
            )
            assert_no_unqualified_live_claims_in_file(self, fixture)


# ---------------------------------------------------------------------------
# docs/architecture/overview.md
# ---------------------------------------------------------------------------


class ArchitectureOverviewContractTest(unittest.TestCase):
    RELPATH = "docs/architecture/overview.md"
    HEADINGS = [
        "Components",
        "Data flow",
        "Capacity and fairness",
        "Persisted lifecycle",
        "External authority",
        "Residual risks",
    ]

    def test_required_headings_in_order(self) -> None:
        assert_sections(self, self.RELPATH, self.HEADINGS)

    def test_no_unqualified_live_claims(self) -> None:
        assert_no_unqualified_live_claims(self, self.RELPATH)

    def test_states_no_inbound_route_to_docker_host(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("no inbound", text)
        self.assertIn("docker host", text)

    def test_states_one_fresh_runner_per_job_destroyed_after(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("fresh", text)
        self.assertIn("one job", text)
        self.assertIn("destroyed", text)

    def test_states_setup_helper_exits_before_verifier_and_listener(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("helper", text)
        self.assertIn("exits", text)
        self.assertIn("verifier", text)
        self.assertIn("listener", text)

    def test_states_worker_and_durable_object_are_sole_routing_writer(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("cloudflare worker", text)
        self.assertIn("durable object", text)
        self.assertIn("sole", text)
        self.assertIn("per fleet", text)

    def test_states_jit_bounded_and_not_claimed_hidden(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("jit", text)
        self.assertIn("bounded", text)
        self.assertNotIn("invisible", text)

    def test_states_container_grade_not_vm_grade(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("container grade", text)
        self.assertIn("not vm grade", text)


# ---------------------------------------------------------------------------
# docs/security/trust-boundaries.md
# ---------------------------------------------------------------------------


class TrustBoundariesContractTest(unittest.TestCase):
    RELPATH = "docs/security/trust-boundaries.md"
    HEADINGS = [
        "Trusted components",
        "Untrusted components",
        "Bounded credentials",
        "Docker-host-equivalent authority",
        "Egress barrier",
        "Shared-kernel boundary",
        "Explicit non-claims",
    ]

    def test_required_headings_in_order(self) -> None:
        assert_sections(self, self.RELPATH, self.HEADINGS)

    def test_no_unqualified_live_claims(self) -> None:
        assert_no_unqualified_live_claims(self, self.RELPATH)

    def test_trusted_components_are_named(self) -> None:
        text = _normalized(self.RELPATH)
        for term in ("docker daemon", "controller", "watchdog", "worker", "durable object", "github app"):
            self.assertIn(term, text, f"trusted components section should mention {term!r}")

    def test_untrusted_components_are_named(self) -> None:
        text = _normalized(self.RELPATH)
        for term in ("repository content", "action", "job", "artifact"):
            self.assertIn(term, text, f"untrusted components section should mention {term!r}")

    def test_docker_control_is_host_root_equivalent(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("host root", text)

    def test_explicit_non_claims_present(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("not vm", text)
        self.assertIn("not a hosted service", text)
        self.assertNotIn("invisible", text)


# ---------------------------------------------------------------------------
# docs/operations/*.md
# ---------------------------------------------------------------------------


class ProductionLifecycleContractTest(unittest.TestCase):
    RELPATH = "docs/operations/production-lifecycle.md"
    HEADINGS = [
        "Persisted controller states",
        "Safe upgrade sequence",
        "Host-profile probes",
        "Dark deployment",
    ]

    def test_required_headings_in_order(self) -> None:
        assert_sections(self, self.RELPATH, self.HEADINGS)

    def test_no_unqualified_live_claims(self) -> None:
        assert_no_unqualified_live_claims(self, self.RELPATH)

    def test_links_to_architecture_and_trust_docs(self) -> None:
        text = (REPO_ROOT / self.RELPATH).read_text(encoding="utf-8")
        self.assertIn("../architecture/overview.md", text)
        self.assertIn("../security/trust-boundaries.md", text)

    def test_states_dark_deployment_is_zero_capacity_observer(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("zero", text)
        self.assertIn("observer", text)


class DeploymentAndRollbackContractTest(unittest.TestCase):
    RELPATH = "docs/operations/deployment-and-rollback.md"
    HEADINGS = [
        "Mutually exclusive rollback barrier",
        "Hosted hold as the only maintenance freeze",
        "Positive read-back gates",
        "Rollback sequence",
    ]

    def test_required_headings_in_order(self) -> None:
        assert_sections(self, self.RELPATH, self.HEADINGS)

    def test_no_unqualified_live_claims(self) -> None:
        assert_no_unqualified_live_claims(self, self.RELPATH)

    def test_links_to_architecture_and_trust_docs(self) -> None:
        text = (REPO_ROOT / self.RELPATH).read_text(encoding="utf-8")
        self.assertIn("../architecture/overview.md", text)
        self.assertIn("../security/trust-boundaries.md", text)

    def test_states_fleets_never_acquire_concurrently(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("never", text)
        self.assertIn("concurrent", text)

    def test_states_read_backs_are_positive_not_assumed(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("read back", text)


class FailoverAndNotificationsContractTest(unittest.TestCase):
    RELPATH = "docs/operations/failover-and-notifications.md"
    HEADINGS = [
        "Server-owned enrollment epochs",
        "Heartbeat replay and ordering",
        "Transition, outbox, and read-back",
        "Canary-gated failback",
        "Independent notification retries",
    ]

    def test_required_headings_in_order(self) -> None:
        assert_sections(self, self.RELPATH, self.HEADINGS)

    def test_no_unqualified_live_claims(self) -> None:
        assert_no_unqualified_live_claims(self, self.RELPATH)

    def test_links_to_architecture_and_trust_docs(self) -> None:
        text = (REPO_ROOT / self.RELPATH).read_text(encoding="utf-8")
        self.assertIn("../architecture/overview.md", text)
        self.assertIn("../security/trust-boundaries.md", text)

    def test_states_notification_failure_never_blocks_routing_safety(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("never", text)
        self.assertIn("block", text)
        self.assertIn("routing safety", text)

    def test_states_replayed_and_reordered_heartbeats_are_rejected(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("replay", text)
        self.assertIn("reorder", text)
        self.assertIn("reject", text)


class WorkflowMigrationContractTest(unittest.TestCase):
    RELPATH = "docs/operations/workflow-migration.md"
    HEADINGS = [
        "Stable required checks",
        "Hosted-only workloads",
        "Per-workflow eligibility",
        "Route attestation as proof",
    ]

    def test_required_headings_in_order(self) -> None:
        assert_sections(self, self.RELPATH, self.HEADINGS)

    def test_no_unqualified_live_claims(self) -> None:
        assert_no_unqualified_live_claims(self, self.RELPATH)

    def test_links_to_architecture_and_trust_docs(self) -> None:
        text = (REPO_ROOT / self.RELPATH).read_text(encoding="utf-8")
        self.assertIn("../architecture/overview.md", text)
        self.assertIn("../security/trust-boundaries.md", text)

    def test_states_hosted_only_workload_classes(self) -> None:
        text = _normalized(self.RELPATH)
        for term in ("secret bearing", "release", "deployment write", "unsupported"):
            self.assertIn(term, text, f"workflow-migration.md should mention {term!r}")
        self.assertIn("github hosted", text)

    def test_states_route_attestation_not_variable_read(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("route attestation", text)
        self.assertIn("not", text)
        self.assertIn("variable read", text)


class OperationsContractTest(unittest.TestCase):
    RELPATH = "docs/operations/operations.md"
    HEADINGS = [
        "Watchdog restart authority",
        "Incident evidence",
        "Retention",
    ]

    def test_required_headings_in_order(self) -> None:
        assert_sections(self, self.RELPATH, self.HEADINGS)

    def test_no_unqualified_live_claims(self) -> None:
        assert_no_unqualified_live_claims(self, self.RELPATH)

    def test_links_to_architecture_and_trust_docs(self) -> None:
        text = (REPO_ROOT / self.RELPATH).read_text(encoding="utf-8")
        self.assertIn("../architecture/overview.md", text)
        self.assertIn("../security/trust-boundaries.md", text)

    def test_states_watchdog_cannot_change_routing(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("watchdog", text)
        self.assertIn("restart", text)
        self.assertIn("never", text)
        self.assertIn("routing", text)


# ---------------------------------------------------------------------------
# README.md (Task 7)
# ---------------------------------------------------------------------------


class ReadmeContractTest(unittest.TestCase):
    RELPATH = "README.md"
    HEADINGS = [
        "Status",
        "Purpose",
        "Architecture",
        "Trust boundaries",
        "Intended production lifecycle",
        "Deployment and rollback gates",
        "Failover and notifications design",
        "Workflow migration plan",
        "Operations",
        "Repository map",
        "Development and CI",
        "Release and security",
        "Docs and license",
    ]

    def test_required_sections_in_order(self) -> None:
        assert_sections(self, self.RELPATH, self.HEADINGS)

    def test_no_unqualified_live_claims(self) -> None:
        assert_no_unqualified_live_claims(self, self.RELPATH)

    def test_states_pre_deployment_and_experimental_upstream(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("pre deployment", text)
        self.assertIn("experimental", text)
        self.assertIn("actions/scaleset", text.replace(" ", ""))

    def test_states_not_an_official_github_project(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("not an official github project", text)

    def test_states_container_grade_only_no_hosted_service(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("container grade", text)
        self.assertIn("no hosted", text)

    def test_has_generic_mermaid_diagram(self) -> None:
        text = (REPO_ROOT / self.RELPATH).read_text(encoding="utf-8")
        self.assertIn("```mermaid", text)

    def test_states_final_posture_gated_on_live_evidence(self) -> None:
        text = _normalized(self.RELPATH)
        self.assertIn("after", text)
        self.assertIn("deployment", text)
        self.assertIn("rollback", text)
        self.assertIn("failover", text)
        self.assertIn("read back", text)

    def test_links_every_phase_1_doc(self) -> None:
        text = (REPO_ROOT / self.RELPATH).read_text(encoding="utf-8")
        for target in (
            "docs/architecture/overview.md",
            "docs/security/trust-boundaries.md",
            "docs/operations/production-lifecycle.md",
            "docs/operations/deployment-and-rollback.md",
            "docs/operations/failover-and-notifications.md",
            "docs/operations/workflow-migration.md",
            "docs/operations/operations.md",
        ):
            self.assertIn(target, text, f"README.md should link {target}")


if __name__ == "__main__":
    unittest.main()
