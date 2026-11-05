"""Synthetic timing/privacy contracts for the controller-runtime gate."""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "scripts/test-controller-runtime.sh").read_text(encoding="utf-8")
PREFIX, _ = SOURCE.split(
    "run_stage source-integrity-entry stage_source_integrity_entry || unit_failed=1\n",
    1,
)
FINISH = "cleanup_private_state || true\n" + SOURCE.rsplit(
    "cleanup_private_state || true\n", 1
)[1]
STAGES = {
    "source-integrity-entry", "gofmt", "vet", "unit", "race",
    "network-authority", "acquisition-authority", "routing-authority",
    "boundary", "staticcheck", "module", "shellcheck", "shfmt", "bats",
    "python-contract", "workflow-policy", "repository-metadata",
    "public-sanitizer", "chaos-source", "source-integrity-exit",
    "linux-docker-preflight", "image-reproducibility", "integration-authority",
    "chaos", "docker-state-exit", "source-integrity-docker-exit", "cleanup",
}
SENTINEL = "SYNTHETIC_PRIVATE_STAGE_OUTPUT"


class RuntimeGateTimingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.script = self.root / "scripts/gate.sh"
        self.environment = {**os.environ, "TMPDIR": str(self.logs)}

    def write_fixture(self, body: str, *, finish: bool = True) -> None:
        self.script.write_text(
            PREFIX + body + "\n" + (FINISH if finish else ""), encoding="utf-8"
        )

    def run_fixture(self, body: str, *, finish: bool = True) -> subprocess.CompletedProcess:
        self.write_fixture(body, finish=finish)
        return subprocess.run(
            ["bash", str(self.script), "--unit"],
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def records(self, stderr: str) -> list[dict]:
        records = []
        for line in stderr.splitlines():
            if not line.startswith("{"):
                continue
            record = json.loads(line)
            self.assertEqual(set(record), {
                "schema_version", "event", "stage", "state", "elapsed_seconds",
            })
            self.assertEqual(record["schema_version"], 1)
            self.assertEqual(record["event"], "runtime-gate-stage")
            self.assertIn(record["stage"], STAGES)
            self.assertIn(record["state"], {"start", "pass", "fail"})
            self.assertIs(type(record["elapsed_seconds"]), int)
            self.assertGreaterEqual(record["elapsed_seconds"], 0)
            self.assertLessEqual(record["elapsed_seconds"], 86400)
            records.append(record)
        self.assertLessEqual(len(records), 54)
        return records

    def assert_completed(self, result, stage: str, status: str) -> dict:
        self.assertEqual(result.returncode, 0 if status == "pass" else 1)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        summary = json.loads(result.stdout)
        self.assertEqual(set(summary), {
            "schema_version", "gate", "mode", "status", "failed_stage",
            "linux_docker", "stages",
        })
        self.assertEqual(summary["status"], status)
        self.assertEqual(summary["stages"], [{"id": stage, "status": status}])
        records = self.records(result.stderr)
        self.assertEqual(
            [(record["stage"], record["state"]) for record in records],
            [(stage, "start"), (stage, status), ("cleanup", "start"), ("cleanup", "pass")],
        )
        self.assertEqual(list(self.logs.iterdir()), [])
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        return summary

    def test_success_preserves_stdout_cleanup_and_private_child_descriptors(self) -> None:
        child = self.root / "child.py"
        child.write_text(
            "import os\n"
            f"payload = {SENTINEL.encode()!r} + b'\\n'\n"
            "for fd in range(1, 64):\n"
            "    try:\n"
            "        os.write(fd, payload)\n"
            "    except OSError:\n"
            "        pass\n",
            encoding="utf-8",
        )
        self.environment["SYNTHETIC_CHILD"] = str(child)
        result = self.run_fixture('run_stage gofmt python3 "$SYNTHETIC_CHILD" || true')
        self.assert_completed(result, "gofmt", "pass")
        self.assertEqual(len(result.stderr.splitlines()), 4)

    def test_failure_preserves_diagnostic_and_exit(self) -> None:
        result = self.run_fixture(
            f"synthetic_failure() {{ printf '%s\\n' {SENTINEL} >&2; return 7; }}\n"
            "run_stage gofmt synthetic_failure || true"
        )
        summary = self.assert_completed(result, "gofmt", "fail")
        self.assertEqual(summary["failed_stage"], "gofmt")
        self.assertTrue(result.stderr.endswith("gofmt:command-failed\ngofmt\n"))

    def test_verified_end_waits_for_fail_closed_evidence_checks(self) -> None:
        for output, command_status, expected, reason in [
            ("", 3, "fail", "command-failed"),
            ("", 0, "fail", "evidence-empty"),
            ("ok fake [no tests to run]", 0, "fail", "evidence-empty"),
            ("--- SKIP: TestSynthetic", 0, "fail", "evidence-skip"),
            ("ok fake", 0, "fail", "evidence-count"),
            ("--- PASS: TestSynthetic\nok fake", 0, "pass", None),
        ]:
            with self.subTest(reason=reason):
                result = self.run_fixture(
                    f"synthetic_test() {{ printf '%s' '{output}'; return {command_status}; }}\n"
                    "run_verified_go_test_stage integration-authority 1 1 "
                    "'^--- PASS: TestSynthetic$' synthetic_test || true"
                )
                self.assert_completed(result, "integration-authority", expected)
                if reason:
                    self.assertTrue(result.stderr.endswith(
                        f"integration-authority:{reason}\nintegration-authority\n"
                    ))

    def test_cleanup_failure_has_one_failed_end_and_unchanged_summary(self) -> None:
        result = self.run_fixture("rm() { return 1; }")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["stages"], [{"id": "cleanup", "status": "fail"}])
        self.assertEqual(
            [(record["stage"], record["state"]) for record in self.records(result.stderr)],
            [("cleanup", "start"), ("cleanup", "fail")],
        )

    def test_interruption_leaves_start_without_summary_or_false_end(self) -> None:
        for stop_signal in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(stop_signal=stop_signal):
                started = self.root / f"started-{stop_signal.value}"
                self.environment["SYNTHETIC_STARTED"] = str(started)
                self.write_fixture(
                    f"synthetic_wait() {{ printf '%s\\n' {SENTINEL}; "
                    ': > "$SYNTHETIC_STARTED"; sleep 60; }\n'
                    "run_stage image-reproducibility synthetic_wait || true"
                )
                with subprocess.Popen(
                    ["bash", str(self.script), "--unit"],
                    env=self.environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                ) as process:
                    # Read the live control line before stopping the process group.
                    # communicate has a timeout so a missing start cannot hang tests.
                    try:
                        ready, _, _ = select.select([process.stderr], [], [], 3)
                        self.assertTrue(ready, "stage start was not emitted before blocking")
                        first_line = process.stderr.readline()
                        deadline = time.monotonic() + 3
                        while not started.exists() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue(started.exists(), "synthetic stage did not start")
                        os.killpg(process.pid, stop_signal)
                        stdout, remainder = process.communicate(timeout=3)
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.communicate(timeout=3)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(stdout, "")
                records = self.records(first_line + remainder)
                self.assertEqual([(r["stage"], r["state"]) for r in records], [
                    ("image-reproducibility", "start"),
                ])
                self.assertNotIn(SENTINEL, first_line + remainder)

    def test_labels_states_count_and_clock_are_bounded(self) -> None:
        result = self.run_fixture(
            "emit_stage_timing 'SYNTHETIC_PRIVATE_STAGE_OUTPUT' start\n"
            "emit_stage_timing gofmt 'SYNTHETIC_PRIVATE_STAGE_OUTPUT'\n"
            "SECONDS=-10\nemit_stage_timing gofmt start\n"
            "SECONDS=999999\nemit_stage_timing gofmt pass\n"
            "unset SECONDS\nSECONDS=malformed\nemit_stage_timing gofmt start\n"
            "for ((index=0; index<100; index++)); do emit_stage_timing gofmt start; done",
            finish=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        records = self.records(result.stderr)
        self.assertEqual(len(records), 54)
        self.assertEqual(records[0]["elapsed_seconds"], 0)
        self.assertEqual(records[1]["elapsed_seconds"], 86400)
        self.assertEqual(records[2]["elapsed_seconds"], 0)
        self.assertNotIn(SENTINEL, result.stderr)

    def test_noncanonical_clock_cannot_break_record_json(self) -> None:
        result = self.run_fixture(
            "unset SECONDS\n"
            "for value in 00001 00009 00086400; do\n"
            "  SECONDS=$value\n  emit_stage_timing gofmt start\ndone",
            finish=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual([r["elapsed_seconds"] for r in self.records(result.stderr)], [0, 0, 0])

    def test_broken_pipe_stderr_does_not_change_success(self) -> None:
        self.write_fixture("run_stage gofmt true || true")
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = subprocess.run(
                ["bash", str(self.script), "--unit"],
                env=self.environment,
                stdout=subprocess.PIPE,
                stderr=writer,
                text=True,
                timeout=10,
                check=False,
            )
        finally:
            os.close(writer)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["status"], "pass")
        self.assertEqual(list(self.logs.iterdir()), [])

    def test_unwritable_stderr_does_not_change_success(self) -> None:
        for redirection in ("2>/dev/full", "2>&-"):
            with self.subTest(redirection=redirection):
                result = self.run_fixture(
                    f"exec {redirection}\nrun_stage gofmt true || true"
                )
                self.assertEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stdout)["status"], "pass")
                self.assertEqual(list(self.logs.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
