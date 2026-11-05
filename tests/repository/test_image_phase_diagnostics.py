"""Closed image/phase diagnostics with synthetic subprocesses only."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECK_IMAGES = ROOT / "scripts/ci/check-images.sh"
GATE_SOURCE = (ROOT / "scripts/test-controller-runtime.sh").read_text(encoding="utf-8")
GATE_PREFIX = GATE_SOURCE.split(
    "run_stage source-integrity-entry stage_source_integrity_entry || unit_failed=1\n", 1
)[0]
GATE_FINISH = "cleanup_private_state || true\n" + GATE_SOURCE.rsplit(
    "cleanup_private_state || true\n", 1
)[1]
IMAGES = (
    "network-adapter", "network-broker-dialer", "network-broker-parser",
    "network-helper", "network-verifier", "runner", "synthetic-listener",
)
PHASES = (
    "first-build", "first-id-inspect", "first-created-inspect", "first-created-time",
    "second-build", "second-id-inspect", "second-created-inspect", "second-created-time",
    "image-id-mismatch",
)
EPOCH = "1700000000"
SENTINEL = "SYNTHETIC_PRIVATE_IMAGE_OUTPUT"
FORGED = "image-reproducibility:synthetic-listener:first-build"
DOCKER = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with open(os.environ["SYNTHETIC_CALLS"], "a", encoding="utf-8") as log:
    log.write(json.dumps([os.environ.get("SOURCE_DATE_EPOCH", ""), args]) + "\n")
state = Path(os.environ["SYNTHETIC_STATE"])
tags = set(state.read_text().splitlines())
if args[:2] == ["info", "--format"]:
    print('"27.1.2"')
    sys.exit(0)
if args[:2] in (["ps", "-a"], ["network", "ls"], ["volume", "ls"]):
    sys.exit(0)
if args[:2] == ["image", "ls"]:
    print("\n".join(sorted(tags)))
    sys.exit(0)
if args[:2] == ["image", "rm"]:
    tags.difference_update(args[3:])
    state.write_text("\n".join(sorted(tags)))
    sys.exit(0)
if args[:2] == ["buildx", "build"]:
    output = args[args.index("--output") + 1]
    tag = output.split("name=", 1)[1].split(",", 1)[0]
    phase = "first-build" if tag.endswith("-a") else "second-build"
    tags.add(tag)
    state.write_text("\n".join(sorted(tags)))
elif args[:2] == ["image", "inspect"]:
    tag = args[-1]
    phase = ("first-" if tag.endswith("-a") else "second-") + {
        "{{.Id}}": "id-inspect", "{{.Created}}": "created-inspect",
    }[args[3]]
else:
    sys.exit(1)
name = tag.split(":", 1)[1].rsplit("-", 1)[0]
target = os.environ.get("SYNTHETIC_IMAGE") == name
failure = os.environ.get("SYNTHETIC_PHASE", "")
if target and failure == phase:
    payload = (os.environ["SYNTHETIC_SENTINEL"] + "\n" +
               os.environ["SYNTHETIC_FORGED"] + "\n").encode()
    for fd in range(1, 64):
        try:
            os.write(fd, payload)
        except OSError:
            pass
    sys.exit(int(os.environ.get("SYNTHETIC_DOCKER_STATUS", "7")))
if args[:2] == ["image", "inspect"]:
    if args[3] == "{{.Id}}":
        print("sha256:" + ("b" if target and failure == "image-id-mismatch"
                          and tag.endswith("-b") else "a") * 64)
    else:
        wrong_time = target and failure == phase.replace("inspect", "time")
        print(os.environ.get("SYNTHETIC_BAD_TIME", "2023-11-14T22:13:21Z")
              if wrong_time else "2023-11-14T22:13:20Z")
'''
JQ = r'''#!/bin/sh
count=0
IFS= read -r count <"$SYNTHETIC_JQ_COUNT" || true
count=$((count + 1))
printf '%s\n' "$count" >"$SYNTHETIC_JQ_COUNT"
if [ "$count" -eq "${SYNTHETIC_JQ_FAIL:-0}" ]; then
    printf '%s\n' "$SYNTHETIC_SENTINEL"
    printf '%s\n' "$SYNTHETIC_FORGED" >&2
    exit "$SYNTHETIC_CONTROL_STATUS"
fi
if [ "$count" -eq 14 ] && [ "${SYNTHETIC_CLASSIFIER_OUTPUT+x}" = x ]; then
    printf '%s\n' "$SYNTHETIC_CLASSIFIER_OUTPUT"
    exit 0
fi
exec "$SYNTHETIC_REAL_JQ" "$@"
'''
GIT = r'''#!/usr/bin/env python3
import os
import sys
if sys.argv[1:] == ["show", "-s", "--format=%ct", "HEAD"]:
    status = int(os.environ.get("SYNTHETIC_GIT_STATUS", "0"))
    if status:
        print(os.environ["SYNTHETIC_SENTINEL"], file=sys.stderr)
        sys.exit(status)
    print("1700000000")
elif sys.argv[1] != "diff":
    sys.exit(1)
'''
GO = r'''#!/usr/bin/env python3
import os
import sys
from pathlib import Path
with Path(os.environ["SYNTHETIC_DOWNSTREAM"]).open("a") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
if "-tags=integration" in sys.argv:
    names = ["ShutdownIntegrationAuthorityStopsOnlyExactTuple",
             "ShutdownIntegrationAuthorityAcceptsExactInactiveAbsence",
             "ProveIntegrationAuthorityAbsentIsReadOnly",
             "ShutdownIntegrationAuthorityRejectsPartialOrAmbiguousClaim",
             "ShutdownIntegrationAuthorityRejectsOpenInputs"]
    repeat = 1
elif "-tags=chaos" in sys.argv:
    names = ["ChaosSourceOptInBoundary", "ChaosOperationalGate",
             "ControllerStateRestartTable", "DockerComponentFailureCleanup",
             "FleetFenceRaceAndObserverRecovery", "JailPermitFailuresNeverReachKernelDial",
             "JailRaceNarrowingAndCancellationRemainClosed",
             "QTSLifecycleEveryJournalEffectResumesAfterRestart",
             "QTSShellLifecycleFailureRemainsClosed"]
    repeat = 10
else:
    sys.exit(1)
for _ in range(repeat):
    for name in names:
        print("--- PASS: Test" + name + " (0.00s)")
print("ok  example.invalid/synthetic 0.001s")
'''


def entry(name: str) -> dict[str, str]:
    return {"name": name, "context": f"images/{name}",
            "dockerfile": f"images/{name}/Dockerfile"}


class ImagePhaseDiagnosticsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.logs = self.root / "logs"
        self.logs.mkdir()
        (self.root / "scripts/ci").mkdir(parents=True)
        shutil.copy2(CHECK_IMAGES, self.root / "scripts/ci/check-images.sh")
        self.manifest = self.root / "images/manifest.json"
        self.calls = self.root / "calls.jsonl"
        self.state = self.root / "tags"
        self.jq_count = self.root / "jq-count"
        self.downstream = self.root / "downstream"
        self.environment = {
            **os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "TMPDIR": str(self.logs), "SYNTHETIC_CALLS": str(self.calls),
            "SYNTHETIC_STATE": str(self.state), "SYNTHETIC_JQ_COUNT": str(self.jq_count),
            "SYNTHETIC_REAL_JQ": shutil.which("jq"), "SYNTHETIC_SENTINEL": SENTINEL,
            "SYNTHETIC_FORGED": FORGED, "SYNTHETIC_DOWNSTREAM": str(self.downstream),
            "PGHAR_INTEGRATION_DOCKER": "1", "PGHAR_CHAOS_DOCKER": "1",
        }
        self.environment.pop("IMAGES_MANIFEST", None)
        for name, source in (("docker", DOCKER), ("jq", JQ), ("git", GIT), ("go", GO)):
            self.executable(self.bin / name, source)
        self.executable(self.bin / "uname", "#!/bin/sh\nprintf '%s\\n' Linux\n")
        self.write_manifest([entry(name) for name in IMAGES])

    def executable(self, path: Path, source: str) -> None:
        path.write_text(source, encoding="utf-8")
        path.chmod(0o700)

    def write_manifest(self, entries: list[dict], path: Path | None = None) -> None:
        for image in entries:
            (self.root / image["context"]).mkdir(parents=True, exist_ok=True)
            (self.root / image["dockerfile"]).write_text("FROM scratch\n", encoding="utf-8")
        destination = path or self.manifest
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps({"version": 1, "images": entries}), encoding="utf-8")

    def run_command(self, command: list[str], **overrides: str) -> subprocess.CompletedProcess:
        for path, value in ((self.calls, ""), (self.state, ""), (self.jq_count, "0"),
                            (self.downstream, "")):
            path.write_text(value, encoding="utf-8")
        return subprocess.run(command, cwd=self.root, env={**self.environment, **overrides},
                              capture_output=True, text=True, timeout=15, check=False)

    def run_wrapper(self, *arguments: str, **overrides: str) -> subprocess.CompletedProcess:
        return self.run_command(["bash", str(CHECK_IMAGES), *arguments], **overrides)

    def docker_calls(self) -> list[list]:
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def assert_public_gate(self, result, expected: str | None) -> dict:
        self.assertEqual(result.returncode, 1 if expected else 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        summary = json.loads(result.stdout)
        self.assertEqual(set(summary), {"schema_version", "gate", "mode", "status",
                                       "failed_stage", "linux_docker", "stages"})
        self.assertEqual(summary["status"], "fail" if expected else "pass")
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        diagnostics = [line for line in result.stderr.splitlines() if not line.startswith("{")]
        self.assertEqual(diagnostics, [expected, "image-reproducibility"] if expected else [])
        records = [json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")]
        self.assertLessEqual(len(records), 54)
        for record in records:
            self.assertEqual(set(record), {"schema_version", "event", "stage", "state",
                                          "elapsed_seconds"})
            self.assertEqual(record["schema_version"], 1)
            self.assertEqual(record["event"], "runtime-gate-stage")
            self.assertIs(type(record["elapsed_seconds"]), int)
            self.assertGreaterEqual(record["elapsed_seconds"], 0)
            self.assertLessEqual(record["elapsed_seconds"], 86400)
        expected_records = [(stage["id"], state) for stage in summary["stages"]
                            for state in ("start", stage["status"])]
        expected_records += [("cleanup", "start"), ("cleanup", "pass")]
        self.assertEqual([(r["stage"], r["state"]) for r in records], expected_records)
        self.assertEqual(list(self.logs.iterdir()), [])
        return summary

    def test_all_known_image_phase_codes_ignore_manifest_position(self) -> None:
        for index, name in enumerate(IMAGES):
            self.write_manifest([entry(name)])
            for offset, phase in enumerate(PHASES):
                with self.subTest(name=name, phase=phase):
                    result = self.run_wrapper(SYNTHETIC_IMAGE=name, SYNTHETIC_PHASE=phase)
                    self.assertEqual(result.returncode, 50 + index * 10 + offset, result.stderr)
                    commands = [["buildx", "build"], ["image", "inspect"], ["image", "inspect"],
                                ["buildx", "build"], ["image", "inspect"], ["image", "inspect"]]
                    expected = commands[:(1, 2, 3, 3, 4, 5, 6, 6, 6)[offset]]
                    if offset in (3, 7, 8):
                        expected.append(["image", "rm"])
                    self.assertEqual([args[:2] for _, args in self.docker_calls()], expected)

    def test_unknown_or_changed_triples_keep_all_legacy_phases(self) -> None:
        variants = [entry("synthetic-unknown"),
                    {**entry("runner"), "name": "synthetic-renamed"},
                    {**entry("runner"), "context": "images/runner/.",
                     "dockerfile": "images/runner/./Dockerfile"},
                    {**entry("runner"), "dockerfile": "images/runner/Alternate"},
                    {**entry("runner"), "context": "images"}]
        for image in variants:
            self.write_manifest([image])
            for offset, phase in enumerate(PHASES):
                with self.subTest(image=image, phase=phase):
                    result = self.run_wrapper(SYNTHETIC_IMAGE=image["name"], SYNTHETIC_PHASE=phase)
                    self.assertEqual(result.returncode, 40 + offset, result.stderr)

    def test_lossy_shell_strings_do_not_gain_known_tuple_authority(self) -> None:
        # Command substitution strips trailing newlines; Bash also discards
        # NULs. Attribution must compare the original JSON values instead.
        for field in ("name", "context", "dockerfile"):
            for suffix in ("\n", "\x00"):
                with self.subTest(field=field, suffix=repr(suffix)):
                    image = entry("runner")
                    image[field] += suffix
                    self.manifest.write_text(json.dumps({"version": 1, "images": [image]}),
                                             encoding="utf-8")
                    result = self.run_wrapper(SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE="first-build")
                    self.assertEqual(result.returncode, 40, result.stderr)

    def test_argument_and_environment_overrides_preserve_exact_tuple_binding(self) -> None:
        known = self.root / "known.json"
        unknown = self.root / "unknown.json"
        empty = self.root / "empty.json"
        self.write_manifest([entry("runner")], known)
        self.write_manifest([{**entry("runner"), "dockerfile": "images/runner/Alternate"}], unknown)
        self.write_manifest([], empty)
        for manifest, expected in ((known, 100), (unknown, 40), (empty, 0)):
            for use_argument in (False, True):
                with self.subTest(manifest=manifest.name, argument=use_argument):
                    arguments = (str(manifest),) if use_argument else ()
                    environment = str(empty) if use_argument else str(manifest)
                    result = self.run_wrapper(*arguments, IMAGES_MANIFEST=environment,
                                              SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE="first-build")
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected == 0:
                        self.assertEqual(self.docker_calls(), [])

    def test_jq_and_git_reserved_statuses_are_not_protocol_authority(self) -> None:
        self.write_manifest([entry("runner")])
        # jq calls cover initial JSON validation, every control assignment in
        # both passes, every field extraction, and the exact-tuple classifier.
        for code in (40, 50, 118):
            for invocation in range(1, 15):
                with self.subTest(tool="jq", code=code, invocation=invocation):
                    result = self.run_wrapper(SYNTHETIC_JQ_FAIL=str(invocation),
                                              SYNTHETIC_CONTROL_STATUS=str(code))
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(self.docker_calls(), [])
            with self.subTest(tool="git", code=code):
                result = self.run_wrapper(SYNTHETIC_GIT_STATUS=str(code))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(self.docker_calls(), [])

    def test_malformed_classifier_output_fails_generically_before_docker(self) -> None:
        self.write_manifest([entry("runner")])
        for value in ("", "0", "symbolic", "39", "49", "59", "119", "256", "-1", "040", "40\n50"):
            with self.subTest(value=value):
                result = self.run_wrapper(SYNTHETIC_CLASSIFIER_OUTPUT=value,
                                          SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE="first-build")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(self.docker_calls(), [])

    def test_docker_reserved_status_is_translated_by_actual_image_and_phase(self) -> None:
        self.write_manifest([entry("runner")])
        for phase in ("first-build", "first-id-inspect", "first-created-inspect",
                      "second-build", "second-id-inspect", "second-created-inspect"):
            for code in (40, 50, 118, 124, 137, 255):
                with self.subTest(phase=phase, code=code):
                    result = self.run_wrapper(SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE=phase,
                                              SYNTHETIC_DOCKER_STATUS=str(code))
                    self.assertEqual(result.returncode, 100 + PHASES.index(phase), result.stderr)

    def test_parent_decodes_every_exit_byte_and_keeps_forged_output_private(self) -> None:
        child = self.root / "child.py"
        child.write_text(
            "import os, sys\n"
            f"payload = {(SENTINEL + chr(10) + FORGED + chr(10)).encode()!r}\n"
            "for fd in range(1, 64):\n"
            "    try: os.write(fd, payload)\n"
            "    except OSError: pass\n"
            "sys.exit(int(sys.argv[1]))\n", encoding="utf-8")
        gate = self.root / "scripts/gate.sh"
        gate.write_text(GATE_PREFIX + 'run_stage image-reproducibility python3 "$SYNTHETIC_CHILD" '
                        '"$SYNTHETIC_EXIT" || true\n' + GATE_FINISH, encoding="utf-8")
        labels = {40 + offset: f"image-reproducibility:{phase}"
                  for offset, phase in enumerate(PHASES)}
        labels.update({50 + index * 10 + offset: f"image-reproducibility:{name}:{phase}"
                       for index, name in enumerate(IMAGES) for offset, phase in enumerate(PHASES)})
        for code in range(256):
            with self.subTest(code=code):
                result = self.run_command(["bash", str(gate), "--docker"],
                                          SYNTHETIC_CHILD=str(child), SYNTHETIC_EXIT=str(code))
                expected = labels.get(code, "image-reproducibility:command-failed") if code else None
                self.assert_public_gate(result, expected)

    def test_success_keeps_every_build_flag_operation_order_and_cleanup(self) -> None:
        order = list(reversed(IMAGES))
        self.write_manifest([entry(name) for name in order])
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = []
        for name in order:
            tags = [f"portable-ghar-check-images:{name}-{suffix}" for suffix in ("a", "b")]
            for tag in tags:
                expected.append([EPOCH, ["buildx", "build", "--platform", "linux/amd64",
                    "--no-cache", "--provenance=false", "--sbom=false", "--build-arg",
                    f"SOURCE_DATE_EPOCH={EPOCH}", "--output",
                    f"type=docker,name={tag},rewrite-timestamp=true", "-f",
                    f"images/{name}/Dockerfile", f"images/{name}"]])
                expected.extend([["", ["image", "inspect", "--format", field, tag]]
                                 for field in ("{{.Id}}", "{{.Created}}")])
            expected.append(["", ["image", "rm", "-f", *tags]])
        self.assertEqual(self.docker_calls(), expected)
        self.assertEqual(self.state.read_text(), "")
        self.assertTrue(result.stdout.endswith("all 7 registered image(s) build reproducibly\n"))

    def test_creation_time_validation_keeps_closed_phase_and_cleanup(self) -> None:
        self.write_manifest([entry("runner")])
        for phase in ("first-created-time", "second-created-time"):
            for value in ("invalid", "2023-11-14T22:13:20.1Z", "2023-11-14T22:13:20+01:00"):
                with self.subTest(phase=phase, value=value):
                    result = self.run_wrapper(SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE=phase,
                                              SYNTHETIC_BAD_TIME=value)
                    self.assertEqual(result.returncode, 100 + PHASES.index(phase))
                    self.assertEqual(self.state.read_text(), "")

    def test_complete_gate_stops_after_first_image_failure_and_cleans_up(self) -> None:
        gate = self.root / "scripts/gate.sh"
        gate.write_text(GATE_SOURCE, encoding="utf-8")
        for phase in PHASES:
            with self.subTest(phase=phase):
                result = self.run_command(["bash", str(gate), "--docker"],
                                          SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE=phase)
                summary = self.assert_public_gate(result, f"image-reproducibility:runner:{phase}")
                self.assertEqual(summary["failed_stage"], "image-reproducibility")
                self.assertEqual([s["id"] for s in summary["stages"]], [
                    "source-integrity-entry", "linux-docker-preflight", "image-reproducibility",
                    "docker-state-exit", "source-integrity-docker-exit"])
                self.assertEqual(self.downstream.read_text(), "")
                self.assertEqual(self.state.read_text(), "")
                builds = [args for _, args in self.docker_calls() if args[:2] == ["buildx", "build"]]
                self.assertFalse(any("images/synthetic-listener" in args for args in builds))
                self.assertEqual(len(builds), 11 if PHASES.index(phase) < 4 else 12)
                # For inspection/build failures the wrapper preserves its existing
                # cleanup behavior; the parent still removes remaining fixed tags.
                clean_phases = {"first-created-time", "second-created-time", "image-id-mismatch"}
                self.assertEqual(summary["stages"][-2]["status"],
                                 "pass" if phase in clean_phases else "fail")

    def test_complete_gate_control_failures_stay_generic_and_private(self) -> None:
        gate = self.root / "scripts/gate.sh"
        gate.write_text(GATE_SOURCE, encoding="utf-8")
        for environment in ({"SYNTHETIC_GIT_STATUS": "50"},
                            {"SYNTHETIC_JQ_FAIL": "4", "SYNTHETIC_CONTROL_STATUS": "118"}):
            # Two jq calls belong to preflight; call four is the wrapper's
            # version assignment. Neither control failure is Docker authority.
            with self.subTest(environment=environment):
                result = self.run_command(["bash", str(gate), "--docker"], **environment)
                self.assert_public_gate(result, "image-reproducibility:command-failed")
                self.assertEqual(self.downstream.read_text(), "")
                self.assertFalse(any(args[:2] == ["buildx", "build"]
                                     for _, args in self.docker_calls()))

    def test_complete_gate_unknown_name_never_reaches_public_diagnostics(self) -> None:
        name = "synthetic-private-image-name"
        self.write_manifest([entry(name)])
        gate = self.root / "scripts/gate.sh"
        gate.write_text(GATE_SOURCE, encoding="utf-8")
        result = self.run_command(["bash", str(gate), "--docker"],
                                  SYNTHETIC_IMAGE=name, SYNTHETIC_PHASE="first-build")
        self.assert_public_gate(result, "image-reproducibility:first-build")
        self.assertNotIn(name, result.stdout + result.stderr)
        self.assertEqual(self.state.read_text(), "")
        self.assertEqual(self.downstream.read_text(), "")

    def test_complete_gate_success_has_no_failure_diagnostic(self) -> None:
        gate = self.root / "scripts/gate.sh"
        gate.write_text(GATE_SOURCE, encoding="utf-8")
        result = self.run_command(["bash", str(gate), "--docker"])
        summary = self.assert_public_gate(result, None)
        self.assertEqual(summary["failed_stage"], None)
        self.assertEqual([s["id"] for s in summary["stages"]], [
            "source-integrity-entry", "linux-docker-preflight", "image-reproducibility",
            "integration-authority", "chaos", "docker-state-exit", "source-integrity-docker-exit"])
        self.assertEqual(len(self.downstream.read_text().splitlines()), 2)
        self.assertEqual(self.state.read_text(), "")


if __name__ == "__main__":
    unittest.main()
