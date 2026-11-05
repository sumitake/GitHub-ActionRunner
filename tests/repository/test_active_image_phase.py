# SPDX-License-Identifier: MPL-2.0
"""Production gate last-started records, with synthetic subprocesses only."""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import shutil
import subprocess
import sys
import time
import unittest

from repository import test_image_phase_diagnostics as fixture


NORMAL = (*fixture.PHASES[:8], "cleanup", "image-id-compare")
FIELDS = {"schema_version", "event", "state", "image", "phase"}
FORGED_EVENT = ('{"schema_version":1,"event":"image-phase","state":"last-started",'
                '"image":"synthetic-listener","phase":"second-build"}')


class ActiveImagePhaseTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.ImagePhaseDiagnosticsTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.environment["SYNTHETIC_FORGED"] = FORGED_EVENT
        self.fixture.write_manifest([fixture.entry("runner")])
        self.gate = self.fixture.root / "scripts/gate.sh"
        self.gate.write_text(fixture.GATE_SOURCE)

    def records(self, stderr):
        records = [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]
        phases = [r for r in records if r["event"] == "image-phase"]
        self.assertLessEqual(len(phases), 128)
        for index, record in enumerate(phases):
            self.assertEqual(set(record), FIELDS)
            self.assertEqual(record["schema_version"], 1)
            self.assertIn(record["image"], (*fixture.IMAGES, "unattributed"))
            if record["state"] == "unavailable":
                self.assertEqual(index, 127)
                self.assertEqual(record["image"], "unattributed")
                self.assertEqual(record["phase"], "record-limit")
            else:
                self.assertLess(index, 127)
                self.assertEqual(record["state"], "last-started")
                self.assertIn(record["phase"], (*NORMAL, "manifest-validation", "entry-prepare"))
        return phases

    def test_complete_gate_has_closed_last_started_sequence(self):
        result = self.fixture.run_command(["bash", str(self.gate), "--docker"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(r["image"], r["phase"]) for r in self.records(result.stderr)],
                         [("unattributed", "manifest-validation"),
                          ("unattributed", "entry-prepare"),
                          *(("runner", phase) for phase in NORMAL)])

    def test_live_first_build_before_outer_term_or_kill(self):
        f = self.fixture
        marker = f.root / "synthetic-block-entered"
        synthetic = fixture.DOCKER.replace('if target and failure == phase:\n', '''if target and failure == phase:
    import signal
    Path(os.environ["SYNTHETIC_BLOCK_ENTERED"]).touch()
    while True:
        signal.pause()
if target and failure == phase:
''')
        f.executable(f.bin / "docker", synthetic)
        for stop in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=stop):
                marker.unlink(missing_ok=True)
                for path, value in ((f.calls, ""), (f.state, ""), (f.jq_count, "0"), (f.downstream, "")):
                    path.write_text(value)
                # A background test runner may inherit ignored SIGINT. Establish
                # the intended disposition only in this synthetic child, then
                # exec Bash without changing its PID/process group or the runner.
                launch = ("import os, signal, sys\n"
                          "signal.signal(signal.SIGINT, signal.SIG_DFL)\n"
                          "os.execvp('bash', ['bash', *sys.argv[1:]])\n")
                process = subprocess.Popen([sys.executable, "-c", launch, str(self.gate), "--docker"], cwd=f.root,
                    env={**f.environment, "SYNTHETIC_IMAGE": "runner", "SYNTHETIC_PHASE": "first-build",
                         "SYNTHETIC_BLOCK_ENTERED": str(marker)}, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
                try:
                    deadline = time.monotonic() + 10
                    while not marker.exists() and time.monotonic() < deadline:
                        self.assertIsNone(process.poll(), "Synthetic build exited before block")
                        time.sleep(0.01)
                    self.assertTrue(marker.exists(), "Synthetic build never reached block")
                    lines = []
                    while select.select([process.stderr], [], [], 0.1)[0]:
                        lines.append(process.stderr.readline().decode())
                    phases = self.records("".join(lines))
                    self.assertTrue(phases, "No live image/phase record before blocked build")
                    self.assertEqual(phases[-1], {"schema_version": 1, "event": "image-phase",
                        "state": "last-started", "image": "runner", "phase": "first-build"})
                    os.killpg(process.pid, stop)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(stdout, b"", "No summary is valid after interruption")
                    self.assertEqual(stderr, b"")
                    self.assertIn(process.returncode, (-stop, 128 + stop))
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.communicate(timeout=5)


    def test_live_signal_matrix_with_inherited_ignored_sigint(self):
        probe = """import signal, unittest
from repository.test_active_image_phase import ActiveImagePhaseTest
signal.signal(signal.SIGINT, signal.SIG_IGN)
suite = unittest.TestSuite([ActiveImagePhaseTest('test_live_first_build_before_outer_term_or_kill')])
result = unittest.TextTestRunner(verbosity=2).run(suite)
assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
raise SystemExit(0 if result.wasSuccessful() else 1)
"""
        result = subprocess.run([sys.executable, "-c", probe], cwd=fixture.ROOT,
            env={**os.environ, "PYTHONPATH": str(fixture.ROOT / "tests")},
            capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def write_gate(self, body=None, prefix=fixture.GATE_PREFIX):
        self.gate.write_text(prefix + (body or 'run_image_stage || true\n') + fixture.GATE_FINISH)

    def reset_state(self):
        f = self.fixture
        for path, value in ((f.calls, ""), (f.state, ""), (f.jq_count, "0"), (f.downstream, "")):
            path.write_text(value)
        for directory in f.logs.iterdir():
            shutil.rmtree(directory)

    def test_every_helper_start_is_live_before_term_or_kill(self):
        f = self.fixture
        self.write_gate()
        blocker = f.root / "blocker.py"
        blocker.write_text('''import json, os, signal, subprocess, sys
from pathlib import Path
payload = (os.environ["SYNTHETIC_SENTINEL"] + "\\n" + os.environ["SYNTHETIC_FORGED"] + "\\n").encode()
fds = set(range(1, 64)) | {int(x) for x in os.listdir("/proc/self/fd")}
for fd in fds:
    try: os.write(fd, payload)
    except OSError: pass
Path(os.environ["SYNTHETIC_BLOCK_ENTERED"]).write_text(str(os.getpid()))
while True: signal.pause()
''')
        helper_phases = {
            "validate_manifest": "manifest-validation", "prepare_entry": "entry-prepare",
            "build_a": "first-build", "id_a": "first-id-inspect",
            "created_a": "first-created-inspect", "validate_a": "first-created-time",
            "build_b": "second-build", "id_b": "second-id-inspect",
            "created_b": "second-created-inspect", "validate_b": "second-created-time",
            "cleanup_ab": "cleanup", "compare_report": "image-id-compare",
        }
        marker = f.root / "blocked"
        original = fixture.CHECK_IMAGES.read_text()
        for helper, phase in helper_phases.items():
            for stop in (signal.SIGTERM, signal.SIGKILL):
                with self.subTest(helper=helper, signal=stop):
                    self.reset_state()
                    marker.unlink(missing_ok=True)
                    (f.root / "scripts/ci/check-images.sh").write_text(
                        original + '\nci_images_' + helper + '() { python3 "$SYNTHETIC_BLOCKER"; }\n')
                    process = subprocess.Popen(["bash", str(self.gate), "--docker"], cwd=f.root,
                        env={**f.environment, "SYNTHETIC_BLOCKER": str(blocker),
                             "SYNTHETIC_BLOCK_ENTERED": str(marker)}, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
                    try:
                        deadline = time.monotonic() + 10
                        while not marker.exists() and time.monotonic() < deadline:
                            self.assertIsNone(process.poll())
                            time.sleep(0.01)
                        self.assertTrue(marker.exists())
                        lines = []
                        while select.select([process.stderr], [], [], 0.05)[0]:
                            lines.append(process.stderr.readline().decode())
                        public = "".join(lines)
                        phases = self.records(public)
                        self.assertEqual(phases[-1]["phase"], phase)
                        self.assertEqual(phases[-1]["image"], "unattributed" if helper in
                                         ("validate_manifest", "prepare_entry") else "runner")
                        self.assertNotIn(fixture.SENTINEL, public)
                        self.assertNotIn(FORGED_EVENT, public)
                        private = list(f.logs.glob("*/image-reproducibility.log"))
                        self.assertEqual(len(private), 1)
                        self.assertEqual(private[0].parent.stat().st_mode & 0o777, 0o700)
                        self.assertEqual(private[0].stat().st_mode & 0o777, 0o600)
                        self.assertIn(fixture.SENTINEL, private[0].read_text())
                        child = int(marker.read_text())
                        os.killpg(process.pid, stop)
                        stdout, stderr = process.communicate(timeout=5)
                        self.assertEqual(stdout, b"")
                        self.assertEqual(stderr, b"")
                        self.assertIn(process.returncode, (-stop, 128 + stop))
                        stat = Path(f"/proc/{child}/stat")
                        deadline = time.monotonic() + 5
                        while stat.exists():
                            try:
                                state = stat.read_text().rsplit(")", 1)[1].split()[0]
                            except (FileNotFoundError, ProcessLookupError):
                                break
                            if state == "Z":
                                break
                            self.assertLess(time.monotonic(), deadline, "Synthetic descendant survived")
                            time.sleep(0.01)
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.communicate(timeout=5)

    def test_invalid_time_cleanup_start_is_live_on_both_paths(self):
        f = self.fixture
        self.write_gate()
        marker = f.root / "cleanup-entered"
        synthetic = fixture.DOCKER.replace('if args[:2] == ["image", "rm"]:\n', '''if args[:2] == ["image", "rm"]:
    import signal
    Path(os.environ["SYNTHETIC_BLOCK_ENTERED"]).touch()
    while True: signal.pause()
''')
        f.executable(f.bin / "docker", synthetic)
        for phase in ("first-created-time", "second-created-time"):
            for stop in (signal.SIGTERM, signal.SIGKILL):
                with self.subTest(phase=phase, signal=stop):
                    self.reset_state()
                    marker.unlink(missing_ok=True)
                    process = subprocess.Popen(["bash", str(self.gate), "--docker"], cwd=f.root,
                        env={**f.environment, "SYNTHETIC_IMAGE": "runner", "SYNTHETIC_PHASE": phase,
                             "SYNTHETIC_BLOCK_ENTERED": str(marker)}, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
                    try:
                        deadline = time.monotonic() + 10
                        while not marker.exists() and time.monotonic() < deadline:
                            self.assertIsNone(process.poll())
                            time.sleep(0.01)
                        self.assertTrue(marker.exists())
                        lines = []
                        while select.select([process.stderr], [], [], 0.05)[0]:
                            lines.append(process.stderr.readline().decode())
                        self.assertEqual([r["phase"] for r in self.records("".join(lines))][-2:],
                                         [phase, "cleanup"])
                        os.killpg(process.pid, stop)
                        stdout, stderr = process.communicate(timeout=5)
                        self.assertEqual(stdout + stderr, b"")
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.communicate(timeout=5)

    def test_children_and_grandchildren_cannot_forge_via_actual_inherited_fds(self):
        f = self.fixture
        self.write_gate()
        attack = r'''
import subprocess
attack = """import os
fds = set(range(1, 64)) | {int(x) for x in os.listdir('/proc/self/fd')}
for fd in fds:
    try: os.write(fd, (os.environ['SYNTHETIC_SENTINEL'] + '\\n' + os.environ['SYNTHETIC_FORGED'] + '\\n').encode())
    except OSError: pass
"""
exec(attack)
subprocess.run([sys.executable, '-c', attack], close_fds=False, check=True)
'''
        source = fixture.DOCKER.replace(
            'if target and failure == phase:\n',
            'if os.environ.get("SYNTHETIC_ATTACK") == phase:\n    exec(' + repr(attack) + ')\n' +
            'if target and failure == phase:\n')
        source = source.replace('    tags.difference_update(args[3:])',
            '    if os.environ.get("SYNTHETIC_ATTACK") == "cleanup":\n        exec(' + repr(attack) + ')\n' +
            '    tags.difference_update(args[3:])')
        f.executable(f.bin / "docker", source)
        for phase in ("first-build", "first-id-inspect", "first-created-inspect", "second-build",
                      "second-id-inspect", "second-created-inspect", "cleanup"):
            with self.subTest(phase=phase):
                result = f.run_command(["bash", str(self.gate), "--docker"], SYNTHETIC_ATTACK=phase)
                self.assertNotIn(fixture.SENTINEL, result.stdout + result.stderr)
                self.assertNotIn(FORGED_EVENT, result.stdout + result.stderr)
                self.assertNotIn(str(f.root), result.stdout + result.stderr)
                records = self.records(result.stderr)
                self.assertIn(phase, [r["phase"] for r in records])
        for backend, original in (("jq", fixture.JQ), ("git", fixture.GIT)):
            with self.subTest(backend=backend):
                # Attack every invocation of this control backend, then preserve
                # the backend result; a capture may be corrupt, but stays private.
                f.executable(f.bin / "docker", fixture.DOCKER)
                real = f.bin / (backend + "-real")
                f.executable(real, original)
                wrapper = '#!/usr/bin/env python3\nimport os, sys\n' + attack
                wrapper += f'os.execv({str(real)!r}, [{str(real)!r}, *sys.argv[1:]])\n'
                f.executable(f.bin / backend, wrapper)
                result = f.run_command(["bash", str(self.gate), "--docker"])
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(fixture.SENTINEL, result.stdout + result.stderr)
                self.assertNotIn(FORGED_EVENT, result.stdout + result.stderr)
                self.records(result.stderr)
                f.executable(f.bin / backend, original)

    def test_timestamp_validation_descendants_have_only_private_descriptors(self):
        f = self.fixture
        self.write_gate()
        real_python = shutil.which("python3")
        source = '#!' + real_python + '\n' + 'import os, subprocess, sys\nif len(sys.argv) > 1 and sys.argv[1] == "-":\n    attack = """import os\nfds = set(range(1, 64)) | {int(x) for x in os.listdir(\'/proc/self/fd\')}\nfor fd in fds:\n    try: os.write(fd, (os.environ[\'SYNTHETIC_SENTINEL\'] + \'\\\\n\' + os.environ[\'SYNTHETIC_FORGED\'] + \'\\\\n\').encode())\n    except OSError: pass\n"""\n    exec(attack)\n    subprocess.run([sys.executable, \'-c\', attack], close_fds=False, check=True)\nos.execv(sys.executable, [sys.executable, *sys.argv[1:]])\n'
        f.executable(f.bin / "python3", source)
        result = f.run_command(["bash", str(self.gate), "--docker"])
        f.assert_public_gate(result, "image-reproducibility:runner:first-created-time")
        self.assertNotIn(FORGED_EVENT, result.stdout + result.stderr)
        self.assertEqual([r["phase"] for r in self.records(result.stderr)][-2:],
                         ["first-created-time", "cleanup"])

    def test_private_open_failure_is_generic_at_every_helper(self):
        f = self.fixture
        functions = ("has_next", "validate_manifest", "prepare_entry", "build_a", "id_a", "created_a",
                     "validate_a", "build_b", "id_b", "created_b", "validate_b", "cleanup_ab",
                     "compare_report", "finish", "cleanup_a", "bad_a", "bad_b")
        prefix = fixture.GATE_PREFIX.replace(
            '    { "$@" >>"$ci_images_log_path" 2>&1; } 2>/dev/null',
            '''    if [ "$1" = "$SYNTHETIC_OPEN_FAIL" ]; then
      ci_images_log_path="$log_directory/nonexistent-private-directory/raw.log"
    fi
    { "$@" >>"$ci_images_log_path" 2>&1; } 2>/dev/null''')
        self.assertNotEqual(prefix, fixture.GATE_PREFIX)
        self.write_gate(prefix=prefix)
        for helper in functions:
            with self.subTest(helper=helper):
                failure = ("first-created-time" if helper in ("cleanup_a", "bad_a") else
                           "second-created-time" if helper == "bad_b" else "")
                result = f.run_command(["bash", str(self.gate), "--docker"],
                    SYNTHETIC_OPEN_FAIL="ci_images_" + helper,
                    SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE=failure)
                f.assert_public_gate(result, "image-reproducibility:command-failed")
                self.assertNotIn("nonexistent-private-directory", result.stdout + result.stderr)

    def test_original_json_fields_control_live_attribution(self):
        f = self.fixture
        self.write_gate()
        for field in ("name", "context", "dockerfile"):
            for suffix in ("\n", "\x00"):
                with self.subTest(field=field, suffix=repr(suffix)):
                    row = fixture.entry("runner")
                    row[field] += suffix
                    f.manifest.write_text(json.dumps({"version": 1, "images": [row]}))
                    result = f.run_command(["bash", str(self.gate), "--docker"],
                        SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE="first-build")
                    f.assert_public_gate(result, "image-reproducibility:first-build")
                    self.assertEqual(self.records(result.stderr)[-1]["image"], "unattributed")
        unknown = "synthetic-private-name"
        f.write_manifest([fixture.entry("runner"), fixture.entry(unknown)])
        result = f.run_command(["bash", str(self.gate), "--docker"],
            SYNTHETIC_IMAGE=unknown, SYNTHETIC_PHASE="first-build")
        f.assert_public_gate(result, "image-reproducibility:first-build")
        self.assertEqual([(r["image"], r["phase"]) for r in self.records(result.stderr)][-2:],
                         [("unattributed", "entry-prepare"), ("unattributed", "first-build")])
        self.assertNotIn(unknown, result.stdout + result.stderr)

    def test_source_load_errors_and_open_failure_stay_private(self):
        f = self.fixture
        self.write_gate()
        source = f.root / "scripts/ci/check-images.sh"
        cases = ("printf '%s\\n' \"$SYNTHETIC_SENTINEL\" >&2\nreturn 1\n", "if (\n")
        for content in cases:
            with self.subTest(content=content):
                source.write_text(content)
                result = f.run_command(["bash", str(self.gate), "--docker"])
                f.assert_public_gate(result, "image-reproducibility:command-failed")
                self.assertNotIn(str(f.root), result.stdout + result.stderr)
                self.assertEqual(self.records(result.stderr), [])
        source.unlink()
        result = f.run_command(["bash", str(self.gate), "--docker"])
        f.assert_public_gate(result, "image-reproducibility:command-failed")
        source.write_text(fixture.CHECK_IMAGES.read_text())
        self.write_gate('mkdir "$log_directory/image-reproducibility.log"\nrun_image_stage || true\n')
        result = f.run_command(["bash", str(self.gate), "--docker"])
        f.assert_public_gate(result, "image-reproducibility:command-failed")
        self.assertEqual(self.records(result.stderr), [])

    def test_record_cap_exact_boundaries_and_invalid_labels(self):
        for count in (127, 128, 129, 260):
            with self.subTest(count=count):
                self.write_gate(f'''ci_images_records=0
for ((synthetic_i=0; synthetic_i<{count}; synthetic_i++)); do
  emit_image_phase 100 first-build
done
''')
                result = self.fixture.run_command(["bash", str(self.gate), "--docker"])
                records = self.records(result.stderr)
                self.assertEqual(len(records), min(count, 128))
                self.assertEqual(sum(r["state"] == "last-started" for r in records), min(count, 127))
                self.assertEqual(sum(r["state"] == "unavailable" for r in records), int(count >= 128))
        self.write_gate('''ci_images_records=0
emit_image_phase runner first-build
emit_image_phase 0100 first-build
emit_image_phase '100\n' first-build
emit_image_phase 100 'first-build\n'
emit_image_phase 100 '$SYNTHETIC_SENTINEL'
emit_image_phase 100 first-build
''')
        result = self.fixture.run_command(["bash", str(self.gate), "--docker"])
        self.assertEqual(len(self.records(result.stderr)), 1)

    def test_cap_never_limits_manifest_or_later_failure_decoder(self):
        f = self.fixture
        entries = [fixture.entry("synthetic-extra-" + str(i)) for i in range(15)]
        f.write_manifest([*entries, fixture.entry("runner")])
        self.write_gate()
        for failure in ("", "second-build"):
            with self.subTest(failure=failure):
                result = f.run_command(["bash", str(self.gate), "--docker"],
                    SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE=failure)
                f.assert_public_gate(result, "image-reproducibility:runner:second-build" if failure else None)
                records = self.records(result.stderr)
                self.assertEqual(len(records), 128)
                self.assertEqual(records[-1]["state"], "unavailable")
                self.assertEqual(len(f.docker_calls()), 15 * 7 + (4 if failure else 7))

    def test_complete_gate_separate_budgets_and_cap_cleanup(self):
        f = self.fixture
        f.write_manifest([fixture.entry("synthetic-extra-" + str(i)) for i in range(15)])
        result = f.run_command(["bash", str(self.gate), "--docker"])
        f.assert_public_gate(result, None)
        self.assertEqual(len(self.records(result.stderr)), 128)
        self.assertEqual(f.state.read_text(), "")
        self.assertEqual(len(f.downstream.read_text().splitlines()), 2)

    def test_broken_public_stderr_noninterference(self):
        f = self.fixture
        self.write_gate()
        for failure in ("", "second-build"):
            for sink in ("full", "pipe"):
                with self.subTest(failure=failure, sink=sink):
                    self.reset_state()
                    if sink == "pipe":
                        read_fd, write_fd = os.pipe()
                        os.close(read_fd)
                    else:
                        write_fd = os.open("/dev/full", os.O_WRONLY)
                    try:
                        # Omit legacy final diagnostic writes, whose behavior is
                        # unchanged. Exercise the new emitter and exact stage return.
                        self.write_gate('run_image_stage; exit "$?"\n')
                        result = subprocess.run(["bash", str(self.gate), "--docker"], cwd=f.root,
                            env={**f.environment, "SYNTHETIC_IMAGE": "runner", "SYNTHETIC_PHASE": failure},
                            stdout=subprocess.PIPE, stderr=write_fd, timeout=15)
                    finally:
                        os.close(write_fd)
                    self.assertEqual(result.returncode, 1 if failure else 0)
                    self.assertEqual(len(f.docker_calls()), 4 if failure else 7)

    def test_source_guard_is_silent_and_does_not_mutate_caller_state(self):
        source = str(fixture.CHECK_IMAGES)
        script = '''set +e +u
set +o pipefail
umask 027
trap ':' USR1
manifest=synthetic-manifest
name=synthetic-name
i=23
ci_images_manifest=synthetic-private-manifest
ci_images_i=19
before=$(set +o; umask; trap -p; pwd; declare -p manifest name i ci_images_manifest ci_images_i)
source "$1"
after=$(set +o; umask; trap -p; pwd; declare -p manifest name i ci_images_manifest ci_images_i)
[ "$before" = "$after" ] || exit 91
'''
        result = self.fixture.run_command(["bash", "-c", script, "synthetic", source])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertEqual(self.fixture.docker_calls(), [])

    def test_conditional_driver_restores_prefixed_and_unprefixed_caller_state(self):
        script = '''set -euo pipefail
source "$1"
manifest=synthetic-manifest
name=synthetic-name
i=23
ci_images_manifest=synthetic-private-manifest
ci_images_i=19
before=$(declare -p manifest name i ci_images_manifest ci_images_i)
if ci_images_run; then status=0; else status=$?; fi
after=$(declare -p manifest name i ci_images_manifest ci_images_i)
[ "$before" = "$after" ] || exit 91
exit "$status"
'''
        f = self.fixture
        for failure in ("", *fixture.PHASES):
            with self.subTest(failure=failure):
                result = f.run_command(["bash", "-c", script, "synthetic", str(fixture.CHECK_IMAGES)],
                                       SYNTHETIC_IMAGE="runner", SYNTHETIC_PHASE=failure)
                expected = 100 + fixture.PHASES.index(failure) if failure else 0
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_malformed_count_stays_private_and_empty_spellings_keep_early_exit(self):
        f = self.fixture
        jq = fixture.JQ.replace('count=0\n', 'if [ "$2" = \'.images | length\' ]; then\n    printf \'%s\\n\' "$SYNTHETIC_COUNT"\n    exit 0\nfi\ncount=0\n')
        f.executable(f.bin / "jq", jq)
        for count in ("00", "+0", " 0", "0 "):
            with self.subTest(count=count):
                result = f.run_wrapper(SYNTHETIC_COUNT=count)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout.splitlines(),
                                 ["check-images: images/manifest.json registers no images; nothing to build"])
                self.assertEqual(f.docker_calls(), [])
        self.write_gate()
        result = f.run_command(["bash", str(self.gate), "--docker"], SYNTHETIC_COUNT=fixture.SENTINEL)
        f.assert_public_gate(result, "image-reproducibility:command-failed")
        self.assertEqual(f.docker_calls(), [])

    def test_raw_report_write_failures_are_generic(self):
        f = self.fixture
        for failure, sink in (("", "stdout"), ("first-created-time", "stderr"),
                              ("second-created-time", "stderr"), ("image-id-mismatch", "stderr")):
            with self.subTest(failure=failure, sink=sink):
                self.reset_state()
                with open("/dev/full", "w") as full:
                    result = subprocess.run(["bash", str(fixture.CHECK_IMAGES)], cwd=f.root,
                        env={**f.environment, "SYNTHETIC_IMAGE": "runner", "SYNTHETIC_PHASE": failure},
                        stdout=full if sink == "stdout" else subprocess.PIPE,
                        stderr=full if sink == "stderr" else subprocess.PIPE, timeout=15)
                self.assertEqual(result.returncode, 1)
        f.write_manifest([])
        with open("/dev/full", "w") as full:
            result = subprocess.run(["bash", str(fixture.CHECK_IMAGES)], cwd=f.root,
                env=f.environment, stdout=full, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(result.returncode, 1)
        f.write_manifest([fixture.entry("runner")])
        # Directly inject only final-report write failure after all normal work.
        script = '''source "$1"
ci_images_private() {
  if [ "$1" = ci_images_finish ]; then "$@" >/dev/full; else "$@"; fi
}
if ci_images_run; then exit 0; else exit "$?"; fi
'''
        result = f.run_command(["bash", "-c", script, "synthetic", str(fixture.CHECK_IMAGES)])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(f.docker_calls()), 7)


if __name__ == "__main__":
    unittest.main()
