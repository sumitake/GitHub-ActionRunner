# SPDX-License-Identifier: MPL-2.0
"""Stock-image boot: runner install, stdlib SSM, self-update relaunch, template inputs."""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials as BotoCredentials

from overflow_watcher import guest_runner, guest_ssm, supervisor
from overflow_watcher.guest_bootstrap import render_user_data
from overflow_watcher.types import REPORT_AFTER_SECONDS

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
PARAM = "/overflow-watcher/jit/" + ("ef" * 32)


def _tarball(path: Path, *, listener: bool = True) -> str:
    """Write a runner-shaped tarball and return its sha256."""
    with tarfile.open(path, "w:gz") as tar:
        files = {"run.sh": b"#!/bin/sh\n"}
        if listener:
            files["bin/Runner.Listener"] = b"#!/bin/sh\nexit 0\n"
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RunnerInstallTests(unittest.TestCase):
    def test_guest_runner_pin_matches_release_manifest(self) -> None:
        manifest = json.loads((REPO_ROOT / "release" / "manifest.json").read_text(encoding="utf-8"))
        release = manifest["runtime"]["runner_release"]
        self.assertEqual("v" + guest_runner.RUNNER_VERSION, release["version"])
        self.assertEqual("sha256:" + guest_runner.RUNNER_SHA256, release["linux_x64_asset_digest"])
        self.assertTrue(guest_runner.RUNNER_URL.endswith("/" + release["linux_x64_asset_name"]))

    def test_tarball_sha_mismatch_fails_boot_and_installs_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "runner.tar.gz"
            _tarball(archive)
            root = Path(tmp) / "opt" / "actions-runner"
            env = {"OVERFLOW_RUNNER_ROOT": str(root), "OVERFLOW_RUNNER_URL": archive.as_uri()}
            with patch.dict(os.environ, env):
                code = guest_runner.main(["guest_runner", "install"])
            self.assertEqual(code, 1)
            self.assertFalse(root.exists())
            self.assertEqual([p.name for p in root.parent.iterdir()], [])

    def test_tarball_without_listener_fails_and_installs_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "runner.tar.gz"
            digest = _tarball(archive, listener=False)
            root = Path(tmp) / "opt" / "actions-runner"
            with self.assertRaisesRegex(guest_runner.InstallError, "listener missing"):
                guest_runner.install(str(root), archive.as_uri(), digest)
            self.assertFalse(root.exists())
            self.assertEqual([p.name for p in root.parent.iterdir()], [])

    def test_verified_tarball_installs_executable_listener(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "runner.tar.gz"
            digest = _tarball(archive)
            root = Path(tmp) / "opt" / "actions-runner"
            guest_runner.install(str(root), archive.as_uri(), digest)
            self.assertTrue(os.access(root / "bin" / "Runner.Listener", os.X_OK))
            with self.assertRaisesRegex(guest_runner.InstallError, "already exists"):
                guest_runner.install(str(root), archive.as_uri(), digest)


class UserDataTests(unittest.TestCase):
    def test_user_data_has_no_aws_cli_and_installs_runner_before_reading_secret(self) -> None:
        script = render_user_data(PARAM)
        self.assertNotIn("aws ssm", script)
        self.assertNotIn("/opt/actions-runner/bin", script)
        self.assertLess(script.index("guest_runner install"), script.index("guest_ssm get"))
        self.assertIn('export HOME="${HOME:-/root}" RUNNER_ALLOW_RUNASROOT=1', script)
        self.assertIn("if ! command -v git >/dev/null; then", script)
        self.assertLess(script.index("command -v git"), script.index("guest_ssm get"))
        self.assertLessEqual(len(script.encode("utf-8")), 16384)

    def test_runner_install_failure_parks_without_reading_secret(self) -> None:
        """Run the rendered user data with a bad tarball; only python3 is wrapped."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / "runner.tar.gz"
            _tarball(archive)
            log = base / "calls.log"
            stub = base / "bin"
            stub.mkdir()
            wrapper = stub / "python3"
            wrapper.write_text(
                "#!/bin/sh\n"
                'case "$2" in\n'
                f'  overflow_watcher.supervisor) echo "supervisor config=${{RUNNER_CONFIG-unset}}" >>"{log}"; exit 0 ;;\n'
                f'  overflow_watcher.guest_ssm) echo "ssm $3" >>"{log}"; exit 0 ;;\n'
                "esac\n"
                f'exec "{sys.executable}" "$@"\n',
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            user_data = base / "user-data.sh"
            user_data.write_text(render_user_data(PARAM), encoding="utf-8")
            runner_root = base / "opt" / "actions-runner"
            env = {
                "PATH": f"{stub}:{os.environ['PATH']}",
                "HOME": tmp,
                "OVERFLOW_INSTALL_ROOT": str(base / "opt" / "overflow-watcher"),
                "OVERFLOW_RUNNER_ROOT": str(runner_root),
                "OVERFLOW_RUNNER_URL": archive.as_uri(),
                "RUNNER_CONFIG": "/should/be/unset",
            }
            proc = subprocess.run(["sh", str(user_data)], cwd=tmp, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("runner sha256 mismatch", proc.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["supervisor config=unset"])
            self.assertFalse(runner_root.exists())


class GuestSsmTests(unittest.TestCase):
    CREDS = guest_ssm.Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "session-token-example")
    WHEN = datetime.datetime(2026, 11, 11, 13, 45, 7, tzinfo=datetime.timezone.utc)

    def test_sigv4_signature_matches_botocore(self) -> None:
        body = json.dumps({"Name": PARAM, "WithDecryption": True}).encode("utf-8")
        ours = guest_ssm.signed_request("GetParameter", body, self.CREDS, "us-west-2", self.WHEN)
        theirs = AWSRequest(
            method="POST",
            url="https://ssm.us-west-2.amazonaws.com/",
            data=body,
            headers={"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "AmazonSSM.GetParameter"},
        )
        theirs.context["timestamp"] = self.WHEN.strftime("%Y%m%dT%H%M%SZ")
        auth = SigV4Auth(BotoCredentials("AKIDEXAMPLE", self.CREDS.secret_key, self.CREDS.token), "ssm", "us-west-2")
        auth._modify_request_before_signing(theirs)
        canonical = auth.canonical_request(theirs)
        expected = auth.signature(auth.string_to_sign(theirs, canonical), theirs)
        header = ours.get_header("Authorization")
        self.assertTrue(header.endswith("Signature=" + expected), header)
        self.assertIn("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target", header)
        self.assertEqual(ours.full_url, "https://ssm.us-west-2.amazonaws.com/")

    def test_get_writes_value_only_on_success(self) -> None:
        sent = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def opener(request, timeout):
            sent.append(request)
            return Response(json.dumps({"Parameter": {"Value": "jit-value"}}).encode())

        out = io.StringIO()
        with patch.object(guest_ssm, "instance_identity", lambda: (self.CREDS, "us-west-2")), patch.object(
            guest_ssm.urllib.request, "urlopen", opener
        ), patch("sys.stdout", out):
            self.assertEqual(guest_ssm.main(["guest_ssm", "get", PARAM]), 0)
        self.assertEqual(out.getvalue(), "jit-value")
        self.assertEqual(sent[0].get_header("X-amz-target"), "AmazonSSM.GetParameter")
        self.assertEqual(json.loads(sent[0].data), {"Name": PARAM, "WithDecryption": True})

    def test_get_failure_fails_closed_and_prints_nothing(self) -> None:
        def boom():
            raise OSError("imds unreachable")

        out, err = io.StringIO(), io.StringIO()
        with patch.object(guest_ssm, "instance_identity", boom), patch("sys.stdout", out), patch("sys.stderr", err):
            self.assertEqual(guest_ssm.main(["guest_ssm", "get", PARAM]), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn("imds unreachable", err.getvalue())


class _Stop(Exception):
    pass


class SelfUpdateRelaunchTests(unittest.TestCase):
    """supervisor.main with a fake listener; the clock advances inside sleep."""

    def _run(self, listener_body: str, max_clock: int) -> tuple[list[str], str, Path]:
        tmp = tempfile.mkdtemp()
        base = Path(tmp)
        config = base / "jitconfig"
        config.write_text("x", encoding="utf-8")
        listener = base / "listener.sh"
        listener.write_text("#!/bin/sh\n" + listener_body, encoding="utf-8")
        listener.chmod(0o755)
        clock = [1_000_000.0]
        real_sleep = supervisor.time.sleep
        shutdowns: list[str] = []

        def fake_sleep(seconds: float) -> None:
            clock[0] += seconds
            if clock[0] - 1_000_000.0 > max_clock:
                raise _Stop()
            real_sleep(0.02)

        env = {"RUNNER_CONFIG": str(config), "RUNNER_COMMAND": f"{listener} {base}", "OVERFLOW_RUNNER_ROOT": tmp}
        out = io.StringIO()
        with patch.dict(os.environ, env), patch.object(supervisor.time, "sleep", fake_sleep), patch.object(
            supervisor.time, "time", lambda: clock[0]
        ), patch.object(supervisor, "_shutdown", lambda: shutdowns.append("shutdown")), patch("sys.stdout", out):
            try:
                supervisor.main()
            except _Stop:
                pass
        return shutdowns, out.getvalue(), base

    def test_update_exit_relaunches_then_completes_normally(self) -> None:
        body = (
            'n=$(cat "$1/count" 2>/dev/null || echo 0); n=$((n+1)); echo $n >"$1/count"\n'
            'if [ "$n" = 1 ]; then touch "$1/update.finished"; exit 4; fi\n'
            "sleep 0.3 & wait\n"
            "exit 0\n"
        )
        shutdowns, _, base = self._run(body, 600)
        self.assertEqual(shutdowns, ["shutdown"])
        self.assertEqual((base / "count").read_text().strip(), "2")
        self.assertFalse((base / "update.finished").exists())

    def test_update_exit_without_flag_does_not_relaunch_or_shut_down(self) -> None:
        body = 'n=$(cat "$1/count" 2>/dev/null || echo 0); n=$((n+1)); echo $n >"$1/count"\nexit 4\n'
        shutdowns, out, base = self._run(body, REPORT_AFTER_SECONDS + 300)
        self.assertEqual(shutdowns, [])
        self.assertEqual((base / "count").read_text().strip(), "1")
        self.assertIn("overflow-supervisor report", out)

    def test_endless_update_exits_are_bounded_and_never_shut_down(self) -> None:
        body = (
            'n=$(cat "$1/count" 2>/dev/null || echo 0); n=$((n+1)); echo $n >"$1/count"\n'
            'touch "$1/update.finished"; exit 4\n'
        )
        shutdowns, out, base = self._run(body, REPORT_AFTER_SECONDS + 120)
        self.assertEqual(shutdowns, [])
        self.assertEqual((base / "count").read_text().strip(), str(1 + supervisor.MAX_UPDATE_RELAUNCHES))
        self.assertIn("overflow-supervisor report", out)


class TemplateInputTests(unittest.TestCase):
    def test_ami_resolves_from_public_ubuntu_parameter_and_root_is_sda1(self) -> None:
        text = (ROOT / "template.yaml").read_text(encoding="utf-8")
        block = text[text.index("  AmiId:\n") : text.index("  SubnetId:\n")]
        self.assertIn("Type: AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>", block)
        self.assertIn(
            "Default: /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id", block
        )
        self.assertIn("- DeviceName: /dev/sda1", text)
        self.assertNotIn("/dev/xvda", text)


if __name__ == "__main__":
    unittest.main()
