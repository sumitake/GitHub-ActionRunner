"""The final-image probe must use the production metadata-only contract."""
# SPDX-License-Identifier: MPL-2.0
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock
from tests.repository.test_runtime_snapshot_binding import rehearsal


class FinalRunnerSmoke(unittest.TestCase):
    def setUp(self):
        self.ns = rehearsal()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.log = self.root / 'private.log'

    def invoke(self, output=b'1.2.3\n', error=b'', code=0):
        result = subprocess.CompletedProcess([], code, output, error)
        with mock.patch.object(self.ns['subprocess'], 'run', return_value=result) as run:
            self.ns['verify_final_runner_smoke'](
                'synthetic-image', '1.2.3', 'synthetic-probe',
                cwd=self.root, env={}, log=self.log,
            )
        return run.call_args

    def test_probe_has_fixed_uid_private_runtime_and_no_runner_state_mount(self):
        call = self.invoke()
        self.assertEqual(call.args[0], [
            'docker', 'run', '--name', 'synthetic-probe',
            '--network', 'none', '--read-only', '--user', '65532:65532',
            '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700',
            '--entrypoint', '/opt/actions-runner/bin/Runner.Listener',
            'synthetic-image', '--version',
        ])
        self.assertEqual(call.kwargs['timeout'], 120)
        self.assertEqual(call.kwargs['stdin'], subprocess.DEVNULL)

    def test_nonexact_version_warning_or_exit_cannot_pass(self):
        for output, error, code in [
            (b'1.2.3', b'', 0), (b'1.2.3\n\n', b'', 0),
            (b'wrong\n', b'', 0), (b'1.2.3\n', b'warning', 0),
            (b'1.2.3\n', b'', 1),
        ]:
            with self.subTest(output=output, error=error, code=code):
                with self.assertRaises(self.ns['RehearsalError']):
                    self.invoke(output, error, code)

    def test_final_image_probe_is_wired_before_root_metadata_audit(self):
        source = (pathlib.Path(__file__).resolve().parents[2] / 'scripts/release/rehearse-runtime.sh').read_text()
        start = source.index('expected_version = runner["version"][1:]')
        body = source[start:source.index('inspection_container = None', start)]
        self.assertLess(body.index('verify_final_runner_smoke('), body.index('"0:0"'))
        self.assertNotIn('test "$(/opt/actions-runner/bin/Runner.Listener --version)', body)
