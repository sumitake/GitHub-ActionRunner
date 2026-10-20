"""Producer diagnostic privacy, authority and terminal admission checks."""
# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _bounded_qualification as q
import _metadata_probe as probe
spec = importlib.util.spec_from_file_location('metadata_host', ROOT / 'scripts/release/qualify-runtime.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class MetadataProbe(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        scripts = self.root / 'source/scripts'
        scripts.mkdir(parents=True)
        for name in ('sanitize_public.py', '_sanitize_normalize.py', 'public_dependency_metadata.py'):
            shutil.copyfile(ROOT / 'scripts' / name, scripts / name)
        self.scanner = q.module(ROOT, 'sanitize_public.py')

    def test_only_explicit_owner_diagnostic_inputs_are_admitted(self):
        environment = dict(GITHUB_EVENT_NAME='workflow_dispatch', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux', RUNNER_ARCH='X64', GITHUB_REPOSITORY='synthetic/example', GITHUB_ACTOR='synthetic', GITHUB_REF='refs/heads/codex/runner-dotnet-servicing', GITHUB_SHA='a' * 40, GITHUB_RUN_ID='12345', GITHUB_RUN_ATTEMPT='1')
        event = {'repository': {'private': False, 'full_name': 'synthetic/example', 'owner': {'login': 'synthetic'}}, 'inputs': {'bounded_qualification': 'false', 'metadata_probe': 'true', 'expected_commit': 'a' * 40, 'expected_tree': 'b' * 40, 'carry_in_bytes': str(q.RESERVE)}}
        def command(args, **_kwargs):
            if args[-2:] == ['--format=%ct', 'HEAD']: return '123'
            if args[-1] == 'HEAD': return 'a' * 40
            if args[-1] == 'HEAD^{tree}': return 'b' * 40
            return ''
        with mock.patch.object(host, 'command', side_effect=command):
            result = host.admission(ROOT, event, environment, metadata_probe=True)
            self.assertTrue(result['metadata_probe'])
            for key, value in [('bounded_qualification', 'true'), ('metadata_probe', 'false'), ('actions_read', 'true'), ('carry_in_bytes', '0')]:
                bad = copy.deepcopy(event)
                bad['inputs'][key] = value
                with self.subTest(key=key), self.assertRaises(q.Stop):
                    host.admission(ROOT, bad, environment, metadata_probe=True)
            for changes in [{'GITHUB_ACTOR': 'other'}, {'GITHUB_RUN_ATTEMPT': '2'}, {'GITHUB_EVENT_NAME': 'push'}, {'GITHUB_SHA': 'c' * 40}]:
                with self.subTest(changes=changes), self.assertRaises(q.Stop):
                    host.admission(ROOT, event, {**environment, **changes}, metadata_probe=True)
            with self.assertRaises(q.Stop):
                host.admission(ROOT, event, environment)

    def test_native_values_and_unknown_field_names_never_leave_summary(self):
        private = 'private-person@private.internal'
        key = 'PrivateOwnerName'
        data = {'Metadata': {'Author': private}, key: '10.23.45.67', 'ReportID': '87654321-4321-4123-8123-cba987654321'}
        path = self.root / 'native.json'
        raw = json.dumps(data).encode()
        path.write_bytes(raw)
        summary, parsed = probe.describe(path, self.scanner)
        encoded = json.dumps(summary)
        self.assertNotIn(private, encoded)
        self.assertNotIn(key, encoded)
        self.assertNotIn('10.23.45.67', encoded)
        self.assertNotIn(data['ReportID'], encoded)
        self.assertEqual(parsed, data)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(summary['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertTrue({'MAIL001', 'IP001', 'DEPLOYID002'} <= {rule for row in summary['fields'] for rule in row['rules']})
        self.assertEqual(self.scanner.scan_generated_bytes(json.dumps(summary).encode(), 'metadata-probe/summary.json', False, []), [])

    def test_native_duplicate_nonfinite_aliased_and_oversized_inputs_fail(self):
        path = self.root / 'native.json'
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(q.Stop): probe.read_json(path)
        path.write_bytes(b'{}')
        alias = self.root / 'alias'
        os.link(path, alias)
        with self.assertRaises(q.Stop): probe.read_json(path)
        alias.unlink()
        path.write_bytes(b' ' * (probe.NATIVE_LIMIT + 1))
        with self.assertRaises(q.Stop): probe.read_json(path)

    def test_public_summary_keeps_sensitive_fields_blocked(self):
        for data in ({'text': 'person@private.internal'}, {'text': '/home/private-person/work'}, {'text': '10.23.45.67'}, {'text': ''.join(('-----BEGIN ', 'RSA PRIVATE ', 'KEY-----'))}):
            with self.subTest(data=data), self.assertRaises(q.Stop): probe.safe_summary(self.root, data)
        with self.assertRaises(q.Stop): probe.safe_summary(self.root, {'text': 'a' * probe.LIMIT})

    def prepare_upload(self):
        (self.root / 'evidence').mkdir()
        (self.root / 'public').mkdir()
        q.write(self.root / 'inputs.json', {'metadata_probe': True, 'commit': 'a' * 40, 'tree': 'b' * 40})
        q.write(self.root / 'evidence/terminal.json', {'workers_joined': True, 'scope_exit_code': 0, 'budget_or_execution_error': None})
        q.write(self.root / 'public/metadata-probe.json', {'diagnostic_status': 'pass', 'source_commit': 'a' * 40, 'source_tree': 'b' * 40, 'release_admitted': False})

    def test_terminal_admission_publishes_only_structural_result(self):
        self.prepare_upload()
        raw = b'private-person@private.internal'
        (self.root / 'evidence/native-report.json').write_bytes(raw)
        probe.admit_upload(self.root)
        self.assertEqual({path.name for path in (self.root / 'public').iterdir()}, {'metadata-probe.json', 'evidence-inventory.json'})
        manifest = json.loads((self.root / 'public/evidence-inventory.json').read_text())
        self.assertFalse(manifest['artifact_qualification_admitted'])
        self.assertFalse(manifest['release_admitted'])
        self.assertEqual((self.root / 'evidence/native-report.json').read_bytes(), raw)
        self.assertEqual((self.root / 'evidence').stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / 'inputs.json').stat().st_mode & 0o777, 0o600)
        probe.check_upload(self.root / 'public')
        (self.root / 'public/metadata-probe.json').write_bytes(b'{}')
        with self.assertRaises(q.Stop): probe.check_upload(self.root / 'public')
        self.assertLess(sum(path.stat().st_size for path in (self.root / 'public').iterdir()), probe.LIMIT)

    def test_unjoined_failed_drifted_or_extra_output_cannot_be_uploaded(self):
        self.prepare_upload()
        terminal = self.root / 'evidence/terminal.json'
        good = json.loads(terminal.read_text())
        for field, value in [('workers_joined', False), ('scope_exit_code', 1), ('budget_or_execution_error', 'failure')]:
            q.write(terminal, {**good, field: value})
            with self.subTest(field=field), self.assertRaises(q.Stop): probe.admit_upload(self.root)
        q.write(terminal, good)
        q.write(self.root / 'inputs.json', {'metadata_probe': True, 'commit': 'c' * 40, 'tree': 'b' * 40})
        with self.assertRaises(q.Stop): probe.admit_upload(self.root)
        q.write(self.root / 'inputs.json', {'metadata_probe': True, 'commit': 'a' * 40, 'tree': 'b' * 40})
        (self.root / 'public/native.json').write_bytes(b'{}')
        with self.assertRaises(q.Stop): probe.admit_upload(self.root)

    def test_synthetic_layout_is_verified_by_unchanged_graph_checker(self):
        path = self.root / 'layout'
        digest = probe.synthetic_layout(path)
        self.assertEqual(q.graph(path, q.release_functions(ROOT))['manifest_digest'], digest)

    def test_workflow_probe_has_only_read_permission_and_short_deadline(self):
        checker = q.module(ROOT, 'check_workflow_policy.py')
        workflow = checker.parse_workflow((ROOT / '.github/workflows/ci.yml').read_text())
        job = workflow['jobs']['metadata-probe']
        self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertEqual(job['timeout-minutes'], '15')
        self.assertIn('inputs.metadata_probe && !inputs.bounded_qualification', job['if'])
        upload = job['steps'][-1]['with']
        self.assertEqual(upload['retention-days'], '1')
        self.assertIn('metadata-probe/public', upload['path'])
        for name, other in workflow['jobs'].items():
            if name not in ('metadata-probe', 'bounded-qualification'):
                self.assertIn('!inputs.metadata_probe', other['if'])


if __name__ == '__main__':
    unittest.main()
