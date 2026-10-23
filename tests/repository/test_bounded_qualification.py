"""Manual qualification authority, resource and raw-layout regression checks."""
# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _bounded_qualification as q
spec = importlib.util.spec_from_file_location('bounded_host', ROOT / 'scripts/release/qualify-runtime.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class BoundedQualification(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.environment = dict(GITHUB_EVENT_NAME='workflow_dispatch', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux', RUNNER_ARCH='X64', GITHUB_REPOSITORY='synthetic/example', GITHUB_ACTOR='synthetic', GITHUB_REF='refs/heads/codex/runner-dotnet-servicing', GITHUB_SHA='a' * 40, GITHUB_RUN_ID='12345', GITHUB_RUN_ATTEMPT='1')
        self.event = {'repository': {'private': False, 'full_name': 'synthetic/example', 'owner': {'login': 'synthetic'}}, 'inputs': {'bounded_qualification': 'true', 'expected_commit': 'a' * 40, 'expected_tree': 'b' * 40, 'carry_in_bytes': str(q.RESERVE)}}

    def command(self, args, **_kwargs):
        if args[-2:] == ['--format=%ct', 'HEAD']: return '123'
        if args[-1] == 'HEAD': return 'a' * 40
        if args[-1] == 'HEAD^{tree}': return 'b' * 40
        return ''

    def admit(self, event=None, environment=None):
        with mock.patch.object(host, 'command', side_effect=self.command):
            return host.admission(self.root, event or self.event, environment or self.environment)

    def test_legitimate_owner_dispatch_binds_source_and_carry_in(self):
        value = self.admit()
        self.assertEqual(value['commit'], 'a' * 40)
        self.assertEqual(value['tree'], 'b' * 40)
        self.assertEqual(value['carry_in_bytes'], q.RESERVE)
        self.assertFalse(value['live_operations'])

    def test_fork_ordinary_event_actor_ref_and_identity_drift_are_refused(self):
        for key, value in [('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_ACTOR', 'untrusted'), ('RUNNER_ENVIRONMENT', 'self-hosted'), ('GITHUB_REF', 'refs/heads/main'), ('GITHUB_SHA', 'c' * 40)]:
            with self.subTest(key=key), self.assertRaises(q.Stop):
                self.admit(environment={**self.environment, key: value})
        for key, value in [('private', True), ('full_name', 'other/example')]:
            event = copy.deepcopy(self.event)
            event['repository'][key] = value
            with self.subTest(key=key), self.assertRaises(q.Stop): self.admit(event=event)

    def test_closed_inputs_and_budget_cannot_be_relaxed(self):
        for key, value in [('extra', 'true'), ('carry_in_bytes', '0'), ('carry_in_bytes', str(q.SOFT)), ('bounded_qualification', 'false'), ('expected_commit', '../other')]:
            event = copy.deepcopy(self.event)
            event['inputs'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(q.Stop): self.admit(event=event)

    def test_kernel_and_storage_guards_fail_closed(self):
        row = {'kernel': {'cpu.max': '400000 100000', 'memory.max': str(q.MEMORY), 'memory.swap.max': '0', 'pids.max': '1024', 'memory.events': 'oom 0\noom_kill 0'}, 'accounted_bytes': q.RESERVE, 'writable_root_bytes': 0, 'free_bytes': 20 * q.GIB, 'free_inodes': 800000, 'available_memory_bytes': 12 * q.GIB}
        q.checks(row)
        for key, value in [('accounted_bytes', q.SOFT), ('writable_root_bytes', 2 * q.GIB), ('free_bytes', 13 * q.GIB - 1), ('free_inodes', 499999), ('available_memory_bytes', 4 * q.GIB - 1)]:
            with self.subTest(key=key), self.assertRaises(q.Stop): q.checks({**row, key: value})
        for key, value in [('cpu.max', 'max 100000'), ('memory.max', str(7 * q.GIB)), ('memory.swap.max', '1024'), ('pids.max', 'max'), ('memory.events', 'oom 1\noom_kill 0')]:
            with self.subTest(key=key), self.assertRaises(q.Stop): q.checks({**row, 'kernel': {**row['kernel'], key: value}})

    def test_approved_disk_budget_retains_reserve_and_enforces_new_boundary(self):
        self.assertEqual(q.SOFT, 10737418240)
        self.assertEqual(q.HARD, 12348030976)
        self.assertEqual(q.HARD - q.SOFT, 1610612736)
        self.assertEqual(q.RESERVE, 3758096384)
        self.assertEqual(q.MEMORY, 6174015488)
        self.assertEqual(q.ARTIFACT_LIMIT, q.GIB)
        row = {'kernel': {'cpu.max': '400000 100000', 'memory.max': str(q.MEMORY), 'memory.swap.max': '0', 'pids.max': '1024', 'memory.events': 'oom 0\noom_kill 0'}, 'accounted_bytes': q.SOFT - 1, 'writable_root_bytes': 2 * q.GIB - 1, 'free_bytes': 13 * q.GIB, 'free_inodes': 500000, 'available_memory_bytes': 4 * q.GIB}
        q.checks(row)
        with self.assertRaises(q.Stop):
            q.checks({**row, 'accounted_bytes': q.SOFT})

    def layout(self):
        layout = self.root / 'layout'
        blobs = layout / 'blobs/sha256'
        blobs.mkdir(parents=True)
        def blob(raw):
            digest = hashlib.sha256(raw).hexdigest()
            (blobs / digest).write_bytes(raw)
            return {'mediaType': 'synthetic', 'digest': 'sha256:' + digest, 'size': len(raw)}
        layer = blob(b'synthetic raw layer')
        config = blob(json.dumps({'os': 'linux', 'architecture': 'amd64', 'config': {'User': '65532:65532'}}).encode())
        manifest = blob(json.dumps({'schemaVersion': 2, 'config': config, 'layers': [layer]}).encode())
        manifest['platform'] = {'architecture': 'amd64', 'os': 'linux'}
        (layout / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}))
        (layout / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
        return layout

    def test_raw_layout_uses_existing_tar_graph_verifier_and_exact_bytes(self):
        layout = self.layout()
        functions = q.release_functions(ROOT)
        archive = self.root / 'image.tar'
        with tarfile.open(archive, 'w') as stream:
            for path in sorted(layout.rglob('*')):
                stream.add(path, arcname=path.relative_to(layout).as_posix(), recursive=False)
        self.assertEqual(q.graph(layout, functions), functions['oci_graph'](archive))
        before = q.inventory(layout)
        self.assertEqual(before, q.inventory(layout))
        target = next((layout / 'blobs/sha256').iterdir())
        target.write_bytes(b'changed')
        with self.assertRaises(functions['RehearsalError']): q.graph(layout, functions)

    def test_layout_alias_extra_file_and_missing_closure_are_refused(self):
        layout = self.layout()
        outside = self.root / 'outside'
        outside.write_bytes(b'synthetic')
        (layout / 'extra').symlink_to(outside)
        with self.assertRaises(q.Stop): q.LayoutArchive(layout)
        (layout / 'extra').unlink()
        (layout / 'extra').write_bytes(b'unknown')
        with self.assertRaises(q.Stop): q.LayoutArchive(layout)
        (layout / 'extra').unlink()
        target = next((layout / 'blobs/sha256').iterdir())
        os.link(target, self.root / 'alias')
        with self.assertRaises(q.Stop): q.LayoutArchive(layout)

    def test_only_credential_free_transport_reaches_children(self):
        with mock.patch.dict(os.environ, {'GH_TOKEN': 'synthetic-secret', 'ACTIONS_RUNTIME_TOKEN': 'synthetic-secret'}, clear=True):
            value = host.safe_environment(self.root, self.root / 'go')
        self.assertNotIn('GH_TOKEN', value)
        self.assertNotIn('ACTIONS_RUNTIME_TOKEN', value)
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'http://synthetic:secret@proxy.invalid'}, clear=True):
            with self.assertRaises(q.Stop): host.safe_environment(self.root, self.root / 'go')

    def test_workflow_never_runs_qualification_on_push_or_pr(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.bounded_qualification", text)
        self.assertEqual(text.count("if: github.event_name != 'workflow_dispatch' || (!inputs.bounded_qualification && !inputs.metadata_probe && !inputs.payload_reconstruction)"), 5)
        self.assertIn('retention-days: 1', text)
        self.assertIn('timeout-minutes: 90', text)
        section = text.split('  bounded-qualification:', 1)[1]
        self.assertNotIn('id-token:', section)
        self.assertNotIn('packages:', section)
        self.assertNotIn('secrets.', section)
        self.assertIn('ref: ${{ github.sha }}', section)

    def test_raw_outputs_survive_failed_text_gate_without_admission(self):
        (self.root / 'source').symlink_to(ROOT, target_is_directory=True)
        evidence = self.root / 'evidence'
        (evidence / 'artifacts/images-A').mkdir(parents=True)
        (evidence / 'artifacts/images-B').mkdir()
        for phase in ('A', 'B'):
            (evidence / ('artifacts/images-' + phase) / 'blob').write_bytes(b'raw independent synthetic OCI export')
        (evidence / 'RESULT.json').write_text('{"status":"pass"}')
        (evidence / 'unsafe.log').write_text('unpublishable path /home/synthetic/private')
        with self.assertRaises(q.Stop): host.export_evidence(self.root)
        public = self.root / 'public'
        self.assertEqual((public / 'artifacts/images-A/blob').read_bytes(), (public / 'artifacts/images-B/blob').read_bytes())
        self.assertEqual(json.loads((public / 'RESULT.json').read_text())['status'], 'fail')
        manifest = json.loads((public / 'evidence-inventory.json').read_text())
        self.assertFalse(manifest['artifact_qualification_admitted'])
        for entry in manifest['files']:
            self.assertEqual(q.sha(public / entry['path']), entry['sha256'])

    def test_release_check_uses_normalized_outputs_but_raw_evidence_still_blocks_export(self):
        sanitizer = q.module(ROOT, 'sanitize_public.py')
        (self.root / 'source').symlink_to(ROOT, target_is_directory=True)
        sbom = self.root / 'evidence/sbom'
        sbom.mkdir(parents=True)
        raw = sbom / 'synthetic.raw.spdx.json'
        raw.write_text('{"fileName":"/home/synthetic/private"}')
        normalized = sbom / 'synthetic.spdx.json'
        normalized.write_text('{"fileName":"./bin/synthetic"}')
        notices = self.root / 'evidence/THIRD-PARTY-NOTICES.txt'
        notices.write_text('Synthetic public notice\n')
        original = raw.read_bytes()
        worker = object.__new__(q.Qualification)
        worker.root = self.root
        observed = []
        def run(_name, args):
            paths = [pathlib.Path(args[index + 1]) for index, value in enumerate(args) if value == '--generated']
            observed.extend(paths)
            findings = [finding for path in paths for finding in sanitizer.scan_generated_tree(path, ROOT)]
            if findings:
                raise q.Stop('generated-sanitization failed')
        worker.run = run
        worker.sanitize_release_outputs([('bin/synthetic', normalized)], notices)
        self.assertEqual(observed, [normalized, notices])
        self.assertEqual(raw.read_bytes(), original)
        with self.assertRaises(q.Stop):
            host.export_evidence(self.root)
        manifest = json.loads((self.root / 'public/evidence-inventory.json').read_text())
        self.assertFalse(manifest['artifact_qualification_admitted'])
        self.assertEqual(manifest['unsafe_text_withheld'][0]['path'], 'sbom/synthetic.raw.spdx.json')
        self.assertEqual(raw.read_bytes(), original)

    def test_sensitive_normalized_output_still_fails_release_check(self):
        sanitizer = q.module(ROOT, 'sanitize_public.py')
        normalized = self.root / 'synthetic.spdx.json'
        normalized.write_text('{"fileName":"/home/synthetic/private"}')
        notices = self.root / 'notices.txt'
        notices.write_text('Synthetic public notice\n')
        worker = object.__new__(q.Qualification)
        worker.root = self.root
        def run(_name, args):
            paths = [pathlib.Path(args[index + 1]) for index, value in enumerate(args) if value == '--generated']
            if any(sanitizer.scan_generated_tree(path, ROOT) for path in paths):
                raise q.Stop('generated-sanitization failed')
        worker.run = run
        with self.assertRaises(q.Stop):
            worker.sanitize_release_outputs([('bin/synthetic', normalized)], notices)

    def test_oversized_export_refuses_before_copying_or_moving_raw_outputs(self):
        evidence = self.root / 'evidence'
        (evidence / 'artifacts').mkdir(parents=True)
        raw = evidence / 'artifacts/blob'
        raw.write_bytes(b'independent raw output')
        with mock.patch.object(q, 'ARTIFACT_LIMIT', 2**20):
            with self.assertRaises(q.Stop): host.export_evidence(self.root)
        self.assertEqual(raw.read_bytes(), b'independent raw output')
        self.assertFalse((self.root / 'public').exists())

    def test_guarded_export_requires_a_live_observer_before_any_public_allocation(self):
        (self.root / 'evidence').mkdir()
        heartbeat = self.root / 'heartbeat.json'
        heartbeat.write_text('{}')
        os.utime(heartbeat, (1, 1))
        with self.assertRaises(q.Stop): host.export_evidence(self.root, guarded=True)
        self.assertFalse((self.root / 'public').exists())

    def test_abort_retains_completed_raw_bytes_without_copying_or_admission(self):
        raw = self.root / 'evidence/artifacts/images-A'
        raw.mkdir(parents=True)
        (raw / 'blob').write_bytes(b'original raw export')
        inode = (raw / 'blob').stat().st_ino
        with mock.patch.object(host.shutil, 'copyfile', side_effect=AssertionError('no copies allowed')):
            host.retain_failure(self.root)
        public = self.root / 'public'
        self.assertEqual((public / 'artifacts/images-A/blob').stat().st_ino, inode)
        self.assertEqual((public / 'artifacts/images-A/blob').read_bytes(), b'original raw export')
        result = json.loads((public / 'RESULT.json').read_text())
        self.assertEqual(result['status'], 'fail')
        manifest = json.loads((public / 'evidence-inventory.json').read_text())
        self.assertFalse(manifest['artifact_qualification_admitted'])
        for entry in manifest['files']:
            self.assertEqual(q.sha(public / entry['path']), entry['sha256'])

    def test_oversized_transfer_never_emits_upload_permission(self):
        import contextlib
        public = self.root / 'public'
        public.mkdir()
        (public / 'evidence-inventory.json').write_text('{}')
        (public / 'raw').write_bytes(b'x' * 100)
        output = io.StringIO()
        with mock.patch.object(q, 'ARTIFACT_LIMIT', 10), mock.patch.object(sys, 'argv', ['qualify-runtime.py', '--check-upload', str(public)]), contextlib.redirect_stdout(output):
            with self.assertRaises(q.Stop): host.main()
        self.assertEqual(output.getvalue(), '')

    def test_rerun_cannot_reuse_stale_carry_in(self):
        with self.assertRaises(q.Stop): self.admit(environment={**self.environment, 'GITHUB_RUN_ATTEMPT': '2'})
