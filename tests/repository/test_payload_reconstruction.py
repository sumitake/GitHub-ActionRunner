"""Offline regressions for reconstruction authority and exact-byte admission."""
# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _payload_reconstruction as reconstruction
import _bounded_qualification as q
spec = importlib.util.spec_from_file_location('reconstruction_host', ROOT / 'scripts/release/qualify-runtime.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class Reconstruction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        self.product = self.root / 'product'
        self.tooling = self.root / 'tooling'
        self.product.mkdir()
        self.tooling.mkdir()
        self.environment = dict(GITHUB_EVENT_NAME='workflow_dispatch', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux', RUNNER_ARCH='X64', GITHUB_REPOSITORY='sumitake/GitHub-ActionRunner', GITHUB_ACTOR='sumitake', GITHUB_REF=reconstruction.BRANCH, GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', GITHUB_WORKSPACE=str(self.root))
        self.event = {'repository': {'private': False, 'full_name': 'sumitake/GitHub-ActionRunner', 'owner': {'login': 'sumitake'}}, 'inputs': {'bounded_qualification': 'false', 'metadata_probe': 'false', 'payload_reconstruction': 'true', 'expected_commit': 'a' * 40, 'expected_tree': 'b' * 40, 'carry_in_bytes': str(q.RESERVE)}}

    def command(self, argv, **_kwargs):
        if argv[-1] == 'HEAD':
            return 'a' * 40
        if argv[-1] == 'HEAD^{tree}':
            return 'b' * 40
        return ''

    def admit(self, event=None, environment=None):
        with mock.patch.object(reconstruction, 'verify_source'):
            return reconstruction.admission(self.product, self.tooling, event or self.event, environment or self.environment, self.command)

    def test_exact_owner_dispatch_keeps_product_and_tooling_identities_separate(self):
        result = self.admit()
        self.assertEqual(result['commit'], reconstruction.COMMIT)
        self.assertEqual(result['tree'], reconstruction.TREE)
        self.assertEqual(result['tooling_commit'], 'a' * 40)
        self.assertTrue(result['payload_reconstruction'])
        self.assertFalse(result['live_operations'])

    def test_wrong_actor_machine_attempt_branch_identity_and_budget_fail_closed(self):
        for key, value in [('GITHUB_EVENT_NAME', 'push'), ('RUNNER_ENVIRONMENT', 'self-hosted'), ('RUNNER_ARCH', 'ARM64'), ('GITHUB_ACTOR', 'other'), ('GITHUB_REF', 'refs/heads/main'), ('GITHUB_SHA', 'c' * 40), ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_WORKSPACE', '/tmp')]:
            with self.subTest(key=key), self.assertRaises(q.Stop):
                self.admit(environment={**self.environment, key: value})
        for key, value in [('payload_reconstruction', 'false'), ('expected_tree', 'c' * 40), ('carry_in_bytes', '0'), ('carry_in_bytes', str(q.SOFT)), ('extra', 'true'), ('bounded_qualification', 'true'), ('metadata_probe', 'true')]:
            event = copy.deepcopy(self.event)
            event['inputs'][key] = value
            with self.subTest(key=key), self.assertRaises(q.Stop):
                self.admit(event=event)

    def test_group_writable_source_and_symlink_are_rejected_before_execution(self):
        path = self.product / 'script.py'
        path.write_text('content')
        path.chmod(0o644)
        def command(argv, **_kwargs):
            if 'ls-tree' in argv: return '100644 blob ' + 'a' * 40 + '\tscript.py'
            if argv[-1] == 'HEAD': return reconstruction.COMMIT
            if argv[-1] == 'HEAD^{tree}': return reconstruction.TREE
            return ''
        reconstruction.verify_source(self.product, command)
        path.chmod(0o664)
        with self.assertRaises(q.Stop): reconstruction.verify_source(self.product, command)
        path.unlink()
        path.symlink_to(ROOT / 'go.mod')
        with self.assertRaises(q.Stop): reconstruction.verify_source(self.product, command)

    def test_real_identity_document_is_pinned_and_exactly_five_role_runtime(self):
        expected = reconstruction.expected()
        self.assertEqual(expected['file_count'], 63)
        self.assertEqual(sum(row['bytes'] for row in expected['required_original_members']), 455533293)
        self.assertEqual(set(expected['runtime_images']), {'runner', 'adapter', 'broker', 'helper', 'verifier'})

    def fixture(self):
        root = self.root / 'work'
        artifacts = root / 'evidence/artifacts'
        artifacts.mkdir(parents=True)
        (artifacts / 'payload').write_bytes(b'qualified')
        q.write(root / 'inputs.json', {'tooling_commit': 'a' * 40, 'tooling_tree': 'b' * 40})
        images = [{'image': str(n), 'phase': 'A', 'oci_graph': {'id': n}, 'source_to_image': {'stamp': 'fixed'}} for n in range(5)]
        authority = {'file_count': 1, 'file_content_bytes': 9, 'required_original_members': [{'path': 'artifacts/payload', 'bytes': 9, 'sha256': hashlib.sha256(b'qualified').hexdigest()}], 'runtime_images': {str(n): {key: images[n][key] for key in ('image', 'oci_graph', 'source_to_image')} for n in range(5)}}
        return root, types.SimpleNamespace(artifacts=artifacts, images=images), authority

    def test_changed_missing_extra_linked_or_graph_mismatched_payload_cannot_publish(self):
        mutations = ['changed', 'missing', 'extra', 'symlink', 'hardlink', 'graph', 'stamp']
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=self.root) as temp:
                original = self.root
                self.root = pathlib.Path(temp).resolve()
                root, worker, authority = self.fixture()
                payload = worker.artifacts / 'payload'
                if mutation == 'changed': payload.write_bytes(b'Qualified')
                elif mutation == 'missing': payload.unlink()
                elif mutation == 'extra': (worker.artifacts / 'extra').write_bytes(b'extra')
                elif mutation == 'symlink':
                    payload.unlink(); payload.symlink_to(ROOT / 'go.mod')
                elif mutation == 'hardlink': os.link(payload, root / 'alias')
                elif mutation == 'graph': worker.images[0]['oci_graph'] = {'id': 100}
                elif mutation == 'stamp': worker.images[0]['source_to_image'] = {'stamp': 'other'}
                with self.assertRaises(q.Stop): reconstruction.compare(root, worker, authority)
                self.assertFalse((root / 'public').exists())
                self.root = original

    def test_success_is_explicitly_not_qualification_and_resource_failure_blocks_upload(self):
        root, worker, authority = self.fixture()
        reconstruction.compare(root, worker, authority)
        proof = json.loads((root / 'public/payload-identity-comparison.json').read_text())
        self.assertTrue(proof['reconstruction_matched'])
        self.assertFalse(proof['qualification_executed'])
        self.assertFalse(proof['release_admitted'])
        final = {**proof, 'resource_qualification': 'fail', 'workers_joined': True, 'scope_exit_code': 0}
        with self.assertRaises(q.Stop): reconstruction.finalize(root, final)
        with self.assertRaises(q.Stop), mock.patch.object(reconstruction, 'expected', return_value=authority):
            reconstruction.check_upload(root / 'public')


    def success(self):
        root, worker, authority = self.fixture()
        reconstruction.compare(root, worker, authority)
        proof = reconstruction.read_json(root / 'public/payload-identity-comparison.json')
        final = {**proof, 'resource_qualification': 'pass', 'workers_joined': True, 'scope_exit_code': 0}
        reconstruction.finalize(root, final)
        return root, authority

    def test_upload_rehash_rejects_post_comparison_mutation_and_unapproved_metadata(self):
        for mutation in ('changed', 'missing', 'extra', 'symlink', 'hardlink', 'unknown_receipt_field', 'wrong_authority'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=self.root) as temp:
                original = self.root
                self.root = pathlib.Path(temp).resolve()
                root, authority = self.success()
                public = root / 'public'
                with mock.patch.object(reconstruction, 'expected', return_value=authority):
                    reconstruction.check_upload(public)
                    payload = public / 'artifacts/payload'
                    if mutation == 'changed': payload.write_bytes(b'Qualified')
                    elif mutation == 'missing': payload.unlink()
                    elif mutation == 'extra': (public / 'native-log.txt').write_text('must never be uploaded')
                    elif mutation == 'symlink':
                        payload.unlink(); payload.symlink_to(ROOT / 'go.mod')
                    elif mutation == 'hardlink': os.link(payload, root / 'alias')
                    else:
                        proof = reconstruction.read_json(public / 'payload-identity-comparison.json')
                        if mutation == 'unknown_receipt_field': proof['native-log'] = 'must never be uploaded'
                        else: proof['live_operations'] = True
                        q.write(public / 'payload-identity-comparison.json', proof)
                    with self.assertRaises(q.Stop): reconstruction.check_upload(public)
                self.root = original

    def test_success_exposes_only_public_tree_and_failure_keeps_root_private(self):
        root, _ = self.success()
        self.assertEqual(root.stat().st_mode & 0o777, 0o755)
        self.assertEqual((root / 'evidence').stat().st_mode & 0o777, 0o700)
        self.assertEqual((root / 'inputs.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual((root / 'public/artifacts/payload').stat().st_mode & 0o777, 0o644)
        original = self.root
        with tempfile.TemporaryDirectory(dir=self.root) as temp:
            self.root = pathlib.Path(temp).resolve()
            root, worker, authority = self.fixture()
            reconstruction.compare(root, worker, authority)
            proof = reconstruction.read_json(root / 'public/payload-identity-comparison.json')
            with self.assertRaises(q.Stop): reconstruction.finalize(root, {**proof, 'resource_qualification': 'fail', 'workers_joined': True, 'scope_exit_code': 0})
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        self.root = original

    def test_json_ambiguity_nonfinite_and_private_links_fail_closed(self):
        for raw in (b'{"status":"pass","status":"fail"}', b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(q.Stop): reconstruction.parse(raw)
        root, worker, authority = self.fixture()
        reconstruction.compare(root, worker, authority)
        (root / 'private-link').symlink_to(ROOT, target_is_directory=True)
        proof = reconstruction.read_json(root / 'public/payload-identity-comparison.json')
        with self.assertRaises(q.Stop): reconstruction.finalize(root, {**proof, 'resource_qualification': 'pass', 'workers_joined': True, 'scope_exit_code': 0})
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)

    def test_existing_qualification_accepts_only_false_reconstruction_selector(self):
        event = {'repository': {'private': False, 'full_name': 'synthetic/example', 'owner': {'login': 'synthetic'}}, 'inputs': {'bounded_qualification': 'true', 'metadata_probe': 'false', 'payload_reconstruction': 'false', 'expected_commit': 'a' * 40, 'expected_tree': 'b' * 40, 'carry_in_bytes': str(q.RESERVE)}}
        env = {**self.environment, 'GITHUB_REPOSITORY': 'synthetic/example', 'GITHUB_ACTOR': 'synthetic', 'GITHUB_REF': 'refs/heads/codex/runner-dotnet-servicing'}
        def command(argv, **kwargs):
            if '--format=%ct' in argv: return '123'
            return self.command(argv, **kwargs)
        with mock.patch.object(host, 'command', side_effect=command):
            self.assertEqual(host.admission(self.product, event, env)['commit'], 'a' * 40)
            for value in ('true', '', 'FALSE'):
                event['inputs']['payload_reconstruction'] = value
                with self.subTest(value=value), self.assertRaises(q.Stop):
                    host.admission(self.product, event, env)

    def test_worker_entrypoint_never_selects_scans_or_normal_qualification(self):
        worker = mock.Mock(daemon=None)
        with mock.patch.object(sys, 'argv', ['qualify-runtime.py', '--reconstruct-worker', str(self.root)]), mock.patch.object(q, 'Qualification', return_value=worker), mock.patch.object(reconstruction, 'compare') as compare:
            host.main()
        worker.build.assert_called_once_with(reconstruction=True)
        worker.scan.assert_not_called()
        compare.assert_called_once()



if __name__ == '__main__':
    unittest.main()
