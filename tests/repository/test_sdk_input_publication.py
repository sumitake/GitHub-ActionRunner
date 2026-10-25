"""Exercise SDK publication offline; no hosted job, token mint or SDK build."""
# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import types
import unittest
from unittest import mock

from tests.repository import test_retained_runner as retained_tests

retained = retained_tests.retained

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/release/publish-runtime-release.sh'
REPOSITORY = 'sumitake/GitHub-ActionRunner'
COMMIT = 'a' * 40


def publisher_module():
    body = SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
    # Load definitions without invoking the real CLI/transport.
    body = body.rsplit('\ntry:\n    main(', 1)[0]
    module = types.ModuleType('sdk_input_publisher')
    with mock.patch.object(sys, 'argv', ['-', str(SCRIPT)]):
        exec(compile(body, str(SCRIPT), 'exec'), module.__dict__)
    return module


class API:
    """In-memory GitHub responses, with the real publisher state machine."""
    def __init__(self, module):
        self.module = module
        self.calls = []
        self.ref = None
        self.release = None
        self.assets = []
        self.bytes = {}
        self.enabled = True
        self.signed = True
        self.missing_digest = False
        self.corrupt_download = False
        self.mutable = False
        self.move_after_upload = False

    def settings(self):
        self.calls.append(('SETTINGS', None))
        if not self.enabled:
            self.module.reject('immutable settings disabled')

    def api(self, method, path, *, data=None):
        self.calls.append((method, path))
        prefix = '/repos/' + REPOSITORY
        value = None
        status = 200
        if path.startswith(prefix + '/git/commits/'):
            value = dict(sha=COMMIT, verification=dict(verified=self.signed))
        elif path.startswith(prefix + '/git/ref/tags/'):
            status = 200 if self.ref else 404
            value = self.ref or {}
        elif path == prefix + '/git/refs' and method == 'POST':
            request = json.loads(data)
            self.ref = dict(ref=request['ref'], object=dict(type='commit', sha=request['sha']))
            status, value = 201, self.ref
        elif path.startswith(prefix + '/releases?'):
            value = [self.release] if self.release else []
        elif path == prefix + '/releases' and method == 'POST':
            self.release = dict(json.loads(data), id=42, immutable=False)
            status, value = 201, self.release
        elif path.startswith(prefix + '/releases/42/assets?'):
            value = copy.deepcopy(self.assets)
            if self.missing_digest:
                for row in value:
                    row['digest'] = None
        elif path == prefix + '/releases/42' and method == 'PATCH':
            self.release.update(json.loads(data), immutable=not self.mutable)
            value = self.release
        else:
            raise AssertionError((method, path))
        return status, self.module.canonical_json(value)

    def upload(self, release_id, name, path):
        assert release_id == 42
        self.calls.append(('UPLOAD', name))
        raw = path.read_bytes()
        row = dict(id=100 + len(self.assets), name=name, state='uploaded',
                   size=len(raw), digest='sha256:' + hashlib.sha256(raw).hexdigest())
        self.assets.append(row)
        self.bytes[row['id']] = raw
        if self.move_after_upload:
            self.ref['object']['sha'] = 'b' * 40
        return 201, self.module.canonical_json(row)

    def download_asset(self, asset_id, *, expected_size, expected_digest):
        self.calls.append(('DOWNLOAD', asset_id))
        raw = self.bytes[asset_id] + (b'x' if self.corrupt_download else b'')
        if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_digest:
            self.module.reject('asset bytes')

    def mutations(self):
        return [row for row in self.calls if row[0] in ('POST', 'PATCH', 'DELETE', 'UPLOAD')]


class SDKInputPublication(unittest.TestCase):
    def setUp(self):
        self.fixture = retained_tests.RetainedRunner()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.module = publisher_module()
        self.enterContext(mock.patch.object(self.module, 'SOURCE', self.fixture.source))
        self.api = API(self.module)
        self.tag = 'runner-sdk-input-' + self.fixture.pin['archive']['sha256'] + '-' + COMMIT

    def load(self):
        return self.module.load_sdk_input(self.fixture.input, REPOSITORY, self.tag, COMMIT)

    def publisher(self, kind='sdk-input'):
        assets, title, body = self.load()
        return self.module.Publisher(self.api, kind=kind, repository=REPOSITORY,
            tag=self.tag, target_commit=COMMIT, product_tag_object=None,
            title=title, body=body, assets=assets)

    def test_fresh_sdk_input_exact_assets_prerelease_and_signed_ref(self):
        publisher = self.publisher()
        publisher.run()
        self.assertIs(self.api.release['draft'], False)
        self.assertIs(self.api.release['immutable'], True)
        self.assertIs(self.api.release['prerelease'], True)
        self.assertEqual(self.api.release['make_latest'], 'false')
        self.assertIn('Unqualified retained SDK input', self.api.release['body'])
        self.assertEqual({r['name'] for r in self.api.assets},
                         {self.fixture.archive.name, retained.RECEIPT_NAME})
        self.assertEqual(len([r for r in self.api.calls if r[0] == 'UPLOAD']), 2)
        self.assertEqual(len([r for r in self.api.calls if r[0] == 'PATCH']), 1)
        self.assertGreaterEqual(len([r for r in self.api.calls if r[0] == 'SETTINGS']), 5)
        self.assertEqual(publisher.bound_release_id, 42)
        self.api.calls.clear()
        self.publisher().run()
        self.assertFalse(self.api.mutations())
        self.assertEqual(len([r for r in self.api.calls if r[0] == 'DOWNLOAD']), 2)

    def test_disabled_settings_and_unsigned_source_stop_before_mutation(self):
        for field in ('enabled', 'signed'):
            with self.subTest(field=field):
                api = API(self.module)
                setattr(api, field, False)
                self.api = api
                with self.assertRaises(self.module.PublicationError):
                    self.publisher().run()
                self.assertFalse(api.mutations())

    def test_wrong_ref_and_wrong_release_role_are_not_repaired(self):
        publisher = self.publisher()
        self.api.ref = dict(ref='refs/tags/' + self.tag, object=dict(type='commit', sha='b' * 40))
        with self.assertRaises(self.module.PublicationError):
            publisher.run()
        self.assertFalse(self.api.mutations())
        self.api = API(self.module)
        self.publisher().run()
        self.api.calls.clear()
        self.api.release['prerelease'] = False
        with self.assertRaises(self.module.PublicationError):
            self.publisher().run()
        self.assertFalse(self.api.mutations())

    def test_missing_server_digest_and_corrupt_bytes_cannot_publish(self):
        for field in ('missing_digest', 'corrupt_download', 'move_after_upload'):
            with self.subTest(field=field):
                self.api = API(self.module)
                setattr(self.api, field, True)
                with self.assertRaises(self.module.PublicationError):
                    self.publisher().run()
                self.assertFalse([r for r in self.api.calls if r[0] == 'PATCH'])

    def test_extra_asset_or_mutable_terminal_response_is_failure_without_retry(self):
        self.publisher().run()
        self.api.calls.clear()
        self.api.assets.append(dict(id=999, name='private-proof.json', state='uploaded'))
        with self.assertRaises(self.module.PublicationError):
            self.publisher().run()
        self.assertFalse(self.api.mutations())
        self.api = API(self.module)
        self.api.mutable = True
        with self.assertRaises(self.module.PublicationError):
            self.publisher().run()
        self.assertEqual(len([r for r in self.api.calls if r[0] == 'PATCH']), 1)

    def test_local_closure_hash_alias_and_tag_fail_before_api(self):
        original = self.fixture.archive.read_bytes()
        extra = self.fixture.input / 'private-proof.json'
        for change in ('extra', 'hash', 'symlink', 'hardlink', 'tag'):
            with self.subTest(change=change):
                if change == 'extra': extra.write_bytes(b'{}')
                if change == 'hash': self.fixture.archive.write_bytes(b'x' * len(original))
                if change == 'symlink':
                    self.fixture.archive.unlink()
                    self.fixture.archive.symlink_to(self.fixture.private / 'SDK-RESULT.json')
                if change == 'hardlink': os.link(self.fixture.archive, extra)
                if change == 'tag': self.tag += '-changed'
                with self.assertRaises(Exception): self.load()
                self.assertFalse(self.api.calls)
                extra.unlink(missing_ok=True)
                self.fixture.archive.unlink(missing_ok=True)
                self.fixture.archive.write_bytes(original)

    def test_local_archive_drift_after_admission_stops_before_upload(self):
        publisher = self.publisher()
        self.fixture.archive.write_bytes(b'x' * len(self.fixture.data))
        with self.assertRaises(Exception): publisher.run()
        self.assertFalse([r for r in self.api.calls if r[0] == 'UPLOAD'])

    def test_two_credentials_required_and_routed_to_distinct_header_files(self):
        with mock.patch.dict(os.environ, {'PGHAR_RELEASE_TOKEN': 'synthetic',
                                         'PGHAR_RELEASE_SETTINGS_TOKEN': 'synthetic'}):
            with self.assertRaises(self.module.PublicationError): self.module.require_tokens()
        temporary = self.fixture.root / 'transport'; temporary.mkdir()
        api = self.module.GitHub(REPOSITORY, 'synthetic-write', 'synthetic-settings', temporary)
        with mock.patch.object(api, '_request', return_value=(200, b'{"enabled":true}', '')) as request:
            api.settings()
            self.assertEqual(request.call_args.kwargs['header_file'], api.settings_headers)
            api.api('GET', '/repos/' + REPOSITORY + '/releases')
            self.assertEqual(request.call_args.kwargs['header_file'], api.release_headers)
        with self.assertRaises(self.module.PublicationError):
            api.api('GET', '/repos/' + REPOSITORY + '/immutable-releases')

    def test_sdk_cli_only_emits_locator_after_readback_and_cleanup(self):
        arguments = ['--release-kind', 'sdk-input', '--repository', REPOSITORY,
                     '--tag', self.tag, '--target-commit', COMMIT, '--tree', str(self.fixture.input)]
        class Output(io.StringIO):
            def __init__(self): super().__init__(); self.buffer = io.BytesIO()
        for enabled in (False, True):
            self.api = API(self.module); self.api.enabled = enabled
            output = Output()
            with mock.patch.object(self.module, 'GitHub', return_value=self.api), \
                 mock.patch.object(self.module, 'require_tokens', return_value=('synthetic-write', 'synthetic-settings')), \
                 mock.patch.object(self.module.tempfile, 'mkdtemp', return_value=str(self.fixture.root / 'cli-temp')), \
                 mock.patch.object(sys, 'stdout', output):
                (self.fixture.root / 'cli-temp').mkdir()
                if enabled:
                    self.module.main(arguments)
                    value = json.loads(output.buffer.getvalue())
                    self.assertEqual(value, dict(schema_version=1, role='unqualified-sdk-input',
                        repository=REPOSITORY, tag=self.tag, release_id=42, commit_sha=COMMIT))
                else:
                    with self.assertRaises(self.module.PublicationError): self.module.main(arguments)
                    self.assertEqual(output.buffer.getvalue(), b'')
                self.assertFalse((self.fixture.root / 'cli-temp').exists())

    def test_product_candidate_prerelease_behavior_and_existing_assets_preserved(self):
        for kind in ('product', 'candidate'):
            publisher = self.publisher(kind)
            value = dict(id=1, tag_name=self.tag, target_commitish=COMMIT,
                         name=publisher.title, body=publisher.body,
                         prerelease=False, draft=True, immutable=False)
            self.assertEqual(publisher.validate_release(value, 'draft'), 1)
            value['prerelease'] = True
            with self.assertRaises(self.module.PublicationError): publisher.validate_release(value, 'draft')
        args = ['--release-kind', 'sdk-input', '--repository', REPOSITORY, '--tag', self.tag,
                '--target-commit', COMMIT, '--tree', str(self.fixture.input)]
        self.module.parse_arguments(args)
        with self.assertRaises(self.module.PublicationError):
            self.module.parse_arguments(args + ['--product-tag-object', 'b' * 40])

    def producer_publisher(self):
        assets, title, body = self.module.load_sdk_input(None, REPOSITORY, self.tag, COMMIT)
        return self.module.Publisher(self.api, kind='sdk-input', repository=REPOSITORY,
            tag=self.tag, target_commit=COMMIT, product_tag_object=None,
            title=title, body=body, assets=assets, producer_upload=True)

    def producer_rows(self):
        rows = []
        for index, path in enumerate(sorted(self.fixture.input.iterdir()), 100):
            raw = path.read_bytes()
            rows.append(dict(id=index, name=path.name, state='uploaded',
                size=len(raw), digest='sha256:' + hashlib.sha256(raw).hexdigest()))
            self.api.bytes[index] = raw
        return rows

    def test_external_producer_uploads_are_verified_but_never_uploaded_by_job(self):
        publisher = self.producer_publisher()
        original = self.api.api
        count = 0
        def api(method, path, **kwargs):
            nonlocal count
            if '/releases/42/assets?' in path:
                count += 1
                if count == 2:
                    self.api.assets = self.producer_rows()
            return original(method, path, **kwargs)
        with mock.patch.object(self.api, 'api', side_effect=api), \
             mock.patch.object(self.api, 'upload', side_effect=AssertionError('job upload forbidden')), \
             mock.patch.object(self.module.time, 'monotonic', side_effect=[0, 0, 721]), \
             mock.patch.object(self.module.time, 'sleep') as sleep, \
             mock.patch.object(sys, 'stderr', io.StringIO()):
            publisher.run()
        self.assertEqual(sleep.call_count, 1)
        self.assertIs(self.api.release['immutable'], True)
        self.assertEqual({r['name'] for r in self.api.assets},
                         {self.fixture.archive.name, retained.RECEIPT_NAME})
        self.assertFalse([r for r in self.api.calls if r[0] in ('UPLOAD', 'DELETE')])
        self.assertTrue([r for r in self.api.calls if r[0] == 'DOWNLOAD'])

    def test_external_upload_timeout_preserves_draft_without_delete_or_retry(self):
        publisher = self.producer_publisher()
        with mock.patch.object(self.module.time, 'monotonic', side_effect=[0, 0, 1801]), \
             mock.patch.object(self.module.time, 'sleep') as sleep, \
             mock.patch.object(sys, 'stderr', io.StringIO()), \
             self.assertRaisesRegex(self.module.PublicationError, 'upload deadline'):
            publisher.run()
        self.assertTrue(self.api.release['draft'])
        self.assertEqual(sleep.call_count, 1)
        self.assertFalse([r for r in self.api.calls if r[0] in ('PATCH', 'UPLOAD', 'DELETE')])

    def test_external_preflight_failure_creates_neither_ref_nor_draft(self):
        self.api.enabled = False
        with self.assertRaises(self.module.PublicationError):
            self.producer_publisher().run()
        self.assertFalse(self.api.mutations())
        self.assertIsNone(self.api.ref)
        self.assertIsNone(self.api.release)

    def test_external_existing_draft_and_wait_recheck_live_settings(self):
        publisher = self.producer_publisher()
        self.api.ref = dict(ref='refs/tags/' + self.tag, object=dict(type='commit', sha=COMMIT))
        self.api.release = dict(id=42, tag_name=self.tag, target_commitish=COMMIT,
            name=publisher.title, body=publisher.body, prerelease=True, draft=True, immutable=False)
        self.api.enabled = False
        output = io.StringIO()
        with mock.patch.object(sys, 'stderr', output), self.assertRaises(self.module.PublicationError):
            publisher.run()
        self.assertEqual(output.getvalue(), '')
        self.assertFalse(self.api.mutations())
        self.api.enabled = True
        def changed(_seconds): self.api.enabled = False
        with mock.patch.object(self.module.time, 'sleep', side_effect=changed), \
             mock.patch.object(sys, 'stderr', io.StringIO()), self.assertRaises(self.module.PublicationError):
            self.producer_publisher().run()
        self.assertFalse(self.api.mutations())

    def test_external_bad_extra_or_starter_assets_cannot_be_published(self):
        for change in ('digest', 'extra', 'starter'):
            self.api = API(self.module)
            self.api.assets = self.producer_rows()
            if change == 'digest': self.api.assets[0]['digest'] = 'sha256:' + 'f' * 64
            if change == 'extra': self.api.assets.append(dict(id=999, name='private-proof.json', state='uploaded'))
            if change == 'starter': self.api.assets[0]['state'] = 'starter'
            with self.subTest(change=change), \
                 mock.patch.object(self.module.time, 'monotonic', side_effect=[0, 0, 1801]), \
                 mock.patch.object(self.module.time, 'sleep'), \
                 mock.patch.object(sys, 'stderr', io.StringIO()), \
                 self.assertRaises(self.module.PublicationError):
                self.producer_publisher().run()
            self.assertFalse([r for r in self.api.calls if r[0] in ('PATCH', 'UPLOAD', 'DELETE')])

    def test_producer_mode_has_no_tree_or_other_release_kind_escape(self):
        args = ['--release-kind', 'sdk-input', '--repository', REPOSITORY,
                '--tag', self.tag, '--target-commit', COMMIT, '--producer-upload', 'true']
        self.module.parse_arguments(args)
        for bad in [args + ['--tree', str(self.fixture.input)],
                    [value if value != 'true' else 'false' for value in args],
                    [value if value != 'sdk-input' else 'candidate' for value in args]]:
            with self.subTest(bad=bad), self.assertRaises(self.module.PublicationError):
                self.module.parse_arguments(bad)


class SDKPublicationWorkflow(unittest.TestCase):
    def workflow(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        import check_workflow_policy
        return check_workflow_policy.parse_workflow(
            (ROOT / '.github/workflows/runner-release-candidate.yml').read_text())

    def test_single_manual_publication_job_has_no_build_artifact_or_token_export(self):
        workflow = self.workflow()
        job = workflow['jobs']['sdk-input-publication']
        self.assertEqual(job['permissions'], {'contents': 'write'})
        self.assertEqual(job['timeout-minutes'], '45')
        self.assertIn("github.event_name == 'workflow_dispatch'", job['if'])
        self.assertIn('inputs.sdk_input_publication', job['if'])
        steps = job['steps']
        self.assertIn('Validate trusted SDK', steps[0]['name'])
        action = [i for i,s in enumerate(steps) if str(s.get('uses','')).startswith('actions/create-github-app-token@')]
        self.assertEqual(len(action), 1)
        self.assertGreater(action[0], 0)
        self.assertEqual(steps[action[0]]['with'], {
            'client-id': '${{ vars.PORTABLE_GHAR_RELEASE_APP_CLIENT_ID }}',
            'private-key': '${{ secrets.PORTABLE_GHAR_RELEASE_APP_PRIVATE_KEY }}',
            'permission-administration': 'read'})
        text = '\n'.join(str(s.get('run','')) for s in steps)
        for forbidden in ('rebuild-runner', 'rehearse-runtime', 'qualify-runtime',
                          'gh release upload', 'gh auth token', 'cache', '--clobber'):
            self.assertNotIn(forbidden, text)
        self.assertFalse([s for s in steps if 'upload-artifact@' in str(s.get('uses',''))])
        self.assertIn('--producer-upload true', steps[-1]['run'])
        self.assertEqual(steps[-1]['env'], {
            'PGHAR_RELEASE_SETTINGS_TOKEN': '${{ steps.sdk-settings-token.outputs.token }}',
            'PGHAR_RELEASE_TOKEN': '${{ github.token }}'})

    def test_dispatch_guard_rejects_wrong_identity_mixed_inputs_source_and_reruns(self):
        job = self.workflow()['jobs']['sdk-input-publication']
        step = job['steps'][0]
        good = {'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':REPOSITORY,
                'GITHUB_ACTOR':'trusted-observer','PORTABLE_GHAR_RUNNER_OBSERVER_ACTOR':'trusted-observer',
                'GITHUB_REF':'refs/heads/codex/rr7-runner-version-refresh','GITHUB_SHA':COMMIT,
                'GITHUB_RUN_ATTEMPT':'1','RUNNER_ENVIRONMENT':'github-hosted',
                'RUNNER_OS':'Linux','RUNNER_ARCH':'X64','EXPECTED_COMMIT':COMMIT,'EXPECTED_TREE':'b'*40}
        event = dict(inputs=dict(sdk_input_publication='true',expected_commit=COMMIT,expected_tree='b'*40))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'event.json'
            def run(environment, raw):
                path.write_bytes(raw)
                return subprocess.run(['bash','-c',step['run']],env={**environment,'GITHUB_EVENT_PATH':str(path)},
                    capture_output=True, text=True)
            self.assertEqual(run(good,json.dumps(event).encode()).returncode,0)
            for key,value in [('GITHUB_EVENT_NAME','push'),('GITHUB_ACTOR','other'),
                              ('GITHUB_REPOSITORY','other/repository'),('GITHUB_REF','refs/heads/main'),
                              ('GITHUB_SHA','c'*40),('EXPECTED_TREE','../escape'),
                              ('GITHUB_RUN_ATTEMPT','2'),('RUNNER_ENVIRONMENT','self-hosted')]:
                with self.subTest(key=key):
                    self.assertNotEqual(run({**good,key:value},json.dumps(event).encode()).returncode,0)
            for inputs in ({**event['inputs'],'candidate_refresh':'true'},
                           {**event['inputs'],'sdk_input_publication':'false'},
                           {**event['inputs'],'expected_commit':'c'*40}):
                self.assertNotEqual(run(good,json.dumps(dict(inputs=inputs)).encode()).returncode,0)
            self.assertNotEqual(run(good,b'{"inputs":{},"inputs":{}}').returncode,0)


if __name__ == '__main__':
    unittest.main()
