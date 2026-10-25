"""Retained SDK inputs must fail before any SDK or downloader execution."""
# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock
import io
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _retained_runner as retained
from tests.repository.test_runtime_snapshot_binding import rehearsal


class RetainedRunner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'
        for name in ['release', 'internal/buildinfo']:
            (self.source / name).mkdir(parents=True, exist_ok=True)
        for name in ['release/manifest.json', 'release/runner-rebuild.patch']:
            (self.source / name).write_bytes((ROOT / name).read_bytes())
        descriptor = json.loads((ROOT / 'internal/buildinfo/runner_rebuild.json').read_text())
        self.data = b'synthetic authenticated SDK archive\n'
        descriptor.update(linux_x64_sha256=hashlib.sha256(self.data).hexdigest(), archive_bytes=len(self.data))
        (self.source / 'internal/buildinfo/runner_rebuild.json').write_text(json.dumps(descriptor, indent=2) + '\n')
        self.input = self.source / '.retained-sdk-input'
        self.input.mkdir(parents=True)
        self.private = self.root / 'private-proof'; self.private.mkdir()
        self.archive = self.input / descriptor['asset_name']
        self.archive.write_bytes(self.data)
        self.pin = copy.deepcopy(json.loads((ROOT / 'release/retained-runner-provenance.json').read_text()))
        self.pin['archive'].update(sha256=descriptor['linux_x64_sha256'], bytes=len(self.data))
        self.pin['producer_result']['archives'] = [{k: self.pin['archive'][k] for k in ('sha256', 'bytes', 'manifest_sha256')}] * 2
        result = self.pin['producer_result']
        proof = {'SDK-RESULT.json': result, 'producer-terminal.json': {**result, 'cleanup_verified': True}}
        self.pin['evidence'] = {}
        for name, value in proof.items():
            data = (json.dumps(value, indent=2) + '\n').encode()
            (self.private / name).write_bytes(data)
            self.pin['evidence'][name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.write_pin()
        self.enterContext(mock.patch.object(retained.q, 'release_functions', return_value=rehearsal()))
        self.run = self.enterContext(mock.patch('subprocess.run', side_effect=AssertionError('no subprocess allowed')))
        self.popen = self.enterContext(mock.patch('subprocess.Popen', side_effect=AssertionError('no subprocess allowed')))

    def write_pin(self):
        data = (json.dumps(self.pin, indent=2) + '\n').encode()
        (self.source / 'release/retained-runner-provenance.json').write_bytes(data)
        self.enterContext(mock.patch.object(retained, 'PROVENANCE_SHA256', hashlib.sha256(data).hexdigest()))
        public = retained.canonical(retained.public_claims(self.pin))
        (self.source / 'release/retained-sdk-verification.json').write_bytes(public)
        (self.input / retained.RECEIPT_NAME).write_bytes(public)

    def tearDown(self):
        # A negative-path exception must never hide an attempted fallback.
        self.run.assert_not_called()
        self.popen.assert_not_called()

    def verify(self):
        return retained.verify_inputs(self.source, self.input)

    def test_valid_inputs_stage_exact_bytes_and_honest_prior_receipt_without_subprocess(self):
        output = self.root / 'selected'
        archive, receipt = retained.stage(self.source, self.input, output)
        self.assertEqual(archive.read_bytes(), self.data)
        self.assertEqual(receipt['sdk_source'], 'verified-retained-ab')
        self.assertIs(receipt['sdk_build_executed_this_run'], False)
        self.assertIs(receipt['prior_sdk_startup_verified'], True)
        retained.validate_receipt(self.source, receipt)
        self.run.assert_not_called()
        self.popen.assert_not_called()

    def test_missing_wrong_size_wrong_hash_and_wrong_basename_are_rejected(self):
        for data in [b'', self.data + b'x', b'x' * len(self.data)]:
            self.archive.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(Exception):
                self.verify()
        self.archive.unlink()
        (self.input / 'wrong.tar.gz').write_bytes(self.data)
        with self.assertRaises(Exception):
            self.verify()

    def test_all_missing_extra_aliased_and_changed_evidence_fails_closed(self):
        proof = self.private / 'SDK-RESULT.json'
        original = proof.read_bytes()
        for change in ['missing', 'extra', 'symlink', 'hardlink', 'changed']:
            proof.unlink(missing_ok=True)
            proof.write_bytes(original)
            extra = self.private / 'extra'
            if change == 'missing':
                proof.unlink()
            elif change == 'extra':
                extra.write_bytes(b'x')
            elif change == 'symlink':
                proof.unlink(); proof.symlink_to(self.private / 'producer-terminal.json')
            elif change == 'hardlink':
                os.link(proof, extra)
            else:
                proof.write_bytes(original + b' ')
            with self.subTest(change=change), self.assertRaises(Exception):
                retained.verify_private_evidence(self.source, self.private)
            extra.unlink(missing_ok=True)

    def test_archive_symlinks_hardlinks_and_extra_input_members_are_rejected(self):
        extra = self.input / 'extra'
        os.link(self.archive, extra)
        with self.assertRaises(Exception): self.verify()
        extra.unlink()
        original = self.root / 'archive'
        self.archive.rename(original); self.archive.symlink_to(original)
        with self.assertRaises(Exception): self.verify()

    def test_source_pin_drift_and_descriptor_patch_mismatch_are_rejected(self):
        pin = self.source / 'release/retained-runner-provenance.json'
        pin.write_bytes(pin.read_bytes() + b' ')
        with self.assertRaises(Exception): self.verify()
        self.write_pin()
        (self.source / 'release/runner-rebuild.patch').write_bytes(b'drift')
        with self.assertRaises(Exception): self.verify()

    def test_private_cleanup_failure_cannot_derive_a_public_receipt(self):
        path = self.private / 'producer-terminal.json'
        doc = json.loads(path.read_bytes()); doc['cleanup_verified'] = False
        data = (json.dumps(doc, indent=2) + '\n').encode(); path.write_bytes(data)
        self.pin['evidence'][path.name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.write_pin()
        with self.assertRaises(Exception): retained.verify_private_evidence(self.source, self.private)

    def test_public_claims_reject_false_prior_build_and_extra_authority(self):
        for key, value in [('independent_AB_identical', False), ('actual_app_local_startup', False),
                           ('actual_normal_help_network_none', False), ('reference_sdk_image_executed', True),
                           ('qualification_executed', True), ('release_admitted', True),
                           ('target_conformance_executed', True), ('live_operations', True)]:
            pin = copy.deepcopy(self.pin); pin['producer_result'][key] = value
            with self.subTest(key=key), self.assertRaises(Exception): retained.public_claims(pin)

    def test_public_receipt_is_exact_and_raw_evidence_is_not_an_input(self):
        self.assertEqual(retained.verify_private_evidence(self.source, self.private), retained.public_receipt_bytes(self.source))
        path = self.input / retained.RECEIPT_NAME; original = path.read_bytes()
        for data in [original + b' ', original.replace(b'unqualified-sdk-input', b'qualified-sdk-input')]:
            path.write_bytes(data)
            with self.assertRaises(Exception): self.verify()
        path.write_bytes(original)
        (self.input / 'proof').mkdir()
        with self.assertRaises(Exception): self.verify()

    def test_old_or_extra_receipt_authority_is_rejected(self):
        receipt = retained.receipt(self.source)
        for key, value in [('sdk_build_executed_this_run', True), ('sdk_source', 'fresh-build'),
                           ('sdk_public_recipe_matched', True), ('extra', True)]:
            with self.subTest(key=key), self.assertRaises(Exception):
                retained.validate_receipt(self.source, {**receipt, key: value})

    def test_missing_input_fails_before_any_stage_output_is_created(self):
        output = self.root / 'selected'
        self.archive.unlink()
        with self.assertRaises(Exception): retained.stage(self.source, self.input, output)
        self.assertFalse(output.exists())

    def test_archive_mutation_between_validation_and_copy_cannot_publish(self):
        original = retained.os.fstat
        inode = self.archive.stat().st_ino
        calls = 0
        def changed(descriptor):
            nonlocal calls
            value = original(descriptor)
            if value.st_ino == inode:
                calls += 1
                # Calls1/2 authenticate the input; call3 starts the real copier.
                if calls == 3:
                    os.utime(self.archive, ns=(value.st_atime_ns, value.st_mtime_ns + 1))
            return value
        output = self.root / 'selected'
        with mock.patch.object(retained.os, 'fstat', side_effect=changed):
            with self.assertRaises(Exception):
                retained.stage(self.source, self.input, output)
        self.assertGreaterEqual(calls, 3)
        self.assertFalse(output.exists())

    def fetch_module(self):
        spec = importlib.util.spec_from_file_location('retained_fetch', ROOT / 'scripts/release/fetch-retained-runner.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_unbound_release_locator_fails_before_network(self):
        module = self.fetch_module()
        unbound = dict(schema_version=1, role='unqualified-sdk-input', repository=module.REPOSITORY,
                       tag=None, release_id=None, commit_sha=None)
        (self.source / 'release/retained-runner-input.json').write_text(json.dumps(unbound))
        with mock.patch.object(module, 'ROOT', self.source), mock.patch.object(module, 'api', side_effect=AssertionError('network entered')):
            with self.assertRaisesRegex(Exception, 'confirmed retained release'):
                module.main()

    def test_release_identity_requires_published_immutable_input_and_signed_commit(self):
        module = self.fetch_module()
        value = dict(release_id=1, tag='sdk-input-test', commit_sha='a' * 40)
        release = dict(id=1, tag_name=value['tag'], draft=False, immutable=True, prerelease=True)
        reference = dict(ref='refs/tags/' + value['tag'], object=dict(type='commit', sha='a' * 40))
        commit = dict(sha='a' * 40, verification=dict(verified=True))
        module.release_identity(value, release, reference, commit)
        for key, changed in [('id', True), ('id', 9), ('draft', True), ('immutable', False), ('prerelease', False), ('tag_name', 'other')]:
            with self.subTest(key=key), self.assertRaises(Exception): module.release_identity(value, {**release, key: changed}, reference, commit)
        with self.assertRaises(Exception): module.release_identity(value, release, reference, {**commit, 'verification': dict(verified=False)})
        with self.assertRaises(Exception): module.release_identity(value, release, {**reference, 'object':dict(type='commit', sha='b'*40)}, commit)
        tagged = dict(sha='c'*40, tag=value['tag'], object=dict(type='commit', sha='a'*40))
        ref = dict(ref=reference['ref'], object=dict(type='tag', sha='c'*40))
        module.release_identity(value, release, ref, commit, tagged)
        with self.assertRaises(Exception): module.release_identity(value, release, ref, commit, {**tagged, 'sha':'d'*40})

    def release_rows(self):
        rows=[]
        for index, path in enumerate(sorted(self.input.iterdir()),1):
            data=path.read_bytes(); rows.append(dict(id=index,name=path.name,state='uploaded',size=len(data),digest='sha256:'+hashlib.sha256(data).hexdigest()))
        return rows

    def test_exact_two_asset_release_rejects_drift_extra_raw_proof_and_aliases(self):
        module=self.fetch_module(); rows=self.release_rows(); module.release_assets(self.source, rows)
        for key,value in [('name','../escape'),('id',True),('state','starter'),('size',1),('digest','sha256:'+'f'*64)]:
            changed=copy.deepcopy(rows); changed[0][key]=value
            with self.subTest(key=key), self.assertRaises(Exception):module.release_assets(self.source,changed)
        for changed in [rows+[dict(id=3,name='raw-proof',state='uploaded',size=1,digest='sha256:'+'a'*64)], rows[:1], [rows[0],rows[0]]]:
            with self.assertRaises(Exception):module.release_assets(self.source,changed)

    def test_public_release_download_never_forwards_auth_or_accepts_derived_host(self):
        module=self.fetch_module(); endpoint=module.API+'/repos/'+module.REPOSITORY+'/releases/assets/1'
        class Reply(io.BytesIO): status=200
        for location in ['http://release-assets.githubusercontent.com/file', 'https://evil.invalid/file',
                         'https://release-assets.githubusercontent.com.evil.invalid/file',
                         'https://user@release-assets.githubusercontent.com/file']:
            error=urllib.error.HTTPError(endpoint,302,'redirect',{'Location':location},None)
            opener=mock.Mock();opener.open.side_effect=error
            with mock.patch.object(module.urllib.request,'build_opener',return_value=opener), self.subTest(location=location),self.assertRaises(Exception):module.transfer(endpoint,io.BytesIO(),1,binary=True)
            self.assertEqual(opener.open.call_count,1)
        opener=mock.Mock();opener.open.side_effect=[urllib.error.HTTPError(endpoint,302,'redirect',{'Location':'https://release-assets.githubusercontent.com/file'},None),Reply(b'x')]
        with mock.patch.object(module.urllib.request,'build_opener',return_value=opener),mock.patch.dict(os.environ,{'GH_TOKEN':'synthetic-never-forwarded'}):
            output=io.BytesIO();module.transfer(endpoint,output,1,binary=True);self.assertEqual(output.getvalue(),b'x')
        for args in opener.open.call_args_list:self.assertNotIn('Authorization',args.args[0].headers)
        self.assertEqual(set(opener.open.call_args_list[1].args[0].headers),{'User-agent'})
        opener.open.side_effect=[Reply(b'xx')]
        with mock.patch.object(module.urllib.request,'build_opener',return_value=opener), self.assertRaises(Exception):module.transfer(endpoint,io.BytesIO(),1,binary=True)

    def test_duplicate_locator_keys_and_nonfinite_numbers_are_rejected(self):
        module=self.fetch_module()
        for raw in [b'{"id":1,"id":2}',b'{"id":NaN}']:
            with self.assertRaises(Exception):module.parse_json(raw)

    def test_main_downloads_only_two_exact_public_assets_and_rechecks_real_bytes(self):
        module=self.fetch_module(); rows=self.release_rows()
        data={row['id']:(self.input/row['name']).read_bytes() for row in rows}
        for path in self.input.iterdir():path.unlink()
        self.input.rmdir()
        value=dict(schema_version=1,role='unqualified-sdk-input',repository=module.REPOSITORY,tag='sdk-input-test',release_id=1,commit_sha='a'*40)
        (self.source/'release/retained-runner-input.json').write_text(json.dumps(value))
        observation=self.root/'accounting.json'
        observation.write_text(json.dumps(dict(read_only_accounting_preflight='pass',retained_bootstrap_admitted=True,source=str(self.source),observed_at=time.time())))
        answers={'releases/1':dict(id=1,tag_name=value['tag'],draft=False,immutable=True,prerelease=True),
                 'git/ref/tags/'+value['tag']:dict(ref='refs/tags/'+value['tag'],object=dict(type='commit',sha='a'*40)),
                 'git/commits/'+'a'*40:dict(sha='a'*40,verification=dict(verified=True)),
                 'releases/1/assets?per_page=3':rows}
        def transfer(url,output,limit,**kwargs):
            raw=data[int(url.rsplit('/',1)[1])];self.assertEqual(limit,len(raw));output.write(raw)
        space=mock.Mock(f_bavail=40*2**30,f_frsize=1,f_favail=1000000)
        with mock.patch.object(module,'ROOT',self.source),mock.patch.object(module,'api',side_effect=lambda path:answers[path]) as api,mock.patch.object(module,'transfer',side_effect=transfer) as download,mock.patch.object(module.os,'statvfs',return_value=space):
            module.main(observation)
            self.assertEqual(download.call_count,2)
            self.assertEqual(api.call_count,4)
        self.assertEqual(self.archive.read_bytes(),self.data)
        self.verify()

    def test_no_actions_or_credentials_are_required_by_public_input_workflow(self):
        text=(ROOT/'.github/workflows/ci.yml').read_text()
        for job,next_job in [('container','bounded-qualification'),('candidate-refresh',None)]:
            part=text.split('  '+job+':',1)[1]
            if next_job:part=part.split('\n  '+next_job+':',1)[0]
            self.assertNotIn('GH_TOKEN:',part)
            self.assertNotIn('actions: read',part)
        source=(ROOT/'scripts/release/fetch-retained-runner.py').read_text()
        self.assertNotIn('/actions/artifacts/',source)
        self.assertNotIn('Authorization',source)


class NoSdkFallback(unittest.TestCase):
    def test_bootstrap_charges_transport_and_decoded_input_before_acquisition(self):
        spec = importlib.util.spec_from_file_location('retained_bootstrap', ROOT / 'scripts/release/qualify-runtime.py')
        host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
        host.retained_bootstrap_checks(retained.q.RESERVE, 1024, 30 * 2**30, 1000000, 8 * 2**30)
        for values in [(retained.q.RESERVE, retained.q.SOFT, 30 * 2**30, 1000000, 8 * 2**30),
                       (retained.q.RESERVE, 1024, 13 * 2**30, 1000000, 8 * 2**30),
                       (retained.q.RESERVE - 1, 1024, 30 * 2**30, 1000000, 8 * 2**30),
                       (retained.q.RESERVE, 1024, 30 * 2**30, 500000, 8 * 2**30)]:
            with self.subTest(values=values), self.assertRaises(Exception):
                host.retained_bootstrap_checks(*values)

    def test_direct_recipe_rejects_adopted_sdk_before_prerequisite_or_build_calls(self):
        spec = importlib.util.spec_from_file_location('retained_recipe', ROOT / 'scripts/release/rebuild-runner.py')
        recipe = importlib.util.module_from_spec(spec); spec.loader.exec_module(recipe)
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(sys, 'argv', ['rebuild-runner.py', '--output-directory', str(Path(temporary).resolve())]), mock.patch.object(recipe.shutil, 'which', side_effect=AssertionError('build prerequisites reached')), mock.patch('subprocess.run', side_effect=AssertionError('SDK reached')):
                with self.assertRaisesRegex(ValueError, 'retained SDK required'):
                    recipe.main()

    def test_workflow_requires_retained_archive_without_empty_argument_fallback(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertNotIn('rebuild-runner.py --if-selected', text)
        self.assertNotIn('archive_args=()', text)
        self.assertIn('test -n "$REBUILT_RUNNER_ARCHIVE"', text)
        self.assertIn('fetch-retained-runner.py', text)
        self.assertNotIn('continue-on-error', text)

    def test_direct_qualification_sdk_rebuild_is_disabled_before_work(self):
        spec = importlib.util.spec_from_file_location('retained_host', ROOT / 'scripts/release/qualify-runtime.py')
        host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
        with mock.patch.object(host.importlib.util, 'spec_from_file_location', side_effect=AssertionError('legacy loader entered')), mock.patch('subprocess.run', side_effect=AssertionError('no subprocess')):
            with self.assertRaisesRegex(Exception, 'retained'):
                host.sdk_rebuild(Path('/nonexistent'), {}, 'unused', 'unused')

    def test_legacy_hosts_stop_before_event_or_compiler_acquisition(self):
        spec = importlib.util.spec_from_file_location('retained_host_modes', ROOT / 'scripts/release/qualify-runtime.py')
        host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
        for reconstruction in [False, True]:
            with mock.patch('subprocess.run', side_effect=AssertionError('no subprocess')):
                with self.subTest(reconstruction=reconstruction), self.assertRaisesRegex(Exception, 'retained'):
                    host.host(ROOT, Path('/nonexistent'), Path('/nonexistent-event'), None, reconstruction=reconstruction)


if __name__ == '__main__':
    unittest.main()
