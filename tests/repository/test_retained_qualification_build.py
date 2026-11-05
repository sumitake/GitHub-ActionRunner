"""Source-only retained SDK worker coverage; no compiler, container or network."""
# SPDX-License-Identifier: MPL-2.0
import copy
import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _bounded_qualification as q
import _candidate_refresh as candidate
import _go_patch_refresh as compiler


class RetainedBuild(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.worker = q.Qualification.__new__(q.Qualification)
        w = self.worker
        w.root = self.root
        w.source = self.root / 'source'
        w.output = self.root / 'evidence'
        w.artifacts = w.output / 'artifacts'
        w.artifacts.mkdir(parents=True)
        w.source.mkdir()
        w.commit = q.RETAINED_SOURCE
        w.inputs = dict(commit=w.commit, tree=q.RETAINED_TREE, epoch=123)
        w.version = 'candidate-' + w.commit[:12]
        w.env = dict(PATH='/usr/bin', GOROOT='/toolchain/go')
        w.runtime = copy.deepcopy(json.loads((ROOT / 'release/manifest.json').read_text())['runtime'])
        w.images = []
        w.commands = []
        w.buildkit_publication = mock.Mock()
        self.descriptor = dict(linux_x64_sha256=q.RETAINED_SDK_SHA256, archive_bytes=q.RETAINED_SDK_BYTES)

    def identity(self):
        with mock.patch.object(candidate, 'sdk_authority', return_value=self.descriptor):
            self.worker.retained_qualification_identity()

    def test_exact_source_membership_sdk_and_separate_tooling(self):
        self.identity()
        self.assertEqual(self.worker.version, q.RETAINED_VERSION)
        mutations = [lambda: setattr(self.worker, 'commit', 'a' * 40),
                     lambda: self.worker.inputs.update(tree='b' * 40),
                     lambda: self.worker.runtime['images'].pop(),
                     lambda: self.worker.runtime['binaries'].append(self.worker.runtime['binaries'][0]),
                     lambda: self.descriptor.update(archive_bytes=1),
                     lambda: self.descriptor.update(linux_x64_sha256='0' * 64),
                     lambda: setattr(self.worker, 'source', ROOT)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.setUp()
                mutate()
                with self.assertRaises(q.Stop):
                    self.identity()

    def test_conflicting_modes_fail_before_work(self):
        for flag in ('reconstruction', 'go_patch_refresh', 'candidate_refresh'):
            with self.subTest(flag=flag), self.assertRaises(q.Stop):
                self.worker.build(retained_sdk_qualification=True, **{flag: True})

    def test_reused_output_generations_are_rejected_before_compiler(self):
        (self.worker.artifacts / 'binaries-A').mkdir()
        with mock.patch.object(candidate, 'sdk_authority', return_value=self.descriptor), \
             mock.patch.object(compiler, 'constrain_compiler') as constrain:
            with self.assertRaisesRegex(q.Stop, 'fresh output generations'):
                self.worker.build(retained_sdk_qualification=True)
        constrain.assert_not_called()

    def simulate_build(self, **mode):
        w = self.worker
        release_dir = w.source / 'release'
        release_dir.mkdir()
        (release_dir / 'manifest.json').write_text('{}')
        (release_dir / 'public-dependency-metadata.json').write_text('{"go_licenses": []}')
        (release_dir / 'runner-licenses.json').write_text('{"licenses": []}')
        selected = w.root / 'selected-runner'
        selected.mkdir()
        archive = selected / 'sdk.tar.gz'
        archive.write_bytes(b'retained SDK fixture, never rebuilt')
        payload = dict(asset_name=archive.name, sha256=q.sha(archive), archive_bytes=archive.stat().st_size)
        stamp = lambda: 'portable-ghar-build-identity-v1|' + w.version + '|' + w.commit
        def stage(source, directory, runtime, identity):
            for image in runtime['images']:
                build = source / image['context'] / 'build'
                build.mkdir(parents=True, exist_ok=True)
                names = ['portable-ghar-' + image['name']]
                if image['name'] == 'runner':
                    names = ['portable-ghar-runner-gate']
                if image['name'] == 'network-broker-dialer':
                    names.append('portable-ghar-network-broker-parser')
                for name in names:
                    shutil.copyfile(directory / 'bin' / name, build / name)
        w.release = dict(validate_release_manifest=lambda _: None,
                         validate_dockerfiles=lambda *_: None,
                         select_runner_payload=lambda *_: payload,
                         stage_stamped_image_inputs=stage)
        def run(name, argv, **kwargs):
            w.commands.append(dict(name=name, argv=argv))
            log = w.output / (name + '.log')
            text = ''
            if name == 'linked-identity':
                text = stamp()
            elif name == 'fixed-go-version':
                text = 'go version go1.26.10 linux/amd64'
            elif name.startswith('binary-toolchain-'):
                text = argv[-1] + ': go1.26.10'
            elif name.startswith('binary-'):
                path = pathlib.Path(argv[argv.index('-o') + 1])
                path.write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 + b'\x3e\0' + stamp().encode())
            log.write_text(text + '\n')
            return 0, log
        exports = []
        def buildctl(label, context, dockerfile, output, extra):
            exports.append(output)
            directory = pathlib.Path(output.split('dest=', 1)[1].split(',', 1)[0])
            directory.mkdir()
            # Original exporter metadata is retained and compared, not rewritten.
            (directory / 'index.json').write_text(output.split(',name=', 1)[1])
        def remove(relative):
            path = w.root / relative
            if path.exists():
                shutil.rmtree(path)
        with mock.patch.object(w, 'run', side_effect=run), \
             mock.patch.object(w, 'start'), mock.patch.object(w, 'stop'), \
             mock.patch.object(w, 'buildctl', side_effect=buildctl), \
             mock.patch.object(w, 'remove', side_effect=remove), \
             mock.patch.object(w, 'debian_cache'), \
             mock.patch.object(w, 'image_binaries', return_value={'stamp': stamp()}), \
             mock.patch.object(q, 'graph', return_value={'manifest_digest': 'sha256:' + 'a' * 64}), \
             mock.patch.object(q.subprocess, 'check_output', side_effect=lambda args, **_: '' if args[1] == 'status' else (w.commit if args[-1] == 'HEAD' else w.inputs['tree'])), \
             mock.patch.object(compiler, 'constrain_compiler', side_effect=lambda root, env: env) as constrain, \
             mock.patch.object(candidate, 'sdk_authority', return_value=self.descriptor), \
             mock.patch.object(candidate, 'retain_sdk_and_build_probe') as retain:
            w.build(**mode)
        return exports, constrain, retain

    def test_full_fresh_ab_pinned_exporter_and_both_generations_retained(self):
        exports, constrain, retain = self.simulate_build(retained_sdk_qualification=True)
        constrain.assert_called_once()
        retain.assert_called_once_with(self.worker)
        self.assertEqual(len(exports), 12)
        for name in q.RETAINED_IMAGES:
            self.assertEqual(sum(',name=portable-ghar/' + name + ':' + q.RETAINED_VERSION + ',' in row for row in exports), 2)
        for phase in ('A', 'B'):
            self.assertEqual({p.name for p in (self.worker.artifacts / ('binaries-' + phase)).iterdir()}, q.RETAINED_BINARIES)
            self.assertEqual({p.name for p in (self.worker.artifacts / ('images-' + phase)).iterdir()}, q.RETAINED_IMAGES)
        commands = self.worker.commands
        self.assertEqual(sum(row['argv'][:2] == ['go', 'build'] for row in commands), 22)
        self.assertFalse(any('dotnet' in arg or 'Restore' in arg for row in commands for arg in row['argv']))
        result = json.loads((self.worker.output / 'build-result.json').read_text())
        self.assertEqual((result['binaries'], result['images']), (22, 12))
        self.assertFalse(result['qualification_executed'])
        self.assertFalse(result['sdk_build_executed_this_run'])

    def test_candidate_still_filters_sixth_and_discards_b(self):
        exports, _, retain = self.simulate_build(candidate_refresh=True)
        retain.assert_called_once()
        self.assertEqual(len(exports), 10)
        self.assertFalse((self.worker.artifacts / 'binaries-B').exists())
        self.assertFalse((self.worker.artifacts / 'images-B').exists())
        self.assertFalse(any('/network-broker-parser:' in row for row in exports))

    def test_fixed_go_refresh_still_filters_and_reconstruction_stays_single_phase(self):
        exports, _, retain = self.simulate_build(go_patch_refresh=True)
        retain.assert_not_called()
        self.assertEqual(len(exports), 10)
        self.assertFalse((self.worker.artifacts / 'images-B').exists())
        self.setUp()
        exports, constrain, retain = self.simulate_build(reconstruction=True)
        constrain.assert_not_called()
        retain.assert_not_called()
        self.assertEqual(len(exports), 5)
        self.assertFalse((self.worker.artifacts / 'binaries-B').exists())

    def test_legacy_still_retains_six_images_with_commit_export_names(self):
        exports, constrain, retain = self.simulate_build()
        constrain.assert_not_called()
        retain.assert_not_called()
        self.assertEqual(len(exports), 12)
        self.assertTrue(all(':' + q.RETAINED_SOURCE + ',' in row for row in exports))
        self.assertTrue((self.worker.artifacts / 'images-B').exists())

    def test_scan_requires_matching_explicit_mode_and_restores_version(self):
        self.simulate_build(retained_sdk_qualification=True)
        with self.assertRaisesRegex(q.Stop, 'explicit scan mode'):
            self.worker.scan()
        self.worker.version = 'candidate-' + self.worker.commit[:12]
        with mock.patch.object(candidate, 'sdk_authority', return_value=self.descriptor), \
             mock.patch.object(q, 'module', side_effect=RuntimeError('scanner reached')):
            with self.assertRaisesRegex(RuntimeError, 'scanner reached'):
                self.worker.scan(retained_sdk_qualification=True)
        self.assertEqual(self.worker.version, q.RETAINED_VERSION)
        image_path = self.worker.output / 'image-results.json'
        image_rows = json.loads(image_path.read_text())
        image_path.write_text(json.dumps(image_rows[:-1]))
        with mock.patch.object(candidate, 'sdk_authority', return_value=self.descriptor), self.assertRaisesRegex(q.Stop, 'image generations incomplete'):
            self.worker.scan(retained_sdk_qualification=True)
        image_path.write_text(json.dumps(image_rows))
        path = self.worker.output / 'build-result.json'
        result = json.loads(path.read_text())
        for key, value in [('version', 'wrong'), ('images', 10), ('binaries', 11), ('sdk_build_executed_this_run', True), ('source_commit', 'a' * 40)]:
            with self.subTest(key=key):
                path.write_text(json.dumps({**result, key: value}))
                with mock.patch.object(candidate, 'sdk_authority', return_value=self.descriptor), self.assertRaises(q.Stop):
                    self.worker.scan(retained_sdk_qualification=True)


if __name__ == '__main__':
    unittest.main()
