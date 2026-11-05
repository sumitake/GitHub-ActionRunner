"""Offline synthetic packaging tests; never live qualification evidence."""
# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _qualification_packaging as packaging
import _bounded_qualification as q


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class QualificationPackaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.release = q.release_functions(ROOT)
        self.debian_cache, self.go_cache = self.root / 'debian', self.root / 'go'
        self.debian_cache.mkdir()
        self.go_cache.mkdir()

    def layout(self, path):
        path.mkdir(parents=True)
        files = {}
        def blob(data, media):
            digest = hashlib.sha256(data).hexdigest()
            files['blobs/sha256/' + digest] = data
            return {'digest': 'sha256:' + digest, 'size': len(data), 'mediaType': media}
        config = blob(canonical({'architecture': 'amd64', 'os': 'linux'}), 'application/vnd.oci.image.config.v1+json')
        layer = blob(b'synthetic-layer', 'application/vnd.oci.image.layer.v1.tar')
        manifest = blob(canonical({'schemaVersion': 2, 'config': config, 'layers': [layer]}), 'application/vnd.oci.image.manifest.v1+json')
        manifest['platform'] = {'architecture': 'amd64', 'os': 'linux'}
        files['index.json'] = canonical({'schemaVersion': 2, 'manifests': [manifest],
                                         'annotations': {'org.opencontainers.image.ref.name': 'synthetic-original'}})
        files['oci-layout'] = canonical({'imageLayoutVersion': '1.0.0'})
        for name, data in reversed(list(files.items())):
            destination = path / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        return files

    def test_deterministic_archive_retains_every_original_byte_and_graph(self):
        layout = self.root / 'layout'
        files = self.layout(layout)
        a, b = self.root / 'a.tar', self.root / 'b.tar'
        first = packaging.package_oci_layout(layout, a, self.release)
        for path in layout.rglob('*'):
            os.utime(path, (100, 100))
            if path.is_file():
                path.chmod(0o600)
        second = packaging.package_oci_layout(layout, b, self.release)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        self.assertEqual(first, second)
        self.assertEqual(first['oci_graph'], q.graph(layout, self.release))
        self.assertNotEqual(first['sha256'], first['oci_graph']['manifest_digest'][7:])
        with tarfile.open(a) as archive:
            self.assertEqual(archive.getnames(), sorted(files))
            for member in archive:
                self.assertEqual(archive.extractfile(member).read(), files[member.name])
                self.assertEqual((member.uid, member.gid, member.mtime, member.mode), (0, 0, 0, 0o444))

    def test_unsafe_extra_changed_or_aliased_layout_fails(self):
        for mutation in ('extra', 'empty-directory', 'symlink', 'hardlink', 'corrupt'):
            with self.subTest(mutation=mutation):
                layout = self.root / mutation
                self.layout(layout)
                if mutation == 'extra':
                    (layout / 'unknown').write_bytes(b'unknown')
                elif mutation == 'empty-directory':
                    (layout / 'extra').mkdir()
                elif mutation == 'symlink':
                    (layout / 'unknown').symlink_to(layout / 'index.json')
                elif mutation == 'hardlink':
                    os.link(layout / 'index.json', self.root / 'alias')
                else:
                    next((layout / 'blobs/sha256').iterdir()).write_bytes(b'corrupt')
                target = self.root / (mutation + '.tar')
                with self.assertRaises((q.Stop, self.release['RehearsalError'])):
                    packaging.package_oci_layout(layout, target, self.release)
                self.assertFalse(target.exists())

    def test_existing_destination_is_never_replaced(self):
        layout = self.root / 'layout'
        self.layout(layout)
        target = self.root / 'existing'
        target.write_bytes(b'preserved')
        with self.assertRaises(q.Stop):
            packaging.package_oci_layout(layout, target, self.release)
        self.assertEqual(target.read_bytes(), b'preserved')

    def fixture_bundle(self):
        bundle = self.root / 'qualification'
        for phase in ('A', 'B'):
            binaries = bundle / 'artifacts' / ('binaries-' + phase)
            binaries.mkdir(parents=True)
            for name in packaging.BINARIES:
                (binaries / name).write_bytes(('synthetic-' + name).encode())
            for name in packaging.IMAGES:
                self.layout(bundle / 'artifacts' / ('images-' + phase) / name)
        sbom = bundle / 'sbom'
        sbom.mkdir()
        for name in (*packaging.BINARIES, *packaging.IMAGES):
            digest = (q.sha(bundle / 'artifacts/binaries-B' / name) if name in packaging.BINARIES
                      else q.graph(bundle / 'artifacts/images-B' / name, self.release)['manifest_digest'][7:])
            value = {'SPDXID': 'SPDXRef-DOCUMENT', 'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0',
                     'name': name, 'documentNamespace': 'https://example.test/synthetic',
                     'creationInfo': {'creators': ['Tool: synthetic']},
                     'packages': [{'SPDXID': 'SPDXRef-root', 'name': 'synthetic-root',
                                   'versionInfo': 'sha256:' + digest, 'primaryPackagePurpose': 'FILE',
                                   'checksums': [{'algorithm': 'SHA256', 'checksumValue': digest}]}],
                     'relationships': [{'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': 'SPDXRef-root'}]}
            (sbom / (name + '.raw.spdx.json')).write_bytes(canonical(value))
            (sbom / (name + '.spdx.json')).write_bytes(canonical({**value, 'name': 'original-qualification'}))
        bundle.chmod(0o755)
        for path in bundle.rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        (bundle / 'qualification-bundle-inventory.json').write_bytes(self.release['canonical_json'](packaging.inventory(bundle)))
        (bundle / 'qualification-bundle-inventory.json').chmod(0o644)
        return bundle

    def test_full_membership_normalization_mapping_and_unchanged_comparator(self):
        bundle = self.fixture_bundle()
        before = q.inventory(bundle)
        runtime = self.release['read_json'](ROOT / 'release/manifest.json')['runtime']
        runtime = copy.deepcopy(runtime)
        runtime['license_exceptions'] = []
        # Synthetic SBOM roots deliberately omit real SDK licensing inputs. Only
        # that supplement and public sanitizer are mocked; normalization, notices,
        # authority generation and final comparator run unchanged and offline.
        release = {**self.release, 'apply_baseline_runner_licenses': mock.Mock(return_value=[])}
        metadata = types.SimpleNamespace(complete_go_license_records=lambda *args: None, MetadataError=ValueError, load=mock.Mock(return_value={}))
        identity = {'commit': packaging.SOURCE_COMMIT, 'tree': packaging.SOURCE_TREE, 'epoch': 123}
        mappings = []
        with mock.patch.object(packaging.subprocess, 'run') as sanitizer:
            for phase in ('A', 'B'):
                mappings.append(packaging._assemble(ROOT, bundle, self.root / phase, phase,
                                                    identity, release, runtime, (metadata, {}), self.debian_cache, self.go_cache))
            self.assertEqual(sanitizer.call_count, 2)
            for call in sanitizer.call_args_list:
                self.assertIn('--verified-dependency-metadata', call.args[0])
                self.assertEqual(call.args[0][call.args[0].index('--dependency-debian-cache') + 1], str(self.debian_cache))
                self.assertEqual(call.args[0][call.args[0].index('--dependency-go-module-cache') + 1], str(self.go_cache))
        self.assertEqual(mappings[0], mappings[1])
        self.assertEqual(q.inventory(bundle), before)
        for phase in ('A', 'B'):
            stage = self.root / phase
            manifest = json.loads((stage / 'runtime-release.json').read_bytes())
            self.assertEqual(len(manifest['subjects']), 38)
            self.assertEqual(len(q.inventory(stage)), 41)
            self.assertEqual(len((stage / 'checksums.txt').read_text().splitlines()), 39)
            self.assertEqual(len(json.loads((stage / 'provenance-subjects.json').read_bytes())['subjects']), 40)
            self.assertEqual(manifest['source'], {'commit': identity['commit'], 'tree': identity['tree'], 'source_date_epoch': 123})
            self.assertFalse(any('tar.gz' in r['path'] for r in q.inventory(stage)))
            for row in mappings[0]:
                value = json.loads((stage / 'sbom' / (row['subject'] + '.spdx.json')).read_bytes())
                self.assertTrue(value['documentNamespace'].endswith('/' + row['namespace_sha256']))
                if row['subject'] in packaging.IMAGES:
                    self.assertNotEqual(row['namespace_sha256'], row['notices_root_sha256'])
        result = subprocess.run(['bash', str(ROOT / 'scripts/release/compare-runtime-rebuilds.sh'),
                                 str(self.root / 'A'), str(self.root / 'B')], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        runner_call = release['apply_baseline_runner_licenses'].call_args
        runner_mapping = next(r for r in mappings[0] if r['subject'] == 'runner')
        self.assertEqual(runner_call.args[4], runner_mapping['notices_root_sha256'])

    def test_full_payload_comparison_rejects_changed_or_missing_sixth_image(self):
        bundle = self.fixture_bundle()
        packaging._exact_payloads(bundle)
        parser = bundle / 'artifacts/images-B/network-broker-parser/index.json'
        parser.write_bytes(parser.read_bytes() + b' ')
        with self.assertRaises(q.Stop):
            packaging._exact_payloads(bundle)
        shutil.rmtree(parser.parent)
        with self.assertRaises(q.Stop):
            packaging._exact_payloads(bundle)

    def test_complete_bundle_inventory_is_required_before_output(self):
        bundle = self.fixture_bundle()
        expected = packaging.inventory(bundle)
        (bundle / 'extra.json').write_text('{}')
        with mock.patch.object(packaging, '_checkout'), self.assertRaisesRegex(q.Stop, 'complete input inventory'):
            packaging.assemble_release_pair(ROOT, ROOT, bundle, self.root / 'new',
                source_identity={'commit': packaging.SOURCE_COMMIT, 'tree': packaging.SOURCE_TREE, 'epoch': 123},
                tooling_identity={'commit': 'a' * 40, 'tree': 'b' * 40},
                public_evidence=None, expected_inventory=expected,
                dependency_debian_cache=self.debian_cache, dependency_go_module_cache=self.go_cache)
        self.assertFalse((self.root / 'new').exists())

    def test_pair_receipt_binds_source_tooling_and_preserves_false_authority(self):
        bundle = self.fixture_bundle()
        release = {**self.release, 'apply_baseline_runner_licenses': lambda *args, **kwargs: []}
        metadata = types.SimpleNamespace(complete_go_license_records=lambda *args: None, MetadataError=ValueError, load=mock.Mock(return_value={}))
        source = {'commit': packaging.SOURCE_COMMIT, 'tree': packaging.SOURCE_TREE, 'epoch': 123}
        tooling = {'commit': 'a' * 40, 'tree': 'b' * 40}
        actual_run = subprocess.run
        def commands(args, **kwargs):
            if args[0] == 'bash':
                return actual_run(args, **kwargs)
            self.assertEqual(Path(args[1]).name, 'sanitize_public.py')
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.object(packaging, '_checkout'), mock.patch.object(q, 'module', return_value=metadata), mock.patch.object(q, 'release_functions', return_value=release), mock.patch.object(packaging.subprocess, 'run', side_effect=commands):
            receipt = packaging.assemble_release_pair(ROOT, ROOT, bundle, self.root / 'output',
                source_identity=source, tooling_identity=tooling,
                public_evidence=(metadata, {}), expected_inventory=packaging.inventory(bundle),
                dependency_debian_cache=self.debian_cache, dependency_go_module_cache=self.go_cache)
        self.assertEqual(receipt['source'], source)
        self.assertEqual(receipt['tooling'], tooling)
        self.assertEqual(receipt['comparison'], 'equal')
        self.assertEqual(len(receipt['assets']), 41)
        for row in receipt['assets']:
            self.assertEqual(row['mode'], '0555' if row['path'].startswith('bin/') else '0444')
        self.assertIsInstance(receipt, packaging.PreparedAssets)
        self.assertIs(packaging.revalidate_prepared_assets(receipt), receipt)
        self.assertEqual(receipt['qualification_bundle_inventory_sha256'], q.sha(bundle / 'qualification-bundle-inventory.json'))
        self.assertEqual(receipt.qualification_root, bundle)
        self.assertEqual(receipt.output, self.root / 'output')
        with self.assertRaises(q.Stop):
            packaging.revalidate_prepared_assets(dict(receipt))
        (receipt.output / 'B/sbom/runner.spdx.json').chmod(0o600)
        with self.assertRaisesRegex(q.Stop, 'bytes or modes changed'):
            packaging.revalidate_prepared_assets(receipt)
        (receipt.output / 'B/sbom/runner.spdx.json').chmod(0o444)
        receipt['comparison'] = 'supplied-pass'
        with self.assertRaisesRegex(q.Stop, 'receipt changed'):
            packaging.revalidate_prepared_assets(receipt)
        receipt['comparison'] = 'equal'
        for key in ('qualification_executed', 'artifact_qualification_admitted', 'publication_authorized', 'deployment_authorized'):
            self.assertIs(receipt[key], False)
        self.assertFalse((self.root / 'output/A/qualification-result.json').exists())
        self.assertEqual(receipt['qualification_inventory_rows_sha256'], hashlib.sha256(release['canonical_json'](packaging.inventory(bundle))).hexdigest())

    def test_mode_drift_is_not_hidden_by_unchanged_bytes(self):
        bundle = self.fixture_bundle()
        expected = packaging.inventory(bundle)
        (bundle / 'sbom/runner.spdx.json').chmod(0o600)
        with mock.patch.object(packaging, '_checkout'), self.assertRaisesRegex(q.Stop, 'complete input inventory'):
            packaging.assemble_release_pair(ROOT, ROOT, bundle, self.root / 'new',
                source_identity={'commit': packaging.SOURCE_COMMIT, 'tree': packaging.SOURCE_TREE, 'epoch': 123},
                tooling_identity={'commit': 'a' * 40, 'tree': 'b' * 40},
                public_evidence=None, expected_inventory=expected,
                dependency_debian_cache=self.debian_cache, dependency_go_module_cache=self.go_cache)

    def test_metadata_is_reauthenticated_from_explicit_caches_not_trusted_tuple(self):
        producer = types.SimpleNamespace(load=mock.Mock(return_value={'verified': 'original'}))
        supplied = (object(), {'verified': 'original'})
        with mock.patch.object(q, 'module', return_value=producer) as loader:
            observed = packaging._dependency_evidence(ROOT, supplied, self.debian_cache, self.go_cache)
            self.assertIs(observed[0], producer)
            loader.assert_called_once_with(ROOT, 'public_dependency_metadata.py')
            producer.load.assert_called_once_with(ROOT, debian_cache=self.debian_cache, go_module_cache=self.go_cache)
            with self.assertRaisesRegex(q.Stop, 'metadata binding mismatch'):
                packaging._dependency_evidence(ROOT, (object(), {'verified': 'changed'}), self.debian_cache, self.go_cache)

    def test_real_metadata_and_sanitizer_reject_missing_explicit_cache_inputs(self):
        producer = q.module(ROOT, 'public_dependency_metadata.py')
        with self.assertRaises(producer.MetadataError):
            producer.load(ROOT, debian_cache=self.debian_cache, go_module_cache=self.go_cache)
        generated = self.root / 'generated.txt'
        generated.write_text('Synthetic public text\n')
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/sanitize_public.py'),
            '--verified-dependency-metadata', '--dependency-debian-cache', str(self.debian_cache),
            '--dependency-go-module-cache', str(self.go_cache), '--generated', str(generated)],
            cwd=ROOT, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'unverified public dependency metadata', result.stdout)

    def test_prepared_assets_constructor_rejects_supplied_receipts_and_unsealed_instances(self):
        with self.assertRaises(q.Stop):
            packaging.PreparedAssets({}, qualification_root=self.root, output=self.root,
                source_identity={}, tooling_identity={}, qualification_inventory=[])
        with self.assertRaises(q.Stop):
            packaging.revalidate_prepared_assets(dict.__new__(packaging.PreparedAssets))

    def test_assembly_requires_original_bundle_inventory_file(self):
        bundle = self.fixture_bundle()
        (bundle / 'qualification-bundle-inventory.json').unlink()
        with mock.patch.object(packaging, '_checkout'), self.assertRaises(FileNotFoundError):
            packaging.assemble_release_pair(ROOT, ROOT, bundle, self.root / 'new',
                source_identity={'commit': packaging.SOURCE_COMMIT, 'tree': packaging.SOURCE_TREE, 'epoch': 123},
                tooling_identity={'commit': 'a' * 40, 'tree': 'b' * 40},
                public_evidence=None, expected_inventory=packaging.inventory(bundle),
                dependency_debian_cache=self.debian_cache, dependency_go_module_cache=self.go_cache)
        self.assertFalse((self.root / 'new').exists())

    def test_publication_bundle_is_deterministic_and_retains_exact_asset_modes(self):
        bundle = self.fixture_bundle()
        release = {**self.release, 'apply_baseline_runner_licenses': lambda *args, **kwargs: []}
        metadata = types.SimpleNamespace(complete_go_license_records=lambda *args: None,
                                        MetadataError=ValueError, load=lambda *args, **kwargs: {})
        actual_run = subprocess.run
        def commands(args, **kwargs):
            return actual_run(args, **kwargs) if args[0] == 'bash' else subprocess.CompletedProcess(args, 0)
        with mock.patch.object(packaging, '_checkout'), mock.patch.object(q, 'module', return_value=metadata), mock.patch.object(q, 'release_functions', return_value=release), mock.patch.object(packaging.subprocess, 'run', side_effect=commands):
            prepared = packaging.assemble_release_pair(ROOT, ROOT, bundle, self.root / 'output',
                source_identity={'commit': packaging.SOURCE_COMMIT, 'tree': packaging.SOURCE_TREE, 'epoch': 123},
                tooling_identity={'commit': 'a' * 40, 'tree': 'b' * 40}, public_evidence=(metadata, {}),
                expected_inventory=packaging.inventory(bundle), dependency_debian_cache=self.debian_cache,
                dependency_go_module_cache=self.go_cache)
        first = packaging.seal_publication_bundle(prepared, self.root / 'first.tar')
        second = packaging.seal_publication_bundle(prepared, self.root / 'second.tar')
        self.assertEqual(first['sha256'], second['sha256'])
        self.assertEqual(first['bytes'], second['bytes'])
        self.assertEqual(first['assets'], prepared['assets'])
        with tarfile.open(self.root / 'first.tar') as archive:
            self.assertEqual(archive.getnames(), [r['path'] for r in prepared['assets']])
            for member, row in zip(archive, prepared['assets']):
                self.assertEqual(member.mode, int(row['mode'], 8))
                self.assertEqual(member.size, row['bytes'])
                self.assertEqual(hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest(), row['sha256'])
        with self.assertRaises(q.Stop):
            packaging.seal_publication_bundle(dict(prepared), self.root / 'untrusted.tar')
        with self.assertRaises(q.Stop):
            packaging.seal_publication_bundle(prepared, self.root / 'first.tar')
        with self.assertRaises(q.Stop):
            packaging.seal_publication_bundle(prepared, prepared.output / 'nested.tar')
        (prepared.output / 'B/sbom/runner.spdx.json').chmod(0o600)
        with self.assertRaises(q.Stop):
            packaging.seal_publication_bundle(prepared, self.root / 'changed.tar')
        self.assertFalse((self.root / 'changed.tar').exists())

    def test_release_pair_modes_and_archive_are_independent_of_caller_umask(self):
        bundle = self.fixture_bundle()
        expected = packaging.inventory(bundle)
        release = {**self.release, 'apply_baseline_runner_licenses': lambda *args, **kwargs: []}
        metadata = types.SimpleNamespace(complete_go_license_records=lambda *args: None,
                                        MetadataError=ValueError, load=lambda *args, **kwargs: {})
        actual_run = subprocess.run
        def commands(args, **kwargs):
            return actual_run(args, **kwargs) if args[0] == 'bash' else subprocess.CompletedProcess(args, 0)
        archives = []
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)):
                previous = os.umask(mask)
                try:
                    with mock.patch.object(packaging, '_checkout'), mock.patch.object(q, 'module', return_value=metadata), mock.patch.object(q, 'release_functions', return_value=release), mock.patch.object(packaging.subprocess, 'run', side_effect=commands):
                        prepared = packaging.assemble_release_pair(ROOT, ROOT, bundle, self.root / ('output-' + str(mask)),
                            source_identity={'commit': packaging.SOURCE_COMMIT, 'tree': packaging.SOURCE_TREE, 'epoch': 123},
                            tooling_identity={'commit': 'a' * 40, 'tree': 'b' * 40}, public_evidence=(metadata, {}),
                            expected_inventory=expected, dependency_debian_cache=self.debian_cache,
                            dependency_go_module_cache=self.go_cache)
                    self.assertIs(packaging.revalidate_prepared_assets(prepared), prepared)
                    for directory in (prepared.output, *(p for p in prepared.output.rglob('*') if p.is_dir())):
                        self.assertEqual(directory.stat().st_mode & 0o7777, 0o755)
                    for row in prepared['assets']:
                        self.assertEqual(row['mode'], '0555' if row['path'].startswith('bin/') else '0444')
                    target = self.root / ('bundle-' + str(mask) + '.tar')
                    packaging.seal_publication_bundle(prepared, target)
                    archives.append(target.read_bytes())
                    self.assertEqual(packaging.inventory(bundle), expected)
                    self.assertEqual(os.umask(mask), mask)
                finally:
                    os.umask(previous)
        self.assertEqual(len(archives), 2)
        self.assertEqual(archives[0], archives[1])

    def test_source_identity_cannot_be_tooling_identity(self):
        with self.assertRaisesRegex(q.Stop, 'product source'):
            packaging.assemble_release_pair(ROOT, ROOT, self.root, self.root / 'new',
                source_identity={'commit': 'a' * 40, 'tree': 'b' * 40, 'epoch': 123},
                tooling_identity={'commit': packaging.SOURCE_COMMIT, 'tree': packaging.SOURCE_TREE},
                public_evidence=None, expected_inventory=[],
                dependency_debian_cache=self.debian_cache, dependency_go_module_cache=self.go_cache)


if __name__ == '__main__':
    unittest.main()
