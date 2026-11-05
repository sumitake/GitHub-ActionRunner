"""Synthetic contract tests, not observed qualification or publication evidence."""
# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import io
import json
import os
import pathlib
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _retained_qualification as retained
import _bounded_qualification as q
import _trivy_report


def identity():
    def execution(commit, run):
        return dict(repository='sumitake/' + 'GitHub-ActionRunner', actor='sumitake',
                    workflow_path='.github/workflows/ci.yml', workflow_commit=commit,
                    workflow_blob='c' * 40, run_id=run, run_attempt=1, job_id=run + 1,
                    artifact_name='synthetic-evidence')
    candidate = execution(retained.SOURCE_COMMIT, 1)
    candidate.update(conclusion='success', artifact=dict(id=1, name='synthetic-evidence', bytes=1, sha256='d' * 64))
    return dict(source_commit=retained.SOURCE_COMMIT, source_tree=retained.SOURCE_TREE,
                tooling_commit='a' * 40, tooling_tree='b' * 40,
                candidate_execution=candidate, qualification_execution=execution('a' * 40, 3))


class RetainedQualification(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir(mode=0o755)
        self.bundle.chmod(0o755)

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        for directory in path.relative_to(self.bundle).parents:
            (self.bundle / directory).chmod(0o755)
        path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value, indent=2) + '\n').encode())
        path.chmod(0o644)

    def fixture(self):
        names = retained.BUILD_REPORTS | retained.SCAN_REPORTS | {
            'sbom/' + name + '.spdx.json' for name in retained.BINARIES | retained.IMAGES} | {
            'THIRD-PARTY-NOTICES.txt', 'binary-comparison.json', 'image-results.json',
            'source-inputs.json', 'source-acquisition.json', 'sdk-retained.json',
            'selected-payload.json', 'go-compiler.json', 'tool-syft.json', 'tool-trivy.json',
            'scanner-database-before.json', 'scanner-database-after.json',
            'trivy-report-rendering.json', 'runner-reported-CVE-clearance.json',
            'security-results.json', 'build-result.json', 'scan-result.json',
            'producer-publication-stages.json', 'export-policy.json', 'terminal.json',
            'RESULT.json', 'resource-samples.jsonl', 'candidate-image-smoke.json',
            'worker-terminal.json', 'scan-terminal.json'}
        for name in names:
            if not (self.bundle / name).exists():
                self.put(self.bundle / name, b'{"synthetic":true}\n')
        subjects = dict(schema_version=1, specification_sha256=retained.SPEC_SHA256,
                        identities=identity(), source_inputs=[], version=retained.VERSION,
                        subjects=[dict(kind=kind, name=name) for kind, names in
                                  [('binary', retained.BINARIES), ('image', retained.IMAGES)] for name in sorted(names)])
        self.put(self.bundle / retained.SUBJECTS, subjects)
        self.reseal()

    def reseal(self):
        rows = retained.inventory(self.bundle, exclude=retained.SIDECARS)
        self.put(self.bundle / retained.WORKER_INVENTORY,
                 dict(schema_version=1, identities=identity(), files=rows))
        result = dict(schema_version=1, identities=identity(),
                      qualification_subjects_sha256=q.sha(self.bundle / retained.SUBJECTS),
                      worker_evidence_inventory_sha256=q.sha(self.bundle / retained.WORKER_INVENTORY),
                      qualification_executed=True, artifact_qualification_admitted=True,
                      workers_joined=True, scope_exit_code=0, resource_qualification='pass',
                      public_evidence_sanitization='pass', unsafe_text_withheld=[],
                      binary_count=11, image_count=6, sbom_count=17, producer_report_count=40,
                      **retained.FALSE_AUTHORITY)
        self.put(self.bundle / retained.RESULT, result)
        self.finalize()

    def finalize(self):
        self.put(self.bundle / retained.FINAL_INVENTORY,
                 dict(schema_version=1, identities=identity(),
                      files=retained.inventory(self.bundle, exclude={retained.FINAL_INVENTORY})))

    def archive(self, destination, rows, *, mutate=None):
        with tarfile.open(destination, 'w', format=tarfile.USTAR_FORMAT) as stream:
            for row in rows:
                info = tarfile.TarInfo(row['path'])
                data = (self.bundle / row['path']).read_bytes()
                info.size, info.mode = len(data), int(row['mode'], 8)
                if mutate:
                    data = mutate(info, data)
                    info.size = len(data)
                stream.addfile(info, io.BytesIO(data))

    def test_buildkit_directory_export_uses_tag_and_normalized_image_name(self):
        # Source-derived synthetic index, NOT bytes from an actual build/run.
        # BuildKit v0.32.0 commit f5d08d5a04381687203ced27ef877e0c417fd122:
        # exporter/oci/export.go normalizedNames; client/solve.go store update;
        # client/ociindex/ociindex.go insertDesc and ociReferenceName.
        path = ROOT / 'tests/fixtures/retained-qualification/buildkit-v0.32.0/index.json'
        raw = path.read_bytes()
        index = retained.read(path)
        retained.verify_exporter_reference(index, 'runner')
        self.assertEqual(path.read_bytes(), raw)
        annotations = index['manifests'][0]['annotations']
        for key, value in [
            ('org.opencontainers.image.ref.name', 'portable-ghar/runner:' + retained.VERSION),
            ('org.opencontainers.image.ref.name', 'wrong-tag'),
            ('io.containerd.image.name', 'portable-ghar/runner:' + retained.VERSION),
            ('io.containerd.image.name', 'docker.io/portable-ghar/other:' + retained.VERSION),
            ('io.containerd.image.name', 'docker.io/portable-ghar/runner:wrong-tag'),
        ]:
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(index)
                changed['manifests'][0]['annotations'][key] = value
                with self.assertRaises(q.Stop): retained.verify_exporter_reference(changed, 'runner')
        for key in annotations:
            changed = copy.deepcopy(index)
            del changed['manifests'][0]['annotations'][key]
            with self.assertRaises(q.Stop): retained.verify_exporter_reference(changed, 'runner')
        changed = copy.deepcopy(index)
        changed['manifests'].append(copy.deepcopy(changed['manifests'][0]))
        with self.assertRaises(q.Stop): retained.verify_exporter_reference(changed, 'runner')

    def test_zip_preflights_all_sizes_before_any_inflation(self):
        self.put(self.bundle / 'one', b'one')
        rows = retained.inventory(self.bundle)
        path = self.root / 'oversized.zip'
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            entry = zipfile.ZipInfo('one')
            entry.create_system, entry.external_attr = 3, (0o100644 << 16)
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, b'x' * (2 * 2**20))
        self.assertLess(path.stat().st_size, 4096)
        for expected in (rows, [{**rows[0], 'bytes': 2 * 2**20}]):
            with mock.patch.object(q, 'ARTIFACT_LIMIT', 4096), mock.patch.object(retained.zlib, 'decompressobj', side_effect=AssertionError('inflation before preflight')):
                with self.assertRaises(q.Stop): retained.verify_archive(path, expected)

    def test_zip_understated_central_count_fails_before_index_allocation(self):
        self.put(self.bundle / 'one', b'one')
        rows = retained.inventory(self.bundle)
        path = self.root / 'many-members.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for number in range(1000):
                entry = zipfile.ZipInfo('one' if number == 0 else 'extra-' + str(number))
                entry.create_system, entry.external_attr = 3, (0o100644 << 16)
                archive.writestr(entry, b'one')
        raw = bytearray(path.read_bytes())
        struct.pack_into('<2H', raw, len(raw) - 22 + 8, 1, 1)
        path.write_bytes(raw)
        with mock.patch.object(retained.zipfile, 'ZipFile', side_effect=AssertionError('allocated ZIP index before central validation')):
            with self.assertRaises(q.Stop): retained.verify_archive(path, rows)

    def test_publication_tar_requires_exact_order_and_native_headers(self):
        self.put(self.bundle / 'one', b'one')
        self.put(self.bundle / 'two', b'two')
        rows = [{**row, 'mode': '0444'} for row in retained.inventory(self.bundle)]
        path = self.root / 'publication.tar'
        self.archive(path, rows)
        retained.verify_archive(path, rows, publication=True)
        for mutation in ('order', 'uid', 'gid', 'mtime', 'uname', 'gname'):
            with self.subTest(mutation=mutation):
                def alter(info, data):
                    if mutation != 'order':
                        setattr(info, mutation, 'synthetic' if mutation in ('uname', 'gname') else 123)
                    return data
                self.archive(path, list(reversed(rows)) if mutation == 'order' else rows, mutate=alter)
                with self.assertRaises(q.Stop): retained.verify_archive(path, rows, publication=True)

    def test_checkout_hashes_bytes_despite_index_optimization_flags(self):
        import subprocess
        import _qualification_packaging as packaging
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                source = self.root / flag[2:]
                source.mkdir()
                def git(*args):
                    return subprocess.check_output(['git', *args], cwd=source, text=True, stderr=subprocess.DEVNULL).strip()
                git('init', '-q')
                helper = source / 'helper.py'
                helper.write_text('original = True\n')
                helper.chmod(0o644)
                git('add', 'helper.py')
                git('-c', 'user.name=Synthetic', '-c', 'user.email=operator@example.invalid',
                    '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic fixture')
                commit, tree = git('rev-parse', 'HEAD', 'HEAD^{tree}').splitlines()
                retained.verify_checkout(source, commit, tree)
                packaging._checkout(source, {'commit': commit, 'tree': tree})
                git('update-index', flag, 'helper.py')
                helper.write_text('modified = True\n')
                self.assertEqual(git('status', '--porcelain', '--untracked-files=all'), '')
                with self.assertRaises(q.Stop): retained.verify_checkout(source, commit, tree)
                with self.assertRaises(q.Stop): packaging._checkout(source, {'commit': commit, 'tree': tree})

    def test_memberships_are_exact_and_distinct(self):
        self.assertEqual((len(retained.BINARIES), len(retained.CANDIDATE_IMAGES),
                          len(retained.IMAGES), len(retained.BUILD_REPORTS), len(retained.SCAN_REPORTS)), (11, 5, 6, 13, 27))
        self.assertFalse(retained.BUILD_REPORTS & retained.SCAN_REPORTS)
        self.fixture()
        document = retained.verify_chain(self.bundle, identity())
        self.assertEqual(document['identities'], identity())
        self.assertEqual(len(document['subjects']), 17)

    def test_hard_binding_uses_original_bytes_not_reserialized_json(self):
        self.fixture()
        path = self.bundle / retained.SUBJECTS
        path.write_bytes(path.read_bytes() + b' ')
        self.finalize()
        with self.assertRaisesRegex(q.Stop, 'hard hash'):
            retained.verify_chain(self.bundle, identity())

    def test_worker_and_final_inventories_are_one_way_not_circular(self):
        self.fixture()
        worker = retained.read(self.bundle / retained.WORKER_INVENTORY)
        final = retained.read(self.bundle / retained.FINAL_INVENTORY)
        self.assertFalse(retained.SIDECARS & {r['path'] for r in worker['files']})
        self.assertEqual(retained.SIDECARS & {r['path'] for r in final['files']},
                         retained.SIDECARS - {retained.FINAL_INVENTORY})
        worker['files'].append(retained.file_record(self.bundle, retained.SUBJECTS))
        self.put(self.bundle / retained.WORKER_INVENTORY, worker)
        result = retained.read(self.bundle / retained.RESULT)
        result['worker_evidence_inventory_sha256'] = q.sha(self.bundle / retained.WORKER_INVENTORY)
        self.put(self.bundle / retained.RESULT, result)
        self.finalize()
        with self.assertRaisesRegex(q.Stop, 'wrong evidence'):
            retained.verify_chain(self.bundle, identity())

    def test_tuple_drift_missing_fields_and_authority_escalation_fail(self):
        self.fixture()
        path = self.bundle / retained.RESULT
        baseline = retained.read(path)
        for key, value in [('release_admitted', True), ('deployment_admitted', True),
                           ('workers_joined', False), ('scope_exit_code', False),
                           ('image_count', 5), ('producer_report_count', 41),
                           ('unsafe_text_withheld', ['synthetic']), ('public_evidence_sanitization', 'pending')]:
            with self.subTest(key=key):
                self.put(path, {**baseline, key: value})
                self.finalize()
                with self.assertRaises(q.Stop): retained.verify_chain(self.bundle, identity())
        for key in ('qualification_subjects_sha256', 'worker_evidence_inventory_sha256'):
            changed = dict(baseline)
            changed.pop(key)
            self.put(path, changed)
            self.finalize()
            with self.assertRaises(q.Stop): retained.verify_chain(self.bundle, identity())
        changed = copy.deepcopy(baseline)
        changed['identities']['qualification_execution']['job_id'] += 1
        self.put(path, changed)
        self.finalize()
        with self.assertRaises(q.Stop): retained.verify_chain(self.bundle, identity())

    def test_replaced_or_missing_reports_cannot_pass_by_count(self):
        self.fixture()
        original = self.bundle / 'security-image-network-broker-parser.json'
        original.rename(self.bundle / 'security-image-invented.json')
        self.reseal()
        with self.assertRaisesRegex(q.Stop, '13 build / 27 scan'):
            retained.verify_chain(self.bundle, identity())

    def test_missing_subject_extra_file_and_duplicate_keys_fail(self):
        self.fixture()
        path = self.bundle / retained.SUBJECTS
        doc = retained.read(path)
        doc['subjects'][-1] = doc['subjects'][0]
        self.put(path, doc)
        self.reseal()
        with self.assertRaisesRegex(q.Stop, 'subject manifest membership'):
            retained.verify_chain(self.bundle, identity())
        self.put(path, b'{"a":1,"a":2}')
        with self.assertRaises(_trivy_report.ReportError): retained.read(path)
        self.put(path, b'{"a":NaN}')
        with self.assertRaises(_trivy_report.ReportError): retained.read(path)
        self.put(path, doc)
        self.put(self.bundle / 'unstaged.txt', b'synthetic')
        with self.assertRaises(q.Stop): retained.verify_chain(self.bundle, identity())

    def test_source_tooling_and_execution_identities_are_distinct(self):
        baseline = identity()
        self.assertEqual(retained.identities(baseline), baseline)
        for key, value in [('source_commit', 'f' * 40), ('tooling_commit', retained.SOURCE_COMMIT),
                           ('tooling_tree', retained.SOURCE_TREE)]:
            with self.assertRaises(q.Stop): retained.identities({**baseline, key: value})
        for key, value in [('run_attempt', True), ('actor', 'other'), ('workflow_commit', retained.SOURCE_COMMIT), ('artifact', {})]:
            changed = copy.deepcopy(baseline)
            changed['qualification_execution'][key] = value
            with self.assertRaises(q.Stop): retained.identities(changed)
        changed = copy.deepcopy(baseline)
        changed['candidate_execution']['conclusion'] = 'failure'
        with self.assertRaises(q.Stop): retained.identities(changed)

    def test_unsafe_paths_modes_links_and_empty_directories_fail(self):
        for value in ('../outside', '/absolute', 'a//b', 'a/./b', 'a\\b', 'a\nb'):
            with self.assertRaises(q.Stop): retained.relative(value)
        target = self.bundle / 'safe'
        self.put(target, b'synthetic')
        target.chmod(0o600)
        with self.assertRaises(q.Stop): retained.inventory(self.bundle)
        target.chmod(0o644)
        alias = self.bundle / 'alias'
        os.link(target, alias)
        with self.assertRaises(q.Stop): retained.inventory(self.bundle)
        alias.unlink()
        alias.symlink_to(target)
        with self.assertRaises(q.Stop): retained.inventory(self.bundle)
        alias.unlink()
        (self.bundle / 'empty').mkdir()
        with self.assertRaises(q.Stop): retained.inventory(self.bundle)

    def test_full_archive_rehashed_without_extraction(self):
        self.put(self.bundle / 'one', b'one')
        self.put(self.bundle / 'sub/two', b'two')
        rows = retained.inventory(self.bundle)
        archive = self.root / 'evidence.tar'
        self.archive(archive, rows)
        retained.verify_archive(archive, rows)
        self.assertEqual(set(self.root.iterdir()), {self.bundle, archive})
        for name, mutate in [
            ('traversal', lambda i, b: (setattr(i, 'name', '../outside'), b)[1]),
            ('duplicate', lambda i, b: (setattr(i, 'name', 'one'), b)[1]),
            ('mode', lambda i, b: (setattr(i, 'mode', 0o777), b)[1]),
            ('changed', lambda i, b: b'changed'),
            ('link', lambda i, b: (setattr(i, 'type', tarfile.SYMTYPE), b)[1]),
        ]:
            with self.subTest(name=name):
                self.archive(archive, rows, mutate=mutate)
                with self.assertRaises(q.Stop): retained.verify_archive(archive, rows)

    def test_archive_hidden_tail_prefix_and_extension_records_fail(self):
        self.put(self.bundle / 'one', b'one')
        rows = retained.inventory(self.bundle)
        archive = self.root / 'evidence.tar'
        self.archive(archive, rows)
        original = archive.read_bytes()
        for suffix in (b'hidden', original):
            archive.write_bytes(original + suffix)
            with self.assertRaises(q.Stop): retained.verify_archive(archive, rows)
        archive.write_bytes(original)
        with tarfile.open(archive, 'w', format=tarfile.GNU_FORMAT) as stream:
            entry = tarfile.TarInfo('one')
            entry.size, entry.mode = 3, 0o644
            stream.addfile(entry, io.BytesIO(b'one'))
        with self.assertRaises(q.Stop): retained.verify_archive(archive, rows)
        path = self.root / 'evidence.zip'
        with zipfile.ZipFile(path, 'w') as stream:
            entry = zipfile.ZipInfo('one')
            entry.create_system, entry.external_attr = 3, (0o100644 << 16)
            stream.writestr(entry, b'one')
        original = path.read_bytes()
        for raw in (original + b'hidden', b'hidden' + original):
            path.write_bytes(raw)
            with self.assertRaises(q.Stop): retained.verify_archive(path, rows)

    def test_deflate_hidden_compressed_suffix_is_rejected(self):
        self.put(self.bundle / 'one', b'one')
        rows = retained.inventory(self.bundle)
        path = self.root / 'evidence.zip'
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            entry = zipfile.ZipInfo('one')
            entry.create_system, entry.external_attr = 3, (0o100644 << 16)
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, b'one')
        retained.verify_archive(path, rows)
        with zipfile.ZipFile(path) as archive:
            start = archive.start_dir
            compressed = archive.getinfo('one').compress_size
        hidden = b'synthetic-hidden-data'
        raw = bytearray(path.read_bytes())
        raw[start:start] = hidden
        struct.pack_into('<I', raw, 18, compressed + len(hidden))
        struct.pack_into('<I', raw, start + len(hidden) + 20, compressed + len(hidden))
        struct.pack_into('<I', raw, len(raw) - 22 + 16, start + len(hidden))
        path.write_bytes(raw)
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(archive.read('one'), b'one')
        with self.assertRaises(q.Stop): retained.verify_archive(path, rows)

    def test_complete_zip_checks_native_modes_and_membership(self):
        self.put(self.bundle / 'one', b'one')
        rows = retained.inventory(self.bundle)
        path = self.root / 'evidence.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            entry = zipfile.ZipInfo('one')
            entry.create_system, entry.external_attr = 3, (0o100644 << 16)
            archive.writestr(entry, b'one')
        retained.verify_archive(path, rows)
        with zipfile.ZipFile(path, 'w') as archive:
            entry = zipfile.ZipInfo('one')
            entry.create_system, entry.external_attr = 3, (0o120777 << 16)
            archive.writestr(entry, b'one')
        with self.assertRaises(q.Stop): retained.verify_archive(path, rows)

    def test_committed_legal_inputs_and_read_only_entrypoint(self):
        records = retained.source_inputs(ROOT)
        names = {row['path'] for row in records}
        self.assertTrue(set(retained.INPUT_PATHS) <= names)
        self.assertTrue(any(name.startswith('release/runner-license-texts/') for name in names))
        self.assertFalse(any('/build/' in name for name in names))
        import subprocess
        completed = subprocess.run([sys.executable, str(ROOT / 'scripts/release/verify-retained-qualification.py'), '--help'],
                                   capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('--candidate-archive', completed.stdout)
        self.assertNotIn('--host', completed.stdout)

    def test_handoff_requires_actual_prepared_assets_and_joins_their_exact_bytes(self):
        import subprocess
        import types
        import _qualification_packaging as packaging
        from tests.repository.test_qualification_packaging import QualificationPackaging
        fixture = QualificationPackaging()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.bundle = fixture.fixture_bundle()
        self.fixture()
        release = {**fixture.release, 'apply_baseline_runner_licenses': lambda *args, **kwargs: []}
        metadata = types.SimpleNamespace(complete_go_license_records=lambda *args: None,
                                        MetadataError=ValueError, load=lambda *args, **kwargs: {})
        actual_run = subprocess.run
        def commands(args, **kwargs):
            return actual_run(args, **kwargs) if args[0] == 'bash' else subprocess.CompletedProcess(args, 0)
        with mock.patch.object(packaging, '_checkout'), mock.patch.object(q, 'module', return_value=metadata), mock.patch.object(q, 'release_functions', return_value=release), mock.patch.object(packaging.subprocess, 'run', side_effect=commands):
            prepared = packaging.assemble_release_pair(ROOT, ROOT, self.bundle, fixture.root / 'output',
                source_identity={'commit': packaging.SOURCE_COMMIT, 'tree': packaging.SOURCE_TREE, 'epoch': 123},
                tooling_identity={'commit': 'a' * 40, 'tree': 'b' * 40}, public_evidence=(metadata, {}),
                expected_inventory=packaging.inventory(self.bundle), dependency_debian_cache=fixture.debian_cache,
                dependency_go_module_cache=fixture.go_cache)
        qualified, published = self.root / 'qualification.tar', self.root / 'publication.tar'
        self.archive(qualified, retained.inventory(self.bundle))
        packaging.seal_publication_bundle(prepared, published)
        def transport(path, identifier):
            return dict(id=identifier, name='synthetic-evidence', bytes=path.stat().st_size, sha256=q.sha(path))
        canonical = (json.dumps(dict(prepared), sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
        handoff = dict(schema_version=1, identities=identity(),
                       qualification_subjects_sha256=q.sha(self.bundle / retained.SUBJECTS),
                       qualification_result_sha256=q.sha(self.bundle / retained.RESULT),
                       qualification_inventory_sha256=q.sha(self.bundle / retained.FINAL_INVENTORY),
                       qualification_artifact=transport(qualified, 2), publication_artifact=transport(published, 3),
                       packaging_tooling=dict(commit='a' * 40, tree='b' * 40, files=prepared['tooling_files'], method=prepared['packaging_method']),
                       packaging_receipt_sha256=hashlib.sha256(canonical).hexdigest(),
                       assets=prepared['assets'], attestation_subjects=prepared['assets'],
                       comparator=dict(status='pass', independent_payload_generations=['A', 'B'], independent_metadata_generations=False),
                       **retained.FALSE_AUTHORITY)
        verified = retained.verify_handoff(self.bundle, qualified, published, handoff, identity(), prepared=prepared)
        self.assertTrue(verified['content_consistent'])
        self.assertFalse(verified['external_execution_verified'])
        self.assertFalse(verified['publication_authorized'])
        with self.assertRaises(q.Stop):
            retained.verify_handoff(self.bundle, qualified, published, handoff, identity(), prepared=dict(prepared))
        changed = copy.deepcopy(handoff)
        changed['assets'][0]['sha256'] = 'a' * 64
        with self.assertRaises(q.Stop):
            retained.verify_handoff(self.bundle, qualified, published, changed, identity(), prepared=prepared)

    def test_legacy_host_rejection_remains(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('retained_host_test', ROOT / 'scripts/release/qualify-runtime.py')
        host = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(host)
        with mock.patch.object(host.os, 'geteuid', side_effect=AssertionError('must reject before host work')):
            with self.assertRaisesRegex(q.Stop, 'not admitted'):
                host.host(None, None, None, None)


if __name__ == '__main__':
    unittest.main()
