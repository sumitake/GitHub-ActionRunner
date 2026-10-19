"""Synthetic source-bound public package attribution and license tests."""
# SPDX-License-Identifier: MPL-2.0
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class PublicDependencyMetadata(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('public_metadata', ROOT / 'scripts/public_dependency_metadata.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.base = 'debian:bookworm-slim@sha256:' + 'a' * 64
        self.purl = 'pkg:deb/debian/example-tool@1.2.3?arch=amd64&distro=debian-12'
        self.producer = 'Person: Example Maintainer (maintainer@producer.test)'
        self.identifier = 'SPDXRef-synthetic-known-package'
        self.body = ('Synthetic complete producer licensing terms.\n' * 5).encode()
        digest = hashlib.sha256(self.body).hexdigest()
        self.docpath = 'release/public-dependency-texts/' + digest + '.txt'
        (self.root / self.docpath).parent.mkdir(parents=True)
        (self.root / self.docpath).write_bytes(self.body)
        source = self.root / 'images/runner'
        source.mkdir(parents=True)
        (source / 'Dockerfile').write_text('FROM ' + self.base + '\n')
        (source / 'verify-debian-cache.sh').write_text('verify ' + 'b' * 64 + ' archive/debian/20000101T000000Z/dists/bookworm/InRelease\n')
        archive_h1 = 'h1:' + base64.b64encode(b'x' * 32).decode()
        (self.root / 'go.sum').write_text('example.invalid/public v1.2.3 ' + archive_h1 + '\n')
        self.registry = {
            'schema_version': 1,
            'base_image': self.base,
            'debian_indexes': [{'url': 'https://snapshot.debian.org/archive/debian/20000101T000000Z/dists/bookworm/main/binary-amd64/Packages.xz', 'sha256': 'e' * 64, 'bytes': 123, 'inrelease_url': 'https://snapshot.debian.org/archive/debian/20000101T000000Z/dists/bookworm/InRelease', 'inrelease_sha256': 'b' * 64}],
            'packages': [{'name': 'example-tool', 'version': '1.2.3', 'purl': self.purl, 'maintainer': 'Example Maintainer <maintainer@producer.test>', 'deb_url': 'https://snapshot.debian.org/archive/debian/20000101T000000Z/pool/main/e/example/example_1.2.3_amd64.deb', 'deb_sha256': 'c' * 64, 'stanza_sha256': 'd' * 64, 'index_sha256': 'e' * 64, 'attribution_fields': ['originator', 'supplier'], 'spdx_id': self.identifier}],
            'go_licenses': [{'module': 'example.invalid/public', 'version': 'v1.2.3', 'file': 'NOTICE', 'module_zip_h1': archive_h1, 'source_url': 'https://proxy.golang.org/example.invalid/public/@v/v1.2.3.zip', 'path': self.docpath, 'sha256': digest}],
        }
        self.path = self.root / 'release/public-dependency-metadata.json'
        self.write_registry()
        self.git('init', '-q')
        self.commit()

    def git(self, *arguments):
        return subprocess.run(['git', '-c', 'user.name=Synthetic Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', *arguments], cwd=self.root, check=True, capture_output=True)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic fixture authority')

    def write_registry(self):
        self.path.write_text(json.dumps(self.registry, indent=2) + '\n')

    def metadata(self):
        return self.module.load(self.root)

    def document(self):
        return {'spdxVersion': 'SPDX-2.3', 'packages': [{'SPDXID': self.identifier, 'name': 'example-tool', 'versionInfo': '1.2.3', 'supplier': self.producer, 'originator': self.producer, 'externalRefs': [{'referenceType': 'purl', 'referenceLocator': self.purl}]}], 'relationships': [{'spdxElementId': 'SPDXRef-document', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': self.identifier}]}

    def test_only_exact_package_fields_and_graph_references_are_projected(self):
        document = self.document()
        document['comment'] = 'private@operator.test'
        original = json.dumps(document, separators=(',', ':')).replace('"private@operator.test"', '"\\u0070rivate@operator.test"')
        projected = self.module.project_spdx(original, self.metadata())
        self.assertIn('"\\u0070rivate@operator.test"', projected)
        value = json.loads(projected)
        self.assertNotEqual(value['packages'][0]['supplier'], self.producer)
        self.assertEqual(value['packages'][0]['externalRefs'], document['packages'][0]['externalRefs'])
        self.assertEqual(value['relationships'][0]['relatedSpdxElement'], value['packages'][0]['SPDXID'])
        self.assertIn(self.producer, original)

    def test_unknown_package_identity_or_changed_contact_stays_visible(self):
        for kind in ('version', 'purl', 'contact'):
            with self.subTest(kind=kind):
                document = self.document()
                if kind == 'version': document['packages'][0]['versionInfo'] = '1.2.4'
                elif kind == 'purl': document['packages'][0]['externalRefs'][0]['referenceLocator'] += '-changed'
                else: document['packages'][0]['supplier'] = 'Person: Other (private@operator.test)'
                raw = json.dumps(document)
                projected = self.module.project_spdx(raw, self.metadata())
                expected = document['packages'][0]['supplier']
                self.assertIn(expected, projected)

    def test_unregistered_fields_are_not_hidden_by_a_known_public_contact(self):
        document = self.document()
        document['comment'] = self.producer
        value = json.loads(self.module.project_spdx(json.dumps(document), self.metadata()))
        self.assertEqual(value['comment'], self.producer)

    def test_uncommitted_registry_and_aliased_documents_are_refused(self):
        self.path.write_text(self.path.read_text() + ' ')
        with self.assertRaises(self.module.MetadataError): self.metadata()
        self.write_registry()
        document = self.root / self.docpath
        alternate = self.root / 'alternate.txt'
        document.rename(alternate)
        document.symlink_to(alternate)
        with self.assertRaises(self.module.MetadataError): self.metadata()

    def test_changed_license_bytes_and_duplicate_registry_keys_are_refused(self):
        document = self.root / self.docpath
        document.write_bytes(self.body + b'changed')
        with self.assertRaises(self.module.MetadataError): self.metadata()
        document.write_bytes(self.body)
        self.path.write_text(self.path.read_text().replace('{', '{"schema_version":1,', 1))
        self.commit()
        with self.assertRaises(self.module.MetadataError): self.metadata()

    def test_full_terms_and_public_citations_replace_missing_license_text(self):
        entry = {'licenseId': 'LicenseRef-synthetic-source', 'extractedText': 'NOASSERTION', 'seeAlsos': ['file://$GOPATH/pkg/mod/example.invalid/public@v1.2.3/NOTICE']}
        document = {'hasExtractedLicensingInfos': [entry], 'packages': [{'name': 'synthetic'}], 'relationships': []}
        before = copy.deepcopy(document)
        self.module.complete_go_license_records(document, self.metadata())
        self.assertEqual(entry['extractedText'], self.body.decode())
        self.assertTrue(entry['seeAlsos'][0].startswith('https://proxy.golang.org/'))
        self.assertEqual(entry['licenseId'], before['hasExtractedLicensingInfos'][0]['licenseId'])
        self.assertEqual(document['packages'], before['packages'])
        self.assertEqual(document['relationships'], before['relationships'])

    def test_conflicting_terms_are_never_overwritten(self):
        entry = {'licenseId': 'LicenseRef-synthetic-source', 'extractedText': 'Conflicting synthetic terms', 'seeAlsos': ['file://$GOPATH/pkg/mod/example.invalid/public@v1.2.3/NOTICE']}
        with self.assertRaises(self.module.MetadataError): self.module.complete_go_license_records({'hasExtractedLicensingInfos': [entry]}, self.metadata())
        self.assertEqual(entry['extractedText'], 'Conflicting synthetic terms')

    def test_small_public_terms_do_not_become_global_text_exemptions(self):
        self.body = b'Short synthetic terms.\n'
        digest = hashlib.sha256(self.body).hexdigest()
        doc = self.root / ('release/public-dependency-texts/' + digest + '.txt')
        doc.write_bytes(self.body)
        self.registry['go_licenses'][0].update(path=str(doc.relative_to(self.root)), sha256=digest)
        self.write_registry()
        self.commit()
        self.assertEqual(self.metadata()['documents'], [])

    def test_generated_scan_recognizes_only_source_bound_fields(self):
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        import sanitize_public as sanitizer
        document = self.document()
        raw = json.dumps(document).encode()
        findings = sanitizer.scan_generated_bytes(raw, 'artifacts/runner.spdx.json', False, (), public_metadata=self.metadata())
        self.assertNotIn('MAIL001', {finding.rule for finding in findings})
        document['comment'] = 'private@operator.test'
        changed = json.dumps(document).encode()
        findings = sanitizer.scan_generated_bytes(changed, 'artifacts/runner.spdx.json', False, (), public_metadata=self.metadata())
        self.assertIn('MAIL001', {finding.rule for finding in findings})
        self.assertEqual(changed, json.dumps(document).encode())

    def test_generated_size_guard_precedes_public_projection(self):
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        import sanitize_public as sanitizer
        from unittest import mock
        with mock.patch.object(sanitizer, 'MAX_FILE_BYTES', 10):
            findings = sanitizer.scan_generated_bytes(json.dumps(self.document()).encode(), 'artifacts/runner.spdx.json', False, (), public_metadata=self.metadata())
        self.assertIn('SIZE_LIMIT', {finding.rule for finding in findings})

    def test_public_projection_requires_explicit_evidence_and_raw_denylist_still_applies(self):
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        import sanitize_public as sanitizer
        raw = json.dumps(self.document()).encode()
        self.assertIn('MAIL001', {f.rule for f in sanitizer.scan_generated_bytes(raw, 'artifacts/runner.spdx.json', False, ())})
        self.assertNotIn('MAIL001', {f.rule for f in sanitizer.scan_generated_bytes(raw, 'artifacts/runner.spdx.json', False, (), public_metadata=self.metadata())})
        generated = self.root / 'generated.spdx.json'
        generated.write_bytes(raw)
        denylist = self.root / 'operator-denylist.txt'
        denylist.write_text(self.producer + '\n')
        findings = sanitizer.scan_private_denylist(self.root, False, [str(generated)], denylist, False)
        self.assertIn('PRIVATE_DENYLIST', {f.rule for f in findings})
        self.assertEqual(generated.read_bytes(), raw)

    def test_unknown_graph_and_malformed_duplicate_key_documents_stay_visible(self):
        document = self.document()
        document['relationships'][0]['comment'] = self.identifier
        document['relationships'].append({'spdxElementId': 'SPDXRef-unknown', 'relatedSpdxElement': 'private@operator.test'})
        projected = json.loads(self.module.project_spdx(json.dumps(document), self.metadata()))
        self.assertEqual(projected['relationships'][0]['comment'], self.identifier)
        self.assertEqual(projected['relationships'][1], document['relationships'][1])
        raw = json.dumps(document).replace('"spdxVersion":', '"spdxVersion":"SPDX-2.3","spdxVersion":', 1)
        self.assertEqual(self.module.project_spdx(raw, self.metadata()), raw)

    def test_changed_base_image_index_or_module_authority_is_refused(self):
        for relative in ('images/runner/Dockerfile', 'images/runner/verify-debian-cache.sh', 'go.sum'):
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b'changed\n')
                with self.assertRaises(self.module.MetadataError): self.metadata()
                path.write_bytes(original)

    def test_release_normalization_preserves_graph_and_includes_complete_terms(self):
        from tests.repository.test_runtime_sbom_metadata import rehearsal
        namespace = rehearsal()
        raw = self.root / 'raw.spdx.json'
        output = self.root / 'normalized.spdx.json'
        value = {'SPDXID': 'SPDXRef-DOCUMENT', 'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'name': 'synthetic', 'documentNamespace': 'https://example.invalid/synthetic', 'creationInfo': {'creators': ['Tool: synthetic']}, 'packages': [], 'relationships': [], 'hasExtractedLicensingInfos': [{'licenseId': 'LicenseRef-synthetic-source', 'extractedText': 'NOASSERTION', 'seeAlsos': ['file://$GOPATH/pkg/mod/example.invalid/public@v1.2.3/NOTICE']}]}
        raw.write_text(json.dumps(value))
        namespace['normalize_spdx'](raw, output, 'synthetic', 'a' * 64, 123, public_evidence=(self.module, self.metadata()))
        normalized = json.loads(output.read_text())
        self.assertEqual(normalized['packages'], value['packages'])
        self.assertEqual(normalized['relationships'], value['relationships'])
        self.assertEqual(normalized['hasExtractedLicensingInfos'][0]['extractedText'], self.body.decode())
        self.assertEqual(json.loads(raw.read_text()), value)
