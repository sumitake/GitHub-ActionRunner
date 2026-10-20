"""Narrow source-bound metadata handling keeps unrelated content blocking."""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import importlib.util
import json
import pathlib
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
sys.path.insert(0, str(ROOT / 'scripts'))
import _producer_publication as publication
import _trivy_db
import public_dependency_metadata as producer
import sanitize_public as scanner
spec = importlib.util.spec_from_file_location('producer_publication_host', ROOT / 'scripts/release/qualify-runtime.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)

NONCE = '-'.join(('12345678', '1234', '4123', '8123', '123456789abc'))


class ProducerPublication(unittest.TestCase):
    def rules(self, raw):
        return {finding.rule for finding in scanner.scan_generated_bytes(raw, 'qualification-evidence/report.json', False, [])}

    def test_syft_nonce_keeps_private_name_and_unknown_fields_visible(self):
        base = {'spdxVersion': 'SPDX-2.3', 'creationInfo': {'creators': ['Tool: syft-1.50.0']}, 'documentNamespace': 'https://anchore.com/syft/file/probe-' + NONCE}
        def view(value):
            return publication.syft_view(json.dumps(value).encode(), {'licenses': []}, producer, scanner)
        self.assertFalse(self.rules(view(base)))
        self.assertIn('DEPLOYID002', self.rules(view({**base, 'Unknown': NONCE})))
        private_name = 'https://anchore.com/syft/file/' + '/home/' + 'private-user/probe-' + NONCE
        self.assertIn('PATH001', self.rules(view({**base, 'documentNamespace': private_name})))
        with self.assertRaises(publication.PublicationError):
            view({**base, 'creationInfo': {'creators': ['Tool: syft-0.0.0']}})

    def test_only_exact_authenticated_legal_citation_position_is_projected(self):
        row = {'module': 'github.com/synthetic/public', 'version': 'v1.0.0', 'file': 'LICENSE', 'content': b'Synthetic public legal text.'}
        citation = ':'.join(('file', '//$GOPATH/pkg/mod/')) + row['module'] + '@' + row['version'] + '/' + row['file']
        document = {'hasExtractedLicensingInfos': [{'seeAlsos': [citation], 'extractedText': row['content'].decode()}]}
        bindings = publication.go_citations(document, {'licenses': [row]})
        raw = json.dumps({**document, 'Unknown': citation}).encode()
        projected = publication.project(raw, bindings, producer, scanner)
        self.assertIn('PATH001', self.rules(projected))
        self.assertEqual(json.loads(projected)['Unknown'], citation)
        document['hasExtractedLicensingInfos'][0]['extractedText'] += ' changed'
        document['hasExtractedLicensingInfos'][0]['seeAlsos'] = [citation + '.changed']
        self.assertFalse(publication.go_citations(document, {'licenses': [row]}))

    def test_known_public_scalar_does_not_waive_secret_or_neighbor_rules(self):
        value = 'person' + '@private.' + 'internal'
        raw = json.dumps({'Metadata': {'Author': value}, 'Unknown': value}).encode()
        view = publication.project(raw, {('Metadata', 'Author'): (value, {'MAIL001'})}, producer, scanner)
        self.assertIn('MAIL001', self.rules(view))
        secret = '-----BEGIN ' + 'RSA PRIVATE KEY-----'
        with self.assertRaises(publication.PublicationError):
            publication.project(json.dumps({'Description': secret}).encode(), {('Description',): (secret, {'MAIL001', 'HOST001', 'IP001', 'PATH001', 'DEPLOYID002'})}, producer, scanner)
        with self.assertRaises(ValueError):
            publication.project(b'{"Author":"a","Auth\\u006fr":"b"}', {}, producer, scanner)
        for character in (chr(0x202e), chr(0xff0f)):
            value = 'public' + character + 'value'
            for ascii_only in (True, False):
                with self.assertRaises(publication.PublicationError):
                    publication.project(json.dumps({'Description': value}, ensure_ascii=ascii_only).encode(), {('Description',): (value, {'MAIL001', 'HOST001', 'IP001', 'PATH001', 'DEPLOYID002'})}, producer, scanner)

    def test_buildkit_enum_requires_filter_context_and_preserves_neighbors(self):
        atom = 'type==source' + '.local'
        stdout = 'ID:\tsynthetic\nGC Policy rule#0:\n\tAll:\tfalse\n\tFilters:\t' + atom + ',type==exec.cachemount\n'
        raw = json.dumps({'stdout': stdout, 'pid': 123}).encode()
        view = publication.buildkit_view(raw, producer, scanner)
        self.assertFalse(self.rules(view))
        neighbor = stdout.replace(',type==', ',worker' + '.private.local type==')
        with self.assertRaises(publication.PublicationError):
            publication.buildkit_view(json.dumps({'stdout': neighbor, 'pid': 123}).encode(), producer, scanner)
        for changed in (stdout.replace('GC Policy rule#0:', 'Labels:'), stdout.replace(atom, atom + '.changed')):
            with self.assertRaises(publication.PublicationError):
                publication.buildkit_view(json.dumps({'stdout': changed, 'pid': 123}).encode(), producer, scanner)

    def test_epoch_and_release_package_identity_cannot_be_reassigned(self):
        package = {'Name': 'synthetic', 'Version': '1.2.3', 'Release': '4', 'Epoch': 1, 'Arch': 'amd64', 'Identifier': {'PURL': 'pkg:deb/debian/synthetic@1.2.3-4?arch=amd64&distro=debian-12.1&epoch=1'}}
        self.assertEqual(publication.package_identity(package, '12.1'), ('synthetic', '1:1.2.3-4', 'amd64'))
        with self.assertRaises(publication.PublicationError):
            publication.package_identity({**package, 'Epoch': 2}, '12.1')
        with self.assertRaises(publication.PublicationError):
            publication.package_identity(package, '12.2')

    def test_admitted_public_hosting_origin_does_not_waive_other_identity_checks(self):
        import _trivy_report
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / 'source').symlink_to(ROOT, target_is_directory=True)
            stage = publication.Stage(root, 'scan', scanner, producer)
            origin = 'https://github.com/sumitake/' + 'GitHub' + '-ActionRunner.git'
            identity = {'RepoURL': origin, 'Commit': 'a' * 40, 'Author': 'Synthetic <person@example.com>', 'Committer': 'Synthetic <person@example.com>'}
            value = {'SchemaVersion': 2, 'Trivy': {'Version': '0.72.0'}, 'ReportID': NONCE, 'Metadata': identity}
            rendered, receipt = _trivy_report.render(json.dumps(value).encode())
            self.assertFalse(self.rules(stage.trivy_view(rendered, None, identity, receipt)))
            value['Unknown'] = origin
            rendered, receipt = _trivy_report.render(json.dumps(value).encode())
            self.assertIn('REPO_IDENTITY', self.rules(stage.trivy_view(rendered, None, identity, receipt)))
            value['Metadata'] = {**identity, 'RepoURL': origin + '.changed'}
            rendered, receipt = _trivy_report.render(json.dumps(value).encode())
            with self.assertRaises(publication.PublicationError): stage.trivy_view(rendered, None, identity, receipt)

    def test_fingerprint_is_recomputed_and_unrelated_digest_still_scans(self):
        # Public retained producer example: this computed digest happens to
        # decode to a path-like fragment. It grants no vulnerable-image pass.
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / 'source').symlink_to(ROOT, target_is_directory=True)
            stage = publication.Stage(root, 'scan', scanner, producer)
            parts = ('sha256:e64d2a15c378b3c116a4db71bd0240195e137a3d764c47579fdddf35f1a10947', 'opt/actions-runner/bin/Runner.Worker.deps.json', 'Microsoft.NETCore.App.Runtime.linux-x64/8.0.31', 'CVE-2026-58280')
            fingerprint = 'sha256:' + ''.join(('3e315b3ae8af77c2', '42df1471417e2f49', 'd0d165a4b217dcda', 'be7ec5dac30c9778'))
            self.assertEqual(fingerprint, 'sha256:' + hashlib.sha256(':'.join(parts).encode()).hexdigest())
            self.assertIn('PATH001', self.rules(json.dumps(fingerprint).encode()))
            value = {'SchemaVersion': 2, 'Trivy': {'Version': '0.72.0'}, 'ReportID': NONCE, 'ArtifactID': parts[0], 'Results': [{'Target': parts[1], 'Type': 'synthetic', 'Vulnerabilities': [{'PkgID': parts[2], 'VulnerabilityID': parts[3], 'Fingerprint': fingerprint}]}]}
            import _trivy_report
            rendered, receipt = _trivy_report.render(json.dumps(value).encode())
            self.assertFalse(self.rules(stage.trivy_view(rendered, None, {}, receipt)))
            value['Unknown'] = fingerprint
            rendered, receipt = _trivy_report.render(json.dumps(value).encode())
            self.assertIn('PATH001', self.rules(stage.trivy_view(rendered, None, {}, receipt)))
            value.pop('Unknown')
            value['Results'][0]['Vulnerabilities'][0]['Fingerprint'] = 'sha256:' + 'b' * 64
            rendered, receipt = _trivy_report.render(json.dumps(value).encode())
            with self.assertRaises(publication.PublicationError): stage.trivy_view(rendered, None, {}, receipt)
            with self.assertRaises(publication.PublicationError): stage.trivy_view(rendered + b' ', None, {}, receipt)

    def test_completed_staging_rejects_extra_and_changed_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / 'source').symlink_to(ROOT, target_is_directory=True)
            (root / 'evidence').mkdir()
            (root / 'inputs.json').write_text(json.dumps({'commit': 'a' * 40, 'tree': 'b' * 40}))
            runtime = json.loads((ROOT / 'release/manifest.json').read_bytes())['runtime']
            images = {row['name'] for row in runtime['images']}
            members = {'buildkit': {'buildkit-workers-apt-plan.json'} | {'buildkit-workers-' + letter + '-' + name + '.json' for letter in ('A', 'B') for name in images}, 'scan': {'security-source.json', 'security-binaries-A.json', 'security-binaries-B.json', 'runner-all-severities.json'} | {'security-image-' + name + '.json' for name in images} | {'sbom/' + name + '.raw.spdx.json' for name in images | {row['name'] for row in runtime['binaries']}}}
            for role, paths in members.items():
                stage = publication.Stage(root, role, scanner, producer)
                for relative in paths:
                    path = root / 'evidence' / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    raw = b'{"public":"synthetic"}\n'
                    path.write_bytes(raw)
                    stage.add(path, raw, raw)
                stage.finish()
            admission = publication.completed_stages(root)
            self.assertEqual(len(admission.files), 40)
            extra = root / 'staged-scan/extra.json'
            extra.write_bytes(b'{}')
            with self.assertRaises(publication.PublicationError): publication.completed_stages(root)
            extra.unlink()
            target = root / 'evidence/security-source.json'
            target.write_bytes(b'changed')
            with self.assertRaises(publication.PublicationError): publication.completed_stages(root)
            # The controller must also catch disappearance after validation,
            # then continue strictly scanning evidence finalized after scans.
            target.unlink()
            heartbeat = {'kernel': {'cpu.max': '400000 100000', 'memory.max': str(host.q.MEMORY), 'memory.swap.max': '0', 'pids.max': '1024', 'memory.events': 'oom 0\noom_kill 0'}, 'accounted_bytes': host.q.RESERVE, 'writable_root_bytes': 0, 'free_bytes': 20 * host.q.GIB, 'free_inodes': 800000, 'available_memory_bytes': 12 * host.q.GIB}
            (root / 'heartbeat.json').write_text(json.dumps(heartbeat))
            policy = scanner, scanner.load_allowlist(ROOT / scanner.ALLOWLIST_FILENAME), (), None, True
            with mock.patch.object(host, 'export_policy', return_value=policy), self.assertRaisesRegex(host.q.Stop, 'missing during export'):
                host.export_evidence(root, guarded=True, staged=admission)
            shutil.rmtree(root / 'public')
            target.write_bytes(b'{"public":"synthetic"}\n')
            (root / 'evidence/late-console.log').write_text('/home/' + 'private-user/path')
            with mock.patch.object(host, 'export_policy', return_value=policy), self.assertRaisesRegex(host.q.Stop, 'failed public sanitization'):
                host.export_evidence(root, guarded=True, staged=admission)
            inventory = json.loads((root / 'public/evidence-inventory.json').read_bytes())
            self.assertEqual({row['path'] for row in inventory['unsafe_text_withheld']}, {'late-console.log'})
            self.assertFalse(inventory['artifact_qualification_admitted'])


class PublicDatabase(unittest.TestCase):
    def database(self, path):
        pages = bytearray(4 * 4096)
        value = b'{"Title":"synthetic public advisory"}'
        key = b'CVE-2000-12345'
        def leaf(offset, pid, name, content, flags):
            struct.pack_into('<QHHI', pages, offset, pid, 2, 1, 0)
            struct.pack_into('<IIII', pages, offset + 16, flags, 16, len(name), len(content))
            pages[offset + 32:offset + 32 + len(name) + len(content)] = name + content
        leaf(8192, 2, b'vulnerability', struct.pack('<QQ', 3, 0), 1)
        leaf(12288, 3, key, value, 0)
        for pid in (0, 1):
            offset = pid * 4096
            struct.pack_into('<QHHI', pages, offset, pid, 4, 0, 0)
            struct.pack_into('<IIIIQQQQQ', pages, offset + 16, 0xed0cdaed, 2, 4096, 0, 2, 0, 3, 4, pid + 1)
            checksum = 0xcbf29ce484222325
            for byte in pages[offset + 16:offset + 72]: checksum = ((checksum ^ byte) * 0x100000001b3) & (2**64 - 1)
            struct.pack_into('<Q', pages, offset + 72, checksum)
        path.write_bytes(pages)
        return hashlib.sha256(pages).hexdigest(), key, value

    def test_exact_readonly_lookup_and_wrong_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'public.db'
            digest, key, value = self.database(path)
            reader = _trivy_db.Reader(path, digest)
            try:
                self.assertEqual(reader.value([b'vulnerability'], key), value)
                self.assertIsNone(reader.value([b'vulnerability'], b'unknown'))
            finally: reader.close()
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            with self.assertRaises(_trivy_db.DatabaseError): _trivy_db.Reader(path, '0' * 64)

    def test_malformed_page_and_post_read_mutation_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'public.db'
            digest, key, _value = self.database(path)
            raw = bytearray(path.read_bytes())
            struct.pack_into('<I', raw, 8192 + 16 + 4, 999999)
            path.write_bytes(raw)
            reader = _trivy_db.Reader(path, hashlib.sha256(raw).hexdigest())
            try:
                with self.assertRaises(_trivy_db.DatabaseError): reader.value([b'vulnerability'], key)
            finally: reader.close()
            digest, _key, _value = self.database(path)
            reader = _trivy_db.Reader(path, digest)
            with path.open('r+b') as stream:
                stream.seek(12288 + 32)
                stream.write(b'x')
            with self.assertRaises(_trivy_db.DatabaseError): reader.close()


if __name__ == '__main__':
    unittest.main()
