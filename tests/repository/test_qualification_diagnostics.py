"""Failure diagnostics keep strict content rules and never grant authority."""
# SPDX-License-Identifier: MPL-2.0
import importlib.util
import json
import os
import pathlib
import ssl
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _bounded_qualification as q
spec = importlib.util.spec_from_file_location('diagnostic_host', ROOT / 'scripts/release/qualify-runtime.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class QualificationDiagnostics(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # The real location would fail PATH001 as a published file label.
        self.root = pathlib.Path(self.temporary.name) / 'home/runner/work/_temp/qualification'
        self.root.mkdir(parents=True)
        (self.root / 'source').symlink_to(ROOT, target_is_directory=True)
        self.evidence = self.root / 'evidence'
        (self.evidence / 'artifacts/binaries-A').mkdir(parents=True)
        (self.evidence / 'artifacts/binaries-A/synthetic').write_bytes(b'original raw export')
        (self.evidence / 'RESULT.json').write_text('{"status":"fail"}')
        self.empty = self.evidence / 'empty.log'
        self.empty.write_bytes(b'')
        self.sanitizer = q.module(ROOT, 'sanitize_public.py')
        self.allowlist = self.sanitizer.load_allowlist(ROOT / self.sanitizer.ALLOWLIST_FILENAME)

    def policy(self, verified=False):
        return self.sanitizer, self.allowlist, (), None, verified

    @unittest.skipUnless(pathlib.Path('/etc/ssl/certs/ca-certificates.crt').is_file(), 'Linux worker CA bundle required')
    def test_worker_trust_store_survives_missing_openssl_default_aliases(self):
        absent = str(self.root / 'absent-default-trust-store')
        with mock.patch.dict(os.environ, {'SSL_CERT_FILE': absent, 'SSL_CERT_DIR': absent}):
            self.assertEqual(ssl.create_default_context().cert_store_stats()['x509_ca'], 0)
            environment = host.worker_environment({'SSL_CERT_FILE': absent})
            with mock.patch.dict(os.environ, environment):
                context = ssl.create_default_context()
            self.assertGreater(context.cert_store_stats()['x509_ca'], 0)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)

    def export(self, verified=False):
        with mock.patch.object(host, 'export_policy', return_value=self.policy(verified)):
            host.export_evidence(self.root)
        return self.root / 'public'

    def test_partial_authority_cache_retains_strict_empty_diagnostics(self):
        for name in ('debian-cache', 'go-mod'): (self.root / name).mkdir()
        policy = host.export_policy(ROOT, self.root)
        self.assertFalse(policy[-1])
        self.assertEqual(policy[2], ())
        self.assertIsNone(policy[3])
        inode = (self.evidence / 'artifacts/binaries-A/synthetic').stat().st_ino
        with mock.patch.object(host, 'export_policy', return_value=policy): host.export_evidence(self.root)
        public = self.root / 'public'
        self.assertEqual((public / 'empty.log').read_bytes(), b'')
        self.assertEqual((public / 'artifacts/binaries-A/synthetic').stat().st_ino, inode)
        manifest = json.loads((public / 'evidence-inventory.json').read_text())
        self.assertFalse(manifest['producer_authority_verified'])
        self.assertFalse(manifest['artifact_qualification_admitted'])
        self.assertEqual(manifest['unsafe_text_withheld'], [])

    def test_logical_name_does_not_exempt_private_content(self):
        self.empty.write_text('private path /home/synthetic/private')
        with self.assertRaises(q.Stop): self.export()
        public = self.root / 'public'
        self.assertFalse((public / 'empty.log').exists())
        self.assertEqual(json.loads((public / 'RESULT.json').read_text())['status'], 'fail')

    def test_fixture_label_never_applies_and_scanned_bytes_are_copied_exactly(self):
        original = self.sanitizer.scan_generated_bytes
        seen = []
        def scan(raw, label, fixture, *args, **kwargs):
            seen.append((label, fixture))
            if label.endswith('/empty.log'):
                self.empty.write_text('changed after read /home/synthetic/private')
            return original(raw, label, fixture, *args, **kwargs)
        with mock.patch.object(self.sanitizer, 'scan_generated_bytes', side_effect=scan): public = self.export()
        self.assertEqual((public / 'empty.log').read_bytes(), b'')
        self.assertIn(('qualification-evidence/empty.log', False), seen)
        self.assertTrue(all(not fixture for _, fixture in seen))

    def test_missing_authority_cannot_admit_an_otherwise_passing_result(self):
        (self.evidence / 'RESULT.json').write_text('{"status":"pass"}')
        public = self.export()
        self.assertEqual(json.loads((public / 'RESULT.json').read_text())['status'], 'fail')
        self.assertFalse(json.loads((public / 'evidence-inventory.json').read_text())['artifact_qualification_admitted'])

    def test_validated_authority_and_clean_content_can_admit(self):
        (self.evidence / 'RESULT.json').write_text('{"status":"pass"}')
        public = self.export(verified=True)
        self.assertTrue(json.loads((public / 'evidence-inventory.json').read_text())['artifact_qualification_admitted'])

    def test_linked_text_is_not_copied(self):
        self.empty.unlink()
        self.empty.symlink_to(self.evidence / 'RESULT.json')
        with self.assertRaises(q.Stop): self.export()
        self.assertFalse((self.root / 'public/empty.log').exists())

    def test_invalid_runner_authority_discards_every_projection(self):
        for name in ('debian-cache', 'go-mod'): (self.root / name).mkdir()
        with mock.patch.object(host.q, 'module', return_value=self.sanitizer), mock.patch.object(self.sanitizer, 'load_verified_upstream_licenses', side_effect=self.sanitizer.VerifiedLicenseError('synthetic')):
            policy = host.export_policy(ROOT, self.root)
        self.assertEqual(policy[2:], ((), None, False))

    def test_dependency_authority_uses_explicit_offline_caches_and_original_policy(self):
        for name in ('debian-cache', 'go-mod'): (self.root / name).mkdir()
        metadata = {'source_raw': b'private path /home/synthetic/private', 'source_path': 'release/public-dependency-metadata.json', 'documents': []}
        with mock.patch.object(host.q, 'module', return_value=self.sanitizer), mock.patch.object(self.sanitizer, 'load_verified_upstream_licenses', return_value=()), mock.patch.object(self.sanitizer.public_metadata_source, 'load', return_value=metadata) as load:
            with self.assertRaises(q.Stop): host.export_policy(ROOT, self.root)
        load.assert_called_once_with(ROOT, debian_cache=self.root / 'debian-cache', go_module_cache=self.root / 'go-mod')

    def test_validated_authorities_combine_only_matching_exact_documents(self):
        for name in ('debian-cache', 'go-mod'): (self.root / name).mkdir()
        metadata = {'source_raw': b'{}', 'source_path': 'release/public-dependency-metadata.json', 'documents': [('synthetic/LICENSE', b'public license')]}
        with mock.patch.object(host.q, 'module', return_value=self.sanitizer), mock.patch.object(self.sanitizer, 'load_verified_upstream_licenses', return_value=[('synthetic/LICENSE', b'public license')]), mock.patch.object(self.sanitizer.public_metadata_source, 'load', return_value=metadata):
            policy = host.export_policy(ROOT, self.root)
            self.assertTrue(policy[-1])
            metadata['documents'] = [('synthetic/LICENSE', b'different license')]
            with self.assertRaises(q.Stop): host.export_policy(ROOT, self.root)

    def test_failure_receipt_omits_raw_message_url_and_transport_data(self):
        error = urllib.error.HTTPError('https://example.invalid/private?token=synthetic', 503, 'unpublishable message', {'sensitive': 'synthetic'}, None)
        q.failure_receipt(self.root, 'build', error)
        raw = (self.evidence / 'build-failure.json').read_text()
        receipt = json.loads(raw)
        self.assertEqual(receipt['http_status'], 503)
        self.assertEqual(receipt['exception_type'], 'HTTPError')
        for value in ('example.invalid', 'token', 'unpublishable', 'sensitive'): self.assertNotIn(value, raw)
        with self.assertRaises(q.Stop): q.failure_receipt(self.root, 'untrusted-stage', error)
