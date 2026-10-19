"""Synthetic checks for exact public-document recognition in generated outputs."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import sanitize_public as sp


class VerifiedUpstreamLicenses(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = 'images/runner/build/runner/externals/node20/LICENSE'
        self.original = 'Synthetic public upstream notice.\n' * 8 + 'Contact: author@project.test\nExample address: 198.51.100.19\n'
        self.source = self.root / self.path
        self.source.parent.mkdir(parents=True)
        (self.root / 'release').mkdir()
        self.registry_path = self.root / 'release/runner-licenses.json'
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.registry = {'schema_version': 1, 'runner_asset_digest': 'sha256:' + 'a' * 64, 'packages': [], 'licenses': [{'license_id': 'LicenseRef-Runner-Upstream-fixture', 'name': 'Synthetic source document', 'files': [{'name': 'LICENSE', 'path': self.path, 'sha256': hashlib.sha256(self.original.encode()).hexdigest()}], 'see_also': ['https://example.invalid/LICENSE']}]}
        self.commit()
        self.output = self.root / 'output.txt'

    def commit(self):
        self.source.write_bytes(self.original.encode())
        self.registry_path.write_text(json.dumps(self.registry))
        subprocess.run(['git', 'add', 'release/runner-licenses.json'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Example', '-c', 'user.email=operator@example.invalid', 'commit', '-qm', 'Synthetic licensing authority'], cwd=self.root, check=True)

    def materials(self):
        return sp.load_verified_upstream_licenses(self.root)

    def allowed(self):
        entries = []
        for finding in sp.scan_text_content(self.original, self.path, fixture=False):
            if finding.rule in {'MAIL001', 'IP001'}:
                entries.append({'path': self.path, 'line': finding.line, 'rule': finding.rule, 'sha256': sp.compute_line_hash(finding.content), 'reason': 'Exact synthetic public-document fixture'})
        return sp.AllowlistIndex(entries)

    def scan(self, text, materials=None):
        self.output.write_text(text)
        findings = sp.scan_generated_tree(self.output, self.root, self.materials() if materials is None else materials)
        return self.allowed().filter(findings)

    def test_exact_plain_and_json_encoded_documents_use_exact_source_allowlist(self):
        for text in (self.original, json.dumps({'extractedText': self.original}, ensure_ascii=True)):
            with self.subTest(text=text):
                self.assertEqual(self.scan(text), [])
        self.output.write_text(self.original)
        self.assertTrue(sp.scan_generated_tree(self.output, self.root))

    def test_modified_document_or_added_metadata_stays_blocking(self):
        for text in (self.original.replace('public upstream', 'changed upstream'), self.original + 'Other: operator@private.test\n', json.dumps({'extractedText': self.original, 'other': 'operator@private.test'})):
            with self.subTest(text=text):
                self.assertTrue(self.scan(text))

    def test_secret_rules_apply_inside_and_outside_known_documents(self):
        secret = ''.join(['ghp', '_', 'Z' * 24])
        self.assertIn('SECRET_TOKEN', {f.rule for f in self.scan(self.original + secret)})
        self.original += secret + '\n'
        self.registry['licenses'][0]['files'][0]['sha256'] = hashlib.sha256(self.original.encode()).hexdigest()
        self.commit()
        self.assertIn('SECRET_TOKEN', {f.rule for f in self.scan(self.original)})

    def test_unsafe_or_changed_source_or_uncommitted_authority_is_refused(self):
        self.source.write_text(self.original + 'changed')
        with self.assertRaises(sp.VerifiedLicenseError): self.materials()
        self.source.write_text(self.original)
        self.registry_path.write_text('{}')
        with self.assertRaises(sp.VerifiedLicenseError): self.materials()
        self.registry_path.write_text(json.dumps(self.registry))
        self.source.unlink()
        self.source.symlink_to(self.registry_path)
        with self.assertRaises(sp.VerifiedLicenseError): self.materials()

    def test_tiny_document_cannot_be_a_projection_authority(self):
        self.original = '.'
        self.registry['licenses'][0]['files'][0]['sha256'] = hashlib.sha256(self.original.encode()).hexdigest()
        self.commit()
        with self.assertRaises(sp.VerifiedLicenseError): self.materials()

    def test_original_size_cap_cannot_be_reduced_by_projection(self):
        text = self.original * (sp.MAX_FILE_BYTES // len(self.original) + 1)
        self.assertIn('SIZE_LIMIT', {f.rule for f in self.scan(text)})


if __name__ == '__main__':
    unittest.main()
