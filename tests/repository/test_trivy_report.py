"""Deterministic report identity without altering findings or native bytes."""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
sys.path.insert(0, str(ROOT / 'scripts'))
import _trivy_report as report
import sanitize_public as sanitizer
spec = importlib.util.spec_from_file_location('trivy_capture_host', ROOT / 'scripts/release/qualify-runtime.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
NONCE = '-'.join(('12345678', '1234', '4123', '8123', '123456789abc'))


class TrivyReport(unittest.TestCase):
    def sample(self, **extra):
        return json.dumps({'SchemaVersion': 2, 'Trivy': {'Version': '0.72.0'}, 'ReportID': NONCE, **extra}).encode()

    def test_only_root_value_token_changes_with_exact_other_bytes(self):
        raw = self.sample(Unknown={'ReportID': NONCE, 'number': None, 'text': 'é'}).replace(b'null', b'0.12345678901234567890123456789').replace(b'"ReportID"', b'"Report\\u0049D"', 1)
        rendered, receipt = report.render(raw)
        token = json.dumps(NONCE).encode()
        start = raw.index(token)
        self.assertEqual(rendered[:start], raw[:start])
        self.assertEqual(rendered[start + 73:], raw[start + len(token):])
        self.assertEqual(report.render(raw), (rendered, receipt))
        changed_nonce = raw[:start] + token.replace(b'12345678', b'87654321', 1) + raw[start + len(token):]
        self.assertEqual(report.render(changed_nonce)[0], rendered)
        self.assertEqual(receipt['native_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(receipt['rendered_sha256'], hashlib.sha256(rendered).hexdigest())
        self.assertIn(token, rendered)  # Nested IDs remain intact and blocking.

    def test_empty_results_and_metadata_may_be_omitted_by_native_omitempty(self):
        rendered, _receipt = report.render(self.sample())
        self.assertEqual(set(json.loads(rendered)), {'SchemaVersion', 'Trivy', 'ReportID'})

    def test_malformed_and_ambiguous_inputs_fail_closed(self):
        raw = self.sample()
        cases = [raw + b'{}', raw.replace(b'"SchemaVersion": 2', b'"SchemaVersion": 2, "SchemaVersion": 2'), raw.replace(b'"ReportID":', b'"ReportID": "other", "Report\\u0049D":'), self.sample(SchemaVersion=True), self.sample(Trivy={'Version': '0.73.0'}), self.sample(ReportID='unrecognized'), self.sample(Results={}), self.sample(Metadata=[]), raw[:-1] + b', "Unknown": NaN}', raw[:-1] + b', "Unknown": Infinity}', raw[:-1] + b', "Unknown": "\xff"}', b'']
        for candidate in cases:
            with self.subTest(candidate=candidate[:60]), self.assertRaises((ValueError, TypeError)):
                report.render(candidate)

    def test_findings_advisories_and_unknown_fields_still_block(self):
        for field, value, expected in [('Unknown', NONCE, 'DEPLOYID002'), ('Unknown', '/home/' + 'private-user/task', 'PATH001'), ('Results', [{'Vulnerabilities': [{'Description': 'Endpoint ' + '10.23.45.67'}]}], 'IP001'), ('Metadata', {'Author': 'person' + '@private.internal'}, 'MAIL001'), ('Unknown', 'worker' + '.private.local', 'HOST001')]:
            with self.subTest(expected=expected):
                rendered, _receipt = report.render(self.sample(**{field: value}))
                self.assertEqual(json.loads(rendered)[field], value)
                self.assertIn(expected, {f.rule for f in sanitizer.scan_generated_bytes(rendered, 'qualification-evidence/report.json', False, [])})

    def test_actual_capture_binds_executable_subject_and_private_native_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            executable = root / 'trivy'
            executable.write_bytes(b'synthetic executable')
            expected = hashlib.sha256(executable.read_bytes()).hexdigest()
            raw = self.sample(Results=[])
            native = []
            def invoke(path):
                path.write_bytes(raw)
                native.append(path)
                return 1
            code, receipt = report.capture(executable, expected, root / 'private', root / 'public.json', lambda: 'sealed subject', invoke)
            self.assertEqual(code, 1)
            self.assertEqual(native[0].read_bytes(), raw)
            self.assertEqual((root / 'public.json').read_bytes(), report.render(raw)[0])
            self.assertEqual(receipt['producer_binary_sha256'], expected)
            self.assertEqual((root / 'private').stat().st_mode & 0o777, 0o700)

    def test_capture_mutations_missing_pin_and_linked_native_output_are_refused(self):
        for mode in ('before-executable', 'after-executable', 'subject', 'native-link', 'missing-pin', 'failed-command'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                executable = root / 'trivy'
                executable.write_bytes(b'synthetic executable')
                expected = hashlib.sha256(executable.read_bytes()).hexdigest()
                subject = ['original']
                raw = self.sample()
                if mode == 'before-executable': executable.write_bytes(b'changed')
                if mode == 'missing-pin': expected = ''
                def invoke(path):
                    path.write_bytes(raw)
                    if mode == 'after-executable': executable.write_bytes(b'changed')
                    if mode == 'subject': subject[0] = 'changed'
                    if mode == 'native-link':
                        path.rename(root / 'native.json')
                        path.symlink_to(root / 'native.json')
                    return 2 if mode == 'failed-command' else 0
                with self.assertRaises(report.ReportError):
                    report.capture(executable, expected, root / 'private', root / 'public.json', lambda: list(subject), invoke)
                self.assertFalse((root / 'public.json').exists())

    def test_clone_origin_records_local_acquisition_and_rejects_identity_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            inputs = {'repository': 'synthetic/example', 'commit': 'a' * 40, 'tree': 'b' * 40, 'checkout': '/synthetic/checkout'}
            current = [inputs['checkout']]
            def command(args, **_kwargs):
                if args[1:] == ['rev-parse', 'HEAD']: return inputs['commit']
                if args[1:] == ['rev-parse', 'HEAD^{tree}']: return inputs['tree']
                if args[1] == 'status': return ''
                if args[1] == 'config': return current[0]
                if args[1:4] == ['remote', 'set-url', 'origin']:
                    current[0] = args[4]
                    return ''
                raise AssertionError(args)
            with mock.patch.object(host, 'command', side_effect=command):
                host.prepare_public_clone(root, inputs, {})
            receipt = json.loads((root / 'evidence/source-acquisition.json').read_bytes())
            self.assertEqual(receipt['repository'], 'synthetic/example')
            self.assertTrue(receipt['origin_matches_admitted_public_repository'])
            self.assertIn('no remote fetch', receipt['method'])
            self.assertNotIn(inputs['checkout'], json.dumps(receipt))
            for wrong in ('different', 'https://github.com/synthetic/example.git'):
                current[0] = wrong
                with mock.patch.object(host, 'command', side_effect=command), self.assertRaises(host.q.Stop):
                    host.prepare_public_clone(root, inputs, {})


if __name__ == '__main__':
    unittest.main()
