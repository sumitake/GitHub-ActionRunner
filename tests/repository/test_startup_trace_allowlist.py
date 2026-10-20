"""Producer trace exceptions remain bound to public metadata and exact contexts."""
# SPDX-License-Identifier: MPL-2.0
import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import sanitize_public as sanitizer

spec = importlib.util.spec_from_file_location('trace_audit', ROOT / 'scripts/release/audit-startup-trace-allowlist.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class StartupTraceAllowlist(unittest.TestCase):
    def setUp(self):
        self.line = '    Microsoft.CSharp.dll assemblyVersion=8.0.0.0 fileVersion=8.0.3226.50405'
        self.path = audit.PREFIX + 'Runner.Listener.trace'
        self.allowlist = sanitizer.load_allowlist(ROOT / sanitizer.ALLOWLIST_FILENAME)
        self.records = {('Microsoft.CSharp.dll', '8.0.0.0', '8.0.3226.50405')}

    def finding(self, text=None, *, rule='IP001', path=None, line=47):
        return sanitizer.Finding(path or self.path, line, rule, 'synthetic audit finding', text or self.line)

    def test_producer_records_cover_native_and_flattened_runtime_targets(self):
        rows = audit.producer_records({'targets': {'synthetic': {'library': {
            'runtime': {'a.dll': {'assemblyVersion': '1.0.0.0', 'fileVersion': '1.2.3.4'}},
            'runtimeTargets': {'lib/net8.0/b.dll': {'assemblyVersion': '2.0.0.0', 'fileVersion': '2.3.4.5'}},
            'native': {'native.so': {'fileVersion': '0.0.0.0'}, 'unversioned.so': {}},
        }}}})
        self.assertIn(('b.dll', '2.0.0.0', '2.3.4.5'), rows)
        self.assertIn(('lib/net8.0/b.dll', '2.0.0.0', '2.3.4.5'), rows)
        self.assertIn(('native.so', '', '0.0.0.0'), rows)
        self.assertFalse(any(row[0] == 'unversioned.so' for row in rows))

    def test_full_line_shapes_require_exact_producer_fields(self):
        for text in (self.line,
                     '    Entry 1 for asset name: Microsoft.CSharp, relpath: Microsoft.CSharp.dll, assemblyVersion 8.0.0.0, fileVersion 8.0.3226.50405',
                     'Adding tpa entry: /work/runner-source/_layout/bin/Microsoft.CSharp.dll, AssemblyVersion: 8.0.0.0, FileVersion: 8.0.3226.50405'):
            audit.verify_line(self.finding(text), self.records)
        for text in (self.line + ' 10.2.3.4', self.line.replace('8.0.0.0', '10.2.3.4'),
                     'private host=internal.example ' + self.line,
                     '    Entry 1 for asset name: different, relpath: Microsoft.CSharp.dll, assemblyVersion 8.0.0.0, fileVersion 8.0.3226.50405'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                audit.verify_line(self.finding(text), self.records)
        with self.assertRaises(ValueError):
            audit.verify_line(self.finding(rule='SECRET_TOKEN'), self.records)

    def test_registered_context_does_not_suppress_changed_data_or_other_contexts(self):
        self.assertTrue(self.allowlist.suppresses(self.finding()))
        for finding in (self.finding(self.line + ' 10.2.3.4'), self.finding(line=48),
                        self.finding(path=audit.PREFIX + 'different.trace'),
                        self.finding(rule='SECRET_TOKEN'),
                        self.finding(self.line.replace('8.0.0.0', '10.2.3.4'))):
            with self.subTest(finding=finding):
                self.assertFalse(self.allowlist.suppresses(finding))
        raw = ('\n' * 46 + self.line + ' private path /home/synthetic/private\n').encode()
        blocked = self.allowlist.filter(sanitizer.scan_generated_bytes(raw, self.path, False, ()))
        self.assertIn('PATH001', {finding.rule for finding in blocked})

    def test_existing_canonical_hash_semantics_are_explicit(self):
        self.assertTrue(self.allowlist.suppresses(self.finding(self.line + ' \t')))
        self.assertEqual(sanitizer.compute_line_hash(self.line), sanitizer.compute_line_hash(self.line + ' \t'))

    def test_host_findings_require_the_known_producer_identifier(self):
        records = {('System.Transactions.Local.dll', '8.0.0.0', '8.0.3226.50405')}
        text = '    Entry 144 for asset name: System.Transactions.Local, relpath: System.Transactions.Local.dll, assemblyVersion 8.0.0.0, fileVersion 8.0.3226.50405'
        finding = self.finding(text, rule='HOST001', line=595)
        audit.verify_line(finding, records)
        self.assertTrue(self.allowlist.suppresses(finding))
        with self.assertRaises(ValueError):
            audit.verify_line(self.finding(rule='HOST001'), self.records)
