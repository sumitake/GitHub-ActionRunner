"""Bounded control copies bind selected receipts to the unchanged raw inventory."""
# SPDX-License-Identifier: MPL-2.0
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _qualification_control as control


class QualificationControl(unittest.TestCase):
    def fixture(self, root, admitted=True):
        public = root / 'public'
        public.mkdir()
        inputs = {'commit': 'a' * 40, 'tree': 'b' * 40}
        values = {name: {'status': 'pass'} for name in control.REQUIRED}
        values['source-inputs.json'] = inputs
        values['RESULT.json'] = {'status': 'pass' if admitted else 'fail', 'source_commit': inputs['commit'], 'source_tree': inputs['tree']}
        if not admitted:
            values = {'RESULT.json': values['RESULT.json']}
        files = []
        for name, value in values.items():
            raw = (json.dumps(value) + '\n').encode()
            (public / name).write_bytes(raw)
            files.append(control.row(name, raw))
        # A complete raw inventory may include large payloads without copying them.
        files.append({'path': 'raw/A.tar', 'bytes': 20 * 2**20, 'sha256': 'c' * 64})
        (public / 'evidence-inventory.json').write_text(json.dumps({'artifact_qualification_admitted': admitted, 'files': files}))
        return public, inputs

    def test_complete_and_failed_control_keep_source_inventory_and_raw_budget(self):
        for admitted in (True, False):
            with self.subTest(admitted=admitted), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                public, inputs = self.fixture(root, admitted)
                target = root / 'control'
                control.create(public, target, inputs, 2**30)
                index = control.verify(target)
                self.assertIs(index['artifact_qualification_admitted'], admitted)
                self.assertEqual((target / 'evidence-inventory.json').read_bytes(), (public / 'evidence-inventory.json').read_bytes())
                self.assertFalse((target / 'raw').exists())
                with self.assertRaises(control.ControlError):
                    control.create(public, root / 'over-budget', inputs, 20 * 2**20)
                self.assertFalse((root / 'over-budget').exists())

    def test_changed_extra_and_oversized_members_cannot_upload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public, inputs = self.fixture(root)
            target = root / 'control'
            for failure in ('changed', 'extra', 'oversized'):
                with self.subTest(failure=failure):
                    control.create(public, target, inputs, 2**30)
                    if failure == 'changed':
                        (target / 'RESULT.json').write_bytes(b'{"status":"fail"}\n')
                    elif failure == 'extra':
                        (target / 'unexpected').write_bytes(b'private')
                    else:
                        with (target / 'RESULT.json').open('wb') as stream:
                            stream.truncate(control.LIMIT + 1)
                    with self.assertRaises(control.ControlError):
                        control.verify(target)
                    shutil.rmtree(target)


if __name__ == '__main__':
    unittest.main()
