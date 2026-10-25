"""The source-only SDK check cannot claim a different compiler or runtime."""
# SPDX-License-Identifier: MPL-2.0
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class RunnerVersionSource(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('runner_version_source', ROOT / 'scripts/release/check-runner-version-source.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_compiler_and_app_runtime_are_exact(self):
        self.module.verify_toolchain(b'8.0.426\n', b'Microsoft.NETCore.App 8.0.32 [/synthetic/runtime]\n')
        for sdk, runtime in [
            (b'10.0.402\n', b'Microsoft.NETCore.App 8.0.32 [/synthetic/runtime]\n'),
            (b'8.0.426\n', b'Microsoft.NETCore.App 8.0.31 [/synthetic/runtime]\n'),
            (b'8.0.426\nwarning\n', b'Microsoft.NETCore.App 8.0.32 [/synthetic/runtime]\n'),
        ]:
            with self.subTest(sdk=sdk, runtime=runtime), self.assertRaises(ValueError):
                self.module.verify_toolchain(sdk, runtime)

    def test_source_addition_is_the_reviewed_exact_patch(self):
        patch = (ROOT / 'release/runner-version-smoke.patch').read_bytes()
        self.module.verify_patch(patch)
        with self.assertRaises(ValueError):
            self.module.verify_patch(patch + b'\n')

    def test_normal_argv_cannot_masquerade_as_fastpath(self):
        import json
        cases = self.module.CASES
        def rows(fixed):
            return b'\n'.join(json.dumps({'argv':args,'pass':(i != 0 or fixed),'code':0 if fixed and i==0 else None,'error':None if fixed and i==0 else 'HOST_CONTEXT_TRAP','context_constructions':0 if fixed and i==0 else 1,'env_read':not(fixed and i==0),'runtime_framework':'.NET 8.0.32'}).encode() for i,args in enumerate(cases)) + b'\n'
        self.module.verify_cases(rows(False), fixed=False)
        self.module.verify_cases(rows(True), fixed=True)
        with self.assertRaises(ValueError):
            self.module.verify_cases(rows(True).replace(b'"env_read": true', b'"env_read": false'), fixed=True)

    def test_authenticated_sdk_rejects_changed_or_extra_code(self):
        import hashlib
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            sdk = root / 'sdk'
            sdk.mkdir()
            archive = root / 'sdk.tar.gz'
            data = b'synthetic SDK host, never executed'
            (sdk / 'dotnet').write_bytes(data)
            with tarfile.open(archive, 'w:gz') as output:
                member = tarfile.TarInfo('dotnet')
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
            digest = hashlib.sha512(archive.read_bytes()).hexdigest()
            self.assertEqual(self.module.verify_sdk(archive, sdk, digest), 1)
            (sdk / 'unexpected.dll').write_bytes(b'synthetic extra code')
            with self.assertRaises(ValueError):
                self.module.verify_sdk(archive, sdk, digest)
            (sdk / 'unexpected.dll').unlink()
            (sdk / 'dotnet').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                self.module.verify_sdk(archive, sdk, digest)
