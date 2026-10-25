#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Check the prospective metadata fastpath with authenticated SDK8 inputs.

This produces source-boundary evidence only. It neither constructs/adopts a
runner archive nor changes its existing admitted descriptor or release locks.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
PATCH_SHA256 = '10c8b068f7a31520ad2cad60a0788ed416c59a71b8b933a8884bad7ea14f7648'
PROGRAM_BLOB = 'd2923736402decc05ccbf79ca600fe68f9a3f702'
CASES = [['--version'], [], ['run'], ['--version', 'extra'], ['--Version'], ['--commit'], ['--help'], ['--version', '--help']]
LIMIT = 1 << 20


def verify_toolchain(sdk, runtime):
    if sdk != b'8.0.426\n' or not any(line.startswith(b'Microsoft.NETCore.App 8.0.32 ') for line in runtime.splitlines()):
        raise ValueError('exact SDK8/runtime8 required')


def verify_patch(data):
    if hashlib.sha256(data).hexdigest() != PATCH_SHA256:
        raise ValueError('reviewed source patch differs')


def verify_cases(raw, *, fixed):
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) != len(CASES):
        raise ValueError('incomplete source contract evidence')
    for i, (args, row) in enumerate(zip(CASES, rows)):
        fast = fixed and i == 0
        expected = {'argv': args, 'pass': fixed or i != 0, 'code': 0 if fast else None,
                    'error': None if fast else 'HOST_CONTEXT_TRAP',
                    'context_constructions': 0 if fast else 1, 'env_read': not fast,
                    'runtime_framework': '.NET 8.0.32'}
        if row != expected:
            raise ValueError('incorrect source contract result')


def verify_sdk(archive, sdk_root, expected_sha512):
    if not archive.is_file() or archive.is_symlink() or archive.stat().st_size > 512 * 2**20:
        raise ValueError('invalid SDK archive')
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha512').hexdigest() != expected_sha512:
            raise ValueError('SDK archive input differs')
    count = 0
    total = 0
    expected = set()
    with tarfile.open(archive) as files:
        for member in files:
            relative = pathlib.PurePosixPath(member.name.removeprefix('./'))
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('unsafe authenticated SDK path')
            path = sdk_root.joinpath(*relative.parts)
            if member.isdir():
                if path.is_symlink() or not path.is_dir():
                    raise ValueError('SDK directory differs')
                continue
            expected.add(relative.as_posix())
            count += 1
            total += member.size
            if count > 32768 or total > 3 * 2**30:
                raise ValueError('SDK input bounds')
            if member.issym():
                if not path.is_symlink() or os.readlink(path) != member.linkname:
                    raise ValueError('SDK symbolic link differs')
            elif member.isfile() or member.islnk():
                if path.is_symlink() or not path.resolve(strict=True).is_relative_to(sdk_root) or not path.is_file():
                    raise ValueError('SDK file path differs')
                source = files.extractfile(member)
                if source is None:
                    raise ValueError('SDK archive member unavailable')
                with source, path.open('rb') as installed:
                    if hashlib.file_digest(source, 'sha256').digest() != hashlib.file_digest(installed, 'sha256').digest():
                        raise ValueError('SDK installed bytes differ')
            else:
                raise ValueError('unexpected SDK member type')
    if count == 0:
        raise ValueError('empty SDK archive')
    actual = {path.relative_to(sdk_root).as_posix() for path in sdk_root.rglob('*')
              if path.is_symlink() or not path.is_dir()}
    if actual != expected:
        raise ValueError('unexpected SDK files')
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream-source', type=pathlib.Path, required=True)
    parser.add_argument('--sdk-root', type=pathlib.Path, required=True)
    parser.add_argument('--sdk-archive', type=pathlib.Path, required=True)
    parser.add_argument('--output-directory', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
        raise ValueError('pinned SDK archive validation requires Linux x64')
    source = args.upstream_source.resolve(strict=True)
    sdk_root = args.sdk_root.resolve(strict=True)
    archive = args.sdk_archive.resolve(strict=True)
    output = args.output_directory
    if not output.is_absolute() or output.exists() or output.is_symlink() or output.parent.resolve(strict=True) != output.parent:
        raise ValueError('fresh canonical output directory required')
    descriptor = json.loads((ROOT / 'internal/buildinfo/runner_rebuild.json').read_text())
    if (descriptor['dotnet_sdk_version'], descriptor['dotnet_runtime_version']) != ('8.0.426', '8.0.32'):
        raise ValueError('different SDK source authority')
    sdk_files = verify_sdk(archive, sdk_root, descriptor['sdk_archive_sha512'])
    base_patch = (ROOT / 'release/runner-rebuild.patch').read_bytes()
    if hashlib.sha256(base_patch).hexdigest() != descriptor['source_patch_sha256']:
        raise ValueError('admitted SDK provenance drift')
    patch = (ROOT / 'release/runner-version-smoke.patch').read_bytes()
    verify_patch(patch)
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if head != descriptor['upstream_source_commit']:
        raise ValueError('different upstream source')
    baseline = subprocess.check_output(['git', '-C', str(source), 'show', head + ':src/Runner.Listener/Program.cs'])
    if hashlib.sha1(b'blob ' + str(len(baseline)).encode() + b'\0' + baseline).hexdigest() != PROGRAM_BLOB:
        raise ValueError('different upstream Program')
    output.mkdir(mode=0o700)
    contract = output / 'contract'
    shutil.copytree(ROOT / 'tests/fixtures/runner-version-source', contract)
    proposal = output / 'proposal/src/Runner.Listener'
    proposal.mkdir(parents=True)
    (proposal / 'Program.cs').write_bytes(baseline)
    subprocess.run(['git', 'apply', '--check', str(ROOT / 'release/runner-version-smoke.patch')], cwd=output / 'proposal', check=True)
    subprocess.run(['git', 'apply', str(ROOT / 'release/runner-version-smoke.patch')], cwd=output / 'proposal', check=True)
    fixed = (proposal / 'Program.cs').read_bytes()
    state = output / 'cli'
    state.mkdir(mode=0o700)
    env = {k: os.environ[k] for k in ('HOME', 'PATH', 'LANG') if k in os.environ}
    env.update(DOTNET_ROOT=str(sdk_root), DOTNET_CLI_HOME=str(state), NUGET_PACKAGES=str(state / 'packages'),
               NUGET_HTTP_CACHE_PATH=str(state / 'http-cache'), DOTNET_CLI_TELEMETRY_OPTOUT='1',
               DOTNET_GENERATE_ASPNET_CERTIFICATE='false', DOTNET_ADD_GLOBAL_TOOLS_TO_PATH='false',
               DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true', DOTNET_NOLOGO='1',
               MSBUILDDISABLENODEREUSE='1', DOTNET_PROCESSOR_COUNT='2', TMPDIR=str(state))
    (output / 'global.json').write_text(json.dumps({'sdk': {'version': '8.0.426', 'rollForward': 'disable', 'allowPrerelease': False}}))
    cli = sdk_root / 'dotnet'
    rows = []
    def run(arguments, name, expected=0):
        result = subprocess.run([str(cli), *arguments], cwd=contract, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=90)
        if max(len(result.stdout), len(result.stderr)) > LIMIT:
            raise ValueError('oversized source test log')
        (output / (name + '.stdout')).write_bytes(result.stdout)
        (output / (name + '.stderr')).write_bytes(result.stderr)
        rows.append({'name': name, 'exit_code': result.returncode, 'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
                     'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()})
        (output / 'progress.json').write_text(json.dumps(rows, indent=2) + '\n')
        if result.returncode != expected:
            raise ValueError('source test command failed: ' + name)
        return result.stdout
    sdk = run(['--version'], 'SDK')
    runtime = run(['--list-runtimes'], 'runtime')
    verify_toolchain(sdk, runtime)
    (contract / 'Program.cs').write_bytes(baseline)
    run(['restore', 'contract.csproj', '--configfile', 'NuGet.Config', '-p:ImportDirectoryBuildProps=false', '-p:ImportDirectoryBuildTargets=false'], 'restore')
    build = ['build', 'contract.csproj', '--no-restore', '-c', 'Release', '-p:UseSharedCompilation=false', '-p:ImportDirectoryBuildProps=false', '-p:ImportDirectoryBuildTargets=false']
    run(build, 'baseline-build')
    verify_cases(run([str(contract / 'bin/Release/net8.0/contract.dll')], 'baseline-RED', expected=1), fixed=False)
    (contract / 'Program.cs').write_bytes(fixed)
    run(build, 'proposal-build')
    verify_cases(run([str(contract / 'bin/Release/net8.0/contract.dll')], 'proposal-GREEN'), fixed=True)
    proof = {'status': 'pass', 'source_boundary_cases': len(CASES), 'sdk': '8.0.426', 'runtime': '8.0.32',
             'upstream_source_commit': head, 'upstream_Program_git_blob': PROGRAM_BLOB,
             'baseline_Program_sha256': hashlib.sha256(baseline).hexdigest(), 'fixed_Program_sha256': hashlib.sha256(fixed).hexdigest(),
             'sdk_archive_sha512': descriptor['sdk_archive_sha512'], 'authenticated_sdk_files': sdk_files,
             'checker_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
             'fixture_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted((ROOT / 'tests/fixtures/runner-version-source').iterdir()) if path.is_file()},
             'admitted_source_patch_sha256': descriptor['source_patch_sha256'],
             'additional_source_patch_sha256': PATCH_SHA256, 'prospective_combined_patch_sha256': hashlib.sha256(base_patch + patch).hexdigest(),
             'sdk_archive_or_product_artifact_constructed': False, 'admission_or_target_acceptance': False,
             'limits': 'Actual Program.Main with synthetic dependency traps; not a full runner or final product image execution.', 'steps': rows}
    (output / 'RESULT.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof))


if __name__ == '__main__':
    main()
