"""Consume the exact reviewed prior SDK A/B result; never build or fetch it."""
# SPDX-License-Identifier: MPL-2.0
import argparse
import hashlib
import json
import os
import pathlib
import stat

import _bounded_qualification as q

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROVENANCE_SHA256 = 'a40e82a78031c7199de70af0d63c36888e526d6dbf5a980afe1bbca8024aaab6'
ARCHIVE_SHA256 = '8c6ad1f743c97ab650b5c149bda95386a2b6d290b90fa8e0ea732ae89b67eee9'
INPUT_NAME = '.retained-sdk-input'


def checked_file(path, size, digest, *, content=False):
    """Read bounded regular bytes without accepting aliases or concurrent drift."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise q.Stop('retained input path is indirect')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != size:
            raise q.Stop('retained input identity differs')
        checksum = hashlib.sha256(); chunks = []
        remaining = size
        while remaining:
            data = stream.read(min(remaining, 1024 * 1024))
            if not data:
                raise q.Stop('retained input short read')
            remaining -= len(data); checksum.update(data)
            if content:
                chunks.append(data)
        if stream.read(1):
            raise q.Stop('retained input grew')
        after = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)
        if identity(before) != identity(after) or checksum.hexdigest() != digest:
            raise q.Stop('retained input hash or identity drift')
    return b''.join(chunks) if content else None


def load_pin(source):
    path = source / 'release/retained-runner-provenance.json'
    size = path.lstat().st_size
    if not 0 < size <= 16384:
        raise q.Stop('retained provenance size differs')
    return json.loads(checked_file(path, size, PROVENANCE_SHA256, content=True))


def authority(source):
    pin = load_pin(source)
    functions = q.release_functions(source)
    runner = functions['validate_runner'](json.loads((source / 'release/manifest.json').read_text())['runtime']['runner_release'])
    payload = functions['select_runner_payload'](source, runner)
    if payload['kind'] != 'dotnet-rebuild' or any(payload[k] != pin['archive'][v] for k, v in [('sha256', 'sha256'), ('archive_bytes', 'bytes'), ('asset_name', 'asset_name')]):
        raise q.Stop('retained descriptor differs from pinned producer archive')
    descriptor = json.loads((source / 'internal/buildinfo/runner_rebuild.json').read_text())
    result = pin['producer_result']
    if result['source_commit'] != descriptor['upstream_source_commit'] or result['source_patch_sha256'] != descriptor['source_patch_sha256'] or result['sdk_archive_sha512'] != descriptor['sdk_archive_sha512'] or result['reference_sdk_image'] != descriptor['sdk_container_image']:
        raise q.Stop('retained compiler or source binding differs')
    return pin, payload, functions


def receipt(source):
    pin = load_pin(source)
    return dict(schema_version=1, sdk_source='verified-retained-ab',
                sdk_build_executed_this_run=False, archive_sha256=pin['archive']['sha256'],
                archive_bytes=pin['archive']['bytes'], provenance_sha256=PROVENANCE_SHA256,
                producer_result_sha256=pin['evidence']['SDK-RESULT.json']['sha256'],
                producer_terminal_sha256=pin['evidence']['producer-terminal.json']['sha256'],
                payload_manifest_sha256=pin['archive']['manifest_sha256'],
                prior_sdk_startup_verified=True,
                verification_receipt_sha256=hashlib.sha256(public_receipt_bytes(source)).hexdigest())


def validate_receipt(source, value):
    expected = receipt(source)
    if type(value) is not dict or value != expected or any(type(value[key]) is not type(item) for key, item in expected.items()):
        raise q.Stop('retained SDK receipt differs or claims a fresh build')


RECEIPT_NAME = 'sdk-verification.json'


def public_claims(pin):
    """Project reviewed prior claims, not raw operational identifiers or traces."""
    result = pin['producer_result']
    archive = {key: pin['archive'][key] for key in ('sha256', 'bytes', 'manifest_sha256')}
    if result['status'] != 'pass' or result['archives'] != [archive, archive] or result['independent_AB_identical'] is not True or result['reference_sdk_image_executed'] is not False or result['actual_app_local_startup'] is not True or result['actual_normal_help_network_none'] is not True or any(result[key] is not False for key in ('qualification_executed', 'release_admitted', 'target_conformance_executed', 'live_operations')):
        raise q.Stop('prior SDK claims differ or imply downstream authority')
    return dict(schema_version=1, role='unqualified-sdk-input',
                archive=pin['archive'],
                source={key: result[key] for key in ('source_commit', 'source_tree', 'source_patch_sha256', 'mode_patch_sha256')},
                compiler={key: result[key] for key in ('sdk_archive_sha512', 'reference_sdk_image', 'reference_sdk_image_executed', 'compiler_source')},
                prior_build=dict(independent_AB_identical=True, app_local_startup_verified=True,
                                 listener_help_network_none_verified=True, cleanup_verified=True),
                retained_evidence=dict(provenance_sha256=PROVENANCE_SHA256,
                                       producer_result_sha256=pin['evidence']['SDK-RESULT.json']['sha256'],
                                       producer_terminal_sha256=pin['evidence']['producer-terminal.json']['sha256'],
                                       proof_manifest_sha256=hashlib.sha256(canonical(pin['evidence'])).hexdigest()),
                authority={key: False for key in ('qualification_executed', 'release_admitted', 'target_conformance_executed', 'live_operations')})


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def public_receipt_bytes(source):
    expected = canonical(public_claims(load_pin(source)))
    path = source / 'release/retained-sdk-verification.json'
    # Both source identity and the exact projection are checked, not arbitrary JSON.
    actual = checked_file(path, len(expected), hashlib.sha256(expected).hexdigest(), content=True)
    if actual != expected:
        raise q.Stop('retained public verification receipt differs')
    return expected


def verify_private_evidence(source, proof):
    """Offline derivation only: verify every original without executing any input."""
    pin, _, _ = authority(source)
    if not proof.is_absolute() or proof.resolve(strict=True) != proof or not proof.is_dir():
        raise q.Stop('retained evidence directory is indirect')
    expected = pin['evidence']
    paths = []
    for path in proof.rglob('*'):
        paths.append(path)
        if len(paths) > 2 * len(expected):
            raise q.Stop('retained evidence member count exceeds bound')
    if any(p.is_symlink() or p.resolve(strict=True) != p or not (p.is_dir() or p.is_file()) for p in paths):
        raise q.Stop('retained evidence contains an indirect member')
    if {p.relative_to(proof).as_posix() for p in paths if p.is_file()} != set(expected):
        raise q.Stop('retained evidence membership differs')
    allowed_dirs = {str(parent) for name in expected for parent in pathlib.PurePosixPath(name).parents if str(parent) != '.'}
    if {p.relative_to(proof).as_posix() for p in paths if p.is_dir()} != allowed_dirs:
        raise q.Stop('retained evidence directory membership differs')
    if sum(v['bytes'] for v in expected.values()) > 8 * 2**20:
        raise q.Stop('retained evidence exceeds bound')
    documents = {}
    for name, item in expected.items():
        raw = checked_file(proof / name, item['bytes'], item['sha256'], content=name in ('SDK-RESULT.json', 'producer-terminal.json'))
        if raw is not None:
            documents[name] = json.loads(raw)
    result = documents['SDK-RESULT.json']; terminal = documents['producer-terminal.json']
    if result != pin['producer_result'] or result['status'] != 'pass' or result['independent_AB_identical'] is not True or result['reference_sdk_image_executed'] is not False or result['actual_app_local_startup'] is not True or result['actual_normal_help_network_none'] is not True:
        raise q.Stop('retained SDK producer result differs')
    if any(terminal.get(k) != v for k, v in result.items()) or terminal.get('cleanup_verified') is not True:
        raise q.Stop('retained SDK terminal cleanup differs')

    return public_receipt_bytes(source)


def verify_inputs(source, directory):
    pin, payload, _ = authority(source)
    if not directory.is_absolute() or directory.resolve(strict=True) != directory or not directory.is_dir():
        raise q.Stop('retained input directory is indirect')
    if {p.name for p in directory.iterdir()} != {payload['asset_name'], RECEIPT_NAME}:
        raise q.Stop('retained input closure differs')
    expected = public_receipt_bytes(source)
    checked_file(directory / RECEIPT_NAME, len(expected), hashlib.sha256(expected).hexdigest())
    checked_file(directory / payload['asset_name'], payload['archive_bytes'], payload['sha256'])
    return receipt(source)


def stage(source, directory, destination):
    result = verify_inputs(source, directory)
    _, payload, functions = authority(source)
    if not destination.is_absolute() or destination.parent.resolve(strict=True) != destination.parent or destination.exists() or destination.is_symlink():
        raise q.Stop('fresh retained SDK destination required')
    destination.mkdir(mode=0o700)
    archive = destination / payload['asset_name']
    try:
        functions['copy_rebuilt_runner_archive'](directory / payload['asset_name'], archive, payload)
        archive.chmod(0o400)
    except BaseException:
        archive.unlink(missing_ok=True)
        destination.rmdir()
        raise
    return archive, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-directory', type=pathlib.Path, required=True)
    parser.add_argument('--output-directory', type=pathlib.Path, required=True)
    args = parser.parse_args()
    archive, _ = stage(ROOT, args.input_directory, args.output_directory)
    print(archive)


if __name__ == '__main__':
    main()
