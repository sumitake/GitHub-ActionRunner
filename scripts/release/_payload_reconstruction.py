"""Exact-subject reconstruction; never a qualification or release admission."""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import json
import os
import pathlib
import re
import stat

import _bounded_qualification as q

COMMIT = '874fcc9557166d94a97026ae7c966c99fa598fa9'
TREE = '8fbc190401b664d434bb405303efd714e0fce1aa'
EXPECTED_SHA256 = 'cf457df91c94f6afdd0edf88b2be7b202d97dd7af4906446fe05aa52e028b8a6'
BRANCH = 'refs/heads/codex/rr7-payload-reconstruction'


def stable_bytes(path, limit=2**20):
    info = path.lstat()
    if path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
        raise q.Stop('unsafe reconstruction metadata')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise q.Stop('reconstruction metadata replaced')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(raw) != info.st_size or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise q.Stop('reconstruction metadata changed')
    return raw


def parse(raw):
    try:
        return json.loads(raw, object_pairs_hook=q._trivy_report.unique, parse_constant=q._trivy_report.nonfinite)
    except (ValueError, UnicodeError) as error:
        raise q.Stop('invalid reconstruction JSON') from error


def read_json(path, limit=2**20):
    return parse(stable_bytes(path, limit))


def expected():
    here = pathlib.Path(__file__).resolve().parent
    path = here / 'reconstruction-identities.json'
    if not path.exists():
        path = here.parents[1] / 'release/reconstruction-identities.json'
    raw = stable_bytes(path)
    value = parse(raw)
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256 or value['source_commit'] != COMMIT or value['source_tree'] != TREE:
        raise q.Stop('reconstruction identity authority changed')
    return value


def verify_source(source, command):
    def git(*args):
        return command(['git', '-c', 'safe.directory=' + str(source), *args], cwd=source)
    if source.resolve(strict=True) != source or git('rev-parse', 'HEAD') != COMMIT or git('rev-parse', 'HEAD^{tree}') != TREE or git('status', '--porcelain', '--untracked-files=all'):
        raise q.Stop('qualified source identity changed')
    # Git's executable bit alone does not detect the recovered tar's group-write.
    for entry in git('ls-tree', '-r', 'HEAD').splitlines():
        meta, name = entry.split('\t', 1)
        mode, kind, _ = meta.split()
        path = source / name
        info = path.lstat()
        if mode not in ('100644', '100755') or kind != 'blob' or path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != int(mode, 8) & 0o777:
            raise q.Stop('qualified source file mode changed')


def admission(source, tooling, event, environment, command):
    repo = event.get('repository', {})
    values = event.get('inputs', {})
    required = {'bounded_qualification', 'metadata_probe', 'payload_reconstruction', 'expected_commit', 'expected_tree', 'carry_in_bytes'}
    if environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or environment.get('RUNNER_ENVIRONMENT') != 'github-hosted' or environment.get('RUNNER_OS') != 'Linux' or environment.get('RUNNER_ARCH') != 'X64' or environment.get('GITHUB_REF') != BRANCH or environment.get('GITHUB_RUN_ATTEMPT') != '1':
        raise q.Stop('manual hosted reconstruction dispatch required')
    if repo.get('private') is not False or repo.get('full_name') != 'sumitake/GitHub-ActionRunner' or environment.get('GITHUB_REPOSITORY') != repo['full_name'] or environment.get('GITHUB_ACTOR') != repo.get('owner', {}).get('login'):
        raise q.Stop('public repository owner required')
    if not isinstance(values, dict) or set(values) != required or values.get('payload_reconstruction') != 'true' or values.get('bounded_qualification') != 'false' or values.get('metadata_probe') != 'false':
        raise q.Stop('closed reconstruction inputs required')
    for key in ('expected_commit', 'expected_tree'):
        if not isinstance(values[key], str) or re.fullmatch('[0-9a-f]{40}', values[key]) is None:
            raise q.Stop('exact tooling identity required')
    if source.parent != tooling.parent or source.name != 'product' or tooling.name != 'tooling' or str(source.parent) != environment.get('GITHUB_WORKSPACE'):
        raise q.Stop('separate accounted product and tooling checkouts required')
    if environment.get('GITHUB_SHA') != values['expected_commit'] or tooling.resolve(strict=True) != tooling or command(['git', '-c', 'safe.directory=' + str(tooling), 'rev-parse', 'HEAD'], cwd=tooling) != values['expected_commit'] or command(['git', '-c', 'safe.directory=' + str(tooling), 'rev-parse', 'HEAD^{tree}'], cwd=tooling) != values['expected_tree'] or command(['git', '-c', 'safe.directory=' + str(tooling), 'status', '--porcelain', '--untracked-files=all'], cwd=tooling):
        raise q.Stop('reviewed tooling checkout changed')
    carry = values['carry_in_bytes']
    run_id = environment.get('GITHUB_RUN_ID', '')
    if not isinstance(carry, str) or re.fullmatch('[1-9][0-9]{0,10}', carry) is None or not q.RESERVE <= int(carry) < q.SOFT - 64 * 2**20 or re.fullmatch('[1-9][0-9]{0,19}', run_id) is None:
        raise q.Stop('reconstruction resource admission failed')
    verify_source(source, command)
    expected()
    return {'schema_version': 1, 'payload_reconstruction': True, 'metadata_probe': False, 'commit': COMMIT, 'tree': TREE, 'epoch': 1792478220, 'carry_in_bytes': int(carry), 'run_id': run_id, 'repository': repo['full_name'], 'tooling_checkout': str(tooling), 'tooling_commit': values['expected_commit'], 'tooling_tree': values['expected_tree'], 'live_operations': False}



def stage_tooling(tooling, destination, command):
    destination.mkdir(mode=0o700)
    rows = command(['git', '-c', 'safe.directory=' + str(tooling), 'ls-tree', '-r', 'HEAD', 'scripts/release'], cwd=tooling)
    for entry in rows.splitlines():
        meta, name = entry.split('\t', 1)
        mode, kind, oid = meta.split()
        relative = pathlib.PurePosixPath(name).relative_to('scripts/release')
        if mode not in ('100644', '100755') or kind != 'blob' or '..' in relative.parts:
            raise q.Stop('unsafe tooling member')
        source = tooling / name
        info = source.lstat()
        if source.resolve(strict=True) != source or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise q.Stop('indirect tooling member')
        raw = source.read_bytes()
        if hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != oid:
            raise q.Stop('tooling member changed')
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(int(mode, 8) & 0o777)
    raw = (tooling / 'release/reconstruction-identities.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise q.Stop('tooling identity authority changed')
    (destination / 'reconstruction-identities.json').write_bytes(raw)


def compare(root, worker, authority):
    actual = [{'path': 'artifacts/' + row['path'], 'bytes': row['bytes'], 'sha256': row['sha256']} for row in q.inventory(worker.artifacts)]
    want = sorted(authority['required_original_members'], key=lambda row: row['path'])
    if sorted(actual, key=lambda row: row['path']) != want:
        raise q.Stop('reconstructed payload bytes differ')
    if len(worker.images) != 5:
        raise q.Stop('reconstructed image membership changed')
    for row in authority['runtime_images'].values():
        found = [image for image in worker.images if image['image'] == row['image'] and image['phase'] == 'A']
        if len(found) != 1 or found[0]['oci_graph'] != row['oci_graph'] or found[0]['source_to_image'] != row['source_to_image']:
            raise q.Stop('reconstructed OCI identity differs')
    inputs = read_json(root / 'inputs.json')
    receipt = {'status': 'pass', 'reconstruction_matched': True, 'expected_sha256': EXPECTED_SHA256, 'source_commit': COMMIT, 'source_tree': TREE, 'tooling_commit': inputs['tooling_commit'], 'tooling_tree': inputs['tooling_tree'], 'binary_count': 11, 'runtime_image_count': 5, 'file_count': len(actual), 'file_content_bytes': sum(row['bytes'] for row in actual), 'qualification_executed': False, 'release_admitted': False, 'target_conformance_executed': False, 'live_operations': False}
    q.write(root / 'evidence/reconstruction-result.json', receipt)
    public = root / 'public'
    public.mkdir(mode=0o700)
    # Only identical, previously qualified subject bytes and fixed receipts.
    # Fresh native logs/metadata stay private; no publication rule is relaxed.
    worker.artifacts.rename(public / 'artifacts')
    q.write(public / 'payload-identity-comparison.json', receipt)
    q.write(public / 'payload-inventory.json', {'files': want})


def finalize(root, final):
    if root.resolve(strict=True) != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise q.Stop('unsafe reconstruction root')
    root.chmod(0o700)
    if final.get('resource_qualification') != 'pass' or final.get('workers_joined') is not True or final.get('scope_exit_code') != 0:
        final['status'] = 'fail'
    public = root / 'public'
    if public.exists():
        if public.resolve(strict=True) != public or not stat.S_ISDIR(public.lstat().st_mode):
            raise q.Stop('unsafe reconstruction publication root')
        q.write(public / 'RESULT.json', final)
    if final.get('status') != 'pass' or not public.exists():
        raise q.Stop('reconstruction or resource proof failed')
    for path in root.iterdir():
        if path.name == 'public':
            continue
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            path.chmod(0o700)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            path.chmod(0o600)
        else:
            raise q.Stop('unsafe private reconstruction entry')
    for path in [public, *public.rglob('*')]:
        info = path.lstat()
        if path.resolve(strict=True) != path or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
            raise q.Stop('unsafe reconstruction publication member')
        path.chmod(0o755 if stat.S_ISDIR(info.st_mode) else 0o644)
    root.chmod(0o755)


def check_upload(public):
    # Invoked in a separate read-only, two-minute resource-bounded scope.
    if public.resolve(strict=True) != public or not stat.S_ISDIR(public.lstat().st_mode):
        raise q.Stop('unsafe reconstruction upload root')
    files = q.inventory(public)
    if sum(row['bytes'] for row in files) > q.ARTIFACT_LIMIT:
        raise q.Stop('reconstruction transfer limit exceeded')
    if {row['path'] for row in files if not row['path'].startswith('artifacts/')} != {'RESULT.json', 'payload-identity-comparison.json', 'payload-inventory.json'}:
        raise q.Stop('unexpected reconstruction publication member')
    authority = expected()
    want = sorted(authority['required_original_members'], key=lambda row: row['path'])
    if [row for row in files if row['path'].startswith('artifacts/')] != want:
        raise q.Stop('reconstruction payload changed before upload')
    final = read_json(public / 'RESULT.json')
    proof = read_json(public / 'payload-identity-comparison.json')
    inventory = read_json(public / 'payload-inventory.json')
    fields = {'status', 'reconstruction_matched', 'expected_sha256', 'source_commit', 'source_tree', 'tooling_commit', 'tooling_tree', 'binary_count', 'runtime_image_count', 'file_count', 'file_content_bytes', 'qualification_executed', 'release_admitted', 'target_conformance_executed', 'live_operations'}
    if set(proof) != fields or set(final) != fields | {'resource_qualification', 'workers_joined', 'scope_exit_code'}:
        raise q.Stop('unexpected reconstruction receipt field')
    if any(final[key] != proof[key] for key in fields) or inventory != {'files': want}:
        raise q.Stop('reconstruction receipt binding changed')
    if final.get('status') != 'pass' or final.get('resource_qualification') != 'pass' or final.get('workers_joined') is not True or type(final.get('scope_exit_code')) is not int or final['scope_exit_code'] != 0 or proof.get('reconstruction_matched') is not True or proof.get('expected_sha256') != EXPECTED_SHA256 or proof.get('source_commit') != COMMIT or proof.get('source_tree') != TREE:
        raise q.Stop('reconstruction upload not admitted')
    if any(proof.get(key) is not False for key in ('qualification_executed', 'release_admitted', 'target_conformance_executed', 'live_operations')) or any(not isinstance(proof.get(key), str) or re.fullmatch('[0-9a-f]{40}', proof[key]) is None for key in ('tooling_commit', 'tooling_tree')):
        raise q.Stop('reconstruction authority misclassified')
    if (proof['binary_count'], proof['runtime_image_count'], proof['file_count'], proof['file_content_bytes']) != (11, 5, authority['file_count'], authority['file_content_bytes']):
        raise q.Stop('reconstruction subject counts changed')
