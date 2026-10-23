"""Bounded fixed-Go rebuild of qualified source; no target or release admission."""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import tarfile
import time
import urllib.request
import urllib.parse

import _bounded_qualification as q
import _payload_reconstruction as original

VERSION = 'go1.26.10'
URL = 'https://go.dev/dl/go1.26.10.linux-amd64.tar.gz'
ARCHIVE_BYTES = 66936659
ARCHIVE_SHA256 = 'ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5'
SDK_SHA256 = 'abd94fed68a6e31394b68103e1afa8b0eabe36b523cc781e00bf2b01f452ce29'
SDK_BYTES = 220723260
MAX_EXTRACTED = q.GIB
MAX_MEMBERS = 40000
FOCUSED = ['fixed-go-version', 'fixed-go-tls-tests', 'fixed-go-govulncheck', 'module-verify', 'linked-identity-test']
PROOF_FIELDS = {'schema_version', 'status', 'go_patch_refresh', 'reconstruction_matched', 'source_commit', 'source_tree', 'original_authority_sha256', 'tooling_commit', 'tooling_tree', 'compiler', 'version', 'binary_count', 'runtime_image_count', 'independent_AB_identical', 'focused_checks', 'sdk_archive_sha256', 'sdk_archive_bytes', 'sdk_dotnet_unchanged', 'qualification_executed', 'release_admitted', 'target_conformance_executed', 'live_operations', 'source_toolchain_directive', 'explicit_compiler_override', 'binary_toolchain_checks'}
NON_GO_LAYERS = {'runner': (0, 1, 3, 4), 'network-adapter': (0, 2, 3), 'network-broker-dialer': (0, 1, 2, 3, 4, 7, 8, 9), 'network-helper': (0, 1, 3, 4, 5), 'network-verifier': (0, 1, 2, 4, 5, 6)}
PUBLIC_METADATA = {'RESULT.json', 'go-refresh-identities.json', 'payload-inventory.json'}


def compiler_identity(root):
    if root.resolve(strict=True) != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise q.Stop('unsafe fixed compiler root')
    directories = []
    for path in [root, *sorted(root.rglob('*'))]:
        if path.is_dir():
            if path.resolve(strict=True) != path or stat.S_IMODE(path.lstat().st_mode) != 0o555:
                raise q.Stop('fixed compiler directory is writable or indirect')
            directories.append({'path': path.relative_to(root).as_posix(), 'mode': 0o555})
    rows = q.inventory(root)
    for row in rows:
        mode = stat.S_IMODE((root / row['path']).lstat().st_mode)
        if mode not in (0o444, 0o555):
            raise q.Stop('fixed compiler is writable or has unsafe mode')
        row['mode'] = mode
    return hashlib.sha256(json.dumps({'files': rows, 'directories': directories}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def extract(archive, destination):
    """Do not delegate archive paths, links, modes or size policy to tar."""
    seen = set()
    total = 0
    with tarfile.open(archive, 'r|gz') as stream:
        for member in stream:
            name = pathlib.PurePosixPath(member.name)
            if not name.parts or name.parts[0] != 'go' or '..' in name.parts or str(name) != member.name.rstrip('/') or name in seen or len(seen) >= MAX_MEMBERS or not (member.isfile() or member.isdir()) or member.mode & 0o7022 or member.size < 0:
                raise q.Stop('unsafe fixed compiler archive member')
            seen.add(name)
            total += member.size
            if total > MAX_EXTRACTED or (member.isdir() and member.size):
                raise q.Stop('fixed compiler extraction limit exceeded')
            path = destination / name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as source, path.open('xb') as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                if path.stat().st_size != member.size:
                    raise q.Stop('truncated fixed compiler member')
                path.chmod(0o555 if member.mode & 0o111 else 0o444)
    root = destination / 'go'
    if not (root / 'bin/go').is_file() or not (root / 'pkg/tool/linux_amd64/compile').is_file():
        raise q.Stop('fixed compiler executable missing')
    for path in [*root.rglob('*'), root]:
        if path.is_dir():
            path.chmod(0o555)
    return root


class OfficialHTTPS(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname not in ('go.dev', 'dl.google.com') or parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443):
            raise q.Stop('nonofficial or insecure compiler redirect')
        return super().redirect_request(request, response, code, message, headers, url)


def open_official():
    return urllib.request.build_opener(OfficialHTTPS()).open(URL, timeout=30)


def acquire(destination):
    # Called only after aggregate observer admission. Entire parent workspace
    # (archive AND extracted compiler) remains charged until the run joins.
    if destination.exists() or destination.parent.resolve(strict=True) != destination.parent:
        raise q.Stop('fresh accounted compiler destination required')
    destination.mkdir(mode=0o700)
    archive = destination / 'go.tar.gz'
    started = time.monotonic()
    with open_official() as response, archive.open('xb') as target:
        size = 0
        while block := response.read(1024 * 1024):
            size += len(block)
            if size > ARCHIVE_BYTES or time.monotonic() - started > 300:
                raise q.Stop('fixed compiler download limit exceeded')
            target.write(block)
    if size != ARCHIVE_BYTES or q.sha(archive) != ARCHIVE_SHA256:
        raise q.Stop('fixed compiler archive identity mismatch')
    root = extract(archive, destination)
    return root, {'version': VERSION, 'os': 'linux', 'arch': 'amd64', 'archive_sha256': ARCHIVE_SHA256, 'archive_bytes': ARCHIVE_BYTES, 'extracted_tree_sha256': compiler_identity(root)}


def constrain_compiler(root, environment):
    # Qualified source scripts explicitly select their historical compiler.
    # Preserve those source bytes while binding ALL Go calls to the fixed mount.
    if environment.get('GOROOT') != '/toolchain/go':
        raise q.Stop('fixed read-only compiler mount required')
    directory = root / 'fixed-go-bin'
    directory.mkdir(mode=0o700)
    wrapper = directory / 'go'
    wrapper.write_text('#!/bin/sh\nGOTOOLCHAIN=local\nexport GOTOOLCHAIN\nexec /toolchain/go/bin/go "$@"\n')
    wrapper.chmod(0o555)
    return {**environment, 'PATH': str(directory) + ':' + environment['PATH']}


def compare(root, worker):
    authority = original.expected()
    binaries = original.read_json(worker.output / 'binary-comparison.json')
    rows = binaries['binaries']
    if binaries['all_eleven_identical'] is not True or len(rows) != 22 or len(worker.images) != 10:
        raise q.Stop('fixed Go A/B proof incomplete')
    names = {row['name'] for row in authority['binaries']}
    expected_images = {row['image'] for row in authority['runtime_images'].values()}
    if any({row['name'] for row in rows if row['phase'] == phase} != names for phase in ('A', 'B')):
        raise q.Stop('fixed Go binary membership changed')
    for name in names:
        a, b = [next(row for row in rows if row['phase'] == phase and row['name'] == name) for phase in ('A', 'B')]
        if (a['sha256'], a['bytes']) != (b['sha256'], b['bytes']):
            raise q.Stop('fixed Go binary reproducibility mismatch')
    images = []
    for name in sorted(expected_images):
        pair = [next(row for row in worker.images if row['phase'] == phase and row['image'] == name) for phase in ('A', 'B')]
        if any(pair[0][key] != pair[1][key] for key in ('oci_graph', 'source_to_image', 'files')):
            raise q.Stop('fixed Go image reproducibility mismatch')
        images.append({'image': name, 'oci_graph': pair[0]['oci_graph'], 'source_to_image': pair[0]['source_to_image']})
    selected = original.read_json(worker.output / 'selected-payload.json')
    descriptor = selected['descriptor']
    if selected['archive_sha256'] != SDK_SHA256 or selected['archive_bytes'] != SDK_BYTES or selected['all_entrypoints_verified'] is not True or descriptor != json.loads((worker.source / 'internal/buildinfo/runner_rebuild.json').read_text()):
        raise q.Stop('unchanged SDK/.NET identity mismatch')
    commands = original.read_json(worker.output / 'commands-build.json')
    required = FOCUSED
    if any(len([row for row in commands if row['name'] == name and row['exit_code'] == 0]) != 1 for name in required):
        raise q.Stop('fixed compiler focused checks incomplete')
    versions = [row for row in commands if row['name'].startswith('binary-toolchain-') and row['exit_code'] == 0]
    if {row['name'] for row in versions} != {'binary-toolchain-' + phase + '-' + name for phase in ('A', 'B') for name in names} or len(versions) != 22:
        raise q.Stop('binary compiler metadata incomplete')
    compiler = original.read_json(worker.output / 'go-compiler.json')
    inputs = original.read_json(root / 'inputs.json')
    proof = {'source_toolchain_directive': 'go1.26.9', 'explicit_compiler_override': True, 'binary_toolchain_checks': 22, 'schema_version': 1, 'status': 'pass', 'go_patch_refresh': True, 'reconstruction_matched': False, 'source_commit': original.COMMIT, 'source_tree': original.TREE, 'original_authority_sha256': original.EXPECTED_SHA256, 'tooling_commit': inputs['tooling_commit'], 'tooling_tree': inputs['tooling_tree'], 'compiler': compiler, 'version': worker.version, 'binary_count': 11, 'runtime_image_count': 5, 'independent_AB_identical': True, 'focused_checks': required, 'sdk_archive_sha256': SDK_SHA256, 'sdk_archive_bytes': SDK_BYTES, 'sdk_dotnet_unchanged': True, 'qualification_executed': False, 'release_admitted': False, 'target_conformance_executed': False, 'live_operations': False}
    # Public schema contains only fixed receipts, public names and hash identities.
    identities = {'proof': proof, 'binaries': [{key: row[key] for key in ('name', 'sha256', 'bytes')} for row in rows if row['phase'] == 'A'], 'images': images}
    files = [{'path': 'artifacts/' + row['path'], 'bytes': row['bytes'], 'sha256': row['sha256']} for row in q.inventory(worker.artifacts)]
    validate_subjects(worker.artifacts, identities, worker.release)
    q.write(root / 'evidence/reconstruction-result.json', proof)
    public = root / 'public'
    public.mkdir(mode=0o700)
    worker.artifacts.rename(public / 'artifacts')
    q.write(public / 'go-refresh-identities.json', identities)
    q.write(public / 'payload-inventory.json', {'files': files})


def validate_subjects(artifacts, identities, functions):
    names = {row['name'] for row in original.expected()['binaries']}
    images = {row['image'] for row in original.expected()['runtime_images'].values()}
    if set(identities) != {'proof', 'binaries', 'images'} or len(identities['binaries']) != 11 or len(identities['images']) != 5 or {row['name'] for row in identities['binaries']} != names or {row['image'] for row in identities['images']} != images or {path.name for path in artifacts.iterdir()} != {'binaries-A', 'images-A'}:
        raise q.Stop('unexpected fixed Go subjects')
    if {path.name for path in (artifacts / 'binaries-A').iterdir()} != names or {path.name for path in (artifacts / 'images-A').iterdir()} != images:
        raise q.Stop('fixed Go subject membership changed')
    for row in identities['binaries']:
        path = artifacts / 'binaries-A' / row['name']
        old_binary = next(value for value in original.expected()['binaries'] if value['name'] == row['name'])
        if row['sha256'] == old_binary['sha256']:
            raise q.Stop('old Go binary cannot claim refresh')
        if set(row) != {'name', 'sha256', 'bytes'} or q.sha(path) != row['sha256'] or path.stat().st_size != row['bytes']:
            raise q.Stop('fixed Go binary identity mismatch')
    for row in identities['images']:
        binding = row['source_to_image']
        old = next(value for value in original.expected()['runtime_images'].values() if value['image'] == row['image'])
        binaries = {value['name']: value['sha256'] for value in identities['binaries']}
        if set(binding) != {'uid', 'embedded_binaries', 'stamp'} or binding['uid'] != '65532:65532' or binding['stamp'] != 'portable-ghar-build-identity-v1|candidate-' + original.COMMIT[:12] + '-go1.26.10|' + original.COMMIT or binding['embedded_binaries'] != {name: binaries[pathlib.PurePosixPath(name).name] for name in old['source_to_image']['embedded_binaries']}:
            raise q.Stop('fixed Go embedded binary binding changed')
        directory = artifacts / 'images-A' / row['image']
        if set(row) != {'image', 'oci_graph', 'source_to_image'} or q.graph(directory, functions) != row['oci_graph']:
            raise q.Stop('fixed Go image graph mismatch')
        graph = row['oci_graph']
        previous = old['oci_graph']
        if len(graph['layer_digests']) != len(previous['layer_digests']) or any(graph[key] == previous[key] for key in ('index_digest', 'manifest_digest', 'config_digest')) or any(graph['layer_digests'][index] != previous['layer_digests'][index] for index in NON_GO_LAYERS[row['image']]):
            raise q.Stop('Go refresh changed immutable layers or retained old image identity')
        observed = q.image_binary_binding(directory, graph, row['image'], binding['stamp'], binding['embedded_binaries'])
        if observed != binding:
            raise q.Stop('uploaded image binary binding mismatch')


def finalize(root, final):
    original.finalize(root, final)


def check_upload(public):
    if public.resolve(strict=True) != public or not stat.S_ISDIR(public.lstat().st_mode):
        raise q.Stop('unsafe fixed Go upload root')
    files = q.inventory(public)
    if sum(row['bytes'] for row in files) > q.ARTIFACT_LIMIT or {row['path'] for row in files if not row['path'].startswith('artifacts/')} != PUBLIC_METADATA:
        raise q.Stop('fixed Go upload limit or metadata membership changed')
    identities = original.read_json(public / 'go-refresh-identities.json')
    proof = identities['proof']
    if set(proof) != PROOF_FIELDS or proof['schema_version'] != 1 or proof['focused_checks'] != FOCUSED or proof['source_toolchain_directive'] != 'go1.26.9' or proof['explicit_compiler_override'] is not True or proof['binary_toolchain_checks'] != 22 or any(not isinstance(proof[key], str) or re.fullmatch('[0-9a-f]{40}', proof[key]) is None for key in ('tooling_commit', 'tooling_tree')):
        raise q.Stop('unexpected fixed Go proof field')
    final = original.read_json(public / 'RESULT.json')
    if set(final) != set(proof) | {'resource_qualification', 'workers_joined', 'scope_exit_code'} or any(final[key] != value for key, value in proof.items()) or final['resource_qualification'] != 'pass' or final['workers_joined'] is not True or type(final['scope_exit_code']) is not int or final['scope_exit_code'] != 0:
        raise q.Stop('fixed Go resource receipt incomplete')
    if proof['status'] != 'pass' or proof['go_patch_refresh'] is not True or proof['reconstruction_matched'] is not False or proof['source_commit'] != original.COMMIT or proof['source_tree'] != original.TREE or proof['original_authority_sha256'] != original.EXPECTED_SHA256 or proof['independent_AB_identical'] is not True or proof['sdk_archive_sha256'] != SDK_SHA256 or proof['sdk_archive_bytes'] != SDK_BYTES or proof['sdk_dotnet_unchanged'] is not True or proof['version'] != 'candidate-' + original.COMMIT[:12] + '-go1.26.10' or (proof['binary_count'], proof['runtime_image_count']) != (11, 5):
        raise q.Stop('fixed Go provenance changed')
    if any(proof.get(key) is not False for key in ('qualification_executed', 'release_admitted', 'target_conformance_executed', 'live_operations')):
        raise q.Stop('fixed Go authority misclassified')
    compiler = proof['compiler']
    if set(compiler) != {'version', 'os', 'arch', 'archive_sha256', 'archive_bytes', 'extracted_tree_sha256'} or compiler['version'] != VERSION or compiler['os'] != 'linux' or compiler['arch'] != 'amd64' or compiler['archive_sha256'] != ARCHIVE_SHA256 or compiler['archive_bytes'] != ARCHIVE_BYTES or not isinstance(compiler['extracted_tree_sha256'], str) or re.fullmatch('[0-9a-f]{64}', compiler['extracted_tree_sha256']) is None:
        raise q.Stop('fixed compiler pin changed')
    actual = [row for row in files if row['path'].startswith('artifacts/')]
    if original.read_json(public / 'payload-inventory.json') != {'files': actual}:
        raise q.Stop('fixed Go transfer bytes changed')
    functions = q.release_functions(pathlib.Path(__file__).resolve().parents[2])
    validate_subjects(public / 'artifacts', identities, functions)
