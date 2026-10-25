"""Closed candidate build receipts; never original reconstruction or admission."""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile

import _bounded_qualification as q
import _go_patch_refresh as compiler
import _payload_reconstruction as original
import _retained_runner as retained

BRANCH = 'refs/heads/codex/rr7-runner-version-refresh'
COMBINED_PATCH_SHA256 = '835c6c6f0a1c3dffbe176c1a8acc2fa2ed782c7bfad2f6d2dc7919919c7ef078'
OLD_SDK_SHA256 = compiler.SDK_SHA256
IMAGES = {'runner', 'network-adapter', 'network-broker-dialer', 'network-helper', 'network-verifier'}
REVIEWED = {'internal/productionruntime/release_artifacts.go': '48b3bd66a9f344b48abe517f683ce6a4227ff69394d6c83e178bd28e5d989cdf', 'scripts/release/rehearse-runtime.sh': 'cc72c80e787e8fee6b40fba1974b14f5659525c20a375dd49f705d09e58782b1'}
PINNED = {'schema_version': 1, 'enabled': True, 'upstream_version': 'v2.338.0', 'upstream_source_commit': '197ca027b90de199464dee3bb9ff198a1db60967', 'upstream_linux_x64_sha256': 'af4b794c1bc41d73d40535e3fe092a39f9679cd8d965954c2aca25a05ca41d32', 'dotnet_sdk_version': '8.0.426', 'dotnet_runtime_version': '8.0.32', 'sdk_container_image': 'mcr.microsoft.com/dotnet/sdk@sha256:8467fac908c4b0ac0496335989ca196721537277e42474a40f61e34fdc8ad772', 'sdk_archive_sha512': '8141d01bdc53f604aed3bb661b604707a64209f8a947cd81bf95b4f518951593d77864069191f54ea5e84362a409da6b0f69074bf893b283d7e0cf93e2bf20a8', 'source_patch_sha256': COMBINED_PATCH_SHA256, 'asset_name': 'actions-runner-linux-x64-2.338.0-dotnet-8.0.32.tar.gz'}
FALSE_AUTHORITY = dict(qualification_executed=False, release_admitted=False, target_conformance_executed=False, live_operations=False)
PROOF_FIELDS = {'schema_version', 'status', 'candidate_refresh', 'source_commit', 'source_tree', 'compiler', 'sdk_descriptor', 'sdk_source', 'sdk_build_executed_this_run', 'sdk_retained', 'smoke_verifier', 'binary_count', 'runtime_image_count', 'independent_AB_identical', 'final_image_smoke', *FALSE_AUTHORITY}
PUBLIC_METADATA = {'RESULT.json', 'candidate-identities.json', 'payload-inventory.json'}


def read(path):
    return original.read_json(path)


def sdk_authority(source):
    descriptor = read(source / 'internal/buildinfo/runner_rebuild.json')
    if set(descriptor) != set(PINNED) | {'linux_x64_sha256', 'archive_bytes'} or any(type(descriptor[k]) is not type(v) or descriptor[k] != v for k, v in PINNED.items()):
        raise q.Stop('candidate SDK inputs differ')
    digest, size = descriptor['linux_x64_sha256'], descriptor['archive_bytes']
    if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None or digest == OLD_SDK_SHA256 or type(size) is not int or not 0 < size <= 256 * 2**20:
        raise q.Stop('new genuine SDK identity required')
    if q.sha(source / 'release/runner-rebuild.patch') != COMBINED_PATCH_SHA256 or any(q.sha(source / p) != digest for p, digest in REVIEWED.items()):
        raise q.Stop('reviewed candidate source changed')
    return descriptor


def admission(source, event, environment, command):
    repo, values = event.get('repository', {}), event.get('inputs', {})
    required = {'candidate_refresh', 'bounded_qualification', 'metadata_probe', 'payload_reconstruction', 'expected_commit', 'expected_tree', 'carry_in_bytes'}
    expected = dict(GITHUB_EVENT_NAME='workflow_dispatch', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux', RUNNER_ARCH='X64', GITHUB_REPOSITORY='sumitake/GitHub-ActionRunner', GITHUB_ACTOR='sumitake', GITHUB_REF=BRANCH, GITHUB_RUN_ATTEMPT='1', GITHUB_WORKSPACE=str(source))
    if any(environment.get(k) != v for k, v in expected.items()) or repo.get('private') is not False or repo.get('full_name') != expected['GITHUB_REPOSITORY'] or repo.get('owner', {}).get('login') != expected['GITHUB_ACTOR']:
        raise q.Stop('manual public owner candidate dispatch required')
    if type(values) is not dict or set(values) != required or values['candidate_refresh'] != 'true' or any(values[k] != 'false' for k in ('bounded_qualification', 'metadata_probe', 'payload_reconstruction')):
        raise q.Stop('closed candidate inputs required')
    commit, tree, carry = (values[k] for k in ('expected_commit', 'expected_tree', 'carry_in_bytes'))
    if any(not isinstance(v, str) or re.fullmatch('[0-9a-f]{40}', v) is None for v in (commit, tree)) or commit == original.COMMIT or environment.get('GITHUB_SHA') != commit:
        raise q.Stop('new exact candidate source required')
    run_id = environment.get('GITHUB_RUN_ID', '')
    if not isinstance(carry, str) or re.fullmatch('[1-9][0-9]{0,10}', carry) is None or not q.RESERVE <= int(carry) < q.SOFT - 64 * 2**20 or re.fullmatch('[1-9][0-9]{0,19}', run_id) is None:
        raise q.Stop('candidate resource admission failed')
    def git(*args):
        return command(['git', '-c', 'safe.directory=' + str(source), *args], cwd=source)
    if source.resolve(strict=True) != source or git('rev-parse', 'HEAD') != commit or git('rev-parse', 'HEAD^{tree}') != tree or git('status', '--porcelain', '--untracked-files=all'):
        raise q.Stop('dirty or different candidate source')
    for row in git('ls-tree', '-r', 'HEAD').splitlines():
        meta, name = row.split('\t', 1); mode, kind, _ = meta.split(); path = source / name; info = path.lstat()
        if kind != 'blob' or mode not in ('100644', '100755') or path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != int(mode, 8) & 0o777:
            raise q.Stop('candidate source mode changed')
    descriptor = sdk_authority(source)
    return dict(schema_version=1, candidate_refresh=True, commit=commit, tree=tree, epoch=int(git('show', '-s', '--format=%ct', 'HEAD')), carry_in_bytes=int(carry), run_id=run_id, repository=repo['full_name'], sdk_sha256=descriptor['linux_x64_sha256'], **FALSE_AUTHORITY)


def retain_sdk_and_build_probe(worker):
    descriptor = sdk_authority(worker.source)
    selected = read(worker.output / 'selected-payload.json')
    archive = worker.root / 'selected-runner' / descriptor['asset_name']
    if selected != {'descriptor': descriptor, 'archive_sha256': descriptor['linux_x64_sha256'], 'archive_bytes': descriptor['archive_bytes'], 'all_entrypoints_verified': True, 'sdk_source': 'verified-retained-ab', 'sdk_build_executed_this_run': False} or q.sha(archive) != descriptor['linux_x64_sha256'] or archive.stat().st_size != descriptor['archive_bytes']:
        raise q.Stop('candidate retained SDK identity differs')
    shutil.copyfile(archive, worker.output / 'serviced-runner.tar.gz')
    # Private validation executable, never one of the eleven product subjects.
    executable = worker.root / 'final-image-smoke.test'
    worker.run('candidate-smoke-probe-build', ['go', 'test', '-c', '-trimpath', '-o', str(executable), './internal/productionruntime'])
    _, log = worker.run('candidate-smoke-probe-toolchain', ['go', 'version', '-m', str(executable)])
    if log.read_text().splitlines()[0] != str(executable) + ': go1.26.10':
        raise q.Stop('final smoke verifier compiler differs')
    q.write(worker.output / 'candidate-smoke-probe.json', {'sha256': q.sha(executable), 'compiler': 'go1.26.10', 'source_commit': worker.inputs['commit'], 'test_source_sha256': q.sha(worker.source / 'internal/productionruntime/release_artifacts_image_test.go')})


def compare(worker):
    rows = read(worker.output / 'binary-comparison.json')
    names = {r['name'] for r in original.expected()['binaries']}
    if len(rows.get('binaries', [])) != 22 or rows.get('all_eleven_identical') is not True or len(worker.images) != 10:
        raise q.Stop('candidate A/B membership incomplete')
    binaries = []
    for name in sorted(names):
        pair = [r for r in rows['binaries'] if r['name'] == name]
        if len(pair) != 2 or {r['phase'] for r in pair} != {'A', 'B'} or any(pair[0][k] != pair[1][k] for k in ('sha256', 'bytes')):
            raise q.Stop('candidate binary A/B mismatch')
        binaries.append({k: pair[0][k] for k in ('name', 'sha256', 'bytes')})
    images = []
    for name in sorted(IMAGES):
        pair = [r for r in worker.images if r['image'] == name]
        if len(pair) != 2 or {r['phase'] for r in pair} != {'A', 'B'} or any(pair[0][k] != pair[1][k] for k in ('oci_graph', 'source_to_image', 'files')):
            raise q.Stop('candidate image A/B mismatch')
        images.append({k: pair[0][k] for k in ('image', 'oci_graph', 'source_to_image')})
    commands = read(worker.output / 'commands-build.json')
    required = ['fixed-go-version', 'fixed-go-tls-tests', 'fixed-go-govulncheck', 'module-verify', 'linked-identity-test', 'candidate-smoke-probe-build', 'candidate-smoke-probe-toolchain'] + ['binary-toolchain-' + phase + '-' + name for phase in ('A', 'B') for name in sorted(names)]
    if any(len([r for r in commands if r['name'] == name and r['exit_code'] == 0]) != 1 for name in required):
        raise q.Stop('candidate focused build checks incomplete')
    identities = {'binaries': binaries, 'images': images}
    validate_subjects(worker.artifacts, identities, worker.release, worker.inputs['commit'])
    q.write(worker.output / 'candidate-build-identities.json', identities)
    q.write(worker.output / 'candidate-result.json', {'status': 'pass', **FALSE_AUTHORITY})


def validate_subjects(artifacts, identities, functions, commit):
    names = {r['name'] for r in original.expected()['binaries']}
    if set(identities) != {'binaries', 'images'} or len(identities['binaries']) != 11 or len(identities['images']) != 5 or {r['name'] for r in identities['binaries']} != names or {r['image'] for r in identities['images']} != IMAGES or {p.name for p in artifacts.iterdir()} != {'binaries-A', 'images-A'}:
        raise q.Stop('candidate subject membership differs')
    if {p.name for p in (artifacts / 'binaries-A').iterdir()} != names or {p.name for p in (artifacts / 'images-A').iterdir()} != IMAGES:
        raise q.Stop('candidate subject directories differ')
    hashes = {}
    for row in identities['binaries']:
        path = artifacts / 'binaries-A' / row['name']
        if set(row) != {'name', 'sha256', 'bytes'} or q.sha(path) != row['sha256'] or path.stat().st_size != row['bytes']:
            raise q.Stop('candidate binary bytes differ')
        hashes[row['name']] = row['sha256']
    baseline = original.expected()['runtime_images']
    for row in identities['images']:
        directory = artifacts / 'images-A' / row['image']; graph = q.graph(directory, functions)
        old = next(r for r in baseline.values() if r['image'] == row['image'])
        stamp = 'portable-ghar-build-identity-v1|candidate-' + commit[:12] + '-go1.26.10|' + commit
        binding = {'uid': '65532:65532', 'stamp': stamp, 'embedded_binaries': {p: hashes[pathlib.PurePosixPath(p).name] for p in old['source_to_image']['embedded_binaries']}}
        if set(row) != {'image', 'oci_graph', 'source_to_image'} or graph != row['oci_graph'] or row['source_to_image'] != binding or q.image_binary_binding(directory, graph, row['image'], stamp, binding['embedded_binaries']) != binding:
            raise q.Stop('candidate image binding differs')
        # Runner SDK/locks legitimately change; base and every unaffected helper
        # layer retain the original immutable identity. All deltas are retained.
        immutable = (0,) if row['image'] == 'runner' else compiler.NON_GO_LAYERS[row['image']]
        if len(graph['layer_digests']) != len(old['oci_graph']['layer_digests']) or any(graph['layer_digests'][i] != old['oci_graph']['layer_digests'][i] for i in immutable):
            raise q.Stop('candidate immutable layer differs')


def validate_smoke(row, graph, version):
    expected = dict(schema_version=1, image_id=row.get('image_id'), index_digest=graph['index_digest'], manifest_digest=graph['manifest_digest'], config_digest=graph['config_digest'], runner_version=version, production_smoke=True, rehearsal_smoke=True, stdout_sha256=hashlib.sha256((version + '\n').encode()).hexdigest(), stderr_sha256=hashlib.sha256(b'').hexdigest(), exit_code=0, containers_removed=True, image_removed=True)
    if row.get('image_id') not in image_refs(graph) or row != expected or any(type(row[k]) is not type(v) for k, v in expected.items()):
        raise q.Stop('final candidate image smoke incomplete')


def image_refs(graph):
    refs = list(dict.fromkeys(graph[k] for k in ('index_digest', 'manifest_digest', 'config_digest')))
    if any(not isinstance(ref, str) or re.fullmatch('sha256:[0-9a-f]{64}', ref) is None for ref in refs):
        raise q.Stop('invalid final image graph identity')
    return refs


def missing_image(result, reference):
    return result.returncode != 0 and result.stderr.strip() in tuple((prefix + 'No such image: ' + reference).encode() for prefix in ('Error response from daemon: ', 'Error: '))


def inspect_image(docker, reference, environment):
    result = subprocess.run([docker, 'image', 'inspect', '--format', '{{json .}}', reference], env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    if missing_image(result, reference):
        return None
    if result.returncode != 0 or result.stderr or len(result.stdout) > 2**20:
        raise q.Stop('image inspection failed')
    return json.loads(result.stdout)


def verify_observation(observed, graph, config):
    if observed.get('Id') not in image_refs(graph) or observed.get('Os') != 'linux' or observed.get('Architecture') != 'amd64' or observed.get('RootFS', {}).get('Layers') != config['rootfs']['diff_ids'] or any(observed.get('Config', {}).get(k) != v for k, v in config['config'].items()):
        raise q.Stop('loaded final image differs from OCI export')
    return observed['Id']


def export(root):
    inputs = read(root / 'inputs.json'); source = root / 'source'; evidence = root / 'evidence'
    descriptor = sdk_authority(source); identities = read(evidence / 'candidate-build-identities.json')
    runner = next(r for r in identities['images'] if r['image'] == 'runner')
    smoke = read(evidence / 'candidate-image-smoke.json'); validate_smoke(smoke, runner['oci_graph'], descriptor['upstream_version'][1:])
    provenance = read(evidence / 'go-compiler.json')
    if provenance.get('version') != compiler.VERSION or provenance.get('archive_sha256') != compiler.ARCHIVE_SHA256:
        raise q.Stop('candidate fixed compiler differs')
    prior = read(evidence / 'sdk-retained.json')
    retained.validate_receipt(source, prior)
    verifier = read(evidence / 'candidate-smoke-probe.json')
    validate_verifier(verifier, inputs['commit'], source)
    proof = dict(schema_version=1, status='pass', candidate_refresh=True, source_commit=inputs['commit'], source_tree=inputs['tree'], compiler=provenance, sdk_descriptor=descriptor, sdk_source='verified-retained-ab', sdk_build_executed_this_run=False, sdk_retained=prior, smoke_verifier=verifier, binary_count=11, runtime_image_count=5, independent_AB_identical=True, final_image_smoke=smoke, **FALSE_AUTHORITY)
    public = root / 'public'; public.mkdir(mode=0o700)
    (evidence / 'artifacts').rename(public / 'artifacts'); (evidence / 'serviced-runner.tar.gz').rename(public / descriptor['asset_name'])
    q.write(public / 'candidate-identities.json', {'proof': proof, **identities})
    q.write(public / 'payload-inventory.json', {'files': [r for r in q.inventory(public) if r['path'].startswith('artifacts/') or r['path'] == descriptor['asset_name']]})
    q.write(evidence / 'candidate-result.json', proof)


def finalize(root, final):
    original.finalize(root, final)


def check_upload(public):
    files = q.inventory(public); identities = read(public / 'candidate-identities.json'); proof = identities.get('proof', {})
    if set(identities) != {'proof', 'binaries', 'images'} or set(proof) != PROOF_FIELDS or any(proof.get(k) is not v for k, v in FALSE_AUTHORITY.items()) or type(proof.get('schema_version')) is not int or proof.get('schema_version') != 1 or type(proof.get('binary_count')) is not int or type(proof.get('runtime_image_count')) is not int or proof.get('status') != 'pass' or proof.get('candidate_refresh') is not True or (proof.get('sdk_source') != 'verified-retained-ab' or proof.get('sdk_build_executed_this_run') is not False) or proof.get('independent_AB_identical') is not True or (proof.get('binary_count'), proof.get('runtime_image_count')) != (11, 5):
        raise q.Stop('candidate proof authority differs')
    final = read(public / 'RESULT.json')
    if set(final) != PROOF_FIELDS | {'resource_qualification', 'workers_joined', 'scope_exit_code'} or any(final[k] != v for k, v in proof.items()) or final['resource_qualification'] != 'pass' or final['workers_joined'] is not True or type(final['scope_exit_code']) is not int or final['scope_exit_code'] != 0:
        raise q.Stop('candidate resource receipt incomplete')
    for key in ('source_commit', 'source_tree'):
        if not isinstance(proof[key], str) or re.fullmatch('[0-9a-f]{40}', proof[key]) is None:
            raise q.Stop('candidate source identity invalid')
    source = pathlib.Path(__file__).resolve().parents[2]
    actual = subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), 'rev-parse', 'HEAD', 'HEAD^{tree}'], cwd=source, text=True, timeout=20).splitlines()
    if actual != [proof['source_commit'], proof['source_tree']]:
        raise q.Stop('candidate upload source binding differs')
    expected_compiler = {'version', 'os', 'arch', 'archive_sha256', 'archive_bytes', 'extracted_tree_sha256'}
    value = proof['compiler']
    if set(value) != expected_compiler or value['version'] != compiler.VERSION or value['os'] != 'linux' or value['arch'] != 'amd64' or value['archive_sha256'] != compiler.ARCHIVE_SHA256 or value['archive_bytes'] != compiler.ARCHIVE_BYTES or not isinstance(value['extracted_tree_sha256'], str) or re.fullmatch('[0-9a-f]{64}', value['extracted_tree_sha256']) is None:
        raise q.Stop('candidate compiler receipt differs')
    validate_verifier(proof['smoke_verifier'], proof['source_commit'], source)
    retained.validate_receipt(source, proof['sdk_retained'])
    descriptor = proof['sdk_descriptor']; name = descriptor['asset_name']
    if proof['sdk_retained']['archive_sha256'] != descriptor['linux_x64_sha256'] or proof['sdk_retained']['archive_bytes'] != descriptor['archive_bytes']:
        raise q.Stop('retained receipt and transferred SDK differ')
    if descriptor != sdk_authority(pathlib.Path(__file__).resolve().parents[2]) or descriptor['linux_x64_sha256'] != q.sha(public / name) or descriptor['archive_bytes'] != (public / name).stat().st_size:
        raise q.Stop('candidate SDK transfer differs')
    if sum(r['bytes'] for r in files) > q.ARTIFACT_LIMIT or {r['path'] for r in files if not r['path'].startswith('artifacts/')} != PUBLIC_METADATA | {name} or read(public / 'payload-inventory.json') != {'files': [r for r in files if r['path'].startswith('artifacts/') or r['path'] == name]}:
        raise q.Stop('candidate transfer exceeds closed envelope')
    functions = q.release_functions(pathlib.Path(__file__).resolve().parents[2])
    validate_subjects(public / 'artifacts', {k: identities[k] for k in ('binaries', 'images')}, functions, proof['source_commit'])
    runner = next(r for r in identities['images'] if r['image'] == 'runner')
    validate_smoke(proof['final_image_smoke'], runner['oci_graph'], descriptor['upstream_version'][1:])


def smoke_image(root, environment, parent, label, command):
    """Load the exact verified OCI export; exercise production and rehearsal."""
    evidence = root / 'evidence'; inputs = read(root / 'inputs.json')
    identities = read(evidence / 'candidate-build-identities.json')
    row = next(r for r in identities['images'] if r['image'] == 'runner')
    directory = evidence / 'artifacts/images-A/runner'; source = root / 'source'
    functions = q.release_functions(source)
    if q.graph(directory, functions) != row['oci_graph']:
        raise q.Stop('final runner OCI changed')
    graph = row['oci_graph']; refs = image_refs(graph); image = None
    version = sdk_authority(source)['upstream_version'][1:]
    config_document = read(directory / ('blobs/sha256/' + graph['config_digest'][7:]))
    docker = shutil.which('docker', path=environment['PATH'])
    if docker is None:
        raise q.Stop('Docker CLI unavailable')
    names = ['pghar-candidate-' + inputs['run_id'] + '-' + suffix for suffix in ('production', 'rehearsal')]
    for name in names:
        if command([docker, 'ps', '-aq', '--filter', 'name=^/' + name + '$']):
            raise q.Stop('existing smoke container name')
    if any(inspect_image(docker, ref, environment) is not None for ref in refs):
        raise q.Stop('final image not proven absent before load')
    archive = root / 'final-smoke-oci.tar'
    with tarfile.open(archive, 'w:') as stream:
        for item in q.inventory(directory):
            path = directory / item['path']; info = tarfile.TarInfo(item['path']); info.size = item['bytes']; info.mode = 0o444
            with path.open('rb') as data:
                stream.addfile(info, data)
    # Creation follows worker join, so no build worker can edit this control.
    q.write(evidence / 'candidate-smoke-control.json', {'image_refs': refs, 'previously_absent': True})
    bin_dir = root / 'final-smoke-bin'; bin_dir.mkdir(mode=0o700)
    home = root / 'final-smoke-home'; home.mkdir(mode=0o700)
    config = home / 'docker'; config.mkdir(mode=0o700)
    succeeded = False
    try:
        command([docker, 'image', 'load', '--input', str(archive)])
        observed = [value for ref in refs if (value := inspect_image(docker, ref, environment)) is not None]
        ids = {verify_observation(value, graph, config_document) for value in observed}
        if len(ids) != 1:
            raise q.Stop('ambiguous or absent loaded final image')
        image = ids.pop()
        base = ['--network', 'none', '--read-only', '--user', '65532:65532', '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700', '--entrypoint', '/opt/actions-runner/bin/Runner.Listener', image, '--version']
        allowed = [['run', '--rm', *base], ['run', '--name', names[1], *base]]
        wrapper = bin_dir / 'docker'
        wrapper.write_text('#!/usr/bin/python3\nimport os,sys\na=sys.argv[1:]\nallowed=' + repr(allowed) + '\nif a not in allowed:raise SystemExit(64)\nextra=' + repr(['--pull=never', '--label', label, '--cgroup-parent', parent]) + '\nif a==allowed[0]:extra += ' + repr(['--name', names[0]]) + '\nos.execve(' + repr(docker) + ',[' + repr(docker) + ',"run",*extra,*a[1:]],' + repr({'HOME': str(home), 'DOCKER_CONFIG': str(config), 'PATH': '/usr/bin:/bin'}) + ')\n')
        wrapper.chmod(0o500)
        env = {**environment, 'PGHAR_REAL_FINAL_IMAGE': '1', 'PGHAR_FINAL_IMAGE_DOCKER': str(wrapper), 'PGHAR_FINAL_IMAGE_ID': image}
        result = subprocess.run([str(root / 'final-image-smoke.test'), '-test.run=^TestReleaseArtifactVerifierRealFinalImage$', '-test.v'], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=135)
        (evidence / 'production-final-smoke.log').write_bytes(result.stdout + result.stderr)
        marker = b'FINAL_IMAGE_SMOKE_RECEIPT='
        receipts = [json.loads(line.split(marker, 1)[1]) for line in result.stdout.splitlines() if marker in line]
        if result.returncode != 0 or result.stderr or len(result.stdout) > 65536 or receipts != [{'image_id': image, 'runner_version': version}]:
            raise q.Stop('production final-image smoke failed')
        functions['verify_final_runner_smoke'](image, version, names[1], cwd=source, env={**environment, 'PATH': str(bin_dir) + ':' + environment['PATH']}, log=evidence / 'rehearsal-final-smoke.log')
        succeeded = True
    finally:
        for name in names:
            # Verify absence afterward; a failed cleanup can never become PASS.
            subprocess.run([docker, 'rm', '--force', name], env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        containers_removed = all(command([docker, 'ps', '-aq', '--filter', 'name=^/' + name + '$']) == '' for name in names)
        image_removed = cleanup_image(root, environment)
        archive.unlink(missing_ok=True)
        q.write(evidence / 'candidate-image-smoke.json', dict(schema_version=1, image_id=image, index_digest=graph['index_digest'], manifest_digest=graph['manifest_digest'], config_digest=graph['config_digest'], runner_version=version, production_smoke=succeeded, rehearsal_smoke=succeeded, stdout_sha256=hashlib.sha256((version + '\n').encode()).hexdigest(), stderr_sha256=hashlib.sha256(b'').hexdigest(), exit_code=0 if succeeded else 1, containers_removed=containers_removed, image_removed=image_removed))
    validate_smoke(read(evidence / 'candidate-image-smoke.json'), graph, version)


def cleanup_image(root, environment=None):
    """Idempotent outer cleanup after cancellation; never remove existing input."""
    path = root / 'evidence/candidate-smoke-control.json'
    if not path.exists():
        return True
    control = read(path)
    identities = read(root / 'evidence/candidate-build-identities.json')
    runner = next(r for r in identities['images'] if r['image'] == 'runner')
    refs = image_refs(runner['oci_graph'])
    if set(control) != {'image_refs', 'previously_absent'} or control['previously_absent'] is not True or control['image_refs'] != refs:
        raise q.Stop('unsafe smoke cleanup control')
    env = environment or {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'home'), 'DOCKER_CONFIG': str(root / 'home/docker-smoke')}
    docker = shutil.which('docker', path=env['PATH'])
    if docker is None:
        return False
    for reference in refs:
        subprocess.run([docker, 'image', 'rm', '--force', reference], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    return all(inspect_image(docker, reference, env) is None for reference in refs)


def normal_startup(rebuild, work, command, environment, evidence_root):
    """Real unconfigured help path, only in a private SDK layout before sealing."""
    script = r'''set -eu
root=/work/runner-source/_layout
for name in .runner .credentials .credentials_rsaparams; do
  test ! -e "$root/$name" && test ! -L "$root/$name"
done
COREHOST_TRACE=1 COREHOST_TRACEFILE=/work/normal-help.trace timeout -k 5s 20s "$root/bin/Runner.Listener" --help >/work/normal-help.stdout 2>/work/normal-help.stderr
for name in .runner .credentials .credentials_rsaparams; do
  test ! -e "$root/$name" && test ! -L "$root/$name"
done
test -d "$root/_diag"
'''
    rebuild.run_sdk(command[:2] + ['--network', 'none'] + command[2:] + ['/bin/sh', '-c', script], work, environment)
    output, error, trace = (work / ('normal-help.' + name) for name in ('stdout', 'stderr', 'trace'))
    for path in (output, error, trace):
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > 8 * 2**20:
            raise q.Stop('normal startup evidence invalid')
    if error.read_bytes() or b'Commands:' not in output.read_bytes() or b'--version' not in output.read_bytes() or b"CoreCLR path = '/work/runner-source/_layout/bin/libcoreclr.so'" not in trace.read_bytes() or b'Execute managed assembly exit code: 0x0' not in trace.read_bytes():
        raise q.Stop('real normal startup help failed')
    retained = evidence_root / 'sdk-normal-startup'
    retained.mkdir(mode=0o700)
    for path in (output, error, trace):
        shutil.copyfile(path, retained / path.name)
    q.write(evidence_root / 'sdk-normal-startup.json', {'status': 'pass', 'mode': 'unconfigured-help', 'network': 'none', 'credentials_or_config_created': False, 'stdout_sha256': q.sha(output), 'stderr_sha256': q.sha(error), 'trace_sha256': q.sha(trace)})


def validate_normal(row):
    fields = {'status', 'mode', 'network', 'credentials_or_config_created', 'stdout_sha256', 'stderr_sha256', 'trace_sha256'}
    if set(row) != fields or row['status'] != 'pass' or row['mode'] != 'unconfigured-help' or row['network'] != 'none' or row['credentials_or_config_created'] is not False or row['stderr_sha256'] != hashlib.sha256(b'').hexdigest() or any(not isinstance(row[k], str) or re.fullmatch('[0-9a-f]{64}', row[k]) is None for k in ('stdout_sha256', 'stderr_sha256', 'trace_sha256')):
        raise q.Stop('normal startup receipt differs')


def validate_verifier(row, commit, source):
    if set(row) != {'sha256', 'compiler', 'source_commit', 'test_source_sha256'} or row['compiler'] != 'go1.26.10' or row['source_commit'] != commit or not isinstance(row['sha256'], str) or re.fullmatch('[0-9a-f]{64}', row['sha256']) is None or row['test_source_sha256'] != q.sha(source / 'internal/productionruntime/release_artifacts_image_test.go'):
        raise q.Stop('final smoke verifier provenance differs')
