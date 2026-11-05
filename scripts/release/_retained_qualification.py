"""Offline retained-SDK evidence contracts, never dispatch or publication authority.

The controller must separately observe workers and authenticate execution/artifact
provenance. A consistent on-disk packet alone cannot establish those facts.
"""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import json
import os
import pathlib
import re
import stat
import struct
import subprocess
import tarfile
import zipfile
import zlib

import _bounded_qualification as q
import _candidate_refresh as candidate
import _trivy_report

SOURCE_COMMIT = 'df760529f7635b7fc2d4982f72a50b53d0363de3'
SOURCE_TREE = 'ea097a04a995899a0b586b70c14a310c54a55a0f'
SPEC_SHA256 = 'c88d9e0195b9d22d2af08d61a1540ba252723416fd19705e34b84bbb1624d609'
VERSION = 'candidate-' + SOURCE_COMMIT[:12] + '-go1.26.10'
STAMP = 'portable-ghar-build-identity-v1|' + VERSION + '|' + SOURCE_COMMIT
BINARIES = frozenset('portable-ghar' + suffix for suffix in (
    '', '-controller', '-fleet-fence', '-network-adapter', '-network-broker-dialer',
    '-network-broker-parser', '-network-helper', '-network-verifier', '-runner-gate',
    '-runtime-lock', '-watchdog'))
IMAGES = frozenset(('network-adapter', 'network-broker-dialer',
                    'network-broker-parser', 'network-helper', 'network-verifier', 'runner'))
CANDIDATE_IMAGES = IMAGES - {'network-broker-parser'}
SUBJECTS = 'qualification-subjects.json'
RESULT = 'qualification-result.json'
WORKER_INVENTORY = 'worker-evidence-inventory.json'
FINAL_INVENTORY = 'qualification-bundle-inventory.json'
SIDECARS = frozenset((SUBJECTS, RESULT, WORKER_INVENTORY, FINAL_INVENTORY))
FALSE_AUTHORITY = dict(release_admitted=False, deployment_admitted=False, live_operations=False)
IDENTITY_FIELDS = frozenset(('source_commit', 'source_tree', 'tooling_commit', 'tooling_tree',
                             'candidate_execution', 'qualification_execution'))
BUILD_REPORTS = frozenset({'buildkit-workers-apt-plan.json'} | {
    'buildkit-workers-' + phase + '-' + name + '.json'
    for phase in ('A', 'B') for name in IMAGES})
SCAN_REPORTS = frozenset({'security-source.json', 'security-binaries-A.json',
                        'security-binaries-B.json', 'runner-all-severities.json'} | {
    'security-image-' + name + '.json' for name in IMAGES} | {
    'sbom/' + name + '.raw.spdx.json' for name in BINARIES | IMAGES})
INPUT_PATHS = ('release/manifest.json', 'internal/buildinfo/runner_rebuild.json',
               'release/retained-runner-input.json', 'release/retained-runner-provenance.json',
               'release/retained-sdk-verification.json', 'release/runner-rebuild.patch',
               'release/runner-licenses.json', 'release/public-dependency-metadata.json')


def require(condition, reason):
    if not condition:
        raise q.Stop('retained qualification: ' + reason)


def read(path):
    return json.loads(_trivy_report.stable_bytes(path, 16 * 2**20),
                      object_pairs_hook=_trivy_report.unique,
                      parse_constant=_trivy_report.nonfinite)


def digest(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def positive(value):
    return type(value) is int and value > 0


def relative(value):
    require(isinstance(value, str) and value and '\\' not in value and
            not any(ord(c) < 32 or ord(c) == 127 for c in value), 'invalid member name')
    path = pathlib.PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and
            all(part not in ('', '.', '..') for part in value.split('/')), 'unsafe member name')
    return value


def file_record(root, name):
    path = root / relative(name)
    info = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode) and
            info.st_nlink == 1, 'indirect or aliased member')
    # Qualification/public transfers are data, including the ELF files. Release
    # executable modes are applied only by the independent deterministic assembler.
    require(stat.S_IMODE(info.st_mode) == 0o644, 'transfer file mode differs')
    before = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    checksum = q.sha(path)
    after = path.lstat()
    require(before == (after.st_dev, after.st_ino, after.st_size,
                       after.st_mtime_ns, after.st_ctime_ns), 'member changed during hashing')
    return dict(path=name, bytes=info.st_size, sha256=checksum, mode='0644')


def inventory(root, *, exclude=()):
    root = pathlib.Path(root)
    require(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir(),
            'canonical directory required')
    rows, directories = [], set()
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        info = path.lstat()
        require(path.resolve(strict=True) == path, 'indirect member')
        if stat.S_ISDIR(info.st_mode):
            require(stat.S_IMODE(info.st_mode) == 0o755, 'transfer directory mode differs')
            directories.add(name)
        else:
            row = file_record(root, name)
            if name not in exclude:
                rows.append(row)
    # Empty/extra directories are not an unbound extension to a closed transfer.
    parents = {p.as_posix() for path in root.rglob('*') if path.is_file()
               for p in pathlib.PurePosixPath(path.relative_to(root).as_posix()).parents
               if p.as_posix() != '.'}
    require(directories == parents, 'unexpected empty transfer directory')
    require(sum(row['bytes'] for row in rows) <= q.ARTIFACT_LIMIT, 'transfer exceeds content ceiling')
    return rows


def exact_rows(rows, *, publication=False):
    require(type(rows) is list, 'file inventory must be a list')
    indexed = {}
    for row in rows:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'mode'},
                'file inventory fields differ')
        name = relative(row['path'])
        require(name not in indexed and type(row['bytes']) is int and row['bytes'] >= 0 and
                digest(row['sha256']) and row['mode'] == (('0555' if name.startswith('bin/') else '0444') if publication else '0644'), 'invalid inventory record')
        indexed[name] = row
    require(list(indexed) == sorted(indexed), 'inventory order differs')
    return indexed


def artifact(value):
    require(type(value) is dict and set(value) == {'id', 'name', 'bytes', 'sha256'} and
            positive(value['id']) and positive(value['bytes']) and value['bytes'] <= q.ARTIFACT_LIMIT and
            digest(value['sha256']) and isinstance(value['name'], str) and
            re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', value['name']),
            'invalid complete artifact identity')


def execution(value, *, completed):
    fields = {'repository', 'workflow_path', 'workflow_commit', 'workflow_blob',
              'run_id', 'run_attempt', 'job_id', 'actor', 'artifact_name'}
    if completed:
        fields |= {'conclusion', 'artifact'}
    require(type(value) is dict and set(value) == fields, 'execution fields differ')
    require(value['repository'] == 'sumitake/GitHub-ActionRunner' and value['actor'] == 'sumitake' and
            type(value['run_attempt']) is int and value['run_attempt'] == 1 and
            positive(value['run_id']) and positive(value['job_id']) and
            digest(value['workflow_commit'], 40) and digest(value['workflow_blob'], 40),
            'execution identity differs')
    require(isinstance(value['workflow_path'], str) and
            re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.yml', value['workflow_path']),
            'workflow path differs')
    require(isinstance(value['artifact_name'], str) and
            re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', value['artifact_name']), 'artifact name differs')
    if completed:
        artifact(value['artifact'])
        require(value['conclusion'] == 'success' and value['artifact']['name'] == value['artifact_name'],
                'candidate execution did not complete successfully')


def identities(value):
    require(type(value) is dict and set(value) == IDENTITY_FIELDS, 'identity tuple fields differ')
    require(value['source_commit'] == SOURCE_COMMIT and value['source_tree'] == SOURCE_TREE,
            'product source differs')
    require(digest(value['tooling_commit'], 40) and digest(value['tooling_tree'], 40) and
            value['tooling_commit'] != SOURCE_COMMIT and value['tooling_tree'] != SOURCE_TREE,
            'separate reviewed tooling identity required')
    execution(value['candidate_execution'], completed=True)
    execution(value['qualification_execution'], completed=False)
    require(value['candidate_execution']['workflow_commit'] == SOURCE_COMMIT and
            value['qualification_execution']['workflow_commit'] == value['tooling_commit'] and
            value['candidate_execution']['run_id'] != value['qualification_execution']['run_id'],
            'execution/source/tooling binding differs')
    return value


def verify_checkout(source, commit, tree):
    source = pathlib.Path(source)
    require(source.is_absolute() and source.resolve(strict=True) == source, 'checkout is indirect')
    def git(*args):
        return subprocess.check_output(['git', '--no-replace-objects', '-c', 'safe.directory=' + str(source), *args],
                                       cwd=source, text=True, timeout=20).strip()
    require(git('rev-parse', 'HEAD', 'HEAD^{tree}').splitlines() == [commit, tree] and
            not git('status', '--porcelain', '--untracked-files=all'), 'dirty or different checkout')
    for row in git('ls-tree', '-rz', tree).split('\0'):
        if not row:
            continue
        metadata, name = row.split('\t', 1)
        mode, kind, expected_blob = metadata.split()
        path = source / relative(name)
        info = path.lstat()
        require(kind == 'blob' and mode in ('100644', '100755') and
                path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode) and
                info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == int(mode[-3:], 8),
                'checkout member mode differs')
        # status can deliberately skip tracked files under assume-unchanged or
        # skip-worktree. Hash their exact worktree bytes against the admitted
        # tree's blob IDs, bypassing index hints, filters and replacement refs.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            signature = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                       value.st_mtime_ns, value.st_ctime_ns, value.st_nlink, value.st_mode)
            require(signature(before) == signature(info), 'checkout member changed before hashing')
            checksum = hashlib.sha1(('blob ' + str(before.st_size)).encode() + b'\0')
            while chunk := stream.read(1024 * 1024):
                checksum.update(chunk)
            require(signature(before) == signature(os.fstat(stream.fileno())) and
                    signature(before) == signature(path.lstat()) and path.resolve(strict=True) == path and
                    checksum.hexdigest() == expected_blob, 'checkout bytes differ from admitted tree blob')
    require(git('rev-parse', 'HEAD', 'HEAD^{tree}').splitlines() == [commit, tree],
            'checkout identity changed during hashing')



def source_inputs(source):
    names = set(INPUT_PATHS)
    registry = read(source / 'release/runner-licenses.json')
    for license_row in registry['licenses']:
        for item in license_row['files']:
            if item['path'].startswith('release/'):
                relative(item['path'])
                require(q.sha(source / item['path']) == item['sha256'], 'committed legal input hash differs')
                names.add(item['path'])
    return [file_record(source, name) for name in sorted(names)]

def verify_candidate(source, directory):
    """Rehash the whole downloaded B tree without relabeling its false authority."""
    verify_checkout(source, SOURCE_COMMIT, SOURCE_TREE)
    rows = inventory(directory)
    candidate.check_upload(directory, source=source)
    proof = read(directory / 'candidate-identities.json')['proof']
    require(proof['source_commit'] == SOURCE_COMMIT and proof['source_tree'] == SOURCE_TREE,
            'candidate source tuple differs')
    return rows



def verify_exporter_reference(index, name):
    """Check the pinned BuildKit directory-export annotation semantics as emitted."""
    require(name in IMAGES and type(index) is dict and type(index.get('manifests')) is list and
            len(index['manifests']) == 1 and type(index['manifests'][0]) is dict,
            'original exporter descriptor differs')
    annotations = index['manifests'][0].get('annotations')
    # BuildKit v0.32.0 normalizes exporter names before ociindex.Name writes
    # the full name and OCI tag into their distinct descriptor annotations.
    require(type(annotations) is dict and
            annotations.get('org.opencontainers.image.ref.name') == VERSION and
            annotations.get('io.containerd.image.name') == 'docker.io/portable-ghar/' + name + ':' + VERSION,
            'original exporter reference differs')


def subjects(source, directory, candidate_directory, identity):
    """Derive subjects from original bytes. Caller first verifies the complete B transfer."""
    identities(identity)
    functions = q.release_functions(source)
    baseline = read(candidate_directory / 'candidate-identities.json')
    require(set(baseline) == {'proof', 'binaries', 'images'}, 'candidate identities differ')
    binaries = {row['name']: row for row in baseline['binaries']}
    images = {row['image']: row for row in baseline['images']}
    require(len(baseline['binaries']) == 11 and set(binaries) == BINARIES and
            len(baseline['images']) == 5 and set(images) == CANDIDATE_IMAGES,
            'candidate overlap membership differs')
    files = inventory(directory)
    for phase in ('A', 'B'):
        require({r['path'].removeprefix('artifacts/binaries-' + phase + '/') for r in files
                 if r['path'].startswith('artifacts/binaries-' + phase + '/')} == BINARIES,
                'binary payload membership differs')
        image_root = directory / ('artifacts/images-' + phase)
        require(image_root.is_dir() and {p.name for p in image_root.iterdir()} == IMAGES,
                'image payload membership differs')
    require({p.name for p in (directory / 'artifacts').iterdir()} ==
            {'binaries-A', 'binaries-B', 'images-A', 'images-B'}, 'raw A/B generations incomplete')
    result, hashes = [], {}
    for name in sorted(BINARIES):
        pair = {phase: file_record(directory, 'artifacts/binaries-' + phase + '/' + name)
                for phase in ('A', 'B')}
        expected = binaries[name]
        require(set(expected) == {'name', 'bytes', 'sha256'} and
                all(pair[phase][key] == expected[key] for phase in pair for key in ('bytes', 'sha256')),
                'Q A/B binary differs from candidate A')
        raw = (directory / pair['A']['path']).read_bytes()
        require(raw[:6] == b'\x7fELF\x02\x01' and len(raw) >= 20 and
                int.from_bytes(raw[18:20], 'little') == 62 and STAMP.encode() in raw,
                'binary architecture or build stamp differs')
        hashes[name] = expected['sha256']
        result.append(dict(kind='binary', name=name, generations=pair, candidate_overlap=True,
                           candidate_sha256=expected['sha256'], release_path='bin/' + name))
    old = read(source / 'release/reconstruction-identities.json')['runtime_images']
    for name in sorted(IMAGES):
        pair = {}
        paths = ({'usr/local/bin/portable-ghar-network-broker-parser'} if name == 'network-broker-parser'
                 else set(next(row for row in old.values() if row['image'] == name)['source_to_image']['embedded_binaries']))
        embedded = {path: hashes[pathlib.PurePosixPath(path).name] for path in paths}
        for phase in ('A', 'B'):
            prefix = 'artifacts/images-' + phase + '/' + name
            layout = directory / prefix
            graph = q.graph(layout, functions)
            binding = q.image_binary_binding(layout, graph, name, STAMP, embedded)
            members = inventory(layout)
            index = read(layout / 'index.json')
            verify_exporter_reference(index, name)
            pair[phase] = dict(path=prefix, files=members, oci_graph=graph, source_to_image=binding)
        require(all(pair['A'][key] == pair['B'][key] for key in ('files', 'oci_graph', 'source_to_image')),
                'Q image A/B differs')
        overlap = name in CANDIDATE_IMAGES
        if overlap:
            expected = images[name]
            require(set(expected) == {'image', 'oci_graph', 'source_to_image'} and
                    all(pair['A'][key] == expected[key] for key in ('oci_graph', 'source_to_image')) and
                    pair['A']['files'] == inventory(candidate_directory / ('artifacts/images-A/' + name)),
                    'Q image differs from candidate original inventory/graph')
        result.append(dict(kind='image', name=name, generations=pair, candidate_overlap=overlap,
                           sixth_image_status=None if overlap else 'fresh-independent-A/B',
                           release_path='images/' + name + '.oci.tar'))
    for row in result:
        name = row['name']
        row['raw_sbom'] = file_record(directory, 'sbom/' + name + '.raw.spdx.json')
        row['normalized_sbom'] = file_record(directory, 'sbom/' + name + '.spdx.json')
        security = ('security-binaries-B.json' if row['kind'] == 'binary'
                    else 'security-image-' + name + '.json')
        row['security_report'] = file_record(directory, security)
    inputs = source_inputs(source)
    return dict(schema_version=1, specification_sha256=SPEC_SHA256, identities=identity,
                source_inputs=inputs, version=VERSION, subjects=result)


def verify_membership(rows):
    indexed = exact_rows(rows)
    names = set(indexed)
    observed_build = {p for p in names if p.startswith('buildkit-workers-')}
    observed_scan = {p for p in names if p.startswith('security-') and p.endswith('.json') and
                     p != 'security-results.json'} | {p for p in names if p.endswith('.raw.spdx.json')} | (
                         names & {'runner-all-severities.json'})
    require(observed_build == BUILD_REPORTS and observed_scan == SCAN_REPORTS,
            'exact 13 build / 27 scan reports required')
    normalized = {'sbom/' + name + '.spdx.json' for name in BINARIES | IMAGES}
    require({p for p in names if p.endswith('.spdx.json') and not p.endswith('.raw.spdx.json')} == normalized,
            'exact 17 normalized SBOMs required')
    required = {'THIRD-PARTY-NOTICES.txt', 'binary-comparison.json', 'image-results.json',
                'source-inputs.json', 'source-acquisition.json', 'sdk-retained.json',
                'selected-payload.json', 'go-compiler.json', 'tool-syft.json', 'tool-trivy.json',
                'scanner-database-before.json', 'scanner-database-after.json',
                'trivy-report-rendering.json', 'runner-reported-CVE-clearance.json',
                'security-results.json', 'build-result.json', 'scan-result.json',
                'producer-publication-stages.json', 'export-policy.json', 'terminal.json',
                'RESULT.json', 'resource-samples.jsonl', 'candidate-image-smoke.json',
                'worker-terminal.json', 'scan-terminal.json'}
    require(required <= names, 'required worker/control evidence missing')
    return indexed


def verify_chain(directory, expected_identity):
    """Verify the one-way byte chain, not external execution or permission claims."""
    identities(expected_identity)
    subject_raw = _trivy_report.stable_bytes(directory / SUBJECTS, 16 * 2**20)
    subject_document, result = read(directory / SUBJECTS), read(directory / RESULT)
    worker, final = read(directory / WORKER_INVENTORY), read(directory / FINAL_INVENTORY)
    require(set(subject_document) == {'schema_version', 'specification_sha256', 'identities', 'source_inputs', 'version', 'subjects'} and
            type(subject_document['schema_version']) is int and subject_document['schema_version'] == 1 and
            subject_document['specification_sha256'] == SPEC_SHA256 and subject_document['version'] == VERSION and
            subject_document['identities'] == expected_identity, 'subject identity/specification differs')
    require(set(worker) == {'schema_version', 'identities', 'files'} and
            type(worker['schema_version']) is int and worker['schema_version'] == 1 and
            worker['identities'] == expected_identity, 'worker inventory identity differs')
    require(set(final) == {'schema_version', 'identities', 'files'} and
            type(final['schema_version']) is int and final['schema_version'] == 1 and
            final['identities'] == expected_identity, 'final inventory identity differs')
    fields = {'schema_version', 'identities', 'qualification_subjects_sha256',
              'worker_evidence_inventory_sha256', 'qualification_executed',
              'artifact_qualification_admitted', 'workers_joined', 'scope_exit_code',
              'resource_qualification', 'public_evidence_sanitization', 'unsafe_text_withheld',
              'binary_count', 'image_count', 'sbom_count', 'producer_report_count', *FALSE_AUTHORITY}
    require(set(result) == fields and type(result['schema_version']) is int and result['schema_version'] == 1 and
            result['identities'] == expected_identity and
            result['qualification_subjects_sha256'] == hashlib.sha256(subject_raw).hexdigest() and
            result['worker_evidence_inventory_sha256'] == q.sha(directory / WORKER_INVENTORY),
            'result hard hash/identity binding differs')
    require(all(result[key] is False for key in FALSE_AUTHORITY) and
            all(result[key] is True for key in ('qualification_executed', 'artifact_qualification_admitted', 'workers_joined')) and
            type(result['scope_exit_code']) is int and result['scope_exit_code'] == 0 and
            result['resource_qualification'] == result['public_evidence_sanitization'] == 'pass' and
            result['unsafe_text_withheld'] == [], 'result incomplete or grants excess authority')
    require(all(type(result[key]) is int and result[key] == count for key, count in
                [('binary_count', 11), ('image_count', 6), ('sbom_count', 17), ('producer_report_count', 40)]),
            'result membership differs')
    actual = inventory(directory, exclude={FINAL_INVENTORY})
    exact_rows(final['files'])
    require(final['files'] == actual, 'final inventory does not bind complete original bytes')
    expected_worker = [row for row in actual if row['path'] not in SIDECARS]
    require(worker['files'] == expected_worker, 'worker inventory excludes/includes wrong evidence')
    verify_membership(worker['files'])
    rows = subject_document['subjects']
    require(type(rows) is list and len(rows) == 17 and
            {(row.get('kind'), row.get('name')) for row in rows} ==
            {('binary', name) for name in BINARIES} | {('image', name) for name in IMAGES},
            'subject manifest membership differs')
    return subject_document


def verify_bundle(source, tooling, directory, candidate_directory, expected_identity, *, candidate_archive):
    """Read-only consumer. No supplied JSON confers observed-producer recognition."""
    identities(expected_identity)
    verify_checkout(source, SOURCE_COMMIT, SOURCE_TREE)
    verify_checkout(tooling, expected_identity['tooling_commit'], expected_identity['tooling_tree'])
    candidate_files = verify_candidate(source, candidate_directory)
    transport = expected_identity['candidate_execution']['artifact']
    require(candidate_archive.stat().st_size == transport['bytes'] and q.sha(candidate_archive) == transport['sha256'],
            'complete candidate download hash differs')
    verify_archive(candidate_archive, candidate_files)
    document = verify_chain(directory, expected_identity)
    require(document == subjects(source, directory, candidate_directory, expected_identity),
            'subject sidecar does not describe original payload bytes')
    return dict(content_consistent=True, external_execution_verified=False,
                publication_authorized=False, qualification_inventory=inventory(directory),
                identities=expected_identity, **FALSE_AUTHORITY)


def verify_handoff(directory, qualification_archive, publication_archive, handoff, expected_identity, *, prepared):
    """Bind external artifacts to actual in-process assembly, never owner approval."""
    import _qualification_packaging as packaging
    packaging.revalidate_prepared_assets(prepared)
    require(prepared.qualification_root == directory and
            prepared.source_identity['commit'] == expected_identity['source_commit'] and
            prepared.source_identity['tree'] == expected_identity['source_tree'] and
            prepared.tooling_identity == {'commit': expected_identity['tooling_commit'],
                                          'tree': expected_identity['tooling_tree']},
            'prepared assets belong to a different qualification/source/tooling tuple')
    verify_chain(directory, expected_identity)
    require(set(handoff) == {'schema_version', 'identities', 'qualification_subjects_sha256',
                            'qualification_result_sha256', 'qualification_inventory_sha256',
                            'qualification_artifact', 'publication_artifact', 'packaging_tooling',
                            'assets', 'attestation_subjects', 'comparator', 'packaging_receipt_sha256', *FALSE_AUTHORITY},
            'handoff fields differ')
    require(type(handoff['schema_version']) is int and handoff['schema_version'] == 1 and
            handoff['identities'] == expected_identity and
            all(handoff[key] is False for key in FALSE_AUTHORITY), 'handoff authority differs')
    for key, filename in [('qualification_subjects_sha256', SUBJECTS),
                          ('qualification_result_sha256', RESULT),
                          ('qualification_inventory_sha256', FINAL_INVENTORY)]:
        require(handoff[key] == q.sha(directory / filename), 'handoff hard binding differs')
    for key, path in [('qualification_artifact', qualification_archive),
                      ('publication_artifact', publication_archive)]:
        artifact(handoff[key])
        value = handoff[key]
        require(path.is_absolute() and path.resolve(strict=True) == path and
                stat.S_ISREG(path.lstat().st_mode) and path.lstat().st_nlink == 1 and
                path.stat().st_size == value['bytes'] and q.sha(path) == value['sha256'],
                'complete artifact download hash differs')
    require(handoff['qualification_artifact']['name'] == expected_identity['qualification_execution']['artifact_name'],
            'Q artifact name binding differs')
    require(handoff['packaging_tooling'] == {'commit': expected_identity['tooling_commit'],
                                           'tree': expected_identity['tooling_tree'],
                                           'files': prepared['tooling_files'],
                                           'method': prepared['packaging_method']}, 'packaging tooling differs')
    canonical = (json.dumps(dict(prepared), sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
    require(handoff['packaging_receipt_sha256'] == hashlib.sha256(canonical).hexdigest() and
            prepared['qualification_bundle_inventory_sha256'] == handoff['qualification_inventory_sha256'],
            'prepared receipt or original qualification inventory differs')
    assets = handoff['assets']
    expected_paths = {'bin/' + name for name in BINARIES} | {'images/' + name + '.oci.tar' for name in IMAGES} | {
        'sbom/' + name + '.spdx.json' for name in BINARIES | IMAGES} | {
        'notices/THIRD-PARTY-NOTICES.txt', 'runner-release.json', 'runner-payload.json',
        'runner-rebuild.json', 'runtime-release.json', 'checksums.txt', 'provenance-subjects.json'}
    indexed = exact_rows(assets, publication=True)
    require(assets == prepared['assets'] and set(indexed) == expected_paths and handoff['attestation_subjects'] == assets and
            handoff['comparator'] == {'status': 'pass', 'independent_payload_generations': ['A', 'B'],
                                      'independent_metadata_generations': False}, 'publication membership/comparator differs')
    verify_archive(qualification_archive, inventory(directory))
    verify_archive(publication_archive, assets, publication=True)
    packaging.revalidate_prepared_assets(prepared)
    return dict(content_consistent=True, external_execution_verified=False,
                publication_authorized=False, **FALSE_AUTHORITY)



def _tar_framing(path, *, publication=False):
    """Closed uncompressed USTAR framing; no invisible extension/tail records."""
    size = path.stat().st_size
    with path.open('rb') as stream:
        offset = 0
        while True:
            header = stream.read(512)
            require(len(header) == 512, 'short TAR header')
            if header == bytes(512):
                expected_size = ((offset + 1024 + 10239) // 10240) * 10240
                require(size == expected_size and not any(stream.read()), 'TAR hidden or noncanonical trailer')
                break
            require(header[156:157] in (b'0', b'\0', b'5') and
                    header[257:263] == b'ustar\0' and header[263:265] == b'00',
                    'TAR extension or non-USTAR header')
            if publication:
                member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
                canonical = tarfile.TarInfo(member.name)
                canonical.size, canonical.mode = member.size, member.mode
                require(member.isfile() and header == canonical.tobuf(format=tarfile.USTAR_FORMAT),
                        'publication TAR header differs from deterministic seal')
            raw_size = header[124:136].rstrip(b'\0 ')
            require(bool(raw_size) and all(c in b'01234567 ' for c in raw_size), 'TAR non-octal size')
            payload_size = int(raw_size, 8)
            require(payload_size <= q.ARTIFACT_LIMIT, 'TAR member size exceeds bound')
            padded = (payload_size + 511) // 512 * 512
            require(offset + 512 + padded < size, 'TAR member extends beyond archive')
            stream.seek(payload_size, 1)
            require(not any(stream.read(padded - payload_size)), 'TAR nonzero file padding')
            offset += 512 + padded



def _zip_metadata_preflight(path, expected, allowed_directories):
    """Bound and stream-validate native central records before ZipFile allocation."""
    names = set(expected) | {name + '/' for name in allowed_directories}
    maximum_central = sum(46 + len(name.encode('utf-8')) for name in names)
    maximum_name = max((len(name.encode('utf-8')) for name in names), default=0)
    size = path.stat().st_size
    with path.open('rb') as stream:
        require(size >= 22, 'short ZIP trailer')
        stream.seek(-22, 2)
        ending = struct.unpack('<4s4H2IH', stream.read(22))
        signature, disk, start_disk, disk_count, declared_count, central_size, start, comment = ending
        require(signature == b'PK\x05\x06' and disk == start_disk == comment == 0 and
                disk_count == declared_count <= len(names) and central_size <= maximum_central and
                start + central_size == size - 22, 'ZIP central directory exceeds closed metadata bounds')
        stream.seek(start)
        seen, files, expanded_total, count = set(), set(), 0, 0
        while stream.tell() < start + central_size:
            count += 1
            require(count <= declared_count and start + central_size - stream.tell() >= 46,
                    'ZIP actual central count exceeds bound')
            header = stream.read(46)
            require(len(header) == 46 and header[:4] == b'PK\x01\x02', 'ZIP central framing differs')
            made, _needed, flags, compression = struct.unpack_from('<4H', header, 4)
            expanded = struct.unpack_from('<I', header, 24)[0]
            name_length, extra_length, comment_length, disk_start = struct.unpack_from('<4H', header, 28)
            attributes = struct.unpack_from('<I', header, 38)[0]
            require(made >> 8 == 3 and not flags & ~0x080e and
                    compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                    extra_length == comment_length == disk_start == 0 and
                    0 < name_length <= maximum_name and
                    name_length <= start + central_size - stream.tell(),
                    'ZIP central member metadata is unsupported or oversized')
            name = stream.read(name_length).decode('utf-8' if flags & 0x800 else 'cp437')
            require(name in names and name not in seen, 'ZIP central membership differs')
            seen.add(name)
            mode = attributes >> 16
            if name.endswith('/'):
                require(stat.S_ISDIR(mode) and stat.S_IMODE(mode) == 0o755 and expanded == 0,
                        'ZIP central directory mode/size differs')
            else:
                require(stat.S_ISREG(mode) and expanded == expected[name]['bytes'] and
                        stat.S_IMODE(mode) == int(expected[name]['mode'], 8),
                        'ZIP central file mode/size differs')
                expanded_total += expanded
                require(expanded_total <= q.ARTIFACT_LIMIT, 'ZIP expanded bytes exceed content ceiling')
                files.add(name)
        require(count == declared_count and stream.tell() == start + central_size and files == set(expected),
                'ZIP complete central framing/count/membership differs')

def _zip_framing(path, archive):
    """Require contiguous native entries and an exact terminal central directory.

    Closed transport accepts ordinary 32-bit ZIPs with stored/deflated members,
    optional streaming data descriptors, no comments, and no extra fields. An
    unsupported metadata extension stops consumption rather than being ignored.
    """
    size = path.stat().st_size
    with path.open('rb') as stream:
        require(size >= 22, 'short ZIP trailer')
        stream.seek(size - 22)
        trailer = struct.unpack('<4s4H2IH', stream.read(22))
        signature, disk, start_disk, disk_count, count, central_size, central_start, comment = trailer
        require(signature == b'PK\x05\x06' and disk == start_disk == comment == 0 and
                disk_count == count == len(archive.infolist()) and
                central_start == archive.start_dir and central_start + central_size == size - 22,
                'ZIP hidden prefix/trailer or unsupported end record')
        position = 0
        for member in sorted(archive.infolist(), key=lambda value: value.header_offset):
            require(member.header_offset == position and not member.extra and not member.comment,
                    'ZIP hidden local data or extension metadata')
            stream.seek(position)
            header = stream.read(30)
            require(len(header) == 30, 'short ZIP local header')
            sig, _version, flags, compression, _time, _date, crc, compressed, expanded, name_length, extra_length = struct.unpack('<4s5H3I2H', header)
            require(sig == b'PK\x03\x04' and not flags & ~0x080e and
                    flags == member.flag_bits and compression == member.compress_type and
                    compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and extra_length == 0,
                    'ZIP local metadata differs or is unsupported')
            raw_name = stream.read(name_length)
            require(raw_name.decode('utf-8' if flags & 0x800 else 'cp437') == member.filename,
                    'ZIP local/central filename differs')
            if compression == zipfile.ZIP_STORED:
                require(member.compress_size == member.file_size, 'stored ZIP size differs')
            else:
                # ZipFile intentionally ignores deflate unused_data. Verify the
                # complete native compressed stream as well as extracted bytes.
                decoder = zlib.decompressobj(-zlib.MAX_WBITS)
                remaining, expanded_bytes = member.compress_size, 0
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    require(bool(chunk), 'short ZIP compressed data')
                    remaining -= len(chunk)
                    while chunk:
                        output = decoder.decompress(chunk, min(1024 * 1024, member.file_size - expanded_bytes + 1))
                        expanded_bytes += len(output)
                        require(expanded_bytes <= member.file_size and not decoder.unused_data,
                                'ZIP hidden deflate suffix or expansion overflow')
                        chunk = decoder.unconsumed_tail
                require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and
                        expanded_bytes == member.file_size, 'ZIP incomplete or hidden deflate stream')
            position += 30 + name_length + member.compress_size
            require(position <= central_start, 'ZIP local data overlaps central directory')
            stream.seek(position)
            if flags & 8:
                require((crc, compressed, expanded) in ((0, 0, 0), (member.CRC, member.compress_size, member.file_size)),
                        'ZIP streaming header differs')
                marker = stream.read(4)
                if marker == b'PK\x07\x08':
                    descriptor = stream.read(12)
                    position += 16
                else:
                    descriptor = marker + stream.read(8)
                    position += 12
                require(len(descriptor) == 12 and struct.unpack('<3I', descriptor) ==
                        (member.CRC, member.compress_size, member.file_size), 'ZIP streaming descriptor differs')
            else:
                require((crc, compressed, expanded) == (member.CRC, member.compress_size, member.file_size),
                        'ZIP local/central sizes differ')
        require(position == central_start, 'ZIP gap before central directory')
        stream.seek(central_start)
        for member in archive.infolist():
            header = stream.read(46)
            require(len(header) == 46 and header[:4] == b'PK\x01\x02', 'ZIP central framing differs')
            name_length, extra_length, comment_length = struct.unpack_from('<3H', header, 28)
            require(extra_length == comment_length == 0, 'ZIP central extension metadata')
            raw_name = stream.read(name_length)
            require(raw_name.decode('utf-8' if member.flag_bits & 0x800 else 'cp437') == member.filename,
                    'ZIP central filename differs')
        require(stream.tell() == central_start + central_size, 'ZIP hidden central records')

def verify_archive(path, rows, *, publication=False):
    """Stream the complete downloaded ZIP/TAR without extracting or following links."""
    expected = exact_rows(rows, publication=publication)
    require(path.is_absolute() and path.resolve(strict=True) == path and
            stat.S_ISREG(path.lstat().st_mode) and path.lstat().st_nlink == 1 and
            0 < path.stat().st_size <= q.ARTIFACT_LIMIT, 'unsafe complete archive')
    seen, directories, order, total = set(), set(), [], 0
    allowed_directories = {p.as_posix() for name in expected
                           for p in pathlib.PurePosixPath(name).parents if p.as_posix() != '.'}
    def consume(name, size, mode, stream):
        nonlocal total
        relative(name)
        require(name in expected and name not in seen, 'unexpected or duplicate archive member')
        row = expected[name]
        require(size == row['bytes'] and mode == int(row['mode'], 8), 'archive member size/mode differs')
        total += size
        require(total <= q.ARTIFACT_LIMIT, 'archive expanded bytes exceed content ceiling')
        hasher = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            require(bool(chunk), 'archive member short read')
            remaining -= len(chunk)
            hasher.update(chunk)
        require(not stream.read(1) and hasher.hexdigest() == row['sha256'], 'archive member bytes differ')
        seen.add(name)
        order.append(name)
    def directory(name, mode):
        relative(name)
        require(name in allowed_directories and name not in directories and mode == 0o755,
                'unexpected/duplicate archive directory')
        directories.add(name)
    if zipfile.is_zipfile(path):
        require(not publication, 'publication bundle must use the deterministic USTAR seal')
        _zip_metadata_preflight(path, expected, allowed_directories)
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            preflight_files, preflight_dirs, expanded_total = set(), set(), 0
            require(len(entries) <= len(expected) + len(allowed_directories), 'archive member count exceeds bound')
            for member in entries:
                require(not member.flag_bits & 1 and member.create_system == 3,
                        'encrypted or mode-less ZIP member')
                mode = member.external_attr >> 16
                if member.is_dir():
                    name = relative(member.filename[:-1])
                    require(stat.S_ISDIR(mode) and stat.S_IMODE(mode) == 0o755 and member.file_size == 0 and
                            name in allowed_directories and name not in preflight_dirs,
                            'ZIP directory metadata differs')
                    preflight_dirs.add(name)
                else:
                    name = relative(member.filename)
                    require(stat.S_ISREG(mode) and name in expected and name not in preflight_files,
                            'unexpected or duplicate ZIP member')
                    require(member.file_size == expected[name]['bytes'] and
                            stat.S_IMODE(mode) == int(expected[name]['mode'], 8),
                            'ZIP declared member size/mode differs')
                    expanded_total += member.file_size
                    require(expanded_total <= q.ARTIFACT_LIMIT, 'ZIP expanded bytes exceed content ceiling')
                    preflight_files.add(name)
            require(preflight_files == set(expected), 'complete ZIP membership differs')
            _zip_framing(path, archive)
            for member in entries:
                mode = member.external_attr >> 16
                if member.is_dir():
                    directory(member.filename[:-1], stat.S_IMODE(mode))
                else:
                    with archive.open(member) as stream:
                        consume(member.filename, member.file_size, stat.S_IMODE(mode), stream)
    else:
        _tar_framing(path, publication=publication)
        with tarfile.open(path, 'r:') as archive:
            count = 0
            for member in archive:
                count += 1
                require(count <= len(expected) + len(allowed_directories), 'archive member count exceeds bound')
                require(not member.pax_headers, 'archive extended metadata is not part of the contract')
                if member.isdir():
                    require(member.size == 0, 'TAR directory type differs')
                    directory(member.name.rstrip('/'), member.mode)
                else:
                    require(member.isfile(), 'TAR member is not regular')
                    with archive.extractfile(member) as stream:
                        consume(member.name, member.size, member.mode, stream)
    require(seen == set(expected), 'complete archive membership differs')
    if publication:
        require(not directories and order == list(expected), 'publication TAR order differs from deterministic seal')
