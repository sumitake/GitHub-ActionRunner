"""Offline preparation of closed candidate assets, never release authority.

Consumes two retained raw generations and separately admitted source/tooling
checkouts. It does not build, scan, dispatch, publish, or establish qualification.
"""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import copy
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile

import _bounded_qualification as q

SOURCE_COMMIT = 'df760529f7635b7fc2d4982f72a50b53d0363de3'
SOURCE_TREE = 'ea097a04a995899a0b586b70c14a310c54a55a0f'
VERSION = 'candidate-df760529f763-go1.26.10'
BINARIES = ('portable-ghar', 'portable-ghar-controller', 'portable-ghar-fleet-fence',
            'portable-ghar-network-adapter', 'portable-ghar-network-broker-dialer',
            'portable-ghar-network-broker-parser', 'portable-ghar-network-helper',
            'portable-ghar-network-verifier', 'portable-ghar-runner-gate',
            'portable-ghar-runtime-lock', 'portable-ghar-watchdog')
IMAGES = ('network-adapter', 'network-broker-dialer', 'network-broker-parser',
          'network-helper', 'network-verifier', 'runner')
UNCHANGED_HELPERS = ('scripts/release/rehearse-runtime.sh',
                     'scripts/release/compare-runtime-rebuilds.sh',
                     'scripts/sanitize_public.py', 'scripts/_sanitize_normalize.py',
                     'scripts/public_dependency_metadata.py')


_PREPARED_SEAL = object()


def _receipt_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


class PreparedAssets(dict):
    """In-process assembler result; serialized receipts carry no admission token."""
    def __init__(self, receipt, *, qualification_root, output, source_identity,
                 tooling_identity, qualification_inventory, _seal=None):
        if _seal is not _PREPARED_SEAL:
            raise q.Stop('prepared assets require successful in-process assembly')
        super().__init__(copy.deepcopy(receipt))
        self.qualification_root = pathlib.Path(qualification_root)
        self.output = pathlib.Path(output)
        self.source_identity = copy.deepcopy(source_identity)
        self.tooling_identity = copy.deepcopy(tooling_identity)
        self._qualification_inventory = copy.deepcopy(qualification_inventory)
        self._receipt = _receipt_bytes(receipt)
        self._paths = (self.qualification_root, self.output)
        self._seal = _seal


def revalidate_prepared_assets(value):
    """Reject supplied JSON, changed receipts, or changed prepared input/output."""
    if not isinstance(value, PreparedAssets) or getattr(value, '_seal', None) is not _PREPARED_SEAL:
        raise q.Stop('unrecognized prepared assets')
    if (_receipt_bytes(value) != value._receipt
            or (value.qualification_root, value.output) != value._paths
            or value.source_identity != value['source'] or value.tooling_identity != value['tooling']):
        raise q.Stop('prepared assets receipt changed')
    _directory(value.qualification_root)
    _directory(value.output)
    if inventory(value.qualification_root) != value._qualification_inventory:
        raise q.Stop('prepared qualification input changed')
    if {p.name for p in value.output.iterdir()} != {'A', 'B'}:
        raise q.Stop('prepared output membership changed')
    for phase in ('A', 'B'):
        stage = value.output / phase
        _directory(stage)
        expected_dirs = {str(parent) for row in value['assets']
                         for parent in pathlib.PurePosixPath(row['path']).parents if str(parent) != '.'}
        actual_dirs = {path.relative_to(stage).as_posix() for path in stage.rglob('*') if path.is_dir()}
        if actual_dirs != expected_dirs or any(stat.S_IMODE((stage / name).lstat().st_mode) != 0o755
                                               for name in (*actual_dirs, '.')):
            raise q.Stop('prepared assets directory inventory or modes changed')
        if inventory(stage) != value['assets']:
            raise q.Stop('prepared assets bytes or modes changed')
    return value


def _regular(path):
    path = pathlib.Path(path)
    st = path.lstat()
    if path.resolve(strict=True) != path or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise q.Stop('unsafe packaging input')
    return st


def _directory(path):
    path = pathlib.Path(path)
    if path.resolve(strict=True) != path or not stat.S_ISDIR(path.lstat().st_mode):
        raise q.Stop('unsafe packaging directory')


def inventory(root):
    """Exact file inventory including modes, matching the bundle verifier shape."""
    return [{**row, 'mode': format(stat.S_IMODE((root / row['path']).lstat().st_mode), '04o')}
            for row in q.inventory(root)]


def _dependency_evidence(source, supplied, debian_cache, go_module_cache):
    # Never fall back to HTTPS or an ambient module cache during packaging.
    if not isinstance(supplied, tuple) or len(supplied) != 2:
        raise q.Stop('packaging requires authenticated dependency metadata')
    _directory(debian_cache)
    _directory(go_module_cache)
    producer = q.module(source, 'public_dependency_metadata.py')
    evidence = producer.load(source, debian_cache=debian_cache, go_module_cache=go_module_cache)
    if evidence != supplied[1]:
        raise q.Stop('packaging dependency metadata binding mismatch')
    return producer, evidence


def _checkout(root, identity):
    _directory(root)
    if any(not isinstance(identity.get(k), str) or re.fullmatch('[0-9a-f]{40}', identity[k]) is None
           for k in ('commit', 'tree')):
        raise q.Stop('packaging checkout identity')
    from _retained_qualification import verify_checkout
    verify_checkout(root, identity['commit'], identity['tree'])
    if 'epoch' in identity:
        actual_epoch = subprocess.run(['git', '--no-replace-objects', '-C', str(root), 'show', '-s',
                                       '--format=%ct', identity['commit']], check=True,
                                      capture_output=True, text=True, timeout=30).stdout.strip()
        if actual_epoch != str(identity['epoch']):
            raise q.Stop('packaging source epoch mismatch')


def package_oci_layout(layout, destination, release):
    """Write deterministic uncompressed USTAR, retaining every original file byte."""
    layout, destination = pathlib.Path(layout), pathlib.Path(destination)
    _directory(layout)
    if destination.exists() or destination.is_symlink():
        raise q.Stop('packaging destination already exists')
    before = q.inventory(layout)
    graph = q.graph(layout, release)
    expected_dirs = {str(p) for row in before for p in pathlib.PurePosixPath(row['path']).parents if str(p) != '.'}
    actual_dirs = {p.relative_to(layout).as_posix() for p in layout.rglob('*') if p.is_dir()}
    if actual_dirs != expected_dirs:
        raise q.Stop('extra OCI directories')
    owned = False
    try:
        with destination.open('xb') as output:
            owned = True
            with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for row in before:
                    path = layout / row['path']
                    _regular(path)
                    info = tarfile.TarInfo(row['path'])
                    info.size = row['bytes']
                    info.mode = 0o444
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    with path.open('rb') as stream:
                        archive.addfile(info, stream)
        if q.inventory(layout) != before or release['oci_graph'](destination) != graph:
            raise q.Stop('OCI packaging input drift')
        with tarfile.open(destination, 'r:') as archive:
            members = archive.getmembers()
            observed = [{'path': m.name, 'bytes': m.size,
                         'sha256': hashlib.file_digest(archive.extractfile(m), 'sha256').hexdigest()}
                        for m in members]
        if observed != before:
            raise q.Stop('OCI archive member bytes mismatch')
        os.chmod(destination, 0o444)
        return {'sha256': q.sha(destination), 'bytes': destination.stat().st_size,
                'oci_graph': graph, 'files': before}
    except BaseException:
        if owned:
            destination.unlink(missing_ok=True)
        raise


def _copy(source, destination, mode):
    _regular(source)
    before = q.sha(source)
    with source.open('rb') as input_file, destination.open('xb') as output:
        shutil.copyfileobj(input_file, output)
    if q.sha(source) != before or q.sha(destination) != before:
        raise q.Stop('packaging copy drift')
    os.chmod(destination, mode)


def _exact_payloads(root):
    for phase in ('A', 'B'):
        binaries, images = root / 'artifacts' / ('binaries-' + phase), root / 'artifacts' / ('images-' + phase)
        _directory(binaries)
        _directory(images)
        if {p.name for p in binaries.iterdir()} != set(BINARIES) or {p.name for p in images.iterdir()} != set(IMAGES):
            raise q.Stop('packaging payload membership')
        for name in BINARIES:
            _regular(binaries / name)
        for name in IMAGES:
            _directory(images / name)
    for family in ('binaries', 'images'):
        a, b = (root / 'artifacts' / (family + '-' + phase) for phase in ('A', 'B'))
        if q.inventory(a) != q.inventory(b):
            raise q.Stop('packaging A/B payload mismatch')
        modes = lambda p: [(r.relative_to(p).as_posix(), stat.S_IMODE(r.lstat().st_mode)) for r in sorted(p.rglob('*'))]
        if modes(a) != modes(b):
            raise q.Stop('packaging A/B modes mismatch')


def _assemble(source, root, stage, phase, identity, release, runtime, public_evidence,
              dependency_debian_cache, dependency_go_module_cache):
    stage.mkdir(mode=0o755)
    for directory in ('bin', 'images', 'sbom', 'notices'):
        (stage / directory).mkdir(mode=0o755)
    subjects, mappings, rows, digests = [], [], [], {}
    for name in BINARIES:
        _copy(root / 'artifacts' / ('binaries-' + phase) / name, stage / 'bin' / name, 0o555)
        release['add_subject'](subjects, stage, 'bin/' + name, 'binary')
    for name in IMAGES:
        relative = 'images/' + name + '.oci.tar'
        archive = package_oci_layout(root / 'artifacts' / ('images-' + phase) / name, stage / relative, release)
        release['add_subject'](subjects, stage, relative, 'oci-image', archive['oci_graph'])
    runner = runtime['runner_release']
    payload = release['select_runner_payload'](source, runner)
    if payload['kind'] != 'dotnet-rebuild':
        raise q.Stop('packaging requires retained runner descriptor')
    for filename, value, kind in [('runner-release.json', runner, 'runner-manifest'),
                                   ('runner-payload.json', payload, 'runner-payload')]:
        (stage / filename).write_bytes(release['canonical_json'](value))
        os.chmod(stage / filename, 0o444)
        release['add_subject'](subjects, stage, filename, kind)
    _copy(source / 'internal/buildinfo/runner_rebuild.json', stage / 'runner-rebuild.json', 0o444)
    release['add_subject'](subjects, stage, 'runner-rebuild.json', 'runner-rebuild-provenance')
    first_party = release['first_party_metadata'](source, VERSION, identity['commit'])
    license_args = []
    for name in (*BINARIES, *IMAGES):
        relative = 'bin/' + name if name in BINARIES else 'images/' + name + '.oci.tar'
        raw, original = root / 'sbom' / (name + '.raw.spdx.json'), root / 'sbom' / (name + '.spdx.json')
        _regular(raw)
        _regular(original)
        normalized = stage / 'sbom' / (name + '.spdx.json')
        digest = q.sha(stage / relative)
        graph_digest = next(s['oci_graph']['manifest_digest'][7:] for s in subjects if s['path'] == relative) if name in IMAGES else digest
        release['normalize_spdx'](raw, normalized, name, digest, identity['epoch'], first_party=first_party, public_evidence=public_evidence)
        if name == 'runner':
            license_args = release['apply_baseline_runner_licenses'](source, runner, runner, normalized, graph_digest, payload=payload)
        os.chmod(normalized, 0o444)
        release['add_subject'](subjects, stage, 'sbom/' + normalized.name, 'sbom')
        rows.append((relative, normalized))
        digests[relative] = graph_digest
        mappings.append({'subject': name, 'raw_path': 'sbom/' + raw.name,
                         'qualification_normalized_path': 'sbom/' + original.name,
                         'release_normalized_path': 'sbom/' + normalized.name,
                         'raw_sha256': q.sha(raw), 'qualification_normalized_sha256': q.sha(original),
                         'release_normalized_sha256': q.sha(normalized), 'namespace_sha256': digest,
                         'notices_root_sha256': graph_digest})
    notices = stage / 'notices/THIRD-PARTY-NOTICES.txt'
    release['generate_notices'](rows, runtime['license_exceptions'], notices, digests)
    os.chmod(notices, 0o444)
    release['add_subject'](subjects, stage, 'notices/THIRD-PARTY-NOTICES.txt', 'notices')
    if len(subjects) != 38:
        raise q.Stop('packaging subject membership')
    release['write_authority_files'](stage, 'candidate', VERSION, identity['commit'], identity['tree'], identity['epoch'],
                                     q.sha(source / 'release/manifest.json'), runner, runtime['tools'], subjects)
    for name in ('runtime-release.json', 'checksums.txt', 'provenance-subjects.json'):
        os.chmod(stage / name, 0o444)
    # Preserve the existing generated-text sanitizer and its license authorities.
    text_paths = [p for p in stage.rglob('*') if p.is_file() and p.parts[-2] not in ('bin', 'images')]
    args = [sys.executable, str(source / 'scripts/sanitize_public.py'), '--verified-dependency-metadata',
            '--dependency-debian-cache', str(dependency_debian_cache),
            '--dependency-go-module-cache', str(dependency_go_module_cache), *license_args]
    for path in sorted(text_paths):
        args.extend(['--generated', str(path)])
    subprocess.run(args, cwd=source, check=True, capture_output=True, timeout=600)
    return mappings


def assemble_release_pair(source, tooling, qualification_root, output, *, source_identity,
                          tooling_identity, public_evidence, expected_inventory,
                          dependency_debian_cache, dependency_go_module_cache):
    """Prepare A/B trees from a separately verified complete qualification bundle.

    expected_inventory is the exact complete inventory returned by the caller's
    bundle verifier, not an execution claim. Receipt remains outside both trees.
    """
    source, tooling, qualification_root, output = map(pathlib.Path, (source, tooling, qualification_root, output))
    if source_identity.get('commit') != SOURCE_COMMIT or source_identity.get('tree') != SOURCE_TREE:
        raise q.Stop('packaging product source changed')
    if type(source_identity.get('epoch')) is not int or source_identity['epoch'] < 1:
        raise q.Stop('packaging source epoch')
    _checkout(source, source_identity)
    _checkout(tooling, tooling_identity)
    for relative in UNCHANGED_HELPERS:
        _regular(source / relative)
        _regular(tooling / relative)
        if q.sha(source / relative) != q.sha(tooling / relative):
            raise q.Stop('packaging verifier drift')
    _directory(qualification_root)
    if not expected_inventory or inventory(qualification_root) != expected_inventory:
        raise q.Stop('packaging complete input inventory mismatch')
    if output.exists() or output.is_symlink() or output.resolve() != output:
        raise q.Stop('packaging output must be new and direct')
    for root in (source, tooling, qualification_root):
        if output.is_relative_to(root):
            raise q.Stop('packaging output overlaps input')
    bundle_inventory_path = qualification_root / 'qualification-bundle-inventory.json'
    _regular(bundle_inventory_path)
    bundle_inventory_sha256 = q.sha(bundle_inventory_path)
    _exact_payloads(qualification_root)
    release = q.release_functions(source)
    runtime = release['read_json'](source / 'release/manifest.json')['runtime']
    if {r['name'] for r in runtime['binaries']} != set(BINARIES) or {r['name'] for r in runtime['images']} != set(IMAGES):
        raise q.Stop('packaging source subject registry')
    dependency_debian_cache, dependency_go_module_cache = map(pathlib.Path, (dependency_debian_cache, dependency_go_module_cache))
    public_evidence = _dependency_evidence(source, public_evidence, dependency_debian_cache, dependency_go_module_cache)
    output.mkdir(mode=0o755)
    try:
        mappings = [_assemble(source, qualification_root, output / phase, phase, source_identity,
                              release, runtime, public_evidence, dependency_debian_cache, dependency_go_module_cache) for phase in ('A', 'B')]
        if mappings[0] != mappings[1]:
            raise q.Stop('packaging normalized A/B mismatch')
        subprocess.run(['bash', str(source / 'scripts/release/compare-runtime-rebuilds.sh'),
                        str(output / 'A'), str(output / 'B')], cwd=source, check=True, capture_output=True, timeout=600)
        for phase in ('A', 'B'):
            stage = output / phase
            if (len(q.inventory(stage)) != 41 or len((stage / 'checksums.txt').read_text().splitlines()) != 39
                    or len(release['read_json'](stage / 'provenance-subjects.json')['subjects']) != 40):
                raise q.Stop('packaging final closed membership')
        if inventory(qualification_root) != expected_inventory:
            raise q.Stop('packaging qualification input drift')
        _dependency_evidence(source, public_evidence, dependency_debian_cache, dependency_go_module_cache)
        _checkout(source, source_identity)
        _checkout(tooling, tooling_identity)
        receipt = {'schema_version': 1, 'kind': 'prepared-candidate-assets',
                'source': dict(source_identity), 'tooling': dict(tooling_identity),
                'tooling_files': {p: q.sha(tooling / p) for p in (*UNCHANGED_HELPERS, 'scripts/release/_qualification_packaging.py',
                                                                              'scripts/release/_bounded_qualification.py',
                                                                              'scripts/release/_retained_qualification.py')},
                'qualification_inventory_rows_sha256': hashlib.sha256(release['canonical_json'](expected_inventory)).hexdigest(),
                'qualification_bundle_inventory_sha256': bundle_inventory_sha256,
                'packaging_method': {'oci': 'sorted-regular-members-ustar-uid0-gid0-mtime0-mode0444',
                                     'publication': 'sorted-regular-members-ustar-uid0-gid0-mtime0-bin0555-other0444'},
                'dependency_metadata_sha256': q.sha(source / 'release/public-dependency-metadata.json'),
                'normalization_mapping': mappings[0], 'assets': inventory(output / 'A'),
                'comparison': 'equal', 'qualification_executed': False, 'artifact_qualification_admitted': False,
                'publication_authorized': False, 'deployment_authorized': False}
        return PreparedAssets(receipt, qualification_root=qualification_root, output=output,
                              source_identity=source_identity, tooling_identity=tooling_identity,
                              qualification_inventory=expected_inventory, _seal=_PREPARED_SEAL)
    except BaseException:
        shutil.rmtree(output)
        raise


def seal_publication_bundle(prepared, destination):
    """Seal prepared assets into an offline archive; grants no publication authority."""
    prepared = revalidate_prepared_assets(prepared)
    destination = pathlib.Path(destination)
    if destination.exists() or destination.is_symlink() or destination.resolve() != destination:
        raise q.Stop('publication bundle destination must be new and direct')
    _directory(destination.parent)
    if destination.is_relative_to(prepared.output) or destination.is_relative_to(prepared.qualification_root):
        raise q.Stop('publication bundle overlaps prepared inputs')
    owned = False
    try:
        with destination.open('xb') as output:
            owned = True
            with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for row in prepared['assets']:
                    path = prepared.output / 'A' / row['path']
                    _regular(path)
                    member = tarfile.TarInfo(row['path'])
                    member.size = row['bytes']
                    member.mode = int(row['mode'], 8)
                    member.uid = member.gid = member.mtime = 0
                    member.uname = member.gname = ''
                    with path.open('rb') as stream:
                        archive.addfile(member, stream)
        with tarfile.open(destination, mode='r:') as archive:
            rows = [{'path': member.name, 'bytes': member.size,
                     'mode': format(member.mode, '04o'),
                     'sha256': hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest()}
                    for member in archive]
        if rows != prepared['assets']:
            raise q.Stop('publication archive member mismatch')
        revalidate_prepared_assets(prepared)
        os.chmod(destination, 0o444)
        return {'path': str(destination), 'bytes': destination.stat().st_size,
                'sha256': q.sha(destination), 'assets': copy.deepcopy(rows)}
    except BaseException:
        if owned:
            destination.unlink(missing_ok=True)
        raise
