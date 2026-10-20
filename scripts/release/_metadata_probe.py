"""Bounded prospective producer diagnostics; never qualification authority."""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import io
import json
import pathlib
import re
import stat
import subprocess
import tarfile

import _bounded_qualification as q

LIMIT = 2**20
NATIVE_LIMIT = 8 * LIMIT
PUBLIC_FIELDS = frozenset(('ReportID', 'documentNamespace', 'Metadata', 'RepoURL', 'Author', 'Committer', 'Commit', 'CommitMsg', 'stdout', 'creationInfo', 'creators', 'hasExtractedLicensingInfos', 'seeAlsos', 'packages', 'files', 'relationships'))
# Exact pinned BuildKit default GC source enum; only its presence is public.
GC_ENUM_SHA256 = '56bcacfa79639bf7dd99324b1857327f5910663709618010021a9855370ea728'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise q.Stop('duplicate diagnostic JSON key')
        result[key] = value
    return result


def reject_constant(_value):
    raise q.Stop('nonfinite diagnostic JSON')


def read_json(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.resolve(strict=True) != path or not 0 < info.st_size <= NATIVE_LIMIT:
        raise q.Stop('unsafe native diagnostic report')
    raw = path.read_bytes()
    return raw, json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def scalars(value, pointer=()):
    if isinstance(value, dict):
        for key, item in value.items():
            # Field names can themselves carry private data. Unknown names
            # are identified by hash; never print arbitrary producer keys.
            field = key if key in PUBLIC_FIELDS else 'key-sha256-' + digest(key.encode())
            yield from scalars(item, (*pointer, field))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from scalars(item, (*pointer, str(index)))
    elif isinstance(value, str):
        yield '/'.join(pointer), value


def describe(path, scanner):
    raw, value = read_json(path)
    if not isinstance(value, dict):
        raise q.Stop('diagnostic object required')
    fields = []
    for pointer, text in scalars(value):
        findings = scanner.scan_generated_bytes(json.dumps(text).encode(), 'metadata-probe/native.json', False, [])
        rules = sorted({item.rule for item in findings})
        if rules or pointer in ('ReportID', 'documentNamespace') or pointer.startswith('Metadata/'):
            fields.append({'field': pointer, 'bytes': len(text.encode()), 'sha256': digest(text.encode()), 'rules': rules})
        if len(fields) > 2048:
            raise q.Stop('diagnostic field budget')
    return {'bytes': len(raw), 'sha256': digest(raw), 'fields': fields}, value


def synthetic_layout(destination):
    destination.mkdir()
    (destination / 'blobs/sha256').mkdir(parents=True)
    def blob(raw, media):
        identifier = digest(raw)
        (destination / 'blobs/sha256' / identifier).write_bytes(raw)
        return {'mediaType': media, 'digest': 'sha256:' + identifier, 'size': len(raw)}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        body = b'Synthetic metadata probe subject.\n'
        info = tarfile.TarInfo('probe.txt')
        info.size, info.mode = len(body), 0o444
        archive.addfile(info, io.BytesIO(body))
    layer_bytes = stream.getvalue()
    layer = blob(layer_bytes, 'application/vnd.oci.image.layer.v1.tar')
    config = blob(json.dumps({'architecture': 'amd64', 'os': 'linux', 'config': {}, 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + digest(layer_bytes)]}}).encode(), 'application/vnd.oci.image.config.v1+json')
    manifest = blob(json.dumps({'schemaVersion': 2, 'config': config, 'layers': [layer]}).encode(), 'application/vnd.oci.image.manifest.v1+json')
    manifest['platform'] = {'os': 'linux', 'architecture': 'amd64'}
    q.write(destination / 'index.json', {'schemaVersion': 2, 'manifests': [manifest]})
    q.write(destination / 'oci-layout', {'imageLayoutVersion': '1.0.0'})
    return manifest['digest']


def instance(root):
    value = q.Qualification(root)
    if value.inputs.get('metadata_probe') is not True:
        raise q.Stop('metadata mode was not admitted')
    return value


def buildkit(root):
    value = instance(root)
    try:
        value.start('metadata-probe')
    finally:
        value.stop('metadata-probe')


def git(source, *args):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), *args], cwd=source, timeout=10, text=True).rstrip('\n')


def scan(root):
    value = instance(root)
    scanner = q.module(value.source, 'sanitize_public.py')
    tools = value.root / 'metadata-tools'
    tools.mkdir()
    pins = {}
    for name in ('syft', 'trivy'):
        pin = value.runtime['tools'][name]
        archive = tools / pin['asset_name']
        value.release['curl_download'](pin['source_url'], archive, pin['sha256'], value.env, value.output / 'metadata-acquisition.log')
        value.release['extract_one_binary'](archive, name, tools / name)
        pins[name] = {'archive_sha256': q.sha(archive), 'binary_sha256': q.sha(tools / name)}
        archive.unlink()
        value.run('metadata-version-' + name, [str(tools / name), '--version'], timeout=30)
    value.env.update(SYFT_CHECK_FOR_APP_UPDATE='false', SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES='false', SYFT_GOLANG_SEARCH_REMOTE_LICENSES='false', TRIVY_CACHE_DIR=str(value.root / 'metadata-trivy-cache'), TRIVY_DISABLE_VEX_NOTICE='true', TRIVY_SKIP_VERSION_CHECK='true')
    subject = value.artifacts / 'binaries-B' / 'synthetic-probe'
    subject.parent.mkdir()
    subject.write_bytes(b'Synthetic metadata probe subject.\n')
    layout = value.artifacts / 'images-B' / 'synthetic-probe'
    layout.parent.mkdir()
    manifest_digest = synthetic_layout(layout)
    reports = {}
    for name, scheme, path in [('file', 'file', subject), ('image', 'oci-dir', layout)]:
        target = value.output / ('metadata-' + name + '.raw.spdx.json')
        value.run('metadata-syft-' + name, [str(tools / 'syft'), 'scan', scheme + ':' + str(path), '--output', 'spdx-json=' + str(target)], timeout=90)
        summary, data = describe(target, scanner)
        if data.get('spdxVersion') != 'SPDX-2.3' or 'Tool: syft-1.50.0' not in data.get('creationInfo', {}).get('creators', []) or not isinstance(data.get('documentNamespace'), str):
            raise q.Stop('unrecognized Syft diagnostic producer')
        reports['syft_' + name] = summary
    target = value.output / 'metadata-trivy-source.json'
    value.run('metadata-trivy-source', [str(tools / 'trivy'), 'fs', '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--scanners', 'secret', '--exit-code', '1', '--no-progress', '--format', 'json', '--output', str(target), str(value.source)], timeout=90)
    reports['trivy_source'], data = describe(target, scanner)
    if data.get('SchemaVersion') != 2 or data.get('Trivy', {}).get('Version') != '0.72.0' or not isinstance(data.get('ReportID'), str) or not isinstance(data.get('Results'), list):
        raise q.Stop('unrecognized Trivy diagnostic producer')
    metadata = data.get('Metadata', {})
    required = ('RepoURL', 'Commit', 'Author', 'Committer')
    if any(not isinstance(metadata.get(key), str) or not metadata[key] for key in required):
        raise q.Stop('Trivy source provenance unavailable')
    bindings = {'clone_origin_matches': metadata['RepoURL'] == git(value.source, 'config', '--get', 'remote.origin.url'), 'commit_matches': metadata['Commit'] == value.commit, 'author_matches': metadata['Author'] == git(value.source, 'show', '-s', '--format=%an <%ae>', 'HEAD'), 'committer_matches': metadata['Committer'] == git(value.source, 'show', '-s', '--format=%cn <%ce>', 'HEAD')}
    if not all(bindings.values()) or any(row.get('Secrets') for row in data['Results']):
        raise q.Stop('diagnostic provenance or secret check failed')
    worker = value.output / 'buildkit-workers-metadata-probe.json'
    reports['buildkit'], data = describe(worker, scanner)
    stdout = data.get('stdout')
    if not isinstance(stdout, str) or 'overlayfs' not in stdout or not any(digest(token.encode()) == GC_ENUM_SHA256 for token in re.findall(r'type==[^,\s]+', stdout)):
        raise q.Stop('BuildKit verbose diagnostic incomplete')
    result = {'schema_version': 1, 'diagnostic_status': 'pass', 'source_commit': value.commit, 'source_tree': value.inputs['tree'], 'tool_pins': pins, 'synthetic_subject_sha256': q.sha(subject), 'synthetic_OCI_manifest': manifest_digest, 'reports': reports, 'source_bindings': bindings, 'BuildKit_default_source_local_enum_present': True, 'vulnerability_database_fetched': False, 'historical_artifact_requested': False, 'prior_qualification_validated': False, 'release_admitted': False, 'live_operations': False}
    q.write(value.output / 'metadata-probe-result.json', result)


def safe_summary(root, result):
    scanner = q.module(root / 'source', 'sanitize_public.py')
    raw = (json.dumps(result, indent=2, allow_nan=False) + '\n').encode()
    if len(raw) > LIMIT - 65536 or scanner.scan_generated_bytes(raw, 'metadata-probe/summary.json', False, []):
        raise q.Stop('diagnostic output rejected')
    return raw


def export(root):
    _raw, result = read_json(root / 'evidence/metadata-probe-result.json')
    if result.get('diagnostic_status') != 'pass' or result.get('release_admitted') is not False:
        raise q.Stop('diagnostic result incomplete')
    raw = safe_summary(root, result)
    public = root / 'public'
    public.mkdir()
    (public / 'metadata-probe.json').write_bytes(raw)


def admit_upload(root):
    """Publish only a checked structural result plus fixed terminal fields."""
    _raw, inputs = read_json(root / 'inputs.json')
    _raw, terminal = read_json(root / 'evidence/terminal.json')
    _raw, result = read_json(root / 'public/metadata-probe.json')
    if inputs.get('metadata_probe') is not True or result.get('diagnostic_status') != 'pass' or result.get('release_admitted') is not False or result.get('source_commit') != inputs['commit'] or result.get('source_tree') != inputs['tree'] or terminal.get('workers_joined') is not True or terminal.get('scope_exit_code') != 0 or terminal.get('budget_or_execution_error') is not None:
        raise q.Stop('diagnostic terminal admission failed')
    result['resource_guards'] = 'pass'
    result['workers_joined'] = True
    # The complete candidate was scanned inside the observed worker scope.
    # Only the two fixed terminal fields above are added after workers join.
    encoded = (json.dumps(result, indent=2, allow_nan=False) + '\n').encode()
    if len(encoded) > LIMIT - 65536:
        raise q.Stop('diagnostic terminal metadata budget')
    (root / 'public/metadata-probe.json').write_bytes(encoded)
    files = q.inventory(root / 'public')
    if {row['path'] for row in files} != {'metadata-probe.json'}:
        raise q.Stop('unexpected diagnostic publication member')
    manifest = {'files': files, 'diagnostic_only': True, 'artifact_qualification_admitted': False, 'release_admitted': False}
    raw = (json.dumps(manifest, indent=2) + '\n').encode()
    if len(raw) + sum(row['bytes'] for row in files) > LIMIT:
        raise q.Stop('diagnostic transfer exceeds 1 MiB')
    (root / 'public/evidence-inventory.json').write_bytes(raw)
    # Open traversal only after every nonpublic entry has been protected.
    # Never follow a substituted link while changing owned permissions.
    for path in root.iterdir():
        if path.name == 'public':
            continue
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            path.chmod(0o700)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            path.chmod(0o600)
        else:
            raise q.Stop('unsafe private diagnostic entry')
    for path in (root, root / 'public', *list((root / 'public').iterdir())):
        path.chmod(0o755 if path.is_dir() else 0o644)


def check_upload(public):
    """Unprivileged read-only verification; never read native task evidence."""
    files = q.inventory(public)
    if {row['path'] for row in files} != {'metadata-probe.json', 'evidence-inventory.json'} or sum(row['bytes'] for row in files) > LIMIT:
        raise q.Stop('diagnostic publication membership or size failed')
    _raw, manifest = read_json(public / 'evidence-inventory.json')
    expected = [row for row in files if row['path'] == 'metadata-probe.json']
    if manifest != {'files': expected, 'diagnostic_only': True, 'artifact_qualification_admitted': False, 'release_admitted': False}:
        raise q.Stop('diagnostic publication inventory mismatch')
