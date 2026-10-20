"""Small retrievable copies of already admitted public qualification receipts."""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import json
import pathlib
import re
import stat

import _trivy_report

LIMIT = 2**20
COPY_BUDGET = 768 * 1024
REQUIRED = ('RESULT.json', 'source-inputs.json', 'source-acquisition.json', 'build-result.json', 'scan-result.json', 'security-results.json', 'runner-reported-CVE-clearance.json', 'scanner-database-before.json', 'scanner-database-after.json', 'producer-publication-stages.json', 'trivy-report-rendering.json', 'worker-terminal.json', 'scan-terminal.json', 'export-policy.json')
OPTIONAL = ('tool-trivy.json', 'tool-syft.json', 'image-results.json', 'resource-samples.jsonl')
MEMBERS = frozenset((*REQUIRED, *OPTIONAL, 'evidence-inventory.json'))


class ControlError(ValueError):
    pass


def require(condition):
    if not condition:
        raise ControlError('bounded public control evidence failed admission')


def parse(raw):
    return json.loads(raw, object_pairs_hook=_trivy_report.unique, parse_constant=_trivy_report.nonfinite)


def row(name, raw):
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def create(public, destination, inputs, raw_limit):
    public, destination = pathlib.Path(public), pathlib.Path(destination)
    inventory = _trivy_report.stable_bytes(public / 'evidence-inventory.json', LIMIT)
    manifest = parse(inventory)
    admitted = manifest.get('artifact_qualification_admitted')
    require(type(admitted) is bool)
    indexed = {item['path']: item for item in manifest['files']}
    require(len(indexed) == len(manifest['files']) and 'RESULT.json' in indexed)
    if admitted:
        require(set(REQUIRED) <= indexed.keys())
    selected = {'evidence-inventory.json': inventory}
    used = len(inventory)
    omitted = []
    for name in (*REQUIRED, *OPTIONAL):
        item = indexed.get(name)
        if item is None:
            omitted.append({'path': name, 'reason': 'not-present'})
            continue
        require(type(item['bytes']) is int and item['bytes'] > 0)
        if used + item['bytes'] > COPY_BUDGET:
            require(name not in REQUIRED or not admitted)
            omitted.append({'path': name, 'reason': 'size-budget'})
            continue
        raw = _trivy_report.stable_bytes(public / name, LIMIT)
        require(row(name, raw) == item)
        selected[name] = raw
        used += len(raw)
    index = {'schema_version': 1, 'control_only': True, 'source_commit': inputs['commit'], 'source_tree': inputs['tree'], 'source_manifest_sha256': hashlib.sha256(inventory).hexdigest(), 'artifact_qualification_admitted': admitted, 'release_admitted': False, 'files': [row(name, raw) for name, raw in sorted(selected.items())], 'omitted_control_receipts': omitted}
    encoded = (json.dumps(index, indent=2) + '\n').encode()
    require(len(encoded) + used <= LIMIT)
    # The duplicate small receipts also count toward the existing aggregate
    # file-content transfer cap; raw payloads are never copied or repartitioned.
    require(sum(item['bytes'] for item in manifest['files']) + len(inventory) + used + len(encoded) <= raw_limit)
    destination.mkdir(mode=0o700)
    for name, raw in {**selected, 'control-index.json': encoded}.items():
        with (destination / name).open('xb') as stream:
            stream.write(raw)
    verify(destination)
    for path in destination.iterdir():
        path.chmod(0o644)
    destination.chmod(0o755)


def verify(directory):
    directory = pathlib.Path(directory)
    require(directory.resolve(strict=True) == directory and directory.is_dir())
    paths = list(directory.iterdir())
    require(len(paths) <= len(MEMBERS) + 1 and {path.name for path in paths} <= MEMBERS | {'control-index.json'})
    total = 0
    for path in paths:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= LIMIT)
        total += info.st_size
    require(total <= LIMIT)
    index = parse(_trivy_report.stable_bytes(directory / 'control-index.json', LIMIT))
    require(set(index) == {'schema_version', 'control_only', 'source_commit', 'source_tree', 'source_manifest_sha256', 'artifact_qualification_admitted', 'release_admitted', 'files', 'omitted_control_receipts'})
    require(type(index['schema_version']) is int and index['schema_version'] == 1 and index['control_only'] is True and index['release_admitted'] is False and type(index['artifact_qualification_admitted']) is bool)
    require(all(isinstance(index[key], str) and re.fullmatch('[0-9a-f]{40}', index[key]) is not None for key in ('source_commit', 'source_tree')))
    rows = index['files']
    require(len(rows) == len(paths) - 1 and {item['path'] for item in rows} == {path.name for path in paths} - {'control-index.json'})
    raw_files = {}
    for item in rows:
        require(item['path'] in MEMBERS)
        raw = _trivy_report.stable_bytes(directory / item['path'], LIMIT)
        require(row(item['path'], raw) == item)
        raw_files[item['path']] = raw
    manifest_raw = raw_files['evidence-inventory.json']
    require(hashlib.sha256(manifest_raw).hexdigest() == index['source_manifest_sha256'])
    manifest = parse(manifest_raw)
    require(manifest['artifact_qualification_admitted'] is index['artifact_qualification_admitted'])
    source = {item['path']: item for item in manifest['files']}
    require(len(source) == len(manifest['files']))
    for name, raw in raw_files.items():
        if name != 'evidence-inventory.json':
            require(row(name, raw) == source[name])
    if index['artifact_qualification_admitted']:
        require(set(REQUIRED) <= raw_files.keys())
        inputs = parse(raw_files['source-inputs.json'])
        result = parse(raw_files['RESULT.json'])
        require(inputs['commit'] == index['source_commit'] and inputs['tree'] == index['source_tree'] and result['status'] == 'pass' and result['source_commit'] == index['source_commit'] and result['source_tree'] == index['source_tree'])
    return index
