#!/usr/bin/env python3
"""Audit fixed trace exceptions against the digest-pinned producer archive.

This read-only authoring check grants no runtime authority or new exceptions.
"""
# SPDX-License-Identifier: MPL-2.0
import argparse
import hashlib
import json
import pathlib
import re
import stat
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import public_dependency_metadata as metadata
import sanitize_public as sanitizer

ENTRIES = ('Runner.Listener', 'Runner.Worker', 'Runner.PluginHost')
PREFIX = 'qualification-evidence/sdk-startup/'
PATTERNS = (
    re.compile(r'    ([^ ,]+) assemblyVersion=([0-9.]*) fileVersion=([0-9.]+)'),
    re.compile(r'    Entry [0-9]+ for asset name: ([^ /,]+), relpath: ([^ ,]+), assemblyVersion ([0-9.]*), fileVersion ([0-9.]+)'),
    re.compile(r'Adding tpa entry: /work/runner-source/_layout/bin/([^ /,]+), AssemblyVersion: ([0-9.]+), FileVersion: ([0-9.]+)'),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path, maximum):
    info = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum, 'unsafe audit input')
    return info


def producer_records(document):
    records = set()
    for target in document['targets'].values():
        for library in target.values():
            for group in ('runtime', 'runtimeTargets', 'native'):
                for name, row in library.get(group, {}).items():
                    if 'fileVersion' not in row:
                        continue
                    versions = (row.get('assemblyVersion', ''), row['fileVersion'])
                    records.add((name, *versions))
                    records.add((pathlib.PurePosixPath(name).name, *versions))
    return records


def verify_line(finding, records):
    require(finding.rule in ('IP001', 'HOST001'), 'unrelated trace finding')
    matches = [(index, pattern.fullmatch(finding.content)) for index, pattern in enumerate(PATTERNS)]
    matches = [(index, match) for index, match in matches if match is not None]
    require(len(matches) == 1, 'unrecognized producer trace line')
    index, match = matches[0]
    if index == 1:
        asset, name, assembly, file_version = match.groups()
        require(asset == pathlib.PurePosixPath(name).stem, 'producer asset identity')
    else:
        name, assembly, file_version = match.groups()
    require((name, assembly, file_version) in records, 'unbound producer version')
    if finding.rule == 'HOST001':
        require(name == 'System.Transactions.Local.dll', 'unrelated producer identifier')


def audit(archive, evidence):
    descriptor = metadata.parse(metadata.committed(ROOT, 'internal/buildinfo/runner_rebuild.json'))
    require(regular(archive, descriptor['archive_bytes']).st_size == descriptor['archive_bytes'], 'archive size mismatch')
    with archive.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == descriptor['linux_x64_sha256'], 'archive digest mismatch')
    records, members = {}, []
    with tarfile.open(archive) as source:
        all_members = source.getmembers()
        for entry in ENTRIES:
            name = './bin/' + entry + '.deps.json'
            selected = [member for member in all_members if member.name == name]
            require(len(selected) == 1 and selected[0].isfile() and 0 < selected[0].size <= 2**20, 'unsafe producer member')
            raw = source.extractfile(selected[0]).read()
            records[entry] = producer_records(metadata.parse(raw))
            members.append({'member': name, 'sha256': hashlib.sha256(raw).hexdigest()})
    allowlist = sanitizer.load_allowlist(ROOT / sanitizer.ALLOWLIST_FILENAME)
    reports = []
    checked = set()
    for entry in ENTRIES:
        path = evidence / (entry + '.trace')
        regular(path, 8 * 2**20)
        raw = path.read_bytes()
        findings = sanitizer.scan_text_content(raw.decode('utf-8', 'strict'), PREFIX + path.name, fixture=False)
        for finding in findings:
            verify_line(finding, records[entry])
            require(allowlist.suppresses(finding), 'producer trace line is not registered')
            checked.add((finding.path, finding.line, finding.rule, sanitizer.compute_line_hash(finding.content)))
        reports.append({'entrypoint': entry, 'trace_sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'findings_checked': len(findings)})
    registered = {(row['path'], row['line'], row['rule'], row['sha256']) for row in allowlist._entries if row['path'].startswith(PREFIX)}
    require(checked == registered, 'trace exception inventory mismatch')
    return {'status': 'pass', 'archive_sha256': descriptor['linux_x64_sha256'], 'producer_members': members, 'traces': reports, 'canonical_line_exceptions': len(checked), 'unmatched_findings': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner-archive', type=pathlib.Path, required=True)
    parser.add_argument('--evidence-directory', type=pathlib.Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.runner_archive.absolute(), args.evidence_directory.absolute()), indent=2))


if __name__ == '__main__':
    main()
