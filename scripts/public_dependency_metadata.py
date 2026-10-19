"""Committed producer evidence for narrowly scoped generated SPDX checks.

Projection is in memory and changes only exact, source-bound attribution or
reference fields. All other original bytes, including their escaping, remain
available to the public sanitizer. Publication retains the original metadata.
"""
# SPDX-License-Identifier: MPL-2.0
import email.utils
import hashlib
import json
import pathlib
import re
import stat
import subprocess
import urllib.parse

REGISTRY = 'release/public-dependency-metadata.json'
HEX = re.compile(r'[0-9a-f]{64}')


class MetadataError(ValueError):
    pass


def pairs(items):
    result = dict(items)
    if len(result) != len(items):
        raise MetadataError('duplicate public metadata key')
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def committed(root, relative, maximum=2**20):
    path = root / relative
    info = path.lstat()
    if path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise MetadataError('unsafe public evidence path')
    raw = path.read_bytes()
    result = subprocess.run(['git', 'show', 'HEAD:' + relative], cwd=root, capture_output=True, timeout=30, check=False)
    if result.returncode or result.stdout != raw:
        raise MetadataError('uncommitted public evidence')
    return raw


def source_url(value, host):
    if not isinstance(value, str):
        raise MetadataError('public source URL type')
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != 'https' or parsed.netloc != host or parsed.query or parsed.fragment or any(part in ('.', '..') for part in urllib.parse.unquote(parsed.path).split('/')):
        raise MetadataError('public source URL')
    return parsed


def load(repository):
    try:
        root = pathlib.Path(repository)
        if not root.is_absolute() or root.resolve(strict=True) != root:
            raise MetadataError('indirect evidence repository')
        raw = committed(root, REGISTRY)
        value = parse(raw)
        if not isinstance(value, dict) or set(value) != {'schema_version', 'base_image', 'debian_indexes', 'packages', 'go_licenses'} or type(value['schema_version']) is not int or value['schema_version'] != 1:
            raise MetadataError('public evidence schema')
        dockerfile = committed(root, 'images/runner/Dockerfile').decode('utf-8')
        bases = set(re.findall(r'^FROM (debian:bookworm-slim@sha256:[0-9a-f]{64})(?:\s.*)?$', dockerfile, re.M))
        if bases != {value['base_image']}:
            raise MetadataError('public evidence base image')
        verifier = committed(root, 'images/runner/verify-debian-cache.sh').decode('utf-8')
        releases = dict((relative, sha) for sha, relative in re.findall(r'^verify ([0-9a-f]{64}) (archive/\S+/InRelease)$', verifier, re.M))
        indexes = {}
        if not isinstance(value['debian_indexes'], list) or not 1 <= len(value['debian_indexes']) <= 3:
            raise MetadataError('public index count')
        for row in value['debian_indexes']:
            if not isinstance(row, dict) or set(row) != {'url', 'sha256', 'bytes', 'inrelease_url', 'inrelease_sha256'} or HEX.fullmatch(row['sha256']) is None or HEX.fullmatch(row['inrelease_sha256']) is None or type(row['bytes']) is not int or not 0 < row['bytes'] <= 32 * 2**20:
                raise MetadataError('public index schema')
            url = source_url(row['url'], 'snapshot.debian.org')
            release = source_url(row['inrelease_url'], 'snapshot.debian.org')
            if releases.get(release.path.removeprefix('/')) != row['inrelease_sha256'] or url.path != release.path.removesuffix('InRelease') + 'main/binary-amd64/Packages.xz' or row['sha256'] in indexes:
                raise MetadataError('public signed index binding')
            indexes[row['sha256']] = row
        packages = {}
        if not isinstance(value['packages'], list) or not 0 < len(value['packages']) <= 256:
            raise MetadataError('public package count')
        required = {'name', 'version', 'purl', 'maintainer', 'deb_url', 'deb_sha256', 'stanza_sha256', 'index_sha256', 'attribution_fields'}
        for row in value['packages']:
            if not isinstance(row, dict) or set(row) not in (required, required | {'spdx_id'}) or not all(isinstance(row[key], str) and row[key] for key in required - {'attribution_fields'}):
                raise MetadataError('public package schema')
            if any(HEX.fullmatch(row[key]) is None for key in ('deb_sha256', 'stanza_sha256', 'index_sha256')) or row['index_sha256'] not in indexes or row['purl'] in packages:
                raise MetadataError('public package source binding')
            purl = urllib.parse.urlsplit(row['purl'])
            qualifiers = urllib.parse.parse_qs(purl.query, strict_parsing=True)
            if urllib.parse.unquote(row['purl'].split('?', 1)[0]) != 'pkg:deb/debian/' + row['name'] + '@' + row['version'] or not {'arch', 'distro'} <= set(qualifiers) or set(qualifiers) - {'arch', 'distro', 'upstream'} or any(len(v) != 1 for v in qualifiers.values()) or qualifiers['arch'][0] not in ('amd64', 'all') or re.fullmatch(r'debian-12(?:\.[0-9]+)?', qualifiers['distro'][0]) is None:
                raise MetadataError('public package identity')
            url = source_url(row['deb_url'], 'snapshot.debian.org')
            prefix = source_url(indexes[row['index_sha256']]['url'], 'snapshot.debian.org').path.split('/dists/', 1)[0] + '/pool/'
            if not url.path.startswith(prefix) or not url.path.endswith('.deb'):
                raise MetadataError('public package archive source')
            fields = row['attribution_fields']
            if not isinstance(fields, list) or fields != sorted(set(fields)) or not set(fields) <= {'originator', 'supplier'}:
                raise MetadataError('public attribution fields')
            name, address = email.utils.parseaddr(row['maintainer'])
            if not name or re.fullmatch(r'[^@\s]+@[^@\s]+', address) is None:
                raise MetadataError('public producer identity')
            if 'spdx_id' in row and (not isinstance(row['spdx_id'], str) or re.fullmatch(r'SPDXRef-[A-Za-z0-9.-]+', row['spdx_id']) is None):
                raise MetadataError('public package reference')
            if not fields and 'spdx_id' not in row:
                raise MetadataError('unused public package evidence')
            packages[row['purl']] = {**row, 'rendered_producer': 'Person: ' + name + ' (' + address + ')'}
        licenses = []
        documents = {}
        if not isinstance(value['go_licenses'], list) or len(value['go_licenses']) > 64:
            raise MetadataError('public license count')
        go_sum = committed(root, 'go.sum').decode('utf-8').splitlines() if value['go_licenses'] else []
        seen = set()
        total = 0
        for row in value['go_licenses']:
            if not isinstance(row, dict) or set(row) != {'module', 'version', 'file', 'module_zip_h1', 'source_url', 'path', 'sha256'} or not all(isinstance(v, str) and v for v in row.values()):
                raise MetadataError('public Go license schema')
            key = (row['module'], row['version'], row['file'])
            file = pathlib.PurePosixPath(row['file'])
            if key in seen or file.is_absolute() or str(file) != row['file'] or any(p in ('.', '..') for p in row['file'].split('/')) or '\\' in row['file'] or HEX.fullmatch(row['sha256']) is None or row['path'] != 'release/public-dependency-texts/' + row['sha256'] + '.txt' or row['source_url'] != 'https://proxy.golang.org/' + row['module'] + '/@v/' + row['version'] + '.zip':
                raise MetadataError('public Go license identity')
            source_url(row['source_url'], 'proxy.golang.org')
            if re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', row['module_zip_h1']) is None or row['module'] + ' ' + row['version'] + ' ' + row['module_zip_h1'] not in go_sum:
                raise MetadataError('public Go module checksum binding')
            body = committed(root, row['path'])
            body.decode('utf-8', 'strict')
            if digest(body) != row['sha256']:
                raise MetadataError('public Go license digest')
            total += len(body)
            if total > 8 * 2**20:
                raise MetadataError('public licensing budget')
            seen.add(key)
            # Do not make short legal notices into arbitrary text exemptions.
            if len(body) >= 128:
                documents[row['path']] = body
            licenses.append({**row, 'content': body})
        return {'source_path': REGISTRY, 'source_raw': raw, 'package_records': packages, 'licenses': licenses, 'documents': sorted(documents.items(), key=lambda pair: (-len(pair[1]), pair[0]))}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError) as error:
        raise MetadataError('unverified public dependency metadata') from error


def string_spans(text):
    """Locate JSON string values without reserializing any other source bytes."""
    decoder = json.JSONDecoder(object_pairs_hook=pairs)
    def whitespace(position):
        while position < len(text) and text[position] in ' \t\r\n': position += 1
        return position
    def value(position, path, depth):
        if depth > 64: raise MetadataError('SPDX nesting limit')
        position = whitespace(position)
        if text[position] == '{':
            position = whitespace(position + 1)
            if text[position] == '}': return position + 1
            while True:
                key, position = decoder.raw_decode(text, position)
                if not isinstance(key, str): raise MetadataError('SPDX key')
                position = whitespace(position)
                if text[position] != ':': raise MetadataError('SPDX object')
                position = yield from value(position + 1, path + (key,), depth + 1)
                position = whitespace(position)
                if text[position] == '}': return position + 1
                if text[position] != ',': raise MetadataError('SPDX object separator')
                position = whitespace(position + 1)
        elif text[position] == '[':
            position = whitespace(position + 1)
            if text[position] == ']': return position + 1
            index = 0
            while True:
                position = yield from value(position, path + (index,), depth + 1)
                position = whitespace(position)
                if text[position] == ']': return position + 1
                if text[position] != ',': raise MetadataError('SPDX array separator')
                position = whitespace(position + 1)
                index += 1
        else:
            item, end = decoder.raw_decode(text, position)
            if isinstance(item, str): yield path, item, position, end
            return end
    yield from value(0, (), 0)


def project_spdx(text, metadata):
    try:
        document = parse(text)
    except (ValueError, TypeError):
        return text
    if not isinstance(document, dict) or document.get('spdxVersion') != 'SPDX-2.3' or not isinstance(document.get('packages'), list):
        return text
    replacements = {}
    references = set()
    for index, package in enumerate(document['packages']):
        if not isinstance(package, dict): continue
        refs = package.get('externalRefs', [])
        if not isinstance(refs, list): continue
        purls = [r.get('referenceLocator') for r in refs if isinstance(r, dict) and r.get('referenceType') == 'purl']
        if len(purls) != 1 or not isinstance(purls[0], str): continue
        row = metadata['package_records'].get(purls[0])
        if row is None or package.get('name') != row['name'] or package.get('versionInfo') != row['version']: continue
        for field in row['attribution_fields']:
            if package.get(field) == row['rendered_producer']:
                replacements[('packages', index, field)] = package[field]
        if row.get('spdx_id') is not None and package.get('SPDXID') == row['spdx_id']:
            replacements[('packages', index, 'SPDXID')] = row['spdx_id']
            references.add(row['spdx_id'])
    if not replacements: return text
    changes = []
    for path, value, start, end in string_spans(text):
        reference = value in references and (len(path) == 3 and path[0] == 'relationships' and path[2] in ('spdxElementId', 'relatedSpdxElement') or len(path) == 2 and path[0] == 'documentDescribes')
        if replacements.get(path) == value or reference:
            marker = '[public-dependency-sha256:' + digest(value.encode()) + ']'
            changes.append((start, end, json.dumps(marker)))
    pieces = []
    previous = 0
    for start, end, replacement in changes:
        pieces.extend((text[previous:start], replacement))
        previous = end
    pieces.append(text[previous:])
    return ''.join(pieces)


def complete_go_license_records(document, metadata):
    prefix = ':'.join(('file', '//$GOPATH/pkg/mod/'))
    sources = {prefix + row['module'] + '@' + row['version'] + '/' + row['file']: row for row in metadata['licenses']}
    for info in document.get('hasExtractedLicensingInfos', []):
        if not isinstance(info, dict) or not isinstance(info.get('seeAlsos', []), list):
            raise MetadataError('SPDX license citation schema')
        selected = [sources[url] for url in info.get('seeAlsos', []) if isinstance(url, str) and url in sources]
        if not selected: continue
        original = info.get('extractedText', 'NOASSERTION')
        if not isinstance(original, str): raise MetadataError('SPDX license text schema')
        if original not in ('', 'NOASSERTION') and any(row['content'].decode().strip() not in original for row in selected):
            raise MetadataError('conflicting producer licensing text')
        if original in ('', 'NOASSERTION'):
            bodies = list(dict.fromkeys(row['content'].decode() for row in selected))
            info['extractedText'] = '\n\n'.join(bodies)
        info['seeAlsos'] = [sources[url]['source_url'] + '#' + urllib.parse.quote(sources[url]['module'] + '@' + sources[url]['version'] + '/' + sources[url]['file'], safe='/@.-_') if isinstance(url, str) and url in sources else url for url in info['seeAlsos']]
