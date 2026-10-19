"""Committed producer evidence for narrowly scoped generated SPDX checks.

Projection is in memory and changes only exact, source-bound attribution or
reference fields. All other original bytes, including their escaping, remain
available to the public sanitizer. Publication retains the original metadata.
"""
# SPDX-License-Identifier: MPL-2.0
import base64
import email.utils
import hashlib
import io
import json
import lzma
import os
import pathlib
import re
import stat
import subprocess
import urllib.parse
import urllib.request
import zipfile

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



def cached_bytes(cache, relative, maximum):
    root = pathlib.Path(cache)
    path = root / relative
    if not root.is_absolute() or root.resolve(strict=True) != root or path.resolve(strict=True) != path:
        raise MetadataError('indirect producer cache')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise MetadataError('unsafe producer cache file')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    stable = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
    if stable(before) != stable(after) or len(raw) != before.st_size:
        raise MetadataError('changed producer cache file')
    return raw


def debian_bytes(url, maximum, cache, expected_sha=None):
    parsed = source_url(url, 'snapshot.debian.org')
    if cache is not None:
        return cached_bytes(cache, parsed.path.removeprefix('/'), maximum)
    # Reject proxy credentials and cross-origin redirects. Snapshot can
    # redirect an immutable archive path to its content-addressed /file/ path.
    class SnapshotRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, response, code, message, headers, target):
            target_url = source_url(target, 'snapshot.debian.org')
            names = [pathlib.PurePosixPath(parsed.path).name]
            if expected_sha is not None:
                names.append(expected_sha)
            content_path = r'/file/[0-9a-f]{40}(?:/(?:' + '|'.join(re.escape(name) for name in names) + r'))?/?'
            if re.fullmatch(content_path, target_url.path) is None:
                raise MetadataError('producer source redirect')
            return super().redirect_request(request, response, code, message, headers, target)
    proxies = {kind: value for kind, value in urllib.request.getproxies().items() if kind in ('http', 'https', 'all', 'no')}
    for kind, value in proxies.items():
        if kind == 'no':
            continue
        proxy = urllib.parse.urlsplit(value)
        if proxy.scheme not in ('http', 'https') or not proxy.netloc or proxy.username is not None or proxy.password is not None:
            raise MetadataError('producer proxy credentials or scheme')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies), SnapshotRedirect())
    with opener.open(url, timeout=30) as response:
        if response.status != 200:
            raise MetadataError('producer source response')
        raw = response.read(maximum + 1)
    if not 0 < len(raw) <= maximum:
        raise MetadataError('producer source budget')
    return raw


def verified_index(row, cache, wanted):
    release = debian_bytes(row['inrelease_url'], 2**20, cache, row['inrelease_sha256'])
    if digest(release) != row['inrelease_sha256']:
        raise MetadataError('producer InRelease digest')
    sections = re.findall(r'^SHA256:\n((?: [^\n]+\n)+)', release.decode('utf-8'), re.M)
    if len(sections) != 1:
        raise MetadataError('producer signed SHA256 section')
    entries = re.findall(r'^ ([0-9a-f]{64}) +([0-9]+) +main/binary-amd64/Packages\.xz$', sections[0], re.M)
    if entries != [(row['sha256'], str(row['bytes']))]:
        raise MetadataError('producer signed index digest')
    raw = debian_bytes(row['url'], 32 * 2**20, cache, row['sha256'])
    if len(raw) != row['bytes'] or digest(raw) != row['sha256']:
        raise MetadataError('producer index digest')
    found = {}
    expanded = 0
    stanza = bytearray()
    def accept():
        if not stanza:
            return
        text = bytes(stanza).decode('utf-8', 'strict')
        fields = {}
        current = None
        for line in text.splitlines():
            if line.startswith((' ', '\t')) and current is not None:
                fields[current] += '\n' + line
            else:
                current, separator, value = line.partition(': ')
                if not separator or current in fields:
                    raise MetadataError('ambiguous producer stanza')
                fields[current] = value
        key = (fields.get('Package'), fields.get('Version'), fields.get('Architecture'))
        if key in wanted:
            if key in found:
                raise MetadataError('duplicate producer package')
            found[key] = (fields, digest(stanza))
        stanza.clear()
    with lzma.LZMAFile(io.BytesIO(raw)) as stream:
        while True:
            line = stream.readline(2**20 + 1)
            if not line:
                break
            expanded += len(line)
            if expanded > 128 * 2**20 or len(stanza) + len(line) > 2**20:
                raise MetadataError('producer index expansion budget')
            if line == b'\n':
                accept()
            else:
                stanza.extend(line)
        accept()
    return found


def verified_go_members(cache, module, version, expected, files):
    # Go's dirhash.HashZip hashes every uncompressed member, not the ZIP's
    # self-declared .ziphash sidecar or central-directory CRC values.
    raw = cached_bytes(cache, 'cache/download/' + module + '/@v/' + version + '.zip', 64 * 2**20)
    manifest = hashlib.sha256()
    selected = {}
    prefix = module + '@' + version + '/'
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(entries) > 16384 or len(set(names)) != len(names) or sum(entry.file_size for entry in entries) > 512 * 2**20:
            raise MetadataError('producer module archive budget or ambiguity')
        for entry in sorted(entries, key=lambda entry: entry.filename):
            name = entry.filename
            if not name.startswith(prefix) or '\n' in name or '\\' in name or any(part in ('.', '..', '') for part in name.split('/')) or entry.is_dir() or stat.S_ISLNK(entry.external_attr >> 16):
                raise MetadataError('unsafe producer module member')
            member_digest = hashlib.sha256()
            content = bytearray()
            size = 0
            with archive.open(entry) as stream:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > entry.file_size:
                        raise MetadataError('producer module member size')
                    member_digest.update(chunk)
                    if name.removeprefix(prefix) in files:
                        if size > 2**20:
                            raise MetadataError('producer legal member budget')
                        content.extend(chunk)
            if size != entry.file_size:
                raise MetadataError('producer module member size')
            manifest.update((member_digest.hexdigest() + '  ' + name + '\n').encode())
            if name.removeprefix(prefix) in files:
                selected[name.removeprefix(prefix)] = bytes(content)
    if 'h1:' + base64.b64encode(manifest.digest()).decode() != expected or set(selected) != files:
        raise MetadataError('producer module checksum or legal member')
    return selected


def load(repository, *, debian_cache=None, go_module_cache=None):
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
        wanted = {(row.get('name'), row.get('version'), urllib.parse.parse_qs(urllib.parse.urlsplit(row.get('purl', '')).query).get('arch', [None])[0]) for row in value['packages'] if isinstance(row, dict)} if isinstance(value['packages'], list) else set()
        producer_indexes = {sha: verified_index(row, debian_cache, wanted) for sha, row in indexes.items()}
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
            actual = producer_indexes[row['index_sha256']].get((row['name'], row['version'], qualifiers['arch'][0]))
            if actual is None:
                raise MetadataError('missing producer package')
            producer, stanza_digest = actual
            archive_prefix = indexes[row['index_sha256']]['url'].split('/dists/', 1)[0] + '/'
            if stanza_digest != row['stanza_sha256'] or producer.get('Maintainer') != row['maintainer'] or producer.get('SHA256') != row['deb_sha256'] or archive_prefix + producer.get('Filename', '') != row['deb_url']:
                raise MetadataError('producer package byte binding')
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
        verified_modules = {}
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
            module_key = (row['module'], row['version'], row['module_zip_h1'])
            if module_key not in verified_modules:
                members = {item['file'] for item in value['go_licenses'] if isinstance(item, dict) and item.get('module') == row['module'] and item.get('version') == row['version']}
                verified_modules[module_key] = verified_go_members(go_module_cache or os.environ.get('GOMODCACHE', ''), row['module'], row['version'], row['module_zip_h1'], members)
            body = committed(root, row['path'])
            if verified_modules[module_key].get(row['file']) != body:
                raise MetadataError('producer legal member bytes')
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
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError, lzma.LZMAError, zipfile.BadZipFile) as error:
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
