#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Read an exact public SDK-input release without credentials or SDK fallback.

The unqualified input must be published before ordinary CI. A later qualified
candidate publication is separate. Null bindings fail before network or output.
"""
import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

import _bounded_qualification as q
import _retained_runner as retained

ROOT = pathlib.Path(__file__).resolve().parents[2]
API = 'https://api.github.com'
REPOSITORY = 'sumitake/GitHub-ActionRunner'
MAX_ARCHIVE = 256 * 2**20
MAX_JSON = 2**20


def parse_json(raw):
    def pairs(items):
        value = dict(items)
        if len(value) != len(items):
            raise q.Stop('duplicate retained release key')
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(q.Stop('nonfinite release number')))


def locator(source):
    path = source / 'release/retained-runner-input.json'
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise q.Stop('unsafe retained release locator')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 4096:
            raise q.Stop('unsafe retained release locator')
        raw = stream.read(4097)
        after = os.fstat(stream.fileno())
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns, row.st_nlink)
        if len(raw) != before.st_size or identity(before) != identity(after):
            raise q.Stop('retained release locator changed')
    value = parse_json(raw)
    if type(value) is not dict or set(value) != {'schema_version', 'role', 'repository', 'tag', 'release_id', 'commit_sha'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['repository'] != REPOSITORY or value['role'] != 'unqualified-sdk-input':
        raise q.Stop('retained release locator differs')
    if type(value['release_id']) is not int or value['release_id'] <= 0 or not isinstance(value['tag'], str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,126}', value['tag']) is None or not isinstance(value['commit_sha'], str) or re.fullmatch('[0-9a-f]{40}', value['commit_sha']) is None:
        raise q.Stop('confirmed retained release identity required before publication')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def transfer(url, output, limit, *, binary=False):
    """Bound bytes/deadline; allow one official binary redirect without auth."""
    if not url.startswith(API + '/repos/' + REPOSITORY + '/'):
        raise q.Stop('unexpected retained release API origin')
    opener = urllib.request.build_opener(NoRedirect())
    headers = {'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json',
               'User-Agent': 'portable-ghar-retained-input', 'X-GitHub-Api-Version': '2026-03-10'}
    started = time.monotonic()
    try:
        response = opener.open(urllib.request.Request(url, headers=headers), timeout=30)
    except urllib.error.HTTPError as error:
        location = error.headers.get('Location', '')
        error.close()
        parsed = urllib.parse.urlsplit(location)
        if not binary or error.code != 302 or parsed.scheme != 'https' or parsed.netloc != 'release-assets.githubusercontent.com' or parsed.username or parsed.password or parsed.fragment:
            raise q.Stop('retained release response or redirect refused') from None
        # Recheck derived authority at use; no API headers or token follow.
        try:
            response = opener.open(urllib.request.Request(location, headers={'User-Agent': headers['User-Agent']}), timeout=30)
        except (urllib.error.URLError, OSError):
            raise q.Stop('retained binary transport failed') from None
    except (urllib.error.URLError, OSError):
        raise q.Stop('retained release transport failed') from None
    with response:
        if response.status != 200:
            raise q.Stop('retained release response refused')
        remaining = limit
        while True:
            if time.monotonic() - started > 120:
                raise q.Stop('retained release transfer deadline exceeded')
            data = response.read(min(remaining + 1, 1024 * 1024))
            if len(data) > remaining:
                raise q.Stop('retained release bytes exceed bound')
            if not data:
                break
            output.write(data); remaining -= len(data)


def api(path):
    output = io.BytesIO()
    transfer(API + '/repos/' + REPOSITORY + '/' + path, output, MAX_JSON)
    return parse_json(output.getvalue())


def release_identity(value, release, reference, commit, annotated=None):
    if type(release) is not dict or type(release.get('id')) is not int or release['id'] != value['release_id'] or release.get('tag_name') != value['tag'] or release.get('draft') is not False or release.get('immutable') is not True or release.get('prerelease') is not True:
        raise q.Stop('unqualified immutable SDK input release required')
    if reference.get('ref') != 'refs/tags/' + value['tag']:
        raise q.Stop('retained release tag differs')
    target = reference.get('object', {})
    if target.get('type') == 'tag':
        if type(annotated) is not dict or annotated.get('sha') != target.get('sha') or annotated.get('tag') != value['tag']:
            raise q.Stop('retained annotated tag differs')
        target = annotated.get('object', {})
    if target.get('type') != 'commit' or target.get('sha') != value['commit_sha'] or commit.get('sha') != value['commit_sha'] or commit.get('verification', {}).get('verified') is not True:
        raise q.Stop('retained release signed source differs')


def release_assets(source, rows):
    _, payload, _ = retained.authority(source)
    raw = retained.public_receipt_bytes(source)
    expected = {payload['asset_name']: dict(bytes=payload['archive_bytes'], sha256=payload['sha256']),
                retained.RECEIPT_NAME: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())}
    if type(rows) is not list or len(rows) != 2 or any(type(row) is not dict for row in rows) or {row.get('name') for row in rows} != set(expected):
        raise q.Stop('retained release asset closure differs')
    ids = set()
    for row in rows:
        pin = expected[row['name']]
        if type(row.get('id')) is not int or row['id'] <= 0 or row['id'] in ids or row.get('state') != 'uploaded' or type(row.get('size')) is not int or row['size'] != pin['bytes'] or row.get('digest') != 'sha256:' + pin['sha256'] or pin['bytes'] > MAX_ARCHIVE:
            raise q.Stop('retained release asset identity differs')
        ids.add(row['id'])
    return expected


def main(accounting=None):
    value = locator(ROOT)
    if accounting is None or not accounting.is_absolute() or accounting.resolve(strict=True) != accounting or accounting.is_symlink() or not 0 < accounting.stat().st_size <= 8192:
        raise q.Stop('current complete retained input observation required')
    observation = parse_json(accounting.read_bytes())
    if observation.get('read_only_accounting_preflight') != 'pass' or observation.get('retained_bootstrap_admitted') is not True or observation.get('source') != str(ROOT) or type(observation.get('observed_at')) not in (int, float) or not 0 <= time.time() - observation['observed_at'] <= 120:
        raise q.Stop('retained input observation is stale or unrelated')
    destination = ROOT / retained.INPUT_NAME
    if destination.exists() or destination.is_symlink():
        raise q.Stop('prior retained input staging requires reconciliation')
    available = os.statvfs(ROOT)
    # Keep the prior conservative reserve even though ZIPs are no longer used.
    if available.f_bavail * available.f_frsize < 13 * 2**30 + MAX_ARCHIVE + 225823773 or available.f_favail < 500000:
        raise q.Stop('retained input reserve unavailable')
    release = api('releases/' + str(value['release_id']))
    reference = api('git/ref/tags/' + value['tag'])
    target = reference.get('object', {})
    annotated = api('git/tags/' + target['sha']) if target.get('type') == 'tag' and re.fullmatch('[0-9a-f]{40}', str(target.get('sha'))) else None
    commit = api('git/commits/' + value['commit_sha'])
    release_identity(value, release, reference, commit, annotated)
    rows = api('releases/' + str(value['release_id']) + '/assets?per_page=3')
    expected = release_assets(ROOT, rows)
    destination.mkdir(mode=0o700)
    for row in rows:
        path = destination / row['name']; pin = expected[row['name']]
        with path.open('xb') as output:
            transfer(API + '/repos/' + REPOSITORY + '/releases/assets/' + str(row['id']), output, pin['bytes'], binary=True)
        retained.checked_file(path, pin['bytes'], pin['sha256'])
    retained.verify_inputs(ROOT, destination)
    # No retries/fallback. Partial staging stays visible and accounted.


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accounting', type=pathlib.Path, required=True)
    main(parser.parse_args().accounting)
