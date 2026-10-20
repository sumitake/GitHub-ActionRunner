"""Render only the fresh pinned producer's root report nonce deterministically."""
# SPDX-License-Identifier: MPL-2.0
import decimal
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile

LIMIT = 25 * 2**20
METHOD = 'trivy-root-report-id-byte-slices-v1'


class ReportError(ValueError):
    pass


def unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ReportError('duplicate native report key')
        result[key] = value
    return result


def nonfinite(_value):
    raise ReportError('nonfinite native report number')


def render(raw):
    """Preserve every byte outside the unique root ReportID value token."""
    if not 0 < len(raw) <= LIMIT:
        raise ReportError('native report size')
    text = raw.decode('utf-8', 'strict')
    decoder = json.JSONDecoder(object_pairs_hook=unique, parse_float=decimal.Decimal, parse_constant=nonfinite)
    value = decoder.decode(text)
    if (not isinstance(value, dict) or type(value.get('SchemaVersion')) is not int
            or value['SchemaVersion'] != 2 or value.get('Trivy') != {'Version': '0.72.0'}
            or not isinstance(value.get('ReportID'), str)
            or re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', value['ReportID']) is None
            or 'Metadata' in value and not isinstance(value['Metadata'], dict)
            or 'Results' in value and not isinstance(value['Results'], list)):
        raise ReportError('unrecognized pinned native report')
    def whitespace(position):
        while position < len(text) and text[position] in ' \t\r\n':
            position += 1
        return position
    position = whitespace(whitespace(0) + 1)
    span = None
    while text[position] != '}':
        key, position = decoder.raw_decode(text, position)
        position = whitespace(position)
        if text[position] != ':':
            raise ReportError('native object separator')
        start = whitespace(position + 1)
        _item, end = decoder.raw_decode(text, start)
        if key == 'ReportID':
            span = (len(text[:start].encode()), len(text[:end].encode()))
        position = whitespace(end)
        if text[position] == '}':
            break
        if text[position] != ',':
            raise ReportError('native member separator')
        position = whitespace(position + 1)
    if span is None:
        raise ReportError('missing root report ID token')
    start, end = span
    before, after = raw[:start], raw[end:]
    identity = hashlib.sha256(METHOD.encode() + b'\0' + len(before).to_bytes(8, 'big') + before + len(after).to_bytes(8, 'big') + after).hexdigest()
    encoded = before + json.dumps('sha256:' + identity).encode() + after
    return encoded, {'method': METHOD, 'native_sha256': hashlib.sha256(raw).hexdigest(), 'native_bytes': len(raw), 'native_ReportID_sha256': hashlib.sha256(value['ReportID'].encode()).hexdigest(), 'rendered_sha256': hashlib.sha256(encoded).hexdigest(), 'rendered_bytes': len(encoded)}


def stable_bytes(path, maximum):
    path = pathlib.Path(path)
    if path.resolve(strict=True) != path:
        raise ReportError('indirect capture path')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise ReportError('unsafe capture file')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
    if identity(before) != identity(after) or len(raw) != before.st_size:
        raise ReportError('changed capture file')
    return raw


def capture(executable, expected_sha256, private_root, destination, subject_seal, invoke):
    """The controlled caller supplies the actual joined invocation, never a receipt."""
    if re.fullmatch('[0-9a-f]{64}', expected_sha256) is None:
        raise ReportError('missing executable identity')
    def executable_identity():
        return hashlib.sha256(stable_bytes(executable, 256 * 2**20)).hexdigest()
    if executable_identity() != expected_sha256:
        raise ReportError('changed pinned executable')
    subject = subject_seal()
    private_root.mkdir(mode=0o700, exist_ok=True)
    if private_root.resolve(strict=True) != private_root or stat.S_IMODE(private_root.stat().st_mode) != 0o700:
        raise ReportError('unsafe private capture root')
    directory = pathlib.Path(tempfile.mkdtemp(prefix='capture-', dir=private_root))
    native = directory / 'native.json'
    code = invoke(native)
    if type(code) is not int or code not in (0, 1) or subject_seal() != subject or executable_identity() != expected_sha256:
        raise ReportError('native invocation or subject identity changed')
    raw = stable_bytes(native, LIMIT)
    rendered, receipt = render(raw)
    # Native bytes stay intact and charged until the task's ordinary cleanup.
    if stable_bytes(native, LIMIT) != raw:
        raise ReportError('native report changed during rendering')
    with destination.open('xb') as stream:
        stream.write(rendered)
    return code, {**receipt, 'producer_binary_sha256': expected_sha256}
