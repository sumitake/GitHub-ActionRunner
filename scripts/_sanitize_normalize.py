"""Shared IP + string normalizer for the public-source sanitizer (H3).

This module is deliberately self-contained (Python 3 stdlib only) and
side-effect free: every function is a pure function over strings/bytes. That
makes it golden-vector-testable in isolation, and importable unmodified by a
future runtime broker (`docs/superpowers/plans/2026-07-11-controller-runtime.md`)
so the CI scanner and the live network-policy broker classify addresses
identically. All subnet-membership decisions use ``ipaddress`` (mathematical
containment on parsed address objects) -- never string/prefix comparison.

Public API:
    nfkc(text)                    -- Unicode NFKC fold (obfuscation-resistant matching)
    nfc(text)                     -- Unicode NFC fold (canonicalization for hashing)
    parse_ipv4_literal(token)     -- alt-numeric-form-aware IPv4 parser (H3)
    parse_ip_literal(token)       -- IPv4 + IPv6 (mapped/scoped/compressed) parser (H3)
    classify_ip(ip)               -- deny-class name or "public" (H1, H3)
    iter_ip_candidates(text)      -- bounded regex-based candidate extraction
    unescape_layer(text)          -- one layer of \\u / \\x / HTML-entity / percent decode (H7, H12)
    decode_residual_layers(token) -- ordered bounded decode pipeline + fail-closed residual flag (H12, H19)
    looks_still_encoded(token)    -- true if a token still matches an encoded alphabet shape (H19)
    shannon_entropy(s)            -- bits/char entropy estimate (H7 generic high-entropy gate)
"""

from __future__ import annotations

import base64
import binascii
import html
import ipaddress
import math
import re
import unicodedata
from typing import Iterator, Optional, Union

IPAddr = Union["ipaddress.IPv4Address", "ipaddress.IPv6Address"]

# ---------------------------------------------------------------------------
# Unicode folding
# ---------------------------------------------------------------------------


def nfkc(text: str) -> str:
    """Compatibility-fold text so full-width/compat digits, homoglyph-adjacent
    compatibility characters, and other confusables collapse to their plain
    ASCII-ish equivalents before matching."""
    return unicodedata.normalize("NFKC", text)


def nfc(text: str) -> str:
    """Canonical-compose text. Used for allowlist-hash canonicalization (H14),
    which deliberately does NOT compatibility-fold (NFC preserves meaning;
    NFKC is a matching aid, not a hashing canonicalization)."""
    return unicodedata.normalize("NFC", text)


# Codepoints (not literal glyphs) so this module's own source stays free of
# the very control characters the sanitizer flags. Covers zero-width
# space/joiner/non-joiner/word-joiner/BOM, the LRE..RLO + LRM/RLM bidi
# embedding/override set, and the LRI/RLI/FSI/PDI isolates.
_BIDI_ZERO_WIDTH_CODEPOINTS = (
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
)
_BIDI_ZERO_WIDTH = dict.fromkeys(_BIDI_ZERO_WIDTH_CODEPOINTS)


def strip_bidi_and_zero_width(text: str) -> str:
    """Remove zero-width and bidi-override control characters so they cannot
    be used to visually or structurally split an otherwise-matching token."""
    return text.translate(_BIDI_ZERO_WIDTH)


# ---------------------------------------------------------------------------
# Deny-class table (mirrors config/examples/fleet.example.json blockedEgressClasses)
# ---------------------------------------------------------------------------

DENY_CLASSES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("loopback", ("127.0.0.0/8", "::1/128")),
    (
        "privateUniqueLocal",
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"),
    ),
    (
        "linkLocalMetadata",
        ("169.254.0.0/16", "fe80::/10", "169.254.169.254/32"),
    ),
    ("sharedCgnat", ("100.64.0.0/10",)),
    (
        "reservedDocumentationBenchmarking",
        (
            "0.0.0.0/8",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "198.18.0.0/15",
            "240.0.0.0/4",
            "::/128",
            "2001:db8::/32",
        ),
    ),
    (
        "multicastBroadcast",
        ("224.0.0.0/4", "255.255.255.255/32", "ff00::/8"),
    ),
)

_DENY_NETWORKS: list[tuple[str, "ipaddress._BaseNetwork"]] = [
    (name, ipaddress.ip_network(cidr, strict=False))
    for name, cidrs in DENY_CLASSES
    for cidr in cidrs
]


def classify_ip(ip: IPAddr) -> str:
    """Return the deny-class name an address belongs to, or "public" for any
    other global-unicast/other address. IPv4-mapped IPv6 addresses
    (``::ffff:a.b.c.d`` in ANY notation -- ipaddress stores the integer, not
    the source text, so hex-group and dotted-quad spellings classify
    identically) are classified against their embedded IPv4 form (H3)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    for name, net in _DENY_NETWORKS:
        if ip in net:
            return name
    return "public"


# ---------------------------------------------------------------------------
# IPv4 alt-numeric-form parsing (octal / hex / fewer-than-4-part / mixed)
# ---------------------------------------------------------------------------

_INT_TOKEN_RE = re.compile(r"\A(?:0[xX][0-9a-fA-F]+|0[0-7]+|0|[1-9][0-9]*)\Z")


def _parse_int_flexible(tok: str) -> Optional[int]:
    """Parse a single dotted-quad component honoring C/BSD ``inet_aton``
    numeric-base rules: ``0x`` -> hex, leading ``0`` -> octal, else decimal."""
    if not _INT_TOKEN_RE.match(tok):
        return None
    if tok[:2] in ("0x", "0X"):
        return int(tok, 16)
    if len(tok) > 1 and tok[0] == "0":
        return int(tok, 8)
    return int(tok, 10)


def parse_ipv4_literal(token: str) -> Optional["ipaddress.IPv4Address"]:
    """Parse an IPv4 literal, including ``inet_aton``-style alt-numeric and
    fewer-than-4-part shorthand forms:

    - 4-part: ``a.b.c.d``, each an 8-bit value (decimal/octal/hex).
    - 3-part: ``a.b.c``, ``c`` is a 16-bit value  (loopback-net dot-one form).
    - 2-part: ``a.b``,   ``b`` is a 24-bit value  (two-part loopback shorthand).
    - 1-part: ``a``,     the whole address as one 32-bit integer.

    Returns None (never raises) for anything that is not a valid literal.
    """
    token = token.strip()
    if not token:
        return None
    parts = token.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    ints = [_parse_int_flexible(p) for p in parts]
    if any(v is None for v in ints):
        return None
    n = len(ints)
    if n == 4:
        if any(v > 0xFF for v in ints):  # type: ignore[operator]
            return None
        value = (ints[0] << 24) | (ints[1] << 16) | (ints[2] << 8) | ints[3]  # type: ignore[operator]
    elif n == 3:
        if ints[0] > 0xFF or ints[1] > 0xFF or ints[2] > 0xFFFF:  # type: ignore[operator]
            return None
        value = (ints[0] << 24) | (ints[1] << 16) | ints[2]  # type: ignore[operator]
    elif n == 2:
        if ints[0] > 0xFF or ints[1] > 0xFFFFFF:  # type: ignore[operator]
            return None
        value = (ints[0] << 24) | ints[1]  # type: ignore[operator]
    else:  # n == 1
        if ints[0] > 0xFFFFFFFF:  # type: ignore[operator]
            return None
        value = ints[0]  # type: ignore[operator]
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def parse_ipv6_literal(token: str) -> Optional["ipaddress.IPv6Address"]:
    """Parse an IPv6 literal, handling brackets and percent-encoded scoped
    zone IDs (``%25eth0`` -> ``%eth0``); ``ipaddress`` natively supports
    scoped zones, IPv4-mapped/compat forms, and 6to4/Teredo embeds once the
    scope/brackets are normalized."""
    token = token.strip()
    if token.startswith("[") and "]" in token:
        token = token[1 : token.index("]")]
    token = token.replace("%25", "%")
    try:
        return ipaddress.IPv6Address(token)
    except ValueError:
        return None


def parse_ip_literal(token: str) -> Optional[IPAddr]:
    """Parse token as IPv4 (incl. alt-numeric forms) or IPv6 (incl. scoped /
    mapped forms). Returns None for anything unparsable."""
    token = strip_bidi_and_zero_width(nfkc(token)).strip()
    if not token:
        return None
    if ":" in token:
        return parse_ipv6_literal(token)
    return parse_ipv4_literal(token)


# ---------------------------------------------------------------------------
# Candidate extraction (regex over free text -> strings handed to the parsers
# above). Kept intentionally narrow for the *unconditional* 4-part dotted
# quad and IPv6 forms (they do not collide with ordinary prose/semver); the
# fewer-than-4-part/whole-integer shorthand forms are supported by the
# parser API above but are NOT extracted unconditionally from free text --
# see scripts/sanitize_public.py IP_CONTEXT_RE for why (semver collision).
# ---------------------------------------------------------------------------

_OCTET_DEC = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_OCTET_OCT = r"0[0-7]{1,3}"
_OCTET_HEX = r"0[xX][0-9a-fA-F]{1,2}"
_OCTET_ANY = rf"(?:{_OCTET_HEX}|{_OCTET_OCT}|{_OCTET_DEC})"

IPV4_DOTTED_QUAD_RE = re.compile(
    rf"(?<![\w.]){_OCTET_ANY}(?:\.{_OCTET_ANY}){{3}}(?![\w.])"
)

# Broad candidate: any run containing hex digits/colons/dots/brackets/percent
# with at least two colons. Deliberately over-inclusive; ipaddress.* is the
# real validator, so a non-IPv6 colon-run (e.g. "10:30:00") is rejected by
# the strict parser above, not by this regex.
IPV6_CANDIDATE_RE = re.compile(
    r"(?<![\w:])\[?[0-9A-Fa-f:%.]*:[0-9A-Fa-f:%.]*:[0-9A-Fa-f:%.]*\]?(?![\w:])"
)


def iter_ip_candidates(text: str) -> Iterator[tuple[int, int, str]]:
    """Yield (start, end, matched_text) for every dotted-quad or IPv6-shaped
    candidate substring in ``text`` (NFKC-folded first so full-width digits
    are found). Callers still MUST validate each candidate with
    ``parse_ip_literal`` -- this only narrows what is worth parsing."""
    folded = nfkc(text)
    seen: set[tuple[int, int]] = set()
    for m in IPV4_DOTTED_QUAD_RE.finditer(folded):
        seen.add((m.start(), m.end()))
        yield m.start(), m.end(), m.group(0)
    for m in IPV6_CANDIDATE_RE.finditer(folded):
        if (m.start(), m.end()) in seen:
            continue
        yield m.start(), m.end(), m.group(0)


# ---------------------------------------------------------------------------
# Decode pipeline (H7 unescape-before-match, H12 ordered decode + data URIs,
# H19 hex/base32/base64url + fail-closed residual)
# ---------------------------------------------------------------------------

_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_STRING_CONCAT_RE = re.compile(r'"([^"\\]*)"\s*\+\s*"([^"\\]*)"')


def unescape_layer(text: str) -> str:
    """Apply ONE layer of: HTML-entity decode, percent-decode, ``\\uXXXX`` /
    ``\\xXX`` escape decode. Safe to call repeatedly (idempotent on text with
    no more escapes left)."""
    out = html.unescape(text)
    out = _UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), out)
    out = _HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), out)
    # percent-decode only well-formed %XX runs, never touch a bare '%'
    if "%" in out:
        try:
            out2 = re.sub(
                r"(?:%[0-9a-fA-F]{2})+",
                lambda m: _percent_decode(m.group(0)),
                out,
            )
            out = out2
        except Exception:
            pass
    return out


def _percent_decode(run: str) -> str:
    raw = bytes(int(run[i + 1 : i + 3], 16) for i in range(0, len(run), 3))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def reassemble_string_concat(text: str) -> str:
    """Collapse adjacent quoted-string-literal concatenation
    (``"ghp_" + "abc123"`` -> ``"ghp_abc123"``) so a token split to dodge
    literal matching is still detected (H7)."""
    prev = None
    out = text
    # bounded iterations: a chain of N literals needs N-1 passes; cap at 8
    for _ in range(8):
        if out == prev:
            break
        prev = out
        out = _STRING_CONCAT_RE.sub(lambda m: '"' + m.group(1) + m.group(2) + '"', out)
    return out


_B64_ALPHABET = re.compile(r"\A[A-Za-z0-9+/]{16,}={0,2}\Z")
_B64URL_ALPHABET = re.compile(r"\A[A-Za-z0-9_-]{16,}={0,2}\Z")
_B32_ALPHABET = re.compile(r"\A[A-Z2-7]{16,}={0,6}\Z")
_HEX_ALPHABET = re.compile(r"\A(?:[0-9a-fA-F]{2}){8,}\Z")


def _try_decode_alphabet(token: str) -> Optional[str]:
    """Try, in priority order, hex / base32 / base64url / base64 decode of a
    single token, returning the FIRST successful decode (best-effort
    utf-8/latin-1) or None.

    Priority matters: the hex alphabet (``0-9a-f``) is a strict SUBSET of
    the base64 alphabet, so a pure-hex token would otherwise ambiguously
    match both -- checking hex first (the narrower, more specific alphabet)
    avoids mis-decoding a hex-encoded token as if it were base64.
    """

    def _decode(raw_bytes: bytes) -> Optional[str]:
        try:
            return raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return raw_bytes.decode("latin-1")
            except UnicodeDecodeError:
                return None

    if _HEX_ALPHABET.match(token):
        try:
            decoded = _decode(bytes.fromhex(token))
            if decoded is not None:
                return decoded
        except ValueError:
            pass
    if _B32_ALPHABET.match(token):
        pad = "=" * (-len(token) % 8)
        try:
            decoded = _decode(base64.b32decode(token + pad))
            if decoded is not None:
                return decoded
        except (binascii.Error, ValueError):
            pass
    if _B64URL_ALPHABET.match(token) and ("-" in token or "_" in token):
        pad = "=" * (-len(token) % 4)
        try:
            decoded = _decode(base64.urlsafe_b64decode(token + pad))
            if decoded is not None:
                return decoded
        except (binascii.Error, ValueError):
            pass
    if _B64_ALPHABET.match(token):
        pad = "=" * (-len(token) % 4)
        try:
            decoded = _decode(base64.b64decode(token + pad))
            if decoded is not None:
                return decoded
        except (binascii.Error, ValueError):
            pass
    return None


MAX_DECODE_LAYERS = 3


def decode_residual_layers(token: str) -> tuple[list[str], bool]:
    """Ordered bounded decode pipeline (H12/H19): entity -> percent ->
    unicode/hex-escape -> (base64 | base64url | base32 | hex) whole-token
    decode, repeated up to ``MAX_DECODE_LAYERS`` times.

    Returns ``(layers, still_encoded)`` where ``layers`` is every
    intermediate string produced (including the original) so callers can
    re-run detection rules against each one, and ``still_encoded`` is True
    when the budget was exhausted while the residual text still LOOKS like
    an undecoded encoded alphabet (long hex/base32/base64/base64url run) --
    the fail-closed signal for H19 ("stop just before plaintext" is a
    finding, not a pass).
    """
    layers = [token]
    current = token
    for _ in range(MAX_DECODE_LAYERS):
        unescaped = unescape_layer(current)
        decoded = _try_decode_alphabet(current.strip())
        nxt = decoded if decoded is not None else unescaped
        if nxt == current:
            break
        layers.append(nxt)
        current = nxt
    still_encoded = looks_still_encoded(current)
    return layers, still_encoded


def looks_still_encoded(token: str) -> bool:
    """True if ``token`` still matches a long, otherwise-unexplained encoded
    alphabet run (H19 residual fail-closed check)."""
    t = token.strip()
    if len(t) < 20:
        return False
    return bool(
        _B64_ALPHABET.match(t)
        or _B64URL_ALPHABET.match(t)
        or _B32_ALPHABET.match(t)
        or _HEX_ALPHABET.match(t)
    )


DATA_URI_RE = re.compile(
    r"data:[\w.+-]+/[\w.+-]+(?:;charset=[\w-]+)?;base64,([A-Za-z0-9+/]+=*)"
)


def iter_data_uri_payloads(text: str) -> Iterator[str]:
    """Yield decoded (best-effort text) payloads for every ``data:...;base64,``
    URI found in ``text`` (H12)."""
    for m in DATA_URI_RE.finditer(text):
        b64 = m.group(1)
        pad = "=" * (-len(b64) % 4)
        try:
            raw = base64.b64decode(b64 + pad)
        except (binascii.Error, ValueError):
            continue
        try:
            yield raw.decode("utf-8")
        except UnicodeDecodeError:
            yield raw.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# Entropy (H7 generic high-entropy gate, used only on already label-scoped
# candidate values -- see scripts/sanitize_public.py for why unscoped
# entropy scanning is not applied repo-wide)
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Bits-per-character Shannon entropy estimate of ``s``."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# Homoglyph / fullwidth path separator helpers (H12)
# ---------------------------------------------------------------------------

# Codepoints again (fullwidth solidus U+FF0F, fullwidth reverse solidus
# U+FF3C) so no literal fullwidth separator glyph appears in this source.
FULLWIDTH_SEPARATORS = tuple(chr(cp) for cp in (0xFF0F, 0xFF3C))


def contains_fullwidth_separator(text: str) -> bool:
    return any(ch in text for ch in FULLWIDTH_SEPARATORS)


# LRE/RLE/PDF/LRO/RLO bidi embedding+override codepoints, by number.
_BIDI_OVERRIDES = tuple(chr(cp) for cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E))


def contains_bidi_override(text: str) -> bool:
    return any(ch in text for ch in _BIDI_OVERRIDES)
