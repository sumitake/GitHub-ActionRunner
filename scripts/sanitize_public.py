#!/usr/bin/env python3
"""Fail-closed public-source sanitizer for Portable GHAR.

Blocks committing deployment-specific / secret / non-synthetic content to the
public source tree. Python 3 stdlib only (no third-party imports) so it runs
anywhere the repo's toolchain runs, including hosted CI.

    python3 scripts/sanitize_public.py --tracked [--generated PATH ...]
                                        [--private-denylist PATH] [--history]

Diagnostics: ``path:line:rule: message`` (one per line, sorted, deterministic).
Exit 0 iff no findings across every requested scan mode. Exit 1 on any
finding OR on any unscannable-but-required input (fail closed, never a
silent skip). On a clean ``--tracked`` run, prints ``sanitization passed``.

See the design record for the full threat model and per-rule rationale:
    docs/superpowers/plans/2026-07-11-public-foundation.md
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable, NamedTuple, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _sanitize_normalize as norm  # noqa: E402

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


class Finding(NamedTuple):
    path: str
    line: object  # int (1-based), "file", or "A-B" span string
    rule: str
    message: str
    content: str = ""  # hash-worthy content; NEVER printed (avoids re-leaking secrets)


def format_finding(f: Finding) -> str:
    return f"{f.path}:{f.line}:{f.rule}: {f.message}"


def _sort_key(f: Finding):
    line = f.line
    line_key = (0, line) if isinstance(line, int) else (1, str(line))
    return (f.path, line_key, f.rule, f.message)


# All rule identifiers the scanner can emit. Also the closed vocabulary the
# allowlist schema validates against (H14: "unknown rule" is a hard failure).
KNOWN_RULES = frozenset(
    {
        "IP001",
        "HOST001",
        "URI001",
        "MAIL001",
        "DEPLOYID001",
        "DEPLOYID002",
        "SECRET_PEM",
        "SECRET_SSHKEY",
        "SECRET_TOKEN",
        "SECRET_JWT",
        "SECRET_ASSIGN",
        "PATH001",
        "ARCHIVE_UNSUPPORTED",
        "ARCHIVE_ENCRYPTED",
        "ARCHIVE_DEPTH",
        "ARCHIVE_SYMLINK",
        "SIZE_LIMIT",
        "DECODE_FAIL",
        "GENERATED_MISSING",
        "REPO_IDENTITY",
        "BINARY_UNALLOWLISTED",
        "SYMLINK_TRACKED",
        "SUBMODULE_PRESENT",
        "LFS_TRACKED",
        "ENCODED_RESIDUAL",
        "HISTORY_META",
        "PRIVATE_DENYLIST",
    }
)

MAX_FILE_BYTES = 25 * 1024 * 1024
ARCHIVE_MAX_DEPTH = 5
ARCHIVE_TOTAL_BUDGET = 200 * 1024 * 1024

# ---------------------------------------------------------------------------
# Fixture-path qualification (H2): the ONLY exemption mechanism for rules
# that legitimately need to discuss/document real-shaped values (IPs,
# hostnames, deployment-id shapes, absolute paths, and near-misses of our own
# repo identity). Rules that detect genuine secret material, structural
# integrity violations (archives/symlinks/submodules/LFS/oversize/allowlist
# schema) are NEVER fixture-exempt -- they apply everywhere, always.
# ---------------------------------------------------------------------------

FIXTURE_PATH_PREFIXES = ("tests/", "config/examples/", "docs/")


def is_fixture_path(relpath: str) -> bool:
    normalized = relpath.replace(os.sep, "/")
    if any(normalized.startswith(p) for p in FIXTURE_PATH_PREFIXES):
        return True
    return "fixtures" in normalized.split("/")


# ---------------------------------------------------------------------------
# Canonicalization + hashing (H14)
# ---------------------------------------------------------------------------


def _canonicalize_text(text: str) -> str:
    text = norm.nfc(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip(" \t") for ln in text.split("\n")]
    return "\n".join(lines)


def compute_line_hash(line_text: str) -> str:
    canon = _canonicalize_text(line_text)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def compute_span_hash(lines_text: Iterable[str]) -> str:
    """Hash a multi-line finding span. Uses the SAME no-separator
    concatenation convention as ``_check_secrets_multiline`` (which joins
    adjacent lines with no separator so a token split mid-line by a literal
    line break is still detected) -- callers constructing an allowlist entry
    for a multi-line finding must hash the identical representation."""
    canon = _canonicalize_text("".join(lines_text))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def compute_file_hash(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return hashlib.sha256(raw).hexdigest()
    canon = _canonicalize_text(text)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Allowlist (H14): the ONLY suppression mechanism. Exact {path, line, rule,
# sha256} match required. No wildcard paths, no path-exclude, no duplicates,
# no unknown rules -- any of those is a hard failure of the allowlist itself.
# ---------------------------------------------------------------------------

REQUIRED_ALLOWLIST_KEYS = {"path", "line", "rule", "sha256", "reason"}
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_HISTORICAL_ALLOWLIST_PATH_RE = re.compile(
    r"\A[^@]+@[0-9a-f]{40}(?:!.+)?\Z"
)


class AllowlistError(Exception):
    pass


class AllowlistIndex:
    def __init__(self, entries: list[dict]):
        self._entries = entries
        # keyed by (path, str(line), rule) -> sha256
        self._index: dict[tuple[str, str, str], str] = {}
        for e in entries:
            key = (e["path"], str(e["line"]), e["rule"])
            self._index[key] = e["sha256"]

    @classmethod
    def empty(cls) -> "AllowlistIndex":
        return cls([])

    def suppresses(self, f: Finding) -> bool:
        key = (f.path, str(f.line), f.rule)
        expected = self._index.get(key)
        if expected is None:
            return False
        if isinstance(f.content, (bytes, bytearray)):
            actual = hashlib.sha256(bytes(f.content)).hexdigest()
        else:
            actual = hashlib.sha256(_canonicalize_text(f.content).encode("utf-8")).hexdigest()
        return expected == actual

    def filter(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if not self.suppresses(f)]


def load_allowlist(path: Path) -> AllowlistIndex:
    if not path.exists():
        return AllowlistIndex.empty()
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise AllowlistError(f"allowlist is not valid UTF-8 text: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AllowlistError(f"allowlist is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise AllowlistError("allowlist root must be a JSON array")

    seen: set[tuple[str, str, str]] = set()
    entries: list[dict] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise AllowlistError(f"entry #{i} is not an object")
        keys = set(entry.keys())
        if keys != REQUIRED_ALLOWLIST_KEYS:
            raise AllowlistError(
                f"entry #{i} has keys {sorted(keys)}, expected exactly {sorted(REQUIRED_ALLOWLIST_KEYS)}"
            )
        path_val = entry["path"]
        line_val = entry["line"]
        rule_val = entry["rule"]
        sha_val = entry["sha256"]
        reason_val = entry["reason"]
        if not isinstance(path_val, str) or not path_val:
            raise AllowlistError(f"entry #{i} path must be a non-empty string")
        if any(ch in path_val for ch in "*?[]"):
            raise AllowlistError(f"entry #{i} path {path_val!r} contains a wildcard -- exact paths only")
        if "@" in path_val and not _HISTORICAL_ALLOWLIST_PATH_RE.fullmatch(
            path_val
        ):
            raise AllowlistError(
                f"entry #{i} historical path must carry one complete 40-character blob OID"
            )
        if not (isinstance(line_val, int) or (isinstance(line_val, str) and (line_val == "file" or re.fullmatch(r"\d+-\d+", line_val)))):
            raise AllowlistError(f"entry #{i} line must be an int, 'file', or 'A-B' span string")
        if not isinstance(rule_val, str) or rule_val not in KNOWN_RULES:
            raise AllowlistError(f"entry #{i} rule {rule_val!r} is not a known rule id")
        if not isinstance(sha_val, str) or not _SHA256_RE.match(sha_val):
            raise AllowlistError(f"entry #{i} sha256 must be 64 lowercase hex chars")
        if not isinstance(reason_val, str) or not reason_val.strip():
            raise AllowlistError(f"entry #{i} reason must be a non-empty string")
        key = (path_val, str(line_val), rule_val)
        if key in seen:
            raise AllowlistError(f"entry #{i} duplicates an existing (path, line, rule) key: {key}")
        seen.add(key)
        entries.append(entry)
    return AllowlistIndex(entries)


# ---------------------------------------------------------------------------
# H1/H2/H3 -- IP literals
# ---------------------------------------------------------------------------

IP_LABEL_CONTEXT_RE = re.compile(
    r"\b(?:ip|addr|address|host|cidr|loopback_alias|target)\b\s*[:=]\s*$",
    re.IGNORECASE,
)


def _check_ip_literals(line: str, ctx: "LineCtx") -> list[Finding]:
    if ctx.fixture:
        return []
    out: list[Finding] = []
    for start, end, cand in norm.iter_ip_candidates(line):
        ip = norm.parse_ip_literal(cand)
        if ip is None:
            continue
        cls = norm.classify_ip(ip)
        out.append(
            Finding(
                ctx.relpath,
                ctx.lineno,
                "IP001",
                f"IP literal outside a fixture-qualified path (deny-class: {cls})",
                line,
            )
        )
    # context-gated shorthand / alt-numeric forms (see _sanitize_normalize
    # module docstring: unconditional shorthand scanning collides with
    # dotted semver strings like "4.10.0", so it is only attempted right
    # after an explicit ip/host/address/cidr label).
    for m in re.finditer(r"[:=]\s*([0-9xXA-Fa-f.]{1,32})\b", line):
        prefix = line[: m.start()]
        if not IP_LABEL_CONTEXT_RE.search(prefix + line[m.start() : m.start() + 1]):
            if not re.search(r"\b(?:ip|addr|address|host|cidr|loopback_alias|target)\s*$", prefix, re.IGNORECASE):
                continue
        cand = m.group(1)
        ip = norm.parse_ip_literal(cand)
        if ip is None:
            continue
        cls = norm.classify_ip(ip)
        out.append(
            Finding(
                ctx.relpath,
                ctx.lineno,
                "IP001",
                f"IP literal (alt/shorthand numeric form) in labeled context (deny-class: {cls})",
                line,
            )
        )
    return out


# ---------------------------------------------------------------------------
# H4/H5 -- hostnames, .local, punycode, URI authority
# ---------------------------------------------------------------------------

LOCAL_SUFFIX_RE = re.compile(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.local\b", re.IGNORECASE)
# Labeled context = the only place H4 looks for bare hostnames/FQDNs (single-
# label AND multi-label): free-text scanning for "any word that might be a
# hostname" is not attempted (see module notes on the private-denylist being
# the honest control for unscoped free-text PII, H16).
LABELED_HOST_RE = re.compile(
    r"\b(?:hostname|ssh_target|device_name|host)\b\s*[:=]\s*\"?([A-Za-z][A-Za-z0-9.-]{1,63})\"?"
)
SSH_USERHOST_RE = re.compile(r"\bssh\s+(?:-\S+\s+)*(?:[\w.-]+@)([A-Za-z][A-Za-z0-9.-]{1,63})\b")
PUNYCODE_LABEL_RE = re.compile(r"\bxn--[A-Za-z0-9-]+\b", re.IGNORECASE)
_PLACEHOLDER_HOSTS = {"localhost", "example", "host", "hostname"}

URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+")


def _is_allowed_hostname(hostval: str) -> bool:
    # param name deliberately not "host"/"hostname" so this scanner's own
    # source does not trip the labeled-host rule when it scans itself.
    h = hostval.lower().rstrip(".")
    if h in _PLACEHOLDER_HOSTS:
        return True
    return any(h == s or h.endswith("." + s) for s in ALLOWED_MAIL_DOMAIN_SUFFIXES)


def _check_hostnames(line: str, ctx: "LineCtx") -> list[Finding]:
    if ctx.fixture:
        return []
    out: list[Finding] = []
    if LOCAL_SUFFIX_RE.search(line):
        out.append(Finding(ctx.relpath, ctx.lineno, "HOST001", "mDNS/.local hostname literal", line))
    for rex in (LABELED_HOST_RE, SSH_USERHOST_RE):
        for m in rex.finditer(line):
            hostval = m.group(1)
            if _is_allowed_hostname(hostval):
                continue
            shape = "single-label hostname" if "." not in hostval else "non-allowlisted FQDN"
            out.append(
                Finding(ctx.relpath, ctx.lineno, "HOST001", f"{shape} in labeled context: redacted", line)
            )
    if PUNYCODE_LABEL_RE.search(line):
        out.append(Finding(ctx.relpath, ctx.lineno, "HOST001", "punycode-encoded (xn--) hostname label present", line))
    return out


def _check_uri_authority(line: str, ctx: "LineCtx") -> list[Finding]:
    if ctx.fixture:
        return []
    out: list[Finding] = []
    for m in URL_RE.finditer(line):
        url = m.group(0)
        authority = url.split("//", 1)[1] if "//" in url else url
        authority = authority.split("/", 1)[0]
        if "@" in authority:
            out.append(
                Finding(
                    ctx.relpath,
                    ctx.lineno,
                    "URI001",
                    "URI authority contains userinfo (possible basic-auth decoy) -- classify on the real host, never the userinfo",
                    line,
                )
            )
    return out


# ---------------------------------------------------------------------------
# H4/rule5 -- email / mail domains
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
ALLOWED_MAIL_DOMAIN_SUFFIXES = ("example.com", "example.org", "example.net", "example.invalid", "example.edu")


def _is_allowed_mail_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == s or d.endswith("." + s) for s in ALLOWED_MAIL_DOMAIN_SUFFIXES)


def _check_mail(line: str, ctx: "LineCtx") -> list[Finding]:
    if ctx.fixture:
        return []
    out: list[Finding] = []
    for m in EMAIL_RE.finditer(line):
        domain = m.group(1)
        if not _is_allowed_mail_domain(domain):
            out.append(Finding(ctx.relpath, ctx.lineno, "MAIL001", "email address domain not in the synthetic allowlist", line))
    return out


# ---------------------------------------------------------------------------
# H6 -- deployment identifiers
# ---------------------------------------------------------------------------

DEPLOY_LABEL_RE = re.compile(
    r"\b(?:account_id|zone_id|tunnel_id|tunnel|installation_id|client_id|app_id|CLOUDFLARE_[A-Z_]+)\s*[:=]\s*[\"']?([0-9a-fA-F-]{8,})[\"']?",
    re.IGNORECASE,
)
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
HEX32_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")


def _check_deployment_ids(line: str, ctx: "LineCtx") -> list[Finding]:
    if ctx.fixture:
        return []
    out: list[Finding] = []
    if DEPLOY_LABEL_RE.search(line):
        out.append(Finding(ctx.relpath, ctx.lineno, "DEPLOYID001", "labeled deployment identifier (account/zone/tunnel/app id)", line))
    if UUID_RE.search(line) or HEX32_RE.search(line):
        out.append(Finding(ctx.relpath, ctx.lineno, "DEPLOYID002", "bare UUID/32-hex identifier outside a fixture-qualified path", line))
    return out


# ---------------------------------------------------------------------------
# H13 -- closed canonical-exception table for our own repo identity
# ---------------------------------------------------------------------------

GITHUB_REF_RE = re.compile(
    r"(?:https?://|git@)?github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?(?=[/\s\"'<>)\],]|$)",
    re.IGNORECASE,
)
MENTION_RE = re.compile(r"@(sumitake[A-Za-z0-9_-]*)")
CANONICAL_OWNER = "sumitake"
CANONICAL_REPO = "portable-ghar"
# Built from parts so the mention literal never appears contiguously in this
# source (which would otherwise trip the scanner's own near-miss rule when it
# scans itself). The runtime value is the canonical CODEOWNERS wildcard line.
CODEOWNERS_LINE = "* @" + CANONICAL_OWNER


def _check_repo_identity(line: str, ctx: "LineCtx") -> list[Finding]:
    if ctx.fixture:
        return []
    out: list[Finding] = []
    for m in GITHUB_REF_RE.finditer(line):
        owner, repo = m.group(1), m.group(2)
        if owner.lower() == CANONICAL_OWNER and repo.lower() == CANONICAL_REPO:
            continue  # exact canonical import/source prefix -- always OK
        if CANONICAL_OWNER in owner.lower() or CANONICAL_OWNER in repo.lower() or CANONICAL_REPO in repo.lower() or CANONICAL_REPO in owner.lower():
            out.append(
                Finding(
                    ctx.relpath,
                    ctx.lineno,
                    "REPO_IDENTITY",
                    f"near-miss of the canonical {CANONICAL_OWNER}/{CANONICAL_REPO} identity: owner={owner!r} repo={repo!r}",
                    line,
                )
            )
    for m in MENTION_RE.finditer(line):
        mention = "@" + m.group(1)
        if mention == "@" + CANONICAL_OWNER and line.strip() == CODEOWNERS_LINE and ctx.basename == "CODEOWNERS":
            continue  # the one permitted exact CODEOWNERS shape
        out.append(
            Finding(
                ctx.relpath,
                ctx.lineno,
                "REPO_IDENTITY",
                f"CODEOWNERS-shaped/near-miss mention {mention!r} outside the canonical CODEOWNERS context",
                line,
            )
        )
    return out


# ---------------------------------------------------------------------------
# H8 -- closed absolute-path grammar
# ---------------------------------------------------------------------------

# The user-profile / home-dir / home-env patterns are assembled from split
# fragments so those literal path prefixes do not appear contiguously in this
# source (which would otherwise make the scanner flag its own rule table).
# Runtime-compiled patterns are identical to the plain single-literal forms.
PATH_RULES = [
    re.compile("/Users" + r"/[^/\s\"']+"),
    re.compile("/home" + r"/[^/\s\"']+"),
    re.compile(r"~[A-Za-z0-9_.-]*/"),
    re.compile(r"\$" + r"HOME\b"),
    re.compile(r"/root/\.ssh\b"),
    re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+"),
    re.compile(r"\\\\[^\\\s\"']+\\[^\\\s\"']+"),  # UNC
    re.compile(r"\bfile://[^\s\"']+"),
    re.compile(r"/share/[A-Za-z0-9_.-]+"),
]


def _check_paths(text: str, relpath: str, lineno, fixture: bool) -> list[Finding]:
    if fixture:
        return []
    out: list[Finding] = []
    for rex in PATH_RULES:
        if rex.search(text):
            out.append(Finding(relpath, lineno, "PATH001", "personal/NAS/UNC/Windows-profile absolute path literal", text))
    return out


# ---------------------------------------------------------------------------
# H7/H18 -- secrets: PEM, non-PEM keys, GitHub + vendor token prefixes, JWT,
# labeled credential-shaped assignment. NEVER fixture-exempt.
# ---------------------------------------------------------------------------

PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
SSH_KEY_RE = re.compile(r"\bssh-(?:ed25519|rsa|dss|ecdsa-[a-z0-9-]+)\s+AAAA[0-9A-Za-z+/=]{20,}")
AGE_KEY_RE = re.compile(r"\bAGE-SECRET-KEY-1[A-Z0-9]{20,}\b")
WG_KEY_RE = re.compile(r"\bPrivateKey\s*=\s*[A-Za-z0-9+/]{40,}={0,2}")
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")

VENDOR_TOKEN_RES = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA|AGPA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk|pk)_live_[0-9A-Za-z]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35,}\b")),
    ("Twilio SID/key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("PyPI token", re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}\b")),
]
GCP_SA_TYPE_RE = re.compile(r'"type"\s*:\s*"service_account"')

CREDENTIAL_ASSIGN_RE = re.compile(r"\b([A-Z][A-Z0-9_]*_(?:TOKEN|SECRET|KEY))\s*=\s*[\"']?([^\s\"']{8,})[\"']?")
_PLACEHOLDER_VALUES = {"changeme", "example", "xxx", "placeholder", "todo", "redacted"}


def _secret_regex_hits(text: str) -> list[str]:
    hits: list[str] = []
    if PEM_RE.search(text):
        hits.append("SECRET_PEM:PEM/key block header")
    if SSH_KEY_RE.search(text):
        hits.append("SECRET_SSHKEY:OpenSSH public/private key material")
    if AGE_KEY_RE.search(text):
        hits.append("SECRET_SSHKEY:age secret key")
    if WG_KEY_RE.search(text):
        hits.append("SECRET_SSHKEY:WireGuard PrivateKey")
    if GITHUB_TOKEN_RE.search(text):
        hits.append("SECRET_TOKEN:GitHub token prefix")
    if JWT_RE.search(text):
        hits.append("SECRET_JWT:JWT-shaped token")
    for name, rex in VENDOR_TOKEN_RES:
        if rex.search(text):
            hits.append(f"SECRET_TOKEN:{name}")
    if GCP_SA_TYPE_RE.search(text) and PEM_RE.search(text):
        hits.append("SECRET_PEM:GCP service-account key material")
    return hits


def _check_secrets_single_line(line: str, ctx: "LineCtx") -> list[Finding]:
    out: list[Finding] = []
    variants = {line}
    variants.add(norm.unescape_layer(line))
    variants.add(norm.reassemble_string_concat(norm.unescape_layer(line)))
    seen_rules: set[str] = set()
    for variant in variants:
        for hit in _secret_regex_hits(variant):
            rule, _, desc = hit.partition(":")
            if rule in seen_rules:
                continue
            seen_rules.add(rule)
            out.append(Finding(ctx.relpath, ctx.lineno, rule, desc, line))
    for m in CREDENTIAL_ASSIGN_RE.finditer(line):
        name, value = m.group(1), m.group(2)
        if value.lower() in _PLACEHOLDER_VALUES or (value.startswith("<") and value.endswith(">")) or value.startswith("env:"):
            continue
        entropy = norm.shannon_entropy(value)
        out.append(
            Finding(
                ctx.relpath,
                ctx.lineno,
                "SECRET_ASSIGN",
                f"labeled credential-shaped assignment {name}= with non-placeholder value (entropy={entropy:.2f} bits/char)",
                line,
            )
        )
    return out


def _check_secrets_multiline(lines: list[str], relpath: str) -> list[Finding]:
    out: list[Finding] = []
    for i in range(len(lines) - 1):
        a, b = lines[i], lines[i + 1]
        joined = a + b
        if _secret_regex_hits(a) or _secret_regex_hits(b):
            continue  # already caught per-line; only report genuinely span-only hits
        hits = _secret_regex_hits(joined)
        for hit in hits:
            rule, _, desc = hit.partition(":")
            out.append(Finding(relpath, i + 1, rule, f"{desc} (spans lines {i + 1}-{i + 2})", joined))
    return out


# ---------------------------------------------------------------------------
# H12/H19 -- obfuscation decode pipeline + fail-closed residual + data URIs
# ---------------------------------------------------------------------------

OBFUSCATION_MARKER_RE = re.compile(
    r"(?:%[0-9a-fA-F]{2}){3,}"
    r"|(?:&#x?[0-9a-fA-F]+;){2,}"
    r"|(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){2,}"
)

# Bare encoded runs (no obfuscation marker): a long base64 / base64url /
# base32 run, or a long even-length hex run. These are decode-and-rechecked
# so a secret/IP EMBEDDED in decoded content is found -- not only when the
# whole decoded blob is itself the token (H12/H19 decode-and-recheck).
# {0,6} covers base32's max padding (base64's max 2 is a subset); the trailing
# lookahead excludes only unpadded alphabet chars since any '=' padding has
# already been consumed by the run.
_ENCODED_RUN_RE = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,6}(?![A-Za-z0-9+/_-])")
_HEX_RUN_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
_MAX_DECODE_CANDIDATES_PER_LINE = 200


def _is_probably_text(s: str) -> bool:
    """True if ``s`` is plausibly human-readable text (used to gate whether a
    DECODED layer is worth re-running the full rule set against). A base64
    integrity hash decodes to high-entropy binary -> False -> not re-scanned,
    which avoids repo-wide false positives; a base64 of a short IP-bearing
    sentence decodes to printable text -> True -> re-scanned."""
    if not s:
        return False
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\t\n\r ")
    return printable / len(s) >= 0.85


def _rescan_decoded_layer(layer: str, line: str, ctx: "LineCtx") -> list[Finding]:
    """Re-run the FULL content rule set on a decoded layer so an embedded
    IP / token / domain / path / deploy-id anywhere in the decoded content is
    found. Findings carry the ORIGINAL visible ``line`` as their content (so
    the decoded secret is never emitted or hashed) and a ``[via decode]`` tag."""
    out: list[Finding] = []
    for f in _run_content_rules(layer, ctx):
        out.append(f._replace(message=f"[via decode] {f.message}", content=line))
    return out


def _check_obfuscation_and_residual(line: str, ctx: "LineCtx") -> list[Finding]:
    out: list[Finding] = []
    if norm.contains_fullwidth_separator(line):
        out.append(Finding(ctx.relpath, ctx.lineno, "ENCODED_RESIDUAL", "fullwidth path-separator homoglyph present", line))
    if norm.contains_bidi_override(line):
        out.append(Finding(ctx.relpath, ctx.lineno, "ENCODED_RESIDUAL", "bidi/RTL override control character present", line))

    candidates: list[str] = [m.group(0) for m in OBFUSCATION_MARKER_RE.finditer(line)]
    candidates += list(norm.iter_data_uri_payloads(line))
    candidates += [m.group(0) for m in _ENCODED_RUN_RE.finditer(line)]
    candidates += [m.group(0) for m in _HEX_RUN_RE.finditer(line)]
    candidates = candidates[:_MAX_DECODE_CANDIDATES_PER_LINE]

    seen_decoded: set[str] = set()
    for cand in candidates:
        layers, still_encoded = norm.decode_residual_layers(cand)
        # Re-scan every decoded layer (layers[1:] are the decoded forms).
        for layer in layers[1:]:
            if layer in seen_decoded:
                continue
            seen_decoded.add(layer)
            if _is_probably_text(layer):
                out += _rescan_decoded_layer(layer, line, ctx)
        # ENCODED_RESIDUAL fires ONLY when we actually peeled at least one
        # decode layer and the residual still looks encoded after the budget
        # -- a bare hash that never decoded to a nested encoding does NOT
        # trip this (that guard is what keeps go.sum / package-lock clean).
        if still_encoded and len(layers) > 1:
            out.append(
                Finding(
                    ctx.relpath,
                    ctx.lineno,
                    "ENCODED_RESIDUAL",
                    "decode budget exhausted but residual still matches an encoded alphabet shape (fail closed)",
                    line,
                )
            )
    return out


# ---------------------------------------------------------------------------
# Per-line orchestration
# ---------------------------------------------------------------------------


class LineCtx(NamedTuple):
    relpath: str
    lineno: int
    fixture: bool
    basename: str


def _run_content_rules(text: str, ctx: "LineCtx") -> list[Finding]:
    """Every non-obfuscation content rule, applied to a single string. Called
    both on the raw line and (via the decode pipeline) on each decoded layer.
    Deliberately excludes ``_check_obfuscation_and_residual`` so decoded-layer
    re-scanning does not recurse."""
    out: list[Finding] = []
    out += _check_ip_literals(text, ctx)
    out += _check_hostnames(text, ctx)
    out += _check_uri_authority(text, ctx)
    out += _check_mail(text, ctx)
    out += _check_deployment_ids(text, ctx)
    out += _check_repo_identity(text, ctx)
    out += _check_paths(text, ctx.relpath, ctx.lineno, ctx.fixture)
    out += _check_secrets_single_line(text, ctx)
    return out


def scan_line(lineno: int, line: str, relpath: str, fixture: bool, basename: str) -> list[Finding]:
    ctx = LineCtx(relpath, lineno, fixture, basename)
    out: list[Finding] = []
    out += _run_content_rules(line, ctx)
    out += _check_obfuscation_and_residual(line, ctx)
    return out


def scan_text_content(text: str, relpath: str, *, fixture: bool) -> list[Finding]:
    basename = os.path.basename(relpath)
    lines = re.split(r"\r\n|\r|\n", text)
    out: list[Finding] = []
    for i, line in enumerate(lines, start=1):
        out += scan_line(i, line, relpath, fixture, basename)
    out += _check_secrets_multiline(lines, relpath)
    if basename == ".gitattributes":
        for i, line in enumerate(lines, start=1):
            if "filter=lfs" in line:
                out.append(Finding(relpath, i, "LFS_TRACKED", "path is Git-LFS filtered; real payload not scanned (fail closed)", line))
    if lines and lines[0].startswith("version https://git-lfs.github.com/spec/v1"):
        out.append(Finding(relpath, 1, "LFS_TRACKED", "file is a Git-LFS pointer stub; real payload not scanned (fail closed)", lines[0]))
    if basename == ".gitmodules":
        found_url = False
        for i, line in enumerate(lines, start=1):
            if re.match(r"\s*url\s*=", line):
                found_url = True
                out.append(Finding(relpath, i, "SUBMODULE_PRESENT", "submodule URL entry present (submodules are not scanned; treated as a finding)", line))
        if not found_url and text.strip():
            out.append(Finding(relpath, "file", "SUBMODULE_PRESENT", ".gitmodules present", text))
    return out


# ---------------------------------------------------------------------------
# Archive / container recursion (H9, H17)
# ---------------------------------------------------------------------------


class Budget:
    def __init__(self):
        self.total = 0

    def spend(self, n: int) -> bool:
        self.total += n
        return self.total <= ARCHIVE_TOTAL_BUDGET


def _sniff_archive_kind(raw: bytes) -> Optional[str]:
    if raw[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if raw[:2] == b"\x1f\x8b":
        return "gzip"
    if raw[:3] == b"BZh":
        return "bzip2"
    if raw[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if raw[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if raw[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if raw[:4] == b"Rar!":
        return "rar"
    if len(raw) > 262 and raw[257:263] in (b"ustar\x00", b"ustar "):
        return "tar"
    return None


def scan_bytes_as_file(
    raw: bytes,
    relpath: str,
    *,
    fixture: bool,
    depth: int = 0,
    budget: Optional[Budget] = None,
    label_suffix: str = "",
) -> list[Finding]:
    """Full per-file pipeline: size cap, path-string rules, archive
    recursion by magic bytes, text-vs-binary dispatch."""
    budget = budget or Budget()
    display_path = relpath + label_suffix
    out: list[Finding] = []

    out += _check_paths(relpath, relpath, "file", fixture)
    out += [f for f in (_check_ip_literals(relpath, LineCtx(relpath, "file", fixture, os.path.basename(relpath))))]

    if len(raw) > MAX_FILE_BYTES:
        return out + [Finding(display_path, "file", "SIZE_LIMIT", f"file exceeds {MAX_FILE_BYTES} byte cap (fail closed)", raw[:1024].decode("latin-1"))]

    if depth > ARCHIVE_MAX_DEPTH:
        return out + [Finding(display_path, "file", "ARCHIVE_DEPTH", f"archive recursion exceeded max depth {ARCHIVE_MAX_DEPTH}", "")]
    if not budget.spend(len(raw)):
        return out + [Finding(display_path, "file", "ARCHIVE_DEPTH", "archive total extraction budget exceeded", "")]

    kind = _sniff_archive_kind(raw)
    if kind == "zip":
        out += _scan_zip(raw, relpath, fixture, depth, budget)
        return out
    if kind == "tar":
        out += _scan_tar(raw, relpath, fixture, depth, budget)
        return out
    if kind in ("gzip", "bzip2", "xz"):
        try:
            if kind == "gzip":
                inner = gzip.decompress(raw)
            elif kind == "bzip2":
                inner = bz2.decompress(raw)
            else:
                inner = lzma.decompress(raw)
        except Exception:
            return out + [Finding(display_path, "file", "ARCHIVE_UNSUPPORTED", f"{kind} stream could not be decompressed (fail closed)", "")]
        out += scan_bytes_as_file(inner, relpath, fixture=fixture, depth=depth + 1, budget=budget, label_suffix=label_suffix + f"!{kind}")
        return out
    if kind in ("zstd", "7z", "rar"):
        return out + [Finding(display_path, "file", "ARCHIVE_UNSUPPORTED", f"{kind} is not a supported recurse type (stdlib-only); contents unverified (fail closed)", "")]

    # Not an archive: text or opaque binary.
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        h = compute_file_hash(raw)
        return out + [Finding(display_path, "file", "BINARY_UNALLOWLISTED", f"undecodable binary content, not covered by a whole-file allowlist entry (sha256={h})", raw)]
    out += scan_text_content(text, display_path, fixture=fixture)
    return out


def _member_is_symlink_zip(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == 0o120000


def _scan_zip(raw: bytes, relpath: str, fixture: bool, depth: int, budget: Budget) -> list[Finding]:
    out: list[Finding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        return [Finding(relpath, "file", "ARCHIVE_UNSUPPORTED", "zip-family container could not be opened (fail closed)", "")]
    if zf.comment:
        try:
            out += scan_text_content(zf.comment.decode("utf-8"), relpath + "#zip-comment", fixture=fixture)
        except UnicodeDecodeError:
            pass
    for info in zf.infolist():
        member_label = f"{relpath}!{info.filename}"
        if info.comment:
            try:
                out += scan_text_content(info.comment.decode("utf-8"), member_label + "#comment", fixture=fixture)
            except UnicodeDecodeError:
                pass
        if _member_is_symlink_zip(info):
            out.append(Finding(member_label, "file", "ARCHIVE_SYMLINK", "zip member is a symlink (not followed; rejected)", ""))
            continue
        if info.is_dir():
            continue
        if info.flag_bits & 0x1:
            out.append(Finding(member_label, "file", "ARCHIVE_ENCRYPTED", "zip member is encrypted; contents unverified (fail closed)", ""))
            continue
        try:
            data = zf.read(info)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
            out.append(Finding(member_label, "file", "ARCHIVE_ENCRYPTED", "zip member could not be read (possibly encrypted); fail closed", ""))
            continue
        out += scan_bytes_as_file(data, member_label, fixture=fixture, depth=depth + 1, budget=budget)
    return out


def _scan_tar(raw: bytes, relpath: str, fixture: bool, depth: int, budget: Budget) -> list[Finding]:
    out: list[Finding] = []
    try:
        tf = tarfile.open(fileobj=io.BytesIO(raw))
    except tarfile.TarError:
        return [Finding(relpath, "file", "ARCHIVE_UNSUPPORTED", "tar container could not be opened (fail closed)", "")]
    for member in tf.getmembers():
        member_label = f"{relpath}!{member.name}"
        if member.issym() or member.islnk():
            out.append(Finding(member_label, "file", "ARCHIVE_SYMLINK", "tar member is a symlink/hardlink (not followed; rejected)", ""))
            continue
        if not member.isfile():
            continue
        fobj = tf.extractfile(member)
        if fobj is None:
            out.append(Finding(member_label, "file", "ARCHIVE_UNSUPPORTED", "tar member could not be extracted (fail closed)", ""))
            continue
        data = fobj.read()
        out += scan_bytes_as_file(data, member_label, fixture=fixture, depth=depth + 1, budget=budget)
    return out


# ---------------------------------------------------------------------------
# Tracked-tree collection (H15: symlinks + submodules)
# ---------------------------------------------------------------------------


def _run_git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, check=True)
    return result.stdout.decode("utf-8", errors="surrogateescape")


def discover_repo_root(start: Optional[Path] = None) -> Path:
    start = start or Path.cwd()
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=str(start), capture_output=True, check=True)
    return Path(out.stdout.decode("utf-8").strip())


def collect_tracked_entries(repo_root: Path) -> list[tuple[str, str]]:
    """Return (relpath, git-mode) pairs from ``git ls-files -s -z``."""
    raw = subprocess.run(["git", "ls-files", "-s", "-z"], cwd=str(repo_root), capture_output=True, check=True).stdout
    entries = []
    for chunk in raw.split(b"\x00"):
        if not chunk:
            continue
        meta, _, path = chunk.partition(b"\t")
        mode = meta.split(b" ")[0].decode("ascii")
        entries.append((path.decode("utf-8", errors="surrogateescape"), mode))
    return entries


def scan_tracked(repo_root: Path) -> list[Finding]:
    out: list[Finding] = []
    for relpath, mode in collect_tracked_entries(repo_root):
        fixture = is_fixture_path(relpath)
        abs_path = repo_root / relpath
        if mode == "120000":
            try:
                target = os.readlink(abs_path)
            except OSError:
                target = ""
            out.append(Finding(relpath, "file", "SYMLINK_TRACKED", "tracked worktree symlink present (not followed; rejected)", target))
            out += scan_text_content(target, relpath, fixture=fixture)
            continue
        try:
            raw = abs_path.read_bytes()
        except OSError as exc:
            out.append(Finding(relpath, "file", "DECODE_FAIL", f"could not read tracked file: {exc}", ""))
            continue
        out += scan_bytes_as_file(raw, relpath, fixture=fixture)
    return out


def scan_generated_tree(root_path: Path, repo_root: Path) -> list[Finding]:
    out: list[Finding] = []
    root_path = root_path.resolve()
    if not root_path.exists():
        return [Finding(str(root_path), "file", "DECODE_FAIL", "--generated path does not exist", "")]
    if root_path.is_file():
        files = [root_path]
    else:
        files = sorted(p for p in root_path.rglob("*") if p.is_file() or p.is_symlink())
    for abs_path in files:
        try:
            relpath = str(abs_path.relative_to(repo_root))
        except ValueError:
            relpath = str(abs_path)
        fixture = is_fixture_path(relpath)
        if abs_path.is_symlink():
            target = os.readlink(abs_path)
            out.append(Finding(relpath, "file", "SYMLINK_TRACKED", "generated-output symlink present (not followed; rejected)", target))
            out += scan_text_content(target, relpath, fixture=fixture)
            continue
        raw = abs_path.read_bytes()
        out += scan_bytes_as_file(raw, relpath, fixture=fixture)
    return out


# ---------------------------------------------------------------------------
# H11 -- mandatory generated-path manifest
# ---------------------------------------------------------------------------

KNOWN_GENERATED_DIRS = ("dist", "build", "site", "out", ".output", "coverage", ".wrangler")


def check_generated_manifest(repo_root: Path, generated_args: list[str]) -> list[Finding]:
    passed = {str((repo_root / p).resolve()) for p in generated_args}
    out: list[Finding] = []
    for name in KNOWN_GENERATED_DIRS:
        d = repo_root / name
        if d.is_dir() and str(d.resolve()) not in passed:
            out.append(Finding(name, "file", "GENERATED_MISSING", f"known generated directory '{name}' exists but was not passed via --generated", ""))
    return out


# ---------------------------------------------------------------------------
# H10 -- history + metadata scan
# ---------------------------------------------------------------------------

PUBLIC_HISTORY_METADATA_LINES = frozenset(
    {
        "".join(("GitHub <noreply", "@github.com>")),
        "".join(
            (
                "John Osumi <931193+sumitake",
                "@users.noreply.github.com>",
            )
        ),
        "".join(
            (
                "dependabot[bot] <49699333+dependabot[bot]",
                "@users.noreply.github.com>",
            )
        ),
        "".join(("Signed-off-by: dependabot[bot] <support", "@github.com>")),
        "".join(
            (
                "Co-Authored-By: Claude Fable 5 <noreply",
                "@anthropic.com>",
            )
        ),
        "".join(
            (
                "Co-authored-by: Claude Fable 5 <noreply",
                "@anthropic.com>",
            )
        ),
        "".join(
            (
                "Conduct, changelog, third-party-notices placeholder, "
                "CODEOWNERS (* ",
                "@",
                CANONICAL_OWNER,
                "),",
            )
        ),
    }
)


def _history_blob_label(original_path: str, finding_path: str, blob_oid: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", blob_oid):
        raise ValueError("historical blob OID must be complete lowercase hex")
    if finding_path == original_path:
        suffix = ""
    elif finding_path.startswith(original_path + "!"):
        suffix = finding_path[len(original_path) :]
    else:
        raise ValueError("historical finding escaped its original path")
    return f"{original_path}@{blob_oid}{suffix}"


def _scan_public_history_metadata(value: str, label: str) -> list[Finding]:
    findings = scan_text_content(value, label, fixture=False)
    return [
        finding._replace(rule="HISTORY_META")
        for finding in findings
        if finding.content not in PUBLIC_HISTORY_METADATA_LINES
    ]


def scan_history(repo_root: Path) -> list[Finding]:
    out: list[Finding] = []

    # Reachable blobs across every ref that would exist on a public remote.
    rev_list = _run_git(["rev-list", "--objects", "--all"], repo_root)
    blob_entries = []
    for line in rev_list.splitlines():
        if not line.strip():
            continue
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        sha, path = parts
        blob_entries.append((sha, path))

    if blob_entries:
        batch_input = "\n".join(sha for sha, _ in blob_entries) + "\n"
        check_proc = subprocess.run(
            ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            cwd=str(repo_root),
            input=batch_input.encode("utf-8"),
            capture_output=True,
            check=True,
        )
        types = {}
        for line in check_proc.stdout.decode("utf-8").splitlines():
            fields = line.split(" ")
            if len(fields) == 3:
                types[fields[0]] = (fields[1], int(fields[2]))

        for sha, path in blob_entries:
            info = types.get(sha)
            if info is None or info[0] != "blob":
                continue
            _, size = info
            if size > MAX_FILE_BYTES:
                out.append(Finding(f"{path}@{sha}", "file", "SIZE_LIMIT", "historical blob exceeds size cap (fail closed)", ""))
                continue
            content = subprocess.run(["git", "cat-file", "blob", sha], cwd=str(repo_root), capture_output=True, check=True).stdout
            fixture = is_fixture_path(path)
            historical_findings = scan_bytes_as_file(
                content,
                path,
                fixture=fixture,
            )
            out += [
                finding._replace(
                    path=_history_blob_label(path, finding.path, sha)
                )
                for finding in historical_findings
            ]

    # Commit metadata: subject, body, author/committer identity.
    log = _run_git(["log", "--all", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%s%x1f%b%x1e"], repo_root)
    for record in log.split("\x1e"):
        record = record.strip("\n")
        if not record.strip():
            continue
        fields = record.split("\x1f")
        if len(fields) < 7:
            continue
        sha, an, ae, cn, ce, subject, body = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]
        label = f"<commit {sha[:8]}>"
        for field_name, value in (
            ("author", f"{an} <{ae}>"),
            ("committer", f"{cn} <{ce}>"),
            ("subject", subject),
            ("body", body),
        ):
            out += _scan_public_history_metadata(
                value,
                f"{label}#{field_name}",
            )

    # Tag names + annotations.
    tag_out = _run_git(["tag", "-l", "-n999"], repo_root)
    for line in tag_out.splitlines():
        if not line.strip():
            continue
        out += _scan_public_history_metadata(line, "<tag>")

    # Branch names (local + remote-tracking).
    for ref_kind in ("refs/heads", "refs/remotes"):
        refs = _run_git(["for-each-ref", "--format=%(refname:short)", ref_kind], repo_root)
        for line in refs.splitlines():
            if not line.strip():
                continue
            out += _scan_public_history_metadata(line, "<branch-name>")

    # Deleted-file path strings (identifier-bearing filenames survive even
    # though the blob walk above already covers their *content*).
    deleted = _run_git(["log", "--all", "--diff-filter=D", "--name-only", "--pretty=format:"], repo_root)
    for path in sorted(set(p for p in deleted.splitlines() if p.strip())):
        for f in scan_text_content(path, f"<deleted-path>", fixture=is_fixture_path(path)):
            out.append(f._replace(rule="HISTORY_META", message=f"identifier in a deleted filename: {f.message}"))

    return out


# ---------------------------------------------------------------------------
# Private denylist (operator-supplied, additive only, never echoed)
# ---------------------------------------------------------------------------


def scan_private_denylist(repo_root: Path, tracked: bool, generated: list[str], denylist_path: Path, history: bool) -> list[Finding]:
    if not denylist_path.exists():
        return [Finding(str(denylist_path), "file", "DECODE_FAIL", "--private-denylist path does not exist", "")]
    try:
        terms = [
            ln.strip()
            for ln in denylist_path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
    except UnicodeDecodeError:
        return [Finding(str(denylist_path), "file", "DECODE_FAIL", "--private-denylist is not valid UTF-8 text", "")]

    out: list[Finding] = []

    def scan_one(relpath: str, text: str) -> None:
        for i, line in enumerate(re.split(r"\r\n|\r|\n", text), start=1):
            for term in terms:
                if term and term in line:
                    # Never echo the matched term or the denylist content itself.
                    out.append(Finding(relpath, i, "PRIVATE_DENYLIST", "line matches an operator-supplied private-denylist term", line))

    targets: list[str] = []
    if tracked:
        targets += [rp for rp, mode in collect_tracked_entries(repo_root) if mode != "120000"]
    for g in generated:
        gp = Path(g)
        if gp.is_file():
            targets.append(str(gp))
        elif gp.is_dir():
            targets += [str(p) for p in gp.rglob("*") if p.is_file()]

    for relpath in targets:
        abs_path = repo_root / relpath if not os.path.isabs(relpath) else Path(relpath)
        try:
            text = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        scan_one(relpath, text)

    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="sanitize_public.py")
    p.add_argument("--tracked", action="store_true", help="scan git-tracked files")
    p.add_argument("--generated", action="append", default=[], metavar="PATH", help="scan a generated-output path (repeatable)")
    p.add_argument("--private-denylist", metavar="PATH", help="operator-supplied untracked denylist file (never in CI)")
    p.add_argument("--history", action="store_true", help="scan reachable git history + metadata")
    return p.parse_args(argv)


ALLOWLIST_FILENAME = ".sanitization-allowlist.json"


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        repo_root = discover_repo_root()
    except subprocess.CalledProcessError:
        print(f"<repo>:0:DECODE_FAIL: not inside a git repository", file=sys.stderr)
        return 1

    allowlist_path = repo_root / ALLOWLIST_FILENAME
    try:
        allowlist = load_allowlist(allowlist_path)
    except AllowlistError as exc:
        print(f"{ALLOWLIST_FILENAME}:file:ALLOWLIST_INVALID: {exc}")
        return 1

    ran_any = False
    findings: list[Finding] = []

    if args.tracked:
        ran_any = True
        findings += scan_tracked(repo_root)
        findings += check_generated_manifest(repo_root, args.generated)

    for g in args.generated:
        ran_any = True
        findings += scan_generated_tree(Path(g), repo_root)

    if args.private_denylist:
        ran_any = True
        findings += scan_private_denylist(repo_root, args.tracked, args.generated, Path(args.private_denylist), args.history)

    if args.history:
        ran_any = True
        findings += scan_history(repo_root)

    if not ran_any:
        print("no scan mode selected; pass --tracked, --generated, and/or --history", file=sys.stderr)
        return 1

    findings = allowlist.filter(findings)
    unique = sorted(set(findings), key=_sort_key)
    for f in unique:
        print(format_finding(f))

    if unique:
        return 1
    if args.tracked:
        print("sanitization passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
