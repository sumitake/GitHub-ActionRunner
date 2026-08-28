#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Fail-closed GitHub Actions workflow policy checker for Portable GHAR.

Validates every ``*.yml``/``*.yaml`` workflow file directly inside a given
directory against this project's supply-chain and least-privilege posture:

- Every remote (non ``./``-local, non ``docker://``) action ref pins a full
  40-character commit SHA that exactly matches a reviewed entry in
  ``REVIEWED_ACTION_PINS``, with a trailing ``# <release>`` comment that
  matches that entry's reviewed release string exactly.
- ``docker://`` actions must be pinned by digest (``@sha256:...``).
- ``./``-prefixed local actions are always allowed.
- No workflow trigger is ``pull_request_target`` (or another trigger this
  checker treats as unsafe with untrusted fork code).
- Every job's ``runs-on`` is the single hosted value ``ubuntu-24.04`` --
  never a self-hosted runner and never a ``${{ ... }}`` expression.
- The workflow-level ``permissions`` key is present and never grants
  ``write``/``write-all``; a job-level ``permissions`` block may grant a
  scoped ``write`` (e.g. a release job), but never ``write-all``.
- Every job declares ``timeout-minutes`` and a ``concurrency`` block whose
  ``group`` is keyed on both ``github.workflow`` and ``github.ref`` and
  whose ``cancel-in-progress`` is ``true``.
- Every ``actions/checkout`` step sets ``with.persist-credentials: false``.
- No two workflow files in the directory define the same job id (GitHub's
  default required-status-check "context"); duplicate contexts across the
  workflow set are rejected.

This checker does NOT depend on a YAML library (mirrors the stdlib-only
convention of scripts/sanitize_public.py and
scripts/check_repository_metadata.py, so it runs anywhere the repo's
toolchain runs, including hosted CI, with no extra install step). Instead
it implements a small, deliberately restricted block-style YAML parser for
exactly the subset GitHub Actions workflows need: block mappings, block
sequences (including "- key: value" inline-mapping sequence items), plain/
quoted scalars, and the two empty flow collections ``{}``/``[]``. Anything
the parser cannot prove safe -- anchors (``&``), aliases (``*``), tags
(``!``), multiline block scalars (``|``/``>``), non-empty flow collections
(``{...}``/``[...]``), tab indentation, or multiple YAML documents in one
file -- is rejected outright rather than silently accepted or guessed at:
fail closed, never a silent skip.

    python3 scripts/check_workflow_policy.py <workflows-dir>

Diagnostics: ``path: message`` (one per line to stdout, sorted,
deterministic; ``path`` is the workflow file name relative to the given
directory). Exit 0 iff every workflow in the directory passes every check.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Optional, Union

# ---------------------------------------------------------------------------
# Reviewed action pin table: "owner/repo" -> (40-hex sha, release comment).
#
# This is the single source of truth for every remote action this project's
# workflows are permitted to reference. A SHA is added here only after
# manual review of the corresponding tagged release; adding an entry is a
# deliberate, reviewed act, never automatic. Entries beyond the five Task 8
# uses (actions/checkout, actions/setup-go, actions/setup-node,
# actions/upload-artifact, docker/setup-buildx-action,
# aquasecurity/trivy-action) are pre-reviewed for
# later tasks (CodeQL, dependency review, Gitleaks, attestation, SBOM,
# Bats, and least-privilege GitHub App token minting) so this table does
# not need to change again when those workflows are added.
# ---------------------------------------------------------------------------
REVIEWED_ACTION_PINS: dict[str, tuple[str, str]] = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/setup-go": ("b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", "v7.0.0"),
    "actions/setup-node": ("820762786026740c76f36085b0efc47a31fe5020", "v7.0.0"),
    "actions/upload-artifact": ("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "v7.0.1"),
    "docker/setup-buildx-action": ("8d2750c68a42422c14e847fe6c8ac0403b4cbd6f", "v3"),
    "aquasecurity/trivy-action": ("ed142fd0673e97e23eac54620cfb913e5ce36c25", "v0.36.0"),
    "github/codeql-action": ("5595ccaf912efad79be6eef63a5619ff05969be3", "v4.37.6"),
    "actions/dependency-review-action": (
        "a1d282b36b6f3519aa1f3fc636f609c47dddb294",
        "v5.0.0",
    ),
    "gitleaks/gitleaks-action": ("e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e", "v3.0.0"),
    "actions/attest": ("1e69f48acb82d1966a394da916b4c1698aa569d6", "v4.2.2"),
    "actions/create-github-app-token": (
        "bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "v3.2.0",
    ),
    "anchore/sbom-action": ("e22c389904149dbc22b58101806040fa8d37a610", "v0.24.0"),
    "bats-core/bats-action": ("77d6fb60505b4d0d1d73e48bd035b55074bbfb43", "4.0.0"),
}

UNSAFE_TRIGGERS = frozenset({"pull_request_target"})
REQUIRED_RUNNER = "ubuntu-24.04"
LOCAL_ACTION_PREFIX = "./"
DOCKER_ACTION_PREFIX = "docker://"

HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_MISSING = object()

# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


class Diagnostics:
    """Accumulates (path, message) findings. Truthy iff non-empty."""

    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []

    def add(self, path: str, message: str) -> None:
        self.items.append((path, message))

    def __bool__(self) -> bool:
        return bool(self.items)


# ---------------------------------------------------------------------------
# Restricted block-style YAML parser
# ---------------------------------------------------------------------------


class WorkflowParseError(Exception):
    def __init__(self, lineno: Optional[int], reason: str) -> None:
        self.lineno = lineno
        self.reason = reason
        super().__init__(reason)


class Scalar(str):
    """A YAML plain/quoted scalar that remembers its source line and any
    trailing inline comment (used to validate action-pin release comments).
    Behaves exactly like ``str`` everywhere else."""

    lineno: int
    comment: Optional[str]

    def __new__(cls, value: str, lineno: int, comment: Optional[str] = None) -> "Scalar":
        obj = str.__new__(cls, value)
        obj.lineno = lineno
        obj.comment = comment
        return obj


Node = Union[None, str, Scalar, dict, list]

_UNSAFE_VALUE_PREFIXES = ("&", "*", "!", "|", ">", "{", "[")


def _tokenize(text: str) -> list[tuple[int, int, str]]:
    """Splits into (lineno, indent, content) tokens, dropping blank lines
    and full-line comments. Raises on tab indentation or a second YAML
    document marker (multi-document files cannot be proven safe)."""
    tokens: list[tuple[int, int, str]] = []
    seen_content = False
    for lineno, raw in enumerate(text.split("\n"), start=1):
        if raw.strip() == "":
            continue
        indent_len = len(raw) - len(raw.lstrip(" "))
        if "\t" in raw[:indent_len]:
            raise WorkflowParseError(lineno, "tab indentation is not supported")
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        if stripped == "---":
            if seen_content:
                raise WorkflowParseError(lineno, "multiple YAML documents are not supported")
            continue
        if stripped == "...":
            continue
        tokens.append((lineno, indent_len, raw[indent_len:]))
        seen_content = True
    return tokens


def _split_comment(content: str, lineno: int) -> tuple[str, Optional[str]]:
    """Splits ``content`` into (code, comment) at the first unquoted
    ``#`` that is preceded by whitespace or is the first character."""
    in_single = False
    in_double = False
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == "\\" and i + 1 < n:
                i += 1
            elif ch == '"':
                in_double = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "#" and (i == 0 or content[i - 1] in (" ", "\t")):
                return content[:i].rstrip(), content[i + 1 :].strip()
        i += 1
    if in_single or in_double:
        raise WorkflowParseError(lineno, "unterminated quoted string")
    return content.rstrip(), None


def _split_key_value(content: str, lineno: int) -> Optional[tuple[str, str]]:
    """Splits a mapping-entry line at the first unquoted ``: `` (or a
    trailing unquoted ``:``). Returns None if no such colon is found."""
    in_single = False
    in_double = False
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == "\\" and i + 1 < n:
                i += 1
            elif ch == '"':
                in_double = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == ":" and (i + 1 == n or content[i + 1] == " "):
                return content[:i].strip(), content[i + 1 :].strip()
        i += 1
    if in_single or in_double:
        raise WorkflowParseError(lineno, "unterminated quoted string")
    return None


def _unquote(value: str, lineno: int) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        inner = v[1:-1]
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    if len(v) >= 2 and v[0] == "'" and v[-1] == "'":
        return v[1:-1].replace("''", "'")
    return v


def _parse_scalar_value(value: str, lineno: int, comment: Optional[str]) -> Scalar:
    v = value.strip()
    if v.startswith('"') or v.startswith("'"):
        return Scalar(_unquote(v, lineno), lineno, comment)
    if v[:1] in _UNSAFE_VALUE_PREFIXES:
        raise WorkflowParseError(
            lineno,
            f"cannot safely parse YAML value starting with {v[0]!r} "
            "(anchors, aliases, tags, block scalars, and non-empty flow "
            "collections are not supported by this fail-closed parser)",
        )
    return Scalar(v, lineno, comment)


def _consume_mapping_value(
    tokens: list[tuple[int, int, str]], i: int, key_indent: int, value_raw: str,
    comment: Optional[str], lineno: int,
) -> tuple[Node, int]:
    if value_raw == "":
        if i < len(tokens) and tokens[i][1] > key_indent:
            return _parse_node(tokens, i, tokens[i][1])
        return None, i
    if value_raw == "{}":
        return {}, i
    if value_raw == "[]":
        return [], i
    return _parse_scalar_value(value_raw, lineno, comment), i


def _parse_mapping(tokens: list[tuple[int, int, str]], i: int, indent: int) -> tuple[dict, int]:
    result: dict[str, Node] = {}
    while i < len(tokens):
        lineno, tok_indent, content = tokens[i]
        if tok_indent != indent:
            break
        if content == "-" or content.startswith("- "):
            break
        i += 1
        code, comment = _split_comment(content, lineno)
        kv = _split_key_value(code, lineno)
        if kv is None:
            raise WorkflowParseError(lineno, f"expected 'key: value' mapping entry, got {content!r}")
        key_raw, value_raw = kv
        key = _unquote(key_raw, lineno)
        if key in result:
            raise WorkflowParseError(lineno, f"duplicate mapping key {key!r}")
        value, i = _consume_mapping_value(tokens, i, indent, value_raw, comment, lineno)
        result[key] = value
    return result, i


def _parse_sequence(tokens: list[tuple[int, int, str]], i: int, indent: int) -> tuple[list, int]:
    items: list[Node] = []
    while i < len(tokens):
        lineno, tok_indent, content = tokens[i]
        if tok_indent != indent:
            break
        if not (content == "-" or content.startswith("- ")):
            break
        i += 1
        rest = content[1:]
        if rest.startswith(" "):
            rest = rest[1:]
        elif rest != "":
            raise WorkflowParseError(lineno, f"ambiguous sequence marker: {content!r}")
        if rest == "":
            if i < len(tokens) and tokens[i][1] > indent:
                node, i = _parse_node(tokens, i, tokens[i][1])
                items.append(node)
            else:
                items.append(None)
            continue
        code, comment = _split_comment(rest, lineno)
        kv = _split_key_value(code, lineno)
        if kv is None:
            items.append(_parse_scalar_value(rest, lineno, comment))
            continue
        key_raw, value_raw = kv
        key = _unquote(key_raw, lineno)
        mapping_indent = indent + 2
        value, i = _consume_mapping_value(tokens, i, mapping_indent, value_raw, comment, lineno)
        mapping: dict[str, Node] = {key: value}
        if (
            i < len(tokens)
            and tokens[i][1] == mapping_indent
            and not (tokens[i][2] == "-" or tokens[i][2].startswith("- "))
        ):
            more, i = _parse_mapping(tokens, i, mapping_indent)
            for k, v in more.items():
                if k in mapping:
                    raise WorkflowParseError(tokens[i - 1][0] if i else lineno, f"duplicate mapping key {k!r}")
                mapping[k] = v
        items.append(mapping)
    return items, i


def _parse_node(tokens: list[tuple[int, int, str]], i: int, indent: int) -> tuple[Node, int]:
    if i >= len(tokens):
        return None, i
    _, tok_indent, content = tokens[i]
    if tok_indent != indent:
        raise WorkflowParseError(tokens[i][0], "unexpected indentation")
    if content == "-" or content.startswith("- "):
        return _parse_sequence(tokens, i, indent)
    return _parse_mapping(tokens, i, indent)


def parse_workflow(text: str) -> dict:
    """Parses a workflow YAML document into a tree of dict/list/Scalar/None.
    Raises WorkflowParseError for anything the restricted grammar cannot
    prove safe."""
    tokens = _tokenize(text)
    if not tokens:
        return {}
    node, i = _parse_node(tokens, 0, tokens[0][1])
    if i != len(tokens):
        raise WorkflowParseError(tokens[i][0], "unexpected indentation at top level")
    if not isinstance(node, dict):
        raise WorkflowParseError(tokens[0][0], "workflow document root must be a mapping")
    return node


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


def _check_permissions_value(
    relpath: str, label: str, value: Node, diag: Diagnostics, *, allow_scoped_write: bool
) -> None:
    if isinstance(value, list):
        diag.add(relpath, f"{label} must be a mapping (or '{{}}'), not a list")
        return
    if isinstance(value, dict):
        for scope, level in value.items():
            lvl = str(level).strip().lower()
            if lvl == "write-all":
                diag.add(relpath, f"{label}: scope {scope!r} must not grant 'write-all'")
            elif lvl == "write" and not allow_scoped_write:
                diag.add(
                    relpath,
                    f"{label}: scope {scope!r} must not grant 'write' at workflow level "
                    "(write-default); scope a job-level permissions block instead",
                )
        return
    v = str(value).strip().lower()
    if v == "write-all":
        diag.add(relpath, f"{label} must not be 'write-all' (write-default permissions, unsafe)")
    elif v not in ("read-all", "none", ""):
        diag.add(relpath, f"{label}: unrecognized permissions value {value!r}")


def _check_runs_on(relpath: str, job_id: str, value: Node, diag: Diagnostics) -> None:
    if not isinstance(value, str) or isinstance(value, (dict, list)):
        diag.add(relpath, f"job {job_id!r}: 'runs-on' must be a single hosted runner string")
        return
    v = str(value)
    if "${{" in v:
        diag.add(relpath, f"job {job_id!r}: 'runs-on' must not use an expression (got {v!r})")
        return
    if "self-hosted" in v.lower():
        diag.add(relpath, f"job {job_id!r}: 'runs-on' must not target a self-hosted runner (got {v!r})")
        return
    if v != REQUIRED_RUNNER:
        diag.add(relpath, f"job {job_id!r}: 'runs-on' must be {REQUIRED_RUNNER!r} (got {v!r})")


def _check_concurrency(relpath: str, job_id: str, value: Node, diag: Diagnostics) -> None:
    if not isinstance(value, dict):
        diag.add(
            relpath,
            f"job {job_id!r}: 'concurrency' must be a mapping with 'group' and "
            "'cancel-in-progress: true'",
        )
        return
    group = value.get("group")
    if not group:
        diag.add(relpath, f"job {job_id!r}: 'concurrency.group' is required")
    else:
        g = str(group)
        if "github.workflow" not in g or "github.ref" not in g:
            diag.add(
                relpath,
                f"job {job_id!r}: 'concurrency.group' must be keyed on both "
                f"github.workflow and github.ref (got {g!r})",
            )
    cancel = value.get("cancel-in-progress")
    if str(cancel).strip().lower() != "true":
        diag.add(relpath, f"job {job_id!r}: 'concurrency.cancel-in-progress' must be true")


def _check_uses(relpath: str, job_id: str, uses_value: Scalar, step: dict, diag: Diagnostics) -> None:
    uses = str(uses_value)
    loc = f"job {job_id!r}"

    if uses.startswith(LOCAL_ACTION_PREFIX):
        return

    if uses.startswith(DOCKER_ACTION_PREFIX):
        if "@sha256:" not in uses:
            diag.add(
                relpath,
                f"{loc}: Docker action {uses!r} must be pinned by an "
                "'@sha256:<64-hex>' digest, not a mutable tag",
            )
        return

    if "@" not in uses:
        diag.add(relpath, f"{loc}: action ref {uses!r} is missing an '@<sha>' pin")
        return

    name, _, ref = uses.rpartition("@")
    if not HEX40_RE.match(ref):
        diag.add(
            relpath,
            f"{loc}: action ref {uses!r} must pin a full 40-character commit SHA, "
            "not a tag/branch/short ref",
        )
        return

    # The pin table is keyed by "owner/repo" (the reviewed unit), but some
    # reviewed repos host multiple actions at subpaths with no usable
    # root-level action (e.g. github/codeql-action's "/init", "/analyze",
    # "/autobuild" -- there is no "github/codeql-action" action itself). Look
    # the pin up by the first two "/"-separated segments of the ref so a
    # subpath action is checked against its owning repo's reviewed pin; for
    # every single-action repo already in the table this is a no-op (the
    # owner/repo prefix equals the full name).
    pin_key = "/".join(name.split("/")[:2])
    pin = REVIEWED_ACTION_PINS.get(pin_key)
    if pin is None:
        diag.add(relpath, f"{loc}: action {name!r} is not in the reviewed pin table")
        return

    expected_sha, expected_release = pin
    if ref.lower() != expected_sha.lower():
        diag.add(
            relpath,
            f"{loc}: action {name!r} SHA {ref} does not match the reviewed pin "
            f"{expected_sha}",
        )

    comment = getattr(uses_value, "comment", None)
    if not comment:
        diag.add(relpath, f"{loc}: action {name!r} is missing its '# {expected_release}' release comment")
    elif comment.strip() != expected_release:
        diag.add(
            relpath,
            f"{loc}: action {name!r} release comment {comment!r} does not match "
            f"the reviewed release {expected_release!r}",
        )

    if name == "actions/checkout":
        with_block = step.get("with")
        persisted = with_block.get("persist-credentials") if isinstance(with_block, dict) else None
        if persisted is None or str(persisted).strip().lower() != "false":
            diag.add(relpath, f"{loc}: actions/checkout must set 'with.persist-credentials: false'")


def check_workflow(relpath: str, root: dict, diag: Diagnostics) -> set[str]:
    """Runs every policy check against one already-parsed workflow document
    and returns the set of stable job/context ids it defines."""
    contexts: set[str] = set()

    on = root.get("on", _MISSING)
    if on is _MISSING:
        diag.add(relpath, "missing 'on' triggers")
    elif isinstance(on, dict):
        for trigger in on:
            if trigger in UNSAFE_TRIGGERS:
                diag.add(relpath, f"unsafe trigger with fork code: {trigger!r}")
    else:
        diag.add(relpath, "'on' must be a mapping of trigger names")

    top_perms = root.get("permissions", _MISSING)
    if top_perms is _MISSING:
        diag.add(relpath, "missing top-level 'permissions' (defaults to broad/write access)")
    else:
        _check_permissions_value(relpath, "top-level permissions", top_perms, diag, allow_scoped_write=False)

    jobs = root.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        diag.add(relpath, "missing or empty 'jobs' mapping")
        return contexts

    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            diag.add(relpath, f"job {job_id!r} must be a mapping")
            continue
        contexts.add(job_id)

        runs_on = job.get("runs-on", _MISSING)
        if runs_on is _MISSING:
            diag.add(relpath, f"job {job_id!r}: missing 'runs-on'")
        else:
            _check_runs_on(relpath, job_id, runs_on, diag)

        if "timeout-minutes" not in job:
            diag.add(relpath, f"job {job_id!r}: missing 'timeout-minutes'")

        concurrency = job.get("concurrency", _MISSING)
        if concurrency is _MISSING:
            diag.add(relpath, f"job {job_id!r}: missing 'concurrency'")
        else:
            _check_concurrency(relpath, job_id, concurrency, diag)

        job_perms = job.get("permissions", _MISSING)
        if job_perms is not _MISSING:
            _check_permissions_value(
                relpath, f"job {job_id!r} permissions", job_perms, diag, allow_scoped_write=True
            )

        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            diag.add(relpath, f"job {job_id!r}: missing or empty 'steps'")
            continue

        for step in steps:
            if not isinstance(step, dict):
                diag.add(relpath, f"job {job_id!r}: each step must be a mapping")
                continue
            uses = step.get("uses")
            if uses is not None:
                _check_uses(relpath, job_id, uses, step, diag)

    return contexts


def check_directory(workflows_dir: Path) -> Diagnostics:
    diag = Diagnostics()
    files = sorted(
        p
        for p in workflows_dir.iterdir()
        if p.is_file() and p.suffix in (".yml", ".yaml")
    )

    context_sources: dict[str, list[str]] = {}
    for path in files:
        relpath = path.name
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            diag.add(relpath, f"cannot read file: {exc}")
            continue
        try:
            root = parse_workflow(text)
        except WorkflowParseError as exc:
            loc = f" (line {exc.lineno})" if exc.lineno else ""
            diag.add(relpath, f"cannot safely parse YAML{loc}: {exc.reason}")
            continue
        contexts = check_workflow(relpath, root, diag)
        for ctx in contexts:
            context_sources.setdefault(ctx, []).append(relpath)

    for ctx, sources in context_sources.items():
        if len(sources) > 1:
            for src in sources:
                others = sorted(s for s in sources if s != src)
                diag.add(src, f"duplicate stable context {ctx!r} also defined in {', '.join(others)}")

    return diag


def parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "workflows_dir",
        type=Path,
        help="directory containing GitHub Actions workflow YAML files (non-recursive)",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    workflows_dir: Path = args.workflows_dir
    if not workflows_dir.is_dir():
        print(f"{workflows_dir}: workflows directory does not exist or is not a directory")
        return 1

    diag = check_directory(workflows_dir)
    for path, message in sorted(diag.items):
        print(f"{path}: {message}")

    if diag:
        return 1
    print("workflow policy checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
