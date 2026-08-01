#!/usr/bin/env python3
"""Validate the closed runner base/snapshot/package provenance tuple."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


class ContractError(Exception):
    """The public runner snapshot contract is unavailable."""


HEX64 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
BASE_REFERENCE = re.compile(
    r"^debian:bookworm-slim@sha256:[0-9a-f]{64}$"
)
VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$")
SNAPSHOT = re.compile(r"^[0-9]{8}T000000Z$")
CREATED = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z$")

TOP_LEVEL_KEYS = {
    "schema_version",
    "architecture",
    "base",
    "snapshot",
    "sources",
    "direct_packages",
    "additional_anchors",
}
BASE_KEYS = {
    "reference",
    "config_digest",
    "layer_digest",
    "created_at",
    "source_epoch",
}
SOURCE_KEYS = {
    "archive",
    "suite",
    "component",
    "inrelease_sha256",
    "packages_size",
    "packages_sha256",
}
PACKAGE_KEYS = {"name", "version"}
EXPECTED_SOURCES = (
    ("debian", "bookworm"),
    ("debian", "bookworm-updates"),
    ("debian-security", "bookworm-security"),
)
EXPECTED_DIRECT_NAMES = (
    "ca-certificates",
    "curl",
    "git",
    "libicu72",
    "libkrb5-3",
    "liblttng-ust1",
    "libssl3",
    "zlib1g",
)
EXPECTED_ANCHOR_NAMES = ("perl", "perl-base")


def _reject(_message: str = "unavailable") -> None:
    raise ContractError(_message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate key")
        result[key] = value
    return result


def _reject_float(_value: str) -> None:
    _reject("floating number")


def _reject_constant(_value: str) -> None:
    _reject("non-finite number")


def _regular_single_link(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 2
            or metadata.st_size > 1024 * 1024
        ):
            _reject("unsafe file")
        return path.read_bytes()
    except OSError:
        _reject("unreadable file")


def load_lock(path: Path) -> dict[str, Any]:
    raw = _regular_single_link(path)
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        _reject("invalid JSON")
    validate_lock(value)
    return value


def _exact_keys(value: Any, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _reject("object shape")
    return value


def _valid_package(entry: Any) -> tuple[str, str]:
    package = _exact_keys(entry, PACKAGE_KEYS)
    name = package["name"]
    version = package["version"]
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name)
        or not isinstance(version, str)
        or VERSION.fullmatch(version) is None
    ):
        _reject("package")
    return name, version


def validate_lock(value: Any) -> None:
    lock = _exact_keys(value, TOP_LEVEL_KEYS)
    if (
        type(lock["schema_version"]) is not int
        or lock["schema_version"] != 1
        or lock["architecture"] != "amd64"
    ):
        _reject("header")

    base = _exact_keys(lock["base"], BASE_KEYS)
    if (
        not isinstance(base["reference"], str)
        or BASE_REFERENCE.fullmatch(base["reference"]) is None
        or not isinstance(base["config_digest"], str)
        or DIGEST.fullmatch(base["config_digest"]) is None
        or not isinstance(base["layer_digest"], str)
        or DIGEST.fullmatch(base["layer_digest"]) is None
        or not isinstance(base["created_at"], str)
        or CREATED.fullmatch(base["created_at"]) is None
        or type(base["source_epoch"]) is not int
        or base["source_epoch"] <= 0
        or not isinstance(lock["snapshot"], str)
        or SNAPSHOT.fullmatch(lock["snapshot"]) is None
    ):
        _reject("base")
    try:
        created = datetime.datetime.strptime(
            base["created_at"],
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        _reject("base time")
    if (
        int(created.timestamp()) != base["source_epoch"]
        or created.strftime("%Y%m%dT%H%M%SZ") != lock["snapshot"]
    ):
        _reject("base time")

    sources = lock["sources"]
    if not isinstance(sources, list) or len(sources) != len(EXPECTED_SOURCES):
        _reject("sources")
    for source, expected in zip(sources, EXPECTED_SOURCES, strict=True):
        row = _exact_keys(source, SOURCE_KEYS)
        archive, suite = expected
        if (
            row["archive"] != archive
            or row["suite"] != suite
            or row["component"] != "main"
            or not isinstance(row["inrelease_sha256"], str)
            or HEX64.fullmatch(row["inrelease_sha256"]) is None
            or type(row["packages_size"]) is not int
            or row["packages_size"] <= 0
            or not isinstance(row["packages_sha256"], str)
            or HEX64.fullmatch(row["packages_sha256"]) is None
        ):
            _reject("source")

    direct = lock["direct_packages"]
    if not isinstance(direct, list) or len(direct) != len(
        EXPECTED_DIRECT_NAMES
    ):
        _reject("direct packages")
    direct_rows = [_valid_package(entry) for entry in direct]
    if tuple(name for name, _version in direct_rows) != EXPECTED_DIRECT_NAMES:
        _reject("direct packages")

    anchors = lock["additional_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(
        EXPECTED_ANCHOR_NAMES
    ):
        _reject("anchors")
    anchor_rows = [_valid_package(entry) for entry in anchors]
    if (
        tuple(name for name, _version in anchor_rows)
        != EXPECTED_ANCHOR_NAMES
        or anchor_rows[0][1] != anchor_rows[1][1]
        or set(EXPECTED_DIRECT_NAMES) & set(EXPECTED_ANCHOR_NAMES)
    ):
        _reject("anchors")


def _source_lines(lock: dict[str, Any]) -> list[str]:
    snapshot = lock["snapshot"]
    return [
        (
            "deb [check-valid-until=no] "
            f"https://snapshot.debian.org/archive/{row['archive']}/"
            f"{snapshot} {row['suite']} {row['component']}"
        )
        for row in lock["sources"]
    ]


def _normalized_shell(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\\\n", " ")).strip()


def _require_consumer_fragments(
    lock: dict[str, Any],
    lock_sha: str,
    dockerfile: str,
    dockerignore: str,
) -> None:
    base_reference = lock["base"]["reference"]
    from_references = []
    for line in dockerfile.splitlines():
        match = re.fullmatch(
            r"FROM ([^ ]+)(?: AS [A-Za-z0-9._-]+)?",
            line,
        )
        if match:
            from_references.append(match.group(1))
    if from_references != [base_reference, base_reference]:
        _reject("base consumers")

    actual_sources = re.findall(
        r"deb \[check-valid-until=no\] "
        r"https://snapshot[.]debian[.]org/archive/"
        r"[a-z-]+/[0-9]{8}T[0-9]{6}Z [a-z-]+ [a-z ]+",
        dockerfile,
    )
    if actual_sources != _source_lines(lock):
        _reject("source consumers")
    if (
        "20250101T000000Z" in dockerfile
        or "http://snapshot.debian.org" in dockerfile
        or "deb.debian.org" in dockerfile
        or "security.debian.org" in dockerfile
    ):
        _reject("moving source")

    digest_match = re.search(
        r"expected_debian_snapshot_lock_sha=([0-9a-f]{64})",
        dockerfile,
    )
    if digest_match is None or digest_match.group(1) != lock_sha:
        _reject("lock digest consumer")

    normalized = _normalized_shell(dockerfile)
    direct_arguments = " ".join(
        f"{row['name']}={row['version']}"
        for row in lock["direct_packages"]
    )
    if (
        f"install -y --no-install-recommends {direct_arguments} "
        not in normalized
    ):
        _reject("install consumer")

    verifier_arguments = " ".join(
        (
            f"{row['suite']} {row['inrelease_sha256']} "
            f"{row['packages_size']} {row['packages_sha256']}"
        )
        for row in lock["sources"]
    )
    verifier_call = (
        "/usr/local/bin/verify-debian-snapshot /var/lib/apt/lists "
        f"{verifier_arguments}"
    )
    verifier_index = normalized.find(verifier_call)
    install_index = normalized.find("install -y --no-install-recommends")
    if (
        verifier_index < 0
        or install_index < 0
        or verifier_index >= install_index
    ):
        _reject("index verifier consumer")

    anchor_rows = [
        (row["name"], row["version"]) for row in lock["direct_packages"]
    ] + [
        (row["name"], row["version"])
        for row in lock["additional_anchors"]
    ]
    anchor_arguments = " ".join(
        f"'{name}' '{version}'" for name, version in anchor_rows
    )
    anchor_names = " ".join(name for name, _version in anchor_rows)
    if (
        f"printf '%s\\t%s\\n' {anchor_arguments}" not in normalized
        or f"for package in {anchor_names}; do" not in normalized
        or "cmp /tmp/runner-package-anchors.expected "
        "/usr/share/portable-ghar/runner-package-anchors.tsv"
        not in normalized
        or "dpkg-query -W" not in normalized
        or "dpkg-manifest.tsv" not in normalized
    ):
        _reject("anchor consumer")

    required_context = {
        "!debian-snapshot.lock.json",
        "!verify-debian-snapshot.sh",
    }
    ignore_lines = dockerignore.splitlines()
    if not required_context.issubset(set(ignore_lines)):
        _reject("context admission")
    if {
        line
        for line in ignore_lines
        if "debian-snapshot" in line
    } != required_context:
        _reject("context admission")
    for fragment in (
        "debian-snapshot.lock.json|verify-debian-snapshot.sh",
        "sha256sum /context/debian-snapshot.lock.json",
        "/context/verify-debian-snapshot.sh",
        "/usr/share/portable-ghar/debian-snapshot.lock.json",
    ):
        if fragment not in dockerfile:
            _reject("context audit consumer")


def validate_repository(root: Path) -> None:
    root = root.resolve(strict=True)
    lock_path = root / "images/runner/debian-snapshot.lock.json"
    lock = load_lock(lock_path)
    lock_sha = hashlib.sha256(_regular_single_link(lock_path)).hexdigest()

    dockerfile = _regular_single_link(
        root / "images/runner/Dockerfile"
    ).decode("utf-8", "strict")
    dockerignore = _regular_single_link(
        root / "images/runner/.dockerignore"
    ).decode("utf-8", "strict")
    verifier_path = root / "images/runner/verify-debian-snapshot.sh"
    verifier = _regular_single_link(verifier_path).decode("utf-8", "strict")
    if (
        not os.access(verifier_path, os.X_OK)
        or "verify-debian-snapshot: verified" not in verifier
        or "main/binary-amd64/Packages.xz" not in verifier
    ):
        _reject("index verifier")

    _require_consumer_fragments(
        lock,
        lock_sha,
        dockerfile,
        dockerignore,
    )

    readme = _regular_single_link(
        root / "images/runner/README.md"
    ).decode("utf-8", "strict")
    if (
        "debian-snapshot.lock.json" not in readme
        or lock["snapshot"] not in readme
        or "atomic" not in readme.lower()
        or "InRelease" not in readme
    ):
        _reject("README consumer")

    gate = _regular_single_link(
        root / "scripts/test-controller-runtime.sh"
    ).decode("utf-8", "strict")
    rehearsal = _regular_single_link(
        root / "scripts/release/rehearse-runtime.sh"
    ).decode("utf-8", "strict")
    invocation = "scripts/ci/check_runner_debian_snapshot.py"
    if invocation not in gate or invocation not in rehearsal:
        _reject("validator invocation")
    validator_start = rehearsal.find("def validate_dockerfiles(")
    validator_end = rehearsal.find("\ndef inspect_buildkit(", validator_start)
    if (
        validator_start < 0
        or validator_end < 0
        or "20250101T000000Z"
        in rehearsal[validator_start:validator_end]
    ):
        _reject("stale release consumer")


def main(argv: list[str]) -> int:
    if argv:
        print("check-runner-debian-snapshot: unavailable", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[2]
    try:
        validate_repository(root)
    except (ContractError, OSError, UnicodeError, ValueError):
        print("check-runner-debian-snapshot: unavailable", file=sys.stderr)
        return 1
    print("check-runner-debian-snapshot: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
