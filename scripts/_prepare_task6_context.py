#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Emit canonical, secret-free manifests for one generated legacy rootfs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def fail() -> "NoReturn":
    raise SystemExit("prepare-task6-context: unavailable")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_entries(root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        base = Path(directory)
        for name in [*names, *files]:
            candidate = base / name
            relative = candidate.relative_to(root).as_posix()
            metadata = candidate.lstat()
            mode = format(stat.S_IMODE(metadata.st_mode), "o")
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(candidate)
                if not target or "\n" in target or "\x00" in target:
                    fail()
                entries.append(
                    {
                        "path": relative,
                        "type": "symlink",
                        "mode": mode,
                        "target": target,
                    }
                )
            elif stat.S_ISDIR(metadata.st_mode):
                entries.append(
                    {"path": relative, "type": "directory", "mode": mode}
                )
            elif stat.S_ISREG(metadata.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "type": "file",
                        "mode": mode,
                        "sha256": sha256_file(candidate),
                    }
                )
            else:
                fail()
    entries.sort(key=lambda entry: str(entry["path"]))
    if not entries:
        fail()
    return entries


def layout_line(entry: dict[str, object]) -> str:
    kinds = {"directory": "d", "file": "f", "symlink": "l"}
    kind = kinds.get(str(entry["type"]))
    if kind is None:
        fail()
    target = str(entry.get("target", ""))
    return f"{kind} {entry['mode']} {entry['path']} {target}\n"


def write_bytes(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o444)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--rootfs")
    parser.add_argument("--package-lock")
    parser.add_argument("--output")
    namespace = parser.parse_args()
    if (
        not namespace.rootfs
        or not namespace.package_lock
        or not namespace.output
    ):
        fail()

    root = Path(namespace.rootfs)
    package_lock = Path(namespace.package_lock)
    output = Path(namespace.output)
    if (
        not root.is_absolute()
        or not package_lock.is_absolute()
        or not output.is_absolute()
        or root.is_symlink()
        or package_lock.is_symlink()
        or output.is_symlink()
        or not root.is_dir()
        or not package_lock.is_file()
        or not output.is_dir()
    ):
        fail()

    lock = json.loads(package_lock.read_text(encoding="utf-8"))
    if (
        set(lock) != {
            "schema_version",
            "snapshot",
            "architecture",
            "data_member",
            "packages",
        }
        or lock["schema_version"] != 1
        or lock["architecture"] != "amd64"
        or lock["data_member"] != "data.tar.xz"
        or not isinstance(lock["packages"], list)
        or len(lock["packages"]) != 8
    ):
        fail()

    entries = canonical_entries(root)
    layout = "".join(layout_line(entry) for entry in entries).encode("utf-8")
    layout_digest = hashlib.sha256(layout).hexdigest()
    regular = "".join(
        f"{entry['sha256']}  {entry['path']}\n"
        for entry in entries
        if entry["type"] == "file"
    ).encode("utf-8")
    if not regular:
        fail()

    manifest = {
        "schema_version": 1,
        "architecture": "linux-amd64",
        "package_lock_sha256": sha256_file(package_lock),
        "layout_sha256": layout_digest,
        "entries": entries,
    }
    manifest_bytes = (
        json.dumps(
            manifest,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    write_bytes(output / "legacy.layout", layout)
    write_bytes(
        output / "legacy.layout.sha256",
        f"{layout_digest}  legacy.layout\n".encode("ascii"),
    )
    write_bytes(output / "legacy.sha256", regular)
    write_bytes(output / "legacy.manifest.json", manifest_bytes)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        fail()
