#!/usr/bin/env python3
"""Build one exact, normalized Actions runner tree from reviewed source inputs.

The product rehearsal validates the closed runner-release document before
invoking this program.  This boundary independently rechecks every identity it
uses, keeps all mutable state below one caller-owned work root, and publishes
only after the complete tree has been built and verified.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
from typing import Any


class BuildError(Exception):
    """A closed source-build invariant was not satisfied."""


MAX_ARCHIVE_ENTRIES = 100_000
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
PROCESS_GROUP_JOIN_SECONDS = 5.0
RUNTIME_PACK_NAME = re.compile(
    r"^Microsoft\.[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*\.linux-x64$"
)
EXECUTABLE_LAYOUT_FILES = {
    "bin/Runner.Listener",
    "bin/Runner.PluginHost",
    "bin/Runner.Worker",
    "bin/installdependencies.sh",
    "safe_sleep.sh",
}
PROHIBITED_COMPONENTS = {"_diag", "_update", "_work", ".runner"}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
VERSION = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SUBPROCESS_STAGES = frozenset(
    {
        "download",
        "listener version",
        "runner layout",
        "runtime lock build",
        "runtime lock publish",
        "sdk runtime",
        "sdk version",
        "source checkout",
        "source fetch",
        "source identity",
        "source init",
        "source remote",
    }
)
DIAGNOSTIC_CODE = re.compile(
    rb"(?<![A-Za-z0-9])(?:MSB|NETSDK|NU|CS|CA|SYSLIB)[0-9]{4,5}(?![A-Za-z0-9])"
)
LOCK_PATHS = (
    "Runner.Common/packages.lock.json",
    "Runner.Listener/packages.lock.json",
    "Runner.PluginHost/packages.lock.json",
    "Runner.Plugins/packages.lock.json",
    "Runner.Sdk/packages.lock.json",
    "Runner.Worker/packages.lock.json",
    "Sdk/packages.lock.json",
)
EXTERNAL_LAYOUTS = ("node20", "node20_alpine", "node24", "node24_alpine")
SOURCE_LOCK_KEYS = (
    "schema_version",
    "runner_version",
    "runner_payload_sha256",
    "runner_source_commit",
    "runner_source_tree",
    "runner_release_evidence",
    "command_settings_sha256",
    "runner_base_image",
    "manifest_sha256",
    "tree_lock_sha256",
    "evidence_generation",
    "listener",
)
LISTENER_KEYS = ("path", "sha256", "size", "mode", "uid", "gid")
READY_KEYS = (
    "schema_version",
    "runtime_lock_sha256",
    "tree_lock_sha256",
    "manifest_sha256",
    "evidence_generation",
)


def _safe_member_path(value: str, expected_root: str | None) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise BuildError("unsafe archive path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BuildError("unsafe archive path")
    while value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    if not value:
        return PurePosixPath(".")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise BuildError("unsafe archive path")
    if str(pure) != value:
        raise BuildError("noncanonical archive path")
    if expected_root is not None:
        if not expected_root or "/" in expected_root or pure.parts[0] != expected_root:
            raise BuildError("archive root mismatch")
        if len(pure.parts) == 1:
            return PurePosixPath(".")
        pure = PurePosixPath(*pure.parts[1:])
    return pure


def _safe_link_target(member: PurePosixPath, value: str) -> PurePosixPath:
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or value.startswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BuildError("unsafe archive link")
    target_parts: list[str] = list(member.parent.parts)
    for part in PurePosixPath(value).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not target_parts:
                raise BuildError("archive link escapes root")
            target_parts.pop()
        else:
            target_parts.append(part)
    if not target_parts:
        raise BuildError("archive link target invalid")
    return PurePosixPath(*target_parts)


def extract_verified_tar(
    archive_path: Path,
    output_path: Path,
    *,
    expected_root: str | None,
    maximum_entries: int = MAX_ARCHIVE_ENTRIES,
    maximum_expanded_bytes: int = MAX_ARCHIVE_BYTES,
) -> None:
    """Extract a digest-verified tar after a complete, link-safe preflight.

    Digest verification is deliberately the caller's preceding operation; this
    function proves that the same stable regular file is safe to materialize.
    """

    archive_path = Path(archive_path)
    output_path = Path(output_path)
    try:
        before = archive_path.lstat()
    except OSError as error:
        raise BuildError("archive unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or archive_path.is_symlink()
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_mode & 0o022
        or output_path.exists()
        or output_path.is_symlink()
    ):
        raise BuildError("archive identity invalid")
    if maximum_entries < 1 or maximum_expanded_bytes < 1:
        raise BuildError("archive limit invalid")

    entries: dict[PurePosixPath, tuple[tarfile.TarInfo, str]] = {}
    folded: set[str] = set()
    expanded = 0
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > maximum_entries:
                raise BuildError("archive entry count invalid")
            for info in members:
                relative = _safe_member_path(info.name, expected_root)
                if relative == PurePosixPath("."):
                    if not info.isdir():
                        raise BuildError("archive root invalid")
                    continue
                key = str(relative).casefold()
                if key in folded or relative in entries:
                    raise BuildError("archive path collision")
                folded.add(key)
                if info.isdir():
                    kind = "directory"
                    if info.size != 0 or info.linkname:
                        raise BuildError("archive directory invalid")
                elif info.isfile():
                    kind = "regular"
                    if info.size < 0 or info.linkname:
                        raise BuildError("archive file invalid")
                    expanded += info.size
                    if expanded > maximum_expanded_bytes:
                        raise BuildError("archive expanded size exceeded")
                elif info.issym():
                    kind = "symlink"
                    if info.size != 0:
                        raise BuildError("archive symlink invalid")
                    _safe_link_target(relative, info.linkname)
                else:
                    raise BuildError("archive entry type prohibited")
                entries[relative] = (info, kind)

            for relative, (_info, _kind) in entries.items():
                parent = relative.parent
                while parent != PurePosixPath("."):
                    parent_entry = entries.get(parent)
                    if parent_entry is not None and parent_entry[1] != "directory":
                        raise BuildError("archive parent is not a directory")
                    parent = parent.parent
            for relative, (info, kind) in entries.items():
                if kind != "symlink":
                    continue
                target = _safe_link_target(relative, info.linkname)
                target_entry = entries.get(target)
                if target_entry is None or target_entry[1] != "regular":
                    raise BuildError("archive link target is not a regular file")

            temporary_parent = output_path.parent
            temporary_parent.mkdir(parents=True, exist_ok=True)
            temporary = Path(
                tempfile.mkdtemp(prefix=f".{output_path.name}.extract.", dir=temporary_parent)
            )
            staged = temporary / "root"
            staged.mkdir(mode=0o700)
            try:
                for relative, (info, kind) in sorted(
                    entries.items(), key=lambda item: (len(item[0].parts), str(item[0]))
                ):
                    destination = staged.joinpath(*relative.parts)
                    if kind == "directory":
                        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
                    elif kind == "regular":
                        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        source = archive.extractfile(info)
                        if source is None:
                            raise BuildError("archive file body unavailable")
                        with source, destination.open("xb") as target:
                            copied = shutil.copyfileobj(source, target, 1024 * 1024)
                            del copied
                        if destination.stat().st_size != info.size:
                            raise BuildError("archive file size changed")
                        destination.chmod(0o500 if info.mode & 0o111 else 0o400)
                    else:
                        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        os.symlink(info.linkname, destination)
                for directory in sorted(
                    (path for path in staged.rglob("*") if path.is_dir()),
                    key=lambda path: len(path.parts),
                    reverse=True,
                ):
                    directory.chmod(0o500)
                after = archive_path.stat()
                if (
                    before.st_dev != after.st_dev
                    or before.st_ino != after.st_ino
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                ):
                    raise BuildError("archive changed during extraction")
                os.replace(staged, output_path)
                output_path.chmod(0o500)
            except BaseException:
                if staged.exists():
                    for path in sorted(staged.rglob("*"), reverse=True):
                        if path.is_dir() and not path.is_symlink():
                            path.chmod(0o700)
                        elif not path.is_symlink():
                            path.chmod(0o600)
                    staged.chmod(0o700)
                raise
            finally:
                shutil.rmtree(temporary, ignore_errors=True)
    except BuildError:
        if output_path.exists() or output_path.is_symlink():
            _remove_tree(output_path)
        raise
    except (OSError, tarfile.TarError) as error:
        if output_path.exists() or output_path.is_symlink():
            _remove_tree(output_path)
        raise BuildError("archive extraction failed") from error


def _runtime_pack_assets(document: Any) -> dict[str, str]:
    try:
        frameworks = document["project"]["frameworks"]
    except (KeyError, TypeError) as error:
        raise BuildError("restore assets schema invalid") from error
    discovered: dict[str, str] = {}
    if not isinstance(frameworks, dict):
        raise BuildError("restore assets frameworks invalid")
    for framework in frameworks.values():
        if not isinstance(framework, dict):
            raise BuildError("restore assets framework invalid")
        dependencies = framework.get("downloadDependencies", [])
        if not isinstance(dependencies, list):
            raise BuildError("restore assets dependencies invalid")
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                raise BuildError("restore assets dependency invalid")
            name = dependency.get("name")
            version = dependency.get("version")
            if (
                set(dependency) != {"name", "version"}
                or not isinstance(name, str)
                or not isinstance(version, str)
            ):
                raise BuildError("restore assets dependency invalid")
            if name in discovered:
                raise BuildError("restore runtime pack duplicated")
            discovered[name] = version
    return discovered


def _verify_runtime_pack_set(
    discovered: dict[str, str], runtime_version: str
) -> None:
    expected = f"[{runtime_version}, {runtime_version}]"
    valid = all(
        RUNTIME_PACK_NAME.fullmatch(name) is not None and version == expected
        for name, version in discovered.items()
    )
    if not valid:
        raise BuildError("restore runtime pack mismatch")


def layout_contract(
    *,
    source_root: Path,
    sdk_root: Path,
    nuget_root: Path,
    source_date_epoch: int,
    runner_version: str,
    restore_locked: bool,
) -> tuple[list[str], dict[str, str]]:
    """Return the sole locked, deterministic upstream layout invocation."""

    source_root = Path(source_root)
    sdk_root = Path(sdk_root)
    nuget_root = Path(nuget_root)
    if source_date_epoch < 1 or not runner_version or not isinstance(restore_locked, bool):
        raise BuildError("layout identity invalid")
    command = [
        str(sdk_root / "dotnet"),
        "msbuild",
        "-t:Layout",
        "-p:PackageRuntime=linux-x64",
        "-p:RuntimeIdentifier=linux-x64",
        "-p:RuntimeIdentifiers=linux-x64",
        "-p:BUILDCONFIG=Release",
        f"-p:RunnerVersion={runner_version}",
        f"-p:RestoreLockedMode={str(restore_locked).lower()}",
        "-p:RestorePackagesWithLockFile=true",
        "-p:TargetLatestRuntimePatch=true",
        "-p:ContinuousIntegrationBuild=true",
        "-p:Deterministic=true",
        f"-p:PathMap={source_root}=/src",
        str(source_root / "src" / "dir.proj"),
    ]
    environment = {
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_GENERATE_ASPNET_CERTIFICATE": "0",
        "DOTNET_NOLOGO": "1",
        "DOTNET_ROOT": str(sdk_root),
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "NUGET_PACKAGES": str(nuget_root),
        "SOURCE_DATE_EPOCH": str(source_date_epoch),
    }
    return command, environment


def normalize_runner_layout(root: Path) -> None:
    """Reject mutable/special residue and seal one complete runner layout."""

    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise BuildError("runner layout unavailable")
    paths = [root, *root.rglob("*")]
    for path in paths:
        relative = path.relative_to(root)
        folded_parts = {part.casefold() for part in relative.parts}
        if folded_parts & PROHIBITED_COMPONENTS or any(
            part.startswith(".credentials") for part in folded_parts
        ):
            raise BuildError("mutable runner residue")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            value = os.readlink(path)
            member = PurePosixPath(*relative.parts)
            target = _safe_link_target(member, value)
            resolved = root.joinpath(*target.parts)
            try:
                target_info = resolved.stat()
            except OSError as error:
                raise BuildError("runner symlink target unavailable") from error
            if not stat.S_ISREG(target_info.st_mode):
                raise BuildError("runner symlink target is not regular")
        elif stat.S_ISDIR(info.st_mode):
            continue
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise BuildError("runner layout entry prohibited")
    listener = root / "bin/Runner.Listener"
    if not listener.is_file() or listener.is_symlink():
        raise BuildError("runner listener missing")
    for relative in EXECUTABLE_LAYOUT_FILES:
        path = root / relative
        if path.exists():
            if not path.is_file() or path.is_symlink():
                raise BuildError("runner executable invalid")
            path.chmod(path.stat().st_mode | 0o100)
    for path in paths:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            continue
        if stat.S_ISDIR(info.st_mode):
            path.chmod(0o555)
        else:
            path.chmod(0o555 if info.st_mode & 0o111 else 0o444)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BuildError("duplicate JSON key")
        result[key] = value
    return result


def load_runner_release(path: Path) -> dict[str, Any]:
    """Load and independently validate the closed source-build authority."""

    try:
        info = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise BuildError("runner manifest unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or info.st_nlink != 1
        or not raw
        or len(raw) > 4 * 1024 * 1024
        or info.st_mode & 0o022
    ):
        raise BuildError("runner manifest identity invalid")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_float=lambda _value: (_ for _ in ()).throw(BuildError("float prohibited")),
            parse_constant=lambda _value: (_ for _ in ()).throw(BuildError("constant prohibited")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError("runner manifest JSON invalid") from error
    top_keys = {
        "build",
        "command_settings_sha256",
        "observation_evidence",
        "published_at",
        "schema_version",
        "source_commit_sha",
        "source_tree_sha",
        "tag_ref_sha",
        "version",
    }
    if not isinstance(value, dict) or set(value) != top_keys or canonical_json(value) != raw:
        raise BuildError("runner manifest schema invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != 2:
        raise BuildError("runner manifest version invalid")
    if VERSION.fullmatch(value.get("version", "")) is None:
        raise BuildError("runner version invalid")
    if any(
        HEX40.fullmatch(value.get(key, "")) is None
        for key in ("tag_ref_sha", "source_commit_sha", "source_tree_sha")
    ):
        raise BuildError("runner source identity invalid")
    if HEX64.fullmatch(value.get("command_settings_sha256", "")) is None:
        raise BuildError("runner command identity invalid")
    build = value.get("build")
    if not isinstance(build, dict) or set(build) != {
        "dotnet_sdk",
        "expected_listener_version",
        "externals",
        "nuget_locks",
    }:
        raise BuildError("runner build schema invalid")
    if build["expected_listener_version"] != value["version"][1:]:
        raise BuildError("runner listener identity invalid")

    dotnet = build["dotnet_sdk"]
    if not isinstance(dotnet, dict) or set(dotnet) != {
        "asset_name",
        "rid",
        "runtime_version",
        "sha512",
        "source_url",
        "version",
    }:
        raise BuildError("dotnet schema invalid")
    dotnet_version = dotnet.get("version")
    runtime_version = dotnet.get("runtime_version")
    if (
        not isinstance(dotnet_version, str)
        or re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", dotnet_version) is None
        or not isinstance(runtime_version, str)
        or re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", runtime_version) is None
        or dotnet.get("rid") != "linux-x64"
        or HEX128.fullmatch(dotnet.get("sha512", "")) is None
    ):
        raise BuildError("dotnet identity invalid")
    dotnet_name = f"dotnet-sdk-{dotnet_version}-linux-x64.tar.gz"
    if (
        dotnet.get("asset_name") != dotnet_name
        or dotnet.get("source_url")
        != f"https://builds.dotnet.microsoft.com/dotnet/Sdk/{dotnet_version}/{dotnet_name}"
    ):
        raise BuildError("dotnet source invalid")

    locks = build["nuget_locks"]
    files = locks.get("files") if isinstance(locks, dict) else None
    if (
        not isinstance(locks, dict)
        or set(locks) != {"aggregate_sha256", "files"}
        or not isinstance(files, list)
        or len(files) != len(LOCK_PATHS)
    ):
        raise BuildError("NuGet lock schema invalid")
    for expected, item in zip(LOCK_PATHS, files, strict=True):
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or item.get("path") != expected
            or HEX64.fullmatch(item.get("sha256", "")) is None
        ):
            raise BuildError("NuGet lock identity invalid")
    if locks.get("aggregate_sha256") != hashlib.sha256(
        canonical_json({"files": files})
    ).hexdigest():
        raise BuildError("NuGet lock aggregate invalid")

    externals = build["externals"]
    if not isinstance(externals, list) or len(externals) != len(EXTERNAL_LAYOUTS):
        raise BuildError("external schema invalid")
    for expected_layout, item in zip(EXTERNAL_LAYOUTS, externals, strict=True):
        if not isinstance(item, dict) or set(item) != {
            "asset_name",
            "layout",
            "sha256",
            "source_url",
            "version",
        }:
            raise BuildError("external schema invalid")
        version = item.get("version")
        if (
            item.get("layout") != expected_layout
            or not isinstance(version, str)
            or re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", version) is None
            or HEX64.fullmatch(item.get("sha256", "")) is None
        ):
            raise BuildError("external identity invalid")
        alpine = expected_layout.endswith("_alpine")
        name = (
            f"node-v{version}-alpine-x64.tar.gz"
            if alpine
            else f"node-v{version}-linux-x64.tar.gz"
        )
        url = (
            f"https://github.com/actions/alpine_nodejs/releases/download/v{version}/{name}"
            if alpine
            else f"https://nodejs.org/dist/v{version}/{name}"
        )
        if item.get("asset_name") != name or item.get("source_url") != url:
            raise BuildError("external source invalid")

    admitted = {key: item for key, item in value.items() if key != "observation_evidence"}
    evidence = hashlib.sha256(
        canonical_json(
            {
                "protocol": "portable-ghar-runner-source-release-v2",
                "runner_release": admitted,
            }
        )
    ).hexdigest()
    if value.get("observation_evidence") != evidence:
        raise BuildError("runner observation evidence invalid")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise BuildError("file digest unavailable") from error
    return digest.hexdigest()


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise BuildError("file digest unavailable") from error
    return digest.hexdigest()


def create_deterministic_runner_archive(root: Path, destination: Path) -> str:
    """Encode the sealed layout in the canonical archive form the Go verifier admits."""

    root = Path(root)
    destination = Path(destination)
    if not root.is_dir() or root.is_symlink() or destination.exists():
        raise BuildError("runner archive inputs invalid")
    entries = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    try:
        with destination.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    root_info = tarfile.TarInfo("./")
                    root_info.type = tarfile.DIRTYPE
                    root_info.mode = 0o555
                    root_info.uid = 0
                    root_info.gid = 0
                    root_info.mtime = 0
                    archive.addfile(root_info)
                    for path in entries:
                        relative = path.relative_to(root).as_posix()
                        info = path.lstat()
                        name = f"./{relative}"
                        header = tarfile.TarInfo(name + ("/" if stat.S_ISDIR(info.st_mode) else ""))
                        header.uid = 0
                        header.gid = 0
                        header.mtime = 0
                        if stat.S_ISDIR(info.st_mode):
                            header.type = tarfile.DIRTYPE
                            header.mode = 0o555
                            archive.addfile(header)
                        elif stat.S_ISREG(info.st_mode):
                            header.type = tarfile.REGTYPE
                            header.mode = 0o555 if info.st_mode & 0o111 else 0o444
                            header.size = info.st_size
                            with path.open("rb") as source:
                                archive.addfile(header, source)
                        elif stat.S_ISLNK(info.st_mode):
                            header.type = tarfile.SYMTYPE
                            header.mode = 0
                            header.linkname = os.readlink(path)
                            archive.addfile(header)
                        else:
                            raise BuildError("runner archive entry prohibited")
        destination.chmod(0o400)
    except BuildError:
        destination.unlink(missing_ok=True)
        raise
    except (OSError, tarfile.TarError) as error:
        destination.unlink(missing_ok=True)
        raise BuildError("runner archive encoding failed") from error
    return sha256_file(destination)


def _join_process_group(
    process: subprocess.Popen[bytes], leader_timeout: float
) -> tuple[int | None, bool]:
    """Boundedly reap the leader and release its entire private process group."""
    returncode: int | None = None
    released = True
    try:
        returncode = process.wait(timeout=max(0.0, leader_timeout))
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        released = False

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        released = False

    if returncode is None:
        try:
            returncode = process.wait(timeout=PROCESS_GROUP_JOIN_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            released = False

    deadline = time.monotonic() + PROCESS_GROUP_JOIN_SECONDS
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        except OSError:
            released = False
            break
        if time.monotonic() >= deadline:
            released = False
            break
        time.sleep(0.01)
    return returncode, released


def _subprocess_rejection(
    stage: str,
    returncode: int,
    stdout: bytes | bytearray,
    stderr: bytes | bytearray,
) -> str:
    disposition = (
        f"signal {-returncode}" if returncode < 0 else f"exit {returncode}"
    )
    diagnostics = DIAGNOSTIC_CODE.findall(bytes(stdout) + bytes(stderr))
    diagnostic = (
        f" diagnostic {diagnostics[-1].decode('ascii').lower()}"
        if diagnostics
        else ""
    )
    return f"{stage} subprocess rejected {disposition}{diagnostic}"


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    log: Path,
    timeout: int,
    stage: str,
    capture: bool = False,
    maximum: int = 4 * 1024 * 1024,
) -> bytes:
    if (
        not command
        or timeout < 1
        or maximum < 1
        or stage not in SUBPROCESS_STAGES
    ):
        raise BuildError("subprocess contract invalid")
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise BuildError(f"{stage} subprocess failed") from error

    selector = selectors.DefaultSelector()
    overflow = False
    failed = False
    deadline = time.monotonic() + timeout
    streams: list[Any] = []
    try:
        if capture and process.stdout is not None:
            selector.register(process.stdout, selectors.EVENT_READ, stdout_buffer)
            streams.append(process.stdout)
        if process.stderr is not None:
            selector.register(process.stderr, selectors.EVENT_READ, stderr_buffer)
            streams.append(process.stderr)
    except (KeyError, OSError, ValueError) as error:
        _join_process_group(process, 0.0)
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        raise BuildError(f"{stage} subprocess failed") from error
    pending_error: BaseException | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = True
                break
            try:
                events = selector.select(min(remaining, 0.25))
            except OSError:
                failed = True
                break
            for key, _events in events:
                try:
                    chunk = os.read(key.fd, 64 * 1024)
                except OSError:
                    failed = True
                    break
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer = key.data
                available = maximum - len(buffer)
                if len(chunk) > available:
                    buffer.extend(chunk[: max(available, 0)])
                    overflow = True
                    break
                buffer.extend(chunk)
            if failed or overflow:
                break
    except BaseException as error:
        failed = True
        pending_error = error
    finally:
        leader_timeout = 0.0 if failed or overflow else max(
            0.0, deadline - time.monotonic()
        )
        returncode, group_released = _join_process_group(process, leader_timeout)
        if returncode is None or not group_released:
            failed = True
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()
        try:
            with log.open("ab") as stream:
                if capture:
                    stream.write(stdout_buffer)
                stream.write(stderr_buffer)
        except OSError as error:
            raise BuildError(f"{stage} subprocess failed") from error

    if pending_error is not None:
        raise pending_error
    if overflow:
        raise BuildError(f"{stage} subprocess output exceeded bound")
    if failed:
        raise BuildError(f"{stage} subprocess failed")
    if returncode != 0:
        raise BuildError(
            _subprocess_rejection(stage, returncode, stdout_buffer, stderr_buffer)
        )
    return bytes(stdout_buffer)


def _capture_text(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    log: Path,
    stage: str,
    timeout: int = 60,
) -> str:
    raw = _run(
        command,
        cwd=cwd,
        environment=environment,
        log=log,
        timeout=timeout,
        stage=stage,
        capture=True,
    )
    try:
        return raw.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as error:
        raise BuildError(f"{stage} subprocess text invalid") from error


def _download(
    url: str,
    destination: Path,
    expected_digest: str,
    algorithm: str,
    *,
    environment: dict[str, str],
    log: Path,
    maximum_bytes: int,
) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
        or destination.exists()
    ):
        raise BuildError("download source invalid")
    partial = destination.with_name(f".{destination.name}.partial")
    if partial.exists() or partial.is_symlink():
        raise BuildError("download destination not empty")
    _run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "30",
            "--max-time",
            "900",
            "--max-filesize",
            str(maximum_bytes),
            "--output",
            str(partial),
            "--",
            url,
        ],
        cwd=destination.parent,
        environment=environment,
        log=log,
        timeout=930,
        stage="download",
    )
    try:
        info = partial.lstat()
    except OSError as error:
        raise BuildError("download result unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or partial.is_symlink()
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > maximum_bytes
    ):
        partial.unlink(missing_ok=True)
        raise BuildError("download result invalid")
    actual = sha512_file(partial) if algorithm == "sha512" else sha256_file(partial)
    if actual != expected_digest:
        partial.unlink(missing_ok=True)
        raise BuildError("download digest mismatch")
    partial.chmod(0o400)
    os.replace(partial, destination)


def _validate_private_empty_directory(path: Path) -> None:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
        entries = list(path.iterdir())
    except OSError as error:
        raise BuildError("work root unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or path.is_symlink()
        or resolved != path
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or entries
    ):
        raise BuildError("work root identity invalid")


def _validate_new_output(path: Path, work_root: Path) -> None:
    try:
        parent_info = path.parent.lstat()
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise BuildError("output parent unavailable") from error
    if (
        path.exists()
        or path.is_symlink()
        or not path.is_absolute()
        or path != Path(os.path.normpath(path))
        or not stat.S_ISDIR(parent_info.st_mode)
        or path.parent.is_symlink()
        or parent != path.parent
        or parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o022
        or path.is_relative_to(work_root)
        or work_root.is_relative_to(path)
    ):
        raise BuildError("output identity invalid")


def _clone_exact_source(
    release: dict[str, Any],
    destination: Path,
    *,
    environment: dict[str, str],
    log: Path,
) -> int:
    tag = release["version"]
    _run(
        ["git", "init", "--quiet", str(destination)],
        cwd=destination.parent,
        environment=environment,
        log=log,
        timeout=60,
        stage="source init",
    )
    _run(
        ["git", "remote", "add", "origin", "https://github.com/actions/runner.git"],
        cwd=destination,
        environment=environment,
        log=log,
        timeout=30,
        stage="source remote",
    )
    _run(
        [
            "git",
            "-c",
            "protocol.version=2",
            "fetch",
            "--depth=1",
            "--no-tags",
            "origin",
            f"refs/tags/{tag}:refs/tags/{tag}",
        ],
        cwd=destination,
        environment=environment,
        log=log,
        timeout=600,
        stage="source fetch",
    )
    _run(
        ["git", "checkout", "--quiet", "--detach", release["source_commit_sha"]],
        cwd=destination,
        environment=environment,
        log=log,
        timeout=120,
        stage="source checkout",
    )
    observations = {
        "origin": _capture_text(
            ["git", "remote", "get-url", "origin"],
            cwd=destination,
            environment=environment,
            log=log,
            stage="source identity",
        ),
        "tag_ref": _capture_text(
            ["git", "rev-parse", f"refs/tags/{tag}"],
            cwd=destination,
            environment=environment,
            log=log,
            stage="source identity",
        ),
        "tag_commit": _capture_text(
            ["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"],
            cwd=destination,
            environment=environment,
            log=log,
            stage="source identity",
        ),
        "commit": _capture_text(
            ["git", "rev-parse", "HEAD"],
            cwd=destination,
            environment=environment,
            log=log,
            stage="source identity",
        ),
        "tree": _capture_text(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=destination,
            environment=environment,
            log=log,
            stage="source identity",
        ),
        "dirty": _capture_text(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=destination,
            environment=environment,
            log=log,
            stage="source identity",
        ),
    }
    if observations != {
        "origin": "https://github.com/actions/runner.git",
        "tag_ref": release["tag_ref_sha"],
        "tag_commit": release["source_commit_sha"],
        "commit": release["source_commit_sha"],
        "tree": release["source_tree_sha"],
        "dirty": "",
    }:
        raise BuildError("runner source identity mismatch")
    epoch = _capture_text(
        ["git", "show", "-s", "--format=%ct", "HEAD"],
        cwd=destination,
        environment=environment,
        log=log,
        stage="source identity",
    )
    if not epoch.isdigit() or int(epoch) < 1:
        raise BuildError("runner source epoch invalid")
    version_path = destination / "src/runnerversion"
    command_path = destination / "src/Runner.Listener/CommandSettings.cs"
    try:
        version = version_path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise BuildError("runner source version unavailable") from error
    if version != release["version"][1:] or sha256_file(command_path) != release["command_settings_sha256"]:
        raise BuildError("runner source content mismatch")
    return int(epoch)


def _copy_locked_graph(
    release: dict[str, Any], repository: Path, source: Path
) -> None:
    lock_root = repository / "release/runner-source-locks"
    observed: list[dict[str, str]] = []
    for item in release["build"]["nuget_locks"]["files"]:
        relative = item["path"]
        source_lock = lock_root / relative
        destination = source / "src" / relative
        if sha256_file(source_lock) != item["sha256"] or destination.exists():
            raise BuildError("NuGet lock source mismatch")
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_lock, destination)
            destination.chmod(0o444)
        except OSError as error:
            raise BuildError("NuGet lock publication failed") from error
        if sha256_file(destination) != item["sha256"]:
            raise BuildError("NuGet lock publication changed")
        observed.append({"path": relative, "sha256": item["sha256"]})
    aggregate = hashlib.sha256(canonical_json({"files": observed})).hexdigest()
    if aggregate != release["build"]["nuget_locks"]["aggregate_sha256"]:
        raise BuildError("NuGet lock aggregate changed")


def _verify_locked_graph(release: dict[str, Any], source: Path) -> None:
    expected = {
        item["path"]: item["sha256"]
        for item in release["build"]["nuget_locks"]["files"]
    }
    root = source / "src"
    observed: dict[str, str] = {}
    try:
        candidates = tuple(root.rglob("packages.lock.json"))
        for candidate in candidates:
            metadata = candidate.lstat()
            relative = candidate.relative_to(root).as_posix()
            if not stat.S_ISREG(metadata.st_mode) or relative in observed:
                raise BuildError("NuGet lock changed")
            observed[relative] = sha256_file(candidate)
    except OSError as error:
        raise BuildError("NuGet lock changed") from error
    if observed != expected:
        raise BuildError("NuGet lock changed")


def _verify_sdk(
    sdk_root: Path,
    release: dict[str, Any],
    *,
    environment: dict[str, str],
    log: Path,
) -> None:
    dotnet = release["build"]["dotnet_sdk"]
    version = _capture_text(
        [str(sdk_root / "dotnet"), "--version"],
        cwd=sdk_root,
        environment=environment,
        log=log,
        stage="sdk version",
    )
    runtimes = _capture_text(
        [str(sdk_root / "dotnet"), "--list-runtimes"],
        cwd=sdk_root,
        environment=environment,
        log=log,
        stage="sdk runtime",
    ).splitlines()
    expected_runtime = dotnet["runtime_version"]
    observed = set()
    for line in runtimes:
        parts = line.split()
        if len(parts) >= 2:
            observed.add((parts[0], parts[1]))
    expected = {
        ("Microsoft.AspNetCore.App", expected_runtime),
        ("Microsoft.NETCore.App", expected_runtime),
    }
    if version != dotnet["version"] or observed != expected:
        raise BuildError("dotnet SDK/runtime mismatch")


def _verify_restore_assets(source: Path, runtime_version: str) -> None:
    observed: set[str] = set()
    for relative in LOCK_PATHS:
        project = relative.split("/", 1)[0]
        assets_path = source / "src" / project / "obj/project.assets.json"
        try:
            document = json.loads(assets_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise BuildError("restore assets unavailable") from error
        discovered = _runtime_pack_assets(document)
        _verify_runtime_pack_set(discovered, runtime_version)
        observed.update(discovered)
    if not observed:
        raise BuildError("restore runtime pack mismatch")


def _populate_externals(
    release: dict[str, Any],
    downloads: Path,
    layout: Path,
) -> None:
    externals_root = layout / "externals"
    try:
        externals_root.mkdir(mode=0o700)
    except OSError as error:
        raise BuildError("external layout unavailable") from error
    for item in release["build"]["externals"]:
        expected_root = None
        if not item["layout"].endswith("_alpine"):
            expected_root = item["asset_name"].removesuffix(".tar.gz")
        extract_verified_tar(
            downloads / item["asset_name"],
            externals_root / item["layout"],
            expected_root=expected_root,
            maximum_entries=MAX_ARCHIVE_ENTRIES,
            maximum_expanded_bytes=MAX_ARCHIVE_BYTES,
        )
        node = externals_root / item["layout"] / "bin/node"
        if not node.is_file() or node.is_symlink():
            raise BuildError("external node runtime missing")


def _validate_published_runtime(
    output: Path,
    release: dict[str, Any],
    payload_sha256: str,
) -> None:
    try:
        lock_raw = (output / "runner.runtime-lock.json").read_bytes()
        ready_raw = (output / "READY").read_bytes()
        lock = json.loads(
            lock_raw.decode("utf-8", "strict"), object_pairs_hook=_unique_object
        )
        ready = json.loads(
            ready_raw.decode("utf-8", "strict"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError("source runtime readback unavailable") from error
    ordered_lock = (
        json.dumps(lock, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if (
        not isinstance(lock, dict)
        or tuple(lock) != SOURCE_LOCK_KEYS
        or ordered_lock != lock_raw
    ):
        raise BuildError("source runtime lock noncanonical")
    listener = lock["listener"]
    expected = {
        "schema_version": 2,
        "runner_version": release["version"],
        "runner_payload_sha256": payload_sha256,
        "runner_source_commit": release["source_commit_sha"],
        "runner_source_tree": release["source_tree_sha"],
        "runner_release_evidence": release["observation_evidence"],
        "command_settings_sha256": release["command_settings_sha256"],
    }
    if any(lock.get(key) != value for key, value in expected.items()):
        raise BuildError("source runtime identity mismatch")
    if (
        type(lock["schema_version"]) is not int
        or not isinstance(listener, dict)
        or tuple(listener) != LISTENER_KEYS
        or listener["path"] != "/opt/actions-runner/bin/Runner.Listener"
        or HEX64.fullmatch(listener.get("sha256", "")) is None
        or type(listener.get("size")) is not int
        or listener["size"] < 1
        or type(listener.get("mode")) is not int
        or listener.get("mode") != 0o555
        or type(listener.get("uid")) is not int
        or listener.get("uid") != 0
        or type(listener.get("gid")) is not int
        or listener.get("gid") != 0
        or HEX64.fullmatch(lock.get("manifest_sha256", "")) is None
        or HEX64.fullmatch(lock.get("tree_lock_sha256", "")) is None
        or re.fullmatch(
            r"[^\s@]+@sha256:[0-9a-f]{64}", lock.get("runner_base_image", "")
        )
        is None
        or type(lock.get("evidence_generation")) is not int
        or lock["evidence_generation"] != 1
    ):
        raise BuildError("source runtime content invalid")
    ordered_ready = (
        json.dumps(ready, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if (
        not isinstance(ready, dict)
        or tuple(ready) != READY_KEYS
        or ordered_ready != ready_raw
        or type(ready.get("schema_version")) is not int
        or ready["schema_version"] != 1
        or type(ready.get("evidence_generation")) is not int
        or ready["evidence_generation"] != 1
        or ready.get("runtime_lock_sha256") != hashlib.sha256(lock_raw).hexdigest()
        or ready.get("manifest_sha256") != lock["manifest_sha256"]
        or ready.get("tree_lock_sha256") != lock["tree_lock_sha256"]
    ):
        raise BuildError("source runtime readiness mismatch")


def _remove_tree(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        path.unlink(missing_ok=True)
        return
    if path.exists():
        for child in sorted(path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if not child.is_symlink():
                try:
                    child.chmod(0o700 if child.is_dir() else 0o600)
                except OSError:
                    pass
        try:
            path.chmod(0o700)
        except OSError:
            pass
        shutil.rmtree(path, ignore_errors=True)


def _parse_arguments(arguments: list[str]) -> tuple[Path, Path, Path]:
    if len(arguments) != 6:
        raise BuildError("arguments invalid")
    values: dict[str, str] = {}
    for index in range(0, len(arguments), 2):
        name, value = arguments[index], arguments[index + 1]
        if name not in {"--runner-manifest", "--output", "--work-root"}:
            raise BuildError("argument unknown")
        if not value or name in values:
            raise BuildError("argument duplicated or empty")
        values[name] = value
    if len(values) != 3:
        raise BuildError("arguments incomplete")
    paths = tuple(Path(values[name]) for name in ("--runner-manifest", "--output", "--work-root"))
    if any(not path.is_absolute() or path != Path(os.path.normpath(path)) for path in paths):
        raise BuildError("argument path invalid")
    return paths  # type: ignore[return-value]


def main() -> int:
    manifest_path, output, work_root = _parse_arguments(sys.argv[1:])
    release = load_runner_release(manifest_path)
    _validate_private_empty_directory(work_root)
    _validate_new_output(output, work_root)
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise BuildError("Linux amd64 required")
    if any(shutil.which(command) is None for command in ("curl", "git", "go")):
        raise BuildError("source-build prerequisite unavailable")

    repository = Path(__file__).resolve(strict=True).parents[2]
    if not (repository / "go.mod").is_file() or not (repository / "release/runner-source-locks").is_dir():
        raise BuildError("product source unavailable")
    os.umask(0o077)
    log = work_root / "source-build.log"
    log.touch(mode=0o600)
    downloads = work_root / "downloads"
    home = work_root / "home"
    http_cache = work_root / "nuget-http"
    nuget = work_root / "nuget-packages"
    plugin_cache = work_root / "nuget-plugins"
    tools = work_root / "tools"
    for directory in (downloads, home, http_cache, nuget, plugin_cache, tools):
        directory.mkdir(mode=0o700)

    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(home),
        }
    )
    source = work_root / "actions-runner"
    source_epoch = _clone_exact_source(
        release,
        source,
        environment=environment,
        log=log,
    )
    _copy_locked_graph(release, repository, source)

    dotnet = release["build"]["dotnet_sdk"]
    sdk_archive = downloads / dotnet["asset_name"]
    _download(
        dotnet["source_url"],
        sdk_archive,
        dotnet["sha512"],
        "sha512",
        environment=environment,
        log=log,
        maximum_bytes=512 * 1024 * 1024,
    )
    for item in release["build"]["externals"]:
        _download(
            item["source_url"],
            downloads / item["asset_name"],
            item["sha256"],
            "sha256",
            environment=environment,
            log=log,
            maximum_bytes=256 * 1024 * 1024,
        )

    sdk_root = work_root / "dotnet-sdk"
    extract_verified_tar(
        sdk_archive,
        sdk_root,
        expected_root=None,
        maximum_entries=MAX_ARCHIVE_ENTRIES,
        maximum_expanded_bytes=MAX_ARCHIVE_BYTES,
    )
    command, build_values = layout_contract(
        source_root=source,
        sdk_root=sdk_root,
        nuget_root=nuget,
        source_date_epoch=source_epoch,
        runner_version=release["build"]["expected_listener_version"],
        restore_locked=True,
    )
    build_values.update(
        {
            "DOTNET_CLI_HOME": str(home),
            "DOTNET_MULTILEVEL_LOOKUP": "0",
            "NUGET_HTTP_CACHE_PATH": str(http_cache),
            "NUGET_PLUGINS_CACHE_PATH": str(plugin_cache),
            "PATH": f"{sdk_root}:{environment.get('PATH', '/usr/bin:/bin')}",
        }
    )
    build_environment = {**environment, **build_values}
    _verify_sdk(
        sdk_root,
        release,
        environment=build_environment,
        log=log,
    )
    _run(
        command,
        cwd=source / "src",
        environment=build_environment,
        log=log,
        timeout=3600,
        stage="runner layout",
        capture=True,
        maximum=32 * 1024 * 1024,
    )
    _verify_locked_graph(release, source)
    _verify_restore_assets(source, dotnet["runtime_version"])

    layout = source / "_layout"
    if not layout.is_dir() or layout.is_symlink():
        raise BuildError("runner layout missing")
    _populate_externals(release, downloads, layout)
    for pdb in layout.rglob("*.pdb"):
        if not pdb.is_file() or pdb.is_symlink():
            raise BuildError("runner symbol residue invalid")
        pdb.unlink()
    diagnostic = layout / "_diag"
    if diagnostic.exists() or diagnostic.is_symlink():
        _remove_tree(diagnostic)
    listener = layout / "bin/Runner.Listener"
    listener.chmod(listener.stat().st_mode | 0o100)
    listener_version = _capture_text(
        [str(listener), "--version"],
        cwd=layout,
        environment=build_environment,
        log=log,
        stage="listener version",
        timeout=120,
    )
    if listener_version != release["build"]["expected_listener_version"]:
        raise BuildError("runner listener version mismatch")
    normalize_runner_layout(layout)

    payload_archive = work_root / (
        f"actions-runner-source-linux-x64-{release['version'][1:]}.tar.gz"
    )
    payload_sha256 = create_deterministic_runner_archive(layout, payload_archive)
    runtime_lock = tools / "portable-ghar-runtime-lock"
    _run(
        [
            "go",
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-o",
            str(runtime_lock),
            "./cmd/portable-ghar-runtime-lock",
        ],
        cwd=repository,
        environment=environment,
        log=log,
        timeout=1800,
        stage="runtime lock build",
        capture=True,
        maximum=16 * 1024 * 1024,
    )
    runtime_lock.chmod(0o500)
    staged_runtime = work_root / "runner-runtime"
    _run(
        [
            str(runtime_lock),
            "extract-source-runner",
            "--archive",
            str(payload_archive),
            "--sha256",
            payload_sha256,
            "--generation",
            "1",
            "--output-dir",
            str(staged_runtime),
        ],
        cwd=repository,
        environment=environment,
        log=log,
        timeout=1800,
        stage="runtime lock publish",
        capture=True,
        maximum=4 * 1024 * 1024,
    )
    _validate_published_runtime(staged_runtime, release, payload_sha256)
    try:
        os.replace(staged_runtime, output)
        parent_descriptor = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as error:
        if output.exists() or output.is_symlink():
            _remove_tree(output)
        raise BuildError("source runtime publication failed") from error
    return 0


def _closed_failure_reason(error: BuildError) -> str:
    message = str(error)
    if re.fullmatch(r"[a-z][a-z0-9 ]{0,79}", message) is None:
        return "internal-error"
    return message.replace(" ", "-")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as error:
        print(
            "build-runner-from-source: unavailable "
            f"reason={_closed_failure_reason(error)}",
            file=sys.stderr,
        )
        raise SystemExit(1)
