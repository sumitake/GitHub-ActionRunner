#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Build one closed Portable-GHAR Linux/amd64 release tree in a private,
# disposable transaction. This script never publishes and never mutates the
# caller checkout. All diagnostics remain private; its public failure surface
# is deliberately closed.

set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: rehearse-runtime.sh --release-kind candidate|product --version VERSION --runner-manifest PATH --output PATH' >&2
}

if [ "$#" -ne 8 ] ||
  [ "$1" != "--release-kind" ] ||
  [ "$3" != "--version" ] ||
  [ "$5" != "--runner-manifest" ] ||
  [ "$7" != "--output" ]; then
  usage
  exit 2
fi

release_kind=$2
version=$4
runner_manifest=$6
output=$8

python3 - "$release_kind" "$version" "$runner_manifest" "$output" "$(dirname "$0")/../.." <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse


class RehearsalError(Exception):
    pass


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RUNNER_VERSION = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
RUNNER_KEYS = {
    "schema_version",
    "version",
    "tag_ref_sha",
    "source_commit_sha",
    "linux_x64_asset_name",
    "linux_x64_asset_size",
    "linux_x64_asset_digest",
    "published_at",
    "command_settings_sha256",
    "observation_evidence",
}
RUNTIME_MANIFEST_KEYS = {
    "schema_version",
    "platform",
    "debian_snapshot",
    "runner_release",
    "tools",
    "binaries",
    "images",
    "candidate_protected_files",
    "candidate_substitutions",
    "license_exceptions",
}
TOKEN_NAMES = {
    "version_bare",
    "linux_x64_sha256",
    "source_commit",
    "command_settings_sha256",
}
MAX_JSON = 32 * 1024 * 1024
MAX_TOOL_BYTES = 512 * 1024 * 1024
UINT64_MAX = (1 << 64) - 1
ASSET_REDIRECT_HOST = "release-assets.githubusercontent.com"
BASELINE_AUTHORITY_PATH = "release/manifest.json"
IDENTITY_INVENTORY_PATTERN = re.compile(
    rb"(?<![0-9A-Za-z])v?((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    rb"(?:0|[1-9][0-9]*))(?![0-9]|\.[0-9])"
    rb"|(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{40})(?![0-9a-f])"
)


def reject(_message="unavailable"):
    raise RehearsalError(_message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject("duplicate JSON key")
        result[key] = value
    return result


def reject_float(_value):
    reject("floating JSON number")


def reject_constant(_value):
    reject("non-finite JSON number")


def load_json_bytes(raw):
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=unique_object,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("invalid JSON")


def read_json(path):
    try:
        st = path.lstat()
        if (
            not stat.S_ISREG(st.st_mode)
            or stat.S_ISLNK(st.st_mode)
            or st.st_nlink != 1
            or st.st_size < 1
            or st.st_size > MAX_JSON
        ):
            reject("unsafe JSON input")
        return load_json_bytes(path.read_bytes())
    except OSError:
        reject("unreadable JSON input")


def canonical_json(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
    except OSError:
        reject("unreadable file")
    return digest.hexdigest()


def safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        reject("unsafe path")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        reject("unsafe path")
    pure = pathlib.PurePosixPath(value)
    if pure.is_absolute() or str(pure) != value:
        reject("unsafe path")
    if any(part in ("", ".", "..") for part in pure.parts):
        reject("unsafe path")
    return value


def validate_new_output(value):
    path = pathlib.Path(value)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        reject("output path")
    else:
        reject("output already exists")
    try:
        parent_st = path.parent.lstat()
        parent = path.parent.resolve(strict=True)
    except OSError:
        reject("output parent")
    if (
        not stat.S_ISDIR(parent_st.st_mode)
        or path.parent.is_symlink()
        or parent != path.parent.absolute()
        or path.name in ("", ".", "..")
    ):
        reject("output parent")
    return parent / path.name


def version_tuple(value):
    if not isinstance(value, str):
        reject("runner version")
    match = RUNNER_VERSION.fullmatch(value)
    if match is None:
        reject("runner version")
    parts = tuple(int(item, 10) for item in match.groups())
    if any(item > UINT64_MAX for item in parts):
        reject("runner version")
    return parts


def evidence_digest(value):
    digest = hashlib.sha256()
    fields = (
        value["version"],
        value["tag_ref_sha"],
        value["source_commit_sha"],
        value["linux_x64_asset_name"],
        value["linux_x64_asset_size"],
        value["linux_x64_asset_digest"],
        value["published_at"],
    )
    for item in ("portable-ghar-runner-release-observation-v1", *fields):
        raw = str(item).encode("utf-8")
        digest.update(struct.pack(">Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


def validate_runner(value):
    if not isinstance(value, dict) or set(value) != RUNNER_KEYS:
        reject("runner manifest schema")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        reject("runner manifest schema")
    version_tuple(value["version"])
    for key in ("tag_ref_sha", "source_commit_sha"):
        if not isinstance(value[key], str) or HEX40.fullmatch(value[key]) is None:
            reject("runner commit")
    expected_name = f"actions-runner-linux-x64-{value['version'][1:]}.tar.gz"
    if value["linux_x64_asset_name"] != expected_name:
        reject("runner asset")
    if (
        type(value["linux_x64_asset_size"]) is not int
        or value["linux_x64_asset_size"] < 1
        or value["linux_x64_asset_size"] > 1024 * 1024 * 1024
    ):
        reject("runner asset")
    if (
        not isinstance(value["linux_x64_asset_digest"], str)
        or DIGEST.fullmatch(value["linux_x64_asset_digest"]) is None
    ):
        reject("runner digest")
    if (
        not isinstance(value["published_at"], str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            value["published_at"],
        )
        is None
    ):
        reject("runner publication")
    for key in ("command_settings_sha256", "observation_evidence"):
        if not isinstance(value[key], str) or HEX64.fullmatch(value[key]) is None:
            reject("runner evidence")
    if value["observation_evidence"] != evidence_digest(value):
        reject("runner observation evidence")
    return value


def validate_release_manifest(root):
    if not isinstance(root, dict) or set(root) != {"version", "subjects", "runtime"}:
        reject("release manifest schema")
    if root["version"] != 1 or root["subjects"] != ["portable-ghar-*.tar.gz"]:
        reject("release manifest schema")
    runtime = root["runtime"]
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_MANIFEST_KEYS:
        reject("runtime manifest schema")
    if (
        runtime["schema_version"] != 1
        or runtime["platform"] != "linux/amd64"
        or runtime["debian_snapshot"] != "20250101T000000Z"
    ):
        reject("runtime manifest identity")
    validate_runner(runtime["runner_release"])

    tools = runtime["tools"]
    if not isinstance(tools, dict) or set(tools) != {
        "buildx",
        "buildkit",
        "syft",
        "trivy",
    }:
        reject("tool registry")
    for name in ("buildx", "syft", "trivy"):
        tool = tools[name]
        if (
            not isinstance(tool, dict)
            or set(tool) != {"version", "asset_name", "sha256", "source_url"}
            or not isinstance(tool["version"], str)
            or not isinstance(tool["asset_name"], str)
            or not isinstance(tool["source_url"], str)
            or HEX64.fullmatch(tool["sha256"]) is None
            or not tool["source_url"].startswith("https://github.com/")
        ):
            reject("tool identity")
    buildkit = tools["buildkit"]
    if (
        not isinstance(buildkit, dict)
        or set(buildkit) != {"image", "platform_digest"}
        or not isinstance(buildkit["image"], str)
        or "@sha256:" not in buildkit["image"]
        or not isinstance(buildkit["platform_digest"], str)
        or DIGEST.fullmatch(buildkit["platform_digest"]) is None
    ):
        reject("buildkit identity")

    binaries = runtime["binaries"]
    if not isinstance(binaries, list) or not binaries:
        reject("binary registry")
    names = []
    packages = []
    for entry in binaries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"name", "package"}
            or not isinstance(entry["name"], str)
            or re.fullmatch(r"portable-ghar(?:-[a-z0-9-]+)?", entry["name"]) is None
            or not isinstance(entry["package"], str)
            or re.fullmatch(r"\./cmd/portable-ghar(?:-[a-z0-9-]+)?", entry["package"])
            is None
        ):
            reject("binary registry")
        names.append(entry["name"])
        packages.append(entry["package"])
    if names != sorted(names) or len(set(names)) != len(names) or len(set(packages)) != len(
        packages
    ):
        reject("binary registry")
    if "portable-ghar-synthetic-listener" in names:
        reject("binary registry")

    images = runtime["images"]
    if not isinstance(images, list) or not images:
        reject("image registry")
    image_names = []
    for entry in images:
        if not isinstance(entry, dict) or set(entry) != {
            "name",
            "context",
            "dockerfile",
        }:
            reject("image registry")
        name = entry["name"]
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is None
            or entry["context"] != f"images/{name}"
            or entry["dockerfile"] != f"images/{name}/Dockerfile"
        ):
            reject("image registry")
        image_names.append(name)
    if (
        image_names != sorted(image_names)
        or len(set(image_names)) != len(image_names)
        or "synthetic-listener" in image_names
    ):
        reject("image registry")

    substitutions = runtime["candidate_substitutions"]
    if not isinstance(substitutions, list) or not substitutions:
        reject("substitution registry")
    seen = set()
    for entry in substitutions:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "token", "count", "replace"}
            or safe_relative(entry["path"]) != entry["path"]
            or entry["token"] not in TOKEN_NAMES
            or type(entry["count"]) is not int
            or entry["count"] < 1
            or type(entry["replace"]) is not bool
        ):
            reject("substitution registry")
        key = (entry["path"], entry["token"])
        if key in seen:
            reject("substitution registry")
        seen.add(key)
    protected_files = runtime["candidate_protected_files"]
    if not isinstance(protected_files, list) or not protected_files:
        reject("protected file registry")
    protected_paths = []
    for entry in protected_files:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "identity_inventory_sha256"}
            or safe_relative(entry["path"]) != entry["path"]
            or entry["path"] == BASELINE_AUTHORITY_PATH
            or not isinstance(entry["identity_inventory_sha256"], str)
            or HEX64.fullmatch(entry["identity_inventory_sha256"]) is None
        ):
            reject("protected file registry")
        protected_paths.append(entry["path"])
    if (
        protected_paths != sorted(protected_paths)
        or len(set(protected_paths)) != len(protected_paths)
        or set(protected_paths) != {path for path, _token in seen}
    ):
        reject("protected file registry")
    exceptions = runtime["license_exceptions"]
    if not isinstance(exceptions, list):
        reject("license exceptions")
    exception_seen = set()
    for entry in exceptions:
        if (
            not isinstance(entry, dict)
            or set(entry)
            != {"subject", "purl", "version", "license_expression", "reason"}
            or not all(isinstance(entry[key], str) and entry[key] for key in entry)
            or any("*" in entry[key] or "?" in entry[key] for key in entry)
        ):
            reject("license exceptions")
        key = (entry["subject"], entry["purl"], entry["version"])
        if key in exception_seen:
            reject("license exceptions")
        exception_seen.add(key)
    return runtime


def run(command, *, cwd, env, log, timeout):
    try:
        with log.open("ab") as stream:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout,
            )
    except (OSError, subprocess.TimeoutExpired):
        reject("subprocess failure")
    if completed.returncode != 0:
        reject("subprocess failure")


def capture(command, *, cwd, env, log, timeout, maximum=MAX_JSON):
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        reject("subprocess failure")
    try:
        with log.open("ab") as stream:
            stream.write(completed.stderr[:maximum])
    except OSError:
        reject("private log")
    if completed.returncode != 0 or len(completed.stdout) > maximum:
        reject("subprocess failure")
    return completed.stdout


def curl_download(
    url,
    destination,
    expected_sha,
    env,
    log,
    maximum=MAX_TOOL_BYTES,
):
    parsed_source = urllib.parse.urlsplit(url)
    if (
        parsed_source.scheme != "https"
        or parsed_source.hostname != "github.com"
        or parsed_source.netloc != "github.com"
        or parsed_source.username is not None
        or parsed_source.password is not None
        or parsed_source.fragment
        or parsed_source.query
    ):
        reject("download source")

    def transfer(transfer_url):
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            reject("download")
        else:
            reject("download")
        command = [
            "curl",
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--request",
            "GET",
            "--proto",
            "=https",
            "--connect-timeout",
            "30",
            "--max-time",
            "900",
            "--max-redirs",
            "0",
            "--retry",
            "2",
            "--retry-delay",
            "1",
            "--max-filesize",
            str(maximum),
            "--output",
            os.fspath(destination),
            "--write-out",
            "%{http_code}\n%{redirect_url}",
            transfer_url,
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=destination.parent,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=930,
            )
        except (OSError, subprocess.TimeoutExpired):
            reject("download")
        try:
            with log.open("ab") as stream:
                stream.write(completed.stderr[:MAX_JSON])
        except OSError:
            reject("private log")
        if completed.returncode != 0 or len(completed.stdout) > 8192:
            reject("download")
        try:
            rendered = completed.stdout.decode("utf-8", "strict")
        except UnicodeDecodeError:
            reject("download")
        status_text, separator, redirect = rendered.partition("\n")
        if (
            re.fullmatch(r"[0-9]{3}", status_text) is None
            or not separator
            or "\n" in redirect
        ):
            reject("download")
        try:
            st = destination.lstat()
        except OSError:
            reject("download")
        if (
            not stat.S_ISREG(st.st_mode)
            or stat.S_ISLNK(st.st_mode)
            or st.st_nlink != 1
            or st.st_size > maximum
        ):
            reject("download")
        return int(status_text), redirect

    status, redirect = transfer(url)
    if status == 302 and redirect:
        parsed = urllib.parse.urlsplit(redirect)
        if (
            parsed.scheme != "https"
            or parsed.hostname != ASSET_REDIRECT_HOST
            or parsed.netloc != ASSET_REDIRECT_HOST
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            reject("download redirect")
        try:
            destination.unlink()
        except OSError:
            reject("download redirect")
        second_status, second_redirect = transfer(redirect)
        if second_status != 200 or second_redirect:
            reject("download redirect")
    elif status != 200 or redirect:
        reject("download redirect")
    try:
        st = destination.lstat()
    except OSError:
        reject("download")
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size < 1:
        reject("download")
    if st.st_size > maximum:
        reject("download")
    if sha256_file(destination) != expected_sha:
        reject("download digest")


def extract_one_binary(archive_path, binary_name, destination):
    matches = []
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                normalized = member.name.removeprefix("./")
                if normalized == binary_name:
                    matches.append(member)
            if len(matches) != 1:
                reject("tool archive")
            member = matches[0]
            if not member.isfile() or member.linkname or member.size > 512 * 1024 * 1024:
                reject("tool archive")
            source = archive.extractfile(member)
            if source is None:
                reject("tool archive")
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o500,
            )
            with os.fdopen(descriptor, "wb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
                target.flush()
                os.fsync(target.fileno())
    except (OSError, tarfile.TarError):
        reject("tool archive")


def candidate_identity_inventory(raw):
    inventory = []
    for match in IDENTITY_INVENTORY_PATTERN.finditer(raw):
        if match.group(1) is not None:
            inventory.append(["runner-version", match.group(1).decode("ascii")])
        else:
            value = match.group(2).decode("ascii")
            inventory.append([f"hex{len(value)}", value])
    return inventory


def candidate_identity_inventory_sha256(raw):
    return sha256_bytes(canonical_json(candidate_identity_inventory(raw)))


def apply_candidate_overlay(clone, runtime, candidate):
    baseline = runtime["runner_release"]
    old = {
        "version_bare": baseline["version"][1:],
        "linux_x64_sha256": baseline["linux_x64_asset_digest"].removeprefix(
            "sha256:"
        ),
        "source_commit": baseline["source_commit_sha"],
        "command_settings_sha256": baseline["command_settings_sha256"],
    }
    new = {
        "version_bare": candidate["version"][1:],
        "linux_x64_sha256": candidate["linux_x64_asset_digest"].removeprefix(
            "sha256:"
        ),
        "source_commit": candidate["source_commit_sha"],
        "command_settings_sha256": candidate["command_settings_sha256"],
    }
    table = runtime["candidate_substitutions"]
    protected_registry = {
        entry["path"]: entry["identity_inventory_sha256"]
        for entry in runtime["candidate_protected_files"]
    }
    protected_inventories = {}
    protected_totals = {name: 0 for name in TOKEN_NAMES}
    for entry in table:
        path = clone / entry["path"]
        try:
            st = path.lstat()
            raw = path.read_bytes()
        except OSError:
            reject("substitution path")
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
            reject("substitution path")
        if entry["path"] not in protected_registry:
            reject("protected file registry")
        if entry["path"] not in protected_inventories:
            if candidate_identity_inventory_sha256(raw) != protected_registry[entry["path"]]:
                reject("protected identity inventory")
            protected_inventories[entry["path"]] = candidate_identity_inventory(raw)
        needle = old[entry["token"]].encode("ascii")
        if raw.count(needle) != entry["count"]:
            reject("substitution count")
        protected_totals[entry["token"]] += entry["count"]

    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=clone,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if tracked.returncode != 0:
        reject("tracked inventory")
    observed = {name: 0 for name in TOKEN_NAMES}
    candidate_observed = {name: 0 for name in TOKEN_NAMES}
    for raw_path in tracked.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8", "strict")
        if relative == BASELINE_AUTHORITY_PATH:
            continue
        try:
            path = clone / relative
            st = path.lstat()
            content = path.read_bytes()
        except OSError:
            reject("tracked inventory")
        if (
            not stat.S_ISREG(st.st_mode)
            or stat.S_ISLNK(st.st_mode)
            or st.st_nlink != 1
        ):
            reject("tracked inventory")
        for token, value in old.items():
            observed[token] += content.count(value.encode("ascii"))
            if new[token] != value:
                candidate_observed[token] += content.count(new[token].encode("ascii"))
    if observed != protected_totals:
        reject("protected token closure")
    if any(candidate_observed.values()):
        reject("candidate token preexistence")

    for entry in table:
        if not entry["replace"]:
            continue
        path = clone / entry["path"]
        raw = path.read_bytes()
        token = entry["token"]
        before = old[token].encode("ascii")
        after = new[token].encode("ascii")
        if before != after:
            raw = raw.replace(before, after)
            path.write_bytes(raw)

    expected_old = {name: 0 for name in TOKEN_NAMES}
    expected_new = {name: 0 for name in TOKEN_NAMES}
    for entry in table:
        token = entry["token"]
        if old[token] == new[token]:
            expected_old[token] += entry["count"]
        elif entry["replace"]:
            expected_new[token] += entry["count"]
        else:
            expected_old[token] += entry["count"]

    observed_old = {name: 0 for name in TOKEN_NAMES}
    observed_new = {name: 0 for name in TOKEN_NAMES}
    for raw_path in tracked.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8", "strict")
        if relative == BASELINE_AUTHORITY_PATH:
            continue
        try:
            content = (clone / relative).read_bytes()
        except OSError:
            reject("tracked inventory")
        for token in TOKEN_NAMES:
            observed_old[token] += content.count(old[token].encode("ascii"))
            if new[token] != old[token]:
                observed_new[token] += content.count(new[token].encode("ascii"))
    if observed_old != expected_old or observed_new != expected_new:
        reject("substitution result")

    replacements_by_path = {}
    for entry in table:
        if not entry["replace"] or old[entry["token"]] == new[entry["token"]]:
            continue
        key = (entry["token"], old[entry["token"]])
        replacements_by_path.setdefault(entry["path"], {})[key] = (
            new[entry["token"]],
            entry["count"],
        )
    for relative, before_inventory in protected_inventories.items():
        remaining = {
            key: count
            for key, (_replacement, count) in replacements_by_path.get(
                relative, {}
            ).items()
        }
        expected_inventory = []
        for kind, value in before_inventory:
            replacement = None
            for (token, old_value), (new_value, _count) in replacements_by_path.get(
                relative, {}
            ).items():
                expected_kind = {
                    "version_bare": "runner-version",
                    "linux_x64_sha256": "hex64",
                    "source_commit": "hex40",
                    "command_settings_sha256": "hex64",
                }[token]
                if kind == expected_kind and value == old_value:
                    if replacement is not None and replacement != new_value:
                        reject("protected identity inventory")
                    replacement = new_value
                    remaining[(token, old_value)] -= 1
            expected_inventory.append([kind, replacement or value])
        if any(value != 0 for value in remaining.values()):
            reject("protected identity inventory")
        try:
            after_inventory = candidate_identity_inventory(
                (clone / relative).read_bytes()
            )
        except OSError:
            reject("protected identity inventory")
        if after_inventory != expected_inventory:
            reject("protected identity inventory")

    for entry in table:
        try:
            content = (clone / entry["path"]).read_bytes()
        except OSError:
            reject("substitution path")
        token = entry["token"]
        if old[token] == new[token] or not entry["replace"]:
            if content.count(old[token].encode("ascii")) != entry["count"]:
                reject("substitution result")
        elif (
            content.count(old[token].encode("ascii")) != 0
            or content.count(new[token].encode("ascii")) != entry["count"]
        ):
            reject("substitution result")


def validate_dockerfiles(clone, runtime):
    try:
        snapshot_check = subprocess.run(
            [
                sys.executable,
                "scripts/ci/check_runner_debian_snapshot.py",
            ],
            cwd=clone,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        reject("runner Debian snapshot contract")
    if (
        snapshot_check.returncode != 0
        or snapshot_check.stdout
        != b"check-runner-debian-snapshot: verified\n"
        or snapshot_check.stderr
    ):
        reject("runner Debian snapshot contract")

    snapshot_lock = read_json(
        clone / "images/runner/debian-snapshot.lock.json"
    )
    try:
        expected_sources = [
            (
                "deb [check-valid-until=no] "
                "https://snapshot.debian.org/archive/"
                f"{row['archive']}/{snapshot_lock['snapshot']} "
                f"{row['suite']} {row['component']}"
            )
            for row in snapshot_lock["sources"]
        ]
    except (KeyError, TypeError):
        reject("runner Debian snapshot contract")

    acquirers = []
    for entry in runtime["images"]:
        dockerfile = clone / entry["dockerfile"]
        try:
            text = dockerfile.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            reject("Dockerfile")
        for line in text.splitlines():
            stripped = line.strip()
            if re.match(r"(?i)^FROM(?:\s|$)", stripped):
                match = re.fullmatch(
                    r"(?i)FROM[ \t]+([^ \t]+)(?:[ \t]+AS[ \t]+[A-Za-z0-9._-]+)?",
                    stripped,
                )
                if match is None:
                    reject("base image")
                image = match.group(1)
                if (
                    "$" in image
                    or (
                        image != "scratch"
                        and re.fullmatch(r"[^@ \t]+@sha256:[0-9a-f]{64}", image)
                        is None
                    )
                ):
                    reject("mutable base image")
        if "deb.debian.org" in text or "security.debian.org" in text:
            reject("moving package source")
        if "apt-get" in text:
            acquirers.append(entry["name"])
            if (
                "ARG SOURCE_DATE_EPOCH" not in text
                or any(source not in text for source in expected_sources)
            ):
                reject("package snapshot")
    if acquirers != ["runner"]:
        reject("package acquisition registry")


def inspect_buildkit(raw, expected):
    root = load_json_bytes(raw)
    if not isinstance(root, dict):
        reject("BuildKit manifest")
    if isinstance(root.get("manifests"), list):
        matches = []
        for descriptor in root["manifests"]:
            if not isinstance(descriptor, dict):
                reject("BuildKit manifest")
            if descriptor.get("platform") == {"architecture": "amd64", "os": "linux"}:
                matches.append(descriptor.get("digest"))
        if matches != [expected]:
            reject("BuildKit platform")
    else:
        reject("BuildKit index")


def normalize_spdx(raw_path, output_path, subject, digest, source_epoch):
    value = read_json(raw_path)
    required = {
        "SPDXID",
        "spdxVersion",
        "dataLicense",
        "name",
        "documentNamespace",
        "creationInfo",
        "packages",
        "relationships",
    }
    allowed = required | {
        "documentDescribes",
        "files",
        "annotations",
        "externalDocumentRefs",
        "hasExtractedLicensingInfos",
        "comment",
        "revieweds",
    }
    if not isinstance(value, dict) or not required.issubset(value) or set(value) - allowed:
        reject("SPDX schema")
    creation = value["creationInfo"]
    if not isinstance(creation, dict) or "creators" not in creation:
        reject("SPDX creation")
    created = datetime.datetime.fromtimestamp(
        source_epoch, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    creation["created"] = created
    value["name"] = f"portable-ghar-{subject}"
    value["documentNamespace"] = (
        f"https://github.com/sumitake/portable-ghar/sbom/{subject}/{digest}"
    )
    sort_keys = {
        "documentDescribes": lambda item: str(item),
        "packages": lambda item: str(item.get("SPDXID", "")),
        "files": lambda item: str(item.get("SPDXID", "")),
        "relationships": lambda item: (
            str(item.get("spdxElementId", "")),
            str(item.get("relationshipType", "")),
            str(item.get("relatedSpdxElement", "")),
        ),
        "annotations": lambda item: canonical_json(item),
        "externalDocumentRefs": lambda item: str(item.get("externalDocumentId", "")),
        "hasExtractedLicensingInfos": lambda item: str(item.get("licenseId", "")),
        "revieweds": lambda item: canonical_json(item),
    }
    for key, function in sort_keys.items():
        if key in value:
            if not isinstance(value[key], list):
                reject("SPDX array")
            value[key] = sorted(value[key], key=function)
    output_path.write_bytes(canonical_json(value))


def package_purl(package):
    refs = package.get("externalRefs", [])
    if not isinstance(refs, list):
        reject("SPDX external refs")
    values = []
    for ref in refs:
        if (
            isinstance(ref, dict)
            and ref.get("referenceType") == "purl"
            and isinstance(ref.get("referenceLocator"), str)
        ):
            values.append(ref["referenceLocator"])
    if len(set(values)) != 1:
        reject("package purl")
    return values[0]


def generate_notices(sbom_rows, exceptions, output):
    exception_map = {
        (entry["subject"], entry["purl"], entry["version"]): entry
        for entry in exceptions
    }
    used_exceptions = set()
    rows = []
    for subject, path in sbom_rows:
        value = read_json(path)
        packages = value.get("packages")
        if not isinstance(packages, list):
            reject("SPDX packages")
        for package in packages:
            if not isinstance(package, dict):
                reject("SPDX package")
            name = package.get("name")
            version = package.get("versionInfo")
            if not isinstance(name, str) or not name:
                reject("package name")
            if not isinstance(version, str) or not version or version == "NOASSERTION":
                reject("package version")
            purl = package_purl(package)
            concluded = package.get("licenseConcluded")
            declared = package.get("licenseDeclared")
            license_expression = concluded
            if license_expression in (None, "", "NOASSERTION"):
                license_expression = declared
            key = (subject, purl, version)
            if license_expression in (None, "", "NOASSERTION"):
                exception = exception_map.get(key)
                if exception is None:
                    reject("package license")
                license_expression = exception["license_expression"]
                used_exceptions.add(key)
            elif key in exception_map:
                exception = exception_map[key]
                if exception["license_expression"] != license_expression:
                    reject("license exception drift")
                used_exceptions.add(key)
            rows.append((subject, purl, version, license_expression, name))
    if used_exceptions != set(exception_map):
        reject("unused license exception")
    rows = sorted(set(rows))
    lines = [
        "Portable-GHAR Third-Party Notices",
        "",
        "subject\tpurl\tversion\tlicense\tpackage",
    ]
    lines.extend("\t".join(row) for row in rows)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def oci_graph(path):
    member_names = set()
    small = {}
    try:
        with tarfile.open(path, mode="r:") as archive:
            for member in archive:
                name = member.name.rstrip("/") if member.isdir() else member.name
                safe_relative(name)
                if member.isdir():
                    continue
                if not member.isfile() or member.linkname or name in member_names:
                    reject("OCI member")
                member_names.add(name)
                if name in ("index.json", "oci-layout"):
                    if member.size > MAX_JSON:
                        reject("OCI authority size")
                    source = archive.extractfile(member)
                    if source is None:
                        reject("OCI member")
                    small[name] = source.read()
    except (OSError, tarfile.TarError):
        reject("OCI archive")
    if set(("index.json", "oci-layout")) - set(small):
        reject("OCI layout")
    if load_json_bytes(small["oci-layout"]) != {"imageLayoutVersion": "1.0.0"}:
        reject("OCI layout")
    index_raw = small["index.json"]
    index = load_json_bytes(index_raw)
    if (
        not isinstance(index, dict)
        or index.get("schemaVersion") != 2
        or not isinstance(index.get("manifests"), list)
        or len(index["manifests"]) != 1
    ):
        reject("OCI index")
    descriptor = index["manifests"][0]
    if (
        not isinstance(descriptor, dict)
        or descriptor.get("platform") != {"architecture": "amd64", "os": "linux"}
    ):
        reject("OCI platform")
    manifest_digest = descriptor.get("digest")
    if not isinstance(manifest_digest, str) or DIGEST.fullmatch(manifest_digest) is None:
        reject("OCI manifest")
    manifest_name = f"blobs/sha256/{manifest_digest.removeprefix('sha256:')}"
    if manifest_name not in member_names:
        reject("OCI manifest")
    try:
        with tarfile.open(path, mode="r:") as archive:
            member = archive.getmember(manifest_name)
            if member.size > MAX_JSON:
                reject("OCI manifest size")
            source = archive.extractfile(member)
            if source is None:
                reject("OCI manifest")
            manifest_raw = source.read()
    except (OSError, KeyError, tarfile.TarError):
        reject("OCI manifest")
    if f"sha256:{sha256_bytes(manifest_raw)}" != manifest_digest:
        reject("OCI manifest")
    manifest = load_json_bytes(manifest_raw)
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        reject("OCI manifest")
    config = manifest.get("config")
    layers = manifest.get("layers")
    if not isinstance(config, dict) or not isinstance(layers, list):
        reject("OCI manifest")
    config_digest = config.get("digest")
    if not isinstance(config_digest, str) or DIGEST.fullmatch(config_digest) is None:
        reject("OCI config")
    layer_digests = []
    for layer in layers:
        if not isinstance(layer, dict):
            reject("OCI layer")
        digest = layer.get("digest")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            reject("OCI layer")
        layer_digests.append(digest)
    expected_blobs = {manifest_digest, config_digest, *layer_digests}
    actual_blobs = {
        f"sha256:{name.removeprefix('blobs/sha256/')}"
        for name in member_names
        if name.startswith("blobs/sha256/")
    }
    if actual_blobs != expected_blobs:
        reject("OCI blob closure")
    descriptor_sizes = {
        manifest_digest: descriptor.get("size"),
        config_digest: config.get("size"),
        **{layer.get("digest"): layer.get("size") for layer in layers},
    }
    if any(type(size) is not int or size < 0 for size in descriptor_sizes.values()):
        reject("OCI descriptor size")
    try:
        with tarfile.open(path, mode="r:") as archive:
            for digest, expected_size in descriptor_sizes.items():
                name = f"blobs/sha256/{digest.removeprefix('sha256:')}"
                member = archive.getmember(name)
                if member.size != expected_size:
                    reject("OCI descriptor size")
                source = archive.extractfile(member)
                if source is None:
                    reject("OCI blob")
                hasher = hashlib.sha256()
                total = 0
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    hasher.update(block)
                    total += len(block)
                if total != expected_size or f"sha256:{hasher.hexdigest()}" != digest:
                    reject("OCI blob")
    except (OSError, KeyError, tarfile.TarError):
        reject("OCI blob")
    return {
        "index_digest": f"sha256:{sha256_bytes(index_raw)}",
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
        "layer_digests": layer_digests,
    }


def add_subject(subjects, stage, relative, subject_type, graph=None):
    safe_relative(relative)
    path = stage / relative
    try:
        st = path.lstat()
    except OSError:
        reject("subject")
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
        reject("subject")
    record = {
        "path": relative,
        "type": subject_type,
        "size": st.st_size,
        "sha256": sha256_file(path),
    }
    if graph is not None:
        record["oci_graph"] = graph
    subjects.append(record)


def write_authority_files(
    stage,
    release_kind,
    version,
    source_commit,
    source_tree,
    source_epoch,
    release_manifest_sha,
    runner,
    tools,
    subjects,
):
    subjects.sort(key=lambda item: item["path"].encode("utf-8"))
    runner_raw = (stage / "runner-release.json").read_bytes()
    runtime = {
        "schema_version": 1,
        "release_kind": release_kind,
        "version": version,
        "platform": "linux/amd64",
        "source": {
            "commit": source_commit,
            "tree": source_tree,
            "source_date_epoch": source_epoch,
        },
        "release_manifest_sha256": release_manifest_sha,
        "runner_manifest_sha256": sha256_bytes(runner_raw),
        "runner_release": runner,
        "tools": tools,
        "subjects": subjects,
    }
    runtime_path = stage / "runtime-release.json"
    runtime_path.write_bytes(canonical_json(runtime))

    checksum_paths = sorted(
        [item["path"] for item in subjects] + ["runtime-release.json"],
        key=lambda item: item.encode("utf-8"),
    )
    checksum_path = stage / "checksums.txt"
    checksum_path.write_text(
        "".join(f"{sha256_file(stage / path)}  {path}\n" for path in checksum_paths),
        encoding="utf-8",
    )
    provenance_paths = sorted(
        checksum_paths + ["checksums.txt"], key=lambda item: item.encode("utf-8")
    )
    provenance = {
        "schema_version": 1,
        "subjects": [
            {
                "path": path,
                "sha256": sha256_file(stage / path),
                "size": (stage / path).stat().st_size,
            }
            for path in provenance_paths
        ],
    }
    (stage / "provenance-subjects.json").write_bytes(canonical_json(provenance))


def main():
    if len(sys.argv) != 6:
        return 2
    release_kind, version, runner_manifest_arg, output_arg, repository_arg = sys.argv[1:]
    if release_kind not in ("candidate", "product"):
        reject("release kind")
    if (
        not SAFE_VERSION.fullmatch(version)
        or ".." in version
        or len(version.encode("utf-8")) > 128
    ):
        reject("release version")
    output = validate_new_output(output_arg)
    runner_path = pathlib.Path(runner_manifest_arg)
    runner = validate_runner(read_json(runner_path))
    try:
        runner_input_raw = runner_path.read_bytes()
    except OSError:
        reject("runner manifest")
    if canonical_json(runner) != runner_input_raw:
        reject("runner manifest canonicalization")
    repository = pathlib.Path(repository_arg).resolve(strict=True)
    release_manifest_path = repository / "release/manifest.json"
    release_manifest_raw = release_manifest_path.read_bytes()
    release_root = load_json_bytes(release_manifest_raw)
    runtime = validate_release_manifest(release_root)
    baseline = runtime["runner_release"]
    relation = (
        version_tuple(runner["version"]) > version_tuple(baseline["version"])
    )
    if release_kind == "product" and runner != baseline:
        reject("product runner identity")
    if release_kind == "candidate" and (not relation or runner == baseline):
        reject("candidate runner identity")

    # All cheap, non-mutating validation precedes host/tool/network admission.
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        reject("Linux amd64 required")
    required_commands = (
        "curl",
        "docker",
        "git",
        "go",
        "jq",
        "python3",
        "tar",
    )
    if any(shutil.which(command) is None for command in required_commands):
        reject("missing prerequisite")
    dirty = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if dirty.returncode != 0 or dirty.stdout:
        reject("dirty source")

    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    source_tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=repository, text=True
    ).strip()
    source_epoch_text = subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", "HEAD"], cwd=repository, text=True
    ).strip()
    if (
        HEX40.fullmatch(source_commit) is None
        or HEX40.fullmatch(source_tree) is None
        or not source_epoch_text.isdigit()
        or int(source_epoch_text) < 1
    ):
        reject("source identity")
    source_epoch = int(source_epoch_text)

    work = pathlib.Path(
        tempfile.mkdtemp(prefix=".runtime-rehearsal.", dir=os.fspath(output.parent))
    ).resolve(strict=True)
    os.chmod(work, 0o700)
    log = work / "rehearsal.log"
    log.touch(mode=0o600)
    clone = work / "source"
    stage = work / "artifact-tree"
    downloads = work / "downloads"
    tools_directory = work / "tools"
    caches = work / "caches"
    docker_config = work / "docker-config"
    builder_name = f"pghar-{os.getpid()}-{time.monotonic_ns()}"
    loaded_image = None
    inspection_container = None
    env = os.environ.copy()
    builder_created = False
    output_committed = False
    try:
        for directory in (downloads, tools_directory, caches, docker_config):
            directory.mkdir(mode=0o700)
        run(
            [
                "git",
                "clone",
                "--no-local",
                "--no-checkout",
                "--",
                os.fspath(repository),
                os.fspath(clone),
            ],
            cwd=work,
            env=env,
            log=log,
            timeout=300,
        )
        run(
            ["git", "checkout", "--detach", source_commit],
            cwd=clone,
            env=env,
            log=log,
            timeout=120,
        )
        if (
            capture(
                ["git", "rev-parse", "HEAD"],
                cwd=clone,
                env=env,
                log=log,
                timeout=30,
            ).decode().strip()
            != source_commit
            or capture(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=clone,
                env=env,
                log=log,
                timeout=30,
            ).decode().strip()
            != source_tree
        ):
            reject("clone identity")

        # Runner transfer and independent size/hash proof happen before the
        # candidate overlay or any archive use.
        runner_archive = downloads / runner["linux_x64_asset_name"]
        runner_url = (
            "https://github.com/actions/runner/releases/download/"
            f"{runner['version']}/{runner['linux_x64_asset_name']}"
        )
        curl_download(
            runner_url,
            runner_archive,
            runner["linux_x64_asset_digest"].removeprefix("sha256:"),
            env,
            log,
            maximum=runner["linux_x64_asset_size"],
        )
        if runner_archive.stat().st_size != runner["linux_x64_asset_size"]:
            reject("runner asset size")
        os.chmod(runner_archive, 0o400)

        apply_candidate_overlay(clone, runtime, runner)
        validate_dockerfiles(clone, runtime)
        if release_kind == "product":
            if capture(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=clone,
                env=env,
                log=log,
                timeout=30,
            ):
                reject("product overlay")

        env.update(
            {
                "HOME": os.fspath(work / "home"),
                "DOCKER_CONFIG": os.fspath(docker_config),
                "GOCACHE": os.fspath(caches / "go-build"),
                "GOMODCACHE": os.fspath(caches / "go-mod"),
                "GOPATH": os.fspath(caches / "gopath"),
                "GOTOOLCHAIN": "go1.26.6",
                "SOURCE_DATE_EPOCH": str(source_epoch),
                "TRIVY_CACHE_DIR": os.fspath(caches / "trivy"),
                "SYFT_CHECK_FOR_APP_UPDATE": "false",
                "TRIVY_DISABLE_VEX_NOTICE": "true",
            }
        )
        for path in (
            pathlib.Path(env["HOME"]),
            pathlib.Path(env["GOCACHE"]),
            pathlib.Path(env["GOMODCACHE"]),
            pathlib.Path(env["GOPATH"]),
            pathlib.Path(env["TRIVY_CACHE_DIR"]),
        ):
            path.mkdir(parents=True, mode=0o700)

        identity_raw = capture(
            [
                "go",
                "run",
                "./internal/buildinfo/cmd/portable-ghar-build-identity",
                version,
                source_commit,
            ],
            cwd=clone,
            env=env,
            log=log,
            timeout=120,
        )
        if (
            not identity_raw.endswith(b"\n")
            or b"\n" in identity_raw[:-1]
            or b"\r" in identity_raw
        ):
            reject("binary identity")
        try:
            identity_stamp = identity_raw[:-1].decode("ascii", "strict")
        except UnicodeDecodeError:
            reject("binary identity")
        if not identity_stamp:
            reject("binary identity")
        identity_ldflags = (
            "-s -w -buildid= "
            f"-X github.com/sumitake/portable-ghar/internal/buildinfo.version={version} "
            f"-X github.com/sumitake/portable-ghar/internal/buildinfo.commit={source_commit} "
            f"-X github.com/sumitake/portable-ghar/internal/buildinfo.stamp={identity_stamp}"
        )
        run(
            [
                "go",
                "test",
                "-run",
                "^TestLinkedIdentity$",
                "-count=1",
                f"-ldflags={identity_ldflags}",
                "./internal/buildinfo",
            ],
            cwd=clone,
            env={
                **env,
                "PGHAR_EXPECTED_BUILD_VERSION": version,
                "PGHAR_EXPECTED_BUILD_COMMIT": source_commit,
            },
            log=log,
            timeout=1800,
        )

        acquired = {}
        for name in ("buildx", "syft", "trivy"):
            tool = runtime["tools"][name]
            archive = downloads / tool["asset_name"]
            curl_download(tool["source_url"], archive, tool["sha256"], env, log)
            if name == "buildx":
                target = docker_config / "cli-plugins/docker-buildx"
                target.parent.mkdir(mode=0o700)
                shutil.copyfile(archive, target)
                os.chmod(target, 0o500)
            else:
                target = tools_directory / name
                extract_one_binary(archive, name, target)
            acquired[name] = target

        buildx_version = capture(
            ["docker", "buildx", "version"],
            cwd=clone,
            env=env,
            log=log,
            timeout=30,
        ).decode("utf-8", "strict")
        if runtime["tools"]["buildx"]["version"] not in buildx_version:
            reject("buildx version")
        raw_buildkit = capture(
            [
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                "--raw",
                runtime["tools"]["buildkit"]["image"],
            ],
            cwd=clone,
            env=env,
            log=log,
            timeout=300,
        )
        inspect_buildkit(
            raw_buildkit, runtime["tools"]["buildkit"]["platform_digest"]
        )
        run(
            [
                "docker",
                "buildx",
                "create",
                "--name",
                builder_name,
                "--driver",
                "docker-container",
                "--driver-opt",
                f"image={runtime['tools']['buildkit']['image']}",
                "--use",
            ],
            cwd=clone,
            env=env,
            log=log,
            timeout=120,
        )
        builder_created = True
        run(
            ["docker", "buildx", "inspect", "--bootstrap", builder_name],
            cwd=clone,
            env=env,
            log=log,
            timeout=300,
        )

        # Prepare every test/release image context, then run the complete gate.
        run(
            ["scripts/prepare-task6-images.sh"],
            cwd=clone,
            env=env,
            log=log,
            timeout=1800,
        )
        ca_bundle = clone / "images/trust/build/ca-bundle.pem"
        try:
            resolved_ca_bundle = ca_bundle.resolve(strict=True)
        except OSError:
            reject("CA bundle path")
        if resolved_ca_bundle != ca_bundle or not ca_bundle.is_file():
            reject("CA bundle path")
        run(
            [
                "scripts/prepare-task5-images.sh",
                "--generation",
                "1",
                "--runner-archive",
                os.fspath(runner_archive),
                "--ca-bundle",
                os.fspath(resolved_ca_bundle),
            ],
            cwd=clone,
            env=env,
            log=log,
            timeout=1800,
        )
        run(
            ["scripts/prepare-task11-images.sh", "--generation", "1"],
            cwd=clone,
            env=env,
            log=log,
            timeout=1800,
        )
        gate_env = env.copy()
        gate_env["PGHAR_INTEGRATION_DOCKER"] = "1"
        gate_env["PGHAR_CHAOS_DOCKER"] = "1"
        gate_raw = capture(
            ["scripts/test-controller-runtime.sh", "--release"],
            cwd=clone,
            env=gate_env,
            log=log,
            timeout=7200,
        )
        gate = load_json_bytes(gate_raw)
        if (
            not isinstance(gate, dict)
            or gate.get("schema_version") != 1
            or gate.get("gate") != "portable-ghar-controller-runtime"
            or gate.get("mode") != "release"
            or gate.get("status") != "pass"
            or gate.get("failed_stage") is not None
            or gate.get("linux_docker") != "ready"
        ):
            reject("full runtime gate")

        for relative in ("bin", "images", "sbom", "notices"):
            (stage / relative).mkdir(parents=True, mode=0o755)
        if release_kind == "product":
            (stage / "source").mkdir(mode=0o755)

        subjects = []
        for entry in runtime["binaries"]:
            destination = stage / "bin" / entry["name"]
            run(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-buildvcs=false",
                    f"-ldflags={identity_ldflags}",
                    "-o",
                    os.fspath(destination),
                    entry["package"],
                ],
                cwd=clone,
                env={
                    **env,
                    "CGO_ENABLED": "0",
                    "GOOS": "linux",
                    "GOARCH": "amd64",
                },
                log=log,
                timeout=1800,
            )
            os.chmod(destination, 0o555)
            raw_head = destination.read_bytes()[:64]
            if (
                len(raw_head) < 20
                or raw_head[:4] != b"\x7fELF"
                or raw_head[4:6] != b"\x02\x01"
                or int.from_bytes(raw_head[18:20], "little") != 62
            ):
                reject("binary platform")
            binary_bytes = destination.read_bytes()
            if identity_stamp.encode("ascii") not in binary_bytes:
                reject("binary identity")
            if (
                b"portable-ghar-build-identity-v1|dev|unknown"
                in binary_bytes
            ):
                reject("binary identity")
            if (
                os.fspath(clone).encode() in binary_bytes
                or os.fspath(repository).encode() in binary_bytes
            ):
                reject("embedded build path")
            add_subject(
                subjects,
                stage,
                f"bin/{entry['name']}",
                "binary",
            )

        for entry in runtime["images"]:
            archive = stage / "images" / f"{entry['name']}.oci.tar"
            reference = f"portable-ghar/{entry['name']}:{source_commit}"
            command = [
                "docker",
                "buildx",
                "build",
                "--builder",
                builder_name,
                "--platform",
                "linux/amd64",
                "--provenance=false",
                "--sbom=false",
                "--pull",
                "--no-cache",
                "--file",
                entry["dockerfile"],
                "--tag",
                reference,
                "--output",
                f"type=oci,dest={archive},rewrite-timestamp=true",
            ]
            if entry["name"] == "runner":
                command.extend(["--build-arg", f"SOURCE_DATE_EPOCH={source_epoch}"])
            command.append(entry["context"])
            run(command, cwd=clone, env=env, log=log, timeout=3600)
            os.chmod(archive, 0o444)
            graph = oci_graph(archive)
            add_subject(
                subjects,
                stage,
                f"images/{entry['name']}.oci.tar",
                "oci-image",
                graph,
            )
            if entry["name"] == "runner":
                loaded_image = f"portable-ghar-runner-check:{source_commit}"
                inspection_container = (
                    f"pghar-inspect-{os.getpid()}-{time.monotonic_ns()}"
                )
                load_command = [
                    "docker",
                    "buildx",
                    "build",
                    "--builder",
                    builder_name,
                    "--platform",
                    "linux/amd64",
                    "--provenance=false",
                    "--sbom=false",
                    "--pull",
                    "--no-cache",
                    "--file",
                    entry["dockerfile"],
                    "--tag",
                    loaded_image,
                    "--build-arg",
                    f"SOURCE_DATE_EPOCH={source_epoch}",
                    "--load",
                    entry["context"],
                ]
                run(load_command, cwd=clone, env=env, log=log, timeout=3600)
                expected_version = runner["version"][1:]
                inspection = capture(
                    [
                        "docker",
                        "run",
                        "--name",
                        inspection_container,
                        "--user",
                        "0:0",
                        "--entrypoint",
                        "/bin/sh",
                        loaded_image,
                        "-ceu",
                        (
                            'test "$(/opt/actions-runner/bin/Runner.Listener --version)" = "$1"; '
                            'test "$(find /opt/actions-runner -type f -name Runner.Listener | wc -l)" = 1; '
                            "test ! -e /opt/actions-runner/_work; "
                            "test ! -e /opt/actions-runner/_update; "
                            "test -f /opt/portable-ghar/runner.READY; "
                            "test -f /opt/portable-ghar/runner.tree-lock; "
                            "test -f /opt/portable-ghar/runner.runtime-lock.json"
                        ),
                        "runner-inspect",
                        expected_version,
                    ],
                    cwd=clone,
                    env=env,
                    log=log,
                    timeout=120,
                )
                if inspection:
                    reject("runner inspection")
                run(
                    ["docker", "container", "rm", "-f", inspection_container],
                    cwd=clone,
                    env=env,
                    log=log,
                    timeout=120,
                )
                inspection_container = None

        if release_kind == "product":
            run(
                [
                    "scripts/release/package-source.sh",
                    version,
                    os.fspath(stage / "source"),
                ],
                cwd=clone,
                env=env,
                log=log,
                timeout=300,
            )
            source_relative = f"source/portable-ghar-{version}.tar.gz"
            source_path = stage / source_relative
            os.chmod(source_path, 0o444)
            add_subject(subjects, stage, source_relative, "source-archive")

        # Runner identity is a primary authority subject.
        runner_path_out = stage / "runner-release.json"
        runner_path_out.write_bytes(canonical_json(runner))
        os.chmod(runner_path_out, 0o444)
        add_subject(subjects, stage, "runner-release.json", "runner-manifest")

        # Pinned Trivy is a live-DB fail-closed admission gate, deliberately
        # excluded from byte-reproducibility evidence.
        trivy = os.fspath(acquired["trivy"])
        run(
            [
                trivy,
                "fs",
                "--scanners",
                "vuln,secret",
                "--severity",
                "HIGH,CRITICAL",
                "--exit-code",
                "1",
                "--no-progress",
                os.fspath(clone),
            ],
            cwd=clone,
            env=env,
            log=log,
            timeout=3600,
        )
        # Image scans admit only findings an upstream fix exists for. The
        # pinned Debian base permanently carries unfixable HIGH/CRITICAL
        # entries (no vendor fix published), so blocking on them would leave
        # the gate with no achievable green state; the scheduled
        # vulnerability-watch workflow turns red the week any of them gains a
        # fix, and every package version remains recorded in the SBOMs. The
        # source fs scan above deliberately keeps unfixed findings blocking.
        for entry in runtime["images"]:
            run(
                [
                    trivy,
                    "image",
                    "--input",
                    os.fspath(stage / "images" / f"{entry['name']}.oci.tar"),
                    "--scanners",
                    "vuln,secret",
                    "--severity",
                    "HIGH,CRITICAL",
                    "--ignore-unfixed",
                    "--exit-code",
                    "1",
                    "--no-progress",
                ],
                cwd=clone,
                env=env,
                log=log,
                timeout=3600,
            )

        syft = os.fspath(acquired["syft"])
        sbom_rows = []
        artifact_rows = [
            (item["name"], f"bin/{item['name']}", "sbom")
            for item in runtime["binaries"]
        ] + [
            (item["name"], f"images/{item['name']}.oci.tar", "sbom")
            for item in runtime["images"]
        ]
        if release_kind == "product":
            artifact_rows.append(
                ("source", f"source/portable-ghar-{version}.tar.gz", "source-sbom")
            )
        for subject_name, relative, subject_type in artifact_rows:
            raw_sbom = work / f"{subject_name}.raw.spdx.json"
            normalized = stage / "sbom" / f"{subject_name}.spdx.json"
            scheme = "oci-archive" if relative.startswith("images/") else "file"
            run(
                [
                    syft,
                    "scan",
                    f"{scheme}:{relative}",
                    "--output",
                    f"spdx-json={raw_sbom}",
                ],
                cwd=stage,
                env=env,
                log=log,
                timeout=1800,
            )
            normalize_spdx(
                raw_sbom,
                normalized,
                subject_name,
                sha256_file(stage / relative),
                source_epoch,
            )
            os.chmod(normalized, 0o444)
            add_subject(
                subjects,
                stage,
                f"sbom/{subject_name}.spdx.json",
                subject_type,
            )
            sbom_rows.append((relative, normalized))

        notices = stage / "notices/THIRD-PARTY-NOTICES.txt"
        generate_notices(sbom_rows, runtime["license_exceptions"], notices)
        os.chmod(notices, 0o444)
        add_subject(
            subjects,
            stage,
            "notices/THIRD-PARTY-NOTICES.txt",
            "notices",
        )

        write_authority_files(
            stage,
            release_kind,
            version,
            source_commit,
            source_tree,
            source_epoch,
            sha256_bytes(release_manifest_raw),
            runner,
            runtime["tools"],
            subjects,
        )
        for name in (
            "runtime-release.json",
            "checksums.txt",
            "provenance-subjects.json",
        ):
            os.chmod(stage / name, 0o444)

        text_authorities = [
            stage / "runner-release.json",
            stage / "runtime-release.json",
            stage / "checksums.txt",
            stage / "provenance-subjects.json",
            notices,
            *sorted((stage / "sbom").glob("*.spdx.json")),
        ]
        expected_text = {
            "runner-release.json",
            "runtime-release.json",
            "checksums.txt",
            "provenance-subjects.json",
            "notices/THIRD-PARTY-NOTICES.txt",
            *{f"sbom/{path.name}" for path in (stage / "sbom").glob("*.spdx.json")},
        }
        actual_text = {
            path.relative_to(stage).as_posix() for path in text_authorities
        }
        if actual_text != expected_text:
            reject("text authority registry")
        sanitizer_command = ["python3", "scripts/sanitize_public.py"]
        for path in text_authorities:
            sanitizer_command.extend(["--generated", os.fspath(path)])
        run(
            sanitizer_command,
            cwd=clone,
            env=env,
            log=log,
            timeout=600,
        )
        run(
            [
                trivy,
                "fs",
                "--scanners",
                "vuln,secret",
                "--severity",
                "HIGH,CRITICAL",
                "--exit-code",
                "1",
                "--no-progress",
                os.fspath(stage),
            ],
            cwd=clone,
            env=env,
            log=log,
            timeout=3600,
        )

        for directory, dirnames, filenames in os.walk(stage):
            os.chmod(directory, 0o755)
            for filename in filenames:
                path = pathlib.Path(directory) / filename
                relative = path.relative_to(stage).as_posix()
                subject = next(
                    (item for item in subjects if item["path"] == relative), None
                )
                os.chmod(path, 0o555 if subject and subject["type"] == "binary" else 0o444)

        comparator = clone / "scripts/release/compare-runtime-rebuilds.sh"
        run(
            [os.fspath(comparator), os.fspath(stage), os.fspath(stage)],
            cwd=clone,
            env=env,
            log=log,
            timeout=1800,
        )

        if loaded_image is not None:
            run(
                ["docker", "image", "rm", "-f", loaded_image],
                cwd=clone,
                env=env,
                log=log,
                timeout=120,
            )
            loaded_image = None
        if builder_created:
            run(
                ["docker", "buildx", "rm", "-f", builder_name],
                cwd=clone,
                env=env,
                log=log,
                timeout=180,
            )
            builder_created = False

        try:
            os.rename(stage, output)
        except OSError:
            reject("atomic output")
        output_committed = True
        directory_fd = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return 0
    finally:
        cleanup_failed = False
        failed_before_cleanup = sys.exc_info()[0] is not None
        if inspection_container is not None:
            try:
                completed = subprocess.run(
                    ["docker", "container", "rm", "-f", inspection_container],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=120,
                    check=False,
                )
                if completed.returncode != 0:
                    cleanup_failed = True
            except (OSError, subprocess.SubprocessError):
                cleanup_failed = True
        if loaded_image is not None:
            try:
                completed = subprocess.run(
                    ["docker", "image", "rm", "-f", loaded_image],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=120,
                    check=False,
                )
                if completed.returncode != 0:
                    cleanup_failed = True
            except (OSError, subprocess.SubprocessError):
                cleanup_failed = True
        if builder_created:
            try:
                completed = subprocess.run(
                    ["docker", "buildx", "rm", "-f", builder_name],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=180,
                    check=False,
                )
                if completed.returncode != 0:
                    cleanup_failed = True
            except (OSError, subprocess.SubprocessError):
                cleanup_failed = True
        try:
            if work.exists():
                for root, directories, files in os.walk(work):
                    for name in directories:
                        try:
                            os.chmod(pathlib.Path(root) / name, 0o700)
                        except OSError:
                            pass
                    for name in files:
                        try:
                            os.chmod(pathlib.Path(root) / name, 0o600)
                        except OSError:
                            pass
                shutil.rmtree(work)
        except OSError:
            cleanup_failed = True
        if output_committed and (failed_before_cleanup or cleanup_failed):
            try:
                if output.exists():
                    shutil.rmtree(output)
                    parent_fd = os.open(output.parent, os.O_RDONLY)
                    try:
                        os.fsync(parent_fd)
                    finally:
                        os.close(parent_fd)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            reject("cleanup")


try:
    raise SystemExit(main())
except RehearsalError:
    print("rehearse-runtime: unavailable", file=sys.stderr)
    raise SystemExit(1)
except (OSError, subprocess.SubprocessError, UnicodeError, ValueError, OverflowError):
    print("rehearse-runtime: unavailable", file=sys.stderr)
    raise SystemExit(1)
except KeyboardInterrupt:
    raise SystemExit(130)
PY
