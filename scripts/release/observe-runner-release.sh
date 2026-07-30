#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Observe the one current official actions/runner Linux x64 release and emit a
# canonical candidate manifest only when it is strictly newer than the
# checked-in baseline. Exit 3 means "no newer candidate"; every ambiguity is a
# hard failure and no output is written.

set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: observe-runner-release.sh --current-manifest PATH --output PATH' >&2
}

if [ "$#" -ne 4 ] || [ "$1" != "--current-manifest" ] || [ "$3" != "--output" ]; then
  usage
  exit 2
fi

current_manifest=$2
output=$4

python3 - "$current_manifest" "$output" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile


class ObservationError(Exception):
    pass


class DuplicateKeyError(ObservationError):
    pass


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
UTC_SECONDS = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
UINT64_MAX = (1 << 64) - 1
MAX_API_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
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


def fail(message="unavailable"):
    raise ObservationError(message)


def reject_float(_value):
    fail("floating-point JSON number")


def reject_constant(_value):
    fail("non-finite JSON number")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate JSON key")
        result[key] = value
    return result


def load_json_bytes(raw):
    try:
        text = raw.decode("utf-8", "strict")
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKeyError):
        fail("invalid JSON")


def read_bounded(path, maximum):
    try:
        size = path.stat().st_size
    except OSError:
        fail()
    if size < 1 or size > maximum:
        fail("response size")
    try:
        return path.read_bytes()
    except OSError:
        fail()


def request(url, destination, maximum, accept):
    command = [
        "curl",
        "--disable",
        "--fail",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--connect-timeout",
        "10",
        "--max-time",
        "45",
        "--retry",
        "2",
        "--retry-delay",
        "1",
        "--retry-max-time",
        "90",
        "--max-redirs",
        "0",
        "--max-filesize",
        str(maximum),
        "--header",
        f"Accept: {accept}",
        "--header",
        "X-GitHub-Api-Version: 2022-11-28",
        "--header",
        "User-Agent: portable-ghar-runner-observer/1",
        "--output",
        os.fspath(destination),
        url,
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=100,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail()
    if completed.returncode != 0:
        fail()
    return read_bounded(destination, maximum)


def version_tuple(value):
    if not isinstance(value, str):
        fail("version type")
    match = VERSION.fullmatch(value)
    if match is None:
        fail("version syntax")
    parts = tuple(int(component, 10) for component in match.groups())
    if any(component > UINT64_MAX for component in parts):
        fail("version overflow")
    return parts


def exact_bool(value, expected):
    if not isinstance(value, bool) or value is not expected:
        fail("release state")


def exact_time(value):
    if not isinstance(value, str) or UTC_SECONDS.fullmatch(value) is None:
        fail("publication time")
    try:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail("publication time")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        fail("publication time")
    return value


def exact_sha(value):
    if not isinstance(value, str) or HEX40.fullmatch(value) is None:
        fail("commit identity")
    return value


def evidence_digest(values):
    digest = hashlib.sha256()
    for value in ("portable-ghar-runner-release-observation-v1", *values):
        raw = str(value).encode("utf-8")
        digest.update(struct.pack(">Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


def validate_runner_identity(value):
    if not isinstance(value, dict) or set(value) != RUNNER_KEYS:
        fail("runner identity schema")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        fail("runner identity schema")
    version_tuple(value.get("version"))
    exact_sha(value.get("tag_ref_sha"))
    exact_sha(value.get("source_commit_sha"))
    bare = value["version"][1:]
    expected_name = f"actions-runner-linux-x64-{bare}.tar.gz"
    if value.get("linux_x64_asset_name") != expected_name:
        fail("asset identity")
    size = value.get("linux_x64_asset_size")
    if type(size) is not int or size < 1 or size > 1024 * 1024 * 1024:
        fail("asset size")
    if not isinstance(value.get("linux_x64_asset_digest"), str):
        fail("asset digest")
    if DIGEST.fullmatch(value["linux_x64_asset_digest"]) is None:
        fail("asset digest")
    exact_time(value.get("published_at"))
    if not isinstance(value.get("command_settings_sha256"), str):
        fail("source digest")
    if HEX64.fullmatch(value["command_settings_sha256"]) is None:
        fail("source digest")
    expected_evidence = evidence_digest(
        (
            value["version"],
            value["tag_ref_sha"],
            value["source_commit_sha"],
            value["linux_x64_asset_name"],
            value["linux_x64_asset_size"],
            value["linux_x64_asset_digest"],
            value["published_at"],
        )
    )
    if value.get("observation_evidence") != expected_evidence:
        fail("observation evidence")
    return value


def validate_current(path):
    try:
        st = path.lstat()
    except OSError:
        fail("current manifest")
    if not path.is_file() or path.is_symlink() or st.st_nlink != 1:
        fail("current manifest")
    raw = read_bounded(path, MAX_API_BYTES)
    root = load_json_bytes(raw)
    if not isinstance(root, dict):
        fail("current manifest")
    runtime = root.get("runtime")
    if not isinstance(runtime, dict):
        fail("current manifest")
    return validate_runner_identity(runtime.get("runner_release"))


def validate_output(path):
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        fail("output path")
    else:
        fail("output already exists")
    parent = path.parent
    try:
        parent_lstat = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError:
        fail("output parent")
    if not parent.is_dir() or parent.is_symlink() or parent_lstat.st_nlink < 1:
        fail("output parent")
    if resolved != parent.absolute():
        fail("output parent")
    return resolved / path.name


def main():
    if len(sys.argv) != 3:
        return 2
    current_path = pathlib.Path(sys.argv[1])
    output_path = pathlib.Path(sys.argv[2])
    current = validate_current(current_path)
    output_path = validate_output(output_path)

    work = None
    staged = None
    output_linked = False
    success = False
    try:
        try:
            work = pathlib.Path(
                tempfile.mkdtemp(
                    prefix=".runner-observation.",
                    dir=os.fspath(output_path.parent),
                )
            )
            os.chmod(work, 0o700)
        except OSError:
            fail("private work directory")

        release_raw = request(
            "https://api.github.com/repos/actions/runner/releases/latest",
            work / "release.json",
            MAX_API_BYTES,
            "application/vnd.github+json",
        )
        release = load_json_bytes(release_raw)
        if not isinstance(release, dict):
            fail("release schema")
        version = release.get("tag_name")
        candidate_version = version_tuple(version)
        exact_bool(release.get("draft"), False)
        exact_bool(release.get("prerelease"), False)
        published_at = exact_time(release.get("published_at"))
        bare = version[1:]
        asset_name = f"actions-runner-linux-x64-{bare}.tar.gz"
        assets = release.get("assets")
        if not isinstance(assets, list):
            fail("assets schema")
        matches = [
            item
            for item in assets
            if isinstance(item, dict) and item.get("name") == asset_name
        ]
        if len(matches) != 1:
            fail("asset identity")
        asset = matches[0]
        size = asset.get("size")
        digest = asset.get("digest")
        if type(size) is not int or size < 1 or size > 1024 * 1024 * 1024:
            fail("asset size")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            fail("asset digest")

        ref_raw = request(
            f"https://api.github.com/repos/actions/runner/git/ref/tags/{version}",
            work / "ref.json",
            MAX_API_BYTES,
            "application/vnd.github+json",
        )
        ref = load_json_bytes(ref_raw)
        if not isinstance(ref, dict) or ref.get("ref") != f"refs/tags/{version}":
            fail("tag ref")
        ref_object = ref.get("object")
        if not isinstance(ref_object, dict):
            fail("tag ref")
        tag_ref_sha = exact_sha(ref_object.get("sha"))
        ref_type = ref_object.get("type")
        if ref_type == "commit":
            source_commit_sha = tag_ref_sha
        elif ref_type == "tag":
            tag_raw = request(
                f"https://api.github.com/repos/actions/runner/git/tags/{tag_ref_sha}",
                work / "tag.json",
                MAX_API_BYTES,
                "application/vnd.github+json",
            )
            tag = load_json_bytes(tag_raw)
            if not isinstance(tag, dict) or tag.get("tag") != version:
                fail("annotated tag")
            tag_object = tag.get("object")
            if not isinstance(tag_object, dict) or tag_object.get("type") != "commit":
                fail("annotated tag")
            source_commit_sha = exact_sha(tag_object.get("sha"))
        else:
            fail("tag object type")

        command_raw = request(
            "https://raw.githubusercontent.com/actions/runner/"
            f"{source_commit_sha}/src/Runner.Listener/CommandSettings.cs",
            work / "CommandSettings.cs",
            MAX_SOURCE_BYTES,
            "application/octet-stream",
        )
        command_digest = hashlib.sha256(command_raw).hexdigest()
        candidate = {
            "schema_version": 1,
            "version": version,
            "tag_ref_sha": tag_ref_sha,
            "source_commit_sha": source_commit_sha,
            "linux_x64_asset_name": asset_name,
            "linux_x64_asset_size": size,
            "linux_x64_asset_digest": digest,
            "published_at": published_at,
            "command_settings_sha256": command_digest,
        }
        candidate["observation_evidence"] = evidence_digest(
            (
                version,
                tag_ref_sha,
                source_commit_sha,
                asset_name,
                size,
                digest,
                published_at,
            )
        )
        validate_runner_identity(candidate)

        current_version = version_tuple(current["version"])
        if candidate_version < current_version:
            fail("runner downgrade")
        if candidate_version == current_version:
            if candidate == current:
                return 3
            fail("equal-version identity drift")

        encoded = (
            json.dumps(candidate, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("utf-8")
        descriptor = None
        try:
            descriptor, staged_name = tempfile.mkstemp(
                prefix=".runner-candidate.",
                dir=os.fspath(output_path.parent),
            )
            staged = pathlib.Path(staged_name)
            os.fchmod(descriptor, 0o600)
        except OSError:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            fail("private candidate file")
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

        # Reclaim all observation state before making the candidate visible.
        # Cleanup failure is terminal and therefore cannot leave a successful
        # output behind.
        try:
            shutil.rmtree(work)
        except OSError:
            fail("work cleanup")
        work = None

        try:
            os.link(staged, output_path, follow_symlinks=False)
        except OSError:
            fail("atomic output")
        output_linked = True
        try:
            staged.unlink()
        except OSError:
            fail("candidate cleanup")
        staged = None
        try:
            directory = os.open(
                output_path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            fail("atomic output")
        success = True
        return 0
    finally:
        active_exception = sys.exc_info()[0] is not None
        cleanup_failed = False
        if staged is not None:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failed = True
        if work is not None:
            try:
                shutil.rmtree(work)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failed = True
        if output_linked and not success:
            try:
                output_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failed = True
        if cleanup_failed and not active_exception:
            fail("cleanup")


try:
    raise SystemExit(main())
except ObservationError:
    print("observe-runner-release: unavailable", file=sys.stderr)
    raise SystemExit(1)
except KeyboardInterrupt:
    raise SystemExit(130)
PY
