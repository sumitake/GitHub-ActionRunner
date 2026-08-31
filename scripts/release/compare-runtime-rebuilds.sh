#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Read-only validator/comparator for two Portable-GHAR runtime release trees.
# Calling it with the same tree twice is the publication-path validation mode.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf '%s\n' 'usage: compare-runtime-rebuilds.sh TREE_A TREE_B' >&2
  exit 2
fi

python3 - "$1" "$2" <<'PY'
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import sys
import tarfile


class ValidationError(Exception):
    pass


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
RUNTIME_KEYS = {
    "schema_version",
    "release_kind",
    "version",
    "platform",
    "source",
    "release_manifest_sha256",
    "runner_manifest_sha256",
    "runner_release",
    "tools",
    "subjects",
}
SOURCE_KEYS = {"commit", "tree", "source_date_epoch"}
SUBJECT_KEYS = {"path", "type", "size", "sha256"}
OCI_SUBJECT_KEYS = SUBJECT_KEYS | {"oci_graph"}
OCI_GRAPH_KEYS = {
    "index_digest",
    "manifest_digest",
    "config_digest",
    "layer_digests",
}
RUNNER_KEYS = {
    "build",
    "command_settings_sha256",
    "observation_evidence",
    "published_at",
    "schema_version",
    "version",
    "tag_ref_sha",
    "source_commit_sha",
    "source_tree_sha",
}
RUNNER_BUILD_KEYS = {
    "dotnet_sdk",
    "expected_listener_version",
    "externals",
    "nuget_locks",
}
DOTNET_SDK_KEYS = {
    "asset_name",
    "rid",
    "runtime_version",
    "sha512",
    "source_url",
    "version",
}
NUGET_LOCK_KEYS = {"aggregate_sha256", "files"}
NUGET_LOCK_FILE_KEYS = {"path", "sha256"}
EXTERNAL_KEYS = {"asset_name", "layout", "sha256", "source_url", "version"}
NUGET_LOCK_PATHS = (
    "Runner.Common/packages.lock.json",
    "Runner.Listener/packages.lock.json",
    "Runner.PluginHost/packages.lock.json",
    "Runner.Plugins/packages.lock.json",
    "Runner.Sdk/packages.lock.json",
    "Runner.Worker/packages.lock.json",
    "Sdk/packages.lock.json",
)
EXTERNAL_LAYOUTS = ("node20", "node20_alpine", "node24", "node24_alpine")
PROVENANCE_KEYS = {"schema_version", "subjects"}
PROVENANCE_SUBJECT_KEYS = {"path", "sha256", "size"}
SUBJECT_TYPES = {
    "binary",
    "oci-image",
    "sbom",
    "notices",
    "runner-manifest",
    "source-archive",
    "source-sbom",
}
MAX_JSON = 32 * 1024 * 1024
MAX_OCI_JSON = 16 * 1024 * 1024
MAX_OCI_MEMBERS = 10000


def reject(_message="invalid"):
    raise ValidationError(_message)


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


def parse_json(raw):
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=unique_object,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("invalid JSON")


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
        reject("unreadable subject")
    return digest.hexdigest()


def safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        reject("unsafe path")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        reject("unsafe path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or str(path) != value:
        reject("unsafe path")
    if any(part in ("", ".", "..") for part in path.parts):
        reject("unsafe path")
    return value


def require_file(root, relative, mode):
    path = root / relative
    try:
        st = path.lstat()
    except OSError:
        reject("missing subject")
    if (
        not stat.S_ISREG(st.st_mode)
        or stat.S_ISLNK(st.st_mode)
        or st.st_nlink != 1
        or stat.S_IMODE(st.st_mode) != mode
    ):
        reject("unsafe subject metadata")
    return path, st


def read_small(path, maximum=MAX_JSON):
    try:
        st = path.stat()
        if st.st_size < 1 or st.st_size > maximum:
            reject("authority size")
        return path.read_bytes()
    except OSError:
        reject("unreadable authority")


def validate_dotnet_sdk(value):
    if not isinstance(value, dict) or set(value) != DOTNET_SDK_KEYS:
        reject("runner dotnet schema")
    version = value["version"]
    runtime = value["runtime_version"]
    if (
        not isinstance(version, str)
        or re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", version) is None
        or not isinstance(runtime, str)
        or re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", runtime) is None
        or value["rid"] != "linux-x64"
    ):
        reject("runner dotnet version")
    expected_name = f"dotnet-sdk-{version}-linux-x64.tar.gz"
    expected_url = f"https://builds.dotnet.microsoft.com/dotnet/Sdk/{version}/{expected_name}"
    if value["asset_name"] != expected_name or value["source_url"] != expected_url:
        reject("runner dotnet asset")
    if not isinstance(value["sha512"], str) or re.fullmatch(
        r"[0-9a-f]{128}", value["sha512"]
    ) is None:
        reject("runner dotnet digest")


def validate_nuget_locks(value):
    if not isinstance(value, dict) or set(value) != NUGET_LOCK_KEYS:
        reject("runner nuget schema")
    files = value["files"]
    if not isinstance(files, list) or len(files) != len(NUGET_LOCK_PATHS):
        reject("runner nuget files")
    paths = []
    for item in files:
        if (
            not isinstance(item, dict)
            or set(item) != NUGET_LOCK_FILE_KEYS
            or not isinstance(item["path"], str)
            or not isinstance(item["sha256"], str)
            or HEX64.fullmatch(item["sha256"]) is None
        ):
            reject("runner nuget file")
        paths.append(item["path"])
    if tuple(paths) != NUGET_LOCK_PATHS:
        reject("runner nuget paths")
    if value["aggregate_sha256"] != sha256_bytes(canonical_json({"files": files})):
        reject("runner nuget aggregate")


def validate_externals(value):
    if not isinstance(value, list) or len(value) != len(EXTERNAL_LAYOUTS):
        reject("runner externals schema")
    layouts = []
    for item in value:
        if not isinstance(item, dict) or set(item) != EXTERNAL_KEYS:
            reject("runner external schema")
        layout = item["layout"]
        version = item["version"]
        if (
            layout not in EXTERNAL_LAYOUTS
            or not isinstance(version, str)
            or re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", version) is None
            or not isinstance(item["sha256"], str)
            or HEX64.fullmatch(item["sha256"]) is None
        ):
            reject("runner external identity")
        alpine = layout.endswith("_alpine")
        expected_name = (
            f"node-v{version}-alpine-x64.tar.gz"
            if alpine
            else f"node-v{version}-linux-x64.tar.gz"
        )
        expected_url = (
            f"https://github.com/actions/alpine_nodejs/releases/download/v{version}/{expected_name}"
            if alpine
            else f"https://nodejs.org/dist/v{version}/{expected_name}"
        )
        if item["asset_name"] != expected_name or item["source_url"] != expected_url:
            reject("runner external asset")
        layouts.append(layout)
    if tuple(layouts) != EXTERNAL_LAYOUTS:
        reject("runner external ordering")


def runner_evidence_digest(value):
    admitted = {
        key: item for key, item in value.items() if key != "observation_evidence"
    }
    return sha256_bytes(
        canonical_json(
            {
                "protocol": "portable-ghar-runner-source-release-v2",
                "runner_release": admitted,
            }
        )
    )


def validate_runner(value):
    if not isinstance(value, dict) or set(value) != RUNNER_KEYS:
        reject("runner schema")
    if type(value["schema_version"]) is not int or value["schema_version"] != 2:
        reject("runner schema")
    version = value["version"]
    match = re.fullmatch(
        r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version
    ) if isinstance(version, str) else None
    if match is None or any(int(item) > (1 << 64) - 1 for item in match.groups()):
        reject("runner version")
    for key in ("tag_ref_sha", "source_commit_sha", "source_tree_sha"):
        if not isinstance(value[key], str) or HEX40.fullmatch(value[key]) is None:
            reject("runner commit")
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
    build = value["build"]
    if not isinstance(build, dict) or set(build) != RUNNER_BUILD_KEYS:
        reject("runner build schema")
    validate_dotnet_sdk(build["dotnet_sdk"])
    validate_nuget_locks(build["nuget_locks"])
    validate_externals(build["externals"])
    if build["expected_listener_version"] != version[1:]:
        reject("runner listener version")
    if value["observation_evidence"] != runner_evidence_digest(value):
        reject("runner observation evidence")
    return value


def validate_tools(value):
    if not isinstance(value, dict) or set(value) != {
        "buildx",
        "buildkit",
        "syft",
        "trivy",
    }:
        reject("tool registry")
    for key in ("buildx", "syft", "trivy"):
        tool = value[key]
        if (
            not isinstance(tool, dict)
            or set(tool) != {"version", "asset_name", "sha256", "source_url"}
            or not isinstance(tool["version"], str)
            or not isinstance(tool["asset_name"], str)
            or not isinstance(tool["source_url"], str)
            or HEX64.fullmatch(tool["sha256"]) is None
        ):
            reject("tool identity")
    buildkit = value["buildkit"]
    if (
        not isinstance(buildkit, dict)
        or set(buildkit) != {"image", "platform_digest"}
        or not isinstance(buildkit["image"], str)
        or "@sha256:" not in buildkit["image"]
        or not isinstance(buildkit["platform_digest"], str)
        or DIGEST.fullmatch(buildkit["platform_digest"]) is None
    ):
        reject("buildkit identity")


def validate_descriptor(value, blob_records, *, platform=False):
    if not isinstance(value, dict):
        reject("OCI descriptor")
    allowed = {"mediaType", "digest", "size", "annotations", "platform"}
    if not set(value).issubset(allowed):
        reject("OCI descriptor")
    if not isinstance(value.get("mediaType"), str):
        reject("OCI descriptor")
    digest = value.get("digest")
    size = value.get("size")
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        reject("OCI descriptor")
    if type(size) is not int or size < 0:
        reject("OCI descriptor")
    if "urls" in value:
        reject("OCI foreign URL")
    record = blob_records.get(digest)
    if record is None or record[0] != size:
        reject("OCI descriptor")
    if platform:
        platform_value = value.get("platform")
        if (
            not isinstance(platform_value, dict)
            or set(platform_value) != {"architecture", "os"}
            or platform_value != {"architecture": "amd64", "os": "linux"}
        ):
            reject("OCI platform")
    elif "platform" in value:
        reject("unexpected OCI platform")
    if "annotations" in value and not isinstance(value["annotations"], dict):
        reject("OCI annotations")
    return digest


def validate_oci(path):
    try:
        archive = tarfile.open(path, mode="r:")
    except (OSError, tarfile.TarError):
        reject("OCI archive")
    members = {}
    try:
        for index, member in enumerate(archive):
            if index >= MAX_OCI_MEMBERS:
                reject("OCI member count")
            name = member.name.rstrip("/") if member.isdir() else member.name
            safe_relative(name)
            if name in members:
                reject("duplicate OCI member")
            if member.isdir():
                continue
            if not member.isfile() or member.linkname:
                reject("unsafe OCI member")
            if member.size < 0:
                reject("OCI member")
            extracted = archive.extractfile(member)
            if extracted is None:
                reject("OCI member")
            raw = extracted.read(MAX_OCI_JSON + 1) if (
                name in ("index.json", "oci-layout") or name.startswith("blobs/sha256/")
            ) else b""
            if len(raw) > MAX_OCI_JSON and (
                name in ("index.json", "oci-layout")
                or name.startswith("blobs/sha256/")
            ):
                # Layers may be larger than JSON. Re-read them by streaming
                # directly from the tar below; only JSON-addressed blobs need
                # this bound.
                if name.startswith("blobs/sha256/"):
                    raw = None
                else:
                    reject("OCI JSON size")
            members[name] = (member, raw)
    finally:
        archive.close()

    required = {"oci-layout", "index.json"}
    if not required.issubset(members):
        reject("OCI layout")
    layout_raw = members["oci-layout"][1]
    layout = parse_json(layout_raw)
    if layout != {"imageLayoutVersion": "1.0.0"}:
        reject("OCI layout")
    index_raw = members["index.json"][1]
    index = parse_json(index_raw)
    if (
        not isinstance(index, dict)
        or set(index) - {"schemaVersion", "mediaType", "manifests", "annotations"}
        or index.get("schemaVersion") != 2
        or not isinstance(index.get("manifests"), list)
        or len(index["manifests"]) != 1
    ):
        reject("OCI index")

    # Stream every digest-addressed blob and independently prove its address.
    blob_records = {}
    try:
        archive = tarfile.open(path, mode="r:")
        for member in archive:
            if not member.isfile() or not member.name.startswith("blobs/sha256/"):
                continue
            digest = member.name.removeprefix("blobs/sha256/")
            if HEX64.fullmatch(digest) is None:
                reject("OCI blob path")
            extracted = archive.extractfile(member)
            if extracted is None:
                reject("OCI blob")
            hasher = hashlib.sha256()
            total = 0
            retained = bytearray()
            while True:
                block = extracted.read(1024 * 1024)
                if not block:
                    break
                hasher.update(block)
                total += len(block)
                if len(retained) <= MAX_OCI_JSON:
                    retained.extend(block)
            if hasher.hexdigest() != digest:
                reject("OCI blob digest")
            raw = bytes(retained) if total <= MAX_OCI_JSON else None
            blob_records[f"sha256:{digest}"] = (total, raw)
    except (OSError, tarfile.TarError):
        reject("OCI archive")
    finally:
        try:
            archive.close()
        except Exception:
            pass

    manifest_digest = validate_descriptor(
        index["manifests"][0], blob_records, platform=True
    )
    manifest_raw = blob_records[manifest_digest][1]
    if manifest_raw is None:
        reject("OCI manifest size")
    manifest = parse_json(manifest_raw)
    if (
        not isinstance(manifest, dict)
        or set(manifest) - {
            "schemaVersion",
            "mediaType",
            "config",
            "layers",
            "annotations",
        }
        or manifest.get("schemaVersion") != 2
        or not isinstance(manifest.get("layers"), list)
    ):
        reject("OCI manifest")
    config_digest = validate_descriptor(manifest.get("config"), blob_records)
    config_raw = blob_records[config_digest][1]
    if config_raw is None:
        reject("OCI config size")
    config = parse_json(config_raw)
    if not isinstance(config, dict):
        reject("OCI config")
    if config.get("architecture") != "amd64" or config.get("os") != "linux":
        reject("OCI config platform")
    layers = [
        validate_descriptor(descriptor, blob_records) for descriptor in manifest["layers"]
    ]
    referenced = {manifest_digest, config_digest, *layers}
    if set(blob_records) != referenced:
        reject("unreferenced OCI blob")
    return {
        "index_digest": f"sha256:{sha256_bytes(index_raw)}",
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
        "layer_digests": layers,
    }


def validate_tree(argument):
    root = pathlib.Path(argument)
    try:
        st = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError:
        reject("missing tree")
    if not stat.S_ISDIR(st.st_mode) or root.is_symlink() or resolved != root.absolute():
        reject("unsafe tree")
    root = resolved

    runtime_path, _ = require_file(root, "runtime-release.json", 0o444)
    runtime_raw = read_small(runtime_path)
    runtime = parse_json(runtime_raw)
    if canonical_json(runtime) != runtime_raw:
        reject("noncanonical runtime manifest")
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_KEYS:
        reject("runtime schema")
    if type(runtime["schema_version"]) is not int or runtime["schema_version"] != 1:
        reject("runtime schema")
    kind = runtime["release_kind"]
    if kind not in ("candidate", "product"):
        reject("release kind")
    version = runtime["version"]
    if (
        not isinstance(version, str)
        or SAFE_VERSION.fullmatch(version) is None
        or ".." in version
    ):
        reject("release version")
    if runtime["platform"] != "linux/amd64":
        reject("release platform")
    source = runtime["source"]
    if not isinstance(source, dict) or set(source) != SOURCE_KEYS:
        reject("source identity")
    if (
        not isinstance(source["commit"], str)
        or HEX40.fullmatch(source["commit"]) is None
        or not isinstance(source["tree"], str)
        or HEX40.fullmatch(source["tree"]) is None
        or type(source["source_date_epoch"]) is not int
        or source["source_date_epoch"] < 1
    ):
        reject("source identity")
    for key in ("release_manifest_sha256", "runner_manifest_sha256"):
        if not isinstance(runtime[key], str) or HEX64.fullmatch(runtime[key]) is None:
            reject("manifest identity")
    validate_runner(runtime["runner_release"])
    validate_tools(runtime["tools"])

    subjects = runtime["subjects"]
    if not isinstance(subjects, list) or not subjects:
        reject("subject registry")
    paths = []
    parsed_subjects = {}
    source_archive_count = 0
    source_sbom_count = 0
    for subject in subjects:
        if not isinstance(subject, dict):
            reject("subject schema")
        subject_type = subject.get("type")
        expected_keys = OCI_SUBJECT_KEYS if subject_type == "oci-image" else SUBJECT_KEYS
        if set(subject) != expected_keys or subject_type not in SUBJECT_TYPES:
            reject("subject schema")
        relative = safe_relative(subject["path"])
        if relative in parsed_subjects:
            reject("duplicate subject")
        size = subject["size"]
        digest = subject["sha256"]
        if type(size) is not int or size < 1:
            reject("subject size")
        if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
            reject("subject digest")
        expected_mode = 0o555 if subject_type == "binary" else 0o444
        path, file_stat = require_file(root, relative, expected_mode)
        if file_stat.st_size != size or sha256_file(path) != digest:
            reject("subject bytes")
        if subject_type == "binary" and not relative.startswith("bin/"):
            reject("binary path")
        if subject_type == "oci-image":
            if not relative.startswith("images/") or not relative.endswith(".oci.tar"):
                reject("image path")
            graph = subject["oci_graph"]
            if (
                not isinstance(graph, dict)
                or set(graph) != OCI_GRAPH_KEYS
                or any(
                    not isinstance(graph[key], str)
                    or DIGEST.fullmatch(graph[key]) is None
                    for key in ("index_digest", "manifest_digest", "config_digest")
                )
                or not isinstance(graph["layer_digests"], list)
                or any(
                    not isinstance(item, str) or DIGEST.fullmatch(item) is None
                    for item in graph["layer_digests"]
                )
            ):
                reject("OCI graph claim")
            if validate_oci(path) != graph:
                reject("OCI graph mismatch")
        if subject_type in ("sbom", "source-sbom"):
            if not relative.startswith("sbom/") or not relative.endswith(".spdx.json"):
                reject("SBOM path")
            raw = read_small(path)
            value = parse_json(raw)
            if canonical_json(value) != raw:
                reject("noncanonical SBOM")
        if subject_type == "notices":
            if relative != "notices/THIRD-PARTY-NOTICES.txt":
                reject("notices path")
            raw = read_small(path)
            try:
                text = raw.decode("utf-8", "strict")
            except UnicodeDecodeError:
                reject("notices encoding")
            if "\x00" in text or not text.endswith("\n"):
                reject("notices encoding")
        if subject_type == "runner-manifest":
            if relative != "runner-release.json":
                reject("runner manifest path")
            raw = read_small(path)
            parsed_runner = parse_json(raw)
            if canonical_json(parsed_runner) != raw:
                reject("runner manifest canonicalization")
            validate_runner(parsed_runner)
            if parsed_runner != runtime["runner_release"]:
                reject("runner manifest mismatch")
            if sha256_bytes(raw) != runtime["runner_manifest_sha256"]:
                reject("runner manifest digest")
        if subject_type == "source-archive":
            source_archive_count += 1
            if not relative.startswith("source/portable-ghar-") or not relative.endswith(
                ".tar.gz"
            ):
                reject("source path")
        if subject_type == "source-sbom":
            source_sbom_count += 1
        paths.append(relative)
        parsed_subjects[relative] = subject

    if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
        reject("subject ordering")
    if kind == "candidate" and (source_archive_count or source_sbom_count):
        reject("candidate source membership")
    if kind == "product" and (source_archive_count != 1 or source_sbom_count != 1):
        reject("product source membership")

    expected_files = set(paths) | {
        "runtime-release.json",
        "checksums.txt",
        "provenance-subjects.json",
    }
    actual_files = set()
    actual_dirs = set()
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = pathlib.Path(directory)
        relative_directory = directory_path.relative_to(root)
        for dirname in list(dirnames):
            candidate = directory_path / dirname
            try:
                dir_st = candidate.lstat()
            except OSError:
                reject("tree inventory")
            if not stat.S_ISDIR(dir_st.st_mode) or stat.S_ISLNK(dir_st.st_mode):
                reject("tree directory")
            relative = candidate.relative_to(root).as_posix()
            safe_relative(relative)
            if stat.S_IMODE(dir_st.st_mode) != 0o755:
                reject("tree directory mode")
            actual_dirs.add(relative)
        for filename in filenames:
            relative = (relative_directory / filename).as_posix()
            safe_relative(relative)
            actual_files.add(relative)
    if actual_files != expected_files:
        reject("tree inventory")
    expected_dirs = {
        str(parent)
        for relative in expected_files
        for parent in pathlib.PurePosixPath(relative).parents
        if str(parent) != "."
    }
    if actual_dirs != expected_dirs:
        reject("tree directory inventory")

    checksum_path, _ = require_file(root, "checksums.txt", 0o444)
    checksum_raw = read_small(checksum_path)
    try:
        checksum_text = checksum_raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        reject("checksums encoding")
    if not checksum_text.endswith("\n") or checksum_text.endswith("\n\n"):
        reject("checksums newline")
    checksum_rows = {}
    for line in checksum_text[:-1].split("\n"):
        match = re.fullmatch(r"([0-9a-f]{64})  ([!-~]+)", line)
        if match is None:
            reject("checksums grammar")
        digest, relative = match.groups()
        safe_relative(relative)
        if relative in checksum_rows:
            reject("checksums duplicate")
        checksum_rows[relative] = digest
    expected_checksum_paths = set(paths) | {"runtime-release.json"}
    if set(checksum_rows) != expected_checksum_paths:
        reject("checksums membership")
    if list(checksum_rows) != sorted(
        checksum_rows, key=lambda item: item.encode("utf-8")
    ):
        reject("checksums ordering")
    for relative, digest in checksum_rows.items():
        if sha256_file(root / relative) != digest:
            reject("checksums digest")

    provenance_path, provenance_stat = require_file(
        root, "provenance-subjects.json", 0o444
    )
    provenance_raw = read_small(provenance_path)
    provenance = parse_json(provenance_raw)
    if canonical_json(provenance) != provenance_raw:
        reject("provenance canonicalization")
    if (
        not isinstance(provenance, dict)
        or set(provenance) != PROVENANCE_KEYS
        or provenance.get("schema_version") != 1
        or not isinstance(provenance.get("subjects"), list)
    ):
        reject("provenance schema")
    expected_provenance_paths = expected_checksum_paths | {"checksums.txt"}
    provenance_paths = []
    for subject in provenance["subjects"]:
        if (
            not isinstance(subject, dict)
            or set(subject) != PROVENANCE_SUBJECT_KEYS
        ):
            reject("provenance subject")
        relative = safe_relative(subject["path"])
        if relative in provenance_paths:
            reject("provenance duplicate")
        path = root / relative
        try:
            st = path.stat()
        except OSError:
            reject("provenance subject")
        if (
            type(subject["size"]) is not int
            or subject["size"] != st.st_size
            or not isinstance(subject["sha256"], str)
            or HEX64.fullmatch(subject["sha256"]) is None
            or subject["sha256"] != sha256_file(path)
        ):
            reject("provenance subject")
        provenance_paths.append(relative)
    if set(provenance_paths) != expected_provenance_paths or provenance_paths != sorted(
        provenance_paths, key=lambda item: item.encode("utf-8")
    ):
        reject("provenance membership")

    return {
        "root": root,
        "runtime_raw": runtime_raw,
        "runtime": runtime,
        "subjects": parsed_subjects,
        "provenance_sha256": sha256_bytes(provenance_raw),
        "provenance_size": provenance_stat.st_size,
    }


def compare(a, b):
    if a["runtime_raw"] != b["runtime_raw"]:
        reject("runtime manifests differ")
    if (
        a["provenance_sha256"] != b["provenance_sha256"]
        or a["provenance_size"] != b["provenance_size"]
    ):
        reject("provenance differs")
    for relative, subject in a["subjects"].items():
        other = b["subjects"].get(relative)
        if other != subject:
            reject("subject registry differs")
        if subject["type"] == "oci-image":
            if subject["oci_graph"] != other["oci_graph"]:
                reject("OCI graph differs")
        else:
            path_a = a["root"] / relative
            path_b = b["root"] / relative
            try:
                with path_a.open("rb") as stream_a, path_b.open("rb") as stream_b:
                    while True:
                        block_a = stream_a.read(1024 * 1024)
                        block_b = stream_b.read(1024 * 1024)
                        if block_a != block_b:
                            reject("subject bytes differ")
                        if not block_a:
                            break
            except OSError:
                reject("subject comparison")


try:
    tree_a = validate_tree(sys.argv[1])
    tree_b = validate_tree(sys.argv[2])
    compare(tree_a, tree_b)
except (ValidationError, OSError, ValueError, OverflowError):
    print("compare-runtime-rebuilds: unavailable", file=sys.stderr)
    raise SystemExit(1)
except KeyboardInterrupt:
    raise SystemExit(130)
PY
