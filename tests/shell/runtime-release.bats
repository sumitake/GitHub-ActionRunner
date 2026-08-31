#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd -P)"
  REHEARSE="$REPO_ROOT/scripts/release/rehearse-runtime.sh"
  COMPARE="$REPO_ROOT/scripts/release/compare-runtime-rebuilds.sh"
  MANIFEST="$REPO_ROOT/release/manifest.json"
  WORK="$(mktemp -d)"
  WORK="$(cd "$WORK" && pwd -P)"
}

teardown() {
  rm -rf "$WORK"
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

write_runtime_tree() {
  local target=$1
  local variant=${2:-valid}
  python3 - "$target" "$variant" <<'PY'
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
variant = sys.argv[2]


def canonical(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    return digest(path.read_bytes())


def put(path, raw, mode=0o444):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def runner_evidence(value):
    admitted = {
        key: item for key, item in value.items() if key != "observation_evidence"
    }
    return digest(
        canonical(
            {
                "protocol": "portable-ghar-runner-source-release-v2",
                "runner_release": admitted,
            }
        )
    )


def make_oci(path):
    layer = b"fixture-layer\n"
    layer_digest = f"sha256:{digest(layer)}"
    config = canonical(
        {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"diff_ids": [layer_digest], "type": "layers"},
        }
    )[:-1]
    config_digest = f"sha256:{digest(config)}"
    manifest = canonical(
        {
            "config": {
                "digest": config_digest,
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": len(config),
            },
            "layers": [
                {
                    "digest": layer_digest,
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "size": len(layer),
                }
            ],
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
    )[:-1]
    manifest_digest = f"sha256:{digest(manifest)}"
    descriptor = {
        "digest": manifest_digest,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "platform": {"architecture": "amd64", "os": "linux"},
        "size": len(manifest),
    }
    manifests = [descriptor]
    if variant == "multi-platform":
        manifests = [descriptor, descriptor]
    index = canonical(
        {
            "manifests": manifests,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "schemaVersion": 2,
        }
    )[:-1]
    members = {
        "oci-layout": canonical({"imageLayoutVersion": "1.0.0"})[:-1],
        "index.json": index,
        f"blobs/sha256/{manifest_digest[7:]}": manifest,
        f"blobs/sha256/{config_digest[7:]}": config,
        f"blobs/sha256/{layer_digest[7:]}": layer,
    }
    if variant == "unreferenced-blob":
        extra = b"not referenced\n"
        members[f"blobs/sha256/{digest(extra)}"] = extra
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(members):
            raw = members[name]
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o444
            info.uid = 0
            info.gid = 0
            info.mtime = 1
            archive.addfile(info, io.BytesIO(raw))
    path.chmod(0o444)
    graph = {
        "config_digest": config_digest,
        "index_digest": f"sha256:{digest(index)}",
        "layer_digests": [layer_digest],
        "manifest_digest": manifest_digest,
    }
    if variant == "graph-mismatch":
        graph["config_digest"] = "sha256:" + "f" * 64
    return graph


for directory in ("bin", "images", "sbom", "notices"):
    (root / directory).mkdir(parents=True, mode=0o755)
put(root / "bin/portable-ghar", b"\x7fELFfixture\n", 0o555)
graph = make_oci(root / "images/runner.oci.tar")
put(
    root / "sbom/runner.spdx.json",
    canonical({"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3"}),
)
put(
    root / "notices/THIRD-PARTY-NOTICES.txt",
    b"Portable-GHAR Third-Party Notices\n",
)
nuget_files = [
    {"path": path, "sha256": str(index) * 64}
    for index, path in enumerate(
        (
            "Runner.Common/packages.lock.json",
            "Runner.Listener/packages.lock.json",
            "Runner.PluginHost/packages.lock.json",
            "Runner.Plugins/packages.lock.json",
            "Runner.Sdk/packages.lock.json",
            "Runner.Worker/packages.lock.json",
            "Sdk/packages.lock.json",
        ),
        start=1,
    )
]
runner = {
    "build": {
        "dotnet_sdk": {
            "asset_name": "dotnet-sdk-8.0.424-linux-x64.tar.gz",
            "rid": "linux-x64",
            "runtime_version": "8.0.30",
            "sha512": "a" * 128,
            "source_url": (
                "https://builds.dotnet.microsoft.com/dotnet/Sdk/8.0.424/"
                "dotnet-sdk-8.0.424-linux-x64.tar.gz"
            ),
            "version": "8.0.424",
        },
        "expected_listener_version": "2.336.0",
        "externals": [
            {
                "asset_name": "node-v20.20.2-linux-x64.tar.gz",
                "layout": "node20",
                "sha256": "8" * 64,
                "source_url": (
                    "https://nodejs.org/dist/v20.20.2/"
                    "node-v20.20.2-linux-x64.tar.gz"
                ),
                "version": "20.20.2",
            },
            {
                "asset_name": "node-v20.20.2-alpine-x64.tar.gz",
                "layout": "node20_alpine",
                "sha256": "9" * 64,
                "source_url": (
                    "https://github.com/actions/alpine_nodejs/releases/download/"
                    "v20.20.2/node-v20.20.2-alpine-x64.tar.gz"
                ),
                "version": "20.20.2",
            },
            {
                "asset_name": "node-v24.18.0-linux-x64.tar.gz",
                "layout": "node24",
                "sha256": "b" * 64,
                "source_url": (
                    "https://nodejs.org/dist/v24.18.0/"
                    "node-v24.18.0-linux-x64.tar.gz"
                ),
                "version": "24.18.0",
            },
            {
                "asset_name": "node-v24.18.0-alpine-x64.tar.gz",
                "layout": "node24_alpine",
                "sha256": "c" * 64,
                "source_url": (
                    "https://github.com/actions/alpine_nodejs/releases/download/"
                    "v24.18.0/node-v24.18.0-alpine-x64.tar.gz"
                ),
                "version": "24.18.0",
            },
        ],
        "nuget_locks": {
            "aggregate_sha256": digest(canonical({"files": nuget_files})),
            "files": nuget_files,
        },
    },
    "command_settings_sha256": "4" * 64,
    "published_at": "2026-07-20T17:45:55Z",
    "schema_version": 2,
    "source_commit_sha": "2" * 40,
    "source_tree_sha": "3" * 40,
    "tag_ref_sha": "1" * 40,
    "version": "v2.336.0",
}
runner["observation_evidence"] = runner_evidence(runner)
put(root / "runner-release.json", canonical(runner))

subjects = []
for relative, kind in (
    ("bin/portable-ghar", "binary"),
    ("images/runner.oci.tar", "oci-image"),
    ("notices/THIRD-PARTY-NOTICES.txt", "notices"),
    ("runner-release.json", "runner-manifest"),
    ("sbom/runner.spdx.json", "sbom"),
):
    path = root / relative
    row = {
        "path": relative,
        "sha256": file_digest(path),
        "size": path.stat().st_size,
        "type": kind,
    }
    if kind == "oci-image":
        row["oci_graph"] = graph
    subjects.append(row)
subjects.sort(key=lambda row: row["path"].encode())
tools = {
    "buildkit": {
        "image": "moby/buildkit:v1@sha256:" + "5" * 64,
        "platform_digest": "sha256:" + "6" * 64,
    },
    "buildx": {
        "asset_name": "buildx",
        "sha256": "7" * 64,
        "source_url": "https://example.invalid/buildx",
        "version": "v1",
    },
    "syft": {
        "asset_name": "syft",
        "sha256": "8" * 64,
        "source_url": "https://example.invalid/syft",
        "version": "v1",
    },
    "trivy": {
        "asset_name": "trivy",
        "sha256": "9" * 64,
        "source_url": "https://example.invalid/trivy",
        "version": "v1",
    },
}
runtime = {
    "platform": "linux/amd64",
    "release_kind": "candidate",
    "release_manifest_sha256": "a" * 64,
    "runner_manifest_sha256": file_digest(root / "runner-release.json"),
    "runner_release": runner,
    "schema_version": 1,
    "source": {
        "commit": "b" * 40,
        "source_date_epoch": 1,
        "tree": "c" * 40,
    },
    "subjects": subjects,
    "tools": tools,
    "version": "0.1.0-candidate",
}
put(root / "runtime-release.json", canonical(runtime))
checksum_paths = sorted(
    [row["path"] for row in subjects] + ["runtime-release.json"],
    key=lambda item: item.encode(),
)
put(
    root / "checksums.txt",
    "".join(f"{file_digest(root / path)}  {path}\n" for path in checksum_paths).encode(),
)
provenance_paths = sorted(checksum_paths + ["checksums.txt"], key=lambda item: item.encode())
provenance = {
    "schema_version": 1,
    "subjects": [
        {
            "path": path,
            "sha256": file_digest(root / path),
            "size": (root / path).stat().st_size,
        }
        for path in provenance_paths
    ],
}
put(root / "provenance-subjects.json", canonical(provenance))
for directory, dirnames, filenames in os.walk(root):
    pathlib.Path(directory).chmod(0o755)
PY
}

tree_fingerprint() {
  python3 - "$1" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
h = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().encode()):
    st = path.lstat()
    relative = path.relative_to(root).as_posix().encode()
    h.update(len(relative).to_bytes(8, "big"))
    h.update(relative)
    for value in (stat.S_IMODE(st.st_mode), st.st_nlink, st.st_size, st.st_mtime_ns):
        h.update(value.to_bytes(16, "big", signed=False))
    if path.is_file() and not path.is_symlink():
        h.update(hashlib.sha256(path.read_bytes()).digest())
print(h.hexdigest())
PY
}

run_candidate_overlay_case() {
  local case_name=$1
  python3 -B - "$REHEARSE" "$WORK/overlay-$case_name" "$case_name" <<'PY'
import ast
import hashlib
import json
import pathlib
import re
import subprocess
import sys

script = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
case_name = sys.argv[3]
source = script.read_text(encoding="utf-8")
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
tree = ast.parse(payload, filename=str(script))
if not tree.body or not isinstance(tree.body[-1], ast.Try):
    raise SystemExit("unexpected rehearsal entry point")
tree.body = tree.body[:-1]
namespace = {}
exec(compile(tree, str(script), "exec"), namespace)

old = {
    "version_bare": "2.336.0",
    "source_commit": "2" * 40,
    "source_tree": "3" * 40,
    "runner_release_evidence": "4" * 64,
    "command_settings_sha256": "5" * 64,
}
new = {
    "version_bare": "2.338.0",
    "source_commit": "6" * 40,
    "source_tree": "7" * 40,
    "runner_release_evidence": "8" * 64,
    "command_settings_sha256": "9" * 64,
}


def inventory(raw):
    matches = []
    matcher = re.compile(
        rb"(?<![0-9A-Za-z])v?((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
        rb"(?:0|[1-9][0-9]*))(?![0-9]|\.[0-9])"
        rb"|(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{40})(?![0-9a-f])"
    )
    for match in matcher.finditer(raw):
        if match.group(1) is not None:
            matches.append(["runner-version", match.group(1).decode("ascii")])
        else:
            value = match.group(2).decode("ascii")
            matches.append([f"hex{len(value)}", value])
    return matches


def inventory_digest(path):
    raw = (
        json.dumps(
            inventory(path.read_bytes()),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


(root / "internal").mkdir(parents=True)
(root / "release").mkdir()
(root / "scripts").mkdir()
(root / "internal/pins.go").write_text(
    (
        f'const runnerVersion = "{old["version_bare"]}"\n'
        f'const runnerCommit = "{old["source_commit"]}"\n'
        f'const runnerTree = "{old["source_tree"]}"\n'
        f'const runnerEvidence = "{old["runner_release_evidence"]}"\n'
        f'const commandSettings = "{old["command_settings_sha256"]}"\n'
    ),
    encoding="ascii",
)
(root / "release/manifest.json").write_text(
    f'{{"baseline":"{old["version_bare"]}"}}\n',
    encoding="ascii",
)
baseline_inventory_digest = inventory_digest(root / "internal/pins.go")
if case_name == "unlisted":
    (root / "scripts/extra.sh").write_text(
        f'runner="{old["version_bare"]}"\n',
        encoding="ascii",
    )
elif case_name == "third-value":
    (root / "internal/pins.go").write_text(
        (
            f'const runnerVersion = "{old["version_bare"]}"\n'
            'const alternateRunnerVersion = "v7.1.0"\n'
        ),
        encoding="ascii",
    )
elif case_name == "count-mismatch":
    (root / "internal/pins.go").write_text(
        'const runnerVersion = "2.335.1"\n',
        encoding="ascii",
    )
(root / "scripts/extra.sh").touch(exist_ok=True)
subprocess.run(
    ["git", "init", "-q"],
    cwd=root,
    check=True,
    stdout=subprocess.DEVNULL,
)
subprocess.run(
    ["git", "add", "."],
    cwd=root,
    check=True,
    stdout=subprocess.DEVNULL,
)

runtime = {
    "runner_release": {
        "version": f'v{old["version_bare"]}',
        "source_commit_sha": old["source_commit"],
        "source_tree_sha": old["source_tree"],
        "observation_evidence": old["runner_release_evidence"],
        "command_settings_sha256": old["command_settings_sha256"],
    },
    "candidate_substitutions": [
        {
            "path": "internal/pins.go",
            "token": token,
            "count": 1,
            "replace": True,
        }
        for token in (
            "version_bare",
            "source_commit",
            "source_tree",
            "runner_release_evidence",
            "command_settings_sha256",
        )
    ],
    "candidate_protected_files": [
        {
            "path": "internal/pins.go",
            "identity_inventory_sha256": baseline_inventory_digest,
        }
    ],
}
candidate = {
    "version": "v3.0.0" if case_name == "major-upgrade" else f'v{new["version_bare"]}',
    "source_commit_sha": new["source_commit"],
    "source_tree_sha": new["source_tree"],
    "observation_evidence": new["runner_release_evidence"],
    "command_settings_sha256": new["command_settings_sha256"],
}

expected_rejection = case_name not in {"valid", "major-upgrade"}
try:
    namespace["apply_candidate_overlay"](root, runtime, candidate)
except namespace["RehearsalError"]:
    rejected = True
else:
    rejected = False
if rejected != expected_rejection:
    raise SystemExit(1)
PY
}

@test "runtime release entry points exist and are executable" {
  [ -x "$REHEARSE" ]
  [ -x "$COMPARE" ]
}

@test "rehearsal stages form a closed diagnostic allowlist" {
  run python3 -B - "$REHEARSE" <<'PY'
import ast
import pathlib
import sys

script = pathlib.Path(sys.argv[1])
source = script.read_text(encoding="utf-8")
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
tree = ast.parse(payload, filename=str(script))
assert isinstance(tree.body[-1], ast.Try)
tree.body = tree.body[:-1]
namespace = {}
exec(compile(tree, str(script), "exec"), namespace)
stage_type = namespace["RehearsalStage"]
expected_values = (
    "source",
    "runner",
    "build",
    "security",
    "sbom",
    "authority",
    "compare",
    "cleanup",
)
assert tuple(stage.value for stage in stage_type) == expected_values
for stage, value in zip(stage_type, expected_values, strict=True):
    namespace["set_stage"](stage)
    assert namespace["unavailable_message"](stage) == (
        f"rehearse-runtime: unavailable stage={value}"
    )
assert namespace["unavailable_message"]("private diagnostic") == (
    "rehearse-runtime: unavailable stage=source"
)
PY
  [ "$status" -eq 0 ]
}

@test "candidate and product rehearsals admit only the exact checked-in runner" {
  run python3 -B - "$REHEARSE" <<'PY'
import ast
import pathlib
import sys

script = pathlib.Path(sys.argv[1])
source = script.read_text(encoding="utf-8")
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
tree = ast.parse(payload, filename=str(script))
assert isinstance(tree.body[-1], ast.Try)
tree.body = tree.body[:-1]
namespace = {}
exec(compile(tree, str(script), "exec"), namespace)

baseline = {"version": "v2.336.0", "identity": "exact"}
for release_kind in ("candidate", "product"):
    namespace["validate_runner_identity"](
        release_kind, dict(baseline), baseline
    )
    for changed in (
        {"version": "v2.337.0", "identity": "newer"},
        {"version": "v2.336.0", "identity": "drift"},
        {"version": "v2.335.0", "identity": "older"},
    ):
        try:
            namespace["validate_runner_identity"](
                release_kind, changed, baseline
            )
        except namespace["RehearsalError"]:
            pass
        else:
            raise AssertionError(
                f"{release_kind} admitted a non-baseline runner: {changed}"
            )
PY
  [ "$status" -eq 0 ]
}

@test "rehearsal failure exposes only its closed stage" {
  local sentinel=private-rehearsal-diagnostic-must-not-escape
  printf '{"detail":"%s"}\n' "$sentinel" >"$WORK/$sentinel.json"

  run "$REHEARSE" \
    --release-kind candidate \
    --version diagnostic-fixture \
    --runner-manifest "$WORK/$sentinel.json" \
    --output "$WORK/$sentinel-output"
  [ "$status" -eq 1 ]
  [ "$output" = "rehearse-runtime: unavailable stage=source" ]
  [[ "$output" != *"$sentinel"* ]]
  [[ "$output" != *"rehearsal.log"* ]]
}

@test "release manifest registers one closed Linux amd64 runtime" {
  run jq -e '
    .version == 1 and
    .subjects == ["portable-ghar-*.tar.gz"] and
    (.runtime | keys) == [
      "binaries",
      "candidate_protected_files",
      "candidate_substitutions",
      "debian_snapshot",
      "images",
      "license_exceptions",
      "platform",
      "runner_release",
      "schema_version",
      "tools"
    ] and
    .runtime.schema_version == 1 and
    .runtime.platform == "linux/amd64" and
    .runtime.debian_snapshot == "20250101T000000Z" and
    [.runtime.binaries[].name] == [
      "portable-ghar",
      "portable-ghar-controller",
      "portable-ghar-fleet-fence",
      "portable-ghar-network-adapter",
      "portable-ghar-network-broker-dialer",
      "portable-ghar-network-broker-parser",
      "portable-ghar-network-helper",
      "portable-ghar-network-verifier",
      "portable-ghar-runner-gate",
      "portable-ghar-runtime-lock",
      "portable-ghar-watchdog"
    ] and
    ([.runtime.binaries[].name] | length) ==
      ([.runtime.binaries[].name] | unique | length) and
    [.runtime.images[].name] == [
      "network-adapter",
      "network-broker-dialer",
      "network-broker-parser",
      "network-helper",
      "network-verifier",
      "runner"
    ] and
    ([.runtime.images[].name] | index("synthetic-listener")) == null and
    .runtime.license_exceptions == [] and
    (.runtime.candidate_substitutions | length) > 0 and
    all(.runtime.candidate_substitutions[];
      (keys == ["count", "path", "replace", "token"]) and
      (.path | type == "string" and length > 0) and
      (.token | IN(
        "version_bare",
        "source_commit",
        "source_tree",
        "runner_release_evidence",
        "command_settings_sha256"
      )) and
      (.count | type == "number" and . > 0 and floor == .) and
      (.replace | type == "boolean")
    ) and
    ([.runtime.candidate_substitutions[].token] | unique) == [
      "command_settings_sha256",
      "runner_release_evidence",
      "source_commit",
      "source_tree",
      "version_bare"
    ] and
    (.runtime.candidate_protected_files | length) > 0 and
    all(.runtime.candidate_protected_files[];
      (keys == ["identity_inventory_sha256", "path"]) and
      (.path | type == "string" and length > 0) and
      (.identity_inventory_sha256 | test("^[0-9a-f]{64}$"))
    ) and
    (.runtime.runner_release | keys) == [
      "build",
      "command_settings_sha256",
      "observation_evidence",
      "published_at",
      "schema_version",
      "source_commit_sha",
      "source_tree_sha",
      "tag_ref_sha",
      "version"
    ] and
    .runtime.runner_release.schema_version == 2 and
    (.runtime.runner_release.build | keys) == [
      "dotnet_sdk",
      "expected_listener_version",
      "externals",
      "nuget_locks"
    ] and
    (.runtime.runner_release.build.dotnet_sdk | keys) == [
      "asset_name",
      "rid",
      "runtime_version",
      "sha512",
      "source_url",
      "version"
    ] and
    .runtime.runner_release.build.expected_listener_version ==
      (.runtime.runner_release.version | ltrimstr("v")) and
    [.runtime.runner_release.build.externals[].layout] == [
      "node20",
      "node20_alpine",
      "node24",
      "node24_alpine"
    ] and
    all(.runtime.runner_release.build.externals[];
      keys == ["asset_name", "layout", "sha256", "source_url", "version"]
    ) and
    (.runtime.runner_release.build.nuget_locks | keys) == [
      "aggregate_sha256",
      "files"
    ] and
    [.runtime.runner_release.build.nuget_locks.files[].path] == [
      "Runner.Common/packages.lock.json",
      "Runner.Listener/packages.lock.json",
      "Runner.PluginHost/packages.lock.json",
      "Runner.Plugins/packages.lock.json",
      "Runner.Sdk/packages.lock.json",
      "Runner.Worker/packages.lock.json",
      "Sdk/packages.lock.json"
    ] and
    all(.runtime.runner_release.build.nuget_locks.files[];
      keys == ["path", "sha256"]
    )
  ' "$MANIFEST"
  [ "$status" -eq 0 ]
}

@test "release tools and immutable BuildKit identity are exact" {
  run jq -e '
    .runtime.tools.buildx == {
      version: "v0.36.0",
      asset_name: "buildx-v0.36.0.linux-amd64",
      sha256: "07823fdfcd82a41be90155a8b16876c1a780a6462de805a9f3f63b3119ccfb99",
      source_url: "https://github.com/docker/buildx/releases/download/v0.36.0/buildx-v0.36.0.linux-amd64"
    } and
    .runtime.tools.buildkit == {
      image: "moby/buildkit:v0.32.0@sha256:1f8167fcb0eca5b7126353d35299386945cbb8949cc516c592a49f80cfce4fa2",
      platform_digest: "sha256:af9560645cde6da2d0c5be4ebe5b2ec67ab63269ae4d4561b4afd49d9d8121fe"
    } and
    .runtime.tools.syft.version == "v1.50.0" and
    .runtime.tools.syft.sha256 == "bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788" and
    .runtime.tools.trivy.version == "v0.72.0" and
    .runtime.tools.trivy.sha256 == "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea"
  ' "$MANIFEST"
  [ "$status" -eq 0 ]
}

@test "release binaries bind the exact release version and source commit" {
  local version=binary-stamp-fixture
  local commit
  local stamp
  local name
  local package
  local package_json
  commit="$(printf '%040d' 0)"
  mkdir -m 700 "$WORK/bin"

  run bash -c '
    exec env GOTOOLCHAIN=go1.26.6 \
      go run ./internal/buildinfo/cmd/portable-ghar-build-identity \
      "$1" "$2" 2>"$3"
  ' _ "$version" "$commit" "$WORK/build-identity.stderr"
  [ "$status" -eq 0 ]
  stamp=$output
  [ -n "$stamp" ]

  run env \
    PGHAR_EXPECTED_BUILD_VERSION="$version" \
    PGHAR_EXPECTED_BUILD_COMMIT="$commit" \
    GOTOOLCHAIN=go1.26.6 \
    go test \
    -run '^TestLinkedIdentity$' \
    -count=1 \
    "-ldflags=-s -w -buildid= -X github.com/sumitake/portable-ghar/internal/buildinfo.version=$version -X github.com/sumitake/portable-ghar/internal/buildinfo.commit=$commit" \
    ./internal/buildinfo
  [ "$status" -ne 0 ]
  [[ "$output" == *"buildinfo: invalid build identity"* ]]

  run env \
    PGHAR_EXPECTED_BUILD_VERSION="$version" \
    PGHAR_EXPECTED_BUILD_COMMIT="$commit" \
    GOTOOLCHAIN=go1.26.6 \
    go test \
    -run '^TestLinkedIdentity$' \
    -count=1 \
    "-ldflags=-s -w -buildid= -X github.com/sumitake/portable-ghar/internal/buildinfo.version=$version -X github.com/sumitake/portable-ghar/internal/buildinfo.commit=$commit -X github.com/sumitake/portable-ghar/internal/buildinfo.stamp=$stamp" \
    ./internal/buildinfo
  [ "$status" -eq 0 ]

  while IFS="$(printf '\t')" read -r name package; do
    run bash -c '
      exec env GOTOOLCHAIN=go1.26.6 \
        go list -json "$1" 2>"$2"
    ' _ "$package" "$WORK/go-list.stderr"
    [ "$status" -eq 0 ]
    package_json=$output
    run jq -e \
      --arg required \
      "github.com/sumitake/portable-ghar/internal/buildinfo" \
      '.Imports | index($required) != null' <<<"$package_json"
    [ "$status" -eq 0 ]

    run env \
      CGO_ENABLED=0 \
      GOOS=linux \
      GOARCH=amd64 \
      GOTOOLCHAIN=go1.26.6 \
      go build \
      -trimpath \
      -buildvcs=false \
      "-ldflags=-s -w -buildid= -X github.com/sumitake/portable-ghar/internal/buildinfo.version=$version -X github.com/sumitake/portable-ghar/internal/buildinfo.commit=$commit -X github.com/sumitake/portable-ghar/internal/buildinfo.stamp=$stamp" \
      -o "$WORK/bin/$name" \
      "$package"
    [ "$status" -eq 0 ]

    run python3 -B - "$WORK/bin/$name" "$stamp" <<'PY'
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
assert sys.argv[2].encode("ascii") in raw
assert b"portable-ghar-build-identity-v1|dev|unknown" not in raw
PY
    [ "$status" -eq 0 ]
  done < <(
    jq -r '.runtime.binaries[] | [.name, .package] | @tsv' "$MANIFEST"
  )
}

@test "candidate overlay cannot rewrite build identity proof surfaces" {
  run jq -e '
    (.runtime.candidate_substitutions |
      map(select(.replace == true) | .path)) as $rewritten |
    ([
      "internal/buildinfo/buildinfo.go",
      "internal/buildinfo/cmd/portable-ghar-build-identity/main.go",
      "scripts/release/rehearse-runtime.sh",
      "tests/shell/runtime-release.bats"
    ] + [
      .runtime.binaries[].package |
      ltrimstr("./") + "/build_identity.go"
    ]) |
    all(. as $path | ($rewritten | index($path) == null))
  ' "$MANIFEST"
  [ "$status" -eq 0 ]
}

@test "rehearsal treats Docker cleanup failure as terminal and rolls back output" {
  grep -F 'if completed.returncode != 0:' "$REHEARSE"
  grep -F 'failed_before_cleanup = sys.exc_info()[0] is not None' "$REHEARSE"
  grep -F 'if output_committed and (failed_before_cleanup or cleanup_failed):' \
    "$REHEARSE"
  grep -F 'shutil.rmtree(output)' "$REHEARSE"
}

@test "rehearsal bounds downloads and explicitly reclaims the inspection container" {
  grep -F 'MAX_TOOL_BYTES = 512 * 1024 * 1024' "$REHEARSE"
  grep -F '"--disable",' "$REHEARSE"
  grep -F '"--max-filesize",' "$REHEARSE"
  grep -F 'f"pghar-inspect-{os.getpid()}-{time.monotonic_ns()}"' "$REHEARSE"
  grep -F '"--name",' "$REHEARSE"
  grep -F '["docker", "container", "rm", "-f", inspection_container]' "$REHEARSE"
  grep -F 'if inspection_container is not None:' "$REHEARSE"
}

@test "candidate overlay is closed across tracked paths and protected identities" {
  run run_candidate_overlay_case valid
  [ "$status" -eq 0 ]

  run run_candidate_overlay_case unlisted
  [ "$status" -eq 0 ]

  run run_candidate_overlay_case third-value
  [ "$status" -eq 0 ]

  run run_candidate_overlay_case major-upgrade
  [ "$status" -eq 0 ]

  run run_candidate_overlay_case count-mismatch
  [ "$status" -eq 0 ]
}

@test "real candidate inventory closes every baseline token outside its authority manifest" {
  run python3 -B - "$REPO_ROOT" "$MANIFEST" <<'PY'
import hashlib
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
runtime = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))["runtime"]
baseline = runtime["runner_release"]
old = {
    "version_bare": baseline["version"][1:],
    "source_commit": baseline["source_commit_sha"],
    "source_tree": baseline["source_tree_sha"],
    "runner_release_evidence": baseline["observation_evidence"],
    "command_settings_sha256": baseline["command_settings_sha256"],
}
matcher = re.compile(
    rb"(?<![0-9A-Za-z])v?((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    rb"(?:0|[1-9][0-9]*))(?![0-9]|\.[0-9])"
    rb"|(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{40})(?![0-9a-f])"
)


def identity_digest(path):
    values = []
    for match in matcher.finditer(path.read_bytes()):
        if match.group(1) is not None:
            values.append(["runner-version", match.group(1).decode("ascii")])
        else:
            value = match.group(2).decode("ascii")
            values.append([f"hex{len(value)}", value])
    raw = (
        json.dumps(values, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


protected = {
    entry["path"]: entry["identity_inventory_sha256"]
    for entry in runtime["candidate_protected_files"]
}
table_paths = {entry["path"] for entry in runtime["candidate_substitutions"]}
assert set(protected) == table_paths
for relative, expected in protected.items():
    assert identity_digest(root / relative) == expected

expected = {name: 0 for name in old}
for entry in runtime["candidate_substitutions"]:
    expected[entry["token"]] += entry["count"]
observed = {name: 0 for name in old}
tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
for raw_path in tracked:
    if not raw_path:
        continue
    relative = raw_path.decode("utf-8", "strict")
    if relative == "release/manifest.json":
        continue
    content = (root / relative).read_bytes()
    for token, value in old.items():
        observed[token] += content.count(value.encode("ascii"))
assert observed == expected
PY
  [ "$status" -eq 0 ]
}

@test "rehearsal source-builds the runner before image preparation and commits authority atomically" {
  run python3 -B - "$REHEARSE" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
main = text[text.index("def main():") :]
overlay = main.index("apply_candidate_overlay(")
source_build = main.index('"scripts/release/build-runner-from-source.py"')
build_stage = main.index("set_stage(RehearsalStage.BUILD)")
prepare_runner = main.index('"scripts/prepare-task5-images.sh"')
runner_runtime = main.index('"--runner-runtime"', prepare_runner)
runner_manifest = main.index('"--runner-manifest"', prepare_runner)
assert overlay < source_build < build_stage < prepare_runner < runner_runtime
source_build_call = main[source_build:build_stage]
assert '"--runner-manifest"' in source_build_call
assert "os.fspath(runner_path)" in source_build_call
assert '"--output"' in source_build_call
assert "os.fspath(runner_runtime)" in source_build_call
assert '"--work-root"' in source_build_call
prepare_call = main[prepare_runner:main.index('set_stage(RehearsalStage.SECURITY)', prepare_runner)]
assert runner_runtime < runner_manifest
assert "os.fspath(runner_path)" in prepare_call
assert "run_source_builder(" in main[source_build - 100:build_stage]
assert "build-runner-from-source: unavailable reason=" in text
for forbidden in (
    "actions-runner-linux-x64-",
    "linux_x64_asset_",
    "runner_archive",
    '"--runner-archive"',
    '"scripts/fetch-runner.sh"',
):
    assert forbidden not in main
assert main.index("write_authority_files(") < main.index(
    "comparator = clone"
)
assert main.index("[os.fspath(comparator), os.fspath(stage), os.fspath(stage)]") < main.index(
    "os.rename(stage, output)"
)
assert main.index("os.rename(stage, output)") < main.index(
    "output_committed = True"
)
PY
  [ "$status" -eq 0 ]
}

@test "license exceptions are exact consumed tuples and cannot override drift" {
  run python3 -B - "$REHEARSE" "$WORK/license" <<'PY'
import ast
import json
import pathlib
import sys

script = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
root.mkdir()
source = script.read_text(encoding="utf-8")
payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
tree = ast.parse(payload, filename=str(script))
assert isinstance(tree.body[-1], ast.Try)
tree.body = tree.body[:-1]
namespace = {}
exec(compile(tree, str(script), "exec"), namespace)

sbom = root / "subject.spdx.json"
output = root / "notices.txt"
package = {
    "name": "fixture",
    "versionInfo": "1.0.0",
    "licenseConcluded": "NOASSERTION",
    "licenseDeclared": "NOASSERTION",
    "externalRefs": [
        {
            "referenceType": "purl",
            "referenceLocator": "pkg:generic/fixture@1.0.0",
        }
    ],
}
sbom.write_text(json.dumps({"packages": [package]}) + "\n", encoding="utf-8")
exact = {
    "subject": "binary",
    "purl": "pkg:generic/fixture@1.0.0",
    "version": "1.0.0",
    "license_expression": "MIT",
    "reason": "fixture lacks declared metadata",
}
namespace["generate_notices"]([("binary", sbom)], [exact], output)
assert "binary\tpkg:generic/fixture@1.0.0\t1.0.0\tMIT\tfixture" in output.read_text()

for mutated in (
    {**exact, "subject": "other"},
    {**exact, "version": "2.0.0"},
):
    try:
        namespace["generate_notices"]([("binary", sbom)], [mutated], output)
    except namespace["RehearsalError"]:
        pass
    else:
        raise AssertionError("mismatched exception accepted")

package["licenseConcluded"] = "Apache-2.0"
sbom.write_text(json.dumps({"packages": [package]}) + "\n", encoding="utf-8")
try:
    namespace["generate_notices"]([("binary", sbom)], [exact], output)
except namespace["RehearsalError"]:
    pass
else:
    raise AssertionError("license drift accepted")
PY
  [ "$status" -eq 0 ]
}

@test "rehearsal download redirects are one-hop and host locked" {
  ! grep -F '"--location",' "$REHEARSE"
  grep -F 'ASSET_REDIRECT_HOST = "release-assets.githubusercontent.com"' \
    "$REHEARSE"
  grep -F 'parsed.hostname != ASSET_REDIRECT_HOST' "$REHEARSE"
  grep -F 'second_status != 200 or second_redirect' "$REHEARSE"
}

@test "every production Dockerfile is digest pinned and only runner acquires snapshot packages" {
  run python3 - "$REPO_ROOT" "$MANIFEST" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text())
images = manifest["runtime"]["images"]
snapshot_lock = json.loads(
    (root / "images/runner/debian-snapshot.lock.json").read_text()
)
expected_sources = [
    (
        "deb [check-valid-until=no] "
        "https://snapshot.debian.org/archive/"
        f"{row['archive']}/{snapshot_lock['snapshot']} "
        f"{row['suite']} {row['component']}"
    )
    for row in snapshot_lock["sources"]
]
assert len(images) == 6
acquirers = []
for entry in images:
    dockerfile = root / entry["dockerfile"]
    text = dockerfile.read_text()
    for line in text.splitlines():
        if line.startswith("FROM "):
            image = line.split()[1]
            assert image == "scratch" or "@sha256:" in image
    assert "deb.debian.org" not in text
    assert "security.debian.org" not in text
    if "apt-get" in text:
        acquirers.append(entry["name"])
        assert all(source in text for source in expected_sources)
        assert "ARG SOURCE_DATE_EPOCH" in text
assert acquirers == ["runner"]
PY
  [ "$status" -eq 0 ]
  grep -F 'scripts/ci/check_runner_debian_snapshot.py' "$REHEARSE"
}

@test "rehearsal rejects malformed arguments and an existing output before Docker" {
  run "$REHEARSE"
  [ "$status" -eq 2 ]

  mkdir "$WORK/output"
  printf '{}\n' >"$WORK/runner.json"
  run "$REHEARSE" \
    --release-kind candidate \
    --version 0.1.0 \
    --runner-manifest "$WORK/runner.json" \
    --output "$WORK/output"
  [ "$status" -eq 1 ]
}

@test "rehearsal rejects malformed candidate identity before Docker" {
  printf '{"schema_version":2,"version":"v2.336.0"}\n' >"$WORK/runner.json"
  run "$REHEARSE" \
    --release-kind candidate \
    --version 0.1.0 \
    --runner-manifest "$WORK/runner.json" \
    --output "$WORK/output"
  [ "$status" -eq 1 ]
  [ ! -e "$WORK/output" ]
}

@test "comparator rejects missing arguments and missing artifact trees" {
  run "$COMPARE"
  [ "$status" -eq 2 ]

  mkdir "$WORK/a" "$WORK/b"
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]
}

@test "comparator never rewrites invalid input trees" {
  mkdir "$WORK/a" "$WORK/b"
  printf 'invalid\n' >"$WORK/a/runtime-release.json"
  cp "$WORK/a/runtime-release.json" "$WORK/b/runtime-release.json"
  before_a="$(file_sha256 "$WORK/a/runtime-release.json")"
  before_b="$(file_sha256 "$WORK/b/runtime-release.json")"
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]
  [ "$(file_sha256 "$WORK/a/runtime-release.json")" = "$before_a" ]
  [ "$(file_sha256 "$WORK/b/runtime-release.json")" = "$before_b" ]
}

@test "comparator accepts closed identical trees without changing bytes or metadata" {
  write_runtime_tree "$WORK/a"
  write_runtime_tree "$WORK/b"
  before_a="$(tree_fingerprint "$WORK/a")"
  before_b="$(tree_fingerprint "$WORK/b")"
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 0 ]
  [ "$output" = "" ]
  [ "$(tree_fingerprint "$WORK/a")" = "$before_a" ]
  [ "$(tree_fingerprint "$WORK/b")" = "$before_b" ]
}

@test "comparator rejects changed subject bytes and unsafe filesystem aliases" {
  write_runtime_tree "$WORK/a"
  write_runtime_tree "$WORK/b"
  chmod 755 "$WORK/b/bin/portable-ghar"
  printf 'changed\n' >>"$WORK/b/bin/portable-ghar"
  chmod 555 "$WORK/b/bin/portable-ghar"
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]

  rm -rf "$WORK/b"
  write_runtime_tree "$WORK/b"
  rm "$WORK/b/sbom/runner.spdx.json"
  ln "$WORK/b/notices/THIRD-PARTY-NOTICES.txt" "$WORK/b/sbom/runner.spdx.json"
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]

  rm -rf "$WORK/b"
  write_runtime_tree "$WORK/b"
  printf 'extra\n' >"$WORK/b/extra"
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]
}

@test "comparator rejects internally consistent outer authorities over an invalid OCI graph" {
  write_runtime_tree "$WORK/a" unreferenced-blob
  write_runtime_tree "$WORK/b" unreferenced-blob
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]

  rm -rf "$WORK/a" "$WORK/b"
  write_runtime_tree "$WORK/a" multi-platform
  write_runtime_tree "$WORK/b" multi-platform
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]

  rm -rf "$WORK/a" "$WORK/b"
  write_runtime_tree "$WORK/a" graph-mismatch
  write_runtime_tree "$WORK/b" graph-mismatch
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]
}

@test "comparator rejects noncanonical or incomplete authority layers" {
  write_runtime_tree "$WORK/a"
  write_runtime_tree "$WORK/b"
  chmod 644 "$WORK/b/provenance-subjects.json"
  printf '%s' "$(cat "$WORK/b/provenance-subjects.json")" \
    >"$WORK/b/provenance-subjects.json"
  chmod 444 "$WORK/b/provenance-subjects.json"
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]

  rm -rf "$WORK/b"
  write_runtime_tree "$WORK/b"
  sed '$d' "$WORK/b/checksums.txt" >"$WORK/b/checksums.truncated"
  mv "$WORK/b/checksums.truncated" "$WORK/b/checksums.txt"
  chmod 444 "$WORK/b/checksums.txt"
  run "$COMPARE" "$WORK/a" "$WORK/b"
  [ "$status" -eq 1 ]
}
