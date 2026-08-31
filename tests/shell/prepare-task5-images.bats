#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/prepare-task5-images.sh"
  WORK="$(mktemp -d)"
}

teardown() {
  chmod -R u+w "$WORK" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}

make_minimal_repository() {
  repository="$WORK/repository"
  mkdir -p "$repository/scripts" "$repository/images/runner" \
    "$repository/images/network-adapter" "$repository/images/trust/build"
  cp "$SCRIPT" "$repository/scripts/prepare-task5-images.sh"
  chmod 755 "$repository/scripts/prepare-task5-images.sh"
  printf '%s\n' 'module example.invalid/test' >"$repository/go.mod"
  printf '%s\n' \
    'images/runner/build/' \
    'images/network-adapter/build/' \
    'images/trust/build/' \
    'images/.task5-prepare.lock/' >"$repository/.gitignore"
  printf '%s\n' fixture-ca >"$repository/images/trust/build/ca-bundle.pem"
  ca_sha="$(
    python3 -c \
      'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' \
      "$repository/images/trust/build/ca-bundle.pem"
  )"
  printf '%s\n' \
    '{' \
    '  "schema_version": 1,' \
    "  \"sha256\": \"$ca_sha\"," \
    '  "copied_path": "/etc/ssl/certs/ca-bundle.crt",' \
    '  "context_path": "images/trust/build/ca-bundle.pem"' \
    '}' >"$repository/images/trust/ca-bundle.lock.json"
  git -C "$repository" init -q
}

assert_no_transaction() {
  [ ! -e "$repository/images/runner/build" ]
  [ ! -e "$repository/images/network-adapter/build" ]
  [ ! -e "$repository/images/.task5-prepare.lock" ]
}

mode_of() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%OLp' "$1"
  fi
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

make_offline_preparation_fixture() {
  make_minimal_repository
  repository="$(cd -P "$repository" && pwd -P)"
  fake_bin="$WORK/fake-bin"
  mkdir -p "$fake_bin"

  cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
set -eu
output=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output=$2
    shift 2
  else
    shift
  fi
done
[ -n "$output" ]
printf '%s\n' '#!/bin/sh' 'exit 0' >"$output"
chmod 0555 "$output"
EOF
  chmod 0755 "$fake_bin/go"

  cat >"$repository/scripts/fetch-runner.sh" <<'EOF'
#!/bin/sh
set -eu
build=
while [ "$#" -gt 0 ]; do
  case "$1" in
  --build-dir)
    build=$2
    ;;
  esac
  shift 2
done
[ -n "$build" ]
output="$build/runner-runtime"
mkdir -p "$output/runner/bin"
printf '%s\n' runner >"$output/runner/bin/Runner.Listener"
chmod 0700 "$output/runner"
chmod 0555 "$output/runner/bin" "$output/runner/bin/Runner.Listener"
for name in runner.tree-manifest.json runner.tree-lock runner.runtime-lock.json READY; do
  printf '%s\n' "$name" >"$output/$name"
  chmod 0444 "$output/$name"
done
EOF
  chmod 0755 "$repository/scripts/fetch-runner.sh"

  cat >"$repository/scripts/stage-action-tool-archive.sh" <<'EOF'
#!/bin/sh
set -eu
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
  --output-dir)
    output=$2
    ;;
  esac
  shift 2
done
[ -n "$output" ]
mkdir -p "$output/seed-cache/tool"
printf '%s\n' seed >"$output/seed-cache/tool/payload"
chmod 0700 "$output/seed-cache"
chmod 0555 "$output/seed-cache/tool"
chmod 0444 "$output/seed-cache/tool/payload"
for name in seed-cache.manifest.json seed-cache.tree-lock READY; do
  printf '%s\n' "$name" >"$output/$name"
  chmod 0444 "$output/$name"
done
EOF
  chmod 0755 "$repository/scripts/stage-action-tool-archive.sh"
}

@test "prepare-task5-images.sh exists, is executable, and parses as POSIX shell" {
  [ -x "$SCRIPT" ]
  run sh -n "$SCRIPT"
  [ "$status" -eq 0 ]
}

@test "invalid or partial inputs fail before creating a transaction" {
  run "$SCRIPT" --generation 0
  [ "$status" -ne 0 ]
  [[ "$output" == *"prepare-task5-images: unavailable"* ]]

  run "$SCRIPT" --generation 1
  [ "$status" -ne 0 ]
  [[ "$output" == *"prepare-task5-images: unavailable"* ]]

  run "$SCRIPT" --generation 1 --seed-root "$WORK"
  [ "$status" -ne 0 ]
  [[ "$output" == *"prepare-task5-images: unavailable"* ]]

  mkdir -p "$WORK/archive" "$WORK/runtime"
  printf '%s\n' archive >"$WORK/archive/runner.tar.gz"
  run "$SCRIPT" \
    --generation 1 \
    --runner-archive "$WORK/archive/runner.tar.gz" \
    --runner-runtime "$WORK/runtime"
  [ "$status" -ne 0 ]
  [[ "$output" == *"prepare-task5-images: unavailable"* ]]
}

@test "an existing context or preparation lock is never overwritten" {
  make_minimal_repository
  mkdir "$repository/images/runner/build"
  printf '%s\n' sentinel >"$repository/images/runner/build/sentinel"

  run "$repository/scripts/prepare-task5-images.sh" \
    --generation 1 \
    --ca-bundle "$repository/images/trust/build/ca-bundle.pem"
  [ "$status" -ne 0 ]
  [ "$(cat "$repository/images/runner/build/sentinel")" = sentinel ]
  [ ! -e "$repository/images/network-adapter/build" ]
}

@test "CA admission rejects missing, alternate, mismatched, and symlink paths before mutation" {
  make_minimal_repository
  ca_bundle="$repository/images/trust/build/ca-bundle.pem"
  cp "$ca_bundle" "$WORK/original-ca.pem"

  mv "$ca_bundle" "$WORK/missing-ca.pem"
  run "$repository/scripts/prepare-task5-images.sh" \
    --generation 1 \
    --ca-bundle "$ca_bundle"
  [ "$status" -ne 0 ]
  assert_no_transaction
  mv "$WORK/missing-ca.pem" "$ca_bundle"

  cp "$ca_bundle" "$WORK/alternate-ca.pem"
  run "$repository/scripts/prepare-task5-images.sh" \
    --generation 1 \
    --ca-bundle "$WORK/alternate-ca.pem"
  [ "$status" -ne 0 ]
  assert_no_transaction

  printf '%s\n' tampered-ca >"$ca_bundle"
  run "$repository/scripts/prepare-task5-images.sh" \
    --generation 1 \
    --ca-bundle "$ca_bundle"
  [ "$status" -ne 0 ]
  assert_no_transaction

  mv "$ca_bundle" "$WORK/tampered-ca.pem"
  ln -s "$WORK/original-ca.pem" "$ca_bundle"
  run "$repository/scripts/prepare-task5-images.sh" \
    --generation 1 \
    --ca-bundle "$ca_bundle"
  [ "$status" -ne 0 ]
  assert_no_transaction
}

@test "preparation compiles only final static targets and copies only verified outputs" {
  grep -F 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64' "$SCRIPT"
  grep -F './cmd/portable-ghar-runner-gate' "$SCRIPT"
  grep -F './cmd/portable-ghar-network-adapter' "$SCRIPT"
  grep -F 'scripts/fetch-runner.sh' "$SCRIPT"
  grep -F -- '--runner-runtime' "$SCRIPT"
  grep -F -- '--runner-manifest' "$SCRIPT"
  grep -F 'scripts/stage-action-tool-archive.sh' "$SCRIPT"
  grep -F 'runner.tree-manifest.json runner.tree-lock runner.runtime-lock.json' "$SCRIPT"
  ! grep -F 'cp -R "$acquisition"' "$SCRIPT"
  ! grep -F 'portable-ghar-runtime-lock" "$runner_stage' "$SCRIPT"
  ! grep -F '2.336.0' "$SCRIPT"
  ! grep -F '2.336.0' "$REPO_ROOT/images/runner/Dockerfile"
  grep -F 'runner-download-spec' "$SCRIPT"
}

@test "a source-built runtime bypasses archive acquisition and preserves its lock" {
  make_offline_preparation_fixture
  mkdir -p "$repository/release" "$WORK/source-runtime/runner/bin" \
    "$WORK/source-runtime/runner/externals"
  source_runtime="$(cd -P "$WORK/source-runtime" && pwd -P)"
  printf '%s\n' runner >"$source_runtime/runner/bin/Runner.Listener"
  chmod 0700 "$source_runtime/runner"
  chmod 0555 "$source_runtime/runner/bin" \
    "$source_runtime/runner/externals" \
    "$source_runtime/runner/bin/Runner.Listener"
  printf '%s\n' manifest >"$source_runtime/runner.tree-manifest.json"
  printf '%s\n' tree >"$source_runtime/runner.tree-lock"
  manifest_sha="$(file_sha256 "$source_runtime/runner.tree-manifest.json")"
  tree_sha="$(file_sha256 "$source_runtime/runner.tree-lock")"
  cat >"$source_runtime/runner.runtime-lock.json" <<EOF
{"schema_version":2,"runner_version":"v2.336.0","runner_payload_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runner_source_commit":"98aabcd429c4e8402406c56ce2d26387fed3b9ce","runner_source_tree":"3789e2e60ae52fc9c45b78e0d7f436ee2526b6d5","runner_release_evidence":"cfd5c4acaa59579ff850aaad8d4e3f614afc6f80853e870a5271de7db516ba7b","command_settings_sha256":"937f6552579f7d1eeb0a6d0201586781eb3e2e5ea2ab3878429076560e0cab08","runner_base_image":"fixture","manifest_sha256":"$manifest_sha","tree_lock_sha256":"$tree_sha","evidence_generation":1,"listener":{"path":"/opt/actions-runner/bin/Runner.Listener","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":7,"mode":365,"uid":0,"gid":0}}
EOF
  runtime_sha="$(file_sha256 "$source_runtime/runner.runtime-lock.json")"
  cat >"$source_runtime/READY" <<EOF
{"schema_version":1,"runtime_lock_sha256":"$runtime_sha","tree_lock_sha256":"$tree_sha","manifest_sha256":"$manifest_sha","evidence_generation":1}
EOF
  chmod 0444 "$source_runtime/READY" \
    "$source_runtime/runner.runtime-lock.json" \
    "$source_runtime/runner.tree-manifest.json" \
    "$source_runtime/runner.tree-lock"
  runner_manifest="$(cd -P "$WORK" && pwd -P)/candidate-runner-release.json"
  cat >"$runner_manifest" <<'EOF'
{"version":"v2.336.0","source_commit_sha":"98aabcd429c4e8402406c56ce2d26387fed3b9ce","source_tree_sha":"3789e2e60ae52fc9c45b78e0d7f436ee2526b6d5","observation_evidence":"cfd5c4acaa59579ff850aaad8d4e3f614afc6f80853e870a5271de7db516ba7b","command_settings_sha256":"937f6552579f7d1eeb0a6d0201586781eb3e2e5ea2ab3878429076560e0cab08"}
EOF
  cat >"$repository/release/manifest.json" <<'EOF'
{"runtime":{"runner_release":{"version":"v9.9.9","source_commit_sha":"1111111111111111111111111111111111111111","source_tree_sha":"2222222222222222222222222222222222222222","observation_evidence":"3333333333333333333333333333333333333333333333333333333333333333","command_settings_sha256":"4444444444444444444444444444444444444444444444444444444444444444"}}}
EOF

  run env PATH="$fake_bin:$PATH" \
    "$repository/scripts/prepare-task5-images.sh" \
    --generation 1 \
    --runner-runtime "$source_runtime" \
    --ca-bundle "$repository/images/trust/build/ca-bundle.pem"
  [ "$status" -ne 0 ]
  assert_no_transaction

  run env PATH="$fake_bin:$PATH" \
    "$repository/scripts/prepare-task5-images.sh" \
    --generation 1 \
    --runner-runtime "$source_runtime" \
    --runner-manifest "$runner_manifest" \
    --ca-bundle "$repository/images/trust/build/ca-bundle.pem"
  [ "$status" -eq 0 ] || {
    printf '%s\n' "$output" >&2
    false
  }
  [ -f "$repository/images/runner/build/runner.runtime-lock.json" ]
  [ "$(file_sha256 "$repository/images/runner/build/runner.runtime-lock.json")" = "$runtime_sha" ]
}

@test "prepared runner and seed contexts preserve verified object modes" {
  make_offline_preparation_fixture

  run env PATH="$fake_bin:$PATH" \
    "$repository/scripts/prepare-task5-images.sh" \
    --generation 1 \
    --ca-bundle "$repository/images/trust/build/ca-bundle.pem"
  [ "$status" -eq 0 ]

  [ "$(mode_of "$repository/images/runner/build/runner/bin")" = 555 ]
  [ "$(mode_of "$repository/images/runner/build/runner/bin/Runner.Listener")" = 555 ]
  [ "$(mode_of "$repository/images/runner/build/seed-cache/tool")" = 555 ]
  [ "$(mode_of "$repository/images/runner/build/seed-cache/tool/payload")" = 444 ]
}

@test "both Docker contexts deny all by default and audit the effective context" {
  for image in runner network-adapter; do
    [ "$(sed -n '1p' "$REPO_ROOT/images/$image/.dockerignore")" = '**' ]
    grep -F 'COPY . /context' "$REPO_ROOT/images/$image/Dockerfile"
    grep -F '*) exit 1 ;;' "$REPO_ROOT/images/$image/Dockerfile"
  done
  grep -F 'build/runner/**' "$REPO_ROOT/images/runner/.dockerignore"
  grep -F '!build/portable-ghar-network-adapter' \
    "$REPO_ROOT/images/network-adapter/.dockerignore"
}
