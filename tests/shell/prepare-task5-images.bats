#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/prepare-task5-images.sh"
  WORK="$(mktemp -d)"
}

teardown() {
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
  grep -F 'scripts/stage-action-tool-archive.sh' "$SCRIPT"
  grep -F 'runner.tree-manifest.json runner.tree-lock runner.runtime-lock.json' "$SCRIPT"
  ! grep -F 'cp -R "$acquisition"' "$SCRIPT"
  ! grep -F 'portable-ghar-runtime-lock" "$runner_stage' "$SCRIPT"
  ! grep -F '2.336.0' "$SCRIPT"
  ! grep -F '2.336.0' "$REPO_ROOT/images/runner/Dockerfile"
  grep -F 'runner-download-spec' "$SCRIPT"
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
