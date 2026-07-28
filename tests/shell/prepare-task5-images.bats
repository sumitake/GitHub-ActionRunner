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

@test "prepare-task5-images.sh exists, is executable, and parses as POSIX shell" {
  [ -x "$SCRIPT" ]
  run sh -n "$SCRIPT"
  [ "$status" -eq 0 ]
}

@test "invalid or partial inputs fail before creating a transaction" {
  run "$SCRIPT" --generation 0
  [ "$status" -ne 0 ]
  [[ "$output" == *"prepare-task5-images: unavailable"* ]]

  run "$SCRIPT" --generation 1 --seed-root "$WORK"
  [ "$status" -ne 0 ]
  [[ "$output" == *"prepare-task5-images: unavailable"* ]]
}

@test "an existing context or preparation lock is never overwritten" {
  repository="$WORK/repository"
  mkdir -p "$repository/scripts" "$repository/images/runner/build" \
    "$repository/images/network-adapter"
  cp "$SCRIPT" "$repository/scripts/prepare-task5-images.sh"
  chmod 755 "$repository/scripts/prepare-task5-images.sh"
  printf '%s\n' 'module example.invalid/test' >"$repository/go.mod"
  printf '%s\n' \
    'images/runner/build/' \
    'images/network-adapter/build/' \
    'images/.task5-prepare.lock/' >"$repository/.gitignore"
  git -C "$repository" init -q
  printf '%s\n' sentinel >"$repository/images/runner/build/sentinel"

  run "$repository/scripts/prepare-task5-images.sh" --generation 1
  [ "$status" -ne 0 ]
  [ "$(cat "$repository/images/runner/build/sentinel")" = sentinel ]
  [ ! -e "$repository/images/network-adapter/build" ]
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
