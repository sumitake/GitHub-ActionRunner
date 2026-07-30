#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0
#
# TDD suite for scripts/ci/check-images.sh -- the manifest-driven container
# image build/reproducibility gate. Asserts an explicit empty manifest passes
# without invoking Docker, the real manifest registers all Task-5/6/11 images,
# and malformed manifests fail closed before any Docker invocation.

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/ci/check-images.sh"
  TMP_DIR="$(mktemp -d)"
}

teardown() {
  rm -rf "$TMP_DIR"
}

@test "check-images.sh exists and is executable" {
  [ -f "$SCRIPT" ]
  [ -x "$SCRIPT" ]
}

@test "an explicit empty manifest passes without invoking docker" {
  printf '%s\n' '{"version":1,"images":[]}' >"$TMP_DIR/manifest.json"
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"registers no images"* ]]
}

@test "the real manifest registers all Task 5, Task 6, and Task 11 contexts" {
  run jq -r '.images[].name' "$REPO_ROOT/images/manifest.json"
  [ "$status" -eq 0 ]
  [ "$output" = $'network-adapter\nnetwork-broker-dialer\nnetwork-broker-parser\nnetwork-helper\nnetwork-verifier\nrunner\nsynthetic-listener' ]
}

@test "default manifest path resolves relative to the current directory" {
  mkdir -p "$TMP_DIR/images"
  printf '%s\n' '{"version":1,"images":[]}' >"$TMP_DIR/images/manifest.json"
  cd "$TMP_DIR"
  run bash "$SCRIPT"
  [ "$status" -eq 0 ]
}

@test "IMAGES_MANIFEST env override is honored" {
  printf '%s\n' '{"version":1,"images":[]}' >"$TMP_DIR/manifest.json"
  run env IMAGES_MANIFEST="$TMP_DIR/manifest.json" bash "$SCRIPT"
  [ "$status" -eq 0 ]
}

@test "missing manifest file fails closed" {
  run bash "$SCRIPT" "$TMP_DIR/does-not-exist.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"manifest not found"* ]]
}

@test "invalid JSON fails closed" {
  printf '{not valid json' >"$TMP_DIR/manifest.json"
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not valid JSON"* ]]
}

@test "missing version field fails closed" {
  printf '{"images":[]}' >"$TMP_DIR/manifest.json"
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"version"* ]]
}

@test "wrong version number fails closed" {
  printf '{"version":2,"images":[]}' >"$TMP_DIR/manifest.json"
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"version"* ]]
}

@test "non-array images field fails closed" {
  printf '{"version":1,"images":{}}' >"$TMP_DIR/manifest.json"
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"must be an array"* ]]
}

@test "image entry missing required fields fails closed" {
  printf '{"version":1,"images":[{"name":"runner"}]}' >"$TMP_DIR/manifest.json"
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"must set non-empty"* ]]
}

@test "image entry that is not an object fails closed" {
  printf '{"version":1,"images":["runner"]}' >"$TMP_DIR/manifest.json"
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"must be an object"* ]]
}

@test "duplicate image names fail closed" {
  mkdir -p "$TMP_DIR/images/runner"
  printf 'FROM scratch\n' >"$TMP_DIR/images/runner/Dockerfile"
  cat >"$TMP_DIR/manifest.json" <<EOF
{
  "version": 1,
  "images": [
    {"name": "runner", "context": "$TMP_DIR/images/runner", "dockerfile": "$TMP_DIR/images/runner/Dockerfile"},
    {"name": "runner", "context": "$TMP_DIR/images/runner", "dockerfile": "$TMP_DIR/images/runner/Dockerfile"}
  ]
}
EOF
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"duplicate image name"* ]]
}

@test "missing context directory fails closed" {
  cat >"$TMP_DIR/manifest.json" <<EOF
{
  "version": 1,
  "images": [
    {"name": "runner", "context": "$TMP_DIR/no-such-context", "dockerfile": "$TMP_DIR/no-such-context/Dockerfile"}
  ]
}
EOF
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"context directory not found"* ]]
}

@test "missing dockerfile fails closed" {
  mkdir -p "$TMP_DIR/images/runner"
  cat >"$TMP_DIR/manifest.json" <<EOF
{
  "version": 1,
  "images": [
    {"name": "runner", "context": "$TMP_DIR/images/runner", "dockerfile": "$TMP_DIR/images/runner/Dockerfile"}
  ]
}
EOF
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"dockerfile not found"* ]]
}

@test "dockerfile outside its declared context fails closed" {
  mkdir -p "$TMP_DIR/images/runner" "$TMP_DIR/outside"
  printf 'FROM scratch\n' >"$TMP_DIR/outside/Dockerfile"
  cat >"$TMP_DIR/manifest.json" <<EOF
{
  "version": 1,
  "images": [
    {"name": "runner", "context": "$TMP_DIR/images/runner", "dockerfile": "$TMP_DIR/outside/Dockerfile"}
  ]
}
EOF
  run bash "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"is not inside context"* ]]
}

@test "a well-formed registered image without docker installed fails closed rather than silently skipping" {
  mkdir -p "$TMP_DIR/images/runner"
  printf 'FROM scratch\n' >"$TMP_DIR/images/runner/Dockerfile"
  cat >"$TMP_DIR/manifest.json" <<EOF
{
  "version": 1,
  "images": [
    {"name": "runner", "context": "$TMP_DIR/images/runner", "dockerfile": "$TMP_DIR/images/runner/Dockerfile"}
  ]
}
EOF
  # Build an isolated PATH containing only jq (never docker), so this test
  # deterministically exercises the "docker is required" fail-closed branch
  # regardless of whether the host running this suite happens to have
  # docker installed.
  mkdir -p "$TMP_DIR/bin"
  ln -s "$(command -v jq)" "$TMP_DIR/bin/jq"
  run env PATH="$TMP_DIR/bin" "$(command -v bash)" "$SCRIPT" "$TMP_DIR/manifest.json"
  [ "$status" -ne 0 ]
  [[ "$output" == *"docker is required"* ]]
}

@test "both no-cache builds share the exact commit epoch and disable provenance" {
  mkdir -p "$TMP_DIR/images/runner" "$TMP_DIR/bin"
  printf 'FROM scratch\n' >"$TMP_DIR/images/runner/Dockerfile"
  cat >"$TMP_DIR/manifest.json" <<EOF
{
  "version": 1,
  "images": [
    {"name": "runner", "context": "$TMP_DIR/images/runner", "dockerfile": "$TMP_DIR/images/runner/Dockerfile"}
  ]
}
EOF
  cat >"$TMP_DIR/bin/docker" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$DOCKER_CALLS"
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
  printf '%s\n' 'sha256:fixed-image-id'
fi
EOF
  chmod +x "$TMP_DIR/bin/docker"
  ln -s "$(command -v jq)" "$TMP_DIR/bin/jq"
  ln -s "$(command -v git)" "$TMP_DIR/bin/git"
  expected_epoch="$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)"

  run env \
    DOCKER_CALLS="$TMP_DIR/docker.calls" \
    PATH="$TMP_DIR/bin" \
    "$(command -v bash)" "$SCRIPT" "$TMP_DIR/manifest.json"

  [ "$status" -eq 0 ]
  [ "$(grep -c '^build ' "$TMP_DIR/docker.calls")" -eq 2 ]
  [ "$(grep -c -- "--no-cache --provenance=false --build-arg SOURCE_DATE_EPOCH=$expected_epoch" "$TMP_DIR/docker.calls")" -eq 2 ]
}
