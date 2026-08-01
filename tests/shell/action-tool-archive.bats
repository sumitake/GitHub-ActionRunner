#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/stage-action-tool-archive.sh"
  WORK="$(mktemp -d)"
  WORK="$(cd "$WORK" && pwd -P)"
  BIN="$WORK/bin"
  mkdir -p "$BIN"
  LOG="$WORK/calls.log"
  export LOG
  make_runtime_lock
}

teardown() {
  rm -rf "$WORK"
}

make_runtime_lock() {
  cat >"$BIN/runtime-lock" <<'SH'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$LOG"
[ "${1-}" = stage-seeds ] || exit 2
output=""
generation=""
root=""
manifest=""
shift
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --manifest) manifest="$2"; shift 2 ;;
    --generation) generation="$2"; shift 2 ;;
    --output-dir) output="$2"; shift 2 ;;
    *) exit 2 ;;
  esac
done
[ "$generation" = 9 ] && [ -n "$output" ]
if [ -n "$root" ] || [ -n "$manifest" ]; then
  [ -d "$root" ] && [ -f "$manifest" ]
fi
if [ "${RUNTIME_STAGE_FAIL-0}" = 1 ]; then
  mkdir -p "$output"
  exit 1
fi
mkdir -m 700 "$output"
empty=false
[ -n "$root" ] || empty=true
printf '{"schema_version":1,"manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tree_lock_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidence_generation":9,"empty":%s}\n' "$empty" >"$output/READY"
chmod 444 "$output/READY"
cat "$output/READY"
SH
  chmod 755 "$BIN/runtime-lock"
}

@test "stages a nonempty verified source through the authority binary" {
  mkdir -m 700 "$WORK/source"
  printf 'data\n' >"$WORK/source/file"
  chmod 444 "$WORK/source/file"
  printf '{"schema_version":1,"seeds":[]}\n' >"$WORK/manifest.json"
  chmod 400 "$WORK/manifest.json"

  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --runtime-lock-bin "$BIN/runtime-lock" \
    --root "$WORK/source" \
    --manifest "$WORK/manifest.json" \
    --generation 9 \
    --output-dir "$WORK/staged"
  [ "$status" -eq 0 ]
  [ -f "$WORK/staged/READY" ]
  [ "$(find "$WORK" -maxdepth 1 -name '.portable-ghar-stage-ready.*' -print | wc -l | tr -d ' ')" -eq 0 ]
  [ "$output" = '{"schema_version":1,"manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tree_lock_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidence_generation":9,"empty":false}' ]
  grep -F "stage-seeds --root $WORK/source --manifest $WORK/manifest.json --generation 9 --output-dir $WORK/staged" "$LOG"
}

@test "stages an explicit empty immutable seed cache without a source pair" {
  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --runtime-lock-bin "$BIN/runtime-lock" \
    --generation 9 \
    --output-dir "$WORK/staged"
  [ "$status" -eq 0 ]
  [ "$output" = '{"schema_version":1,"manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tree_lock_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidence_generation":9,"empty":true}' ]
  grep -Fx "stage-seeds --generation 9 --output-dir $WORK/staged" "$LOG"
}

@test "rejects a partial source pair and noncanonical generation" {
  mkdir -m 700 "$WORK/source"
  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --runtime-lock-bin "$BIN/runtime-lock" \
    --root "$WORK/source" \
    --generation 9 \
    --output-dir "$WORK/staged"
  [ "$status" -ne 0 ]
  ! grep -F "stage-seeds" "$LOG"

  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --runtime-lock-bin "$BIN/runtime-lock" \
    --generation 09 \
    --output-dir "$WORK/staged"
  [ "$status" -ne 0 ]
  ! grep -F "stage-seeds" "$LOG"
}

@test "rejects a source tree that git could track" {
  git init -q "$WORK/repository"
  mkdir -m 700 "$WORK/repository/source"
  printf 'data\n' >"$WORK/repository/source/file"
  chmod 444 "$WORK/repository/source/file"
  printf '{"schema_version":1,"seeds":[]}\n' >"$WORK/manifest.json"

  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --runtime-lock-bin "$BIN/runtime-lock" \
    --root "$WORK/repository/source" \
    --manifest "$WORK/manifest.json" \
    --generation 9 \
    --output-dir "$WORK/staged"
  [ "$status" -ne 0 ]
  ! grep -F "stage-seeds" "$LOG"
}

@test "removes partial output when verified staging fails" {
  export RUNTIME_STAGE_FAIL=1
  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --runtime-lock-bin "$BIN/runtime-lock" \
    --generation 9 \
    --output-dir "$WORK/staged"
  [ "$status" -ne 0 ]
  [ ! -e "$WORK/staged" ]
  [ "$(find "$WORK" -maxdepth 1 -name '.portable-ghar-stage-ready.*' -print | wc -l | tr -d ' ')" -eq 0 ]
}

@test "uses a private unpredictable directory for readiness capture" {
  grep -F 'mktemp -d' "$SCRIPT"
  ! grep -F 'ready.$$' "$SCRIPT"
}
