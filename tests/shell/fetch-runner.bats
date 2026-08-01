#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/fetch-runner.sh"
  WORK="$(mktemp -d)"
  WORK="$(cd "$WORK" && pwd -P)"
  BIN="$WORK/bin"
  mkdir -p "$BIN"
  LOG="$WORK/calls.log"
  export LOG
  export RUNNER_ASSET="actions-runner-linux-x64-2.336.0.tar.gz"
  export RUNNER_REDIRECT="https://release-assets.githubusercontent.com/github-production-release-asset/184286875/4f75472f-4bf4-4f5e-b40a-660e7ceb303f?response-content-disposition=attachment%3B%20filename%3D${RUNNER_ASSET}&response-content-type=application%2Foctet-stream&sig=public-release-signature"
  make_runtime_lock
  make_curl
}

teardown() {
  rm -rf "$WORK"
}

make_runtime_lock() {
  cat >"$BIN/runtime-lock" <<'SH'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$LOG"
case "${1-}" in
  runner-download-spec)
    printf '%s\n' '{"schema_version":1,"source_url":"https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz","asset_name":"actions-runner-linux-x64-2.336.0.tar.gz","sha256":"04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d"}'
    ;;
  validate-runner-redirect)
    IFS= read -r value || true
    [ "$value" = "$RUNNER_REDIRECT" ] || exit 1
    printf '%s\n' "$value"
    ;;
  extract-runner)
    [ "${RUNTIME_EXTRACT_FAIL-0}" = 0 ] || {
      output=""
      while [ "$#" -gt 0 ]; do
        if [ "$1" = "--output-dir" ]; then output="$2"; break; fi
        shift
      done
      [ -z "$output" ] || mkdir -p "$output"
      exit 1
    }
    archive=""
    generation=""
    output=""
    shift
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --archive) archive="$2"; shift 2 ;;
        --generation) generation="$2"; shift 2 ;;
        --output-dir) output="$2"; shift 2 ;;
        *) exit 2 ;;
      esac
    done
    [ -f "$archive" ] && [ "$generation" = 7 ] && [ -n "$output" ]
    mkdir -m 700 "$output"
    printf '%s\n' '{"schema_version":1,"runtime_lock_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tree_lock_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","manifest_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","evidence_generation":7}' >"$output/READY"
    chmod 444 "$output/READY"
    cat "$output/READY"
    ;;
  *)
    exit 2
    ;;
esac
SH
  chmod 755 "$BIN/runtime-lock"
}

make_curl() {
  cat >"$BIN/curl" <<'SH'
#!/bin/sh
set -eu
printf 'curl %s\n' "$*" >>"$LOG"
output=""
head_request=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --head) head_request=1; shift ;;
    --output) output="$2"; shift 2 ;;
    --write-out) shift 2 ;;
    *) shift ;;
  esac
done
if [ "${CURL_FAIL-0}" = 1 ]; then
  exit 22
fi
if [ "$head_request" = 1 ]; then
  printf '%s\n%s' "${HEAD_STATUS-302}" "${HEAD_REDIRECT-$RUNNER_REDIRECT}"
  exit 0
fi
[ -n "$output" ] || exit 2
printf 'fake runner archive\n' >"$output"
printf '%s\n%s' "${DOWNLOAD_STATUS-200}" "${DOWNLOAD_EFFECTIVE-$RUNNER_REDIRECT}"
SH
  chmod 755 "$BIN/curl"
}

run_fetch() {
  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --runtime-lock-bin "$BIN/runtime-lock" \
    --generation 7 \
    --build-dir "$WORK/build"
}

@test "fetches only the pinned release through one validated redirect" {
  run_fetch
  [ "$status" -eq 0 ]
  [ -f "$WORK/build/$RUNNER_ASSET" ]
  [ "$(stat -c %a "$WORK/build/$RUNNER_ASSET" 2>/dev/null || stat -f %Lp "$WORK/build/$RUNNER_ASSET")" = 400 ]
  [ -f "$WORK/build/runner-runtime/READY" ]
  [ "$output" = '{"schema_version":1,"runtime_lock_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tree_lock_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","manifest_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","evidence_generation":7}' ]
  grep -Fx "runner-download-spec" "$LOG"
  grep -Fx "validate-runner-redirect" "$LOG"
  grep -F "extract-runner --archive $WORK/build/$RUNNER_ASSET --generation 7 --output-dir $WORK/build/runner-runtime" "$LOG"
  ! grep -E -- '(^|[[:space:]])(-L|--location)([[:space:]]|$)' "$LOG"
}

@test "rejects a redirect outside the release-assets binding and removes the transaction" {
  export HEAD_REDIRECT="https://example.com/not-the-runner"
  run_fetch
  [ "$status" -ne 0 ]
  [ ! -e "$WORK/build" ]
  ! grep -F "extract-runner" "$LOG"
}

@test "rejects unexpected HEAD or final HTTP state" {
  export HEAD_STATUS=200
  run_fetch
  [ "$status" -ne 0 ]
  [ ! -e "$WORK/build" ]

  : >"$LOG"
  unset HEAD_STATUS
  export DOWNLOAD_EFFECTIVE="https://release-assets.githubusercontent.com/other"
  run_fetch
  [ "$status" -ne 0 ]
  [ ! -e "$WORK/build" ]
  ! grep -F "extract-runner" "$LOG"
}

@test "rejects an existing build directory and a noncanonical generation" {
  mkdir "$WORK/build"
  run_fetch
  [ "$status" -ne 0 ]
  rmdir "$WORK/build"

  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --runtime-lock-bin "$BIN/runtime-lock" \
    --generation 07 \
    --build-dir "$WORK/build"
  [ "$status" -ne 0 ]
  [ ! -e "$WORK/build" ]
}

@test "rejects a build directory that git could track" {
  git init -q "$WORK/repository"
  mkdir -m 700 "$WORK/repository/build-parent"
  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --runtime-lock-bin "$BIN/runtime-lock" \
    --generation 7 \
    --build-dir "$WORK/repository/build-parent/build"
  [ "$status" -ne 0 ]
  [ ! -e "$WORK/repository/build-parent/build" ]
}

@test "removes partial output when the authority binary rejects extraction" {
  export RUNTIME_EXTRACT_FAIL=1
  run_fetch
  [ "$status" -ne 0 ]
  [ ! -e "$WORK/build" ]
}
