#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd -P)"
  SCRIPT="$REPO_ROOT/scripts/release/observe-runner-release.sh"
  WORK="$(mktemp -d)"
  WORK="$(cd "$WORK" && pwd -P)"
  BIN="$WORK/bin"
  mkdir -m 700 "$BIN" "$WORK/out"
  export CURL_LOG="$WORK/curl.log"
  export CURRENT_VERSION=v2.335.0
  export CURRENT_TAG_SHA=cccccccccccccccccccccccccccccccccccccccc
  export CURRENT_SOURCE_SHA=cccccccccccccccccccccccccccccccccccccccc
  export CURRENT_ASSET_DIGEST=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  export CURRENT_ASSET_SIZE=101
  export CURRENT_PUBLISHED=2026-06-01T00:00:00Z
  export CURRENT_COMMAND_BODY='current command settings'
  export LATEST_VERSION=v2.336.0
  export LATEST_TAG_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  export LATEST_SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  export LATEST_ASSET_DIGEST=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  export LATEST_ASSET_SIZE=202
  export LATEST_PUBLISHED=2026-07-01T00:00:00Z
  export LATEST_COMMAND_BODY='candidate command settings'
  write_current_manifest
  write_fake_curl
}

teardown() {
  rm -rf "$WORK"
}

evidence_digest() {
  python3 - "$@" <<'PY'
import hashlib
import struct
import sys

h = hashlib.sha256()
for value in ("portable-ghar-runner-release-observation-v1", *sys.argv[1:]):
    raw = value.encode("utf-8")
    h.update(struct.pack(">Q", len(raw)))
    h.update(raw)
print(h.hexdigest())
PY
}

body_digest() {
  printf '%s\n' "$1" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
}

write_current_manifest() {
  local bare evidence command_digest
  bare="${CURRENT_VERSION#v}"
  command_digest="$(body_digest "$CURRENT_COMMAND_BODY")"
  evidence="$(
    evidence_digest \
      "$CURRENT_VERSION" \
      "$CURRENT_TAG_SHA" \
      "$CURRENT_SOURCE_SHA" \
      "actions-runner-linux-x64-$bare.tar.gz" \
      "$CURRENT_ASSET_SIZE" \
      "$CURRENT_ASSET_DIGEST" \
      "$CURRENT_PUBLISHED"
  )"
  jq -n \
    --arg version "$CURRENT_VERSION" \
    --arg tag "$CURRENT_TAG_SHA" \
    --arg source "$CURRENT_SOURCE_SHA" \
    --arg name "actions-runner-linux-x64-$bare.tar.gz" \
    --argjson size "$CURRENT_ASSET_SIZE" \
    --arg digest "$CURRENT_ASSET_DIGEST" \
    --arg published "$CURRENT_PUBLISHED" \
    --arg command "$command_digest" \
    --arg evidence "$evidence" \
    '{
      version: 1,
      subjects: ["portable-ghar-*.tar.gz"],
      runtime: {
        schema_version: 1,
        runner_release: {
          schema_version: 1,
          version: $version,
          tag_ref_sha: $tag,
          source_commit_sha: $source,
          linux_x64_asset_name: $name,
          linux_x64_asset_size: $size,
          linux_x64_asset_digest: $digest,
          published_at: $published,
          command_settings_sha256: $command,
          observation_evidence: $evidence
        }
      }
    }' >"$WORK/current.json"
}

write_fake_curl() {
  cat >"$BIN/curl" <<'SH'
#!/bin/sh
set -eu
[ "$1" = "--disable" ] || exit 2
output=
url=
saw_max_filesize=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --max-filesize)
      saw_max_filesize=1
      shift 2
      ;;
    --output)
      output=$2
      shift 2
      ;;
    http://* | https://*)
      url=$1
      shift
      ;;
    *)
      shift
      ;;
  esac
done
[ "$saw_max_filesize" = 1 ] && [ -n "$output" ] && [ -n "$url" ] || exit 2
printf '%s\n' "$url" >>"$CURL_LOG"
[ "${CURL_FAIL-0}" = 0 ] || exit 22
bare=${LATEST_VERSION#v}
case "$url" in
  https://api.github.com/repos/actions/runner/releases/latest)
    if [ "${DUPLICATE_JSON-0}" = 1 ]; then
      printf '{"tag_name":"%s","tag_name":"%s"}\n' "$LATEST_VERSION" "$LATEST_VERSION" >"$output"
      exit 0
    fi
    duplicate=
    if [ "${DUPLICATE_ASSET-0}" = 1 ]; then
      duplicate=',{"name":"actions-runner-linux-x64-'"$bare"'.tar.gz","size":'"$LATEST_ASSET_SIZE"',"digest":"'"$LATEST_ASSET_DIGEST"'"}'
    fi
    printf '{"tag_name":"%s","draft":%s,"prerelease":%s,"published_at":"%s","assets":[{"name":"actions-runner-linux-arm64-%s.tar.gz","size":1,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"name":"actions-runner-linux-x64-%s.tar.gz","size":%s,"digest":"%s"}%s]}\n' \
      "$LATEST_VERSION" "${LATEST_DRAFT-false}" "${LATEST_PRERELEASE-false}" \
      "$LATEST_PUBLISHED" "$bare" "$bare" "$LATEST_ASSET_SIZE" \
      "$LATEST_ASSET_DIGEST" "$duplicate" >"$output"
    ;;
  https://api.github.com/repos/actions/runner/git/ref/tags/*)
    ref_name=${REF_NAME-"refs/tags/$LATEST_VERSION"}
    ref_type=${REF_TYPE-commit}
    printf '{"ref":"%s","object":{"sha":"%s","type":"%s"}}\n' \
      "$ref_name" "$LATEST_TAG_SHA" "$ref_type" >"$output"
    ;;
  https://api.github.com/repos/actions/runner/git/tags/*)
    printf '{"tag":"%s","object":{"sha":"%s","type":"%s"}}\n' \
      "${ANNOTATED_TAG-$LATEST_VERSION}" "$LATEST_SOURCE_SHA" \
      "${PEELED_TYPE-commit}" >"$output"
    ;;
  https://raw.githubusercontent.com/actions/runner/*/src/Runner.Listener/CommandSettings.cs)
    printf '%s\n' "$LATEST_COMMAND_BODY" >"$output"
    ;;
  *)
    exit 22
    ;;
esac
SH
  chmod 755 "$BIN/curl"
}

run_observer() {
  run env PATH="$BIN:$PATH" "$SCRIPT" \
    --current-manifest "$WORK/current.json" \
    --output "$WORK/out/candidate.json"
}

@test "observer exists and is executable" {
  [ -f "$SCRIPT" ]
  [ -x "$SCRIPT" ]
}

@test "emits one canonical strictly newer Linux x64 candidate" {
  run_observer
  [ "$status" -eq 0 ]
  [ "$output" = "" ]
  [ -f "$WORK/out/candidate.json" ]
  [ "$(tail -c 1 "$WORK/out/candidate.json" | od -An -t u1 | tr -d ' ')" = 10 ]
  run jq -e --arg command "$(body_digest "$LATEST_COMMAND_BODY")" '
    keys == [
      "command_settings_sha256",
      "linux_x64_asset_digest",
      "linux_x64_asset_name",
      "linux_x64_asset_size",
      "observation_evidence",
      "published_at",
      "schema_version",
      "source_commit_sha",
      "tag_ref_sha",
      "version"
    ] and
    .schema_version == 1 and
    .version == "v2.336.0" and
    .linux_x64_asset_name == "actions-runner-linux-x64-2.336.0.tar.gz" and
    .linux_x64_asset_size == 202 and
    .command_settings_sha256 == $command
  ' "$WORK/out/candidate.json"
  [ "$status" -eq 0 ]
  expected="$(
    evidence_digest \
      "$LATEST_VERSION" \
      "$LATEST_TAG_SHA" \
      "$LATEST_SOURCE_SHA" \
      "actions-runner-linux-x64-2.336.0.tar.gz" \
      "$LATEST_ASSET_SIZE" \
      "$LATEST_ASSET_DIGEST" \
      "$LATEST_PUBLISHED"
  )"
  [ "$(jq -r .observation_evidence "$WORK/out/candidate.json")" = "$expected" ]
  grep -Fx "https://api.github.com/repos/actions/runner/releases/latest" "$CURL_LOG"
  grep -Fx "https://api.github.com/repos/actions/runner/git/ref/tags/v2.336.0" "$CURL_LOG"
  grep -Fx "https://raw.githubusercontent.com/actions/runner/$LATEST_SOURCE_SHA/src/Runner.Listener/CommandSettings.cs" "$CURL_LOG"
}

@test "cleanup failure is terminal before candidate publication" {
  mkdir -m 700 "$WORK/site"
  cat >"$WORK/site/sitecustomize.py" <<'PY'
import pathlib
import shutil

original_rmtree = shutil.rmtree
failed = False


def fail_first_observation_cleanup(path, *args, **kwargs):
    global failed
    if not failed and pathlib.Path(path).name.startswith(".runner-observation."):
        failed = True
        raise OSError("injected cleanup failure")
    return original_rmtree(path, *args, **kwargs)


shutil.rmtree = fail_first_observation_cleanup
PY
  run env \
    PYTHONPATH="$WORK/site" \
    PATH="$BIN:$PATH" \
    "$SCRIPT" \
    --current-manifest "$WORK/current.json" \
    --output "$WORK/out/candidate.json"
  [ "$status" -eq 1 ]
  [ ! -e "$WORK/out/candidate.json" ]
  run find "$WORK/out" -mindepth 1 -maxdepth 1 -print
  [ "$status" -eq 0 ]
  [ "$output" = "" ]
}

@test "peels exactly one annotated tag" {
  export REF_TYPE=tag
  export LATEST_TAG_SHA=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
  export LATEST_SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  run_observer
  [ "$status" -eq 0 ]
  [ "$(jq -r .tag_ref_sha "$WORK/out/candidate.json")" = "$LATEST_TAG_SHA" ]
  [ "$(jq -r .source_commit_sha "$WORK/out/candidate.json")" = "$LATEST_SOURCE_SHA" ]
  grep -Fx "https://api.github.com/repos/actions/runner/git/tags/$LATEST_TAG_SHA" "$CURL_LOG"
}

@test "exact current identity is typed no-candidate and writes nothing" {
  export LATEST_VERSION="$CURRENT_VERSION"
  export LATEST_TAG_SHA="$CURRENT_TAG_SHA"
  export LATEST_SOURCE_SHA="$CURRENT_SOURCE_SHA"
  export LATEST_ASSET_DIGEST="$CURRENT_ASSET_DIGEST"
  export LATEST_ASSET_SIZE="$CURRENT_ASSET_SIZE"
  export LATEST_PUBLISHED="$CURRENT_PUBLISHED"
  export LATEST_COMMAND_BODY="$CURRENT_COMMAND_BODY"
  run_observer
  [ "$status" -eq 3 ]
  [ ! -e "$WORK/out/candidate.json" ]
}

@test "downgrade and equal-version identity drift fail closed" {
  export LATEST_VERSION=v2.334.9
  run_observer
  [ "$status" -eq 1 ]
  [ ! -e "$WORK/out/candidate.json" ]

  export LATEST_VERSION="$CURRENT_VERSION"
  run_observer
  [ "$status" -eq 1 ]
  [ ! -e "$WORK/out/candidate.json" ]
}

@test "draft prerelease noncanonical and duplicate Linux x64 releases fail closed" {
  export LATEST_DRAFT=true
  run_observer
  [ "$status" -eq 1 ]
  unset LATEST_DRAFT

  export LATEST_PRERELEASE=true
  run_observer
  [ "$status" -eq 1 ]
  unset LATEST_PRERELEASE

  export LATEST_VERSION=v2.336.0-rc.1
  run_observer
  [ "$status" -eq 1 ]
  export LATEST_VERSION=v2.336.0

  export DUPLICATE_ASSET=1
  run_observer
  [ "$status" -eq 1 ]
}

@test "bad digest duplicate JSON and ref mismatch fail closed" {
  export LATEST_ASSET_DIGEST=bbbb
  run_observer
  [ "$status" -eq 1 ]
  export LATEST_ASSET_DIGEST=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

  export DUPLICATE_JSON=1
  run_observer
  [ "$status" -eq 1 ]
  unset DUPLICATE_JSON

  export REF_NAME=refs/tags/v9.9.9
  run_observer
  [ "$status" -eq 1 ]
}

@test "nested annotated tag and transfer failure fail closed" {
  export REF_TYPE=tag
  export PEELED_TYPE=tag
  run_observer
  [ "$status" -eq 1 ]
  unset REF_TYPE PEELED_TYPE

  export CURL_FAIL=1
  run_observer
  [ "$status" -eq 1 ]
  [ ! -e "$WORK/out/candidate.json" ]
}

@test "existing output and malformed argument surfaces fail before network" {
  : >"$WORK/out/candidate.json"
  run_observer
  [ "$status" -eq 1 ]
  [ ! -s "$CURL_LOG" ]

  run "$SCRIPT" --current-manifest "$WORK/current.json"
  [ "$status" -eq 2 ]
}
