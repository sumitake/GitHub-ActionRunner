#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  VERIFY="$REPO_ROOT/images/runner/verify-debian-snapshot.sh"
  WORK="$(mktemp -d)"
  LISTS="$WORK/lists"
  mkdir "$LISTS"
  LISTS="$(cd -P "$LISTS" && pwd -P)"
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

make_inrelease() {
  suite=$1
  packages_sha=$2
  packages_size=$3
  path="$LISTS/snapshot_dists_${suite}_InRelease"
  printf '%s\n' \
    "Suite: $suite" \
    'SHA256:' \
    " $packages_sha $packages_size main/binary-amd64/Packages.xz" >"$path"
  file_sha256 "$path"
}

run_verifier() {
  run "$VERIFY" "$LISTS" \
    bookworm "$BOOKWORM_INRELEASE" 100 "$BOOKWORM_PACKAGES" \
    bookworm-updates "$UPDATES_INRELEASE" 200 "$UPDATES_PACKAGES" \
    bookworm-security "$SECURITY_INRELEASE" 300 "$SECURITY_PACKAGES"
}

prepare_valid_lists() {
  BOOKWORM_PACKAGES="$(
    printf bookworm-packages | file_sha256 /dev/stdin
  )"
  UPDATES_PACKAGES="$(
    printf updates-packages | file_sha256 /dev/stdin
  )"
  SECURITY_PACKAGES="$(
    printf security-packages | file_sha256 /dev/stdin
  )"
  BOOKWORM_INRELEASE="$(
    make_inrelease bookworm "$BOOKWORM_PACKAGES" 100
  )"
  UPDATES_INRELEASE="$(
    make_inrelease bookworm-updates "$UPDATES_PACKAGES" 200
  )"
  SECURITY_INRELEASE="$(
    make_inrelease bookworm-security "$SECURITY_PACKAGES" 300
  )"
}

@test "snapshot verifier accepts exactly three content-pinned signed indexes" {
  prepare_valid_lists
  run_verifier
  [ "$status" -eq 0 ]
  [ "$output" = "verify-debian-snapshot: verified" ]
}

@test "snapshot verifier rejects changed InRelease bytes" {
  prepare_valid_lists
  printf '%s\n' changed >>"$LISTS/snapshot_dists_bookworm_InRelease"
  run_verifier
  [ "$status" -ne 0 ]
}

@test "snapshot verifier rejects missing or extra suite files" {
  prepare_valid_lists
  mv "$LISTS/snapshot_dists_bookworm-security_InRelease" \
    "$WORK/security.InRelease"
  run_verifier
  [ "$status" -ne 0 ]

  mv "$WORK/security.InRelease" \
    "$LISTS/snapshot_dists_bookworm-security_InRelease"
  cp "$LISTS/snapshot_dists_bookworm_InRelease" \
    "$LISTS/unexpected_dists_extra_InRelease"
  run_verifier
  [ "$status" -ne 0 ]
}

@test "snapshot verifier rejects a signed table without exact Packages evidence" {
  prepare_valid_lists
  sed 's#main/binary-amd64/Packages.xz#main/binary-amd64/Packages.gz#' \
    "$LISTS/snapshot_dists_bookworm_InRelease" >"$WORK/changed.InRelease"
  mv "$WORK/changed.InRelease" \
    "$LISTS/snapshot_dists_bookworm_InRelease"
  BOOKWORM_INRELEASE="$(
    file_sha256 "$LISTS/snapshot_dists_bookworm_InRelease"
  )"
  run_verifier
  [ "$status" -ne 0 ]
}
