#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0
#
# TDD suite for scripts/release/package-source.sh -- the deterministic,
# manifest-gated source-archive packager.
#
# Asserts the core reproducibility contract (two packages of the SAME commit
# produce byte-identical SHA-256) and every fail-closed branch: a dirty tree,
# an invalid/empty VERSION, a missing/underivable SOURCE_DATE_EPOCH, a
# symlink planted at the target artifact path (write-through escape), and an
# output whose name matches no registered release subject.
#
# The suite builds throwaway git repositories in a temp dir so it never
# depends on -- or perturbs -- the repository it lives in.

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/release/package-source.sh"
  WORK="$(mktemp -d)"
  OUT="$(mktemp -d)"
}

teardown() {
  rm -rf "$WORK" "$OUT"
}

# Portable SHA-256 of a file (sha256sum on Linux CI, shasum on macOS).
file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Create a committed, clean git repository at $1 with a fixed commit date so
# the derived SOURCE_DATE_EPOCH is stable across test runs.
make_repo() {
  git init -q "$1"
  git -C "$1" config user.email dev@example.com
  git -C "$1" config user.name "Dev Example"
  git -C "$1" config commit.gpgsign false
  printf 'hello\n' >"$1/README.md"
  printf 'package main\n' >"$1/main.go"
  git -C "$1" add -A
  GIT_COMMITTER_DATE="2020-06-01T12:00:00Z" GIT_AUTHOR_DATE="2020-06-01T12:00:00Z" \
    git -C "$1" commit -qm "initial commit"
}

@test "package-source.sh exists and is executable" {
  [ -f "$SCRIPT" ]
  [ -x "$SCRIPT" ]
}

@test "two packages of the same commit produce identical SHA-256 (determinism)" {
  make_repo "$WORK"
  cd "$WORK"

  run bash "$SCRIPT" 1.0.0 "$OUT/a"
  [ "$status" -eq 0 ]
  run bash "$SCRIPT" 1.0.0 "$OUT/b"
  [ "$status" -eq 0 ]

  [ -f "$OUT/a/portable-ghar-1.0.0.tar.gz" ]
  [ -f "$OUT/b/portable-ghar-1.0.0.tar.gz" ]
  h1="$(file_sha256 "$OUT/a/portable-ghar-1.0.0.tar.gz")"
  h2="$(file_sha256 "$OUT/b/portable-ghar-1.0.0.tar.gz")"
  [ "$h1" = "$h2" ]
}

@test "the archive uses the versioned prefix directory" {
  make_repo "$WORK"
  cd "$WORK"

  run bash "$SCRIPT" 2.3.4 "$OUT/rel"
  [ "$status" -eq 0 ]
  run tar -tzf "$OUT/rel/portable-ghar-2.3.4.tar.gz"
  [ "$status" -eq 0 ]
  [[ "$output" == *"portable-ghar-2.3.4/README.md"* ]]
  [[ "$output" == *"portable-ghar-2.3.4/main.go"* ]]
}

@test "a dirty tree fails closed" {
  make_repo "$WORK"
  cd "$WORK"
  printf 'uncommitted\n' >>README.md

  run bash "$SCRIPT" 1.0.0 "$OUT/x"
  [ "$status" -ne 0 ]
  [[ "$output" == *"dirty"* ]]
  [ ! -f "$OUT/x/portable-ghar-1.0.0.tar.gz" ]
}

@test "an untracked file also makes the tree dirty and fails closed" {
  make_repo "$WORK"
  cd "$WORK"
  printf 'stray\n' >stray.txt

  run bash "$SCRIPT" 1.0.0 "$OUT/x"
  [ "$status" -ne 0 ]
  [[ "$output" == *"dirty"* ]]
}

@test "an empty VERSION fails closed" {
  make_repo "$WORK"
  cd "$WORK"

  run bash "$SCRIPT" "" "$OUT/x"
  [ "$status" -ne 0 ]
  [[ "$output" == *"VERSION"* ]]
}

@test "a VERSION with path-traversal characters fails closed" {
  make_repo "$WORK"
  cd "$WORK"

  run bash "$SCRIPT" "../../etc" "$OUT/x"
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid VERSION"* ]]
}

@test "a VERSION containing a slash fails closed" {
  make_repo "$WORK"
  cd "$WORK"

  run bash "$SCRIPT" "1.0/0" "$OUT/x"
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid VERSION"* ]]
}

@test "a missing/underivable SOURCE_DATE_EPOCH fails closed" {
  # A freshly-initialised repo with no commits: the tree is clean (nothing
  # tracked, nothing untracked) but HEAD has no commit, so no epoch can be
  # derived -- the packager must fail rather than fall back to wall-clock.
  git init -q "$WORK"
  git -C "$WORK" config user.email dev@example.com
  git -C "$WORK" config user.name "Dev Example"
  cd "$WORK"

  run bash "$SCRIPT" 1.0.0 "$OUT/x"
  [ "$status" -ne 0 ]
  [[ "$output" == *"SOURCE_DATE_EPOCH"* ]]
}

@test "a symlink planted at the target artifact path fails closed (write-through escape)" {
  make_repo "$WORK"
  cd "$WORK"
  mkdir -p "$OUT/dest"
  # Plant a symlink where the artifact would be written, pointing outside the
  # output directory. Writing through it would clobber an out-of-tree file.
  ln -s "$OUT/evil-target" "$OUT/dest/portable-ghar-1.0.0.tar.gz"

  run bash "$SCRIPT" 1.0.0 "$OUT/dest"
  [ "$status" -ne 0 ]
  [[ "$output" == *"symlink"* ]]
  [ ! -e "$OUT/evil-target" ]
}

@test "an output that matches no registered subject fails closed" {
  make_repo "$WORK"
  cd "$WORK"
  printf '{"version":1,"subjects":["some-other-artifact-*.zip"]}' >"$WORK/alt-manifest.json"

  run env RELEASE_MANIFEST="$WORK/alt-manifest.json" bash "$SCRIPT" 1.0.0 "$OUT/x"
  [ "$status" -ne 0 ]
  [[ "$output" == *"registered release subject"* ]]
  [ ! -f "$OUT/x/portable-ghar-1.0.0.tar.gz" ]
}

@test "a manifest with the wrong version fails closed" {
  make_repo "$WORK"
  cd "$WORK"
  printf '{"version":2,"subjects":["portable-ghar-*.tar.gz"]}' >"$WORK/alt-manifest.json"

  run env RELEASE_MANIFEST="$WORK/alt-manifest.json" bash "$SCRIPT" 1.0.0 "$OUT/x"
  [ "$status" -ne 0 ]
  [[ "$output" == *"version"* ]]
}

@test "invalid manifest JSON fails closed" {
  make_repo "$WORK"
  cd "$WORK"
  printf '{not valid json' >"$WORK/alt-manifest.json"

  run env RELEASE_MANIFEST="$WORK/alt-manifest.json" bash "$SCRIPT" 1.0.0 "$OUT/x"
  [ "$status" -ne 0 ]
  [[ "$output" == *"JSON"* ]]
}

@test "wrong argument count fails closed" {
  make_repo "$WORK"
  cd "$WORK"

  run bash "$SCRIPT" 1.0.0
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage"* ]]
}
