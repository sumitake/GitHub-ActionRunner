#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Deterministic, manifest-gated source-archive packager for Portable GHAR.
#
# Produces exactly ONE reproducible source tarball
# (portable-ghar-<VERSION>.tar.gz) from the current git work tree's HEAD:
#
#   scripts/release/package-source.sh VERSION OUTPUT_DIR
#
# Reproducibility contract: two invocations against the SAME commit produce
# byte-identical output. This is achieved with `git archive` (deterministic
# for a fixed tree + prefix), a commit-derived SOURCE_DATE_EPOCH, and
# `gzip -n` (no embedded filename or timestamp).
#
# Fails closed -- never a silent skip -- on any of:
#   * a dirty work tree (uncommitted or untracked changes),
#   * an empty or unsafe VERSION (path-traversal / non-release charset),
#   * a missing or underivable SOURCE_DATE_EPOCH (no wall-clock fallback),
#   * a symlink planted at the target artifact path (write-through escape),
#   * an output whose name matches no registered release subject in the
#     manifest (release/manifest.json, or $RELEASE_MANIFEST). Phase 1
#     registers only the source archive glob -- no binaries or images.

set -euo pipefail

fail() {
  printf 'package-source: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: package-source.sh VERSION OUTPUT_DIR\n' >&2
}

if [ "$#" -ne 2 ]; then
  usage
  exit 2
fi

version="$1"
output_dir="$2"

# --- 1. VERSION validation ------------------------------------------------
# A release version is a pure basename component: it becomes both the archive
# filename and the archive's top-level prefix directory. Restricting it to a
# conservative charset (and rejecting '..') guarantees it can never contain a
# path separator or traversal sequence that would let the artifact escape
# OUTPUT_DIR or the prefix escape the archive root.
if [ -z "$version" ]; then
  fail "VERSION must not be empty"
fi
if ! printf '%s' "$version" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._+-]*$'; then
  fail "invalid VERSION '$version' (allowed charset: [A-Za-z0-9][A-Za-z0-9._+-]*)"
fi
case "$version" in
*..*)
  fail "invalid VERSION '$version' (must not contain '..')"
  ;;
esac

# --- 2. Manifest load + registered-subject check --------------------------
script_dir="$(cd "$(dirname "$0")" && pwd)"
default_manifest="$script_dir/../../release/manifest.json"
manifest="${RELEASE_MANIFEST:-$default_manifest}"

command -v jq >/dev/null 2>&1 || fail "jq is required but was not found on PATH"
[ -f "$manifest" ] || fail "release manifest not found: $manifest"
jq empty "$manifest" >/dev/null 2>&1 || fail "release manifest is not valid JSON: $manifest"

manifest_version="$(jq -r 'if has("version") then (.version | tostring) else "<missing>" end' "$manifest")"
if [ "$manifest_version" != "1" ]; then
  fail "release manifest: unsupported or missing \"version\" (expected 1, got $manifest_version)"
fi

subjects_type="$(jq -r '.subjects | type' "$manifest")"
if [ "$subjects_type" != "array" ]; then
  fail "release manifest: \"subjects\" must be an array (got $subjects_type)"
fi

artifact_name="portable-ghar-${version}.tar.gz"

# The produced artifact must match at least one registered subject glob.
# An unregistered output (e.g. a stray binary or image) fails closed.
registered=0
subjects="$(jq -r '.subjects[]' "$manifest")"
while IFS= read -r subject; do
  [ -n "$subject" ] || continue
  # shellcheck disable=SC2254  # $subject is an intentional glob pattern
  case "$artifact_name" in
  $subject)
    registered=1
    break
    ;;
  esac
done <<EOF
$subjects
EOF
if [ "$registered" -ne 1 ]; then
  fail "output '$artifact_name' is not a registered release subject in $manifest"
fi

# --- 3. Clean-tree check --------------------------------------------------
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not inside a git work tree"
if [ -n "$(git status --porcelain)" ]; then
  fail "refusing to package a dirty tree (git status --porcelain is non-empty)"
fi

# --- 4. Commit-derived SOURCE_DATE_EPOCH ----------------------------------
# Prefer an explicit override (so a caller/workflow can pin it); otherwise
# derive it from HEAD's commit time. A missing value is a hard failure -- a
# wall-clock fallback would defeat reproducibility.
source_epoch="${SOURCE_DATE_EPOCH:-}"
if [ -z "$source_epoch" ]; then
  source_epoch="$(git log -1 --format=%ct 2>/dev/null || true)"
fi
case "$source_epoch" in
"")
  fail "missing SOURCE_DATE_EPOCH (could not derive a commit timestamp from HEAD)"
  ;;
*[!0-9]*)
  fail "SOURCE_DATE_EPOCH must be an integer epoch (got '$source_epoch')"
  ;;
esac
export SOURCE_DATE_EPOCH="$source_epoch"

# --- 5. Symlink-escape guard + deterministic archive ----------------------
mkdir -p "$output_dir"
artifact_path="$output_dir/$artifact_name"

# Never write THROUGH a pre-existing symlink at the target path: an
# attacker-planted link could redirect the write outside OUTPUT_DIR.
if [ -L "$artifact_path" ]; then
  fail "refusing to write through an existing symlink at $artifact_path"
fi

# Archive HEAD into a temp file, then atomically move into place. `git
# archive` is deterministic for a fixed commit + prefix; `gzip -n` strips the
# gzip filename/timestamp fields so the compressed bytes are reproducible.
tmp_artifact="$(mktemp "${artifact_path}.XXXXXX")"
trap 'rm -f "$tmp_artifact"' EXIT
git archive --format=tar --prefix="portable-ghar-${version}/" HEAD |
  gzip -n -9 >"$tmp_artifact"
mv -f "$tmp_artifact" "$artifact_path"
trap - EXIT

printf '%s\n' "$artifact_path"
