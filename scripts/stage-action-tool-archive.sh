#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
#
# Publish one optional first-party seed snapshot. The runtime-lock binary owns
# manifest policy, descriptor-bound verification, immutable copying, and READY.

set -eu
umask 077

die() {
  printf '%s\n' "stage-action-tool-archive: unavailable" >&2
  exit 1
}

canonical_existing_file() {
  candidate=$1
  case "$candidate" in
  /*) ;;
  *) return 1 ;;
  esac
  [ -f "$candidate" ] && [ ! -L "$candidate" ] || return 1
  parent=$(dirname "$candidate") || return 1
  leaf=$(basename "$candidate") || return 1
  resolved=$(cd -P "$parent" 2>/dev/null && pwd -P) || return 1
  [ "$candidate" = "$resolved/$leaf" ]
}

canonical_existing_directory() {
  candidate=$1
  case "$candidate" in
  /*) ;;
  *) return 1 ;;
  esac
  [ -d "$candidate" ] && [ ! -L "$candidate" ] || return 1
  resolved=$(cd -P "$candidate" 2>/dev/null && pwd -P) || return 1
  [ "$candidate" = "$resolved" ]
}

canonical_new_path() {
  candidate=$1
  case "$candidate" in
  /*) ;;
  *) return 1 ;;
  esac
  [ ! -e "$candidate" ] && [ ! -L "$candidate" ] || return 1
  parent=$(dirname "$candidate") || return 1
  leaf=$(basename "$candidate") || return 1
  [ "$leaf" != "." ] && [ "$leaf" != ".." ] && [ -n "$leaf" ] || return 1
  resolved=$(cd -P "$parent" 2>/dev/null && pwd -P) || return 1
  [ "$candidate" = "$resolved/$leaf" ]
}

require_nontrackable() {
  candidate=$1
  parent=$candidate
  [ -d "$candidate" ] || parent=$(dirname "$candidate")
  repository=$(git -C "$parent" rev-parse --show-toplevel 2>/dev/null || true)
  [ -n "$repository" ] || return 0
  repository=$(cd -P "$repository" 2>/dev/null && pwd -P) || return 1
  case "$candidate" in
  "$repository"/*) relative=${candidate#"$repository"/} ;;
  *) return 1 ;;
  esac
  git -C "$repository" check-ignore -q -- "$relative" || return 1
  if git -C "$repository" ls-files --error-unmatch -- "$relative" >/dev/null 2>&1; then
    return 1
  fi
}

runtime_lock=
root=
manifest=
generation=
output_directory=
seen_runtime=0
seen_root=0
seen_manifest=0
seen_generation=0
seen_output=0
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || die
  case "$1" in
  --runtime-lock-bin)
    [ "$seen_runtime" = 0 ] || die
    runtime_lock=$2
    seen_runtime=1
    ;;
  --root)
    [ "$seen_root" = 0 ] || die
    root=$2
    seen_root=1
    ;;
  --manifest)
    [ "$seen_manifest" = 0 ] || die
    manifest=$2
    seen_manifest=1
    ;;
  --generation)
    [ "$seen_generation" = 0 ] || die
    generation=$2
    seen_generation=1
    ;;
  --output-dir)
    [ "$seen_output" = 0 ] || die
    output_directory=$2
    seen_output=1
    ;;
  *)
    die
    ;;
  esac
  shift 2
done

[ "$seen_runtime" = 1 ] && [ "$seen_generation" = 1 ] && [ "$seen_output" = 1 ] || die
[ "$seen_root" = "$seen_manifest" ] || die
case "$generation" in
[1-9] | [1-9][0-9]*) ;;
*) die ;;
esac
canonical_existing_file "$runtime_lock" && [ -x "$runtime_lock" ] || die
canonical_new_path "$output_directory" || die
for dependency in git cmp chmod rm mktemp dirname cat rmdir; do
  command -v "$dependency" >/dev/null 2>&1 || die
done
require_nontrackable "$output_directory" || die

if [ "$seen_root" = 1 ]; then
  canonical_existing_directory "$root" || die
  canonical_existing_file "$manifest" || die
  require_nontrackable "$root" || die
fi

committed=0
owns_output=0
ready_directory=
ready_output=
# shellcheck disable=SC2329 # invoked by the EXIT trap below
cleanup() {
  status=$1
  trap - 0 1 2 15
  if [ -n "$ready_directory" ]; then
    chmod -R u+w "$ready_directory" >/dev/null 2>&1 || true
    rm -rf "$ready_directory"
  fi
  if [ "$owns_output" = 1 ] && [ "$committed" != 1 ]; then
    chmod -R u+w "$output_directory" >/dev/null 2>&1 || true
    rm -rf "$output_directory"
  fi
  exit "$status"
}
trap 'cleanup $?' 0
trap 'exit 1' 1 2 15

ready_directory=$(mktemp -d "$(dirname "$output_directory")/.portable-ghar-stage-ready.XXXXXX") || die
canonical_existing_directory "$ready_directory" || die
chmod 700 "$ready_directory" || die
ready_output="$ready_directory/READY"
owns_output=1
if [ "$seen_root" = 1 ]; then
  "$runtime_lock" stage-seeds \
    --root "$root" \
    --manifest "$manifest" \
    --generation "$generation" \
    --output-dir "$output_directory" >"$ready_output" 2>/dev/null || die
else
  "$runtime_lock" stage-seeds \
    --generation "$generation" \
    --output-dir "$output_directory" >"$ready_output" 2>/dev/null || die
fi
[ -f "$output_directory/READY" ] && [ ! -L "$output_directory/READY" ] || die
cmp -s "$ready_output" "$output_directory/READY" || die
cat "$ready_output" || die
rm -f "$ready_output" || die
rmdir "$ready_directory" || die
ready_directory=
committed=1
exit 0
