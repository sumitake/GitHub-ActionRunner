#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
#
# Prepare the two untracked Task-5 Docker contexts from one authenticated
# runner acquisition and one verified seed publication. No upstream archive,
# transfer metadata, native verifier, or source tree enters either context.

set -eu
umask 077

die() {
  printf '%s\n' "prepare-task5-images: unavailable" >&2
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

require_untracked_if_in_repository() {
  candidate=$1
  repository=$2
  case "$candidate" in
  "$repository"/*)
    relative=${candidate#"$repository"/}
    git -C "$repository" check-ignore -q -- "$relative" || return 1
    if git -C "$repository" ls-files --error-unmatch -- "$relative" >/dev/null 2>&1; then
      return 1
    fi
    ;;
  esac
}

generation=
runner_archive=
seed_root=
seed_manifest=
seen_generation=0
seen_archive=0
seen_seed_root=0
seen_seed_manifest=0
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || die
  case "$1" in
  --generation)
    [ "$seen_generation" = 0 ] || die
    generation=$2
    seen_generation=1
    ;;
  --runner-archive)
    [ "$seen_archive" = 0 ] || die
    runner_archive=$2
    seen_archive=1
    ;;
  --seed-root)
    [ "$seen_seed_root" = 0 ] || die
    seed_root=$2
    seen_seed_root=1
    ;;
  --seed-manifest)
    [ "$seen_seed_manifest" = 0 ] || die
    seed_manifest=$2
    seen_seed_manifest=1
    ;;
  *)
    die
    ;;
  esac
  shift 2
done

[ "$seen_generation" = 1 ] || die
case "$generation" in
[1-9] | [1-9][0-9]*) ;;
*) die ;;
esac
[ "$seen_seed_root" = "$seen_seed_manifest" ] || die

for dependency in go git jq cp mv rm mkdir chmod dirname basename mktemp; do
  command -v "$dependency" >/dev/null 2>&1 || die
done

script_directory=$(CDPATH='' cd -- "$(dirname "$0")" && pwd -P) || die
repository=$(cd -P "$script_directory/.." && pwd -P) || die
[ -f "$repository/go.mod" ] && [ -d "$repository/images/runner" ] &&
  [ -d "$repository/images/network-adapter" ] || die

runner_build="$repository/images/runner/build"
adapter_build="$repository/images/network-adapter/build"
prepare_lock="$repository/images/.task5-prepare.lock"
[ ! -e "$runner_build" ] && [ ! -L "$runner_build" ] || die
[ ! -e "$adapter_build" ] && [ ! -L "$adapter_build" ] || die
[ ! -e "$prepare_lock" ] && [ ! -L "$prepare_lock" ] || die
git -C "$repository" check-ignore -q --no-index -- "images/runner/build/probe" || die
git -C "$repository" check-ignore -q --no-index -- "images/network-adapter/build/probe" || die
git -C "$repository" check-ignore -q --no-index -- "images/.task5-prepare.lock/probe" || die

if [ "$seen_archive" = 1 ]; then
  canonical_existing_file "$runner_archive" || die
  require_untracked_if_in_repository "$runner_archive" "$repository" || die
fi
if [ "$seen_seed_root" = 1 ]; then
  canonical_existing_directory "$seed_root" || die
  canonical_existing_file "$seed_manifest" || die
  require_untracked_if_in_repository "$seed_root" "$repository" || die
fi

work=
runner_stage="$repository/images/runner/.build.$$"
adapter_stage="$repository/images/network-adapter/.build.$$"
committed=0
lock_owned=0
# shellcheck disable=SC2329 # invoked by the EXIT trap below
cleanup() {
  status=$1
  trap - 0 1 2 15
  if [ "$committed" != 1 ]; then
    for candidate in "$runner_stage" "$adapter_stage" "$runner_build" "$adapter_build"; do
      if [ -e "$candidate" ] || [ -L "$candidate" ]; then
        chmod -R u+w "$candidate" >/dev/null 2>&1 || true
        rm -rf "$candidate"
      fi
    done
  fi
  if [ -n "$work" ]; then
    chmod -R u+w "$work" >/dev/null 2>&1 || true
    rm -rf "$work"
  fi
  if [ "$lock_owned" = 1 ]; then
    rm -rf "$prepare_lock"
  fi
  exit "$status"
}
trap 'cleanup $?' 0
trap 'exit 1' 1 2 15

mkdir -m 700 "$prepare_lock" || die
lock_owned=1
[ ! -e "$runner_build" ] && [ ! -L "$runner_build" ] || die
[ ! -e "$adapter_build" ] && [ ! -L "$adapter_build" ] || die
work=$(mktemp -d "${TMPDIR:-/tmp}/portable-ghar-task5-images.XXXXXX") || die
work=$(cd -P "$work" && pwd -P) || die
chmod 700 "$work" || die

native_runtime_lock="$work/portable-ghar-runtime-lock"
(
  cd "$repository"
  go build -trimpath -buildvcs=false -o "$native_runtime_lock" ./cmd/portable-ghar-runtime-lock
) || die
chmod 500 "$native_runtime_lock" || die

if [ "$seen_archive" = 1 ]; then
  runner_download_spec=$("$native_runtime_lock" runner-download-spec) || die
  expected_runner_asset=$(
    printf '%s\n' "$runner_download_spec" |
      jq -er 'if .schema_version == 1 and (.asset_name | type) == "string" then .asset_name else empty end'
  ) || die
  [ -n "$expected_runner_asset" ] &&
    [ "$(basename "$runner_archive")" = "$expected_runner_asset" ] || die
  acquisition="$work/acquisition"
  mkdir -m 700 "$acquisition" || die
  runtime_output="$acquisition/runner-runtime"
  "$native_runtime_lock" extract-runner \
    --archive "$runner_archive" \
    --generation "$generation" \
    --output-dir "$runtime_output" >/dev/null 2>&1 || die
else
  acquisition="$work/acquisition"
  "$repository/scripts/fetch-runner.sh" \
    --runtime-lock-bin "$native_runtime_lock" \
    --generation "$generation" \
    --build-dir "$acquisition" >/dev/null 2>&1 || die
  runtime_output="$acquisition/runner-runtime"
fi

seed_output="$work/seeds"
if [ "$seen_seed_root" = 1 ]; then
  "$repository/scripts/stage-action-tool-archive.sh" \
    --runtime-lock-bin "$native_runtime_lock" \
    --root "$seed_root" \
    --manifest "$seed_manifest" \
    --generation "$generation" \
    --output-dir "$seed_output" >/dev/null 2>&1 || die
else
  "$repository/scripts/stage-action-tool-archive.sh" \
    --runtime-lock-bin "$native_runtime_lock" \
    --generation "$generation" \
    --output-dir "$seed_output" >/dev/null 2>&1 || die
fi

mkdir -m 700 "$runner_stage" "$adapter_stage" || die
(
  cd "$repository"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$runner_stage/portable-ghar-runner-gate" ./cmd/portable-ghar-runner-gate
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$adapter_stage/portable-ghar-network-adapter" ./cmd/portable-ghar-network-adapter
) || die
chmod 555 "$runner_stage/portable-ghar-runner-gate" \
  "$adapter_stage/portable-ghar-network-adapter" || die

cp -R "$runtime_output/runner" "$runner_stage/runner" || die
for name in runner.tree-manifest.json runner.tree-lock runner.runtime-lock.json; do
  cp -p "$runtime_output/$name" "$runner_stage/$name" || die
done
cp -p "$runtime_output/READY" "$runner_stage/runner.READY" || die
cp -R "$seed_output/seed-cache" "$runner_stage/seed-cache" || die
for name in seed-cache.manifest.json seed-cache.tree-lock; do
  cp -p "$seed_output/$name" "$runner_stage/$name" || die
done
cp -p "$seed_output/READY" "$runner_stage/seed-cache.READY" || die
chmod 444 \
  "$runner_stage/runner.tree-manifest.json" \
  "$runner_stage/runner.tree-lock" \
  "$runner_stage/runner.runtime-lock.json" \
  "$runner_stage/runner.READY" \
  "$runner_stage/seed-cache.manifest.json" \
  "$runner_stage/seed-cache.tree-lock" \
  "$runner_stage/seed-cache.READY" || die

mv "$adapter_stage" "$adapter_build" || die
mv "$runner_stage" "$runner_build" || die
committed=1
printf '%s\n' "prepare-task5-images: ready generation=$generation"
exit 0
