#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
#
# Prepare the ignored Task 11 synthetic-listener image context from current
# source. This transaction performs no network, Docker, or host mutation.

set -eu
umask 077

die() {
  printf '%s\n' "prepare-task11-images: unavailable" >&2
  exit 1
}

generation=
seen_generation=0
while [ "$#" -gt 0 ]; do
  [ "$#" -eq 2 ] || die
  case "$1" in
  --generation)
    [ "$seen_generation" = 0 ] || die
    generation=$2
    seen_generation=1
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

for dependency in go git cp mv rm mkdir chmod dirname mktemp; do
  command -v "$dependency" >/dev/null 2>&1 || die
done

script_directory=$(CDPATH='' cd -- "$(dirname "$0")" && pwd -P) || die
repository=$(cd -P "$script_directory/.." && pwd -P) || die
context="$repository/images/synthetic-listener"
[ -f "$repository/go.mod" ] && [ -d "$context" ] || die

build="$context/build"
stage="$context/.build.$$"
prepare_lock="$repository/images/.task11-prepare.lock"
[ ! -e "$build" ] && [ ! -L "$build" ] || die
[ ! -e "$stage" ] && [ ! -L "$stage" ] || die
[ ! -e "$prepare_lock" ] && [ ! -L "$prepare_lock" ] || die
git -C "$repository" check-ignore -q --no-index -- "images/synthetic-listener/build/probe" || die
git -C "$repository" check-ignore -q --no-index -- "images/synthetic-listener/.build.1/probe" || die
git -C "$repository" check-ignore -q --no-index -- "images/.task11-prepare.lock/probe" || die

work=
committed=0
lock_owned=0
# shellcheck disable=SC2329 # invoked by the EXIT trap below.
cleanup() {
  status=$1
  trap - 0 1 2 15
  if [ "$committed" != 1 ]; then
    for candidate in "$stage" "$build"; do
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
[ ! -e "$build" ] && [ ! -L "$build" ] || die
work=$(mktemp -d "${TMPDIR:-/tmp}/portable-ghar-task11-images.XXXXXX") || die
work=$(cd -P "$work" && pwd -P) || die
chmod 700 "$work" || die

native_runtime_lock="$work/portable-ghar-runtime-lock"
listener="$work/portable-ghar-task11-listener"
runner_gate="$work/portable-ghar-runner-gate"
(
  cd "$repository"
  GOTOOLCHAIN=go1.26.6 \
    go build -trimpath -buildvcs=false \
    -o "$native_runtime_lock" ./cmd/portable-ghar-runtime-lock
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.26.6 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$listener" ./cmd/portable-ghar-task11-listener
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.26.6 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$runner_gate" ./cmd/portable-ghar-runner-gate
) || die
chmod 500 "$native_runtime_lock" || die
chmod 555 "$listener" "$runner_gate" || die

runtime_output="$work/listener-runtime"
"$native_runtime_lock" stage-synthetic-listener \
  --listener "$listener" \
  --generation "$generation" \
  --output-dir "$runtime_output" >/dev/null 2>&1 || die

seed_root="$work/seed-source"
seed_directory="$seed_root/task11"
seed_file="$seed_directory/portable-ghar-task11-seed-v1.bin"
seed_manifest="$work/seed.manifest.json"
mkdir -m 700 "$seed_root" "$seed_directory" || die
printf '%s\n' 'portable-ghar-task11-immutable-seed-v1' >"$seed_file" || die
chmod 644 "$seed_file" || die
printf '%s\n' \
  '{"schema_version":1,"seeds":[{"id":"portable-ghar-task11-seed-v1","kind":"synthetic","source":"","revision":"","license":{"spdx":"","path":"","size":0,"sha256":""},"files":[{"path":"task11/portable-ghar-task11-seed-v1.bin","target":"tools/portable-ghar-task11-seed-v1/payload.bin","sha256":"ef368121857519d3895e11481813b99d2e1d76d0555074a79d6af3ce9039e636","size":39,"mode":420}]}]}' \
  >"$seed_manifest" || die
chmod 400 "$seed_manifest" || die

seed_output="$work/seeds"
"$native_runtime_lock" stage-seeds \
  --root "$seed_root" \
  --manifest "$seed_manifest" \
  --generation "$generation" \
  --output-dir "$seed_output" >/dev/null 2>&1 || die

mkdir -m 700 "$stage" || die
cp -p "$runner_gate" "$stage/portable-ghar-runner-gate" || die
cp -Rp "$runtime_output/runner" "$stage/runner" || die
for name in runner.tree-manifest.json runner.tree-lock runner.runtime-lock.json; do
  cp -p "$runtime_output/$name" "$stage/$name" || die
done
cp -p "$runtime_output/READY" "$stage/runner.READY" || die
cp -Rp "$seed_output/seed-cache" "$stage/seed-cache" || die
for name in seed-cache.manifest.json seed-cache.tree-lock; do
  cp -p "$seed_output/$name" "$stage/$name" || die
done
cp -p "$seed_output/READY" "$stage/seed-cache.READY" || die
chmod 555 "$stage/portable-ghar-runner-gate" || die
chmod 444 \
  "$stage/runner.tree-manifest.json" \
  "$stage/runner.tree-lock" \
  "$stage/runner.runtime-lock.json" \
  "$stage/runner.READY" \
  "$stage/seed-cache.manifest.json" \
  "$stage/seed-cache.tree-lock" \
  "$stage/seed-cache.READY" || die

mv "$stage" "$build" || die
committed=1
printf '%s\n' "prepare-task11-images: ready generation=$generation"
exit 0
