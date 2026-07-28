#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
#
# Fetch one release-locked Linux x64 Actions runner into a private,
# non-trackable build transaction. The runtime-lock binary is the only pin and
# archive-authority source; this wrapper owns only HTTPS transfer mechanics.

set -eu
umask 077

die() {
  printf '%s\n' "fetch-runner: unavailable" >&2
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
  parent=$(dirname "$candidate") || return 1
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

read_transfer_metadata() {
  metadata=$1
  line_count=$(awk 'END { print NR }' "$metadata") || return 1
  [ "$line_count" = 2 ] || return 1
  HTTP_STATUS=$(sed -n '1p' "$metadata") || return 1
  HTTP_TARGET=$(sed -n '2p' "$metadata") || return 1
  [ -n "$HTTP_STATUS" ] && [ -n "$HTTP_TARGET" ]
}

runtime_lock=
generation=
build_directory=
seen_runtime=0
seen_generation=0
seen_build=0
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || die
  case "$1" in
  --runtime-lock-bin)
    [ "$seen_runtime" = 0 ] || die
    runtime_lock=$2
    seen_runtime=1
    ;;
  --generation)
    [ "$seen_generation" = 0 ] || die
    generation=$2
    seen_generation=1
    ;;
  --build-dir)
    [ "$seen_build" = 0 ] || die
    build_directory=$2
    seen_build=1
    ;;
  *)
    die
    ;;
  esac
  shift 2
done

[ "$seen_runtime" = 1 ] && [ "$seen_generation" = 1 ] && [ "$seen_build" = 1 ] || die
case "$generation" in
[1-9] | [1-9][0-9]*) ;;
*) die ;;
esac
canonical_existing_file "$runtime_lock" && [ -x "$runtime_lock" ] || die
canonical_new_path "$build_directory" || die

for dependency in curl git jq awk sed cmp chmod mkdir mv rm; do
  command -v "$dependency" >/dev/null 2>&1 || die
done
require_nontrackable "$build_directory" || die

spec=$("$runtime_lock" runner-download-spec 2>/dev/null) || die
printf '%s' "$spec" | jq -e '
  type == "object" and
  (keys | sort) == ["asset_name", "schema_version", "sha256", "source_url"] and
  .schema_version == 1 and
  (.asset_name | type == "string" and test("^actions-runner-linux-x64-[0-9]+\\.[0-9]+\\.[0-9]+\\.tar\\.gz$")) and
  (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
  (.source_url | type == "string")
' >/dev/null 2>&1 || die
asset_name=$(printf '%s' "$spec" | jq -er '.asset_name') || die
source_url=$(printf '%s' "$spec" | jq -er '.source_url') || die
version=${asset_name#actions-runner-linux-x64-}
version=${version%.tar.gz}
[ "$source_url" = "https://github.com/actions/runner/releases/download/v$version/$asset_name" ] || die

created=0
committed=0
# shellcheck disable=SC2329 # invoked by the EXIT trap below
cleanup() {
  status=$1
  trap - 0 1 2 15
  if [ "$created" = 1 ] && [ "$committed" != 1 ]; then
    chmod -R u+w "$build_directory" >/dev/null 2>&1 || true
    rm -rf "$build_directory"
  fi
  exit "$status"
}
trap 'cleanup $?' 0
trap 'exit 1' 1 2 15

mkdir -m 700 "$build_directory" || die
created=1
spec_path="$build_directory/runner-download-spec.json"
printf '%s\n' "$spec" >"$spec_path" || die
chmod 444 "$spec_path" || die

head_metadata="$build_directory/.head-metadata"
if ! curl \
  --silent --show-error --fail \
  --proto '=https' --proto-redir '=https' \
  --connect-timeout 30 --max-time 120 --max-redirs 0 \
  --head --output /dev/null \
  --write-out '%{http_code}\n%{redirect_url}' \
  "$source_url" >"$head_metadata"; then
  die
fi
read_transfer_metadata "$head_metadata" || die
[ "$HTTP_STATUS" = 302 ] || die
redirect_input="$build_directory/.redirect-input"
redirect_output="$build_directory/.redirect-output"
printf '%s' "$HTTP_TARGET" >"$redirect_input" || die
"$runtime_lock" validate-runner-redirect <"$redirect_input" >"$redirect_output" 2>/dev/null || die
read_transfer_metadata_for_redirect=$(awk 'END { print NR }' "$redirect_output") || die
[ "$read_transfer_metadata_for_redirect" = 1 ] || die
validated_redirect=$(sed -n '1p' "$redirect_output") || die
[ "$validated_redirect" = "$HTTP_TARGET" ] || die

archive_part="$build_directory/.archive.part"
download_metadata="$build_directory/.download-metadata"
if ! curl \
  --silent --show-error --fail \
  --proto '=https' --proto-redir '=https' \
  --connect-timeout 30 --max-time 900 --max-redirs 0 \
  --output "$archive_part" \
  --write-out '%{http_code}\n%{url_effective}' \
  "$validated_redirect" >"$download_metadata"; then
  die
fi
read_transfer_metadata "$download_metadata" || die
[ "$HTTP_STATUS" = 200 ] && [ "$HTTP_TARGET" = "$validated_redirect" ] || die
[ -s "$archive_part" ] && [ ! -L "$archive_part" ] || die
chmod 400 "$archive_part" || die
archive_path="$build_directory/$asset_name"
mv "$archive_part" "$archive_path" || die

runtime_output="$build_directory/runner-runtime"
ready_output="$build_directory/.ready-output"
"$runtime_lock" extract-runner \
  --archive "$archive_path" \
  --generation "$generation" \
  --output-dir "$runtime_output" >"$ready_output" 2>/dev/null || die
[ -f "$runtime_output/READY" ] && [ ! -L "$runtime_output/READY" ] || die
cmp -s "$ready_output" "$runtime_output/READY" || die

rm -f "$head_metadata" "$redirect_input" "$redirect_output" "$download_metadata"
cat "$ready_output" || die
rm -f "$ready_output"
committed=1
exit 0
