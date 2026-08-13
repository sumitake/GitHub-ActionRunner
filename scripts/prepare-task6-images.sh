#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
#
# Prepare the ignored Task-6 image contexts from immutable dependency locks.
# The script performs no Docker or host-network mutation.

set -eu
umask 077

die() {
  printf '%s\n' "prepare-task6-images: unavailable" >&2
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

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

copy_node() {
  relative=$1
  source="$extract/$relative"
  target="$helper_rootfs/$relative"
  [ -e "$source" ] || [ -L "$source" ] || die
  mkdir -p "$(dirname "$target")" || die
  cp -Pp "$source" "$target" || die
}

copy_license() {
  package=$1
  source="$extract/usr/share/doc/$package/copyright"
  target="$helper_rootfs/usr/share/licenses/$package/copyright"
  [ -f "$source" ] && [ ! -L "$source" ] || die
  mkdir -p "$(dirname "$target")" || die
  cp -p "$source" "$target" || die
}

ca_bundle=
seen_ca_bundle=0
while [ "$#" -gt 0 ]; do
  [ "$#" -eq 2 ] || die
  case "$1" in
  --ca-bundle)
    [ "$seen_ca_bundle" = 0 ] || die
    ca_bundle=$2
    seen_ca_bundle=1
    ;;
  *)
    die
    ;;
  esac
  shift 2
done

for dependency in \
  ar awk basename chmod cp curl cut dirname find git go jq ln mkdir mktemp \
  mv python3 readlink rm sort tar; do
  command -v "$dependency" >/dev/null 2>&1 || die
done
if ! command -v sha256sum >/dev/null 2>&1 &&
  ! command -v shasum >/dev/null 2>&1; then
  die
fi

script_directory=$(CDPATH='' cd -- "$(dirname "$0")" && pwd -P) || die
repository=$(cd -P "$script_directory/.." && pwd -P) || die
ca_lock="$repository/images/trust/ca-bundle.lock.json"
ca_sbom="$repository/images/trust/ca-bundle.spdx.json"
package_lock="$repository/images/network-helper/legacy/packages.lock.json"
package_sbom="$repository/images/network-helper/legacy/packages.spdx.json"
context_builder="$repository/scripts/_prepare_task6_context.py"
for required in "$ca_lock" "$ca_sbom" "$package_lock" "$package_sbom" "$context_builder"; do
  [ -f "$required" ] && [ ! -L "$required" ] || die
done

jq -e '
  .schema_version == 1 and
  (.source_url | type) == "string" and
  (.source_revision | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
  (.sha256 | test("^[0-9a-f]{64}$")) and
  .license_spdx == "MPL-2.0" and
  .copied_path == "/etc/ssl/certs/ca-bundle.crt" and
  .context_path == "images/trust/build/ca-bundle.pem" and
  .sbom_path == "images/trust/ca-bundle.spdx.json"
' "$ca_lock" >/dev/null || die
jq -e '
  .schema_version == 1 and
  .snapshot == "20250101T000000Z" and
  .architecture == "amd64" and
  .data_member == "data.tar.xz" and
  (.packages | length) == 8 and
  ([.packages[].name] == ([.packages[].name] | sort | unique)) and
  all(.packages[];
    (.source_url | startswith("https://snapshot.debian.org/archive/debian/20250101T000000Z/")) and
    (.sha256 | test("^[0-9a-f]{64}$")) and
    (.license_spdx | type) == "string")
' "$package_lock" >/dev/null || die
jq -e --slurpfile lock "$package_lock" '
  .spdxVersion == "SPDX-2.3" and
  (.packages | length) == ($lock[0].packages | length) and
  (([.packages[] | {
      name: .name,
      version: .versionInfo,
      source_url: .downloadLocation,
      sha256: .checksums[0].checksumValue,
      license_spdx: .licenseDeclared
    }] | sort_by(.name)) ==
    ([$lock[0].packages[] | {
      name: .name,
      version: .version,
      source_url: .source_url,
      sha256: .sha256,
      license_spdx: .license_spdx
    }] | sort_by(.name)))
' "$package_sbom" >/dev/null || die

if [ "$seen_ca_bundle" = 1 ]; then
  canonical_existing_file "$ca_bundle" || die
fi

contexts="network-helper network-verifier network-broker-parser network-broker-dialer"
for image in $contexts; do
  [ -d "$repository/images/$image" ] || die
  [ ! -e "$repository/images/$image/build" ] &&
    [ ! -L "$repository/images/$image/build" ] || die
  git -C "$repository" check-ignore -q --no-index -- "images/$image/build/probe" || die
done
[ ! -e "$repository/images/trust/build" ] &&
  [ ! -L "$repository/images/trust/build" ] || die
git -C "$repository" check-ignore -q --no-index -- "images/trust/build/probe" || die

prepare_lock="$repository/images/.task6-prepare.lock"
[ ! -e "$prepare_lock" ] && [ ! -L "$prepare_lock" ] || die
git -C "$repository" check-ignore -q --no-index -- "images/.task6-prepare.lock/probe" || die

work=
committed=0
lock_owned=0
helper_stage="$repository/images/network-helper/.build.$$"
verifier_stage="$repository/images/network-verifier/.build.$$"
parser_stage="$repository/images/network-broker-parser/.build.$$"
dialer_stage="$repository/images/network-broker-dialer/.build.$$"
trust_stage="$repository/images/trust/.build.$$"
# shellcheck disable=SC2329 # invoked by traps below.
cleanup() {
  status=$1
  trap - 0 1 2 15
  if [ "$committed" != 1 ]; then
    for candidate in \
      "$helper_stage" "$verifier_stage" "$parser_stage" "$dialer_stage" \
      "$trust_stage" \
      "$repository/images/network-helper/build" \
      "$repository/images/network-verifier/build" \
      "$repository/images/network-broker-parser/build" \
      "$repository/images/network-broker-dialer/build" \
      "$repository/images/trust/build"; do
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
work=$(mktemp -d "${TMPDIR:-/tmp}/portable-ghar-task6-images.XXXXXX") || die
work=$(cd -P "$work" && pwd -P) || die
chmod 700 "$work" || die

expected_ca_sha=$(jq -er '.sha256' "$ca_lock") || die
source_ca_url=$(jq -er '.source_url' "$ca_lock") || die
staged_ca="$work/ca-bundle.pem"
if [ "$seen_ca_bundle" = 1 ]; then
  cp -p "$ca_bundle" "$staged_ca" || die
else
  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --retry 2 \
    --output "$staged_ca" "$source_ca_url" || die
fi
[ "$(file_sha256 "$staged_ca")" = "$expected_ca_sha" ] || die

downloads="$work/packages"
extract="$work/extracted"
mkdir -m 700 "$downloads" "$extract" || die
data_member=$(jq -er '.data_member' "$package_lock") || die
jq -r '.packages[] | [.name, .source_url, .sha256] | @tsv' "$package_lock" |
  while IFS='	' read -r package url expected; do
    [ -n "$package" ] && [ -n "$url" ] && [ -n "$expected" ] || exit 1
    archive="$downloads/$package.deb"
    curl --fail --silent --show-error --location \
      --proto '=https' --tlsv1.2 \
      --connect-timeout 15 --max-time 120 --retry 2 \
      --output "$archive" "$url" || exit 1
    [ "$(file_sha256 "$archive")" = "$expected" ] || exit 1
    member="$downloads/$package.$data_member"
    ar -p "$archive" "$data_member" >"$member" || exit 1
    tar -xJf "$member" -C "$extract" || exit 1
  done || die

mkdir -m 700 \
  "$helper_stage" "$verifier_stage" "$parser_stage" "$dialer_stage" \
  "$trust_stage" || die
helper_rootfs="$helper_stage/rootfs"
mkdir -m 755 "$helper_rootfs" || die

for relative in \
  lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
  lib/x86_64-linux-gnu/libc.so.6 \
  lib/x86_64-linux-gnu/libm.so.6 \
  lib64/ld-linux-x86-64.so.2 \
  usr/sbin/xtables-legacy-multi \
  usr/lib/x86_64-linux-gnu/libip4tc.so.2 \
  usr/lib/x86_64-linux-gnu/libip4tc.so.2.0.0 \
  usr/lib/x86_64-linux-gnu/libip6tc.so.2 \
  usr/lib/x86_64-linux-gnu/libip6tc.so.2.0.0 \
  usr/lib/x86_64-linux-gnu/libmnl.so.0 \
  usr/lib/x86_64-linux-gnu/libmnl.so.0.2.0 \
  usr/lib/x86_64-linux-gnu/libnetfilter_conntrack.so.3 \
  usr/lib/x86_64-linux-gnu/libnetfilter_conntrack.so.3.8.0 \
  usr/lib/x86_64-linux-gnu/libnfnetlink.so.0 \
  usr/lib/x86_64-linux-gnu/libnfnetlink.so.0.2.0 \
  usr/lib/x86_64-linux-gnu/libxtables.so.12 \
  usr/lib/x86_64-linux-gnu/libxtables.so.12.7.0; do
  copy_node "$relative"
done

mkdir -p "$helper_rootfs/usr/lib/x86_64-linux-gnu" || die
cp -Rp \
  "$extract/usr/lib/x86_64-linux-gnu/xtables" \
  "$helper_rootfs/usr/lib/x86_64-linux-gnu/xtables" || die
for command in \
  iptables-restore iptables-save ip6tables-restore ip6tables-save; do
  ln -s xtables-legacy-multi "$helper_rootfs/usr/sbin/$command" || die
done
for package in \
  iptables libc6 libip4tc2 libip6tc2 libmnl0 \
  libnetfilter-conntrack3 libnfnetlink0 libxtables12; do
  copy_license "$package"
done

(
  cd "$repository"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.26.6 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$helper_stage/portable-ghar-network-helper" \
    ./cmd/portable-ghar-network-helper
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.26.6 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$verifier_stage/portable-ghar-network-verifier" \
    ./cmd/portable-ghar-network-verifier
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.26.6 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$parser_stage/portable-ghar-network-broker-parser" \
    ./cmd/portable-ghar-network-broker-parser
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.26.6 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o "$dialer_stage/portable-ghar-network-broker-dialer" \
    ./cmd/portable-ghar-network-broker-dialer
) || die
chmod 555 \
  "$helper_stage/portable-ghar-network-helper" \
  "$verifier_stage/portable-ghar-network-verifier" \
  "$parser_stage/portable-ghar-network-broker-parser" \
  "$dialer_stage/portable-ghar-network-broker-dialer" || die

cp -p \
  "$parser_stage/portable-ghar-network-broker-parser" \
  "$dialer_stage/portable-ghar-network-broker-parser" || die
chmod 555 "$dialer_stage/portable-ghar-network-broker-parser" || die

python3 -B "$context_builder" \
  --rootfs "$helper_rootfs" \
  --package-lock "$package_lock" \
  --output "$helper_stage" || die
cp -p "$package_lock" "$helper_stage/packages.lock.json" || die
cp -p "$package_sbom" "$helper_stage/packages.spdx.json" || die
chmod 444 \
  "$helper_stage/packages.lock.json" \
  "$helper_stage/packages.spdx.json" || die

for stage in "$verifier_stage" "$dialer_stage"; do
  cp -p "$staged_ca" "$stage/ca-bundle.pem" || die
  printf '%s  %s\n' "$expected_ca_sha" "ca-bundle.pem" \
    >"$stage/ca-bundle.sha256" || die
  cp -p "$ca_lock" "$stage/ca-bundle.lock.json" || die
  cp -p "$ca_sbom" "$stage/ca-bundle.spdx.json" || die
  chmod 444 \
    "$stage/ca-bundle.pem" \
    "$stage/ca-bundle.sha256" \
    "$stage/ca-bundle.lock.json" \
    "$stage/ca-bundle.spdx.json" || die
done
cp -p "$staged_ca" "$trust_stage/ca-bundle.pem" || die
chmod 444 "$trust_stage/ca-bundle.pem" || die

mv "$helper_stage" "$repository/images/network-helper/build" || die
mv "$verifier_stage" "$repository/images/network-verifier/build" || die
mv "$parser_stage" "$repository/images/network-broker-parser/build" || die
mv "$dialer_stage" "$repository/images/network-broker-dialer/build" || die
mv "$trust_stage" "$repository/images/trust/build" || die
committed=1
printf '%s\n' \
  "prepare-task6-images: ready ca_revision=$(jq -er '.source_revision' "$ca_lock")"
exit 0
