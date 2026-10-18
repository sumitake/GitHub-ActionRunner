#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# The directory name is not authority. Bind offline bytes to the reviewed
# immutable snapshot; APT subsequently verifies the Debian signature chain.
set -eu
fail() {
  printf '%s\n' 'runner snapshot cache unavailable' >&2
  exit 1
}
[ "$#" -eq 2 ] || fail
cache=$1
[ "$2" = 20261010T000000Z ] || fail
case "$cache" in /*) ;; *) fail ;; esac
[ -d "$cache" ] || fail
[ ! -L "$cache" ] || fail
verify() {
  expected=$1
  relative=$2
  path="$cache/$relative"
  [ -f "$path" ] || fail
  [ ! -L "$path" ] || fail
  printf '%s  %s\n' "$expected" "$path" | sha256sum -c --status || fail
}
verify 77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa archive/debian/20261010T000000Z/dists/bookworm/InRelease
verify dcdf98aca9065258e525b17f1882013c000374c250d7b9c04ed31f5df7be400d archive/debian/20261010T000000Z/dists/bookworm-updates/InRelease
verify 2bd798862c6ff3a5fab5b0798735135cb141d06e0e765fc37cb14a339977226e archive/debian-security/20261010T000000Z/dists/bookworm-security/InRelease
