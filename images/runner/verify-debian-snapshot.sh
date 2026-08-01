#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
#
# Fail closed unless apt's three authenticated InRelease files are exactly the
# content-pinned runner source universe and each signed SHA256 table names the
# locked amd64 Packages index.

set -eu
umask 077

die() {
  printf '%s\n' "verify-debian-snapshot: unavailable" >&2
  exit 1
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

valid_sha256() {
  [ "${#1}" -eq 64 ] || return 1
  case "$1" in
  *[!0-9a-f]*) return 1 ;;
  *) return 0 ;;
  esac
}

verify_one() {
  suite=$1
  expected_inrelease=$2
  expected_packages_size=$3
  expected_packages_sha=$4

  case "$suite" in
  bookworm | bookworm-updates | bookworm-security) ;;
  *) return 1 ;;
  esac
  valid_sha256 "$expected_inrelease" || return 1
  valid_sha256 "$expected_packages_sha" || return 1
  case "$expected_packages_size" in
  [1-9] | [1-9][0-9]*) ;;
  *) return 1 ;;
  esac

  matched=
  matched_count=0
  for candidate in "$lists_directory"/*_dists_"$suite"_InRelease; do
    [ -e "$candidate" ] || [ -L "$candidate" ] || continue
    [ -f "$candidate" ] && [ ! -L "$candidate" ] || return 1
    matched=$candidate
    matched_count=$((matched_count + 1))
  done
  [ "$matched_count" -eq 1 ] || return 1
  [ "$(file_sha256 "$matched")" = "$expected_inrelease" ] || return 1

  awk \
    -v expected_sha="$expected_packages_sha" \
    -v expected_size="$expected_packages_size" '
      $0 == "SHA256:" {
        in_sha256 = 1
        next
      }
      in_sha256 && /^ / {
        if ($1 == expected_sha && $2 == expected_size &&
            $3 == "main/binary-amd64/Packages.xz") {
          matches++
        }
        next
      }
      in_sha256 {
        in_sha256 = 0
      }
      END {
        exit(matches == 1 ? 0 : 1)
      }
    ' "$matched"
}

[ "$#" -eq 13 ] || die
lists_directory=$1
shift

case "$lists_directory" in
/*) ;;
*) die ;;
esac
[ -d "$lists_directory" ] && [ ! -L "$lists_directory" ] || die
resolved_lists=$(
  CDPATH='' cd -- "$lists_directory" 2>/dev/null && pwd -P
) || die
[ "$resolved_lists" = "$lists_directory" ] || die

for dependency in awk wc; do
  command -v "$dependency" >/dev/null 2>&1 || die
done
if ! command -v sha256sum >/dev/null 2>&1 &&
  ! command -v shasum >/dev/null 2>&1; then
  die
fi

inrelease_count=0
for candidate in "$lists_directory"/*_InRelease; do
  [ -e "$candidate" ] || [ -L "$candidate" ] || continue
  [ -f "$candidate" ] && [ ! -L "$candidate" ] || die
  inrelease_count=$((inrelease_count + 1))
done
[ "$inrelease_count" -eq 3 ] || die

[ "$1" = bookworm ] || die
verify_one "$1" "$2" "$3" "$4" || die
shift 4
[ "$1" = bookworm-updates ] || die
verify_one "$1" "$2" "$3" "$4" || die
shift 4
[ "$1" = bookworm-security ] || die
verify_one "$1" "$2" "$3" "$4" || die

printf '%s\n' "verify-debian-snapshot: verified"
