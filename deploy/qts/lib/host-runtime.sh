#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Static shell boundary for the installed Portable-GHAR Go authority.

pghar_fail() {
  printf '%s\n' 'portable-ghar-qts: action failed' >&2
  exit "${1:-70}"
}

pghar_require_target() {
  umask 077
  [ "$(/bin/uname -s 2>/dev/null)" = "Linux" ] || pghar_fail 69
  [ "$(/usr/bin/id -u 2>/dev/null)" = "0" ] || pghar_fail 77
}

pghar_require_absolute_path() {
  case "$1" in
  /) return 0 ;;
  /*)
    case "$1" in
    *//* | */./* | */../* | */. | */..) pghar_fail 64 ;;
    esac
    ;;
  *) pghar_fail 64 ;;
  esac
}

pghar_installed_binary() {
  pghar_script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && /bin/pwd -P) ||
    pghar_fail 70
  pghar_binary="${pghar_script_dir}/portable-ghar"
  [ -f "$pghar_binary" ] || pghar_fail 69
  [ -x "$pghar_binary" ] || pghar_fail 69
  printf '%s\n' "$pghar_binary"
}

pghar_invoke() {
  pghar_binary=$(pghar_installed_binary) || pghar_fail 70
  if ! pghar_result=$("$pghar_binary" host-runtime "$@"); then
    pghar_fail 70
  fi
  [ -n "$pghar_result" ] || pghar_fail 70
  case "$pghar_result" in
  *'
'*) pghar_fail 70 ;;
  esac
  printf '%s\n' "$pghar_result"
}
