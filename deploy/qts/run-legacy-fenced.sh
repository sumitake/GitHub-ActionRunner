#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
#
# Closed QTS legacy-runner fence wrapper. The caller supplies an already
# captured command vector; this file never evaluates or reparses command text.
set -eu

unavailable() {
  printf '%s\n' 'run-legacy-fenced: unavailable' >&2
  exit "$1"
}

[ "$(/bin/uname -s 2>/dev/null)" = "Linux" ] || unavailable 69
[ "$#" -ge 5 ] || unavailable 64

fence_binary="$1"
state_dir="$2"
generation="$3"
separator="$4"
shift 4

case "$fence_binary" in
/*) ;;
*) unavailable 64 ;;
esac
case "$state_dir" in
/*) ;;
*) unavailable 64 ;;
esac
case "$generation" in
0 | *[!0-9]* | '') unavailable 64 ;;
esac
[ "$separator" = "--" ] || unavailable 64
[ "$#" -ge 1 ] || unavailable 64
case "$1" in
/*) ;;
*) unavailable 64 ;;
esac

exec "$fence_binary" guard \
  --state-dir "$state_dir" \
  --fleet legacy \
  --generation "$generation" \
  -- "$@"
