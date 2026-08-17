#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Validate a synthetic or operator-supplied overlay path without printing values.
set -euo pipefail
umask 077

if [ "$#" -ne 1 ]; then
  printf '%s\n' arguments >&2
  exit 2
fi

overlay=$1
if [ ! -d "$overlay" ]; then
  printf '%s\n' missing >&2
  exit 1
fi

mode=
if mode="$(stat -c '%a' "$overlay" 2>/dev/null)"; then
  :
elif mode="$(stat -f '%Lp' "$overlay" 2>/dev/null)"; then
  :
else
  printf '%s\n' mode >&2
  exit 1
fi
if [ "$mode" != 700 ]; then
  printf '%s\n' mode >&2
  exit 1
fi

printf '%s\n' 'private overlay: PASS'
