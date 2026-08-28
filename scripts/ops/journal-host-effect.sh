#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Fixed-action host journal for synthetic tests. No arbitrary commands.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  printf '%s\n' arguments >&2
  exit 2
fi

journal=$1
operation_id=$2
phase=$3
case "$phase" in
applying | proven) ;;
*)
  printf '%s\n' phase >&2
  exit 2
  ;;
esac
case "$operation_id" in
'' | *[!A-Za-z0-9._-]*)
  printf '%s\n' operation >&2
  exit 2
  ;;
esac

if [ -e "$journal" ]; then
  existing=$(cat "$journal")
  if [ "$existing" = "$operation_id applying" ] && [ "$phase" = proven ]; then
    printf '%s proven\n' "$operation_id" >"$journal"
    printf '%s\n' journaled
    exit 0
  fi
  if [ "$existing" = "$operation_id proven" ]; then
    printf '%s\n' journaled
    exit 0
  fi
  printf '%s\n' conflict >&2
  exit 1
fi

if [ "$phase" != applying ]; then
  printf '%s\n' phase >&2
  exit 1
fi
printf '%s applying\n' "$operation_id" >"$journal"
printf '%s\n' journaled
