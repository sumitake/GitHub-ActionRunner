#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && /bin/pwd -P)
# shellcheck disable=SC1091
. "${script_dir}/lib/host-runtime.sh"
# shellcheck disable=SC1091
. "${script_dir}/lib/operation-journal.sh"

pghar_require_target
[ "$#" -eq 5 ] || pghar_fail 64
[ "$1" = "--private" ] || pghar_fail 64
case "$3" in
--drain-policy=wait | --drain-policy=cancel) ;;
*) pghar_fail 64 ;;
esac
[ "$4" = "--hosted-confirmation" ] || pghar_fail 64
pghar_require_absolute_path "$2"
pghar_require_absolute_path "$5"
[ "$2" != "$5" ] || pghar_fail 64
pghar_resume_operation suspend "$@" --require-zero-listeners
