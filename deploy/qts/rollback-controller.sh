#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && /bin/pwd -P)
# shellcheck disable=SC1091
. "${script_dir}/lib/host-runtime.sh"
# shellcheck disable=SC1091
. "${script_dir}/lib/operation-journal.sh"

pghar_require_target
[ "$#" -eq 8 ] || pghar_fail 64
[ "$1" = "--private" ] || pghar_fail 64
[ "$3" = "--expected-generation" ] || pghar_fail 64
case "$4" in
0 | 0* | *[!0-9]* | '') pghar_fail 64 ;;
esac
[ "$5" = "--hosted-confirmation" ] || pghar_fail 64
[ "$7" = "--legacy-command-file" ] || pghar_fail 64
pghar_require_absolute_path "$2"
pghar_require_absolute_path "$6"
pghar_require_absolute_path "$8"
[ "$2" != "$6" ] || pghar_fail 64
[ "$2" != "$8" ] || pghar_fail 64
[ "$6" != "$8" ] || pghar_fail 64
pghar_resume_operation rollback "$@"
