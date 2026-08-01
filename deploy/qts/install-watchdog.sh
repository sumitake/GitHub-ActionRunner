#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && /bin/pwd -P)
# shellcheck disable=SC1091
. "${script_dir}/lib/host-runtime.sh"
# shellcheck disable=SC1091
. "${script_dir}/lib/operation-journal.sh"

pghar_require_target
[ "$#" -eq 4 ] || pghar_fail 64
[ "$1" = "--private" ] || pghar_fail 64
[ "$3" = "--manifest" ] || pghar_fail 64
pghar_require_absolute_path "$2"
pghar_require_absolute_path "$4"
[ "$2" != "$4" ] || pghar_fail 64
pghar_resume_operation watchdog-install "$@"
