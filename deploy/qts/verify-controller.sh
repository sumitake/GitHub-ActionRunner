#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && /bin/pwd -P)
# shellcheck disable=SC1091
. "${script_dir}/lib/host-runtime.sh"
# shellcheck disable=SC1091
. "${script_dir}/lib/runtime-manifest.sh"

pghar_require_target
[ "$#" -eq 5 ] || pghar_fail 64
[ "$1" = "--private" ] || pghar_fail 64
[ "$3" = "--manifest" ] || pghar_fail 64
[ "$5" = "--require-zero-listeners" ] || pghar_fail 64
pghar_validate_runtime_manifest "$2" "$4"
