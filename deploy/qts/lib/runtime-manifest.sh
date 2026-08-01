#!/bin/sh
# SPDX-License-Identifier: MPL-2.0

# This helper delegates manifest validation and zero-listener readback to the
# installed Go authority. It never parses manifest JSON in shell.
pghar_validate_runtime_manifest() {
  [ "$#" -eq 2 ] || pghar_fail 64
  pghar_require_absolute_path "$1"
  pghar_require_absolute_path "$2"
  pghar_invoke verify \
    --private "$1" \
    --manifest "$2" \
    --require-zero-listeners
}
