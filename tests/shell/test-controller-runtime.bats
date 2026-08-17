#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0
#
# Task 0: the aggregate controller-runtime gate must not wait for an
# interactive confirmation when invoked by CI or an agent.

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/test-controller-runtime.sh"
  TMP_DIR="$(mktemp -d)"
}

teardown() {
  rm -rf "$TMP_DIR"
}

@test "controller-runtime gate exists and is executable" {
  [ -f "$SCRIPT" ]
  [ -x "$SCRIPT" ]
}

@test "controller-runtime gate forces noninteractive stdin before stages" {
  grep -Eq -- '^exec[[:space:]]+</dev/null$' "$SCRIPT"
}

@test "controller-runtime gate does not block on a hanging stdin for usage" {
  fifo="$TMP_DIR/hang"
  mkfifo "$fifo"
  # RDWR open does not wait for a writer, but a later read would block.
  run bash -c '
    set -euo pipefail
    exec 3<>"$1"
    timeout 2 bash "$2" --not-a-mode <&3
  ' bash "$fifo" "$SCRIPT"
  [ "$status" -ne 0 ]
  [ "$status" -ne 124 ]
}
