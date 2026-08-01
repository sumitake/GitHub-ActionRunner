#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../../.." && pwd)"
  WRAPPER="$REPO_ROOT/deploy/qts/run-legacy-fenced.sh"
  COMMAND_DIR="$REPO_ROOT/cmd/portable-ghar-fleet-fence"
}

@test "fleet-fence command and QTS wrapper exist and parse" {
  [ -f "$COMMAND_DIR/main.go" ]
  [ -x "$WRAPPER" ]
  run /bin/sh -n "$WRAPPER"
  [ "$status" -eq 0 ]
}

@test "QTS wrapper refuses a non-Linux host before executing a child" {
  if [ "$(/usr/bin/uname -s)" = "Linux" ]; then
    skip "negative host-platform gate is exercised on non-Linux CI"
  fi
  marker="$BATS_TEST_TMPDIR/started"
  run "$WRAPPER" /usr/bin/touch "$BATS_TEST_TMPDIR/state" 1 -- "$marker"
  [ "$status" -eq 69 ]
  [ "$output" = "run-legacy-fenced: unavailable" ]
  [ ! -e "$marker" ]
}

@test "QTS wrapper has one quoted exec boundary and no evaluation surface" {
  run grep -F 'exec "$fence_binary" guard \' "$WRAPPER"
  [ "$status" -eq 0 ]
  run grep -F -- '--fleet legacy \' "$WRAPPER"
  [ "$status" -eq 0 ]
  run grep -F -- '-- "$@"' "$WRAPPER"
  [ "$status" -eq 0 ]
  run grep -E '(^|[[:space:]])(eval|source|\\.)[[:space:]]' "$WRAPPER"
  [ "$status" -eq 1 ]
  run grep -E 'command[_-]?file|docker|systemctl|launchctl|retag' "$WRAPPER"
  [ "$status" -eq 1 ]
}

@test "Go command tests cover exact forwarding and stale-authority refusal" {
  run env \
    GOCACHE="$BATS_TEST_TMPDIR/go-cache" \
    GOTOOLCHAIN=go1.26.5 \
    go test ./cmd/portable-ghar-fleet-fence \
      -run 'Test(HandoffInspectAndGuardUseOneCanonicalFence|GuardNeverStartsChildWithoutExactAuthority|GuardRenewalFailureTerminatesAndReapsChild|GuardChildRetainsFenceIfParentIsKilled|GuardEscalatesForwardedTerminationAndReapsChild)' \
      -count=1
  [ "$status" -eq 0 ]
}
