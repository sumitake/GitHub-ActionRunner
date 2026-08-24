#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0
#
# Task 0: the aggregate controller-runtime gate must not wait for an
# interactive confirmation when invoked by CI or an agent.

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/test-controller-runtime.sh"
  TMP_DIR="$(mktemp -d)"
  FAKE_BIN="$TMP_DIR/bin"
  mkdir -p "$FAKE_BIN"
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

make_failing_gofmt() {
  cat >"$FAKE_BIN/gofmt" <<'EOF'
#!/bin/sh
printf '%s\n' 'FAKE_GOFMT_PRIVATE_OUTPUT' >&2
exit 1
EOF
  chmod +x "$FAKE_BIN/gofmt"
}

make_docker_gate_fakes() {
  export FAKE_DOCKER_STATE="$TMP_DIR/docker-tags"
  export FAKE_DOCKER_CALLS="$TMP_DIR/docker.calls"
  export FAKE_IMAGE_ID="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  export FAKE_CREATED
  FAKE_CREATED="$(
    python3 - "$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)" <<'PY'
import datetime
import sys
print(datetime.datetime.fromtimestamp(
    int(sys.argv[1]),
    datetime.timezone.utc,
).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
  )"
  : >"$FAKE_DOCKER_STATE"
  : >"$FAKE_DOCKER_CALLS"

  cat >"$FAKE_BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_DOCKER_CALLS"

case "${1:-} ${2:-}" in
"info --format")
  printf '%s\n' '"27.1.2"'
  ;;
"ps -a" | "network ls" | "volume ls")
  ;;
"image ls")
  cat "$FAKE_DOCKER_STATE"
  ;;
"buildx build")
  previous=
  for argument in "$@"; do
    if [ "$previous" = --output ]; then
      tag="${argument#*name=}"
      tag="${tag%%,*}"
      printf '%s\n' "$tag" >>"$FAKE_DOCKER_STATE"
      LC_ALL=C sort -u -o "$FAKE_DOCKER_STATE" "$FAKE_DOCKER_STATE"
      exit 0
    fi
    previous=$argument
  done
  exit 1
  ;;
"image inspect")
  case "${4:-}" in
  "{{.Id}}") printf '%s\n' "$FAKE_IMAGE_ID" ;;
  "{{.Created}}") printf '%s\n' "$FAKE_CREATED" ;;
  *) exit 1 ;;
  esac
  ;;
"image rm")
  shift 2
  [ "${1:-}" = -f ] && shift
  temporary="$FAKE_DOCKER_STATE.next"
  cp "$FAKE_DOCKER_STATE" "$temporary"
  for target in "$@"; do
    awk -v target="$target" '$0 != target' "$temporary" >"$temporary.filtered"
    mv "$temporary.filtered" "$temporary"
  done
  mv "$temporary" "$FAKE_DOCKER_STATE"
  ;;
*)
  exit 1
  ;;
esac
EOF
  chmod +x "$FAKE_BIN/docker"

  cat >"$FAKE_BIN/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case " $* " in
*" ./tests/integration "*)
  exit 97
  ;;
*" -tags=integration ./internal/networkjail "*)
  for name in \
    TestShutdownIntegrationAuthorityStopsOnlyExactTuple \
    TestShutdownIntegrationAuthorityAcceptsExactInactiveAbsence \
    TestProveIntegrationAuthorityAbsentIsReadOnly \
    TestShutdownIntegrationAuthorityRejectsPartialOrAmbiguousClaim \
    TestShutdownIntegrationAuthorityRejectsOpenInputs; do
    printf '%s\n' "--- PASS: $name (0.00s)"
  done
  printf '%s\n' 'ok  github.com/sumitake/portable-ghar/internal/networkjail 0.001s'
  ;;
*" -tags=chaos ./tests/chaos -v -count=10 "*)
  [ "${PGHAR_CHAOS_IMAGE:-}" = "$FAKE_IMAGE_ID" ] || exit 98
  if [ "${FAKE_CHAOS_FAIL:-0}" = 1 ]; then
    printf '%s\n' \
      'FAKE_CHAOS_PRIVATE_OUTPUT' \
      '--- FAIL: TestFleetFenceRaceAndObserverRecovery (0.00s)' >&2
    exit 99
  fi
  for _iteration in 1 2 3 4 5 6 7 8 9 10; do
    for name in \
      TestChaosSourceOptInBoundary \
      TestChaosOperationalGate \
      TestControllerStateRestartTable \
      TestDockerComponentFailureCleanup \
      TestFleetFenceRaceAndObserverRecovery \
      TestJailPermitFailuresNeverReachKernelDial \
      TestJailRaceNarrowingAndCancellationRemainClosed \
      TestQTSLifecycleEveryJournalEffectResumesAfterRestart \
      TestQTSShellLifecycleFailureRemainsClosed; do
      printf '%s\n' "--- PASS: $name (0.00s)"
    done
  done
  printf '%s\n' 'ok  github.com/sumitake/portable-ghar/tests/chaos 0.001s'
  ;;
*)
  case "${1:-}" in
  tool | mod | vet)
    ;;
  test)
    for name in \
      TestBrokerDialerRevalidatesThenPermitsEveryLiteralAttempt \
      TestBrokerDialerLiteralSkipsResolverAndRequiresPermit \
      TestBrokerDialerPermitFailurePreventsKernelDial \
      TestDoHResolverUsesOnePermittedLockedPersistentConnection \
      TestPollPermitFailureAbortsBeforeAcquireAndLeavesServiceReady \
      TestServiceTransitionCancelsAndJoinsOldOperationBeforeOpen \
      TestServiceDisabledTransitionRequiresListenerQuiescence \
      TestServiceTransitionJoinTimeoutPersistsFatalBeforeTermination \
      TestReplayHostedExplicitRouteFailureIsDurableAndNeverAcknowledged \
      TestReplayHostedEmptyOwnershipProofIsDurableFailure \
      TestChaosSourceOptInBoundary; do
      printf '%s\n' "--- PASS: $name (0.00s)"
    done
    printf '%s\n' 'ok  github.com/sumitake/portable-ghar/fake 0.001s'
    ;;
  *) exit 96 ;;
  esac
  ;;
esac
EOF
  chmod +x "$FAKE_BIN/go"

  cat >"$FAKE_BIN/bats" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x "$FAKE_BIN/bats"

  cat >"$FAKE_BIN/uname" <<'EOF'
#!/bin/sh
printf '%s\n' Linux
EOF
  chmod +x "$FAKE_BIN/uname"
}

@test "release mode is accepted and remains fail closed when its unit gate fails" {
  make_failing_gofmt

  run env PATH="$FAKE_BIN:$PATH" bash "$SCRIPT" --release

  [ "$status" -eq 1 ]
  gate_output=$output
  summary=${lines[0]}
  run jq -e '
    .mode == "release" and
    .status == "fail" and
    .failed_stage == "gofmt"
  ' <<<"$summary"
  [ "$status" -eq 0 ]
  if [[ "$gate_output" != *"gofmt:command-failed"* ]] ||
    [[ "$gate_output" == *"FAKE_GOFMT_PRIVATE_OUTPUT"* ]]; then
    return 1
  fi
}

@test "the ambiguous full mode is rejected before any gate stage" {
  make_failing_gofmt

  run env PATH="$FAKE_BIN:$PATH" bash "$SCRIPT" --full

  [ "$status" -eq 2 ]
  [ "$output" = arguments ]
}

@test "release mode composes the unit and docker gates" {
  make_docker_gate_fakes

  run env \
    PATH="$FAKE_BIN:$PATH" \
    PGHAR_INTEGRATION_DOCKER=1 \
    PGHAR_CHAOS_DOCKER=1 \
    bash "$SCRIPT" --release

  [ "$status" -eq 0 ]
  summary=${lines[0]}
  run jq -e '
    .mode == "release" and
    .status == "pass" and
    .linux_docker == "ready" and
    ([.stages[].id] | index("gofmt")) <
      ([.stages[].id] | index("linux-docker-preflight")) and
    ([.stages[].id] | index("source-integrity-exit")) <
      ([.stages[].id] | index("linux-docker-preflight")) and
    any(.stages[];
      .id == "source-integrity-docker-exit" and .status == "pass")
  ' <<<"$summary"
  [ "$status" -eq 0 ]
  [ ! -s "$FAKE_DOCKER_STATE" ]
}

@test "docker mode is self contained and leaves target conformance operator gated" {
  make_docker_gate_fakes

  run env \
    PATH="$FAKE_BIN:$PATH" \
    PGHAR_INTEGRATION_DOCKER=1 \
    PGHAR_CHAOS_DOCKER=1 \
    bash "$SCRIPT" --docker

  [ "$status" -eq 0 ]
  summary=${lines[0]}
  run jq -e '
    .mode == "docker" and
    .status == "pass" and
    .failed_stage == null and
    .linux_docker == "ready" and
    [.stages[].id] == [
      "source-integrity-entry",
      "linux-docker-preflight",
      "image-reproducibility",
      "integration-authority",
      "chaos",
      "docker-state-exit",
      "source-integrity-docker-exit"
    ] and
    all(.stages[]; .status == "pass")
  ' <<<"$summary"
  [ "$status" -eq 0 ]
  [ ! -s "$FAKE_DOCKER_STATE" ]
}

@test "docker mode removes its temporary runner image when chaos fails" {
  make_docker_gate_fakes

  run env \
    PATH="$FAKE_BIN:$PATH" \
    PGHAR_INTEGRATION_DOCKER=1 \
    PGHAR_CHAOS_DOCKER=1 \
    FAKE_CHAOS_FAIL=1 \
    bash "$SCRIPT" --docker

  [ "$status" -eq 1 ]
  gate_output=$output
  summary=${lines[0]}
  run jq -e '
    .mode == "docker" and
    .status == "fail" and
    .failed_stage == "chaos" and
    any(.stages[]; .id == "docker-state-exit" and .status == "pass") and
    any(.stages[]; .id == "source-integrity-docker-exit" and .status == "pass")
  ' <<<"$summary"
  [ "$status" -eq 0 ]
  if [[ "$gate_output" != *"chaos:test-failed:TestFleetFenceRaceAndObserverRecovery"* ]] ||
    [[ "$gate_output" == *"FAKE_CHAOS_PRIVATE_OUTPUT"* ]]; then
    return 1
  fi
  [ ! -s "$FAKE_DOCKER_STATE" ]
}
