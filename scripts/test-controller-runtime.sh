#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Non-mutating controller-runtime release gate. Subordinate output stays in a
# private temporary directory; callers receive only one closed JSON summary.
# Stage functions are invoked through the fixed identifier/function table.
# shellcheck disable=SC2329

set -euo pipefail
umask 077
# CI and agent invocations must never block on a terminal prompt.
exec </dev/null

if [ "$#" -ne 1 ]; then
  printf '%s\n' arguments >&2
  exit 2
fi

case "$1" in
--unit) mode=unit ;;
--full) mode=full ;;
*)
  printf '%s\n' arguments >&2
  exit 2
  ;;
esac

script_directory="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
repository_root="$(CDPATH='' cd -- "$script_directory/.." && pwd -P)"
cd "$repository_root"

export GOTOOLCHAIN=go1.26.6

log_directory="$(mktemp -d "${TMPDIR:-/tmp}/portable-ghar-runtime-gate.XXXXXX")"
stages_json=
gate_status=pass
failed_stage=
linux_docker=not_run
entry_tree_fingerprint=
entry_index_fingerprint=
entry_fingerprint_ready=0
docker_ready=0
docker_containers_fingerprint=
docker_networks_fingerprint=
docker_volumes_fingerprint=

private_mode() {
  local path=$1
  local value
  if value="$(stat -c '%a' "$path" 2>/dev/null)"; then
    printf '%s' "$value"
    return 0
  fi
  if value="$(stat -f '%Lp' "$path" 2>/dev/null)"; then
    printf '%s' "$value"
    return 0
  fi
  return 1
}

if [ "$(private_mode "$log_directory")" != 700 ]; then
  /bin/rm -rf "$log_directory" >/dev/null 2>&1 || true
  printf '%s\n' bootstrap >&2
  exit 1
fi

hash_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

append_stage() {
  local identifier=$1
  local stage_status=$2
  local record
  record="{\"id\":\"${identifier}\",\"status\":\"${stage_status}\"}"
  if [ -z "$stages_json" ]; then
    stages_json=$record
  else
    stages_json="${stages_json},${record}"
  fi
}

record_failure() {
  local identifier=$1
  gate_status=fail
  if [ -z "$failed_stage" ]; then
    failed_stage=$identifier
  fi
}

run_stage() {
  local identifier=$1
  shift
  local log_path="$log_directory/${identifier}.log"
  if "$@" >"$log_path" 2>&1; then
    append_stage "$identifier" pass
    return 0
  fi
  append_stage "$identifier" fail
  record_failure "$identifier"
  return 1
}

run_verified_go_test_stage() {
  local identifier=$1
  local expected_packages=$2
  local expected_passes=$3
  local pass_pattern=$4
  shift 4
  local log_path="$log_directory/${identifier}.log"
  local package_count
  local pass_count
  if ! "$@" >"$log_path" 2>&1; then
    append_stage "$identifier" fail
    record_failure "$identifier"
    return 1
  fi
  if [ ! -s "$log_path" ] ||
    grep -Eq -- '(^|[[:space:]])--- SKIP:|\[no tests to run\]|SKIP unsupported host profile' "$log_path"; then
    append_stage "$identifier" fail
    record_failure "$identifier"
    return 1
  fi
  package_count="$(
    awk '/^ok[[:space:]]/ { count++ } END { print count + 0 }' "$log_path"
  )" || {
    append_stage "$identifier" fail
    record_failure "$identifier"
    return 1
  }
  pass_count="$(
    awk -v pattern="$pass_pattern" \
      '$0 ~ pattern { count++ } END { print count + 0 }' "$log_path"
  )" || {
    append_stage "$identifier" fail
    record_failure "$identifier"
    return 1
  }
  if [ "$package_count" -ne "$expected_packages" ] ||
    [ "$pass_count" -ne "$expected_passes" ]; then
    append_stage "$identifier" fail
    record_failure "$identifier"
    return 1
  fi
  append_stage "$identifier" pass
}

tracked_tree_fingerprint() {
  git diff --no-ext-diff --binary HEAD -- | hash_stream
}

tracked_index_fingerprint() {
  git diff --cached --no-ext-diff --binary HEAD -- | hash_stream
}

stage_source_integrity_entry() {
  entry_tree_fingerprint="$(tracked_tree_fingerprint)" || return 1
  entry_index_fingerprint="$(tracked_index_fingerprint)" || return 1
  [ "${#entry_tree_fingerprint}" -eq 64 ] || return 1
  [ "${#entry_index_fingerprint}" -eq 64 ] || return 1
  entry_fingerprint_ready=1
}

stage_source_integrity_exit() {
  local tree_fingerprint
  local index_fingerprint
  [ "$entry_fingerprint_ready" -eq 1 ] || return 1
  tree_fingerprint="$(tracked_tree_fingerprint)" || return 1
  index_fingerprint="$(tracked_index_fingerprint)" || return 1
  [ "$tree_fingerprint" = "$entry_tree_fingerprint" ] || return 1
  [ "$index_fingerprint" = "$entry_index_fingerprint" ]
}

stage_gofmt() {
  local output="$log_directory/gofmt.list"
  if ! find cmd internal tests -type f -name '*.go' -print0 |
    xargs -0 gofmt -l >"$output"; then
    return 1
  fi
  [ ! -s "$output" ]
}

stage_vet() {
  go vet ./...
}

run_go_test() (
  # The gate itself stays private-by-default, but multiple integrity tests
  # deliberately create unsafe-mode fixtures and then prove they are rejected.
  # Normalize only the test subprocess umask so those fixtures are not silently
  # masked into safe objects by the gate's global umask.
  umask 022
  go test "$@"
)

stage_unit() {
  run_go_test ./... -count=1
}

stage_race() {
  run_go_test -race ./... -count=1
}

stage_network_authority() {
  run_go_test ./internal/networkjail \
    -run '^(TestBrokerDialerRevalidatesThenPermitsEveryLiteralAttempt|TestBrokerDialerLiteralSkipsResolverAndRequiresPermit|TestBrokerDialerPermitFailurePreventsKernelDial|TestDoHResolverUsesOnePermittedLockedPersistentConnection)$' \
    -v \
    -count=1
}

stage_acquisition_authority() {
  run_go_test ./internal/controller \
    -run '^(TestPollPermitFailureAbortsBeforeAcquireAndLeavesServiceReady|TestServiceTransitionCancelsAndJoinsOldOperationBeforeOpen|TestServiceDisabledTransitionRequiresListenerQuiescence|TestServiceTransitionJoinTimeoutPersistsFatalBeforeTermination)$' \
    -v \
    -count=1
}

stage_routing_authority() {
  run_go_test ./internal/controller \
    -run '^(TestReplayHostedExplicitRouteFailureIsDurableAndNeverAcknowledged|TestReplayHostedEmptyOwnershipProofIsDurableFailure)$' \
    -v \
    -count=1
}

stage_boundary() {
  run_go_test ./tests/boundaries -count=1
}

stage_staticcheck() {
  STATICCHECK_CACHE="$log_directory/staticcheck-cache" go tool staticcheck ./...
}

stage_module() {
  go mod verify
}

stage_runner_debian_snapshot() {
  python3 scripts/ci/check_runner_debian_snapshot.py
}

stage_shellcheck() {
  local inventory="$log_directory/shellcheck.files"
  local files=()
  local path
  git ls-files -z -- '*.sh' >"$inventory" || return 1
  while IFS= read -r -d '' path; do
    files[${#files[@]}]="$path"
  done <"$inventory"
  [ "${#files[@]}" -gt 0 ] || return 1
  shellcheck --severity=warning "${files[@]}"
}

stage_shfmt() {
  local output="$log_directory/shfmt.diff"
  if ! go tool shfmt -d scripts deploy >"$output"; then
    return 1
  fi
  [ ! -s "$output" ]
}

stage_bats() {
  local inventory="$log_directory/bats.files"
  local files=()
  local path
  git ls-files -z -- 'tests/shell/*.bats' 'tests/shell/**/*.bats' \
    >"$inventory" || return 1
  while IFS= read -r -d '' path; do
    files[${#files[@]}]="$path"
  done <"$inventory"
  [ "${#files[@]}" -gt 0 ] || return 1
  bats "${files[@]}"
}

stage_python_contract() {
  python3 -m unittest discover -s tests -p 'test_*.py'
}

stage_workflow_policy() {
  python3 scripts/check_workflow_policy.py .github/workflows
}

stage_repository_metadata() {
  python3 scripts/check_repository_metadata.py
}

stage_public_sanitizer() {
  python3 scripts/sanitize_public.py --tracked
}

stage_chaos_source() {
  run_go_test -tags=chaos ./tests/chaos \
    -run '^TestChaosSourceOptInBoundary$' \
    -v \
    -count=1
}

docker_fingerprint() {
  local kind=$1
  case "$kind" in
  containers)
    docker ps -a --no-trunc --format '{{.ID}}	{{.Names}}' |
      LC_ALL=C sort | hash_stream
    ;;
  networks)
    docker network ls --no-trunc --format '{{.ID}}	{{.Name}}' |
      LC_ALL=C sort | hash_stream
    ;;
  volumes)
    docker volume ls --format '{{.Driver}}	{{.Name}}' |
      LC_ALL=C sort | hash_stream
    ;;
  *)
    return 1
    ;;
  esac
}

fixed_check_image_tags() {
  docker image ls --format '{{.Repository}}:{{.Tag}}' |
    LC_ALL=C awk 'index($0, "portable-ghar-check-images:") == 1'
}

bounded_docker_info() {
  local docker_path
  docker_path="$(command -v docker)" || return 1
  python3 -c '
import subprocess
import sys

result = subprocess.run(
    [sys.argv[1], "info", "--format", "{{json .ServerVersion}}"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    timeout=15,
    check=False,
)
if result.returncode != 0 or not result.stdout.strip():
    raise SystemExit(1)
' "$docker_path"
}

prepared_image_contexts() {
  local image_rows
  command -v jq >/dev/null 2>&1 || return 1
  jq -e '
    .version == 1 and
    (.images | type == "array") and
    (.images | length > 0) and
    all(.images[];
      type == "object" and
      (.name | type == "string" and length > 0) and
      (.context | type == "string" and length > 0) and
      (.dockerfile | type == "string" and length > 0)
    )
  ' images/manifest.json >/dev/null || return 1
  image_rows="$(
    jq -r '.images[] | [.context, .dockerfile] | @tsv' images/manifest.json
  )" || return 1
  while IFS="$(printf '\t')" read -r context dockerfile; do
    [ -n "$context" ] || return 1
    [ -n "$dockerfile" ] || return 1
    [ -d "$context" ] || return 1
    [ -f "$dockerfile" ] || return 1
    case "$dockerfile" in
    "$context"/*) ;;
    *) return 1 ;;
    esac
  done <<EOF
$image_rows
EOF
}

stage_linux_docker_preflight() {
  local tags
  linux_docker=failed
  [ "$(uname -s)" = Linux ] || return 1
  [ "${PGHAR_INTEGRATION_DOCKER:-}" = 1 ] || return 1
  [ "${PGHAR_CHAOS_DOCKER:-}" = 1 ] || return 1
  command -v docker >/dev/null 2>&1 || return 1
  bounded_docker_info || return 1
  prepared_image_contexts || return 1
  tags="$(fixed_check_image_tags)" || return 1
  [ -z "$tags" ] || return 1
  docker_containers_fingerprint="$(docker_fingerprint containers)" || return 1
  docker_networks_fingerprint="$(docker_fingerprint networks)" || return 1
  docker_volumes_fingerprint="$(docker_fingerprint volumes)" || return 1
  [ "${#docker_containers_fingerprint}" -eq 64 ] || return 1
  [ "${#docker_networks_fingerprint}" -eq 64 ] || return 1
  [ "${#docker_volumes_fingerprint}" -eq 64 ] || return 1
  docker_ready=1
  linux_docker=ready
}

stage_image_reproducibility() {
  bash scripts/ci/check-images.sh
}

stage_integration_authority() {
  run_go_test -tags=integration ./internal/networkjail -v -count=1
}

stage_conformance() {
  run_go_test -tags=integration ./tests/integration ./tests/conformance -v -count=1
}

stage_chaos() {
  run_go_test -tags=chaos ./tests/chaos -v -count=10
}

stage_docker_state_exit() {
  local tags
  local containers
  local networks
  local volumes
  [ "$docker_ready" -eq 1 ] || return 1
  tags="$(fixed_check_image_tags)" || return 1
  [ -z "$tags" ] || return 1
  containers="$(docker_fingerprint containers)" || return 1
  networks="$(docker_fingerprint networks)" || return 1
  volumes="$(docker_fingerprint volumes)" || return 1
  [ "$containers" = "$docker_containers_fingerprint" ] || return 1
  [ "$networks" = "$docker_networks_fingerprint" ] || return 1
  [ "$volumes" = "$docker_volumes_fingerprint" ]
}

cleanup_fixed_images() {
  local tags
  tags="$(fixed_check_image_tags)" || return 1
  if [ -z "$tags" ]; then
    return 0
  fi
  while IFS= read -r tag; do
    [ -n "$tag" ] || continue
    docker image rm -f "$tag" >/dev/null 2>&1 || return 1
  done <<EOF
$tags
EOF
}

cleanup_private_state() {
  local cleanup_ok=1
  if [ "$docker_ready" -eq 1 ]; then
    cleanup_fixed_images || cleanup_ok=0
  fi
  if ! rm -rf "$log_directory" >/dev/null 2>&1; then
    cleanup_ok=0
  fi
  if [ "$cleanup_ok" -ne 1 ]; then
    append_stage cleanup fail
    record_failure cleanup
    return 1
  fi
  return 0
}

emit_summary() {
  local failed_json=null
  if [ -n "$failed_stage" ]; then
    failed_json="\"${failed_stage}\""
  fi
  printf '{"schema_version":1,"gate":"portable-ghar-controller-runtime","mode":"%s","status":"%s","failed_stage":%s,"linux_docker":"%s","stages":[%s]}\n' \
    "$mode" \
    "$gate_status" \
    "$failed_json" \
    "$linux_docker" \
    "$stages_json"
}

unit_failed=0
run_unit_stage() {
  if [ "$unit_failed" -ne 0 ]; then
    return 0
  fi
  if ! run_stage "$1" "$2"; then
    unit_failed=1
  fi
}

run_unit_verified_stage() {
  if [ "$unit_failed" -ne 0 ]; then
    return 0
  fi
  if ! run_verified_go_test_stage "$@"; then
    unit_failed=1
  fi
}

run_unit_stage source-integrity-entry stage_source_integrity_entry
run_unit_stage gofmt stage_gofmt
run_unit_stage vet stage_vet
run_unit_stage unit stage_unit
run_unit_stage race stage_race
run_unit_verified_stage \
  network-authority 1 4 \
  '^--- PASS: (TestBrokerDialerRevalidatesThenPermitsEveryLiteralAttempt|TestBrokerDialerLiteralSkipsResolverAndRequiresPermit|TestBrokerDialerPermitFailurePreventsKernelDial|TestDoHResolverUsesOnePermittedLockedPersistentConnection)([[:space:]]|$)' \
  stage_network_authority
run_unit_verified_stage \
  acquisition-authority 1 4 \
  '^--- PASS: (TestPollPermitFailureAbortsBeforeAcquireAndLeavesServiceReady|TestServiceTransitionCancelsAndJoinsOldOperationBeforeOpen|TestServiceDisabledTransitionRequiresListenerQuiescence|TestServiceTransitionJoinTimeoutPersistsFatalBeforeTermination)([[:space:]]|$)' \
  stage_acquisition_authority
run_unit_verified_stage \
  routing-authority 1 2 \
  '^--- PASS: (TestReplayHostedExplicitRouteFailureIsDurableAndNeverAcknowledged|TestReplayHostedEmptyOwnershipProofIsDurableFailure)([[:space:]]|$)' \
  stage_routing_authority
run_unit_stage boundary stage_boundary
run_unit_stage staticcheck stage_staticcheck
run_unit_stage module stage_module
run_unit_stage runner-debian-snapshot stage_runner_debian_snapshot
run_unit_stage shellcheck stage_shellcheck
run_unit_stage shfmt stage_shfmt
run_unit_stage bats stage_bats
run_unit_stage python-contract stage_python_contract
run_unit_stage workflow-policy stage_workflow_policy
run_unit_stage repository-metadata stage_repository_metadata
run_unit_stage public-sanitizer stage_public_sanitizer
run_unit_verified_stage \
  chaos-source \
  1 1 \
  '^--- PASS: TestChaosSourceOptInBoundary([[:space:]]|$)' \
  stage_chaos_source

if [ "$entry_fingerprint_ready" -eq 1 ]; then
  run_stage source-integrity-exit stage_source_integrity_exit || unit_failed=1
fi

full_failed=0
if [ "$unit_failed" -eq 0 ] && [ "$mode" = full ]; then
  if ! run_stage linux-docker-preflight stage_linux_docker_preflight; then
    full_failed=1
  else
    if ! run_stage image-reproducibility stage_image_reproducibility; then
      full_failed=1
    fi
    if [ "$full_failed" -eq 0 ] &&
      ! run_verified_go_test_stage \
        integration-authority 1 5 \
        '^--- PASS: (TestShutdownIntegrationAuthorityStopsOnlyExactTuple|TestShutdownIntegrationAuthorityAcceptsExactInactiveAbsence|TestProveIntegrationAuthorityAbsentIsReadOnly|TestShutdownIntegrationAuthorityRejectsPartialOrAmbiguousClaim|TestShutdownIntegrationAuthorityRejectsOpenInputs)([[:space:]]|$)' \
        stage_integration_authority; then
      full_failed=1
    fi
    if [ "$full_failed" -eq 0 ] &&
      ! run_verified_go_test_stage \
        conformance 2 2 \
        '^--- PASS: (TestPortableGHARConformance|TestPublicEvidenceTypesExposeNoCompositeAuthority)([[:space:]]|$)' \
        stage_conformance; then
      full_failed=1
    fi
    if [ "$full_failed" -eq 0 ] &&
      ! run_verified_go_test_stage \
        chaos 1 90 \
        '^--- PASS: (TestChaosSourceOptInBoundary|TestChaosOperationalGate|TestControllerStateRestartTable|TestDockerComponentFailureCleanup|TestFleetFenceRaceAndObserverRecovery|TestJailPermitFailuresNeverReachKernelDial|TestJailRaceNarrowingAndCancellationRemainClosed|TestQTSLifecycleEveryJournalEffectResumesAfterRestart|TestQTSShellLifecycleFailureRemainsClosed)([[:space:]]|$)' \
        stage_chaos; then
      full_failed=1
    fi
  fi

  if [ "$docker_ready" -eq 1 ]; then
    run_stage docker-state-exit stage_docker_state_exit || full_failed=1
  fi
  run_stage source-integrity-full-exit stage_source_integrity_exit || full_failed=1
fi

cleanup_private_state || true
emit_summary

if [ "$gate_status" = pass ]; then
  exit 0
fi
if [ -n "$failed_stage" ]; then
  printf '%s\n' "$failed_stage" >&2
fi
exit 1
