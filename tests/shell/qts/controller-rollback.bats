#!/usr/bin/env bats

load test_helper

setup() {
  setup_qts_fixture
}

@test "rollback forwards only canonical argv-file inputs" {
  run "$QTS_ROOT/rollback-controller.sh" \
    --private /private/runtime.json \
    --expected-generation 42 \
    --hosted-confirmation /private/hold.json \
    --legacy-command-file /private/legacy.json
  [ "$status" -eq 0 ]
  assert_fixed_dispatch \
    "host-runtime rollback --private /private/runtime.json --expected-generation 42 --hosted-confirmation /private/hold.json --legacy-command-file /private/legacy.json"
}

@test "rollback rejects noncanonical generation" {
  run "$QTS_ROOT/rollback-controller.sh" \
    --private /private/runtime.json \
    --expected-generation 042 \
    --hosted-confirmation /private/hold.json \
    --legacy-command-file /private/legacy.json
  assert_generic_failure
  [ ! -e "$FAKE_LOG" ]
}
