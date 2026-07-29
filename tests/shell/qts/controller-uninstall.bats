#!/usr/bin/env bats

load test_helper

setup() {
  setup_qts_fixture
}

@test "uninstall retains state" {
  run "$QTS_ROOT/uninstall-controller.sh" \
    --private /private/runtime.json \
    --retain-state
  [ "$status" -eq 0 ]
  assert_fixed_dispatch \
    "host-runtime uninstall --private /private/runtime.json --retain-state"
}

@test "uninstall refuses purge syntax" {
  run "$QTS_ROOT/uninstall-controller.sh" \
    --private /private/runtime.json \
    --purge-state-after-retention
  assert_generic_failure
  [ ! -e "$FAKE_LOG" ]
}
