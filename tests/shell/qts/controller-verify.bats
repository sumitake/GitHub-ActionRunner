#!/usr/bin/env bats

load test_helper

setup() {
  setup_qts_fixture
}

@test "verify dispatch requires zero listeners" {
  run "$QTS_ROOT/verify-controller.sh" \
    --private /private/runtime.json \
    --manifest /release/manifest.json \
    --require-zero-listeners
  [ "$status" -eq 0 ]
  assert_fixed_dispatch \
    "host-runtime verify --private /private/runtime.json --manifest /release/manifest.json --require-zero-listeners"
}

@test "verify rejects reordered arguments" {
  run "$QTS_ROOT/verify-controller.sh" \
    --manifest /release/manifest.json \
    --private /private/runtime.json \
    --require-zero-listeners
  assert_generic_failure
  [ ! -e "$FAKE_LOG" ]
}
