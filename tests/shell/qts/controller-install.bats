#!/usr/bin/env bats

load test_helper

setup() {
  setup_qts_fixture
}

@test "install dispatch is exact and acquisition remains disabled" {
  run "$QTS_ROOT/install-controller.sh" \
    --private /private/runtime.json \
    --manifest /release/manifest.json \
    --acquisition disabled
  [ "$status" -eq 0 ]
  assert_fixed_dispatch \
    "host-runtime install --private /private/runtime.json --manifest /release/manifest.json --acquisition disabled"
}

@test "install rejects enabled acquisition before invoking Go" {
  run "$QTS_ROOT/install-controller.sh" \
    --private /private/runtime.json \
    --manifest /release/manifest.json \
    --acquisition enabled
  assert_generic_failure
  [ ! -e "$FAKE_LOG" ]
}

@test "install hides Go failure details" {
  export FAKE_FAIL=1
  run "$QTS_ROOT/install-controller.sh" \
    --private /private/runtime.json \
    --manifest /release/manifest.json \
    --acquisition disabled
  assert_generic_failure
  [[ "$output" != *"/private/runtime.json"* ]]
}
