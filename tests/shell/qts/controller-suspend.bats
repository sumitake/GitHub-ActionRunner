#!/usr/bin/env bats

load test_helper

setup() {
  setup_qts_fixture
}

@test "suspend appends the fixed zero-listener proof requirement" {
  run "$QTS_ROOT/suspend-controller.sh" \
    --private /private/runtime.json \
    --drain-policy=wait \
    --hosted-confirmation /private/hold.json
  [ "$status" -eq 0 ]
  assert_fixed_dispatch \
    "host-runtime suspend --private /private/runtime.json --drain-policy=wait --hosted-confirmation /private/hold.json --require-zero-listeners"
}

@test "suspend rejects an unknown drain policy" {
  run "$QTS_ROOT/suspend-controller.sh" \
    --private /private/runtime.json \
    --drain-policy=kill \
    --hosted-confirmation /private/hold.json
  assert_generic_failure
  [ ! -e "$FAKE_LOG" ]
}
