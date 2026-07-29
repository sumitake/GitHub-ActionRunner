#!/usr/bin/env bats

load test_helper

setup() {
  setup_qts_fixture
}

@test "resume is fixed to disabled acquisition" {
  run "$QTS_ROOT/resume-controller.sh" \
    --private /private/runtime.json \
    --acquisition disabled
  [ "$status" -eq 0 ]
  assert_fixed_dispatch \
    "host-runtime resume --private /private/runtime.json --acquisition disabled"
}

@test "resume rejects omitted acquisition mode" {
  run "$QTS_ROOT/resume-controller.sh" \
    --private /private/runtime.json
  assert_generic_failure
  [ ! -e "$FAKE_LOG" ]
}
