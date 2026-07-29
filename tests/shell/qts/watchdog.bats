#!/usr/bin/env bats

load test_helper

setup() {
  setup_qts_fixture
}

@test "watchdog install and uninstall use only fixed target actions" {
  run "$QTS_ROOT/install-watchdog.sh" \
    --private /private/runtime.json \
    --manifest /release/manifest.json
  [ "$status" -eq 0 ]
  assert_fixed_dispatch \
    "host-runtime watchdog-install --private /private/runtime.json --manifest /release/manifest.json"

  run "$QTS_ROOT/uninstall-watchdog.sh" \
    --private /private/runtime.json
  [ "$status" -eq 0 ]
  assert_fixed_dispatch \
    "host-runtime watchdog-uninstall --private /private/runtime.json"
}

@test "watchdog cron source contains placeholders and no selected schedule" {
  run grep -F "<SCHEDULE>" "$QTS_ROOT/watchdog.cron.example"
  [ "$status" -eq 0 ]
  run grep -E '^[[:space:]]*([0-9*,-]+[[:space:]]+){5}' \
    "$QTS_ROOT/watchdog.cron.example"
  [ "$status" -ne 0 ]
}

@test "QTS wrappers reject non-root before invoking Go" {
  export FAKE_EUID=501
  run "$QTS_ROOT/install-watchdog.sh" \
    --private /private/runtime.json \
    --manifest /release/manifest.json
  assert_generic_failure
  [ ! -e "$FAKE_LOG" ]
}

@test "systemd watchdog template has no Docker or IP-network authority" {
  unit="${BATS_TEST_DIRNAME}/../../../deploy/systemd/portable-ghar-watchdog.service"
  run grep -F "IPAddressDeny=any" "$unit"
  [ "$status" -eq 0 ]
  run grep -F "RestrictAddressFamilies=AF_UNIX" "$unit"
  [ "$status" -eq 0 ]
  run grep -Ei 'docker|network-online|AF_INET' "$unit"
  [ "$status" -ne 0 ]
}
