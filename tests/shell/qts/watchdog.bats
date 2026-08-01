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

@test "systemd watchdog reaps only its oneshot main process" {
  unit="${BATS_TEST_DIRNAME}/../../../deploy/systemd/portable-ghar-watchdog.service"

  run grep -c '^KillMode=process$' "$unit"
  [ "$status" -eq 0 ]
  [ "$output" -eq 1 ]

  run grep -c '^KillMode=' "$unit"
  [ "$status" -eq 0 ]
  [ "$output" -eq 1 ]

  run grep -E '^KillMode=(control-group|mixed|none)$' "$unit"
  [ "$status" -ne 0 ]
}

@test "systemd templates use supported path checks and unit start limits" {
  controller="${BATS_TEST_DIRNAME}/../../../deploy/systemd/portable-ghar-controller.service"
  watchdog="${BATS_TEST_DIRNAME}/../../../deploy/systemd/portable-ghar-watchdog.service"

  for unit in "$controller" "$watchdog"; do
    run grep -F "ConditionPathIsRegular=" "$unit"
    [ "$status" -ne 0 ]
    run grep -F "ConditionPathExists=/ABSOLUTE/PORTABLE_GHAR/PRIVATE/controller-runtime.json" "$unit"
    [ "$status" -eq 0 ]
    run grep -F "ConditionPathExists=/ABSOLUTE/PORTABLE_GHAR/RELEASE/runtime-manifest.json" "$unit"
    [ "$status" -eq 0 ]
  done

  run grep -F "ConditionFileIsExecutable=/ABSOLUTE/PORTABLE_GHAR/RELEASE/portable-ghar-controller" "$controller"
  [ "$status" -eq 0 ]
  run grep -F "ConditionFileIsExecutable=/ABSOLUTE/PORTABLE_GHAR/RELEASE/portable-ghar-watchdog" "$watchdog"
  [ "$status" -eq 0 ]

  run grep -Fx "TimeoutStartSec=2min" "$watchdog"
  [ "$status" -eq 0 ]
  run grep -Fx "TimeoutStartSec=30s" "$watchdog"
  [ "$status" -ne 0 ]

  unit_end="$(grep -n '^\[Service\]$' "$controller" | cut -d: -f1)"
  interval_line="$(grep -n '^StartLimitIntervalSec=' "$controller" | cut -d: -f1)"
  burst_line="$(grep -n '^StartLimitBurst=' "$controller" | cut -d: -f1)"
  [ "$interval_line" -lt "$unit_end" ]
  [ "$burst_line" -lt "$unit_end" ]
}
