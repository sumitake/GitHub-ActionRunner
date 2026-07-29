setup_qts_fixture() {
  export QTS_ROOT="${BATS_TEST_TMPDIR}/qts"
  export FAKE_BIN="${BATS_TEST_TMPDIR}/fake-bin"
  export FAKE_LOG="${BATS_TEST_TMPDIR}/portable-ghar.args"
  mkdir -p "$QTS_ROOT" "$FAKE_BIN"
  cp -R "${BATS_TEST_DIRNAME}/../../../deploy/qts/." "$QTS_ROOT/"

  cat >"${FAKE_BIN}/id" <<'EOF'
#!/bin/sh
printf '%s\n' "${FAKE_EUID:-0}"
EOF
  cat >"${FAKE_BIN}/uname" <<'EOF'
#!/bin/sh
printf '%s\n' 'Linux'
EOF
  cat >"${QTS_ROOT}/portable-ghar" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >"$FAKE_LOG"
[ "${FAKE_FAIL:-0}" = "0" ] || exit 1
printf '%s\n' '{"schema_version":1,"status":"complete","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","journal_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","target_proof_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fence_generation":7,"active_fleet":"portable","error_class":""}'
EOF
  chmod 755 "${FAKE_BIN}/id" "${FAKE_BIN}/uname" \
    "${QTS_ROOT}/portable-ghar"

  local file
  for file in "$QTS_ROOT"/*.sh "$QTS_ROOT"/lib/*.sh; do
    sed \
      -e "s#/usr/bin/id#${FAKE_BIN}/id#g" \
      -e "s#/bin/uname#${FAKE_BIN}/uname#g" \
      "$file" >"${file}.fixture"
    mv "${file}.fixture" "$file"
    chmod 755 "$file"
  done
}

assert_fixed_dispatch() {
  local expected="$1"
  run cat "$FAKE_LOG"
  [ "$status" -eq 0 ]
  [ "$output" = "$expected" ]
}

assert_generic_failure() {
  [ "$status" -ne 0 ]
  [ "$output" = "portable-ghar-qts: action failed" ]
}
