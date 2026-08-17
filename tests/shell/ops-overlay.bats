#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  TMP_DIR="$(mktemp -d)"
  chmod 700 "$TMP_DIR"
}

teardown() {
  rm -rf "$TMP_DIR"
}

@test "assert-private-overlay accepts mode 700 and rejects missing paths" {
  run bash "$REPO_ROOT/scripts/ops/assert-private-overlay.sh" "$TMP_DIR"
  [ "$status" -eq 0 ]
  [[ "$output" == *"PASS"* ]]
  run bash "$REPO_ROOT/scripts/ops/assert-private-overlay.sh" "$TMP_DIR/missing"
  [ "$status" -ne 0 ]
}

@test "overlay validator rejects secret values and wrong targets" {
  cat >"$TMP_DIR/overlay.json" <<'JSON'
{
  "schemaVersion": 1,
  "targetId": "example-target",
  "accountRef": "ACCOUNT_REF",
  "hostRef": "HOST_REF",
  "fleetIds": ["example-fleet"],
  "fleetIdsRevision": "1",
  "fleetIdsDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
JSON
  run node "$REPO_ROOT/scripts/ops/validate-overlay.mjs" "$TMP_DIR/overlay.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"PASS"* ]]
  cat >"$TMP_DIR/bad.json" <<'JSON'
{
  "schemaVersion": 1,
  "targetId": "example-target",
  "accountRef": "1-not-a-secret-reference",
  "hostRef": "HOST_REF",
  "fleetIds": ["example-fleet"],
  "fleetIdsRevision": "1",
  "fleetIdsDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
JSON
  run node "$REPO_ROOT/scripts/ops/validate-overlay.mjs" "$TMP_DIR/bad.json"
  [ "$status" -ne 0 ]
}

@test "host journal is idempotent and rejects unknown phases" {
  journal="$TMP_DIR/journal"
  run bash "$REPO_ROOT/scripts/ops/journal-host-effect.sh" "$journal" op-1 applying
  [ "$status" -eq 0 ]
  run bash "$REPO_ROOT/scripts/ops/journal-host-effect.sh" "$journal" op-1 proven
  [ "$status" -eq 0 ]
  run bash "$REPO_ROOT/scripts/ops/journal-host-effect.sh" "$journal" op-1 proven
  [ "$status" -eq 0 ]
  run bash "$REPO_ROOT/scripts/ops/journal-host-effect.sh" "$journal" op-2 rm-rf
  [ "$status" -ne 0 ]
}

@test "cutover verifier requires authoritative receipts and rejects grafana authority" {
  cat >"$TMP_DIR/ok.json" <<'JSON'
{
  "githubRoute": "pass",
  "controllerAdapter": "pass",
  "signedHeartbeat": "pass",
  "scope": "pass",
  "configuration": "pass",
  "grafana": "projection"
}
JSON
  run node "$REPO_ROOT/scripts/ops/cutover-verify.mjs" "$TMP_DIR/ok.json"
  [ "$status" -eq 0 ]
  cat >"$TMP_DIR/bad.json" <<'JSON'
{
  "githubRoute": "pass",
  "controllerAdapter": "pass",
  "signedHeartbeat": "pass",
  "scope": "pass",
  "configuration": "pass",
  "grafana": "authority"
}
JSON
  run node "$REPO_ROOT/scripts/ops/cutover-verify.mjs" "$TMP_DIR/bad.json"
  [ "$status" -ne 0 ]
}
