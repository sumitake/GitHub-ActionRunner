#!/usr/bin/env node
// Strict overlay check without npm dependencies so the shell CI job can run it.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const overlayPath = process.argv[2];
if (!overlayPath) {
  process.stderr.write("arguments\n");
  process.exit(2);
}

const secretRef = /^[A-Za-z][A-Za-z0-9_.:/-]*$/;
const secretShaped =
  /^(ghp_|gho_|ghs_|ghr_|ghu_|github_pat_|sk-|sk_live_|sk_test_|AKIA|ASIA|xox[baprs]-|-----BEGIN)/;
const longB64 = /^[A-Za-z0-9+/=]{20,}$/;
const fleetId = /^[a-z][a-z0-9-]{0,63}$/;
const digest = /^[0-9a-f]{64}$/;

function isSecretReference(value) {
  return (
    typeof value === "string" &&
    value.length >= 3 &&
    value.length <= 128 &&
    secretRef.test(value) &&
    !longB64.test(value) &&
    !secretShaped.test(value)
  );
}

let document;
try {
  document = JSON.parse(readFileSync(resolve(overlayPath), "utf8"));
} catch {
  process.stderr.write("overlay-invalid\n");
  process.exit(1);
}

const keys = document && typeof document === "object" ? Object.keys(document).sort() : [];
const required = [
  "accountRef",
  "fleetIds",
  "fleetIdsDigest",
  "fleetIdsRevision",
  "hostRef",
  "schemaVersion",
  "targetId",
];
if (
  document === null ||
  typeof document !== "object" ||
  Array.isArray(document) ||
  keys.length !== required.length ||
  keys.some((key, index) => key !== required[index]) ||
  document.schemaVersion !== 1 ||
  typeof document.targetId !== "string" ||
  !fleetId.test(document.targetId) ||
  !isSecretReference(document.accountRef) ||
  !isSecretReference(document.hostRef) ||
  !Array.isArray(document.fleetIds) ||
  document.fleetIds.length < 1 ||
  new Set(document.fleetIds).size !== document.fleetIds.length ||
  document.fleetIds.some((id) => typeof id !== "string" || !fleetId.test(id)) ||
  typeof document.fleetIdsRevision !== "string" ||
  document.fleetIdsRevision.length < 1 ||
  document.fleetIdsRevision.length > 64 ||
  typeof document.fleetIdsDigest !== "string" ||
  !digest.test(document.fleetIdsDigest)
) {
  process.stderr.write("overlay-invalid\n");
  process.exit(1);
}
process.stdout.write("failover configuration: PASS\n");
