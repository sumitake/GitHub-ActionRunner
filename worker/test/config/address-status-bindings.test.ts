import { expect, test } from "vitest";

import { parseWorkerBindings } from "../../src/bindings";
import { parseAddressStatusBindings } from "../../src/config/address-status-bindings";

const ordinaryKeyHex = "0b".repeat(32);
const cronKeyHex = "0c".repeat(32);
const inventoryDigest = "a".repeat(64);

function validEnv(): Record<string, unknown> {
  return {
    FLEET_IDS: "alpha,beta",
    HMAC_KEY: ordinaryKeyHex,
    CRON_HMAC_KEY: cronKeyHex,
    TIMESTAMP_WINDOW_MS: "5000",
    NONCE_TTL_MS: "60000",
    FLEET_INVENTORY_REVISION: "1",
    FLEET_INVENTORY_DIGEST: inventoryDigest,
  };
}

test("address-status bindings expose only its minimal runtime inputs", () => {
  const parsed = parseAddressStatusBindings(validEnv());
  expect(parsed).toEqual({
    inventoriedFleetIds: ["alpha", "beta"],
    cronHmacKey: new Uint8Array(32).fill(0x0c),
    timestampWindowMs: 5_000,
    nonceTtlMs: 60_000,
    inventoryRevision: "1",
    inventoryDigest,
  });
  expect(parsed).not.toHaveProperty("hmacKey");
  expect(parsed).not.toHaveProperty("secrets");
  expect(parsed).not.toHaveProperty("leaseDurationMs");
});

test("lease, archive, selector, and safety-margin configuration is irrelevant", () => {
  const env = {
    ...validEnv(),
    LEASE_DURATION_MS: "invalid",
    ARCHIVE_EVIDENCE_MAX_AGE_MS: "0",
    SELECTOR_EVIDENCE_MAX_AGE_MS: "unset",
    HOSTED_TRANSITION_SAFETY_MARGIN_MS: "-1",
    UNKNOWN_EXTERNAL_AUTHORITY_TERM: { malformed: true },
  };
  expect(parseWorkerBindings(env)).toBeNull();
  expect(parseAddressStatusBindings(env)).not.toBeNull();

  const withoutExternalTerms = validEnv();
  expect(parseWorkerBindings(withoutExternalTerms)).toBeNull();
  expect(parseAddressStatusBindings(withoutExternalTerms)).not.toBeNull();
});

test("address-status bindings reject missing or malformed required inputs", () => {
  for (const name of [
    "FLEET_IDS",
    "HMAC_KEY",
    "CRON_HMAC_KEY",
    "TIMESTAMP_WINDOW_MS",
    "NONCE_TTL_MS",
    "FLEET_INVENTORY_REVISION",
    "FLEET_INVENTORY_DIGEST",
  ]) {
    const env = validEnv();
    delete env[name];
    expect(parseAddressStatusBindings(env), name).toBeNull();
  }

  const invalid: Array<[string, Record<string, unknown>]> = [
    ["empty fleet", { FLEET_IDS: "" }],
    ["invalid fleet", { FLEET_IDS: "Alpha" }],
    ["duplicate fleet", { FLEET_IDS: "alpha,alpha" }],
    ["unsorted fleet", { FLEET_IDS: "beta,alpha" }],
    ["empty ordinary key", { HMAC_KEY: "" }],
    ["short ordinary key", { HMAC_KEY: "0b".repeat(31) }],
    ["invalid ordinary key", { HMAC_KEY: "zz" }],
    ["short Cron key", { CRON_HMAC_KEY: "0c".repeat(31) }],
    ["invalid Cron key", { CRON_HMAC_KEY: "CC".repeat(32) }],
    ["equal keys", { CRON_HMAC_KEY: ordinaryKeyHex }],
    ["zero timestamp window", { TIMESTAMP_WINDOW_MS: "0" }],
    ["signed timestamp window", { TIMESTAMP_WINDOW_MS: "+1" }],
    ["unsafe timestamp window", { TIMESTAMP_WINDOW_MS: "9007199254740992" }],
    ["zero nonce ttl", { NONCE_TTL_MS: "0" }],
    ["fractional nonce ttl", { NONCE_TTL_MS: "1.5" }],
    ["zero revision", { FLEET_INVENTORY_REVISION: "0" }],
    ["padded revision", { FLEET_INVENTORY_REVISION: "01" }],
    ["overflow revision", { FLEET_INVENTORY_REVISION: "18446744073709551616" }],
    ["uppercase digest", { FLEET_INVENTORY_DIGEST: "A".repeat(64) }],
    ["short digest", { FLEET_INVENTORY_DIGEST: "a".repeat(63) }],
  ];
  for (const [name, override] of invalid) {
    expect(
      parseAddressStatusBindings({ ...validEnv(), ...override }),
      name,
    ).toBeNull();
  }
});

test("address-status parsing ignores unrelated Worker bindings", () => {
  const parsed = parseAddressStatusBindings({
    ...validEnv(),
    FLEET: { getByName: "provided by Cloudflare" },
    MAX_FLEETS: "not-needed-for-one-status-read",
    PER_FLEET_DEADLINE_MS: "not-needed-for-one-status-read",
    CRON_BUDGET_OVERHEAD_MS: "not-needed-for-one-status-read",
    CRON_TICK_BUDGET_MS: "not-needed-for-one-status-read",
  });
  expect(parsed?.inventoriedFleetIds).toEqual(["alpha", "beta"]);
});
