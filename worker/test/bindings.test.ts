import { expect, test } from "vitest";

import { parseCronBindings, parseWorkerBindings } from "../src/bindings";
import { handleWorkerFetch, handleWorkerScheduled } from "../src/index";
import {
  hexToBytes,
  MAC_HEADER,
  signCanonical,
  TIMESTAMP_HEADER,
} from "../src/protocol/auth";
import { canonicalize } from "../src/protocol/canonical";
import { MemoryFleetStore } from "../src/state/memory";

const keyHex = "0b".repeat(32);
const digest = "a".repeat(64);
const session = "c".repeat(64);

function validEnv(): Record<string, string> {
  return {
    HMAC_KEY: keyHex,
    FLEET_IDS: "example-fleet",
    TIMESTAMP_WINDOW_MS: "5000",
    NONCE_TTL_MS: "60000",
    LEASE_DURATION_MS: "8000",
    ARCHIVE_EVIDENCE_MAX_AGE_MS: "60000",
    SELECTOR_EVIDENCE_MAX_AGE_MS: "60000",
    HOSTED_TRANSITION_SAFETY_MARGIN_MS: "1000",
  };
}

test("worker bindings fail closed when any required term is unset", () => {
  expect(parseWorkerBindings({})).toBeNull();
  expect(parseWorkerBindings({ ...validEnv(), HMAC_KEY: "zz" })).toBeNull();
  expect(parseWorkerBindings({ ...validEnv(), FLEET_IDS: "" })).toBeNull();
  expect(
    parseWorkerBindings({ ...validEnv(), LEASE_DURATION_MS: "0" }),
  ).toBeNull();
  expect(
    parseWorkerBindings({ ...validEnv(), FLEET_IDS: "Example" }),
  ).toBeNull();
});

test("worker fetch uses the gateway when bindings parse", async () => {
  const parsed = parseWorkerBindings(validEnv());
  expect(parsed).not.toBeNull();
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  store.fleet.inventoried = true;
  store.fleet.epoch = 1;
  store.fleet.sessionId = session;
  store.fleet.sequence = 0;
  store.fleet.fenceGeneration = 1;
  store.fleet.routingState = "PORTABLE";
  store.fleet.policyDigest = digest;
  store.fleet.configRevision = 1;
  store.fleet.maxCapacity = 2;
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "self-hosted",
    confirmedRoute: "self-hosted",
    archiveLatched: false,
    archiveObservedAt: "2026-01-01T00:00:09.000Z",
    archived: false,
    selectorEvidenceAt: "2026-01-01T00:00:09.000Z",
    openQueueRisk: null,
  });
  const timestamp = "2026-01-01T00:00:10.000Z";
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 1,
    sessionId: session,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp,
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
    },
  });
  const mac = await signCanonical(
    hexToBytes(keyHex),
    "POST",
    "/v1/heartbeat",
    timestamp,
    body,
  );
  const rejected = await handleWorkerFetch(
    new Request("https://worker.example/v1/heartbeat", {
      method: "POST",
      headers: { [TIMESTAMP_HEADER]: timestamp, [MAC_HEADER]: mac },
      body,
    }),
    {},
    () => store,
  );
  expect(rejected.status).toBe(401);
  const accepted = await handleWorkerFetch(
    new Request("https://worker.example/v1/heartbeat", {
      method: "POST",
      headers: { [TIMESTAMP_HEADER]: timestamp, [MAC_HEADER]: mac },
      body,
    }),
    validEnv(),
    () => store,
  );
  expect(accepted.status).toBe(200);
  expect(await accepted.text()).toContain('"mode":"enabled"');
});

test("cron bindings and scheduled tick stay fail-closed without a client", async () => {
  expect(parseCronBindings(validEnv())).toBeNull();
  const cronEnv = {
    ...validEnv(),
    MAX_FLEETS: "4",
    CLAIM_TTL_MS: "5000",
    PER_FLEET_DEADLINE_MS: "20",
    FLEET_INVENTORY_REVISION: "1",
    FLEET_INVENTORY_DIGEST: "a",
  };
  expect(parseCronBindings(cronEnv)?.maxFleets).toBe(4);
  expect(await handleWorkerScheduled(cronEnv)).toBeNull();
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.enqueue({
    id: "due-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {},
  });
  const result = await handleWorkerScheduled(
    cronEnv,
    async () => undefined,
    () => store,
    () => "2026-01-01T00:00:00.000Z",
  );
  expect(result?.addressed).toEqual(["example-fleet"]);
});
