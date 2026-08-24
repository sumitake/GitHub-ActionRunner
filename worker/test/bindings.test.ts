import { expect, test } from "vitest";

import { parseCronBindings, parseWorkerBindings } from "../src/bindings";
import { handleWorkerFetch } from "../src/runtime";
import {
  ADMIN_STATUS_PATH,
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

function validCronEnv(): Record<string, string> {
  return {
    ...validEnv(),
    CRON_HMAC_KEY: "0c".repeat(32),
    FLEET_IDS: "alpha,beta",
    MAX_FLEETS: "2",
    PER_FLEET_DEADLINE_MS: "20",
    CRON_BUDGET_OVERHEAD_MS: "10",
    CRON_TICK_BUDGET_MS: "50",
    FLEET_INVENTORY_REVISION: "1",
    FLEET_INVENTORY_DIGEST: "a".repeat(64),
  };
}

function heartbeatSnapshot(timestamp: string) {
  return {
    observedAt: timestamp,
    fleetAlias: "example-fleet",
    policyEpoch: 1,
    policyDigest: digest,
    repositoryPolicyRevision: 1,
    acquisitionMode: "enabled",
    capacity: {
      configured: 2,
      effective: 2,
      occupied: 0,
      available: 2,
      queued: 0,
    },
    assignedJobs: 0,
    runningJobs: 0,
    oldestLiveAssignmentAgeMs: 0,
    unassignedReleasedListeners: 0,
    lastTerminalAt: null,
    hostProfileId: "strict-linux-v1",
    degraded: false,
    buildId: digest,
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
    parseWorkerBindings({
      ...validEnv(),
      LEASE_DURATION_MS: "9223372036855",
    }),
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
  store.fleet.leaseGeneration = 1;
  store.fleet.fenceGeneration = 1;
  store.fleet.routingState = "PORTABLE";
  store.fleet.policyDigest = digest;
  store.fleet.configRevision = 1;
  store.fleet.maxCapacity = 2;
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "self-hosted",
    confirmedRoute: "self-hosted",
    expectedScaleSet: "portable-runners",
    confirmedScaleSet: "portable-runners",
    expectedLegacyLabel: "legacy-runners",
    confirmedLegacyLabel: "legacy-runners",
    archiveEligibility: "active",
    archivePolicyRevision: null,
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
    snapshot: heartbeatSnapshot(timestamp),
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

test("session and heartbeat routes reject unauthenticated query semantics", async () => {
  const timestamp = "2026-01-01T00:00:00.000Z";
  const body = canonicalize({
    buildId: digest,
    fleetId: "example-fleet",
    nonce: "d".repeat(64),
    protocolVersion: 1,
    timestamp,
  });
  const mac = await signCanonical(
    hexToBytes(keyHex),
    "POST",
    "/v1/session",
    timestamp,
    body,
  );
  for (const query of ["?ignored=1", "?"]) {
    const store = new MemoryFleetStore("example-fleet", {
      now: () => timestamp,
    });
    const response = await handleWorkerFetch(
      new Request(`https://worker.example/v1/session${query}`, {
        method: "POST",
        headers: { [TIMESTAMP_HEADER]: timestamp, [MAC_HEADER]: mac },
        body,
      }),
      validEnv(),
      () => store,
    );
    expect(response.status, query).toBe(401);
    expect(store.fleet.sessionId, query).toBeNull();
  }
});

test("gateway rejects a declared oversized body before authority mutation", async () => {
  const timestamp = "2026-01-01T00:00:00.000Z";
  const body = canonicalize({
    buildId: digest,
    fleetId: "example-fleet",
    nonce: "e".repeat(64),
    protocolVersion: 1,
    timestamp,
  });
  const mac = await signCanonical(
    hexToBytes(keyHex),
    "POST",
    "/v1/session",
    timestamp,
    body,
  );
  const store = new MemoryFleetStore("example-fleet", { now: () => timestamp });
  const response = await handleWorkerFetch(
    new Request("https://worker.example/v1/session", {
      method: "POST",
      headers: {
        "content-length": "65537",
        [TIMESTAMP_HEADER]: timestamp,
        [MAC_HEADER]: mac,
      },
      body,
    }),
    validEnv(),
    () => store,
  );
  expect(response.status).toBe(401);
  expect(store.fleet.sessionId).toBeNull();
});

test("gateway bounds an undeclared streamed body before protocol parsing", async () => {
  const timestamp = "2026-01-01T00:00:00.000Z";
  const store = new MemoryFleetStore("example-fleet", { now: () => timestamp });
  const request = new Request("https://worker.example/v1/session", {
    method: "POST",
    headers: {
      [TIMESTAMP_HEADER]: timestamp,
      [MAC_HEADER]: "0".repeat(64),
    },
    body: "x".repeat(65_537),
  });
  expect(request.headers.get("content-length")).toBeNull();
  const response = await handleWorkerFetch(request, validEnv(), () => store);
  expect(response.status).toBe(401);
  expect(store.fleet.sessionId).toBeNull();
});

test("outer runtime rejects admin status when address bindings are missing", async () => {
  const request = new Request(`https://worker.example${ADMIN_STATUS_PATH}`, {
    method: "POST",
    body: "{}",
  });
  let urlReads = 0;
  Object.defineProperty(request, "url", {
    configurable: true,
    get() {
      urlReads += 1;
      return `https://worker.example${ADMIN_STATUS_PATH}`;
    },
  });
  let storeLookups = 0;

  const response = await handleWorkerFetch(request, validEnv(), () => {
    storeLookups += 1;
    return undefined;
  });

  expect(response.status).toBe(401);
  expect(urlReads).toBe(1);
  expect(request.bodyUsed).toBe(false);
  expect(storeLookups).toBe(0);
});

test("production fetch stays fail-closed without a fleet Durable Object", async () => {
  const timestamp = new Date().toISOString().replace(/\.\d+Z$/, ".000Z");
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 1,
    sessionId: session,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp,
    snapshot: heartbeatSnapshot(timestamp),
  });
  const mac = await signCanonical(
    hexToBytes(keyHex),
    "POST",
    "/v1/heartbeat",
    timestamp,
    body,
  );
  const request = () =>
    new Request("https://worker.example/v1/heartbeat", {
      method: "POST",
      headers: { [TIMESTAMP_HEADER]: timestamp, [MAC_HEADER]: mac },
      body,
    });
  const isolated = await handleWorkerFetch(request(), validEnv());
  expect(isolated.status).toBe(401);
  expect(await isolated.text()).not.toContain("lease");

  let routed: string | undefined;
  const forwarded = await handleWorkerFetch(request(), {
    ...validEnv(),
    FLEET: {
      getByName(name: string) {
        routed = name;
        return {
          fetch: async () =>
            new Response("from-durable-object", { status: 200 }),
        };
      },
    },
  });
  expect(routed).toBeUndefined();
  expect(forwarded.status).toBe(401);
  expect(await forwarded.text()).not.toContain("from-durable-object");
});

test("Cron bindings enforce distinct keys, canonical inventory, and safe budget", () => {
  expect(parseCronBindings(validEnv())).toBeNull();
  const parsed = parseCronBindings(validCronEnv());
  expect(parsed).toMatchObject({
    inventoriedFleetIds: ["alpha", "beta"],
    inventoryRevision: "1",
    inventoryDigest: "a".repeat(64),
    maxFleets: 2,
    perFleetDeadlineMs: 20,
    cronBudgetOverheadMs: 10,
    cronTickBudgetMs: 50,
  });
  expect(
    parseCronBindings({
      ...validCronEnv(),
      LEASE_DURATION_MS: "invalid-for-external-authority-only",
      ARCHIVE_EVIDENCE_MAX_AGE_MS: "0",
      SELECTOR_EVIDENCE_MAX_AGE_MS: "unset",
      HOSTED_TRANSITION_SAFETY_MARGIN_MS: "-1",
    }),
  ).not.toBeNull();
  expect(
    parseCronBindings({
      ...validCronEnv(),
      CRON_HMAC_KEY: keyHex,
    }),
  ).toBeNull();
  expect(
    parseCronBindings({
      ...validCronEnv(),
      FLEET_IDS: "beta,alpha",
    }),
  ).toBeNull();
  expect(
    parseCronBindings({
      ...validCronEnv(),
      FLEET_INVENTORY_REVISION: "01",
    }),
  ).toBeNull();
  expect(
    parseCronBindings({
      ...validCronEnv(),
      FLEET_INVENTORY_REVISION: "18446744073709551616",
    }),
  ).toBeNull();
  expect(
    parseCronBindings({
      ...validCronEnv(),
      FLEET_INVENTORY_DIGEST: "A".repeat(64),
    }),
  ).toBeNull();
  expect(
    parseCronBindings({
      ...validCronEnv(),
      CRON_TICK_BUDGET_MS: "49",
    }),
  ).toBeNull();
  expect(
    parseCronBindings({
      ...validCronEnv(),
      CRON_TICK_BUDGET_MS: "900001",
    }),
  ).toBeNull();
  expect(
    parseCronBindings({
      ...validCronEnv(),
      MAX_FLEETS: "9007199254740992",
    }),
  ).toBeNull();
});
