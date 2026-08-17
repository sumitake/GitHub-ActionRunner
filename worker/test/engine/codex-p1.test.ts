import { expect, test } from "vitest";

import { handleHeartbeat } from "../../src/engine/heartbeat";
import { dispatchFleetRequest } from "../../src/gateway";
import {
  abortCanary,
  executeDueWork,
  persistCanary,
} from "../../src/github/outbox";
import {
  hexToBytes,
  MAC_HEADER,
  signCanonical,
  TIMESTAMP_HEADER,
} from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import { runCronTick } from "../../src/scheduler/cron";
import { MemoryFleetStore } from "../../src/state/memory";

const key = hexToBytes("0b".repeat(32));
const digest = "a".repeat(64);
const session = "c".repeat(64);

function secrets() {
  return {
    hmacKey: key,
    timestampWindowMs: 5_000,
    nonceTtlMs: 60_000,
    hostedTransitionSafetyMarginMs: 1_000,
    leaseDurationMs: 8_000,
    archiveEvidenceMaxAgeMs: 60_000,
    selectorEvidenceMaxAgeMs: 60_000,
  };
}

function portableStore(): MemoryFleetStore {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  store.fleet.inventoried = true;
  store.fleet.epoch = 1;
  store.fleet.sessionId = session;
  store.fleet.sequence = 0;
  store.fleet.leaseGeneration = 1;
  store.fleet.routingState = "PORTABLE";
  store.fleet.fenceGeneration = 1;
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
  return store;
}

async function heartbeat(
  store: MemoryFleetStore,
  timestamp: string,
  extra: Record<string, unknown> = {},
) {
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
    ...extra,
  });
  const mac = await signCanonical(
    key,
    "POST",
    "/v1/heartbeat",
    timestamp,
    body,
  );
  return handleHeartbeat(store, secrets(), {
    method: "POST",
    path: "/v1/heartbeat",
    timestamp,
    macHex: mac,
    body,
    inventoried: true,
  });
}

test("heartbeat outside the timestamp window is rejected", async () => {
  const store = portableStore();
  const result = await heartbeat(store, "2026-01-01T00:00:00.000Z");
  expect(result.status).toBe(401);
  expect(result.body).not.toContain("enabled");
});

test("unsigned controller policy cannot mint a lease", async () => {
  const store = portableStore();
  store.fleet.policyDigest = "f".repeat(64);
  const result = await heartbeat(store, "2026-01-01T00:00:10.000Z");
  expect(result.status).toBe(200);
  expect(result.body).toContain("policy-mismatch");
  expect(result.body).not.toContain('"mode":"enabled"');
});

test("matching Worker-owned policy can mint an enabled lease", async () => {
  const result = await heartbeat(portableStore(), "2026-01-01T00:00:10.000Z");
  expect(result.status).toBe(200);
  expect(result.body).toContain('"mode":"enabled"');
  expect(result.body).toContain('"maxCapacity":2');
});

test("stale selector evidence enqueues a named hosted route mutation", async () => {
  const store = portableStore();
  store.fleet.routingState = "PORTABLE";
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "self-hosted",
    confirmedRoute: "self-hosted",
    archiveLatched: false,
    archiveObservedAt: "2026-01-01T00:00:09.000Z",
    archived: false,
    selectorEvidenceAt: "2026-01-01T00:00:00.000Z",
    openQueueRisk: null,
  });
  store.now = () => "2026-01-01T00:01:10.000Z";
  const result = await heartbeat(store, "2026-01-01T00:01:10.000Z");
  expect(result.body).toContain("stale-selector-evidence");
  const row = store.dueWork.find((item) => item.kind === "github-mutate-route");
  expect(row?.payload).toEqual({
    name: "PORTABLE_GHAR_ROUTE",
    value: "hosted",
  });
});

test("due-work claims expire in the future and are not immediately reclaimed", () => {
  const store = portableStore();
  store.enqueue({
    id: "due-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:10.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {},
  });
  const first = store.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000);
  expect(first).toHaveLength(1);
  expect(first[0]?.claimExpiresAt).toBe("2026-01-01T00:00:15.000Z");
  const second = store.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000);
  expect(second).toHaveLength(0);
  expect(() => store.claimReady("2026-01-01T00:00:10.000Z", 8, 0)).toThrow();
});

test("cron abandons a hung fleet and still addresses later fleets", async () => {
  const hung = new MemoryFleetStore("hung-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  const healthy = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  const seen: string[] = [];
  const result = await runCronTick(
    { revision: "1", digest: "a", fleetIds: ["hung-fleet", "example-fleet"] },
    4,
    new Map([
      ["hung-fleet", hung],
      ["example-fleet", healthy],
    ]),
    20,
    5_000,
    () => "2026-01-01T00:00:00.000Z",
    async (store) => {
      seen.push(store.fleet.fleetId);
      if (store.fleet.fleetId === "hung-fleet") {
        await new Promise(() => undefined);
      }
    },
  );
  expect(seen).toContain("hung-fleet");
  expect(result.failed).toContain("hung-fleet");
  expect(result.addressed).toContain("example-fleet");
});

test("canary dispatch and self-hosted read-back enter PORTABLE", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  store.fleet.routingState = "HOSTED";
  persistCanary(store, "2026-01-01T00:00:10.000Z", "PORTABLE_CANARY");
  const client = {
    mutateVariable: async () => ({ status: 200 }),
    readVariable: async (_name: string, value?: string) => ({
      status: 200,
      body: value ?? "self-hosted",
    }),
    observeCanary: async () => ({
      status: 200,
      body: "pass",
    }),
  };
  await executeDueWork(
    store,
    client,
    store.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000),
  );
  expect(store.fleet.canaryPassed).toBe(true);
  expect(store.fleet.routingState).toBe("PORTABLE_CANARY");

  store.fleet.inventoried = true;
  store.fleet.epoch = 1;
  store.fleet.sessionId = session;
  store.fleet.sequence = 0;
  store.fleet.fenceGeneration = 1;
  store.fleet.policyDigest = digest;
  store.fleet.configRevision = 1;
  store.fleet.maxCapacity = 2;
  store.fleet.canaryScaleSet = "canary-set";
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "hosted",
    confirmedRoute: "hosted",
    archiveLatched: false,
    archiveObservedAt: "2026-01-01T00:00:09.000Z",
    archived: false,
    selectorEvidenceAt: "2026-01-01T00:00:09.000Z",
    openQueueRisk: null,
  });
  const ready = await heartbeat(store, "2026-01-01T00:00:10.000Z", {
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
      capacity: { configured: 2, effective: 2 },
    },
  });
  expect(ready.body).toContain('"mode":"canary-only"');
  expect(ready.body).not.toContain('"mode":"enabled"');
  const selfHosted = store.dueWork.find(
    (row) =>
      row.kind === "github-mutate-route" && row.payload.value === "self-hosted",
  );
  expect(selfHosted).toBeDefined();
  await executeDueWork(
    store,
    client,
    store.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000),
  );
  expect(store.fleet.routingState).toBe("PORTABLE");
});

test("worker fetch routes a signed heartbeat to the fleet store", async () => {
  const store = portableStore();
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
    key,
    "POST",
    "/v1/heartbeat",
    timestamp,
    body,
  );
  const response = await dispatchFleetRequest(
    new Request("https://worker.example/v1/heartbeat", {
      method: "POST",
      headers: {
        [TIMESTAMP_HEADER]: timestamp,
        [MAC_HEADER]: mac,
      },
      body,
    }),
    {
      inventoriedFleetIds: ["example-fleet"],
      secrets: secrets(),
      storeFor: () => store,
    },
  );
  expect(response.status).toBe(200);
  expect(await response.text()).toContain('"mode":"enabled"');
});

test("canary-only or zero-capacity heartbeats do not enqueue self-hosted", async () => {
  const store = portableStore();
  store.fleet.routingState = "PORTABLE_CANARY";
  store.fleet.canaryPassed = true;
  store.fleet.canaryScaleSet = "canary-set";
  const denied = await heartbeat(store, "2026-01-01T00:00:10.000Z", {
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "canary-only",
      unassignedReleasedListeners: 0,
      capacity: { configured: 2, effective: 0 },
    },
  });
  expect(denied.body).toContain('"mode":"canary-only"');
  expect(
    store.dueWork.some(
      (row) =>
        row.kind === "github-mutate-route" &&
        row.payload.value === "self-hosted",
    ),
  ).toBe(false);
});

test("signed lease keeps the accepted local policy epoch", async () => {
  const store = portableStore();
  store.fleet.configRevision = 1;
  const result = await heartbeat(store, "2026-01-01T00:00:10.000Z", {
    snapshot: {
      policyEpoch: 9,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
    },
  });
  expect(result.body).toContain('"localPolicyEpoch":9');
  expect(result.body).toContain('"repositoryPolicyRevision":1');
});

test("cron aborts timed-out work and pins unjoined claims", async () => {
  const hung = new MemoryFleetStore("hung-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  hung.enqueue({
    id: "due-hung",
    kind: "canary-dispatch",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {},
  });
  const healthy = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  let aborted = false;
  const result = await runCronTick(
    { revision: "1", digest: "a", fleetIds: ["hung-fleet", "example-fleet"] },
    4,
    new Map([
      ["hung-fleet", hung],
      ["example-fleet", healthy],
    ]),
    20,
    5_000,
    () => "2026-01-01T00:00:00.000Z",
    async (store, _batch, signal) => {
      if (store.fleet.fleetId !== "hung-fleet") {
        return;
      }
      if (signal === undefined) {
        await new Promise(() => undefined);
      }
      await new Promise<void>((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("aborted"));
        });
      });
    },
  );
  expect(aborted).toBe(true);
  expect(result.failed).toContain("hung-fleet");
  expect(result.addressed).toContain("example-fleet");
  expect(hung.dueWork[0]?.status).toBe("claimed");
  expect(hung.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000)).toHaveLength(0);
});

test("heartbeat fence and holder must match Worker-owned fleet state", async () => {
  const store = portableStore();
  store.fleet.fenceGeneration = 4;
  const staleFence = await heartbeat(store, "2026-01-01T00:00:10.000Z", {
    fenceGeneration: 1,
  });
  expect(staleFence.body).toContain("invalid-request");
  expect(staleFence.body).not.toContain('"mode":"enabled"');
  store.fleet.sequence = 0;
  const wrongHolder = await heartbeat(store, "2026-01-01T00:00:10.000Z", {
    fenceGeneration: 4,
    holder: "legacy",
  });
  expect(wrongHolder.body).toContain("invalid-request");
  expect(wrongHolder.body).not.toContain('"mode":"enabled"');
});

test("a new canary epoch clears prior canary success", () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "HOSTED";
  persistCanary(store, "2026-01-01T00:00:00.000Z", "PORTABLE_CANARY");
  store.fleet.canaryPassed = true;
  abortCanary(store);
  expect(store.fleet.canaryPassed).toBe(false);
  store.fleet.routingState = "HOSTED";
  store.fleet.canaryPassed = true;
  persistCanary(store, "2026-01-01T00:00:00.000Z", "PORTABLE_CANARY");
  expect(store.fleet.canaryPassed).toBe(false);
});

test("legacy canary readiness enqueues legacy and promotes after read-back", async () => {
  const store = portableStore();
  store.fleet.routingState = "HOSTED";
  persistCanary(store, "2026-01-01T00:00:10.000Z", "LEGACY_CANARY");
  store.fleet.canaryPassed = true;
  store.fleet.canaryScaleSet = "canary-set";
  store.fleet.sequence = 0;
  const ready = await heartbeat(store, "2026-01-01T00:00:10.000Z", {
    holder: "legacy",
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
      capacity: { configured: 2, effective: 2 },
    },
  });
  expect(ready.body).toContain('"mode":"canary-only"');
  const legacy = store.dueWork.find(
    (row) =>
      row.kind === "github-mutate-route" && row.payload.value === "legacy",
  );
  expect(legacy).toBeDefined();
  await executeDueWork(
    store,
    {
      mutateVariable: async () => ({ status: 200 }),
      readVariable: async () => ({ status: 200, body: "legacy" }),
      observeCanary: async () => ({ status: 200, body: "pass" }),
    },
    store.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000),
  );
  expect(store.fleet.routingState).toBe("LEGACY");
});

test("stale selector drains prior leases before hosted mutation is due", async () => {
  const store = portableStore();
  store.fleet.lastIssuedLeaseExpiryMax = "2026-01-01T00:02:00.000Z";
  store.fleet.routingState = "PORTABLE";
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "self-hosted",
    confirmedRoute: "self-hosted",
    archiveLatched: false,
    archiveObservedAt: "2026-01-01T00:00:09.000Z",
    archived: false,
    selectorEvidenceAt: "2026-01-01T00:00:00.000Z",
    openQueueRisk: null,
  });
  store.now = () => "2026-01-01T00:01:10.000Z";
  const result = await heartbeat(store, "2026-01-01T00:01:10.000Z");
  expect(result.body).toContain("stale-selector-evidence");
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  const hosted = store.dueWork.find(
    (row) => row.kind === "github-mutate-route",
  );
  expect(hosted?.payload).toEqual({
    name: "PORTABLE_GHAR_ROUTE",
    value: "hosted",
  });
  expect(hosted?.dueAt).toBe("2026-01-01T00:02:01.000Z");
  expect(store.claimReady("2026-01-01T00:01:10.000Z", 8, 5_000)).toHaveLength(
    0,
  );
});

test("unjoined cron timeout fails the claim so later work can be recovered", async () => {
  const hung = new MemoryFleetStore("hung-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  hung.enqueue({
    id: "due-hung",
    kind: "canary-dispatch",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {},
  });
  await runCronTick(
    { revision: "1", digest: "a", fleetIds: ["hung-fleet"] },
    4,
    new Map([["hung-fleet", hung]]),
    20,
    5_000,
    () => "2026-01-01T00:00:00.000Z",
    async () => {
      await new Promise(() => undefined);
    },
  );
  expect(hung.dueWork[0]?.status).toBe("failed");
  expect(hung.dueWork[0]?.claimExpiresAt).not.toBe("9999-12-31T23:59:59.000Z");
  hung.enqueue({
    id: "due-retry",
    kind: "canary-dispatch",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {},
  });
  expect(hung.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000)).toHaveLength(1);
});
