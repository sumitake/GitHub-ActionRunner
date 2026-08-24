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
import type {
  CanaryEvidence,
  CanaryExpectation,
} from "../../src/routing/canary";
import { runCronTick } from "../../src/scheduler/cron";
import { MAX_DUE_WORK, MemoryFleetStore } from "../../src/state/memory";

const key = hexToBytes("0b".repeat(32));
const digest = "a".repeat(64);
const session = "c".repeat(64);
const canaryRevision = "0123456789abcdef0123456789abcdef01234567";

function canaryStart(observeUntil = "2026-01-01T00:05:00.000Z") {
  return {
    repositoryAlias: "repo-a",
    workflow: "recovery-canary.yml",
    revision: canaryRevision,
    observeUntil,
  } as const;
}

function beginCanary(
  store: MemoryFleetStore,
  now: string,
  next: "PORTABLE_CANARY" | "LEGACY_CANARY",
): CanaryExpectation {
  store.fleet.canaryScaleSet = "canary-set";
  persistCanary(store, now, next, canaryStart());
  const row = store.dueWork.find((work) => work.kind === "canary-observe");
  if (row === undefined) {
    throw new Error("canary observation is missing");
  }
  return JSON.parse(row.payload.expectation ?? "") as CanaryExpectation;
}

function canaryObservation(expectation: CanaryExpectation): string {
  return JSON.stringify({
    schemaVersion: 1,
    status: "success",
    repositoryAlias: expectation.repositoryAlias,
    workflow: expectation.workflow,
    revision: expectation.revision,
    scaleSet: expectation.scaleSet,
    environment: expectation.environment,
    completedAt: expectation.startedAt,
  });
}

function passedCanary(expectation: CanaryExpectation): CanaryEvidence {
  return {
    ...expectation,
    completedAt: expectation.startedAt,
    observedAt: expectation.startedAt,
    heartbeatSequence: 0,
  };
}

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
  store.fleet.canaryScaleSet = "canary-set";
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
  return store;
}

function heartbeatSnapshot(timestamp: string) {
  return {
    observedAt: timestamp,
    fleetAlias: "example-fleet",
    acquisitionMode: "enabled",
    policyEpoch: 1,
    policyDigest: digest,
    repositoryPolicyRevision: 1,
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

async function heartbeat(
  store: MemoryFleetStore,
  timestamp: string,
  extra: Record<string, unknown> = {},
) {
  const { snapshot: snapshotValue, ...requestExtra } = extra;
  const snapshotExtra = (snapshotValue ?? {}) as Record<string, unknown>;
  const capacityExtra = (snapshotExtra.capacity ?? {}) as Record<
    string,
    unknown
  >;
  const baseSnapshot = heartbeatSnapshot(timestamp);
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 1,
    sessionId: session,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp,
    ...requestExtra,
    snapshot: {
      ...baseSnapshot,
      ...snapshotExtra,
      capacity: {
        ...baseSnapshot.capacity,
        ...capacityExtra,
      },
    },
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

test("an open queue risk blocks local acquisition", async () => {
  const store = portableStore();
  store.repositories.get("repo-a")!.openQueueRisk = {
    transitionEpoch: 7,
    sourceHead: "unknown",
    evidenceDigest: digest,
    reason: "pre-transition-queue-may-remain",
  };

  const result = await heartbeat(store, "2026-01-01T00:00:10.000Z");

  expect(result.status).toBe(200);
  expect(result.body).toContain("queue-risk-open");
  expect(result.body).not.toContain('"mode":"enabled"');
});

test("PORTABLE and LEGACY reject non-enabled snapshots", async () => {
  const portable = await heartbeat(
    portableStore(),
    "2026-01-01T00:00:10.000Z",
    {
      snapshot: {
        policyEpoch: 1,
        policyDigest: digest,
        repositoryPolicyRevision: 1,
        acquisitionMode: "canary-only",
        unassignedReleasedListeners: 0,
      },
    },
  );
  expect(portable.status).toBe(200);
  expect(portable.body).toContain("lease-disabled");
  expect(portable.body).not.toContain('"mode":"enabled"');

  const unknown = portableStore();
  const unknownMode = await heartbeat(unknown, "2026-01-01T00:00:10.000Z", {
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "maybe",
      unassignedReleasedListeners: 0,
    },
  });
  expect(unknownMode.status).toBe(401);
  expect(unknown.fleet.sequence).toBe(0);
  expect(unknownMode.body).not.toContain('"mode":"enabled"');

  const legacyStore = portableStore();
  legacyStore.fleet.routingState = "LEGACY";
  const legacy = await heartbeat(legacyStore, "2026-01-01T00:00:10.000Z", {
    holder: "legacy",
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "canary-only",
      unassignedReleasedListeners: 0,
    },
  });
  expect(legacy.body).toContain("lease-disabled");
  expect(legacy.body).not.toContain('"mode":"enabled"');
});

test("stale selector evidence enqueues a named hosted route mutation", async () => {
  const store = portableStore();
  store.fleet.routingState = "PORTABLE";
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
    selectorEvidenceAt: "2026-01-01T00:00:00.000Z",
    openQueueRisk: null,
  });
  store.now = () => "2026-01-01T00:01:10.000Z";
  const result = await heartbeat(store, "2026-01-01T00:01:10.000Z");
  expect(result.body).toContain("stale-selector-evidence");
  expect(store.repositories.get("repo-a")?.openQueueRisk).toEqual({
    transitionEpoch: 1,
    sourceHead: "unknown",
    evidenceDigest: digest,
    reason: "pre-transition-queue-may-remain",
  });
  const row = store.dueWork.find((item) => item.kind === "github-mutate-route");
  expect(row?.payload).toEqual({
    effectKey: "route-2-repo-a",
    repositoryAlias: "repo-a",
    name: "PORTABLE_GHAR_ROUTE",
    configurationRevision: "1",
    transitionRevision: "2",
    value: "hosted",
  });
});

test("hosted readback creates no queue risk while unknown and legacy do", async () => {
  for (const [confirmedRoute, expectedRisk] of [
    ["hosted", false],
    ["legacy", true],
    [null, true],
  ] as const) {
    const store = portableStore();
    const repository = store.repositories.get("repo-a")!;
    repository.confirmedRoute = confirmedRoute;
    repository.selectorEvidenceAt = "2026-01-01T00:00:00.000Z";
    store.now = () => "2026-01-01T00:01:10.000Z";

    const result = await heartbeat(store, "2026-01-01T00:01:10.000Z");

    expect(result.body, String(confirmedRoute)).toContain(
      "stale-selector-evidence",
    );
    if (expectedRisk) {
      expect(repository.openQueueRisk, String(confirmedRoute)).toEqual({
        transitionEpoch: 1,
        sourceHead: "unknown",
        evidenceDigest: digest,
        reason: "pre-transition-queue-may-remain",
      });
    } else {
      expect(repository.openQueueRisk, String(confirmedRoute)).toBeNull();
    }
  }
});

test("hosted drain exchanges the canary boundary reserve for route readback", async () => {
  const store = portableStore();
  store.fleet.routingState = "PORTABLE_CANARY";
  store.repositories.get("repo-a")!.selectorEvidenceAt =
    "2026-01-01T00:00:00.000Z";
  for (let index = 0; index < MAX_DUE_WORK - 2; index += 1) {
    store.enqueue({
      id: `capacity-readback-${index}`,
      kind: "github-readback",
      dueAt: "2026-01-01T00:02:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: `capacity-mutation-${index}` },
    });
  }
  store.now = () => "2026-01-01T00:01:10.000Z";

  const result = await heartbeat(store, "2026-01-01T00:01:10.000Z");

  expect(result.body).toContain("stale-selector-evidence");
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(store.dueWork).toHaveLength(MAX_DUE_WORK - 1);
  expect(
    store.dueWork.find((row) => row.kind === "github-mutate-route"),
  ).toBeDefined();
});

test("hosted drain capacity failure returns no lease without partial mutation", async () => {
  const store = portableStore();
  store.repositories.get("repo-a")!.selectorEvidenceAt =
    "2026-01-01T00:00:00.000Z";
  for (let index = 0; index < MAX_DUE_WORK - 1; index += 1) {
    store.enqueue({
      id: `capacity-readback-${index}`,
      kind: "github-readback",
      dueAt: "2026-01-01T00:02:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: `capacity-mutation-${index}` },
    });
  }
  store.now = () => "2026-01-01T00:01:10.000Z";

  const result = await heartbeat(store, "2026-01-01T00:01:10.000Z");

  expect(result.body).toContain("stale-selector-evidence");
  expect(result.body).not.toContain('"mode":"enabled"');
  expect(store.fleet.routingState).toBe("PORTABLE");
  expect(store.fleet.leaseGeneration).toBe(1);
  expect(store.transitions).toHaveLength(0);
  expect(store.repositories.get("repo-a")?.openQueueRisk).toBeNull();
  expect(store.dueWork).toHaveLength(MAX_DUE_WORK - 1);
});

test("newer hosted drain supersedes an unstarted self-hosted route intent", async () => {
  const store = portableStore();
  store.fleet.routingState = "PORTABLE_CANARY";
  store.enqueue({
    id: "route-1",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {
      effectKey: "route-1",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "1",
      transitionRevision: "1",
      value: "self-hosted",
    },
  });
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
    selectorEvidenceAt: "2026-01-01T00:00:00.000Z",
    openQueueRisk: null,
  });
  store.now = () => "2026-01-01T00:01:10.000Z";

  const result = await heartbeat(store, "2026-01-01T00:01:10.000Z");
  const routeRows = store.dueWork.filter(
    (row) => row.kind === "github-mutate-route",
  );

  expect(result.body).toContain("stale-selector-evidence");
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(store.repositories.get("repo-a")?.openQueueRisk).toEqual({
    transitionEpoch: 1,
    sourceHead: "unknown",
    evidenceDigest: digest,
    reason: "pre-transition-queue-may-remain",
  });
  expect(routeRows).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ id: "route-1", status: "failed" }),
      expect.objectContaining({
        id: "route-2-repo-a",
        status: "ready",
        payload: expect.objectContaining({
          transitionRevision: "2",
          value: "hosted",
        }),
      }),
    ]),
  );

  const mutationValues: string[] = [];
  await executeDueWork(
    store,
    {
      mutateVariable: async (_alias, _name, value) => {
        mutationValues.push(value);
        return { status: 200 };
      },
      readVariable: async () => ({ status: 200, body: "hosted" }),
      observeCanary: async () => ({ status: 200, body: "pass" }),
    },
    store.claimReady("2026-01-01T00:01:10.000Z", 8, 5_000),
    undefined,
    {
      hostedTransitionSafetyMarginMs: 1_000,
      selectorEvidenceMaxAgeMs: 60_000,
    },
  );
  expect(mutationValues).toEqual(["hosted"]);
  expect(store.fleet.routingState).toBe("HOSTED");
});

test("newer hosted drain fences a claimed self-hosted route intent", async () => {
  const store = portableStore();
  store.fleet.routingState = "PORTABLE_CANARY";
  store.enqueue({
    id: "route-1",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: "claim-route-1",
    claimExpiresAt: "2026-01-01T00:02:00.000Z",
    attempts: 1,
    status: "claimed",
    payload: {
      effectKey: "route-1",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "1",
      transitionRevision: "1",
      value: "self-hosted",
    },
  });
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
    selectorEvidenceAt: "2026-01-01T00:00:00.000Z",
    openQueueRisk: null,
  });
  store.now = () => "2026-01-01T00:01:10.000Z";

  await heartbeat(store, "2026-01-01T00:01:10.000Z");

  expect(store.dueWork.find((row) => row.id === "route-1")).toEqual(
    expect.objectContaining({ status: "uncertain", claimId: null }),
  );
  expect(store.dueWork.find((row) => row.id === "route-2-repo-a")).toEqual(
    expect.objectContaining({
      status: "ready",
      payload: expect.objectContaining({
        transitionRevision: "2",
        value: "hosted",
      }),
    }),
  );
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
  store.fleet.inventoried = true;
  store.fleet.epoch = 1;
  store.fleet.sessionId = session;
  store.fleet.sequence = 0;
  store.fleet.leaseGeneration = 1;
  store.fleet.fenceGeneration = 1;
  store.fleet.policyDigest = digest;
  store.fleet.configRevision = 1;
  store.fleet.maxCapacity = 2;
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "hosted",
    confirmedRoute: "hosted",
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
  const expectation = beginCanary(
    store,
    "2026-01-01T00:00:10.000Z",
    "PORTABLE_CANARY",
  );
  const client = {
    mutateVariable: async () => ({ status: 200 }),
    readVariable: async () => ({
      status: 200,
      body: "self-hosted",
    }),
    observeCanary: async () => ({
      status: 200,
      body: canaryObservation(expectation),
    }),
  };
  await executeDueWork(
    store,
    client,
    store.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000),
    undefined,
    {
      hostedTransitionSafetyMarginMs: 1_000,
      selectorEvidenceMaxAgeMs: 60_000,
    },
  );
  expect(store.fleet.canaryEvidence).toEqual(passedCanary(expectation));
  expect(store.fleet.routingState).toBe("PORTABLE_CANARY");

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
    undefined,
    {
      hostedTransitionSafetyMarginMs: 1_000,
      selectorEvidenceMaxAgeMs: 60_000,
    },
  );
  expect(store.fleet.routingState).toBe("PORTABLE");
});

test("failed current route outcome requires resolution instead of automatic replay", async () => {
  const store = portableStore();
  store.fleet.routingState = "PORTABLE_CANARY";
  store.fleet.canaryScaleSet = "canary-set";
  store.enqueue({
    id: "route-1",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 3,
    status: "failed",
    payload: {
      effectKey: "route-1",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "1",
      transitionRevision: "1",
      value: "self-hosted",
    },
  });

  const result = await heartbeat(store, "2026-01-01T00:00:10.000Z", {
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
      capacity: { configured: 2, effective: 2 },
    },
  });

  expect(result.body).toContain('"mode":"canary-only"');
  expect(store.fleet.leaseGeneration).toBe(1);
  expect(store.dueWork).toHaveLength(1);
  expect(store.dueWork[0]?.status).toBe("failed");
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
    snapshot: heartbeatSnapshot(timestamp),
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
  store.fleet.canaryScaleSet = "canary-set";
  const denied = await heartbeat(store, "2026-01-01T00:00:10.000Z", {
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "canary-only",
      unassignedReleasedListeners: 0,
      capacity: { configured: 2, effective: 0, available: 0 },
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
  const store = portableStore();
  store.fleet.routingState = "HOSTED";
  const first = beginCanary(
    store,
    "2026-01-01T00:00:00.000Z",
    "PORTABLE_CANARY",
  );
  store.fleet.canaryEvidence = passedCanary(first);
  abortCanary(store, 1_000);
  expect(store.fleet.canaryEvidence).toBeNull();
  expect(store.repositories.get("repo-a")?.openQueueRisk).toBeNull();
  store.fleet.routingState = "HOSTED";
  store.fleet.canaryEvidence = {
    ...passedCanary(first),
    leaseGeneration: store.fleet.leaseGeneration,
  };
  beginCanary(store, "2026-01-01T00:00:00.000Z", "PORTABLE_CANARY");
  expect(store.fleet.canaryEvidence).toBeNull();
});

test("legacy canary readiness drains before route promotion and enabled authority", async () => {
  const store = portableStore();
  store.fleet.routingState = "HOSTED";
  const expectation = beginCanary(
    store,
    "2026-01-01T00:00:10.000Z",
    "LEGACY_CANARY",
  );
  await executeDueWork(
    store,
    {
      mutateVariable: async () => ({ status: 500 }),
      readVariable: async () => ({ status: 500 }),
      observeCanary: async () => ({
        status: 200,
        body: canaryObservation(expectation),
      }),
    },
    store.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000),
  );
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
  expect(ready.body).toContain("predecessor-lease-draining");
  expect(ready.body).not.toContain('"mode":"canary-only"');
  expect(ready.body).not.toContain('"mode":"enabled"');
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
      observeCanary: async () => ({
        status: 200,
        body: canaryObservation(expectation),
      }),
    },
    store.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000),
    undefined,
    {
      hostedTransitionSafetyMarginMs: 1_000,
      selectorEvidenceMaxAgeMs: 60_000,
    },
  );
  expect(store.fleet.routingState).toBe("LEGACY");
  const enabled = await heartbeat(store, "2026-01-01T00:00:10.000Z", {
    sequence: 2,
    holder: "legacy",
  });
  expect(enabled.body).toContain('"mode":"enabled"');
});

test("stale selector drains prior leases before hosted mutation is due", async () => {
  const store = portableStore();
  store.fleet.lastIssuedLeaseExpiryMax = "2026-01-01T00:02:00.000Z";
  store.fleet.routingState = "PORTABLE";
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
    effectKey: "route-2-repo-a",
    repositoryAlias: "repo-a",
    name: "PORTABLE_GHAR_ROUTE",
    configurationRevision: "1",
    transitionRevision: "2",
    value: "hosted",
  });
  expect(hosted?.dueAt).toBe("2026-01-01T00:02:01.000Z");
  expect(store.claimReady("2026-01-01T00:01:10.000Z", 8, 5_000)).toHaveLength(
    0,
  );
});

test("unjoined effect timeout becomes uncertain so later work can be recovered", async () => {
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
  expect(hung.dueWork[0]?.status).toBe("uncertain");
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
