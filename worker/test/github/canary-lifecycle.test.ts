import { expect, test } from "vitest";

import { handleHeartbeat } from "../../src/engine/heartbeat";
import {
  abortCanary,
  executeDueWork,
  persistCanary,
  type GitHubClient,
} from "../../src/github/outbox";
import {
  decodeCanaryExpectation,
  type CanaryEvidence,
  type CanaryExpectation,
} from "../../src/routing/canary";
import { hexToBytes, signCanonical } from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import { MAX_DUE_WORK, MemoryFleetStore } from "../../src/state/memory";

const session = "1".repeat(64);
const revision = "0123456789abcdef0123456789abcdef01234567";
const marginMs = 1_000;
const digest = "a".repeat(64);
const hmacKey = hexToBytes("0b".repeat(32));

function makeStore(now: () => string): MemoryFleetStore {
  const store = new MemoryFleetStore("example-fleet", { now });
  store.fleet.routingState = "HOSTED";
  store.fleet.inventoried = true;
  store.fleet.epoch = 1;
  store.fleet.sessionId = session;
  store.fleet.leaseGeneration = 7;
  store.fleet.sequence = 4;
  store.fleet.canaryScaleSet = "portable-canary";
  store.fleet.fenceGeneration = 1;
  store.fleet.policyDigest = digest;
  store.fleet.configRevision = 1;
  store.fleet.maxCapacity = 2;
  store.fleet.lastIssuedLeaseExpiryMax = "2026-01-01T00:03:00.000Z";
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
    archiveObservedAt: "2026-01-01T00:01:00.000Z",
    archived: false,
    selectorEvidenceAt: "2026-01-01T00:01:00.000Z",
    openQueueRisk: null,
  });
  return store;
}

async function heartbeat(
  store: MemoryFleetStore,
  timestamp: string,
  sequence: number,
  capacity = { configured: 2, effective: 2 },
) {
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 1,
    sessionId: store.fleet.sessionId,
    sequence,
    holder: "portable",
    fenceGeneration: 1,
    timestamp,
    snapshot: {
      observedAt: timestamp,
      fleetAlias: "example-fleet",
      acquisitionMode: "enabled",
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      capacity: {
        ...capacity,
        occupied: 0,
        available: capacity.effective,
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
    },
  });
  return handleHeartbeat(
    store,
    {
      hmacKey,
      timestampWindowMs: 5_000,
      leaseDurationMs: 8_000,
      archiveEvidenceMaxAgeMs: 60_000,
      selectorEvidenceMaxAgeMs: 60_000,
      hostedTransitionSafetyMarginMs: marginMs,
    },
    {
      method: "POST",
      path: "/v1/heartbeat",
      timestamp,
      macHex: await signCanonical(
        hmacKey,
        "POST",
        "/v1/heartbeat",
        timestamp,
        body,
      ),
      body,
      inventoried: true,
    },
  );
}

function startCanary(store: MemoryFleetStore): CanaryExpectation {
  persistCanary(store, "2026-01-01T00:00:00.000Z", "PORTABLE_CANARY", {
    repositoryAlias: "repo-a",
    workflow: "recovery-canary.yml",
    revision,
    observeUntil: "2026-01-01T00:05:00.000Z",
  });
  const row = store.dueWork.find((work) => work.kind === "canary-observe");
  if (row === undefined) {
    throw new Error("canary observation work is missing");
  }
  return decodeCanaryExpectation(row.payload);
}

function observation(
  expectation: CanaryExpectation,
  status: "pending" | "success" | "failure" | "cancelled",
  overrides: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    schemaVersion: 1,
    status,
    repositoryAlias: expectation.repositoryAlias,
    workflow: expectation.workflow,
    revision: expectation.revision,
    scaleSet: expectation.scaleSet,
    environment: expectation.environment,
    completedAt: status === "pending" ? null : "2026-01-01T00:01:00.000Z",
    ...overrides,
  });
}

function client(observe: GitHubClient["observeCanary"]): GitHubClient {
  return {
    mutateVariable: async () => ({ status: 500 }),
    readVariable: async () => ({ status: 500 }),
    observeCanary: observe,
  };
}

test("canary observation receives the exact durable expectation", async () => {
  let current = "2026-01-01T00:01:01.000Z";
  const store = makeStore(() => current);
  const expected = startCanary(store);
  let observed: CanaryExpectation | undefined;

  await executeDueWork(
    store,
    client(async (value) => {
      observed = value;
      return { status: 200, body: observation(expected, "success") };
    }),
    store.claimReady(current, 8, 5_000),
    undefined,
    { hostedTransitionSafetyMarginMs: marginMs },
  );

  expect(observed).toEqual(expected);
  expect(store.fleet.canaryEvidence).toEqual({
    ...expected,
    completedAt: "2026-01-01T00:01:00.000Z",
    observedAt: current,
    heartbeatSequence: 4,
  });
  expect(store.fleet.routingState).toBe("PORTABLE_CANARY");
  current = "2026-01-01T00:02:00.000Z";
});

test("wrong and late canary observations fail closed into one boundary row", async () => {
  const cases: Array<[string, (expectation: CanaryExpectation) => string]> = [
    [
      "revision",
      (value) => observation(value, "success", { revision: "wrong" }),
    ],
    [
      "workflow",
      (value) => observation(value, "success", { workflow: "wrong.yml" }),
    ],
    [
      "scale set",
      (value) => observation(value, "success", { scaleSet: "wrong" }),
    ],
    [
      "environment",
      (value) => observation(value, "success", { environment: "hosted" }),
    ],
    [
      "late",
      (value) =>
        observation(value, "success", {
          completedAt: "2026-01-01T00:05:00.001Z",
        }),
    ],
    ["cancelled", (value) => observation(value, "cancelled")],
  ];

  for (const [name, body] of cases) {
    let current = "2026-01-01T00:01:01.000Z";
    const store = makeStore(() => current);
    const expected = startCanary(store);
    await executeDueWork(
      store,
      client(async () => ({ status: 200, body: body(expected) })),
      store.claimReady(current, 8, 5_000),
      undefined,
      { hostedTransitionSafetyMarginMs: marginMs },
    );

    expect(store.fleet.routingState, name).toBe("DRAINING_TO_HOSTED");
    expect(store.fleet.canaryEvidence, name).toBeNull();
    expect(
      store.dueWork.filter((row) => row.kind === "canary-boundary"),
      name,
    ).toEqual([
      expect.objectContaining({
        dueAt: "2026-01-01T00:03:01.000Z",
        status: "ready",
        payload: {
          transitionRevision: "8",
          from: "PORTABLE_CANARY",
        },
      }),
    ]);
    expect(
      store.dueWork.some((row) => row.kind === "github-mutate-route"),
      name,
    ).toBe(false);
    expect(store.repositories.get("repo-a")?.openQueueRisk, name).toBeNull();

    current = "2026-01-01T00:03:00.999Z";
    expect(store.claimReady(current, 8, 5_000)).toHaveLength(0);
    current = "2026-01-01T00:03:01.000Z";
    const boundary = store.claimReady(current, 8, 5_000);
    expect(boundary).toHaveLength(1);
    await executeDueWork(
      store,
      client(async () => ({ status: 500 })),
      boundary,
      undefined,
      { hostedTransitionSafetyMarginMs: marginMs },
    );
    expect(store.fleet.routingState, name).toBe("HOSTED");
    await executeDueWork(
      store,
      client(async () => ({ status: 500 })),
      boundary,
      undefined,
      { hostedTransitionSafetyMarginMs: marginMs },
    );
    expect(store.fleet.routingState, name).toBe("HOSTED");
  }
});

test("a clock regression after boundary claim releases it for exact-time completion", async () => {
  let current = "2026-01-01T00:01:01.000Z";
  const store = makeStore(() => current);
  startCanary(store);
  abortCanary(store, marginMs);
  current = "2026-01-01T00:03:01.000Z";
  const early = store.claimReady(current, 8, 5_000);
  expect(early).toHaveLength(1);
  current = "2026-01-01T00:03:00.999Z";
  await executeDueWork(
    store,
    client(async () => ({ status: 500 })),
    early,
  );
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(
    store.dueWork.find((row) => row.kind === "canary-boundary")?.status,
  ).toBe("ready");

  current = "2026-01-01T00:03:01.000Z";
  await executeDueWork(
    store,
    client(async () => ({ status: 500 })),
    store.claimReady(current, 8, 5_000),
  );
  expect(store.fleet.routingState).toBe("HOSTED");
});

test("late completion from a replaced session cannot install evidence", async () => {
  const current = "2026-01-01T00:01:01.000Z";
  const store = makeStore(() => current);
  const expected = startCanary(store);
  const stale = store.claimReady(current, 8, 5_000);
  store.fleet.sessionId = "2".repeat(64);
  store.fleet.leaseGeneration += 1;
  store.fleet.canaryEvidence = null;

  await executeDueWork(
    store,
    client(async () => ({
      status: 200,
      body: observation(expected, "success"),
    })),
    stale,
    undefined,
    { hostedTransitionSafetyMarginMs: marginMs },
  );

  expect(store.fleet.canaryEvidence).toBeNull();
  expect(store.fleet.leaseGeneration).toBe(8);
});

test("read-only canary outages retry only before the frozen observation deadline", async () => {
  const cases: Array<[string, GitHubClient["observeCanary"]]> = [
    [
      "throw",
      async () => {
        throw new Error("unavailable");
      },
    ],
    ["ambiguous", async () => ({ status: 500 })],
  ];

  for (const [name, observeCanary] of cases) {
    let current = "2026-01-01T00:04:59.999Z";
    const store = makeStore(() => current);
    startCanary(store);
    await executeDueWork(
      store,
      client(observeCanary),
      store.claimReady(current, 8, 5_000),
      undefined,
      { hostedTransitionSafetyMarginMs: marginMs },
    );
    expect(store.fleet.routingState, name).toBe("PORTABLE_CANARY");
    expect(
      store.dueWork.find((row) => row.kind === "canary-observe")?.status,
      name,
    ).toBe("ready");
    expect(
      store.dueWork.some((row) => row.kind === "canary-boundary"),
      name,
    ).toBe(false);

    current = "2026-01-01T00:05:00.000Z";
    await executeDueWork(
      store,
      client(observeCanary),
      store.claimReady(current, 8, 5_000),
      undefined,
      { hostedTransitionSafetyMarginMs: marginMs },
    );
    expect(store.fleet.routingState, name).toBe("DRAINING_TO_HOSTED");
    expect(
      store.dueWork.filter((row) => row.kind === "canary-boundary"),
      name,
    ).toHaveLength(1);
  }
});

test("route readiness is bound to evidence identity, a newer heartbeat, and exact capacity", async () => {
  let current = "2026-01-01T00:01:01.000Z";
  const store = makeStore(() => current);
  const expected = startCanary(store);
  await executeDueWork(
    store,
    client(async () => ({
      status: 200,
      body: observation(expected, "success"),
    })),
    store.claimReady(current, 8, 5_000),
    undefined,
    { hostedTransitionSafetyMarginMs: marginMs },
  );
  const evidence = store.fleet.canaryEvidence;
  if (evidence === null) {
    throw new Error("canary evidence is missing");
  }

  const mismatches: Array<[string, CanaryEvidence]> = [
    ["session", { ...evidence, sessionId: "2".repeat(64) }],
    ["generation", { ...evidence, leaseGeneration: 6 }],
    ["scale set", { ...evidence, scaleSet: "other-canary" }],
  ];
  for (const [name, mismatch] of mismatches) {
    store.fleet.canaryEvidence = mismatch;
    store.fleet.sequence = 4;
    await heartbeat(store, current, 5);
    expect(
      store.dueWork.some((row) => row.kind === "github-mutate-route"),
      name,
    ).toBe(false);
  }

  store.fleet.canaryEvidence = { ...evidence, heartbeatSequence: 5 };
  store.fleet.sequence = 4;
  await heartbeat(store, current, 5);
  expect(
    store.dueWork.some((row) => row.kind === "github-mutate-route"),
    "same sequence",
  ).toBe(false);

  store.fleet.canaryEvidence = evidence;
  store.fleet.sequence = 4;
  await heartbeat(store, current, 5, { configured: 1, effective: 2 });
  expect(
    store.dueWork.some((row) => row.kind === "github-mutate-route"),
    "configured capacity",
  ).toBe(false);
  store.fleet.sequence = 4;
  await heartbeat(store, current, 5, { configured: 2, effective: 1 });
  expect(
    store.dueWork.some((row) => row.kind === "github-mutate-route"),
    "effective capacity",
  ).toBe(false);

  store.fleet.sequence = 4;
  const ready = await heartbeat(store, current, 5);
  expect(ready.body).toContain('"mode":"canary-only"');
  expect(ready.body).not.toContain('"mode":"enabled"');
  const route = store.dueWork.find(
    (row) =>
      row.kind === "github-mutate-route" && row.payload.value === "self-hosted",
  );
  expect(route?.payload.canaryEvidence).toBe(JSON.stringify(evidence));

  let mutations = 0;
  await executeDueWork(
    store,
    {
      mutateVariable: async () => {
        mutations += 1;
        return { status: 200 };
      },
      readVariable: async () => ({ status: 200, body: "self-hosted" }),
      observeCanary: async () => ({ status: 500 }),
    },
    store.claimReady(current, 8, 5_000),
    undefined,
    {
      hostedTransitionSafetyMarginMs: marginMs,
      selectorEvidenceMaxAgeMs: 60_000,
    },
  );
  expect(mutations).toBe(1);
  expect(store.fleet.routingState).toBe("PORTABLE");
  expect(store.fleet.canaryEvidence).toBeNull();

  current = "2026-01-01T00:01:02.000Z";
  const enabled = await heartbeat(store, current, 6);
  expect(enabled.body).toContain('"mode":"enabled"');
});

test("cleared evidence makes an already-enqueued local route intent stale", async () => {
  const current = "2026-01-01T00:01:01.000Z";
  const store = makeStore(() => current);
  const expected = startCanary(store);
  await executeDueWork(
    store,
    client(async () => ({
      status: 200,
      body: observation(expected, "success"),
    })),
    store.claimReady(current, 8, 5_000),
    undefined,
    { hostedTransitionSafetyMarginMs: marginMs },
  );
  await heartbeat(store, current, 5);
  store.fleet.canaryEvidence = null;
  let mutations = 0;

  await executeDueWork(
    store,
    {
      mutateVariable: async () => {
        mutations += 1;
        return { status: 200 };
      },
      readVariable: async () => ({ status: 200, body: "self-hosted" }),
      observeCanary: async () => ({ status: 500 }),
    },
    store.claimReady(current, 8, 5_000),
  );

  expect(mutations).toBe(0);
  expect(store.fleet.routingState).toBe("PORTABLE_CANARY");
});

test("a passed canary reserves the hard-cap slot needed for a later abort boundary", async () => {
  const store = makeStore(() => "2026-01-01T00:01:01.000Z");
  const expected = startCanary(store);
  await executeDueWork(
    store,
    client(async () => ({
      status: 200,
      body: observation(expected, "success"),
    })),
    store.claimReady(store.now(), 8, 5_000),
    undefined,
    { hostedTransitionSafetyMarginMs: marginMs },
  );
  expect(store.fleet.canaryEvidence).not.toBeNull();
  for (let index = 0; index < MAX_DUE_WORK - 2; index += 1) {
    store.enqueue({
      id: `capacity-readback-${index}`,
      kind: "github-readback",
      dueAt: "2026-01-01T01:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: `capacity-mutation-${index}` },
    });
  }

  expect(store.dueWork).toHaveLength(MAX_DUE_WORK - 1);
  expect(() =>
    store.enqueue({
      id: "capacity-overflow",
      kind: "github-readback",
      dueAt: "2026-01-01T01:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: "capacity-overflow" },
    }),
  ).toThrow("canary boundary reserve is exhausted");

  abortCanary(store, marginMs);

  expect(store.dueWork).toHaveLength(MAX_DUE_WORK);
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(
    store.dueWork.filter((row) => row.kind === "canary-boundary"),
  ).toHaveLength(1);
});

test("failed canary setup and abort validation leave fleet authority unchanged", () => {
  const saturated = makeStore(() => "2026-01-01T00:01:01.000Z");
  saturated.fleet.routingState = "HOSTED";
  for (let index = 0; index < MAX_DUE_WORK - 1; index += 1) {
    saturated.enqueue({
      id: `saturated-readback-${index}`,
      kind: "github-readback",
      dueAt: "2026-01-01T01:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: `saturated-mutation-${index}` },
    });
  }
  const saturatedGeneration = saturated.fleet.leaseGeneration;
  expect(() => startCanary(saturated)).toThrow(
    "canary boundary reserve is exhausted",
  );
  expect(saturated.fleet.routingState).toBe("HOSTED");
  expect(saturated.fleet.leaseGeneration).toBe(saturatedGeneration);
  expect(saturated.transitions).toHaveLength(0);

  for (const generation of [
    Number.MAX_SAFE_INTEGER - 1,
    Number.MAX_SAFE_INTEGER,
  ]) {
    const overflow = makeStore(() => "2026-01-01T00:01:01.000Z");
    overflow.fleet.routingState = "HOSTED";
    overflow.fleet.leaseGeneration = generation;
    expect(() => startCanary(overflow)).toThrow(
      "canary lease generation has no abort headroom",
    );
    expect(overflow.fleet.routingState).toBe("HOSTED");
    expect(overflow.fleet.leaseGeneration).toBe(generation);
    expect(overflow.dueWork).toHaveLength(0);
    expect(overflow.transitions).toHaveLength(0);
  }

  const timestamp = makeStore(() => "2026-01-01T00:01:01.000Z");
  timestamp.fleet.lastIssuedLeaseExpiryMax = "9999-12-31T23:59:59.999Z";
  startCanary(timestamp);
  const timestampRows = timestamp.dueWork.length;
  expect(() => abortCanary(timestamp, marginMs)).toThrow(
    "due-work row is invalid",
  );
  expect(timestamp.fleet.routingState).toBe("PORTABLE_CANARY");
  expect(timestamp.fleet.leaseGeneration).toBe(7);
  expect(timestamp.dueWork).toHaveLength(timestampRows);
  expect(timestamp.transitions).toHaveLength(1);
});
