import { expect, test } from "vitest";

import {
  enqueueArchiveObservation,
  executeDueWork,
  persistCanary,
  type GitHubClient,
} from "../../src/github/outbox";
import { canonicalize } from "../../src/protocol/canonical";
import type { ArchiveExpectation } from "../../src/routing/archive";
import { decodeCanaryExpectation } from "../../src/routing/canary";
import { MemoryFleetStore } from "../../src/state/memory";

const start = "2026-01-01T00:00:10.000Z";
const observeUntil = "2026-01-01T00:01:10.000Z";

function storeAt(now: () => string): MemoryFleetStore {
  const store = new MemoryFleetStore("example-fleet", { now });
  store.fleet.routingState = "HOSTED";
  store.fleet.configRevision = 7;
  store.fleet.leaseGeneration = 5;
  store.fleet.lastIssuedLeaseExpiryMax = "2026-01-01T00:00:20.000Z";
  store.transitions.push({ epoch: 3, from: "UNINITIALIZED", to: "HOSTED" });
  for (const alias of ["repo-a", "repo-b"]) {
    store.putRepository({
      alias,
      expectedRoute: "hosted",
      confirmedRoute: "hosted",
      archiveEligibility: "active",
      archivePolicyRevision: null,
      archiveObservedAt: start,
      archived: false,
      selectorEvidenceAt: start,
      openQueueRisk: null,
    });
  }
  return store;
}

function archiveBody(
  expectation: ArchiveExpectation,
  archived: boolean,
): string {
  if (expectation.kind !== "archive-sweep") {
    throw new Error("expected archive sweep");
  }
  return canonicalize({
    schemaVersion: 1,
    kind: expectation.kind,
    status: "observed",
    fleetId: expectation.fleetId,
    repositoryAlias: expectation.repositoryAlias,
    configurationRevision: expectation.configurationRevision,
    transitionEpoch: expectation.transitionEpoch,
    archived,
  });
}

function client(
  observeArchive: NonNullable<GitHubClient["observeArchive"]>,
): GitHubClient {
  return {
    mutateVariable: async () => ({ status: 500 }),
    readVariable: async () => ({ status: 500 }),
    observeCanary: async () => ({ status: 500 }),
    observeQueueRecovery: async () => ({ status: 500 }),
    observeArchive,
  };
}

test("archive true latches one alias and later false cannot reactivate it", async () => {
  let now = start;
  const store = storeAt(() => now);
  enqueueArchiveObservation(store, now, "repo-a", observeUntil);
  await executeDueWork(
    store,
    client(async (expectation) => ({
      status: 200,
      body: archiveBody(expectation, true),
    })),
    store.claimReady(now, 8, 5_000),
  );

  const repoA = store.repositories.get("repo-a")!;
  expect(repoA.archiveEligibility).toBe("archived-disabled");
  expect(repoA.archivePolicyRevision).toBe(7);
  expect(repoA.archived).toBe(true);
  expect(repoA.archiveObservedAt).toBe(start);
  expect(store.repositories.get("repo-b")?.archiveEligibility).toBe("active");
  expect(store.audit).toContain(
    "archive-disabled:repo-a:policy-7:drain-until-2026-01-01T00:00:20.000Z",
  );

  now = "2026-01-01T00:00:30.000Z";
  enqueueArchiveObservation(store, now, "repo-a", "2026-01-01T00:01:30.000Z");
  await executeDueWork(
    store,
    client(async (expectation) => ({
      status: 200,
      body: archiveBody(expectation, false),
    })),
    store.claimReady(now, 8, 5_000),
  );
  expect(repoA.archiveEligibility).toBe("archived-disabled");
  expect(repoA.archivePolicyRevision).toBe(7);
  expect(repoA.archived).toBe(false);
  expect(repoA.archiveObservedAt).toBe(now);
});

test("failed and exact-deadline archive reads never refresh evidence", async () => {
  let now = start;
  const store = storeAt(() => now);
  const original = store.repositories.get("repo-a")!.archiveObservedAt;
  enqueueArchiveObservation(store, now, "repo-a", observeUntil);
  await executeDueWork(
    store,
    client(async () => ({ status: 503 })),
    store.claimReady(now, 8, 5_000),
  );
  expect(store.repositories.get("repo-a")?.archiveObservedAt).toBe(original);

  now = observeUntil;
  await executeDueWork(
    store,
    client(async (expectation) => ({
      status: 200,
      body: archiveBody(expectation, false),
    })),
    store.claimReady(now, 8, 5_000),
  );
  expect(store.repositories.get("repo-a")?.archiveObservedAt).toBe(original);
  expect(store.dueWork[0]?.status).toBe("failed");
});

test("archive rate limits honor one bounded Retry-After", async () => {
  const now = start;
  const store = storeAt(() => now);
  enqueueArchiveObservation(store, now, "repo-a", observeUntil);

  await executeDueWork(
    store,
    client(async () => ({ status: 429, retryAfterMs: 5_000 })),
    store.claimReady(now, 8, 5_000),
  );

  expect(store.dueWork[0]).toEqual(
    expect.objectContaining({
      status: "ready",
      dueAt: "2026-01-01T00:00:15.000Z",
      attempts: 1,
    }),
  );
});

test("invalid or exact-deadline Retry-After is terminal", async () => {
  for (const retryAfterMs of [undefined, 0, 60_000, 60_001]) {
    const now = start;
    const store = storeAt(() => now);
    enqueueArchiveObservation(store, now, "repo-a", observeUntil);

    await executeDueWork(
      store,
      client(async () => ({ status: 429, retryAfterMs })),
      store.claimReady(now, 8, 5_000),
    );

    expect(store.dueWork[0]?.status, String(retryAfterMs)).toBe("failed");
  }
});

test("archive convergence makes the targeted canary result inert", async () => {
  const now = start;
  const store = storeAt(() => now);
  store.fleet.sessionId = "c".repeat(64);
  store.fleet.canaryScaleSet = "portable-canary";
  persistCanary(store, now, "PORTABLE_CANARY", {
    repositoryAlias: "repo-a",
    workflow: "recovery-canary.yml",
    revision: "0123456789abcdef0123456789abcdef01234567",
    observeUntil,
  });
  const canary = store.dueWork.find((row) => row.kind === "canary-observe")!;
  canary.status = "claimed";
  canary.claimId = "claim-canary";
  canary.claimExpiresAt = observeUntil;
  enqueueArchiveObservation(store, now, "repo-a", observeUntil);
  const archiveBatch = store
    .claimReady(now, 8, 5_000)
    .filter((row) => row.kind === "archive-observe");

  await executeDueWork(
    store,
    client(async (expectation) => ({
      status: 200,
      body: archiveBody(expectation, true),
    })),
    archiveBatch,
  );
  expect(canary.status).toBe("failed");
  expect(store.fleet.canaryEvidence).toBeNull();
  expect(store.repositories.get("repo-a")?.archiveEligibility).toBe(
    "archived-disabled",
  );
});

test("archive convergence preserves unrelated canary work and evidence", async () => {
  const now = start;
  const store = storeAt(() => now);
  store.fleet.sessionId = "c".repeat(64);
  store.fleet.canaryScaleSet = "portable-canary";
  persistCanary(store, now, "PORTABLE_CANARY", {
    repositoryAlias: "repo-b",
    workflow: "recovery-canary.yml",
    revision: "0123456789abcdef0123456789abcdef01234567",
    observeUntil,
  });
  const canary = store.dueWork.find((row) => row.kind === "canary-observe")!;
  canary.dueAt = observeUntil;
  const expectation = decodeCanaryExpectation(canary.payload);
  const evidence = {
    ...expectation,
    completedAt: "2026-01-01T00:00:11.000Z",
    observedAt: "2026-01-01T00:00:12.000Z",
    heartbeatSequence: 1,
  };
  store.fleet.canaryEvidence = evidence;
  enqueueArchiveObservation(store, now, "repo-a", observeUntil);
  const archiveBatch = store
    .claimReady(now, 8, 5_000)
    .filter((row) => row.kind === "archive-observe");

  await executeDueWork(
    store,
    client(async (archiveExpectation) => ({
      status: 200,
      body: archiveBody(archiveExpectation, true),
    })),
    archiveBatch,
  );

  expect(canary.status).toBe("ready");
  expect(store.fleet.canaryEvidence).toEqual(evidence);
  expect(store.repositories.get("repo-b")?.archiveEligibility).toBe("active");
});
