import { expect, test } from "vitest";

import {
  assertNoDurableObjectAlarms,
  runCronTick,
  validateFleetInventory,
} from "../../src/scheduler/cron";
import {
  executeDueWork,
  persistHostedTransition,
} from "../../src/github/outbox";
import { MemoryFleetStore } from "../../src/state/memory";

function prepareRepository(store: MemoryFleetStore): void {
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
    archiveObservedAt: store.now(),
    archived: false,
    selectorEvidenceAt: store.now(),
    openQueueRisk: null,
  });
}

test("cron inventory rejects duplicates, empty, and oversized lists", () => {
  expect(() =>
    validateFleetInventory({ revision: "1", digest: "a", fleetIds: [] }, 2),
  ).toThrow();
  expect(() =>
    validateFleetInventory(
      {
        revision: "1",
        digest: "a",
        fleetIds: ["example-fleet", "example-fleet"],
      },
      2,
    ),
  ).toThrow();
  expect(() =>
    validateFleetInventory(
      { revision: "1", digest: "a", fleetIds: ["one", "two", "three"] },
      2,
    ),
  ).toThrow();
  expect(
    validateFleetInventory(
      { revision: "1", digest: "a", fleetIds: ["example-fleet"] },
      2,
    ),
  ).toEqual(["example-fleet"]);
});

test("cron addresses every configured fleet and does not use alarms", async () => {
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
  const result = await runCronTick(
    { revision: "1", digest: "a", fleetIds: ["example-fleet"] },
    4,
    new Map([["example-fleet", store]]),
    1_000,
    5_000,
    () => "2026-01-01T00:00:00.000Z",
    async (next, batch) => {
      expect(next.fleet.fleetId).toBe("example-fleet");
      expect(batch).toHaveLength(1);
    },
  );
  expect(result.addressed).toEqual(["example-fleet"]);
  expect(() => assertNoDurableObjectAlarms("const ok = true;")).not.toThrow();
  expect(() =>
    assertNoDurableObjectAlarms("await this.ctx.storage.setAlarm(1);"),
  ).toThrow();
});

test("unjoined GitHub mutation becomes uncertain with read-back work", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  prepareRepository(store);
  persistHostedTransition(store, "2026-01-01T00:00:00.000Z");

  await runCronTick(
    { revision: "1", digest: "a", fleetIds: ["example-fleet"] },
    1,
    new Map([["example-fleet", store]]),
    5,
    5_000,
    () => "2026-01-01T00:00:00.000Z",
    async () => new Promise(() => undefined),
  );

  expect(
    store.dueWork.find((row) => row.kind === "github-mutate-route")?.status,
  ).toBe("uncertain");
  expect(
    store.dueWork.some(
      (row) =>
        row.kind === "github-readback" &&
        row.payload.mutationId === "route-1-repo-a",
    ),
  ).toBe(true);
});

test("late GitHub mutation completion cannot overwrite timeout uncertainty", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  prepareRepository(store);
  persistHostedTransition(store, "2026-01-01T00:00:00.000Z");
  let releaseMutation: (() => void) | undefined;
  const mutationGate = new Promise<void>((resolve) => {
    releaseMutation = resolve;
  });

  await runCronTick(
    { revision: "1", digest: "a", fleetIds: ["example-fleet"] },
    1,
    new Map([["example-fleet", store]]),
    5,
    5_000,
    () => "2026-01-01T00:00:00.000Z",
    async (next, batch, signal) =>
      executeDueWork(
        next,
        {
          mutateVariable: async () => {
            await mutationGate;
            return { status: 200 };
          },
          readVariable: async () => ({ status: 200, body: "hosted" }),
          observeCanary: async () => ({ status: 200, body: "pass" }),
        },
        batch,
        signal,
        {
          hostedTransitionSafetyMarginMs: 1_000,
          selectorEvidenceMaxAgeMs: 60_000,
        },
      ),
  );
  releaseMutation?.();
  await mutationGate;
  await new Promise((resolve) => setTimeout(resolve, 0));

  expect(store.fleet.routingState).toBe("UNINITIALIZED");
  expect(
    store.dueWork.find((row) => row.kind === "github-mutate-route")?.status,
  ).toBe("uncertain");
});

test("late successful read-back cannot overwrite timeout uncertainty", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "DRAINING_TO_HOSTED";
  store.fleet.leaseGeneration = 1;
  prepareRepository(store);
  store.enqueue({
    id: "route-1",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 1,
    status: "uncertain",
    payload: {
      effectKey: "route-1",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      transitionRevision: "1",
      value: "hosted",
    },
  });
  store.enqueue({
    id: "readback-route-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {
      effectKey: "route-1",
      mutationId: "route-1",
      mutationKind: "github-mutate-route",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      observeUntil: "2026-01-01T00:01:00.000Z",
      transitionRevision: "1",
      value: "hosted",
    },
  });
  let releaseReadback: (() => void) | undefined;
  const readbackGate = new Promise<void>((resolve) => {
    releaseReadback = resolve;
  });

  await runCronTick(
    { revision: "1", digest: "a", fleetIds: ["example-fleet"] },
    1,
    new Map([["example-fleet", store]]),
    5,
    5_000,
    () => "2026-01-01T00:00:00.000Z",
    async (next, batch, signal) =>
      executeDueWork(
        next,
        {
          mutateVariable: async () => ({ status: 200 }),
          readVariable: async () => {
            await readbackGate;
            return { status: 200, body: "hosted" };
          },
          observeCanary: async () => ({ status: 200, body: "pass" }),
        },
        batch,
        signal,
        {
          hostedTransitionSafetyMarginMs: 1_000,
          selectorEvidenceMaxAgeMs: 60_000,
        },
      ),
  );
  releaseReadback?.();
  await readbackGate;
  await new Promise((resolve) => setTimeout(resolve, 0));

  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(store.dueWork.find((row) => row.id === "route-1")?.status).toBe(
    "uncertain",
  );
  expect(
    store.dueWork.find((row) => row.id === "readback-route-1")?.status,
  ).toBe("ready");

  const retry = await runCronTick(
    { revision: "1", digest: "a", fleetIds: ["example-fleet"] },
    1,
    new Map([["example-fleet", store]]),
    1_000,
    5_000,
    () => "2026-01-01T00:00:01.000Z",
    async (next, batch, signal) =>
      executeDueWork(
        next,
        {
          mutateVariable: async () => ({ status: 200 }),
          readVariable: async () => ({ status: 200, body: "hosted" }),
          observeCanary: async () => ({ status: 200, body: "pass" }),
        },
        batch,
        signal,
        {
          hostedTransitionSafetyMarginMs: 1_000,
          selectorEvidenceMaxAgeMs: 60_000,
        },
      ),
  );

  expect(retry.addressed).toEqual(["example-fleet"]);
  expect(store.fleet.routingState).toBe("HOSTED");
});
