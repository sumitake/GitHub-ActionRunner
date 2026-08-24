import { expect, test } from "vitest";

import {
  abortCanary,
  classifyGitHub,
  enqueueSelectorCompanionMutations,
  executeDueWork,
  persistCanary,
  persistHostedTransition,
} from "../../src/github/outbox";
import type { CanaryExpectation } from "../../src/routing/canary";
import { MAX_DUE_WORK, MemoryFleetStore } from "../../src/state/memory";

const canaryStart = {
  repositoryAlias: "repo-a",
  workflow: "recovery-canary.yml",
  revision: "0123456789abcdef0123456789abcdef01234567",
  observeUntil: "2026-01-01T00:05:00.000Z",
} as const;
const executionOptions = {
  hostedTransitionSafetyMarginMs: 1_000,
  selectorEvidenceMaxAgeMs: 60_000,
};

function prepareRepository(
  store: MemoryFleetStore,
  expectedRoute = "hosted",
): void {
  store.putRepository({
    alias: "repo-a",
    expectedRoute,
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

function prepareCanary(store: MemoryFleetStore): void {
  store.fleet.sessionId = "c".repeat(64);
  store.fleet.leaseGeneration = 1;
  store.fleet.canaryScaleSet = "portable-canary";
  prepareRepository(store);
}

function canaryObservation(
  expectation: CanaryExpectation,
  status: "pending" | "success" | "failure",
): string {
  return JSON.stringify({
    schemaVersion: 1,
    status,
    repositoryAlias: expectation.repositoryAlias,
    workflow: expectation.workflow,
    revision: expectation.revision,
    scaleSet: expectation.scaleSet,
    environment: expectation.environment,
    completedAt: status === "pending" ? null : "2026-01-01T00:00:00.000Z",
  });
}

function githubClient(body = "hosted") {
  return {
    mutateVariable: async () => ({ status: 200 }),
    readVariable: async () => ({ status: 200, body }),
    observeCanary: async (expectation: CanaryExpectation) => ({
      status: 200,
      body: canaryObservation(expectation, "success"),
    }),
  };
}

test("canary abort reuses draining-to-hosted and does not mutate GitHub", () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "HOSTED";
  prepareCanary(store);
  persistCanary(
    store,
    "2026-01-01T00:00:00.000Z",
    "PORTABLE_CANARY",
    canaryStart,
  );
  abortCanary(store, 1_000);
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(store.dueWork.some((row) => row.kind === "github-mutate-route")).toBe(
    false,
  );
});

test("GitHub classification and hosted read-back are required for success", async () => {
  expect(classifyGitHub({ status: 429 })).toBe("retry");
  expect(classifyGitHub({ status: 404 })).toBe("permanent");
  expect(classifyGitHub({ status: 0 })).toBe("ambiguous");
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  prepareRepository(store);
  persistHostedTransition(store, "2026-01-01T00:00:00.000Z");
  const batch = store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000);
  await executeDueWork(
    store,
    githubClient("hosted"),
    batch,
    undefined,
    executionOptions,
  );
  expect(store.fleet.routingState).toBe("HOSTED");
  expect(store.transitions).toEqual([
    { epoch: 1, from: "UNINITIALIZED", to: "HOSTED" },
  ]);
});

test("hosted read-back records the terminal drain transition", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "DRAINING_TO_HOSTED";
  store.fleet.leaseGeneration = 2;
  store.transitions.push({
    epoch: 1,
    from: "PORTABLE",
    to: "DRAINING_TO_HOSTED",
  });
  prepareRepository(store);
  store.enqueue({
    id: "route-2-repo-a",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {
      effectKey: "route-2-repo-a",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      transitionRevision: "2",
      value: "hosted",
    },
  });

  await executeDueWork(
    store,
    githubClient("hosted"),
    store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000),
    undefined,
    executionOptions,
  );

  expect(store.fleet.routingState).toBe("HOSTED");
  expect(store.transitions).toEqual([
    { epoch: 1, from: "PORTABLE", to: "DRAINING_TO_HOSTED" },
    { epoch: 2, from: "DRAINING_TO_HOSTED", to: "HOSTED" },
  ]);
});

test("hosted read-back does not duplicate a pre-recorded terminal transition", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "DRAINING_TO_HOSTED";
  store.fleet.leaseGeneration = 1;
  store.transitions.push({
    epoch: 1,
    from: "PORTABLE",
    to: "DRAINING_TO_HOSTED",
  });
  prepareRepository(store);
  persistHostedTransition(store, "2026-01-01T00:00:00.000Z");

  await executeDueWork(
    store,
    githubClient("hosted"),
    store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000),
    undefined,
    executionOptions,
  );

  expect(store.fleet.routingState).toBe("HOSTED");
  expect(store.transitions).toEqual([
    { epoch: 1, from: "PORTABLE", to: "DRAINING_TO_HOSTED" },
    { epoch: 2, from: "DRAINING_TO_HOSTED", to: "HOSTED" },
  ]);
});

test("unknown-effect mutation becomes uncertain and is never replayed", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  prepareRepository(store);
  persistHostedTransition(store, "2026-01-01T00:00:00.000Z");
  let mutationCalls = 0;
  const client = {
    mutateVariable: async () => {
      mutationCalls += 1;
      return { status: 0 };
    },
    readVariable: async () => ({ status: 503 }),
    observeCanary: async () => ({ status: 200, body: "pass" }),
  };

  await executeDueWork(
    store,
    client,
    store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000),
  );

  const mutation = store.dueWork.find(
    (row) => row.kind === "github-mutate-route",
  );
  expect(mutation?.status).toBe("uncertain");
  expect(
    store.dueWork.some(
      (row) =>
        row.kind === "github-readback" &&
        row.payload.mutationId === mutation?.id,
    ),
  ).toBe(true);

  await executeDueWork(
    store,
    client,
    store.claimReady("2026-01-01T01:00:00.000Z", 8, 5_000),
  );
  expect(mutationCalls).toBe(1);
  expect(mutation?.status).toBe("uncertain");
});

test("reusing an ambiguous mutation batch performs no second write", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  prepareRepository(store);
  persistHostedTransition(store, "2026-01-01T00:00:00.000Z");
  const batch = store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000);
  let mutationCalls = 0;
  const client = {
    mutateVariable: async () => {
      mutationCalls += 1;
      return { status: 0 };
    },
    readVariable: async () => ({ status: 503 }),
    observeCanary: async () => ({ status: 200, body: "pass" }),
  };

  await executeDueWork(store, client, batch);
  await executeDueWork(store, client, batch);

  expect(mutationCalls).toBe(1);
  expect(
    store.dueWork.find((row) => row.kind === "github-mutate-route")?.status,
  ).toBe("uncertain");
});

test("a stale claimed route cannot execute after the fleet intent advances", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "PORTABLE_CANARY";
  store.fleet.leaseGeneration = 1;
  prepareRepository(store, "self-hosted");
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
      configurationRevision: "0",
      transitionRevision: "1",
      value: "self-hosted",
    },
  });
  const staleBatch = store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000);
  store.fleet.routingState = "DRAINING_TO_HOSTED";
  store.fleet.leaseGeneration = 2;
  store.repositories.get("repo-a")!.expectedRoute = "hosted";
  store.enqueue({
    id: "route-2",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {
      effectKey: "route-2",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      transitionRevision: "2",
      value: "hosted",
    },
  });
  let mutationCalls = 0;

  await executeDueWork(
    store,
    {
      mutateVariable: async () => {
        mutationCalls += 1;
        return { status: 200 };
      },
      readVariable: async () => ({ status: 200, body: "self-hosted" }),
      observeCanary: async () => ({ status: 200, body: "pass" }),
    },
    staleBatch,
  );

  expect(mutationCalls).toBe(0);
  expect(store.dueWork.find((row) => row.id === "route-1")?.status).toBe(
    "failed",
  );
  expect(store.dueWork.find((row) => row.id === "route-2")?.status).toBe(
    "ready",
  );
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
});

test("stale route read-back cannot promote an obsolete local intent", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "DRAINING_TO_HOSTED";
  store.fleet.leaseGeneration = 2;
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
      value: "self-hosted",
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
      value: "self-hosted",
    },
  });

  await executeDueWork(
    store,
    githubClient("self-hosted"),
    store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000),
  );

  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(store.dueWork.find((row) => row.id === "route-1")?.status).toBe(
    "done",
  );
  expect(store.audit).toContain("github-mutation-readback-superseded:route-1");
});

test("exhausted unknown-effect read-back stays blocked for manual resolution", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:01:00.000Z",
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
    attempts: 4,
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

  await executeDueWork(
    store,
    githubClient("self-hosted"),
    store.claimReady("2026-01-01T00:01:00.000Z", 8, 5_000),
  );

  expect(store.dueWork.find((row) => row.id === "route-1")?.status).toBe(
    "uncertain",
  );
  expect(
    store.dueWork.find((row) => row.id === "readback-route-1")?.status,
  ).toBe("failed");
  expect(store.audit).toContain(
    "github-mutation-manual-resolution-required:route-1",
  );
  expect(
    store
      .claimReady("2026-01-01T01:00:00.000Z", 8, 5_000)
      .some((row) => row.kind === "github-mutate-route"),
  ).toBe(false);
});

test("expired uncertain mutation receives read-only reconciliation work", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  prepareRepository(store);
  store.enqueue({
    id: "route-1",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: "claim-route-1",
    claimExpiresAt: "2026-01-01T00:00:05.000Z",
    attempts: 1,
    status: "claimed",
    payload: {
      effectKey: "route-1",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      transitionRevision: "1",
      value: "hosted",
    },
  });
  expect(store.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000)).toHaveLength(
    0,
  );

  await executeDueWork(store, githubClient("self-hosted"), []);

  expect(store.dueWork[0]?.status).toBe("uncertain");
  expect(
    store.dueWork.some(
      (row) =>
        row.kind === "github-readback" && row.payload.mutationId === "route-1",
    ),
  ).toBe(true);
});

test("successful write with mismatched read-back becomes uncertain", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  prepareRepository(store);
  persistHostedTransition(store, "2026-01-01T00:00:00.000Z");

  await executeDueWork(
    store,
    {
      mutateVariable: async () => ({ status: 204 }),
      readVariable: async () => ({ status: 200, body: "self-hosted" }),
      observeCanary: async () => ({ status: 200, body: "pass" }),
    },
    store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000),
  );

  expect(
    store.dueWork.find((row) => row.kind === "github-mutate-route")?.status,
  ).toBe("uncertain");
  expect(store.fleet.routingState).not.toBe("HOSTED");
});

test("selector companion mutations call GitHub with exact repository identity and confirm independently", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  store.fleet.routingState = "HOSTED";
  store.fleet.configRevision = 4;
  store.fleet.leaseGeneration = 7;
  store.transitions.push({ epoch: 3, from: "UNINITIALIZED", to: "HOSTED" });
  for (const alias of ["repo-a", "repo-b"]) {
    const repository = {
      alias,
      expectedRoute: "hosted",
      confirmedRoute: "hosted",
      archiveEligibility: "active" as const,
      archivePolicyRevision: null,
      archiveObservedAt: store.now(),
      archived: false,
      selectorEvidenceAt: null,
      openQueueRisk: null,
    };
    Object.assign(repository, {
      expectedScaleSet: "portable-runners",
      confirmedScaleSet: null,
      expectedLegacyLabel: "legacy-runners",
      confirmedLegacyLabel: null,
    });
    store.putRepository(repository);
    for (const [kind, name, value] of [
      [
        "github-mutate-scale-set",
        "PORTABLE_GHAR_SCALE_SET",
        "portable-runners",
      ],
      [
        "github-mutate-legacy-label",
        "PORTABLE_GHAR_LEGACY_LABEL",
        "legacy-runners",
      ],
    ] as const) {
      store.enqueue({
        id: `${kind}-${alias}`,
        kind,
        dueAt: store.now(),
        claimId: null,
        claimExpiresAt: null,
        attempts: 0,
        status: "ready",
        payload: {
          effectKey: `${kind}-${alias}`,
          repositoryAlias: alias,
          name,
          value,
          configurationRevision: "4",
          transitionRevision: "3",
        },
      });
    }
  }
  const mutateCalls: unknown[][] = [];
  const readCalls: unknown[][] = [];
  await executeDueWork(
    store,
    {
      mutateVariable: async (...args: unknown[]) => {
        mutateCalls.push(args);
        return { status: 204 };
      },
      readVariable: async (...args: unknown[]) => {
        readCalls.push(args);
        return {
          status: 200,
          body:
            args[1] === "PORTABLE_GHAR_SCALE_SET"
              ? "portable-runners"
              : "legacy-runners",
        };
      },
      observeCanary: async () => ({ status: 500 }),
    },
    store.claimReady(store.now(), 8, 5_000),
  );

  expect(mutateCalls.map((args) => args.slice(0, 3))).toEqual([
    ["repo-a", "PORTABLE_GHAR_LEGACY_LABEL", "legacy-runners"],
    ["repo-b", "PORTABLE_GHAR_LEGACY_LABEL", "legacy-runners"],
    ["repo-a", "PORTABLE_GHAR_SCALE_SET", "portable-runners"],
    ["repo-b", "PORTABLE_GHAR_SCALE_SET", "portable-runners"],
  ]);
  expect(readCalls.map((args) => args.slice(0, 2))).toEqual([
    ["repo-a", "PORTABLE_GHAR_LEGACY_LABEL"],
    ["repo-b", "PORTABLE_GHAR_LEGACY_LABEL"],
    ["repo-a", "PORTABLE_GHAR_SCALE_SET"],
    ["repo-b", "PORTABLE_GHAR_SCALE_SET"],
  ]);
  expect(store.repositories.get("repo-a")).toEqual(
    expect.objectContaining({
      confirmedScaleSet: "portable-runners",
      confirmedLegacyLabel: "legacy-runners",
      selectorEvidenceAt: store.now(),
    }),
  );
  expect(store.repositories.get("repo-b")).toEqual(
    expect.objectContaining({
      confirmedScaleSet: "portable-runners",
      confirmedLegacyLabel: "legacy-runners",
      selectorEvidenceAt: store.now(),
    }),
  );
});

test("selector companion production is all-or-nothing and rejects missing expectations", () => {
  function prepared(fillerRows: number): MemoryFleetStore {
    const store = new MemoryFleetStore("example-fleet", {
      now: () => "2026-01-01T00:00:10.000Z",
    });
    store.fleet.routingState = "HOSTED";
    store.fleet.configRevision = 4;
    store.transitions.push({ epoch: 3, from: "UNINITIALIZED", to: "HOSTED" });
    for (const alias of ["repo-a", "repo-b"]) {
      store.putRepository({
        alias,
        expectedRoute: "hosted",
        confirmedRoute: "hosted",
        expectedScaleSet: "portable-runners",
        confirmedScaleSet: null,
        expectedLegacyLabel: "legacy-runners",
        confirmedLegacyLabel: null,
        archiveEligibility: "active",
        archivePolicyRevision: null,
        archiveObservedAt: store.now(),
        archived: false,
        selectorEvidenceAt: null,
        openQueueRisk: null,
      });
    }
    for (let index = 0; index < fillerRows; index += 1) {
      store.enqueue({
        id: `prior-readback-${index}`,
        kind: "github-readback",
        dueAt: store.now(),
        claimId: null,
        claimExpiresAt: null,
        attempts: 0,
        status: "ready",
        payload: { mutationId: `prior-mutation-${index}` },
      });
    }
    return store;
  }

  const exact = prepared(0);
  enqueueSelectorCompanionMutations(exact, exact.now());
  expect(
    exact.dueWork.map((row) => [
      row.kind,
      row.payload.repositoryAlias,
      row.payload.configurationRevision,
    ]),
  ).toEqual([
    ["github-mutate-scale-set", "repo-a", "4"],
    ["github-mutate-legacy-label", "repo-a", "4"],
    ["github-mutate-scale-set", "repo-b", "4"],
    ["github-mutate-legacy-label", "repo-b", "4"],
  ]);

  const missing = prepared(0);
  missing.repositories.get("repo-b")!.expectedLegacyLabel = null;
  expect(() =>
    enqueueSelectorCompanionMutations(missing, missing.now()),
  ).toThrow("selector companion expectation is unavailable");
  expect(missing.dueWork).toHaveLength(0);

  const saturated = prepared(MAX_DUE_WORK - 7);
  expect(() =>
    enqueueSelectorCompanionMutations(saturated, saturated.now()),
  ).toThrow("due-work readback reserve is exhausted");
  expect(saturated.dueWork).toHaveLength(MAX_DUE_WORK - 7);
});

test("every 422 mutation result performs exact same-alias read-back without replay", async () => {
  for (const [kind, name, value] of [
    ["github-mutate-route", "PORTABLE_GHAR_ROUTE", "legacy"],
    ["github-mutate-scale-set", "PORTABLE_GHAR_SCALE_SET", "portable-runners"],
    [
      "github-mutate-legacy-label",
      "PORTABLE_GHAR_LEGACY_LABEL",
      "legacy-runners",
    ],
  ] as const) {
    const store = new MemoryFleetStore("example-fleet", {
      now: () => "2026-01-01T00:00:10.000Z",
    });
    store.fleet.routingState =
      kind === "github-mutate-route" ? "LEGACY_CANARY" : "HOSTED";
    store.fleet.configRevision = 4;
    store.fleet.leaseGeneration = 7;
    store.fleet.sessionId = "c".repeat(64);
    store.transitions.push({ epoch: 3, from: "UNINITIALIZED", to: "HOSTED" });
    const repository = {
      alias: "repo-a",
      expectedRoute: kind === "github-mutate-route" ? "legacy" : "hosted",
      confirmedRoute: "hosted",
      archiveEligibility: "active" as const,
      archivePolicyRevision: null,
      archiveObservedAt: store.now(),
      archived: false,
      selectorEvidenceAt: store.now(),
      openQueueRisk: null,
    };
    Object.assign(repository, {
      expectedScaleSet: "portable-runners",
      confirmedScaleSet: "portable-runners",
      expectedLegacyLabel: "legacy-runners",
      confirmedLegacyLabel: "legacy-runners",
    });
    store.putRepository(repository);
    const evidence = {
      schemaVersion: 1 as const,
      repositoryAlias: "repo-a",
      workflow: "legacy-canary.yml",
      revision: "0123456789abcdef0123456789abcdef01234567",
      scaleSet: "legacy-runners",
      environment: "self-hosted" as const,
      startedAt: "2026-01-01T00:00:00.000Z",
      observeUntil: "2026-01-01T00:01:00.000Z",
      sessionId: "c".repeat(64),
      leaseGeneration: 7,
      completedAt: "2026-01-01T00:00:05.000Z",
      observedAt: "2026-01-01T00:00:06.000Z",
      heartbeatSequence: 1,
    };
    store.fleet.canaryEvidence = evidence;
    store.enqueue({
      id: `mutation-${kind}`,
      kind,
      dueAt: store.now(),
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: {
        effectKey: `mutation-${kind}`,
        repositoryAlias: "repo-a",
        name,
        value,
        configurationRevision: "4",
        transitionRevision: kind === "github-mutate-route" ? "7" : "3",
        ...(kind === "github-mutate-route"
          ? { canaryEvidence: JSON.stringify(evidence) }
          : {}),
      },
    });
    let writes = 0;
    const reads: unknown[][] = [];
    await executeDueWork(
      store,
      {
        mutateVariable: async () => {
          writes += 1;
          return { status: 422 };
        },
        readVariable: async (...args: unknown[]) => {
          reads.push(args);
          return { status: 200, body: value };
        },
        observeCanary: async () => ({ status: 500 }),
      },
      store.claimReady(store.now(), 8, 5_000),
    );
    await executeDueWork(store, githubClient(value), []);
    expect(writes, kind).toBe(1);
    expect(
      reads.map((args) => args.slice(0, 2)),
      kind,
    ).toEqual([["repo-a", name]]);
    expect(store.dueWork[0]?.status, kind).toBe("done");
  }
});

test("canary observe is pass, fail, or pending", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "HOSTED";
  prepareCanary(store);
  persistCanary(
    store,
    "2026-01-01T00:00:00.000Z",
    "PORTABLE_CANARY",
    canaryStart,
  );
  await executeDueWork(
    store,
    {
      ...githubClient(),
      observeCanary: async (expectation) => ({
        status: 200,
        body: canaryObservation(expectation, "pending"),
      }),
    },
    store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000),
  );
  expect(store.fleet.canaryEvidence).toBeNull();
  expect(store.fleet.routingState).toBe("PORTABLE_CANARY");
  await executeDueWork(
    store,
    githubClient(),
    store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000),
  );
  expect(store.fleet.canaryEvidence).not.toBeNull();

  const failed = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  failed.fleet.routingState = "HOSTED";
  prepareCanary(failed);
  persistCanary(
    failed,
    "2026-01-01T00:00:00.000Z",
    "PORTABLE_CANARY",
    canaryStart,
  );
  await executeDueWork(
    failed,
    {
      ...githubClient(),
      observeCanary: async (expectation) => ({
        status: 200,
        body: canaryObservation(expectation, "failure"),
      }),
    },
    failed.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000),
    undefined,
    { hostedTransitionSafetyMarginMs: 1_000 },
  );
  expect(failed.fleet.canaryEvidence).toBeNull();
  expect(failed.fleet.routingState).toBe("DRAINING_TO_HOSTED");
});
