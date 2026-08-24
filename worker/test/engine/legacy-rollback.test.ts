import { DatabaseSync } from "node:sqlite";
import { expect, test } from "vitest";

import {
  handleAdminCommand,
  type AdminCommandInput,
} from "../../src/engine/admin";
import { handleHeartbeat } from "../../src/engine/heartbeat";
import { executeDueWork, type GitHubClient } from "../../src/github/outbox";
import {
  ADMIN_COMMAND_PATH,
  hexToBytes,
  signCanonical,
} from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import type { CanaryExpectation } from "../../src/routing/canary";
import {
  MAX_NON_ROUTE_DUE_WORK,
  MemoryFleetStore,
} from "../../src/state/memory";
import {
  loadFleetStore,
  saveFleetStore,
  type FleetSql,
} from "../../src/state/persist";
import { FLEET_SCHEMA_SQL } from "../../src/state/schema";

const commandTime = "2026-01-01T00:00:10.000Z";
const observeUntil = "2026-01-01T00:01:10.000Z";
const revision = "0123456789abcdef0123456789abcdef01234567";
const session = "c".repeat(64);
const policyDigest = "a".repeat(64);
const hmacKey = hexToBytes("0b".repeat(32));

const adminSecrets = {
  hmacKey,
  timestampWindowMs: 5_000,
  nonceTtlMs: 60_000,
  archiveEvidenceMaxAgeMs: 60_000,
  selectorEvidenceMaxAgeMs: 60_000,
};

type LegacyRollbackCommand = {
  protocolVersion: 1;
  kind: "legacy-rollback";
  fleetId: string;
  timestamp: string;
  nonce: string;
  repositoryAlias: string;
  workflow: string;
  revision: string;
  legacyLabel: string;
  configurationRevision: number;
  transitionEpoch: number;
  leaseGeneration: number;
  fenceGeneration: number;
  observeUntil: string;
};

function command(
  overrides: Partial<LegacyRollbackCommand> = {},
): LegacyRollbackCommand {
  return {
    protocolVersion: 1,
    kind: "legacy-rollback",
    fleetId: "example-fleet",
    timestamp: commandTime,
    nonce: "9".repeat(64),
    repositoryAlias: "repo-a",
    workflow: "legacy-canary.yml",
    revision,
    legacyLabel: "legacy-runners",
    configurationRevision: 4,
    transitionEpoch: 3,
    leaseGeneration: 11,
    fenceGeneration: 5,
    observeUntil,
    ...overrides,
  };
}

async function inputFor(
  value: LegacyRollbackCommand,
): Promise<AdminCommandInput> {
  const body = canonicalize(value);
  return {
    method: "POST",
    path: ADMIN_COMMAND_PATH,
    timestamp: value.timestamp,
    macHex: await signCanonical(
      hmacKey,
      "POST",
      ADMIN_COMMAND_PATH,
      value.timestamp,
      body,
    ),
    body,
    inventoried: true,
  };
}

function addRepository(
  store: MemoryFleetStore,
  alias: string,
  overrides: Record<string, unknown> = {},
): void {
  const repository = {
    alias,
    expectedRoute: "hosted",
    confirmedRoute: "hosted",
    archiveEligibility: "active" as const,
    archivePolicyRevision: null,
    archiveObservedAt: "2026-01-01T00:00:09.000Z",
    archived: false,
    selectorEvidenceAt: "2026-01-01T00:00:09.000Z",
    openQueueRisk: null,
  };
  Object.assign(repository, {
    expectedScaleSet: "portable-runners",
    confirmedScaleSet: "portable-runners",
    expectedLegacyLabel: "legacy-runners",
    confirmedLegacyLabel: "legacy-runners",
    ...overrides,
  });
  store.putRepository(repository);
}

function makeStore(now: () => string = () => commandTime): MemoryFleetStore {
  const store = new MemoryFleetStore("example-fleet", { now });
  store.fleet.inventoried = true;
  store.fleet.epoch = 1;
  store.fleet.sessionId = session;
  store.fleet.sequence = 4;
  store.fleet.leaseGeneration = 11;
  store.fleet.lastIssuedLeaseExpiryMax = "2026-01-01T00:03:00.000Z";
  store.fleet.routingState = "HOSTED";
  store.fleet.fenceGeneration = 5;
  store.fleet.configRevision = 4;
  store.fleet.policyDigest = policyDigest;
  store.fleet.maxCapacity = 2;
  store.transitions.push({ epoch: 3, from: "UNINITIALIZED", to: "HOSTED" });
  addRepository(store, "repo-a");
  addRepository(store, "repo-b");
  return store;
}

function canaryObservation(
  expectation: CanaryExpectation,
  status: "success" | "failure" = "success",
): string {
  return JSON.stringify({
    schemaVersion: 1,
    status,
    repositoryAlias: expectation.repositoryAlias,
    workflow: expectation.workflow,
    revision: expectation.revision,
    scaleSet: expectation.scaleSet,
    environment: expectation.environment,
    completedAt: commandTime,
  });
}

function githubClient(
  observeCanary: GitHubClient["observeCanary"],
): GitHubClient {
  return {
    mutateVariable: async () => ({ status: 500 }),
    readVariable: async () => ({ status: 500 }),
    observeCanary,
    observeQueueRecovery: async () => ({ status: 500 }),
    observeArchive: async () => ({ status: 500 }),
  };
}

async function heartbeat(
  store: MemoryFleetStore,
  timestamp: string,
  sequence: number,
  overrides: Record<string, unknown> = {},
) {
  const snapshotOverrides = (overrides.snapshot ?? {}) as Record<
    string,
    unknown
  >;
  const capacityOverrides = (snapshotOverrides.capacity ?? {}) as Record<
    string,
    unknown
  >;
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 1,
    sessionId: session,
    sequence,
    holder: "legacy",
    fenceGeneration: 5,
    timestamp,
    ...overrides,
    snapshot: {
      observedAt: timestamp,
      fleetAlias: "example-fleet",
      acquisitionMode: "enabled",
      policyEpoch: 1,
      policyDigest,
      repositoryPolicyRevision: 4,
      capacity: {
        configured: 2,
        effective: 2,
        occupied: 0,
        available: 2,
        queued: 0,
        ...capacityOverrides,
      },
      assignedJobs: 0,
      runningJobs: 0,
      oldestLiveAssignmentAgeMs: 0,
      unassignedReleasedListeners: 0,
      lastTerminalAt: null,
      hostProfileId: "strict-linux-v1",
      degraded: false,
      buildId: policyDigest,
      ...snapshotOverrides,
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
      hostedTransitionSafetyMarginMs: 1_000,
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

async function admit(store: MemoryFleetStore): Promise<void> {
  const result = await handleAdminCommand(
    store,
    adminSecrets,
    await inputFor(command()),
  );
  expect(result.status).toBe(200);
  expect(result.body).toContain('"kind":"legacy-rollback"');
}

test("authenticated rollback admits atomically into exactly one legacy canary", async () => {
  const store = makeStore();
  await admit(store);

  expect(store.fleet.routingState).toBe("LEGACY_CANARY");
  expect(store.fleet.canaryScaleSet).toBe("legacy-runners");
  expect(store.nonces.has("9".repeat(64))).toBe(true);
  expect(store.dueWork).toEqual([
    expect.objectContaining({ kind: "canary-observe", status: "ready" }),
  ]);
  expect(store.transitions.at(-1)).toEqual({
    epoch: 4,
    from: "HOSTED",
    to: "LEGACY_CANARY",
  });
});

test("rollback admission gates and selector deadline equality reject with zero partial state", async () => {
  const cases: Array<
    [string, (store: MemoryFleetStore) => void, Partial<LegacyRollbackCommand>?]
  > = [
    ["wrong-state", (store) => (store.fleet.routingState = "PORTABLE")],
    ["hosted-hold", (store) => (store.fleet.hostedHold = true)],
    ["missing-session", (store) => (store.fleet.sessionId = null)],
    ["wrong-config", () => undefined, { configurationRevision: 5 }],
    ["wrong-epoch", () => undefined, { transitionEpoch: 2 }],
    ["wrong-generation", () => undefined, { leaseGeneration: 10 }],
    ["wrong-fence", () => undefined, { fenceGeneration: 4 }],
    ["zero-fence", (store) => (store.fleet.fenceGeneration = 0)],
    [
      "queue-risk",
      (store) => {
        store.repositories.get("repo-b")!.openQueueRisk = {
          transitionEpoch: 3,
          sourceHead: "unknown",
          evidenceDigest: "b".repeat(64),
          reason: "pre-transition-queue-may-remain",
        };
      },
    ],
    [
      "archive-restricted",
      (store) => {
        store.repositories.get("repo-b")!.archiveEligibility =
          "archived-disabled";
      },
    ],
    [
      "selector-mismatch",
      (store) => {
        Object.assign(store.repositories.get("repo-b")!, {
          confirmedLegacyLabel: "other-label",
        });
      },
    ],
    [
      "selector-future",
      (store) => {
        store.repositories.get("repo-b")!.selectorEvidenceAt =
          "2026-01-01T00:00:10.001Z";
      },
    ],
    [
      "selector-stale-at-equality",
      (store) => {
        store.repositories.get("repo-b")!.selectorEvidenceAt =
          "2025-12-31T23:59:10.000Z";
      },
    ],
    [
      "wrong-persisted-label",
      (store) => {
        Object.assign(store.repositories.get("repo-b")!, {
          expectedLegacyLabel: "other-label",
          confirmedLegacyLabel: "other-label",
        });
      },
    ],
    [
      "unresolved-github-work",
      (store) => {
        store.enqueue({
          id: "pending-selector",
          kind: "github-readback",
          dueAt: commandTime,
          claimId: null,
          claimExpiresAt: null,
          attempts: 0,
          status: "ready",
          payload: { mutationId: "pending-mutation" },
        });
      },
    ],
  ];

  for (const [name, mutate, overrides] of cases) {
    const store = makeStore();
    mutate(store);
    const beforeScaleSet = store.fleet.canaryScaleSet;
    const result = await handleAdminCommand(
      store,
      adminSecrets,
      await inputFor(command(overrides)),
    );
    expect(result.status, name).toBe(401);
    expect(store.fleet.routingState, name).toBe(
      name === "wrong-state" ? "PORTABLE" : "HOSTED",
    );
    expect(store.fleet.canaryScaleSet, name).toBe(beforeScaleSet);
    expect(store.nonces.size, name).toBe(0);
    expect(
      store.dueWork.filter((row) => row.kind === "canary-observe"),
      name,
    ).toHaveLength(0);
    expect(store.transitions, name).toHaveLength(1);
  }
});

test("nonce and due-work capacity failures restore nonce, label, state, and transition", async () => {
  const nonceFailure = makeStore();
  nonceFailure.fleet.canaryScaleSet = "prior-canary";
  nonceFailure.rememberNonce = () => false;
  expect(
    (
      await handleAdminCommand(
        nonceFailure,
        adminSecrets,
        await inputFor(command()),
      )
    ).status,
  ).toBe(401);
  expect(nonceFailure.fleet.routingState).toBe("HOSTED");
  expect(nonceFailure.fleet.canaryScaleSet).toBe("prior-canary");
  expect(nonceFailure.dueWork).toHaveLength(0);
  expect(nonceFailure.transitions).toHaveLength(1);

  const saturated = makeStore();
  saturated.fleet.canaryScaleSet = "prior-canary";
  for (let index = 0; index < MAX_NON_ROUTE_DUE_WORK; index += 1) {
    saturated.enqueue({
      id: `notify-${index}`,
      kind: "notify-email",
      dueAt: commandTime,
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { eventId: `event-${index}` },
    });
  }
  expect(
    (
      await handleAdminCommand(
        saturated,
        adminSecrets,
        await inputFor(command()),
      )
    ).status,
  ).toBe(401);
  expect(saturated.fleet.routingState).toBe("HOSTED");
  expect(saturated.fleet.canaryScaleSet).toBe("prior-canary");
  expect(saturated.nonces.size).toBe(0);
  expect(saturated.transitions).toHaveLength(1);
  expect(saturated.dueWork).toHaveLength(MAX_NON_ROUTE_DUE_WORK);
});

test("two aliases commit only after the prior lease boundary and exact independent read-backs", async () => {
  let current = commandTime;
  const store = makeStore(() => current);
  await admit(store);
  await executeDueWork(
    store,
    githubClient(async (expectation) => ({
      status: 200,
      body: canaryObservation(expectation),
    })),
    store.claimReady(current, 8, 5_000),
    undefined,
    { hostedTransitionSafetyMarginMs: 1_000 },
  );

  current = "2026-01-01T00:00:20.000Z";
  const commit = await heartbeat(store, current, 5);
  expect(commit.body).not.toContain('"mode":"enabled"');
  expect(store.fleet.routingState).toBe("LEGACY_CANARY");
  expect(store.fleet.leaseGeneration).toBe(12);
  expect(store.fleet.leaseNotBefore).toBe("2026-01-01T00:03:01.000Z");
  const routes = store.dueWork.filter(
    (row) =>
      row.kind === "github-mutate-route" && row.payload.value === "legacy",
  );
  expect(routes).toHaveLength(2);
  expect(routes.map((row) => row.payload.repositoryAlias).sort()).toEqual([
    "repo-a",
    "repo-b",
  ]);
  expect(new Set(routes.map((row) => row.payload.transitionRevision))).toEqual(
    new Set(["12"]),
  );
  expect(new Set(routes.map((row) => row.payload.canaryEvidence)).size).toBe(1);
  expect(routes.every((row) => row.dueAt === "2026-01-01T00:03:01.000Z")).toBe(
    true,
  );

  current = "2026-01-01T00:03:00.999Z";
  expect(
    store
      .claimReady(current, 8, 5_000)
      .filter((row) => row.kind === "github-mutate-route"),
  ).toHaveLength(0);
  expect((await heartbeat(store, current, 6)).body).not.toContain(
    '"mode":"enabled"',
  );

  current = "2026-01-01T00:03:01.000Z";
  const batch = store
    .claimReady(current, 8, 5_000)
    .filter((row) => row.kind === "github-mutate-route");
  expect(batch).toHaveLength(2);
  const calls: unknown[][] = [];
  const client: GitHubClient = {
    mutateVariable: async (...args: unknown[]) => {
      calls.push(args);
      return { status: 204 };
    },
    readVariable: async (...args: unknown[]) => ({
      status: 200,
      body: args[1] === "PORTABLE_GHAR_ROUTE" ? "legacy" : "wrong",
    }),
    observeCanary: async () => ({ status: 500 }),
    observeQueueRecovery: async () => ({ status: 500 }),
    observeArchive: async () => ({ status: 500 }),
  };
  await executeDueWork(store, client, [batch[0]!], undefined, {
    hostedTransitionSafetyMarginMs: 1_000,
    selectorEvidenceMaxAgeMs: 60_000,
  });
  expect(store.fleet.routingState).toBe("LEGACY_CANARY");
  expect((await heartbeat(store, current, 7)).body).not.toContain(
    '"mode":"enabled"',
  );
  await executeDueWork(store, client, [batch[1]!], undefined, {
    hostedTransitionSafetyMarginMs: 1_000,
    selectorEvidenceMaxAgeMs: 60_000,
  });
  expect(calls.map((args) => args.slice(0, 3))).toEqual([
    ["repo-a", "PORTABLE_GHAR_ROUTE", "legacy"],
    ["repo-b", "PORTABLE_GHAR_ROUTE", "legacy"],
  ]);
  expect(store.fleet.routingState).toBe("LEGACY");
  expect(store.fleet.leaseNotBefore).toBeNull();

  const enabled = await heartbeat(store, current, 8);
  expect(enabled.body).toContain('"mode":"enabled"');
  expect(enabled.body).toContain('"holder":"legacy"');
});

test("partial legacy route read-back never promotes and survives reload as non-authorizing", async () => {
  let current = commandTime;
  const store = makeStore(() => current);
  await admit(store);
  await executeDueWork(
    store,
    githubClient(async (expectation) => ({
      status: 200,
      body: canaryObservation(expectation),
    })),
    store.claimReady(current, 8, 5_000),
    undefined,
    { hostedTransitionSafetyMarginMs: 1_000 },
  );
  current = "2026-01-01T00:00:20.000Z";
  await heartbeat(store, current, 5);

  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql: FleetSql = {
    run(query, ...binds) {
      if (binds.length === 0) db.exec(query);
      else db.prepare(query).run(...binds);
    },
    all(query, ...binds) {
      return db.prepare(query).all(...binds) as Record<string, unknown>[];
    },
    transaction(work) {
      db.exec("BEGIN IMMEDIATE");
      try {
        work();
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
  saveFleetStore(sql, store);
  const loaded = loadFleetStore(sql, "example-fleet", { now: () => current });
  expect(loaded.fleet.routingState).toBe("LEGACY_CANARY");
  expect(loaded.fleet.leaseNotBefore).toBe("2026-01-01T00:03:01.000Z");
  expect(
    loaded.dueWork.filter(
      (row) => row.kind === "github-mutate-route" && row.status === "ready",
    ),
  ).toHaveLength(2);
  expect((await heartbeat(loaded, current, 6)).body).not.toContain(
    '"mode":"enabled"',
  );
});

test("failed legacy canary uses the no-route shortcut, but maybe-effective route failure restores hosted with alias risk", async () => {
  const preEffect = makeStore();
  await admit(preEffect);
  await executeDueWork(
    preEffect,
    githubClient(async (expectation) => ({
      status: 200,
      body: canaryObservation(expectation, "failure"),
    })),
    preEffect.claimReady(commandTime, 8, 5_000),
    undefined,
    { hostedTransitionSafetyMarginMs: 1_000 },
  );
  expect(preEffect.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(
    preEffect.dueWork.some((row) => row.kind === "github-mutate-route"),
  ).toBe(false);
  expect(
    [...preEffect.repositories.values()].every(
      (repository) => repository.openQueueRisk === null,
    ),
  ).toBe(true);

  let current = commandTime;
  const postEffect = makeStore(() => current);
  await admit(postEffect);
  await executeDueWork(
    postEffect,
    githubClient(async (expectation) => ({
      status: 200,
      body: canaryObservation(expectation),
    })),
    postEffect.claimReady(current, 8, 5_000),
    undefined,
    { hostedTransitionSafetyMarginMs: 1_000 },
  );
  current = "2026-01-01T00:00:20.000Z";
  await heartbeat(postEffect, current, 5);
  current = "2026-01-01T00:03:01.000Z";
  const routes = postEffect
    .claimReady(current, 8, 5_000)
    .filter((row) => row.kind === "github-mutate-route");
  await executeDueWork(
    postEffect,
    {
      mutateVariable: async (...args: unknown[]) =>
        args[0] === "repo-a" ? { status: 0 } : { status: 404 },
      readVariable: async () => ({ status: 503 }),
      observeCanary: async () => ({ status: 500 }),
      observeQueueRecovery: async () => ({ status: 500 }),
      observeArchive: async () => ({ status: 500 }),
    },
    routes,
  );
  expect(postEffect.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  for (const repository of postEffect.repositories.values()) {
    expect(repository.openQueueRisk, repository.alias).not.toBeNull();
  }
  expect(
    postEffect.dueWork.filter(
      (row) =>
        row.kind === "github-mutate-route" && row.payload.value === "hosted",
    ),
  ).toHaveLength(2);
});
