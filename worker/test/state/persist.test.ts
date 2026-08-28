import { DatabaseSync } from "node:sqlite";
import { expect, test } from "vitest";

import { MAX_DUE_WORK, MemoryFleetStore } from "../../src/state/memory";
import { executeDueWork, persistCanary } from "../../src/github/outbox";
import {
  dueWorkClaimGuard,
  loadFleetStore,
  saveFleetStore,
  type FleetSql,
} from "../../src/state/persist";
import { FLEET_SCHEMA_SQL } from "../../src/state/schema";
import {
  decodeCanaryExpectation,
  encodeCanaryExpectation,
  type CanaryEvidence,
} from "../../src/routing/canary";
import { encodeQueueRecoveryExpectation } from "../../src/protocol/admin";

function applySql(db: DatabaseSync, query: string, binds: unknown[]): void {
  if (binds.length === 0) {
    db.exec(query);
    return;
  }
  db.prepare(query).run(...binds);
}

function databaseSql(db: DatabaseSync): FleetSql {
  return {
    run(query: string, ...binds: unknown[]) {
      applySql(db, query, binds);
    },
    all(query: string, ...binds: unknown[]) {
      return db.prepare(query).all(...binds) as Record<string, unknown>[];
    },
    transaction(work: () => void) {
      db.exec("BEGIN IMMEDIATE");
      try {
        work();
        db.exec("COMMIT");
      } catch (error) {
        try {
          db.exec("ROLLBACK");
        } catch {
          // Keep the original failure.
        }
        throw error;
      }
    },
  };
}

function memorySql(): FleetSql {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  return databaseSql(db);
}

test("fleet store survives save and load", () => {
  const sql = memorySql();
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const store = new MemoryFleetStore("example-fleet", clock);
  store.fleet.inventoried = true;
  store.fleet.epoch = 3;
  store.fleet.sessionId = "c".repeat(64);
  store.fleet.sequence = 4;
  store.fleet.leaseGeneration = 5;
  store.fleet.holder = "portable";
  store.fleet.fenceGeneration = 7;
  store.fleet.routingState = "PORTABLE";
  store.fleet.policyDigest = "a".repeat(64);
  store.fleet.configRevision = 2;
  store.fleet.maxCapacity = 2;
  const canaryExpectation = {
    schemaVersion: 1,
    repositoryAlias: "repo-a",
    workflow: "recovery-canary.yml",
    revision: "0123456789abcdef0123456789abcdef01234567",
    scaleSet: "portable-canary",
    environment: "self-hosted",
    startedAt: "2026-01-01T00:00:00.000Z",
    observeUntil: "2026-01-01T00:05:00.000Z",
    sessionId: "c".repeat(64),
    leaseGeneration: 5,
  } as const;
  const canaryEvidence: CanaryEvidence = {
    ...canaryExpectation,
    completedAt: "2026-01-01T00:00:08.000Z",
    observedAt: "2026-01-01T00:00:09.000Z",
    heartbeatSequence: 4,
  };
  store.fleet.canaryEvidence = canaryEvidence;
  store.rememberNonce("n".repeat(64), "2026-01-01T00:01:00.000Z");
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "self-hosted",
    confirmedRoute: "self-hosted",
    archiveEligibility: "active",
    archivePolicyRevision: null,
    archiveObservedAt: "2026-01-01T00:00:09.000Z",
    archived: false,
    selectorEvidenceAt: "2026-01-01T00:00:09.000Z",
    openQueueRisk: {
      transitionEpoch: 7,
      sourceHead: "unknown",
      evidenceDigest: "b".repeat(64),
      reason: "pre-transition-queue-may-remain",
    },
  });
  store.enqueue({
    id: "due-1",
    kind: "canary-observe",
    dueAt: "2026-01-01T00:00:10.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 1,
    status: "ready",
    payload: encodeCanaryExpectation(canaryExpectation),
  });
  store.transitions.push({ epoch: 5, from: "HOSTED", to: "PORTABLE_CANARY" });
  store.recordAudit("session-accepted");
  saveFleetStore(sql, store);

  const loaded = loadFleetStore(sql, "example-fleet", clock);
  expect(loaded.fleet.epoch).toBe(3);
  expect(loaded.fleet.fenceGeneration).toBe(7);
  expect(loaded.fleet.routingState).toBe("PORTABLE");
  expect(loaded.fleet.canaryEvidence).toEqual(canaryEvidence);
  expect(loaded.fleet.maxCapacity).toBe(2);
  expect(loaded.nonces.get("n".repeat(64))).toBe("2026-01-01T00:01:00.000Z");
  expect(loaded.repositories.get("repo-a")?.expectedRoute).toBe("self-hosted");
  expect(loaded.repositories.get("repo-a")?.openQueueRisk).toEqual({
    transitionEpoch: 7,
    sourceHead: "unknown",
    evidenceDigest: "b".repeat(64),
    reason: "pre-transition-queue-may-remain",
  });
  expect(loaded.dueWork).toHaveLength(1);
  expect(decodeCanaryExpectation(loaded.dueWork[0]?.payload ?? {})).toEqual({
    schemaVersion: 1,
    repositoryAlias: "repo-a",
    workflow: "recovery-canary.yml",
    revision: "0123456789abcdef0123456789abcdef01234567",
    scaleSet: "portable-canary",
    environment: "self-hosted",
    startedAt: "2026-01-01T00:00:00.000Z",
    observeUntil: "2026-01-01T00:05:00.000Z",
    sessionId: "c".repeat(64),
    leaseGeneration: 5,
  });
  expect(loaded.transitions).toEqual([
    { epoch: 5, from: "HOSTED", to: "PORTABLE_CANARY" },
  ]);
  expect(loaded.audit).toContain("session-accepted");
});

test("repository selector companions survive reload and corrupt alias values restrict locally", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const store = new MemoryFleetStore("example-fleet", clock);
  for (const alias of ["repo-a", "repo-b"]) {
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
    });
    store.putRepository(repository);
  }
  saveFleetStore(sql, store);

  const first = loadFleetStore(sql, "example-fleet", clock);
  expect(first.repositories.get("repo-a")).toEqual(
    expect.objectContaining({
      expectedScaleSet: "portable-runners",
      confirmedScaleSet: "portable-runners",
      expectedLegacyLabel: "legacy-runners",
      confirmedLegacyLabel: "legacy-runners",
    }),
  );

  db.prepare(
    `UPDATE repositories SET expected_scale_set = 'bad/value',
      confirmed_scale_set = '', expected_legacy_label = NULL,
      confirmed_legacy_label = X'01' WHERE alias = 'repo-a'`,
  ).run();
  const restrictive = loadFleetStore(sql, "example-fleet", clock);
  expect(restrictive.repositories.get("repo-a")).toEqual(
    expect.objectContaining({
      expectedScaleSet: null,
      confirmedScaleSet: null,
      expectedLegacyLabel: null,
      confirmedLegacyLabel: null,
    }),
  );
  expect(restrictive.repositories.get("repo-b")).toEqual(
    expect.objectContaining({
      expectedScaleSet: "portable-runners",
      confirmedScaleSet: "portable-runners",
      expectedLegacyLabel: "legacy-runners",
      confirmedLegacyLabel: "legacy-runners",
    }),
  );
});

test("failed canary transition epochs survive abort, boundary, and reload", async () => {
  const sql = memorySql();
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const store = new MemoryFleetStore("example-fleet", clock);
  store.fleet.routingState = "HOSTED";
  store.fleet.sessionId = "c".repeat(64);
  store.fleet.leaseGeneration = 5;
  store.fleet.canaryScaleSet = "portable-canary";
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "hosted",
    confirmedRoute: "hosted",
    archiveEligibility: "active",
    archivePolicyRevision: null,
    archiveObservedAt: clock.now(),
    archived: false,
    selectorEvidenceAt: clock.now(),
    openQueueRisk: null,
  });
  persistCanary(store, clock.now(), "PORTABLE_CANARY", {
    repositoryAlias: "repo-a",
    workflow: "recovery-canary.yml",
    revision: "0123456789abcdef0123456789abcdef01234567",
    observeUntil: "2026-01-01T00:05:00.000Z",
  });
  saveFleetStore(sql, store);
  const observing = loadFleetStore(sql, "example-fleet", clock);
  const observationBatch = observing.claimReady(clock.now(), 8, 5_000);
  expect(observationBatch).toHaveLength(1);
  saveFleetStore(sql, observing);
  const observationGuard = dueWorkClaimGuard(observationBatch[0]!);
  const expectation = decodeCanaryExpectation(observationBatch[0]!.payload);
  await executeDueWork(
    observing,
    {
      mutateVariable: async () => ({ status: 500 }),
      readVariable: async () => ({ status: 500 }),
      observeCanary: async () => ({
        status: 200,
        body: JSON.stringify({
          schemaVersion: 1,
          status: "failure",
          repositoryAlias: expectation.repositoryAlias,
          workflow: expectation.workflow,
          revision: expectation.revision,
          scaleSet: expectation.scaleSet,
          environment: expectation.environment,
          completedAt: clock.now(),
        }),
      }),
    },
    observationBatch,
    undefined,
    { hostedTransitionSafetyMarginMs: 1_000 },
  );
  saveFleetStore(sql, observing, { expectedClaims: [observationGuard] });

  const draining = loadFleetStore(sql, "example-fleet", clock);
  expect(draining.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(draining.transitions).toEqual([
    { epoch: 1, from: "HOSTED", to: "PORTABLE_CANARY" },
    {
      epoch: 2,
      from: "PORTABLE_CANARY",
      to: "DRAINING_TO_HOSTED",
    },
  ]);

  const boundaryBatch = draining.claimReady(clock.now(), 8, 5_000);
  expect(boundaryBatch).toHaveLength(1);
  expect(boundaryBatch[0]?.kind).toBe("canary-boundary");
  saveFleetStore(sql, draining);
  const boundaryGuard = dueWorkClaimGuard(boundaryBatch[0]!);
  await executeDueWork(
    draining,
    {
      mutateVariable: async () => ({ status: 500 }),
      readVariable: async () => ({ status: 500 }),
      observeCanary: async () => ({ status: 500 }),
    },
    boundaryBatch,
  );
  saveFleetStore(sql, draining, { expectedClaims: [boundaryGuard] });
  const hosted = loadFleetStore(sql, "example-fleet", clock);
  expect(hosted.fleet.routingState).toBe("HOSTED");
  expect(hosted.transitions).toEqual([
    { epoch: 1, from: "HOSTED", to: "PORTABLE_CANARY" },
    {
      epoch: 2,
      from: "PORTABLE_CANARY",
      to: "DRAINING_TO_HOSTED",
    },
    { epoch: 3, from: "DRAINING_TO_HOSTED", to: "HOSTED" },
  ]);
  expect(hosted.dueWork).toEqual([
    expect.objectContaining({ kind: "canary-observe", status: "failed" }),
  ]);
});

test("missing fleet row hydrates an empty store", () => {
  const loaded = loadFleetStore(memorySql(), "example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  expect(loaded.fleet.epoch).toBe(0);
  expect(loaded.fleet.routingState).toBe("UNINITIALIZED");
});

test("archive eligibility states survive reload with one policy revision", () => {
  for (const archiveEligibility of [
    "active",
    "archived-disabled",
    "pending-reactivation",
  ] as const) {
    const sql = memorySql();
    const clock = { now: () => "2026-01-01T00:00:10.000Z" };
    const store = new MemoryFleetStore("example-fleet", clock);
    store.fleet.configRevision = 8;
    store.putRepository({
      alias: "repo-a",
      expectedRoute: "hosted",
      confirmedRoute: "hosted",
      archiveEligibility,
      archivePolicyRevision: archiveEligibility === "active" ? null : 7,
      archiveObservedAt: "2026-01-01T00:00:09.000Z",
      archived: false,
      selectorEvidenceAt: null,
      openQueueRisk: null,
    });
    saveFleetStore(sql, store);

    const loaded = loadFleetStore(sql, "example-fleet", clock);
    expect(loaded.repositories.get("repo-a")?.archiveEligibility).toBe(
      archiveEligibility,
    );
    expect(loaded.repositories.get("repo-a")?.archivePolicyRevision).toBe(
      archiveEligibility === "active" ? null : 7,
    );
  }
});

test("malformed archive columns hydrate as an alias-local restriction", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const store = new MemoryFleetStore("example-fleet", clock);
  store.fleet.configRevision = 4;
  for (const alias of ["repo-a", "repo-b"]) {
    store.putRepository({
      alias,
      expectedRoute: "hosted",
      confirmedRoute: "hosted",
      archiveEligibility: "active",
      archivePolicyRevision: null,
      archiveObservedAt: "2026-01-01T00:00:09.000Z",
      archived: false,
      selectorEvidenceAt: null,
      openQueueRisk: null,
    });
  }
  saveFleetStore(sql, store);
  db.prepare(
    `UPDATE repositories SET archive_latched = 9,
      archive_policy_revision = -1, archive_observed_at = 'bad-time',
      archived = 7 WHERE alias = 'repo-a'`,
  ).run();

  const loaded = loadFleetStore(sql, "example-fleet", clock);
  expect(loaded.repositories.get("repo-a")).toEqual(
    expect.objectContaining({
      archiveEligibility: "archived-disabled",
      archivePolicyRevision: 4,
      archiveObservedAt: null,
      archived: true,
    }),
  );
  expect(loaded.repositories.get("repo-b")).toEqual(
    expect.objectContaining({
      archiveEligibility: "active",
      archivePolicyRevision: null,
      archived: false,
    }),
  );
});

test("queue risk hydration rejects malformed or widened durable state", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const store = new MemoryFleetStore("example-fleet", clock);
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "hosted",
    confirmedRoute: "hosted",
    archiveEligibility: "active",
    archivePolicyRevision: null,
    archiveObservedAt: null,
    archived: false,
    selectorEvidenceAt: null,
    openQueueRisk: {
      transitionEpoch: 7,
      sourceHead: "unknown",
      evidenceDigest: "a".repeat(64),
      reason: "pre-transition-queue-may-remain",
    },
  });
  saveFleetStore(sql, store);

  for (const invalid of [
    "not-json",
    JSON.stringify({ transitionEpoch: 7 }),
    JSON.stringify({
      transitionEpoch: 7,
      sourceHead: "unknown",
      evidenceDigest: "a".repeat(64),
      reason: "pre-transition-queue-may-remain",
      extra: true,
    }),
  ]) {
    db.prepare("UPDATE repositories SET open_queue_risk = ?").run(invalid);
    expect(() => loadFleetStore(sql, "example-fleet", clock)).toThrow(
      "repository row is invalid",
    );
  }
});

test("save uses a storage transaction instead of SQL BEGIN", () => {
  const statements: string[] = [];
  let transacted = false;
  const inner = memorySql();
  const sql: FleetSql = {
    run(query: string, ...binds: unknown[]) {
      statements.push(query);
      inner.run(query, ...binds);
    },
    all(query: string, ...binds: unknown[]) {
      return inner.all(query, ...binds);
    },
    transaction(work: () => void) {
      transacted = true;
      inner.transaction(work);
    },
  };
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  store.fleet.epoch = 3;
  saveFleetStore(sql, store);
  expect(transacted).toBe(true);
  expect(
    statements.some((query) =>
      /^(BEGIN|COMMIT|ROLLBACK)\b/i.test(query.trim()),
    ),
  ).toBe(false);
});

test("save never clears durable tables wholesale", () => {
  const statements: string[] = [];
  const inner = memorySql();
  const sql: FleetSql = {
    run(query: string, ...binds: unknown[]) {
      statements.push(query.trim());
      inner.run(query, ...binds);
    },
    all(query: string, ...binds: unknown[]) {
      return inner.all(query, ...binds);
    },
    transaction(work: () => void) {
      inner.transaction(work);
    },
  };
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  store.rememberNonce("n".repeat(64), "2026-01-01T00:01:00.000Z");
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "hosted",
    confirmedRoute: "hosted",
    archiveEligibility: "active",
    archivePolicyRevision: null,
    archiveObservedAt: null,
    archived: false,
    selectorEvidenceAt: "2026-01-01T00:00:09.000Z",
    openQueueRisk: null,
  });
  store.enqueue({
    id: "due-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:10.000Z",
    claimId: "claim-due-1",
    claimExpiresAt: "2026-01-01T00:00:20.000Z",
    attempts: 1,
    status: "claimed",
    payload: { repository: "repo-a" },
  });
  store.transitions.push({ epoch: 1, from: "UNINITIALIZED", to: "HOSTED" });
  store.recordAudit("state-initialized");

  saveFleetStore(sql, store);

  const protectedTables =
    "(?:fleet_state|request_nonces|repositories|due_work|transitions|audit_events)";
  const blanketDelete = new RegExp(
    `^DELETE\\s+FROM\\s+${protectedTables}\\s*;?$`,
    "i",
  );
  expect(statements.filter((query) => blanketDelete.test(query))).toEqual([]);
});

test("save preserves audit sequence and appends duplicate event text once", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const first = new MemoryFleetStore("example-fleet", clock);
  first.recordAudit("same-event");
  saveFleetStore(sql, first);
  const original = db
    .prepare("SELECT seq, event FROM audit_events ORDER BY seq")
    .all() as Array<{ seq: number; event: string }>;
  expect(original).toHaveLength(1);

  const second = loadFleetStore(sql, "example-fleet", clock);
  second.recordAudit("same-event");
  saveFleetStore(sql, second);

  expect(
    db.prepare("SELECT seq, event FROM audit_events ORDER BY seq").all(),
  ).toEqual([
    { seq: original[0]?.seq, event: "same-event" },
    { seq: (original[0]?.seq ?? 0) + 1, event: "same-event" },
  ]);
});

test("full duplicate audit window still appends one new sequence", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const first = new MemoryFleetStore("example-fleet", clock);
  for (let index = 0; index < 256; index += 1) {
    first.recordAudit("same-event");
  }
  saveFleetStore(sql, first);
  const initial = db
    .prepare("SELECT seq FROM audit_events ORDER BY seq")
    .all() as Array<{ seq: number }>;
  const previousMaximum = initial.at(-1)?.seq;
  expect(initial).toHaveLength(256);

  const second = loadFleetStore(sql, "example-fleet", clock);
  second.recordAudit("same-event");
  saveFleetStore(sql, second);

  const retained = db
    .prepare("SELECT seq, event FROM audit_events ORDER BY seq")
    .all() as Array<{ seq: number; event: string }>;
  expect(retained).toHaveLength(256);
  expect(retained[0]?.seq).toBe((initial[0]?.seq ?? 0) + 1);
  expect(retained.at(-1)?.seq).toBe((previousMaximum ?? 0) + 1);
  expect(retained.every((row) => row.event === "same-event")).toBe(true);
});

test("failed save does not expire the in-memory nonce", () => {
  const inner = memorySql();
  let now = "2026-01-01T00:00:00.000Z";
  let failSave = false;
  const sql: FleetSql = {
    run(query: string, ...binds: unknown[]) {
      if (failSave && query.includes("INSERT INTO fleet_state")) {
        throw new Error("save failed");
      }
      inner.run(query, ...binds);
    },
    all(query: string, ...binds: unknown[]) {
      return inner.all(query, ...binds);
    },
    transaction(work: () => void) {
      inner.transaction(work);
    },
  };
  const store = new MemoryFleetStore("example-fleet", { now: () => now });
  const nonce = "n".repeat(64);
  store.rememberNonce(nonce, "2026-01-01T00:00:05.000Z");
  saveFleetStore(sql, store);

  now = "2026-01-01T00:00:10.000Z";
  failSave = true;
  expect(() => saveFleetStore(sql, store)).toThrow("save failed");
  expect(store.nonces.get(nonce)).toBe("2026-01-01T00:00:05.000Z");
});

test("loading a foreign fleet fails closed", () => {
  const sql = memorySql();
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  saveFleetStore(sql, new MemoryFleetStore("foreign-fleet", clock));

  expect(() => loadFleetStore(sql, "example-fleet", clock)).toThrow(
    "durable object contains a foreign fleet",
  );
});

test("completed due work compacts atomically while unresolved outcomes stay visible", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  for (const [id, status] of [
    ["done-1", "done"],
    ["failed-1", "failed"],
    ["uncertain-1", "uncertain"],
  ] as const) {
    store.enqueue({
      id,
      kind: "github-readback",
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 1,
      status,
      payload: { mutationId: "mutation-1" },
    });
  }

  saveFleetStore(sql, store);

  expect(
    db.prepare("SELECT id, status FROM due_work ORDER BY id").all(),
  ).toEqual([
    { id: "failed-1", status: "failed" },
    { id: "uncertain-1", status: "uncertain" },
  ]);
  expect(
    db.prepare("SELECT event FROM audit_events ORDER BY seq").all(),
  ).toContainEqual({ event: "due-work-completed:done-1" });
  expect(store.dueWork.map((row) => row.id).sort()).toEqual([
    "failed-1",
    "uncertain-1",
  ]);
});

test("stale claimant cannot commit an outcome over a newer claim", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const original = new MemoryFleetStore("example-fleet", clock);
  original.fleet.leaseGeneration = 7;
  original.enqueue({
    id: "readback-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: "claim-old",
    claimExpiresAt: "2026-01-01T00:00:20.000Z",
    attempts: 1,
    status: "claimed",
    payload: {
      effectKey: "effect-1",
      mutationId: "mutation-1",
      transitionRevision: "7",
    },
  });
  saveFleetStore(sql, original);

  const stale = loadFleetStore(sql, "example-fleet", clock);
  db.prepare(
    `UPDATE due_work
    SET claim_id = ?, claim_expires_at = ?, attempts = ?
    WHERE id = ?`,
  ).run("claim-new", "2026-01-01T00:00:30.000Z", 2, "readback-1");

  const staleRow = stale.dueWork[0];
  if (staleRow === undefined) {
    throw new Error("stale claim fixture is missing");
  }
  const staleGuard = dueWorkClaimGuard(staleRow);
  staleRow.status = "done";
  expect(() =>
    saveFleetStore(sql, stale, {
      expectedClaims: [staleGuard],
    }),
  ).toThrow("due-work claim diverged");
  expect(
    db
      .prepare("SELECT claim_id, status FROM due_work WHERE id = ?")
      .get("readback-1"),
  ).toEqual({ claim_id: "claim-new", status: "claimed" });
});

test("exact claim guards protect read-only controller outcomes", () => {
  const expectation = encodeCanaryExpectation({
    schemaVersion: 1,
    repositoryAlias: "repo-a",
    workflow: "recovery-canary.yml",
    revision: "0123456789abcdef0123456789abcdef01234567",
    scaleSet: "portable-canary",
    environment: "self-hosted",
    startedAt: "2026-01-01T00:00:00.000Z",
    observeUntil: "2026-01-01T00:05:00.000Z",
    sessionId: "c".repeat(64),
    leaseGeneration: 1,
  });
  const cases = [
    {
      id: "canary-1",
      kind: "canary-observe" as const,
      payload: expectation,
    },
    {
      id: "canary-boundary-2",
      kind: "canary-boundary" as const,
      payload: {
        transitionRevision: "2",
        from: "PORTABLE_CANARY",
      },
    },
    {
      id: "queue-recovery-repo-a-7",
      kind: "github-attestation" as const,
      payload: encodeQueueRecoveryExpectation({
        schemaVersion: 1,
        fleetId: "example-fleet",
        repositoryAlias: "repo-a",
        transitionEpoch: 7,
        riskEvidenceDigest: "a".repeat(64),
        sourceHead: "0123456789abcdef0123456789abcdef01234567",
        recoveryEvidenceDigest: "d".repeat(64),
        observeUntil: "2026-01-01T00:01:10.000Z",
      }),
    },
  ];

  for (const fixture of cases) {
    const db = new DatabaseSync(":memory:");
    db.exec(FLEET_SCHEMA_SQL);
    const sql = databaseSql(db);
    const clock = { now: () => "2026-01-01T00:00:10.000Z" };
    const original = new MemoryFleetStore("example-fleet", clock);
    original.enqueue({
      ...fixture,
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: `claim-${fixture.id}`,
      claimExpiresAt: "2026-01-01T00:00:20.000Z",
      attempts: 1,
      status: "claimed",
    });
    saveFleetStore(sql, original);
    const stale = loadFleetStore(sql, "example-fleet", clock);
    const row = stale.dueWork[0];
    if (row === undefined) {
      throw new Error("canary claim fixture is missing");
    }
    const guard = dueWorkClaimGuard(row);
    row.status = "failed";
    row.claimId = null;
    row.claimExpiresAt = null;
    db.prepare("UPDATE due_work SET claim_id = ? WHERE id = ?").run(
      `replacement-${fixture.id}`,
      fixture.id,
    );

    expect(() =>
      saveFleetStore(sql, stale, { expectedClaims: [guard] }),
    ).toThrow("due-work claim diverged");
  }
});

test("expired read-only claim can persist ready when another row takes the batch slot", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const original = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  original.enqueue({
    id: "a-priority",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: { mutationId: "mutation-a" },
  });
  original.enqueue({
    id: "z-expired",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:01.000Z",
    claimId: "claim-z",
    claimExpiresAt: "2026-01-01T00:00:05.000Z",
    attempts: 1,
    status: "claimed",
    payload: { mutationId: "mutation-z" },
  });
  saveFleetStore(sql, original);

  const recovered = loadFleetStore(sql, "example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  expect(
    recovered
      .claimReady("2026-01-01T00:00:10.000Z", 1, 5_000)
      .map((row) => row.id),
  ).toEqual(["a-priority"]);
  expect(recovered.dueWork.find((row) => row.id === "z-expired")?.status).toBe(
    "ready",
  );

  expect(() => saveFleetStore(sql, recovered)).not.toThrow();
  expect(
    db
      .prepare("SELECT claim_id, status FROM due_work WHERE id = ?")
      .get("z-expired"),
  ).toEqual({ claim_id: null, status: "ready" });
});

test("failed outcome transaction preserves the claim and synthetic audit state", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const original = new MemoryFleetStore("example-fleet", clock);
  original.fleet.leaseGeneration = 7;
  original.enqueue({
    id: "readback-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: "claim-1",
    claimExpiresAt: "2026-01-01T00:00:20.000Z",
    attempts: 1,
    status: "claimed",
    payload: {
      effectKey: "effect-1",
      mutationId: "mutation-1",
      transitionRevision: "7",
    },
  });
  saveFleetStore(sql, original);

  const outcome = loadFleetStore(sql, "example-fleet", clock);
  const row = outcome.dueWork[0];
  if (row === undefined) {
    throw new Error("outcome fixture is missing");
  }
  const guard = dueWorkClaimGuard(row);
  row.status = "done";
  row.claimId = null;
  row.claimExpiresAt = null;
  const failing: FleetSql = {
    run(query: string, ...binds: unknown[]) {
      if (query.includes("INSERT INTO audit_events")) {
        throw new Error("audit insert failed");
      }
      sql.run(query, ...binds);
    },
    all(query: string, ...binds: unknown[]) {
      return sql.all(query, ...binds);
    },
    transaction(work: () => void) {
      sql.transaction(work);
    },
  };
  expect(() =>
    saveFleetStore(failing, outcome, { expectedClaims: [guard] }),
  ).toThrow("audit insert failed");
  expect(outcome.dueWork.map((item) => item.id)).toEqual(["readback-1"]);
  expect(outcome.audit).not.toContain("due-work-completed:readback-1");
  expect(
    db
      .prepare("SELECT claim_id, status FROM due_work WHERE id = ?")
      .get("readback-1"),
  ).toEqual({ claim_id: "claim-1", status: "claimed" });

  saveFleetStore(sql, outcome, { expectedClaims: [guard] });
  expect(outcome.dueWork).toHaveLength(0);
  expect(outcome.audit).toContain("due-work-completed:readback-1");
});

test("stale outcome cannot overwrite a newer durable fleet snapshot", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const original = new MemoryFleetStore("example-fleet", clock);
  original.fleet.leaseGeneration = 7;
  original.fleet.routingState = "PORTABLE_CANARY";
  original.enqueue({
    id: "route-7",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: "claim-7",
    claimExpiresAt: "2026-01-01T00:00:20.000Z",
    attempts: 1,
    status: "claimed",
    payload: {
      effectKey: "route-7",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      transitionRevision: "7",
      value: "self-hosted",
    },
  });
  saveFleetStore(sql, original);

  const stale = loadFleetStore(sql, "example-fleet", clock);
  const newer = loadFleetStore(sql, "example-fleet", clock);
  newer.fleet.sequence = 99;
  newer.fleet.holder = "portable";
  newer.fleet.routingState = "DRAINING_TO_HOSTED";
  saveFleetStore(sql, newer);

  const staleRow = stale.dueWork[0];
  if (staleRow === undefined) {
    throw new Error("stale outcome fixture is missing");
  }
  const staleGuard = dueWorkClaimGuard(staleRow);
  staleRow.status = "done";
  staleRow.claimId = null;
  staleRow.claimExpiresAt = null;
  stale.fleet.routingState = "PORTABLE";

  expect(() =>
    saveFleetStore(sql, stale, {
      expectedClaims: [staleGuard],
    }),
  ).toThrow("fleet state diverged");
  expect(
    db
      .prepare(
        `SELECT holder, lease_generation, routing_state, sequence
        FROM fleet_state WHERE fleet_id = ?`,
      )
      .get("example-fleet"),
  ).toEqual({
    holder: "portable",
    lease_generation: 7,
    routing_state: "DRAINING_TO_HOSTED",
    sequence: 99,
  });
  expect(
    db
      .prepare("SELECT claim_id, status FROM due_work WHERE id = ?")
      .get("route-7"),
  ).toEqual({ claim_id: "claim-7", status: "claimed" });
});

test("outcome guards reject deleted rows and independent effect identity drift", () => {
  const cases = [
    { field: "deleted", value: "" },
    { field: "effectKey", value: "effect-new" },
    { field: "transitionRevision", value: "8" },
  ] as const;
  for (const scenario of cases) {
    const db = new DatabaseSync(":memory:");
    db.exec(FLEET_SCHEMA_SQL);
    const sql = databaseSql(db);
    const clock = { now: () => "2026-01-01T00:00:10.000Z" };
    const original = new MemoryFleetStore("example-fleet", clock);
    original.fleet.leaseGeneration = 7;
    original.enqueue({
      id: "readback-1",
      kind: "github-readback",
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: "claim-1",
      claimExpiresAt: "2026-01-01T00:00:20.000Z",
      attempts: 1,
      status: "claimed",
      payload: {
        effectKey: "effect-1",
        mutationId: "mutation-1",
        transitionRevision: "7",
      },
    });
    saveFleetStore(sql, original);
    const outcome = loadFleetStore(sql, "example-fleet", clock);
    const row = outcome.dueWork[0];
    if (row === undefined) {
      throw new Error("guard fixture is missing");
    }
    const guard = dueWorkClaimGuard(row);
    row.status = "done";
    row.claimId = null;
    row.claimExpiresAt = null;
    if (scenario.field === "deleted") {
      db.prepare("DELETE FROM due_work WHERE id = ?").run("readback-1");
    } else {
      const payload = JSON.stringify({
        effectKey: scenario.field === "effectKey" ? scenario.value : "effect-1",
        mutationId: "mutation-1",
        transitionRevision:
          scenario.field === "transitionRevision" ? scenario.value : "7",
      });
      db.prepare("UPDATE due_work SET payload = ? WHERE id = ?").run(
        payload,
        "readback-1",
      );
    }

    expect(() =>
      saveFleetStore(sql, outcome, {
        expectedClaims: [guard],
      }),
    ).toThrow("due-work claim diverged");
  }
});

test("exact claim guard rejects immutable payload divergence", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const sql = databaseSql(db);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const original = new MemoryFleetStore("example-fleet", clock);
  original.fleet.leaseGeneration = 7;
  original.enqueue({
    id: "readback-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: "claim-1",
    claimExpiresAt: "2026-01-01T00:00:20.000Z",
    attempts: 1,
    status: "claimed",
    payload: {
      effectKey: "effect-1",
      mutationId: "mutation-1",
      name: "PORTABLE_GHAR_ROUTE",
      transitionRevision: "7",
      value: "hosted",
    },
  });
  saveFleetStore(sql, original);
  const outcome = loadFleetStore(sql, "example-fleet", clock);
  const row = outcome.dueWork[0];
  if (row === undefined) {
    throw new Error("payload fixture is missing");
  }
  const guard = dueWorkClaimGuard(row);
  row.status = "done";
  row.claimId = null;
  row.claimExpiresAt = null;
  row.payload.value = "self-hosted";

  expect(() =>
    saveFleetStore(sql, outcome, {
      expectedClaims: [guard],
    }),
  ).toThrow("due-work claim diverged");
  expect(
    db.prepare("SELECT payload FROM due_work WHERE id = ?").get("readback-1"),
  ).toEqual({
    payload: JSON.stringify({
      effectKey: "effect-1",
      mutationId: "mutation-1",
      name: "PORTABLE_GHAR_ROUTE",
      transitionRevision: "7",
      value: "hosted",
    }),
  });
});

test("due-work hydration rejects unknown values and an oversized queue", () => {
  const invalid = new DatabaseSync(":memory:");
  invalid.exec(FLEET_SCHEMA_SQL);
  const invalidSql = databaseSql(invalid);
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  saveFleetStore(invalidSql, new MemoryFleetStore("example-fleet", clock));
  invalid
    .prepare(
      `INSERT INTO due_work (
        id, kind, due_at, claim_id, claim_expires_at, attempts, status, payload
      ) VALUES (?, ?, ?, NULL, NULL, 0, ?, ?)`,
    )
    .run("bad-1", "unknown-kind", clock.now(), "unknown-status", "{}");
  expect(() => loadFleetStore(invalidSql, "example-fleet", clock)).toThrow(
    "due-work row is invalid",
  );

  const oversized = new DatabaseSync(":memory:");
  oversized.exec(FLEET_SCHEMA_SQL);
  const oversizedSql = databaseSql(oversized);
  saveFleetStore(oversizedSql, new MemoryFleetStore("example-fleet", clock));
  const insert = oversized.prepare(
    `INSERT INTO due_work (
      id, kind, due_at, claim_id, claim_expires_at, attempts, status, payload
    ) VALUES (?, 'github-readback', ?, NULL, NULL, 0, 'ready', '{}')`,
  );
  for (let index = 0; index < 257; index += 1) {
    insert.run(`due-${index}`, clock.now());
  }
  expect(() => loadFleetStore(oversizedSql, "example-fleet", clock)).toThrow(
    "due-work capacity is exceeded",
  );
});

test("a full valid queue reloads regardless of mutation/read-back sort order", () => {
  const sql = memorySql();
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const store = new MemoryFleetStore("example-fleet", clock);
  for (let index = 0; index < MAX_DUE_WORK - 2; index += 1) {
    store.enqueue({
      id: `prior-readback-${index}`,
      kind: "github-readback",
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: `prior-mutation-${index}` },
    });
  }
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
    payload: { mutationId: "route-1" },
  });
  saveFleetStore(sql, store);

  expect(loadFleetStore(sql, "example-fleet", clock).dueWork).toHaveLength(
    MAX_DUE_WORK,
  );
});

test("a failed save keeps the previous snapshot", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  let fleetInserts = 0;
  const sql: FleetSql = {
    run(query: string, ...binds: unknown[]) {
      if (query.includes("INSERT INTO fleet_state") && fleetInserts++ >= 1) {
        throw new Error("insert failed");
      }
      applySql(db, query, binds);
    },
    all(query: string, ...binds: unknown[]) {
      return db.prepare(query).all(...binds) as Record<string, unknown>[];
    },
    transaction(work: () => void) {
      db.exec("BEGIN IMMEDIATE");
      try {
        work();
        db.exec("COMMIT");
      } catch (error) {
        try {
          db.exec("ROLLBACK");
        } catch {
          // Keep the original failure.
        }
        throw error;
      }
    },
  };
  const clock = { now: () => "2026-01-01T00:00:10.000Z" };
  const first = new MemoryFleetStore("example-fleet", clock);
  first.fleet.epoch = 3;
  first.fleet.routingState = "PORTABLE";
  first.fleet.policyDigest = "a".repeat(64);
  saveFleetStore(sql, first);

  const second = loadFleetStore(sql, "example-fleet", clock);
  second.fleet.epoch = 9;
  second.fleet.routingState = "HOSTED";
  expect(() => saveFleetStore(sql, second)).toThrow("insert failed");

  const loaded = loadFleetStore(sql, "example-fleet", clock);
  expect(loaded.fleet.epoch).toBe(3);
  expect(loaded.fleet.routingState).toBe("PORTABLE");
  expect(loaded.fleet.policyDigest).toBe("a".repeat(64));
});
