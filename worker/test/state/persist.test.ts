import { DatabaseSync } from "node:sqlite";
import { expect, test } from "vitest";

import { MemoryFleetStore } from "../../src/state/memory";
import {
  loadFleetStore,
  saveFleetStore,
  type FleetSql,
} from "../../src/state/persist";
import { FLEET_SCHEMA_SQL } from "../../src/state/schema";

function applySql(db: DatabaseSync, query: string, binds: unknown[]): void {
  if (binds.length === 0) {
    db.exec(query);
    return;
  }
  db.prepare(query).run(...binds);
}

function memorySql(): FleetSql {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
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
  store.fleet.canaryPassed = true;
  store.rememberNonce("n".repeat(64), "2026-01-01T00:01:00.000Z");
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
  store.enqueue({
    id: "due-1",
    kind: "canary-observe",
    dueAt: "2026-01-01T00:00:10.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 1,
    status: "ready",
    payload: { workflow: "canary.yml" },
  });
  store.transitions.push({ epoch: 5, from: "HOSTED", to: "PORTABLE_CANARY" });
  store.recordAudit("session-accepted");
  saveFleetStore(sql, store);

  const loaded = loadFleetStore(sql, "example-fleet", clock);
  expect(loaded.fleet.epoch).toBe(3);
  expect(loaded.fleet.fenceGeneration).toBe(7);
  expect(loaded.fleet.routingState).toBe("PORTABLE");
  expect(loaded.fleet.canaryPassed).toBe(true);
  expect(loaded.fleet.maxCapacity).toBe(2);
  expect(loaded.nonces.get("n".repeat(64))).toBe("2026-01-01T00:01:00.000Z");
  expect(loaded.repositories.get("repo-a")?.expectedRoute).toBe("self-hosted");
  expect(loaded.dueWork).toHaveLength(1);
  expect(loaded.dueWork[0]?.payload.workflow).toBe("canary.yml");
  expect(loaded.transitions).toEqual([
    { epoch: 5, from: "HOSTED", to: "PORTABLE_CANARY" },
  ]);
  expect(loaded.audit).toContain("session-accepted");
});

test("missing fleet row hydrates an empty store", () => {
  const loaded = loadFleetStore(memorySql(), "example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  expect(loaded.fleet.epoch).toBe(0);
  expect(loaded.fleet.routingState).toBe("UNINITIALIZED");
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
    statements.some((query) => /^(BEGIN|COMMIT|ROLLBACK)\b/i.test(query.trim())),
  ).toBe(false);
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
