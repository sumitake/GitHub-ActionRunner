import { DatabaseSync } from "node:sqlite";
import { expect, test } from "vitest";

import {
  persistCronAddressReceipt,
  type CronAddressReceiptInput,
} from "../../src/state/cron-receipt";
import type { FleetSql } from "../../src/state/persist";
import { FLEET_SCHEMA_SQL } from "../../src/state/schema";

const digestA = "a".repeat(64);
const digestB = "b".repeat(64);

function fleetSql(db: DatabaseSync): FleetSql {
  return {
    run(query: string, ...binds: unknown[]) {
      db.prepare(query).run(...binds);
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
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

function database(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  return db;
}

function receipt(
  overrides: Partial<CronAddressReceiptInput> = {},
): CronAddressReceiptInput {
  return {
    fleetId: "alpha",
    inventoryRevision: "1",
    inventoryDigest: digestA,
    tickTimestamp: "2026-01-01T00:00:00.000Z",
    tickNonce: "1".repeat(64),
    addressedAt: "2026-01-01T00:00:00.010Z",
    nonceExpiresAt: "2026-01-01T00:01:00.010Z",
    ...overrides,
  };
}

function rows(db: DatabaseSync, table: string): unknown[] {
  return db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all();
}

test("first Cron address creates only an inert fleet receipt and nonce", () => {
  const db = database();
  const result = persistCronAddressReceipt(fleetSql(db), receipt());

  expect(result).toEqual({ persistenceGeneration: 1 });
  expect(
    db
      .prepare(
        `SELECT fleet_id, inventoried, holder, routing_state, max_capacity,
          cron_inventory_revision, cron_inventory_digest,
          cron_tick_timestamp, cron_tick_nonce, cron_addressed_at,
          persistence_generation FROM fleet_state`,
      )
      .get(),
  ).toEqual({
    fleet_id: "alpha",
    inventoried: 0,
    holder: "none",
    routing_state: "UNINITIALIZED",
    max_capacity: 0,
    cron_inventory_revision: "1",
    cron_inventory_digest: digestA,
    cron_tick_timestamp: "2026-01-01T00:00:00.000Z",
    cron_tick_nonce: "1".repeat(64),
    cron_addressed_at: "2026-01-01T00:00:00.010Z",
    persistence_generation: 1,
  });
  expect(rows(db, "request_nonces")).toEqual([
    {
      digest: `cron:${"1".repeat(64)}`,
      expires_at: "2026-01-01T00:01:00.010Z",
    },
  ]);
  for (const table of [
    "repositories",
    "transitions",
    "due_work",
    "audit_events",
  ]) {
    expect(rows(db, table)).toEqual([]);
  }
});

test("receipt CAS changes no authority or child responsibility state", () => {
  const db = database();
  db.exec(`INSERT INTO fleet_state (
    fleet_id, inventoried, epoch, session_id, sequence, lease_generation,
    last_issued_lease_expiry_max, lease_not_before, holder, fence_generation,
    routing_state, hosted_hold, config_revision, policy_digest, max_capacity,
    canary_scale_set, canary_passed, persistence_generation
  ) VALUES (
    'alpha', 1, 7, '${"c".repeat(64)}', 8, 9,
    '2026-01-01T01:00:00.000Z', '2026-01-01T00:59:00.000Z',
    'portable', 10, 'PORTABLE', 0, 11, '${digestB}', 2,
    'canary', 1, 12
  );
  INSERT INTO repositories (
    alias, expected_route, confirmed_route, archive_latched,
    archive_observed_at, archived, selector_evidence_at, open_queue_risk
  ) VALUES ('repo-a', 'self-hosted', 'self-hosted', 0, NULL, 0, NULL, NULL);
  INSERT INTO transitions (epoch, from_state, to_state)
    VALUES (7, 'PORTABLE_CANARY', 'PORTABLE');
  INSERT INTO due_work (
    id, kind, due_at, claim_id, claim_expires_at, attempts, status, payload
  ) VALUES ('due-a', 'github-readback', '2026-01-01T00:00:00.000Z',
    NULL, NULL, 0, 'ready', '{}');
  INSERT INTO audit_events (event) VALUES ('kept');
  INSERT INTO request_nonces (digest, expires_at)
    VALUES ('external', '2026-01-01T00:02:00.000Z');`);
  const authorityBefore = db
    .prepare(
      `SELECT inventoried, epoch, session_id, sequence, lease_generation,
        last_issued_lease_expiry_max, lease_not_before, holder,
        fence_generation, routing_state, hosted_hold, config_revision,
        policy_digest, max_capacity, canary_scale_set, canary_passed
      FROM fleet_state`,
    )
    .get();
  const childrenBefore = [
    rows(db, "repositories"),
    rows(db, "transitions"),
    rows(db, "due_work"),
    rows(db, "audit_events"),
  ];

  const result = persistCronAddressReceipt(fleetSql(db), receipt());

  expect(result.persistenceGeneration).toBe(13);
  expect(
    db
      .prepare(
        `SELECT inventoried, epoch, session_id, sequence, lease_generation,
          last_issued_lease_expiry_max, lease_not_before, holder,
          fence_generation, routing_state, hosted_hold, config_revision,
          policy_digest, max_capacity, canary_scale_set, canary_passed
        FROM fleet_state`,
      )
      .get(),
  ).toEqual(authorityBefore);
  expect([
    rows(db, "repositories"),
    rows(db, "transitions"),
    rows(db, "due_work"),
    rows(db, "audit_events"),
  ]).toEqual(childrenBefore);
});

test("receipt replay, conflicting revision, and nonmonotonic time roll back", () => {
  const db = database();
  const sql = fleetSql(db);
  persistCronAddressReceipt(sql, receipt());

  expect(() => persistCronAddressReceipt(sql, receipt())).toThrow();
  expect(() =>
    persistCronAddressReceipt(
      sql,
      receipt({
        tickNonce: "2".repeat(64),
      }),
    ),
  ).toThrow();
  expect(() =>
    persistCronAddressReceipt(
      sql,
      receipt({
        inventoryDigest: digestB,
        tickTimestamp: "2026-01-01T00:00:01.000Z",
        tickNonce: "3".repeat(64),
        addressedAt: "2026-01-01T00:00:01.010Z",
        nonceExpiresAt: "2026-01-01T00:01:01.010Z",
      }),
    ),
  ).toThrow();
  expect(() =>
    persistCronAddressReceipt(
      sql,
      receipt({
        inventoryRevision: "2",
        tickTimestamp: "2026-01-01T00:00:01.000Z",
        tickNonce: "4".repeat(64),
        addressedAt: "2026-01-01T00:00:00.009Z",
        nonceExpiresAt: "2026-01-01T00:01:01.000Z",
      }),
    ),
  ).toThrow();

  expect(
    db
      .prepare(
        `SELECT cron_inventory_revision, cron_tick_nonce,
          persistence_generation FROM fleet_state`,
      )
      .get(),
  ).toEqual({
    cron_inventory_revision: "1",
    cron_tick_nonce: "1".repeat(64),
    persistence_generation: 1,
  });
  expect(
    db.prepare("SELECT digest FROM request_nonces ORDER BY digest").all(),
  ).toEqual([{ digest: `cron:${"1".repeat(64)}` }]);
});

test("newer equal inventory and higher revision advance monotonically", () => {
  const db = database();
  const sql = fleetSql(db);
  persistCronAddressReceipt(sql, receipt());
  expect(
    persistCronAddressReceipt(
      sql,
      receipt({
        tickTimestamp: "2026-01-01T00:00:01.000Z",
        tickNonce: "2".repeat(64),
        addressedAt: "2026-01-01T00:00:01.010Z",
        nonceExpiresAt: "2026-01-01T00:01:01.010Z",
      }),
    ),
  ).toEqual({ persistenceGeneration: 2 });
  expect(
    persistCronAddressReceipt(
      sql,
      receipt({
        inventoryRevision: "18446744073709551615",
        inventoryDigest: digestB,
        tickTimestamp: "2026-01-01T00:00:02.000Z",
        tickNonce: "3".repeat(64),
        addressedAt: "2026-01-01T00:00:02.010Z",
        nonceExpiresAt: "2026-01-01T00:01:02.010Z",
      }),
    ),
  ).toEqual({ persistenceGeneration: 3 });

  expect(() =>
    persistCronAddressReceipt(
      sql,
      receipt({
        inventoryRevision: "2",
        inventoryDigest: digestA,
        tickTimestamp: "2026-01-01T00:00:03.000Z",
        tickNonce: "4".repeat(64),
        addressedAt: "2026-01-01T00:00:03.010Z",
        nonceExpiresAt: "2026-01-01T00:01:03.010Z",
      }),
    ),
  ).toThrow("Cron inventory revision regressed");
  expect(
    db
      .prepare(
        `SELECT cron_inventory_revision, cron_inventory_digest,
          cron_tick_nonce, persistence_generation FROM fleet_state`,
      )
      .get(),
  ).toEqual({
    cron_inventory_revision: "18446744073709551615",
    cron_inventory_digest: digestB,
    cron_tick_nonce: "3".repeat(64),
    persistence_generation: 3,
  });
  expect(
    db
      .prepare("SELECT digest FROM request_nonces WHERE digest = ?")
      .all(`cron:${"4".repeat(64)}`),
  ).toEqual([]);
});

test("nonce cleanup is bounded to expired rows and is transactional", () => {
  const db = database();
  db.exec(`INSERT INTO request_nonces (digest, expires_at) VALUES
    ('expired', '2025-12-31T23:59:59.999Z'),
    ('live', '2026-01-01T00:00:00.011Z')`);
  const sql = fleetSql(db);
  persistCronAddressReceipt(sql, receipt());
  expect(
    db.prepare("SELECT digest FROM request_nonces ORDER BY digest").all(),
  ).toEqual([{ digest: `cron:${"1".repeat(64)}` }, { digest: "live" }]);

  db.exec(`INSERT INTO request_nonces (digest, expires_at)
    VALUES ('rollback-expired', '2025-12-31T23:59:59.999Z')`);
  expect(() => persistCronAddressReceipt(sql, receipt())).toThrow();
  expect(
    db
      .prepare(
        "SELECT digest FROM request_nonces WHERE digest = 'rollback-expired'",
      )
      .all(),
  ).toEqual([{ digest: "rollback-expired" }]);
});
