import { DatabaseSync } from "node:sqlite";

import { expect, test } from "vitest";

import type { AddressStatusResponseV1 } from "../../src/protocol/address-status";
import {
  readAddressStatus,
  type AddressStatusReadInput,
} from "../../src/state/address-status";
import {
  persistCronAddressReceipt,
  type CronAddressReceiptInput,
} from "../../src/state/cron-receipt";
import type { FleetSql } from "../../src/state/persist";
import { FLEET_SCHEMA_SQL } from "../../src/state/schema";

const inventoryDigest = "a".repeat(64);

function fleetSql(
  db: DatabaseSync,
  transactionCount?: { value: number },
): FleetSql {
  let inTransaction = false;
  return {
    run(query: string, ...binds: unknown[]) {
      if (!inTransaction && transactionCount !== undefined) {
        throw new Error("status write escaped its transaction");
      }
      db.prepare(query).run(...binds);
    },
    all(query: string, ...binds: unknown[]) {
      if (!inTransaction && transactionCount !== undefined) {
        throw new Error("status read escaped its transaction");
      }
      return db.prepare(query).all(...binds) as Record<string, unknown>[];
    },
    transaction(work: () => void) {
      if (transactionCount !== undefined) {
        transactionCount.value += 1;
      }
      db.exec("BEGIN IMMEDIATE");
      inTransaction = true;
      try {
        work();
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      } finally {
        inTransaction = false;
      }
    },
  };
}

function cronReceipt(
  overrides: Partial<CronAddressReceiptInput> = {},
): CronAddressReceiptInput {
  return {
    fleetId: "alpha",
    inventoryRevision: "1",
    inventoryDigest,
    tickTimestamp: "2026-01-01T00:00:00.000Z",
    tickNonce: "1".repeat(64),
    addressedAt: "2026-01-01T00:00:00.010Z",
    nonceExpiresAt: "2026-01-01T00:01:00.010Z",
    ...overrides,
  };
}

function input(
  overrides: Partial<AddressStatusReadInput> = {},
): AddressStatusReadInput {
  return {
    fleetId: "alpha",
    inventoryRevision: "1",
    inventoryDigest,
    nonce: "2".repeat(64),
    requestTime: "2026-01-01T00:00:00.020Z",
    responseTime: "2026-01-01T00:00:00.030Z",
    nonceTtlMs: 60_000,
    ...overrides,
  };
}

function database(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  persistCronAddressReceipt(fleetSql(db), cronReceipt());
  return db;
}

function rows(db: DatabaseSync, table: string): unknown[] {
  return db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all();
}

function nonNonceSnapshot(db: DatabaseSync): unknown[] {
  return [
    rows(db, "fleet_state"),
    rows(db, "repositories"),
    rows(db, "transitions"),
    rows(db, "due_work"),
    rows(db, "audit_events"),
  ];
}

test("address-status exposes one receipt-only SQLite reader", async () => {
  const module = await import("../../src/state/address-status");
  expect(module.readAddressStatus).toBeTypeOf("function");
});

test("address-status reads one inert receipt and consumes only its nonce", () => {
  const db = database();
  db.exec(`INSERT INTO request_nonces (digest, expires_at) VALUES
    ('expired', '2026-01-01T00:00:00.005Z'),
    ('live', '2026-01-01T00:02:00.000Z')`);
  const before = nonNonceSnapshot(db);
  const transactions = { value: 0 };

  const status = readAddressStatus(fleetSql(db, transactions), input());

  expect(transactions.value).toBe(1);
  expect(status).toEqual({
    tickTimestamp: "2026-01-01T00:00:00.000Z",
    receiptTime: "2026-01-01T00:00:00.010Z",
    persistenceGeneration: 1,
    inventoried: false,
    holder: "none",
    maxCapacity: 0,
    routingState: "UNINITIALIZED",
    childCounts: {
      repositories: 0,
      transitions: 0,
      dueWork: 0,
      auditEvents: 0,
    },
  } satisfies Omit<
    AddressStatusResponseV1,
    | "protocolVersion"
    | "status"
    | "fleetId"
    | "nonce"
    | "requestTime"
    | "responseTime"
    | "inventoryRevision"
    | "inventoryDigest"
  >);
  expect(nonNonceSnapshot(db)).toEqual(before);
  expect(rows(db, "request_nonces")).toEqual([
    {
      digest: `cron:${"1".repeat(64)}`,
      expires_at: "2026-01-01T00:01:00.010Z",
    },
    { digest: "live", expires_at: "2026-01-01T00:02:00.000Z" },
    {
      digest: `status:${"2".repeat(64)}`,
      expires_at: "2026-01-01T00:01:00.030Z",
    },
  ]);
});

test("address-status replay rolls back without touching persisted state", () => {
  const db = database();
  const sql = fleetSql(db);
  readAddressStatus(sql, input());
  const before = [nonNonceSnapshot(db), rows(db, "request_nonces")];

  expect(() => readAddressStatus(sql, input())).toThrow();
  expect([nonNonceSnapshot(db), rows(db, "request_nonces")]).toEqual(before);
});

test("address-status accepts exact receipt freshness equality and rejects one millisecond later", () => {
  const atBoundary = database();
  expect(() =>
    readAddressStatus(
      fleetSql(atBoundary),
      input({
        requestTime: "2026-01-01T00:01:00.010Z",
        responseTime: "2026-01-01T00:01:00.010Z",
      }),
    ),
  ).not.toThrow();

  const stale = database();
  const before = [nonNonceSnapshot(stale), rows(stale, "request_nonces")];
  expect(() =>
    readAddressStatus(
      fleetSql(stale),
      input({
        requestTime: "2026-01-01T00:01:00.011Z",
        responseTime: "2026-01-01T00:01:00.011Z",
      }),
    ),
  ).toThrow();
  expect([nonNonceSnapshot(stale), rows(stale, "request_nonces")]).toEqual(
    before,
  );
});

test("address-status rejects non-inert, corrupt, foreign, or child state atomically", () => {
  const cases: Array<
    [string, (db: DatabaseSync) => void, Partial<AddressStatusReadInput>?]
  > = [
    ["inventoried", (db) => db.exec("UPDATE fleet_state SET inventoried = 1")],
    ["holder", (db) => db.exec("UPDATE fleet_state SET holder = 'portable'")],
    ["capacity", (db) => db.exec("UPDATE fleet_state SET max_capacity = 1")],
    [
      "routing",
      (db) => db.exec("UPDATE fleet_state SET routing_state = 'HOSTED'"),
    ],
    ["epoch", (db) => db.exec("UPDATE fleet_state SET epoch = 1")],
    [
      "child",
      (db) => db.exec("INSERT INTO audit_events (event) VALUES ('unexpected')"),
    ],
    [
      "incomplete receipt",
      (db) => db.exec("UPDATE fleet_state SET cron_addressed_at = NULL"),
    ],
    ["wrong digest", () => undefined, { inventoryDigest: "b".repeat(64) }],
    [
      "foreign fleet",
      (db) => db.exec("UPDATE fleet_state SET fleet_id = 'beta'"),
    ],
    [
      "time reversal",
      () => undefined,
      {
        requestTime: "2025-12-31T23:59:59.999Z",
        responseTime: "2025-12-31T23:59:59.999Z",
      },
    ],
  ];

  for (const [name, mutate, override] of cases) {
    const db = database();
    mutate(db);
    const before = [nonNonceSnapshot(db), rows(db, "request_nonces")];
    expect(
      () => readAddressStatus(fleetSql(db), input(override)),
      name,
    ).toThrow();
    expect([nonNonceSnapshot(db), rows(db, "request_nonces")], name).toEqual(
      before,
    );
  }
});
