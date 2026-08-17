import { DatabaseSync } from "node:sqlite";
import { expect, test } from "vitest";

import { hexToBytes, MAC_HEADER, signCanonical, TIMESTAMP_HEADER } from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import { FleetDurableObject } from "../../src/state/durable";
import { MemoryFleetStore } from "../../src/state/memory";
import { saveFleetStore, type FleetSql } from "../../src/state/persist";
import { FLEET_SCHEMA_SQL } from "../../src/state/schema";

const keyHex = "0b".repeat(32);
const digest = "a".repeat(64);
const session = "c".repeat(64);

function validEnv(): Record<string, string> {
  return {
    HMAC_KEY: keyHex,
    FLEET_IDS: "example-fleet",
    TIMESTAMP_WINDOW_MS: "5000",
    NONCE_TTL_MS: "60000",
    LEASE_DURATION_MS: "8000",
    ARCHIVE_EVIDENCE_MAX_AGE_MS: "60000",
    SELECTOR_EVIDENCE_MAX_AGE_MS: "60000",
    HOSTED_TRANSITION_SAFETY_MARGIN_MS: "1000",
  };
}

function sqliteTransaction(db: DatabaseSync, work: () => void): void {
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
}

function sharedSql(): {
  sql: {
    exec(
      query: string,
      ...binds: unknown[]
    ): { toArray: () => Record<string, unknown>[] };
  };
  persist: FleetSql;
  transactionSync: (work: () => void) => void;
  transactionCalls: { count: number };
} {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  const transactionCalls = { count: 0 };
  const persist: FleetSql = {
    run(query: string, ...binds: unknown[]) {
      if (/^(BEGIN|COMMIT|ROLLBACK)\b/i.test(query.trim())) {
        throw new Error("SQL transaction control is unsupported");
      }
      if (binds.length === 0) {
        db.exec(query);
        return;
      }
      db.prepare(query).run(...binds);
    },
    all(query: string, ...binds: unknown[]) {
      return db.prepare(query).all(...binds) as Record<string, unknown>[];
    },
    transaction(work: () => void) {
      sqliteTransaction(db, work);
    },
  };
  return {
    sql: {
      exec(query: string, ...binds: unknown[]) {
        if (/^(BEGIN|COMMIT|ROLLBACK)\b/i.test(query.trim())) {
          throw new Error("SQL transaction control is unsupported");
        }
        const isSelect = /^\s*SELECT/i.test(query);
        if (binds.length === 0) {
          if (isSelect) {
            return { toArray: () => db.prepare(query).all() as Record<string, unknown>[] };
          }
          db.exec(query);
          return { toArray: () => [] };
        }
        const stmt = db.prepare(query);
        if (isSelect) {
          return { toArray: () => stmt.all(...binds) as Record<string, unknown>[] };
        }
        stmt.run(...binds);
        return { toArray: () => [] };
      },
    },
    persist,
    transactionSync(work: () => void) {
      transactionCalls.count += 1;
      sqliteTransaction(db, work);
    },
    transactionCalls,
  };
}

test("overlapping same-sequence heartbeats issue only one lease", async () => {
  const { sql, persist, transactionSync, transactionCalls } = sharedSql();
  const timestamp = new Date().toISOString().replace(/\.\d+Z$/, ".000Z");
  const store = new MemoryFleetStore("example-fleet", { now: () => timestamp });
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
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "self-hosted",
    confirmedRoute: "self-hosted",
    archiveLatched: false,
    archiveObservedAt: timestamp,
    archived: false,
    selectorEvidenceAt: timestamp,
    openQueueRisk: null,
  });
  saveFleetStore(persist, store);

  const durable = new FleetDurableObject(
    { storage: { sql, transactionSync }, id: { name: "example-fleet" } },
    validEnv(),
  );
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 1,
    sessionId: session,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp,
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
    },
  });
  const mac = await signCanonical(
    hexToBytes(keyHex),
    "POST",
    "/v1/heartbeat",
    timestamp,
    body,
  );
  const request = () =>
    new Request("https://worker.example/v1/heartbeat", {
      method: "POST",
      headers: { [TIMESTAMP_HEADER]: timestamp, [MAC_HEADER]: mac },
      body,
    });
  const [first, second] = await Promise.all([
    durable.fetch(request()),
    durable.fetch(request()),
  ]);
  const statuses = [first.status, second.status].sort();
  const bodies = [await first.text(), await second.text()];
  expect(statuses).toEqual([200, 401]);
  expect(bodies.filter((bodyText) => bodyText.includes('"mode":"enabled"'))).toHaveLength(1);
  expect(transactionCalls.count).toBeGreaterThan(0);
});
