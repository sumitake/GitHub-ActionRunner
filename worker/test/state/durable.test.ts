import { DatabaseSync } from "node:sqlite";
import { expect, test } from "vitest";

import {
  hexToBytes,
  MAC_HEADER,
  signCronRequest,
  signCanonical,
  TIMESTAMP_HEADER,
  verifyCronResponse,
} from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import {
  ADDRESS_STATUS_PATH,
  ADDRESS_STATUS_PROTOCOL_VERSION,
  parseAddressStatusResponse,
  signAddressStatusRequest,
  verifyAddressStatusResponse,
  type AddressStatusRequestV1,
} from "../../src/protocol/address-status";
import {
  CRON_ADDRESS_PROTOCOL_VERSION,
  CRON_PATH,
  parseCronAddressResponse,
} from "../../src/protocol/cron";
import { FleetDurableObject } from "../../src/state/durable";
import { MemoryFleetStore } from "../../src/state/memory";
import { saveFleetStore, type FleetSql } from "../../src/state/persist";
import { FLEET_SCHEMA_SQL, TABLE_NAMES } from "../../src/state/schema";

const keyHex = "0b".repeat(32);
const digest = "a".repeat(64);
const session = "c".repeat(64);
const cronKeyHex = "0c".repeat(32);
const cronDigest =
  "6a9aedffdae5b07550af1921963f6aa007cf4d6425762e0b30afa8ac7cbed91d";

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

function validCronEnv(): Record<string, string> {
  return {
    ...validEnv(),
    CRON_HMAC_KEY: cronKeyHex,
    FLEET_IDS: "alpha,beta",
    MAX_FLEETS: "2",
    PER_FLEET_DEADLINE_MS: "25",
    CRON_BUDGET_OVERHEAD_MS: "25",
    CRON_TICK_BUDGET_MS: "75",
    FLEET_INVENTORY_REVISION: "1",
    FLEET_INVENTORY_DIGEST: cronDigest,
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
  db: DatabaseSync;
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
    db,
    sql: {
      exec(query: string, ...binds: unknown[]) {
        if (/^(BEGIN|COMMIT|ROLLBACK)\b/i.test(query.trim())) {
          throw new Error("SQL transaction control is unsupported");
        }
        const isSelect = /^\s*(?:SELECT|PRAGMA)/i.test(query);
        if (binds.length === 0) {
          if (isSelect) {
            return {
              toArray: () =>
                db.prepare(query).all() as Record<string, unknown>[],
            };
          }
          db.exec(query);
          return { toArray: () => [] };
        }
        const stmt = db.prepare(query);
        if (isSelect) {
          return {
            toArray: () => stmt.all(...binds) as Record<string, unknown>[],
          };
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

function durableSnapshot(db: DatabaseSync): Record<string, unknown[]> {
  return Object.fromEntries(
    TABLE_NAMES.map((table) => [
      table,
      db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all(),
    ]),
  );
}

async function cronRequest(
  overrides: Partial<Record<string, unknown>> = {},
): Promise<Request> {
  const tickTimestamp = "2026-01-01T00:00:00.000Z";
  const value = {
    protocolVersion: CRON_ADDRESS_PROTOCOL_VERSION,
    fleetId: "alpha",
    fleetIds: ["alpha", "beta"],
    revision: "1",
    inventoryDigest: cronDigest,
    nonce: "1".repeat(64),
    tickTimestamp,
    deadline: "2026-01-01T00:00:00.025Z",
    ...overrides,
  };
  const body = canonicalize(value);
  const mac = await signCronRequest(
    hexToBytes(cronKeyHex),
    "POST",
    CRON_PATH,
    tickTimestamp,
    body,
  );
  return new Request(`https://fleet.internal${CRON_PATH}`, {
    method: "POST",
    headers: { [TIMESTAMP_HEADER]: tickTimestamp, [MAC_HEADER]: mac },
    body,
  });
}

async function statusRequest(
  overrides: Partial<AddressStatusRequestV1> = {},
): Promise<{ request: Request; value: AddressStatusRequestV1 }> {
  const value: AddressStatusRequestV1 = {
    protocolVersion: ADDRESS_STATUS_PROTOCOL_VERSION,
    fleetId: "alpha",
    nonce: "2".repeat(64),
    requestTime: "2026-01-01T00:00:00.020Z",
    inventoryRevision: "1",
    inventoryDigest: cronDigest,
    ...overrides,
  };
  const body = canonicalize(value);
  const mac = await signAddressStatusRequest(
    hexToBytes(cronKeyHex),
    value.requestTime,
    body,
  );
  return {
    value,
    request: new Request(`https://fleet.internal${ADDRESS_STATUS_PATH}`, {
      method: "POST",
      headers: { [TIMESTAMP_HEADER]: value.requestTime, [MAC_HEADER]: mac },
      body,
    }),
  };
}

test("address-only Durable Object rejects direct heartbeat authority without mutation", async () => {
  const { db, sql, persist, transactionSync } = sharedSql();
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
    archiveEligibility: "active",
    archivePolicyRevision: null,
    archiveObservedAt: timestamp,
    archived: false,
    selectorEvidenceAt: timestamp,
    openQueueRisk: null,
  });
  saveFleetStore(persist, store);
  const before = durableSnapshot(db);

  const durable = new FleetDurableObject(
    {
      storage: { sql, transactionSync },
      id: { name: "example-fleet" },
      blockConcurrencyWhile: async (work) => work(),
    },
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
  expect(statuses).toEqual([401, 401]);
  expect(bodies.every((bodyText) => !bodyText.includes("lease"))).toBe(true);
  expect(durableSnapshot(db)).toEqual(before);
});

test("internal Cron address persists a signed inert receipt only", async () => {
  const { db, sql, transactionSync } = sharedSql();
  const durable = new FleetDurableObject(
    {
      storage: { sql, transactionSync },
      id: { name: "alpha" },
      blockConcurrencyWhile: async (work) => work(),
    },
    validCronEnv(),
    () => "2026-01-01T00:00:00.010Z",
  );

  const response = await durable.fetch(await cronRequest());

  expect(response.status).toBe(200);
  const responseTimestamp = response.headers.get(TIMESTAMP_HEADER) ?? "";
  const responseMac = response.headers.get(MAC_HEADER) ?? "";
  const responseBody = await response.text();
  await verifyCronResponse(
    hexToBytes(cronKeyHex),
    "POST",
    CRON_PATH,
    responseTimestamp,
    responseBody,
    responseMac,
  );
  expect(parseCronAddressResponse(responseBody)).toMatchObject({
    fleetId: "alpha",
    revision: "1",
    inventoryDigest: cronDigest,
    nonce: "1".repeat(64),
    tickTimestamp: "2026-01-01T00:00:00.000Z",
    deadline: "2026-01-01T00:00:00.025Z",
    receiptTime: "2026-01-01T00:00:00.010Z",
    persistenceGeneration: 1,
  });
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
    cron_inventory_digest: cronDigest,
    cron_tick_timestamp: "2026-01-01T00:00:00.000Z",
    cron_tick_nonce: "1".repeat(64),
    cron_addressed_at: "2026-01-01T00:00:00.010Z",
    persistence_generation: 1,
  });
  for (const table of [
    "repositories",
    "transitions",
    "due_work",
    "audit_events",
  ]) {
    expect(db.prepare(`SELECT * FROM ${table}`).all()).toEqual([]);
  }
});

test("internal Cron rejects replay, object mismatch, and stale deadline without writes", async () => {
  for (const scenario of [
    {
      name: "object mismatch",
      objectName: "beta",
      clock: () => "2026-01-01T00:00:00.010Z",
    },
    {
      name: "stale deadline",
      objectName: "alpha",
      clock: () => "2026-01-01T00:00:00.026Z",
    },
  ]) {
    const { db, sql, transactionSync } = sharedSql();
    const durable = new FleetDurableObject(
      {
        storage: { sql, transactionSync },
        id: { name: scenario.objectName },
        blockConcurrencyWhile: async (work) => work(),
      },
      validCronEnv(),
      scenario.clock,
    );
    const response = await durable.fetch(await cronRequest());
    expect(response.status, scenario.name).toBe(401);
    expect(db.prepare("SELECT * FROM fleet_state").all()).toEqual([]);
    expect(db.prepare("SELECT * FROM request_nonces").all()).toEqual([]);
  }

  const { db, sql, transactionSync } = sharedSql();
  const durable = new FleetDurableObject(
    {
      storage: { sql, transactionSync },
      id: { name: "alpha" },
      blockConcurrencyWhile: async (work) => work(),
    },
    validCronEnv(),
    () => "2026-01-01T00:00:00.010Z",
  );
  expect((await durable.fetch(await cronRequest())).status).toBe(200);
  expect((await durable.fetch(await cronRequest())).status).toBe(401);
  expect(
    db.prepare("SELECT persistence_generation FROM fleet_state").get(),
  ).toEqual({ persistence_generation: 1 });
});

test("internal Cron rechecks deadline immediately before receipt transaction", async () => {
  const { db, sql, transactionSync } = sharedSql();
  const times = ["2026-01-01T00:00:00.010Z", "2026-01-01T00:00:00.026Z"];
  const durable = new FleetDurableObject(
    {
      storage: { sql, transactionSync },
      id: { name: "alpha" },
      blockConcurrencyWhile: async (work) => work(),
    },
    validCronEnv(),
    () => times.shift() ?? "2026-01-01T00:00:00.026Z",
  );

  const response = await durable.fetch(await cronRequest());

  expect(response.status).toBe(401);
  expect(db.prepare("SELECT * FROM fleet_state").all()).toEqual([]);
  expect(db.prepare("SELECT * FROM request_nonces").all()).toEqual([]);
});

test("signed address-status reads the committed inert Cron receipt", async () => {
  const { db, sql, transactionSync, transactionCalls } = sharedSql();
  let now = "2026-01-01T00:00:00.010Z";
  const env = {
    ...validCronEnv(),
    LEASE_DURATION_MS: "invalid",
    ARCHIVE_EVIDENCE_MAX_AGE_MS: "invalid",
    SELECTOR_EVIDENCE_MAX_AGE_MS: "invalid",
    HOSTED_TRANSITION_SAFETY_MARGIN_MS: "invalid",
  };
  const durable = new FleetDurableObject(
    {
      storage: { sql, transactionSync },
      id: { name: "alpha" },
      blockConcurrencyWhile: async (work) => work(),
    },
    env,
    () => now,
  );
  expect((await durable.fetch(await cronRequest())).status).toBe(200);
  const beforeGeneration = db
    .prepare("SELECT persistence_generation FROM fleet_state")
    .get();
  const beforeTransactions = transactionCalls.count;
  now = "2026-01-01T00:00:00.020Z";
  const signed = await statusRequest();

  const response = await durable.fetch(signed.request);

  expect(response.status).toBe(200);
  const responseTimestamp = response.headers.get(TIMESTAMP_HEADER) ?? "";
  const responseMac = response.headers.get(MAC_HEADER) ?? "";
  const body = await response.text();
  const parsed = await verifyAddressStatusResponse({
    key: hexToBytes(cronKeyHex),
    body,
    headerTimestamp: responseTimestamp,
    macHex: responseMac,
    observedAt: now,
    timestampWindowMs: 5_000,
    request: signed.value,
  });
  expect(parseAddressStatusResponse(body)).toEqual(parsed);
  expect(parsed).toMatchObject({
    status: "inert-receipt",
    fleetId: "alpha",
    inventoryRevision: "1",
    inventoryDigest: cronDigest,
    tickTimestamp: "2026-01-01T00:00:00.000Z",
    receiptTime: "2026-01-01T00:00:00.010Z",
    persistenceGeneration: 1,
    inventoried: false,
    holder: "none",
    maxCapacity: 0,
    routingState: "UNINITIALIZED",
  });
  expect(transactionCalls.count).toBe(beforeTransactions + 1);
  expect(
    db.prepare("SELECT persistence_generation FROM fleet_state").get(),
  ).toEqual(beforeGeneration);
});

test("address-status replay and widened request semantics fail closed", async () => {
  const { db, sql, transactionSync } = sharedSql();
  let now = "2026-01-01T00:00:00.010Z";
  const durable = new FleetDurableObject(
    {
      storage: { sql, transactionSync },
      id: { name: "alpha" },
      blockConcurrencyWhile: async (work) => work(),
    },
    validCronEnv(),
    () => now,
  );
  expect((await durable.fetch(await cronRequest())).status).toBe(200);
  now = "2026-01-01T00:00:00.020Z";
  const first = await statusRequest();
  expect((await durable.fetch(first.request)).status).toBe(200);
  const afterSuccess = durableSnapshot(db);

  const replay = await statusRequest();
  expect((await durable.fetch(replay.request)).status).toBe(401);
  expect(durableSnapshot(db)).toEqual(afterSuccess);

  for (const request of [
    new Request(`https://fleet.internal${ADDRESS_STATUS_PATH}?query=1`, {
      method: "POST",
      body: "{}",
    }),
    new Request(`https://fleet.internal${ADDRESS_STATUS_PATH}`, {
      method: "GET",
    }),
    new Request(`https://fleet.internal${ADDRESS_STATUS_PATH}`, {
      method: "POST",
      headers: {
        [TIMESTAMP_HEADER]: now,
        [MAC_HEADER]: "0".repeat(64),
      },
      body: "x".repeat(65_537),
    }),
  ]) {
    expect((await durable.fetch(request)).status).toBe(401);
    expect(durableSnapshot(db)).toEqual(afterSuccess);
  }
});
