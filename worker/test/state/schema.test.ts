import { DatabaseSync } from "node:sqlite";
import { expect, test } from "vitest";

import { FleetDurableObject } from "../../src/state/durable";
import { FLEET_SCHEMA_SQL, TABLE_NAMES } from "../../src/state/schema";

const CRON_RECEIPT_COLUMNS = [
  "cron_inventory_revision",
  "cron_inventory_digest",
  "cron_tick_timestamp",
  "cron_tick_nonce",
  "cron_addressed_at",
] as const;
const SELECTOR_COMPANION_COLUMNS = [
  "expected_scale_set",
  "confirmed_scale_set",
  "expected_legacy_label",
  "confirmed_legacy_label",
] as const;

const LEGACY_SCHEMA_SQL = FLEET_SCHEMA_SQL.replace(/^  cron_[^\n]+\n/gm, "")
  .replace(
    /,\n  persistence_generation INTEGER NOT NULL(?: DEFAULT 1)?\n/,
    "\n",
  )
  .replace(/^  archive_policy_revision[^\n]+\n/gm, "")
  .replace(
    /^  (?:expected|confirmed)_(?:scale_set|legacy_label)[^\n]+\n/gm,
    "",
  );

function storageFor(
  db: DatabaseSync,
  options: { failPostMigrationReadback?: boolean } = {},
) {
  let pragmaReads = 0;
  let initialization: Promise<unknown> = Promise.resolve();
  return {
    get initialization() {
      return initialization;
    },
    blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T> {
      const result = callback();
      initialization = result;
      return result;
    },
    storage: {
      sql: {
        exec(query: string, ...binds: unknown[]) {
          const select = /^\s*(?:SELECT|PRAGMA)/i.test(query);
          if (/^\s*PRAGMA\s+table_info/i.test(query)) {
            pragmaReads += 1;
            if (options.failPostMigrationReadback && pragmaReads === 2) {
              throw new Error("migration read-back failed");
            }
          }
          if (binds.length === 0 && !select) {
            db.exec(query);
            return { toArray: () => [] };
          }
          const statement = db.prepare(query);
          if (select) {
            return {
              toArray: () =>
                statement.all(...binds) as Record<string, unknown>[],
            };
          }
          statement.run(...binds);
          return { toArray: () => [] };
        },
      },
      transactionSync(work: () => void) {
        db.exec("BEGIN IMMEDIATE");
        try {
          work();
          db.exec("COMMIT");
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      },
    },
  };
}

function columnNames(db: DatabaseSync): string[] {
  return (
    db.prepare("PRAGMA table_info(fleet_state)").all() as Array<{
      name: string;
    }>
  ).map((row) => row.name);
}

function repositoryColumnNames(db: DatabaseSync): string[] {
  return (
    db.prepare("PRAGMA table_info(repositories)").all() as Array<{
      name: string;
    }>
  ).map((row) => row.name);
}

function createLegacyFleet(db: DatabaseSync, populated: boolean): void {
  db.exec(LEGACY_SCHEMA_SQL);
  if (!populated) {
    return;
  }
  db.exec(`INSERT INTO fleet_state (
    fleet_id, inventoried, epoch, session_id, sequence, lease_generation,
    last_issued_lease_expiry_max, lease_not_before, holder, fence_generation,
    routing_state, hosted_hold, config_revision, policy_digest, max_capacity,
    canary_scale_set, canary_passed
  ) VALUES (
    'example-fleet', 0, 0, NULL, 0, 1, NULL, NULL, 'none', 0,
    'UNINITIALIZED', 0, 0, NULL, 0, NULL, 0
  )`);
}

test("schema defines exactly the six responsibility tables", () => {
  expect(TABLE_NAMES).toEqual([
    "fleet_state",
    "request_nonces",
    "repositories",
    "transitions",
    "due_work",
    "audit_events",
  ]);
  for (const table of TABLE_NAMES) {
    expect(FLEET_SCHEMA_SQL).toContain(`CREATE TABLE IF NOT EXISTS ${table}`);
  }
  expect(FLEET_SCHEMA_SQL).not.toContain("CREATE TABLE IF NOT EXISTS alarm");
  expect(columnNamesFromSchema()).toEqual(
    expect.arrayContaining(CRON_RECEIPT_COLUMNS),
  );
});

function columnNamesFromSchema(): string[] {
  const db = new DatabaseSync(":memory:");
  db.exec(FLEET_SCHEMA_SQL);
  return columnNames(db);
}

test("durable object applies the six-table schema and never installs alarms", () => {
  const db = new DatabaseSync(":memory:");
  const object = new FleetDurableObject(storageFor(db));
  expect(object).toBeInstanceOf(FleetDurableObject);
  expect(columnNames(db)).toContain("persistence_generation");
  expect(FLEET_SCHEMA_SQL.includes("setAlarm")).toBe(false);
});

test("legacy fleet schema upgrades all receipt columns idempotently", () => {
  for (const populated of [false, true]) {
    const db = new DatabaseSync(":memory:");
    createLegacyFleet(db, populated);
    const context = storageFor(db);

    new FleetDurableObject(context);
    new FleetDurableObject(context);

    for (const name of ["persistence_generation", ...CRON_RECEIPT_COLUMNS]) {
      expect(columnNames(db).filter((column) => column === name)).toHaveLength(
        1,
      );
    }
    const rows = db
      .prepare(
        `SELECT persistence_generation, cron_inventory_revision,
          cron_inventory_digest, cron_tick_timestamp, cron_tick_nonce,
          cron_addressed_at FROM fleet_state`,
      )
      .all();
    expect(rows).toEqual(
      populated
        ? [
            {
              persistence_generation: 1,
              cron_inventory_revision: null,
              cron_inventory_digest: null,
              cron_tick_timestamp: null,
              cron_tick_nonce: null,
              cron_addressed_at: null,
            },
          ]
        : [],
    );
  }
});

test("legacy repository schema adds one archive policy revision idempotently", () => {
  const db = new DatabaseSync(":memory:");
  createLegacyFleet(db, true);
  expect(repositoryColumnNames(db)).not.toContain("archive_policy_revision");

  const context = storageFor(db);
  new FleetDurableObject(context);
  new FleetDurableObject(context);

  expect(
    repositoryColumnNames(db).filter(
      (column) => column === "archive_policy_revision",
    ),
  ).toHaveLength(1);
});

test("legacy repository schema adds exactly four selector companion columns idempotently", () => {
  const db = new DatabaseSync(":memory:");
  createLegacyFleet(db, true);
  for (const name of SELECTOR_COMPANION_COLUMNS) {
    expect(repositoryColumnNames(db)).not.toContain(name);
  }

  const context = storageFor(db);
  new FleetDurableObject(context);
  new FleetDurableObject(context);

  for (const name of SELECTOR_COMPANION_COLUMNS) {
    expect(
      repositoryColumnNames(db).filter((column) => column === name),
    ).toHaveLength(1);
  }
  expect(
    db
      .prepare(
        `SELECT expected_scale_set, confirmed_scale_set,
          expected_legacy_label, confirmed_legacy_label
        FROM repositories`,
      )
      .all(),
  ).toEqual([]);
});

test("legacy schema migration rolls back if post-migration verification fails", async () => {
  const db = new DatabaseSync(":memory:");
  createLegacyFleet(db, true);
  const context = storageFor(db, { failPostMigrationReadback: true });

  new FleetDurableObject(context);
  await expect(context.initialization).rejects.toThrow(
    "migration read-back failed",
  );

  expect(columnNames(db)).not.toContain("persistence_generation");
  for (const name of CRON_RECEIPT_COLUMNS) {
    expect(columnNames(db)).not.toContain(name);
  }
  for (const name of SELECTOR_COMPANION_COLUMNS) {
    expect(repositoryColumnNames(db)).not.toContain(name);
  }
  expect(db.prepare("SELECT fleet_id FROM fleet_state").all()).toEqual([
    { fleet_id: "example-fleet" },
  ]);
});
