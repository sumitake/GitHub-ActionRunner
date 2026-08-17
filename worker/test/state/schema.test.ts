import { expect, test } from "vitest";

import { FleetDurableObject } from "../../src/state/durable";
import { FLEET_SCHEMA_SQL, TABLE_NAMES } from "../../src/state/schema";

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
});

test("durable object applies the six-table schema and never installs alarms", () => {
  const queries: string[] = [];
  const object = new FleetDurableObject({
    storage: {
      sql: {
        exec(query: string) {
          queries.push(query);
        },
      },
    },
  });
  expect(object).toBeInstanceOf(FleetDurableObject);
  expect(queries).toEqual([FLEET_SCHEMA_SQL]);
  expect(FLEET_SCHEMA_SQL.includes("setAlarm")).toBe(false);
});
