import { expect, test } from "vitest";

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
