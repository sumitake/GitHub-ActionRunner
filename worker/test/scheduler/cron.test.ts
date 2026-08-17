import { expect, test } from "vitest";

import {
  assertNoDurableObjectAlarms,
  runCronTick,
  validateFleetInventory,
} from "../../src/scheduler/cron";
import { MemoryFleetStore } from "../../src/state/memory";

test("cron inventory rejects duplicates, empty, and oversized lists", () => {
  expect(() =>
    validateFleetInventory({ revision: "1", digest: "a", fleetIds: [] }, 2),
  ).toThrow();
  expect(() =>
    validateFleetInventory(
      {
        revision: "1",
        digest: "a",
        fleetIds: ["example-fleet", "example-fleet"],
      },
      2,
    ),
  ).toThrow();
  expect(() =>
    validateFleetInventory(
      { revision: "1", digest: "a", fleetIds: ["one", "two", "three"] },
      2,
    ),
  ).toThrow();
  expect(
    validateFleetInventory(
      { revision: "1", digest: "a", fleetIds: ["example-fleet"] },
      2,
    ),
  ).toEqual(["example-fleet"]);
});

test("cron addresses every configured fleet and does not use alarms", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.enqueue({
    id: "due-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {},
  });
  const result = await runCronTick(
    { revision: "1", digest: "a", fleetIds: ["example-fleet"] },
    4,
    new Map([["example-fleet", store]]),
    1_000,
    () => "2026-01-01T00:00:00.000Z",
    async (next, batch) => {
      expect(next.fleet.fleetId).toBe("example-fleet");
      expect(batch).toHaveLength(1);
    },
  );
  expect(result.addressed).toEqual(["example-fleet"]);
  expect(() => assertNoDurableObjectAlarms("const ok = true;")).not.toThrow();
  expect(() =>
    assertNoDurableObjectAlarms("await this.ctx.storage.setAlarm(1);"),
  ).toThrow();
});
