import { expect, test } from "vitest";

import {
  abortCanary,
  classifyGitHub,
  executeDueWork,
  persistCanary,
  persistHostedTransition,
} from "../../src/github/outbox";
import { MemoryFleetStore } from "../../src/state/memory";

test("canary abort reuses draining-to-hosted and does not mutate GitHub", () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "HOSTED";
  persistCanary(store, "2026-01-01T00:00:00.000Z", "PORTABLE_CANARY");
  abortCanary(store);
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(store.dueWork.some((row) => row.kind === "github-mutate-route")).toBe(
    false,
  );
});

test("GitHub classification and hosted read-back are required for success", async () => {
  expect(classifyGitHub({ status: 429 })).toBe("retry");
  expect(classifyGitHub({ status: 404 })).toBe("permanent");
  expect(classifyGitHub({ status: 0 })).toBe("retry");
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  persistHostedTransition(store, "2026-01-01T00:00:00.000Z");
  const batch = store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000);
  await executeDueWork(
    store,
    {
      mutateVariable: async () => ({ status: 200 }),
      readVariable: async () => ({ status: 200, body: "hosted" }),
      dispatchCanary: async () => ({ status: 200 }),
      observeCanary: async () => ({ status: 200, body: "pass" }),
    },
    batch,
  );
  expect(store.fleet.routingState).toBe("HOSTED");
});
