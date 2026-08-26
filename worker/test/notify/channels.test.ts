import { expect, test } from "vitest";

import {
  deliverNotifications,
  enqueueNotifications,
} from "../../src/notify/channels";
import { MemoryFleetStore } from "../../src/state/memory";

test("notification failure is independent of routing state", () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.routingState = "HOSTED";
  enqueueNotifications(
    store,
    {
      eventId: "evt-1",
      transitionId: "tr-1",
      displayName: "example fleet",
      repositoryAliases: ["repo-a"],
      confirmedRoute: "hosted",
      reasonCode: "HOSTED_HOLD",
      receiptTime: "2026-01-01T00:00:00.000Z",
      operatorAction: "acknowledge",
    },
    "2026-01-01T00:00:00.000Z",
  );
  const batch = store.claimReady("2026-01-01T00:00:00.000Z", 8, 5_000);
  deliverNotifications(
    store,
    batch,
    new Set(["notify-email", "notify-webhook"]),
  );
  expect(store.fleet.routingState).toBe("HOSTED");
  expect(batch.every((row) => row.status === "failed")).toBe(true);
});
