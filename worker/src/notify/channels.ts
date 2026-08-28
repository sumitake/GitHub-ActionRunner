import type { DueWorkRecord, MemoryFleetStore } from "../state/memory";

export type NotificationEvent = {
  eventId: string;
  transitionId: string;
  displayName: string;
  repositoryAliases: string[];
  confirmedRoute: "hosted" | "self-hosted" | "legacy";
  reasonCode: string;
  receiptTime: string;
  operatorAction:
    "none" | "acknowledge" | "escalate" | "retry" | "rollback" | "suppress";
};

export function enqueueNotifications(
  store: MemoryFleetStore,
  event: NotificationEvent,
  now: string,
): void {
  store.enqueue({
    id: `email-${event.eventId}`,
    kind: "notify-email",
    dueAt: now,
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: { eventId: event.eventId },
  });
  store.enqueue({
    id: `webhook-${event.eventId}`,
    kind: "notify-webhook",
    dueAt: now,
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: { eventId: event.eventId },
  });
}

export function deliverNotifications(
  store: MemoryFleetStore,
  batch: DueWorkRecord[],
  fail: Set<string>,
): void {
  for (const row of batch) {
    if (row.kind !== "notify-email" && row.kind !== "notify-webhook") {
      continue;
    }
    if (fail.has(row.kind)) {
      row.status = "failed";
      row.claimId = null;
      row.claimExpiresAt = null;
      store.recordAudit(`${row.kind}-failed`);
      continue;
    }
    row.status = "done";
    row.claimId = null;
    row.claimExpiresAt = null;
  }
}
