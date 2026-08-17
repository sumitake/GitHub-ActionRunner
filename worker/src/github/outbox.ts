import { assertTransition, type PersistedRouting } from "../routing/machine";
import type { RoutingState } from "../protocol/messages";
import type { DueWorkRecord, MemoryFleetStore } from "../state/memory";

export type GitHubResult = {
  status: number;
  retryAfterMs?: number;
  body?: string;
  runId?: string;
};

export type GitHubClient = {
  mutateVariable(
    name: string,
    value: string,
    signal?: AbortSignal,
  ): Promise<GitHubResult>;
  readVariable(name: string, signal?: AbortSignal): Promise<GitHubResult>;
  dispatchCanary(signal?: AbortSignal): Promise<GitHubResult>;
  observeCanary(runId: string, signal?: AbortSignal): Promise<GitHubResult>;
};

export function persistHostedTransition(
  store: MemoryFleetStore,
  now: string,
): void {
  const from = store.fleet.routingState;
  assertTransition(from, "HOSTED");
  store.transitions.push({
    epoch: store.fleet.leaseGeneration,
    from,
    to: "HOSTED",
  });
  store.fleet.leaseGeneration += 1;
  store.enqueue({
    id: `route-${store.fleet.leaseGeneration}`,
    kind: "github-mutate-route",
    dueAt: now,
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: { name: "PORTABLE_GHAR_ROUTE", value: "hosted" },
  });
}

export function persistCanary(
  store: MemoryFleetStore,
  now: string,
  next: Extract<RoutingState, "PORTABLE_CANARY" | "LEGACY_CANARY">,
): void {
  assertTransition(store.fleet.routingState, next);
  store.transitions.push({
    epoch: store.fleet.leaseGeneration,
    from: store.fleet.routingState,
    to: next,
  });
  store.fleet.routingState = next;
  store.fleet.canaryPassed = false;
  failPendingCanaryWork(store);
  store.enqueue({
    id: `canary-${store.fleet.leaseGeneration}`,
    kind: "canary-dispatch",
    dueAt: now,
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: { workflow: "canary.yml" },
  });
}

export function abortCanary(store: MemoryFleetStore): void {
  const from = store.fleet.routingState;
  if (from !== "PORTABLE_CANARY" && from !== "LEGACY_CANARY") {
    throw new Error("canary abort requires a canary state");
  }
  assertTransition(from, "DRAINING_TO_HOSTED");
  store.fleet.leaseGeneration += 1;
  store.fleet.routingState = "DRAINING_TO_HOSTED";
  store.fleet.canaryPassed = false;
  failPendingCanaryWork(store);
  store.recordAudit("canary-aborted-drain");
}

export function classifyGitHub(
  result: GitHubResult,
): "ok" | "retry" | "ambiguous" | "permanent" {
  if (result.status === 200 || result.status === 201 || result.status === 204) {
    return "ok";
  }
  if (result.status === 404 || result.status === 422) {
    return "permanent";
  }
  if (result.status === 429 || result.status === 0) {
    return "retry";
  }
  return "ambiguous";
}

export async function executeDueWork(
  store: MemoryFleetStore,
  client: GitHubClient,
  batch: DueWorkRecord[],
  signal?: AbortSignal,
): Promise<void> {
  for (const row of batch) {
    throwIfAborted(signal);
    if (row.kind === "notify-email" || row.kind === "notify-webhook") {
      row.status = "failed";
      store.recordAudit(`notify-failed:${row.kind}`);
      continue;
    }
    if (row.kind === "canary-dispatch") {
      await settleCanaryDispatch(store, client, row, signal);
      continue;
    }
    if (row.kind === "canary-observe") {
      await settleCanaryObserve(store, client, row, signal);
      continue;
    }
    if (row.kind === "github-mutate-route") {
      const result = await client.mutateVariable(
        row.payload.name ?? "",
        row.payload.value ?? "",
        signal,
      );
      const classed = classifyGitHub(result);
      if (classed === "ok") {
        const read = await client.readVariable(row.payload.name ?? "", signal);
        if (classifyGitHub(read) === "ok" && read.body === row.payload.value) {
          row.status = "done";
          completeRoute(store, row.payload.value);
          continue;
        }
        releaseClaim(row);
        continue;
      }
      if (classed === "permanent") {
        row.status = "failed";
        continue;
      }
      releaseClaim(row);
    }
  }
}

async function settleCanaryDispatch(
  store: MemoryFleetStore,
  client: GitHubClient,
  row: DueWorkRecord,
  signal?: AbortSignal,
): Promise<void> {
  const result = await client.dispatchCanary(signal);
  const classed = classifyGitHub(result);
  if (classed === "ok" && result.runId) {
    row.status = "done";
    enqueueCanaryObserve(store, row.dueAt, result.runId);
    store.recordAudit("canary-dispatched");
    return;
  }
  if (classed === "ok") {
    row.status = "failed";
    store.recordAudit("canary-dispatch-missing-run");
    return;
  }
  if (classed === "permanent") {
    row.status = "failed";
    return;
  }
  releaseClaim(row);
}

async function settleCanaryObserve(
  store: MemoryFleetStore,
  client: GitHubClient,
  row: DueWorkRecord,
  signal?: AbortSignal,
): Promise<void> {
  const runId = row.payload.runId ?? "";
  const result = await client.observeCanary(runId, signal);
  if (
    classifyGitHub(result) === "ok" &&
    runId !== "" &&
    result.runId === runId &&
    canaryObservationPassed(result.body)
  ) {
    row.status = "done";
    store.fleet.canaryPassed = true;
    store.recordAudit("canary-passed");
    return;
  }
  if (classifyGitHub(result) === "permanent") {
    row.status = "failed";
    return;
  }
  releaseClaim(row);
}

function canaryObservationPassed(body: string | undefined): boolean {
  return (
    body === "pass" ||
    body === "success" ||
    body === "runner.environment=self-hosted"
  );
}

function enqueueCanaryObserve(
  store: MemoryFleetStore,
  now: string,
  runId: string,
): void {
  const pending = store.dueWork.some(
    (row) =>
      row.kind === "canary-observe" &&
      row.payload.runId === runId &&
      (row.status === "ready" || row.status === "claimed"),
  );
  if (pending) {
    return;
  }
  store.enqueue({
    id: `canary-observe-${store.fleet.leaseGeneration}`,
    kind: "canary-observe",
    dueAt: now,
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {
      workflow: "canary.yml",
      runId,
      generation: String(store.fleet.leaseGeneration),
    },
  });
}

function failPendingCanaryWork(store: MemoryFleetStore): void {
  for (const row of store.dueWork) {
    if (
      (row.kind === "canary-dispatch" || row.kind === "canary-observe") &&
      (row.status === "ready" || row.status === "claimed")
    ) {
      row.status = "failed";
      row.claimId = null;
      row.claimExpiresAt = null;
    }
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new Error("due-work aborted");
  }
}

function releaseClaim(row: DueWorkRecord): void {
  row.status = "ready";
  row.claimId = null;
  row.claimExpiresAt = null;
}

function completeRoute(
  store: MemoryFleetStore,
  value: string | undefined,
): void {
  if (value === "hosted") {
    completeHosted(store);
    return;
  }
  if (
    value === "self-hosted" &&
    store.fleet.routingState === "PORTABLE_CANARY"
  ) {
    assertTransition("PORTABLE_CANARY", "PORTABLE");
    store.transitions.push({
      epoch: store.fleet.leaseGeneration,
      from: "PORTABLE_CANARY",
      to: "PORTABLE",
    });
    store.fleet.routingState = "PORTABLE";
    store.recordAudit("canary-promoted-portable");
    return;
  }
  if (value === "legacy" && store.fleet.routingState === "LEGACY_CANARY") {
    assertTransition("LEGACY_CANARY", "LEGACY");
    store.transitions.push({
      epoch: store.fleet.leaseGeneration,
      from: "LEGACY_CANARY",
      to: "LEGACY",
    });
    store.fleet.routingState = "LEGACY";
    store.recordAudit("canary-promoted-legacy");
  }
}

function completeHosted(store: MemoryFleetStore): void {
  const from = store.fleet.routingState;
  if (from === "UNINITIALIZED" || from === "DRAINING_TO_HOSTED") {
    store.fleet.routingState = "HOSTED";
  }
}

export function bootstrapRequiresHostedReadback(
  from: PersistedRouting,
): boolean {
  return from === "UNINITIALIZED";
}
