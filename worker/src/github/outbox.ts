import { assertTransition, type PersistedRouting } from "../routing/machine";
import type { RoutingState } from "../protocol/messages";
import {
  decodeQueueRecoveryExpectation,
  evaluateQueueRecoveryObservation,
  type QueueRecoveryExpectation,
} from "../protocol/admin";
import {
  archiveEvidenceState,
  decodeArchiveExpectation,
  encodeArchiveExpectation,
  evaluateArchiveObservation,
  type ArchiveExpectation,
  type ArchiveSweepExpectation,
} from "../routing/archive";
import {
  decodeCanaryExpectation,
  encodeCanaryEvidence,
  encodeCanaryExpectation,
  evaluateCanaryObservation,
  type CanaryExpectation,
} from "../routing/canary";
import {
  nextTransitionRecord,
  isGitHubMutation,
  type DueWorkRecord,
  type MemoryFleetStore,
  type RepositoryRecord,
} from "../state/memory";
import {
  isSelectorScalar,
  selectorRestrictionReason,
} from "../routing/selector";

export type GitHubResult = {
  status: number;
  retryAfterMs?: number;
  body?: string;
};

export type GitHubClient = {
  mutateVariable(
    repositoryAlias: string,
    name: string,
    value: string,
    signal?: AbortSignal,
  ): Promise<GitHubResult>;
  readVariable(
    repositoryAlias: string,
    name: string,
    signal?: AbortSignal,
  ): Promise<GitHubResult>;
  observeCanary(
    expectation: CanaryExpectation,
    signal?: AbortSignal,
  ): Promise<GitHubResult>;
  observeQueueRecovery(
    expectation: QueueRecoveryExpectation,
    signal?: AbortSignal,
  ): Promise<GitHubResult>;
  observeArchive(
    expectation: ArchiveExpectation,
    signal?: AbortSignal,
  ): Promise<GitHubResult>;
};

export type CanaryStart = {
  repositoryAlias: string;
  workflow: string;
  revision: string;
  observeUntil: string;
};

export type DueWorkExecutionOptions = {
  hostedTransitionSafetyMarginMs: number;
  archiveEvidenceMaxAgeMs?: number;
  selectorEvidenceMaxAgeMs?: number;
};

export function enqueueArchiveObservation(
  store: MemoryFleetStore,
  now: string,
  repositoryAlias: string,
  observeUntil: string,
): void {
  if (!store.repositories.has(repositoryAlias)) {
    throw new Error("archive repository is unavailable");
  }
  const transitionEpoch = currentTransitionEpoch(store);
  if (transitionEpoch === null) {
    throw new Error("archive transition epoch is unavailable");
  }
  const expectation: ArchiveSweepExpectation = {
    schemaVersion: 1,
    kind: "archive-sweep",
    fleetId: store.fleet.fleetId,
    repositoryAlias,
    configurationRevision: store.fleet.configRevision,
    transitionEpoch,
    observeUntil,
  };
  store.enqueue({
    id: `archive-sweep-${repositoryAlias}-${now}`,
    kind: "archive-observe",
    dueAt: now,
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: encodeArchiveExpectation(expectation),
  });
}

export function enqueueSelectorCompanionMutations(
  store: MemoryFleetStore,
  now: string,
): void {
  if (store.fleet.routingState !== "HOSTED" || store.fleet.configRevision < 1) {
    throw new Error("selector companion production is unavailable");
  }
  const transitionRevision = currentTransitionEpoch(store);
  if (transitionRevision === null) {
    throw new Error("selector companion transition is unavailable");
  }
  const rows: DueWorkRecord[] = [];
  for (const repository of [...store.repositories.values()].sort(
    (left, right) => left.alias.localeCompare(right.alias),
  )) {
    if (
      !isSelectorScalar(repository.expectedScaleSet) ||
      !isSelectorScalar(repository.expectedLegacyLabel)
    ) {
      throw new Error("selector companion expectation is unavailable");
    }
    for (const [kind, name, expected, confirmed] of [
      [
        "github-mutate-scale-set",
        "PORTABLE_GHAR_SCALE_SET",
        repository.expectedScaleSet,
        repository.confirmedScaleSet,
      ],
      [
        "github-mutate-legacy-label",
        "PORTABLE_GHAR_LEGACY_LABEL",
        repository.expectedLegacyLabel,
        repository.confirmedLegacyLabel,
      ],
    ] as const) {
      if (expected === confirmed) {
        continue;
      }
      const effectKey = `${kind}-${store.fleet.configRevision}-${repository.alias}`;
      rows.push({
        id: effectKey,
        kind,
        dueAt: now,
        claimId: null,
        claimExpiresAt: null,
        attempts: 0,
        status: "ready",
        payload: {
          effectKey,
          repositoryAlias: repository.alias,
          name,
          value: expected,
          configurationRevision: String(store.fleet.configRevision),
          transitionRevision: String(transitionRevision),
        },
      });
    }
  }
  enqueueBatchAtomically(store, rows);
}

export function enqueueRepositoryRoutes(
  store: MemoryFleetStore,
  dueAt: string,
  value: "hosted" | "self-hosted" | "legacy",
  transitionRevision: number,
  canaryEvidence?: string,
): void {
  if (!Number.isSafeInteger(transitionRevision) || transitionRevision < 1) {
    throw new Error("route transition revision is invalid");
  }
  const repositories = [...store.repositories.values()].sort((left, right) =>
    left.alias.localeCompare(right.alias),
  );
  if (repositories.length === 0) {
    throw new Error("route repository inventory is empty");
  }
  const rows = repositories.map((repository): DueWorkRecord => {
    const effectKey = `route-${transitionRevision}-${repository.alias}`;
    return {
      id: effectKey,
      kind: "github-mutate-route",
      dueAt,
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: {
        effectKey,
        repositoryAlias: repository.alias,
        name: "PORTABLE_GHAR_ROUTE",
        transitionRevision: String(transitionRevision),
        configurationRevision: String(store.fleet.configRevision),
        value,
        ...(canaryEvidence === undefined ? {} : { canaryEvidence }),
      },
    };
  });
  const previous = repositories.map((repository) => ({
    repository,
    expectedRoute: repository.expectedRoute,
    selectorEvidenceAt: repository.selectorEvidenceAt,
  }));
  try {
    for (const repository of repositories) {
      repository.expectedRoute = value;
      repository.selectorEvidenceAt = null;
    }
    enqueueBatchAtomically(store, rows);
  } catch (error) {
    for (const snapshot of previous) {
      snapshot.repository.expectedRoute = snapshot.expectedRoute;
      snapshot.repository.selectorEvidenceAt = snapshot.selectorEvidenceAt;
    }
    throw error;
  }
}

function enqueueBatchAtomically(
  store: MemoryFleetStore,
  rows: readonly DueWorkRecord[],
): void {
  const start = store.dueWork.length;
  try {
    for (const row of rows) {
      store.enqueue(row);
    }
  } catch (error) {
    store.dueWork.splice(start);
    throw error;
  }
}

export function persistHostedTransition(
  store: MemoryFleetStore,
  now: string,
): void {
  const from = store.fleet.routingState;
  assertTransition(from, "HOSTED");
  const transition = nextTransitionRecord(store, from, "HOSTED");
  const nextGeneration = store.fleet.leaseGeneration + 1;
  if (!Number.isSafeInteger(nextGeneration)) {
    throw new Error("route lease generation is exhausted");
  }
  enqueueRepositoryRoutes(store, now, "hosted", nextGeneration);
  store.transitions.push(transition);
  store.fleet.leaseGeneration = nextGeneration;
}

export function persistCanary(
  store: MemoryFleetStore,
  now: string,
  next: Extract<RoutingState, "PORTABLE_CANARY" | "LEGACY_CANARY">,
  start: CanaryStart,
): void {
  const sessionId = store.fleet.sessionId;
  const scaleSet = store.fleet.canaryScaleSet;
  if (sessionId === null || scaleSet === null) {
    throw new Error("canary identity is unavailable");
  }
  if (
    !Number.isSafeInteger(store.fleet.leaseGeneration) ||
    store.fleet.leaseGeneration < 1 ||
    store.fleet.leaseGeneration > Number.MAX_SAFE_INTEGER - 2
  ) {
    throw new Error("canary lease generation has no abort headroom");
  }
  const expectation: CanaryExpectation = {
    schemaVersion: 1,
    repositoryAlias: start.repositoryAlias,
    workflow: start.workflow,
    revision: start.revision,
    scaleSet,
    environment: "self-hosted",
    startedAt: now,
    observeUntil: start.observeUntil,
    sessionId,
    leaseGeneration: store.fleet.leaseGeneration,
  };
  const payload = encodeCanaryExpectation(expectation);
  assertTransition(store.fleet.routingState, next);
  const transition = nextTransitionRecord(
    store,
    store.fleet.routingState,
    next,
  );
  const work: DueWorkRecord = {
    id: `canary-${store.fleet.leaseGeneration}`,
    kind: "canary-observe",
    dueAt: now,
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload,
  };
  store.enqueue(work);
  store.transitions.push(transition);
  store.fleet.routingState = next;
  store.fleet.canaryEvidence = null;
  failPendingCanaryWork(store, work.id);
}

export function abortCanary(
  store: MemoryFleetStore,
  hostedTransitionSafetyMarginMs: number,
): void {
  const from = store.fleet.routingState;
  if (from !== "PORTABLE_CANARY" && from !== "LEGACY_CANARY") {
    throw new Error("canary abort requires a canary state");
  }
  if (
    !Number.isSafeInteger(hostedTransitionSafetyMarginMs) ||
    hostedTransitionSafetyMarginMs <= 0
  ) {
    throw new Error("hosted transition safety margin is invalid");
  }
  assertTransition(from, "DRAINING_TO_HOSTED");
  const transition = nextTransitionRecord(store, from, "DRAINING_TO_HOSTED");
  const nextLeaseGeneration = store.fleet.leaseGeneration + 1;
  if (!Number.isSafeInteger(nextLeaseGeneration)) {
    throw new Error("canary lease generation is exhausted");
  }
  const dueAt =
    store.fleet.lastIssuedLeaseExpiryMax === null
      ? store.now()
      : addMs(
          store.fleet.lastIssuedLeaseExpiryMax,
          hostedTransitionSafetyMarginMs,
        );
  const boundary: DueWorkRecord = {
    id: `canary-boundary-${nextLeaseGeneration}`,
    kind: "canary-boundary",
    dueAt,
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {
      transitionRevision: String(nextLeaseGeneration),
      from,
    },
  };
  store.enqueue(boundary);
  store.transitions.push(transition);
  store.fleet.leaseGeneration = nextLeaseGeneration;
  store.fleet.routingState = "DRAINING_TO_HOSTED";
  store.fleet.canaryEvidence = null;
  failPendingCanaryWork(store);
  store.recordAudit("canary-aborted-drain");
}

export function classifyGitHub(
  result: GitHubResult,
): "ok" | "retry" | "ambiguous" | "permanent" {
  if (result.status === 200 || result.status === 201 || result.status === 204) {
    return "ok";
  }
  if (result.status === 404) {
    return "permanent";
  }
  if (result.status === 429) {
    return "retry";
  }
  if (result.status === 0) {
    return "ambiguous";
  }
  return "ambiguous";
}

export async function executeDueWork(
  store: MemoryFleetStore,
  client: GitHubClient,
  batch: DueWorkRecord[],
  signal?: AbortSignal,
  options?: DueWorkExecutionOptions,
): Promise<void> {
  const claims = batch.map(snapshotClaim);
  ensureUncertainMutationReadbacks(store);
  for (const claim of claims) {
    throwIfAborted(signal);
    const row = resolveClaimedWork(store, claim);
    if (row === undefined) {
      continue;
    }
    if (row.kind === "notify-email" || row.kind === "notify-webhook") {
      continue;
    }
    if (row.kind === "archive-observe") {
      await settleArchive(store, client, row, claim, signal, options);
      continue;
    }
    if (row.kind === "canary-boundary") {
      settleCanaryBoundary(store, claim);
      continue;
    }
    if (row.kind === "canary-observe") {
      await settleCanary(store, client, row, claim, signal, options);
      continue;
    }
    if (row.kind === "github-attestation") {
      await settleQueueRecovery(store, client, row, claim, signal);
      continue;
    }
    if (row.kind === "github-readback") {
      await settleMutationReadback(store, client, row, claim, signal, options);
      continue;
    }
    if (isGitHubMutation(row.kind)) {
      await settleMutation(store, client, row, claim, signal, options);
    }
  }
}

export function ensureUncertainMutationReadbacks(
  store: MemoryFleetStore,
): void {
  for (const row of store.dueWork) {
    if (isGitHubMutation(row.kind) && row.status === "uncertain") {
      ensureMutationReadback(store, row);
    }
  }
}

async function settleMutation(
  store: MemoryFleetStore,
  client: GitHubClient,
  row: DueWorkRecord,
  claim: DueWorkClaimSnapshot,
  signal?: AbortSignal,
  options?: DueWorkExecutionOptions,
): Promise<void> {
  if (!mutationIntentIsCurrent(store, row)) {
    finishWork(row, "failed");
    store.recordAudit(`github-mutation-superseded:${row.id}:failed`);
    failPossiblyEffectiveLegacyCommit(store, row);
    return;
  }
  if (row.kind === "github-mutate-route") {
    retireUnstartedRoutePredecessors(store, row);
    if (hasUnresolvedRoutePredecessor(store, row)) {
      row.dueAt = addMs(store.now(), 1_000);
      releaseClaim(row);
      return;
    }
  }

  let result: GitHubResult;
  try {
    result = await client.mutateVariable(
      row.payload.repositoryAlias ?? "",
      row.payload.name ?? "",
      row.payload.value ?? "",
      signal,
    );
  } catch {
    const owned = resolveClaimedWork(store, claim);
    if (owned !== undefined) {
      markMutationUncertain(store, owned);
    }
    return;
  }
  const ownedAfterMutation = resolveClaimedWork(store, claim);
  if (ownedAfterMutation === undefined) {
    return;
  }
  const classed = classifyGitHub(result);
  if (classed === "ok" || classed === "ambiguous") {
    let read: GitHubResult;
    try {
      read = await client.readVariable(
        ownedAfterMutation.payload.repositoryAlias ?? "",
        ownedAfterMutation.payload.name ?? "",
        signal,
      );
    } catch {
      const owned = resolveClaimedWork(store, claim);
      if (owned !== undefined) {
        markMutationUncertain(store, owned);
      }
      return;
    }
    const ownedAfterRead = resolveClaimedWork(store, claim);
    if (ownedAfterRead === undefined) {
      return;
    }
    if (
      classifyGitHub(read) === "ok" &&
      read.body === ownedAfterRead.payload.value &&
      mutationIntentIsCurrent(store, ownedAfterRead)
    ) {
      finishWork(ownedAfterRead, "done");
      completeMutation(store, ownedAfterRead, options);
      return;
    }
    markMutationUncertain(store, ownedAfterRead);
    return;
  }
  if (classed === "permanent") {
    finishWork(ownedAfterMutation, "failed");
    store.recordAudit(`github-mutation-failed:${ownedAfterMutation.id}`);
    failPossiblyEffectiveLegacyCommit(store, ownedAfterMutation);
    return;
  }
  if (retryDefinitiveFailure(store, ownedAfterMutation, result.retryAfterMs)) {
    failPossiblyEffectiveLegacyCommit(store, ownedAfterMutation);
  }
}

async function settleMutationReadback(
  store: MemoryFleetStore,
  client: GitHubClient,
  row: DueWorkRecord,
  claim: DueWorkClaimSnapshot,
  signal?: AbortSignal,
  options?: DueWorkExecutionOptions,
): Promise<void> {
  const mutation = resolveLinkedUncertainMutation(store, row);
  if (mutation === undefined) {
    finishWork(row, "failed");
    store.recordAudit(`github-readback-orphaned:${row.id}`);
    return;
  }
  let result: GitHubResult | undefined;
  try {
    result = await client.readVariable(
      mutation.payload.repositoryAlias ?? "",
      mutation.payload.name ?? "",
      signal,
    );
  } catch {
    // Read-only observation can be retried within its persisted bound.
  }
  const ownedReadback = resolveClaimedWork(store, claim);
  if (ownedReadback === undefined) {
    return;
  }
  const ownedMutation = resolveLinkedUncertainMutation(store, ownedReadback);
  if (ownedMutation === undefined) {
    finishWork(ownedReadback, "failed");
    store.recordAudit(`github-readback-orphaned:${ownedReadback.id}`);
    return;
  }
  if (
    result !== undefined &&
    classifyGitHub(result) === "ok" &&
    result.body === ownedMutation.payload.value
  ) {
    finishWork(ownedMutation, "done");
    finishWork(ownedReadback, "done");
    if (mutationIntentIsCurrent(store, ownedMutation)) {
      completeMutation(store, ownedMutation, options);
    } else {
      store.recordAudit(
        `github-mutation-readback-superseded:${ownedMutation.id}`,
      );
    }
    return;
  }
  const observeUntil = ownedReadback.payload.observeUntil;
  if (
    ownedReadback.attempts >= 5 ||
    (typeof observeUntil === "string" && observeUntil <= store.now())
  ) {
    finishWork(ownedReadback, "failed");
    store.recordAudit(`github-readback-exhausted:${ownedReadback.id}`);
    store.recordAudit(
      `github-mutation-manual-resolution-required:${ownedMutation.id}`,
    );
    failPossiblyEffectiveLegacyCommit(store, ownedMutation);
    return;
  }
  ownedReadback.dueAt = addMs(store.now(), 1_000);
  releaseClaim(ownedReadback);
}

async function settleQueueRecovery(
  store: MemoryFleetStore,
  client: GitHubClient,
  row: DueWorkRecord,
  claim: DueWorkClaimSnapshot,
  signal?: AbortSignal,
): Promise<void> {
  let expectation: QueueRecoveryExpectation;
  try {
    expectation = decodeQueueRecoveryExpectation(row.payload);
  } catch {
    finishWork(row, "failed");
    store.recordAudit(`queue-recovery-invalid:${row.id}`);
    return;
  }
  if (!queueRecoveryIsCurrent(store, expectation)) {
    finishWork(row, "failed");
    store.recordAudit(`queue-recovery-superseded:${row.id}`);
    return;
  }
  if (store.now() >= expectation.observeUntil) {
    finishWork(row, "failed");
    store.recordAudit(`queue-recovery-exhausted:${row.id}`);
    return;
  }

  let result: GitHubResult | undefined;
  try {
    result = await client.observeQueueRecovery(expectation, signal);
  } catch {
    // Read-only observation can be retried within its persisted bound.
  }
  const owned = resolveClaimedWork(store, claim);
  if (owned === undefined) {
    return;
  }
  if (!queueRecoveryIsCurrent(store, expectation)) {
    finishWork(owned, "failed");
    store.recordAudit(`queue-recovery-superseded:${owned.id}`);
    return;
  }
  if (result === undefined || classifyGitHub(result) !== "ok") {
    if (result !== undefined && classifyGitHub(result) === "permanent") {
      finishWork(owned, "failed");
      store.recordAudit(`queue-recovery-failed:${owned.id}`);
      return;
    }
    releaseQueueRecovery(store, owned, expectation);
    return;
  }
  const evaluated = evaluateQueueRecoveryObservation(
    expectation,
    result.body ?? "",
    store.now(),
  );
  if (evaluated.kind === "verified") {
    const repository = store.repositories.get(expectation.repositoryAlias);
    if (
      repository === undefined ||
      !queueRecoveryIsCurrent(store, expectation)
    ) {
      finishWork(owned, "failed");
      store.recordAudit(`queue-recovery-superseded:${owned.id}`);
      return;
    }
    repository.openQueueRisk = null;
    finishWork(owned, "done");
    store.recordAudit(
      `queue-risk-cleared:${expectation.repositoryAlias}:${expectation.transitionEpoch}`,
    );
    return;
  }
  if (evaluated.kind === "failed") {
    finishWork(owned, "failed");
    store.recordAudit(`queue-recovery-failed:${owned.id}`);
    return;
  }
  releaseQueueRecovery(store, owned, expectation);
}

function releaseQueueRecovery(
  store: MemoryFleetStore,
  row: DueWorkRecord,
  expectation: QueueRecoveryExpectation,
): void {
  if (
    !queueRecoveryIsCurrent(store, expectation) ||
    row.attempts >= 5 ||
    store.now() >= expectation.observeUntil
  ) {
    finishWork(row, "failed");
    store.recordAudit(`queue-recovery-exhausted:${row.id}`);
    return;
  }
  row.dueAt = addMs(store.now(), 1_000);
  releaseClaim(row);
}

function queueRecoveryIsCurrent(
  store: MemoryFleetStore,
  expectation: QueueRecoveryExpectation,
): boolean {
  const risk = store.repositories.get(
    expectation.repositoryAlias,
  )?.openQueueRisk;
  return (
    store.fleet.routingState === "HOSTED" &&
    risk !== null &&
    risk !== undefined &&
    risk.transitionEpoch === expectation.transitionEpoch &&
    risk.evidenceDigest === expectation.riskEvidenceDigest &&
    (risk.sourceHead === "unknown" ||
      risk.sourceHead === expectation.sourceHead)
  );
}

function resolveLinkedUncertainMutation(
  store: MemoryFleetStore,
  readback: DueWorkRecord,
): DueWorkRecord | undefined {
  return store.dueWork.find(
    (candidate) =>
      candidate.id === readback.payload.mutationId &&
      isGitHubMutation(candidate.kind) &&
      candidate.status === "uncertain" &&
      candidate.payload.effectKey === readback.payload.effectKey &&
      candidate.payload.repositoryAlias === readback.payload.repositoryAlias &&
      candidate.kind === readback.payload.mutationKind &&
      candidate.payload.name === readback.payload.name &&
      candidate.payload.configurationRevision ===
        readback.payload.configurationRevision &&
      candidate.payload.transitionRevision ===
        readback.payload.transitionRevision &&
      candidate.payload.value === readback.payload.value,
  );
}

async function settleCanary(
  store: MemoryFleetStore,
  client: GitHubClient,
  row: DueWorkRecord,
  claim: DueWorkClaimSnapshot,
  signal?: AbortSignal,
  options?: DueWorkExecutionOptions,
): Promise<void> {
  let expectation: CanaryExpectation;
  try {
    expectation = decodeCanaryExpectation(row.payload);
  } catch {
    finishWork(row, "failed");
    return;
  }
  if (!canaryExpectationIsCurrent(store, expectation)) {
    finishWork(row, "failed");
    store.recordAudit("canary-result-superseded");
    return;
  }
  let result: GitHubResult;
  try {
    result = await client.observeCanary(expectation, signal);
  } catch {
    const owned = resolveClaimedWork(store, claim);
    if (owned !== undefined) {
      releaseCanaryObservation(store, owned, expectation, options);
    }
    return;
  }
  const owned = resolveClaimedWork(store, claim);
  if (owned === undefined) {
    return;
  }
  const classification = classifyGitHub(result);
  if (classification !== "ok") {
    if (classification === "permanent") {
      failCurrentCanary(store, owned, expectation, options);
      return;
    }
    releaseCanaryObservation(store, owned, expectation, options);
    return;
  }
  const evaluated = evaluateCanaryObservation(
    expectation,
    result.body ?? "",
    store.now(),
    store.fleet.sequence,
  );
  if (evaluated.kind === "passed") {
    if (!canaryExpectationIsCurrent(store, expectation)) {
      finishWork(owned, "failed");
      store.recordAudit("canary-result-superseded");
      return;
    }
    finishWork(owned, "done");
    store.fleet.canaryEvidence = evaluated.evidence;
    store.recordAudit("canary-passed");
    return;
  }
  if (evaluated.kind === "failed") {
    store.recordAudit("canary-failed");
    failCurrentCanary(store, owned, expectation, options);
    return;
  }
  releaseCanaryObservation(store, owned, expectation, options);
}

function releaseCanaryObservation(
  store: MemoryFleetStore,
  row: DueWorkRecord,
  expectation: CanaryExpectation,
  options: DueWorkExecutionOptions | undefined,
): void {
  if (!canaryExpectationIsCurrent(store, expectation)) {
    finishWork(row, "failed");
    store.recordAudit("canary-result-superseded");
    return;
  }
  if (store.now() >= expectation.observeUntil) {
    if (options === undefined) {
      throw new Error("canary execution policy is unavailable");
    }
    store.recordAudit("canary-observation-deadline");
    abortCanary(store, options.hostedTransitionSafetyMarginMs);
    return;
  }
  releaseClaim(row);
}

function failCurrentCanary(
  store: MemoryFleetStore,
  row: DueWorkRecord,
  expectation: CanaryExpectation,
  options: DueWorkExecutionOptions | undefined,
): void {
  if (!canaryExpectationIsCurrent(store, expectation)) {
    finishWork(row, "failed");
    store.recordAudit("canary-result-superseded");
    return;
  }
  if (options === undefined) {
    throw new Error("canary execution policy is unavailable");
  }
  abortCanary(store, options.hostedTransitionSafetyMarginMs);
}

function canaryExpectationIsCurrent(
  store: MemoryFleetStore,
  expectation: CanaryExpectation,
): boolean {
  const repository = store.repositories.get(expectation.repositoryAlias);
  return (
    (store.fleet.routingState === "PORTABLE_CANARY" ||
      store.fleet.routingState === "LEGACY_CANARY") &&
    store.fleet.sessionId === expectation.sessionId &&
    store.fleet.leaseGeneration === expectation.leaseGeneration &&
    store.fleet.canaryScaleSet === expectation.scaleSet &&
    repository !== undefined &&
    repository.archiveEligibility === "active" &&
    !repository.archived
  );
}

async function settleArchive(
  store: MemoryFleetStore,
  client: GitHubClient,
  row: DueWorkRecord,
  claim: DueWorkClaimSnapshot,
  signal?: AbortSignal,
  options?: DueWorkExecutionOptions,
): Promise<void> {
  let expectation: ArchiveExpectation;
  try {
    expectation = decodeArchiveExpectation(row.payload);
  } catch {
    finishWork(row, "failed");
    store.recordAudit(`archive-observation-invalid:${row.id}`);
    return;
  }
  const attemptTime = store.now();
  if (
    !archiveExpectationIsCurrent(store, expectation) ||
    !archiveExistingEvidenceIsFresh(store, expectation, options, attemptTime)
  ) {
    finishWork(row, "failed");
    store.recordAudit(`archive-observation-superseded:${row.id}`);
    return;
  }
  if (attemptTime >= expectation.observeUntil) {
    finishWork(row, "failed");
    store.recordAudit(`archive-observation-exhausted:${row.id}`);
    return;
  }
  let result: GitHubResult | undefined;
  try {
    result = await client.observeArchive(expectation, signal);
  } catch {
    // Read-only observation can be retried through the existing due-work row.
  }
  const owned = resolveClaimedWork(store, claim);
  if (owned === undefined) {
    return;
  }
  const settlementTime = store.now();
  if (settlementTime >= expectation.observeUntil) {
    finishWork(owned, "failed");
    store.recordAudit(`archive-observation-exhausted:${owned.id}`);
    return;
  }
  if (!archiveExpectationIsCurrent(store, expectation)) {
    finishWork(owned, "failed");
    store.recordAudit(`archive-observation-superseded:${owned.id}`);
    return;
  }
  if (result === undefined || classifyGitHub(result) !== "ok") {
    if (result !== undefined && classifyGitHub(result) === "permanent") {
      finishWork(owned, "failed");
      store.recordAudit(`archive-observation-failed:${owned.id}`);
      return;
    }
    releaseArchiveObservation(
      store,
      owned,
      expectation,
      result !== undefined && classifyGitHub(result) === "retry"
        ? result.retryAfterMs
        : 1_000,
    );
    return;
  }
  const evaluated = evaluateArchiveObservation(
    expectation,
    result.body ?? "",
    settlementTime,
  );
  if (expectation.kind === "archive-sweep" && evaluated.kind === "observed") {
    applyArchiveObservation(
      store,
      expectation,
      evaluated.archived,
      settlementTime,
    );
    finishWork(owned, "done");
    return;
  }
  if (
    expectation.kind === "archive-reactivation" &&
    evaluated.kind === "verified" &&
    archiveExpectationIsCurrent(store, expectation)
  ) {
    const repository = store.repositories.get(expectation.repositoryAlias);
    if (repository === undefined) {
      finishWork(owned, "failed");
      return;
    }
    repository.archiveObservedAt = settlementTime;
    repository.archived = false;
    repository.archiveEligibility = "active";
    repository.archivePolicyRevision = null;
    finishWork(owned, "done");
    store.recordAudit(
      `archive-reactivated:${expectation.repositoryAlias}:policy-${expectation.configurationRevision}`,
    );
    return;
  }
  if (evaluated.kind === "pending") {
    const repository = store.repositories.get(expectation.repositoryAlias);
    if (
      expectation.kind !== "archive-reactivation" ||
      repository === undefined
    ) {
      finishWork(owned, "failed");
      return;
    }
    repository.archiveObservedAt = settlementTime;
    repository.archived = false;
    releaseArchiveObservation(store, owned, expectation, 1_000);
    return;
  }
  finishWork(owned, "failed");
  store.recordAudit(`archive-observation-failed:${owned.id}`);
}

function applyArchiveObservation(
  store: MemoryFleetStore,
  expectation: ArchiveSweepExpectation,
  archived: boolean,
  receiptTime: string,
): void {
  const repository = store.repositories.get(expectation.repositoryAlias);
  if (repository === undefined) {
    throw new Error("archive repository disappeared");
  }
  repository.archiveObservedAt = receiptTime;
  repository.archived = archived;
  if (!archived) {
    store.recordAudit(`archive-observed-active:${repository.alias}`);
    return;
  }
  repository.archiveEligibility = "archived-disabled";
  repository.archivePolicyRevision = expectation.configurationRevision;
  invalidateCanaryForAlias(store, repository.alias);
  const drainUntil = store.fleet.lastIssuedLeaseExpiryMax ?? receiptTime;
  store.recordAudit(
    `archive-disabled:${repository.alias}:policy-${expectation.configurationRevision}:drain-until-${drainUntil}`,
  );
}

function invalidateCanaryForAlias(
  store: MemoryFleetStore,
  repositoryAlias: string,
): void {
  for (const row of store.dueWork) {
    if (row.status !== "ready" && row.status !== "claimed") {
      continue;
    }
    let targeted =
      row.kind === "canary-dispatch" &&
      row.payload.repositoryAlias === repositoryAlias;
    if (row.kind === "canary-observe") {
      try {
        targeted =
          decodeCanaryExpectation(row.payload).repositoryAlias ===
          repositoryAlias;
      } catch {
        targeted = true;
      }
    }
    if (targeted) {
      finishWork(row, "failed");
      store.recordAudit(`archive-canary-inert:${repositoryAlias}:${row.id}`);
    }
  }
  if (store.fleet.canaryEvidence?.repositoryAlias === repositoryAlias) {
    store.fleet.canaryEvidence = null;
  }
}

function archiveExpectationIsCurrent(
  store: MemoryFleetStore,
  expectation: ArchiveExpectation,
): boolean {
  const repository = store.repositories.get(expectation.repositoryAlias);
  if (
    repository === undefined ||
    expectation.fleetId !== store.fleet.fleetId ||
    expectation.configurationRevision !== store.fleet.configRevision ||
    expectation.transitionEpoch !== currentTransitionEpoch(store)
  ) {
    return false;
  }
  if (expectation.kind === "archive-sweep") {
    return true;
  }
  return (
    repository.archiveEligibility === "pending-reactivation" &&
    repository.archivePolicyRevision !== null &&
    expectation.configurationRevision > repository.archivePolicyRevision &&
    store.fleet.routingState === "HOSTED" &&
    store.fleet.leaseGeneration === expectation.leaseGeneration &&
    repository.openQueueRisk === null
  );
}

function archiveExistingEvidenceIsFresh(
  store: MemoryFleetStore,
  expectation: ArchiveExpectation,
  options: DueWorkExecutionOptions | undefined,
  receiptTime: string,
): boolean {
  if (expectation.kind === "archive-sweep") {
    return true;
  }
  const repository = store.repositories.get(expectation.repositoryAlias);
  return (
    repository !== undefined &&
    options?.archiveEvidenceMaxAgeMs !== undefined &&
    archiveEvidenceState(
      repository,
      receiptTime,
      options.archiveEvidenceMaxAgeMs,
    ) === "fresh"
  );
}

function releaseArchiveObservation(
  store: MemoryFleetStore,
  row: DueWorkRecord,
  expectation: ArchiveExpectation,
  retryAfterMs: number | undefined,
): void {
  const now = store.now();
  if (
    row.attempts >= 5 ||
    now >= expectation.observeUntil ||
    !Number.isSafeInteger(retryAfterMs) ||
    (retryAfterMs ?? 0) <= 0 ||
    (retryAfterMs ?? 0) > 60_000
  ) {
    finishWork(row, "failed");
    store.recordAudit(`archive-observation-exhausted:${row.id}`);
    return;
  }
  const dueAt = addMs(now, retryAfterMs ?? 0);
  if (dueAt >= expectation.observeUntil) {
    finishWork(row, "failed");
    store.recordAudit(`archive-observation-exhausted:${row.id}`);
    return;
  }
  row.dueAt = dueAt;
  releaseClaim(row);
}

function currentTransitionEpoch(store: MemoryFleetStore): number | null {
  const epoch = store.transitions.at(-1)?.epoch;
  if (!Number.isSafeInteger(epoch) || epoch === undefined || epoch < 1) {
    return null;
  }
  return epoch;
}

function settleCanaryBoundary(
  store: MemoryFleetStore,
  claim: DueWorkClaimSnapshot,
): void {
  const owned = resolveClaimedWork(store, claim);
  if (owned === undefined) {
    return;
  }
  if (store.now() < owned.dueAt) {
    releaseClaim(owned);
    store.recordAudit(`canary-boundary-early:${owned.id}`);
    return;
  }
  if (
    store.fleet.routingState !== "DRAINING_TO_HOSTED" ||
    owned.payload.transitionRevision !== String(store.fleet.leaseGeneration)
  ) {
    finishWork(owned, "failed");
    store.recordAudit(`canary-boundary-superseded:${owned.id}`);
    return;
  }
  const from = store.fleet.routingState;
  assertTransition(from, "HOSTED");
  store.transitions.push(nextTransitionRecord(store, from, "HOSTED"));
  store.fleet.routingState = "HOSTED";
  finishWork(owned, "done");
  store.recordAudit("canary-boundary-hosted");
}

function failPendingCanaryWork(store: MemoryFleetStore, keepId?: string): void {
  for (const row of store.dueWork) {
    if (
      row.kind === "canary-observe" &&
      row.id !== keepId &&
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

function finishWork(
  row: DueWorkRecord,
  status: Extract<DueWorkRecord["status"], "done" | "failed" | "uncertain">,
): void {
  row.status = status;
  row.claimId = null;
  row.claimExpiresAt = null;
}

function markMutationUncertain(
  store: MemoryFleetStore,
  row: DueWorkRecord,
): void {
  ensureMutationReadback(store, row);
  finishWork(row, "uncertain");
  store.recordAudit(`github-mutation-uncertain:${row.id}`);
}

function ensureMutationReadback(
  store: MemoryFleetStore,
  row: DueWorkRecord,
): void {
  const linkedReadback = store.dueWork.find(
    (candidate) =>
      candidate.kind === "github-readback" &&
      candidate.payload.mutationId === row.id,
  );
  if (linkedReadback === undefined) {
    const now = store.now();
    store.enqueue({
      id: `readback-${row.id}`,
      kind: "github-readback",
      dueAt: now,
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: {
        effectKey: row.payload.effectKey ?? row.id,
        mutationId: row.id,
        mutationKind: row.kind,
        repositoryAlias: row.payload.repositoryAlias ?? "",
        name: row.payload.name ?? "",
        observeUntil: addMs(now, 60_000),
        configurationRevision: row.payload.configurationRevision ?? "",
        transitionRevision: row.payload.transitionRevision ?? "",
        value: row.payload.value ?? "",
      },
    });
  }
}

function retryDefinitiveFailure(
  store: MemoryFleetStore,
  row: DueWorkRecord,
  retryAfterMs: number | undefined,
): boolean {
  if (
    row.attempts >= 3 ||
    !Number.isInteger(retryAfterMs) ||
    (retryAfterMs ?? 0) <= 0 ||
    (retryAfterMs ?? 0) > 60_000
  ) {
    finishWork(row, "failed");
    store.recordAudit(`github-mutation-retry-exhausted:${row.id}`);
    return true;
  }
  row.dueAt = addMs(store.now(), retryAfterMs ?? 0);
  releaseClaim(row);
  return false;
}

function addMs(timestamp: string, deltaMs: number): string {
  const next = Date.parse(timestamp) + deltaMs;
  if (!Number.isFinite(next)) {
    throw new Error("due-work timestamp is invalid");
  }
  return new Date(next).toISOString().replace(/\.(\d{3})\d*Z$/, ".$1Z");
}

function completeMutation(
  store: MemoryFleetStore,
  row: DueWorkRecord,
  options?: DueWorkExecutionOptions,
): void {
  if (!mutationIntentIsCurrent(store, row)) {
    return;
  }
  const repository = store.repositories.get(row.payload.repositoryAlias ?? "");
  if (repository === undefined) {
    return;
  }
  const value = row.payload.value;
  if (row.kind === "github-mutate-route") {
    repository.confirmedRoute = value ?? null;
  } else if (row.kind === "github-mutate-scale-set") {
    repository.confirmedScaleSet = value ?? null;
  } else {
    repository.confirmedLegacyLabel = value ?? null;
  }
  refreshSelectorEvidence(repository, store.now());
  if (row.kind !== "github-mutate-route") {
    store.recordAudit(
      `github-selector-confirmed:${repository.alias}:${row.kind}`,
    );
    return;
  }
  if (value === "hosted") {
    completeHosted(store, options);
    return;
  }
  if (
    value === "self-hosted" &&
    store.fleet.routingState === "PORTABLE_CANARY" &&
    allRepositoriesReady(store, options)
  ) {
    promote(store, "PORTABLE_CANARY", "PORTABLE", "canary-promoted-portable");
    return;
  }
  if (
    value === "legacy" &&
    store.fleet.routingState === "LEGACY_CANARY" &&
    allRepositoriesReady(store, options)
  ) {
    promote(store, "LEGACY_CANARY", "LEGACY", "canary-promoted-legacy");
    store.fleet.leaseNotBefore = null;
  }
}

function refreshSelectorEvidence(
  repository: RepositoryRecord,
  receiptTime: string,
): void {
  const prior = repository.selectorEvidenceAt;
  repository.selectorEvidenceAt = receiptTime;
  if (
    selectorRestrictionReason(
      repository,
      receiptTime,
      Number.MAX_SAFE_INTEGER,
    ) !== null
  ) {
    repository.selectorEvidenceAt = prior;
  }
}

function allRepositoriesReady(
  store: MemoryFleetStore,
  options: DueWorkExecutionOptions | undefined,
): boolean {
  const maxAgeMs = options?.selectorEvidenceMaxAgeMs;
  return (
    maxAgeMs !== undefined &&
    [...store.repositories.values()].every(
      (repository) =>
        selectorRestrictionReason(repository, store.now(), maxAgeMs) === null,
    )
  );
}

function failPossiblyEffectiveLegacyCommit(
  store: MemoryFleetStore,
  row: DueWorkRecord,
): void {
  if (
    row.kind !== "github-mutate-route" ||
    row.payload.value !== "legacy" ||
    store.fleet.routingState !== "LEGACY_CANARY"
  ) {
    return;
  }
  const nextGeneration = store.fleet.leaseGeneration + 1;
  if (!Number.isSafeInteger(nextGeneration)) {
    store.recordAudit("legacy-route-hosted-restore-generation-exhausted");
    return;
  }
  const transition = nextTransitionRecord(
    store,
    "LEGACY_CANARY",
    "DRAINING_TO_HOSTED",
  );
  for (const candidate of store.dueWork) {
    if (
      candidate.kind !== "github-mutate-route" ||
      candidate.payload.value !== "legacy" ||
      candidate.payload.transitionRevision !==
        String(store.fleet.leaseGeneration)
    ) {
      continue;
    }
    if (candidate.status === "ready") {
      finishWork(candidate, "failed");
    } else if (candidate.status === "claimed" && candidate.id !== row.id) {
      finishWork(candidate, "failed");
    }
  }
  let restorationStaged = true;
  try {
    enqueueRepositoryRoutes(store, store.now(), "hosted", nextGeneration);
  } catch {
    restorationStaged = false;
    store.recordAudit("legacy-route-hosted-restore-capacity-exhausted");
  }
  for (const repository of store.repositories.values()) {
    repository.openQueueRisk = {
      transitionEpoch: transition.epoch,
      sourceHead: "unknown",
      evidenceDigest:
        store.fleet.policyDigest !== null &&
        /^[0-9a-f]{64}$/.test(store.fleet.policyDigest)
          ? store.fleet.policyDigest
          : "0".repeat(64),
      reason: "pre-transition-queue-may-remain",
    };
  }
  store.transitions.push(transition);
  store.fleet.routingState = "DRAINING_TO_HOSTED";
  store.fleet.leaseGeneration = nextGeneration;
  store.fleet.leaseNotBefore = null;
  store.fleet.canaryEvidence = null;
  store.recordAudit(
    restorationStaged
      ? "legacy-route-hosted-restore-staged"
      : "legacy-route-hosted-restore-manual-resolution-required",
  );
}

type DueWorkClaimSnapshot = {
  id: string;
  kind: DueWorkRecord["kind"];
  claimId: string | null;
  status: DueWorkRecord["status"];
  payload: Readonly<Record<string, string>>;
};

function snapshotClaim(row: DueWorkRecord): DueWorkClaimSnapshot {
  return {
    id: row.id,
    kind: row.kind,
    claimId: row.claimId,
    status: row.status,
    payload: { ...row.payload },
  };
}

function resolveClaimedWork(
  store: MemoryFleetStore,
  claim: DueWorkClaimSnapshot,
): DueWorkRecord | undefined {
  if (claim.status !== "claimed" || claim.claimId === null) {
    return undefined;
  }
  const current = store.dueWork.find((row) => row.id === claim.id);
  if (
    current === undefined ||
    current.kind !== claim.kind ||
    current.status !== "claimed" ||
    current.claimId !== claim.claimId ||
    !samePayload(current.payload, claim.payload)
  ) {
    return undefined;
  }
  return current;
}

function samePayload(
  left: Readonly<Record<string, string>>,
  right: Readonly<Record<string, string>>,
): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) => key === rightKeys[index] && left[key] === right[key],
    )
  );
}

function mutationIntentIsCurrent(
  store: MemoryFleetStore,
  row: DueWorkRecord,
): boolean {
  const repository = store.repositories.get(row.payload.repositoryAlias ?? "");
  if (repository === undefined) {
    return false;
  }
  if (row.kind === "github-mutate-scale-set") {
    return (
      store.fleet.routingState === "HOSTED" &&
      row.payload.name === "PORTABLE_GHAR_SCALE_SET" &&
      row.payload.configurationRevision ===
        String(store.fleet.configRevision) &&
      row.payload.transitionRevision ===
        String(currentTransitionEpoch(store)) &&
      repository.expectedScaleSet === row.payload.value
    );
  }
  if (row.kind === "github-mutate-legacy-label") {
    return (
      store.fleet.routingState === "HOSTED" &&
      row.payload.name === "PORTABLE_GHAR_LEGACY_LABEL" &&
      row.payload.configurationRevision ===
        String(store.fleet.configRevision) &&
      row.payload.transitionRevision ===
        String(currentTransitionEpoch(store)) &&
      repository.expectedLegacyLabel === row.payload.value
    );
  }
  if (
    row.kind !== "github-mutate-route" ||
    row.payload.name !== "PORTABLE_GHAR_ROUTE" ||
    row.payload.configurationRevision !== String(store.fleet.configRevision) ||
    row.payload.transitionRevision !== String(store.fleet.leaseGeneration) ||
    repository.expectedRoute !== row.payload.value
  ) {
    return false;
  }
  if (row.payload.value === "hosted") {
    return (
      store.fleet.routingState === "UNINITIALIZED" ||
      store.fleet.routingState === "DRAINING_TO_HOSTED"
    );
  }
  if (row.payload.value === "self-hosted") {
    return (
      store.fleet.routingState === "PORTABLE_CANARY" &&
      routeCanaryEvidenceMatches(store, row)
    );
  }
  return (
    row.payload.value === "legacy" &&
    store.fleet.routingState === "LEGACY_CANARY" &&
    routeCanaryEvidenceMatches(store, row)
  );
}

function routeCanaryEvidenceMatches(
  store: MemoryFleetStore,
  row: DueWorkRecord,
): boolean {
  const evidence = store.fleet.canaryEvidence;
  if (evidence === null || row.payload.canaryEvidence === undefined) {
    return false;
  }
  try {
    return encodeCanaryEvidence(evidence) === row.payload.canaryEvidence;
  } catch {
    return false;
  }
}

function retireUnstartedRoutePredecessors(
  store: MemoryFleetStore,
  current: DueWorkRecord,
): void {
  for (const row of store.dueWork) {
    if (isEarlierRouteIntent(row, current) && row.status === "ready") {
      finishWork(row, "failed");
      store.recordAudit(`github-route-superseded:${row.id}:failed`);
    }
  }
}

function hasUnresolvedRoutePredecessor(
  store: MemoryFleetStore,
  current: DueWorkRecord,
): boolean {
  return store.dueWork.some(
    (row) =>
      isEarlierRouteIntent(row, current) &&
      (row.status === "claimed" || row.status === "uncertain"),
  );
}

function isEarlierRouteIntent(
  candidate: DueWorkRecord,
  current: DueWorkRecord,
): boolean {
  if (
    candidate.id === current.id ||
    candidate.kind !== "github-mutate-route" ||
    candidate.payload.repositoryAlias !== current.payload.repositoryAlias ||
    candidate.payload.name !== current.payload.name
  ) {
    return false;
  }
  try {
    return (
      BigInt(candidate.payload.transitionRevision ?? "") <
      BigInt(current.payload.transitionRevision ?? "")
    );
  } catch {
    return false;
  }
}

function promote(
  store: MemoryFleetStore,
  from: Extract<RoutingState, "PORTABLE_CANARY" | "LEGACY_CANARY">,
  to: Extract<RoutingState, "PORTABLE" | "LEGACY">,
  audit: string,
): void {
  assertTransition(from, to);
  store.transitions.push(nextTransitionRecord(store, from, to));
  store.fleet.routingState = to;
  store.fleet.canaryEvidence = null;
  store.recordAudit(audit);
}

function completeHosted(
  store: MemoryFleetStore,
  options: DueWorkExecutionOptions | undefined,
): void {
  const from = store.fleet.routingState;
  if (
    (from === "UNINITIALIZED" || from === "DRAINING_TO_HOSTED") &&
    allRepositoriesReady(store, options)
  ) {
    const tail = store.transitions.at(-1);
    if (
      from === "DRAINING_TO_HOSTED" &&
      (tail?.from !== from || tail.to !== "HOSTED")
    ) {
      assertTransition(from, "HOSTED");
      store.transitions.push(nextTransitionRecord(store, from, "HOSTED"));
    }
    store.fleet.routingState = "HOSTED";
  }
}

export function bootstrapRequiresHostedReadback(
  from: PersistedRouting,
): boolean {
  return from === "UNINITIALIZED";
}
