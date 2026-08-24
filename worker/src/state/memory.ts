import {
  ALIAS,
  type Holder,
  type NoLeaseReason,
  type RoutingState,
} from "../protocol/messages";
import { isSelectorScalar } from "../routing/selector";
import { isRfc3339MsZ } from "../protocol/auth";
import {
  decodeCanaryExpectation,
  type CanaryEvidence,
} from "../routing/canary";
import { decodeQueueRecoveryExpectation } from "../protocol/admin";
import type { ArchiveEligibility } from "../routing/archive";
import type { QueueRiskRecord } from "../routing/queue-risk";

export type DueKind =
  | "github-mutate-route"
  | "github-mutate-scale-set"
  | "github-mutate-legacy-label"
  | "github-readback"
  | "github-attestation"
  | "canary-dispatch"
  | "canary-observe"
  | "canary-boundary"
  | "notify-email"
  | "notify-webhook"
  | "archive-observe";

export type DueStatus = "ready" | "claimed" | "done" | "failed" | "uncertain";

export const MAX_DUE_WORK = 256;
export const MAX_NON_ROUTE_DUE_WORK = 224;

const DUE_KINDS: ReadonlySet<string> = new Set<DueKind>([
  "github-mutate-route",
  "github-mutate-scale-set",
  "github-mutate-legacy-label",
  "github-readback",
  "github-attestation",
  "canary-dispatch",
  "canary-observe",
  "canary-boundary",
  "notify-email",
  "notify-webhook",
  "archive-observe",
]);

const DUE_STATUSES: ReadonlySet<string> = new Set<DueStatus>([
  "ready",
  "claimed",
  "done",
  "failed",
  "uncertain",
]);

export type FleetRecord = {
  fleetId: string;
  inventoried: boolean;
  epoch: number;
  sessionId: string | null;
  sequence: number;
  leaseGeneration: number;
  lastIssuedLeaseExpiryMax: string | null;
  leaseNotBefore: string | null;
  holder: Holder;
  fenceGeneration: number;
  routingState: RoutingState | "UNINITIALIZED";
  hostedHold: boolean;
  configRevision: number;
  policyDigest: string | null;
  maxCapacity: number;
  canaryScaleSet: string | null;
  canaryEvidence: CanaryEvidence | null;
};

export type RepositoryRecord = {
  alias: string;
  expectedRoute: string;
  confirmedRoute: string | null;
  expectedScaleSet: string | null;
  confirmedScaleSet: string | null;
  expectedLegacyLabel: string | null;
  confirmedLegacyLabel: string | null;
  archiveEligibility: ArchiveEligibility;
  archivePolicyRevision: number | null;
  archiveObservedAt: string | null;
  archived: boolean;
  selectorEvidenceAt: string | null;
  openQueueRisk: QueueRiskRecord | null;
};

export type DueWorkRecord = {
  id: string;
  kind: DueKind;
  dueAt: string;
  claimId: string | null;
  claimExpiresAt: string | null;
  attempts: number;
  status: DueStatus;
  payload: Record<string, string>;
};

export type MemoryClock = {
  now(): string;
};

export type AuditPersistenceState = {
  lastSequence: number | null;
  persistedEvents: readonly string[];
  pendingEvents: number;
};

export type TransitionRecord = {
  epoch: number;
  from: RoutingState | "UNINITIALIZED";
  to: RoutingState;
};

export class MemoryFleetStore {
  readonly fleet: FleetRecord;
  readonly nonces = new Map<string, string>();
  readonly repositories = new Map<string, RepositoryRecord>();
  readonly dueWork: DueWorkRecord[] = [];
  readonly audit: string[] = [];
  readonly transitions: TransitionRecord[] = [];
  private auditLastSequence: number | null = null;
  private auditPersistedEvents: string[] = [];
  private auditPendingEvents = 0;
  private persistedFleetGeneration = 0;

  constructor(
    fleetId: string,
    private readonly clock: MemoryClock,
  ) {
    this.fleet = {
      fleetId,
      inventoried: false,
      epoch: 0,
      sessionId: null,
      sequence: 0,
      leaseGeneration: 0,
      lastIssuedLeaseExpiryMax: null,
      leaseNotBefore: null,
      holder: "none",
      fenceGeneration: 0,
      routingState: "UNINITIALIZED",
      hostedHold: false,
      configRevision: 0,
      policyDigest: null,
      maxCapacity: 0,
      canaryScaleSet: null,
      canaryEvidence: null,
    };
  }

  now(): string {
    return this.clock.now();
  }

  fleetPersistenceGeneration(): number {
    return this.persistedFleetGeneration;
  }

  markFleetPersisted(generation: number): void {
    if (!Number.isSafeInteger(generation) || generation < 0) {
      throw new Error("fleet persistence generation is invalid");
    }
    this.persistedFleetGeneration = generation;
  }

  rememberNonce(digest: string, expiresAt: string): boolean {
    if (this.nonces.has(digest)) {
      return false;
    }
    this.nonces.set(digest, expiresAt);
    return true;
  }

  expireNonces(now: string): void {
    for (const [digest, expiresAt] of this.nonces) {
      if (expiresAt <= now) {
        this.nonces.delete(digest);
      }
    }
  }

  putRepository(record: RepositoryRecord): void {
    this.repositories.set(record.alias, record);
  }

  enqueue(work: DueWorkRecord): void {
    assertDueWorkRecord(work);
    if (this.dueWork.some((row) => row.id === work.id)) {
      throw new Error("due-work id is duplicated");
    }
    const missingReadbacks = this.missingMutationReadbacks();
    const missingCanaryBoundaries = this.missingCanaryBoundaries();
    const consumesReservedReadback =
      work.kind === "github-readback" &&
      this.dueWork.some(
        (row) =>
          isGitHubMutation(row.kind) &&
          row.status !== "done" &&
          row.status !== "failed" &&
          work.payload.mutationId === row.id &&
          !this.hasMutationReadback(row.id),
      );
    const addsReadbackReserve =
      isGitHubMutation(work.kind) &&
      work.status !== "done" &&
      work.status !== "failed" &&
      !this.hasMutationReadback(work.id);
    const consumesCanaryBoundaryReserve =
      missingCanaryBoundaries > 0 &&
      isCanaryRoutingState(this.fleet.routingState) &&
      currentCanaryBoundaryRevision(this) === work.payload.transitionRevision &&
      ((work.kind === "canary-boundary" &&
        work.payload.from === this.fleet.routingState) ||
        (work.kind === "github-mutate-route" &&
          (work.payload.value === "hosted" ||
            (this.fleet.routingState === "LEGACY_CANARY" &&
              work.payload.value === "legacy"))));
    const addsCanaryBoundaryReserve =
      work.kind === "canary-observe" &&
      isUnresolved(work.status) &&
      !isCanaryRoutingState(this.fleet.routingState);
    const legacyRestoration = this.legacyRestorationReservation(
      work,
      missingCanaryBoundaries,
    );
    const effectiveCapacity =
      MAX_DUE_WORK -
      missingReadbacks -
      missingCanaryBoundaries -
      legacyRestoration.reservedSlots -
      (addsReadbackReserve ? 1 : 0) +
      (consumesReservedReadback ? 1 : 0) -
      (addsCanaryBoundaryReserve ? 1 : 0) +
      (consumesCanaryBoundaryReserve ? 1 : 0) +
      legacyRestoration.consumedSlots;
    if (this.dueWork.length >= MAX_DUE_WORK) {
      throw new Error("due-work capacity is exhausted");
    }
    if (this.dueWork.length >= effectiveCapacity) {
      if (legacyRestoration.reservedSlots > 0) {
        throw new Error("legacy restoration reserve is exhausted");
      }
      if (missingCanaryBoundaries > 0 || addsCanaryBoundaryReserve) {
        throw new Error("canary boundary reserve is exhausted");
      }
      throw new Error("due-work readback reserve is exhausted");
    }
    if (
      !isReservedControlWork(work.kind) &&
      this.dueWork.filter((row) => !isReservedControlWork(row.kind)).length >=
        MAX_NON_ROUTE_DUE_WORK
    ) {
      throw new Error("non-route due-work capacity is exhausted");
    }
    if (isGitHubMutation(work.kind)) {
      const identity = mutationIdentity(work);
      if (
        this.dueWork.some(
          (row) =>
            isUnresolved(row.status) &&
            row.kind === work.kind &&
            mutationIdentity(row) === identity,
        )
      ) {
        throw new Error("route mutation target is unresolved");
      }
    }
    this.dueWork.push(work);
  }

  private hasMutationReadback(mutationId: string): boolean {
    return this.dueWork.some(
      (row) =>
        row.kind === "github-readback" && row.payload.mutationId === mutationId,
    );
  }

  private missingMutationReadbacks(): number {
    return this.dueWork.filter(
      (row) =>
        isGitHubMutation(row.kind) &&
        row.status !== "done" &&
        row.status !== "failed" &&
        !this.hasMutationReadback(row.id),
    ).length;
  }

  private missingCanaryBoundaries(): number {
    if (!isCanaryRoutingState(this.fleet.routingState)) {
      return 0;
    }
    const revision = currentCanaryBoundaryRevision(this);
    if (revision === null) {
      return 1;
    }
    return this.dueWork.some(
      (row) =>
        isUnresolved(row.status) &&
        row.payload.transitionRevision === revision &&
        ((row.kind === "canary-boundary" &&
          row.payload.from === this.fleet.routingState) ||
          (row.kind === "github-mutate-route" &&
            (row.payload.value === "hosted" ||
              (this.fleet.routingState === "LEGACY_CANARY" &&
                row.payload.value === "legacy")))),
    )
      ? 0
      : 1;
  }

  private legacyRestorationReservation(
    candidate: DueWorkRecord,
    missingCanaryBoundaries: number,
  ): {
    reservedSlots: number;
    consumedSlots: number;
  } {
    if (
      this.fleet.routingState !== "LEGACY_CANARY" ||
      !Number.isSafeInteger(this.fleet.leaseGeneration) ||
      this.fleet.leaseGeneration < 1 ||
      this.fleet.leaseGeneration >= Number.MAX_SAFE_INTEGER
    ) {
      return { reservedSlots: 0, consumedSlots: 0 };
    }
    const currentRevision = String(this.fleet.leaseGeneration);
    const nextRevision = String(this.fleet.leaseGeneration + 1);
    const isCandidateLegacyCommit = (row: DueWorkRecord): boolean =>
      row.kind === "github-mutate-route" &&
      row.payload.value === "legacy" &&
      (row.payload.transitionRevision === currentRevision ||
        row.payload.transitionRevision === nextRevision);
    const legacyCommit = [candidate, ...this.dueWork].find(
      isCandidateLegacyCommit,
    );
    let restorationRevision: string;
    if (legacyCommit !== undefined) {
      const parsed = Number(legacyCommit.payload.transitionRevision);
      if (!Number.isSafeInteger(parsed) || parsed >= Number.MAX_SAFE_INTEGER) {
        return { reservedSlots: 0, consumedSlots: 0 };
      }
      restorationRevision = String(parsed + 1);
    } else if (
      candidate.kind === "github-mutate-route" &&
      candidate.payload.value === "hosted" &&
      candidate.payload.transitionRevision === nextRevision
    ) {
      restorationRevision = nextRevision;
    } else {
      return { reservedSlots: 0, consumedSlots: 0 };
    }
    const isHostedRestoration = (row: DueWorkRecord): boolean =>
      row.kind === "github-mutate-route" &&
      row.payload.value === "hosted" &&
      row.payload.transitionRevision === restorationRevision &&
      this.repositories.has(row.payload.repositoryAlias ?? "");
    const stagedAliases = new Set(
      this.dueWork
        .filter(isHostedRestoration)
        .map((row) => row.payload.repositoryAlias ?? ""),
    );
    const candidateAlias = candidate.payload.repositoryAlias ?? "";
    const consumesRestorationSlot =
      isHostedRestoration(candidate) && !stagedAliases.has(candidateAlias);
    const missingRestorations = this.repositories.size - stagedAliases.size;
    const overlapsCanaryBoundary =
      missingRestorations > 0 &&
      missingCanaryBoundaries > 0 &&
      restorationRevision === currentCanaryBoundaryRevision(this);
    return {
      reservedSlots: 2 * missingRestorations - (overlapsCanaryBoundary ? 1 : 0),
      consumedSlots: consumesRestorationSlot
        ? overlapsCanaryBoundary
          ? 1
          : 2
        : 0,
    };
  }

  claimReady(now: string, limit: number, claimTtlMs: number): DueWorkRecord[] {
    if (
      !Number.isInteger(limit) ||
      limit <= 0 ||
      !Number.isInteger(claimTtlMs) ||
      claimTtlMs <= 0 ||
      !isRfc3339MsZ(now)
    ) {
      throw new Error("claim ttl is unset");
    }
    for (const row of this.dueWork) {
      if (
        row.status === "claimed" &&
        row.claimExpiresAt !== null &&
        row.claimExpiresAt <= now
      ) {
        row.status = isExternalEffectWork(row.kind) ? "uncertain" : "ready";
        row.claimId = null;
        row.claimExpiresAt = null;
        if (row.status === "uncertain") {
          this.recordAudit(
            isGitHubMutation(row.kind)
              ? `github-mutation-claim-expired:${row.id}`
              : `external-effect-claim-expired:${row.id}`,
          );
        }
      }
    }
    const claimed = this.dueWork
      .filter((row) => row.status === "ready" && row.dueAt <= now)
      .sort((left, right) => {
        const leftKey = `${left.dueAt}\n${left.id}`;
        const rightKey = `${right.dueAt}\n${right.id}`;
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
      })
      .slice(0, limit);
    for (const row of claimed) {
      const nextAttempt = row.attempts + 1;
      row.status = "claimed";
      row.claimId = `claim-${row.id}-${nextAttempt}-${now}`;
      row.claimExpiresAt = addMs(now, claimTtlMs);
      row.attempts = nextAttempt;
    }
    return claimed;
  }

  recordAudit(event: string): void {
    this.audit.push(event);
    if (this.audit.length > 256) {
      this.audit.shift();
    }
    this.auditPendingEvents = Math.min(
      this.auditPendingEvents + 1,
      this.audit.length,
    );
  }

  auditPersistenceState(): AuditPersistenceState {
    return {
      lastSequence: this.auditLastSequence,
      persistedEvents: [...this.auditPersistedEvents],
      pendingEvents: this.auditPendingEvents,
    };
  }

  markAuditPersisted(lastSequence: number | null): void {
    this.auditLastSequence = lastSequence;
    this.auditPersistedEvents = [...this.audit];
    this.auditPendingEvents = 0;
  }
}

export function isDueKind(value: string): value is DueKind {
  return DUE_KINDS.has(value);
}

export function nextTransitionRecord(
  store: MemoryFleetStore,
  from: RoutingState | "UNINITIALIZED",
  to: RoutingState,
): TransitionRecord {
  let lastEpoch = 0;
  for (const transition of store.transitions) {
    if (
      !Number.isSafeInteger(transition.epoch) ||
      transition.epoch < 1 ||
      transition.epoch <= lastEpoch
    ) {
      throw new Error("transition epoch is invalid");
    }
    lastEpoch = transition.epoch;
  }
  const epoch = lastEpoch + 1;
  if (!Number.isSafeInteger(epoch)) {
    throw new Error("transition epoch is exhausted");
  }
  return { epoch, from, to };
}

export function isDueStatus(value: string): value is DueStatus {
  return DUE_STATUSES.has(value);
}

export function isGitHubMutation(kind: DueKind): boolean {
  return (
    kind === "github-mutate-route" ||
    kind === "github-mutate-scale-set" ||
    kind === "github-mutate-legacy-label"
  );
}

export function isExternalEffectWork(kind: DueKind): boolean {
  return (
    isGitHubMutation(kind) ||
    kind === "canary-dispatch" ||
    kind === "notify-email" ||
    kind === "notify-webhook"
  );
}

export function assertDueWorkRecord(work: DueWorkRecord): void {
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$/.test(work.id) ||
    !isDueKind(work.kind) ||
    !isDueStatus(work.status) ||
    !Number.isSafeInteger(work.attempts) ||
    work.attempts < 0 ||
    !isRfc3339MsZ(work.dueAt) ||
    work.payload === null ||
    typeof work.payload !== "object" ||
    Array.isArray(work.payload) ||
    !Object.values(work.payload).every((value) => typeof value === "string")
  ) {
    throw new Error("due-work row is invalid");
  }
  const claimed = work.status === "claimed";
  if (
    claimed !== (work.claimId !== null) ||
    claimed !== (work.claimExpiresAt !== null) ||
    (work.claimId !== null &&
      (work.claimId === "" || work.claimId.length > 512)) ||
    (work.claimExpiresAt !== null && !isRfc3339MsZ(work.claimExpiresAt))
  ) {
    throw new Error("due-work row is invalid");
  }
  if (isGitHubMutation(work.kind)) {
    if (work.id.length > 182) {
      throw new Error("due-work row is invalid");
    }
    mutationTarget(work);
    if (!/^[1-9][0-9]*$/.test(work.payload.transitionRevision ?? "")) {
      throw new Error("due-work row is invalid");
    }
    if (
      work.kind === "github-mutate-route" &&
      (work.payload.name !== "PORTABLE_GHAR_ROUTE" ||
        (work.payload.value !== "hosted" &&
          work.payload.value !== "self-hosted" &&
          work.payload.value !== "legacy") ||
        work.payload.effectKey === undefined ||
        work.payload.effectKey === "" ||
        !/^(?:0|[1-9][0-9]*)$/.test(work.payload.configurationRevision ?? "") ||
        work.payload.transitionRevision === undefined ||
        !/^[1-9][0-9]*$/.test(work.payload.transitionRevision))
    ) {
      throw new Error("due-work row is invalid");
    }
  }
  if (work.kind === "canary-observe") {
    decodeCanaryExpectation(work.payload);
  }
  if (work.kind === "github-attestation") {
    decodeQueueRecoveryExpectation(work.payload);
  }
  if (
    work.kind === "canary-boundary" &&
    (Object.keys(work.payload).length !== 2 ||
      !/^[1-9][0-9]*$/.test(work.payload.transitionRevision ?? "") ||
      (work.payload.from !== "PORTABLE_CANARY" &&
        work.payload.from !== "LEGACY_CANARY"))
  ) {
    throw new Error("due-work row is invalid");
  }
}

function isReservedControlWork(kind: DueKind): boolean {
  return (
    isGitHubMutation(kind) ||
    kind === "github-readback" ||
    kind === "github-attestation" ||
    kind === "canary-boundary"
  );
}

function isCanaryRoutingState(
  state: FleetRecord["routingState"],
): state is "PORTABLE_CANARY" | "LEGACY_CANARY" {
  return state === "PORTABLE_CANARY" || state === "LEGACY_CANARY";
}

function currentCanaryBoundaryRevision(store: MemoryFleetStore): string | null {
  const next = store.fleet.leaseGeneration + 1;
  return Number.isSafeInteger(next) ? String(next) : null;
}

function mutationTarget(work: DueWorkRecord): string {
  const target = work.payload.name;
  if (
    typeof target !== "string" ||
    target === "" ||
    !ALIAS.test(work.payload.repositoryAlias ?? "")
  ) {
    throw new Error("due-work row is invalid");
  }
  if (
    work.kind === "github-mutate-scale-set" &&
    (target !== "PORTABLE_GHAR_SCALE_SET" ||
      !isSelectorScalar(work.payload.value) ||
      !/^[1-9][0-9]*$/.test(work.payload.configurationRevision ?? ""))
  ) {
    throw new Error("due-work row is invalid");
  }
  if (
    work.kind === "github-mutate-legacy-label" &&
    (target !== "PORTABLE_GHAR_LEGACY_LABEL" ||
      !isSelectorScalar(work.payload.value) ||
      !/^[1-9][0-9]*$/.test(work.payload.configurationRevision ?? ""))
  ) {
    throw new Error("due-work row is invalid");
  }
  return target;
}

function mutationIdentity(work: DueWorkRecord): string {
  return `${work.payload.repositoryAlias ?? ""}\n${mutationTarget(work)}\n${work.payload.transitionRevision ?? ""}`;
}

function isUnresolved(status: DueStatus): boolean {
  return status === "ready" || status === "claimed" || status === "uncertain";
}

function addMs(timestamp: string, deltaMs: number): string {
  const next = Date.parse(timestamp) + deltaMs;
  if (!Number.isFinite(next)) {
    throw new Error("claim timestamp is invalid");
  }
  return new Date(next).toISOString().replace(/\.(\d{3})\d*Z$/, ".$1Z");
}

export function noLease(reason: NoLeaseReason): {
  lease: null;
  noLeaseReason: NoLeaseReason;
} {
  return { lease: null, noLeaseReason: reason };
}
