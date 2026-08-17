import type { Holder, NoLeaseReason, RoutingState } from "../protocol/messages";

export type DueKind =
  | "github-mutate-route"
  | "github-mutate-scale-set"
  | "github-mutate-legacy-label"
  | "github-readback"
  | "github-attestation"
  | "canary-dispatch"
  | "canary-observe"
  | "notify-email"
  | "notify-webhook"
  | "archive-observe";

export type DueStatus = "ready" | "claimed" | "done" | "failed";

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
  canaryPassed: boolean;
};

export type RepositoryRecord = {
  alias: string;
  expectedRoute: string;
  confirmedRoute: string | null;
  archiveLatched: boolean;
  archiveObservedAt: string | null;
  archived: boolean;
  selectorEvidenceAt: string | null;
  openQueueRisk: { transitionEpoch: number; reason: string } | null;
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

export class MemoryFleetStore {
  readonly fleet: FleetRecord;
  readonly nonces = new Map<string, string>();
  readonly repositories = new Map<string, RepositoryRecord>();
  readonly dueWork: DueWorkRecord[] = [];
  readonly audit: string[] = [];
  readonly transitions: Array<{ epoch: number; from: string; to: string }> = [];

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
      canaryPassed: false,
    };
  }

  now(): string {
    return this.clock.now();
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
    this.dueWork.push(work);
  }

  claimReady(now: string, limit: number, claimTtlMs: number): DueWorkRecord[] {
    if (!Number.isInteger(claimTtlMs) || claimTtlMs <= 0) {
      throw new Error("claim ttl is unset");
    }
    const claimed: DueWorkRecord[] = [];
    for (const row of this.dueWork) {
      if (claimed.length >= limit) {
        break;
      }
      if (
        row.status === "claimed" &&
        row.claimExpiresAt !== null &&
        row.claimExpiresAt <= now
      ) {
        row.status = "ready";
        row.claimId = null;
        row.claimExpiresAt = null;
      }
      if (row.status === "ready" && row.dueAt <= now) {
        row.status = "claimed";
        row.claimId = `claim-${row.id}-${now}`;
        row.claimExpiresAt = addMs(now, claimTtlMs);
        row.attempts += 1;
        claimed.push(row);
      }
    }
    return claimed;
  }

  recordAudit(event: string): void {
    this.audit.push(event);
    if (this.audit.length > 256) {
      this.audit.shift();
    }
  }
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
