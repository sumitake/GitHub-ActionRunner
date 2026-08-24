import { isRfc3339MsZ } from "../protocol/auth";
import { canonicalize, parseCanonical } from "../protocol/canonical";
import { ALIAS, FLEET_ID, HEX64 } from "../protocol/messages";
import type { RepositoryRecord } from "../state/memory";

export type ArchiveEligibility =
  "active" | "archived-disabled" | "pending-reactivation";

export type ArchiveSweepExpectation = {
  schemaVersion: 1;
  kind: "archive-sweep";
  fleetId: string;
  repositoryAlias: string;
  configurationRevision: number;
  transitionEpoch: number;
  observeUntil: string;
};

export type ArchiveReactivationExpectation = {
  schemaVersion: 1;
  kind: "archive-reactivation";
  fleetId: string;
  repositoryAlias: string;
  configurationRevision: number;
  transitionEpoch: number;
  leaseGeneration: number;
  startedAt: string;
  workflowAuditDigest: string;
  securityAuditDigest: string;
  hostedBootstrapDigest: string;
  queueClearanceDigest: string;
  canaryEvidenceDigest: string;
  observeUntil: string;
};

export type ArchiveExpectation =
  ArchiveSweepExpectation | ArchiveReactivationExpectation;

export type ArchiveEvaluation =
  | { kind: "pending" }
  | { kind: "failed" }
  | { kind: "observed"; archived: boolean }
  | { kind: "verified"; verifiedAt: string };

export type ArchiveEvidenceState =
  | "fresh"
  | "missing-evidence"
  | "invalid-evidence"
  | "future-evidence"
  | "stale-evidence"
  | "archived";

export type ArchiveRestrictionReason =
  ArchiveEvidenceState | Exclude<ArchiveEligibility, "active">;

const SWEEP_EXPECTATION_FIELDS = [
  "schemaVersion",
  "kind",
  "fleetId",
  "repositoryAlias",
  "configurationRevision",
  "transitionEpoch",
  "observeUntil",
] as const;

const REACTIVATION_EXPECTATION_FIELDS = [
  "schemaVersion",
  "kind",
  "fleetId",
  "repositoryAlias",
  "configurationRevision",
  "transitionEpoch",
  "leaseGeneration",
  "startedAt",
  "workflowAuditDigest",
  "securityAuditDigest",
  "hostedBootstrapDigest",
  "queueClearanceDigest",
  "canaryEvidenceDigest",
  "observeUntil",
] as const;

const SWEEP_OBSERVATION_FIELDS = [
  "schemaVersion",
  "kind",
  "status",
  "fleetId",
  "repositoryAlias",
  "configurationRevision",
  "transitionEpoch",
  "archived",
] as const;

const REACTIVATION_OBSERVATION_FIELDS = [
  ...REACTIVATION_EXPECTATION_FIELDS,
  "status",
  "archived",
  "verifiedAt",
] as const;

export function encodeArchiveExpectation(
  expectation: ArchiveExpectation,
): Record<string, string> {
  assertArchiveExpectation(expectation);
  return { archive: canonicalize(expectation) };
}

export function decodeArchiveExpectation(
  payload: Readonly<Record<string, string>>,
): ArchiveExpectation {
  if (
    Object.keys(payload).length !== 1 ||
    typeof payload.archive !== "string"
  ) {
    throw new Error("archive expectation payload is invalid");
  }
  const parsed = asRecord(parseCanonical(payload.archive));
  const expectation = parsed as ArchiveExpectation;
  assertArchiveExpectation(expectation);
  return expectation;
}

export function evaluateArchiveObservation(
  expectation: ArchiveExpectation,
  body: string,
  receiptTime: string,
): ArchiveEvaluation {
  try {
    assertArchiveExpectation(expectation);
    if (!isRfc3339MsZ(receiptTime) || receiptTime >= expectation.observeUntil) {
      return { kind: "failed" };
    }
    const parsed = asRecord(parseCanonical(body));
    if (expectation.kind === "archive-sweep") {
      assertExactKeys(parsed, SWEEP_OBSERVATION_FIELDS);
      if (
        parsed.schemaVersion !== 1 ||
        parsed.kind !== "archive-sweep" ||
        parsed.status !== "observed" ||
        typeof parsed.archived !== "boolean" ||
        !matchesCommon(expectation, parsed)
      ) {
        return { kind: "failed" };
      }
      return { kind: "observed", archived: parsed.archived };
    }
    assertExactKeys(parsed, REACTIVATION_OBSERVATION_FIELDS);
    if (
      parsed.schemaVersion !== 1 ||
      parsed.kind !== "archive-reactivation" ||
      (parsed.status !== "pending" && parsed.status !== "verified") ||
      parsed.archived !== false ||
      (parsed.verifiedAt !== null && typeof parsed.verifiedAt !== "string") ||
      !matchesReactivation(expectation, parsed)
    ) {
      return { kind: "failed" };
    }
    if (parsed.status === "pending") {
      return parsed.verifiedAt === null
        ? { kind: "pending" }
        : { kind: "failed" };
    }
    if (
      typeof parsed.verifiedAt !== "string" ||
      !isRfc3339MsZ(parsed.verifiedAt) ||
      parsed.verifiedAt < expectation.startedAt ||
      parsed.verifiedAt > receiptTime ||
      parsed.verifiedAt >= expectation.observeUntil
    ) {
      return { kind: "failed" };
    }
    return { kind: "verified", verifiedAt: parsed.verifiedAt };
  } catch {
    return { kind: "failed" };
  }
}

export function archiveEvidenceState(
  repository: Pick<RepositoryRecord, "archiveObservedAt" | "archived">,
  receiptTime: string,
  maxAgeMs: number,
): ArchiveEvidenceState {
  if (
    !isRfc3339MsZ(receiptTime) ||
    !Number.isSafeInteger(maxAgeMs) ||
    maxAgeMs <= 0
  ) {
    return "invalid-evidence";
  }
  if (repository.archived) {
    return "archived";
  }
  const observedAt = repository.archiveObservedAt;
  if (observedAt === null) {
    return "missing-evidence";
  }
  if (!isRfc3339MsZ(observedAt)) {
    return "invalid-evidence";
  }
  const receiptMs = Date.parse(receiptTime);
  const observedMs = Date.parse(observedAt);
  if (!Number.isSafeInteger(receiptMs) || !Number.isSafeInteger(observedMs)) {
    return "invalid-evidence";
  }
  if (observedMs > receiptMs) {
    return "future-evidence";
  }
  if (receiptMs - observedMs >= maxAgeMs) {
    return "stale-evidence";
  }
  return "fresh";
}

export function archiveRestrictionReason(
  repository: Pick<
    RepositoryRecord,
    "archiveEligibility" | "archiveObservedAt" | "archived"
  >,
  receiptTime: string,
  maxAgeMs: number,
): ArchiveRestrictionReason | null {
  if (repository.archiveEligibility !== "active") {
    return repository.archiveEligibility;
  }
  const evidence = archiveEvidenceState(repository, receiptTime, maxAgeMs);
  return evidence === "fresh" ? null : evidence;
}

function assertArchiveExpectation(expectation: ArchiveExpectation): void {
  const record = expectation as unknown as Readonly<Record<string, unknown>>;
  assertExactKeys(
    record,
    expectation.kind === "archive-sweep"
      ? SWEEP_EXPECTATION_FIELDS
      : REACTIVATION_EXPECTATION_FIELDS,
  );
  if (
    expectation.schemaVersion !== 1 ||
    (expectation.kind !== "archive-sweep" &&
      expectation.kind !== "archive-reactivation") ||
    !FLEET_ID.test(expectation.fleetId) ||
    !ALIAS.test(expectation.repositoryAlias) ||
    !isNonNegativeSafeInteger(expectation.configurationRevision) ||
    !isPositiveSafeInteger(expectation.transitionEpoch) ||
    !isRfc3339MsZ(expectation.observeUntil)
  ) {
    throw new Error("archive expectation is invalid");
  }
  if (
    expectation.kind === "archive-reactivation" &&
    (!isPositiveSafeInteger(expectation.leaseGeneration) ||
      !isRfc3339MsZ(expectation.startedAt) ||
      expectation.startedAt >= expectation.observeUntil ||
      !HEX64.test(expectation.workflowAuditDigest) ||
      !HEX64.test(expectation.securityAuditDigest) ||
      !HEX64.test(expectation.hostedBootstrapDigest) ||
      !HEX64.test(expectation.queueClearanceDigest) ||
      !HEX64.test(expectation.canaryEvidenceDigest))
  ) {
    throw new Error("archive reactivation expectation is invalid");
  }
}

function matchesCommon(
  expectation: Pick<
    ArchiveExpectation,
    "fleetId" | "repositoryAlias" | "configurationRevision" | "transitionEpoch"
  >,
  observation: Readonly<Record<string, unknown>>,
): boolean {
  return (
    observation.fleetId === expectation.fleetId &&
    observation.repositoryAlias === expectation.repositoryAlias &&
    observation.configurationRevision === expectation.configurationRevision &&
    observation.transitionEpoch === expectation.transitionEpoch
  );
}

function matchesReactivation(
  expectation: ArchiveReactivationExpectation,
  observation: Readonly<Record<string, unknown>>,
): boolean {
  return (
    matchesCommon(expectation, observation) &&
    observation.leaseGeneration === expectation.leaseGeneration &&
    observation.startedAt === expectation.startedAt &&
    observation.workflowAuditDigest === expectation.workflowAuditDigest &&
    observation.securityAuditDigest === expectation.securityAuditDigest &&
    observation.hostedBootstrapDigest === expectation.hostedBootstrapDigest &&
    observation.queueClearanceDigest === expectation.queueClearanceDigest &&
    observation.canaryEvidenceDigest === expectation.canaryEvidenceDigest &&
    observation.observeUntil === expectation.observeUntil
  );
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("archive value is invalid");
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    !actual.every((key, index) => key === wanted[index])
  ) {
    throw new Error("archive value fields are invalid");
  }
}
