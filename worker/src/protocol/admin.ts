import { isRfc3339MsZ } from "./auth";
import { canonicalize, parseCanonical } from "./canonical";
import { ALIAS, FLEET_ID, HEX64 } from "./messages";

const SHA40 = /^[0-9a-f]{40}$/;
const QUEUE_RECOVERY_COMMAND_FIELDS = [
  "protocolVersion",
  "kind",
  "fleetId",
  "timestamp",
  "nonce",
  "repositoryAlias",
  "transitionEpoch",
  "riskEvidenceDigest",
  "sourceHead",
  "recoveryEvidenceDigest",
] as const;
const ARCHIVE_REACTIVATION_COMMAND_FIELDS = [
  "protocolVersion",
  "kind",
  "fleetId",
  "timestamp",
  "nonce",
  "repositoryAlias",
  "configurationRevision",
  "transitionEpoch",
  "leaseGeneration",
  "workflowAuditDigest",
  "securityAuditDigest",
  "hostedBootstrapDigest",
  "queueClearanceDigest",
  "canaryEvidenceDigest",
  "observeUntil",
] as const;
const LEGACY_ROLLBACK_COMMAND_FIELDS = [
  "protocolVersion",
  "kind",
  "fleetId",
  "timestamp",
  "nonce",
  "repositoryAlias",
  "workflow",
  "revision",
  "legacyLabel",
  "configurationRevision",
  "transitionEpoch",
  "leaseGeneration",
  "fenceGeneration",
  "observeUntil",
] as const;
const WORKFLOW = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml$/;
const SELECTOR = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const EXPECTATION_FIELDS = [
  "schemaVersion",
  "fleetId",
  "repositoryAlias",
  "transitionEpoch",
  "riskEvidenceDigest",
  "sourceHead",
  "recoveryEvidenceDigest",
  "observeUntil",
] as const;
const OBSERVATION_FIELDS = [
  "schemaVersion",
  "status",
  "fleetId",
  "repositoryAlias",
  "transitionEpoch",
  "riskEvidenceDigest",
  "sourceHead",
  "recoveryEvidenceDigest",
  "verifiedAt",
] as const;

export type QueueRecoveryCommandV1 = {
  protocolVersion: 1;
  kind: "queue-recovery";
  fleetId: string;
  timestamp: string;
  nonce: string;
  repositoryAlias: string;
  transitionEpoch: number;
  riskEvidenceDigest: string;
  sourceHead: string;
  recoveryEvidenceDigest: string;
};

export type ArchiveReactivationCommandV1 = {
  protocolVersion: 1;
  kind: "archive-reactivation";
  fleetId: string;
  timestamp: string;
  nonce: string;
  repositoryAlias: string;
  configurationRevision: number;
  transitionEpoch: number;
  leaseGeneration: number;
  workflowAuditDigest: string;
  securityAuditDigest: string;
  hostedBootstrapDigest: string;
  queueClearanceDigest: string;
  canaryEvidenceDigest: string;
  observeUntil: string;
};

export type LegacyRollbackCommandV1 = {
  protocolVersion: 1;
  kind: "legacy-rollback";
  fleetId: string;
  timestamp: string;
  nonce: string;
  repositoryAlias: string;
  workflow: string;
  revision: string;
  legacyLabel: string;
  configurationRevision: number;
  transitionEpoch: number;
  leaseGeneration: number;
  fenceGeneration: number;
  observeUntil: string;
};

export type AdminCommandV1 =
  | QueueRecoveryCommandV1
  | ArchiveReactivationCommandV1
  | LegacyRollbackCommandV1;

export type QueueRecoveryExpectation = {
  schemaVersion: 1;
  fleetId: string;
  repositoryAlias: string;
  transitionEpoch: number;
  riskEvidenceDigest: string;
  sourceHead: string;
  recoveryEvidenceDigest: string;
  observeUntil: string;
};

export type QueueRecoveryEvaluation =
  | { kind: "pending" }
  | { kind: "failed" }
  | { kind: "verified"; verifiedAt: string };

type QueueRecoveryObservation = {
  schemaVersion: 1;
  status: "pending" | "verified";
  fleetId: string;
  repositoryAlias: string;
  transitionEpoch: number;
  riskEvidenceDigest: string;
  sourceHead: string;
  recoveryEvidenceDigest: string;
  verifiedAt: string | null;
};

export function parseQueueRecoveryCommand(
  body: string,
): QueueRecoveryCommandV1 {
  const parsed = asRecord(parseCanonical(body));
  assertQueueRecoveryCommand(parsed);
  return parsed as QueueRecoveryCommandV1;
}

export function parseAdminCommand(body: string): AdminCommandV1 {
  const parsed = asRecord(parseCanonical(body));
  if (parsed.kind === "queue-recovery") {
    assertQueueRecoveryCommand(parsed);
    return parsed as QueueRecoveryCommandV1;
  }
  if (parsed.kind === "archive-reactivation") {
    assertArchiveReactivationCommand(parsed);
    return parsed as ArchiveReactivationCommandV1;
  }
  if (parsed.kind === "legacy-rollback") {
    assertLegacyRollbackCommand(parsed);
    return parsed as LegacyRollbackCommandV1;
  }
  throw new Error("admin command is invalid");
}

function assertLegacyRollbackCommand(parsed: Record<string, unknown>): void {
  assertExactKeys(parsed, LEGACY_ROLLBACK_COMMAND_FIELDS);
  const command = parsed as LegacyRollbackCommandV1;
  if (
    command.protocolVersion !== 1 ||
    command.kind !== "legacy-rollback" ||
    !FLEET_ID.test(command.fleetId) ||
    !isRfc3339MsZ(command.timestamp) ||
    !HEX64.test(command.nonce) ||
    !ALIAS.test(command.repositoryAlias) ||
    !WORKFLOW.test(command.workflow) ||
    !SHA40.test(command.revision) ||
    !SELECTOR.test(command.legacyLabel) ||
    !isPositiveSafeInteger(command.configurationRevision) ||
    !isPositiveSafeInteger(command.transitionEpoch) ||
    !isPositiveSafeInteger(command.leaseGeneration) ||
    !isPositiveSafeInteger(command.fenceGeneration) ||
    !isRfc3339MsZ(command.observeUntil) ||
    command.observeUntil !== addMs(command.timestamp, 60_000)
  ) {
    throw new Error("legacy-rollback command is invalid");
  }
}

function assertQueueRecoveryCommand(parsed: Record<string, unknown>): void {
  assertExactKeys(parsed, QUEUE_RECOVERY_COMMAND_FIELDS);
  const command = parsed as QueueRecoveryCommandV1;
  if (
    command.protocolVersion !== 1 ||
    command.kind !== "queue-recovery" ||
    !FLEET_ID.test(command.fleetId) ||
    !isRfc3339MsZ(command.timestamp) ||
    !HEX64.test(command.nonce) ||
    !ALIAS.test(command.repositoryAlias) ||
    !isPositiveSafeInteger(command.transitionEpoch) ||
    !HEX64.test(command.riskEvidenceDigest) ||
    !SHA40.test(command.sourceHead) ||
    !HEX64.test(command.recoveryEvidenceDigest)
  ) {
    throw new Error("queue-recovery command is invalid");
  }
}

function assertArchiveReactivationCommand(
  parsed: Record<string, unknown>,
): void {
  assertExactKeys(parsed, ARCHIVE_REACTIVATION_COMMAND_FIELDS);
  const command = parsed as ArchiveReactivationCommandV1;
  if (
    command.protocolVersion !== 1 ||
    command.kind !== "archive-reactivation" ||
    !FLEET_ID.test(command.fleetId) ||
    !isRfc3339MsZ(command.timestamp) ||
    !HEX64.test(command.nonce) ||
    !ALIAS.test(command.repositoryAlias) ||
    !isPositiveSafeInteger(command.configurationRevision) ||
    !isPositiveSafeInteger(command.transitionEpoch) ||
    !isPositiveSafeInteger(command.leaseGeneration) ||
    !HEX64.test(command.workflowAuditDigest) ||
    !HEX64.test(command.securityAuditDigest) ||
    !HEX64.test(command.hostedBootstrapDigest) ||
    !HEX64.test(command.queueClearanceDigest) ||
    !HEX64.test(command.canaryEvidenceDigest) ||
    !isRfc3339MsZ(command.observeUntil) ||
    command.observeUntil <= command.timestamp
  ) {
    throw new Error("archive-reactivation command is invalid");
  }
}

export function encodeQueueRecoveryExpectation(
  expectation: QueueRecoveryExpectation,
): Record<string, string> {
  assertExactKeys(
    expectation as unknown as Readonly<Record<string, unknown>>,
    EXPECTATION_FIELDS,
  );
  assertQueueRecoveryExpectation(expectation);
  return { queueRecovery: canonicalize(expectation) };
}

export function decodeQueueRecoveryExpectation(
  payload: Readonly<Record<string, string>>,
): QueueRecoveryExpectation {
  if (
    Object.keys(payload).length !== 1 ||
    typeof payload.queueRecovery !== "string"
  ) {
    throw new Error("queue-recovery expectation payload is invalid");
  }
  const parsed = asRecord(parseCanonical(payload.queueRecovery));
  assertExactKeys(parsed, EXPECTATION_FIELDS);
  const expectation = parsed as QueueRecoveryExpectation;
  assertQueueRecoveryExpectation(expectation);
  return expectation;
}

export function evaluateQueueRecoveryObservation(
  expectation: QueueRecoveryExpectation,
  body: string,
  receiptTime: string,
): QueueRecoveryEvaluation {
  try {
    assertQueueRecoveryExpectation(expectation);
    if (!isRfc3339MsZ(receiptTime) || receiptTime >= expectation.observeUntil) {
      return { kind: "failed" };
    }
    const observation = parseQueueRecoveryObservation(body);
    if (!observationMatches(expectation, observation)) {
      return { kind: "failed" };
    }
    if (observation.status === "pending") {
      return observation.verifiedAt === null
        ? { kind: "pending" }
        : { kind: "failed" };
    }
    if (
      observation.verifiedAt === null ||
      !isRfc3339MsZ(observation.verifiedAt) ||
      observation.verifiedAt > receiptTime ||
      observation.verifiedAt >= expectation.observeUntil
    ) {
      return { kind: "failed" };
    }
    return { kind: "verified", verifiedAt: observation.verifiedAt };
  } catch {
    return { kind: "failed" };
  }
}

function assertQueueRecoveryExpectation(
  expectation: QueueRecoveryExpectation,
): void {
  if (
    expectation.schemaVersion !== 1 ||
    !FLEET_ID.test(expectation.fleetId) ||
    !ALIAS.test(expectation.repositoryAlias) ||
    !isPositiveSafeInteger(expectation.transitionEpoch) ||
    !HEX64.test(expectation.riskEvidenceDigest) ||
    !SHA40.test(expectation.sourceHead) ||
    !HEX64.test(expectation.recoveryEvidenceDigest) ||
    !isRfc3339MsZ(expectation.observeUntil)
  ) {
    throw new Error("queue-recovery expectation is invalid");
  }
}

function parseQueueRecoveryObservation(body: string): QueueRecoveryObservation {
  const parsed = asRecord(parseCanonical(body));
  assertExactKeys(parsed, OBSERVATION_FIELDS);
  if (
    parsed.schemaVersion !== 1 ||
    (parsed.status !== "pending" && parsed.status !== "verified") ||
    typeof parsed.fleetId !== "string" ||
    typeof parsed.repositoryAlias !== "string" ||
    !isPositiveSafeInteger(parsed.transitionEpoch) ||
    typeof parsed.riskEvidenceDigest !== "string" ||
    typeof parsed.sourceHead !== "string" ||
    typeof parsed.recoveryEvidenceDigest !== "string" ||
    (parsed.verifiedAt !== null && typeof parsed.verifiedAt !== "string")
  ) {
    throw new Error("queue-recovery observation is invalid");
  }
  return parsed as QueueRecoveryObservation;
}

function observationMatches(
  expectation: QueueRecoveryExpectation,
  observation: QueueRecoveryObservation,
): boolean {
  return (
    observation.fleetId === expectation.fleetId &&
    observation.repositoryAlias === expectation.repositoryAlias &&
    observation.transitionEpoch === expectation.transitionEpoch &&
    observation.riskEvidenceDigest === expectation.riskEvidenceDigest &&
    observation.sourceHead === expectation.sourceHead &&
    observation.recoveryEvidenceDigest === expectation.recoveryEvidenceDigest
  );
}

function isPositiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value > 0;
}

function addMs(timestamp: string, deltaMs: number): string {
  const next = Date.parse(timestamp) + deltaMs;
  if (!Number.isFinite(next)) {
    throw new Error("admin timestamp is invalid");
  }
  return new Date(next).toISOString().replace(/\.(\d{3})\d*Z$/, ".$1Z");
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("queue-recovery value is invalid");
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
    throw new Error("queue-recovery value is invalid");
  }
}
