import { parseCanonical } from "./canonical";
import { isRfc3339MsZ } from "./auth";
import { HEARTBEAT_PROTOCOL_VERSION } from "./version";

export const HEX64 = /^[0-9a-f]{64}$/;
export const FLEET_ID = /^[a-z][a-z0-9-]{0,63}$/;
export const ALIAS = /^[a-z][a-z0-9-]{0,63}$/;

export type Holder = "portable" | "legacy" | "none";
export type LeaseHolder = "portable" | "legacy";
export type LeaseMode = "disabled" | "canary-only" | "enabled";
export type RoutingState =
  | "HOSTED"
  | "DRAINING_TO_HOSTED"
  | "PORTABLE_CANARY"
  | "PORTABLE"
  | "LEGACY_CANARY"
  | "LEGACY";

export const ROUTING_STATES: readonly RoutingState[] = [
  "HOSTED",
  "DRAINING_TO_HOSTED",
  "PORTABLE_CANARY",
  "PORTABLE",
  "LEGACY_CANARY",
  "LEGACY",
];

export type NoLeaseReason =
  | "predecessor-lease-draining"
  | "fleet-not-inventoried"
  | "hosted-hold"
  | "stale-selector-evidence"
  | "queue-risk-open"
  | "invalid-request"
  | "clock-anomaly"
  | "policy-mismatch"
  | "capacity-zero"
  | "routing-hosted"
  | "lease-disabled";

export type SessionRequestV1 = {
  protocolVersion: typeof HEARTBEAT_PROTOCOL_VERSION;
  fleetId: string;
  nonce: string;
  timestamp: string;
  buildId: string;
};

export type SessionResponseV1 = {
  protocolVersion: typeof HEARTBEAT_PROTOCOL_VERSION;
  fleetId: string;
  nonce: string;
  epoch: number;
  sessionId: string;
  sequence: number;
  leaseGeneration: number;
  leaseNotBefore: string;
  receiptTime: string;
};

export type HeartbeatSnapshotV1 = {
  observedAt: string;
  fleetAlias: string;
  acquisitionMode: "disabled" | "canary-only" | "enabled" | "fatal";
  policyEpoch: number;
  policyDigest: string;
  repositoryPolicyRevision: number;
  capacity: {
    configured: number;
    effective: number;
    occupied: number;
    available: number;
    queued: number;
  };
  assignedJobs: number;
  runningJobs: number;
  oldestLiveAssignmentAgeMs: number;
  unassignedReleasedListeners: number;
  lastTerminalAt: string | null;
  hostProfileId: "strict-linux-v1" | "qts-capless-root";
  degraded: boolean;
  buildId: string;
};

export type HeartbeatRequestV1 = {
  protocolVersion: typeof HEARTBEAT_PROTOCOL_VERSION;
  fleetId: string;
  epoch: number;
  sessionId: string;
  sequence: number;
  holder: Holder;
  fenceGeneration: number;
  snapshot: HeartbeatSnapshotV1;
  timestamp: string;
};

export type AcquisitionLeaseV1 = {
  protocolVersion: typeof HEARTBEAT_PROTOCOL_VERSION;
  fleetId: string;
  holder: LeaseHolder;
  serverEpoch: number;
  sessionId: string;
  leaseGeneration: number;
  mode: LeaseMode;
  policyDigest: string;
  repositoryPolicyRevision: number;
  localPolicyEpoch: number;
  maxCapacity: number;
  canaryScaleSet: string | null;
  archivedDisabledAliases: string[];
  durationMs: number;
  expiry: string;
};

export type MaintenanceDirectiveV1 = {
  kind: "hosted-hold" | "none";
  sessionId: string;
  leaseGeneration: number;
};

export type HeartbeatResponseV1 = {
  protocolVersion: typeof HEARTBEAT_PROTOCOL_VERSION;
  fleetId: string;
  sessionId: string;
  sequence: number;
  receiptTime: string;
  routingState: RoutingState;
  maintenance: MaintenanceDirectiveV1;
  lease: AcquisitionLeaseV1 | null;
  noLeaseReason: NoLeaseReason | null;
};

export type HeartbeatBudget = {
  leaseDurationMs: number;
  maxAttemptIntervalMs: number;
  deadlineMs: number;
  shorteningMarginMs: number;
  lostRenewals: number;
};

export class ProtocolMessageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolMessageError";
  }
}

export function parseSessionRequest(body: string): SessionRequestV1 {
  const value = asRecord(parseCanonical(body));
  const request: SessionRequestV1 = {
    protocolVersion: requireVersion(value.protocolVersion),
    fleetId: requireFleetId(value.fleetId),
    nonce: requireHex64(value.nonce),
    timestamp: requireTimestamp(value.timestamp),
    buildId: requireHex64(value.buildId),
  };
  assertExactKeys(value, [
    "buildId",
    "fleetId",
    "nonce",
    "protocolVersion",
    "timestamp",
  ]);
  return request;
}

export function parseSessionResponse(body: string): SessionResponseV1 {
  const value = asRecord(parseCanonical(body));
  const response: SessionResponseV1 = {
    protocolVersion: requireVersion(value.protocolVersion),
    fleetId: requireFleetId(value.fleetId),
    nonce: requireHex64(value.nonce),
    epoch: requireUint(value.epoch),
    sessionId: requireHex64(value.sessionId),
    sequence: requireUint(value.sequence),
    leaseGeneration: requireUint(value.leaseGeneration),
    leaseNotBefore: requireTimestamp(value.leaseNotBefore),
    receiptTime: requireTimestamp(value.receiptTime),
  };
  assertExactKeys(value, [
    "epoch",
    "fleetId",
    "leaseGeneration",
    "leaseNotBefore",
    "nonce",
    "protocolVersion",
    "receiptTime",
    "sequence",
    "sessionId",
  ]);
  return response;
}

export function parseLease(value: unknown): AcquisitionLeaseV1 {
  const record = asRecord(value);
  const lease: AcquisitionLeaseV1 = {
    protocolVersion: requireVersion(record.protocolVersion),
    fleetId: requireFleetId(record.fleetId),
    holder: requireLeaseHolder(record.holder),
    serverEpoch: requireUint(record.serverEpoch),
    sessionId: requireHex64(record.sessionId),
    leaseGeneration: requireUint(record.leaseGeneration),
    mode: requireLeaseMode(record.mode),
    policyDigest: requireHex64(record.policyDigest),
    repositoryPolicyRevision: requireUint(record.repositoryPolicyRevision),
    localPolicyEpoch: requireUint(record.localPolicyEpoch),
    maxCapacity: requireUint(record.maxCapacity),
    canaryScaleSet: requireNullableAlias(record.canaryScaleSet),
    archivedDisabledAliases: requireAliasSet(record.archivedDisabledAliases),
    durationMs: requirePositiveInt(record.durationMs),
    expiry: requireTimestamp(record.expiry),
  };
  assertExactKeys(record, [
    "archivedDisabledAliases",
    "canaryScaleSet",
    "durationMs",
    "expiry",
    "fleetId",
    "holder",
    "leaseGeneration",
    "localPolicyEpoch",
    "maxCapacity",
    "mode",
    "policyDigest",
    "protocolVersion",
    "repositoryPolicyRevision",
    "serverEpoch",
    "sessionId",
  ]);
  if (lease.mode === "canary-only") {
    if (lease.maxCapacity !== 1 || lease.canaryScaleSet === null) {
      throw new ProtocolMessageError("canary lease shape is invalid");
    }
  }
  if (
    lease.mode === "disabled" &&
    (lease.maxCapacity !== 0 || lease.canaryScaleSet !== null)
  ) {
    throw new ProtocolMessageError("disabled lease shape is invalid");
  }
  if (lease.mode === "enabled" && lease.maxCapacity < 1) {
    throw new ProtocolMessageError("enabled lease capacity is invalid");
  }
  return lease;
}

export function admissionAuthorityKey(lease: AcquisitionLeaseV1): string {
  return JSON.stringify({
    archivedDisabledAliases: lease.archivedDisabledAliases,
    canaryScaleSet: lease.canaryScaleSet,
    durationMs: lease.durationMs,
    fleetId: lease.fleetId,
    holder: lease.holder,
    leaseGeneration: lease.leaseGeneration,
    localPolicyEpoch: lease.localPolicyEpoch,
    maxCapacity: lease.maxCapacity,
    mode: lease.mode,
    policyDigest: lease.policyDigest,
    protocolVersion: lease.protocolVersion,
    repositoryPolicyRevision: lease.repositoryPolicyRevision,
    serverEpoch: lease.serverEpoch,
    sessionId: lease.sessionId,
  });
}

export function assertHeartbeatBudget(budget: HeartbeatBudget): void {
  if (
    budget.leaseDurationMs <= 0 ||
    budget.maxAttemptIntervalMs <= 0 ||
    budget.deadlineMs <= 0 ||
    budget.shorteningMarginMs <= 0 ||
    budget.lostRenewals < 1
  ) {
    throw new ProtocolMessageError("heartbeat budget terms are incomplete");
  }
  const right =
    (budget.lostRenewals + 1) * budget.maxAttemptIntervalMs +
    budget.deadlineMs +
    budget.shorteningMarginMs;
  if (!(budget.leaseDurationMs > right)) {
    throw new ProtocolMessageError("heartbeat lease inequality is false");
  }
}

export function localLeaseDeadlineMs(
  sendAnchorMs: number,
  durationMs: number,
  shorteningMarginMs: number,
): number {
  if (sendAnchorMs <= 0 || durationMs <= 0 || shorteningMarginMs <= 0) {
    throw new ProtocolMessageError("lease deadline terms are incomplete");
  }
  if (durationMs <= shorteningMarginMs) {
    throw new ProtocolMessageError("lease shortening leaves no authority");
  }
  return sendAnchorMs + durationMs - shorteningMarginMs;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolMessageError("protocol value is not an object");
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(value: Record<string, unknown>, keys: string[]): void {
  const got = Object.keys(value).sort();
  const want = [...keys].sort();
  if (
    got.length !== want.length ||
    got.some((key, index) => key !== want[index])
  ) {
    throw new ProtocolMessageError("protocol object fields are not exact");
  }
}

function requireVersion(value: unknown): typeof HEARTBEAT_PROTOCOL_VERSION {
  if (value !== HEARTBEAT_PROTOCOL_VERSION) {
    throw new ProtocolMessageError("protocol version is invalid");
  }
  return HEARTBEAT_PROTOCOL_VERSION;
}

function requireFleetId(value: unknown): string {
  if (typeof value !== "string" || !FLEET_ID.test(value)) {
    throw new ProtocolMessageError("fleet id is invalid");
  }
  return value;
}

function requireHex64(value: unknown): string {
  if (typeof value !== "string" || !HEX64.test(value)) {
    throw new ProtocolMessageError("hex64 field is invalid");
  }
  return value;
}

function requireTimestamp(value: unknown): string {
  if (typeof value !== "string" || !isRfc3339MsZ(value)) {
    throw new ProtocolMessageError("timestamp is invalid");
  }
  return value;
}

function requireUint(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new ProtocolMessageError("unsigned integer is invalid");
  }
  return value;
}

function requirePositiveInt(value: unknown): number {
  const next = requireUint(value);
  if (next <= 0) {
    throw new ProtocolMessageError("positive integer is invalid");
  }
  return next;
}

function requireLeaseHolder(value: unknown): LeaseHolder {
  if (value === "portable" || value === "legacy") {
    return value;
  }
  throw new ProtocolMessageError("lease holder is invalid");
}

function requireLeaseMode(value: unknown): LeaseMode {
  if (value === "disabled" || value === "canary-only" || value === "enabled") {
    return value;
  }
  throw new ProtocolMessageError("lease mode is invalid");
}

function requireNullableAlias(value: unknown): string | null {
  if (value === null) {
    return null;
  }
  if (typeof value === "string" && ALIAS.test(value)) {
    return value;
  }
  throw new ProtocolMessageError("canary scale set is invalid");
}

function requireAliasSet(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new ProtocolMessageError("archive alias set is invalid");
  }
  const aliases = value.map((item) => {
    if (typeof item !== "string" || !ALIAS.test(item)) {
      throw new ProtocolMessageError("archive alias is invalid");
    }
    return item;
  });
  for (let i = 1; i < aliases.length; i += 1) {
    if (aliases[i]! <= aliases[i - 1]!) {
      throw new ProtocolMessageError(
        "archive aliases must be sorted and unique",
      );
    }
  }
  return aliases;
}
