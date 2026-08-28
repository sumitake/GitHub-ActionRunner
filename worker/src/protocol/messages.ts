import { parseCanonical } from "./canonical";
import { isRfc3339MsZ } from "./auth";
import { HEARTBEAT_PROTOCOL_VERSION } from "./version";

export const HEX64 = /^[0-9a-f]{64}$/;
export const FLEET_ID = /^[a-z][a-z0-9-]{0,63}$/;
export const ALIAS = /^[a-z][a-z0-9-]{0,63}$/;
export const MAX_LEASE_DURATION_MS = 9_223_372_036_854;

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
  if (
    response.epoch < 1 ||
    response.leaseGeneration < 1 ||
    response.sequence !== 0 ||
    response.sessionId === response.nonce ||
    response.leaseNotBefore < response.receiptTime
  ) {
    throw new ProtocolMessageError("session response state is inconsistent");
  }
  return response;
}

export function parseHeartbeatRequest(body: string): HeartbeatRequestV1 {
  const value = asRecord(parseCanonical(body));
  const request: HeartbeatRequestV1 = {
    protocolVersion: requireVersion(value.protocolVersion),
    fleetId: requireFleetId(value.fleetId),
    epoch: requireUint(value.epoch),
    sessionId: requireHex64(value.sessionId),
    sequence: requireUint(value.sequence),
    holder: requireHolder(value.holder),
    fenceGeneration: requireUint(value.fenceGeneration),
    snapshot: parseHeartbeatSnapshot(value.snapshot),
    timestamp: requireTimestamp(value.timestamp),
  };
  assertExactKeys(value, [
    "epoch",
    "fenceGeneration",
    "fleetId",
    "holder",
    "protocolVersion",
    "sequence",
    "sessionId",
    "snapshot",
    "timestamp",
  ]);
  if (request.snapshot.fleetAlias !== request.fleetId) {
    throw new ProtocolMessageError("heartbeat fleet binding is invalid");
  }
  return request;
}

export function parseHeartbeatResponse(body: string): HeartbeatResponseV1 {
  const value = asRecord(parseCanonical(body));
  const response: HeartbeatResponseV1 = {
    protocolVersion: requireVersion(value.protocolVersion),
    fleetId: requireFleetId(value.fleetId),
    sessionId: requireHex64(value.sessionId),
    sequence: requireUint(value.sequence),
    receiptTime: requireTimestamp(value.receiptTime),
    routingState: requireRoutingState(value.routingState),
    maintenance: parseMaintenanceDirective(value.maintenance),
    lease: value.lease === null ? null : parseLease(value.lease),
    noLeaseReason: requireNullableNoLeaseReason(value.noLeaseReason),
  };
  assertExactKeys(value, [
    "fleetId",
    "lease",
    "maintenance",
    "noLeaseReason",
    "protocolVersion",
    "receiptTime",
    "routingState",
    "sequence",
    "sessionId",
  ]);
  if (
    response.maintenance.sessionId !== response.sessionId ||
    (response.lease === null) === (response.noLeaseReason === null) ||
    (response.maintenance.kind === "hosted-hold" && response.lease !== null)
  ) {
    throw new ProtocolMessageError("heartbeat response state is inconsistent");
  }
  if (
    response.lease !== null &&
    (response.lease.fleetId !== response.fleetId ||
      response.lease.sessionId !== response.sessionId ||
      response.lease.leaseGeneration !== response.maintenance.leaseGeneration)
  ) {
    throw new ProtocolMessageError("heartbeat lease binding is invalid");
  }
  if (response.lease !== null) {
    assertHeartbeatLeaseEnvelope(response);
  }
  return response;
}

function assertHeartbeatLeaseEnvelope(response: HeartbeatResponseV1): void {
  const lease = response.lease;
  if (lease === null) {
    return;
  }
  const receiptMs = Date.parse(response.receiptTime);
  const expiryMs = Date.parse(lease.expiry);
  const expectedExpiryMs = receiptMs + lease.durationMs;
  if (
    !Number.isSafeInteger(expectedExpiryMs) ||
    expectedExpiryMs !== expiryMs
  ) {
    throw new ProtocolMessageError("heartbeat lease expiry is invalid");
  }
  switch (response.routingState) {
    case "PORTABLE_CANARY":
      if (lease.holder !== "portable" || lease.mode !== "canary-only") {
        throw new ProtocolMessageError("heartbeat lease routing is invalid");
      }
      return;
    case "PORTABLE":
      if (
        lease.holder !== "portable" ||
        lease.mode !== "enabled" ||
        lease.canaryScaleSet !== null
      ) {
        throw new ProtocolMessageError("heartbeat lease routing is invalid");
      }
      return;
    case "LEGACY_CANARY":
      if (lease.holder !== "legacy" || lease.mode !== "canary-only") {
        throw new ProtocolMessageError("heartbeat lease routing is invalid");
      }
      return;
    case "LEGACY":
      if (
        lease.holder !== "legacy" ||
        lease.mode !== "enabled" ||
        lease.canaryScaleSet !== null
      ) {
        throw new ProtocolMessageError("heartbeat lease routing is invalid");
      }
      return;
    case "HOSTED":
    case "DRAINING_TO_HOSTED":
      throw new ProtocolMessageError("hosted routing cannot carry a lease");
  }
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
    durationMs: requireLeaseDuration(record.durationMs),
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
  if (lease.leaseGeneration < 1) {
    throw new ProtocolMessageError("lease generation is invalid");
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
  const terms = [
    budget.leaseDurationMs,
    budget.maxAttemptIntervalMs,
    budget.deadlineMs,
    budget.shorteningMarginMs,
    budget.lostRenewals,
  ];
  if (
    terms.some((term) => !Number.isSafeInteger(term) || term <= 0) ||
    budget.lostRenewals < 1
  ) {
    throw new ProtocolMessageError("heartbeat budget terms are incomplete");
  }
  const renewalCount = budget.lostRenewals + 1;
  const renewalWindow = renewalCount * budget.maxAttemptIntervalMs;
  const right = renewalWindow + budget.deadlineMs + budget.shorteningMarginMs;
  if (
    !Number.isSafeInteger(renewalCount) ||
    !Number.isSafeInteger(renewalWindow) ||
    !Number.isSafeInteger(right)
  ) {
    throw new ProtocolMessageError("heartbeat budget arithmetic is unsafe");
  }
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
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ProtocolMessageError("unsigned integer is invalid");
  }
  return value;
}

function parseHeartbeatSnapshot(value: unknown): HeartbeatSnapshotV1 {
  const record = asRecord(value);
  const capacity = asRecord(record.capacity);
  const snapshot: HeartbeatSnapshotV1 = {
    observedAt: requireTimestamp(record.observedAt),
    fleetAlias: requireFleetId(record.fleetAlias),
    acquisitionMode: requireAcquisitionMode(record.acquisitionMode),
    policyEpoch: requireUint(record.policyEpoch),
    policyDigest: requireHex64(record.policyDigest),
    repositoryPolicyRevision: requireUint(record.repositoryPolicyRevision),
    capacity: {
      configured: requireUint(capacity.configured),
      effective: requireUint(capacity.effective),
      occupied: requireUint(capacity.occupied),
      available: requireUint(capacity.available),
      queued: requireUint(capacity.queued),
    },
    assignedJobs: requireUint(record.assignedJobs),
    runningJobs: requireUint(record.runningJobs),
    oldestLiveAssignmentAgeMs: requireUint(record.oldestLiveAssignmentAgeMs),
    unassignedReleasedListeners: requireUint(
      record.unassignedReleasedListeners,
    ),
    lastTerminalAt: requireNullableTimestamp(record.lastTerminalAt),
    hostProfileId: requireHostProfileID(record.hostProfileId),
    degraded: requireBoolean(record.degraded),
    buildId: requireHex64(record.buildId),
  };
  assertExactKeys(capacity, [
    "available",
    "configured",
    "effective",
    "occupied",
    "queued",
  ]);
  assertExactKeys(record, [
    "acquisitionMode",
    "assignedJobs",
    "buildId",
    "capacity",
    "degraded",
    "fleetAlias",
    "hostProfileId",
    "lastTerminalAt",
    "observedAt",
    "oldestLiveAssignmentAgeMs",
    "policyDigest",
    "policyEpoch",
    "repositoryPolicyRevision",
    "runningJobs",
    "unassignedReleasedListeners",
  ]);
  const expectedAvailable = Math.max(
    snapshot.capacity.effective - snapshot.capacity.occupied,
    0,
  );
  if (
    snapshot.policyEpoch < 1 ||
    snapshot.repositoryPolicyRevision < 1 ||
    snapshot.capacity.effective > snapshot.capacity.configured ||
    snapshot.capacity.occupied > snapshot.capacity.configured ||
    snapshot.capacity.available > snapshot.capacity.effective ||
    snapshot.capacity.available !== expectedAvailable ||
    snapshot.runningJobs > snapshot.assignedJobs ||
    (snapshot.lastTerminalAt !== null &&
      snapshot.lastTerminalAt > snapshot.observedAt)
  ) {
    throw new ProtocolMessageError("heartbeat snapshot is inconsistent");
  }
  return snapshot;
}

function requireHolder(value: unknown): Holder {
  if (value === "portable" || value === "legacy" || value === "none") {
    return value;
  }
  throw new ProtocolMessageError("holder is invalid");
}

function requireAcquisitionMode(
  value: unknown,
): HeartbeatSnapshotV1["acquisitionMode"] {
  if (
    value === "disabled" ||
    value === "canary-only" ||
    value === "enabled" ||
    value === "fatal"
  ) {
    return value;
  }
  throw new ProtocolMessageError("acquisition mode is invalid");
}

function requireNullableTimestamp(value: unknown): string | null {
  return value === null ? null : requireTimestamp(value);
}

function requireHostProfileID(
  value: unknown,
): HeartbeatSnapshotV1["hostProfileId"] {
  if (value === "strict-linux-v1" || value === "qts-capless-root") {
    return value;
  }
  throw new ProtocolMessageError("host profile id is invalid");
}

function requireBoolean(value: unknown): boolean {
  if (typeof value !== "boolean") {
    throw new ProtocolMessageError("boolean field is invalid");
  }
  return value;
}

function parseMaintenanceDirective(value: unknown): MaintenanceDirectiveV1 {
  const record = asRecord(value);
  const directive: MaintenanceDirectiveV1 = {
    kind: requireMaintenanceKind(record.kind),
    sessionId: requireHex64(record.sessionId),
    leaseGeneration: requireUint(record.leaseGeneration),
  };
  assertExactKeys(record, ["kind", "leaseGeneration", "sessionId"]);
  if (directive.leaseGeneration < 1) {
    throw new ProtocolMessageError("maintenance generation is invalid");
  }
  return directive;
}

function requireMaintenanceKind(
  value: unknown,
): MaintenanceDirectiveV1["kind"] {
  if (value === "hosted-hold" || value === "none") {
    return value;
  }
  throw new ProtocolMessageError("maintenance kind is invalid");
}

function requireRoutingState(value: unknown): RoutingState {
  if (
    typeof value === "string" &&
    (ROUTING_STATES as readonly string[]).includes(value)
  ) {
    return value as RoutingState;
  }
  throw new ProtocolMessageError("routing state is invalid");
}

function requireNullableNoLeaseReason(value: unknown): NoLeaseReason | null {
  if (value === null) {
    return null;
  }
  if (typeof value !== "string") {
    throw new ProtocolMessageError("no-lease reason is invalid");
  }
  switch (value) {
    case "predecessor-lease-draining":
    case "fleet-not-inventoried":
    case "hosted-hold":
    case "stale-selector-evidence":
    case "queue-risk-open":
    case "invalid-request":
    case "clock-anomaly":
    case "policy-mismatch":
    case "capacity-zero":
    case "routing-hosted":
    case "lease-disabled":
      return value;
    default:
      throw new ProtocolMessageError("no-lease reason is invalid");
  }
}

function requireLeaseDuration(value: unknown): number {
  const next = requireUint(value);
  if (next <= 0 || next > MAX_LEASE_DURATION_MS) {
    throw new ProtocolMessageError("lease duration is invalid");
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
