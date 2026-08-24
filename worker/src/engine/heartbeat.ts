import {
  assertTimestampWindow,
  signCanonical,
  verifyCanonical,
} from "../protocol/auth";
import { canonicalize } from "../protocol/canonical";
import {
  parseHeartbeatRequest,
  parseLease,
  type AcquisitionLeaseV1,
  type HeartbeatRequestV1,
  type HeartbeatResponseV1,
  HEX64,
  type NoLeaseReason,
  type RoutingState,
} from "../protocol/messages";
import { HEARTBEAT_PROTOCOL_VERSION } from "../protocol/version";
import { encodeCanaryEvidence, type CanaryEvidence } from "../routing/canary";
import { archiveRestrictionReason } from "../routing/archive";
import { enqueueRepositoryRoutes } from "../github/outbox";
import { assertTransition, isLocalAuthorityState } from "../routing/machine";
import { QUEUE_RISK_REASON, type QueueRiskRecord } from "../routing/queue-risk";
import { selectorRestrictionReason } from "../routing/selector";
import {
  nextTransitionRecord,
  noLease,
  type DueWorkRecord,
  type MemoryFleetStore,
} from "../state/memory";

export type HeartbeatSecrets = {
  hmacKey: Uint8Array;
  timestampWindowMs: number;
  leaseDurationMs: number;
  archiveEvidenceMaxAgeMs: number;
  selectorEvidenceMaxAgeMs: number;
  hostedTransitionSafetyMarginMs: number;
};

export type HeartbeatInput = {
  method: string;
  path: string;
  timestamp: string;
  macHex: string;
  body: string;
  inventoried: boolean;
};

function addMs(timestamp: string, deltaMs: number): string {
  return new Date(Date.parse(timestamp) + deltaMs)
    .toISOString()
    .replace(/\.(\d{3})\d*Z$/, ".$1Z");
}

function maxTimestamp(values: readonly (string | null)[]): string {
  const filtered = values.filter((value): value is string => value !== null);
  if (
    filtered.length === 0 ||
    filtered.some((value) => !Number.isFinite(Date.parse(value)))
  ) {
    throw new Error("heartbeat boundary is invalid");
  }
  return filtered.reduce((latest, value) => (value > latest ? value : latest));
}

export async function handleHeartbeat(
  store: MemoryFleetStore,
  secrets: HeartbeatSecrets,
  input: HeartbeatInput,
): Promise<{
  status: number;
  body: string;
  timestamp: string;
  macHex: string;
}> {
  const receiptTime = store.now();
  const reject = async () => {
    const body = canonicalize({ error: "rejected" });
    const macHex = await signCanonical(
      secrets.hmacKey,
      "POST",
      input.path,
      receiptTime,
      body,
    );
    return { status: 401, body, timestamp: receiptTime, macHex };
  };
  if (
    !input.inventoried ||
    input.method !== "POST" ||
    input.path !== "/v1/heartbeat"
  ) {
    return reject();
  }
  let request: HeartbeatRequestV1;
  try {
    await verifyCanonical(
      secrets.hmacKey,
      input.method,
      input.path,
      input.timestamp,
      input.body,
      input.macHex,
    );
    request = parseHeartbeatRequest(input.body);
    if (
      request.protocolVersion !== HEARTBEAT_PROTOCOL_VERSION ||
      request.fleetId !== store.fleet.fleetId ||
      request.timestamp !== input.timestamp
    ) {
      throw new Error("binding");
    }
    assertTimestampWindow(
      receiptTime,
      request.timestamp,
      secrets.timestampWindowMs,
    );
    assertTimestampWindow(
      request.timestamp,
      request.snapshot.observedAt,
      secrets.timestampWindowMs,
    );
  } catch {
    return reject();
  }
  const fleet = store.fleet;
  if (request.sessionId !== fleet.sessionId || request.epoch !== fleet.epoch) {
    const body = encodeResponse(store, receiptTime, null, "invalid-request");
    const macHex = await signCanonical(
      secrets.hmacKey,
      "POST",
      input.path,
      receiptTime,
      body,
    );
    store.recordAudit("heartbeat-old-session");
    return { status: 200, body, timestamp: receiptTime, macHex };
  }
  if (request.sequence <= fleet.sequence) {
    return reject();
  }
  fleet.sequence = request.sequence;
  if (legacyRouteCommitPending(store)) {
    const body = encodeResponse(
      store,
      receiptTime,
      null,
      "predecessor-lease-draining",
    );
    const macHex = await signCanonical(
      secrets.hmacKey,
      "POST",
      input.path,
      receiptTime,
      body,
    );
    store.recordAudit("heartbeat-legacy-route-commit-pending");
    return { status: 200, body, timestamp: receiptTime, macHex };
  }
  if (fleet.leaseNotBefore !== null && receiptTime < fleet.leaseNotBefore) {
    const body = encodeResponse(
      store,
      receiptTime,
      null,
      "predecessor-lease-draining",
    );
    const macHex = await signCanonical(
      secrets.hmacKey,
      "POST",
      input.path,
      receiptTime,
      body,
    );
    store.recordAudit("heartbeat-predecessor-drain");
    return { status: 200, body, timestamp: receiptTime, macHex };
  }
  const reason = evaluateLease(store, secrets, request, receiptTime);
  if (reason !== null) {
    const body = encodeResponse(store, receiptTime, null, reason);
    const macHex = await signCanonical(
      secrets.hmacKey,
      "POST",
      input.path,
      receiptTime,
      body,
    );
    return { status: 200, body, timestamp: receiptTime, macHex };
  }
  const localRoute = readyLocalRoute(fleet, request);
  if (localRoute !== null) {
    const nonAuthorizing = enqueueNamedRoute(
      store,
      receiptTime,
      localRoute.value,
      localRoute.evidence,
      secrets.hostedTransitionSafetyMarginMs,
    );
    if (nonAuthorizing) {
      const body = encodeResponse(
        store,
        receiptTime,
        null,
        "predecessor-lease-draining",
      );
      const macHex = await signCanonical(
        secrets.hmacKey,
        "POST",
        input.path,
        receiptTime,
        body,
      );
      store.recordAudit("heartbeat-legacy-route-commit-started");
      return { status: 200, body, timestamp: receiptTime, macHex };
    }
  }
  const lease = issueLease(store, secrets, request, receiptTime);
  const body = encodeResponse(store, receiptTime, lease, null);
  const macHex = await signCanonical(
    secrets.hmacKey,
    "POST",
    input.path,
    receiptTime,
    body,
  );
  store.recordAudit("heartbeat-lease-issued");
  return { status: 200, body, timestamp: receiptTime, macHex };
}

function evaluateLease(
  store: MemoryFleetStore,
  secrets: HeartbeatSecrets,
  request: HeartbeatRequestV1,
  receiptTime: string,
): NoLeaseReason | null {
  const fleet = store.fleet;
  if (
    isLocalAuthorityState(fleet.routingState) &&
    !fenceMatches(fleet, request)
  ) {
    return "invalid-request";
  }
  if (fleet.hostedHold) {
    return "hosted-hold";
  }
  if (
    fleet.routingState === "UNINITIALIZED" ||
    fleet.routingState === "HOSTED" ||
    fleet.routingState === "DRAINING_TO_HOSTED"
  ) {
    return "routing-hosted";
  }
  if (!isLocalAuthorityState(fleet.routingState)) {
    return "routing-hosted";
  }
  for (const repository of store.repositories.values()) {
    if (repository.openQueueRisk !== null) {
      return "queue-risk-open";
    }
    if (
      selectorRestrictionReason(
        repository,
        receiptTime,
        secrets.selectorEvidenceMaxAgeMs,
      ) !== null
    ) {
      try {
        beginHostedDrain(
          store,
          secrets,
          receiptTime,
          fleet.policyDigest !== null && HEX64.test(fleet.policyDigest)
            ? fleet.policyDigest
            : request.snapshot.policyDigest,
        );
      } catch {
        store.recordAudit("hosted-drain-deferred");
      }
      return "stale-selector-evidence";
    }
  }
  if (
    fleet.policyDigest === null ||
    fleet.policyDigest !== request.snapshot.policyDigest ||
    fleet.configRevision !== request.snapshot.repositoryPolicyRevision
  ) {
    return "policy-mismatch";
  }
  if (
    fleet.routingState === "PORTABLE_CANARY" ||
    fleet.routingState === "LEGACY_CANARY"
  ) {
    if (fleet.canaryScaleSet === null) {
      return "policy-mismatch";
    }
  } else if (fleet.maxCapacity < 1) {
    return "capacity-zero";
  }
  const mode = request.snapshot.acquisitionMode;
  if (mode !== "enabled" && mode !== "canary-only") {
    return "lease-disabled";
  }
  if (
    (fleet.routingState === "PORTABLE" || fleet.routingState === "LEGACY") &&
    mode !== "enabled"
  ) {
    return "lease-disabled";
  }
  return null;
}

function fenceMatches(
  fleet: MemoryFleetStore["fleet"],
  request: HeartbeatRequestV1,
): boolean {
  if (
    fleet.fenceGeneration < 1 ||
    request.fenceGeneration !== fleet.fenceGeneration
  ) {
    return false;
  }
  const holder = expectedHolder(fleet.routingState);
  return holder !== null && request.holder === holder;
}

function expectedHolder(
  state: MemoryFleetStore["fleet"]["routingState"],
): "portable" | "legacy" | null {
  if (state === "PORTABLE" || state === "PORTABLE_CANARY") {
    return "portable";
  }
  if (state === "LEGACY" || state === "LEGACY_CANARY") {
    return "legacy";
  }
  return null;
}

function readyLocalRoute(
  fleet: MemoryFleetStore["fleet"],
  request: HeartbeatRequestV1,
): { value: "self-hosted" | "legacy"; evidence: CanaryEvidence } | null {
  const evidence = fleet.canaryEvidence;
  if (
    evidence === null ||
    fleet.sessionId === null ||
    evidence.sessionId !== fleet.sessionId ||
    evidence.sessionId !== request.sessionId ||
    evidence.leaseGeneration !== fleet.leaseGeneration ||
    evidence.scaleSet !== fleet.canaryScaleSet ||
    request.sequence <= evidence.heartbeatSequence ||
    request.snapshot.acquisitionMode !== "enabled" ||
    request.snapshot.capacity.configured !== fleet.maxCapacity ||
    request.snapshot.capacity.effective !== fleet.maxCapacity ||
    fleet.maxCapacity < 1
  ) {
    return null;
  }
  if (fleet.routingState === "PORTABLE_CANARY") {
    return { value: "self-hosted", evidence };
  }
  if (fleet.routingState === "LEGACY_CANARY") {
    return { value: "legacy", evidence };
  }
  return null;
}

function beginHostedDrain(
  store: MemoryFleetStore,
  secrets: HeartbeatSecrets,
  receiptTime: string,
  evidenceDigest: string,
): void {
  const from = store.fleet.routingState;
  if (!isLocalAuthorityState(from) || !HEX64.test(evidenceDigest)) {
    throw new Error("hosted drain identity is invalid");
  }
  assertTransition(from, "DRAINING_TO_HOSTED");
  const transition = nextTransitionRecord(store, from, "DRAINING_TO_HOSTED");
  const nextLeaseGeneration = store.fleet.leaseGeneration + 1;
  if (!Number.isSafeInteger(nextLeaseGeneration)) {
    throw new Error("hosted drain generation is exhausted");
  }
  const dueAt =
    store.fleet.lastIssuedLeaseExpiryMax === null ||
    !(secrets.hostedTransitionSafetyMarginMs > 0)
      ? receiptTime
      : addMs(
          store.fleet.lastIssuedLeaseExpiryMax,
          secrets.hostedTransitionSafetyMarginMs,
        );
  const revision = String(nextLeaseGeneration);
  const pending = hasBlockingExactRouteOutcome(store, revision, "hosted");
  if (!pending) {
    enqueueRepositoryRoutes(store, dueAt, "hosted", nextLeaseGeneration);
  }
  const risk: QueueRiskRecord = {
    transitionEpoch: transition.epoch,
    sourceHead: "unknown",
    evidenceDigest,
    reason: QUEUE_RISK_REASON,
  };
  supersedeStaleRouteIntents(store, revision, "hosted");
  for (const repository of store.repositories.values()) {
    if (repository.confirmedRoute !== "hosted") {
      repository.openQueueRisk = { ...risk };
    }
  }
  store.transitions.push(transition);
  store.fleet.routingState = "DRAINING_TO_HOSTED";
  store.fleet.canaryEvidence = null;
  store.fleet.leaseGeneration = nextLeaseGeneration;
}

function enqueueNamedRoute(
  store: MemoryFleetStore,
  now: string,
  value: "self-hosted" | "legacy",
  canaryEvidence: CanaryEvidence,
  hostedTransitionSafetyMarginMs: number,
): boolean {
  const currentRevision = String(store.fleet.leaseGeneration);
  if (hasBlockingExactRouteOutcome(store, currentRevision, value)) {
    return value === "legacy";
  }
  const nextGeneration = store.fleet.leaseGeneration + 1;
  if (!Number.isSafeInteger(nextGeneration)) {
    throw new Error("route generation is exhausted");
  }
  const dueAt =
    value === "legacy"
      ? maxTimestamp([
          now,
          store.fleet.leaseNotBefore,
          store.fleet.lastIssuedLeaseExpiryMax === null
            ? now
            : addMs(
                store.fleet.lastIssuedLeaseExpiryMax,
                hostedTransitionSafetyMarginMs,
              ),
        ])
      : now;
  enqueueRepositoryRoutes(
    store,
    dueAt,
    value,
    nextGeneration,
    encodeCanaryEvidence(canaryEvidence),
  );
  store.fleet.leaseGeneration = nextGeneration;
  if (value === "legacy") {
    store.fleet.leaseNotBefore = dueAt;
  }
  supersedeStaleRouteIntents(store, String(nextGeneration), value);
  return value === "legacy";
}

function legacyRouteCommitPending(store: MemoryFleetStore): boolean {
  const evidence = store.fleet.canaryEvidence;
  return (
    store.fleet.routingState === "LEGACY_CANARY" &&
    ((evidence !== null &&
      evidence.leaseGeneration < store.fleet.leaseGeneration) ||
      store.dueWork.some(
        (row) =>
          row.kind === "github-mutate-route" &&
          row.payload.value === "legacy" &&
          row.payload.transitionRevision ===
            String(store.fleet.leaseGeneration),
      ))
  );
}

function hasBlockingExactRouteOutcome(
  store: MemoryFleetStore,
  transitionRevision: string,
  value: string,
): boolean {
  return store.dueWork.some(
    (row) =>
      row.kind === "github-mutate-route" &&
      row.payload.name === "PORTABLE_GHAR_ROUTE" &&
      row.payload.transitionRevision === transitionRevision &&
      row.payload.value === value &&
      row.status !== "done",
  );
}

function supersedeStaleRouteIntents(
  store: MemoryFleetStore,
  transitionRevision: string,
  value: string,
): void {
  for (const row of store.dueWork) {
    if (
      row.kind !== "github-mutate-route" ||
      row.payload.name !== "PORTABLE_GHAR_ROUTE" ||
      (row.payload.transitionRevision === transitionRevision &&
        row.payload.value === value)
    ) {
      continue;
    }
    if (row.status === "ready") {
      finishSupersededRoute(store, row, "failed");
    } else if (row.status === "claimed") {
      finishSupersededRoute(store, row, "uncertain");
    }
  }
}

function finishSupersededRoute(
  store: MemoryFleetStore,
  row: DueWorkRecord,
  status: Extract<DueWorkRecord["status"], "failed" | "uncertain">,
): void {
  row.status = status;
  row.claimId = null;
  row.claimExpiresAt = null;
  store.recordAudit(`github-route-superseded:${row.id}:${status}`);
}

function issueLease(
  store: MemoryFleetStore,
  secrets: HeartbeatSecrets,
  request: HeartbeatRequestV1,
  receiptTime: string,
): AcquisitionLeaseV1 {
  const fleet = store.fleet;
  const aliases = [...store.repositories.values()]
    .filter(
      (repository) =>
        archiveRestrictionReason(
          repository,
          receiptTime,
          secrets.archiveEvidenceMaxAgeMs,
        ) !== null,
    )
    .map((repository) => repository.alias)
    .sort();
  const mode =
    fleet.routingState === "PORTABLE_CANARY" ||
    fleet.routingState === "LEGACY_CANARY"
      ? "canary-only"
      : "enabled";
  const holder = fleet.routingState.startsWith("LEGACY")
    ? "legacy"
    : "portable";
  const expiry = addMs(receiptTime, secrets.leaseDurationMs);
  const lease = parseLease({
    protocolVersion: HEARTBEAT_PROTOCOL_VERSION,
    fleetId: fleet.fleetId,
    holder,
    serverEpoch: fleet.epoch,
    sessionId: request.sessionId,
    leaseGeneration: fleet.leaseGeneration,
    mode,
    policyDigest: requirePolicyDigest(fleet.policyDigest),
    repositoryPolicyRevision: fleet.configRevision,
    localPolicyEpoch: request.snapshot.policyEpoch,
    maxCapacity: mode === "canary-only" ? 1 : fleet.maxCapacity,
    canaryScaleSet: mode === "canary-only" ? fleet.canaryScaleSet : null,
    archivedDisabledAliases: aliases,
    durationMs: secrets.leaseDurationMs,
    expiry,
  });
  if (
    fleet.lastIssuedLeaseExpiryMax === null ||
    expiry > fleet.lastIssuedLeaseExpiryMax
  ) {
    fleet.lastIssuedLeaseExpiryMax = expiry;
  }
  fleet.holder = holder;
  return lease;
}

function requirePolicyDigest(digest: string | null): string {
  if (digest === null) {
    throw new Error("worker policy digest is unset");
  }
  return digest;
}

function encodeResponse(
  store: MemoryFleetStore,
  receiptTime: string,
  lease: AcquisitionLeaseV1 | null,
  reason: NoLeaseReason | null,
): string {
  const routingState: RoutingState =
    store.fleet.routingState === "UNINITIALIZED"
      ? "HOSTED"
      : store.fleet.routingState;
  const response: HeartbeatResponseV1 = {
    protocolVersion: HEARTBEAT_PROTOCOL_VERSION,
    fleetId: store.fleet.fleetId,
    sessionId: store.fleet.sessionId ?? "0".repeat(64),
    sequence: store.fleet.sequence,
    receiptTime,
    routingState,
    maintenance: {
      kind: store.fleet.hostedHold ? "hosted-hold" : "none",
      sessionId: store.fleet.sessionId ?? "0".repeat(64),
      leaseGeneration: store.fleet.leaseGeneration,
    },
    lease,
    noLeaseReason: reason === null ? null : noLease(reason).noLeaseReason,
  };
  return canonicalize(response);
}
