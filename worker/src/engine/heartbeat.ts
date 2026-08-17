import { signCanonical, verifyCanonical } from "../protocol/auth";
import { canonicalize, parseCanonical } from "../protocol/canonical";
import {
  parseLease,
  type AcquisitionLeaseV1,
  type HeartbeatResponseV1,
  type NoLeaseReason,
  type RoutingState,
} from "../protocol/messages";
import { HEARTBEAT_PROTOCOL_VERSION } from "../protocol/version";
import { isLocalAuthorityState } from "../routing/machine";
import { noLease, type MemoryFleetStore } from "../state/memory";

export type HeartbeatSecrets = {
  hmacKey: Uint8Array;
  timestampWindowMs: number;
  leaseDurationMs: number;
  archiveEvidenceMaxAgeMs: number;
  selectorEvidenceMaxAgeMs: number;
};

export type HeartbeatInput = {
  method: string;
  path: string;
  timestamp: string;
  macHex: string;
  body: string;
  inventoried: boolean;
};

type HeartbeatRequest = {
  protocolVersion: number;
  fleetId: string;
  epoch: number;
  sessionId: string;
  sequence: number;
  holder: "portable" | "legacy" | "none";
  fenceGeneration: number;
  timestamp: string;
  snapshot: {
    policyEpoch: number;
    policyDigest: string;
    repositoryPolicyRevision: number;
    acquisitionMode: string;
    unassignedReleasedListeners: number;
  };
};

function addMs(timestamp: string, deltaMs: number): string {
  return new Date(Date.parse(timestamp) + deltaMs)
    .toISOString()
    .replace(/\.(\d{3})\d*Z$/, ".$1Z");
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
  let request: HeartbeatRequest;
  try {
    await verifyCanonical(
      secrets.hmacKey,
      input.method,
      input.path,
      input.timestamp,
      input.body,
      input.macHex,
    );
    request = parseCanonical(input.body) as HeartbeatRequest;
    if (
      request.protocolVersion !== HEARTBEAT_PROTOCOL_VERSION ||
      request.fleetId !== store.fleet.fleetId ||
      request.timestamp !== input.timestamp
    ) {
      throw new Error("binding");
    }
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
  fleet.holder = request.holder;
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
  request: HeartbeatRequest,
  receiptTime: string,
): NoLeaseReason | null {
  const fleet = store.fleet;
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
    const evidenceAt = repository.selectorEvidenceAt;
    if (
      evidenceAt === null ||
      Date.parse(receiptTime) - Date.parse(evidenceAt) >
        secrets.selectorEvidenceMaxAgeMs
    ) {
      fleet.leaseGeneration += 1;
      store.enqueue({
        id: `hosted-${fleet.leaseGeneration}`,
        kind: "github-mutate-route",
        dueAt: receiptTime,
        claimId: null,
        claimExpiresAt: null,
        attempts: 0,
        status: "ready",
        payload: { route: "hosted" },
      });
      return "stale-selector-evidence";
    }
  }
  if (
    request.snapshot.acquisitionMode === "disabled" ||
    request.snapshot.acquisitionMode === "fatal"
  ) {
    return "lease-disabled";
  }
  return null;
}

function issueLease(
  store: MemoryFleetStore,
  secrets: HeartbeatSecrets,
  request: HeartbeatRequest,
  receiptTime: string,
): AcquisitionLeaseV1 {
  const fleet = store.fleet;
  const aliases = [...store.repositories.values()]
    .filter((repository) => {
      if (repository.archiveLatched) {
        return true;
      }
      if (repository.archiveObservedAt === null) {
        return true;
      }
      return (
        repository.archived ||
        Date.parse(receiptTime) - Date.parse(repository.archiveObservedAt) >
          secrets.archiveEvidenceMaxAgeMs
      );
    })
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
    policyDigest: request.snapshot.policyDigest,
    repositoryPolicyRevision: request.snapshot.repositoryPolicyRevision,
    localPolicyEpoch: request.snapshot.policyEpoch,
    maxCapacity: mode === "canary-only" ? 1 : 2,
    canaryScaleSet: mode === "canary-only" ? "canary-set" : null,
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
