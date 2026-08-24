import { bytesToHex, signCanonical, verifyCanonical } from "../protocol/auth";
import { canonicalize } from "../protocol/canonical";
import {
  HEX64,
  parseSessionRequest,
  type SessionRequestV1,
  type SessionResponseV1,
} from "../protocol/messages";
import { HEARTBEAT_PROTOCOL_VERSION } from "../protocol/version";
import type { MemoryFleetStore } from "../state/memory";

export type SessionSecrets = {
  hmacKey: Uint8Array;
  timestampWindowMs: number;
  nonceTtlMs: number;
  hostedTransitionSafetyMarginMs: number;
};

export type SessionInput = {
  method: string;
  path: string;
  timestamp: string;
  macHex: string;
  body: string;
  inventoried: boolean;
};

export type SessionIDSource = () => string;

function randomSessionID(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function addMs(timestamp: string, deltaMs: number): string {
  return new Date(Date.parse(timestamp) + deltaMs)
    .toISOString()
    .replace(/\.(\d{3})\d*Z$/, ".$1Z");
}

function maxTimestamp(values: Array<string | null>): string {
  return (
    values
      .filter((value): value is string => value !== null)
      .sort()
      .at(-1) ?? ""
  );
}

export async function handleSession(
  store: MemoryFleetStore,
  secrets: SessionSecrets,
  input: SessionInput,
  sessionIDSource: SessionIDSource = randomSessionID,
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
    input.path !== "/v1/session"
  ) {
    store.recordAudit("session-rejected-inventory-or-path");
    return reject();
  }
  let request: SessionRequestV1;
  try {
    await verifyCanonical(
      secrets.hmacKey,
      input.method,
      input.path,
      input.timestamp,
      input.body,
      input.macHex,
    );
    request = parseSessionRequest(input.body);
    if (
      request.fleetId !== store.fleet.fleetId ||
      request.timestamp !== input.timestamp
    ) {
      throw new Error("binding");
    }
    const receipt = Date.parse(receiptTime);
    const sent = Date.parse(request.timestamp);
    if (
      receipt - sent > secrets.timestampWindowMs ||
      sent - receipt > secrets.timestampWindowMs
    ) {
      throw new Error("window");
    }
  } catch {
    store.recordAudit("session-rejected-auth");
    return reject();
  }
  store.expireNonces(receiptTime);
  if (store.nonces.has(request.nonce)) {
    store.recordAudit("session-rejected-nonce");
    return reject();
  }
  const fleet = store.fleet;
  let sessionId: string;
  try {
    sessionId = sessionIDSource();
    if (!HEX64.test(sessionId) || sessionId === request.nonce) {
      throw new Error("session identity");
    }
  } catch {
    store.recordAudit("session-rejected-session-id");
    return reject();
  }
  const nextEpoch = fleet.epoch + 1;
  const nextLeaseGeneration = fleet.leaseGeneration + 1;
  if (
    !Number.isSafeInteger(nextEpoch) ||
    !Number.isSafeInteger(nextLeaseGeneration)
  ) {
    store.recordAudit("session-rejected-counter-overflow");
    return reject();
  }
  const candidate =
    fleet.lastIssuedLeaseExpiryMax === null
      ? receiptTime
      : addMs(
          fleet.lastIssuedLeaseExpiryMax,
          secrets.hostedTransitionSafetyMarginMs,
        );
  const leaseNotBefore = maxTimestamp([
    receiptTime,
    fleet.leaseNotBefore,
    candidate,
  ]);
  const response: SessionResponseV1 = {
    protocolVersion: HEARTBEAT_PROTOCOL_VERSION,
    fleetId: fleet.fleetId,
    nonce: request.nonce,
    epoch: nextEpoch,
    sessionId,
    sequence: 0,
    leaseGeneration: nextLeaseGeneration,
    leaseNotBefore,
    receiptTime,
  };
  const body = canonicalize(response);
  const macHex = await signCanonical(
    secrets.hmacKey,
    "POST",
    input.path,
    receiptTime,
    body,
  );
  if (
    !store.rememberNonce(request.nonce, addMs(receiptTime, secrets.nonceTtlMs))
  ) {
    store.recordAudit("session-rejected-nonce");
    return reject();
  }
  fleet.inventoried = true;
  fleet.epoch = nextEpoch;
  fleet.leaseGeneration = nextLeaseGeneration;
  fleet.sessionId = sessionId;
  fleet.sequence = 0;
  fleet.holder = "none";
  fleet.leaseNotBefore = leaseNotBefore;
  fleet.canaryEvidence = null;
  store.recordAudit("session-accepted");
  return { status: 200, body, timestamp: receiptTime, macHex };
}
