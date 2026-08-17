import {
  bytesToHex,
  hexToBytes,
  signCanonical,
  verifyCanonical,
} from "../protocol/auth";
import { canonicalize } from "../protocol/canonical";
import {
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
  if (
    !store.rememberNonce(request.nonce, addMs(receiptTime, secrets.nonceTtlMs))
  ) {
    store.recordAudit("session-rejected-nonce");
    return reject();
  }
  const fleet = store.fleet;
  fleet.inventoried = true;
  fleet.epoch += 1;
  fleet.leaseGeneration += 1;
  fleet.sessionId = bytesToHex(hexToBytes(request.nonce));
  fleet.sequence = 0;
  fleet.holder = "none";
  const candidate =
    fleet.lastIssuedLeaseExpiryMax === null
      ? receiptTime
      : addMs(
          fleet.lastIssuedLeaseExpiryMax,
          secrets.hostedTransitionSafetyMarginMs,
        );
  fleet.leaseNotBefore = maxTimestamp([
    receiptTime,
    fleet.leaseNotBefore,
    candidate,
  ]);
  const response: SessionResponseV1 = {
    protocolVersion: HEARTBEAT_PROTOCOL_VERSION,
    fleetId: fleet.fleetId,
    nonce: request.nonce,
    epoch: fleet.epoch,
    sessionId: fleet.sessionId,
    sequence: fleet.sequence,
    leaseGeneration: fleet.leaseGeneration,
    leaseNotBefore: fleet.leaseNotBefore,
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
  store.recordAudit("session-accepted");
  return { status: 200, body, timestamp: receiptTime, macHex };
}
