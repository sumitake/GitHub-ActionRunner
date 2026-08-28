import { canonicalize } from "./canonical";

export const SESSION_PATH = "/v1/session";
export const HEARTBEAT_PATH = "/v1/heartbeat";
export const ADMIN_COMMAND_PATH = "/v1/admin/command";
export const ADMIN_STATUS_PATH = "/v1/admin/status";
export const TIMESTAMP_HEADER = "x-portable-ghar-timestamp";
export const MAC_HEADER = "x-portable-ghar-mac";

const CRON_REQUEST_MAC_DOMAIN = "portable-ghar-cron-request-v1";
const CRON_RESPONSE_MAC_DOMAIN = "portable-ghar-cron-response-v1";

const HEX = /^[0-9a-f]+$/;

export class ProtocolAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolAuthError";
  }
}

export function macInput(
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
): Uint8Array {
  return new TextEncoder().encode(
    macInputText(method, path, timestamp, canonicalBody),
  );
}

function macInputText(
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
): string {
  if (
    method !== "POST" ||
    !path.startsWith("/v1/") ||
    !isRfc3339MsZ(timestamp)
  ) {
    throw new ProtocolAuthError("mac input is invalid");
  }
  return `${method}\n${path}\n${timestamp}\n${canonicalBody}`;
}

export async function signCanonical(
  key: Uint8Array,
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
): Promise<string> {
  return signInput(key, macInput(method, path, timestamp, canonicalBody));
}

export async function signCronRequest(
  key: Uint8Array,
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
): Promise<string> {
  return signDomainSeparatedCanonical(
    key,
    CRON_REQUEST_MAC_DOMAIN,
    method,
    path,
    timestamp,
    canonicalBody,
  );
}

export async function signCronResponse(
  key: Uint8Array,
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
): Promise<string> {
  return signDomainSeparatedCanonical(
    key,
    CRON_RESPONSE_MAC_DOMAIN,
    method,
    path,
    timestamp,
    canonicalBody,
  );
}

export async function signDomainSeparatedCanonical(
  key: Uint8Array,
  domain: string,
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
): Promise<string> {
  return signInput(
    key,
    taggedMacInput(domain, method, path, timestamp, canonicalBody),
  );
}

async function signInput(key: Uint8Array, input: Uint8Array): Promise<string> {
  const cryptoKey = await importHmacKey(key);
  const mac = await crypto.subtle.sign("HMAC", cryptoKey, ownedBytes(input));
  return bytesToHex(new Uint8Array(mac));
}

export async function verifyCanonical(
  key: Uint8Array,
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
  presentedMacHex: string,
): Promise<void> {
  const expected = await signCanonical(
    key,
    method,
    path,
    timestamp,
    canonicalBody,
  );
  if (!constantTimeEqualHex(expected, presentedMacHex)) {
    throw new ProtocolAuthError("mac mismatch");
  }
}

export async function verifyCronRequest(
  key: Uint8Array,
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
  presentedMacHex: string,
): Promise<void> {
  const expected = await signCronRequest(
    key,
    method,
    path,
    timestamp,
    canonicalBody,
  );
  if (!constantTimeEqualHex(expected, presentedMacHex)) {
    throw new ProtocolAuthError("mac mismatch");
  }
}

export async function verifyCronResponse(
  key: Uint8Array,
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
  presentedMacHex: string,
): Promise<void> {
  const expected = await signCronResponse(
    key,
    method,
    path,
    timestamp,
    canonicalBody,
  );
  if (!constantTimeEqualHex(expected, presentedMacHex)) {
    throw new ProtocolAuthError("mac mismatch");
  }
}

export async function verifyDomainSeparatedCanonical(
  key: Uint8Array,
  domain: string,
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
  presentedMacHex: string,
): Promise<void> {
  const expected = await signDomainSeparatedCanonical(
    key,
    domain,
    method,
    path,
    timestamp,
    canonicalBody,
  );
  if (!constantTimeEqualHex(expected, presentedMacHex)) {
    throw new ProtocolAuthError("mac mismatch");
  }
}

function taggedMacInput(
  domain: string,
  method: string,
  path: string,
  timestamp: string,
  canonicalBody: string,
): Uint8Array {
  return new TextEncoder().encode(
    `${domain}\n${macInputText(method, path, timestamp, canonicalBody)}`,
  );
}

export function assertTimestampWindow(
  receiptTime: string,
  requestTimestamp: string,
  windowMs: number,
): void {
  if (
    windowMs <= 0 ||
    !isRfc3339MsZ(receiptTime) ||
    !isRfc3339MsZ(requestTimestamp)
  ) {
    throw new ProtocolAuthError("timestamp window is invalid");
  }
  const receipt = Date.parse(receiptTime);
  const request = Date.parse(requestTimestamp);
  if (!Number.isFinite(receipt) || !Number.isFinite(request)) {
    throw new ProtocolAuthError("timestamp window is invalid");
  }
  const delta = receipt - request;
  if (delta < -windowMs || delta > windowMs) {
    throw new ProtocolAuthError("timestamp outside window");
  }
}

export function encodeSignedBody(value: unknown): string {
  return canonicalize(value);
}

export function isRfc3339MsZ(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    return false;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0 || hex.length % 2 !== 0 || !HEX.test(hex)) {
    throw new ProtocolAuthError("hex encoding is invalid");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function constantTimeEqualHex(left: string, right: string): boolean {
  if (left.length !== right.length || !HEX.test(left) || !HEX.test(right)) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < left.length; i += 1) {
    mismatch |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return mismatch === 0;
}

async function importHmacKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.byteLength < 32) {
    throw new ProtocolAuthError("hmac key is too short");
  }
  return crypto.subtle.importKey(
    "raw",
    ownedBytes(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function ownedBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const owned = new Uint8Array(new ArrayBuffer(value.byteLength));
  owned.set(value);
  return owned;
}
