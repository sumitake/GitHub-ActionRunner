import { bytesToHex, isRfc3339MsZ } from "./auth";
import { canonicalize, parseCanonical } from "./canonical";
import { FLEET_ID, HEX64 } from "./messages";

export const CRON_PATH = "/v1/internal/cron";
export const CRON_ADDRESS_PROTOCOL_VERSION = 1 as const;
export const ADDRESS_ONLY_AUTHORITY_DISABLED = true;

const INVENTORY_PROTOCOL = "cron-address-v1";
const MAX_UINT64 = 18_446_744_073_709_551_615n;
const UINT64_DECIMAL = /^[1-9][0-9]{0,19}$/;

export type CronAddressRequestV1 = {
  protocolVersion: typeof CRON_ADDRESS_PROTOCOL_VERSION;
  fleetId: string;
  fleetIds: string[];
  revision: string;
  inventoryDigest: string;
  nonce: string;
  tickTimestamp: string;
  deadline: string;
};

export type CronAddressResponseV1 = {
  protocolVersion: typeof CRON_ADDRESS_PROTOCOL_VERSION;
  fleetId: string;
  revision: string;
  inventoryDigest: string;
  nonce: string;
  tickTimestamp: string;
  deadline: string;
  receiptTime: string;
  persistenceGeneration: number;
};

export class CronProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CronProtocolError";
  }
}

export function isCanonicalInventoryRevision(value: string): boolean {
  if (!UINT64_DECIMAL.test(value)) {
    return false;
  }
  try {
    return BigInt(value) <= MAX_UINT64;
  } catch {
    return false;
  }
}

export function isCanonicalCronTimestamp(value: string): boolean {
  if (!isRfc3339MsZ(value)) {
    return false;
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    return false;
  }
  try {
    return new Date(parsed).toISOString() === value;
  } catch {
    return false;
  }
}

export function requireCanonicalFleetIds(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new CronProtocolError("fleet inventory is invalid");
  }
  const fleetIds = value.map((item) => {
    if (typeof item !== "string" || !FLEET_ID.test(item)) {
      throw new CronProtocolError("fleet inventory is invalid");
    }
    return item;
  });
  for (let index = 1; index < fleetIds.length; index += 1) {
    if (fleetIds[index]! <= fleetIds[index - 1]!) {
      throw new CronProtocolError("fleet inventory is not canonical");
    }
  }
  return fleetIds;
}

export async function inventoryDigest(
  revision: string,
  fleetIds: string[],
): Promise<string> {
  requireRevision(revision);
  const canonicalFleetIds = requireCanonicalFleetIds(fleetIds);
  const preimage = canonicalize({
    protocol: INVENTORY_PROTOCOL,
    revision,
    fleetIds: canonicalFleetIds,
  });
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(preimage),
  );
  return bytesToHex(new Uint8Array(digest));
}

export function deadlineForTick(
  tickTimestamp: string,
  deadlineMs: number,
): string {
  if (
    !isCanonicalCronTimestamp(tickTimestamp) ||
    !Number.isSafeInteger(deadlineMs) ||
    deadlineMs <= 0
  ) {
    throw new CronProtocolError("Cron deadline terms are invalid");
  }
  const tickMs = Date.parse(tickTimestamp);
  const deadlineValue = tickMs + deadlineMs;
  if (!Number.isSafeInteger(deadlineValue)) {
    throw new CronProtocolError("Cron deadline overflows");
  }
  let deadline: string;
  try {
    deadline = new Date(deadlineValue).toISOString();
  } catch {
    throw new CronProtocolError("Cron deadline overflows");
  }
  if (!isRfc3339MsZ(deadline)) {
    throw new CronProtocolError("Cron deadline overflows");
  }
  return deadline;
}

export function parseCronAddressRequest(body: string): CronAddressRequestV1 {
  const value = asRecord(parseCanonical(body));
  const request: CronAddressRequestV1 = {
    protocolVersion: requireVersion(value.protocolVersion),
    fleetId: requireFleetId(value.fleetId),
    fleetIds: requireCanonicalFleetIds(value.fleetIds),
    revision: requireRevision(value.revision),
    inventoryDigest: requireHex64(value.inventoryDigest),
    nonce: requireHex64(value.nonce),
    tickTimestamp: requireTimestamp(value.tickTimestamp),
    deadline: requireTimestamp(value.deadline),
  };
  assertExactKeys(value, [
    "deadline",
    "fleetId",
    "fleetIds",
    "inventoryDigest",
    "nonce",
    "protocolVersion",
    "revision",
    "tickTimestamp",
  ]);
  if (!request.fleetIds.includes(request.fleetId)) {
    throw new CronProtocolError("addressed fleet is not inventoried");
  }
  if (request.deadline <= request.tickTimestamp) {
    throw new CronProtocolError("Cron deadline is not after its tick");
  }
  return request;
}

export function parseCronAddressResponse(body: string): CronAddressResponseV1 {
  const value = asRecord(parseCanonical(body));
  const response: CronAddressResponseV1 = {
    protocolVersion: requireVersion(value.protocolVersion),
    fleetId: requireFleetId(value.fleetId),
    revision: requireRevision(value.revision),
    inventoryDigest: requireHex64(value.inventoryDigest),
    nonce: requireHex64(value.nonce),
    tickTimestamp: requireTimestamp(value.tickTimestamp),
    deadline: requireTimestamp(value.deadline),
    receiptTime: requireTimestamp(value.receiptTime),
    persistenceGeneration: requirePositiveSafeInt(value.persistenceGeneration),
  };
  assertExactKeys(value, [
    "deadline",
    "fleetId",
    "inventoryDigest",
    "nonce",
    "persistenceGeneration",
    "protocolVersion",
    "receiptTime",
    "revision",
    "tickTimestamp",
  ]);
  if (
    response.deadline <= response.tickTimestamp ||
    response.receiptTime < response.tickTimestamp ||
    response.receiptTime > response.deadline
  ) {
    throw new CronProtocolError("Cron response time is invalid");
  }
  return response;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CronProtocolError("Cron protocol value is not an object");
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
    throw new CronProtocolError("Cron protocol fields are not exact");
  }
}

function requireVersion(value: unknown): typeof CRON_ADDRESS_PROTOCOL_VERSION {
  if (value !== CRON_ADDRESS_PROTOCOL_VERSION) {
    throw new CronProtocolError("Cron protocol version is invalid");
  }
  return CRON_ADDRESS_PROTOCOL_VERSION;
}

function requireFleetId(value: unknown): string {
  if (typeof value !== "string" || !FLEET_ID.test(value)) {
    throw new CronProtocolError("fleet id is invalid");
  }
  return value;
}

function requireRevision(value: unknown): string {
  if (typeof value !== "string" || !isCanonicalInventoryRevision(value)) {
    throw new CronProtocolError("inventory revision is invalid");
  }
  return value;
}

function requireHex64(value: unknown): string {
  if (typeof value !== "string" || !HEX64.test(value)) {
    throw new CronProtocolError("hex64 field is invalid");
  }
  return value;
}

function requireTimestamp(value: unknown): string {
  if (typeof value !== "string" || !isCanonicalCronTimestamp(value)) {
    throw new CronProtocolError("timestamp is invalid");
  }
  return value;
}

function requirePositiveSafeInt(value: unknown): number {
  if (!Number.isSafeInteger(value) || typeof value !== "number" || value <= 0) {
    throw new CronProtocolError("persistence generation is invalid");
  }
  return value;
}
