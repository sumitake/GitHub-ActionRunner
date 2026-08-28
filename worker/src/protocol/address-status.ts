import {
  ADMIN_STATUS_PATH,
  assertTimestampWindow,
  isRfc3339MsZ,
  signDomainSeparatedCanonical,
  verifyDomainSeparatedCanonical,
} from "./auth";
import { parseCanonical } from "./canonical";
import { isCanonicalInventoryRevision } from "./cron";
import { FLEET_ID, HEX64 } from "./messages";

export const ADDRESS_STATUS_PATH = ADMIN_STATUS_PATH;
export const ADDRESS_STATUS_PROTOCOL_VERSION = 1 as const;

const ADDRESS_STATUS_REQUEST_MAC_DOMAIN =
  "portable-ghar-address-status-request-v1";
const ADDRESS_STATUS_RESPONSE_MAC_DOMAIN =
  "portable-ghar-address-status-response-v1";

export type AddressStatusRequestV1 = {
  protocolVersion: typeof ADDRESS_STATUS_PROTOCOL_VERSION;
  fleetId: string;
  nonce: string;
  requestTime: string;
  inventoryRevision: string;
  inventoryDigest: string;
};

export type AddressStatusChildCounts = {
  repositories: 0;
  transitions: 0;
  dueWork: 0;
  auditEvents: 0;
};

export type AddressStatusResponseV1 = {
  protocolVersion: typeof ADDRESS_STATUS_PROTOCOL_VERSION;
  status: "inert-receipt";
  fleetId: string;
  nonce: string;
  requestTime: string;
  responseTime: string;
  inventoryRevision: string;
  inventoryDigest: string;
  tickTimestamp: string;
  receiptTime: string;
  persistenceGeneration: number;
  inventoried: false;
  holder: "none";
  maxCapacity: 0;
  routingState: "UNINITIALIZED";
  childCounts: AddressStatusChildCounts;
};

export type AddressStatusIdentity = {
  fleetId: string;
  inventoryRevision: string;
  inventoryDigest: string;
};

export class AddressStatusProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AddressStatusProtocolError";
  }
}

export function parseAddressStatusRequest(
  body: string,
): AddressStatusRequestV1 {
  const value = asRecord(parseCanonical(body));
  assertExactKeys(value, [
    "fleetId",
    "inventoryDigest",
    "inventoryRevision",
    "nonce",
    "protocolVersion",
    "requestTime",
  ]);
  return {
    protocolVersion: requireVersion(value.protocolVersion),
    fleetId: requireFleetId(value.fleetId),
    nonce: requireHex64(value.nonce),
    requestTime: requireTimestamp(value.requestTime),
    inventoryRevision: requireRevision(value.inventoryRevision),
    inventoryDigest: requireHex64(value.inventoryDigest),
  };
}

export function parseAddressStatusResponse(
  body: string,
): AddressStatusResponseV1 {
  const value = asRecord(parseCanonical(body));
  assertExactKeys(value, [
    "childCounts",
    "fleetId",
    "holder",
    "inventoried",
    "inventoryDigest",
    "inventoryRevision",
    "maxCapacity",
    "nonce",
    "persistenceGeneration",
    "protocolVersion",
    "receiptTime",
    "requestTime",
    "responseTime",
    "routingState",
    "status",
    "tickTimestamp",
  ]);
  const childCounts = requireChildCounts(value.childCounts);
  const response: AddressStatusResponseV1 = {
    protocolVersion: requireVersion(value.protocolVersion),
    status: requireLiteral(value.status, "inert-receipt", "status"),
    fleetId: requireFleetId(value.fleetId),
    nonce: requireHex64(value.nonce),
    requestTime: requireTimestamp(value.requestTime),
    responseTime: requireTimestamp(value.responseTime),
    inventoryRevision: requireRevision(value.inventoryRevision),
    inventoryDigest: requireHex64(value.inventoryDigest),
    tickTimestamp: requireTimestamp(value.tickTimestamp),
    receiptTime: requireTimestamp(value.receiptTime),
    persistenceGeneration: requirePositiveSafeInt(
      value.persistenceGeneration,
      "persistence generation",
    ),
    inventoried: requireLiteral(value.inventoried, false, "inventory mode"),
    holder: requireLiteral(value.holder, "none", "holder"),
    maxCapacity: requireLiteral(value.maxCapacity, 0, "capacity"),
    routingState: requireLiteral(
      value.routingState,
      "UNINITIALIZED",
      "routing state",
    ),
    childCounts,
  };
  if (
    response.responseTime < response.requestTime ||
    response.receiptTime < response.tickTimestamp ||
    response.receiptTime > response.responseTime
  ) {
    throw new AddressStatusProtocolError("status times are inconsistent");
  }
  return response;
}

export async function signAddressStatusRequest(
  key: Uint8Array,
  timestamp: string,
  canonicalBody: string,
): Promise<string> {
  return signDomainSeparatedCanonical(
    key,
    ADDRESS_STATUS_REQUEST_MAC_DOMAIN,
    "POST",
    ADDRESS_STATUS_PATH,
    timestamp,
    canonicalBody,
  );
}

export async function signAddressStatusResponse(
  key: Uint8Array,
  timestamp: string,
  canonicalBody: string,
): Promise<string> {
  return signDomainSeparatedCanonical(
    key,
    ADDRESS_STATUS_RESPONSE_MAC_DOMAIN,
    "POST",
    ADDRESS_STATUS_PATH,
    timestamp,
    canonicalBody,
  );
}

export async function verifyAddressStatusRequest(input: {
  key: Uint8Array;
  body: string;
  headerTimestamp: string;
  macHex: string;
  observedAt: string;
  timestampWindowMs: number;
  expected: AddressStatusIdentity;
}): Promise<AddressStatusRequestV1> {
  await verifyDomainSeparatedCanonical(
    input.key,
    ADDRESS_STATUS_REQUEST_MAC_DOMAIN,
    "POST",
    ADDRESS_STATUS_PATH,
    input.headerTimestamp,
    input.body,
    input.macHex,
  );
  const request = parseAddressStatusRequest(input.body);
  if (
    request.requestTime !== input.headerTimestamp ||
    !sameIdentity(request, input.expected)
  ) {
    throw new AddressStatusProtocolError("status request identity is invalid");
  }
  assertTimestampWindow(
    input.observedAt,
    request.requestTime,
    input.timestampWindowMs,
  );
  return request;
}

export async function verifyAddressStatusResponse(input: {
  key: Uint8Array;
  body: string;
  headerTimestamp: string;
  macHex: string;
  observedAt: string;
  timestampWindowMs: number;
  request: AddressStatusRequestV1;
}): Promise<AddressStatusResponseV1> {
  await verifyDomainSeparatedCanonical(
    input.key,
    ADDRESS_STATUS_RESPONSE_MAC_DOMAIN,
    "POST",
    ADDRESS_STATUS_PATH,
    input.headerTimestamp,
    input.body,
    input.macHex,
  );
  const response = parseAddressStatusResponse(input.body);
  if (
    response.responseTime !== input.headerTimestamp ||
    response.requestTime !== input.request.requestTime ||
    response.nonce !== input.request.nonce ||
    !sameIdentity(response, input.request)
  ) {
    throw new AddressStatusProtocolError("status response identity is invalid");
  }
  assertTimestampWindow(
    response.responseTime,
    input.request.requestTime,
    input.timestampWindowMs,
  );
  assertTimestampWindow(
    input.observedAt,
    response.responseTime,
    input.timestampWindowMs,
  );
  return response;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AddressStatusProtocolError("status value is not an object");
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
    throw new AddressStatusProtocolError("status fields are not exact");
  }
}

function requireVersion(
  value: unknown,
): typeof ADDRESS_STATUS_PROTOCOL_VERSION {
  if (value !== ADDRESS_STATUS_PROTOCOL_VERSION) {
    throw new AddressStatusProtocolError("status version is invalid");
  }
  return ADDRESS_STATUS_PROTOCOL_VERSION;
}

function requireFleetId(value: unknown): string {
  if (typeof value !== "string" || !FLEET_ID.test(value)) {
    throw new AddressStatusProtocolError("status fleet is invalid");
  }
  return value;
}

function requireHex64(value: unknown): string {
  if (typeof value !== "string" || !HEX64.test(value)) {
    throw new AddressStatusProtocolError("status digest is invalid");
  }
  return value;
}

function requireRevision(value: unknown): string {
  if (typeof value !== "string" || !isCanonicalInventoryRevision(value)) {
    throw new AddressStatusProtocolError("status revision is invalid");
  }
  return value;
}

function requireTimestamp(value: unknown): string {
  if (typeof value !== "string" || !isRfc3339MsZ(value)) {
    throw new AddressStatusProtocolError("status timestamp is invalid");
  }
  return value;
}

function requirePositiveSafeInt(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new AddressStatusProtocolError(`${name} is invalid`);
  }
  return value;
}

function requireLiteral<const T>(value: unknown, expected: T, name: string): T {
  if (value !== expected) {
    throw new AddressStatusProtocolError(`${name} is not inert`);
  }
  return expected;
}

function requireChildCounts(value: unknown): AddressStatusChildCounts {
  const counts = asRecord(value);
  assertExactKeys(counts, [
    "auditEvents",
    "dueWork",
    "repositories",
    "transitions",
  ]);
  return {
    repositories: requireLiteral(counts.repositories, 0, "repository count"),
    transitions: requireLiteral(counts.transitions, 0, "transition count"),
    dueWork: requireLiteral(counts.dueWork, 0, "due-work count"),
    auditEvents: requireLiteral(counts.auditEvents, 0, "audit-event count"),
  };
}

function sameIdentity(
  value: AddressStatusIdentity,
  expected: AddressStatusIdentity,
): boolean {
  return (
    value.fleetId === expected.fleetId &&
    value.inventoryRevision === expected.inventoryRevision &&
    value.inventoryDigest === expected.inventoryDigest
  );
}
