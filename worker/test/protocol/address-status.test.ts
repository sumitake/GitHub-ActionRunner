import { expect, test } from "vitest";

import { hexToBytes, signCanonical } from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import {
  ADDRESS_STATUS_PATH,
  ADDRESS_STATUS_PROTOCOL_VERSION,
  parseAddressStatusRequest,
  parseAddressStatusResponse,
  signAddressStatusRequest,
  signAddressStatusResponse,
  type AddressStatusRequestV1,
  type AddressStatusResponseV1,
  verifyAddressStatusRequest,
  verifyAddressStatusResponse,
} from "../../src/protocol/address-status";

const key = hexToBytes("0c".repeat(32));
const inventoryDigest = "a".repeat(64);
const nonce = "b".repeat(64);
const requestTime = "2026-01-01T00:00:10.000Z";
const responseTime = "2026-01-01T00:00:10.010Z";

const request: AddressStatusRequestV1 = {
  protocolVersion: ADDRESS_STATUS_PROTOCOL_VERSION,
  fleetId: "alpha",
  nonce,
  requestTime,
  inventoryRevision: "1",
  inventoryDigest,
};

const response: AddressStatusResponseV1 = {
  protocolVersion: ADDRESS_STATUS_PROTOCOL_VERSION,
  status: "inert-receipt",
  fleetId: "alpha",
  nonce,
  requestTime,
  responseTime,
  inventoryRevision: "1",
  inventoryDigest,
  tickTimestamp: "2026-01-01T00:00:00.000Z",
  receiptTime: "2026-01-01T00:00:00.010Z",
  persistenceGeneration: 7,
  inventoried: false,
  holder: "none",
  maxCapacity: 0,
  routingState: "UNINITIALIZED",
  childCounts: {
    repositories: 0,
    transitions: 0,
    dueWork: 0,
    auditEvents: 0,
  },
};

const expectedRequestBody =
  '{"fleetId":"alpha","inventoryDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inventoryRevision":"1","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","protocolVersion":1,"requestTime":"2026-01-01T00:00:10.000Z"}';
const expectedResponseBody =
  '{"childCounts":{"auditEvents":0,"dueWork":0,"repositories":0,"transitions":0},"fleetId":"alpha","holder":"none","inventoried":false,"inventoryDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inventoryRevision":"1","maxCapacity":0,"nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","persistenceGeneration":7,"protocolVersion":1,"receiptTime":"2026-01-01T00:00:00.010Z","requestTime":"2026-01-01T00:00:10.000Z","responseTime":"2026-01-01T00:00:10.010Z","routingState":"UNINITIALIZED","status":"inert-receipt","tickTimestamp":"2026-01-01T00:00:00.000Z"}';

test("address-status canonical bodies and MAC domains are frozen", async () => {
  const requestBody = canonicalize(request);
  const responseBody = canonicalize(response);
  expect(ADDRESS_STATUS_PATH).toBe("/v1/admin/status");
  expect(requestBody).toBe(expectedRequestBody);
  expect(responseBody).toBe(expectedResponseBody);

  const requestMac = await signAddressStatusRequest(
    key,
    requestTime,
    requestBody,
  );
  const responseMac = await signAddressStatusResponse(
    key,
    responseTime,
    responseBody,
  );
  expect(requestMac).toBe(
    "3c110c5e41c1f1c07c6b27ac8d13c157261e5d810d9b0b2da38b579c4e8cdf1a",
  );
  expect(responseMac).toBe(
    "8484023dad20c9a31ca1dd6be3d8c6b136356255c6b206c74cb2dc4892c8632a",
  );
  expect(requestMac).not.toBe(responseMac);
  await expect(
    verifyAddressStatusResponse({
      key,
      body: responseBody,
      headerTimestamp: responseTime,
      macHex: requestMac,
      observedAt: responseTime,
      timestampWindowMs: 5_000,
      request,
    }),
  ).rejects.toThrow("mac mismatch");
});

test("address-status request accepts one complete signed identity", async () => {
  const body = canonicalize(request);
  const macHex = await signAddressStatusRequest(key, requestTime, body);
  await expect(
    verifyAddressStatusRequest({
      key,
      body,
      headerTimestamp: requestTime,
      macHex,
      observedAt: "2026-01-01T00:00:10.005Z",
      timestampWindowMs: 5_000,
      expected: {
        fleetId: "alpha",
        inventoryRevision: "1",
        inventoryDigest,
      },
    }),
  ).resolves.toEqual(request);
});

test("address-status response accepts one complete signed inert receipt", async () => {
  const body = canonicalize(response);
  const macHex = await signAddressStatusResponse(key, responseTime, body);
  await expect(
    verifyAddressStatusResponse({
      key,
      body,
      headerTimestamp: responseTime,
      macHex,
      observedAt: "2026-01-01T00:00:10.015Z",
      timestampWindowMs: 5_000,
      request,
    }),
  ).resolves.toEqual(response);
});

test("address-status parsers reject widened or noncanonical messages", () => {
  expect(parseAddressStatusRequest(canonicalize(request))).toEqual(request);
  expect(parseAddressStatusResponse(canonicalize(response))).toEqual(response);
  for (const invalid of [
    { ...request, extra: true },
    { ...request, protocolVersion: 2 },
    { ...request, fleetId: "Alpha" },
    { ...request, inventoryRevision: "01" },
    { ...request, inventoryDigest: "A".repeat(64) },
    { ...request, nonce: "b".repeat(63) },
    { ...request, requestTime: "2026-01-01T00:00:10Z" },
  ]) {
    expect(() => parseAddressStatusRequest(canonicalize(invalid))).toThrow();
  }
  expect(() => parseAddressStatusRequest(JSON.stringify(request))).toThrow();

  for (const invalid of [
    { ...response, extra: true },
    { ...response, status: "ready" },
    { ...response, inventoried: true },
    { ...response, holder: "portable" },
    { ...response, maxCapacity: 1 },
    { ...response, routingState: "HOSTED" },
    {
      ...response,
      childCounts: { ...response.childCounts, repositories: 1 },
    },
    { ...response, persistenceGeneration: 0 },
    { ...response, receiptTime: "2025-12-31T23:59:59.999Z" },
    { ...response, receiptTime: "2026-01-01T00:00:10.011Z" },
  ]) {
    expect(() => parseAddressStatusResponse(canonicalize(invalid))).toThrow();
  }
});

test("address-status authentication rejects malformed MACs", async () => {
  const body = canonicalize(request);
  for (const macHex of ["", "0".repeat(63), "G".repeat(64)]) {
    await expect(
      verifyAddressStatusRequest({
        key,
        body,
        headerTimestamp: requestTime,
        macHex,
        observedAt: requestTime,
        timestampWindowMs: 5_000,
        expected: {
          fleetId: "alpha",
          inventoryRevision: "1",
          inventoryDigest,
        },
      }),
    ).rejects.toThrow("mac mismatch");
  }
});

test("address-status request rejects stale, future, and wrong identity", async () => {
  const body = canonicalize(request);
  const macHex = await signAddressStatusRequest(key, requestTime, body);
  const base = {
    key,
    body,
    headerTimestamp: requestTime,
    macHex,
    timestampWindowMs: 5_000,
    expected: {
      fleetId: "alpha",
      inventoryRevision: "1",
      inventoryDigest,
    },
  };
  for (const input of [
    { ...base, observedAt: "2026-01-01T00:00:15.001Z" },
    { ...base, observedAt: "2026-01-01T00:00:04.999Z" },
    { ...base, observedAt: requestTime, headerTimestamp: responseTime },
    {
      ...base,
      observedAt: requestTime,
      expected: { ...base.expected, fleetId: "beta" },
    },
    {
      ...base,
      observedAt: requestTime,
      expected: { ...base.expected, inventoryRevision: "2" },
    },
    {
      ...base,
      observedAt: requestTime,
      expected: { ...base.expected, inventoryDigest: "c".repeat(64) },
    },
  ]) {
    await expect(verifyAddressStatusRequest(input)).rejects.toThrow();
  }
});

test("address-status response rejects stale, future, and reflected identity", async () => {
  const body = canonicalize(response);
  const macHex = await signAddressStatusResponse(key, responseTime, body);
  const requestBody = canonicalize(request);
  const requestMac = await signAddressStatusRequest(
    key,
    requestTime,
    requestBody,
  );
  const base = {
    key,
    body,
    headerTimestamp: responseTime,
    macHex,
    observedAt: responseTime,
    timestampWindowMs: 5_000,
    request,
  };
  for (const input of [
    { ...base, observedAt: "2026-01-01T00:00:15.011Z" },
    { ...base, observedAt: "2026-01-01T00:00:04.999Z" },
    { ...base, headerTimestamp: requestTime },
    { ...base, macHex: requestMac },
    { ...base, request: { ...request, fleetId: "beta" } },
    { ...base, request: { ...request, nonce: "c".repeat(64) } },
    {
      ...base,
      request: { ...request, inventoryRevision: "2" },
    },
    {
      ...base,
      request: { ...request, inventoryDigest: "c".repeat(64) },
    },
  ]) {
    await expect(verifyAddressStatusResponse(input)).rejects.toThrow();
  }

  const ordinaryMac = await signCanonical(
    key,
    "POST",
    ADDRESS_STATUS_PATH,
    requestTime,
    requestBody,
  );
  expect(ordinaryMac).not.toBe(requestMac);
});
