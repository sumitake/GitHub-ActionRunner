import { expect, test } from "vitest";

import type { FleetNamespace } from "../../src/bindings";
import {
  hexToBytes,
  MAC_HEADER,
  TIMESTAMP_HEADER,
} from "../../src/protocol/auth";
import {
  ADDRESS_STATUS_PATH,
  ADDRESS_STATUS_PROTOCOL_VERSION,
  signAddressStatusRequest,
  verifyAddressStatusRequest,
  type AddressStatusRequestV1,
} from "../../src/protocol/address-status";
import { canonicalize } from "../../src/protocol/canonical";
import { handleWorkerFetch } from "../../src/runtime";

const ordinaryKeyHex = "0b".repeat(32);
const cronKeyHex = "0c".repeat(32);
const cronKey = hexToBytes(cronKeyHex);
const inventoryDigest =
  "6a9aedffdae5b07550af1921963f6aa007cf4d6425762e0b30afa8ac7cbed91d";
const requestTime = "2026-01-01T00:00:00.000Z";

function env(namespace: FleetNamespace): Record<string, unknown> {
  return {
    FLEET_IDS: "alpha,beta",
    HMAC_KEY: ordinaryKeyHex,
    CRON_HMAC_KEY: cronKeyHex,
    TIMESTAMP_WINDOW_MS: "5000",
    NONCE_TTL_MS: "60000",
    FLEET_INVENTORY_REVISION: "1",
    FLEET_INVENTORY_DIGEST: inventoryDigest,
    LEASE_DURATION_MS: "invalid",
    ARCHIVE_EVIDENCE_MAX_AGE_MS: "invalid",
    SELECTOR_EVIDENCE_MAX_AGE_MS: "invalid",
    HOSTED_TRANSITION_SAFETY_MARGIN_MS: "invalid",
    FLEET: namespace,
  };
}

async function signedRequest(
  overrides: Partial<AddressStatusRequestV1> = {},
  suffix = "",
): Promise<Request> {
  const value: AddressStatusRequestV1 = {
    protocolVersion: ADDRESS_STATUS_PROTOCOL_VERSION,
    fleetId: "alpha",
    nonce: "1".repeat(64),
    requestTime,
    inventoryRevision: "1",
    inventoryDigest,
    ...overrides,
  };
  const body = canonicalize(value);
  const mac = await signAddressStatusRequest(cronKey, requestTime, body);
  return new Request(`https://worker.example${ADDRESS_STATUS_PATH}${suffix}`, {
    method: "POST",
    headers: { [TIMESTAMP_HEADER]: requestTime, [MAC_HEADER]: mac },
    body,
  });
}

test("production Worker dispatches only signed address-status to its inventoried object", async () => {
  const calls: string[] = [];
  const namespace: FleetNamespace = {
    getByName(name: string) {
      calls.push(`get:${name}`);
      return {
        async fetch(request: Request) {
          calls.push("fetch");
          const body = await request.text();
          await verifyAddressStatusRequest({
            key: cronKey,
            body,
            headerTimestamp: request.headers.get(TIMESTAMP_HEADER) ?? "",
            macHex: request.headers.get(MAC_HEADER) ?? "",
            observedAt: requestTime,
            timestampWindowMs: 5_000,
            expected: {
              fleetId: "alpha",
              inventoryRevision: "1",
              inventoryDigest,
            },
          });
          return new Response(null, { status: 204 });
        },
      };
    },
  };

  const response = await handleWorkerFetch(
    await signedRequest(),
    env(namespace),
  );

  expect(response.status).toBe(204);
  expect(calls).toEqual(["get:alpha", "fetch"]);
});

test("outer address-status routing rejects widened identity without object dispatch", async () => {
  for (const request of [
    await signedRequest({ fleetId: "gamma" }),
    await signedRequest({}, "?query=1"),
    new Request(`https://worker.example${ADDRESS_STATUS_PATH}`, {
      method: "GET",
    }),
    new Request(`https://worker.example${ADDRESS_STATUS_PATH}`, {
      method: "POST",
      body: "x".repeat(65_537),
    }),
  ]) {
    let calls = 0;
    const response = await handleWorkerFetch(
      request,
      env({
        getByName() {
          calls += 1;
          throw new Error("rejected status reached a Durable Object");
        },
      }),
    );
    expect(response.status).toBe(401);
    expect(calls).toBe(0);
  }
});
