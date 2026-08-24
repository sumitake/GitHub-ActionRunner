import { expect, test } from "vitest";

import { canonicalize } from "../../src/protocol/canonical";
import {
  CRON_ADDRESS_PROTOCOL_VERSION,
  CRON_PATH,
  deadlineForTick,
  inventoryDigest,
  parseCronAddressRequest,
  parseCronAddressResponse,
} from "../../src/protocol/cron";

const revision = "18446744073709551615";
const fleetIds = ["alpha", "beta"];
const digest =
  "51110b9179430f51a3e5551a2280cc9a4bddf905dc8d80ab02008998d0aaadf5";
const nonce = "a".repeat(64);
const tickTimestamp = "2026-01-01T00:00:00.000Z";
const deadline = "2026-01-01T00:00:00.250Z";

function requestValue(): Record<string, unknown> {
  return {
    protocolVersion: CRON_ADDRESS_PROTOCOL_VERSION,
    fleetId: "alpha",
    fleetIds,
    revision,
    inventoryDigest: digest,
    nonce,
    tickTimestamp,
    deadline,
  };
}

test("Cron inventory digest freezes the canonical full-inventory preimage", async () => {
  await expect(inventoryDigest(revision, fleetIds)).resolves.toBe(digest);
  expect(CRON_PATH).toBe("/v1/internal/cron");
});

test("Cron request parser accepts only exact canonical address messages", () => {
  expect(parseCronAddressRequest(canonicalize(requestValue()))).toEqual(
    requestValue(),
  );
  for (const invalidRevision of ["0", "01", "+1", "18446744073709551616"]) {
    expect(() =>
      parseCronAddressRequest(
        canonicalize({ ...requestValue(), revision: invalidRevision }),
      ),
    ).toThrow();
  }
  expect(() =>
    parseCronAddressRequest(
      canonicalize({ ...requestValue(), fleetIds: ["beta", "alpha"] }),
    ),
  ).toThrow();
  expect(() =>
    parseCronAddressRequest(
      canonicalize({ ...requestValue(), fleetIds: ["alpha", "alpha"] }),
    ),
  ).toThrow();
  expect(() =>
    parseCronAddressRequest(
      canonicalize({ ...requestValue(), fleetId: "gamma" }),
    ),
  ).toThrow();
  expect(() =>
    parseCronAddressRequest(
      canonicalize({ ...requestValue(), deadline: tickTimestamp }),
    ),
  ).toThrow();
  expect(() =>
    parseCronAddressRequest(canonicalize({ ...requestValue(), extra: true })),
  ).toThrow();
});

test("Cron response parser requires exact echoed identity and generation", () => {
  const response = {
    protocolVersion: CRON_ADDRESS_PROTOCOL_VERSION,
    fleetId: "alpha",
    revision,
    inventoryDigest: digest,
    nonce,
    tickTimestamp,
    deadline,
    receiptTime: "2026-01-01T00:00:00.010Z",
    persistenceGeneration: 7,
  };
  expect(parseCronAddressResponse(canonicalize(response))).toEqual(response);
  expect(() =>
    parseCronAddressResponse(
      canonicalize({ ...response, persistenceGeneration: 0 }),
    ),
  ).toThrow();
  expect(() =>
    parseCronAddressResponse(
      canonicalize({ ...response, nonce: "A".repeat(64) }),
    ),
  ).toThrow();
  expect(() =>
    parseCronAddressResponse(canonicalize({ ...response, extra: true })),
  ).toThrow();
});

test("Cron deadline arithmetic is exact and rejects overflow or bad clocks", () => {
  expect(deadlineForTick(tickTimestamp, 250)).toBe(deadline);
  expect(() => deadlineForTick(tickTimestamp, 0)).toThrow();
  expect(() => deadlineForTick("not-time", 250)).toThrow();
  expect(() => deadlineForTick("2026-02-30T00:00:00.000Z", 250)).toThrow();
  expect(() => deadlineForTick("9999-12-31T23:59:59.999Z", 1)).toThrow();
});
