import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "vitest";

import {
  constantTimeEqualHex,
  hexToBytes,
  signCronRequest,
  signCronResponse,
  signCanonical,
  verifyCronRequest,
  verifyCronResponse,
  verifyCanonical,
} from "../../src/protocol/auth";

const fixtureRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../tests/fixtures/protocol/v1",
);

test("HMAC vector matches the frozen cross-language fixture", async () => {
  const vector = JSON.parse(
    readFileSync(join(fixtureRoot, "hmac-vector.json"), "utf8"),
  ) as {
    keyHex: string;
    method: string;
    path: string;
    timestamp: string;
    canonicalBodyFile: string;
    macHex: string;
  };
  const body = readFileSync(
    join(fixtureRoot, vector.canonicalBodyFile),
    "utf8",
  ).trimEnd();
  const mac = await signCanonical(
    hexToBytes(vector.keyHex),
    vector.method,
    vector.path,
    vector.timestamp,
    body,
  );
  expect(mac).toBe(vector.macHex);
  await verifyCanonical(
    hexToBytes(vector.keyHex),
    vector.method,
    vector.path,
    vector.timestamp,
    body,
    vector.macHex,
  );
});

test("full session and heartbeat exchange matches frozen Go HMAC vectors", async () => {
  const fixture = JSON.parse(
    readFileSync(join(fixtureRoot, "exchange-hmac-vectors.json"), "utf8"),
  ) as {
    keyHex: string;
    vectors: Array<{
      name: string;
      method: string;
      path: string;
      timestamp: string;
      canonicalBodyFile: string;
      macHex: string;
    }>;
  };
  const key = hexToBytes(fixture.keyHex);
  for (const vector of fixture.vectors) {
    const body = readFileSync(
      join(fixtureRoot, vector.canonicalBodyFile),
      "utf8",
    ).trimEnd();
    expect(
      await signCanonical(
        key,
        vector.method,
        vector.path,
        vector.timestamp,
        body,
      ),
      vector.name,
    ).toBe(vector.macHex);
  }
});

test("MAC verification is constant-time and rejects a flipped bit", async () => {
  const key = hexToBytes("0b".repeat(32));
  const mac = await signCanonical(
    key,
    "POST",
    "/v1/session",
    "2026-01-01T00:00:00.000Z",
    "{}",
  );
  const flipped = `${mac.slice(0, -1)}${mac.endsWith("a") ? "b" : "a"}`;
  await expect(
    verifyCanonical(
      key,
      "POST",
      "/v1/session",
      "2026-01-01T00:00:00.000Z",
      "{}",
      flipped,
    ),
  ).rejects.toThrow("mac mismatch");
  expect(constantTimeEqualHex(mac, mac)).toBe(true);
  expect(constantTimeEqualHex(mac, flipped)).toBe(false);
  expect(constantTimeEqualHex(mac, mac.slice(1))).toBe(false);
});

test("Cron request and response MAC domains cannot reflect into each other", async () => {
  const key = hexToBytes("0c".repeat(32));
  const timestamp = "2026-01-01T00:00:00.000Z";
  const body = "{}";
  const requestMac = await signCronRequest(
    key,
    "POST",
    "/v1/internal/cron",
    timestamp,
    body,
  );
  const responseMac = await signCronResponse(
    key,
    "POST",
    "/v1/internal/cron",
    timestamp,
    body,
  );
  const ordinaryMac = await signCanonical(
    key,
    "POST",
    "/v1/internal/cron",
    timestamp,
    body,
  );
  expect(requestMac).not.toBe(responseMac);
  expect(requestMac).not.toBe(ordinaryMac);
  await verifyCronRequest(
    key,
    "POST",
    "/v1/internal/cron",
    timestamp,
    body,
    requestMac,
  );
  await verifyCronResponse(
    key,
    "POST",
    "/v1/internal/cron",
    timestamp,
    body,
    responseMac,
  );
  await expect(
    verifyCronResponse(
      key,
      "POST",
      "/v1/internal/cron",
      timestamp,
      body,
      requestMac,
    ),
  ).rejects.toThrow("mac mismatch");
});
