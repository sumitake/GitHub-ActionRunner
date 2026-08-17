import { expect, test } from "vitest";

import { handleHeartbeat } from "../../src/engine/heartbeat";
import { handleSession } from "../../src/engine/session";
import { hexToBytes, signCanonical } from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import { parseSessionResponse } from "../../src/protocol/messages";
import { MemoryFleetStore } from "../../src/state/memory";

const key = hexToBytes("0b".repeat(32));
const digest = "a".repeat(64);
const nonce = "c".repeat(64);

function secrets() {
  return {
    hmacKey: key,
    timestampWindowMs: 5_000,
    nonceTtlMs: 60_000,
    hostedTransitionSafetyMarginMs: 1_000,
    leaseDurationMs: 8_000,
    archiveEvidenceMaxAgeMs: 2_000,
    selectorEvidenceMaxAgeMs: 2_000,
  };
}

test("session replay and old-session heartbeats fail closed", async () => {
  let now = Date.parse("2026-01-01T00:00:00.000Z");
  const store = new MemoryFleetStore("example-fleet", {
    now: () => new Date(now).toISOString(),
  });
  const body = canonicalize({
    buildId: digest,
    fleetId: "example-fleet",
    nonce,
    protocolVersion: 1,
    timestamp: "2026-01-01T00:00:00.000Z",
  });
  const mac = await signCanonical(
    key,
    "POST",
    "/v1/session",
    "2026-01-01T00:00:00.000Z",
    body,
  );
  const first = await handleSession(store, secrets(), {
    method: "POST",
    path: "/v1/session",
    timestamp: "2026-01-01T00:00:00.000Z",
    macHex: mac,
    body,
    inventoried: true,
  });
  expect(first.status).toBe(200);
  const session = parseSessionResponse(first.body);
  expect(session.nonce).toBe(nonce);
  const replay = await handleSession(store, secrets(), {
    method: "POST",
    path: "/v1/session",
    timestamp: "2026-01-01T00:00:00.000Z",
    macHex: mac,
    body,
    inventoried: true,
  });
  expect(replay.status).toBe(401);

  now += 10;
  const hbBody = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: session.epoch,
    sessionId: "d".repeat(64),
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp: new Date(now).toISOString(),
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
    },
  });
  const hbMac = await signCanonical(
    key,
    "POST",
    "/v1/heartbeat",
    new Date(now).toISOString(),
    hbBody,
  );
  const oldSession = await handleHeartbeat(store, secrets(), {
    method: "POST",
    path: "/v1/heartbeat",
    timestamp: new Date(now).toISOString(),
    macHex: hbMac,
    body: hbBody,
    inventoried: true,
  });
  expect(oldSession.status).toBe(200);
  expect(oldSession.body).toContain("invalid-request");
});

test("predecessor drain grants no lease before leaseNotBefore", async () => {
  let now = Date.parse("2026-01-01T00:00:00.000Z");
  const store = new MemoryFleetStore("example-fleet", {
    now: () => new Date(now).toISOString(),
  });
  store.fleet.lastIssuedLeaseExpiryMax = "2026-01-01T00:00:30.000Z";
  const body = canonicalize({
    buildId: digest,
    fleetId: "example-fleet",
    nonce,
    protocolVersion: 1,
    timestamp: "2026-01-01T00:00:00.000Z",
  });
  const mac = await signCanonical(
    key,
    "POST",
    "/v1/session",
    "2026-01-01T00:00:00.000Z",
    body,
  );
  const enrolled = await handleSession(store, secrets(), {
    method: "POST",
    path: "/v1/session",
    timestamp: "2026-01-01T00:00:00.000Z",
    macHex: mac,
    body,
    inventoried: true,
  });
  const session = parseSessionResponse(enrolled.body);
  expect(session.leaseNotBefore >= "2026-01-01T00:00:31.000Z").toBe(true);
  const hbTs = "2026-01-01T00:00:00.010Z";
  now = Date.parse(hbTs);
  const hbBody = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: session.epoch,
    sessionId: session.sessionId,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp: hbTs,
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
    },
  });
  const hbMac = await signCanonical(key, "POST", "/v1/heartbeat", hbTs, hbBody);
  const drained = await handleHeartbeat(store, secrets(), {
    method: "POST",
    path: "/v1/heartbeat",
    timestamp: hbTs,
    macHex: hbMac,
    body: hbBody,
    inventoried: true,
  });
  expect(drained.body).toContain("predecessor-lease-draining");
  expect(drained.body).not.toContain('"mode"');
});
