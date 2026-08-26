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

function snapshot(observedAt: string) {
  return {
    observedAt,
    fleetAlias: "example-fleet",
    acquisitionMode: "enabled" as const,
    policyEpoch: 1,
    policyDigest: digest,
    repositoryPolicyRevision: 1,
    capacity: {
      configured: 1,
      effective: 1,
      occupied: 0,
      available: 1,
      queued: 0,
    },
    assignedJobs: 0,
    runningJobs: 0,
    oldestLiveAssignmentAgeMs: 0,
    unassignedReleasedListeners: 0,
    lastTerminalAt: null,
    hostProfileId: "strict-linux-v1" as const,
    degraded: false,
    buildId: digest,
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
  expect(session.sessionId).not.toBe(nonce);
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
    snapshot: snapshot(new Date(now).toISOString()),
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

  now += 10;
  const replacementNonce = "e".repeat(64);
  const replacementTimestamp = new Date(now).toISOString();
  const replacementBody = canonicalize({
    buildId: digest,
    fleetId: "example-fleet",
    nonce: replacementNonce,
    protocolVersion: 1,
    timestamp: replacementTimestamp,
  });
  const replacementMac = await signCanonical(
    key,
    "POST",
    "/v1/session",
    replacementTimestamp,
    replacementBody,
  );
  const replacement = await handleSession(
    store,
    secrets(),
    {
      method: "POST",
      path: "/v1/session",
      timestamp: replacementTimestamp,
      macHex: replacementMac,
      body: replacementBody,
      inventoried: true,
    },
    () => "f".repeat(64),
  );
  expect(replacement.status).toBe(200);
  const replacementSession = parseSessionResponse(replacement.body);
  expect(replacementSession.epoch).toBe(session.epoch + 1);
  expect(replacementSession.sessionId).toBe("f".repeat(64));

  now += 10;
  const oldTimestamp = new Date(now).toISOString();
  const actualOldBody = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: session.epoch,
    sessionId: session.sessionId,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp: oldTimestamp,
    snapshot: snapshot(oldTimestamp),
  });
  const actualOldMac = await signCanonical(
    key,
    "POST",
    "/v1/heartbeat",
    oldTimestamp,
    actualOldBody,
  );
  const actualOldSession = await handleHeartbeat(store, secrets(), {
    method: "POST",
    path: "/v1/heartbeat",
    timestamp: oldTimestamp,
    macHex: actualOldMac,
    body: actualOldBody,
    inventoried: true,
  });
  expect(actualOldSession.status).toBe(200);
  expect(actualOldSession.body).toContain("invalid-request");
  expect(store.fleet).toMatchObject({
    epoch: replacementSession.epoch,
    sessionId: replacementSession.sessionId,
    sequence: 0,
  });
});

test("partial heartbeat fails before sequence mutation", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:00.000Z",
  });
  store.fleet.epoch = 2;
  store.fleet.sessionId = "d".repeat(64);
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 2,
    sessionId: store.fleet.sessionId,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp: "2026-01-01T00:00:00.000Z",
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
    },
  });
  const mac = await signCanonical(
    key,
    "POST",
    "/v1/heartbeat",
    "2026-01-01T00:00:00.000Z",
    body,
  );

  const response = await handleHeartbeat(store, secrets(), {
    method: "POST",
    path: "/v1/heartbeat",
    timestamp: "2026-01-01T00:00:00.000Z",
    macHex: mac,
    body,
    inventoried: true,
  });

  expect(response.status).toBe(401);
  expect(store.fleet.sequence).toBe(0);
});

test("stale observed health fails before sequence mutation", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  store.fleet.epoch = 2;
  store.fleet.sessionId = "d".repeat(64);
  const timestamp = "2026-01-01T00:00:10.000Z";
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 2,
    sessionId: store.fleet.sessionId,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp,
    snapshot: snapshot("2026-01-01T00:00:00.000Z"),
  });
  const mac = await signCanonical(
    key,
    "POST",
    "/v1/heartbeat",
    timestamp,
    body,
  );

  const response = await handleHeartbeat(store, secrets(), {
    method: "POST",
    path: "/v1/heartbeat",
    timestamp,
    macHex: mac,
    body,
    inventoried: true,
  });

  expect(response.status).toBe(401);
  expect(store.fleet.sequence).toBe(0);
});

test("duplicate heartbeat sequence is rejected without a second mutation", async () => {
  const timestamp = "2026-01-01T00:00:00.000Z";
  const store = new MemoryFleetStore("example-fleet", { now: () => timestamp });
  store.fleet.epoch = 2;
  store.fleet.sessionId = "d".repeat(64);
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 2,
    sessionId: store.fleet.sessionId,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp,
    snapshot: snapshot(timestamp),
  });
  const mac = await signCanonical(
    key,
    "POST",
    "/v1/heartbeat",
    timestamp,
    body,
  );
  const input = {
    method: "POST",
    path: "/v1/heartbeat",
    timestamp,
    macHex: mac,
    body,
    inventoried: true,
  };
  const accepted = await handleHeartbeat(store, secrets(), input);
  expect(accepted.status).toBe(200);
  expect(store.fleet.sequence).toBe(1);
  const duplicate = await handleHeartbeat(store, secrets(), input);
  expect(duplicate.status).toBe(401);
  expect(store.fleet.sequence).toBe(1);
});

test("session identity failure and counter overflow leave authority unchanged", async () => {
  const timestamp = "2026-01-01T00:00:00.000Z";
  const body = canonicalize({
    buildId: digest,
    fleetId: "example-fleet",
    nonce,
    protocolVersion: 1,
    timestamp,
  });
  const mac = await signCanonical(key, "POST", "/v1/session", timestamp, body);
  const input = {
    method: "POST",
    path: "/v1/session",
    timestamp,
    macHex: mac,
    body,
    inventoried: true,
  };

  for (const source of [
    () => nonce,
    () => {
      throw new Error("rng failed");
    },
  ]) {
    const store = new MemoryFleetStore("example-fleet", {
      now: () => timestamp,
    });
    const response = await handleSession(store, secrets(), input, source);
    expect(response.status).toBe(401);
    expect(store.nonces.size).toBe(0);
    expect(store.fleet).toMatchObject({
      epoch: 0,
      leaseGeneration: 0,
      sessionId: null,
      sequence: 0,
    });
  }

  const overflow = new MemoryFleetStore("example-fleet", {
    now: () => timestamp,
  });
  overflow.fleet.epoch = Number.MAX_SAFE_INTEGER;
  overflow.fleet.leaseGeneration = Number.MAX_SAFE_INTEGER;
  const response = await handleSession(overflow, secrets(), input, () =>
    "d".repeat(64),
  );
  expect(response.status).toBe(401);
  expect(overflow.nonces.size).toBe(0);
  expect(overflow.fleet).toMatchObject({
    epoch: Number.MAX_SAFE_INTEGER,
    leaseGeneration: Number.MAX_SAFE_INTEGER,
    sessionId: null,
    sequence: 0,
  });
});

test("malformed session envelopes leave all authority counters unchanged", async () => {
  const timestamp = "2026-01-01T00:00:00.000Z";
  const body = canonicalize({
    buildId: digest,
    fleetId: "example-fleet",
    nonce,
    protocolVersion: 1,
    timestamp,
  });
  const macHex = await signCanonical(
    key,
    "POST",
    "/v1/session",
    timestamp,
    body,
  );
  const validInput = {
    method: "POST",
    path: "/v1/session",
    timestamp,
    macHex,
    body,
    inventoried: true,
  };
  for (const input of [
    { ...validInput, method: "PUT" },
    { ...validInput, path: "/v1/heartbeat" },
    { ...validInput, timestamp: "2026-01-01T00:00:01.000Z" },
    { ...validInput, macHex: "0".repeat(64) },
  ]) {
    const store = new MemoryFleetStore("example-fleet", {
      now: () => timestamp,
    });
    const response = await handleSession(store, secrets(), input, () =>
      "d".repeat(64),
    );
    expect(response.status).toBe(401);
    expect(store.nonces.size).toBe(0);
    expect(store.fleet).toMatchObject({
      epoch: 0,
      leaseGeneration: 0,
      sessionId: null,
      sequence: 0,
    });
  }
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
    snapshot: snapshot(hbTs),
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
