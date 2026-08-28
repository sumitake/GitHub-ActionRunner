import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "vitest";

import { canonicalize } from "../../src/protocol/canonical";
import {
  admissionAuthorityKey,
  assertHeartbeatBudget,
  localLeaseDeadlineMs,
  parseHeartbeatRequest,
  parseHeartbeatResponse,
  parseLease,
  parseSessionRequest,
  parseSessionResponse,
} from "../../src/protocol/messages";

const fixtureRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../tests/fixtures/protocol/v1",
);

const digest = "a".repeat(64);
const session = "b".repeat(64);

const validLease = {
  archivedDisabledAliases: ["repo-a"],
  canaryScaleSet: "canary-set",
  durationMs: 8000,
  expiry: "2026-01-01T00:00:09.000Z",
  fleetId: "example-fleet",
  holder: "portable",
  leaseGeneration: 3,
  localPolicyEpoch: 9,
  maxCapacity: 1,
  mode: "canary-only",
  policyDigest: digest,
  protocolVersion: 1,
  repositoryPolicyRevision: 4,
  serverEpoch: 2,
  sessionId: session,
};

const validHeartbeat = {
  epoch: 2,
  fenceGeneration: 1,
  fleetId: "example-fleet",
  holder: "portable",
  protocolVersion: 1,
  sequence: 1,
  sessionId: session,
  snapshot: {
    acquisitionMode: "enabled",
    assignedJobs: 2,
    buildId: digest,
    capacity: {
      available: 1,
      configured: 2,
      effective: 2,
      occupied: 1,
      queued: 0,
    },
    degraded: false,
    fleetAlias: "example-fleet",
    hostProfileId: "strict-linux-v1",
    lastTerminalAt: "2026-01-01T00:00:00.000Z",
    observedAt: "2026-01-01T00:00:01.000Z",
    oldestLiveAssignmentAgeMs: 1000,
    policyDigest: digest,
    policyEpoch: 1,
    repositoryPolicyRevision: 1,
    runningJobs: 1,
    unassignedReleasedListeners: 0,
  },
  timestamp: "2026-01-01T00:00:01.000Z",
};

const validHeartbeatResponse = {
  fleetId: "example-fleet",
  lease: validLease,
  maintenance: {
    kind: "none",
    leaseGeneration: validLease.leaseGeneration,
    sessionId: session,
  },
  noLeaseReason: null,
  protocolVersion: 1,
  receiptTime: "2026-01-01T00:00:01.000Z",
  routingState: "PORTABLE_CANARY",
  sequence: 1,
  sessionId: session,
};

test("session request rejects unknown, missing, and noncanonical fields", () => {
  const body = canonicalize({
    buildId: digest,
    fleetId: "example-fleet",
    nonce: session,
    protocolVersion: 1,
    timestamp: "2026-01-01T00:00:00.000Z",
  });
  expect(parseSessionRequest(body).fleetId).toBe("example-fleet");
  expect(() =>
    parseSessionRequest(body.replace("example-fleet", "Example")),
  ).toThrow();
  expect(() => parseSessionRequest('{"fleetId":"example-fleet"}')).toThrow();
  expect(() =>
    parseSessionRequest(
      canonicalize({
        buildId: digest,
        extra: true,
        fleetId: "example-fleet",
        nonce: session,
        protocolVersion: 1,
        timestamp: "2026-01-01T00:00:00.000Z",
      }),
    ),
  ).toThrow();
});

test("session response binds a fresh initial session and monotonic boundary", () => {
  const response = {
    epoch: 1,
    fleetId: "example-fleet",
    leaseGeneration: 1,
    leaseNotBefore: "2026-01-01T00:00:00.000Z",
    nonce: "a".repeat(64),
    protocolVersion: 1,
    receiptTime: "2026-01-01T00:00:00.000Z",
    sequence: 0,
    sessionId: "c".repeat(64),
  };
  expect(parseSessionResponse(canonicalize(response)).sequence).toBe(0);
  expect(() =>
    parseSessionResponse(canonicalize({ ...response, sequence: 1 })),
  ).toThrow();
  expect(() =>
    parseSessionResponse(
      canonicalize({ ...response, sessionId: response.nonce }),
    ),
  ).toThrow();
  expect(() =>
    parseSessionResponse(
      canonicalize({
        ...response,
        leaseNotBefore: "2025-12-31T23:59:59.999Z",
      }),
    ),
  ).toThrow();
});

test("Worker canonical messages match every frozen Go exchange fixture", () => {
  const fixtures = [
    ["session-request", parseSessionRequest],
    ["session-response", parseSessionResponse],
    ["heartbeat-request", parseHeartbeatRequest],
    ["heartbeat-response-lease", parseHeartbeatResponse],
    ["heartbeat-response-no-lease", parseHeartbeatResponse],
  ] as const;
  for (const [name, parse] of fixtures) {
    const document = JSON.parse(
      readFileSync(join(fixtureRoot, `${name}.json`), "utf8"),
    ) as unknown;
    const canonical = readFileSync(
      join(fixtureRoot, `${name}.canonical.txt`),
      "utf8",
    ).trimEnd();
    expect(canonicalize(document), name).toBe(canonical);
    expect(() => parse(canonical), name).not.toThrow();
  }
});

test("protocol scalars reject calendar-invalid timestamps and unsafe integers", () => {
  expect(() =>
    parseSessionRequest(
      canonicalize({
        buildId: digest,
        fleetId: "example-fleet",
        nonce: session,
        protocolVersion: 1,
        timestamp: "2026-02-31T00:00:00.000Z",
      }),
    ),
  ).toThrow();
  expect(() =>
    parseLease({
      ...validLease,
      serverEpoch: Number.MAX_SAFE_INTEGER + 1,
    }),
  ).toThrow();
});

test("heartbeat snapshot rejects internally inconsistent health", () => {
  expect(parseHeartbeatRequest(canonicalize(validHeartbeat)).sequence).toBe(1);
  expect(() =>
    parseHeartbeatRequest(
      canonicalize({
        ...validHeartbeat,
        snapshot: {
          ...validHeartbeat.snapshot,
          capacity: {
            ...validHeartbeat.snapshot.capacity,
            available: 2,
          },
        },
      }),
    ),
  ).toThrow();
  expect(() =>
    parseHeartbeatRequest(
      canonicalize({
        ...validHeartbeat,
        snapshot: {
          ...validHeartbeat.snapshot,
          assignedJobs: 0,
          runningJobs: 1,
        },
      }),
    ),
  ).toThrow();
  expect(() =>
    parseHeartbeatRequest(
      canonicalize({
        ...validHeartbeat,
        snapshot: {
          ...validHeartbeat.snapshot,
          lastTerminalAt: "2026-01-01T00:00:02.000Z",
        },
      }),
    ),
  ).toThrow();
});

test("heartbeat response is exact and binds lease state", () => {
  expect(
    parseHeartbeatResponse(canonicalize(validHeartbeatResponse)).lease?.mode,
  ).toBe("canary-only");
  expect(() =>
    parseHeartbeatResponse(
      canonicalize({
        ...validHeartbeatResponse,
        maintenance: { ...validHeartbeatResponse.maintenance, extra: true },
      }),
    ),
  ).toThrow();
  expect(() =>
    parseHeartbeatResponse(
      canonicalize({
        ...validHeartbeatResponse,
        noLeaseReason: "lease-disabled",
      }),
    ),
  ).toThrow();
  expect(() =>
    parseHeartbeatResponse(
      canonicalize({
        ...validHeartbeatResponse,
        sessionId: "d".repeat(64),
      }),
    ),
  ).toThrow();
});

test("heartbeat lease expiry exactly equals receipt plus bounded duration", () => {
  for (const lease of [
    { ...validLease, expiry: "2026-01-01T00:00:08.999Z" },
    { ...validLease, expiry: "2026-01-01T00:00:09.001Z" },
    { ...validLease, durationMs: 9_223_372_036_855 },
  ]) {
    expect(() =>
      parseHeartbeatResponse(
        canonicalize({ ...validHeartbeatResponse, lease }),
      ),
    ).toThrow();
  }
});

test("heartbeat response enforces routing holder and mode matrix", () => {
  const fullLease = {
    ...validLease,
    canaryScaleSet: null,
    maxCapacity: 2,
    mode: "enabled",
  };
  const response = {
    ...validHeartbeatResponse,
    lease: fullLease,
    maintenance: {
      ...validHeartbeatResponse.maintenance,
      leaseGeneration: fullLease.leaseGeneration,
    },
    routingState: "PORTABLE",
  };
  expect(parseHeartbeatResponse(canonicalize(response)).lease?.mode).toBe(
    "enabled",
  );
  for (const next of [
    { ...response, routingState: "HOSTED" },
    { ...response, routingState: "DRAINING_TO_HOSTED" },
    { ...response, routingState: "PORTABLE_CANARY" },
    { ...response, lease: { ...fullLease, holder: "legacy" } },
    {
      ...response,
      lease: { ...fullLease, canaryScaleSet: "canary-set" },
    },
    { ...response, routingState: "LEGACY" },
  ]) {
    expect(() => parseHeartbeatResponse(canonicalize(next))).toThrow();
  }
});

test("heartbeat response and standalone lease require positive generation", () => {
  const response = {
    ...validHeartbeatResponse,
    lease: { ...validLease, leaseGeneration: 0 },
    maintenance: {
      ...validHeartbeatResponse.maintenance,
      leaseGeneration: 0,
    },
  };
  expect(() => parseHeartbeatResponse(canonicalize(response))).toThrow();
  expect(() =>
    parseHeartbeatResponse(
      canonicalize({
        ...response,
        lease: null,
        noLeaseReason: "routing-hosted",
        routingState: "HOSTED",
      }),
    ),
  ).toThrow();
  expect(() => parseLease({ ...validLease, leaseGeneration: 0 })).toThrow();
});

test("lease validation rejects unsorted aliases and wrong canary shape", () => {
  const lease = parseLease(validLease);
  expect(lease.archivedDisabledAliases).toEqual(["repo-a"]);
  expect(() =>
    parseLease({
      ...validLease,
      archivedDisabledAliases: ["repo-b", "repo-a"],
    }),
  ).toThrow();
  expect(() =>
    parseLease({
      ...validLease,
      archivedDisabledAliases: ["repo-a", "repo-a"],
    }),
  ).toThrow();
  expect(() => parseLease({ ...validLease, extra: 1 })).toThrow();
  expect(() =>
    parseLease({ ...validLease, mode: "enabled", maxCapacity: 0 }),
  ).toThrow();
  expect(() => parseLease({ ...validLease, canaryScaleSet: null })).toThrow();
});

test("admission authority key ignores renewal envelope fields", () => {
  const left = parseLease(validLease);
  const right = parseLease({
    ...validLease,
    expiry: "2026-01-01T00:00:10.000Z",
  });
  expect(admissionAuthorityKey(left)).toBe(admissionAuthorityKey(right));
  const changed = parseLease({
    ...validLease,
    durationMs: 9000,
    expiry: "2026-01-01T00:00:10.000Z",
  });
  expect(admissionAuthorityKey(left)).not.toBe(admissionAuthorityKey(changed));
});

test("heartbeat inequality requires every symbolic term", () => {
  assertHeartbeatBudget({
    leaseDurationMs: 20,
    maxAttemptIntervalMs: 4,
    deadlineMs: 3,
    shorteningMarginMs: 2,
    lostRenewals: 1,
  });
  expect(() =>
    assertHeartbeatBudget({
      leaseDurationMs: 10,
      maxAttemptIntervalMs: 4,
      deadlineMs: 3,
      shorteningMarginMs: 2,
      lostRenewals: 1,
    }),
  ).toThrow();
  expect(() =>
    assertHeartbeatBudget({
      leaseDurationMs: 20,
      maxAttemptIntervalMs: 4,
      deadlineMs: 3,
      shorteningMarginMs: 2,
      lostRenewals: 0,
    }),
  ).toThrow();
  expect(() =>
    assertHeartbeatBudget({
      leaseDurationMs: 20.5,
      maxAttemptIntervalMs: 4,
      deadlineMs: 3,
      shorteningMarginMs: 2,
      lostRenewals: 1,
    }),
  ).toThrow();
  expect(() =>
    assertHeartbeatBudget({
      leaseDurationMs: 20,
      maxAttemptIntervalMs: 4,
      deadlineMs: 3,
      shorteningMarginMs: 2,
      lostRenewals: 1.5,
    }),
  ).toThrow();
});

test("send-anchored local deadline is strictly shorter than server duration", () => {
  expect(localLeaseDeadlineMs(1_000, 8_000, 1_000)).toBe(8_000);
  expect(() => localLeaseDeadlineMs(1_000, 8_000, 8_000)).toThrow();
  expect(() => localLeaseDeadlineMs(1_000, 8_000, 0)).toThrow();
});
