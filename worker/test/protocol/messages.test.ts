import { expect, test } from "vitest";

import { canonicalize } from "../../src/protocol/canonical";
import {
  admissionAuthorityKey,
  assertHeartbeatBudget,
  localLeaseDeadlineMs,
  parseLease,
  parseSessionRequest,
} from "../../src/protocol/messages";

const digest = "a".repeat(64);
const session = "b".repeat(64);

const validLease = {
  archivedDisabledAliases: ["repo-a"],
  canaryScaleSet: "canary-set",
  durationMs: 8000,
  expiry: "2026-01-01T00:00:08.000Z",
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
    expiry: "2026-01-01T00:00:09.000Z",
  });
  expect(admissionAuthorityKey(left)).toBe(admissionAuthorityKey(right));
  const changed = parseLease({
    ...validLease,
    durationMs: 9000,
    expiry: "2026-01-01T00:00:09.000Z",
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
});

test("send-anchored local deadline is strictly shorter than server duration", () => {
  expect(localLeaseDeadlineMs(1_000, 8_000, 1_000)).toBe(8_000);
  expect(() => localLeaseDeadlineMs(1_000, 8_000, 8_000)).toThrow();
  expect(() => localLeaseDeadlineMs(1_000, 8_000, 0)).toThrow();
});
