import { expect, test } from "vitest";

import { canonicalize } from "../../src/protocol/canonical";
import {
  archiveEvidenceState,
  archiveRestrictionReason,
  decodeArchiveExpectation,
  encodeArchiveExpectation,
  evaluateArchiveObservation,
  type ArchiveReactivationExpectation,
  type ArchiveSweepExpectation,
} from "../../src/routing/archive";
import type { RepositoryRecord } from "../../src/state/memory";

const now = "2026-01-01T00:00:10.000Z";

const sweep: ArchiveSweepExpectation = {
  schemaVersion: 1,
  kind: "archive-sweep",
  fleetId: "example-fleet",
  repositoryAlias: "repo-a",
  configurationRevision: 7,
  transitionEpoch: 3,
  observeUntil: "2026-01-01T00:01:10.000Z",
};

const reactivation: ArchiveReactivationExpectation = {
  schemaVersion: 1,
  kind: "archive-reactivation",
  fleetId: "example-fleet",
  repositoryAlias: "repo-a",
  configurationRevision: 8,
  transitionEpoch: 3,
  leaseGeneration: 11,
  startedAt: "2026-01-01T00:00:10.000Z",
  workflowAuditDigest: "a".repeat(64),
  securityAuditDigest: "b".repeat(64),
  hostedBootstrapDigest: "c".repeat(64),
  queueClearanceDigest: "d".repeat(64),
  canaryEvidenceDigest: "e".repeat(64),
  observeUntil: "2026-01-01T00:01:10.000Z",
};

function repository(
  overrides: Partial<RepositoryRecord> = {},
): RepositoryRecord {
  return {
    alias: "repo-a",
    expectedRoute: "hosted",
    confirmedRoute: "hosted",
    archiveEligibility: "active",
    archivePolicyRevision: null,
    archiveObservedAt: now,
    archived: false,
    selectorEvidenceAt: now,
    openQueueRisk: null,
    ...overrides,
  };
}

test("archive expectation codecs are exact and canonical", () => {
  const sweepPayload = encodeArchiveExpectation(sweep);
  expect(decodeArchiveExpectation(sweepPayload)).toEqual(sweep);
  const reactivationPayload = encodeArchiveExpectation(reactivation);
  expect(decodeArchiveExpectation(reactivationPayload)).toEqual(reactivation);

  expect(() =>
    decodeArchiveExpectation({
      archive: canonicalize({ ...sweep, unknown: true }),
    }),
  ).toThrow();
  expect(() =>
    decodeArchiveExpectation({
      archive: JSON.stringify(sweep),
    }),
  ).toThrow();
  expect(() =>
    encodeArchiveExpectation({
      ...sweep,
      configurationRevision: Number.MAX_SAFE_INTEGER + 1,
    }),
  ).toThrow();
  expect(() =>
    encodeArchiveExpectation({
      ...sweep,
      observeUntil: "2026-02-30T00:00:00.000Z",
    }),
  ).toThrow();
});

test("archive observations bind identity and reject the exact deadline", () => {
  const body = canonicalize({
    schemaVersion: 1,
    kind: "archive-sweep",
    status: "observed",
    fleetId: sweep.fleetId,
    repositoryAlias: sweep.repositoryAlias,
    configurationRevision: sweep.configurationRevision,
    transitionEpoch: sweep.transitionEpoch,
    archived: true,
  });
  expect(evaluateArchiveObservation(sweep, body, now)).toEqual({
    kind: "observed",
    archived: true,
  });
  expect(evaluateArchiveObservation(sweep, body, sweep.observeUntil)).toEqual({
    kind: "failed",
  });
  expect(
    evaluateArchiveObservation(
      sweep,
      canonicalize({
        ...JSON.parse(body),
        repositoryAlias: "repo-b",
      }),
      now,
    ),
  ).toEqual({ kind: "failed" });

  const verifiedAt = now;
  const verified = canonicalize({
    ...reactivation,
    status: "verified",
    archived: false,
    verifiedAt,
  });
  expect(evaluateArchiveObservation(reactivation, verified, now)).toEqual({
    kind: "verified",
    verifiedAt,
  });
  expect(
    evaluateArchiveObservation(
      reactivation,
      canonicalize({
        ...reactivation,
        status: "verified",
        archived: false,
        verifiedAt: "2026-01-01T00:00:09.999Z",
      }),
      now,
    ),
  ).toEqual({ kind: "failed" });
  expect(
    evaluateArchiveObservation(
      reactivation,
      canonicalize({
        ...reactivation,
        status: "verified",
        archived: true,
        verifiedAt,
      }),
      now,
    ),
  ).toEqual({ kind: "failed" });
});

test("one archive predicate fails closed at malformed, future, and age equality", () => {
  expect(archiveEvidenceState(repository(), now, 2_000)).toBe("fresh");
  expect(archiveRestrictionReason(repository(), now, 2_000)).toBeNull();
  expect(
    archiveRestrictionReason(
      repository({ archiveObservedAt: "not-a-time" }),
      now,
      2_000,
    ),
  ).toBe("invalid-evidence");
  expect(
    archiveRestrictionReason(
      repository({ archiveObservedAt: "2026-01-01T00:00:11.000Z" }),
      now,
      2_000,
    ),
  ).toBe("future-evidence");
  expect(
    archiveRestrictionReason(
      repository({ archiveObservedAt: "2026-01-01T00:00:08.000Z" }),
      now,
      2_000,
    ),
  ).toBe("stale-evidence");
  expect(
    archiveRestrictionReason(
      repository({ archiveEligibility: "pending-reactivation" }),
      now,
      2_000,
    ),
  ).toBe("pending-reactivation");
  expect(
    archiveRestrictionReason(repository({ archived: true }), now, 2_000),
  ).toBe("archived");
});
