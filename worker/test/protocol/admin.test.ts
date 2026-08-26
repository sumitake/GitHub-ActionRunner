import { expect, test } from "vitest";

import {
  decodeQueueRecoveryExpectation,
  encodeQueueRecoveryExpectation,
  evaluateQueueRecoveryObservation,
  parseAdminCommand,
  parseQueueRecoveryCommand,
  type ArchiveReactivationCommandV1,
  type QueueRecoveryCommandV1,
  type QueueRecoveryExpectation,
} from "../../src/protocol/admin";
import { canonicalize } from "../../src/protocol/canonical";

const command: QueueRecoveryCommandV1 = {
  protocolVersion: 1,
  kind: "queue-recovery",
  fleetId: "example-fleet",
  timestamp: "2026-01-01T00:00:10.000Z",
  nonce: "b".repeat(64),
  repositoryAlias: "repo-a",
  transitionEpoch: 7,
  riskEvidenceDigest: "a".repeat(64),
  sourceHead: "0123456789abcdef0123456789abcdef01234567",
  recoveryEvidenceDigest: "d".repeat(64),
};

const archiveCommand: ArchiveReactivationCommandV1 = {
  protocolVersion: 1,
  kind: "archive-reactivation",
  fleetId: "example-fleet",
  timestamp: "2026-01-01T00:00:10.000Z",
  nonce: "f".repeat(64),
  repositoryAlias: "repo-a",
  configurationRevision: 8,
  transitionEpoch: 3,
  leaseGeneration: 11,
  workflowAuditDigest: "a".repeat(64),
  securityAuditDigest: "b".repeat(64),
  hostedBootstrapDigest: "c".repeat(64),
  queueClearanceDigest: "d".repeat(64),
  canaryEvidenceDigest: "e".repeat(64),
  observeUntil: "2026-01-01T00:01:10.000Z",
};

const legacyRollbackCommand = {
  protocolVersion: 1,
  kind: "legacy-rollback",
  fleetId: "example-fleet",
  timestamp: "2026-01-01T00:00:10.000Z",
  nonce: "9".repeat(64),
  repositoryAlias: "repo-a",
  workflow: "legacy-canary.yml",
  revision: "0123456789abcdef0123456789abcdef01234567",
  legacyLabel: "legacy-runners",
  configurationRevision: 8,
  transitionEpoch: 3,
  leaseGeneration: 11,
  fenceGeneration: 5,
  observeUntil: "2026-01-01T00:01:10.000Z",
} as const;

const expectation: QueueRecoveryExpectation = {
  schemaVersion: 1,
  fleetId: command.fleetId,
  repositoryAlias: command.repositoryAlias,
  transitionEpoch: command.transitionEpoch,
  riskEvidenceDigest: command.riskEvidenceDigest,
  sourceHead: command.sourceHead,
  recoveryEvidenceDigest: command.recoveryEvidenceDigest,
  observeUntil: "2026-01-01T00:01:10.000Z",
};

function observation(
  status: "pending" | "verified",
  overrides: Record<string, unknown> = {},
): string {
  return canonicalize({
    schemaVersion: 1,
    status,
    fleetId: expectation.fleetId,
    repositoryAlias: expectation.repositoryAlias,
    transitionEpoch: expectation.transitionEpoch,
    riskEvidenceDigest: expectation.riskEvidenceDigest,
    sourceHead: expectation.sourceHead,
    recoveryEvidenceDigest: expectation.recoveryEvidenceDigest,
    verifiedAt: status === "pending" ? null : "2026-01-01T00:00:20.000Z",
    ...overrides,
  });
}

test("queue-recovery is one strict canonical admin command member", () => {
  const body = canonicalize(command);
  expect(parseQueueRecoveryCommand(body)).toEqual(command);

  for (const invalid of [
    { ...command, kind: "clear-all" },
    { ...command, nonce: "b".repeat(63) },
    { ...command, repositoryAlias: "Repo-A" },
    { ...command, transitionEpoch: 0 },
    { ...command, riskEvidenceDigest: "A".repeat(64) },
    { ...command, sourceHead: "unknown" },
    { ...command, recoveryEvidenceDigest: "d".repeat(63) },
    { ...command, extra: true },
  ]) {
    expect(() => parseQueueRecoveryCommand(canonicalize(invalid))).toThrow();
  }
  expect(() => parseQueueRecoveryCommand(JSON.stringify(command))).toThrow();
});

test("archive-reactivation is the only added exact admin command member", () => {
  expect(parseAdminCommand(canonicalize(archiveCommand))).toEqual(
    archiveCommand,
  );
  expect(parseAdminCommand(canonicalize(command))).toEqual(command);
  for (const invalid of [
    { ...archiveCommand, configurationRevision: 0 },
    { ...archiveCommand, transitionEpoch: Number.MAX_SAFE_INTEGER + 1 },
    { ...archiveCommand, leaseGeneration: 0 },
    { ...archiveCommand, workflowAuditDigest: "A".repeat(64) },
    { ...archiveCommand, securityAuditDigest: "b".repeat(63) },
    { ...archiveCommand, observeUntil: archiveCommand.timestamp },
    { ...archiveCommand, observeUntil: "2026-02-30T00:00:00.000Z" },
    { ...archiveCommand, extra: true },
  ]) {
    expect(() => parseAdminCommand(canonicalize(invalid))).toThrow();
  }
  expect(() =>
    parseAdminCommand(
      canonicalize({ ...archiveCommand, kind: "archive-clear" }),
    ),
  ).toThrow();
});

test("legacy-rollback is one strict canonical admin command member", () => {
  expect(parseAdminCommand(canonicalize(legacyRollbackCommand))).toEqual(
    legacyRollbackCommand,
  );
  expect(parseAdminCommand(canonicalize(command))).toEqual(command);
  expect(parseAdminCommand(canonicalize(archiveCommand))).toEqual(
    archiveCommand,
  );

  for (const invalid of [
    { ...legacyRollbackCommand, kind: "legacy" },
    { ...legacyRollbackCommand, workflow: "../legacy.yml" },
    { ...legacyRollbackCommand, revision: "f".repeat(39) },
    { ...legacyRollbackCommand, legacyLabel: " legacy-runners" },
    { ...legacyRollbackCommand, legacyLabel: "legacy/runners" },
    { ...legacyRollbackCommand, configurationRevision: 0 },
    { ...legacyRollbackCommand, transitionEpoch: 0 },
    { ...legacyRollbackCommand, leaseGeneration: 0 },
    { ...legacyRollbackCommand, fenceGeneration: 0 },
    {
      ...legacyRollbackCommand,
      observeUntil: "2026-01-01T00:01:09.999Z",
    },
    {
      ...legacyRollbackCommand,
      observeUntil: "2026-01-01T00:01:10.001Z",
    },
    { ...legacyRollbackCommand, extra: true },
  ]) {
    expect(() => parseAdminCommand(canonicalize(invalid))).toThrow();
  }
  expect(() =>
    parseAdminCommand(JSON.stringify(legacyRollbackCommand)),
  ).toThrow();
});

test("queue-recovery expectation and observation have one exact identity", () => {
  const payload = encodeQueueRecoveryExpectation(expectation);
  expect(decodeQueueRecoveryExpectation(payload)).toEqual(expectation);
  expect(() =>
    encodeQueueRecoveryExpectation({
      ...expectation,
      extra: "forbidden",
    } as QueueRecoveryExpectation),
  ).toThrow();
  expect(() =>
    decodeQueueRecoveryExpectation({ ...payload, extra: "forbidden" }),
  ).toThrow();

  expect(
    evaluateQueueRecoveryObservation(
      expectation,
      observation("pending"),
      "2026-01-01T00:00:20.000Z",
    ),
  ).toEqual({ kind: "pending" });
  expect(
    evaluateQueueRecoveryObservation(
      expectation,
      observation("verified"),
      "2026-01-01T00:00:21.000Z",
    ),
  ).toEqual({
    kind: "verified",
    verifiedAt: "2026-01-01T00:00:20.000Z",
  });
});

test("wrong, widened, future, and late queue observations fail closed", () => {
  const cases = [
    observation("verified", { repositoryAlias: "repo-b" }),
    observation("verified", { transitionEpoch: 8 }),
    observation("verified", { riskEvidenceDigest: "f".repeat(64) }),
    observation("verified", { sourceHead: "f".repeat(40) }),
    observation("verified", { recoveryEvidenceDigest: "e".repeat(64) }),
    observation("verified", { verifiedAt: "2026-01-01T00:00:22.000Z" }),
    observation("verified", { extra: true }),
    "not-json",
  ];
  for (const [index, body] of cases.entries()) {
    const receiptTime =
      index === 5 ? "2026-01-01T00:00:21.000Z" : "2026-01-01T00:00:30.000Z";
    expect(
      evaluateQueueRecoveryObservation(expectation, body, receiptTime),
    ).toEqual({ kind: "failed" });
  }
  expect(
    evaluateQueueRecoveryObservation(
      expectation,
      observation("pending"),
      expectation.observeUntil,
    ),
  ).toEqual({ kind: "failed" });
});
