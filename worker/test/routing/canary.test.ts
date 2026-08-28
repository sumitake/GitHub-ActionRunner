import { expect, test } from "vitest";

import {
  decodeCanaryExpectation,
  encodeCanaryEvidence,
  encodeCanaryExpectation,
  evaluateCanaryObservation,
  type CanaryExpectation,
} from "../../src/routing/canary";

const expectation: CanaryExpectation = {
  schemaVersion: 1,
  repositoryAlias: "repo-a",
  workflow: "recovery-canary.yml",
  revision: "0123456789abcdef0123456789abcdef01234567",
  scaleSet: "portable-canary",
  environment: "self-hosted",
  startedAt: "2026-01-01T00:00:00.000Z",
  observeUntil: "2026-01-01T00:05:00.000Z",
  sessionId: "1".repeat(64),
  leaseGeneration: 7,
};

function observation(
  status: "pending" | "success" | "failure" | "cancelled",
  overrides: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    schemaVersion: 1,
    status,
    repositoryAlias: expectation.repositoryAlias,
    workflow: expectation.workflow,
    revision: expectation.revision,
    scaleSet: expectation.scaleSet,
    environment: expectation.environment,
    completedAt: status === "pending" ? null : "2026-01-01T00:01:00.000Z",
    ...overrides,
  });
}

test("canary expectation has one strict durable representation", () => {
  const payload = encodeCanaryExpectation(expectation);
  expect(payload).toEqual({ expectation: JSON.stringify(expectation) });
  expect(decodeCanaryExpectation(payload)).toEqual(expectation);
  expect(() =>
    encodeCanaryExpectation({
      ...expectation,
      extra: "value",
    } as CanaryExpectation),
  ).toThrow();
  expect(() =>
    encodeCanaryEvidence({
      ...expectation,
      completedAt: "2026-01-01T00:01:00.000Z",
      observedAt: "2026-01-01T00:01:01.000Z",
      heartbeatSequence: 11,
      extra: "value",
    } as Parameters<typeof encodeCanaryEvidence>[0]),
  ).toThrow();

  for (const invalid of [
    {},
    { ...payload, extra: "value" },
    {
      expectation:
        payload.expectation?.replace(
          '"leaseGeneration":7',
          '"leaseGeneration":0',
        ) ?? "",
    },
    {
      expectation:
        payload.expectation?.replace(
          '"environment":"self-hosted"',
          '"environment":"hosted"',
        ) ?? "",
    },
    {
      expectation:
        payload.expectation?.replace(
          '"observeUntil":"2026-01-01T00:05:00.000Z"',
          '"observeUntil":"2026-01-01T00:00:00.000Z"',
        ) ?? "",
    },
  ]) {
    expect(() => decodeCanaryExpectation(invalid)).toThrow();
  }
});

test("only an exact in-window terminal observation passes", () => {
  const evaluated = evaluateCanaryObservation(
    expectation,
    observation("success"),
    "2026-01-01T00:01:01.000Z",
    11,
  );
  expect(evaluated).toEqual({
    kind: "passed",
    evidence: {
      ...expectation,
      completedAt: "2026-01-01T00:01:00.000Z",
      observedAt: "2026-01-01T00:01:01.000Z",
      heartbeatSequence: 11,
    },
  });
  expect(
    evaluateCanaryObservation(
      expectation,
      observation("pending"),
      "2026-01-01T00:01:01.000Z",
      11,
    ),
  ).toEqual({ kind: "pending" });
  expect(
    evaluateCanaryObservation(
      expectation,
      observation("failure"),
      "2026-01-01T00:01:01.000Z",
      11,
    ),
  ).toEqual({ kind: "failed" });
  expect(
    evaluateCanaryObservation(
      expectation,
      observation("cancelled"),
      "2026-01-01T00:01:01.000Z",
      11,
    ),
  ).toEqual({ kind: "failed" });
});

test("wrong, stale, late, future, malformed, and widened observations fail closed", () => {
  const cases = [
    observation("success", { repositoryAlias: "repo-b" }),
    observation("success", { workflow: "wrong.yml" }),
    observation("success", { revision: "f".repeat(40) }),
    observation("success", { scaleSet: "wrong-canary" }),
    observation("success", { environment: "hosted" }),
    observation("success", { completedAt: "2025-12-31T23:59:59.999Z" }),
    observation("success", { completedAt: "2026-01-01T00:05:00.001Z" }),
    observation("success", { completedAt: "2026-01-01T00:02:00.000Z" }),
    observation("success", { extra: true }),
    "not-json",
  ];
  for (const [index, body] of cases.entries()) {
    const receiptTime =
      index === 7 ? "2026-01-01T00:01:59.999Z" : "2026-01-01T00:04:00.000Z";
    expect(
      evaluateCanaryObservation(expectation, body, receiptTime, 11),
    ).toEqual({ kind: "failed" });
  }
});
