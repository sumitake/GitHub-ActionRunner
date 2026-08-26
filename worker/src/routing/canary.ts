import { isRfc3339MsZ } from "../protocol/auth";
import { HEX64 } from "../protocol/messages";

const ALIAS = /^[a-z][a-z0-9-]{0,63}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const WORKFLOW = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml$/;
const EXPECTATION_FIELDS = [
  "schemaVersion",
  "repositoryAlias",
  "workflow",
  "revision",
  "scaleSet",
  "environment",
  "startedAt",
  "observeUntil",
  "sessionId",
  "leaseGeneration",
] as const;
const EVIDENCE_FIELDS = [
  ...EXPECTATION_FIELDS,
  "completedAt",
  "observedAt",
  "heartbeatSequence",
] as const;

export type CanaryExpectation = {
  schemaVersion: 1;
  repositoryAlias: string;
  workflow: string;
  revision: string;
  scaleSet: string;
  environment: "self-hosted";
  startedAt: string;
  observeUntil: string;
  sessionId: string;
  leaseGeneration: number;
};

export type CanaryEvidence = CanaryExpectation & {
  completedAt: string;
  observedAt: string;
  heartbeatSequence: number;
};

export type CanaryEvaluation =
  | { kind: "pending" }
  | { kind: "failed" }
  | { kind: "passed"; evidence: CanaryEvidence };

type CanaryObservation = {
  schemaVersion: 1;
  status: "pending" | "success" | "failure" | "cancelled";
  repositoryAlias: string;
  workflow: string;
  revision: string;
  scaleSet: string;
  environment: "self-hosted";
  completedAt: string | null;
};

export function encodeCanaryExpectation(
  expectation: CanaryExpectation,
): Record<string, string> {
  assertExactKeys(
    expectation as unknown as Readonly<Record<string, unknown>>,
    EXPECTATION_FIELDS,
  );
  assertCanaryExpectation(expectation);
  return { expectation: JSON.stringify(expectation) };
}

export function decodeCanaryExpectation(
  payload: Readonly<Record<string, string>>,
): CanaryExpectation {
  if (
    Object.keys(payload).length !== 1 ||
    typeof payload.expectation !== "string"
  ) {
    throw new Error("canary expectation payload is invalid");
  }
  const parsed = parseObject(payload.expectation);
  assertExactKeys(parsed, EXPECTATION_FIELDS);
  const expectation = parsed as CanaryExpectation;
  assertCanaryExpectation(expectation);
  if (JSON.stringify(expectation) !== payload.expectation) {
    throw new Error("canary expectation payload is not canonical");
  }
  return expectation;
}

export function evaluateCanaryObservation(
  expectation: CanaryExpectation,
  body: string,
  receiptTime: string,
  heartbeatSequence: number,
): CanaryEvaluation {
  try {
    assertCanaryExpectation(expectation);
    if (
      !isRfc3339MsZ(receiptTime) ||
      !Number.isSafeInteger(heartbeatSequence) ||
      heartbeatSequence < 0 ||
      receiptTime < expectation.startedAt ||
      receiptTime > expectation.observeUntil
    ) {
      return { kind: "failed" };
    }
    const observation = parseCanaryObservation(body);
    if (!observationMatches(expectation, observation)) {
      return { kind: "failed" };
    }
    if (observation.status === "pending") {
      return observation.completedAt === null
        ? { kind: "pending" }
        : { kind: "failed" };
    }
    const completedAt = observation.completedAt;
    if (
      completedAt === null ||
      !isRfc3339MsZ(completedAt) ||
      completedAt < expectation.startedAt ||
      completedAt > expectation.observeUntil ||
      completedAt > receiptTime
    ) {
      return { kind: "failed" };
    }
    if (observation.status !== "success") {
      return { kind: "failed" };
    }
    return {
      kind: "passed",
      evidence: {
        ...expectation,
        completedAt,
        observedAt: receiptTime,
        heartbeatSequence,
      },
    };
  } catch {
    return { kind: "failed" };
  }
}

export function assertCanaryEvidence(value: CanaryEvidence): void {
  assertCanaryExpectation(value);
  if (
    !isRfc3339MsZ(value.completedAt) ||
    !isRfc3339MsZ(value.observedAt) ||
    value.completedAt < value.startedAt ||
    value.completedAt > value.observeUntil ||
    value.completedAt > value.observedAt ||
    value.observedAt > value.observeUntil ||
    !Number.isSafeInteger(value.heartbeatSequence) ||
    value.heartbeatSequence < 0
  ) {
    throw new Error("canary evidence is invalid");
  }
}

export function encodeCanaryEvidence(value: CanaryEvidence): string {
  assertExactKeys(
    value as unknown as Readonly<Record<string, unknown>>,
    EVIDENCE_FIELDS,
  );
  assertCanaryEvidence(value);
  return JSON.stringify(value);
}

export function decodeCanaryEvidence(text: string): CanaryEvidence {
  const parsed = parseObject(text);
  assertExactKeys(parsed, EVIDENCE_FIELDS);
  const evidence = parsed as CanaryEvidence;
  assertCanaryEvidence(evidence);
  if (JSON.stringify(evidence) !== text) {
    throw new Error("canary evidence is not canonical");
  }
  return evidence;
}

function parseCanaryObservation(body: string): CanaryObservation {
  const parsed = parseObject(body);
  assertExactKeys(parsed, [
    "schemaVersion",
    "status",
    "repositoryAlias",
    "workflow",
    "revision",
    "scaleSet",
    "environment",
    "completedAt",
  ]);
  if (
    parsed.schemaVersion !== 1 ||
    (parsed.status !== "pending" &&
      parsed.status !== "success" &&
      parsed.status !== "failure" &&
      parsed.status !== "cancelled") ||
    typeof parsed.repositoryAlias !== "string" ||
    typeof parsed.workflow !== "string" ||
    typeof parsed.revision !== "string" ||
    typeof parsed.scaleSet !== "string" ||
    parsed.environment !== "self-hosted" ||
    (parsed.completedAt !== null && typeof parsed.completedAt !== "string")
  ) {
    throw new Error("canary observation is invalid");
  }
  return parsed as CanaryObservation;
}

function observationMatches(
  expectation: CanaryExpectation,
  observation: CanaryObservation,
): boolean {
  return (
    observation.repositoryAlias === expectation.repositoryAlias &&
    observation.workflow === expectation.workflow &&
    observation.revision === expectation.revision &&
    observation.scaleSet === expectation.scaleSet &&
    observation.environment === expectation.environment
  );
}

function assertCanaryExpectation(value: CanaryExpectation): void {
  if (
    value.schemaVersion !== 1 ||
    typeof value.repositoryAlias !== "string" ||
    !ALIAS.test(value.repositoryAlias) ||
    typeof value.workflow !== "string" ||
    !WORKFLOW.test(value.workflow) ||
    typeof value.revision !== "string" ||
    !IDENTIFIER.test(value.revision) ||
    typeof value.scaleSet !== "string" ||
    !IDENTIFIER.test(value.scaleSet) ||
    value.environment !== "self-hosted" ||
    !isRfc3339MsZ(value.startedAt) ||
    !isRfc3339MsZ(value.observeUntil) ||
    value.startedAt >= value.observeUntil ||
    typeof value.sessionId !== "string" ||
    !HEX64.test(value.sessionId) ||
    !Number.isSafeInteger(value.leaseGeneration) ||
    value.leaseGeneration < 1
  ) {
    throw new Error("canary expectation is invalid");
  }
}

function parseObject(text: string): Record<string, unknown> {
  if (text.length === 0 || text.length > 16_384) {
    throw new Error("canary document is invalid");
  }
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("canary document is invalid");
  }
  return parsed as Record<string, unknown>;
}

function assertExactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): void {
  const actual = Object.keys(value);
  if (
    actual.length !== expected.length ||
    !actual.every((key, index) => key === expected[index])
  ) {
    throw new Error("canary document fields are invalid");
  }
}
