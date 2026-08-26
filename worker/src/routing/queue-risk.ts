import { canonicalize, parseCanonical } from "../protocol/canonical";
import { HEX64 } from "../protocol/messages";

export const QUEUE_RISK_REASON = "pre-transition-queue-may-remain" as const;

const SHA40 = /^[0-9a-f]{40}$/;
const QUEUE_RISK_FIELDS = [
  "transitionEpoch",
  "sourceHead",
  "evidenceDigest",
  "reason",
] as const;

export type QueueRiskRecord = {
  transitionEpoch: number;
  sourceHead: string;
  evidenceDigest: string;
  reason: typeof QUEUE_RISK_REASON;
};

export function assertQueueRiskRecord(value: QueueRiskRecord): void {
  assertExactKeys(
    value as unknown as Readonly<Record<string, unknown>>,
    QUEUE_RISK_FIELDS,
  );
  if (
    !Number.isSafeInteger(value.transitionEpoch) ||
    value.transitionEpoch < 1 ||
    (value.sourceHead !== "unknown" && !SHA40.test(value.sourceHead)) ||
    !HEX64.test(value.evidenceDigest) ||
    value.reason !== QUEUE_RISK_REASON
  ) {
    throw new Error("queue risk is invalid");
  }
}

export function encodeQueueRiskRecord(value: QueueRiskRecord): string {
  assertQueueRiskRecord(value);
  return canonicalize(value);
}

export function decodeQueueRiskRecord(text: string): QueueRiskRecord {
  const parsed = parseCanonical(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("queue risk is invalid");
  }
  const value = parsed as QueueRiskRecord;
  assertQueueRiskRecord(value);
  return value;
}

function assertExactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    !actual.every((key, index) => key === wanted[index])
  ) {
    throw new Error("queue risk is invalid");
  }
}
