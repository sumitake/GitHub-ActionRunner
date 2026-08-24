import { isRfc3339MsZ } from "../protocol/auth";
import type { RepositoryRecord } from "../state/memory";

const SELECTOR = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ROUTES = new Set(["hosted", "self-hosted", "legacy"]);

export function isSelectorScalar(value: unknown): value is string {
  return typeof value === "string" && SELECTOR.test(value);
}

export function selectorRestrictionReason(
  repository: Readonly<RepositoryRecord>,
  receiptTime: string,
  maxAgeMs: number,
): string | null {
  if (
    !Number.isSafeInteger(maxAgeMs) ||
    maxAgeMs <= 0 ||
    !isRfc3339MsZ(receiptTime) ||
    !ROUTES.has(repository.expectedRoute) ||
    repository.confirmedRoute !== repository.expectedRoute ||
    !isSelectorScalar(repository.expectedScaleSet) ||
    repository.confirmedScaleSet !== repository.expectedScaleSet ||
    !isSelectorScalar(repository.expectedLegacyLabel) ||
    repository.confirmedLegacyLabel !== repository.expectedLegacyLabel ||
    repository.selectorEvidenceAt === null ||
    !isRfc3339MsZ(repository.selectorEvidenceAt)
  ) {
    return "selector-evidence-invalid";
  }
  const age =
    Date.parse(receiptTime) - Date.parse(repository.selectorEvidenceAt);
  if (age < 0 || age >= maxAgeMs) {
    return "selector-evidence-stale";
  }
  return null;
}
