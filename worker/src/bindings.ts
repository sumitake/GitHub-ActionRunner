import type { GatewaySecrets } from "./gateway";
import { constantTimeEqualHex, hexToBytes } from "./protocol/auth";
import { isCanonicalInventoryRevision } from "./protocol/cron";
import { FLEET_ID, HEX64, MAX_LEASE_DURATION_MS } from "./protocol/messages";

export type FleetNamespace = {
  getByName(name: string): { fetch(request: Request): Promise<Response> };
};

export type WorkerEnv = Record<string, unknown>;

export type ParsedWorkerBindings = {
  inventoriedFleetIds: string[];
  secrets: GatewaySecrets;
};

export type ParsedCronBindings = {
  inventoriedFleetIds: string[];
  cronHmacKey: Uint8Array;
  timestampWindowMs: number;
  nonceTtlMs: number;
  inventoryRevision: string;
  inventoryDigest: string;
  maxFleets: number;
  perFleetDeadlineMs: number;
  cronBudgetOverheadMs: number;
  cronTickBudgetMs: number;
};

function requiredPositiveInt(env: WorkerEnv, name: string): number | null {
  const raw = env[name];
  if (typeof raw !== "string" || raw === "") {
    return null;
  }
  if (!/^[1-9][0-9]*$/.test(raw)) {
    return null;
  }
  const value = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(value) || value <= 0) {
    return null;
  }
  return value;
}

function parseFleetIds(raw: unknown): string[] | null {
  if (typeof raw !== "string" || raw === "") {
    return null;
  }
  const fleetIds = raw.split(",").map((item) => item.trim());
  if (fleetIds.length === 0) {
    return null;
  }
  const seen = new Set<string>();
  for (const fleetId of fleetIds) {
    if (!FLEET_ID.test(fleetId) || seen.has(fleetId)) {
      return null;
    }
    seen.add(fleetId);
  }
  return fleetIds;
}

export function parseWorkerBindings(
  env: WorkerEnv,
): ParsedWorkerBindings | null {
  const fleetIds = parseFleetIds(env.FLEET_IDS);
  const timestampWindowMs = requiredPositiveInt(env, "TIMESTAMP_WINDOW_MS");
  const nonceTtlMs = requiredPositiveInt(env, "NONCE_TTL_MS");
  const leaseDurationMs = requiredPositiveInt(env, "LEASE_DURATION_MS");
  const archiveEvidenceMaxAgeMs = requiredPositiveInt(
    env,
    "ARCHIVE_EVIDENCE_MAX_AGE_MS",
  );
  const selectorEvidenceMaxAgeMs = requiredPositiveInt(
    env,
    "SELECTOR_EVIDENCE_MAX_AGE_MS",
  );
  const hostedTransitionSafetyMarginMs = requiredPositiveInt(
    env,
    "HOSTED_TRANSITION_SAFETY_MARGIN_MS",
  );
  if (
    fleetIds === null ||
    timestampWindowMs === null ||
    nonceTtlMs === null ||
    leaseDurationMs === null ||
    leaseDurationMs > MAX_LEASE_DURATION_MS ||
    archiveEvidenceMaxAgeMs === null ||
    selectorEvidenceMaxAgeMs === null ||
    hostedTransitionSafetyMarginMs === null
  ) {
    return null;
  }
  let hmacKey: Uint8Array;
  try {
    hmacKey = hexToBytes(typeof env.HMAC_KEY === "string" ? env.HMAC_KEY : "");
  } catch {
    return null;
  }
  if (hmacKey.byteLength < 32) {
    return null;
  }
  return {
    inventoriedFleetIds: fleetIds,
    secrets: {
      hmacKey,
      timestampWindowMs,
      nonceTtlMs,
      leaseDurationMs,
      archiveEvidenceMaxAgeMs,
      selectorEvidenceMaxAgeMs,
      hostedTransitionSafetyMarginMs,
    },
  };
}

export function parseCronBindings(env: WorkerEnv): ParsedCronBindings | null {
  const fleetIds = parseFleetIds(env.FLEET_IDS);
  const timestampWindowMs = requiredPositiveInt(env, "TIMESTAMP_WINDOW_MS");
  const nonceTtlMs = requiredPositiveInt(env, "NONCE_TTL_MS");
  const maxFleets = requiredPositiveInt(env, "MAX_FLEETS");
  const perFleetDeadlineMs = requiredPositiveInt(env, "PER_FLEET_DEADLINE_MS");
  const cronBudgetOverheadMs = requiredPositiveInt(
    env,
    "CRON_BUDGET_OVERHEAD_MS",
  );
  const cronTickBudgetMs = requiredPositiveInt(env, "CRON_TICK_BUDGET_MS");
  const inventoryRevision = env.FLEET_INVENTORY_REVISION;
  const inventoryDigest = env.FLEET_INVENTORY_DIGEST;
  const hmacKeyHex = env.HMAC_KEY;
  const cronHmacKeyHex = env.CRON_HMAC_KEY;
  let hmacKey: Uint8Array;
  let cronHmacKey: Uint8Array;
  try {
    hmacKey = hexToBytes(typeof hmacKeyHex === "string" ? hmacKeyHex : "");
    cronHmacKey = hexToBytes(
      typeof cronHmacKeyHex === "string" ? cronHmacKeyHex : "",
    );
  } catch {
    return null;
  }
  if (
    fleetIds === null ||
    timestampWindowMs === null ||
    nonceTtlMs === null ||
    maxFleets === null ||
    perFleetDeadlineMs === null ||
    cronBudgetOverheadMs === null ||
    cronTickBudgetMs === null ||
    typeof inventoryRevision !== "string" ||
    !isCanonicalInventoryRevision(inventoryRevision) ||
    typeof inventoryDigest !== "string" ||
    !HEX64.test(inventoryDigest) ||
    typeof hmacKeyHex !== "string" ||
    typeof cronHmacKeyHex !== "string" ||
    hmacKey.byteLength < 32 ||
    cronHmacKey.byteLength < 32 ||
    constantTimeEqualHex(cronHmacKeyHex, hmacKeyHex) ||
    cronTickBudgetMs > 900_000 ||
    fleetIds.length > maxFleets
  ) {
    return null;
  }
  for (let index = 1; index < fleetIds.length; index += 1) {
    if (fleetIds[index]! <= fleetIds[index - 1]!) {
      return null;
    }
  }
  const requiredBudget =
    BigInt(maxFleets) * BigInt(perFleetDeadlineMs) +
    BigInt(cronBudgetOverheadMs);
  if (requiredBudget > BigInt(cronTickBudgetMs)) {
    return null;
  }
  return {
    inventoriedFleetIds: fleetIds,
    cronHmacKey,
    timestampWindowMs,
    nonceTtlMs,
    inventoryRevision,
    inventoryDigest,
    maxFleets,
    perFleetDeadlineMs,
    cronBudgetOverheadMs,
    cronTickBudgetMs,
  };
}
