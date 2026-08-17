import type { GatewaySecrets } from "./gateway";
import { hexToBytes } from "./protocol/auth";
import { FLEET_ID } from "./protocol/messages";

export type FleetNamespace = {
  getByName(name: string): { fetch(request: Request): Promise<Response> };
};

export type WorkerEnv = Record<string, unknown>;

export type ParsedWorkerBindings = {
  inventoriedFleetIds: string[];
  secrets: GatewaySecrets;
};

export type ParsedCronBindings = ParsedWorkerBindings & {
  inventoryRevision: string;
  inventoryDigest: string;
  maxFleets: number;
  claimTtlMs: number;
  perFleetDeadlineMs: number;
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
  if (!Number.isInteger(value) || value <= 0) {
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
  const base = parseWorkerBindings(env);
  const maxFleets = requiredPositiveInt(env, "MAX_FLEETS");
  const claimTtlMs = requiredPositiveInt(env, "CLAIM_TTL_MS");
  const perFleetDeadlineMs = requiredPositiveInt(env, "PER_FLEET_DEADLINE_MS");
  const inventoryRevision = env.FLEET_INVENTORY_REVISION;
  const inventoryDigest = env.FLEET_INVENTORY_DIGEST;
  if (
    base === null ||
    maxFleets === null ||
    claimTtlMs === null ||
    perFleetDeadlineMs === null ||
    typeof inventoryRevision !== "string" ||
    inventoryRevision === "" ||
    typeof inventoryDigest !== "string" ||
    inventoryDigest === ""
  ) {
    return null;
  }
  return {
    ...base,
    inventoryRevision,
    inventoryDigest,
    maxFleets,
    claimTtlMs,
    perFleetDeadlineMs,
  };
}
