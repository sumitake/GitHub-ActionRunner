import { constantTimeEqualHex, hexToBytes } from "../protocol/auth";
import {
  isCanonicalInventoryRevision,
  requireCanonicalFleetIds,
} from "../protocol/cron";
import { HEX64 } from "../protocol/messages";

export type AddressStatusEnv = Record<string, unknown>;

export type ParsedAddressStatusBindings = {
  inventoriedFleetIds: string[];
  cronHmacKey: Uint8Array;
  timestampWindowMs: number;
  nonceTtlMs: number;
  inventoryRevision: string;
  inventoryDigest: string;
};

export function parseAddressStatusBindings(
  env: AddressStatusEnv,
): ParsedAddressStatusBindings | null {
  const inventoriedFleetIds = parseFleetIds(env.FLEET_IDS);
  const timestampWindowMs = requiredPositiveInt(env.TIMESTAMP_WINDOW_MS);
  const nonceTtlMs = requiredPositiveInt(env.NONCE_TTL_MS);
  const inventoryRevision = env.FLEET_INVENTORY_REVISION;
  const inventoryDigest = env.FLEET_INVENTORY_DIGEST;
  const ordinaryKeyHex = env.HMAC_KEY;
  const cronKeyHex = env.CRON_HMAC_KEY;
  if (
    inventoriedFleetIds === null ||
    timestampWindowMs === null ||
    nonceTtlMs === null ||
    typeof inventoryRevision !== "string" ||
    !isCanonicalInventoryRevision(inventoryRevision) ||
    typeof inventoryDigest !== "string" ||
    !HEX64.test(inventoryDigest) ||
    typeof ordinaryKeyHex !== "string" ||
    typeof cronKeyHex !== "string"
  ) {
    return null;
  }
  let ordinaryKey: Uint8Array;
  let cronHmacKey: Uint8Array;
  try {
    ordinaryKey = hexToBytes(ordinaryKeyHex);
    cronHmacKey = hexToBytes(cronKeyHex);
  } catch {
    return null;
  }
  if (
    ordinaryKey.byteLength < 32 ||
    cronHmacKey.byteLength < 32 ||
    constantTimeEqualHex(ordinaryKeyHex, cronKeyHex)
  ) {
    return null;
  }
  return {
    inventoriedFleetIds,
    cronHmacKey,
    timestampWindowMs,
    nonceTtlMs,
    inventoryRevision,
    inventoryDigest,
  };
}

function parseFleetIds(value: unknown): string[] | null {
  if (typeof value !== "string" || value === "") {
    return null;
  }
  try {
    return requireCanonicalFleetIds(
      value.split(",").map((fleetId) => fleetId.trim()),
    );
  } catch {
    return null;
  }
}

function requiredPositiveInt(value: unknown): number | null {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) {
    return null;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}
