import type { DueWorkRecord, MemoryFleetStore } from "../state/memory";

export type FleetInventory = {
  revision: string;
  digest: string;
  fleetIds: string[];
};

export class CronError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CronError";
  }
}

export function validateFleetInventory(
  inventory: FleetInventory,
  maxFleets: number,
): string[] {
  if (maxFleets <= 0) {
    throw new CronError("fleet inventory bound is unset");
  }
  if (
    inventory.fleetIds.length === 0 ||
    inventory.fleetIds.length > maxFleets
  ) {
    throw new CronError("fleet inventory size is invalid");
  }
  const seen = new Set<string>();
  for (const fleetId of inventory.fleetIds) {
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(fleetId) || seen.has(fleetId)) {
      throw new CronError("fleet inventory is not canonical");
    }
    seen.add(fleetId);
  }
  return inventory.fleetIds;
}

export async function runCronTick(
  inventory: FleetInventory,
  maxFleets: number,
  stores: Map<string, MemoryFleetStore>,
  perFleetDeadlineMs: number,
  claimTtlMs: number,
  now: () => string,
  execute: (
    store: MemoryFleetStore,
    batch: DueWorkRecord[],
    signal: AbortSignal,
  ) => Promise<void>,
): Promise<{ addressed: string[]; failed: string[] }> {
  const fleetIds = validateFleetInventory(inventory, maxFleets);
  if (!Number.isInteger(claimTtlMs) || claimTtlMs <= 0) {
    throw new CronError("claim ttl is unset");
  }
  const addressed: string[] = [];
  const failed: string[] = [];
  for (const fleetId of fleetIds) {
    const store = stores.get(fleetId);
    if (store === undefined) {
      failed.push(fleetId);
      continue;
    }
    store.fleet.inventoried = true;
    const abort = new AbortController();
    let batch: DueWorkRecord[] = [];
    const work = (async () => {
      batch = store.claimReady(now(), 8, claimTtlMs);
      await execute(store, batch, abort.signal);
    })();
    try {
      await withDeadline(work, perFleetDeadlineMs);
      addressed.push(fleetId);
    } catch {
      abort.abort();
      const joined = await joinWork(work, perFleetDeadlineMs);
      if (!joined) {
        pinClaims(batch);
      }
      failed.push(fleetId);
    }
  }
  return { addressed, failed };
}

async function joinWork(
  work: Promise<unknown>,
  deadlineMs: number,
): Promise<boolean> {
  const settled = work.then(
    () => true,
    () => true,
  );
  try {
    await withDeadline(settled, deadlineMs);
    return true;
  } catch {
    return false;
  }
}

function pinClaims(batch: DueWorkRecord[]): void {
  for (const row of batch) {
    if (row.status === "claimed") {
      row.claimExpiresAt = "9999-12-31T23:59:59.000Z";
    }
  }
}

async function withDeadline<T>(
  work: Promise<T>,
  deadlineMs: number,
): Promise<T> {
  if (!Number.isFinite(deadlineMs) || deadlineMs <= 0) {
    throw new CronError("per-fleet deadline is unset");
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new CronError("per-fleet deadline exceeded"));
    }, deadlineMs);
  });
  try {
    return await Promise.race([work, timeout]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    void work.catch(() => undefined);
  }
}

export function assertNoDurableObjectAlarms(source: string): void {
  if (
    source.includes("setAlarm") ||
    source.includes("storage.alarms") ||
    source.includes("ctx.storage.getAlarm")
  ) {
    throw new CronError("durable object alarms are forbidden");
  }
}
