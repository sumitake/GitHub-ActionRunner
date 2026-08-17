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
  now: () => string,
  execute: (store: MemoryFleetStore, batch: DueWorkRecord[]) => Promise<void>,
): Promise<{ addressed: string[]; failed: string[] }> {
  const fleetIds = validateFleetInventory(inventory, maxFleets);
  const addressed: string[] = [];
  const failed: string[] = [];
  for (const fleetId of fleetIds) {
    const store = stores.get(fleetId);
    if (store === undefined) {
      failed.push(fleetId);
      continue;
    }
    store.fleet.inventoried = true;
    const started = Date.now();
    try {
      const batch = store.claimReady(now(), 8);
      await execute(store, batch);
      if (Date.now() - started > perFleetDeadlineMs) {
        throw new CronError("per-fleet deadline exceeded");
      }
      addressed.push(fleetId);
    } catch {
      failed.push(fleetId);
    }
  }
  return { addressed, failed };
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
