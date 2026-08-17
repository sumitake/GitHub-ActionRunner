import {
  parseCronBindings,
  parseWorkerBindings,
  type WorkerEnv,
} from "./bindings";
import { dispatchFleetRequest } from "./gateway";
import { runCronTick } from "./scheduler/cron";
import type { DueWorkRecord } from "./state/memory";
import {
  ADMIN_COMMAND_PATH,
  ADMIN_STATUS_PATH,
  HEARTBEAT_PATH,
  SESSION_PATH,
} from "./protocol/auth";
import { MemoryFleetStore } from "./state/memory";

export { FleetDurableObject } from "./state/durable";

const isolateStores = new Map<string, MemoryFleetStore>();

function isolateStoreFor(fleetId: string): MemoryFleetStore {
  const existing = isolateStores.get(fleetId);
  if (existing !== undefined) {
    return existing;
  }
  const store = new MemoryFleetStore(fleetId, {
    now: () => new Date().toISOString(),
  });
  isolateStores.set(fleetId, store);
  return store;
}

function rejected(): Response {
  return Response.json({ error: "rejected" }, { status: 401 });
}

export async function handleWorkerFetch(
  request: Request,
  env: WorkerEnv,
  storeFor?: (fleetId: string) => MemoryFleetStore | undefined,
): Promise<Response> {
  const bindings = parseWorkerBindings(env);
  if (bindings === null) {
    return rejected();
  }
  const url = new URL(request.url);
  if (
    request.method !== "POST" ||
    (url.pathname !== SESSION_PATH &&
      url.pathname !== HEARTBEAT_PATH &&
      url.pathname !== ADMIN_COMMAND_PATH &&
      url.pathname !== ADMIN_STATUS_PATH)
  ) {
    return rejected();
  }
  return dispatchFleetRequest(request, {
    inventoriedFleetIds: bindings.inventoriedFleetIds,
    secrets: bindings.secrets,
    storeFor: storeFor ?? isolateStoreFor,
  });
}

export async function handleWorkerScheduled(
  env: WorkerEnv,
  execute?: (
    store: MemoryFleetStore,
    batch: DueWorkRecord[],
    signal: AbortSignal,
  ) => Promise<void>,
  storeFor: (fleetId: string) => MemoryFleetStore = isolateStoreFor,
  now: () => string = () => new Date().toISOString(),
): Promise<{ addressed: string[]; failed: string[] } | null> {
  const cron = parseCronBindings(env);
  if (cron === null || execute === undefined) {
    return null;
  }
  const stores = new Map<string, MemoryFleetStore>();
  for (const fleetId of cron.inventoriedFleetIds) {
    stores.set(fleetId, storeFor(fleetId));
  }
  return runCronTick(
    {
      revision: cron.inventoryRevision,
      digest: cron.inventoryDigest,
      fleetIds: cron.inventoriedFleetIds,
    },
    cron.maxFleets,
    stores,
    cron.perFleetDeadlineMs,
    cron.claimTtlMs,
    now,
    execute,
  );
}

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    return handleWorkerFetch(request, env);
  },
  async scheduled(_event: unknown, env: WorkerEnv): Promise<void> {
    await handleWorkerScheduled(env);
  },
};
