import { parseWorkerBindings, type WorkerEnv } from "./bindings";
import { dispatchFleetRequest } from "./gateway";
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

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    return handleWorkerFetch(request, env);
  },
  async scheduled(): Promise<void> {
    return;
  },
};
