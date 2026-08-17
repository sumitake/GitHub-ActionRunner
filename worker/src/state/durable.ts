import { parseWorkerBindings, type WorkerEnv } from "../bindings";
import { dispatchFleetRequest } from "../gateway";
import { parseCanonical } from "../protocol/canonical";
import { FLEET_ID } from "../protocol/messages";
import { loadFleetStore, saveFleetStore, type FleetSql } from "./persist";
import { FLEET_SCHEMA_SQL } from "./schema";

type SqlStorage = {
  exec(
    query: string,
    ...binds: unknown[]
  ): { toArray?: () => Record<string, unknown>[] };
};

type DurableStorage = {
  sql: SqlStorage;
};

type DurableContext = {
  storage: DurableStorage;
  id?: { name?: string };
};

function rejected(): Response {
  return Response.json({ error: "rejected" }, { status: 401 });
}

function fleetSql(sql: SqlStorage): FleetSql {
  return {
    run(query: string, ...binds: unknown[]) {
      sql.exec(query, ...binds);
    },
    all(query: string, ...binds: unknown[]) {
      const cursor = sql.exec(query, ...binds);
      if (cursor !== undefined && typeof cursor.toArray === "function") {
        return cursor.toArray();
      }
      return [];
    },
  };
}

function fleetIdFromBody(body: string): string | null {
  try {
    const value = parseCanonical(body);
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return null;
    }
    const fleetId = (value as { fleetId?: unknown }).fleetId;
    if (typeof fleetId !== "string" || !FLEET_ID.test(fleetId)) {
      return null;
    }
    return fleetId;
  } catch {
    return null;
  }
}

// FleetDurableObject is the sole per-fleet SQLite authority. Alarms are not a
// second scheduler and are never installed here.
export class FleetDurableObject {
  private readonly sql: FleetSql;
  private readonly env: WorkerEnv;
  private readonly objectName: string | undefined;

  constructor(ctx: DurableContext, env: WorkerEnv = {}) {
    ctx.storage.sql.exec(FLEET_SCHEMA_SQL);
    this.sql = fleetSql(ctx.storage.sql);
    this.env = env;
    this.objectName = ctx.id?.name;
  }

  async fetch(request: Request): Promise<Response> {
    const bindings = parseWorkerBindings(this.env);
    if (bindings === null) {
      return rejected();
    }
    const copy = request.clone();
    const fleetId = this.objectName ?? fleetIdFromBody(await copy.text());
    if (fleetId === null) {
      return rejected();
    }
    const store = loadFleetStore(this.sql, fleetId, {
      now: () => new Date().toISOString(),
    });
    const response = await dispatchFleetRequest(request, {
      inventoriedFleetIds: bindings.inventoriedFleetIds,
      secrets: bindings.secrets,
      storeFor: (id) => (id === store.fleet.fleetId ? store : undefined),
    });
    saveFleetStore(this.sql, store);
    return response;
  }
}
