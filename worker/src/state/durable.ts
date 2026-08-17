import { parseWorkerBindings, type WorkerEnv } from "../bindings";
import { dispatchFleetRequest, fleetIdFromBody } from "../gateway";
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

// FleetDurableObject is the sole per-fleet SQLite authority. Alarms are not a
// second scheduler and are never installed here. Incoming fetches are queued
// because awaiting HMAC verification opens the isolate input gate.
export class FleetDurableObject {
  private readonly sql: FleetSql;
  private readonly env: WorkerEnv;
  private readonly objectName: string | undefined;
  private tail: Promise<void> = Promise.resolve();

  constructor(ctx: DurableContext, env: WorkerEnv = {}) {
    ctx.storage.sql.exec(FLEET_SCHEMA_SQL);
    this.sql = fleetSql(ctx.storage.sql);
    this.env = env;
    this.objectName = ctx.id?.name;
  }

  fetch(request: Request): Promise<Response> {
    const result = this.tail.then(() => this.handle(request));
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async handle(request: Request): Promise<Response> {
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
