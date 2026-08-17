import { FLEET_SCHEMA_SQL } from "./schema";

type SqlStorage = {
  exec(query: string): unknown;
};

type DurableStorage = {
  sql: SqlStorage;
};

type DurableContext = {
  storage: DurableStorage;
};

// FleetDurableObject is the sole per-fleet SQLite authority. Alarms are not a
// second scheduler and are never installed here.
export class FleetDurableObject {
  constructor(ctx: DurableContext) {
    ctx.storage.sql.exec(FLEET_SCHEMA_SQL);
  }

  async fetch(): Promise<Response> {
    return Response.json({ error: "rejected" }, { status: 401 });
  }
}
