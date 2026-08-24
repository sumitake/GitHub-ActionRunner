import { DurableObject } from "cloudflare:workers";

import {
  parseCronBindings,
  parseWorkerBindings,
  type WorkerEnv,
} from "../bindings";
import { parseAddressStatusBindings } from "../config/address-status-bindings";
import {
  dispatchFleetRequest,
  fleetIdFromBody,
  readBoundedBody,
} from "../gateway";
import {
  assertTimestampWindow,
  MAC_HEADER,
  signCronResponse,
  TIMESTAMP_HEADER,
  verifyCronRequest,
} from "../protocol/auth";
import {
  ADDRESS_STATUS_PATH,
  ADDRESS_STATUS_PROTOCOL_VERSION,
  signAddressStatusResponse,
  verifyAddressStatusRequest,
} from "../protocol/address-status";
import { canonicalize } from "../protocol/canonical";
import {
  ADDRESS_ONLY_AUTHORITY_DISABLED,
  CRON_PATH,
  deadlineForTick,
  inventoryDigest,
  parseCronAddressRequest,
} from "../protocol/cron";
import { persistCronAddressReceipt } from "./cron-receipt";
import { readAddressStatus } from "./address-status";
import { loadFleetStore, saveFleetStore, type FleetSql } from "./persist";
import {
  FLEET_SCHEMA_SQL,
  FLEET_STATE_COLUMN_MIGRATIONS,
  REPOSITORY_COLUMN_MIGRATIONS,
} from "./schema";

type SqlStorage = {
  exec(
    query: string,
    ...binds: unknown[]
  ): { toArray?: () => Record<string, unknown>[] };
};

type DurableStorage = {
  sql: SqlStorage;
  transactionSync(closure: () => void): void;
};

type DurableContext = {
  storage: DurableStorage;
  id?: { name?: string };
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
};

function schemaColumns(
  storage: DurableStorage,
  table: "fleet_state" | "repositories",
): string[] {
  const cursor = storage.sql.exec(`PRAGMA table_info(${table})`);
  if (cursor === undefined || typeof cursor.toArray !== "function") {
    throw new Error("fleet schema inspection is unavailable");
  }
  const names = cursor.toArray().map((row) => row.name);
  if (!names.every((name) => typeof name === "string" && name !== "")) {
    throw new Error("fleet schema inspection is invalid");
  }
  return names as string[];
}

export function initializeFleetSchema(storage: DurableStorage): void {
  if (typeof storage.transactionSync !== "function") {
    throw new Error("durable storage transaction is unavailable");
  }
  storage.transactionSync(() => {
    storage.sql.exec(FLEET_SCHEMA_SQL);
    const before = schemaColumns(storage, "fleet_state");
    for (const migration of FLEET_STATE_COLUMN_MIGRATIONS) {
      if (!before.includes(migration.name)) {
        storage.sql.exec(migration.sql);
      }
    }
    const after = schemaColumns(storage, "fleet_state");
    for (const migration of FLEET_STATE_COLUMN_MIGRATIONS) {
      if (after.filter((column) => column === migration.name).length !== 1) {
        throw new Error("fleet schema migration verification failed");
      }
    }
    const repositoryBefore = schemaColumns(storage, "repositories");
    for (const migration of REPOSITORY_COLUMN_MIGRATIONS) {
      if (!repositoryBefore.includes(migration.name)) {
        storage.sql.exec(migration.sql);
      }
    }
    const repositoryAfter = schemaColumns(storage, "repositories");
    for (const migration of REPOSITORY_COLUMN_MIGRATIONS) {
      if (
        repositoryAfter.filter((column) => column === migration.name).length !==
        1
      ) {
        throw new Error("repository schema migration verification failed");
      }
    }
  });
}

function rejected(): Response {
  return Response.json({ error: "rejected" }, { status: 401 });
}

function fleetSql(storage: DurableStorage): FleetSql {
  return {
    run(query: string, ...binds: unknown[]) {
      storage.sql.exec(query, ...binds);
    },
    all(query: string, ...binds: unknown[]) {
      const cursor = storage.sql.exec(query, ...binds);
      if (cursor !== undefined && typeof cursor.toArray === "function") {
        return cursor.toArray();
      }
      return [];
    },
    transaction(work: () => void) {
      if (typeof storage.transactionSync !== "function") {
        throw new Error("durable storage transaction is unavailable");
      }
      storage.transactionSync(work);
    },
  };
}

// FleetDurableObject is the sole per-fleet SQLite authority. Alarms are not a
// second scheduler and are never installed here. Incoming fetches are queued
// because awaiting HMAC verification opens the isolate input gate.
export class FleetDurableObject extends DurableObject<WorkerEnv> {
  private readonly sql: FleetSql;
  private readonly workerEnv: WorkerEnv;
  private readonly objectName: string | undefined;
  private readonly now: () => string;
  private tail: Promise<void> = Promise.resolve();

  constructor(
    ctx: DurableContext,
    env: WorkerEnv = {},
    now: () => string = () => new Date().toISOString(),
  ) {
    super(ctx as unknown as DurableObjectState, env);
    void ctx.blockConcurrencyWhile(async () => {
      initializeFleetSchema(ctx.storage);
    });
    this.sql = fleetSql(ctx.storage);
    this.workerEnv = env;
    this.objectName = ctx.id?.name;
    this.now = now;
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
    const url = new URL(request.url);
    if (url.pathname === ADDRESS_STATUS_PATH) {
      try {
        return await this.handleAddressStatus(request, url);
      } catch {
        return rejected();
      }
    }
    if (url.pathname === CRON_PATH) {
      try {
        return await this.handleCron(request, url);
      } catch {
        return rejected();
      }
    }
    if (ADDRESS_ONLY_AUTHORITY_DISABLED) {
      return rejected();
    }
    const bindings = parseWorkerBindings(this.workerEnv);
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

  private async handleAddressStatus(
    request: Request,
    url: URL,
  ): Promise<Response> {
    const serializerHeadTime = this.now();
    const bindings = parseAddressStatusBindings(this.workerEnv);
    if (
      bindings === null ||
      request.method !== "POST" ||
      url.search !== "" ||
      this.objectName === undefined ||
      !bindings.inventoriedFleetIds.includes(this.objectName)
    ) {
      throw new Error("address-status request is rejected");
    }
    const environmentDigest = await inventoryDigest(
      bindings.inventoryRevision,
      bindings.inventoriedFleetIds,
    );
    if (environmentDigest !== bindings.inventoryDigest) {
      throw new Error("address-status inventory is rejected");
    }
    const timestamp = request.headers.get(TIMESTAMP_HEADER) ?? "";
    const mac = request.headers.get(MAC_HEADER) ?? "";
    const body = await readBoundedBody(request);
    if (body === null) {
      throw new Error("address-status body is rejected");
    }
    const value = await verifyAddressStatusRequest({
      key: bindings.cronHmacKey,
      body,
      headerTimestamp: timestamp,
      macHex: mac,
      observedAt: serializerHeadTime,
      timestampWindowMs: bindings.timestampWindowMs,
      expected: {
        fleetId: this.objectName,
        inventoryRevision: bindings.inventoryRevision,
        inventoryDigest: bindings.inventoryDigest,
      },
    });
    const responseTime = this.now();
    assertTimestampWindow(
      responseTime,
      value.requestTime,
      bindings.timestampWindowMs,
    );
    const snapshot = readAddressStatus(this.sql, {
      fleetId: value.fleetId,
      inventoryRevision: value.inventoryRevision,
      inventoryDigest: value.inventoryDigest,
      nonce: value.nonce,
      requestTime: value.requestTime,
      responseTime,
      nonceTtlMs: bindings.nonceTtlMs,
    });
    const responseBody = canonicalize({
      protocolVersion: ADDRESS_STATUS_PROTOCOL_VERSION,
      status: "inert-receipt",
      fleetId: value.fleetId,
      nonce: value.nonce,
      requestTime: value.requestTime,
      responseTime,
      inventoryRevision: value.inventoryRevision,
      inventoryDigest: value.inventoryDigest,
      ...snapshot,
    });
    const responseMac = await signAddressStatusResponse(
      bindings.cronHmacKey,
      responseTime,
      responseBody,
    );
    return new Response(responseBody, {
      status: 200,
      headers: {
        "content-type": "application/json",
        [TIMESTAMP_HEADER]: responseTime,
        [MAC_HEADER]: responseMac,
      },
    });
  }

  private async handleCron(request: Request, url: URL): Promise<Response> {
    const serializerHeadTime = this.now();
    const bindings = parseCronBindings(this.workerEnv);
    if (
      bindings === null ||
      request.method !== "POST" ||
      url.search !== "" ||
      this.objectName === undefined
    ) {
      throw new Error("Cron address request is rejected");
    }
    const timestamp = request.headers.get(TIMESTAMP_HEADER) ?? "";
    const mac = request.headers.get(MAC_HEADER) ?? "";
    const body = await request.text();
    const value = parseCronAddressRequest(body);
    if (
      timestamp !== value.tickTimestamp ||
      value.fleetId !== this.objectName ||
      value.revision !== bindings.inventoryRevision ||
      value.inventoryDigest !== bindings.inventoryDigest ||
      !sameFleetIds(value.fleetIds, bindings.inventoriedFleetIds) ||
      value.deadline !==
        deadlineForTick(value.tickTimestamp, bindings.perFleetDeadlineMs) ||
      serializerHeadTime > value.deadline
    ) {
      throw new Error("Cron address identity is rejected");
    }
    assertTimestampWindow(
      serializerHeadTime,
      value.tickTimestamp,
      bindings.timestampWindowMs,
    );
    await verifyCronRequest(
      bindings.cronHmacKey,
      "POST",
      CRON_PATH,
      timestamp,
      body,
      mac,
    );
    const requestDigest = await inventoryDigest(value.revision, value.fleetIds);
    const environmentDigest = await inventoryDigest(
      bindings.inventoryRevision,
      bindings.inventoriedFleetIds,
    );
    if (
      requestDigest !== value.inventoryDigest ||
      environmentDigest !== bindings.inventoryDigest
    ) {
      throw new Error("Cron inventory digest is rejected");
    }

    const receiptTime = this.now();
    if (receiptTime < value.tickTimestamp || receiptTime > value.deadline) {
      throw new Error("Cron address deadline elapsed");
    }
    const saved = persistCronAddressReceipt(this.sql, {
      fleetId: value.fleetId,
      inventoryRevision: value.revision,
      inventoryDigest: value.inventoryDigest,
      tickTimestamp: value.tickTimestamp,
      tickNonce: value.nonce,
      addressedAt: receiptTime,
      nonceExpiresAt: deadlineForTick(receiptTime, bindings.nonceTtlMs),
    });
    const responseBody = canonicalize({
      protocolVersion: value.protocolVersion,
      fleetId: value.fleetId,
      revision: value.revision,
      inventoryDigest: value.inventoryDigest,
      nonce: value.nonce,
      tickTimestamp: value.tickTimestamp,
      deadline: value.deadline,
      receiptTime,
      persistenceGeneration: saved.persistenceGeneration,
    });
    const responseMac = await signCronResponse(
      bindings.cronHmacKey,
      "POST",
      CRON_PATH,
      receiptTime,
      responseBody,
    );
    return new Response(responseBody, {
      status: 200,
      headers: {
        "content-type": "application/json",
        [TIMESTAMP_HEADER]: receiptTime,
        [MAC_HEADER]: responseMac,
      },
    });
  }
}

function sameFleetIds(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((fleetId, index) => fleetId === right[index])
  );
}
