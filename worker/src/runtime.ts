import {
  parseCronBindings,
  parseWorkerBindings,
  type FleetNamespace,
  type ParsedCronBindings,
  type WorkerEnv,
} from "./bindings";
import { parseAddressStatusBindings } from "./config/address-status-bindings";
import {
  dispatchFleetRequest,
  fleetIdFromBody,
  readBoundedBody,
} from "./gateway";
import {
  ADMIN_COMMAND_PATH,
  bytesToHex,
  HEARTBEAT_PATH,
  MAC_HEADER,
  SESSION_PATH,
  signCronRequest,
  TIMESTAMP_HEADER,
  verifyCronResponse,
} from "./protocol/auth";
import { canonicalize } from "./protocol/canonical";
import {
  ADDRESS_STATUS_PATH,
  parseAddressStatusRequest,
  verifyAddressStatusRequest,
} from "./protocol/address-status";
import {
  ADDRESS_ONLY_AUTHORITY_DISABLED,
  CRON_ADDRESS_PROTOCOL_VERSION,
  CRON_PATH,
  deadlineForTick,
  isCanonicalCronTimestamp,
  inventoryDigest,
  parseCronAddressResponse,
  type CronAddressRequestV1,
} from "./protocol/cron";
import { HEX64 } from "./protocol/messages";
import type { MemoryFleetStore } from "./state/memory";
const MAX_CRON_RESPONSE_BYTES = 65_536;

function rejected(): Response {
  return Response.json({ error: "rejected" }, { status: 401 });
}

export async function handleWorkerFetch(
  request: Request,
  env: WorkerEnv,
  storeFor?: (fleetId: string) => MemoryFleetStore | undefined,
): Promise<Response> {
  const url = new URL(request.url);
  if (storeFor === undefined && url.pathname === ADDRESS_STATUS_PATH) {
    return handleWorkerAddressStatusFetch(request, url, env);
  }
  if (storeFor === undefined && ADDRESS_ONLY_AUTHORITY_DISABLED) {
    return rejected();
  }
  const bindings = parseWorkerBindings(env);
  if (bindings === null) {
    return rejected();
  }
  if (
    request.method !== "POST" ||
    (url.pathname !== SESSION_PATH &&
      url.pathname !== HEARTBEAT_PATH &&
      url.pathname !== ADMIN_COMMAND_PATH)
  ) {
    return rejected();
  }
  if (storeFor !== undefined) {
    return dispatchFleetRequest(request, {
      inventoriedFleetIds: bindings.inventoriedFleetIds,
      secrets: bindings.secrets,
      storeFor,
    });
  }
  const fleets = fleetNamespace(env);
  if (fleets === null) {
    return rejected();
  }
  const fleetId = fleetIdFromBody(await request.clone().text());
  if (fleetId === null) {
    return rejected();
  }
  return fleets.getByName(fleetId).fetch(request);
}

async function handleWorkerAddressStatusFetch(
  request: Request,
  url: URL,
  env: WorkerEnv,
): Promise<Response> {
  try {
    const bindings = parseAddressStatusBindings(env);
    if (bindings === null || request.method !== "POST" || url.search !== "") {
      return rejected();
    }
    const fleets = fleetNamespace(env);
    if (fleets === null) {
      return rejected();
    }
    const body = await readBoundedBody(request.clone());
    if (body === null) {
      return rejected();
    }
    const value = parseAddressStatusRequest(body);
    if (
      !bindings.inventoriedFleetIds.includes(value.fleetId) ||
      value.inventoryRevision !== bindings.inventoryRevision ||
      value.inventoryDigest !== bindings.inventoryDigest
    ) {
      return rejected();
    }
    const environmentDigest = await inventoryDigest(
      bindings.inventoryRevision,
      bindings.inventoriedFleetIds,
    );
    if (environmentDigest !== bindings.inventoryDigest) {
      return rejected();
    }
    await verifyAddressStatusRequest({
      key: bindings.cronHmacKey,
      body,
      headerTimestamp: request.headers.get(TIMESTAMP_HEADER) ?? "",
      macHex: request.headers.get(MAC_HEADER) ?? "",
      observedAt: value.requestTime,
      timestampWindowMs: bindings.timestampWindowMs,
      expected: value,
    });
    return fleets.getByName(value.fleetId).fetch(request);
  } catch {
    return rejected();
  }
}

function fleetNamespace(env: WorkerEnv): FleetNamespace | null {
  const fleet = env.FLEET;
  if (fleet === undefined || fleet === null || typeof fleet !== "object") {
    return null;
  }
  const candidate = fleet as { getByName?: unknown };
  if (typeof candidate.getByName !== "function") {
    return null;
  }
  return fleet as FleetNamespace;
}

export async function handleWorkerScheduled(
  controller: Pick<ScheduledController, "noRetry">,
  env: WorkerEnv,
  options: CronAddressOptions = {},
): Promise<CronAddressResult> {
  controller.noRetry();
  const now = options.now ?? (() => new Date().toISOString());
  const makeNonce = options.nonce ?? randomNonce;
  const cron = parseCronBindings(env);
  if (cron === null) {
    emitCronDiagnostic(options, {
      schemaVersion: 1,
      event: "cron-address",
      status: "configuration-rejected",
    });
    throw new CronAddressRunError("Cron bindings are invalid", {
      addressed: [],
      failed: [],
    });
  }
  let scheduledTimestamp: string;
  let tickStart: number;
  try {
    scheduledTimestamp = now();
    tickStart = parseRuntimeTime(scheduledTimestamp);
  } catch {
    emitCronDiagnostic(options, {
      schemaVersion: 1,
      event: "cron-address",
      status: "configuration-rejected",
    });
    throw new CronAddressRunError("Cron clock is invalid", {
      addressed: [],
      failed: [],
    });
  }
  const result: CronAddressResult = { addressed: [], failed: [] };
  const receipts: CronAddressReceiptDiagnostic[] = [];
  try {
    const globalDeadlineMs = tickStart + cron.cronTickBudgetMs;
    if (!Number.isSafeInteger(globalDeadlineMs)) {
      throw new Error("Cron tick budget overflows");
    }
    const computedDigest = await inventoryDigest(
      cron.inventoryRevision,
      cron.inventoriedFleetIds,
    );
    if (computedDigest !== cron.inventoryDigest) {
      throw new Error("Cron inventory digest is invalid");
    }
    if (parseRuntimeTime(now()) >= globalDeadlineMs) {
      throw new Error("Cron setup exceeded its tick budget");
    }
    const fleets = fleetNamespace(env);
    if (fleets === null) {
      throw new Error("fleet namespace is unavailable");
    }
    if (parseRuntimeTime(now()) >= globalDeadlineMs) {
      throw new Error("Cron setup exceeded its tick budget");
    }
    for (const fleetId of cron.inventoriedFleetIds) {
      try {
        const tickTimestamp = now();
        const tickMs = parseRuntimeTime(tickTimestamp);
        const deadline = deadlineForTick(
          tickTimestamp,
          cron.perFleetDeadlineMs,
        );
        const deadlineMs = Date.parse(deadline);
        if (
          tickMs < tickStart ||
          deadlineMs > globalDeadlineMs ||
          globalDeadlineMs - tickMs < cron.perFleetDeadlineMs
        ) {
          throw new Error("Cron tick has insufficient remaining budget");
        }
        const nonce = makeNonce();
        if (!HEX64.test(nonce)) {
          throw new Error("Cron nonce is invalid");
        }
        const value: CronAddressRequestV1 = {
          protocolVersion: CRON_ADDRESS_PROTOCOL_VERSION,
          fleetId,
          fleetIds: [...cron.inventoriedFleetIds],
          revision: cron.inventoryRevision,
          inventoryDigest: cron.inventoryDigest,
          nonce,
          tickTimestamp,
          deadline,
        };
        const body = canonicalize(value);
        const mac = await signCronRequest(
          cron.cronHmacKey,
          "POST",
          CRON_PATH,
          tickTimestamp,
          body,
        );
        const callNowMs = parseRuntimeTime(now());
        const remainingMs = Math.min(
          deadlineMs - callNowMs,
          globalDeadlineMs - callNowMs,
        );
        if (!Number.isSafeInteger(remainingMs) || remainingMs <= 0) {
          throw new Error("Cron request deadline elapsed before dispatch");
        }
        const abort = new AbortController();
        const request = new Request(`https://fleet.internal${CRON_PATH}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            [TIMESTAMP_HEADER]: tickTimestamp,
            [MAC_HEADER]: mac,
          },
          body,
          signal: abort.signal,
        });
        const stub = fleets.getByName(fleetId);
        const work = callFleet(stub, request).then((response) =>
          verifyCronAddressResponse(
            response,
            value,
            cron.cronHmacKey,
            abort.signal,
          ),
        );
        const receipt = await withAbortDeadline(work, remainingMs, abort);
        const completedAt = parseRuntimeTime(now());
        if (completedAt > deadlineMs || completedAt > globalDeadlineMs) {
          throw new Error("Cron response completed after its deadline");
        }
        result.addressed.push(fleetId);
        receipts.push({ fleetId, ...receipt });
      } catch {
        result.failed.push(fleetId);
      }
    }
    if (result.failed.length !== 0) {
      throw new CronAddressRunError(
        "one or more fleets were not addressed",
        result,
      );
    }
  } catch (error) {
    if (result.addressed.length === 0 && result.failed.length === 0) {
      result.failed.push(...cron.inventoriedFleetIds);
    }
    emitCronResult(options, cron, scheduledTimestamp, result, receipts);
    if (error instanceof CronAddressRunError) {
      throw error;
    }
    throw new CronAddressRunError("Cron address run failed", result);
  }
  emitCronResult(options, cron, scheduledTimestamp, result, receipts);
  return result;
}

export type CronAddressResult = {
  addressed: string[];
  failed: string[];
};

export type CronAddressOptions = {
  now?: () => string;
  nonce?: () => string;
  log?: (record: CronAddressDiagnostic) => void;
};

export type CronAddressReceiptDiagnostic = {
  fleetId: string;
  persistenceGeneration: number;
  receiptTime: string;
};

export type CronAddressDiagnostic =
  | {
      schemaVersion: 1;
      event: "cron-address";
      status: "configuration-rejected";
    }
  | {
      schemaVersion: 1;
      event: "cron-address";
      inventoryRevision: string;
      inventoryDigest: string;
      scheduledTimestamp: string;
      addressedFleetIds: string[];
      failedFleetIds: string[];
      receipts: CronAddressReceiptDiagnostic[];
      status: "success" | "partial" | "failure";
    };

export class CronAddressRunError extends Error {
  constructor(
    message: string,
    readonly result: CronAddressResult,
  ) {
    super(message);
    this.name = "CronAddressRunError";
  }
}

function emitCronResult(
  options: CronAddressOptions,
  cron: ParsedCronBindings,
  scheduledTimestamp: string,
  result: CronAddressResult,
  receipts: CronAddressReceiptDiagnostic[],
): void {
  const status =
    result.failed.length === 0
      ? "success"
      : result.addressed.length === 0
        ? "failure"
        : "partial";
  emitCronDiagnostic(options, {
    schemaVersion: 1,
    event: "cron-address",
    inventoryRevision: cron.inventoryRevision,
    inventoryDigest: cron.inventoryDigest,
    scheduledTimestamp,
    addressedFleetIds: [...result.addressed],
    failedFleetIds: [...result.failed],
    receipts: receipts.map((receipt) => ({ ...receipt })),
    status,
  });
}

function emitCronDiagnostic(
  options: CronAddressOptions,
  record: CronAddressDiagnostic,
): void {
  const log =
    options.log ??
    ((value: CronAddressDiagnostic) => {
      console.log(JSON.stringify(value));
    });
  try {
    log(record);
  } catch {
    // Persistent signed status is deployment authority; logging is diagnostic.
  }
}

function randomNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function parseRuntimeTime(value: string): number {
  if (!isCanonicalCronTimestamp(value)) {
    throw new Error("Cron clock is invalid");
  }
  const parsed = Date.parse(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error("Cron clock is invalid");
  }
  return parsed;
}

function callFleet(
  stub: { fetch(request: Request): Promise<Response> },
  request: Request,
): Promise<Response> {
  try {
    const work = stub.fetch(request);
    void work.catch(() => undefined);
    return work;
  } catch (error) {
    return Promise.reject(error);
  }
}

async function withAbortDeadline<T>(
  work: Promise<T>,
  deadlineMs: number,
  abort: AbortController,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      abort.abort();
      reject(new Error("Cron fleet deadline exceeded"));
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

async function verifyCronAddressResponse(
  response: Response,
  request: CronAddressRequestV1,
  key: Uint8Array,
  signal: AbortSignal,
): Promise<Omit<CronAddressReceiptDiagnostic, "fleetId">> {
  if (response.status !== 200) {
    throw new Error("Cron fleet rejected the address request");
  }
  const timestamp = response.headers.get(TIMESTAMP_HEADER) ?? "";
  const mac = response.headers.get(MAC_HEADER) ?? "";
  const body = await readCronResponseBody(response, signal);
  const value = parseCronAddressResponse(body);
  await verifyCronResponse(key, "POST", CRON_PATH, timestamp, body, mac);
  if (
    timestamp !== value.receiptTime ||
    value.protocolVersion !== request.protocolVersion ||
    value.fleetId !== request.fleetId ||
    value.revision !== request.revision ||
    value.inventoryDigest !== request.inventoryDigest ||
    value.nonce !== request.nonce ||
    value.tickTimestamp !== request.tickTimestamp ||
    value.deadline !== request.deadline
  ) {
    throw new Error("Cron fleet response identity diverged");
  }
  return {
    receiptTime: value.receiptTime,
    persistenceGeneration: value.persistenceGeneration,
  };
}

async function readCronResponseBody(
  response: Response,
  signal: AbortSignal,
): Promise<string> {
  if (response.body === null) {
    return "";
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: false,
  });
  const chunks: string[] = [];
  let byteCount = 0;
  const cancel = () => {
    void reader.cancel("Cron response deadline elapsed").catch(() => undefined);
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) {
        break;
      }
      byteCount += next.value.byteLength;
      if (byteCount > MAX_CRON_RESPONSE_BYTES) {
        await reader.cancel("Cron response body exceeds bound");
        throw new Error("Cron response body exceeds bound");
      }
      chunks.push(decoder.decode(next.value, { stream: true }));
    }
    chunks.push(decoder.decode());
    return chunks.join("");
  } finally {
    signal.removeEventListener("abort", cancel);
    reader.releaseLock();
  }
}
