#!/usr/bin/env node

import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import {
  closeSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const STATUS_PATH = "/v1/admin/status";
const REQUEST_DOMAIN = "portable-ghar-address-status-request-v1";
const RESPONSE_DOMAIN = "portable-ghar-address-status-response-v1";
const TIMESTAMP_HEADER = "x-portable-ghar-timestamp";
const MAC_HEADER = "x-portable-ghar-mac";
const MAX_PROTOCOL_BYTES = 65_536;
const MAX_VERIFICATION_WINDOW_MS = 30 * 60_000;
const FLEET_ID = /^[a-z][a-z0-9-]{0,63}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const UINT64_DECIMAL = /^[1-9][0-9]{0,19}$/;
const MAX_UINT64 = 18_446_744_073_709_551_615n;
const SAFE_VERSION_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export class AddressabilityUnavailableError extends Error {
  constructor(evidence) {
    super("Worker addressability evidence is unavailable");
    this.name = "AddressabilityUnavailableError";
    this.evidence = evidence;
  }
}

export function createDeadlineScope(deadlineMs, now = Date.now) {
  if (!Number.isSafeInteger(deadlineMs)) {
    throw new Error("deadline rejected");
  }
  const controller = new AbortController();
  let timer;
  let closed = false;
  const delay = deadlineMs - now();
  if (delay <= 0) {
    controller.abort(new Error("deadline elapsed"));
  } else {
    timer = setTimeout(() => {
      timer = undefined;
      controller.abort(new Error("deadline elapsed"));
    }, delay);
  }
  return {
    signal: controller.signal,
    close() {
      if (closed) {
        return;
      }
      closed = true;
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      controller.abort(new Error("verification closed"));
    },
  };
}

export function waitUntil(targetMs, signal) {
  if (!Number.isSafeInteger(targetMs)) {
    return Promise.reject(new Error("wait rejected"));
  }
  if (signal.aborted) {
    return Promise.reject(new Error("aborted"));
  }
  const delay = targetMs - Date.now();
  if (delay <= 0) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const cleanup = () => {
      signal.removeEventListener("abort", onAbort);
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
    };
    const finish = (work) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      work();
    };
    const onAbort = () => finish(() => reject(new Error("aborted")));
    signal.addEventListener("abort", onAbort, { once: true });
    timer = setTimeout(() => finish(resolve), delay);
  });
}

export async function verifyWorkerAddressability(rawInput, overrides = {}) {
  const input = validateInput(rawInput);
  const dependencies = {
    now: overrides.now ?? Date.now,
    nonce: overrides.nonce ?? (() => randomBytes(32).toString("hex")),
    waitUntil: overrides.waitUntil ?? waitUntil,
    fetch: overrides.fetch ?? globalThis.fetch,
    createDeadlineScope: overrides.createDeadlineScope ?? createDeadlineScope,
  };
  const deadlineMs = Date.parse(input.deadlineAt);
  const versionCreatedMs = Date.parse(input.versionCreatedAt);
  const startedMs = dependencies.now();
  if (
    !Number.isSafeInteger(startedMs) ||
    deadlineMs <= startedMs ||
    deadlineMs - startedMs > MAX_VERIFICATION_WINDOW_MS
  ) {
    throw new Error("verification window rejected");
  }
  const scope = dependencies.createDeadlineScope(deadlineMs, dependencies.now);
  const accepted = new Map();
  try {
    for (;;) {
      const pending = input.fleetIds.filter(
        (fleetId) => !accepted.has(fleetId),
      );
      if (pending.length === 0) {
        return buildEvidence("verified", input, accepted, dependencies.now());
      }
      const nowMs = dependencies.now();
      const boundaryMs = nextNaturalMinute(nowMs);
      if (
        scope.signal.aborted ||
        nowMs >= deadlineMs ||
        boundaryMs >= deadlineMs
      ) {
        throw new AddressabilityUnavailableError(
          buildEvidence(
            "unavailable",
            input,
            accepted,
            Math.min(nowMs, deadlineMs),
          ),
        );
      }
      try {
        await dependencies.waitUntil(boundaryMs, scope.signal);
      } catch {
        throw new AddressabilityUnavailableError(
          buildEvidence(
            "unavailable",
            input,
            accepted,
            Math.min(dependencies.now(), deadlineMs),
          ),
        );
      }
      if (scope.signal.aborted || dependencies.now() >= deadlineMs) {
        throw new AddressabilityUnavailableError(
          buildEvidence(
            "unavailable",
            input,
            accepted,
            Math.min(dependencies.now(), deadlineMs),
          ),
        );
      }
      const attempts = await Promise.all(
        pending.map((fleetId) =>
          attemptFleet({
            input,
            fleetId,
            boundaryMs,
            deadlineMs,
            versionCreatedMs,
            dependencies,
            lifecycleSignal: scope.signal,
          }),
        ),
      );
      for (const result of attempts) {
        if (result !== null) {
          accepted.set(result.fleetId, result);
        }
      }
      if (scope.signal.aborted) {
        throw new AddressabilityUnavailableError(
          buildEvidence(
            "unavailable",
            input,
            accepted,
            Math.min(dependencies.now(), deadlineMs),
          ),
        );
      }
    }
  } finally {
    scope.close();
  }
}

async function attemptFleet({
  input,
  fleetId,
  boundaryMs,
  deadlineMs,
  versionCreatedMs,
  dependencies,
  lifecycleSignal,
}) {
  const requestMs = dependencies.now();
  if (
    lifecycleSignal.aborted ||
    requestMs < boundaryMs ||
    requestMs >= deadlineMs
  ) {
    return null;
  }
  const requestTime = new Date(requestMs).toISOString();
  const nonce = dependencies.nonce(fleetId, boundaryMs);
  if (!HEX64.test(nonce)) {
    return null;
  }
  const requestValue = {
    protocolVersion: 1,
    fleetId,
    nonce,
    requestTime,
    inventoryRevision: input.inventoryRevision,
    inventoryDigest: input.inventoryDigest,
  };
  const body = canonicalize(requestValue);
  const mac = statusMac(
    input.cronHmacKeyHex,
    REQUEST_DOMAIN,
    requestTime,
    body,
  );
  const requestDeadlineMs = Math.min(
    deadlineMs,
    requestMs + input.timestampWindowMs,
  );
  const timeoutMs = requestDeadlineMs - requestMs;
  if (timeoutMs <= 0) {
    return null;
  }
  const controller = new AbortController();
  const abortFromLifecycle = () => controller.abort();
  lifecycleSignal.addEventListener("abort", abortFromLifecycle, { once: true });
  let timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const request = new Request(new URL(STATUS_PATH, input.endpoint), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        [TIMESTAMP_HEADER]: requestTime,
        [MAC_HEADER]: mac,
      },
      body,
      signal: controller.signal,
    });
    const response = await dependencies.fetch(request);
    if (response.status !== 200) {
      return null;
    }
    const responseBody = await readBoundedResponse(response, controller.signal);
    const observedMs = dependencies.now();
    if (observedMs >= deadlineMs) {
      return null;
    }
    return verifyStatusResponse({
      response,
      body: responseBody,
      request: requestValue,
      input,
      observedMs,
      versionCreatedMs,
    });
  } catch {
    return null;
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
    lifecycleSignal.removeEventListener("abort", abortFromLifecycle);
  }
}

function verifyStatusResponse({
  response,
  body,
  request,
  input,
  observedMs,
  versionCreatedMs,
}) {
  const timestamp = response.headers.get(TIMESTAMP_HEADER) ?? "";
  const presentedMac = response.headers.get(MAC_HEADER) ?? "";
  if (
    !constantTimeMacEqual(
      statusMac(input.cronHmacKeyHex, RESPONSE_DOMAIN, timestamp, body),
      presentedMac,
    )
  ) {
    return null;
  }
  const value = parseCanonicalObject(body);
  exactKeys(value, [
    "childCounts",
    "fleetId",
    "holder",
    "inventoried",
    "inventoryDigest",
    "inventoryRevision",
    "maxCapacity",
    "nonce",
    "persistenceGeneration",
    "protocolVersion",
    "receiptTime",
    "requestTime",
    "responseTime",
    "routingState",
    "status",
    "tickTimestamp",
  ]);
  const childCounts = record(value.childCounts);
  exactKeys(childCounts, [
    "auditEvents",
    "dueWork",
    "repositories",
    "transitions",
  ]);
  if (
    value.protocolVersion !== 1 ||
    value.status !== "inert-receipt" ||
    value.fleetId !== request.fleetId ||
    value.nonce !== request.nonce ||
    value.requestTime !== request.requestTime ||
    value.responseTime !== timestamp ||
    value.inventoryRevision !== input.inventoryRevision ||
    value.inventoryDigest !== input.inventoryDigest ||
    value.inventoried !== false ||
    value.holder !== "none" ||
    value.maxCapacity !== 0 ||
    value.routingState !== "UNINITIALIZED" ||
    childCounts.repositories !== 0 ||
    childCounts.transitions !== 0 ||
    childCounts.dueWork !== 0 ||
    childCounts.auditEvents !== 0 ||
    typeof value.persistenceGeneration !== "number" ||
    !Number.isSafeInteger(value.persistenceGeneration) ||
    value.persistenceGeneration <= 0 ||
    !isTimestamp(value.tickTimestamp) ||
    !isTimestamp(value.receiptTime) ||
    !isTimestamp(value.responseTime)
  ) {
    return null;
  }
  const requestMs = Date.parse(request.requestTime);
  const responseMs = Date.parse(value.responseTime);
  const receiptMs = Date.parse(value.receiptTime);
  const tickMs = Date.parse(value.tickTimestamp);
  if (
    responseMs < requestMs ||
    receiptMs < tickMs ||
    receiptMs > responseMs ||
    receiptMs <= versionCreatedMs ||
    Math.abs(responseMs - requestMs) > input.timestampWindowMs ||
    Math.abs(observedMs - responseMs) > input.timestampWindowMs
  ) {
    return null;
  }
  return {
    fleetId: value.fleetId,
    tickTimestamp: value.tickTimestamp,
    receiptTime: value.receiptTime,
    persistenceGeneration: value.persistenceGeneration,
  };
}

async function readBoundedResponse(response, signal) {
  if (response.body === null) {
    return "";
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: false,
  });
  const chunks = [];
  let length = 0;
  const cancel = () => {
    void reader.cancel("verification aborted").catch(() => undefined);
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) {
        break;
      }
      length += next.value.byteLength;
      if (length > MAX_PROTOCOL_BYTES) {
        await reader.cancel("response rejected");
        throw new Error("response rejected");
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

function validateInput(value) {
  const input = record(value);
  exactKeys(input, [
    "cronHmacKeyHex",
    "deadlineAt",
    "endpoint",
    "fleetIds",
    "inventoryDigest",
    "inventoryRevision",
    "timestampWindowMs",
    "versionCreatedAt",
    "versionId",
  ]);
  let endpoint;
  try {
    endpoint = new URL(input.endpoint);
  } catch {
    throw new Error("endpoint rejected");
  }
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.pathname !== "/" ||
    endpoint.search !== "" ||
    endpoint.hash !== "" ||
    endpoint.port !== "" ||
    !Array.isArray(input.fleetIds) ||
    input.fleetIds.length !== 3 ||
    !input.fleetIds.every(
      (fleetId, index) =>
        typeof fleetId === "string" &&
        FLEET_ID.test(fleetId) &&
        (index === 0 || fleetId > input.fleetIds[index - 1]),
    ) ||
    typeof input.inventoryRevision !== "string" ||
    !isRevision(input.inventoryRevision) ||
    typeof input.inventoryDigest !== "string" ||
    !HEX64.test(input.inventoryDigest) ||
    typeof input.cronHmacKeyHex !== "string" ||
    !/^[0-9a-f]+$/.test(input.cronHmacKeyHex) ||
    input.cronHmacKeyHex.length < 64 ||
    input.cronHmacKeyHex.length % 2 !== 0 ||
    typeof input.timestampWindowMs !== "number" ||
    !Number.isSafeInteger(input.timestampWindowMs) ||
    input.timestampWindowMs <= 0 ||
    typeof input.versionId !== "string" ||
    !SAFE_VERSION_ID.test(input.versionId) ||
    typeof input.versionCreatedAt !== "string" ||
    !isTimestamp(input.versionCreatedAt) ||
    typeof input.deadlineAt !== "string" ||
    !isTimestamp(input.deadlineAt) ||
    input.deadlineAt <= input.versionCreatedAt
  ) {
    throw new Error("verification input rejected");
  }
  const preimage = canonicalize({
    fleetIds: input.fleetIds,
    protocol: "cron-address-v1",
    revision: input.inventoryRevision,
  });
  if (
    createHash("sha256").update(preimage).digest("hex") !==
    input.inventoryDigest
  ) {
    throw new Error("inventory rejected");
  }
  return {
    ...input,
    endpoint: endpoint.href,
    fleetIds: [...input.fleetIds],
  };
}

function buildEvidence(status, input, accepted, observedMs) {
  const fleets = input.fleetIds
    .filter((fleetId) => accepted.has(fleetId))
    .map((fleetId) => ({ ...accepted.get(fleetId) }));
  return {
    schemaVersion: 1,
    status,
    workerName: "github-actionrunner",
    endpoint: input.endpoint,
    versionId: input.versionId,
    versionCreatedAt: input.versionCreatedAt,
    inventoryRevision: input.inventoryRevision,
    inventoryDigest: input.inventoryDigest,
    verifiedAt: new Date(observedMs).toISOString(),
    fleets,
    pendingFleetIds: input.fleetIds.filter((fleetId) => !accepted.has(fleetId)),
  };
}

function nextNaturalMinute(nowMs) {
  const boundary = Math.floor(nowMs / 60_000) * 60_000 + 60_000;
  if (!Number.isSafeInteger(boundary)) {
    throw new Error("boundary rejected");
  }
  return boundary;
}

function statusMac(keyHex, domain, timestamp, body) {
  if (!isTimestamp(timestamp)) {
    throw new Error("timestamp rejected");
  }
  return createHmac("sha256", Buffer.from(keyHex, "hex"))
    .update(`${domain}\nPOST\n${STATUS_PATH}\n${timestamp}\n${body}`)
    .digest("hex");
}

function constantTimeMacEqual(expected, presented) {
  if (!HEX64.test(expected) || !HEX64.test(presented)) {
    return false;
  }
  return timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(presented, "hex"),
  );
}

function canonicalize(value) {
  const encoded = JSON.stringify(sortValue(value));
  if (
    encoded === undefined ||
    Buffer.byteLength(encoded, "utf8") > MAX_PROTOCOL_BYTES
  ) {
    throw new Error("canonical value rejected");
  }
  return encoded;
}

function sortValue(value) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new Error("number rejected");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value !== null && typeof value === "object") {
    const output = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) {
        throw new Error("field rejected");
      }
      output[key] = sortValue(value[key]);
    }
    return output;
  }
  throw new Error("canonical value rejected");
}

function parseCanonicalObject(body) {
  if (
    typeof body !== "string" ||
    body.length === 0 ||
    Buffer.byteLength(body, "utf8") > MAX_PROTOCOL_BYTES
  ) {
    throw new Error("body rejected");
  }
  const value = JSON.parse(body);
  if (canonicalize(value) !== body) {
    throw new Error("body rejected");
  }
  return record(value);
}

function record(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("record rejected");
  }
  return value;
}

function exactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error("fields rejected");
  }
}

function isTimestamp(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  ) {
    return false;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function isRevision(value) {
  if (!UINT64_DECIMAL.test(value)) {
    return false;
  }
  try {
    return BigInt(value) <= MAX_UINT64;
  } catch {
    return false;
  }
}

export function writeAddressabilityEvidence(path, evidence) {
  const data = `${JSON.stringify(evidence, null, 2)}\n`;
  const temporary = join(dirname(path), `.${randomUUID()}.tmp`);
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, data, { encoding: "utf8" });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    linkSync(temporary, path);
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
    try {
      unlinkSync(temporary);
    } catch {
      // The temporary file may not exist after a rejected write.
    }
  }
}

function requirePrivateJson(path) {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || (metadata.mode & 0o777) !== 0o600) {
    throw new Error("private file rejected");
  }
  return record(JSON.parse(readFileSync(path, "utf8")));
}

function parseArgs(argv) {
  const expected = [
    "--descriptor",
    "--secrets",
    "--endpoint",
    "--version-id",
    "--version-created-at",
    "--deadline-at",
    "--output",
  ];
  if (argv.length !== expected.length * 2) {
    throw new Error("arguments rejected");
  }
  const values = {};
  for (let index = 0; index < expected.length; index += 1) {
    const offset = index * 2;
    if (argv[offset] !== expected[index]) {
      throw new Error("arguments rejected");
    }
    values[expected[index].slice(2)] = argv[offset + 1];
  }
  return values;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const descriptor = requirePrivateJson(args.descriptor);
  const secrets = requirePrivateJson(args.secrets);
  exactKeys(descriptor, [
    "accountId",
    "cronBudgetOverheadMs",
    "cronTickBudgetMs",
    "fleetIds",
    "inventoryDigest",
    "inventoryRevision",
    "maxFleets",
    "nonceTtlMs",
    "perFleetDeadlineMs",
    "timestampWindowMs",
  ]);
  exactKeys(secrets, ["CRON_HMAC_KEY", "HMAC_KEY"]);
  const verificationInput = {
    endpoint: args.endpoint,
    fleetIds: descriptor.fleetIds,
    inventoryRevision: descriptor.inventoryRevision,
    inventoryDigest: descriptor.inventoryDigest,
    cronHmacKeyHex: secrets.CRON_HMAC_KEY,
    timestampWindowMs: descriptor.timestampWindowMs,
    versionId: args["version-id"],
    versionCreatedAt: args["version-created-at"],
    deadlineAt: args["deadline-at"],
  };
  try {
    const evidence = await verifyWorkerAddressability(verificationInput);
    writeAddressabilityEvidence(args.output, evidence);
  } catch (error) {
    if (error instanceof AddressabilityUnavailableError) {
      writeAddressabilityEvidence(args.output, error.evidence);
    }
    throw error;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    await main();
  } catch {
    process.stderr.write("verify-worker-addressability: unavailable\n");
    process.exitCode = 1;
  }
}
