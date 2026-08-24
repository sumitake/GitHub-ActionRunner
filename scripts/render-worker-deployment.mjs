#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
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
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function parseArgs(argv) {
  const expected = ["--base", "--descriptor", "--secrets", "--output"];
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

const FLEET_ID = /^[a-z][a-z0-9-]{0,63}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ACCOUNT_ID = /^[0-9a-f]{32}$/;
const UINT64_DECIMAL = /^[1-9][0-9]{0,19}$/;
const MAX_UINT64 = 18_446_744_073_709_551_615n;

function requirePrivateRegular(path) {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || (metadata.mode & 0o777) !== 0o600) {
    throw new Error("private file rejected");
  }
}

function parseJson(path, isPrivate = false) {
  if (isPrivate) {
    requirePrivateRegular(path);
  }
  const value = JSON.parse(readFileSync(path, "utf8"));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("document rejected");
  }
  return value;
}

function parseJsonc(path) {
  const metadata = lstatSync(path);
  if (!metadata.isFile()) {
    throw new Error("base rejected");
  }
  const source = readFileSync(path, "utf8")
    .replace(/\/\/[^\n\r]*/g, "")
    .replace(/,\s*([}\]])/g, "$1");
  return JSON.parse(source);
}

function exactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error("fields rejected");
  }
}

function positiveSafeInteger(value) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error("integer rejected");
  }
  return value;
}

function validateBase(base) {
  exactKeys(base, [
    "compatibility_date",
    "durable_objects",
    "main",
    "migrations",
    "name",
  ]);
  if (
    base.name !== "portable-ghar-worker" ||
    base.main !== "src/index.ts" ||
    base.compatibility_date !== "2026-07-08"
  ) {
    throw new Error("base identity rejected");
  }
  const bindings = base.durable_objects?.bindings;
  if (!Array.isArray(bindings) || bindings.length !== 1) {
    throw new Error("binding rejected");
  }
  exactKeys(bindings[0], ["class_name", "name"]);
  if (
    bindings[0].name !== "FLEET" ||
    bindings[0].class_name !== "FleetDurableObject"
  ) {
    throw new Error("binding rejected");
  }
  if (!Array.isArray(base.migrations) || base.migrations.length !== 1) {
    throw new Error("migration rejected");
  }
  exactKeys(base.migrations[0], ["new_sqlite_classes", "tag"]);
  if (
    base.migrations[0].tag !== "v1" ||
    !Array.isArray(base.migrations[0].new_sqlite_classes) ||
    base.migrations[0].new_sqlite_classes.length !== 1 ||
    base.migrations[0].new_sqlite_classes[0] !== "FleetDurableObject"
  ) {
    throw new Error("migration rejected");
  }
}

function validateDescriptor(descriptor) {
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
  if (!ACCOUNT_ID.test(descriptor.accountId)) {
    throw new Error("account rejected");
  }
  if (!Array.isArray(descriptor.fleetIds) || descriptor.fleetIds.length !== 3) {
    throw new Error("inventory rejected");
  }
  for (let index = 0; index < descriptor.fleetIds.length; index += 1) {
    const fleetId = descriptor.fleetIds[index];
    if (
      typeof fleetId !== "string" ||
      !FLEET_ID.test(fleetId) ||
      (index > 0 && fleetId <= descriptor.fleetIds[index - 1])
    ) {
      throw new Error("inventory rejected");
    }
  }
  const timestampWindowMs = positiveSafeInteger(descriptor.timestampWindowMs);
  const nonceTtlMs = positiveSafeInteger(descriptor.nonceTtlMs);
  const maxFleets = positiveSafeInteger(descriptor.maxFleets);
  const perFleetDeadlineMs = positiveSafeInteger(descriptor.perFleetDeadlineMs);
  const cronBudgetOverheadMs = positiveSafeInteger(
    descriptor.cronBudgetOverheadMs,
  );
  const cronTickBudgetMs = positiveSafeInteger(descriptor.cronTickBudgetMs);
  if (maxFleets !== descriptor.fleetIds.length || cronTickBudgetMs > 900_000) {
    throw new Error("budget rejected");
  }
  const requiredBudget =
    BigInt(maxFleets) * BigInt(perFleetDeadlineMs) +
    BigInt(cronBudgetOverheadMs);
  if (requiredBudget > BigInt(cronTickBudgetMs)) {
    throw new Error("budget rejected");
  }
  if (
    typeof descriptor.inventoryRevision !== "string" ||
    !UINT64_DECIMAL.test(descriptor.inventoryRevision) ||
    BigInt(descriptor.inventoryRevision) > MAX_UINT64 ||
    typeof descriptor.inventoryDigest !== "string" ||
    !HEX64.test(descriptor.inventoryDigest)
  ) {
    throw new Error("inventory identity rejected");
  }
  const preimage = JSON.stringify({
    fleetIds: descriptor.fleetIds,
    protocol: "cron-address-v1",
    revision: descriptor.inventoryRevision,
  });
  const computedDigest = createHash("sha256").update(preimage).digest("hex");
  if (computedDigest !== descriptor.inventoryDigest) {
    throw new Error("inventory identity rejected");
  }
  return {
    timestampWindowMs,
    nonceTtlMs,
    maxFleets,
    perFleetDeadlineMs,
    cronBudgetOverheadMs,
    cronTickBudgetMs,
  };
}

function validateSecrets(secrets) {
  exactKeys(secrets, ["CRON_HMAC_KEY", "HMAC_KEY"]);
  const hmac = secrets.HMAC_KEY;
  const cron = secrets.CRON_HMAC_KEY;
  if (
    typeof hmac !== "string" ||
    typeof cron !== "string" ||
    !/^[0-9a-f]+$/.test(hmac) ||
    !/^[0-9a-f]+$/.test(cron) ||
    hmac.length < 64 ||
    cron.length < 64 ||
    hmac.length % 2 !== 0 ||
    cron.length % 2 !== 0 ||
    hmac === cron
  ) {
    throw new Error("secrets rejected");
  }
}

function writeAtomicPrivate(path, data) {
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
      // The temporary file may not have been created or may already be gone.
    }
  }
}

export function renderWorkerDeployment({
  basePath,
  descriptorPath,
  secretsPath,
  outputPath,
}) {
  const base = parseJsonc(basePath);
  const descriptor = parseJson(descriptorPath, true);
  const secrets = parseJson(secretsPath, true);
  validateBase(base);
  const terms = validateDescriptor(descriptor);
  validateSecrets(secrets);
  const rendered = {
    name: "github-actionrunner",
    main: resolve(dirname(basePath), base.main),
    compatibility_date: base.compatibility_date,
    account_id: descriptor.accountId,
    workers_dev: true,
    observability: {
      enabled: true,
      head_sampling_rate: 1,
      logs: {
        invocation_logs: false,
        persist: true,
      },
    },
    durable_objects: base.durable_objects,
    migrations: base.migrations,
    triggers: { crons: ["* * * * *"] },
    vars: {
      FLEET_IDS: descriptor.fleetIds.join(","),
      TIMESTAMP_WINDOW_MS: String(terms.timestampWindowMs),
      NONCE_TTL_MS: String(terms.nonceTtlMs),
      MAX_FLEETS: String(terms.maxFleets),
      PER_FLEET_DEADLINE_MS: String(terms.perFleetDeadlineMs),
      CRON_BUDGET_OVERHEAD_MS: String(terms.cronBudgetOverheadMs),
      CRON_TICK_BUDGET_MS: String(terms.cronTickBudgetMs),
      FLEET_INVENTORY_REVISION: descriptor.inventoryRevision,
      FLEET_INVENTORY_DIGEST: descriptor.inventoryDigest,
    },
  };
  writeAtomicPrivate(outputPath, `${JSON.stringify(rendered, null, 2)}\n`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  renderWorkerDeployment({
    basePath: args.base,
    descriptorPath: args.descriptor,
    secretsPath: args.secrets,
    outputPath: args.output,
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch {
    process.stderr.write("render-worker-deployment: rejected\n");
    process.exitCode = 1;
  }
}
