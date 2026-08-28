import type {
  AddressStatusChildCounts,
  AddressStatusResponseV1,
} from "../protocol/address-status";
import {
  deadlineForTick,
  isCanonicalCronTimestamp,
  isCanonicalInventoryRevision,
} from "../protocol/cron";
import { FLEET_ID, HEX64 } from "../protocol/messages";
import type { FleetSql } from "./persist";

export type AddressStatusReadInput = {
  fleetId: string;
  inventoryRevision: string;
  inventoryDigest: string;
  nonce: string;
  requestTime: string;
  responseTime: string;
  nonceTtlMs: number;
};

export type AddressStatusSnapshot = Omit<
  AddressStatusResponseV1,
  | "protocolVersion"
  | "status"
  | "fleetId"
  | "nonce"
  | "requestTime"
  | "responseTime"
  | "inventoryRevision"
  | "inventoryDigest"
>;

export function readAddressStatus(
  sql: FleetSql,
  input: AddressStatusReadInput,
): AddressStatusSnapshot {
  validateInput(input);
  const nonceKey = `status:${input.nonce}`;
  const nonceExpiresAt = deadlineForTick(input.responseTime, input.nonceTtlMs);
  let snapshot: AddressStatusSnapshot | undefined;
  sql.transaction(() => {
    sql.run(
      "DELETE FROM request_nonces WHERE expires_at <= ?",
      input.responseTime,
    );
    if (
      sql.all("SELECT digest FROM request_nonces WHERE digest = ?", nonceKey)
        .length !== 0
    ) {
      throw new Error("address-status nonce was already used");
    }

    const rows = sql.all(
      `SELECT fleet_id, inventoried, epoch, session_id, sequence,
        lease_generation, last_issued_lease_expiry_max, lease_not_before,
        holder, fence_generation, routing_state, hosted_hold,
        config_revision, policy_digest, max_capacity, canary_scale_set,
        canary_passed, canary_evidence, cron_inventory_revision,
        cron_inventory_digest, cron_tick_timestamp, cron_tick_nonce,
        cron_addressed_at, persistence_generation
      FROM fleet_state ORDER BY fleet_id`,
    );
    if (rows.length !== 1) {
      throw new Error("address-status fleet state is unavailable");
    }
    const row = rows[0];
    if (row === undefined || asString(row.fleet_id) !== input.fleetId) {
      throw new Error("address-status fleet identity diverged");
    }
    const receipt = validateInertReceipt(row, input);
    const childCounts = readChildCounts(sql);

    sql.run(
      "INSERT INTO request_nonces (digest, expires_at) VALUES (?, ?)",
      nonceKey,
      nonceExpiresAt,
    );
    const savedNonce = sql.all(
      "SELECT digest, expires_at FROM request_nonces WHERE digest = ?",
      nonceKey,
    );
    if (
      savedNonce.length !== 1 ||
      asString(savedNonce[0]?.digest) !== nonceKey ||
      asString(savedNonce[0]?.expires_at) !== nonceExpiresAt
    ) {
      throw new Error("address-status nonce receipt diverged");
    }
    snapshot = {
      tickTimestamp: receipt.tickTimestamp,
      receiptTime: receipt.receiptTime,
      persistenceGeneration: receipt.persistenceGeneration,
      inventoried: false,
      holder: "none",
      maxCapacity: 0,
      routingState: "UNINITIALIZED",
      childCounts,
    };
  });
  if (snapshot === undefined) {
    throw new Error("address-status receipt was not read");
  }
  return snapshot;
}

function validateInput(input: AddressStatusReadInput): void {
  if (
    !FLEET_ID.test(input.fleetId) ||
    !isCanonicalInventoryRevision(input.inventoryRevision) ||
    !HEX64.test(input.inventoryDigest) ||
    !HEX64.test(input.nonce) ||
    !isCanonicalCronTimestamp(input.requestTime) ||
    !isCanonicalCronTimestamp(input.responseTime) ||
    input.responseTime < input.requestTime ||
    !Number.isSafeInteger(input.nonceTtlMs) ||
    input.nonceTtlMs <= 0
  ) {
    throw new Error("address-status read input is invalid");
  }
}

function validateInertReceipt(
  row: Record<string, unknown>,
  input: AddressStatusReadInput,
): {
  tickTimestamp: string;
  receiptTime: string;
  persistenceGeneration: number;
} {
  if (
    row.inventoried !== 0 ||
    row.epoch !== 0 ||
    row.session_id !== null ||
    row.sequence !== 0 ||
    row.lease_generation !== 0 ||
    row.last_issued_lease_expiry_max !== null ||
    row.lease_not_before !== null ||
    row.holder !== "none" ||
    row.fence_generation !== 0 ||
    row.routing_state !== "UNINITIALIZED" ||
    row.hosted_hold !== 0 ||
    row.config_revision !== 0 ||
    row.policy_digest !== null ||
    row.max_capacity !== 0 ||
    row.canary_scale_set !== null ||
    row.canary_passed !== 0 ||
    row.canary_evidence !== null
  ) {
    throw new Error("address-status authority is not inert");
  }
  const revision = asString(row.cron_inventory_revision);
  const digest = asString(row.cron_inventory_digest);
  const tickTimestamp = asString(row.cron_tick_timestamp);
  const tickNonce = asString(row.cron_tick_nonce);
  const receiptTime = asString(row.cron_addressed_at);
  const persistenceGeneration = asPositiveSafeInt(row.persistence_generation);
  if (
    revision !== input.inventoryRevision ||
    digest !== input.inventoryDigest ||
    !isCanonicalInventoryRevision(revision) ||
    !HEX64.test(digest) ||
    !isCanonicalCronTimestamp(tickTimestamp) ||
    !HEX64.test(tickNonce) ||
    !isCanonicalCronTimestamp(receiptTime) ||
    receiptTime < tickTimestamp ||
    input.responseTime < receiptTime ||
    input.responseTime > deadlineForTick(receiptTime, input.nonceTtlMs)
  ) {
    throw new Error("address-status Cron receipt is invalid");
  }
  return { tickTimestamp, receiptTime, persistenceGeneration };
}

function readChildCounts(sql: FleetSql): AddressStatusChildCounts {
  return {
    repositories: requireZeroCount(sql, "repositories"),
    transitions: requireZeroCount(sql, "transitions"),
    dueWork: requireZeroCount(sql, "due_work"),
    auditEvents: requireZeroCount(sql, "audit_events"),
  };
}

function requireZeroCount(
  sql: FleetSql,
  table: "repositories" | "transitions" | "due_work" | "audit_events",
): 0 {
  const rows = sql.all(`SELECT COUNT(*) AS count FROM ${table}`);
  if (rows.length !== 1 || rows[0]?.count !== 0) {
    throw new Error("address-status child state is not inert");
  }
  return 0;
}

function asString(value: unknown): string {
  if (typeof value !== "string" || value === "") {
    throw new Error("address-status value is invalid");
  }
  return value;
}

function asPositiveSafeInt(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error("address-status generation is invalid");
  }
  return value;
}
