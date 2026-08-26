import {
  isCanonicalCronTimestamp,
  isCanonicalInventoryRevision,
} from "../protocol/cron";
import { FLEET_ID, HEX64 } from "../protocol/messages";
import type { FleetSql } from "./persist";

export type CronAddressReceiptInput = {
  fleetId: string;
  inventoryRevision: string;
  inventoryDigest: string;
  tickTimestamp: string;
  tickNonce: string;
  addressedAt: string;
  nonceExpiresAt: string;
};

export type CronAddressReceiptResult = {
  persistenceGeneration: number;
};

type ExistingReceipt = {
  revision: string;
  digest: string;
  tickTimestamp: string;
  tickNonce: string;
  addressedAt: string;
};

export function persistCronAddressReceipt(
  sql: FleetSql,
  input: CronAddressReceiptInput,
): CronAddressReceiptResult {
  validateInput(input);
  let result: CronAddressReceiptResult | undefined;
  sql.transaction(() => {
    sql.run(
      "DELETE FROM request_nonces WHERE expires_at <= ?",
      input.addressedAt,
    );
    const nonceKey = `cron:${input.tickNonce}`;
    if (
      sql.all("SELECT digest FROM request_nonces WHERE digest = ?", nonceKey)
        .length !== 0
    ) {
      throw new Error("Cron address nonce was already used");
    }

    const rows = sql.all(
      `SELECT fleet_id, persistence_generation, cron_inventory_revision,
        cron_inventory_digest, cron_tick_timestamp, cron_tick_nonce,
        cron_addressed_at FROM fleet_state ORDER BY fleet_id`,
    );
    if (
      rows.length > 1 ||
      (rows.length === 1 && asString(rows[0]?.fleet_id) !== input.fleetId)
    ) {
      throw new Error("durable object contains a foreign fleet");
    }
    const row = rows[0];
    const expectedGeneration =
      row === undefined
        ? 0
        : asPositiveSafeInt(row.persistence_generation, "fleet generation");
    if (row !== undefined) {
      const existing = readExistingReceipt(row);
      if (existing !== null) {
        const revisionOrder =
          BigInt(input.inventoryRevision) - BigInt(existing.revision);
        if (revisionOrder < 0n) {
          throw new Error("Cron inventory revision regressed");
        }
        if (revisionOrder === 0n && input.inventoryDigest !== existing.digest) {
          throw new Error("Cron inventory digest conflicts");
        }
        if (input.tickTimestamp <= existing.tickTimestamp) {
          throw new Error("Cron tick did not advance");
        }
        if (input.addressedAt < existing.addressedAt) {
          throw new Error("Cron addressed time regressed");
        }
      }
    }

    const nextGeneration = expectedGeneration + 1;
    if (!Number.isSafeInteger(nextGeneration)) {
      throw new Error("fleet generation overflows");
    }
    if (row === undefined) {
      sql.run(
        `INSERT INTO fleet_state (
          fleet_id, inventoried, epoch, session_id, sequence,
          lease_generation, last_issued_lease_expiry_max, lease_not_before,
          holder, fence_generation, routing_state, hosted_hold,
          config_revision, policy_digest, max_capacity, canary_scale_set,
          canary_passed, cron_inventory_revision, cron_inventory_digest,
          cron_tick_timestamp, cron_tick_nonce, cron_addressed_at,
          persistence_generation
        ) VALUES (?, 0, 0, NULL, 0, 0, NULL, NULL, 'none', 0,
          'UNINITIALIZED', 0, 0, NULL, 0, NULL, 0, ?, ?, ?, ?, ?, ?)`,
        input.fleetId,
        input.inventoryRevision,
        input.inventoryDigest,
        input.tickTimestamp,
        input.tickNonce,
        input.addressedAt,
        nextGeneration,
      );
    } else {
      sql.run(
        `UPDATE fleet_state SET
          cron_inventory_revision = ?,
          cron_inventory_digest = ?,
          cron_tick_timestamp = ?,
          cron_tick_nonce = ?,
          cron_addressed_at = ?,
          persistence_generation = ?
        WHERE fleet_id = ? AND persistence_generation = ?`,
        input.inventoryRevision,
        input.inventoryDigest,
        input.tickTimestamp,
        input.tickNonce,
        input.addressedAt,
        nextGeneration,
        input.fleetId,
        expectedGeneration,
      );
    }
    sql.run(
      "INSERT INTO request_nonces (digest, expires_at) VALUES (?, ?)",
      nonceKey,
      input.nonceExpiresAt,
    );

    const saved = sql.all(
      `SELECT fleet_id, persistence_generation, cron_inventory_revision,
        cron_inventory_digest, cron_tick_timestamp, cron_tick_nonce,
        cron_addressed_at FROM fleet_state WHERE fleet_id = ?`,
      input.fleetId,
    );
    const savedNonce = sql.all(
      "SELECT digest, expires_at FROM request_nonces WHERE digest = ?",
      nonceKey,
    );
    if (
      saved.length !== 1 ||
      savedNonce.length !== 1 ||
      asString(saved[0]?.fleet_id) !== input.fleetId ||
      asPositiveSafeInt(
        saved[0]?.persistence_generation,
        "fleet generation",
      ) !== nextGeneration ||
      asString(saved[0]?.cron_inventory_revision) !== input.inventoryRevision ||
      asString(saved[0]?.cron_inventory_digest) !== input.inventoryDigest ||
      asString(saved[0]?.cron_tick_timestamp) !== input.tickTimestamp ||
      asString(saved[0]?.cron_tick_nonce) !== input.tickNonce ||
      asString(saved[0]?.cron_addressed_at) !== input.addressedAt ||
      asString(savedNonce[0]?.digest) !== nonceKey ||
      asString(savedNonce[0]?.expires_at) !== input.nonceExpiresAt
    ) {
      throw new Error("Cron address receipt diverged");
    }
    result = { persistenceGeneration: nextGeneration };
  });
  if (result === undefined) {
    throw new Error("Cron address receipt was not committed");
  }
  return result;
}

function validateInput(input: CronAddressReceiptInput): void {
  if (
    !FLEET_ID.test(input.fleetId) ||
    !isCanonicalInventoryRevision(input.inventoryRevision) ||
    !HEX64.test(input.inventoryDigest) ||
    !HEX64.test(input.tickNonce) ||
    !isCanonicalCronTimestamp(input.tickTimestamp) ||
    !isCanonicalCronTimestamp(input.addressedAt) ||
    !isCanonicalCronTimestamp(input.nonceExpiresAt) ||
    input.addressedAt < input.tickTimestamp ||
    input.nonceExpiresAt <= input.addressedAt
  ) {
    throw new Error("Cron address receipt is invalid");
  }
}

function readExistingReceipt(
  row: Record<string, unknown>,
): ExistingReceipt | null {
  const values = [
    row.cron_inventory_revision,
    row.cron_inventory_digest,
    row.cron_tick_timestamp,
    row.cron_tick_nonce,
    row.cron_addressed_at,
  ];
  if (values.every((value) => value === null)) {
    return null;
  }
  if (!values.every((value) => typeof value === "string")) {
    throw new Error("Cron address receipt is incomplete");
  }
  const receipt = {
    revision: values[0] as string,
    digest: values[1] as string,
    tickTimestamp: values[2] as string,
    tickNonce: values[3] as string,
    addressedAt: values[4] as string,
  };
  if (
    !isCanonicalInventoryRevision(receipt.revision) ||
    !HEX64.test(receipt.digest) ||
    !isCanonicalCronTimestamp(receipt.tickTimestamp) ||
    !HEX64.test(receipt.tickNonce) ||
    !isCanonicalCronTimestamp(receipt.addressedAt) ||
    receipt.addressedAt < receipt.tickTimestamp
  ) {
    throw new Error("Cron address receipt is corrupt");
  }
  return receipt;
}

function asString(value: unknown): string {
  if (typeof value !== "string" || value === "") {
    throw new Error("durable value is invalid");
  }
  return value;
}

function asPositiveSafeInt(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}
