import type { Holder, RoutingState } from "../protocol/messages";
import {
  MemoryFleetStore,
  type DueKind,
  type DueStatus,
  type DueWorkRecord,
  type MemoryClock,
  type RepositoryRecord,
} from "./memory";

export type FleetSql = {
  run(query: string, ...binds: unknown[]): void;
  all(query: string, ...binds: unknown[]): Record<string, unknown>[];
};

export function loadFleetStore(
  sql: FleetSql,
  fleetId: string,
  clock: MemoryClock,
): MemoryFleetStore {
  const store = new MemoryFleetStore(fleetId, clock);
  const rows = sql.all("SELECT * FROM fleet_state WHERE fleet_id = ?", fleetId);
  const row = rows[0];
  if (row === undefined) {
    return store;
  }
  store.fleet.inventoried = row.inventoried === 1;
  store.fleet.epoch = asInt(row.epoch);
  store.fleet.sessionId = asNullableString(row.session_id);
  store.fleet.sequence = asInt(row.sequence);
  store.fleet.leaseGeneration = asInt(row.lease_generation);
  store.fleet.lastIssuedLeaseExpiryMax = asNullableString(
    row.last_issued_lease_expiry_max,
  );
  store.fleet.leaseNotBefore = asNullableString(row.lease_not_before);
  store.fleet.holder = asString(row.holder) as Holder;
  store.fleet.fenceGeneration = asInt(row.fence_generation);
  store.fleet.routingState = asString(row.routing_state) as
    RoutingState | "UNINITIALIZED";
  store.fleet.hostedHold = row.hosted_hold === 1;
  store.fleet.configRevision = asInt(row.config_revision);
  store.fleet.policyDigest = asNullableString(row.policy_digest);
  store.fleet.maxCapacity = asInt(row.max_capacity);
  store.fleet.canaryScaleSet = asNullableString(row.canary_scale_set);
  store.fleet.canaryPassed = row.canary_passed === 1;

  for (const nonce of sql.all(
    "SELECT digest, expires_at FROM request_nonces",
  )) {
    store.rememberNonce(asString(nonce.digest), asString(nonce.expires_at));
  }
  for (const repository of sql.all("SELECT * FROM repositories")) {
    store.putRepository(readRepository(repository));
  }
  for (const work of sql.all("SELECT * FROM due_work")) {
    store.enqueue(readDueWork(work));
  }
  for (const transition of sql.all(
    "SELECT epoch, from_state, to_state FROM transitions",
  )) {
    store.transitions.push({
      epoch: asInt(transition.epoch),
      from: asString(transition.from_state),
      to: asString(transition.to_state),
    });
  }
  for (const event of sql.all("SELECT event FROM audit_events ORDER BY seq")) {
    store.recordAudit(asString(event.event));
  }
  return store;
}

export function saveFleetStore(sql: FleetSql, store: MemoryFleetStore): void {
  const fleet = store.fleet;
  sql.run("DELETE FROM fleet_state");
  sql.run("DELETE FROM request_nonces");
  sql.run("DELETE FROM repositories");
  sql.run("DELETE FROM due_work");
  sql.run("DELETE FROM transitions");
  sql.run("DELETE FROM audit_events");
  sql.run(
    `INSERT INTO fleet_state (
      fleet_id, inventoried, epoch, session_id, sequence, lease_generation,
      last_issued_lease_expiry_max, lease_not_before, holder, fence_generation,
      routing_state, hosted_hold, config_revision, policy_digest, max_capacity,
      canary_scale_set, canary_passed
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    fleet.fleetId,
    fleet.inventoried ? 1 : 0,
    fleet.epoch,
    fleet.sessionId,
    fleet.sequence,
    fleet.leaseGeneration,
    fleet.lastIssuedLeaseExpiryMax,
    fleet.leaseNotBefore,
    fleet.holder,
    fleet.fenceGeneration,
    fleet.routingState,
    fleet.hostedHold ? 1 : 0,
    fleet.configRevision,
    fleet.policyDigest,
    fleet.maxCapacity,
    fleet.canaryScaleSet,
    fleet.canaryPassed ? 1 : 0,
  );
  for (const [digest, expiresAt] of store.nonces) {
    sql.run(
      "INSERT INTO request_nonces (digest, expires_at) VALUES (?, ?)",
      digest,
      expiresAt,
    );
  }
  for (const repository of store.repositories.values()) {
    sql.run(
      `INSERT INTO repositories (
        alias, expected_route, confirmed_route, archive_latched,
        archive_observed_at, archived, selector_evidence_at, open_queue_risk
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      repository.alias,
      repository.expectedRoute,
      repository.confirmedRoute,
      repository.archiveLatched ? 1 : 0,
      repository.archiveObservedAt,
      repository.archived ? 1 : 0,
      repository.selectorEvidenceAt,
      repository.openQueueRisk === null
        ? null
        : JSON.stringify(repository.openQueueRisk),
    );
  }
  for (const work of store.dueWork) {
    sql.run(
      `INSERT INTO due_work (
        id, kind, due_at, claim_id, claim_expires_at, attempts, status, payload
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      work.id,
      work.kind,
      work.dueAt,
      work.claimId,
      work.claimExpiresAt,
      work.attempts,
      work.status,
      JSON.stringify(work.payload),
    );
  }
  for (const transition of store.transitions) {
    sql.run(
      "INSERT INTO transitions (epoch, from_state, to_state) VALUES (?, ?, ?)",
      transition.epoch,
      transition.from,
      transition.to,
    );
  }
  for (const event of store.audit) {
    sql.run("INSERT INTO audit_events (event) VALUES (?)", event);
  }
}

function readRepository(row: Record<string, unknown>): RepositoryRecord {
  let openQueueRisk: RepositoryRecord["openQueueRisk"] = null;
  if (typeof row.open_queue_risk === "string" && row.open_queue_risk !== "") {
    openQueueRisk = JSON.parse(
      row.open_queue_risk,
    ) as RepositoryRecord["openQueueRisk"];
  }
  return {
    alias: asString(row.alias),
    expectedRoute: asString(row.expected_route),
    confirmedRoute: asNullableString(row.confirmed_route),
    archiveLatched: row.archive_latched === 1,
    archiveObservedAt: asNullableString(row.archive_observed_at),
    archived: row.archived === 1,
    selectorEvidenceAt: asNullableString(row.selector_evidence_at),
    openQueueRisk,
  };
}

function readDueWork(row: Record<string, unknown>): DueWorkRecord {
  const payload =
    typeof row.payload === "string" && row.payload !== ""
      ? (JSON.parse(row.payload) as Record<string, string>)
      : {};
  return {
    id: asString(row.id),
    kind: asString(row.kind) as DueKind,
    dueAt: asString(row.due_at),
    claimId: asNullableString(row.claim_id),
    claimExpiresAt: asNullableString(row.claim_expires_at),
    attempts: asInt(row.attempts),
    status: asString(row.status) as DueStatus,
    payload,
  };
}

function asString(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("sql text column is invalid");
  }
  return value;
}

function asNullableString(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  return asString(value);
}

function asInt(value: unknown): number {
  if (typeof value === "bigint") {
    return Number(value);
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error("sql integer column is invalid");
  }
  return value;
}
