import type { Holder, RoutingState } from "../protocol/messages";
import { isRfc3339MsZ } from "../protocol/auth";
import type { ArchiveEligibility } from "../routing/archive";
import { decodeCanaryEvidence, encodeCanaryEvidence } from "../routing/canary";
import {
  decodeQueueRiskRecord,
  encodeQueueRiskRecord,
} from "../routing/queue-risk";
import {
  assertDueWorkRecord,
  type AuditPersistenceState,
  isDueKind,
  isDueStatus,
  isExternalEffectWork,
  MAX_DUE_WORK,
  MemoryFleetStore,
  type DueWorkRecord,
  type MemoryClock,
  type RepositoryRecord,
} from "./memory";

export type FleetSql = {
  run(query: string, ...binds: unknown[]): void;
  all(query: string, ...binds: unknown[]): Record<string, unknown>[];
  transaction(work: () => void): void;
};

export type DueWorkClaimGuard = {
  id: string;
  claimId: string;
  kind: DueWorkRecord["kind"];
  payload: Readonly<Record<string, string>>;
};

export type SaveFleetOptions = {
  expectedClaims?: readonly DueWorkClaimGuard[];
};

export function dueWorkClaimGuard(row: DueWorkRecord): DueWorkClaimGuard {
  if (row.status !== "claimed" || row.claimId === null) {
    throw new Error("due-work claim is unavailable");
  }
  return {
    id: row.id,
    claimId: row.claimId,
    kind: row.kind,
    payload: { ...row.payload },
  };
}

export function loadFleetStore(
  sql: FleetSql,
  fleetId: string,
  clock: MemoryClock,
): MemoryFleetStore {
  const store = new MemoryFleetStore(fleetId, clock);
  const rows = sql.all("SELECT * FROM fleet_state ORDER BY fleet_id");
  const row = rows[0];
  if (row === undefined) {
    return store;
  }
  if (rows.length !== 1 || asString(row.fleet_id) !== fleetId) {
    throw new Error("durable object contains a foreign fleet");
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
  const canaryEvidence = asNullableString(row.canary_evidence);
  store.fleet.canaryEvidence =
    canaryEvidence === null ? null : decodeCanaryEvidence(canaryEvidence);
  store.markFleetPersisted(asNonNegativeSafeInt(row.persistence_generation));

  for (const nonce of sql.all(
    "SELECT digest, expires_at FROM request_nonces",
  )) {
    store.rememberNonce(asString(nonce.digest), asString(nonce.expires_at));
  }
  for (const repository of sql.all("SELECT * FROM repositories")) {
    store.putRepository(readRepository(repository, store.fleet.configRevision));
  }
  const dueRows = sql.all("SELECT * FROM due_work ORDER BY due_at, id");
  if (dueRows.length > MAX_DUE_WORK) {
    throw new Error("due-work capacity is exceeded");
  }
  for (const work of dueRows) {
    store.enqueue(readDueWork(work));
  }
  for (const transition of sql.all(
    "SELECT epoch, from_state, to_state FROM transitions ORDER BY epoch",
  )) {
    store.transitions.push({
      epoch: asInt(transition.epoch),
      from: asString(transition.from_state) as RoutingState | "UNINITIALIZED",
      to: asString(transition.to_state) as RoutingState,
    });
  }
  let lastAuditSequence: number | null = null;
  for (const event of sql.all(
    "SELECT seq, event FROM audit_events ORDER BY seq",
  )) {
    const sequence = asInt(event.seq);
    if (sequence <= 0 || sequence <= (lastAuditSequence ?? 0)) {
      throw new Error("audit sequence is invalid");
    }
    lastAuditSequence = sequence;
    store.recordAudit(asString(event.event));
  }
  store.markAuditPersisted(lastAuditSequence);
  return store;
}

export function saveFleetStore(
  sql: FleetSql,
  store: MemoryFleetStore,
  options: SaveFleetOptions = {},
): void {
  const now = store.now();
  const completedIds = store.dueWork
    .filter((row) => row.status === "done")
    .map((row) => row.id);
  const projectedAudit = projectAudit(
    store.audit,
    store.auditPersistenceState(),
    completedIds.map((id) => `due-work-completed:${id}`),
  );
  let persistedAuditSequence = projectedAudit.state.lastSequence;
  let persistedFleetGeneration = store.fleetPersistenceGeneration();
  sql.transaction(() => {
    const guardedClaims = verifyExpectedClaims(
      sql,
      store,
      options.expectedClaims ?? [],
    );
    persistedFleetGeneration = persistFleet(
      sql,
      store.fleet,
      store.fleetPersistenceGeneration(),
    );
    persistNonces(sql, store, now);
    persistRepositories(sql, store);
    persistDueWork(sql, store, now, guardedClaims);
    persistTransitions(sql, store);
    persistedAuditSequence = persistAudit(
      sql,
      projectedAudit.events,
      projectedAudit.state,
    );
  });
  store.markFleetPersisted(persistedFleetGeneration);
  store.expireNonces(now);
  store.audit.splice(0, store.audit.length, ...projectedAudit.events);
  for (let index = store.dueWork.length - 1; index >= 0; index -= 1) {
    if (store.dueWork[index]?.status === "done") {
      store.dueWork.splice(index, 1);
    }
  }
  store.markAuditPersisted(persistedAuditSequence);
}

function persistFleet(
  sql: FleetSql,
  fleet: MemoryFleetStore["fleet"],
  expectedGeneration: number,
): number {
  if (!Number.isSafeInteger(expectedGeneration) || expectedGeneration < 0) {
    throw new Error("fleet state diverged");
  }
  const existing = sql.all(
    "SELECT fleet_id, persistence_generation FROM fleet_state ORDER BY fleet_id",
  );
  if (expectedGeneration === 0) {
    if (existing.length !== 0) {
      throw new Error("fleet state diverged");
    }
  } else if (
    existing.length !== 1 ||
    asString(existing[0]?.fleet_id) !== fleet.fleetId ||
    asNonNegativeSafeInt(existing[0]?.persistence_generation) !==
      expectedGeneration
  ) {
    throw new Error("fleet state diverged");
  }
  const nextGeneration = expectedGeneration + 1;
  if (!Number.isSafeInteger(nextGeneration)) {
    throw new Error("fleet state diverged");
  }
  sql.run(
    `INSERT INTO fleet_state (
      fleet_id, inventoried, epoch, session_id, sequence, lease_generation,
      last_issued_lease_expiry_max, lease_not_before, holder, fence_generation,
      routing_state, hosted_hold, config_revision, policy_digest, max_capacity,
      canary_scale_set, canary_passed, canary_evidence, persistence_generation
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(fleet_id) DO UPDATE SET
      inventoried = excluded.inventoried,
      epoch = excluded.epoch,
      session_id = excluded.session_id,
      sequence = excluded.sequence,
      lease_generation = excluded.lease_generation,
      last_issued_lease_expiry_max = excluded.last_issued_lease_expiry_max,
      lease_not_before = excluded.lease_not_before,
      holder = excluded.holder,
      fence_generation = excluded.fence_generation,
      routing_state = excluded.routing_state,
      hosted_hold = excluded.hosted_hold,
      config_revision = excluded.config_revision,
      policy_digest = excluded.policy_digest,
      max_capacity = excluded.max_capacity,
      canary_scale_set = excluded.canary_scale_set,
      canary_passed = excluded.canary_passed,
      canary_evidence = excluded.canary_evidence,
      persistence_generation = excluded.persistence_generation
    WHERE fleet_state.persistence_generation = ?`,
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
    0,
    fleet.canaryEvidence === null
      ? null
      : encodeCanaryEvidence(fleet.canaryEvidence),
    nextGeneration,
    expectedGeneration,
  );
  const saved = sql.all(
    "SELECT fleet_id, persistence_generation FROM fleet_state WHERE fleet_id = ?",
    fleet.fleetId,
  );
  if (
    saved.length !== 1 ||
    asString(saved[0]?.fleet_id) !== fleet.fleetId ||
    asNonNegativeSafeInt(saved[0]?.persistence_generation) !== nextGeneration
  ) {
    throw new Error("fleet state diverged");
  }
  return nextGeneration;
}

function persistNonces(
  sql: FleetSql,
  store: MemoryFleetStore,
  now: string,
): void {
  sql.run("DELETE FROM request_nonces WHERE expires_at <= ?", now);
  for (const [digest, expiresAt] of store.nonces) {
    if (expiresAt <= now) {
      continue;
    }
    sql.run(
      `INSERT INTO request_nonces (digest, expires_at) VALUES (?, ?)
      ON CONFLICT(digest) DO UPDATE SET expires_at = excluded.expires_at`,
      digest,
      expiresAt,
    );
  }
}

function persistRepositories(sql: FleetSql, store: MemoryFleetStore): void {
  for (const repository of store.repositories.values()) {
    sql.run(
      `INSERT INTO repositories (
        alias, expected_route, confirmed_route, archive_latched,
        archive_policy_revision, archive_observed_at, archived,
        selector_evidence_at, expected_scale_set, confirmed_scale_set,
        expected_legacy_label, confirmed_legacy_label, open_queue_risk
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(alias) DO UPDATE SET
        expected_route = excluded.expected_route,
        confirmed_route = excluded.confirmed_route,
        archive_latched = excluded.archive_latched,
        archive_policy_revision = excluded.archive_policy_revision,
        archive_observed_at = excluded.archive_observed_at,
        archived = excluded.archived,
        selector_evidence_at = excluded.selector_evidence_at,
        expected_scale_set = excluded.expected_scale_set,
        confirmed_scale_set = excluded.confirmed_scale_set,
        expected_legacy_label = excluded.expected_legacy_label,
        confirmed_legacy_label = excluded.confirmed_legacy_label,
        open_queue_risk = excluded.open_queue_risk`,
      repository.alias,
      repository.expectedRoute,
      repository.confirmedRoute,
      encodeArchiveEligibility(repository.archiveEligibility),
      repository.archivePolicyRevision,
      repository.archiveObservedAt,
      repository.archived ? 1 : 0,
      repository.selectorEvidenceAt,
      repository.expectedScaleSet ?? null,
      repository.confirmedScaleSet ?? null,
      repository.expectedLegacyLabel ?? null,
      repository.confirmedLegacyLabel ?? null,
      repository.openQueueRisk === null
        ? null
        : encodeQueueRiskRecord(repository.openQueueRisk),
    );
  }
}

function persistDueWork(
  sql: FleetSql,
  store: MemoryFleetStore,
  now: string,
  guardedClaims: ReadonlyMap<string, string>,
): void {
  for (const work of store.dueWork) {
    assertDueWorkRecord(work);
    const existing = sql.all("SELECT * FROM due_work WHERE id = ?", work.id);
    if (existing.length > 1) {
      throw new Error("due-work id is duplicated");
    }
    const existingRow = existing[0];
    const persisted =
      existingRow === undefined ? undefined : readDueWork(existingRow);
    if (
      persisted !== undefined &&
      (persisted.kind !== work.kind ||
        !samePayload(persisted.payload, work.payload))
    ) {
      throw new Error("due-work identity diverged");
    }
    if (persisted?.status === "claimed") {
      const existingClaimId = persisted.claimId;
      const existingExpiry = persisted.claimExpiresAt;
      const sameClaim =
        work.status === "claimed" && work.claimId === existingClaimId;
      const expiredRecovery =
        existingExpiry !== null &&
        existingExpiry <= now &&
        ((isExternalEffectWork(persisted.kind) &&
          work.status === "uncertain") ||
          (!isExternalEffectWork(persisted.kind) &&
            (work.status === "ready" || work.status === "claimed")));
      if (
        !sameClaim &&
        !expiredRecovery &&
        guardedClaims.get(work.id) !== existingClaimId
      ) {
        throw new Error("due-work claim guard is required");
      }
    }
    if (work.status === "done") {
      const guardedClaim = guardedClaims.get(work.id);
      if (guardedClaim !== undefined) {
        sql.run(
          "DELETE FROM due_work WHERE id = ? AND claim_id = ?",
          work.id,
          guardedClaim,
        );
      } else {
        sql.run("DELETE FROM due_work WHERE id = ?", work.id);
      }
      if (
        sql.all("SELECT id FROM due_work WHERE id = ?", work.id).length !== 0
      ) {
        throw new Error("due-work completion delete failed");
      }
      continue;
    }
    sql.run(
      `INSERT INTO due_work (
        id, kind, due_at, claim_id, claim_expires_at, attempts, status, payload
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        kind = excluded.kind,
        due_at = excluded.due_at,
        claim_id = excluded.claim_id,
        claim_expires_at = excluded.claim_expires_at,
        attempts = excluded.attempts,
        status = excluded.status,
        payload = excluded.payload`,
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
}

function verifyExpectedClaims(
  sql: FleetSql,
  store: MemoryFleetStore,
  guards: readonly DueWorkClaimGuard[],
): ReadonlyMap<string, string> {
  const verified = new Map<string, string>();
  for (const guard of guards) {
    const inMemory = store.dueWork.find((row) => row.id === guard.id);
    if (
      guard.id === "" ||
      guard.claimId === "" ||
      verified.has(guard.id) ||
      inMemory === undefined ||
      inMemory.kind !== guard.kind ||
      !samePayload(inMemory.payload, guard.payload)
    ) {
      throw new Error("due-work claim diverged");
    }
    const rows = sql.all("SELECT * FROM due_work WHERE id = ?", guard.id);
    if (rows.length !== 1) {
      throw new Error("due-work claim diverged");
    }
    const row = rows[0];
    const persisted = row === undefined ? undefined : readDueWork(row);
    if (
      persisted === undefined ||
      persisted.status !== "claimed" ||
      persisted.claimId !== guard.claimId
    ) {
      throw new Error("due-work claim diverged");
    }
    if (
      persisted.kind !== guard.kind ||
      !samePayload(persisted.payload, guard.payload)
    ) {
      throw new Error("due-work claim diverged");
    }
    verified.set(guard.id, guard.claimId);
  }
  return verified;
}

function persistTransitions(sql: FleetSql, store: MemoryFleetStore): void {
  for (const transition of store.transitions) {
    const existing = sql.all(
      "SELECT from_state, to_state FROM transitions WHERE epoch = ?",
      transition.epoch,
    );
    if (existing.length > 1) {
      throw new Error("transition epoch is not unique");
    }
    const row = existing[0];
    if (row !== undefined) {
      if (
        asString(row.from_state) !== transition.from ||
        asString(row.to_state) !== transition.to
      ) {
        throw new Error("transition history diverged");
      }
      continue;
    }
    sql.run(
      "INSERT INTO transitions (epoch, from_state, to_state) VALUES (?, ?, ?)",
      transition.epoch,
      transition.from,
      transition.to,
    );
  }
}

function persistAudit(
  sql: FleetSql,
  desired: readonly string[],
  state: AuditPersistenceState,
): number | null {
  const existing = readAuditRows(sql);
  const lastExistingSequence = existing.at(-1)?.seq ?? null;
  if (lastExistingSequence !== state.lastSequence) {
    throw new Error("audit history diverged");
  }
  if (!hasAuditSuffix(existing, state.persistedEvents)) {
    throw new Error("audit history diverged");
  }
  if (
    !Number.isInteger(state.pendingEvents) ||
    state.pendingEvents < 0 ||
    state.pendingEvents > desired.length
  ) {
    throw new Error("audit pending state is invalid");
  }
  for (const event of desired.slice(desired.length - state.pendingEvents)) {
    sql.run("INSERT INTO audit_events (event) VALUES (?)", event);
  }

  const afterAppend = readAuditRows(sql);
  if (!hasAuditSuffix(afterAppend, desired)) {
    throw new Error("audit append read-back failed");
  }
  const excess = afterAppend.length - desired.length;
  if (excess > 0) {
    const cutoff = afterAppend[excess - 1];
    if (cutoff === undefined) {
      throw new Error("audit retention cutoff is unavailable");
    }
    sql.run("DELETE FROM audit_events WHERE seq <= ?", cutoff.seq);
  }
  const retained = readAuditRows(sql);
  if (
    retained.length !== desired.length ||
    !retained.every((row, index) => row.event === desired[index])
  ) {
    throw new Error("audit retention read-back failed");
  }
  return retained.at(-1)?.seq ?? null;
}

function readAuditRows(sql: FleetSql): Array<{ seq: number; event: string }> {
  return sql
    .all("SELECT seq, event FROM audit_events ORDER BY seq")
    .map((row) => ({ seq: asInt(row.seq), event: asString(row.event) }));
}

function hasAuditSuffix(
  rows: ReadonlyArray<{ event: string }>,
  desired: readonly string[],
): boolean {
  if (rows.length < desired.length) {
    return false;
  }
  const offset = rows.length - desired.length;
  return desired.every((event, index) => rows[offset + index]?.event === event);
}

function projectAudit(
  current: readonly string[],
  state: AuditPersistenceState,
  appended: readonly string[],
): { events: string[]; state: AuditPersistenceState } {
  const events = [...current];
  let pendingEvents = state.pendingEvents;
  for (const event of appended) {
    events.push(event);
    if (events.length > 256) {
      events.shift();
    }
    pendingEvents = Math.min(pendingEvents + 1, events.length);
  }
  return {
    events,
    state: {
      lastSequence: state.lastSequence,
      persistedEvents: [...state.persistedEvents],
      pendingEvents,
    },
  };
}

function readRepository(
  row: Record<string, unknown>,
  currentConfigurationRevision: number,
): RepositoryRecord {
  let openQueueRisk: RepositoryRecord["openQueueRisk"] = null;
  if (typeof row.open_queue_risk === "string" && row.open_queue_risk !== "") {
    try {
      openQueueRisk = decodeQueueRiskRecord(row.open_queue_risk);
    } catch {
      throw new Error("repository row is invalid");
    }
  } else if (row.open_queue_risk !== null) {
    throw new Error("repository row is invalid");
  }
  const archiveEligibility = decodeArchiveEligibility(row.archive_latched);
  const archiveObservedAt = restrictiveArchiveTimestamp(
    row.archive_observed_at,
  );
  const archived = restrictiveArchiveBoolean(row.archived);
  let archivePolicyRevision = restrictiveArchivePolicyRevision(
    row.archive_policy_revision,
  );
  if (archiveEligibility !== "active" && archivePolicyRevision === null) {
    archivePolicyRevision = currentConfigurationRevision;
  }
  const consistentEligibility =
    archiveEligibility === "active" && archivePolicyRevision !== null
      ? "archived-disabled"
      : archiveEligibility;
  return {
    alias: asString(row.alias),
    expectedRoute: asString(row.expected_route),
    confirmedRoute: asNullableString(row.confirmed_route),
    expectedScaleSet: restrictiveSelectorScalar(row.expected_scale_set),
    confirmedScaleSet: restrictiveSelectorScalar(row.confirmed_scale_set),
    expectedLegacyLabel: restrictiveSelectorScalar(row.expected_legacy_label),
    confirmedLegacyLabel: restrictiveSelectorScalar(row.confirmed_legacy_label),
    archiveEligibility: consistentEligibility,
    archivePolicyRevision:
      consistentEligibility === "active"
        ? null
        : (archivePolicyRevision ?? currentConfigurationRevision),
    archiveObservedAt,
    archived,
    selectorEvidenceAt: asNullableString(row.selector_evidence_at),
    openQueueRisk,
  };
}

function restrictiveSelectorScalar(value: unknown): string | null {
  return typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value)
    ? value
    : null;
}

function encodeArchiveEligibility(value: ArchiveEligibility): number {
  if (value === "active") {
    return 0;
  }
  if (value === "archived-disabled") {
    return 1;
  }
  if (value === "pending-reactivation") {
    return 2;
  }
  throw new Error("repository archive eligibility is invalid");
}

function decodeArchiveEligibility(value: unknown): ArchiveEligibility {
  const decoded = asSqlIntegerOrNull(value);
  if (decoded === 0) {
    return "active";
  }
  if (decoded === 1) {
    return "archived-disabled";
  }
  if (decoded === 2) {
    return "pending-reactivation";
  }
  return "archived-disabled";
}

function restrictiveArchiveBoolean(value: unknown): boolean {
  const decoded = asSqlIntegerOrNull(value);
  if (decoded === 0) {
    return false;
  }
  return true;
}

function restrictiveArchiveTimestamp(value: unknown): string | null {
  return typeof value === "string" && isRfc3339MsZ(value) ? value : null;
}

function restrictiveArchivePolicyRevision(value: unknown): number | null {
  const decoded = asSqlIntegerOrNull(value);
  return decoded !== null && Number.isSafeInteger(decoded) && decoded >= 0
    ? decoded
    : null;
}

function asSqlIntegerOrNull(value: unknown): number | null {
  if (typeof value === "bigint") {
    const decoded = Number(value);
    return Number.isSafeInteger(decoded) ? decoded : null;
  }
  return typeof value === "number" && Number.isSafeInteger(value)
    ? value
    : null;
}

function readDueWork(row: Record<string, unknown>): DueWorkRecord {
  const kind = asString(row.kind);
  const status = asString(row.status);
  if (!isDueKind(kind) || !isDueStatus(status)) {
    throw new Error("due-work row is invalid");
  }
  const record: DueWorkRecord = {
    id: asString(row.id),
    kind,
    dueAt: asString(row.due_at),
    claimId: asNullableString(row.claim_id),
    claimExpiresAt: asNullableString(row.claim_expires_at),
    attempts: asInt(row.attempts),
    status,
    payload: parseDuePayload(row.payload),
  };
  try {
    assertDueWorkRecord(record);
  } catch {
    throw new Error("due-work row is invalid");
  }
  return record;
}

function parseDuePayload(value: unknown): Record<string, string> {
  if (typeof value !== "string" || value === "") {
    throw new Error("due-work row is invalid");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("due-work row is invalid");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    !Object.values(parsed).every((item) => typeof item === "string")
  ) {
    throw new Error("due-work row is invalid");
  }
  return parsed as Record<string, string>;
}

function samePayload(
  left: Readonly<Record<string, string>>,
  right: Readonly<Record<string, string>>,
): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) => key === rightKeys[index] && left[key] === right[key],
    )
  );
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

function asNonNegativeSafeInt(value: unknown): number {
  const number = asInt(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new Error("sql integer column is invalid");
  }
  return number;
}
