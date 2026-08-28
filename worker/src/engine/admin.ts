import {
  ADMIN_COMMAND_PATH,
  assertTimestampWindow,
  signCanonical,
  verifyCanonical,
} from "../protocol/auth";
import {
  encodeQueueRecoveryExpectation,
  parseAdminCommand,
  type AdminCommandV1,
  type ArchiveReactivationCommandV1,
  type LegacyRollbackCommandV1,
  type QueueRecoveryExpectation,
} from "../protocol/admin";
import { canonicalize } from "../protocol/canonical";
import {
  archiveEvidenceState,
  encodeArchiveExpectation,
  type ArchiveReactivationExpectation,
} from "../routing/archive";
import { persistCanary } from "../github/outbox";
import { selectorRestrictionReason } from "../routing/selector";
import {
  isGitHubMutation,
  type DueWorkRecord,
  type MemoryFleetStore,
} from "../state/memory";

const QUEUE_RECOVERY_WINDOW_MS = 60_000;
const ARCHIVE_REACTIVATION_WINDOW_MS = 60_000;

export type AdminSecrets = {
  hmacKey: Uint8Array;
  timestampWindowMs: number;
  nonceTtlMs: number;
  archiveEvidenceMaxAgeMs?: number;
  selectorEvidenceMaxAgeMs?: number;
};

export type AdminCommandInput = {
  method: string;
  path: string;
  timestamp: string;
  macHex: string;
  body: string;
  inventoried: boolean;
};

export async function handleAdminCommand(
  store: MemoryFleetStore,
  secrets: AdminSecrets,
  input: AdminCommandInput,
): Promise<{
  status: number;
  body: string;
  timestamp: string;
  macHex: string;
}> {
  const receiptTime = store.now();
  const respond = async (status: number, body: string) => ({
    status,
    body,
    timestamp: receiptTime,
    macHex: await signCanonical(
      secrets.hmacKey,
      "POST",
      input.path,
      receiptTime,
      body,
    ),
  });
  const reject = () => respond(401, canonicalize({ error: "rejected" }));
  if (
    !input.inventoried ||
    input.method !== "POST" ||
    input.path !== ADMIN_COMMAND_PATH
  ) {
    return reject();
  }

  let command: AdminCommandV1;
  try {
    await verifyCanonical(
      secrets.hmacKey,
      input.method,
      input.path,
      input.timestamp,
      input.body,
      input.macHex,
    );
    command = parseAdminCommand(input.body);
    if (
      command.fleetId !== store.fleet.fleetId ||
      command.timestamp !== input.timestamp
    ) {
      throw new Error("admin command binding is invalid");
    }
    assertTimestampWindow(
      receiptTime,
      command.timestamp,
      secrets.timestampWindowMs,
    );
  } catch {
    return reject();
  }

  store.expireNonces(receiptTime);
  if (store.nonces.has(command.nonce)) {
    return reject();
  }
  if (command.kind === "archive-reactivation") {
    return handleArchiveReactivation(
      store,
      secrets,
      command,
      receiptTime,
      respond,
      reject,
    );
  }
  if (command.kind === "legacy-rollback") {
    return handleLegacyRollback(
      store,
      secrets,
      command,
      receiptTime,
      respond,
      reject,
    );
  }
  const repository = store.repositories.get(command.repositoryAlias);
  const risk = repository?.openQueueRisk;
  if (
    repository === undefined ||
    risk === undefined ||
    risk === null ||
    store.fleet.routingState !== "HOSTED" ||
    risk.transitionEpoch !== command.transitionEpoch ||
    risk.evidenceDigest !== command.riskEvidenceDigest ||
    (risk.sourceHead !== "unknown" && risk.sourceHead !== command.sourceHead)
  ) {
    return reject();
  }

  let expiresAt: string;
  let expectation: QueueRecoveryExpectation;
  let work: DueWorkRecord;
  try {
    expiresAt = addMs(receiptTime, secrets.nonceTtlMs);
    expectation = {
      schemaVersion: 1,
      fleetId: command.fleetId,
      repositoryAlias: command.repositoryAlias,
      transitionEpoch: command.transitionEpoch,
      riskEvidenceDigest: command.riskEvidenceDigest,
      sourceHead: command.sourceHead,
      recoveryEvidenceDigest: command.recoveryEvidenceDigest,
      observeUntil: addMs(command.timestamp, QUEUE_RECOVERY_WINDOW_MS),
    };
    work = {
      id: `queue-recovery-${command.repositoryAlias}-${command.transitionEpoch}`,
      kind: "github-attestation",
      dueAt: receiptTime,
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: encodeQueueRecoveryExpectation(expectation),
    };
  } catch {
    return reject();
  }

  const existing = store.dueWork.find((row) => row.id === work.id);
  if (existing === undefined) {
    try {
      store.enqueue(work);
    } catch {
      return reject();
    }
  } else if (
    existing.kind !== work.kind ||
    (existing.status !== "ready" && existing.status !== "claimed") ||
    !samePayload(existing.payload, work.payload)
  ) {
    return reject();
  }
  if (!store.rememberNonce(command.nonce, expiresAt)) {
    return reject();
  }
  store.recordAudit(
    `queue-recovery-queued:${command.repositoryAlias}:${command.transitionEpoch}`,
  );
  return respond(
    200,
    canonicalize({
      protocolVersion: 1,
      kind: "queue-recovery",
      fleetId: command.fleetId,
      nonce: command.nonce,
      repositoryAlias: command.repositoryAlias,
      transitionEpoch: command.transitionEpoch,
      status: "queued",
      receiptTime,
    }),
  );
}

async function handleLegacyRollback(
  store: MemoryFleetStore,
  secrets: AdminSecrets,
  command: LegacyRollbackCommandV1,
  receiptTime: string,
  respond: (
    status: number,
    body: string,
  ) => Promise<{
    status: number;
    body: string;
    timestamp: string;
    macHex: string;
  }>,
  reject: () => Promise<{
    status: number;
    body: string;
    timestamp: string;
    macHex: string;
  }>,
): Promise<{
  status: number;
  body: string;
  timestamp: string;
  macHex: string;
}> {
  const archiveEvidenceMaxAgeMs = secrets.archiveEvidenceMaxAgeMs;
  const selectorEvidenceMaxAgeMs = secrets.selectorEvidenceMaxAgeMs;
  const repositories = [...store.repositories.values()];
  const selected = store.repositories.get(command.repositoryAlias);
  const unresolved = store.dueWork.some(
    (row) =>
      (row.status === "ready" ||
        row.status === "claimed" ||
        row.status === "uncertain") &&
      (isGitHubMutation(row.kind) ||
        row.kind === "github-readback" ||
        row.kind === "canary-observe" ||
        row.kind === "canary-boundary"),
  );
  if (
    selected === undefined ||
    repositories.length === 0 ||
    store.fleet.routingState !== "HOSTED" ||
    store.fleet.hostedHold ||
    store.fleet.sessionId === null ||
    store.fleet.configRevision !== command.configurationRevision ||
    currentTransitionEpoch(store) !== command.transitionEpoch ||
    store.fleet.leaseGeneration !== command.leaseGeneration ||
    store.fleet.fenceGeneration < 1 ||
    store.fleet.fenceGeneration !== command.fenceGeneration ||
    archiveEvidenceMaxAgeMs === undefined ||
    selectorEvidenceMaxAgeMs === undefined ||
    unresolved ||
    repositories.some(
      (repository) =>
        repository.openQueueRisk !== null ||
        repository.archiveEligibility !== "active" ||
        repository.archived ||
        archiveEvidenceState(
          repository,
          receiptTime,
          archiveEvidenceMaxAgeMs,
        ) !== "fresh" ||
        repository.expectedRoute !== "hosted" ||
        selectorRestrictionReason(
          repository,
          receiptTime,
          selectorEvidenceMaxAgeMs,
        ) !== null ||
        repository.expectedLegacyLabel !== command.legacyLabel,
    ) ||
    command.observeUntil !== addMs(command.timestamp, 60_000)
  ) {
    return reject();
  }

  let expiresAt: string;
  let accepted: Awaited<ReturnType<typeof respond>>;
  try {
    expiresAt = addMs(receiptTime, secrets.nonceTtlMs);
    accepted = await respond(
      200,
      canonicalize({
        protocolVersion: 1,
        kind: command.kind,
        fleetId: command.fleetId,
        nonce: command.nonce,
        repositoryAlias: command.repositoryAlias,
        transitionEpoch: command.transitionEpoch,
        status: "legacy-canary",
        receiptTime,
      }),
    );
  } catch {
    return reject();
  }
  if (!store.rememberNonce(command.nonce, expiresAt)) {
    return reject();
  }

  const previous = {
    canaryScaleSet: store.fleet.canaryScaleSet,
    canaryEvidence: store.fleet.canaryEvidence,
    routingState: store.fleet.routingState,
    dueWork: store.dueWork.length,
    transitions: store.transitions.length,
    audit: store.audit.length,
  };
  try {
    store.fleet.canaryScaleSet = command.legacyLabel;
    persistCanary(store, receiptTime, "LEGACY_CANARY", {
      repositoryAlias: command.repositoryAlias,
      workflow: command.workflow,
      revision: command.revision,
      observeUntil: command.observeUntil,
    });
  } catch {
    store.nonces.delete(command.nonce);
    store.fleet.canaryScaleSet = previous.canaryScaleSet;
    store.fleet.canaryEvidence = previous.canaryEvidence;
    store.fleet.routingState = previous.routingState;
    store.dueWork.splice(previous.dueWork);
    store.transitions.splice(previous.transitions);
    store.audit.splice(previous.audit);
    return reject();
  }
  store.recordAudit(
    `legacy-rollback-canary:${command.repositoryAlias}:${command.transitionEpoch}`,
  );
  return accepted;
}

async function handleArchiveReactivation(
  store: MemoryFleetStore,
  secrets: AdminSecrets,
  command: ArchiveReactivationCommandV1,
  receiptTime: string,
  respond: (
    status: number,
    body: string,
  ) => Promise<{
    status: number;
    body: string;
    timestamp: string;
    macHex: string;
  }>,
  reject: () => Promise<{
    status: number;
    body: string;
    timestamp: string;
    macHex: string;
  }>,
): Promise<{
  status: number;
  body: string;
  timestamp: string;
  macHex: string;
}> {
  const repository = store.repositories.get(command.repositoryAlias);
  const archiveEvidenceMaxAgeMs = secrets.archiveEvidenceMaxAgeMs;
  if (
    repository === undefined ||
    (repository.archiveEligibility !== "archived-disabled" &&
      repository.archiveEligibility !== "pending-reactivation") ||
    repository.archivePolicyRevision === null ||
    store.fleet.routingState !== "HOSTED" ||
    store.fleet.configRevision !== command.configurationRevision ||
    command.configurationRevision <= repository.archivePolicyRevision ||
    store.fleet.leaseGeneration !== command.leaseGeneration ||
    currentTransitionEpoch(store) !== command.transitionEpoch ||
    repository.openQueueRisk !== null ||
    archiveEvidenceMaxAgeMs === undefined ||
    archiveEvidenceState(repository, receiptTime, archiveEvidenceMaxAgeMs) !==
      "fresh" ||
    command.observeUntil !==
      addMs(command.timestamp, ARCHIVE_REACTIVATION_WINDOW_MS)
  ) {
    return reject();
  }

  let expectation: ArchiveReactivationExpectation;
  let work: DueWorkRecord;
  let expiresAt: string;
  let accepted: Awaited<ReturnType<typeof respond>>;
  try {
    expectation = {
      schemaVersion: 1,
      kind: "archive-reactivation",
      fleetId: command.fleetId,
      repositoryAlias: command.repositoryAlias,
      configurationRevision: command.configurationRevision,
      transitionEpoch: command.transitionEpoch,
      leaseGeneration: command.leaseGeneration,
      startedAt: command.timestamp,
      workflowAuditDigest: command.workflowAuditDigest,
      securityAuditDigest: command.securityAuditDigest,
      hostedBootstrapDigest: command.hostedBootstrapDigest,
      queueClearanceDigest: command.queueClearanceDigest,
      canaryEvidenceDigest: command.canaryEvidenceDigest,
      observeUntil: command.observeUntil,
    };
    work = {
      id: `archive-reactivation-${command.repositoryAlias}-${command.configurationRevision}-${command.transitionEpoch}-${command.leaseGeneration}`,
      kind: "archive-observe",
      dueAt: receiptTime,
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: encodeArchiveExpectation(expectation),
    };
    expiresAt = addMs(receiptTime, secrets.nonceTtlMs);
    accepted = await respond(
      200,
      canonicalize({
        protocolVersion: 1,
        kind: command.kind,
        fleetId: command.fleetId,
        nonce: command.nonce,
        repositoryAlias: command.repositoryAlias,
        configurationRevision: command.configurationRevision,
        status: "pending-reactivation",
        receiptTime,
      }),
    );
  } catch {
    return reject();
  }

  const existing = store.dueWork.find((row) => row.id === work.id);
  if (
    existing !== undefined &&
    (existing.kind !== work.kind ||
      (existing.status !== "ready" && existing.status !== "claimed") ||
      !samePayload(existing.payload, work.payload))
  ) {
    return reject();
  }
  if (!store.rememberNonce(command.nonce, expiresAt)) {
    return reject();
  }
  if (existing === undefined) {
    try {
      store.enqueue(work);
    } catch {
      store.nonces.delete(command.nonce);
      return reject();
    }
  }
  repository.archiveEligibility = "pending-reactivation";
  store.recordAudit(
    `archive-reactivation-pending:${command.repositoryAlias}:policy-${command.configurationRevision}`,
  );
  return accepted;
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

function addMs(timestamp: string, deltaMs: number): string {
  if (!Number.isSafeInteger(deltaMs) || deltaMs <= 0) {
    throw new Error("queue-recovery duration is invalid");
  }
  const next = Date.parse(timestamp) + deltaMs;
  if (!Number.isFinite(next)) {
    throw new Error("queue-recovery timestamp is invalid");
  }
  return new Date(next).toISOString().replace(/\.(\d{3})\d*Z$/, ".$1Z");
}

function currentTransitionEpoch(store: MemoryFleetStore): number | null {
  const epoch = store.transitions.at(-1)?.epoch;
  if (epoch === undefined || !Number.isSafeInteger(epoch) || epoch < 1) {
    return null;
  }
  return epoch;
}
