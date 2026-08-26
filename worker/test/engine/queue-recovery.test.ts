import { expect, test } from "vitest";

import {
  handleAdminCommand,
  type AdminCommandInput,
  type AdminSecrets,
} from "../../src/engine/admin";
import { executeDueWork, type GitHubClient } from "../../src/github/outbox";
import {
  ADMIN_COMMAND_PATH,
  hexToBytes,
  signCanonical,
  verifyCanonical,
} from "../../src/protocol/auth";
import type {
  QueueRecoveryCommandV1,
  QueueRecoveryExpectation,
} from "../../src/protocol/admin";
import { canonicalize } from "../../src/protocol/canonical";
import { MAX_DUE_WORK, MemoryFleetStore } from "../../src/state/memory";

const hmacKey = hexToBytes("0b".repeat(32));
const riskDigest = "a".repeat(64);
const recoveryDigest = "d".repeat(64);
const sourceHead = "0123456789abcdef0123456789abcdef01234567";
const timestamp = "2026-01-01T00:00:10.000Z";
const secrets: AdminSecrets = {
  hmacKey,
  timestampWindowMs: 5_000,
  nonceTtlMs: 60_000,
};

function makeStore(now: () => string = () => timestamp): MemoryFleetStore {
  const store = new MemoryFleetStore("example-fleet", { now });
  store.fleet.routingState = "HOSTED";
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "hosted",
    confirmedRoute: "hosted",
    archiveEligibility: "active",
    archivePolicyRevision: null,
    archiveObservedAt: timestamp,
    archived: false,
    selectorEvidenceAt: timestamp,
    openQueueRisk: {
      transitionEpoch: 7,
      sourceHead: "unknown",
      evidenceDigest: riskDigest,
      reason: "pre-transition-queue-may-remain",
    },
  });
  return store;
}

function command(nonce = "b".repeat(64)): QueueRecoveryCommandV1 {
  return {
    protocolVersion: 1,
    kind: "queue-recovery",
    fleetId: "example-fleet",
    timestamp,
    nonce,
    repositoryAlias: "repo-a",
    transitionEpoch: 7,
    riskEvidenceDigest: riskDigest,
    sourceHead,
    recoveryEvidenceDigest: recoveryDigest,
  };
}

async function inputFor(
  value: QueueRecoveryCommandV1,
): Promise<AdminCommandInput> {
  const body = canonicalize(value);
  return {
    method: "POST",
    path: ADMIN_COMMAND_PATH,
    timestamp: value.timestamp,
    macHex: await signCanonical(
      hmacKey,
      "POST",
      ADMIN_COMMAND_PATH,
      value.timestamp,
      body,
    ),
    body,
    inventoried: true,
  };
}

function observation(
  expectation: QueueRecoveryExpectation,
  status: "pending" | "verified",
): string {
  return canonicalize({
    schemaVersion: 1,
    status,
    fleetId: expectation.fleetId,
    repositoryAlias: expectation.repositoryAlias,
    transitionEpoch: expectation.transitionEpoch,
    riskEvidenceDigest: expectation.riskEvidenceDigest,
    sourceHead: expectation.sourceHead,
    recoveryEvidenceDigest: expectation.recoveryEvidenceDigest,
    verifiedAt: status === "pending" ? null : "2026-01-01T00:00:20.000Z",
  });
}

function client(
  observeQueueRecovery: GitHubClient["observeQueueRecovery"],
): GitHubClient {
  return {
    mutateVariable: async () => ({ status: 500 }),
    readVariable: async () => ({ status: 500 }),
    observeCanary: async () => ({ status: 500 }),
    observeQueueRecovery,
  };
}

test("authenticated queue recovery persists nonce and one read-only attestation", async () => {
  let current = timestamp;
  const store = makeStore(() => current);
  const first = await handleAdminCommand(
    store,
    secrets,
    await inputFor(command()),
  );
  expect(first.status).toBe(200);
  await verifyCanonical(
    hmacKey,
    "POST",
    ADMIN_COMMAND_PATH,
    first.timestamp,
    first.body,
    first.macHex,
  );
  expect(first.body).toContain('"status":"queued"');
  expect(store.nonces.has("b".repeat(64))).toBe(true);
  expect(store.repositories.get("repo-a")?.openQueueRisk).not.toBeNull();
  expect(
    store.dueWork.filter((row) => row.kind === "github-attestation"),
  ).toHaveLength(1);

  const replay = await handleAdminCommand(
    store,
    secrets,
    await inputFor(command()),
  );
  expect(replay.status).toBe(401);
  current = "2026-01-01T00:00:12.000Z";
  const duplicate = await handleAdminCommand(
    store,
    secrets,
    await inputFor(command("c".repeat(64))),
  );
  expect(duplicate.status).toBe(200);
  expect(
    store.dueWork.filter((row) => row.kind === "github-attestation"),
  ).toHaveLength(1);
});

test("ambiguous read-only recovery exhausts after five persisted attempts", async () => {
  let current = timestamp;
  const store = makeStore(() => current);
  await handleAdminCommand(store, secrets, await inputFor(command()));
  let calls = 0;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    current = `2026-01-01T00:00:${String(10 + attempt).padStart(2, "0")}.000Z`;
    await executeDueWork(
      store,
      client(async () => {
        calls += 1;
        return { status: 0 };
      }),
      store.claimReady(current, 8, 5_000),
    );
  }

  expect(calls).toBe(5);
  expect(store.dueWork[0]?.attempts).toBe(5);
  expect(store.dueWork[0]?.status).toBe("failed");
  expect(store.repositories.get("repo-a")?.openQueueRisk).not.toBeNull();
});

test("stale or unauthenticated recovery cannot consume nonce or enqueue work", async () => {
  const cases: Array<[string, (value: QueueRecoveryCommandV1) => void]> = [
    ["epoch", (value) => void (value.transitionEpoch = 8)],
    [
      "risk digest",
      (value) => void (value.riskEvidenceDigest = "f".repeat(64)),
    ],
    ["alias", (value) => void (value.repositoryAlias = "repo-b")],
  ];
  for (const [name, mutate] of cases) {
    const store = makeStore();
    const value = command();
    mutate(value);
    const result = await handleAdminCommand(
      store,
      secrets,
      await inputFor(value),
    );
    expect(result.status, name).toBe(401);
    expect(store.nonces.size, name).toBe(0);
    expect(store.dueWork, name).toHaveLength(0);
    expect(
      store.repositories.get("repo-a")?.openQueueRisk,
      name,
    ).not.toBeNull();
  }

  const store = makeStore();
  const invalidMac = await inputFor(command());
  invalidMac.macHex = "0".repeat(64);
  const rejected = await handleAdminCommand(store, secrets, invalidMac);
  expect(rejected.status).toBe(401);
  expect(store.nonces.size).toBe(0);
  expect(store.dueWork).toHaveLength(0);
});

test("only exact current GitHub verification clears one repository risk", async () => {
  let current = timestamp;
  const store = makeStore(() => current);
  await handleAdminCommand(store, secrets, await inputFor(command()));
  let observed: QueueRecoveryExpectation | undefined;
  await executeDueWork(
    store,
    client(async (expectation) => {
      observed = expectation;
      return { status: 200, body: observation(expectation, "pending") };
    }),
    store.claimReady(current, 8, 5_000),
  );
  expect(observed).toEqual(
    expect.objectContaining({
      repositoryAlias: "repo-a",
      transitionEpoch: 7,
      riskEvidenceDigest: riskDigest,
      sourceHead,
      recoveryEvidenceDigest: recoveryDigest,
    }),
  );
  expect(store.repositories.get("repo-a")?.openQueueRisk).not.toBeNull();
  expect(store.dueWork[0]?.status).toBe("ready");

  current = "2026-01-01T00:00:21.000Z";
  await executeDueWork(
    store,
    client(async (expectation) => ({
      status: 200,
      body: observation(expectation, "verified"),
    })),
    store.claimReady(current, 8, 5_000),
  );
  expect(store.repositories.get("repo-a")?.openQueueRisk).toBeNull();
  expect(store.dueWork[0]?.status).toBe("done");
  expect(store.audit).toContain("queue-risk-cleared:repo-a:7");
});

test("late and superseded queue verification leave risk safely open", async () => {
  let current = timestamp;
  const late = makeStore(() => current);
  await handleAdminCommand(late, secrets, await inputFor(command()));
  current = "2026-01-01T00:01:10.000Z";
  await executeDueWork(
    late,
    client(async (expectation) => ({
      status: 200,
      body: observation(expectation, "pending"),
    })),
    late.claimReady(current, 8, 5_000),
  );
  expect(late.repositories.get("repo-a")?.openQueueRisk).not.toBeNull();
  expect(late.dueWork[0]?.status).toBe("failed");

  const superseded = makeStore();
  await handleAdminCommand(superseded, secrets, await inputFor(command()));
  await executeDueWork(
    superseded,
    client(async (expectation) => {
      superseded.repositories.get("repo-a")!.openQueueRisk = {
        transitionEpoch: 8,
        sourceHead: "unknown",
        evidenceDigest: "e".repeat(64),
        reason: "pre-transition-queue-may-remain",
      };
      return { status: 200, body: observation(expectation, "verified") };
    }),
    superseded.claimReady(timestamp, 8, 5_000),
  );
  expect(
    superseded.repositories.get("repo-a")?.openQueueRisk?.transitionEpoch,
  ).toBe(8);
  expect(superseded.dueWork[0]?.status).toBe("failed");
});

test("queue exhaustion returns no false queued or cleared result", async () => {
  const store = makeStore();
  for (let index = 0; index < MAX_DUE_WORK; index += 1) {
    store.enqueue({
      id: `readback-${index}`,
      kind: "github-readback",
      dueAt: timestamp,
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: `mutation-${index}` },
    });
  }
  const result = await handleAdminCommand(
    store,
    secrets,
    await inputFor(command()),
  );
  expect(result.status).toBe(401);
  expect(store.nonces.size).toBe(0);
  expect(store.repositories.get("repo-a")?.openQueueRisk).not.toBeNull();
  expect(store.dueWork).toHaveLength(MAX_DUE_WORK);
});
