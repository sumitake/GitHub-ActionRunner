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
} from "../../src/protocol/auth";
import type { ArchiveReactivationCommandV1 } from "../../src/protocol/admin";
import { canonicalize } from "../../src/protocol/canonical";
import type { ArchiveExpectation } from "../../src/routing/archive";
import {
  MAX_NON_ROUTE_DUE_WORK,
  MemoryFleetStore,
} from "../../src/state/memory";

const timestamp = "2026-01-01T00:00:10.000Z";
const observeUntil = "2026-01-01T00:01:10.000Z";
const hmacKey = hexToBytes("0b".repeat(32));
const secrets: AdminSecrets = {
  hmacKey,
  timestampWindowMs: 5_000,
  nonceTtlMs: 60_000,
  archiveEvidenceMaxAgeMs: 60_000,
};

function makeStore(now: () => string = () => timestamp): MemoryFleetStore {
  const store = new MemoryFleetStore("example-fleet", { now });
  store.fleet.routingState = "HOSTED";
  store.fleet.configRevision = 8;
  store.fleet.leaseGeneration = 11;
  store.transitions.push({ epoch: 3, from: "UNINITIALIZED", to: "HOSTED" });
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "hosted",
    confirmedRoute: "hosted",
    archiveEligibility: "archived-disabled",
    archivePolicyRevision: 7,
    archiveObservedAt: "2026-01-01T00:00:09.000Z",
    archived: false,
    selectorEvidenceAt: timestamp,
    openQueueRisk: null,
  });
  return store;
}

function command(
  overrides: Partial<ArchiveReactivationCommandV1> = {},
): ArchiveReactivationCommandV1 {
  return {
    protocolVersion: 1,
    kind: "archive-reactivation",
    fleetId: "example-fleet",
    timestamp,
    nonce: "f".repeat(64),
    repositoryAlias: "repo-a",
    configurationRevision: 8,
    transitionEpoch: 3,
    leaseGeneration: 11,
    workflowAuditDigest: "a".repeat(64),
    securityAuditDigest: "b".repeat(64),
    hostedBootstrapDigest: "c".repeat(64),
    queueClearanceDigest: "d".repeat(64),
    canaryEvidenceDigest: "e".repeat(64),
    observeUntil,
    ...overrides,
  };
}

async function inputFor(
  value: ArchiveReactivationCommandV1,
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
  expectation: ArchiveExpectation,
  verifiedAt = timestamp,
): string {
  if (expectation.kind !== "archive-reactivation") {
    throw new Error("expected reactivation");
  }
  return canonicalize({
    ...expectation,
    status: "verified",
    archived: false,
    verifiedAt,
  });
}

function client(
  observeArchive: NonNullable<GitHubClient["observeArchive"]>,
): GitHubClient {
  return {
    mutateVariable: async () => ({ status: 500 }),
    readVariable: async () => ({ status: 500 }),
    observeCanary: async () => ({ status: 500 }),
    observeQueueRecovery: async () => ({ status: 500 }),
    observeArchive,
  };
}

test("one authenticated command stages pending then exact evidence activates", async () => {
  const store = makeStore();
  const accepted = await handleAdminCommand(
    store,
    secrets,
    await inputFor(command()),
  );
  expect(accepted.status).toBe(200);
  expect(accepted.body).toContain('"status":"pending-reactivation"');
  expect(store.repositories.get("repo-a")?.archiveEligibility).toBe(
    "pending-reactivation",
  );
  expect(store.nonces.has("f".repeat(64))).toBe(true);
  expect(store.dueWork).toHaveLength(1);
  expect(store.dueWork[0]?.kind).toBe("archive-observe");

  await executeDueWork(
    store,
    client(async (expectation) => ({
      status: 200,
      body: observation(expectation),
    })),
    store.claimReady(timestamp, 8, 5_000),
    undefined,
    {
      hostedTransitionSafetyMarginMs: 1_000,
      archiveEvidenceMaxAgeMs: 60_000,
    },
  );
  expect(store.repositories.get("repo-a")?.archiveEligibility).toBe("active");
  expect(store.repositories.get("repo-a")?.archivePolicyRevision).toBeNull();
  expect(store.repositories.get("repo-a")?.archiveObservedAt).toBe(timestamp);
  expect(store.dueWork[0]?.status).toBe("done");
});

test("reactivation gates reject without partial state", async () => {
  const cases: Array<
    [
      string,
      (store: MemoryFleetStore) => void,
      Partial<ArchiveReactivationCommandV1>?,
    ]
  > = [
    ["revision-not-advanced", () => undefined, { configurationRevision: 7 }],
    [
      "live-archived",
      (store) => {
        store.repositories.get("repo-a")!.archived = true;
      },
    ],
    [
      "not-hosted",
      (store) => {
        store.fleet.routingState = "PORTABLE";
      },
    ],
    [
      "queue-risk",
      (store) => {
        store.repositories.get("repo-a")!.openQueueRisk = {
          transitionEpoch: 3,
          sourceHead: "unknown",
          evidenceDigest: "1".repeat(64),
          reason: "pre-transition-queue-may-remain",
        };
      },
    ],
    [
      "missing-transition",
      (store) => {
        store.transitions.length = 0;
      },
    ],
  ];
  for (const [name, mutate, overrides] of cases) {
    const store = makeStore();
    mutate(store);
    const result = await handleAdminCommand(
      store,
      secrets,
      await inputFor(command(overrides)),
    );
    expect(result.status, name).toBe(401);
    expect(store.repositories.get("repo-a")?.archiveEligibility, name).toBe(
      "archived-disabled",
    );
    expect(store.dueWork, name).toHaveLength(0);
    expect(store.nonces.size, name).toBe(0);
  }
});

test("due-work saturation rejects before pending or nonce mutation", async () => {
  const store = makeStore();
  for (let index = 0; index < MAX_NON_ROUTE_DUE_WORK; index += 1) {
    store.enqueue({
      id: `notify-${index}`,
      kind: "notify-email",
      dueAt: timestamp,
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { eventId: `event-${index}` },
    });
  }
  const result = await handleAdminCommand(
    store,
    secrets,
    await inputFor(command()),
  );
  expect(result.status).toBe(401);
  expect(store.repositories.get("repo-a")?.archiveEligibility).toBe(
    "archived-disabled",
  );
  expect(store.nonces.size).toBe(0);
  expect(store.dueWork).toHaveLength(MAX_NON_ROUTE_DUE_WORK);
});

test("nonce staging failure leaves no queued or pending state", async () => {
  const store = makeStore();
  store.rememberNonce = () => false;

  const result = await handleAdminCommand(
    store,
    secrets,
    await inputFor(command()),
  );

  expect(result.status).toBe(401);
  expect(store.repositories.get("repo-a")?.archiveEligibility).toBe(
    "archived-disabled",
  );
  expect(store.dueWork).toHaveLength(0);
  expect(store.nonces.size).toBe(0);
});

test("post-await archive supersession cannot activate", async () => {
  const store = makeStore();
  await handleAdminCommand(store, secrets, await inputFor(command()));
  const repository = store.repositories.get("repo-a")!;
  await executeDueWork(
    store,
    client(async (expectation) => {
      repository.archived = true;
      repository.archiveEligibility = "archived-disabled";
      return { status: 200, body: observation(expectation) };
    }),
    store.claimReady(timestamp, 8, 5_000),
    undefined,
    {
      hostedTransitionSafetyMarginMs: 1_000,
      archiveEvidenceMaxAgeMs: 60_000,
    },
  );
  expect(repository.archiveEligibility).toBe("archived-disabled");
  expect(store.dueWork[0]?.status).toBe("failed");
});

test("a result received at the exact deadline cannot activate", async () => {
  let now = timestamp;
  const store = makeStore(() => now);
  await handleAdminCommand(store, secrets, await inputFor(command()));
  const repository = store.repositories.get("repo-a")!;
  await executeDueWork(
    store,
    client(async (expectation) => {
      now = observeUntil;
      return { status: 200, body: observation(expectation) };
    }),
    store.claimReady(timestamp, 8, 5_000),
    undefined,
    {
      hostedTransitionSafetyMarginMs: 1_000,
      archiveEvidenceMaxAgeMs: 60_000,
    },
  );
  expect(repository.archiveEligibility).toBe("pending-reactivation");
  expect(store.dueWork[0]?.status).toBe("failed");
  expect(store.audit).toContain(
    `archive-observation-exhausted:${store.dueWork[0]?.id}`,
  );
});

test("fresh returned evidence can replace evidence that aged during the call", async () => {
  let now = timestamp;
  const store = makeStore(() => now);
  await handleAdminCommand(
    store,
    { ...secrets, archiveEvidenceMaxAgeMs: 5_000 },
    await inputFor(command()),
  );
  const repository = store.repositories.get("repo-a")!;
  await executeDueWork(
    store,
    client(async (expectation) => {
      now = "2026-01-01T00:00:15.000Z";
      return { status: 200, body: observation(expectation, now) };
    }),
    store.claimReady(timestamp, 8, 5_000),
    undefined,
    {
      hostedTransitionSafetyMarginMs: 1_000,
      archiveEvidenceMaxAgeMs: 5_000,
    },
  );
  expect(repository.archiveEligibility).toBe("active");
  expect(repository.archiveObservedAt).toBe(now);
  expect(store.dueWork[0]?.status).toBe("done");
});

test("verification predating the operator command cannot activate", async () => {
  const store = makeStore();
  await handleAdminCommand(store, secrets, await inputFor(command()));
  const repository = store.repositories.get("repo-a")!;
  await executeDueWork(
    store,
    client(async (expectation) => ({
      status: 200,
      body: observation(expectation, "2026-01-01T00:00:09.999Z"),
    })),
    store.claimReady(timestamp, 8, 5_000),
    undefined,
    {
      hostedTransitionSafetyMarginMs: 1_000,
      archiveEvidenceMaxAgeMs: 60_000,
    },
  );
  expect(repository.archiveEligibility).toBe("pending-reactivation");
  expect(store.dueWork[0]?.status).toBe("failed");
});

test("new nonce is idempotent while the exact reactivation is pending", async () => {
  const store = makeStore();
  expect(
    (await handleAdminCommand(store, secrets, await inputFor(command())))
      .status,
  ).toBe(200);
  expect(
    (
      await handleAdminCommand(
        store,
        secrets,
        await inputFor(command({ nonce: "9".repeat(64) })),
      )
    ).status,
  ).toBe(200);
  expect(store.dueWork).toHaveLength(1);
  expect(store.nonces.size).toBe(2);
});
