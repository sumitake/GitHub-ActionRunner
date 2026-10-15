import { expect, test } from "vitest";

import {
  handleAdminCommand,
  type AdminCommandInput,
  type AdminSecrets,
} from "../../src/engine/admin";
import { handleHeartbeat } from "../../src/engine/heartbeat";
import {
  ADMIN_COMMAND_PATH,
  hexToBytes,
  signCanonical,
} from "../../src/protocol/auth";
import { executeDueWork, type GitHubClient } from "../../src/github/outbox";
import { canonicalize } from "../../src/protocol/canonical";
import { MemoryFleetStore } from "../../src/state/memory";

const commandTime = "2026-01-01T00:00:10.000Z";
const observeUntil = "2026-01-01T01:00:10.000Z";
const revision = "0123456789abcdef0123456789abcdef01234567";
const session = "c".repeat(64);
const policyDigest = "a".repeat(64);
const hmacKey = hexToBytes("0b".repeat(32));
const leaseExpiry = "2026-01-01T00:03:00.000Z";

const adminSecrets: AdminSecrets = {
  hmacKey,
  timestampWindowMs: 5_000,
  nonceTtlMs: 60_000,
  archiveEvidenceMaxAgeMs: 60_000,
  selectorEvidenceMaxAgeMs: 60_000,
  hostedTransitionSafetyMarginMs: 1_000,
};

let nonceCounter = 0;

function nonce(): string {
  nonceCounter += 1;
  return nonceCounter.toString(16).padStart(64, "0");
}

function startCommand(overrides: Record<string, unknown> = {}) {
  return {
    protocolVersion: 1,
    kind: "portable-canary-start",
    fleetId: "example-fleet",
    timestamp: commandTime,
    nonce: nonce(),
    repositoryAlias: "repo-a",
    workflow: "portable-canary.yml",
    revision,
    scaleSet: "portable-canary",
    configurationRevision: 4,
    policyDigest,
    fenceGeneration: 5,
    leaseGeneration: 11,
    observeUntil,
    ...overrides,
  };
}

function stopCommand(timestamp: string) {
  return {
    protocolVersion: 1,
    kind: "portable-canary-stop",
    fleetId: "example-fleet",
    timestamp,
    nonce: nonce(),
  };
}

async function inputFor(
  value: Record<string, unknown>,
): Promise<AdminCommandInput> {
  const body = canonicalize(value);
  const timestamp = value.timestamp as string;
  return {
    method: "POST",
    path: ADMIN_COMMAND_PATH,
    timestamp,
    macHex: await signCanonical(
      hmacKey,
      "POST",
      ADMIN_COMMAND_PATH,
      timestamp,
      body,
    ),
    body,
    inventoried: true,
  };
}

function makeStore(clock: { now: string }): MemoryFleetStore {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => clock.now,
  });
  store.fleet.inventoried = true;
  store.fleet.epoch = 1;
  store.fleet.sessionId = session;
  store.fleet.sequence = 4;
  store.fleet.leaseGeneration = 11;
  store.fleet.lastIssuedLeaseExpiryMax = leaseExpiry;
  return store;
}

async function admin(
  store: MemoryFleetStore,
  value: Record<string, unknown>,
  secrets: AdminSecrets = adminSecrets,
) {
  return handleAdminCommand(store, secrets, await inputFor(value));
}

async function heartbeat(
  store: MemoryFleetStore,
  timestamp: string,
  sequence: number,
  overrides: Record<string, unknown> = {},
  acquisitionMode = "canary-only",
) {
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 1,
    sessionId: session,
    sequence,
    holder: "portable",
    fenceGeneration: 5,
    timestamp,
    ...overrides,
    snapshot: {
      observedAt: timestamp,
      fleetAlias: "example-fleet",
      acquisitionMode,
      policyEpoch: 1,
      policyDigest,
      repositoryPolicyRevision: 4,
      capacity: {
        configured: 1,
        effective: 1,
        occupied: 0,
        available: 1,
        queued: 0,
      },
      assignedJobs: 0,
      runningJobs: 0,
      oldestLiveAssignmentAgeMs: 0,
      unassignedReleasedListeners: 0,
      lastTerminalAt: null,
      hostProfileId: "strict-linux-v1",
      degraded: false,
      buildId: policyDigest,
    },
  });
  const result = await handleHeartbeat(
    store,
    {
      hmacKey,
      timestampWindowMs: 5_000,
      leaseDurationMs: 8_000,
      archiveEvidenceMaxAgeMs: 60_000,
      selectorEvidenceMaxAgeMs: 60_000,
      hostedTransitionSafetyMarginMs: 1_000,
    },
    {
      method: "POST",
      path: "/v1/heartbeat",
      timestamp,
      macHex: await signCanonical(
        hmacKey,
        "POST",
        "/v1/heartbeat",
        timestamp,
        body,
      ),
      body,
      inventoried: true,
    },
  );
  return {
    status: result.status,
    body: JSON.parse(result.body) as {
      routingState: string;
      lease: {
        holder: string;
        mode: string;
        maxCapacity: number;
        canaryScaleSet: string | null;
      } | null;
      noLeaseReason: string | null;
    },
  };
}

test("start moves a hosted fleet with no repositories into a portable canary", async () => {
  const clock = { now: commandTime };
  const store = makeStore(clock);
  store.fleet.routingState = "HOSTED";
  store.transitions.push({ epoch: 1, from: "UNINITIALIZED", to: "HOSTED" });

  const result = await admin(store, startCommand());

  expect(result.status).toBe(200);
  expect(JSON.parse(result.body)).toMatchObject({
    kind: "portable-canary-start",
    scaleSet: "portable-canary",
    status: "portable-canary",
  });
  expect(store.fleet.routingState).toBe("PORTABLE_CANARY");
  expect(store.fleet.canaryScaleSet).toBe("portable-canary");
  expect(store.fleet.fenceGeneration).toBe(5);
  expect(store.fleet.policyDigest).toBe(policyDigest);
  expect(store.fleet.configRevision).toBe(4);
  expect(store.transitions.at(-1)).toMatchObject({
    from: "HOSTED",
    to: "PORTABLE_CANARY",
  });
  expect(store.audit.at(-1)).toBe("portable-canary-start:portable-canary");
});

test("start bootstraps an uninitialized fleet through HOSTED", async () => {
  const clock = { now: commandTime };
  const store = makeStore(clock);

  const result = await admin(store, startCommand());

  expect(result.status).toBe(200);
  expect(store.fleet.routingState).toBe("PORTABLE_CANARY");
  expect(store.transitions).toEqual([
    { epoch: 1, from: "UNINITIALIZED", to: "HOSTED" },
    { epoch: 2, from: "HOSTED", to: "PORTABLE_CANARY" },
  ]);
});

test("start is refused unless every precondition holds", async () => {
  const cases: Array<[string, (store: MemoryFleetStore) => void]> = [
    [
      "repository records exist",
      (store) =>
        store.putRepository({
          alias: "repo-a",
          expectedRoute: "hosted",
          confirmedRoute: "hosted",
          archiveEligibility: "active",
          archivePolicyRevision: null,
          archiveObservedAt: commandTime,
          archived: false,
          selectorEvidenceAt: commandTime,
          openQueueRisk: null,
          expectedScaleSet: "portable-canary",
          confirmedScaleSet: "portable-canary",
          expectedLegacyLabel: "legacy-runners",
          confirmedLegacyLabel: "legacy-runners",
        }),
    ],
    ["no session", (store) => (store.fleet.sessionId = null)],
    ["stale lease generation", (store) => (store.fleet.leaseGeneration = 12)],
    ["hosted hold", (store) => (store.fleet.hostedHold = true)],
    [
      "already a canary",
      (store) => {
        store.fleet.routingState = "PORTABLE_CANARY";
      },
    ],
  ];
  for (const [name, mutate] of cases) {
    const store = makeStore({ now: commandTime });
    mutate(store);
    const before = JSON.stringify({
      fleet: store.fleet,
      transitions: store.transitions,
      dueWork: store.dueWork,
    });
    const result = await admin(store, startCommand());
    expect(result.status, name).toBe(401);
    expect(
      JSON.stringify({
        fleet: store.fleet,
        transitions: store.transitions,
        dueWork: store.dueWork,
      }),
      name,
    ).toBe(before);
  }
});

test("start rejects a replayed nonce and an unbounded observation window", async () => {
  const store = makeStore({ now: commandTime });
  const first = startCommand();
  expect((await admin(store, first)).status).toBe(200);

  const replay = makeStore({ now: commandTime });
  replay.rememberNonce(first.nonce as string, "2026-01-01T00:01:10.000Z");
  expect((await admin(replay, { ...first })).status).toBe(401);

  const unbounded = makeStore({ now: commandTime });
  expect(
    (
      await admin(
        unbounded,
        startCommand({ observeUntil: "2026-01-02T00:00:10.001Z" }),
      )
    ).status,
  ).toBe(401);
  expect(unbounded.fleet.routingState).toBe("UNINITIALIZED");
});

test("a portable canary issues one canary-only lease for the named scale set", async () => {
  const clock = { now: commandTime };
  const store = makeStore(clock);
  expect((await admin(store, startCommand())).status).toBe(200);

  const leased = await heartbeat(store, "2026-01-01T00:00:11.000Z", 5);
  expect(leased.status).toBe(200);
  expect(leased.body.routingState).toBe("PORTABLE_CANARY");
  expect(leased.body.lease).toMatchObject({
    holder: "portable",
    mode: "canary-only",
    maxCapacity: 1,
    canaryScaleSet: "portable-canary",
  });

  const disabled = await heartbeat(
    store,
    "2026-01-01T00:00:12.000Z",
    6,
    {},
    "disabled",
  );
  expect(disabled.body.lease).toBeNull();
  expect(disabled.body.noLeaseReason).toBe("lease-disabled");

  const wrongFence = await heartbeat(store, "2026-01-01T00:00:13.000Z", 7, {
    fenceGeneration: 6,
  });
  expect(wrongFence.body.lease).toBeNull();
  expect(wrongFence.body.noLeaseReason).toBe("invalid-request");

  const legacyHolder = await heartbeat(store, "2026-01-01T00:00:14.000Z", 8, {
    holder: "legacy",
  });
  expect(legacyHolder.body.lease).toBeNull();
  expect(legacyHolder.body.noLeaseReason).toBe("invalid-request");
  expect(store.fleet.routingState).toBe("PORTABLE_CANARY");
});

test("stop drains to hosted only after the last lease and margin expire", async () => {
  const clock = { now: commandTime };
  const store = makeStore(clock);
  expect((await admin(store, startCommand())).status).toBe(200);
  const generation = store.fleet.leaseGeneration;

  const first = await admin(store, stopCommand(commandTime));
  expect(first.status).toBe(200);
  expect(JSON.parse(first.body).status).toBe("draining");
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
  expect(store.fleet.leaseGeneration).toBe(generation + 1);

  const drained = await heartbeat(store, "2026-01-01T00:00:11.000Z", 5);
  expect(drained.body.lease).toBeNull();
  expect(drained.body.noLeaseReason).toBe("routing-hosted");

  const early = "2026-01-01T00:03:00.500Z";
  clock.now = early;
  const second = await admin(store, stopCommand(early));
  expect(JSON.parse(second.body).status).toBe("draining");
  expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");

  const due = "2026-01-01T00:03:01.000Z";
  clock.now = due;
  const third = await admin(store, stopCommand(due));
  expect(third.status).toBe(200);
  expect(JSON.parse(third.body).status).toBe("hosted");
  expect(store.fleet.routingState).toBe("HOSTED");
  expect(store.transitions.at(-1)).toMatchObject({
    from: "DRAINING_TO_HOSTED",
    to: "HOSTED",
  });

  const restart = await admin(
    store,
    startCommand({
      timestamp: due,
      observeUntil: "2026-01-01T01:03:01.000Z",
      leaseGeneration: store.fleet.leaseGeneration,
    }),
  );
  expect(restart.status).toBe(200);
  expect(store.fleet.routingState).toBe("PORTABLE_CANARY");
});

// A controller can re-enroll while the fleet drains. The accepted session
// advances the lease generation (handleSession), and the drain must still
// complete, through the stop command and through the due-work runner alike.
test("a session replacement during the drain still lets it complete", async () => {
  const due = "2026-01-01T00:03:01.000Z";
  for (const path of ["stop", "due-work"] as const) {
    const clock = { now: commandTime };
    const store = makeStore(clock);
    expect((await admin(store, startCommand())).status).toBe(200);
    expect((await admin(store, stopCommand(commandTime))).status).toBe(200);
    expect(store.fleet.routingState).toBe("DRAINING_TO_HOSTED");
    store.fleet.leaseGeneration += 1;

    clock.now = due;
    if (path === "stop") {
      const stop = await admin(store, stopCommand(due));
      expect(stop.status).toBe(200);
      expect(JSON.parse(stop.body).status).toBe("hosted");
    } else {
      await executeDueWork(
        store,
        {} as GitHubClient,
        store.claimReady(due, 8, 5_000),
      );
    }
    expect(store.fleet.routingState).toBe("HOSTED");
  }
});

test("stop is refused outside a portable canary or without a safety margin", async () => {
  const hosted = makeStore({ now: commandTime });
  hosted.fleet.routingState = "HOSTED";
  hosted.transitions.push({ epoch: 1, from: "UNINITIALIZED", to: "HOSTED" });
  expect((await admin(hosted, stopCommand(commandTime))).status).toBe(401);
  expect(hosted.fleet.routingState).toBe("HOSTED");

  const canary = makeStore({ now: commandTime });
  expect((await admin(canary, startCommand())).status).toBe(200);
  const withoutMargin: AdminSecrets = { ...adminSecrets };
  delete withoutMargin.hostedTransitionSafetyMarginMs;
  expect(
    (await admin(canary, stopCommand(commandTime), withoutMargin)).status,
  ).toBe(401);
  expect(canary.fleet.routingState).toBe("PORTABLE_CANARY");
});
