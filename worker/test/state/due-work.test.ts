import { expect, test } from "vitest";

import { enqueueRepositoryRoutes } from "../../src/github/outbox";
import {
  MAX_DUE_WORK,
  MAX_NON_ROUTE_DUE_WORK,
  MemoryFleetStore,
} from "../../src/state/memory";

function store(): MemoryFleetStore {
  return new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
}

test("expired mutation claims become uncertain while read-only claims recover", () => {
  const next = store();
  next.enqueue({
    id: "mutation-1",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: "claim-mutation-1",
    claimExpiresAt: "2026-01-01T00:00:05.000Z",
    attempts: 1,
    status: "claimed",
    payload: {
      effectKey: "effect-1",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      transitionRevision: "1",
      value: "hosted",
    },
  });
  next.enqueue({
    id: "readback-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: "claim-readback-1",
    claimExpiresAt: "2026-01-01T00:00:05.000Z",
    attempts: 1,
    status: "claimed",
    payload: { mutationId: "mutation-1" },
  });

  const claimed = next.claimReady("2026-01-01T00:00:10.000Z", 8, 5_000);

  expect(next.dueWork[0]?.status).toBe("uncertain");
  expect(next.dueWork[0]?.claimId).toBeNull();
  expect(claimed.map((row) => row.id)).toEqual(["readback-1"]);
});

test("expired external-effect claims never return to the executable queue", () => {
  for (const kind of [
    "canary-dispatch",
    "notify-email",
    "notify-webhook",
  ] as const) {
    const next = store();
    next.enqueue({
      id: `effect-${kind}`,
      kind,
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: `claim-${kind}`,
      claimExpiresAt: "2026-01-01T00:00:05.000Z",
      attempts: 1,
      status: "claimed",
      payload: { eventId: `event-${kind}` },
    });

    expect(next.claimReady("2026-01-01T00:00:10.000Z", 1, 5_000)).toHaveLength(
      0,
    );
    expect(next.dueWork[0]?.status).toBe("uncertain");
    expect(next.dueWork[0]?.claimId).toBeNull();
  }
});

test("canary boundary rows are strict and expired claims return to ready", () => {
  const next = store();
  next.enqueue({
    id: "canary-boundary-2",
    kind: "canary-boundary",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: "claim-canary-boundary-2",
    claimExpiresAt: "2026-01-01T00:00:05.000Z",
    attempts: 1,
    status: "claimed",
    payload: {
      transitionRevision: "2",
      from: "PORTABLE_CANARY",
    },
  });

  const claimed = next.claimReady("2026-01-01T00:00:10.000Z", 1, 5_000);
  expect(claimed).toHaveLength(1);
  expect(claimed[0]).toEqual(
    expect.objectContaining({
      id: "canary-boundary-2",
      status: "claimed",
      attempts: 2,
    }),
  );

  expect(() =>
    next.enqueue({
      id: "canary-boundary-invalid",
      kind: "canary-boundary",
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: {
        transitionRevision: "3",
        from: "PORTABLE_CANARY",
        extra: "forbidden",
      },
    }),
  ).toThrow("due-work row is invalid");
});

test("ready work is claimed in canonical due-time and id order", () => {
  const next = store();
  for (const [id, dueAt] of [
    ["work-b", "2026-01-01T00:00:02.000Z"],
    ["work-c", "2026-01-01T00:00:01.000Z"],
    ["work-a", "2026-01-01T00:00:01.000Z"],
  ] as const) {
    next.enqueue({
      id,
      kind: "github-readback",
      dueAt,
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: `mutation-${id}` },
    });
  }

  expect(
    next.claimReady("2026-01-01T00:00:10.000Z", 2, 5_000).map((row) => row.id),
  ).toEqual(["work-a", "work-c"]);
});

test("outbox reserves control-plane capacity and rejects duplicate route revisions", () => {
  const next = store();
  for (let index = 0; index < MAX_NON_ROUTE_DUE_WORK; index += 1) {
    next.enqueue({
      id: `notify-${index}`,
      kind: "notify-email",
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { eventId: `event-${index}` },
    });
  }
  expect(() =>
    next.enqueue({
      id: "notify-overflow",
      kind: "notify-email",
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { eventId: "overflow" },
    }),
  ).toThrow("non-route due-work capacity is exhausted");

  next.enqueue({
    id: "route-hosted-1",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {
      effectKey: "route-hosted-1",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      transitionRevision: "1",
      value: "hosted",
    },
  });
  expect(next.dueWork).toHaveLength(MAX_NON_ROUTE_DUE_WORK + 1);
  expect(next.dueWork.length).toBeLessThanOrEqual(MAX_DUE_WORK);
  expect(() =>
    next.enqueue({
      id: "route-portable-duplicate",
      kind: "github-mutate-route",
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: {
        effectKey: "route-portable-duplicate",
        repositoryAlias: "repo-a",
        name: "PORTABLE_GHAR_ROUTE",
        configurationRevision: "0",
        transitionRevision: "1",
        value: "self-hosted",
      },
    }),
  ).toThrow("route mutation target is unresolved");
  next.enqueue({
    id: "route-portable-2",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {
      effectKey: "route-portable-2",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      transitionRevision: "2",
      value: "self-hosted",
    },
  });
  expect(next.dueWork.at(-1)?.id).toBe("route-portable-2");
});

test("outbox rejects duplicate row identity", () => {
  const next = store();
  const row = {
    id: "due-1",
    kind: "github-readback" as const,
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready" as const,
    payload: { mutationId: "mutation-1" },
  };
  next.enqueue(row);
  expect(() => next.enqueue({ ...row })).toThrow("due-work id is duplicated");
});

test("GitHub mutation identity is strict and repository-local for all three kinds", () => {
  const next = store();
  const base = {
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready" as const,
  };
  for (const [kind, name, value] of [
    ["github-mutate-route", "PORTABLE_GHAR_ROUTE", "legacy"],
    ["github-mutate-scale-set", "PORTABLE_GHAR_SCALE_SET", "portable-runners"],
    [
      "github-mutate-legacy-label",
      "PORTABLE_GHAR_LEGACY_LABEL",
      "legacy-runners",
    ],
  ] as const) {
    expect(() =>
      next.enqueue({
        ...base,
        id: `missing-alias-${kind}`,
        kind,
        payload: {
          effectKey: `missing-alias-${kind}`,
          name,
          value,
          configurationRevision: "4",
          transitionRevision: "7",
        },
      }),
    ).toThrow("due-work row is invalid");
  }

  for (const repositoryAlias of ["repo-a", "repo-b"]) {
    next.enqueue({
      ...base,
      id: `legacy-${repositoryAlias}`,
      kind: "github-mutate-route",
      payload: {
        effectKey: `legacy-${repositoryAlias}`,
        repositoryAlias,
        name: "PORTABLE_GHAR_ROUTE",
        value: "legacy",
        configurationRevision: "4",
        transitionRevision: "7",
      },
    });
  }
  expect(
    next.dueWork.filter((row) => row.kind === "github-mutate-route"),
  ).toHaveLength(2);
});

test("an unresolved mutation keeps one hard-cap slot for its read-back", () => {
  const next = store();
  for (let index = 0; index < MAX_DUE_WORK - 2; index += 1) {
    next.enqueue({
      id: `prior-readback-${index}`,
      kind: "github-readback",
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: `prior-mutation-${index}` },
    });
  }
  next.enqueue({
    id: "route-1",
    kind: "github-mutate-route",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: {
      effectKey: "route-1",
      repositoryAlias: "repo-a",
      name: "PORTABLE_GHAR_ROUTE",
      configurationRevision: "0",
      transitionRevision: "1",
      value: "hosted",
    },
  });
  expect(() =>
    next.enqueue({
      id: "unrelated-readback",
      kind: "github-readback",
      dueAt: "2026-01-01T00:00:00.000Z",
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: "other-mutation" },
    }),
  ).toThrow("due-work readback reserve is exhausted");
  next.enqueue({
    id: "readback-route-1",
    kind: "github-readback",
    dueAt: "2026-01-01T00:00:00.000Z",
    claimId: null,
    claimExpiresAt: null,
    attempts: 0,
    status: "ready",
    payload: { mutationId: "route-1" },
  });
  expect(next.dueWork).toHaveLength(MAX_DUE_WORK);
});

test("legacy route staging preserves all-alias hosted restoration headroom", () => {
  function preparedStore(fillerRows: number): MemoryFleetStore {
    const next = store();
    next.fleet.routingState = "LEGACY_CANARY";
    next.fleet.leaseGeneration = 7;
    for (const alias of ["repo-a", "repo-b"]) {
      next.putRepository({
        alias,
        expectedRoute: "hosted",
        confirmedRoute: "hosted",
        expectedScaleSet: "portable-runners",
        confirmedScaleSet: "portable-runners",
        expectedLegacyLabel: "legacy-runners",
        confirmedLegacyLabel: "legacy-runners",
        archiveEligibility: "active",
        archivePolicyRevision: null,
        archiveObservedAt: next.now(),
        archived: false,
        selectorEvidenceAt: next.now(),
        openQueueRisk: null,
      });
    }
    for (let index = 0; index < fillerRows; index += 1) {
      next.enqueue({
        id: `prior-readback-${index}`,
        kind: "github-readback",
        dueAt: next.now(),
        claimId: null,
        claimExpiresAt: null,
        attempts: 0,
        status: "ready",
        payload: { mutationId: `prior-mutation-${index}` },
      });
    }
    return next;
  }

  const insufficient = preparedStore(MAX_DUE_WORK - 7);
  expect(() =>
    enqueueRepositoryRoutes(insufficient, insufficient.now(), "legacy", 8),
  ).toThrow("legacy restoration reserve is exhausted");
  expect(insufficient.dueWork).toHaveLength(MAX_DUE_WORK - 7);
  expect(
    [...insufficient.repositories.values()].map(
      (repository) => repository.expectedRoute,
    ),
  ).toEqual(["hosted", "hosted"]);

  const exact = preparedStore(MAX_DUE_WORK - 8);
  enqueueRepositoryRoutes(exact, exact.now(), "legacy", 8);
  exact.fleet.leaseGeneration = 8;
  expect(() =>
    exact.enqueue({
      id: "unrelated-readback",
      kind: "github-readback",
      dueAt: exact.now(),
      claimId: null,
      claimExpiresAt: null,
      attempts: 0,
      status: "ready",
      payload: { mutationId: "unrelated-mutation" },
    }),
  ).toThrow("legacy restoration reserve is exhausted");

  for (const row of exact.dueWork) {
    if (row.kind === "github-mutate-route" && row.payload.value === "legacy") {
      row.status = "failed";
    }
  }
  enqueueRepositoryRoutes(exact, exact.now(), "hosted", 9);
  expect(
    exact.dueWork.filter(
      (row) =>
        row.kind === "github-mutate-route" && row.payload.value === "hosted",
    ),
  ).toHaveLength(2);
});
