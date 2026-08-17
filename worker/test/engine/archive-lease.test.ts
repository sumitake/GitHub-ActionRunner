import { expect, test } from "vitest";

import { handleHeartbeat } from "../../src/engine/heartbeat";
import { hexToBytes, signCanonical } from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import { MemoryFleetStore } from "../../src/state/memory";

const key = hexToBytes("0b".repeat(32));
const digest = "a".repeat(64);
const session = "c".repeat(64);

test("missing archive evidence is restrictive and stale selector issues no lease", async () => {
  const store = new MemoryFleetStore("example-fleet", {
    now: () => "2026-01-01T00:00:10.000Z",
  });
  store.fleet.inventoried = true;
  store.fleet.epoch = 1;
  store.fleet.sessionId = session;
  store.fleet.sequence = 0;
  store.fleet.leaseGeneration = 1;
  store.fleet.routingState = "PORTABLE";
  store.fleet.fenceGeneration = 1;
  store.putRepository({
    alias: "repo-a",
    expectedRoute: "self-hosted",
    confirmedRoute: "self-hosted",
    archiveLatched: false,
    archiveObservedAt: null,
    archived: false,
    selectorEvidenceAt: "2026-01-01T00:00:00.000Z",
    openQueueRisk: null,
  });
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 1,
    sessionId: session,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp: "2026-01-01T00:00:10.000Z",
    snapshot: {
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
      unassignedReleasedListeners: 0,
    },
  });
  const mac = await signCanonical(
    key,
    "POST",
    "/v1/heartbeat",
    "2026-01-01T00:00:10.000Z",
    body,
  );
  const result = await handleHeartbeat(
    store,
    {
      hmacKey: key,
      timestampWindowMs: 5_000,
      leaseDurationMs: 8_000,
      archiveEvidenceMaxAgeMs: 2_000,
      selectorEvidenceMaxAgeMs: 2_000,
    },
    {
      method: "POST",
      path: "/v1/heartbeat",
      timestamp: "2026-01-01T00:00:10.000Z",
      macHex: mac,
      body,
      inventoried: true,
    },
  );
  expect(result.body).toContain("stale-selector-evidence");
  expect(store.dueWork.some((row) => row.kind === "github-mutate-route")).toBe(
    true,
  );
});
