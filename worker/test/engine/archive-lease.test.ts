import { expect, test } from "vitest";

import { handleHeartbeat } from "../../src/engine/heartbeat";
import { hexToBytes, signCanonical } from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import { parseHeartbeatResponse } from "../../src/protocol/messages";
import type { ArchiveEligibility } from "../../src/routing/archive";
import { MemoryFleetStore } from "../../src/state/memory";

const key = hexToBytes("0b".repeat(32));
const digest = "a".repeat(64);
const session = "c".repeat(64);
const now = "2026-01-01T00:00:10.000Z";

type ArchiveCase = {
  name: string;
  archiveEligibility?: ArchiveEligibility;
  archiveObservedAt?: string | null;
  archived?: boolean;
  restricted: boolean;
};

async function heartbeat(archive: ArchiveCase) {
  const store = new MemoryFleetStore("example-fleet", { now: () => now });
  Object.assign(store.fleet, {
    inventoried: true,
    epoch: 1,
    sessionId: session,
    sequence: 0,
    leaseGeneration: 1,
    routingState: "PORTABLE",
    fenceGeneration: 1,
    policyDigest: digest,
    configRevision: 1,
    maxCapacity: 1,
  });
  for (const alias of ["repo-a", "repo-b"]) {
    store.putRepository({
      alias,
      expectedRoute: "self-hosted",
      confirmedRoute: "self-hosted",
      expectedScaleSet: "portable-runners",
      confirmedScaleSet: "portable-runners",
      expectedLegacyLabel: "legacy-runners",
      confirmedLegacyLabel: "legacy-runners",
      archiveEligibility:
        alias === "repo-a"
          ? (archive.archiveEligibility ?? "active")
          : "active",
      archivePolicyRevision:
        alias === "repo-a" && archive.archiveEligibility !== undefined
          ? 1
          : null,
      archiveObservedAt:
        alias === "repo-a"
          ? archive.archiveObservedAt === undefined
            ? "2026-01-01T00:00:09.000Z"
            : archive.archiveObservedAt
          : "2026-01-01T00:00:09.000Z",
      archived: alias === "repo-a" ? (archive.archived ?? false) : false,
      selectorEvidenceAt: now,
      openQueueRisk: null,
    });
  }
  const body = canonicalize({
    protocolVersion: 1,
    fleetId: "example-fleet",
    epoch: 1,
    sessionId: session,
    sequence: 1,
    holder: "portable",
    fenceGeneration: 1,
    timestamp: now,
    snapshot: {
      observedAt: now,
      fleetAlias: "example-fleet",
      policyEpoch: 1,
      policyDigest: digest,
      repositoryPolicyRevision: 1,
      acquisitionMode: "enabled",
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
      buildId: digest,
    },
  });
  const mac = await signCanonical(key, "POST", "/v1/heartbeat", now, body);
  return parseHeartbeatResponse(
    (
      await handleHeartbeat(
        store,
        {
          hmacKey: key,
          timestampWindowMs: 5_000,
          leaseDurationMs: 8_000,
          archiveEvidenceMaxAgeMs: 2_000,
          selectorEvidenceMaxAgeMs: 2_000,
          hostedTransitionSafetyMarginMs: 1_000,
        },
        {
          method: "POST",
          path: "/v1/heartbeat",
          timestamp: now,
          macHex: mac,
          body,
          inventoried: true,
        },
      )
    ).body,
  );
}

test("archive evidence and eligibility restrict only the affected alias", async () => {
  const cases: ArchiveCase[] = [
    { name: "fresh", restricted: false },
    { name: "missing", archiveObservedAt: null, restricted: true },
    {
      name: "malformed",
      archiveObservedAt: "not-a-time",
      restricted: true,
    },
    {
      name: "future",
      archiveObservedAt: "2026-01-01T00:00:11.000Z",
      restricted: true,
    },
    {
      name: "exact-age-boundary",
      archiveObservedAt: "2026-01-01T00:00:08.000Z",
      restricted: true,
    },
    {
      name: "stale",
      archiveObservedAt: "2026-01-01T00:00:07.999Z",
      restricted: true,
    },
    { name: "live-archived", archived: true, restricted: true },
    {
      name: "latched",
      archiveEligibility: "archived-disabled",
      restricted: true,
    },
    {
      name: "pending",
      archiveEligibility: "pending-reactivation",
      restricted: true,
    },
  ];
  for (const archive of cases) {
    const response = await heartbeat(archive);
    expect(response.lease, archive.name).not.toBeNull();
    expect(response.lease?.archivedDisabledAliases, archive.name).toEqual(
      archive.restricted ? ["repo-a"] : [],
    );
    expect(
      response.lease?.archivedDisabledAliases.includes("repo-b"),
      archive.name,
    ).toBe(false);
  }
});
