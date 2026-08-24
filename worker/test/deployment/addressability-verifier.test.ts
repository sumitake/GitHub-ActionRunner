import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  AddressabilityUnavailableError,
  createDeadlineScope,
  verifyWorkerAddressability,
  waitUntil,
  writeAddressabilityEvidence,
} from "../../../scripts/ops/verify-worker-addressability.mjs";

const keyHex = "0c".repeat(32);
const inventoryDigest =
  "786c8d5ae1c3ebeea30656a1a48f87c0124132c26f090d2d099425bd9c5b1dd3";
const versionCreatedAt = "2026-01-01T00:00:30.000Z";
const startTime = Date.parse("2026-01-01T00:00:40.000Z");
const temporaryRoots: string[] = [];

afterEach(() => {
  vi.useRealTimers();
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function canonicalize(value: unknown): string {
  const sort = (input: unknown): unknown => {
    if (Array.isArray(input)) {
      return input.map(sort);
    }
    if (input !== null && typeof input === "object") {
      return Object.fromEntries(
        Object.entries(input)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([key, nested]) => [key, sort(nested)]),
      );
    }
    return input;
  };
  return JSON.stringify(sort(value));
}

function mac(domain: string, timestamp: string, body: string): string {
  return createHmac("sha256", Buffer.from(keyHex, "hex"))
    .update(`${domain}\nPOST\n/v1/admin/status\n${timestamp}\n${body}`)
    .digest("hex");
}

type StatusRequest = {
  fleetId: string;
  inventoryDigest: string;
  inventoryRevision: string;
  nonce: string;
  protocolVersion: number;
  requestTime: string;
};

function signedResponse(
  request: StatusRequest,
  responseTime: string,
  overrides: Record<string, unknown> = {},
): Response {
  const value = {
    protocolVersion: 1,
    status: "inert-receipt",
    fleetId: request.fleetId,
    nonce: request.nonce,
    requestTime: request.requestTime,
    responseTime,
    inventoryRevision: request.inventoryRevision,
    inventoryDigest: request.inventoryDigest,
    tickTimestamp: responseTime,
    receiptTime: responseTime,
    persistenceGeneration: 1,
    inventoried: false,
    holder: "none",
    maxCapacity: 0,
    routingState: "UNINITIALIZED",
    childCounts: {
      repositories: 0,
      transitions: 0,
      dueWork: 0,
      auditEvents: 0,
    },
    ...overrides,
  };
  const body = canonicalize(value);
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/json",
      "x-portable-ghar-timestamp": responseTime,
      "x-portable-ghar-mac": mac(
        "portable-ghar-address-status-response-v1",
        responseTime,
        body,
      ),
    },
  });
}

function input(deadlineAt = "2026-01-01T00:03:00.000Z") {
  return {
    endpoint: "https://github-actionrunner.example.workers.dev",
    fleetIds: ["alpha", "beta", "gamma"],
    inventoryRevision: "1",
    inventoryDigest,
    cronHmacKeyHex: keyHex,
    cronTickBudgetMs: 35_000,
    timestampWindowMs: 5_000,
    versionId: "version-123",
    versionCreatedAt,
    deadlineAt,
  };
}

function harness(
  responder: (
    request: StatusRequest,
    boundaryMs: number,
    attempt: number,
    setNow: (value: number) => void,
  ) => Response | Promise<Response>,
) {
  let nowMs = startTime;
  let closeCount = 0;
  let activeWaiters = 0;
  const attempts = new Map<string, number>();
  const calls: Array<{ fleetId: string; boundaryMs: number }> = [];
  const waitTargets: number[] = [];
  const abort = new AbortController();
  return {
    calls,
    waitTargets,
    closeCount: () => closeCount,
    activeWaiters: () => activeWaiters,
    dependencies: {
      now: () => nowMs,
      nonce: (fleetId: string, boundaryMs: number) => {
        const suffix = `${fleetId}:${boundaryMs}`;
        return createHmac("sha256", "test-nonce").update(suffix).digest("hex");
      },
      waitUntil: async (targetMs: number, signal: AbortSignal) => {
        activeWaiters += 1;
        try {
          if (signal.aborted) {
            throw new Error("aborted");
          }
          waitTargets.push(targetMs);
          nowMs = targetMs;
        } finally {
          activeWaiters -= 1;
        }
      },
      fetch: async (request: Request) => {
        const body = await request.clone().text();
        const parsed = JSON.parse(body) as StatusRequest;
        const boundaryMs =
          Math.floor(Date.parse(parsed.requestTime) / 60_000) * 60_000;
        calls.push({ fleetId: parsed.fleetId, boundaryMs });
        const expectedMac = mac(
          "portable-ghar-address-status-request-v1",
          parsed.requestTime,
          body,
        );
        expect(request.headers.get("x-portable-ghar-mac")).toBe(expectedMac);
        expect(request.signal.aborted).toBe(false);
        const attempt = (attempts.get(parsed.fleetId) ?? 0) + 1;
        attempts.set(parsed.fleetId, attempt);
        return responder(parsed, boundaryMs, attempt, (value) => {
          nowMs = value;
        });
      },
      createDeadlineScope: () => ({
        signal: abort.signal,
        close: () => {
          closeCount += 1;
          abort.abort();
        },
      }),
    },
  };
}

describe("natural-Cron addressability verifier", () => {
  test("rejects an unbounded overall verification window", async () => {
    const testHarness = harness((request) =>
      signedResponse(request, request.requestTime),
    );

    await expect(
      verifyWorkerAddressability(
        input("2026-01-01T01:00:00.000Z"),
        testHarness.dependencies,
      ),
    ).rejects.toThrow("verification window rejected");
    expect(testHarness.calls).toEqual([]);
  });

  test("rejects a delayed poll window that can cross the next natural boundary", async () => {
    const testHarness = harness((request) =>
      signedResponse(request, request.requestTime),
    );

    await expect(
      verifyWorkerAddressability(
        { ...input(), cronTickBudgetMs: 50_000 },
        testHarness.dependencies,
      ),
    ).rejects.toThrow("verification input rejected");
    expect(testHarness.calls).toEqual([]);
  });

  test("accepts one signed inert receipt for every fleet after one natural boundary", async () => {
    const testHarness = harness((request) =>
      signedResponse(request, request.requestTime),
    );

    const evidence = await verifyWorkerAddressability(
      input(),
      testHarness.dependencies,
    );

    expect(evidence.status).toBe("verified");
    expect(
      evidence.fleets.map((fleet: { fleetId: string }) => fleet.fleetId),
    ).toEqual(["alpha", "beta", "gamma"]);
    expect(testHarness.calls).toEqual([
      { fleetId: "alpha", boundaryMs: Date.parse("2026-01-01T00:01:00.000Z") },
      { fleetId: "beta", boundaryMs: Date.parse("2026-01-01T00:01:00.000Z") },
      { fleetId: "gamma", boundaryMs: Date.parse("2026-01-01T00:01:00.000Z") },
    ]);
    expect(testHarness.waitTargets).toEqual([
      Date.parse("2026-01-01T00:01:40.000Z"),
    ]);
    expect(testHarness.activeWaiters()).toBe(0);
    expect(testHarness.closeCount()).toBe(1);
    expect(JSON.stringify(evidence)).not.toContain(keyHex);
    expect(JSON.stringify(evidence)).not.toContain("nonce");
    expect(JSON.stringify(evidence)).not.toContain("mac");
  });

  test("preserves partial success and never polls a fleet twice in one boundary", async () => {
    const testHarness = harness((request, _boundaryMs, attempt) => {
      if (request.fleetId === "alpha" || attempt > 1) {
        return signedResponse(request, request.requestTime);
      }
      return new Response('{"error":"rejected"}', { status: 401 });
    });

    const evidence = await verifyWorkerAddressability(
      input(),
      testHarness.dependencies,
    );

    expect(evidence.status).toBe("verified");
    expect(
      testHarness.calls.filter((call) => call.fleetId === "alpha"),
    ).toHaveLength(1);
    expect(
      testHarness.calls.filter((call) => call.fleetId === "beta"),
    ).toHaveLength(2);
    expect(
      testHarness.calls.filter((call) => call.fleetId === "gamma"),
    ).toHaveLength(2);
    const unique = new Set(
      testHarness.calls.map((call) => `${call.fleetId}:${call.boundaryMs}`),
    );
    expect(unique.size).toBe(testHarness.calls.length);
  });

  test.each([
    [
      "stale version receipt",
      (request: StatusRequest, _boundaryMs: number, attempt: number) =>
        signedResponse(
          request,
          request.requestTime,
          attempt === 1
            ? {
                tickTimestamp: versionCreatedAt,
                receiptTime: versionCreatedAt,
              }
            : {},
        ),
    ],
    [
      "response identity mismatch",
      (request: StatusRequest, _boundaryMs: number, attempt: number) =>
        signedResponse(
          request,
          request.requestTime,
          attempt === 1 ? { fleetId: "foreign" } : {},
        ),
    ],
    [
      "response nonce mismatch",
      (request: StatusRequest, _boundaryMs: number, attempt: number) =>
        signedResponse(
          request,
          request.requestTime,
          attempt === 1 ? { nonce: "f".repeat(64) } : {},
        ),
    ],
  ])("retries only at the next boundary after %s", async (_name, responder) => {
    const testHarness = harness((request, boundaryMs, attempt) => {
      if (request.fleetId !== "alpha") {
        return signedResponse(request, request.requestTime);
      }
      return responder(request, boundaryMs, attempt);
    });

    const evidence = await verifyWorkerAddressability(
      input(),
      testHarness.dependencies,
    );

    expect(evidence.status).toBe("verified");
    const alphaCalls = testHarness.calls.filter(
      (call) => call.fleetId === "alpha",
    );
    expect(alphaCalls.map((call) => call.boundaryMs)).toEqual([
      Date.parse("2026-01-01T00:01:00.000Z"),
      Date.parse("2026-01-01T00:02:00.000Z"),
    ]);
  });

  test("treats the delayed poll exactly at the overall deadline as unavailable", async () => {
    const testHarness = harness((request) =>
      signedResponse(request, request.requestTime),
    );

    await expect(
      verifyWorkerAddressability(
        input("2026-01-01T00:01:40.000Z"),
        testHarness.dependencies,
      ),
    ).rejects.toBeInstanceOf(AddressabilityUnavailableError);
    expect(testHarness.calls).toEqual([]);
    expect(testHarness.activeWaiters()).toBe(0);
    expect(testHarness.closeCount()).toBe(1);
  });

  test("treats a response completing exactly at the overall deadline as unavailable", async () => {
    const deadlineAt = "2026-01-01T00:01:45.000Z";
    const deadlineMs = Date.parse(deadlineAt);
    const testHarness = harness((request, _boundaryMs, _attempt, setNow) => {
      setNow(deadlineMs);
      return signedResponse(request, deadlineAt);
    });

    await expect(
      verifyWorkerAddressability(input(deadlineAt), testHarness.dependencies),
    ).rejects.toBeInstanceOf(AddressabilityUnavailableError);
    expect(testHarness.calls).toHaveLength(3);
    expect(testHarness.activeWaiters()).toBe(0);
    expect(testHarness.closeCount()).toBe(1);
  });

  test("returns sanitized partial evidence when the overall deadline expires", async () => {
    const testHarness = harness((request) => {
      if (request.fleetId === "alpha") {
        return signedResponse(request, request.requestTime);
      }
      return new Response('{"error":"rejected"}', { status: 401 });
    });

    let failure: AddressabilityUnavailableError | undefined;
    try {
      await verifyWorkerAddressability(
        input("2026-01-01T00:02:00.000Z"),
        testHarness.dependencies,
      );
    } catch (error) {
      expect(error).toBeInstanceOf(AddressabilityUnavailableError);
      failure = error as AddressabilityUnavailableError;
    }
    expect(failure?.evidence.status).toBe("unavailable");
    expect(
      failure?.evidence.fleets.map(
        (fleet: { fleetId: string }) => fleet.fleetId,
      ),
    ).toEqual(["alpha"]);
    expect(failure?.evidence.pendingFleetIds).toEqual(["beta", "gamma"]);
    expect(JSON.stringify(failure?.evidence)).not.toContain(keyHex);
    expect(testHarness.closeCount()).toBe(1);
  });
});

test("deadline and boundary waiters close idempotently without timer leaks", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
  const scope = createDeadlineScope(Date.now() + 10_000);
  expect(vi.getTimerCount()).toBe(1);
  scope.close();
  scope.close();
  expect(scope.signal.aborted).toBe(true);
  expect(vi.getTimerCount()).toBe(0);

  const abort = new AbortController();
  const waiting = waitUntil(Date.now() + 5_000, abort.signal);
  expect(vi.getTimerCount()).toBe(1);
  abort.abort();
  await expect(waiting).rejects.toThrow("aborted");
  expect(vi.getTimerCount()).toBe(0);
});

test("sanitized evidence is written atomically as a private regular file", async () => {
  const testHarness = harness((request) =>
    signedResponse(request, request.requestTime),
  );
  const evidence = await verifyWorkerAddressability(
    input(),
    testHarness.dependencies,
  );
  const root = mkdtempSync(join(tmpdir(), "pghar-address-evidence-"));
  temporaryRoots.push(root);
  const output = join(root, "evidence.json");

  writeAddressabilityEvidence(output, evidence);

  expect(statSync(output).isFile()).toBe(true);
  expect(statSync(output).mode & 0o777).toBe(0o600);
  const raw = readFileSync(output, "utf8");
  expect(raw).toBe(`${JSON.stringify(evidence, null, 2)}\n`);
  expect(raw).not.toContain(keyHex);
  expect(raw).not.toContain("nonce");
  expect(raw).not.toContain("mac");
});
