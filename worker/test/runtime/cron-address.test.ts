import { expect, test } from "vitest";

import type { FleetNamespace } from "../../src/bindings";
import {
  MAC_HEADER,
  signCronResponse,
  TIMESTAMP_HEADER,
  verifyCronRequest,
} from "../../src/protocol/auth";
import { canonicalize } from "../../src/protocol/canonical";
import {
  CRON_PATH,
  parseCronAddressRequest,
  type CronAddressRequestV1,
} from "../../src/protocol/cron";
import { CronAddressRunError, handleWorkerScheduled } from "../../src/runtime";

const workerKeyHex = "0b".repeat(32);
const cronKeyHex = "0c".repeat(32);
const cronKey = Uint8Array.from({ length: 32 }, () => 0x0c);
const timestamp = "2026-01-01T00:00:00.000Z";
const defaultPerFleetDeadlineMs = 2_000;
const digestByFleets: Record<string, string> = {
  alpha: "ceb56a401b60bbcac93ae24231b7b9a72ad4bd7310db77d4e5571c752882dc5e",
  "alpha,beta":
    "6a9aedffdae5b07550af1921963f6aa007cf4d6425762e0b30afa8ac7cbed91d",
  "alpha,beta,gamma":
    "786c8d5ae1c3ebeea30656a1a48f87c0124132c26f090d2d099425bd9c5b1dd3",
};

function cronEnv(fleetIds = "alpha,beta"): Record<string, unknown> {
  const count = fleetIds.split(",").length;
  return {
    HMAC_KEY: workerKeyHex,
    CRON_HMAC_KEY: cronKeyHex,
    FLEET_IDS: fleetIds,
    TIMESTAMP_WINDOW_MS: "5000",
    NONCE_TTL_MS: "60000",
    LEASE_DURATION_MS: "8000",
    ARCHIVE_EVIDENCE_MAX_AGE_MS: "60000",
    SELECTOR_EVIDENCE_MAX_AGE_MS: "60000",
    HOSTED_TRANSITION_SAFETY_MARGIN_MS: "1000",
    MAX_FLEETS: String(count),
    PER_FLEET_DEADLINE_MS: String(defaultPerFleetDeadlineMs),
    CRON_BUDGET_OVERHEAD_MS: String(defaultPerFleetDeadlineMs),
    CRON_TICK_BUDGET_MS: String(
      count * defaultPerFleetDeadlineMs + defaultPerFleetDeadlineMs,
    ),
    FLEET_INVENTORY_REVISION: "1",
    FLEET_INVENTORY_DIGEST: digestByFleets[fleetIds],
  };
}

function controller(events: string[] = []): { noRetry(): void } {
  return {
    noRetry() {
      events.push("noRetry");
    },
  };
}

async function acceptedResponse(
  request: Request,
  persistenceGeneration = 1,
): Promise<Response> {
  const timestampHeader = request.headers.get(TIMESTAMP_HEADER) ?? "";
  const mac = request.headers.get(MAC_HEADER) ?? "";
  const requestBody = await request.text();
  await verifyCronRequest(
    cronKey,
    "POST",
    CRON_PATH,
    timestampHeader,
    requestBody,
    mac,
  );
  const value = parseCronAddressRequest(requestBody);
  const responseValue = {
    protocolVersion: value.protocolVersion,
    fleetId: value.fleetId,
    revision: value.revision,
    inventoryDigest: value.inventoryDigest,
    nonce: value.nonce,
    tickTimestamp: value.tickTimestamp,
    deadline: value.deadline,
    receiptTime: value.tickTimestamp,
    persistenceGeneration,
  };
  const body = canonicalize(responseValue);
  const responseMac = await signCronResponse(
    cronKey,
    "POST",
    CRON_PATH,
    responseValue.receiptTime,
    body,
  );
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/json",
      [TIMESTAMP_HEADER]: responseValue.receiptTime,
      [MAC_HEADER]: responseMac,
    },
  });
}

test("scheduled entry calls noRetry before invalid configuration fails", async () => {
  const events: string[] = [];
  await expect(handleWorkerScheduled(controller(events), {})).rejects.toThrow();
  expect(events).toEqual(["noRetry"]);
});

test("scheduled address calls each named fleet serially with signed full inventory", async () => {
  const events: string[] = [];
  const observed: CronAddressRequestV1[] = [];
  const env = cronEnv();
  env.FLEET = {
    getByName(name: string) {
      events.push(`get:${name}`);
      return {
        async fetch(request: Request) {
          events.push(`fetch:${name}`);
          const body = await request.clone().text();
          observed.push(parseCronAddressRequest(body));
          return acceptedResponse(request, observed.length);
        },
      };
    },
  } satisfies FleetNamespace;
  let nonce = 0;

  const result = await handleWorkerScheduled(controller(events), env, {
    now: () => timestamp,
    nonce: () => String((nonce += 1)).padStart(64, "0"),
  });

  expect(result).toEqual({ addressed: ["alpha", "beta"], failed: [] });
  expect(events).toEqual([
    "noRetry",
    "get:alpha",
    "fetch:alpha",
    "get:beta",
    "fetch:beta",
  ]);
  expect(observed.map((item) => item.fleetId)).toEqual(["alpha", "beta"]);
  for (const item of observed) {
    expect(item.fleetIds).toEqual(["alpha", "beta"]);
    expect(item.inventoryDigest).toBe(digestByFleets["alpha,beta"]);
    expect(item.deadline).toBe("2026-01-01T00:00:02.000Z");
  }
  expect(new Set(observed.map((item) => item.nonce)).size).toBe(2);
});

test("inventory digest mismatch and unsafe global budget perform zero namespace calls", async () => {
  for (const override of [
    { FLEET_INVENTORY_DIGEST: "f".repeat(64) },
    { CRON_TICK_BUDGET_MS: "49" },
  ]) {
    let namespaceCalls = 0;
    const env = {
      ...cronEnv(),
      ...override,
      FLEET: {
        getByName() {
          namespaceCalls += 1;
          throw new Error("must not address");
        },
      },
    };
    await expect(
      handleWorkerScheduled(controller(), env, {
        now: () => timestamp,
        nonce: () => "1".repeat(64),
      }),
    ).rejects.toThrow();
    expect(namespaceCalls).toBe(0);
  }
});

test("tick budget starts after noRetry and can expire before namespace lookup", async () => {
  let namespaceReads = 0;
  const env = cronEnv("alpha");
  Object.defineProperty(env, "FLEET", {
    get() {
      namespaceReads += 1;
      throw new Error("expired setup must not inspect the namespace");
    },
  });
  let clockReads = 0;

  await expect(
    handleWorkerScheduled(controller(), env, {
      now: () =>
        clockReads++ === 0
          ? "2026-01-01T00:00:00.000Z"
          : "2026-01-01T00:00:10.000Z",
      nonce: () => "1".repeat(64),
    }),
  ).rejects.toThrow();

  expect(namespaceReads).toBe(0);
});

test("final response verification cannot claim success after global deadline", async () => {
  let currentTime = timestamp;
  let calls = 0;
  const env = cronEnv("alpha");
  env.FLEET = {
    getByName() {
      calls += 1;
      return {
        async fetch(request: Request) {
          const response = await acceptedResponse(request);
          currentTime = "2026-01-01T00:00:10.000Z";
          return response;
        },
      };
    },
  } satisfies FleetNamespace;

  const failure = await handleWorkerScheduled(controller(), env, {
    now: () => currentTime,
    nonce: () => "1".repeat(64),
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(CronAddressRunError);
  expect(failure).toMatchObject({
    result: { addressed: [], failed: ["alpha"] },
  });
  expect(calls).toBe(1);
});

test("one fleet rejection is retained while later fleets are still addressed once", async () => {
  const calls: string[] = [];
  const env = cronEnv("alpha,beta,gamma");
  env.FLEET = {
    getByName(name: string) {
      calls.push(name);
      return {
        fetch(request: Request) {
          if (name === "beta") {
            return Promise.reject(new Error("unavailable"));
          }
          return acceptedResponse(request);
        },
      };
    },
  } satisfies FleetNamespace;
  let nonce = 0;

  const failure = await handleWorkerScheduled(controller(), env, {
    now: () => timestamp,
    nonce: () => String((nonce += 1)).padStart(64, "0"),
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(CronAddressRunError);
  expect(failure).toMatchObject({
    result: { addressed: ["alpha", "gamma"], failed: ["beta"] },
  });
  expect(calls).toEqual(["alpha", "beta", "gamma"]);
});

test("per-fleet timeout aborts the request and does not wait forever", async () => {
  let aborted = false;
  const env = {
    ...cronEnv("alpha"),
    PER_FLEET_DEADLINE_MS: "5",
    CRON_BUDGET_OVERHEAD_MS: "5",
    CRON_TICK_BUDGET_MS: "10",
    FLEET: {
      getByName() {
        return {
          fetch(request: Request) {
            request.signal.addEventListener("abort", () => {
              aborted = true;
            });
            return new Promise<Response>(() => undefined);
          },
        };
      },
    } satisfies FleetNamespace,
  };

  const failure = await handleWorkerScheduled(controller(), env, {
    now: () => timestamp,
    nonce: () => "1".repeat(64),
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(CronAddressRunError);
  expect(failure).toMatchObject({
    result: { addressed: [], failed: ["alpha"] },
  });
  expect(aborted).toBe(true);
});

test("per-fleet timeout includes response body and signature validation", async () => {
  let aborted = false;
  let cancelled = false;
  const env = {
    ...cronEnv("alpha"),
    PER_FLEET_DEADLINE_MS: "5",
    CRON_BUDGET_OVERHEAD_MS: "5",
    CRON_TICK_BUDGET_MS: "10",
    FLEET: {
      getByName() {
        return {
          async fetch(request: Request) {
            request.signal.addEventListener("abort", () => {
              aborted = true;
            });
            return new Response(
              new ReadableStream({
                start() {},
                cancel() {
                  cancelled = true;
                },
              }),
              {
                status: 200,
                headers: {
                  [TIMESTAMP_HEADER]: timestamp,
                  [MAC_HEADER]: "0".repeat(64),
                },
              },
            );
          },
        };
      },
    } satisfies FleetNamespace,
  };

  const outcome = await Promise.race([
    handleWorkerScheduled(controller(), env, {
      now: () => timestamp,
      nonce: () => "1".repeat(64),
    }).catch((error: unknown) => error),
    new Promise<string>((resolve) => {
      setTimeout(() => resolve("hung"), 50);
    }),
  ]);

  expect(outcome).toBeInstanceOf(CronAddressRunError);
  expect(aborted).toBe(true);
  expect(cancelled).toBe(true);
});
