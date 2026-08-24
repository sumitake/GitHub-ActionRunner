import { handleAdminCommand, type AdminSecrets } from "./engine/admin";
import { handleHeartbeat, type HeartbeatSecrets } from "./engine/heartbeat";
import { handleSession, type SessionSecrets } from "./engine/session";
import {
  ADMIN_COMMAND_PATH,
  HEARTBEAT_PATH,
  MAC_HEADER,
  SESSION_PATH,
  TIMESTAMP_HEADER,
} from "./protocol/auth";
import { MAX_PROTOCOL_BYTES, parseCanonical } from "./protocol/canonical";
import { FLEET_ID } from "./protocol/messages";
import type { MemoryFleetStore } from "./state/memory";

export type GatewaySecrets = HeartbeatSecrets & SessionSecrets & AdminSecrets;

export type FleetGateway = {
  inventoriedFleetIds: readonly string[];
  secrets: GatewaySecrets;
  storeFor(fleetId: string): MemoryFleetStore | undefined;
};

function rejected(): Response {
  return Response.json({ error: "rejected" }, { status: 401 });
}

export function fleetIdFromBody(body: string): string | null {
  try {
    const value = parseCanonical(body);
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return null;
    }
    const fleetId = (value as { fleetId?: unknown }).fleetId;
    if (typeof fleetId !== "string" || !FLEET_ID.test(fleetId)) {
      return null;
    }
    return fleetId;
  } catch {
    return null;
  }
}

export async function dispatchFleetRequest(
  request: Request,
  gateway: FleetGateway,
): Promise<Response> {
  if (request.method !== "POST") {
    return rejected();
  }
  const url = new URL(request.url);
  const path = url.pathname;
  if (
    url.href.includes("?") ||
    (path !== SESSION_PATH &&
      path !== HEARTBEAT_PATH &&
      path !== ADMIN_COMMAND_PATH)
  ) {
    return rejected();
  }
  const timestamp = request.headers.get(TIMESTAMP_HEADER) ?? "";
  const macHex = request.headers.get(MAC_HEADER) ?? "";
  if (timestamp === "" || macHex === "") {
    return rejected();
  }
  const body = await readBoundedBody(request);
  if (body === null) {
    return rejected();
  }
  const fleetId = fleetIdFromBody(body);
  if (fleetId === null || !gateway.inventoriedFleetIds.includes(fleetId)) {
    return rejected();
  }
  const store = gateway.storeFor(fleetId);
  if (store === undefined) {
    return rejected();
  }
  const input = {
    method: request.method,
    path,
    timestamp,
    macHex,
    body,
    inventoried: true,
  };
  const result =
    path === HEARTBEAT_PATH
      ? await handleHeartbeat(store, gateway.secrets, input)
      : path === SESSION_PATH
        ? await handleSession(store, gateway.secrets, input)
        : await handleAdminCommand(store, gateway.secrets, input);
  return new Response(result.body, {
    status: result.status,
    headers: {
      "content-type": "application/json",
      [TIMESTAMP_HEADER]: result.timestamp,
      [MAC_HEADER]: result.macHex,
    },
  });
}

export async function readBoundedBody(
  request: Request,
): Promise<string | null> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength)) {
      return null;
    }
    const parsed = Number(declaredLength);
    if (!Number.isSafeInteger(parsed) || parsed > MAX_PROTOCOL_BYTES) {
      return null;
    }
  }
  if (request.body === null) {
    return "";
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value === undefined) {
        return null;
      }
      length += value.byteLength;
      if (length > MAX_PROTOCOL_BYTES) {
        void reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      body,
    );
  } catch {
    return null;
  }
}
