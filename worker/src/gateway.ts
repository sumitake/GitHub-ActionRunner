import { handleHeartbeat, type HeartbeatSecrets } from "./engine/heartbeat";
import { handleSession, type SessionSecrets } from "./engine/session";
import {
  HEARTBEAT_PATH,
  MAC_HEADER,
  SESSION_PATH,
  TIMESTAMP_HEADER,
} from "./protocol/auth";
import { parseCanonical } from "./protocol/canonical";
import { FLEET_ID } from "./protocol/messages";
import type { MemoryFleetStore } from "./state/memory";

export type GatewaySecrets = HeartbeatSecrets & SessionSecrets;

export type FleetGateway = {
  inventoriedFleetIds: readonly string[];
  secrets: GatewaySecrets;
  storeFor(fleetId: string): MemoryFleetStore | undefined;
};

function rejected(): Response {
  return Response.json({ error: "rejected" }, { status: 401 });
}

function fleetIdFromBody(body: string): string | null {
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
  const path = new URL(request.url).pathname;
  if (path !== SESSION_PATH && path !== HEARTBEAT_PATH) {
    return rejected();
  }
  const timestamp = request.headers.get(TIMESTAMP_HEADER) ?? "";
  const macHex = request.headers.get(MAC_HEADER) ?? "";
  if (timestamp === "" || macHex === "") {
    return rejected();
  }
  const body = await request.text();
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
      : await handleSession(store, gateway.secrets, input);
  return new Response(result.body, {
    status: result.status,
    headers: {
      "content-type": "application/json",
      [TIMESTAMP_HEADER]: result.timestamp,
      [MAC_HEADER]: result.macHex,
    },
  });
}
