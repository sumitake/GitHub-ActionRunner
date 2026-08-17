import {
  ADMIN_COMMAND_PATH,
  ADMIN_STATUS_PATH,
  HEARTBEAT_PATH,
  SESSION_PATH,
} from "./protocol/auth";

export { FleetDurableObject } from "./state/durable";

// The Worker entrypoint stays fail-closed until inventory, HMAC secrets,
// and a fleet store are bound. dispatchFleetRequest is the testable router.
export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST") {
      return Response.json({ error: "rejected" }, { status: 401 });
    }
    switch (url.pathname) {
      case SESSION_PATH:
      case HEARTBEAT_PATH:
      case ADMIN_COMMAND_PATH:
      case ADMIN_STATUS_PATH:
        return Response.json({ error: "rejected" }, { status: 401 });
      default:
        return Response.json({ error: "rejected" }, { status: 401 });
    }
  },
  async scheduled(): Promise<void> {
    return;
  },
};
