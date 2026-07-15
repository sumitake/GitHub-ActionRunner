import { expect, test } from "vitest";

import { HEARTBEAT_PROTOCOL_VERSION } from "../../src/protocol/version";

test("heartbeat protocol version is 1", () => {
  expect(HEARTBEAT_PROTOCOL_VERSION).toBe(1);
});
