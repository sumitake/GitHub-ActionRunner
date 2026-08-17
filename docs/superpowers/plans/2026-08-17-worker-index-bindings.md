# Worker index bindings

**Goal:** The Worker `fetch` entrypoint uses `dispatchFleetRequest` when inventory and secrets parse, and stays 401 when they do not.

**Also landed:** SQLite load/save of the six-table fleet store, and Cron scheduling only when inventory bounds and an execute client are present. Still no live GitHub or Cloudflare deploy.

**Why this is small:** The router and MemoryFleetStore already exist. `index.ts` is still a dead 401 switch. Wiring it without a complete SQL adapter or a GitHub client is the honest next step. The isolate store is not crash-safe; the DO remains the future SQLite authority and keeps failing closed.

## Failure modes

| Input | Degradation |
| --- | --- |
| Missing/invalid HMAC key | 401 |
| Missing/invalid fleet inventory | 401 |
| Any timeout/duration unset or non-positive | 401 |
| Unknown fleet id | 401 |
| Durable Object / SQL not implemented | unused; not claimed |

No numeric defaults. Operator supplies every bound.

## Implementation

- `worker/src/bindings.ts` — parse env into gateway secrets + fleet ids, or `null`
- `worker/src/index.ts` — `handleWorkerFetch` calls `dispatchFleetRequest`
- Tests for reject/accept parse and a signed heartbeat through the handler
