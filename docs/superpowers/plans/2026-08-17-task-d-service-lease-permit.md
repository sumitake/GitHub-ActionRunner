# Task D: Service lease-permit binding

**Goal:** Prove `controller.Service` can be constructed with `failoverclient.CachedLeasePermitProvider` and that acquisition fails closed without a current matching lease.

**Architecture:** The disabled observer remains the production process. The permit provider stays a local cache check (no HTTP, no remote per-operation record). Task D is the Service binding and its tests, not live enrollment.

**Not in this slice:** Worker `index` wiring, heartbeat HTTP, overlay Worker URL/HMAC, GitHub canary run identity, notification delivery, listener/Ack journal, starting `Service` from `production_controller.go`.

---

## Why this slice is small

Earlier P1 rounds tried to hang a lease graph on the disabled observer. That lied: the observer must not acquire. The honest seam is `ServiceConfig.Permits`. `NewService` already requires a non-nil provider. This slice replaces the test stub with the real cached-lease provider and locks the fail-closed cases.

## Threat model

An acquisition call must not proceed unless a process-memory lease is present, unexpired, and exact on holder, fence, policy digest, and local policy epoch. Missing, stale, or expired authority is deny. The disabled production path must not gain a permit provider.

Bypass classes this slice must keep closed:

- empty cache
- incapable or missing clock
- holder / fence / digest / epoch mismatch
- archive alias
- canary scale-set mismatch
- lease past `LocalDeadline`
- `Close` after the operation deadline
- constructing `Service` with `Permits == nil` (already rejected)

## Failure modes

| Dependency | Failure | Degradation |
|---|---|---|
| Lease cache | empty / missing | `Acquire` denies |
| Authority clock | unsupported / error | `Acquire` denies |
| Deadline terms | unset call duration or tail | `Acquire` denies |
| Installed lease | expired or mismatched | `Acquire` denies |
| Production process | no Worker enrollment | stays `unavailableExternalGraph` |

No retry, no failover to a stub permit, no network.

## Implementation

### 1. Fail-closed constructor

**Files:**
- Modify: `internal/failoverclient/permit.go`
- Test: `internal/failoverclient/permit_test.go`

`NewCachedLeasePermitProvider` rejects missing cache, incapable clock, zero fence, unset deadlines, or an invalid holder. `Acquire` and `Close` stay as they are.

A same-package `controller.Service` test cannot import `failoverclient` (import cycle). The provider already satisfies `controller.AcquisitionPermitProvider`. When a future enrollment path constructs `Service`, it uses this constructor. This slice does not invent a second stub island to force `NewService` in the controller package.

### 2. Keep production honest

No change to `production_controller.go`. The disabled observer still uses `unavailableExternalGraph`.

## Verification

```sh
GOTOOLCHAIN=go1.26.6 go test ./internal/controller ./internal/failoverclient ./cmd/portable-ghar-controller -count=1
npm run worker:test
```

Worker tests are a no-change regression check.

## Distinct-family plan review

No distinct-family reviewer is available in this session. Self-adversarial check: the slice does not add HTTP, does not populate a cache from nothing, and does not attach permits to the disabled observer. Those were the previous fail-open/lie paths.
