# Portable-GHAR Task 11 Split Structural Observer Amendment

## Scope and reason

This amendment corrects one load-bearing ordering defect in the reviewed
Task 11 synthetic lifecycle plan. A listener-bearing runner may stop when its
listener exits. At that point Docker can report `State.Pid=0` and can already
have removed the runner cgroup even though the stopped container object still
exists. Therefore a structural observer first armed after attach EOF cannot
truthfully capture the runner's live cgroup, process-membership, or namespace
identities.

No missing post-exit identity may be defaulted, reconstructed from a container
name, inferred from absence, or discovered by a host-wide scan.

## Revised one-use observer

The observer has the closed states:

```text
unarmed
structural-armed
outcome-sealed
proved
failed
```

Every error is terminal. Every transition is one-use. No transition emits a
cleanup boolean, cleanup observation, or cleanup digest except
`outcome-sealed -> proved`, after state-aware cleanup.

### Structural arm

`ArmStructural` runs while the exact engine-issued managed objects are still
live and before listener release can stop the runner. It consumes:

- the validated primary and direct-child cycle bindings;
- the exact engine-issued `ManagedSnapshot`;
- the immutable `RecoverySpec`;
- the exact expected managed presence/running vector;
- the production capacity-slot and job-generation tuple;
- the exact static cgroup version and private process/descriptor limits; and
- the exact authority expectation for that stage.

It captures only fixed, exact identities:

- exact container IDs and immutable image/mount/tmpfs facts;
- the runner's existing versioned cgroup path set;
- the bounded current cgroup member PID/start-time records;
- namespace identities held by the bounded same-cgroup process set;
- bounded descriptor target identities;
- Docker's exact network-sandbox path and identity;
- exact authority and relay directory/socket identities; and
- exact declaration-ordered cycle-root entries.

The cgroup path set is the authoritative membership boundary across a
hold-to-listener process replacement. Pre-release PIDs are retained as exact
supplemental identities but are not, by themselves, proof that every later
listener process was reclaimed. A cgroup path missing at `ArmStructural`
fails; `State.Pid=0` is never admitted as a live structural capture.

### Outcome seal

`SealListenerOutcome` is allowed exactly once after attach EOF and the
scenario's indivisible attach/container-exit predicate succeeds. It consumes
only the already parsed, exact bound stream and exit result:

- normal rows require boundary plus terminal and exit `0`;
- crash requires its one boundary, no terminal, and exit `70`; and
- upgrade interruption requires its one boundary, no terminal, and exit
  `71`.

It binds the outcome to the same cycle run digest, cgroup version, runner ID,
and structural-arm seal. Listener high-water values enter only through a
valid normal terminal. It performs no new `/proc`, cgroup, namespace, mount,
or path discovery.

`SealNoListenerOutcome` is the only alternate seal. It is allowed only for:

- caller cancellation after exact `RELEASE_ARMED`, before secret construction
  or `Release`;
- the exact pre-delegate `StageRunnerAuthorize` injected failure; and
- one controller-restart subcycle after exact durable checkpoint and fresh
  recovery inventory validation.

It requires exact proof that no attach was started and no listener-release
effect completed or became ambiguous. It contains no terminal, high-water,
listener frame, or exit value.

### Prove

After the row's state-aware production cleanup, `Prove` may re-read only the
identities frozen by `ArmStructural` and the immutable binding:

1. fresh exact-label `InspectManaged` is empty and direct fixed inspect of
   every captured container returns exact not-found;
2. every captured cgroup path is absent;
3. every captured PID is absent or has a different canonical start time;
4. captured namespace ownership is gone because its exact cgroup paths,
   bounded members, sandbox path, and containers are gone;
5. captured sandbox, authority, relay, and socket identities are absent;
6. the authority tuple is inactive with no exact claimant;
7. exact relay/authority/temp/work/update paths are absent;
8. the cycle root contains no unexpected entry, is removed by its stable
   descriptor-relative lease, and is `Lstat`-absent; and
9. immutable payload count remains exactly one.

Only after every closed predicate is true may `Prove` marshal the canonical
13-assertion cleanup observation and derive the cleanup observation digest.

## Listener-bearing normal sequence

The exact sequence is:

1. create and validate the empty direct-child cycle root;
2. build the production composition and seed the durable assignment;
3. call production `Prepare` through `RELEASE_ARMED`;
4. obtain the exact live `ManagedSnapshot`;
5. start fixed `docker attach` before `Release`;
6. `ArmStructural` while the held runner has nonzero PID and live cgroup;
7. construct the canonical synthetic secret;
8. call production `Release`;
9. validate attach EOF, exact container exit readback, and closed stream;
10. `SealListenerOutcome`;
11. for normal rows, advance adjacent `JOB_RUNNING -> JOB_FINISHED`;
12. perform state-aware `DestroyLive`;
13. call `Prove`;
14. persist the exact adjacent normal destroy or post-release resolution;
15. require terminal offer replay; and
16. return the sealed row result.

Attach still starts before `Release`. Structural arming may occur immediately
before or after attach start, but both must precede `Release`; source uses the
fixed order above. No cleanup evidence exists before step 13.

## Non-listener and restart rows

Cancellation and pre-listener-failure rows call `ArmStructural` from their
exact held inventory, then `SealNoListenerOutcome`, then execute independent
state-aware cleanup and `Prove`.

Each restart subcycle first loses process-local setup handles at the durable
post-`Complete` tripwire. Fresh recovery then validates the exact table row,
obtains a fresh exact `ManagedSnapshot`, calls `ArmStructural` while any
captured objects still exist, and calls `SealNoListenerOutcome` before exact
authority shutdown and `RemoveManaged`. Stages with no runner still require
the exact adapter/broker inventory and authority expectation from the
normative restart table; the runner-specific cgroup/process/namespace capture
is absent rather than defaulted.

## Rejection tests

Tests must reject:

- first structural capture after attach EOF;
- `State.Pid=0`, missing cgroup, or empty substituted cgroup path at arm;
- structural re-arm after listener exit;
- listener outcome seal before the exact joint predicate;
- no-listener seal after attach start or any listener-release effect;
- any high-water value in a no-listener seal;
- proof before outcome seal or before cleanup;
- post-exit adoption of a new PID, cgroup, namespace, sandbox, or path;
- treating pre-release PIDs alone as complete membership proof;
- cgroup absence before cleanup being accepted as cleanup evidence; and
- stable-container-object presence being substituted for live structural
  identity.

## Unchanged boundaries

This amendment does not change the listener protocol, production runner
runtime, Docker resource limits, immutable image, seed catalog, assignment
state machine, post-release evidence formula, exact cleanup catalog, host
configuration, numeric sizing, or operator-gated target execution.

## Distinct-family confirmation

The exact 7,570-byte amendment at SHA-256
`24710328b60bd45c9679f676728718d58d273459de748c5097717d5298bd2016`
received a direct, broker-bypassed xAI/Grok 4.5 high-effort adversarial
architecture verdict of `PROCEED` on 2026-07-29. The reviewer confirmed that
the pre-release cgroup-path capture is the authoritative membership boundary
across hold-to-listener process replacement, that pre-release PIDs remain
supplemental, and that outcome sealing introduces no post-exit structural
rediscovery. It reported no remaining material design gap.
