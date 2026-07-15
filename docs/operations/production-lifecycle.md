# Production lifecycle

This runbook describes the intended production lifecycle of a Portable
GHAR deployment: the controller's persisted states, its safe-upgrade
sequence, the host-profile probes a deployment must pass, and the
zero-capacity dark-deployment step every install starts from. It assumes
the components in [Architecture overview](../architecture/overview.md)
and the boundaries in [Trust boundaries](../security/trust-boundaries.md).
All commands shown here are synthetic and illustrative -- they describe
the shape of an operator's positive read-back gate, not a real
deployment's paths, hosts, or credentials.

Phase 1 of this repository ships no runtime controller. This page
describes the intended lifecycle the later runtime phases implement; it is
not a claim that any of the states or gates below are live today.

## Persisted controller states

Each job assignment the controller accepts is tracked through a persisted
state machine, checkpointed at every real external effect:

```text
RECEIVED -> CAPACITY_RESERVED -> ADAPTER_CREATED -> ADAPTER_VERIFIED
  -> BROKER_HELD -> BROKER_POLICY_APPLIED -> DIAL_AUTHORITY_READY
  -> BROKER_RELEASED -> EGRESS_VERIFIED -> RUNNER_HELD -> RELEASE_ARMED
  -> LISTENER_RELEASED -> JOB_RUNNING -> JOB_FINISHED -> DESTROYED
```

Persistence exists so a controller restart -- planned or crash-induced --
can reconcile every in-flight assignment to exactly one terminal outcome
without ever duplicating a runner or double-accepting a job. A transition
that is repeated after a restart is always either a no-op or the
completion of the interrupted step.

Acquisition policy itself (mode, eligible scale sets, capacity, and
per-repository policy) is also persisted, and every change to it passes
through one bounded epoch barrier before taking effect: stale in-flight
operations are cancelled and joined, and an operation the controller
cannot join in time makes the controller fail closed rather than let a
stale operation acquire capacity under superseded policy.

## Safe upgrade sequence

An upgrade never replaces a running controller in place while it might
still be accepting work. The intended sequence is:

1. enable the Worker-owned hosted hold and positively read back every
   configured repository routed to GitHub-hosted runners;
2. stop new acquisition and drain or cancel assigned jobs per policy;
3. prove zero listeners, adapters, brokers, helpers, verifiers, and
   per-job sockets remain -- retained ledger state stays retained, not
   reused, until its retention window expires;
4. replace the pinned controller binary and images, then run compatibility
   and host-profile probes;
5. start the replacement disabled, and clear every open queue-risk row
   through authenticated GitHub read-back before any new acquisition;
6. set canary-only intent, release the hosted hold into a new recovery
   epoch, and run one canary operation that must obtain a fresh Worker
   permit while consumer routing stays hosted; and
7. only after that canary passes, and a fresh heartbeat proves full
   acquisition capacity, does the failover state machine permit
   self-hosted routing to resume.

An illustrative operator gate read for step 1 of this sequence:

```operator-command
portable-ghar status --expect-route hosted --expect-hold true
```

Host lifecycle changes use a durable operation journal keyed by an
idempotent operation ID; a rerun after a crash resumes or compensates
forward rather than repeating an already-applied effect. An upstream
compatibility failure leaves acquisition disabled and hosted routing
unchanged.

## Host-profile probes

A host is only eligible to acquire work after it positively proves,
rather than merely declares, every required property: supported
Docker/runtime version and kernel features; CPU, memory, PID, tmpfs,
read-only-root, seccomp, and capability enforcement; non-root execution or
an explicitly acknowledged, visibly flagged degraded-root profile; checked
free-byte and free-inode headroom on every filesystem the controller
writes to; complete egress-policy enforcement observed from an actual
runner namespace; no access to host Docker control or private paths from
inside a job; and reboot-persistent watchdog behavior. An unsupported host
profile fails closed rather than falling back to a weaker default.

## Dark deployment

A new Portable GHAR install is never handed live traffic on day one.
While an existing (legacy, or no) fleet still owns the host-local
fleet-generation fence, the new controller and watchdog start as a
**force-disabled, zero-capacity observer**: they may run, report local
health, and prove their own host-profile conformance, but they cannot
poll for work, acquire a job, or generate a JIT credential. Only an
explicit, fenced hand-off from the prior fleet to `portable` -- itself
gated on the safe-upgrade sequence above -- ever lets the observer begin
acquiring at nonzero capacity.
