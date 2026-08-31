# QTS live canary

This runbook defines the bounded live admission test for one immutable Portable
GHAR runner image on RhoNAS. LabMacPro remains the active production runner and
immediate rollback/failback path throughout. JOHN-MBP is prohibited as a
runtime, staging, control, or deployment host.

Passing this runbook admits only the exact payload and observed RhoNAS host
profile. It does not grant ordinary acquisition authority, change consumer
routing, install a dark observer, or authorize retirement of LabMacPro.

## Exact identities before mutation

The private execution packet binds one signed merged product SHA and tree, one
new immutable release tag, the version-2 source-release manifest and evidence,
the identical Build A/Build B payload digest, the OCI image digest, checksums,
SBOM, provenance, attestations, canary repository and workflow revision, and
one operation-specific selector.

Before any RhoNAS write, positively read back all of the following in one
bounded inventory:

- LabMacPro control-host identity, current production runner registrations,
  selectors, active workload health, and its unchanged rollback command;
- the control path from LabMacPro to the exact RhoNAS target;
- RhoNAS hostname, QTS identity, Linux architecture, Docker binary and server
  version, Docker root, daemon configuration and restart identity, target
  storage devices/inodes/free space, CPU and memory, crond state, root cron,
  and the identities and configuration of unrelated preexisting containers and
  images;
- the exact release, image, and source-payload digests available for staging;
- the exact canary workflow revision and one pre-dispatched secretless job;
  and
- absence of the new selector from every LabMacPro registration and every
  existing RhoNAS registration.

A mismatch, missing field, stale observation, or ambiguous identity is a stop.
Do not repair an unexpected host, registration, cron line, or container as a
side effect of this canary.

## Disjoint one-job authority

The selector is a private scalar with the fixed shape
`rhonas-canary-ephemeral-<operation-digest-prefix>`. The canary workflow targets
that selector directly and never the consumer `PORTABLE_GHAR_ROUTE`
expression. LabMacPro and RhoNAS therefore cannot race for the same job.

Each operation uses one pre-dispatched, secretless job and one fresh JIT
registration for an ephemeral runner in the qualified immutable image.
`DisableUpdate` is required. GitHub's native assignment is the only authority
for that job; the canary adds no controller, observer, watchdog, cron, queue,
scheduler, retry loop, fence owner, or persistent permit service.

The private operation record follows one closed state machine:

```text
prepared -> dispatched -> assigned -> completed -> reclaimed
                                \-> failed-or-ambiguous -> disarmed
```

Record the workflow run and job identities before starting the candidate.
Status reads use one overall deadline. A definite dispatch rejection that
proves no run or job was created may be corrected only under a new operation
ID. Once dispatch is accepted, never redispatch that operation. A local startup
interruption may resume the same operation only when authoritative readback
proves its recorded job is still queued and unassigned, no registration or job
effect occurred, and the operation has not consumed its one permitted JIT
registration. A timeout or conflicting readback is `failed-or-ambiguous`, never
permission to submit another run.

Candidate secrets are written only to a private, mode-restricted ephemeral
file or descriptor supported by the existing runtime, never argv, logs, the
repository, an image layer, or persistent QTS configuration. Destroy or revoke
only an exact known candidate credential and positively read back its absence.

## Approved sizing and resource bounds

Reuse the validator-proven sizing tuple; do not re-derive or silently widen it.
Its binding digest is
`1e675e7d01ab33306e2c8fbcd86c2379aa5475f949363b30d0904c53847d841e`:

- `/runner` tmpfs 3 GiB, `/tmp` 512 MiB, scratch 512 MiB;
- runner memory 5 GiB, memory plus swap 10 GiB, and PIDs 512;
- cgroup p99 3.5 GiB plus 1 GiB process margin; and
- one-minute reclamation cadence.

The tuple permits at most four production runners, but this canary uses exactly
one. Capture CPU, iowait, available memory, storage free bytes and inodes, PID
count, container count, and QTS/Docker health before, during, and after every
job. Any configured threshold breach, unbounded growth, or degraded shared
service disarms the candidate. It never triggers a whole-Docker or QTS restart.

Private overlay values remain mechanically sourced: operator-signed sizing and
retention terms, live RhoNAS host/storage/profile observations, release-derived
manifest and image digests, and validator-fixed Linux/amd64, QTS, disabled,
network, egress, and health-sink values. Do not hand-author live-captured or
release-derived identity fields.

## Three-job stability window

Run three controlled jobs serially with fresh operation IDs and JIT
registrations but the same immutable image, source payload, RhoNAS identity,
Docker identity, sizing tuple, and workflow revision. Never have two canary
jobs or candidate containers eligible at once.

After each job, positively prove:

- the exact run and job ID, workflow revision, selector, self-hosted
  environment, runner name, listener version, and successful terminal result;
- exactly one assignment and one effect marker, with no duplicate run, job,
  runner, listener, or external effect;
- zero remaining candidate container, listener, registration, worktree,
  tmpfs, update staging, socket, namespace, and secret material;
- the exact admitted candidate image remains at its expected immutable digest;
- Docker daemon binary, server, root, configuration, and restart identity plus
  the identities and configuration of unrelated preexisting containers and
  images are unchanged, and crond state and unrelated root cron bytes are
  unchanged;
- every observed resource remains within the approved bounds; and
- LabMacPro is healthy and authoritative on its original production selectors.

Between successful jobs two and three, exercise candidate-only recovery on job
three's already queued run and recorded operation. Interrupt only its local
pre-registration startup gate. If authoritative readback proves that exact job
is still queued and unassigned, no registration or job effect occurred, and
the operation has not consumed its one permitted JIT registration, reclaim the
local startup residue and resume the same operation, run, and job through that
registration. Do not create a new operation ID or dispatch another run. Any
missing, conflicting, or effect-bearing readback disarms the canary and stops.
Never restart the shared Docker daemon or RhoNAS while legacy or unrelated
workloads may be active.

The stability window is these three serial jobs plus the bounded interruption
and resource observations. It is not a permanent observer, soak daemon,
watchdog, or cron.

## Failure, cleanup, and rollback

On any failed or ambiguous readback:

1. stop new canary dispatch;
2. stop and remove only the exact candidate container when its identity is
   known;
3. delete or revoke only the exact candidate registration or credential when
   its identity is known;
4. preserve an unknown or mismatched remote effect for adjudication rather
   than broadly deleting or retrying it;
5. prove the exact candidate image remains at its admitted digest, zero known
   candidate runtime residue, unchanged Docker daemon and unrelated preexisting
   container/image identities, and unchanged QTS crond/root-cron state; and
6. positively re-read LabMacPro health and production authority.

The rollback path is disarm-and-remove of the QTS candidate. LabMacPro needs no
automatic failover action because it was never drained, relabeled, stopped, or
used for the canary. Do not dispatch a replacement LabMacPro copy of a canary
job that may already have taken effect.

## Expansion boundary

Three green jobs and candidate-only recovery admit the exact source-built
payload and RhoNAS host profile. They do not prove the ordinary Worker
maintenance client, signed execution packet, production acquisition lease,
consumer route change, full capacity, or retirement gate.

Proceed into the existing production migration only when those pre-existing
authority and execution-packet gates are positively present and bound to the
same exact release. Otherwise stop with LabMacPro healthy and authoritative,
retain the immutable release and sanitized canary evidence, and report the
production-migration blocker separately.
