# Portable-GHAR Task 11 Restart Cleanup Aggregate Amendment

Author: openai/gpt-5.6-sol
Date: 2026-07-29
Scope: source design and Linux integration harness only; no host mutation and
no operator sizing selection

## Reason for this amendment

The controller-restart cleanup row is one public matrix row, but it exercises
all sixteen declaration-ordered durable setup stages. Each stage is a fresh
child cycle with its own assignment, managed-resource inventory, structural
observer, cleanup proof, durable `DESTROYED` state, and terminal offer replay.

The prior reviewed amendments correctly require all sixteen child cycles, but
do not specify how those sixteen `CompleteCleanupProof` values become the one
`CompleteCleanupProof` returned for the controller-restart matrix row. Picking
one child proof would erase fifteen stages. Returning sixteen public rows would
change the frozen conformance schema. Hashing an unordered set would permit
stage substitution or reordering.

This amendment defines one closed, declaration-ordered aggregate. It changes
no public matrix shape and chooses no operating value.

## Non-negotiable boundaries

1. The aggregate is produced only after every child cycle has independently
   completed the reviewed restart sequence: fresh recovery, exact inventory,
   structural arm, no-listener seal, authority shutdown when applicable,
   `RemoveManaged`, positive absence proof, durable `DESTROYED`, and exact
   terminal offer replay.
2. A partial aggregate is never returned. Any missing, repeated, reordered,
   failed, ambiguous, or extra child fails the controller-restart row.
3. Child cleanup evidence remains the existing thirteen-assertion
   `task11synthetic.CleanupObservation`. The aggregate cannot replace a child
   observer, infer child absence, or turn an attempt into a proof.
4. The public cleanup matrix remains exactly six rows. The controller-restart
   row remains one `CompleteCleanupProof`.
5. The aggregate is test-harness evidence only. It adds no production API,
   command, environment variable, report loader, recovery authority, or host
   probe.
6. No host, QTS, Docker daemon, service, runner, selector, broker, sizing
   value, cadence, timeout, or concurrency setting changes under this
   amendment.

## Closed aggregate contract

The source adds this semantic domain:

```text
portable-ghar.task11.restart-cleanup-aggregate.v1\0
```

The input parent is the existing
`cleanup-controller-restart` cycle identity. The aggregate accepts exactly the
sixteen values returned by `task11synthetic.RestartSetupStages()` in their
declaration order.

The observer's existing public-facing `Prove` result is not sufficient
provenance for this aggregate because `CompleteCleanupProof` deliberately
omits its cycle binding and canonical observation. The implementation
therefore adds one harness-private `task11SyntheticProvedCleanup` value,
constructible only by the successful one-use observer proof transition. It
retains:

```text
exact immutable observer binding
canonical task11synthetic.CleanupObservation
derived CompleteCleanupProof
structural-capture seal
outcome seal
```

Its validator re-runs `task11CleanupObservationMatchesBinding`, recomputes the
single-child cleanup-observation digest under the existing domain, and
requires exact equality with the retained `CompleteCleanupProof`. Normal rows
may immediately project `.Proof`; restart aggregation retains the private
value through accept-time validation.

Each private aggregate entry is a fixed struct with:

```text
setup_stage
declaration_index
child_cycle_run_digest
child_cleanup_digest
containers_absent
cgroups_absent
tmpfs_absent
work_absent
work_update_absent
processes_absent
namespaces_absent
sockets_absent
authorities_absent
temporary_files_absent
host_backed_work_absent
unexpected_objects_absent
payload_version_count
assertion_count
child_observation_digest
assignment_destroyed
terminal_offer_replay
```

For entry index `i`:

- `setup_stage` equals `RestartSetupStages()[i]`;
- `declaration_index` equals `i`;
- `child_cycle_run_digest` equals
  `DeriveRestartCycleRunDigest(parent.RunDigest, setup_stage, i)`;
- `child_cleanup_digest` equals
  `DeriveCleanupDigest(child_cycle_run_digest)`;
- every absence boolean is true;
- `payload_version_count` is exactly `1`;
- `assertion_count` is exactly `13`;
- `child_observation_digest` equals the digest in the retained
  `task11SyntheticProvedCleanup`, whose canonical observation carries the same
  child cycle run digest, child cleanup digest, cgroup version, and thirteen
  exact assertions;
- `assignment_destroyed` is derived from a private success-completion token
  minted only after exact assignment/effect readback reports durable,
  nonambiguous `DESTROYED`; and
- `terminal_offer_replay` is derived from that same token only after replaying
  the original exact offer/evidence returns the production
  `OfferTerminalReplay` disposition, exact assignment key, and
  `StateDestroyed`.

All child run digests, cleanup digests, and observation digests must be
pairwise distinct. The aggregate rejects a valid proof borrowed from another
stage, parent, row, ordinal, run, cgroup version, or root.

The canonical aggregate wire is a fixed JSON struct:

```text
schema_version = 1
protocol_id = portable-ghar-task11-synthetic-v1
parent_cycle_run_digest
parent_cleanup_digest
cgroup_version
stage_count = 16
stages = the exact fixed entries above in declaration order
containers_absent = true
cgroups_absent = true
tmpfs_absent = true
work_absent = true
work_update_absent = true
processes_absent = true
namespaces_absent = true
sockets_absent = true
authorities_absent = true
temporary_files_absent = true
host_backed_work_absent = true
unexpected_objects_absent = true
payload_version_count = 1
assertion_count = 208
```

`parent_cleanup_digest` must equal
`DeriveCleanupDigest(parent_cycle_run_digest)`. `assertion_count` is the exact
checked product `16 * 13`; it is not caller-selected. The twelve aggregate
absence booleans are conjunctions of the corresponding child fields.
`payload_version_count` is the invariant immutable payload count, not a sum.

Canonicalization uses the same fixed-struct `json.Marshal` rules as the
existing synthetic protocol, with no maps, omitted fields, arbitrary values,
or trailing LF inside the hash. The aggregate observation digest is:

```text
sha256(
    "portable-ghar.task11.restart-cleanup-aggregate.v1\0" ||
    canonical_aggregate_json
)
```

That digest becomes the controller-restart row's
`CompleteCleanupProof.ObservationDigest`. Its other fields are the aggregate
booleans, payload count `1`, and assertion count `208`.

The aggregate digest is deliberately distinct from the existing
single-child cleanup-observation domain. It cannot be passed to
`DerivePostreleaseResolutionEvidence`, substituted for any child observation,
or accepted by the child observer. The public row seal may accept it only
through the controller-restart-specific aggregate validator.

## Harness-private accept-time evidence bundle

`CompleteCleanupProof` alone is explicitly insufficient to accept or
revalidate the restart row. The driver returns a harness-private
`task11SyntheticRestartAggregateEvidence` to the lifecycle coordinator. Its
closed fields are:

```text
parent task11SyntheticCycleIdentity
children [16]task11SyntheticRestartChildEvidence
aggregate CompleteCleanupProof
```

Each child evidence value contains:

```text
stage and declaration index
derived child task11SyntheticCycleIdentity
retained task11SyntheticProvedCleanup
private success-completion token
private cycle-owner removal snapshot
```

The success-completion token is not a caller boolean. Its constructor consumes
the exact original offer/evidence, the `RecordOffer` terminal replay receipt,
the final store/effect readbacks, and the same child assignment key, then
retains only the closed proof fields needed by the aggregate wire. It has no
failure-path constructor.

The cycle-owner removal snapshot is likewise not a caller boolean. The owner
itself freezes it only after every handle registered to that child reports
`RecordedRemoved=true`; it carries the exact child run digest and ordered
registered-handle digest. Emergency or state-aware failure cleanup may remove
objects and handles but cannot mint this success-only frozen snapshot.

The controller-restart-specific validator consumes the whole bundle while the
private children are still present. For every index it:

1. derives the stage and child cycle identity again from the parent;
2. validates the retained canonical child cleanup observation against the
   child's exact observer binding;
3. recomputes the existing single-child observation digest and requires it to
   equal both the child proof and aggregate entry;
4. validates the private success-completion token against the same assignment
   key and derived child cycle;
5. validates the cycle-owner removal snapshot against the same child run
   digest and its complete registered-handle set; and
6. only then recomputes the aggregate wire and aggregate digest.

Only after the validator succeeds may the coordinator project the one public
`CompleteCleanupProof` into the six-row cleanup matrix. The private evidence
bundle is consumed once and discarded; it is not serialized into the public
report.

## Construction and ownership order

The driver retains the parent restart cycle identity while iterating children.
For each child, it:

1. derives the exact stage child identity;
2. records the child aggregate cleanup handle before creating its root;
3. runs the reviewed restart tripwire and recovery path;
4. obtains the private `task11SyntheticProvedCleanup` only from the child's
   one-use observer after cleanup;
5. verifies exact `DESTROYED` state and terminal offer replay and mints the
   private success-completion token;
6. verifies every child-owned handle removed and freezes the cycle-owner
   removal snapshot; and
7. appends one immutable private child evidence value.

The parent aggregate is sealed only after step 7 succeeds for the sixteenth
stage. Outer fixture cleanup may invoke any recorded child handle after a
failure; the cycle owner must execute state-aware or emergency cleanup once
for that child and mark all of that child's handles removed. It may not mark
another child removed or synthesize an aggregate proof during failure cleanup.

There are separate success and failure paths. Any child error, panic other
than the exact restart sentinel, ambiguous readback, cleanup failure, observer
failure, replay mismatch, or unexpected object irreversibly marks the parent
builder failed. Failure cleanup may reclaim resources but can neither append a
child evidence value nor call the aggregate sealer. The aggregate sealer
requires the builder's declaration-ordered completion vector to be exactly
sixteen successful values and its failure bit to be false.

## Consumer validation

The synthetic lifecycle coordinator applies a controller-restart-specific
validator to the complete private evidence bundle before accepting the
projected result:

- kind and ordinal are exact;
- the success vector contains exactly stages zero through fifteen and the
  builder failure bit is false;
- every retained child cleanup evidence, success-completion token, and
  cycle-owner removal snapshot validates under the same derived child
  identity;
- all aggregate fields and the exact 208 assertion count are recomputed from
  those validated children;
- recomputing the aggregate from its private stage entries yields the returned
  digest;
- the digest has not appeared in any earlier cleanup row or child; and
- no per-listener result, reclamation resource, or staging result accompanies
  the row.

Other cleanup rows continue to require a single observer proof with exactly
thirteen assertions. This prevents a composite proof from being smuggled into
a normal row and prevents a normal proof from satisfying controller restart.

## RED tests before implementation

Tests must reject:

- zero, fifteen, seventeen, or duplicate stage entries;
- skipped or reordered stages;
- wrong declaration index;
- a child digest derived from the parent or another stage;
- repeated child run, cleanup, or observation digest;
- any false absence predicate or payload count other than one;
- any child assertion count other than thirteen;
- missing durable `DESTROYED` or terminal replay proof;
- aggregate assertion count other than 208;
- a valid child proof presented as the aggregate;
- an aggregate proof presented as a normal cleanup row;
- aggregate sealing before the final child is removed and replayed;
- failure cleanup being converted into a passing aggregate; and
- noncanonical or map-based aggregate encoding.

Tests also construct a self-consistent private-entry array with derived child
run/cleanup digests, arbitrary distinct observation digests, all-true
booleans, and true completion flags, but no retained observer evidence,
success-completion tokens, or owner-removal snapshots. The accept-time
validator must reject it.

## Distinct-family review trace

Direct, broker-bypassed xAI/Grok 4.5 high-effort review of the initial
8,679-byte artifact at SHA-256
`7545cfcfd830b3dc8cb4c55d63f884af20e3e473cc680e4444f50b717eb5df0f`
returned `REVISE`. It correctly found that `CompleteCleanupProof` alone cannot
support aggregate recomputation, that private entries were not yet bound to
retained observer-produced child evidence, and that failure cleanup needed a
validator-visible success/failure distinction. This revision integrates all
three findings.

The exact revised 13,932-byte artifact at SHA-256
`591dac2c6e46af3acb646a3d49322a9bb9e605653766a87fe1144cec4a4f290c`
then received a direct, broker-bypassed xAI/Grok 4.5 high-effort confirm
verdict of `PROCEED` on 2026-07-29. Session
`019fb092-4b7b-7182-98b4-4a3613b64ee1`, request
`ab8b16bd-885e-4b47-9266-ec8182ecf797`. The reviewer found no remaining
material gap in accept-time provenance, exact stage identity, success-only
sealing, ordering, replay, single-child confusion, or six-row compatibility.

## Success condition

The design is complete when a distinct-family reviewer confirms that the
aggregate preserves all sixteen independently proved restart stages without
changing the public six-row schema, admits no partial or reordered success,
and cannot be confused with a single-child cleanup observation.
