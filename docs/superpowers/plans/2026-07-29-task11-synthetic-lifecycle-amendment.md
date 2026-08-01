# Portable-GHAR Task 11 Synthetic Lifecycle Amendment v4

Author: openai/gpt-5.6-sol
Date: 2026-07-29
Scope: source design and Linux integration harness only; no host mutation and
no operator sizing selection

## Why this amendment exists

The converged Task 11 plan requires the synthetic one-job, cleanup-matrix,
reclamation, and seed-isolation cases to use the same production runner and
network-jail path as an actual runner. The source implementation now has a
closed coordinator for those cases, but two load-bearing details were not
specified precisely enough to implement safely:

1. the plan names one immutable seed and a synthetic listener, but does not
   define the exact seed identifier or the listener's input/output protocol;
2. the controller-restart cleanup row must simulate loss of process-local
   handles after a durable setup checkpoint, but an in-process simulation
   would leave the `UnixAuthorityManager` goroutine and socket alive unless the
   integration harness has one exact, test-only shutdown capability.

This amendment closes those gaps. It does not choose a tmpfs size, cgroup
limit, timeout, cadence, sample count, concurrency, or other operator value.
It does not add a production recovery authority or a generic command surface.

The v1 Grok architecture review returned `REVISE` because the first draft was
category-closed but not byte/schema-closed. It required a normative listener
wire, exact matrix fault triggers, a restart stage/inventory table, a durable
crash-bag contract, named absence sources, and explicit cross-cycle seed
comparisons. This revision integrates every material finding.

The first v2 confirmation attempt returned typed broker `teardown_error` with
no review text, so it supplied no design verdict. A subsequent primary
self-adversarial pass found one material portability bug: Task 11 static
preflight permits cgroup version `1` or `2`, while v2 accidentally named only
cgroup-v2 measurement files. Continued source comparison also found that the
draft named a tmpfs listener path instead of the production gate's immutable
listener path, rejected valid cgroup-v1 controller co-mounts, omitted a
listener-side cgroup-version binding on nonterminal rows, and incorrectly
bounded a host-wide `/proc` scan by the runner process limit. This revision
closes those source-derived gaps with an exact role qualification pair,
version-bound measurement/cleanup, and captured-identity absence contract. It
does not infer review approval from the failed call.

The first direct Grok review of v3 examined the exact paired artifact
`49ffd0411f7dda29719928070763364310c26840788d09ad13a359a2500e6cd6`
and returned `REVISE`. Adjudication accepted its load-bearing requests for an
explicit two-phase pre/post-cleanup observer, exact non-listener row
inventories, a joint boundary/exit predicate, a jointly fresh cutover evidence
tuple, and a hard conformance/telemetry separation. This revision integrates
those requests.

Four review claims were narrowed against the artifact and source:

- the cgroup-v1 contract uses `memory` and `pids`, not a CPU metric; it already
  fixes the memory/memsw read order and rejects an unstable pair. This
  revision makes explicit that only normal terminal frames carry high-water
  values and that the complete terminal is bound to cycle, scenario, and
  cgroup version;
- the harness cannot construct listener frames from expected input. It
  accepts only the bounded attach bytes of the independently qualified image
  after the production relay path is the sole reachable egress. Adding a new
  broker-minted token would widen production protocol without closing a
  demonstrated path, so that suggestion is not adopted;
- the seed sequence already requires fixed absolute paths, fresh-copy/source
  equality, known mutation-digest inequality in cycle two, and exact
  post-mutation proof in cycle one. This revision restates those values as
  terminal acceptance predicates; and
- the role section already requires distinct image IDs, references, and
  digests, the role-specific version pair, and held-gate inventory equality.
  No additional dual-role predicate is needed.

## Non-negotiable boundaries

1. All implementation in this amendment is source-only. Do not modify a live
   runner, Docker daemon, QTS host, systemd unit, launchd job, selector, broker,
   or provider lifecycle.
2. The existing private conformance input remains the only source of images,
   sentinels, limits, profile identity, runtime identity, and authorization.
3. The synthetic listener image must be the already-qualified immutable
   `ConformanceInput.Images.SyntheticListener` binding. Source cannot substitute
   a tag, local build, actual runner image, or caller-selected executable.
4. Every synthetic cycle uses production `hostruntime.DockerCLI`,
   `networkjail.Orchestrator.Prepare`, and `networkjail.Orchestrator.Release`.
   No fake engine, direct `docker run`, alternate namespace setup, host bind,
   or lifecycle shortcut may produce passing integration evidence.
5. Synthetic input is not GitHub JIT. It contains no GitHub token, runner
   registration URL, repository identity, workflow identity, caller argv,
   caller environment, host path, container identity, or arbitrary field.
6. Synthetic output is a closed observation wire. Raw logs, token bytes,
   paths, process IDs, container IDs, socket names, errors, timings, and
   arbitrary key/value data are forbidden.
7. Cleanup evidence is accepted only after exact positive absence. A cleanup
   attempt, timeout, cancellation, or best-effort removal cannot pass a row.
8. The restart hook described below is compiled only for Linux integration
   builds. It is not part of the production authority interface and cannot
   mint release, cleanup, or conformance authority.
9. The checked pre-release terminal state transition remains
   `state.Store.AdvancePreReleaseDestroyed`. The harness must not invent a
   synthetic success state after an interrupted setup.
10. Any implementation need for another private value, executable, path,
    numeric operating value, or generic command is a stop condition requiring
    another reviewed amendment.

## Closed semantic identifiers

The implementation adds source constants whose values are protocol semantics,
not operator configuration:

```text
wire schema version       1
synthetic protocol ID     portable-ghar-task11-synthetic-v1
immutable seed ID         portable-ghar-task11-seed-v1
seed source relative path task11/portable-ghar-task11-seed-v1.bin
seed target               tools/portable-ghar-task11-seed-v1/payload.bin
seed source SHA-256       ef368121857519d3895e11481813b99d2e1d76d0555074a79d6af3ce9039e636
seed mutation SHA-256     bb69dc01bb526d5ce99678516845137b391164b6143d34140059650156ffc71f
HTTPS relay endpoint      127.0.0.1:18080
upgrade staging marker    /runner/_work/_update/portable-ghar-task11-upgrade-staging-v1
cycle digest domain       portable-ghar.task11.synthetic-cycle.v1\0
restart cycle domain      portable-ghar.task11.synthetic-restart-cycle.v1\0
job marker domain         portable-ghar.task11.synthetic-job-marker.v1\0
proxy proof domain        portable-ghar.task11.synthetic-proxy-proof.v1\0
response proof domain     portable-ghar.task11.synthetic-response-proof.v1\0
job completion domain     portable-ghar.task11.synthetic-completion.v1\0
registration domain       portable-ghar.task11.synthetic-registration.v1\0
cleanup digest domain     portable-ghar.task11.synthetic-cleanup.v1\0
cleanup evidence domain   portable-ghar.task11.cleanup-evidence.v1\0
postrelease domain        portable-ghar.task11.post-release-resolution.v1\0
seed mutation suffix      portable-ghar-task11-current-copy-mutation-v1\n
normal exit status        0
listener-crash status     70
upgrade-interrupt status  71
```

The seed ID is valid under the existing runner-gate seed grammar and length
bound. It identifies one entry that must already exist in the qualified
synthetic-listener image's immutable seed catalog. That entry contains exactly
one regular, nonlinked file: source relative path
`task11/portable-ghar-task11-seed-v1.bin`, hydrated target
`tools/portable-ghar-task11-seed-v1/payload.bin`, mode `0644`, and exact bytes
`portable-ghar-task11-immutable-seed-v1` followed by one LF. Qualified-image
preflight independently requires the exact source and mutation digests above.
The listener reads only the fixed absolute source
`/opt/portable-ghar/seed-cache/task11/portable-ghar-task11-seed-v1.bin` and
hydrated copy
`/runner/_work/_tool/portable-ghar-task11-seed-v1/payload.bin`.
`HydrateSeeds` must fail if the image does not contain that exact entry. No
fallback seed, empty selection, extra seed file, image-inspection bypass, or
runtime-created source is allowed.

The closed scenario enum is exactly:

```text
one-job
cleanup-success
cleanup-listener-crash
cleanup-upgrade-interruption
reclamation
seed-first
seed-second
```

`cleanup-cancellation`, `cleanup-pre-listener-failure`, and
`cleanup-controller-restart` are harness-controlled cycle kinds that do not
invoke a listener and therefore are not accepted by the listener protocol.

The closed cycle-kind enum is exactly:

```text
one-job
cleanup-success
cleanup-cancellation
cleanup-pre-listener-failure
cleanup-listener-crash
cleanup-controller-restart
cleanup-upgrade-interruption
reclamation
seed-first
seed-second
```

The only boundary-frame enum is:

```text
listener-ready
listener-crash-armed
upgrade-interruption-armed
```

The only terminal outcome enum is:

```text
completed
```

Listener crash and upgrade interruption intentionally have no terminal frame.
They are proved by an exact boundary frame plus the corresponding exact
container exit status. Cancellation, pre-listener failure, and controller
restart do not invoke the listener and therefore produce no listener frame.

### Trusted listener artifact boundary

The source build adds:

- `internal/task11synthetic`, containing only the closed wire/digest/resource
  contracts shared by the harness and listener;
- `cmd/portable-ghar-task11-listener`, whose accepted argv is exactly `run`
  for execution or `--version` for immutable-image smoke; and
- `images/synthetic-listener`, a deterministic runner-role image that uses
  the production runner gate and contains exactly one tree-locked
  `/opt/actions-runner/bin/Runner.Listener` payload plus the exact seed
  catalog above.

The production gate and image verifier continue to use their existing
`/opt/actions-runner` tree manifest, tree lock, runtime lock, readiness, and
seed-readiness contracts. In a synthetic image the runtime lock's pinned
upstream-runner fields bind only the gate/build ABI; they are not evidence
that the custom one-file listener tree is an actual GitHub runner. Static
qualification therefore requires this exact role-dependent pair:

```text
actual runner:
  gate verify-image == pinned upstream runner version without leading "v"
  direct Runner.Listener --version == the same upstream version

synthetic listener:
  gate verify-image == pinned upstream runner version without leading "v"
  direct Runner.Listener --version == portable-ghar-task11-synthetic-v1
```

Each result is obtained from the exact immutable image binding under the
prepared numeric user, with the held-gate inventory equal before, between,
and after both calls. The input's actual-runner and synthetic-listener image
IDs, references, and digests must be different. A pair equality in the
synthetic case, a pair inequality in the actual case, a generic version
acceptance, or either role's image digest in the other role fails before a
cycle. This preserves the existing production gate and runtime-lock format
without misclassifying the synthetic payload.

The image contains no GitHub runner `externals`, registration binary, updater,
second `bin` tree, `_work`, or `_work/_update`.
`immutable_payload_count=1` means that one qualified synthetic listener
payload at the production gate's fixed listener path.

Only code inside the qualified image observes or emits listener frames and
resource high-water values. The host harness treats its output as untrusted
bytes until the exact canonical parser, run/scenario binding, digest formulas,
exit readback, and cleanup proofs all succeed. A locally compiled but
unqualified listener cannot produce passing evidence.

### Closed digest formulas

Every digest below is SHA-256 and is encoded as 64 lowercase hexadecimal
characters. Text length prefixes are unsigned 16-bit big-endian; ordinals are
unsigned 64-bit big-endian. Raw digest and nonce inputs are decoded to their
fixed 32-byte values before hashing.

```text
cycle_run_digest =
  SHA256(
    cycle_domain ||
    primary_run_digest_raw32 ||
    uint16be(len(cycle_kind_utf8)) ||
    cycle_kind_utf8 ||
    uint64be(ordinal)
  )

restart_cycle_run_digest =
  SHA256(
    restart_cycle_domain ||
    cleanup_controller_restart_cycle_digest_raw32 ||
    uint16be(len(setup_stage_string_utf8)) ||
    setup_stage_string_utf8 ||
    uint64be(setup_stage_declaration_index)
  )

job_marker_digest =
  SHA256(
    job_marker_domain ||
    cycle_run_digest_raw32 ||
    nonce_raw32
  )

proxy_request_digest =
  SHA256(
    proxy_proof_domain ||
    cycle_run_digest_raw32 ||
    nonce_raw32 ||
    policy_entry_digest_raw32 ||
    policy_evidence_digest_raw32 ||
    observed_response_body_sha256_raw32
  )

response_body_proof_digest =
  SHA256(
    response_proof_domain ||
    cycle_run_digest_raw32 ||
    nonce_raw32 ||
    observed_response_body_sha256_raw32 ||
    expected_response_body_digest_raw32
  )

job_completion_digest =
  SHA256(
    job_completion_domain ||
    cycle_run_digest_raw32 ||
    job_marker_digest_raw32 ||
    canonical_terminal_frame_with_lf
  )

deregistration_digest =
  SHA256(
    registration_domain ||
    cycle_run_digest_raw32 ||
    job_marker_digest_raw32 ||
    canonical_terminal_frame_with_lf
  )

cleanup_digest =
  SHA256(
    cleanup_digest_domain ||
    cycle_run_digest_raw32
  )

cleanup_observation_digest =
  SHA256(
    cleanup_evidence_domain ||
    canonical_cleanup_observation_json_without_digest
  )

postrelease_resolution_evidence =
  SHA256(
    postrelease_domain ||
    cycle_run_digest_raw32 ||
    cleanup_observation_digest_raw32
  )

seed_source_digest =
  SHA256(exact_immutable_seed_file_bytes)

seed_copy_digest =
  SHA256(exact_hydrated_current_job_copy_bytes)

seed_mutation_digest =
  SHA256(
    exact_immutable_seed_file_bytes ||
    "portable-ghar-task11-current-copy-mutation-v1\n"
  )
```

The proxy and response proofs are created only after the actual HTTPS request
traverses the same-run broker and the observed response body digest exactly
equals the input's expected digest. Expected values alone cannot mint either
proof. The nonce is never emitted. No secret input other than the nonce
participates in these digests. The seed mutation is deterministic: the first
seed listener appends the exact suffix above to only the current-job copy; the
second listener computes the same expected digest independently from its
fresh immutable source and proves that no source or hydrated copy has that
digest.

## Canonical synthetic input wire

For every listener cycle, the integration harness constructs one JSON object
using a fixed Go struct. Its top-level members, in exact declaration order and
with exact JSON types, are:

1. `schema_version`: integer, exactly `1`;
2. `protocol_id`: string, exactly
   `portable-ghar-task11-synthetic-v1`;
3. `scenario`: string, one exact closed listener scenario;
4. `cycle_run_digest`: string, canonical lower-hex SHA-256;
5. `nonce`: string, a freshly generated canonical lower-hex 32-byte value;
6. `sentinel`: object with the exact members below; and
7. `seed_id`: string, present only for `seed-first` and `seed-second`, exactly
   `portable-ghar-task11-seed-v1`.

The `sentinel` object's declaration order and types are:

1. `url`: nonempty string, exact already-validated positive HTTPS URL;
2. `host`: nonempty string, exact already-validated host;
3. `port`: integer in `1..65535`, exact already-validated port;
4. `host_identity_digest`: canonical lower-hex SHA-256 string;
5. `spki_digest`: canonical lower-hex SHA-256 string;
6. `certificate_digest`: canonical lower-hex SHA-256 string;
7. `policy_entry_digest`: canonical lower-hex SHA-256 string;
8. `policy_evidence_digest`: canonical lower-hex SHA-256 string; and
9. `response_body_digest`: canonical lower-hex SHA-256 string.

Canonical bytes are exactly `encoding/json.Marshal` of those declaration-
ordered structs with default Go JSON string escaping, followed by one LF.
Maps, `json.RawMessage`, floating-point numbers, custom marshalers, and
HTML-escaping configuration changes are forbidden. Both the harness and
listener parse with `DisallowUnknownFields`, require one object followed by
EOF, validate every semantic value, re-marshal the parsed fixed struct,
append one LF, and require byte equality with the received document. This
rejects duplicate members, member reordering, alternate whitespace or escape
forms, explicit default fields, trailing bytes, and every noncanonical
encoding.

For a seed scenario, production `runtimeSpec.HydrateSeeds` must be exactly the
one-element declaration-ordered list containing the fixed seed ID, and that
value must equal both the input `seed_id` and every listener output
`seed.seed_id`. For every non-seed scenario, `HydrateSeeds` must be empty and
the input and output seed members must be absent. Empty, fallback, reordered,
duplicate, or unequal seed identities fail.

Every field is mandatory for its scenario and forbidden otherwise. The
document length, including its LF, must be less than or equal to both the
private input's `MaximumCommandInputBytes` and the production runner-gate
`maxJITLength`/`maxJITBytes` ceiling of exactly `65536`; the smaller bound
wins. The harness verifies before release that the document has no field shape
accepted as GitHub JIT and no value matching the Task 11 credential-shape
scanner.

The canonical bytes are immediately moved into `redaction.Secret`; the source
byte slice is zeroed. There is exactly one admission channel:

```text
Orchestrator.Release
  -> hostSetupRuntime.ReleaseRunner
  -> hostruntime.DockerCLI.ReleaseRunner
  -> runner-gate release frame
  -> executeVerifiedListener
  -> runtimeenv.Listener
  -> ACTIONS_RUNNER_INPUT_JITCONFIG
```

The verified listener is invoked with the production fixed argv `run`. No
alternate environment variable, file, argv member, mount, socket, stdin,
direct `docker exec`, or harness-created transport may admit the synthetic
input. The secret is passed only to `Orchestrator.Release` and is destroyed on
every terminal path by the existing release contract. The listener rejects a
GitHub JIT object even when all its fields are otherwise syntactically valid.

## Canonical synthetic output wire

Before `Release`, the cycle session starts exactly one fixed

```text
docker attach --no-stdin --sig-proxy=false <engine-issued-runner-id>
```

against the held runner's opaque engine-issued identity. The command and
arguments are source constants; callers cannot add arguments or environment.
The session captures bounded stdout, requires stderr to remain empty, and owns
the attach process through completion and cleanup. The runner gate's `OK`
release response is sent to its Docker exec client, not container stdout, so
the attach stream contains only listener frames.

The listener emits one of exactly two canonical stream shapes:

```text
normal scenario:             boundary-frame LF, terminal-frame LF, EOF
crash/upgrade interruption:  boundary-frame LF, EOF
```

A zero-frame, terminal-only, third-frame, partial-frame, trailing-byte, or
noncanonical stream fails. Each frame is `encoding/json.Marshal` of a fixed
declaration-ordered Go struct followed by one LF and is parsed with the same
unknown-field, EOF, semantic-validation, re-marshal, and byte-equality rules
as the input.

The boundary frame members, in exact order and with exact JSON types, are:

1. `schema_version`: integer `1`;
2. `protocol_id`: exact protocol string;
3. `frame`: string exactly `boundary`;
4. `scenario`: exact scenario string;
5. `cycle_run_digest`: canonical lower-hex SHA-256 string;
6. `job_marker_digest`: canonical lower-hex SHA-256 string;
7. `boundary`: exact closed boundary enum;
8. `synthetic_token_absent`: boolean, exactly `true`;
9. `immutable_payload_count`: integer, exactly `1`;
10. `upgrade_interruption_exercised`: boolean; and
11. `cgroup_version`: string, exactly `1` or `2`, independently equal to
    static host preflight; and
12. `seed_id`: exact fixed string, present only in seed scenarios.

The exact scenario-to-boundary mapping is:

```text
one-job, cleanup-success, reclamation, seed-first, seed-second
  -> listener-ready, upgrade_interruption_exercised=false
cleanup-listener-crash
  -> listener-crash-armed, upgrade_interruption_exercised=false
cleanup-upgrade-interruption
  -> upgrade-interruption-armed, upgrade_interruption_exercised=true
```

The terminal frame members, in exact order and with exact JSON types, are:

1. `schema_version`: integer `1`;
2. `protocol_id`: exact protocol string;
3. `frame`: string exactly `terminal`;
4. `scenario`: exact scenario string;
5. `cycle_run_digest`: canonical lower-hex SHA-256 string;
6. `job_marker_digest`: canonical lower-hex SHA-256 string;
7. `outcome`: string exactly `completed`;
8. `proxy_request_digest`: canonical lower-hex SHA-256 string;
9. `response_body_proof_digest`: canonical lower-hex SHA-256 string;
10. `registration_removed`: boolean, exactly `true`;
11. `synthetic_token_absent`: boolean, exactly `true`;
12. `immutable_payload_count`: integer, exactly `1`;
13. `upgrade_interruption_exercised`: boolean, exactly `false`;
14. `cgroup_version`: string, exactly equal to the boundary frame and static
    host preflight;
15. `resources`: array in the exact order below; and
16. `seed`: object present only in seed scenarios.

Each `resources` entry is the fixed struct
`{"resource":<enum string>,"high_water":<nonnegative integer>}`. The array
must contain every member exactly once in this order:

```text
memory_bytes
swap_bytes
runner_tmpfs_bytes
tmp_bytes
scratch_bytes
containers
processes
file_descriptors
namespaces
conntrack_rows
inodes
```

The listener derives `cgroup_version` before its boundary frame, only by
canonical parsing of `/proc/self/cgroup` plus `/proc/self/mountinfo`. Exactly
one of these closed layouts is accepted:

- version `2`: one unified hierarchy and one exact self cgroup path; or
- version `1`: exactly one membership for each of the `memory` and `pids`
  controllers, with memory and memory+swap accounting present. The
  controllers may be on separate v1 mounts or on one canonical co-mounted
  hierarchy. Separate mounts produce two exact paths. A co-mount may resolve
  both controllers to the same device/inode/path, which is retained once in
  the cleanup path set while both controller bindings remain mandatory.

Mixed/hybrid, the same controller appearing in more than one membership or
mount, an unrelated controller masquerading as either binding, missing swap
accounting, traversal, noncanonical path, mount disagreement, or a listener
value unequal to the static Docker-info preflight fails. Version detection
cannot fall back from one layout to the other after a read error.

The seed object's members, in exact order, are:

1. `seed_id`: exact fixed string;
2. `source_digest`: canonical lower-hex SHA-256 string;
3. `copy_digest`: canonical lower-hex SHA-256 string;
4. `mutation_digest`: canonical lower-hex SHA-256 string;
5. `source_post_digest`: canonical lower-hex SHA-256 string from the
   immutable source after every scenario mutation/absence check;
6. `mutation_absent`: boolean, false for `seed-first` and true for
   `seed-second`; and
7. `source_immutable`: boolean, exactly true.

The trusted qualified listener is the only source for every high-water value.
It obtains each value through the fixed in-image source bound to that resource
enum, fails on an unsupported or unreadable source, and never substitutes
zero, a harness-computed value, or a caller value. The harness accepts only
the parsed closed vector and does not recompute, default, or overwrite it.
High-water values exist only in a valid normal terminal frame. That same fixed
frame contains the exact `cycle_run_digest`, listener scenario, boundary-equal
`cgroup_version`, and declaration-ordered vector, and the complete canonical
terminal participates in `job_completion_digest`. Crash, upgrade,
cancellation, pre-listener, and restart rows cannot emit, inherit, or reuse a
high-water vector.

After the attach stream reaches EOF, the harness uses fixed Docker inspect
readback for the same engine-issued runner identity and requires:
`Running=false`, `OOMKilled=false`, empty `State.Error`, and exact exit status
`0`, `70`, or `71` as dictated by the scenario. The attach client itself must
exit normally with that same status and no stderr. The crash listener emits its
boundary then exits `70`. The upgrade-interruption listener creates only its
in-container ephemeral update-staging object: mode-`0700`, fresh no-follow
directory `/runner/_work/_update`, containing exactly one fresh mode-`0600`
regular marker named `portable-ghar-task11-upgrade-staging-v1` whose bytes are
the raw 32-byte job-marker digest. It fsyncs marker, directory, and work parent,
emits its boundary, then exits `71`; cleanup must later prove the entire
staging directory absent. Any existing object, link, extra entry, wrong
identity/mode/size, or second payload path fails before the boundary. The
harness never sends a kill signal to manufacture either outcome.

Crash and upgrade rows use one indivisible acceptance predicate, in this
order: parse the one exact armed boundary for the bound scenario and cycle;
observe attach EOF with no partial or second frame; obtain the exact matching
attach and container exit status (`70` or `71`); prove that no terminal frame
exists; then complete the bound cleanup digest and structural absence proof.
Boundary without exit, exit without boundary, a boundary for another
scenario, wrong cgroup version, any terminal bytes, or cleanup evidence
produced before the joint predicate fails the row. Neither the boundary nor
the exit status can pass independently.

The listener never emits the nonce, input token, sentinel text, URL, host,
port, certificate, SPKI, paths, process/container/socket identifiers, logs,
errors, timing, environment, or a generic pass boolean. The runner container's
immutable payload count is always one. Exercising upgrade interruption must
not create, retain, or report a second payload version.

### Synthetic registration and proxy operation

After canonical input parsing, the listener immediately removes
`ACTIONS_RUNNER_INPUT_JITCONFIG` from its environment and requires
`LookupEnv` to report absence before any frame. It creates exactly one
mode-`0600`, no-follow local registration marker at the compile-time path
`/runner/_work/.portable-ghar-task11-registration-v1`, requiring a fresh
regular file owned by the listener UID. Its bytes are exactly the raw 32-byte
job-marker digest, followed by `fsync(file)` and `fsync(/runner/_work)`.
Existing, linked, nonregular, wrong-owner/mode, short/long, or changed marker
identity fails.

Normal scenarios then emit the boundary, perform one HTTPS request for the
input sentinel through exact endpoint `127.0.0.1:18080` from the immutable
relay contract, validate the TLS name/SPKI/certificate and exact response-body
digest, compute the proxy/response proofs, remove the exact marker by
descriptor-relative no-follow unlink, fsync the parent, prove it absent, and
emit the terminal frame. `registration_removed=true` means only that exact
ordered removal proof; it is not a GitHub API deregistration claim.

Crash and upgrade-interruption scenarios create the same marker and leave it
present after their boundary before exiting with their exact status. Their
cleanup rows prove the marker and entire work area absent structurally.
Cancellation, pre-listener failure, and restart never create the marker.

The request uses no ambient proxy variable, caller proxy address, DNS fallback,
direct-connect fallback, alternate port, or automatic redirect. The
compile-time relay destination is a loopback CONNECT endpoint already bound by
the production adapter/broker contract. The request target remains the exact
input sentinel host/port and is independently bound by the policy and evidence
digests in the input.

For the Case 7 runtime observation, mappings are exact:

```text
JobCompleted          = valid normal terminal plus exit 0 and adjacent durable states
JobCompletionDigest   = job_completion_digest
ProxyRequestComplete  = valid proxy and response proof pair in that terminal
ProxyRequestDigest    = terminal proxy_request_digest
Deregistered          = exact registration removal proof
DeregistrationDigest  = deregistration_digest
Reclaimed             = complete cleanup catalog
ReclamationDigest     = cleanup_observation_digest
```

No second digest constructor or generic `passed` conversion may populate
those fields.

## Per-cycle production composition

Each secondary cycle remains below the one already-authorized fixture root:

1. derive the cycle run digest from the primary run digest, exact cycle kind,
   and ordinal using a closed domain;
2. derive the existing `compositionIdentity` from that cycle digest;
3. require the cycle slot identity to be a direct-child basename;
4. clone the validated private overlay in memory with
   `Paths.BrokerRoot = primary ConformanceInput.Fixture.Root`;
5. clone the validated input in memory with
   `Fixture.Root = <primary-root>/<cycle-slot-identity>`;
6. require the cycle root's parent to be the primary root and its basename to
   equal the derived slot identity;
7. call the existing `compositionPlanFrom`,
   `runtimeSpecCompositionFrom`, and `newFixtureRuntimeComposition`; and
8. replace only `Runner.Image` with the exact qualified synthetic-listener
   image reference and set the exact scenario's seed selection.

The cycle root layout remains:

```text
<primary-root>/<cycle-slot-identity>/
    relay/
    authority/
```

This satisfies both composition's direct-child invariant and
`hostruntime.RecoverySpec`, which binds relay and authority parents to the
exact slot basename. The cycle cannot write outside this child, reuse the
primary slot identity, or share relay/authority directories with another
cycle.

The secondary composition uses the same validated graph, policy, seccomp
binding, static users, runtime limits, sentinel membership, Docker path,
broker network, fleet generation, and immutable images as the primary
composition. Only the derived assignment/slot identity, synthetic runner
image, scenario token, and scenario-owned seed list differ.

## Normal cycle sequence

For `one-job`, `cleanup-success`, every reclamation sample, and both seed
runs, the exact sequence is:

1. create and positively verify the empty cycle root;
2. construct the production composition and record every opaque cleanup
   handle with the cycle owner;
3. call `Orchestrator.Prepare` through durable `StageRunnerAuthorize`;
4. start the fixed attach session for the held runner;
5. construct the canonical synthetic secret;
6. call `Orchestrator.Release`, which must complete the production
   `StageListenerRelease` effect and advance to `LISTENER_RELEASED`;
7. validate the closed listener stream and exact container exit readback;
8. advance the durable state through the adjacent production sequence
   `JOB_RUNNING` then `JOB_FINISHED`;
9. arm the one-use structural observer while the exact live managed snapshot,
   cgroup members, namespaces, sandbox, authority, sockets, and child-root
   identities still exist;
10. call `Orchestrator.DestroyLive`;
11. use only that armed observer session to prove the closed post-cleanup
    absence catalog and remove/prove the exact child root absent;
12. advance the durable state from `JOB_FINISHED` to `DESTROYED`;
13. replay the original exact `RecordOffer` and require terminal replay of
    `DESTROYED`;
14. seal the cycle's complete cleanup proof.

No result is returned until step 14 succeeds. If any earlier step fails, the
cycle follows the state-aware cleanup branch in the table below under an
independent private cleanup deadline. A failed observation never becomes a
passing case, and a post-release failure never uses a blind adjacent
`Advance(...DESTROYED)`.

## Cleanup-matrix semantics

The fixed rows remain declaration ordered:

1. success;
2. caller cancellation;
3. pre-listener failure;
4. listener crash;
5. controller restart; and
6. upgrade interruption.

Every row uses a distinct cycle run digest, slot identity, cleanup digest, and
child root. A duplicate cleanup digest, reused slot, skipped row, reordered
row, extra row, or substituted result shape fails the entire synthetic
lifecycle stage.

The scenario/trigger/state table is normative:

| Matrix row | Listener scenario and exact trigger | Required listener result | Required terminal state path |
| --- | --- | --- | --- |
| success | `cleanup-success`; normal production release | boundary + terminal, exit `0` | `LISTENER_RELEASED -> JOB_RUNNING -> JOB_FINISHED`; `DestroyLive`; positive absence; adjacent `DESTROYED` |
| caller cancellation | no listener scenario; after `Prepare` has returned an exact held jail and durable state is `RELEASE_ARMED`, cancel the caller context before secret construction or `Release` | no attach and no listener frame | independent cleanup context; `DestroyHeld`; positive absence; `AdvancePreReleaseDestroyed`; exact `DESTROYED` |
| pre-listener failure | no listener scenario; the existing test-local recording-engine wrapper fails exactly at `StageRunnerAuthorize` before delegating `AuthorizeRelease` | no attach and no listener frame | production `Prepare` failure cleanup; exact positive absence and durable `DESTROYED`; no listener-release effect |
| listener crash | `cleanup-listener-crash`; qualified listener emits its exact crash boundary then exits `70` | boundary only, exit `70` | `LISTENER_RELEASED`; `DestroyLive`; positive absence; `ResolvePostRelease(PostReleaseDestroyed, exact evidence)`; exact `DESTROYED` |
| controller restart | no listener scenario; exact durable-`Complete` panic matrix below | no attach and no listener frame | fresh recovery, positive absence, `AdvancePreReleaseDestroyed`, exact `DESTROYED` |
| upgrade interruption | `cleanup-upgrade-interruption`; qualified listener creates its ephemeral staging object, emits the exact upgrade boundary, then exits `71` | boundary only, exit `71` | `LISTENER_RELEASED`; `DestroyLive`; staging and full positive absence; `ResolvePostRelease(PostReleaseDestroyed, exact evidence)`; exact `DESTROYED` |

The two non-listener fault rows have this exact pre-cleanup inventory and
observer order:

| Row | Fault checkpoint | Exact live inventory before cleanup | Observer and terminal proof |
| --- | --- | --- | --- |
| caller cancellation | `Prepare` returned a held jail; durable state and selected effect are exact `RELEASE_ARMED`/completed | adapter, broker, runner, exact active authority; empty-seed hydration has created only the fresh work root; no attach, listener, registration marker, or upgrade marker | arm from the engine-issued held capability; cancel the caller context; call `DestroyHeld` under an independent cleanup context; prove the armed absence catalog; call `AdvancePreReleaseDestroyed`; require exact `DESTROYED` |
| pre-listener failure | inside the one closed test-local runtime wrapper, at `StageRunnerAuthorize` after held-runner audit and immediately before delegating `AuthorizeRelease` | adapter, broker, runner, exact active authority; fresh work root; no release authorization, attach, listener, registration marker, or upgrade marker | the wrapper must arm the observer from its engine-issued refs before returning the injected typed failure; ordinary production `Prepare` cleanup then runs; after `Prepare` returns, prove only that armed catalog and require the production journal/store readback to be exact `DESTROYED` |

The pre-listener wrapper cannot call removal, alter the durable result,
construct an authorization, or arm from labels. If it cannot capture the
complete exact inventory before returning its fault, the row fails and
production cleanup still runs. Neither row can borrow a success-row snapshot
or infer absence merely from the lack of listener output.

The post-release resolution evidence uses the exact closed formula above over
the cleanup-observation digest defined below. It is nonzero, persisted by
`ResolvePostRelease`, read back from the exact post-release-resolution effect,
and must match on replay. The resolution time comes from the harness's
injected clock after the assignment's durable update time; wall-clock parsing
or caller-provided time is forbidden.

Cancellation therefore occurs before listener release, not after a listener
boundary. Pre-listener failure occurs before `AuthorizeRelease` can mint a
release authorization. Listener crash and upgrade interruption are
listener-driven exact outcomes rather than harness signals. Upgrade
interruption must retain exactly one immutable payload version and leave no
`_work/_update` or other version-staging object after cleanup.

For this synthetic row, this amendment supersedes the base plan's phrase
“old and candidate payloads staged.” Recreating two runnable payload trees
would reproduce the defective self-update shape the design is meant to reject
and would contradict the fixed payload count. The qualified listener instead
creates one exact bounded `_work/_update` staging marker while the sole
tree-locked listener payload remains unchanged, then exits `71`. The row proves
interrupted staging cleanup without ever admitting a second payload.

## Controller-restart simulation

The restart row iterates the declaration-ordered durable setup stages from
`StageAdapterCreate` through `StageRunnerAuthorize`, excluding
`StageListenerRelease`.

The selected checkpoint is always immediately after the real journal's
`Complete` succeeds and before the next `Advance`, `Before`, or external
action. The exact expected durable state and managed inventory at that point
are:

| Selected completed stage | Durable assignment state | Exact managed inventory | Authority |
| --- | --- | --- | --- |
| `StageAdapterCreate` | `CAPACITY_RESERVED` | adapter | absent |
| `StageAdapterEmpty` | `ADAPTER_CREATED` | adapter | absent |
| `StageBrokerCreate` | `ADAPTER_VERIFIED` | adapter, broker | absent |
| `StagePolicyApply` | `BROKER_HELD` | adapter, broker | absent |
| `StageAuthorityStart` | `BROKER_POLICY_APPLIED` | adapter, broker | exact active tuple |
| `StageAuthorityBind` | `BROKER_POLICY_APPLIED` | adapter, broker | exact active tuple |
| `StageBrokerRelease` | `DIAL_AUTHORITY_READY` | adapter, broker | exact active tuple |
| `StageAdapterBind` | `BROKER_RELEASED` | adapter, broker | exact active tuple |
| `StageEgressVerify` | `BROKER_RELEASED` | adapter, broker | exact active tuple |
| `StageRunnerCreate` | `EGRESS_VERIFIED` | adapter, broker, runner | exact active tuple |
| `StageSeedHydrate` | `RUNNER_HELD` | adapter, broker, runner | exact active tuple |
| `StageNamespacePreArm` | `RUNNER_HELD` | adapter, broker, runner | exact active tuple |
| `StageFinalAudit` | `RUNNER_HELD` | adapter, broker, runner | exact active tuple |
| `StageRunnerArm` | `RUNNER_HELD` | adapter, broker, runner | exact active tuple |
| `StageNamespaceFinal` | `RUNNER_HELD` | adapter, broker, runner | exact active tuple |
| `StageRunnerAuthorize` | `RUNNER_HELD` | adapter, broker, runner | exact active tuple |

Adapter, broker, and runner mean the exact immutable-label objects returned by
fresh `InspectManaged`; order is declaration order. Helper and verifier
containers are one-shot and must be absent at every checkpoint. Any missing
required object, additional object, wrong order, wrong identity, or wrong
durable state fails before cleanup.

The selected effect result is also exact. Before delegating `Complete`, the
wrapper requires `StageAdapterCreate`, `StageBrokerCreate`, and
`StageRunnerCreate` to carry respectively the adapter/broker/runner identity
in their matching journal identity column; `StagePolicyApply` carries the
exact policy digest in the policy column; every other selected stage carries
empty result identity with `JournalIdentityNone`; all carry `Failure=false`.
After durable completion, `LookupAssignmentEffect` must expose the same result
identity and empty reason, while `ListRecoverable` must expose the
corresponding durable adapter/broker/runner/policy field. This jointly proves
the column application even though `EffectRecord` intentionally does not
export the column enum. Any other shape is not a restart checkpoint.

Before `Prepare`, the harness creates one closed crash bag containing only:

- the production store pointer;
- the immutable cycle run digest;
- the exact assignment key;
- the original exact offer and its evidence needed for terminal replay;
- qualified input/build/fleet/root bindings needed to recompute the closed
  `RecoverySpec`; and
- the authority-manager pointer, used only for test hygiene.

It contains no `HeldJail`, setup resource, runtime ref, container ID, process
ID, socket path, effect result, mutable stage, or caller-provided cleanup
identity. For each selected stage:

1. create a fresh cycle with a fresh assignment and slot;
2. wrap `networkjail.LifecycleJournal`;
3. delegate `Before`, `Advance`, `MarkAmbiguous`, and `Complete` to the real
   `StateLifecycleJournal`;
4. after the wrapped `Complete` durably succeeds for the selected stage, panic
   with one private typed sentinel carrying only that exact stage, but only
   after re-reading the selected effect as exactly `EffectCompleted` with the
   expected closed result identity;
5. recover only that exact sentinel at the harness boundary; every other panic
   is immediately re-panicked;
6. discard the entire process-local `Prepare` frame and all of its handles;
7. obtain the one exact `ListRecoverable` row for the assignment and require
   its durable state to match the table;
8. obtain the exact selected-stage `LookupAssignmentEffect` and require
   `EffectCompleted`, the expected identity column/result, and no failure or
   ambiguity;
9. recompute the expected slot identity, generation, managed names, and
   `RecoverySpec` only from the immutable crash bag, then require equality
   with the durable row; durable data, not the panic payload, is authoritative;
10. require the permit authority's
    `ActiveRevision(slot,generation)` to be absent or exact as specified by
    the table;
11. instantiate a fresh `hostruntime.DockerCLI`;
12. call `InspectManaged` with the recomputed exact `RecoverySpec`;
13. require the exact managed inventory in the table;
14. arm a fresh structural observer session from that engine-issued snapshot,
    its exact container/cgroup/process/namespace/sandbox identities, and the
    exact derived authority/relay/socket identities while they still exist;
15. use the integration-only exact authority shutdown; its success cannot
    alter or replace the observer's captured identities;
16. call `RemoveManaged` with the engine-issued snapshot even when the
    expected inventory is empty;
17. run a second exact-label inventory and require zero objects;
18. prove the armed structural absence catalog, including authority, relay,
    cgroup, namespace, process, tmpfs/work/update, sandbox, and exact-root
    absence;
19. call `AdvancePreReleaseDestroyed` for the exact assignment;
20. positively read the assignment and listener-release effect as exact
    `DESTROYED`/absent and nonambiguous;
21. replay the original exact `RecordOffer`; and
22. require the production terminal-replay result for `DESTROYED`, with the
    same assignment/slot identity and no new effect or object.

The wrapper panic occurs after the durable result checkpoint and before the
next state/effect operation. Because Go does not recover inside
`Orchestrator.Prepare`, its normal `fail` cleanup does not run; this models
loss of process-local handles while retaining the production durable record.
The production `Prepare`, journal, and runtime code must not contain a recover
for this test sentinel. A partial/failed `Complete`, an unreadable
post-complete effect, or a panic from any other source never satisfies the
tripwire.

`InspectManaged` must observe exactly the table's inventory, never an
arbitrary valid subset. Unknown, duplicate, drifted, mismatched, or extra
objects fail closed. Cleanup evidence never asserts that a stage completed
merely because no object exists.

The observer is armed only after the panic has discarded the entire
process-local `Prepare` frame. It therefore obtains identities from fresh
Docker inspection, the exact durable binding, and fixed structural reads—not
from the setup handles or panic payload. The immutable crash bag itself
contains no captured resource identity. Failure of authority shutdown,
`RemoveManaged`, observer proof, or `AdvancePreReleaseDestroyed` is terminal;
no later absence or replay can convert it to success.

## Linux-integration-only exact authority shutdown

Add one exported method in an
`internal/networkjail/*_integration_linux.go` file guarded by:

```go
//go:build integration && linux
```

The exact method is:

```go
func (manager *UnixAuthorityManager) ShutdownIntegrationAuthority(
    ctx context.Context,
    slot CapacitySlotID,
    generation JobGeneration,
    directory string,
) error
```

It is available only on `*UnixAuthorityManager` and accepts:

- exact capacity slot ID;
- exact job generation; and
- exact absolute authority directory.

It derives the only permitted socket path from that directory. Under the
manager lock it requires exactly one of these closed states:

- no endpoint claims the exact tuple or derived socket and the exact socket is
  absent; or
- one matching active endpoint exists whose stored slot, generation, and
  socket path all equal the request.

An unrelated primary-fixture endpoint is outside the requested tuple and is
left untouched. Any endpoint claiming only part of the requested tuple,
duplicate claimant for the tuple/socket, nil reservation, tuple mismatch,
unexpected socket identity, symlink, or ambiguous state fails. For the
matching endpoint it performs the same ordered actions as production `Stop`:
close server, verify and remove the exact socket identity, deactivate the
exact permit-authority tuple, remove the exact active-map entry, and prove the
socket absent, `ActiveRevision(slot,generation)` inactive, and no claimant for
that tuple/socket remains.

The method returns only success/error. It exposes no lease, endpoint, socket
identity, active map, or cleanup proof. Its successful return is necessary
test hygiene before fresh recovery, never conformance evidence.

Stages before `StageAuthorityStart` must use the no-endpoint/no-socket branch.
Stages at or after `StageAuthorityStart` must require the exact active endpoint;
they cannot silently accept absence.

## Closed structural absence observer

The Linux integration harness adds one test-local
`syntheticCleanupObserver`. It accepts only the prevalidated primary/cycle
root bindings, immutable cycle and cleanup digests, private limits, the exact
engine-issued managed snapshot, and structural identities captured from those
managed objects before removal. It accepts no caller path, process/container
ID, cgroup, namespace, mount, or arbitrary probe.

The observer is a one-use, two-phase session with the closed states `unarmed`,
`armed`, and `proved`. Construction validates and freezes the primary/cycle
root, cycle/cleanup digests, recovery specification, expected inventory, and
private bounds but produces no cleanup evidence. `Arm` is permitted exactly
once, only from `unarmed`, while the expected resources and authority state
are still live. It consumes the exact engine-issued snapshot and performs all
identity capture below before returning an immutable armed session.
`Prove` is permitted exactly once, only from that same armed session after the
row's state-aware cleanup has completed. It may re-read only the frozen
identities and fixed absence predicates, then atomically advances to `proved`
and emits the cleanup observation. A failed `Arm` or `Prove`, a second call,
an attempt to prove before cleanup, an attempt to arm after cleanup, a
different cycle/cleanup digest, or recapture/adoption of any path or identity
fails the row. No cleanup boolean, observation digest, or
`CompleteCleanupProof` is available before successful `Prove`.

Before cleanup, the observer captures through fixed Docker inspect/top and
Linux `/proc` read paths:

- the exact adapter, broker, and runner container identities that exist for
  the scenario;
- runner `HostConfig.Tmpfs`, `Mounts`, state, and image digest;
- the exact versioned runner cgroup path set: one unified path for version
  `2`, or exact memory and pids controller bindings for version `1` with an
  identity-deduplicated one-or-two-path cleanup set, plus bounded process
  membership;
- each member PID's start time, cgroup membership, namespace device/inode
  tuple, and bounded file-descriptor device/inode targets;
- the adapter's exact Docker network-sandbox path and device/inode identity,
  which is independently equal to the runner's shared network namespace;
- the exact authority tuple and socket identity, when present; and
- the exact declaration-ordered entries beneath the cycle relay, authority,
  and root directories.

Symlinks, unknown mounts, bind/volume-backed runner/work/tmp/scratch paths,
hybrid cgroup identity, duplicate PIDs, more members than private
`MaximumProcesses`, more descriptors per member than private
`MaximumFileDescriptors`, unreadable required fields, or identity change
during capture fail closed. Nothing from Docker logs or free-form command
text is parsed.

After state-aware production cleanup, the observer performs this exact
declaration-ordered catalog:

1. `ContainersAbsent`: fresh `InspectManaged` for the exact `RecoverySpec`
   returns an engine-issued empty snapshot, and direct fixed inspect of every
   captured managed identity returns only exact not-found;
2. `CgroupsAbsent`: every captured exact versioned cgroup path is
   `Lstat`-absent;
3. `TmpfsAbsent`: the runner/work/tmp/scratch locations were proved before
   cleanup to be only container-private tmpfs/container-layer storage, and
   the exact container and cgroup are now absent;
4. `WorkAbsent`: the same structural proof covers the exact runner work
   location and no host-backed mount exists;
5. `WorkUpdateAbsent`: the same structural proof covers `_work/_update`,
   including the upgrade-interruption staging object;
6. `ProcessesAbsent`: every captured PID is directly `Lstat`-absent or has a
   different canonical start time, every exact cgroup path is absent, and the
   pre-cleanup runner proof established cap-drop-all, read-only cgroup
   membership, no Docker/control authority, and no host mount through which a
   descendant could migrate or persist;
7. `NamespacesAbsent`: `ProcessesAbsent` is true, the exact Docker
   network-sandbox path and identity are absent, and the pre-cleanup proof
   established that namespace descriptors were held only by the bounded
   same-cgroup process set. No host-wide namespace scan or prefix match may
   substitute for those exact ownership facts;
8. `SocketsAbsent`: the exact authority and relay socket identities are
   absent, with no symlink substitution;
9. `AuthoritiesAbsent`: `ActiveRevision(slot,generation)` is inactive and the
   integration-only manager check finds no claimant for the exact
   tuple/socket;
10. `TemporaryFilesAbsent`: the exact relay, authority, and scenario-owned
    temporary entries are absent;
11. `HostBackedWorkAbsent`: the pre-cleanup Docker inspection contained no
    bind or named/anonymous volume for runner/work/tmp/scratch, and no
    scenario path exists outside the validated child root;
12. `UnexpectedObjectsAbsent`: the second managed inventory is empty, the
    exact child root contains no unknown entry, the child root is removed,
    and `Lstat` proves it absent; and
13. `PayloadVersionCount`: exactly `1`, sourced from qualified immutable-image
    preflight and, when a listener ran, independently equal to the listener
    frame value.

Only the exact absence predicates may be re-read, at the private reclamation
cadence and no later than the private cleanup/reclamation deadline. A re-read
cannot discover or adopt a new identity/path. Deadline expiry, cancellation,
or an intermediate non-not-found error fails cleanup; it does not convert the
last observation to absent.

Pre-cleanup cgroup enumeration admits at most the private maximum process
count and at most the private maximum descriptors per member. Post-cleanup
checks address only those captured PID/start-time identities and the exact
cgroup/sandbox paths. The private runner process limit is never misused as a
bound on all host `/proc` entries. Enumeration overflow, permission denial,
disappearing identity during a required pre-cleanup read, or an unrecognized
namespace/descriptor target fails rather than proving absence. Every exact
cgroup-path absence remains mandatory; PID reuse cannot satisfy or invalidate
a captured PID/start-time identity.

The observer materializes one fixed, declaration-ordered cleanup JSON struct
with:

```text
schema_version = 1
protocol_id = portable-ghar-task11-synthetic-v1
cycle_run_digest
cleanup_digest
cgroup_version = exact static/boundary version
the twelve CompleteCleanupProof absence booleans in struct order
payload_version_count = 1
assertion_count = 13
```

The canonical JSON has no digest member and uses the same fixed-struct
`json.Marshal` rules as the listener wire, without a trailing LF inside the
hash. `cleanup_observation_digest` is computed by the closed formula above and
becomes `CompleteCleanupProof.ObservationDigest`. No boolean or zero can be
defaulted: all thirteen catalog records must be independently present before
the document is sealed.

## Reclamation observations

The harness runs exactly the private `ReclamationSampleCount`; source does not
select or alter it. Every sample is a fresh normal synthetic cycle.

The qualified listener is the trusted measurement boundary for the
runner-scoped high-water vector. Its immutable implementation maps the closed
resources to these fixed in-container sources:

| Resource | Fixed high-water source |
| --- | --- |
| `memory_bytes` | v2: unified `memory.peak`; v1: memory-controller `memory.max_usage_in_bytes` |
| `swap_bytes` | v2: unified `memory.swap.peak`; v1: maximum checked `memory.memsw.usage_in_bytes - memory.usage_in_bytes` across the fixed event sequence |
| `runner_tmpfs_bytes` | maximum exact used-byte result for `/runner` across the fixed event sequence below |
| `tmp_bytes` | maximum exact used-byte result for `/tmp` across that sequence |
| `scratch_bytes` | maximum exact used-byte result for the configured scratch mount across that sequence |
| `containers` | exactly one self container, proved by the listener's own cgroup/container boundary and immutable runner-role contract |
| `processes` | maximum exact process-membership count from unified `cgroup.procs` (v2) or the exact pids-controller `cgroup.procs` (v1) across the fixed event sequence |
| `file_descriptors` | maximum exact count across `/proc/self/fd` plus every same-cgroup child at the fixed event sequence |
| `namespaces` | maximum exact count of distinct namespace device/inode tuples across the same-cgroup process set at the fixed event sequence |
| `conntrack_rows` | maximum exact parsed row count in the listener network namespace at the fixed event sequence |
| `inodes` | maximum exact used-inode result across `/runner`, `/tmp`, and scratch at the fixed event sequence |

The fixed event sequence is: listener entry before any synthetic operation;
after canonical input validation; after seed verification/hydration readback
when applicable; after the exact HTTPS proxy exchange; after deterministic
seed mutation when applicable; after creation of the upgrade staging object
when applicable; and immediately before the terminal frame or intentional
exit. The listener performs no asynchronous synthetic workload outside those
boundaries. The version-specific paths are resolved once before the first
measurement and their mount/device/inode identities must remain stable through
the last.

At each v1 event the listener uses already-open, no-follow descriptors for the
resolved memory-controller directory. It reads one complete
`memory.usage_in_bytes`/`memory.memsw.usage_in_bytes` pair twice in the exact
order memory, memsw, memory, memsw. Both memory values and both memsw values
must be byte-canonical, numerically equal across the two reads, and within
`uint64`; no retry is made. Swap for that event is the checked
`memsw - memory` result and must be nonnegative. The v1 high-water memory
source remains the monotonic `memory.max_usage_in_bytes`, read canonically at
each fixed event; high-water swap is the maximum accepted event result. This
defines the unavoidable non-atomic v1 observation boundary without silently
mixing two different instants or adding an unreviewed retry value.

A required file, cgroup controller, namespace table, descriptor set, or stat
source that is missing, unsupported, unstable across its prescribed read, or
arithmetically out of range fails the listener before a terminal frame. It
does not report a default, estimate, caller value, or harness value.

The post-cleanup vector is runner-cycle-attributed and exactly zero for every
resource, but each zero is admitted only after its corresponding closed
catalog proof: cgroup absence for memory/swap/processes; container absence for
containers; tmpfs/work/host-backing absence for runner/tmp/scratch/inodes;
captured PID/FD absence for file descriptors; namespace absence for
namespaces/conntrack; and exact-root absence for remaining filesystem
attribution. The harness never writes over or recomputes the listener's
high-water vector.

For every resource, high-water must be greater than or equal to post-cleanup.
Every sample must have its own complete cleanup proof. Version staging must be
absent, with a distinct bounded absence digest. The coordinator then applies
the existing exact-integer reclamation-series validator and private baselines;
it waits only under the private reclamation deadline/cadence and never retunes
a baseline, margin, slope, cadence, or sample count.

## Seed-isolation sequence

The first seed cycle:

1. passes exactly `portable-ghar-task11-seed-v1` to production
   `HydrateSeeds`;
2. requires input, `HydrateSeeds`, boundary output, and terminal output seed
   IDs to be byte-equal;
3. has the listener hash the exact immutable source and hydrated current-job
   copy and require equality;
4. appends the fixed mutation suffix only to the current-job tmpfs copy;
5. hashes the mutated copy and requires the exact deterministic
   `seed_mutation_digest` formula;
6. re-hashes the immutable source into `source_post_digest` and requires it
   equal to `source_digest`;
7. emits `mutation_absent=false`, `source_immutable=true`; and
8. completes exact cleanup and proves the workspace absent.

The second fresh cycle:

1. hydrates the same exact seed ID from the same immutable image;
2. independently computes the expected deterministic mutation digest from
   its immutable source and fixed suffix; no cycle-one digest is passed in the
   second input;
3. hashes the source, fresh current-job copy, and post-check source and
   requires equality with the first cycle's retained source/copy/post-source
   digests;
4. proves neither source nor fresh copy has the expected mutation digest and
   that the fixed mutation suffix is absent from both;
5. emits the same `mutation_digest` with `mutation_absent=true` and
   `source_immutable=true`; and
6. completes exact cleanup and proves the workspace absent.

The coordinator retains only the first cycle's four lower-hex digests and
closed booleans, never source or copy bytes. It requires exact equality across
both seed IDs, both source digests, both pre-mutation copy digests, both
deterministic mutation digests, and a post-source digest; it also requires the
mutation digest to differ from the source digest, first-cycle mutation
absence false, second-cycle mutation absence true, and source immutable true
in both. Both cleanup proofs must be complete and distinct. No host-backed,
shared, or cross-cycle seed path may exist.

Terminal acceptance is the conjunction of these exact predicates; none may be
inferred from another:

- `seed-first`: `source_digest` and the pre-mutation `copy_digest` both equal
  the published seed source SHA-256; `mutation_digest` equals the published
  mutation SHA-256 and differs from both source and copy; `source_post_digest`
  again equals the published source SHA-256; `mutation_absent=false`; and
  `source_immutable=true`;
- `seed-second`: `source_digest`, the fresh `copy_digest`, and
  `source_post_digest` all equal the published seed source SHA-256;
  `mutation_digest` equals the same published mutation SHA-256 and differs
  from source and copy; the fixed mutation suffix is absent from both fixed
  absolute source and copy paths; `mutation_absent=true`; and
  `source_immutable=true`; and
- both cycles used only
  `/opt/portable-ghar/seed-cache/task11/portable-ghar-task11-seed-v1.bin` and
  `/runner/_work/_tool/portable-ghar-task11-seed-v1/payload.bin`. A relative,
  caller-selected, host-backed, shared, alternate, or newly discovered path
  is not eligible evidence.

## Conformance and operational-telemetry separation

Task 11 conformance artifacts are test-only evidence. The protocol ID,
scenario/cycle identifiers, cycle/cleanup/job/proxy/response/completion/
registration digests, cleanup booleans, cleanup observation/evidence,
listener frames, resource vectors, seed proofs, restart crash bags, and
matrix outcomes must never enter the production `health.Snapshot`, signed
Worker heartbeat, `portable_ghar_health` InfluxDB measurement, Grafana
variables or annotations, GitHub collector records, or a cutover evidence
tuple. Production telemetry may report only the independently reviewed closed
health schema. No conformance field may be renamed, hashed, aggregated, or
projected into that schema. A source dependency, adapter mapping, or dashboard
query that crosses this boundary fails the Task 11 build.

## Exact Task 11 cycle mapping

The coordinator accepts only this declaration-ordered mapping. `ordinal` is
the zero-based position within the named parent case and participates in the
cycle-run digest formula:

| Parent case / ordinal | Cycle kind | Listener scenario | Terminal shape |
| --- | --- | --- | --- |
| one-job / `0` | `one-job` | `one-job` | boundary + terminal, exit `0` |
| cleanup / `0` | `cleanup-success` | `cleanup-success` | boundary + terminal, exit `0` |
| cleanup / `1` | `cleanup-cancellation` | none | no listener |
| cleanup / `2` | `cleanup-pre-listener-failure` | none | no listener |
| cleanup / `3` | `cleanup-listener-crash` | `cleanup-listener-crash` | boundary only, exit `70` |
| cleanup / `4` | `cleanup-controller-restart` | none | no listener; one subcycle per ordered setup stage |
| cleanup / `5` | `cleanup-upgrade-interruption` | `cleanup-upgrade-interruption` | boundary only, exit `71` |
| reclamation / private sample index | `reclamation` | `reclamation` | boundary + terminal, exit `0` |
| seed / `0` | `seed-first` | `seed-first` | boundary + terminal, exit `0` |
| seed / `1` | `seed-second` | `seed-second` | boundary + terminal, exit `0` |

Each controller-restart subcycle further derives a distinct child cycle digest
from the cleanup controller-restart digest, the exact setup-stage string, and
that stage's zero-based declaration index using the closed restart formula
above.
No row shares a digest, slot, root, cleanup digest, assignment, or listener
session with another row.

## RED tests before implementation

Add failing tests for:

- unknown, duplicate, reordered, defaulted, GitHub-JIT-shaped, oversized, or
  noncanonical synthetic input, including wrong LF/EOF and alternate escaping;
- credential-shaped input or output;
- wrong protocol, schema, scenario, run binding, digest formula, seed ID, or
  scenario-specific field;
- any mismatch among `HydrateSeeds`, input seed ID, boundary seed ID, and
  terminal seed ID, or a seed member/list in a non-seed scenario;
- output with token/log/path/ID/error/timing data;
- missing, reordered, duplicated, substituted, partial, third, trailing, or
  noncanonical listener frames;
- attach started after release, caller-controlled attach argv/environment,
  nonempty attach stderr, missing inspect readback, wrong exit status,
  OOM-kill, or nonempty container state error;
- harness-manufactured listener crash/upgrade kill, terminal frame after
  crash/upgrade boundary, or zero frame for either;
- immutable payload count other than one;
- upgrade-interruption not exercised or version staging remaining;
- cancellation after secret construction/release or with any listener frame;
- pre-listener fault at any stage other than the exact pre-delegate
  `StageRunnerAuthorize` boundary;
- wrong adjacent normal state transition, blind post-release `Advance` to
  destroyed, missing/mismatched post-release resolution evidence, or terminal
  offer replay that creates a new object/effect;
- cycle root outside the primary root, wrong basename, shared slot, or reused
  relay/authority directory;
- bypass of production `Prepare`/`Release`;
- duplicate cleanup digests or incomplete positive absence;
- wrong restart stage, skipped/reordered stage, panic before durable complete,
  unexpected panic, production recovery of the sentinel, attempted
  listener-release interruption, mutable/runtime handle in the crash bag, or
  durable state/inventory mismatch against the normative table;
- restart recovery derived from panic/process-local values instead of
  `ListRecoverable`, selected `LookupAssignmentEffect`, immutable crash-bag
  bindings, and exact permit-authority revision;
- wrong authority tuple, unexpected active endpoint, missing required active
  endpoint, socket replacement, symlink, or residual authority;
- recovery inventory drift, extra object, residual root, relay, authority,
  process, namespace, cgroup, tmpfs, work, or staging path;
- cleanup observer caller path/ID input, Docker-log parsing, defaulted boolean
  or zero, unbounded `/proc`/FD enumeration, PID-reuse acceptance, unreadable
  source accepted as absent, wrong assertion count, or noncanonical cleanup
  observation digest;
- observer proof before arm or cleanup, arm after cleanup, a second arm/prove,
  cross-cycle session reuse, identity recapture/adoption, or cleanup evidence
  visible before successful one-use `Prove`;
- `AdvancePreReleaseDestroyed` failure, listener effect presence, ambiguity, or
  nonterminal readback, and terminal `RecordOffer` replay mismatch;
- wrong reclamation sample count/resource order, high-water below postcleanup,
  defaulted zero, duplicate sample cleanup, staging digest substitution,
  harness-recomputed high-water, unsupported listener source, wrong fixed
  measurement event order, or post-cleanup zero without its catalog proof;
- cgroup v1/v2 preflight-listener mismatch, hybrid layout, missing v1
  memory+swap accounting, rejection of a valid memory+pids co-mount,
  acceptance of a duplicate/ambiguous controller binding, version fallback
  after read failure, unstable cgroup identity, unequal double-read pairs,
  negative/overflowing v1 swap arithmetic, or failure to prove every
  identity-deduplicated versioned cgroup path absent;
- a listener boundary without cgroup version, boundary/terminal/static
  cgroup-version disagreement, or a cleanup observation that substitutes an
  unbound version;
- a host-wide `/proc` scan bounded by the runner process limit, prefix-based
  namespace discovery, missing Docker sandbox identity, external
  namespace-FD authority, or process/namespace absence inferred without exact
  PID/start-time, cgroup, and sandbox-path proofs;
- absent seed, different seed ID, source mutation, first mutation visible in
  second run, differing deterministic mutation digests, second-cycle input
  carrying first-cycle digests, shared path, host-backed path, or either
  workspace remaining;
- any Task 11 protocol/scenario/digest/cleanup/seed/reclamation/restart value
  entering health, heartbeat, InfluxDB, Grafana, GitHub collector, or cutover
  evidence;
- wrong parent/row/cycle-kind/scenario/ordinal mapping or any reused
  run/slot/root/cleanup/assignment identity; and
- availability of the authority shutdown method outside
  `integration && linux`.

Unit tests use fakes only for parser/coordinator rejection and sequencing.
Passing lifecycle evidence requires the Linux integration driver and real
production composition.

## Implementation order

1. Add `internal/task11synthetic` protocol/input/output types, canonical
   encoders/parsers, digest constructors, and RED parser tests.
2. Add `cmd/portable-ghar-task11-listener`, deterministic image/seed assets,
   fixed self-observation sources, and source tests before adding the host
   driver.
3. Add cycle identity/root derivation and RED composition tests.
4. Add fixed attach/inspect and structural-observer sessions with rejection
   tests; no generic command surface.
5. Add the Linux-integration-only exact authority shutdown and its Linux
   integration tests.
6. Add the production-cycle driver for normal scenarios and state-aware exact
   cleanup.
7. Add controller-restart stage iteration, crash-bag recovery, and terminal
   replay proof.
8. Add reclamation sampling and bind every post-cleanup zero to the closed
   catalog.
9. Add the two-cycle immutable-seed proof.
10. Bind the driver into the existing Task 11 synthetic lifecycle coordinator.
11. Run macOS-safe unit/source tests and Linux cross-compile/build-tag checks.
12. Run Linux integration tests only on an explicitly authorized compatible
    host; do not change host configuration as part of this source task.
13. Seal the exact source diff, including the approved observability-plan
    addition, for Grok-first distinct-family review.

## Source checkpoint versus operational gate

The source checkpoint may be committed after:

- the amendment has converged through distinct-family architecture review;
- parser, coordinator, composition, and macOS-safe tests pass;
- Linux integration code compiles for its intended build tags;
- the exact source diff receives substantive matching-digest distinct-family
  approval; and
- leak, path, generated-artifact, and unrelated-diff checks pass.

This does not complete the Task 11 operational gate. Linux+Docker execution
with approved private input, numeric sizing sign-off, and any RhoNAS host
change remain separate operator-gated work.
