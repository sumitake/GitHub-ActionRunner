# Read the canary start inputs

Run this only as the operator on the QTS target through the verified control
host. It is a phase 8 prerequisite, not a canary launcher. Worker deployment,
D5, D7, D2, and the real canary remain separate operator steps.

After the acquiring controller has established its authenticated Worker session
while still `disabled`, read the exact pending runtime and intended policy:

```sh
<controller_binary> canary-plan \
  --config=<overlay_path> --eligible-scale-set=<canary_scale_set>
```

The root-only command reads the pinned manifest/overlay and pending D2 report,
then queries the existing root-local admin probe. It requires a current
`disabled` policy, an authenticated nonzero Worker lease generation, and exactly
one active overlay repository naming the selected scale set. Its alias and
scale-set name must satisfy the Worker's existing V1 identifier constraint. The probe must also name
that same pending report digest, captured when the process matched it to its
runtime at startup. That digest commits its build, manifest, overlay, fleet
counter, and report run; replacing files beside an older process cannot produce
a plan from mixed inputs. It does not open another
Worker session, read a credential, change policy, dispatch work, or consume
input/evidence. An unready or unavailable session yields an error; a later
read-only query is safe.

Retain the receipt in the private canary journal. It supplies these start fields:

| Receipt field            | Worker `portable-canary-start` field |
| ------------------------ | ------------------------------------ |
| `fleet_id`               | `fleetId`                            |
| `repository_alias`       | `repositoryAlias`                    |
| `scale_set`              | `scaleSet`                           |
| `configuration_revision` | `configurationRevision`              |
| `policy_digest`          | `policyDigest`                       |
| `fence_generation`       | `fenceGeneration`                    |
| `lease_generation`       | `leaseGeneration`                    |

The receipt also records the original pending `report_digest`. Compare that to
the approved D2 report. The policy preview uses the same Go function as the
actual `acquisition set --set=canary-only` transition; no script reimplements its
digest. Policy epochs do not enter that digest. The fence generation is N+1;
lease generation is independent and must never be guessed from N or assumed to
be one.

The session counter comes only from authenticated session/heartbeat responses
already processed by the running controller. It is metadata, not authority. It
can become stale after readback; the Worker's existing start precondition rejects
a mismatch. No automatic transport retry or replacement session is added.
Generate a fresh command identity only in the journaled operator step described
in [Worker canary authority](worker-canary-authority.md). Do not dispatch until
the verified Worker start and local canary-only transition both succeed.

## Bind the one approved manual run

`canary-only` also requires an independent expected job identity. Before the
first approval file exists, the acquiring controller waits without polling
GitHub. It keeps its existing policy and authenticated Worker heartbeat; the
missing approval grants no acquisition authority.

Only after the separate operator go, the verified Worker start, and the local
canary-only transition, dispatch the reviewed manual workflow. Read its actual
run ID, source revision, workflow ref, event, and repository from authenticated
GitHub metadata. Check that revision against the reviewed source and workflow;
workflow inputs and job output are not evidence of the revision. Do not guess a
run ID or authorize a run based only on its display name. This command neither
dispatches work nor queries GitHub; the root operator supplies that verified
identity:

```sh
<controller_binary> canary-bind \
  --config=<overlay_path> --alias=<approved_repository_alias> \
  --run-id=<verified_run_id> \
  --workflow-ref=owner/repository/.github/workflows/canary.yml@refs/heads/main \
  --event=workflow_dispatch
```

The repository and sole scale-set label come from the pinned overlay. The
command requires the matching pending D2 report and fresh, zero-activity canary
evidence. It exclusively publishes `canary-job-approval.json` in the existing
root-owned private state directory (file mode `0400`). It never overwrites or
repairs an existing approval. The receipt records its digest and run ID; retain
it in the private journal. Publication does not enable policy or grant Worker,
fence, capacity, or conformance authority.

Before acquisition, the controller compares every offer's repository, owner,
run ID, workflow ref, event, and sole requested label with that approval. It
acknowledges unrelated notifications without acquiring or durably recording
their jobs, including notifications mixed with the approved offer. It rechecks
the approval immediately before acquisition and again before JIT authorization.
The approval's accepted bytes are pinned for the process lifetime; a subsequent
change, disappearance, or unsafe file fails closed and cannot heal in place.
The scale-set offer has no source revision field, so the authenticated run ID
and operator revision check are required together.

A failed or uncertain canary still uses the existing fail-stop, operator-led
recovery. Do not replace the approval to switch runs, automatically cancel or
rerun work, or restart into a guessed generation. End stopped and disabled with
zero activity, retain evidence, and follow the exact approved fence cleanup.

## Remaining runbook input

The D5 inventory is required before selecting the exact target-local legacy and
watchdog reverse commands. A return handover writes N+2. The original canary
manifest and D2 report remain bound to N+1, so blindly restarting the observer or
rearming its old watchdog after that handover is not a verified restoration.
The live acquisition plan's D5 explicitly requires reading the live fence before
designing that handover. Keep the affected script steps pending until the
operator supplies that inventory; no host command has been run by an agent.
