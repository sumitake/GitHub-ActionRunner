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
one overlay repository naming the selected scale set. The probe must also name
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

## Remaining runbook input

The D5 inventory is required before selecting the exact target-local legacy and
watchdog reverse commands. A return handover writes N+2. The original canary
manifest and D2 report remain bound to N+1, so blindly restarting the observer or
rearming its old watchdog after that handover is not a verified restoration.
The live acquisition plan's D5 explicitly requires reading the live fence before
designing that handover. Keep the affected script steps pending until the
operator supplies that inventory; no host command has been run by an agent.
