# Completing case 15 from the one-job canary

D2, Worker deployment, and the real canary remain operator steps. Install the
reviewed runtime-manifest assembly, Worker admin client, bounded runner
configuration layout, and this collector before D2. Rebuild the controller and
runner image, then assemble and approve their final manifest and overlay before
consuming D2's input. The bounded-credential amendment to the live acquisition
plan governs case 15.

The original pending report remains at
`<state_root>/conformance-report.json`, root-owned mode `0600`, in the private
state directory. Do not reconstruct it, copy cases from another run, or edit its
binding. The collector commits its exact digest, binding digest, and fleet
generation before acquisition. The manifest commits the image, policy, network,
and storage tuple; the overlay digest commits the concrete composition.

## Durable evidence

The store's `canary_evidence` row is an observation journal, not authority.
There is at most one row and at most 8192 bytes, reserved against the existing
history budget before acquisition. It preserves evidence after ordinary
assignment compaction. A restart of the same report preserves observations; a
fresh report replaces only this proof journal. No acquisition, lease, permit, or
listener-release decision consults the row. Extra work invalidates the one-job
proof without changing whether that work is authorized by `canary-only`.

| Case 15 item                                 | Source and durable observation                                                                                                                                                                                                                                         |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Governed acquisition                         | `assignments.acquisition_outcome=acquired`, not revoked, joined to its completed `message_acquisitions` batch. The journal retains the batch result digest and a digest of the assignment identity.                                                                    |
| One JIT attempt and live compatibility       | The lifecycle writes intent before `GenerateJITAuthorized`; the journal counts attempts, saturating at two. `session.Compatibility()` from the in-run authenticated session supplies `DisableUpdate` and the single-name-label observation.                            |
| Existing authority used for listener release | The journal retains the existing acquisition permit's digest and policy digest, requires `jit`, the same generation/repository, `canary-only`, and capacity one. The completed `listener-release` effect must name that digest. No new permit is created.              |
| Real listener and one successful job         | The existing identity-checked Started/Completed observations advance the assignment. The journal records the Completed result; only `success` and one job pass. The workflow run ID must match the scale-set assignment.                                               |
| Checkout, sandbox, credentials, and tools    | The reviewed workflow sends the closed observation described below while the job is running. The journal retains only its bounded fields, revision, and run ID.                                                                                                        |
| Deregistration                               | Ordinary lifecycle cleanup proves absence by both the known upstream runner ID and opaque name. The cleanup callback records that proof; a renamed but still-present runner does not pass.                                                                             |
| Runtime reclamation                          | The same cleanup callback follows the existing managed runtime absence proof. Finalization occurs in the terminal-compaction transaction after acknowledgement, capacity/slot retirement, and admission clearing. The proof survives deletion of the assignment graph. |
| Safe sealing state                           | A read-only consistent snapshot requires `disabled` and no live assignment, runner slot, reservation, or admission projection.                                                                                                                                         |

The store cannot independently observe which tool ran, checkout's transport,
credential readability inside the job, or the repository's reviewed revision.
Those claims come from the workflow. The operator must compare its reported run
ID and revision with the single dispatched GitHub run and approved repository
revision before sealing. This is evidence correlation; it adds no per-job
acquisition binding or single-use authority.

## Workflow reporting

Install the example as described in
[the template instructions](../../examples/live-acquisition/README.md). Its final
step runs only after all ten tool probes succeed. It verifies the HTTPS origin,
checks the actual job environment for the inherited JIT variable, runs the
existing sandbox conformance helper, and measures own-job `/proc` and decoded
credential readability. Own-job readability is allowed and recorded as booleans.
The helper receives its required closed runtime environment; the job's actual
JIT-environment check runs separately before that filtered helper call.

The probe also scans the existing runner diagnostics for the original encoded
JIT and sensitive decoded credential components. It refuses indirect files,
oversized files, and an unbounded traversal. It never emits credential bytes or
raw errors. This is a measurement of diagnostics present at the final step, not
an independent audit of future listener output. The controller and image's
existing environment, mount, and logging boundaries remain part of the proof;
the workflow does not gain controller credentials or inspect private host logs.
Normal GitHub job-scoped platform credentials are required for the action probes.

The final step creates one private Unix socket at
`/runner/.portable-ghar/canary-report.sock`, inside the job's existing tmpfs. It
waits at most two minutes for the controller's ordinary running-job
reconciliation to read one canonical JSON document. The controller queries only
the exact live managed runner identity through the fixed `canary-read` command,
then persists the observation under the existing lifecycle lock before a
Completed event can reclaim the tmpfs. There is no host mount, HTTP endpoint,
background reporting service, raw log ingestion, or new acquisition rule. A
missing, malformed, mismatched, or interrupted observation cannot yield a pass.
A transport interruption is not replayed automatically.

## Operator commands

Run these on the QTS target through the verified control host. Keep outputs in
the private canary journal; do not publish the report, database, or real logs.
Use the exact approved controller binary and overlay throughout:

```sh
controller='<release_root>/bin/portable-ghar-controller'
overlay='<private_overlay_path>'
"$controller" canary-status --config="$overlay"
```

Wait for `ready_to_seal:true`, `invalid:false`, `jit_count:1`, `job_count:1`,
`job_result:"success"`, and `finalized:true`. Verify the run ID, revision,
original report digest, generation, and policy digest against the private
journal and GitHub's read-only run status. Disable acquisition immediately after
the job, using the existing `acquisition set` command in the phase 8 runbook.
Never dispatch or replay another job to repair an uncertain result.

After acquisition is disabled and the reverse steps/residue checks prove the
canary stopped, run once:

```sh
"$controller" canary-seal --config="$overlay"
"$controller" canary-status --config="$overlay"
```

`canary-seal` reads durable evidence and the pinned runtime files only. It makes
no GitHub, Docker, fence, or Worker call. It replaces only case 15 in the same
pending report, recomputes the overall status, report digest, and build seal,
validates the completed report, then atomically replaces the private report and
syncs its parent directory. Cases 1-14, their target evidence, the original
binding, and cleanup remain identical. The receipt reports the original report
digest, completed report digest, and case 15 observation digest. Retain it
privately. The command does not consume evidence or enable acquisition.

If the command's outcome is uncertain, inspect `canary-status` first. A completed
report has `report_status:"passed"` and a new digest; `ready_to_seal` is false
because it is no longer pending. Do not overwrite it with another D2 report or
retry sealing a report already completed. Leave acquisition disabled.
