# Dedicated canary repository template

These files are examples, not a workflow enabled in this repository. The
operator installs and reviews them in the dedicated canary repository before
D2. No agent dispatches the workflow.

Copy `workflow.yml` to `.github/workflows/portable-canary.yml`, `probe.mjs` to
`canary/probe.mjs`, and `fixture/` to `fixture/` in that repository. Replace the
single literal `example-canary` label with the exact D7 single-name label. Keep
all action revision pins and the probe unchanged. Do not add another trigger,
job, or consumer of that label. Use a repository containing only these synthetic
fixtures and reviewed workflow/probe files, with at least two commits for the
dependency comparison. Record and review the resulting head and parent revisions
privately. The dispatch ref must resolve to that head revision when dispatched.

Prerequisites: GitHub Actions, dependency graph/review, CodeQL code scanning,
artifact attestations, and the action permissions in the example must be
available for the canary repository. The Gitleaks action needs its normal license
when used by an organization; use an eligible repository rather than introducing
an unreviewed secret. Install no production code or real credentials in the
fixture repository. The ordinary job-scoped GitHub token and artifact/OIDC
credentials stay subject to the accepted one-job credential boundary.

Each named action really runs. Go and Node execute the tiny fixtures. SBOM,
Trivy, CodeQL, dependency review, Gitleaks, artifact upload, and attestation use
only synthetic inputs. The final step requires successful step outcomes and
reports no raw tool output. The only uploaded fixture is `fixture/index.js`.
GitHub's normal action logs still exist; keep the canary repository and its
operator outputs private as appropriate, and never copy real logs here.

Dispatch inputs are the exact pending report digest and the approved parent
revision. The workflow reports `GITHUB_RUN_ID` and `GITHUB_SHA`; compare both to
the single dispatch recorded in the private journal before sealing. These inputs
correlate evidence and do not grant acquisition authority.

The final Node process creates a private Unix socket in the existing runner
tmpfs and waits for ordinary controller reconciliation to collect a bounded JSON
observation. It reports own-job credential readability as booleans under the
operator-approved bounded-exposure amendment. Credential contents are never
printed or uploaded. A missing reader times out and fails the job. Do not rerun
the job to recover from an ambiguous dispatch or report transfer.

The Node tests use synthetic credentials and temporary local sockets only:

```sh
npm run canary:test
go tool actionlint -config-file examples/live-acquisition/actionlint.yaml examples/live-acquisition/workflow.yml
```

See [the case 15 evidence mapping](../../docs/operations/live-acquisition-case15.md)
and the phase 8 operator runbook for lifecycle and stop commands. Finish image,
manifest, overlay, and repository review before D2 consumes its input.
