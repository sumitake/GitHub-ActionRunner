# Workflow migration

This runbook describes how a repository's workflows are migrated onto the
three-state Portable GHAR routing contract, and which workloads are
intentionally kept off self-hosted capacity even after migration. It
assumes the components in
[Architecture overview](../architecture/overview.md) and the boundaries
in [Trust boundaries](../security/trust-boundaries.md).

Phase 2 source does not yet ship the later consumer-workflow migration
phase. This page describes its intended migration contract; it is not a
claim that any repository has been migrated onto this contract today.

## Stable required checks

Migrating a repository never renames its required status checks. The
routing contract is added to an existing workflow's `runs-on` expression
without changing its job IDs or check names, so branch-protection
configuration keeps working across the migration and any later rollback.
The public consumer routing expression is:

```yaml
runs-on: >-
  ${{
    vars.PORTABLE_GHAR_ROUTE == 'self-hosted'
    && vars.PORTABLE_GHAR_SCALE_SET
    || vars.PORTABLE_GHAR_ROUTE == 'legacy'
    && vars.PORTABLE_GHAR_LEGACY_LABEL
    || 'ubuntu-latest'
  }}
```

A missing, empty, case-variant, or unknown route value always selects
`ubuntu-latest` -- a GitHub-hosted runner -- never a local one. Only the
Worker ever writes `PORTABLE_GHAR_ROUTE`.

## Hosted-only workloads

Not every workload is a migration candidate. **Secret-bearing**,
**release**, **deployment-write**, and other explicitly **unsupported**
job classes (for example, jobs whose semantics depend on an unqualified
host or browser profile) stay on **GitHub-hosted** runners even after a
repository is otherwise migrated, unless a job is separately reviewed and
its eligibility explicitly extended. Self-hosted capacity existing for a
repository is never, by itself, a reason to move a sensitive job onto it.

## Per-workflow eligibility

Eligibility is evaluated **per workflow**, not per repository: a
repository can have some workflows migrated to the routing expression
above while its secret-bearing or release workflows remain permanently
pinned to GitHub-hosted runners. Each candidate workflow's path, exact
blob content hash, job IDs, and required-check names are bound before
migration, so a later edit to that workflow cannot silently change what
was reviewed and approved for local routing.

## Route attestation as proof

Route confirmation relies on **route attestation, not a variable read**,
as its proof. A dedicated attestation step in each candidate workflow
records the runner's actual `runner.environment` at run time; a
hosted-confirmed repository is only accepted once a bound candidate run's
attestation step has been positively observed reporting `github-hosted`,
and a self-hosted transition is only accepted once the same step reports
`self-hosted` at the exact expected workflow revision. Reading back the
`PORTABLE_GHAR_ROUTE` variable's value alone is never sufficient proof --
the variable states intent, and the attestation step is what confirms the
job actually ran where that intent said it should.

## Consumer notes: agent-collab-workspace (first migration target, 2026-08-22)

Captured during a RhoHaus-side effort to distribute `agent-collab-workspace`'s
self-hosted Linux CI off the capacity-constrained RhoNAS (QNAP) onto a second
host, ahead of the full Portable GHAR cutover. These record blockers to account
for when migrating this repo's workflows.

1. **The Linux unit-test suite is NOT host-portable as-is.** `unittest.yml`'s
   suite includes tests *of RhoNAS-specific infrastructure* that pass on a
   RhoNAS runner but fail on any other host (verified on a second host with the
   same runner image, different host):
   - `interfaces/dev_runner/tests/test_watcher_*` — "watcher Python path"
     `ChannelError` (validates the launchd/plugin watcher).
   - `scripts/rhonas-runner-ops/...test_forced_bump_rehearsal_is_hermetic` —
     "canary interruption evidence 1 != 0".
   These must be **host-guarded (skip on non-RhoNAS) or made hermetic** before
   the Linux suite can run on the ephemeral fleet. This is the load-bearing
   prerequisite for migrating `unittest.yml`.

2. **`required-gates.yml` is Tier-3 governance authority.** Changing its
   `runs-on` is not a routine migration edit — it trips classify-tier=T3,
   phase1-extension (Tier-3 peer review), and governance-migration-gate
   (Gate 2B: authority/adapter path requires a released `mirror_parity_only`
   Gate-1 packet). Its routing migration must go through the Tier-3 + Gate-2B
   process, not a casual relabel.

3. **A transition-ready `homelab-linux` label fleet already exists.** RhoNAS's
   workspace runners were relabeled to carry BOTH `rhonas` and `homelab-linux`,
   and a second host (LabMacPro) was stood up with matching `homelab-linux`
   runners. This shared label can serve as `PORTABLE_GHAR_LEGACY_LABEL` during
   the three-state transition, or inform scale-set naming.

4. **LabMacPro is a macOS host — not a Portable-GHAR host type** (profiles are
   `qts`/`systemd`). Its Linux runners are hand-rolled on Colima (Docker in a
   Linux VM), deliberately aligned to Portable GHAR conventions: runner image
   mirrors RhoNAS's (ubuntu 22.04 + py3.12 + runner 2.336.0); egress matches the
   `networkPolicy` deny-list (RFC1918 + link-local/metadata + CGNAT, with a
   docker-bridge carve-out); ephemeral per-job; unprivileged service user.
   Portable GHAR does not manage it; it coexists under the same `homelab-linux`
   label. Separately, LabMacPro runs a native **Intel macOS** self-hosted runner
   for the `provider-runtime-intel` build (which RhoNAS/Linux cannot do).

5. **Performance sizing (LabMacPro Colima).** The heavy unit-test suite runs
   slower under the Colima VM (subprocess-spawn overhead): it needs the
   `unittest.yml` job `timeout-minutes` >= 20 (RhoNAS-tuned 12 is too tight) and
   a Colima allocation of ~12 vCPU to keep `test_escalation` (107 real-subprocess
   spawns) under the 120s per-suite cap in `scripts/run_all_tests.py`.
