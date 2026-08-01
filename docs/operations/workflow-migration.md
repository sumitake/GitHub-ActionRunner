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
