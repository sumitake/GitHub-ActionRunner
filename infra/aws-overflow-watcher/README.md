# AWS overflow watcher

One poll-only controller Lambda, one DynamoDB table, and an instance boot
wrapper. This directory does not deploy anything and contains no account
identifiers, credentials, or live resource ids.

Rule ids below are the controlling design rules. Later budget rules (C1-C6)
win where they disagree with earlier F/R lines (F0, F0b).

## What it does

Every minute, EventBridge invokes the controller (reserved concurrency 1,
timeout 45 seconds). The Lambda resource policy allows only that rule. The
controller polls GitHub. It does not accept a webhook.

Admission (C1, F1, F2, R4, V5-04):

- Repos are the configured set: Contextual-Conversation-Gateway,
  agent-collab-workspace, and keicrew. Ids, owner, and installation ids come
  from config. `keicrew-public` is rejected. An empty or placeholder config
  does not launch.
- A job is admitted only when every `runs-on` label is one of `self-hosted`,
  `Linux`, `X64`, and `homelab-linux`, matched in exact case (F1). Empty
  `runs-on` is denied. Labels `rhonas`, `macOS`, `intel-labmac`, `ubuntu-*`,
  `macos-*`, or any label containing `dispatch` are denied.
- The job must have been queued for at least five minutes.
- Per repo, a fully paginated HTTP 200 runner list with no matching online
  runner is overflow-eligible (F2, R4). Offline runners count as no capacity.
  The watcher does not require a registration the repo does not have.
- Any API error, partial page, malformed body, unauthorized response, or
  missing or exhausted rate-limit header blocks launch for that repo.

There is no runner-count limit (C5). Cost is the only admission gate.

## Reservations and accrual

R1 / F4. A launch writes a ClientToken reservation and its 6-hour allowance
debit in one DynamoDB transaction before `RunInstances`. When an instance id
comes back, one `TransactWriteItems` deletes the reservation and puts the
instance record. The debit stays, so the slot's committed cost never drops
in that step. An unresolved `RunInstances` (timeout or 5xx) leaves the
reservation in place. A later poll retries that same ClientToken with the
parameters stored on the reservation. EC2 describe results and any index
count cannot release a reservation. After the retry window (15 minutes) the
reservation still counts and Ops is alerted once. TTL is enabled only for
terminal audit cleanup and is not set on open reservations.

A definitive capacity or parameter refusal (including vCPU quota) is stored
as a failure, the uncreated reservation is reversed, and further launches
wait out a 15-minute cooldown. The handler does not loop on that error (C5).

R2 / F5. The month bucket is the America/Los_Angeles calendar month. The
all-in hourly price is a decimal dollar string supplied by config (instance
plus public IPv4 plus EBS). The initial debit is that rate times 6 hours,
rounded up to integer cents. Six hours is an allowance, not a ceiling and
not a refundable minimum. Later polls add only the positive delta of actual
elapsed time past the per-instance watermark, split across LA months,
including across the November DST change. Duplicate or stale invocations add
zero. Open obligations stay on the books across the month boundary. Figures
are estimated accrued cost, not AWS invoice charges. Admission debits are
not refunded when a job finishes early.

## Budget

C1. A new launch is refused when estimated month spend (ledger, which
includes open reservation debits) plus the new allowance would exceed
`MONTHLY_SOFT_CAP_CENTS` (3000).

C3. The first time the estimate passes 3000 cents in a month bucket, John
gets one alert with the estimated overage and the cause.

C2 / C4b. `CONTINUE_ACTIVE_UNTIL_CENTS` (3300) is the ceiling. It is an
estimate, not a guaranteed invoice limit. Every poll recomputes the
projection: the month ledger (admission debits and accruals, which are not
reduced) plus remaining future burn of excluded work plus unresolved
exposure plus remaining future burn of eligible instances. There is no
survivor watermark. A prior evaluation does not suppress a later stop.
Month, instance, and action claims only dedupe a cancel or an alert and
let a cancel wait finish.

The controller intervenes only when that projection is above 3300. At or
below 3300 nothing is stopped. Above it, only instances with positive
future burn are stopped, smallest set first (highest remaining future
burn, then newest launch, then instance id). If the ledger plus excluded
and unresolved future is already at or above 3300, every eligible instance
with positive future burn is stopped. An instance whose avoidable future
burn is zero is left running. Spend that is already on the ledger and
cannot be avoided raises the grace alert and does not terminate anything.

1. A target must have both a DynamoDB instance record written by this
   watcher and the `overflow-watcher=owned` tag. Unknown state or
   ownership fails closed: that instance is not stopped, its remaining
   burn stays in the projection, new launches are refused, and Ops is
   alerted. Ownership, tag, and state are read again immediately before
   each cancel and each terminate. Tagged-instance reads can raise
   committed cost (an unknown tagged instance is held once) and never
   lower it (F3, F7f).
2. The assigned workflow, job, and labels are matched against
   `BUDGET_STOP_EXCLUSIONS`. Excluded deploy or migration work is never
   stopped. Its future burn stays in the projection. Empty exclusions
   fail closed and do not launch.
3. The controller cancels the assigned workflow run
   (`POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel`), then waits
   `BUDGET_CANCEL_WAIT_SECONDS`. The wait is stored in DynamoDB and finished
   on a later poll, so it does not sleep inside the Lambda. Terminate runs
   only if the projection is still above the ceiling, the instance still
   has positive future burn, it is still `pending` or `running` after the
   bound, the workflow has not completed, and DescribeInstances is
   unambiguous. A failed or unavailable cancel still falls through to that
   single terminate after the bound. It is not retried in a loop.
4. Records and debits stay until DescribeInstances shows that exact instance
   id `terminated` (F3, R1). Accrual continues until then. The stop marker
   dedupes the action for that instance. It does not forgive a later poll.
5. John and Ops get one grace alert for the month, with the estimated
   overage, the cause, and the instance ids selected for stop. The alert
   claim is written only after the log line is emitted. A failed emit
   leaves a retry record and the next poll tries again. The soft-cap alert
   uses the same rule.

This stop can fail an in-progress overflow job. It does not touch untagged
instances, local runners, or unrelated jobs. There is no idle sweep and no
timed kill (F6, R3). The instance supervisor is a separate path: it shuts
the guest down only after a proven normal completion, which makes EC2
terminate the instance because
`InstanceInitiatedShutdownBehavior` is `terminate`.

R5. `ec2:TerminateInstances` appears on the controller role only, and only
with `aws:ResourceTag/overflow-watcher` = `owned`. The runner role does not
have that action. The only call site is the budget-stop function
`advance_owned_stop`.

## Supervisor (F6, R3)

`boot/supervisor.sh` starts `overflow_watcher.supervisor`. The runner command
must include `--ephemeral` (one job). The supervisor shuts the guest down
only when the listener and worker process tree have exited naturally, the
supervisor did not restart them, a job was actually assigned, and no worker
is still alive. Exit code 0 by itself is not proof. A missing runner config,
a never-assigned runner, or an abnormal exit keeps the instance up and emits
one report at 30 minutes. `config.sh remove` and the runner DELETE endpoint
are not called.

## Required inputs

Unset or invalid spend knobs and required inputs do not launch. An empty
`BUDGET_STOP_EXCLUSIONS` does not launch. The shipped default excludes
deploy and migration workflow and job names.

| Variable                                                    | Meaning                                                                                                                                |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `ALL_IN_HOURLY_PRICE`                                       | Fetched all-in hourly price in dollars (instance + IPv4 + EBS).                                                                        |
| `AMI_ID`, `SUBNET_ID`, `SECURITY_GROUP_ID`, `INSTANCE_TYPE` | Launch placement. The template also requires a VPC id and an EBS size.                                                                 |
| `INSTANCE_PROFILE_NAME`                                     | Runner instance profile. The template names it `overflow-runner`.                                                                      |
| `GITHUB_APP_IDENTIFIER`, `GITHUB_APP_PEM`                   | GitHub App identity and private key. Not stored in this repo.                                                                          |
| `WATCHED_REPOS`                                             | JSON list of `{id, owner, name, installation}` for the three repos.                                                                    |
| `MONTHLY_SOFT_CAP_CENTS`                                    | `3000`. Stop-new threshold.                                                                                                            |
| `GRACE_PCT` or `GRACE_CENTS`                                | `10` or `300`. Must agree with the grace below.                                                                                        |
| `CONTINUE_ACTIVE_UNTIL_CENTS`                               | `3300`. Enforced estimate, not an invoice cap.                                                                                         |
| `BUDGET_CANCEL_WAIT_SECONDS`                                | Wait after cancel before a terminate. No default.                                                                                      |
| `BUDGET_STOP_EXCLUSIONS`                                    | JSON list of `{kind, pattern}`. Empty fails closed. Default excludes `deploy-*` and `migrate*` / `*migration*`.                          |
| `TABLE_NAME`                                                | DynamoDB table.                                                                                                                        |
| `CodeS3Bucket`, `CodeS3Key`                                 | Template only. Zip of this package. No default.                                                                                        |

GitHub App permissions this poll needs, which the operator must grant:

- Actions: Read, to list queued workflow runs and jobs.
- Actions: Write, to cancel a workflow run during the budget stop. Read is
  not enough for that call. If write is missing, cancel fails and the
  controller terminates after the wait bound, once.
- Administration: Read, to list the repo's self-hosted runners.

Placeholder text `REQUIRED_INPUT` is treated as unset.

## Template

`template.yaml` is one CloudFormation file: the table, the Lambda, the
minute rule and its resource policy, the controller role, the runner role
and instance profile, a security group with an empty ingress list, and a
launch template with IMDSv2 required (`HttpTokens: required`),
`InstanceInitiatedShutdownBehavior: terminate`, and `DeleteOnTermination`
on the volume. Open reservations do not get a TTL timestamp.

## Tests

Offline. DynamoDB Local is started by `scripts/run-tests.sh` (the upstream
jar, or a jar already listening on localhost port 8000). No AWS account and
no GitHub calls.

```sh
sh infra/aws-overflow-watcher/scripts/run-tests.sh
```

The repository-metadata job in CI runs that script on `ubuntu-24.04`, the
hosted runner label this repo already uses. It is not a separate status
check.
