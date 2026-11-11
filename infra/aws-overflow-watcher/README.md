# AWS overflow watcher

One poll-only controller Lambda, one DynamoDB table, and an instance boot
wrapper. This directory does not deploy anything and contains no account
identifiers, credentials, or live resource ids.

Rule ids below are the controlling design rules. Later budget rules (C1-C6)
win where they disagree with earlier F/R lines (F0, F0b).

## What it does

Every minute, EventBridge invokes the controller (timeout 45 seconds). The
Lambda resource policy allows only that rule. The controller polls GitHub. It
does not accept a webhook.

One poll runs at a time. Each poll first takes a DynamoDB lease
(`LEASE#poll`, expiring 55 seconds after it is taken: longer than the timeout,
shorter than the schedule) with a conditional write. A poll that finds the
lease held, such as an async retry or a duplicate delivery, returns success
without reading or writing anything else. The lease is never deleted, so a
poll cannot remove a successor's lease. Lambda reserved concurrency is
optional (`ControllerReservedConcurrency`, empty by default for accounts whose
unreserved concurrency floor leaves no room).

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
- Per repo, a fully paginated HTTP 200 runner list with no available match
  is overflow-eligible (F2, R4, B3). A runner is available only when it is
  online, its labels contain the job's labels, and `busy` is false.
  `busy: true` counts as no capacity, the same as offline. A missing or
  non-boolean `busy` on an online label match fails closed and does not
  launch. Offline runners count as no capacity. The watcher does not
  require a registration the repo does not have.
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
terminal audit cleanup and is not set on open reservations. A per-job lock
refreshes a seven-day `expiresAt` while its reservation or instance is open.
That timestamp is garbage collection for a lock that is already idle. It is
not a capacity release.

One admitted job holds one lock, so a second poll does not debit it again.
An ephemeral runner minted for the admitted label tuple can still take a
narrower queued job, because GitHub assigns any queued job whose labels are
a subset of the runner's. The $33 stop keeps cancelling the stored
`workflowRunId`. The watcher does not make another GitHub call to find out
which job the runner took.

A definitive capacity or parameter refusal (including vCPU quota) is stored
as a failure, the uncreated reservation is reversed, and further launches
wait out a 15-minute cooldown. The handler does not loop on that error (C5).

R2 / F5. The month bucket is the America/Los_Angeles calendar month. The
all-in hourly price is a decimal dollar string supplied by config (instance
plus public IPv4 plus EBS). The initial debit is that rate times 6 hours,
rounded up to integer cents. Six hours is a reservation while the instance
is open, not a ceiling and not a permanent charge. Later polls add only the
positive delta of actual elapsed time past the per-instance watermark, split
across LA months, including across the November DST change. Duplicate or
stale invocations add zero. Open obligations stay on the books across the
month boundary. When a positive EC2 read shows the instance terminated, the
close trues the debit up to actual runtime (launch to the closing poll, at
least 60 seconds) times the all-in price, per LA month, in the same
transaction that closes the record. A short job therefore releases the rest
of its allowance; the only limits are the monthly budget and the grace stop.
A refund that would take a month ledger below zero cancels the close and
keeps the debit. Figures are estimated accrued cost, not AWS invoice charges.

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
Month, instance, and action claims only dedupe a cancel or an alert.
This poll advances only the minimum set it just chose. A cancel-wait claim
for an instance left out of that set is deleted, so a later reselection
starts a new wait instead of reusing an expired one.

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
   on a later poll, so it does not sleep inside the Lambda. A stop runs only
   for an instance in this poll's minimum set that is still owned (record
   and tag), still `pending` or `running`, and still has positive future
   burn. After the wait, a decisive workflow read of `True` (completed) or
   `False` (not completed) terminates that instance. A read of `None` is
   ambiguous: Ops is alerted, the claim stays `cancel_wait`, and the
   instance is not terminated. A failed or unavailable cancel still falls
   through to that single terminate after the bound when the read is
   decisive. It is not retried in a loop. An owned instance that is already
   `stopping` or `shutting-down` is transitional exposure: its future burn
   stays in the projection, and it is not reported as unknown. A missing
   tag, an uncertain describe, or any other state still fails closed.
4. Records and debits stay until DescribeInstances shows that exact instance
   id `terminated` (F3, R1). Accrual continues until then. The stop marker
   records the in-flight cancel for an instance this poll selected. It does
   not keep a runner in the stop set after a later poll leaves it out.
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

## Budget alarm

The controller log group has two metric filters on the JSON lines this
process already prints. `{ $.kind = "budget" }` increments
`OverflowWatcher / SoftCapCrossed`. `{ $.kind = "grace" }` increments
`OverflowWatcher / GraceCrossed`. Each metric has an alarm at a sum of at
least 1 over 60 seconds. Both alarms publish to one SNS topic
encrypted with a customer-managed KMS key that `sns.amazonaws.com` and
`cloudwatch.amazonaws.com` may use. `AlertEmail` subscribes to that
topic. The Lambda does not read the address, and launch
admission does not depend on it. Confirming the subscription is a live Ops
step. The template has no AWS Budget. `past-allowance` and the other
non-budget kinds stay log-only.

R5. `ec2:TerminateInstances` appears on the controller role only, and only
with `aws:ResourceTag/overflow-watcher` = `owned`. The runner role does not
have that action. The only call site is the budget-stop function
`advance_owned_stop`.

## Supervisor (F6, R3)

RunInstances user data is a self-contained bootstrap. It installs
`overflow_watcher` under `/opt/overflow-watcher` and sets `PYTHONPATH` to
that directory. It does not look for a source checkout. The launch template
user data only starts the supervisor when that install is already present.
`boot/supervisor.sh` is the same launcher. The runner command
must include `--ephemeral` (one job). The controller writes the encoded
JIT config to an SSM SecureString at `/overflow-watcher/jit/<client-token>`
and puts only that name in user data. The guest reads the value, deletes
the parameter, and sets `RUNNER_CONFIG` to the file and `RUNNER_COMMAND` to
a wrapper that execs `Runner.Listener`. The image is stock Ubuntu 24.04
(`AmiId` defaults to Canonical's public SSM parameter). Before it reads the
secret, the guest downloads the runner version pinned in
`release/manifest.json`, refuses it unless the sha256 matches, and installs
it at `/opt/actions-runner`. If that install fails, the secret is not read
and the supervisor takes the missing-config path below. The guest reads and
deletes the secret with a stdlib SigV4 client (`guest_ssm.py`), because
Ubuntu images have no aws CLI. It installs git with apt only if the image
lacks it. When GitHub pushes a runner self-update, the listener exits 3 or 4.
The supervisor relaunches it only after the updater writes
`update.finished` (waiting up to 120 seconds), at most three times;
otherwise that exit is reported like any other abnormal exit. The encoded config is not written
to DynamoDB or user data. The supervisor shuts the guest down
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

| Variable                                                    | Meaning                                                                                                                                                                                                |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ALL_IN_HOURLY_PRICE`                                       | Fetched all-in hourly price in dollars (instance + IPv4 + EBS).                                                                                                                                        |
| `AMI_ID`, `SUBNET_ID`, `SECURITY_GROUP_ID`, `INSTANCE_TYPE` | Launch placement. The template also requires a VPC id and an EBS size.                                                                                                                                 |
| `INSTANCE_PROFILE_NAME`                                     | Runner instance profile. The template names it `overflow-runner`.                                                                                                                                      |
| `GITHUB_APP_IDENTIFIER`, `GITHUB_APP_PEM`                   | Existing release App `ghar-release-settings`. Config App ID `4644050`. PEM from the BWS item id recorded in `docs/operations/overflow-watcher-deploy-inputs.md`. Id only; the PEM is not in this repo. |
| `WATCHED_REPOS`                                             | JSON list of `{id, owner, name, installation}` for the three repos, plus optional `runnerGroupId` (default 1). Use installation `154814987`. Config, not a code pin.                                   |
| `AlertEmail`                                                | `<ALERT_EMAIL>`. SNS subscription for the budget and grace alarms. Confirmation is a live step.                                                                                                        |
| `MONTHLY_SOFT_CAP_CENTS`                                    | `3000`. Stop-new threshold.                                                                                                                                                                            |
| `GRACE_PCT` or `GRACE_CENTS`                                | `10` or `300`. Must agree with the grace below.                                                                                                                                                        |
| `CONTINUE_ACTIVE_UNTIL_CENTS`                               | `3300`. Enforced estimate, not an invoice cap.                                                                                                                                                         |
| `BUDGET_CANCEL_WAIT_SECONDS`                                | Wait after cancel before a terminate. No default.                                                                                                                                                      |
| `BUDGET_STOP_EXCLUSIONS`                                    | JSON list of `{kind, pattern}`. Empty fails closed. Default excludes `deploy-*` and `migrate*` / `*migration*`.                                                                                        |
| `TABLE_NAME`                                                | DynamoDB table.                                                                                                                                                                                        |
| `CodeS3Bucket`, `CodeS3Key`, `CodeS3ObjectVersion`          | Template inputs for the Lambda zip. No defaults. Not an S3 object check.                                                                                                                               |

The watcher reuses the existing release App `ghar-release-settings` (App ID
`4644050`, installation `154814987`). It does not create a new GitHub App.
Those ids are deploy config, not pins in application code. The BWS item id for the PEM is recorded in `docs/operations/overflow-watcher-deploy-inputs.md`. The App is
installed on GitHub-ActionRunner, Contextual-Conversation-Gateway,
agent-collab-workspace, and keicrew. Watched repos stay the configured
three. Metadata: Read is mandatory on every GitHub App and is not
sufficient for any call below. No organization permissions.

GitHub's REST docs for
`POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig` require
"Administration" repository permissions (write). John granted Administration
write on this App on 2026-11-11, which unblocks live B1 registration.

| Permission     | Level                                     | Calls                                                                                                                                                                              |
| -------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Actions        | Read and write                            | Read lists queued runs and jobs. Write cancels a run during the budget stop. Write is the grant; read is included. If cancel fails, the controller terminates once after the wait. |
| Administration | Read and write (write granted 2026-11-11) | Read lists self-hosted runners. Write calls `generate-jitconfig` for the JIT runner.                                                                                               |
| Metadata       | Read                                      | Platform mandatory. It cannot be turned off. It does not authorize the calls above.                                                                                                |

Not requested, because this process does not call them: Contents, Workflows,
Checks, Secrets, Variables, Environments, Pull requests, and organization
runners.

Placeholder text `REQUIRED_INPUT` is treated as unset.

## Template

`template.yaml` is one CloudFormation file: the table, the Lambda, the
minute rule and its resource policy, the controller role, the runner role
and instance profile, a security group with an empty ingress list, and a
launch template with IMDSv2 required (`HttpTokens: required`),
`InstanceInitiatedShutdownBehavior: terminate`, and `DeleteOnTermination`
on the volume. Open reservations do not get a TTL timestamp.
`scripts/package-lambda.sh` writes the Lambda zip and a sibling binding
whose sha256 is that zip. The checker accepts the binding only when
`template.yaml` still passes `CodeS3Bucket`, `CodeS3Key`, and
`CodeS3ObjectVersion` into the function `Code` property, with no defaults.
That is an offline identity check. It does not read or attest an S3 object,
so the live object linkage stays unproven. Before deploy, Nova approves and
Ops runs a read-only comparison of the recorded zip with the object those
parameters name. Upload the zip with `--checksum-algorithm SHA256` so the
object carries `ChecksumSHA256`. The command was not run for this packet, so
the live object linkage stays UNPROVEN/HOLD:

```sh
aws s3api head-object \
  --bucket "$CodeS3Bucket" \
  --key "$CodeS3Key" \
  --version-id "$CodeS3ObjectVersion" \
  --checksum-mode ENABLED
```

`ContentLength` must equal `artifact_bytes` in the sibling
`.binding.json`. `ChecksumSHA256` is the base64 encoding of the raw 32-byte digest.
The binding stores `artifact_sha256` as hex. Compare with:

```sh
python3 -c 'import base64,sys;print(base64.b64encode(bytes.fromhex(sys.argv[1])).decode())' "$artifact_sha256"
```

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
