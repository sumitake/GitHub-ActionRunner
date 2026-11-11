# Overflow watcher GitHub App deploy inputs

The overflow watcher reuses the existing release App `ghar-release-settings`.
It does not create a new GitHub App. These values are deploy config, not
pins in application code. This page records identifiers only. It does not
contain a private key or any other secret value.

| Input                       | Value                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------- |
| App name                    | `ghar-release-settings`                                                                 |
| App ID                      | `4644050` (CloudFormation parameter `GithubAppIdentifier`)                              |
| Installation ID             | `154814987` (each `WatchedRepos[].installation`)                                        |
| Installed on                | GitHub-ActionRunner, Contextual-Conversation-Gateway, agent-collab-workspace, keicrew   |
| Watched repos               | Contextual-Conversation-Gateway, agent-collab-workspace, keicrew                        |
| BWS item id for the App PEM | `6fd60b4e-5511-402b-842c-b4ff0071e77e`                                                  |
| BWS project                 | Trusted Automation, id prefix `d6b52362`                                                |
| Current App permissions     | Actions read/write, Administration read/write (write granted 2026-11-11), Metadata read |

Fill `GithubAppPem` from that BWS item at deploy. Do not commit the PEM.

## B1 registration permission

Live JIT registration calls
`POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig`, which
needs "Administration" repository permissions (write):
<https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2026-03-10#create-configuration-for-a-just-in-time-runner-for-a-repository>.
John granted that on 2026-11-11.

## Stack inputs (chosen 2026-11-11)

These are deploy config for `infra/aws-overflow-watcher/template.yaml`.
`InstanceType`, `VolumeSizeGiB`, `AllInHourlyPrice`, and
`BudgetCancelWaitSeconds` keep no template default, so the price cannot
silently disagree with the type. Change the price whenever the type, size,
or region changes.

| Input                           | Value                                                                                                                               |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `AmiId`                         | Template default: `/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id`                              |
| `InstanceType`                  | `c8a.xlarge` (4 vCPU, 8 GiB, x86_64)                                                                                                |
| `VolumeSizeGiB`                 | `30` (gp3 root, `/dev/sda1`)                                                                                                        |
| `AllInHourlyPrice`              | `0.22383`                                                                                                                           |
| `BudgetCancelWaitSeconds`       | `300`                                                                                                                               |
| `ControllerReservedConcurrency` | Empty (no reservation; account 922176437318 has a concurrency limit of 10, all unreserved). The poll lease runs one poll at a time. |
| `AlertEmail`                    | `hal@osumi.co` (the subscription must be confirmed from that mailbox)                                                               |
| `VpcId` / `SubnetId`            | Default VPC; a public subnet whose AZ offers `c8a.xlarge`                                                                           |

Runner image: stock Ubuntu 24.04 from Canonical's public SSM parameter,
resolved to one AMI id at each stack create or update. No custom AMI.
Ubuntu, not Amazon Linux, because `actions/setup-python` publishes Linux
builds for Ubuntu only, and every admitted job uses it. At boot the guest
downloads the Actions runner pinned in `release/manifest.json`, checks its
sha256, and installs it at `/opt/actions-runner` before it reads the JIT
secret. The guest reads and deletes the secret with a stdlib SigV4 client,
because Ubuntu images do not ship the aws CLI.

Price (on-demand, us-west-2, AWS public Price List files published
2026-11-10 for EC2 and 2026-11-05 for VPC; looked up 2026-11-11):

| Part                          | Rate                      | Per hour  |
| ----------------------------- | ------------------------- | --------- |
| `c8a.xlarge` Linux            | $0.21554/hr               | 0.2155400 |
| In-use public IPv4            | $0.005/hr                 | 0.0050000 |
| gp3 storage, 30 GiB           | $0.08/GB-month × 30 ÷ 730 | 0.0032877 |
| Total, rounded up to 5 places |                           | 0.22383   |

Admission reserves 6 hours at this price (135 cents) per launch. That is a
reservation, not a permanent charge: when the watcher sees the instance
terminated, it trues the month ledger to actual runtime times
`AllInHourlyPrice` (at least 60 seconds). The binding limits stay the $30
month budget and the $33 grace stop; no runner-count cap.

`SubnetId` must be a default-VPC public subnet (`MapPublicIpOnLaunch` true).
The template does not request a public address itself; the subnet assigns
one, and the runner needs it for GitHub egress because there is no NAT.
Before deploy, check read-only that the subnet's AZ offers `c8a.xlarge`
(`aws ec2 describe-instance-type-offerings --location-type availability-zone --filters Name=instance-type,Values=c8a.xlarge`). gp3 baseline IOPS and throughput carry no
extra charge.
