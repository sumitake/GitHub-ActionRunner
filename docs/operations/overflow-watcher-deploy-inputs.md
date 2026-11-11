# Overflow watcher GitHub App deploy inputs

The overflow watcher reuses the existing release App `ghar-release-settings`.
It does not create a new GitHub App. These values are deploy config, not
pins in application code. This page records identifiers only. It does not
contain a private key or any other secret value.

| Input                       | Value                                                                                 |
| --------------------------- | ------------------------------------------------------------------------------------- |
| App name                    | `ghar-release-settings`                                                               |
| App ID                      | `4644050` (CloudFormation parameter `GithubAppIdentifier`)                            |
| Installation ID             | `154814987` (each `WatchedRepos[].installation`)                                      |
| Installed on                | GitHub-ActionRunner, Contextual-Conversation-Gateway, agent-collab-workspace, keicrew |
| Watched repos               | Contextual-Conversation-Gateway, agent-collab-workspace, keicrew                      |
| BWS item id for the App PEM | `6fd60b4e-5511-402b-842c-b4ff0071e77e`                                                |
| BWS project                 | Trusted Automation, id prefix `d6b52362`                                              |
| Current App permissions     | Actions read/write, Administration read, Metadata read                                |

Fill `GithubAppPem` from that BWS item at deploy. Do not commit the PEM.

## Open John decision — B1 registration is blocked

Live JIT registration calls
`POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig`. GitHub's
REST docs (API version 2026-03-10) require
"Administration" repository permissions (write) for that endpoint:

<https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2026-03-10#create-configuration-for-a-just-in-time-runner-for-a-repository>

This App has Administration read only. Read can list runners. It cannot
mint a JIT config. B1 registration stays blocked until John grants
Administration write, or rules otherwise. This change does not assume
that grant and does not add a workaround.
