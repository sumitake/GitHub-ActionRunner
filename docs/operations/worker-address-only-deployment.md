# Worker address-only deployment

This runbook deploys only the `github-actionrunner` Cloudflare Worker in its
address-only state. Ordinary session, heartbeat, lease, archive, selector, and
state-changing administration paths remain behind the production authority
fence. The only live effect is a natural, once-per-minute Cron receipt for each
inventoried Durable Object and an authenticated read-only status query.

The bounded QTS live canary is a separate deployment leg. It installs no
persistent observer, watchdog, or cron. A missing or rejected QTS OCI artifact
does not invalidate this already-completed Worker deployment, and no QTS
artifact is consumed by these steps.

## Private production inputs

The operator's private deployment packet, not this public repository, supplies
the real fleet inventory and live Personal account identifier. The following
descriptor is a synthetic shape example with the fixed address-only timing and
capacity terms:

```json
{
  "accountId": "<32-lowercase-hex-account-id>",
  "fleetIds": ["alpha", "beta", "gamma"],
  "timestampWindowMs": 5000,
  "nonceTtlMs": 60000,
  "maxFleets": 3,
  "perFleetDeadlineMs": 10000,
  "cronBudgetOverheadMs": 5000,
  "cronTickBudgetMs": 35000,
  "inventoryRevision": "1",
  "inventoryDigest": "786c8d5ae1c3ebeea30656a1a48f87c0124132c26f090d2d099425bd9c5b1dd3"
}
```

The digest is SHA-256 over this exact UTF-8 preimage:

```text
{"fleetIds":["alpha","beta","gamma"],"protocol":"cron-address-v1","revision":"1"}
```

For deployment, substitute the private packet's exact sorted three-fleet
inventory and recompute its digest. Changing any fleet or revision requires a
new descriptor and digest; it is not an in-place operational edit.

## Admission gates

Before creating private inputs:

1. Check out the exact merged `main` commit in a clean worktree. Record its
   commit and tree, verify the commit signature, and require the exact-head CI
   and review receipts. A later commit invalidates those receipts.
2. Require `git status --porcelain=v1 --untracked-files=all` to be empty and
   `HEAD` to equal `origin/main`. Deploying from a topic branch, generated tree,
   or dirty checkout is prohibited.
3. Read the Cloudflare Personal account and account Workers subdomain from the
   live API. The account identifier must match the established Personal-account
   prefix. Do not copy an account or permission-group identifier from a prior
   handoff.
4. Read the current API-token permission groups and select the unique group
   whose name and scope are `Workers Scripts Write`. An absent, duplicate, or
   differently scoped result is a stop.
5. Prove that an existing script named `github-actionrunner` is absent. An
   unexpected existing script is not overwritten; inventory and adjudicate it
   first.

The existing `v0.1.0` and `v0.1.1` tags are unrelated to this deploy command and
must never be moved, deleted, or reused.

## Private workspace and secrets

Create a disposable directory outside the repository with `umask 077`. All
descriptor, secret, token, rendered-config, readback, and evidence files must be
regular, non-symlink files with mode `0600`.

The secret document contains exactly two independently generated 32-byte or
longer lowercase-hex values:

```json
{
  "HMAC_KEY": "<independent-random-lowercase-hex>",
  "CRON_HMAC_KEY": "<independent-random-lowercase-hex>"
}
```

These are one new deployment secret class with two domain-separated values.
Generate them directly into the private file; never print, pipe through a log,
place on argv, or copy them into the rendered Wrangler configuration. The
renderer rejects short, malformed, or equal keys.

Render and validate the private configuration from the clean checkout:

```bash
node scripts/render-worker-deployment.mjs \
  --base worker/wrangler.jsonc \
  --descriptor "$PRIVATE_ROOT/deployment.json" \
  --secrets "$PRIVATE_ROOT/secrets.json" \
  --output "$PRIVATE_ROOT/wrangler.json"

WRANGLER_WRITE_LOGS=0 ./node_modules/.bin/wrangler deploy \
  --dry-run \
  --config "$PRIVATE_ROOT/wrangler.json"
```

The dry run must show only Worker `github-actionrunner`, one `FLEET` Durable
Object binding, the sole `v1` SQLite migration, one `* * * * *` schedule, and
the nine rendered nonsecret variables. It must not show either HMAC value or any
lease, archive, selector, or safety-margin variable.

## Short-lived deploy token

Retrieve the standing parent token from the keychain reference in the private
credential inventory without printing it. With that parent token:

1. read the live Personal account and permission-group inventory;
2. create one account-scoped token containing only the current `Workers Scripts
Write` permission group;
3. set `not_before` to the current time and `expires_on` no more than two hours
   later; and
4. write the returned token identifier and value directly to a private `0600`
   file.

The child token is used only for dry-run-independent deployment and readback.
It is revoked with the parent token in the cleanup path whether deployment,
verification, or rollback succeeds or fails. Token creation without a captured
identifier is a stop because revocation cannot be proven.

## One-version deployment

Use Wrangler 4.125.0 from the repository lockfile. Pass the private secret file
to the deploy itself so code, configuration, and both secret bindings enter one
Worker version. Load the captured child-token value into Wrangler's standard
authentication environment from the private operator process without printing
it, then run:

```bash
WRANGLER_WRITE_LOGS=0 ./node_modules/.bin/wrangler deploy \
  --strict \
  --config "$PRIVATE_ROOT/wrangler.json" \
  --secrets-file "$PRIVATE_ROOT/secrets.json" \
  --tag "$MERGED_SHA" \
  --message "address-only deployment from $MERGED_SHA"
```

Do not run `wrangler secret put` or `wrangler secret bulk` before or after this
command; either would create a second version and invalidate the version-bound
Cron cutoff.

## Independent readback

Immediately after deploy, capture API/Wrangler JSON readbacks to private files.
Do not rely on the deploy command's success line. Require all of the following:

- production traffic is 100% on exactly one new version;
- the version tag is the exact merged SHA and its creation time is present;
- Worker name is exactly `github-actionrunner` and workers.dev is enabled;
- the entry module and deployed version metadata identify the checked source;
- the only Durable Object binding is `FLEET` to `FleetDurableObject`;
- the only migration is tag `v1` with `FleetDurableObject` as a new SQLite
  class;
- the only Cron schedule is `* * * * *`;
- the nine nonsecret variable names and values byte-match the rendered config;
- secret binding names are exactly `HMAC_KEY` and `CRON_HMAC_KEY`, with no
  values returned or recorded; and
- the workers.dev hostname is derived from the live account subdomain and its
  script-level enabled readback, not guessed from a prior deployment.

`wrangler deployments status --json`, `wrangler versions list --json`, and
`wrangler versions view <id> --json` provide the version-side evidence. Read the
script subdomain and schedules from the Cloudflare API because they are
deployment resources, not proof carried by version metadata. Any mismatch,
missing field, second production version, or unexpected binding is a failed
deployment.

## Natural-Cron proof

Cron is the only allowed receipt producer. Never invoke, replay, or synthesize a
scheduled event. Use the deployed version creation time from readback as the
strict receipt cutoff and choose an overall deadline no more than 30 minutes in
the future:

```bash
node scripts/ops/verify-worker-addressability.mjs \
  --descriptor "$PRIVATE_ROOT/deployment.json" \
  --secrets "$PRIVATE_ROOT/secrets.json" \
  --endpoint "$WORKERS_DEV_ENDPOINT" \
  --version-id "$VERSION_ID" \
  --version-created-at "$VERSION_CREATED_AT" \
  --deadline-at "$DEADLINE_AT" \
  --output "$PRIVATE_ROOT/addressability-evidence.json"
```

The verifier waits until the configured Cron tick budget plus one timestamp
window has elapsed after each natural UTC minute boundary. This lets the bounded
Cron invocation finish before status polling without adding another attempt in
that minute. It attempts each unresolved fleet at most once per boundary and
preserves partial evidence. Green requires exactly three successful fleets, no
pending fleets, the fixed inventory digest, receipt times strictly after the
deployed version creation time, positive persistence generations, and an inert
authority/read-only state for each Durable Object.

Cloudflare Cron configuration can take time to propagate. The bounded verifier
allows that delay, but missing, partial, stale, malformed, or timed-out signed
status evidence is **not approval**. Logs are corroborating diagnostics only and
cannot substitute for the signed persistent evidence file.

## Cleanup and rollback

After a green proof, revoke the short-lived token with the parent token and read
back that the token is inactive. Retain only the sanitized readback and
addressability evidence required by the deployment record; securely discard the
temporary config, secret values, and child-token file.

If deployment or proof fails, use the still-live short-lived token to delete
only the exact script `github-actionrunner`:

```bash
WRANGLER_WRITE_LOGS=0 ./node_modules/.bin/wrangler delete github-actionrunner \
  --config "$PRIVATE_ROOT/wrangler.json"
```

Then positively read back that `github-actionrunner` is absent, revoke the
short-lived token with the parent token, and read back token inactivity even if
the delete or absence check failed. Never delete another Worker, account
subdomain, Durable Object namespace, route, or account resource as part of this
rollback. A failed delete, failed absence readback, or failed token revocation is
an incident requiring operator attention, not a successful rollback.
