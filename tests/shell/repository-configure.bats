#!/usr/bin/env bats
# SPDX-License-Identifier: MPL-2.0
#
# TDD suite for scripts/repository/configure.sh -- the repository-settings +
# protected-main ruleset bootstrap tool. Every `gh` invocation is served by a
# STUB `gh` placed first on PATH that returns canned JSON and records each call
# to $GH_CALLS; NO real network or GitHub API is ever touched. The suite pins:
#   - each fail-closed rejection (missing repo, non-public repo, absent PR /
#     head SHA, any of the seven contexts missing/unsuccessful, unresolved
#     CODEOWNERS mode, malformed API response, apply without confirmation,
#     apply without admin);
#   - that --check mutates nothing (records zero --method calls);
#   - that the seven-context precheck requires ALL seven (incl. dependency-
#     review) on the head SHA, while the created ruleset requires only the SIX
#     (dependency-review is NOT required on main);
#   - that mutating calls carry the pinned REST API version header and the
#     exact endpoints/payloads the runbook documents.

setup() {
  REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  SCRIPT="$REPO_ROOT/scripts/repository/configure.sh"
  TMP_DIR="$(mktemp -d)"
  GH_CALLS="$TMP_DIR/gh-calls.log"
  : >"$GH_CALLS"
  export GH_CALLS

  # ---- STUB gh (test double) -------------------------------------------
  # Records every call, then emits the canned scalar/body the script reads
  # back. Behaviour is tunable per-test through STUB_* environment vars.
  mkdir -p "$TMP_DIR/bin"
  cat >"$TMP_DIR/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -u
calls_file="${GH_CALLS:?}"
raw_args="$*"
method="GET"
endpoint=""
jq_expr=""
has_input=0
while [ $# -gt 0 ]; do
  case "$1" in
  api) ;;
  -H)
    shift
    ;;
  --method)
    method="$2"
    shift
    ;;
  --jq)
    jq_expr="$2"
    shift
    ;;
  --input)
    has_input=1
    shift
    ;;
  --silent) ;;
  -f | -F)
    shift
    ;;
  -*) ;;
  *) [ -z "$endpoint" ] && endpoint="$1" ;;
  esac
  shift
done
body=""
[ "$has_input" -eq 1 ] && body="$(cat)"
printf '%s %s jq=%s input=%s raw=[%s]\n' "$method" "$endpoint" "$jq_expr" "$body" "$raw_args" >>"$calls_file"

default_contexts="go success
worker success
shell success
repository-metadata success
container success
sanitization success
dependency-review success"

case "$method $endpoint" in
"GET "*"/actions/permissions/workflow")
  case "$jq_expr" in
  ".default_workflow_permissions") printf 'read\n' ;;
  ".can_approve_pull_request_reviews") printf 'false\n' ;;
  *) printf '{}\n' ;;
  esac
  ;;
"GET "*"/actions/permissions/selected-actions")
  case "$jq_expr" in
  ".github_owned_allowed") printf 'true\n' ;;
  ".verified_allowed") printf 'false\n' ;;
  ".patterns_allowed | length") printf '4\n' ;;
  *) printf '{}\n' ;;
  esac
  ;;
"GET "*"/actions/permissions")
  case "$jq_expr" in
  ".allowed_actions") printf 'selected\n' ;;
  ".enabled") printf 'true\n' ;;
  *) printf '{}\n' ;;
  esac
  ;;
*"/vulnerability-alerts")
  exit 0
  ;;
*"/automated-security-fixes")
  case "$jq_expr" in
  ".enabled") printf 'true\n' ;;
  *) exit 0 ;;
  esac
  ;;
*"/private-vulnerability-reporting")
  case "$jq_expr" in
  ".enabled") printf 'true\n' ;;
  *) exit 0 ;;
  esac
  ;;
"GET "*"/pulls/"*)
  printf '%s\n' "${STUB_HEAD_SHA-1111111111111111111111111111111111111111}"
  ;;
"GET "*"/commits/"*"/check-runs")
  printf '%s\n' "${STUB_CONTEXTS-$default_contexts}"
  ;;
"POST "*"/rulesets")
  printf '%s\n' "${STUB_RULESET_ID-4242}"
  ;;
"GET "*"/rulesets/"*)
  case "$jq_expr" in
  ".enforcement") printf 'active\n' ;;
  ".id") printf '%s\n' "${STUB_RULESET_ID-4242}" ;;
  *) printf '{}\n' ;;
  esac
  ;;
"GET "*"/rulesets")
  printf '\n'
  ;;
"GET repos/"*)
  case "$jq_expr" in
  ".visibility") printf '%s\n' "${STUB_VISIBILITY-public}" ;;
  ".permissions.admin") printf '%s\n' "${STUB_ADMIN-true}" ;;
  ".delete_branch_on_merge") printf 'true\n' ;;
  ".allow_merge_commit") printf 'false\n' ;;
  ".allow_squash_merge") printf 'true\n' ;;
  ".allow_rebase_merge") printf 'true\n' ;;
  ".security_and_analysis"*) printf 'enabled\n' ;;
  *) printf '{}\n' ;;
  esac
  ;;
*)
  # Any mutating PATCH/PUT with no read-back: record-and-succeed.
  exit 0
  ;;
esac
exit 0
STUB
  chmod +x "$TMP_DIR/bin/gh"
  PATH="$TMP_DIR/bin:$PATH"
  export PATH
}

teardown() {
  rm -rf "$TMP_DIR"
}

# ---------------------------------------------------------------------------
# Basic existence / shape
# ---------------------------------------------------------------------------

@test "configure.sh exists and is executable" {
  [ -f "$SCRIPT" ]
  [ -x "$SCRIPT" ]
}

@test "no mode selected fails closed" {
  run bash "$SCRIPT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"mode"* ]]
}

@test "missing repository argument fails closed" {
  run bash "$SCRIPT" --check
  [ "$status" -ne 0 ]
  [[ "$output" == *"REPOSITORY"* || "$output" == *"repository"* ]]
}

# ---------------------------------------------------------------------------
# Public-repo + read-only guarantees
# ---------------------------------------------------------------------------

@test "non-public repository fails closed" {
  STUB_VISIBILITY=private run bash "$SCRIPT" --check owner/repository
  [ "$status" -ne 0 ]
  [[ "$output" == *"not public"* ]]
}

@test "malformed API response (empty visibility) fails closed" {
  STUB_VISIBILITY="" run bash "$SCRIPT" --check owner/repository
  [ "$status" -ne 0 ]
  [[ "$output" == *"visibility"* ]]
}

@test "--check succeeds and mutates nothing (records zero --method calls)" {
  run bash "$SCRIPT" --check owner/repository
  [ "$status" -eq 0 ]
  run grep -c -- "--method" "$GH_CALLS"
  [ "$output" -eq 0 ]
}

@test "--check emits the pinned REST API version header on its read calls" {
  run bash "$SCRIPT" --check owner/repository
  [ "$status" -eq 0 ]
  grep -q "X-GitHub-Api-Version: 2026-03-10" "$GH_CALLS"
}

# ---------------------------------------------------------------------------
# --apply-foundation
# ---------------------------------------------------------------------------

@test "--apply-foundation without confirmation is refused" {
  run bash "$SCRIPT" --apply-foundation owner/repository
  [ "$status" -ne 0 ]
  [[ "$output" == *"confirm"* ]]
  # refused before any mutating call
  run grep -c -- "--method" "$GH_CALLS"
  [ "$output" -eq 0 ]
}

@test "--apply-foundation on EOF stdin without --yes is refused" {
  run bash -c 'exec <&-; exec bash "$1" --apply-foundation owner/repository' bash "$SCRIPT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"confirm"* ]]
  run grep -c -- "--method" "$GH_CALLS"
  [ "$output" -eq 0 ]
}

@test "--apply-foundation without admin access fails closed" {
  STUB_ADMIN=false run bash "$SCRIPT" --apply-foundation owner/repository --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"admin"* ]]
}

@test "--apply-foundation applies the documented settings and reads each back" {
  run bash "$SCRIPT" --apply-foundation owner/repository --yes
  [ "$status" -eq 0 ]
  # default workflow token read-only + Actions cannot approve PRs
  grep -q 'PUT repos/owner/repository/actions/permissions/workflow' "$GH_CALLS"
  grep -q '"default_workflow_permissions":"read"' "$GH_CALLS"
  grep -q '"can_approve_pull_request_reviews":false' "$GH_CALLS"
  # selected-actions allowlist: GitHub-owned + the four third-party actions
  grep -q 'PUT repos/owner/repository/actions/permissions/selected-actions' "$GH_CALLS"
  grep -q '"github_owned_allowed":true' "$GH_CALLS"
  grep -q 'gitleaks/gitleaks-action@\*' "$GH_CALLS"
  grep -q 'aquasecurity/trivy-action@\*' "$GH_CALLS"
  grep -q 'anchore/sbom-action@\*' "$GH_CALLS"
  grep -q 'bats-core/bats-action@\*' "$GH_CALLS"
  # merge policy: delete branch on merge, no merge commits, squash + rebase
  grep -q '"delete_branch_on_merge":true' "$GH_CALLS"
  grep -q '"allow_merge_commit":false' "$GH_CALLS"
  grep -q '"allow_squash_merge":true' "$GH_CALLS"
  grep -q '"allow_rebase_merge":true' "$GH_CALLS"
  # security features
  grep -q 'PUT repos/owner/repository/vulnerability-alerts' "$GH_CALLS"
  grep -q 'PUT repos/owner/repository/automated-security-fixes' "$GH_CALLS"
  grep -q 'PUT repos/owner/repository/private-vulnerability-reporting' "$GH_CALLS"
  grep -q '"secret_scanning":{"status":"enabled"}' "$GH_CALLS"
  grep -q '"secret_scanning_push_protection":{"status":"enabled"}' "$GH_CALLS"
  grep -q '"secret_scanning_validity_checks":{"status":"enabled"}' "$GH_CALLS"
  grep -q '"secret_scanning_non_provider_patterns":{"status":"enabled"}' "$GH_CALLS"
}

@test "--apply-foundation stamps the pinned REST API version header on mutating calls" {
  run bash "$SCRIPT" --apply-foundation owner/repository --yes
  [ "$status" -eq 0 ]
  # every recorded gh call includes the version header
  total="$(wc -l <"$GH_CALLS")"
  hdr="$(grep -c 'X-GitHub-Api-Version: 2026-03-10' "$GH_CALLS")"
  [ "$total" -gt 0 ]
  [ "$hdr" -eq "$total" ]
}

# ---------------------------------------------------------------------------
# --apply-ruleset
# ---------------------------------------------------------------------------

@test "--apply-ruleset without a PR number fails closed" {
  run bash "$SCRIPT" --apply-ruleset owner/repository --yes --maintainer-mode sole
  [ "$status" -ne 0 ]
  [[ "$output" == *"PR"* ]]
}

@test "--apply-ruleset without confirmation is refused" {
  run bash "$SCRIPT" --apply-ruleset owner/repository 7 --maintainer-mode sole
  [ "$status" -ne 0 ]
  [[ "$output" == *"confirm"* ]]
}

@test "--apply-ruleset without admin access fails closed" {
  STUB_ADMIN=false run bash "$SCRIPT" --apply-ruleset owner/repository 7 --yes --maintainer-mode sole
  [ "$status" -ne 0 ]
  [[ "$output" == *"admin"* ]]
}

@test "--apply-ruleset fails closed when the PR head SHA is absent" {
  STUB_HEAD_SHA="" run bash "$SCRIPT" --apply-ruleset owner/repository 7 --yes --maintainer-mode sole
  [ "$status" -ne 0 ]
  [[ "$output" == *"SHA"* ]]
  # no ruleset was created
  run grep -c 'POST repos/owner/repository/rulesets' "$GH_CALLS"
  [ "$output" -eq 0 ]
}

@test "--apply-ruleset fails closed when a required context is missing on the head SHA" {
  STUB_CONTEXTS="go success
worker success
shell success
repository-metadata success
sanitization success
dependency-review success" run bash "$SCRIPT" --apply-ruleset owner/repository 7 --yes --maintainer-mode sole
  [ "$status" -ne 0 ]
  [[ "$output" == *"container"* ]]
  run grep -c 'POST repos/owner/repository/rulesets' "$GH_CALLS"
  [ "$output" -eq 0 ]
}

@test "--apply-ruleset fails closed when a required context did not succeed" {
  STUB_CONTEXTS="go success
worker failure
shell success
repository-metadata success
container success
sanitization success
dependency-review success" run bash "$SCRIPT" --apply-ruleset owner/repository 7 --yes --maintainer-mode sole
  [ "$status" -ne 0 ]
  [[ "$output" == *"worker"* ]]
  run grep -c 'POST repos/owner/repository/rulesets' "$GH_CALLS"
  [ "$output" -eq 0 ]
}

@test "--apply-ruleset precheck requires dependency-review too (all seven)" {
  STUB_CONTEXTS="go success
worker success
shell success
repository-metadata success
container success
sanitization success" run bash "$SCRIPT" --apply-ruleset owner/repository 7 --yes --maintainer-mode sole
  [ "$status" -ne 0 ]
  [[ "$output" == *"dependency-review"* ]]
}

@test "--apply-ruleset fails closed on an unresolved CODEOWNERS mode" {
  run bash "$SCRIPT" --apply-ruleset owner/repository 7 --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"maintainer"* || "$output" == *"CODEOWNERS"* ]]
  run grep -c 'POST repos/owner/repository/rulesets' "$GH_CALLS"
  [ "$output" -eq 0 ]
}

@test "--apply-ruleset creates an ACTIVE main ruleset with the six required contexts and records its id" {
  run bash "$SCRIPT" --apply-ruleset owner/repository 7 --yes --maintainer-mode sole
  [ "$status" -eq 0 ]
  # proved the contexts on the exact head SHA first
  grep -q 'GET repos/owner/repository/pulls/7' "$GH_CALLS"
  grep -q 'GET repos/owner/repository/commits/1111111111111111111111111111111111111111/check-runs' "$GH_CALLS"
  # created an ACTIVE branch ruleset targeting main
  grep -q 'POST repos/owner/repository/rulesets' "$GH_CALLS"
  grep -q '"enforcement":"active"' "$GH_CALLS"
  grep -q '"include":\["refs/heads/main"\]' "$GH_CALLS"
  # rules present
  grep -q '"type":"pull_request"' "$GH_CALLS"
  grep -q '"required_review_thread_resolution":true' "$GH_CALLS"
  grep -q '"type":"required_linear_history"' "$GH_CALLS"
  grep -q '"type":"required_signatures"' "$GH_CALLS"
  grep -q '"type":"deletion"' "$GH_CALLS"
  grep -q '"type":"non_fast_forward"' "$GH_CALLS"
  grep -q '"strict_required_status_checks_policy":true' "$GH_CALLS"
  # the SIX required contexts on main
  grep -q '"context":"go"' "$GH_CALLS"
  grep -q '"context":"worker"' "$GH_CALLS"
  grep -q '"context":"shell"' "$GH_CALLS"
  grep -q '"context":"repository-metadata"' "$GH_CALLS"
  grep -q '"context":"container"' "$GH_CALLS"
  grep -q '"context":"sanitization"' "$GH_CALLS"
  # dependency-review is NOT required on main (never in the ruleset payload)
  run grep -c 'dependency-review' "$GH_CALLS"
  [ "$output" -eq 0 ]
  # sole-maintainer mode: zero approvals + code-owner enforcement off, no bypass
  run bash -c "grep -q '\"required_approving_review_count\":0' '$GH_CALLS'"
  [ "$status" -eq 0 ]
  run bash -c "grep -q '\"require_code_owner_review\":false' '$GH_CALLS'"
  [ "$status" -eq 0 ]
  run bash -c "grep -q '\"bypass_actors\":\[\]' '$GH_CALLS'"
  [ "$status" -eq 0 ]
  # read back the ruleset id
  run bash -c "grep -q 'GET repos/owner/repository/rulesets/4242' '$GH_CALLS'"
  [ "$status" -eq 0 ]
}

@test "--apply-ruleset reports the created ruleset id to the operator" {
  run bash "$SCRIPT" --apply-ruleset owner/repository 7 --yes --maintainer-mode sole
  [ "$status" -eq 0 ]
  [[ "$output" == *"4242"* ]]
}
