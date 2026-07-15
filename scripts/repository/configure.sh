#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
#
# Repository-settings + protected-main bootstrap for a PUBLIC Portable GHAR
# mirror. Codifies the repository's foundation posture and its `main` branch
# ruleset as reproducible, read-back-verified `gh api` calls.
#
# This tool is NOT executed during the source phase; it is tested (via a stub
# `gh`) and documented only. See docs/operations/repository-bootstrap.md for
# the two-stage bootstrap order this script implements.
#
# Usage:
#   configure.sh --check REPOSITORY
#       Read-only. Reports the current foundation settings and ruleset status.
#       Mutates nothing.
#
#   configure.sh --apply-foundation REPOSITORY (--yes | interactive prompt)
#       Applies the foundation settings (workflow-token, Actions allowlist,
#       merge policy, security features). Requires confirmation + admin.
#
#   configure.sh --apply-ruleset REPOSITORY PR_NUMBER --maintainer-mode MODE \
#                (--yes | interactive prompt)
#       Proves the seven CI contexts SUCCEEDED on the PR's exact head SHA, then
#       creates the ACTIVE `main` ruleset. Requires confirmation + admin.
#       MODE is `sole` (sole-maintainer: zero approvals, code-owner enforcement
#       off) or `independent` (one approval, code-owner enforcement on).
#
# Fail-closed contract: a missing repository, a non-public repository, an
# absent PR number or head SHA, any of the seven contexts missing/unsuccessful
# on that head SHA, an unresolved maintainer/CODEOWNERS mode, a malformed API
# response, or any apply without confirmation is a hard, non-zero-exit failure.
# Every mutating call is read back before the next step proceeds.

set -eu

API_VERSION="2026-03-10"

# The seven stable CI contexts (Tasks 8+9). ALL seven must have succeeded on
# the bootstrap PR's head SHA before a ruleset is created. Only the SIX below
# become required status checks on `main`: dependency-review is observed on the
# PR but is deliberately NOT required on main.
CONTEXTS_ALL="go worker shell repository-metadata container sanitization dependency-review"
CONTEXTS_REQUIRED_MAIN="go worker shell repository-metadata container sanitization"

usage() {
  cat <<'USAGE'
usage:
  configure.sh --check REPOSITORY
  configure.sh --apply-foundation REPOSITORY [--yes]
  configure.sh --apply-ruleset REPOSITORY PR_NUMBER --maintainer-mode <sole|independent> [--yes]
USAGE
}

die() {
  printf 'configure: %s\n' "$1" >&2
  exit 1
}

note() {
  printf 'configure: %s\n' "$1"
}

# Thin wrapper so the pinned REST API version header is stamped on EVERY call.
api() {
  gh api -H "X-GitHub-Api-Version: $API_VERSION" "$@"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

MODE=""
REPOSITORY=""
PR_NUMBER=""
ASSUME_YES=0
MAINTAINER_MODE=""
argn=0

while [ $# -gt 0 ]; do
  case "$1" in
  --check) MODE="check" ;;
  --apply-foundation) MODE="foundation" ;;
  --apply-ruleset) MODE="ruleset" ;;
  --yes) ASSUME_YES=1 ;;
  --maintainer-mode)
    [ $# -ge 2 ] || die "--maintainer-mode requires a value (sole|independent)"
    MAINTAINER_MODE="$2"
    shift
    ;;
  --maintainer-mode=*) MAINTAINER_MODE="${1#*=}" ;;
  -h | --help)
    usage
    exit 0
    ;;
  --*) die "unknown option: $1" ;;
  *)
    argn=$((argn + 1))
    if [ "$argn" -eq 1 ]; then
      REPOSITORY="$1"
    elif [ "$argn" -eq 2 ]; then
      PR_NUMBER="$1"
    else
      die "unexpected extra argument: $1"
    fi
    ;;
  esac
  shift
done

[ -n "$MODE" ] || {
  usage >&2
  die "no mode selected; use --check, --apply-foundation, or --apply-ruleset"
}
[ -n "$REPOSITORY" ] || die "missing required REPOSITORY argument (owner/repository)"
command -v gh >/dev/null 2>&1 || die "gh (GitHub CLI) is required but was not found on PATH"

# ---------------------------------------------------------------------------
# Shared guards
# ---------------------------------------------------------------------------

confirm_or_die() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  if [ -t 0 ]; then
    printf 'configure: this will modify %s. Continue? [y/N] ' "$REPOSITORY" >&2
    read -r reply || reply=""
    case "$reply" in
    y | Y | yes | YES | Yes) return 0 ;;
    esac
  fi
  die "confirmation required: re-run with --yes (or answer yes at the interactive prompt)"
}

ensure_public() {
  visibility=$(api "repos/$REPOSITORY" --jq '.visibility' 2>/dev/null) ||
    die "could not query repository $REPOSITORY (API error) (fail closed)"
  [ -n "$visibility" ] ||
    die "could not determine repository visibility (malformed API response) (fail closed)"
  [ "$visibility" = "public" ] ||
    die "repository $REPOSITORY is not public (visibility: $visibility); refusing to proceed (fail closed)"
}

ensure_admin() {
  admin=$(api "repos/$REPOSITORY" --jq '.permissions.admin' 2>/dev/null) ||
    die "could not query repository permissions (API error) (fail closed)"
  [ "$admin" = "true" ] ||
    die "admin access to $REPOSITORY is required to apply changes (got: ${admin:-none}) (fail closed)"
}

# read_back ENDPOINT JQ EXPECTED DESCRIPTION -- fail closed on mismatch.
read_back() {
  rb_actual=$(api "$1" --jq "$2" 2>/dev/null) ||
    die "read-back failed: could not query $4 (fail closed)"
  [ "$rb_actual" = "$3" ] ||
    die "read-back mismatch for $4: expected '$3', got '${rb_actual:-none}' (fail closed)"
}

# put_json ENDPOINT BODY -- mutating PUT with a JSON body on stdin.
put_json() {
  printf '%s' "$2" | api --method PUT "$1" --input - >/dev/null 2>&1 ||
    die "mutation failed: PUT $1 (fail closed)"
}

# patch_json ENDPOINT BODY -- mutating PATCH with a JSON body on stdin.
patch_json() {
  printf '%s' "$2" | api --method PATCH "$1" --input - >/dev/null 2>&1 ||
    die "mutation failed: PATCH $1 (fail closed)"
}

# put_empty ENDPOINT -- mutating PUT with no body (feature-enable endpoints).
put_empty() {
  api --method PUT "$1" >/dev/null 2>&1 ||
    die "mutation failed: PUT $1 (fail closed)"
}

# ---------------------------------------------------------------------------
# --check
# ---------------------------------------------------------------------------

cmd_check() {
  ensure_public
  note "repository: $REPOSITORY (visibility: $visibility)"

  wf=$(api "repos/$REPOSITORY/actions/permissions/workflow" \
    --jq '.default_workflow_permissions' 2>/dev/null || echo "?")
  approve=$(api "repos/$REPOSITORY/actions/permissions/workflow" \
    --jq '.can_approve_pull_request_reviews' 2>/dev/null || echo "?")
  note "default workflow token permissions: $wf"
  note "Actions can approve pull requests: $approve"

  allowed=$(api "repos/$REPOSITORY/actions/permissions" \
    --jq '.allowed_actions' 2>/dev/null || echo "?")
  note "allowed actions policy: $allowed"

  if api "repos/$REPOSITORY/vulnerability-alerts" >/dev/null 2>&1; then
    note "vulnerability alerts: enabled"
  else
    note "vulnerability alerts: disabled"
  fi

  note "check complete (read-only; no changes were made)"
}

# ---------------------------------------------------------------------------
# --apply-foundation
# ---------------------------------------------------------------------------

cmd_foundation() {
  confirm_or_die
  ensure_public
  ensure_admin

  # 1. Actions policy: restrict to a selected allowlist.
  put_json "repos/$REPOSITORY/actions/permissions" \
    '{"enabled":true,"allowed_actions":"selected"}'
  read_back "repos/$REPOSITORY/actions/permissions" '.allowed_actions' \
    "selected" "actions allowed-actions policy"

  # 2. Selected-actions allowlist: GitHub-owned + Gitleaks + Trivy + Anchore
  #    SBOM + Bats only.
  put_json "repos/$REPOSITORY/actions/permissions/selected-actions" \
    '{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["gitleaks/gitleaks-action@*","aquasecurity/trivy-action@*","anchore/sbom-action@*","bats-core/bats-action@*"]}'
  read_back "repos/$REPOSITORY/actions/permissions/selected-actions" \
    '.github_owned_allowed' "true" "selected-actions github_owned_allowed"
  read_back "repos/$REPOSITORY/actions/permissions/selected-actions" \
    '.patterns_allowed | length' "4" "selected-actions allowlist size"
  note "Actions restricted to a GitHub-owned + four-vendor allowlist"

  # 3. Default workflow token READ-ONLY; Actions cannot approve PRs.
  put_json "repos/$REPOSITORY/actions/permissions/workflow" \
    '{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}'
  read_back "repos/$REPOSITORY/actions/permissions/workflow" \
    '.default_workflow_permissions' "read" "default workflow token permissions"
  read_back "repos/$REPOSITORY/actions/permissions/workflow" \
    '.can_approve_pull_request_reviews' "false" "Actions can-approve-PRs"
  note "workflow token set read-only; Actions cannot approve pull requests"

  # 4. Merge policy: delete branch on merge; no merge commits; squash + rebase.
  patch_json "repos/$REPOSITORY" \
    '{"delete_branch_on_merge":true,"allow_merge_commit":false,"allow_squash_merge":true,"allow_rebase_merge":true}'
  read_back "repos/$REPOSITORY" '.delete_branch_on_merge' "true" "delete branch on merge"
  read_back "repos/$REPOSITORY" '.allow_merge_commit' "false" "merge-commit policy"
  read_back "repos/$REPOSITORY" '.allow_squash_merge' "true" "squash-merge policy"
  read_back "repos/$REPOSITORY" '.allow_rebase_merge' "true" "rebase-merge policy"
  note "merge policy: squash + rebase only, delete branch on merge"

  # 5. Dependency security: vulnerability alerts + automated security updates.
  put_empty "repos/$REPOSITORY/vulnerability-alerts"
  api "repos/$REPOSITORY/vulnerability-alerts" >/dev/null 2>&1 ||
    die "read-back failed: vulnerability alerts are not enabled (fail closed)"
  put_empty "repos/$REPOSITORY/automated-security-fixes"
  read_back "repos/$REPOSITORY/automated-security-fixes" '.enabled' "true" \
    "automated security updates"
  note "vulnerability alerts + automated security updates enabled"

  # 6. Private vulnerability reporting.
  put_empty "repos/$REPOSITORY/private-vulnerability-reporting"
  read_back "repos/$REPOSITORY/private-vulnerability-reporting" '.enabled' "true" \
    "private vulnerability reporting"
  note "private vulnerability reporting enabled"

  # 7. Secret scanning + push protection + validity checks + non-provider
  #    patterns (where supported).
  patch_json "repos/$REPOSITORY" \
    '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"},"secret_scanning_validity_checks":{"status":"enabled"},"secret_scanning_non_provider_patterns":{"status":"enabled"}}}'
  read_back "repos/$REPOSITORY" '.security_and_analysis.secret_scanning.status' \
    "enabled" "secret scanning"
  read_back "repos/$REPOSITORY" \
    '.security_and_analysis.secret_scanning_push_protection.status' \
    "enabled" "secret scanning push protection"
  read_back "repos/$REPOSITORY" \
    '.security_and_analysis.secret_scanning_validity_checks.status' \
    "enabled" "secret scanning validity checks"
  read_back "repos/$REPOSITORY" \
    '.security_and_analysis.secret_scanning_non_provider_patterns.status' \
    "enabled" "secret scanning non-provider patterns"
  note "secret scanning, push protection, validity checks, non-provider patterns enabled"

  note "foundation settings applied and read back on $REPOSITORY"
}

# ---------------------------------------------------------------------------
# --apply-ruleset
# ---------------------------------------------------------------------------

resolve_maintainer_mode() {
  case "$MAINTAINER_MODE" in
  sole)
    REVIEW_COUNT=0
    REQUIRE_CODEOWNER="false"
    ;;
  independent)
    REVIEW_COUNT=1
    REQUIRE_CODEOWNER="true"
    ;;
  "")
    die "unresolved CODEOWNERS mode: pass --maintainer-mode sole (sole-maintainer: zero approvals, code-owner enforcement off) or independent (one approval, code-owner enforcement on) (fail closed)"
    ;;
  *)
    die "invalid --maintainer-mode '$MAINTAINER_MODE'; expected sole or independent (fail closed)"
    ;;
  esac
}

prove_contexts_on_head() {
  [ -n "$PR_NUMBER" ] || die "missing required PR_NUMBER argument (fail closed)"

  sha=$(api "repos/$REPOSITORY/pulls/$PR_NUMBER" --jq '.head.sha' 2>/dev/null) ||
    die "could not query PR #$PR_NUMBER (API error) (fail closed)"
  [ -n "$sha" ] ||
    die "could not determine the head SHA of PR #$PR_NUMBER (absent/malformed) (fail closed)"
  note "PR #$PR_NUMBER head SHA: $sha"

  ctx_map=$(api "repos/$REPOSITORY/commits/$sha/check-runs" \
    --jq '.check_runs[] | .name + " " + .conclusion' 2>/dev/null) ||
    die "could not query check runs for head SHA $sha (fail closed)"

  for ctx in $CONTEXTS_ALL; do
    line=$(printf '%s\n' "$ctx_map" | grep -E "^${ctx} " || true)
    [ -n "$line" ] ||
      die "required context '$ctx' is missing on head SHA $sha (fail closed)"
    concl=${line#"${ctx} "}
    [ "$concl" = "success" ] ||
      die "required context '$ctx' did not succeed on head SHA $sha (conclusion: ${concl:-none}) (fail closed)"
  done
  note "all seven CI contexts succeeded on head SHA $sha"
}

build_required_status_checks() {
  # Emit {"context":"NAME"},... for the six required-on-main contexts.
  rsc=""
  for ctx in $CONTEXTS_REQUIRED_MAIN; do
    if [ -z "$rsc" ]; then
      rsc="{\"context\":\"$ctx\"}"
    else
      rsc="$rsc,{\"context\":\"$ctx\"}"
    fi
  done
  printf '%s' "$rsc"
}

cmd_ruleset() {
  confirm_or_die
  resolve_maintainer_mode
  ensure_public
  ensure_admin
  prove_contexts_on_head

  required_checks=$(build_required_status_checks)
  ruleset_body=$(
    printf '%s' "{\"name\":\"main\",\"target\":\"branch\",\"enforcement\":\"active\",\"conditions\":{\"ref_name\":{\"include\":[\"refs/heads/main\"],\"exclude\":[]}},\"bypass_actors\":[],\"rules\":[{\"type\":\"pull_request\",\"parameters\":{\"required_approving_review_count\":$REVIEW_COUNT,\"require_code_owner_review\":$REQUIRE_CODEOWNER,\"dismiss_stale_reviews_on_push\":true,\"require_last_push_approval\":false,\"required_review_thread_resolution\":true}},{\"type\":\"required_linear_history\"},{\"type\":\"required_signatures\"},{\"type\":\"deletion\"},{\"type\":\"non_fast_forward\"},{\"type\":\"required_status_checks\",\"parameters\":{\"strict_required_status_checks_policy\":true,\"required_status_checks\":[$required_checks]}}]}"
  )

  ruleset_id=$(printf '%s' "$ruleset_body" |
    api --method POST "repos/$REPOSITORY/rulesets" --jq '.id' --input - 2>/dev/null) ||
    die "ruleset creation failed: POST repos/$REPOSITORY/rulesets (fail closed)"
  [ -n "$ruleset_id" ] ||
    die "ruleset creation returned no id (malformed API response) (fail closed)"

  read_back "repos/$REPOSITORY/rulesets/$ruleset_id" '.enforcement' "active" \
    "ruleset enforcement"
  note "created ACTIVE main ruleset id=$ruleset_id on $REPOSITORY (maintainer mode: $MAINTAINER_MODE)"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

case "$MODE" in
check) cmd_check ;;
foundation) cmd_foundation ;;
ruleset) cmd_ruleset ;;
*) die "internal error: unhandled mode '$MODE'" ;;
esac
