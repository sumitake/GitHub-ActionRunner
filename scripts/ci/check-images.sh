#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Manifest-driven image reproducibility gate. Sourcing defines functions only:
# it does not change caller variables, options, traps, umask or working directory.
# Standalone: scripts/ci/check-images.sh [MANIFEST_PATH], or IMAGES_MANIFEST.
# The runtime gate installs fixed private/progress adapters around this driver.
# shellcheck disable=SC2329

ci_images_private() { "$@"; }
ci_images_progress() { :; }

ci_images_validate_manifest() {
  ci_images_manifest="${1:-${IMAGES_MANIFEST:-images/manifest.json}}"

  if ! command -v jq >/dev/null 2>&1; then
    printf 'check-images: jq is required but was not found on PATH\n' >&2
    return 1
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    printf 'check-images: python3 is required but was not found on PATH\n' >&2
    return 1
  fi

  if [ ! -f "$ci_images_manifest" ]; then
    printf 'check-images: manifest not found: %s\n' "$ci_images_manifest" >&2
    return 1
  fi

  if ! jq empty "$ci_images_manifest" >/dev/null 2>&1; then
    printf 'check-images: %s is not valid JSON\n' "$ci_images_manifest" >&2
    return 1
  fi

  ci_images_version="$(jq -r 'if has("version") then (.version | tostring) else "<missing>" end' "$ci_images_manifest")" || return 1
  if [ "$ci_images_version" != "1" ]; then
    printf 'check-images: %s: unsupported or missing "version" (expected 1, got %s)\n' "$ci_images_manifest" "$ci_images_version" >&2
    return 1
  fi

  ci_images_images_type="$(jq -r '.images | type' "$ci_images_manifest")" || return 1
  if [ "$ci_images_images_type" != "array" ]; then
    printf 'check-images: %s: "images" must be an array (got %s)\n' "$ci_images_manifest" "$ci_images_images_type" >&2
    return 1
  fi

  ci_images_image_count="$(jq -r '.images | length' "$ci_images_manifest")" || return 1

  if [ "$ci_images_image_count" -eq 0 ]; then
    ci_images_empty=1
    printf 'check-images: %s registers no images; nothing to build\n' "$ci_images_manifest" || return 1
    return 0
  fi

  # Pass 1: validate every entry's shape, uniqueness, and path existence
  # before requiring or invoking docker at all, so a malformed manifest is
  # always caught by pure validation -- never masked by (or dependent on)
  # docker's availability.
  ci_images_names_seen=""
  ci_images_i=0
  while [ "$ci_images_i" -lt "$ci_images_image_count" ]; do
    ci_images_entry="$(jq -c ".images[$ci_images_i]" "$ci_images_manifest")" || return 1

    ci_images_entry_type="$(printf '%s' "$ci_images_entry" | jq -r 'type')" || return 1
    if [ "$ci_images_entry_type" != "object" ]; then
      printf 'check-images: %s: images[%d] must be an object\n' "$ci_images_manifest" "$ci_images_i" >&2
      return 1
    fi

    ci_images_name="$(printf '%s' "$ci_images_entry" | jq -r 'if has("name") then .name else "" end')" || return 1
    ci_images_context="$(printf '%s' "$ci_images_entry" | jq -r 'if has("context") then .context else "" end')" || return 1
    ci_images_dockerfile="$(printf '%s' "$ci_images_entry" | jq -r 'if has("dockerfile") then .dockerfile else "" end')" || return 1

    if [ -z "$ci_images_name" ] || [ -z "$ci_images_context" ] || [ -z "$ci_images_dockerfile" ]; then
      printf 'check-images: %s: images[%d] must set non-empty "name", "context", and "dockerfile"\n' \
        "$ci_images_manifest" "$ci_images_i" >&2
      return 1
    fi

    case " $ci_images_names_seen " in
    *" $ci_images_name "*)
      printf 'check-images: %s: duplicate image name %s\n' "$ci_images_manifest" "$ci_images_name" >&2
      return 1
      ;;
    esac
    ci_images_names_seen="$ci_images_names_seen $ci_images_name"

    if [ ! -d "$ci_images_context" ]; then
      printf 'check-images: %s: images[%d] (%s) context directory not found: %s\n' \
        "$ci_images_manifest" "$ci_images_i" "$ci_images_name" "$ci_images_context" >&2
      return 1
    fi

    if [ ! -f "$ci_images_dockerfile" ]; then
      printf 'check-images: %s: images[%d] (%s) dockerfile not found: %s\n' \
        "$ci_images_manifest" "$ci_images_i" "$ci_images_name" "$ci_images_dockerfile" >&2
      return 1
    fi

    case "$ci_images_dockerfile" in
    "$ci_images_context"/*) : ;;
    *)
      printf 'check-images: %s: images[%d] (%s) dockerfile %s is not inside context %s\n' \
        "$ci_images_manifest" "$ci_images_i" "$ci_images_name" "$ci_images_dockerfile" "$ci_images_context" >&2
      return 1
      ;;
    esac

    ci_images_i=$((ci_images_i + 1))
  done

  # Pass 2: every registered entry is well-formed. Only now do we require
  # docker and start building.
  if ! command -v docker >/dev/null 2>&1; then
    printf 'check-images: docker is required to build %d registered image(s) but was not found on PATH\n' \
      "$ci_images_image_count" >&2
    return 1
  fi

  ci_images_source_epoch="$(git show -s --format=%ct HEAD)" || return 1
  case "$ci_images_source_epoch" in
  "" | *[!0-9]* | 0)
    printf 'check-images: exact HEAD has no valid positive source epoch\n' >&2
    return 1
    ;;
  esac
}

ci_images_created_epoch() {
  python3 - "$1" <<'PY'
import datetime
import re
import sys

value = sys.argv[1]
if not re.fullmatch(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:[.]0+)?(?:Z|[+]00:00)",
    value,
):
    raise SystemExit(1)
normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
parsed = datetime.datetime.fromisoformat(normalized)
if parsed.tzinfo is None:
    raise SystemExit(1)
print(int(parsed.timestamp()))
PY
}

ci_images_prepare_entry() {
  ci_images_entry="$(jq -c ".images[$ci_images_i]" "$ci_images_manifest")" || return 1
  ci_images_name="$(printf '%s' "$ci_images_entry" | jq -r '.name')" || return 1
  ci_images_context="$(printf '%s' "$ci_images_entry" | jq -r '.context')" || return 1
  ci_images_dockerfile="$(printf '%s' "$ci_images_entry" | jq -r '.dockerfile')" || return 1

  # Compare the original JSON fields: shell command substitution can lose
  # trailing newlines and NULs. Only exact fixed triples gain image attribution;
  # unknown or changed triples retain the legacy phase-only codes 40..48.
  ci_images_failure_base="$(
    printf '%s' "$ci_images_entry" | jq -r '
      if [.name, .context, .dockerfile] == [
        "network-adapter", "images/network-adapter", "images/network-adapter/Dockerfile"
      ] then 50
      elif [.name, .context, .dockerfile] == [
        "network-broker-dialer", "images/network-broker-dialer", "images/network-broker-dialer/Dockerfile"
      ] then 60
      elif [.name, .context, .dockerfile] == [
        "network-broker-parser", "images/network-broker-parser", "images/network-broker-parser/Dockerfile"
      ] then 70
      elif [.name, .context, .dockerfile] == [
        "network-helper", "images/network-helper", "images/network-helper/Dockerfile"
      ] then 80
      elif [.name, .context, .dockerfile] == [
        "network-verifier", "images/network-verifier", "images/network-verifier/Dockerfile"
      ] then 90
      elif [.name, .context, .dockerfile] == [
        "runner", "images/runner", "images/runner/Dockerfile"
      ] then 100
      elif [.name, .context, .dockerfile] == [
        "synthetic-listener", "images/synthetic-listener", "images/synthetic-listener/Dockerfile"
      ] then 110
      else 40
      end
    '
  )" || return 1
  case "$ci_images_failure_base" in
  40 | 50 | 60 | 70 | 80 | 90 | 100 | 110) ;;
  *) return 1 ;;
  esac

  ci_images_tag_a="portable-ghar-check-images:${ci_images_name}-a"
  ci_images_tag_b="portable-ghar-check-images:${ci_images_name}-b"
}

ci_images_build_a() {
  SOURCE_DATE_EPOCH="$ci_images_source_epoch" docker buildx build \
    --platform linux/amd64 --no-cache --provenance=false --sbom=false \
    --build-arg "SOURCE_DATE_EPOCH=$ci_images_source_epoch" \
    --output "type=docker,name=$ci_images_tag_a,rewrite-timestamp=true" \
    -f "$ci_images_dockerfile" "$ci_images_context" >/dev/null || return "$((ci_images_failure_base + 0))"
}
ci_images_id_a() {
  ci_images_id_a="$(docker image inspect --format '{{.Id}}' "$ci_images_tag_a")" || return "$((ci_images_failure_base + 1))"
}
ci_images_created_a() {
  ci_images_created_a="$(docker image inspect --format '{{.Created}}' "$ci_images_tag_a")" || return "$((ci_images_failure_base + 2))"
}
ci_images_validate_a() {
  ci_images_created_epoch_a="$(ci_images_created_epoch "$ci_images_created_a")" || return "$((ci_images_failure_base + 3))"
  [ "$ci_images_created_epoch_a" = "$ci_images_source_epoch" ] || return "$((ci_images_failure_base + 3))"
}
ci_images_build_b() {
  SOURCE_DATE_EPOCH="$ci_images_source_epoch" docker buildx build \
    --platform linux/amd64 --no-cache --provenance=false --sbom=false \
    --build-arg "SOURCE_DATE_EPOCH=$ci_images_source_epoch" \
    --output "type=docker,name=$ci_images_tag_b,rewrite-timestamp=true" \
    -f "$ci_images_dockerfile" "$ci_images_context" >/dev/null || return "$((ci_images_failure_base + 4))"
}
ci_images_id_b() {
  ci_images_id_b="$(docker image inspect --format '{{.Id}}' "$ci_images_tag_b")" || return "$((ci_images_failure_base + 5))"
}
ci_images_created_b() {
  ci_images_created_b="$(docker image inspect --format '{{.Created}}' "$ci_images_tag_b")" || return "$((ci_images_failure_base + 6))"
}
ci_images_validate_b() {
  ci_images_created_epoch_b="$(ci_images_created_epoch "$ci_images_created_b")" || return "$((ci_images_failure_base + 7))"
  [ "$ci_images_created_epoch_b" = "$ci_images_source_epoch" ] || return "$((ci_images_failure_base + 7))"
}
ci_images_cleanup_a() { docker image rm -f "$ci_images_tag_a" >/dev/null 2>&1 || true; }
ci_images_cleanup_ab() { docker image rm -f "$ci_images_tag_a" "$ci_images_tag_b" >/dev/null 2>&1 || true; }
ci_images_bad_a() {
  printf 'check-images: %s first export has noncanonical creation time\n' "$ci_images_name" >&2
}
ci_images_bad_b() {
  printf 'check-images: %s second export has noncanonical creation time\n' "$ci_images_name" >&2
}
ci_images_compare_report() {
  if [ "$ci_images_id_a" != "$ci_images_id_b" ]; then
    printf 'check-images: %s is not reproducible: %s != %s\n' \
      "$ci_images_name" "$ci_images_id_a" "$ci_images_id_b" >&2 || return 1
    return "$((ci_images_failure_base + 8))"
  fi
  # A raw report write failure is generic, never an image-ID mismatch.
  printf 'check-images: %s builds reproducibly (%s)\n' \
    "$ci_images_name" "$ci_images_id_a" || return 1
}
ci_images_has_next() {
  # The count comes from jq. Keep even malformed-control test errors private,
  # and distinguish successful end-of-list from a private log open failure.
  ci_images_more=0
  if [ "$ci_images_i" -lt "$ci_images_image_count" ]; then
    ci_images_more=1
  fi
  return 0
}
ci_images_finish() {
  [ "$ci_images_empty" -eq 0 ] || return 0
  printf 'check-images: all %d registered image(s) build reproducibly\n' "$ci_images_image_count" || return 1
}

# This synchronous owner has the only diagnostic call sites. Every command,
# raw capture, and untrusted message is inside an explicitly private helper.
# Helpers use prefixed Bash dynamic scope, with no state files or phase CLI.
# Conditional callers suppress errexit: every consequential failure is checked.
# Mapped command failures originate inside helpers; a private adapter/open
# failure is generic and must not become an attributable image/phase exit.
ci_images_run() {
  local ci_images_manifest ci_images_version ci_images_images_type ci_images_image_count=0
  local ci_images_names_seen ci_images_i=0 ci_images_entry ci_images_entry_type
  local ci_images_name ci_images_context ci_images_dockerfile ci_images_source_epoch
  local ci_images_failure_base ci_images_tag_a ci_images_tag_b ci_images_id_a ci_images_id_b
  local ci_images_created_a ci_images_created_b ci_images_created_epoch_a ci_images_created_epoch_b
  local ci_images_status ci_images_empty=0 ci_images_more=0
  ci_images_progress 40 manifest-validation || true
  ci_images_private ci_images_validate_manifest "$@" || return 1
  ci_images_i=0
  while :; do
    ci_images_private ci_images_has_next || return 1
    [ "$ci_images_more" -eq 1 ] || break
    ci_images_progress 40 entry-prepare || true
    ci_images_private ci_images_prepare_entry || return 1
    ci_images_progress "$ci_images_failure_base" first-build || true
    ci_images_private ci_images_build_a || return "$?"
    ci_images_progress "$ci_images_failure_base" first-id-inspect || true
    ci_images_private ci_images_id_a || return "$?"
    ci_images_progress "$ci_images_failure_base" first-created-inspect || true
    ci_images_private ci_images_created_a || return "$?"
    ci_images_progress "$ci_images_failure_base" first-created-time || true
    if ci_images_private ci_images_validate_a; then
      :
    else
      ci_images_status=$?
      [ "$ci_images_status" -eq "$((ci_images_failure_base + 3))" ] || return 1
      ci_images_progress "$ci_images_failure_base" cleanup || true
      ci_images_private ci_images_cleanup_a || return 1
      ci_images_private ci_images_bad_a || return 1
      return "$ci_images_status"
    fi
    ci_images_progress "$ci_images_failure_base" second-build || true
    ci_images_private ci_images_build_b || return "$?"
    ci_images_progress "$ci_images_failure_base" second-id-inspect || true
    ci_images_private ci_images_id_b || return "$?"
    ci_images_progress "$ci_images_failure_base" second-created-inspect || true
    ci_images_private ci_images_created_b || return "$?"
    ci_images_progress "$ci_images_failure_base" second-created-time || true
    if ci_images_private ci_images_validate_b; then
      :
    else
      ci_images_status=$?
      [ "$ci_images_status" -eq "$((ci_images_failure_base + 7))" ] || return 1
      ci_images_progress "$ci_images_failure_base" cleanup || true
      ci_images_private ci_images_cleanup_ab || return 1
      ci_images_private ci_images_bad_b || return 1
      return "$ci_images_status"
    fi
    ci_images_progress "$ci_images_failure_base" cleanup || true
    ci_images_private ci_images_cleanup_ab || return 1
    ci_images_progress "$ci_images_failure_base" image-id-compare || true
    ci_images_private ci_images_compare_report || return "$?"
    ci_images_i=$((ci_images_i + 1))
  done
  ci_images_private ci_images_finish || return 1
}

ci_images_main() {
  set -euo pipefail
  ci_images_run "$@"
}
if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
  ci_images_main "$@"
fi
