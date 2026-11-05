#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Manifest-driven container image build/reproducibility gate for CI.
#
# Validates images/manifest.json (or an override manifest passed as $1 or
# via IMAGES_MANIFEST) against a small closed schema, then -- for every
# registered image -- builds it twice with --no-cache and requires the two
# resulting image IDs to be identical (a basic reproducible-build gate).
# An explicitly empty override manifest still passes without invoking Docker;
# the repository manifest registers the prepared Task-5 images.
#
# Usage: scripts/ci/check-images.sh [MANIFEST_PATH]
#        IMAGES_MANIFEST=path scripts/ci/check-images.sh
#
# Fails closed: missing/invalid JSON, wrong "version", a non-array
# "images", a malformed image entry, a duplicate name, or a missing/
# outside-context Dockerfile is a hard failure before any docker
# invocation is attempted.

set -euo pipefail

manifest="${1:-${IMAGES_MANIFEST:-images/manifest.json}}"

if ! command -v jq >/dev/null 2>&1; then
  printf 'check-images: jq is required but was not found on PATH\n' >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf 'check-images: python3 is required but was not found on PATH\n' >&2
  exit 1
fi

if [ ! -f "$manifest" ]; then
  printf 'check-images: manifest not found: %s\n' "$manifest" >&2
  exit 1
fi

if ! jq empty "$manifest" >/dev/null 2>&1; then
  printf 'check-images: %s is not valid JSON\n' "$manifest" >&2
  exit 1
fi

version="$(jq -r 'if has("version") then (.version | tostring) else "<missing>" end' "$manifest")" || exit 1
if [ "$version" != "1" ]; then
  printf 'check-images: %s: unsupported or missing "version" (expected 1, got %s)\n' "$manifest" "$version" >&2
  exit 1
fi

images_type="$(jq -r '.images | type' "$manifest")" || exit 1
if [ "$images_type" != "array" ]; then
  printf 'check-images: %s: "images" must be an array (got %s)\n' "$manifest" "$images_type" >&2
  exit 1
fi

image_count="$(jq -r '.images | length' "$manifest")" || exit 1

if [ "$image_count" -eq 0 ]; then
  printf 'check-images: %s registers no images; nothing to build\n' "$manifest"
  exit 0
fi

# Pass 1: validate every entry's shape, uniqueness, and path existence
# before requiring or invoking docker at all, so a malformed manifest is
# always caught by pure validation -- never masked by (or dependent on)
# docker's availability.
names_seen=""
i=0
while [ "$i" -lt "$image_count" ]; do
  entry="$(jq -c ".images[$i]" "$manifest")" || exit 1

  entry_type="$(printf '%s' "$entry" | jq -r 'type')" || exit 1
  if [ "$entry_type" != "object" ]; then
    printf 'check-images: %s: images[%d] must be an object\n' "$manifest" "$i" >&2
    exit 1
  fi

  name="$(printf '%s' "$entry" | jq -r 'if has("name") then .name else "" end')" || exit 1
  context="$(printf '%s' "$entry" | jq -r 'if has("context") then .context else "" end')" || exit 1
  dockerfile="$(printf '%s' "$entry" | jq -r 'if has("dockerfile") then .dockerfile else "" end')" || exit 1

  if [ -z "$name" ] || [ -z "$context" ] || [ -z "$dockerfile" ]; then
    printf 'check-images: %s: images[%d] must set non-empty "name", "context", and "dockerfile"\n' \
      "$manifest" "$i" >&2
    exit 1
  fi

  case " $names_seen " in
  *" $name "*)
    printf 'check-images: %s: duplicate image name %s\n' "$manifest" "$name" >&2
    exit 1
    ;;
  esac
  names_seen="$names_seen $name"

  if [ ! -d "$context" ]; then
    printf 'check-images: %s: images[%d] (%s) context directory not found: %s\n' \
      "$manifest" "$i" "$name" "$context" >&2
    exit 1
  fi

  if [ ! -f "$dockerfile" ]; then
    printf 'check-images: %s: images[%d] (%s) dockerfile not found: %s\n' \
      "$manifest" "$i" "$name" "$dockerfile" >&2
    exit 1
  fi

  case "$dockerfile" in
  "$context"/*) : ;;
  *)
    printf 'check-images: %s: images[%d] (%s) dockerfile %s is not inside context %s\n' \
      "$manifest" "$i" "$name" "$dockerfile" "$context" >&2
    exit 1
    ;;
  esac

  i=$((i + 1))
done

# Pass 2: every registered entry is well-formed. Only now do we require
# docker and start building.
if ! command -v docker >/dev/null 2>&1; then
  printf 'check-images: docker is required to build %d registered image(s) but was not found on PATH\n' \
    "$image_count" >&2
  exit 1
fi

source_epoch="$(git show -s --format=%ct HEAD)" || exit 1
case "$source_epoch" in
"" | *[!0-9]* | 0)
  printf 'check-images: exact HEAD has no valid positive source epoch\n' >&2
  exit 1
  ;;
esac

created_epoch() {
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

i=0
while [ "$i" -lt "$image_count" ]; do
  entry="$(jq -c ".images[$i]" "$manifest")" || exit 1
  name="$(printf '%s' "$entry" | jq -r '.name')" || exit 1
  context="$(printf '%s' "$entry" | jq -r '.context')" || exit 1
  dockerfile="$(printf '%s' "$entry" | jq -r '.dockerfile')" || exit 1

  # Compare the original JSON fields: shell command substitution can lose
  # trailing newlines and NULs. Only exact fixed triples gain image attribution;
  # unknown or changed triples retain the legacy phase-only codes 40..48.
  failure_base="$(
    printf '%s' "$entry" | jq -r '
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
  )" || exit 1
  case "$failure_base" in
  40 | 50 | 60 | 70 | 80 | 90 | 100 | 110) ;;
  *) exit 1 ;;
  esac

  tag_a="portable-ghar-check-images:${name}-a"
  tag_b="portable-ghar-check-images:${name}-b"

  # Fixed bases plus offsets 0..8 form the closed image/phase protocol.
  # Docker output remains private and is never parsed for diagnostic authority.
  if ! SOURCE_DATE_EPOCH="$source_epoch" docker buildx build \
    --platform linux/amd64 \
    --no-cache \
    --provenance=false \
    --sbom=false \
    --build-arg "SOURCE_DATE_EPOCH=$source_epoch" \
    --output "type=docker,name=$tag_a,rewrite-timestamp=true" \
    -f "$dockerfile" "$context" >/dev/null; then
    exit "$((failure_base + 0))"
  fi
  if ! id_a="$(docker image inspect --format '{{.Id}}' "$tag_a")"; then
    exit "$((failure_base + 1))"
  fi
  if ! created_a="$(docker image inspect --format '{{.Created}}' "$tag_a")"; then
    exit "$((failure_base + 2))"
  fi
  if ! created_epoch_a="$(created_epoch "$created_a")" ||
    [ "$created_epoch_a" != "$source_epoch" ]; then
    docker image rm -f "$tag_a" >/dev/null 2>&1 || true
    printf 'check-images: %s first export has noncanonical creation time\n' "$name" >&2
    exit "$((failure_base + 3))"
  fi

  if ! SOURCE_DATE_EPOCH="$source_epoch" docker buildx build \
    --platform linux/amd64 \
    --no-cache \
    --provenance=false \
    --sbom=false \
    --build-arg "SOURCE_DATE_EPOCH=$source_epoch" \
    --output "type=docker,name=$tag_b,rewrite-timestamp=true" \
    -f "$dockerfile" "$context" >/dev/null; then
    exit "$((failure_base + 4))"
  fi
  if ! id_b="$(docker image inspect --format '{{.Id}}' "$tag_b")"; then
    exit "$((failure_base + 5))"
  fi
  if ! created_b="$(docker image inspect --format '{{.Created}}' "$tag_b")"; then
    exit "$((failure_base + 6))"
  fi
  if ! created_epoch_b="$(created_epoch "$created_b")" ||
    [ "$created_epoch_b" != "$source_epoch" ]; then
    docker image rm -f "$tag_a" "$tag_b" >/dev/null 2>&1 || true
    printf 'check-images: %s second export has noncanonical creation time\n' "$name" >&2
    exit "$((failure_base + 7))"
  fi

  docker image rm -f "$tag_a" "$tag_b" >/dev/null 2>&1 || true

  if [ "$id_a" != "$id_b" ]; then
    printf 'check-images: %s is not reproducible: %s != %s\n' "$name" "$id_a" "$id_b" >&2
    exit "$((failure_base + 8))"
  fi

  printf 'check-images: %s builds reproducibly (%s)\n' "$name" "$id_a"

  i=$((i + 1))
done

printf 'check-images: all %d registered image(s) build reproducibly\n' "$image_count"
