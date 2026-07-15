#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Manifest-driven container image build/reproducibility gate for CI.
#
# Validates images/manifest.json (or an override manifest passed as $1 or
# via IMAGES_MANIFEST) against a small closed schema, then -- for every
# registered image -- builds it twice with --no-cache and requires the two
# resulting image IDs to be identical (a basic reproducible-build gate).
# The phase-1 manifest registers zero images ({"version":1,"images":[]})
# and must pass explicitly without ever invoking docker.
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

if [ ! -f "$manifest" ]; then
  printf 'check-images: manifest not found: %s\n' "$manifest" >&2
  exit 1
fi

if ! jq empty "$manifest" >/dev/null 2>&1; then
  printf 'check-images: %s is not valid JSON\n' "$manifest" >&2
  exit 1
fi

version="$(jq -r 'if has("version") then (.version | tostring) else "<missing>" end' "$manifest")"
if [ "$version" != "1" ]; then
  printf 'check-images: %s: unsupported or missing "version" (expected 1, got %s)\n' "$manifest" "$version" >&2
  exit 1
fi

images_type="$(jq -r '.images | type' "$manifest")"
if [ "$images_type" != "array" ]; then
  printf 'check-images: %s: "images" must be an array (got %s)\n' "$manifest" "$images_type" >&2
  exit 1
fi

image_count="$(jq -r '.images | length' "$manifest")"

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
  entry="$(jq -c ".images[$i]" "$manifest")"

  entry_type="$(printf '%s' "$entry" | jq -r 'type')"
  if [ "$entry_type" != "object" ]; then
    printf 'check-images: %s: images[%d] must be an object\n' "$manifest" "$i" >&2
    exit 1
  fi

  name="$(printf '%s' "$entry" | jq -r 'if has("name") then .name else "" end')"
  context="$(printf '%s' "$entry" | jq -r 'if has("context") then .context else "" end')"
  dockerfile="$(printf '%s' "$entry" | jq -r 'if has("dockerfile") then .dockerfile else "" end')"

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

i=0
while [ "$i" -lt "$image_count" ]; do
  entry="$(jq -c ".images[$i]" "$manifest")"
  name="$(printf '%s' "$entry" | jq -r '.name')"
  context="$(printf '%s' "$entry" | jq -r '.context')"
  dockerfile="$(printf '%s' "$entry" | jq -r '.dockerfile')"

  tag_a="portable-ghar-check-images:${name}-a"
  tag_b="portable-ghar-check-images:${name}-b"

  docker build --no-cache -f "$dockerfile" -t "$tag_a" "$context" >/dev/null
  id_a="$(docker image inspect --format '{{.Id}}' "$tag_a")"
  docker build --no-cache -f "$dockerfile" -t "$tag_b" "$context" >/dev/null
  id_b="$(docker image inspect --format '{{.Id}}' "$tag_b")"

  docker image rm -f "$tag_a" "$tag_b" >/dev/null 2>&1 || true

  if [ "$id_a" != "$id_b" ]; then
    printf 'check-images: %s is not reproducible: %s != %s\n' "$name" "$id_a" "$id_b" >&2
    exit 1
  fi

  printf 'check-images: %s builds reproducibly (%s)\n' "$name" "$id_a"

  i=$((i + 1))
done

printf 'check-images: all %d registered image(s) build reproducibly\n' "$image_count"
