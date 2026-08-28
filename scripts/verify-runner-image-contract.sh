#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ "$1" != "--source-only" ]; then
  printf '%s\n' \
    'usage: verify-runner-image-contract.sh --source-only' >&2
  exit 2
fi

repository_root=$(
  CDPATH='' cd -- "$(dirname -- "$0")/.." &&
    pwd -P
)
cd "$repository_root"

: "${GOCACHE:=/private/tmp/portable-ghar-runner-image-go-cache}"
: "${GOTOOLCHAIN:=go1.26.6}"
export GOCACHE GOTOOLCHAIN

go test -race \
  ./internal/archive \
  ./internal/imageverify \
  ./cmd/portable-ghar-runner-gate \
  -count=1
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest \
  tests.repository.test_runner_image_reproducibility_contract
