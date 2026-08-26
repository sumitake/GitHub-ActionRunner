#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
export GOTOOLCHAIN=go1.26.6
npm run --workspace worker lint
npm run --workspace worker typecheck
npm run --workspace worker test
GOTOOLCHAIN=go1.26.6 go test ./internal/failoverclient ./internal/health ./internal/observability -count=1
printf '%s\n' 'failover source: PASS'
