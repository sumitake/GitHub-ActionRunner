#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Boot wrapper. Completion rules live in overflow_watcher.supervisor.
set -eu
here=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
export PYTHONPATH="${here}/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m overflow_watcher.supervisor
