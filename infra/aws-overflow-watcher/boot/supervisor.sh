#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Guest launcher. The package is installed at $OVERFLOW_INSTALL_ROOT
# (default /opt/overflow-watcher), not in a source checkout.
set -eu
root=${OVERFLOW_INSTALL_ROOT:-/opt/overflow-watcher}
if [ ! -d "$root/overflow_watcher" ]; then
  echo "overflow_watcher is not installed under $root" >&2
  exit 1
fi
export PYTHONPATH="$root"
exec python3 -m overflow_watcher.supervisor
