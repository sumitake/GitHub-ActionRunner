#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Zip the controller for CodeS3Key. The archive root contains src/ and boot/.
# controller.py's parents[2] / boot / supervisor.sh is inside that root.
# The function environment sets PYTHONPATH=/var/task/src.
set -eu
root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
dest=${1:?output zip}
tmp=$(mktemp -d)
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
mkdir -p "$tmp/src" "$tmp/boot"
cp -R "$root/src/overflow_watcher" "$tmp/src/"
rm -rf "$tmp/src/overflow_watcher/__pycache__"
cp "$root/boot/supervisor.sh" "$tmp/boot/supervisor.sh"
python3 - "$tmp" "$dest" <<'PY'
import sys
import zipfile
from pathlib import Path

src = Path(sys.argv[1])
dest = Path(sys.argv[2])
with zipfile.ZipFile(dest, "w") as archive:
    for path in sorted(src.rglob("*")):
        if path.is_file():
            archive.write(path, path.relative_to(src).as_posix())
PY
