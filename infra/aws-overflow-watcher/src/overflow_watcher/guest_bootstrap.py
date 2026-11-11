# SPDX-License-Identifier: MPL-2.0
"""Self-contained guest user data. The supervisor closure travels inside the script."""

from __future__ import annotations

import base64
import io
import tarfile
from pathlib import Path

_SCRIPT = """#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Install overflow_watcher under the guest root, then start the supervisor.
# Cloud-init runs this file from its own script directory, so the package
# cannot be found relative to a source checkout.
set -eu
root=${OVERFLOW_INSTALL_ROOT:-/opt/overflow-watcher}
mkdir -p "$root"
payload=$(awk 'f {print; exit} /^# PAYLOAD$/ {f=1}' "$0")
printf '%s\\n' "$payload" | base64 -d | tar -xzf - -C "$root"
export PYTHONPATH="$root"
if [ "${OVERFLOW_BOOTSTRAP:-run}" = "install" ]; then
  exit 0
fi
exec python3 -m overflow_watcher.supervisor
# PAYLOAD
PAYLOAD_LINE
"""

# Import closure of `python -m overflow_watcher.supervisor`: package init,
# supervisor.py, and types.py. EC2 rejects RunInstances user data above
# 16384 raw bytes, so the guest tarball is only these modules.
_SUPERVISOR_CLOSURE = ("__init__.py", "supervisor.py", "types.py")


def render_user_data() -> str:
    """Shell script that installs the supervisor closure and execs it."""
    package = Path(__file__).resolve().parent
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as archive:
        for name in _SUPERVISOR_CLOSURE:
            archive.add(package / name, arcname=str(Path("overflow_watcher") / name))
    payload = base64.b64encode(blob.getvalue()).decode("ascii")
    return _SCRIPT.replace("PAYLOAD_LINE", payload)
