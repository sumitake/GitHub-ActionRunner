# SPDX-License-Identifier: MPL-2.0
"""Self-contained guest user data. The supervisor closure travels inside the script."""

from __future__ import annotations

import base64
import io
import tarfile
from pathlib import Path

from overflow_watcher.jit_handoff import valid_parameter_name

_SCRIPT = r"""#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Install overflow_watcher under the guest root, then start the supervisor.
# Cloud-init runs this file from its own script directory, so the package
# cannot be found relative to a source checkout.
set -eu
root=${OVERFLOW_INSTALL_ROOT:-/opt/overflow-watcher}
mkdir -p "$root"
payload=$(awk 'f {print; exit} /^# PAYLOAD$/ {f=1}' "$0")
printf '%s\n' "$payload" | base64 -d | tar -xzf - -C "$root"
export PYTHONPATH="$root"
if [ "${OVERFLOW_BOOTSTRAP:-run}" = "install" ]; then
  exit 0
fi
umask 077
mkdir -p /run/overflow-watcher
param=PARAM_LITERAL
tmp=$(mktemp)
if ! aws ssm get-parameter --name "$param" --with-decryption --query Parameter.Value --output text >"$tmp"; then
  rm -f "$tmp"
  unset RUNNER_CONFIG
  exec python3 -m overflow_watcher.supervisor
fi
python3 - "$tmp" <<'PY'
import pathlib, sys
src = pathlib.Path(sys.argv[1])
data = src.read_bytes()
if data.endswith(b"\n"):
    data = data[:-1]
dest = pathlib.Path("/run/overflow-watcher/jitconfig")
dest.write_bytes(data)
dest.chmod(0o600)
src.unlink()
PY
aws ssm delete-parameter --name "$param" || true
cat > /run/overflow-watcher/launch <<'END'
#!/bin/sh
set -eu
exec /opt/actions-runner/bin/Runner.Listener run --jitconfig "$(cat /run/overflow-watcher/jitconfig)" "$@"
END
chmod 0700 /run/overflow-watcher/launch
export RUNNER_CONFIG=/run/overflow-watcher/jitconfig
export RUNNER_COMMAND=/run/overflow-watcher/launch
export PYTHONPATH="$root"
exec python3 -m overflow_watcher.supervisor
# PAYLOAD
PAYLOAD_LINE
"""

# Import closure of `python -m overflow_watcher.supervisor`: package init,
# supervisor.py, and types.py. EC2 rejects RunInstances user data above
# 16384 raw bytes, so the guest tarball is only these modules.
_SUPERVISOR_CLOSURE = ("__init__.py", "supervisor.py", "types.py")


def render_user_data(parameter_name: str) -> str:
    """Shell script that installs the supervisor and reads one SSM secret by name."""
    if not valid_parameter_name(parameter_name):
        raise ValueError("jit parameter name")
    package = Path(__file__).resolve().parent
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as archive:
        for name in _SUPERVISOR_CLOSURE:
            archive.add(package / name, arcname=str(Path("overflow_watcher") / name))
    payload = base64.b64encode(blob.getvalue()).decode("ascii")
    script = _SCRIPT.replace("PARAM_LITERAL", "'" + parameter_name + "'", 1)
    return script.replace("PAYLOAD_LINE", payload)
