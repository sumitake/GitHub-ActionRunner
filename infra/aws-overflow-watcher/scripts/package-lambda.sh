#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Zip the controller and record an offline binding to the template parameters
# that name its bucket, key, and object version. This does not read S3.
set -eu
root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
template="$root/template.yaml"

if [ "${1:-}" = "--check" ]; then
  zip=${2:?zip}
  binding=${3:?binding}
  template=${4:?template}
  python3 - "$zip" "$binding" "$template" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

zip_path = Path(sys.argv[1])
binding_path = Path(sys.argv[2])
template_path = Path(sys.argv[3])
expected = ["CodeS3Bucket", "CodeS3Key", "CodeS3ObjectVersion"]


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if not binding_path.is_file():
    fail("absent linkage")
if not zip_path.is_file():
    fail("missing artifact")
binding = json.loads(binding_path.read_text(encoding="utf-8"))
if binding.get("s3_object_attested") is not False:
    fail("refusing S3 object attestation")
if binding.get("parameters") != expected:
    fail("stale binding parameters")
digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
if digest != binding.get("artifact_sha256") or binding.get("artifact_bytes") != zip_path.stat().st_size:
    fail("mismatched artifact")
text = template_path.read_text(encoding="utf-8")
code_at = text.index("      Code:\n")
environment_at = text.index("      Environment:\n", code_at)
refs = re.findall(r"Ref: (\w+)", text[code_at:environment_at])
if refs != expected:
    fail("substituted or stale template input")
for name in expected:
    start = text.index(f"  {name}:\n")
    rest = text[start + len(f"  {name}:\n") :]
    nxt = re.search(r"\n  [A-Z]", rest)
    block = rest[: nxt.start()] if nxt else rest
    if re.search(r"(?m)^\s*Default:", block):
        fail("substituted template input")
print("offline binding ok")
PY
  exit 0
fi

dest=${1:?output zip}
tmp=$(mktemp -d)
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
mkdir -p "$tmp/src" "$tmp/boot"
cp -R "$root/src/overflow_watcher" "$tmp/src/"
rm -rf "$tmp/src/overflow_watcher/__pycache__"
cp "$root/boot/supervisor.sh" "$tmp/boot/supervisor.sh"
python3 - "$tmp" "$dest" <<'PY'
import hashlib
import json
import sys
import zipfile
from pathlib import Path

src = Path(sys.argv[1])
dest = Path(sys.argv[2])
with zipfile.ZipFile(dest, "w") as archive:
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        info = zipfile.ZipInfo(path.relative_to(src).as_posix())
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (path.stat().st_mode & 0o777) << 16
        archive.writestr(info, path.read_bytes())
raw = dest.read_bytes()
binding = {
    "kind": "offline-lambda-zip-binding",
    "artifact_sha256": hashlib.sha256(raw).hexdigest(),
    "artifact_bytes": len(raw),
    "parameters": ["CodeS3Bucket", "CodeS3Key", "CodeS3ObjectVersion"],
    "s3_object_attested": False,
}
dest.with_name(dest.name + ".binding.json").write_text(
    json.dumps(binding, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
