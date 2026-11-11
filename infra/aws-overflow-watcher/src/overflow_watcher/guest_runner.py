# SPDX-License-Identifier: MPL-2.0
"""Install the pinned Actions runner on a stock image at boot. Stdlib only."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

# Mirror of release/manifest.json runtime.runner_release. A unit test fails
# when the two differ, so a runner bump there moves this value too.
RUNNER_VERSION = "2.338.0"
RUNNER_SHA256 = "af4b794c1bc41d73d40535e3fe092a39f9679cd8d965954c2aca25a05ca41d32"
RUNNER_URL = (
    "https://github.com/actions/runner/releases/download/"
    f"v{RUNNER_VERSION}/actions-runner-linux-x64-{RUNNER_VERSION}.tar.gz"
)
DEFAULT_ROOT = "/opt/actions-runner"
LISTENER = Path("bin") / "Runner.Listener"


class InstallError(RuntimeError):
    """The runner was not installed. Nothing is left at the target root."""


def _download(url: str, dest: Path) -> str:
    digest = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=120) as response, open(dest, "wb") as out:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest()


def install(root: str = DEFAULT_ROOT, url: str = RUNNER_URL, sha256: str = RUNNER_SHA256) -> Path:
    """Download, verify, extract, and move the runner into `root`."""
    target = Path(root)
    if target.exists():
        raise InstallError("runner root already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".runner-", dir=target.parent))
    try:
        archive = work / "runner.tar.gz"
        if _download(url, archive) != sha256:
            raise InstallError("runner sha256 mismatch")
        staged = work / "root"
        staged.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(staged, filter="data")
        listener = staged / LISTENER
        if not listener.is_file() or not os.access(listener, os.X_OK):
            raise InstallError("runner listener missing")
        os.rename(staged, target)
        return target
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv: list[str]) -> int:
    if argv[1:] != ["install"]:
        print("usage: guest_runner install", file=sys.stderr)
        return 2
    root = os.environ.get("OVERFLOW_RUNNER_ROOT", DEFAULT_ROOT)
    try:
        install(root, os.environ.get("OVERFLOW_RUNNER_URL", RUNNER_URL))
    except Exception as exc:  # any failure leaves no runner and fails boot closed
        print(f"overflow-runner install failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
