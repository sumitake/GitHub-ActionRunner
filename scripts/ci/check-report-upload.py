"""Snapshot one complete scanner report before permitting its artifact upload."""
# SPDX-License-Identifier: MPL-2.0
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys


# Two ordinary reports per publication: at most 96 MiB of file contents.
# Each upload contains one fixed short filename; 4 MiB remains for ZIP framing.
REPORT_LIMIT = 48 * 2**20
REPORTS = {"gitleaks": "results.sarif", "trivy": "trivy-fs-results.json"}


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def snapshot_report(kind: str, workspace: Path, temporary: Path) -> Path:
    if kind not in REPORTS or any(
        not root.is_absolute() or root.resolve(strict=True) != root
        or any(char in str(root) for char in "\r\n")
        for root in (workspace, temporary)
    ):
        raise ValueError("invalid report roots")
    source = workspace / REPORTS[kind]
    before = source.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= REPORT_LIMIT):
        raise ValueError("report is not a bounded regular file")
    target_root = temporary / ("pghar-report-upload-" + kind)
    target_root.mkdir(mode=0o700)
    target = target_root / source.name
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(source, flags), "rb") as reader:
        if identity(os.fstat(reader.fileno())) != identity(before):
            raise ValueError("report changed before snapshot")
        with target.open("xb") as writer:
            copied = 0
            while chunk := reader.read(2**20):
                copied += len(chunk)
                if copied > REPORT_LIMIT:
                    raise ValueError("report exceeds upload limit")
                writer.write(chunk)
        if (copied != before.st_size
                or identity(os.fstat(reader.fileno())) != identity(before)
                or identity(source.lstat()) != identity(before)):
            raise ValueError("report changed during snapshot")
    target.chmod(0o400)
    target_root.chmod(0o500)
    return target


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("one report kind required")
        result = snapshot_report(sys.argv[1], Path(os.environ["GITHUB_WORKSPACE"]),
                                 Path(os.environ["RUNNER_TEMP"]))
    except (KeyError, OSError, ValueError):
        raise SystemExit("report upload admission failed; no report bytes emitted") from None
    print("path=" + str(result))


if __name__ == "__main__":
    main()
