# SPDX-License-Identifier: MPL-2.0
"""The overflow-watcher package must not embed the target AWS account id."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
NEEDLE = "922176437318"
EXCLUDE = Path(__file__).resolve()


class AccountIdRedactionTests(unittest.TestCase):
    def test_source_does_not_embed_the_aws_account_id(self) -> None:
        listed = subprocess.check_output(
            [
                "git",
                "ls-files",
                "infra/aws-overflow-watcher/",
                "docs/operations/overflow-watcher-deploy-inputs.md",
            ],
            cwd=REPO,
            text=True,
        ).splitlines()
        self.assertIn("infra/aws-overflow-watcher/CHECKLIST.md", listed)
        self.assertIn("docs/operations/overflow-watcher-deploy-inputs.md", listed)
        hits: list[str] = []
        needle = NEEDLE.encode("ascii")
        for rel in listed:
            path = (REPO / rel).resolve()
            if path == EXCLUDE:
                continue
            if needle in path.read_bytes():
                hits.append(rel)
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
