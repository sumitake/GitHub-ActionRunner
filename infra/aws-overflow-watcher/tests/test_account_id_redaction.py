# SPDX-License-Identifier: MPL-2.0
"""Tracked text must not embed the target AWS account id."""

from __future__ import annotations

import hashlib
import re
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
# sha256 of the 12-digit AWS account id, encoded as ASCII digits.
# The id itself is not stored in the tree.
ACCOUNT_ID_SHA256 = "f54ac8067e994939f071066b3e92f4a2d3cfa59f43623557a02c662361b65b00"
_TWELVE_DIGITS = re.compile(rb"(?=(\d{12}))")


def _tracked_text_files() -> list[str]:
    listed = subprocess.check_output(["git", "ls-files"], cwd=REPO, text=True).splitlines()
    return listed


def _hits_in(rel: str) -> bool:
    path = REPO / rel
    if not path.is_file():
        return False
    data = path.read_bytes()
    if b"\0" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    for run in _TWELVE_DIGITS.findall(data):
        if hashlib.sha256(run).hexdigest() == ACCOUNT_ID_SHA256:
            return True
    return False


class AccountIdRedactionTests(unittest.TestCase):
    def test_source_does_not_embed_the_aws_account_id(self) -> None:
        listed = _tracked_text_files()
        self.assertIn("infra/aws-overflow-watcher/CHECKLIST.md", listed)
        self.assertIn("docs/operations/overflow-watcher-deploy-inputs.md", listed)
        hits = [rel for rel in listed if _hits_in(rel)]
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
