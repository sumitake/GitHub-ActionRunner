"""Privilege-boundary contracts for the one-shot network policy helper."""

from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class NetworkHelperPrivilegeContractTest(unittest.TestCase):
    def test_image_defaults_non_root_before_entrypoint(self) -> None:
        dockerfile = (
            REPO_ROOT / "images/network-helper/Dockerfile"
        ).read_text(encoding="utf-8")

        final_stage = dockerfile.rsplit("\nFROM scratch\n", maxsplit=1)[1]
        user_index = final_stage.index("\nUSER 65532:65532\n")
        entrypoint_index = final_stage.index("\nENTRYPOINT ")

        self.assertLess(user_index, entrypoint_index)


if __name__ == "__main__":
    unittest.main()
