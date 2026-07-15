"""Tests for the docs tooling used to keep public docs honest:

- scripts/docs/check-links.mjs           -- local links/anchors resolve;
  external links are syntax-checked only (no network).
- scripts/docs/check-command-examples.mjs -- every fenced ``operator-command``
  block maps to an existing repo-relative script path or a documented
  planned executable (no shell evaluation).

Both tools are run as real `node` subprocesses (deterministic, no mocking of
the tool itself) against the real docs AND against small seeded temp
fixtures, so a regression in either the docs or the tool is caught.

Run: python3 -m unittest tests.repository.test_docs_tools -v
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK_LINKS = REPO_ROOT / "scripts" / "docs" / "check-links.mjs"
CHECK_COMMANDS = REPO_ROOT / "scripts" / "docs" / "check-command-examples.mjs"

NODE = shutil.which("node") or "node"


def run_node(script: Path, *args: str, timeout: float = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [NODE, str(script), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class ToolsExistTest(unittest.TestCase):
    def test_check_links_script_exists(self) -> None:
        self.assertTrue(CHECK_LINKS.is_file(), f"missing {CHECK_LINKS}")

    def test_check_command_examples_script_exists(self) -> None:
        self.assertTrue(CHECK_COMMANDS.is_file(), f"missing {CHECK_COMMANDS}")


class CheckLinksToolTest(unittest.TestCase):
    def test_passes_on_real_docs(self) -> None:
        result = run_node(CHECK_LINKS)
        self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}")

    def test_fails_on_seeded_broken_local_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n[bad link](./does-not-exist.md)\n", encoding="utf-8"
            )
            result = run_node(CHECK_LINKS, str(tmp_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does-not-exist.md", result.stdout + result.stderr)

    def test_fails_on_seeded_broken_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n## Real Heading\n\n[bad anchor](#not-a-real-heading)\n",
                encoding="utf-8",
            )
            result = run_node(CHECK_LINKS, str(tmp_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not-a-real-heading", result.stdout + result.stderr)

    def test_fails_on_seeded_broken_cross_file_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n[link](./b.md#missing-section)\n", encoding="utf-8"
            )
            (tmp_path / "b.md").write_text("# B\n\n## Present Section\n", encoding="utf-8")
            result = run_node(CHECK_LINKS, str(tmp_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing-section", result.stdout + result.stderr)

    def test_passes_on_seeded_good_links_and_never_hits_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n"
                "## Real Heading\n\n"
                "[same-file anchor](#real-heading)\n"
                "[other file](./b.md)\n"
                "[other file anchor](./b.md#other-heading)\n"
                "[external, syntax only](https://this-host-does-not-resolve.invalid.example/docs)\n"
                "[mailto external](mailto:operator@example.invalid)\n",
                encoding="utf-8",
            )
            (tmp_path / "b.md").write_text("# B\n\n## Other Heading\n", encoding="utf-8")
            result = run_node(CHECK_LINKS, str(tmp_path), timeout=15)
            self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}")

    def test_fails_on_seeded_syntactically_invalid_external_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n[bad external](https://)\n", encoding="utf-8"
            )
            result = run_node(CHECK_LINKS, str(tmp_path))
            self.assertNotEqual(result.returncode, 0)


class CheckCommandExamplesToolTest(unittest.TestCase):
    def test_passes_on_real_docs(self) -> None:
        result = run_node(CHECK_COMMANDS)
        self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}")

    def test_fails_on_seeded_unknown_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n```operator-command\ntotally-unknown-binary status\n```\n",
                encoding="utf-8",
            )
            result = run_node(CHECK_COMMANDS, str(tmp_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("totally-unknown-binary", result.stdout + result.stderr)

    def test_passes_on_seeded_known_planned_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n```operator-command\nportable-ghar status --expect-route hosted\n```\n",
                encoding="utf-8",
            )
            result = run_node(CHECK_COMMANDS, str(tmp_path))
            self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}")

    def test_ignores_non_operator_command_fences(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n```sh\ntotally-unknown-binary status\n```\n",
                encoding="utf-8",
            )
            result = run_node(CHECK_COMMANDS, str(tmp_path))
            self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}")

    def test_passes_on_seeded_existing_repo_script_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n```operator-command\npython3 scripts/sanitize_public.py --tracked\n```\n",
                encoding="utf-8",
            )
            result = run_node(CHECK_COMMANDS, str(tmp_path))
            self.assertEqual(result.returncode, 0, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}")

    def test_fails_on_seeded_nonexistent_script_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "a.md").write_text(
                "# A\n\n```operator-command\npython3 scripts/does-not-exist.py\n```\n",
                encoding="utf-8",
            )
            result = run_node(CHECK_COMMANDS, str(tmp_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("scripts/does-not-exist.py", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
