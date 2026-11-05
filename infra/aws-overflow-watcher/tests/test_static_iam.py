# SPDX-License-Identifier: MPL-2.0
"""Static checks: one tagged terminate path, no deregister, no runner DELETE."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Finder(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.found: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "terminate_instances":
            self.found.append(self.stack[-1] if self.stack else "")
        self.generic_visit(node)


class StaticIamTests(unittest.TestCase):
    def test_static_terminate_instances_only_on_budget_stop_with_tag_condition(self) -> None:
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        self.assertEqual(template.count("ec2:TerminateInstances"), 1)
        window = template[template.index("ec2:TerminateInstances") : template.index("ec2:TerminateInstances") + 350]
        self.assertIn("aws:ResourceTag/overflow-watcher", window)
        self.assertIn("owned", window)
        finder = Finder()
        for path in (ROOT / "src").rglob("*.py"):
            finder.visit(ast.parse(path.read_text(encoding="utf-8")))
        self.assertEqual(finder.found, ["advance_owned_stop"])

    def test_static_no_deregister_or_runner_delete(self) -> None:
        blobs = []
        for path in list((ROOT / "src").rglob("*.py")) + list((ROOT / "boot").rglob("*")):
            if path.is_file():
                blobs.append(path.read_text(encoding="utf-8"))
        text = "\n".join(blobs)
        self.assertNotIn("config.sh", text)
        self.assertNotIn("RUNNER_TARGET", text)
        self.assertNotIn('method="DELETE"', text)
        self.assertNotIn("Method=DELETE", text)


if __name__ == "__main__":
    unittest.main()
