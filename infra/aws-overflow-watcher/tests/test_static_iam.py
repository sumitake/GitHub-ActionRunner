# SPDX-License-Identifier: MPL-2.0
"""Static checks: one tagged terminate path, and runner DELETE only in the GitHub client."""

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


class DeleteFinder(ast.NodeVisitor):
    """Record functions that pass method="DELETE"."""

    def __init__(self) -> None:
        self.stack: list[str] = []
        self.found: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_keyword(self, node: ast.keyword) -> None:
        if node.arg == "method" and isinstance(node.value, ast.Constant) and node.value.value == "DELETE":
            self.found.append(self.stack[-1] if self.stack else "")
        self.generic_visit(node)


class StaticIamTests(unittest.TestCase):
    def test_static_terminate_instances_only_on_budget_stop_with_tag_condition(self) -> None:
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        self.assertEqual(template.count("ec2:TerminateInstances"), 1)
        self.assertIn("ec2:CreateAction: RunInstances", template)
        create_at = template.index("ec2:CreateTags")
        self.assertNotIn('Resource: "*"', template[create_at : create_at + 280])
        window = template[template.index("ec2:TerminateInstances") : template.index("ec2:TerminateInstances") + 350]
        self.assertIn("aws:ResourceTag/overflow-watcher", window)
        self.assertIn("owned", window)
        finder = Finder()
        for path in (ROOT / "src").rglob("*.py"):
            finder.visit(ast.parse(path.read_text(encoding="utf-8")))
        self.assertEqual(finder.found, ["advance_owned_stop"])

    def test_static_no_deregister_or_runner_delete(self) -> None:
        paths = [
            path
            for path in list((ROOT / "src").rglob("*.py")) + list((ROOT / "boot").rglob("*"))
            if path.is_file()
        ]
        text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        self.assertNotIn("config.sh", text)
        self.assertNotIn("RUNNER_TARGET", text)
        self.assertNotIn("Method=DELETE", text)
        self.assertNotIn("method='DELETE'", text)
        github = (ROOT / "src" / "overflow_watcher" / "github_api.py").resolve()
        for path in paths:
            body = path.read_text(encoding="utf-8")
            if path.resolve() == github:
                self.assertEqual(body.count('method="DELETE"'), 1, path)
                continue
            self.assertNotIn('method="DELETE"', body, path)
        finder = DeleteFinder()
        finder.visit(ast.parse(github.read_text(encoding="utf-8")))
        self.assertEqual(finder.found, ["delete_runner"])


if __name__ == "__main__":
    unittest.main()
