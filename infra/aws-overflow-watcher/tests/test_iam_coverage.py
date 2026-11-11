# SPDX-License-Identifier: MPL-2.0
"""Every AWS API call in the source maps to an action the template grants its role."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

import botocore.session
from botocore import xform_name

from test_template_concurrency import load_template

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "overflow_watcher"
# Modules that run on the runner instance under RunnerRole, not in the Lambda.
GUEST = {"guest_bootstrap.py", "guest_runner.py", "guest_ssm.py", "supervisor.py"}
# Called but deliberately not granted, with the reason.
NOT_GRANTED = {
    "dynamodb:CreateTable": "DynamoDB Local only; CloudFormation owns the table, so a missing table fails closed",
}


def role_actions(role: str) -> set[str]:
    actions: set[str] = set()
    for policy in load_template()["Resources"][role]["Properties"]["Policies"]:
        for statement in policy["PolicyDocument"]["Statement"]:
            if statement["Effect"] != "Allow":
                continue
            action = statement["Action"]
            actions.update([action] if isinstance(action, str) else action)
    return actions


def _trees(paths):
    for path in paths:
        yield ast.parse(path.read_text(encoding="utf-8"))


def controller_calls() -> set[str]:
    """IAM actions for boto3 client methods called in the Lambda modules."""
    paths = [path for path in sorted(SRC.glob("*.py")) if path.name not in GUEST]
    services: set[str] = set()
    names: set[str] = set()
    for tree in _trees(paths):
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            func = node.func
            if (
                func.attr == "client"
                and isinstance(func.value, ast.Name)
                and func.value.id == "boto3"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                services.add(node.args[0].value)
            names.add(func.attr)
    session = botocore.session.get_session()
    actions: set[str] = set()
    for service in services:
        model = session.get_service_model(service)
        for operation in model.operation_names:
            if xform_name(operation) in names:
                actions.add(f"{service}:{operation}")
    return actions


def guest_calls() -> set[str]:
    """SSM targets the guest signs by hand: guest_ssm.call("Operation", ...)."""
    actions: set[str] = set()
    for tree in _trees([SRC / "guest_ssm.py"]):
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "call"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                actions.add(f"ssm:{node.args[0].value}")
    return actions


class IamCoverageTests(unittest.TestCase):
    def test_controller_calls_are_granted(self) -> None:
        calls = controller_calls()
        # Guards the scan itself: these are known calls.
        self.assertTrue({"dynamodb:DescribeTable", "ec2:RunInstances", "ssm:PutParameter"} <= calls, calls)
        missing = calls - role_actions("ControllerRole") - set(NOT_GRANTED)
        self.assertEqual(missing, set())

    def test_guest_calls_are_granted(self) -> None:
        calls = guest_calls()
        self.assertEqual(calls, {"ssm:GetParameter", "ssm:DeleteParameter"})
        self.assertEqual(calls - role_actions("RunnerRole"), set())

    def test_describe_table_is_scoped_to_the_state_table(self) -> None:
        statements = load_template()["Resources"]["ControllerRole"]["Properties"]["Policies"][0]["PolicyDocument"][
            "Statement"
        ]
        scoped = [s for s in statements if "dynamodb:DescribeTable" in s["Action"]]
        self.assertEqual(len(scoped), 1)
        self.assertEqual(scoped[0]["Resource"], [{"Fn::GetAtt": ["StateTable", "Arn"]}])


if __name__ == "__main__":
    unittest.main()
