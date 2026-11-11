# SPDX-License-Identifier: MPL-2.0
"""ControllerReservedConcurrency: empty omits the property, a number sets it. Stack Outputs."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import check_workflow_policy  # noqa: E402  (repo's fail-closed YAML subset parser)

NO_VALUE = object()


def load_template() -> dict:
    """Parse template.yaml, replacing the one block scalar the parser refuses."""
    out: list[str] = []
    skip: int | None = None
    for line in (ROOT / "template.yaml").read_text(encoding="utf-8").split("\n"):
        indent = len(line) - len(line.lstrip())
        if skip is not None:
            if line.strip() == "" or indent > skip:
                continue
            skip = None
        if line.rstrip().endswith(": |"):
            out.append(line.rstrip()[:-1] + "block-scalar")
            skip = indent
            continue
        out.append(line)
    return check_workflow_policy.parse_workflow("\n".join(out))


def resolve(node, params: dict, conditions: dict):
    """Evaluate the intrinsics this check needs: Ref, Fn::Equals, Fn::Not, Fn::If."""
    if isinstance(node, dict) and len(node) == 1:
        (key, value), = node.items()
        if key == "Ref":
            if value == "AWS::NoValue":
                return NO_VALUE
            return params[value] if value in params else node
        if key == "Fn::Equals":
            left, right = (resolve(item, params, conditions) for item in value)
            return left == right
        if key == "Fn::Not":
            return not resolve(value[0], params, conditions)
        if key == "Fn::If":
            name, yes, no = value
            return resolve(yes if conditions[name] else no, params, conditions)
    if isinstance(node, dict):
        resolved = {k: resolve(v, params, conditions) for k, v in node.items()}
        return {k: v for k, v in resolved.items() if v is not NO_VALUE}
    if isinstance(node, list):
        return [resolve(item, params, conditions) for item in node]
    return node


def controller_properties(value: str) -> dict:
    template = load_template()
    params = {"ControllerReservedConcurrency": value}
    conditions = {
        name: resolve(body, params, {}) for name, body in template["Conditions"].items()
    }
    return resolve(template["Resources"]["ControllerFunction"]["Properties"], params, conditions)


class ReservedConcurrencyParamTests(unittest.TestCase):
    def test_empty_parameter_omits_reserved_concurrency(self) -> None:
        props = controller_properties("")
        self.assertNotIn("ReservedConcurrentExecutions", props)
        self.assertEqual(props["Timeout"], "45")

    def test_one_sets_reserved_concurrency(self) -> None:
        self.assertEqual(controller_properties("1")["ReservedConcurrentExecutions"], "1")

    def test_parameter_defaults_to_empty_and_rejects_zero(self) -> None:
        param = load_template()["Parameters"]["ControllerReservedConcurrency"]
        self.assertEqual(param["Default"], "")
        pattern = re.compile(param["AllowedPattern"])
        for ok in ("", "1", "10"):
            self.assertIsNotNone(pattern.fullmatch(ok), ok)
        for bad in ("0", "01", "-1", "x"):
            self.assertIsNone(pattern.fullmatch(bad), bad)

    def test_no_literal_reservation_remains(self) -> None:
        text = (ROOT / "template.yaml").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"ReservedConcurrentExecutions:\s*\d")

    def test_stack_outputs_name_controller_topic_and_table(self) -> None:
        template = load_template()
        outputs = {name: body["Value"] for name, body in template["Outputs"].items()}
        self.assertEqual(outputs["ControllerFunctionName"], {"Ref": "ControllerFunction"})
        self.assertEqual(
            outputs["ControllerFunctionArn"], {"Fn::GetAtt": ["ControllerFunction", "Arn"]}
        )
        self.assertEqual(outputs["BudgetAlertTopicArn"], {"Ref": "BudgetAlertTopic"})
        self.assertEqual(outputs["StateTableName"], {"Ref": "StateTable"})
        for resource in ("ControllerFunction", "BudgetAlertTopic", "StateTable"):
            self.assertIn(resource, template["Resources"])


if __name__ == "__main__":
    unittest.main()
