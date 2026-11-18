# SPDX-License-Identifier: MPL-2.0
"""Controller Lambda Errors alarm and its topic-policy ARN."""

from __future__ import annotations

import unittest

from test_template_concurrency import load_template


def _getatt(name: str) -> dict:
    return {"Fn::GetAtt": [name, "Arn"]}


def _function_name_dimension(props: dict):
    for dim in props.get("Dimensions") or []:
        if dim.get("Name") == "FunctionName":
            return dim.get("Value")
    return None


class ControllerErrorsAlarmTests(unittest.TestCase):
    def test_controller_errors_alarm_watches_lambda_errors(self) -> None:
        resources = load_template()["Resources"]
        self.assertIn("ControllerErrorsAlarm", resources)
        alarm = resources["ControllerErrorsAlarm"]
        self.assertEqual(alarm["Type"], "AWS::CloudWatch::Alarm")
        props = alarm["Properties"]
        self.assertEqual(props["Namespace"], "AWS/Lambda")
        self.assertEqual(props["MetricName"], "Errors")
        self.assertEqual(_function_name_dimension(props), {"Ref": "ControllerFunction"})
        self.assertEqual(props["Statistic"], "Sum")
        self.assertEqual(props["Period"], "60")
        self.assertEqual(props["EvaluationPeriods"], "1")
        self.assertEqual(props["Threshold"], "1")
        self.assertEqual(props["ComparisonOperator"], "GreaterThanOrEqualToThreshold")
        self.assertEqual(props["TreatMissingData"], "notBreaching")
        self.assertEqual(props["AlarmActions"], [{"Ref": "BudgetAlertTopic"}])

    def test_alert_topic_policy_allows_the_errors_alarm(self) -> None:
        policy = load_template()["Resources"]["BudgetAlertTopicPolicy"]
        statement = policy["Properties"]["PolicyDocument"]["Statement"][0]
        self.assertEqual(statement["Sid"], "AllowCloudWatchAlarms")
        source = statement["Condition"]["ArnEquals"]["aws:SourceArn"]
        expected = [
            _getatt("SoftCapAlarm"),
            _getatt("GraceAlarm"),
            _getatt("ControllerErrorsAlarm"),
        ]
        self.assertEqual(len(source), 3)
        self.assertCountEqual(source, expected)


if __name__ == "__main__":
    unittest.main()
