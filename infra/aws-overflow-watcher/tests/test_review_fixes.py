# SPDX-License-Identifier: MPL-2.0
"""Regression tests for the review findings on the overflow watcher."""

from __future__ import annotations

import base64
import json
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from fakes import FakeEc2, FakeGitHub
from support import NOW, add_cents, cfg, fresh_store, sample_job, seed_instance, watcher_env

from overflow_watcher.budget import AlertLog
from overflow_watcher.config import load_config
from overflow_watcher.controller import admission_allows, ec2_params, launch_one, resolve_reservations, run_poll
from overflow_watcher.ec2view import Ec2Views
from overflow_watcher.handler import response_from_poll
from overflow_watcher.money import month_key
from overflow_watcher.supervisor import KEEP, Proof, _workers_alive, decide
from overflow_watcher.types import Decision, InstanceView

ROOT = Path(__file__).resolve().parents[1]


class ReviewFixTests(unittest.TestCase):
    def test_h1_sunk_over_grace_stops_every_eligible_once(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        for index, run_id in enumerate(("1", "2", "3"), start=1):
            seed_instance(
                store,
                ec2,
                instance_id=f"i-{index}",
                debit=100,
                month=month,
                launch_epoch=NOW - index * 100,
                run_id=run_id,
            )
        add_cents(store, month, 3300 - store.get_accrued(month))
        before = store.get_accrued(month)
        config = cfg()
        run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual({call[2] for call in github.cancel_calls}, {"1", "2", "3"})
        self.assertEqual(store.get_accrued(month), before)
        run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual(len(github.cancel_calls), 3)

    def test_h1_estimate_change_stops_instance_spared_by_earlier_poll(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-live", debit=600, month=month,
            launch_epoch=NOW - 3600, run_id="2", price_numer=1, price_denom=1,
        )
        add_cents(store, month, 3200 - store.get_accrued(month))
        config = cfg()
        first = run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual([item for item in first.alerts.items if item.kind == "grace"], [])
        add_cents(store, month, 1)
        second = run_poll(store, ec2, ec2, github, config, NOW + 5)
        self.assertEqual([call[2] for call in github.cancel_calls], ["2"])
        self.assertEqual(second.budget.cancelled, ("i-live",))
        self.assertIsNone(store.get_marker(f"MONTH#{month}", "C4B#EPISODE"))

    def test_h2_empty_exclusions_fail_closed(self) -> None:
        for raw in ("", "[]"):
            loaded = load_config(watcher_env(BUDGET_STOP_EXCLUSIONS=raw))
            self.assertFalse(loaded.ok, raw)
            result = run_poll(fresh_store(), FakeEc2(), FakeEc2(), FakeGitHub(), loaded, NOW)
            self.assertEqual(result.launched, 0)

    def test_h2_default_patterns_exclude_deploy_and_migration(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-deploy", debit=50, month=month,
            launch_epoch=NOW - 30, workflow="deploy-site", job_name="ship", run_id="3",
        )
        seed_instance(
            store, ec2, instance_id="i-move", debit=50, month=month,
            launch_epoch=NOW - 20, workflow="CI", job_name="migrate-db", run_id="4",
        )
        seed_instance(
            store, ec2, instance_id="i-ok", debit=50, month=month,
            launch_epoch=NOW - 10, workflow="CI", job_name="test", run_id="5",
        )
        add_cents(store, month, 3600 - store.get_accrued(month))
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([call[2] for call in github.cancel_calls], ["5"])

    def test_h3_budget_and_grace_alerts_are_one_json_line_and_once_per_month(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-hit", debit=100, month=month, launch_epoch=NOW - 10, run_id="9")
        add_cents(store, month, 3400 - store.get_accrued(month))
        config = cfg()
        first = run_poll(store, ec2, ec2, github, config, NOW)
        second = run_poll(store, ec2, ec2, github, config, NOW)
        buffer = StringIO()
        with patch("sys.stdout", buffer):
            payload = response_from_poll(first)
        lines = [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]
        kinds = [line["kind"] for line in lines]
        self.assertEqual(kinds.count("budget"), 1)
        self.assertEqual(kinds.count("grace"), 1)
        self.assertEqual(payload["alerts"], lines)
        self.assertIsNotNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET"))
        self.assertIsNotNone(store.get_marker(f"MONTH#{month}", "ALERT#GRACE"))
        self.assertEqual([item.kind for item in second.alerts.items if item.kind in {"budget", "grace"}], [])

    def test_m1_run_instances_uses_launch_template_and_user_data(self) -> None:
        params = ec2_params(cfg())
        self.assertEqual(params["LaunchTemplate"]["LaunchTemplateId"], "lt-placeholder")
        script = base64.b64decode(params["UserData"])
        self.assertIn(b"overflow_watcher.supervisor", script)

    def test_m2_capacity_refusal_after_ambiguous_keeps_reservation(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        ec2.ambiguous = True
        config = cfg()
        month = month_key(NOW)
        self.assertEqual(launch_one(store, ec2, config, sample_job(), NOW), "ambiguous")
        held = store.get_accrued(month)
        self.assertEqual(len(store.list_open_reservations()), 1)
        ec2.ambiguous = False
        ec2.quota = True
        resolve_reservations(store, ec2, AlertLog(), NOW)
        self.assertEqual(len(store.list_open_reservations()), 1)
        self.assertEqual(store.get_accrued(month), held)

    def test_l1_list_tagged_ids_follows_next_token(self) -> None:
        class Pages:
            def __init__(self) -> None:
                self.tokens: list[str | None] = []

            def describe_instances(self, **kwargs):
                token = kwargs.get("NextToken")
                self.tokens.append(token)
                if token is None:
                    return {
                        "Reservations": [{"Instances": [{"InstanceId": "i-a"}]}],
                        "NextToken": "page-2",
                    }
                return {"Reservations": [{"Instances": [{"InstanceId": "i-b"}]}]}

        client = Pages()
        self.assertEqual(Ec2Views(client).list_tagged_ids(), ["i-a", "i-b"])
        self.assertEqual(client.tokens, [None, "page-2"])

    def test_l2_proc_read_error_is_not_no_worker(self) -> None:
        with patch("overflow_watcher.supervisor.os.listdir", side_effect=OSError("unread")):
            self.assertIsNone(_workers_alive(1))
        action = decide(
            Proof(False, None, 0, True, False, True, True),
            10,
            False,
        )
        self.assertEqual(action, KEEP)

    def test_l3_create_tags_is_not_unscoped(self) -> None:
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        create_at = template.index("ec2:CreateTags")
        window = template[create_at : create_at + 280]
        self.assertNotIn('Resource: "*"', window)
        self.assertIn("ec2:CreateAction: RunInstances", window)

    def test_l4_dynamodb_local_and_java_are_pinned(self) -> None:
        script = (ROOT / "scripts" / "run-tests.sh").read_text(encoding="utf-8")
        url_at = script.index("dynamodb_local_2025-07-15.tar.gz")
        sha_at = script.index("1125086301253b89539fa3bdbf1ded0656c596a2d34e0ca3c10af83373e7fd88")
        check_at = script.index("sha256sum -c -")
        self.assertLess(url_at, check_at)
        self.assertLess(sha_at, check_at)
        workflow = (ROOT.parents[1] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('openjdk_pin="21.0.12.""1+1-1~24.04.4"', workflow)
        self.assertIn('openjdk-21-jre-headless=${openjdk_pin}', workflow)
        pinned = "21.0.12." + "1+1-1~24.04.4"
        self.assertEqual(pinned, "21.0.12.1+1-1~24.04.4")

    def test_c4b_threshold_boundaries(self) -> None:
        self.assertTrue(admission_allows(2999, 1, 3000))
        self.assertFalse(admission_allows(3000, 1, 3000))
        self.assertFalse(admission_allows(3300, 1, 3000))
        for total, expects_budget in ((2999, False), (3000, False), (3001, True)):
            store = fresh_store()
            month = month_key(NOW)
            add_cents(store, month, total)
            result = run_poll(store, FakeEc2(), FakeEc2(), FakeGitHub(), cfg(), NOW)
            budget = [item for item in result.alerts.items if item.kind == "budget"]
            self.assertEqual(bool(budget), expects_budget, total)
            self.assertEqual([item for item in result.alerts.items if item.kind == "grace"], [], total)
        for total in (3299, 3300):
            store = fresh_store()
            ec2 = FakeEc2()
            github = FakeGitHub()
            month = month_key(NOW)
            seed_instance(
                store, ec2, instance_id="i-flat", debit=6, month=month, launch_epoch=NOW, run_id="1",
            )
            add_cents(store, month, total - store.get_accrued(month))
            result = run_poll(store, ec2, ec2, github, cfg(), NOW)
            self.assertEqual(github.cancel_calls, [], total)
            self.assertEqual(ec2.terminate_calls, [], total)
            self.assertEqual([item for item in result.alerts.items if item.kind == "grace"], [], total)
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-flat", debit=6, month=month, launch_epoch=NOW, run_id="1")
        add_cents(store, month, 3301 - store.get_accrued(month))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        grace = [item for item in result.alerts.items if item.kind == "grace"]
        self.assertEqual(len(grace), 1)
        self.assertEqual(grace[0].instance_ids, ())

    def test_partial_and_uncertain_stop(self) -> None:
        store = fresh_store()
        github = FakeGitHub()
        month = month_key(NOW)

        class Flip(FakeEc2):
            def describe_instances(self, ids: list[str]):
                if ids == ["i-b"]:
                    self.views["i-b"] = InstanceView("i-b", None, False, True)
                return super().describe_instances(ids)

        ec2 = Flip()
        seed_instance(
            store, ec2, instance_id="i-a", debit=600, month=month,
            launch_epoch=NOW - 3600, run_id="1", price_numer=1, price_denom=1,
        )
        seed_instance(
            store, ec2, instance_id="i-b", debit=600, month=month,
            launch_epoch=NOW - 3600, run_id="2", price_numer=1, price_denom=1,
        )
        add_cents(store, month, 3400 - store.get_accrued(month))
        github.decision = Decision(False, "queued", (sample_job(workflow_run_id="90"),))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([call[2] for call in github.cancel_calls], ["1"])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(result.launched, 0)
        self.assertEqual(result.blocked_reason, "unknown-inventory")
        self.assertTrue(result.budget.block_launch)
        self.assertTrue(any(item.instance_ids == ("i-b",) for item in result.alerts.items))

    def test_alert_emit_failure_leaves_a_retry_and_commits_after_success(self) -> None:
        store = fresh_store()
        month = month_key(NOW)
        add_cents(store, month, 3001)
        original = AlertLog.emit
        failed = {"budget": False}

        def flaky(self, alert):
            if alert.kind == "budget" and not failed["budget"]:
                failed["budget"] = True
                raise RuntimeError("log down")
            original(self, alert)

        config = cfg()
        with patch.object(AlertLog, "emit", flaky):
            run_poll(store, FakeEc2(), FakeEc2(), FakeGitHub(), config, NOW)
        self.assertIsNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET"))
        self.assertIsNotNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET#RETRY"))
        second = run_poll(store, FakeEc2(), FakeEc2(), FakeGitHub(), config, NOW)
        self.assertIsNotNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET"))
        self.assertEqual([item.kind for item in second.alerts.items if item.kind == "budget"], ["budget"])
        third = run_poll(store, FakeEc2(), FakeEc2(), FakeGitHub(), config, NOW)
        self.assertEqual([item for item in third.alerts.items if item.kind == "budget"], [])

    def test_unknown_ownership_blocks_new_launch(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-mystery", debit=6, month=month, launch_epoch=NOW,
            has_tag=False, tagged_list=False, run_id="1",
        )
        github.decision = Decision(False, "queued", (sample_job(),))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(result.launched, 0)
        self.assertEqual(result.blocked_reason, "unknown-inventory")
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertTrue(any(item.kind == "unknown-ownership" for item in result.alerts.items))

    def test_excluded_burn_stays_in_the_forecast_and_is_not_stopped(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-deploy", debit=600, month=month,
            launch_epoch=NOW - 3600, workflow="deploy-site", job_name="ship", run_id="3",
            price_numer=1, price_denom=1,
        )
        seed_instance(
            store, ec2, instance_id="i-ci", debit=600, month=month,
            launch_epoch=NOW - 1800, workflow="CI", job_name="test", run_id="4",
            price_numer=1, price_denom=1,
        )
        before = 3200
        add_cents(store, month, before - store.get_accrued(month))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([call[2] for call in github.cancel_calls], ["4"])
        self.assertNotIn("3", [call[2] for call in github.cancel_calls])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertGreaterEqual(store.get_accrued(month), before)
        self.assertEqual([item.instance_ids for item in result.alerts.items if item.kind == "grace"], [("i-ci",)])

    def test_irreducible_overspend_alerts_and_does_not_terminate(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-done", debit=6, month=month, launch_epoch=NOW, run_id="8",
        )
        seed_instance(
            store, ec2, instance_id="i-deploy", debit=6, month=month, launch_epoch=NOW,
            workflow="deploy-site", job_name="ship", run_id="9",
        )
        add_cents(store, month, 3400 - store.get_accrued(month))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(store.get_instance("i-done")["state"], "OPEN")
        self.assertEqual(store.get_instance("i-deploy")["state"], "OPEN")
        grace = [item for item in result.alerts.items if item.kind == "grace"]
        self.assertEqual(len(grace), 1)
        self.assertEqual(grace[0].instance_ids, ())
        self.assertGreaterEqual(store.get_accrued(month), 3400)


if __name__ == "__main__":
    unittest.main()
