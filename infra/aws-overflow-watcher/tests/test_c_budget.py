# SPDX-License-Identifier: MPL-2.0
"""C1-C4b: stop-new, grace stop, alerts, quota, and no runner-count gate."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from fakes import FakeEc2, FakeGitHub, FakeSsm
from support import NOW, add_cents, cfg, fresh_store, sample_job, seed_instance, watcher_env, clear_poll_lease

from overflow_watcher.config import load_config
from overflow_watcher.controller import launch_one, run_poll
from overflow_watcher.money import cost_cents, month_key
from overflow_watcher.types import Decision, InstanceView


def _over(store, month: str, target: int) -> None:
    current = store.get_accrued(month)
    if target != current:
        add_cents(store, month, target - current)


class BudgetTests(unittest.TestCase):
    def test_c1_stop_new_at_soft_cap(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        config = cfg()
        month = month_key(NOW)
        add_cents(store, month, 2994)
        github = FakeGitHub()
        ssm = FakeSsm()
        self.assertEqual(launch_one(store, ec2, config, sample_job(), NOW, github=github, ssm=ssm), "launched")
        self.assertEqual(store.get_accrued(month), 3000)
        self.assertEqual(
            launch_one(store, ec2, config, sample_job(workflow_run_id="78"), NOW, github=github, ssm=ssm),
            "cap",
        )
        self.assertEqual(len(store.list_open_instances()), 1)

    def test_c_active_between_cap_and_grace_is_not_terminated(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-live", debit=100, month=month, launch_epoch=NOW - 30)
        _over(store, month, 3100)
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(store.get_instance("i-live")["state"], "OPEN")
        self.assertEqual(result.launched, 0)

    def test_c3_soft_cap_alert_has_overage_and_cause_once(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        add_cents(store, month, 3001)
        config = cfg()
        first = run_poll(store, ec2, ec2, github, config, NOW)
        second = run_poll(store, ec2, ec2, github, config, NOW)
        alerts = [item for item in first.alerts.items if item.kind == "budget"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].audience, "john")
        self.assertEqual(alerts[0].overage_cents, 1)
        self.assertEqual(alerts[0].estimated_cents, 3001)
        self.assertIn("soft cap", alerts[0].cause)
        self.assertEqual([item for item in second.alerts.items if item.kind == "budget"], [])

    def test_c_budget_stop_does_not_fire_at_3299(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-under", debit=100, month=month, launch_epoch=NOW, run_id="9")
        _over(store, month, 3299)
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual([item for item in result.alerts.items if item.kind == "grace"], [])
        self.assertEqual(store.get_instance("i-under")["state"], "OPEN")

    def test_c_budget_stop_fires_at_threshold(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-hit", debit=200, month=month, launch_epoch=NOW - 10, run_id="9")
        _over(store, month, 3300)
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.cancel_calls, [("example", "keicrew", "9")])
        self.assertEqual(ec2.terminate_calls, [])
        stop = [item for item in result.alerts.items if item.kind == "grace"]
        self.assertEqual(len(stop), 1)
        self.assertIn("john", stop[0].audience)
        self.assertIn("ops", stop[0].audience)
        self.assertEqual(stop[0].overage_cents, 300)
        self.assertEqual(stop[0].instance_ids, ("i-hit",))
        self.assertIn("grace", stop[0].cause)

    def test_c_budget_stop_requires_record_and_tag(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-owned", debit=400, month=month, launch_epoch=NOW - 50, run_id="1")
        seed_instance(
            store,
            ec2,
            instance_id="i-record",
            debit=50,
            month=month,
            launch_epoch=NOW - 40,
            run_id="2",
            has_tag=False,
            tagged_list=False,
        )
        ec2.tagged.append("i-tagonly")
        _over(store, month, 3600)
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        acted = [call[2] for call in github.cancel_calls]
        self.assertEqual(acted, ["1"])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertTrue(any(item.kind == "unknown-tag" and "i-tagonly" in item.instance_ids for item in result.alerts.items))
        self.assertTrue(any(item.kind == "unknown-ownership" and "i-record" in item.instance_ids for item in result.alerts.items))
        self.assertFalse(store.has_instance("i-tagonly"))

    def test_c_budget_stop_skips_excluded_jobs(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store,
            ec2,
            instance_id="i-deploy",
            debit=400,
            month=month,
            launch_epoch=NOW - 20,
            workflow="deploy-site",
            job_name="migrate",
            run_id="3",
        )
        seed_instance(store, ec2, instance_id="i-ok", debit=400, month=month, launch_epoch=NOW - 10, run_id="4")
        _over(store, month, 3600)
        config = cfg(
            BUDGET_STOP_EXCLUSIONS=json.dumps(
                [{"kind": "workflow", "pattern": "deploy-*"}, {"kind": "job", "pattern": "migrate"}]
            )
        )
        result = run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual([call[2] for call in github.cancel_calls], ["4"])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertTrue(all("i-deploy" not in item.instance_ids or item.kind != "grace" for item in result.alerts.items))

    def test_c_budget_stop_cancels_before_terminate(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        github.cancel_error = "http-403"
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-wait", debit=400, month=month, launch_epoch=NOW - 15, run_id="8")
        _over(store, month, 3400)
        config = cfg()
        first = run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual(len(github.cancel_calls), 1)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(first.budget.cancelled, ("i-wait",))
        clear_poll_lease(store)
        early = run_poll(store, ec2, ec2, github, config, NOW + 119)
        self.assertEqual(len(github.cancel_calls), 1)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(early.budget.cancelled, ())
        clear_poll_lease(store)
        due = run_poll(store, ec2, ec2, github, config, NOW + 120)
        self.assertEqual(ec2.terminate_calls, [["i-wait"]])
        self.assertEqual(due.budget.terminated, ("i-wait",))
        clear_poll_lease(store)
        again = run_poll(store, ec2, ec2, github, config, NOW + 180)
        self.assertEqual(ec2.terminate_calls, [["i-wait"]])
        self.assertEqual(again.budget.terminated, ())
        # Closing the terminated instance replaces its 400-cent reservation with actual runtime.
        self.assertEqual(store.get_instance("i-wait")["state"], "CLOSED")
        self.assertEqual(store.get_accrued(month), 3400 - 400 + cost_cents(195, 1, 100))

    def test_c_budget_stop_minimum_set(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-soon", debit=600, month=month,
            launch_epoch=NOW - 5 * 3600, run_id="1", price_numer=1, price_denom=1,
        )
        seed_instance(
            store, ec2, instance_id="i-spent", debit=600, month=month,
            launch_epoch=NOW - 3600, run_id="2", price_numer=1, price_denom=1,
        )
        seed_instance(
            store, ec2, instance_id="i-other", debit=600, month=month,
            launch_epoch=NOW - 1800, run_id="3", price_numer=1, price_denom=1,
        )
        _over(store, month, 3000)
        before = store.get_accrued(month)
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([call[2] for call in github.cancel_calls], ["1"])
        self.assertEqual(store.get_accrued(month), before)
        self.assertEqual(store.get_instance("i-spent")["state"], "OPEN")
        self.assertEqual(store.get_instance("i-other")["state"], "OPEN")

    def test_c_budget_stop_accounting_persists(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store,
            ec2,
            instance_id="i-keep",
            debit=600,
            month=month,
            launch_epoch=NOW - 3600,
            run_id="6",
            price_numer=1,
            price_denom=1,
        )
        _over(store, month, 3400)
        before = store.get_accrued(month)
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(store.get_instance("i-keep")["state"], "OPEN")
        self.assertGreaterEqual(store.get_accrued(month), before)
        saved = store.get_instance("i-keep")
        self.assertEqual(saved["clientToken"], "tok-i-keep")

    def test_c_budget_stop_race_finished_during_wait(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-done", debit=400, month=month, launch_epoch=NOW - 12, run_id="11")
        _over(store, month, 3400)
        config = cfg()
        run_poll(store, ec2, ec2, github, config, NOW)
        github.completed.add("11")
        done = run_poll(store, ec2, ec2, github, config, NOW + 120)
        self.assertEqual(ec2.terminate_calls, [["i-done"]])
        self.assertEqual(done.budget.terminated, ("i-done",))
        self.assertEqual(store.get_instance("i-done")["state"], "OPEN")

    def test_c_budget_stop_ambiguous_describe_does_not_terminate(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-fuzzy", debit=400, month=month, launch_epoch=NOW - 12, run_id="12")
        _over(store, month, 3400)
        config = cfg()
        run_poll(store, ec2, ec2, github, config, NOW)
        ec2.views["i-fuzzy"] = InstanceView("i-fuzzy", None, False, True)
        result = run_poll(store, ec2, ec2, github, config, NOW + 120)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertTrue(any(item.instance_ids == ("i-fuzzy",) for item in result.alerts.items))
        self.assertEqual(store.get_instance("i-fuzzy")["state"], "OPEN")

    def test_c_budget_stop_duplicate_invocation_is_noop(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-once", debit=400, month=month, launch_epoch=NOW - 12, run_id="13")
        _over(store, month, 3400)
        config = cfg()
        run_poll(store, ec2, ec2, github, config, NOW)
        clear_poll_lease(store)
        second = run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual(len(github.cancel_calls), 1)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(second.budget.cancelled, ())
        self.assertEqual(second.budget.terminated, ())

    def test_c_no_runner_count_limit(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        config = cfg()
        github = FakeGitHub()
        ssm = FakeSsm()
        for index in range(25):
            job = sample_job(workflow_run_id=str(100 + index), job_id=str(1000 + index))
            outcome = launch_one(store, ec2, config, job, NOW, github=github, ssm=ssm)
            self.assertEqual(outcome, "launched", index)
        self.assertEqual(len(store.list_open_instances()), 25)
        root = Path(__file__).resolve().parents[1]
        source = "\n".join(path.read_text(encoding="utf-8") for path in (root / "src").rglob("*.py"))
        self.assertNotIn("MAX_RUNNERS", source)

    def test_c_quota_refusal_is_recorded_without_retry_storm(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        ec2.quota = True
        github = FakeGitHub()
        github.decision = Decision(False, "no-matching-capacity", (sample_job(),))
        config = cfg()
        ssm = FakeSsm()
        first = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(len(ec2.calls), 1)
        token = ec2.calls[0]
        second = run_poll(store, ec2, ec2, github, config, NOW + 1, ssm=ssm)
        self.assertEqual(ec2.calls, [token])
        self.assertEqual(first.quota_failures, 1)
        self.assertEqual(second.quota_failures, 0)
        self.assertEqual(store.failure_count(), 1)
        self.assertEqual(store.list_open_reservations(), [])
        self.assertEqual(ec2.terminate_calls, [])

    def test_c_unset_grace_knob_does_not_launch(self) -> None:
        env = watcher_env()
        del env["CONTINUE_ACTIVE_UNTIL_CENTS"]
        loaded = load_config(env)
        self.assertFalse(loaded.ok)
        store = fresh_store()
        ec2 = FakeEc2()
        result = run_poll(store, ec2, ec2, FakeGitHub(), loaded, NOW)
        self.assertEqual(result.launched, 0)
        self.assertEqual(ec2.terminate_calls, [])


if __name__ == "__main__":
    unittest.main()
