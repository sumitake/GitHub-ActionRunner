# SPDX-License-Identifier: MPL-2.0
"""F7 negatives (a) through (g)."""

from __future__ import annotations

import unittest

from fakes import FakeEc2, FakeGitHub, FakeSsm
from support import NOW, add_cents, cfg, fresh_store, sample_job, seed_instance

from overflow_watcher.budget import AlertLog
from overflow_watcher.controller import (
    _record_for,
    accrue,
    launch_one,
    reconcile,
    resolve_reservations,
    run_poll,
)
from overflow_watcher.money import month_key
from overflow_watcher.supervisor import KEEP, Proof, apply_decision, decide
from overflow_watcher.types import RETRY_WINDOW_SECONDS, Decision


class NegativeTests(unittest.TestCase):
    def test_f7a_missing_runner_config_does_not_remove_or_terminate(self) -> None:
        shutdown: list[str] = []
        reports: list[str] = []
        action = decide(
            Proof(False, False, None, False, False, False, False),
            10,
            False,
        )
        apply_decision(action, shutdown, reports)
        self.assertEqual(action, KEEP)
        self.assertEqual(shutdown, [])
        self.assertEqual(reports, [])

    def test_f7b_empty_runner_lookup_does_not_terminate_or_release(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        config = cfg()
        month = month_key(NOW)
        record = _record_for(sample_job(), config, "tok-hold", NOW - RETRY_WINDOW_SECONDS - 10, month)
        self.assertTrue(
            store.reserve(token="tok-hold", allowance=config.allowance, month=month, cap=3000, record=record)
        )
        github.decision = Decision(False, "no-matching-capacity", ())
        result = run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual(result.launched, 0)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertIsNotNone(store.get_reservation("tok-hold"))
        self.assertEqual(store.get_accrued(month), config.allowance)
        ec2.index = 0
        reconcile(store, ec2, index_count=0)
        self.assertIsNotNone(store.get_reservation("tok-hold"))

    def test_f7c_job_assigned_while_idle_keeps_running(self) -> None:
        action = decide(
            Proof(True, False, None, False, False, True, True),
            10,
            False,
        )
        self.assertEqual(action, KEEP)

    def test_f7d_runner_still_running_after_job_no_shutdown(self) -> None:
        action = decide(
            Proof(False, True, 0, True, False, True, True),
            10,
            False,
        )
        self.assertEqual(action, KEEP)

    def test_f7e_crash_before_transaction_retries_same_client_token_once(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        config = cfg()
        month = month_key(NOW)
        record = _record_for(sample_job(), config, "tok-crash", NOW, month)
        record["jitReady"] = True
        self.assertTrue(
            store.reserve(token="tok-crash", allowance=config.allowance, month=month, cap=3000, record=record)
        )
        ec2.by_token["tok-crash"] = "i-existing"
        held = store.get_accrued(month)
        github = FakeGitHub()
        resolve_reservations(store, ec2, AlertLog(), NOW, github=github, ssm=FakeSsm())
        self.assertEqual(github.mint_calls, [])
        self.assertEqual(ec2.calls, ["tok-crash"])
        self.assertEqual(ec2.by_token, {"tok-crash": "i-existing"})
        self.assertIsNone(store.get_reservation("tok-crash"))
        saved = store.get_instance("i-existing")
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved["state"], "OPEN")
        self.assertEqual(store.get_accrued(month), held)
        self.assertEqual(len(store.list_open_instances()), 1)

    def test_f7f_invisible_instance_still_counts(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        month = month_key(NOW)
        seed_instance(
            store,
            ec2,
            instance_id="i-hidden",
            debit=80,
            month=month,
            launch_epoch=NOW - 60,
            uncertain=True,
            state=None,
            has_tag=False,
            tagged_list=False,
        )
        reconcile(store, ec2, index_count=0)
        saved = store.get_instance("i-hidden")
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved["state"], "OPEN")
        self.assertEqual(store.get_accrued(month), 80)
        self.assertEqual(ec2.terminate_calls, [])

    def test_f7g_past_allowance_accrues_blocks_launch_does_not_stop_job(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        launch = NOW - 7 * 3600
        seed_instance(
            store,
            ec2,
            instance_id="i-long",
            debit=6,
            month=month,
            launch_epoch=launch,
            price_numer=1,
            price_denom=100,
        )
        add_cents(store, month, 2994)
        self.assertEqual(store.get_accrued(month), 3000)
        alerts = AlertLog()
        accrue(store, alerts, NOW)
        self.assertEqual(store.get_accrued(month), 3001)
        self.assertTrue(any(item.kind == "past-allowance" for item in alerts.items))
        saved = store.get_instance("i-long")
        assert saved is not None
        self.assertEqual(saved["state"], "OPEN")
        outcome = launch_one(store, ec2, cfg(), sample_job(), NOW)
        self.assertEqual(outcome, "cap")
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(result.launched, 0)
        self.assertTrue(any(item.kind == "budget" for item in result.alerts.items))


if __name__ == "__main__":
    unittest.main()
