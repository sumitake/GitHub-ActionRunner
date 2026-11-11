# SPDX-License-Identifier: MPL-2.0
"""The admission allowance is a reservation, trued up to actual runtime at close."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from fakes import FakeEc2, FakeGitHub, FakeSsm
from support import NOW, add_cents, cfg, fresh_store, sample_job, seed_instance

from overflow_watcher.controller import accrue, reconcile, run_poll
from overflow_watcher.budget import AlertLog
from overflow_watcher.money import actual_by_month, allowance_cents, cost_cents, month_key
from overflow_watcher.types import Decision, InstanceView

JIT_FIXTURE = "zz-jit-fixture-true-up-4d2e-zz"


def _terminate(ec2: FakeEc2, instance_id: str) -> None:
    ec2.views[instance_id] = InstanceView(instance_id, "terminated", True, False)


class TrueUpTests(unittest.TestCase):
    def test_short_run_releases_the_reservation_and_charges_actual_hours(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        job = sample_job()
        github.decision = Decision(False, "assessed", (job,), (job.job_id,))
        github.mint_secret = JIT_FIXTURE
        config = cfg()
        month = month_key(NOW)
        result = run_poll(store, ec2, ec2, github, config, NOW, ssm=FakeSsm())
        self.assertEqual(result.launched, 1)
        self.assertEqual(store.get_accrued(month), config.allowance)
        instance_id = store.list_open_instances()[0]["instanceId"]
        numer, denom = config.price_numer, config.price_denom
        _terminate(ec2, instance_id)
        end = NOW + 1800
        accrue(store, AlertLog(), end)
        reconcile(store, ec2, index_count=0, now=end)
        actual = cost_cents(1800, numer, denom)
        # Fails if the true-up is skipped: the ledger would still hold the 6 h allowance.
        self.assertLess(actual, config.allowance)
        self.assertEqual(store.get_accrued(month), actual)
        saved = store.get_instance(instance_id)
        self.assertEqual(saved["state"], "CLOSED")
        self.assertEqual(saved["cumulativeDebitCents"], actual)
        self.assertEqual(saved["debitByMonth"], {month: actual})
        # A second close or poll does not move the ledger again.
        self.assertFalse(store.close_instance(instance_id, end + 600))
        reconcile(store, ec2, index_count=0, now=end + 600)
        self.assertEqual(store.get_accrued(month), actual)

    def test_long_run_across_a_month_boundary_charges_actual_per_month(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        launch = int(datetime(2026, 12, 1, 5, 0, tzinfo=timezone.utc).timestamp())  # Nov 30 21:00 PT
        end = launch + 8 * 3600
        nov, dec = month_key(launch), month_key(end)
        self.assertNotEqual(nov, dec)
        allowance = allowance_cents(22383, 100000)
        seed_instance(
            store,
            ec2,
            instance_id="i-long",
            debit=allowance,
            month=nov,
            launch_epoch=launch,
            price_numer=22383,
            price_denom=100000,
        )
        accrue(store, AlertLog(), launch + 7 * 3600)
        _terminate(ec2, "i-long")
        reconcile(store, ec2, index_count=0, now=end)
        expected = actual_by_month(launch, end, 22383, 100000)
        self.assertEqual(set(expected), {nov, dec})
        # Nov 30 21:00 PT to midnight is 3 h; the rest lands in December.
        self.assertEqual(expected[nov], cost_cents(3 * 3600, 22383, 100000))
        self.assertEqual(store.get_accrued(nov), expected[nov])
        self.assertEqual(store.get_accrued(dec), expected[dec])
        self.assertEqual(sum(expected.values()), cost_cents(8 * 3600, 22383, 100000))

    def test_refund_below_zero_cancels_and_keeps_the_debit(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-odd", debit=500, month=month, launch_epoch=NOW)
        add_cents(store, month, -400)
        _terminate(ec2, "i-odd")
        reconcile(store, ec2, index_count=0, now=NOW + 60)
        self.assertEqual(store.get_accrued(month), 100)
        self.assertEqual(store.get_instance("i-odd")["state"], "OPEN")

    def test_stale_watermark_does_not_close(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-race", debit=135, month=month, launch_epoch=NOW)
        saved = store.get_instance("i-race")
        store.client.update_item(
            TableName=store.table,
            Key={"pk": {"S": "INST#i-race"}, "sk": {"S": "META"}},
            UpdateExpression="SET watermarkEpoch = :w",
            ExpressionAttributeValues={":w": {"N": str(saved["watermarkEpoch"] + 5)}},
        )
        original = store.get_instance
        store.get_instance = lambda _id: saved  # read before the concurrent accrual
        try:
            self.assertFalse(store.close_instance("i-race", NOW + 60))
        finally:
            store.get_instance = original
        self.assertEqual(store.get_accrued(month), 135)
        self.assertEqual(store.get_instance("i-race")["state"], "OPEN")


if __name__ == "__main__":
    unittest.main()
