# SPDX-License-Identifier: MPL-2.0
"""R1: a reservation stays held through conversion and through an unresolved launch."""

from __future__ import annotations

import unittest

from fakes import FakeEc2, FakeGitHub, FakeSsm
from support import NOW, cfg, fresh_store, sample_job

from overflow_watcher.budget import AlertLog
from overflow_watcher.controller import launch_one, reconcile, resolve_reservations
from overflow_watcher.money import month_key


class ReservationHoldTests(unittest.TestCase):
    def test_r1_slot_held_through_reservation_and_instance(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        config = cfg()
        month = month_key(NOW)
        outcome = launch_one(store, ec2, config, sample_job(), NOW, github=FakeGitHub(), ssm=FakeSsm())
        self.assertEqual(outcome, "launched")
        self.assertEqual(store.list_open_reservations(), [])
        instances = store.list_open_instances()
        self.assertEqual(len(instances), 1)
        self.assertEqual(store.get_accrued(month), config.allowance)
        self.assertEqual(instances[0]["clientToken"], ec2.calls[0])

    def test_r1_unresolved_run_stays_reserved_despite_empty_ec2_and_index(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        ec2.ambiguous = True
        github = FakeGitHub()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        outcome = launch_one(store, ec2, config, sample_job(), NOW, github=github, ssm=ssm)
        self.assertEqual(outcome, "ambiguous")
        held = store.get_accrued(month)
        self.assertEqual(len(store.list_open_reservations()), 1)
        self.assertEqual(store.list_open_instances(), [])
        ec2.index = 0
        ec2.views.clear()
        reconcile(store, ec2, index_count=0, now=NOW)
        self.assertEqual(len(store.list_open_reservations()), 1)
        self.assertEqual(store.get_accrued(month), held)
        token = ec2.calls[0]
        ec2.ambiguous = False
        resolve_reservations(store, ec2, AlertLog(), NOW, github=github, ssm=ssm)
        self.assertEqual(ec2.calls, [token, token])
        self.assertEqual(list(ec2.by_token), [token])
        self.assertEqual(store.list_open_reservations(), [])
        self.assertEqual(len(store.list_open_instances()), 1)
        self.assertEqual(store.get_accrued(month), held)


if __name__ == "__main__":
    unittest.main()
