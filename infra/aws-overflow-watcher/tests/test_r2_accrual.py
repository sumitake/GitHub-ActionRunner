# SPDX-License-Identifier: MPL-2.0
"""R2: positive deltas only, including the November DST boundary."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from support import fresh_store

from overflow_watcher.money import month_key, owed_cents, plan_accrual

UTC = timezone.utc
LAUNCH = int(datetime(2026, 11, 1, 0, 0, tzinfo=UTC).timestamp())
END = int(datetime(2026, 11, 1, 10, 0, tzinfo=UTC).timestamp())
BOUNDARY = int(datetime(2026, 11, 1, 7, 0, tzinfo=UTC).timestamp())
FOLD_START = int(datetime(2026, 11, 1, 8, 30, tzinfo=UTC).timestamp())
FOLD_END = int(datetime(2026, 11, 1, 9, 30, tzinfo=UTC).timestamp())


class AccrualTests(unittest.TestCase):
    def test_r2_duplicate_and_stale_add_zero(self) -> None:
        store = fresh_store()
        record = {
            "instanceId": "i-accrue",
            "clientToken": "tok-accrue",
            "allowanceCents": 600,
            "month": "2026-10",
            "createdEpoch": LAUNCH,
            "launchEpoch": LAUNCH,
            "watermarkEpoch": LAUNCH,
            "cumulativeDebitCents": 600,
            "debitByMonth": {"2026-10": 600},
            "state": "OPEN",
            "params": {},
            "owner": "example",
            "repoName": "keicrew",
            "installation": "201",
            "workflowName": "CI",
            "jobName": "test",
            "workflowRunId": "1",
            "labels": ["self-hosted", "Linux"],
            "priceNumer": 1,
            "priceDenom": 1,
        }
        store.client.put_item(TableName=store.table, Item=store._instance_item(record))
        store.client.update_item(
            TableName=store.table,
            Key={"pk": {"S": "MONTH#2026-10"}, "sk": {"S": "LEDGER"}},
            UpdateExpression="ADD accruedCents :cents",
            ExpressionAttributeValues={":cents": {"N": "600"}},
        )
        from overflow_watcher.budget import AlertLog
        from overflow_watcher.controller import accrue

        alerts = AlertLog()
        accrue(store, alerts, END)
        after = store.get_accrued("2026-10") + store.get_accrued("2026-11")
        accrue(store, alerts, END)
        duplicate = store.get_accrued("2026-10") + store.get_accrued("2026-11")
        accrue(store, alerts, END - 60)
        stale = store.get_accrued("2026-10") + store.get_accrued("2026-11")
        self.assertGreater(after, 600)
        self.assertEqual(duplicate, after)
        self.assertEqual(stale, after)

    def test_r2_obligation_carries_across_november_dst_boundary(self) -> None:
        self.assertEqual(month_key(BOUNDARY - 1), "2026-10")
        self.assertEqual(month_key(BOUNDARY), "2026-11")
        self.assertEqual(FOLD_END - FOLD_START, 3600)
        plan = plan_accrual(
            launch_epoch=LAUNCH,
            watermark=LAUNCH,
            cumulative=600,
            debit_by_month={"2026-10": 600},
            now=END,
            numer=1,
            denom=1,
        )
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.delta, 400)
        self.assertEqual(plan.month_deltas["2026-10"], 100)
        self.assertEqual(plan.month_deltas["2026-11"], 300)
        self.assertEqual(owed_cents(END - LAUNCH, 1, 1), 1000)
        fold = plan_accrual(
            launch_epoch=LAUNCH,
            watermark=FOLD_START,
            cumulative=owed_cents(FOLD_START - LAUNCH, 1, 1),
            debit_by_month={"2026-10": 700, "2026-11": 150},
            now=FOLD_END,
            numer=1,
            denom=1,
        )
        self.assertIsNotNone(fold)
        assert fold is not None
        self.assertEqual(fold.delta, 100)
        self.assertEqual(fold.month_deltas, {"2026-11": 100})


if __name__ == "__main__":
    unittest.main()
