# SPDX-License-Identifier: MPL-2.0
"""F7 real-store checks against DynamoDB Local."""

from __future__ import annotations

import unittest

from fakes import FakeEc2, FakeGitHub
from support import NOW, cfg, fresh_store, sample_job

from overflow_watcher.controller import _record_for, resolve_reservations
from overflow_watcher.money import month_key


class RealStoreTests(unittest.TestCase):
    def test_f7_conditional_debit(self) -> None:
        store = fresh_store()
        config = cfg()
        month = month_key(NOW)
        record = _record_for(sample_job(), config, "tok-a", NOW, month)
        self.assertTrue(
            store.reserve(token="tok-a", allowance=100, month=month, cap=150, record=record)
        )
        second = dict(record)
        second["clientToken"] = "tok-b"
        self.assertFalse(
            store.reserve(token="tok-b", allowance=100, month=month, cap=150, record=second)
        )
        self.assertEqual(store.get_accrued(month), 100)
        self.assertIsNotNone(store.get_reservation("tok-a"))
        self.assertIsNone(store.get_reservation("tok-b"))

    def test_f7_reservation_to_instance_transaction(self) -> None:
        store = fresh_store()
        config = cfg()
        month = month_key(NOW)
        record = _record_for(sample_job(), config, "tok-tx", NOW, month)
        self.assertTrue(
            store.reserve(token="tok-tx", allowance=config.allowance, month=month, cap=3000, record=record)
        )
        before = store.get_accrued(month)
        conflicting = dict(record)
        conflicting.update(
            {
                "instanceId": "i-conflict",
                "state": "OPEN",
                "launchEpoch": NOW,
                "watermarkEpoch": NOW,
                "cumulativeDebitCents": config.allowance,
                "debitByMonth": {month: config.allowance},
            }
        )
        store.client.put_item(TableName=store.table, Item=store._instance_item(conflicting))
        with self.assertRaises(Exception):
            store.convert_reservation("tok-tx", "i-conflict", NOW)
        self.assertIsNotNone(store.get_reservation("tok-tx"))
        self.assertEqual(store.get_accrued(month), before)
        store.client.delete_item(
            TableName=store.table,
            Key={"pk": {"S": "INST#i-conflict"}, "sk": {"S": "META"}},
        )
        store.convert_reservation("tok-tx", "i-real", NOW)
        self.assertIsNone(store.get_reservation("tok-tx"))
        saved = store.get_instance("i-real")
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved["clientToken"], "tok-tx")
        self.assertEqual(saved["state"], "OPEN")
        self.assertEqual(store.get_accrued(month), before)

    def test_f7_dst_month_key(self) -> None:
        from datetime import datetime, timezone

        from overflow_watcher.controller import accrue
        from overflow_watcher.money import month_key as key

        utc = timezone.utc
        launch = int(datetime(2026, 11, 1, 0, 0, tzinfo=utc).timestamp())
        end = int(datetime(2026, 11, 1, 10, 0, tzinfo=utc).timestamp())
        boundary = int(datetime(2026, 11, 1, 7, 0, tzinfo=utc).timestamp())
        self.assertEqual(key(boundary - 1), "2026-10")
        self.assertEqual(key(boundary), "2026-11")
        store = fresh_store()
        record = {
            "instanceId": "i-dst",
            "clientToken": "tok-dst",
            "allowanceCents": 600,
            "month": "2026-10",
            "createdEpoch": launch,
            "launchEpoch": launch,
            "watermarkEpoch": launch,
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

        accrue(store, AlertLog(), end)
        self.assertEqual(store.get_accrued("2026-10"), 700)
        self.assertEqual(store.get_accrued("2026-11"), 300)
        saved = store.get_instance("i-dst")
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved["state"], "OPEN")
        self.assertEqual(saved["cumulativeDebitCents"], 1000)


if __name__ == "__main__":
    unittest.main()
