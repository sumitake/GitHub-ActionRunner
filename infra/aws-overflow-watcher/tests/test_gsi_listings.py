# SPDX-License-Identifier: MPL-2.0
"""GSI listings: Query instead of table Scan, open range only."""

from __future__ import annotations

import json
import unittest

from fakes import FakeEc2, FakeGitHub, FakeSsm
from support import NOW, cfg, clear_poll_lease, fresh_store, seed_instance
from test_poll_lease import RecordingClient

from overflow_watcher.controller import run_poll
from overflow_watcher.money import month_key
from overflow_watcher.types import Decision

THREE_REPOS = json.dumps(
    [
        {"id": "101", "owner": "example", "name": "keicrew", "installation": "201"},
        {"id": "102", "owner": "example", "name": "Contextual-Conversation-Gateway", "installation": "201"},
        {"id": "103", "owner": "example", "name": "agent-collab-workspace", "installation": "201"},
    ]
)


def _three_repo_cfg():
    return cfg(WATCHED_REPOS=THREE_REPOS)


def _idle_github() -> FakeGitHub:
    github = FakeGitHub()
    github.decision = Decision(False, "assessed", (), ())
    return github


def _write_marker(store) -> None:
    store.client.put_item(
        TableName=store.table,
        Item={"pk": {"S": "BACKFILL#gsi-v1"}, "sk": {"S": "META"}},
    )


def _closed_record(instance_id: str, repo_id: str = "101", job_id: str = "7") -> dict:
    month = month_key(NOW)
    return {
        "instanceId": instance_id,
        "clientToken": f"tok-{instance_id}",
        "allowanceCents": 1,
        "month": month,
        "createdEpoch": NOW,
        "launchEpoch": NOW,
        "watermarkEpoch": NOW,
        "cumulativeDebitCents": 1,
        "debitByMonth": {month: 1},
        "state": "CLOSED",
        "params": {"ImageId": "ami-placeholder"},
        "owner": "example",
        "repoName": "keicrew",
        "installation": "201",
        "workflowName": "CI",
        "jobName": "test",
        "workflowRunId": "77",
        "labels": ["self-hosted", "Linux"],
        "priceNumer": 1,
        "priceDenom": 100,
        "repoId": repo_id,
        "jobId": job_id,
    }


class GsiListingTests(unittest.TestCase):
    def test_ensure_table_creates_gsi(self) -> None:
        store = fresh_store()
        described = store.client.describe_table(TableName=store.table)["Table"]
        names = [index["IndexName"] for index in described.get("GlobalSecondaryIndexes", [])]
        self.assertIn("gsiPk-index", names)

    def test_list_open_instances_ignores_closed_history(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        month = month_key(NOW)
        for index in range(8):
            store.client.put_item(
                TableName=store.table,
                Item=store._instance_item(_closed_record(f"i-closed{index}")),
            )
        seed_instance(
            store,
            ec2,
            instance_id="i-open",
            debit=1,
            month=month,
            launch_epoch=NOW,
        )
        opened = store.list_open_instances()
        self.assertEqual([item["instanceId"] for item in opened], ["i-open"])

    def test_close_instance_moves_gsi_sk_to_closed(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        month = month_key(NOW)
        record = _closed_record("i-live")
        record["state"] = "OPEN"
        record["repoId"] = "101"
        record["jobId"] = "9"
        seed_instance(
            store,
            ec2,
            instance_id="i-live",
            debit=1,
            month=month,
            launch_epoch=NOW,
        )
        # overwrite with repo/job so instances_returned can count
        record["state"] = "OPEN"
        store.client.put_item(TableName=store.table, Item=store._instance_item(record))
        self.assertTrue(store.close_instance("i-live", NOW))
        self.assertEqual(store.list_open_instances(), [])
        item = store.client.get_item(
            TableName=store.table,
            Key={"pk": {"S": "INST#i-live"}, "sk": {"S": "META"}},
            ConsistentRead=True,
        )["Item"]
        self.assertEqual(item["gsiSk"]["S"], "CLOSED#i-live")
        self.assertEqual(store.instances_returned("101", "9"), 1)

    def test_idle_poll_and_listings_do_not_scan(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        month = month_key(NOW)
        for index in range(6):
            store.client.put_item(
                TableName=store.table,
                Item=store._instance_item(_closed_record(f"i-old{index}", job_id=str(20 + index))),
            )
        seed_instance(
            store,
            ec2,
            instance_id="i-open",
            debit=1,
            month=month,
            launch_epoch=NOW,
        )
        _write_marker(store)
        recorder = RecordingClient(store.client)
        store.client = recorder
        result = run_poll(store, ec2, ec2, _idle_github(), _three_repo_cfg(), NOW, ssm=FakeSsm())
        self.assertNotEqual(result.blocked_reason, "poll-lease-held")
        self.assertNotIn("scan", recorder.calls)
        self.assertEqual(recorder.calls.count("query"), 8)
        self.assertEqual([item["instanceId"] for item in store.list_open_instances()], ["i-open"])

    def test_backfill_keys_closed_rows_from_the_attribute(self) -> None:
        store = fresh_store()
        month = month_key(NOW)
        record = {
            "instanceId": "i-legacy",
            "clientToken": "tok-i-legacy",
            "allowanceCents": 1,
            "month": month,
            "createdEpoch": NOW,
            "launchEpoch": NOW,
            "watermarkEpoch": NOW,
            "cumulativeDebitCents": 1,
            "debitByMonth": {month: 1},
            "state": "OPEN",
            "params": {"ImageId": "ami-placeholder"},
            "repoId": "101",
            "jobId": "55",
            "priceNumer": 1,
            "priceDenom": 100,
        }
        store.client.put_item(
            TableName=store.table,
            Item={
                "pk": {"S": "INST#i-legacy"},
                "sk": {"S": "META"},
                "state": {"S": "CLOSED"},
                "watermarkEpoch": {"N": str(NOW)},
                "cumulativeDebitCents": {"N": "1"},
                "debitByMonth": {"S": json.dumps({month: 1}, sort_keys=True)},
                "record": {"S": json.dumps(record, sort_keys=True)},
            },
        )
        store.client.put_item(
            TableName=store.table,
            Item={
                "pk": {"S": "INST#i-legacy"},
                "sk": {"S": "ALERT#ALLOWANCE"},
                "kind": {"S": "past-allowance"},
            },
        )
        store.client.put_item(
            TableName=store.table,
            Item={
                "pk": {"S": "RES#tok-open"},
                "sk": {"S": "ALERT#RETRY"},
                "kind": {"S": "retry-held"},
            },
        )
        recorder = RecordingClient(store.client)
        store.client = recorder
        result = run_poll(store, FakeEc2(), FakeEc2(), _idle_github(), _three_repo_cfg(), NOW, ssm=FakeSsm())
        self.assertNotEqual(result.blocked_reason, "poll-lease-held")
        self.assertEqual(store.list_open_instances(), [])
        self.assertEqual(store.instances_returned("101", "55"), 1)
        legacy = store.client.get_item(
            TableName=store.table,
            Key={"pk": {"S": "INST#i-legacy"}, "sk": {"S": "META"}},
            ConsistentRead=True,
        )["Item"]
        self.assertEqual(legacy["gsiPk"]["S"], "INST")
        self.assertEqual(legacy["gsiSk"]["S"], "CLOSED#i-legacy")
        alert = store.client.get_item(
            TableName=store.table,
            Key={"pk": {"S": "INST#i-legacy"}, "sk": {"S": "ALERT#ALLOWANCE"}},
            ConsistentRead=True,
        )["Item"]
        self.assertNotIn("gsiPk", alert)
        retry = store.client.get_item(
            TableName=store.table,
            Key={"pk": {"S": "RES#tok-open"}, "sk": {"S": "ALERT#RETRY"}},
            ConsistentRead=True,
        )["Item"]
        self.assertNotIn("gsiPk", retry)
        self.assertIsNotNone(store.get_marker("BACKFILL#gsi-v1", "META"))
        first_scans = recorder.calls.count("scan")
        self.assertGreaterEqual(first_scans, 1)
        recorder.calls.clear()
        clear_poll_lease(store)
        second = run_poll(store, FakeEc2(), FakeEc2(), _idle_github(), _three_repo_cfg(), NOW + 60, ssm=FakeSsm())
        self.assertNotEqual(second.blocked_reason, "poll-lease-held")
        self.assertNotIn("scan", recorder.calls)


if __name__ == "__main__":
    unittest.main()
