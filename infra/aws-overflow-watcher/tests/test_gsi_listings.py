# SPDX-License-Identifier: MPL-2.0
"""GSI listings: Query instead of table Scan, open range only."""

from __future__ import annotations

import json
import unittest

from botocore.exceptions import ClientError
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




class _PagedScan:
    """Return scripted Scan pages and record each call's kwargs."""

    def __init__(self, inner, pages: list[dict]) -> None:
        self._inner = inner
        self._pages = list(pages)
        self.scan_kwargs: list[dict] = []

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def scan(self, **kwargs):
        self.scan_kwargs.append(dict(kwargs))
        if len(self.scan_kwargs) > len(self._pages):
            raise AssertionError("unexpected extra scan")
        return self._pages[len(self.scan_kwargs) - 1]


class _FailSecondUpdate:
    """Pass the first update_item through, then raise InternalServerError."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.update_keys: list[dict] = []

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def update_item(self, **kwargs):
        key = kwargs["Key"]
        self.update_keys.append(key)
        if len(self.update_keys) >= 2:
            raise ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "InternalServerError"}},
                "UpdateItem",
            )
        return self._inner.update_item(**kwargs)


def _unkeyed_instance_item(store, instance_id: str, *, top_state: str, json_state: str) -> dict:
    month = month_key(NOW)
    record = {
        "instanceId": instance_id,
        "clientToken": f"tok-{instance_id}",
        "allowanceCents": 1,
        "month": month,
        "createdEpoch": NOW,
        "launchEpoch": NOW,
        "watermarkEpoch": NOW,
        "cumulativeDebitCents": 1,
        "debitByMonth": {month: 1},
        "state": json_state,
        "params": {"ImageId": "ami-placeholder"},
        "repoId": "101",
        "jobId": "55",
        "priceNumer": 1,
        "priceDenom": 100,
    }
    return {
        "pk": {"S": f"INST#{instance_id}"},
        "sk": {"S": "META"},
        "state": {"S": top_state},
        "watermarkEpoch": {"N": str(NOW)},
        "cumulativeDebitCents": {"N": "1"},
        "debitByMonth": {"S": json.dumps({month: 1}, sort_keys=True)},
        "record": {"S": json.dumps(record, sort_keys=True)},
    }


def _get(store, pk: str, sk: str) -> dict:
    return store.client.get_item(
        TableName=store.table,
        Key={"pk": {"S": pk}, "sk": {"S": sk}},
        ConsistentRead=True,
    )["Item"]


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
        # Eight queries from the rest of the poll, plus the idle reaper's open-instance list.
        self.assertEqual(recorder.calls.count("query"), 9)
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


    def test_backfill_follows_scan_pagination(self) -> None:
        store = fresh_store()
        first = _unkeyed_instance_item(store, "i-page1", top_state="CLOSED", json_state="OPEN")
        second = _unkeyed_instance_item(store, "i-page2", top_state="CLOSED", json_state="OPEN")
        store.client.put_item(TableName=store.table, Item=first)
        store.client.put_item(TableName=store.table, Item=second)
        start_key = {"pk": {"S": "INST#i-page1"}, "sk": {"S": "META"}}
        pager = _PagedScan(
            store.client,
            [
                {"Items": [first], "LastEvaluatedKey": start_key},
                {"Items": [second]},
            ],
        )
        store.client = pager
        store.maybe_backfill_gsi()
        self.assertEqual(len(pager.scan_kwargs), 2)
        self.assertEqual(pager.scan_kwargs[1].get("ExclusiveStartKey"), start_key)
        one = _get(store, "INST#i-page1", "META")
        two = _get(store, "INST#i-page2", "META")
        self.assertEqual(one["gsiPk"]["S"], "INST")
        self.assertEqual(one["gsiSk"]["S"], "CLOSED#i-page1")
        self.assertEqual(two["gsiPk"]["S"], "INST")
        self.assertEqual(two["gsiSk"]["S"], "CLOSED#i-page2")
        self.assertIsNotNone(store.get_marker("BACKFILL#gsi-v1", "META"))

    def test_backfill_keys_open_rows_from_the_attribute(self) -> None:
        store = fresh_store()
        store.client.put_item(
            TableName=store.table,
            Item=_unkeyed_instance_item(store, "i-open-legacy", top_state="OPEN", json_state="CLOSED"),
        )
        store.client.put_item(
            TableName=store.table,
            Item={
                "pk": {"S": "INST#i-open-legacy"},
                "sk": {"S": "ALERT#ALLOWANCE"},
                "kind": {"S": "past-allowance"},
            },
        )
        store.maybe_backfill_gsi()
        opened = store.list_open_instances()
        self.assertEqual([item["instanceId"] for item in opened], ["i-open-legacy"])
        item = _get(store, "INST#i-open-legacy", "META")
        self.assertEqual(item["gsiPk"]["S"], "INST")
        self.assertEqual(item["gsiSk"]["S"], "OPEN#i-open-legacy")
        alert = _get(store, "INST#i-open-legacy", "ALERT#ALLOWANCE")
        self.assertNotIn("gsiPk", alert)
        self.assertIsNotNone(store.get_marker("BACKFILL#gsi-v1", "META"))

    def test_backfill_failure_midway_leaves_the_marker_unset_and_resumes(self) -> None:
        store = fresh_store()
        store.client.put_item(
            TableName=store.table,
            Item=_unkeyed_instance_item(store, "i-first", top_state="CLOSED", json_state="OPEN"),
        )
        store.client.put_item(
            TableName=store.table,
            Item=_unkeyed_instance_item(store, "i-second", top_state="CLOSED", json_state="OPEN"),
        )
        inner = store.client
        wrapper = _FailSecondUpdate(inner)
        store.client = wrapper
        with self.assertRaises(ClientError) as raised:
            store.maybe_backfill_gsi()
        self.assertEqual(raised.exception.response["Error"]["Code"], "InternalServerError")
        self.assertEqual(len(wrapper.update_keys), 2)
        written = wrapper.update_keys[0]
        failed = wrapper.update_keys[1]
        store.client = inner
        written_item = store.client.get_item(
            TableName=store.table, Key=written, ConsistentRead=True
        )["Item"]
        failed_item = store.client.get_item(
            TableName=store.table, Key=failed, ConsistentRead=True
        )["Item"]
        self.assertEqual(written_item["gsiPk"]["S"], "INST")
        self.assertNotIn("gsiPk", failed_item)
        self.assertIsNone(store.get_marker("BACKFILL#gsi-v1", "META"))
        store.maybe_backfill_gsi()
        resumed = store.client.get_item(
            TableName=store.table, Key=failed, ConsistentRead=True
        )["Item"]
        self.assertEqual(resumed["gsiPk"]["S"], "INST")
        self.assertIsNotNone(store.get_marker("BACKFILL#gsi-v1", "META"))


if __name__ == "__main__":
    unittest.main()
