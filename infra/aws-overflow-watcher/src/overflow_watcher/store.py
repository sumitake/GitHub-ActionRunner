# SPDX-License-Identifier: MPL-2.0
"""DynamoDB state for reservations, instances, and the month ledger."""

from __future__ import annotations

import json
import re
from typing import Any

import boto3
from botocore.exceptions import ClientError

from overflow_watcher.money import AccrualPlan, actual_by_month

_DIGITS = re.compile(r"[0-9]+\Z")


class StoreError(RuntimeError):
    """A store read or write could not be completed."""


def _s(value: str) -> dict[str, str]:
    return {"S": value}


def _n(value: int) -> dict[str, str]:
    return {"N": str(int(value))}


def _key(pk: str, sk: str) -> dict[str, dict[str, str]]:
    return {"pk": _s(pk), "sk": _s(sk)}


class Store:
    def __init__(self, client: Any, table: str) -> None:
        self.client = client
        self.table = table

    @classmethod
    def connect(cls, *, table: str, endpoint_url: str | None) -> "Store":
        kwargs: dict[str, str] = {"region_name": "us-west-2"}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
            kwargs["aws_access_key_id"] = "local"
            kwargs["aws_secret_access_key"] = "local"
        client = boto3.client("dynamodb", **kwargs)
        store = cls(client, table)
        store.ensure_table()
        return store

    def ensure_table(self) -> None:
        try:
            self.client.describe_table(TableName=self.table)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        self.client.create_table(
            TableName=self.table,
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

    def get_accrued(self, month: str) -> int:
        item = self._get(f"MONTH#{month}", "LEDGER")
        if item is None:
            return 0
        return int(item["accruedCents"]["N"])

    def reserve(
        self,
        *,
        token: str,
        allowance: int,
        month: str,
        cap: int,
        record: dict[str, Any],
        job_lock: dict[str, Any] | None = None,
    ) -> bool | str:
        """Debit the allowance and write the reservation, or write neither.

        Without a job lock the return is a bool, for callers that never launch.
        With a job lock the return is ``ok``, ``duplicate``, or ``cap``.
        """
        if allowance <= 0 or allowance > cap:
            return False
        item = {
            "pk": _s(f"RES#{token}"),
            "sk": _s("META"),
            "state": _s("OPEN"),
            "clientToken": _s(token),
            "allowanceCents": _n(allowance),
            "month": _s(month),
            "record": _s(json.dumps(record, sort_keys=True)),
        }
        reservation_put = {
            "Put": {
                "TableName": self.table,
                "Item": item,
                "ConditionExpression": "attribute_not_exists(pk)",
            }
        }
        ledger_update = {
            "Update": {
                "TableName": self.table,
                "Key": _key(f"MONTH#{month}", "LEDGER"),
                "UpdateExpression": "ADD accruedCents :allowance",
                "ConditionExpression": (
                    "attribute_not_exists(accruedCents) OR accruedCents <= :max_before"
                ),
                "ExpressionAttributeValues": {
                    ":allowance": _n(allowance),
                    ":max_before": _n(cap - allowance),
                },
            }
        }
        items = [reservation_put, ledger_update]
        repo_id = ""
        job_id = ""
        if job_lock is not None:
            repo_id = str(job_lock["repo_id"])
            job_id = str(job_lock["job_id"])
            items = [
                {
                    "Put": {
                        "TableName": self.table,
                        "Item": {
                            "pk": _s(f"JOB#{repo_id}#{job_id}"),
                            "sk": _s("META"),
                            "state": _s("HELD"),
                            "clientToken": _s(token),
                            "month": _s(month),
                            "allowanceCents": _n(allowance),
                            "repoId": _s(repo_id),
                            "jobId": _s(job_id),
                            "createdEpoch": _n(int(job_lock["created_epoch"])),
                            "instanceId": _s(""),
                            "expiresAt": _n(int(job_lock["expires_at"])),
                        },
                        "ConditionExpression": "attribute_not_exists(pk)",
                    }
                },
                reservation_put,
                ledger_update,
            ]
        try:
            self.client.transact_write_items(TransactItems=items)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            if job_lock is None:
                return False
            return self._classify_reserve_cancel(
                exc,
                token=token,
                allowance=allowance,
                month=month,
                cap=cap,
                repo_id=repo_id,
                job_id=job_id,
            )
        if job_lock is None:
            return True
        return "ok"

    def get_reservation(self, token: str) -> dict[str, Any] | None:
        item = self._get(f"RES#{token}", "META")
        if item is None:
            return None
        return self._reservation_from_item(item)

    def list_open_reservations(self) -> list[dict[str, Any]]:
        return [
            self._reservation_from_item(item)
            for item in self._scan_prefix("RES#", "META")
            if item.get("state", {}).get("S") == "OPEN"
        ]

    def convert_reservation(self, token: str, instance_id: str, now: int) -> None:
        existing = self.get_instance(instance_id)
        if existing and existing["clientToken"] == token:
            if self.get_reservation(token) is None:
                return
        reservation = self.get_reservation(token)
        if reservation is None:
            raise StoreError("reservation missing during convert")
        record = dict(reservation["record"])
        month = reservation["month"]
        allowance = reservation["allowanceCents"]
        repo_id = str(record.get("repoId") or "")
        job_id = str(record.get("jobId") or "")
        job_item = None
        if _DIGITS.fullmatch(repo_id) and _DIGITS.fullmatch(job_id):
            job_item = self._get(f"JOB#{repo_id}#{job_id}", "META")
        record.update(
            {
                "instanceId": instance_id,
                "clientToken": token,
                "launchEpoch": now,
                "watermarkEpoch": now,
                "cumulativeDebitCents": allowance,
                "debitByMonth": {month: allowance},
                "state": "OPEN",
            }
        )
        transact = [
            {
                "Delete": {
                    "TableName": self.table,
                    "Key": _key(f"RES#{token}", "META"),
                    "ConditionExpression": "attribute_exists(pk) AND #state = :open",
                    "ExpressionAttributeNames": {"#state": "state"},
                    "ExpressionAttributeValues": {":open": _s("OPEN")},
                }
            },
            {
                "Put": {
                    "TableName": self.table,
                    "Item": self._instance_item(record),
                    "ConditionExpression": "attribute_not_exists(pk)",
                }
            },
        ]
        if job_item is not None:
            transact.append(
                {
                    "Update": {
                        "TableName": self.table,
                        "Key": _key(f"JOB#{repo_id}#{job_id}", "META"),
                        "UpdateExpression": "SET instanceId = :id",
                        "ConditionExpression": "clientToken = :token AND #state = :held",
                        "ExpressionAttributeNames": {"#state": "state"},
                        "ExpressionAttributeValues": {
                            ":id": _s(instance_id),
                            ":token": _s(token),
                            ":held": _s("HELD"),
                        },
                    }
                }
            )
        try:
            self.client.transact_write_items(TransactItems=transact)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            existing = self.get_instance(instance_id)
            if existing and existing["clientToken"] == token and self.get_reservation(token) is None:
                return
            raise

    def release_reservation(self, token: str) -> None:
        """Reverse an admission debit after a definitive no-create response."""
        reservation = self.get_reservation(token)
        if reservation is None:
            return
        record = reservation["record"]
        repo_id = str(record.get("repoId") or "")
        job_id = str(record.get("jobId") or "")
        digits_ok = bool(_DIGITS.fullmatch(repo_id) and _DIGITS.fullmatch(job_id))
        if "jitParameter" in record and not digits_ok:
            return
        allowance = reservation["allowanceCents"]
        month = reservation["month"]
        items: list[dict[str, Any]] = [
            {
                "Delete": {
                    "TableName": self.table,
                    "Key": _key(f"RES#{token}", "META"),
                    "ConditionExpression": "attribute_exists(pk)",
                }
            },
            {
                "Update": {
                    "TableName": self.table,
                    "Key": _key(f"MONTH#{month}", "LEDGER"),
                    "UpdateExpression": "ADD accruedCents :refund",
                    "ConditionExpression": "accruedCents >= :allowance",
                    "ExpressionAttributeValues": {
                        ":refund": _n(-allowance),
                        ":allowance": _n(allowance),
                    },
                }
            },
        ]
        if digits_ok:
            job_item = self._get(f"JOB#{repo_id}#{job_id}", "META")
            if job_item is not None and job_item.get("clientToken", {}).get("S") == token:
                items.append(
                    {
                        "Delete": {
                            "TableName": self.table,
                            "Key": _key(f"JOB#{repo_id}#{job_id}", "META"),
                            "ConditionExpression": "clientToken = :token",
                            "ExpressionAttributeValues": {":token": _s(token)},
                        }
                    }
                )
        self.client.transact_write_items(TransactItems=items)

    def update_reservation_fields(self, token: str, fields: dict[str, Any]) -> None:
        item = self._get(f"RES#{token}", "META")
        if item is None:
            return
        record = json.loads(item["record"]["S"])
        record.update(fields)
        self.client.update_item(
            TableName=self.table,
            Key=_key(f"RES#{token}", "META"),
            UpdateExpression="SET #record = :record",
            ExpressionAttributeNames={"#record": "record"},
            ExpressionAttributeValues={":record": _s(json.dumps(record, sort_keys=True))},
        )

    def mark_reservation_ambiguous(self, token: str) -> None:
        self.update_reservation_fields(token, {"ambiguousAttempt": True})

    def instances_returned(self, repo_id: str, job_id: str) -> int:
        """How many instance ids have been stored for this job, open or closed."""
        count = 0
        for item in self._scan_prefix("INST#", "META"):
            raw = item.get("record", {}).get("S")
            if not raw:
                continue
            record = json.loads(raw)
            if str(record.get("repoId", "")) == repo_id and str(record.get("jobId", "")) == job_id:
                count += 1
        return count

    def list_job_locks(self, repo_id: str) -> list[dict[str, Any]]:
        return [_plain(item) for item in self._scan_prefix(f"JOB#{repo_id}#", "META")]

    def touch_job_lock(self, repo_id: str, job_id: str, expires_at: int) -> None:
        self.client.update_item(
            TableName=self.table,
            Key=_key(f"JOB#{repo_id}#{job_id}", "META"),
            UpdateExpression="SET expiresAt = :expires",
            ConditionExpression="attribute_exists(pk)",
            ExpressionAttributeValues={":expires": _n(expires_at)},
        )

    def delete_job_lock(self, repo_id: str, job_id: str) -> None:
        self.client.delete_item(TableName=self.table, Key=_key(f"JOB#{repo_id}#{job_id}", "META"))

    def _classify_reserve_cancel(
        self,
        exc: ClientError,
        *,
        token: str,
        allowance: int,
        month: str,
        cap: int,
        repo_id: str,
        job_id: str,
    ) -> str:
        reasons = exc.response.get("CancellationReasons") or []
        codes = [str(item.get("Code", "")) for item in reasons if isinstance(item, dict)]
        if len(codes) >= 3:
            if codes[0] == "ConditionalCheckFailed" or codes[1] == "ConditionalCheckFailed":
                return "duplicate"
            if codes[2] == "ConditionalCheckFailed":
                return "cap"
            return "duplicate"
        if self._get(f"JOB#{repo_id}#{job_id}", "META") is not None:
            return "duplicate"
        if self._get(f"RES#{token}", "META") is not None:
            return "duplicate"
        if self.get_accrued(month) > cap - allowance:
            return "cap"
        return "duplicate"

    def release_all_open_reservations(self) -> None:
        for reservation in self.list_open_reservations():
            self.release_reservation(reservation["clientToken"])

    def get_instance(self, instance_id: str) -> dict[str, Any] | None:
        item = self._get(f"INST#{instance_id}", "META")
        if item is None:
            return None
        return self._instance_from_item(item)

    def list_open_instances(self) -> list[dict[str, Any]]:
        return [
            self._instance_from_item(item)
            for item in self._scan_prefix("INST#", "META")
            if item.get("state", {}).get("S") == "OPEN"
        ]

    def has_instance(self, instance_id: str) -> bool:
        return self.get_instance(instance_id) is not None

    def close_instance(self, instance_id: str, now: int) -> bool:
        """Close a terminated instance and true up its debit to actual runtime.

        The admission allowance was a reservation. At close the per-month debit
        becomes the actual runtime cost through max(now, watermark), and each
        month ledger moves by the difference, in one transaction with the close.
        A refund that would take a month ledger below zero cancels the whole
        write, so the debit stays and the record stays open.
        """
        inst = self.get_instance(instance_id)
        if inst is None or inst.get("state") != "OPEN":
            return False
        old = {str(k): int(v) for k, v in inst.get("debitByMonth", {}).items()}
        watermark = int(inst["watermarkEpoch"])
        actual = actual_by_month(
            int(inst["launchEpoch"]),
            max(now, watermark),
            int(inst["priceNumer"]),
            int(inst["priceDenom"]),
        )
        items: list[dict[str, Any]] = [
            {
                "Update": {
                    "TableName": self.table,
                    "Key": _key(f"INST#{instance_id}", "META"),
                    "UpdateExpression": (
                        "SET #state = :closed, cumulativeDebitCents = :cumulative, "
                        "debitByMonth = :debits"
                    ),
                    "ConditionExpression": (
                        "attribute_exists(pk) AND #state = :open AND watermarkEpoch = :watermark"
                    ),
                    "ExpressionAttributeNames": {"#state": "state"},
                    "ExpressionAttributeValues": {
                        ":closed": _s("CLOSED"),
                        ":open": _s("OPEN"),
                        ":watermark": _n(watermark),
                        ":cumulative": _n(sum(actual.values())),
                        ":debits": _s(json.dumps(actual, sort_keys=True)),
                    },
                }
            }
        ]
        for month in sorted(set(old) | set(actual)):
            delta = actual.get(month, 0) - old.get(month, 0)
            if delta == 0:
                continue
            update: dict[str, Any] = {
                "TableName": self.table,
                "Key": _key(f"MONTH#{month}", "LEDGER"),
                "UpdateExpression": "ADD accruedCents :delta",
                "ExpressionAttributeValues": {":delta": _n(delta)},
            }
            if delta < 0:
                update["ConditionExpression"] = "accruedCents >= :refund"
                update["ExpressionAttributeValues"][":refund"] = _n(-delta)
            items.append({"Update": update})
        try:
            self.client.transact_write_items(TransactItems=items)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                return False
            raise
        return True

    def apply_accrual(self, instance_id: str, plan: AccrualPlan) -> int:
        """Apply a plan once. A stale watermark adds zero."""
        values: dict[str, dict[str, str]] = {
            ":expected": _n(plan.expected_watermark),
            ":watermark": _n(plan.new_watermark),
            ":cumulative": _n(plan.new_cumulative),
            ":debits": _s(json.dumps(plan.debit_by_month, sort_keys=True)),
            ":open": _s("OPEN"),
        }
        names = {"#state": "state"}
        updates: list[dict[str, Any]] = [
            {
                "Update": {
                    "TableName": self.table,
                    "Key": _key(f"INST#{instance_id}", "META"),
                    "UpdateExpression": (
                        "SET watermarkEpoch = :watermark, cumulativeDebitCents = :cumulative, "
                        "debitByMonth = :debits"
                    ),
                    "ConditionExpression": (
                        "attribute_exists(pk) AND #state = :open AND watermarkEpoch = :expected"
                    ),
                    "ExpressionAttributeNames": names,
                    "ExpressionAttributeValues": values,
                }
            }
        ]
        for month, delta in plan.month_deltas.items():
            if delta <= 0:
                continue
            updates.append(
                {
                    "Update": {
                        "TableName": self.table,
                        "Key": _key(f"MONTH#{month}", "LEDGER"),
                        "UpdateExpression": "ADD accruedCents :delta",
                        "ExpressionAttributeValues": {":delta": _n(delta)},
                    }
                }
            )
        try:
            self.client.transact_write_items(TransactItems=updates)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                return 0
            raise
        return plan.delta

    def add_tag_hold(self, instance_id: str, cents: int, month: str) -> bool:
        """Count an unknown tagged instance once. Never removes the hold."""
        try:
            self.client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": self.table,
                            "Item": {
                                "pk": _s(f"TAG#{instance_id}"),
                                "sk": _s("HOLD"),
                                "cents": _n(cents),
                                "month": _s(month),
                            },
                            "ConditionExpression": "attribute_not_exists(pk)",
                        }
                    },
                    {
                        "Update": {
                            "TableName": self.table,
                            "Key": _key(f"MONTH#{month}", "LEDGER"),
                            "UpdateExpression": "ADD accruedCents :cents",
                            "ExpressionAttributeValues": {":cents": _n(cents)},
                        }
                    },
                ]
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                return False
            raise
        return True

    def has_tag_hold(self, instance_id: str) -> bool:
        return self._get(f"TAG#{instance_id}", "HOLD") is not None

    def claim(self, pk: str, sk: str, attributes: dict[str, Any]) -> bool:
        item = {"pk": _s(pk), "sk": _s(sk)}
        for key, value in attributes.items():
            if isinstance(value, int):
                item[key] = _n(value)
            else:
                item[key] = _s(str(value))
        try:
            self.client.put_item(
                TableName=self.table,
                Item=item,
                ConditionExpression="attribute_not_exists(pk)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def delete_marker(self, pk: str, sk: str) -> None:
        self.client.delete_item(TableName=self.table, Key=_key(pk, sk))

    def get_marker(self, pk: str, sk: str) -> dict[str, Any] | None:
        item = self._get(pk, sk)
        if item is None:
            return None
        return _plain(item)

    def update_marker(self, pk: str, sk: str, attributes: dict[str, Any]) -> None:
        names = {}
        values: dict[str, dict[str, str]] = {}
        parts = []
        for index, (key, value) in enumerate(attributes.items()):
            names[f"#k{index}"] = key
            if isinstance(value, int):
                values[f":v{index}"] = _n(value)
            else:
                values[f":v{index}"] = _s(str(value))
            parts.append(f"#k{index} = :v{index}")
        self.client.update_item(
            TableName=self.table,
            Key=_key(pk, sk),
            UpdateExpression="SET " + ", ".join(parts),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )

    def record_failure(self, token: str, code: str, now: int) -> None:
        self.client.put_item(
            TableName=self.table,
            Item={
                "pk": _s(f"FAIL#{token}"),
                "sk": _s("META"),
                "code": _s(code),
                "epoch": _n(now),
            },
        )

    def failure_count(self) -> int:
        return len(self._scan_prefix("FAIL#", "META"))

    def cooldown_until(self) -> int:
        item = self._get("COOLDOWN", "CAPACITY")
        if item is None:
            return 0
        return int(item["untilEpoch"]["N"])

    def set_cooldown(self, until_epoch: int) -> None:
        self.client.put_item(
            TableName=self.table,
            Item={"pk": _s("COOLDOWN"), "sk": _s("CAPACITY"), "untilEpoch": _n(until_epoch)},
        )

    def _get(self, pk: str, sk: str) -> dict[str, Any] | None:
        response = self.client.get_item(TableName=self.table, Key=_key(pk, sk), ConsistentRead=True)
        return response.get("Item")

    def _scan_prefix(self, prefix: str, sk: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "TableName": self.table,
            "FilterExpression": "begins_with(pk, :prefix) AND sk = :sk",
            "ExpressionAttributeValues": {":prefix": _s(prefix), ":sk": _s(sk)},
            "ConsistentRead": True,
        }
        while True:
            response = self.client.scan(**kwargs)
            items.extend(response.get("Items", []))
            last = response.get("LastEvaluatedKey")
            if not last:
                return items
            kwargs["ExclusiveStartKey"] = last

    def _instance_item(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "pk": _s(f"INST#{record['instanceId']}"),
            "sk": _s("META"),
            "state": _s(record["state"]),
            "watermarkEpoch": _n(int(record["watermarkEpoch"])),
            "cumulativeDebitCents": _n(int(record["cumulativeDebitCents"])),
            "debitByMonth": _s(json.dumps(record["debitByMonth"], sort_keys=True)),
            "record": _s(json.dumps(record, sort_keys=True)),
        }

    def _reservation_from_item(self, item: dict[str, Any]) -> dict[str, Any]:
        record = json.loads(item["record"]["S"])
        record["clientToken"] = item["clientToken"]["S"]
        record["allowanceCents"] = int(item["allowanceCents"]["N"])
        record["month"] = item["month"]["S"]
        record["state"] = item["state"]["S"]
        record["record"] = json.loads(item["record"]["S"])
        return record

    def _instance_from_item(self, item: dict[str, Any]) -> dict[str, Any]:
        record = json.loads(item["record"]["S"])
        record["state"] = item["state"]["S"]
        record["watermarkEpoch"] = int(item["watermarkEpoch"]["N"])
        record["cumulativeDebitCents"] = int(item["cumulativeDebitCents"]["N"])
        record["debitByMonth"] = {
            str(key): int(value) for key, value in json.loads(item["debitByMonth"]["S"]).items()
        }
        return record


def _plain(item: dict[str, Any]) -> dict[str, Any]:
    plain: dict[str, Any] = {}
    for key, value in item.items():
        if "N" in value:
            plain[key] = int(value["N"])
        elif "S" in value:
            plain[key] = value["S"]
    return plain
