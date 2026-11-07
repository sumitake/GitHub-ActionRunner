# SPDX-License-Identifier: MPL-2.0
"""Shared fixtures for overflow watcher tests."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from overflow_watcher.config import DEFAULT_BUDGET_STOP_EXCLUSIONS, load_config  # noqa: E402
from overflow_watcher.store import Store  # noqa: E402
from overflow_watcher.types import InstanceView, Job  # noqa: E402

NOW = int(datetime(2026, 11, 15, 20, 0, tzinfo=timezone.utc).timestamp())
_TABLES = 0


def fresh_store() -> Store:
    global _TABLES
    _TABLES += 1
    endpoint = os.environ.get("DDB_LOCAL_ENDPOINT", "http://localhost:8000")
    name = f"ow{os.getpid()}x{_TABLES}"
    return Store.connect(table=name, endpoint_url=endpoint)


def watcher_env(**overrides: str) -> dict[str, str]:
    env = {
        "ALL_IN_HOURLY_PRICE": "0.01",
        "MONTHLY_SOFT_CAP_CENTS": "3000",
        "GRACE_PCT": "10",
        "GRACE_CENTS": "300",
        "CONTINUE_ACTIVE_UNTIL_CENTS": "3300",
        "BUDGET_CANCEL_WAIT_SECONDS": "120",
        "BUDGET_STOP_EXCLUSIONS": DEFAULT_BUDGET_STOP_EXCLUSIONS,
        "LAUNCH_TEMPLATE_ID": "lt-placeholder",
        "WATCHED_REPOS": json.dumps(
            [
                {
                    "id": "101",
                    "owner": "example",
                    "name": "keicrew",
                    "installation": "201",
                }
            ]
        ),
        "AMI_ID": "ami-placeholder",
        "SUBNET_ID": "subnet-placeholder",
        "SECURITY_GROUP_ID": "sg-placeholder",
        "INSTANCE_TYPE": "m7i.large",
        "INSTANCE_PROFILE_NAME": "overflow-runner",
        "GITHUB_APP_IDENTIFIER": "app-placeholder",
        "GITHUB_APP_PEM": "not-a-real-pem",
        "TABLE_NAME": "overflow-watcher",
    }
    env.update(overrides)
    return env


def cfg(**overrides: str):
    loaded = load_config(watcher_env(**overrides))
    if not loaded.ok:
        raise AssertionError(loaded.reason)
    return loaded


def sample_job(**overrides) -> Job:
    data = {
        "owner": "example",
        "repo_name": "keicrew",
        "installation": "201",
        "workflow_name": "CI",
        "job_name": "test",
        "workflow_run_id": "77",
        "labels": ("self-hosted", "Linux"),
        "queued_epoch": NOW - 600,
    }
    data.update(overrides)
    return Job(**data)


def add_cents(store: Store, month: str, cents: int) -> None:
    store.client.update_item(
        TableName=store.table,
        Key={"pk": {"S": f"MONTH#{month}"}, "sk": {"S": "LEDGER"}},
        UpdateExpression="ADD accruedCents :cents",
        ExpressionAttributeValues={":cents": {"N": str(cents)}},
    )


def seed_instance(
    store: Store,
    ec2,
    *,
    instance_id: str,
    debit: int,
    month: str,
    launch_epoch: int,
    workflow: str = "CI",
    job_name: str = "test",
    labels: tuple[str, ...] = ("self-hosted", "Linux"),
    run_id: str = "77",
    has_tag: bool = True,
    state: str | None = "running",
    uncertain: bool = False,
    price_numer: int = 1,
    price_denom: int = 100,
    tagged_list: bool = True,
) -> None:
    record = {
        "instanceId": instance_id,
        "clientToken": f"tok-{instance_id}",
        "allowanceCents": debit,
        "month": month,
        "createdEpoch": launch_epoch,
        "launchEpoch": launch_epoch,
        "watermarkEpoch": launch_epoch,
        "cumulativeDebitCents": debit,
        "debitByMonth": {month: debit},
        "state": "OPEN",
        "params": {"ImageId": "ami-placeholder"},
        "owner": "example",
        "repoName": "keicrew",
        "installation": "201",
        "workflowName": workflow,
        "jobName": job_name,
        "workflowRunId": run_id,
        "labels": list(labels),
        "priceNumer": price_numer,
        "priceDenom": price_denom,
    }
    store.client.put_item(TableName=store.table, Item=store._instance_item(record))
    add_cents(store, month, debit)
    ec2.views[instance_id] = InstanceView(instance_id, state, has_tag, uncertain)
    if tagged_list and has_tag and instance_id not in ec2.tagged:
        ec2.tagged.append(instance_id)
