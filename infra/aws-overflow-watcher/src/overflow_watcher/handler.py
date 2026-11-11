# SPDX-License-Identifier: MPL-2.0
"""Lambda entrypoint. Poll only; the event payload is ignored."""

from __future__ import annotations

import os
import time
from typing import Any

import boto3

from overflow_watcher.budget import Alert, alert_dict, write_alert_line
from overflow_watcher.config import load_config
from overflow_watcher.controller import PollResult, run_poll
from overflow_watcher.ec2view import Ec2Views
from overflow_watcher.github_api import LiveGitHub
from overflow_watcher.store import Store


def alert_payload(alert: Alert) -> dict[str, Any]:
    return alert_dict(alert)


def response_from_poll(result: PollResult) -> dict[str, Any]:
    """Return every alert. A line is printed here only if the poll did not already log it."""
    rendered = []
    for alert in result.alerts.items:
        if not alert.logged:
            write_alert_line(alert)
        rendered.append(alert_payload(alert))
    return {
        "ok": True,
        "launched": result.launched,
        "blocked": result.blocked_reason,
        "quotaFailures": result.quota_failures,
        "alerts": rendered,
    }


def handler(event: dict[str, Any], context: object) -> dict[str, Any]:
    del event, context
    cfg = load_config(dict(os.environ))
    if not cfg.ok:
        return {"ok": False, "launched": 0, "reason": cfg.reason}
    endpoint = os.environ.get("DDB_ENDPOINT") or None
    store = Store.connect(table=cfg.table_name, endpoint_url=endpoint)
    raw = boto3.client("ec2")
    region = os.environ.get("AWS_REGION") or "us-west-2"
    ssm = boto3.client("ssm", region_name=region)
    result = run_poll(
        store,
        Ec2Views(raw),
        raw,
        LiveGitHub(cfg),
        cfg,
        int(time.time()),
        ssm=ssm,
    )
    return response_from_poll(result)
