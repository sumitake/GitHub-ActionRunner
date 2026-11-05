# SPDX-License-Identifier: MPL-2.0
"""Lambda entrypoint. Poll only; the event payload is ignored."""

from __future__ import annotations

import os
import time
from typing import Any

import boto3

from overflow_watcher.config import load_config
from overflow_watcher.controller import run_poll
from overflow_watcher.ec2view import Ec2Views
from overflow_watcher.github_api import LiveGitHub
from overflow_watcher.store import Store


def handler(event: dict[str, Any], context: object) -> dict[str, Any]:
    del event, context
    cfg = load_config(dict(os.environ))
    if not cfg.ok:
        return {"ok": False, "launched": 0, "reason": cfg.reason}
    endpoint = os.environ.get("DDB_ENDPOINT") or None
    store = Store.connect(table=cfg.table_name, endpoint_url=endpoint)
    raw = boto3.client("ec2")
    result = run_poll(
        store,
        Ec2Views(raw),
        raw,
        LiveGitHub(cfg),
        cfg,
        int(time.time()),
    )
    return {
        "ok": True,
        "launched": result.launched,
        "blocked": result.blocked_reason,
        "quotaFailures": result.quota_failures,
    }
