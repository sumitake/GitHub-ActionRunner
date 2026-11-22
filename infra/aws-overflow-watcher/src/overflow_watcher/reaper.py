# SPDX-License-Identifier: MPL-2.0
"""Idle overflow runners: deregister, then terminate. Unknown state waits."""

from __future__ import annotations

import json
from typing import Any

from overflow_watcher.budget import advance_owned_stop
from overflow_watcher.money import month_key
from overflow_watcher.store import Store

# GitHub calls are the slow part of the poll. Busy rows count toward this cap.
_GITHUB_CHECKS_PER_POLL = 5


def reap_idle_runners(
    store: Store,
    ec2: Any,
    ec2_api: Any,
    github: Any,
    alerts: Any,
    now: int,
    grace: int,
) -> None:
    """Deregister and terminate owned runners idle past grace.

    Zero or a negative grace returns immediately. `alerts` is unused: a reap
    is one log line and does not alarm. The record stays open for reconcile.
    """
    _ = alerts
    if grace <= 0:
        return
    pending = [
        inst
        for inst in store.list_open_instances()
        if _past_grace(inst, now, grace) and not _in_cancel_wait(store, inst, now)
    ]
    pending.sort(key=lambda item: (int(item["launchEpoch"]), str(item["instanceId"])))
    checked = 0
    for inst in pending:
        if checked >= _GITHUB_CHECKS_PER_POLL:
            break
        instance_id = str(inst["instanceId"])
        if not _running_owned(ec2, instance_id):
            continue
        checked += 1
        # No HTTP status can be a 10s connect timeout. Stop this pass so five
        # of them cannot outlast the Lambda and skip the budget stop.
        if not _reap_one(ec2_api, github, inst, now):
            return


def note_reaper_abort(exc: BaseException | None = None) -> None:
    """One log line. A logging failure must not skip the rest of the poll."""
    payload: dict[str, object] = {"kind": "idle-reap", "result": "aborted"}
    if exc is not None:
        payload["error"] = type(exc).__name__
    try:
        print(json.dumps(payload, sort_keys=True), flush=True)
    except Exception:
        return


def _past_grace(inst: dict[str, Any], now: int, grace: int) -> bool:
    if type(inst.get("githubRunnerId")) is not int:
        return False
    owner = inst.get("owner")
    repo = inst.get("repoName")
    if not isinstance(owner, str) or owner == "" or not isinstance(repo, str) or repo == "":
        return False
    launch = inst.get("launchEpoch")
    if type(launch) is not int:
        return False
    return now - launch >= grace


def _in_cancel_wait(store: Store, inst: dict[str, Any], now: int) -> bool:
    """Skip only an in-flight budget cancel. Other stop markers do not suppress a reap."""
    marker = store.get_marker(f"STOP#{month_key(now)}", f"INST#{inst['instanceId']}")
    return bool(marker and marker.get("phase") == "cancel_wait")


def _running_owned(ec2: Any, instance_id: str) -> bool:
    views = ec2.describe_instances([instance_id])
    view = views.get(instance_id)
    if view is None or view.uncertain or not view.has_tag:
        return False
    return view.state == "running"


def _reap_one(ec2_api: Any, github: Any, inst: dict[str, Any], now: int) -> bool:
    """Terminate only after DELETE 204 or 404, or when GET says the runner is gone.

    Return False when GET or DELETE has no HTTP status so this poll stops.
    A real HTTP status, or a non-bool `busy`, returns True and skips only
    this runner. `busy` false is enough. Offline is reaped. Do not require
    status online.
    """
    instance_id = str(inst["instanceId"])
    runner_id = inst["githubRunnerId"]
    owner = str(inst["owner"])
    repo = str(inst["repoName"])
    status, busy = github.get_runner(owner, repo, runner_id)
    if status is None:
        return False
    if status == 404:
        _terminate(ec2_api, instance_id, runner_id, now - int(inst["launchEpoch"]))
        return True
    if status != 200 or type(busy) is not bool or busy:
        return True
    deleted = github.delete_runner(owner, repo, runner_id)
    if deleted is None:
        return False
    if deleted not in (204, 404):
        return True
    _terminate(ec2_api, instance_id, runner_id, now - int(inst["launchEpoch"]))
    return True


def _terminate(ec2_api: Any, instance_id: str, runner_id: int, idle_s: int) -> None:
    advance_owned_stop(ec2_api, instance_id)
    print(
        json.dumps(
            {
                "kind": "idle-reap",
                "instance": instance_id,
                "runner_id": runner_id,
                "idle_s": idle_s,
                "result": "terminated",
            },
            sort_keys=True,
        ),
        flush=True,
    )
