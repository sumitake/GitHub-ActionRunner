# SPDX-License-Identifier: MPL-2.0
"""One-minute poll: admit, accrue, reconcile, and maybe budget-stop."""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass, field
from typing import Any

from overflow_watcher.budget import (
    Alert,
    AlertLog,
    BudgetResult,
    deliver_month_alert,
    enforce_budget_stop,
    write_alert_line,
)
from overflow_watcher.guest_bootstrap import render_user_data
from overflow_watcher.inventory import reservations_released_by_ec2
from overflow_watcher.money import month_key, plan_accrual
from overflow_watcher.store import Store
from overflow_watcher.types import (
    CAPACITY_COOLDOWN_SECONDS,
    RETRY_WINDOW_SECONDS,
    TAG_VALUE,
    WATCHER_TAG_NAME,
    AmbiguousLaunch,
    CapacityRefused,
)


def retry_token(reservation: dict[str, Any]) -> str:
    """F7(e): an unresolved launch retries the original ClientToken."""
    return str(reservation["clientToken"])


def admission_allows(accrued: int, allowance: int, cap: int) -> bool:
    """C1: block a launch that would push the estimate over the soft cap."""
    if allowance <= 0:
        return False
    return accrued + allowance <= cap


def supervisor_user_data() -> str:
    """Base64 of the self-contained guest bootstrap sent as RunInstances user data."""
    return base64.b64encode(render_user_data().encode("utf-8")).decode("ascii")


def ec2_params(cfg: Any) -> dict[str, Any]:
    return {
        "LaunchTemplate": {
            "LaunchTemplateId": cfg.launch_template_id,
            "Version": "$Latest",
        },
        "UserData": supervisor_user_data(),
        "ImageId": cfg.ami_id,
        "InstanceType": cfg.instance_type,
        "SubnetId": cfg.subnet_id,
        "SecurityGroupIds": [cfg.security_group_id],
        "MinCount": 1,
        "MaxCount": 1,
        "IamInstanceProfile": {"Name": cfg.instance_profile_name},
        "InstanceInitiatedShutdownBehavior": "terminate",
        "MetadataOptions": {
            "HttpTokens": "required",
            "HttpEndpoint": "enabled",
            "HttpPutResponseHopLimit": 1,
        },
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": WATCHER_TAG_NAME, "Value": TAG_VALUE},
                ],
            }
        ],
    }


@dataclass
class PollResult:
    launched: int = 0
    blocked_reason: str = ""
    budget: BudgetResult | None = None
    quota_failures: int = 0
    alerts: AlertLog = field(default_factory=AlertLog)


def reconcile(store: Store, ec2: Any, *, index_count: int | None) -> None:
    """Close records only on a positive terminated read. Never release reservations."""
    views = {}
    described_empty = True
    try:
        ids = [item["instanceId"] for item in store.list_open_instances()]
        if ids:
            views = ec2.describe_instances(ids)
            described_empty = not any(
                view.state is not None and not view.uncertain for view in views.values()
            )
    except Exception:
        described_empty = True
    if reservations_released_by_ec2(index_count, described_empty):
        store.release_all_open_reservations()
    for instance_id, view in views.items():
        if view.uncertain or view.state != "terminated":
            continue
        store.close_instance(instance_id)


def _record_for(job: Any, cfg: Any, token: str, now: int, month: str) -> dict[str, Any]:
    return {
        "clientToken": token,
        "allowanceCents": cfg.allowance,
        "month": month,
        "createdEpoch": now,
        "params": ec2_params(cfg),
        "owner": job.owner,
        "repoName": job.repo_name,
        "installation": job.installation,
        "workflowName": job.workflow_name,
        "jobName": job.job_name,
        "workflowRunId": job.workflow_run_id,
        "labels": list(job.labels),
        "priceNumer": cfg.price_numer,
        "priceDenom": cfg.price_denom,
    }


def resolve_reservations(store: Store, ec2: Any, alerts: AlertLog, now: int) -> None:
    for reservation in store.list_open_reservations():
        age = now - int(reservation["createdEpoch"])
        stored = str(reservation["clientToken"])
        token = retry_token(reservation)
        if age > RETRY_WINDOW_SECONDS:
            if store.get_marker(f"RES#{stored}", "ALERT#RETRY"):
                continue
            alert = Alert(
                audience="ops",
                kind="retry-held",
                month=reservation["month"],
                estimated_cents=store.get_accrued(reservation["month"]),
                overage_cents=0,
                cause="unresolved launch stayed reserved past the retry window",
                instance_ids=(),
            )
            try:
                write_alert_line(alert)
                alerts.emit(alert)
            except Exception:
                store.claim(f"RES#{stored}", "ALERT#RETRY#RETRY", {"kind": "retry-held"})
                continue
            store.claim(f"RES#{stored}", "ALERT#RETRY", {"kind": "retry-held"})
            continue
        try:
            instance_id = ec2.run_instances(token, reservation["params"])
        except CapacityRefused as exc:
            _capacity_after_attempt(store, stored, exc.code, now)
            continue
        except AmbiguousLaunch:
            store.mark_reservation_ambiguous(stored)
            continue
        store.convert_reservation(stored, instance_id, now)


def _record_capacity_failure(store: Store, token: str, code: str, now: int) -> None:
    store.record_failure(token, code, now)
    store.release_reservation(token)
    store.set_cooldown(now + CAPACITY_COOLDOWN_SECONDS)


def _capacity_after_attempt(store: Store, token: str, code: str, now: int) -> None:
    """A quota error after an ambiguous attempt must keep the reservation."""
    reservation = store.get_reservation(token)
    if reservation and reservation.get("ambiguousAttempt"):
        store.record_failure(token, code, now)
        return
    _record_capacity_failure(store, token, code, now)


def accrue(store: Store, alerts: AlertLog, now: int) -> None:
    for inst in store.list_open_instances():
        plan = plan_accrual(
            launch_epoch=int(inst["launchEpoch"]),
            watermark=int(inst["watermarkEpoch"]),
            cumulative=int(inst["cumulativeDebitCents"]),
            debit_by_month={str(k): int(v) for k, v in inst.get("debitByMonth", {}).items()},
            now=now,
            numer=int(inst["priceNumer"]),
            denom=int(inst["priceDenom"]),
        )
        if plan is None:
            continue
        applied = store.apply_accrual(inst["instanceId"], plan)
        if applied and plan.crossed_allowance:
            pk = f"INST#{inst['instanceId']}"
            if store.get_marker(pk, "ALERT#ALLOWANCE"):
                continue
            alert = Alert(
                audience="ops",
                kind="past-allowance",
                month=month_key(now),
                estimated_cents=store.get_accrued(month_key(now)),
                overage_cents=0,
                cause="instance runtime passed the 6 hour allowance",
                instance_ids=(inst["instanceId"],),
            )
            try:
                write_alert_line(alert)
                alerts.emit(alert)
            except Exception:
                store.claim(pk, "ALERT#ALLOWANCE#RETRY", {"kind": "past-allowance"})
                continue
            store.claim(pk, "ALERT#ALLOWANCE", {"kind": "past-allowance"})


def maybe_soft_alert(store: Store, alerts: AlertLog, cfg: Any, now: int) -> None:
    month = month_key(now)
    accrued = store.get_accrued(month)
    if accrued <= cfg.soft_cap:
        return
    deliver_month_alert(
        store,
        month,
        "BUDGET",
        Alert(
            audience="john",
            kind="budget",
            month=month,
            estimated_cents=accrued,
            overage_cents=accrued - cfg.soft_cap,
            cause="estimated accrued cost passed the monthly soft cap",
        ),
        alerts,
    )


def launch_one(store: Store, ec2: Any, cfg: Any, job: Any, now: int) -> str:
    if now < store.cooldown_until():
        return "cooldown"
    month = month_key(now)
    accrued = store.get_accrued(month)
    if not admission_allows(accrued, cfg.allowance, cfg.soft_cap):
        return "cap"
    token = secrets.token_hex(8)
    record = _record_for(job, cfg, token, now, month)
    if not store.reserve(
        token=token,
        allowance=cfg.allowance,
        month=month,
        cap=cfg.soft_cap,
        record=record,
    ):
        return "cap"
    try:
        instance_id = ec2.run_instances(token, record["params"])
    except CapacityRefused as exc:
        _capacity_after_attempt(store, token, exc.code, now)
        if store.get_reservation(token):
            return "quota-held"
        return "quota"
    except AmbiguousLaunch:
        store.mark_reservation_ambiguous(token)
        return "ambiguous"
    store.convert_reservation(token, instance_id, now)
    return "launched"


def run_poll(store: Store, ec2: Any, ec2_api: Any, github: Any, cfg: Any, now: int) -> PollResult:
    result = PollResult()
    if not cfg.launch_allowed:
        result.blocked_reason = cfg.reason or "config"
        return result
    resolve_reservations(store, ec2, result.alerts, now)
    accrue(store, result.alerts, now)
    index = ec2.index_count() if hasattr(ec2, "index_count") else None
    reconcile(store, ec2, index_count=index)
    result.budget = enforce_budget_stop(
        store=store,
        ec2=ec2,
        ec2_api=ec2_api,
        github=github,
        alerts=result.alerts,
        now=now,
        grace=cfg.continue_until,
        soft_cap=cfg.soft_cap,
        cancel_wait=cfg.cancel_wait,
        exclusions=cfg.exclusions,
        allowance=cfg.allowance,
    )
    maybe_soft_alert(store, result.alerts, cfg, now)
    if result.budget.uncertain or result.budget.block_launch:
        result.blocked_reason = "unknown-inventory"
        return result
    for repo in cfg.repos:
        decision = github.assess(repo, now)
        if decision.uncertain:
            continue
        for job in decision.jobs:
            outcome = launch_one(store, ec2, cfg, job, now)
            if outcome == "launched":
                result.launched += 1
            elif outcome == "quota":
                result.quota_failures += 1
                return result
            elif outcome == "cap":
                result.blocked_reason = "soft-cap"
                return result
            elif outcome == "cooldown":
                result.blocked_reason = "cooldown"
                return result
    return result
