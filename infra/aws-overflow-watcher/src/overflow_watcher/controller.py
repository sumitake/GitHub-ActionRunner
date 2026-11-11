# SPDX-License-Identifier: MPL-2.0
"""One-minute poll: admit, accrue, reconcile, and maybe budget-stop."""

from __future__ import annotations

import hashlib
import re
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
from overflow_watcher.jit_handoff import JitParams, parameter_name
from overflow_watcher.money import month_key, plan_accrual
from overflow_watcher.store import Store
from overflow_watcher.types import (
    CAPACITY_COOLDOWN_SECONDS,
    JOB_HOLD_TTL_SECONDS,
    RETRY_WINDOW_SECONDS,
    TAG_VALUE,
    WATCHER_TAG_NAME,
    AmbiguousLaunch,
    CapacityRefused,
)

_DIGITS = re.compile(r"[0-9]+\Z")
_RUNNER_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")


def client_token(repo_id: str, job_id: str, attempt: int) -> str:
    """EC2 ClientToken. attempt counts instance ids already returned for the job."""
    if _DIGITS.fullmatch(repo_id) is None or _DIGITS.fullmatch(job_id) is None or attempt < 0:
        raise ValueError("client token")
    material = "\n".join(("overflow-watcher/v1", repo_id, job_id, str(attempt)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def retry_token(reservation: dict[str, Any]) -> str:
    """F7(e): an unresolved launch retries the original ClientToken."""
    return str(reservation["clientToken"])


def admission_allows(accrued: int, allowance: int, cap: int) -> bool:
    """C1: block a launch that would push the estimate over the soft cap."""
    if allowance <= 0:
        return False
    return accrued + allowance <= cap


def ec2_params(cfg: Any, *, parameter_name: str) -> dict[str, Any]:
    return {
        "LaunchTemplate": {
            "LaunchTemplateId": cfg.launch_template_id,
            "Version": "$Latest",
        },
        "UserData": render_user_data(parameter_name),
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


def _drop_parameter(ssm: Any, name: str) -> None:
    if ssm is None or not name:
        return
    try:
        JitParams(ssm).delete(name)
    except Exception:
        return


def reconcile(store: Store, ec2: Any, *, index_count: int | None, ssm: Any = None) -> None:
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
        if ssm is not None:
            saved = store.get_instance(instance_id)
            if saved:
                _drop_parameter(ssm, str(saved.get("jitParameter") or ""))
        store.close_instance(instance_id)


def _record_for(
    job: Any,
    cfg: Any,
    token: str,
    now: int,
    month: str,
    *,
    parameter_name: str | None = None,
    runner_name: str = "",
    runner_group_id: int = 1,
) -> dict[str, Any]:
    if parameter_name is None:
        parameter_name = "/overflow-watcher/jit/" + ("0" * 64)
    record = {
        "clientToken": token,
        "allowanceCents": cfg.allowance,
        "month": month,
        "createdEpoch": now,
        "params": ec2_params(cfg, parameter_name=parameter_name),
        "owner": job.owner,
        "repoName": job.repo_name,
        "installation": job.installation,
        "workflowName": job.workflow_name,
        "jobName": job.job_name,
        "workflowRunId": job.workflow_run_id,
        "labels": list(job.labels),
        "priceNumer": cfg.price_numer,
        "priceDenom": cfg.price_denom,
        "repoId": getattr(job, "repo_id", ""),
        "jobId": getattr(job, "job_id", ""),
    }
    if runner_name:
        record["jitParameter"] = parameter_name
        record["jitReady"] = False
        record["runnerName"] = runner_name
        record["runnerGroupId"] = runner_group_id
    return record


def _runner_group(cfg: Any, repo_id: str) -> int:
    for repo in cfg.repos:
        if repo.repo_id == repo_id:
            return int(repo.runner_group_id)
    return 1


def _runner_name(repo_id: str, job_id: str, created_epoch: int) -> str:
    name = f"overflow-{repo_id}-{job_id}-{created_epoch}"
    if _RUNNER_NAME.fullmatch(name) is None:
        return ""
    return name


def _fail_unlaunched(store: Store, ssm: Any, token: str, *, delete_param: bool) -> None:
    reservation = store.get_reservation(token)
    name = str((reservation or {}).get("jitParameter") or "")
    if delete_param:
        _drop_parameter(ssm, name)
    store.release_reservation(token)


def _prepare_jit(store: Store, github: Any, ssm: Any, token: str, now: int) -> str | None:
    """Mint and store the secret. None means the reservation is ready to launch."""
    reservation = store.get_reservation(token)
    if reservation is None:
        return "missing"
    if reservation.get("jitReady"):
        return None
    name = str(reservation.get("jitParameter") or "")
    runner = str(reservation.get("runnerName") or "")
    if github is None or ssm is None or runner == "":
        _fail_unlaunched(store, ssm, token, delete_param=False)
        return "mint-failed"
    try:
        minted = github.mint_jitconfig(
            owner=str(reservation["owner"]),
            repo=str(reservation["repoName"]),
            installation=str(reservation["installation"]),
            runner_name=runner,
            labels=tuple(reservation.get("labels") or ()),
            runner_group_id=int(reservation.get("runnerGroupId") or 1),
            now=now,
        )
    except Exception:
        minted = None
    secret = minted.get("encoded_jit_config") if isinstance(minted, dict) else None
    if not isinstance(secret, str) or secret == "":
        _fail_unlaunched(store, ssm, token, delete_param=False)
        return "mint-failed"
    try:
        outcome = JitParams(ssm).put(name, secret)
    except Exception:
        _fail_unlaunched(store, ssm, token, delete_param=True)
        return "put-failed"
    if outcome not in {"ready", "exists"}:
        _fail_unlaunched(store, ssm, token, delete_param=True)
        return "put-failed"
    fields: dict[str, Any] = {"jitReady": True}
    runner_id = minted.get("github_runner_id") if isinstance(minted, dict) else None
    if type(runner_id) is int:
        fields["githubRunnerId"] = runner_id
    store.update_reservation_fields(token, fields)
    return None


def _capacity_after_attempt(store: Store, token: str, code: str, now: int, ssm: Any) -> None:
    """A quota error after an ambiguous attempt must keep the reservation."""
    reservation = store.get_reservation(token)
    if reservation and reservation.get("ambiguousAttempt"):
        store.record_failure(token, code, now)
        return
    name = str((reservation or {}).get("jitParameter") or "")
    _drop_parameter(ssm, name)
    store.record_failure(token, code, now)
    store.release_reservation(token)
    store.set_cooldown(now + CAPACITY_COOLDOWN_SECONDS)


def _run_reserved(store: Store, ec2: Any, ssm: Any, token: str, now: int) -> str:
    reservation = store.get_reservation(token)
    if reservation is None:
        return "missing"
    try:
        instance_id = ec2.run_instances(token, reservation["params"])
    except CapacityRefused as exc:
        _capacity_after_attempt(store, token, exc.code, now, ssm)
        if store.get_reservation(token):
            return "quota-held"
        return "quota"
    except AmbiguousLaunch:
        store.mark_reservation_ambiguous(token)
        return "ambiguous"
    store.convert_reservation(token, instance_id, now)
    return "launched"


def finish_launch(store: Store, ec2: Any, github: Any, ssm: Any, token: str, now: int) -> str:
    prepared = _prepare_jit(store, github, ssm, token, now)
    if prepared:
        return prepared
    return _run_reserved(store, ec2, ssm, token, now)


def resolve_reservations(
    store: Store,
    ec2: Any,
    alerts: AlertLog,
    now: int,
    *,
    github: Any = None,
    ssm: Any = None,
) -> None:
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
        finish_launch(store, ec2, github, ssm, token, now)


def release_finished_jobs(store: Store, repo: Any, queued_ids: tuple[str, ...] | list[str], now: int) -> None:
    """Drop a job lock once its reservation and instance are both gone.

    queued_ids is every positive job id seen in this poll. A lock is released
    whether or not that id is still queued. Callers skip this when assess is uncertain.
    """
    _ = queued_ids
    for row in store.list_job_locks(repo.repo_id):
        job_id = str(row.get("jobId") or "")
        token = str(row.get("clientToken") or "")
        instance_id = str(row.get("instanceId") or "")
        open_reservation = store.get_reservation(token) is not None
        open_instance = False
        if instance_id:
            saved = store.get_instance(instance_id)
            open_instance = bool(saved and saved.get("state") == "OPEN")
        if open_reservation or open_instance:
            store.touch_job_lock(repo.repo_id, job_id, now + JOB_HOLD_TTL_SECONDS)
            continue
        store.delete_job_lock(repo.repo_id, job_id)


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


def _open_instance_for_job(store: Store, repo_id: str, job_id: str, token: str) -> bool:
    for inst in store.list_open_instances():
        if str(inst.get("clientToken", "")) == token:
            return True
        if str(inst.get("repoId", "")) == repo_id and str(inst.get("jobId", "")) == job_id:
            return True
    return False


def launch_one(
    store: Store,
    ec2: Any,
    cfg: Any,
    job: Any,
    now: int,
    *,
    github: Any = None,
    ssm: Any = None,
) -> str:
    if now < store.cooldown_until():
        return "cooldown"
    month = month_key(now)
    accrued = store.get_accrued(month)
    if not admission_allows(accrued, cfg.allowance, cfg.soft_cap):
        return "cap"
    repo_id = getattr(job, "repo_id", "")
    job_id = getattr(job, "job_id", "")
    if _DIGITS.fullmatch(str(repo_id)) is None or _DIGITS.fullmatch(str(job_id)) is None:
        return "invalid-job"
    repo_id = str(repo_id)
    job_id = str(job_id)
    attempt = store.instances_returned(repo_id, job_id)
    token = client_token(repo_id, job_id, attempt)
    if _open_instance_for_job(store, repo_id, job_id, token):
        return "duplicate"
    name = _runner_name(repo_id, job_id, now)
    if name == "":
        return "mint-failed"
    jit_name = parameter_name(token)
    record = _record_for(
        job,
        cfg,
        token,
        now,
        month,
        parameter_name=jit_name,
        runner_name=name,
        runner_group_id=_runner_group(cfg, repo_id),
    )
    outcome = store.reserve(
        token=token,
        allowance=cfg.allowance,
        month=month,
        cap=cfg.soft_cap,
        record=record,
        job_lock={
            "repo_id": repo_id,
            "job_id": job_id,
            "created_epoch": now,
            "expires_at": now + JOB_HOLD_TTL_SECONDS,
        },
    )
    if outcome is False or outcome == "cap":
        return "cap"
    if outcome is not True and outcome != "ok":
        return "duplicate"
    return finish_launch(store, ec2, github, ssm, token, now)


def run_poll(
    store: Store,
    ec2: Any,
    ec2_api: Any,
    github: Any,
    cfg: Any,
    now: int,
    *,
    ssm: Any = None,
) -> PollResult:
    result = PollResult()
    if not cfg.launch_allowed:
        result.blocked_reason = cfg.reason or "config"
        return result
    resolve_reservations(store, ec2, result.alerts, now, github=github, ssm=ssm)
    accrue(store, result.alerts, now)
    index = ec2.index_count() if hasattr(ec2, "index_count") else None
    reconcile(store, ec2, index_count=index, ssm=ssm)
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
        release_finished_jobs(store, repo, decision.seen_job_ids, now)
        for job in decision.jobs:
            outcome = launch_one(store, ec2, cfg, job, now, github=github, ssm=ssm)
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
