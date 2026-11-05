# SPDX-License-Identifier: MPL-2.0
"""C4b budget stop. The only TerminateInstances call site lives here."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from overflow_watcher.money import month_key, select_minimum
from overflow_watcher.store import Store
from overflow_watcher.types import StopCandidate


@dataclass
class Alert:
    audience: str
    kind: str
    month: str
    estimated_cents: int
    overage_cents: int
    cause: str
    instance_ids: tuple[str, ...] = ()


@dataclass
class AlertLog:
    items: list[Alert] = field(default_factory=list)

    def emit(self, alert: Alert) -> None:
        self.items.append(alert)


@dataclass
class BudgetResult:
    fired: bool
    uncertain: bool
    cancelled: tuple[str, ...]
    terminated: tuple[str, ...]
    spared: tuple[str, ...]


class Ec2Reads:
    """Read side of EC2. Termination is not part of this interface."""

    def describe_instances(self, ids: list[str]) -> dict[str, InstanceView]:
        raise NotImplementedError

    def list_tagged_ids(self) -> list[str] | None:
        raise NotImplementedError

    def index_count(self) -> int | None:
        raise NotImplementedError

    def run_instances(self, token: str, params: dict) -> str:
        raise NotImplementedError


class GitHubActions:
    def cancel_workflow_run(self, owner: str, repo: str, run_id: str) -> str:
        raise NotImplementedError

    def workflow_completed(self, owner: str, repo: str, run_id: str) -> bool | None:
        raise NotImplementedError


def _excluded(candidate: StopCandidate, exclusions: tuple) -> bool:
    for rule in exclusions:
        if rule.kind == "workflow" and fnmatch.fnmatchcase(candidate.workflow_name, rule.pattern):
            return True
        if rule.kind == "job" and fnmatch.fnmatchcase(candidate.job_name, rule.pattern):
            return True
        if rule.kind == "label" and any(
            fnmatch.fnmatchcase(label, rule.pattern) for label in candidate.labels
        ):
            return True
    return False


def _once(store: Store, pk: str, sk: str, **attributes: object) -> bool:
    return store.claim(pk, sk, attributes)


def advance_owned_stop(ec2_api: Any, instance_id: str) -> None:
    """Terminate one verified instance. This is the only such call in the package."""
    ec2_api.terminate_instances(InstanceIds=[instance_id])


def enforce_budget_stop(
    *,
    store: Store,
    ec2: Ec2Reads,
    ec2_api: Any,
    github: GitHubActions,
    alerts: AlertLog,
    now: int,
    grace: int,
    soft_cap: int,
    cancel_wait: int,
    exclusions: tuple,
    allowance: int,
) -> BudgetResult:
    """Stop the minimum verified set once estimated spend reaches the grace."""
    month = month_key(now)
    uncertain = False
    tagged = ec2.list_tagged_ids()
    if tagged is None:
        uncertain = True
        if _once(store, f"MONTH#{month}", "ALERT#EC2READ", kind="ec2-uncertain"):
            alerts.emit(
                Alert(
                    audience="ops",
                    kind="ec2-uncertain",
                    month=month,
                    estimated_cents=store.get_accrued(month),
                    overage_cents=0,
                    cause="tagged-instance read failed; no instances were stopped",
                )
            )
    else:
        for instance_id in tagged:
            if store.has_instance(instance_id):
                continue
            if store.add_tag_hold(instance_id, allowance, month):
                alerts.emit(
                    Alert(
                        audience="ops",
                        kind="unknown-tag",
                        month=month,
                        estimated_cents=store.get_accrued(month),
                        overage_cents=0,
                        cause="tagged instance has no watcher ownership record and was not touched",
                        instance_ids=(instance_id,),
                    )
                )
    accrued = store.get_accrued(month)
    if accrued < grace:
        return BudgetResult(False, uncertain, (), (), ())

    try:
        views = ec2.describe_instances([item["instanceId"] for item in store.list_open_instances()])
    except Exception:
        views = {}
        uncertain = True

    eligible: list[StopCandidate] = []
    excluded_over: list[str] = []
    open_instances = store.list_open_instances()
    for inst in open_instances:
        instance_id = inst["instanceId"]
        view = views.get(instance_id)
        if view and not view.uncertain and view.state == "terminated":
            store.close_instance(instance_id)
            continue
        if view is None or view.uncertain or not view.has_tag or view.state not in {"pending", "running"}:
            if _once(store, f"INST#{instance_id}", "ALERT#UNKNOWN", kind="unknown-ownership"):
                alerts.emit(
                    Alert(
                        audience="ops",
                        kind="unknown-ownership",
                        month=month,
                        estimated_cents=accrued,
                        overage_cents=max(0, accrued - soft_cap),
                        cause="instance is missing a watcher tag or a clear EC2 state and was not touched",
                        instance_ids=(instance_id,),
                    )
                )
            continue
        debit = int(inst.get("debitByMonth", {}).get(month, 0))
        candidate = StopCandidate(
            instance_id=instance_id,
            month_debit=debit,
            launch_epoch=int(inst["launchEpoch"]),
            workflow_name=str(inst.get("workflowName", "")),
            job_name=str(inst.get("jobName", "")),
            labels=tuple(inst.get("labels") or ()),
            workflow_run_id=str(inst.get("workflowRunId", "")),
            owner=str(inst.get("owner", "")),
            repo_name=str(inst.get("repoName", "")),
        )
        if not candidate.workflow_run_id or not candidate.workflow_name:
            if _once(store, f"INST#{instance_id}", "ALERT#UNKNOWN", kind="unknown-ownership"):
                alerts.emit(
                    Alert(
                        audience="ops",
                        kind="unknown-ownership",
                        month=month,
                        estimated_cents=accrued,
                        overage_cents=max(0, accrued - soft_cap),
                        cause="assigned overflow job is unknown and the instance was not touched",
                        instance_ids=(instance_id,),
                    )
                )
            continue
        if _excluded(candidate, exclusions):
            excluded_over.append(instance_id)
            continue
        eligible.append(candidate)

    chosen = select_minimum(eligible, accrued, grace)
    cancelled: list[str] = []
    terminated: list[str] = []
    spared: list[str] = []
    for candidate in chosen:
        outcome = _advance_candidate(
            store=store,
            ec2=ec2,
            ec2_api=ec2_api,
            github=github,
            alerts=alerts,
            candidate=candidate,
            now=now,
            month=month,
            cancel_wait=cancel_wait,
            accrued=accrued,
            soft_cap=soft_cap,
        )
        if outcome == "cancelled":
            cancelled.append(candidate.instance_id)
        elif outcome == "terminated":
            terminated.append(candidate.instance_id)
        elif outcome == "spared":
            spared.append(candidate.instance_id)

    if not chosen and (excluded_over or eligible):
        if _once(store, f"MONTH#{month}", "ALERT#STILLOVER", kind="still-over-grace"):
            alerts.emit(
                Alert(
                    audience="john-and-ops",
                    kind="still-over-grace",
                    month=month,
                    estimated_cents=accrued,
                    overage_cents=max(0, accrued - soft_cap),
                    cause=(
                        "estimated spend remains over the grace after excluding "
                        "untouchable work; no broader stop was performed"
                    ),
                    instance_ids=tuple(excluded_over),
                )
            )
    if cancelled or terminated:
        acted = tuple(cancelled + terminated)
        alerts.emit(
            Alert(
                audience="john-and-ops",
                kind="budget-stop",
                month=month,
                estimated_cents=accrued,
                overage_cents=max(0, accrued - soft_cap),
                cause=(
                    "estimated month spend reached the grace threshold; "
                    "the minimum watcher-owned set was cancelled or terminated. "
                    "The grace figure is an estimate, not an invoice limit"
                ),
                instance_ids=acted,
            )
        )
    return BudgetResult(True, uncertain, tuple(cancelled), tuple(terminated), tuple(spared))


def _advance_candidate(
    *,
    store: Store,
    ec2: Ec2Reads,
    ec2_api: Any,
    github: GitHubActions,
    alerts: AlertLog,
    candidate: StopCandidate,
    now: int,
    month: str,
    cancel_wait: int,
    accrued: int,
    soft_cap: int,
) -> str:
    pk = f"STOP#{month}"
    sk = f"INST#{candidate.instance_id}"
    marker = store.get_marker(pk, sk)
    if marker is None:
        claimed = store.claim(
            pk,
            sk,
            {
                "phase": "cancel_wait",
                "deadline": now + cancel_wait,
                "cancelStatus": "pending",
                "unknownAlerted": 0,
            },
        )
        if not claimed:
            return "noop"
        status = "requested"
        try:
            github.cancel_workflow_run(candidate.owner, candidate.repo_name, candidate.workflow_run_id)
        except Exception:
            status = "unavailable"
        store.update_marker(pk, sk, {"cancelStatus": status})
        return "cancelled"
    if marker.get("phase") != "cancel_wait":
        return "noop"
    deadline = int(marker.get("deadline", 0))
    if now < deadline:
        return "noop"
    try:
        views = ec2.describe_instances([candidate.instance_id])
    except Exception:
        views = {}
    view = views.get(candidate.instance_id)
    if view is None or view.uncertain or view.state is None or not view.has_tag:
        if not int(marker.get("unknownAlerted", 0)):
            alerts.emit(
                Alert(
                    audience="ops",
                    kind="ambiguous-instance",
                    month=month,
                    estimated_cents=accrued,
                    overage_cents=max(0, accrued - soft_cap),
                    cause="DescribeInstances state was unknown; instance was not terminated",
                    instance_ids=(candidate.instance_id,),
                )
            )
            store.update_marker(pk, sk, {"unknownAlerted": 1})
        return "noop"
    if view.state == "terminated":
        store.close_instance(candidate.instance_id)
        store.update_marker(pk, sk, {"phase": "observed_terminated"})
        return "spared"
    if view.state == "shutting-down":
        store.update_marker(pk, sk, {"phase": "finished_during_wait"})
        return "spared"
    completed = github.workflow_completed(candidate.owner, candidate.repo_name, candidate.workflow_run_id)
    if completed is True:
        store.update_marker(pk, sk, {"phase": "finished_during_wait"})
        return "spared"
    if view.state in {"running", "pending"}:
        advance_owned_stop(ec2_api, candidate.instance_id)
        store.update_marker(pk, sk, {"phase": "api_terminated"})
        return "terminated"
    store.update_marker(pk, sk, {"phase": "not_running"})
    return "spared"
