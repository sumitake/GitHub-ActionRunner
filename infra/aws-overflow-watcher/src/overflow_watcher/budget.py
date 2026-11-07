# SPDX-License-Identifier: MPL-2.0
"""C4b budget stop. The only TerminateInstances call site lives here."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from typing import Any

from overflow_watcher.money import month_key, remaining_future_cents, select_minimum
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
    logged: bool = False


def alert_dict(alert: Alert) -> dict[str, Any]:
    return {
        "audience": alert.audience,
        "kind": alert.kind,
        "month": alert.month,
        "estimatedCents": alert.estimated_cents,
        "overageCents": alert.overage_cents,
        "cause": alert.cause,
        "instanceIds": list(alert.instance_ids),
    }


def write_alert_line(alert: Alert) -> None:
    """One JSON log line. Callers claim delivery only after this returns."""
    print(json.dumps(alert_dict(alert), sort_keys=True), flush=True)
    alert.logged = True


@dataclass
class AlertLog:
    items: list[Alert] = field(default_factory=list)

    def emit(self, alert: Alert) -> None:
        self.items.append(alert)


@dataclass
class BudgetResult:
    fired: bool
    uncertain: bool
    block_launch: bool
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


def deliver_month_alert(store: Store, month: str, name: str, alert: Alert, alerts: AlertLog) -> None:
    """Emit first. The month claim is written only after that emit succeeds."""
    confirmed = f"ALERT#{name}"
    retry = f"ALERT#{name}#RETRY"
    if store.get_marker(f"MONTH#{month}", confirmed):
        return
    try:
        write_alert_line(alert)
        alerts.emit(alert)
    except Exception:
        store.claim(f"MONTH#{month}", retry, {"kind": name})
        return
    store.claim(f"MONTH#{month}", confirmed, {"kind": name})


def _revalidate(ec2: Ec2Reads, candidate: StopCandidate, exclusions: tuple) -> tuple[str, Any]:
    """Ownership, tag, exclusion, and state, read immediately before a stop."""
    try:
        views = ec2.describe_instances([candidate.instance_id])
    except Exception:
        return "blocked", None
    view = views.get(candidate.instance_id)
    if view is None or view.uncertain or not view.has_tag or view.state is None:
        return "blocked", view
    if view.state not in {"pending", "running"}:
        return "spared", view
    if _excluded(candidate, exclusions):
        return "spared", view
    return "stop", view


def _unknown_alert(
    store: Store,
    month: str,
    instance_id: str,
    accrued: int,
    soft_cap: int,
    alerts: AlertLog,
    cause: str,
) -> None:
    deliver_month_alert(
        store,
        month,
        f"UNKNOWN-{instance_id}",
        Alert(
            audience="ops",
            kind="unknown-ownership",
            month=month,
            estimated_cents=accrued,
            overage_cents=max(0, accrued - soft_cap),
            cause=cause,
            instance_ids=(instance_id,),
        ),
        alerts,
    )


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
    """Stop avoidable future burn when the projection is above the grace ceiling."""
    month = month_key(now)
    uncertain = False
    block_launch = False
    tagged = ec2.list_tagged_ids()
    if tagged is None:
        uncertain = True
        block_launch = True
        deliver_month_alert(
            store,
            month,
            "EC2READ",
            Alert(
                audience="ops",
                kind="ec2-uncertain",
                month=month,
                estimated_cents=store.get_accrued(month),
                overage_cents=0,
                cause="tagged-instance read failed; no new launch is admitted",
            ),
            alerts,
        )
    else:
        for instance_id in tagged:
            if store.has_instance(instance_id):
                continue
            block_launch = True
            uncertain = True
            store.add_tag_hold(instance_id, allowance, month)
            deliver_month_alert(
                store,
                month,
                f"TAG-{instance_id}",
                Alert(
                    audience="ops",
                    kind="unknown-tag",
                    month=month,
                    estimated_cents=store.get_accrued(month),
                    overage_cents=0,
                    cause="tagged instance has no watcher ownership record; it was not stopped and no new launch is admitted",
                    instance_ids=(instance_id,),
                ),
                alerts,
            )
    accrued = store.get_accrued(month)
    try:
        views = ec2.describe_instances([item["instanceId"] for item in store.list_open_instances()])
    except Exception:
        views = {}
        uncertain = True

    eligible: list[StopCandidate] = []
    excluded_over: list[str] = []
    unresolved_future = 0
    transitional_future = 0
    open_instances = store.list_open_instances()
    for inst in open_instances:
        instance_id = inst["instanceId"]
        view = views.get(instance_id)
        if view and not view.uncertain and view.state == "terminated":
            store.close_instance(instance_id)
            continue
        future = remaining_future_cents(
            int(inst["launchEpoch"]),
            now,
            int(inst["priceNumer"]),
            int(inst["priceDenom"]),
        )
        if (
            view is not None
            and not view.uncertain
            and view.has_tag
            and view.state in {"stopping", "shutting-down"}
        ):
            transitional_future += future
            continue
        if view is None or view.uncertain or not view.has_tag or view.state not in {"pending", "running"}:
            block_launch = True
            uncertain = True
            unresolved_future += future
            _unknown_alert(
                store,
                month,
                instance_id,
                accrued,
                soft_cap,
                alerts,
                "instance ownership or state is unknown; it was not stopped and no new launch is admitted",
            )
            continue
        debit = int(inst.get("debitByMonth", {}).get(month, 0))
        candidate = StopCandidate(
            instance_id=instance_id,
            month_debit=debit,
            remaining_future=remaining_future_cents(
                int(inst["launchEpoch"]),
                now,
                int(inst["priceNumer"]),
                int(inst["priceDenom"]),
            ),
            launch_epoch=int(inst["launchEpoch"]),
            workflow_name=str(inst.get("workflowName", "")),
            job_name=str(inst.get("jobName", "")),
            labels=tuple(inst.get("labels") or ()),
            workflow_run_id=str(inst.get("workflowRunId", "")),
            owner=str(inst.get("owner", "")),
            repo_name=str(inst.get("repoName", "")),
        )
        if not candidate.workflow_run_id or not candidate.workflow_name:
            block_launch = True
            uncertain = True
            unresolved_future += future
            _unknown_alert(
                store,
                month,
                instance_id,
                accrued,
                soft_cap,
                alerts,
                "assigned overflow job is unknown; it was not stopped and no new launch is admitted",
            )
            continue
        if _excluded(candidate, exclusions):
            excluded_over.append(instance_id)
            continue
        eligible.append(candidate)

    excluded_future = 0
    for inst in open_instances:
        if inst["instanceId"] not in excluded_over:
            continue
        excluded_future += remaining_future_cents(
            int(inst["launchEpoch"]),
            now,
            int(inst["priceNumer"]),
            int(inst["priceDenom"]),
        )
    held_future = excluded_future + unresolved_future + transitional_future
    chosen = select_minimum(eligible, accrued, held_future, grace)
    projected = accrued + held_future + sum(item.remaining_future for item in eligible)
    if projected > grace:
        deliver_month_alert(
            store,
            month,
            "GRACE",
            Alert(
                audience="john-and-ops",
                kind="grace",
                month=month,
                estimated_cents=accrued,
                overage_cents=max(0, accrued - soft_cap),
                cause=(
                    "projected spend is above the grace ceiling; "
                    "only avoidable future burn is stopped and the ledger is not reduced. "
                    "The grace figure is an estimate, not an invoice limit"
                ),
                instance_ids=tuple(item.instance_id for item in chosen),
            ),
            alerts,
        )
    chosen_ids = {item.instance_id for item in chosen}
    for inst in open_instances:
        instance_id = str(inst["instanceId"])
        if instance_id in chosen_ids:
            continue
        stop_pk = f"STOP#{month}"
        stop_sk = f"INST#{instance_id}"
        marker = store.get_marker(stop_pk, stop_sk)
        if marker and marker.get("phase") == "cancel_wait":
            store.delete_marker(stop_pk, stop_sk)
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
            exclusions=exclusions,
        )
        if outcome == "blocked":
            block_launch = True
            uncertain = True
        if outcome == "cancelled":
            cancelled.append(candidate.instance_id)
        elif outcome == "terminated":
            terminated.append(candidate.instance_id)
        elif outcome == "spared":
            spared.append(candidate.instance_id)

    return BudgetResult(
        projected > grace,
        uncertain,
        block_launch,
        tuple(cancelled),
        tuple(terminated),
        tuple(spared),
    )


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
    exclusions: tuple,
) -> str:
    pk = f"STOP#{month}"
    sk = f"INST#{candidate.instance_id}"
    marker = store.get_marker(pk, sk)
    phase = str(marker.get("phase")) if marker else ""
    # A claim is kept only while this poll still selects an in-flight cancel.
    if phase == "cancel_wait" and now < int(marker.get("deadline", 0)):
        return "noop"
    if candidate.remaining_future <= 0:
        return "spared"
    gate, view = _revalidate(ec2, candidate, exclusions)
    if gate == "blocked":
        _unknown_alert(
            store,
            month,
            candidate.instance_id,
            accrued,
            soft_cap,
            alerts,
            "ownership, tag, or state failed revalidation; the instance was not stopped",
        )
        return "blocked"
    if gate != "stop":
        if view is not None and view.state == "terminated":
            store.close_instance(candidate.instance_id)
        return "spared"
    if phase == "cancel_wait":
        completed = github.workflow_completed(
            candidate.owner, candidate.repo_name, candidate.workflow_run_id
        )
        if completed is None:
            deliver_month_alert(
                store,
                month,
                f"WORKFLOW-{candidate.instance_id}",
                Alert(
                    audience="ops",
                    kind="ambiguous-workflow",
                    month=month,
                    estimated_cents=accrued,
                    overage_cents=max(0, accrued - soft_cap),
                    cause="workflow completion read was ambiguous; the cancel wait was left in place and the instance was not terminated",
                    instance_ids=(candidate.instance_id,),
                ),
                alerts,
            )
            return "noop"
        return _terminate_selected(store, ec2_api, candidate, pk, sk)
    if phase in {"api_terminated", "finished_during_wait", "observed_terminated"}:
        return _terminate_selected(store, ec2_api, candidate, pk, sk)
    if marker is None:
        claimed = store.claim(
            pk,
            sk,
            {
                "phase": "cancel_wait",
                "deadline": now + cancel_wait,
                "cancelStatus": "pending",
            },
        )
        if not claimed:
            return "noop"
    else:
        store.update_marker(
            pk,
            sk,
            {"phase": "cancel_wait", "deadline": now + cancel_wait, "cancelStatus": "pending"},
        )
    status = "requested"
    try:
        github.cancel_workflow_run(candidate.owner, candidate.repo_name, candidate.workflow_run_id)
    except Exception:
        status = "unavailable"
    store.update_marker(pk, sk, {"cancelStatus": status})
    return "cancelled"


def _terminate_selected(store: Store, ec2_api: Any, candidate: StopCandidate, pk: str, sk: str) -> str:
    advance_owned_stop(ec2_api, candidate.instance_id)
    if store.get_marker(pk, sk) is None:
        store.claim(pk, sk, {"phase": "api_terminated"})
    else:
        store.update_marker(pk, sk, {"phase": "api_terminated"})
    return "terminated"
