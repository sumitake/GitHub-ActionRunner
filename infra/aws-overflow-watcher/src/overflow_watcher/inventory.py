# SPDX-License-Identifier: MPL-2.0
"""Runner inventory and the five-minute queue rule. R4 / F2."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from overflow_watcher.labels import labels_admitted
from overflow_watcher.types import QUEUE_SECONDS, Decision, Job, RepoSpec


@dataclass(frozen=True)
class HttpPage:
    status: int
    headers: dict[str, str]
    body: object
    url: str


class Transport(Protocol):
    def get(self, url: str) -> HttpPage: ...


def reservations_released_by_ec2(index_count: int | None, described_empty: bool) -> bool:
    """R1: EC2 reads and index counts never release a reservation."""
    _ = (index_count, described_empty)
    return False


def empty_inventory_is_eligible(complete: bool, error: str | None) -> bool:
    """R4: a fully paginated empty result is overflow-eligible.

    Partial, malformed, or unauthorized inventory is unknown and is not eligible.
    """
    return complete and error is None


def _header(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def rate_limit_error(headers: dict[str, str], has_next: bool) -> str | None:
    """Missing or exhausted rate-limit headers fail closed.

    A final page that reports zero remaining has exhausted the budget for any
    further read, so the inventory is not treated as complete.
    """
    raw = _header(headers, "X-RateLimit-Remaining")
    if raw is None:
        return "missing-rate-limit"
    try:
        remaining = int(raw)
    except ValueError:
        return "malformed-rate-limit"
    if remaining <= 0:
        return "exhausted-rate-limit"
    _ = has_next
    return None


def next_link(headers: dict[str, str]) -> str | None:
    link = _header(headers, "Link")
    if not link:
        return None
    for part in link.split(","):
        if 'rel="next"' in part:
            url = part.split(";", 1)[0].strip()
            if url.startswith("<") and url.endswith(">"):
                return url[1:-1]
    return None


def parse_epoch(text: str | None) -> int | None:
    if not text:
        return None
    try:
        when = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(when.timestamp())


def _runner_label_names(runner: dict) -> set[str]:
    names: set[str] = set()
    for label in runner.get("labels") or []:
        if isinstance(label, str):
            names.add(label)
        elif isinstance(label, dict) and isinstance(label.get("name"), str):
            names.add(label["name"])
    return names


def matching_online(runners: list[dict], job_labels: tuple[str, ...]) -> bool:
    for runner in runners:
        if runner.get("status") != "online":
            continue
        names = _runner_label_names(runner)
        if all(label in names for label in job_labels):
            return True
    return False


def fetch_collection(
    transport: Transport, url: str, key: str, *, page_cap: int = 50
) -> tuple[list[dict] | None, str | None]:
    """Return (items, error). items is None when the read is not fully known."""
    items: list[dict] = []
    seen = 0
    while url:
        seen += 1
        if seen > page_cap:
            return None, "pagination-limit"
        page = transport.get(url)
        if page.status in (401, 403):
            return None, "unauthorized"
        if page.status != 200:
            return None, f"http-{page.status}"
        nxt = next_link(page.headers)
        limit_error = rate_limit_error(page.headers, nxt is not None)
        if limit_error:
            return None, limit_error
        if not isinstance(page.body, dict):
            return None, "malformed"
        chunk = page.body.get(key)
        if not isinstance(chunk, list):
            return None, "malformed"
        for entry in chunk:
            if not isinstance(entry, dict):
                return None, "malformed"
            items.append(entry)
        if not nxt:
            break
        url = nxt
    return items, None


def judge_jobs(
    *,
    runners: list[dict] | None,
    runner_error: str | None,
    jobs: list[dict],
    now: int,
    repo: RepoSpec,
    workflow_name: str,
    workflow_run_id: str,
) -> Decision:
    if not empty_inventory_is_eligible(runners is not None, runner_error):
        return Decision(True, runner_error or "unknown-runners", ())
    eligible: list[Job] = []
    assert runners is not None
    for job in jobs:
        if job.get("status") != "queued":
            continue
        raw_labels = job.get("labels")
        if not isinstance(raw_labels, list) or not all(isinstance(item, str) for item in raw_labels):
            continue
        labels = tuple(raw_labels)
        if not labels_admitted(labels):
            continue
        queued = parse_epoch(job.get("created_at") if isinstance(job.get("created_at"), str) else None)
        if queued is None or now - queued < QUEUE_SECONDS:
            continue
        if matching_online(runners, labels):
            continue
        name = job.get("name")
        job_name = name if isinstance(name, str) and name else ""
        eligible.append(
            Job(
                owner=repo.owner,
                repo_name=repo.name,
                installation=repo.installation,
                workflow_name=workflow_name,
                job_name=job_name,
                workflow_run_id=workflow_run_id,
                labels=labels,
                queued_epoch=queued,
            )
        )
    return Decision(False, "no-matching-capacity" if not runners else "assessed", tuple(eligible))


def assess_repo(transport: Transport, repo: RepoSpec, now: int) -> Decision:
    base = f"https://api.github.com/repos/{repo.owner}/{repo.name}"
    runners, runner_error = fetch_collection(
        transport, f"{base}/actions/runners?per_page=100", "runners"
    )
    runner_complete = runners is not None and runner_error is None
    if not empty_inventory_is_eligible(runner_complete, runner_error):
        return Decision(True, runner_error or "unknown-runners", ())
    runners = runners or []
    runs, run_error = fetch_collection(
        transport,
        f"{base}/actions/runs?status=queued&per_page=100",
        "workflow_runs",
    )
    if not empty_inventory_is_eligible(runs is not None and run_error is None, run_error):
        return Decision(True, run_error or "unknown-runs", ())
    runs = runs or []
    collected: list[Job] = []
    for run in runs:
        if run.get("status") not in (None, "queued", "pending", "waiting"):
            continue
        run_id = run.get("id")
        if not isinstance(run_id, int):
            return Decision(True, "malformed", ())
        workflow_name = run.get("name") if isinstance(run.get("name"), str) else ""
        jobs, job_error = fetch_collection(
            transport,
            f"{base}/actions/runs/{run_id}/jobs?per_page=100",
            "jobs",
        )
        if not empty_inventory_is_eligible(jobs is not None and job_error is None, job_error):
            return Decision(True, job_error or "unknown-jobs", ())
        jobs = jobs or []
        decision = judge_jobs(
            runners=runners,
            runner_error=None,
            jobs=jobs,
            now=now,
            repo=repo,
            workflow_name=workflow_name,
            workflow_run_id=str(run_id),
        )
        if decision.uncertain:
            return decision
        collected.extend(decision.jobs)
    reason = "no-matching-capacity" if not runners else "assessed"
    return Decision(False, reason, tuple(collected))
