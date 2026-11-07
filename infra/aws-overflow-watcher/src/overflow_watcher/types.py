# SPDX-License-Identifier: MPL-2.0
"""Shared values for the overflow watcher."""

from __future__ import annotations

from dataclasses import dataclass

WATCHER_TAG_NAME = "overflow-watcher"
TAG_VALUE = "owned"
ALLOWANCE_SECONDS = 6 * 3600
QUEUE_SECONDS = 300
RETRY_WINDOW_SECONDS = 900
CAPACITY_COOLDOWN_SECONDS = 900
REPORT_AFTER_SECONDS = 1800


class CapacityRefused(Exception):
    """RunInstances refused for quota or capacity. The instance was not created."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class AmbiguousLaunch(Exception):
    """RunInstances ended without a definitive create-or-refuse outcome."""


class Ec2Uncertainty(Exception):
    """An EC2 read failed or was incomplete. Callers fail closed."""


class CancelUnavailable(Exception):
    """Workflow-run cancellation could not be performed."""


@dataclass(frozen=True)
class InstanceView:
    instance_id: str
    state: str | None
    has_tag: bool
    uncertain: bool


@dataclass(frozen=True)
class RepoSpec:
    repo_id: str
    owner: str
    name: str
    installation: str


@dataclass(frozen=True)
class Job:
    owner: str
    repo_name: str
    installation: str
    workflow_name: str
    job_name: str
    workflow_run_id: str
    labels: tuple[str, ...]
    queued_epoch: int


@dataclass(frozen=True)
class Decision:
    uncertain: bool
    reason: str
    jobs: tuple[Job, ...]


@dataclass(frozen=True)
class StopCandidate:
    instance_id: str
    month_debit: int
    remaining_future: int
    launch_epoch: int
    workflow_name: str
    job_name: str
    labels: tuple[str, ...]
    workflow_run_id: str
    owner: str
    repo_name: str
