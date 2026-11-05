# SPDX-License-Identifier: MPL-2.0
"""In-process EC2 and GitHub stand-ins. No network."""

from __future__ import annotations

from overflow_watcher.types import (
    AmbiguousLaunch,
    CancelUnavailable,
    CapacityRefused,
    Decision,
    InstanceView,
)


class FakeEc2:
    def __init__(self) -> None:
        self.by_token: dict[str, str] = {}
        self.calls: list[str] = []
        self.quota = False
        self.ambiguous = False
        self.views: dict[str, InstanceView] = {}
        self.tagged: list[str] = []
        self.list_fails = False
        self.terminate_calls: list[list[str]] = []
        self.index = 0
        self._seq = 0

    def run_instances(self, token: str, params: dict) -> str:
        del params
        self.calls.append(token)
        if self.ambiguous:
            raise AmbiguousLaunch("timeout")
        if token in self.by_token:
            return self.by_token[token]
        if self.quota:
            raise CapacityRefused("VcpuLimitExceeded")
        self._seq += 1
        instance_id = f"i-{self._seq}"
        self.by_token[token] = instance_id
        self.views[instance_id] = InstanceView(instance_id, "running", True, False)
        if instance_id not in self.tagged:
            self.tagged.append(instance_id)
        return instance_id

    def describe_instances(self, ids: list[str]) -> dict[str, InstanceView]:
        return {
            instance_id: self.views.get(
                instance_id, InstanceView(instance_id, None, False, True)
            )
            for instance_id in ids
        }

    def list_tagged_ids(self) -> list[str] | None:
        if self.list_fails:
            return None
        return list(self.tagged)

    def index_count(self) -> int:
        return self.index

    def terminate_instances(self, InstanceIds: list[str]) -> None:
        self.terminate_calls.append(list(InstanceIds))
        for instance_id in InstanceIds:
            current = self.views.get(instance_id)
            has_tag = True if current is None else current.has_tag
            self.views[instance_id] = InstanceView(instance_id, "terminated", has_tag, False)


class FakeGitHub:
    def __init__(self) -> None:
        self.decision = Decision(False, "assessed", ())
        self.cancel_calls: list[tuple[str, str, str]] = []
        self.cancel_error: str | None = None
        self.completed: set[str] = set()

    def assess(self, repo, now: int) -> Decision:
        del repo, now
        return self.decision

    def cancel_workflow_run(self, owner: str, repo: str, run_id: str) -> str:
        self.cancel_calls.append((owner, repo, run_id))
        if self.cancel_error:
            raise CancelUnavailable(self.cancel_error)
        return "requested"

    def workflow_completed(self, owner: str, repo: str, run_id: str) -> bool:
        del owner, repo
        return run_id in self.completed
