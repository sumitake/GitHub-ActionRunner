# SPDX-License-Identifier: MPL-2.0
"""One poll at a time without Lambda reserved concurrency: the poll lease."""

from __future__ import annotations

import unittest

from fakes import FakeEc2, FakeGitHub, FakeSsm
from support import NOW, cfg, fresh_store, sample_job

from overflow_watcher.controller import run_poll
from overflow_watcher.types import POLL_LEASE_SECONDS, Decision

JIT_FIXTURE = "zz-jit-fixture-poll-lease-7b1c-zz"


def _admitted() -> FakeGitHub:
    github = FakeGitHub()
    job = sample_job()
    github.decision = Decision(False, "assessed", (job,), (job.job_id,))
    github.mint_secret = JIT_FIXTURE
    return github


def _table(store) -> list:
    items = store.client.scan(TableName=store.table, ConsistentRead=True)["Items"]
    return sorted(items, key=lambda item: (item["pk"]["S"], item["sk"]["S"]))


class CountingGitHub(FakeGitHub):
    def __init__(self) -> None:
        super().__init__()
        self.assess_calls = 0

    def assess(self, repo, now: int) -> Decision:
        self.assess_calls += 1
        return super().assess(repo, now)


class RecordingClient:
    """Pass-through DynamoDB client that records every operation name."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.calls: list[str] = []

    def __getattr__(self, name):
        attr = getattr(self._inner, name)
        if callable(attr):
            def wrapped(*args, **kwargs):
                self.calls.append(name)
                return attr(*args, **kwargs)
            return wrapped
        return attr


class PollLeaseTests(unittest.TestCase):
    def test_overlapping_poll_writes_nothing(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        first = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(first.launched, 1)
        before = _table(store)
        calls = list(ec2.calls)
        mints = len(github.mint_calls)
        # A second invocation inside the lease window (async retry or duplicate delivery).
        second = run_poll(store, ec2, ec2, github, config, NOW + 30, ssm=ssm)
        self.assertEqual(second.blocked_reason, "poll-lease-held")
        self.assertEqual(second.launched, 0)
        self.assertIsNone(second.budget)
        self.assertEqual(ec2.calls, calls)
        self.assertEqual(len(github.mint_calls), mints)
        self.assertEqual(_table(store), before)

    def test_lease_is_reacquired_after_expiry(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = CountingGitHub()
        config = cfg()
        run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual(github.assess_calls, 1)
        at_edge = run_poll(store, ec2, ec2, github, config, NOW + POLL_LEASE_SECONDS)
        self.assertEqual(at_edge.blocked_reason, "poll-lease-held")
        self.assertEqual(github.assess_calls, 1)
        nxt = run_poll(store, ec2, ec2, github, config, NOW + 60)
        self.assertNotEqual(nxt.blocked_reason, "poll-lease-held")
        self.assertIsNotNone(nxt.budget)
        self.assertEqual(github.assess_calls, 2)
        lease = store.get_marker("LEASE#poll", "META")
        self.assertEqual(lease["expiresAt"], NOW + 60 + POLL_LEASE_SECONDS)

    def test_held_lease_stops_the_poll_before_any_read_or_write(self) -> None:
        # Fails if run_poll skips the lease check: the poll would read and write state.
        store = fresh_store()
        ec2 = FakeEc2()
        github = CountingGitHub()
        store.acquire_poll_lease = lambda now: False
        recorder = RecordingClient(store.client)
        store.client = recorder
        result = run_poll(store, ec2, ec2, github, cfg(), NOW, ssm=FakeSsm())
        self.assertEqual(result.blocked_reason, "poll-lease-held")
        self.assertEqual(recorder.calls, [])
        self.assertEqual(github.assess_calls, 0)
        self.assertEqual(ec2.calls, [])


if __name__ == "__main__":
    unittest.main()
