# SPDX-License-Identifier: MPL-2.0
"""R4: fully paginated empty inventory is eligible; partial inventory is not."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from support import NOW

from overflow_watcher.inventory import HttpPage, assess_repo
from overflow_watcher.types import RepoSpec

REPO = RepoSpec("101", "example", "keicrew", "201")
BASE = "https://api.github.com/repos/example/keicrew"


def _stamp(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _page(body, status: int = 200, remaining: str | None = "20", link: str | None = None) -> HttpPage:
    headers: dict[str, str] = {}
    if remaining is not None:
        headers["X-RateLimit-Remaining"] = remaining
    if link:
        headers["Link"] = link
    return HttpPage(status, headers, body, BASE)


class ScriptTransport:
    def __init__(self, routes: dict[str, list[HttpPage]]) -> None:
        self.routes = {key: list(value) for key, value in routes.items()}

    def get(self, url: str) -> HttpPage:
        queue = self.routes.get(url)
        if not queue:
            return _page(None, status=500, remaining="20")
        return queue.pop(0)


def _routes(runners, jobs=None, *, runner_pages: list[HttpPage] | None = None) -> dict[str, list[HttpPage]]:
    if jobs is None:
        jobs = ["self-hosted", "Linux"]
    created = _stamp(NOW - 600)
    job_body = {
        "jobs": [
            {
                "id": 4242,
                "status": "queued",
                "name": "test",
                "labels": list(jobs),
                "created_at": created,
            }
        ]
    }
    return {
        f"{BASE}/actions/runners?per_page=100": runner_pages
        or [_page({"runners": runners})],
        f"{BASE}/actions/runs?status=queued&per_page=100": [
            _page({"workflow_runs": [{"id": 7, "status": "queued", "name": "CI"}]})
        ],
        f"{BASE}/actions/runs/7/jobs?per_page=100": [_page(job_body)],
    }


class InventoryTests(unittest.TestCase):
    def test_r4_fully_paginated_empty_is_overflow_eligible(self) -> None:
        decision = assess_repo(ScriptTransport(_routes([])), REPO, NOW)
        self.assertFalse(decision.uncertain)
        self.assertEqual(len(decision.jobs), 1)
        self.assertEqual(decision.reason, "no-matching-capacity")

    def test_r4_partial_malformed_or_unauthorized_does_not_launch(self) -> None:
        partial = _routes(
            [],
            ["self-hosted", "Linux"],
            runner_pages=[
                _page({"runners": []}, link='<https://api.github.com/runners-next>; rel="next"'),
                _page({"runners": []}, status=500),
            ],
        )
        partial["https://api.github.com/runners-next"] = [_page({"runners": []}, status=500)]
        self.assertTrue(assess_repo(ScriptTransport(partial), REPO, NOW).uncertain)

        malformed = _routes([])
        malformed[f"{BASE}/actions/runners?per_page=100"] = [_page(["not-an-object"])]
        self.assertTrue(assess_repo(ScriptTransport(malformed), REPO, NOW).uncertain)

        denied = _routes([])
        denied[f"{BASE}/actions/runners?per_page=100"] = [_page({"runners": []}, status=401)]
        self.assertTrue(assess_repo(ScriptTransport(denied), REPO, NOW).uncertain)

        missing_limit = _routes([])
        missing_limit[f"{BASE}/actions/runners?per_page=100"] = [_page({"runners": []}, remaining=None)]
        self.assertTrue(assess_repo(ScriptTransport(missing_limit), REPO, NOW).uncertain)

        recent = _routes([])
        recent[f"{BASE}/actions/runs/7/jobs?per_page=100"] = [
            _page(
                {
                    "jobs": [
                        {
                            "id": 4242,
                            "status": "queued",
                            "name": "test",
                            "labels": ["self-hosted", "Linux"],
                            "created_at": _stamp(NOW - 60),
                        }
                    ]
                }
            )
        ]
        self.assertEqual(assess_repo(ScriptTransport(recent), REPO, NOW).jobs, ())

        denied_label = assess_repo(
            ScriptTransport(_routes([], ["self-hosted", "ubuntu-24.04"])), REPO, NOW
        )
        self.assertEqual(denied_label.jobs, ())
        self.assertFalse(denied_label.uncertain)

        online = _routes(
            [{"status": "online", "busy": False, "labels": [{"name": "self-hosted"}, {"name": "Linux"}]}]
        )
        idle = assess_repo(ScriptTransport(online), REPO, NOW)
        self.assertEqual(idle.jobs, ())
        self.assertFalse(idle.uncertain)

        offline = _routes([{"status": "offline", "labels": [{"name": "self-hosted"}, {"name": "Linux"}]}])
        self.assertEqual(len(assess_repo(ScriptTransport(offline), REPO, NOW).jobs), 1)


if __name__ == "__main__":
    unittest.main()
