# SPDX-License-Identifier: MPL-2.0
"""Idle-runner reaper: deregister, then terminate. Unknown GitHub state waits."""

from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request
from email.message import Message
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from fakes import FakeEc2, FakeGitHub, FakeSsm
from support import NOW, cfg, clear_poll_lease, fresh_store, sample_job, seed_instance, watcher_env

from overflow_watcher.config import load_config
from overflow_watcher.controller import run_poll
from overflow_watcher.github_api import LiveGitHub
from overflow_watcher.money import month_key
from overflow_watcher.types import Decision, InstanceView

ROOT = Path(__file__).resolve().parents[1]
RUNNER = 8675309


def _seed(
    store,
    ec2,
    instance_id: str,
    *,
    runner_id: int | None = RUNNER,
    launch_epoch: int = NOW - 1000,
    state: str | None = "running",
    has_tag: bool = True,
    uncertain: bool = False,
) -> None:
    seed_instance(
        store,
        ec2,
        instance_id=instance_id,
        debit=10,
        month=month_key(NOW),
        launch_epoch=launch_epoch,
        state=state,
        has_tag=has_tag,
        uncertain=uncertain,
        github_runner_id=runner_id,
    )


def _idle_github() -> FakeGitHub:
    github = FakeGitHub()
    github.runner_get = (200, False)
    github.delete_status = 204
    return github


def _trace(github: FakeGitHub, ec2: FakeEc2) -> list:
    order: list[tuple] = []
    raw_get = github.get_runner
    raw_delete = github.delete_runner
    raw_terminate = ec2.terminate_instances

    def get_runner(owner, repo, runner_id):
        order.append(("get", owner, repo, runner_id))
        return raw_get(owner, repo, runner_id)

    def delete_runner(owner, repo, runner_id):
        order.append(("delete", owner, repo, runner_id))
        return raw_delete(owner, repo, runner_id)

    def terminate_instances(InstanceIds):
        order.append(("terminate", list(InstanceIds)))
        return raw_terminate(InstanceIds)

    github.get_runner = get_runner  # type: ignore[method-assign]
    github.delete_runner = delete_runner  # type: ignore[method-assign]
    ec2.terminate_instances = terminate_instances  # type: ignore[method-assign]
    return order


def _lines(buffer: StringIO) -> list[dict]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


class IdleReaperTests(unittest.TestCase):
    def test_idle_past_grace_deletes_then_terminates_stored_runner(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        _seed(store, ec2, "i-idle", launch_epoch=NOW - 1000)
        order = _trace(github, ec2)
        buffer = StringIO()
        with patch("sys.stdout", buffer):
            result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        saved = store.get_instance("i-idle")
        assert saved is not None
        self.assertEqual(saved["githubRunnerId"], RUNNER)
        self.assertEqual(github.runner_deletes, [("example", "keicrew", RUNNER)])
        self.assertEqual(
            order,
            [
                ("get", "example", "keicrew", RUNNER),
                ("delete", "example", "keicrew", RUNNER),
                ("terminate", ["i-idle"]),
            ],
        )
        self.assertEqual(ec2.terminate_calls, [["i-idle"]])
        self.assertEqual(
            _lines(buffer),
            [
                {
                    "idle_s": 1000,
                    "instance": "i-idle",
                    "kind": "idle-reap",
                    "result": "terminated",
                    "runner_id": RUNNER,
                }
            ],
        )
        self.assertIsNotNone(result.budget)

    def test_offline_and_busy_false_past_grace_is_reaped(self) -> None:
        # The read is only (status, busy). Offline is not a separate gate.
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        github.runner_get = (200, False)
        _seed(store, ec2, "i-off")
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.runner_deletes, [("example", "keicrew", RUNNER)])
        self.assertEqual(ec2.terminate_calls, [["i-off"]])

    def test_busy_runner_past_grace_is_left_alone(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        github.runner_get = (200, True)
        _seed(store, ec2, "i-busy")
        buffer = StringIO()
        with patch("sys.stdout", buffer):
            run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.runner_gets, [("example", "keicrew", RUNNER)])
        self.assertEqual(github.runner_deletes, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(_lines(buffer), [])
        self.assertEqual(store.get_instance("i-busy")["state"], "OPEN")

    def test_delete_other_than_204_or_404_does_not_terminate(self) -> None:
        cases = {"422": 422, "409": 409, "403": 403, "400": 400, "500": 500, "network": None}
        for name, status in cases.items():
            with self.subTest(name=name):
                store = fresh_store()
                ec2 = FakeEc2()
                github = _idle_github()
                github.delete_status = status
                _seed(store, ec2, "i-race")
                run_poll(store, ec2, ec2, github, cfg(), NOW)
                self.assertEqual(github.runner_deletes, [("example", "keicrew", RUNNER)])
                self.assertEqual(ec2.terminate_calls, [])
                self.assertEqual(store.get_instance("i-race")["state"], "OPEN")

    def test_delete_404_terminates(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        github.delete_status = 404
        _seed(store, ec2, "i-gone")
        order = _trace(github, ec2)
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([item[0] for item in order], ["get", "delete", "terminate"])
        self.assertEqual(ec2.terminate_calls, [["i-gone"]])

    def test_unknown_read_skips_and_a_later_poll_reaps(self) -> None:
        cases: dict[str, tuple[int | None, bool | None] | str] = {
            "error": "raise",
            "network": (None, None),
            "token": (None, None),
            "http-500": (500, False),
            "http-401": (401, None),
            "http-403": (403, False),
            "busy-missing": (200, None),
            "busy-non-bool": (200, None),
        }
        for name, read in cases.items():
            with self.subTest(name=name):
                store = fresh_store()
                ec2 = FakeEc2()
                github = _idle_github()
                _seed(store, ec2, "i-later")
                if read == "raise":
                    github.fail_get = True
                else:
                    github.runner_get = read  # type: ignore[assignment]
                run_poll(store, ec2, ec2, github, cfg(), NOW)
                self.assertEqual(github.runner_deletes, [])
                self.assertEqual(ec2.terminate_calls, [])
                self.assertEqual(store.get_instance("i-later")["state"], "OPEN")
                github.fail_get = False
                github.runner_get = (200, False)
                github.delete_status = 204
                clear_poll_lease(store)
                run_poll(store, ec2, ec2, github, cfg(), NOW)
                self.assertEqual(github.runner_deletes, [("example", "keicrew", RUNNER)])
                self.assertEqual(ec2.terminate_calls, [["i-later"]])

    def test_get_404_terminates_without_delete(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        github.runner_get = (404, None)
        _seed(store, ec2, "i-missing")
        order = _trace(github, ec2)
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([item[0] for item in order], ["get", "terminate"])
        self.assertEqual(github.runner_deletes, [])
        self.assertEqual(ec2.terminate_calls, [["i-missing"]])

    def test_younger_than_grace_is_kept_and_exact_grace_is_reaped(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        grace = cfg().idle_reap_grace
        self.assertEqual(grace, 600)
        _seed(store, ec2, "i-young", runner_id=1, launch_epoch=NOW - (grace - 1))
        _seed(store, ec2, "i-due", runner_id=2, launch_epoch=NOW - grace)
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.runner_gets, [("example", "keicrew", 2)])
        self.assertEqual(github.runner_deletes, [("example", "keicrew", 2)])
        self.assertEqual(ec2.terminate_calls, [["i-due"]])
        self.assertEqual(store.get_instance("i-young")["state"], "OPEN")

    def test_grace_zero_reaps_nothing_and_still_polls(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        github.decision = Decision(False, "queued", (sample_job(job_id="4242"),))
        _seed(store, ec2, "i-old", launch_epoch=NOW - 5000)
        loaded = cfg(IDLE_REAP_GRACE_SECONDS="0")
        self.assertTrue(loaded.launch_allowed)
        self.assertEqual(loaded.idle_reap_grace, 0)
        result = run_poll(store, ec2, ec2, github, loaded, NOW, ssm=FakeSsm())
        self.assertEqual(github.runner_gets, [])
        self.assertEqual(github.runner_deletes, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(result.launched, 1)
        self.assertIsNotNone(result.budget)
        self.assertEqual(store.get_instance("i-old")["state"], "OPEN")

    def test_ec2_uncertain_untagged_or_not_running_is_skipped(self) -> None:
        cases = {
            "uncertain": {"uncertain": True},
            "untagged": {"has_tag": False},
            "pending": {"state": "pending"},
            "stopping": {"state": "stopping"},
            "shutting-down": {"state": "shutting-down"},
            "stopped": {"state": "stopped"},
        }
        for name, flags in cases.items():
            with self.subTest(name=name):
                store = fresh_store()
                ec2 = FakeEc2()
                github = _idle_github()
                _seed(store, ec2, "i-skip", **flags)
                run_poll(store, ec2, ec2, github, cfg(), NOW)
                self.assertEqual(github.runner_gets, [])
                self.assertEqual(github.runner_deletes, [])
                self.assertEqual(ec2.terminate_calls, [])

    def test_record_without_github_runner_id_is_skipped(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        _seed(store, ec2, "i-legacy", runner_id=None, launch_epoch=NOW - 5000)
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertIsNone(store.get_instance("i-legacy").get("githubRunnerId"))
        self.assertEqual(github.runner_gets, [])
        self.assertEqual(github.runner_deletes, [])
        self.assertEqual(ec2.terminate_calls, [])

    def test_cancel_wait_is_skipped_and_api_terminated_is_reaped(self) -> None:
        month = month_key(NOW)
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        _seed(store, ec2, "i-wait", runner_id=11)
        _seed(store, ec2, "i-left", runner_id=12)
        self.assertTrue(
            store.claim(f"STOP#{month}", "INST#i-wait", {"phase": "cancel_wait", "deadline": NOW + 30})
        )
        self.assertTrue(store.claim(f"STOP#{month}", "INST#i-left", {"phase": "api_terminated"}))
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertNotIn(11, [item[2] for item in github.runner_gets])
        self.assertEqual(github.runner_deletes, [("example", "keicrew", 12)])
        self.assertEqual(ec2.terminate_calls, [["i-left"]])
        self.assertEqual(store.get_instance("i-wait")["state"], "OPEN")

    def test_cap_checks_five_oldest_running_runners(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        _seed(store, ec2, "i-down", runner_id=1, launch_epoch=NOW - 9000, state="stopped")
        running = []
        for offset, runner_id in enumerate((10, 11, 12, 13, 14, 15)):
            instance_id = f"i-{runner_id}"
            _seed(store, ec2, instance_id, runner_id=runner_id, launch_epoch=NOW - 8000 + offset)
            running.append((instance_id, runner_id))
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        checked = [item[2] for item in github.runner_gets]
        self.assertEqual(checked, [10, 11, 12, 13, 14])
        self.assertNotIn(1, checked)
        self.assertNotIn(15, checked)
        self.assertEqual(ec2.terminate_calls, [["i-10"], ["i-11"], ["i-12"], ["i-13"], ["i-14"]])
        self.assertEqual(store.get_instance("i-15")["state"], "OPEN")
        self.assertEqual(store.get_instance("i-down")["state"], "OPEN")

    def test_busy_rows_count_toward_the_cap(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        for offset, runner_id in enumerate((10, 11, 12, 13, 14)):
            github.runner_by_id[runner_id] = (200, True)
            _seed(store, ec2, f"i-{runner_id}", runner_id=runner_id, launch_epoch=NOW - 8000 + offset)
        github.runner_by_id[15] = (200, False)
        _seed(store, ec2, "i-15", runner_id=15, launch_epoch=NOW - 1000)
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([item[2] for item in github.runner_gets], [10, 11, 12, 13, 14])
        self.assertEqual(github.runner_deletes, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(store.get_instance("i-15")["state"], "OPEN")

    def test_reaper_exception_still_budget_stops_and_launches(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _idle_github()
        github.fail_get = True
        github.decision = Decision(False, "queued", (sample_job(job_id="4242"),))
        _seed(store, ec2, "i-boom")
        buffer = StringIO()
        with patch("sys.stdout", buffer):
            result = run_poll(store, ec2, ec2, github, cfg(), NOW, ssm=FakeSsm())
        self.assertEqual(result.launched, 1)
        self.assertIsNotNone(result.budget)
        self.assertEqual(result.blocked_reason, "")
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(github.runner_deletes, [])
        self.assertEqual(github.runner_gets, [("example", "keicrew", RUNNER)])
        self.assertEqual(_lines(buffer), [{"error": "RuntimeError", "kind": "idle-reap", "result": "aborted"}])
        self.assertEqual(store.get_instance("i-boom")["state"], "OPEN")


class IdleReapConfigTests(unittest.TestCase):
    def test_unset_grace_is_600_and_launch_stays_allowed(self) -> None:
        loaded = load_config(watcher_env())
        self.assertNotIn("IDLE_REAP_GRACE_SECONDS", watcher_env())
        self.assertTrue(loaded.ok)
        self.assertTrue(loaded.launch_allowed)
        self.assertEqual(loaded.idle_reap_grace, 600)
        self.assertEqual(loaded.reason, "")
        blank = load_config(watcher_env(IDLE_REAP_GRACE_SECONDS="  "))
        self.assertTrue(blank.launch_allowed)
        self.assertEqual(blank.idle_reap_grace, 600)

    def test_invalid_grace_is_a_config_error(self) -> None:
        for raw in ("nope", "-1", "1.5"):
            with self.subTest(raw=raw):
                loaded = load_config(watcher_env(IDLE_REAP_GRACE_SECONDS=raw))
                self.assertFalse(loaded.ok)
                self.assertFalse(loaded.launch_allowed)
                self.assertIn("IDLE_REAP_GRACE_SECONDS invalid", loaded.reason)

    def test_template_wires_idle_reap_grace_seconds(self) -> None:
        text = (ROOT / "template.yaml").read_text(encoding="utf-8")
        param = text.split("  IdleReapGraceSeconds:\n", 1)[1].split("  BudgetStopExclusions:\n", 1)[0]
        self.assertIn("Type: String", param)
        self.assertIn('Default: "600"', param)
        self.assertNotIn("Type: Number", param)
        env = text.split("IDLE_REAP_GRACE_SECONDS:\n", 1)[1].split("BUDGET_STOP_EXCLUSIONS:\n", 1)[0]
        self.assertIn("Ref: IdleReapGraceSeconds", env)


class _Page:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.headers = {"Content-Type": "application/json"}
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> bool:
        return False


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.github.com/runners", code, "err", Message(), None)


class LiveGitHubRunnerTests(unittest.TestCase):
    def test_get_and_delete_keep_real_statuses(self) -> None:
        github = LiveGitHub(cfg(), token="test-token")
        captured: list[urllib.request.Request] = []

        def urlopen(request, timeout=None):
            captured.append(request)
            if request.get_method() == "DELETE":
                if request.full_url.endswith("/77"):
                    raise _http_error(404)
                if request.full_url.endswith("/78"):
                    raise urllib.error.URLError("down")
                if request.full_url.endswith("/79"):
                    raise _http_error(422)
                return _Page(204, b"")
            if request.full_url.endswith("/5"):
                return _Page(200, json.dumps({"id": 5, "busy": False, "status": "offline"}).encode())
            if request.full_url.endswith("/6"):
                return _Page(200, json.dumps({"id": 6, "busy": True, "status": "online"}).encode())
            if request.full_url.endswith("/7"):
                return _Page(200, json.dumps({"id": 7, "status": "online"}).encode())
            if request.full_url.endswith("/8"):
                return _Page(200, json.dumps({"id": 8, "busy": "false"}).encode())
            if request.full_url.endswith("/9"):
                return _Page(200, json.dumps({"id": 9, "busy": 0}).encode())
            if request.full_url.endswith("/10"):
                raise _http_error(404)
            if request.full_url.endswith("/11"):
                raise _http_error(500)
            if request.full_url.endswith("/12"):
                raise _http_error(401)
            if request.full_url.endswith("/13"):
                raise urllib.error.URLError("reset")
            raise AssertionError(request.full_url)

        with patch("overflow_watcher.github_api.urllib.request.urlopen", urlopen):
            self.assertEqual(github.get_runner("example", "keicrew", 5), (200, False))
            self.assertEqual(github.get_runner("example", "keicrew", 6), (200, True))
            self.assertEqual(github.get_runner("example", "keicrew", 7), (200, None))
            self.assertEqual(github.get_runner("example", "keicrew", 8), (200, None))
            self.assertEqual(github.get_runner("example", "keicrew", 9), (200, None))
            self.assertEqual(github.get_runner("example", "keicrew", 10), (404, None))
            self.assertEqual(github.get_runner("example", "keicrew", 11), (500, None))
            self.assertEqual(github.get_runner("example", "keicrew", 12), (401, None))
            self.assertEqual(github.get_runner("example", "keicrew", 13), (None, None))
            self.assertEqual(github.delete_runner("example", "keicrew", 70), 204)
            self.assertEqual(github.delete_runner("example", "keicrew", 77), 404)
            self.assertEqual(github.delete_runner("example", "keicrew", 79), 422)
            self.assertIsNone(github.delete_runner("example", "keicrew", 78))
        self.assertEqual(captured[0].get_method(), "GET")
        self.assertIn("/repos/example/keicrew/actions/runners/5", captured[0].full_url)
        self.assertEqual(captured[-4].get_method(), "DELETE")
        self.assertIn("/actions/runners/70", captured[-4].full_url)

    def test_missing_token_returns_no_status_and_does_not_call_github(self) -> None:
        github = LiveGitHub(cfg(), token=None)
        called = {"n": 0}

        def urlopen(request, timeout=None):
            called["n"] += 1
            raise AssertionError("network")

        with patch("overflow_watcher.github_api.installation_token", return_value=None), patch(
            "overflow_watcher.github_api.urllib.request.urlopen", urlopen
        ):
            self.assertEqual(github.get_runner("example", "keicrew", 5), (None, None))
            self.assertIsNone(github.delete_runner("example", "keicrew", 5))
        self.assertEqual(called["n"], 0)


if __name__ == "__main__":
    unittest.main()
