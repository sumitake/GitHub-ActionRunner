# SPDX-License-Identifier: MPL-2.0
"""B1 JIT handoff, B2 job lock, B3 busy admission, and the budget alarm."""

from __future__ import annotations

import json
import re
import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from fakes import FakeEc2, FakeGitHub, FakeSsm
from support import NOW, add_cents, cfg, fresh_store, sample_job

from overflow_watcher.budget import Alert, AlertLog, write_alert_line
from overflow_watcher.controller import client_token, launch_one, resolve_reservations, run_poll
from overflow_watcher.inventory import HttpPage, assess_repo
from overflow_watcher.jit_handoff import parameter_name
from overflow_watcher.money import month_key
from overflow_watcher.types import CAPACITY_COOLDOWN_SECONDS, Decision, RepoSpec

ROOT = Path(__file__).resolve().parents[1]
REPO = RepoSpec("101", "example", "keicrew", "201")
BASE = "https://api.github.com/repos/example/keicrew"
_KIND_PATTERN = re.compile(r'^\{ \$\.kind = "([A-Za-z]+)" \}$')
SECRET = "ZZ-JIT-SECRET-b1-9f3c7a-ZZ"


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


def _routes(runners, jobs=None) -> dict[str, list[HttpPage]]:
    if jobs is None:
        jobs = ["self-hosted", "Linux"]
    job_body = {
        "jobs": [
            {
                "id": 4242,
                "status": "queued",
                "name": "test",
                "labels": list(jobs),
                "created_at": _stamp(NOW - 600),
            }
        ]
    }
    return {
        f"{BASE}/actions/runners?per_page=100": [_page({"runners": runners})],
        f"{BASE}/actions/runs?status=queued&per_page=100": [
            _page({"workflow_runs": [{"id": 7, "status": "queued", "name": "CI"}]})
        ],
        f"{BASE}/actions/runs/7/jobs?per_page=100": [_page(job_body)],
    }


def _runner(busy) -> dict:
    return {
        "status": "online",
        "busy": busy,
        "labels": [{"name": "self-hosted"}, {"name": "Linux"}],
    }


def _admitted(job=None) -> FakeGitHub:
    github = FakeGitHub()
    chosen = sample_job() if job is None else job
    github.decision = Decision(False, "assessed", (chosen,), (chosen.job_id,))
    github.mint_secret = SECRET
    return github


def _table_text(store) -> str:
    blob = json.dumps(store.client.scan(TableName=store.table), sort_keys=True)
    return blob


def _filter_patterns(template: str) -> list[str]:
    found: list[str] = []
    for line in template.splitlines():
        stripped = line.strip()
        if not stripped.startswith("FilterPattern:"):
            continue
        raw = stripped.split(":", 1)[1].strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
            raw = raw[1:-1]
        found.append(raw)
    return found


def _kind_match(pattern: str, line: str) -> bool:
    """Understand only `{ $.kind = "<word>" }`. Compare that word to JSON kind."""
    match = _KIND_PATTERN.fullmatch(pattern)
    if match is None:
        return False
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    return payload.get("kind") == match.group(1)


class JitAndLockTests(unittest.TestCase):
    def test_b1_mint_failure_does_not_launch_and_refunds(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        github.mint_error = "http-403"
        ssm = FakeSsm()
        month = month_key(NOW)
        result = run_poll(store, ec2, ec2, github, cfg(), NOW, ssm=ssm)
        self.assertEqual(result.launched, 0)
        self.assertEqual(ec2.calls, [])
        self.assertEqual(store.get_accrued(month), 0)
        self.assertEqual(store.list_open_reservations(), [])
        self.assertEqual(store.list_job_locks("101"), [])
        self.assertEqual(ssm.values, {})
        self.assertEqual(github.runner_deletes, [])

    def test_b1_put_failure_refunds_without_launch(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        ssm = FakeSsm()
        ssm.fail_put = True
        month = month_key(NOW)
        result = run_poll(store, ec2, ec2, github, cfg(), NOW, ssm=ssm)
        self.assertEqual(result.launched, 0)
        self.assertEqual(ec2.calls, [])
        self.assertEqual(store.get_accrued(month), 0)
        self.assertEqual(store.list_open_reservations(), [])
        self.assertEqual(store.list_job_locks("101"), [])
        self.assertEqual(ssm.values, {})
        self.assertEqual(github.runner_deletes, [])

    def test_b1_existing_parameter_is_kept_and_not_overwritten(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        github.mint_secret = "fresh-minted-secret"
        ssm = FakeSsm()
        name = parameter_name(client_token("101", "9001", 0))
        ssm.values[name] = "kept-original-bytes"
        outcome = launch_one(store, ec2, cfg(), sample_job(), NOW, github=github, ssm=ssm)
        self.assertEqual(outcome, "launched")
        self.assertEqual(ssm.values[name], "kept-original-bytes")
        self.assertNotIn("fresh-minted-secret", ssm.values.values())
        self.assertEqual(github.runner_deletes, [])

    def test_b1_definitive_runinstances_refusal_deletes_parameter_and_does_not_delete_runner(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        ec2.quota = True
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        first = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(first.quota_failures, 1)
        self.assertEqual(ssm.values, {})
        self.assertEqual(store.get_accrued(month), 0)
        self.assertEqual(store.failure_count(), 1)
        self.assertEqual(github.runner_deletes, [])
        self.assertEqual(store.list_job_locks("101"), [])
        calls = list(ec2.calls)
        self.assertEqual(len(calls), 1)
        second = run_poll(store, ec2, ec2, github, config, NOW + 1, ssm=ssm)
        self.assertEqual(second.launched, 0)
        self.assertEqual(ec2.calls, calls)
        self.assertEqual(github.runner_deletes, [])

    def test_b1_ambiguous_retry_reuses_client_token_without_remint(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        ec2.ambiguous = True
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        self.assertEqual(
            launch_one(store, ec2, config, sample_job(), NOW, github=github, ssm=ssm),
            "ambiguous",
        )
        token = ec2.calls[0]
        ec2.ambiguous = False
        ec2.by_token[token] = "i-seeded"
        resolve_reservations(store, ec2, AlertLog(), NOW, github=github, ssm=ssm)
        self.assertEqual(len(github.mint_calls), 1)
        self.assertEqual(ssm.puts, [parameter_name(token)])
        self.assertEqual(store.get_accrued(month), config.allowance)
        self.assertEqual(ec2.calls, [token, token])
        self.assertEqual(list(ec2.by_token), [token])
        self.assertEqual(store.get_instance("i-seeded")["state"], "OPEN")
        self.assertEqual(len(store.list_open_instances()), 1)

    def test_b1_userdata_and_store_do_not_contain_jit_secret(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        ssm = FakeSsm()
        buffer = StringIO()
        with patch("sys.stdout", buffer):
            result = run_poll(store, ec2, ec2, github, cfg(), NOW, ssm=ssm)
        self.assertEqual(result.launched, 1)
        self.assertEqual(list(ssm.values.values()), [SECRET])
        saved = store.list_open_instances()[0]
        raw = saved["params"]["UserData"]
        self.assertNotIn(SECRET, raw)
        self.assertNotIn(SECRET, json.dumps(saved))
        self.assertNotIn(SECRET, _table_text(store))
        self.assertNotIn(SECRET, buffer.getvalue())
        name = parameter_name(saved["clientToken"])
        self.assertIn(name, raw)
        self.assertLessEqual(len(raw.encode("utf-8")), 16384)
        self.assertEqual(github.runner_deletes, [])

    def test_b2_second_poll_same_job_does_not_double_debit(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        first = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(first.launched, 1)
        self.assertEqual(
            launch_one(store, ec2, config, sample_job(), NOW, github=github, ssm=ssm),
            "duplicate",
        )
        second = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(second.launched, 0)
        self.assertEqual(len(store.list_open_instances()), 1)
        self.assertEqual(store.get_accrued(month), config.allowance)
        self.assertEqual(len(github.mint_calls), 1)

    def test_b2_two_jobs_two_debits(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        for job_id in ("9001", "9002"):
            outcome = launch_one(
                store,
                ec2,
                config,
                sample_job(job_id=job_id, workflow_run_id=job_id),
                NOW,
                github=github,
                ssm=ssm,
            )
            self.assertEqual(outcome, "launched", job_id)
        self.assertEqual(len(store.list_open_instances()), 2)
        self.assertEqual(store.get_accrued(month), config.allowance * 2)

    def test_b2_ambiguous_attempt_is_not_refunded(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        ec2.ambiguous = True
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        self.assertEqual(
            launch_one(store, ec2, config, sample_job(), NOW, github=github, ssm=ssm),
            "ambiguous",
        )
        self.assertEqual(store.get_accrued(month), config.allowance)
        self.assertEqual(len(store.list_open_reservations()), 1)
        locks = store.list_job_locks("101")
        self.assertEqual(len(locks), 1)
        self.assertEqual(locks[0]["state"], "HELD")

    def test_b2_capacity_refusal_refunds_once(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        ec2.quota = True
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        first = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(first.quota_failures, 1)
        self.assertEqual(store.get_accrued(month), 0)
        self.assertEqual(store.list_job_locks("101"), [])
        token = ec2.calls[0]
        ec2.quota = False
        later = NOW + CAPACITY_COOLDOWN_SECONDS + 1
        second = run_poll(store, ec2, ec2, github, config, later, ssm=ssm)
        self.assertEqual(second.launched, 1)
        self.assertEqual(ec2.calls, [token, token])
        self.assertEqual(len(store.list_open_instances()), 1)
        self.assertEqual(store.get_accrued(month), config.allowance)
        self.assertEqual(len(github.mint_calls), 2)
        self.assertNotEqual(
            github.mint_calls[0]["runner_name"],
            github.mint_calls[1]["runner_name"],
        )

    def test_b2_launched_instance_is_not_refunded(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        self.assertEqual(
            launch_one(store, ec2, config, sample_job(), NOW, github=github, ssm=ssm),
            "launched",
        )
        store.release_reservation(ec2.calls[0])
        self.assertEqual(store.get_accrued(month), config.allowance)
        self.assertEqual(store.list_open_instances()[0]["state"], "OPEN")

    def test_b2_open_instance_blocks_a_second_debit_even_if_job_key_is_gone(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        first = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(first.launched, 1)
        store.delete_job_lock("101", "9001")
        self.assertEqual(store.list_job_locks("101"), [])
        held = store.get_accrued(month)
        calls = list(ec2.calls)
        second = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(second.launched, 0)
        self.assertEqual(ec2.calls, calls)
        self.assertEqual(store.get_accrued(month), held)
        self.assertEqual(len(store.list_open_instances()), 1)

    def test_b2_job_key_held_until_closed_and_not_queued(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        first = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(first.launched, 1)
        locks = store.list_job_locks("101")
        self.assertEqual(len(locks), 1)
        self.assertEqual(locks[0]["state"], "HELD")
        held = store.get_accrued(month)
        instance_id = store.list_open_instances()[0]["instanceId"]
        github.decision = Decision(False, "assessed", (), ())
        dropped = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(dropped.launched, 0)
        self.assertEqual(len(store.list_job_locks("101")), 1)
        self.assertEqual(store.get_instance(instance_id)["state"], "OPEN")
        ec2.terminate_instances([instance_id])
        closed = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(closed.launched, 0)
        self.assertEqual(store.list_job_locks("101"), [])
        self.assertEqual(store.get_instance(instance_id)["state"], "CLOSED")
        self.assertEqual(store.get_accrued(month), held)

    def test_b2_relaunch_after_close_uses_a_new_client_token(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = _admitted()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        first = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(first.launched, 1)
        first_id = store.list_open_instances()[0]["instanceId"]
        before = store.get_accrued(month)
        first_token = ec2.calls[0]
        self.assertEqual(first_token, client_token("101", "9001", 0))
        ec2.terminate_instances([first_id])
        second = run_poll(store, ec2, ec2, github, config, NOW + 1, ssm=ssm)
        self.assertEqual(second.launched, 1)
        self.assertEqual(len(ec2.calls), 2)
        second_token = ec2.calls[1]
        self.assertNotEqual(second_token, first_token)
        self.assertEqual(second_token, client_token("101", "9001", 1))
        self.assertEqual(store.get_instance(first_id)["state"], "CLOSED")
        second_id = store.list_open_instances()[0]["instanceId"]
        self.assertNotEqual(second_id, first_id)
        self.assertIsNotNone(store.get_instance(second_id))
        self.assertEqual(store.get_accrued(month), before + config.allowance)
        self.assertEqual(store.instances_returned("101", "9001"), 2)

    def test_b3_all_busy_launches_once(self) -> None:
        decision = assess_repo(ScriptTransport(_routes([_runner(True)])), REPO, NOW)
        self.assertFalse(decision.uncertain)
        self.assertEqual(len(decision.jobs), 1)
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        github.decision = decision
        result = run_poll(store, ec2, ec2, github, cfg(), NOW, ssm=FakeSsm())
        self.assertEqual(result.launched, 1)
        self.assertEqual(len(store.list_open_instances()), 1)

    def test_b3_one_idle_online_does_not_launch(self) -> None:
        decision = assess_repo(ScriptTransport(_routes([_runner(False)])), REPO, NOW)
        self.assertEqual(decision.jobs, ())
        self.assertFalse(decision.uncertain)
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        github.decision = decision
        result = run_poll(store, ec2, ec2, github, cfg(), NOW, ssm=FakeSsm())
        self.assertEqual(result.launched, 0)
        self.assertEqual(ec2.calls, [])

    def test_b3_busy_and_dedupe_one_instance(self) -> None:
        decision = assess_repo(ScriptTransport(_routes([_runner(True)])), REPO, NOW)
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        github.decision = decision
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        first = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        second = run_poll(store, ec2, ec2, github, config, NOW, ssm=ssm)
        self.assertEqual(first.launched, 1)
        self.assertEqual(second.launched, 0)
        self.assertEqual(len(store.list_open_instances()), 1)
        self.assertEqual(store.get_accrued(month), config.allowance)

    def test_b3_non_boolean_busy_is_malformed_no_launch(self) -> None:
        missing = dict(_runner(False))
        del missing["busy"]
        for runner in (missing, _runner("yes")):
            decision = assess_repo(ScriptTransport(_routes([runner])), REPO, NOW)
            self.assertTrue(decision.uncertain, runner)
            self.assertEqual(decision.jobs, ())

    def test_b3_runner_api_error_does_not_launch(self) -> None:
        runners_url = f"{BASE}/actions/runners?per_page=100"
        cases = {
            "401": _routes([]),
            "500": _routes([]),
            "missing-rate-limit": _routes([]),
            "truncated": _routes([]),
        }
        cases["401"][runners_url] = [_page({"runners": []}, status=401)]
        cases["500"][runners_url] = [_page({"runners": []}, status=500)]
        cases["missing-rate-limit"][runners_url] = [_page({"runners": []}, remaining=None)]
        cases["truncated"][runners_url] = [
            _page({"runners": []}, link=f"<{runners_url}-next>; rel=\"next\""),
        ]
        cases["truncated"][f"{runners_url}-next"] = [_page({"runners": []}, status=500)]
        for name, routes in cases.items():
            with self.subTest(name=name):
                decision = assess_repo(ScriptTransport(routes), REPO, NOW)
                self.assertTrue(decision.uncertain)
                self.assertEqual(decision.jobs, ())
                store = fresh_store()
                ec2 = FakeEc2()
                github = FakeGitHub()
                github.decision = decision
                result = run_poll(store, ec2, ec2, github, cfg(), NOW, ssm=FakeSsm())
                self.assertEqual(result.launched, 0)
                self.assertEqual(ec2.calls, [])

    def test_alarm_filter_matches_budget_and_grace_lines_only(self) -> None:
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        patterns = _filter_patterns(template)
        self.assertEqual(patterns, ['{ $.kind = "budget" }', '{ $.kind = "grace" }'])
        budget_pattern, grace_pattern = patterns
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        add_cents(store, month, 3301)
        buffer = StringIO()
        with patch("sys.stdout", buffer):
            run_poll(store, ec2, ec2, github, cfg(), NOW, ssm=FakeSsm())
        lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
        budget_lines = [line for line in lines if _kind_match(budget_pattern, line)]
        grace_lines = [line for line in lines if _kind_match(grace_pattern, line)]
        self.assertEqual(len(budget_lines), 1)
        self.assertEqual(len(grace_lines), 1)
        self.assertEqual(json.loads(budget_lines[0])["kind"], "budget")
        self.assertEqual(json.loads(grace_lines[0])["kind"], "grace")
        extra = StringIO()
        with patch("sys.stdout", extra):
            write_alert_line(
                Alert(
                    audience="ops",
                    kind="past-allowance",
                    month=month,
                    estimated_cents=3301,
                    overage_cents=0,
                    cause="instance runtime passed the 6 hour allowance",
                )
            )
            write_alert_line(
                Alert(
                    audience="ops",
                    kind="past-allowance",
                    month=month,
                    estimated_cents=3301,
                    overage_cents=0,
                    cause="the budget word is in the cause but the kind is not budget",
                )
            )
        for line in extra.getvalue().splitlines():
            self.assertFalse(_kind_match(budget_pattern, line))
            self.assertFalse(_kind_match(grace_pattern, line))
            self.assertEqual(json.loads(line)["kind"], "past-allowance")

    def test_static_jit_parameter_iam_is_path_scoped(self) -> None:
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        controller, runner_rest = template.split("RunnerRole:", 1)
        runner = runner_rest.split("RunnerInstanceProfile:", 1)[0]
        runner_actions = sorted(re.findall(r"ssm:[A-Za-z]+", runner))
        self.assertEqual(runner_actions, ["ssm:DeleteParameter", "ssm:GetParameter"])
        self.assertIn("ssm:PutParameter", controller)
        self.assertIn("ssm:DeleteParameter", controller)
        self.assertNotIn("ssm:GetParameter", controller)
        self.assertIn("parameter/overflow-watcher/jit/*", controller)
        self.assertIn("parameter/overflow-watcher/jit/*", runner)
        self.assertNotIn("GetParametersByPath", template)
        self.assertNotIn("kms:", template)
        self.assertEqual(template.count("ec2:TerminateInstances"), 1)
        source = (ROOT / "src" / "overflow_watcher" / "controller.py").read_text(encoding="utf-8")
        self.assertNotIn("token_hex", source)


if __name__ == "__main__":
    unittest.main()
