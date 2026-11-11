# SPDX-License-Identifier: MPL-2.0
"""Regression tests for the review findings on the overflow watcher."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from fakes import FakeEc2, FakeGitHub, FakeSsm
from support import NOW, add_cents, cfg, fresh_store, sample_job, seed_instance, watcher_env

from overflow_watcher.budget import AlertLog
from overflow_watcher.config import load_config
from overflow_watcher.controller import (
    _record_for,
    admission_allows,
    accrue,
    ec2_params,
    launch_one,
    resolve_reservations,
    run_poll,
)
from overflow_watcher.ec2view import Ec2Views
from overflow_watcher.guest_bootstrap import render_user_data
from overflow_watcher.handler import response_from_poll
from overflow_watcher.money import month_key
from overflow_watcher.supervisor import KEEP, Proof, _workers_alive, decide
from overflow_watcher.types import RETRY_WINDOW_SECONDS, Decision, InstanceView

ROOT = Path(__file__).resolve().parents[1]


class ReviewFixTests(unittest.TestCase):
    def test_h1_sunk_over_grace_stops_every_eligible_once(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        for index, run_id in enumerate(("1", "2", "3"), start=1):
            seed_instance(
                store,
                ec2,
                instance_id=f"i-{index}",
                debit=100,
                month=month,
                launch_epoch=NOW - index * 100,
                run_id=run_id,
            )
        add_cents(store, month, 3300 - store.get_accrued(month))
        before = store.get_accrued(month)
        config = cfg()
        run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual({call[2] for call in github.cancel_calls}, {"1", "2", "3"})
        self.assertEqual(store.get_accrued(month), before)
        run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual(len(github.cancel_calls), 3)

    def test_h1_estimate_change_stops_instance_spared_by_earlier_poll(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-live", debit=600, month=month,
            launch_epoch=NOW - 3600, run_id="2", price_numer=1, price_denom=1,
        )
        add_cents(store, month, 3200 - store.get_accrued(month))
        config = cfg()
        first = run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual([item for item in first.alerts.items if item.kind == "grace"], [])
        add_cents(store, month, 1)
        second = run_poll(store, ec2, ec2, github, config, NOW + 5)
        self.assertEqual([call[2] for call in github.cancel_calls], ["2"])
        self.assertEqual(second.budget.cancelled, ("i-live",))
        marker = store.get_marker(f"STOP#{month}", "INST#i-live")
        self.assertIsNotNone(marker)
        assert marker is not None
        self.assertEqual(marker.get("phase"), "cancel_wait")

    def test_h2_empty_exclusions_fail_closed(self) -> None:
        for raw in ("", "[]"):
            loaded = load_config(watcher_env(BUDGET_STOP_EXCLUSIONS=raw))
            self.assertFalse(loaded.ok, raw)
            result = run_poll(fresh_store(), FakeEc2(), FakeEc2(), FakeGitHub(), loaded, NOW)
            self.assertEqual(result.launched, 0)

    def test_h2_default_patterns_exclude_deploy_and_migration(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-deploy", debit=50, month=month,
            launch_epoch=NOW - 30, workflow="deploy-site", job_name="ship", run_id="3",
        )
        seed_instance(
            store, ec2, instance_id="i-move", debit=50, month=month,
            launch_epoch=NOW - 20, workflow="CI", job_name="migrate-db", run_id="4",
        )
        seed_instance(
            store, ec2, instance_id="i-ok", debit=50, month=month,
            launch_epoch=NOW - 10, workflow="CI", job_name="test", run_id="5",
        )
        add_cents(store, month, 3600 - store.get_accrued(month))
        run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([call[2] for call in github.cancel_calls], ["5"])

    def test_h3_budget_and_grace_alerts_are_one_json_line_and_once_per_month(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-hit", debit=100, month=month, launch_epoch=NOW - 10, run_id="9")
        add_cents(store, month, 3400 - store.get_accrued(month))
        config = cfg()
        buffer = StringIO()
        with patch("sys.stdout", buffer):
            first = run_poll(store, ec2, ec2, github, config, NOW)
        second = run_poll(store, ec2, ec2, github, config, NOW)
        payload = response_from_poll(first)
        lines = [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]
        kinds = [line["kind"] for line in lines]
        self.assertEqual(kinds.count("budget"), 1)
        self.assertEqual(kinds.count("grace"), 1)
        self.assertEqual(payload["alerts"], lines)
        self.assertIsNotNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET"))
        self.assertIsNotNone(store.get_marker(f"MONTH#{month}", "ALERT#GRACE"))
        self.assertEqual([item.kind for item in second.alerts.items if item.kind in {"budget", "grace"}], [])

    def test_m1_run_instances_uses_launch_template_and_user_data(self) -> None:
        params = ec2_params(cfg(), parameter_name="/overflow-watcher/jit/" + ("ab" * 32))
        self.assertEqual(params["LaunchTemplate"]["LaunchTemplateId"], "lt-placeholder")
        self.assertNotIn("BlockDeviceMappings", params)
        # Botocore base64-encodes RunInstances UserData once. The value we pass
        # is the raw script, and that raw form must fit in 16384 bytes.
        raw = params["UserData"]
        encoded = raw.encode("utf-8")
        with self.subTest("raw limit"):
            self.assertLessEqual(len(encoded), 16384, f"raw UserData is {len(encoded)} bytes")
        with self.subTest("single encode"):
            body = base64.b64decode(base64.b64encode(encoded))
            self.assertTrue(body.startswith(b"#!"), body[:12])
            self.assertIn(b"overflow_watcher.supervisor", body)

    def test_m2_capacity_refusal_after_ambiguous_keeps_reservation(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        ec2.ambiguous = True
        github = FakeGitHub()
        ssm = FakeSsm()
        config = cfg()
        month = month_key(NOW)
        self.assertEqual(launch_one(store, ec2, config, sample_job(), NOW, github=github, ssm=ssm), "ambiguous")
        held = store.get_accrued(month)
        self.assertEqual(len(store.list_open_reservations()), 1)
        ec2.ambiguous = False
        ec2.quota = True
        resolve_reservations(store, ec2, AlertLog(), NOW, github=github, ssm=ssm)
        self.assertEqual(len(store.list_open_reservations()), 1)
        self.assertEqual(store.get_accrued(month), held)

    def test_l1_list_tagged_ids_follows_next_token(self) -> None:
        class Pages:
            def __init__(self) -> None:
                self.tokens: list[str | None] = []

            def describe_instances(self, **kwargs):
                token = kwargs.get("NextToken")
                self.tokens.append(token)
                self.filters = kwargs.get("Filters")
                if token is None:
                    return {
                        "Reservations": [{"Instances": [{"InstanceId": "i-a"}]}],
                        "NextToken": "page-2",
                    }
                return {"Reservations": [{"Instances": [{"InstanceId": "i-b"}]}]}

        client = Pages()
        self.assertEqual(Ec2Views(client).list_tagged_ids(), ["i-a", "i-b"])
        self.assertEqual(client.tokens, [None, "page-2"])
        states = next(item["Values"] for item in client.filters if item["Name"] == "instance-state-name")
        self.assertEqual(states, ["pending", "running", "stopping", "shutting-down"])

    def test_l2_proc_read_error_is_not_no_worker(self) -> None:
        with patch("overflow_watcher.supervisor.os.listdir", side_effect=OSError("unread")):
            self.assertIsNone(_workers_alive(1))
        action = decide(
            Proof(False, None, 0, True, False, True, True),
            10,
            False,
        )
        self.assertEqual(action, KEEP)

    def test_l3_create_tags_is_not_unscoped(self) -> None:
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        create_at = template.index("ec2:CreateTags")
        window = template[create_at : create_at + 280]
        self.assertNotIn('Resource: "*"', window)
        self.assertIn("ec2:CreateAction: RunInstances", window)

    def test_l4_dynamodb_local_and_java_are_pinned(self) -> None:
        script = (ROOT / "scripts" / "run-tests.sh").read_text(encoding="utf-8")
        url_at = script.index("dynamodb_local_2025-07-15.tar.gz")
        sha_at = script.index("1125086301253b89539fa3bdbf1ded0656c596a2d34e0ca3c10af83373e7fd88")
        check_at = script.index("sha256sum -c -")
        self.assertLess(url_at, check_at)
        self.assertLess(sha_at, check_at)
        workflow = (ROOT.parents[1] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        package, major = (ROOT / "tests" / "fixtures" / "openjdk-pin.txt").read_text(encoding="utf-8").split()
        self.assertEqual(package, f"openjdk-{major}-jre-headless")
        step = workflow.index("Install Java for overflow watcher")
        window = workflow[step:step + 500]
        self.assertIn(f"apt-get install -y --no-install-recommends {package}", window)
        self.assertNotIn(f"{package}=", window)

    def test_c4b_threshold_boundaries(self) -> None:
        self.assertTrue(admission_allows(2999, 1, 3000))
        self.assertFalse(admission_allows(3000, 1, 3000))
        self.assertFalse(admission_allows(3300, 1, 3000))
        for total, expects_budget in ((2999, False), (3000, False), (3001, True)):
            store = fresh_store()
            month = month_key(NOW)
            add_cents(store, month, total)
            result = run_poll(store, FakeEc2(), FakeEc2(), FakeGitHub(), cfg(), NOW)
            budget = [item for item in result.alerts.items if item.kind == "budget"]
            self.assertEqual(bool(budget), expects_budget, total)
            self.assertEqual([item for item in result.alerts.items if item.kind == "grace"], [], total)
        for total in (3299, 3300):
            store = fresh_store()
            ec2 = FakeEc2()
            github = FakeGitHub()
            month = month_key(NOW)
            seed_instance(
                store, ec2, instance_id="i-flat", debit=6, month=month, launch_epoch=NOW, run_id="1",
            )
            add_cents(store, month, total - store.get_accrued(month))
            result = run_poll(store, ec2, ec2, github, cfg(), NOW)
            self.assertEqual(github.cancel_calls, [], total)
            self.assertEqual(ec2.terminate_calls, [], total)
            self.assertEqual([item for item in result.alerts.items if item.kind == "grace"], [], total)
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-flat", debit=6, month=month, launch_epoch=NOW, run_id="1")
        add_cents(store, month, 3301 - store.get_accrued(month))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        grace = [item for item in result.alerts.items if item.kind == "grace"]
        self.assertEqual(len(grace), 1)
        self.assertEqual(grace[0].instance_ids, ())

    def test_partial_and_uncertain_stop(self) -> None:
        store = fresh_store()
        github = FakeGitHub()
        month = month_key(NOW)

        class Flip(FakeEc2):
            def describe_instances(self, ids: list[str]):
                if ids == ["i-b"]:
                    self.views["i-b"] = InstanceView("i-b", None, False, True)
                return super().describe_instances(ids)

        ec2 = Flip()
        seed_instance(
            store, ec2, instance_id="i-a", debit=600, month=month,
            launch_epoch=NOW - 3600, run_id="1", price_numer=1, price_denom=1,
        )
        seed_instance(
            store, ec2, instance_id="i-b", debit=600, month=month,
            launch_epoch=NOW - 3600, run_id="2", price_numer=1, price_denom=1,
        )
        add_cents(store, month, 3400 - store.get_accrued(month))
        github.decision = Decision(False, "queued", (sample_job(workflow_run_id="90"),))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([call[2] for call in github.cancel_calls], ["1"])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(result.launched, 0)
        self.assertEqual(result.blocked_reason, "unknown-inventory")
        self.assertTrue(result.budget.block_launch)
        self.assertTrue(any(item.instance_ids == ("i-b",) for item in result.alerts.items))

    def test_alert_emit_failure_leaves_a_retry_and_commits_after_success(self) -> None:
        store = fresh_store()
        month = month_key(NOW)
        add_cents(store, month, 3001)
        original = AlertLog.emit
        failed = {"budget": False}

        def flaky(self, alert):
            if alert.kind == "budget" and not failed["budget"]:
                failed["budget"] = True
                raise RuntimeError("log down")
            original(self, alert)

        config = cfg()
        with patch.object(AlertLog, "emit", flaky):
            run_poll(store, FakeEc2(), FakeEc2(), FakeGitHub(), config, NOW)
        self.assertIsNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET"))
        self.assertIsNotNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET#RETRY"))
        second = run_poll(store, FakeEc2(), FakeEc2(), FakeGitHub(), config, NOW)
        self.assertIsNotNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET"))
        self.assertEqual([item.kind for item in second.alerts.items if item.kind == "budget"], ["budget"])
        third = run_poll(store, FakeEc2(), FakeEc2(), FakeGitHub(), config, NOW)
        self.assertEqual([item for item in third.alerts.items if item.kind == "budget"], [])

    def test_unknown_ownership_blocks_new_launch(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-mystery", debit=6, month=month, launch_epoch=NOW,
            has_tag=False, tagged_list=False, run_id="1",
        )
        github.decision = Decision(False, "queued", (sample_job(),))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(result.launched, 0)
        self.assertEqual(result.blocked_reason, "unknown-inventory")
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertTrue(any(item.kind == "unknown-ownership" for item in result.alerts.items))

    def test_excluded_burn_stays_in_the_forecast_and_is_not_stopped(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-deploy", debit=600, month=month,
            launch_epoch=NOW - 3600, workflow="deploy-site", job_name="ship", run_id="3",
            price_numer=1, price_denom=1,
        )
        seed_instance(
            store, ec2, instance_id="i-ci", debit=600, month=month,
            launch_epoch=NOW - 1800, workflow="CI", job_name="test", run_id="4",
            price_numer=1, price_denom=1,
        )
        before = 3200
        add_cents(store, month, before - store.get_accrued(month))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual([call[2] for call in github.cancel_calls], ["4"])
        self.assertNotIn("3", [call[2] for call in github.cancel_calls])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertGreaterEqual(store.get_accrued(month), before)
        self.assertEqual([item.instance_ids for item in result.alerts.items if item.kind == "grace"], [("i-ci",)])

    def test_irreducible_overspend_alerts_and_does_not_terminate(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-done", debit=6, month=month, launch_epoch=NOW, run_id="8",
        )
        seed_instance(
            store, ec2, instance_id="i-deploy", debit=6, month=month, launch_epoch=NOW,
            workflow="deploy-site", job_name="ship", run_id="9",
        )
        add_cents(store, month, 3400 - store.get_accrued(month))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(store.get_instance("i-done")["state"], "OPEN")
        self.assertEqual(store.get_instance("i-deploy")["state"], "OPEN")
        grace = [item for item in result.alerts.items if item.kind == "grace"]
        self.assertEqual(len(grace), 1)
        self.assertEqual(grace[0].instance_ids, ())
        self.assertGreaterEqual(store.get_accrued(month), 3400)

    def test_finished_during_wait_does_not_spare_a_running_instance(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-live", debit=600, month=month,
            launch_epoch=NOW - 3600, run_id="2", price_numer=1, price_denom=1,
        )
        add_cents(store, month, 3400 - store.get_accrued(month))
        self.assertTrue(store.claim(f"STOP#{month}", "INST#i-live", {"phase": "finished_during_wait"}))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(ec2.terminate_calls, [["i-live"]])
        self.assertEqual(result.budget.terminated, ("i-live",))
        self.assertEqual(result.budget.spared, ())

    def test_ambiguous_workflow_read_alerts_and_does_not_terminate(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-wait", debit=400, month=month, launch_epoch=NOW - 15, run_id="8")
        add_cents(store, month, 3400 - store.get_accrued(month))
        config = cfg()
        run_poll(store, ec2, ec2, github, config, NOW)
        github.ambiguous_completion = True
        result = run_poll(store, ec2, ec2, github, config, NOW + 120)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(len(result.alerts.items), 1)
        self.assertEqual(result.alerts.items[0].kind, "ambiguous-workflow")
        marker = store.get_marker(f"STOP#{month}", "INST#i-wait")
        self.assertIsNotNone(marker)
        assert marker is not None
        self.assertEqual(marker.get("phase"), "cancel_wait")

    def test_excluded_runners_over_projection_alert_once_and_do_not_stop(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-deploy", debit=600, month=month,
            launch_epoch=NOW - 3600, workflow="deploy-site", job_name="ship", run_id="3",
            price_numer=1, price_denom=1,
        )
        seed_instance(
            store, ec2, instance_id="i-move", debit=600, month=month,
            launch_epoch=NOW - 1800, workflow="CI", job_name="migrate-db", run_id="4",
            price_numer=1, price_denom=1,
        )
        add_cents(store, month, 3200 - store.get_accrued(month))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(github.cancel_calls, [])
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(result.budget.cancelled, ())
        self.assertEqual(result.budget.terminated, ())
        grace = [item for item in result.alerts.items if item.kind == "grace"]
        self.assertEqual(len(grace), 1)

    def test_alert_line_is_printed_before_the_claim(self) -> None:
        store = fresh_store()
        month = month_key(NOW)
        add_cents(store, month, 3001)
        with patch("overflow_watcher.budget.write_alert_line", side_effect=RuntimeError("log down")):
            run_poll(store, FakeEc2(), FakeEc2(), FakeGitHub(), cfg(), NOW)
        self.assertIsNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET"))
        self.assertIsNotNone(store.get_marker(f"MONTH#{month}", "ALERT#BUDGET#RETRY"))

    def test_lambda_package_has_supervisor_at_the_userdata_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "pkg.zip"
            subprocess.run(
                ["sh", str(ROOT / "scripts" / "package-lambda.sh"), str(archive)],
                check=True,
            )
            extracted = Path(tmp) / "out"
            with zipfile.ZipFile(archive) as packed:
                packed.extractall(extracted)
            controller = extracted / "src" / "overflow_watcher" / "controller.py"
            script = controller.resolve().parents[2] / "boot" / "supervisor.sh"
            self.assertTrue(script.is_file())
            self.assertIn("overflow_watcher.supervisor", script.read_text(encoding="utf-8"))
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        self.assertIn("PYTHONPATH: /var/task/src", template)

    def test_built_zip_is_not_bound_to_a_deployment_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "pkg.zip"
            subprocess.run(
                ["sh", str(ROOT / "scripts" / "package-lambda.sh"), str(archive)],
                check=True,
            )
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        template = (ROOT / "template.yaml").read_text(encoding="utf-8")
        key_at = template.index("CodeS3Key:")
        window = template[key_at : key_at + 180]
        self.assertNotIn("Default:", window)
        self.assertNotIn(digest, template)

    def _package(self, tmp: str) -> tuple[Path, Path]:
        archive = Path(tmp) / "pkg.zip"
        subprocess.run(["sh", str(ROOT / "scripts" / "package-lambda.sh"), str(archive)], check=True)
        return archive, Path(str(archive) + ".binding.json")

    def _check_binding(self, archive: Path, binding: Path, template: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(ROOT / "scripts" / "package-lambda.sh"), "--check", str(archive), str(binding), str(template)],
            capture_output=True,
            text=True,
        )

    def test_package_binding_matches_zip_and_template_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive, binding = self._package(tmp)
            record = json.loads(binding.read_text(encoding="utf-8"))
            self.assertEqual(record["artifact_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertFalse(record["s3_object_attested"])
            self.assertEqual(record["parameters"], ["CodeS3Bucket", "CodeS3Key", "CodeS3ObjectVersion"])
            checked = self._check_binding(archive, binding, ROOT / "template.yaml")
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_package_binding_rejects_missing_mismatch_and_stale_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive, binding = self._package(tmp)
            template = ROOT / "template.yaml"
            absent = self._check_binding(archive, Path(tmp) / "missing.json", template)
            self.assertNotEqual(absent.returncode, 0)
            self.assertIn("absent linkage", absent.stderr)
            missing_zip = Path(tmp) / "gone.zip"
            gone = self._check_binding(missing_zip, binding, template)
            self.assertNotEqual(gone.returncode, 0)
            self.assertIn("missing artifact", gone.stderr)
            archive.write_bytes(archive.read_bytes() + b"x")
            substituted = self._check_binding(archive, binding, template)
            self.assertNotEqual(substituted.returncode, 0)
            self.assertIn("mismatched artifact", substituted.stderr)
            archive, binding = self._package(tmp)
            record = json.loads(binding.read_text(encoding="utf-8"))
            record["artifact_sha256"] = "0" * 64
            binding.write_text(json.dumps(record), encoding="utf-8")
            stale_digest = self._check_binding(archive, binding, template)
            self.assertNotEqual(stale_digest.returncode, 0)
            self.assertIn("mismatched artifact", stale_digest.stderr)
            archive, binding = self._package(tmp)
            stale_template = Path(tmp) / "template.yaml"
            stale_template.write_text(
                template.read_text(encoding="utf-8").replace("Ref: CodeS3ObjectVersion", "Ref: CodeS3KeyOld"),
                encoding="utf-8",
            )
            stale = self._check_binding(archive, binding, stale_template)
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn("stale template input", stale.stderr)
            literal = Path(tmp) / "literal.yaml"
            literal.write_text(
                template.read_text(encoding="utf-8").replace("Ref: CodeS3Key", "S3Key: other.zip"),
                encoding="utf-8",
            )
            replaced = self._check_binding(archive, binding, literal)
            self.assertNotEqual(replaced.returncode, 0)
            self.assertIn("substituted or stale template input", replaced.stderr)

    def test_readme_checksum_is_base64_of_raw_digest(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("base64 encoding of the raw 32-byte digest", readme)
        line = next(
            row for row in readme.splitlines() if row.startswith("python3 -c 'import base64,sys;") and "bytes.fromhex" in row
        )
        self.assertTrue(line.endswith(' "$artifact_sha256"'), line)
        empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        done = subprocess.run(
            ["sh", "-c", line, "sh"],
            env={**os.environ, "artifact_sha256": empty},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
        self.assertNotIn("the base64 encoding of the recorded `artifact_sha256`", readme)

    def test_readme_states_none_does_not_terminate(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("A read of `None` is", readme)
        self.assertIn("the claim stays `cancel_wait`", readme)
        self.assertIn("instance is not terminated", readme)
        self.assertIn("`True` (completed) or", readme)
        self.assertIn("`False` (not completed) terminates", readme)

    def test_unselected_cancel_wait_does_not_terminate_and_reselection_is_fresh(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-a", debit=600, month=month,
            launch_epoch=NOW - 5 * 3600, run_id="1", price_numer=1, price_denom=1,
        )
        add_cents(store, month, 3000 - store.get_accrued(month))
        config = cfg()
        run_poll(store, ec2, ec2, github, config, NOW)
        self.assertEqual([call[2] for call in github.cancel_calls], ["1"])
        first_deadline = int(store.get_marker(f"STOP#{month}", "INST#i-a")["deadline"])
        self.assertEqual(first_deadline, NOW + config.cancel_wait)
        _set_price(store, "i-a", 1, 100)
        seed_instance(
            store, ec2, instance_id="i-b", debit=600, month=month,
            launch_epoch=NOW - 5 * 3600, run_id="2", price_numer=1, price_denom=1,
        )
        add_cents(store, month, -600)
        second = run_poll(store, ec2, ec2, github, config, NOW + config.cancel_wait + 30)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual([call[2] for call in github.cancel_calls], ["1", "2"])
        self.assertIsNone(store.get_marker(f"STOP#{month}", "INST#i-a"))
        self.assertEqual(second.budget.terminated, ())
        ec2.views["i-b"] = InstanceView("i-b", "terminated", True, False)
        _set_price(store, "i-a", 1, 1)
        later = NOW + config.cancel_wait + 400
        third = run_poll(store, ec2, ec2, github, config, later)
        self.assertEqual(ec2.terminate_calls, [])
        self.assertEqual(third.budget.cancelled, ("i-a",))
        refreshed = store.get_marker(f"STOP#{month}", "INST#i-a")
        self.assertIsNotNone(refreshed)
        assert refreshed is not None
        self.assertEqual(int(refreshed["deadline"]), later + config.cancel_wait)
        self.assertNotEqual(int(refreshed["deadline"]), first_deadline)

    def test_guest_bootstrap_imports_without_the_source_tree(self) -> None:
        script = render_user_data("/overflow-watcher/jit/" + ("cd" * 32))
        self.assertNotIn("../src", script)
        with tempfile.TemporaryDirectory() as tmp:
            guest = Path(tmp) / "opt" / "overflow-watcher"
            path = Path(tmp) / "user-data.sh"
            path.write_text(script, encoding="utf-8")
            path.chmod(0o755)
            install_env = os.environ.copy()
            install_env.pop("PYTHONPATH", None)
            install_env["OVERFLOW_INSTALL_ROOT"] = str(guest)
            install_env["OVERFLOW_BOOTSTRAP"] = "install"
            subprocess.run(["sh", str(path)], cwd=tmp, env=install_env, check=True)
            probe = "import overflow_watcher.supervisor as supervisor; print(supervisor.__file__)"
            proc = subprocess.run(
                [sys.executable, "-c", probe],
                cwd=tmp,
                env={"PATH": os.environ["PATH"], "PYTHONPATH": str(guest), "HOME": tmp},
                capture_output=True,
                text=True,
                check=True,
            )
            loaded = Path(proc.stdout.strip())
            self.assertEqual(loaded, guest / "overflow_watcher" / "supervisor.py")
            self.assertFalse(str(ROOT / "src") in str(loaded))
            names = sorted(path.name for path in (guest / "overflow_watcher").glob("*.py"))
            self.assertEqual(names, ["__init__.py", "supervisor.py", "types.py"])

    def test_past_allowance_alert_is_not_claimed_when_emit_fails(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        month = month_key(NOW)
        seed_instance(
            store, ec2, instance_id="i-long", debit=6, month=month,
            launch_epoch=NOW - 7 * 3600, price_numer=1, price_denom=100,
        )
        with patch("overflow_watcher.controller.write_alert_line", side_effect=RuntimeError("log down")):
            accrue(store, AlertLog(), NOW)
        self.assertIsNone(store.get_marker("INST#i-long", "ALERT#ALLOWANCE"))
        self.assertIsNotNone(store.get_marker("INST#i-long", "ALERT#ALLOWANCE#RETRY"))

    def test_retry_held_alert_is_not_claimed_when_emit_fails(self) -> None:
        store = fresh_store()
        config = cfg()
        month = month_key(NOW)
        record = _record_for(sample_job(), config, "tok-old", NOW - RETRY_WINDOW_SECONDS - 5, month)
        self.assertTrue(
            store.reserve(token="tok-old", allowance=config.allowance, month=month, cap=3000, record=record)
        )
        with patch("overflow_watcher.controller.write_alert_line", side_effect=RuntimeError("log down")):
            resolve_reservations(store, FakeEc2(), AlertLog(), NOW)
        self.assertIsNone(store.get_marker("RES#tok-old", "ALERT#RETRY"))
        self.assertIsNotNone(store.get_marker("RES#tok-old", "ALERT#RETRY#RETRY"))

    def test_owned_stopping_is_exposure_not_an_unknown(self) -> None:
        for state in ("stopping", "shutting-down"):
            with self.subTest(state=state):
                store = fresh_store()
                ec2 = FakeEc2()
                github = FakeGitHub()
                month = month_key(NOW)
                seed_instance(
                    store, ec2, instance_id="i-stop", debit=600, month=month,
                    launch_epoch=NOW - 3600, run_id="7", price_numer=1, price_denom=1,
                )
                ec2.views["i-stop"] = InstanceView("i-stop", state, True, False)
                add_cents(store, month, 3250 - store.get_accrued(month))
                result = run_poll(store, ec2, ec2, github, cfg(), NOW)
                self.assertEqual(github.cancel_calls, [])
                self.assertEqual(ec2.terminate_calls, [])
                self.assertFalse(result.budget.block_launch)
                self.assertEqual(result.blocked_reason, "")
                self.assertEqual(
                    [item.kind for item in result.alerts.items if item.kind == "unknown-ownership"],
                    [],
                )
                self.assertEqual(len([item for item in result.alerts.items if item.kind == "grace"]), 1)

    def test_uncertain_owned_instance_still_blocks_launch(self) -> None:
        store = fresh_store()
        ec2 = FakeEc2()
        github = FakeGitHub()
        month = month_key(NOW)
        seed_instance(store, ec2, instance_id="i-fuzzy", debit=6, month=month, launch_epoch=NOW, run_id="1")
        ec2.views["i-fuzzy"] = InstanceView("i-fuzzy", "running", True, True)
        github.decision = Decision(False, "queued", (sample_job(),))
        result = run_poll(store, ec2, ec2, github, cfg(), NOW)
        self.assertEqual(result.launched, 0)
        self.assertEqual(result.blocked_reason, "unknown-inventory")
        self.assertTrue(any(item.kind == "unknown-ownership" for item in result.alerts.items))


def _set_price(store, instance_id: str, numer: int, denom: int) -> None:
    item = store._get(f"INST#{instance_id}", "META")
    assert item is not None
    record = json.loads(item["record"]["S"])
    record["priceNumer"] = numer
    record["priceDenom"] = denom
    store.client.update_item(
        TableName=store.table,
        Key={"pk": {"S": f"INST#{instance_id}"}, "sk": {"S": "META"}},
        UpdateExpression="SET #record = :record",
        ExpressionAttributeNames={"#record": "record"},
        ExpressionAttributeValues={":record": {"S": json.dumps(record, sort_keys=True)}},
    )


if __name__ == "__main__":
    unittest.main()
