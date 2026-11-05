# SPDX-License-Identifier: MPL-2.0
"""R3: exit 0 is not a normal completion while a worker is alive."""

from __future__ import annotations

import unittest

from overflow_watcher.supervisor import KEEP, REPORT_KEEP, SHUTDOWN, Proof, apply_decision, decide
from overflow_watcher.types import REPORT_AFTER_SECONDS


def _proof(**overrides) -> Proof:
    base = dict(
        listener_alive=False,
        worker_alive=False,
        listener_exit_code=0,
        natural_exit=True,
        restarted=False,
        job_assigned=True,
        runner_config_present=True,
    )
    base.update(overrides)
    return Proof(**base)


class SupervisorTests(unittest.TestCase):
    def test_r3_exit_zero_with_live_worker_does_not_shutdown(self) -> None:
        shutdown: list[str] = []
        reports: list[str] = []
        action = decide(_proof(worker_alive=True, listener_exit_code=0), 10, False)
        apply_decision(action, shutdown, reports)
        self.assertEqual(action, KEEP)
        self.assertEqual(shutdown, [])

    def test_r3_proven_completion_shuts_down(self) -> None:
        shutdown: list[str] = []
        action = decide(_proof(), 10, False)
        apply_decision(action, shutdown, [])
        self.assertEqual(action, SHUTDOWN)
        self.assertEqual(shutdown, ["shutdown"])

    def test_r3_never_assigned_is_reported_not_shut_down(self) -> None:
        action = decide(_proof(job_assigned=False, listener_exit_code=None, natural_exit=False), REPORT_AFTER_SECONDS, False)
        self.assertEqual(action, REPORT_KEEP)


if __name__ == "__main__":
    unittest.main()
