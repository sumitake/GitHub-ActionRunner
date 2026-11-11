# SPDX-License-Identifier: MPL-2.0
"""Instance boot supervisor. Shutdown only on a proven normal completion."""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass

from overflow_watcher.types import REPORT_AFTER_SECONDS


@dataclass(frozen=True)
class Proof:
    listener_alive: bool
    worker_alive: bool | None
    listener_exit_code: int | None
    natural_exit: bool
    restarted: bool
    job_assigned: bool
    runner_config_present: bool


# Runner.Listener exits 3 (RunnerUpdating) or 4 (RunOnceRunnerUpdating) after
# a server-pushed self-update is staged; the updater writes update.finished
# when the new files are in place. Relaunch only after that flag is seen, at
# most three times. Otherwise the exit falls through to the report/park path.
UPDATE_EXIT_CODES = (3, 4)
UPDATE_WAIT_SECONDS = 120
MAX_UPDATE_RELAUNCHES = 3

KEEP = "keep"
SHUTDOWN = "shutdown"
REPORT_KEEP = "report-keep"


def normal_completion(proof: Proof) -> bool:
    """R3: exit code 0 is not proof while a worker or listener is still alive."""
    if not proof.runner_config_present:
        return False
    if proof.listener_alive:
        return False
    if proof.worker_alive is None or proof.worker_alive:
        return False
    if proof.restarted:
        return False
    if not proof.natural_exit:
        return False
    if proof.listener_exit_code != 0:
        return False
    if not proof.job_assigned:
        return False
    return True


def decide(proof: Proof, age_seconds: int, already_reported: bool) -> str:
    if normal_completion(proof):
        return SHUTDOWN
    needs_report = (
        age_seconds >= REPORT_AFTER_SECONDS
        and not already_reported
        and (
            not proof.job_assigned
            or not proof.natural_exit
            or not proof.runner_config_present
            or proof.listener_exit_code not in (None, 0)
        )
    )
    if needs_report:
        return REPORT_KEEP
    return KEEP


def apply_decision(action: str, shutdown: list[str], reports: list[str]) -> str:
    """Record the action. There is no remove and no EC2 terminate here."""
    if action == SHUTDOWN:
        shutdown.append("shutdown")
        return action
    if action == REPORT_KEEP:
        reports.append("report")
        return action
    return action


def _workers_alive(listener_pid: int) -> bool | None:
    """True/False when /proc can be read. None means the read failed closed."""
    proc_root = "/proc"
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return None
    for entry in entries:
        if not entry.isdigit() or entry == str(listener_pid):
            continue
        try:
            with open(os.path.join(proc_root, entry, "status"), encoding="utf-8") as handle:
                status = handle.read()
        except OSError:
            return None
        for line in status.splitlines():
            if line.startswith("PPid:") and line.split()[-1] == str(listener_pid):
                return True
    return False


def _shutdown() -> None:
    command = os.environ.get("OVERFLOW_SHUTDOWN_COMMAND", "shutdown -h now")
    subprocess.Popen(shlex.split(command))


def _wait_for_update(runner_root: str, wait_seconds: int = UPDATE_WAIT_SECONDS) -> bool:
    """True once the runner updater's flag file was seen and removed."""
    flag = os.path.join(runner_root, "update.finished")
    for _ in range(wait_seconds + 1):
        if os.path.exists(flag):
            os.remove(flag)
            return True
        time.sleep(1)
    return False


def _park(config_present: bool) -> None:
    """Never-assigned or unconfigured runners stay up and are reported once."""
    started = time.time()
    reported = False
    while True:
        proof = Proof(
            listener_alive=False,
            worker_alive=False,
            listener_exit_code=None,
            natural_exit=False,
            restarted=False,
            job_assigned=False,
            runner_config_present=config_present,
        )
        action = decide(proof, int(time.time() - started), reported)
        if action == REPORT_KEEP:
            reported = True
            print("overflow-supervisor report", flush=True)
        time.sleep(30)


def main() -> None:
    """Run one ephemeral runner and shut down only on a proven completion."""
    config_path = os.environ.get("RUNNER_CONFIG", "")
    if not config_path or not os.path.isfile(config_path):
        _park(False)
        return
    command = os.environ.get("RUNNER_COMMAND", "").strip()
    if not command:
        _park(True)
        return
    argv = shlex.split(command)
    if "--ephemeral" not in argv:
        argv.append("--ephemeral")
    runner_root = os.environ.get("OVERFLOW_RUNNER_ROOT", "/opt/actions-runner")
    proc = subprocess.Popen(argv, start_new_session=True)
    relaunches = 0
    update_failed = False
    started = time.time()
    reported = False
    saw_worker = False
    while True:
        exit_code = proc.poll()
        if exit_code in UPDATE_EXIT_CODES and not update_failed and relaunches < MAX_UPDATE_RELAUNCHES:
            # A staged self-update happens before any job in run-once mode.
            if _wait_for_update(runner_root):
                relaunches += 1
                saw_worker = False
                proc = subprocess.Popen(argv, start_new_session=True)
                continue
            update_failed = True
        worker_alive = _workers_alive(proc.pid)
        if worker_alive is None:
            time.sleep(5)
            continue
        if worker_alive:
            saw_worker = True
        proof = Proof(
            listener_alive=exit_code is None,
            worker_alive=worker_alive,
            listener_exit_code=exit_code,
            natural_exit=exit_code is not None,
            restarted=False,
            job_assigned=saw_worker,
            runner_config_present=True,
        )
        action = decide(proof, int(time.time() - started), reported)
        if action == SHUTDOWN:
            _shutdown()
            return
        if action == REPORT_KEEP:
            reported = True
            print("overflow-supervisor report", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    main()
