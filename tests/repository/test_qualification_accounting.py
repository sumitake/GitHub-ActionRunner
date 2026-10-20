"""Physical allocation and observer liveness regressions for hosted qualification."""
# SPDX-License-Identifier: MPL-2.0
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _bounded_qualification as q
spec = importlib.util.spec_from_file_location('accounting_host', ROOT / 'scripts/release/qualify-runtime.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class QualificationAccounting(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = pathlib.Path(self.temporary.name)
        self.docker = self.base / 'docker'
        self.payload = self.docker / 'overlay2' / ('a' * 64) / 'diff'
        self.payload.mkdir(parents=True)
        self.image_id = 'sha256:' + 'b' * 64

    def catalog(self, upper=None):
        image = {'Id': self.image_id, 'RootFS': {'Layers': ['sha256:' + 'c' * 64]}, 'GraphDriver': {'Name': 'overlay2', 'Data': {'UpperDir': str(upper or self.payload)}}}
        with mock.patch.object(host, 'command', return_value=self.image_id), mock.patch.object(host, 'docker_json', return_value=[image]):
            return host.preinstalled_payloads(self.docker)

    def test_only_verified_immutable_payloads_are_frozen(self):
        self.assertEqual(self.catalog(), (self.payload,))
        outside = self.base / 'outside'
        outside.mkdir()
        with self.assertRaises(ValueError): self.catalog(outside)
        links = self.docker / 'overlay2/l'
        links.mkdir()
        (links / 'synthetic').symlink_to(self.payload)
        self.assertEqual(self.catalog(links / 'synthetic'), (self.payload,))
        with self.assertRaises(q.Stop): self.catalog(self.payload.parent)

    def test_preinstalled_contents_are_not_walked_and_pending_pulls_are_charged(self):
        excluded = self.catalog()
        old = self.payload / 'preinstalled'
        old.write_bytes(b'x' * 2**20)
        pending = self.docker / 'tmp/pending-pull'
        pending.parent.mkdir()
        pending.write_bytes(b'p' * 2**19)
        first = q.allocated([self.docker], excluded)[str(self.docker)]
        # Even an unreadable baseline payload must never be traversed.
        self.payload.chmod(0)
        try:
            self.assertEqual(q.allocated([self.docker], excluded)[str(self.docker)], first)
        finally:
            self.payload.chmod(0o755)
        old.unlink()
        self.assertEqual(q.allocated([self.docker], excluded)[str(self.docker)], first)
        blocks = pending.stat().st_blocks * 512
        pending.unlink()
        self.assertEqual(q.allocated([self.docker], excluded)[str(self.docker)], first - blocks)

    def test_interrupted_or_timed_out_accounting_never_uses_partial_output(self):
        for failure in (subprocess.TimeoutExpired(['du'], 20, output='0\t' + str(self.docker)), InterruptedError('synthetic interruption')):
            with self.subTest(failure=type(failure).__name__), mock.patch.object(q.subprocess, 'run', side_effect=failure) as run:
                with self.assertRaises(q.Stop): q.allocated([self.docker])
                self.assertEqual(run.call_count, 1)
                self.assertLessEqual(run.call_args.kwargs['timeout'], 20)

    def test_signalled_measurement_is_not_retried_or_admitted(self):
        result = types.SimpleNamespace(returncode=-15, stdout='0\t' + str(self.docker) + '\n')
        with mock.patch.object(q.subprocess, 'run', return_value=result) as run:
            with self.assertRaises(q.Stop): q.allocated([self.docker])
            self.assertEqual(run.call_count, 1)

    def test_first_observer_admission_accepts_a_valid_slow_sample(self):
        clock = types.SimpleNamespace(value=0)
        def advance(_seconds):
            clock.value += 1
            if clock.value == 18:
                (self.base / 'heartbeat.json').write_text('{"synthetic":"validated"}')
        with mock.patch.object(host.time, 'monotonic', side_effect=lambda: clock.value), mock.patch.object(host.time, 'sleep', side_effect=advance), mock.patch.object(q, 'checks') as checks:
            host.wait_for_observer(self.base)
        self.assertEqual(clock.value, 18)
        checks.assert_called_once_with({'synthetic': 'validated'})
        (self.base / 'heartbeat.json').unlink()
        clock.value = 0
        with mock.patch.object(host.time, 'monotonic', side_effect=lambda: clock.value), mock.patch.object(host.time, 'sleep', side_effect=lambda _seconds: setattr(clock, 'value', clock.value + 1)):
            with self.assertRaises(q.Stop): host.wait_for_observer(self.base)
        self.assertEqual(clock.value, 30)

    def test_ordinary_CI_probe_is_read_only_and_cannot_start_qualification(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('sudo /usr/bin/python3 -B scripts/release/qualify-runtime.py --check-accounting', text)
        self.assertNotIn('workflow_dispatch', text.split('      - name: Check read-only hosted allocation accounting', 1)[1].split('      - name:', 1)[0])
        with mock.patch.object(host, 'allocation_preflight', return_value=(self.docker, (), {'synthetic': {'free_bytes': 1}}, {str(self.docker): 2, str(self.base): 3})), mock.patch.object(host, 'child', side_effect=AssertionError('no worker')), mock.patch.object(host, 'host', side_effect=AssertionError('no qualification')), mock.patch.object(sys, 'argv', ['qualify-runtime.py', '--check-accounting', '--source', str(self.base)]), mock.patch('builtins.print') as output:
            host.main()
        report = json.loads(output.call_args.args[0])
        self.assertFalse(report['qualification_executed'])
        self.assertFalse(report['Docker_mutations'])

    def test_successful_but_late_accounting_is_rejected(self):
        clock = types.SimpleNamespace(value=0)
        def late(*_args, **_kwargs):
            clock.value = 21
            return types.SimpleNamespace(returncode=0, stdout='0\t' + str(self.docker) + '\n')
        with mock.patch.object(q.time, 'monotonic', side_effect=lambda: clock.value), mock.patch.object(q.subprocess, 'run', side_effect=late):
            with self.assertRaises(q.Stop): q.allocated([self.docker])

    def test_malformed_and_incomplete_successful_output_is_rejected(self):
        for output in ('', '0\t/elsewhere\n', '0\t' + str(self.docker) + '\n0\t' + str(self.docker) + '\n'):
            with mock.patch.object(q.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout=output)):
                with self.assertRaises(q.Stop): q.allocated([self.docker])

    def test_filesystem_aliases_count_once_and_deletion_cannot_discount_owned_bytes(self):
        source, work = self.base / 'source', self.base / 'work'
        source.mkdir()
        work.mkdir()
        baseline = host.filesystems((self.docker, source, work))
        self.assertEqual(len(baseline), 1)
        device = next(iter(baseline))
        baseline[device]['used_bytes'] = 10000
        current = {device: {**baseline[device], 'used_bytes': 100}}
        usage = {str(path): 1000 for path in (work, source, self.docker)}
        result = host.charge_allocation(usage, work, source, self.docker, current, baseline, q.RESERVE, 200)
        self.assertEqual(result['accounted_bytes'], q.RESERVE + 3000 + 64 * 2**20)
        current[device]['used_bytes'] = 15000
        result = host.charge_allocation(usage, work, source, self.docker, current, baseline, q.RESERVE, 200)
        self.assertEqual(result['accounted_bytes'], q.RESERVE + 5200 + 64 * 2**20)
        with self.assertRaises(q.Stop): host.charge_allocation(usage, work, source, self.docker, {}, baseline, q.RESERVE, 200)

    def sample_fixture(self):
        work, source, control = (self.base / name for name in ('work', 'source', 'control'))
        for path in (work, source, control, work / 'evidence'): path.mkdir()
        (work / 'scope.json').write_text(json.dumps({'cgroup': str(control)}))
        values = {'cpu.max': '400000 100000', 'memory.max': str(q.MEMORY), 'memory.swap.max': '0', 'memory.events': 'oom 0\noom_kill 0', 'memory.current': '0', 'memory.peak': '0', 'pids.max': '1024', 'pids.current': '0', 'pids.peak': '0'}
        for key, value in values.items(): (control / key).write_text(value)
        writable = self.docker / 'overlay2' / ('d' * 64)
        (writable / 'diff').mkdir(parents=True)
        (writable / 'work').mkdir()
        (writable / 'diff/tiny').write_bytes(b'x')
        item = {'Id': 'synthetic', 'State': {'Running': False, 'Pid': 0}, 'SizeRw': 1, 'Mounts': [], 'HostConfig': {'NanoCpus': 4000000000, 'Memory': q.MEMORY, 'MemorySwap': q.MEMORY, 'PidsLimit': 1024, 'CgroupParent': 'synthetic'}, 'GraphDriver': {'Data': {'UpperDir': str(writable / 'diff'), 'WorkDir': str(writable / 'work')}}}
        original_run, original_iterdir = subprocess.run, pathlib.Path.iterdir
        def run(args, **kwargs):
            if args[0] == 'docker':
                self.assertNotIn('--size', args)
                return types.SimpleNamespace(returncode=0, stdout=json.dumps([item]))
            return original_run(args, **kwargs)
        self.enterContext(mock.patch.object(host, 'own_containers', return_value=['synthetic']))
        self.enterContext(mock.patch.object(host.subprocess, 'run', side_effect=run))
        self.enterContext(mock.patch.object(pathlib.Path, 'iterdir', lambda path: iter(()) if str(path) == '/proc' else original_iterdir(path)))
        self.enterContext(mock.patch.object(q, 'checks'))
        return work, source, host.filesystems((work, self.docker, source))

    def test_writable_limit_uses_allocated_blocks_including_tiny_file_slack(self):
        work, source, baseline = self.sample_fixture()
        row = host.sample(work, {'checkout': str(source), 'run_id': '123', 'carry_in_bytes': q.RESERVE}, self.docker, self.catalog(), baseline, 0)
        self.assertGreater(row['writable_root_bytes'], 1)
        self.assertEqual(row['writable_root_bytes'], sum(q.du(pathlib.Path(row['containers'][0][key])) for key in ('upper', 'work')))
        self.assertEqual(row['docker_allocated_bytes'], q.allocated([self.docker], self.catalog())[str(self.docker)])

    def test_failed_measurement_does_not_refresh_the_observer_heartbeat(self):
        work, source, baseline = self.sample_fixture()
        heartbeat = work / 'heartbeat.json'
        heartbeat.write_bytes(b'prior validated sample')
        before = heartbeat.stat().st_mtime_ns
        with mock.patch.object(q, 'allocated', side_effect=q.Stop('synthetic slow accounting')):
            with self.assertRaises(q.Stop): host.sample(work, {'checkout': str(source), 'run_id': '123', 'carry_in_bytes': q.RESERVE}, self.docker, (), baseline, 0)
        self.assertEqual(heartbeat.read_bytes(), b'prior validated sample')
        self.assertEqual(heartbeat.stat().st_mtime_ns, before)
        self.assertFalse((work / 'evidence/resource-samples.jsonl').exists())
