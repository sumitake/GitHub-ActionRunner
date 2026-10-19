#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Manually dispatched, bounded offline A/B qualification on a disposable hosted VM."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _bounded_qualification as q


def command(args, **kwargs):
    return subprocess.check_output(args, text=True, timeout=60, **kwargs).strip()


def admission(source, event, environment):
    if environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or environment.get('RUNNER_ENVIRONMENT') != 'github-hosted' or environment.get('RUNNER_OS') != 'Linux' or environment.get('RUNNER_ARCH') != 'X64':
        raise q.Stop('manual standard hosted Linux runner required')
    repository = event.get('repository', {})
    owner = repository.get('owner', {}).get('login')
    if repository.get('private') is not False or repository.get('full_name') != environment.get('GITHUB_REPOSITORY') or not owner or environment.get('GITHUB_ACTOR') != owner:
        raise q.Stop('public owner dispatch required')
    if environment.get('GITHUB_REF') != 'refs/heads/codex/runner-dotnet-servicing' or environment.get('GITHUB_RUN_ATTEMPT') != '1':
        raise q.Stop('candidate branch required')
    values = event.get('inputs')
    if not isinstance(values, dict) or set(values) != {'bounded_qualification', 'expected_commit', 'expected_tree', 'carry_in_bytes'} or values['bounded_qualification'] != 'true':
        raise q.Stop('closed bounded dispatch inputs required')
    commit, tree = values['expected_commit'], values['expected_tree']
    if not isinstance(commit, str) or re.fullmatch('[0-9a-f]{40}', commit) is None or not isinstance(tree, str) or re.fullmatch('[0-9a-f]{40}', tree) is None or environment.get('GITHUB_SHA') != commit:
        raise q.Stop('exact candidate identity required')
    carry = values['carry_in_bytes']
    if not isinstance(carry, str) or re.fullmatch('[1-9][0-9]{0,10}', carry) is None or not q.RESERVE <= int(carry) < q.SOFT - 64 * 2**20:
        raise q.Stop('retained carry-in exceeds admission envelope')
    if source.resolve(strict=True) != source or command(['git', '-c', 'safe.directory=' + str(source), 'rev-parse', 'HEAD'], cwd=source) != commit or command(['git', '-c', 'safe.directory=' + str(source), 'rev-parse', 'HEAD^{tree}'], cwd=source) != tree or command(['git', '-c', 'safe.directory=' + str(source), 'status', '--porcelain', '--untracked-files=all'], cwd=source):
        raise q.Stop('dirty or different candidate checkout')
    run_id = environment.get('GITHUB_RUN_ID', '')
    if re.fullmatch('[1-9][0-9]{0,19}', run_id) is None:
        raise q.Stop('run identity unavailable')
    epoch = int(command(['git', '-c', 'safe.directory=' + str(source), 'show', '-s', '--format=%ct', 'HEAD'], cwd=source))
    return {'schema_version': 1, 'commit': commit, 'tree': tree, 'epoch': epoch, 'carry_in_bytes': int(carry), 'run_id': run_id, 'repository': repository['full_name'], 'candidate_test_plan_end_state': 'stopped/disabled at N+2; production runners untouched; operator-led recovery', 'live_operations': False}


def safe_environment(root, go_root):
    value = {'PATH': str(go_root / 'bin') + ':/usr/local/bin:/usr/bin:/bin', 'GOROOT': str(go_root), 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp'), 'GOCACHE': str(root / 'go-build'), 'GOMODCACHE': str(root / 'go-mod'), 'GOTOOLCHAIN': 'local', 'GOTELEMETRY': 'off', 'GOMAXPROCS': '4', 'GOMEMLIMIT': '1GiB', 'GOFLAGS': '-p=1 -mod=readonly', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0'}
    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
        if key in os.environ:
            if key.lower() != 'no_proxy':
                proxy = urllib.parse.urlsplit(os.environ[key])
                if proxy.username is not None or proxy.password is not None:
                    raise q.Stop('credentialed transport refused')
            value[key] = os.environ[key]
    return value


def docker_json(args):
    return json.loads(command(['docker', *args]))


def own_containers(label):
    raw = command(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'label=' + label])
    return raw.splitlines() if raw else []


def compose_worker(root, label):
    """Reconstruct the existing bounded tool image from public hosted OS tools."""
    tools = root / 'buildkit-tools'
    tools.mkdir()
    image_before = set(command(['docker', 'image', 'ls', '-aq', '--no-trunc']).splitlines())
    subprocess.run(['docker', 'pull', q.BUILDKit], check=True, timeout=300)
    image = docker_json(['image', 'inspect', q.BUILDKit])[0]
    if q.BUILDKit.split('@', 1)[1] not in [item.split('@', 1)[-1] for item in image.get('RepoDigests', [])]:
        raise q.Stop('BuildKit image digest unavailable')
    container = command(['docker', 'create', '--label', label, q.BUILDKit])
    try:
        for name in ('buildkitd', 'buildctl', 'buildkit-runc'):
            subprocess.run(['docker', 'cp', container + ':/usr/bin/' + name, str(tools / name)], check=True, timeout=60)
    finally:
        subprocess.run(['docker', 'rm', container], check=True, timeout=30)
    if image['Id'] not in image_before:
        subprocess.run(['docker', 'image', 'rm', q.BUILDKit], check=True, timeout=60)
    tree = root / 'worker-rootfs'
    tree.mkdir()
    files = set()
    for name in 'rmdir xz sh bash git env python3 jq curl tar gzip ar awk basename chmod cp cut dirname find ln mkdir mktemp mv readlink rm sort sha256sum stat touch date wc cat head sed grep xargs install cmp uname id sleep timeout du df ps kill'.split():
        path = shutil.which(name)
        if not path:
            raise q.Stop('missing hosted tool ' + name)
        files.add(path)
    version = sys.version_info
    python_dir = pathlib.Path('/usr/lib') / ('python' + str(version.major) + '.' + str(version.minor))
    for path in (python_dir, pathlib.Path('/etc/ssl/certs')):
        shutil.copytree(path, tree / str(path).lstrip('/'), symlinks=False)
    files.update(str(p) for p in python_dir.rglob('*.so'))
    for file in list(files):
        result = subprocess.run(['ldd', file], capture_output=True, text=True, timeout=10)
        files.update(re.findall(r'(/[^\s()]+)', result.stdout))
    records = []
    for file in sorted(files):
        source = pathlib.Path(file)
        if source.is_file():
            destination = tree / file.lstrip('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            records.append({'path': file, 'sha256': q.sha(source), 'bytes': source.stat().st_size})
    for file in ('/usr/lib/git-core/git', '/usr/lib/git-core/git-upload-pack', '/usr/lib/git-core/git-receive-pack', '/etc/nsswitch.conf'):
        if pathlib.Path(file).exists():
            destination = tree / file.lstrip('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, destination)
            records.append({'path': file, 'sha256': q.sha(file)})
    for name in ('buildkitd', 'buildctl', 'buildkit-runc'):
        shutil.copy2(tools / name, tree / 'usr/bin' / name)
    (tree / 'bin').mkdir(exist_ok=True)
    shutil.copy2(shutil.which('sh'), tree / 'bin/sh')
    for name in ('tmp', 'run', 'root', 'etc', 'work', 'toolchain/go'):
        (tree / name).mkdir(parents=True, exist_ok=True)
    (tree / 'etc/passwd').write_text('root:x:0:0:builder:/root:/bin/sh\nnobody:x:65534:65534:nobody:/tmp:/bin/sh\n')
    (tree / 'etc/group').write_text('root:x:0:\nnogroup:x:65534:\n')
    os.chmod(tree / 'tmp', 0o1777)
    archive = root / 'worker-rootfs.tar'
    with tarfile.open(archive, 'w') as output:
        for path in sorted(tree.rglob('*')):
            info = output.gettarinfo(str(path), arcname=path.relative_to(tree).as_posix())
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = 'root'
            if path.is_file():
                with path.open('rb') as stream:
                    output.addfile(info, stream)
            else:
                output.addfile(info)
    identifier = command(['docker', 'import', '--change', 'LABEL ' + label, str(archive)])
    q.write(root / 'evidence/worker-inputs.json', {'buildkit_upstream': q.BUILDKit, 'rootfs_sha256': q.sha(archive), 'image_id': identifier, 'public_host_tools': records, 'buildkit_binaries': {p.name: q.sha(p) for p in tools.iterdir()}})
    archive.unlink()
    shutil.rmtree(tree)
    shutil.rmtree(tools)
    return identifier


def sdk_rebuild(root, environment, parent, label):
    source = root / 'source'
    path = source / 'scripts/release/rebuild-runner.py'
    spec = importlib.util.spec_from_file_location('bounded_selected_runner_rebuild', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    original = value.sdk_container_command
    def sdk_command(work, descriptor, env):
        args = original(work, descriptor, env)
        return args[:2] + ['--cgroup-parent', parent, '--label', label] + args[2:]
    value.sdk_container_command = sdk_command
    verify = value.verify_startup_evidence
    def startup(evidence, *args):
        result = verify(evidence, *args)
        shutil.copytree(evidence, root / 'evidence/sdk-startup')
        return result
    value.verify_startup_evidence = startup
    destination = root / 'selected-runner'
    destination.mkdir()
    descriptor = json.loads((source / 'internal/buildinfo/runner_rebuild.json').read_text())
    existed = subprocess.run(['docker', 'image', 'inspect', descriptor['sdk_container_image']], capture_output=True).returncode == 0
    old_args, old_env = sys.argv, dict(os.environ)
    try:
        sys.argv = [str(path), '--output-directory', str(destination)]
        os.environ.clear()
        os.environ.update(environment)
        value.main()
    finally:
        sys.argv = old_args
        os.environ.clear()
        os.environ.update(old_env)
    files = list(destination.iterdir())
    if len(files) != 1 or q.sha(files[0]) != descriptor['linux_x64_sha256'] or files[0].stat().st_size != descriptor['archive_bytes']:
        raise q.Stop('rebuilt payload identity mismatch')
    q.write(root / 'evidence/selected-payload.json', {'descriptor': descriptor, 'archive_sha256': q.sha(files[0]), 'archive_bytes': files[0].stat().st_size, 'all_entrypoints_verified': True})
    if not existed:
        subprocess.run(['docker', 'image', 'rm', descriptor['sdk_container_image']], check=True, timeout=60)
    cache = root / 'go-build'
    if cache.exists():
        shutil.rmtree(cache)


def child(root, go_root):
    inputs = json.loads((root / 'inputs.json').read_text())
    slice_name = 'pghar-qualification-' + inputs['run_id'] + '.slice'
    subprocess.run(['systemctl', 'set-property', '--runtime', slice_name, 'CPUQuota=400%', 'CPUQuotaPeriodSec=100ms', 'MemoryMax=' + str(q.MEMORY), 'MemorySwapMax=0', 'TasksMax=1024'], check=True, timeout=20)
    group = command(['systemctl', 'show', '--property=ControlGroup', '--value', slice_name])
    if not group.startswith('/') or '..' in group.split('/') or not group.endswith('/' + slice_name):
        raise q.Stop('unexpected aggregate cgroup')
    control = pathlib.Path('/sys/fs/cgroup') / group.lstrip('/')
    q.write(root / 'scope.json', {'name': slice_name, 'cgroup': str(control)})
    admitted = False
    for _ in range(150):
        if (root / 'heartbeat.json').exists():
            q.checks(json.loads((root / 'heartbeat.json').read_text()))
            admitted = True
            break
        time.sleep(.1)
    if not admitted:
        raise q.Stop('host observer did not admit aggregate bounds')
    parent = slice_name if docker_json(['info', '--format', '{{json .CgroupDriver}}']) == 'systemd' else group
    label = 'pghar.qualification=' + inputs['run_id']
    environment = safe_environment(root, go_root)
    environment.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='safe.directory', GIT_CONFIG_VALUE_0=str(root / 'source'))
    for name in ('home', 'tmp'):
        (root / name).mkdir(exist_ok=True)
    old_env = dict(os.environ)
    os.environ.clear()
    os.environ.update(environment)
    worker = image = None
    try:
        subprocess.run(['git', '-c', 'safe.directory=' + str(inputs['checkout']), 'clone', '--no-local', '--quiet', str(inputs['checkout']), str(root / 'source')], check=True, env=environment, timeout=90)
        subprocess.run(['git', 'checkout', '--quiet', '--detach', inputs['commit']], cwd=root / 'source', check=True, env=environment, timeout=30)
        q.write(root / 'phase.json', {'phase': 'selected-SDK-rebuild'})
        sdk_rebuild(root, environment, parent, label)
        q.write(root / 'phase.json', {'phase': 'worker-bootstrap'})
        image = compose_worker(root, label)
        args = ['docker', 'create', '--pull=never', '--cpus=4', '--memory=' + str(q.MEMORY), '--memory-swap=' + str(q.MEMORY), '--pids-limit=1024', '--cgroup-parent', parent, '--label', label, '--restart=no', '--log-opt=max-size=5m', '--log-opt=max-file=2', '--mount', 'type=bind,src=' + str(root) + ',dst=/work', '--mount', 'type=bind,src=' + str(go_root) + ',dst=/toolchain/go,readonly']
        worker_env = {**environment, 'PATH': '/toolchain/go/bin:/usr/bin:/bin', 'GOROOT': '/toolchain/go'}
        for key, entry in worker_env.items():
            args += ['--env', key + '=' + entry]
        for mode, privileged in (('worker', True), ('scan', False)):
            q.write(root / 'phase.json', {'phase': 'build-worker' if privileged else 'fresh-security-and-SBOM'})
            worker = command(args[:2] + (['--privileged'] if privileged else []) + args[2:] + [image, 'python3', '/work/source/scripts/release/qualify-runtime.py', '--' + mode, '/work'])
            q.write(root / 'worker.json', {'container_id': worker, 'image_id': image, 'parent': parent, 'privileged': privileged})
            subprocess.run(['docker', 'start', worker], check=True, timeout=30)
            # Only BuildKit needs privilege. Scanners receive the same bounded
            # task mount and no daemon socket, hosted checkout, or credentials.
            result = subprocess.run(['docker', 'wait', worker], check=True, capture_output=True, text=True)
            with (root / ('evidence/' + mode + '-console.log')).open('wb') as stream:
                subprocess.run(['docker', 'logs', worker], stdout=stream, stderr=subprocess.STDOUT, timeout=30, check=False)
            if result.stdout.strip() != '0':
                raise q.Stop('bounded ' + mode + ' container failed')
            q.write(root / ('evidence/' + mode + '-terminal.json'), {'exit_code': 0, 'inspect': {k: docker_json(['inspect', '--size', worker])[0][k] for k in ('Id', 'State', 'SizeRw')}})
            subprocess.run(['docker', 'rm', worker], check=True, timeout=30)
            worker = None
        lineage = root / 'evidence/actual-worker-lineage.jsonl'
        names = {row['executable'] for line in lineage.read_text().splitlines() for row in json.loads(line)} if lineage.exists() else set()
        if not {'dotnet', 'buildkit-runc'} <= names:
            raise q.Stop('actual SDK/BuildKit descendant proof missing')
    finally:
        if worker is not None:
            subprocess.run(['docker', 'rm', '--force', worker], timeout=30, check=False)
        if image is not None:
            subprocess.run(['docker', 'image', 'rm', image], timeout=60, check=False)
        try:
            final = json.loads((root / 'evidence/scan-result.json').read_text()) if (root / 'evidence/scan-result.json').exists() else {}
            final.update(status='pass' if sys.exc_info()[0] is None and final.get('status') == 'pass' else 'fail', resource_qualification='pending-final-observer', release_admitted=False, live_operations=False)
            q.write(root / 'evidence/RESULT.json', final)
            # Export remains inside the common cgroup while the host observer
            # enforces retained allocation, kernel limits and reserve floors.
            export_evidence(root, guarded=True)
        finally:
            os.environ.clear()
            os.environ.update(old_env)


def sample(root, inputs, docker_root, docker_baseline):
    scope = json.loads((root / 'scope.json').read_text())
    control = pathlib.Path(scope['cgroup'])
    kernel = {key: (control / key).read_text().strip() for key in ('cpu.max', 'memory.max', 'memory.swap.max', 'memory.events', 'memory.current', 'memory.peak', 'pids.max', 'pids.current', 'pids.peak')}
    ids = own_containers('pghar.qualification=' + inputs['run_id'])
    writable = 0
    containers = []
    for identifier in ids:
        result = subprocess.run(['docker', 'inspect', '--size', identifier], capture_output=True, text=True, timeout=15)
        if result.returncode:
            if identifier in own_containers('pghar.qualification=' + inputs['run_id']):
                raise q.Stop('owned container inspection unavailable')
            continue
        item = json.loads(result.stdout)[0]
        config = item['HostConfig']
        if config['NanoCpus'] != 4000000000 or config['Memory'] != q.MEMORY or config['MemorySwap'] != q.MEMORY or config['PidsLimit'] != 1024 or any(m['Destination'] == '/var/run/docker.sock' for m in item['Mounts']):
            # The source image is copied from an unstarted container during
            # bootstrap; only running build descendants consume this allowance.
            if item['State']['Running']:
                raise q.Stop('running descendant escaped resource policy')
        pid = item['State']['Pid']
        if pid:
            lineage = pathlib.Path('/proc', str(pid), 'cgroup').read_text().strip().split(':', 2)[-1]
            expected = str(control.relative_to('/sys/fs/cgroup'))
            if not lineage.lstrip('/').startswith(expected + '/'):
                raise q.Stop('running container escaped aggregate cgroup')
        writable += item.get('SizeRw', 0)
        containers.append({'id': identifier, 'running': item['State']['Running'], 'pid': pid, 'size_rw': item.get('SizeRw', 0), 'cgroup_parent': config['CgroupParent']})
    memory = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    filesystem = os.statvfs(root)
    docker_filesystem = os.statvfs(docker_root)
    row = {'captured_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'kernel': kernel, 'work_bytes': q.du(root), 'docker_growth_bytes': max(0, q.du(docker_root) - docker_baseline), 'checkout_bytes': q.du(pathlib.Path(inputs['checkout'])), 'carry_in_bytes': inputs['carry_in_bytes'], 'control_reserve_bytes': 64 * 2**20, 'writable_root_bytes': writable, 'free_bytes': min(filesystem.f_bavail * filesystem.f_frsize, docker_filesystem.f_bavail * docker_filesystem.f_frsize), 'free_inodes': min(filesystem.f_favail, docker_filesystem.f_favail), 'available_memory_bytes': int(memory['MemAvailable'].split()[0]) * 1024, 'containers': containers}
    workers = []
    for proc in pathlib.Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            executable = (proc / 'cmdline').read_bytes().split(b'\x00', 1)[0].rsplit(b'/', 1)[-1]
            if executable not in (b'buildkit-runc', b'dotnet'):
                continue
            member_group = (proc / 'cgroup').read_text().strip().split(':', 2)[-1]
            if not member_group.lstrip('/').startswith(str(control.relative_to('/sys/fs/cgroup')) + '/'):
                raise q.Stop('actual build worker escaped aggregate cgroup')
            workers.append({'pid': int(proc.name), 'executable': executable.decode(), 'cgroup': member_group, 'aggregate_limits_apply': True})
        except (FileNotFoundError, ProcessLookupError):
            pass
    if workers:
        with (root / 'evidence/actual-worker-lineage.jsonl').open('a') as stream:
            stream.write(json.dumps(workers) + '\n')
    row['accounted_bytes'] = sum(row[key] for key in ('work_bytes', 'docker_growth_bytes', 'checkout_bytes', 'carry_in_bytes', 'control_reserve_bytes'))
    q.write(root / 'heartbeat.json', row)
    with (root / 'evidence/resource-samples.jsonl').open('a') as stream:
        stream.write(json.dumps(row) + '\n')
    q.checks(row)
    return row


def export_evidence(root, guarded=False):
    """Always retain raw exports; publish only text that passes public policy."""
    source, evidence, public = root / 'source', root / 'evidence', root / 'public'
    # Preflight the whole possible bundle before any copy. Oversized failures
    # retain original raw outputs and cannot allocate a duplicate public tree.
    if sum(path.stat().st_size for path in evidence.rglob('*') if path.is_file()) > q.ARTIFACT_LIMIT - 2**20:
        raise q.Stop('raw evidence exceeds fixed 1 GiB transfer cap')
    def guard():
        if guarded:
            heartbeat = root / 'heartbeat.json'
            if time.time() - heartbeat.stat().st_mtime > 30:
                raise q.Stop('export observer heartbeat stale')
            q.checks(json.loads(heartbeat.read_text()))
    guard()
    public.mkdir()
    raw = evidence / 'artifacts'
    if raw.exists():
        raw.rename(public / 'artifacts')
    rejected = []
    producer_available = (root / 'debian-cache').exists() and (root / 'go-mod').exists()
    for path in sorted(evidence.rglob('*')):
        if not path.is_file():
            continue
        guard()
        args = ['python3', str(source / 'scripts/sanitize_public.py'), '--generated', str(path)]
        if producer_available:
            args += ['--verified-runner-licenses', '--verified-dependency-metadata', '--dependency-debian-cache', str(root / 'debian-cache'), '--dependency-go-module-cache', str(root / 'go-mod')]
        result = subprocess.run(args, cwd=source, env={**os.environ, 'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'safe.directory', 'GIT_CONFIG_VALUE_0': str(source)}, capture_output=True, timeout=180)
        if result.returncode:
            rejected.append({'path': path.relative_to(evidence).as_posix(), 'sha256': q.sha(path), 'bytes': path.stat().st_size})
            continue
        target = public / path.relative_to(evidence)
        target.parent.mkdir(parents=True, exist_ok=True)
        guard()
        shutil.copyfile(path, target)
    if rejected:
        q.write(public / 'RESULT.json', {'status': 'fail', 'public_evidence_sanitization': 'fail', 'release_admitted': False, 'live_operations': False})
    guard()
    files = q.inventory(public)
    if sum(item['bytes'] for item in files) > q.ARTIFACT_LIMIT:
        raise q.Stop('raw evidence exceeds fixed 1 GiB transfer cap')
    q.write(public / 'evidence-inventory.json', {'files': files, 'raw_AB_retained': True, 'unsafe_text_withheld': rejected, 'artifact_qualification_admitted': not rejected and (public / 'RESULT.json').exists() and json.loads((public / 'RESULT.json').read_text()).get('status') == 'pass'})
    # Text failures never waive a release/privacy gate. Complete raw A/B bytes
    # and the safe receipts remain downloadable even on a failed attempt.
    if rejected:
        raise q.Stop('some text evidence failed public sanitization')


def retain_failure(root):
    """After worker shutdown, retain raw bytes using only the control reserve."""
    public, evidence = root / 'public', root / 'evidence'
    raw = public / 'artifacts' if (public / 'artifacts').exists() else evidence / 'artifacts'
    if not raw.exists():
        raise q.Stop('no completed raw exports available')
    files = q.inventory(raw)
    if sum(item['bytes'] for item in files) > q.ARTIFACT_LIMIT - 2**20:
        raise q.Stop('raw failure evidence exceeds transfer cap')
    # No text copy, scanner, compilation, download or raw payload allocation.
    # Previously copied text is redundant; its originals remain in evidence.
    public.mkdir(exist_ok=True)
    for path in public.iterdir():
        if path.name != 'artifacts':
            shutil.rmtree(path) if path.is_dir() else path.unlink()
    if raw != public / 'artifacts':
        raw.rename(public / 'artifacts')
    q.write(public / 'RESULT.json', {'status': 'fail', 'resource_qualification': 'not-admitted', 'raw_failure_retention_only': True, 'release_admitted': False, 'live_operations': False})
    files = [{**entry, 'path': 'artifacts/' + entry['path']} for entry in files]
    files.append({'path': 'RESULT.json', 'bytes': (public / 'RESULT.json').stat().st_size, 'sha256': q.sha(public / 'RESULT.json')})
    manifest = {'files': files, 'completed_raw_exports_retained': True, 'unsafe_text_withheld': [], 'artifact_qualification_admitted': False}
    encoded = json.dumps(manifest, indent=2) + '\n'
    if len(encoded.encode()) > 2**20:
        raise q.Stop('failure retention metadata exceeds control allowance')
    (public / 'evidence-inventory.json').write_text(encoded)


def host(source, root, event_path, go_root):
    if os.geteuid() != 0:
        raise q.Stop('ephemeral hosted root supervisor required')
    info = event_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 2**20 or event_path.resolve(strict=True) != event_path:
        raise q.Stop('unsafe dispatch event')
    event = json.loads(event_path.read_text(), object_pairs_hook=lambda pairs: dict(pairs) if len(dict(pairs)) == len(pairs) else (_ for _ in ()).throw(q.Stop('duplicate event key')))
    inputs = admission(source, event, os.environ)
    if root.exists() or root.parent.resolve(strict=True) != root.parent or not root.is_absolute():
        raise q.Stop('fresh canonical output directory required')
    # The selected Go toolchain must already exist in the hosted image. It is
    # immutable baseline OS tooling, not a cache downloaded outside accounting.
    if go_root.resolve(strict=True) != go_root or command([str(go_root / 'bin/go'), 'version'], env={'PATH': '/usr/bin:/bin', 'GOTOOLCHAIN': 'local'}) != 'go version go1.26.9 linux/amd64':
        raise q.Stop('preinstalled pinned Go toolchain unavailable')
    docker_info = docker_json(['info', '--format', '{{json .}}'])
    if docker_info['CgroupVersion'] != '2' or docker_info['Driver'] != 'overlay2':
        raise q.Stop('hosted cgroup v2 and overlay2 required')
    docker_root = pathlib.Path(docker_info['DockerRootDir'])
    if docker_root.resolve(strict=True) != docker_root:
        raise q.Stop('indirect Docker data root')
    docker_baseline = q.du(docker_root)
    memory = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    fs = os.statvfs(root.parent)
    if int(memory['MemAvailable'].split()[0]) * 1024 < 11 * q.GIB or fs.f_favail < 700000 or fs.f_bavail * fs.f_frsize < 13 * q.GIB + (q.SOFT - inputs['carry_in_bytes']):
        raise q.Stop('hosted admission reserve unavailable')
    root.mkdir(mode=0o700)
    (root / 'evidence').mkdir()
    inputs['checkout'] = str(source)
    q.write(root / 'inputs.json', inputs)
    q.write(root / 'evidence/source-inputs.json', {key: value for key, value in inputs.items() if key != 'checkout'})
    scope_name = 'pghar-qualification-' + inputs['run_id']
    process = None
    error = None
    old_handlers = {}
    def cancelled(*_args):
        raise q.Stop('qualification cancelled')
    for signum in (signal.SIGINT, signal.SIGTERM):
        old_handlers[signum] = signal.signal(signum, cancelled)
    try:
        args = ['systemd-run', '--scope', '--quiet', '--unit=' + scope_name, '--slice=' + scope_name + '.slice', '/usr/bin/python3', str(pathlib.Path(__file__).resolve()), '--scope-child', str(root), '--go-root', str(go_root)]
        # Only this control supervisor sees the dispatch metadata. Credentials
        # and Actions runtime tokens are excluded from every child environment.
        log = (root / 'evidence/supervisor.log').open('wb')
        process = subprocess.Popen(args, env=safe_environment(root, go_root), stdout=log, stderr=subprocess.STDOUT)
        log.close()
        started = time.monotonic()
        while process.poll() is None:
            if time.monotonic() - started >= 85 * 60:
                raise q.Stop('85-minute worker deadline')
            if (root / 'scope.json').exists():
                sample(root, inputs, docker_root, docker_baseline)
            elif time.monotonic() - started > 20:
                raise q.Stop('aggregate cgroup admission missing')
            time.sleep(2)
        if process.returncode:
            raise q.Stop('qualification scope failed')
        sample(root, inputs, docker_root, docker_baseline)
    except BaseException as failure:
        error = type(failure).__name__ + ': ' + str(failure)
        q.write(root / 'evidence/FAILURE.json', {'error': error, 'release_admitted': False, 'live_operations': False})
    finally:
        # All names/IDs are task-owned. Never stop the daemon or unrelated jobs.
        subprocess.run(['systemctl', 'stop', scope_name + '.slice'], timeout=30, check=False, capture_output=True)
        for identifier in own_containers('pghar.qualification=' + inputs['run_id']):
            subprocess.run(['docker', 'rm', '--force', identifier], timeout=30, check=False, capture_output=True)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        final = json.loads((root / 'evidence/scan-result.json').read_text()) if (root / 'evidence/scan-result.json').exists() else {}
        final.update(status='pass' if error is None and final.get('status') == 'pass' else 'fail', resource_qualification='pass' if error is None else 'fail', release_admitted=False, live_operations=False)
        q.write(root / 'evidence/RESULT.json', final)
        q.write(root / 'evidence/terminal.json', {'workers_joined': not own_containers('pghar.qualification=' + inputs['run_id']), 'scope_exit_code': None if process is None else process.returncode, 'budget_or_execution_error': error, 'live_operations': False, 'production_runners_touched': False})
    if not (root / 'public/evidence-inventory.json').exists():
        # A budget/deadline kill can interrupt child finally. Only move completed
        # raw exports into the upload bundle, under unchanged kernel limits.
        # Hashing and <=1MiB metadata use the already-accounted control reserve.
        args = ['systemd-run', '--scope', '--quiet', '--unit=' + scope_name + '-retain', '--property=CPUQuota=400%', '--property=CPUQuotaPeriodSec=100ms', '--property=MemoryMax=' + str(q.MEMORY), '--property=MemorySwapMax=0', '--property=TasksMax=1024', '/usr/bin/python3', str(pathlib.Path(__file__).resolve()), '--retain-failure', str(root)]
        with (root / 'evidence/failure-retention.log').open('wb') as stream:
            retention = subprocess.Popen(args, env=safe_environment(root, go_root), stdout=stream, stderr=subprocess.STDOUT)
            try:
                retention.wait(timeout=120)
            except subprocess.TimeoutExpired:
                subprocess.run(['systemctl', 'stop', scope_name + '-retain.scope'], check=False, timeout=20, capture_output=True)
                retention.kill()
                retention.wait(timeout=10)
    # Only small final admission metadata is written after the capped export.
    # Raw files and all expensive scanning, sanitizing and hashing ran inside it.
    public = root / 'public'
    manifest_path = public / 'evidence-inventory.json'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if not manifest.get('artifact_qualification_admitted'):
            final.update(status='fail')
        if manifest['unsafe_text_withheld']:
            final.update(status='fail', public_evidence_sanitization='fail')
        q.write(public / 'RESULT.json', final)
        manifest['files'] = [entry for entry in manifest['files'] if entry['path'] != 'RESULT.json'] + [{'path': 'RESULT.json', 'bytes': (public / 'RESULT.json').stat().st_size, 'sha256': q.sha(public / 'RESULT.json')}]
        manifest['artifact_qualification_admitted'] = final['status'] == 'pass'
        q.write(manifest_path, manifest)
    # Upload action is unprivileged and needs only this sanitized bundle.
    if public.exists():
        for path in [public, *public.rglob('*')]:
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        os.chmod(root, 0o755)
    if error:
        raise q.Stop(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--host', type=pathlib.Path)
    group.add_argument('--scope-child', type=pathlib.Path)
    group.add_argument('--worker', type=pathlib.Path)
    group.add_argument('--scan', type=pathlib.Path)
    group.add_argument('--retain-failure', type=pathlib.Path)
    group.add_argument('--check-upload', type=pathlib.Path)
    parser.add_argument('--source', type=pathlib.Path)
    parser.add_argument('--event', type=pathlib.Path)
    parser.add_argument('--go-root', type=pathlib.Path)
    args = parser.parse_args()
    if args.check_upload:
        files = q.inventory(args.check_upload)
        if sum(item['bytes'] for item in files) > q.ARTIFACT_LIMIT or not (args.check_upload / 'evidence-inventory.json').is_file():
            raise q.Stop('fixed evidence transfer not admitted')
        print('ready=true')
    elif args.retain_failure:
        retain_failure(args.retain_failure)
    elif args.scan:
        q.Qualification(args.scan).scan()
    elif args.worker:
        instance = q.Qualification(args.worker)
        try:
            instance.build()
        finally:
            if instance.daemon is not None:
                instance.stop('terminal')
    elif args.scope_child:
        child(args.scope_child, args.go_root)
    else:
        host(args.source, args.host, args.event, args.go_root)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('bounded-qualification: ' + str(error), file=sys.stderr)
        sys.exit(1)
