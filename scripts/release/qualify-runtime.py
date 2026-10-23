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
    return subprocess.check_output(args, text=True, timeout=kwargs.pop('timeout', 60), **kwargs).strip()


def admission(source, event, environment, *, metadata_probe=False):
    if environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or environment.get('RUNNER_ENVIRONMENT') != 'github-hosted' or environment.get('RUNNER_OS') != 'Linux' or environment.get('RUNNER_ARCH') != 'X64':
        raise q.Stop('manual standard hosted Linux runner required')
    repository = event.get('repository', {})
    owner = repository.get('owner', {}).get('login')
    if repository.get('private') is not False or repository.get('full_name') != environment.get('GITHUB_REPOSITORY') or not owner or environment.get('GITHUB_ACTOR') != owner:
        raise q.Stop('public owner dispatch required')
    if environment.get('GITHUB_REF') != 'refs/heads/codex/runner-dotnet-servicing' or environment.get('GITHUB_RUN_ATTEMPT') != '1':
        raise q.Stop('candidate branch required')
    values = event.get('inputs')
    # The new CI selector must be explicitly false for existing modes.
    if isinstance(values, dict) and 'payload_reconstruction' in values:
        if values['payload_reconstruction'] != 'false':
            raise q.Stop('reconstruction cannot enter qualification')
        values = {key: value for key, value in values.items() if key != 'payload_reconstruction'}
    required = {'bounded_qualification', 'expected_commit', 'expected_tree', 'carry_in_bytes'}
    if not isinstance(values, dict) or set(values) not in (required, required | {'metadata_probe'}) or values.get('bounded_qualification') != ('false' if metadata_probe else 'true') or values.get('metadata_probe', 'false') != ('true' if metadata_probe else 'false'):
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
    return {'schema_version': 1, 'metadata_probe': metadata_probe, 'commit': commit, 'tree': tree, 'epoch': epoch, 'carry_in_bytes': int(carry), 'run_id': run_id, 'repository': repository['full_name'], 'candidate_test_plan_end_state': 'stopped/disabled at N+2; production runners untouched; operator-led recovery', 'live_operations': False}


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


def worker_environment(environment):
    # compose_worker copies this CA bundle, not the host's OpenSSL default
    # path aliases. Keep verification enabled with that exact copied store.
    return {**environment, 'PATH': '/toolchain/go/bin:/usr/bin:/bin', 'GOROOT': '/toolchain/go', 'SSL_CERT_FILE': '/etc/ssl/certs/ca-certificates.crt'}


def public_initial_allocations(initial, docker_root, source):
    # Publish exact measured values without embedding the hosted user's path.
    if set(initial) != {str(docker_root), str(source)}:
        raise q.Stop('unexpected initial allocation roots')
    return {'Docker_store': initial[str(docker_root)], 'checkout': initial[str(source)]}


def docker_json(args, **kwargs):
    return json.loads(command(['docker', *args], **kwargs))


def own_containers(label, **kwargs):
    raw = command(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'label=' + label], **kwargs)
    return raw.splitlines() if raw else []


def layer_path(raw, docker_root, leaf):
    if not isinstance(raw, str) or not raw or any(c in raw for c in '\n\r\t*?[]\\'):
        raise q.Stop('invalid Docker graph path')
    path = pathlib.Path(raw).resolve(strict=True)
    relative = path.relative_to(docker_root)
    if len(relative.parts) != 3 or relative.parts[0] != 'overlay2' or re.fullmatch('[0-9a-f]{64}', relative.parts[1]) is None or relative.parts[2] != leaf or not path.is_dir():
        raise q.Stop('unexpected Docker graph path')
    return path


def preinstalled_payloads(docker_root):
    """Freeze only immutable image payloads, before any task Docker mutation."""
    deadline = time.monotonic() + 20
    identifiers = sorted(set(command(['docker', 'image', 'ls', '-aq', '--no-trunc'], timeout=q.remaining(deadline)).splitlines()))
    if len(identifiers) > 1024 or any(re.fullmatch('sha256:[0-9a-f]{64}', value) is None for value in identifiers):
        raise q.Stop('unbounded or invalid baseline image inventory')
    images = docker_json(['image', 'inspect', *identifiers], timeout=q.remaining(deadline)) if identifiers else []
    if {image['Id'] for image in images} != set(identifiers) or len(images) != len(identifiers):
        raise q.Stop('incomplete baseline image inventory')
    excluded = set()
    for image in images:
        driver = image['GraphDriver']
        if driver['Name'] != 'overlay2':
            raise q.Stop('unsupported baseline image storage')
        data = driver['Data'] or {}
        if not image.get('RootFS', {}).get('Layers') and not data:
            continue
        if not data.get('UpperDir') or not isinstance(data.get('LowerDir', ''), str):
            raise q.Stop('baseline image payload unavailable')
        for raw in [data['UpperDir'], *filter(None, data.get('LowerDir', '').split(':'))]:
            excluded.add(layer_path(raw, docker_root, 'diff'))
        q.remaining(deadline)
    if len(excluded) > 4096 or sum(len(str(path).encode()) + 12 for path in excluded) > 512 * 1024:
        raise q.Stop('unbounded baseline exclusion catalog')
    q.remaining(deadline)
    return tuple(sorted(excluded))


def filesystems(paths):
    """Each physical device contributes once, even with several task paths."""
    rows = {}
    for path in paths:
        device = str(path.stat().st_dev)
        value = os.statvfs(path)
        row = {'used_bytes': (value.f_blocks - value.f_bfree) * value.f_frsize, 'free_bytes': value.f_bavail * value.f_frsize, 'free_inodes': value.f_favail}
        if device in rows:
            previous = rows[device]
            row = {'used_bytes': max(previous['used_bytes'], row['used_bytes']), 'free_bytes': min(previous['free_bytes'], row['free_bytes']), 'free_inodes': min(previous['free_inodes'], row['free_inodes'])}
        rows[device] = row
    return rows


def charge_allocation(usage, root, source, docker_root, current, baseline, carry, initial_charge):
    if set(current) != set(baseline):
        raise q.Stop('allocation filesystem changed')
    owned = sum(usage[str(path)] for path in (root, source, docker_root))
    growth = sum(max(0, row['used_bytes'] - baseline[device]['used_bytes']) for device, row in current.items())
    # Physical filesystem growth can catch pending/unlinked allocations. It is
    # only an additional floor: unrelated deletions never discount owned bytes.
    charged = max(owned, growth + initial_charge)
    return {'allocated_task_and_Docker_bytes': owned, 'filesystem_growth_bytes': growth, 'accounted_bytes': carry + charged + 64 * 2**20}


def allocation_preflight(source, output_parent):
    """Read-only host compatibility check, shared by CI and manual admission."""
    info = docker_json(['info', '--format', '{{json .}}'])
    if info['CgroupVersion'] != '2' or info['Driver'] != 'overlay2':
        raise q.Stop('hosted cgroup v2 and overlay2 required')
    docker_root = pathlib.Path(info['DockerRootDir'])
    if docker_root.resolve(strict=True) != docker_root:
        raise q.Stop('indirect Docker data root')
    if source == docker_root or source.is_relative_to(docker_root) or docker_root.is_relative_to(source):
        raise q.Stop('overlapping allocation roots')
    excluded = preinstalled_payloads(docker_root)
    baseline = filesystems((output_parent, docker_root, source))
    initial = q.allocated([docker_root, source], excluded)
    return docker_root, excluded, baseline, initial


def wait_for_observer(root):
    # No build descendant starts before admission. Allow the full20-second
    # sample plus scheduling margin within the existing30-second freshness bound.
    deadline = time.monotonic() + 30
    heartbeat = root / 'heartbeat.json'
    while time.monotonic() < deadline:
        if heartbeat.exists():
            if time.time() - heartbeat.stat().st_mtime > 30:
                raise q.Stop('initial observer heartbeat stale')
            q.checks(json.loads(heartbeat.read_text()))
            return
        time.sleep(.1)
    raise q.Stop('host observer did not admit aggregate bounds')


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


def prepare_public_clone(root, inputs, environment):
    repository = inputs['repository']
    if not isinstance(repository, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', repository) is None or repository.split('/')[1] in ('.', '..'):
        raise q.Stop('invalid admitted public repository')
    source = root / 'source'
    def git(*args):
        return command(['git', *args], cwd=source, env=environment)
    if git('rev-parse', 'HEAD') != inputs['commit'] or git('rev-parse', 'HEAD^{tree}') != inputs['tree'] or git('status', '--porcelain', '--untracked-files=all') or git('config', '--get', 'remote.origin.url') != inputs['checkout']:
        raise q.Stop('disposable clone acquisition mismatch')
    public_origin = 'https://github.com/' + repository + '.git'
    git('remote', 'set-url', 'origin', public_origin)
    if git('config', '--get', 'remote.origin.url') != public_origin:
        raise q.Stop('public clone origin mismatch')
    q.write(root / 'evidence/source-acquisition.json', {'method': 'local reviewed checkout clone with --no-local; detached admitted commit; no remote fetch', 'source_commit': inputs['commit'], 'source_tree': inputs['tree'], 'repository': repository, 'origin_matches_admitted_public_repository': True, 'checked_out_identity_verified': True, 'acquisition_location': 'reviewed hosted checkout'})


def child(root, go_root, *, reconstruction=False):
    inputs = json.loads((root / 'inputs.json').read_text())
    slice_name = 'pghar-qualification-' + inputs['run_id'] + '.slice'
    subprocess.run(['systemctl', 'set-property', '--runtime', slice_name, 'CPUQuota=400%', 'CPUQuotaPeriodSec=100ms', 'MemoryMax=' + str(q.MEMORY), 'MemorySwapMax=0', 'TasksMax=1024'], check=True, timeout=20)
    group = command(['systemctl', 'show', '--property=ControlGroup', '--value', slice_name])
    if not group.startswith('/') or '..' in group.split('/') or not group.endswith('/' + slice_name):
        raise q.Stop('unexpected aggregate cgroup')
    control = pathlib.Path('/sys/fs/cgroup') / group.lstrip('/')
    q.write(root / 'scope.json', {'name': slice_name, 'cgroup': str(control)})
    wait_for_observer(root)
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
        if reconstruction:
            import _payload_reconstruction as reconstruct
            reconstruct.verify_source(root / 'source', command)
            tooling = pathlib.Path(inputs['tooling_checkout'])
            reconstruct.stage_tooling(tooling, root / 'tooling', command)
        probe = inputs.get('metadata_probe') is True
        if not probe:
            prepare_public_clone(root, inputs, environment)
            q.write(root / 'phase.json', {'phase': 'selected-SDK-rebuild'})
            sdk_rebuild(root, environment, parent, label)
        q.write(root / 'phase.json', {'phase': 'worker-bootstrap'})
        image = compose_worker(root, label)
        args = ['docker', 'create', '--pull=never', '--hostname=example', '--cpus=4', '--memory=' + str(q.MEMORY), '--memory-swap=' + str(q.MEMORY), '--pids-limit=1024', '--cgroup-parent', parent, '--label', label, '--restart=no', '--log-opt=max-size=5m', '--log-opt=max-file=2', '--mount', 'type=bind,src=' + str(root) + ',dst=/work', '--mount', 'type=bind,src=' + str(go_root) + ',dst=/toolchain/go,readonly']
        worker_env = worker_environment(environment)
        for key, entry in worker_env.items():
            args += ['--env', key + '=' + entry]
        modes = (('reconstruct-worker', True),) if reconstruction else ((('metadata-buildkit', True), ('metadata-scan', False)) if probe else (('worker', True), ('scan', False)))
        for mode, privileged in modes:
            q.write(root / 'phase.json', {'phase': 'build-worker' if privileged else 'fresh-security-and-SBOM'})
            entrypoint = '/work/tooling/qualify-runtime.py' if reconstruction else '/work/source/scripts/release/qualify-runtime.py'
            worker = command(args[:2] + (['--privileged'] if privileged else []) + args[2:] + [image, 'python3', entrypoint, '--' + mode, '/work'])
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
        if not probe and not {'dotnet', 'buildkit-runc'} <= names:
            raise q.Stop('actual SDK/BuildKit descendant proof missing')
    except BaseException as failure:
        q.failure_receipt(root, 'scope', failure)
        raise
    finally:
        if worker is not None:
            subprocess.run(['docker', 'rm', '--force', worker], timeout=30, check=False)
        if image is not None:
            subprocess.run(['docker', 'image', 'rm', image], timeout=60, check=False)
        try:
            result_name = 'reconstruction-result.json' if reconstruction else 'scan-result.json'
            result_path = root / 'evidence' / result_name
            final = json.loads(result_path.read_text()) if result_path.exists() else {}
            final.update(status='pass' if sys.exc_info()[0] is None and final.get('status') == 'pass' else 'fail', resource_qualification='pending-final-observer', release_admitted=False, live_operations=False)
            q.write(root / 'evidence/RESULT.json', final)
            # Export remains inside the common cgroup while the host observer
            # enforces retained allocation, kernel limits and reserve floors.
            if reconstruction:
                # Identity-matched subjects were staged under the same guard.
                # Never call qualification/publication admission for this mode.
                pass
            elif inputs.get('metadata_probe') is True:
                import _metadata_probe
                if sys.exc_info()[0] is None:
                    _metadata_probe.export(root)
            else:
                # Only this controller observed both actual workers join
                # successfully. Their sealed staging manifests transport
                # producer-aware checks; they are not independently supplied
                # recognition authority. Failure paths use strict raw scans.
                staged = None
                if sys.exc_info()[0] is None and final.get('status') == 'pass':
                    import _producer_publication
                    staged = _producer_publication.completed_stages(root)
                export_evidence(root, guarded=True, staged=staged)
        finally:
            os.environ.clear()
            os.environ.update(old_env)


def sample(root, inputs, docker_root, excluded, baseline, initial_charge):
    deadline = time.monotonic() + 20
    source = pathlib.Path(inputs.get('accounting_source', inputs['checkout']))
    scope = json.loads((root / 'scope.json').read_text())
    control = pathlib.Path(scope['cgroup'])
    kernel = {key: (control / key).read_text().strip() for key in ('cpu.max', 'memory.max', 'memory.swap.max', 'memory.events', 'memory.current', 'memory.peak', 'pids.max', 'pids.current', 'pids.peak')}
    label = 'pghar.qualification=' + inputs['run_id']
    ids = own_containers(label, timeout=q.remaining(deadline))
    containers = []
    for identifier in ids:
        result = subprocess.run(['docker', 'inspect', identifier], capture_output=True, text=True, timeout=min(15, q.remaining(deadline)))
        if result.returncode:
            if identifier in own_containers(label, timeout=q.remaining(deadline)):
                raise q.Stop('owned container inspection unavailable')
            continue
        item = json.loads(result.stdout)[0]
        config = item['HostConfig']
        if config['NanoCpus'] != 4000000000 or config['Memory'] != q.MEMORY or config['MemorySwap'] != q.MEMORY or config['PidsLimit'] != 1024 or any(m['Destination'] == '/var/run/docker.sock' for m in item['Mounts']):
            if item['State']['Running']:
                raise q.Stop('running descendant escaped resource policy')
        pid = item['State']['Pid']
        if pid:
            lineage = pathlib.Path('/proc', str(pid), 'cgroup').read_text().strip().split(':', 2)[-1]
            expected = str(control.relative_to('/sys/fs/cgroup'))
            if not lineage.lstrip('/').startswith(expected + '/'):
                raise q.Stop('running container escaped aggregate cgroup')
        try:
            data = item['GraphDriver']['Data']
            upper = layer_path(data['UpperDir'], docker_root, 'diff')
            work = layer_path(data['WorkDir'], docker_root, 'work')
        except FileNotFoundError:
            if identifier not in own_containers(label, timeout=q.remaining(deadline)):
                continue
            raise q.Stop('owned writable root unavailable')
        if upper in excluded:
            raise q.Stop('writable root overlaps immutable baseline payload')
        containers.append({'id': identifier, 'running': item['State']['Running'], 'pid': pid, 'upper': str(upper), 'work': str(work), 'cgroup_parent': config['CgroupParent']})
    usage = q.allocated([root, docker_root, source], excluded, deadline=deadline, depth=3)
    present = set(own_containers(label, timeout=q.remaining(deadline)))
    writable_paths = set()
    for item in containers:
        for key in ('upper', 'work'):
            path = item[key]
            if path not in usage:
                if item['id'] in present:
                    raise q.Stop('incomplete writable-root allocation')
            else:
                writable_paths.add(path)
    writable = sum(usage[path] for path in writable_paths)
    current = filesystems((root, docker_root, source))
    memory = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    row = {'kernel': kernel, 'work_bytes': usage[str(root)], 'docker_allocated_bytes': usage[str(docker_root)], 'checkout_bytes': usage[str(source)], 'carry_in_bytes': inputs['carry_in_bytes'], 'control_reserve_bytes': 64 * 2**20, 'writable_root_bytes': writable, 'free_bytes': min(value['free_bytes'] for value in current.values()), 'free_inodes': min(value['free_inodes'] for value in current.values()), 'available_memory_bytes': int(memory['MemAvailable'].split()[0]) * 1024, 'containers': containers, 'filesystems': current, 'immutable_preinstalled_payloads': len(excluded)}
    row.update(charge_allocation(usage, root, source, docker_root, current, baseline, inputs['carry_in_bytes'], initial_charge))
    workers = []
    for proc in pathlib.Path('/proc').iterdir():
        q.remaining(deadline)
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
    q.remaining(deadline)
    q.checks(row)
    if workers:
        with (root / 'evidence/actual-worker-lineage.jsonl').open('a') as stream:
            stream.write(json.dumps(workers) + '\n')
    row['captured_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    row['accounting_seconds'] = 20 - q.remaining(deadline)
    q.write(root / 'heartbeat.json', row)
    with (root / 'evidence/resource-samples.jsonl').open('a') as stream:
        stream.write(json.dumps(row) + '\n')
    return row


def export_policy(source, root):
    """Use existing public rules with exact authority or strict raw scanning."""
    sanitizer = q.module(source, 'sanitize_public.py')
    allowlist = sanitizer.load_allowlist(source / sanitizer.ALLOWLIST_FILENAME)
    upstream, metadata = (), None
    verified = False
    if (root / 'debian-cache').is_dir() and (root / 'go-mod').is_dir():
        try:
            upstream = sanitizer.load_verified_upstream_licenses(source)
            metadata = sanitizer.public_metadata_source.load(source, debian_cache=root / 'debian-cache', go_module_cache=root / 'go-mod')
            findings = sanitizer.scan_bytes_as_file(metadata['source_raw'], metadata['source_path'], fixture=False)
            if list(allowlist.filter(findings)):
                raise q.Stop('producer registry failed public policy')
            documents = dict(upstream)
            for path, body in metadata['documents']:
                if path in documents and documents[path] != body:
                    raise q.Stop('conflicting producer documents')
                documents[path] = body
            if sum(len(body) for body in documents.values()) > 8 * 1024 * 1024:
                raise q.Stop('producer document budget')
            upstream = sorted(documents.items(), key=lambda item: (-len(item[1]), item[0]))
            verified = True
        except (sanitizer.VerifiedLicenseError, sanitizer.public_metadata_source.MetadataError, OSError, subprocess.SubprocessError):
            # Incomplete acquisition is not exemption authority. Diagnostics
            # can still pass the original raw rules; qualification cannot pass.
            upstream, metadata = (), None
    return sanitizer, allowlist, upstream, metadata, verified


def export_evidence(root, guarded=False, *, staged=None):
    """Always retain raw exports; publish only text that passes public policy."""
    source, evidence, public = root / 'source', root / 'evidence', root / 'public'
    if staged is not None:
        import _producer_publication
        if not guarded or not isinstance(staged, _producer_publication.StageAdmission) or staged.root != root:
            raise q.Stop('producer staging requires successful observed controller')
        q.write(evidence / 'producer-publication-stages.json', {'producer_checks_completed_in_actual_workers': True, 'files': list(staged.files.values()), 'source_commit': staged.manifests[0]['source_commit'], 'source_tree': staged.manifests[0]['source_tree']})
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
    sanitizer, allowlist, upstream, metadata, producer_verified = export_policy(source, root)
    q.write(evidence / 'export-policy.json', {'producer_authority_verified': producer_verified, 'strict_raw_diagnostics_only': not producer_verified, 'release_admitted': False})
    consumed_staged = set()
    for path in sorted(evidence.rglob('*')):
        if not path.is_file():
            continue
        guard()
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.resolve(strict=True) != path:
            raise q.Stop('unsafe evidence text file')
        relative = path.relative_to(evidence).as_posix()
        raw = path.read_bytes()
        # Ambient hosted paths are not published evidence names. Scan the
        # exact original bytes under their retained logical name, with no
        # fixture exemption. Content containing private paths still fails.
        if staged is not None and relative in staged.files:
            row = staged.files[relative]
            if row['bytes'] != len(raw) or row['sha256'] != hashlib.sha256(raw).hexdigest():
                raise q.Stop('producer checked report changed before export')
            consumed_staged.add(relative)
            findings = []  # The entire exact report view passed in its worker.
        else:
            findings = sanitizer.scan_generated_bytes(raw, 'qualification-evidence/' + relative, False, upstream, public_metadata=metadata)
        blocked = list(allowlist.filter(findings))
        if blocked:
            rejected.append({'path': relative, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'rules': sorted({finding.rule for finding in blocked})})
            continue
        target = public / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        guard()
        target.write_bytes(raw)
    if staged is not None and consumed_staged != set(staged.files):
        raise q.Stop('producer checked report missing during export')
    if rejected:
        q.write(public / 'RESULT.json', {'status': 'fail', 'public_evidence_sanitization': 'fail', 'release_admitted': False, 'live_operations': False})
    elif not producer_verified and (public / 'RESULT.json').exists() and json.loads((public / 'RESULT.json').read_text()).get('status') == 'pass':
        q.write(public / 'RESULT.json', {'status': 'fail', 'producer_authority': 'unavailable', 'release_admitted': False, 'live_operations': False})
    guard()
    files = q.inventory(public)
    if sum(item['bytes'] for item in files) > q.ARTIFACT_LIMIT:
        raise q.Stop('raw evidence exceeds fixed 1 GiB transfer cap')
    q.write(public / 'evidence-inventory.json', {'files': files, 'raw_AB_retained': True, 'unsafe_text_withheld': rejected, 'producer_authority_verified': producer_verified, 'artifact_qualification_admitted': producer_verified and not rejected and (public / 'RESULT.json').exists() and json.loads((public / 'RESULT.json').read_text()).get('status') == 'pass'})
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


def host(source, root, event_path, go_root, *, metadata_probe=False, reconstruction=False):
    if os.geteuid() != 0:
        raise q.Stop('ephemeral hosted root supervisor required')
    info = event_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 2**20 or event_path.resolve(strict=True) != event_path:
        raise q.Stop('unsafe dispatch event')
    event = json.loads(event_path.read_text(), object_pairs_hook=lambda pairs: dict(pairs) if len(dict(pairs)) == len(pairs) else (_ for _ in ()).throw(q.Stop('duplicate event key')))
    if reconstruction:
        import _payload_reconstruction as reconstruct
        tooling = pathlib.Path(__file__).resolve().parents[2]
        inputs = reconstruct.admission(source, tooling, event, os.environ, command)
        accounting_source = source.parent
    else:
        inputs = admission(source, event, os.environ, metadata_probe=metadata_probe)
        accounting_source = source
    if root.exists() or root.parent.resolve(strict=True) != root.parent or not root.is_absolute():
        raise q.Stop('fresh canonical output directory required')
    # The selected Go toolchain must already exist in the hosted image. It is
    # immutable baseline OS tooling, not a cache downloaded outside accounting.
    if go_root.resolve(strict=True) != go_root or command([str(go_root / 'bin/go'), 'version'], env={'PATH': '/usr/bin:/bin', 'GOTOOLCHAIN': 'local'}) != 'go version go1.26.9 linux/amd64':
        raise q.Stop('preinstalled pinned Go toolchain unavailable')
    docker_root, excluded, baseline, initial = allocation_preflight(accounting_source, root.parent)
    if root == docker_root or root.is_relative_to(docker_root) or docker_root.is_relative_to(root) or root == accounting_source or root.is_relative_to(accounting_source) or accounting_source.is_relative_to(root):
        raise q.Stop('overlapping allocation roots')
    if inputs['carry_in_bytes'] + sum(initial[str(path)] for path in (docker_root, accounting_source)) + 64 * 2**20 >= q.SOFT:
        raise q.Stop('initial allocated storage exceeds admission envelope')
    memory = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    if int(memory['MemAvailable'].split()[0]) * 1024 < 11 * q.GIB or min(value['free_inodes'] for value in baseline.values()) < 700000 or min(value['free_bytes'] for value in baseline.values()) < 13 * q.GIB + (q.SOFT - inputs['carry_in_bytes']):
        raise q.Stop('hosted admission reserve unavailable')
    root.mkdir(mode=0o700)
    (root / 'evidence').mkdir()
    inputs['checkout'] = str(source)
    if reconstruction:
        inputs['accounting_source'] = str(accounting_source)
    q.write(root / 'evidence/Docker-accounting.json', {'method': 'allocated blocks excluding only frozen immutable preinstalled image payloads; no baseline subtraction', 'excluded_payloads': [str(path) for path in excluded], 'filesystem_baseline': baseline, 'initial_allocated_bytes': public_initial_allocations(initial, docker_root, accounting_source)})
    q.write(root / 'inputs.json', inputs)
    q.write(root / 'evidence/source-inputs.json', {key: value for key, value in inputs.items() if key not in ('checkout', 'tooling_checkout', 'accounting_source')})
    scope_name = 'pghar-qualification-' + inputs['run_id']
    process = None
    error = None
    old_handlers = {}
    def cancelled(*_args):
        raise q.Stop('qualification cancelled')
    for signum in (signal.SIGINT, signal.SIGTERM):
        old_handlers[signum] = signal.signal(signum, cancelled)
    try:
        child_mode = '--reconstruction-scope-child' if reconstruction else '--scope-child'
        args = ['systemd-run', '--scope', '--quiet', '--unit=' + scope_name, '--slice=' + scope_name + '.slice', '/usr/bin/python3', str(pathlib.Path(__file__).resolve()), child_mode, str(root), '--go-root', str(go_root)]
        # Only this control supervisor sees the dispatch metadata. Credentials
        # and Actions runtime tokens are excluded from every child environment.
        log = (root / 'evidence/supervisor.log').open('wb')
        process = subprocess.Popen(args, env=safe_environment(root, go_root), stdout=log, stderr=subprocess.STDOUT)
        log.close()
        started = time.monotonic()
        while process.poll() is None:
            if time.monotonic() - started >= (10 if metadata_probe else 85) * 60:
                raise q.Stop('bounded worker deadline')
            if (root / 'scope.json').exists():
                sample(root, inputs, docker_root, excluded, baseline, sum(initial.values()))
            elif time.monotonic() - started > 20:
                raise q.Stop('aggregate cgroup admission missing')
            time.sleep(2)
        if process.returncode:
            raise q.Stop('qualification scope failed')
        sample(root, inputs, docker_root, excluded, baseline, sum(initial.values()))
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
        result_path = root / 'evidence' / ('reconstruction-result.json' if reconstruction else 'scan-result.json')
        final = json.loads(result_path.read_text()) if result_path.exists() else {}
        workers_joined = not own_containers('pghar.qualification=' + inputs['run_id'])
        final.update(status='pass' if error is None and workers_joined and final.get('status') == 'pass' else 'fail', resource_qualification='pass' if error is None and workers_joined else 'fail', workers_joined=workers_joined, scope_exit_code=None if process is None else process.returncode, release_admitted=False, live_operations=False)
        q.write(root / 'evidence/RESULT.json', final)
        q.write(root / 'evidence/terminal.json', {'workers_joined': workers_joined, 'scope_exit_code': None if process is None else process.returncode, 'budget_or_execution_error': error, 'live_operations': False, 'production_runners_touched': False})
    if reconstruction:
        final['qualification_executed'] = False
        reconstruct.finalize(root, final)
        return
    if metadata_probe:
        if error:
            raise q.Stop('metadata probe resource or execution failure')
        import _metadata_probe
        _metadata_probe.admit_upload(root)
        return
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
        import _qualification_control
        try:
            _qualification_control.create(public, root / 'control', inputs, q.ARTIFACT_LIMIT)
        except Exception:
            # A missing or inconsistent control copy cannot claim success.
            (root / 'control/control-index.json').unlink(missing_ok=True)
            final.update(status='fail', control_evidence='fail')
            q.write(public / 'RESULT.json', final)
            manifest['files'] = [entry for entry in manifest['files'] if entry['path'] != 'RESULT.json'] + [{'path': 'RESULT.json', 'bytes': (public / 'RESULT.json').stat().st_size, 'sha256': q.sha(public / 'RESULT.json')}]
            manifest['artifact_qualification_admitted'] = False
            q.write(manifest_path, manifest)
            error = error or 'bounded public control evidence failed admission'
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
    group.add_argument('--reconstruction-host', type=pathlib.Path)
    group.add_argument('--reconstruction-scope-child', type=pathlib.Path)
    group.add_argument('--reconstruct-worker', type=pathlib.Path)
    group.add_argument('--check-reconstruction-upload', type=pathlib.Path)
    group.add_argument('--metadata-host', type=pathlib.Path)
    group.add_argument('--metadata-buildkit', type=pathlib.Path)
    group.add_argument('--metadata-scan', type=pathlib.Path)
    group.add_argument('--check-metadata-upload', type=pathlib.Path)
    group.add_argument('--scope-child', type=pathlib.Path)
    group.add_argument('--worker', type=pathlib.Path)
    group.add_argument('--scan', type=pathlib.Path)
    group.add_argument('--retain-failure', type=pathlib.Path)
    group.add_argument('--check-upload', type=pathlib.Path)
    group.add_argument('--check-control-upload', type=pathlib.Path)
    group.add_argument('--check-accounting', action='store_true')
    parser.add_argument('--source', type=pathlib.Path)
    parser.add_argument('--event', type=pathlib.Path)
    parser.add_argument('--go-root', type=pathlib.Path)
    args = parser.parse_args()
    if args.check_reconstruction_upload:
        import _payload_reconstruction as reconstruct
        reconstruct.check_upload(args.check_reconstruction_upload)
        print('ready=true')
    elif args.reconstruct_worker:
        import _payload_reconstruction as reconstruct
        instance = q.Qualification(args.reconstruct_worker)
        try:
            instance.build(reconstruction=True)
            reconstruct.compare(args.reconstruct_worker, instance, reconstruct.expected())
        finally:
            if instance.daemon is not None:
                instance.stop('terminal')
    elif args.reconstruction_scope_child:
        child(args.reconstruction_scope_child, args.go_root, reconstruction=True)
    elif args.reconstruction_host:
        host(args.source, args.reconstruction_host, args.event, args.go_root, reconstruction=True)
    elif args.metadata_buildkit or args.metadata_scan or args.check_metadata_upload:
        import _metadata_probe
        if args.metadata_buildkit:
            _metadata_probe.buildkit(args.metadata_buildkit)
        elif args.metadata_scan:
            _metadata_probe.scan(args.metadata_scan)
        else:
            _metadata_probe.check_upload(args.check_metadata_upload)
            print('ready=true')
    elif args.check_accounting:
        source = args.source.resolve(strict=True)
        started = time.monotonic()
        docker_root, excluded, baseline, initial = allocation_preflight(source, source.parent)
        print(json.dumps({'read_only_accounting_preflight': 'pass', 'immutable_preinstalled_payloads': len(excluded), 'docker_allocated_bytes': initial[str(docker_root)], 'checkout_bytes': initial[str(source)], 'physical_filesystems': len(baseline), 'free_bytes': min(row['free_bytes'] for row in baseline.values()), 'seconds': time.monotonic() - started, 'qualification_executed': False, 'Docker_mutations': False}))
    elif args.check_control_upload:
        import _qualification_control
        _qualification_control.verify(args.check_control_upload)
        print('ready=true')
    elif args.check_upload:
        files = q.inventory(args.check_upload)
        if sum(item['bytes'] for item in files) > q.ARTIFACT_LIMIT or not (args.check_upload / 'evidence-inventory.json').is_file():
            raise q.Stop('fixed evidence transfer not admitted')
        print('ready=true')
    elif args.retain_failure:
        retain_failure(args.retain_failure)
    elif args.scan:
        try:
            q.Qualification(args.scan).scan()
        except BaseException as failure:
            q.failure_receipt(args.scan, 'scan', failure)
            raise
    elif args.worker:
        instance = q.Qualification(args.worker)
        try:
            instance.build()
        except BaseException as failure:
            q.failure_receipt(args.worker, 'build', failure)
            raise
        finally:
            if instance.daemon is not None:
                instance.stop('terminal')
    elif args.scope_child:
        child(args.scope_child, args.go_root)
    else:
        host(args.source, args.metadata_host or args.host, args.event, args.go_root, metadata_probe=args.metadata_host is not None)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        private_probe = any(value.startswith(('--metadata-', '--check-metadata-')) for value in sys.argv[1:])
        if not private_probe and not isinstance(error, (ValueError, OSError, subprocess.SubprocessError)):
            raise
        print('metadata-probe: ' + type(error).__name__ if private_probe else 'bounded-qualification: ' + str(error), file=sys.stderr)
        sys.exit(1)
