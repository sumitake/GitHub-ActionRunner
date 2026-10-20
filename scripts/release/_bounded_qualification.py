"""Offline candidate qualification primitives; never a deployment authority."""
# SPDX-License-Identifier: MPL-2.0
import ast
import hashlib
import importlib.util
import json
import os
import pathlib
import posixpath
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import types

GIB = 2**30
MEMORY = 6174015488
SOFT = 10 * GIB
HARD = 23 * GIB // 2
RESERVE = 3758096384
BUILDKit = 'moby/buildkit:v0.32.0@sha256:1f8167fcb0eca5b7126353d35299386945cbb8949cc516c592a49f80cfce4fa2'
FRONTEND = 'docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e'
ARTIFACT_LIMIT = GIB


class Stop(ValueError):
    pass


def sha(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.partial')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def failure_receipt(root, stage, error):
    """Retain fixed failure classifications without messages or transport data."""
    if stage not in ('scope', 'build', 'scan'):
        raise Stop('unknown qualification failure stage')
    name = type(error).__name__
    if re.fullmatch('[A-Za-z_][A-Za-z_0-9]{0,63}', name) is None:
        name = 'unavailable'
    status = getattr(error, 'code', None)
    write(root / 'evidence' / (stage + '-failure.json'), {'stage': stage, 'exception_type': name, 'http_status': status if type(status) is int and 400 <= status <= 599 else None, 'release_admitted': False, 'live_operations': False})


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise Stop('allocated storage observation deadline exceeded')
    return seconds


def allocated(paths, excluded=(), *, deadline=None, depth=0):
    """One bounded traversal; never admit partial, late or interrupted output."""
    deadline = time.monotonic() + 20 if deadline is None else deadline
    names = [os.fspath(path) for path in paths]
    if not names or len(set(names)) != len(names) or any(not pathlib.Path(name).is_absolute() or any(c in name for c in '\n\r\t') for name in names):
        raise Stop('invalid allocation roots')
    args = ['du', '-x', '-B1', '--count-links', '--max-depth=' + str(depth)]
    args += ['--exclude=' + os.fspath(path) for path in excluded]
    for _ in range(3):
        try:
            result = subprocess.run([*args, '--', *names], capture_output=True, text=True, timeout=remaining(deadline))
        except (subprocess.TimeoutExpired, InterruptedError) as error:
            raise Stop('allocated storage observation interrupted or timed out') from error
        remaining(deadline)
        if result.returncode < 0:
            raise Stop('allocated storage observation was interrupted')
        if result.returncode == 0:
            rows = {}
            for line in result.stdout.splitlines():
                fields = line.split('\t', 1)
                if len(fields) != 2 or not fields[0].isdigit() or fields[1] in rows or not any(pathlib.Path(fields[1]).is_relative_to(name) for name in names):
                    raise Stop('invalid allocated storage observation')
                rows[fields[1]] = int(fields[0])
            if not set(names) <= rows.keys():
                raise Stop('incomplete allocated storage observation')
            return rows
        time.sleep(min(.1, remaining(deadline)))
    raise Stop('allocated storage observation unavailable')


def du(path):
    return allocated([path])[os.fspath(path)]


def checks(row):
    expected = {'cpu.max': '400000 100000', 'memory.max': str(MEMORY), 'memory.swap.max': '0', 'pids.max': '1024'}
    if any(row['kernel'][key] != value for key, value in expected.items()):
        raise Stop('aggregate kernel limits changed')
    events = dict(line.split() for line in row['kernel']['memory.events'].splitlines())
    if not {'oom', 'oom_kill'} <= set(events) or any(not events[key].isdigit() for key in ('oom', 'oom_kill')):
        raise Stop('unverifiable aggregate OOM state')
    if int(events['oom']) or int(events['oom_kill']):
        raise Stop('aggregate OOM event')
    if row['accounted_bytes'] >= SOFT or row['writable_root_bytes'] >= 2 * GIB:
        raise Stop('storage early stop')
    if row['free_bytes'] < 13 * GIB or row['free_inodes'] < 500000 or row['available_memory_bytes'] < 4 * GIB:
        raise Stop('host reserve exhausted')


def release_functions(source):
    raw = (source / 'scripts/release/rehearse-runtime.sh').read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]
    tree = ast.parse(raw)
    tree.body = tree.body[:-1]
    result = {}
    exec(compile(tree, 'committed-release-verifiers', 'exec'), result)
    return result


class LayoutArchive:
    """Present sealed OCI layout files to the unchanged release graph verifier."""
    def __init__(self, root, **_kwargs):
        self.root = pathlib.Path(root)
        if self.root.resolve(strict=True) != self.root or not self.root.is_dir():
            raise Stop('indirect OCI layout')
        self.members = {}
        self.streams = []
        for path in sorted(self.root.rglob('*')):
            info = path.lstat()
            if path.resolve(strict=True) != path or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise Stop('unsafe OCI layout member')
            if stat.S_ISDIR(info.st_mode):
                continue
            if info.st_nlink != 1:
                raise Stop('aliased OCI layout member')
            relative = path.relative_to(self.root).as_posix()
            if relative not in ('index.json', 'oci-layout') and re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', relative) is None:
                raise Stop('unknown OCI layout file')
            member = tarfile.TarInfo(relative)
            member.size = info.st_size
            self.members[member.name] = member
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        for stream in self.streams:
            stream.close()
        return False
    def __iter__(self):
        return iter(self.members.values())
    def getmember(self, name):
        return self.members[name]
    def extractfile(self, member):
        member = self.getmember(member) if isinstance(member, str) else self.getmember(member.name)
        stream = (self.root / member.name).open('rb')
        self.streams.append(stream)
        return stream


def graph(directory, functions):
    facade = types.SimpleNamespace(open=LayoutArchive, TarError=tarfile.TarError)
    verifier = types.FunctionType(functions['oci_graph'].__code__, {**functions, 'tarfile': facade})
    return verifier(directory)


def inventory(directory):
    result = []
    for path in sorted(directory.rglob('*')):
        info = path.lstat()
        if path.resolve(strict=True) != path or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise Stop('unsafe evidence member')
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise Stop('aliased evidence member')
            result.append({'path': path.relative_to(directory).as_posix(), 'bytes': info.st_size, 'sha256': sha(path)})
    return result


def module(source, name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), source / 'scripts' / name)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class Qualification:
    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.source = self.root / 'source'
        self.output = self.root / 'evidence'
        self.artifacts = self.output / 'artifacts'
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.inputs = json.loads((self.root / 'inputs.json').read_text())
        self.commit = self.inputs['commit']
        self.version = 'candidate-' + self.commit[:12]
        self.release = release_functions(self.source)
        self.runtime = json.loads((self.source / 'release/manifest.json').read_text())['runtime']
        self.daemon = None
        self.active = None
        self.commands = []
        self.images = []
        self.env = {key: value for key, value in os.environ.items() if key in ('PATH', 'GOROOT', 'SSL_CERT_FILE', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
        self.env.update(HOME=str(self.root / 'home'), TMPDIR=str(self.root / 'tmp'), XDG_CACHE_HOME=str(self.root / 'cache'), GOCACHE=str(self.root / 'go-build'), GOMODCACHE=str(self.root / 'go-mod'), GOTOOLCHAIN='local', GOTELEMETRY='off', CGO_ENABLED='0', GOMAXPROCS='4', GOMEMLIMIT='1GiB', GOFLAGS='-p=1 -mod=readonly', GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='safe.directory', GIT_CONFIG_VALUE_0=str(self.source), GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0', PYTHONDONTWRITEBYTECODE='1')
        for key in ('HOME', 'TMPDIR', 'XDG_CACHE_HOME'):
            pathlib.Path(self.env[key]).mkdir(exist_ok=True)
        os.environ.update({key: value for key, value in self.env.items() if key.startswith('GIT_CONFIG_')})

    def record(self, name, value):
        write(self.output / name, value)

    def run(self, name, args, timeout=1200, extra=None, allow_failure=False):
        write(self.root / 'phase.json', {'phase': name})
        log = self.output / (name + '.log')
        log.parent.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        with log.open('wb') as stream:
            self.active = subprocess.Popen(args, cwd=self.source, env={**self.env, **(extra or {})}, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while self.active.poll() is None:
                    heartbeat = self.root / 'heartbeat.json'
                    if not heartbeat.exists() or time.time() - heartbeat.stat().st_mtime > 30:
                        raise Stop('host observer heartbeat stale')
                    if time.monotonic() - started > timeout:
                        raise Stop(name + ' timed out')
                    time.sleep(.2)
                code = self.active.returncode
            finally:
                if self.active.poll() is None:
                    os.killpg(self.active.pid, signal.SIGTERM)
                    try:
                        self.active.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(self.active.pid, signal.SIGKILL)
                        self.active.wait(timeout=5)
                self.active = None
        self.commands.append({'name': name, 'argv': args, 'exit_code': code, 'seconds': round(time.monotonic() - started, 3)})
        self.record('commands-' + ('build' if str(self.root) == '/work' else 'scan') + '.json', self.commands)
        if code and not allow_failure:
            raise Stop(name + ' failed')
        return code, log

    def remove(self, relative):
        path = self.root / relative
        if path.parent.resolve() != path.parent or path.is_symlink() or not path.is_relative_to(self.root):
            raise Stop('unsafe owned cache cleanup')
        if path.exists():
            before = du(path)
            shutil.rmtree(path)
            self.record('cleanup-' + relative.replace('/', '-') + '.json', {'path': relative, 'allocated_bytes': before, 'after_users_joined': True})

    def start(self, label):
        state = self.root / 'buildkit-state'
        if self.daemon is not None or state.exists():
            raise Stop('BuildKit state was reused')
        self.env['BUILDKIT_HOST'] = 'unix://' + str(self.root / 'buildkit.sock')
        stream = (self.output / ('buildkit-' + label + '.log')).open('wb')
        self.daemon = subprocess.Popen(['buildkitd', '--addr', self.env['BUILDKIT_HOST'], '--root', str(state), '--containerd-worker=false', '--oci-worker-snapshotter=overlayfs', '--oci-worker-net=host'], env=self.env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        stream.close()
        for _ in range(100):
            result = subprocess.run(['buildctl', 'debug', 'workers', '--verbose'], env=self.env, capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                if 'overlayfs' not in result.stdout or 'native' in result.stdout:
                    raise Stop('copy-on-write worker not proven')
                self.record('buildkit-workers-' + label + '.json', {'stdout': result.stdout, 'pid': self.daemon.pid})
                return
            if self.daemon.poll() is not None:
                raise Stop('BuildKit exited before readiness')
            time.sleep(.3)
        raise Stop('BuildKit startup timeout')

    def stop(self, label):
        if self.daemon is not None:
            self.daemon.terminate()
            try:
                self.daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.daemon.pid, signal.SIGKILL)
                self.daemon.wait(timeout=5)
                raise Stop('BuildKit forced termination')
            self.daemon = None
        remaining = []
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                if b'buildkit-runc' in (proc / 'cmdline').read_bytes():
                    remaining.append(proc.name)
            except (FileNotFoundError, ProcessLookupError):
                pass
        if remaining:
            raise Stop('BuildKit workers remain')
        self.record('buildkit-joined-' + label + '.json', {'joined': True, 'remaining_workers': remaining})
        self.remove('buildkit-state')

    def buildctl(self, label, context, dockerfile, output, extra=()):
        self.run(label, ['buildctl', 'build', '--no-cache', '--frontend', 'dockerfile.v0', '--local', 'context=' + str(context), '--local', 'dockerfile=' + str(dockerfile), '--opt', 'build-arg:BUILDKIT_SYNTAX=' + FRONTEND, '--opt', 'build-arg:SOURCE_DATE_EPOCH=' + str(self.inputs['epoch']), '--opt', 'force-network-mode=none', '--opt', 'platform=linux/amd64', *extra, '--output', output])

    def debian_cache(self):
        self.record('debian-producer-stage.json', {'stage': 'producer-input-acquisition', 'status': 'started'})
        cache = self.root / 'debian-cache'
        cache.mkdir()
        producer = module(self.source, 'public_dependency_metadata.py')
        registry = json.loads((self.source / producer.REGISTRY).read_text())
        verifier = (self.source / 'images/runner/verify-debian-cache.sh').read_text()
        for row in registry['debian_indexes']:
            relative = row['inrelease_url'].split('snapshot.debian.org/', 1)[1]
            if 'verify ' + row['inrelease_sha256'] + ' ' + relative not in verifier.splitlines():
                raise Stop('unbound producer index')
            for url, expected, maximum in ((row['inrelease_url'], row['inrelease_sha256'], 2**20), (row['url'], row['sha256'], row['bytes'])):
                raw = producer.debian_bytes(url, maximum, None, expected)
                if hashlib.sha256(raw).hexdigest() != expected:
                    raise Stop('producer bytes changed')
                path = cache / url.split('snapshot.debian.org/', 1)[1]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
        # APT verifies the distro signatures without network access and derives
        # the exact install/upgrade closure from the same pinned base image.
        context = self.root / 'apt-context'
        context.mkdir()
        base = registry['base_image']
        lines = ['FROM ' + base + ' AS plan', 'RUN --network=none --mount=type=bind,from=debian-cache,target=/cache,ro set -eu; rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; printf "%s\\n" ']
        sources = ['deb [check-valid-until=no] file:/cache/' + row['inrelease_url'].split('snapshot.debian.org/', 1)[1].split('/dists/')[0] + ' ' + row['inrelease_url'].split('/dists/')[1].split('/')[0] + ' main' for row in registry['debian_indexes']]
        lines[-1] += ' '.join("'" + item + "'" for item in sources) + ' > /etc/apt/sources.list; apt-get -o Acquire::Languages=none -o Acquire::By-Hash=false update; mkdir /plan; apt-get -s --no-install-recommends install ca-certificates curl git libicu72 libkrb5-3 liblttng-ust1 libssl3 zlib1g > /plan/install.txt; apt-get -s --no-install-recommends dist-upgrade > /plan/upgrade.txt; sha256sum /usr/share/keyrings/debian-archive-keyring.gpg > /plan/base-keyring.sha256'
        lines += ['FROM scratch', 'COPY --from=plan /plan /']
        (context / 'Dockerfile').write_text('\n'.join(lines) + '\n')
        self.start('apt-plan')
        try:
            self.buildctl('apt-plan', context, context, 'type=local,dest=' + str(self.output / 'apt-plan'), ['--local', 'debian-cache=' + str(cache), '--opt', 'context:debian-cache=local:debian-cache'])
        finally:
            self.stop('apt-plan')
        wanted = set()
        for name in ('install', 'upgrade'):
            for line in (self.output / 'apt-plan' / (name + '.txt')).read_text().splitlines():
                if line.startswith('Inst '):
                    match = re.fullmatch(r'Inst (\S+)(?: \[[^]]+\])? \((\S+) .*\)', line)
                    if match is None:
                        raise Stop('unparseable APT plan')
                    wanted.add((match[1].split(':')[0], match[2]))
        records = []
        for row in registry['debian_indexes']:
            found = producer.verified_index(row, cache, {(name, version, architecture) for name, version in wanted for architecture in ('amd64', 'all')})
            for key, (fields, stanza) in found.items():
                url = row['url'].split('/dists/')[0] + '/' + fields['Filename']
                producer.source_url(url, 'snapshot.debian.org')
                size = int(fields['Size'])
                if not 0 < size < 100 * 2**20 or re.fullmatch(r'[0-9a-f]{64}', fields['SHA256']) is None:
                    raise Stop('unbound Debian archive')
                path = cache / url.split('snapshot.debian.org/', 1)[1]
                if not path.exists():
                    raw = producer.debian_bytes(url, size, None, fields['SHA256'])
                    if len(raw) != size or hashlib.sha256(raw).hexdigest() != fields['SHA256']:
                        raise Stop('Debian archive digest')
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                records.append({'name': key[0], 'version': key[1], 'architecture': key[2], 'url': url, 'sha256': fields['SHA256'], 'stanza_sha256': stanza, 'bytes': size})
        if {(r['name'], r['version']) for r in records} != wanted or sum(r['bytes'] for r in records) > 150 * 2**20:
            raise Stop('incomplete or oversized APT closure')
        self.record('debian-inputs.json', records)
        self.record('debian-producer-stage.json', {'stage': 'producer-input-acquisition', 'status': 'complete'})
        self.remove('apt-context')

    def image_binaries(self, directory, value, name, stamp):
        expected = {'usr/local/bin/' + r['binary']: r['sha256'] for r in json.loads((self.output / 'image-binary-inputs.json').read_text()) if r['image'] == name}
        observed = {}
        config = json.loads((directory / 'blobs/sha256' / value['config_digest'][7:]).read_bytes())
        if config['config']['User'] != '65532:65532':
            raise Stop('runtime UID changed')
        for digest in value['layer_digests']:
            with tarfile.open(directory / 'blobs/sha256' / digest[7:], 'r|*') as layer:
                for member in layer:
                    path = member.name.removeprefix('./').rstrip('/')
                    if path.startswith('/') or '..' in path.split('/'):
                        raise Stop('unsafe runtime layer')
                    parent, leaf = posixpath.split(path)
                    if leaf.startswith('.wh.'):
                        removed = parent + '/' if leaf == '.wh..wh..opq' else posixpath.join(parent, leaf[4:])
                        observed = {k: v for k, v in observed.items() if not (k == removed or k.startswith(removed.rstrip('/') + '/'))}
                    elif path in expected:
                        if not member.isfile() or not member.mode & 0o111:
                            raise Stop('runtime binary type')
                        observed[path] = hashlib.file_digest(layer.extractfile(member), 'sha256').hexdigest()
                    elif any(k.startswith(path + '/') for k in expected) and not member.isdir():
                        raise Stop('runtime binary parent type')
        if observed != expected:
            raise Stop('source-to-image binary mismatch')
        if name == 'runner' and (set(config['config']['Env']) != {'HOME=/runner', 'LANG=C.UTF-8', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'XDG_RUNTIME_DIR=/tmp'} or len(config['config']['Env']) != 4):
            raise Stop('private runtime environment changed')
        return {'uid': '65532:65532', 'embedded_binaries': observed, 'stamp': stamp}

    def build(self):
        self.release['validate_release_manifest'](json.loads((self.source / 'release/manifest.json').read_text()))
        self.release['validate_dockerfiles'](self.source, self.runtime)
        if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.source, env=self.env, text=True).strip() != self.commit or subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=self.source, env=self.env, text=True).strip() != self.inputs['tree']:
            raise Stop('candidate source changed')
        self.run('module-download', ['go', 'mod', 'download'], timeout=900)
        self.run('module-verify', ['go', 'mod', 'verify'])
        _, log = self.run('linked-identity', ['go', 'run', './internal/buildinfo/cmd/portable-ghar-build-identity', self.version, self.commit])
        stamp = log.read_text().strip()
        if stamp != 'portable-ghar-build-identity-v1|' + self.version + '|' + self.commit:
            raise Stop('build stamp changed')
        flags = '-s -w -buildid= -X github.com/sumitake/portable-ghar/internal/buildinfo.version=' + self.version + ' -X github.com/sumitake/portable-ghar/internal/buildinfo.commit=' + self.commit + ' -X github.com/sumitake/portable-ghar/internal/buildinfo.stamp=' + stamp
        self.run('linked-identity-test', ['go', 'test', '-run', '^TestLinkedIdentity$', '-count=1', '-ldflags=' + flags, './internal/buildinfo'], extra={'PGHAR_EXPECTED_BUILD_VERSION': self.version, 'PGHAR_EXPECTED_BUILD_COMMIT': self.commit})
        binaries = []
        for letter in ('A', 'B'):
            for row in self.runtime['binaries']:
                path = self.artifacts / ('binaries-' + letter) / row['name']
                path.parent.mkdir(exist_ok=True)
                self.run('binary-' + letter + '-' + row['name'], ['go', 'build', '-trimpath', '-buildvcs=false', '-ldflags=' + flags, '-o', str(path), row['package']], extra={'GOOS': 'linux', 'GOARCH': 'amd64'})
                data = path.read_bytes()
                if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 62 or stamp.encode() not in data or str(self.source).encode() in data:
                    raise Stop('unstamped or wrong binary')
                binaries.append({'phase': letter, 'name': row['name'], 'sha256': sha(path), 'bytes': len(data)})
            self.remove('go-build')
        if any(a['sha256'] != b['sha256'] for a, b in zip(binaries[:11], binaries[11:])) or len(binaries) != 22:
            raise Stop('binary A/B mismatch')
        self.record('binary-comparison.json', {'source_commit': self.commit, 'stamp': stamp, 'binaries': binaries, 'all_eleven_identical': True})
        self.run('prepare-task6', ['scripts/prepare-task6-images.sh'])
        runner = self.runtime['runner_release']
        payload = self.release['select_runner_payload'](self.source, runner)
        archive = self.root / 'selected-runner' / payload['asset_name']
        if sha(archive) != payload['sha256'] or archive.stat().st_size != payload['archive_bytes']:
            raise Stop('selected payload changed')
        self.run('prepare-task5', ['scripts/prepare-task5-images.sh', '--generation', '1', '--runner-archive', str(archive), '--ca-bundle', str(self.source / 'images/trust/build/ca-bundle.pem')])
        stage = self.root / 'stamp-stage'
        stage.mkdir()
        (stage / 'bin').symlink_to(self.artifacts / 'binaries-A')
        self.release['stage_stamped_image_inputs'](self.source, stage, self.runtime, stamp)
        (stage / 'bin').unlink()
        stage.rmdir()
        inputs = []
        for image in self.runtime['images']:
            for path in (self.source / image['context'] / 'build').glob('portable-ghar-*'):
                expected = sha(self.artifacts / 'binaries-A' / path.name)
                if path.is_symlink() or sha(path) != expected:
                    raise Stop('stamped context drift')
                inputs.append({'image': image['name'], 'binary': path.name, 'sha256': expected})
        if len(inputs) != 7:
            raise Stop('stamped context inventory')
        self.record('image-binary-inputs.json', inputs)
        self.remove('selected-runner')
        self.remove('go-build')
        # Go compilation is finished. Retain full legal files, module metadata
        # and the three exact ZIPs needed by the producer verifier, not code caches.
        required = {r['module'] + '/@v/' + r['version'] + '.zip' for r in json.loads((self.source / 'release/public-dependency-metadata.json').read_text())['go_licenses']}
        retained = []
        cache = self.root / 'go-mod'
        for path in cache.rglob('*'):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(cache).as_posix()
            legal = re.search(r'(?i)(license|notice|copying|copyright|authors|patents)|\.(md|mod|info|sum)$', path.name)
            needed_zip = any(relative == 'cache/download/' + item for item in required)
            if legal or needed_zip:
                retained.append({'path': relative, 'sha256': sha(path), 'bytes': path.stat().st_size})
            else:
                path.unlink()
        self.record('retained-module-legal-inputs.json', retained)
        self.debian_cache()
        for letter in ('A', 'B'):
            for image in sorted(self.runtime['images'], key=lambda r: (r['name'] != 'runner', r['name'])):
                name = image['name']
                directory = self.artifacts / ('images-' + letter) / name
                directory.parent.mkdir(exist_ok=True)
                self.start(letter + '-' + name)
                try:
                    extra = ['--local', 'debian-cache=' + str(self.root / 'debian-cache'), '--opt', 'context:debian-cache=local:debian-cache', '--opt', 'build-arg:DEBIAN_SNAPSHOT_SOURCE=offline'] if name == 'runner' else []
                    self.buildctl('image-' + letter + '-' + name, self.source / image['context'], (self.source / image['dockerfile']).parent, 'type=oci,tar=false,dest=' + str(directory) + ',name=portable-ghar/' + name + ':' + self.commit + ',rewrite-timestamp=true', extra)
                    value = graph(directory, self.release)
                    identity = self.image_binaries(directory, value, name, stamp)
                    files = inventory(directory)
                    row = {'phase': letter, 'image': name, 'path': str(directory.relative_to(self.output)), 'oci_graph': value, 'source_to_image': identity, 'files': files}
                    if letter == 'B':
                        previous = next(r for r in self.images if r['phase'] == 'A' and r['image'] == name)
                        if any(previous[key] != row[key] for key in ('oci_graph', 'source_to_image', 'files')):
                            raise Stop('OCI A/B mismatch')
                    self.images.append(row)
                    self.record('image-results.json', self.images)
                finally:
                    self.stop(letter + '-' + name)
        legal = []
        registry = json.loads((self.source / 'release/runner-licenses.json').read_text())
        for row in registry['licenses']:
            for item in row['files']:
                if item['path'].startswith('images/'):
                    path = self.source / item['path']
                    if sha(path) != item['sha256']:
                        raise Stop('runner legal source drift')
                    legal.append((path, path.read_bytes(), item['sha256']))
        for image in self.runtime['images']:
            path = self.source / image['context'] / 'build'
            if path.exists():
                self.remove(str(path.relative_to(self.root)))
        for path, body, expected in legal:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(0o444)
            if sha(path) != expected:
                raise Stop('runner legal source preservation failed')
        if (self.source / 'images/trust/build').exists():
            self.remove('source/images/trust/build')
        for path in (self.root / 'debian-cache').rglob('*.deb'):
            path.unlink()
        self.record('build-result.json', {'status': 'pass', 'binaries': 22, 'images': 12, 'fresh_state_per_image': True, 'raw_format': 'OCI image-layout directories; both complete independent exports retained'})

    def sanitize_release_outputs(self, rows, notices):
        # Syft's raw producer reports remain evidence, but the release-output
        # check consumes the normalized SBOMs used to generate the notices.
        # Export independently scans every retained raw report and still fails
        # qualification if any text is withheld.
        args = ['python3', 'scripts/sanitize_public.py', '--verified-runner-licenses', '--verified-dependency-metadata', '--dependency-debian-cache', str(self.root / 'debian-cache'), '--dependency-go-module-cache', str(self.root / 'go-mod')]
        for path in [*(path for _relative, path in rows), notices]:
            args += ['--generated', str(path)]
        self.run('generated-sanitization', args)

    def scan(self):
        if json.loads((self.output / 'build-result.json').read_text())['status'] != 'pass':
            raise Stop('build phase incomplete')
        images = json.loads((self.output / 'image-results.json').read_text())
        tools = self.root / 'security-tools'
        tools.mkdir()
        def acquire(name):
            row = self.runtime['tools'][name]
            archive = tools / row['asset_name']
            self.release['curl_download'](row['source_url'], archive, row['sha256'], self.env, self.output / 'tool-acquisition.log')
            self.release['extract_one_binary'](archive, name, tools / name)
            archive.unlink()
            self.run('tool-version-' + name, [str(tools / name), '--version'])
            self.record('tool-' + name + '.json', {'pin': row, 'binary_sha256': sha(tools / name)})
        # Defer Syft until the live Trivy DB has been verified and reclaimed.
        acquire('trivy')
        self.env.update(TRIVY_CACHE_DIR=str(self.root / 'trivy-cache'), TRIVY_DISABLE_VEX_NOTICE='true')
        trivy = str(tools / 'trivy')
        self.run('database-download', [trivy, 'image', '--download-db-only'], timeout=1200)
        metadata = json.loads((self.root / 'trivy-cache/db/metadata.json').read_text())
        import datetime
        if datetime.datetime.fromisoformat(metadata['NextUpdate'].replace('Z', '+00:00')) <= datetime.datetime.now(datetime.timezone.utc):
            raise Stop('scanner database stale')
        db_inventory = inventory(self.root / 'trivy-cache/db')
        self.record('scanner-database-before.json', {'metadata': metadata, 'files': db_inventory})
        results = []
        for name, path in [('source', self.source), ('binaries-A', self.artifacts / 'binaries-A'), ('binaries-B', self.artifacts / 'binaries-B')]:
            code, _ = self.run('security-' + name, [trivy, 'fs', '--skip-db-update', '--scanners', 'vuln,secret', '--severity', 'HIGH,CRITICAL', '--exit-code', '1', '--no-progress', '--format', 'json', '--output', str(self.output / ('security-' + name + '.json')), str(path)], timeout=1800, allow_failure=True)
            results.append({'subject': name, 'exit_code': code})
        for row in images:
            if row['phase'] != 'B':
                continue
            path = self.output / row['path']
            if graph(path, self.release) != row['oci_graph'] or inventory(path) != row['files']:
                raise Stop('OCI output drift before scanning')
            code, _ = self.run('security-image-' + row['image'], [trivy, 'image', '--input', str(path), '--skip-db-update', '--scanners', 'vuln,secret', '--severity', 'HIGH,CRITICAL', '--ignore-unfixed', '--exit-code', '1', '--no-progress', '--format', 'json', '--output', str(self.output / ('security-image-' + row['image'] + '.json'))], timeout=1800, allow_failure=True)
            results.append({'subject': row['image'], 'exit_code': code})
        runner = next(row for row in images if row['phase'] == 'B' and row['image'] == 'runner')
        all_findings = self.output / 'runner-all-severities.json'
        self.run('runner-all-severities', [trivy, 'image', '--input', str(self.output / runner['path']), '--skip-db-update', '--scanners', 'vuln,secret', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--no-progress', '--format', 'json', '--output', str(all_findings)], timeout=1800)
        report = json.loads(all_findings.read_text())
        if report.get('ArtifactType') != 'container_image' or report.get('Metadata', {}).get('OS', {}).get('Family') != 'debian':
            raise Stop('runner image was not analyzed as Debian')
        os_packages = [p for row in report.get('Results', []) if row.get('Type') == 'debian' for p in row.get('Packages', [])]
        dotnet = [p for row in report.get('Results', []) if row.get('Type') == 'dotnet-core' for p in row.get('Packages', [])]
        expected_runtime = json.loads((self.source / 'internal/buildinfo/runner_rebuild.json').read_text())['dotnet_runtime_version']
        expected = {'Microsoft.NETCore.App.Runtime.linux-x64': expected_runtime, 'System.Security.Cryptography.Pkcs': '10.0.13', 'System.Formats.Asn1': '10.0.13'}
        if len(os_packages) < 100 or any({p['Version'] for p in dotnet if p['Name'] == name} != {version} for name, version in expected.items()):
            raise Stop('runner package or serviced-runtime inventory incomplete')
        reported = {'CVE-2026-58280', 'CVE-2026-69651', 'CVE-2026-96225', 'CVE-2026-96231', 'CVE-2026-96233', 'CVE-2026-70162', 'CVE-2026-84008'}
        found = {item['VulnerabilityID'] for row in report.get('Results', []) for item in row.get('Vulnerabilities', [])}
        if reported & found or any(row.get('Secrets') for row in report.get('Results', [])):
            raise Stop('reported runner CVEs or secrets remain')
        self.record('runner-reported-CVE-clearance.json', {'reported': sorted(reported), 'absent': sorted(reported - found), 'secrets': 0})
        if inventory(self.root / 'trivy-cache/db') != db_inventory:
            raise Stop('scanner database changed')
        self.record('security-results.json', results)
        self.record('scanner-database-after.json', {'same_authenticated_database_unchanged': True, 'files': db_inventory})
        self.remove('trivy-cache')
        (tools / 'trivy').unlink()
        acquire('syft')
        self.env.update(SYFT_CHECK_FOR_APP_UPDATE='false', SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES='true', SYFT_GOLANG_LOCAL_MOD_CACHE_DIR=str(self.root / 'go-mod'), SYFT_GOLANG_SEARCH_REMOTE_LICENSES='false')
        producer = module(self.source, 'public_dependency_metadata.py')
        evidence = (producer, producer.load(self.source, debian_cache=self.root / 'debian-cache', go_module_cache=self.root / 'go-mod'))
        sbom = self.output / 'sbom'
        sbom.mkdir()
        identity = self.release['first_party_metadata'](self.source, self.version, self.commit)
        subjects = [('bin/' + r['name'], self.artifacts / 'binaries-B' / r['name'], 'file') for r in self.runtime['binaries']]
        subjects += [('images/' + r['image'] + '.oci.tar', self.output / r['path'], 'oci-dir') for r in images if r['phase'] == 'B']
        rows = []
        digests = {}
        for relative, path, scheme in subjects:
            name = path.name
            raw, normalized = sbom / (name + '.raw.spdx.json'), sbom / (name + '.spdx.json')
            self.run('sbom-' + name, [str(tools / 'syft'), 'scan', scheme + ':' + str(path), '--output', 'spdx-json=' + str(raw)])
            digest = graph(path, self.release)['manifest_digest'][7:] if scheme == 'oci-dir' else sha(path)
            self.release['normalize_spdx'](raw, normalized, name, digest, self.inputs['epoch'], first_party=identity, public_evidence=evidence)
            if name == 'runner' and scheme == 'oci-dir':
                self.release['apply_baseline_runner_licenses'](self.source, self.runtime['runner_release'], self.runtime['runner_release'], normalized, digest, payload=self.release['select_runner_payload'](self.source, self.runtime['runner_release']))
            rows.append((relative, normalized))
            digests[relative] = digest
        notices = self.output / 'THIRD-PARTY-NOTICES.txt'
        self.release['generate_notices'](rows, self.runtime['license_exceptions'], notices, digests)
        self.sanitize_release_outputs(rows, notices)
        if any(r['exit_code'] != 0 for r in results):
            raise Stop('vulnerability or secret gate failed')
        self.remove('security-tools')
        self.record('scan-result.json', {'status': 'pass', 'source_commit': self.commit, 'source_tree': self.inputs['tree'], 'binary_AB': 11, 'OCI_AB': 6, 'SBOM_subjects': len(rows), 'strict_notices': 'pass', 'security_gates': 'pass', 'generated_sanitization': 'pass', 'live_operations': False, 'production_runners_touched': False, 'release_authority_written': False, 'target_conformance_executed': False, 'candidate_test_plan_end_state': 'stopped/disabled at N+2; operator-led recovery; no observer enrollment'})
