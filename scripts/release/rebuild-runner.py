#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Reproduce the explicitly pinned app-local runner from public inputs.

The SDK container receives only a fresh build directory and optional existing
transport proxy/CA settings. No Docker socket, GitHub credentials or home
configuration is mounted. Its output is accepted only at the descriptor digest.
"""
import argparse
import ast
import gzip
import hashlib
import json
import os
import pathlib
import platform
import re
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
STAGE = "admission"


def stage(value):
    global STAGE
    STAGE = value
    print("rebuild-runner: stage=" + value, file=sys.stderr, flush=True)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def rehearsal_functions():
    # Share the release authority's closed descriptor and HTTPS transfer checks.
    script = ROOT / "scripts/release/rehearse-runtime.sh"
    text = script.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
    tree = ast.parse(text)
    if not isinstance(tree.body[-1], ast.Try):
        raise ValueError("unrecognized rehearsal entrypoint")
    tree.body.pop()
    namespace = {}
    exec(compile(tree, str(script), "exec"), namespace)
    return namespace


def package_archive(layout, destination, epoch):
    rows = []
    for path in sorted(layout.rglob("*"), key=lambda p: str(p.relative_to(layout)).encode()):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError("nonregular rebuild output")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError("linked rebuild output")
        rows.append((path, info))
    if len(rows) >= 16384 or sum(info.st_size for _, info in rows if stat.S_ISREG(info.st_mode)) >= 2**30:
        raise ValueError("oversized rebuild output")
    with destination.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=9) as compressed, tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
        root = tarfile.TarInfo("./")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        root.mtime = epoch
        archive.addfile(root)
        for path, source_info in rows:
            info = tarfile.TarInfo("./" + str(path.relative_to(layout)))
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            info.mode = 0o755 if stat.S_ISDIR(source_info.st_mode) or source_info.st_mode & 0o111 else 0o644
            info.pax_headers = {}
            if stat.S_ISDIR(source_info.st_mode):
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = source_info.st_size
                with path.open("rb") as stream:
                    archive.addfile(info, stream)


def publish_archive(partial, destination, payload):
    try:
        info = partial.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != payload["archive_bytes"] or sha256(partial) != payload["sha256"]:
            raise ValueError("rebuild differs from the pinned archive")
        # A hard link creates the destination exclusively; never replace evidence.
        os.link(partial, destination, follow_symlinks=False)
        os.chmod(destination, 0o400)
    finally:
        partial.unlink(missing_ok=True)


def prepare_documents(source, layout, packages):
    for path in (source / "src/Misc/layoutroot").rglob("*"):
        if not path.is_file() or path.name.endswith(".cmd"):
            continue
        relative = path.relative_to(source / "src/Misc/layoutroot")
        if len(relative.parts) != 1:
            raise ValueError("unexpected root script")
        target = layout / relative
        shutil.copyfile(path, target)
        os.chmod(target, 0o755 if path.name.endswith((".sh", ".sh.template")) else 0o644)
    shutil.copyfile(source / "LICENSE", layout / "LICENSE")
    os.chmod(layout / "LICENSE", 0o644)
    docs = layout / "bin/third-party-licenses"
    docs.mkdir()
    libraries = {}
    for path in (layout / "bin").glob("*.deps.json"):
        libraries.update({key: value for key, value in json.loads(path.read_text())["libraries"].items() if value["type"] == "package"})
    rows = []
    for key in sorted(libraries):
        name, version = key.split("/")
        directory = packages / name.lower() / version
        nuspecs = list(directory.glob("*.nuspec"))
        if len(nuspecs) != 1:
            raise ValueError("missing NuGet producer metadata")
        metadata = next(x for x in ET.parse(nuspecs[0]).getroot() if x.tag.rsplit("}", 1)[-1] == "metadata")
        fields = {x.tag.rsplit("}", 1)[-1]: (x.text or "") for x in metadata}
        license_node = next((x for x in metadata if x.tag.rsplit("}", 1)[-1] == "license"), None)
        files = [nuspecs[0]]
        if license_node is not None and license_node.attrib.get("type") == "file":
            files.append(directory / (license_node.text or ""))
        for pattern in ("LICENSE*", "license*", "ThirdPartyNotices*", "THIRD-PARTY-NOTICES*"):
            files.extend(p for p in directory.glob(pattern) if p.is_file())
        copied, seen = [], set()
        for path in files:
            if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()) or path.stat().st_size > 2**20:
                raise ValueError("invalid NuGet licensing file")
            if path in seen:
                continue
            seen.add(path)
            destination = docs / name / version / path.relative_to(directory)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            os.chmod(destination, 0o644)
            copied.append({"path": str(destination.relative_to(layout)), "sha256": sha256(destination), "bytes": destination.stat().st_size})
        archive = directory / (name.lower() + "." + version + ".nupkg")
        rows.append({"name": name, "version": version, "purl": "pkg:nuget/" + name + "@" + version, "nupkg_sha256": sha256(archive), "producer": fields.get("authors"), "copyright": fields.get("copyright"), "license": None if license_node is None else {"type": license_node.attrib.get("type"), "value": license_node.text}, "licensing_files": copied})
    upstream = docs / "upstream"
    upstream.mkdir()
    for path in sorted((ROOT / "release/runner-license-texts").glob("*.txt")):
        shutil.copyfile(path, upstream / path.name)
        os.chmod(upstream / path.name, 0o644)
    runtime = packages / "microsoft.netcore.app.runtime.linux-x64/8.0.32"
    for name in ("LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"):
        target = docs / ("dotnet-8.0.32-" + name)
        shutil.copyfile(runtime / name, target)
        os.chmod(target, 0o644)
    (docs / "package-producers.json").write_text(json.dumps(rows, sort_keys=True, indent=2) + "\n")
    os.chmod(docs / "package-producers.json", 0o644)


def run(arguments, cwd, env):
    subprocess.run(arguments, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=sys.stderr, check=True, timeout=1800)


def sdk_container_command(work, descriptor, env):
    image = descriptor["sdk_container_image"]
    if re.fullmatch(r"mcr\.microsoft\.com/dotnet/sdk@sha256:[0-9a-f]{64}", image) is None:
        raise ValueError("unbound SDK image")
    (work / "tmp").mkdir(mode=0o700)
    (work / "runtime").mkdir(mode=0o700)
    command = ["docker", "run", "--platform=linux/amd64", "--cpus=4", "--memory=6174015488", "--memory-swap=6174015488", "--pids-limit=1024", "--user=" + str(os.getuid()) + ":" + str(os.getgid()), "--mount", "type=bind,src=" + str(work) + ",dst=/work", "--workdir=/work/runner-source/src"]
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        if key in env:
            command += ["--env", key]
    ca = env.get("SSL_CERT_FILE") or env.get("GIT_SSL_CAINFO")
    if ca:
        certificate = pathlib.Path(ca).resolve(strict=True)
        if not certificate.is_file():
            raise ValueError("existing CA file unavailable")
        command += ["--mount", "type=bind,src=" + str(certificate) + ",dst=/transport-ca.pem,readonly", "--env", "SSL_CERT_FILE=/transport-ca.pem", "--env", "GIT_SSL_CAINFO=/transport-ca.pem"]
    settings = {"XDG_RUNTIME_DIR": "/work/runtime", "TMPDIR": "/work/tmp", "HOME": "/work/home", "DOTNET_CLI_HOME": "/work/home", "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "NUGET_PACKAGES": "/work/output/sdk-attempt4/nuget-packages", "MSBUILDDISABLENODEREUSE": "1", "DOTNET_PROCESSOR_COUNT": "4"}
    for key, value in settings.items():
        command += ["--env", key + "=" + value]
    return command + [image]


STARTUP_SCRIPT = r"""
set -eu
root=$1
proof=$2
mkdir -m 700 "$proof"
cd "$proof"
for entry in Runner.Listener Runner.Worker Runner.PluginHost; do
  set --
  if [ "$entry" = Runner.Listener ]; then set -- --version; fi
  status=0
  COREHOST_TRACE=1 COREHOST_TRACEFILE="$proof/$entry.trace" timeout -k 5s 20s "$root/bin/$entry" "$@" >"$proof/$entry.log" 2>&1 || status=$?
  printf '%s\n' "$status" >"$proof/$entry.exit"
done
"""


def verify_startup_evidence(evidence, version, runtime_bin):
    def read(name):
        path = evidence / name
        info = path.lstat()
        if path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8 * 2**20:
            raise ValueError("unsafe entrypoint evidence")
        return path.read_text(encoding="utf-8", errors="strict")
    rows = []
    for name, code, expected_arguments in (("Runner.Listener", 0, None), ("Runner.Worker", 1, 3), ("Runner.PluginHost", 1, 2)):
        status = read(name + ".exit")
        output = read(name + ".log")
        trace = read(name + ".trace")
        if status != str(code) + "\n" or "CoreCLR path = '" + runtime_bin + "/libcoreclr.so'" not in trace or "Execute managed assembly exit code: 0x" + str(code) not in trace:
            raise ValueError("entrypoint did not load its app-local CLR")
        if name == "Runner.Listener":
            if output.strip() != version:
                raise ValueError("unexpected runner version")
        elif "Expected '" + str(expected_arguments) + "'. Actual '0'." not in output or "GitHub.Runner." + name.removeprefix("Runner.") + ".Program.Main" not in output:
            raise ValueError("unexpected worker or plugin startup failure")
        rows.append({"entrypoint": name, "exit_code": code, "app_local_CLR_loaded": True, "trace_sha256": sha256(evidence / (name + ".trace")), "output_sha256": sha256(evidence / (name + ".log"))})
    return rows


def take_prepared_externals(prepared, destination):
    os.chmod(prepared, 0o700)
    # Moving a directory between parents updates its .. entry and needs write
    # permission on that directory, even when both parents are private.
    os.chmod(prepared / "externals", 0o700)
    (prepared / "externals").rename(destination)
    for directory, _, _ in os.walk(prepared):
        os.chmod(directory, 0o700)
    shutil.rmtree(prepared)


def run_sdk(arguments, work, env):
    # Keep the control file outside the build mount so the SDK process cannot
    # redirect cleanup toward a different container.
    with tempfile.TemporaryDirectory(prefix=".runner-control-", dir=work.parent) as control:
        cidfile = pathlib.Path(control) / "container-id"
        command = arguments[:2] + ["--cidfile", str(cidfile)] + arguments[2:]
        try:
            run(command, work, env)
        finally:
            if cidfile.exists():
                container_id = cidfile.read_text().strip()
                if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
                    raise ValueError("invalid SDK container receipt")
                cleanup = subprocess.run(
                    ["docker", "rm", "--force", container_id], env=env,
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
                )
                absent = ("Error response from daemon: No such container: " + container_id).encode()
                if cleanup.returncode and cleanup.stderr.strip() != absent:
                    raise ValueError("SDK container cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=pathlib.Path, required=True)
    parser.add_argument("--if-selected", action="store_true", help="succeed without output when the official payload is selected")
    args = parser.parse_args()
    output = args.output_directory
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise ValueError("Linux x64 build host required")
    if not output.is_absolute() or output.resolve(strict=True) != output or not output.is_dir():
        raise ValueError("canonical existing output directory required")
    authority = rehearsal_functions()
    runner = authority["validate_runner"](json.loads((ROOT / "release/manifest.json").read_text())["runtime"]["runner_release"])
    payload = authority["select_runner_payload"](ROOT, runner)
    if payload["kind"] != "dotnet-rebuild":
        if args.if_selected:
            return
        raise ValueError("the selected payload is official; use the official acquisition path")
    destination = output / payload["asset_name"]
    if destination.exists() or destination.is_symlink():
        raise ValueError("output already exists")
    descriptor = json.loads((ROOT / "internal/buildinfo/runner_rebuild.json").read_text())
    for tool in ("docker", "git", "go", "curl"):
        if shutil.which(tool) is None:
            raise ValueError("missing build prerequisite: " + tool)
    with tempfile.TemporaryDirectory(prefix=".runner-rebuild-", dir=output) as temporary:
        work = pathlib.Path(temporary)
        os.chmod(work, 0o700)
        # Reuse only transport settings. Never pass a token, user Git config or
        # signing material to either the source acquisition or SDK container.
        env = {key: value for key, value in os.environ.items() if key in ("PATH", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "SSL_CERT_FILE", "GIT_SSL_CAINFO", "GOCACHE", "GOMODCACHE", "GOTOOLCHAIN", "GOROOT", "GOPROXY", "GOSUMDB", "GOFLAGS")}
        env.update(HOME=str(work / "home"), GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
        pathlib.Path(env["HOME"]).mkdir()
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            if key in env:
                proxy = urllib.parse.urlsplit(env[key])
                if proxy.username is not None or proxy.password is not None:
                    raise ValueError("credentialed proxy is not a build input")
        stage("public-source")
        source = work / "runner-source"
        run(["git", "init", str(source)], work, env)
        run(["git", "-C", str(source), "fetch", "--depth=1", "https://github.com/actions/runner.git", descriptor["upstream_source_commit"]], work, env)
        run(["git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD"], work, env)
        run(["git", "-C", str(source), "apply", str(ROOT / "release/runner-rebuild.patch")], work, env)
        stage("upstream-acquisition")
        official = work / runner["linux_x64_asset_name"]
        authority["curl_download"]("https://github.com/actions/runner/releases/download/" + runner["version"] + "/" + runner["linux_x64_asset_name"], official, payload["upstream_sha256"], env, work / "transfer.log", maximum=256 * 2**20)
        stage("upstream-verification")
        prepared = work / "prepared-upstream"
        run(["go", "run", "./scripts/release/rebuildinput", str(official), str(prepared)], ROOT, env)
        # Discard the authenticated old bin immediately. Only externals are
        # carried into the new layout, and moving avoids a second large copy.
        stage("upstream-cleanup")
        take_prepared_externals(prepared, work / "externals")
        official.unlink()
        # The SDK builds at the same absolute path as the reviewed A/B builds;
        # this also avoids path-dependent portable PDB differences.
        sdk_command = sdk_container_command(work, descriptor, env)
        command = sdk_command + ["/bin/sh", "-c", 'set -eu; test "$(dotnet --version)" = "$1"; shift; exec dotnet msbuild "$@"', "rebuild-runner", descriptor["dotnet_sdk_version"], "-t:Layout", "-p:PackageRuntime=linux-x64", "-p:RuntimeIdentifiers=linux-x64", "-p:RuntimeFrameworkVersion=" + descriptor["dotnet_runtime_version"], "-p:BUILDCONFIG=Release", "-p:RunnerVersion=" + runner["version"][1:], "-p:BuildInParallel=false", "-p:RestoreDisableParallel=true", "-p:UseSharedCompilation=false", "-m:1", "./dir.proj"]
        stage("SDK-publication")
        run_sdk(command, work, env)
        layout = source / "_layout"
        (work / "externals").rename(layout / "externals")
        stage("notice-packaging")
        prepare_documents(source, layout, work / "output/sdk-attempt4/nuget-packages")
        stage("all-entrypoint-startup")
        diagnostics = layout / "_diag"
        if diagnostics.exists() or diagnostics.is_symlink():
            raise ValueError("unexpected preexisting startup diagnostics")
        run_sdk(sdk_command + ["/bin/sh", "-c", STARTUP_SCRIPT, "runner-startups", "/work/runner-source/_layout", "/work/startup-evidence"], work, env)
        startup = verify_startup_evidence(work / "startup-evidence", runner["version"][1:], "/work/runner-source/_layout/bin")
        (work / "startup-evidence/summary.json").write_text(json.dumps(startup, indent=2) + "\n")
        if diagnostics.exists():
            if diagnostics.is_symlink() or not diagnostics.is_dir():
                raise ValueError("unsafe startup diagnostics")
            shutil.rmtree(diagnostics)
        epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=source, env=env, text=True))
        partial = work / "archive.part"
        package_archive(layout, partial, epoch)
        stage("archive-authentication")
        print(f"rebuild-runner: archive-sha256={sha256(partial)} archive-bytes={partial.stat().st_size}", file=sys.stderr)
        publish_archive(partial, destination, payload)
    print(destination)


if __name__ == "__main__":
    def terminate(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Report only static stages and error types, never URLs, environment
        # settings or private paths from exception messages.
        code = getattr(error, "errno", None)
        print(f"rebuild-runner: unavailable stage={STAGE} class={type(error).__name__} errno={code}; no archive was published", file=sys.stderr)
        sys.exit(1)
