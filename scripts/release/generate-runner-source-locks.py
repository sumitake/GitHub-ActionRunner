#!/usr/bin/env python3
"""Generate and locked-revalidate the exact Actions runner NuGet graph."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
from types import ModuleType
from typing import Any


BUILDER_PATH = Path(__file__).with_name("build-runner-from-source.py")
MAX_LOCK_BYTES = 16 * 1024 * 1024
MAX_PRODUCT_MANIFEST_BYTES = 4 * 1024 * 1024


def _load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("runner_source_builder", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("runner source builder import unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_builder = _load_builder()
BuildError = _builder.BuildError


def _load_product_runner_release(path: Path, destination: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise BuildError("product manifest unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
        or not raw
        or len(raw) > MAX_PRODUCT_MANIFEST_BYTES
        or metadata.st_mode & 0o022
    ):
        raise BuildError("product manifest identity invalid")
    try:
        product = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_builder._unique_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                BuildError("float prohibited")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                BuildError("constant prohibited")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError("product manifest JSON invalid") from error
    runtime = product.get("runtime") if isinstance(product, dict) else None
    release = runtime.get("runner_release") if isinstance(runtime, dict) else None
    if not isinstance(release, dict):
        raise BuildError("product runner manifest schema invalid")
    try:
        with destination.open("xb") as handle:
            handle.write(_builder.canonical_json(release))
        destination.chmod(0o400)
    except OSError as error:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise BuildError("runner manifest staging unavailable") from error
    return _builder.load_runner_release(destination)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _lock_paths(release: dict[str, Any]) -> tuple[str, ...]:
    paths = tuple(
        item["path"] for item in release["build"]["nuget_locks"]["files"]
    )
    if paths != _builder.LOCK_PATHS:
        raise BuildError("NuGet lock path mismatch")
    return paths


def _collect_locks(release: dict[str, Any], source: Path) -> dict[str, bytes]:
    root = source / "src"
    expected = _lock_paths(release)
    observed: dict[str, bytes] = {}
    try:
        for candidate in root.rglob("packages.lock.json"):
            metadata = candidate.lstat()
            relative = candidate.relative_to(root).as_posix()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size < 2
                or metadata.st_size > MAX_LOCK_BYTES
                or relative in observed
            ):
                raise BuildError("NuGet lock generation failed")
            observed[relative] = candidate.read_bytes()
    except OSError as error:
        raise BuildError("NuGet lock generation failed") from error
    if tuple(relative for relative in expected if relative in observed) != expected:
        raise BuildError("NuGet lock generation failed")
    if set(observed) != set(expected):
        raise BuildError("NuGet lock generation failed")
    return {relative: observed[relative] for relative in expected}


def _copy_locks(locks: dict[str, bytes], source: Path) -> None:
    try:
        for relative, raw in locks.items():
            destination = source / "src" / relative
            if destination.exists() or destination.is_symlink():
                raise BuildError("NuGet lock revalidation failed")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(raw)
            destination.chmod(0o444)
    except OSError as error:
        raise BuildError("NuGet lock revalidation failed") from error


def _layout_environment(
    *,
    source: Path,
    sdk_root: Path,
    pass_root: Path,
    source_date_epoch: int,
    runner_version: str,
    restore_locked: bool,
    base_environment: dict[str, str],
) -> tuple[list[str], dict[str, str], Path]:
    try:
        pass_root.mkdir(mode=0o700)
        home = pass_root / "home"
        packages = pass_root / "packages"
        http = pass_root / "http"
        plugins = pass_root / "plugins"
        for directory in (home, packages, http, plugins):
            directory.mkdir(mode=0o700)
        log = pass_root / "layout.log"
        log.touch(mode=0o600)
    except OSError as error:
        raise BuildError("NuGet lock pass root invalid") from error
    command, values = _builder.layout_contract(
        source_root=source,
        sdk_root=sdk_root,
        nuget_root=packages,
        source_date_epoch=source_date_epoch,
        runner_version=runner_version,
        restore_locked=restore_locked,
    )
    values.update(
        {
            "DOTNET_CLI_HOME": str(home),
            "DOTNET_MULTILEVEL_LOOKUP": "0",
            "HOME": str(home),
            "NUGET_HTTP_CACHE_PATH": str(http),
            "NUGET_PLUGINS_CACHE_PATH": str(plugins),
            "PATH": f"{sdk_root}:{base_environment.get('PATH', '/usr/bin:/bin')}",
        }
    )
    return command, {**base_environment, **values}, log


def _run_layout(
    *,
    release: dict[str, Any],
    source: Path,
    sdk_root: Path,
    pass_root: Path,
    source_date_epoch: int,
    restore_locked: bool,
    base_environment: dict[str, str],
) -> None:
    command, environment, log = _layout_environment(
        source=source,
        sdk_root=sdk_root,
        pass_root=pass_root,
        source_date_epoch=source_date_epoch,
        runner_version=release["build"]["expected_listener_version"],
        restore_locked=restore_locked,
        base_environment=base_environment,
    )
    _builder._run(
        command,
        cwd=source / "src",
        environment=environment,
        log=log,
        timeout=3600,
        stage="runner layout",
        capture=True,
        maximum=32 * 1024 * 1024,
    )


def _receipt(release: dict[str, Any], locks: dict[str, bytes]) -> dict[str, Any]:
    files = [
        {"path": relative, "sha256": sha256_bytes(raw)}
        for relative, raw in locks.items()
    ]
    aggregate = sha256_bytes(_builder.canonical_json({"files": files}))
    return {
        "schema_version": 1,
        "runner_version": release["version"],
        "source_commit_sha": release["source_commit_sha"],
        "source_tree_sha": release["source_tree_sha"],
        "dotnet_sdk": release["build"]["dotnet_sdk"],
        "layout": {
            "package_runtime": "linux-x64",
            "build_config": "Release",
            "restore_packages_with_lock_file": True,
            "target_latest_runtime_patch": True,
            "generation_restore_locked": False,
            "revalidation_restore_locked": True,
        },
        "nuget_locks": {"aggregate_sha256": aggregate, "files": files},
    }


def _publish(
    output: Path, locks: dict[str, bytes], receipt: dict[str, Any]
) -> None:
    stage = output.with_name(f".{output.name}.partial")
    if output.exists() or output.is_symlink() or stage.exists() or stage.is_symlink():
        raise BuildError("NuGet lock output invalid")
    try:
        stage.mkdir(mode=0o700)
        for relative, raw in locks.items():
            destination = stage / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(raw)
            destination.chmod(0o444)
        receipt_path = stage / "receipt.json"
        receipt_path.write_bytes(_builder.canonical_json(receipt))
        receipt_path.chmod(0o444)
        os.replace(stage, output)
    except OSError as error:
        _builder._remove_tree(stage)
        raise BuildError("NuGet lock publication failed") from error


def generate_from_prepared_sources(
    *,
    release: dict[str, Any],
    first_source: Path,
    second_source: Path,
    sdk_root: Path,
    first_root: Path,
    second_root: Path,
    output: Path,
    source_date_epoch: int,
    base_environment: dict[str, str],
) -> dict[str, Any]:
    paths = tuple(
        Path(value)
        for value in (
            first_source,
            second_source,
            sdk_root,
            first_root,
            second_root,
            output,
        )
    )
    if len(set(paths)) != len(paths) or source_date_epoch < 1:
        raise BuildError("NuGet lock generation identity invalid")
    if output.exists() or output.is_symlink():
        raise BuildError("NuGet lock output invalid")
    _run_layout(
        release=release,
        source=first_source,
        sdk_root=sdk_root,
        pass_root=first_root,
        source_date_epoch=source_date_epoch,
        restore_locked=False,
        base_environment=base_environment,
    )
    generated = _collect_locks(release, first_source)
    _copy_locks(generated, second_source)
    _run_layout(
        release=release,
        source=second_source,
        sdk_root=sdk_root,
        pass_root=second_root,
        source_date_epoch=source_date_epoch,
        restore_locked=True,
        base_environment=base_environment,
    )
    revalidated = _collect_locks(release, second_source)
    if revalidated != generated:
        raise BuildError("NuGet lock revalidation failed")
    _builder._verify_restore_assets(
        second_source, release["build"]["dotnet_sdk"]["runtime_version"]
    )
    receipt = _receipt(release, generated)
    _publish(output, generated, receipt)
    return receipt


def main(arguments: list[str]) -> int:
    manifest_path, output, work_root = _builder._parse_arguments(arguments)
    _builder._validate_private_empty_directory(work_root)
    _builder._validate_new_output(output, work_root)
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise BuildError("Linux amd64 required")
    if any(shutil.which(command) is None for command in ("curl", "git")):
        raise BuildError("lock generation prerequisite unavailable")

    try:
        os.umask(0o077)
        log = work_root / "source.log"
        log.touch(mode=0o600)
        downloads = work_root / "downloads"
        bootstrap_home = work_root / "bootstrap-home"
        downloads.mkdir(mode=0o700)
        bootstrap_home.mkdir(mode=0o700)
    except OSError as error:
        raise BuildError("lock generation setup unavailable") from error
    release = _load_product_runner_release(
        manifest_path, work_root / "runner-release.json"
    )
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(bootstrap_home),
        }
    )
    first_source = work_root / "actions-runner-a"
    second_source = work_root / "actions-runner-b"
    first_epoch = _builder._clone_exact_source(
        release, first_source, environment=environment, log=log
    )
    second_epoch = _builder._clone_exact_source(
        release, second_source, environment=environment, log=log
    )
    if first_epoch != second_epoch:
        raise BuildError("runner source epoch mismatch")

    dotnet = release["build"]["dotnet_sdk"]
    sdk_archive = downloads / dotnet["asset_name"]
    _builder._download(
        dotnet["source_url"],
        sdk_archive,
        dotnet["sha512"],
        "sha512",
        environment=environment,
        log=log,
        maximum_bytes=512 * 1024 * 1024,
    )
    sdk_root = work_root / "dotnet-sdk"
    _builder.extract_verified_tar(
        sdk_archive,
        sdk_root,
        expected_root=None,
        maximum_entries=_builder.MAX_ARCHIVE_ENTRIES,
        maximum_expanded_bytes=_builder.MAX_ARCHIVE_BYTES,
    )
    sdk_environment = {
        **environment,
        "DOTNET_CLI_HOME": str(bootstrap_home),
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_GENERATE_ASPNET_CERTIFICATE": "0",
        "DOTNET_MULTILEVEL_LOOKUP": "0",
        "DOTNET_NOLOGO": "1",
        "DOTNET_ROOT": str(sdk_root),
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "PATH": f"{sdk_root}:{environment.get('PATH', '/usr/bin:/bin')}",
    }
    _builder._verify_sdk(
        sdk_root, release, environment=sdk_environment, log=log
    )
    generate_from_prepared_sources(
        release=release,
        first_source=first_source,
        second_source=second_source,
        sdk_root=sdk_root,
        first_root=work_root / "pass-a",
        second_root=work_root / "pass-b",
        output=output,
        source_date_epoch=first_epoch,
        base_environment=environment,
    )
    return 0


def cli(arguments: list[str]) -> int:
    try:
        return main(arguments)
    except BuildError as error:
        print(
            "generate-runner-source-locks: unavailable "
            f"reason={_builder._closed_failure_reason(error)}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(cli(sys.argv[1:]))
