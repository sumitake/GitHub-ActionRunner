"""Behavior tests for the bounded Actions runner source builder."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts" / "release" / "build-runner-from-source.py"


def load_builder() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("runner_source_builder", BUILDER)
    if spec is None or spec.loader is None:
        raise AssertionError("builder import unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def add_regular(archive: tarfile.TarFile, name: str, raw: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.size = len(raw)
    archive.addfile(info, io.BytesIO(raw))


class RunnerSourceBuildTest(unittest.TestCase):
    def test_subprocess_rejection_reports_closed_diagnostic_without_output(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = "PRIVATE-DIAGNOSTIC-MATERIAL"
            with self.assertRaises(module.BuildError) as caught:
                module._run(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import sys; "
                            f"sys.stdout.write({secret!r} + ' NU1301\\n'); "
                            "sys.stderr.write('MSB1001\\n'); "
                            "raise SystemExit(17)"
                        ),
                    ],
                    cwd=root,
                    environment=dict(os.environ),
                    log=root / "build.log",
                    timeout=10,
                    capture=True,
                    maximum=1024,
                    stage="runner layout",
                )
            self.assertEqual(
                str(caught.exception),
                "runner layout subprocess rejected exit 17 diagnostic msb1001",
            )
            self.assertEqual(
                module._closed_failure_reason(caught.exception),
                "runner-layout-subprocess-rejected-exit-17-diagnostic-msb1001",
            )
            self.assertNotIn(secret, str(caught.exception))

    def test_subprocess_stage_rejects_unsafe_dynamic_text(self) -> None:
        module = load_builder()
        self.assertEqual(
            module._subprocess_rejection("download", -15, b"", b""),
            "download subprocess rejected signal 15",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                module.BuildError, "^subprocess contract invalid$"
            ):
                module._run(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=root,
                    environment=dict(os.environ),
                    log=root / "build.log",
                    timeout=10,
                    stage="download=/private/path",
                )

    def test_subprocess_timeout_is_stage_scoped_and_bounded(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = time.monotonic()
            with self.assertRaisesRegex(
                module.BuildError, "^download subprocess failed$"
            ):
                module._run(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    cwd=root,
                    environment=dict(os.environ),
                    log=root / "build.log",
                    timeout=1,
                    stage="download",
                )
            self.assertLess(time.monotonic() - started, 7)

    def test_subprocess_output_is_bounded_without_limiting_artifact_writes(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact"
            log = root / "build.log"
            with self.assertRaises(module.BuildError):
                module._run(
                    [
                        sys.executable,
                        "-c",
                        (
                            "from pathlib import Path; import sys; "
                            f"Path({str(artifact)!r}).write_bytes(b'x' * 8192); "
                            "sys.stdout.buffer.write(b'y' * 8192)"
                        ),
                    ],
                    cwd=root,
                    environment=dict(os.environ),
                    log=log,
                    timeout=10,
                    stage="download",
                    capture=True,
                    maximum=1024,
                )
            self.assertEqual(artifact.stat().st_size, 8192)
            self.assertLessEqual(log.stat().st_size, 2048)

    def test_subprocess_success_reaps_a_descendant_that_closed_its_pipes(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "descendant"
            module._run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os,time\n"
                        "from pathlib import Path\n"
                        f"identity=Path({str(identity)!r})\n"
                        "child=os.fork()\n"
                        "if child == 0:\n"
                        "    identity.write_text(f'{os.getpid()} {os.getpgrp()}')\n"
                        "    os.close(1)\n"
                        "    os.close(2)\n"
                        "    time.sleep(60)\n"
                        "    os._exit(0)\n"
                        "while not identity.exists():\n"
                        "    time.sleep(0.01)\n"
                    ),
                ],
                cwd=root,
                environment=dict(os.environ),
                log=root / "build.log",
                timeout=10,
                stage="download",
            )
            pid, process_group = (int(value) for value in identity.read_text().split())
            deadline = time.monotonic() + 5
            while True:
                try:
                    still_owned = os.getpgid(pid) == process_group
                except ProcessLookupError:
                    still_owned = False
                if not still_owned or time.monotonic() >= deadline:
                    break
                time.sleep(0.01)
            if still_owned:
                os.killpg(process_group, module.signal.SIGKILL)
            self.assertFalse(still_owned)

    def test_download_enforces_transfer_size_before_post_readback(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "asset"
            observed: list[str] = []

            def fake_run(command: list[str], **_kwargs: object) -> bytes:
                observed.extend(command)
                Path(command[command.index("--output") + 1]).write_bytes(b"asset")
                return b""

            with mock.patch.object(module, "_run", side_effect=fake_run):
                module._download(
                    "https://example.com/asset",
                    destination,
                    module.hashlib.sha256(b"asset").hexdigest(),
                    "sha256",
                    environment=dict(os.environ),
                    log=root / "download.log",
                    maximum_bytes=4096,
                )
            self.assertEqual(observed[observed.index("--max-filesize") + 1], "4096")

    def test_safe_extraction_rejects_traversal_and_escaping_symlink(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            traversal = root / "traversal.tar.gz"
            with tarfile.open(traversal, "w:gz") as archive:
                add_regular(archive, "node-v1-linux-x64/bin/node", b"node", 0o755)
                add_regular(archive, "../escaped", b"escape")

            output = root / "traversal-output"
            with self.assertRaises(module.BuildError):
                module.extract_verified_tar(
                    traversal,
                    output,
                    expected_root="node-v1-linux-x64",
                    maximum_entries=32,
                    maximum_expanded_bytes=1024,
                )
            self.assertFalse(output.exists())
            self.assertFalse((root / "escaped").exists())

            escaping = root / "escaping.tar.gz"
            with tarfile.open(escaping, "w:gz") as archive:
                add_regular(archive, "node-v1-linux-x64/bin/node", b"node", 0o755)
                info = tarfile.TarInfo("node-v1-linux-x64/bin/npm")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../outside"
                archive.addfile(info)
            with self.assertRaises(module.BuildError):
                module.extract_verified_tar(
                    escaping,
                    root / "escaping-output",
                    expected_root="node-v1-linux-x64",
                    maximum_entries=32,
                    maximum_expanded_bytes=1024,
                )

    def test_safe_extraction_preserves_complete_internal_node_layout(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "node.tar.gz"
            with tarfile.open(source, "w:gz") as archive:
                add_regular(
                    archive,
                    "node-v20.20.2-linux-x64/bin/node",
                    b"node-runtime",
                    0o755,
                )
                add_regular(
                    archive,
                    "node-v20.20.2-linux-x64/lib/node_modules/npm/bin/npm-cli.js",
                    b"npm-cli",
                )
                link = tarfile.TarInfo("node-v20.20.2-linux-x64/bin/npm")
                link.type = tarfile.SYMTYPE
                link.linkname = "../lib/node_modules/npm/bin/npm-cli.js"
                archive.addfile(link)

            output = root / "node"
            module.extract_verified_tar(
                source,
                output,
                expected_root="node-v20.20.2-linux-x64",
                maximum_entries=32,
                maximum_expanded_bytes=4096,
            )
            self.assertEqual((output / "bin/node").read_bytes(), b"node-runtime")
            self.assertEqual(
                (output / "lib/node_modules/npm/bin/npm-cli.js").read_bytes(),
                b"npm-cli",
            )
            self.assertTrue((output / "bin/npm").is_symlink())
            self.assertEqual(
                os.readlink(output / "bin/npm"),
                "../lib/node_modules/npm/bin/npm-cli.js",
            )

    def test_restore_assets_validate_the_closed_linux_pack_graph(self) -> None:
        module = load_builder()
        runtime_version = "fixture-runtime"
        names = (
            "Microsoft.AspNetCore.App.Runtime.linux-x64",
            "Microsoft.NETCore.App.Crossgen2.linux-x64",
            "Microsoft.NETCore.App.Host.linux-x64",
            "Microsoft.NETCore.App.Runtime.linux-x64",
        )
        exact = f"[{runtime_version}, {runtime_version}]"

        def write_assets(
            source: Path, project: str, dependencies: list[dict[str, object]]
        ) -> None:
            target = source / "src" / project / "obj" / "project.assets.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(
                    {
                        "project": {
                            "frameworks": {
                                "net8.0": {"downloadDependencies": dependencies}
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

        def write_graph(
            source: Path, assignments: dict[str, list[str]] | None = None
        ) -> None:
            if assignments is None:
                assignments = {
                    "Runner.Common": [names[0], names[1]],
                    "Runner.Listener": [names[0], names[2]],
                    "Runner.Worker": [names[3]],
                }
            for relative in module.LOCK_PATHS:
                project = relative.split("/", 1)[0]
                write_assets(
                    source,
                    project,
                    [
                        {"name": name, "version": exact}
                        for name in assignments.get(project, [])
                    ],
                )

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            write_graph(source)
            module._verify_restore_assets(source, runtime_version)

            write_graph(source)
            write_assets(source, "Runner.Common", [{"name": names[0], "version": "[old, old]"}])
            with self.assertRaisesRegex(module.BuildError, "^restore runtime pack mismatch$"):
                module._verify_restore_assets(source, runtime_version)

            write_graph(source, {})
            with self.assertRaisesRegex(module.BuildError, "^restore runtime pack mismatch$"):
                module._verify_restore_assets(source, runtime_version)

            invalid_names = (
                "",
                "microsoft.NETCore.App.Runtime.linux-x64",
                "Mıcrosoft.NETCore.App.Runtime.linux-x64",
                "Contoso.NETCore.App.Runtime.linux-x64",
                "Microsoft.NETCore..App.Runtime.linux-x64",
                "Microsoft.NETCore.App.Runtime-.linux-x64",
                "Microsoft.NETCore.App.Runtime.osx-arm64",
                "Microsoft.NETCore.App.Runtime.win-x64",
                "Microsoft.NETCore.App.Runtime.linux-arm64",
                "Microsoft.NETCore.App.Runtime.linux-x64.evil",
            )
            for invalid_name in invalid_names:
                with self.subTest(invalid_name=invalid_name):
                    write_graph(source)
                    write_assets(
                        source,
                        "Sdk",
                        [{"name": invalid_name, "version": exact}],
                    )
                    with self.assertRaisesRegex(
                        module.BuildError, "^restore runtime pack mismatch$"
                    ):
                        module._verify_restore_assets(source, runtime_version)

            write_graph(source)
            write_assets(
                source,
                "Runner.Listener",
                [
                    {"name": names[1], "version": exact},
                    {"name": names[1], "version": exact},
                ],
            )
            with self.assertRaisesRegex(module.BuildError, "^restore runtime pack duplicated$"):
                module._verify_restore_assets(source, runtime_version)

            write_graph(source)
            write_assets(source, "Runner.Common", [{"name": names[0], "version": 8}])
            with self.assertRaisesRegex(module.BuildError, "^restore assets dependency invalid$"):
                module._verify_restore_assets(source, runtime_version)

            write_graph(source)
            write_assets(
                source,
                "Runner.Common",
                [{"name": names[0], "version": exact, "unexpected": "field"}],
            )
            with self.assertRaisesRegex(module.BuildError, "^restore assets dependency invalid$"):
                module._verify_restore_assets(source, runtime_version)

            write_graph(source)
            (source / "src/Runner.PluginHost/obj/project.assets.json").unlink()
            with self.assertRaisesRegex(module.BuildError, "^restore assets unavailable$"):
                module._verify_restore_assets(source, runtime_version)

    def test_build_contract_is_locked_isolated_and_deterministic(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            sdk = root / "sdk"
            nuget = root / "nuget"
            source.mkdir()
            sdk.mkdir()
            nuget.mkdir()
            command, environment = module.layout_contract(
                source_root=source,
                sdk_root=sdk,
                nuget_root=nuget,
                source_date_epoch=1784569340,
                runner_version="2.336.0",
                restore_locked=True,
            )

            self.assertEqual(command[0], str(sdk / "dotnet"))
            self.assertEqual(
                [
                    value
                    for value in command
                    if value.startswith(
                        ("-p:RuntimeIdentifier=", "-p:RuntimeIdentifiers=")
                    )
                ],
                [
                    "-p:RuntimeIdentifier=linux-x64",
                    "-p:RuntimeIdentifiers=linux-x64",
                ],
            )
            self.assertIn("-p:RestoreLockedMode=true", command)
            self.assertIn("-p:RestorePackagesWithLockFile=true", command)
            self.assertIn("-p:TargetLatestRuntimePatch=true", command)
            self.assertIn("-p:ContinuousIntegrationBuild=true", command)
            self.assertIn("-p:Deterministic=true", command)
            self.assertIn(f"-p:PathMap={source}=/src", command)
            self.assertNotIn("-p:TargetLatestRuntimePatch=false", command)
            self.assertEqual(environment["NUGET_PACKAGES"], str(nuget))
            self.assertEqual(environment["SOURCE_DATE_EPOCH"], "1784569340")
            self.assertEqual(environment["DOTNET_ROOT"], str(sdk))
            self.assertEqual(environment["DOTNET_CLI_TELEMETRY_OPTOUT"], "1")
            self.assertEqual(environment["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"], "1")

    def test_lock_generation_changes_only_the_locked_mode_bit(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            sdk = root / "sdk"
            nuget = root / "nuget"
            source.mkdir()
            sdk.mkdir()
            nuget.mkdir()
            common = {
                "source_root": source,
                "sdk_root": sdk,
                "nuget_root": nuget,
                "source_date_epoch": 1784569340,
                "runner_version": "fixture-version",
            }

            generated, generated_environment = module.layout_contract(
                **common, restore_locked=False
            )
            revalidated, revalidated_environment = module.layout_contract(
                **common, restore_locked=True
            )

            self.assertEqual(generated_environment, revalidated_environment)
            self.assertEqual(
                [value for value in generated if not value.startswith("-p:RestoreLockedMode=")],
                [value for value in revalidated if not value.startswith("-p:RestoreLockedMode=")],
            )
            self.assertIn("-p:RestoreLockedMode=false", generated)
            self.assertNotIn("-p:RestoreLockedMode=true", generated)
            self.assertIn("-p:RestoreLockedMode=true", revalidated)
            self.assertNotIn("-p:RestoreLockedMode=false", revalidated)

    def test_locked_graph_recheck_detects_post_restore_byte_change(self) -> None:
        module = load_builder()
        self.assertTrue(hasattr(module, "_verify_locked_graph"))
        release = json.loads((ROOT / "release/manifest.json").read_text(encoding="utf-8"))[
            "runtime"
        ]["runner_release"]
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            module._copy_locked_graph(release, ROOT, source)
            module._verify_locked_graph(release, source)

            first = release["build"]["nuget_locks"]["files"][0]["path"]
            changed = source / "src" / first
            changed.chmod(0o644)
            changed.write_bytes(b"changed after restore\n")
            with self.assertRaisesRegex(module.BuildError, "^NuGet lock changed$"):
                module._verify_locked_graph(release, source)

    def test_normalization_rejects_mutable_residue_and_closes_modes(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "layout"
            (root / "bin").mkdir(parents=True)
            (root / "externals/node20/bin").mkdir(parents=True)
            (root / "bin/Runner.Listener").write_bytes(b"listener")
            (root / "bin/Runner.Listener").chmod(0o755)
            (root / "externals/node20/bin/node").write_bytes(b"node")
            (root / "externals/node20/bin/node").chmod(0o755)
            (root / "bin/library.dll").write_bytes(b"library")

            module.normalize_runner_layout(root)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((root / "bin").stat().st_mode), 0o555)
            self.assertEqual(
                stat.S_IMODE((root / "bin/Runner.Listener").stat().st_mode), 0o555
            )
            self.assertEqual(stat.S_IMODE((root / "bin/library.dll").stat().st_mode), 0o444)

            residue = root / "_update"
            root.chmod(0o755)
            residue.mkdir()
            with self.assertRaises(module.BuildError):
                module.normalize_runner_layout(root)

    def test_runner_release_loader_is_closed_and_evidence_bound(self) -> None:
        module = load_builder()
        release = json.loads((ROOT / "release/manifest.json").read_text(encoding="utf-8"))[
            "runtime"
        ]["runner_release"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "runner-release.json"
            valid.write_bytes(module.canonical_json(release))
            self.assertEqual(module.load_runner_release(valid), release)

            extra = json.loads(json.dumps(release))
            extra["linux_x64_asset_name"] = "historical-archive.tar.gz"
            invalid = root / "archive-shaped.json"
            invalid.write_bytes(module.canonical_json(extra))
            with self.assertRaises(module.BuildError):
                module.load_runner_release(invalid)

            drift = json.loads(json.dumps(release))
            drift["build"]["dotnet_sdk"]["runtime_version"] = "8.0.0"
            invalid.write_bytes(module.canonical_json(drift))
            with self.assertRaises(module.BuildError):
                module.load_runner_release(invalid)

    def test_runtime_readback_accepts_only_go_ordered_closed_source_lock(self) -> None:
        module = load_builder()
        release = json.loads((ROOT / "release/manifest.json").read_text(encoding="utf-8"))[
            "runtime"
        ]["runner_release"]
        payload = "a" * 64
        lock = {
            "schema_version": 2,
            "runner_version": release["version"],
            "runner_payload_sha256": payload,
            "runner_source_commit": release["source_commit_sha"],
            "runner_source_tree": release["source_tree_sha"],
            "runner_release_evidence": release["observation_evidence"],
            "command_settings_sha256": release["command_settings_sha256"],
            "runner_base_image": "example.invalid/runner@sha256:" + "b" * 64,
            "manifest_sha256": "c" * 64,
            "tree_lock_sha256": "d" * 64,
            "evidence_generation": 1,
            "listener": {
                "path": "/opt/actions-runner/bin/Runner.Listener",
                "sha256": "e" * 64,
                "size": 1,
                "mode": 365,
                "uid": 0,
                "gid": 0,
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            raw = (json.dumps(lock, separators=(",", ":")) + "\n").encode("ascii")
            (output / "runner.runtime-lock.json").write_bytes(raw)
            ready = {
                "schema_version": 1,
                "runtime_lock_sha256": module.hashlib.sha256(raw).hexdigest(),
                "tree_lock_sha256": lock["tree_lock_sha256"],
                "manifest_sha256": lock["manifest_sha256"],
                "evidence_generation": 1,
            }
            (output / "READY").write_text(
                json.dumps(ready, separators=(",", ":")) + "\n", encoding="ascii"
            )
            module._validate_published_runtime(output, release, payload)

            sorted_raw = module.canonical_json(lock)
            (output / "runner.runtime-lock.json").write_bytes(sorted_raw)
            ready["runtime_lock_sha256"] = module.hashlib.sha256(sorted_raw).hexdigest()
            (output / "READY").write_text(
                json.dumps(ready, separators=(",", ":")) + "\n", encoding="ascii"
            )
            with self.assertRaises(module.BuildError):
                module._validate_published_runtime(output, release, payload)

    def test_cli_emits_one_closed_source_build_reason(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(BUILDER)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(
            completed.stderr,
            b"build-runner-from-source: unavailable reason=arguments-invalid\n",
        )

    def test_runner_archive_is_byte_reproducible_across_mtime_and_root(self) -> None:
        module = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            archives = []
            for index in range(2):
                root = parent / f"layout-{index}"
                (root / "bin").mkdir(parents=True)
                (root / "externals/node20/bin").mkdir(parents=True)
                (root / "bin/Runner.Listener").write_bytes(b"listener")
                (root / "bin/Runner.Listener").chmod(0o755)
                (root / "externals/node20/bin/node").write_bytes(b"node")
                (root / "externals/node20/bin/node").chmod(0o755)
                (root / "LICENSE").write_bytes(b"license")
                os.utime(root / "LICENSE", (100 + index, 100 + index))
                module.normalize_runner_layout(root)
                archive = parent / f"runner-{index}.tar.gz"
                module.create_deterministic_runner_archive(root, archive)
                archives.append(archive.read_bytes())
            self.assertEqual(archives[0], archives[1])
            with tarfile.open(fileobj=io.BytesIO(archives[0]), mode="r:gz") as archive:
                self.assertEqual(archive.getmembers()[0].name, ".")
                self.assertIn("./bin/Runner.Listener", archive.getnames())


if __name__ == "__main__":
    unittest.main()
