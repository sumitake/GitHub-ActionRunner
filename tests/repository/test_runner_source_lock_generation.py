"""Behavior tests for exact runner NuGet lock generation."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import textwrap
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "release" / "generate-runner-source-locks.py"


def load_generator() -> types.ModuleType:
    if not GENERATOR.is_file():
        raise AssertionError("runner source lock generator is missing")
    spec = importlib.util.spec_from_file_location("runner_source_lock_generator", GENERATOR)
    if spec is None or spec.loader is None:
        raise AssertionError("runner source lock generator import unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RunnerSourceLockGenerationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.release = json.loads(
            (ROOT / "release/manifest.json").read_text(encoding="utf-8")
        )["runtime"]["runner_release"]
        self.lock_paths = [
            item["path"] for item in self.release["build"]["nuget_locks"]["files"]
        ]

    def _write_fake_sdk(self, root: Path) -> Path:
        sdk = root / "sdk"
        sdk.mkdir()
        dotnet = sdk / "dotnet"
        dotnet.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                from pathlib import Path
                import sys

                locked = next(
                    value.rsplit("=", 1)[1]
                    for value in sys.argv
                    if value.startswith("-p:RestoreLockedMode=")
                )
                source = Path(sys.argv[-1]).parent.parent
                paths = json.loads(os.environ["TEST_LOCK_PATHS"])
                marker = {
                    "locked": locked,
                    "nuget": os.environ["NUGET_PACKAGES"],
                    "home": os.environ["DOTNET_CLI_HOME"],
                    "http": os.environ["NUGET_HTTP_CACHE_PATH"],
                    "plugins": os.environ["NUGET_PLUGINS_CACHE_PATH"],
                }
                (source / "observed-layout.json").write_text(
                    json.dumps(marker, sort_keys=True), encoding="utf-8"
                )
                if locked == "false":
                    for relative in paths:
                        target = source / "src" / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(
                            json.dumps({"path": relative}, sort_keys=True) + "\\n",
                            encoding="utf-8",
                        )
                else:
                    for relative in paths:
                        if not (source / "src" / relative).is_file():
                            raise SystemExit(9)
                    if os.environ.get("TEST_MUTATE_LOCK") == "1":
                        changed = source / "src" / paths[0]
                        changed.chmod(0o644)
                        changed.write_text("mutated\\n", encoding="utf-8")
                runtime_packs = [
                    "Microsoft.AspNetCore.App.Runtime.linux-x64",
                    "Microsoft.NETCore.App.Crossgen2.linux-x64",
                    "Microsoft.NETCore.App.Host.linux-x64",
                    "Microsoft.NETCore.App.Runtime.linux-x64",
                ]
                assets = {
                    "project": {
                        "frameworks": {
                            "net8.0": {
                                "downloadDependencies": [
                                    {"name": name, "version": "[8.0.30, 8.0.30]"}
                                    for name in runtime_packs
                                ]
                            }
                        }
                    }
                }
                assignments = {
                    paths[0].split("/", 1)[0]: [runtime_packs[0]],
                    paths[1].split("/", 1)[0]: [runtime_packs[1]],
                    paths[2].split("/", 1)[0]: [runtime_packs[2]],
                    paths[3].split("/", 1)[0]: [runtime_packs[3]],
                }
                for relative in paths:
                    project = relative.split("/", 1)[0]
                    dependencies = [
                        {"name": name, "version": "[8.0.30, 8.0.30]"}
                        for name in assignments.get(project, [])
                    ]
                    assets["project"]["frameworks"]["net8.0"][
                        "downloadDependencies"
                    ] = dependencies
                    target = source / "src" / project / "obj" / "project.assets.json"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(json.dumps(assets), encoding="utf-8")
                """
            ),
            encoding="utf-8",
        )
        dotnet.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        return sdk

    def _source(self, root: Path, name: str) -> Path:
        source = root / name
        (source / "src").mkdir(parents=True)
        (source / "src" / "dir.proj").write_text("<Project />\n", encoding="utf-8")
        return source

    def test_two_layouts_use_fresh_roots_and_publish_exact_unchanged_locks(self) -> None:
        module = load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first_source = self._source(root, "source-a")
            second_source = self._source(root, "source-b")
            sdk = self._write_fake_sdk(root)
            output = root / "output"
            environment = {
                **os.environ,
                "TEST_LOCK_PATHS": json.dumps(self.lock_paths),
            }

            receipt = module.generate_from_prepared_sources(
                release=self.release,
                first_source=first_source,
                second_source=second_source,
                sdk_root=sdk,
                first_root=root / "pass-a",
                second_root=root / "pass-b",
                output=output,
                source_date_epoch=1784569340,
                base_environment=environment,
            )

            first_marker = json.loads(
                (first_source / "observed-layout.json").read_text(encoding="utf-8")
            )
            second_marker = json.loads(
                (second_source / "observed-layout.json").read_text(encoding="utf-8")
            )
            self.assertEqual(first_marker["locked"], "false")
            self.assertEqual(second_marker["locked"], "true")
            for key in ("nuget", "home", "http", "plugins"):
                self.assertNotEqual(first_marker[key], second_marker[key])

            self.assertEqual(
                sorted(
                    path.relative_to(output).as_posix()
                    for path in output.rglob("packages.lock.json")
                ),
                sorted(self.lock_paths),
            )
            for relative in self.lock_paths:
                self.assertEqual(
                    (output / relative).read_bytes(),
                    (second_source / "src" / relative).read_bytes(),
                )
            self.assertEqual(receipt["nuget_locks"]["files"], [
                {
                    "path": relative,
                    "sha256": module.sha256_bytes((output / relative).read_bytes()),
                }
                for relative in self.lock_paths
            ])
            self.assertEqual(
                json.loads((output / "receipt.json").read_text(encoding="utf-8")),
                receipt,
            )

    def test_locked_layout_byte_mutation_is_terminal_and_publishes_nothing(self) -> None:
        module = load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = {
                **os.environ,
                "TEST_LOCK_PATHS": json.dumps(self.lock_paths),
                "TEST_MUTATE_LOCK": "1",
            }
            output = root / "output"
            with self.assertRaisesRegex(module.BuildError, "^NuGet lock revalidation failed$"):
                module.generate_from_prepared_sources(
                    release=self.release,
                    first_source=self._source(root, "source-a"),
                    second_source=self._source(root, "source-b"),
                    sdk_root=self._write_fake_sdk(root),
                    first_root=root / "pass-a",
                    second_root=root / "pass-b",
                    output=output,
                    source_date_epoch=1784569340,
                    base_environment=environment,
                )
            self.assertFalse(output.exists())

    def test_cli_setup_oserror_is_sanitized(self) -> None:
        module = load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            work = root / "work"
            work.mkdir(mode=0o700)
            work.chmod(0o700)
            stdout = io.StringIO()
            stderr = io.StringIO()
            prior_umask = os.umask(0o077)
            os.umask(prior_umask)
            try:
                with mock.patch.object(
                    module._builder,
                    "load_runner_release",
                    return_value=self.release,
                ), mock.patch.object(
                    module.platform,
                    "system",
                    return_value="Linux",
                ), mock.patch.object(
                    module.platform,
                    "machine",
                    return_value="x86_64",
                ), mock.patch.object(
                    Path,
                    "touch",
                    side_effect=OSError("PRIVATE-LOCAL-PATH-MATERIAL"),
                ):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        result = module.cli(
                            [
                                "--runner-manifest",
                                str(ROOT / "release/manifest.json"),
                                "--output",
                                str(root / "output"),
                                "--work-root",
                                str(work),
                            ]
                        )
            finally:
                os.umask(prior_umask)

            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                stderr.getvalue(),
                "generate-runner-source-locks: unavailable "
                "reason=lock-generation-setup-unavailable\n",
            )
            self.assertNotIn("PRIVATE-LOCAL-PATH-MATERIAL", stderr.getvalue())

    def test_product_manifest_extracts_one_exact_runner_release(self) -> None:
        module = load_generator()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary).resolve() / "runner-release.json"

            observed = module._load_product_runner_release(
                ROOT / "release/manifest.json", destination
            )

            self.assertEqual(observed, self.release)
            self.assertEqual(
                destination.read_bytes(), module._builder.canonical_json(self.release)
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)


if __name__ == "__main__":
    unittest.main()
