"""Executable contract for the single source-built Actions runner payload."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "release" / "manifest.json"
REHEARSAL = ROOT / "scripts" / "release" / "rehearse-runtime.sh"

EXPECTED_LOCK_PATHS = [
    "Runner.Common/packages.lock.json",
    "Runner.Listener/packages.lock.json",
    "Runner.PluginHost/packages.lock.json",
    "Runner.Plugins/packages.lock.json",
    "Runner.Sdk/packages.lock.json",
    "Runner.Worker/packages.lock.json",
    "Sdk/packages.lock.json",
]

EXPECTED_EXTERNALS = [
    {
        "asset_name": "node-v20.20.2-linux-x64.tar.gz",
        "layout": "node20",
        "sha256": "19e56f0825510207dd904f087fe52faa0a4eb6b2aab5f0ea7a33830d04888b8b",
        "source_url": "https://nodejs.org/dist/v20.20.2/node-v20.20.2-linux-x64.tar.gz",
        "version": "20.20.2",
    },
    {
        "asset_name": "node-v20.20.2-alpine-x64.tar.gz",
        "layout": "node20_alpine",
        "sha256": "f21a2253025a5d1a14332a0b1ed48871689c5ca9aa37a6141428944b75de7d91",
        "source_url": "https://github.com/actions/alpine_nodejs/releases/download/v20.20.2/node-v20.20.2-alpine-x64.tar.gz",
        "version": "20.20.2",
    },
    {
        "asset_name": "node-v24.18.0-linux-x64.tar.gz",
        "layout": "node24",
        "sha256": "783130984963db7ba9cbd01089eaf2c2efb055c7c1693c943174b967b3050cb8",
        "source_url": "https://nodejs.org/dist/v24.18.0/node-v24.18.0-linux-x64.tar.gz",
        "version": "24.18.0",
    },
    {
        "asset_name": "node-v24.18.0-alpine-x64.tar.gz",
        "layout": "node24_alpine",
        "sha256": "0103dd81376d57dcc2bcb39a13cfd6db19ab82f6c2c83a166e44d775f736d0d9",
        "source_url": "https://github.com/actions/alpine_nodejs/releases/download/v24.18.0/node-v24.18.0-alpine-x64.tar.gz",
        "version": "24.18.0",
    },
]


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def source_evidence(value: dict[str, object]) -> str:
    admitted = {key: item for key, item in value.items() if key != "observation_evidence"}
    document = {
        "protocol": "portable-ghar-runner-source-release-v2",
        "runner_release": admitted,
    }
    return hashlib.sha256(canonical(document)).hexdigest()


def lock_aggregate(files: list[dict[str, str]]) -> str:
    return hashlib.sha256(canonical({"files": files})).hexdigest()


def fixture() -> dict[str, object]:
    lock_files = [
            {"path": path, "sha256": format(index + 1, "064x")}
            for index, path in enumerate(EXPECTED_LOCK_PATHS)
        ]
    locks = {
        "aggregate_sha256": lock_aggregate(lock_files),
        "files": lock_files,
    }
    value: dict[str, object] = {
        "build": {
            "dotnet_sdk": {
                "asset_name": "dotnet-sdk-8.0.424-linux-x64.tar.gz",
                "rid": "linux-x64",
                "runtime_version": "8.0.30",
                "sha512": "6503fd9f464d5e3a4f43a881d2b74afc6a2c46ceda74d027f1565b7239f4b3ec884857c03c0dcd49eb52f384d5ae1fa5aaf135f0a6aabc5518103aceed643c74",
                "source_url": "https://builds.dotnet.microsoft.com/dotnet/Sdk/8.0.424/dotnet-sdk-8.0.424-linux-x64.tar.gz",
                "version": "8.0.424",
            },
            "expected_listener_version": "2.336.0",
            "externals": EXPECTED_EXTERNALS,
            "nuget_locks": locks,
        },
        "command_settings_sha256": "937f6552579f7d1eeb0a6d0201586781eb3e2e5ea2ab3878429076560e0cab08",
        "observation_evidence": "",
        "published_at": "2026-07-20T17:45:55Z",
        "schema_version": 2,
        "source_commit_sha": "98aabcd429c4e8402406c56ce2d26387fed3b9ce",
        "source_tree_sha": "3789e2e60ae52fc9c45b78e0d7f436ee2526b6d5",
        "tag_ref_sha": "98aabcd429c4e8402406c56ce2d26387fed3b9ce",
        "version": "v2.336.0",
    }
    value["observation_evidence"] = source_evidence(value)
    return value


def rehearsal_namespace() -> dict[str, object]:
    source = REHEARSAL.read_text(encoding="utf-8")
    payload = source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
    tree = ast.parse(payload, filename=str(REHEARSAL))
    if not tree.body or not isinstance(tree.body[-1], ast.Try):
        raise AssertionError("unexpected rehearsal entry point")
    tree.body = tree.body[:-1]
    namespace: dict[str, object] = {}
    exec(compile(tree, str(REHEARSAL), "exec"), namespace)
    return namespace


class RunnerSourceContractTest(unittest.TestCase):
    def test_release_manifest_selects_one_exact_source_built_payload(self) -> None:
        runtime = json.loads(MANIFEST.read_text(encoding="utf-8"))["runtime"]
        runner = runtime["runner_release"]

        expected = fixture()
        self.assertEqual(
            {
                key: runner[key]
                for key in runner
                if key not in {"build", "observation_evidence"}
            },
            {
                key: expected[key]
                for key in expected
                if key not in {"build", "observation_evidence"}
            },
        )
        self.assertEqual(runner["build"]["dotnet_sdk"], expected["build"]["dotnet_sdk"])
        self.assertEqual(
            runner["build"]["expected_listener_version"], "2.336.0"
        )
        self.assertEqual(runner["build"]["externals"], EXPECTED_EXTERNALS)
        self.assertNotIn("runner_source", runtime)
        self.assertFalse(
            {"linux_x64_asset_name", "linux_x64_asset_size", "linux_x64_asset_digest"}
            & runner.keys()
        )
        locks = runner["build"]["nuget_locks"]
        self.assertEqual([item["path"] for item in locks["files"]], EXPECTED_LOCK_PATHS)
        for item in locks["files"]:
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
            lock_path = ROOT / "release" / "runner-source-locks" / item["path"]
            self.assertTrue(lock_path.is_file())
            self.assertFalse(lock_path.is_symlink())
            self.assertEqual(hashlib.sha256(lock_path.read_bytes()).hexdigest(), item["sha256"])
        self.assertEqual(locks["aggregate_sha256"], lock_aggregate(locks["files"]))
        self.assertEqual(runner["observation_evidence"], source_evidence(runner))

    def test_rehearsal_accepts_v2_and_rejects_archive_v1(self) -> None:
        namespace = rehearsal_namespace()
        validate = namespace["validate_runner"]
        source_built = fixture()
        self.assertEqual(validate(source_built), source_built)

        archive_v1 = {
            "command_settings_sha256": "4" * 64,
            "linux_x64_asset_digest": "sha256:" + "3" * 64,
            "linux_x64_asset_name": "actions-runner-linux-x64-2.336.0.tar.gz",
            "linux_x64_asset_size": 1,
            "observation_evidence": "5" * 64,
            "published_at": "2026-07-20T17:45:55Z",
            "schema_version": 1,
            "source_commit_sha": "2" * 40,
            "tag_ref_sha": "1" * 40,
            "version": "v2.336.0",
        }
        with self.assertRaises(namespace["RehearsalError"]):
            validate(archive_v1)

    def test_source_evidence_binds_every_build_input(self) -> None:
        namespace = rehearsal_namespace()
        evidence_digest = namespace["evidence_digest"]
        base = fixture()
        self.assertEqual(evidence_digest(base), base["observation_evidence"])

        mutations = []
        source_tree = dict(base)
        source_tree["source_tree_sha"] = "a" * 40
        mutations.append(source_tree)

        sdk = json.loads(json.dumps(base))
        sdk["build"]["dotnet_sdk"]["runtime_version"] = "8.0.29"
        mutations.append(sdk)

        external = json.loads(json.dumps(base))
        external["build"]["externals"][0]["sha256"] = "b" * 64
        mutations.append(external)

        lock = json.loads(json.dumps(base))
        lock["build"]["nuget_locks"]["files"][0]["sha256"] = "c" * 64
        mutations.append(lock)

        for value in mutations:
            with self.subTest(value=value):
                self.assertNotEqual(evidence_digest(value), base["observation_evidence"])


if __name__ == "__main__":
    unittest.main()
