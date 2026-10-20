"""Synthetic offline provenance and refusal checks for runner license metadata."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def rehearsal():
    path = ROOT / "scripts/release/rehearse-runtime.sh"
    text = path.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
    tree = ast.parse(text)
    tree.body = tree.body[:-1]
    namespace = {}
    exec(compile(tree, str(path), "exec"), namespace)
    return namespace


class RunnerLicensingMetadata(unittest.TestCase):
    def setUp(self):
        self.n = rehearsal()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "release/runner-license-texts").mkdir(parents=True)
        self.text_path = self.root / "release/runner-license-texts/fixture.txt"
        self.text_path.write_text("Synthetic upstream licensing fixture.\n")
        self.asset = "sha256:" + "a" * 64
        self.digest = "b" * 64
        self.license_id = "LicenseRef-Runner-Upstream-" + "c" * 20
        self.registry = {
            "schema_version": 1,
            "runner_asset_digest": self.asset,
            "packages": [
                {"name": "Example.Dependency", "version": "1.2.3", "purl": "pkg:nuget/Example.Dependency@1.2.3", "license_expression": "MIT", "evidence": [{"url": "https://example.invalid/dependency.nuspec", "sha256": "d" * 64, "detail": "metadata/license type=expression: MIT"}]},
                {"name": "fixture-engine", "version": "2.0.0", "purl": "pkg:generic/fixture-engine@2.0.0", "license_expression": self.license_id, "evidence": [{"url": "https://example.invalid/engine/LICENSE", "sha256": hashlib.sha256(self.text_path.read_bytes()).hexdigest(), "detail": "exact upstream license text"}]},
            ],
            "licenses": [{"license_id": self.license_id, "name": "Synthetic upstream licensing text", "files": [{"name": "LICENSE", "path": str(self.text_path.relative_to(self.root)), "sha256": hashlib.sha256(self.text_path.read_bytes()).hexdigest()}], "see_also": ["https://example.invalid/engine/LICENSE"]}],
        }
        self.value = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"}],
            "packages": [{"SPDXID": "SPDXRef-root", "name": "fixture-image", "primaryPackagePurpose": "CONTAINER", "versionInfo": "sha256:" + self.digest, "checksums": [{"algorithm": "SHA256", "checksumValue": self.digest}], "licenseDeclared": "NOASSERTION"}] + [
                {"SPDXID": "SPDXRef-package-" + str(i), "name": r["name"], "versionInfo": r["version"], "licenseDeclared": "NOASSERTION", "licenseConcluded": "NOASSERTION", "externalRefs": [{"referenceType": "purl", "referenceLocator": r["purl"]}]} for i, r in enumerate(self.registry["packages"])
            ],
        }
        self.spdx = self.root / "runner.spdx.json"

    def write(self):
        (self.root / "release/runner-licenses.json").write_text(json.dumps(self.registry))
        self.spdx.write_text(json.dumps(self.value))

    def apply(self, asset=None):
        self.write()
        before = self.spdx.read_bytes()
        try:
            self.n["supplement_runner_licenses"](self.root, {"linux_x64_asset_digest": asset or self.asset}, self.spdx, self.digest)
        except Exception:
            self.assertEqual(self.spdx.read_bytes(), before)
            raise
        return json.loads(self.spdx.read_text())

    def test_exact_upstream_declaration_and_full_text_are_preserved(self):
        result = self.apply()
        self.assertEqual(result["packages"][1]["licenseDeclared"], "MIT")
        self.assertEqual(result["packages"][1]["licenseConcluded"], "NOASSERTION")
        self.assertEqual(result["packages"][2]["licenseDeclared"], self.license_id)
        self.assertIn("d" * 64, result["packages"][1]["licenseComments"])
        self.assertIn(self.text_path.read_text(), result["hasExtractedLicensingInfos"][0]["extractedText"])
        projection = lambda v: [(p["SPDXID"], p["name"], p["versionInfo"], p.get("externalRefs")) for p in v["packages"]]
        self.assertEqual(projection(result), projection(self.value))
        before = self.spdx.read_bytes()
        self.n["supplement_runner_licenses"](self.root, {"linux_x64_asset_digest": self.asset}, self.spdx, self.digest)
        self.assertEqual(self.spdx.read_bytes(), before)
        notices = self.root / "NOTICES.txt"
        self.n["generate_notices"]([("images/runner.oci.tar", self.spdx)], [], notices, {"images/runner.oci.tar": self.digest})
        self.assertIn(self.text_path.read_text(), notices.read_text())

    def test_rebuild_licenses_bind_actual_archive_separately(self):
        self.write()
        official = {"linux_x64_asset_digest": "sha256:" + "f" * 64}
        payload = {"kind": "dotnet-rebuild", "sha256": self.asset.removeprefix("sha256:"), "upstream_sha256": "f" * 64}
        flags = self.n["apply_baseline_runner_licenses"](self.root, official, official, self.spdx, self.digest, payload=payload)
        self.assertEqual(flags, ["--verified-runner-licenses"])
        self.assertEqual(json.loads(self.spdx.read_text())["packages"][1]["licenseDeclared"], "MIT")
        self.write()
        payload["upstream_sha256"] = "e" * 64
        with self.assertRaises(self.n["RehearsalError"]):
            self.n["apply_baseline_runner_licenses"](self.root, official, official, self.spdx, self.digest, payload=payload)

    def test_other_runner_asset_is_refused(self):
        with self.assertRaises(self.n["RehearsalError"]):
            self.apply("sha256:" + "e" * 64)

    def test_identity_inventory_and_existing_license_drift_are_refused(self):
        for change in ("version", "name", "purl", "license", "unused", "duplicate"):
            with self.subTest(change=change):
                saved_value, saved_registry = copy.deepcopy(self.value), copy.deepcopy(self.registry)
                if change == "version": self.value["packages"][1]["versionInfo"] = "9.9.9"
                elif change == "name": self.value["packages"][1]["name"] = "Other.Dependency"
                elif change == "purl": self.value["packages"][1]["externalRefs"][0]["referenceLocator"] = "pkg:nuget/Other.Dependency@1.2.3"
                elif change == "license": self.value["packages"][1]["licenseDeclared"] = "GPL-3.0-only"
                elif change == "unused": self.value["packages"].pop()
                else: self.registry["packages"].append(copy.deepcopy(self.registry["packages"][0]))
                with self.assertRaises(self.n["RehearsalError"]): self.apply()
                self.value, self.registry = saved_value, saved_registry

    def test_license_text_hash_and_paths_are_checked(self):
        for change in ("hash", "escape", "symlink"):
            with self.subTest(change=change):
                saved = copy.deepcopy(self.registry)
                if change == "hash": self.registry["licenses"][0]["files"][0]["sha256"] = "f" * 64
                elif change == "escape": self.registry["licenses"][0]["files"][0]["path"] = "../fixture.txt"
                else:
                    alias = self.text_path.with_name("alias.txt")
                    alias.symlink_to(self.text_path)
                    self.registry["licenses"][0]["files"][0]["path"] = str(alias.relative_to(self.root))
                with self.assertRaises(self.n["RehearsalError"]): self.apply()
                self.registry = saved

    def test_license_reference_requires_text_and_conflicting_reference_blocks(self):
        saved_licenses = copy.deepcopy(self.registry["licenses"])
        self.registry["licenses"] = []
        with self.assertRaises(self.n["RehearsalError"]): self.apply()
        self.registry["licenses"] = saved_licenses
        self.value["hasExtractedLicensingInfos"] = [{"licenseId": self.license_id, "extractedText": "different synthetic terms"}]
        with self.assertRaises(self.n["RehearsalError"]): self.apply()

    def test_unknown_package_remains_blocking(self):
        other = copy.deepcopy(self.value["packages"][1])
        other.update(SPDXID="SPDXRef-other", name="Other.Dependency", externalRefs=[{"referenceType": "purl", "referenceLocator": "pkg:nuget/Other.Dependency@1.2.3"}])
        self.value["packages"].append(other)
        result = self.apply()
        self.assertEqual(result["packages"][-1]["licenseDeclared"], "NOASSERTION")
        with self.assertRaisesRegex(self.n["RehearsalError"], "package license"):
            self.n["generate_notices"]([("images/runner.oci.tar", self.spdx)], [], self.root / "NOTICES.txt", {"images/runner.oci.tar": self.digest})

    def test_notices_require_full_text_for_supplemented_reference(self):
        value = self.apply()
        value.pop("hasExtractedLicensingInfos")
        self.spdx.write_text(json.dumps(value))
        with self.assertRaisesRegex(self.n["RehearsalError"], "runner licensing text"):
            self.n["generate_notices"]([("images/runner.oci.tar", self.spdx)], [], self.root / "NOTICES.txt", {"images/runner.oci.tar": self.digest})

    def test_other_candidate_asset_uses_its_own_catalog_without_retargeting_evidence(self):
        self.write()
        original = self.spdx.read_bytes()
        candidate = {"linux_x64_asset_digest": "sha256:" + "e" * 64}
        self.assertEqual(self.n["apply_baseline_runner_licenses"](self.root, {"linux_x64_asset_digest": self.asset}, candidate, self.spdx, self.digest), [])
        self.assertEqual(self.spdx.read_bytes(), original)
        with self.assertRaisesRegex(self.n["RehearsalError"], "package license"):
            self.n["generate_notices"]([("images/runner.oci.tar", self.spdx)], [], self.root / "NOTICES.txt", {"images/runner.oci.tar": self.digest})
        for package in self.value["packages"][1:]:
            package["licenseDeclared"] = "MIT"
        self.write()
        original = self.spdx.read_bytes()
        self.assertEqual(self.n["apply_baseline_runner_licenses"](self.root, {"linux_x64_asset_digest": self.asset}, candidate, self.spdx, self.digest), [])
        self.assertEqual(self.spdx.read_bytes(), original)
        self.n["generate_notices"]([("images/runner.oci.tar", self.spdx)], [], self.root / "NOTICES.txt", {"images/runner.oci.tar": self.digest})

    def test_authenticated_baseline_receives_reviewed_supplement(self):
        self.write()
        baseline = {"linux_x64_asset_digest": self.asset}
        self.assertEqual(self.n["apply_baseline_runner_licenses"](self.root, baseline, baseline, self.spdx, self.digest), ["--verified-runner-licenses"])
        self.assertEqual(json.loads(self.spdx.read_text())["packages"][1]["licenseDeclared"], "MIT")

    def test_subject_digest_mismatch_blocks_metadata(self):
        self.value["packages"][0]["checksums"][0]["checksumValue"] = "f" * 64
        with self.assertRaises(self.n["RehearsalError"]): self.apply()


if __name__ == "__main__":
    unittest.main()
