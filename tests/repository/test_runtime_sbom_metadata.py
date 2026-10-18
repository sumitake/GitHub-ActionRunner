"""Fail closed on dependencies while recognizing an authenticated SPDX subject."""
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


class RuntimeSBOMMetadata(unittest.TestCase):
    def setUp(self):
        self.n = rehearsal()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.digest = "a" * 64
        self.root_package = {
            "SPDXID": "SPDXRef-subject",
            "name": "fixture-binary",
            "primaryPackagePurpose": "FILE",
            "versionInfo": "sha256:" + self.digest,
            "checksums": [{"algorithm": "SHA256", "checksumValue": self.digest}],
            "licenseDeclared": "NOASSERTION",
        }
        self.dependency = {
            "SPDXID": "SPDXRef-dependency",
            "name": "fixture-dependency",
            "versionInfo": "1.0.0",
            "licenseDeclared": "MIT",
            "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:generic/fixture-dependency@1.0.0"}],
        }
        self.value = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-subject"}],
            "packages": [self.root_package, self.dependency],
        }

    def notices(self, value):
        path = self.root / "fixture.spdx.json"
        path.write_text(json.dumps(value))
        before = path.read_bytes()
        output = self.root / "NOTICES.txt"
        self.n["generate_notices"]([("bin/fixture", path)], [], output, {"bin/fixture": self.digest})
        self.assertEqual(path.read_bytes(), before)
        return output.read_text()

    def test_verified_subject_is_not_a_dependency(self):
        text = self.notices(self.value)
        self.assertIn("pkg:generic/fixture-dependency@1.0.0", text)
        self.assertNotIn("fixture-binary", text)

    def test_unknown_dependency_still_blocks(self):
        self.dependency["licenseDeclared"] = "NOASSERTION"
        with self.assertRaisesRegex(self.n["RehearsalError"], "package license"):
            self.notices(self.value)

    def test_subject_needs_exact_checksum_and_graph_binding(self):
        for change in ["checksum", "relationship", "ambiguous", "purpose", "duplicate-id", "document-id", "related-type"]:
            with self.subTest(change=change):
                value = copy.deepcopy(self.value)
                if change == "checksum":
                    value["packages"][0]["checksums"][0]["checksumValue"] = "b" * 64
                elif change == "relationship":
                    value["relationships"][0]["spdxElementId"] = "SPDXRef-other"
                elif change == "ambiguous":
                    value["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-dependency"})
                elif change == "purpose":
                    value["packages"][0]["primaryPackagePurpose"] = "LIBRARY"
                elif change == "duplicate-id":
                    value["packages"].append(copy.deepcopy(value["packages"][0]))
                elif change == "document-id":
                    value["SPDXID"] = None
                    value["relationships"][0]["spdxElementId"] = None
                else:
                    value["relationships"][0]["relatedSpdxElement"] = []
                with self.assertRaises(self.n["RehearsalError"]):
                    self.notices(value)

    def test_lookalike_unbound_file_is_not_skipped(self):
        self.dependency.update(primaryPackagePurpose="FILE", checksums=copy.deepcopy(self.root_package["checksums"]))
        self.dependency.pop("externalRefs")
        with self.assertRaisesRegex(self.n["RehearsalError"], "package purl"):
            self.notices(self.value)

    def test_first_party_metadata_is_source_backed_and_conflicts_block(self):
        (self.root / "go.mod").write_text("module example.invalid/fixture\n\ngo 1.26.0\n")
        (self.root / "package.json").write_text(json.dumps({"license": "MPL-2.0"}))
        (self.root / "LICENSE").write_text("Mozilla Public License Version 2.0\nsynthetic license fixture\n")
        identity = self.n["first_party_metadata"](self.root, "candidate-fixture", "c" * 40)
        package = {"name": "example.invalid/fixture", "versionInfo": "UNKNOWN", "licenseDeclared": "NOASSERTION", "licenseConcluded": "NOASSERTION", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/example.invalid/fixture"}]}
        value = {"packages": [package, copy.deepcopy(self.dependency)]}
        dependency_before = copy.deepcopy(value["packages"][1])
        self.n["normalize_first_party_packages"](value, identity)
        self.assertEqual(package["versionInfo"], "candidate-fixture")
        self.assertEqual(package["licenseDeclared"], "MPL-2.0")
        self.assertIn("c" * 40, package["sourceInfo"])
        self.assertIn(hashlib.sha256((self.root / "LICENSE").read_bytes()).hexdigest(), package["sourceInfo"])
        self.assertEqual(value["packages"][1], dependency_before)
        for field, conflicting in [("licenseDeclared", "MIT"), ("versionInfo", "different")]:
            bad = copy.deepcopy(package)
            bad[field] = conflicting
            with self.assertRaises(self.n["RehearsalError"]):
                self.n["normalize_first_party_packages"]({"packages": [bad]}, identity)

    def test_syft_prefixed_release_version_normalizes_without_allowing_drift(self):
        for version in ("1.2.3", "1.2.3-rc1", "v1.2.3"):
            with self.subTest(version=version):
                identity = {"module": "example.invalid/fixture", "version": version, "license": "MPL-2.0", "source_commit": "c" * 40, "license_sha256": "d" * 64}
                inferred = version if version.startswith("v") else "v" + version
                package = {"name": identity["module"], "versionInfo": inferred, "licenseDeclared": "NOASSERTION", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/example.invalid/fixture@" + inferred}]}
                self.n["normalize_first_party_packages"]({"packages": [package]}, identity)
                self.assertEqual(package["versionInfo"], version)
                self.assertEqual(package["externalRefs"][0]["referenceLocator"], "pkg:golang/example.invalid/fixture@" + version)
                self.assertEqual(package["licenseDeclared"], "MPL-2.0")
                for field, conflicting in (("versionInfo", "v9.9.9"), ("externalRefs", [{"referenceType": "purl", "referenceLocator": "pkg:golang/example.invalid/fixture@v9.9.9"}])):
                    bad = copy.deepcopy(package)
                    bad[field] = conflicting
                    with self.assertRaises(self.n["RehearsalError"]):
                        self.n["normalize_first_party_packages"]({"packages": [bad]}, identity)

    def test_unrelated_unknown_license_cannot_be_filled(self):
        package = copy.deepcopy(self.dependency)
        package["licenseDeclared"] = "NOASSERTION"
        original = copy.deepcopy(package)
        identity = {"module": "example.invalid/fixture", "version": "candidate-fixture", "license": "MPL-2.0", "source_commit": "c" * 40, "license_sha256": "d" * 64}
        self.n["normalize_first_party_packages"]({"packages": [package]}, identity)
        self.assertEqual(package, original)

    def test_source_license_declaration_and_file_must_agree(self):
        (self.root / "go.mod").write_text("module example.invalid/fixture\n")
        (self.root / "package.json").write_text(json.dumps({"license": "MIT"}))
        (self.root / "LICENSE").write_text("Mozilla Public License Version 2.0\n")
        with self.assertRaises(self.n["RehearsalError"]):
            self.n["first_party_metadata"](self.root, "candidate-fixture", "c" * 40)


if __name__ == "__main__":
    unittest.main()
