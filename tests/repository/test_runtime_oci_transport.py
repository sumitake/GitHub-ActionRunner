"""Exercise verified OCI transport without a Docker daemon or vendor program."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

from tests.repository.test_runtime_sbom_metadata import rehearsal


def canonical(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class RuntimeOCITransport(unittest.TestCase):
    def setUp(self):
        self.n = rehearsal()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, name="fixture.oci.tar", corrupt=False, extra=False):
        blobs = {}

        def blob(data, media):
            digest = hashlib.sha256(data).hexdigest()
            blobs["blobs/sha256/" + digest] = data
            return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media}

        config = blob(canonical({"architecture": "amd64", "os": "linux"}), "application/vnd.oci.image.config.v1+json")
        layer = blob(b"synthetic-layer", "application/vnd.oci.image.layer.v1.tar")
        manifest = blob(canonical({"schemaVersion": 2, "config": config, "layers": [layer]}), "application/vnd.oci.image.manifest.v1+json")
        manifest["platform"] = {"architecture": "amd64", "os": "linux"}
        files = {"oci-layout": canonical({"imageLayoutVersion": "1.0.0"}), "index.json": canonical({"schemaVersion": 2, "manifests": [manifest]}), **blobs}
        if corrupt:
            files["blobs/sha256/" + layer["digest"][7:]] = b"wrong-same-size!"
        if extra:
            files["unexpected"] = b"synthetic-input"
        path = self.root / name
        with tarfile.open(path, "w") as tf:
            for relative, data in files.items():
                info = tarfile.TarInfo(relative)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return path, files

    def test_layout_preserves_every_verified_blob(self):
        path, expected = self.archive()
        before = path.read_bytes()
        layout = self.root / "layout"
        self.n["materialize_oci_layout"](path, layout)
        observed = {p.relative_to(layout).as_posix(): p.read_bytes() for p in layout.rglob("*") if p.is_file()}
        self.assertEqual(observed, expected)
        self.assertEqual(path.read_bytes(), before)

    def test_bad_blob_or_extra_file_is_refused(self):
        for name, kwargs in [("corrupt", {"corrupt": True}), ("extra", {"extra": True})]:
            path, _ = self.archive(name + ".tar", **kwargs)
            layout = self.root / name
            with self.subTest(name=name), self.assertRaises(self.n["RehearsalError"]):
                self.n["materialize_oci_layout"](path, layout)
            self.assertFalse(layout.exists())

    def test_existing_layout_is_preserved(self):
        path, _ = self.archive()
        layout = self.root / "layout"
        layout.mkdir()
        (layout / "sentinel").write_text("synthetic-existing")
        with self.assertRaises(self.n["RehearsalError"]):
            self.n["materialize_oci_layout"](path, layout)
        self.assertEqual((layout / "sentinel").read_text(), "synthetic-existing")

    def test_scanner_receives_layout_and_failure_is_not_swallowed(self):
        path, _ = self.archive()
        tool = self.root / "fixture-scanner"
        tool.write_text("#!" + sys.executable + "\n" + '''import pathlib,sys
a=sys.argv[1:]
assert a[0]=='image'
p=pathlib.Path(a[a.index('--input')+1])
assert p.is_dir() and (p/'index.json').is_file()
assert a[a.index('--severity')+1]=='HIGH,CRITICAL'
assert a[a.index('--scanners')+1]=='vuln,secret'
assert '--ignore-unfixed' in a
raise SystemExit(int(__import__('os').environ['FIXTURE_EXIT']))
''')
        tool.chmod(0o755)
        log = self.root / "scan.log"
        for code in [0, 31]:
            layout = self.root / ("layout-" + str(code))
            args = (str(tool), path, layout, self.root, {**os.environ, "FIXTURE_EXIT": str(code)}, log)
            if code:
                with self.assertRaises(self.n["RehearsalError"]):
                    self.n["scan_oci_image"](*args)
            else:
                self.n["scan_oci_image"](*args)
            self.assertFalse(layout.exists())

    def test_image_inputs_use_the_verified_stamped_binaries(self):
        clone = self.root / "clone"
        context = clone / "images/fixture/build"
        context.mkdir(parents=True)
        stage = self.root / "stage"
        (stage / "bin").mkdir(parents=True)
        target = context / "portable-ghar-fixture"
        target.write_bytes(b"synthetic-unstamped")
        binary = stage / "bin/portable-ghar-fixture"
        binary.write_bytes(b"synthetic-verified-identity-stamp")
        runtime = {"images": [{"name": "fixture", "context": "images/fixture"}], "binaries": [{"name": binary.name}]}
        self.n["stage_stamped_image_inputs"](clone, stage, runtime, "verified-identity-stamp")
        self.assertEqual(target.read_bytes(), binary.read_bytes())
        self.assertEqual(target.stat().st_mode & 0o777, 0o555)
        (context / "portable-ghar-unknown").write_bytes(b"synthetic-unknown")
        with self.assertRaises(self.n["RehearsalError"]):
            self.n["stage_stamped_image_inputs"](clone, stage, runtime, "verified-identity-stamp")


if __name__ == "__main__":
    unittest.main()
