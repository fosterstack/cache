# proves: REQ-SCAN-008-AC3, REQ-REL-004-AC3
"""The daily auditor reads the rescan's `images` artifact as Build lays it out: out/<variant>.tar (production.tar, fips.tar), not <variant>.oci.
The readers are the real functions of auditor-panel.py and auditor-manifest.py; only skopeo and the image reader are replaced."""
import hashlib, importlib.util, io, json, os, tarfile, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load(name, fname):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BIN, fname))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


P = load("auditor_panel_tar", "auditor-panel.py")
M = load("auditor_manifest_tar", "auditor-manifest.py")


def image_tar(path):
    """A minimal OCI layout archive: index.json naming one manifest blob that exists."""
    blob = b"{}"
    d = "sha256:" + hashlib.sha256(blob).hexdigest()
    with tarfile.open(path, "w") as t:
        for name, data in (("index.json", json.dumps({"manifests": [{"digest": d}]}).encode()), ("blobs/" + d.replace(":", "/"), blob)):
            ti = tarfile.TarInfo(name); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
    return d


class ImagesTar(unittest.TestCase):
    def test_rescan_binding_reads_the_tar_files_of_the_images_artifact(self):
        with tempfile.TemporaryDirectory() as w:
            images = os.path.join(w, "images"); os.makedirs(images)
            d1, d2 = image_tar(os.path.join(images, "production.tar")), image_tar(os.path.join(images, "fips.tar"))
            for n in ("production.digest", "production.manifests", "fips.digest"):
                open(os.path.join(images, n), "w").write("x\n")      # the other files of the artifact are ignored
            b = os.path.join(w, "binding.json")
            json.dump({"run_id": "1", "head": "a" * 40, "main_head": "a" * 40, "conclusion": "success"}, open(b, "w"))
            got, why = P.rescan_binding(b, images)
            self.assertIsNone(why)
            self.assertEqual(got["digests"], {"production": d1, "fips": d2})

    def test_bundles_read_variant_dot_tar(self):
        seen = []
        def read(path, arch):
            seen.append(path); raise OSError("stop")
        P.Bundles("/x/images", read=read)({"image": "production-amd64"})
        self.assertEqual(seen, ["/x/images/production.tar"])

    def test_manifest_finds_production_tar(self):
        with tempfile.TemporaryDirectory() as w:
            os.makedirs(os.path.join(w, "images")); open(os.path.join(w, "images", "production.tar"), "w").write("x")
            with mock.patch.object(M, "_skopeo", return_value=True) as sk:
                got, why = M._archives(w, "", os.path.join(w, "c.oci"), os.path.join(w, "c.tar"))
            self.assertIsNone(why)
            self.assertEqual(got, "production.tar")
            self.assertTrue(sk.call_args_list[0][0][0].endswith("production.tar"))


if __name__ == "__main__":
    unittest.main()
