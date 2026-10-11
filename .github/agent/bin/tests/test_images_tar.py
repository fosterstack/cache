# proves: REQ-SCAN-008-AC3, REQ-REL-004-AC3
"""The daily auditor reads the rescan's `images` artifact as Build lays it out: one OCI layout DIRECTORY per variant (images/production/, images/fips/ with
oci-layout, index.json and blobs/), so the image digest is the one Build recorded; an archive file or a docker-save shape is no evidence.
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


def image_layout(path, layout_file=True):
    """A minimal OCI image LAYOUT directory (Build's images/<variant>/): oci-layout, index.json naming one manifest, and that blob."""
    blob = b"{}"
    d = "sha256:" + hashlib.sha256(blob).hexdigest()
    os.makedirs(os.path.join(path, "blobs", "sha256"))
    if layout_file:
        open(os.path.join(path, "oci-layout"), "w").write('{"imageLayoutVersion": "1.0.0"}')
    open(os.path.join(path, "index.json"), "w").write(json.dumps({"manifests": [{"digest": d}]}))
    open(os.path.join(path, "blobs", "sha256", d.split(":")[1]), "wb").write(blob)
    return d


def binding(w):
    b = os.path.join(w, "binding.json")
    json.dump({"run_id": "1", "head": "a" * 40, "main_head": "a" * 40, "conclusion": "success"}, open(b, "w"))
    return b


class ImagesLayout(unittest.TestCase):
    def test_rescan_binding_reads_the_layout_directories_of_the_images_artifact(self):
        with tempfile.TemporaryDirectory() as w:
            images = os.path.join(w, "images"); os.makedirs(images)
            d1, d2 = image_layout(os.path.join(images, "production")), image_layout(os.path.join(images, "fips"))
            for n in ("production.digest", "production.manifests", "fips.digest"):
                open(os.path.join(images, n), "w").write("x\n")      # the other files of the artifact are ignored
            got, why = P.rescan_binding(binding(w), images)
            self.assertIsNone(why)
            self.assertEqual(got["digests"], {"production": d1, "fips": d2})

    def test_a_docker_save_shape_or_an_archive_file_is_not_evidence(self):
        with tempfile.TemporaryDirectory() as w:
            images = os.path.join(w, "images"); os.makedirs(images)
            image_layout(os.path.join(images, "production"), layout_file=False)          # index.json and blobs but no oci-layout
            os.makedirs(os.path.join(images, "fips")); open(os.path.join(images, "fips", "manifest.json"), "w").write("[]")   # docker save
            open(os.path.join(images, "production.tar"), "w").write("x"); open(os.path.join(images, "fips.oci"), "w").write("x")
            got, why = P.rescan_binding(binding(w), images)
            self.assertIsNone(got)
            self.assertIn("no image digest", why)

    def test_bundles_read_the_variant_directory(self):
        seen = []
        def read(path, arch):
            seen.append(path); raise OSError("stop")
        P.Bundles("/x/images", read=read)({"image": "production-amd64"})
        self.assertEqual(seen, ["/x/images/production"])

    def test_missing_variant_layout_has_no_evidence(self):
        with tempfile.TemporaryDirectory() as w:
            self.assertIn("could not be read", P.Bundles(w)({"image": "fips-amd64"}))

    def test_read_image_refuses_a_directory_that_is_not_a_layout(self):
        with tempfile.TemporaryDirectory() as w:
            os.makedirs(os.path.join(w, "production")); open(os.path.join(w, "production", "manifest.json"), "w").write("[]")
            with self.assertRaises((OSError, ValueError, KeyError)):
                P.read_image(os.path.join(w, "production"), "amd64")

    def test_manifest_finds_the_production_layout_and_reads_it_with_skopeo_oci(self):
        with tempfile.TemporaryDirectory() as w:
            lay = os.path.join(w, "images", "production"); image_layout(lay)
            with mock.patch.object(M, "_skopeo", return_value=True) as sk:
                got, why = M._archives(w, "", os.path.join(w, "c.oci"), os.path.join(w, "c.tar"))
            self.assertIsNone(why)
            self.assertEqual(got, "production")
            self.assertEqual(sk.call_args_list[0][0][0], "oci:" + lay)

    def test_manifest_without_a_production_layout_fails_closed(self):
        with tempfile.TemporaryDirectory() as w:
            open(os.path.join(w, "production.oci"), "w").write("x"); open(os.path.join(w, "production.tar"), "w").write("x")
            os.makedirs(os.path.join(w, "images", "production")); open(os.path.join(w, "images", "production", "manifest.json"), "w").write("[]")
            got, why = M._archives(w, "", os.path.join(w, "c.oci"), os.path.join(w, "c.tar"))
            self.assertIsNone(got)
            self.assertIn("OCI layout", why)


if __name__ == "__main__":
    unittest.main()
