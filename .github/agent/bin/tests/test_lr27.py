"""LR-27 (a), (b), (d): small contained defects the coverage work found (handoff 0007 sweep).
(c) is covered in test_cov_decisions.ClassifyManifestValidation; (e) is not a contained fix."""
import importlib.util, json, os, shutil, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.dirname(HERE)
sys.path.insert(0, BIN)
from auditorlib import vex  # noqa: E402


def _load(fname, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BIN, fname))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


M = _load("auditor-manifest.py", "auditor_manifest_lr27")
P = _load("auditor-poam.py", "auditor_poam_lr27")


class NormRef(unittest.TestCase):
    """(a) a registry with a port keeps its path; only the image's own tag is dropped."""
    def test_port_registry_keeps_path(self):
        self.assertEqual(M._norm_ref("localhost:5000/team/img:1.0@sha256:X"), "localhost:5000/team/img@sha256:X")
        self.assertEqual(M._norm_ref("localhost:5000/img@sha256:X"), "localhost:5000/img@sha256:X")

    def test_tag_dropped_and_plain_refs_unchanged(self):
        self.assertEqual(M._norm_ref("debian:12.0@sha256:X"), "debian@sha256:X")
        self.assertEqual(M._norm_ref("ghcr.io/o/i:t@sha256:X"), "ghcr.io/o/i@sha256:X")
        self.assertEqual(M._norm_ref("debian:12.0"), "debian:12.0")


class RemoveIgnores(unittest.TestCase):
    """(b) a JSON file that is not an object in the suppression dir is not an ignore — no crash,
    and the real per-finding ignore beside it is still removed."""
    def test_array_json_is_skipped(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "list.json"), "w") as fh:
            json.dump([1, 2], fh)
        with open(os.path.join(d, "ig.json"), "w") as fh:
            json.dump({"id": "CVE-1"}, fh)
        removed = P._remove_ignores(d, {"CVE-1"})
        self.assertEqual([os.path.basename(x) for x in removed], ["ig.json"])
        self.assertTrue(os.path.exists(os.path.join(d, "list.json")))


class SchemaLocation(unittest.TestCase):
    """(d) production reads the OpenVEX schema from beside its code, never from test fixtures."""
    def test_schema_beside_the_code(self):
        self.assertEqual(os.path.dirname(os.path.abspath(vex.SCHEMA)), os.path.join(BIN, "auditorlib"))
        self.assertTrue(os.path.exists(vex.SCHEMA))
        self.assertNotIn("fixtures", vex.SCHEMA)


if __name__ == "__main__":
    unittest.main(verbosity=2)
