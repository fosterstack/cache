"""The strict .snyk reader (auditorlib/snykpolicy.py) and the consistency check that uses it
(REQ-AUD-18 AC2: the auditor reads its own .snyk with no YAML library at runtime). Every accepted
shape is checked against the vendored PyYAML (string-only BaseLoader) as the reference parser;
every rejected shape must raise, and consistency must report it — fail closed, never "no ignores"."""
import importlib.util, json, os, shutil, sys, tempfile, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.dirname(HERE)
AGENT = os.path.dirname(BIN)
sys.path.insert(0, BIN)
sys.path.insert(0, os.path.join(AGENT, "fixtures", "testlib"))
from auditorlib import snykpolicy, cli  # noqa: E402
import pyyaml as yaml  # noqa: E402  (test-only reference parser)


def _load(fname, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BIN, fname))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


R = _load("auditor-run.py", "auditor_run_snyk")
C = _load("auditor-consistency.py", "auditor_consistency_snyk")


def reference(text):
    return (yaml.load(text, Loader=yaml.BaseLoader) or {}).get("ignore") or {}


class StrictReader(unittest.TestCase):
    def assert_agrees(self, text):
        self.assertEqual(snykpolicy.load(text)["ignore"], reference(text))

    def test_fixture_policy_agrees_with_reference(self):
        with open(os.path.join(AGENT, "fixtures", "suppression", "set-01", ".snyk")) as fh:
            text = fh.read()
        self.assert_agrees(text)
        got = snykpolicy.load(text)["ignore"]
        self.assertEqual(sorted(got), ["SNYK-DEBIAN12-APT-1", "SNYK-DEBIAN12-COREUTILS-2"])
        self.assertEqual(got["SNYK-DEBIAN12-COREUTILS-2"], [{"*": {"reason": "muted",
                                                                   "expires": "2026-10-01T00:00:00.000Z"}}])

    def test_writer_output_agrees_with_reference(self):
        stmts = [
            {"@id": "https://x/vex#stmt-cve-2099-1", "status": "not_affected",
             "vulnerability": {"name": "CVE-2099-1"},
             "products": [{"@id": "p", "subcomponents": [{"@id": "pkg:deb/debian/zlib@1"}]}]},
            {"@id": "https://x/vex#stmt-cve-2099-1~b", "status": "affected",
             "vulnerability": {"name": "CVE-2099-1"},
             "products": [{"@id": "p", "subcomponents": [{"@id": "pkg:deb/debian/openssl@3"}]}]},
            {"@id": "https://x/vex#stmt-cve-2099-2", "status": "not_affected",
             "vulnerability": {"name": "CVE-2099-2"}, "products": [{"@id": "p"}]},
        ]
        expiry = {("CVE-2099-1", "pkg:deb/debian/openssl@3"): "2026-12-01"}   # a date, as every real source gives
        snyk_text, _ = R._ignores_from_statements(stmts, expiry)
        self.assert_agrees(snyk_text)
        got = snykpolicy.load(snyk_text)["ignore"]
        self.assertEqual(len(got["CVE-2099-1"]), 2)             # one selector per package
        self.assertEqual(list(got["CVE-2099-2"][0]), ["*"])       # no package -> CVE-wide
        self.assertIn("stmt-cve-2099-1", json.dumps(got["CVE-2099-1"]))

    def test_empty_and_accepted_top_level_forms(self):
        for text in ("version: v1.5.0\nignore:\n", "version: v1.5.0\nignore: {}\npatch: {}\n",
                     "# comment\n\nversion: v1\nignore:\n  ID-1:\n    - 'pkg:x@1':\n        reason: 'r'\n"
                     "        expires: 2026-10-01T00:00:00.000Z\n        vex: 'https://x#stmt-id-1'\n"):
            self.assert_agrees(text)

    def test_anything_outside_the_shape_raises(self):
        # every YAML feature the writer never emits is REFUSED, not read as raw text with a meaning
        # YAML would not give it (Codex AC2 round-5 blocker: a comment/anchor "citing" a statement)
        body = "version: v1\nignore:\n  ID-1:\n    - '*':\n        vex: %s\n"
        bad = {
            "ignore: {ID: []}\n": "must open a block",
            "patch:\n  x: y\n": "only an empty",
            "version:\n": "version must be a plain token",
            "version: 'v1' # c\n": "version must be a plain token",
            "version: v1\nexclude:\n  - x\n": "unexpected content",
            "version: v1\nignore:\n  ID-1:\n  ID-1:\n": "duplicate ignore id",
            "version: v1\nignore:\n    - '*':\n": "not in the auditor's ignore shape",
            "version: v1\nignore:\n  ID-1:\n        reason: x\n": "not in the auditor's ignore shape",
            "version: v1\nignore:\n  ID-1: [a, b]\n": "not in the auditor's ignore shape",
            "version: v1\nignore:\n  &a ID-1:\n": "not in the auditor's ignore shape",
            "version: v1\nignore:\n  ID-1:\n    - pkg:x@1:\n": "not in the auditor's ignore shape",
            "version: v1\nignore:\n  ID-1:\n    - \"pkg:x\":\n": "not in the auditor's ignore shape",
            body % "none # previously stmt-cve-2099-1234": "not in the auditor's ignore shape",
            body % "&stmt-unused none": "not in the auditor's ignore shape",
            body % "'https://x#stmt-cve-1": "not in the auditor's ignore shape",
            body % '"https://x#\\x73tmt-cve-1"': "not in the auditor's ignore shape",
            body % "'a' 'b'": "not in the auditor's ignore shape",
            body % "!!str x": "not in the auditor's ignore shape",
            # any plain value other than a timestamp: a trailing colon is invalid YAML (Codex AC2
            # round-6 blocker), and a bare word has YAML semantics this reader will not reproduce
            body % "stmt-cve-2011-3374:": "not in the auditor's ignore shape",
            body % "none": "not in the auditor's ignore shape",
            body % "2026-10-01T00:00:00.000Z:": "not in the auditor's ignore shape",
            "version: v1:\n": "version must be a plain token",
            "version: v1\nignore:\n  CVE-1::\n": "not in the auditor's ignore shape",
            "  ID-1:\n": "unexpected content",
        }
        for text, why in bad.items():
            with self.assertRaises(ValueError, msg=text) as cm:
                snykpolicy.load(text)
            self.assertIn(why, str(cm.exception), text)


class ConsistencyReadsSnykStrictly(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)
        self.man = os.path.join(self.d, "manifest.json")
        with open(self.man, "w") as fh:
            json.dump({"scanner_reports": {}}, fh)

    def run_check(self, snyk_text):
        with open(os.path.join(self.d, ".snyk"), "w") as fh:
            fh.write(snyk_text)
        out = os.path.join(self.d, "c.json")
        with mock.patch.object(cli, "ARGS", ["--suppression-dir", self.d, "--live-findings", self.man,
                                             "--out", out]):
            C.main()
        with open(out) as fh:
            return json.load(fh)

    def test_citing_ignore_is_consistent_and_uncited_is_flagged(self):
        ok = self.run_check("version: v1\nignore:\n  CVE-1:\n    - '*':\n        reason: 'x; governed by "
                            "https://x/vex#stmt-cve-1'\n        vex: 'https://x/vex#stmt-cve-1'\n")
        self.assertEqual(ok, {"consistent": True, "problems": []})
        bad = self.run_check("version: v1\nignore:\n  CVE-2:\n    - '*':\n        reason: 'muted'\n")
        self.assertEqual(bad["problems"], [{"type": "tool_only_ignore", "id": "CVE-2"}])

    def test_unparseable_policy_fails_closed(self):
        res = self.run_check("version: v1\nignore: {CVE-3: [{'*': {reason: muted}}]}\n")
        self.assertFalse(res["consistent"])
        self.assertEqual([p["type"] for p in res["problems"]], ["consistency-check-unparseable-snyk"])
        self.assertIn("must open a block", res["problems"][0]["detail"])

    def test_commented_citation_is_never_consistent(self):
        # YAML reads `vex: none # ... stmt-...` as "none" — uncited. The old PyYAML path flagged
        # it; the strict reader must never call it consistent (Codex AC2 round-5 blocker).
        res = self.run_check("version: v1\nignore:\n  CVE-4:\n    - '*':\n        reason: 'muted'\n"
                             "        vex: none # previously stmt-cve-2099-1234\n")
        self.assertFalse(res["consistent"])
        self.assertEqual([p["type"] for p in res["problems"]], ["consistency-check-unparseable-snyk"])

    def test_consistency_imports_no_yaml_library(self):
        with open(os.path.join(BIN, "auditor-consistency.py")) as fh:
            src = fh.read()
        self.assertNotIn("pyyaml", src); self.assertNotIn("fixtures", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
