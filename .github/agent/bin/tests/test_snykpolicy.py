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

    def test_empty_policy_is_the_writers(self):
        text, _ = R._ignores_from_statements([], {})
        self.assertEqual(text, "version: v1.5.0\nignore:\n")
        self.assert_agrees(text)
        self.assertEqual(snykpolicy.load(text)["ignore"], {})

    def test_anything_but_the_writers_canonical_bytes_raises(self):
        # every form a review round found YAML reads differently (or rejects) — and every YAML
        # feature the writer never emits — is REFUSED, never given a meaning (rounds 5-7)
        good = "version: v1.5.0\nignore:\n  CVE-1:\n    - '*':\n        reason: 'r'\n        vex: 'x#stmt-cve-1'\n"
        self.assert_agrees(good)
        body = "version: v1.5.0\nignore:\n  CVE-1:\n    - '*':\n        vex: %s\n"
        bad = [
            "version: v1.5.0\nignore: {}\n", "version: v1.5.0\nignore:\npatch: {}\n",
            "ignore: {ID: []}\n", "version: -\nignore:\n", "version: v1\nversion: v2\nignore:\n",
            "# c\n" + good, good + "\n", good + "# c\n", good.replace("\n", "\r\n"), good[:-1],
            "\ufeff" + good, good.replace("  CVE-1:", "\tCVE-1:"), "---\n" + good,
            good + "ignore:\n", good + "  CVE-1:\n    - '*':\n        vex: 'y'\n",
            "version: v1.5.0\nignore:\n  CVE-1:\n", "version: v1.5.0\nignore:\n  CVE-1:\n    - '*':\n",
            "version: v1.5.0\nignore:\n  CVE-1:\n    - '*':\n    - 'p':\n        vex: 'x'\n",
            "version: v1.5.0\nignore:\n  :\n    - '*':\n        vex: 'x'\n",
            "version: v1.5.0\nignore:\n  &a CVE-1:\n    - '*':\n        vex: 'x'\n",
            "version: v1.5.0\nignore:\n  CVE-1:\n    - pkg:x@1:\n        vex: 'x'\n",
            "version: v1.5.0\nignore:\n  CVE-1:\n    - \"pkg:x\":\n        vex: 'x'\n",
            "version: v1.5.0\nignore:\n  CVE-1:\n    - '%s':\n        vex: 'x'\n" % ("p" * 1023),
            body % "none # previously stmt-cve-2099-1234", body % "&stmt-unused none",
            body % "'https://x#stmt-cve-1", body % '"https://x#\\x73tmt-cve-1"', body % "'a' 'b'",
            body % "!!str x", body % "stmt-cve-2011-3374:", body % "none",
            body % "2026-10-01T00:00:00.000Z:", body % "2026-10-01T00:00:00.000Z ",
            body % "'a\x01b'", body % "'a\x85b'", body % "'a\ufffe'", body % "'it''s'",
            body % "'x'\n        vex: 'y'",
            "version: v1.5.0\nignore:\n  %s:\n    - '*':\n        vex: 'x'\n" % ("C" * 1025),  # over-long id
            body % "'2026-10-01T00:00:00.000Z'",   # line-valid, but the writer never quotes a timestamp
        ]
        for text in bad:
            with self.assertRaises(ValueError, msg=repr(text)):
                snykpolicy.load(text)

    def test_character_and_length_boundaries_are_yamls_own(self):
        # both directions, against PyYAML: the reader accepts a character / key length exactly
        # when YAML reads it to the same value — never what YAML rejects (U+FFFE, surrogates,
        # NEL folding), never refusing writer output YAML accepts (a 999-1022-char purl, LS/PS,
        # BOM, astral) (Codex AC2 round-8 blockers)
        def ours(t):
            try:
                return snykpolicy.load(t)["ignore"]
            except ValueError:
                return None
        def yamls(t):
            try:
                return reference(t)
            except Exception:
                return None
        # a character is accepted only if YAML reads it identically in EVERY context — bare and
        # between spaces (YAML 1.1 folds spaces around its line breaks NEL/LS/PS)
        value = "version: v1.5.0\nignore:\n  CVE-1:\n    - '*':\n        vex: 'a%sb a %s b'\n"
        points = list(range(0x3000)) + [0xd7ff, 0xd800, 0xdfff, 0xe000, 0xfeff, 0xfffd, 0xfffe,
                                        0xffff, 0x10000, 0x1f600, 0x10ffff]
        for cp in points:
            if cp == 0x27:                     # the quote itself: YAML's '' escape, never emitted
                continue
            t = value % (chr(cp), chr(cp))
            y = yamls(t)
            same = y is not None and y["CVE-1"][0]["*"]["vex"] == "a%sb a %s b" % (chr(cp), chr(cp))
            self.assertEqual(ours(t) is not None, same, hex(cp))
        for tpl in ("version: v1.5.0\nignore:\n  CVE-1:\n    - '%s':\n        vex: 'x'\n",
                    "version: v1.5.0\nignore:\n  %s:\n    - '*':\n        vex: 'x'\n",
                    "version: v1.5.0\nignore:\n  CVE-1:\n    - '*':\n        %s: 'x'\n"):
            for n in range(1015, 1032):
                t = tpl % ("a" * n)
                self.assertEqual(ours(t), yamls(t), (tpl[:40], n))
        ids = "version: v1.5.0\nignore:\n  %s:\n    - '*':\n        vex: 'x'\n"
        for i in ("RHSA-2024:1234", "GHSA-abcd-efgh-ijkl", "GO-2024-1234", "DLA-1234-1", "TEMP-0000000-ABC"):
            self.assertEqual(ours(ids % i), yamls(ids % i), i)
        long_purl = "pkg:deb/debian/coreutils@9.1-1?distro=" + "a" * 961          # 999 chars
        writer, _ = R._ignores_from_statements([{"@id": "https://x/vex#stmt-cve-1", "status": "affected",
            "vulnerability": {"name": "CVE-1"}, "products": [{"@id": "p", "subcomponents": [{"@id": long_purl}]}]}], {})
        self.assertEqual(ours(writer), yamls(writer))
        self.assertIsNotNone(ours(writer))

    def test_every_accepted_mutant_reads_the_same_in_yaml(self):
        # property: whatever the reader ACCEPTS, YAML reads to the same value. A deterministic
        # sweep of single-character edits of real writer output — a mutant the reader accepts
        # must parse identically under PyYAML (BaseLoader); anything else must raise.
        import random
        stmts = [{"@id": "https://x/vex#stmt-cve-2099-%d" % i, "status": "not_affected",
                  "vulnerability": {"name": "CVE-2099-%d" % i},
                  "products": [{"@id": "p", "subcomponents": [{"@id": "pkg:deb/debian/lib%d@1" % i}]}]}
                 for i in range(3)]
        base, _ = R._ignores_from_statements(stmts, {("CVE-2099-1", "pkg:deb/debian/lib1@1"): "2026-12-01"})
        rng = random.Random(1804)
        alphabet = " \t\n:'\"#&*!|>-{}[],?%@`\\~0aZ\x00\x85\u2028\ufeff"
        accepted = 0
        for _ in range(4000):
            i = rng.randrange(len(base)); op = rng.randrange(3); c = rng.choice(alphabet)
            mut = base[:i] + (c if op != 2 else "") + base[i + (op != 1):]
            try:
                got = snykpolicy.load(mut)["ignore"]
            except ValueError:
                continue
            accepted += 1
            self.assertEqual(got, reference(mut), repr(mut))
        self.assertGreater(accepted, 0)      # the sweep did reach accepted mutants


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
        self.assertIn("want `ignore:`", res["problems"][0]["detail"])

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
