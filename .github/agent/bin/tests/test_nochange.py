"""REQ-AUD-3 AC3 (rc-5b item 10): the daily auditor makes zero model calls on a no-change day.

The pieces that decide it, tested as pure functions: the one finding-set hash (everything a verdict depends on), the
per-call key, and the validator of yesterday's state file, which must never let a missing, malformed, oversized,
forged or different-hash file change a run (anything unusable = today's behaviour, model calls).
"""
import json, os, sys, tempfile, unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import nochange as N  # noqa: E402

H = "a" * 64
K1 = "b" * 64
K2 = "c" * 64


def groups():
    return {"CVE-2024-0001": {"aliases": {"CVE-2024-0001", "GHSA-xxxx"},
                              "findings": [{"scanner": "grype", "purl": "pkg:apk/wolfi/zlib@1.3.1-r0", "package": "zlib",
                                            "installed": "1.3.1-r0", "fixed": None, "severity": "high",
                                            "finding_id": "CVE-2024-0001", "aliases": ["GHSA-xxxx"]},
                                           {"scanner": "scout", "purl": "pkg:apk/wolfi/zlib@1.3.1-r0", "package": "zlib",
                                            "installed": "1.3.1-r0", "fixed": None, "severity": "high",
                                            "finding_id": "CVE-2024-0001", "aliases": []}]}}


def good():
    return {"schema": N.SCHEMA, "run_date": "2026-10-23", "finding_set_hash": H,
            "verdicts": {K1: "false_positive"}, "pullability": {K2: {"pullable": False, "lift_trigger": "base >= 3"}},
            "narrative": {"key": K1, "text": "Nothing changed.", "date": "2026-10-22"}}


class Hashes(unittest.TestCase):
    def test_finding_set_hash_is_64_hex_and_stable_across_ordering(self):
        a = N.finding_set_hash(groups(), {"image": "sha256:1"})
        self.assertRegex(a, r"^[0-9a-f]{64}$")
        g = groups(); g["CVE-2024-0001"]["findings"].reverse(); g["CVE-2024-0001"]["aliases"] = {"GHSA-xxxx", "CVE-2024-0001"}
        self.assertEqual(a, N.finding_set_hash(g, {"image": "sha256:1"}))

    def test_every_dependency_of_a_verdict_changes_the_hash(self):
        base = N.finding_set_hash(groups(), {"image": "sha256:1"})
        seen = {base}
        for field, value in (("package", "zlib2"), ("installed", "1.3.2-r0"), ("fixed", "1.3.3-r0"), ("severity", "critical"),
                             ("scanner", "grype2"), ("purl", "pkg:apk/wolfi/zlib@9"), ("aliases", ["GHSA-other"])):
            g = groups(); g["CVE-2024-0001"]["findings"][0][field] = value
            h = N.finding_set_hash(g, {"image": "sha256:1"})
            self.assertNotIn(h, seen, field); seen.add(h)
        g = groups(); g["CVE-2024-0001"]["aliases"].add("CVE-2024-0002")
        self.assertNotIn(N.finding_set_hash(g, {"image": "sha256:1"}), seen)
        seen.add(N.finding_set_hash(g, {"image": "sha256:1"}))
        g = groups(); g["CVE-2024-0001"]["findings"].append({"scanner": "inspector", "purl": "p"})
        self.assertNotIn(N.finding_set_hash(g, {"image": "sha256:1"}), seen)
        g = groups(); g["CVE-2024-0009"] = g.pop("CVE-2024-0001")
        self.assertNotIn(N.finding_set_hash(g, {"image": "sha256:1"}), seen)
        self.assertNotEqual(base, N.finding_set_hash(groups(), {"image": "sha256:2"}))
        self.assertNotEqual(base, N.finding_set_hash(groups(), {"image": "sha256:1", "knowledge": "x"}))

    def test_call_key_depends_on_kind_and_every_context_value(self):
        ctx = {"finding_id": "CVE-1", "installed_version": "1", "knowledge": "k"}
        k = N.call_key("adjudicate", ctx)
        self.assertRegex(k, r"^[0-9a-f]{64}$")
        self.assertEqual(k, N.call_key("adjudicate", dict(reversed(list(ctx.items())))))
        self.assertNotEqual(k, N.call_key("pullability", ctx))
        self.assertNotEqual(k, N.call_key("adjudicate", dict(ctx, installed_version="2")))
        self.assertNotEqual(k, N.call_key("adjudicate", dict(ctx, knowledge="k2")))
        self.assertNotEqual(k, N.call_key("adjudicate", dict(ctx, extra=1)))


class Load(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def write(self, doc, raw=None):
        p = os.path.join(self.d, "auditor-state.json")
        with open(p, "w") as fh:
            fh.write(raw if raw is not None else json.dumps(doc))
        return p

    def test_a_valid_state_is_returned(self):
        self.assertEqual(N.load(self.write(good())), good())

    def test_unusable_inputs_are_none_never_an_exception(self):
        self.assertIsNone(N.load(None))
        self.assertIsNone(N.load(os.path.join(self.d, "missing.json")))
        self.assertIsNone(N.load(self.d))                              # a directory
        link = os.path.join(self.d, "link.json"); os.symlink(self.write(good()), link)
        self.assertIsNone(N.load(link))                                # a link is not a regular file
        self.assertIsNone(N.load(self.write(None, raw="")))            # empty
        self.assertIsNone(N.load(self.write(None, raw="{not json")))
        self.assertIsNone(N.load(self.write(None, raw="[1]")))
        self.assertIsNone(N.load(self.write(None, raw='{"a": NaN}')))
        self.assertIsNone(N.load(self.write(None, raw=b"\xff\xfe".decode("latin-1"))))
        self.assertIsNone(N.load(self.write(None, raw=json.dumps(good()) + " " * N.MAX_BYTES)))     # over the size bound

    def test_every_malformed_field_is_refused(self):
        def bad(mut):
            d = good(); mut(d); return N.load(self.write(d))
        self.assertIsNone(bad(lambda d: d.update(schema="other")))
        self.assertIsNone(bad(lambda d: d.update(extra=1)))
        self.assertIsNone(bad(lambda d: d.pop("verdicts")))
        self.assertIsNone(bad(lambda d: d.update(finding_set_hash="XYZ")))
        self.assertIsNone(bad(lambda d: d.update(finding_set_hash=H.upper())))
        self.assertIsNone(bad(lambda d: d.update(run_date="yesterday")))
        self.assertIsNone(bad(lambda d: d.update(run_date=20261023)))
        self.assertIsNone(bad(lambda d: d.update(verdicts=[])))
        self.assertIsNone(bad(lambda d: d.update(verdicts={"nothex": "false_positive"})))
        self.assertIsNone(bad(lambda d: d.update(verdicts={K1: "burn_it_down"})))
        self.assertIsNone(bad(lambda d: d.update(verdicts={K1: 1})))
        self.assertIsNone(bad(lambda d: d.update(pullability=[])))
        self.assertIsNone(bad(lambda d: d.update(pullability={"nothex": {}})))
        self.assertIsNone(bad(lambda d: d.update(pullability={K2: "x"})))
        self.assertIsNone(bad(lambda d: d.update(pullability={K2: {"unknown_key": 1}})))
        self.assertIsNone(bad(lambda d: d.update(pullability={K2: {"pullable": {"nested": 1}}})))
        self.assertIsNone(bad(lambda d: d.update(pullability={K2: {"evidence": "x" * 5000}})))
        self.assertIsNone(bad(lambda d: d.update(narrative="text")))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": "nothex", "text": "t", "date": "2026-10-22"})))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": K1, "text": "", "date": "2026-10-22"})))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": K1, "text": "x" * 20001, "date": "2026-10-22"})))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": K1, "text": "t", "date": "soon"})))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": K1, "text": "t", "date": "2026-10-22", "x": 1})))

    def test_no_narrative_and_no_verdicts_is_a_valid_state(self):
        d = good(); d["narrative"] = None; d["verdicts"] = {}; d["pullability"] = {}
        self.assertEqual(N.load(self.write(d)), d)


class Use(unittest.TestCase):
    def test_a_state_is_used_only_on_an_exact_hash_match(self):
        s = good()
        self.assertIs(N.matching(s, H), s)
        self.assertIsNone(N.matching(s, "d" * 64))
        self.assertIsNone(N.matching(None, H))

    def test_lookups_answer_only_what_was_stored(self):
        s = good()
        self.assertEqual(N.verdict(s, K1), "false_positive")
        self.assertIsNone(N.verdict(s, K2)); self.assertIsNone(N.verdict(None, K1))
        self.assertEqual(N.pullability(s, K2), {"pullable": False, "lift_trigger": "base >= 3"})
        self.assertIsNone(N.pullability(s, K1)); self.assertIsNone(N.pullability(None, K2))
        self.assertEqual(N.narrative(s, K1), ("Nothing changed.", "2026-10-22"))
        self.assertIsNone(N.narrative(s, K2)); self.assertIsNone(N.narrative(None, K1))
        self.assertIsNone(N.narrative({"narrative": None}, K1))

    def test_a_returned_pullability_is_a_copy(self):
        s = good(); got = N.pullability(s, K2); got["pullable"] = True
        self.assertIs(N.pullability(s, K2)["pullable"], False)

    def test_dump_round_trips_through_load(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "s.json")
        doc = N.dump("2026-10-24", H, {K1: "real_fixable"}, {K2: {"pullable": True}}, {"key": K1, "text": "t", "date": "2026-10-24"})
        with open(p, "w") as fh:
            json.dump(doc, fh)
        self.assertEqual(N.load(p), doc)
        self.assertIsNone(N.dump("2026-10-24", H, {}, {}, None)["narrative"])


if __name__ == "__main__":
    unittest.main()
