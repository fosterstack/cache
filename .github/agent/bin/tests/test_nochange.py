"""REQ-AUD-3 AC3 (rc-5b item 10): the daily auditor makes zero model calls on a no-change day.

The pieces that decide it, tested as pure functions: the one finding-set hash (everything a verdict depends on), the
per-call key, and the validator of yesterday's state file, which must never let a missing, malformed, oversized,
forged or different-hash file change a run (anything unusable = today's behaviour, model calls).
"""
import json, os, sys, tempfile, unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import nochange as N  # noqa: E402
from auditorlib import parsers as PARS  # noqa: E402

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
            "narrative": {"key": K1, "text": "Nothing changed.", "date": "2026-10-22"}, "unsettled": {}}


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
        for field, value in (("pullable", "yes"), ("pullable", 1), ("lift_trigger", 1), ("lift_trigger", True), ("hold", "arbitrary_disposition"),
                             ("hold", 3), ("bump_attempted", "no"), ("component_fixed", ["1"]), ("evidence", ["x"]),
                             ("evidence", {"k": {"deep": 1}}), ("evidence", {str(i): "v" for i in range(40)}),
                             ("evidence", {"k": "x" * 5000})):
            self.assertIsNone(bad(lambda d, f=field, v=value: d.update(pullability={K2: {f: v}})), (field, value))
        self.assertIsNone(bad(lambda d: d.update(narrative="text")))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": "nothex", "text": "t", "date": "2026-10-22"})))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": K1, "text": "", "date": "2026-10-22"})))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": K1, "text": "x" * 20001, "date": "2026-10-22"})))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": K1, "text": "t", "date": "soon"})))
        self.assertIsNone(bad(lambda d: d.update(narrative={"key": K1, "text": "t", "date": "2026-10-22", "x": 1})))

    def test_the_known_good_pullability_shapes_are_valid(self):
        for rec in ({"pullable": True}, {"pullable": False, "hold": "policy-held", "lift_trigger": "base >= 3"},
                    {"hold": None, "evidence": None}, {"evidence": "text"}, {"evidence": {"how": "pin", "carrier": "nodejs", "n": 2, "ok": True}},
                    {"pullable": False, "lift_trigger": {"carrier": "nodejs", "min_version": "20.2",
                        "component": "libz",
                                                         # rc-5b R1: the structured trigger
                                                         "component_min_version": "1.1"}},
                    {"bump_attempted": False, "bump_result": "none", "component_fixed": "1.2", "repo_version": "1.2",
                     "base_release": "debian 12.6", "candidate_release": None}, {}):
            d = good(); d["pullability"] = {K2: rec}
            self.assertEqual(N.load(self.write(d)), d, rec)

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

    def test_pull_record_keeps_a_valid_answer_whole_and_refuses_a_lossy_one(self):
        ans = {"refused": False, "token_usage": 9, "pullable": False, "hold": "upstream-held", "lift_trigger": "n >= 2",
               "evidence": {"how": "static", "carrier": "nodejs"}, "unread": "dropped"}
        self.assertEqual(N.pull_record(ans), {"pullable": False, "hold": "upstream-held", "lift_trigger": "n >= 2",
                                             "evidence": {"how": "static", "carrier": "nodejs"}})
        self.assertEqual(N.pull_record({"refused": False}), {})
        for key, value in (("lift_trigger", "x" * 5000), ("hold", "arbitrary_disposition"), ("pullable", "maybe"),
                           ("evidence", {"k": {"deep": 1}}), ("lift_trigger", 12)):
            self.assertIsNone(N.pull_record({"pullable": False, key: value}), (key, value))

    def test_an_incomplete_run_keeps_nothing_reusable(self):
        v = {"a" * 64: "false_positive"}; p = {"b" * 64: {"pullable": False}}; n = {"key": "c" * 64, "text": "t", "date": "2026-10-24"}
        self.assertEqual(N.settle(v, p, n, False), (v, p, n))
        self.assertEqual(N.settle(v, p, n, True), ({}, {}, None))

    def test_dump_round_trips_through_load(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "s.json")
        doc = N.dump("2026-10-24", H, {K1: "real_fixable"}, {K2: {"pullable": True}}, {"key": K1, "text": "t", "date": "2026-10-24"}, {})
        with open(p, "w") as fh:
            json.dump(doc, fh)
        self.assertEqual(N.load(p), doc)
        self.assertIsNone(N.dump("2026-10-24", H, {}, {}, None, {})["narrative"])


class Unsettled(unittest.TestCase):
    """REQ-AUD-9 AC3, "a five-iteration stop" (register row 38, the Sep 16 continuous-scanning rule "a five-iteration loop"; advisor reading, Oct 24):
    five CONSECUTIVE auditor runs in which the same finding is still unsettled. The counts ride in the auditor state (the artifact of the no-change day),
    a missing state restarts them and says so, a corrupt state stops the run."""

    def write(self, doc):
        d = tempfile.mkdtemp(); p = os.path.join(d, "auditor-state.json")
        with open(p, "w") as fh:
            fh.write(doc if isinstance(doc, str) else json.dumps(doc))
        return p

    def state(self, unsettled):
        d = good(); d["unsettled"] = unsettled; return d

    def test_no_file_is_missing_not_an_error(self):
        self.assertEqual(N.load_unsettled(None, "2026-10-23"), ("missing", {}))
        self.assertEqual(N.load_unsettled(os.path.join(tempfile.mkdtemp(), "nope.json"), "2026-10-23"), ("missing", {}))

    def test_a_state_written_before_the_counts_existed_is_missing(self):
        d = good(); del d["unsettled"]
        self.assertEqual(N.load_unsettled(self.write(d), "2026-10-23"), ("missing", {}))

    def test_a_valid_state_returns_its_counts(self):
        c = {"CVE-2024-0001": {"runs": 3, "last": "2026-10-22"}}
        self.assertEqual(N.load_unsettled(self.write(self.state(c)), "2026-10-23"), ("ok", c))
        self.assertEqual(N.load_unsettled(self.write(self.state({})), "2026-10-23"), ("ok", {}))

    def test_a_file_that_is_not_an_auditor_state_is_missing_like_the_no_change_day_ignores_it(self):
        ok = {"CVE-2024-0001": {"runs": 3, "last": "2026-10-22"}}
        for doc in ("{", "[]", "null", json.dumps(dict(self.state(ok), schema="other")), "{\"a\": NaN}", " " * (N.MAX_BYTES + 1)):
            self.assertEqual(N.load_unsettled(self.write(doc), "2026-10-23"), ("missing", {}), doc[:40])
        d = tempfile.mkdtemp()
        self.assertEqual(N.load_unsettled(d, "2026-10-23"), ("missing", {}))
        real = self.write(self.state({})); link = os.path.join(d, "l.json"); os.symlink(real, link)
        self.assertEqual(N.load_unsettled(link, "2026-10-23"), ("missing", {}))

    def test_an_auditor_state_with_untrustworthy_counts_raises(self):
        ok = {"CVE-2024-0001": {"runs": 3, "last": "2026-10-22"}}
        bad = [json.dumps(self.state([])), json.dumps(self.state({"bad id": ok["CVE-2024-0001"]})), json.dumps(self.state({"": ok["CVE-2024-0001"]})),
               json.dumps(self.state({"CVE-1": {"runs": 0, "last": "2026-10-22"}})), json.dumps(self.state({"CVE-1": {"runs": True, "last": "2026-10-22"}})),
               json.dumps(self.state({"CVE-1": {"runs": 10 ** 6, "last": "2026-10-22"}})), json.dumps(self.state({"CVE-1": {"runs": 1, "last": "yesterday"}})),
               json.dumps(self.state({"CVE-1": {"runs": 1}})), json.dumps(self.state({"CVE-1": {"runs": 1, "last": "2026-10-22", "x": 1}})),
               json.dumps(self.state({"CVE-%d" % i: {"runs": 1, "last": "2026-10-22"} for i in range(N.UNSETTLED_MAX + 1)}))]
        for doc in bad:
            with self.assertRaises(N.CounterInvalid, msg=doc[:60]):
                N.load_unsettled(self.write(doc), "2026-10-23")

    def test_advance_counts_consecutive_runs_and_resets_a_settled_finding(self):
        prev = {"CVE-A": {"runs": 4, "last": "2026-10-22"}, "CVE-B": {"runs": 2, "last": "2026-10-22"}}
        new = N.advance(prev, {"CVE-A", "CVE-C"}, "2026-10-23")
        self.assertEqual(new, {"CVE-A": {"runs": 5, "last": "2026-10-23"}, "CVE-C": {"runs": 1, "last": "2026-10-23"}})   # CVE-B settled: gone

    def test_a_second_run_on_the_same_day_does_not_count_twice(self):
        prev = {"CVE-A": {"runs": 4, "last": "2026-10-23"}}
        self.assertEqual(N.advance(prev, {"CVE-A"}, "2026-10-23"), {"CVE-A": {"runs": 4, "last": "2026-10-23"}})

    def test_a_count_from_the_future_is_corrupt(self):
        c = {"CVE-A": {"runs": 4, "last": "2026-10-24"}}
        with self.assertRaises(N.CounterInvalid):
            N.load_unsettled(self.write(self.state(c)), "2026-10-23")
        self.assertEqual(N.load_unsettled(self.write(self.state(c)), "2026-10-24"), ("ok", c))        # the same day is not the future

    def test_a_state_the_no_change_day_would_reject_does_not_carry_its_counts(self):
        ok = {"CVE-A": {"runs": 4, "last": "2026-10-22"}}
        for k, v in (("run_date", "not-a-date"), ("run_date", "2026-02-30"), ("finding_set_hash", "x"), ("verdicts", {"nothex": "false_positive"}), ("pullability", []), ("narrative", 5)):
            d = self.state(ok); d[k] = v
            self.assertEqual(N.load_unsettled(self.write(d), "2026-10-23"), ("missing", {}), k)
        d = self.state(ok); d["extra"] = 1
        self.assertEqual(N.load_unsettled(self.write(d), "2026-10-23"), ("missing", {}))

    def test_a_state_dated_after_today_is_corrupt(self):
        d = self.state({"CVE-A": {"runs": 4, "last": "2026-10-22"}}); d["run_date"] = "2026-10-24"
        with self.assertRaises(N.CounterInvalid):
            N.load_unsettled(self.write(d), "2026-10-23")

    def test_a_date_that_is_not_on_the_calendar_is_corrupt(self):
        for d in ("2026-00-00", "2026-02-30", "2026-13-01"):
            with self.assertRaises(N.CounterInvalid, msg=d):
                N.load_unsettled(self.write(self.state({"CVE-A": {"runs": 4, "last": d}})), "2026-12-31")

    def test_a_count_saturates_at_the_most_the_state_accepts(self):
        new = N.advance({"CVE-A": {"runs": N.RUNS_MAX, "last": "2026-10-22"}}, {"CVE-A"}, "2026-10-23")
        self.assertEqual(new["CVE-A"]["runs"], N.RUNS_MAX)
        doc = N.dump("2026-10-23", H, {}, {}, None, new)
        self.assertEqual(N.load_unsettled(self.write(doc), "2026-10-23"), ("ok", new))            # written, then read back

    def test_every_id_the_verdict_parser_accepts_is_one_the_counter_keeps(self):
        for i in ("?", "CVE-2024-0001", "GHSA-xxxx-yyyy-zzzz", "DEBIAN-CVE-2024-1", "GO-2024-1", "a+b", "x" * 200):
            self.assertTrue(PARS._ID.fullmatch(i), i)
            c = {i: {"runs": 2, "last": "2026-10-22"}}
            self.assertEqual(N.load_unsettled(self.write(self.state(c)), "2026-10-23"), ("ok", c), i)
        for i in ("x" * 201, "", "has space", "a`b"):
            self.assertFalse(PARS._ID.fullmatch(i), i)

    def test_more_unsettled_findings_than_the_state_can_hold_is_corrupt(self):
        ids = {"CVE-%d" % i for i in range(N.UNSETTLED_MAX + 1)}
        with self.assertRaises(N.CounterInvalid):
            N.advance({}, ids, "2026-10-23")

    def test_at_limit_names_findings_at_or_above_the_limit_sorted(self):
        c = {"CVE-B": {"runs": 5, "last": "d"}, "CVE-A": {"runs": 7, "last": "d"}, "CVE-C": {"runs": 4, "last": "d"}}
        self.assertEqual(N.at_limit(c, 5), [("CVE-A", 7), ("CVE-B", 5)])
        self.assertEqual(N.at_limit({}, 5), [])

    def test_the_counts_are_part_of_the_state_the_run_writes_and_the_loader_reads(self):
        c = {"CVE-2024-0001": {"runs": 2, "last": "2026-10-22"}}
        doc = N.dump("2026-10-23", H, {}, {}, None, c)
        self.assertEqual(doc["unsettled"], c)
        self.assertIsNotNone(N.load(self.write(doc)))
        self.assertEqual(N.load_unsettled(self.write(doc), "2026-10-23"), ("ok", c))


if __name__ == "__main__":
    unittest.main()
