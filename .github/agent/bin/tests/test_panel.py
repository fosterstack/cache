"""Proves (traced in the auditor's docs/scanner-panel-trace.md; REQ-AUD-18 AC1): REQ-SCAN-007-AC1, REQ-SCAN-008-AC1, REQ-SCAN-008-AC2, REQ-SCAN-008-AC4, REQ-SCAN-008-AC6, REQ-SCAN-008-AC7, REQ-SCAN-008-AC8, REQ-SCAN-008-AC9, REQ-SCAN-009-AC2, REQ-SCAN-009-AC3, REQ-SCAN-013-AC1, REQ-SCAN-013-AC3, REQ-SCAN-014-AC1, REQ-SCAN-014-AC4.

The scanner panel's audits in the daily auditor (scanner-panel rules 7-9, 8(c), 13, 14; owner Oct 2-3).

Offline: stand-in auditors play the two seats; the rescan's verdict.json and the evidence bundles are fixtures.
Every test asserts an effect on the judgment, the day's state, or the text that would be published.
"""
import copy, importlib.util, json, os, sys, unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), os.path.join(BIN, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


P = load("auditor-panel")

BUNDLE = ("image fips-arm64 (tzdata 2026c-0+deb13u1, reported by scout)\n" + P.EVIDENCE_MARK + "\n"
          "package database /var/lib/dpkg/status.d/tzdata:\nPackage: tzdata\nVersion: 2026c-0+deb13u1\n"
          "Status: install ok installed\n"
          "file: /usr/share/zoneinfo/tzdata.zi (version 2026a)\n"
          "go build info: no Go binary in the image records tzdata\n")
EV_REAL = "Package: tzdata Version: 2026c-0+deb13u1"
EV_FALSE = "file: /usr/share/zoneinfo/tzdata.zi (version 2026a)"


PURL = "pkg:deb/debian/tzdata@2026c-0%2Bdeb13u1?arch=all&distro=debian-13"


def finding(fid="CVE-2099-0002", pkg="tzdata", ver="2026c-0+deb13u1", img="fips-arm64", seen=("scout",), of=3,
            purls=(PURL,)):
    return {"image": img, "id": fid, "package": pkg, "version": ver, "seen_by": list(seen), "of": of,
            "unique": len(seen) == 1, "status": "unique" if len(seen) == 1 else "report", "purls": list(purls)}


def verdict(*fs):
    return {"findings": list(fs), "unique": [f for f in fs if f["unique"]]}


class Seat:
    """A stand-in auditor: answers per mode from a script, records every request it saw."""

    def __init__(self, answers):
        self.answers = answers      # mode -> answer, or mode -> list of answers (one per call)
        self.seen = []

    def __call__(self, req):
        self.seen.append(copy.deepcopy(req))
        a = self.answers.get(req["mode"])
        if isinstance(a, list):
            a = a.pop(0)
        if isinstance(a, Exception):
            raise a
        return copy.deepcopy(a)


def real(ev=EV_REAL, why="reads the dpkg status file"):
    return {"verdict": "real", "evidence": [ev], "why": why, "case": "the package database lists it"}


def false(ev=EV_FALSE):
    return {"verdict": "false", "evidence": [ev] if ev else [], "why": None, "case": "the installed data is not affected"}


def bundles(_f):
    return BUNDLE


SCORING = P.scoring_text()


class Profiles(unittest.TestCase):
    def test_validator_requires_finding_and_image_evidence(self):          # REQ-SCAN-007-AC1
        ok = {"scanner": "scout", "kind": "sees_alone", "match": {"package": "^tzdata$"}, "behavior": "b",
              "finding": "f", "evidence": "e"}
        self.assertEqual(P.validate_profiles({"entries": [ok]}), [])
        for broken in ({"finding": ""}, {"evidence": None}, {"scanner": "nope"}, {"kind": "guess"},
                       {"match": {"package": "("}}, {"match": {}}):
            e = dict(ok, **broken)
            self.assertTrue(P.validate_profiles({"entries": [e]}), broken)

    def test_committed_profiles_validate(self):
        path = os.path.join(BIN, "..", "..", "policy", "scanner-profiles.json")
        self.assertEqual(P.validate_profiles(json.load(open(path))), [])

    def test_only_sees_alone_entries_match(self):                           # REQ-SCAN-008-AC6
        prof = {"entries": [{"scanner": "scout", "kind": "sees_alone", "match": {"package": "^tzdata$"}},
                            {"scanner": "google", "kind": "blind_spot", "match": {"package": "^tzdata$"}}]}
        self.assertTrue(P.profile_match(prof, "scout", "tzdata"))
        self.assertIsNone(P.profile_match(prof, "google", "tzdata"))
        self.assertIsNone(P.profile_match(prof, "scout", "busybox"))


class Evidence(unittest.TestCase):
    def test_a_vote_counts_only_with_evidence_quoted_from_the_image(self):
        f = finding()
        self.assertEqual(P.vote(real(), BUNDLE, f), "real")
        self.assertEqual(P.vote(false(), BUNDLE, f), "false")
        self.assertIsNone(P.vote(real(ev="Package: busybox"), BUNDLE, f))     # not in the image
        self.assertIsNone(P.vote(real(ev="   "), BUNDLE, f))
        self.assertIsNone(P.vote(dict(real(), evidence=[]), BUNDLE, f))
        self.assertIsNone(P.vote(dict(real(), evidence=EV_REAL), BUNDLE, f))   # not a list
        self.assertIsNone(P.vote({"verdict": "maybe", "evidence": [EV_REAL]}, BUNDLE, f))
        self.assertIsNone(P.vote({"error": "timeout", "verdict": "real", "evidence": [EV_REAL]}, BUNDLE, f))  # AC4

    def test_short_quotes_are_not_evidence(self):
        self.assertIsNone(P.vote(real(ev="tz"), BUNDLE, finding()))

    def test_the_header_and_diagnostics_are_never_evidence(self):          # Codex r1 B1
        f = finding()
        header = "image fips-arm64 (tzdata 2026c-0+deb13u1, reported by scout)"
        self.assertIsNone(P.vote(real(ev=header), BUNDLE, f))
        self.assertIsNone(P.vote(false(ev=header), BUNDLE, f))
        unreadable = "image fips-arm64: the image could not be read; no evidence is available\n"
        self.assertIsNone(P.vote(real(ev="the image could not be read"), unreadable, f))
        self.assertIsNone(P.vote(false(ev="the image could not be read"), unreadable, f))
        self.assertIsNone(P.vote(real(ev=P.EVIDENCE_MARK), BUNDLE, f))

    def test_real_needs_the_package_at_its_version_and_false_needs_absence_or_another_version(self):
        f = finding()
        self.assertIsNone(P.vote(real(ev="Package: tzdata"), BUNDLE, f))                 # no version
        self.assertIsNone(P.vote(real(ev="Status: install ok installed"), BUNDLE, f))     # no package
        self.assertIsNone(P.vote(false(ev=EV_REAL), BUNDLE, f))                          # present at that version
        self.assertIsNone(P.vote(false(ev="Status: install ok installed"), BUNDLE, f))
        self.assertEqual(P.vote(false(ev="go build info: no Go binary in the image records tzdata"), BUNDLE, f), "false")
        self.assertIsNone(P.vote(real(ev="go build info: no Go binary in the image records tzdata"), BUNDLE, f))
        g = finding(pkg="golang.org/x/sys", ver="v0.47.0")
        gb = "h\n%s\ngo build info /usr/bin/cache: dep golang.org/x/sys v0.47.0 h1:abc\n" % P.EVIDENCE_MARK
        self.assertEqual(P.vote(real(ev="dep golang.org/x/sys v0.47.0"), gb, g), "real")


class OneAudit(unittest.TestCase):                                          # rule 8(a)
    PROF = {"entries": [{"scanner": "scout", "kind": "sees_alone", "match": {"package": "^tzdata$"},
                         "behavior": "b", "finding": "f", "evidence": "e"}]}

    def test_profile_match_takes_one_audit_by_the_primary_seat(self):      # REQ-SCAN-008-AC1, AC6
        a, b = Seat({"audit": real()}), Seat({"audit": false()})
        r = P.judge_unique(finding(), BUNDLE, self.PROF, {"A": a, "B": b}, "A", SCORING)
        self.assertEqual((r["status"], r["path"], len(r["audits"])), ("report", "a", 1))
        self.assertEqual(len(b.seen), 0)
        r = P.judge_unique(finding(), BUNDLE, self.PROF, {"A": a, "B": b}, "B", SCORING)   # seat B holds primary
        self.assertEqual((r["status"], len(a.seen)), ("false-evidence", 1))

    def test_one_audit_real_without_image_evidence_is_false(self):
        r = P.judge_unique(finding(), BUNDLE, self.PROF, {"A": Seat({"audit": real(ev="no such line here")}),
                                                          "B": Seat({})}, "A", SCORING)
        self.assertEqual(r["status"], "false-default")


class TwoAudits(unittest.TestCase):                                         # rule 8(b)
    def judge(self, va, vb, **kw):
        a, b = Seat({"audit": va, **kw.get("a", {})}), Seat({"audit": vb, **kw.get("b", {})})
        return P.judge_unique(finding(), BUNDLE, {"entries": []}, {"A": a, "B": b}, "A", SCORING), a, b

    def test_every_round_one_combination(self):                             # REQ-SCAN-008-AC2, AC4
        cases = [
            (real(), real(), "report"),
            (false(), false(), "false-evidence"),
            (false(ev=None), false(ev=None), "false-default"),
            (real(), {"error": "timeout"}, "false-default"),                 # an error is no evidence, not a vote
            ({"error": "x", "verdict": "real", "evidence": [EV_REAL]}, real(), "false-default"),
            (real(), real(ev="not in the image at all"), "false-default"),
            (real(), RuntimeError("model down"), "false-default"),
        ]
        for va, vb, want in cases:
            r, _, _ = self.judge(va, vb)
            self.assertEqual(r["status"], want, (va, vb))
            self.assertEqual(len(r["audits"]), 2)
            self.assertIsNone(r["debate"])

    def test_errors_are_reported(self):
        r, _, _ = self.judge(real(), RuntimeError("model down"))
        self.assertEqual([a.get("error") for a in r["audits"]][1], "RuntimeError: model down")

    def test_real_carries_why_or_is_flagged_unexplained(self):             # rule 8(b) why, AC5 data
        r, _, _ = self.judge(real(why="reads the dpkg status file"), real(why=None))
        self.assertEqual((r["why"], r["unexplained"]), ("reads the dpkg status file", False))
        r, _, _ = self.judge(real(why=None), real(why=""))
        self.assertEqual((r["why"], r["unexplained"]), (None, True))


class Debate(unittest.TestCase):                                            # rule 8(c)
    def run_debate(self, a_answers, b_answers):
        a, b = Seat(a_answers), Seat(b_answers)
        return P.judge_unique(finding(), BUNDLE, {"entries": []}, {"A": a, "B": b}, "A", SCORING), a, b

    def test_agreement_in_round_two_stops_the_debate(self):                 # REQ-SCAN-008-AC7
        r, a, b = self.run_debate({"audit": real(), "case": real(), "verdict": real()},
                                  {"audit": false(), "case": false(), "verdict": real()})
        d = r["debate"]
        self.assertEqual((r["status"], d["outcome"], len(d["rounds"])), ("report", "agreed-real", 1))
        self.assertEqual(d["sides"], {"A": "real", "B": "false"})
        self.assertEqual(d["prevailing"], "A")
        # each auditor read the OTHER's case before its verdict
        self.assertEqual(b.seen[-1]["mode"], "verdict")
        self.assertEqual(b.seen[-1]["opponent_case"], real()["case"])
        self.assertEqual(a.seen[-1]["opponent_case"], false()["case"])

    def test_agreement_in_round_four(self):
        r, _, _ = self.run_debate({"audit": false(), "case": [false()] * 3, "verdict": [false(), false(), false()]},
                                  {"audit": real(), "case": [real()] * 3, "verdict": [real(), real(), false()]})
        self.assertEqual((r["status"], r["debate"]["outcome"], len(r["debate"]["rounds"])),
                         ("false-evidence", "agreed-false", 3))
        self.assertEqual(r["debate"]["prevailing"], "A")

    def test_no_agreement_after_round_four_is_false_by_default(self):      # REQ-SCAN-008-AC9
        r, a, b = self.run_debate({"audit": false(), "case": [false()] * 3, "verdict": [false()] * 3},
                                  {"audit": real(), "case": [real()] * 3, "verdict": [real()] * 3})
        self.assertEqual((r["status"], r["debate"]["outcome"], len(r["debate"]["rounds"])),
                         ("false-default", "disagreed", 3))
        self.assertIsNone(r["debate"]["prevailing"])
        self.assertEqual(len([x for x in a.seen if x["mode"] == "verdict"]), 3)

    def test_each_auditor_is_told_the_scoring(self):                        # REQ-SCAN-008-AC8
        _, a, b = self.run_debate({"audit": real(), "case": real(), "verdict": real()},
                                  {"audit": false(), "case": false(), "verdict": real()})
        for seat in (a, b):
            for req in seat.seen:
                if req["mode"] in ("case", "verdict"):
                    self.assertEqual(req["scoring"], SCORING)
        self.assertIn("+1", SCORING)
        self.assertIn("-2", SCORING)

    def test_an_error_mid_debate_is_no_evidence(self):
        r, _, _ = self.run_debate({"audit": real(), "case": real(), "verdict": RuntimeError("x")},
                                  {"audit": false(), "case": false(), "verdict": real()})
        self.assertNotEqual(r["status"], "report")

    def test_agreed_real_still_needs_both_citations(self):
        r, _, _ = self.run_debate({"audit": real(), "case": real(), "verdict": real()},
                                  {"audit": false(), "case": false(), "verdict": real(ev="invented line")})
        self.assertEqual(r["status"], "false-default")

    def test_the_record_holds_both_cases_and_verdicts(self):                # REQ-SCAN-013-AC1
        r, _, _ = self.run_debate({"audit": real(), "case": real(), "verdict": real()},
                                  {"audit": false(), "case": false(), "verdict": real()})
        rnd = r["debate"]["rounds"][0]
        self.assertEqual(set(rnd), {"cases", "verdicts"})
        self.assertEqual(set(rnd["cases"]), {"A", "B"})
        self.assertEqual(rnd["verdicts"], {"A": "real", "B": "real"})
        # every answer of every round is kept (Codex r1 B5)
        self.assertEqual([(x["seat"], x["mode"], x["round"]) for x in r["audits"]],
                         [("A", "audit", 1), ("B", "audit", 1), ("A", "case", 2), ("B", "case", 2),
                          ("A", "verdict", 2), ("B", "verdict", 2)])

    def test_an_error_while_building_a_case_is_kept_and_reported(self):
        r, _, _ = self.run_debate({"audit": real(), "case": [RuntimeError("case broke"), real()], "verdict": [false(), real()]},
                                  {"audit": false(), "case": [false(), false()], "verdict": [real(), real()]})
        self.assertIn("RuntimeError: case broke", [x.get("error") for x in r["audits"]])


class Day(unittest.TestCase):
    def day(self, v, state=None, a=None, b=None, today="2026-10-03", profiles=None):
        a = a or Seat({"audit": false(ev=None)})
        b = b or Seat({"audit": false(ev=None)})
        return P.apply_day(v, state or P.new_state(), bundles, profiles or {"entries": []}, {"A": a, "B": b},
                           today, SCORING)

    def test_false_by_default_is_logged_with_reasons_and_no_statement(self):   # REQ-SCAN-009-AC2, AC3
        st, out = self.day(verdict(finding()))
        self.assertEqual([x["status"] for x in out["log"]], ["false-default"])
        self.assertTrue(all("audits" in x for x in out["log"]))
        self.assertEqual((out["issue"], out["vex"], out["owner"]), ("", [], []))
        self.assertEqual([x["id"] for x in st["false"]], ["CVE-2099-0002"])

    def test_false_with_evidence_proposes_not_affected(self):
        st, out = self.day(verdict(finding()), a=Seat({"audit": false()}), b=Seat({"audit": false()}))
        self.assertEqual(out["vex"][0]["status"], "not_affected")
        self.assertIn(EV_FALSE, out["vex"][0]["impact_statement"])
        self.assertEqual(out["vex"][0]["purls"], [PURL])                    # scoped to the exact package

    def test_false_with_evidence_but_no_package_identity_writes_no_blanket_statement(self):
        st, out = self.day(verdict(finding(purls=())), a=Seat({"audit": false()}), b=Seat({"audit": false()}))
        self.assertEqual(out["vex"], [])
        self.assertTrue(any("no VEX statement was written" in o for o in out["owner"]))
        self.assertFalse(st["false"][0]["vex"])

    def test_real_unique_reaches_the_issue_and_proposes_a_profile_entry(self):
        st, out = self.day(verdict(finding()), a=Seat({"audit": real()}), b=Seat({"audit": real()}))
        self.assertIn("CVE-2099-0002", out["issue"])
        self.assertEqual(out["profiles"][0]["scanner"], "scout")
        self.assertEqual(out["profiles"][0]["kind"], "sees_alone")
        st, out = self.day(verdict(finding()), a=Seat({"audit": real(why=None)}), b=Seat({"audit": real(why=None)}))
        self.assertTrue(out["profiles"][0]["unexplained"])
        self.assertTrue(any("unexplained" in o for o in out["owner"]))

    def test_another_scanner_later_reverses_false_as_an_audit_miss(self):   # REQ-SCAN-009-AC4
        st, _ = self.day(verdict(finding()))
        st, out = self.day(verdict(finding(seen=("grype",))), st, today="2026-10-04")
        self.assertEqual(out["misses"][0]["id"], "CVE-2099-0002")
        self.assertIn("audit miss", out["issue"])
        self.assertTrue(any("audit miss" in o for o in out["owner"]))
        self.assertEqual(st["false"], [])
        self.assertEqual([x["id"] for x in st["real"]], ["CVE-2099-0002"])

    def test_a_reversed_vex_statement_turns_affected(self):
        st, out = self.day(verdict(finding()), a=Seat({"audit": false()}), b=Seat({"audit": false()}))
        st, out = self.day(verdict(finding(seen=("grype", "scout"))), st, today="2026-10-04")
        self.assertEqual(out["vex"][0]["status"], "affected")

    def test_once_real_stays_reported_without_new_audits(self):
        st, _ = self.day(verdict(finding()), a=Seat({"audit": real()}), b=Seat({"audit": real()}))
        a = Seat({})
        st, _ = self.day(verdict(finding()), st, a=a, b=a, today="2027-03-01")     # still present months later
        st, out = self.day(verdict(finding()), st, a=a, b=a, today="2027-08-01")
        self.assertIn("CVE-2099-0002", out["issue"])
        self.assertEqual(a.seen, [])

    def test_memory_is_refreshed_while_present_and_expires_when_absent(self):
        st, _ = self.day(verdict(finding()))
        st, _ = self.day(verdict(finding()), st, today="2027-03-01")
        self.assertEqual(st["false"][0]["last_seen"], "2027-03-01")
        st, _ = self.day(verdict(), st, today="2027-08-01")      # absent < window: kept
        self.assertEqual(len(st["false"]), 1)
        st, _ = self.day(verdict(), st, today="2027-09-01")      # absent > window: dropped
        self.assertEqual(st["false"], [])

    def test_a_days_debate_is_recorded_in_the_state(self):                 # REQ-SCAN-013-AC1
        st, out = self.day(verdict(finding()), a=Seat({"audit": real(), "case": real(), "verdict": real()}),
                           b=Seat({"audit": false(), "case": false(), "verdict": real()}))
        d = st["debates"][0]
        self.assertEqual((d["id"], d["on"], d["settled"], d["sides"]), ("CVE-2099-0002", "2026-10-03", None,
                                                                         {"A": "real", "B": "false"}))
        self.assertEqual(out["log"][0]["status"], "report")

    def test_one_finding_across_version_spellings(self):
        self.assertEqual(P.key_of(finding(ver="v0.47.0")), P.key_of(finding(ver="0.47.0")))

    def test_a_non_answer_is_an_error(self):
        r = P.judge_unique(finding(), BUNDLE, {"entries": []}, {"A": lambda q: "real", "B": lambda q: None}, "A", SCORING)
        self.assertEqual([a["error"] for a in r["audits"]], ["no answer", "no answer"])

    def test_two_scanner_findings_are_the_rescans_not_audited(self):
        a = Seat({})
        st, out = self.day(verdict(finding(seen=("grype", "scout"))), a=a, b=a)
        self.assertEqual((a.seen, out["issue"]), ([], ""))


class Scoring(unittest.TestCase):                                           # rule 13
    def debate(self, sides, outcome, prevailing):
        return {"image": "fips-arm64", "id": "CVE-1", "package": "tzdata", "version": "1",
                "sides": sides, "outcome": outcome, "prevailing": prevailing, "settled": None, "rounds": []}

    def test_every_outcome(self):                                           # REQ-SCAN-013-AC3
        AR = {"A": "real", "B": "false"}
        self.assertEqual(P.score(self.debate(AR, "agreed-real", "A"), "real"), {"A": 1, "B": 0})
        self.assertEqual(P.score(self.debate(AR, "agreed-false", "B"), "real"), {"A": 1, "B": -2})
        self.assertEqual(P.score(self.debate(AR, "disagreed", None), "real"), {"A": 1, "B": 0})
        self.assertEqual(P.score(self.debate(AR, "agreed-real", "A"), "false"), {"A": -2, "B": 1})
        self.assertEqual(P.score(self.debate(AR, "agreed-real", "A"), None), {"A": 0, "B": 0})   # unsettled

    def test_settlement_triggers(self):                                     # REQ-SCAN-013-AC2
        st = P.new_state()
        st["debates"].append(self.debate({"A": "real", "B": "false"}, "agreed-false", "B"))
        f = {"image": "fips-arm64", "id": "CVE-1", "package": "tzdata", "version": "1"}
        same = P.settle(copy.deepcopy(st), [], "2026-10-05")
        self.assertIsNone(same["debates"][0]["settled"])
        self.assertEqual(same["scores"], {"A": 0, "B": 0})
        for kind in ("corroborated", "advisory", "fix-shipped"):
            s2 = P.settle(copy.deepcopy(st), [dict(f, kind=kind)], "2026-10-05")
            self.assertEqual(s2["debates"][0]["settled"], {"truth": "real", "by": kind, "on": "2026-10-05"})
            self.assertEqual(s2["scores"], {"A": 1, "B": -2})
        twice = P.settle(P.settle(copy.deepcopy(st), [dict(f, kind="advisory")], "2026-10-05"),
                         [dict(f, kind="corroborated")], "2026-10-06")
        self.assertEqual(twice["scores"], {"A": 1, "B": -2})                 # a debate settles once

    def test_corroboration_in_the_day_settles(self):
        st = P.new_state()
        st["debates"].append(self.debate({"A": "real", "B": "false"}, "agreed-false", "B"))
        st["debates"][0].update(image="fips-arm64", id="CVE-2099-0002", package="tzdata", version="2026c-0+deb13u1")
        st, out = P.apply_day(verdict(finding(seen=("grype", "scout"))), st, bundles, {"entries": []},
                              {"A": Seat({}), "B": Seat({})}, "2026-10-05", SCORING)
        self.assertEqual(st["debates"][0]["settled"]["by"], "corroborated")
        self.assertEqual(st["scores"], {"A": 1, "B": -2})


class PrimarySeat(unittest.TestCase):                                       # rule 14
    def test_thresholds_and_hysteresis(self):                               # REQ-SCAN-014-AC1
        self.assertEqual(P.seat({"A": 0, "B": 0}, "A"), "A")
        self.assertEqual(P.seat({"A": 0, "B": 2}, "A"), "A")
        self.assertEqual(P.seat({"A": 0, "B": 3}, "A"), "B")
        self.assertEqual(P.seat({"A": 1, "B": 3}, "B"), "B")                 # B no longer leads by 3: stays
        self.assertEqual(P.seat({"A": 3, "B": 1}, "B"), "B")
        self.assertEqual(P.seat({"A": 4, "B": 1}, "B"), "A")

    def test_a_seat_change_is_reported_to_the_owner(self):                  # REQ-SCAN-014-AC2 (data)
        st = P.new_state()
        for i in range(3):      # three settled debates B argued right and A argued wrong, never agreeing: B +3
            st["debates"].append({"image": "x", "id": "CVE-%d" % i, "package": "p", "version": "1",
                                  "sides": {"A": "false", "B": "real"}, "outcome": "disagreed", "prevailing": None,
                                  "settled": {"truth": "real", "by": "corroborated", "on": "2026-10-04"}, "rounds": []})
        st, out = P.apply_day(verdict(), st, bundles, {"entries": []}, {"A": Seat({}), "B": Seat({})},
                              "2026-10-05", SCORING)
        self.assertEqual(st["seat"], "B")
        self.assertTrue(any("primary" in o and "vendor B" in o for o in out["owner"]))


class PublicText(unittest.TestCase):                                        # REQ-SCAN-014-AC4, REQ-SCAN-008-AC3 (text)
    def test_no_vendor_or_model_name_in_anything_published(self):
        st = P.new_state()
        a = Seat({"audit": dict(real(why="claude-opus read it; gpt-6 agreed"), evidence=[EV_REAL, "openai quote"])})
        b = Seat({"audit": RuntimeError("gpt-6-astra refused; key sk-abcdefghijk; token eyJhbGciOiJ.eyJzdWIiOiJ.sig")})
        st, out = P.apply_day(verdict(finding()), st, bundles, {"entries": []}, {"A": a, "B": b}, "2026-10-05", SCORING)
        text = json.dumps(P.scrub([out, st])).lower()      # what cmd_judge writes out
        self.assertNotIn("sk-abcdefghijk", text)
        self.assertNotIn("eyjhbgcioij", text)
        for name in ("anthropic", "claude", "openai", "gpt", "codex", "gemini"):
            self.assertNotIn(name, text, name)
        self.assertNotIn(name, SCORING.lower())


if __name__ == "__main__":
    unittest.main()
