# proves: REQ-AUD-018-AC4
"""auditor-review-gate.py (REQ-AUD-18 AC3, option C): every reason a review record fails to clear
the gate, and the CLI's argument and no-change paths, against a real temporary git repository."""
import contextlib, datetime, importlib.util, io, json, os, re, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.dirname(HERE)
_spec = importlib.util.spec_from_file_location("auditor_review_gate", os.path.join(BIN, "auditor-review-gate.py"))
G = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(G)

TREE = "ab" * 32
EV = "cd" * 32
EV2 = "ef" * 32      # the opus entry's own evidence: never the sonnet entry's


def good():
    return {"schema": G.SCHEMA, "tree": TREE,
            "rounds": [{"round": 1, "reviewers": {
                "codex": {"vendor": "openai", "blockers_open": 0, "evidence_sha256": EV},
                "sonnet": {"vendor": "anthropic", "blockers_open": 0, "evidence_sha256": EV}}}],
            "stop": {"codex": "clear", "sonnet": "clear"}}


class RecordProblems(unittest.TestCase):
    def test_a_complete_clear_record_has_no_problems(self):
        self.assertEqual(G.record_problems(good(), TREE), [])

    def test_not_an_object(self):
        self.assertEqual(G.record_problems([good()], TREE), ["record is not a JSON object"])

    def test_wrong_schema_and_stale_tree_are_both_reported(self):
        r = good(); r["schema"] = "v0"
        probs = G.record_problems(r, "ef" * 32)
        self.assertIn("schema is not %s" % G.SCHEMA, probs)
        self.assertIn("record binds tree %s, the change is %s" % (TREE, "ef" * 32), probs)

    def test_no_rounds(self):
        for rounds in (None, [], "r1"):
            r = good(); r["rounds"] = rounds
            self.assertEqual(G.record_problems(r, TREE), ["no review rounds recorded"])

    def test_final_round_without_reviewers(self):
        for final in ("round", {"round": 2}, {"reviewers": ["codex"]}):
            r = good(); r["rounds"].append(final)
            self.assertEqual(G.record_problems(r, TREE), ["final round names no reviewers"])

    def test_only_the_FINAL_round_counts(self):
        r = good()
        r["rounds"].append({"round": 2, "reviewers": {"codex": good()["rounds"][0]["reviewers"]["codex"]}})
        self.assertEqual(G.record_problems(r, TREE), ["final round has no sonnet review"])

    def test_each_vendor_field_is_checked(self):
        r = good(); c = r["rounds"][0]["reviewers"]["codex"]
        c["vendor"] = "anthropic"; c["blockers_open"] = 1; c["evidence_sha256"] = "x"
        r["stop"]["codex"] = "blocked"
        self.assertEqual(G.record_problems(r, TREE), [
            "codex vendor is 'anthropic', want 'openai'",
            "codex has 1 open merge blocker(s)",
            "codex evidence_sha256 is not a sha256",
            "codex stop verdict is 'blocked', want 'clear'"])

    def test_missing_stop_block_is_not_clear(self):
        r = good(); r["stop"] = "clear"
        self.assertEqual(G.record_problems(r, TREE), ["codex stop verdict is None, want 'clear'",
                                                      "sonnet stop verdict is None, want 'clear'"])

    def test_blockers_open_must_be_exactly_zero(self):
        for bad in (None, "0", False, 0.5, 0.0):     # False == 0 and 0.0 == 0 in Python
            r = good(); r["rounds"][0]["reviewers"]["sonnet"]["blockers_open"] = bad
            self.assertEqual(G.record_problems(r, TREE), ["sonnet has %r open merge blocker(s)" % bad])


class Cli(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)
        self.cwd = os.getcwd(); os.chdir(self.d); self.addCleanup(os.chdir, self.cwd)
        self.git("init", "-q")
        os.makedirs(".github/agent/bin"); os.makedirs("src")
        self.write(".github/agent/bin/x.py", "a\n"); self.write("src/y", "s\n")
        self.git("add", "-A"); self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *a):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *a],
                              check=True, capture_output=True, text=True).stdout

    def write(self, p, t):
        with open(p, "w") as fh:
            fh.write(t)

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = G.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_base_is_required(self):
        rc, out, err = self.run_main("--head", "HEAD")
        self.assertEqual(rc, 2)
        self.assertIn("--base is required", err)

    def test_a_flag_without_a_value_is_missing_not_a_crash(self):
        rc, out, err = self.run_main("--head", "HEAD", "--base")
        self.assertEqual(rc, 2)
        self.assertIn("--base is required", err)

    def test_print_tree_is_stable_and_ignores_records_only(self):
        rc, t1, _ = self.run_main("--print-tree")
        self.assertEqual(rc, 0); t1 = t1.strip()
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % ("0" * 64), "{}")
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        self.assertEqual(self.run_main("--print-tree")[1].strip(), t1)          # a record: same tree
        self.write(".github/agent/reviews/notes.txt", "x")
        self.git("add", "-A"); self.git("commit", "-qm", "not a record")
        self.assertNotEqual(self.run_main("--print-tree")[1].strip(), t1)       # anything else: new tree

    def test_no_auditor_change_needs_no_record(self):
        self.write("src/y", "t\n"); self.git("commit", "-qam", "outside")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("no change under .github/agent/", out)

    def test_invalid_record_json_fails_with_its_path(self):
        self.write(".github/agent/bin/x.py", "b\n"); self.git("commit", "-qam", "change")
        tree = self.run_main("--print-tree")[1].strip()
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % tree, "{not json")
        self.git("add", "-A"); self.git("commit", "-qm", "broken record")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertIn(".github/agent/reviews/%s.json" % tree, out)
        self.assertIn("no valid review record", out)

    def test_a_clear_record_passes_and_names_the_rounds(self):
        self.write(".github/agent/bin/x.py", "b\n"); self.git("commit", "-qam", "change")
        tree = self.run_main("--print-tree")[1].strip()
        rec = good(); rec["tree"] = tree
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("clears the stop rule (1 round(s))", out)
        rec["stop"]["sonnet"] = "blocked"
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("commit", "-qam", "not clear")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertIn("sonnet stop verdict is 'blocked'", out)


class GuardFiles(Cli):
    """The allowlist guard's own files sit outside .github/agent/ but are review-gated too: a PR that
    changes only one of them needs a record bound to the content, and the tree hash covers them."""
    GUARDS = ("bin/check-file-allowlist.sh", "bin/check-file-allowlist-test.sh", ".github/workflows/agent-review-gate.yml")

    def setUp(self):
        super().setUp()
        os.makedirs("bin"); os.makedirs(".github/workflows")
        for g in self.GUARDS:
            self.write(g, "v1\n")
        self.write(".github/workflows/ci.yml", "ci1\n")
        self.git("add", "-A"); self.git("commit", "-qm", "guards")
        self.base = self.git("rev-parse", "HEAD").strip()

    def record(self):
        tree = self.run_main("--print-tree")[1].strip()
        rec = good(); rec["tree"] = tree
        os.makedirs(".github/agent/reviews", exist_ok=True)
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        return tree

    def test_each_guard_file_alone_needs_a_record(self):
        for g in self.GUARDS:
            self.git("reset", "-q", "--hard", self.base)
            self.write(g, "v2\n"); self.git("commit", "-qam", "change " + g)
            rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
            self.assertEqual(rc, 1, g)
            self.assertIn("no valid review record", out)
            self.assertIn(g, out)

    def test_a_matching_record_clears_a_guard_only_change(self):
        self.write("bin/check-file-allowlist.sh", "v2\n"); self.git("commit", "-qam", "change")
        self.record()
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0, out)
        self.assertIn("clears the stop rule", out)

    def test_a_stale_record_does_not_clear_a_later_guard_change(self):
        self.write("bin/check-file-allowlist.sh", "v2\n"); self.git("commit", "-qam", "change")
        self.record()
        self.write("bin/check-file-allowlist.sh", "v3\n"); self.git("commit", "-qam", "change again")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)

    def test_an_old_record_cannot_be_replayed_over_a_guard_change(self):
        # a record exists for the unchanged agent content; changing only a guard file must not reuse it
        self.write(".github/agent/bin/x.py", "b\n"); self.git("commit", "-qam", "agent change")
        self.record()
        mid = self.git("rev-parse", "HEAD").strip()
        self.write("bin/check-file-allowlist-test.sh", "v2\n"); self.git("commit", "-qam", "guard only")
        rc, out, _ = self.run_main("--base", mid, "--head", "HEAD")
        self.assertEqual(rc, 1)

    def test_deleting_a_guard_file_is_a_change(self):
        self.git("rm", "-q", "bin/check-file-allowlist.sh"); self.git("commit", "-qm", "delete")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)

    def test_other_files_including_ci_yml_are_unaffected(self):
        self.write(".github/workflows/ci.yml", "ci2\n"); self.write("src/y", "t\n")
        self.git("commit", "-qam", "outside")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("nothing to clear", out)
        t = self.run_main("--print-tree")[1].strip()
        self.write(".github/workflows/ci.yml", "ci3\n"); self.git("commit", "-qam", "ci again")
        self.assertEqual(self.run_main("--print-tree")[1].strip(), t)      # ci.yml is not part of the bound content


# ---- REQ-AUD-018-AC4: a recorded second-seat substitute (the opus entry) -------------------------
Q0317 = "stop all codex no more codex reviews until after 1AM Saturday. replace all codex with opus medium."
Q210 = "Proceed with opus just for this one that codex is hung up on"
EXPIRY = "2026-10-10T05:00:00Z"
BEFORE = "2026-10-09T20:00:00Z"
AFTER = "2026-10-10T05:00:01Z"
SUBS = {"schema": "review-substitutes/v1", "substitutes": [
    {"id": "0317", "for": "codex", "by": "opus", "vendor": "anthropic", "effective_until": EXPIRY,
     "owner_quote": Q0317, "scope": "all"},
    {"id": "pr210", "for": "codex", "by": "opus", "vendor": "anthropic", "effective_until": EXPIRY,
     "owner_quote": Q210, "scope": "pr:210"}]}
# entry 0350 (owner, Oct 9 ~23:10 EDT, to the advisor): TWO spaces after "reviewer." and a lower-case start, verbatim
Q0350 = ("the plan is we use up the full 24% then switch back to opus as reviewer.  but when you switch to opus "
         "you need to scream at me - at that point I will hit the reset button.")
X0350 = "2026-10-17T05:00:00Z"      # Sat Oct 17 01:00 EDT
E0350 = {"id": "0350", "for": "codex", "by": "opus", "vendor": "anthropic", "effective_until": X0350,
         "owner_quote": Q0350, "scope": "all"}


def dt(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def opus(**over):
    e = {"vendor": "anthropic", "substitute_for": "codex", "substitute_id": "0317", "model": "opus",
         "effort": "medium", "blockers_open": 0, "evidence_sha256": EV2}
    e.update(over)
    return {k: v for k, v in e.items() if v is not ...}


def sub_rec(entry=None, completed=BEFORE, tree=TREE):
    r = good(); r["tree"] = tree
    rev = r["rounds"][0]["reviewers"]
    del rev["codex"]
    rev["opus"] = opus() if entry is None else entry
    if completed is not ...:
        r["rounds"][0]["completed_at"] = completed
    r["stop"] = {"sonnet": "clear", "opus": "clear"}
    return r


def problems(rec, subs=None, pr=None, now=BEFORE, tree=TREE):
    return G.record_problems(rec, tree, subs=json.dumps(SUBS) if subs is None else subs, pr=pr, now=dt(now))


def named(probs, text):
    return any(text in p for p in probs)


class Substitute(unittest.TestCase):
    def test_a_valid_0317_substitute_before_expiry_passes(self):
        self.assertEqual(problems(sub_rec()), [])

    def test_the_same_record_after_the_expiry_fails(self):
        self.assertTrue(named(problems(sub_rec(), now=AFTER), "expired"))

    def test_the_expiry_instant_itself_is_expired(self):
        self.assertTrue(named(problems(sub_rec(), now=EXPIRY), "expired"))

    def test_completed_at_after_the_expiry_fails_even_if_the_clock_is_early(self):
        self.assertTrue(named(problems(sub_rec(completed=AFTER), now=BEFORE), "completed_at"))
        self.assertTrue(named(problems(sub_rec(completed=EXPIRY), now=BEFORE), "completed_at"))

    def test_completed_at_missing_or_malformed_fails_naming_it(self):
        for bad in (..., None, "", 5, "2026-10-09", "2026-10-09T20:00:00+00:00", "2026-10-09 20:00:00Z", "2026-13-09T20:00:00Z"):
            self.assertTrue(named(problems(sub_rec(completed=bad)), "completed_at"), bad)

    def test_completed_at_in_the_future_fails(self):
        self.assertTrue(named(problems(sub_rec(completed="2026-10-09T21:00:00Z"), now=BEFORE), "completed_at"))

    def test_an_id_not_in_substitutes_json_fails(self):
        self.assertTrue(named(problems(sub_rec(opus(substitute_id="9999"))), "substitute_id"))
        self.assertTrue(named(problems(sub_rec(opus(substitute_id=...))), "substitute_id"))
        self.assertTrue(named(problems(sub_rec(opus(substitute_id=317))), "substitute_id"))

    def test_no_substitutes_json_on_the_base_fails(self):
        probs = G.record_problems(sub_rec(), TREE, subs=None, pr=None, now=dt(BEFORE))
        self.assertTrue(named(probs, "substitutes.json"))

    def test_substitutes_json_unreadable_or_malformed_fails_naming_it(self):
        def with_(mut):
            o = json.loads(json.dumps(SUBS)); mut(o); return json.dumps(o)
        cases = ["{not json", "[]", json.dumps({"schema": "v0", "substitutes": []}),
                 with_(lambda o: o.update(substitutes="x")),
                 with_(lambda o: o["substitutes"].__setitem__(0, "x")),
                 with_(lambda o: o["substitutes"][0].update(effective_until="2026-10-10")),
                 with_(lambda o: o["substitutes"][0].update(effective_until=5)),
                 with_(lambda o: o["substitutes"][0].update(scope="pr:")),
                 with_(lambda o: o["substitutes"][0].update(scope="everything")),
                 with_(lambda o: o["substitutes"][0].update({"for": "sonnet"})),
                 with_(lambda o: o["substitutes"][0].update(by="gpt")),
                 with_(lambda o: o["substitutes"][0].update(vendor="openai")),
                 with_(lambda o: o["substitutes"][0].pop("effective_until")),
                 with_(lambda o: o["substitutes"].append(dict(o["substitutes"][0])))]     # duplicate id
        for c in cases:
            self.assertNotEqual(problems(sub_rec(), subs=c), [], c)

    def test_an_empty_owner_quote_fails(self):
        for q in ("", "   ", None, 7):
            o = json.loads(json.dumps(SUBS)); o["substitutes"][0]["owner_quote"] = q
            self.assertTrue(named(problems(sub_rec(), subs=json.dumps(o)), "owner_quote"), q)
        o = json.loads(json.dumps(SUBS)); del o["substitutes"][0]["owner_quote"]
        self.assertTrue(named(problems(sub_rec(), subs=json.dumps(o)), "owner_quote"))

    def test_scope_pr_210_passes_only_for_pr_210(self):
        rec = sub_rec(opus(substitute_id="pr210"))
        self.assertEqual(problems(rec, pr=210), [])
        self.assertTrue(named(problems(rec, pr=211), "scope"))
        self.assertTrue(named(problems(rec, pr=2100), "scope"))
        self.assertTrue(named(problems(rec, pr=None), "scope"))

    def test_scope_all_does_not_need_a_pr_number(self):
        self.assertEqual(problems(sub_rec(), pr=None), [])
        self.assertEqual(problems(sub_rec(), pr=211), [])

    def test_sonnet_missing_fails(self):
        r = sub_rec(); del r["rounds"][0]["reviewers"]["sonnet"]
        self.assertTrue(named(problems(r), "no sonnet review"))

    def test_sonnet_cannot_be_substituted(self):
        r = sub_rec(); rev = r["rounds"][0]["reviewers"]
        rev["sonnet"] = opus(substitute_for="sonnet")
        self.assertNotEqual(problems(r), [])
        r = sub_rec(); r["rounds"][0]["reviewers"]["sonnet"] = opus()          # a substitute entry under sonnet
        self.assertNotEqual(problems(r), [])
        r = sub_rec(); del r["rounds"][0]["reviewers"]["sonnet"]
        r["rounds"][0]["reviewers"]["opus"] = opus(substitute_for="sonnet")
        self.assertNotEqual(problems(r), [])

    def test_open_blockers_fail_for_the_substitute_and_for_sonnet(self):
        for bad in (1, False, None, "0", 0.0):
            self.assertTrue(named(problems(sub_rec(opus(blockers_open=bad))), "opus has"), bad)
        r = sub_rec(); r["rounds"][0]["reviewers"]["sonnet"]["blockers_open"] = 1
        self.assertTrue(named(problems(r), "sonnet has"))

    def test_the_substitute_is_never_openai(self):
        for v in ("openai", "", None, "anthropic "):
            self.assertTrue(named(problems(sub_rec(opus(vendor=v))), "opus vendor"), v)

    def test_model_effort_substitute_for_and_evidence_are_exact(self):
        for k, v, word in (("model", "opus-4", "model"), ("model", "sonnet", "model"), ("effort", "high", "effort"),
                           ("effort", None, "effort"), ("substitute_for", "sonnet", "substitute_for"),
                           ("substitute_for", ..., "substitute_for"), ("evidence_sha256", "x", "evidence_sha256"),
                           ("evidence_sha256", ..., "evidence_sha256")):
            self.assertTrue(named(problems(sub_rec(opus(**{k: v}))), word), (k, v))

    def test_the_stop_verdict_for_the_substitute_must_be_clear(self):
        r = sub_rec(); r["stop"]["opus"] = "blocked"
        self.assertTrue(named(problems(r), "opus stop verdict"))
        r = sub_rec(); del r["stop"]["opus"]
        self.assertTrue(named(problems(r), "opus stop verdict"))

    def test_a_wrong_tree_fails(self):
        self.assertTrue(named(problems(sub_rec(), tree="ef" * 32), "binds tree"))

    def test_a_record_with_codex_and_opus_is_judged_on_codex_alone(self):
        r = good(); r["rounds"][0]["reviewers"]["opus"] = opus()                 # no completed_at, no substitutes
        self.assertEqual(G.record_problems(r, TREE, subs=None, pr=None, now=dt(AFTER)), [])
        r["rounds"][0]["reviewers"]["opus"] = {"garbage": True}
        self.assertEqual(G.record_problems(r, TREE), [])
        r["rounds"][0]["reviewers"]["codex"]["blockers_open"] = 1                # a bad codex is not rescued by opus
        r["rounds"][0]["reviewers"]["opus"] = opus()
        self.assertTrue(named(G.record_problems(r, TREE, subs=json.dumps(SUBS), now=dt(BEFORE)), "codex has"))

    def test_without_codex_or_opus_the_old_message_stays(self):
        r = good(); del r["rounds"][0]["reviewers"]["codex"]
        self.assertEqual(G.record_problems(r, TREE), ["final round has no codex review"])

    def test_a_substitute_without_a_clock_uses_the_system_clock_function(self):
        with mock.patch.object(G, "_utcnow", return_value=dt(AFTER)):
            self.assertTrue(named(G.record_problems(sub_rec(), TREE, subs=json.dumps(SUBS)), "expired"))
        with mock.patch.object(G, "_utcnow", return_value=dt(BEFORE)):
            self.assertEqual(G.record_problems(sub_rec(), TREE, subs=json.dumps(SUBS)), [])
        with mock.patch.dict(os.environ, {"GATE_NOW": BEFORE}), mock.patch.object(G, "_utcnow", return_value=dt(AFTER)):
            self.assertTrue(named(G.record_problems(sub_rec(), TREE, subs=json.dumps(SUBS)), "expired"))   # env is ignored
        # the real clock is long past the 2026-10-10 expiry by the time this runs, or not yet: either way it decides
        probs = G.record_problems(sub_rec(), TREE, subs=json.dumps(SUBS))
        self.assertEqual("expired" in " ".join(probs), datetime.datetime.now(datetime.timezone.utc) >= dt(EXPIRY))

    def test_a_substitutes_file_with_the_wrong_schema_fails_naming_the_schema(self):
        bad = dict(SUBS, schema="v0")
        self.assertTrue(named(problems(sub_rec(), subs=json.dumps(bad)), "schema"))

    def test_completed_at_is_read_from_the_FINAL_round(self):
        r = sub_rec(completed=...)
        r["rounds"][0]["completed_at"] = BEFORE
        r["rounds"].append({"round": 2, "reviewers": r["rounds"][0]["reviewers"]})       # final round has none
        self.assertTrue(named(problems(r), "completed_at"))
        r["rounds"][1]["completed_at"] = BEFORE
        self.assertEqual(problems(r), [])

    def test_a_scope_with_a_trailing_newline_fails_named_without_a_traceback(self):
        for scope, pr in (("all\n", None), ("pr:210\n", 210)):
            subs = json.loads(json.dumps(SUBS)); subs["substitutes"][0]["scope"] = scope
            self.assertTrue(named(problems(sub_rec(), subs=json.dumps(subs), pr=pr), "scope"), scope)

    def test_a_record_path_with_a_trailing_newline_is_not_a_record(self):
        self.assertTrue(G._is_record(G.REVIEWS + "a" * 64 + ".json"))
        self.assertFalse(G._is_record(G.REVIEWS + "a" * 64 + ".json\n"))

    def test_a_time_with_a_trailing_newline_is_not_a_time(self):
        self.assertIsNone(G._time(BEFORE + "\n"))
        self.assertTrue(named(problems(sub_rec(completed=BEFORE + "\n")), "completed_at"))

    def test_a_present_but_invalid_codex_entry_never_takes_the_substitute_path(self):
        for bad in (None, [], "x", 0, {}):
            r = sub_rec(); r["rounds"][0]["reviewers"]["codex"] = bad
            ps = problems(r)
            self.assertNotEqual(ps, [], bad)
            self.assertTrue(named(ps, "codex"), (bad, ps))

    def test_an_opus_entry_copied_from_sonnet_fails(self):
        r = sub_rec()
        r["rounds"][0]["reviewers"]["opus"]["evidence_sha256"] = r["rounds"][0]["reviewers"]["sonnet"]["evidence_sha256"]
        self.assertTrue(named(problems(r), "evidence_sha256"))
        r["rounds"][0]["reviewers"]["opus"]["evidence_sha256"] = "12" * 32
        self.assertEqual(problems(r), [])

    def test_evidence_with_a_trailing_newline_or_65_hex_is_rejected(self):
        for bad in (EV2 + "\n", EV2 + "a"):
            self.assertTrue(named(problems(sub_rec(opus(evidence_sha256=bad))), "evidence_sha256"), repr(bad))
        r = good(); r["rounds"][0]["reviewers"]["sonnet"]["evidence_sha256"] = EV + "\n"
        self.assertTrue(named(G.record_problems(r, TREE), "evidence_sha256"))

    def test_a_sonnet_or_codex_entry_marked_as_a_substitute_is_rejected_by_that_rule(self):
        for name, key in (("sonnet", "substitute_for"), ("sonnet", "substitute_id"), ("codex", "substitute_for"), ("codex", "substitute_id")):
            r = good(); r["rounds"][0]["reviewers"][name][key] = "codex"
            self.assertTrue(named(G.record_problems(r, TREE), "is marked as a substitute"), (name, key))
            r = sub_rec(); r["rounds"][0]["reviewers"]["sonnet"][key] = "codex"
            self.assertTrue(named(problems(r), "sonnet is marked as a substitute"), key)

    def test_the_shipped_substitutes_json_is_the_ratified_one(self):
        path = os.path.join(os.path.dirname(BIN), "reviews", "substitutes.json")
        with open(path) as fh:
            text = fh.read()
        self.assertEqual(json.loads(text), dict(SUBS, substitutes=SUBS["substitutes"] + [E0350]))
        self.assertEqual(problems(sub_rec(), subs=text), [])
        self.assertEqual(problems(sub_rec(opus(substitute_id="pr210")), subs=text, pr=210), [])


class SubstituteCli(unittest.TestCase):
    git, write, run_main = Cli.git, Cli.write, Cli.run_main
    SUBPATH = ".github/agent/reviews/substitutes.json"

    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)
        self.cwd = os.getcwd(); os.chdir(self.d); self.addCleanup(os.chdir, self.cwd)
        self.clock = mock.patch.object(G, "_utcnow", return_value=dt(BEFORE)); self.clock.start(); self.addCleanup(self.clock.stop)
        self.git("init", "-q", "-b", "main")
        os.makedirs(".github/agent/prompts"); os.makedirs(".github/agent/reviews")
        self.write(".github/agent/prompts/x.py", "a\n"); self.write(self.SUBPATH, json.dumps(SUBS))
        self.git("add", "-A"); self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def propose(self, entry=None, completed=BEFORE):
        self.write(".github/agent/prompts/x.py", "b\n"); self.git("commit", "-qam", "change")
        tree = self.run_main("--print-tree")[1].strip()
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(sub_rec(entry, completed, tree)))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        return tree

    def judge(self, *extra):
        return self.run_main("--base", self.base, "--head", "HEAD", *extra)

    def test_a_substitute_record_clears_the_cli(self):
        self.propose()
        rc, out, _ = self.judge()
        self.assertEqual(rc, 0, out)
        self.assertIn("clears the stop rule", out)

    def test_after_the_expiry_the_cli_fails(self):
        self.propose()
        with mock.patch.object(G, "_utcnow", return_value=dt(AFTER)):
            rc, out, _ = self.judge()
        self.assertEqual(rc, 1)
        self.assertIn("expired", out)

    def test_a_pr_that_adds_its_own_substitute_does_not_count_for_itself(self):
        self.write(self.SUBPATH, json.dumps({"schema": "review-substitutes/v1", "substitutes": []}))
        self.git("commit", "-qam", "base has no substitute"); self.base = self.git("rev-parse", "HEAD").strip()
        self.write(self.SUBPATH, json.dumps(SUBS)); self.git("commit", "-qam", "the PR adds its own entry")
        self.propose()
        rc, out, _ = self.judge()
        self.assertEqual(rc, 1)
        self.assertIn("substitutes.json", out)

    def test_a_pr_that_extends_the_expiry_or_the_scope_does_not_count_for_itself(self):
        o = json.loads(json.dumps(SUBS)); o["substitutes"][0]["effective_until"] = "2026-10-01T00:00:00Z"
        self.write(self.SUBPATH, json.dumps(o)); self.git("commit", "-qam", "base entry already expired")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write(self.SUBPATH, json.dumps(SUBS)); self.git("commit", "-qam", "the PR extends it")
        self.propose()
        rc, out, _ = self.judge()
        self.assertEqual(rc, 1)
        self.assertIn("substitutes.json", out)      # editing the allow-list now needs a real codex entry

    def test_no_substitutes_json_on_the_base_fails(self):
        self.git("rm", "-q", self.SUBPATH); self.git("commit", "-qm", "base without it")
        self.base = self.git("rev-parse", "HEAD").strip()
        os.makedirs(".github/agent/reviews", exist_ok=True)
        self.write(self.SUBPATH, json.dumps(SUBS)); self.git("add", "-A"); self.git("commit", "-qm", "the PR adds the file")
        self.propose()
        rc, out, _ = self.judge()
        self.assertEqual(rc, 1)
        self.assertIn("substitutes.json", out)

    def test_the_trusted_revision_can_be_main_s_tip_rather_than_the_merge_base(self):
        # the workflow passes the checked-out default branch tip: a substitute merged AFTER the PR branched still counts
        self.git("checkout", "-q", "-b", "pr")
        self.git("checkout", "-q", "main")
        o = json.loads(json.dumps(SUBS)); o["substitutes"] = [dict(SUBS["substitutes"][0], id="0400")]
        self.write(self.SUBPATH, json.dumps(o)); self.git("commit", "-qam", "main moves on")
        tip = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "-q", "pr")
        self.propose(opus(substitute_id="0400"))
        self.assertEqual(self.judge()[0], 1)                                     # the merge base lacks id 0400
        rc, out, _ = self.judge("--subs-rev", tip)
        self.assertEqual(rc, 0, out)

    def test_scope_pr_needs_a_matching_pr_argument(self):
        self.propose(opus(substitute_id="pr210"))
        self.assertEqual(self.judge("--pr", "210")[0], 0)
        for argv in (("--pr", "211"), ()):
            rc, out, _ = self.judge(*argv)
            self.assertEqual(rc, 1, argv)
            self.assertIn("scope", out)

    def test_a_bad_pr_argument_is_refused(self):
        self.propose(opus(substitute_id="pr210"))
        for argv in (("--pr",), ("--pr", "x"), ("--pr", "-1"), ("--pr", ""), ("--pr", "0210")):
            rc, _, err = self.judge(*argv)
            self.assertEqual(rc, 2, argv)
            self.assertIn("--pr", err)

    def test_a_tampered_tree_fails_the_cli(self):
        self.propose()
        self.write(".github/agent/prompts/x.py", "tampered\n"); self.git("commit", "-qam", "after the review")
        rc, out, _ = self.judge()
        self.assertEqual(rc, 1)
        self.assertIn("no valid review record", out)

    def edit_allowlist(self):
        o = json.loads(json.dumps(SUBS))
        for e in o["substitutes"]:
            e["effective_until"] = "2027-12-31T00:00:00Z"
        self.write(self.SUBPATH, json.dumps(o))

    def test_a_change_that_edits_the_allow_list_is_never_cleared_by_a_substitute(self):
        self.edit_allowlist()
        self.propose()
        rc, out, _ = self.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn("substitutes.json", out)
        self.assertIn("codex", out)

    def test_a_change_that_edits_the_allow_list_passes_with_a_real_codex_entry(self):
        self.edit_allowlist()
        self.write(".github/agent/prompts/x.py", "b\n"); self.git("commit", "-qam", "change")
        tree = self.run_main("--print-tree")[1].strip()
        rec = good(); rec["tree"] = tree
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        rc, out, _ = self.judge()
        self.assertEqual(rc, 0, out)

    ENFORCEMENT = (".github/agent/reviews/substitutes.json", ".github/agent/bin/auditor-review-gate.py",
                   ".github/workflows/agent-review-gate.yml", ".github/agent/bin/check-action-pins.py",
                   ".github/agent/bin/tests/test_review_gate.py")

    def touch(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as fh:
            fh.write("# touched\n")
        self.git("add", "-A"); self.git("commit", "-qm", "touch " + path)

    def test_a_change_to_any_enforcement_file_needs_a_real_codex_entry(self):
        for path in self.ENFORCEMENT:
            with self.subTest(path=path):
                self.git("reset", "-q", "--hard", self.base)
                self.touch(path)
                self.propose()
                rc, out, _ = self.judge()
                self.assertEqual(rc, 1, (path, out))
                self.assertIn(path, out)
                self.assertIn("codex", out)

    def test_the_enforcement_set_in_the_script_is_exactly_the_ratified_one(self):
        self.assertEqual(sorted(G.ENFORCEMENT_PREFIXES), [".github/agent/bin/", ".github/agent/fixtures/testlib/"])
        self.assertEqual(sorted(G.ENFORCEMENT), sorted([
            ".github/agent/reviews/substitutes.json", ".github/workflows/agent-review-gate.yml",
            "bin/check-file-allowlist.sh", ".github/agent/tests/pin-wiring-test.sh"]))

    def test_new_files_and_the_gate_s_other_inputs_need_a_real_codex_entry(self):
        for path in (".github/agent/bin/datetime.py", ".github/agent/bin/json.py", ".github/agent/bin/tests/new_test.py",
                     ".github/agent/fixtures/testlib/pyyaml/yaml/__init__.py", ".github/agent/fixtures/testlib/new.py",
                     "bin/check-file-allowlist.sh", ".github/agent/tests/pin-wiring-test.sh"):
            with self.subTest(path=path):
                self.git("reset", "-q", "--hard", self.base)
                self.touch(path)
                self.propose()
                rc, out, _ = self.judge()
                self.assertEqual(rc, 1, (path, out))
                self.assertIn(path, out)
                self.assertIn("codex", out)

    def test_an_ordinary_auditor_change_still_clears_with_a_substitute(self):
        self.touch(".github/agent/prompts/p.md")
        self.propose()
        rc, out, _ = self.judge()
        self.assertEqual(rc, 0, out)

    def test_a_missing_completed_at_fails_the_cli(self):
        self.propose(completed=...)
        rc, out, _ = self.judge()
        self.assertEqual(rc, 1)
        self.assertIn("completed_at", out)


REAL_SUBS = os.path.join(os.path.dirname(BIN), "reviews", "substitutes.json")
D0350 = "2026-10-16T12:00:00Z"      # a completed_at inside 0350's window
ONE_BEFORE_X0350 = "2026-10-17T04:59:59Z"


def real_subs_text():
    with open(REAL_SUBS, "rb") as fh:
        return fh.read().decode("utf-8")


def rec0350(completed=D0350, tree=TREE, **over):
    return sub_rec(opus(substitute_id="0350", **over), completed, tree)


class Substitute0350(unittest.TestCase):
    """REQ-AUD-018-AC4: entry 0350 of the REAL reviews/substitutes.json, judged by the gate as shipped."""

    def test_the_real_file_pins_entry_0350_field_by_field(self):
        text = real_subs_text()
        doc = json.loads(text)
        self.assertEqual(doc["schema"], "review-substitutes/v1")
        ids = [e["id"] for e in doc["substitutes"]]
        self.assertEqual(ids, ["0317", "pr210", "0350"])                 # exactly these three, in this order
        self.assertEqual(len(ids), len(set(ids)))                         # ids are unique
        e = [x for x in doc["substitutes"] if x["id"] == "0350"]
        self.assertEqual(len(e), 1); e = e[0]
        self.assertEqual(list(e), ["id", "for", "by", "vendor", "effective_until", "owner_quote", "scope"])
        self.assertEqual(e["id"], "0350")
        self.assertEqual(e["for"], "codex")
        self.assertEqual(e["by"], "opus")
        self.assertEqual(e["vendor"], "anthropic")
        self.assertEqual(e["scope"], "all")
        self.assertEqual(e["effective_until"], "2026-10-17T05:00:00Z")
        self.assertEqual(e["owner_quote"], Q0350)
        self.assertEqual(e["owner_quote"].encode("utf-8"), Q0350.encode("utf-8"))
        self.assertIn("reviewer.  but", e["owner_quote"])                 # the double space survives
        self.assertTrue(e["owner_quote"].startswith("the plan"))           # the lower-case start survives
        self.assertIn('"owner_quote": %s' % json.dumps(Q0350), text)      # byte for byte in the raw file too
        self.assertEqual(text, json.dumps(doc, indent=2) + "\n")         # the file keeps its formatting

    def test_0350_accepted_before_expiry_for_a_change_outside_the_enforcement_set(self):
        text = real_subs_text()
        self.assertEqual(problems(rec0350(), subs=text, now="2026-10-16T13:00:00Z"), [])
        self.assertEqual(problems(rec0350(), subs=text, now="2026-10-16T13:00:00Z", pr=999), [])   # scope all: any PR

    def test_0350_one_second_before_expiry_accepted_and_at_expiry_rejected_naming_it(self):
        text = real_subs_text()
        self.assertEqual(problems(rec0350(completed="2026-10-17T04:59:58Z"), subs=text, now=ONE_BEFORE_X0350), [])
        for clock in (X0350, "2026-10-17T05:00:01Z", "2026-10-18T00:00:00Z"):
            ps = problems(rec0350(), subs=text, now=clock)
            self.assertTrue(named(ps, "opus substitute 0350 expired at 2026-10-17T05:00:00Z"), (clock, ps))
        ps = problems(rec0350(completed=X0350), subs=text, now=ONE_BEFORE_X0350)     # completed_at at the expiry
        self.assertTrue(named(ps, "completed_at"), ps)

    def test_0350_after_expiry_rejected_by_the_system_clock_function(self):
        text = real_subs_text()
        with mock.patch.object(G, "_utcnow", return_value=dt(ONE_BEFORE_X0350)):
            self.assertEqual(G.record_problems(rec0350(), TREE, subs=text), [])
        with mock.patch.object(G, "_utcnow", return_value=dt(X0350)):
            self.assertTrue(named(G.record_problems(rec0350(), TREE, subs=text), "expired at 2026-10-17T05:00:00Z"))

    def test_a_scope_other_than_all_or_pr_n_without_pr_fails(self):
        for scope in ("pr:1", "pr:350"):
            o = json.loads(real_subs_text()); o["substitutes"][2]["scope"] = scope
            self.assertTrue(named(problems(rec0350(), subs=json.dumps(o), now=D0350), "needs --pr"), scope)
        for scope in ("everything", "", "pr:", "ALL", None):
            o = json.loads(real_subs_text()); o["substitutes"][2]["scope"] = scope
            self.assertTrue(named(problems(rec0350(), subs=json.dumps(o), now=D0350), "scope"), scope)

    def test_a_copy_without_an_owner_quote_is_rejected_naming_it(self):
        for q in ("", "   ", None, ...):
            o = json.loads(real_subs_text()); e = o["substitutes"][2]
            if q is ...:
                del e["owner_quote"]
            else:
                e["owner_quote"] = q
            ps = problems(rec0350(), subs=json.dumps(o), now=D0350)
            self.assertTrue(named(ps, "entry 0350 owner_quote"), (q, ps))

    def test_a_sonnet_substitution_is_still_refused(self):
        text = real_subs_text()
        r = rec0350(); r["rounds"][0]["reviewers"]["sonnet"] = opus(substitute_id="0350", substitute_for="sonnet")
        self.assertNotEqual(problems(r, subs=text, now=D0350), [])
        r = rec0350(); del r["rounds"][0]["reviewers"]["sonnet"]
        self.assertTrue(named(problems(r, subs=text, now=D0350), "no sonnet review"))
        r = good(); del r["rounds"][0]["reviewers"]["sonnet"]
        r["rounds"][0]["reviewers"]["opus"] = opus(substitute_id="0350", substitute_for="sonnet")
        r["rounds"][0]["completed_at"] = D0350
        self.assertNotEqual(problems(r, subs=text, now=D0350), [])

    def test_the_gate_clock_ignores_environment_and_options(self):
        text = real_subs_text()
        with mock.patch.dict(os.environ, {"GATE_NOW": D0350, "TZ": "Pacific/Kiritimati", "FAKETIME": "@2026-10-16 00:00:00"}), \
                mock.patch.object(G, "_utcnow", return_value=dt(X0350)):
            self.assertTrue(named(G.record_problems(rec0350(), TREE, subs=text), "expired"))


class Substitute0350Cli(unittest.TestCase):
    """The gate's CLI on a temporary repository whose TRUSTED (base) revision carries the REAL substitutes.json."""
    git, write, run_main = Cli.git, Cli.write, Cli.run_main
    SUBPATH = SubstituteCli.SUBPATH
    touch = SubstituteCli.touch
    SCRIPT = os.path.join(BIN, "auditor-review-gate.py")

    def setUp(self):
        self.real = real_subs_text()
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)
        self.cwd = os.getcwd(); os.chdir(self.d); self.addCleanup(os.chdir, self.cwd)
        self.clock = mock.patch.object(G, "_utcnow", return_value=dt("2026-10-16T13:00:00Z"))
        self.clock.start(); self.addCleanup(self.clock.stop)
        self.git("init", "-q", "-b", "main")
        os.makedirs(".github/agent/prompts"); os.makedirs(".github/agent/reviews")
        self.write(".github/agent/prompts/x.py", "a\n"); self.write(self.SUBPATH, self.real)
        self.git("add", "-A"); self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def propose(self, completed=D0350, record=None):
        self.write(".github/agent/prompts/x.py", "b\n"); self.git("commit", "-qam", "change")
        tree = self.run_main("--print-tree")[1].strip()
        rec = rec0350(completed, tree) if record is None else record(tree)
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        return tree

    def judge(self, *extra):
        return self.run_main("--base", self.base, "--head", "HEAD", *extra)

    def test_an_ordinary_change_clears_with_0350_before_expiry(self):
        self.propose()
        rc, out, _ = self.judge()
        self.assertEqual(rc, 0, out)
        self.assertIn("clears the stop rule", out)

    def test_one_second_before_clears_and_the_expiry_instant_fails_naming_it(self):
        self.propose(completed="2026-10-17T04:59:58Z")
        with mock.patch.object(G, "_utcnow", return_value=dt(ONE_BEFORE_X0350)):
            self.assertEqual(self.judge()[0], 0)
        for clock in (X0350, "2026-10-17T05:00:01Z"):
            with mock.patch.object(G, "_utcnow", return_value=dt(clock)):
                rc, out, _ = self.judge()
            self.assertEqual(rc, 1, clock)
            self.assertIn("0350 expired at 2026-10-17T05:00:00Z", out)

    def test_no_option_moves_the_clock(self):
        self.propose()
        with mock.patch.object(G, "_utcnow", return_value=dt(X0350)):
            for opt in (("--now", D0350), ("--clock", D0350), ("--time", D0350), ("--as-of", D0350)):
                rc, out, _ = self.judge(*opt)
                self.assertEqual(rc, 1, opt)
                self.assertIn("expired", out)

    def test_this_very_pr_with_a_substitute_only_record_fails(self):
        # base: main WITHOUT 0350; head: the real file WITH 0350 (this PR's diff), a substitute-only record
        o = json.loads(self.real); o["substitutes"] = [e for e in o["substitutes"] if e["id"] != "0350"]
        self.write(self.SUBPATH, json.dumps(o, indent=2) + "\n"); self.git("commit", "-qam", "main before this PR")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write(self.SUBPATH, self.real); self.git("commit", "-qam", "this PR: add 0350")
        self.propose()
        for extra in ((), ("--subs-rev", "HEAD")):          # even if the trusted copy already had 0350
            rc, out, _ = self.judge(*extra)
            self.assertEqual(rc, 1, (extra, out))
            self.assertIn("this change edits .github/agent/reviews/substitutes.json, so a substitute never applies", out)
            self.assertIn("real codex entry is required", out)

    def test_this_very_pr_clears_with_a_real_codex_entry(self):
        o = json.loads(self.real); o["substitutes"] = [e for e in o["substitutes"] if e["id"] != "0350"]
        self.write(self.SUBPATH, json.dumps(o, indent=2) + "\n"); self.git("commit", "-qam", "main before this PR")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write(self.SUBPATH, self.real); self.git("commit", "-qam", "this PR: add 0350")
        self.propose(record=lambda tree: dict(good(), tree=tree))
        rc, out, _ = self.judge()
        self.assertEqual(rc, 0, out)

    def test_any_enforcement_file_edit_is_never_cleared_by_0350(self):
        for path in SubstituteCli.ENFORCEMENT + ("bin/check-file-allowlist.sh", ".github/agent/tests/pin-wiring-test.sh",
                                                 ".github/agent/fixtures/testlib/new.py"):
            with self.subTest(path=path):
                self.git("reset", "-q", "--hard", self.base)
                self.touch(path)
                self.propose()
                rc, out, _ = self.judge()
                self.assertEqual(rc, 1, (path, out))
                self.assertIn(path, out)
                self.assertIn("real codex entry is required", out)

    def test_the_pr_s_own_copy_is_never_trusted(self):
        o = json.loads(self.real); o["substitutes"] = [e for e in o["substitutes"] if e["id"] != "0350"]
        self.write(self.SUBPATH, json.dumps(o, indent=2) + "\n"); self.git("commit", "-qam", "main without 0350")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write(self.SUBPATH, self.real); self.git("commit", "-qam", "the PR's own copy has 0350")
        self.propose()
        rc, out, _ = self.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn("substitutes.json", out)

    def test_the_environment_cannot_move_the_subprocess_gate_s_clock(self):
        # a real subprocess on the system clock: the verdict follows the real UTC time, whatever the environment says
        self.clock.stop(); self.addCleanup(self.clock.start)
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        done = min(now - datetime.timedelta(minutes=1), dt(X0350) - datetime.timedelta(seconds=1))
        tree = self.propose(completed=done.strftime("%Y-%m-%dT%H:%M:%SZ"))
        expired = now >= dt(X0350)
        for env in ({}, {"GATE_NOW": "2026-10-16T00:00:00Z"}, {"GATE_NOW": "2027-01-01T00:00:00Z"},
                    {"TZ": "Etc/GMT+12"}, {"TZ": "Etc/GMT-14"}, {"FAKETIME": "@2027-01-01 00:00:00"}):
            r = subprocess.run([sys.executable, "-I", self.SCRIPT, "--base", self.base, "--head", "HEAD"],
                               capture_output=True, text=True, env=dict(os.environ, **env), stdin=subprocess.DEVNULL)
            self.assertEqual(r.returncode, 1 if expired else 0, (env, r.stdout, r.stderr))
            self.assertEqual("0350 expired" in r.stdout, expired, env)
        self.assertTrue(tree)


class ClockIsSystemOnly(unittest.TestCase):
    """REQ-AUD-018-AC4: the gate's clock is the system clock; no environment variable or option sets it."""
    ROOT = os.path.dirname(os.path.dirname(os.path.dirname(BIN)))
    SCRIPT = os.path.join(BIN, "auditor-review-gate.py")

    def test_the_script_reads_no_environment_and_has_no_clock_option(self):
        import ast
        with open(self.SCRIPT) as fh:
            src = fh.read()
        bad = []
        for n in ast.walk(ast.parse(src)):
            if isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv", "environb", "putenv"):
                bad.append("line %d: %s" % (n.lineno, n.attr))
            if isinstance(n, ast.ImportFrom) and n.module == "os" and any(a.name in ("environ", "getenv") for a in n.names):
                bad.append("line %d: from os import environ/getenv" % n.lineno)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and (
                    "GATE_NOW" in n.value or n.value in ("--now", "--clock", "--time", "--as-of")):
                bad.append("line %d: %r" % (n.lineno, n.value[:40]))
        self.assertEqual(bad, [])

    def test_no_workflow_or_action_file_can_set_the_clock(self):
        files = []
        for base, dirs, names in os.walk(self.ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            for n in names:
                full = os.path.join(base, n)
                rel = os.path.relpath(full, self.ROOT)
                if (rel.startswith(os.path.join(".github", "workflows") + os.sep) and n.endswith((".yml", ".yaml"))) \
                        or n in ("action.yml", "action.yaml"):
                    files.append(full)
        self.assertTrue(any(f.endswith("agent-review-gate.yml") for f in files))
        bad = []
        for f in files:
            with open(f) as fh:
                text = fh.read()
            if "GATE_NOW" in text or re.search(r"--now\b", text):
                bad.append(os.path.relpath(f, self.ROOT))
        self.assertEqual(bad, [])

    def test_the_gate_workflow_passes_the_trusted_allow_list_and_the_pr_and_sets_no_gate_variable(self):
        import yaml
        with open(os.path.join(self.ROOT, ".github", "workflows", "agent-review-gate.yml")) as fh:
            wf = yaml.safe_load(fh)
        def runs(job):
            return [st["run"] for st in wf["jobs"][job]["steps"] if "run" in st]
        def gate_lines(job):
            text = "\n".join(runs(job)).replace("\\\n", " ")
            return [l for l in text.splitlines() if "auditor-review-gate.py" in l and "python3" in l]
        j, w = gate_lines("judge"), gate_lines("sweep")
        self.assertEqual(len(j), 1, j); self.assertEqual(len(w), 1, w)
        for line, pr in ((j[0], '--pr "$PR"'), (w[0], '--pr "$n"')):
            self.assertIn("--subs-rev HEAD", line)
            self.assertEqual(line.count("--subs-rev"), 1)
            self.assertIn(pr, line)
        for name, job in wf["jobs"].items():
            self.assertFalse([k for k in (job.get("env") or {}) if str(k).startswith("GATE_")], name)
            for st in job["steps"]:
                self.assertFalse([k for k in (st.get("env") or {}) if str(k).startswith("GATE_")], (name, st.get("name")))
                self.assertNotIn("GITHUB_ENV", st.get("run", "") + str(st.get("with", "")), (name, st.get("name")))

    # ---- the gate's own wiring is DERIVED, so a future change cannot fall outside the enforcement set ----
    WF = os.path.join(ROOT, ".github", "workflows", "agent-review-gate.yml")

    @staticmethod
    def executed_paths(text):
        """Every repo path the judge and sweep run: lines of their run: scripts (comments dropped)."""
        import yaml
        wf = yaml.safe_load(text)
        paths, lines = set(), []
        for job in ("judge", "sweep"):
            for st in wf["jobs"][job]["steps"]:
                lines += [l for l in st.get("run", "").splitlines() if not l.lstrip().startswith("#")]
        for l in lines:
            for m in re.finditer(r"(?:(?<![\w/.-])|(?<=\$PWD/))((?:\.github|bin)/[\w./-]*\w)", l):
                paths.add(m.group(1))
        return paths, lines

    def test_every_path_the_gate_runs_or_reads_is_in_the_enforcement_set(self):
        with open(self.WF) as fh:
            paths, _ = self.executed_paths(fh.read())
        self.assertIn(".github/agent/bin/auditor-review-gate.py", paths)
        self.assertIn(".github/agent/tests/pin-wiring-test.sh", paths)
        self.assertIn("bin/check-file-allowlist.sh", paths)
        self.assertIn(".github/agent/fixtures/testlib/pyyaml", paths)
        self.assertEqual([p for p in sorted(paths) if not G.enforces(p)], [])

    def test_a_new_executed_script_outside_the_set_is_caught(self):
        with open(self.WF) as fh:
            text = fh.read()
        mutated = text.replace("          echo \"verdict=${verdict}\"", "          bash .github/agent/prompts/extra.sh || verdict=failure\n          echo \"verdict=${verdict}\"", 1)
        self.assertNotEqual(mutated, text)
        paths, _ = self.executed_paths(mutated)
        self.assertEqual([p for p in sorted(paths) if not G.enforces(p)], [".github/agent/prompts/extra.sh"])

    def test_the_gate_and_the_pin_checker_run_in_python_isolated_mode(self):
        with open(self.WF) as fh:
            _, lines = self.executed_paths(fh.read())
        runs = [l for l in lines if re.search(r"\bpython3?\b", l) and ".github/agent/bin/" in l]
        self.assertEqual(len(runs), 4, runs)      # judge: gate, pins; sweep: gate, pins
        for l in runs:
            for m in re.finditer(r"\bpython3?\s+(\S+)", l):
                self.assertEqual(m.group(1), "-I", l)

    def test_the_requirement_text_never_names_the_auditor_directory_literally(self):
        # REQ-AUD-18 AC1: a file outside the auditor directory may not refer to it by its literal path prefix.
        for rel in ("requirements/requirements.yaml", "docs/quality/traceability.md"):
            with open(os.path.join(self.ROOT, rel)) as fh:
                self.assertNotIn(".github/agent/", fh.read(), rel)

    def test_an_environment_value_cannot_unexpire_a_substitute(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        def git(*a):
            return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *a],
                                  cwd=d, check=True, capture_output=True, text=True).stdout
        def put(p, t):
            os.makedirs(os.path.dirname(os.path.join(d, p)), exist_ok=True)
            with open(os.path.join(d, p), "w") as fh:
                fh.write(t)
        old = json.loads(json.dumps(SUBS))
        for e in old["substitutes"]:
            e["effective_until"] = "2020-01-01T00:00:00Z"
        git("init", "-q", "-b", "main")
        put(".github/agent/prompts/x.py", "a\n"); put(".github/agent/reviews/substitutes.json", json.dumps(old))
        git("add", "-A"); git("commit", "-qm", "base"); base = git("rev-parse", "HEAD").strip()
        put(".github/agent/prompts/x.py", "b\n"); git("commit", "-qam", "change")
        run = lambda *a, **env: subprocess.run([sys.executable, self.SCRIPT, *a], cwd=d, capture_output=True, text=True,
                                               env=dict(os.environ, **env))
        tree = run("--print-tree").stdout.strip()
        put(".github/agent/reviews/%s.json" % tree, json.dumps(sub_rec(None, "2019-06-01T00:00:00Z", tree)))
        git("add", "-A"); git("commit", "-qm", "record")
        for env in ({}, {"GATE_NOW": "2019-01-01T00:00:00Z"}):
            r = run("--base", base, "--head", "HEAD", **env)
            self.assertEqual(r.returncode, 1, (env, r.stdout, r.stderr))
            self.assertIn("expired", r.stdout)


class HarnessManifest(unittest.TestCase):
    """The reviewed harness manifest (.github/agent/supply-chain/harness-manifest.json, REQ-SUP-001 AC11) lies under .github/agent/, so a change to it needs a current review record, and any
    edit of it invalidates a record made before. It exempts files from the supply-chain checks, so an unreviewed change would silently hide a pin."""
    M = ".github/agent/supply-chain/harness-manifest.json"
    setUp, git, write, run_main = Cli.setUp, Cli.git, Cli.write, Cli.run_main

    def commit_manifest(self, text, msg="manifest"):
        os.makedirs(os.path.dirname(self.M), exist_ok=True)
        self.write(self.M, text)
        self.git("add", "-A"); self.git("commit", "-qm", msg)

    def test_the_manifest_is_under_the_reviewed_prefix(self):
        self.assertTrue(self.M.startswith(G.AGENT))
        self.assertNotIn(self.M, getattr(G, "GUARDED", ()), "the manifest is covered by the reviewed .github/agent/ prefix, not by the list of guard files outside it")

    def test_a_manifest_only_change_needs_a_record(self):
        self.commit_manifest('{"files": []}\n')
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertIn("no valid review record", out)
        self.assertIn(self.M, out)

    def test_a_manifest_only_change_with_a_current_record_passes(self):
        self.commit_manifest('{"files": []}\n')
        tree = self.run_main("--print-tree")[1].strip()
        rec = good(); rec["tree"] = tree
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("clears the stop rule", out)

    def test_editing_the_manifest_invalidates_an_existing_record(self):
        self.commit_manifest('{"files": []}\n')
        tree = self.run_main("--print-tree")[1].strip()
        rec = good(); rec["tree"] = tree
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        self.assertEqual(self.run_main("--base", self.base, "--head", "HEAD")[0], 0)
        self.commit_manifest('{"files": [{"path": "bin/x-test.sh", "sha256": "%s", "reason": "r"}]}\n' % ("0" * 64), "edited after the review")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertIn("no valid review record", out)
        self.assertIn(self.M, out)
        self.assertNotEqual(self.run_main("--print-tree")[1].strip(), tree)

    def test_the_tree_hash_covers_the_manifest_and_still_ignores_records_only(self):
        t0 = self.run_main("--print-tree")[1].strip()
        self.commit_manifest('{"files": []}\n')
        t1 = self.run_main("--print-tree")[1].strip()
        self.assertNotEqual(t0, t1)
        self.commit_manifest('{"files":   []}\n', "whitespace")
        t2 = self.run_main("--print-tree")[1].strip()
        self.assertNotEqual(t2, t1)
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % ("0" * 64), "{}")
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        self.assertEqual(self.run_main("--print-tree")[1].strip(), t2)

    def test_deleting_the_manifest_is_a_guarded_change(self):
        self.commit_manifest('{"files": []}\n')
        mid = self.git("rev-parse", "HEAD").strip()
        self.git("rm", "-q", self.M); self.git("commit", "-qm", "delete")
        rc, out, _ = self.run_main("--base", mid, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertIn(self.M, out)

    def test_an_unchanged_manifest_and_other_outside_changes_need_no_record(self):
        self.commit_manifest('{"files": []}\n')
        mid = self.git("rev-parse", "HEAD").strip()
        self.write("src/y", "t\n"); self.git("commit", "-qam", "outside")
        rc, out, _ = self.run_main("--base", mid, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("nothing to clear", out)

    def test_files_outside_the_prefix_are_not_reviewed(self):
        self.write(".github/supply-chain-harness.json", "x\n"); self.write(".github/supply-chain-exceptions.json", "{}\n")
        self.git("add", "-A"); self.git("commit", "-qm", "siblings")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)



if __name__ == "__main__":
    unittest.main(verbosity=2)
