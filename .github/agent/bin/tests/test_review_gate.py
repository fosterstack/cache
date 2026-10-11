# proves: REQ-AUD-018-AC3, REQ-AUD-018-AC4, REQ-AUD-018-AC5, REQ-AUD-018-AC6, REQ-AUD-018-AC7, REQ-AUD-018-AC8
"""auditor-review-gate.py (REQ-AUD-18 AC3, option C): every reason a review record fails to clear the gate, and the
CLI's argument and no-change paths, against a real temporary git repository. A record clears only with two Codex
seats on two different models (AC5, AC6); no substitute is accepted (AC4); a record merged before the dual-Codex gate
counts only as the same file already on the trusted revision (AC7); the workflow runs the gate in isolated mode from
the default branch's copy (AC8). Each test class names the AC it proves."""
import ast, contextlib, importlib.util, io, json, os, re, shutil, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.dirname(HERE)
SCRIPT = os.path.join(BIN, "auditor-review-gate.py")
_spec = importlib.util.spec_from_file_location("auditor_review_gate", SCRIPT)
G = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(G)
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(BIN)))
WF = os.path.join(ROOT, ".github", "workflows", "agent-review-gate.yml")

V2 = "auditor-review-record/v2"
V1 = "auditor-review-record/v1"
TREE = "ab" * 32
EVA = "cd" * 32
EVB = "ef" * 32
FIELDS = ("reviewer", "vendor", "seat", "model", "effort", "blockers_open", "evidence_sha256")


def seat(letter, model, effort="xhigh", **over):
    e = {"reviewer": "codex", "vendor": "openai", "seat": letter, "model": model, "effort": effort,
         "blockers_open": 0, "evidence_sha256": EVA if letter == "A" else EVB}
    e.update(over)
    return {k: v for k, v in e.items() if v is not ...}


def good(tree=TREE):
    """A complete schema v2 record: seat A gpt-6.1-sol, seat B gpt-6-astra, both xhigh, both clear."""
    return {"schema": V2, "tree": tree, "change": "test",
            "rounds": [{"round": 1, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol"),
                                                  "codex_b": seat("B", "gpt-6-astra")}}],
            "stop": {"codex_a": "clear", "codex_b": "clear"}}


def legacy(tree=TREE):
    """A schema v1 record of the shape merged before the dual-Codex gate."""
    ev = "12" * 32
    return {"schema": V1, "tree": tree,
            "rounds": [{"round": 1, "reviewers": {
                "codex": {"vendor": "openai", "blockers_open": 0, "evidence_sha256": ev},
                "sonnet": {"vendor": "anthropic", "blockers_open": 0, "evidence_sha256": "34" * 32}}}],
            "stop": {"codex": "clear", "sonnet": "clear"}}


def final(rec):
    return rec["rounds"][-1]["reviewers"]


def problems(rec, tree=TREE):
    return G.record_problems(rec, tree)


def named(probs, text):
    return any(text in p for p in probs)


# ---- REQ-AUD-018-AC5: the record that clears -------------------------------------------------------------------
class ClearingRecord(unittest.TestCase):
    """REQ-AUD-018-AC5."""

    def test_a_complete_v2_record_has_no_problems(self):
        self.assertEqual(problems(good()), [])

    def test_every_listed_model_pair_that_differs_clears(self):
        for a, b in (("gpt-6-sol", "gpt-6-astra"), ("gpt-6-luna", "gpt-6.1-sol"), ("gpt-6-astra", "gpt-6-luna"),
                     ("gpt-6.1-sol", "gpt-6-luna"), ("gpt-6-luna", "gpt-6-sol")):
            for effort in ("medium", "high", "xhigh"):
                r = good(); final(r)["codex_a"]["model"] = a; final(r)["codex_b"]["model"] = b
                final(r)["codex_a"]["effort"] = effort; final(r)["codex_b"]["effort"] = effort
                self.assertEqual(problems(r), [], (a, b, effort))

    def test_the_gate_s_own_lists_are_exactly_the_ratified_ones(self):
        self.assertEqual(sorted(G.CODEX_MODELS), ["gpt-6-astra", "gpt-6-luna", "gpt-6-sol", "gpt-6.1-sol"])
        self.assertEqual(sorted(G.EFFORTS), ["high", "medium", "xhigh"])
        self.assertEqual(G.SCHEMA, V2)
        self.assertEqual(G.SEATS, {"codex_a": "A", "codex_b": "B"})

    def test_not_an_object(self):
        self.assertEqual(problems([good()]), ["record is not a JSON object"])

    def test_a_wrong_tree_fails_naming_both_trees(self):
        self.assertIn("record binds tree %s, the change is %s" % (TREE, "99" * 32), problems(good(), tree="99" * 32))
        r = good(); del r["tree"]
        self.assertTrue(named(problems(r), "record binds tree None"))

    def test_no_rounds(self):
        for rounds in (None, [], "r1", ...):
            r = good()
            if rounds is ...:
                del r["rounds"]
            else:
                r["rounds"] = rounds
            self.assertEqual(problems(r), ["no review rounds recorded"], rounds)

    def test_final_round_without_reviewers(self):
        for fin in ("round", {"round": 2}, {"reviewers": ["codex_a", "codex_b"]}, None):
            r = good(); r["rounds"].append(fin)
            self.assertEqual(problems(r), ["final round names no reviewers"], fin)

    def test_only_the_FINAL_round_counts(self):
        r = good()
        r["rounds"].append({"round": 2, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol", blockers_open=1),
                                                       "codex_b": seat("B", "gpt-6-astra")}})
        self.assertTrue(named(problems(r), "codex_a blockers_open is 1"))
        r = good()        # a dirty first round and a clean final round clears
        r["rounds"].insert(0, {"round": 0, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol", blockers_open=3)}})
        self.assertEqual(problems(r), [])

    def test_every_missing_seat_field_fails_naming_it(self):
        for name, letter, model in (("codex_a", "A", "gpt-6.1-sol"), ("codex_b", "B", "gpt-6-astra")):
            for f in FIELDS:
                r = good(); del final(r)[name][f]
                ps = problems(r)
                self.assertIn("%s has no %s field" % (name, f), ps, (name, f))

    def test_an_extra_seat_field_fails_naming_it(self):
        for extra in ("tier", "note", "evidence", "Model"):
            r = good(); final(r)["codex_b"][extra] = "x"
            self.assertIn("codex_b has an extra field %r" % extra, problems(r), extra)

    def test_a_missing_or_malformed_stop_fails_naming_it(self):
        for stop in ("clear", None, [], ...):
            r = good()
            if stop is ...:
                del r["stop"]
            else:
                r["stop"] = stop
            ps = problems(r)
            self.assertIn("stop is missing or not an object", ps, stop)
        r = good(); del r["stop"]["codex_b"]
        self.assertIn("stop verdict for codex_b is None, want 'clear'", problems(r))

    def test_schema_is_named_when_record_problems_is_given_an_old_schema(self):
        for s in (V1, None, "auditor-review-record/v3", 2):
            r = good(); r["schema"] = s
            self.assertTrue(named(problems(r), "a schema v2 record is required"), s)

    def test_blockers_open_must_be_exactly_the_integer_zero(self):
        for bad in (None, "0", False, 0.0, 0.5, 1, -1, [0]):
            r = good(); final(r)["codex_a"]["blockers_open"] = bad
            self.assertEqual(problems(r), ["codex_a blockers_open is %r, want the integer 0" % (bad,)], bad)

    def test_evidence_must_be_64_lowercase_hex(self):
        for bad in (EVA.upper(), EVA[:63], EVA + "a", EVA + "\n", "", None, 7, "g" * 64):
            r = good(); final(r)["codex_b"]["evidence_sha256"] = bad
            self.assertIn("codex_b evidence_sha256 is not 64 lowercase hex characters", problems(r), repr(bad))

    def test_the_cli_prints_that_a_v2_record_clears(self):
        c = CliRepo(); c.start(self)
        c.change(".github/agent/bin/x.py", "b\n"); c.record(good)
        rc, out, _ = c.judge()
        self.assertEqual(rc, 0, out)
        self.assertIn("clears the stop rule (1 round(s))", out)


# ---- REQ-AUD-018-AC6: the refusals, one per shape ----------------------------------------------------------------
class Refusals(unittest.TestCase):
    """REQ-AUD-018-AC6."""

    def models(self, a, b):
        r = good(); final(r)["codex_a"]["model"] = a; final(r)["codex_b"]["model"] = b
        return problems(r)

    def test_the_same_model_twice_fails(self):
        for m in ("gpt-6-astra", "gpt-6-luna", "gpt-6-sol", "gpt-6.1-sol"):
            self.assertTrue(named(self.models(m, m), "codex_a and codex_b name the same model"), m)

    def test_gpt_6_sol_beside_gpt_6_1_sol_is_the_same_model(self):
        for a, b in (("gpt-6-sol", "gpt-6.1-sol"), ("gpt-6.1-sol", "gpt-6-sol")):
            self.assertTrue(named(self.models(a, b), "codex_a and codex_b name the same model"), (a, b))

    def test_a_missing_seat_fails_naming_it(self):
        for name in ("codex_a", "codex_b"):
            r = good(); del final(r)[name]; del r["stop"][name]
            self.assertIn("final round has no %s entry" % name, problems(r), name)
        r = good(); final(r).clear()
        ps = problems(r)
        self.assertIn("final round has no codex_a entry", ps)
        self.assertIn("final round has no codex_b entry", ps)

    def test_a_third_entry_fails_whatever_its_key_or_content(self):
        for key, entry in (("codex_c", seat("A", "gpt-6-luna", evidence_sha256="56" * 32)),
                           ("codex", seat("B", "gpt-6-luna", evidence_sha256="56" * 32)),
                           ("codex_a2", dict(seat("A", "gpt-6.1-sol"))),      # a valid copy of seat A
                           ("Codex_A", seat("A", "gpt-6-luna")),
                           ("x", {}), ("y", None), ("z", "clear")):
            r = good(); final(r)[key] = entry
            ps = problems(r)
            self.assertTrue(named(ps, "final round entry %r is not a seat" % key), (key, ps))

    def test_a_seat_from_another_reviewer_family_fails(self):
        for f, v, word in (("reviewer", "claude", "codex_b reviewer is 'claude', want 'codex'"),
                           ("reviewer", "Codex", "codex_b reviewer is 'Codex', want 'codex'"),
                           ("reviewer", None, "codex_b reviewer is None, want 'codex'"),
                           ("vendor", "anthropic", "codex_b vendor is 'anthropic', want 'openai'"),
                           ("vendor", "openai ", "codex_b vendor is 'openai ', want 'openai'"),
                           ("model", "some-other-model", "codex_b model 'some-other-model' is not on the gate's list of Codex models")):
            r = good(); final(r)["codex_b"][f] = v
            self.assertIn(word, problems(r), (f, v))

    def test_a_model_or_effort_off_the_lists_fails(self):
        for m in ("gpt-5", "gpt-6-sol-mini", "", "GPT-6-ASTRA", "gpt-6-astra ", None, 6):
            r = good(); final(r)["codex_a"]["model"] = m
            self.assertIn("codex_a model %r is not on the gate's list of Codex models" % (m,), problems(r), m)
        for e in ("low", "XHIGH", "", "minimal", None, 3):
            r = good(); final(r)["codex_b"]["effort"] = e
            self.assertIn("codex_b effort %r is not on the gate's list of efforts" % (e,), problems(r), e)

    def test_a_seat_letter_that_does_not_match_its_key_fails(self):
        r = good(); final(r)["codex_a"]["seat"] = "B"
        self.assertIn("codex_a seat is 'B', want 'A'", problems(r))
        r = good(); final(r)["codex_b"]["seat"] = "a"
        self.assertIn("codex_b seat is 'a', want 'B'", problems(r))
        r = good(); final(r)["codex_a"], final(r)["codex_b"] = final(r)["codex_b"], final(r)["codex_a"]
        ps = problems(r)
        self.assertIn("codex_a seat is 'B', want 'A'", ps)
        self.assertIn("codex_b seat is 'A', want 'B'", ps)

    def test_an_open_blocker_in_either_seat_fails_naming_it(self):
        for name in ("codex_a", "codex_b"):
            r = good(); final(r)[name]["blockers_open"] = 2
            self.assertEqual(problems(r), ["%s blockers_open is 2, want the integer 0" % name])

    def test_the_same_evidence_hash_in_both_seats_fails(self):
        r = good(); final(r)["codex_b"]["evidence_sha256"] = EVA
        self.assertEqual(problems(r), ["codex_a and codex_b have the same evidence_sha256: a copied entry is not an independent review"])

    def test_a_stop_verdict_that_is_not_clear_or_an_extra_stop_key_fails(self):
        for name in ("codex_a", "codex_b"):
            for v in ("blocked", "Clear", None, True):
                r = good(); r["stop"][name] = v
                self.assertIn("stop verdict for %s is %r, want 'clear'" % (name, v), problems(r), (name, v))
        for k in ("sonnet", "codex", "opus", "codex_c"):
            r = good(); r["stop"][k] = "clear"
            self.assertEqual(problems(r), ["stop holds an extra key %r" % k], k)

    def test_a_seat_entry_that_is_not_an_object_fails_naming_it(self):
        for bad in (None, [], "codex", 0, True):
            r = good(); final(r)["codex_a"] = bad
            self.assertIn("codex_a entry is not an object (%r)" % (bad,), problems(r), bad)

    def test_two_shapes_are_both_reported(self):
        r = good(); final(r)["codex_a"]["blockers_open"] = 1; final(r)["codex_b"]["model"] = "gpt-6.1-sol"
        final(r)["codex_a"]["model"] = "gpt-6-sol"
        ps = problems(r)
        self.assertIn("codex_a blockers_open is 1, want the integer 0", ps)
        self.assertTrue(named(ps, "codex_a and codex_b name the same model"))


# ---- REQ-AUD-018-AC4: no substitute is accepted ------------------------------------------------------------------
class NoSubstitute(unittest.TestCase):
    """REQ-AUD-018-AC4."""

    OPUS = {"vendor": "anthropic", "substitute_for": "codex", "substitute_id": "0350", "model": "opus",
            "effort": "medium", "blockers_open": 0, "evidence_sha256": "77" * 32}

    def test_an_entry_under_another_key_in_place_of_a_seat_fails_saying_no_substitute(self):
        for key in ("opus", "sonnet", "claude", "codex"):
            r = good(); del final(r)["codex_b"]; final(r)[key] = dict(self.OPUS)
            ps = problems(r)
            self.assertTrue(named(ps, "final round entry %r is not a seat" % key), (key, ps))
            self.assertTrue(named(ps, "no substitute is accepted"), (key, ps))
            self.assertIn("final round has no codex_b entry", ps)

    def test_a_seat_entry_carrying_a_substitute_field_fails(self):
        for f in ("substitute_for", "substitute_id"):
            for name in ("codex_a", "codex_b"):
                r = good(); final(r)[name][f] = "codex"
                ps = problems(r)
                self.assertTrue(named(ps, "no substitute is accepted"), (f, name, ps))
                self.assertTrue(named(ps, f), (f, name, ps))

    def test_a_record_that_names_a_substitutes_entry_anywhere_fails(self):
        for where in ("top", "round", "stop", "earlier", "nested"):
            r = good()
            if where == "top":
                r["substitute_id"] = "0350"
            elif where == "round":
                r["rounds"][-1]["substitutes"] = ["0350"]
            elif where == "stop":
                r["stop"]["substitute"] = "0350"
            elif where == "earlier":
                r["rounds"].insert(0, {"round": 0, "reviewers": {"opus": dict(self.OPUS)}})
            else:
                r["residuals"] = [{"Substitute_For": "codex"}]
            self.assertTrue(named(problems(r), "no substitute is accepted"), where)

    def test_the_gate_reads_no_substitutes_allow_list_and_no_clock(self):
        with open(SCRIPT) as fh:
            src = fh.read()
        self.assertNotIn("substitutes.json", src)
        self.assertFalse(hasattr(G, "SUBS_PATH"))
        self.assertFalse(hasattr(G, "_utcnow"))
        bad = []
        for n in ast.walk(ast.parse(src)):
            if isinstance(n, ast.Import):
                bad += [a.name for a in n.names if a.name.split(".")[0] in ("datetime", "time", "calendar", "os")]
            if isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] in ("datetime", "time", "calendar", "os"):
                bad.append(n.module)
            if isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv", "environb", "putenv", "now", "utcnow", "today"):
                bad.append("line %d: %s" % (n.lineno, n.attr))
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and (
                    "GATE_NOW" in n.value or n.value in ("--now", "--clock", "--time", "--as-of", "--substitute")):
                bad.append("line %d: %r" % (n.lineno, n.value[:40]))
        self.assertEqual(bad, [])

    def test_the_substitutes_allow_list_file_is_gone(self):
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(BIN), "reviews", "substitutes.json")))

    def test_no_workflow_or_action_file_can_set_a_clock_or_a_substitute(self):
        files = []
        for base, dirs, names in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            for n in names:
                rel = os.path.relpath(os.path.join(base, n), ROOT)
                if (rel.startswith(os.path.join(".github", "workflows") + os.sep) and n.endswith((".yml", ".yaml"))) \
                        or n in ("action.yml", "action.yaml"):
                    files.append(os.path.join(base, n))
        self.assertTrue(any(f.endswith("agent-review-gate.yml") for f in files))
        bad = []
        for f in files:
            with open(f) as fh:
                text = fh.read()
            if "GATE_NOW" in text or re.search(r"--now\b|--substitute", text):
                bad.append(os.path.relpath(f, ROOT))
        self.assertEqual(bad, [])


# ---- the CLI over a real temporary git repository (AC3 to AC7) ---------------------------------------------------
class CliRepo:
    """A temporary repository: main holds .github/agent/bin/x.py and src/y; helpers commit changes and records."""

    def start(self, case, branch="main"):
        self.d = tempfile.mkdtemp(); case.addCleanup(shutil.rmtree, self.d)
        cwd = os.getcwd(); os.chdir(self.d); case.addCleanup(os.chdir, cwd)
        self.git("init", "-q", "-b", branch)
        os.makedirs(".github/agent/bin"); os.makedirs("src")
        self.write(".github/agent/bin/x.py", "a\n"); self.write("src/y", "s\n")
        self.git("add", "-A"); self.git("commit", "-qm", "base")
        self.base = self.rev()
        return self

    def git(self, *a):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *a],
                              check=True, capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout

    def rev(self, r="HEAD"):
        return self.git("rev-parse", r).strip()

    def write(self, p, t, mode="w"):
        if os.path.dirname(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, mode) as fh:
            fh.write(t)

    def change(self, p, t):
        self.write(p, t); self.git("add", "-A"); self.git("commit", "-qm", "change " + p)

    def tree(self):
        return run_main("--print-tree")[1].strip()

    def record(self, make, raw=None):
        """Write make(tree) (or raw bytes) as the record of the current content and commit it; returns its path."""
        t = self.tree()
        path = ".github/agent/reviews/%s.json" % t
        self.write(path, raw if raw is not None else json.dumps(make(t), indent=2) + "\n")
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        return path

    def judge(self, *extra, base=None):
        return run_main("--base", base or self.base, "--head", "HEAD", *extra)


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = G.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    """REQ-AUD-018-AC3: a change under the auditor directory needs a record bound to its exact content."""

    def setUp(self):
        self.r = CliRepo().start(self)
        self.base = self.r.base

    def test_base_is_required(self):
        rc, out, err = run_main("--head", "HEAD")
        self.assertEqual(rc, 2)
        self.assertIn("--base is required", err)

    def test_a_flag_without_a_value_is_missing_not_a_crash(self):
        rc, out, err = run_main("--head", "HEAD", "--base")
        self.assertEqual(rc, 2)
        self.assertIn("--base is required", err)

    def test_a_bad_pr_argument_is_refused(self):
        self.r.change(".github/agent/bin/x.py", "b\n"); self.r.record(good)
        for argv in (("--pr",), ("--pr", "x"), ("--pr", "-1"), ("--pr", ""), ("--pr", "0210")):
            rc, _, err = self.r.judge(*argv)
            self.assertEqual(rc, 2, argv)
            self.assertIn("--pr", err)
        self.assertEqual(self.r.judge("--pr", "210")[0], 0)

    def test_a_trusted_revision_flag_without_a_value_is_refused(self):
        self.r.change(".github/agent/bin/x.py", "b\n"); self.r.record(good)
        rc, _, err = self.r.judge("--subs-rev")
        self.assertEqual(rc, 2)
        self.assertIn("--subs-rev", err)

    def test_print_tree_is_stable_and_ignores_records_only(self):
        t1 = self.r.tree()
        self.r.change(".github/agent/reviews/%s.json" % ("0" * 64), "{}")
        self.assertEqual(self.r.tree(), t1)                      # a record: same tree
        self.r.change(".github/agent/reviews/notes.txt", "x")
        self.assertNotEqual(self.r.tree(), t1)                   # anything else: new tree

    def test_no_auditor_change_needs_no_record(self):
        self.r.change("src/y", "t\n")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 0)
        self.assertIn("no change under .github/agent/", out)

    def test_no_record_fails_naming_the_path(self):
        self.r.change(".github/agent/bin/x.py", "b\n")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("no valid review record", out)
        self.assertIn("Codex", out)

    def test_invalid_record_json_fails_with_its_path(self):
        self.r.change(".github/agent/bin/x.py", "b\n")
        path = self.r.record(None, raw="{not json")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn(path, out)
        self.assertIn("no valid review record", out)

    def test_a_stale_record_fails(self):
        self.r.change(".github/agent/bin/x.py", "b\n"); self.r.record(good)
        self.r.change(".github/agent/bin/x.py", "c\n")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("no valid review record", out)

    def test_a_record_that_does_not_clear_fails_naming_each_cause(self):
        self.r.change(".github/agent/bin/x.py", "b\n")
        def bad(t):
            r = good(t); r["stop"]["codex_b"] = "blocked"; final(r)["codex_b"]["model"] = "gpt-6.1-sol"; return r
        path = self.r.record(bad)
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("::error file=%s::review gate: stop verdict for codex_b is 'blocked'" % path, out)
        self.assertIn("codex_a and codex_b name the same model", out)

    def test_a_record_with_a_wrong_tree_at_the_right_path_fails(self):
        self.r.change(".github/agent/bin/x.py", "b\n")
        self.r.record(lambda t: good("99" * 32))
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("record binds tree %s" % ("99" * 32), out)


class GuardFiles(unittest.TestCase):
    """REQ-AUD-018-AC3: the allowlist guard's own files sit outside the auditor directory but are review-gated too."""
    GUARDS = ("bin/check-file-allowlist.sh", "bin/check-file-allowlist-test.sh", ".github/workflows/agent-review-gate.yml")

    def setUp(self):
        self.r = CliRepo().start(self)
        for g in self.GUARDS:
            self.r.write(g, "v1\n")
        self.r.write(".github/workflows/ci.yml", "ci1\n")
        self.r.git("add", "-A"); self.r.git("commit", "-qm", "guards")
        self.r.base = self.base = self.r.rev()

    def test_each_guard_file_alone_needs_a_record(self):
        for g in self.GUARDS:
            self.r.git("reset", "-q", "--hard", self.base)
            self.r.change(g, "v2\n")
            rc, out, _ = self.r.judge()
            self.assertEqual(rc, 1, g)
            self.assertIn("no valid review record", out)
            self.assertIn(g, out)

    def test_a_matching_record_clears_a_guard_only_change(self):
        self.r.change("bin/check-file-allowlist.sh", "v2\n"); self.r.record(good)
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 0, out)
        self.assertIn("clears the stop rule", out)

    def test_a_stale_record_does_not_clear_a_later_guard_change(self):
        self.r.change("bin/check-file-allowlist.sh", "v2\n"); self.r.record(good)
        self.r.change("bin/check-file-allowlist.sh", "v3\n")
        self.assertEqual(self.r.judge()[0], 1)

    def test_an_old_record_cannot_be_replayed_over_a_guard_change(self):
        self.r.change(".github/agent/bin/x.py", "b\n"); self.r.record(good)
        mid = self.r.rev()
        self.r.change("bin/check-file-allowlist-test.sh", "v2\n")
        self.assertEqual(self.r.judge(base=mid)[0], 1)

    def test_deleting_a_guard_file_is_a_change(self):
        self.r.git("rm", "-q", "bin/check-file-allowlist.sh"); self.r.git("commit", "-qm", "delete")
        self.assertEqual(self.r.judge()[0], 1)

    def test_other_files_including_ci_yml_are_unaffected(self):
        self.r.write(".github/workflows/ci.yml", "ci2\n"); self.r.change("src/y", "t\n")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 0)
        self.assertIn("nothing to clear", out)
        t = self.r.tree()
        self.r.change(".github/workflows/ci.yml", "ci3\n")
        self.assertEqual(self.r.tree(), t)      # ci.yml is not part of the bound content

    def test_a_rename_out_of_the_auditor_directory_is_a_change(self):
        self.r.change(".github/agent/bin/x.py", "b\n"); self.r.record(good)
        mid = self.r.rev()
        self.r.git("mv", ".github/agent/bin/x.py", "src/x.py"); self.r.git("commit", "-qm", "move out")
        self.assertEqual(self.r.judge(base=mid)[0], 1)


class SubstituteCli(unittest.TestCase):
    """REQ-AUD-018-AC4: on the CLI, no substitute counts: not with an allow-list on the trusted revision, not with any
    option, and a missing Codex seat (an outage) leaves the change failing."""

    SUBS = {"schema": "review-substitutes/v1", "substitutes": [
        {"id": "0350", "for": "codex", "by": "opus", "vendor": "anthropic", "effective_until": "2099-01-01T00:00:00Z",
         "owner_quote": "x", "scope": "all"}]}

    def setUp(self):
        self.r = CliRepo().start(self)
        self.r.change(".github/agent/reviews/substitutes.json", json.dumps(self.SUBS))   # on the trusted revision
        self.r.base = self.trusted = self.r.rev()
        self.r.change(".github/agent/bin/x.py", "b\n")

    def subrec(self, t):
        r = good(t); del final(r)["codex_b"]; del r["stop"]["codex_b"]
        final(r)["opus"] = dict(NoSubstitute.OPUS); r["rounds"][-1]["completed_at"] = "2026-10-11T00:00:00Z"
        r["stop"]["opus"] = "clear"
        return r

    def test_an_unexpired_allow_list_entry_on_the_trusted_revision_does_not_make_a_substitute_count(self):
        self.r.record(self.subrec)
        for extra in ((), ("--subs-rev", self.trusted), ("--subs-rev", self.trusted, "--pr", "1")):
            rc, out, _ = self.r.judge(*extra)
            self.assertEqual(rc, 1, (extra, out))
            self.assertIn("no substitute is accepted", out)
            self.assertIn("final round has no codex_b entry", out)

    def test_unknown_options_do_not_make_a_substitute_count(self):
        self.r.record(self.subrec)
        for opt in (("--substitute", "0350"), ("--now", "2026-10-11T00:00:00Z"), ("--allow-substitute",)):
            rc, out, _ = self.r.judge(*opt)
            self.assertNotEqual(rc, 0, opt)

    def test_a_codex_outage_leaves_the_change_waiting(self):
        def only_a(t):
            r = good(t); del final(r)["codex_b"]; del r["stop"]["codex_b"]; return r
        self.r.record(only_a)
        rc, out, _ = self.r.judge("--subs-rev", self.trusted)
        self.assertEqual(rc, 1)
        self.assertIn("final round has no codex_b entry", out)

    def test_an_environment_value_does_not_make_a_substitute_count(self):
        self.r.record(self.subrec)
        env = dict(os.environ, GATE_NOW="2026-10-01T00:00:00Z", GATE_SUBSTITUTE="0350", TZ="Etc/GMT-14")
        p = subprocess.run([sys.executable, "-I", SCRIPT, "--base", self.r.base, "--head", "HEAD", "--subs-rev", self.trusted],
                           capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("no substitute is accepted", p.stdout)


# ---- REQ-AUD-018-AC7: records merged before the dual-Codex gate --------------------------------------------------
class LegacyRecord(unittest.TestCase):
    """REQ-AUD-018-AC7: an old-schema record counts only as the same blob already on the trusted revision."""

    def setUp(self):
        self.r = CliRepo().start(self)

    def merged_legacy(self, make=legacy, raw=None):
        """main: the content x.py=b was reviewed and its v1 record merged; then main moved on to x.py=c.
        A pull request restoring x.py=b carries that same record, unchanged. Returns the record path."""
        self.r.change(".github/agent/bin/x.py", "b\n")
        path = self.r.record(make, raw=raw)
        self.r.change(".github/agent/bin/x.py", "c\n")
        self.r.base = self.trusted = self.r.rev()
        self.r.change(".github/agent/bin/x.py", "b\n")          # the PR: a pure revert to the reviewed tree
        return path

    def test_a_v1_record_byte_identical_on_the_trusted_revision_clears_without_re_judging(self):
        path = self.merged_legacy()
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 0, out)
        self.assertIn("already on the trusted revision", out)
        self.assertIn(path, out)

    def test_the_merged_record_whose_substitute_expired_still_clears_it_is_never_re_judged(self):
        real = os.path.join(os.path.dirname(BIN), "reviews",
                            "d8a4733f6eecb148c03e42ee6e376cdfa8c9e4fa1e983398db0af4c50ba7c941.json")
        with open(real) as fh:
            raw = fh.read()
        self.assertIn('"substitute_id": "0317"', raw)      # the opus record merged under the retired substitute
        self.merged_legacy(raw=raw)                          # its tree field does not match: not re-judged
        rc, out, _ = self.r.judge("--subs-rev", self.trusted)
        self.assertEqual(rc, 0, out)

    def test_a_v1_record_added_by_the_pull_request_fails(self):
        self.r.change(".github/agent/bin/x.py", "b\n")
        path = self.r.record(legacy)
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("a schema v2 record is required", out)
        self.assertIn(path, out)

    def test_a_v1_record_on_the_trusted_revision_edited_by_the_pull_request_fails(self):
        path = self.merged_legacy()
        self.r.write(path, " ", mode="a"); self.r.git("commit", "-qam", "one byte")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("a schema v2 record is required", out)

    def test_an_unreadable_trusted_revision_fails_closed(self):
        self.merged_legacy()
        for bad in ("no-such-ref", "0" * 40, "HEAD:src"):
            rc, out, _ = self.r.judge("--subs-rev", bad)
            self.assertEqual(rc, 1, (bad, out))
            self.assertIn("the trusted revision %r cannot be read" % bad, out)

    def test_a_pr_faking_the_old_shape_fails(self):
        self.r.change(".github/agent/bin/x.py", "b\n")
        self.r.record(legacy)                               # codex + sonnet, schema v1, never on main
        rc, out, _ = self.r.judge("--subs-rev", self.r.base)
        self.assertEqual(rc, 1)
        self.assertIn("a schema v2 record is required", out)
        for schema in (None, "auditor-review-record/v0", "auditor-review-record/v3"):
            self.r.git("reset", "-q", "--hard", self.r.base)
            self.r.change(".github/agent/bin/x.py", "b\n")
            self.r.record(lambda t: dict(legacy(t), schema=schema))
            rc, out, _ = self.r.judge()
            self.assertEqual(rc, 1, schema)
            self.assertIn("a schema v2 record is required", out)

    def test_a_non_object_record_fails_unless_it_is_the_merged_file(self):
        self.r.change(".github/agent/bin/x.py", "b\n")
        self.r.record(None, raw="[1, 2]\n")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("a schema v2 record is required", out)

    def test_the_trusted_revision_can_be_main_s_tip_rather_than_the_merge_base(self):
        # the record merged on main AFTER the PR branched: the merge base lacks it, main's tip (--subs-rev) has it
        self.r.change(".github/agent/bin/x.py", "b\n")
        path = self.r.record(legacy)
        tip = self.r.rev()
        self.r.git("checkout", "-q", "-b", "pr", self.r.base)
        self.r.change(".github/agent/bin/x.py", "b\n")
        self.r.write(path, self.r.git("show", "%s:%s" % (tip, path)))
        self.r.git("add", "-A"); self.r.git("commit", "-qm", "the same record")
        self.assertEqual(self.r.judge()[0], 1)                   # the merge base lacks it
        rc, out, _ = self.r.judge("--subs-rev", tip)
        self.assertEqual(rc, 0, out)

    def test_a_v2_record_is_judged_by_the_v2_rules_even_when_it_is_on_the_trusted_revision(self):
        def blocked(t):
            r = good(t); final(r)["codex_a"]["blockers_open"] = 1; return r
        self.merged_legacy(make=blocked)
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("codex_a blockers_open is 1", out)


# ---- REQ-AUD-018-AC8: the workflow runs the gate in isolated mode from the default branch's copy -----------------
class Wiring(unittest.TestCase):
    """REQ-AUD-018-AC8 (and the trusted revision of AC7): the gate's workflow, read as it is on this branch."""

    @staticmethod
    def wf():
        import yaml
        with open(WF) as fh:
            return yaml.safe_load(fh)

    def runs(self, job):
        return [st for st in self.wf()["jobs"][job]["steps"]]

    def code_lines(self, job):
        return [l for st in self.runs(job) for l in st.get("run", "").replace("\\\n", " ").splitlines()
                if not l.lstrip().startswith("#")]

    def test_the_gate_and_the_pin_checker_run_in_python_isolated_mode(self):
        lines = [l for j in ("judge", "sweep") for l in self.code_lines(j)]
        calls = [m for l in lines for m in re.finditer(r"\bpython3?((?:\s+-\S+)*)\s+(\.github/agent/bin/\S+)", l)]
        self.assertEqual(sorted(m.group(2) for m in calls),      # judge: gate, pins; sweep: gate, pins
                         [".github/agent/bin/auditor-review-gate.py"] * 2 + [".github/agent/bin/check-action-pins.py"] * 2)
        for m in calls:
            self.assertEqual(m.group(1).split(), ["-I"], m.group(0))
        self.assertEqual(len([l for l in lines if re.search(r"\bpython3?\b", l)]), 3, lines)   # no other python run

    def test_the_gate_reads_the_head_and_the_trusted_revision_as_git_data_only(self):
        for job, pr in (("judge", '--pr "$PR"'), ("sweep", '--pr "$n"')):
            gate = [l for l in self.code_lines(job) if "auditor-review-gate.py" in l and "python3" in l]
            self.assertEqual(len(gate), 1, (job, gate))
            self.assertIn("--subs-rev HEAD", gate[0])          # the trusted revision: the checked-out default branch
            self.assertEqual(gate[0].count("--subs-rev"), 1)
            self.assertIn(pr, gate[0])
            text = "\n".join(self.code_lines(job))
            for verb in ("git checkout", "git switch", "git worktree", "git restore", "git reset", "pip install"):
                self.assertNotIn(verb, text, (job, verb))
            for st in self.runs(job):
                if "actions/checkout@" in str(st.get("uses", "")):
                    self.assertFalse({"ref", "repository"} & set(st.get("with") or {}), (job, st))

    def test_no_job_sets_a_gate_variable(self):
        for name, job in self.wf()["jobs"].items():
            self.assertFalse([k for k in (job.get("env") or {}) if str(k).startswith("GATE_")], name)
            for st in job["steps"]:
                self.assertFalse([k for k in (st.get("env") or {}) if str(k).startswith("GATE_")], (name, st.get("name")))
                self.assertNotIn("GITHUB_ENV", st.get("run", "") + str(st.get("with", "")), (name, st.get("name")))

    def test_the_requirement_text_never_names_the_auditor_directory_literally(self):
        # REQ-AUD-18 AC1: a file outside the auditor directory may not refer to it by its literal path prefix.
        for rel in ("requirements/requirements.yaml", "docs/quality/traceability.md"):
            with open(os.path.join(ROOT, rel)) as fh:
                self.assertNotIn(".github/agent/", fh.read(), rel)

    def test_the_isolated_subprocess_gate_clears_a_v2_record(self):
        r = CliRepo().start(self)
        r.change(".github/agent/bin/x.py", "b\n"); r.record(good)
        p = subprocess.run([sys.executable, "-I", SCRIPT, "--base", r.base, "--head", "HEAD", "--subs-rev", r.base],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("clears the stop rule", p.stdout)


class HarnessManifest(unittest.TestCase):
    """REQ-AUD-018-AC3: the reviewed harness manifest (REQ-SUP-001 AC11) lies under the auditor directory, so a change
    to it needs a current review record, and any edit of it invalidates a record made before."""
    M = ".github/agent/supply-chain/harness-manifest.json"

    def setUp(self):
        self.r = CliRepo().start(self)

    def test_the_manifest_is_under_the_reviewed_prefix(self):
        self.assertTrue(self.M.startswith(G.AGENT))
        self.assertNotIn(self.M, G.GUARDED)

    def test_a_manifest_only_change_needs_a_record(self):
        self.r.change(self.M, '{"files": []}\n')
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("no valid review record", out)
        self.assertIn(self.M, out)

    def test_a_manifest_only_change_with_a_current_record_passes_and_an_edit_invalidates_it(self):
        self.r.change(self.M, '{"files": []}\n'); self.r.record(good)
        self.assertEqual(self.r.judge()[0], 0)
        self.r.change(self.M, '{"files":   []}\n')
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn(self.M, out)

    def test_files_outside_the_prefix_are_not_reviewed(self):
        self.r.write(".github/supply-chain-harness.json", "x\n"); self.r.change(".github/supply-chain-exceptions.json", "{}\n")
        self.assertEqual(self.r.judge()[0], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
