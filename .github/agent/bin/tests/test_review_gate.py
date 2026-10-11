# proves: REQ-AUD-018-AC3, REQ-AUD-018-AC4, REQ-AUD-018-AC5, REQ-AUD-018-AC6, REQ-AUD-018-AC7, REQ-AUD-018-AC8
"""auditor-review-gate.py (REQ-AUD-18 AC3, option C): every reason a review record fails to clear the gate, and the
CLI's argument and no-change paths, against a real temporary git repository. A record clears only with its two
review seats on two different listed models (AC5, AC6); no substitute is accepted (AC4); a record merged before the
schema v2 gate counts only as the same file already at the merge base and on the trusted revision, unchanged by the pull
request (AC7); the workflow runs the gate in isolated mode from the default branch's copy (AC8). Each test class names
the AC it proves."""
import ast, contextlib, importlib.util, io, json, os, re, shutil, subprocess, sys, tempfile, unittest, unittest.mock

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
NO_SUB = "no substitute is accepted"
PERMITTED_ONLY = "only the permitted fields are read, and no substitute is accepted"
ANCHOR = '"schema": "%s"' % V2      # where a raw-JSON test inserts a top-level field


def seat(letter, model, effort="xhigh", **over):
    e = {"reviewer": "codex", "vendor": "openai", "seat": letter, "model": model, "effort": effort,
         "blockers_open": 0, "evidence_sha256": EVA if letter == "A" else EVB}
    e.update(over)
    return {k: v for k, v in e.items() if v is not ...}


def good(tree=TREE):
    """A complete schema v2 record: seats A and B on two different listed models, both clear."""
    return {"schema": V2, "tree": tree,
            "rounds": [{"round": 1, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol"),
                                                  "codex_b": seat("B", "gpt-6-astra")}}],
            "stop": {"codex_a": "clear", "codex_b": "clear"}}


def legacy(tree=TREE):
    """A schema v1 record of the shape merged before the schema v2 gate."""
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
        for fin in ("round", {"round": 2}, {"round": 2, "reviewers": ["codex_a", "codex_b"]}, None):
            r = good(); r["rounds"].append(fin)
            self.assertEqual(problems(r), ["final round names no reviewers"], fin)

    def test_only_the_FINAL_round_counts(self):
        r = good()
        r["rounds"].append({"round": 2, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol", blockers_open=1),
                                                       "codex_b": seat("B", "gpt-6-astra")}})
        self.assertTrue(named(problems(r), "codex_a blockers_open is 1"))
        r = good()        # a dirty first round and a clean final round clears
        r["rounds"][0]["round"] = 2
        r["rounds"].insert(0, {"round": 1, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol", blockers_open=3)}})
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
            self.assertIn("codex_b has an extra field %r: %s" % (extra, PERMITTED_ONLY), problems(r), extra)

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
            self.assertEqual(problems(r), ["codex_a blockers_open is %s, want the integer 0" % G._show(bad)], bad)

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
            self.assertEqual(problems(r), ["stop holds an extra key %r: %s" % (k, PERMITTED_ONLY)], k)

    def test_a_seat_entry_that_is_not_an_object_fails_naming_it(self):
        for bad in (None, [], "codex", 0, True):
            r = good(); final(r)["codex_a"] = bad
            self.assertIn("codex_a entry is not an object (%s)" % G._show(bad), problems(r), bad)

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
                r["rounds"][0]["round"] = 2
                r["rounds"].insert(0, {"round": 1, "reviewers": {"opus": dict(self.OPUS)}})
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


# ---- REQ-AUD-018-AC5 and AC4: the permitted fields, at every level ----------------------------------------------
class PermittedFields(unittest.TestCase):
    """REQ-AUD-018-AC5 ("any missing, extra, mistyped or malformed field fails") and AC4 ("a record that names a
    substitutes allow-list entry"): the record, every round and every seat entry hold only their permitted fields;
    anything else is refused, naming it and saying that no substitute is accepted."""

    def test_the_permitted_field_sets_are_exactly_these(self):
        self.assertEqual(sorted(G.RECORD_REQUIRED), ["rounds", "schema", "stop", "tree"])
        self.assertEqual(sorted(G.RECORD_OPTIONAL), ["reviewed_commit"])
        self.assertEqual(sorted(G.ROUND_REQUIRED), ["reviewers", "round"])
        self.assertEqual(sorted(G.ROUND_OPTIONAL), [])
        self.assertEqual(tuple(G.FIELDS), FIELDS)

    def test_a_complete_record_with_every_optional_field_clears(self):
        r = good(); r["reviewed_commit"] = "1f" * 20
        self.assertEqual(problems(r), [])

    def test_an_extra_top_level_field_fails_naming_it_and_saying_no_substitute(self):
        # other ways a record could name an allow-list entry: none is a permitted field
        for key in ("allowlist_entry", "allow_list", "allowlist", "allow-list", "exception", "exceptions", "waiver",
                    "override", "entry", "entry_id", "ref", "references", "approved_by", "owner_decision",
                    "evidence_location", "closed_commit", "completed_at", "x", "", "Schema"):
            for v in ("0317", ["0350"], {"id": "0350"}, None, 1):
                r = good(); r[key] = v
                ps = problems(r)
                self.assertIn("record has an extra field %r: %s" % (key, PERMITTED_ONLY), ps, (key, v, ps))

    def test_an_extra_field_in_the_final_or_an_earlier_round_fails(self):
        for key in ("allowlist_entry", "completed_at", "exception", "x"):
            r = good(); r["rounds"][-1][key] = "0317"
            self.assertIn("rounds[0] has an extra field %r: %s" % (key, PERMITTED_ONLY), problems(r), key)
            r = good(); r["rounds"][0]["round"] = 2
            r["rounds"].insert(0, {"round": 1, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol")}, key: "0317"})
            self.assertIn("rounds[0] has an extra field %r: %s" % (key, PERMITTED_ONLY), problems(r), key)

    def test_an_allow_list_reference_in_a_seat_or_the_stop_block_fails(self):
        for key in ("allowlist_entry", "exception", "waiver"):
            r = good(); final(r)["codex_a"][key] = "0317"
            self.assertIn("codex_a has an extra field %r: %s" % (key, PERMITTED_ONLY), problems(r), key)
            r = good(); r["stop"][key] = "0317"
            self.assertIn("stop holds an extra key %r: %s" % (key, PERMITTED_ONLY), problems(r), key)

    def test_a_string_value_that_names_a_substitute_fails(self):
        for where in ("change", "label", "residuals"):
            for text in (".github/agent/reviews/substitutes.json#0350", "SUBSTITUTE 0317", "a substitution"):
                r = good()
                if where == "change":
                    r["change"] = text
                elif where == "label":
                    r["rounds"][0]["label"] = text
                else:
                    r["residuals"] = ["fine", text]
                ps = problems(r)
                self.assertTrue(named(ps, "names a substitute"), (where, text, ps))
                self.assertTrue(named(ps, NO_SUB), (where, text, ps))

    def test_the_optional_fields_are_typed(self):
        for f, bad, msg in (("reviewed_commit", "1F" * 20, "record reviewed_commit is not 40 lowercase hex characters"),
                            ("reviewed_commit", "1f" * 32, "record reviewed_commit is not 40 lowercase hex characters"),
                            ("reviewed_commit", None, "record reviewed_commit is not 40 lowercase hex characters"),
                            ("reviewed_commit", "pr210", "record reviewed_commit is not 40 lowercase hex characters")):
            r = good(); r[f] = bad
            self.assertIn(msg, problems(r), (f, bad))

    def test_every_round_needs_a_positive_increasing_round_number(self):
        for bad in (..., None, 0, -1, True, "1", 1.0, [1]):
            r = good()
            if bad is ...:
                del r["rounds"][0]["round"]
                want = "rounds[0] has no round field"
            else:
                r["rounds"][0]["round"] = bad
                want = "rounds[0] round is %s, want a positive integer" % G._show(bad)
            self.assertIn(want, problems(r), bad)
        for first, second in ((2, 2), (3, 2)):
            r = good(); r["rounds"][0]["round"] = second
            r["rounds"].insert(0, {"round": first, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol")}})
            self.assertIn("rounds[1] round %d does not follow round %d" % (second, first), problems(r), (first, second))

    def test_an_earlier_round_is_held_to_the_same_fields(self):
        def with_earlier(rv):
            r = good(); r["rounds"][0]["round"] = 2
            r["rounds"].insert(0, {"round": 1, "reviewers": rv})
            return problems(r)
        self.assertEqual(with_earlier({"codex_b": seat("B", "gpt-6-astra", blockers_open=4)}), [])
        for rv, want in (({}, "rounds[0] reviewers is not a non-empty object"),
                         (None, "rounds[0] reviewers is not a non-empty object"),
                         (["codex_a"], "rounds[0] reviewers is not a non-empty object"),
                         ({"opus": {}}, "rounds[0] entry 'opus' is not a seat (only codex_a and codex_b take a seat): " + NO_SUB),
                         ({"codex_a": {k: v for k, v in seat("A", "gpt-6.1-sol").items() if k != "model"}}, "rounds[0].codex_a has no model field"),
                         ({"codex_a": seat("A", "gpt-6.1-sol", vendor="anthropic")}, "rounds[0].codex_a vendor is 'anthropic', want 'openai'"),
                         ({"codex_a": seat("A", "some-model")}, "rounds[0].codex_a model 'some-model' is not on the gate's list of Codex models"),
                         ({"codex_a": seat("B", "gpt-6.1-sol")}, "rounds[0].codex_a seat is 'B', want 'A'"),
                         ({"codex_a": seat("A", "gpt-6.1-sol", evidence_sha256="x")}, "rounds[0].codex_a evidence_sha256 is not 64 lowercase hex characters"),
                         ({"codex_a": seat("A", "gpt-6.1-sol", blockers_open=-1)}, "rounds[0].codex_a blockers_open is -1, want a non-negative integer"),
                         ({"codex_a": seat("A", "gpt-6.1-sol", blockers_open=True)}, "rounds[0].codex_a blockers_open is True, want a non-negative integer"),
                         ({"codex_a": seat("A", "gpt-6.1-sol", blockers_open="2")}, "rounds[0].codex_a blockers_open is '2', want a non-negative integer"),
                         ({"codex_a": seat("A", "gpt-6.1-sol", note="x")}, "rounds[0].codex_a has an extra field 'note': " + PERMITTED_ONLY),
                         ({"codex_a": "clear"}, "rounds[0].codex_a entry is not an object ('clear')")):
            self.assertIn(want, with_earlier(rv), rv)
        r = good(); r["rounds"].insert(0, "round one")
        self.assertIn("rounds[0] is not an object", problems(r))

    def test_a_tree_that_is_not_a_string_fails(self):
        for bad in (None, 1, [TREE], {"tree": TREE}):
            r = good(); r["tree"] = bad
            self.assertIn("record binds tree %s, the change is %s" % (G._show(bad), TREE), problems(r), bad)

    def test_a_deeply_nested_value_is_reported_not_raised(self):
        deep = "x"
        for _ in range(5000):
            deep = [deep]
        r = good(); r["reviewed_commit"] = deep
        ps = problems(r)
        self.assertIn("record reviewed_commit is not 40 lowercase hex characters", ps)


# ---- REQ-AUD-018-AC4, AC5, AC6: the record is read as strict JSON ------------------------------------------------
class StrictJson(unittest.TestCase):
    """REQ-AUD-018-AC5 ("any ... malformed field fails ... naming it"), AC4 and AC6: a record is strict JSON. A repeated
    key at any level (which an ordinary JSON reader resolves by keeping the last, so an earlier substitute, blocker or
    stop verdict would vanish before judging), NaN or Infinity, a byte order mark, bytes that are not UTF-8, anything
    after the value, nesting too deep to read and a record over the size bound are refused, saying which."""

    def body(self, tree=TREE):
        return json.dumps(good(tree), indent=1)

    def load_fails(self, raw, want):
        with self.assertRaises(ValueError) as cm:
            G.load_record(raw)
        self.assertIn(want, str(cm.exception), raw[:80])

    def test_a_good_record_loads(self):
        self.assertEqual(G.load_record(self.body().encode()), good())

    def test_a_repeated_key_is_refused_at_every_level(self):
        b = self.body()
        for before, after, key in (
                ('"stop": {', '"stop": {"codex_a": {"substitute_id": "0350"}, ', "codex_a"),
                ('"blockers_open": 0', '"blockers_open": 1, "blockers_open": 0', "blockers_open"),
                ('"schema": ', '"schema": "auditor-review-record/v1", "schema": ', "schema"),
                ('"reviewers": {', '"reviewers": {"codex_b": {"reviewer": "opus"}, ', "codex_b"),
                ('"round": 1', '"round": 1, "round": 1', "round")):
            raw = b.replace(before, after, 1)
            self.assertNotEqual(raw, b, before)
            self.load_fails(raw.encode(), "the record repeats the key %r" % key)

    def test_nan_and_infinity_are_refused(self):
        for c in ("NaN", "Infinity", "-Infinity"):
            raw = self.body().replace(ANCHOR, ANCHOR + ', "x": [%s]' % c, 1)
            self.load_fails(raw.encode(), "the record holds the non-standard constant %s" % c)

    def test_a_byte_order_mark_is_refused(self):
        self.load_fails(b"\xef\xbb\xbf" + self.body().encode(), "the record starts with a byte order mark")

    def test_bytes_that_are_not_utf_8_are_refused(self):
        for bad in (self.body().replace('"codex"', '"c\xe9dex"', 1).encode("latin-1"), b"\xff\xfe{}", b'{"a": "\xc0\xaf"}'):
            self.load_fails(bad, "the record is not UTF-8")

    def test_anything_after_the_value_is_refused(self):
        for tail in (" x", "{}", "\n{}", " //", "\x00"):
            self.load_fails((self.body() + tail).encode(), "the record is not valid JSON")

    def test_nesting_too_deep_is_refused_not_raised(self):
        ok = self.body().replace(ANCHOR, ANCHOR + ', "x": ' + "[" * 15 + "]" * 15, 1)
        G.load_record(ok.encode())                                   # 16 levels: read (then refused as mistyped)
        over = self.body().replace(ANCHOR, ANCHOR + ', "x": ' + "[" * 16 + "]" * 16, 1)
        self.load_fails(over.encode(), "the record nests too deeply to read (more than 16 levels)")
        quoted = self.body().replace(ANCHOR, ANCHOR + ', "change": "%s"' % ("[{" * 50 + '\\\"' + "]}" * 50), 1)
        self.assertEqual(G.load_record(quoted.encode())["change"][:4], "[{[{")   # brackets inside a string do not count
        raw = self.body().replace(ANCHOR, ANCHOR + ', "x": ' + "[" * 200000 + "]" * 200000, 1)
        self.load_fails(raw.encode(), "the record nests too deeply to read")

    def test_a_record_over_the_size_bound_is_refused(self):
        raw = self.body().replace(ANCHOR, ANCHOR + ', "change": "%s"' % ("x" * G.MAX_RECORD_BYTES), 1)
        self.load_fails(raw.encode(), "the record is larger than %d bytes" % G.MAX_RECORD_BYTES)

    def test_not_json_at_all(self):
        self.load_fails(b"{not json", "the record is not valid JSON")
        self.load_fails(b"", "the record is not valid JSON")

    def test_the_cli_refuses_a_repeated_key_that_hides_a_substitute_naming_it(self):
        c = CliRepo(); c.start(self)
        c.change(".github/agent/bin/x.py", "b\n")
        path = c.record(None, raw=lambda t: self.body(t).replace(
            '"stop": {', '"stop": {"codex_a": {"substitute_id": "0350"}, ', 1).encode())
        rc, out, _ = c.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn(path, out)
        self.assertIn("the record repeats the key 'codex_a'", out)

    def test_the_cli_refuses_a_repeated_key_that_hides_a_blocker(self):
        c = CliRepo(); c.start(self)
        c.change(".github/agent/bin/x.py", "b\n")
        c.record(None, raw=lambda t: self.body(t).replace('"blockers_open": 0', '"blockers_open": 1, "blockers_open": 0', 1))
        rc, out, _ = c.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn("the record repeats the key 'blockers_open'", out)

    def test_the_cli_refuses_nan_a_bom_and_deep_nesting(self):
        for make, want in ((lambda t: self.body(t).replace(ANCHOR, ANCHOR + ', "x": [NaN]', 1),
                            "non-standard constant NaN"),
                           (lambda t: b"\xef\xbb\xbf" + self.body(t).encode(), "byte order mark"),
                           (lambda t: self.body(t).replace(ANCHOR, ANCHOR + ', "x": '
                                                           + "[" * 100000 + "]" * 100000, 1), "nests too deeply")):
            c = CliRepo(); c.start(self)
            c.change(".github/agent/bin/x.py", "b\n")
            c.record(None, raw=make)
            rc, out, _ = c.judge()
            self.assertEqual(rc, 1, (want, out))
            self.assertIn(want, out)
            self.assertIn("no valid review record", out)


# ---- REQ-AUD-018-AC7 and AC3: a pull request cannot seed an old-schema record ------------------------------------
class LegacyProvenance(unittest.TestCase):
    """REQ-AUD-018-AC7 ("any other v1 record, including a v1 record added or edited by the pull request, fails") and
    AC3: an old-schema record counts only when it is already at the merge base, unchanged by the pull request, and the
    same blob on the trusted revision. Every record a pull request adds or changes must be schema v2, even when the
    pull request changes nothing else, so a record-only pull request cannot seed an old-schema record for a tree a
    later pull request will produce (the two-pull-request sequence of the round-1 review)."""

    def setUp(self):
        self.r = CliRepo().start(self)

    def future(self, content="evil\n"):
        """The record path of the tree the auditor will have once x.py holds `content` (computed, then undone)."""
        self.r.change(".github/agent/bin/x.py", content)
        t = self.r.tree()
        self.r.git("reset", "-q", "--hard", self.r.base)
        return ".github/agent/reviews/%s.json" % t

    def test_a_record_only_pull_request_cannot_seed_an_old_schema_record(self):
        path = self.future()
        for body in ('{"schema": "auditor-review-record/v1"}', json.dumps(legacy()), "{}", "[]", '{"schema": null}'):
            self.r.git("reset", "-q", "--hard", self.r.base)
            self.r.change(path, body)                            # pull request 1: a record and nothing else
            rc, out, _ = self.r.judge()
            self.assertEqual(rc, 1, (body, out))
            self.assertIn(path, out)
            self.assertIn("a schema v2 record is required", out)

    def test_the_two_pull_request_sequence_fails_at_both_steps(self):
        path = self.future()
        self.r.change(path, '{"schema": "auditor-review-record/v1"}')        # pull request 1
        pr1 = self.r.rev()
        self.assertEqual(self.r.judge()[0], 1)
        # pull request 2 changes the auditor to that tree; even judged against a trusted revision that holds the
        # seeded file (as if pull request 1 had been merged without the gate), the record is not at its merge base,
        # so it is added by pull request 2 and needs schema v2
        self.r.git("checkout", "-q", "-b", "pr2", self.r.base)
        self.r.change(".github/agent/bin/x.py", "evil\n")
        self.r.git("checkout", "-q", pr1, "--", path); self.r.git("commit", "-qm", "carry the seeded record")
        rc, out, _ = self.r.judge("--subs-rev", pr1)
        self.assertEqual(rc, 1, out)
        self.assertIn("a schema v2 record is required", out)

    def test_an_old_schema_record_added_beside_an_unrelated_change_fails(self):
        path = self.future()
        self.r.write(path, json.dumps(legacy())); self.r.change("src/y", "t\n")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn(path, out)

    def test_a_record_only_pull_request_editing_a_merged_old_record_fails(self):
        self.r.change(".github/agent/bin/x.py", "b\n"); path = self.r.record(legacy)
        self.r.base = self.r.rev()
        self.r.change(path, json.dumps(legacy(), indent=3))
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn("a schema v2 record is required", out)

    def test_a_record_only_pull_request_with_a_strict_v2_record_or_a_deletion_passes(self):
        path = self.future()
        self.r.change(path, json.dumps(good(path[-69:-5])))      # a clearing record of the tree its name names
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 0, out)
        self.r.base = self.r.rev()
        self.r.git("rm", "-q", path); self.r.git("commit", "-qm", "drop")
        self.assertEqual(self.r.judge()[0], 0)

    def test_a_record_only_pull_request_with_a_malformed_record_fails_saying_which(self):
        path = self.future()
        self.r.change(path, json.dumps(good()).replace('"schema"', '"schema": "x", "schema"', 1))
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn("the record repeats the key 'schema'", out)

    def test_a_record_path_that_is_not_a_regular_file_fails(self):
        path = self.future()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(os.path.relpath(os.path.join(self.r.d, "src/y"), os.path.join(self.r.d, os.path.dirname(path))), path); self.r.git("add", "-A"); self.r.git("commit", "-qm", "link")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn("not a regular file", out)

    def test_the_head_record_as_a_link_is_no_valid_record(self):
        self.r.change(".github/agent/bin/x.py", "b\n")
        path = ".github/agent/reviews/%s.json" % self.r.tree()
        self.r.write("src/rec.json", json.dumps(good(self.r.tree())))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(os.path.relpath(os.path.join(self.r.d, "src/rec.json"), os.path.join(self.r.d, os.path.dirname(path))), path); self.r.git("add", "-A"); self.r.git("commit", "-qm", "link")
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn("no valid review record", out)


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
        if isinstance(t, bytes):
            mode = "wb"
        with open(p, mode) as fh:
            fh.write(t)

    def change(self, p, t):
        self.write(p, t); self.git("add", "-A"); self.git("commit", "-qm", "change " + p)

    def tree(self):
        return run_main("--print-tree")[1].strip()

    def legacy_tree(self):
        return G.legacy_tree_hash("HEAD")

    def record(self, make, raw=None, legacy=False):
        """Write make(tree) (or raw text or bytes) as the record of the current content and commit it; returns its path.
        legacy: at the path named by the legacy tree hash (where every record merged before schema v2 lives)."""
        t = self.legacy_tree() if legacy else self.tree()
        path = ".github/agent/reviews/%s.json" % t
        if callable(raw):
            raw = raw(t)
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
    option, and a missing seat (an outage) leaves the change failing."""

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


# ---- REQ-AUD-018-AC7: records merged before the schema v2 gate -----------------------------------------------------
class LegacyRecord(unittest.TestCase):
    """REQ-AUD-018-AC7: an old-schema record counts only as the same blob already on the trusted revision."""

    def setUp(self):
        self.r = CliRepo().start(self)

    def merged_legacy(self, make=legacy, raw=None, at_legacy=True):
        """main: the content x.py=b was reviewed and its record merged (a v1 record at the path named by the legacy tree
        hash, as every record merged before schema v2 is; at_legacy=False: at the schema v2 tree hash's path); then
        main moved on to x.py=c. A pull request restoring x.py=b carries that same record, unchanged. Returns its path."""
        self.r.change(".github/agent/bin/x.py", "b\n")
        path = self.r.record(make, raw=raw, legacy=at_legacy)
        self.r.change(".github/agent/bin/x.py", "c\n")
        self.r.base = self.trusted = self.r.rev()
        self.r.change(".github/agent/bin/x.py", "b\n")          # the PR: a pure revert to the reviewed tree
        return path

    def test_a_v1_record_byte_identical_on_the_trusted_revision_clears_without_re_judging(self):
        path = self.merged_legacy()
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 0, out)
        self.assertIn("already at the merge base and on the trusted revision", out)
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
        # round 3: refused before anything is judged, a schema v2 record included (it once cleared beside it)
        self.merged_legacy()
        v2 = CliRepo().start(self); v2.change(".github/agent/bin/x.py", "b\n"); v2.record(good)
        for repo in (self.r, v2):
            os.chdir(repo.d)
            self.assertEqual(repo.judge()[0], 0)
            for bad in ("no-such-ref", "0" * 40, "HEAD:src", "-x", "--all", "HEAD~99"):
                rc, out, err = repo.judge("--subs-rev", bad)
                self.assertEqual(rc, 2, (bad, out, err))
                self.assertIn("--subs-rev %s is not a commit the gate can read" % G._show(bad), err)
                self.assertNotIn("clears", out)

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

    def test_a_record_on_the_trusted_tip_but_added_by_the_pull_request_fails(self):
        # the record merged on main AFTER the PR branched: the merge base lacks it, so the pull request ADDS it
        # (relative to its base) even though main's tip (--subs-rev) has the same blob: an added v1 record never counts
        self.r.change(".github/agent/bin/x.py", "b\n")
        path = self.r.record(legacy, legacy=True)
        tip = self.r.rev()
        self.r.git("checkout", "-q", "-b", "pr", self.r.base)
        self.r.change(".github/agent/bin/x.py", "b\n")
        self.r.write(path, self.r.git("show", "%s:%s" % (tip, path)))
        self.r.git("add", "-A"); self.r.git("commit", "-qm", "the same record")
        self.assertEqual(self.r.judge()[0], 1)                   # the merge base lacks it
        rc, out, _ = self.r.judge("--subs-rev", tip)
        self.assertEqual(rc, 1, out)
        self.assertIn("a schema v2 record is required", out)

    def test_a_record_at_the_merge_base_but_not_on_the_trusted_revision_fails(self):
        root = self.r.base
        self.merged_legacy()
        rc, out, _ = self.r.judge("--subs-rev", root)
        self.assertEqual(rc, 1, out)
        self.assertIn("a schema v2 record is required", out)

    def test_a_v2_record_is_judged_by_the_v2_rules_even_when_it_is_on_the_trusted_revision(self):
        def blocked(t):
            r = good(t); final(r)["codex_a"]["blockers_open"] = 1; return r
        self.merged_legacy(make=blocked, at_legacy=False)
        rc, out, _ = self.r.judge()
        self.assertEqual(rc, 1)
        self.assertIn("codex_a blockers_open is 1", out)


# ---- REQ-AUD-018-AC8: the workflow runs the gate in isolated mode from the default branch's copy -----------------
class Wiring(unittest.TestCase):
    """REQ-AUD-018-AC8 (and the trusted revision of AC7): the gate's workflow, read as it is on this branch."""

    @staticmethod
    def wf():
        sys.path.insert(0, os.path.join(os.path.dirname(BIN), "fixtures", "testlib"))
        import pyyaml as yaml      # the vendored pure-Python PyYAML the matrix suite reads workflows with
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


# ---- round 2 (Oct 11): free text, diagnostics, bounded work, the merged file, revision arguments ------------------
def run_main_utf8(*argv):
    """main() writing to real UTF-8 streams that refuse what they cannot encode (StringIO hides an encoding failure);
    returns (rc, stdout, stderr), each decoded as ASCII: every diagnostic is plain ASCII, whatever the record holds."""
    ob, eb = io.BytesIO(), io.BytesIO()
    out = io.TextIOWrapper(ob, encoding="utf-8", errors="strict", write_through=True)
    err = io.TextIOWrapper(eb, encoding="utf-8", errors="strict", write_through=True)
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = G.main(list(argv))
    return rc, ob.getvalue().decode("ascii"), eb.getvalue().decode("ascii")


def nested(depth, leaf="x"):
    v = leaf
    for _ in range(depth):
        v = [v]
    return v


class FreeText(unittest.TestCase):
    """REQ-AUD-018-AC4 ("a record that names a substitutes allow-list entry" fails, "naming the entry and saying that no
    substitute is accepted"): a record holds no free text at all (round 3: a pattern on free text cannot tell an entry id
    from a word; the former allow-list's own id pr210 passed it). Every string field is an exact value from the gate's
    lists or a fixed hex form; change, label and residuals are not permitted fields (residuals live in the pull request
    body and the outbox, never in the machine record)."""

    FORMER_IDS = ("pr210", "pr:210", "0317", "0350", "entry pr210 applies", "deadbeef" * 4, "abcdef" * 11,
                  "plain words", "")

    def test_change_label_and_residuals_are_not_permitted_fields(self):
        for v in self.FORMER_IDS:
            r = good(); r["change"] = v
            self.assertIn("record has an extra field 'change': " + PERMITTED_ONLY, problems(r), v)
            r = good(); r["rounds"][0]["label"] = v
            self.assertIn("rounds[0] has an extra field 'label': " + PERMITTED_ONLY, problems(r), v)
            r = good(); r["rounds"][0]["round"] = 2
            r["rounds"].insert(0, {"round": 1, "label": v, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol")}})
            self.assertIn("rounds[0] has an extra field 'label': " + PERMITTED_ONLY, problems(r), v)
            for res in ([v], v, [], [[v]], {"id": v}):
                r = good(); r["residuals"] = res
                self.assertIn("record has an extra field 'residuals': " + PERMITTED_ONLY, problems(r), (v, res))

    def test_the_former_allow_list_id_pr210_never_clears_through_main(self):
        c = CliRepo(); c.start(self)
        c.change(".github/agent/bin/x.py", "b\n")
        for res in (["pr210"], ["pr:210"], ["entry pr210 applies"], ["deadbeef" * 5], ["deadbeef" * 8]):
            c.record(lambda t, res=res: dict(good(t), residuals=res))
            rc, out, err = run_main_utf8("--base", c.base, "--head", "HEAD")
            self.assertEqual(rc, 1, (res, out, err))
            self.assertIn("record has an extra field 'residuals': " + PERMITTED_ONLY, out)
            self.assertNotIn("clears", out)

    def test_no_string_field_takes_free_text(self):
        def at(r, path):
            o = r
            for k in path[:-1]:
                o = o[k]
            return o, path[-1]
        r0 = good(); r0["reviewed_commit"] = "1f" * 20
        paths = [("schema",), ("tree",), ("reviewed_commit",), ("stop", "codex_a"), ("stop", "codex_b")]
        paths += [("rounds", 0, "reviewers", s, f) for s in ("codex_a", "codex_b")
                  for f in FIELDS if isinstance(seat("A", "m")[f], str)]
        for path in paths:
            for v in self.FORMER_IDS:
                r = json.loads(json.dumps(r0)); o, k = at(r, path)
                o[k] = v
                self.assertNotEqual(problems(r), [], (path, v))


class Diagnostics(unittest.TestCase):
    """REQ-AUD-018-AC5 ("any missing, extra, mistyped or malformed field fails the gate with a message naming it"), AC4
    and AC6: every diagnostic is plain ASCII and bounded in length and in number, whatever the record holds (a lone
    surrogate, a long key, a deep value, thousands of extra fields), and no value can make the gate raise."""

    def test_values_are_shown_escaped_and_bounded(self):
        self.assertEqual(G._show("\ud800"), "'\\ud800'")
        self.assertEqual(G._show("caf\u00e9"), "'caf\\xe9'")
        self.assertEqual(G._show("claude"), "'claude'")
        self.assertLess(len(G._show("y" * 100000)), 140)
        self.assertIn("100000 characters", G._show("y" * 100000))
        for v, want in ((None, "None"), (True, "True"), (0, "0"), (-3, "-3"), (0.5, "0.5"),
                        ([], "<a list of length 0>"), ([0], "<a list of length 1>"), (nested(200000), "<a list of length 1>"),
                        ({"a": 1}, "<an object with 1 field(s)>")):
            self.assertEqual(G._show(v), want, v)
        self.assertIn("integer", G._show(10 ** 5000))
        self.assertLess(len(G._show(10 ** 5000)), 80)

    def mutated(self, t, old, new):
        body = json.dumps(good(t))
        self.assertIn(old, body)
        return body.replace(old, new, 1)

    def test_a_lone_surrogate_in_every_string_field_or_key_is_refused_naming_it(self):
        c = CliRepo(); c.start(self)
        c.change(".github/agent/bin/x.py", "b\n")
        S = "\\ud800"
        cases = [('"schema": "%s"' % V2, '"schema": "%s"' % S, "has schema '%s'" % S),
                 ('"tree": "', '"tree": "%s' % S, "record binds tree '"),
                 ('"stop": {', '"reviewed_commit": "%s", "stop": {' % S, "record reviewed_commit is not 40"),
                 ('"reviewer": "codex"', '"reviewer": "%s"' % S, "codex_a reviewer is '%s'" % S),
                 ('"vendor": "openai"', '"vendor": "%s"' % S, "codex_a vendor is '%s'" % S),
                 ('"seat": "A"', '"seat": "%s"' % S, "codex_a seat is '%s'" % S),
                 ('"model": "gpt-6.1-sol"', '"model": "%s"' % S, "codex_a model '%s'" % S),
                 ('"effort": "xhigh"', '"effort": "%s"' % S, "codex_a effort '%s'" % S),
                 ('"evidence_sha256": "%s"' % EVA, '"evidence_sha256": "%s"' % S, "codex_a evidence_sha256 is not 64"),
                 ('"codex_b": "clear"', '"codex_b": "%s"' % S, "stop verdict for codex_b is '%s'" % S),
                 ('"stop": {', '"%s": 1, "stop": {' % S, "record has an extra field '%s'" % S),
                 ('"round": 1', '"round": 1, "%s": 1' % S, "rounds[0] has an extra field '%s'" % S),
                 ('"reviewer": "codex"', '"reviewer": "codex", "%s": 1' % S, "codex_a has an extra field '%s'" % S),
                 ('"reviewers": {', '"reviewers": {"%s": {}, ' % S, "final round entry '%s' is not a seat" % S),
                 ('"stop": {', '"stop": {"%s": "clear", ' % S, "stop holds an extra key '%s'" % S),
                 ('"stop": {', '"substitut%s": 1, "stop": {' % S, "marks a substitute"),
                 ('"stop": {', '"x": ["substitute %s"], "stop": {' % S, "names a substitute ('substitute %s')" % S)]
        for old, new, want in cases:
            c.record(None, raw=lambda t: self.mutated(t, old, new))
            rc, out, err = run_main_utf8("--base", c.base, "--head", "HEAD")
            self.assertEqual(rc, 1, (new, out, err))
            self.assertIn(want, out, (new, out))

    def test_a_lone_surrogate_in_a_record_only_pull_request_is_refused_naming_it(self):
        c = CliRepo(); c.start(self)
        c.change(".github/agent/reviews/%s.json" % ("0" * 64), '{"schema": "\\ud800"}')
        rc, out, _ = run_main_utf8("--base", c.base, "--head", "HEAD")
        self.assertEqual(rc, 1, out)
        self.assertIn("its schema is '\\ud800'", out)

    def test_a_non_ascii_path_is_shown_escaped(self):
        c = CliRepo(); c.start(self)
        c.change(".github/agent/bin/caf\u00e9.py", "b\n")
        rc, out, _ = run_main_utf8("--base", c.base, "--head", "HEAD")
        self.assertEqual(rc, 1, out)
        self.assertIn("caf\\xe9.py", out)

    def test_a_long_key_or_value_is_shown_bounded(self):
        c = CliRepo(); c.start(self)
        c.change(".github/agent/bin/x.py", "b\n")
        c.record(None, raw=lambda t: self.mutated(t, '"stop": {', '"%s": ["%s"], "stop": {' % ("k" * 100000, "substitute" * 10000)))
        rc, out, _ = run_main_utf8("--base", c.base, "--head", "HEAD")
        self.assertEqual(rc, 1, out[:300])
        self.assertTrue(all(len(line) < 1000 for line in out.splitlines()), max(map(len, out.splitlines())))

    def test_the_number_of_problems_is_bounded(self):
        r = good()
        for i in range(5000):
            r["x%d" % i] = 1
        ps = problems(r)
        self.assertEqual(len(ps), G.MAX_PROBLEMS + 1)
        self.assertIn("more problem(s) not shown", ps[-1])
        r = good(); r["residuals"] = ["substitute"] * 5000
        self.assertEqual(len(problems(r)), G.MAX_PROBLEMS + 1)
        r = good(); final(r).update({"k%d" % i: {} for i in range(5000)})
        self.assertEqual(len(problems(r)), G.MAX_PROBLEMS + 1)
        c = CliRepo(); c.start(self)
        c.change(".github/agent/bin/x.py", "b\n")
        c.record(None, raw=lambda t: json.dumps(dict(good(t), **{"x%d" % i: 1 for i in range(5000)})))
        rc, out, _ = run_main_utf8("--base", c.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertLessEqual(len(out.splitlines()), G.MAX_PROBLEMS + 1)
        self.assertIn("more problem(s) not shown", out)

    def test_a_deeply_nested_decoded_value_in_any_field_is_reported_not_raised(self):
        deep = nested(200000)
        def put(path):
            r = good(); r["reviewed_commit"] = "1f" * 20
            o = r
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = deep
            return r
        paths = [(k,) for k in ("schema", "tree", "reviewed_commit", "rounds", "stop", "extra")]
        paths += [("rounds", 0), ("rounds", 0, "round"), ("rounds", 0, "reviewers"), ("stop", "codex_a"), ("stop", "extra")]
        paths += [("rounds", 0, "reviewers", "codex_a")] + [("rounds", 0, "reviewers", "codex_a", f) for f in FIELDS]
        paths += [("rounds", 0, "reviewers", "codex_a", "extra"), ("rounds", 0, "reviewers", "extra")]
        for path in paths:
            ps = problems(put(path))
            self.assertNotEqual(ps, [], path)
        for f in ("model", "evidence_sha256", "seat"):          # both seats deep: the two are never compared deeply
            r = good(); final(r)["codex_a"][f] = nested(200000); final(r)["codex_b"][f] = nested(200000)
            self.assertNotEqual(problems(r), [], f)
        r = good(); r["rounds"][0]["round"] = 2
        r["rounds"].insert(0, {"round": 1, "reviewers": {"codex_a": deep}})
        self.assertNotEqual(problems(r), [])
        self.assertEqual(problems(deep), ["record is not a JSON object"])

    def test_the_substitute_scan_does_not_amplify_a_long_key_into_memory(self):
        import tracemalloc
        r = good(); r["k" * 10000] = [None] * 2000
        r2 = good(); r2["k" * 10000] = {"substitute": ["substitute"] * 2000}
        for rec in (r, r2):
            tracemalloc.start()
            try:
                problems(rec)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertLess(peak, 2000000)


class LinearRead(unittest.TestCase):
    """REQ-AUD-018-AC5 and AC3: reading a record takes time linear in its size (an unterminated string of escaped
    quotes once took quadratic time and could use up the judge's time before any refusal)."""

    def test_the_depth_count_skips_strings_and_escapes(self):
        for text, want in (('["[", {"a": "]\\"["}, [[]]]', 3), ('"\\\\"', 0), ('["\\\\", [1]]', 2), ('{}', 1),
                           ('"[[[', 0), ('"\\"[[[', 0)):
            self.assertEqual(G._depth(text), want, text)

    def test_an_unterminated_string_of_escaped_quotes_is_refused_in_linear_time(self):
        with self.assertRaises(ValueError):
            G.load_record(b'"' + b'\\"' * 20000)
        code = ("import importlib.util,sys,time;s=importlib.util.spec_from_file_location('g',sys.argv[1]);"
                "g=importlib.util.module_from_spec(s);s.loader.exec_module(g);t=time.time()\n"
                "for raw in (b'\"'+b'\\\\\"'*520000, b'{\"a\": \"'+b'\\\\\"'*520000, b'['*16+b'\"'+b'\\\\\"'*520000):\n"
                "  try: g.load_record(raw)\n"
                "  except ValueError: pass\n"
                "  else: sys.exit('read')\n"
                "print('refused in %.1fs' % (time.time()-t))")
        try:
            p = subprocess.run([sys.executable, "-I", "-c", code, SCRIPT], capture_output=True, text=True,
                               timeout=30, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            self.fail("reading 1 MB of escaped quotes took more than 30 seconds")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("refused in", p.stdout)


class MergedFile(unittest.TestCase):
    """REQ-AUD-018-AC7 ("the gate does not re-judge such a record by any rule (old or new)"; "the gate reads the legacy
    record from the trusted revision only"): the identity check comes first (the path untouched by the pull request, the
    same regular-file blob at the merge base, the head and the trusted revision), and only then is the TRUSTED copy read.
    A merged old-schema record is read as the old gate read it (an ordinary JSON reader), so a repeated key or NaN in it
    is history, not a refusal; a merged file whose schema cannot be told, or that claims schema v2 without being strict
    JSON, fails closed."""

    def setUp(self):
        self.r = CliRepo().start(self)
        self.root = self.r.base

    def merged(self, raw):
        """A fresh history from the root: the record `raw(tree)` merged for x.py=b, main moved on, the PR reverts."""
        self.r.git("reset", "-q", "--hard", self.root)
        self.r.base = self.root
        return LegacyRecord.merged_legacy(self, raw=raw)

    def v1(self, t, old='"schema": "%s"' % V1, new=None):
        body = json.dumps(legacy(t))
        self.assertIn(old, body)
        return body.replace(old, new, 1)

    def test_an_unchanged_merged_v1_record_with_a_repeated_key_or_nan_is_honoured(self):
        for new in ('"schema": "%s", "schema": "%s"' % (V1, V1), '"schema": "%s", "x": NaN' % V1,
                    '"schema": "%s", "x": -Infinity' % V1):
            path = self.merged(lambda t, new=new: self.v1(t, new=new))
            rc, out, _ = run_main_utf8("--base", self.r.base, "--head", "HEAD")
            self.assertEqual(rc, 0, (new, out))
            self.assertIn("honoured as merged, not re-judged", out)
            self.assertIn(path, out)

    def test_a_merged_file_whose_schema_cannot_be_told_fails_closed(self):
        for raw in ("{not json", '{"schema": "%s"' % V1, "\ufeff" + '{"schema": "%s"}' % V1,
                    '{"schema": "%s", "x": %s}' % (V1, "[" * 17 + "]" * 17)):
            path = self.merged(lambda t, raw=raw: raw)
            rc, out, _ = run_main_utf8("--base", self.r.base, "--head", "HEAD")
            self.assertEqual(rc, 1, (raw, out))
            self.assertIn(path, out)
            self.assertIn("its schema cannot be told", out)
            self.assertIn("a schema v2 record is required", out)

    def test_a_merged_file_that_claims_schema_v2_without_strict_json_fails_closed(self):
        for new in ('"schema": "%s", "schema": "%s"' % (V2, V1), '"schema": "%s", "x": NaN, "schema": "%s"' % (V1, V2)):
            self.merged(lambda t, new=new: self.v1(t, new=new))
            rc, out, _ = run_main_utf8("--base", self.r.base, "--head", "HEAD")
            self.assertEqual(rc, 1, (new, out))
            self.assertIn("claims schema v2 but is not strict JSON", out)

    def test_the_legacy_record_is_read_from_the_trusted_revision_after_the_identity_check(self):
        path = self.merged(lambda t: json.dumps(legacy(t)))
        trusted = "trusted-tip"                      # the same commit as the merge base, under its own name
        self.r.git("branch", trusted, self.r.base)
        calls, real = [], G._git
        def spy(*a, **k):
            calls.append(a)
            return real(*a, **k)
        with unittest.mock.patch.object(G, "_git", spy):
            rc, out, _ = run_main_utf8("--base", self.r.base, "--head", "HEAD", "--subs-rev", trusted)
        self.assertEqual(rc, 0, out)
        reads = [i for i, a in enumerate(calls) if a[0] == "cat-file"]
        self.assertEqual(len(reads), 1, calls)
        before = calls[:reads[0]]
        listed = [a[2] for a in before if a[0] == "ls-tree" and a[-1] == path]
        self.assertEqual(listed, [trusted, self.r.base, "HEAD"], before)      # trusted first, then base and head
        want = real("ls-tree", "-z", trusted, "--", path).split("\t")[0].split()[2]
        self.assertEqual(calls[reads[0]][-1], want)          # the trusted revision's blob, by its id

    def test_a_record_the_pull_request_adds_is_read_from_the_head_and_judged_strictly(self):
        self.r.change(".github/agent/bin/x.py", "b\n")
        self.r.record(None, raw=lambda t: json.dumps(legacy(t)).replace('"schema"', '"schema": "x", "schema"', 1))
        rc, out, _ = run_main_utf8("--base", self.r.base, "--head", "HEAD")
        self.assertEqual(rc, 1, out)
        self.assertIn("the record repeats the key 'schema'", out)


class RevisionArguments(unittest.TestCase):
    """REQ-AUD-018-AC3: a revision the gate cannot read is refused by name (exit 2), never a traceback, and any failure
    to judge is a named refusal (exit 1), never a pass."""

    def setUp(self):
        self.r = CliRepo().start(self)
        self.r.change(".github/agent/bin/x.py", "b\n"); self.r.record(good)

    def test_an_unreadable_base_or_head_is_refused_naming_it(self):
        for opt in ("--base", "--head"):
            for bad in ("no-such-ref", "0" * 40, "-x", "--all", "HEAD:src", "HEAD~99"):
                argv = {"--base": self.r.base, "--head": "HEAD"}
                argv[opt] = bad
                rc, out, err = run_main_utf8("--base", argv["--base"], "--head", argv["--head"])
                self.assertEqual(rc, 2, (opt, bad, out, err))
                self.assertIn("%s %s is not a commit the gate can read" % (opt, G._show(bad)), err)
        rc, _, err = run_main_utf8("--print-tree", "--head", "no-such-ref")
        self.assertEqual(rc, 2)
        self.assertIn("--head 'no-such-ref' is not a commit the gate can read", err)

    def test_any_failure_to_judge_is_a_named_refusal(self):
        for exc in (RuntimeError("git diff: boom\nmore"), ValueError("bad \ud800"), RecursionError("deep"), MemoryError()):
            with unittest.mock.patch.object(G, "auditor_changes", side_effect=exc):
                rc, out, err = run_main_utf8("--base", self.r.base, "--head", "HEAD")
            self.assertEqual(rc, 1, (exc, out, err))
            self.assertIn("::error::review gate: the change could not be judged (%s" % type(exc).__name__, out)
            self.assertIn("it does not clear", out)



# ---- round 3 (Oct 11): the tree hash, the trusted revision, paths and numbers in diagnostics -----------------------
def plumb(*a, data=None):
    """git over raw bytes (a path may hold any byte but NUL), in the current directory."""
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *a],
                          check=True, capture_output=True, input=data if data is not None else b"").stdout


def index_commit(files, remove=(), msg="plumbed"):
    """Commit `files` ({path bytes: content bytes}) and drop `remove` through the index only (no working-tree file is
    made, so a path no file system takes, a newline or a byte that is not UTF-8, can be committed); returns the commit."""
    for path in remove:
        plumb("update-index", "--force-remove", "--", path)
    for path, content in files.items():
        blob = plumb("hash-object", "-w", "--stdin", data=content).strip().decode()
        plumb("update-index", "--add", "--cacheinfo", "100644,%s,%s" % (blob, path.decode("utf-8", "surrogateescape")))
    plumb("commit", "-qm", msg)
    return plumb("rev-parse", "HEAD").strip().decode()


def listing(rev):
    """The hashed entries of `rev` as raw bytes, read independently of the gate."""
    out = plumb("ls-tree", "-r", "-z", "--full-tree", rev, "--", ".github/agent/", *[g for g in G.GUARDED])
    return [e for e in out.split(b"\0") if e and not re.fullmatch(rb"\.github/agent/reviews/[0-9a-f]{64}\.json",
                                                                      e.split(b"\t", 1)[-1])]


def old_gate_hash(rev):
    """The tree hash as the gate merged before schema v2 computed it: entries joined with newlines."""
    return __import__("hashlib").sha256(("\n".join(e.decode() for e in listing(rev)) + "\n").encode()).hexdigest()


def blob_id(content):
    return plumb("hash-object", "--stdin", data=content).strip().decode()


class TreeHash(unittest.TestCase):
    """REQ-AUD-018-AC3 ("every change ... clears the ... stop rule": a record binds exactly one content), AC5 ("the record
    binds the pull request's tree") and AC7 (an old record clears only the content it was merged for). The tree hash
    frames every entry with a NUL, which no entry can hold, after a version prefix: two different trees never share a
    serialization. A schema v1 record is named by the legacy hash (entries joined with newlines), which is computed only
    to find such a record and only for a tree with no control character and no byte that is not UTF-8 in any hashed
    path, where the legacy serialization is unambiguous too."""

    def setUp(self):
        self.r = CliRepo().start(self)
        self.P, self.Q = b".github/agent/bin/p", b".github/agent/bin/q"
        self.A = index_commit({self.P: b"P\n", self.Q: b"Q\n"}, msg="tree A")
        crafted = self.P + b"\n100644 blob " + blob_id(b"Q\n").encode() + b"\t" + self.Q
        self.crafted = crafted

    def make_b(self):
        """Tree B: one path that holds tree A's second entry as text, with A's first blob."""
        return index_commit({self.crafted: b"P\n"}, remove=(self.P, self.Q), msg="tree B")

    def test_the_tree_hash_is_the_nul_framed_listing_after_a_version_prefix(self):
        want = __import__("hashlib").sha256(b"auditor-tree/v2\0" + b"".join(e + b"\0" for e in listing("HEAD"))).hexdigest()
        self.assertEqual(G.tree_hash("HEAD"), want)
        self.assertEqual(run_main("--print-tree")[1].strip(), want)

    def test_two_trees_the_legacy_hash_confuses_have_two_tree_hashes(self):
        b = self.make_b()
        self.assertEqual(old_gate_hash(self.A), old_gate_hash(b))             # the round-3 finding, on real trees
        self.assertNotEqual(listing(self.A), listing(b))
        self.assertNotEqual(G.tree_hash(self.A), G.tree_hash(b))
        self.assertEqual(G.legacy_tree_hash(self.A), old_gate_hash(self.A))   # the legacy hash is the old gate's
        self.assertIsNone(G.legacy_tree_hash(b))                              # a newline in a path: no legacy name

    def test_no_legacy_name_for_a_path_with_a_control_character_or_not_utf_8(self):
        for bad in (b"a\nb", b"a\rb", b"a\x1bb", b"a\x7fb", b"a\x01b", b"a\tb", b"\xff", b"caf\xc3"):
            plumb("reset", "-q", "--hard", self.A)
            index_commit({b".github/agent/bin/" + bad: b"x\n"})
            self.assertIsNone(G.legacy_tree_hash("HEAD"), bad)
            self.assertRegex(G.tree_hash("HEAD"), "^[0-9a-f]{64}$")
        plumb("reset", "-q", "--hard", self.A)
        index_commit({".github/agent/bin/caf\u00e9 x.py".encode(): b"x\n"})        # plain UTF-8: named as before
        self.assertEqual(G.legacy_tree_hash("HEAD"), old_gate_hash("HEAD"))

    def test_a_merged_v1_record_does_not_clear_a_tree_that_only_shares_its_legacy_hash(self):
        legacy_path = (".github/agent/reviews/%s.json" % old_gate_hash(self.A)).encode()
        index_commit({legacy_path: json.dumps(legacy(old_gate_hash(self.A))).encode()}, msg="v1 record for A")
        index_commit({b".github/agent/bin/x.py": b"moved on\n"}, msg="main moves on")
        main = plumb("rev-parse", "HEAD").strip().decode()
        # a pull request back to tree A exactly: the v1 record clears it, as it did before (AC7)
        index_commit({b".github/agent/bin/x.py": b"a\n"}, msg="revert to A")
        rc, out, err = run_main_utf8("--base", main, "--head", "HEAD", "--subs-rev", main)
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("honoured as merged, not re-judged", out)
        # a pull request to tree B (the legacy hash of A, different content): refused
        plumb("reset", "-q", "--hard", main)
        index_commit({b".github/agent/bin/x.py": b"a\n"}, msg="x back")
        self.make_b()
        self.assertEqual(old_gate_hash("HEAD"), old_gate_hash(self.A))
        rc, out, err = run_main_utf8("--base", main, "--head", "HEAD", "--subs-rev", main)
        self.assertEqual(rc, 1, (out, err))
        self.assertNotIn("honoured", out)
        self.assertIn("no valid review record", out)

    def test_a_path_that_is_not_utf_8_is_hashed_and_named_escaped(self):
        index_commit({b".github/agent/bin/\xff.py": b"x\n"})
        rc, out, _ = run_main_utf8("--print-tree")
        self.assertEqual(rc, 0, out)
        self.assertRegex(out.strip(), "^[0-9a-f]{64}$")
        rc, out, _ = run_main_utf8("--base", self.r.base, "--head", "HEAD")
        self.assertEqual(rc, 1, out)
        self.assertNotIn("could not be judged", out)
        self.assertIn("no valid review record", out)

    def test_a_v2_record_at_the_legacy_path_or_a_v1_record_at_the_tree_path_never_clears(self):
        for at_legacy, make in ((True, good), (False, legacy)):
            lr = LegacyRecord(); lr.r = CliRepo().start(self)
            path = lr.merged_legacy(make=make, at_legacy=at_legacy)
            rc, out, _ = run_main_utf8("--base", lr.r.base, "--head", "HEAD")
            self.assertEqual(rc, 1, (at_legacy, out))
            self.assertIn(path, out)
            self.assertIn("a schema v2 record is required", out)
            self.assertNotIn("honoured", out)

    def test_a_record_at_the_tree_path_is_judged_even_beside_a_merged_v1_record(self):
        lr = LegacyRecord(); lr.r = CliRepo().start(self)
        lr.merged_legacy()
        self.assertEqual(lr.r.judge()[0], 0)
        lr.r.record(lambda t: dict(good(t), stop={"codex_a": "clear", "codex_b": "blocked"}))
        rc, out, _ = lr.r.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn("stop verdict for codex_b is 'blocked'", out)


class ControlSafeDiagnostics(unittest.TestCase):
    """REQ-AUD-018-AC5 and AC6 ("a message naming it"): every line the gate writes is one line of plain ASCII of bounded
    length: a control character (newline, carriage return, escape, ...) anywhere in a line is written escaped, a changed
    path is shown escaped and cut like any record value, and no path can forge a second annotation line."""

    def test_say_escapes_every_control_character_and_bounds_the_line(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            G._say("a\nb\rc\x1bd\x7fe\x00f\tg\u00e9h\u2028i")
        self.assertEqual(out.getvalue(), "a\\nb\\rc\\x1bd\\x7fe\\x00f\\tg\\xe9h\\u2028i\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            G._say("y" * 100000)
        self.assertEqual(out.getvalue().count("\n"), 1)
        self.assertLessEqual(len(out.getvalue()), G.SAY_CHARS + 60)
        self.assertIn("100000 characters", out.getvalue())

    def test_a_changed_path_cannot_forge_a_line_or_an_escape_sequence(self):
        c = CliRepo(); c.start(self)
        index_commit({b".github/agent/bin/a\n::notice::forged\x1b[31m\r" + b"z" * 3000: b"x\n"})
        rc, out, err = run_main_utf8("--base", c.base, "--head", "HEAD")
        self.assertEqual(rc, 1, out)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1, out)
        self.assertTrue(lines[0].startswith("::error::review gate:"), lines[0][:200])
        self.assertNotIn("\x1b", out + err)
        self.assertNotIn("\r", out + err)
        self.assertIn("a\\n::notice::forged\\x1b[31m\\r", out)
        self.assertLess(len(lines[0]), 1000)

    def test_a_changed_path_that_is_long_is_cut(self):
        c = CliRepo(); c.start(self)
        index_commit({b".github/agent/bin/" + b"w" * 3000: b"x\n"})
        rc, out, _ = run_main_utf8("--base", c.base, "--head", "HEAD")
        self.assertEqual(rc, 1, out[:300])
        self.assertLess(max(map(len, out.splitlines())), 1000)
        self.assertIn("characters)", out)


class BoundedNumbers(unittest.TestCase):
    """REQ-AUD-018-AC5 ("any ... malformed field fails ... naming it") and AC3: a number in a record is at most
    MAX_NUMBER_CHARS characters long, refused before it is converted (on every supported Python, the oldest included,
    conversion of a long decimal takes time out of proportion to its length), by the strict reader and by the reader of
    a merged old file alike; and every number in a diagnostic is shown bounded."""

    def test_a_long_number_is_refused_before_conversion(self):
        for tok in ("1" + "0" * G.MAX_NUMBER_CHARS, "-" + "9" * G.MAX_NUMBER_CHARS, "1." + "0" * G.MAX_NUMBER_CHARS,
                    "1e" + "0" * G.MAX_NUMBER_CHARS):
            with self.assertRaises(ValueError) as cm:
                G.load_record(('{"schema": "%s", "x": %s}' % (V2, tok)).encode())
            self.assertIn("the record holds a number longer than %d characters" % G.MAX_NUMBER_CHARS, str(cm.exception))
        ok = G.load_record(('{"x": [%s, %s]}' % ("9" * G.MAX_NUMBER_CHARS, "-" + "9" * (G.MAX_NUMBER_CHARS - 1))).encode())
        self.assertEqual(ok["x"][0], int("9" * G.MAX_NUMBER_CHARS))
        self.assertGreaterEqual(G.MAX_NUMBER_CHARS, 19)                   # every 64-bit integer still reads

    def test_a_merged_old_file_with_a_long_number_fails_closed(self):
        kind, why = G.classify_merged(('{"schema": "%s", "schema": "%s", "x": 1%s}' % (V1, V1, "0" * 1000)).encode())
        self.assertEqual(kind, "refused")
        self.assertIn("its schema cannot be told", why)

    def test_a_record_of_huge_numbers_is_refused_quickly_on_this_python(self):
        code = ("import importlib.util,sys,time;s=importlib.util.spec_from_file_location('g',sys.argv[1]);"
                "g=importlib.util.module_from_spec(s);s.loader.exec_module(g);t=time.time()\n"
                "raws=[b'{\"rounds\": [{\"round\": 1'+b'0'*900000+b'}]}', b'['+b'1'*500000+b','+b'2'*500000+b']']\n"
                "for raw in raws:\n"
                "  try: g.load_record(raw)\n"
                "  except ValueError: pass\n"
                "  else: sys.exit('read')\n"
                "  if g.classify_merged(raw)[0] != 'refused': sys.exit('classified')\n"
                "print('refused in %.1fs' % (time.time()-t))")
        p = subprocess.run([sys.executable, "-I", "-c", code, SCRIPT], capture_output=True, text=True, timeout=30,
                           stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("refused in", p.stdout)

    def test_round_numbers_in_a_diagnostic_are_shown_bounded(self):
        r = good(); r["rounds"][0]["round"] = 10 ** 3000
        r["rounds"].insert(0, {"round": 10 ** 4000, "reviewers": {"codex_a": seat("A", "gpt-6.1-sol")}})
        ps = problems(r)
        hit = [p for p in ps if "does not follow" in p]
        self.assertEqual(len(hit), 1, ps)
        self.assertLess(len(hit[0]), 200)
        self.assertIn("bits", hit[0])


class GlobalProblemBound(unittest.TestCase):
    """REQ-AUD-018-AC7 ("any other v1 record, including a v1 record added or edited by the pull request, fails, naming
    the record") and the bounded diagnostics: however many records a pull request adds, the gate writes at most
    MAX_PROBLEMS problem lines and one count line in all, and stops reading added records once that many have failed."""

    def test_many_bad_added_records_are_bounded_in_lines_and_reads(self):
        c = CliRepo(); c.start(self)
        for i in range(G.MAX_PROBLEMS * 3):
            c.write(".github/agent/reviews/%064x.json" % i, '{"schema": "%s"}' % V1)
        c.write(".github/agent/bin/x.py", "b\n"); c.git("add", "-A"); c.git("commit", "-qm", "many")
        calls, real = [], G._git
        def spy(*a, **k):
            calls.append(a)
            return real(*a, **k)
        with unittest.mock.patch.object(G, "_git", spy):
            rc, out, _ = run_main_utf8("--base", c.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        lines = out.splitlines()
        self.assertLessEqual(len(lines), G.MAX_PROBLEMS + 1, len(lines))
        self.assertIn("more problem(s) not shown", lines[-1])
        self.assertLessEqual(len([a for a in calls if a[0] == "cat-file"]), G.MAX_PROBLEMS)


# ---- round 4 (Oct 11): a non-regular object at a record path, every added record judged, the line bound ------------
def special(path, kind):
    """Commit a non-regular object at `path` (str) through the index, then make the work tree match: a symbolic link
    (kind "link", to a relative target inside the repository), a submodule entry ("gitlink", naming HEAD) or a
    directory ("tree", holding one file)."""
    if kind == "link":
        blob = plumb("hash-object", "-w", "--stdin", data=b"../../../src/y").strip().decode()
        plumb("update-index", "--add", "--cacheinfo", "120000,%s,%s" % (blob, path))
    elif kind == "gitlink":
        commit = plumb("rev-parse", "HEAD").strip().decode()
        plumb("update-index", "--add", "--cacheinfo", "160000,%s,%s" % (commit, path))
    else:
        blob = plumb("hash-object", "-w", "--stdin", data=b"x\n").strip().decode()
        plumb("update-index", "--add", "--cacheinfo", "100644,%s,%s/inner" % (blob, path))
    plumb("commit", "-qm", "a %s at %s" % (kind, path))
    plumb("reset", "-q", "--hard")


def rec_path(h):
    return ".github/agent/reviews/%s.json" % h


class NonRegularRecord(unittest.TestCase):
    """REQ-AUD-018-AC7 (an old record clears only as "a file at the same record path with the same bytes" on the trusted
    revision; "any other v1 record ... fails") and AC3: the gate tells an absent record path from one that holds a
    non-regular object (a symbolic link, a submodule entry or a directory). A non-regular object at the tree-hash path
    or at the legacy path fails closed, naming that path, whether the pull request added it or it was already there; at
    the tree-hash path it is refused before any legacy record is looked at, so it never falls back to a merged record."""

    KINDS = ("link", "gitlink")

    def scenario(self, kind, at, when):
        """main reviewed x.py=b (a v1 record merged at the legacy path), then moved on to x.py=c; the pull request
        restores x.py=b. A `kind` object is put at the tree-hash path (at="tree") or the legacy path (at="legacy"),
        on main before it moved on (when="preexisting") or by the pull request (when="added"). Returns that path."""
        r = self.r = CliRepo().start(self)
        r.change(".github/agent/bin/x.py", "b\n")
        target = rec_path(r.tree()) if at == "tree" else rec_path(r.legacy_tree())
        if at == "tree":
            r.record(legacy, legacy=True)
        if when == "preexisting":
            special(target, kind)
        r.change(".github/agent/bin/x.py", "c\n")
        r.base = r.rev()
        r.change(".github/agent/bin/x.py", "b\n")
        if when == "added":
            special(target, kind)
        return target

    def refused(self, target, *extra):
        rc, out, err = run_main_utf8("--base", self.r.base, "--head", "HEAD", *extra)
        self.assertEqual(rc, 1, (target, out, err))
        self.assertIn(target, out)
        self.assertIn("not a regular file", out)
        self.assertNotIn("honoured", out)
        self.assertNotIn("clears", out)
        return out

    def test_blob_tells_an_absent_path_from_a_regular_file_from_a_non_regular_object(self):
        r = CliRepo().start(self)
        for kind, h in (("link", "1" * 64), ("gitlink", "2" * 64), ("tree", "3" * 64)):
            special(rec_path(h), kind)
        r.change(rec_path("4" * 64), "{}")
        for h in ("1" * 64, "2" * 64, "3" * 64):
            self.assertIs(G._blob("HEAD", rec_path(h)), G.NOT_REGULAR, h)
        self.assertIsNone(G._blob("HEAD", rec_path("5" * 64)))
        self.assertRegex(G._blob("HEAD", rec_path("4" * 64)), "^[0-9a-f]{40}$")

    def test_a_merged_legacy_record_still_clears_without_a_non_regular_object(self):
        self.scenario(None, "tree", "neither")
        self.assertEqual(self.r.judge()[0], 0)

    def test_a_non_regular_object_at_the_tree_path_beside_a_merged_legacy_record_fails(self):
        for kind in self.KINDS:
            for when in ("added", "preexisting"):
                with self.subTest(kind=kind, when=when):
                    self.refused(self.scenario(kind, "tree", when))

    def test_a_non_regular_object_at_the_legacy_path_fails_naming_it(self):
        for kind in self.KINDS:
            for when in ("added", "preexisting"):
                with self.subTest(kind=kind, when=when):
                    self.refused(self.scenario(kind, "legacy", when))

    def test_a_directory_at_either_record_path_fails_naming_it(self):
        # a directory at a record path puts its files into the hashed content, so its path can name the content only by
        # a hash collision; the hash functions are replaced to reach that combination directly
        fake = "f" * 64
        for at in ("tree", "legacy"):
            with self.subTest(at=at):
                r = self.r = CliRepo().start(self)
                special(rec_path(fake), "tree")
                r.change(".github/agent/bin/x.py", "b\n")
                if at == "tree":
                    r.record(legacy, legacy=True)
                r.change(".github/agent/bin/x.py", "c\n")
                r.base = r.rev()
                r.change(".github/agent/bin/x.py", "b\n")
                with unittest.mock.patch.object(G, "tree_hash" if at == "tree" else "legacy_tree_hash",
                                                return_value=fake):
                    self.refused(rec_path(fake))


class EveryAddedRecordJudged(unittest.TestCase):
    """REQ-AUD-018-AC5 ("any missing, extra, mistyped or malformed field fails the gate with a message naming it"), AC4
    (a substitute in any form fails, "naming the entry and saying that no substitute is accepted") and AC7 (no pull
    request introduces a record that is not a valid schema v2 record): EVERY record file a pull request adds or changes
    is judged by the one validator that judges the selected record, bound to the tree its own file name names, in a
    record-only pull request and beside a selected record alike."""

    OTHER = "1" * 64

    def bad_bodies(self, t):
        """(raw record for the tree `t`, the text its refusal must hold)."""
        def j(rec):
            return json.dumps(rec)
        no_model = good(t); del final(no_model)["codex_b"]["model"]
        extra_seat = good(t); final(extra_seat)["codex_a"]["note"] = "x"
        former = good(t); final(former)["codex_a"]["model"] = "pr210"
        open_blocker = good(t); final(open_blocker)["codex_b"]["blockers_open"] = 1
        return [
            (j({"schema": V2, "residuals": ["pr210"]}), "record has an extra field 'residuals': " + PERMITTED_ONLY),
            (j({"schema": V2}), "no review rounds recorded"),
            (j({"schema": V2, "substitute_id": "0317", "rounds": "invalid"}), "marks a substitute: " + NO_SUB),
            (j(no_model), "codex_b has no model field"),
            (j(extra_seat), "codex_a has an extra field 'note'"),
            (j(dict(good(t), residuals=["pr210"])), "record has an extra field 'residuals'"),
            (j(dict(good(t), label="pr:210")), "record has an extra field 'label'"),
            (j(former), "codex_a model 'pr210' is not on the gate's list"),
            (j(open_blocker), "codex_b blockers_open is 1, want the integer 0"),
            (j(good(TREE)), "record binds tree %s" % TREE),
            (j(good(t)).replace('"schema"', '"schema": "x", "schema"', 1), "the record repeats the key 'schema'"),
        ]

    def test_a_record_only_pull_request_adding_an_invalid_v2_record_fails_naming_it(self):
        r = CliRepo().start(self)
        path = rec_path(self.OTHER)
        for raw, want in self.bad_bodies(self.OTHER):
            with self.subTest(want=want):
                r.git("reset", "-q", "--hard", r.base)
                r.change(path, raw)
                rc, out, err = run_main_utf8("--base", r.base, "--head", "HEAD")
                self.assertEqual(rc, 1, (raw, out, err))
                self.assertIn(path, out)
                self.assertIn(want, out)
                self.assertNotIn("nothing to clear", out)

    def test_an_invalid_v2_record_added_beside_a_clearing_selected_record_fails_naming_it(self):
        r = CliRepo().start(self)
        r.change(".github/agent/bin/x.py", "b\n"); r.record(good)
        top = r.rev()
        self.assertEqual(r.judge()[0], 0)
        path = rec_path(self.OTHER)
        for raw, want in self.bad_bodies(self.OTHER):
            with self.subTest(want=want):
                r.git("reset", "-q", "--hard", top)
                r.change(path, raw)
                rc, out, err = run_main_utf8("--base", r.base, "--head", "HEAD")
                self.assertEqual(rc, 1, (raw, out, err))
                self.assertIn(path, out)
                self.assertIn(want, out)
                self.assertNotIn("clears the stop rule", out)

    def test_a_valid_record_for_another_tree_may_be_added(self):
        r = CliRepo().start(self)
        r.change(rec_path(self.OTHER), json.dumps(good(self.OTHER)))
        self.assertEqual(r.judge()[0], 0)
        r.change(".github/agent/bin/x.py", "b\n"); r.record(good)
        self.assertEqual(r.judge()[0], 0)

    def test_a_changed_merged_record_is_judged_too(self):
        r = CliRepo().start(self)
        r.change(rec_path(self.OTHER), json.dumps(good(self.OTHER)))
        r.base = r.rev()
        r.change(rec_path(self.OTHER), json.dumps(dict(good(self.OTHER), residuals=["pr210"])))
        rc, out, _ = r.judge()
        self.assertEqual(rc, 1, out)
        self.assertIn("record has an extra field 'residuals'", out)

    def test_problems_of_many_added_v2_records_are_bounded_in_all(self):
        r = CliRepo().start(self)
        bad = dict(good(self.OTHER), **{"x%d" % i: 1 for i in range(300)})
        for i in range(5):
            h = "%064x" % (i + 7)
            r.write(rec_path(h), json.dumps(dict(bad, tree=h)))
        r.git("add", "-A"); r.git("commit", "-qm", "many")
        rc, out, _ = r.judge()
        self.assertEqual(rc, 1)
        lines = out.splitlines()
        self.assertLessEqual(len(lines), G.MAX_PROBLEMS + 1, len(lines))
        self.assertIn("more problem(s) not shown", lines[-1])


class LineBoundAfterEscaping(unittest.TestCase):
    """REQ-AUD-018-AC5 and AC6 ("a message naming it"): every written line is bounded AFTER escaping (an escape makes one
    character up to ten), whatever the characters: line separators, lone surrogates, combining marks, controls; and a
    revision in a diagnostic is shown like any value."""

    def said(self, line):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            G._say(line)
        return out.getvalue()

    def test_say_bounds_the_escaped_line(self):
        for s in (" " * 2000, "\ud800" * 5000, "é" * 3000, "\x1b" * 3000, "\U0001f600" * 2000,
                  "é" * 2500 + "\n" * 10, "a" * 1990 + " " * 20):
            got = self.said(s)
            self.assertEqual(got.count("\n"), 1, s[:5])
            self.assertTrue(got.isascii(), s[:5])
            self.assertLessEqual(len(got), G.SAY_CHARS + 40, (s[:5], len(got)))
            self.assertIn("characters)", got, s[:5])
        self.assertEqual(self.said("x y"), "x\\u2028y\n")      # a short line is written whole

    def test_a_revision_in_a_refusal_is_shown_bounded(self):
        rev = " " * 3000
        with unittest.mock.patch.object(G, "_blob", return_value=G.NOT_REGULAR):
            with self.assertRaises(RuntimeError) as cm:
                G._read_record(rev, rec_path("1" * 64))
        self.assertLess(len(str(cm.exception)), 400)
        self.assertTrue(str(cm.exception).isascii())

if __name__ == "__main__":
    unittest.main(verbosity=2)
