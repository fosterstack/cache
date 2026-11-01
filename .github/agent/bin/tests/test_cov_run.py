"""REQ-AUD-18 AC2: behaviour tests for .github/agent/bin/auditor-run.py paths the matrix suite does
not reach — the real-gh delivery paths (with a fake subprocess), the pullability class edges, the
merge/consolidate fallbacks, the narrative guard, the scanner tables and main()'s exit codes.

No network, no real git/gh/go: every subprocess call is intercepted by FakeRun and asserted on by
its exact argv. Every write goes to a temp dir."""
import base64, contextlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIX = os.path.abspath(os.path.join(BIN, "..", "fixtures"))
sys.path.insert(0, BIN)
import verdict_fixture  # noqa: E402  (fixture verdicts adapted to the panel's current image set)
_spec = importlib.util.spec_from_file_location("auditor_run_cov", os.path.join(BIN, "auditor-run.py"))
R = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(R)
policy = R.policy
from auditorlib import nochange  # noqa: E402
PROD = policy.VEX_PRODUCT

# env vars that change which delivery path runs — cleared for every test, set explicitly per case
_PATH_ENVS = ("AUDITOR_GIT_SHIM_LOG", "AUDITOR_ALLOW_REAL_GH", "AUDITOR_AUTOMERGE", "AUDITOR_SHIM_ISSUE_FAIL",
              "AUDITOR_SHIM_PR_FAIL", "GITHUB_WORKSPACE", "AUDITOR_ISSUES_TOKEN", "GH_TOKEN",
              "GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "AUDITOR_MODEL_PRIMARY",
              "AUDITOR_MODEL_FALLBACK")


class FakeRun:
    """Stand-in for subprocess.run. `rules` maps an argv PREFIX tuple to a response
    (rc, stdout, stderr), a list of responses consumed in order, or an Exception to raise.
    The longest matching prefix wins; unmatched argv -> rc 0, empty output."""
    def __init__(self, rules=None):
        # the delivery base holds no reviewed file yet unless a test says so (git show of origin/main:<path> is read
        # before the checkout)
        self.defaults = {("git", "show"): (128, "", "fatal: path 'x' does not exist in 'origin/main'"),
                         ("git", "rev-parse", "origin/main"): (0, "a" * 40 + "\n", "")}
        self.rules = dict(rules or {}); self.calls = []

    def __call__(self, argv, **kw):
        argv = list(argv); self.calls.append((argv, kw))
        best = None
        for pre in self.rules:
            if tuple(argv[:len(pre)]) == pre and (best is None or len(pre) > len(best)):
                best = pre
        resp = (0, "", "") if best is None else self.rules[best]
        # no rule of the test: the delivery base holds no reviewed file yet, origin/main resolves to SHA
        if best is None:
            for pre in self.defaults:
                if tuple(argv[:len(pre)]) == pre:
                    resp = self.defaults[pre]
        if isinstance(resp, list):
            resp = resp.pop(0) if len(resp) > 1 else resp[0]
        if isinstance(resp, BaseException):
            raise resp
        rc, out, err = resp
        return subprocess.CompletedProcess(argv, rc, out, err)

    def argvs(self):
        return [a for a, _ in self.calls]


SHA = "a" * 40
OID = "b" * 40
OLDHEAD = "c" * 40
GQL_OK = json.dumps({"data": {"createCommitOnBranch": {"commit": {"oid": OID, "signature": {"isValid": True, "state": "VALID"}}}}})


def head_lookup(verified=True, parent=SHA, parents=None, files=(("go.mod", "modified"),), author="app[bot]",
                committer="web-flow"):
    """GitHub's answer for a commit: its parents, its changed files, who made it and whether it is verified."""
    return (0, json.dumps({"parents": [{"sha": x} for x in (parents if parents is not None else [parent])],
                           "files": [{"filename": f[0], "status": f[1], **(f[2] if len(f) > 2 else {})} for f in files],
                           "author": {"login": author}, "committer": {"login": committer},
                           "commit": {"verification": {"verified": verified}}}), "")


class ApiRun(FakeRun):
    """FakeRun plus the GitHub API the signed delivery uses: the delivery branch's ref (GET answers `live`, None = absent), the temporary ref
    POST / DELETE, the live ref PATCH, the createCommitOnBranch GraphQL call (its stdin kept in .stdins), the commit lookup and a PR's head oid.
    Defaults: the branch exists at OLDHEAD, every write succeeds with a VALID signature, `git status` lists the suppression files as changed and
    `git rev-parse` answers SHA. Override `live`, `post`, `patch`, `delete`, `mutation`, `lookup`, `pr_head`."""
    def __init__(self, rules=None, live=OLDHEAD, post=(0, "{}", ""), patch=(0, "{}", ""), delete=(0, "{}", ""), mutation=(0, GQL_OK, ""),
                 lookup=None, pr_head=OID, contents=None):
        defaults = {("git", "status"): (0, " M .vex/fosterstack-cache.openvex.json\0?? .auditor/knowledge.md\0", ""),
                    ("git", "rev-parse"): (0, SHA + "\n", ""),
                    # no open Dependabot PR (rc-5b A7) unless a test says so
                    ("gh", "pr", "list", "--state", "open", "--author", "app/dependabot"): (0, "[]", "")}
        super().__init__({**defaults, **(rules or {})})
        self.live, self.post, self.patch, self.delete, self.mutation = live, post, patch, delete, mutation
        self.lookup = lookup or head_lookup()
        self.pr_head = pr_head
        self.contents = {"go.mod": b"module m\n"} if contents is None else contents
        self.stdins = []

    def __call__(self, argv, **kw):
        argv = list(argv)
        if argv[:3] == ["gh", "pr", "view"] and "headRefOid" in argv and self.pr_head is not None:
            self.calls.append((argv, kw))
            return subprocess.CompletedProcess(argv, 0, self.pr_head + "\n", "")
        if argv[:2] == ["gh", "api"] and not any(argv[:len(p)] == list(p) for p in self.rules):
            self.calls.append((argv, kw))
            if argv[2] == "graphql":
                self.stdins.append(json.loads(kw["input"])); resp = self.mutation
            elif argv[2] == "--method":
                resp = {"POST": self.post, "PATCH": self.patch, "DELETE": self.delete}[argv[3]]
            elif "/git/ref/heads/" in argv[2]:
                resp = (1, "", "gh: Not Found (HTTP 404)") if self.live is None else (0, json.dumps({"object": {"sha": self.live}}), "")
            elif "/commits/" in argv[2]:
                resp = self.lookup
            elif "/contents/" in argv[2]:
                path = argv[2].split("/contents/")[1].split("?ref=")[0]
                resp = (0, json.dumps({"encoding": "base64", "content": base64.encodebytes(self.contents[path]).decode()}), "") if path in self.contents \
                    else (1, "", "gh: Not Found (HTTP 404)")
            else:
                return super().__call__(argv, **kw)
            return subprocess.CompletedProcess(argv, resp[0], resp[1], resp[2])
        return super().__call__(argv, **kw)

    def no_unsigned(self):
        """Nothing here ever ran `git commit` or `git push`."""
        return not any(a[:2] in (["git", "commit"], ["git", "push"]) for a in self.argvs())

    def ref_writes(self):
        """The writes that move or create a ref or make a commit, in order: ("POST"|"PATCH"|"DELETE"|"COMMIT", target)."""
        out = []
        for a in self.argvs():
            if a[:2] == ["gh", "api"] and a[2] == "graphql":
                out.append(("COMMIT", None))
            elif a[:2] == ["gh", "api"] and a[2] == "--method" and a[3] != "GET":
                out.append((a[3], a[4]))
        return out

    def index(self, argv):
        return self.argvs().index(argv)


def F(fid, purl, pkg, sev="Low", fixed=None, scanner="grype", extra=None):
    return {"scanner": scanner, "finding_id": fid, "purl": purl, "aliases": [fid], "package": pkg,
            "fixed_version": fixed, "severity": sev, "extra": extra or {}}


def scope(purls):
    return ((PROD,), tuple(sorted(purls)))


class Base(unittest.TestCase):
    def assert_branch_off_main(self, fr):
        """A delivered branch is cut from a FRESH origin/main (fetch, then checkout -B <b>
        origin/main) — never from HEAD, so branches never stack (Codex AC2 round-1 residual)."""
        a = fr.argvs()
        co = [x for x in a if x[:3] == ["git", "checkout", "-B"]]
        self.assertTrue(co, "no branch checkout issued")
        for x in co:
            self.assertEqual(len(x), 5)
            # the suppression delivery cuts its branch from the sha origin/main resolved to right after the fetch
            # (cache#708 ruling 1)
            if x[4] != "origin/main":
                self.assertEqual(x[4], SHA)
                self.assertLess(a.index(["git", "rev-parse", "origin/main"]), a.index(co[0]))
        self.assertLess(a.index(["git", "fetch", "origin", "main"]), a.index(co[0]))

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="covrun-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ); p.start(); self.addCleanup(p.stop)
        for k in _PATH_ENVS:
            os.environ.pop(k, None)
        os.environ["GITHUB_WORKSPACE"] = self.d("default-workspace")     # run() falls back to the cwd otherwise and would read the real repo's .vex/.auditor (rc-5b fix 13)

    def d(self, *parts):
        path = os.path.join(self.tmp, *parts); os.makedirs(path, exist_ok=True); return path

    def wj(self, path, obj):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(obj if isinstance(obj, str) else json.dumps(obj))
        return path

    def quiet(self, fn, *a, **kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            res = fn(*a, **kw)
        return res, buf.getvalue()

    def env(self, **kw):
        e = {"gvc": None, "module": None, "gvc_usable": False, "idx": {}, "logpath": None,
             "adjudicator": "/x/real-adjudicator.py", "state": {"tokens": 0, "roles_used": set()},
             "kev_ids": set(), "kev_ok": True, "exp": "2026-10-22", "out": self.d("out"),
             "ts": "2026-09-22T00:00:00Z", "dry": True, "digest": "sha256:cand", "carried_expiry": {},
             "carried_scopes": set(), "carried_status": {}, "today": "2026-09-22", "knowledge": "",
             "carriers": [], "base": {}, "carried_not_pullable": set(), "carried_lift_trigger": {},
             "base_policy_held": False}
        e.update(kw); return e


# ---------------------------------------------------------------- small pure helpers

class PureHelpers(Base):
    def test_carrier_for(self):
        crs = [{"component_purl": "pkg:deb/a@1", "carrier": "node"}]
        self.assertIsNone(R._carrier_for(crs, ["pkg:deb/b@1", None]))          # no match -> None
        self.assertIs(R._carrier_for(crs, [None, "pkg:deb/a@1"]), crs[0])       # match -> the record
        self.assertIsNone(R._carrier_for([], ["pkg:deb/a@1"]))

    def test_trace_covers_and_go_modver(self):
        ev = {"trace_modules": ["example.com/m@1.2.0"]}
        self.assertFalse(R._trace_covers("pkg:deb/debian/x@1.2.0", ev))         # not Go -> no closure
        self.assertFalse(R._trace_covers("pkg:golang/example.com/m", ev))      # no version -> no closure
        self.assertTrue(R._trace_covers("pkg:golang/example.com/m@v1.2.0", ev))
        self.assertFalse(R._trace_covers("pkg:golang/example.com/m@v1.3.0", ev))
        self.assertIsNone(R._go_modver("pkg:npm/left-pad@1.0.0"))
        self.assertEqual(R._go_modver("pkg:golang/example.com/m@v1.2.0?x=1"), "example.com/m@1.2.0")

    def test_a_panel_manifest_must_carry_the_panel_block_with_the_verdict_path(self):
        base = {"scanner_set": "panel", "scanner_reports": {k: None for k in R.PARS.PANEL_SCANNERS},
                "scanner_status": {k: {"reason": "x"} for k in R.PARS.PANEL_SCANNERS}}
        with self.assertRaisesRegex(ValueError, "no panel block"):
            R.C.validate_manifest(dict(base))
        with self.assertRaisesRegex(ValueError, "no panel block"):
            R.C.validate_manifest(dict(base, panel={"not_counted": None}))
        R.C.validate_manifest(dict(base, panel={"verdict": None}))              # a missing verdict is recorded, not a manifest error

    def test_only_the_panel_scanner_set_is_a_manifest(self):
        base = {"scanner_reports": {k: None for k in R.PARS.PANEL_SCANNERS}, "panel": {"verdict": None},
                "scanner_status": {k: {"reason": "x"} for k in R.PARS.PANEL_SCANNERS}}
        for bad in ("Panel", "panels", "", 3, ["panel"], None, "legacy"):         # an explicit null or the retired legacy value is not the panel
            with self.assertRaisesRegex(ValueError, "scanner_set"):
                R.C.validate_manifest(dict(base, scanner_set=bad))
        with self.assertRaisesRegex(ValueError, "scanner_set"):
            R.C.validate_manifest(dict(base))
        R.C.validate_manifest(dict(base, scanner_set="panel"))

    def test_the_panel_verdict_is_reread_and_revalidated_from_its_path(self):
        self.assertIsNone(R._panel_verdict(None)); self.assertIsNone(R._panel_verdict({})); self.assertIsNone(R._panel_verdict({"verdict": None}))
        d = self.d("v"); bad = os.path.join(d, "verdict.json"); open(bad, "w").write("{not json")
        self.assertIsNone(R._panel_verdict({"verdict": bad}))                              # unparseable
        self.assertIsNone(R._panel_verdict({"verdict": os.path.join(d, "gone.json")}))     # missing file
        open(bad, "w").write("{}")
        self.assertIsNone(R._panel_verdict({"verdict": bad}))                              # parses, does not validate

    def test_severity_by_scanner_keeps_each_scanners_highest_and_ignores_the_unrated(self):
        got = R._sev_by_scanner([{"scanner": "grype", "severity": "low"}, {"scanner": "grype", "severity": "high"},
                                 {"scanner": "grype", "severity": "medium"}, {"scanner": "scout"}, {"scanner": "inspector", "severity": "Critical"},
                                 {"severity": "high"}, {"scanner": "google", "severity": "weird"}, {"scanner": "google", "severity": "low"}])
        # a scanner that reported the finding without a severity is shown as not rated (never guessed, never dropped)
        self.assertEqual(got, {"grype": "high", "inspector": "Critical", "google": "low", "scout": "not rated"})

    def test_narrative_ok(self):
        secs = {n: [] for n in range(1, 8)}
        secs[3] = [{"id": "CVE-2099-3"}]; secs[5] = [{"id": "CVE-2099-5"}]
        pad = " " + "x" * 100 + " "
        self.assertFalse(R._narrative_ok("CVE-2099-9 appeared.", secs))                # unknown id
        self.assertFalse(R._narrative_ok("CVE-2099-3 was closed.", secs))              # §3 said closed
        self.assertFalse(R._narrative_ok("CVE-2099-5 is reachable.", secs))            # §5 said reachable
        self.assertTrue(R._narrative_ok("CVE-2099-3 needs a bump." + pad + "CVE-2099-5 is a false positive.", secs))

    def test_conclusion_budget_and_accepted_text(self):
        secs = {n: [] for n in range(1, 8)}; secs[3] = [{"id": "CVE-2099-3"}]
        st = {"tokens": policy.TOKEN_BUDGET}
        with mock.patch.object(R.cli, "ask_model") as ask:
            self.assertEqual(R._conclusion("/x/real.py", secs, {}, st),
                             "conclusion withheld: token budget reached before the narrative.")
            ask.assert_not_called()
        st = {"tokens": 10}
        with mock.patch.object(R.cli, "ask_model", return_value={"narrative": " CVE-2099-3 needs a bump. ", "token_usage": 4}) as ask:
            self.assertEqual(R._conclusion("/x/real.py", secs, {"commit": "c1"}, st), "CVE-2099-3 needs a bump.")
        self.assertEqual(st["tokens"], 14)
        self.assertIn("primary", st["roles_used"])
        self.assertEqual(ask.call_args.kwargs["attempt"], "narrative")
        self.assertNotIn("commit", ask.call_args.kwargs["context"]["structured"])   # the model is told nothing the key leaves out


# ---------------------------------------------------------------- no-change day (REQ-AUD-3 AC3)

class NoChange(Base):
    CTX = {"finding_id": "CVE-2099-7", "package": "libz", "installed_version": "1", "candidate_digest": "sha256:cand"}

    def state(self, **kw):
        st = {"tokens": 0, "roles_used": set(), "nc_verdicts": {}, "nc_pull": {}, "nc_narr": None,
              "nc_prev": None, "nc_today": "2026-10-24"}
        st.update(kw); return st

    def prev(self, **kw):
        doc = nochange.dump("2026-10-23", "a" * 64, {}, {}, None); doc.update(kw); return doc

    def test_a_reused_verdict_makes_no_model_call_and_is_carried_forward(self):
        key = nochange.call_key("adjudicate", self.CTX)
        st = self.state(nc_prev=self.prev(verdicts={key: "false_positive"}))
        with mock.patch.object(R.cli, "ask_model") as ask:
            self.assertEqual(R.adjudicate("/x/real.py", self.CTX, st), "false_positive")
        ask.assert_not_called()
        self.assertNotIn("calls", st); self.assertEqual(st["tokens"], 0)
        self.assertEqual(st["nc_verdicts"], {key: "false_positive"})
        self.assertEqual(st.get("nc_reused"), 1)

    def test_a_fresh_verdict_is_recorded_only_when_it_is_a_real_category(self):
        key = nochange.call_key("adjudicate", self.CTX)
        for cat, kept in (("real_fixable", True), ("under_investigation", True), ("unknown", False), ("burn_it_down", False)):
            st = self.state()
            with mock.patch.object(R.cli, "ask_model", return_value={"category": cat, "token_usage": 1}) as ask:
                self.assertEqual(R.adjudicate("/x/real.py", self.CTX, st), cat)
            self.assertEqual(ask.call_count, 1)
            self.assertEqual(st["nc_verdicts"], {key: cat} if kept else {}, cat)

    def test_a_different_context_is_a_miss_even_with_a_matching_state(self):
        st = self.state(nc_prev=self.prev(verdicts={nochange.call_key("adjudicate", dict(self.CTX, installed_version="0")): "false_positive"}))
        with mock.patch.object(R.cli, "ask_model", return_value={"category": "real_fixable", "token_usage": 1}) as ask:
            self.assertEqual(R.adjudicate("/x/real.py", self.CTX, st), "real_fixable")
        self.assertEqual(ask.call_count, 1)

    def test_a_refusal_or_an_error_is_never_recorded_as_a_verdict(self):
        st = self.state()
        with mock.patch.object(R.cli, "ask_model", side_effect=R.cli.Refused("no")):
            self.assertEqual(R.adjudicate("/x/real.py", self.CTX, st), "refused")
        self.assertEqual(st["nc_verdicts"], {})
        st = self.state()
        with mock.patch.object(R.cli, "ask_model", side_effect=RuntimeError("down")):
            self.assertEqual(R.adjudicate("/x/real.py", self.CTX, st), "adjudicator_error")
        self.assertEqual(st["nc_verdicts"], {})

    # REQ-AUD-3 AC3, Fable ruling on cache#684: a run where ANY attempted model call ended without a cacheable result is an incomplete run; it leaves no usable state.
    def test_a_complete_adjudication_leaves_the_run_complete(self):
        st = self.state()
        with mock.patch.object(R.cli, "ask_model", return_value={"category": "real_fixable", "token_usage": 1}):
            R.adjudicate("/x/real.py", self.CTX, st)
        self.assertFalse(st.get("nc_incomplete"))

    def test_every_uncacheable_adjudication_outcome_marks_the_run_incomplete(self):
        cases = (("an unknown answer", dict(return_value={"category": "unknown", "token_usage": 1}), {}),
                 ("a category outside the five", dict(return_value={"category": "burn_it_down", "token_usage": 1}), {}),
                 ("a refusal", dict(side_effect=R.cli.Refused("no")), {}),
                 ("an error", dict(side_effect=RuntimeError("down")), {}),
                 ("the token budget stop", dict(return_value={"category": "real_fixable"}), {"tokens": R.policy.TOKEN_BUDGET}))
        for label, ask_kw, st_kw in cases:
            st = self.state(**st_kw)
            with mock.patch.object(R.cli, "ask_model", **ask_kw):
                R.adjudicate("/x/real.py", self.CTX, st)
            self.assertTrue(st.get("nc_incomplete"), label)

    def test_a_reused_adjudication_makes_no_call_and_does_not_mark_the_run_incomplete(self):
        key = nochange.call_key("adjudicate", self.CTX)
        st = self.state(nc_prev=self.prev(verdicts={key: "false_positive"}))
        with mock.patch.object(R.cli, "ask_model") as ask:
            R.adjudicate("/x/real.py", self.CTX, st)
        ask.assert_not_called(); self.assertFalse(st.get("nc_incomplete"))

    def test_every_uncacheable_pullability_outcome_marks_the_run_incomplete(self):
        good = {"pullable": False, "token_usage": 1}
        cases = (("a refusal", dict(side_effect=R.cli.Refused("no")), {}),
                 ("an error", dict(side_effect=RuntimeError("down")), {}),
                 ("an answer the router cannot read", dict(return_value={"pullable": "maybe", "token_usage": 1}), {}),
                 ("the token budget stop", dict(return_value=good), {"tokens": R.policy.TOKEN_BUDGET}))
        for label, ask_kw, st_kw in cases:
            st = self.state(**st_kw)
            with mock.patch.object(R.cli, "ask_model", **ask_kw):
                R._pullability("/x/real.py", self.CTX, st)
            self.assertTrue(st.get("nc_incomplete"), label)
        st = self.state()
        with mock.patch.object(R.cli, "ask_model", return_value=good):
            R._pullability("/x/real.py", self.CTX, st)
        self.assertFalse(st.get("nc_incomplete"))

    def test_every_uncacheable_narrative_outcome_marks_the_run_incomplete(self):
        sections, m = {"s": 1}, {}
        cases = (("an error", dict(side_effect=RuntimeError("down")), {}),
                 ("a refusal", dict(side_effect=R.cli.Refused("no")), {}),
                 ("an empty narrative", dict(return_value={"narrative": "  ", "token_usage": 1}), {}),
                 ("a narrative that disagrees with the record", dict(return_value={"narrative": "text", "token_usage": 1}), {"bad": True}),
                 ("the token budget stop", dict(return_value={"narrative": "text"}), {"tokens": R.policy.TOKEN_BUDGET}))
        for label, ask_kw, flags in cases:
            st = self.state(**({"tokens": R.policy.TOKEN_BUDGET} if "budget" in label else {}))
            with mock.patch.object(R.cli, "ask_model", **ask_kw), mock.patch.object(R, "_narrative_structured", return_value={}), \
                 mock.patch.object(R, "_narrative_ok", return_value=not flags.get("bad")):
                R._conclusion("/x/real.py", sections, m, st)
            self.assertTrue(st.get("nc_incomplete"), label)
        st = self.state()
        with mock.patch.object(R.cli, "ask_model", return_value={"narrative": "fine", "token_usage": 1}), mock.patch.object(R, "_narrative_structured", return_value={}), \
             mock.patch.object(R, "_narrative_ok", return_value=True):
            R._conclusion("/x/real.py", sections, m, st)
        self.assertFalse(st.get("nc_incomplete"))

    def test_a_stub_adjudicator_makes_no_call_and_is_not_incomplete(self):
        st = self.state()
        R._conclusion("/x/stub.py", {}, {}, st)
        self.assertFalse(st.get("nc_incomplete"))

    def test_the_stable_base_drops_the_day_counter_but_keeps_the_threshold_decision(self):
        a = R._stable_base({"release": "debian 12.0", "behind_threshold_days": 30, "days_behind": 52})
        b = R._stable_base({"release": "debian 12.0", "behind_threshold_days": 30, "days_behind": 53})
        self.assertEqual(a, b); self.assertNotIn("days_behind", a); self.assertIs(a["behind_beyond_threshold"], True)
        self.assertIs(R._stable_base({"days_behind": 3})["behind_beyond_threshold"], False)
        self.assertEqual(R._stable_base({"release": "x"}), {"release": "x"})
        at, over = (R._stable_base({"behind_threshold_days": 30, "days_behind": d}) for d in (30, 31))
        self.assertNotEqual(at, over)                                              # crossing the threshold is a change
        self.assertEqual(R._stable_base(None), {})

    def test_the_adjudication_fingerprint_follows_prompt_adjudicator_and_model(self):
        adj = os.path.join(self.tmp, "adj.py"); open(adj, "w").write("print(1)")
        with mock.patch.dict(os.environ, {"AUDITOR_MODEL_PRIMARY": "m-one", "AUDITOR_MODEL_FALLBACK": "m-two"}):
            base = R._adjudication_fingerprint(adj)
            os.environ["AUDITOR_MODEL_PRIMARY"], os.environ["AUDITOR_MODEL_FALLBACK"] = "m-two", "m-one"      # the roles swapped
            self.assertNotEqual(base, R._adjudication_fingerprint(adj))
            os.environ["AUDITOR_MODEL_PRIMARY"], os.environ["AUDITOR_MODEL_FALLBACK"] = "m-one", "m-two"
            self.assertEqual(base, R._adjudication_fingerprint(adj))
            os.environ["AUDITOR_MODEL_PRIMARY"] = "m-three"
            self.assertNotEqual(base, R._adjudication_fingerprint(adj))
            os.environ["AUDITOR_MODEL_PRIMARY"] = "m-one"
            open(adj, "w").write("print(2)")
            self.assertNotEqual(base, R._adjudication_fingerprint(adj))
            self.assertNotEqual(R._adjudication_fingerprint(os.path.join(self.tmp, "missing.py")), base)
        self.assertNotIn("m-one", R._adjudication_fingerprint(adj))          # a digest, never the identifier itself

    def test_the_adjudication_fingerprint_follows_the_standing_prompt(self):
        adj = os.path.join(self.tmp, "adj.py"); open(adj, "w").write("print(1)")
        bindir = self.d("fake", "bin"); self.d("fake", "prompts")
        prompt = os.path.join(self.tmp, "fake", "prompts", "adjudicator.md")
        with mock.patch.object(R, "HERE", bindir):
            open(prompt, "w").write("answer in one word")
            a = R._adjudication_fingerprint(adj)
            open(prompt, "w").write("answer in two words")
            self.assertNotEqual(a, R._adjudication_fingerprint(adj))

    def test_a_reused_pullability_verdict_makes_no_call(self):
        ctx = {"kind": "pullability", "finding_id": "C", "candidate_digest": "d"}
        key = nochange.call_key("pullability", ctx)
        verdict = {"pullable": False, "lift_trigger": "base >= 3"}
        st = self.state(nc_prev=self.prev(pullability={key: verdict}))
        with mock.patch.object(R.cli, "ask_model") as ask:
            self.assertEqual(R._pullability("/x/real.py", ctx, st), verdict)
        ask.assert_not_called()
        self.assertEqual(st["nc_pull"], {key: verdict}); self.assertNotIn("calls", st)

    def test_a_fresh_pullability_verdict_is_recorded_by_its_known_keys_only(self):
        ctx = {"kind": "pullability", "finding_id": "C", "candidate_digest": "d"}
        key = nochange.call_key("pullability", ctx)
        st = self.state()
        ans = {"pullable": False, "lift_trigger": "x", "token_usage": 5, "surprise": {"nested": 1}, "evidence": {"how": "e"}}
        with mock.patch.object(R.cli, "ask_model", return_value=ans):
            got = R._pullability("/x/real.py", ctx, st)
        self.assertEqual(got, ans)
        self.assertEqual(st["nc_pull"], {key: {"pullable": False, "lift_trigger": "x", "evidence": {"how": "e"}}})

    def test_a_pullability_answer_the_router_cannot_read_is_unusable_and_not_cached(self):
        ctx = {"kind": "pullability", "finding_id": "C", "candidate_digest": "d"}
        for bad in ({"pullable": False, "lift_trigger": 12}, {"pullable": False, "lift_trigger": "x", "hold": "arbitrary"},
                    {"pullable": "no"}, {"pullable": False, "lift_trigger": "x" * 5000}, {"evidence": ["x"]}):
            st = self.state()
            with mock.patch.object(R.cli, "ask_model", return_value=dict(bad, token_usage=5)):
                self.assertIsNone(R._pullability("/x/real.py", ctx, st), bad)       # as if the model had been unavailable: the finding stays actionable
            self.assertEqual(st["nc_pull"], {}, bad)
            self.assertEqual(st["tokens"], 5)                                     # the call was made and billed

    def test_a_reused_narrative_is_marked_unchanged_and_makes_no_call(self):
        secs = {n: [] for n in range(1, 8)}; secs[3] = [{"id": "CVE-2099-3"}]
        m = {"commit": "c1", "candidate_digests": {"production": "sha256:p"}}
        key = R._narrative_key(secs, m)
        st = self.state(nc_prev=self.prev(narrative={"key": key, "text": "CVE-2099-3 needs a bump.", "date": "2026-10-22"}))
        with mock.patch.object(R.cli, "ask_model") as ask:
            text = R._conclusion("/x/real.py", secs, m, st)
        ask.assert_not_called()
        self.assertEqual(text, "CVE-2099-3 needs a bump.\n\n(unchanged since 2026-10-22)")
        self.assertEqual(st["nc_narr"], {"key": key, "text": "CVE-2099-3 needs a bump.", "date": "2026-10-22"})

    def test_the_narrative_request_is_exactly_what_its_key_covers(self):
        secs = {n: [] for n in range(1, 8)}; secs[3] = [{"id": "CVE-2099-3"}]
        reqs = []
        for commit in ("c1", "c2"):
            with mock.patch.object(R.cli, "ask_model", return_value={"narrative": "CVE-2099-3 needs a bump."}) as ask:
                R._conclusion("/x/real.py", secs, {"commit": commit}, self.state())
            reqs.append(ask.call_args.kwargs["context"])
        self.assertEqual(reqs[0], reqs[1])

    def test_a_new_commit_alone_does_not_change_the_narrative_key(self):
        secs = {n: [] for n in range(1, 8)}
        self.assertEqual(R._narrative_key(secs, {"commit": "c1"}), R._narrative_key(secs, {"commit": "c2"}))
        secs2 = {n: [] for n in range(1, 8)}; secs2[3] = [{"id": "CVE-2099-3"}]
        self.assertNotEqual(R._narrative_key(secs, {"commit": "c1"}), R._narrative_key(secs2, {"commit": "c1"}))

    def test_a_reused_narrative_that_no_longer_fits_the_record_is_asked_again(self):
        secs = {n: [] for n in range(1, 8)}; secs[3] = [{"id": "CVE-2099-3"}]; secs[5] = [{"id": "CVE-2099-5"}]
        m = {"commit": "c1"}; key = R._narrative_key(secs, m)
        st = self.state(nc_prev=self.prev(narrative={"key": key, "text": "CVE-2099-9 appeared.", "date": "2026-10-22"}))
        with mock.patch.object(R.cli, "ask_model", return_value={"narrative": "CVE-2099-3 needs a bump.", "token_usage": 2}) as ask:
            text = R._conclusion("/x/real.py", secs, m, st)
        self.assertEqual(ask.call_count, 1)
        self.assertEqual(text, "CVE-2099-3 needs a bump.")
        self.assertEqual(st["nc_narr"]["date"], "2026-10-24")

    def test_a_fresh_narrative_is_recorded_with_todays_date(self):
        secs = {n: [] for n in range(1, 8)}; secs[3] = [{"id": "CVE-2099-3"}]
        st = self.state()
        with mock.patch.object(R.cli, "ask_model", return_value={"narrative": "CVE-2099-3 needs a bump.", "token_usage": 2}):
            R._conclusion("/x/real.py", secs, {"commit": "c1"}, st)
        self.assertEqual(st["nc_narr"], {"key": R._narrative_key(secs, {"commit": "c1"}), "text": "CVE-2099-3 needs a bump.", "date": "2026-10-24"})

    def test_a_withheld_narrative_is_not_recorded(self):
        secs = {n: [] for n in range(1, 8)}
        st = self.state()
        with mock.patch.object(R.cli, "ask_model", side_effect=RuntimeError("down")):
            R._conclusion("/x/real.py", secs, {}, st)
        self.assertIsNone(st["nc_narr"])
        st = self.state()
        with mock.patch.object(R.cli, "ask_model", return_value={"narrative": "CVE-2099-9 appeared.", "token_usage": 1}):
            R._conclusion("/x/real.py", secs, {}, st)
        self.assertIsNone(st["nc_narr"])


# ---------------------------------------------------------------- pullability model call

class Pullability(Base):
    def test_over_budget_makes_no_call(self):
        with mock.patch.object(R.cli, "ask_model") as ask:
            st = {"tokens": policy.TOKEN_BUDGET}
            self.assertIsNone(R._pullability("/a", {"finding_id": "C"}, st))
        ask.assert_not_called()
        self.assertNotIn("calls", st)

    def test_refusal_is_billed_and_returns_none(self):
        ex = R.cli.Refused("C"); ex.token_usage = 11
        st = {"tokens": 5}
        with mock.patch.object(R.cli, "ask_model", side_effect=ex):
            self.assertIsNone(R._pullability("/a", {"finding_id": "C"}, st))
        self.assertEqual(st["tokens"], 16); self.assertEqual(st["calls"], 1)

    def test_error_recorded_once_masked(self):
        st = {"tokens": 0}
        errs = [RuntimeError("HTTP 529 from claude-zz-9 [request_id=abc123]"),
                RuntimeError("HTTP 529 from claude-zz-9 [request_id=def456]")]
        with mock.patch.object(R.cli, "ask_model", side_effect=errs):
            (r1, out1) = self.quiet(R._pullability, "/a", {"finding_id": "C"}, st)
            (r2, out2) = self.quiet(R._pullability, "/a", {"finding_id": "C"}, st)
        self.assertIsNone(r1); self.assertIsNone(r2)
        self.assertEqual(len(st["adj_errors"]), 1)                          # deduped across request ids
        msg = list(st["adj_errors"].values())[0]
        self.assertIn("RuntimeError: HTTP 529 from <model-id>", msg)
        self.assertNotIn("claude-zz-9", msg)
        self.assertIn("pullability error:", out1); self.assertEqual(out2, "")
        self.assertEqual(st["calls"], 2)


# ---------------------------------------------------------------- _dispose branches

class Dispose(Base):
    PURL = "pkg:deb/debian/libz@1.0?arch=arm64"

    def _log(self, fid, purl):
        return self.wj(os.path.join(self.tmp, "log.json"),
                       {"defects": [{"keys": [{"scanner": "grype", "finding_id": fid, "purl": purl}],
                                     "package": "libz", "disposition": "false_positive"}]})

    def test_model_fp_verified_by_log_closes_section5(self):
        c = "CVE-2099-10"; f = F(c, self.PURL, "libz")
        env = self.env(logpath=self._log(c, self.PURL))
        with mock.patch.object(R.cli, "ask_model", return_value={"category": "false_positive", "token_usage": 3}):
            row, mi = R._dispose(c, [f], [c], env, [])
        self.assertEqual((row["section"], row["disposition"], row["action"]), (5, "not_affected (false positive)", "closed"))
        self.assertEqual(row["reason"], "model FP, evidence-verified"); self.assertEqual(mi, 1)
        self.assertFalse(row["carried"])
        self.assertEqual(row["vex_id"], policy.scope_id(c, PROD, [self.PURL]))
        doc = json.load(open(os.path.join(env["out"], "vex", c + ".openvex.json")))
        self.assertEqual(doc["statements"][0]["status"], "not_affected")
        self.assertEqual(doc["statements"][0]["justification"], "vulnerable_code_not_present")
        # same scope already published not_affected on main -> carried (in force)
        env2 = self.env(logpath=env["logpath"], carried_status={(c, scope([self.PURL])): "not_affected"})
        with mock.patch.object(R.cli, "ask_model", return_value={"category": "false_positive"}):
            row2, _ = R._dispose(c, [f], [c], env2, [])
        self.assertTrue(row2["carried"])

    def test_model_fp_unverified_falls_through_to_poam(self):
        c = "CVE-2099-11"; f = F(c, self.PURL, "libz")
        env = self.env(logpath=self._log("CVE-OTHER", self.PURL))
        with mock.patch.object(R.cli, "ask_model", return_value={"category": "false_positive"}):
            row, _ = R._dispose(c, [f], [c], env, [])
        self.assertEqual((row["section"], row["disposition"]), (2, "carried (POA&M)"))

    def test_refusal_with_stub_does_not_escalate_but_real_does(self):
        c = "CVE-2099-12"; f = F(c, self.PURL, "libz")
        with mock.patch.object(R.cli, "ask_model", side_effect=R.cli.Refused(c)) as ask:
            row, mi = R._dispose(c, [f], [c], self.env(adjudicator="/x/stub-adjudicator.py"), [])
        self.assertEqual([k.kwargs["attempt"] for k in ask.call_args_list], ["primary", "rephrase", "fallback"])
        self.assertEqual((row["section"], row["action"], row["cause"]),
                         (4, "none (stub: no owner escalation)", "stub: no canned answer"))
        self.assertEqual(row["reason"], "adjudication exhausted")
        self.assertNotIn("owner_issue_intent", row); self.assertEqual(mi, 1)
        with mock.patch.object(R.cli, "ask_model", side_effect=R.cli.Refused(c)):
            row2, _ = R._dispose(c, [f], [c], self.env(adjudicator="/x/real-adjudicator.py"), [])
        self.assertEqual(row2["cause"], "model refused after fallback")
        self.assertEqual(row2["owner_issue_intent"]["kind"], "unassessed")

    def _not_pullable(self, kev_ok, sev="Low"):
        c = "CVE-2099-13"; f = F(c, self.PURL, "libz", sev=sev, fixed="1.1")
        carrier = {"component_purl": self.PURL, "carrier": "nodejs", "carrier_version": "20.1"}
        env = self.env(carriers=[carrier], kev_ok=kev_ok)
        ans = {"pullable": False, "lift_trigger": {"carrier": "nodejs", "min_version": "20.2", "component": "libz",
            "component_min_version": "3.0.13"}, "token_usage": 7}
        with mock.patch.object(R.cli, "ask_model", return_value=ans) as ask:
            row, mi = R._dispose(c, [f], [c], env, [])
        self.assertEqual(ask.call_args.kwargs["attempt"], "pullability")
        self.assertEqual(ask.call_args.kwargs["context"]["carrier"], carrier)
        self.assertEqual(env["state"]["tokens"], 7); self.assertEqual(mi, 1)
        return c, env, row

    def test_not_pullable_kev_unavailable_fails_closed_to_owner_issue(self):
        c, env, row = self._not_pullable(kev_ok=False)
        self.assertEqual((row["section"], row["not_pullable"]), (2, "upstream-held"))
        self.assertEqual(row["threshold"], "at_or_above")
        self.assertTrue(row["action"].endswith("; owner-decision issue pending"))
        self.assertEqual(row["owner_issue_intent"]["reason_key"], "kev-unavailable (fail-closed)")
        self.assertEqual(row["owner_issue_intent"]["kind"], "risk_acceptance")
        self.assertIn("carried by nodejs at 20.1", row["reason"])
        self.assertEqual(row["ignore_files"], ["vex"])                       # the OpenVEX is the only exception (rule 4)
        self.assertFalse(os.path.exists(os.path.join(env["out"], "ignores")))

    def test_not_pullable_below_threshold_when_kev_ok(self):
        _c, _e, row = self._not_pullable(kev_ok=True)
        self.assertEqual(row["threshold"], "below")
        self.assertNotIn("owner_issue_intent", row)
        self.assertNotIn("owner-decision", row["action"])

    def test_carried_not_pullable_expired_reopens_section3(self):
        c = "CVE-2099-14"; f = F(c, self.PURL, "libz", fixed="1.1"); key = (c, scope([self.PURL]))
        env = self.env(carried_not_pullable={key}, carried_expiry={key: "2026-09-01"})
        with mock.patch.object(R.cli, "ask_model") as ask:
            row, mi = R._dispose(c, [f], [c], env, [])
        ask.assert_not_called()                                           # no carrier signal -> no call
        self.assertEqual((row["section"], row["disposition"]), (3, "reopened: prior acceptance expired"))
        self.assertIn("recheck deferred", row["reason"])
        self.assertEqual(row["reopened_scope"], [c, [PROD], [self.PURL]])
        self.assertEqual(row["reopened_expired"], "2026-09-01"); self.assertEqual(mi, 0)
        self.assertFalse(os.path.exists(os.path.join(env["out"], "vex", c + ".openvex.json")))

    def test_carried_not_pullable_deferred_kev_unavailable(self):
        c = "CVE-2099-15"; f = F(c, self.PURL, "libz", fixed="1.1"); key = (c, scope([self.PURL]))
        base = dict(carried_not_pullable={key}, carried_expiry={key: "2026-12-01"},
                    carried_lift_trigger={key: {"carrier": "nodejs", "min_version": "20.2", "component": "libz",
                        "component_min_version": "3.0.13"}})
        row, _ = R._dispose(c, [f], [c], self.env(kev_ok=False, **base), [])
        self.assertEqual(row["disposition"], "carried (fix not pullable) — recheck deferred")
        self.assertEqual((row["threshold"], row["expiry"], row["lift_trigger"]), ("at_or_above", "2026-12-01",
            {"carrier": "nodejs", "min_version": "20.2", "component": "libz", "component_min_version": "3.0.13"}))
        self.assertEqual(row["owner_issue_intent"]["reason_key"], "kev-unavailable (fail-closed)")
        self.assertIn("carrier signal absent this run", row["action"])
        row2, _ = R._dispose(c, [f], [c], self.env(kev_ok=True, **base), [])
        self.assertEqual(row2["threshold"], "below"); self.assertNotIn("owner_issue_intent", row2)


# ---------------------------------------------------------------- rc-5b R1: the lift trigger is structured and
# machine-checked

class LiftTrigger(Base):
    PURL = "pkg:deb/debian/libz@1.0?arch=arm64"
    GOOD = {"carrier": "nodejs", "min_version": "20.2", "component": "libz", "component_min_version": "3.0.13"}

    def test_the_shape_is_checked(self):
        self.assertEqual(R._lift_trigger(self.GOOD), self.GOOD)
        self.assertEqual(R._lift_trigger({"carrier": " nodejs ", "min_version": " v20.2.1 ", "component": "openssl",
            "component_min_version": "3.0.13"}), {"carrier": "nodejs", "min_version": "v20.2.1", "component": "openssl",
            "component_min_version": "3.0.13"})
        # a letter suffix is a real version
        self.assertEqual(R._lift_trigger({"carrier": "openssl", "min_version": "1.1.1n", "component": "openssl",
            "component_min_version": "3.0.13"}), {"carrier": "openssl", "min_version": "1.1.1n", "component": "openssl",
            "component_min_version": "3.0.13"})
        for bad in ("nodejs >= 20.2 embeds libz 1.1", "", None, 5, [], {}, {"carrier": "nodejs"},
            {"min_version": "20.2", "component": "openssl", "component_min_version": "3.0.13"},
                    {"carrier": "nodejs", "min_version": "20.2", "extra": 1}, {"carrier": "", "min_version": "20.2",
                        "component": "openssl", "component_min_version": "3.0.13"}, {"carrier": "nodejs",
                        "min_version": "", "component": "openssl", "component_min_version": "3.0.13"},
                    {"carrier": "nodejs", "min_version": "soon", "component": "openssl",
                        "component_min_version": "3.0.13"}, {"carrier": "nodejs", "min_version": "\u0662\u0660",
                        "component": "openssl", "component_min_version": "3.0.13"}, {"carrier": "nodejs",
                        "min_version": "20.2; rm", "component": "openssl", "component_min_version": "3.0.13"},
                        {"carrier": 5, "min_version": "20.2", "component": "openssl",
                        "component_min_version": "3.0.13"},
                    {"carrier": "node\njs", "min_version": "20.2", "component": "openssl",
                        "component_min_version": "3.0.13"}, {"carrier": "x" * 201, "min_version": "20.2",
                        "component": "openssl", "component_min_version": "3.0.13"}, {"carrier": "nodejs",
                        "min_version": "9" * 65}):
            self.assertIsNone(R._lift_trigger(bad), repr(bad))
        g = self.GOOD
        # the old two-key form: no component, no acceptance
        for bad in ({"carrier": "nodejs", "min_version": "20.2"},
                    dict(g, component=""), dict(g, component="o\npenssl"), dict(g, component="x" * 201),
                    dict(g, component_min_version=""), dict(g, component_min_version="soon"), dict(g,
                        component_min_version="3.0; rm"), dict(g, component_min_version="9" * 65),
                    dict(g, component=3), dict(g, component_min_version=None)):
            self.assertIsNone(R._lift_trigger(bad), repr(bad))
        self.assertEqual(R._trigger_text(g), "nodejs >= 20.2 embeds libz >= 3.0.13")

    def test_versions_compare_by_their_numbers_a_letter_or_a_debian_revision(self):
        for a, b, want in (("20.3", "20.2", True), ("20.2", "20.2", True), ("20.1", "20.2", False),
                           ("20.10", "20.2", True), ("v20.2.1", "20.2", True), ("20.2", "20.2.1", False),
                           ("12.4", "12.6", False), ("abc", "20.2", None), ("20.2", "abc", None), (None, "1", None),
                           # a letter suffix orders (OpenSSL), a plain version is below its lettered one
                           ("1.1.1n", "1.1.1w", False), ("1.1.1w", "1.1.1n", True), ("1.1.1n", "1.1.1n", True),
                           ("1.1.1a", "1.1.1", True), ("1.1.1", "1.1.1a", False),
                           # a Debian revision orders: -1 < -1+deb12u1 < -2
                           ("3.0.9-1", "3.0.9-1+deb12u1", False), ("3.0.9-1+deb12u1", "3.0.9-1", True),
                           ("3.0.9-1+deb12u2", "3.0.9-1+deb12u10", False), ("3.0.9-2", "3.0.9-1+deb12u1", True),
                           ("3.0.9-1", "3.0.9", True), ("3.0.9", "3.0.9-1", False),
                           # a suffix that cannot be ordered here is unknown, never equal to its base
                           ("20.2~rc1", "20.2", None), ("20.2", "20.2~rc1", None), ("3.0.13-1~deb12u1", "3.0.13", None),
                           ("1.1.1nn", "1.1.1", None), ("1.1.1N", "1.1.1", None), ("1.1.1n", "3.0.9-1", None)):
            self.assertIs(R._version_ge(a, b), want, (a, b))

    def test_a_carried_trigger_for_another_component_is_not_trusted_on_the_recheck(self):
        c = "CVE-2099-27"; f = F(c, self.PURL, "libz", fixed="1.1"); key = (c, scope([self.PURL]))
        carrier = {"component_purl": self.PURL, "carrier": "nodejs", "carrier_version": "20.1"}   # below the trigger
        about_openssl = dict(self.GOOD, component="openssl")
        env = self.env(carriers=[carrier], carried_not_pullable={key}, carried_expiry={key: "2026-12-01"},
                       carried_lift_trigger={key: about_openssl})
        with mock.patch.object(R.cli, "ask_model", return_value={"pullable": False, "token_usage": 1}) as ask:
            row, mi = R._dispose(c, [f], [c], env, [])
        ask.assert_called_once()                 # not skipped as "unmet": the model is asked, as for a legacy trigger
        self.assertNotEqual(row.get("lift_trigger"), about_openssl)       # and the mismatched trigger is not re-carried

    def test_a_recheck_whose_model_call_fails_says_the_adjudicator_was_unavailable(self):
        c = "CVE-2099-28"; f = F(c, self.PURL, "libz", fixed="1.1"); key = (c, scope([self.PURL]))
        carrier = {"component_purl": self.PURL, "carrier": "nodejs", "carrier_version": "20.3"}     # the trigger is met
        env = self.env(carriers=[carrier], carried_not_pullable={key}, carried_expiry={key: "2026-12-01"},
                       carried_lift_trigger={key: self.GOOD})
        with mock.patch.object(R.cli, "ask_model", side_effect=RuntimeError("down")):
            row, mi = R._dispose(c, [f], [c], env, [])
        self.assertEqual(row["disposition"], "carried (fix not pullable) — recheck deferred")
        # the suppression is retained
        self.assertIn("recheck deferred (adjudicator unavailable)", row["action"])

    def test_a_trigger_must_name_the_findings_own_component(self):
        self.assertEqual(R._trigger_for(self.GOOD, "libz"), self.GOOD)
        self.assertEqual(R._trigger_for(self.GOOD, " LIBZ "), self.GOOD)                 # case and spaces do not matter
        self.assertIsNone(R._trigger_for(self.GOOD, "openssl"))                           # another component's trigger
        self.assertIsNone(R._trigger_for(self.GOOD, None))
        # still checked by shape
        self.assertIsNone(R._trigger_for({"carrier": "nodejs", "min_version": "20.2"}, "libz"))
        c = "CVE-2099-26"; f = F(c, self.PURL, "libz", fixed="1.1")
        carrier = {"component_purl": self.PURL, "carrier": "nodejs", "carrier_version": "20.1"}
        about_openssl = dict(self.GOOD, component="openssl")
        with mock.patch.object(R.cli, "ask_model", return_value={"pullable": False, "lift_trigger": about_openssl,
                                                                  "token_usage": 1}):
            row, _ = R._dispose(c, [f], [c], self.env(carriers=[carrier]), [])
        self.assertNotEqual(row["section"], 2); self.assertNotIn("lift_trigger", row)    # no acceptance: stays visible

    def test_the_trigger_state_reads_the_carrier_version(self):
        crs = {"component_purl": self.PURL, "carrier": "nodejs", "carrier_version": "20.1"}
        self.assertEqual(R._trigger_state(self.GOOD, crs), "unmet")
        self.assertEqual(R._trigger_state(self.GOOD, dict(crs, carrier_version="20.2")), "met")
        # the carrier named by purl or by name
        self.assertEqual(R._trigger_state(self.GOOD, dict(crs, carrier="pkg:deb/debian/NodeJS@20.1")), "unmet")
        # a different carrier proves nothing
        self.assertEqual(R._trigger_state(self.GOOD, dict(crs, carrier="other")), "unknown")
        self.assertEqual(R._trigger_state(self.GOOD, dict(crs, carrier_version="weird")), "unknown")
        self.assertEqual(R._trigger_state(self.GOOD, None), "unknown")
        # a legacy or malformed trigger is never compared
        self.assertEqual(R._trigger_state(None, crs), "unknown")

    def test_a_structured_trigger_is_accepted_and_an_unstructured_one_is_not(self):
        c = "CVE-2099-21"; f = F(c, self.PURL, "libz", fixed="1.1")
        carrier = {"component_purl": self.PURL, "carrier": "nodejs", "carrier_version": "20.1"}
        with mock.patch.object(R.cli, "ask_model", return_value={"pullable": False, "lift_trigger": self.GOOD,
            "token_usage": 1}):
            row, _ = R._dispose(c, [f], [c], self.env(carriers=[carrier]), [])
        self.assertEqual((row["section"], row["lift_trigger"]), (2, self.GOOD))
        self.assertIn("lifts when nodejs >= 20.2", row["reason"])
        with mock.patch.object(R.cli, "ask_model", return_value={"pullable": False,
            "lift_trigger": "nodejs >= 20.2 embeds libz 1.1", "token_usage": 1}):
            row2, _ = R._dispose(c, [f], [c], self.env(carriers=[carrier]), [])
        # no acceptance without a machine-checkable trigger
        self.assertNotEqual(row2["section"], 2)
        self.assertNotIn("lift_trigger", row2)

    def test_a_trigger_the_carrier_already_meets_is_no_acceptance(self):
        c = "CVE-2099-24"; f = F(c, self.PURL, "libz", fixed="1.1")
        # already at the trigger's version
        carrier = {"component_purl": self.PURL, "carrier": "nodejs", "carrier_version": "20.3"}
        with mock.patch.object(R.cli, "ask_model", return_value={"pullable": False, "lift_trigger": self.GOOD,
            "token_usage": 1}):
            row, _ = R._dispose(c, [f], [c], self.env(carriers=[carrier]), [])
        self.assertNotEqual(row["section"], 2); self.assertNotIn("lift_trigger", row)

    def test_a_base_held_scope_is_not_skipped_by_the_carrier_comparison(self):
        c = "CVE-2099-25"; f = F(c, self.PURL, "libz", fixed="1.1"); key = (c, scope([self.PURL]))
        carrier = {"component_purl": self.PURL, "carrier": "nodejs", "carrier_version": "20.1"}
        env = self.env(carriers=[carrier], base_policy_held=True, carried_not_pullable={key},
            carried_expiry={key: "2026-12-01"}, carried_lift_trigger={key: self.GOOD})
        with mock.patch.object(R.cli, "ask_model", return_value={"pullable": True, "component_fixed": "1.1",
            "candidate_release": "debian 12.6", "token_usage": 1}) as ask:
            row, mi = R._dispose(c, [f], [c], env, [])
        # the base release can still lift it
        self.assertEqual(ask.call_args.kwargs["attempt"], "pullability")
        self.assertEqual(row["disposition"], "lifted (fix now pullable)")

    def _recheck(self, version, trigger, ask_answer=None):
        c = "CVE-2099-22"; f = F(c, self.PURL, "libz", fixed="1.1"); key = (c, scope([self.PURL]))
        carrier = {"component_purl": self.PURL, "carrier": "nodejs", "carrier_version": version}
        env = self.env(carriers=[carrier], carried_not_pullable={key}, carried_expiry={key: "2026-12-01"},
            carried_lift_trigger={key: trigger})
        with mock.patch.object(R.cli, "ask_model", return_value=ask_answer or {"pullable": False,
            "lift_trigger": self.GOOD, "token_usage": 1}) as ask:
            row, mi = R._dispose(c, [f], [c], env, [])
        return row, mi, ask

    def test_the_recheck_compares_the_carrier_version_before_asking_the_model(self):
        # the carrier is still below the trigger
        row, mi, ask = self._recheck("20.1", self.GOOD)
        ask.assert_not_called(); self.assertEqual(mi, 0)
        self.assertEqual((row["section"], row["lift_trigger"]), (2, self.GOOD))
        self.assertIn("lift trigger not met", row["action"]); self.assertIn("nodejs at 20.1", row["action"])
        row, mi, ask = self._recheck("20.3", self.GOOD, {"pullable": True, "component_fixed": "1.1",
            "candidate_release": "nodejs 20.3", "token_usage": 1})
        # met: the model confirms before anything lifts
        self.assertEqual(ask.call_args.kwargs["attempt"], "pullability"); self.assertEqual(mi, 1)
        self.assertEqual(row["disposition"], "lifted (fix now pullable)")
        # met but not confirmed: stays carried
        row, mi, ask = self._recheck("20.3", self.GOOD)
        self.assertEqual(mi, 1); self.assertEqual(row["section"], 2)

    def test_a_legacy_text_trigger_is_not_compared_not_dropped(self):
        # carried by an earlier release as free text
        row, mi, ask = self._recheck("20.1", "nodejs >= 20.2 embeds libz 1.1")
        # asked, as before
        self.assertEqual(ask.call_args.kwargs["attempt"], "pullability"); self.assertEqual(mi, 1)
        # and replaced by the structured one the model gives
        self.assertEqual((row["section"], row["lift_trigger"]), (2, self.GOOD))

    def test_a_deferred_recheck_keeps_the_structured_trigger(self):
        c = "CVE-2099-23"; f = F(c, self.PURL, "libz", fixed="1.1"); key = (c, scope([self.PURL]))
        env = self.env(carried_not_pullable={key}, carried_expiry={key: "2026-12-01"},
            carried_lift_trigger={key: self.GOOD})
        row, _ = R._dispose(c, [f], [c], env, [])                                          # no carrier signal this run
        self.assertEqual(row["lift_trigger"], self.GOOD)


# ---------------------------------------------------------------- merge / consolidate fallbacks

class PurlVersion(unittest.TestCase):
    def test_a_purl_version_is_decoded_and_stops_at_the_subpath(self):
        # one version, however a scanner spells it: the disposition grouping must not split on %2B vs +
        self.assertEqual(R._ver_from_purl("pkg:deb/debian/openssl@3.0.1%2Bdeb12u1?arch=amd64"), "3.0.1+deb12u1")
        self.assertEqual(R._ver_from_purl("pkg:deb/debian/openssl@3.0.1+deb12u1"), "3.0.1+deb12u1")
        self.assertEqual(R._ver_from_purl("pkg:golang/x/y@v1.2.3#sub/path"), "v1.2.3")
        self.assertIsNone(R._ver_from_purl("pkg:generic/x"))
        self.assertIsNone(R._ver_from_purl(None))


class NeedsHuman(unittest.TestCase):
    def test_the_unsettled_run_issue_is_a_section_zero_item_and_a_failed_one_is_said(self):
        none = {n: [] for n in range(1, 8)}
        self.assertEqual(R._needs_human([], none, True, None, "ok"), [])
        self.assertEqual(R._needs_human([], none, True, None, "ok", "dry"), [])
        self.assertEqual(R._needs_human([], none, True, None, "ok", "skipped"), [])
        self.assertEqual(R._needs_human([], none, True, None, "ok", "#12"), ["owner-decision needed: findings unsettled for 5 consecutive runs — #12"])
        self.assertEqual(R._needs_human([], none, True, None, "ok", "FAILED"), ["owner-decision issue FAILED to open: findings unsettled for 5 consecutive runs"])


class ResolveCarried(unittest.TestCase):
    def test_a_statement_without_a_vulnerability_name_is_skipped(self):
        """a carried statement that names no vulnerability cannot match a flagged entry, and is never reported as not re-checkable"""
        stmts = [{"products": []}, {"vulnerability": {"name": "CVE-2099-1"}, "products": []}]
        self.assertEqual(R._resolve_carried({}, stmts), ["CVE-2099-1"])

    def _groups(self):
        f = R.PARS._finding("inspector", "CVE-2099-7", "pkg:generic/libfoo", (), "libfoo", None, None, {"carried": True, "version": "1.0"})
        return {"CVE-2099-7": {"id": "CVE-2099-7", "aliases": [], "findings": [f], "lineages": {"inspector"}}}

    @staticmethod
    def _stmt(arch):
        return {"vulnerability": {"name": "CVE-2099-7"},
                "products": [{"@id": "pkg:oci/x", "subcomponents": [{"@id": "pkg:deb/debian/libfoo@1.0?arch=%s&distro=debian-12.0" % arch}]}]}

    def test_a_change_only_in_the_carried_resolution_never_reuses_a_verdict_for_a_different_question(self):
        """the no-change hash is taken over the groups BEFORE the carried statements are resolved, so two runs can share it while the statements resolve differently. That
        cannot produce a wrong reuse: a reused verdict, pullability record or narrative is looked up by the key of the exact context the model is given (nochange.call_key),
        and that context carries the resolved purl, so a different resolution is a different key and the model is asked again; the same resolution is the same question."""
        ctx = lambda groups: {"finding_id": "CVE-2099-7", "package": "libfoo", "purl": groups["CVE-2099-7"]["findings"][0]["purl"]}
        before_a, before_b = self._groups(), self._groups()
        self.assertEqual(nochange.finding_set_hash(before_a, {}), nochange.finding_set_hash(before_b, {}))             # same hash, resolved differently below
        R._resolve_carried(before_a, [self._stmt("amd64")]); R._resolve_carried(before_b, [self._stmt("arm64")])
        same = self._groups(); R._resolve_carried(same, [self._stmt("amd64")])
        key = lambda g: nochange.call_key("adjudicate", ctx(g))
        self.assertNotEqual(key(before_a), key(before_b))
        self.assertEqual(key(before_a), key(same))
        yesterday = {"verdicts": {key(before_a): "false_positive"}}
        self.assertEqual(nochange.verdict(yesterday, key(same)), "false_positive")
        self.assertIsNone(nochange.verdict(yesterday, key(before_b)))


class MergeConsolidate(Base):
    def _stmt(self, cve, purls, status="affected"):
        return R.vex.doc(cve, status, "2026-09-22T00:00:00Z", action="x", subcomponents=purls)["statements"][0]

    def _supp(self, statements, version=1):
        out = self.d("out"); supp = self.d("out", "suppressions")
        self.wj(os.path.join(supp, "fosterstack-cache.openvex.json"),
                {"@context": "c", "@id": policy.VEX_BASE, "author": "a", "role": "vendor",
                 "timestamp": "t", "version": version, "statements": statements})
        return out, supp

    def test_two_retained_statements_without_an_id_are_made_separately_addressable(self):
        # AC2 safety net: statements of DIFFERENT scopes that arrive with no @id (or the same one) never leave the merge sharing an @id
        ws = self.d("ws"); a = self._stmt("CVE-2099-30", ["pkg:deb/a@1"]); b = self._stmt("CVE-2099-30", ["pkg:deb/b@1"])
        a.pop("@id"); b.pop("@id")
        self.wj(os.path.join(ws, ".vex", "fosterstack-cache.openvex.json"),
                {"@context": "c", "@id": policy.VEX_BASE, "author": "a", "role": "vendor", "timestamp": "t", "version": 2, "statements": [a, b]})
        _out, supp = self._supp([self._stmt("CVE-2099-31", ["pkg:deb/c@1"])], version=3)
        R._merge_suppressions(ws, supp)
        got = json.load(open(os.path.join(ws, ".vex", "fosterstack-cache.openvex.json")))["statements"]
        ids = [s["@id"] for s in got]
        self.assertEqual(len(got), 3)
        self.assertEqual(len(set(ids)), 3, ids)

    def test_corrupt_existing_vex_stops_the_run(self):
        # rc-5b fix 13: a reviewed file that is present but unreadable is a stop, never "no statements"
        ws = self.d("ws"); self.wj(os.path.join(ws, ".vex", "fosterstack-cache.openvex.json"), "{not json")
        _out, supp = self._supp([self._stmt("CVE-2099-20", ["pkg:deb/a@1"])], version=4)
        with self.assertRaises(R.ReviewedInputInvalid):
            R._merge_suppressions(ws, supp)
        self.assertEqual(open(os.path.join(ws, ".vex", "fosterstack-cache.openvex.json")).read(), "{not json")      # nothing was rewritten

    def test_corrupt_checkout_inventory_stops_before_the_vex_is_written(self):
        ws = self.d("ws"); self.wj(os.path.join(ws, ".auditor", "accepted-items.json"), "{bad")
        vp = os.path.join(ws, ".vex", "fosterstack-cache.openvex.json")
        _out, supp = self._supp([self._stmt("CVE-2099-20", ["pkg:deb/a@1"])], version=4)
        with self.assertRaises(R.ReviewedInputInvalid):
            R._merge_suppressions(ws, supp)
        self.assertFalse(os.path.exists(vp))                                # the VEX was not written ahead of the stop

    def test_corrupt_run_inventory_stops_the_delivery_merge(self):
        # the run's OWN accepted-items.json (beside its suppressions) that does not parse must not let the VEX ride without its inventory
        ws = self.d("ws")
        _out, supp = self._supp([self._stmt("CVE-2099-20", ["pkg:deb/a@1"])], version=4)
        self.wj(os.path.join(os.path.dirname(supp), ".auditor", "accepted-items.json"), "{bad")
        with self.assertRaises(R.ReviewedInputInvalid):
            R._merge_suppressions(ws, supp)
        self.assertFalse(os.path.exists(os.path.join(ws, ".vex")))      # and neither the VEX nor its folder was created ahead of the stop

    def test_read_reopened_is_strict(self):
        for bad in ({"reopened": [0, None, ""]}, {"reopened": [["CVE", 5, 6]]}, {"reopened": [["CVE", "prod", "purl"]]}, {"reopened": [[["x"], [], []]]}, {"reopened": "x"}, [1]):
            p = os.path.join(self.d("ro"), "reopened-expired.json"); self.wj(p, bad)
            with self.assertRaises(R.ReviewedInputInvalid):
                R._read_reopened(p)
        p = os.path.join(self.d("ro2"), "reopened-expired.json"); self.wj(p, {"reopened": [["CVE-1", ["prod"], ["pkg:deb/a@1"]]]})
        self.assertEqual(R._read_reopened(p), [["CVE-1", ["prod"], ["pkg:deb/a@1"]]])
        self.assertEqual(R._read_reopened(os.path.join(self.d("ro3"), "absent.json")), [])      # absent = none

    def test_a_published_vex_and_the_accepted_items_file_must_carry_their_list(self):
        # a present file of the right name must hold its key as a list of objects: {} and a null list are a stop, [] is a valid empty list (rc-5b fix 13)
        for name, key in (("fosterstack-cache.openvex.json", "statements"), ("accepted-items.json", "accepted_items"), ("f-CVE-2099-1.openvex.json", "statements")):
            for bad in ({}, {key: None}, {"other": []}, {key: {}}, {key: "x"}, {key: [None]}, {key: [3]}, {key: [{}, "x"]}):
                p = os.path.join(self.d("rq"), name); self.wj(p, bad)
                with self.assertRaises(R.ReviewedInputInvalid, msg=repr((name, bad))):
                    R._read_reviewed_json(p)
            for good in ({key: []}, {key: [{}]}, {key: [{"a": 1}], "other": 1}):
                p = os.path.join(self.d("rq2"), name); self.wj(p, good)
                self.assertEqual(R._read_reviewed_json(p), good)
        p = os.path.join(self.d("rq3"), "run-state.json"); self.wj(p, {})      # a file the reader has no rule for is read as before
        self.assertEqual(R._read_reviewed_json(p), {})

    def test_lstat_failure_other_than_absent_is_a_stop(self):
        import errno
        from unittest.mock import patch
        p = os.path.join(self.d("lst"), "x.json")
        with patch.object(R.os, "lstat", side_effect=PermissionError(errno.EACCES, "parent inaccessible")):
            with self.assertRaises(R.ReviewedInputInvalid):
                R._read_reviewed_json(p)
        with patch.object(R.os, "lstat", side_effect=OSError(errno.EIO, "I/O failure")):
            with self.assertRaises(R.ReviewedInputInvalid):
                R._read_reviewed_json(p)
        self.assertIsNone(R._read_reviewed_json(p))                         # really absent: the first run

    def test_legacy_item_resolved_by_unique_package(self):
        ws = self.d("ws"); st = self._stmt("CVE-2099-21", ["pkg:deb/debian/libfoo@1.0"])
        _out, supp = self._supp([st])
        self.wj(os.path.join(ws, ".auditor", "accepted-items.json"),
                {"accepted_items": [{"cve": "CVE-2099-21", "package": "libfoo", "threshold": "below", "expiry": "2026-10-30"}]})
        R._merge_suppressions(ws, supp)
        items = json.load(open(os.path.join(ws, ".auditor", "accepted-items.json")))["accepted_items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["vex_id"], st["@id"])                   # pointer reconciled to its scope

    def test_legacy_item_ambiguous_package_not_reconciled(self):
        ws = self.d("ws")
        s1 = self._stmt("CVE-2099-22", ["pkg:deb/debian/libfoo@1.0"])
        s2 = self._stmt("CVE-2099-22", ["pkg:deb/debian/libfoo@2.0"])
        _out, supp = self._supp([s1, s2])
        self.wj(os.path.join(ws, ".auditor", "accepted-items.json"),
                {"accepted_items": [{"cve": "CVE-2099-22", "package": "libfoo", "threshold": "below", "expiry": "2026-10-30"}]})
        R._merge_suppressions(ws, supp)
        items = json.load(open(os.path.join(ws, ".auditor", "accepted-items.json")))["accepted_items"]
        self.assertEqual(len(items), 1)                                   # kept at CVE level
        self.assertNotIn("vex_id", items[0])                              # but no scope to point at

    def test_panel_mode_merge_regenerates_no_scanner_ignore_files(self):
        ws = self.d("ws"); _out, supp = self._supp([self._stmt("CVE-2099-25", ["pkg:deb/a@1"])])
        R._merge_suppressions(ws, supp)
        merged = json.load(open(os.path.join(ws, ".vex", "fosterstack-cache.openvex.json")))
        self.assertEqual([s["vulnerability"]["name"] for s in merged["statements"]], ["CVE-2099-25"])
        self.assertFalse(os.path.exists(os.path.join(ws, ".snyk")))
        self.assertFalse(os.path.exists(os.path.join(ws, "osv-scanner.toml")))

    def test_consolidate_stops_on_an_unreadable_file(self):
        # rc-5b fix 13: a per-finding VEX this run wrote that does not parse means the run is broken: stop, do not produce "statements: []"
        out = self.d("out")
        good = R.vex.doc("CVE-2099-23", "affected", "t", action="x", subcomponents=["pkg:deb/x@1"])
        self.wj(os.path.join(out, "vex", "a-good.openvex.json"), good)
        self.wj(os.path.join(out, "vex", "b-bad.openvex.json"), "{")
        with self.assertRaises(R.ReviewedInputInvalid):
            R._consolidate(out, "2026-09-22T00:00:00Z")

    def test_consolidate_merges_readable_files(self):
        out = self.d("out")
        good = R.vex.doc("CVE-2099-23", "affected", "t", action="x", subcomponents=["pkg:deb/x@1"])
        self.wj(os.path.join(out, "vex", "a-good.openvex.json"), good)
        supp, n = R._consolidate(out, "2026-09-22T00:00:00Z")
        self.assertEqual(n, 1)
        doc = json.load(open(os.path.join(supp, "fosterstack-cache.openvex.json")))
        self.assertEqual(len(doc["statements"]), 1)
        self.assertEqual(sorted(os.listdir(supp)), ["fosterstack-cache.openvex.json"])         # the VEX is the only file there is


# ---------------------------------------------------------------- real-gh delivery (FakeRun)

class ArmAutomerge(Base):
    def test_arm_success_and_masked_failure(self):
        fr = FakeRun()
        with mock.patch.object(R.subprocess, "run", fr):
            self.assertTrue(R._arm_automerge("https://x/pull/3", "/ws"))
        self.assertEqual(fr.argvs(), [["gh", "pr", "ready", "https://x/pull/3"],
                                      ["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/3"]])
        self.assertEqual(fr.calls[0][1]["cwd"], "/ws")
        fr = FakeRun({("gh", "pr", "merge"): (1, "", "denied via claude-foo-1 token")})
        with mock.patch.object(R.subprocess, "run", fr):
            ok, out = self.quiet(R._arm_automerge, "u", "/ws")
        self.assertFalse(ok)
        self.assertIn("warning: could not arm auto-merge on u: denied via <model-id> token", out)


class SuppressionPR(Base):
    BR = "auditor/2026-09-22-abcdef123456"

    def setUp(self):
        super().setUp()
        self.ws = self.d("ws"); self.out = self.d("out"); self.supp = self.d("out", "suppressions")
        st = R.vex.doc("CVE-2099-30", "affected", "t", action="x", subcomponents=["pkg:deb/x@1"])
        self.wj(os.path.join(self.supp, "fosterstack-cache.openvex.json"), st)
        self.wj(os.path.join(self.out, ".auditor", "knowledge.md"), "# k\n")

    def real(self, fr, automerge=False, supp=None, **kw):
        os.environ.update(AUDITOR_ALLOW_REAL_GH="1", GITHUB_WORKSPACE=self.ws, GITHUB_REPOSITORY="o/r")
        os.environ.pop("AUDITOR_AUTOMERGE", None)
        if automerge:
            os.environ["AUDITOR_AUTOMERGE"] = "on"
        with mock.patch.object(R.subprocess, "run", fr):
            return self.quiet(R._deliver_suppression_pr, self.out, supp or self.supp, 1, "2026-09-22",
                              "abcdef1234567890", False, [], **kw)[0]

    def test_a_panel_delivery_stages_the_vex_only(self):
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.real(fr)
        status = [a for a in fr.argvs() if a[:2] == ["git", "status"]][0]
        paths = status[status.index("--") + 1:]
        self.assertIn(".vex/fosterstack-cache.openvex.json", paths)
        self.assertNotIn(".snyk", paths); self.assertNotIn("osv-scanner.toml", paths)

    def test_dry_run_automerge_proposes_merge(self):
        os.environ["AUDITOR_AUTOMERGE"] = "on"; would = []
        res, out = self.quiet(R._deliver_suppression_pr, self.out, self.supp, 1, "2026-09-22", "abcdef1234567890", True, would)
        self.assertEqual(res, (None, None))
        # ONE plan entry for the one PR (never a second line for the merge), no --draft, auto-merge noted
        self.assertEqual(len(would), 1)
        self.assertTrue(would[0]["cmd"].startswith("gh pr create --base main --head %s" % self.BR))
        self.assertEqual((would[0]["kind"], would[0]["note"]), ("suppression PR", "auto-merge"))
        self.assertIn("dry-run would open auto-merge PR", out)

    def test_git_failures_stop_delivery(self):
        # (changed: `git commit` and `git push` are never run any more; the commit is a signed one made through the API)
        for pre, label in ((("git", "fetch"), "git fetch"), (("git", "checkout"), "git checkout"),
                           (("git", "status"), "git status"), (("git", "rev-parse"), "git rev-parse")):
            fr = ApiRun({pre: (1, "", " %s broke \n" % label)})
            self.assertEqual(self.real(fr), (None, "%s: %s broke" % (label, label)), label)
            self.assertFalse(any(a[:3] == ["gh", "pr", "create"] for a in fr.argvs()), label)
            self.assertTrue(fr.no_unsigned(), label)
        fr = ApiRun({("git", "status"): (0, "", "")})                      # the run changed none of the files: never an empty commit
        self.assertEqual(self.real(fr), (None, "signed commit: nothing to commit (the run changed none of the suppression files)"))
        self.assertFalse(fr.stdins)

    def test_the_signed_commit_is_built_on_the_pinned_base_even_when_the_ref_moves(self):
        # a later `git rev-parse origin/main` would answer SHA: the tracking ref moved
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.assertEqual(self.real(fr, base_sha="b" * 40), ("https://x/pull/9", None))
        # the API commit's parent is the validated sha
        self.assertEqual(fr.stdins[0]["variables"]["input"]["expectedHeadOid"], "b" * 40)
        self.assertIn(["git", "checkout", "-B", self.BR, "b" * 40], fr.argvs())
        # no later lookup of the moving ref
        self.assertFalse(any(a[:2] == ["git", "rev-parse"] for a in fr.argvs()))

    def test_a_reviewed_input_that_stops_the_merge_after_the_checkout_still_ends_the_run(self):
        fr = ApiRun()
        with mock.patch.object(R, "_merge_suppressions", side_effect=R.ReviewedInputInvalid("damaged after the preflight")):
            # exit 3, not a "stage files" error to carry on from
            with self.assertRaises(R.ReviewedInputInvalid):
                self.real(fr, base_sha="b" * 40)

    def test_a_delivery_given_the_base_failure_returns_it_and_fetches_nothing_again(self):
        fr = ApiRun()
        self.assertEqual(self.real(fr, base_err="git fetch: offline"), (None, "git fetch: offline"))
        # not a second fetch, not a read, not a checkout
        self.assertEqual(fr.argvs(), [])

    def test_the_delivery_commit_is_made_through_the_api_never_git(self):   # main requires signed commits
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.assertEqual(self.real(fr), ("https://x/pull/9", None))
        self.assertTrue(fr.no_unsigned(), fr.argvs())                      # NO git commit, NO git push
        self.assertFalse(any(a[:2] == ["git", "add"] for a in fr.argvs()))
        self.assertEqual(len(fr.stdins), 1)
        inp = fr.stdins[0]["variables"]["input"]
        self.assertEqual(inp["branch"]["repositoryNameWithOwner"], "o/r")
        self.assertTrue(inp["branch"]["branchName"].startswith("auditor/tmp-"))   # the commit is made on a TEMPORARY branch; the live one moves after
        self.assertEqual(inp["expectedHeadOid"], SHA)                      # rebuilt on origin/main's tip
        self.assertEqual([x["path"] for x in inp["fileChanges"]["additions"]], [".auditor/knowledge.md", ".vex/fosterstack-cache.openvex.json"])
        self.assertEqual(inp["fileChanges"]["deletions"], [])
        a = fr.argvs()
        self.assertLess(a.index(["git", "fetch", "origin", "main"]), a.index(["gh", "api", "--method", "PATCH", "repos/o/r/git/refs/heads/" + self.BR, "-f", "sha=" + OID, "-F", "force=true"]))
        self.assertLess(a.index(["gh", "api", "graphql", "--input", "-"]), a.index(a[[i for i, x in enumerate(a) if x[:3] == ["gh", "pr", "create"]][0]]))
        # a deleted file is a deletion; a signed commit that cannot be made stops the delivery before any PR
        fr = ApiRun({("git", "status"): (0, " D gone/file.txt\0", "")}); self.real(fr)
        self.assertEqual(fr.stdins[0]["variables"]["input"]["fileChanges"], {"additions": [], "deletions": [{"path": "gone/file.txt"}]})
        fr = ApiRun(mutation=(1, "", "HTTP 403")); res = self.real(fr)
        self.assertEqual(res[0], None); self.assertIn("createCommitOnBranch", res[1]); self.assertIn("HTTP 403", res[1])
        fr = ApiRun(mutation=(0, json.dumps({"data": {"createCommitOnBranch": {"commit": {"oid": OID, "signature": {"isValid": False, "state": "UNSIGNED"}}}}}), ""))
        res = self.real(fr)
        self.assertIn("NOT validly signed", res[1]); self.assertFalse(any(x[:3] == ["gh", "pr", "create"] for x in fr.argvs()))
        os.environ.pop("GITHUB_REPOSITORY"); fr = ApiRun()
        with mock.patch.object(R.subprocess, "run", fr):
            res = R._deliver_suppression_pr(self.out, self.supp, 1, "2026-09-22", "abcdef1234567890", False, [])
        self.assertIn("GITHUB_REPOSITORY is not set", res[1])

    ARMED = {("gh", "pr", "view"): (0, "true\n", ""), ("gh", "pr", "list"): (0, "https://x/pull/7\n", "")}
    DIS = ["gh", "pr", "merge", "--disable-auto", "https://x/pull/7"]

    def test_an_armed_suppression_pr_is_disarmed_before_its_branch_is_replaced_and_stays_disarmed_on_failure(self):
        fr = ApiRun(self.ARMED)
        self.assertEqual(self.real(fr, automerge=True), ("https://x/pull/7", None))
        a = fr.argvs()
        first_write = next(i for i, x in enumerate(a) if x[:2] == ["gh", "api"] and x[2] in ("graphql", "--method"))
        self.assertLess(a.index(self.DIS), first_write)                           # disarmed BEFORE any ref write or commit
        self.assertEqual(a[-1], ["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/7"])   # re-armed afterwards
        self.assertIn(["gh", "pr", "view", "https://x/pull/7", "--json", "headRefOid", "--jq", ".headRefOid"], a)
        fr = ApiRun(self.ARMED, mutation=(1, "", "HTTP 403"))
        res = self.real(fr, automerge=True)
        self.assertIsNone(res[0]); self.assertIn("createCommitOnBranch", res[1])
        self.assertIn(self.DIS, fr.argvs())                                        # a failure leaves it disarmed ...
        self.assertFalse(any(x[:3] == ["gh", "pr", "merge"] and "--auto" in x for x in fr.argvs()))   # ... never re-armed
        self.assertEqual([w for w in fr.ref_writes() if w[1] == "repos/o/r/git/refs/heads/" + self.BR], [])
        fr = ApiRun({**self.ARMED, ("gh", "pr", "merge", "--disable-auto"): (1, "", "HTTP 500")})
        res = self.real(fr, automerge=True)
        self.assertIn("disable auto-merge", res[1]); self.assertEqual(fr.ref_writes(), [])
        fr = ApiRun({**self.ARMED, ("gh", "pr", "view"): (1, "", "HTTP 500")})
        res = self.real(fr, automerge=True)
        self.assertIsNotNone(res[1]); self.assertEqual(fr.ref_writes(), [])
        fr = ApiRun(self.ARMED, pr_head="e" * 40)                                  # another run replaced the head: never armed
        res = self.real(fr, automerge=True)
        self.assertIsNone(res[0]); self.assertIn("not arming", res[1])
        self.assertFalse(any(x[:3] == ["gh", "pr", "merge"] and "--auto" in x for x in fr.argvs()))
        fr = ApiRun({("gh", "pr", "view"): (0, "false\n", ""), ("gh", "pr", "list"): (0, "https://x/pull/7\n", "")})
        self.assertEqual(self.real(fr), ("https://x/pull/7", None))
        self.assertNotIn(self.DIS, fr.argvs())                                     # not armed: nothing to disarm
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})      # no existing PR: no `pr view`
        self.real(fr); self.assertFalse(any(x[:3] == ["gh", "pr", "view"] for x in fr.argvs()))

    def test_a_temporary_ref_that_cannot_be_deleted_is_a_warning_not_a_failure(self):
        fr = ApiRun(delete=(1, "", "HTTP 500"))
        os.environ["GITHUB_REPOSITORY"] = "o/r"
        with mock.patch.object(R.subprocess, "run", fr):
            res, out = self.quiet(R._signed_delivery, self.ws, self.BR, SHA, "title", ["gone.txt"])
        self.assertEqual(res[0], OID); self.assertIsNone(res[1])
        self.assertIn("warning: temporary branch auditor/tmp-", out); self.assertIn("could not be deleted", out)

    def test_a_pr_discovery_failure_aborts_before_any_write(self):
        for rules in ({("gh", "pr", "list"): (1, "", "HTTP 500")}, {("gh", "pr", "list"): (1, "", "")}):
            fr = ApiRun(rules)
            res = self.real(fr, automerge=True)
            self.assertIsNone(res[0]); self.assertIn("gh pr list", res[1])
            self.assertEqual(fr.ref_writes(), []); self.assertTrue(fr.no_unsigned())
            self.assertFalse(any(a[:3] in (["gh", "pr", "merge"], ["gh", "pr", "create"], ["gh", "pr", "view"]) for a in fr.argvs()))

    def test_every_suppression_path_arms_only_the_verified_head(self):
        view = ["gh", "pr", "view", "https://x/pull/9", "--json", "headRefOid", "--jq", ".headRefOid"]
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.assertEqual(self.real(fr, automerge=True), ("https://x/pull/9", None))   # a NEW PR is checked too
        self.assertIn(view, fr.argvs()); self.assertEqual(fr.argvs()[-1], ["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/9"])
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")}, pr_head="e" * 40)   # replaced between the commit and the arm
        res = self.real(fr, automerge=True)
        self.assertIsNone(res[0]); self.assertIn("head changed since it was verified", res[1])
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] and "--auto" in a for a in fr.argvs()))
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")}, pr_head=None)       # unreadable
        self.assertIsNone(self.real(fr, automerge=True)[0])
        fr = ApiRun({("gh", "pr", "list"): [(0, "", ""), (0, "https://x/pull/8", "")], ("gh", "pr", "create"): (1, "", "already exists")}, pr_head="e" * 40)
        self.assertIsNone(self.real(fr, automerge=True)[0])                                       # the race-found PR is bound too
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")}, pr_head="e" * 40)
        self.assertEqual(self.real(fr), ("https://x/pull/9", None))                              # draft (no auto-merge): nothing to arm, nothing to check

    def test_stage_failure(self):
        fr = ApiRun()
        url, err = self.real(fr, supp=self.d("empty-supp"))               # no openvex file to merge
        self.assertIsNone(url); self.assertTrue(err.startswith("stage files: "), err)
        self.assertEqual(fr.argvs(), [["git", "fetch", "origin", "main"], ["git", "rev-parse", "origin/main"], ["git", "show", SHA + ":.vex/fosterstack-cache.openvex.json"],
                                      ["git", "show", SHA + ":.auditor/accepted-items.json"], ["git", "checkout", "-B", self.BR, SHA]])

    def test_existing_pr_reused_and_armed(self):
        fr = ApiRun({("gh", "pr", "list"): (0, "https://x/pull/7\n", "")})
        self.assertEqual(self.real(fr, automerge=True), ("https://x/pull/7", None))
        self.assertIn(["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/7"], fr.argvs())
        self.assertFalse(any(a[:3] == ["gh", "pr", "create"] for a in fr.argvs()))
        # staged files rode the checkout
        self.assertTrue(os.path.exists(os.path.join(self.ws, ".auditor", "knowledge.md")))
        self.assertTrue(os.path.exists(os.path.join(self.ws, ".vex", "fosterstack-cache.openvex.json")))
        # (changed: there is no `git add` any more; the files ride the one signed API commit)
        self.assertIn(".auditor/knowledge.md", [x["path"] for x in fr.stdins[0]["variables"]["input"]["fileChanges"]["additions"]])
        fr = ApiRun({("gh", "pr", "list"): (0, "https://x/pull/7\n", "")})
        self.assertEqual(self.real(fr), ("https://x/pull/7", None))
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] for a in fr.argvs()))

    def test_create_race_already_exists(self):
        fr = ApiRun({("gh", "pr", "list"): [(0, "", ""), (0, "https://x/pull/8", "")],
                      ("gh", "pr", "create"): (1, "", "a pull request already EXISTS for head")})
        self.assertEqual(self.real(fr, automerge=True), ("https://x/pull/8", None))
        self.assertIn(["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/8"], fr.argvs())
        # race but the existing PR cannot be found -> a real failure
        fr = ApiRun({("gh", "pr", "create"): (1, "", "already exists")})
        self.assertEqual(self.real(fr), (None, "gh pr create: already exists"))
        fr = ApiRun({("gh", "pr", "create"): (1, "", "HTTP 403")})
        self.assertEqual(self.real(fr), (None, "gh pr create: HTTP 403"))

    LIST = ("gh", "api", "repos/{owner}/{repo}/pulls?state=open&per_page=100")
    OPEN = ("5 auditor/2026-09-20-aaaaaaaaaaaa\n6 auditor/2026-09-22-abcdef123456\n7 auditor/panel\n8 auditor/bump-example.com-m-1.1.0\n"
            "9 feature/x\n10 auditor/2026-09-21-bbbbbbbbbbbb\n12 auditor/2026-09-23-cccccccccccc\n")

    def test_superseded_daily_suppression_prs_are_closed(self):          # advisor 0187: stale PRs must not pile up behind main
        for how, rules in (("created", {("gh", "pr", "create"): (0, "https://x/pull/11\n", "")}),
                           ("existing", {("gh", "pr", "list"): (0, "https://x/pull/6\n", "")})):
            fr = ApiRun({**rules, self.LIST: (0, self.OPEN, "")})
            self.assertIsNotNone(self.real(fr)[0], how)
            closed = sorted(a[3] for a in fr.argvs() if a[:3] == ["gh", "pr", "close"])
            self.assertEqual(closed, ["10", "5"], how)              # only OLDER daily branches: not today's, not a NEWER one (12), not panel/bump/feature
            first = [a for a in fr.argvs() if a[:3] == ["gh", "pr", "close"]][0]
            self.assertIn("--comment", first)
            self.assertIn("supersed", first[first.index("--comment") + 1].lower())
            self.assertNotIn("--delete-branch", first)                      # the branch stays: nothing here deletes refs

    def test_only_the_apps_own_non_draft_same_repo_prs_are_candidates(self):    # reviewer r1 blocker 2
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/11\n", ""), self.LIST: (0, self.OPEN, "")})
        self.real(fr)
        lst = [a for a in fr.argvs() if a[:3] == list(self.LIST)][0]
        self.assertIn("--paginate", lst)
        jq = lst[lst.index("--jq") + 1]
        for needle in ('.head.repo.fork == false', '.draft == false', '.user.type == "Bot"', '.base.ref == "main"'):
            self.assertIn(needle, jq)                                          # a fork's, a human's and an owner-held draft are never closed

    def test_todays_replacement_must_be_a_same_repo_pr_into_main(self):                            # review r6 B2
        fr = ApiRun({("gh", "pr", "list"): (0, "https://x/pull/7\n", ""), self.LIST: (0, self.OPEN, "")})
        self.real(fr, automerge=True)
        lst = [a for a in fr.argvs() if a[:3] == ["gh", "pr", "list"]][0]
        jq = lst[lst.index("--jq") + 1]
        self.assertIn("isCrossRepository == false", jq); self.assertIn('baseRefName == "main"', jq)

    def test_nothing_is_closed_when_todays_pr_was_not_delivered(self):
        fr = ApiRun({("gh", "pr", "create"): (1, "", "HTTP 403"), self.LIST: (0, self.OPEN, "")})
        self.assertIsNone(self.real(fr)[0])
        self.assertFalse(any(a[:3] == ["gh", "pr", "close"] for a in fr.argvs()))

    def test_a_failing_cleanup_never_fails_the_delivery(self):
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/11\n", ""), self.LIST: (1, "", "HTTP 500"),
                      ("gh", "pr", "close"): (1, "", "HTTP 500")})
        self.assertEqual(self.real(fr), ("https://x/pull/11", None))
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/11\n", ""), self.LIST: (0, self.OPEN, ""), ("gh", "pr", "close"): (1, "", "HTTP 500")})
        self.assertEqual(self.real(fr), ("https://x/pull/11", None))

    def test_a_cleanup_that_raises_never_fails_the_delivery(self):
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/11\n", ""), self.LIST: OSError("gh vanished")})
        res = self.real(fr)
        self.assertEqual(res, ("https://x/pull/11", None))

    def test_create_draft_vs_automerge(self):
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.assertEqual(self.real(fr, automerge=True), ("https://x/pull/9", None))
        self.assert_branch_off_main(fr)
        create = [a for a in fr.argvs() if a[:3] == ["gh", "pr", "create"]][0]
        self.assertNotIn("--draft", create)
        self.assertEqual(fr.argvs()[-1], ["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/9"])
        fr = ApiRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.assertEqual(self.real(fr), ("https://x/pull/9", None))
        create = [a for a in fr.argvs() if a[:3] == ["gh", "pr", "create"]][0]
        self.assertEqual(create[3], "--draft")
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] for a in fr.argvs()))


class FixPR(Base):
    ROW = {"id": "CVE-2099-40", "fix_bump": {"cve": "CVE-2099-40", "module": "example.com/m", "from": "v1.0.0", "to": "v1.1.0"}}
    BR = "auditor/bump-example.com-m-1.1.0"       # keyed by TARGET, never by CVE or commit (LR-32)

    def real(self, rules, automerge=False, api=None, repo="o/r", slug="app", row=None):
        os.environ.update(AUDITOR_ALLOW_REAL_GH="1", GITHUB_WORKSPACE=self.d("ws"), GITHUB_REPOSITORY=repo)
        os.environ.pop("AUDITOR_APP_SLUG", None)
        if slug:
            os.environ["AUDITOR_APP_SLUG"] = slug
        os.environ.pop("AUDITOR_AUTOMERGE", None)
        if automerge:
            os.environ["AUDITOR_AUTOMERGE"] = "1"
        fr = ApiRun(rules, **(api or {}))
        if not os.path.exists(os.path.join(self.d("ws"), "go.mod")):      # what `go get` + `go mod tidy` leave in the checkout
            open(os.path.join(self.d("ws"), "go.mod"), "w").write("module m\n")
        with mock.patch.object(R.subprocess, "run", fr):
            res = self.quiet(R._deliver_fix_pr, row or self.ROW, "2026-09-22", "abcdef1234567890", False, [])[0]
        return res, fr

    def test_dry_and_shim_automerge(self):
        os.environ["AUDITOR_AUTOMERGE"] = "yes"; would = []
        res, _ = self.quiet(R._deliver_fix_pr, self.ROW, "2026-09-22", "abcdef1234567890", True, would)
        self.assertEqual(res, (None, None, "would"))
        self.assertEqual(len(would), 1)                                   # one entry per PR
        self.assertEqual((would[0]["kind"], would[0]["note"], would[0]["key"]), ("bump PR", "auto-merge", self.BR))
        self.assertNotIn("--draft", would[0]["cmd"])
        log = os.path.join(self.tmp, "shim.log"); os.environ["AUDITOR_GIT_SHIM_LOG"] = log
        res = R._deliver_fix_pr(self.ROW, "2026-09-22", "abcdef1234567890", False, [])
        self.assertEqual(res, ("https://github.com/OWNER/REPO/pull/SHIM-bump-example.com-m-1.1.0", None, "delivered"))
        lines = open(log).read().splitlines()
        self.assertIn("gh pr merge --auto --squash %s" % self.BR, lines)
        self.assertIn("go get example.com/m@v1.1.0", lines)

    def test_a_major_is_never_armed_even_when_auto_merge_is_on(self):
        os.environ["AUDITOR_AUTOMERGE"] = "yes"; would = []
        major = {**self.ROW, "fix_bump": {**self.ROW["fix_bump"], "from": "v1.9.0", "to": "v2.0.0"}}
        res, _ = self.quiet(R._deliver_fix_pr, major, "2026-09-22", "abcdef1234567890", True, would)
        self.assertEqual((would[0]["note"], "--draft" in would[0]["cmd"]), ("draft", True))
        log = os.path.join(self.tmp, "major.log"); os.environ["AUDITOR_GIT_SHIM_LOG"] = log
        R._deliver_fix_pr(major, "2026-09-22", "abcdef1234567890", False, [])
        lines = open(log).read().splitlines()
        self.assertFalse(any("pr merge --auto" in l for l in lines))
        self.assertTrue(any(l.startswith("gh pr create --draft") for l in lines))

    MAJOR = {**ROW, "fix_bump": {**ROW["fix_bump"], "from": "v1.9.0", "to": "v2.0.0"}}

    def test_a_reused_major_bump_pr_is_demoted_to_a_draft_with_auto_merge_off_before_anything_else(self):
        u = "https://x/pull/7"
        state = lambda armed, draft: {**self.REUSE, ("gh", "pr", "view", u, "--json", "autoMergeRequest"): (0,
            armed + "\n", ""),
                                      ("gh", "pr", "view", u, "--json", "isDraft"): (0, draft + "\n", "")}
        look = {"lookup": head_lookup(True, SHA)}
        # armed and ready: both undone
        res, fr = self.real(state("true", "false"), automerge=True, row=self.MAJOR, api=look)
        self.assertEqual(res, (u, None, "delivered")); argv = fr.argvs()
        self.assertIn(["gh", "pr", "merge", "--disable-auto", u], argv)
        self.assertIn(["gh", "pr", "ready", "--undo", u], argv)
        self.assertLess(argv.index(["gh", "pr", "ready", "--undo", u]), [i for i,
            a in enumerate(argv) if a[:3] == ["gh", "pr", "edit"]][0])
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] and "--auto" in a for a in argv))
        # already a draft, unarmed: left alone
        res, fr = self.real(state("false", "true"), automerge=True, row=self.MAJOR, api=look)
        self.assertEqual(res, (u, None, "delivered"))
        self.assertFalse(any(a[:3] in (["gh", "pr", "ready"], ["gh", "pr", "merge"]) for a in fr.argvs()))
        # not a major: chain's rule, no demotion
        res, fr = self.real(state("true", "false"), automerge=True, row=self.ROW, api=look)
        self.assertFalse(any(a[:3] == ["gh", "pr", "ready"] for a in fr.argvs()))

    def test_a_major_bump_pr_is_demoted_before_its_branch_is_replaced_even_when_the_replacement_fails(self):
        u = "https://x/pull/7"
        armed = {**self.CHG, ("gh", "pr", "list"): (0, u + "\n", ""), ("gh", "pr", "view", u, "--json",
            "autoMergeRequest"): (0, "true\n", ""),
                 ("gh", "pr", "view", u, "--json", "isDraft"): (0, "false\n", "")}
        res, fr = self.real(armed, automerge=True, row=self.MAJOR, api={"mutation": (1, "", "HTTP 403")})
        self.assertEqual(res[2], "error"); argv = fr.argvs()
        self.assertIn(["gh", "pr", "merge", "--disable-auto", u], argv)
        self.assertIn(["gh", "pr", "ready", "--undo", u], argv)
        self.assertLess(argv.index(["gh", "pr", "ready", "--undo", u]), argv.index(["gh", "api", "graphql", "--input",
            "-"]))
        # not a major: only disarmed, as before
        res, fr = self.real(armed, automerge=True, api={"mutation": (1, "", "HTTP 403")})
        self.assertFalse(any(a[:3] == ["gh", "pr", "ready"] for a in fr.argvs()))
        # no PR yet: nothing to demote
        res, fr = self.real({**self.CHG}, automerge=True, row=self.MAJOR)
        self.assertFalse(any(a[:3] == ["gh", "pr", "ready"] for a in fr.argvs()))

    def test_a_reused_major_bump_pr_that_cannot_be_demoted_fails_the_delivery_and_is_not_edited(self):
        u = "https://x/pull/7"; look = {"lookup": head_lookup(True, SHA)}
        base = {**self.REUSE, ("gh", "pr", "view", u, "--json", "autoMergeRequest"): (0, "false\n", ""),
                ("gh", "pr", "view", u, "--json", "isDraft"): (0, "false\n", "")}
        for rules, word in (({**base, ("gh", "pr", "ready", "--undo"): (1, "", "HTTP 500")}, "draft"),
                            ({**base, ("gh", "pr", "view", u, "--json", "isDraft"): (1, "", "HTTP 500")}, "isDraft"),
                            ({**base, ("gh", "pr", "view", u, "--json", "autoMergeRequest"): (0, "true\n", ""),
                              ("gh", "pr", "merge", "--disable-auto"): (1, "", "HTTP 500")}, "disable auto-merge")):
            res, fr = self.real(rules, automerge=True, row=self.MAJOR, api=look)
            self.assertEqual((res[0], res[2]), (None, "error")); self.assertIn(word, res[1])
            self.assertFalse(any(a[:3] == ["gh", "pr", "edit"] for a in fr.argvs()))

    def test_git_failures(self):
        for pre, label in ((("git", "fetch"), "git fetch"), (("git", "checkout"), "git checkout")):
            res, fr = self.real({pre: (1, "", "nope")})
            self.assertEqual(res, (None, "%s: nope" % label, "error"))
            # (after the Dependabot lookup)
            self.assertEqual([a for a in fr.argvs() if a[0] == "git"][0], ["git", "reset", "--hard"])
        # (changed: `git commit` / `git push` are never run; the commit is made through the API and its failures are signed-commit failures)
        res, fr = self.real({("git", "diff"): (1, "", ""), ("git", "rev-parse"): (1, "", "bad ref")})
        self.assertEqual(res, (None, "git rev-parse: bad ref", "error"))
        res, fr = self.real({("git", "diff"): (1, "", "")}, api={"mutation": (1, "", "HTTP 422 empty")})
        self.assertEqual(res[2], "error"); self.assertIn("signed commit: createCommitOnBranch", res[1]); self.assertIn("HTTP 422 empty", res[1])
        self.assertTrue(fr.no_unsigned())
        res, fr = self.real({("git", "diff"): (1, "", "")}, api={"post": (1, "", "HTTP 500")})
        self.assertEqual(res[2], "error"); self.assertIn("creating temporary branch", res[1])
        res, fr = self.real({("git", "diff"): (1, "", "")}, repo="")
        self.assertEqual(res[2], "error"); self.assertIn("GITHUB_REPOSITORY is not set", res[1])

    def test_the_bump_commit_is_made_through_the_api_never_git(self):
                                                                                   # (no go.sum in the checkout: a module with no dependencies)
        res, fr = self.real({("git", "diff"): (1, "", ""), ("gh", "pr", "create"): (0, "https://x/pull/3\n", "")})
        self.assertEqual(res, ("https://x/pull/3", None, "delivered"))
        self.assertTrue(fr.no_unsigned(), fr.argvs())
        inp = fr.stdins[0]["variables"]["input"]
        self.assertTrue(inp["branch"]["branchName"].startswith("auditor/tmp-"))
        self.assertEqual(inp["expectedHeadOid"], SHA)
        self.assertEqual(inp["fileChanges"], {"additions": [{"path": "go.mod", "contents": "bW9kdWxlIG0K"}], "deletions": []})
        self.assertIn("bump example.com/m", inp["message"]["headline"])
        self.assertIn(["gh", "api", "repos/o/r/git/ref/heads/" + self.BR], fr.argvs())

    ARMED = {("gh", "pr", "view"): (0, "true\n", ""), ("gh", "pr", "list"): (0, "https://x/pull/7\n", "")}
    CHG = {("git", "diff"): (1, "", "")}

    def assert_disarmed_before_any_write(self, fr, label):
        a = fr.argvs()
        dis = ["gh", "pr", "merge", "--disable-auto", "https://x/pull/7"]
        self.assertIn(dis, a, label)
        first_write = next(i for i, x in enumerate(a) if x[:2] == ["gh", "api"] and (x[2] in ("graphql", "--method")))
        self.assertLess(a.index(dis), first_write, label)                   # disarmed BEFORE any ref write or commit

    def test_an_armed_bump_pr_is_disarmed_before_its_branch_is_replaced_and_stays_disarmed_on_failure(self):
        res, fr = self.real({**self.CHG, **self.ARMED}, automerge=True)
        self.assertEqual(res, ("https://x/pull/7", None, "delivered"))
        self.assert_disarmed_before_any_write(fr, "bump")
        self.assertEqual(fr.argvs()[-1], ["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/7"])   # re-armed, bound to the head we wrote
        self.assertIn(["gh", "pr", "view", "https://x/pull/7", "--json", "headRefOid", "--jq", ".headRefOid"], fr.argvs())
        res, fr = self.real({**self.CHG, **self.ARMED}, automerge=True, api={"mutation": (1, "", "HTTP 403")})
        self.assertEqual(res[2], "error"); self.assert_disarmed_before_any_write(fr, "failed")
        self.assertFalse(any(a[:4] == ["gh", "pr", "merge", "--auto"][:4] or a[:3] == ["gh", "pr", "merge"] and "--auto" in a for a in fr.argvs()))
        self.assertEqual([w for w in fr.ref_writes() if w[1] == "repos/o/r/git/refs/heads/" + self.BR], [])    # the live branch was never moved
        # a disarm that fails stops the delivery before anything is written
        res, fr = self.real({**self.CHG, **self.ARMED, ("gh", "pr", "merge", "--disable-auto"): (1, "", "HTTP 500")}, automerge=True)
        self.assertEqual(res[2], "error"); self.assertIn("disable auto-merge", res[1]); self.assertEqual(fr.ref_writes(), [])
        res, fr = self.real({**self.CHG, **self.ARMED, ("gh", "pr", "view"): (1, "", "HTTP 500")}, automerge=True)
        self.assertEqual(res[2], "error"); self.assertEqual(fr.ref_writes(), [])
        # an unarmed PR is not disarmed; a head that is not the one written is not armed
        res, fr = self.real({**self.CHG, ("gh", "pr", "view"): (0, "false\n", ""), ("gh", "pr", "list"): (0, "https://x/pull/7\n", "")}, automerge=True)
        self.assertEqual(res[0], "https://x/pull/7"); self.assertFalse(any(a[:4] == ["gh", "pr", "merge", "--disable-auto"][:4] and "--disable-auto" in a for a in fr.argvs()))
        res, fr = self.real({**self.CHG, **self.ARMED}, automerge=True, api={"pr_head": "e" * 40})
        self.assertEqual(res[2], "error"); self.assertIn("not arming", res[1])
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] and "--auto" in a for a in fr.argvs()))

    REUSE = {("git", "diff", "--cached"): (1, "", ""), ("git", "diff", "--quiet"): (0, "", ""), ("gh", "pr", "list"): (0, "https://x/pull/7\n", "")}

    def test_a_bump_branch_is_reused_only_when_the_app_made_its_commit(self):
        for kw in (dict(api={"lookup": head_lookup(True, SHA, author="someone")}), dict(api={"lookup": head_lookup(True,
            SHA)}, slug=None)):
            res, fr = self.real(self.REUSE, **kw)
            # rebuilt through the API, not left as it was
            self.assertNotEqual(fr.ref_writes(), [])

    def test_an_existing_bump_branch_is_reused_only_for_one_reviewed_bump_commit_on_main_with_the_same_bytes(self):
        # one verified commit on the CURRENT main, changing only go.mod, with the same bytes: reused, no write at all
        res, fr = self.real(self.REUSE, api={"lookup": head_lookup(True, SHA)})
        self.assertEqual(res, ("https://x/pull/7", None, "delivered")); self.assertEqual(fr.ref_writes(), [])
        self.assertIn(["gh", "api", "repos/o/r/commits/" + OLDHEAD], fr.argvs())
        # everything else is rebuilt through the API (the PR is then updated); never reused
        for label, api in (("unsigned", {"lookup": head_lookup(False, SHA)}), ("old main", {"lookup": head_lookup(True, "9" * 40)}),
                           ("two parents (a verified merge commit)", {"lookup": head_lookup(True, parents=[SHA, "9" * 40])}),
                           ("parent is not main", {"lookup": head_lookup(True, parents=["9" * 40])}),
                           ("an extra changed file", {"lookup": head_lookup(True, SHA, files=[("go.mod", "modified"), ("README.md", "modified")])}),
                           ("a rename", {"lookup": head_lookup(True, SHA, files=[("go.mod", "renamed", {"previous_filename": "a"})])}),
                           ("different bytes", {"contents": {"go.mod": b"module other\n"}}),
                           ("lookup failure", {"lookup": (1, "", "HTTP 500")}), ("absent", {"live": None})):
            res, fr = self.real(self.REUSE, api=api)
            self.assertEqual(res, ("https://x/pull/7", None, "delivered"), label)
            self.assertEqual([w[0] for w in fr.ref_writes()], ["POST", "COMMIT", "PATCH" if label != "absent" else "POST", "DELETE"], label)
            self.assertTrue(fr.no_unsigned(), label)
        # never delivered on an unverified head: the rebuild itself failing is an error, and the live branch was not touched
        for api in ({"lookup": head_lookup(False, SHA), "mutation": (1, "", "HTTP 403")}, {"lookup": (1, "", "HTTP 500"), "post": (1, "", "HTTP 403")}):
            res, fr = self.real(self.REUSE, api=api)
            self.assertEqual(res[0], None); self.assertEqual(res[2], "error")
            self.assertEqual([w for w in fr.ref_writes() if w[1] == "repos/o/r/git/refs/heads/" + self.BR], [])
        # an unchanged branch with no repository to verify against is an error, never "delivered"
        res, fr = self.real(self.REUSE, repo="")
        self.assertEqual(res[2], "error")

    def test_a_pr_discovery_failure_aborts_before_any_write(self):                     # a failed lookup is not "no PR"
        for rules in ({("gh", "pr", "list"): (1, "", "HTTP 500")}, {("gh", "pr", "list"): (1, "", "")}):
            res, fr = self.real({**self.CHG, **rules}, automerge=True)
            self.assertEqual(res[0], None); self.assertEqual(res[2], "error"); self.assertIn("gh pr list", res[1])
            self.assertEqual(fr.ref_writes(), []); self.assertTrue(fr.no_unsigned())
            self.assertFalse(any(a[:3] in (["gh", "pr", "merge"], ["gh", "pr", "create"], ["gh", "pr", "view"]) for a in fr.argvs()))
        res, fr = self.real({**self.REUSE, ("gh", "pr", "list"): (1, "", "HTTP 500")})   # also when the branch would be reused
        self.assertEqual(res[2], "error"); self.assertEqual(fr.ref_writes(), [])

    def test_every_bump_path_arms_only_the_verified_head(self):
        new = {**self.CHG, ("gh", "pr", "create"): (0, "https://x/pull/9\n", "")}
        res, fr = self.real(new, automerge=True)                                       # a new PR: head == the commit the helper made
        self.assertEqual(res, ("https://x/pull/9", None, "delivered"))
        self.assertEqual(fr.argvs()[-1], ["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/9"])
        self.assertLess(fr.index(["gh", "pr", "view", "https://x/pull/9", "--json", "headRefOid", "--jq", ".headRefOid"]), len(fr.argvs()) - 1)
        res, fr = self.real(new, automerge=True, api={"pr_head": "e" * 40})            # replaced between the commit and the arm
        self.assertEqual(res[0], None); self.assertEqual(res[2], "error"); self.assertIn("head changed since it was verified", res[1])
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] and "--auto" in a for a in fr.argvs()))
        res, fr = self.real(self.REUSE, automerge=True, api={"pr_head": OLDHEAD})      # a REUSED branch: bound to the head that was verified
        self.assertEqual(res, ("https://x/pull/7", None, "delivered")); self.assertEqual(fr.ref_writes(), [])
        self.assertEqual(fr.argvs()[-1], ["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/7"])
        res, fr = self.real(self.REUSE, automerge=True, api={"pr_head": "e" * 40})      # its head changed after the verification
        self.assertEqual(res[2], "error"); self.assertIn("head changed since it was verified", res[1])
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] and "--auto" in a for a in fr.argvs()))
        res, fr = self.real({**self.CHG, ("gh", "pr", "list"): [(0, "", ""), (0, "https://x/pull/8", "")], ("gh", "pr", "create"): (1, "", "already exists")},
                            automerge=True, api={"pr_head": "e" * 40})                 # the race-found PR is bound too
        self.assertEqual(res[2], "error")
        res, fr = self.real(new, automerge=True, api={"pr_head": None})                # a head that cannot be read is not armed either
        self.assertEqual(res[2], "error")

    def test_a_staging_failure_is_an_error_and_a_missing_go_sum_is_not_staged(self):
        res, fr = self.real({("git", "add"): (1, "", "fatal: pathspec 'go.mod' did not match")})
        self.assertEqual(res, (None, "git add: fatal: pathspec 'go.mod' did not match", "error"))
        self.assertEqual(fr.ref_writes(), [])
        res, fr = self.real({**self.CHG, ("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.assertIn(["git", "add", "go.mod"], fr.argvs())                           # no go.sum in the checkout: only what exists is staged
        os.remove(os.path.join(self.d("ws"), "go.mod"))
        os.environ.update(AUDITOR_ALLOW_REAL_GH="1", GITHUB_WORKSPACE=self.d("ws"), GITHUB_REPOSITORY="o/r")
        fr = ApiRun()
        with mock.patch.object(R.subprocess, "run", fr):
            res = self.quiet(R._deliver_fix_pr, self.ROW, "2026-09-22", "abcdef1234567890", False, [])[0]
        self.assertEqual(res[2], "error"); self.assertIn("go.mod", res[1])            # no go.mod at all: nothing to stage, never "unresolvable"

    def test_open_dependabot_prs_and_the_title_match(self):
        os.environ.update(AUDITOR_ALLOW_REAL_GH="1", GITHUB_WORKSPACE=self.d("ws"))
        os.environ.pop("AUDITOR_GIT_SHIM_LOG", None)
        prs = [{"number": 5, "title": "Bump example.com/m from 1.0.0 to 1.1.0", "url": "https://x/pull/5"},
            {"number": 6, "title": "build(deps): bump other.org/z from 1 to 2", "url": "u"}]
        fr = FakeRun({("gh", "pr", "list"): (0, json.dumps(prs), "")})
        with mock.patch.object(R.subprocess, "run", fr):
            got, err = R._open_dependabot_prs(self.d("ws"))
        self.assertEqual((got, err), (prs, None))
        self.assertEqual(R._dependabot_match(got, "example.com/m", "1.1.0"), (5, "https://x/pull/5"))
        self.assertEqual(R._dependabot_match(got, "example.com/m", "1.1.1"), None)                  # another version
        # a module that is only a prefix
        self.assertEqual(R._dependabot_match(got, "example.com", "1.1.0"), None)
        # the conventional-commit prefix still matches
        self.assertEqual(R._dependabot_match(got, "other.org/z", "2"), (6, "u"))
        self.assertEqual(R._dependabot_match(None, "m", "1"), None)
        other_dir = [{"number": 8, "title": "Bump example.com/m from 1.0.0 to 1.1.0 in /tools/govulncheck",
            "url": "u8"}]
        # another directory's go.mod is not ours
        self.assertIsNone(R._dependabot_match(other_dir, "example.com/m", "1.1.0"))
        for rules in ({("gh", "pr", "list"): (1, "", "HTTP 500")}, {("gh", "pr", "list"): (0, "not json", "")}):
            with mock.patch.object(R.subprocess, "run", FakeRun(rules)):
                got, err = R._open_dependabot_prs(self.d("ws"))
            self.assertIsNone(got); self.assertIn("gh pr list", err)

    def test_a_real_run_defers_to_an_open_dependabot_pr_and_survives_a_failed_lookup(self):
        dep = {("gh", "pr", "list", "--state", "open", "--author", "app/dependabot"): (0, json.dumps([{"number": 5,
            "title": "Bump example.com/m from 1.0.0 to 1.1.0", "url": "https://x/pull/5"}]), "")}
        res, fr = self.real({**self.CHG, **dep})
        self.assertEqual(res, ("https://x/pull/5", None, "deferred"))
        # nothing was built or opened
        self.assertFalse(any(a[:2] in (["git", "checkout"], ["go", "get"]) for a in fr.argvs()))
        # a deferral touches no pull request: the auditor's own draft is never closed, edited, readied or armed
        changes = ("close", "edit", "ready", "merge", "create")
        self.assertFalse(any(a[:2] == ["gh", "pr"] and a[2] in changes for a in fr.argvs()))
        self.assertFalse(any(a[:3] == ["gh", "issue", "create"] for a in fr.argvs()))     # ... and opens no issue
        res, fr = self.real({**self.CHG, ("gh", "pr", "list", "--state", "open", "--author", "app/dependabot"): (1, "",
            "HTTP 500"), ("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.assertEqual(res, ("https://x/pull/9", None, "delivered-unchecked"))

    def test_only_a_changed_major_is_held_so_a_v0_minor_is_not(self):
        m = "example.com/m"
        # advisor Oct 24: v0.9 -> v0.10 is not a major
        self.assertFalse(R._is_major_bump(m, "v0.9.0", "v0.10.0"))
        self.assertFalse(R._is_major_bump(m + "/v2", "v2.1.0", "v2.2.0"))
        # not versions: held
        for bad in ("v1.2.3-", "v1.2.3+", "v1.2.3-..", "v1.2.3-a..b", "v1.2.3+x y", "v1.2"):
            self.assertTrue(R._is_major_bump(m, "v1.2.3", bad), bad)
        for good in ("v1.2.4-rc.1", "v1.2.4+incompatible", "v1.2.4-0.20200101000000-abcdef123456"):
            self.assertFalse(R._is_major_bump(m, "v1.2.3", good), good)
        self.assertTrue(R._is_major_bump(m, "v0.9.0", "v1.0.0"))            # v0 -> v1 is
        self.assertTrue(R._is_major_bump(m, "v1.9.0", "v2.0.0"))
        self.assertTrue(R._is_major_bump(m, "v1.0.0", "garbage"))           # unreadable: held, never treated as a patch

    def test_a_dry_run_and_a_disabled_delivery_do_not_claim_an_issue_was_opened_and_a_dry_run_checks_the_deferral(self):
        row = lambda: {"id": "CVE-2099-50", "fix_bump": {"cve": "CVE-2099-50", "module": "example.com/m",
            "from": "v0.9.0", "to": "v1.0.0"}}
        r1 = row(); would = []
        self.quiet(R._deliver_bumps, [r1], "2026-09-22", "abcdef1234567890", True, would)
        self.assertIn("would be opened (dry run)", r1["action"])
        self.assertNotIn("held as a harness lane task (issue", r1["action"])
        self.assertTrue(any(w["kind"] == "held-major issue" for w in would))
        os.environ["AUDITOR_ALLOW_REAL_GH"] = "0"; os.environ.pop("AUDITOR_GIT_SHIM_LOG", None)
        r2 = row()
        with mock.patch.object(R, "_deliver_fix_pr", return_value=("https://x/pull/3", None, "delivered")):
            self.quiet(R._deliver_bumps, [r2], "2026-09-22", "abcdef1234567890", False, [])
        self.assertIn("issue NOT opened (delivery disabled)", r2["action"])
        # a dry run that can read GitHub says it would defer to the open Dependabot PR
        os.environ["AUDITOR_GIT_SHIM_LOG"] = os.path.join(self.tmp, "dd.log")
        os.environ["AUDITOR_SHIM_DEPENDABOT_PRS"] = json.dumps([{"number": 41,
            "title": "Bump example.com/m from 0.9.0 to 1.0.0"}])
        try:
            r3 = row(); would = []
            self.quiet(R._deliver_bumps, [r3], "2026-09-22", "abcdef1234567890", True, would)
        finally:
            os.environ.pop("AUDITOR_SHIM_DEPENDABOT_PRS", None)
        self.assertIn("deferred to Dependabot PR", r3["action"])
        self.assertTrue(any("deferred to Dependabot PR #41" in (w.get("note") or "") for w in would))

    def test_the_held_major_issue(self):
        would = []
        self.assertEqual(R._emit_held_issue("t", "b", True, would, cves=["C"], target="x"), (True, "dry"))
        self.assertEqual(len(would), 1)
        os.environ.pop("AUDITOR_GIT_SHIM_LOG", None); os.environ["AUDITOR_ALLOW_REAL_GH"] = "0"
        self.assertEqual(R._emit_held_issue("t", "b", False, []), (True, "skipped"))
        os.environ["AUDITOR_ALLOW_REAL_GH"] = "1"
        def go(rules):
            fr = FakeRun(rules)
            with mock.patch.object(R.subprocess, "run", fr):
                return R._emit_held_issue("t", "b", False, []), fr
        res, fr = go({("gh", "issue", "list"): (0, "[]", ""), ("gh", "issue", "create"): (0, "https://x/issues/12\n",
            "")})
        self.assertEqual(res, (True, 12))
        create = [a for a in fr.argvs() if a[:3] == ["gh", "issue", "create"]][0]
        # never an owner-decision issue
        self.assertNotIn("--label", create); self.assertNotIn("--assignee", create)
        res, fr = go({("gh", "issue", "list"): (0, json.dumps([{"number": 3, "title": "t"}]), "")})
        self.assertEqual(res, (True, 3)); self.assertIn(["gh", "issue", "comment", "3", "--body", "b"], fr.argvs())
        self.assertEqual(go({("gh", "issue", "list"): (1, "", "boom")})[0], (False, None))
        self.assertEqual(go({("gh", "issue", "list"): (0, "[]", ""), ("gh", "issue", "create"): (1, "", "boom")})[0],
            (False, None))
        self.assertEqual(go({("gh", "issue", "list"): (0, "[]", ""), ("gh", "issue", "create"): (0, "", "")})[0], (True,
            ""))
        self.assertEqual(go({("gh", "issue", "list"): (0, "{bad", "")})[0], (False, None))
        log = os.path.join(self.tmp, "fx.log"); os.environ["AUDITOR_GIT_SHIM_LOG"] = log
        self.assertEqual(R._emit_held_issue("t", "b", False, []), (True, "shim-created"))
        self.assertEqual(R._emit_held_issue("t", "b", False, []), (True, "shim-updated"))
        os.environ["AUDITOR_SHIM_ISSUE_FAIL"] = "1"
        try:
            self.assertEqual(R._emit_held_issue("u", "b", False, []), (False, None))
        finally:
            os.environ.pop("AUDITOR_SHIM_ISSUE_FAIL", None)

    def test_a_major_whose_held_issue_fails_makes_the_run_incomplete(self):
        log = os.path.join(self.tmp, "mj.log")
        os.environ["AUDITOR_GIT_SHIM_LOG"] = log
        os.environ["AUDITOR_SHIM_ISSUE_FAIL"] = "1"
        row = {"id": "CVE-2099-40", "fix_bump": {"cve": "CVE-2099-40", "module": "example.com/m", "from": "v0.9.0",
            "to": "v1.0.0"}}
        try:
            errs = self.quiet(R._deliver_bumps, [row], "2026-09-22", "abcdef1234567890", False, [])[0]
        finally:
            os.environ.pop("AUDITOR_SHIM_ISSUE_FAIL", None)
        self.assertEqual(errs, ["held-major issue"])
        self.assertTrue(row["pending_delivery"])
        self.assertIn("FAILED to open", row["action"])

    def test_go_get_unresolvable_and_tidy_error(self):
        res, fr = self.real({("go", "get"): (1, "", "unknown revision")})
        self.assertEqual(res, (None, None, "unresolvable"))
        self.assertIn(["go", "get", "example.com/m@v1.1.0"], fr.argvs())
        self.assertEqual(fr.argvs()[-1], ["git", "reset", "--hard", "origin/main"])
        res, fr = self.real({("go", "mod", "tidy"): (1, "", "missing go.sum entry")})
        self.assertEqual(res, (None, "go mod tidy: missing go.sum entry", "error"))
        self.assertEqual(fr.argvs()[-1], ["git", "reset", "--hard", "origin/main"])

    def test_noop_bump_is_unresolvable(self):
        res, fr = self.real({("git", "diff"): (0, "", "")})                # nothing staged
        self.assertEqual(res, (None, None, "unresolvable"))
        self.assertIn(["git", "add", "go.mod"], fr.argvs())               # (changed: only the files that exist are staged; the checkout has no go.sum)
        self.assertFalse(any(a[:2] == ["git", "commit"] for a in fr.argvs()))

    def test_existing_and_race_and_create(self):
        chg = {("git", "diff"): (1, "", "")}
        res, fr = self.real({**chg, ("gh", "pr", "list"): (0, "https://x/pull/1", "")}, automerge=True)
        self.assertEqual(res, ("https://x/pull/1", None, "delivered"))
        self.assertIn(["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/1"], fr.argvs())
        res, fr = self.real({**chg, ("gh", "pr", "list"): [(0, "", ""), (0, "https://x/pull/2", "")],
                                         ("gh", "pr", "create"): (1, "", "already exists")})
        self.assertEqual(res, ("https://x/pull/2", None, "delivered"))
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] for a in fr.argvs()))   # automerge off: not armed
        # the race-recovered PR is updated to this run's CVE list too (round-1 blocker 2)
        self.assertIn("https://x/pull/2", [a[3] for a in fr.argvs() if a[:3] == ["gh", "pr", "edit"]])
        res, fr = self.real({**chg, ("gh", "pr", "create"): (1, "", "HTTP 422")})
        self.assertEqual(res, (None, "gh pr create: HTTP 422", "error"))
        res, fr = self.real({**chg, ("gh", "pr", "create"): (0, "https://x/pull/3\n", "")})
        self.assertEqual(res, ("https://x/pull/3", None, "delivered"))
        self.assert_branch_off_main(fr)
        create = [a for a in fr.argvs() if a[:3] == ["gh", "pr", "create"]][0]
        self.assertEqual(create[:4], ["gh", "pr", "create", "--draft"])
        self.assertIn("Run report: the daily CVE auditor run report", create[-1])
        res, fr = self.real({**chg, ("gh", "pr", "create"): (0, "https://x/pull/4\n", "")}, automerge=True)
        self.assertEqual(fr.argvs()[-1], ["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/4"])

    def test_failed_edit_is_a_failed_delivery(self):
        """A reused PR whose edit fails is an error on BOTH discovery paths and is never armed
        (round-1 blocker 1: the old CVE list would stand while the run said delivered)."""
        chg = {("git", "diff"): (1, "", ""), ("gh", "pr", "edit"): (1, "", "HTTP 403")}
        for lst, extra in (((0, "https://x/pull/1", ""), {}),
                           ([(0, "", ""), (0, "https://x/pull/1", "")], {("gh", "pr", "create"): (1, "", "already exists")})):
            res, fr = self.real({**chg, **extra, ("gh", "pr", "list"): lst}, automerge=True)
            self.assertEqual(res, (None, "gh pr edit: HTTP 403", "error"))
            self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] for a in fr.argvs()))

    def test_unchanged_target_is_not_pushed(self):
        """AC2 on the real path: go.mod/go.sum identical to the target branch -> no push; the open
        PR is found and only its title/body are refreshed (no duplicate, no overwrite)."""
        rules = {("git", "diff", "--cached"): (1, "", ""), ("git", "diff", "--quiet"): (0, "", ""),
                 ("gh", "pr", "list"): (0, "https://x/pull/1", "")}
        res, fr = self.real(rules)
        self.assertEqual(res, ("https://x/pull/1", None, "delivered"))
        self.assertIn(["git", "fetch", "origin", self.BR], fr.argvs())
        self.assertFalse(any(a[:2] == ["git", "push"] for a in fr.argvs()))
        self.assertFalse(any(a[:3] == ["gh", "pr", "create"] for a in fr.argvs()))
        self.assertTrue(any(a[:4] == ["gh", "pr", "edit", "https://x/pull/1"] for a in fr.argvs()))


class OwnerIssue(Base):
    T = "auditor: owner-decision: CVE-2099-50 — libz — critical-severity"

    def test_real_gh_disabled_is_skipped(self):
        with mock.patch.object(R.subprocess, "run") as sr:
            res, out = self.quiet(R._emit_owner_issue, self.T, "b", False, [])
        self.assertEqual(res, (True, "skipped")); sr.assert_not_called()
        self.assertIn("would open/update owner issue (real gh disabled): " + self.T, out)

    def real(self, rules):
        os.environ.update(AUDITOR_ALLOW_REAL_GH="1", AUDITOR_ISSUES_TOKEN="issues-tok")
        fr = FakeRun(rules)
        with mock.patch.object(R.subprocess, "run", fr):
            res, out = self.quiet(R._emit_owner_issue, self.T, "body", False, [])
        return res, out, fr

    def test_existing_issue_is_commented(self):
        found = json.dumps([{"number": 3, "title": "other"}, {"number": 12, "title": self.T}])
        res, _o, fr = self.real({("gh", "issue", "list"): (0, found, "")})
        self.assertEqual(res, (True, 12))
        self.assertEqual(fr.argvs()[1], ["gh", "issue", "comment", "12", "--body", "body"])
        self.assertEqual(fr.calls[1][1]["env"]["GH_TOKEN"], "issues-tok")
        res, _o, fr = self.real({("gh", "issue", "list"): (0, found, ""), ("gh", "issue", "comment"): (1, "", "x")})
        self.assertEqual(res, (False, 12))

    def test_create_failure_and_exception(self):
        res, out, fr = self.real({("gh", "issue", "list"): (0, "[]", ""), ("gh", "issue", "create"): (1, "", "label missing")})
        self.assertEqual(res, (False, None)); self.assertIn("owner-issue create FAILED: label missing", out)
        res, out, fr = self.real({("gh", "issue", "list"): FileNotFoundError("gh not found")})
        self.assertEqual(res, (False, None)); self.assertIn("owner-issue open/update failed: gh not found", out)


class StandingIssue(Base):
    T = policy.STANDING_ISSUE_TITLE

    def real(self, rules, needs):
        os.environ["AUDITOR_ALLOW_REAL_GH"] = "1"
        fr = FakeRun(rules)
        with mock.patch.object(R.subprocess, "run", fr):
            return R._standing_issue(needs, False, []), fr

    def test_discovery_parse_failure(self):
        (ok, ref), _ = self.real({("gh", "issue", "list"): (0, "not json", "")}, ["x"])
        self.assertFalse(ok); self.assertTrue(ref.startswith("standing-issue discovery parse failed: "), ref)

    def test_needs_comment_on_open_issue(self):
        rows = json.dumps([{"number": 5, "state": "OPEN", "title": self.T}])
        (ok, ref), fr = self.real({("gh", "issue", "list"): (0, rows, "")}, ["item one"])
        self.assertEqual((ok, ref), (True, "commented:5"))
        c = fr.argvs()[1]
        self.assertEqual(c[:5], ["gh", "issue", "comment", "5", "--body"]); self.assertIn("- item one", c[5])
        (ok, ref), fr = self.real({("gh", "issue", "list"): (0, rows, ""),
                                   ("gh", "issue", "comment"): (1, "", "Bearer abcdefghij rejected")}, ["i"])
        self.assertEqual((ok, ref), (False, "standing comment failed: Bearer <redacted> rejected"))

    def test_nothing_needed_closes_open_issues(self):
        rows = json.dumps([{"number": 5, "state": "OPEN", "title": self.T}, {"number": 6, "state": "open", "title": self.T},
                           {"number": 2, "state": "CLOSED", "title": self.T}])
        (ok, ref), fr = self.real({("gh", "issue", "list"): (0, rows, "")}, [])
        self.assertEqual((ok, ref), (True, "closed:5,6"))
        self.assertEqual([a[:4] for a in fr.argvs()[1:]], [["gh", "issue", "close", "5"], ["gh", "issue", "close", "6"]])
        (ok, ref), fr = self.real({("gh", "issue", "list"): (0, rows, ""), ("gh", "issue", "close", "6"): (1, "", "x")}, [])
        self.assertEqual((ok, ref), (False, "close-failed:5,6"))

    def test_nothing_needed_none_open(self):
        rows = json.dumps([{"number": 2, "state": "CLOSED", "title": self.T}])
        (ok, ref), fr = self.real({("gh", "issue", "list"): (0, rows, "")}, [])
        self.assertEqual((ok, ref), (True, "none-open")); self.assertEqual(len(fr.calls), 1)


# ---------------------------------------------------------------- consistency / tables / main

class ConsistencyTablesMain(Base):
    def test_consistency_nonzero_exit_is_a_problem(self):
        res = R._consistency(self.d("out"), self.d("supp"), os.path.join(self.tmp, "missing-manifest.json"))
        self.assertEqual(len(res["problems"]), 1)
        self.assertEqual(res["problems"][0]["type"], "consistency-check-failed")
        self.assertTrue(res["problems"][0]["detail"].startswith("rc=1 "), res)

    def test_scanner_tables_fallback_clean_and_not_run(self):
        keep = []; self.addCleanup(lambda: [os.unlink(k) for k in keep])
        vp = verdict_fixture.fixture_verdict("panel-01", keep)
        status = {"grype": {"ran": True, "package_count": 18}, "scout": {"ran": True, "package_count": 18},
                  "inspector": {"ran": False, "reason": "did not run on: production-amd64", "package_count": 0},
                  "google": {"ran": True, "package_count": 6}}
        m = {"scanner_set": "panel", "panel": {"verdict": vp}, "scanner_status": status,
             "scanner_reports": {sc: vp for sc in ("grype", "scout", "inspector", "google")}}
        rows = [{"id": "CVE-2022-48303", "section": 3, "aliases": [], "scope_purls": ["pkg:deb/debian/other@1"]}]
        out = self.d("out")
        _r, printed = self.quiet(R._scanner_tables, m, rows, out)
        text = open(os.path.join(out, "reports", "scanner-tables.txt")).read()
        self.assertIn(text.strip(), printed)
        tar = [l for l in text.splitlines() if "CVE-2022-48303" in l and "tar" in l]
        self.assertTrue(tar and tar[0].rstrip().endswith("§3"), tar)                    # id-only fallback when the purl matches no routed scope
        cu = [l for l in text.splitlines() if "CVE-2016-2781" in l][0]
        self.assertTrue(cu.rstrip().endswith("-"))                                      # unrouted -> "-"
        insp = text.split("::group::inspector")[1].split("::endgroup::")[0]
        self.assertIn("did not run (did not run on: production-amd64); what it did report follows", insp)
        # a scanner that ran and reported nothing is clean; one that did not run and reported nothing is incomplete, never clean
        vz = verdict_fixture.fixture_verdict("panel-osquorum", keep)
        out2 = self.d("out2")
        m2 = dict(m, panel={"verdict": vz}, scanner_status=dict(status))
        self.quiet(R._scanner_tables, m2, [], out2)
        text2 = open(os.path.join(out2, "reports", "scanner-tables.txt")).read()
        self.assertIn("  clean — no findings", text2.split("::group::grype")[1].split("::endgroup::")[0])
        self.assertIn("no findings reported; scan incomplete (did not run: did not run on: production-amd64)",
                      text2.split("::group::inspector")[1].split("::endgroup::")[0])
        out3 = self.d("out3")
        self.quiet(R._scanner_tables, dict(m, panel={"verdict": None}), [], out3)
        self.assertIn("did not inventory: ", open(os.path.join(out3, "reports", "scanner-tables.txt")).read())

    def test_scanner_tables_panel_with_an_unreadable_verdict_says_so(self):
        bad = self.wj(os.path.join(self.tmp, "verdict-bad.json"), "{")
        m = {"scanner_set": "panel", "panel": {"verdict": bad},
             "scanner_status": {s: {"ran": True, "package_count": 5} for s in ("grype", "scout", "inspector", "google")},
             "scanner_reports": {s: bad for s in ("grype", "scout", "inspector", "google")}}
        out = self.d("out")
        self.quiet(R._scanner_tables, m, [], out)
        text = open(os.path.join(out, "reports", "scanner-tables.txt")).read()
        self.assertEqual(text.count("(could not parse report:"), 4)               # each scanner's group says it could not read the verdict
        self.assertIn("::group::grype — 5 packages, ? findings", text)            # no count is invented for a verdict that cannot be read

    def test_main_exit_codes(self):
        with mock.patch.object(R.cli, "ARGS", []), mock.patch.object(R.cli, "close_adjudicators") as close:
            rc, out = self.quiet(R.main)
        self.assertEqual(rc, 2); self.assertIn("daily CVE auditor: no manifest supplied", out)
        close.assert_not_called()
        args = ["--manifest", "m.json", "--out", self.tmp, "--dry-run", "false", "--today", "2026-09-23"]
        with mock.patch.object(R.cli, "ARGS", args), mock.patch.object(R.cli, "close_adjudicators") as close, \
                mock.patch.object(R, "run", side_effect=ValueError("scanner_reports object is missing")) as run:
            rc, out = self.quiet(R.main)
        self.assertEqual(rc, 3)
        self.assertIn("daily CVE auditor: manifest invalid — scanner_reports object is missing", out)
        close.assert_called_once()
        run.assert_called_once_with("m.json", False, self.tmp, "2026-09-23", kevpath=None)
        for ret, want in ((True, 0), (False, 1)):
            with mock.patch.object(R.cli, "ARGS", args), mock.patch.object(R.cli, "close_adjudicators"), \
                    mock.patch.object(R, "run", return_value=ret):
                self.assertEqual(self.quiet(R.main)[0], want)


# ---------------------------------------------------------------- run() end to end (in-process)

def _expected_images(scanner):
    from auditorlib import nochange,  parsers as PL
    return sum(1 for im in PL.panel_images() if PL.panel_expected(scanner, im))      # follows bin/panel.py VARIANTS (Google: amd64 only)


PANEL_STATUS = {s: {"ran": True, "reason": "ok", "package_count": 6, "images_ran": _expected_images(s), "images_expected": _expected_images(s)}
                for s in ("grype", "scout", "inspector", "google")}


def panel_manifest_fields(tmp):
    """A full-matrix panel verdict (every scanner ran on every image, no findings) and the manifest fields that name it."""
    from auditorlib import parsers as PL
    images = {}
    for im in sorted(PL.panel_images()):
        ran = sorted(x for x in PL.PANEL_SCANNERS if PL.panel_expected(x, im))
        images[im] = {"counts": {x: 10 for x in ran}, "did_not_run": [], "ran": ran, "counts_for_day": True}
    path = os.path.join(tmp, "verdict-ok.json")
    with open(path, "w") as fh:
        json.dump({"images": images, "not_counted": [], "scanner_failures": [], "findings": [], "vex_covered": [],
                   "issue": PL._panel_module().render_issue([]), "unique": [], "exit": 0}, fh)
    return {"scanner_set": "panel", "panel": {"verdict": path}, "scanner_status": PANEL_STATUS,
            "scanner_reports": {x: path for x in PL.PANEL_SCANNERS}}


class Run(Base):
    def grp(self, *findings):
        g = {}
        for f in findings:
            e = g.setdefault(f["finding_id"], {"id": f["finding_id"], "aliases": {f["finding_id"]}, "findings": []})
            e["findings"].append(f)
        return g

    def go(self, groups, dry=True, adjudicator="/x/stub-adjudicator.py", kevpath=None, m_extra=None, ask=None,
           consistency=None):
        m = dict({"commit": "abcdef1234567890", "candidate_digests": {"production": "sha256:d"}}, **panel_manifest_fields(self.tmp))
        m.update(m_extra or {})
        out = self.d("out")
        adj = os.path.join(self.d("adj"), os.path.basename(adjudicator))   # the run fingerprints its adjudicator file: a real file of the same name (no test touches /x)
        open(adj, "w").write("# a stand-in adjudicator\n"); adjudicator = adj
        ask = ask or mock.Mock(side_effect=AssertionError("no model call expected"))
        with mock.patch.object(R.C, "manifest_findings", return_value=(m, groups)), \
                mock.patch.object(R, "_consistency", return_value=consistency or {"problems": []}), \
                mock.patch.object(R.cli, "ask_model", ask):
            complete, printed = self.quiet(R.run, os.path.join(self.tmp, "manifest.json"), dry, out, "2026-09-22",
                                           kevpath=kevpath, adjudicator=adjudicator)
        cls = json.load(open(os.path.join(out, "classification.json")))
        return complete, printed, out, {f["id"]: f for f in cls["findings"]}, cls

    def test_carried_inventory_kev_unparseable_and_tables_failure(self):
        pa, pb, pc = "pkg:deb/debian/liba@1.0", "pkg:deb/debian/libb@1.0", "pkg:deb/debian/libc@1.0"
        ws = self.d("ws"); os.environ["GITHUB_WORKSPACE"] = ws
        self.wj(os.path.join(ws, ".vex", "fosterstack-cache.openvex.json"), {"statements": [
            {"@id": "V#a", "vulnerability": {"name": "CVE-2099-60"}, "status": "affected",
             "products": [{"@id": PROD, "subcomponents": [{"@id": pa}]}]}]})
        self.wj(os.path.join(ws, ".auditor", "accepted-items.json"), {"accepted_items": [
            {"cve": "CVE-2099-60", "scope_purls": [pa], "expiry": "2026-12-01",
             "not_pullable": "upstream-held", "lift_trigger": {"carrier": "nodejs", "min_version": "20.2",
                 "component": "liba", "component_min_version": "3.0.13"}},
            {"cve": "CVE-2099-61", "scope_purls": [pb], "not_pullable": "upstream-held"},      # no expiry: ignored
            {"cve": "CVE-2099-62", "vex_id": "V#unknown", "expiry": "2026-12-01",
             "not_pullable": "upstream-held"}]})                                                # unresolvable: ignored
        kev = self.wj(os.path.join(self.tmp, "kev.json"), "{")
        groups = self.grp(F("CVE-2099-60", pa, "liba", fixed="1.1"), F("CVE-2099-61", pb, "libb", fixed="1.1"),
                          F("CVE-2099-62", pc, "libc", fixed="1.1"))
        with mock.patch.object(R, "_scanner_tables", side_effect=RuntimeError("tbl boom")):
            complete, printed, out, cls, whole = self.go(groups, kevpath=kev)
        self.assertIn("scanner-tables emit failed: tbl boom", printed)
        self.assertEqual(cls["CVE-2099-60"]["disposition"], "carried (fix not pullable) — recheck deferred")
        self.assertEqual(cls["CVE-2099-60"]["section"], 2)
        self.assertIn("owner-decision issue would open (dry run)", cls["CVE-2099-60"]["action"])
        self.assertEqual(cls["CVE-2099-61"]["disposition"], "real, fixable (base rebuild)")
        self.assertEqual(cls["CVE-2099-62"]["disposition"], "real, fixable (base rebuild)")
        items = json.load(open(os.path.join(out, ".auditor", "accepted-items.json")))["accepted_items"]
        self.assertEqual([(i["cve"], i["threshold"], i["lift_trigger"]) for i in items],
                         # KEV unparseable -> fail closed
                         [("CVE-2099-60", "at_or_above", {"carrier": "nodejs", "min_version": "20.2",
                             "component": "liba", "component_min_version": "3.0.13"})])
        self.assertTrue(os.path.exists(os.path.join(out, ".auditor", "knowledge.md")))

    def test_a_consistency_check_that_did_not_complete_makes_the_run_incomplete(self):
        # a consistency check that did not complete means AUDIT INCOMPLETE, never a clean run
        # (Codex AC2 round-5 residual); the same empty run is complete without it
        clean, _p, _o, _c, whole = self.go({})
        self.assertTrue(clean)
        bad = {"consistent": False, "problems": [{"type": "consistency-check-failed", "detail": "rc=1 no manifest"}]}
        complete, printed, _o, _c, whole = self.go({}, consistency=bad)
        self.assertFalse(complete)
        self.assertIn("consistency check did not complete", whole["status"])

    def test_dry_unassessed_issue_would_open(self):
        c = "CVE-2099-63"
        def ask(adj, fid, **kw):
            if fid == "CONCLUSION":
                return {"narrative": ""}
            raise R.cli.Refused(fid)
        complete, _p, _o, cls, _w = self.go(self.grp(F(c, "pkg:deb/debian/libq@1", "libq")),
                                            adjudicator="/x/real-adjudicator.py", ask=mock.Mock(side_effect=ask))
        self.assertEqual(cls[c]["section"], 4)
        self.assertEqual(cls[c]["action"], "owner-decision issue would open (dry run)")

    def test_one_version_spelled_two_ways_is_one_disposition(self):
        # two scanners' own package URLs spell one version differently (%2B vs +): one row, both lineages, no unique-lineage suspicion
        c = "CVE-2099-65"
        g = self.grp(F(c, "pkg:deb/debian/libq@3.0.1%2Bdeb12u1", "libq", fixed="3.0.2", scanner="grype"),
                     F(c, "pkg:deb/debian/libq@3.0.1+deb12u1", "libq", fixed="3.0.2", scanner="scout"))
        _complete, _printed, _o, cls, whole = self.go(g)
        self.assertEqual([f["id"] for f in whole["findings"]].count(c), 1)

    def test_dry_section3_with_nothing_to_open_is_unactioned(self):
        c = "CVE-2099-64"
        complete, printed, _o, cls, whole = self.go(self.grp(F(c, "pkg:deb/debian/libr@1", "libr", fixed="2")))
        self.assertFalse(complete)
        self.assertEqual(cls[c]["section"], 3)
        self.assertEqual(whole["status"], "AUDIT INCOMPLETE: 1 findings without an action")
        self.assertIn("AUDIT INCOMPLETE: 1 findings without an action", printed)

    def test_issue_failures_mark_rows_and_status(self):
        e, r = "CVE-2099-65", "CVE-2099-66"
        os.environ.update(AUDITOR_GIT_SHIM_LOG=os.path.join(self.tmp, "shim.log"), AUDITOR_SHIM_ISSUE_FAIL="1")
        def ask(adj, fid, **kw):
            if fid == "CONCLUSION":
                return {"narrative": ""}
            if fid == e:
                raise RuntimeError("HTTP 500")
            raise R.cli.Refused(fid)
        complete, _p, _o, cls, whole = self.go(
            self.grp(F(e, "pkg:deb/debian/libe@1", "libe"), F(r, "pkg:deb/debian/libf@1", "libf")),
            dry=False, adjudicator="/x/real-adjudicator.py", ask=mock.Mock(side_effect=ask))
        self.assertFalse(complete)
        self.assertEqual(cls[e]["action"], "unassessed: adjudicator unavailable; OWNER ISSUE FAILED")
        self.assertEqual(cls[r]["action"], "OWNER ESCALATION FAILED")
        self.assertIn("2 owner-decision issue(s) failed to open", whole["status"])
        self.assertIn("1 findings unassessed: adjudicator unavailable (RuntimeError: HTTP 500)", whole["status"])

    def test_go_bump_unresolvable_stays_section3(self):
        c = "CVE-2099-67"
        os.environ.update(AUDITOR_ALLOW_REAL_GH="1", GITHUB_WORKSPACE=self.d("ws"))
        fr = FakeRun({("go", "get"): (1, "", "unknown revision v9.9.9"),
                      ("gh", "issue", "list"): (0, "[]", "")})
        f = F(c, "pkg:golang/example.com/m@v1.0.0", "example.com/m", fixed="v9.9.9", scanner="osv-scanner-gomod")
        with mock.patch.object(R.subprocess, "run", fr):
            complete, _p, _o, cls, whole = self.go(self.grp(f), dry=False)
        self.assertEqual(cls[c]["section"], 3)
        self.assertEqual(cls[c]["action"], "fix not resolvable: example.com/m@v9.9.9 did not resolve from the module proxy — stays in section 3")
        self.assertIn(["go", "get", "example.com/m@v9.9.9"], fr.argvs())


class ExitThreeBeforeMutation(unittest.TestCase):
    """cache#701 ruling F3/B3 and the cache#708 ruling: every validation that can end the run with exit 3 runs before
    the first mutating call: the per-finding VEX and the delivery base
    (one fetch, one sha, its two reviewed files read as git objects) before the first owner-decision issue, the run's
    own outputs before `git checkout -B <sha>`."""
    SHA40 = "a" * 40
    VP, AP = ".vex/fosterstack-cache.openvex.json", ".auditor/accepted-items.json"

    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)

    def _show(self, rc, out="", err=""):
        return FakeRun({("git", "show"): (rc, out.encode() if isinstance(out, str) else out, err.encode() if isinstance(err, str) else err)})

    def test_base_file_absent_is_the_first_run_good_files_are_returned(self):
        with mock.patch.object(R.subprocess, "run", self._show(128, "", "fatal: path 'x' does not exist in 'abc'")):
            self.assertIsNone(R._base_file(self.d, self.SHA40, self.VP))
        with mock.patch.object(R.subprocess, "run", self._show(0, json.dumps({"statements": []}))):
            self.assertEqual(R._base_file(self.d, self.SHA40, self.VP), {"statements": []})

    def test_both_not_in_the_base_answers_mean_absent_and_the_workspace_copy_is_never_the_base(self):
        # a workspace file (untracked, or deleted on main): not the base
        os.makedirs(os.path.join(self.d, ".vex")); open(os.path.join(self.d, self.VP), "w").write("{}")
        for gone in ("fatal: path 'x' does not exist in 'abc'", "fatal: path 'x' exists on disk, but not in 'abc'"):
            with mock.patch.object(R.subprocess, "run", self._show(128, "", gone)):
                self.assertIsNone(R._base_file(self.d, self.SHA40, self.VP))

    def test_git_show_runs_in_the_c_locale(self):
        fr = self._show(128, "", "fatal: path 'x' does not exist in 'abc'")
        with mock.patch.object(R.subprocess, "run", fr):
            R._base_file(self.d, self.SHA40, self.VP)
        # git's messages are matched, so they are read in English
        self.assertEqual(fr.calls[0][1]["env"]["LC_ALL"], "C")

    def test_a_base_file_that_cannot_be_read_or_is_not_the_required_object_is_a_stop(self):
        bad = (self._show(128, "", "fatal: bad object"), self._show(0, "{not json"), self._show(0, "[]"), self._show(0, "{}"), self._show(0, b"\xff\xfe{}"))
        for fake in bad:
            with mock.patch.object(R.subprocess, "run", fake):
                with self.assertRaises(R.ReviewedInputInvalid):
                    R._base_file(self.d, self.SHA40, self.VP)

    def test_fetch_base_gives_one_sha_or_the_failure_to_report(self):
        with mock.patch.object(R.subprocess, "run", FakeRun()):
            self.assertEqual(R._fetch_base(self.d), (self.SHA40, None))
        with mock.patch.object(R.subprocess, "run", FakeRun({("git", "fetch"): (1, "", " offline \n")})):
            # handed down: the delivery reports it and never fetches again
            self.assertEqual(R._fetch_base(self.d), (None, "git fetch: offline"))
        with mock.patch.object(R.subprocess, "run", FakeRun({("git", "rev-parse", "origin/main"): (0, "not-a-sha\n", "")})):
            self.assertEqual(R._fetch_base(self.d), (None, "git rev-parse: not-a-sha"))
        with mock.patch.object(R.subprocess, "run", FakeRun({("git", "rev-parse", "origin/main"): (1, "", "bad")})):
            self.assertEqual(R._fetch_base(self.d), (None, "git rev-parse: bad"))

    def test_base_docs_reads_both_reviewed_files_from_the_sha(self):
        fr = FakeRun({("git", "show", self.SHA40 + ":" + self.VP): (0, json.dumps({"statements": []}).encode(), b"")})
        with mock.patch.object(R.subprocess, "run", fr):
            docs = R._base_docs(self.d, self.SHA40)
        self.assertEqual(docs, {self.VP: {"statements": []}, self.AP: None})
        self.assertEqual([a for a in fr.argvs() if a[:2] == ["git", "show"]], [["git", "show", self.SHA40 + ":" + self.VP], ["git", "show", self.SHA40 + ":" + self.AP]])

    def test_preflight_validates_what_the_merge_will_read(self):
        out = os.path.join(self.d, "out"); supp = os.path.join(out, "suppressions"); os.makedirs(supp)
        with mock.patch.object(R.subprocess, "run", FakeRun()):
            # nothing of the run is written yet: first-run shaped, passes
            R._preflight_delivery(out, supp)
            vp = os.path.join(supp, "fosterstack-cache.openvex.json")
            open(vp, "w").write("{}")
            with self.assertRaises(R.ReviewedInputInvalid):
                # a consolidated VEX without its statements stops it
                R._preflight_delivery(out, supp)
            json.dump({"statements": []}, open(vp, "w"))
            R._preflight_delivery(out, supp)
            os.makedirs(os.path.join(out, ".auditor"))
            open(os.path.join(out, ".auditor", "reopened-expired.json"), "w").write("{}")
            with self.assertRaises(R.ReviewedInputInvalid):
                # a damaged ledger of the run stops it before the checkout
                R._preflight_delivery(out, supp)

    def test_collect_vex_reads_and_validates_without_writing(self):
        os.makedirs(os.path.join(self.d, "vex"))
        doc, st = R._collect_vex(self.d, "2026-09-24T00:00:00Z")
        self.assertEqual((st, doc["statements"]), ([], []))
        self.assertFalse(os.path.exists(os.path.join(self.d, "suppressions")))
        open(os.path.join(self.d, "vex", "a.openvex.json"), "w").write("{}")
        with self.assertRaises(R.ReviewedInputInvalid):
            R._collect_vex(self.d, "2026-09-24T00:00:00Z")
        open(os.path.join(self.d, "vex", "a.openvex.json"), "w").write(json.dumps({"statements": [{}]}))
        # a statement set that does not validate is a stop with its own reason, not "manifest invalid"
        with self.assertRaises(R.ReviewedInputInvalid):
            R._collect_vex(self.d, "2026-09-24T00:00:00Z")

    def test_collect_vex_absent_directory_is_none_unreadable_or_not_a_directory_is_a_stop(self):
        # the first run wrote no per-finding VEX at all
        doc, st = R._collect_vex(os.path.join(self.d, "never"), "2026-09-24T00:00:00Z")
        self.assertEqual(st, [])
        open(os.path.join(self.d, "vex"), "w").write("x")
        with self.assertRaises(R.ReviewedInputInvalid):
            R._collect_vex(self.d, "2026-09-24T00:00:00Z")
        os.remove(os.path.join(self.d, "vex")); os.makedirs(os.path.join(self.d, "vex"))
        json.dump({"statements": []}, open(os.path.join(self.d, "vex", "a.openvex.json"), "w"))
        if os.geteuid() != 0:
            os.chmod(os.path.join(self.d, "vex"), 0)
            self.addCleanup(os.chmod, os.path.join(self.d, "vex"), 0o755)
            # glob used to turn this into zero statements
            with self.assertRaises(R.ReviewedInputInvalid):
                R._collect_vex(self.d, "2026-09-24T00:00:00Z")

    def test_parse_decodes_bytes_and_wraps_every_failure(self):
        from auditorlib import reviewed
        self.assertEqual(reviewed.parse(b'{"statements": []}', "x", as_name="a.openvex.json"), {"statements": []})
        for bad in (b"\xff\xfe\x00", b"{no", b"[]", b"{}"):
            with self.assertRaises(reviewed.ReviewedInputInvalid):
                reviewed.parse(bad, "x", as_name="a.openvex.json")

    def test_merge_reads_the_base_documents_it_is_given_not_the_working_tree(self):
        ws = os.path.join(self.d, "ws"); os.makedirs(os.path.join(ws, ".vex")); os.makedirs(os.path.join(ws, ".auditor"))
        tree_stmt = R.vex.doc("CVE-2099-1", "affected", "2026-08-24T00:00:00Z", action="tracked", subcomponents=["pkg:deb/debian/a@1"])["statements"][0]
        base_stmt = R.vex.doc("CVE-2099-2", "affected", "2026-08-24T00:00:00Z", action="tracked", subcomponents=["pkg:deb/debian/b@1"])["statements"][0]
        run_stmt = R.vex.doc("CVE-2099-3", "affected", "2026-08-24T00:00:00Z", action="tracked", subcomponents=["pkg:deb/debian/c@1"])["statements"][0]
        mk = lambda s: {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "x", "author": "a", "role": "vendor", "timestamp": "2026-08-24T00:00:00Z", "version": 3, "statements": [s]}
        # an untracked / modified file in the workspace
        json.dump(mk(tree_stmt), open(os.path.join(ws, self.VP), "w"))
        out = os.path.join(self.d, "out"); supp = os.path.join(out, "suppressions"); os.makedirs(supp)
        json.dump(mk(run_stmt), open(os.path.join(supp, "fosterstack-cache.openvex.json"), "w"))
        R._merge_suppressions(ws, supp, base={self.VP: mk(base_stmt), self.AP: None})
        merged = json.load(open(os.path.join(ws, self.VP)))
        names = sorted(s["vulnerability"]["name"] for s in merged["statements"])
        # the base document, not the tree's: CVE-2099-1 is not carried
        self.assertEqual((names, merged["version"]), (["CVE-2099-2", "CVE-2099-3"], 4))

    def test_delivery_given_the_sha_does_not_fetch_again_and_checks_out_the_sha(self):
        ws = self.d; out = os.path.join(ws, "out"); supp = os.path.join(out, "suppressions"); os.makedirs(supp)
        json.dump({"statements": []}, open(os.path.join(supp, "fosterstack-cache.openvex.json"), "w"))
        fr = FakeRun()
        env = {"AUDITOR_ALLOW_REAL_GH": "1", "GITHUB_WORKSPACE": ws}
        with mock.patch.dict(os.environ, env), mock.patch.object(R.subprocess, "run", fr), contextlib.redirect_stdout(io.StringIO()):
            R._deliver_suppression_pr(out, supp, 1, "2026-09-22", "abcdef1234567890", False, [], base_sha="b" * 40)
        argvs = fr.argvs()
        self.assertNotIn(["git", "fetch", "origin", "main"], argvs)
        self.assertIn(["git", "show", "b" * 40 + ":" + self.VP], argvs)
        co = [a for a in argvs if a[:3] == ["git", "checkout", "-B"]]
        self.assertEqual([a[4] for a in co], ["b" * 40])


class SupplyCves(unittest.TestCase):
    """The suppression PR's plan entry names the CVEs its VEX package carries."""
    def test_names_from_the_package_and_none_without_one(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        self.assertEqual(R._supp_cves(d), [])
        with open(os.path.join(d, "fosterstack-cache.openvex.json"), "w") as fh:
            json.dump({"statements": [{"vulnerability": {"name": "CVE-2"}}, {"vulnerability": {"name": "CVE-1"}},
                                      {"vulnerability": {"name": "CVE-2"}}, {"vulnerability": {}}]}, fh)
        self.assertEqual(R._supp_cves(d), ["CVE-1", "CVE-2"])


class DefectLogLoading(unittest.TestCase):
    """A known-defect log that is not a JSON object is a LOG error (clear message, exit 3) —
    never blamed on the manifest, never a traceback (found while covering REQ-AUD-18 AC2)."""

    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)

    def _log(self, text):
        p = os.path.join(self.d, "log.json")
        with open(p, "w") as fh:
            fh.write(text)
        return p

    def test_absent_log_is_empty(self):
        self.assertEqual(R.load_defect_log(None), {})
        self.assertEqual(R.load_defect_log(os.path.join(self.d, "missing.json")), {})

    def test_object_log_loads_and_indexes(self):
        log = R.load_defect_log(self._log(json.dumps({"defects": [
            {"keys": [{"scanner": "grype", "finding_id": "CVE-1", "purl": "pkg:x"}]}]})))
        self.assertEqual(list(R.log_index(log)), [("grype", "CVE-1", "pkg:x")])

    def test_malformed_and_non_object_logs_raise_log_error(self):
        for text, want in (("{", "Expecting property name"), ("[]", "top level is list")):
            with self.assertRaises(R.DefectLogInvalid) as cm:
                R.load_defect_log(self._log(text))
            self.assertIn(want, str(cm.exception))

    def test_main_reports_log_not_manifest(self):
        out = io.StringIO()
        with mock.patch.object(R, "run", side_effect=R.DefectLogInvalid("log.json: top level is list")), \
             mock.patch.object(R.cli, "ARGS", ["--manifest", "m.json", "--dry-run", "true", "--out", self.d]), \
             mock.patch.object(R.cli, "close_adjudicators") as closed, contextlib.redirect_stdout(out):
            rc = R.main()
        self.assertEqual(rc, 3)
        self.assertIn("known-defect log invalid — log.json: top level is list", out.getvalue())
        self.assertNotIn("manifest invalid", out.getvalue())
        closed.assert_called_once_with()


if __name__ == "__main__":
    unittest.main(verbosity=2)
