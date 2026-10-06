"""REQ-AUD-18 AC2: behaviour tests for .github/agent/bin/auditor-run.py paths the matrix suite does
not reach — the real-gh delivery paths (with a fake subprocess), the pullability class edges, the
merge/consolidate fallbacks, the narrative guard, the scanner tables and main()'s exit codes.

No network, no real git/gh/go: every subprocess call is intercepted by FakeRun and asserted on by
its exact argv. Every write goes to a temp dir."""
import contextlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIX = os.path.abspath(os.path.join(BIN, "..", "fixtures"))
sys.path.insert(0, BIN)
_spec = importlib.util.spec_from_file_location("auditor_run_cov", os.path.join(BIN, "auditor-run.py"))
R = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(R)
policy = R.policy
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
        self.rules = dict(rules or {}); self.calls = []

    def __call__(self, argv, **kw):
        argv = list(argv); self.calls.append((argv, kw))
        best = None
        for pre in self.rules:
            if tuple(argv[:len(pre)]) == pre and (best is None or len(pre) > len(best)):
                best = pre
        resp = (0, "", "") if best is None else self.rules[best]
        if isinstance(resp, list):
            resp = resp.pop(0) if len(resp) > 1 else resp[0]
        if isinstance(resp, BaseException):
            raise resp
        rc, out, err = resp
        return subprocess.CompletedProcess(argv, rc, out, err)

    def argvs(self):
        return [a for a, _ in self.calls]


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
            self.assertEqual(len(x), 5); self.assertEqual(x[4], "origin/main")
        self.assertLess(a.index(["git", "fetch", "origin", "main"]), a.index(co[0]))

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="covrun-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ); p.start(); self.addCleanup(p.stop)
        for k in _PATH_ENVS:
            os.environ.pop(k, None)

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
             "adjudicator": "/x/real-adjudicator.py", "state": {"tokens": 0, "iters": 0, "roles_used": set()},
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

    def test_ignores_skip_statement_without_vulnerability(self):
        sts = [{"@id": "orphan", "status": "affected", "vulnerability": {}},
               {"@id": "S1", "status": "affected", "vulnerability": {"name": "CVE-2099-1"},
                "products": [{"@id": PROD, "subcomponents": [{"@id": "pkg:deb/x@1"}]}]}]
        snyk, toml = R._ignores_from_statements(sts, {("CVE-2099-1", "pkg:deb/x@1"): "2026-10-01"})
        self.assertNotIn("orphan", snyk + toml)
        self.assertEqual(snyk.count("  CVE-"), 1)
        self.assertIn("    - 'pkg:deb/x@1':", snyk)
        self.assertIn("expires: 2026-10-01T00:00:00.000Z", snyk)
        self.assertEqual(toml.count("[[IgnoredVulns]]"), 1)
        self.assertIn('expires = "2026-10-01T00:00:00Z"', toml)

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
        self.assertEqual(ask.call_args.kwargs["context"]["structured"]["commit"], "c1")


# ---------------------------------------------------------------- pullability model call

class Pullability(Base):
    def test_over_budget_makes_no_call(self):
        with mock.patch.object(R.cli, "ask_model") as ask:
            st = {"tokens": policy.TOKEN_BUDGET}
            self.assertIsNone(R._pullability("/a", {"finding_id": "C"}, st))
            st2 = {"tokens": 0, "iters": policy.MAX_ITERATIONS}
            self.assertIsNone(R._pullability("/a", {"finding_id": "C"}, st2))
        ask.assert_not_called()
        self.assertNotIn("calls", st); self.assertNotIn("calls", st2)

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
        ans = {"pullable": False, "lift_trigger": "nodejs >= 20.2 embeds libz 1.1", "token_usage": 7}
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
        ig = json.load(open(os.path.join(env["out"], "ignores", "grype", c + ".json")))
        self.assertEqual((ig["expiry"], ig["scoped_purls"]), ("2026-10-22", [self.PURL]))

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
                    carried_lift_trigger={key: "nodejs >= 20.2"})
        row, _ = R._dispose(c, [f], [c], self.env(kev_ok=False, **base), [])
        self.assertEqual(row["disposition"], "carried (fix not pullable) — recheck deferred")
        self.assertEqual((row["threshold"], row["expiry"], row["lift_trigger"]), ("at_or_above", "2026-12-01", "nodejs >= 20.2"))
        self.assertEqual(row["owner_issue_intent"]["reason_key"], "kev-unavailable (fail-closed)")
        self.assertIn("carrier signal absent this run", row["action"])
        row2, _ = R._dispose(c, [f], [c], self.env(kev_ok=True, **base), [])
        self.assertEqual(row2["threshold"], "below"); self.assertNotIn("owner_issue_intent", row2)


# ---------------------------------------------------------------- merge / consolidate fallbacks

class MergeConsolidate(Base):
    def _stmt(self, cve, purls, status="affected"):
        return R.vex.doc(cve, status, "2026-09-22T00:00:00Z", action="x", subcomponents=purls)["statements"][0]

    def _supp(self, statements, version=1):
        out = self.d("out"); supp = self.d("out", "suppressions")
        self.wj(os.path.join(supp, "fosterstack-cache.openvex.json"),
                {"@context": "c", "@id": policy.VEX_BASE, "author": "a", "role": "vendor",
                 "timestamp": "t", "version": version, "statements": statements})
        return out, supp

    def test_corrupt_existing_vex_treated_as_empty(self):
        ws = self.d("ws"); self.wj(os.path.join(ws, ".vex", "fosterstack-cache.openvex.json"), "{not json")
        _out, supp = self._supp([self._stmt("CVE-2099-20", ["pkg:deb/a@1"])], version=4)
        R._merge_suppressions(ws, supp)
        merged = json.load(open(os.path.join(ws, ".vex", "fosterstack-cache.openvex.json")))
        self.assertEqual(merged["version"], 4)                            # new doc's version, not existing+1
        self.assertEqual([s["vulnerability"]["name"] for s in merged["statements"]], ["CVE-2099-20"])
        self.assertIn("CVE-2099-20", open(os.path.join(ws, ".snyk")).read())

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

    def test_consolidate_skips_unreadable_files(self):
        out = self.d("out")
        good = R.vex.doc("CVE-2099-23", "affected", "t", action="x", subcomponents=["pkg:deb/x@1"])
        self.wj(os.path.join(out, "vex", "a-good.openvex.json"), good)
        self.wj(os.path.join(out, "vex", "b-bad.openvex.json"), "{")
        self.wj(os.path.join(out, "ignores", "grype", "good.json"),
                {"id": "CVE-2099-23", "expiry": "2026-10-01", "scoped_purls": ["pkg:deb/x@1"]})
        self.wj(os.path.join(out, "ignores", "grype", "bad.json"), "{")
        self.wj(os.path.join(out, "evidence", "bad.evidence.json"), "{")
        self.wj(os.path.join(out, "evidence", "good.evidence.json"), {"vulnerability": "CVE-2099-23", "target_date": "2027-01-01"})
        supp, n = R._consolidate(out, "2026-09-22T00:00:00Z")
        self.assertEqual(n, 1)
        doc = json.load(open(os.path.join(supp, "fosterstack-cache.openvex.json")))
        self.assertEqual(len(doc["statements"]), 1)
        snyk = open(os.path.join(supp, ".snyk")).read()
        self.assertIn("expires: 2026-10-01T00:00:00.000Z", snyk)          # the scoped box, not the sidecar's


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

    def real(self, fr, automerge=False, supp=None):
        os.environ.update(AUDITOR_ALLOW_REAL_GH="1", GITHUB_WORKSPACE=self.ws)
        os.environ.pop("AUDITOR_AUTOMERGE", None)
        if automerge:
            os.environ["AUDITOR_AUTOMERGE"] = "on"
        with mock.patch.object(R.subprocess, "run", fr):
            return self.quiet(R._deliver_suppression_pr, self.out, supp or self.supp, 1, "2026-09-22",
                              "abcdef1234567890", False, [])[0]

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
        for pre, label in ((("git", "fetch"), "git fetch"), (("git", "checkout"), "git checkout"),
                           (("git", "commit"), "git commit"), (("git", "push"), "git push")):
            fr = FakeRun({pre: (1, "", " %s broke \n" % label)})
            self.assertEqual(self.real(fr), (None, "%s: %s broke" % (label, label)), label)
            self.assertFalse(any(a[:3] == ["gh", "pr", "create"] for a in fr.argvs()), label)
        push = [a for a in fr.argvs() if a[:2] == ["git", "push"]][0]
        self.assertEqual(push, ["git", "push", "-u", "origin", self.BR, "--force-with-lease"])

    def test_stage_failure(self):
        fr = FakeRun()
        url, err = self.real(fr, supp=self.d("empty-supp"))               # no openvex file to merge
        self.assertIsNone(url); self.assertTrue(err.startswith("stage files: "), err)
        self.assertEqual(fr.argvs(), [["git", "fetch", "origin", "main"], ["git", "checkout", "-B", self.BR, "origin/main"]])

    def test_existing_pr_reused_and_armed(self):
        fr = FakeRun({("gh", "pr", "list"): (0, "https://x/pull/7\n", "")})
        self.assertEqual(self.real(fr, automerge=True), ("https://x/pull/7", None))
        self.assertIn(["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/7"], fr.argvs())
        self.assertFalse(any(a[:3] == ["gh", "pr", "create"] for a in fr.argvs()))
        # staged files rode the checkout
        self.assertTrue(os.path.exists(os.path.join(self.ws, ".auditor", "knowledge.md")))
        self.assertTrue(os.path.exists(os.path.join(self.ws, ".vex", "fosterstack-cache.openvex.json")))
        add = [a for a in fr.argvs() if a[:2] == ["git", "add"]][0]
        self.assertIn(".auditor/knowledge.md", add)
        fr = FakeRun({("gh", "pr", "list"): (0, "https://x/pull/7\n", "")})
        self.assertEqual(self.real(fr), ("https://x/pull/7", None))
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] for a in fr.argvs()))

    def test_create_race_already_exists(self):
        fr = FakeRun({("gh", "pr", "list"): [(0, "", ""), (0, "https://x/pull/8", "")],
                      ("gh", "pr", "create"): (1, "", "a pull request already EXISTS for head")})
        self.assertEqual(self.real(fr, automerge=True), ("https://x/pull/8", None))
        self.assertIn(["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/8"], fr.argvs())
        # race but the existing PR cannot be found -> a real failure
        fr = FakeRun({("gh", "pr", "create"): (1, "", "already exists")})
        self.assertEqual(self.real(fr), (None, "gh pr create: already exists"))
        fr = FakeRun({("gh", "pr", "create"): (1, "", "HTTP 403")})
        self.assertEqual(self.real(fr), (None, "gh pr create: HTTP 403"))

    LIST = ("gh", "api", "repos/{owner}/{repo}/pulls?state=open&per_page=100")
    OPEN = ("5 auditor/2026-09-20-aaaaaaaaaaaa\n6 auditor/2026-09-22-abcdef123456\n7 auditor/panel\n8 auditor/bump-example.com-m-1.1.0\n"
            "9 feature/x\n10 auditor/2026-09-21-bbbbbbbbbbbb\n12 auditor/2026-09-23-cccccccccccc\n")

    def test_superseded_daily_suppression_prs_are_closed(self):          # advisor 0187: stale PRs must not pile up behind main
        for how, rules in (("created", {("gh", "pr", "create"): (0, "https://x/pull/11\n", "")}),
                           ("existing", {("gh", "pr", "list"): (0, "https://x/pull/6\n", "")})):
            fr = FakeRun({**rules, self.LIST: (0, self.OPEN, "")})
            self.assertIsNotNone(self.real(fr)[0], how)
            closed = sorted(a[3] for a in fr.argvs() if a[:3] == ["gh", "pr", "close"])
            self.assertEqual(closed, ["10", "5"], how)              # only OLDER daily branches: not today's, not a NEWER one (12), not panel/bump/feature
            first = [a for a in fr.argvs() if a[:3] == ["gh", "pr", "close"]][0]
            self.assertIn("--comment", first)
            self.assertIn("supersed", first[first.index("--comment") + 1].lower())
            self.assertNotIn("--delete-branch", first)                      # the branch stays: nothing here deletes refs

    def test_only_the_apps_own_non_draft_same_repo_prs_are_candidates(self):    # reviewer r1 blocker 2
        fr = FakeRun({("gh", "pr", "create"): (0, "https://x/pull/11\n", ""), self.LIST: (0, self.OPEN, "")})
        self.real(fr)
        lst = [a for a in fr.argvs() if a[:3] == list(self.LIST)][0]
        self.assertIn("--paginate", lst)
        jq = lst[lst.index("--jq") + 1]
        for needle in ('.head.repo.fork == false', '.draft == false', '.user.type == "Bot"'):
            self.assertIn(needle, jq)                                          # a fork's, a human's and an owner-held draft are never closed

    def test_todays_replacement_must_be_a_same_repo_pr_into_main(self):                            # review r6 B2
        fr = FakeRun({("gh", "pr", "list"): (0, "https://x/pull/7\n", ""), self.LIST: (0, self.OPEN, "")})
        self.real(fr, automerge=True)
        lst = [a for a in fr.argvs() if a[:3] == ["gh", "pr", "list"]][0]
        jq = lst[lst.index("--jq") + 1]
        self.assertIn("isCrossRepository == false", jq); self.assertIn('baseRefName == "main"', jq)

    def test_nothing_is_closed_when_todays_pr_was_not_delivered(self):
        fr = FakeRun({("gh", "pr", "create"): (1, "", "HTTP 403"), self.LIST: (0, self.OPEN, "")})
        self.assertIsNone(self.real(fr)[0])
        self.assertFalse(any(a[:3] == ["gh", "pr", "close"] for a in fr.argvs()))

    def test_a_failing_cleanup_never_fails_the_delivery(self):
        fr = FakeRun({("gh", "pr", "create"): (0, "https://x/pull/11\n", ""), self.LIST: (1, "", "HTTP 500"),
                      ("gh", "pr", "close"): (1, "", "HTTP 500")})
        self.assertEqual(self.real(fr), ("https://x/pull/11", None))
        fr = FakeRun({("gh", "pr", "create"): (0, "https://x/pull/11\n", ""), self.LIST: (0, self.OPEN, ""), ("gh", "pr", "close"): (1, "", "HTTP 500")})
        self.assertEqual(self.real(fr), ("https://x/pull/11", None))

    def test_create_draft_vs_automerge(self):
        fr = FakeRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.assertEqual(self.real(fr, automerge=True), ("https://x/pull/9", None))
        self.assert_branch_off_main(fr)
        create = [a for a in fr.argvs() if a[:3] == ["gh", "pr", "create"]][0]
        self.assertNotIn("--draft", create)
        self.assertEqual(fr.argvs()[-1], ["gh", "pr", "merge", "--auto", "--squash", "https://x/pull/9"])
        fr = FakeRun({("gh", "pr", "create"): (0, "https://x/pull/9\n", "")})
        self.assertEqual(self.real(fr), ("https://x/pull/9", None))
        create = [a for a in fr.argvs() if a[:3] == ["gh", "pr", "create"]][0]
        self.assertEqual(create[3], "--draft")
        self.assertFalse(any(a[:3] == ["gh", "pr", "merge"] for a in fr.argvs()))


class FixPR(Base):
    ROW = {"id": "CVE-2099-40", "fix_bump": {"cve": "CVE-2099-40", "module": "example.com/m", "from": "v1.0.0", "to": "v1.1.0"}}
    BR = "auditor/bump-example.com-m-1.1.0"       # keyed by TARGET, never by CVE or commit (LR-32)

    def real(self, rules, automerge=False):
        os.environ.update(AUDITOR_ALLOW_REAL_GH="1", GITHUB_WORKSPACE=self.d("ws"))
        os.environ.pop("AUDITOR_AUTOMERGE", None)
        if automerge:
            os.environ["AUDITOR_AUTOMERGE"] = "1"
        fr = FakeRun(rules)
        with mock.patch.object(R.subprocess, "run", fr):
            res = self.quiet(R._deliver_fix_pr, self.ROW, "2026-09-22", "abcdef1234567890", False, [])[0]
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

    def test_git_failures(self):
        for pre, label in ((("git", "fetch"), "git fetch"), (("git", "checkout"), "git checkout")):
            res, fr = self.real({pre: (1, "", "nope")})
            self.assertEqual(res, (None, "%s: nope" % label, "error"))
            self.assertEqual(fr.argvs()[0], ["git", "reset", "--hard"])
        res, fr = self.real({("git", "diff"): (1, "", ""), ("git", "commit"): (1, "", "empty")})
        self.assertEqual(res, (None, "git commit: empty", "error"))
        res, fr = self.real({("git", "diff"): (1, "", ""), ("git", "push"): (1, "", "rejected")})
        self.assertEqual(res, (None, "git push: rejected", "error"))

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
        self.assertIn(["git", "add", "go.mod", "go.sum"], fr.argvs())
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

    def test_scanner_tables_fallback_and_unparseable(self):
        bad = self.wj(os.path.join(self.tmp, "trivy-bad.json"), "{")
        m = {"scanner_status": {"grype": {"ran": True, "package_count": 18, "findings": 6},
                                "trivy": {"ran": True, "package_count": 18, "findings": 3},
                                "snyk": {"ran": False, "reason": "no token"}},
             "scanner_reports": {"grype": os.path.join(FIX, "scanners", "grype.json"), "trivy": bad}}
        rows = [{"id": "CVE-2022-48303", "section": 3, "aliases": [], "scope_purls": ["pkg:deb/debian/other@1"]}]
        out = self.d("out")
        _r, printed = self.quiet(R._scanner_tables, m, rows, out)
        text = open(os.path.join(out, "reports", "scanner-tables.txt")).read()
        self.assertIn(text.strip(), printed)
        tar = [l for l in text.splitlines() if "CVE-2022-48303" in l]
        self.assertEqual(len(tar), 1); self.assertTrue(tar[0].rstrip().endswith("§3"), tar[0])  # id-only fallback
        cu = [l for l in text.splitlines() if "CVE-2016-2781" in l][0]
        self.assertTrue(cu.rstrip().endswith("-"))                          # unrouted -> "-"
        self.assertIn("::group::trivy — 18 packages, 3 findings\n  (could not parse report:", text)
        self.assertIn("  clean — no findings", text.split("::group::trivy")[1].split("::endgroup::")[0])
        self.assertIn("::group::snyk — ? packages, ? findings\n  did not inventory: no token", text)

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

QUORUM = {s: {"ran": True, "reason": "ok", "package_count": 6, "os_package_count": 6, "findings": 1}
          for s in ("grype", "trivy", "snyk")}


class Run(Base):
    def grp(self, *findings):
        g = {}
        for f in findings:
            e = g.setdefault(f["finding_id"], {"id": f["finding_id"], "aliases": {f["finding_id"]}, "findings": []})
            e["findings"].append(f)
        return g

    def go(self, groups, dry=True, adjudicator="/x/stub-adjudicator.py", kevpath=None, m_extra=None, ask=None,
           consistency=None):
        m = {"commit": "abcdef1234567890", "candidate_digests": {"production": "sha256:d"},
             "scanner_status": QUORUM, "scanner_reports": {}}
        m.update(m_extra or {})
        out = self.d("out")
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
             "not_pullable": "upstream-held", "lift_trigger": "nodejs >= 20.2"},
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
                         [("CVE-2099-60", "at_or_above", "nodejs >= 20.2")])   # KEV unparseable -> fail closed
        self.assertTrue(os.path.exists(os.path.join(out, ".auditor", "knowledge.md")))

    def test_unparseable_snyk_makes_the_run_incomplete(self):
        # an unreadable .snyk means the consistency check did not complete -> AUDIT INCOMPLETE,
        # never a clean run (Codex AC2 round-5 residual); the same empty run is complete without it
        clean, _p, _o, _c, whole = self.go({})
        self.assertTrue(clean)
        bad = {"consistent": False, "problems": [{"type": "consistency-check-unparseable-snyk",
                                                  "detail": ".snyk line 5: not in the auditor's ignore shape"}]}
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
