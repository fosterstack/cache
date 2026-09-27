"""REQ-AUD-18 AC2: behavioural coverage of the small auditor commands and auditorlib helpers.

Every test asserts an effect (return value, file written, exit message, stdout, or the exact argv a
fake gh / adjudicator received). No network; every write goes to a temp dir.
"""
import importlib.util, io, json, os, runpy, subprocess, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import cli, knowledge as K, parsers as P, policy, vex  # noqa: E402

FIX = os.path.join(BIN, "..", "fixtures")


def read(path):
    with open(path) as fh:
        return fh.read()


def write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def load(name):
    spec = importlib.util.spec_from_file_location("cov_small_" + name.replace("-", "_"),
                                                  os.path.join(BIN, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Tmp(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = self._td.name
        self.addCleanup(self._td.cleanup)

    def p(self, *parts):
        return os.path.join(self.d, *parts)

    def wj(self, name, obj):
        path = self.p(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(obj if isinstance(obj, str) else json.dumps(obj))
        return path

    def rj(self, *parts):
        with open(self.p(*parts)) as fh:
            return json.load(fh)

    def args(self, *a):
        return mock.patch.object(cli, "ARGS", [str(x) for x in a])


GOOD = "sha256:" + "a" * 64


class DigestGuards(Tmp):
    def _run(self, mod, digest):
        rs = self.wj("rs.json", {"run": {"candidate_digests": {"production": digest}}})
        with self.args("--run-state", rs, "--out", self.p("out")):
            mod.main()

    def test_build_parity_refuses_malformed_digest(self):
        m = load("auditor-build-parity")
        with self.assertRaises(SystemExit) as cm:
            self._run(m, "sha256:ABC")
        self.assertIn("build-parity: refusing to compare a malformed digest 'sha256:ABC'", str(cm.exception.code))
        self.assertFalse(os.path.exists(self.p("out", "parity.json")))
        self._run(m, GOOD)
        self.assertEqual(self.rj("out", "parity.json"),
                         {"ci_digest": GOOD, "built_digest": GOOD, "digests_match": True,
                          "compared_before_scan": True})

    def test_consume_rescan_refuses_malformed_digest(self):
        m = load("auditor-consume-rescan")
        with self.assertRaises(SystemExit) as cm:
            self._run(m, GOOD + "\n")
        self.assertIn("consume-rescan: refusing to reuse a malformed candidate digest", str(cm.exception.code))
        self.assertFalse(os.path.exists(self.p("out", "scanner-calls.json")))
        self._run(m, GOOD)
        self.assertEqual(self.rj("out", "scanner-calls.json"), {"count": 0})
        self.assertEqual(self.rj("out", "consumed.json")["digest"], GOOD)


class Consistency(Tmp):
    def test_toml_ignore_without_vex_citation_is_tool_only(self):
        m = load("auditor-consistency")
        live = self.wj("manifest.json", {"scanner_reports": {"grype": None}})
        self.wj("supp/osv-scanner.toml",
                '[[IgnoredVulns]]\nid = "GHSA-aaaa"\nreason = "no citation"\n'
                '[[IgnoredVulns]]\nid = "CVE-2020-1"\nreason = "see stmt-cve-2020-1"\n'
                '[[IgnoredVulns]]\nreason = "no id at all"\n')
        with self.args("--suppression-dir", self.p("supp"), "--live-findings", live,
                       "--out", self.p("c.json")):
            m.main()
        self.assertEqual(self.rj("c.json"),
                         {"consistent": False,
                          "problems": [{"type": "tool_only_ignore", "id": "GHSA-aaaa"}]})

    def test_toml_all_cited_is_consistent(self):
        m = load("auditor-consistency")
        live = self.wj("manifest.json", {"scanner_reports": {}})
        self.wj("supp/osv-scanner.toml", '[[IgnoredVulns]]\nid = "CVE-2020-1"\nreason = "stmt-x"\n')
        with self.args("--suppression-dir", self.p("supp"), "--live-findings", live,
                       "--out", self.p("c.json")):
            m.main()
        self.assertEqual(self.rj("c.json"), {"consistent": True, "problems": []})


ADJ_STUB = r'''
import json, sys
LOG = %r
assert sys.argv[1:] == ["--serve"], sys.argv
for line in sys.stdin:
    req = json.loads(line)
    open(LOG, "a").write(json.dumps(req) + "\n")
    fid = req["finding_id"]
    if fid == "ERR":
        ans = {"error": "client error: boom"}
    elif fid.startswith("NOT-"):
        ans = {"same_defect": False}
    else:
        ans = {"same_defect": True, "category": "false_positive"}
    sys.stdout.write(json.dumps(ans) + "\n"); sys.stdout.flush()
'''


class WithAdjudicator(Tmp):
    def setUp(self):
        super().setUp()
        self.adj_log = self.p("adj.log")
        self.adj = self.wj("adj.py", ADJ_STUB % self.adj_log)
        self.addCleanup(cli.close_adjudicators)

    def adj_requests(self):
        if not os.path.exists(self.adj_log):
            return []
        return [json.loads(l) for l in read(self.adj_log).splitlines()]


class Defectlog(WithAdjudicator):
    def setUp(self):
        super().setUp()
        self.m = load("auditor-defectlog")
        g = P.parse_grype(os.path.join(FIX, "scanners", "grype.json"))
        self.gf = next(f for f in g if f["finding_id"] == "CVE-2016-2781")
        self.manifest = self.wj("manifest.json", {"scanner_reports": {
            "grype": os.path.join(FIX, "scanners", "grype.json")}})

    def reconcile(self, log, fid, purl, manifest=True):
        lp = self.wj("log.json", log)
        a = ["reconcile", "--out", self.p("out"), "--log", lp, "--adjudicator", self.adj,
             "--finding", "grype", fid, purl]
        if manifest:
            a += ["--manifest", self.manifest]
        with self.args(*a):
            self.m.main()
        return self.rj("out", "reconcile.json"), json.loads(read(lp))

    def test_model_says_not_same_defect(self):
        log = {"defects": [{"keys": [{"scanner": "trivy", "finding_id": "NOT-1", "purl": "x"}]}]}
        res, after = self.reconcile(log, "NOT-1", "pkg:x")
        self.assertEqual(res, {"added": False, "reason": "model: not the same defect"})
        self.assertEqual(after, log)
        self.assertEqual([r["finding_id"] for r in self.adj_requests()], ["NOT-1"])

    def test_scanner_does_not_report_purl(self):
        log = {"defects": [{"keys": [{"scanner": "trivy", "finding_id": "CVE-2016-2781", "purl": "x"}]}]}
        res, after = self.reconcile(log, "CVE-2016-2781", "pkg:deb/debian/other@1")
        self.assertEqual(res, {"added": False, "reason": "scanner does not report this purl"})
        self.assertEqual(after, log)
        # no manifest at all: equally unreported
        res2, _ = self.reconcile(log, "CVE-2016-2781", self.gf["purl"], manifest=False)
        self.assertEqual(res2["reason"], "scanner does not report this purl")

    def test_reported_but_no_row_names_it(self):
        log = {"defects": [{"keys": [{"scanner": "trivy", "finding_id": "CVE-1999-0001", "purl": "x"}]}]}
        res, after = self.reconcile(log, "CVE-2016-2781", self.gf["purl"])
        self.assertEqual(res, {"added": False, "reason": "no row names this finding"})
        self.assertEqual(after, log)

    def test_reported_and_row_names_it_adds_key(self):
        log = {"defects": [{"keys": [{"scanner": "trivy", "finding_id": "CVE-2016-2781", "purl": "x"}]}]}
        res, after = self.reconcile(log, "CVE-2016-2781", self.gf["purl"])
        new = {"scanner": "grype", "finding_id": "CVE-2016-2781", "purl": self.gf["purl"]}
        self.assertEqual(res, {"added": new})
        self.assertEqual(after["defects"][0]["keys"][-1], new)

    def test_unknown_op_exits(self):
        with self.args("frobnicate", "--out", self.p("out")):
            with self.assertRaises(SystemExit) as cm:
                self.m.main()
        self.assertEqual(cm.exception.code, "defectlog: unknown op 'frobnicate'")
        self.assertFalse(os.path.exists(self.p("out")))


class KnowledgeScript(Tmp):
    PATH = os.path.join(BIN, "auditor-knowledge.py")
    LOG = {"defects": [
        {"keys": [{"scanner": "grype", "finding_id": "CVE-1", "purl": "p1"}], "package": "zlib",
         "disposition": "false_positive", "evidence": "ev"},
        {"keys": [{"scanner": "grype", "finding_id": "CVE-2", "purl": "p2"}], "package": "bash",
         "disposition": "proposed", "evidence": "model"}]}

    def run_main(self, *a):
        with self.args(*a), mock.patch("sys.stdout", new_callable=io.StringIO) as so:
            runpy.run_path(self.PATH, run_name="__main__")
        return so.getvalue()

    def test_generate_to_file(self):
        lp = self.wj("log.json", self.LOG)
        out = self.run_main("generate", "--log", lp, "--out", self.p("k", "knowledge.md"))
        self.assertEqual(out, "")
        body = read(self.p("k", "knowledge.md"))
        self.assertEqual(body, K.generate(self.LOG))
        self.assertIn("`CVE-1` on `zlib`", body)
        self.assertNotIn("CVE-2", body)

    def test_generate_to_stdout_and_missing_log(self):
        lp = self.wj("log.json", self.LOG)
        # concrete content, not K.generate() as its own oracle (Codex AC2 round-1 residual)
        full = self.run_main("generate", "--log", lp)
        self.assertIn("`CVE-1` on `zlib`", full)
        self.assertNotIn("CVE-2", full)
        self.assertNotIn("None recorded yet.", full)
        empty = self.run_main("generate", "--log", self.p("absent.json"))
        self.assertIn("None recorded yet.", empty)
        self.assertNotIn("CVE-1", empty)

    def test_unknown_op(self):
        with self.assertRaises(SystemExit) as cm:
            self.run_main("publish")
        self.assertEqual(cm.exception.code, "knowledge: unknown op 'publish' (expected 'generate')")


class KnowledgeLib(unittest.TestCase):
    def test_duplicate_finding_package_listed_once(self):
        row = lambda ev: {"keys": [{"scanner": "grype", "finding_id": "CVE-9", "purl": "p"}],
                          "package": "openssl", "disposition": "not_affected", "evidence": ev}
        doc = K.generate({"defects": [row("first"), row("second")]})
        self.assertEqual(doc.count("`CVE-9` on `openssl`"), 1)
        self.assertIn("`CVE-9` on `openssl` — not_affected: first", doc)
        # distinct packages under the same finding are NOT collapsed
        other = row("third"); other["package"] = "libssl"
        doc2 = K.generate({"defects": [row("first"), other]})
        self.assertIn("`CVE-9` on `libssl`", doc2)
        self.assertIn("`CVE-9` on `openssl`", doc2)


class LayoutCheck(Tmp):
    def test_unreadable_path_is_skipped_readable_reference_flagged(self):
        m = load("auditor-layout-check")
        os.makedirs(self.p("docs"))
        write(self.p("docs", "ref.md"), "see .github/agent/bin\n")
        write(self.p("docs", "clean.md"), "nothing here\n")
        bad = m.offenders(["docs/missing.md", "docs/clean.md", "docs/ref.md"], self.d)
        self.assertEqual(bad, [("docs/ref.md", "refers to .github/agent/")])
        self.assertEqual(m.offenders(["docs/missing.md"], self.d), [])


class NoKeyLeak(Tmp):
    def test_unreadable_entry_is_skipped(self):
        m = load("auditor-no-key-leak")
        scan = self.p("scan"); os.makedirs(scan)
        os.symlink(self.p("nowhere"), os.path.join(scan, "dangling"))
        # built at runtime (never a literal, never a foldable "+"): this file lives under the scanned tree
        write(os.path.join(scan, "leak.txt"), "key=%s\n" % "-".join(("sk", "ant", "abcdef123")))
        write(os.path.join(scan, "ok.txt"), "sk-ant-x\n")
        with self.args("--scan", scan, "--out", self.p("out")):
            m.main()
        self.assertEqual(self.rj("out", "leak.json"), {"leaks": [os.path.join(scan, "leak.txt")]})


GH_STUB = r'''
import json, sys
open(%r, "a").write(json.dumps(sys.argv[1:]) + "\n")
if sys.argv[1] == "find":
    print(%r)
elif sys.argv[1] == "create":
    print("42")
'''


class Notify(Tmp):
    def setUp(self):
        super().setUp()
        self.m = load("auditor-notify")
        self.kev = self.wj("kev.json", {"vulnerabilities": [{"cveID": "CVE-KEV"}]})

    def test_is_trigger_branches(self):
        base = {"cve": "CVE-X", "reachable": True, "fix_pullable": False}
        t = self.m.is_trigger
        self.assertFalse(t(dict(base, reachable=False, severity="critical"), self.kev))
        self.assertFalse(t(dict(base, fix_pullable=True, severity="critical"), self.kev))
        self.assertTrue(t(dict(base, severity="CRITICAL"), None))
        self.assertTrue(t(dict(base, severity="high", known_exploited=True), None))
        self.assertTrue(t(dict(base, cve="CVE-KEV", severity="high"), self.kev))
        self.assertFalse(t(dict(base, severity="high"), self.kev))
        self.assertFalse(t(dict(base, cve="CVE-KEV", severity="high"), self.p("no-kev.json")))

    def run_notify(self, finding, find_result):
        log = self.p("gh.log")
        if os.path.exists(log):
            os.remove(log)
        gh = self.wj("gh.py", GH_STUB % (log, find_result))
        fp = self.wj("finding.json", finding)
        env = {k: v for k, v in os.environ.items() if k != "AUDITOR_KEV_CATALOG"}
        with mock.patch.dict(os.environ, env, clear=True), \
                self.args("--out", self.p("out"), "--finding", fp, "--github", gh,
                          "--state", self.p("state.json"), "--artifact", "run-7"):
            self.m.main()
        calls = [json.loads(l) for l in read(log).splitlines()] if os.path.exists(log) else []
        return self.rj("out", "notify.json"), calls

    def test_critical_with_unreadable_kev_creates_issue(self):
        st = self.p("state.json")
        res, calls = self.run_notify({"cve": "CVE-X", "reachable": True, "fix_pullable": False,
                                      "severity": "critical", "package": "zlib"}, "")
        title = "auditor: owner-decision: CVE-X — zlib — critical-severity"
        self.assertEqual(res, {"notified": True, "cve": "CVE-X"})
        self.assertEqual(calls, [
            ["find", st, title],
            ["create", st, title, "owner-decision", "fosterstack-admin"],
            ["comment", st, "42", "Accept risk for CVE-X? evidence attached; artifact run-7"]])

    def test_known_exploited_existing_issue_gets_recheck_comment(self):
        st = self.p("state.json")
        res, calls = self.run_notify({"cve": "CVE-Y", "reachable": True, "fix_pullable": False,
                                      "severity": "high", "known_exploited": True}, "17")
        title = "auditor: owner-decision: CVE-Y — unknown-package — known-exploited"
        self.assertEqual(res, {"notified": True, "cve": "CVE-Y"})
        self.assertEqual(calls, [["find", st, title],
                                 ["comment", st, "17", "re-check: CVE-Y still open run-7"]])

    def test_non_trigger_never_calls_github(self):
        res, calls = self.run_notify({"cve": "CVE-Z", "reachable": False, "severity": "critical"}, "")
        self.assertEqual(res, {"notified": False, "cve": "CVE-Z"})
        self.assertEqual(calls, [])


class Policy(unittest.TestCase):
    def test_threshold_reason_order(self):
        self.assertEqual(policy.threshold_reason("Critical", True, True), "critical-severity")
        self.assertEqual(policy.threshold_reason("high", True, True), "kev")
        self.assertEqual(policy.threshold_reason("high", False, True), "known-exploited")
        self.assertEqual(policy.threshold_reason(None, False, False), "below")


class Recheck(Tmp):
    def test_not_pullable_keeps_vex(self):
        m = load("auditor-recheck")
        disp = {"cve": "CVE-2024-1", "aliases": ["GHSA-1"], "status": "not_affected"}
        vp = self.wj("disp.json", disp)
        shim = self.p("shim.log")
        with mock.patch.dict(os.environ, {"AUDITOR_GIT_SHIM_LOG": shim}), \
                self.args("--out", self.p("out"), "--vex", vp):
            m.main()
        self.assertEqual(self.rj("out", "recheck.json"),
                         {"vex_removed": False, "bump_pr_opened": False, "report_section": None})
        self.assertEqual(self.rj("out", "vex", "still-present.json"), disp)
        self.assertFalse(os.path.exists(shim))

    def test_now_pullable_opens_bump_pr(self):
        m = load("auditor-recheck")
        vp = self.wj("disp.json", {"cve": "CVE-2024-1"})
        shim = self.p("shim.log")
        with mock.patch.dict(os.environ, {"AUDITOR_GIT_SHIM_LOG": shim}), \
                self.args("--out", self.p("out"), "--vex", vp, "--now-pullable"):
            m.main()
        self.assertEqual(self.rj("out", "recheck.json")["report_section"], 1)
        self.assertEqual(read(shim).splitlines(),
                         ["git checkout -b auditor/bump-CVE-2024-1",
                          "gh pr create --head auditor/bump-CVE-2024-1 --base main --label auto-merge-lane"])
        self.assertFalse(os.path.exists(self.p("out", "vex", "still-present.json")))


class Rule0(Tmp):
    def run0(self, state, shim):
        m = load("auditor-rule0-check")
        env = dict(os.environ)
        env.pop("AUDITOR_GIT_SHIM_LOG", None)
        if shim:
            env["AUDITOR_GIT_SHIM_LOG"] = shim
        with mock.patch.dict(os.environ, env, clear=True), \
                self.args("--required-checks-state", state, "--out", self.p("out")):
            m.main()
        return self.rj("out", "rule0.json")

    def test_passing_records_auto_merge_in_shim(self):
        shim = self.p("shim.log")
        r = self.run0("passing", shim)
        self.assertFalse(r["merge_blocked_on_failing_checks"])
        self.assertEqual(read(shim), "gh pr merge --auto\n")

    def test_failing_blocks_and_records_nothing(self):
        shim = self.p("shim.log")
        r = self.run0("failing", shim)
        self.assertTrue(r["merge_blocked_on_failing_checks"])
        self.assertFalse(os.path.exists(shim))
        self.assertFalse(self.run0("passing", None)["merge_blocked_on_failing_checks"])


class FakeProc:
    def __init__(self, wait_exc=None, kill_exc=None):
        self.stdin = None; self.wait_exc = wait_exc; self.kill_exc = kill_exc
        self.killed = False; self.waited = False

    def wait(self, timeout=None):
        self.waited = timeout
        if self.wait_exc:
            raise self.wait_exc

    def kill(self):
        self.killed = True
        if self.kill_exc:
            raise self.kill_exc


class DeadPipeProc:
    """A client that has died: writing raises, stderr carries (or fails to carry) its last line."""
    def __init__(self, exc, stderr, returncode):
        self.exc = exc; self.returncode = returncode
        test = self

        class In:
            def write(self, s): raise test.exc
            def flush(self): pass

        class Err:
            def read(self):
                if isinstance(stderr, Exception):
                    raise stderr
                return stderr
        self.stdin = In(); self.stderr = Err(); self.stdout = None

    def poll(self):
        return None


class CliAdjudicator(WithAdjudicator):
    def test_close_kills_on_wait_failure_and_tolerates_kill_failure(self):
        ok = FakeProc()
        slow = FakeProc(wait_exc=subprocess.TimeoutExpired("adj", 5))
        stuck = FakeProc(wait_exc=subprocess.TimeoutExpired("adj", 5), kill_exc=OSError("gone"))
        with mock.patch.dict(cli._ADJ_PROCS, {"a": ok, "b": slow, "c": stuck}, clear=True):
            cli.close_adjudicators()
            self.assertEqual(cli._ADJ_PROCS, {})
        self.assertEqual((ok.waited, ok.killed), (5, False))
        self.assertEqual((slow.waited, slow.killed), (5, True))
        self.assertTrue(stuck.killed)

    def test_broken_pipe_surfaces_last_stderr_line(self):
        proc = DeadPipeProc(BrokenPipeError(), "warming up\nImportError: anthropic", 3)
        with mock.patch.dict(cli._ADJ_PROCS, {"adj": proc}, clear=True):
            with self.assertRaises(RuntimeError) as cm:
                cli.ask_model("adj", "CVE-1")
            self.assertNotIn("adj", cli._ADJ_PROCS)
        self.assertEqual(str(cm.exception), "adjudicator exit 3: ImportError: anthropic")

    def test_closed_pipe_with_unreadable_stderr(self):
        proc = DeadPipeProc(ValueError("I/O on closed file"), OSError("closed"), None)
        with mock.patch.dict(cli._ADJ_PROCS, {"adj": proc}, clear=True):
            with self.assertRaises(RuntimeError) as cm:
                cli.ask_model("adj", "CVE-1")
        self.assertEqual(str(cm.exception), "adjudicator exit ?: no output")

    def test_client_error_answer_raises_and_ok_answer_returns(self):
        with self.assertRaises(RuntimeError) as cm:
            cli.ask_model(self.adj, "ERR", context={"package": "zlib"})
        self.assertEqual(str(cm.exception), "client error: boom")
        # the client stayed alive: the next request reuses the same process
        proc = cli._ADJ_PROCS[self.adj]
        self.assertEqual(cli.ask_model(self.adj, "CVE-5")["category"], "false_positive")
        self.assertIs(cli._ADJ_PROCS[self.adj], proc)
        self.assertEqual(self.adj_requests(), [
            {"finding_id": "ERR", "attempt": "primary", "model": "primary", "package": "zlib"},
            {"finding_id": "CVE-5", "attempt": "primary", "model": "primary"}])


class CliGh(Tmp):
    def test_nonzero_exit_raises_with_stderr(self):
        api = self.wj("api.py", "import sys\nsys.stderr.write('  rate limited \\n')\nsys.exit(3)\n")
        with self.assertRaises(RuntimeError) as cm:
            cli.gh(api, "find", "s", 1)
        self.assertEqual(str(cm.exception), "gh api exit 3: rate limited")
        ok = self.wj("ok.py", "import sys\nprint(' '.join(sys.argv[1:]) + '  ')\n")
        self.assertEqual(cli.gh(ok, "comment", "s", 7), "comment s 7")


class Parsers(Tmp):
    def test_load_missing_file(self):
        with self.assertRaises(P.ParseError) as cm:
            P.parse_grype(self.p("absent.json"))
        self.assertIn("cannot load %s" % self.p("absent.json"), str(cm.exception))
        with self.assertRaises(P.ParseError):
            P.parse_grype(self.wj("bad.json", "{not json"))

    def test_trivy_without_results(self):
        with self.assertRaisesRegex(P.ParseError, "trivy: no Results"):
            P.parse_trivy(self.wj("t.json", {"SchemaVersion": 2}))
        self.assertEqual(P.parse_trivy(self.wj("t2.json", {"Results": None})), [])

    def test_osv_generic_ecosystem_purl(self):
        self.assertEqual(P._osv_purl({"ecosystem": "PyPI", "name": "requests", "version": "2.0"}),
                         "pkg:pypi/requests@2.0")
        self.assertEqual(P._osv_purl({"ecosystem": "npm", "name": "left-pad"}), "pkg:npm/left-pad")
        self.assertEqual(P._osv_purl({"ecosystem": "Go", "name": "x/y", "version": "v1"}),
                         "pkg:golang/x/y@v1")
        rep = self.wj("osv.json", {"results": [{"packages": [{
            "package": {"ecosystem": "crates.io", "name": "smallvec", "version": "1.0"},
            "vulnerabilities": [{"id": "RUSTSEC-1", "aliases": ["CVE-2021-1"]}]}]}]})
        f, = P.parse_osv(rep)
        self.assertEqual((f["purl"], f["aliases"]),
                         ("pkg:crates.io/smallvec@1.0", ["CVE-2021-1", "RUSTSEC-1"]))

    def test_osv_without_results(self):
        with self.assertRaisesRegex(P.ParseError, "osv: no results"):
            P.parse_osv(self.wj("o.json", {"packages": []}))

    def test_govulncheck_unreadable_and_non_object(self):
        with self.assertRaisesRegex(P.ParseError, "govulncheck: cannot read"):
            P.parse_govulncheck(self.p("absent.jsonl"))
        with self.assertRaisesRegex(P.ParseError, "govulncheck: non-object in stream"):
            P.parse_govulncheck(self.wj("g.jsonl", '{"config": {"scan_level": "symbol"}}\n[1, 2]\n'))
        ok = P.parse_govulncheck(self.wj("g2.jsonl", '{"config": {"scan_level": "symbol"}}\n'))
        self.assertEqual(ok, {"scan_level": "symbol", "module": None, "by_osv": {}})

    def test_kev_without_vulnerabilities(self):
        with self.assertRaisesRegex(P.ParseError, "kev: no vulnerabilities"):
            P.parse_kev(self.wj("k.json", {"catalogVersion": "1"}))
        self.assertEqual(P.parse_kev(self.wj("k2.json", {"vulnerabilities": [{"cveID": "CVE-1"}]})),
                         {"CVE-1"})


class VexValidate(unittest.TestCase):
    def good(self):
        return vex.doc("CVE-2024-1", "not_affected", "2026-09-27T00:00:00Z",
                       justification="vulnerable_code_not_in_execute_path")

    def test_valid_document_passes(self):
        self.assertIsNone(vex.validate(self.good()))

    def test_missing_top_level(self):
        d = self.good(); del d["author"]
        with self.assertRaisesRegex(ValueError, "VEX missing required top-level 'author'"):
            vex.validate(d)

    def test_non_schema_statement_key(self):
        d = self.good(); d["statements"][0]["evidence"] = "x"; d["statements"][0]["target_date"] = "y"
        with self.assertRaises(ValueError) as cm:
            vex.validate(d)
        self.assertEqual(str(cm.exception), "VEX statement has non-schema keys: ['evidence', 'target_date']")

    def test_statement_missing_status(self):
        d = self.good(); del d["statements"][0]["status"]
        with self.assertRaisesRegex(ValueError, "VEX statement missing vulnerability/status"):
            vex.validate(d)
        d2 = self.good(); del d2["statements"][0]["vulnerability"]
        with self.assertRaisesRegex(ValueError, "missing vulnerability/status"):
            vex.validate(d2)


if __name__ == "__main__":
    unittest.main()
