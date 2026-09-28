"""Coverage + behaviour tests for the decision scripts: auditor-classify, auditor-poam,
auditor-release-authz, auditor-suppress (REQ-AUD-18 AC2). Every test asserts an effect:
a return value, a file written (and its content), or the exit message."""
import importlib.util, json, os, shutil, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import cli, policy  # noqa: E402


def _load(fname):
    spec = importlib.util.spec_from_file_location(fname.replace("-", "_")[:-3],
                                                  os.path.join(BIN, fname))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


classify = _load("auditor-classify.py")
poam = _load("auditor-poam.py")
authz = _load("auditor-release-authz.py")
suppress = _load("auditor-suppress.py")


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cov-decisions-")
        self.addCleanup(shutil.rmtree, self.d, True)

    def p(self, *parts):
        return os.path.join(self.d, *parts)

    def put(self, name, obj):
        path = self.p(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(obj if isinstance(obj, str) else json.dumps(obj))
        return path

    def rj(self, *parts):
        with open(self.p(*parts)) as fh:
            return json.load(fh)

    def rt(self, *parts):
        with open(self.p(*parts)) as fh:
            return fh.read()

    def run_main(self, mod, args):
        with mock.patch.object(cli, "ARGS", list(args)):
            return mod.main()

    def main_exit(self, mod, args):
        with self.assertRaises(SystemExit) as cm:
            self.run_main(mod, args)
        return cm.exception.code


def gv_stream(findings, scan_level="symbol", root="example.com/app"):
    """A govulncheck JSON stream: config, SBOM, then one finding message per (osv, trace)."""
    objs = [{"config": {"scan_level": scan_level}},
            {"SBOM": {"modules": [{"path": root}, {"path": "golang.org/x/text", "version": "v0.3.0"}],
                      "roots": [root]}}]
    objs += [{"finding": {"osv": osv, "trace": trace}} for osv, trace in findings]
    return "\n".join(json.dumps(o) for o in objs) + "\n"


IMPORTED = [{"module": "golang.org/x/text", "version": "v0.3.0", "package": "golang.org/x/text/language"}]
CALLED = [{"module": "golang.org/x/text", "version": "v0.3.0", "function": "Parse"}]


# --------------------------------------------------------------------------- classify
class ClassifyVexDoc(unittest.TestCase):
    def test_optional_fields_only_when_given(self):
        full = classify.vex_doc("CVE-2024-1", "not_affected", justification="j", action="a",
                                evidence={"e": 1})
        st = full["statements"][0]
        self.assertEqual(st["@id"], policy.stmt_id("CVE-2024-1"))
        self.assertEqual(st["products"], [{"@id": policy.VEX_PRODUCT}])
        self.assertEqual((st["justification"], st["action_statement"], st["_evidence"]),
                         ("j", "a", {"e": 1}))
        self.assertEqual(full["@id"], policy.VEX_BASE)
        self.assertEqual(full["timestamp"], classify.TS)
        bare = classify.vex_doc("CVE-2024-1", "affected")["statements"][0]
        for k in ("justification", "action_statement", "_evidence"):
            self.assertNotIn(k, bare)
        self.assertEqual(bare["status"], "affected")


class ClassifyGvcVerdict(TmpCase):
    def test_no_stream(self):
        self.assertEqual(classify.gvc_verdict(None, ["X"]),
                         ("no-evidence", {"reason": "no govulncheck stream"}))
        self.assertEqual(classify.gvc_verdict(self.p("absent.json"), ["X"])[1]["reason"],
                         "no govulncheck stream")

    def test_unparseable(self):
        empty = self.put("empty.json", "")
        self.assertEqual(classify.gvc_verdict(empty, ["X"]),
                         ("no-evidence", {"reason": "unparseable govulncheck"}))

    def test_scan_level_must_be_symbol(self):
        g = self.put("pkg.json", gv_stream([("GO-1", IMPORTED)], scan_level="package"))
        self.assertEqual(classify.gvc_verdict(g, ["GO-1"]),
                         ("no-evidence", {"reason": "scan_level=package (symbol required)"}))
        g2 = self.put("sym.json", gv_stream([("GO-1", IMPORTED)]))
        self.assertEqual(classify.gvc_verdict(g2, ["GO-1"])[0], "unreachable")

    def test_module_must_match(self):
        g = self.put("g.json", gv_stream([("GO-1", IMPORTED)], root="example.com/other"))
        v, ev = classify.gvc_verdict(g, ["GO-1"], expected_module="example.com/app")
        self.assertEqual(v, "no-evidence")
        self.assertEqual(ev["reason"], "scanned module 'example.com/other' != 'example.com/app'")
        v2, ev2 = classify.gvc_verdict(g, ["GO-1"], expected_module="example.com/other")
        self.assertEqual(v2, "unreachable")
        self.assertEqual(ev2["trace_modules"], ["golang.org/x/text@0.3.0"])   # leading v stripped
        self.assertEqual(ev2["ids"], ["GO-1"])

    def test_only_empty_traces_prove_nothing(self):
        g = self.put("g.json", gv_stream([("GO-1", []), ("GO-1", [{}])]))
        self.assertEqual(classify.gvc_verdict(g, ["GO-1"]),
                         ("no-evidence", {"reason": "only empty traces; not proof of unreachability"}))
        g2 = self.put("r.json", gv_stream([("GO-1", IMPORTED), ("GO-1", CALLED)]))
        self.assertEqual(classify.gvc_verdict(g2, ["GO-1"])[0], "reachable")


class ClassifyFpVerified(TmpCase):
    def test_lineage_only_copy_is_not_evidence(self):
        key = {"scanner": "grype", "finding_id": "DSA-1", "purl": "pkg:deb/debian/x@1"}
        log = self.put("log.json", {"defects": [{"disposition": "false_positive", "keys": [key]}]})
        lineage = dict(key, _lineage_only=True)
        self.assertIsNone(classify.fp_verified(["CVE-1"], log, [lineage]))
        ev = classify.fp_verified(["CVE-1"], log, [lineage, dict(key)])
        self.assertEqual(ev, {"check": "known-defect-log", "source_file": log,
                              "detail": "exact key grype/DSA-1/pkg:deb/debian/x@1"})


class ClassifyManifestValidation(unittest.TestCase):
    FULL = {k: None for k in ("grype", "trivy", "osv-scanner", "osv-scanner-gomod", "snyk")}

    def test_scanner_reports_missing(self):
        with self.assertRaisesRegex(ValueError, "scanner_reports object is missing"):
            classify.validate_manifest({})
        with self.assertRaisesRegex(ValueError, "scanner_reports object is missing"):
            classify.validate_manifest({"scanner_reports": []})

    def test_missing_key(self):
        r = dict(self.FULL); del r["snyk"]
        with self.assertRaisesRegex(ValueError, "missing key 'snyk'"):
            classify.validate_manifest({"scanner_reports": r})

    def test_null_needs_reason_when_status_recorded(self):
        m = {"scanner_reports": dict(self.FULL), "scanner_status": {"grype": {"reason": None}}}
        with self.assertRaisesRegex(ValueError, "grype is null with no scanner_status reason"):
            classify.validate_manifest(m)
        reasons = {k: {"reason": "timeout"} for k in self.FULL}
        ok = {"scanner_reports": dict(self.FULL), "scanner_status": reasons}
        self.assertIs(classify.validate_manifest(ok), ok)

    def test_null_needs_reason_even_without_scanner_status(self):
        # LR-27 (c): a null report with no scanner_status at all used to pass validation
        with self.assertRaisesRegex(ValueError, "grype is null with no scanner_status reason"):
            classify.validate_manifest({"scanner_reports": dict(self.FULL)})
        r = dict(self.FULL, grype="/g.json", trivy="/t.json", **{"osv-scanner": "/o.json", "osv-scanner-gomod": "/og.json"})
        with self.assertRaisesRegex(ValueError, "snyk is null with no scanner_status reason"):
            classify.validate_manifest({"scanner_reports": r, "scanner_status": {"grype": {"reason": "x"}}})


class ClassifyManifestGvc(unittest.TestCase):
    def test_dict_form_usable_only_when_complete_and_bound(self):
        g = {"path": "/g", "commit": "abc", "complete": True}
        self.assertEqual(classify.manifest_gvc({"govulncheck": g, "commit": "abc", "module": "m"}),
                         ("/g", "m", True))
        self.assertEqual(classify.manifest_gvc({"govulncheck": g, "commit": "zzz", "module": "m"}),
                         ("/g", "m", False))
        self.assertEqual(classify.manifest_gvc({"govulncheck": dict(g, complete=False), "commit": "abc"})[2],
                         False)
        self.assertEqual(classify.manifest_gvc({"govulncheck": dict(g, commit=None), "commit": None})[2],
                         False)
        self.assertEqual(classify.manifest_gvc({"govulncheck": dict(g, module="gm"), "commit": "abc",
                                                "module": "m"})[1], "gm")

    def test_bare_path_form(self):
        self.assertEqual(classify.manifest_gvc({"govulncheck": "/g", "module": "m"}), ("/g", "m", True))


class ClassifyDoManifest(TmpCase):
    PROPOSALS = {"CVE-2024-0001": "not_affected_unreachable",   # GO-1 imported only
                 "CVE-2024-0002": "not_affected_unreachable",   # no finding message
                 "CVE-2024-0003": "false_positive",             # no log row
                 "CVE-2024-0004": "false_positive"}             # log row present

    def _manifest(self, commit):
        def m(cve, alias, name):
            rel = [{"id": alias}] if alias else []
            return {"vulnerability": {"id": cve, "severity": "High", "fix": {"state": "not-fixed"}},
                    "artifact": {"purl": "pkg:golang/%s@v0.3.0" % name, "name": name},
                    "relatedVulnerabilities": rel}
        grype = self.put("grype.json", {"matches": [m("CVE-2024-0001", "GO-1", "text"),
                                                    m("CVE-2024-0002", None, "net"),
                                                    m("CVE-2024-0003", None, "a"),
                                                    m("CVE-2024-0004", None, "b")]})
        gv = self.put("gv.json", gv_stream([("GO-1", IMPORTED)]))
        log = self.put("log.json", {"defects": [{"disposition": "false_positive", "keys": [
            {"scanner": "grype", "finding_id": "CVE-2024-0004", "purl": "pkg:golang/b@v0.3.0"}]}]})
        down = {"reason": "not run in test"}
        return self.put("manifest-%s.json" % commit, {
            "module": "example.com/app", "commit": "c1", "known_defect_log": log,
            "govulncheck": {"path": gv, "commit": commit, "complete": True},
            "scanner_reports": {"grype": grype, "trivy": None, "osv-scanner": None,
                                "osv-scanner-gomod": None, "snyk": None},
            "scanner_status": {k: down for k in ("trivy", "osv-scanner", "osv-scanner-gomod", "snyk")}})

    def _run(self, commit):
        out = self.p("out-" + commit)
        calls = []

        def ask(adj, cid, *a, **k):
            calls.append((adj, cid))
            return {"category": self.PROPOSALS[cid]}
        with mock.patch.object(cli, "ask_model", side_effect=ask):
            classify.do_manifest(self._manifest(commit), "ADJ", out)
        self.assertEqual(sorted(calls), [("ADJ", c) for c in sorted(self.PROPOSALS)])
        cats = {f["id"]: f["category"] for f in json.load(open(os.path.join(out, "classification.json")))["findings"]}
        return out, cats

    def sidecar(self, out, cve):
        return json.load(open(os.path.join(out, "evidence", cve + ".evidence.json")))

    def vexstatus(self, out, cve):
        return json.load(open(os.path.join(out, "vex", cve + ".openvex.json")))["statements"][0]["status"]

    def test_bound_stream_verifies_only_what_it_proves(self):
        out, cats = self._run("c1")
        self.assertEqual(cats, {"CVE-2024-0001": "not_affected_unreachable",
                                "CVE-2024-0002": "under_investigation",
                                "CVE-2024-0003": "under_investigation",
                                "CVE-2024-0004": "false_positive"})
        self.assertEqual(self.vexstatus(out, "CVE-2024-0001"), "not_affected")
        self.assertEqual(self.vexstatus(out, "CVE-2024-0002"), "under_investigation")
        self.assertEqual(self.sidecar(out, "CVE-2024-0002")["evidence"],
                         {"reason": "no finding message for any id"})
        self.assertEqual(self.sidecar(out, "CVE-2024-0003")["evidence"],
                         {"reason": "no false-positive evidence"})
        self.assertFalse(os.path.exists(os.path.join(out, "ignores", "grype", "CVE-2024-0003.json")))
        self.assertTrue(os.path.exists(os.path.join(out, "ignores", "grype", "CVE-2024-0004.json")))
        self.assertEqual(json.load(open(os.path.join(out, "report-sections", "CVE-2024-0003.json"))),
                         {"sections": [4]})
        report = open(os.path.join(out, "report.md")).read()
        self.assertIn("## 4. Could not be assessed\nCVE-2024-0002\nCVE-2024-0003\n", report)

    def test_unbound_stream_cannot_prove_unreachable(self):
        out, cats = self._run("other-commit")
        self.assertEqual(cats["CVE-2024-0001"], "under_investigation")
        self.assertEqual(self.vexstatus(out, "CVE-2024-0001"), "under_investigation")
        self.assertEqual(self.sidecar(out, "CVE-2024-0001")["evidence"]["reason"],
                         "govulncheck stream not usable (incomplete or not bound to this candidate)")


class ClassifyRenderReport(TmpCase):
    def test_header_and_down_scanner_note(self):
        classify._render_report(self.d, {}, header="HEADER LINE\n", context={"down": "snyk"})
        lines = self.rt("report.md").split("\n")
        self.assertEqual(lines[:8], ["# Daily CVE auditor report", "", "## Conclusion", "",
                                     "stub: no narrative", "", "HEADER LINE", ""])
        note = " Not a complete assessment: snyk did not run."
        s3 = lines[lines.index("## 3. Actual vulnerabilities") + 1]
        s7 = lines[lines.index("## 7. Currently suppressed") + 1]
        s4 = lines[lines.index("## 4. Could not be assessed") + 1]
        self.assertTrue(s3.endswith(note) and s7.endswith(note))
        self.assertNotIn("Not a complete assessment", s4)

    def test_no_header_no_down(self):
        classify._render_report(self.d, {3: ["CVE-1"]})
        text = self.rt("report.md")
        self.assertNotIn("Not a complete assessment", text)
        self.assertIn("stub: no narrative\n\n## 1. Lifted", text)
        self.assertIn("## 3. Actual vulnerabilities\nCVE-1\n", text)


class ClassifyMain(TmpCase):
    def test_no_mode_exits(self):
        self.assertEqual(self.main_exit(classify, []),
                         "classify: need --manifest or --finding+--govulncheck")
        self.assertEqual(self.main_exit(classify, ["--finding", "GO-1", "--out", self.d]),
                         "classify: need --manifest or --finding+--govulncheck")

    def test_single_mode_routes(self):
        g = self.put("g.json", gv_stream([("GO-1", [])]))
        self.run_main(classify, ["--finding", "GO-1", "--govulncheck", g, "--out", self.d])
        self.assertEqual(self.rj("status", "GO-1.json"),
                         {"open": True, "reason": "only empty traces; not proof of unreachability"})


# --------------------------------------------------------------------------- poam
def vexfile(*stmts):
    return {"@context": "x", "statements": [
        {"vulnerability": {"name": n, "aliases": al}, "status": "affected"} for n, al in stmts]}


class PoamRemoveFromVex(TmpCase):
    def test_unparseable_and_no_statements(self):
        bad = self.put("bad.openvex.json", "{nope")
        self.assertFalse(poam._remove_from_vex(bad, {"CVE-1"}))
        self.assertEqual(self.rt("bad.openvex.json"), "{nope")
        nost = self.put("n.openvex.json", {"x": 1})
        self.assertFalse(poam._remove_from_vex(nost, {"CVE-1"}))
        self.assertEqual(self.rj("n.openvex.json"), {"x": 1})

    def test_no_match_leaves_file(self):
        f = self.put("v.openvex.json", vexfile(("CVE-2", [])))
        before = self.rt("v.openvex.json")
        self.assertFalse(poam._remove_from_vex(f, {"CVE-1"}))
        self.assertEqual(self.rt("v.openvex.json"), before)

    def test_surgical_by_alias_keeps_others(self):
        f = self.put("v.openvex.json", vexfile(("GHSA-x", ["CVE-1"]), ("CVE-2", [])))
        self.assertTrue(poam._remove_from_vex(f, {"CVE-1"}))
        d = self.rj("v.openvex.json")
        self.assertEqual([s["vulnerability"]["name"] for s in d["statements"]], ["CVE-2"])
        self.assertEqual(d["@context"], "x")

    def test_last_statement_removes_file(self):
        f = self.put("v.openvex.json", vexfile(("CVE-1", [])))
        self.assertTrue(poam._remove_from_vex(f, {"CVE-1"}))
        self.assertFalse(os.path.exists(f))


SNYK = ("version: v1.5.0\nignore:\n"
        "  CVE-2011-3374:\n    - '*':\n        reason: 'a'\n\n"
        "  'CVE-2011-33740':\n    - '*':\n        reason: 'b'\n"
        "  CVE-2099-9:\n    - '*':\n        reason: 'c'\n")


class PoamEditSnyk(TmpCase):
    def test_exact_key_removed_prefix_collision_survives(self):
        f = self.put(".snyk", SNYK)
        poam._edit_snyk(f, {"CVE-2011-3374", "CVE-2099-9"})
        self.assertEqual(self.rt(".snyk"),
                         "version: v1.5.0\nignore:\n  'CVE-2011-33740':\n    - '*':\n        reason: 'b'\n")

    def test_quoted_key_and_no_trailing_newline(self):
        f = self.put(".snyk", SNYK.rstrip("\n"))
        poam._edit_snyk(f, {"CVE-2011-33740"})
        text = self.rt(".snyk")
        self.assertFalse(text.endswith("\n"))
        self.assertNotIn("33740", text)
        self.assertIn("  CVE-2011-3374:\n", text)
        self.assertIn("  CVE-2099-9:", text)


class PoamRecheck(TmpCase):
    def _supp(self):
        s = "supp"
        self.put(s + "/.vex/a.openvex.json", vexfile(("CVE-1", []), ("CVE-2", [])))
        self.put(s + "/ignores/grype/CVE-1.json", {"id": "CVE-1"})
        self.put(s + "/ignores/grype/GHSA-1.json", {"id": "GHSA-1"})   # alias of CVE-1
        self.put(s + "/ignores/grype/CVE-2.json", {"id": "CVE-2"})
        self.put(s + "/ignores/broken.json", "{not json")
        self.put(s + "/.snyk", SNYK.replace("CVE-2011-3374:", "CVE-1:"))
        self.put(s + "/osv-scanner.toml", '# head\n[[IgnoredVulns]]\nid = "CVE-1"\n'
                 '[[IgnoredVulns]]\nid = "CVE-2"\n')
        return self.p(s)

    def test_expired_without_fix_removes_only_this_finding(self):
        supp = self._supp()
        pkg = self.put("pkg.json", {"cve": "CVE-1", "aliases": ["GHSA-1"], "ignore_expiry": "2026-09-01"})
        poam.recheck(pkg, supp, "2026-09-22", self.p("out"))
        r = self.rj("out", "recheck.json")
        self.assertEqual((r["ignore_removed"], r["returned_to_section"], r["policy_reapplied"], r["cve"]),
                         (True, 3, True, "CVE-1"))
        rel = sorted(os.path.relpath(x, supp) for x in r["removed_files"])
        self.assertEqual(rel, [".vex/a.openvex.json", "ignores/grype/CVE-1.json", "ignores/grype/GHSA-1.json"])
        self.assertTrue(os.path.exists(os.path.join(supp, "ignores/grype/CVE-2.json")))
        self.assertTrue(os.path.exists(os.path.join(supp, "ignores/broken.json")))
        v = json.load(open(os.path.join(supp, ".vex/a.openvex.json")))
        self.assertEqual([s["vulnerability"]["name"] for s in v["statements"]], ["CVE-2"])
        snyk = open(os.path.join(supp, ".snyk")).read()
        self.assertNotIn("CVE-1:", snyk)
        self.assertIn("CVE-2011-33740", snyk)
        self.assertEqual(open(os.path.join(supp, "osv-scanner.toml")).read(),
                         '# head\n[[IgnoredVulns]]\nid = "CVE-2"\n')

    def test_not_expired_or_fixed_stays_active(self):
        supp = self._supp()
        for i, pkgd in enumerate(({"cve": "CVE-1", "ignore_expiry": "2026-10-22"},
                                  {"cve": "CVE-1", "ignore_expiry": "2026-09-01", "fix_available": True})):
            out = self.p("out%d" % i)
            poam.recheck(self.put("pkg%d.json" % i, pkgd), supp, "2026-09-22", out)
            self.assertEqual(json.load(open(os.path.join(out, "recheck.json"))),
                             {"ignore_removed": False, "returned_to_section": None, "policy_reapplied": False})
            self.assertEqual(json.load(open(os.path.join(out, "ignores", "still-active.json"))), pkgd)
        self.assertTrue(os.path.exists(os.path.join(supp, "ignores/grype/CVE-1.json")))


class PoamAcceptGuard(TmpCase):
    def test_not_reachable_no_fix_is_refused(self):
        for i, f in enumerate(({"cve": "CVE-1", "reachable": False, "fix_pullable": False},
                               {"cve": "CVE-1", "reachable": True, "fix_pullable": True})):
            out = self.p("o%d" % i)
            poam.accept(self.put("f%d.json" % i, f), None, None, None, "2026-09-22", out)
            self.assertEqual(os.listdir(out), ["decision.json"])
            self.assertEqual(json.load(open(os.path.join(out, "decision.json"))),
                             {"accepted": False, "reason": "not a reachable-no-fix item"})


# --------------------------------------------------------------------------- release-authz
class AuthzHelpers(TmpCase):
    def test_valid_future(self):
        self.assertFalse(authz._valid_future("2026-02-30", "2026-01-01"))   # not a real date
        self.assertFalse(authz._valid_future("2026-09-22", "2026-09-22"))
        self.assertTrue(authz._valid_future("2026-09-23", "2026-09-22"))

    def test_acceptance_latest_owner_comment_wins(self):
        def iss(*bodies, number=7, author="own"):
            return {"issues": [{"number": 99, "comments": [{"author": "own", "body": "ACCEPT CVE-1 until 2027-01-01"}]},
                               {"number": number, "comments": [{"author": author, "body": b} for b in bodies]}]}
        acc, rej = "ACCEPT CVE-1 until 2027-01-01\nwhy", "REJECT CVE-1 no"
        self.assertTrue(authz.acceptance_verdict(iss(acc), "own", 7, "CVE-1", "2026-09-22"))
        self.assertFalse(authz.acceptance_verdict(iss(acc, rej), "own", 7, "CVE-1", "2026-09-22"))
        self.assertFalse(authz.acceptance_verdict(iss(acc, "DO NOT ACCEPT CVE-1"), "own", 7, "CVE-1", "2026-09-22"))
        self.assertTrue(authz.acceptance_verdict(iss(rej, acc), "own", 7, "CVE-1", "2026-09-22"))
        self.assertFalse(authz.acceptance_verdict(iss(acc, "REJECT CVE-2"), "own", 7, "CVE-2", "2026-09-22"))
        self.assertTrue(authz.acceptance_verdict(iss(acc, "REJECT CVE-2"), "own", 7, "CVE-1", "2026-09-22"))
        # issue 99's acceptance does not count for issue 8; non-owner comments are ignored
        self.assertFalse(authz.acceptance_verdict(iss(acc, number=8), "own", 7, "CVE-1", "2026-09-22"))
        self.assertFalse(authz.acceptance_verdict(iss(acc, author="x"), "own", 7, "CVE-1", "2026-09-22"))

    def test_affected_cves(self):
        self.assertEqual(authz.affected_cves(None), (set(), []))
        self.put("v/a.json", {"statements": [
            {"status": "affected", "vulnerability": {"name": "CVE-1"}},
            {"status": "affected", "vulnerability": {}},
            {"status": "not_affected", "vulnerability": {"name": "CVE-2"}}]})
        self.put("v/b.json", {"statements": [{"status": "affected", "vulnerability": {"name": "CVE-3"}}]})
        self.put("v/ignored.txt", "garbage")
        self.assertEqual(authz.affected_cves(self.p("v")), ({"CVE-1", "CVE-3"}, []))
        self.put("v/bad.json", "{x")
        cves, bad = authz.affected_cves(self.p("v"))
        self.assertEqual(cves, {"CVE-1", "CVE-3"})
        self.assertEqual(len(bad), 1)
        self.assertTrue(bad[0].startswith("bad.json ("))


class AuthzMain(TmpCase):
    def decide(self, cand=None, issues=None, vex=None):
        args = ["--out", self.p("decision.json"), "--today", "2026-09-22", "--owner", "own"]
        if vex is not None:
            for i, stmts in enumerate(vex):
                self.put("vex/%d.json" % i, stmts)
            args += ["--vex-dir", self.p("vex")]
        if cand is not None:
            args += ["--candidate", self.put("cand.json", cand)]
        if issues is not None:
            args += ["--issues", self.put("issues.json", issues)]
        self.run_main(authz, args)
        return self.rj("decision.json")

    AFF = [{"statements": [{"status": "affected", "vulnerability": {"name": "CVE-1"}}]}]

    def test_malformed_vex_holds(self):
        r = self.decide(vex=["{broken"])
        self.assertEqual(r["decision"], "hold")
        self.assertTrue(r["reasons"][0].startswith("malformed candidate VEX: 0.json ("))

    def test_no_inventory(self):
        self.assertEqual(self.decide(vex=self.AFF),
                         {"decision": "hold", "reasons": ["affected VEX but no inventory (fail closed)"]})
        self.assertEqual(self.decide(), {"decision": "promote", "reasons": []})

    def test_no_accepted_items_field(self):
        self.assertEqual(self.decide(cand={}),
                         {"decision": "hold", "reasons": ["no accepted_items field (fail closed)"]})

    def test_completeness(self):
        self.assertEqual(self.decide(cand={"accepted_items": []}, vex=self.AFF),
                         {"decision": "hold", "reasons": ["affected CVE-1 not in the candidate inventory"]})
        r = self.decide(cand={"accepted_items": [{"cve": "CVE-1", "threshold": "at_or_above"}]}, vex=self.AFF)
        self.assertEqual(r["decision"], "hold")
        self.assertEqual(r["reasons"], ["affected at-or-above CVE-1 has no owner-decision issue",
                                        "no current owner acceptance for CVE-1"])
        self.assertEqual(self.decide(cand={"accepted_items": [{"cve": "CVE-1", "threshold": "below"}]},
                                     vex=self.AFF),
                         {"decision": "promote", "reasons": []})

    def test_item_shape(self):
        r = self.decide(cand={"accepted_items": [{"cve": "CVE-1"}, {"threshold": "below"},
                                                 {"cve": "CVE-2", "threshold": "medium"}]})
        self.assertEqual(r, {"decision": "hold", "reasons": [
            "item missing cve/threshold (fail closed)", "item missing cve/threshold (fail closed)",
            "unknown threshold 'medium'"]})

    def test_owner_acceptance_promotes(self):
        cand = {"accepted_items": [{"cve": "CVE-1", "threshold": "at_or_above", "owner_issue": 5}]}
        issues = {"issues": [{"number": 5, "comments": [{"author": "own", "body": "ACCEPT CVE-1 until 2026-12-01"}]}]}
        self.assertEqual(self.decide(cand=cand, issues=issues, vex=self.AFF), {"decision": "promote", "reasons": []})
        expired = {"issues": [{"number": 5, "comments": [{"author": "own", "body": "ACCEPT CVE-1 until 2026-09-01"}]}]}
        self.assertEqual(self.decide(cand=cand, issues=expired, vex=self.AFF),
                         {"decision": "hold", "reasons": ["no current owner acceptance for CVE-1"]})


# --------------------------------------------------------------------------- suppress
class SuppressMain(TmpCase):
    PURLS = {"grype": "pkg:golang/golang.org/x/text@v0.3.0"}

    def disp(self, **kw):
        d = {"cve": "CVE-2020-14040", "status": "not_affected", "justification": "vulnerable_code_not_present",
             "aliases": ["GO-2020-0015"], "purls": dict(self.PURLS),
             "evidence": {"check": "known-defect-log", "source_file": self.p("log.json"), "detail": "d"}}
        d.update(kw)
        return self.put("disp.json", d)

    def go(self, **kw):
        return ["--disposition", self.disp(**kw), "--out", self.p("out"), "--today", "2026-09-22"]

    def ev(self, check, src):
        return {"check": check, "source_file": src, "detail": "d"}

    def assert_nothing_written(self):
        self.assertFalse(os.path.exists(self.p("out")))

    def test_invalid_status(self):
        self.assertEqual(self.main_exit(suppress, self.go(status="fixed")), "suppress: invalid status")
        self.assert_nothing_written()

    def test_evidence_shape(self):
        msg = "suppress: evidence must be an object with check, source_file, detail"
        self.assertEqual(self.main_exit(suppress, self.go(evidence="see log")), msg)
        self.assertEqual(self.main_exit(suppress, self.go(evidence={"check": "x", "source_file": "y"})), msg)
        self.assert_nothing_written()

    def test_missing_source_file(self):
        src = self.p("does-not-exist.json")
        self.assertEqual(self.main_exit(suppress, self.go(evidence=self.ev("known-defect-log", src))),
                         "suppress: evidence source_file %r does not exist — refusing" % src)
        self.assert_nothing_written()

    def test_unreadable_log(self):
        self.put("log.json", "{not json")
        code = self.main_exit(suppress, self.go())
        self.assertTrue(code.startswith("suppress: cannot read known-defect log %s: " % self.p("log.json")))
        self.assert_nothing_written()

    def test_log_row_must_be_fp_for_this_package(self):
        key = [{"finding_id": "GO-2020-0015"}]
        self.put("log.json", {"defects": [
            {"disposition": "real", "package": "text", "keys": key},              # not a false positive
            {"disposition": "false_positive", "package": "text", "keys": [{"finding_id": "CVE-9"}]},  # other CVE
            {"disposition": "false_positive", "package": "zlib", "keys": key}]})  # other package
        self.assertEqual(self.main_exit(suppress, self.go()),
                         "suppress: no false_positive log row for CVE-2020-14040 on package(s) ['text'] — refusing")
        self.assert_nothing_written()
        self.put("log.json", {"defects": [{"disposition": "false_positive", "package": "text", "keys": key}]})
        self.run_main(suppress, self.go())
        st = self.rj("out", ".vex", "fosterstack-cache.openvex.json")["statements"][0]
        self.assertEqual(st["status"], "not_affected")
        self.assertEqual(st["products"][0]["subcomponents"], [{"@id": self.PURLS["grype"]}])

    def test_govulncheck_unparseable(self):
        src = self.put("gv.json", "")
        code = self.main_exit(suppress, self.go(evidence=self.ev("govulncheck", src)))
        self.assertTrue(code.startswith("suppress: cannot parse govulncheck stream %s: " % src))
        self.assert_nothing_written()

    def test_govulncheck_must_show_imported_not_called(self):
        refuse = "suppress: govulncheck does not show CVE-2020-14040 imported-but-not-called — refusing"
        for i, findings in enumerate(([("GO-OTHER", IMPORTED)],                      # not present
                                      [("GO-2020-0015", IMPORTED), ("GO-2020-0015", CALLED)],  # reachable
                                      [("GO-2020-0015", [])])):                      # empty trace only
            src = self.put("gv%d.json" % i, gv_stream(findings))
            self.assertEqual(self.main_exit(suppress, self.go(evidence=self.ev("reachability", src))), refuse)
            self.assert_nothing_written()
        src = self.put("ok.json", gv_stream([("GO-2020-0015", IMPORTED)]))
        self.run_main(suppress, self.go(evidence=self.ev("govulncheck", src)))
        side = self.rj("out", "evidence", "CVE-2020-14040.evidence.json")
        self.assertEqual(side["evidence"]["source_file"], src)
        self.assertEqual(side["scoped_purls"], [self.PURLS["grype"]])
        self.assertIn('id = "CVE-2020-14040"', self.rt("out", "osv-scanner.toml"))
        self.assertIn("  CVE-2020-14040:\n", self.rt("out", ".snyk"))

    def test_unknown_check(self):
        src = self.put("x.json", "{}")
        self.assertEqual(self.main_exit(suppress, self.go(evidence=self.ev("vibes", src))),
                         "suppress: unknown evidence check 'vibes' — refusing")
        self.assert_nothing_written()


class SuppressPackageBoundary(unittest.TestCase):
    """A known-defect row for one package never verifies a disposition on another: `ssl` must
    not clear `openssl` (a substring match did — found while covering REQ-AUD-18 AC2)."""

    def _verify(self, rowpkg, purl):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        log = os.path.join(d, "log.json")
        with open(log, "w") as fh:
            json.dump({"defects": [{"disposition": "false_positive", "package": rowpkg,
                                    "keys": [{"finding_id": "CVE-2024-9999"}]}]}, fh)
        ev = {"check": "known-defect-log", "source_file": log, "detail": "x"}
        return suppress._verify("CVE-2024-9999", [], {"grype": purl}, ev)

    def test_substring_package_is_refused(self):
        for rowpkg in ("ssl", "deb", "golang.org/x/tex"):
            purl = "pkg:golang/golang.org/x/text@v0.3.0" if "/" in rowpkg else "pkg:deb/debian/openssl@3.0.11-1"
            with self.assertRaises(SystemExit) as cm:
                self._verify(rowpkg, purl)
            self.assertIn("no false_positive log row", str(cm.exception))

    def test_exact_short_full_and_in_module_names_verify(self):
        for rowpkg, purl in (("openssl", "pkg:deb/debian/openssl@3.0.11-1"),
                             ("example.org/lib", "pkg:golang/example.org/lib@v1"),
                             ("golang.org/x/text/language", "pkg:golang/golang.org/x/text@v0.3.0")):
            self.assertIsNone(self._verify(rowpkg, purl))


if __name__ == "__main__":
    unittest.main()
