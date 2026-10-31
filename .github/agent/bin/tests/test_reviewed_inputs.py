"""rc-5b fix 13 (Fable ruling of cache#701): every reviewed or run-written JSON input the auditor reads is read through ONE required-content reader
(auditorlib/reviewed.py): a PRESENT file must be a JSON object that carries its required key(s) with the right shape; {} and a missing key are a stop, never "nothing".
An ABSENT file stays the first run. The readers of the release gate and the consistency check use the same reader.

No network; every file lives in a temp dir."""
import contextlib, importlib.util, io, json, os, re, subprocess, sys, tempfile, unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import reviewed  # noqa: E402


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BIN, fname))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


R = _load("auditor_run_reviewed", "auditor-run.py")
PANEL = _load("auditor_panel_reviewed", "auditor-panel.py")

# one entry per reviewed-input file name the agent reads: (a sample file name, the required keys, a valid document, documents that must stop)
FILES = [
    ("fosterstack-cache.openvex.json", ("statements",), {"statements": []}, [{}, {"statements": None}, {"statements": {}}, {"statements": "x"}, {"statements": [None]}, {"statements": [3]}, {"other": []}, [], "x"]),
    ("CVE-2099-1.openvex.json", ("statements",), {"statements": [{"a": 1}]}, [{}, {"statements": None}, {"other": []}]),
    ("accepted-items.json", ("accepted_items",), {"accepted_items": []}, [{}, {"accepted_items": None}, {"accepted_items": {}}, {"accepted_items": [None]}, {"accepted_items": ["x"]}, {"other": []}, []]),
    ("reopened-expired.json", ("reopened",), {"reopened": []}, [{}, {"reopened": None}, {"reopened": {}}, {"reopened": "x"}, {"reopened": [None]}, {"other": []}, []]),
    ("consistency.json", ("problems", "consistent"), {"consistent": True, "problems": []}, [{}, {"problems": []}, {"consistent": True}, {"consistent": True, "problems": None}, {"consistent": "yes", "problems": []}, {"consistent": True, "problems": [3]}, []]),
    ("panel-state.json", ("version", "false", "real", "debates", "scores", "seat"),
     {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"},
     [{}, [], None, {"version": 1}, {"version": 2, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"},
      {"version": 1, "false": None, "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"},
      {"version": 1, "false": [], "real": [3], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"},
      {"version": 1, "false": [], "real": [], "debates": {}, "scores": {"A": 0, "B": 0}, "seat": "A"},
      {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0}, "seat": "A"},
      {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": "0", "B": 0}, "seat": "A"},
      {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0, "C": 1}, "seat": "A"},
      {"version": 1, "false": [], "real": [], "debates": [], "scores": [0, 0], "seat": "A"},
      {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "C"},
      {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}}]),
    ("scanner-profiles.json", ("entries",), {"entries": []},
     [{}, [], None, {"entries": None}, {"entries": {}}, {"entries": [None]}, {"comment": ["x"]}]),
    ("known-defect-log.json", ("defects",), {"defects": []}, [{}, {"defects": None}, {"defects": {}}, {"defects": [None]}, {"other": []}, []]),
]

# every other *.json file name that appears as a string literal in the agent's programs, and why it is not a reviewed input read through the reader
_RUN_INTERNAL = "written and read inside one run (a derived, run-internal file), not a reviewed input"
EXEMPT = {n: _RUN_INTERNAL for n in (
    "reconcile.json", "recheck.json", "index.json", "state.json", "notify.json", "decision.json", "day.json", "classification.json", "adjudicator-proposals.json", ".evidence.json",
    "votes.json", "verdict.json", "triggers.json", "syft.json", "stop.json", "still-present.json", "still-active.json", "scanner-calls.json", "run-state.json", "rule0.json",
    "result.json", "refusal-log.json", "probe.json", "pr.json", "plan.json", "parity.json", "package.json", "note.json", "leak.json", "govulncheck.json", "consumed.json",
    "budget.json", "adjudication.json", "accepted-item.json", ".status.json", ".json", "*.json")}
_SWEEP_FILE = ("a file of the records sweep (auditor-vendor-records.py): made and read by "
    "bin/vendor-provenance*.py inside one sweep run, not an input of the "
    "auditor")
for _n in ("dependency-provenance.json", "licenses.json", "origins.json", "provenance.json", "sumdb.json"):
    EXEMPT[_n] = _SWEEP_FILE
EXEMPT["openvex-schema.json"] = "the JSON schema the VEX documents are validated against: a checked-in constant, not an input of a run"
EXEMPT["auditor-state.json"] = "the no-change-day state kept between runs: read by auditorlib/nochange.py with its own strict loader (regular file, size cap, strict JSON, schema fosterstack/auditor-state/v1 checked by _valid); anything unusable is None, i.e. the model is asked again, never a skipped decision"

# every json.load( / json.loads( in the agent programs outside auditorlib/reviewed.py: the file and how many, with the reason it is not a reviewed input read through the reader
_SITES = {
    "auditor-adjudicate.py": (1, "the scenario file of a probe, written by the caller"),
    "auditor-build-parity.py": (1, "run-state.json written earlier in the same run"),
    "auditor-adjudicator-client.py": (3, "the model client's own protocol lines on stdin and the model's reply"),
    "auditor-classify.py": (2, "the run's manifest (validated by validate_manifest) and the manifest's module name"),
    "auditor-consistency.py": (1, "the run's manifest naming the panel verdict"),
    "auditor-layout-check.py": (1, "a syntax check of the files under .github/agent/"),
    "auditor-consume-rescan.py": (1, "run-state.json written earlier in the same run"),
    "auditor-defectlog.py": (2, "the findings file and the manifest, both written by the same run"),
    "auditor-notify.py": (1, "the finding file written earlier in the same run"),
    "auditor-recheck.py": (1, "the disposition file written earlier in the same run"),
    "auditor-manifest.py": (3, "the scanned image's files and a registry reply, validated by the manifest builder"),
    "auditor-run.py": (3, "the known-defect log's own parse (after reviewed.present) and the gh issue list replies"),
    "auditor-poam.py": (2, "the package and the finding files written earlier in the same run"),
    "auditor-votes.py": (1, "the run's manifest"),
    "auditor-panel.py": (9, "registry and scanner-database replies, image blobs, the PR files (parsed by _checked_doc / _checked_state_text and then checked with the shared rules) and the panel's own run files; the persistent state and profiles are read through the shared reader with the panel's own SPECS (cmd_judge)"),
    "auditor-release-authz.py": (1, "the owner-issues list the run fetched with gh"),
    "auditor-report.py": (1, "run-state.json written earlier in the same run"),
    "auditor-suppress.py": (1, "the disposition file written earlier in the same run"),
    "auditor-vex-scope-check.py": (1, "a candidate VEX document: an empty one fails closed (no products, all_scoped false, nothing re-emitted)"),
    "auditorlib/nochange.py": (2, "the no-change-day state, read twice: load (verdict reuse) and load_unsettled (the unsettled-run counts), each its own strict loader; an unusable file is no state, a right-schema file with untrustworthy counts stops the run (see EXEMPT auditor-state.json)"),
    "auditorlib/parsers.py": (2, "the scanners' own reports"),
    "auditorlib/vex.py": (1, "the checked-in VEX schema"),
    "auditorlib/cli.py": (1, "the model client's reply"),
    "auditorlib/signed_commit.py": (1, "the GitHub API reply"),
    "auditorlib/vendor_records.py": (1, "the base commit's reviewed licences file, read from git by the records sweep"),
}


def rd(path, name):
    """read `path` as the file called `name`: the table of the library, or the scanner panel's own rules"""
    return reviewed.read(path, spec=PANEL.SPECS.get(name))


class TheTable(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def write(self, name, doc):
        p = os.path.join(self.d, name)
        with open(p, "w") as fh:
            json.dump(doc, fh)
        return p

    def test_every_reviewed_file_stops_on_empty_and_on_a_missing_or_mis_shaped_key(self):
        for name, keys, good, bads in FILES:
            for bad in bads:
                with self.assertRaises(reviewed.ReviewedInputInvalid, msg=repr((name, bad))):
                    rd(self.write(name, bad), name)
            self.assertEqual(rd(self.write(name, good), name), good, name)

    def test_an_absent_file_is_none_and_a_non_json_or_unlookable_one_is_a_stop(self):
        for name, *_ in FILES:
            self.assertIsNone(rd(os.path.join(self.d, "absent", name), name), name)
            p = os.path.join(self.d, name)
            with open(p, "w") as fh:
                fh.write("{not json")
            with self.assertRaises(reviewed.ReviewedInputInvalid):
                rd(p, name)

    def test_the_table_names_exactly_the_reviewed_files_and_their_required_keys(self):
        for name, keys, *_ in FILES:
            self.assertEqual(tuple(k for k, _ in (PANEL.SPECS.get(name) or reviewed.spec_for(name))), keys, name)
        self.assertEqual(reviewed.spec_for("run-state.json"), ())
        self.assertEqual(reviewed.spec_for("whatever.openvex.json")[0][0], "statements")

    def test_the_panel_scores_may_be_negative_integers_because_a_wrong_vote_costs_two_points(self):
        # rule 13 scoring is +1 / -2 per vendor seat: a state the panel itself wrote carries negative scores and must pass the reader the next day
        good = {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": -4, "B": 3}, "seat": "B"}
        self.assertEqual(rd(self.write("panel-state.json", good), "panel-state.json"), good)
        for bad in (1.5, "1", True, None):
            with self.assertRaises(reviewed.ReviewedInputInvalid, msg=repr(bad)):
                rd(self.write("panel-state.json", dict(good, scores={"A": bad, "B": 0})), "panel-state.json")

    def test_a_file_can_be_read_under_the_rules_of_another_name(self):
        p = self.write("CVE-2099-1.json", {})                       # the release gate's per-finding files carry no openvex in their name
        self.assertEqual(reviewed.read(p), {})
        with self.assertRaises(reviewed.ReviewedInputInvalid):
            reviewed.read(p, as_name="x.openvex.json")

    def test_every_json_file_name_the_agent_programs_mention_is_reviewed_or_declared_exempt(self):
        seen = set()
        for fn in sorted(os.listdir(BIN)) + ["auditorlib/" + f for f in sorted(os.listdir(os.path.join(BIN, "auditorlib")))]:
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(BIN, fn)) as fh:
                src = fh.read()
            for lit in re.findall(r"[\"']([A-Za-z0-9_./*-]*\.json)[\"']", src):
                seen.add(os.path.basename(lit) or lit)
        undecided = sorted(n for n in seen if not reviewed.spec_for(n) and n not in PANEL.SPECS and n not in EXEMPT)
        self.assertEqual(undecided, [], "a new json file name: add it to the table of auditorlib/reviewed.py (a reviewed input) or to EXEMPT here with its reason")


class TheReadSites(unittest.TestCase):
    def test_every_json_load_outside_the_reader_is_declared_with_its_reason(self):
        found = {}
        for fn in sorted(os.listdir(BIN)) + ["auditorlib/" + f for f in sorted(os.listdir(os.path.join(BIN, "auditorlib")))]:
            if not fn.endswith(".py") or fn == "auditorlib/reviewed.py" or not (fn.startswith("auditor")):      # the auditor's programs and library (check-action-pins.py is a CI checker of its own)
                continue
            with open(os.path.join(BIN, fn)) as fh:
                n = len(re.findall(r"\bjson\.loads?\(", fh.read()))
            if n:
                found[fn] = n
        self.assertEqual(found, {k: v[0] for k, v in _SITES.items()}, "a json.load outside auditorlib/reviewed.py: read the file through reviewed.read, or declare it in _SITES with the reason it is not a reviewed input")

    def test_every_caller_of_the_panels_plain_json_helper_is_declared_with_its_reason(self):
        # _load_json is the panel's PLAIN reader (a missing file is its default): a call that reads a reviewed or persistent input must go through reviewed.read instead
        with open(os.path.join(BIN, "auditor-panel.py")) as fh:
            src = fh.read()
        declared = {
            "path, default=None": "the definition",
            "path": "rescan_binding: the rescan binding file the workflow step wrote for this run; checked field by field right after (run, heads, conclusion), not a reviewed input",
            'os.path.join(a.out, "state.json")': "cmd_deliver: the judgment's own output of this run (written by cmd_judge from a validated state)",
            'os.path.join(a.out, "day.json")': "cmd_deliver: the judgment's own output of this run",
        }
        sites = re.findall(r"_load_json\(((?:[^()]|\([^()]*\))*)\)", src)
        self.assertEqual(sorted(s.strip() for s in sites), sorted(declared), "a new _load_json call: read persistent or reviewed inputs through reviewed.read, or declare the site here with its reason")

    def test_a_vex_is_recognised_by_its_suffix_only(self):
        self.assertTrue(reviewed.spec_for("a.openvex.json"))
        self.assertEqual(reviewed.spec_for("openvex-schema.json"), ())
        self.assertEqual(reviewed.spec_for("my-openvex-notes.json"), ())


class TheReaders(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def w(self, name, doc):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        json.dump(doc, open(p, "w"))
        return p

    def run_py(self, script, *args):
        return subprocess.run([sys.executable, os.path.join(BIN, script), *args], capture_output=True, text=True)

    def test_reopened_without_its_key_stops(self):
        for bad in ({}, {"other": []}, {"reopened": None}):
            with self.assertRaises(R.ReviewedInputInvalid, msg=repr(bad)):
                R._read_reopened(self.w("reopened-expired.json", bad))
        self.assertEqual(R._read_reopened(self.w("ok/reopened-expired.json", {"reopened": []})), [])
        self.assertEqual(R._read_reopened(os.path.join(self.d, "none.json")), [])

    def test_the_release_gate_holds_on_an_empty_or_keyless_vex(self):
        for bad in ({}, {"statements": None}, {"other": 1}):
            vd = os.path.join(self.d, "vex"); os.makedirs(vd, exist_ok=True)
            for f in os.listdir(vd):
                os.remove(os.path.join(vd, f))
            self.w("vex/CVE-2099-1.openvex.json", bad)
            out = os.path.join(self.d, "authz.json")
            r = self.run_py("auditor-release-authz.py", "--vex-dir", vd, "--out", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            got = json.load(open(out))
            self.assertEqual(got["decision"], "hold", bad)
            self.assertIn("malformed candidate VEX", got["reasons"][0])
        for f in os.listdir(vd):
            os.remove(os.path.join(vd, f))
        self.w("vex/CVE-2099-1.openvex.json", {"statements": []})
        r = self.run_py("auditor-release-authz.py", "--vex-dir", vd, "--out", out)
        self.assertEqual(json.load(open(out)), {"decision": "promote", "reasons": []})

    def test_the_consistency_check_exits_non_zero_on_an_empty_or_keyless_vex(self):
        man = self.w("manifest.json", {"panel": {}})
        for bad in ({}, {"statements": None}):
            self.w("supp/fosterstack-cache.openvex.json", bad)
            out = os.path.join(self.d, "consistency.json")
            if os.path.exists(out):
                os.remove(out)
            r = self.run_py("auditor-consistency.py", "--suppression-dir", os.path.join(self.d, "supp"), "--live-findings", man, "--out", out)
            self.assertNotEqual(r.returncode, 0, bad)
            self.assertFalse(os.path.exists(out))
        self.w("supp/fosterstack-cache.openvex.json", {"statements": []})
        r = self.run_py("auditor-consistency.py", "--suppression-dir", os.path.join(self.d, "supp"), "--live-findings", man, "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.load(open(out)), {"consistent": True, "problems": []})

    def test_a_consistency_result_without_problems_or_consistent_is_a_failed_check_not_a_clean_one(self):
        for bad in ({}, {"problems": []}, {"consistent": True}):
            out = os.path.join(self.d, "out"); os.makedirs(out, exist_ok=True)
            res = subprocess.CompletedProcess([], 0, "", "")
            def fake(cmd, *a, **k):
                json.dump(bad, open(os.path.join(out, "consistency.json"), "w")); return res
            with unittest_patch(R.subprocess, "run", fake):
                got = R._consistency(out, os.path.join(self.d, "supp"), os.path.join(self.d, "m.json"))
            self.assertEqual(got["problems"][0]["type"], "consistency-check-error", bad)
        with unittest_patch(R.subprocess, "run", lambda *a, **k: (json.dump({"consistent": True, "problems": []}, open(os.path.join(out, "consistency.json"), "w")), res)[1]):
            self.assertEqual(R._consistency(out, "s", "m"), {"consistent": True, "problems": []})

    def test_a_known_defect_log_without_defects_stops_in_every_reader(self):
        for bad in ({}, {"defects": None}, {"other": []}):
            p = self.w("known-defect-log.json", bad)
            with self.assertRaises(R.DefectLogInvalid, msg=repr(bad)):
                R.load_defect_log(p)
            cl = _load("auditor_classify_reviewed", "auditor-classify.py")
            with self.assertRaises(reviewed.ReviewedInputInvalid, msg=repr(bad)):
                cl.fp_verified(["CVE-1"], p, [])
            r = self.run_py("auditor-knowledge.py", "generate", "--log", p)
            self.assertNotEqual(r.returncode, 0, bad)
        p = self.w("ok/known-defect-log.json", {"defects": []})
        self.assertEqual(R.load_defect_log(p), {"defects": []})
        self.assertEqual(R.load_defect_log(os.path.join(self.d, "none.json")), {})


class TheClosedGuards(unittest.TestCase):
    """cache#701 round 2: the reader owns existence (lstat); the readers' own exists() guards, glob and bare json.load are gone."""
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def w(self, name, doc):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        json.dump(doc, open(p, "w"))
        return p

    def run_py(self, script, *args):
        return subprocess.run([sys.executable, os.path.join(BIN, script), *args], capture_output=True, text=True)

    def unreadable(self, path):
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o755)

    def test_a_dangling_symlink_or_an_unreachable_log_is_present_and_stops_not_absent(self):
        link = os.path.join(self.d, "known-defect-log.json"); os.symlink(os.path.join(self.d, "nowhere"), link)
        cl = _load("auditor_classify_closed", "auditor-classify.py")
        with self.assertRaises(R.DefectLogInvalid):
            R.load_defect_log(link)
        with self.assertRaises(reviewed.ReviewedInputInvalid):
            cl.fp_verified(["CVE-1"], link, [])
        if os.geteuid() != 0:
            sub = os.path.join(self.d, "sub"); os.makedirs(sub)
            p = self.w("sub/known-defect-log.json", {"defects": []}); self.unreadable(sub)
            with self.assertRaises(R.DefectLogInvalid):
                R.load_defect_log(p)
            with self.assertRaises(reviewed.ReviewedInputInvalid):
                cl.fp_verified(["CVE-1"], p, [])
        self.assertEqual(R.load_defect_log(os.path.join(self.d, "none.json")), {})
        self.assertIsNone(cl.fp_verified(["CVE-1"], os.path.join(self.d, "none.json"), []))
        self.assertIsNone(cl.fp_verified(["CVE-1"], None, []))

    def authz(self, *args):
        out = os.path.join(self.d, "authz.json")
        if os.path.exists(out):
            os.remove(out)
        r = self.run_py("auditor-release-authz.py", "--out", out, *args)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.load(open(out))

    def test_the_release_gate_holds_when_it_cannot_enumerate_or_read_what_it_judges(self):
        vd = os.path.join(self.d, "vex"); os.makedirs(vd)
        self.w("vex/CVE-2099-1.openvex.json", {"statements": [{"status": "affected", "vulnerability": {"name": "CVE-2099-1"}}]})
        if os.geteuid() != 0:
            self.unreadable(vd)
            got = self.authz("--vex-dir", vd)
            self.assertEqual(got["decision"], "hold", got)
            self.assertIn("malformed candidate VEX", got["reasons"][0])
            os.chmod(vd, 0o755)
        afile = self.w("afile", {})
        got = self.authz("--vex-dir", afile)                                    # a path that exists and is not a directory
        self.assertEqual(got["decision"], "hold", got)
        os.symlink(os.path.join(self.d, "nowhere"), os.path.join(self.d, "dangling"))
        self.assertEqual(self.authz("--vex-dir", os.path.join(self.d, "dangling"))["decision"], "hold")
        self.assertEqual(self.authz("--vex-dir", os.path.join(self.d, "absent-dir")), {"decision": "promote", "reasons": []})      # only a truly absent directory means no VEX
        self.assertEqual(self.authz(), {"decision": "promote", "reasons": []})

    def test_the_release_gate_judges_only_the_vex_files_of_its_directory(self):
        vd = os.path.join(self.d, "vexonly"); os.makedirs(vd)
        self.w("vexonly/still-present.json", {})                      # a disposition the run writes beside the VEX files, and a note: not VEX documents
        self.w("vexonly/note.json", {})
        self.assertEqual(self.authz("--vex-dir", vd), {"decision": "promote", "reasons": []})
        self.w("vexonly/a.openvex.json", {})                         # a VEX file without its list is still a hold
        self.assertEqual(self.authz("--vex-dir", vd)["decision"], "hold")

    def test_the_release_gate_reads_its_candidate_inventory_under_the_inventory_rules(self):
        for bad in ({"accepted_items": {}}, {"accepted_items": ""}, {"accepted_items": None}, {}, {"accepted_items": [3]}):
            got = self.authz("--candidate", self.w("cand.json", bad))
            self.assertEqual(got["decision"], "hold", bad)
            self.assertIn("malformed candidate inventory", got["reasons"][0])
        got = self.authz("--candidate", self.w("cand2.json", {"accepted_items": []}))
        self.assertEqual(got, {"decision": "promote", "reasons": []})

    def test_the_defect_log_tool_stops_on_an_empty_or_keyless_log(self):
        for sub in (["probe", "--hit", "s", "f", "p"], ["run", "--findings", self.w("fnd.json", {"findings": []}), "--adjudicator", "none"], ["reconcile", "--finding", "s", "f", "p", "--adjudicator", "none"]):
            for bad in ({}, {"defects": None}):
                p = self.w("known-defect-log.json", bad)
                r = self.run_py("auditor-defectlog.py", *sub, "--log", p, "--out", os.path.join(self.d, "o"))
                self.assertNotEqual(r.returncode, 0, (sub[0], bad))
        p = self.w("ok/known-defect-log.json", {"defects": []})
        r = self.run_py("auditor-defectlog.py", "probe", "--hit", "s", "f", "p", "--log", p, "--out", os.path.join(self.d, "o2"))
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_py("auditor-defectlog.py", "probe", "--hit", "s", "f", "p", "--log", os.path.join(self.d, "absent.json"), "--out", os.path.join(self.d, "o3"))
        self.assertNotEqual(r.returncode, 0)                                      # a log the tool was told to use must exist

    def test_the_removal_tools_stop_on_a_present_vex_without_statements_and_never_say_removed(self):
        for bad in ({}, {"statements": None}):
            sd = os.path.join(self.d, "supp"); os.makedirs(sd, exist_ok=True)
            self.w("supp/fosterstack-cache.openvex.json", bad)
            pkg = self.w("package.json", {"cve": "CVE-2099-1", "ignore_expiry": "2000-01-01"})
            out = os.path.join(self.d, "po"); 
            r = self.run_py("auditor-poam.py", "--recheck", "--package", pkg, "--suppression-dir", sd, "--today", "2026-10-24", "--out", out)
            self.assertNotEqual(r.returncode, 0, bad)
            self.assertFalse(os.path.exists(os.path.join(out, "recheck.json")), bad)
            disp = self.w("disp.json", {"cve": "CVE-2099-1"})
            r = self.run_py("auditor-recheck.py", "--vex", disp, "--suppression-dir", sd, "--now-pullable", "--out", os.path.join(self.d, "ro"))
            self.assertNotEqual(r.returncode, 0, bad)
            self.assertFalse(os.path.exists(os.path.join(self.d, "ro", "recheck.json")), bad)


def unittest_patch(obj, name, value):
    from unittest import mock
    return mock.patch.object(obj, name, value)


if __name__ == "__main__":
    unittest.main()
