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

# one entry per reviewed-input file name the agent reads: (a sample file name, the required keys, a valid document, documents that must stop)
FILES = [
    ("fosterstack-cache.openvex.json", ("statements",), {"statements": []}, [{}, {"statements": None}, {"statements": {}}, {"statements": "x"}, {"statements": [None]}, {"statements": [3]}, {"other": []}, [], "x"]),
    ("CVE-2099-1.openvex.json", ("statements",), {"statements": [{"a": 1}]}, [{}, {"statements": None}, {"other": []}]),
    ("accepted-items.json", ("accepted_items",), {"accepted_items": []}, [{}, {"accepted_items": None}, {"accepted_items": {}}, {"accepted_items": [None]}, {"accepted_items": ["x"]}, {"other": []}, []]),
    ("reopened-expired.json", ("reopened",), {"reopened": []}, [{}, {"reopened": None}, {"reopened": {}}, {"reopened": "x"}, {"reopened": [None]}, {"other": []}, []]),
    ("consistency.json", ("problems", "consistent"), {"consistent": True, "problems": []}, [{}, {"problems": []}, {"consistent": True}, {"consistent": True, "problems": None}, {"consistent": "yes", "problems": []}, {"consistent": True, "problems": [3]}, []]),
    ("known-defect-log.json", ("defects",), {"defects": []}, [{}, {"defects": None}, {"defects": {}}, {"defects": [None]}, {"other": []}, []]),
]

# every other *.json file name that appears as a string literal in the agent's programs, and why it is not a reviewed input read through the reader
_RUN_INTERNAL = "written and read inside one run (a derived, run-internal file), not a reviewed input"
EXEMPT = {n: _RUN_INTERNAL for n in (
    "reconcile.json", "recheck.json", "index.json", "state.json", "notify.json", "decision.json", "day.json", "classification.json", "adjudicator-proposals.json", ".evidence.json",
    "votes.json", "verdict.json", "triggers.json", "syft.json", "stop.json", "still-present.json", "still-active.json", "scanner-calls.json", "run-state.json", "rule0.json",
    "result.json", "refusal-log.json", "probe.json", "pr.json", "plan.json", "parity.json", "package.json", "note.json", "leak.json", "govulncheck.json", "consumed.json",
    "budget.json", "adjudication.json", "accepted-item.json", ".status.json", "panel-state.json", ".json", "*.json", "openvex-schema.json", "scanner-profiles.json")}


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
                    reviewed.read(self.write(name, bad))
            self.assertEqual(reviewed.read(self.write(name, good)), good, name)

    def test_an_absent_file_is_none_and_a_non_json_or_unlookable_one_is_a_stop(self):
        for name, *_ in FILES:
            self.assertIsNone(reviewed.read(os.path.join(self.d, "absent", name)), name)
            p = os.path.join(self.d, name)
            with open(p, "w") as fh:
                fh.write("{not json")
            with self.assertRaises(reviewed.ReviewedInputInvalid):
                reviewed.read(p)

    def test_the_table_names_exactly_the_reviewed_files_and_their_required_keys(self):
        for name, keys, *_ in FILES:
            self.assertEqual(tuple(k for k, _ in reviewed.spec_for(name)), keys, name)
        self.assertEqual(reviewed.spec_for("run-state.json"), ())
        self.assertEqual(reviewed.spec_for("whatever.openvex.json")[0][0], "statements")

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
        undecided = sorted(n for n in seen if not reviewed.spec_for(n) and n not in EXEMPT and n != "known-defect-log.json")
        self.assertEqual(undecided, [], "a new json file name: add it to the table of auditorlib/reviewed.py (a reviewed input) or to EXEMPT here with its reason")


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


def unittest_patch(obj, name, value):
    from unittest import mock
    return mock.patch.object(obj, name, value)


if __name__ == "__main__":
    unittest.main()
