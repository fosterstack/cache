# Probe mutants distilled from the implementation review
# (audits/2026-09-22/cve-auditor-implementation-1b8916c/evidence/probes/*).
# Each mode is a stand-in that exhibits ONE of the ten findings' wrong behaviours;
# the mutation harness asserts the now-strengthened suite catches it. Every
# invocation writes a marker so a mode that crashes before its bug is not counted.
# Not auditor code — a checked-in TEST INPUT (adversary).
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).stem
mode = os.environ.get("AUDIT_PROBE", "")
args = sys.argv[1:]


def arg(k, d=None):
    return args[args.index(k) + 1] if k in args else d


def put(rel, data):
    p = Path(arg("--out", "/tmp/probe-out")) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data if isinstance(data, str) else json.dumps(data))


def mark(tag):
    mk = os.environ.get("AUDIT_MARKER")
    if mk:
        open(mk, "a").write("%s:%s:%s\n" % (name, mode, tag))


mark("reached")

# F1/F4 — the model authors a not_affected with NO evidence object.
if mode == "model-not-affected-no-evidence" and name == "auditor-classify":
    fid = arg("--finding")
    if fid:
        put("vex/%s.openvex.json" % fid,
            {"statements": [{"vulnerability": {"name": fid}, "status": "not_affected",
                             "justification": "vulnerable_code_not_in_execute_path"}]})
        mark("wrote-unverified-vex")
    sys.exit(0)

# F6 — rechecks report removal booleans but delete nothing.
if mode == "recheck-flags-only":
    if name == "auditor-poam" and "--recheck" in args:
        put("recheck.json", {"ignore_removed": True, "returned_to_section": 3, "policy_reapplied": True})
        mark("flag-without-delete"); sys.exit(0)
    if name == "auditor-recheck":
        put("recheck.json", {"vex_removed": True, "bump_pr_opened": True, "report_section": 1})
        mark("flag-without-delete"); sys.exit(0)

# F5 — reconciliation adds the key to a row by finding-id alone, ignoring same_defect/purl.
if mode == "reconcile-wrong-row" and name == "auditor-defectlog" and args and args[0] == "reconcile":
    logp = arg("--log"); a = args
    sc, fid, purl = a[a.index("--finding") + 1:a.index("--finding") + 4]
    log = json.load(open(logp))
    log["defects"][0]["keys"].append({"scanner": sc, "finding_id": fid, "purl": "pkg:generic/unrelated@999"})
    json.dump(log, open(logp, "w"))
    put("reconcile.json", {"added": True}); mark("wrong-row-and-purl"); sys.exit(0)

# F7 — release authorization accepts a substring, not the parsed acceptance form.
if mode == "authz-substring" and name == "auditor-release-authz":
    issues = json.load(open(arg("--issues")))
    txt = json.dumps(issues)
    decision = "promote" if "ACCEPT" in txt else "hold"   # ignores author, form, date
    put("authz.json", {"decision": decision}); mark("substring-accept"); sys.exit(0)

# F8 — threshold omits known-exploited.
if mode == "known-exploited-omitted" and name == "auditor-poam" and "--recheck" not in args:
    f = json.load(open(arg("--finding")))
    put("decision.json", {"ci_stays_green": True, "report_section": 2,
                          "threshold": "below", "threshold_reason": "below"})
    put("vex/%s.openvex.json" % f["cve"],
        {"statements": [{"vulnerability": {"name": f["cve"]}, "status": "affected", "action_statement": "x"}]})
    put("package.json", {"cve": f["cve"], "ignore_expiry_days": 30})
    mark("known-exploited-omitted"); sys.exit(0)

# F3 — the entrypoint prints a banner and does no audit.
if mode == "entrypoint-noop" and name == "auditor-run":
    print("daily CVE auditor: (no-op banner)"); mark("no-op-run"); sys.exit(0)

# default: produce nothing (other cases fail on the missing effect)
sys.exit(0)
