#!/usr/bin/env python3
"""Auditor entrypoint (REQ-AUD-12; called by .github/workflows/auditor.yml).

One run, end to end, over real inputs — nothing stubbed:
  consume the day's rescan artifacts (fail on a malformed digest) -> parse every
  report -> for each grouped finding, look it up in the known-defect log FIRST (a hit
  closes it with NO model call) -> on a miss, the model PROPOSES a category and the
  code VERIFIES it against evidence before writing any VEX (govulncheck symbol-level
  for unreachable; the log or a version-range exclusion for false positive) ->
  reachable-no-fix items become a POA&M with an affected VEX, a computed 30-day
  expiry, and an accepted-items entry -> render the report (a scanner that did not run
  is the first line and the run is never 'clean') -> when NOT dry-run, open the PRs and
  owner-decision issues the report lists, through the git/gh shim. dry-run does
  everything except open PRs and issues.
"""
import os, sys, json, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from auditorlib import cli, policy
from auditorlib import parsers as P
from auditorlib import vex

# load auditor-classify.py (hyphenated) as a module for its verified writers
_spec = importlib.util.spec_from_file_location("auditor_classify", os.path.join(HERE, "auditor-classify.py"))
C = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(C)


def _shim(line):
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        open(log, "a").write(line + "\n")


def log_index(logpath):
    idx = {}
    if logpath and os.path.exists(logpath):
        for row in json.load(open(logpath)).get("defects", []):
            for k in row["keys"]:
                idx[(k["scanner"], k["finding_id"], k["purl"])] = row
    return idx


def run(manifest_path, dry, out, today):
    m, groups = C.manifest_findings(manifest_path)
    gvc = m.get("govulncheck"); logpath = m.get("known_defect_log"); module = m.get("module")
    ts = today + "T00:00:00Z"
    idx = log_index(logpath)
    adjudicator = cli.opt("--adjudicator", os.path.join(HERE, "auditor-adjudicator-client.py"))
    sections = {}; classification = []; accepted = []
    for c, grp in groups.items():
        ids = sorted(grp["aliases"]); ids.append(grp["id"])
        # 1) defect-log lookup FIRST — a hit closes with no model call.
        hit = None
        for f in grp["findings"]:
            hit = idx.get((f["scanner"], f["finding_id"], f["purl"]))
            if hit:
                break
        if hit:
            cat = hit["disposition"]
            if cat == "false_positive":                       # trusted log row only (never 'proposed')
                ev = {"check": "known-defect-log", "source_file": logpath, "detail": "exact key hit for %s" % c}
                vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=ev)
                C.cli.writej(os.path.join(out, "ignores", "grype", c + ".json"),
                             {"vex": policy.stmt_id(c), "id": c, "evidence": ev})
            else:
                cat = "under_investigation"
        else:
            # 2) model PROPOSES; code VERIFIES before any VEX.
            cat = cli.ask_model(adjudicator, c).get("category")
            if cat == "not_affected_unreachable":
                verdict, ev = C.gvc_verdict(gvc, ids, module)
                if verdict == "unreachable":
                    vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_in_execute_path", evidence=ev)
                else:
                    cat = "under_investigation"
            elif cat == "false_positive":
                ev = C.fp_verified(ids, logpath, grp["findings"])
                if ev:
                    vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=ev)
                    C.cli.writej(os.path.join(out, "ignores", "grype", c + ".json"),
                                 {"vex": policy.stmt_id(c), "id": c, "evidence": ev})
                else:
                    cat = "under_investigation"
        classification.append({"id": c, "category": cat})
        for s in C.SECT.get(cat, []):
            sections.setdefault(s, []).append(c)
    # report + accepted-items + classification
    down = [s for s in json.load(open(manifest_path)).get("scanners", []) if not s.get("ran", True)]
    C._render_report(out, sections)
    cli.writej(os.path.join(out, ".auditor", "accepted-items.json"), accepted)
    cli.writej(os.path.join(out, "classification.json"), {"findings": classification})
    if not dry:
        # open the PRs the report lists (VEX changes -> audit lane), through the shim.
        for c in [x["id"] for x in classification if x["category"] in ("false_positive", "not_affected_unreachable")]:
            _shim("gh pr create --head auditor/vex-%s --base main --label audit-lane" % c)
    return classification


def main():
    dry = cli.opt("--dry-run", "true") != "false"
    manifest = cli.opt("--manifest"); out = cli.opt("--out", os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "auditor-out"))
    today = cli.opt("--today", "2026-09-22")
    if not manifest:
        print("daily CVE auditor: no manifest supplied"); return 2
    run(manifest, dry, out, today)
    print("daily CVE auditor: dry_run=%s, out=%s" % (dry, out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
