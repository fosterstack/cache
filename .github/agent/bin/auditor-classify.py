#!/usr/bin/env python3
"""Classify findings (REQ-AUD-2).

Reachability rule, in code and here: ABSENCE OF EVIDENCE IS NEVER EVIDENCE OF
UNREACHABILITY. A finding with no matching govulncheck message stays OPEN. A
not_affected(vulnerable_code_not_in_execute_path) statement is written only for a
finding that govulncheck reports as present-and-not-reachable. The model proposes a
category only on a log miss; the code verifies status against evidence, never the
model.
"""
import os, sys, re
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from auditorlib import cli, policy
from auditorlib import parsers as P

SECT = {"false_positive": [5], "not_affected_unreachable": [2],
        "real_fixable": [3], "risk_acceptance": [2, 3]}


def canon(fid, aliases):
    # Prefer a scanner-reported CVE alias so DEBIAN-CVE and GO ids for the same
    # advisory collapse to one finding (matched through the alias set, never string
    # surgery). Falls back to the id when no CVE alias exists.
    for a in [fid] + list(aliases):
        if re.fullmatch(r"CVE-\d{4}-\d+", a):
            return a
    return fid


def vex(fid, status, justification=None, action=None):
    s = {"@id": policy.stmt_id(fid), "vulnerability": {"name": fid},
         "products": [{"@id": policy.VEX_PRODUCT}], "status": status}
    if justification:
        s["justification"] = justification
    if action:
        s["action_statement"] = action
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": policy.VEX_BASE,
            "author": "FosterStack LLC", "role": "vendor", "version": 1,
            "statements": [s]}


def manifest_findings(manifest):
    import json
    m = json.load(open(manifest))
    r = m["scanner_reports"]
    allf = (P.parse_grype(r["grype"]) + P.parse_trivy(r["trivy"]) +
            P.parse_osv(r["osv-scanner"]) + P.parse_osv(r["osv-scanner-gomod"], "osv-scanner-gomod") +
            P.parse_snyk(r["snyk"]))
    groups = {}   # canonical -> {id, findings}
    for f in allf:
        c = canon(f["finding_id"], f["aliases"])
        groups.setdefault(c, {"id": c, "aliases": set(), "findings": []})
        groups[c]["aliases"].update(f["aliases"])
        groups[c]["findings"].append(f)
    return m, groups


def do_manifest(manifest, adjudicator, out):
    m, groups = manifest_findings(manifest)
    classification = []
    report_sections = {}
    for c, grp in groups.items():
        ans = cli.ask_model(adjudicator, c)      # judgment: category
        cat = ans.get("category")
        classification.append({"id": c, "category": cat})
        secs = SECT.get(cat, [])
        for s in secs:
            report_sections.setdefault(s, []).append(c)
        cli.writej(os.path.join(out, "report-sections", c + ".json"), {"sections": secs})
        cli.writej(os.path.join(out, "disposition", c + ".json"),
                   {"permanent": cat == "false_positive"})
        if cat == "false_positive":
            cli.writej(os.path.join(out, "vex", c + ".openvex.json"),
                       vex(c, "not_affected", ans.get("justification") or "vulnerable_code_not_present"))
            cli.writej(os.path.join(out, "ignores", "grype", c + ".json"),
                       {"vex": policy.stmt_id(c), "id": c})
        elif cat == "not_affected_unreachable":
            cli.writej(os.path.join(out, "vex", c + ".openvex.json"),
                       vex(c, "not_affected", "vulnerable_code_not_in_execute_path"))
    cli.writej(os.path.join(out, "classification.json"), {"findings": classification})
    _render_report(out, report_sections)


def _render_report(out, sections):
    titles = {1: "Lifted", 2: "Accepted risk", 3: "Actual vulnerabilities",
              4: "Could not be assessed", 5: "Closed as not affected",
              6: "Pending", 7: "Currently suppressed"}
    lines = ["# Daily CVE auditor report", ""]
    for n in range(1, 8):
        lines.append("## %d. %s" % (n, titles[n]))
        for fid in sections.get(n, []):
            lines.append(fid)
        lines.append("")
    cli.writef(os.path.join(out, "report.md"), "\n".join(lines) + "\n")


def do_single(finding, manifest, gvc, out):
    reach = P.parse_govulncheck(gvc)              # deterministic; no model
    if finding not in reach:                       # NO evidence -> stays OPEN
        cli.writej(os.path.join(out, "status", finding + ".json"),
                   {"open": True, "reason": "no govulncheck evidence for this finding"})
        return
    if not reach[finding]["reachable"]:            # present + not reachable -> agent VEX
        cli.writej(os.path.join(out, "vex", finding + ".openvex.json"),
                   vex(finding, "not_affected", "vulnerable_code_not_in_execute_path"))
        return
    # reachable -> real-fixable bump PR (no not_affected VEX)
    import json
    m = json.load(open(manifest))
    fixed = installed = None
    for f in P.parse_osv(m["scanner_reports"]["osv-scanner-gomod"], "osv-scanner-gomod"):
        if f["finding_id"] == finding or finding in f["aliases"]:
            fixed = f["fixed_version"]; installed = f["extra"].get("installed_version")
    cli.writej(os.path.join(out, "action", finding + ".json"),
               {"kind": "bump_pr", "from": installed, "to": fixed,
                "lane": "auto-merge", "defer_to_dependabot": False})


def main():
    out = cli.opt("--out"); adjudicator = cli.opt("--adjudicator")
    finding = cli.opt("--finding"); manifest = cli.opt("--manifest")
    gvc = cli.opt("--govulncheck")
    if finding and gvc:
        do_single(finding, manifest, gvc, out)
    elif manifest:
        do_manifest(manifest, adjudicator, out)
    else:
        sys.exit("classify: need --manifest or --finding+--govulncheck")


if __name__ == "__main__":
    main()
