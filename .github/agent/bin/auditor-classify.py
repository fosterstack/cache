#!/usr/bin/env python3
"""Classify findings (REQ-AUD-2).

Two rules hold everywhere:
  * ABSENCE OF EVIDENCE IS NEVER EVIDENCE OF UNREACHABILITY. A finding with no
    matching govulncheck message stays OPEN.
  * THE MODEL'S ANSWER IS A PROPOSAL. Code writes a VEX only after it has itself
    verified the evidence for that finding, under every alias:
      - not_affected(vulnerable_code_not_in_execute_path) requires a govulncheck
        stream at SYMBOL scan level, a finding message for one of the ids, and no
        function-bearing trace for any id. An empty trace is not proof.
      - false_positive requires a known-defect-log row for one of the ids, or a
        version-range exclusion in the scanner's own data.
    A model proposal the code cannot verify becomes `under_investigation` (section 4).
"""
import os, sys, re, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy
from auditorlib import parsers as P
from auditorlib import vex

SECT = {"false_positive": [5], "not_affected_unreachable": [2],
        "real_fixable": [3], "risk_acceptance": [2, 3], "under_investigation": [4]}
TS = "2026-09-22T00:00:00-04:00"


def canon(fid, aliases):
    for a in [fid] + list(aliases):
        if re.fullmatch(r"CVE-\d{4}-\d+", a):
            return a
    return fid


def vex_doc(fid, status, justification=None, action=None, evidence=None):
    st = {"@id": policy.stmt_id(fid), "vulnerability": {"name": fid},
          "timestamp": TS, "products": [{"@id": policy.VEX_PRODUCT}], "status": status}
    if justification:
        st["justification"] = justification
    if action:
        st["action_statement"] = action
    if evidence:
        st["_evidence"] = evidence
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": policy.VEX_BASE,
            "author": "FosterStack LLC", "role": "vendor", "timestamp": TS, "version": 1,
            "statements": [st]}


def gvc_verdict(gvc_path, ids, expected_module=None):
    """Return ('unreachable'|'reachable'|'no-evidence', evidence). Unreachable requires a
    SYMBOL-level stream whose scanned module equals the repository's, an imported-but-not-
    called finding for one of the ids (a non-empty trace with no function frame — an EMPTY
    trace proves nothing), and no reachable message for any id."""
    if not gvc_path or not os.path.exists(gvc_path):
        return "no-evidence", {"reason": "no govulncheck stream"}
    try:
        g = P.parse_govulncheck(gvc_path)
    except P.ParseError:
        return "no-evidence", {"reason": "unparseable govulncheck"}
    present = [i for i in ids if i in g["by_osv"]]
    if not present:
        return "no-evidence", {"reason": "no finding message for any id"}
    if g["scan_level"] != "symbol":
        return "no-evidence", {"reason": "scan_level=%s (symbol required)" % g["scan_level"]}
    if expected_module and g["module"] != expected_module:
        return "no-evidence", {"reason": "scanned module %r != %r" % (g["module"], expected_module)}
    if any(g["by_osv"][i]["reachable"] for i in present):
        return "reachable", {"scan_level": "symbol", "module": g["module"], "reachable": True}
    if any(g["by_osv"][i]["imported_only"] for i in present):
        return "unreachable", {"source": "govulncheck", "scan_level": "symbol",
                               "module": g["module"], "imported_only": True, "ids": present}
    return "no-evidence", {"reason": "only empty traces; not proof of unreachability"}


def fp_verified(ids, logpath, findings):
    """Verify a false positive only on the FULL exact key (scanner, finding_id, purl) of one
    of the group's findings against a trusted (not model-proposed) log row."""
    if logpath and os.path.exists(logpath):
        log = json.load(open(logpath))
        keys = {(k["scanner"], k["finding_id"], k["purl"]): row
                for row in log.get("defects", []) for k in row.get("keys", [])}
        for f in findings:
            row = keys.get((f["scanner"], f["finding_id"], f["purl"]))
            if row and row.get("disposition") == "false_positive":
                return {"check": "known-defect-log", "source_file": logpath,
                        "detail": "exact key %s/%s/%s" % (f["scanner"], f["finding_id"], f["purl"])}
    return None


def manifest_findings(manifest):
    m = json.load(open(manifest)); r = m["scanner_reports"]
    allf = (P.parse_grype(r["grype"]) + P.parse_trivy(r["trivy"]) +
            P.parse_osv(r["osv-scanner"]) + P.parse_osv(r["osv-scanner-gomod"], "osv-scanner-gomod") +
            P.parse_snyk(r["snyk"]))
    groups = {}
    for f in allf:
        c = canon(f["finding_id"], f["aliases"])
        groups.setdefault(c, {"id": c, "aliases": set(), "findings": []})
        groups[c]["aliases"].update(f["aliases"]); groups[c]["aliases"].add(f["finding_id"])
        groups[c]["findings"].append(f)
    return m, groups


def do_manifest(manifest, adjudicator, out, ts=TS):
    m, groups = manifest_findings(manifest)
    gvc = m.get("govulncheck"); logpath = m.get("known_defect_log"); module = m.get("module")
    classification = []; report_sections = {}
    for c, grp in groups.items():
        ids = sorted(grp["aliases"])
        proposal = cli.ask_model(adjudicator, c).get("category")   # PROPOSAL only
        cat = proposal
        if proposal == "not_affected_unreachable":
            verdict, ev = gvc_verdict(gvc, ids, module)
            if verdict == "unreachable":
                vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_in_execute_path", evidence=ev)
            else:
                cat = "under_investigation"
                vex.write(out, c, "under_investigation", ts, evidence={"reason": ev.get("reason", verdict)})
        elif proposal == "false_positive":
            ev = fp_verified(ids, logpath, grp["findings"])
            if ev:
                vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=ev)
                cli.writej(os.path.join(out, "ignores", "grype", c + ".json"),
                           {"vex": policy.stmt_id(c), "id": c, "evidence": ev})
            else:
                cat = "under_investigation"
                vex.write(out, c, "under_investigation", ts, evidence={"reason": "no false-positive evidence"})
        classification.append({"id": c, "category": cat})
        for s in SECT.get(cat, []):
            report_sections.setdefault(s, []).append(c)
        cli.writej(os.path.join(out, "report-sections", c + ".json"), {"sections": SECT.get(cat, [])})
        cli.writej(os.path.join(out, "disposition", c + ".json"), {"permanent": cat == "false_positive"})
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
    module = None
    if manifest and os.path.exists(manifest):
        module = json.load(open(manifest)).get("module")
    verdict, ev = gvc_verdict(gvc, [finding], module)
    if verdict == "no-evidence":
        cli.writej(os.path.join(out, "status", finding + ".json"),
                   {"open": True, "reason": ev.get("reason", "no evidence")})
        return
    if verdict == "unreachable":
        vex.write(out, finding, "not_affected", cli.opt("--today", TS) + "T00:00:00Z" if len(cli.opt("--today", TS)) == 10 else TS,
                  justification="vulnerable_code_not_in_execute_path", evidence=ev)
        return
    # reachable -> real-fixable bump
    m = json.load(open(manifest)); fixed = installed = None
    for f in P.parse_osv(m["scanner_reports"]["osv-scanner-gomod"], "osv-scanner-gomod"):
        if f["finding_id"] == finding or finding in f["aliases"]:
            fixed = f["fixed_version"]; installed = f["extra"].get("installed_version")
    cli.writej(os.path.join(out, "action", finding + ".json"),
               {"kind": "bump_pr", "from": installed, "to": fixed,
                "lane": "auto-merge", "defer_to_dependabot": False})


def main():
    out = cli.opt("--out"); adjudicator = cli.opt("--adjudicator")
    finding = cli.opt("--finding"); manifest = cli.opt("--manifest"); gvc = cli.opt("--govulncheck")
    today = cli.opt("--today"); ts = (today + "T00:00:00Z") if today else TS
    if finding and gvc:
        do_single(finding, manifest, gvc, out)
    elif manifest:
        do_manifest(manifest, adjudicator, out, ts)
    else:
        sys.exit("classify: need --manifest or --finding+--govulncheck")


if __name__ == "__main__":
    main()
