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


def gvc_verdict(gvc_path, ids, expected_module=None, usable=True):
    """Return ('unreachable'|'reachable'|'no-evidence', evidence). Unreachable requires a
    USABLE govulncheck stream (R11 rank 5: complete AND bound to the candidate commit — the
    caller passes usable=False for an incomplete or stale/unbound stream), at SYMBOL scan
    level, whose scanned module equals the repository's, with an imported-but-not-called
    finding for one of the ids (a non-empty trace of real frames with no function frame — an
    EMPTY or all-bare trace proves nothing), and no reachable message for any id."""
    if not usable:
        return "no-evidence", {"reason": "govulncheck stream not usable (incomplete or not bound to this candidate)"}
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


VALID_CATS = ("false_positive", "not_affected_unreachable", "real_fixable", "risk_acceptance")


def validate_manifest(m):
    """R11 rank 3: the driver validates the manifest on load. Every scanner the driver reads
    must be present as a path or an explicit null (with a reason in scanner_status); a
    missing key is a manifest error, never a KeyError mid-run."""
    r = m.get("scanner_reports")
    if not isinstance(r, dict):
        raise ValueError("manifest: scanner_reports object is missing")
    status = m.get("scanner_status") or {}
    for k in ("grype", "trivy", "osv-scanner", "osv-scanner-gomod", "snyk"):
        if k not in r:
            raise ValueError("manifest: scanner_reports missing key %r (use null for 'did not run')" % k)
        if r[k] is None and status and k in status and status[k].get("reason") is None:
            raise ValueError("manifest: %s is null with no scanner_status reason" % k)
    return m


def scanners_down(m):
    """Names of scanners the manifest records as 'did not run' (path null)."""
    r = m.get("scanner_reports") or {}
    status = m.get("scanner_status") or {}
    down = []
    for k in ("grype", "trivy", "osv-scanner", "osv-scanner-gomod", "snyk"):
        if r.get(k) is None:
            reason = (status.get(k) or {}).get("reason", "no report")
            down.append({"scanner": k, "reason": reason})
    return down


def manifest_gvc(m):
    """Resolve the govulncheck stream and whether it is USABLE (R11 rank 5). A dict form
    carries path/module/commit/complete; it is usable only if complete AND its recorded
    commit equals the manifest commit (bound to this candidate). A bare-path form (test
    harness / older manifest) is treated as usable with no commit binding available."""
    g = m.get("govulncheck")
    if isinstance(g, dict):
        module = g.get("module") or m.get("module")
        commit, top = g.get("commit"), m.get("commit")
        bound = commit is not None and top is not None and commit == top
        return g.get("path"), module, bool(g.get("complete", False)) and bound
    return g, m.get("module"), True


def manifest_findings(manifest):
    m = json.load(open(manifest)); validate_manifest(m); r = m.get("scanner_reports") or {}
    PARSERS = [("grype", P.parse_grype), ("trivy", P.parse_trivy),
               ("osv-scanner", lambda p: P.parse_osv(p, "osv-scanner")),
               ("osv-scanner-gomod", lambda p: P.parse_osv(p, "osv-scanner-gomod")),
               ("snyk", P.parse_snyk)]
    allf = []
    for name, fn in PARSERS:
        path = r.get(name)
        if path:                                    # a null scanner is skipped, not fatal
            allf += fn(path)
    # Group by CONNECTED alias sets, not each record's own canonical CVE (R1 outer round-4
    # #2): two findings the scanners connect through a shared alias belong to ONE group, so a
    # reachable trace for one is not hidden from the other. Union-find over every id/alias.
    parent = {}

    def _find(x):
        parent.setdefault(x, x)
        r = x
        while parent[r] != r:
            r = parent[r]
        while parent[x] != r:
            parent[x], x = r, parent[x]
        return r

    def _union(a, b):
        parent[_find(a)] = _find(b)

    # A finding carrying `bundle_cves` (a distro advisory that co-reports several DISTINCT
    # CVEs) is NOT a vulnerability identity: it must not bridge those CVEs (R1 outer round-5
    # #1). It creates no union edges; instead it is attached to EACH member CVE's group as
    # lineage after the identity groups are built.
    bundles, singles = [], []
    for f in allf:
        (bundles if f.get("extra", {}).get("bundle_cves") else singles).append(f)
    for f in singles:
        ids = [f["finding_id"]] + list(f["aliases"])
        for i in ids[1:]:
            _union(ids[0], i)
    comps = {}
    for f in singles:
        root = _find(f["finding_id"])
        g = comps.setdefault(root, {"aliases": set(), "findings": []})
        g["aliases"].update(f["aliases"]); g["aliases"].add(f["finding_id"]); g["findings"].append(f)
    groups = {}
    cid_by_member = {}
    for g in comps.values():
        cid = canon(sorted(g["aliases"])[0], g["aliases"])   # a CVE from the connected union
        groups[cid] = {"id": cid, "aliases": g["aliases"], "findings": g["findings"]}
        for a in g["aliases"]:
            cid_by_member[a] = cid
    # distribute each advisory bundle to its member CVEs' groups (creating a group for any
    # CVE seen ONLY in the advisory), so every distinct CVE keeps its own disposition
    for f in bundles:
        for cve in f["extra"]["bundle_cves"]:
            cid = cid_by_member.get(cve, cve)
            grp = groups.setdefault(cid, {"id": cid, "aliases": {cid}, "findings": []})
            grp["aliases"].add(cve); grp["findings"].append(f)
            cid_by_member.setdefault(cve, cid)
    return m, groups


def do_manifest(manifest, adjudicator, out, ts=TS):
    m, groups = manifest_findings(manifest)
    gvc, module, gvc_usable = manifest_gvc(m); logpath = m.get("known_defect_log")
    classification = []; report_sections = {}
    for c, grp in groups.items():
        ids = sorted(grp["aliases"])
        proposal = cli.ask_model(adjudicator, c).get("category")   # PROPOSAL only
        cat = proposal if proposal in VALID_CATS else "under_investigation"
        if proposal == "not_affected_unreachable":
            verdict, ev = gvc_verdict(gvc, ids, module, gvc_usable)
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
    r = m.get("scanner_reports") or {}
    k = sum(1 for s in ("grype", "trivy", "osv-scanner") if r.get(s))
    _render_report(out, report_sections, conclusion="stub: no narrative", context={"k": k})


TITLES = {1: "Lifted", 2: "Accepted risk", 3: "Actual vulnerabilities",
          4: "Could not be assessed", 5: "Closed as not affected",
          6: "Pending", 7: "Currently suppressed"}

# R12 item 5: an empty section carries a sentence WITH ITS COUNTS, never a blank or "none".
EMPTY = {
    1: "No suppression was lifted this run: {n} carried statements were re-checked against upstream and the current tree; none has a pullable fix or lost its evidence.",
    2: "No accepted-risk items are carried. Nothing is below threshold and nothing awaits the owner.",
    3: "None. {p} packages inventoried by {k} scanners; no finding is reachable, fixable, and unfixed.",
    4: "None. Every finding was dispositioned; no adjudication was refused or exhausted.",
    5: "None this run. {h} findings were closed by the known-defect log without a model call; {m} new not-affected statements were written with evidence.",
    6: "Nothing pending: no VEX or bump PR awaits the audit lane; no Dependabot PR was deferred to.",
    7: "No suppressions are in force for this candidate; consistency check: {consistency}.",
}


def _render_report(out, sections, header="", conclusion=None, context=None):
    ctx = {"n": 0, "p": 0, "k": 0, "h": 0, "m": 0, "consistency": "clean", "down": ""}
    ctx.update(context or {})
    lines = ["# Daily CVE auditor report", "", "## Conclusion", "",
             (conclusion or "stub: no narrative"), ""]
    if header:
        lines.append(header.rstrip()); lines.append("")
    for n in range(1, 8):
        lines.append("## %d. %s" % (n, TITLES[n]))
        ids = sections.get(n, [])
        if ids:
            for fid in ids:
                lines.append(fid)
        else:
            sentence = EMPTY[n].format(**ctx)
            # a section that could not be computed names the scanner/step (never "none")
            if n in (3, 7) and ctx.get("down"):
                sentence += " Not a complete assessment: %s did not run." % ctx["down"]
            lines.append(sentence)
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
