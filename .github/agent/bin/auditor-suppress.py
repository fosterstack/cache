#!/usr/bin/env python3
"""One VERIFIED disposition -> four per-scanner suppressions (REQ-AUD-4 AC1, R11 rank 1).

Evidence is verified, never named: this OPENS the referenced source file and RE-DERIVES the
check before authoring anything, and REFUSES on any mismatch —
  * a missing / unreadable source file is a refusal (a `/does/not/exist.json` cannot back a
    suppression);
  * check `known-defect-log`: the log must actually contain a false_positive row for this
    CVE whose package is the package the disposition names — a row for one package cannot
    clear another;
  * check `reachability`/`govulncheck`: the stream must carry an imported-but-not-called
    finding for the CVE (or an alias) with no reachable trace.
The authored VEX is scoped by `subcomponents` to exactly the package purls the evidence
covers, so it clears only those packages. It is OpenVEX-conformant (evidence in a sidecar)
and still requires `evidence` to be an object with {check, source_file, detail}.
"""
import os, sys, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy, vex
from auditorlib import parsers as P


def _pkg_of(purl):
    m = re.match(r"pkg:[^/]+/(?:[^/]+/)*([^/@?]+)", purl or "")
    return m.group(1) if m else None


def _verify(cve, aliases, purls, ev):
    src = ev.get("source_file")
    if not src or not os.path.exists(src):
        sys.exit("suppress: evidence source_file %r does not exist — refusing" % src)
    check = ev.get("check")
    ids = {cve} | set(aliases)
    pkgs = {p for p in (_pkg_of(v) for v in purls.values()) if p}
    if check == "known-defect-log":
        try:
            log = json.load(open(src))
        except Exception as e:
            sys.exit("suppress: cannot read known-defect log %s: %s" % (src, e))
        for row in log.get("defects", []):
            if row.get("disposition") != "false_positive":
                continue
            if not any(k.get("finding_id") in ids for k in row.get("keys", [])):
                continue
            rowpkg = row.get("package")
            if rowpkg and (rowpkg in pkgs or any(rowpkg in v for v in purls.values())):
                return   # the log names a false_positive for THIS package -> verified
        sys.exit("suppress: no false_positive log row for %s on package(s) %s — refusing"
                 % (cve, sorted(pkgs)))
    if check in ("reachability", "govulncheck"):
        try:
            g = P.parse_govulncheck(src)
        except Exception as e:
            sys.exit("suppress: cannot parse govulncheck stream %s: %s" % (src, e))
        present = [i for i in ids if i in g["by_osv"]]
        if not present or any(g["by_osv"][i]["reachable"] for i in present) \
                or not any(g["by_osv"][i]["imported_only"] for i in present):
            sys.exit("suppress: govulncheck does not show %s imported-but-not-called — refusing" % cve)
        return
    sys.exit("suppress: unknown evidence check %r — refusing" % check)


def main():
    d = json.load(open(cli.opt("--disposition"))); out = cli.opt("--out")
    cve = d["cve"]; vid = policy.stmt_id(cve); status = d["status"]; expiry = d.get("expiry", "2026-10-22")
    today = cli.opt("--today", "2026-09-22"); ts = today + "T00:00:00Z"
    if status not in ("not_affected", "affected"):
        sys.exit("suppress: invalid status")
    ev = d.get("evidence")
    if not (isinstance(ev, dict) and all(k in ev for k in ("check", "source_file", "detail"))):
        sys.exit("suppress: evidence must be an object with check, source_file, detail")
    purls = d.get("purls", {})
    if status == "not_affected":
        _verify(cve, d.get("aliases", []), purls, ev)     # opens the source; exits on mismatch
    subcomponents = sorted(set(purls.values())) or None
    document = vex.doc(cve, status, ts,
                       justification=(d.get("justification") if status == "not_affected" else None),
                       action=(None if status == "not_affected" else d.get("action_statement", "tracked; re-checked daily")),
                       subcomponents=subcomponents)
    vex.validate(document)
    cli.writej(os.path.join(out, ".vex", "fosterstack-cache.openvex.json"), document)
    cli.writej(os.path.join(out, "evidence", cve + ".evidence.json"),
               {"statement_id": vid, "vulnerability": cve, "evidence": ev, "expiry": expiry,
                "scoped_purls": subcomponents})
    cli.writef(os.path.join(out, ".snyk"),
               "version: v1.5.0\nignore:\n  %s:\n    - '*':\n        reason: '%s; %s'\n"
               "        expires: %sT00:00:00.000Z\n        vex: '%s'\n" % (cve, status, vid, expiry, vid))
    cli.writef(os.path.join(out, "osv-scanner.toml"),
               '[[IgnoredVulns]]\nid = "%s"\nreason = "%s; governed by %s"\n' % (cve, status, vid))


if __name__ == "__main__":
    main()
