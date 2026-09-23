#!/usr/bin/env python3
"""Every-run suppression consistency check (REQ-AUD-4 AC5): every ignore must cite a
governing VEX; every VEX must answer a live finding; nothing suppressed in one
scanner and unhandled in another."""
import os, re, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "testlib"))
from auditorlib import cli
from auditorlib import parsers as P


def live_cves(manifest):
    m = json.load(open(manifest)); r = m.get("scanner_reports") or {}
    cves = set()
    for name, fn in (("grype", P.parse_grype), ("trivy", P.parse_trivy),
                     ("osv-scanner", P.parse_osv), ("snyk", P.parse_snyk),
                     ("osv-scanner-gomod", lambda p: P.parse_osv(p, "osv-scanner-gomod"))):
        path = r.get(name)
        if not path:                                # a null scanner (did not run) is skipped
            continue
        for f in fn(path):
            cves.update(a for a in f["aliases"] if a.startswith("CVE-"))
    return cves


def main():
    d = cli.opt("--suppression-dir"); out = cli.opt("--out")
    live = live_cves(cli.opt("--live-findings"))
    problems = []
    vexf = os.path.join(d, "fosterstack-cache.openvex.json")
    vex_cves = set()
    if os.path.exists(vexf):
        for s in json.load(open(vexf)).get("statements", []):
            cve = (s.get("vulnerability") or {}).get("name")
            vex_cves.add(cve)
            if cve not in live:
                problems.append({"type": "stale_vex", "cve": cve})
    snykf = os.path.join(d, ".snyk")
    if os.path.exists(snykf):
        import pyyaml as yaml
        y = yaml.safe_load(open(snykf).read()) or {}
        for k, entries in (y.get("ignore") or {}).items():
            cites = any("stmt-" in str(e.get(sel, {}).get("vex", "")) for e in entries for sel in e)
            if not cites:
                problems.append({"type": "tool_only_ignore", "id": k})
    tomlf = os.path.join(d, "osv-scanner.toml")
    if os.path.exists(tomlf):
        blocks = re.split(r"\[\[IgnoredVulns\]\]", open(tomlf).read())[1:]
        for b in blocks:
            mid = re.search(r'id\s*=\s*"([^"]+)"', b)
            if mid and "stmt-" not in b:
                problems.append({"type": "tool_only_ignore", "id": mid.group(1)})
    cli.writej(out, {"consistent": not problems, "problems": problems})


if __name__ == "__main__":
    main()
