#!/usr/bin/env python3
"""The daily rescan's scanner panel tally (scanner-panel rules 3-6, ratified by the owner Oct 2; REQ-SCAN-003..006).
Each scanner job leaves its raw output per image under <in>/<scanner>/<image>/:

  grype      result.cdx.json   CycloneDX from `grype --vex <our VEX> -o cyclonedx-json` (VEX applied by Grype)
  scout      sbom.json         `docker scout sbom --format json`
             cves.json         `docker scout cves --format gitlab --vex-location <our VEX>` (VEX applied by Scout)
  inspector  sbom.cdx.json     inspector-sbomgen's CycloneDX
             scan.json         inspector-scan:ScanSbom's answer ({"sbom": CycloneDX with vulnerabilities})
  google     packages.json     the package list gcloud sent to on-demand scanning
             vulns.json        `gcloud artifacts docker images list-vulnerabilities`

and this tallies the day, mechanically:
  rule 3  every scanner reports its package count; zero, an empty or unreadable output = did not run, a pipeline
          failure, never clean; an image counts only if at least three scanners ran on it;
  rule 4  Inspector's and Google's results are filtered against our published OpenVEX here (Grype and Scout
          were given the file); a covered finding is recorded as covered, never reported;
  rule 6  one finding per CVE + package + version per image, "seen by N of M" (M = scanners that ran on it);
  rule 5  seen by two or more -> the tracking issue; seen by one ("unique") -> listed for the auditor.
Rules 7-9 (profiles, audits, debates, what "false" does) are the auditor's: its daily run reads this run's
verdict.json right after the rescan (rule 9, owner Oct 3). This judges no unique finding.
Exit: 0 clean (unique findings alone are not a failure here), 1 something to report, 2 a scanner did not run or an
image did not count (the run fails visibly; never reported clean).

usage: panel.py tally --in DIR --vex F --out DIR
       panel.py google-packages HTTP_LOG   (the package list gcloud sent, from its --log-http output)
"""
import argparse, importlib.util, json, os, re, sys, urllib.parse

_gate_spec = importlib.util.spec_from_file_location(
    "inspector_gate", os.path.join(os.path.dirname(os.path.abspath(__file__)), "inspector-gate.py"))
_gate = importlib.util.module_from_spec(_gate_spec)
_gate_spec.loader.exec_module(_gate)

VARIANTS = ("production", "debug", "fips")
# rule 1, fixed here as in the workflow: Grype, Scout and Inspector on all six images; Google on linux/amd64 only
EXPECTED = {
    "grype": ["%s-%s" % (v, a) for v in VARIANTS for a in ("amd64", "arm64")],
    "scout": ["%s-%s" % (v, a) for v in VARIANTS for a in ("amd64", "arm64")],
    "inspector": ["%s-%s" % (v, a) for v in VARIANTS for a in ("amd64", "arm64")],
    "google": ["%s-amd64" % v for v in VARIANTS],
}
QUORUM = 3
DISTRO_PURL_TYPES = ("deb", "rpm", "apk", "alpm")   # their purl namespace is the distro, not part of the name


def _load(path):
    with open(path) as f:
        text = f.read()
    if not text.strip():
        raise ValueError("empty")
    return json.loads(text)


def load_vex(path):
    return _gate.vex_index(_gate.load(path))


# ----------------------------------------------------------------------------- readers: (count, findings)

def _cdx_packages(doc):
    """Rule 3's package count: components that are packages (carry a package URL). Grype's CycloneDX also
    lists every file it catalogued as a component (946 of 965 on production-amd64, run 36957462057)."""
    return [c for c in doc.get("components") or [] if isinstance(c, dict) and c.get("purl")]


def _purl_name_version(purl):
    """(name, version) from a package URL, as the other scanners name it: a distro package without its distro
    namespace (pkg:deb/debian/libc-bin -> libc-bin), a Go module by its full path; the version un-escaped."""
    name, ver = _gate.name_version(purl)
    if (purl or "").startswith("pkg:") and (purl[4:].split("/", 1)[0] in DISTRO_PURL_TYPES):
        name = name.rsplit("/", 1)[-1]
    return name, urllib.parse.unquote(ver)


def key_of(image, vid, package, version):
    """One finding per CVE + package + version per image (rule 6): case and a Go-style leading v ignored."""
    v = urllib.parse.unquote(version or "")
    if re.match(r"^v\d", v):
        v = v[1:]
    return (image, (vid or "").upper(), (package or "").lower(), v)


def _cdx_findings(doc, comps):
    by_ref = {c.get("bom-ref"): c for c in comps + [c for c in doc.get("components") or [] if isinstance(c, dict)]
              if c.get("bom-ref")}
    out = []
    for v in doc.get("vulnerabilities") or []:
        for a in v.get("affects") or []:
            c = by_ref.get(a.get("ref"), {})
            name, ver = _purl_name_version(c.get("purl") or "")
            if not name:
                name, ver = (c.get("name") or "?"), (c.get("version") or "")
            out.append((v.get("id") or "?", name, ver))
    return out


def read_grype(d):
    doc = _load(os.path.join(d, "result.cdx.json"))
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("Grype's output is not CycloneDX")
    return len(_cdx_packages(doc)), _cdx_findings(doc, [])


def read_scout(d):
    sbom = _load(os.path.join(d, "sbom.json"))
    cves = _load(os.path.join(d, "cves.json"))
    arts = [a for a in sbom.get("artifacts") or [] if isinstance(a, dict) and a.get("name") and (a.get("purl") or a.get("version"))]
    if not isinstance(cves, dict) or not isinstance(cves.get("vulnerabilities"), list):
        raise ValueError("Scout's CVE report has no vulnerabilities list")   # incomplete answer = did not run
    out = []
    for v in cves.get("vulnerabilities") or []:
        ids = [i.get("value") for i in v.get("identifiers") or [] if i.get("value")]
        dep = (v.get("location") or {}).get("dependency") or {}
        out.append((ids[0] if ids else "?", (dep.get("package") or {}).get("name") or "?", dep.get("version") or ""))
    return len(arts), out


def read_inspector(d):
    sbom = _load(os.path.join(d, "sbom.cdx.json"))
    scan = _load(os.path.join(d, "scan.json"))
    if isinstance(scan, dict) and isinstance(scan.get("sbom"), dict):
        scan = scan["sbom"]
    if not isinstance(scan, dict) or scan.get("bomFormat") != "CycloneDX":
        raise ValueError("ScanSbom answer is not CycloneDX")
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("inspector-sbomgen's SBOM is not CycloneDX")
    comps = [c for c in sbom.get("components") or [] if isinstance(c, dict)]
    return len(_cdx_packages(sbom)), _cdx_findings(scan, comps)


def read_google(d):
    pkgs = [p for p in _load(os.path.join(d, "packages.json")) or [] if isinstance(p, dict) and p.get("package") and p.get("version")]
    vulns = _load(os.path.join(d, "vulns.json"))   # no answer = did not run, never "no findings"
    if not isinstance(vulns, list):
        raise ValueError("unexpected shape")
    out = []
    for v in vulns:
        x = v.get("vulnerability") or {}
        vid = x.get("shortDescription") or (v.get("noteName") or "?").rsplit("/", 1)[-1]
        for p in x.get("packageIssue") or [{}]:
            out.append((vid, p.get("affectedPackage") or "?", (p.get("affectedVersion") or {}).get("fullName") or ""))
    return len(pkgs), out


def google_packages(log_text):
    """The packages gcloud extracted locally and sent to on-demand scanning, read from the AnalyzePackages
    request bodies in its --log-http output (the scan answer itself carries no package list)."""
    pkgs = []
    for m in re.finditer(r'"packages"\s*:\s*(\[.*?\])\s*[,}]', log_text, re.S):
        try:
            got = json.loads(m.group(1))
        except ValueError:
            continue
        pkgs += [p for p in got if isinstance(p, dict) and p.get("package")]
    return pkgs


READ = {"grype": read_grype, "scout": read_scout, "inspector": read_inspector, "google": read_google}
FILTER_HERE = ("inspector", "google")   # rule 4: their scan calls cannot read the VEX


def tally(root, vexidx):
    images, findings, covered_log = {}, {}, []
    for s, imgs in EXPECTED.items():
        for img in imgs:
            st = images.setdefault(img, {"counts": {}, "did_not_run": [], "ran": []})
            d = os.path.join(root, s, img)
            try:
                n, found = READ[s](d)
            except (OSError, ValueError, AttributeError, TypeError):
                n, found = 0, []
            if n <= 0:
                st["did_not_run"].append(s)
                continue
            st["counts"][s] = n
            st["ran"].append(s)
            for vid, name, ver in found:
                if s in FILTER_HERE and _gate.covered(vexidx, vid, (name.lower(), ver)):
                    covered_log.append({"image": img, "scanner": s, "id": vid, "package": name, "version": ver})
                    continue
                key = key_of(img, vid, name, ver)
                f = findings.setdefault(key, {"image": img, "id": vid, "package": name, "version": ver, "seen_by": []})
                if s not in f["seen_by"]:
                    f["seen_by"].append(s)
    for img, st in images.items():
        st["did_not_run"].sort(); st["ran"].sort()
        st["counts_for_day"] = len(st["ran"]) >= QUORUM
    not_counted = sorted(i for i, st in images.items() if not st["counts_for_day"])
    scanner_failures = sorted("%s on %s" % (s, i) for i, st in images.items() for s in st["did_not_run"])
    out = []
    for key in sorted(findings):
        f = findings[key]
        f["seen_by"].sort()
        f["of"] = len(images[f["image"]]["ran"])
        f["unique"] = len(f["seen_by"]) == 1
        # rule 5: two or more scanners -> the tracking issue; one scanner -> the auditor's rule-8 audits (rule 9:
        # the AI judging lives in the auditor's daily run; the rescan judges no unique finding)
        f["status"] = "unique" if f["unique"] else "report"
        out.append(f)
    reported = [f for f in out if f["status"] == "report"]
    issue = ""
    if reported:
        lines = ["The daily scanner panel found %d finding(s) on main's candidate that the published VEX does not "
                 "cover, each seen by two or more scanners." % len(reported), ""]
        for f in reported:
            lines.append("- `%s` in `%s %s` on %s — seen by %d of %d (%s)" % (
                f["id"], f["package"], f["version"], f["image"], len(f["seen_by"]), f["of"], ", ".join(f["seen_by"])))
        issue = "\n".join(lines) + "\n"
    # rule 3: a scanner that did not run is a pipeline failure even when the image still has its quorum
    code = 2 if (not_counted or scanner_failures) else (1 if reported else 0)
    return {"images": images, "not_counted": not_counted, "scanner_failures": scanner_failures, "findings": out,
            "unique": [f for f in out if f["unique"]], "vex_covered": covered_log, "issue": issue, "exit": code}


def summary(v):
    rows = ["## Scanner panel", "", "| image | ran | did not run | counts for the day |", "|---|---|---|---|"]
    for img in sorted(v["images"]):
        st = v["images"][img]
        rows.append("| %s | %s | %s | %s |" % (img, ", ".join("%s (%d)" % (s, st["counts"][s]) for s in st["ran"]) or "—",
                                               ", ".join(st["did_not_run"]) or "—", "yes" if st["counts_for_day"] else "**no**"))
    rows += ["", "%d finding(s); %d seen by two or more (reported); %d unique (for the auditor's audits); %d covered by the VEX." % (
        len(v["findings"]), sum(f["status"] == "report" for f in v["findings"]), len(v["unique"]), len(v["vex_covered"]))]
    return "\n".join(rows) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("tally")
    t.add_argument("--in", dest="inp", required=True); t.add_argument("--vex", required=True)
    t.add_argument("--out", required=True)
    g = sub.add_parser("google-packages")
    g.add_argument("log")
    a = ap.parse_args(argv)
    if a.cmd == "google-packages":
        with open(a.log, errors="replace") as f:
            json.dump(google_packages(f.read()), sys.stdout)
        return 0
    v = tally(a.inp, load_vex(a.vex))
    os.makedirs(a.out, exist_ok=True)
    json.dump(v, open(os.path.join(a.out, "verdict.json"), "w"), indent=1)
    open(os.path.join(a.out, "summary.md"), "w").write(summary(v))
    if v["issue"]:
        open(os.path.join(a.out, "issue.md"), "w").write(v["issue"])
    print(summary(v))
    for x in v["scanner_failures"]:
        print("::error::scanner panel: %s did not run — a pipeline failure, never a clean result" % x)
    for img in v["not_counted"]:
        print("::error::scanner panel: %s does not count today — fewer than %d scanners ran on it" % (img, QUORUM))
    return v["exit"]


if __name__ == "__main__":
    sys.exit(main())
