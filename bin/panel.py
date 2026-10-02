#!/usr/bin/env python3
"""The daily rescan's scanner panel judge (scanner-panel rules 3-9, ratified by the owner Oct 2;
REQ-SCAN-003..009). Each scanner job leaves its raw output per image under <in>/<scanner>/<image>/:

  grype      result.cdx.json   CycloneDX from `grype --vex <our VEX> -o cyclonedx-json` (VEX applied by Grype)
  scout      sbom.json         `docker scout sbom --format json`
             cves.json         `docker scout cves --format gitlab --vex-location <our VEX>` (VEX applied by Scout)
  inspector  sbom.cdx.json     inspector-sbomgen's CycloneDX
             scan.json         inspector-scan:ScanSbom's answer ({"sbom": CycloneDX with vulnerabilities})
  google     packages.json     the package list gcloud sent to on-demand scanning
             vulns.json        `gcloud artifacts docker images list-vulnerabilities`

and this judges the day:
  rule 3  every scanner reports its package count; zero, an empty or unreadable output = did not run, never
          clean; an image counts only if at least three scanners ran on it; one that does not fails the run;
  rule 4  Inspector's and Google's results are filtered against our published OpenVEX here (Grype and Scout
          were given the file); a covered finding is recorded as covered, never reported;
  rule 6  one finding per CVE + package + version per image, "seen by N of M" (M = scanners that ran on it);
  rule 5  seen by two or more -> the tracking issue; seen by one ("unique") -> rule 8 first;
  rule 8  a unique finding is presumed false: one audit if it matches a "sees_alone" profile entry, else two
          audits from two different vendors; real only if every audit says real citing evidence from the
          image; an audit that errors cites no evidence, and the error is reported;
  rule 9  false with evidence -> a not_affected VEX proposal citing it; false by default -> logged, no alarm,
          no public statement; a finding judged false before and now seen by two or more is real and an
          "audit miss"; every judged finding is logged with each audit's reasoning.
The audits run here, in the same step that judges (rule 9). Exit: 0 clean, 1 something to report, 2 an image
did not count (the run fails visibly; never reported clean).

usage: panel.py judge --in DIR --vex F --profiles F [--prior F] --out DIR
       panel.py google-packages HTTP_LOG   (the package list gcloud sent, from its --log-http output)
"""
import argparse, datetime, importlib.util, json, os, re, sys, urllib.parse

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
HISTORY_DAYS = 180   # how long a false judgment is remembered for the audit-miss comparison (rule 9)
DISTRO_PURL_TYPES = ("deb", "rpm", "apk", "alpm")   # their purl namespace is the distro, not part of the name
VENDORS = ("vendor_a", "vendor_b")   # rule 8 b: one audit from each of two different vendors (named only in variables)
SCANNERS = tuple(EXPECTED)
KINDS = ("sees_alone", "blind_spot")


def _load(path):
    with open(path) as f:
        text = f.read()
    if not text.strip():
        raise ValueError("empty")
    return json.loads(text)


def load_vex(path):
    return _gate.vex_index(_gate.load(path))


def no_auditor(vendor, finding, image):
    """PR 1: no auditor is configured yet; rule 8 b counts the error as citing no evidence."""
    return {"error": "no auditor configured for %s" % vendor}


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


# ----------------------------------------------------------------------------- profiles (rule 7)

def validate_profiles(doc):
    errs = []
    for i, e in enumerate((doc or {}).get("entries") or []):
        where = "entry %d" % i
        if e.get("scanner") not in SCANNERS:
            errs.append("%s: scanner %r is not one of %s" % (where, e.get("scanner"), ", ".join(SCANNERS)))
        if e.get("kind") not in KINDS:
            errs.append("%s: kind %r is not one of %s" % (where, e.get("kind"), ", ".join(KINDS)))
        for k in ("behavior", "finding", "evidence"):
            if not str(e.get(k) or "").strip():
                errs.append("%s: no %s (an entry cites the finding and the evidence from the image)" % (where, k))
        pat = (e.get("match") or {}).get("package")
        if e.get("kind") == "sees_alone" and not pat:
            errs.append("%s: a sees_alone entry needs match.package" % where)
        if pat:
            try:
                re.compile(pat)
            except re.error as x:
                errs.append("%s: match.package is not a regular expression (%s)" % (where, x))
    return errs


def _profile_match(profiles, scanner, package):
    for e in (profiles or {}).get("entries") or []:
        if e.get("scanner") == scanner and e.get("kind") == "sees_alone" \
                and re.search((e.get("match") or {}).get("package") or "(?!)", package or ""):
            return e
    return None


# ----------------------------------------------------------------------------- the day's judgment

def _audit(audit, vendor, finding, image, errors):
    try:
        a = audit(vendor, finding, image) or {}
    except Exception as e:   # an audit that fails is an error, never a vote
        a = {"error": "%s: %s" % (type(e).__name__, e)}
    a = dict(a, vendor=vendor)
    if a.get("error"):
        errors.append("%s on %s %s: %s" % (vendor, image, finding["id"], a["error"]))
        a = {"vendor": vendor, "error": a["error"]}   # an errored audit casts no vote and cites no evidence
    return a


def judge(root, vexidx, profiles, audit, prior, today=None):
    images, findings, covered_log, errors = {}, {}, [], []
    for s, imgs in EXPECTED.items():
        for img in imgs:
            st = images.setdefault(img, {"counts": {}, "did_not_run": [], "ran": []})
            d = os.path.join(root, s, img)
            try:
                n, found = READ[s](d)
            except (OSError, ValueError, AttributeError, TypeError) as e:
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
    today = today or datetime.date.today().isoformat()
    cutoff = (datetime.date.fromisoformat(today) - datetime.timedelta(days=HISTORY_DAYS)).isoformat()
    earlier_false, earlier_real = {}, {}
    for kind, into in (("false", earlier_false), ("real", earlier_real)):
        for x in (prior or {}).get(kind) or []:
            if not isinstance(x, dict) or str(x.get("since") or today) < cutoff:
                continue
            into[key_of(x.get("image"), x.get("id"), x.get("package"), x.get("version"))] = x
    out, log, proposals, misses, false_now = [], [], [], [], []
    for key in sorted(findings):
        f = findings[key]
        f["seen_by"].sort()
        f["of"] = len(images[f["image"]]["ran"])
        f["unique"] = len(f["seen_by"]) == 1
        f["audits"], f["why"] = [], None
        before = earlier_false.get(key)
        ever = sorted(set(f["seen_by"]) | set((before or {}).get("seen_by") or []) | set((earlier_real.get(key) or {}).get("seen_by") or []))
        if key in earlier_real:
            # once real, it stays real while it is present: a later day with one scanner does not re-presume it false
            f["status"], f["seen_ever"] = "report", ever
        elif before is not None and len(ever) >= 2:
            # judged false earlier, and now another scanner reports it (today or on another day): real (rule 9)
            f["status"], f["miss"], f["seen_ever"] = "report", True, ever
            misses.append({k: f[k] for k in ("image", "id", "package", "version", "seen_by")})
        elif not f["unique"]:
            f["status"] = "report"
        else:
            entry = _profile_match(profiles, f["seen_by"][0], f["package"])
            vendors = VENDORS[:1] if entry else VENDORS
            f["path"] = "a" if entry else "b"
            f["audits"] = [_audit(audit, v, f, f["image"], errors) for v in vendors]
            real = all(a.get("verdict") == "real" and str(a.get("evidence") or "").strip() for a in f["audits"])
            false_ev = [a for a in f["audits"] if a.get("verdict") == "false" and str(a.get("evidence") or "").strip()]
            if real:
                f["status"] = "report"
                f["why"] = next((a.get("why") for a in f["audits"] if a.get("why")), None) or "unexplained"
            elif false_ev:
                f["status"] = "false-evidence"
                proposals.append({"vulnerability": f["id"], "package": f["package"], "version": f["version"],
                                  "image": f["image"], "status": "not_affected",
                                  "justification_evidence": false_ev[0]["evidence"]})
            else:
                f["status"] = "false-default"
            if f["status"] != "report":
                false_now.append(dict({k: f[k] for k in ("image", "id", "package", "version")},
                                      seen_by=ever, since=(before or {}).get("since") or today))
            log.append(f)
        out.append(f)
    reported = [f for f in out if f["status"] == "report"]
    issue = ""
    if reported:
        lines = ["The daily scanner panel found %d finding(s) on main's candidate that the published VEX does not "
                 "cover (seen by two or more scanners, or a unique finding the audits confirmed)." % len(reported), ""]
        for f in reported:
            lines.append("- `%s` in `%s %s` on %s — seen by %d of %d (%s)%s" % (
                f["id"], f["package"], f["version"], f["image"], len(f["seen_by"]), f["of"], ", ".join(f["seen_by"]),
                "; **audit miss** (judged false on an earlier day)" if f.get("miss") else ""))
        if misses:
            lines += ["", "%d audit miss(es): a finding judged false earlier is now seen by two or more scanners. "
                      "Reported to the owner (rule 9)." % len(misses)]
        issue = "\n".join(lines) + "\n"
    # remembered false judgments not seen today are carried forward (an intervening day must not erase them)
    seen_today = {key_of(f["image"], f["id"], f["package"], f["version"]) for f in out}
    false_now += [x for k, x in sorted(earlier_false.items()) if k not in seen_today]
    real_now = [dict({k: f[k] for k in ("image", "id", "package", "version")}, seen_by=f.get("seen_ever") or f["seen_by"],
                     since=(earlier_real.get(key_of(f["image"], f["id"], f["package"], f["version"])) or {}).get("since") or today)
                for f in out if f["status"] == "report"]
    real_now += [x for k, x in sorted(earlier_real.items()) if k not in seen_today]
    # rule 3: a scanner that did not run is a pipeline failure even when the image still has its quorum
    code = 2 if (not_counted or scanner_failures) else (1 if reported else 0)
    return {"images": images, "not_counted": not_counted, "scanner_failures": scanner_failures, "findings": out, "vex_covered": covered_log,
            "issue": issue, "exit": code, "audit_errors": errors, "vex_proposals": proposals, "log": log,
            "misses": misses, "judgments": {"false": false_now, "real": real_now}}


def summary(v):
    rows = ["## Scanner panel", "", "| image | ran | did not run | counts for the day |", "|---|---|---|---|"]
    for img in sorted(v["images"]):
        st = v["images"][img]
        rows.append("| %s | %s | %s | %s |" % (img, ", ".join("%s (%d)" % (s, st["counts"][s]) for s in st["ran"]) or "—",
                                               ", ".join(st["did_not_run"]) or "—", "yes" if st["counts_for_day"] else "**no**"))
    rows += ["", "%d finding(s); %d reported; %d unique judged false; %d covered by the VEX; %d audit error(s); %d audit miss(es)." % (
        len(v["findings"]), sum(f["status"] == "report" for f in v["findings"]),
        sum(f["status"].startswith("false") for f in v["findings"]), len(v["vex_covered"]),
        len(v["audit_errors"]), len(v["misses"]))]
    rows += ["- audit error: %s" % e for e in v["audit_errors"]]
    return "\n".join(rows) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("judge")
    j.add_argument("--in", dest="inp", required=True); j.add_argument("--vex", required=True)
    j.add_argument("--profiles", required=True); j.add_argument("--prior"); j.add_argument("--out", required=True)
    g = sub.add_parser("google-packages")
    g.add_argument("log")
    a = ap.parse_args(argv)
    if a.cmd == "google-packages":
        with open(a.log, errors="replace") as f:
            json.dump(google_packages(f.read()), sys.stdout)
        return 0
    profiles = _gate.load(a.profiles)
    errs = validate_profiles(profiles)
    if errs:
        for e in errs:
            print("::error::scanner profiles: %s" % e)
        return 2
    prior = {"false": []}
    if a.prior and os.path.exists(a.prior):
        try:
            prior = _gate.load(a.prior)
        except (OSError, ValueError):
            print("::warning::yesterday's judgments are unreadable; no audit-miss comparison today")
    v = judge(a.inp, load_vex(a.vex), profiles, no_auditor, prior)
    os.makedirs(a.out, exist_ok=True)
    json.dump(v, open(os.path.join(a.out, "verdict.json"), "w"), indent=1)
    json.dump(v["judgments"], open(os.path.join(a.out, "judgments.json"), "w"), indent=1)
    open(os.path.join(a.out, "summary.md"), "w").write(summary(v))
    if v["issue"]:
        open(os.path.join(a.out, "issue.md"), "w").write(v["issue"])
    print(summary(v))
    for x in v["scanner_failures"]:
        print("::error::scanner panel: %s did not run — a pipeline failure, never a clean result" % x)
    for img in v["not_counted"]:
        print("::error::scanner panel: %s does not count today — fewer than %d scanners ran on it" % (img, QUORUM))
    for e in v["audit_errors"]:
        print("::warning::scanner panel audit error: %s" % e)
    return v["exit"]


if __name__ == "__main__":
    sys.exit(main())
