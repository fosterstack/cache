#!/usr/bin/env python3
"""The daily rescan's scanner panel tally (scanner-panel rules 3-6, ratified by the owner Oct 2; REQ-SCAN-003..006).
Each scanner job leaves its raw output per image under <scanner>/<image>/ in its own artifact panel-<scanner>; the download lays them out as <in>/panel-<scanner>/<scanner>/<image>/ (one folder per artifact, never merged):

  grype      result.cdx.json   CycloneDX from `grype --vex <our VEX> -o cyclonedx-json` (VEX applied by Grype)
  scout      sbom.json         `docker scout sbom --format json`
             cves.json         `docker scout cves --format gitlab --vex-author '^FosterStack LLC$' registry://<image>`
                               (Scout applies our VEX through the attestation in the image index, REQ-REL-010;
                               there is no --vex-location)
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

VARIANTS = ("production", "fips")
# rule 1, fixed here as in the workflow: Grype, Scout and Inspector on all four images (production and fips); Google on linux/amd64 only
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


def _product_id(p):
    """A product's identifier as the PR gate's vex_index reads it: @id when the key is present, else identifiers.purl."""
    ids = p.get("identifiers")
    return p.get("@id") if p.get("@id") is not None else ((ids.get("purl") if isinstance(ids, dict) else None) or "")   # an @id that is present (even "") is the id, as the rescan reads it


def _covers(product, image):
    """Does a statement's product cover this image? The repository-wide product covers every image; a product scoped
    with variant= / arch= qualifiers (the auditor's per-image statements) covers only the image it names. The product is
    read by the PR gate's own grammar (inspector-gate.py::scope_of, the rescan's _parse_product): a product it does not
    accept (a repeated, upper-case, blank, encoded or unknown qualifier, a pinned or foreign product) covers NO image, and an
    OCI product must be this image's own repository (pkg:oci/cache, never cache-candidates), as rescan-statement.py::_vex_match requires."""
    pid = str(product)
    scope = _gate.scope_of(pid)
    if scope is None or (pid.startswith("pkg:oci/") and pid.split("?", 1)[0] != "pkg:oci/cache"):
        return False
    variant, _, arch = image.rpartition("-")
    return scope.get("variant", variant) == variant and scope.get("arch", arch) == arch


def load_vex(path):
    """Per-image VEX indexes ({image: index}): each image is filtered only by the statements whose product covers it,
    with purl versions decoded (%2B is +) so a statement matches the version the scanner reports."""
    doc = _gate.load(path)
    out = {}
    for img in sorted({i for imgs in EXPECTED.values() for i in imgs}):
        stmts = []
        for st in doc.get("statements") or []:
            prods = [p for p in st.get("products") or [] if _covers(_product_id(p), img)]
            if not prods:
                continue
            for p in prods:
                for sub in p.get("subcomponents") or []:
                    if "@id" in sub:
                        sub["@id"] = urllib.parse.unquote(sub["@id"].split("?", 1)[0]) + (
                            "?" + sub["@id"].split("?", 1)[1] if "?" in sub["@id"] else "")
            stmts.append(dict(st, products=prods))
        out[img] = _gate.vex_index(dict(doc, statements=stmts))
    return out


# ----------------------------------------------------------------------------- readers: (count, findings)

def _is_package_url(purl):   # pkg:deb/debian/glibc@2.36 is one; "not-a-purl", "pkg:" and "pkg:/" are not: a type, a slash, then a name
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return False
    slash = purl.find("/", 4)
    return 4 < slash < len(purl) - 1


def _cdx_packages(doc):
    """Rule 3's package count: components that are packages (carry a package URL, pkg:<type>/<name>). Grype's CycloneDX also
    lists every file it catalogued as a component (946 of 965 on production-amd64, run 36957462057)."""
    return [c for c in doc.get("components") or [] if isinstance(c, dict) and _is_package_url(c.get("purl"))]


def _purl_name_version(purl):
    """(name, version) from a package URL, as the other scanners name it: a distro package without its distro
    namespace (pkg:deb/debian/libc-bin -> libc-bin), a Go module by its full path; the version un-escaped."""
    name, ver = _gate.name_version(purl)
    if (purl or "").startswith("pkg:") and (purl[4:].split("/", 1)[0] in DISTRO_PURL_TYPES):
        name = name.rsplit("/", 1)[-1]
    return name, urllib.parse.unquote(ver)


_NOCTL = r"[^\s\x00-\x1f\x7f"
_PURL_RE = re.compile(r"pkg:[a-z][a-z0-9.+-]*/" + _NOCTL + r"?#@]+(@" + _NOCTL + r"?#]+)?"                      # type/namespace/name @ version (not empty)
                      r"(\?[A-Za-z][A-Za-z0-9._-]*=" + _NOCTL + r"&#]+(&[A-Za-z][A-Za-z0-9._-]*=" + _NOCTL + r"&#]+)*)?"   # ?key=value&key=value (values not empty)
                      r"(#" + _NOCTL + r"]+)?")                                                                           # #subpath (not empty)


def purl_ok(purl):
    """The package-URL grammar the verdict allows (the auditor reads the same rule from here): a regular expression plus the one thing it
    cannot state, that a qualifier key appears once."""
    if not isinstance(purl, str) or not _PURL_RE.fullmatch(purl):
        return False
    q = purl.partition("#")[0].partition("?")[2]
    keys = [kv.partition("=")[0] for kv in q.split("&")] if q else []
    return len(set(keys)) == len(keys)


def key_of(image, vid, package, version):
    """One finding per CVE + package + version per image (rule 6): case and a Go-style leading v ignored."""
    v = urllib.parse.unquote(version or "")
    if re.match(r"^v\d", v):
        v = v[1:]
    return (image, (vid or "").upper(), (package or "").lower(), v)


SEVERITIES = ("negligible", "low", "medium", "high", "critical")
_SEV_WORDS = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low",
              "negligible": "negligible", "minimal": "negligible", "info": "negligible", "informational": "negligible"}


def norm_severity(x):
    """A scanner's severity word as one of SEVERITIES; an unknown, unspecified or non-text value is None (absent, never guessed)."""
    return _SEV_WORDS.get(x.strip().lower()) if isinstance(x, str) else None


def _top(sevs):
    """The highest of several normalised severities, or None."""
    got = [s for s in sevs if s in SEVERITIES]
    return max(got, key=SEVERITIES.index) if got else None


def _extra(severity=None, fixed=None, aliases=(), vid=None, known_exploited=False):
    """One scanner's own facts about a finding; a key is present only when the scanner reported it."""
    out = {}
    if severity:
        out["severity"] = severity
    if known_exploited:
        out["known_exploited"] = True
    if isinstance(fixed, str) and fixed:
        out["fixed_version"] = fixed
    al = []
    for a in aliases:
        if isinstance(a, str) and a and a != vid and a not in al:
            al.append(a)
    if al:
        out["aliases"] = al
    return out


def _cdx_findings(doc, comps, inspector=False):
    by_ref = {c.get("bom-ref"): c for c in comps + [c for c in doc.get("components") or [] if isinstance(c, dict)]
              if c.get("bom-ref")}
    out = []
    for v in doc.get("vulnerabilities") or []:
        affects = v.get("affects") or []
        if not affects or not all(isinstance(a, dict) for a in affects):   # a vulnerability nobody can attribute (none, or an entry that is not an object) is an incomplete report: did not run, never silence
            raise ValueError("vulnerability %s has no usable affects list: the report is incomplete" % (v.get("id") or "?"))
        for a in affects:
            c = by_ref.get(a.get("ref"))
            if c is None:   # a finding that names no component of the report cannot be attributed: incomplete, never a nameless "?" finding
                raise ValueError("vulnerability %s affects %r, which is not a component of the report: the report is incomplete" % (v.get("id") or "?", a.get("ref")))
            name, ver = _purl_name_version(c.get("purl") or "")
            if not name:
                name, ver = (c.get("name") or "?"), (c.get("version") or "")
            if name == "?":   # the component has neither a package URL nor a name: still a finding nobody can attribute
                raise ValueError("vulnerability %s affects the component %r, which has neither a package URL nor a name: the report is incomplete" % (v.get("id") or "?", a.get("ref")))
            # Grype writes its CISA KEV listing as a rating (source 'CISA KEV Catalog', method other, justification 'Listed in CISA KEV'): that is the known-exploited
            # marker, not a severity; its 'Negligible' is CycloneDX 'none'
            rts = [r for r in v.get("ratings") or [] if isinstance(r, dict)]
            is_kev = lambda r: (r.get("method") == "other" and r.get("justification") == "Listed in CISA KEV"
                                and isinstance(r.get("source"), dict) and r["source"].get("name") == "CISA KEV Catalog")     # exactly Grype v0.118.0's emitter (grype/presenter/cyclonedx/vulnerability.go)
            word = lambda r: (r.get("severity").strip().lower() if isinstance(r.get("severity"), str) else None)
            sev = _top((norm_severity(r.get("severity")) or ("negligible" if word(r) == "none" else None))
                       for r in rts if not is_kev(r))
            # CycloneDX 'unaffected' versions say which versions are not affected, not that one contains the fix: no fixed version from them.
            # Inspector documents its own properties: the fixed version per affected component and the CISA KEV date.
            fixed, kev = None, any(is_kev(r) for r in rts)
            if inspector:
                pre = "amazon:inspector:sbom_scanner:"
                props = {p_.get("name"): p_.get("value") for p_ in v.get("properties") or [] if isinstance(p_, dict)}
                fixed = props.get(pre + "fixed_version:" + str(a.get("ref")))
                kev = kev or bool(props.get(pre + "cisa_kev_date_added"))
            al = [r.get("id") for r in v.get("references") or [] if isinstance(r, dict)]
            out.append((v.get("id") or "?", name, ver, c.get("purl"), _extra(sev, fixed, al, v.get("id"), kev)))
    return out


def read_grype(d):
    doc = _load(os.path.join(d, "result.cdx.json"))
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("Grype's output is not CycloneDX")
    return len(_cdx_packages(doc)), _cdx_findings(doc, [])


def read_scout(d):
    sbom = _load(os.path.join(d, "sbom.json"))
    cves = _load(os.path.join(d, "cves.json"))
    arts = [a for a in sbom.get("artifacts") or []
            if isinstance(a, dict) and a.get("name") and _is_package_url(a.get("purl"))]
    if not isinstance(cves, dict) or not isinstance(cves.get("vulnerabilities"), list):
        raise ValueError("Scout's CVE report has no vulnerabilities list")   # incomplete answer = did not run
    out = []
    for v in cves.get("vulnerabilities") or []:
        ids = [i.get("value") for i in v.get("identifiers") or [] if i.get("value")]
        dep = (v.get("location") or {}).get("dependency") or {}
        name, ver = (dep.get("package") or {}).get("name") or "?", dep.get("version") or ""
        purl = None
        if name.startswith("pkg:"):   # Scout's GitLab report puts the package URL in name (scout-selfcheck.py:124): name it as the other scanners do
            purl = name
            name, pver = _purl_name_version(purl)
            ver = ver or pver
        purl = purl or next((a.get("purl") for a in arts if a.get("name") == name and a.get("version") == ver and a.get("purl")), None)
        out.append((ids[0] if ids else "?", name, ver, purl, _extra(norm_severity(v.get("severity")), None, ids[1:], ids[0] if ids else None)))
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
    return len(_cdx_packages(sbom)), _cdx_findings(scan, comps, inspector=True)


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
            out.append((vid, p.get("affectedPackage") or "?", (p.get("affectedVersion") or {}).get("fullName") or "", None,
                        _extra(norm_severity(p.get("effectiveSeverity")) or norm_severity(x.get("severity")),      # the package-level severity wins
                               (p.get("fixedVersion") or {}).get("fullName"), (), vid,
                               isinstance(x.get("risk"), dict) and "cisaKev" in x["risk"])))
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


def render_issue(reported):
    """The tracking issue's text for the findings seen by two or more scanners (rule 5); empty when there are none.
    One renderer: the tally writes it and the auditor's verdict validator compares against it."""
    if not reported:
        return ""
    lines = ["The daily scanner panel found %d finding(s) on main's candidate that the published VEX does not "
             "cover, each seen by two or more scanners." % len(reported), ""]
    for f in reported:
        lines.append("- `%s` in `%s %s` on %s — seen by %d of %d (%s)" % (
            f["id"], f["package"], f["version"], f["image"], len(f["seen_by"]), f["of"], ", ".join(f["seen_by"])))
    return "\n".join(lines) + "\n"


# a scanner's diagnostics the producing job writes beside its results (Scout's raw attestation reports); read by nobody here, allowed so the real artifact is not refused
DIAG = {"scout": {"scout-diag"}}


class LayoutError(Exception):
    pass


def scanner_dirs(inp):
    """The downloaded artifacts laid out as <inp>/panel-<scanner>/<scanner>/<image>/ (one folder per artifact, never merged): {scanner: the folder holding its images}.
    A folder that is not panel-<one of the panel's scanners>, a plain file or a link there, an artifact folder holding anything but its own scanner's folder (another scanner's
    output, a stray file) is refused: one scanner's job can never write another scanner's result. A scanner with no artifact is simply absent (the tally calls it did-not-run)."""
    dirs = {}
    try:
        names = sorted(os.listdir(inp))
    except OSError as ex:
        raise LayoutError("the panel artifacts folder %s cannot be read (%s)" % (inp, type(ex).__name__))
    for n in names:
        path = os.path.join(inp, n)
        scanner = n[len("panel-"):] if n.startswith("panel-") else None
        if scanner not in EXPECTED or os.path.islink(path) or not os.path.isdir(path):
            raise LayoutError("%s is not the artifact of a panel scanner (expected a plain folder panel-%s)" % (n, "|".join(sorted(EXPECTED))))
        inner = sorted(os.listdir(path))
        if inner and scanner not in inner and all(x in DIAG.get(scanner, set()) and not os.path.islink(os.path.join(path, x)) and os.path.isdir(os.path.join(path, x)) for x in inner):
            continue    # only its diagnostics (every image failed and its step removed the partial output): a scanner with no results, which the tally calls did-not-run
        if [x for x in inner if x not in ({scanner} | DIAG.get(scanner, set()))] or scanner not in inner:
            raise LayoutError("%s holds %s, not only %s%s: one scanner's artifact never carries another scanner's output" % (n, " ".join(inner) or "nothing", scanner, (" and " + " ".join(sorted(DIAG[scanner]))) if scanner in DIAG else ""))
        for x in inner:
            if x != scanner and (os.path.islink(os.path.join(path, x)) or not os.path.isdir(os.path.join(path, x))):
                raise LayoutError("%s/%s is not a plain folder" % (n, x))
        sub = os.path.join(path, scanner)
        if os.path.islink(sub) or not os.path.isdir(sub):
            raise LayoutError("%s/%s is not a plain folder" % (n, scanner))
        dirs[scanner] = sub
    return dirs


def tally(root, vexidx, dirs=None):
    images, findings, covered_log = {}, {}, []
    for s, imgs in EXPECTED.items():
        for img in imgs:
            st = images.setdefault(img, {"counts": {}, "did_not_run": [], "ran": []})
            d = os.path.join(root, s, img) if dirs is None else os.path.join(dirs[s], img) if s in dirs else None     # no artifact for the scanner: it did not run
            try:
                n, found = READ[s](d)
            except (OSError, ValueError, AttributeError, TypeError):
                n, found = 0, []
            if n <= 0:
                st["did_not_run"].append(s)
                continue
            st["counts"][s] = n
            st["ran"].append(s)
            for vid, name, ver, purl, extra in found:
                if purl and not purl_ok(purl):
                    purl = None           # a package URL outside the verdict's grammar is dropped, never written (the finding still counts)
                if s in FILTER_HERE and _gate.covered(vexidx[img], vid, (name.lower(), ver)):
                    covered_log.append({"image": img, "scanner": s, "id": vid, "package": name, "version": ver})
                    continue
                key = key_of(img, vid, name, ver)
                f = findings.setdefault(key, {"image": img, "id": vid, "package": name, "version": ver, "seen_by": [],
                                              "purls": [], "details": {}})
                if s not in f["seen_by"]:
                    f["seen_by"].append(s)
                have = f["details"].setdefault(s, {})        # this scanner's own record; a repeated entry is merged, never dropped
                if extra.get("severity"):
                    have["severity"] = _top([have.get("severity"), extra["severity"]])      # the highest, in either order
                if extra.get("fixed_version"):
                    have.setdefault("fixed_version", extra["fixed_version"])
                if extra.get("aliases"):
                    have["aliases"] = list(have.get("aliases", [])) + [a_ for a_ in extra["aliases"] if a_ not in have.get("aliases", [])]
                if extra.get("known_exploited"):
                    have["known_exploited"] = True
                if purl and purl not in f["purls"]:
                    f["purls"].append(purl)   # the exact package identity, for a VEX statement scoped to it
                if purl and "purl" not in have:
                    have["purl"] = purl       # and THIS scanner's own (handoff 0601): absent when it reported none, never another scanner's
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
    issue = render_issue(reported)
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
    try:
        dirs = scanner_dirs(a.inp)
    except LayoutError as ex:
        print("::error::scanner panel: %s — a pipeline failure, never a clean result" % ex)
        return 2
    v = tally(a.inp, load_vex(a.vex), dirs)
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
