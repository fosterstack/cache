"""Scanner/evidence parsers for the daily CVE auditor.

Each parser returns a list of findings keyed EXACTLY by (scanner, finding_id, purl)
verbatim as the scanner emits them, with the scanner-reported alias set attached.
No normalization, no string surgery: a DEBIAN-CVE id is matched to a CVE only
through OSV's own aliases, never by editing the string. A malformed report raises
ParseError rather than guessing. (Round-2 design rule: code does only what is exact.)
"""
import json


class ParseError(ValueError):
    pass


def _load(path):
    try:
        return json.load(open(path))
    except Exception as e:
        raise ParseError("cannot load %s: %s" % (path, e))


def _finding(scanner, fid, purl, aliases=(), package=None, fixed_version=None,
             severity=None, extra=None):
    if not fid:
        raise ParseError("%s: finding with no id" % scanner)
    return {
        "scanner": scanner,
        "finding_id": fid,
        "purl": purl,
        "aliases": sorted({a for a in ([fid] + list(aliases)) if a}),
        "package": package,
        "fixed_version": fixed_version,
        "severity": severity,
        "extra": extra or {},
    }


def parse_grype(path):
    d = _load(path)
    if "matches" not in d or not isinstance(d["matches"], list):
        raise ParseError("grype: no matches array")
    out = []
    for m in d["matches"]:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        rel = [r.get("id") for r in m.get("relatedVulnerabilities", []) if r.get("id")]
        fix = v.get("fix") or {}
        fv = None
        if fix.get("state") == "fixed" and fix.get("versions"):
            fv = fix["versions"][0]
        out.append(_finding("grype", v.get("id"), a.get("purl"), rel,
                            a.get("name"), fv, v.get("severity"),
                            {"fix_state": fix.get("state"),
                             "known_exploited": v.get("knownExploited")}))
    return out


def parse_trivy(path):
    d = _load(path)
    if "Results" not in d:
        raise ParseError("trivy: no Results")
    out = []
    for r in d.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            purl = (v.get("PkgIdentifier") or {}).get("PURL")
            # Trivy carries no cross-id aliases; the VulnerabilityID stands alone.
            out.append(_finding("trivy", v.get("VulnerabilityID"), purl, (),
                                v.get("PkgName"), v.get("FixedVersion") or None,
                                v.get("Severity"),
                                {"status": v.get("Status")}))
    return out


def _osv_purl(pkg):
    eco = (pkg.get("ecosystem") or "").lower().split(":")[0]
    name = pkg.get("name")
    ver = pkg.get("version")
    if not (eco and name):
        return None
    base = {"go": "pkg:golang/%s" % name, "debian": "pkg:deb/debian/%s" % name}.get(eco)
    if not base:
        base = "pkg:%s/%s" % (eco, name)
    return base + ("@%s" % ver if ver else "")


def parse_osv(path, scanner="osv-scanner"):
    d = _load(path)
    if "results" not in d:
        raise ParseError("osv: no results")
    out = []
    for r in d.get("results") or []:
        for p in r.get("packages") or []:
            pkg = p.get("package") or {}
            purl = _osv_purl(pkg)
            groups = p.get("groups") or []
            for v in p.get("vulnerabilities") or []:
                fid = v.get("id")
                al = set(v.get("aliases") or [])
                for g in groups:
                    if fid in (g.get("ids") or []):
                        al.update(g.get("aliases") or [])
                        al.update(g.get("ids") or [])
                fixed = None
                for aff in v.get("affected") or []:
                    for rng in aff.get("ranges") or []:
                        for ev in rng.get("events") or []:
                            if ev.get("fixed"):
                                fixed = ev["fixed"]
                out.append(_finding(scanner, fid, purl, al, pkg.get("name"),
                                    fixed, None,
                                    {"ecosystem": pkg.get("ecosystem"),
                                     "installed_version": pkg.get("version")}))
    return out


def parse_snyk(path):
    d = _load(path)
    if "vulnerabilities" not in d and "applications" not in d:
        raise ParseError("snyk: no vulnerabilities or applications")
    out = []
    def emit(v):
        cves = (v.get("identifiers") or {}).get("CVE") or []
        out.append(_finding("snyk", v.get("id"), v.get("purl"), cves,
                            v.get("packageName"), v.get("nearestFixedInVersion") or None,
                            v.get("severity")))
    for v in d.get("vulnerabilities") or []:
        emit(v)
    for app in d.get("applications") or []:
        for v in app.get("vulnerabilities") or []:
            emit(v)
    return out


def _stream(text):
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \n\r\t":
            i += 1
        if i >= n:
            break
        obj, j = dec.raw_decode(text, i)
        yield obj
        i = j


def parse_govulncheck(path):
    """Return {osv_id: {'reachable': bool}} for every finding message in the stream.
    'reachable' is True iff some trace frame names a function (a real call path).
    A finding id absent from the stream is absent from this dict — the caller must
    treat that as 'no evidence', never as 'not reachable'."""
    try:
        text = open(path).read()
    except Exception as e:
        raise ParseError("govulncheck: cannot read %s: %s" % (path, e))
    by_osv = {}
    scan_level = None
    module = None
    saw_any = False
    for obj in _stream(text):
        if not isinstance(obj, dict):
            raise ParseError("govulncheck: non-object in stream")
        saw_any = True
        if "config" in obj:
            scan_level = (obj["config"] or {}).get("scan_level")
        if "SBOM" in obj:
            roots = (obj["SBOM"] or {}).get("roots") or []
            if roots:
                module = roots[0]
        f = obj.get("finding")
        if not f:
            continue
        osv = f.get("osv")
        if not osv:
            raise ParseError("govulncheck: finding with no osv id")
        # A REAL frame names a module, package, or function; a bare {} is not a frame
        # (R11 rank 2: `[{}]` is not a trace). A function-bearing frame is a real call
        # path; a non-empty trace of real frames WITHOUT a function is imported-but-not-
        # called; an empty (or all-bare) trace proves nothing.
        trace = [fr for fr in f.get("trace", [])
                 if isinstance(fr, dict) and (fr.get("module") or fr.get("package") or fr.get("function"))]
        called = any(fr.get("function") for fr in trace)
        imported_only = bool(trace) and not called
        cur = by_osv.get(osv, {"reachable": False, "imported_only": False})
        by_osv[osv] = {"reachable": cur["reachable"] or called,
                       "imported_only": cur["imported_only"] or imported_only}
    if not saw_any:
        raise ParseError("govulncheck: empty stream")
    return {"scan_level": scan_level, "module": module, "by_osv": by_osv}


def parse_kev(path):
    d = _load(path)
    if "vulnerabilities" not in d:
        raise ParseError("kev: no vulnerabilities")
    ids = set()
    for v in d["vulnerabilities"]:
        cid = v.get("cveID")
        if not cid:
            raise ParseError("kev: entry with no cveID")
        ids.add(cid)
    return ids
