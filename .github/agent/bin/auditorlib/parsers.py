"""Scanner/evidence parsers for the daily CVE auditor.

Each parser returns a list of findings keyed EXACTLY by (scanner, finding_id, purl)
verbatim as the scanner emits them, with the scanner-reported alias set attached.
No normalization, no string surgery: a DEBIAN-CVE id is matched to a CVE only
through OSV's own aliases, never by editing the string. A malformed report raises
ParseError rather than guessing. (Round-2 design rule: code does only what is exact.)
"""
import json, re
from auditorlib import policy


class ParseError(ValueError):
    pass


def _load(path):
    try:
        return json.load(open(path))
    except Exception as e:
        raise ParseError("cannot load %s: %s" % (path, e))


def _finding(scanner, fid, purl, aliases=(), package=None, fixed_version=None,
             severity=None, extra=None):
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


PANEL_SCANNERS = ("grype", "scout", "inspector", "google")
_PANEL = []


def _panel_module():
    """bin/panel.py (the rescan's tally) is the one source of the fixed scanner/image matrix and the quorum; it is
    loaded from the same checkout rather than copied here. Unloadable = ParseError (fail closed)."""
    if not _PANEL:
        import importlib.util, os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "bin", "panel.py")
        try:
            spec = importlib.util.spec_from_file_location("_panel_matrix", path)
            mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
            assert set(mod.EXPECTED) == set(PANEL_SCANNERS) and isinstance(mod.QUORUM, int)
        except Exception as e:
            raise ParseError("cannot load the panel's scanner/image matrix from bin/panel.py: %s" % e)
        _PANEL.append(mod)
    return _PANEL[0]


def panel_images():
    """The set of images the panel scans (every image any scanner is expected on)."""
    return {i for imgs in _panel_module().EXPECTED.values() for i in imgs}


def panel_expected(scanner, image):
    """Scanner-panel rule 1, from bin/panel.py: is `scanner` expected on `image`? (Google: linux/amd64 only.)"""
    return image in _panel_module().EXPECTED.get(scanner, [])


def _no_dup_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ParseError("panel verdict: the JSON key %r appears twice (the last would silently win)" % k)
        out[k] = v
    return out


def _refuse_constant(name):
    raise ParseError("panel verdict: %s is not valid JSON" % name)


def load_panel_verdict(path):
    """The one loader for verdict.json: strict JSON (a repeated key at any level, NaN and Infinity are refused), so no
    reader can see a different document from the one a stricter reader refuses. OSError for a missing file."""
    with open(path) as fh:
        try:
            return json.load(fh, object_pairs_hook=_no_dup_pairs, parse_constant=_refuse_constant)
        except RecursionError as e:
            raise ParseError("panel verdict: nested too deeply (%s)" % e)


_TOP_KEYS = frozenset(("images", "not_counted", "scanner_failures", "findings", "unique", "vex_covered", "issue", "exit"))
_IMAGE_KEYS = frozenset(("counts", "did_not_run", "ran", "counts_for_day"))
_FINDING_KEYS = frozenset(("image", "id", "package", "version", "seen_by", "of", "unique", "status", "purls", "details"))
_DETAIL_KEYS = frozenset(("severity", "fixed_version", "aliases", "known_exploited", "purl"))
_SEVERITIES = ("negligible", "low", "medium", "high", "critical")       # bin/panel.py SEVERITIES, in rising order
_VEX_KEYS = frozenset(("image", "scanner", "id", "package", "version"))
_TEXT = re.compile(r"[^\x00-\x1f\x7f`]*")            # no control characters, no backtick (the issue text quotes with it)
_ID = policy.FINDING_ID          # CVE-, GHSA-, DEBIAN-CVE-, GO- ids; the tally's "?" for an id-less result; capped, and the same grammar the unsettled-run counter keeps
_NOCTL = r"[^\s\x00-\x1f\x7f"
class _PurlGrammar:
    """The package-URL grammar the verdict allows: one rule, defined where the tally writes the URLs (bin/panel.py purl_ok)."""
    @staticmethod
    def fullmatch(purl):
        return True if _panel_module().purl_ok(purl) else None


_PURL = _PurlGrammar


def _closed(obj, keys, what):
    if not isinstance(obj, dict) or set(obj) != keys:
        raise ParseError("panel verdict: %s has missing or unknown keys" % what)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_count(v):
    return _is_int(v) and v > 0


def validate_panel_verdict(d):
    """See _validate_panel_verdict; any type error in a malformed document is a ParseError, never a traceback."""
    try:
        return _validate_panel_verdict(d)
    except (TypeError, AttributeError, KeyError, ValueError) as e:
        if isinstance(e, ParseError):
            raise
        raise ParseError("panel verdict: malformed (%s: %s)" % (type(e).__name__, e))


def _validate_panel_verdict(d):
    """The strict shape of bin/panel.py's verdict.json, shared by every reader; fail closed. Anything structurally
    wrong, truncated or internally inconsistent raises ParseError, so a malformed verdict is never read as 'no findings'
    or as a scanner having run. The image set is exactly the panel's; per image, ran and did_not_run are duplicate-free,
    disjoint, known scanner names whose union is exactly the scanners expected there; counts are positive integers
    for exactly the scanners that ran; counts_for_day is the quorum. Each finding is complete, names a known image,
    and its seen_by (scanners that ran on THAT image), 'of' (how many ran there), 'unique' and 'status' agree."""
    pm = _panel_module()
    if not isinstance(d, dict) or not isinstance(d.get("images"), dict) or not isinstance(d.get("findings"), list):
        raise ParseError("panel verdict: no images object or findings array")
    _closed(d, _TOP_KEYS, "the verdict")            # default deny: every level lists its keys, an unknown one is refused
    if set(d["images"]) != panel_images():
        raise ParseError("panel verdict: the image set is not the panel's fixed set")
    for img, st in d["images"].items():
        if not isinstance(st, dict):
            raise ParseError("panel verdict: image %r is not an object" % img)
        _closed(st, _IMAGE_KEYS, "image %s" % img)
        ran, dnr, counts = st.get("ran"), st.get("did_not_run"), st.get("counts")
        if not (isinstance(ran, list) and isinstance(dnr, list) and isinstance(counts, dict)):
            raise ParseError("panel verdict: image %r has no ran/did_not_run/counts" % img)
        if any(not isinstance(x, str) for x in ran + dnr):
            raise ParseError("panel verdict: image %r lists a scanner that is not a name" % img)
        if len(set(ran)) != len(ran) or len(set(dnr)) != len(dnr) or set(ran) & set(dnr):
            raise ParseError("panel verdict: image %r lists a scanner twice or as both ran and did not run" % img)
        want = {s for s in PANEL_SCANNERS if panel_expected(s, img)}
        if set(ran) | set(dnr) != want or any(not isinstance(x, str) for x in ran + dnr):
            raise ParseError("panel verdict: image %r does not list exactly its expected scanners" % img)
        if set(counts) != set(ran) or not all(_is_count(v) for v in counts.values()):
            raise ParseError("panel verdict: image %r has a ran scanner without a positive integer package count" % img)
        if st.get("counts_for_day") is not (len(ran) >= pm.QUORUM):
            raise ParseError("panel verdict: image %r counts_for_day disagrees with the quorum" % img)
    st_all = d["images"]
    if d.get("not_counted") != sorted(i for i, st in st_all.items() if not st["counts_for_day"]):
        raise ParseError("panel verdict: not_counted disagrees with the images")
    if d.get("scanner_failures") != sorted("%s on %s" % (s, i) for i, st in st_all.items() for s in st["did_not_run"]):
        raise ParseError("panel verdict: scanner_failures disagrees with the images")
    for f in d["findings"]:
        if isinstance(f, dict):
            _closed(f, _FINDING_KEYS, "a finding")
            if not _ID.fullmatch(str(f.get("id"))) or not _TEXT.fullmatch(str(f.get("package"))) or not _TEXT.fullmatch(str(f.get("version"))):
                raise ParseError("panel verdict: a finding id, package or version holds a character outside the allowed set")
        if not (isinstance(f, dict) and all(isinstance(f.get(k), str) and f.get(k) for k in ("id", "image", "package"))
                and isinstance(f.get("version"), str) and isinstance(f.get("purls"), list)
                and all(isinstance(x, str) for x in f["purls"]) and f["image"] in st_all):
            raise ParseError("panel verdict: an incomplete finding or one on an unknown image")
        sb, ran = f.get("seen_by"), st_all[f["image"]]["ran"]
        if (not isinstance(sb, list) or not sb or len(set(sb)) != len(sb) or any(x not in ran for x in sb)
                or not _is_int(f.get("of")) or f.get("of") != len(ran) or f.get("unique") is not (len(sb) == 1)
                or f.get("status") != ("unique" if len(sb) == 1 else "report")):
            raise ParseError("panel verdict: finding %s on %s has inconsistent seen_by/of/unique/status" % (f["id"], f["image"]))
    for f in d["findings"]:                      # a package URL must name the package and version the finding names
        for purl in f["purls"]:
            if not _PURL.fullmatch(purl):
                raise ParseError("panel verdict: finding %s on %s has a package URL that is not pkg:TYPE/..." % (f["id"], f["image"]))
            name, ver = pm._purl_name_version(purl)
            if not name or pm.key_of(f["image"], f["id"], name, ver)[2:] != pm.key_of(f["image"], f["id"], f["package"], f["version"])[2:]:
                raise ParseError("panel verdict: finding %s on %s has a package URL for a different package or version" % (f["id"], f["image"]))
    for f in d["findings"]:                      # each reporting scanner's own record: closed keys, exact types; absent = not reported
        det = f["details"]
        if not isinstance(det, dict) or set(det) != set(f["seen_by"]):
            raise ParseError("panel verdict: finding %s on %s has details for different scanners than seen_by" % (f["id"], f["image"]))
        for sc, rec in det.items():
            if not isinstance(rec, dict) or not set(rec) <= _DETAIL_KEYS:
                raise ParseError("panel verdict: finding %s on %s has an unknown key in %s's details" % (f["id"], f["image"], sc))
            al = rec.get("aliases", [])
            if (rec.get("severity", "negligible") not in _SEVERITIES or not isinstance(rec.get("severity", ""), str)
                    or ("fixed_version" in rec and not (isinstance(rec["fixed_version"], str) and rec["fixed_version"] and _TEXT.fullmatch(rec["fixed_version"])))
                    or not isinstance(al, list) or len(set(map(str, al))) != len(al) or not all(isinstance(a, str) and _ID.fullmatch(a) for a in al)
                    or ("aliases" in rec and not al) or not isinstance(rec.get("known_exploited", True), bool)
                    or ("purl" in rec and not (isinstance(rec["purl"], str) and _PURL.fullmatch(rec["purl"])))):
                raise ParseError("panel verdict: finding %s on %s has a malformed value in %s's details" % (f["id"], f["image"], sc))
            if "purl" in rec:                    # that scanner's own package URL names the package and version the finding names
                name, ver = pm._purl_name_version(rec["purl"])
                if not name or pm.key_of(f["image"], f["id"], name, ver)[2:] != pm.key_of(f["image"], f["id"], f["package"], f["version"])[2:]:
                    raise ParseError("panel verdict: finding %s on %s: %s's package URL is for a different package or version" % (f["id"], f["image"], sc))
    keys = [pm.key_of(f["image"], f["id"], f["package"], f["version"]) for f in d["findings"]]
    if len(set(keys)) != len(keys):
        raise ParseError("panel verdict: two findings share one identity (image, CVE, package, version)")
    reported = [f for f in d["findings"] if f["status"] == "report"]
    canon = lambda xs: [json.dumps(x, sort_keys=True) for x in xs]     # type-strict: True is not 1, 4 is not 4.0
    if (not isinstance(d.get("unique"), list) or canon(d["unique"]) != canon([f for f in d["findings"] if f["unique"]])
            or not isinstance(d.get("vex_covered"), list)
            or not isinstance(d.get("issue"), str)):
        raise ParseError("panel verdict: the unique list, vex_covered or issue disagrees with the findings")
    if d["issue"] != pm.render_issue(reported):
        raise ParseError("panel verdict: the issue text is not the tally's rendering of the reported findings")
    for c in d["vex_covered"]:
        if isinstance(c, dict):
            _closed(c, _VEX_KEYS, "a vex_covered entry")                   # what the tally recorded as hidden by our statement (its Inspector and Google results)
        if not (isinstance(c, dict) and all(isinstance(c.get(k), str) and c.get(k) for k in ("image", "scanner", "id", "package"))
                and isinstance(c.get("version"), str) and c["image"] in st_all and c["scanner"] in pm.FILTER_HERE
                and c["scanner"] in st_all[c["image"]]["ran"]):
            raise ParseError("panel verdict: a vex_covered entry is incomplete, names an unknown image or a scanner the tally does not filter, or one that did not run there")
        if not _ID.fullmatch(c["id"]) or not _TEXT.fullmatch(c["package"]) or not _TEXT.fullmatch(c["version"]):
            raise ParseError("panel verdict: a vex_covered id, package or version holds a character outside the allowed set")
    code = 2 if (d["not_counted"] or d["scanner_failures"]) else (1 if reported else 0)
    if not _is_int(d.get("exit")) or d.get("exit") != code:
        raise ParseError("panel verdict: exit status disagrees with the images and findings")
    return d


def manifest_readers(m):
    """[(scanner, reader, path)] for a manifest's four panel scanners; the path is None for a scanner whose report is not available
    (it did not run, or missed an image). All four are read from the one verdict.json."""
    vp = ((m or {}).get("panel") or {}).get("verdict")
    r = (m or {}).get("scanner_reports") or {}
    return [(sc, (lambda p, sc=sc: parse_panel(p, sc)), vp if r.get(sc) else None) for sc in PANEL_SCANNERS]


def parse_panel(path, scanner):
    """One panel scanner's findings from the rescan's verdict.json (bin/panel.py tally): the findings whose
    seen_by names `scanner`, one record per (CVE id, package identity); the images that carry it are kept, each with
    its own 'seen by N of M' and uniqueness (extra.by_image). A malformed verdict is a ParseError."""
    try:
        d = validate_panel_verdict(load_panel_verdict(path))
    except OSError as e:
        raise ParseError("cannot load %s: %s" % (path, e))
    except ValueError as e:
        raise e if isinstance(e, ParseError) else ParseError("cannot load %s: %s" % (path, e))
    seen = {}
    for f in d["findings"]:
        if scanner not in f["seen_by"]:
            continue
        mine = f["details"].get(scanner, {})             # this scanner's own severity / fix / aliases / package URL for this image
        purl = mine.get("purl") or "pkg:generic/%s@%s" % (f.get("package"), f.get("version"))     # never another scanner's package URL
        key = (f["id"], purl)
        rec = seen.get(key)
        if rec is None:
            rec = seen[key] = _finding(scanner, f["id"], purl, (), f.get("package"), None, None,
                                       {"images": [], "version": f.get("version"), "by_image": {}})
        rec["extra"]["images"].append(f["image"])
        if mine.get("severity") and (rec["severity"] is None or _SEVERITIES.index(mine["severity"]) > _SEVERITIES.index(rec["severity"])):
            rec["severity"] = mine["severity"]           # the highest across images; the scanner's words, normalised
        if mine.get("fixed_version") and not rec["fixed_version"]:
            rec["fixed_version"] = mine["fixed_version"]
        if mine.get("known_exploited"):
            rec["extra"]["known_exploited"] = True
        rec["aliases"] = sorted(set(rec["aliases"]) | set(mine.get("aliases") or []))
        rec["extra"]["by_image"][f["image"]] = {"seen_by": sorted(f["seen_by"]), "of": f["of"], "unique": f["unique"]}
    # What the tally recorded as HIDDEN by our published VEX for this scanner (its Inspector and Google results are filtered against the document, bin/panel.py): a carried
    # statement must stay re-judgeable each run, so each entry is emitted as a finding flagged `carried` (rc-5b fix 5, REQ-AUD-2 AC7, REQ-AUD-13 AC7). It carries no package URL of its
    # own (the tally keeps package and version); the run resolves it to the carried statement's scope, or drops it when no carried statement matches.
    for c in d["vex_covered"]:
        if c["scanner"] != scanner:
            continue
        purl = "pkg:generic/%s@%s" % (c["package"], c["version"])
        key = (c["id"], purl)
        rec = seen.get(key)
        if rec is None:
            rec = seen[key] = _finding(scanner, c["id"], purl, (), c["package"], None, None,
                                       {"images": [], "version": c["version"], "by_image": {}, "carried": True})
        if c["image"] not in rec["extra"]["images"]:
            rec["extra"]["images"].append(c["image"])
    for rec in seen.values():
        rec["extra"]["images"].sort()
    return list(seen.values())


def _stream(text):
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \n\r\t":
            i += 1
        if i >= n:
            break
        try:
            obj, j = dec.raw_decode(text, i)
        except ValueError as e:
            raise ParseError("govulncheck: not a JSON stream at offset %d: %s" % (i, e))
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
    osv_aliases = {}
    sbom_ver = {}          # module path -> version, so a trace frame that omits the version
    saw_any = False        # can still be scoped to the exact version scanned (REQ-AUD-13 AC5)
    for obj in _stream(text):
        if not isinstance(obj, dict):
            raise ParseError("govulncheck: non-object in stream")
        saw_any = True
        if "config" in obj:
            scan_level = (obj["config"] or {}).get("scan_level")
        if "SBOM" in obj:
            sbom = obj["SBOM"] or {}
            roots = sbom.get("roots") or []
            for mm in (sbom.get("modules") or []):
                if mm.get("path") and mm.get("version"):
                    sbom_ver[mm["path"]] = mm["version"]
            mods = [(mm.get("path") or "") for mm in (sbom.get("modules") or []) if mm.get("path")]
            # roots[0] is the scanned PACKAGE import path, NOT the module (R1 outer round-3 #3):
            # the module is the SBOM module whose path is a prefix of that package (longest
            # match, excluding stdlib). Fall back to roots[0] only if no module matches.
            root0 = roots[0] if roots else None
            if root0:
                cands = [p for p in mods if p != "stdlib" and (root0 == p or root0.startswith(p + "/"))]
                module = max(cands, key=len) if cands else root0
        if isinstance(obj.get("osv"), dict) and obj["osv"].get("id"):         # the stream's own advisory entry: its aliases
            osv_aliases[obj["osv"]["id"]] = sorted(a for a in (obj["osv"].get("aliases") or []) if isinstance(a, str))
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
        # the (module, version) the trace actually names — a closure may only be scoped to
        # these, never to a sibling version the evidence does not cover (REQ-AUD-13 AC5).
        modvers = {(fr["module"], fr.get("version") or sbom_ver.get(fr["module"]))
                   for fr in trace if fr.get("module")}
        cur = by_osv.get(osv, {"reachable": False, "imported_only": False, "modules": set(), "mods": {}})
        mods = dict(cur["mods"])
        vuln = next((fr for fr in trace if fr.get("module")), None)         # the vulnerable dependency is the trace's first named module
        if vuln:                                                            # its installed version and the stream's fix stay with THAT module
            e = dict(mods.get(vuln["module"], {"installed": None, "fixed": None, "reachable": False}))
            e["installed"] = e["installed"] or vuln.get("version") or sbom_ver.get(vuln["module"])
            e["fixed"] = e["fixed"] or (f["fixed_version"] if isinstance(f.get("fixed_version"), str) and f["fixed_version"] else None)
            e["reachable"] = e["reachable"] or called
            mods[vuln["module"]] = e
        by_osv[osv] = {"reachable": cur["reachable"] or called,
                       "imported_only": cur["imported_only"] or imported_only,
                       "modules": cur.get("modules", set()) | modvers, "mods": mods}
    if not saw_any:
        raise ParseError("govulncheck: empty stream")
    for k, v in by_osv.items():
        v["aliases"] = osv_aliases.get(k, [])
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
