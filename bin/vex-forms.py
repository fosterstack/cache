#!/usr/bin/env python3
"""Our VEX in three forms (scanner-panel rule 10, owner RATIFIED Oct 2; REQ-SCAN-010; advisor 0076/0077).

Generated at release time from the ONE OpenVEX file (.vex/fosterstack-cache.openvex.json) and a digest file naming the
release's images (REQ-SCAN-010-AC5): exactly the two variants production and fips, each an index digest and its
linux/amd64 and linux/arm64 children. No registry read, no network, no cloud call, no clock:
  - an Amazon Inspector suppression-rule file: {"filters": [...]}, one `create-filter --cli-input-json` document per
    suppressible statement scope (not_affected, fixed) that names a package, scoped by CVE, by the image digests the
    statement covers and by that package (and version where the statement gives one); a statement that names no package
    has no rule, so the same CVE in another package is never hidden (owner Oct 16, handoff 0482); the guide applies it with GUIDE_INSPECTOR_COMMAND;
  - a CSAF 2.0 VEX file (csaf_vex) carrying every OpenVEX statement about this release's images, each with its own
    scope, in the shape `gcloud artifacts vulnerabilities load-vex` reads (applied with GUIDE_GOOGLE_COMMAND; a preview
    feature; loading is proven by rule 12's live test).
"The same statements" (advisor's words): the CSAF file carries every OpenVEX statement; the Inspector file carries one
rule per suppressible, package-named statement (not_affected, fixed) and none for affected or under_investigation.
Our own pipeline keeps filtering against the OpenVEX file itself (rule 4); these forms are for customers.

The digest file (AC5, AC6; advisor step 5, Oct 11, handoff 0389): the generator checks its SHAPE AND KEY SET ONLY:
a JSON object with exactly the keys production and fips, no key repeated at any level, each an object with exactly
index and children, children exactly linux/amd64 and linux/arm64, every digest sha256: and 64 lower-case hex, and no
digest named twice. Anything else is refused, naming the key path or the value, before any form file is written. It
does NOT check that the digests are the ones Build verified: that check belongs to the release workflow and is
tested there. The same inputs give the same bytes (AC7): the only dates are the OpenVEX file's own.
"""
import argparse, json, os, re, sys, urllib.parse

REPO = "ghcr.io/fosterstack/cache"
VARIANTS = ("production", "fips")                    # v0.3.0 ships no :debug image (AC5)
PLATFORMS = ("linux/amd64", "linux/arm64")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")             # used with fullmatch only: no trailing newline slips through
CSAF_STATUS = {"not_affected": "known_not_affected", "fixed": "fixed", "affected": "known_affected",
               "under_investigation": "under_investigation"}
SUPPRESSIBLE = ("not_affected", "fixed")
# Codex #165 r1 SEC-165-03: fail on a missing file or a failed call, never report success; a valid file with no rule (every statement affected or
# under investigation) is a no-op that succeeds, so jq has no -e (it exits 4 on no output; a file without a filters list still fails: jq cannot iterate it)
# One ( … ) subshell (Sonnet #167 r3, R3-01): the macOS default shell runs a pipeline's last stage in the current shell,
# so a bare `| while …; do … || exit 1; done` would close the reader's terminal; pipefail stays inside it too
GUIDE_INSPECTOR_COMMAND = ("(set -o pipefail; jq -c '.filters[]' <file> | while read -r f; do "
                           "aws inspector2 create-filter --cli-input-json \"$f\" || exit 1; done)")
# Google's loader (gcloud vex_util.ParseVexFile) applies the products of every branch NAMED like --uri's image path, and
# prefixes https:// once per matching branch — so exactly one branch may match: the one of the digest being loaded,
# renamed to the customer's own image path; --uri carries that digest, so the notes bind to it (Codex #165 r2, SEC-165-06)
GUIDE_GOOGLE_COMMAND = ("jq --arg u \"$IMAGE\" --arg d \"$DIGEST\" '.product_tree.branches |= map(if "
                        "(.product.product_identification_helper.purl | startswith(\"pkg:oci/cache@\" + $d + \"?\")) "
                        "then .name = $u else . end)' <file> > vex-for-my-image.json && "
                        "gcloud artifacts vulnerabilities load-vex --source=vex-for-my-image.json --uri=\"$IMAGE@$DIGEST\"")


class _Obj(dict):
    """A JSON object that remembers the keys its file repeated (json.load keeps the last of two and says nothing)."""
    repeated = ()


def _pairs(pairs):
    d, rep = _Obj(), []
    for k, v in pairs:
        if k in d:
            rep.append(k)
        d[k] = v
    d.repeated = tuple(rep)
    return d


def _refuse_repeats(obj, path=()):
    if isinstance(obj, dict):
        for k in getattr(obj, "repeated", ()):
            raise ValueError("digest file: key %s is repeated" % ".".join(path + (k,)))
        for k, v in obj.items():
            _refuse_repeats(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _refuse_repeats(v, path + (str(i),))


def _exact_keys(obj, keys, path):
    """obj is an object with exactly these keys; otherwise refused, naming the first key path at fault."""
    where = ".".join(path) if path else "the digest file"
    if not isinstance(obj, dict):
        raise ValueError("%s must be a JSON object with exactly the keys %s" % (where, ", ".join(keys)))
    pre = ".".join(path) + "." if path else ""
    for k in keys:
        if k not in obj:
            raise ValueError("digest file: key %s%s is missing" % (pre, k))
    for k in sorted(set(obj) - set(keys)):
        raise ValueError("digest file: key %s%s is not allowed (only %s)" % (pre, k, ", ".join(keys)))


def check_images(images):
    """The digest file's shape and key set (REQ-SCAN-010-AC5, AC6), and nothing more: membership in Build's verified
    set is the release workflow's check. Raises ValueError naming the key path or the value at fault."""
    _refuse_repeats(images)
    _exact_keys(images, VARIANTS, ())
    seen = {}
    for v in VARIANTS:
        _exact_keys(images[v], ("index", "children"), (v,))
        _exact_keys(images[v]["children"], PLATFORMS, (v, "children"))
        for path, d in [((v, "index"), images[v]["index"])] + [((v, "children", p), images[v]["children"][p]) for p in PLATFORMS]:
            where = ".".join(path)
            if not isinstance(d, str) or not DIGEST.fullmatch(d):
                raise ValueError("digest file: %s is %s, not sha256: followed by 64 lower-case hexadecimal characters"
                                 % (where, json.dumps(d)))
            if d in seen:
                raise ValueError("digest file: %s is named twice (%s and %s)" % (d, seen[d], where))
            seen[d] = where


def read_images(path):
    """The digest file, by its path: parsed with every repeated key kept visible, then shape-checked."""
    try:
        with open(path, encoding="utf-8") as fh:
            images = json.load(fh, object_pairs_hook=_pairs)
    except (OSError, ValueError) as e:                 # ValueError: invalid JSON or invalid UTF-8
        raise ValueError("digest file %s is not readable JSON: %s" % (path, e))
    check_images(images)
    return images


def _digests(images):
    check_images(images)
    out = []
    for v in VARIANTS:
        out.append((v, None, images[v]["index"]))
        for plat in PLATFORMS:
            out.append((v, plat, images[v]["children"][plat]))
    return out


def _cve(statement):
    return statement["vulnerability"]["name"]


def _status(statement):
    s = statement.get("status")
    if s not in CSAF_STATUS:
        raise ValueError("unknown OpenVEX status %r for %s" % (s, _cve(statement)))
    return s


def _purl_of(component, cve):
    """The one purl a product or subcomponent names (Codex #165 r3, SEC-165-01): its @id or identifiers.purl — equal when
    both are given. Any other identifier (CPE …), two purls that differ, or no purl at all cannot be read here, and a
    statement this check cannot place must stop generation rather than drop out of scope."""
    ids = component.get("identifiers") or {}
    if not isinstance(ids, dict) or set(ids) - {"purl"}:
        raise ValueError("%s: %r carries an identifier these forms cannot read" % (cve, component))
    at = component.get("@id", "")
    purls = {x for x in (at if at.startswith("pkg:") else None, ids.get("purl")) if x}
    if len(purls) != 1 or (at and not at.startswith("pkg:")):
        raise ValueError("%s: %r does not name exactly one purl" % (cve, component))
    return purls.pop()


# Our image as the OTHER readers recognise it (the gate's OUR_PRODUCTS): repository_url is the FIRST qualifier and spelled out, not percent-encoded; an optional
# @digest may stand between the name and the query (a digest-scoped product, which only these forms read).
RAW_OURS = re.compile(r"pkg:oci/cache(?:@[^?#]*)?\?repository_url=" + re.escape(REPO) + r"(?:&|$|#)")


def _qualifiers(pid, qs, cve):
    """The one scope grammar (rc-5a H; the same as the gate's scope_of, the rescan's _parse_product and the panel's _covers): the
    query is split RAW on '&' (no percent-decoding of keys or of variant/arch), every part is key=value with a non-blank value, the keys are only
    repository_url, variant and arch in lower case, each once, variant is production or fips, arch is amd64 or arm64. repository_url is the first
    qualifier and carries the repository unencoded (the shape every other reader recognises, RAW_OURS); the caller has already checked that.
    Returns (repository_url, variant|None, arch|None); anything else is ValueError (generation stops: a form that could be read wider must not be)."""
    seen = {}
    for part in qs.split("&") if qs else []:
        k, eq, v = part.partition("=")
        if not eq or not v or k not in ("repository_url", "variant", "arch") or k in seen:
            raise ValueError("%s: product %s has a part these forms cannot represent" % (cve, pid))
        seen[k] = v
    if seen.get("variant") not in (None,) + VARIANTS or seen.get("arch") not in (None, "amd64", "arm64"):
        raise ValueError("%s: product %s names an unknown variant or architecture" % (cve, pid))
    return urllib.parse.unquote(seen.get("repository_url", "")), seen.get("variant"), seen.get("arch")


def _scopes(statement, digests, meta=None):
    """[(digests, package)] a statement covers in this release (Codex #165 r1, SEC-165-01): each product that is this
    repository's OCI image (`pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache`, or one digest of it), with each of
    its subcomponents as a package (name, version) — None for the whole image. Another product (another repository, a
    Go module) is not an image of this release: no scope here. A qualifier the forms cannot represent stops generation. `meta` maps each digest to
    (variant, platform|None): a product with variant= / arch= covers only the digests it names (variant: the index and the children of that variant;
    arch: the children of that architecture, an index having none); without `meta` such a product cannot be placed and stops generation."""
    out = []
    for prod in statement.get("products") or []:
        pid = _purl_of(prod, _cve(statement))
        if not pid.startswith("pkg:oci/"):
            continue                                     # not an image (a Go module …)
        # read as the purl spec orders it — #subpath, then ?qualifiers (decoded), then @version — so an encoding never
        # decides whether a product is ours (Sonnet #165 r3b, SEC-165-01)
        rest, _, subpath = pid[len("pkg:oci/"):].partition("#")
        rest, _, qs = rest.partition("?")
        name, at, version = rest.partition("@")
        if urllib.parse.unquote(name) != "cache" or [urllib.parse.unquote(x) for x in urllib.parse.parse_qs(qs, keep_blank_values=True).get("repository_url", [])] != [REPO]:
            continue                                     # another repository's image
        if subpath or "#" in pid or (at and not version) or "@" in version:   # any fragment separator, even an empty fragment, is a subpath the other readers refuse
            raise ValueError("%s: product %s has a part these forms cannot represent" % (_cve(statement), pid))
        if not RAW_OURS.match(pid):                      # ours only after decoding or reordering: the gate, panel and rescan would ignore it, so these forms must not honour it
            raise ValueError("%s: product %s names our image in a form the other readers do not recognise (repository_url first, unencoded)" % (_cve(statement), pid))
        _, variant, arch = _qualifiers(pid, qs, _cve(statement))
        want = urllib.parse.unquote(version) if at else None
        if (variant or arch) and meta is None:
            raise ValueError("%s: product %s is scoped by variant or architecture, which needs the digest file to place" % (_cve(statement), pid))
        ds = [d for d in digests if (want is None or d == want)
              and (variant is None or meta[d][0] == variant) and (arch is None or meta[d][1] == "linux/" + arch)]
        if (variant or arch) and want in digests and not ds:
            raise ValueError("%s: product %s pins a digest that its own variant/arch qualifier excludes" % (_cve(statement), pid))
        subs = prod.get("subcomponents") or []
        if not subs:
            out.append((ds, None))
        for sub in subs:
            # generic packages only: Inspector's filter has no ecosystem, so pkg:npm/foo and pkg:pypi/foo would be one rule (Codex #381 r5/r6)
            # no namespace: the forms carry a package's name only, so pkg:golang/github.com/acme/busybox would widen
            # to every "busybox" (Codex #165 r3, SEC-165-01) — refused, as is a qualifier or subpath
            # The one exception (rc-5a G): a Go module is named by its FULL module path (Inspector and the SBOMs name it so), which needs a
            # host-like first segment and at least one more, so it never widens to a bare last segment.
            sid = _purl_of(sub, _cve(statement))
            pm = re.fullmatch(r"pkg:generic/([^/@?#]+)(?:@([^?#]+))?", sid)
            if not pm:
                pm = re.fullmatch(r"pkg:golang/([^/@?#]+(?:/[^/@?#]+)+)(?:@([^?#]+))?", sid)
                if pm and "." not in urllib.parse.unquote(pm.group(1)).split("/")[0]:
                    pm = None                            # a module path starts with a domain (github.com/…); anything else is not one
            if not pm:                                   # a namespace on a generic package, a qualifier or subpath: not represented
                raise ValueError("%s: subcomponent %r cannot be represented" % (_cve(statement), sub.get("@id")))
            name_, ver_ = urllib.parse.unquote(pm.group(1)), urllib.parse.unquote(pm.group(2) or "")
            if pm.group(1).count("/") == 0 and any(c in name_ for c in "/@?#") or any(c in ver_ for c in "/?#"):
                # a delimiter that was only percent-encoded (busybox%401.37.0, github.com%2Fgolang-jwt%2Fjwt): decoded once it would name another package
                raise ValueError("%s: subcomponent %r hides a purl delimiter in a percent escape" % (_cve(statement), sub.get("@id")))
            if "/" in pm.group(1) and (any(c in seg for seg in name_.split("/") for c in "@?#") or name_.count("/") != pm.group(1).count("/")):
                raise ValueError("%s: subcomponent %r hides a purl delimiter in a percent escape" % (_cve(statement), sub.get("@id")))
            out.append((ds, (name_, ver_)))
    return out


def _check_conflicts(vex, digests, meta=None):
    """A suppressible and a non-suppressible statement of one CVE that cover the same image (and package) contradict
    each other: generation stops — never a suppression of an affected product."""
    by = {}
    for st in vex["statements"]:
        for ds, pkg in _scopes(st, digests, meta):
            for d in ds:
                by.setdefault((_cve(st), d), []).append((_status(st) in SUPPRESSIBLE, pkg))
    def overlap(p, q):                                    # no version = every version of that package (SEC-165-01)
        return p is None or q is None or (p[0] == q[0] and (not p[1] or not q[1] or p[1] == q[1]))
    for (cve, d), xs in by.items():
        for sup, pkg in xs:
            for sup2, pkg2 in xs:
                if sup and not sup2 and overlap(pkg, pkg2):
                    raise ValueError("%s: statements contradict each other for %s" % (cve, d))


def inspector(vex, images, version):
    digests = [d for _, _, d in _digests(images)]
    meta = {d: (v, plat) for v, plat, d in _digests(images)}
    _check_conflicts(vex, digests, meta)
    filters = []
    for st in vex["statements"]:
        if _status(st) not in SUPPRESSIBLE:
            continue
        cve = _cve(st)
        why = st.get("impact_statement") or ("fixed in this release" if st["status"] == "fixed" else st.get("justification", ""))
        for ds, pkg in _scopes(st, digests, meta):
            if not ds or pkg is None:                    # no package named: Inspector cannot narrow the rule to it, so no rule (owner Oct 16)
                continue
            crit = {"vulnerabilityId": [{"comparison": "EQUALS", "value": cve}],
                    "ecrImageHash": [{"comparison": "EQUALS", "value": d} for d in ds]}
            p = {"name": {"comparison": "EQUALS", "value": pkg[0]}}
            if pkg[1]:
                p["version"] = {"comparison": "EQUALS", "value": pkg[1]}
            crit["vulnerablePackages"] = [p]
            k = sum(1 for f in filters if f["filterCriteria"]["vulnerabilityId"][0]["value"] == cve)
            filters.append({
                "name": ("fosterstack-cache-%s-%s%s" % (version, cve, "" if k == 0 else "-%d" % (k + 1)))[:128],
                "action": "SUPPRESS",
                "description": ("FosterStack Cache %s VEX: %s is %s%s (%s)" % (
                    version, cve, st["status"], " in %s" % " ".join(x for x in pkg if x), why))[:512],
                "reason": "FosterStack Cache published VEX statement",
                "filterCriteria": crit,
            })
    return {"filters": filters}


def csaf(vex, images, version):
    """CSAF 2.0 VEX in the shape Google's loader reads (gcloud vex_util: product_tree.branches, one per product, named by
    the image path; SEC-165-02). A statement on the whole image names the image products; a package-scoped one names
    "the package inside the image" products (relationships, default_component_of), which keep the scope exact for CSAF
    readers and which Google's loader, reading branch products only, does not apply (the safe direction)."""
    found = _digests(images)
    digests = [d for _, _, d in found]
    meta = {d: (v, plat) for v, plat, d in _digests(images)}
    _check_conflicts(vex, digests, meta)
    branches, pid = [], {}
    for v, plat, d in found:
        pid[d] = "fosterstack-cache-%s-%s%s" % (version, v, "" if plat is None else "-" + plat.replace("/", "-"))
        branches.append({"category": "product_version", "name": REPO, "product": {
            "name": "%s@%s (%s%s)" % (REPO, d, v, "" if plat is None else ", " + plat), "product_id": pid[d],
            "product_identification_helper": {"purl": "pkg:oci/cache@%s?repository_url=%s" % (d, REPO)}}})
    components, relationships = {}, {}

    def ids(st):
        out = []
        for ds, pkg in _scopes(st, digests, meta):
            for d in ds:
                if pkg is None:
                    out.append(pid[d])
                    continue
                cid = "component-%s@%s" % tuple(urllib.parse.quote(x, safe="") for x in pkg)   # unambiguous (SEC-165-07)
                components.setdefault(cid, {"name": " ".join(x for x in pkg if x), "product_id": cid})
                rid = "%s-in-%s" % (cid, pid[d])
                relationships.setdefault(rid, {"category": "default_component_of", "product_reference": cid,
                                               "relates_to_product_reference": pid[d],
                                               "full_product_name": {"name": "%s %s in %s" % (pkg + (pid[d],)),
                                                                     "product_id": rid}})
                out.append(rid)
        return list(dict.fromkeys(out))
    vulns = []
    for st in vex["statements"]:
        status, these = CSAF_STATUS[_status(st)], ids(st)
        if not these:
            continue                                   # not about an image of this release
        v = {"cve": _cve(st), "product_status": {status: these}}
        if st["status"] == "not_affected" and st.get("justification"):
            v["flags"] = [{"label": st["justification"], "product_ids": list(these)}]
        note = st.get("impact_statement") or st.get("action_statement")
        if note:                                       # Google's _MakeNote reads the title too (SEC-165-02)
            v["notes"] = [{"category": "description", "title": "%s: %s" % (_cve(st), st["status"]), "text": note}]
        if st["status"] == "affected" and st.get("action_statement"):
            v["remediations"] = [{"category": "vendor_fix", "details": st["action_statement"], "product_ids": list(these)}]
        vulns.append(v)
    date = vex.get("timestamp", "1970-01-01T00:00:00Z")
    tree = {"branches": branches}
    if components:
        tree["full_product_names"] = list(components.values())
        tree["relationships"] = list(relationships.values())
    return {
        "document": {
            "category": "csaf_vex", "csaf_version": "2.0",
            "title": "FosterStack Cache %s VEX" % version,
            "publisher": {"category": "vendor", "name": "FosterStack LLC", "namespace": "https://fosterstack.com"},
            "tracking": {"id": "fosterstack-cache-%s-vex" % version, "status": "final",
                         "version": str(vex.get("version", 1)), "initial_release_date": date, "current_release_date": date,
                         "revision_history": [{"number": str(vex.get("version", 1)), "date": date,
                                               "summary": "generated from %s" % vex.get("@id", "the OpenVEX file")}]},
        },
        "product_tree": tree,
        "vulnerabilities": vulns,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vex-forms")
    ap.add_argument("--openvex", required=True)
    ap.add_argument("--images", required=True, metavar="DIGEST_FILE",
                    help='path of a JSON file: {"production": {"index": D, "children": {"linux/amd64": D, '
                         '"linux/arm64": D}}, "fips": {the same}}, D = sha256:<64 lower-case hex>; shape and key set '
                         'are checked here, that the digests are Build\'s verified ones is the release workflow\'s check')
    ap.add_argument("--version", required=True)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args(argv)
    base = os.path.join(a.out_dir, "fosterstack-cache-%s" % a.version)
    try:                                               # both forms are built in memory first: a refusal writes nothing
        images = read_images(a.images)
        with open(a.openvex, encoding="utf-8") as fh:
            vex = json.load(fh)
        forms = [(base + ".inspector-filters.json", json.dumps(inspector(vex, images, a.version), indent=1)),
                 (base + ".csaf.json", json.dumps(csaf(vex, images, a.version), indent=1))]
    except (OSError, ValueError) as e:
        print("vex-forms: refused, nothing written: %s" % e, file=sys.stderr)
        return 1
    for path, text in forms:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    for path, _ in forms:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
