#!/usr/bin/env python3
"""Our VEX in three forms (scanner-panel rule 10, owner RATIFIED Oct 2; REQ-SCAN-010; advisor 0076/0077).

Generated at release time from the ONE OpenVEX file (.vex/fosterstack-cache.openvex.json) and the release's image
digests (each variant's index and its linux/amd64 and linux/arm64 children); no network, no cloud call:
  - an Amazon Inspector suppression-rule file: {"filters": [...]}, one `create-filter --cli-input-json` document per
    suppressible statement scope (not_affected, fixed), scoped by CVE, by the image digests the statement covers and,
    for a package-scoped statement, by that package and version; the guide applies it with GUIDE_INSPECTOR_COMMAND;
  - a CSAF 2.0 VEX file (csaf_vex) carrying every OpenVEX statement about this release's images, each with its own
    scope, in the shape `gcloud artifacts vulnerabilities load-vex` reads (applied with GUIDE_GOOGLE_COMMAND; a preview
    feature; loading is proven by rule 12's live test).
"The same statements" (advisor's words): the CSAF file carries every OpenVEX statement; the Inspector file carries one
rule per suppressible statement (not_affected, fixed) and none for affected or under_investigation.
Our own pipeline keeps filtering against the OpenVEX file itself (rule 4); these forms are for customers.
"""
import argparse, json, os, re, sys, urllib.parse

REPO = "ghcr.io/fosterstack/cache"
VARIANTS = ("production", "debug", "fips")
CSAF_STATUS = {"not_affected": "known_not_affected", "fixed": "fixed", "affected": "known_affected",
               "under_investigation": "under_investigation"}
SUPPRESSIBLE = ("not_affected", "fixed")
# Codex #165 r1 SEC-165-03: fail on a missing file or a failed call, never report success
GUIDE_INSPECTOR_COMMAND = ("set -o pipefail; jq -ce '.filters[]' <file> | while read -r f; do "
                           "aws inspector2 create-filter --cli-input-json \"$f\" || exit 1; done")
# Google's loader (gcloud vex_util.ParseVexFile) applies the products of every branch NAMED like --uri's image path, and
# prefixes https:// once per matching branch — so exactly one branch may match: the one of the digest being loaded,
# renamed to the customer's own image path; --uri carries that digest, so the notes bind to it (Codex #165 r2, SEC-165-06)
GUIDE_GOOGLE_COMMAND = ("jq --arg u \"$IMAGE\" --arg d \"$DIGEST\" '.product_tree.branches |= map(if "
                        "(.product.product_identification_helper.purl | startswith(\"pkg:oci/cache@\" + $d + \"?\")) "
                        "then .name = $u else . end)' <file> > vex-for-my-image.json && "
                        "gcloud artifacts vulnerabilities load-vex --source=vex-for-my-image.json --uri=\"$IMAGE@$DIGEST\"")


def _digests(images):
    missing = [v for v in VARIANTS if v not in images]
    if missing:
        raise ValueError("image digests missing for: " + ", ".join(missing))
    out = []
    for v in VARIANTS:
        out.append((v, None, images[v]["index"]))
        for plat, d in sorted(images[v]["children"].items()):
            out.append((v, plat, d))
    return out


def _cve(statement):
    return statement["vulnerability"]["name"]


def _status(statement):
    s = statement.get("status")
    if s not in CSAF_STATUS:
        raise ValueError("unknown OpenVEX status %r for %s" % (s, _cve(statement)))
    return s


def _scopes(statement, digests):
    """[(digests, package)] a statement covers in this release (Codex #165 r1, SEC-165-01): each product that is this
    repository's OCI image (`pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache`, or one digest of it), with each of
    its subcomponents as a package (name, version) — None for the whole image. Another product (another repository, a
    Go module) is not an image of this release: no scope here. A qualifier the forms cannot represent stops generation."""
    out = []
    for prod in statement.get("products") or []:
        pid = prod.get("@id", "")
        if not pid.startswith("pkg:oci/"):
            continue                                     # not an image (a Go module …)
        # read as the purl spec orders it — #subpath, then ?qualifiers (decoded), then @version — so an encoding never
        # decides whether a product is ours (Sonnet #165 r3b, SEC-165-01)
        rest, _, subpath = pid[len("pkg:oci/"):].partition("#")
        rest, _, qs = rest.partition("?")
        name, at, version = rest.partition("@")
        quals = urllib.parse.parse_qs(qs, keep_blank_values=True)
        if urllib.parse.unquote(name) != "cache" or [urllib.parse.unquote(x) for x in quals.get("repository_url", [])] != [REPO]:
            continue                                     # another repository's image
        if subpath or (at and not version) or "@" in version or set(quals) - {"repository_url"}:
            raise ValueError("%s: product %s has a part these forms cannot represent" % (_cve(statement), pid))
        want = urllib.parse.unquote(version) if at else None
        ds = [d for d in digests if want is None or d == want]
        subs = prod.get("subcomponents") or []
        if not subs:
            out.append((ds, None))
        for sub in subs:
            pm = re.fullmatch(r"pkg:[a-z]+/(?:[^/@?#]+/)*([^/@?#]+)(?:@([^?#]+))?", sub.get("@id", ""))
            if not pm:                                   # a qualifier or subpath restricts it further: not represented
                raise ValueError("%s: subcomponent %r cannot be represented" % (_cve(statement), sub.get("@id")))
            out.append((ds, (urllib.parse.unquote(pm.group(1)), urllib.parse.unquote(pm.group(2) or ""))))
    return out


def _check_conflicts(vex, digests):
    """A suppressible and a non-suppressible statement of one CVE that cover the same image (and package) contradict
    each other: generation stops — never a suppression of an affected product."""
    by = {}
    for st in vex["statements"]:
        for ds, pkg in _scopes(st, digests):
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
    _check_conflicts(vex, digests)
    filters = []
    for st in vex["statements"]:
        if _status(st) not in SUPPRESSIBLE:
            continue
        cve = _cve(st)
        why = st.get("impact_statement") or ("fixed in this release" if st["status"] == "fixed" else st.get("justification", ""))
        for k, (ds, pkg) in enumerate(_scopes(st, digests)):
            if not ds:
                continue
            crit = {"vulnerabilityId": [{"comparison": "EQUALS", "value": cve}],
                    "ecrImageHash": [{"comparison": "EQUALS", "value": d} for d in ds]}
            if pkg is not None:
                p = {"name": {"comparison": "EQUALS", "value": pkg[0]}}
                if pkg[1]:
                    p["version"] = {"comparison": "EQUALS", "value": pkg[1]}
                crit["vulnerablePackages"] = [p]
            filters.append({
                "name": ("fosterstack-cache-%s-%s%s" % (version, cve, "" if k == 0 else "-%d" % (k + 1)))[:128],
                "action": "SUPPRESS",
                "description": ("FosterStack Cache %s VEX: %s is %s%s (%s)" % (
                    version, cve, st["status"], "" if pkg is None else " in %s %s" % pkg, why))[:512],
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
    _check_conflicts(vex, digests)
    branches, pid = [], {}
    for v, plat, d in found:
        pid[d] = "fosterstack-cache-%s-%s%s" % (version, v, "" if plat is None else "-" + plat.replace("/", "-"))
        branches.append({"category": "product_version", "name": REPO, "product": {
            "name": "%s@%s (%s%s)" % (REPO, d, v, "" if plat is None else ", " + plat), "product_id": pid[d],
            "product_identification_helper": {"purl": "pkg:oci/cache@%s?repository_url=%s" % (d, REPO)}}})
    components, relationships = {}, {}

    def ids(st):
        out = []
        for ds, pkg in _scopes(st, digests):
            for d in ds:
                if pkg is None:
                    out.append(pid[d])
                    continue
                cid = "component-%s@%s" % tuple(urllib.parse.quote(x, safe="") for x in pkg)   # unambiguous (SEC-165-07)
                components.setdefault(cid, {"name": "%s %s" % pkg, "product_id": cid})
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
    ap.add_argument("--images", required=True, help="JSON {variant: {index, children: {platform: digest}}}")
    ap.add_argument("--version", required=True)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args(argv)
    vex, images = json.load(open(a.openvex)), json.load(open(a.images))
    base = os.path.join(a.out_dir, "fosterstack-cache-%s" % a.version)
    with open(base + ".inspector-filters.json", "w") as fh:
        json.dump(inspector(vex, images, a.version), fh, indent=1)
    with open(base + ".csaf.json", "w") as fh:
        json.dump(csaf(vex, images, a.version), fh, indent=1)
    print(base + ".inspector-filters.json")
    print(base + ".csaf.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
