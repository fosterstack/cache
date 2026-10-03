#!/usr/bin/env python3
"""Our VEX in three forms (scanner-panel rule 10, owner RATIFIED Oct 2; REQ-SCAN-010; advisor 0076/0077).

Generated at release time from the ONE OpenVEX file (.vex/fosterstack-cache.openvex.json) and the release's image
digests (each variant's index and its linux/amd64 and linux/arm64 children); no network, no cloud call:
  - an Amazon Inspector suppression-rule file: {"filters": [...]}, one `create-filter --cli-input-json` document per
    suppressible statement (not_affected, fixed), scoped by CVE and by every released image digest; the guide applies
    it with GUIDE_INSPECTOR_COMMAND (create-filter takes one filter per call);
  - a CSAF 2.0 VEX file (csaf_vex) carrying every OpenVEX statement, its products the released image digests, for
    `gcloud artifacts vulnerabilities load-vex` (a preview feature; loading is proven by rule 12's live test).
"The same statements" (advisor's words): the CSAF file carries every OpenVEX statement; the Inspector file carries one
rule per suppressible statement (not_affected, fixed) and none for affected or under_investigation.
Our own pipeline keeps filtering against the OpenVEX file itself (rule 4); these forms are for customers.
"""
import argparse, json, os, sys

REPO = "ghcr.io/fosterstack/cache"
VARIANTS = ("production", "debug", "fips")
CSAF_STATUS = {"not_affected": "known_not_affected", "fixed": "fixed", "affected": "known_affected",
               "under_investigation": "under_investigation"}
SUPPRESSIBLE = ("not_affected", "fixed")
GUIDE_INSPECTOR_COMMAND = ("jq -c '.filters[]' <file> | while read -r f; do "
                           "aws inspector2 create-filter --cli-input-json \"$f\"; done")


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


def inspector(vex, images, version):
    hashes = [{"comparison": "EQUALS", "value": d} for _, _, d in _digests(images)]
    filters = []
    for st in vex["statements"]:
        if _status(st) not in SUPPRESSIBLE:
            continue
        cve = _cve(st)
        why = st.get("impact_statement") or ("fixed in this release" if st["status"] == "fixed" else st.get("justification", ""))
        filters.append({
            "name": ("fosterstack-cache-%s-%s" % (version, cve))[:128],
            "action": "SUPPRESS",
            "description": ("FosterStack Cache %s VEX: %s is %s (%s)" % (version, cve, st["status"], why))[:512],
            "reason": "FosterStack Cache published VEX statement",
            "filterCriteria": {"vulnerabilityId": [{"comparison": "EQUALS", "value": cve}],
                               "ecrImageHash": list(hashes)},
        })
    return {"filters": filters}


def csaf(vex, images, version):
    products = []
    for v, plat, d in _digests(images):
        pid = "fosterstack-cache-%s-%s%s" % (version, v, "" if plat is None else "-" + plat.replace("/", "-"))
        products.append({"name": "%s@%s (%s%s)" % (REPO, d, v, "" if plat is None else ", " + plat),
                         "product_id": pid,
                         "product_identification_helper": {"purl": "pkg:oci/cache@%s?repository_url=%s" % (d, REPO)}})
    ids = [p["product_id"] for p in products]
    vulns = []
    for st in vex["statements"]:
        status = CSAF_STATUS[_status(st)]
        v = {"cve": _cve(st), "product_status": {status: list(ids)}}
        if st["status"] == "not_affected" and st.get("justification"):
            v["flags"] = [{"label": st["justification"], "product_ids": list(ids)}]
        note = st.get("impact_statement") or st.get("action_statement")
        if note:
            v["notes"] = [{"category": "description", "text": note}]
        if st["status"] == "affected" and st.get("action_statement"):
            v["remediations"] = [{"category": "vendor_fix", "details": st["action_statement"], "product_ids": list(ids)}]
        vulns.append(v)
    date = vex.get("timestamp", "1970-01-01T00:00:00Z")
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
        "product_tree": {"full_product_names": products},
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
