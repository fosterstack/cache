#!/usr/bin/env python3
# The PR gate's Amazon Inspector verdict for one scanned image (scan.yml,
# decision row 57). inspector-sbomgen writes a CycloneDX SBOM of the image;
# inspector-scan:ScanSbom returns that SBOM annotated with vulnerabilities.
# This reads both and decides, the same way the grype leg does:
#
#   * the package count is the SBOM's components (row 53: zero packages =
#     the scanner did not run, which is red — never a clean pass);
#   * every vulnerability blocks at ANY severity, except one covered by the
#     published OpenVEX document (.vex/) with status not_affected or fixed
#     — Inspector has no VEX input, so the document is applied here, the
#     one exception grype also honours via --vex.
#
# A VEX statement covers a finding when its vulnerability name (or an alias)
# is the finding's id AND one of the statement's products is this repo's
# image or Go module; if the product lists subcomponents, the affected
# package's name@version must be one of them (purl type and qualifiers
# ignored — the generator may call busybox pkg:generic or pkg:apk; a
# namespaced name such as a Go module path must match in full).
#
# Exit 0 = clean, 1 = findings, 2 = did not run (zero packages or unreadable
# input). The summary line always carries the counts.
#
# Usage: inspector-gate.py <label> <sbom.json> <findings.json> <openvex.json>
# Pure python3 + json, no network — exercised by bin/inspector-gate-test.sh.
import json
import re
import sys

OUR_PRODUCTS = re.compile(
    r"^pkg:(oci/cache(-candidates)?\?repository_url=ghcr\.io/fosterstack/cache(-candidates)?"
    r"|golang/github\.com/fosterstack/cache)(@|$|\?)")
SUPPRESSING = {"not_affected", "fixed"}


def name_version(purl_or_id):
    """pkg:<type>/<ns>/<name>@<ver>?q → (name, ver); '' when absent."""
    s = (purl_or_id or "").split("?", 1)[0].split("#", 1)[0]
    if s.startswith("pkg:"):
        s = s[4:].split("/", 1)[-1]
    name, _, ver = s.rpartition("@") if "@" in s else (s, "", "")
    return name.lower(), ver


def same_pkg(a, b):
    """Names match exactly, or — when one side carries no namespace (busybox
    vs alpine/busybox) — by last path segment. Versions must be equal."""
    (an, av), (bn, bv) = a, b
    if av != bv:
        return False
    if an == bn:
        return True
    if "/" in an and "/" in bn:
        return False
    return an.rsplit("/", 1)[-1] == bn.rsplit("/", 1)[-1]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def vex_index(doc):
    """vulnerability id → list of subcomponent (name, ver) sets; an empty set
    means the statement covers every package of our product."""
    idx = {}
    for st in doc.get("statements") or []:
        if not isinstance(st, dict) or st.get("status") not in SUPPRESSING:
            continue
        v = st.get("vulnerability") or {}
        ids = {v.get("name")} | set(v.get("aliases") or [])
        for p in st.get("products") or []:
            pid = p.get("@id") or (p.get("identifiers") or {}).get("purl") or ""
            if not OUR_PRODUCTS.match(pid):
                continue
            subs = {name_version(s.get("@id")) for s in p.get("subcomponents") or []}
            for i in ids:
                if i:
                    idx.setdefault(i, []).append(subs)
    return idx


def covered(idx, vid, pkg):
    for subs in idx.get(vid, []):
        if not subs or any(same_pkg(pkg, s) for s in subs):
            return True
    return False


def main(argv):
    if len(argv) != 5:
        print("usage: inspector-gate.py <label> <sbom.json> <findings.json> <openvex.json>", file=sys.stderr)
        return 2
    label, sbom_p, find_p, vex_p = argv[1:]
    try:
        sbom, findings, vex = load(sbom_p), load(find_p), load(vex_p)
    except (OSError, ValueError) as e:
        print(f"::error::inspector {label}: could not read its output ({e}) — did not run, not a clean pass")
        return 2
    comps = [c for c in sbom.get("components") or [] if isinstance(c, dict)]
    if not comps:
        print(f"::error::inspector {label}: 0 packages inventoried — did not run (row 53), not a clean pass")
        return 2
    by_ref = {}
    for c in comps + [c for c in findings.get("components") or [] if isinstance(c, dict)]:
        if c.get("bom-ref"):
            by_ref[c["bom-ref"]] = c
    idx = vex_index(vex)
    blocking, suppressed = [], []
    for v in findings.get("vulnerabilities") or []:
        vid = v.get("id") or "?"
        sev = ",".join(sorted({(r.get("severity") or "unknown") for r in v.get("ratings") or []})) or "unknown"
        for a in v.get("affects") or [{"ref": ""}]:
            c = by_ref.get(a.get("ref"), {})
            pkg = name_version(c.get("purl") or "")
            if not pkg[0]:
                pkg = ((c.get("name") or "?").lower(), c.get("version") or "")
            row = f"{vid} {pkg[0]}@{pkg[1]} ({sev})"
            (suppressed if covered(idx, vid, pkg) else blocking).append(row)
    print(f"inspector {label}: {len(comps)} packages, {len(blocking)} finding(s), "
          f"{len(suppressed)} covered by the published VEX")
    for r in suppressed:
        print(f"  vex: {r}")
    for r in blocking:
        print(f"::error::inspector {label}: {r}")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
