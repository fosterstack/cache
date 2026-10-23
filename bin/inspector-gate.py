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
# Image scope (REQ-REL-004-AC1): a product with variant= and/or arch= qualifiers covers only the image whose label ends in
# <variant>-<arch> (production|fips, amd64|arm64) and agrees on every qualifier it carries; a product with neither covers every
# image. A scoped product never covers an image whose identity the label does not give, and a repeated qualifier is ambiguous: no cover.
#
# ScanSbom answers {"sbom": <CycloneDX document>}; the document is unwrapped
# here, and a response that is neither that envelope nor a CycloneDX
# document is "did not run" — never read as zero findings.
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
    r"^pkg:(oci/cache\?repository_url=ghcr\.io/fosterstack/cache"
    r"|oci/cache-candidates\?repository_url=ghcr\.io/fosterstack/cache-candidates"
    r"|golang/github\.com/fosterstack/cache)(@|$|&|\?)")
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
    vs the busybox of another namespace) — by last path segment. Versions must be equal."""
    (an, av), (bn, bv) = a, b
    if av != bv:
        return False
    if an == bn:
        return True
    if "/" in an and "/" in bn:
        return False
    return an.rsplit("/", 1)[-1] == bn.rsplit("/", 1)[-1]


IMAGE = re.compile(r"cand-(production|fips)-(amd64|arm64)")   # the tag scan.yml loads every image under: cand-<variant>-<arch>, nothing before or after
VARIANTS = ("production", "fips")
ARCHES = ("amd64", "arm64")


def image_identity(label):
    m = IMAGE.fullmatch(label or "")
    return {"variant": m.group(1), "arch": m.group(2)} if m else {}


def scope_of(product_id):
    """{'variant': .., 'arch': ..} the product names (only those present), read in the rescan statement's grammar: the query is split raw on '&' (no
    percent-decoding), every part is key=value with a non-blank value, the keys are only repository_url, variant and arch, in lower case, each once, variant
    is production or fips and arch is amd64 or arm64. Anything else is None: that product covers nothing (the finding blocks), the rest of the document is
    unaffected."""
    base, q, query = product_id.partition("?")
    if base.startswith("pkg:golang/"):
        return {} if not q and "@" not in base and "\n" not in product_id else None   # the Go product: unversioned, no qualifier (a pinned one never applies). A trailing newline (which OUR_PRODUCTS's $ lets through) is refused here although the rescan reads it as the Go product: the gate only ever blocks more, never suppresses more.
    repo = {"pkg:oci/cache": "ghcr.io/fosterstack/cache", "pkg:oci/cache-candidates": "ghcr.io/fosterstack/cache-candidates"}.get(base)
    if repo is None or not q:
        return None
    scope, seen = {}, set()
    for part in query.split("&"):
        k, eq, v = part.partition("=")
        if not eq or not v or k not in ("repository_url", "variant", "arch") or k in seen:
            return None
        seen.add(k)
        if k == "repository_url" and v != repo:
            return None
        if k == "variant" and v not in VARIANTS or k == "arch" and v not in ARCHES:
            return None
        if k != "repository_url":
            scope[k] = v
    return scope if "repository_url" in seen else None


def in_scope(scope, image):
    return scope is not None and all(image.get(k) == v for k, v in scope.items())


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def vex_index(doc):
    """vulnerability id → list of (subcomponent (name, ver) set, product scope); an empty set
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
                    idx.setdefault(i, []).append((subs, scope_of(pid)))
    return idx


def covered(idx, vid, pkg, image=None):
    """image = the scanned image's identity (image_identity(label)); None means the caller has already filtered the statements to
    this image (the panel's tally does, per image), so the scope is not applied a second time."""
    for subs, scope in idx.get(vid, []):
        if image is not None and not in_scope(scope, image):
            continue
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
    if isinstance(findings, dict) and isinstance(findings.get("sbom"), dict):
        findings = findings["sbom"]
    if not isinstance(findings, dict) or findings.get("bomFormat") != "CycloneDX":
        print(f"::error::inspector {label}: the ScanSbom response is not a CycloneDX document "
              '(expected {"sbom": {"bomFormat": "CycloneDX", ...}}) — did not run, not a clean pass')
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
    image = image_identity(label)
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
            (suppressed if covered(idx, vid, pkg, image) else blocking).append(row)
    print(f"inspector {label}: {len(comps)} packages, {len(blocking)} finding(s), "
          f"{len(suppressed)} covered by the published VEX")
    for r in suppressed:
        print(f"  vex: {r}")
    for r in blocking:
        print(f"::error::inspector {label}: {r}")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
