#!/usr/bin/env python3
# The PR gate's Amazon Inspector verdict for one scanned image (scan.yml,
# decision row 57). inspector-sbomgen writes a CycloneDX SBOM of the image;
# inspector-scan:ScanSbom returns that SBOM annotated with vulnerabilities.
# This reads both and decides, the same way the grype leg does:
#
#   * the package count is the SBOM's components that carry a package URL (row 53: zero packages =
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
import datetime
import sys
import urllib.parse

OUR_PRODUCTS = re.compile(
    r"^pkg:(oci/cache\?repository_url=ghcr\.io/fosterstack/cache"
    r"|oci/cache-candidates\?repository_url=ghcr\.io/fosterstack/cache-candidates"
    r"|golang/github\.com/fosterstack/cache)(@|$|&|\?)")
SUPPRESSING = {"not_affected", "fixed"}


def is_package_url(purl):   # pkg:deb/debian/glibc@2.36 is one; "not-a-purl", "pkg:" and "pkg:/" are not: a type, a slash, then a name
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return False
    slash = purl.find("/", 4)
    return 4 < slash < len(purl) - 1


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
    if bv and av != bv:                 # a subcomponent that names no version stands for every version of that package (as the generated Inspector rule reads it)
        return False
    if an == bn:
        return True
    if any("/" in n and "." in n.split("/", 1)[0] for n in (an, bn)):
        return False                    # a Go module path (host-like first segment) must match in full, never by its last segment
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
        return {} if product_id == "pkg:golang/github.com/fosterstack/cache" else None   # the Go product: unversioned, no qualifier (a pinned one never applies). A trailing newline (which OUR_PRODUCTS's $ lets through) is refused here, and the rescan refuses the document (the exact product only): the gate only ever blocks more, never suppresses more.
    # only this gate's own repository: the images it scans are ghcr.io/fosterstack/cache:cand-<variant>-<arch>, so a statement that names only the
    # candidates repository covers none of them (bin/rescan-statement.py::_vex_match and bin/panel.py::_covers agree; REQ-REL-004-AC1)
    repo = {"pkg:oci/cache": "ghcr.io/fosterstack/cache"}.get(base)
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


def _stamp(value):
    """A statement's timestamp as an aware datetime, or None when it is missing or unreadable (ISO 8601; a trailing Z is UTC; no offset is read as UTC)."""
    if not isinstance(value, str):
        return None
    try:
        d = datetime.datetime.fromisoformat(value.strip()[:-1] + "+00:00" if value.strip().endswith("Z") else value.strip())
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def _product_key(pid):
    """What the readers match a product on, not how it is spelled: the scope (variant, architecture; the query's order and nothing else decides nothing) of this
    gate's own image or of the exact Go product; any other string (a product the readers drop or refuse) is compared as written."""
    sc = scope_of(pid) if isinstance(pid, str) else None
    if sc is None:
        return ("raw", pid)
    return ("fosterstack-module",) if pid.startswith("pkg:golang/") else ("oci", sc.get("variant"), sc.get("arch"))


def _package_key(sid):
    """A subcomponent the way the matchers see it, widened on purpose: percent-decoded, case-folded, the purl type and any namespace ignored (the last path segment),
    with its version. Treating two spellings as one package only ever retracts MORE (a fail-closed direction)."""
    s = urllib.parse.unquote(str(sid)).split("?", 1)[0].split("#", 1)[0]
    s = s[4:].split("/", 1)[-1] if s.startswith("pkg:") else s
    name, _, ver = s.rpartition("@") if "@" in s else (s, "", "")
    return (name.rsplit("/", 1)[-1].lower(), ver)


def superseded(statements):
    """{(statement index, product index)} that a LATER statement for the same vulnerability, product and subcomponent set replaces: the latest statement of such a
    pair is the current one, whatever its status, so a later `affected` retracts an earlier `not_affected`. The vulnerability is the whole alias class (a statement
    that names CVE and GHSA ids links them for the whole document); the product and the packages are compared by what the readers match on (_product_key,
    _package_key), not by spelling. 'Later' is one total order per pair: by timestamp when EVERY statement of the pair carries a readable one (equal times: document
    order), else by document order for the whole pair."""
    parent = {}
    def alias_root(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    named = []
    for st in statements:
        v = (st.get("vulnerability") or {}) if isinstance(st, dict) else {}
        ids = [x for x in ([v.get("name")] + list(v.get("aliases") or [])) if isinstance(x, str) and x]
        named.append(ids)
        for x in ids[1:]:
            parent[alias_root(x)] = alias_root(ids[0])
    groups = {}
    for i, st in enumerate(statements):
        if not isinstance(st, dict) or not named[i]:
            continue
        for pi, p in enumerate(st.get("products") or []):
            if not isinstance(p, dict):
                continue
            at = p.get("@id")
            pid = at if at is not None else (p.get("identifiers") or {}).get("purl") or ""
            subs = frozenset(_package_key(s.get("@id")) for s in p.get("subcomponents") or [] if isinstance(s, dict))
            groups.setdefault((alias_root(named[i][0]), _product_key(pid), subs), []).append((i, pi, _stamp(st.get("timestamp"))))
    dead = set()
    for entries in groups.values():
        if len({e[0] for e in entries}) < 2:
            continue
        timed = all(e[2] is not None for e in entries)
        order = sorted(entries, key=(lambda e: (e[2], e[0], e[1])) if timed else (lambda e: (e[0], e[1])))
        winner = order[-1]
        for e in entries:
            if e[0] != winner[0]:
                dead.add((e[0], e[1]))
    return dead


def vex_index(doc):
    """vulnerability id → list of (subcomponent (name, ver) set, product scope); an empty set
    means the statement covers every package of our product."""
    idx = {}
    dead = superseded(doc.get("statements") or [])
    for si, st in enumerate(doc.get("statements") or []):
        if not isinstance(st, dict) or st.get("status") not in SUPPRESSING:
            continue
        v = st.get("vulnerability") or {}
        ids = {v.get("name")} | set(v.get("aliases") or [])
        for pi, p in enumerate(st.get("products") or []):
            if (si, pi) in dead:       # a later statement of the same vulnerability, product and subcomponents replaces this one
                continue
            pid = p.get("@id") if p.get("@id") is not None else (p.get("identifiers") or {}).get("purl") or ""   # an @id that is present (even "") is the id, as the rescan reads it; only a missing or null one falls back
            if not isinstance(pid, str) or not OUR_PRODUCTS.match(pid):
                continue
            scope = scope_of(pid)
            if scope is None:          # not this gate's repository, or a scope the grammar rejects: it covers nothing, with or without an image (covered(.., image=None) trusts the index)
                continue
            subs = {name_version(s.get("@id")) for s in p.get("subcomponents") or []}
            for i in ids:
                if i:
                    idx.setdefault(i, []).append((subs, scope))
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
    # packages are the components that carry a package URL (pkg:deb/debian/glibc@2.36), not any string (the grype gate and the panel count the same way; files and an
    # operating-system component are not packages): none = the scanner looked at nothing (row 53)
    n_pkg = sum(1 for c in comps if is_package_url(c.get("purl")))
    if not n_pkg:
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
    print(f"inspector {label}: {n_pkg} packages, {len(blocking)} finding(s), "
          f"{len(suppressed)} covered by the published VEX")
    for r in suppressed:
        print(f"  vex: {r}")
    for r in blocking:
        print(f"::error::inspector {label}: {r}")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
