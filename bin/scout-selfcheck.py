#!/usr/bin/env python3
"""Scanner-panel rule 4 / REQ-SCAN-004-AC2, for Docker Scout: judge the rescan's self-check. Two GitLab reports of the
same fixture — `before` with a VEX file of our author that does not cover the target, `after` with one not_affected statement for
the target CVE. Passes only when the target is in `before`, gone from `after`, and every other finding of `before`
remains in `after` — the same (CVE, package, version), as often (an uncovered finding is kept). An empty or malformed report is refused, never read as suppression.
Usage: scout-selfcheck.py <before.json> <after.json> <CVE>"""
import json, sys
from collections import Counter


def findings(path):
    """The report's findings as a multiset of (CVE, package, version) — the identity bin/panel.py reads — never names
    alone (Codex #168 r2, B2: another package or version under a kept CVE is not the finding kept)."""
    try:
        doc = json.load(open(path))
    except (OSError, ValueError) as e:
        raise ValueError("%s: not a Scout report (%s)" % (path, e))
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise ValueError("%s: Scout's report has no vulnerabilities list" % path)
    out = Counter()
    for v in doc["vulnerabilities"]:
        # a finding's CVE is a non-blank string, never a number, a boolean or blanks (Codex #168 r3, B2)
        ids = [i.get("value") for i in (v.get("identifiers") or []) if isinstance(i, dict)] \
            if isinstance(v, dict) and isinstance(v.get("identifiers") or [], list) else []
        if not ids or not isinstance(ids[0], str) or not ids[0].strip():
            raise ValueError("%s: a finding whose identifier is not a CVE string" % path)
        dep = ((v.get("location") or {}).get("dependency") or {}) if isinstance(v, dict) else {}
        name, ver = ((dep.get("package") or {}).get("name"), dep.get("version")) if isinstance(dep, dict) else (None, None)
        if not isinstance(name, str) or not name.strip() or not isinstance(ver, str) or not ver.strip():
            raise ValueError("%s: a finding without its CVE, package or version" % path)
        out[(ids[0], name, ver)] += 1
    return out


def judge(before, after, target):
    covered = Counter({k: n for k, n in before.items() if k[0] == target})
    if not covered:
        return "the fixture's %s is not in Scout's report without a statement" % target
    rest = before - covered
    if not rest:
        return "no uncovered finding to prove the rest is kept"
    if any(k[0] == target for k in after):
        return "Scout kept %s although our statement covers it" % target
    if after != rest:
        return "Scout changed findings our statement does not cover: lost %s, gained %s" % (
            sorted((rest - after).elements()), sorted((after - rest).elements()))
    return None


# advisor 0106: which product identifiers does Scout match for our image? One statement per candidate, each on a
# different CVE the fixture really has; the report says which forms Scout applied (diagnostic — never the verdict)
FIXTURE_DIGEST = "sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab"
PROBE_FORMS = [
    "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache",                     # what we publish today
    "pkg:docker/ghcr.io/fosterstack/cache@selfcheck",
    "pkg:docker/ghcr.io/fosterstack/cache@" + FIXTURE_DIGEST,
    "pkg:docker/ghcr.io/fosterstack/cache",
    "pkg:oci/cache@" + FIXTURE_DIGEST.replace(":", "%3A") + "?repository_url=ghcr.io/fosterstack/cache",
    "ghcr.io/fosterstack/cache@" + FIXTURE_DIGEST,
]


def probe_doc(before_path, author, out_path):
    cves = sorted({k[0] for k in findings(before_path)} - {"CVE-1999-0001"})
    if len(cves) < len(PROBE_FORMS) + 1:
        raise ValueError("the fixture has too few findings to probe %d forms" % len(PROBE_FORMS))
    mapping = dict(zip(PROBE_FORMS, cves))
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://github.com/fosterstack/cache/scout-probe",
           "author": author, "timestamp": "2026-10-03T00:00:00Z", "version": 1,
           "statements": [{"vulnerability": {"name": c}, "status": "not_affected",
                           "justification": "vulnerable_code_not_present", "products": [{"@id": f}]}
                          for f, c in mapping.items()]}
    json.dump(doc, open(out_path, "w"), indent=1)
    json.dump(mapping, open(out_path + ".map", "w"), indent=1)


def probe_report(before_path, after_path, map_path):
    """Which forms Scout applied — only from a consistent delta (Codex #170 r1, B2): the findings that disappeared must be
    exactly the findings of the mapped CVEs that disappeared, every other finding (the uncovered control included) must
    remain as it was; anything else is reported as inconclusive, never as an applied form."""
    before, after = findings(before_path), findings(after_path)
    mapping = json.load(open(map_path))
    bc, ac = {k[0] for k in before}, {k[0] for k in after}
    gone = bc - ac
    applied = [f for f, c in mapping.items() if c in gone]
    expected_after = Counter({k: n for k, n in before.items() if k[0] not in {mapping[f] for f in applied}})
    unmapped = bc - set(mapping.values())
    # the advisor's question, answered on its own line (Codex #171 r1): which findings no statement covers were lost —
    # by (CVE, package, version), duplicates counted — and which findings appeared; mapped changes are the matrix below
    mapped = set(mapping.values())
    unc_before = Counter({k: n for k, n in before.items() if k[0] not in mapped})
    unc_after = Counter({k: n for k, n in after.items() if k[0] not in mapped})
    lost = sorted((unc_before - unc_after).elements())
    gained = sorted((after - before).elements())
    print("uncovered findings lost: %s" % (json.dumps([list(k) for k in lost]) if lost else "none"))
    print("findings gained: %s" % (json.dumps([list(k) for k in gained]) if gained else "none"))
    why = None
    if not unmapped:
        why = "no uncovered control finding in the fixture"
    elif not unmapped <= ac:
        why = "an uncovered finding disappeared too: %s" % sorted(unmapped - ac)
    elif after != expected_after:
        why = "findings changed beyond the mapped CVEs"
    if why:
        print("inconclusive: %s — no form reported as applied" % why)
        return []
    for f, c in mapping.items():
        print("%-9s %s  (%s)" % ("APPLIED" if f in applied else "ignored", f, c))
    print("applied: " + (", ".join(applied) or "none"))
    return applied


def probe_doc3(before_path, sbom_path, author, image, tag, out_path):
    """Advisor 0109, probe 3: statements that also name the finding's package — a subcomponent purl taken from Scout's
    own SBOM of the image — and platform-qualified image identifiers. Each form on a different CVE that affects exactly
    one package, so a drop is attributable."""
    before = findings(before_path)
    sbom = json.load(open(sbom_path))
    purl = {}
    for a in sbom.get("artifacts") or []:
        if isinstance(a, dict) and a.get("purl"):
            purl.setdefault((a.get("name"), a.get("version")), a["purl"])
    per_cve = {}
    for (cve, name, ver), n in before.items():
        per_cve.setdefault(cve, []).append((name, ver, n))
    single = sorted(c for c, ps in per_cve.items() if len(ps) == 1 and ps[0][2] == 1 and (ps[0][0], ps[0][1]) in purl
                    and c != "CVE-1999-0001")
    plat = "?platform=linux%2Famd64"
    repo = image.rsplit("/", 1)[-1]
    forms = [  # (label, product @id, with the package as a subcomponent)
        ("oci+repo, package", "pkg:oci/%s?repository_url=%s" % (repo, image), True),
        ("docker tag, package", "pkg:docker/%s@%s" % (image, tag), True),
        ("docker tag+platform", "pkg:docker/%s@%s%s" % (image, tag, plat), False),
        ("docker tag+platform, package", "pkg:docker/%s@%s%s" % (image, tag, plat), True),
        ("docker digest+platform, package", "pkg:docker/%s@%s%s" % (image, FIXTURE_DIGEST, plat), True),
        ("docker name, package", "pkg:docker/%s" % image, True),
    ]
    if len(single) < len(forms) + 1:
        raise ValueError("the fixture has too few single-package findings with an SBOM purl (%d)" % len(single))
    mapping, statements = {}, []
    for (label, pid, sub), cve in zip(forms, single):
        name, ver, _ = per_cve[cve][0]
        prod = {"@id": pid}
        if sub:
            prod["subcomponents"] = [{"@id": purl[(name, ver)]}]
        statements.append({"vulnerability": {"name": cve}, "status": "not_affected",
                           "justification": "vulnerable_code_not_present", "products": [prod]})
        mapping["%s: %s%s" % (label, pid, " + " + purl[(name, ver)] if sub else "")] = cve
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://github.com/fosterstack/cache/scout-probe-3",
           "author": author, "timestamp": "2026-10-03T00:00:00Z", "version": 1, "statements": statements}
    json.dump(doc, open(out_path, "w"), indent=1)
    json.dump(mapping, open(out_path + ".map", "w"), indent=1)


def main(argv):
    if argv[1:2] == ["probe-doc"]:
        try:
            probe_doc(argv[2], argv[3], argv[4])
        except ValueError as e:
            print("::warning::Scout probe: %s" % e, file=sys.stderr)
            return 1
        return 0
    if argv[1:2] == ["probe-doc3"]:
        try:
            probe_doc3(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7])
        except (ValueError, OSError, KeyError) as e:
            print("::warning::Scout probe 3: %s" % e, file=sys.stderr)
            return 1
        return 0
    if argv[1:2] == ["probe-report"]:
        try:
            probe_report(argv[2], argv[3], argv[4])
        except (ValueError, OSError) as e:
            print("::warning::Scout probe: %s" % e, file=sys.stderr)
        return 0
    try:
        why = judge(findings(argv[1]), findings(argv[2]), argv[3])
    except ValueError as e:
        why = str(e)
    if why:
        print("::error::Scout self-check: %s" % why, file=sys.stderr)
        return 1
    print("Scout applies our VEX: %s dropped, every other finding kept" % argv[3])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
