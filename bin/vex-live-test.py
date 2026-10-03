#!/usr/bin/env python3
"""Scanner-panel rule 12 (owner RATIFIED Oct 2; REQ-SCAN-012; read-back approved, advisor 0098): the offline half of the
live test. bin/vex-live-test.sh does the cloud calls; this file decides what they run on.

- plan:          the guide's ```sh blocks, byte for byte, in order — a settings block (only VAR=value lines: VER, IMAGE)
                 takes the test's values, every other block runs exactly as written
- test-files:    the forms the live test loads: the generator's output for the real OpenVEX file plus ONE test-only
                 not_affected statement for the fixture's CVE on the fixture's digest; the Inspector file's test copy
                 differs from the generator's only in the live-test tag and the test name prefix (check_copy proves it)
- pick-cve:      a CVE every service reports for the fixture, highest severity first — never a guess
- release:       on main, the newest published release that carries the rule-10 files
"""
import argparse, copy, importlib.util, json, os, re, sys

REPO_PURL = "pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache"
PREFIX, TEST_PREFIX = "fosterstack-cache-", "fosterstack-cache-livetest-"
TAG = {"fosterstack-purpose": "live-test"}           # the live-test role's CreateFilter/DeleteFilter fence (ops Terraform)
SETTINGS = ("VER", "IMAGE")
SEVERITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SECTIONS = [("settings", None), ("digest", "imagetools inspect"), ("download", "curl -fsSLO"),
            ("verify", "cosign verify-attestation"), ("grype", "grype "), ("scout", "docker scout cves"),
            ("inspector", "create-filter"), ("google", "load-vex"), ("inspector-remove", "delete-filter")]


def _forms():
    spec = importlib.util.spec_from_file_location("vex_forms", os.path.join(os.path.dirname(__file__), "vex-forms.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def guide_blocks(text):
    """[{kind, section, text}] for every ```sh block of the guide, in order and byte for byte."""
    out = []
    for body in re.findall(r"```sh\n(.*?)```", text, re.S):
        if re.fullmatch(r"(?:[A-Z_]+=\S.*\n)+", body) and set(re.findall(r"(?m)^([A-Z_]+)=", body)) <= set(SETTINGS):
            out.append({"kind": "settings", "section": "settings", "text": body})
            continue
        found = [name for name, key in SECTIONS[1:] if key in body]
        if len(found) != 1:
            raise ValueError("a guide block is not exactly one known step: %r" % body[:80])
        out.append({"kind": "command", "section": found[0], "text": body})
    return out


def render_settings(values):
    if set(values) - set(SETTINGS) - {"DIGEST"}:
        raise ValueError("not a guide setting: %s" % sorted(set(values) - set(SETTINGS) - {"DIGEST"}))
    for k, v in values.items():
        if not re.fullmatch(r"[A-Za-z0-9._:/@-]+", v):
            raise ValueError("%s=%r is not a plain value" % (k, v))
    return "".join("%s='%s'\n" % (k, v) for k, v in values.items())   # plain values only: quoting cannot break


def fixture_vex(vex, images, fixture_digest, cve):
    """The real statements unchanged, plus one test-only not_affected statement for the fixture; the fixture becomes an
    extra child of production so the generator scopes it like any digest of ours."""
    tvex = copy.deepcopy(vex)
    tvex["statements"].append({
        "vulnerability": {"name": cve}, "status": "not_affected", "justification": "vulnerable_code_not_present",
        "impact_statement": "live test (scanner-panel rule 12): a test-only statement for the fixture image",
        "products": [{"@id": REPO_PURL % fixture_digest}]})
    timages = copy.deepcopy(images)
    timages["production"]["children"]["linux/fixture"] = fixture_digest
    return tvex, timages


def inspector_files(V, vex, images, fixture_digest, cve, version):
    """(shipped, generated): the generator's file for the real statements, and that file plus the generator's filters
    for the fixture statement ALONE — so no real statement widens to the fixture's digest."""
    if cve in {s["vulnerability"]["name"] for s in vex["statements"]}:
        raise ValueError("%s is one of our statements: the fixture's CVE must be another" % cve)
    tvex, timages = fixture_vex(vex, images, fixture_digest, cve)
    shipped = V.inspector(vex, images, version)
    fixture = V.inspector({"statements": tvex["statements"][-1:]}, timages, version)
    return shipped, {"filters": shipped["filters"] + fixture["filters"]}


def test_copy(generated):
    out = copy.deepcopy(generated)
    for f in out["filters"]:
        if not f["name"].startswith(PREFIX):
            raise ValueError("a generated filter without our prefix: %s" % f["name"])
        f["name"] = (TEST_PREFIX + f["name"][len(PREFIX):])[:128]
        f["tags"] = dict(TAG)
    return out


def check_copy(shipped, test_generated, copy_, fixture_digest):
    """[] when the test copy is the shipped file with only the tag and the test prefix changed, plus exactly the
    generator's filters for the fixture statement (likewise tagged and prefixed); the differences otherwise."""
    bad = []
    fixture = [f for f in test_generated["filters"] if f not in shipped["filters"]]
    if any(fixture_digest not in [c["value"] for c in f["filterCriteria"]["ecrImageHash"]] for f in fixture):
        bad.append("a filter beyond the shipped ones does not belong to the fixture")
    want = test_copy({"filters": shipped["filters"] + fixture})["filters"]
    got = copy_.get("filters") or []
    if set(copy_) != {"filters"}:
        bad.append("the copy carries keys beyond filters: %s" % sorted(copy_))
    if len(got) != len(want):
        bad.append("the copy has %d filters, the shipped file and the fixture %d" % (len(got), len(want)))
    for g, w in zip(got, want):
        if g != w:
            bad.append("filter %s differs beyond the tag and the prefix" % w["name"])
    return bad


def pick_cve(reports, exclude=()):
    """reports: {"grype": {cve: severity}, "inspector": set, "google": set, "scout": set}; never one of ours (exclude)."""
    common = set(reports["grype"]) - set(exclude)
    for k in ("inspector", "google", "scout"):
        common &= set(reports[k])
    if not common:
        raise ValueError("no CVE that every service reports for the fixture")
    return sorted(common, key=lambda c: (SEVERITY.get(reports["grype"][c], 9), c))[0]


def _semver(tag):
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?", tag)
    return None if not m else (int(m[1]), int(m[2]), int(m[3]), int(m[4]) if m[4] else 1 << 30)


def release_under_test(releases):
    ok = [r["tagName"] for r in releases if not r.get("isDraft") and _semver(r["tagName"])
          and "fosterstack-cache-%s.csaf.json" % r["tagName"] in r.get("assets", [])]
    return max(ok, key=_semver) if ok else None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vex-live-test")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--guide", required=True)
    p.add_argument("--out-dir", required=True)
    t = sub.add_parser("test-files")
    t.add_argument("--openvex", required=True)
    t.add_argument("--images", required=True)
    t.add_argument("--version", required=True)
    t.add_argument("--fixture-digest", required=True)
    t.add_argument("--cve", required=True)
    t.add_argument("--out-dir", required=True)
    c = sub.add_parser("pick-cve")
    c.add_argument("--reports", required=True)
    c.add_argument("--openvex", required=True, help="our statements: their CVEs are never the fixture's")
    st = sub.add_parser("settings", help="print the test's values as the guide's settings (VAR=value ...)")
    st.add_argument("pairs", nargs="+")
    r = sub.add_parser("release")
    r.add_argument("--releases", required=True, help="gh release list --json tagName,isDraft + assets names")
    a = ap.parse_args(argv)
    if a.cmd == "plan":
        for i, b in enumerate(guide_blocks(open(a.guide).read())):
            with open(os.path.join(a.out_dir, "%02d-%s.sh" % (i, b["section"])), "w") as fh:
                fh.write(b["text"])
            print("%02d-%s.sh" % (i, b["section"]))
        return 0
    if a.cmd == "test-files":
        V = _forms()
        vex, images = json.load(open(a.openvex)), json.load(open(a.images))
        tvex, timages = fixture_vex(vex, images, a.fixture_digest, a.cve)
        shipped, generated = inspector_files(V, vex, images, a.fixture_digest, a.cve, a.version)
        tc = test_copy(generated)
        bad = check_copy(shipped, generated, tc, a.fixture_digest)
        if bad:
            print("\n".join(bad), file=sys.stderr)
            return 1
        base = os.path.join(a.out_dir, "fosterstack-cache-%s" % a.version)
        json.dump(tvex, open(os.path.join(a.out_dir, "fosterstack-cache.openvex.json"), "w"), indent=1)
        json.dump(tc, open(base + ".inspector-filters.json", "w"), indent=1)
        json.dump(V.csaf(tvex, timages, a.version), open(base + ".csaf.json", "w"), indent=1)
        return 0
    if a.cmd == "pick-cve":
        rep = json.load(open(a.reports))
        ours = {s["vulnerability"]["name"] for s in json.load(open(a.openvex))["statements"]}
        print(pick_cve({k: (v if k == "grype" else set(v)) for k, v in rep.items()}, ours))
        return 0
    if a.cmd == "settings":
        sys.stdout.write(render_settings(dict(p.split("=", 1) for p in a.pairs)))
        return 0
    found = release_under_test(json.load(open(a.releases)))
    print(found or "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
