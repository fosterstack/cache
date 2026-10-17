#!/usr/bin/env python3
"""Scanner-panel rule 12 (owner RATIFIED Oct 2; REQ-SCAN-012; read-back approved, advisor 0098): the offline half of the
live test. bin/vex-live-run.sh does the cloud calls; this file decides what they run on.

- plan:          the guide's ```sh blocks, byte for byte, in order — a settings block (only VAR=value lines: VER, IMAGE)
                 takes the test's values, every other block runs exactly as written
- test-files:    the forms the live test loads: the generator's output for the real OpenVEX file plus ONE test-only
                 not_affected statement for the fixture's CVE on the fixture's digest (in the Inspector file it names the package
                 Inspector found it in, plus a decoy: another CVE at a version that is not installed, which must hide nothing); the Inspector file's test copy
                 differs from the generator's only in the live-test tag and the test name prefix (check_copy proves it)
- pick-cve:      a CVE every service reports for the fixture, highest severity first — never a guess
- pick-scope:    the package Inspector reports that CVE in, and the decoy CVE (owner Oct 16: every Inspector rule names its package)
- release:       on main, the newest published release that carries the rule-10 files
"""
import argparse, copy, importlib.util, json, os, re, sys

REPO_PURL = "pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache"
PREFIX, TEST_PREFIX = "fosterstack-cache-", "fosterstack-cache-livetest-"
TAG = {"fosterstack-purpose": "live-test"}           # the live-test role's CreateFilter/DeleteFilter fence (ops Terraform)
SETTINGS = ("VER", "IMAGE")
SEVERITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SECTIONS = [("settings", None), ("digest", "imagetools inspect"), ("download", "curl -fsSLO"),
            ("verify", "cosign verify-attestation"), ("grype", "grype "),
            ("inspector", "create-filter"), ("google", "load-vex"), ("inspector-remove", "delete-filter")]


def _forms():
    spec = importlib.util.spec_from_file_location("vex_forms", os.path.join(os.path.dirname(__file__), "vex-forms.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _sh_fences(text):
    """The bodies of the real top-level ```sh blocks of a Markdown text, byte for byte: a fence is a line of 0-3 spaces then 3 or more backticks or tildes
    (CommonMark); it closes at a line of the same character, at least as long, and nothing else. Only an opening line that is exactly three backticks and sh
    (up to 3 spaces of indent: the page's removal block sits in a list item) is a command block; every other fenced block (a longer fence, a tilde fence, one indented 4 or more, a differently named one) is text and its
    contents, even a nested ```sh line, are never commands; a block that is never closed is refused."""
    lines, i, out = text.split("\n"), 0, []
    while i < len(lines):
        m = re.fullmatch(r"( {0,3})(`{3,}|~{3,})(.*)", lines[i])
        if not m:
            # HTML hides Markdown from a reader (a comment or a raw block can wrap a fence the reader never sees), so outside a fence the page may hold neither a line that
            # starts a raw HTML block nor a comment that opens and does not close on its line (the one-line pinned markers at the end of a text line are fine)
            if re.match(r" {0,3}<[A-Za-z/?!]", lines[i]) or re.search(r"<!--(?!.*-->)", lines[i]):
                raise ValueError("the page holds a raw HTML block or a multi-line comment at line %d: not parsed" % (i + 1))
            # a fence opened inside a list item or a block quote (a marker, then the fence on the same line) belongs to a container this parser does not model, and the lines
            # after it are read differently by a Markdown reader: refused, not parsed
            if re.match(r"[ \t]*(?:>[ \t]*|(?:[-*+]|\d{1,9}[.)])[ \t]+)+(?:`{3,}|~{3,})", lines[i]):
                raise ValueError("a fence is opened inside a list item or a block quote at line %d: not parsed" % (i + 1))
            i += 1
            continue
        indent, fence, info = m.groups()
        if fence[0] == "`" and "`" in info:     # an inline code span, not a fence
            i += 1
            continue
        closer = re.compile(r" {0,3}%s{%d,}[ \t]*" % (re.escape(fence[0]), len(fence)))
        j = i + 1
        while j < len(lines) and not closer.fullmatch(lines[j]):
            j += 1
        if j >= len(lines):
            raise ValueError("a fenced block that starts at line %d is never closed" % (i + 1))
        if fence == "```" and info == "sh":
            out.append("\n".join(lines[i + 1:j]) + "\n")
        i = j + 1
    return out


def guide_blocks(text, skip=(), pins=None):
    """[{kind, section, text}] for every ```sh block of the guide, in order and byte for byte. skip: the exact texts of the blocks
    the cannot-run list names (a release candidate publishes nothing, so the blocks that read a release or a registry cannot run
    on it); each must be a block of the guide and only a digest, download, verify or Grype (the scan of the published image) block may be skipped."""
    out = []
    for body in _sh_fences(text):
        # a setting is a plain value and nothing else: VER=0.3.0; false is a command the plan must run (Codex #169 r1,
        # SEC-169-04), so it is not a setting, and a block that is not one known step is refused below
        if re.fullmatch(r"(?:(?:%s)=[A-Za-z0-9._/:@-]+\n)+" % "|".join(SETTINGS), body):
            out.append({"kind": "settings", "section": "settings", "text": body})
            continue
        found = [name for name, key in SECTIONS[1:] if key in body]
        if len(found) != 1:
            raise ValueError("a guide block is not exactly one known step: %r" % body[:80])
        out.append({"kind": "command", "section": found[0], "text": body})
    if pins is not None:    # the live test runs ONLY the pinned blocks, in order: whatever a Markdown reader and this parser disagree about is stopped here
        import hashlib
        got = [(b["section"], hashlib.sha256(b["text"].encode()).hexdigest()) for b in out]
        want = [(x["section"], x["sha256"]) for x in pins]
        if got != want:
            raise ValueError("the page's command blocks are not the pinned ones (docs/using-our-vex.live-blocks.json): %d found, %d pinned" % (len(got), len(want)))
    texts = [b["text"] for b in out]
    for s in skip:
        if texts.count(s) != 1:
            raise ValueError("a cannot-run entry is not exactly one block of the guide: %r" % s[:60])
    skipped = [b for b in out if b["text"] in set(skip)]
    if any(b["section"] not in ("digest", "download", "verify", "grype") for b in skipped):
        raise ValueError("only a digest, download, verify or published-image Grype block may be skipped on a release candidate")
    return [b for b in out if b["text"] not in set(skip)] if skip else out


def render_settings(values):
    if set(values) - set(SETTINGS) - {"DIGEST"}:
        raise ValueError("not a guide setting: %s" % sorted(set(values) - set(SETTINGS) - {"DIGEST"}))
    for k, v in values.items():
        if not re.fullmatch(r"[A-Za-z0-9._:/@-]+", v):
            raise ValueError("%s=%r is not a plain value" % (k, v))
    return "".join("%s='%s'\n" % (k, v) for k, v in values.items())   # plain values only: quoting cannot break


def fixture_vex(vex, images, fixture_digest, cve, repository="ghcr.io/fosterstack/cache"):
    """The real statements unchanged, plus one test-only not_affected statement for the fixture. The images map for the
    fixture's own filters is a valid two-variant digest file (the generator takes exactly production and fips, each with an
    index and the two platform children): production's index is the fixture digest (its children are the real ones, which the statement
    does not name), so the generator scopes the statement to the fixture alone; fips stays as it is."""
    tvex = copy.deepcopy(vex)
    tvex["statements"].append({
        "vulnerability": {"name": cve}, "status": "not_affected", "justification": "vulnerable_code_not_present",
        "impact_statement": "live test (scanner-panel rule 12): a test-only statement for the fixture image",
        "products": [{"@id": "pkg:oci/cache@%s?repository_url=%s" % (fixture_digest, repository)}]})
    timages = copy.deepcopy(images)
    timages["production"] = {"index": fixture_digest, "children": images["production"]["children"]}
    return tvex, timages


PKG_NAME = r"[A-Za-z0-9._+-]+"
PKG_VERSION = r"[A-Za-z0-9._+:~-]+"
DECOY_VERSION = "0.0.0-livetest-not-installed"


def pick_scope(reports, cve, exclude=()):
    """The package the fixture's rule names and the decoy (owner Oct 16, handoff 0482: an Inspector rule always names its package, and the same CVE in another
    package must stay visible). reports["inspector"]: {cve: [{name, version}]} as Inspector lists them for the fixture. The package: the CVE's first package by
    name and version; the decoy: the first OTHER CVE Inspector reports (never one of ours, exclude) with its first package's name — its rule gets a version that
    is not installed, so a correct rule hides nothing. A name or version the OpenVEX/Inspector forms cannot carry is refused."""
    insp = reports.get("inspector")
    if not isinstance(insp, dict):
        raise ValueError("the Inspector report is not a CVE -> packages map")

    def first(c):
        pk = insp.get(c)
        if not isinstance(pk, list) or not pk:
            raise ValueError("Inspector reports no package for %s" % c)
        for x in pk:
            if not (isinstance(x, dict) and isinstance(x.get("name"), str) and re.fullmatch(PKG_NAME, x["name"])
                    and isinstance(x.get("version"), str) and re.fullmatch(PKG_VERSION, x["version"])):
                raise ValueError("a package of %s has a name or version the forms cannot carry: %r" % (c, x))
        x = sorted(pk, key=lambda y: (y["name"], y["version"]))[0]
        return {"name": x["name"], "version": x["version"]}
    package = first(cve)
    if len({x["name"] for x in insp[cve]}) < 2:
        raise ValueError("Inspector reports %s in one package only: the run could not show the same CVE staying visible in another" % cve)
    others = sorted(c for c in insp if c != cve and c not in set(exclude))
    if not others:
        raise ValueError("Inspector reports no other CVE of its own to use as the decoy")
    return {"package": package, "decoy": {"cve": others[0], "name": first(others[0])["name"]}}


def inspector_files(V, vex, images, fixture_digest, cve, version, scope):
    """(shipped, generated): the generator's file for the real statements, and that file plus the generator's filters
    for the fixture's statements ALONE — so no real statement widens to the fixture's digest. The fixture's statements
    name a package (the generator makes no rule for a statement that names none): the fixture CVE in the package Inspector
    found it in, and the decoy CVE in its package at a version that is not installed (it must suppress nothing)."""
    if cve in {s["vulnerability"]["name"] for s in vex["statements"]}:
        raise ValueError("%s is one of our statements: the fixture's CVE must be another" % cve)
    if not isinstance(scope, dict) or not isinstance(scope.get("package"), dict) or not isinstance(scope.get("decoy"), dict):
        raise ValueError("the fixture's package and decoy are needed: the Inspector file never holds a rule without a package")
    if scope["decoy"]["cve"] in (cve, *{s["vulnerability"]["name"] for s in vex["statements"]}):
        raise ValueError("the decoy CVE must be neither the fixture's nor one of ours")
    tvex, timages = fixture_vex(vex, images, fixture_digest, cve)
    own = tvex["statements"][-1]
    st = copy.deepcopy(own)
    st["products"][0]["subcomponents"] = [{"@id": "pkg:generic/%s@%s" % (scope["package"]["name"], scope["package"]["version"])}]
    decoy = copy.deepcopy(own)
    decoy["vulnerability"] = {"name": scope["decoy"]["cve"]}
    decoy["products"][0]["subcomponents"] = [{"@id": "pkg:generic/%s@%s" % (scope["decoy"]["name"], DECOY_VERSION)}]
    shipped = V.inspector(vex, images, version)
    fixture = V.inspector({"statements": [st, decoy]}, timages, version)
    return shipped, {"filters": shipped["filters"] + fixture["filters"]}


STATE_KEYS = ("VER", "IMAGE", "DIGEST")
STATE_VALUE = {"VER": r"[A-Za-z0-9._-]+", "IMAGE": r"[A-Za-z0-9._:/@-]+", "DIGEST": r"sha256:[0-9a-f]{64}"}


def read_state(path):
    """{VER, IMAGE, DIGEST} that are set, from lines NAME='value' (the only form this file is written in); anything else is refused."""
    out = {}
    if not os.path.exists(path):
        return out
    for ln in open(path).read().split("\n"):
        if not ln:
            continue
        m = re.fullmatch(r"([A-Z]+)='([^']*)'", ln)
        if not m or m[1] not in STATE_KEYS or not re.fullmatch(STATE_VALUE[m[1]], m[2]) or m[1] in out:
            raise ValueError("the state file holds a line that is not a plain setting: %r" % ln[:60])
        out[m[1]] = m[2]
    return out


def write_state(path, values):
    for k, v in values.items():
        if k not in STATE_KEYS or not re.fullmatch(STATE_VALUE[k], v):
            raise ValueError("%s=%r is not a plain value" % (k, v))
    with open(path, "w") as fh:
        for k in STATE_KEYS:
            if k in values:
                fh.write("%s='%s'\n" % (k, values[k]))


def run_guide(plan, state_path, section, plan_dir=None):
    """Run every command block of one section of the page, exactly as written, in ONE bash under errexit AND pipefail (a failing command anywhere, inside a pipe
    too, stops the run), with the test's settings (VER, IMAGE, DIGEST) set. Afterwards only those three values are carried on, validated; the blocks may not
    change VER or IMAGE. Returns bash's exit status (1 for a refused value)."""
    import shlex, subprocess, tempfile
    plan_dir = plan_dir or os.path.join(os.path.dirname(os.path.abspath(plan)), "plan")
    st = read_state(state_path)
    files = [ln for ln in open(plan).read().split("\n") if ln.endswith("-%s.sh" % section)]
    script = "set -eo pipefail\n" + "".join("%s=%s\n" % (k, shlex.quote(v)) for k, v in st.items())
    for f in files:
        path = os.path.join(plan_dir, f)
        script += 'echo "::group::guide, as written: %s"\ncat %s\necho "::endgroup::"\nsource %s\n' % (f, shlex.quote(path), shlex.quote(path))
    fd, out = tempfile.mkstemp(prefix="guide-state-")
    os.close(fd)
    try:
        script += 'printf "%%s\\0%%s\\0%%s\\0" "${VER-}" "${IMAGE-}" "${DIGEST-}" > %s\n' % shlex.quote(out)
        rc = subprocess.run(["bash", "-c", script]).returncode
        if rc != 0:
            return rc
        ver, image, digest = open(out).read().split("\0")[:3]
    finally:
        os.unlink(out)
    new = {k: v for k, v in (("VER", ver), ("IMAGE", image), ("DIGEST", digest)) if v}
    for k in ("VER", "IMAGE"):
        if new.get(k) != st.get(k):
            print("::error::a guide block changed %s" % k, file=sys.stderr)
            return 1
    try:
        write_state(state_path, new)
    except ValueError as e:
        print("::error::%s" % e, file=sys.stderr)
        return 1
    return 0


def csaf_test_copy(V, vex, images, fixture_digest, cve, version):
    """The shipped CSAF (the real statements over the real images, so the production load finds its own products) with the fixture added as a product of its
    own, under its own id, and its one statement: the generator's CSAF for the fixture statement alone, narrowed to the fixture's branch."""
    tvex, timages = fixture_vex(vex, images, fixture_digest, cve)
    out = copy.deepcopy(V.csaf(vex, images, version))
    fx = V.csaf({"statements": tvex["statements"][-1:]}, timages, version)
    branches = [b for b in fx["product_tree"]["branches"] if fixture_digest in json.dumps(b)]
    if len(branches) != 1:
        raise ValueError("the fixture is not exactly one product of its CSAF")
    old_id = branches[0]["product"]["product_id"]
    new_id = old_id + "-fixture"
    if any(new_id == b["product"]["product_id"] for b in out["product_tree"]["branches"]):
        raise ValueError("the fixture's product id is already a product of the shipped tree")

    def rename(o):
        if isinstance(o, dict):
            return {k: rename(v) for k, v in o.items()}
        if isinstance(o, list):
            return [rename(v) for v in o]
        return new_id if o == old_id else o
    out["product_tree"]["branches"] += rename(branches)
    out["vulnerabilities"] += rename(fx["vulnerabilities"])
    return out


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
    """reports: {"grype": {cve: severity}, "inspector": set, "google": set}; never one of ours (exclude)."""
    common = set(reports["grype"]) - set(exclude)
    for k in ("inspector", "google"):
        common &= set(reports[k])
    insp = reports["inspector"]
    if isinstance(insp, dict):      # owner Oct 16: the run must show the same CVE in a second package staying visible, so the CVE is one Inspector reports in two package names
        common = {c for c in common if isinstance(insp[c], list) and len({x.get("name") for x in insp[c] if isinstance(x, dict)}) >= 2}
    if not common:
        raise ValueError("no CVE that every service reports for the fixture")
    return sorted(common, key=lambda c: (SEVERITY.get(reports["grype"][c], 9), c))[0]


def _ids(items, path):
    out = []
    for m in items:
        v = m
        for k in path:
            v = v.get(k) if isinstance(v, dict) else None
        if not isinstance(v, str) or not v:
            raise ValueError("a finding without an identifier")
        out.append(v)
    return out


def judge_grype(before, after, cve):
    """None when Grype matched the CVE before, lists exactly those matches as IGNORED after (our VEX applied: affirmative evidence), and keeps every other match
    with nothing new: findings are compared by complete identity (id + package name, version, type), so a finding lost on one package or a new one is caught
    (Codex #169 r1 SEC-169-05: an empty or broken report is never success; Codex #387 r2)."""
    def ident(m):
        a = m.get("artifact") if isinstance(m, dict) else None
        v = m.get("vulnerability") if isinstance(m, dict) else None
        if not isinstance(v, dict) or not isinstance(v.get("id"), str):
            raise ValueError("a Grype finding without an identifier")
        a = a if isinstance(a, dict) else {}
        return (v["id"], str(a.get("name", "")), str(a.get("version", "")), str(a.get("type", "")))
    try:
        for doc in (before, after):
            if not isinstance(doc, dict) or not isinstance(doc.get("matches"), list) \
                    or not isinstance(doc.get("ignoredMatches", []), list):
                return "not a Grype report"
        b, a = [ident(m) for m in before["matches"]], [ident(m) for m in after["matches"]]
        ign = [ident(m) for m in after.get("ignoredMatches", [])]
        bign = [ident(m) for m in before.get("ignoredMatches", [])]
    except ValueError as e:
        return str(e)
    target = sorted(x for x in b if x[0] == cve)
    if not target:
        return "Grype did not report %s before" % cve
    if any(x[0] == cve for x in a) or sorted(x for x in ign if x[0] == cve) != target:
        return "Grype did not ignore %s with our file (on every package it matched before)" % cve
    rest_b = sorted(x for x in b if x[0] != cve)
    if not rest_b:
        return "Grype dropped findings our file does not cover"
    if sorted(a) != rest_b:
        return "Grype's other findings changed (%d before, %d after)" % (len(rest_b), len(a))
    if sorted(x for x in ign if x[0] != cve) != sorted(bign):
        return "Grype ignored findings our file does not cover"
    return None


def judge_inspector(before, after, cve, package):
    """None when, before, the CVE has findings on the fixture in the named package, and after: every finding of before is still there (none new), every finding
    of the CVE in that package (name and version) is SUPPRESSED, and every other finding has the status it had — the same CVE in another package and the
    decoy's CVE included (our file suppressed exactly that CVE in that package: owner Oct 16, handoff 0482). Documents:
    {"findings": [{findingArn, vulnerabilityId, status, packageName, packageVersion}]}."""
    def fx(doc):
        fs = doc.get("findings") if isinstance(doc, dict) else None
        if not isinstance(fs, list) or not all(isinstance(f, dict) and all(isinstance(f.get(k), str) for k in
                ("findingArn", "vulnerabilityId", "status", "packageName", "packageVersion")) for f in fs):
            raise ValueError("not an Inspector finding list")
        out = {f["findingArn"]: f for f in fs}
        if len(out) != len(fs):
            raise ValueError("two findings carry the same ARN")
        return out
    try:
        b, a = fx(before), fx(after)
    except ValueError as e:
        return str(e)
    hit = lambda f: f["vulnerabilityId"] == cve and f["packageName"] == package["name"] and f["packageVersion"] == package["version"]
    if not any(hit(f) for f in b.values()):
        return "Inspector did not report %s in %s %s before" % (cve, package["name"], package["version"])
    if not any(f["vulnerabilityId"] == cve and f["packageName"] != package["name"] and f["status"] == "ACTIVE" for f in b.values()):
        return "Inspector did not report %s active in a second package before: the run could not show a rule for one package leaves the other visible" % cve
    if set(b) != set(a):
        return "the finding inventory changed: %d lost, %d new" % (len(set(b) - set(a)), len(set(a) - set(b)))
    for arn, f in a.items():
        if (f["vulnerabilityId"], f["packageName"], f["packageVersion"]) != (b[arn]["vulnerabilityId"], b[arn]["packageName"], b[arn]["packageVersion"]):
            return "a finding changed its CVE or package (%s %s -> %s %s): it is not the finding that was there" % (
                b[arn]["vulnerabilityId"], b[arn]["packageName"], f["vulnerabilityId"], f["packageName"])
        if hit(f):
            if f["status"] != "SUPPRESSED":
                return "%s is %s after our file, not SUPPRESSED" % (cve, f["status"])
        elif f["status"] != b[arn]["status"]:
            return "an unrelated finding changed (%s in %s: %s -> %s)" % (f["vulnerabilityId"], f["packageName"], b[arn]["status"], f["status"])
    return None


def judge_google(before, after, cve, run_notes):
    """None when, before, the CVE's occurrences on the fixture carry no NOT_AFFECTED assessment, and after: the inventory is COMPLETE and unchanged (every
    occurrence of before is there, none is new: an unrelated finding or one of two target occurrences lost proves nothing), every target occurrence carries
    NOT_AFFECTED from a note THIS run's load created (Codex #169 r1, SEC-169-06: a pre-existing or foreign assessment proves nothing), and no other
    occurrence is assessed by this run's notes (our file suppressed exactly the one CVE)."""
    def occs(doc):
        if not isinstance(doc, dict) or not isinstance(doc.get("occurrences", []), list):
            raise ValueError("not an occurrence list")
        return [o for o in doc.get("occurrences", []) if isinstance(o, dict)]

    def ident(o):   # the occurrence's resource name; one without a name is identified by its note and the rest of its content minus the assessment
        if o.get("name"):
            return str(o["name"])
        v = {k: x for k, x in (o.get("vulnerability") or {}).items() if k != "vexAssessment"}
        return json.dumps({"note": o.get("noteName"), "v": v}, sort_keys=True)

    def assessment(o):
        return ((o.get("vulnerability") or {}).get("vexAssessment")) or {}

    def target(o):
        return str(o.get("noteName", "")).rsplit("/", 1)[-1] == cve
    try:
        bo, ao = occs(before), occs(after)
    except ValueError as e:
        return str(e)
    if not run_notes:
        return "this run's load created no VEX note"
    b, a = [o for o in bo if target(o)], [o for o in ao if target(o)]
    if not b:
        return "Google did not report %s before" % cve
    if any(assessment(o).get("state") == "NOT_AFFECTED" for o in b):
        return "%s was already assessed not affected before our load" % cve
    if not a:
        return "Google no longer reports %s at all" % cve
    bi, ai = [ident(o) for o in bo], [ident(o) for o in ao]
    if len(set(bi)) != len(bi) or len(set(ai)) != len(ai):
        return "two occurrences carry the same identity"
    if set(bi) != set(ai):
        return "the occurrence inventory changed: %d lost, %d new" % (len(set(bi) - set(ai)), len(set(ai) - set(bi)))
    note_of = lambda docs: {ident(o): str(o.get("noteName", "")) for o in docs}
    if note_of(bo) != note_of(ao):
        return "an occurrence changed its note (its CVE): it is not the finding that was there"
    for o in a:
        va = assessment(o)
        if va.get("state") != "NOT_AFFECTED" or va.get("noteName") not in run_notes:
            return "%s is not assessed not affected by this run's note" % cve
    bmap = {ident(o): assessment(o) for o in bo}
    for o in ao:
        if not target(o) and assessment(o) != bmap[ident(o)]:
            return "an unrelated finding's assessment changed (whoever's note)"
    return None


def inventory(kind, doc, prefix=""):
    """Strictly read one listing the sweep acts on (Codex #169 r2, SEC-169-08): any shape this does not expect raises —
    a listing that cannot be read is never taken for an empty one.
    ecr -> [{"imageDigest"}…] chunks of 100; gar -> ["package@version"…]; filters -> [arn…] of names under prefix;
    notes -> {"names": [names of notes whose genericUri starts with prefix], "next": page token or ""};
    ecr-delete -> number of failures."""
    def need(cond, what):
        if not cond:
            raise ValueError("%s listing: %s" % (kind, what))
    s_ = lambda x: isinstance(x, str) and x != ""
    if kind == "ecr":
        need(isinstance(doc, dict) and isinstance(doc.get("imageIds"), list), "no imageIds list")
        ds = []
        for i in doc["imageIds"]:
            need(isinstance(i, dict) and s_(i.get("imageDigest")) and i["imageDigest"].startswith("sha256:"), "an image without its digest")
            ds.append(i["imageDigest"])
        ds = sorted(set(ds))
        return [[{"imageDigest": d} for d in ds[k:k + 100]] for k in range(0, len(ds), 100)]
    if kind == "ecr-indexes":   # describe-images: the digests of the manifest lists (ECR refuses to delete an image a manifest list still references, so these go first)
        need(isinstance(doc, dict) and isinstance(doc.get("imageDetails"), list), "no imageDetails list")
        ds = []
        for i in doc["imageDetails"]:
            need(isinstance(i, dict) and s_(i.get("imageDigest")) and i["imageDigest"].startswith("sha256:") and s_(i.get("imageManifestMediaType")),
                 "an image without its digest or media type")
            if "manifest.list" in i["imageManifestMediaType"] or "image.index" in i["imageManifestMediaType"]:
                ds.append(i["imageDigest"])
        ds = sorted(set(ds))
        return [[{"imageDigest": d} for d in ds[k:k + 100]] for k in range(0, len(ds), 100)]
    if kind == "gar":
        need(isinstance(doc, list), "not a list")
        for i in doc:
            need(isinstance(i, dict) and s_(i.get("package")) and s_(i.get("version")), "an image without package or version")
        return ["%s@%s" % (i["package"], i["version"]) for i in doc]
    if kind == "filters":
        need(isinstance(doc, dict) and isinstance(doc.get("filters"), list), "no filters list")
        for f in doc["filters"]:
            need(isinstance(f, dict) and s_(f.get("name")) and s_(f.get("arn")), "a filter without name or arn")
        return [f["arn"] for f in doc["filters"] if f["name"].startswith(prefix)]
    if kind == "notes":
        need(isinstance(doc, dict) and isinstance(doc.get("notes", []), list), "notes is not a list")
        need(doc.get("nextPageToken") is None or isinstance(doc["nextPageToken"], str), "a page token that is not a string")
        names = []
        for n in doc.get("notes", []):
            need(isinstance(n, dict) and s_(n.get("name")), "a note without its name")
            va = n.get("vulnerabilityAssessment")
            need(va is None or isinstance(va, dict), "an assessment that is not an object")
            prod = (va or {}).get("product")
            need(prod is None or isinstance(prod, dict), "a product that is not an object")
            uri = (prod or {}).get("genericUri")
            need(uri is None or isinstance(uri, str), "a genericUri that is not a string")
            if uri and uri.startswith(prefix):
                names.append(n["name"])
        return {"names": names, "next": doc.get("nextPageToken") or ""}
    if kind == "ecr-delete":
        need(isinstance(doc, dict) and isinstance(doc.get("failures", []), list), "no failures list")
        return len(doc.get("failures", []))
    raise ValueError("unknown inventory %s" % kind)


CA_HOST = "containeranalysis.googleapis.com"


def _opener():
    """urllib's default opener with redirects switched off: a 3xx is an HTTPError, so the bearer header never travels to a redirect target."""
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    return urllib.request.build_opener(NoRedirect)


def ca_request(url, method, token, opener=None):
    """One call to the Container Analysis API (an API call for data, not a software download): the fixed host over https, the bearer token, GET or DELETE
    only. An HTTP error is raised, never turned into an empty answer. Returns the body as text."""
    import urllib.parse, urllib.request
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or p.hostname != CA_HOST or p.username is not None or p.password is not None or p.port not in (None, 443):
        raise ValueError("not a Container Analysis URL: %r" % url[:80])
    if method not in ("GET", "DELETE"):
        raise ValueError("method %r is not GET or DELETE" % method)
    if not token:
        raise ValueError("no access token")
    req = urllib.request.Request(url, method=method, headers={"Authorization": "Bearer " + token})
    with (opener or _opener().open)(req, timeout=60) as r:
        return r.read().decode("utf-8")


def _semver(tag):
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?", tag)
    return None if not m else (int(m[1]), int(m[2]), int(m[3]), int(m[4]) if m[4] else 1 << 30)


def release_under_test(releases):
    ok = [r["tagName"] for r in releases if not r.get("isDraft") and _semver(r["tagName"]) and _semver(r["tagName"])[3] == 1 << 30
          and "fosterstack-cache-%s.csaf.json" % r["tagName"] in r.get("assets", [])]
    return max(ok, key=_semver) if ok else None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vex-live-test")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--guide", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--pins", required=True, help="docs/using-our-vex.live-blocks.json: the only blocks the plan may hold, in order")
    p.add_argument("--skip-cannot-run", help="a release candidate: leave out the blocks this list (docs/using-our-vex.cannot-run.json) names")
    t = sub.add_parser("test-files")
    t.add_argument("--openvex", required=True)
    t.add_argument("--images", required=True)
    t.add_argument("--version", required=True)
    t.add_argument("--fixture-digest", required=True)
    t.add_argument("--cve", required=True)
    t.add_argument("--scope", required=True, help="pick-scope's file: the package the fixture's Inspector rule names and the decoy")
    t.add_argument("--out-dir", required=True)
    t.add_argument("--grype-repository", help="the repository Grype scans the fixture in (the test registry's cache repository); the OpenVEX file names the fixture there")
    c = sub.add_parser("pick-cve")
    c.add_argument("--reports", required=True)
    c.add_argument("--openvex", required=True, help="our statements: their CVEs are never the fixture's")
    sc = sub.add_parser("pick-scope")
    sc.add_argument("--reports", required=True)
    sc.add_argument("--cve", required=True)
    sc.add_argument("--openvex", required=True)
    iv = sub.add_parser("inventory", help="read one listing from stdin, strictly")
    iv.add_argument("--kind", required=True, choices=("ecr", "ecr-indexes", "gar", "filters", "notes", "ecr-delete"))
    iv.add_argument("--prefix", default="")
    j = sub.add_parser("judge")
    j.add_argument("--kind", choices=("grype", "google", "inspector"), required=True)
    j.add_argument("--before", required=True)
    j.add_argument("--scope", help="inspector: pick-scope's file (the package under test)")
    j.add_argument("--after", required=True)
    j.add_argument("--cve", required=True)
    j.add_argument("--notes", help="google: a file with the names of the VEX notes this run created, one per line")
    st = sub.add_parser("settings", help="print the test's values as the guide's settings (VAR=value ...)")
    st.add_argument("--state", help="merge the values into this state file instead of printing them")
    st.add_argument("pairs", nargs="+")
    c2 = sub.add_parser("ca", help="one Container Analysis call as the live-test service account")
    c2.add_argument("method", choices=("GET", "DELETE"))
    c2.add_argument("url")
    g = sub.add_parser("guide", help="run the command blocks of one section of the page as written")
    g.add_argument("--plan", required=True)
    g.add_argument("--state", required=True)
    g.add_argument("section")
    sg = sub.add_parser("state", help="print one value of the state file")
    sg.add_argument("--state", required=True)
    sg.add_argument("name", choices=STATE_KEYS)
    fl = sub.add_parser("field", help="print one field of the JSON read from stdin (names: one per line; next: the next page token or empty)")
    fl.add_argument("key", choices=("names", "next"))
    r = sub.add_parser("release")
    r.add_argument("--releases", required=True, help="gh release list --json tagName,isDraft + assets names")
    a = ap.parse_args(argv)
    if a.cmd == "ca":
        import subprocess
        tok = subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True, check=True).stdout.strip()
        sys.stdout.write(ca_request(a.url, a.method, tok))
        return 0
    if a.cmd == "plan":
        skip = json.load(open(a.skip_cannot_run))["blocks"] if a.skip_cannot_run else ()
        pins = json.load(open(a.pins))["blocks"]
        for i, b in enumerate(guide_blocks(open(a.guide).read(), skip, pins)):
            with open(os.path.join(a.out_dir, "%02d-%s.sh" % (i, b["section"])), "w") as fh:
                fh.write(b["text"])
            print("%02d-%s.sh" % (i, b["section"]))
        return 0
    if a.cmd == "test-files":
        V = _forms()
        vex, images = json.load(open(a.openvex)), json.load(open(a.images))
        tvex, timages = fixture_vex(vex, images, a.fixture_digest, a.cve)
        gvex, _ = fixture_vex(vex, images, a.fixture_digest, a.cve, a.grype_repository) if a.grype_repository else (tvex, None)
        shipped, generated = inspector_files(V, vex, images, a.fixture_digest, a.cve, a.version, json.load(open(a.scope)))
        tc = test_copy(generated)
        bad = check_copy(shipped, generated, tc, a.fixture_digest)
        if bad:
            print("\n".join(bad), file=sys.stderr)
            return 1
        base = os.path.join(a.out_dir, "fosterstack-cache-%s" % a.version)
        json.dump(gvex, open(os.path.join(a.out_dir, "fosterstack-cache.openvex.json"), "w"), indent=1)   # the file Grype reads: the fixture's product in the test registry
        json.dump(tc, open(base + ".inspector-filters.json", "w"), indent=1)
        json.dump(csaf_test_copy(V, vex, images, a.fixture_digest, a.cve, a.version), open(base + ".csaf.json", "w"), indent=1)
        return 0
    if a.cmd == "pick-cve":
        rep = json.load(open(a.reports))
        ours = {s["vulnerability"]["name"] for s in json.load(open(a.openvex))["statements"]}
        print(pick_cve({k: (v if k == "grype" else set(v)) for k, v in rep.items()}, ours))
        return 0
    if a.cmd == "pick-scope":
        ours = {s["vulnerability"]["name"] for s in json.load(open(a.openvex))["statements"]}
        try:
            print(json.dumps(pick_scope(json.load(open(a.reports)), a.cve, ours)))
        except ValueError as e:
            print("::error::%s" % e, file=sys.stderr)
            return 1
        return 0
    if a.cmd == "inventory":
        try:
            out = inventory(a.kind, json.loads(sys.stdin.read()), a.prefix)
        except ValueError as e:      # json.JSONDecodeError is a ValueError
            print("::error::%s" % e, file=sys.stderr)
            return 1
        if isinstance(out, list):
            for x in out:
                print(json.dumps(x) if not isinstance(x, str) else x)
        else:
            print(json.dumps(out) if isinstance(out, dict) else out)
        return 0
    if a.cmd == "judge":
        def load(p):
            try:
                return json.load(open(p))
            except (OSError, ValueError):
                return None
        b, af = load(a.before), load(a.after)
        if a.kind == "inspector":
            if not a.scope:
                print("::error::inspector: the judge needs --scope (the package under test)", file=sys.stderr)
                return 1
            why = judge_inspector(b, af, a.cve, json.load(open(a.scope))["package"])
        elif a.kind == "google":
            notes = {ln.strip() for ln in open(a.notes)} - {""} if a.notes else set()
            why = judge_google(b, af, a.cve, notes)
        else:
            why = judge_grype(b, af, a.cve)
        if why:
            print("::error::%s: %s" % (a.kind, why), file=sys.stderr)
            return 1
        print("%s: %s shown before and suppressed by our file after; every other finding kept" % (a.kind, a.cve))
        return 0
    if a.cmd == "settings":
        pairs = dict(p.split("=", 1) for p in a.pairs)
        if a.state:
            st = read_state(a.state)
            render_settings(pairs)      # refuses a value that is not plain
            st.update(pairs)
            write_state(a.state, st)
            return 0
        sys.stdout.write(render_settings(pairs))
        return 0
    if a.cmd == "guide":
        return run_guide(a.plan, a.state, a.section)
    if a.cmd == "state":
        print(read_state(a.state).get(a.name, ""))
        return 0
    if a.cmd == "field":
        doc = json.loads(sys.stdin.read())
        if a.key == "names":
            print("\n".join(doc["names"]))
        else:
            print(doc["next"])
        return 0
    found = release_under_test(json.load(open(a.releases)))
    print(found or "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
