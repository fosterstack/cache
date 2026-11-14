#!/usr/bin/env bash
# proves: REQ-SCAN-011-AC3, REQ-SCAN-012-AC1, REQ-SCAN-012-AC2, REQ-SCAN-012-AC3, REQ-SCAN-012-AC4, REQ-SCAN-012-AC5, REQ-SCAN-012-AC6
# Scanner-panel rule 12 (owner RATIFIED Oct 2; read-back approved, advisor 0098), offline: the live test's plan runs the
# guide's command blocks byte for byte (only its settings blocks take test values); the test copy of the Inspector file
# differs from the generator's output only in the live-test tag and the test name prefix (plus exactly the fixture's
# own filters); the fixture CVE is one every service reports; at most 50 pushes; the release under test; the wiring
# (rc tags after promotion and main pushes that change the guide or the VEX files — never a schedule, never a PR — in
# the live-test environment, federated, literal regions, pinned actions, cleanup always).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 - "$root" <<'PY'
import copy, importlib.util, json, os, re, shutil, subprocess, sys, tempfile, yaml
root = sys.argv[1]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(root, path))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
L = load("lt", "bin/vex-live-test.py")
V = load("vf", "bin/vex-forms.py")
guide = open(os.path.join(root, "docs/using-our-vex.md")).read()

# --- AC5: the guide's blocks, run byte for byte; only settings blocks take test values
blocks = L.guide_blocks(guide)
raw = re.findall(r"```sh\n(.*?)```", guide, re.S)
check("every sh block of the guide is in the plan, in order, byte for byte (the indent of a closing fence is not part of the block)", [b["text"] for b in blocks] == [r.rstrip(" ") for r in raw],
      len(blocks))
settings = [b for b in blocks if b["kind"] == "settings"]
check("a settings block holds only VAR=value lines",
      all(re.fullmatch(r"(?:[A-Z_]+=\S.*\n)+", b["text"]) for b in settings), [b["text"] for b in settings])
check("the guide's settings are VER and IMAGE, and nothing else is a setting",
      sorted(v for b in settings for v in re.findall(r"(?m)^([A-Z_]+)=", b["text"])) == ["IMAGE", "VER"])
check("no command block assigns VER or IMAGE (a setting cannot hide in a command)",
      not any(re.search(r"(?m)^\s*(VER|IMAGE)=", b["text"]) for b in blocks if b["kind"] == "command"))
check("DIGEST is computed by a command block the test runs as written",
      [b["section"] for b in blocks if b["kind"] == "command" and re.search(r"(?m)^DIGEST=", b["text"])] == ["digest"])
plan = L.render_settings({"VER": "0.3.0-rc1", "DIGEST": "sha256:" + "a" * 64, "IMAGE": "x/y/cache"})
check("test settings are rendered as plain assignments, shell-quoted", plan == "VER='0.3.0-rc1'\nDIGEST='sha256:%s'\nIMAGE='x/y/cache'\n" % ("a" * 64), plan)
for bad in ({"VER": "1; rm -rf /"}, {"VER": "1", "EVIL": "x"}):
    try:
        L.render_settings(bad); got = "accepted"
    except ValueError:
        got = "refused"
    check("render_settings refuses %r" % bad, got == "refused", got)
check("the plan names each command block by the scanner it serves",
      {b["section"] for b in blocks if b["kind"] == "command"} >= {"digest", "download", "verify", "grype", "inspector",
                                                                   "google", "inspector-remove"},
      sorted({b["section"] for b in blocks}))

# --- Codex #387 r4: the plan is pinned. Whatever a Markdown reader and this parser disagree about, the live test runs ONLY the blocks listed (in order, by section and sha256) in
#     docs/using-our-vex.live-blocks.json: an extra, changed, reordered or missing block is refused
import hashlib
pins = json.load(open(os.path.join(root, "docs/using-our-vex.live-blocks.json")))["blocks"]
check("the pin list is exactly the page's blocks (sections and sha256 of their text)", [(b["section"], hashlib.sha256(b["text"].encode()).hexdigest()) for b in blocks] == [(x["section"], x["sha256"]) for x in pins])
check("the pinned plan of the real page is accepted", [b["text"] for b in L.guide_blocks(guide, pins=pins)] == [b["text"] for b in blocks])
for why, g in [("an extra block", guide + "\n```sh\ngrype example.invalid/draft:latest\n```\n"), ("a changed block", guide.replace("grype ", "grype --verbose ", 1)),
               ("a removed block", guide.replace("```sh\nVER=X.Y.Z\n```", "", 1))]:
    try:
        L.guide_blocks(g, pins=pins); got = "accepted"
    except ValueError:
        got = "refused"
    check("SEC-387 a page with %s is refused by the pin list" % why, got == "refused", got)
try:
    L.guide_blocks(guide, pins=list(reversed(pins))); got = "accepted"
except ValueError:
    got = "refused"
check("SEC-387 blocks in another order than the pin list are refused", got == "refused", got)

# --- Markdown structure (Codex #387 r1): only a real top-level ```sh block is a command; an example inside a longer fence, a tilde fence or an indented fence is text
ex = guide + "\n````text\nan example of the syntax:\n```sh\ntouch TEXT_EXAMPLE_EXECUTED\n```\n````\n"
check("a three-backtick sh block inside a four-backtick text example is not a command", [b["text"] for b in L.guide_blocks(ex)] == [b["text"] for b in blocks])
ex = guide + "\n~~~sh\ntouch TILDE_EXECUTED\n~~~\n"
check("a tilde-fenced sh block is not a command", [b["text"] for b in L.guide_blocks(ex)] == [b["text"] for b in blocks])
ex = guide + "\n- a list item:\n\n    ```sh\n    touch INDENTED_EXECUTED\n    ```\n"
check("an indented fenced block is not a command", [b["text"] for b in L.guide_blocks(ex)] == [b["text"] for b in blocks])
ex = guide + "\n```sh\nunclosed block runs to the end of the file\n"
try:
    L.guide_blocks(ex); got = "accepted"
except ValueError:
    got = "refused"
check("a block that is never closed is refused, not run", got == "refused", got)
ex = guide + "\n``` sh\ntouch SPACED_EXECUTED\n```\n"
check("an opening fence whose info string is not exactly sh is not a command", [b["text"] for b in L.guide_blocks(ex)] == [b["text"] for b in blocks])

# --- Codex #387 r2: HTML comments and raw HTML hide Markdown fences from a reader, so a page that holds a multi-line comment or a raw HTML block is refused, not parsed
for why, extra in [("a fence inside a multi-line HTML comment", "\n<!--\n```sh\ngrype example.invalid/draft:latest\n```\n-->\n"),
                   ("a fence inside a single-line-opened comment", "\n<!-- draft\n```sh\ngrype example.invalid/draft:latest\n```\n-->\n"),
                   ("a raw HTML block", "\n<div>\n```sh\ngrype example.invalid/draft:latest\n```\n</div>\n"),
                   ("a raw pre block", "\n<pre>\n```sh\nid\n```\n</pre>\n")]:
    try:
        L.guide_blocks(guide + extra); got = "accepted"
    except ValueError:
        got = "refused"
    check("SEC-387 a page with %s is refused" % why, got == "refused", got)
for why, extra in [("a fence opened after a list marker", "\n- ```text\n```sh\ngrype example.invalid/draft:latest\n```\n"),
                   ("a fence opened after a numbered list marker", "\n1. ```text\n```sh\ngrype example.invalid/draft:latest\n```\n"),
                   ("a fence opened inside a block quote", "\n> ```text\n```sh\ngrype example.invalid/draft:latest\n```\n"),
                   ("a fence opened inside a nested list item", "\n  - ```text\n```sh\ngrype example.invalid/draft:latest\n```\n")]:
    try:
        L.guide_blocks(guide + extra); got = "accepted"
    except ValueError:
        got = "refused"
    check("SEC-387 a page with %s is refused (a container the parser does not model)" % why, got == "refused", got)
check("SEC-387 an HTML comment that opens and closes on one line (the pinned markers) is fine", "<!-- pinned:" in guide and len(L.guide_blocks(guide)) == len(blocks))

# --- release candidates (v0.3: nothing is published): the blocks the page's cannot-run list names are left out of the plan, every other block stays, in order
cr = json.load(open(os.path.join(root, "docs/using-our-vex.cannot-run.json")))
rc_blocks = L.guide_blocks(guide, skip=cr["blocks"])
check("the rc plan is the page's plan minus exactly the listed blocks, in order", [b["text"] for b in rc_blocks] == [b["text"] for b in blocks if b["text"] not in cr["blocks"]])
check("the rc plan has no digest, download, verify or published-image Grype or Scout block", not {"digest", "download", "verify", "grype", "scout"} & {b["section"] for b in rc_blocks})
check("the full plan has the Scout block, after the Google blocks' section order of the page", "scout" in {b["section"] for b in blocks})
check("the rc plan keeps the Inspector and Google blocks and the removal", {"inspector", "google", "inspector-remove"} <= {b["section"] for b in rc_blocks})
try:
    L.guide_blocks(guide, skip=cr["blocks"] + ["not a block of the page\n"]); got = "accepted"
except ValueError:
    got = "refused"
check("a cannot-run entry that is not a block of the page is refused", got == "refused", got)
try:
    L.guide_blocks(guide, skip=[b["text"] for b in blocks if b["section"] == "inspector"]); got = "accepted"
except ValueError:
    got = "refused"
check("a cannot-run list that skips an Inspector or Google block is refused (only digest, download, verify and the published-image Grype and Scout scans may be skipped)", got == "refused", got)

# --- the test copy of the Inspector file (advisor 0098): tag + prefix, and exactly the fixture's own filters
images = {v: {"index": "sha256:" + c * 64, "children": {"linux/amd64": "sha256:" + d * 64, "linux/arm64": "sha256:" + e * 64}}
          for v, c, d, e in (("production", "1", "2", "3"), ("fips", "7", "8", "9"))}
vex = {"@id": "x", "version": 1, "statements": [
    {"vulnerability": {"name": "CVE-2024-0001"}, "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
     "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]}]}
FIX = "sha256:" + "f" * 64
tvex, timages = L.fixture_vex(vex, images, FIX, "CVE-2023-9999")
added = [s for s in tvex["statements"] if s not in vex["statements"]]
check("the fixture adds exactly one not_affected statement for the chosen CVE on the fixture digest",
      len(added) == 1 and added[0]["status"] == "not_affected" and added[0]["vulnerability"]["name"] == "CVE-2023-9999"
      and added[0]["products"] == [{"@id": "pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache" % FIX}], added)
check("the shipped statements are untouched", tvex["statements"][:len(vex["statements"])] == vex["statements"] and vex["statements"] == json.loads(json.dumps(vex["statements"])))
check("the test images map is a valid two-variant digest file for the generator (production's index is the fixture, its children and fips unchanged)",
      timages["production"] == {"index": FIX, "children": images["production"]["children"]} and timages["fips"] == images["fips"]
      and sorted(timages) == ["fips", "production"])
SCOPE = {"package": {"name": "libfoo", "version": "1.2"}, "decoy": {"cve": "CVE-2023-8888", "name": "libbar"}}
try:
    L.inspector_files(V, vex, images, FIX, "CVE-2023-9999", "v0.3.0-rc.1", None); got = "accepted"
except ValueError:
    got = "refused"
check("OWNER-3 the Inspector file for the fixture needs the fixture's package: none is refused, never a rule without one", got == "refused", got)
shipped, test_gen = L.inspector_files(V, vex, images, FIX, "CVE-2023-9999", "v0.3.0-rc.1", SCOPE)
fx_rules = test_gen["filters"][len(shipped["filters"]):]
byc = {f["filterCriteria"]["vulnerabilityId"][0]["value"]: f["filterCriteria"] for f in fx_rules}
check("OWNER-3 the fixture's rule names the package and version found on the fixture, on the fixture digest only",
      byc.get("CVE-2023-9999", {}).get("vulnerablePackages") == [{"name": {"comparison": "EQUALS", "value": "libfoo"}, "version": {"comparison": "EQUALS", "value": "1.2"}}]
      and [x["value"] for x in byc["CVE-2023-9999"]["ecrImageHash"]] == [FIX], byc)
check("OWNER-3 the decoy's rule names that CVE's package with a version that is not there, on the fixture digest only",
      byc.get("CVE-2023-8888", {}).get("vulnerablePackages", [{}])[0].get("name") == {"comparison": "EQUALS", "value": "libbar"}
      and byc["CVE-2023-8888"]["vulnerablePackages"][0]["version"]["value"] not in ("", "1.2")
      and [x["value"] for x in byc["CVE-2023-8888"]["ecrImageHash"]] == [FIX], byc)
check("OWNER-3 the fixture adds exactly those two rules", sorted(byc) == ["CVE-2023-8888", "CVE-2023-9999"] and len(fx_rules) == 2, sorted(byc))
check("the generator's own file for the real statements is the shipped part", shipped == V.inspector(vex, images, "v0.3.0-rc.1"))
check("no real statement widens to the fixture's digest", all(FIX not in json.dumps(f) for f in test_gen["filters"][:len(shipped["filters"])]))
try:
    L.inspector_files(V, vex, images, FIX, "CVE-2024-0001", "v0.3.0-rc.1", SCOPE); got = "accepted"
except ValueError:
    got = "refused"
check("the fixture's CVE is never one of our statements", got == "refused", got)
tcopy = L.test_copy(test_gen)
check("every test filter carries the live-test tag and the test prefix",
      all(f["tags"] == {"fosterstack-purpose": "live-test"} and f["name"].startswith("fosterstack-cache-livetest-")
          and len(f["name"]) <= 128 for f in tcopy["filters"]), [f["name"] for f in tcopy["filters"]])
check("the copy differs from the shipped file only in tag + prefix, plus the fixture's filters",
      L.check_copy(shipped, test_gen, tcopy, FIX) == [], L.check_copy(shipped, test_gen, tcopy, FIX))
def mut(fn):
    c = copy.deepcopy(tcopy); fn(c); return L.check_copy(shipped, test_gen, c, FIX)
for why, fn in [("a widened criterion", lambda c: c["filters"][0]["filterCriteria"]["ecrImageHash"].pop()),
                ("an extra field", lambda c: c["filters"][0].__setitem__("reason", "x")),
                ("another tag", lambda c: c["filters"][0]["tags"].__setitem__("k", "v")),
                ("a name without the test prefix", lambda c: c["filters"][0].__setitem__("name", "fosterstack-cache-x")),
                ("a dropped shipped filter", lambda c: c["filters"].pop(0)),
                ("an extra filter that is not the fixture's", lambda c: c["filters"].append(copy.deepcopy(c["filters"][0]))),
                ("a changed action", lambda c: c["filters"][0].__setitem__("action", "NONE"))]:
    check("check_copy refuses %s" % why, mut(fn) != [], "accepted")
check("the shipped file never carries the tag", all("tags" not in f for f in shipped["filters"]))

# --- Codex #387 r1 (P1): the test CSAF keeps the SHIPPED product tree and adds a separately identified fixture product and statement (the production loading must still find
#     its own products)
vexc = copy.deepcopy(vex)
csaf = L.csaf_test_copy(V, vexc, images, FIX, "CVE-2023-9999", "v0.3.0-rc1")
ship = V.csaf(vexc, images, "v0.3.0-rc1")
prods = [b["product"]["product_id"] for b in csaf["product_tree"]["branches"]]
purls = json.dumps(csaf["product_tree"])
check("test CSAF: the shipped branches come first and unchanged", csaf["product_tree"]["branches"][:len(ship["product_tree"]["branches"])] == ship["product_tree"]["branches"])
check("test CSAF: the real production index is still in the tree", images["production"]["index"] in purls and images["fips"]["index"] in purls)
check("test CSAF: the fixture digest is a product of its own, with its own id", FIX in purls and len(prods) == len(set(prods)) and len(prods) == len(ship["product_tree"]["branches"]) + 1, prods)
check("test CSAF: the shipped vulnerabilities come first and unchanged, the fixture's statement is added",
      csaf["vulnerabilities"][:len(ship["vulnerabilities"])] == ship["vulnerabilities"] and len(csaf["vulnerabilities"]) == len(ship["vulnerabilities"]) + 1
      and csaf["vulnerabilities"][-1]["cve"] == "CVE-2023-9999")
def pids(o):
    if isinstance(o, dict): return [x for v in o.values() for x in pids(v)]
    if isinstance(o, list): return [x for v in o for x in pids(v)]
    return [o] if isinstance(o, str) and o.startswith("fosterstack-cache-v0.3.0-rc1-") else []
check("test CSAF: every product id a statement names is a product of the tree", set(pids(csaf["vulnerabilities"])) <= set(prods), (set(pids(csaf["vulnerabilities"])) - set(prods)))

# --- Codex #387 r3 (P1): Grype scans the test registry's copy of the fixture, and OpenVEX matches the product's repository too: the OpenVEX file Grype reads names the test repository
GREPO = "us-east1-docker.pkg.dev/fosterstack-cache/cache-live-test/cache"
gvex, _t = L.fixture_vex(vex, images, FIX, "CVE-2023-9999", GREPO)
gadded = [s for s in gvex["statements"] if s not in vex["statements"]]
check("grype: the fixture statement's product carries the test repository", len(gadded) == 1 and gadded[0]["products"] == [{"@id": "pkg:oci/cache@%s?repository_url=%s" % (FIX, GREPO)}], gadded)
gdef, _t = L.fixture_vex(vex, images, FIX, "CVE-2023-9999")
check("grype: without a repository the product stays the shipped repository (the generators' form)", gdef["statements"][-1]["products"] == [{"@id": "pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache" % FIX}])

# --- the fixture CVE: one every service reports for the fixture, deterministic
pick = L.pick_cve({"grype": {"CVE-1": "High", "CVE-2": "Critical", "CVE-3": "Low"}, "inspector": {"CVE-1", "CVE-2", "CVE-3"},
                   "google": {"CVE-2", "CVE-3", "CVE-1"}})
check("picks a CVE all three report, highest severity first", pick == "CVE-2", pick)
check("never one of our own CVEs", L.pick_cve({"grype": {"CVE-1": "High", "CVE-2": "Critical"}, "inspector": {"CVE-1", "CVE-2"},
                                                 "google": {"CVE-1", "CVE-2"}}, {"CVE-2"}) == "CVE-1")
try:
    L.pick_cve({"grype": {"CVE-1": "High"}, "inspector": {"CVE-2"}, "google": {"CVE-1"}}); got = "picked"
except ValueError:
    got = "refused"
check("no common CVE is a failure, never a guess", got == "refused", got)
# owner Oct 16: the package under test is one Inspector reports for the chosen CVE; the decoy is another CVE Inspector reports, never ours
RP = {"CVE-T": [{"name": "zlib", "version": "1.3"}, {"name": "abc", "version": "2.0"}], "CVE-U": [{"name": "curl", "version": "8"}], "CVE-V": [{"name": "bash", "version": "5"}]}
sc = L.pick_scope({"inspector": RP}, "CVE-T", {"CVE-U"})
# pick_cve (Inspector as a CVE -> packages map) takes only a CVE Inspector reports in two package names; none is a failure
two = L.pick_cve({"grype": {"CVE-1": "Critical", "CVE-2": "Low"}, "inspector": {"CVE-1": [{"name": "a", "version": "1"}], "CVE-2": [{"name": "a", "version": "1"}, {"name": "b", "version": "1"}]},
                  "google": {"CVE-1", "CVE-2"}})
check("OWNER-3 pick_cve with Inspector's packages prefers a CVE in two package names over a more severe one in one", two == "CVE-2", two)
for why, insp in [("every CVE in one package", {"CVE-1": [{"name": "a", "version": "1"}]}), ("one name at two versions", {"CVE-1": [{"name": "a", "version": "1"}, {"name": "a", "version": "2"}]})]:
    try:
        L.pick_cve({"grype": {"CVE-1": "High"}, "inspector": insp, "google": {"CVE-1"}}); got = "picked"
    except ValueError:
        got = "refused"
    check("OWNER-3 pick_cve refuses %s" % why, got == "refused", got)
# Codex #387 r9 (both seats): the same choice through the CLI the runner calls (pick-cve), not only the helper: the CLI must hand Inspector's package map on
import subprocess as _sp, tempfile as _tf
with _tf.TemporaryDirectory() as _t:
    json.dump({"grype": {"CVE-1": "Critical", "CVE-2": "Low"}, "inspector": {"CVE-1": [{"name": "a", "version": "1"}],
               "CVE-2": [{"name": "a", "version": "1"}, {"name": "b", "version": "1"}]}, "google": ["CVE-1", "CVE-2"]}, open(_t + "/r.json", "w"))
    json.dump({"statements": []}, open(_t + "/v.json", "w"))
    _r = _sp.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "pick-cve", "--reports", _t + "/r.json", "--openvex", _t + "/v.json"], capture_output=True, text=True)
    check("OWNER-3 the pick-cve command takes the CVE in two package names over a more severe one in one (the runner's real path)", _r.stdout.strip() == "CVE-2" and _r.returncode == 0, (_r.returncode, _r.stdout, _r.stderr[-200:]))
check("OWNER-3 pick_scope: the first package of the CVE (by name) and the first other CVE Inspector reports that is not ours, with its package",
      sc == {"package": {"name": "abc", "version": "2.0"}, "decoy": {"cve": "CVE-V", "name": "bash"}}, sc)
for why, rep_, c, ex in [("a CVE in one package name only", {"inspector": {"CVE-T": [{"name": "zlib", "version": "1.3"}], "CVE-U": RP["CVE-U"]}}, "CVE-T", ()),
                         ("a CVE Inspector reports no package for", {"inspector": {"CVE-T": []}}, "CVE-T", ()),
                         ("no other CVE for the decoy", {"inspector": {"CVE-T": RP["CVE-T"]}}, "CVE-T", ()),
                         ("only our own CVEs for the decoy", {"inspector": RP}, "CVE-T", {"CVE-U", "CVE-V"}),
                         ("a package name the forms cannot carry", {"inspector": {"CVE-T": [{"name": "a/b", "version": "1"}], "CVE-U": RP["CVE-U"]}}, "CVE-T", ()),
                         ("a package without a version", {"inspector": {"CVE-T": [{"name": "a", "version": ""}], "CVE-U": RP["CVE-U"]}}, "CVE-T", ())]:
    try:
        L.pick_scope(rep_, c, ex); got = "picked"
    except ValueError:
        got = "refused"
    check("OWNER-3 pick_scope refuses %s" % why, got == "refused", got)

# --- the release under test on main: the newest published release that carries the rule-10 files
def _assets(t): return ["fosterstack-cache.openvex.json", "fosterstack-cache-%s.inspector-filters.json" % t, "fosterstack-cache-%s.csaf.json" % t]
rels = [{"tagName": "v0.3.0", "isDraft": False, "assets": _assets("v0.3.0")},
        {"tagName": "v0.3.1-rc1", "isDraft": False, "assets": _assets("v0.3.1-rc1")},
        {"tagName": "v0.2.1", "isDraft": False, "assets": []}, {"tagName": "v0.10.0", "isDraft": False, "assets": []}]
check("a release candidate tag is never the release under test; the newest published release with the rule-10 files is", L.release_under_test(rels) == "v0.3.0", L.release_under_test(rels))
check("none yet: empty", L.release_under_test(rels[2:]) is None)
# Codex terra on #646: a release is the release under test only when it carries ALL THREE files the guide downloads (a CSAF alone is not enough)
for why, keep in (("only the CSAF file", [2]), ("no CSAF file", [0, 1]), ("no Inspector filters", [0, 2]), ("no OpenVEX file", [1, 2])):
    part = [{"tagName": "v0.3.2", "isDraft": False, "assets": [_assets("v0.3.2")[i] for i in keep]}] + rels
    check("a newer release with %s is not the release under test" % why, L.release_under_test(part) == "v0.3.0", L.release_under_test(part))
check("a release with all three files is", L.release_under_test([{"tagName": "v0.3.2", "isDraft": False, "assets": _assets("v0.3.2")}] + rels) == "v0.3.2")
check("a draft release with all three files is not", L.release_under_test([{"tagName": "v0.3.2", "isDraft": True, "assets": _assets("v0.3.2")}] + rels) == "v0.3.0")
# the main-mode selection reads EVERY page of releases, not the first 50 (Codex terra on #646): paginated, then slurped into one list
_run = open(os.path.join(root, "bin", "vex-live-run.sh")).read()
check("main mode pages through every release before selecting", "gh api --paginate" in _run and "| jq -s ." in _run and "per_page=50" not in _run and "?per_page=50" not in _run)

# --- AC4: at most 50 pushes per run (the counter in the orchestration script)
out = subprocess.run(["bash", "-c", 'source "$0"; crane() { :; }; for i in $(seq 1 50); do push_copy a b || exit 9; done; push_copy a b && exit 7; exit 0',
                      os.path.join(root, "bin/vex-live-run.sh")], capture_output=True, text=True, env=dict(os.environ, VEX_LIVE_TEST_LIB="1"))
check("the 51st push fails the run", out.returncode == 0, (out.returncode, out.stderr[-300:]))

# --- the release candidate under test (v0.3: an rc ends before publishing, so its images exist only as Build's OCI layouts and digests.json): each layout is pushed to
#     the test repository and must come out at exactly the digest Build attested
# (the behavioral cases below drive bin/vex-live-run.sh with stubs; "copy_candidate" is the one place that reads a candidate)

# --- AC1/AC3/AC4: the wiring
wf = lambda n: yaml.load(open(os.path.join(root, ".github/workflows", n)), Loader=yaml.BaseLoader)
rel, ci = wf("release.yml"), wf("ci.yml")
for name, d, job in (("release.yml rc job", rel, rel["jobs"].get("live-test") or {}), ("release.yml post-publish job", rel, rel["jobs"].get("live-test-release") or {}),
                     ("ci.yml", ci, ci["jobs"].get("live-test") or {})):
    steps = job.get("steps") or []
    text = json.dumps(steps)
    check("%s: a live-test job in the live-test environment" % name, job.get("environment") == "live-test", job.get("environment"))
    check("%s: federated (id-token write), contents read, nothing else" % name,
          job.get("permissions") == {"contents": "read", "id-token": "write"}, job.get("permissions"))
    check("%s: AWS through the live-test role, us-east-1 written literally" % name,
          "${{ vars.LIVE_TEST_AWS_ROLE_ARN }}" in text and '"aws-region": "us-east-1"' in text)
    check("%s: GCP through the live-test provider and service account" % name,
          "${{ vars.LIVE_TEST_GCP_PROVIDER }}" in text and "${{ vars.LIVE_TEST_GCP_SERVICE_ACCOUNT }}" in text)
    check("%s: the test repositories by their variables" % name,
          "vars.LIVE_TEST_ECR_REPOSITORY" in text and "vars.LIVE_TEST_GAR_REPOSITORY" in text)
    check("%s: no key or secret material" % name, not re.search(r"secrets\.(AWS|GCP|GOOGLE)|credentials_json|aws-secret-access-key", text))
    uses = [s["uses"] for s in steps if "uses" in s]
    check("%s: every action pinned by commit digest" % name, uses and all(re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses)
    clean = [s for s in steps if "cleanup" in (s.get("name") or "")]
    gc = [s for s in steps if "setup-gcloud" in (s.get("uses") or "")]
    check("%s: gcloud is installed at an explicit version (the pin-age inventory refuses the action's default)" % name,
          len(gc) == 1 and re.fullmatch(r"\d+\.\d+\.\d+", (gc[0].get("with") or {}).get("version", "")) is not None, gc)
    check("%s: cleanup runs always" % name, len(clean) == 1 and clean[0].get("if") == "always()", [s.get("name") for s in steps])
    check("%s: runs the committed orchestration" % name, "bin/vex-live-run.sh" in text)
RJ, PJ = rel["jobs"]["live-test"], rel["jobs"]["live-test-release"]
check("release.yml: the rc job runs after Check, on release-candidate tags (vX.Y.Z-rcN) only, never in the dry run",
      RJ.get("needs") in ("check", ["check"]) and RJ.get("if") == "${{ startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') && !inputs.dry-run }}",
      (RJ.get("needs"), RJ.get("if")))
rtext = json.dumps(RJ.get("steps"))
check("release.yml: the rc job downloads the candidate's digests, items and images from Build's artifacts and runs in rc mode",
      all(('"name": "%s"' % n) in rtext for n in ("digests", "items", "images")) and "download-artifact" in rtext and '"MODE": "rc"' in rtext and "CANDIDATE_DIR" in rtext)
check("release.yml: the post-publish job runs after Release, on final tags only, in release mode, never in the dry run",
      PJ.get("needs") in ("release", ["release"]) and PJ.get("if") == "${{ startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-rc') && !inputs.dry-run }}"
      and '"MODE": "release"' in json.dumps(PJ.get("steps")), (PJ.get("needs"), PJ.get("if")))
cj = ci["jobs"]["live-test"]
check("ci.yml: on push to main only, after the change gate", cj.get("if") == "github.event_name == 'push' && needs.live-test-gate.outputs.changed == 'true'"
      and cj.get("needs") == "live-test-gate", (cj.get("if"), cj.get("needs")))
gate = "\n".join(st.get("run", "") for st in (ci["jobs"].get("live-test-gate") or {}).get("steps", []))
pat = re.search(r"grep -qE '([^']+)'", gate)
def gated(path):
    return bool(pat) and subprocess.run(["grep", "-qE", pat.group(1)], input=path + "\n", text=True).returncode == 0
check("ci.yml: the gate watches the guide, the VEX file and the live test's own code",
      all(gated(x) for x in ("docs/using-our-vex.md", "docs/using-our-vex.live-blocks.json", "docs/using-our-vex.cannot-run.json", ".vex/fosterstack-cache.openvex.json", "bin/vex-forms.py",
                             "bin/vex-live-run.sh", "bin/vex-live-test.py")), pat and pat.group(1))
check("ci.yml: the gate ignores unrelated changes",
      not any(gated(x) for x in ("README.md", "docs/verify-images.md", "bin/panel.py", "docs/using-our-vex.md.bak/x")))
check("ci.yml: no usable base runs the test rather than missing a change", 'echo "changed=true"' in gate.split("exit 0")[0])
check("ci.yml: never on a schedule", "schedule" not in ci["on"], ci["on"])
# release.yml has a daily schedule for its decide job (REQ-REL-009); the live-test jobs must still never run on it: both need a v tag ref, which a scheduled run never has
check("release.yml: the live-test jobs never run on the schedule (both require a v tag ref)", all("startsWith(github.ref, 'refs/tags/v')" in j.get("if", "") for j in (RJ, PJ)))
# --- Codex #169 r1
# SEC-169-04: a settings line is a plain value; anything else is a command the plan must run (or refuse)
for bad_line in ("VER=X.Y.Z; false", "VER=$(false)", "VER=X.Y.Z && false", "IMAGE=x`false`", "VER=X.Y.Z\nfalse"):
    g = guide.replace("```sh\nVER=X.Y.Z\n```", "```sh\n%s\n```" % bad_line, 1)
    try:
        kinds = [b["kind"] for b in L.guide_blocks(g)]
        got = "settings" if g != guide and kinds.count("settings") == 2 else "refused-or-run"
    except ValueError:
        got = "refused-or-run"
    check("SEC-169-04 %r is never swallowed as a setting" % bad_line, got == "refused-or-run", got)
# SEC-169-05: scanner reports must be valid, and suppression shown affirmatively, the rest kept
GB = {"matches": [{"vulnerability": {"id": "CVE-T"}}, {"vulnerability": {"id": "CVE-C"}}], "ignoredMatches": []}
GA = {"matches": [{"vulnerability": {"id": "CVE-C"}}], "ignoredMatches": [{"vulnerability": {"id": "CVE-T"}}]}
check("grype: suppressed and the rest kept passes", L.judge_grype(GB, GA, "CVE-T") is None, L.judge_grype(GB, GA, "CVE-T"))
for why, after in [("{}", {}), ("no matches list", {"ignoredMatches": []}), ("everything dropped", {"matches": [], "ignoredMatches": []}),
                   ("still matched", GB), ("dropped without being ignored", {"matches": [{"vulnerability": {"id": "CVE-C"}}], "ignoredMatches": []}),
                   ("not a dict", "x")]:
    check("SEC-169-05 grype refuses after = %s" % why, L.judge_grype(GB, after, "CVE-T") is not None)
check("SEC-169-05 grype refuses a before without the CVE", L.judge_grype(GA, GA, "CVE-T") is not None)
# Codex #387 r2: Grype's judge compares complete finding identities (id + package), not CVE sets
def gm(cve, pkg, ver="1"): return {"vulnerability": {"id": cve}, "artifact": {"name": pkg, "version": ver, "type": "deb"}}
GB2 = {"matches": [gm("CVE-T", "a"), gm("CVE-U", "lib-a"), gm("CVE-U", "lib-b")], "ignoredMatches": []}
GA2 = {"matches": [gm("CVE-U", "lib-a"), gm("CVE-U", "lib-b")], "ignoredMatches": [gm("CVE-T", "a")]}
check("grype identity: the target moved to ignored and every other finding kept passes", L.judge_grype(GB2, GA2, "CVE-T") is None, L.judge_grype(GB2, GA2, "CVE-T"))
for why, after in [("an unrelated finding on one package lost", {"matches": [gm("CVE-U", "lib-a")], "ignoredMatches": [gm("CVE-T", "a")]}),
                   ("a new unrelated finding", {"matches": [gm("CVE-U", "lib-a"), gm("CVE-U", "lib-b"), gm("CVE-X", "lib-c")], "ignoredMatches": [gm("CVE-T", "a")]}),
                   ("an unrelated finding also ignored", {"matches": [gm("CVE-U", "lib-a")], "ignoredMatches": [gm("CVE-T", "a"), gm("CVE-U", "lib-b")]}),
                   ("the target ignored on another package only", {"matches": [gm("CVE-U", "lib-a"), gm("CVE-U", "lib-b")], "ignoredMatches": [gm("CVE-T", "other")]})]:
    check("SEC-387 grype identity refuses %s" % why, L.judge_grype(GB2, after, "CVE-T") is not None)

# SEC-169-06: Google's assessment must be NEW and come from a note this run's loading created
occ = lambda state, note=None: {"noteName": "projects/goog-vulnz/notes/CVE-T", "vulnerability": dict(
    {"vexAssessment": {"state": state, "noteName": note}} if state else {})}
RUN_NOTES = {"projects/p/notes/ours"}
check("google: unassessed before, ours after passes",
      L.judge_google({"occurrences": [occ(None)]}, {"occurrences": [occ("NOT_AFFECTED", "projects/p/notes/ours")]}, "CVE-T", RUN_NOTES) is None)
for why, b, a in [("pre-existing NOT_AFFECTED before", [occ("NOT_AFFECTED", "projects/p/notes/old")], [occ("NOT_AFFECTED", "projects/p/notes/old")]),
                  ("an assessment from another note", [occ(None)], [occ("NOT_AFFECTED", "projects/unrelated/notes/old")]),
                  ("no occurrence before", [], [occ("NOT_AFFECTED", "projects/p/notes/ours")]),
                  ("no occurrence after", [occ(None)], []),
                  ("still affected after", [occ(None)], [occ("AFFECTED", "projects/p/notes/ours")])]:
    check("SEC-169-06 google refuses %s" % why, L.judge_google({"occurrences": b}, {"occurrences": a}, "CVE-T", RUN_NOTES) is not None)
check("SEC-169-06 google refuses when this run created no note", L.judge_google({"occurrences": [occ(None)]},
      {"occurrences": [occ("NOT_AFFECTED", "projects/p/notes/ours")]}, "CVE-T", set()) is not None)

# Codex #387 r1 (P2): Google's judge compares the COMPLETE occurrence inventories: every occurrence before is still there after (an unrelated finding or one of two
# target occurrences lost proves nothing), every target occurrence carries our note's assessment, and nothing else was assessed by it
def occn(name, cve, state=None, note=None):
    return {"name": name, "noteName": "projects/goog-vulnz/notes/" + cve, "vulnerability": dict(
        {"vexAssessment": {"state": state, "noteName": note}} if state else {})}
OURS = "projects/p/notes/ours"
T1, T2, U1 = occn("o/1", "CVE-T"), occn("o/2", "CVE-T"), occn("o/3", "CVE-U")
T1a, T2a = occn("o/1", "CVE-T", "NOT_AFFECTED", OURS), occn("o/2", "CVE-T", "NOT_AFFECTED", OURS)
check("google inventory: two target occurrences assessed and the unrelated one untouched passes",
      L.judge_google({"occurrences": [T1, T2, U1]}, {"occurrences": [T1a, T2a, U1]}, "CVE-T", {OURS}) is None,
      L.judge_google({"occurrences": [T1, T2, U1]}, {"occurrences": [T1a, T2a, U1]}, "CVE-T", {OURS}))
for why, after in [("an unrelated finding lost", [T1a, T2a]), ("one of two target occurrences lost", [T1a, U1]),
                   ("an unrelated finding assessed by our note too", [T1a, T2a, occn("o/3", "CVE-U", "NOT_AFFECTED", OURS)]),
                   ("one target occurrence left unassessed", [T1a, T2, U1]), ("a new occurrence that was not there before", [T1a, T2a, U1, occn("o/9", "CVE-X")])]:
    check("SEC-387 google inventory refuses %s" % why, L.judge_google({"occurrences": [T1, T2, U1]}, {"occurrences": after}, "CVE-T", {OURS}) is not None)
# Codex #387 r4 (P2): an unrelated occurrence keeps the assessment it had, whoever's note: one gained from a foreign note, or one that was dropped, is refused
UF = occn("o/3", "CVE-U", "NOT_AFFECTED", "projects/other/notes/pre-existing")
check("SEC-387 google: an unrelated occurrence that already had an assessment and keeps it passes",
      L.judge_google({"occurrences": [T1, T2, UF]}, {"occurrences": [T1a, T2a, UF]}, "CVE-T", {OURS}) is None)
check("SEC-387 google refuses an unrelated occurrence that gained an assessment from a foreign note",
      L.judge_google({"occurrences": [T1, T2, U1]}, {"occurrences": [T1a, T2a, occn("o/3", "CVE-U", "NOT_AFFECTED", "projects/other/notes/x")]}, "CVE-T", {OURS}) is not None)
check("SEC-387 google refuses an unrelated occurrence whose existing assessment was dropped",
      L.judge_google({"occurrences": [T1, T2, UF]}, {"occurrences": [T1a, T2a, occn("o/3", "CVE-U")]}, "CVE-T", {OURS}) is not None)
check("SEC-387 google refuses an unrelated occurrence whose assessment changed state",
      L.judge_google({"occurrences": [T1, T2, UF]}, {"occurrences": [T1a, T2a, occn("o/3", "CVE-U", "AFFECTED", "projects/other/notes/pre-existing")]}, "CVE-T", {OURS}) is not None)

# Codex #387 r1 (P2): Inspector's judge compares the complete finding inventories too: the target CVE's findings are all SUPPRESSED after, and every other finding is still
# there, with the status it had (our file suppressed exactly one CVE)
def fi(arn, cve, status, pkg="p1", ver="1"): return {"findingArn": arn, "vulnerabilityId": cve, "status": status, "packageName": pkg, "packageVersion": ver}
PKG = {"name": "p1", "version": "1"}
IB = {"findings": [fi("a/1", "CVE-T", "ACTIVE"), fi("a/2", "CVE-T", "ACTIVE", "p2", "9"), fi("a/3", "CVE-U", "ACTIVE", "p3", "1")]}
P2, P3 = ("p2", "9"), ("p3", "1")
check("inspector inventory: the target suppressed and the other finding untouched passes",
      L.judge_inspector(IB, {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "ACTIVE", *P2), fi("a/3", "CVE-U", "ACTIVE", *P3)]}, "CVE-T", PKG) is None)
for why, after in [("an unrelated CVE suppressed too", [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "ACTIVE", *P2), fi("a/3", "CVE-U", "SUPPRESSED", *P3)]),
                   ("an unrelated finding lost", [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "ACTIVE", *P2)]),
                   ("the target finding still active", [fi("a/1", "CVE-T", "ACTIVE"), fi("a/2", "CVE-T", "ACTIVE", *P2), fi("a/3", "CVE-U", "ACTIVE", *P3)]),
                   ("the target finding lost", [fi("a/2", "CVE-T", "ACTIVE", *P2), fi("a/3", "CVE-U", "ACTIVE", *P3)]),
                   ("a finding that was not there before", [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "ACTIVE", *P2), fi("a/3", "CVE-U", "ACTIVE", *P3), fi("a/4", "CVE-X", "ACTIVE")])]:
    check("SEC-387 inspector inventory refuses %s" % why, L.judge_inspector(IB, {"findings": after}, "CVE-T", PKG) is not None)
# Codex #387 r8 (P2, both seats): the run proves package isolation only if the target CVE is ALSO active in another package before; a singleton passes a CVE-only rule
SOLO = {"findings": [fi("a/1", "CVE-T", "ACTIVE"), fi("a/3", "CVE-U", "ACTIVE", *P3)]}
check("OWNER-3 inspector refuses a before in which the target CVE is in one package only (a CVE-only rule would pass)",
      L.judge_inspector(SOLO, {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/3", "CVE-U", "ACTIVE", *P3)]}, "CVE-T", PKG) is not None)
SAMEPKG = {"findings": [fi("a/1", "CVE-T", "ACTIVE"), fi("a/2", "CVE-T", "ACTIVE", "p1", "2"), fi("a/3", "CVE-U", "ACTIVE", *P3)]}
check("OWNER-3 inspector refuses a before whose other finding of the CVE is the same package name (two versions are not two packages)",
      L.judge_inspector(SAMEPKG, {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "ACTIVE", "p1", "2"), fi("a/3", "CVE-U", "ACTIVE", *P3)]}, "CVE-T", PKG) is not None)
check("OWNER-3 inspector refuses a before whose other-package finding of the CVE is not active",
      L.judge_inspector({"findings": [fi("a/1", "CVE-T", "ACTIVE"), fi("a/2", "CVE-T", "SUPPRESSED", *P2), fi("a/3", "CVE-U", "ACTIVE", *P3)]},
                        {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "SUPPRESSED", *P2), fi("a/3", "CVE-U", "ACTIVE", *P3)]}, "CVE-T", PKG) is not None)
check("SEC-387 inspector refuses a before without the target CVE", L.judge_inspector({"findings": [fi("a/3", "CVE-U", "ACTIVE")]}, {"findings": [fi("a/3", "CVE-U", "ACTIVE")]}, "CVE-T", PKG) is not None)
check("SEC-387 inspector refuses a malformed document", L.judge_inspector(IB, {"findings": "x"}, "CVE-T", PKG) is not None and L.judge_inspector(IB, [], "CVE-T", PKG) is not None)

# owner Oct 16 (handoff 0482): the rule names the package, so the same CVE in another package is never hidden: the judge compares package identity too
IB2 = {"findings": [fi("a/1", "CVE-T", "ACTIVE"), fi("a/2", "CVE-T", "ACTIVE", "p2", "9"), fi("a/3", "CVE-U", "ACTIVE", "p3", "1")]}
check("OWNER-3 inspector: the target package suppressed, the same CVE in another package and the decoy untouched, passes",
      L.judge_inspector(IB2, {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "ACTIVE", "p2", "9"), fi("a/3", "CVE-U", "ACTIVE", "p3", "1")]}, "CVE-T", PKG) is None)
check("OWNER-3 inspector refuses the same CVE suppressed in the other package too",
      L.judge_inspector(IB2, {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "SUPPRESSED", "p2", "9"), fi("a/3", "CVE-U", "ACTIVE", "p3", "1")]}, "CVE-T", PKG) is not None)
check("OWNER-3 inspector refuses the decoy's CVE suppressed (a rule for a package that is not there must hide nothing)",
      L.judge_inspector(IB2, {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "ACTIVE", "p2", "9"), fi("a/3", "CVE-U", "SUPPRESSED", "p3", "1")]}, "CVE-T", PKG) is not None)
check("OWNER-3 inspector refuses a target package finding that stays active",
      L.judge_inspector(IB2, {"findings": [fi("a/1", "CVE-T", "ACTIVE"), fi("a/2", "CVE-T", "ACTIVE", "p2", "9"), fi("a/3", "CVE-U", "ACTIVE", "p3", "1")]}, "CVE-T", PKG) is not None)
check("OWNER-3 inspector refuses a before in which the target CVE is not in the named package",
      L.judge_inspector({"findings": [fi("a/2", "CVE-T", "ACTIVE", "p2", "9")]}, {"findings": [fi("a/2", "CVE-T", "SUPPRESSED", "p2", "9")]}, "CVE-T", PKG) is not None)
check("OWNER-3 inspector refuses a finding that changed its package", L.judge_inspector(IB2, {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-T", "ACTIVE", "p1", "1"), fi("a/3", "CVE-U", "ACTIVE", "p3", "1")]}, "CVE-T", PKG) is not None)
check("OWNER-3 inspector refuses a finding without a package", L.judge_inspector({"findings": [{"findingArn": "a/1", "vulnerabilityId": "CVE-T", "status": "ACTIVE"}]}, {"findings": [{"findingArn": "a/1", "vulnerabilityId": "CVE-T", "status": "SUPPRESSED"}]}, "CVE-T", PKG) is not None)

# Codex #387 r3 (P2): a finding that keeps its ID but changes its CVE is not the finding that was there: the CVE association of every ID is compared
check("SEC-387 inspector refuses an unrelated finding changed to the target CVE and suppressed",
      L.judge_inspector({"findings": [fi("a/1", "CVE-T", "ACTIVE"), fi("a/3", "CVE-U", "ACTIVE")]},
                        {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/3", "CVE-T", "SUPPRESSED")]}, "CVE-T", PKG) is not None)
check("SEC-387 inspector refuses a target finding changed to an unrelated CVE",
      L.judge_inspector({"findings": [fi("a/1", "CVE-T", "ACTIVE"), fi("a/2", "CVE-T", "ACTIVE")]},
                        {"findings": [fi("a/1", "CVE-T", "SUPPRESSED"), fi("a/2", "CVE-U", "ACTIVE")]}, "CVE-T", PKG) is not None)
check("SEC-387 google refuses one of two target occurrences changed to an unrelated CVE while the other is assessed",
      L.judge_google({"occurrences": [T1, T2, U1]}, {"occurrences": [T1a, occn("o/2", "CVE-U"), U1]}, "CVE-T", {OURS}) is not None)
check("SEC-387 google refuses an unrelated occurrence changed to the target CVE",
      L.judge_google({"occurrences": [T1, U1]}, {"occurrences": [T1a, occn("o/3", "CVE-T", "NOT_AFFECTED", OURS)]}, "CVE-T", {OURS}) is not None)

# behavioral: the shell library, with stubs
script = os.path.join(root, "bin/vex-live-run.sh")
def sh(body, stubs, env=None):
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "stub"))
        for name, code in stubs.items():
            with open(os.path.join(t, "stub", name), "w") as fh:
                fh.write("#!/usr/bin/env bash\n" + code + "\n")
            os.chmod(os.path.join(t, "stub", name), 0o755)
        e = dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], VEX_LIVE_TEST_LIB="1", GITHUB_WORKSPACE=root,
                 RUNNER_TEMP=t, ECR="1.dkr.ecr.us-east-1.amazonaws.com/fosterstack-cache-live-test",
                 GAR="us-east1-docker.pkg.dev/fosterstack-cache/cache-live-test", GITHUB_RUN_ID="1", **(env or {}))
        # the Container Analysis calls go through ca() -> the python helper (urllib, tested below); here ca() is replaced by the stub transport so the shell
        # logic around it is tested offline
        prelude = 'ca_get() { ca-transport "$1"; }; ca_delete() { ca-transport -X DELETE "$1"; }; ' if "ca-transport" in stubs else ""
        r = subprocess.run(["bash", "-c", 'set -euo pipefail; source "$0"; ' + prelude + body, script], cwd=t, env=e,
                           capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr
# the Container Analysis API is called by the python helper (an API call for data, not a software download): fixed host, bearer token, the method asked for,
# an HTTP error is an error
import io, urllib.error
seen = {}
class FakeResp:
    def __init__(self, body): self.body = body
    def read(self): return self.body
    def __enter__(self): return self
    def __exit__(self, *a): return False
def opener_ok(req, timeout=None):
    seen["url"], seen["method"], seen["auth"] = req.full_url, req.get_method(), req.get_header("Authorization")
    return FakeResp(b'{"names": []}')
CA = "https://containeranalysis.googleapis.com/v1/projects/p/notes?pageSize=1000"
check("ca: a GET to the Container Analysis host with the bearer token", L.ca_request(CA, "GET", "tok", opener_ok) == '{"names": []}'
      and seen == {"url": CA, "method": "GET", "auth": "Bearer tok"}, seen)
L.ca_request("https://containeranalysis.googleapis.com/v1/projects/p/notes/n", "DELETE", "tok", opener_ok)
check("ca: a DELETE is sent as a DELETE", seen["method"] == "DELETE", seen)
for why, url, method in [("another host", "https://example.org/v1/x", "GET"), ("plain http", "http://containeranalysis.googleapis.com/v1/x", "GET"),
                         ("a host that only starts with the right name", "https://containeranalysis.googleapis.com.evil.example/v1/x", "GET"),
                         ("a user part", "https://containeranalysis.googleapis.com@evil.example/v1/x", "GET"), ("a method that is neither GET nor DELETE", CA, "POST")]:
    try:
        L.ca_request(url, method, "tok", opener_ok); got = "accepted"
    except ValueError:
        got = "refused"
    check("ca refuses %s" % why, got == "refused", got)
def opener_err(req, timeout=None):
    raise urllib.error.HTTPError(req.full_url, 403, "denied", {}, io.BytesIO(b""))
try:
    L.ca_request(CA, "GET", "tok", opener_err); got = "returned"
except urllib.error.HTTPError:
    got = "raised"
check("ca: an HTTP error is an error, never an empty answer", got == "raised", got)
# Codex #387 r1: a redirect is never followed (the bearer header would travel to the redirect target): the default opener refuses it
import http.server, threading
hits = []
class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append((self.path, self.headers.get("Authorization")))
        if self.path == "/start":
            self.send_response(302); self.send_header("Location", "/target"); self.end_headers()
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"target")
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
import urllib.request
try:
    L._opener().open(urllib.request.Request("http://127.0.0.1:%d/start" % srv.server_port, headers={"Authorization": "Bearer tok"}), timeout=5); got = "followed"
except urllib.error.HTTPError as e:
    got = "refused %d" % e.code
srv.shutdown()
check("ca: a redirect is refused and the target is never requested", got == "refused 302" and [h[0] for h in hits] == ["/start"], (got, hits))
try:
    L.ca_request(CA, "GET", "", opener_ok); got = "accepted"
except ValueError:
    got = "refused"
check("ca: no token is refused", got == "refused", got)
# SEC-169-03 (moved to the python runner, advisor Oct 16): the page's blocks run exactly as written, one bash per section with the test's settings, under errexit AND pipefail:
# a failing command anywhere, inside a pipe too, stops the run
def guide_run(blocks, stubs, section, state="VER='0.3.0'\nIMAGE='x/y/cache'\n"):
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "plan")); os.makedirs(os.path.join(t, "stub"))
        names = []
        for i, (sec, text) in enumerate(blocks):
            n = "%02d-%s.sh" % (i, sec); names.append(n)
            open(os.path.join(t, "plan", n), "w").write(text)
        open(os.path.join(t, "plan.txt"), "w").write("\n".join(names) + "\n")
        open(os.path.join(t, "state.env"), "w").write(state)
        for name, code in stubs.items():
            open(os.path.join(t, "stub", name), "w").write("#!/usr/bin/env bash\n" + code + "\n"); os.chmod(os.path.join(t, "stub", name), 0o755)
        r = subprocess.run(["python3", os.path.join(root, "bin/vex-live-test.py"), "guide", "--plan", "plan.txt", "--state", "state.env", section], cwd=t,
                           env=dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"]), capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr, open(os.path.join(t, "state.env")).read()
PIPE = "cosign verify-attestation x | jq -r . > out.json\n"
rc, out, _ = guide_run([("verify", PIPE), ("verify", "echo RAN_$((1+1))\n")], {"cosign": "echo '{}'; exit 42"}, "verify")
check("SEC-169-03 a failed cosign inside a pipe stops the run, and the next block of the section does not run", rc != 0 and "RAN_2" not in out, (rc, out[-200:]))
rc, out, _ = guide_run([("verify", "false\necho RAN_$((1+1))\n")], {}, "verify")
check("SEC-169-03 a failing plain command stops the block", rc != 0 and "RAN_2" not in out, (rc, out[-200:]))
bare = subprocess.run(["bash", "-ec", "false | cat; echo SURVIVED"], capture_output=True, text=True)
check("SEC-169-03 the bad case is real: without pipefail the same pipe would not stop a bash -e run", bare.returncode == 0 and "SURVIVED" in bare.stdout)
rc, out, _ = guide_run([("verify", "echo \"$VER $IMAGE\"\n")], {}, "verify")
check("the blocks see the test's settings", rc == 0 and "0.3.0 x/y/cache" in out, (rc, out[-200:]))
D = "sha256:" + "a" * 64
rc, out, st = guide_run([("digest", "DIGEST=$(echo %s)\n" % D), ("download", "echo got-$DIGEST\n")], {}, "digest")
check("a digest block's DIGEST is kept for the later blocks", rc == 0 and ("DIGEST='%s'" % D) in st, (rc, st))
rc, out, st = guide_run([("digest", "DIGEST=not-a-digest\n")], {}, "digest")
check("a DIGEST that is not sha256:<64 hex> is refused", rc != 0, (rc, out[-200:]))
rc, out, st = guide_run([("verify", "OTHER=1; export OTHER\n")], {}, "verify")
check("nothing but VER, IMAGE and DIGEST is carried between sections", rc == 0 and "OTHER" not in st, st)
rc, out, st = guide_run([("verify", "VER=9.9.9\n")], {}, "verify")
check("a block that changes VER cannot change the test's value", rc != 0 or "VER='0.3.0'" in st, (rc, st))
# SEC-169-08/09: the sweep fails when it cannot list or delete, pages through notes, and empties the test repositories
OKAWS = r"""case "$*" in
  *"ecr list-images"*) echo '{"imageIds": []}' ;;
  *"ecr describe-images"*) echo '{"imageDetails": []}' ;;
  *"inspector2 list-filters"*) echo '{"filters": []}' ;;
  *) echo '{}' ;; esac"""
OKGC = 'case "$*" in *"auth print-access-token"*) echo tok ;; *"images list"*) echo "[]" ;; esac'
OKCURL = 'echo "{}"'
# Codex #387 r1 (P2): a failed delete is recorded for good: a later empty listing does not erase it
GC_FAIL_DEL = r"""case "$*" in *"auth print-access-token"*) echo tok ;; *"images list"*) if [ -f "$RUNNER_TEMP/del" ]; then echo "[]"; else echo '[{"package": "x/y/cache", "version": "sha256:aaaa"}]'; fi ;;
  *"images delete"*) touch "$RUNNER_TEMP/del"; exit 42 ;; esac"""
# Codex #387 r2: an ECR per-image failure on an early pass is recorded for good too
AWS_ECR_FAIL = r"""case "$*" in
  *"ecr describe-images"*) echo '{"imageDetails": []}' ;;
  *"ecr list-images"*) if [ -f "$RUNNER_TEMP/del" ]; then echo '{"imageIds": []}'; else echo '{"imageIds": [{"imageDigest": "sha256:aaaa"}]}'; fi ;;
  *"ecr batch-delete-image"*) if [ -f "$RUNNER_TEMP/first" ]; then touch "$RUNNER_TEMP/del"; echo '{"failures": [], "imageIds": [{"imageDigest": "sha256:aaaa"}]}'; else touch "$RUNNER_TEMP/first"; echo '{"failures": [{"imageId": {"imageDigest": "sha256:aaaa"}, "failureCode": "KmsError"}], "imageIds": []}'; fi ;;
  *"inspector2 list-filters"*) echo '{"filters": []}' ;; *) echo '{}' ;; esac"""
rc, out = sh("sweep", {"aws": AWS_ECR_FAIL, "gcloud": OKGC, "ca-transport": OKCURL})
check("SEC-387 sweep fails when an ECR per-image delete failed on an early pass and a later pass succeeded", rc != 0, (rc, out[-300:]))
# Codex #387 r3 (P2): one failing listing does not stop the cleanup of the other resource families; every failure is kept and the sweep fails at the end
CALLS = r"""echo "$0 $*" >> "$RUNNER_TEMP/calls"; """
AWS_ECR_DOWN = CALLS + r"""case "$*" in *"ecr describe-images"*) exit 42 ;; *"ecr list-images"*) exit 42 ;; *"inspector2 list-filters"*) echo '{"filters": []}' ;; *) echo '{}' ;; esac"""
GC_LOG = CALLS + r"""case "$*" in *"auth print-access-token"*) echo tok ;; *"images list"*) echo "[]" ;; esac"""
# Codex #387 r5 (P2): ECR refuses to delete an image that a manifest list still references, so the indexes go first (found by their media type), then the rest
IDX, CHILD = "sha256:" + "1" * 64, "sha256:" + "2" * 64
AWS_ECR_INDEX = CALLS + ("""IDX=%s; CH=%s
case "$*" in
  *"ecr describe-images"*) if [ -f "$RUNNER_TEMP/idxdel" ]; then echo '{"imageDetails": [{"imageDigest": "'$CH'", "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json"}]}';
    else echo '{"imageDetails": [{"imageDigest": "'$IDX'", "imageManifestMediaType": "application/vnd.oci.image.index.v1+json"}, {"imageDigest": "'$CH'", "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json"}]}'; fi ;;
  *"ecr list-images"*) if [ -f "$RUNNER_TEMP/chdel" ]; then echo '{"imageIds": []}'; elif [ -f "$RUNNER_TEMP/idxdel" ]; then echo '{"imageIds": [{"imageDigest": "'$CH'"}]}'; else echo '{"imageIds": [{"imageDigest": "'$IDX'"}, {"imageDigest": "'$CH'"}]}'; fi ;;
  *"ecr batch-delete-image"*)
    had=0; [ -f "$RUNNER_TEMP/idxdel" ] && had=1
    case "$*" in *$IDX*) touch "$RUNNER_TEMP/idxdel"; ok='{"imageDigest": "'$IDX'"}' ;; *) ok="" ;; esac
    case "$*" in *$CH*) if [ "$had" = 1 ]; then touch "$RUNNER_TEMP/chdel"; ok="${ok:+$ok, }"'{"imageDigest": "'$CH'"}'; fail="";
                         else fail='{"imageId": {"imageDigest": "'$CH'"}, "failureCode": "ImageReferencedByManifestList"}'; fi ;; *) fail="" ;; esac
    echo '{"failures": ['"$fail"'], "imageIds": ['"$ok"']}' ;;
  *"inspector2 list-filters"*) echo '{"filters": []}' ;; *) echo '{}' ;; esac""" % (IDX, CHILD))
rc, out = sh("sweep", {"aws": AWS_ECR_INDEX, "gcloud": OKGC, "ca-transport": OKCURL})
check("SEC-387 ECR: the manifest list is deleted before the image it references, so the sweep passes without any recorded failure", rc == 0, (rc, out[-400:]))
for why, doc, ok in [("indexes found by media type", '{"imageDetails": [{"imageDigest": "sha256:a", "imageManifestMediaType": "application/vnd.oci.image.index.v1+json"}, {"imageDigest": "sha256:b", "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json"}]}', True),
                     ("a Docker manifest list too", '{"imageDetails": [{"imageDigest": "sha256:a", "imageManifestMediaType": "application/vnd.docker.distribution.manifest.list.v2+json"}]}', True),
                     ("an image without its media type", '{"imageDetails": [{"imageDigest": "sha256:a"}]}', False), ("no list", '{}', False)]:
    r = subprocess.run(["python3", os.path.join(root, "bin/vex-live-test.py"), "inventory", "--kind", "ecr-indexes"], input=doc, capture_output=True, text=True)
    check("inventory ecr-indexes: %s is %s" % (why, "read" if ok else "refused"), (r.returncode == 0) == ok, r.stderr[-120:])
r = subprocess.run(["python3", os.path.join(root, "bin/vex-live-test.py"), "inventory", "--kind", "ecr-indexes"],
                   input='{"imageDetails": [{"imageDigest": "sha256:a", "imageManifestMediaType": "application/vnd.oci.image.index.v1+json"}, {"imageDigest": "sha256:b", "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json"}]}', capture_output=True, text=True)
check("inventory ecr-indexes returns only the index digests", "sha256:a" in r.stdout and "sha256:b" not in r.stdout, r.stdout)

rc, out = sh('sweep || echo SWEEP_FAILED; cat "$RUNNER_TEMP/calls"', {"aws": AWS_ECR_DOWN, "gcloud": GC_LOG, "ca-transport": OKCURL})
check("SEC-387 an ECR listing failure does not skip the Google, Inspector and note cleanup, and the sweep still fails",
      "SWEEP_FAILED" in out and "images list" in out and "inspector2 list-filters" in out, (rc, out[-400:]))
# the downloaded forms of a published release are compared with the generator's output, the CSAF included, before the test replaces them
rc, out = sh("mkdir -p regen; echo '{}' > fosterstack-cache.openvex.json; echo '{}' > fosterstack-cache-v0.3.0.inspector-filters.json; echo '{}' > fosterstack-cache-v0.3.0.csaf.json; "
             "cp fosterstack-cache-v0.3.0.inspector-filters.json fosterstack-cache-v0.3.0.csaf.json regen/; compare_release_files v0.3.0 fosterstack-cache.openvex.json",
             {}, {})
check("SEC-387 a published release whose three forms equal the generator's output passes the comparison", rc == 0, (rc, out[-300:]))
rc, out = sh("mkdir -p regen; echo '{}' > fosterstack-cache.openvex.json; echo '{}' > fosterstack-cache-v0.3.0.inspector-filters.json; echo '{\"x\": 1}' > fosterstack-cache-v0.3.0.csaf.json; "
             "echo '{}' > regen/fosterstack-cache-v0.3.0.inspector-filters.json; echo '{}' > regen/fosterstack-cache-v0.3.0.csaf.json; compare_release_files v0.3.0 fosterstack-cache.openvex.json", {}, {})
check("SEC-387 a published CSAF that differs from the generator's output fails the comparison", rc != 0, (rc, out[-300:]))
# Codex #387 r1 (P2): the page's removal block selects every filter named fosterstack-cache-; before it runs, every such filter in the account must be a live-test one
FLT = lambda *names: """echo '{"filters": [%s]}'""" % ", ".join('{"name": "%s", "arn": "arn:%d"}' % (n, i) for i, n in enumerate(names))
rc, out = sh("check_removal_scope", {"aws": FLT("fosterstack-cache-livetest-x", "fosterstack-cache-v0.3.0-CVE-1")}, {"REGION": "us-east-1"})
check("SEC-387 the guide's removal does not run while a non-test filter of ours exists", rc != 0, (rc, out[-200:]))
rc, out = sh("check_removal_scope", {"aws": FLT("fosterstack-cache-livetest-x", "fosterstack-cache-livetest-y")}, {"REGION": "us-east-1"})
check("SEC-387 the guide's removal may run when every filter of ours is a live-test one", rc == 0, (rc, out[-200:]))
rc, out = sh("check_removal_scope", {"aws": FLT()}, {"REGION": "us-east-1"})
check("SEC-387 the guide's removal may run when there is no filter", rc == 0, (rc, out[-200:]))
rc, out = sh("check_removal_scope", {"aws": "exit 254"}, {"REGION": "us-east-1"})
check("SEC-387 a failed filter listing stops the removal", rc != 0, (rc, out[-200:]))
rc, out = sh("sweep", {"aws": OKAWS, "gcloud": OKGC, "ca-transport": OKCURL})
check("sweep of empty test resources passes", rc == 0, out[-300:])
rc, out = sh("sweep", {"aws": OKAWS, "gcloud": GC_FAIL_DEL, "ca-transport": OKCURL})
check("SEC-387 sweep fails when a Google delete fails even though the next listing is empty", rc != 0, (rc, out[-300:]))
rc, out = sh("sweep", {"aws": 'echo AccessDenied >&2; exit 254', "gcloud": OKGC, "ca-transport": OKCURL})
check("SEC-169-08 sweep fails when AWS listing fails", rc != 0, out[-200:])
rc, out = sh("sweep", {"aws": OKAWS, "gcloud": OKGC, "ca-transport": 'echo denied >&2; exit 22'})
check("SEC-169-08 sweep fails when the notes cannot be listed", rc != 0, out[-200:])
rc, out = sh("sweep", {"aws": r"""case "$*" in
  *"ecr list-images"*) echo '{"imageIds": [{"imageDigest": "sha256:a"}]}' ;;
  *"batch-delete-image"*) echo '{"imageIds": [], "failures": [{"imageId": {"imageDigest": "sha256:a"}, "failureCode": "X"}]}' ;;
  *"inspector2 list-filters"*) echo '{"filters": []}' ;; *) echo '{}' ;; esac""", "gcloud": OKGC, "ca-transport": OKCURL})
check("SEC-169-08 sweep fails on an ECR per-image failure", rc != 0, out[-200:])
rc, out = sh("sweep; cat \"$RUNNER_TEMP/deleted\"", {"aws": OKAWS, "gcloud": OKGC, "ca-transport": r"""for a in "$@"; do u=$a; done
case "$u" in
  *notes\?*) [ -s "$RUNNER_TEMP/deleted" ] && { echo '{"notes": []}'; exit 0; } ;;& 
  *notes\?*pageToken=p2*) echo '{"notes": [{"name": "projects/p/notes/two", "vulnerabilityAssessment": {"product": {"genericUri": "https://us-east1-docker.pkg.dev/fosterstack-cache/cache-live-test/cache@sha256:b"}}}]}' ;;
  *notes\?*) echo '{"notes": [{"name": "projects/p/notes/one", "vulnerabilityAssessment": {"product": {"genericUri": "https://us-east1-docker.pkg.dev/fosterstack-cache/cache-live-test/cache@sha256:a"}}}], "nextPageToken": "p2"}' ;;
  *) case " $* " in *" -X DELETE "*) echo "$u" >> "$RUNNER_TEMP/deleted" ;; esac; echo '{}' ;; esac"""})
check("SEC-169-09 sweep pages through the notes and deletes every one of the test repository's",
      "notes/one" in out and "notes/two" in out, out[-400:])
# Codex #169 r2 (SEC-169-08): every inventory is parsed strictly; a malformed or unparseable listing fails the sweep
NOTE_OK = '{"name": "projects/p/notes/stale", "vulnerabilityAssessment": {"product": {"genericUri": "https://us-east1-docker.pkg.dev/fosterstack-cache/cache-live-test/cache@sha256:a"}}}'
for why, aws_s, gc_s, curl_s in [
        ("a note with a numeric genericUri before a stale test note", OKAWS, OKGC,
         'case " $* " in *" -X DELETE "*) echo "{}" ;; *) echo \'{"notes": [{"name": "projects/p/notes/x", "vulnerabilityAssessment": {"product": {"genericUri": 7}}}, %s]}\' ;; esac' % NOTE_OK),
        ("notes listing as a number", OKAWS, OKGC, "echo '{\"notes\": 7}'"),
        ("GAR listing null", OKAWS, 'case "$*" in *"auth print-access-token"*) echo tok ;; *"images list"*) echo null ;; esac', OKCURL),
        ("GAR listing {}", OKAWS, 'case "$*" in *"auth print-access-token"*) echo tok ;; *"images list"*) echo "{}" ;; esac', OKCURL),
        ("ECR listing without imageIds", 'case "$*" in *"ecr list-images"*) echo "{}" ;; *"inspector2 list-filters"*) echo \'{"filters": []}\' ;; *) echo "{}" ;; esac', OKGC, OKCURL),
        ("filters listing null", 'case "$*" in *"ecr list-images"*) echo \'{"imageIds": []}\' ;; *"inspector2 list-filters"*) echo null ;; *) echo "{}" ;; esac', OKGC, OKCURL),
        ("an ECR delete answer without a failures list", r"""case "$*" in
  *"ecr list-images"*) echo '{"imageIds": [{"imageDigest": "sha256:a"}]}' ;;
  *"batch-delete-image"*) echo 'oops' ;;
  *"inspector2 list-filters"*) echo '{"filters": []}' ;; *) echo '{}' ;; esac""", OKGC, OKCURL)]:
    rc, out = sh("sweep", {"aws": aws_s, "gcloud": gc_s, "ca-transport": curl_s})
    check("SEC-169-08 sweep fails on %s" % why, rc != 0, out[-200:])
# Codex #169 r3 (SEC-169-08): a failing step inside the note enumeration (sed, cut) fails the sweep, never reads as empty
NOTE_PAGE = r"""case " $* " in *" -X DELETE "*) echo "{}" ;; *) echo '{"notes": [%s]}' ;; esac""" % NOTE_OK
for tool in ("sed", "cut"):
    rc, out = sh("sweep", {"aws": OKAWS, "gcloud": OKGC, "ca-transport": NOTE_PAGE, tool: "echo %s_FAILED >&2; exit 42" % tool.upper()})
    check("SEC-169-08 sweep fails when %s fails inside the note enumeration" % tool, rc != 0, out[-200:])
for kind, doc, ok in [("notes", '{"notes": [], "nextPageToken": 3}', False), ("notes", '{}', True),
                      ("gar", '[{"package": "x", "version": "sha256:a"}]', True), ("gar", '[{"package": 1}]', False),
                      ("ecr", '{"imageIds": [{"imageDigest": "sha256:a"}]}', True), ("ecr", '{"imageIds": [{}]}', False),
                      ("filters", '{"filters": [{"name": "fosterstack-cache-livetest-x", "arn": "a"}]}', True),
                      ("filters", '{"filters": [{"name": 5, "arn": "a"}]}', False)]:
    r = subprocess.run(["python3", os.path.join(root, "bin/vex-live-test.py"), "inventory", "--kind", kind,
                        "--prefix", "fosterstack-cache-livetest-"], input=doc, capture_output=True, text=True)
    check("inventory %s %s is %s" % (kind, doc, "read" if ok else "refused"), (r.returncode == 0) == ok, r.stderr[-120:])
# SEC-169-09: a push is journaled BEFORE the copy, so a copy that fails midway is still cleaned
rc, out = sh('export PUSHED_LOG="$RUNNER_TEMP/p"; push_copy a b || true; cat "$RUNNER_TEMP/p"', {"crane": "exit 1"})
check("SEC-169-09 a failed copy is still in the journal", out.strip().endswith("b"), out)
# SEC-169-11 (v0.3): main mode with no published release carrying the rule-10 files is an announced skip (no v0.3 release exists yet), never a silent green:
# the notice names it and the run does no live work
rc, out = sh("MODE=main; select_release; echo tag=${tag:-none} skip=${skip:-no}", {"gh": "true"}, {"GITHUB_REPOSITORY": "fosterstack/cache"})
check("SEC-170-02 main mode with no release is an announced skip", rc == 0 and "::notice::" in out and "skip=yes" in out, (rc, out[-300:]))
rc, out = sh("MODE=main; select_release; echo tag=${tag:-none} skip=${skip:-no}", {"gh": "echo '{\"tagName\":\"v0.3.0\",\"isDraft\":false,\"assets\":[\"fosterstack-cache.openvex.json\",\"fosterstack-cache-v0.3.0.inspector-filters.json\",\"fosterstack-cache-v0.3.0.csaf.json\"]}'"}, {"GITHUB_REPOSITORY": "fosterstack/cache"})
check("SEC-170-02 main mode with a published release tests it", rc == 0 and "tag=v0.3.0" in out and "skip=no" in out, (rc, out[-300:]))
for mode, ref, ok in [("rc", "v0.3.0-rc1", True), ("rc", "v0.3.0", False), ("rc", "v0.3.0-rc.1", False), ("rc", "v0.3.0-rc1-x", False),
                      ("release", "v0.3.0", True), ("release", "v0.3.0-rc1", False), ("release", "v0.3", False), ("release", "main", False)]:
    rc, out = sh("MODE=%s; select_release; echo tag=$tag" % mode, {}, {"GITHUB_REF_NAME": ref})
    check("SEC-170-02 %s mode on %s is %s" % (mode, ref, "accepted" if ok else "refused"), (rc == 0) == ok and (not ok or "tag=%s" % ref in out), (rc, out[-200:]))
# the candidate copy: the pushed digest must equal Build's, else the run fails (no digest is ever taken from the registry after the fact)
rc, out = sh('export PUSHED_LOG="$RUNNER_TEMP/p"; copy_candidate "$RUNNER_TEMP/layout" dst/cache:x sha256:%s' % ("a" * 64),
             {"crane": 'case "$1" in push) exit 0 ;; digest) echo sha256:%s ;; esac' % ("a" * 64)})
check("SEC-170-01 a candidate pushed to the digest Build attested is accepted", rc == 0, out[-200:])
rc, out = sh('export PUSHED_LOG="$RUNNER_TEMP/p"; copy_candidate "$RUNNER_TEMP/layout" dst/cache:x sha256:%s' % ("a" * 64),
             {"crane": 'case "$1" in push) exit 0 ;; digest) echo sha256:%s ;; esac' % ("b" * 64)})
check("SEC-170-01 a candidate that comes out at another digest fails the run", rc != 0, out[-200:])
rc, out = sh('export PUSHED_LOG="$RUNNER_TEMP/p"; copy_candidate "$RUNNER_TEMP/layout" dst/cache:x not-a-digest', {"crane": "exit 0"})
check("SEC-170-01 a malformed attested digest fails the run", rc != 0, out[-200:])
rc, out = sh('export PUSHED_LOG="$RUNNER_TEMP/p"; copy_candidate "$RUNNER_TEMP/layout" dst/cache:x sha256:%s || true; cat "$RUNNER_TEMP/p"' % ("a" * 64),
             {"crane": 'case "$1" in push) exit 1 ;; esac'})
check("SEC-170-01 a candidate push is journaled before it starts, so a failed push is still swept", out.strip().endswith("dst/cache:x"), out)
# SEC-169-07: one live test at a time, across both workflows, never cancelled midway
for name, job in (("release.yml rc", RJ), ("release.yml post-publish", PJ), ("ci.yml", ci["jobs"]["live-test"])):
    check("SEC-169-07 %s: the live-test job is serialized with every other live test" % name,
          job.get("concurrency") == {"group": "vex-live-test", "cancel-in-progress": "false"}, job.get("concurrency"))
# SEC-169-10: the gate reads a completed diff (no early-closed pipe under pipefail)
gstep = [st for st in ci["jobs"]["live-test-gate"]["steps"] if "run" in st][0]["run"]
with tempfile.TemporaryDirectory() as t:
    os.makedirs(os.path.join(t, "stub"))
    with open(os.path.join(t, "stub", "git"), "w") as fh:
        fh.write('#!/usr/bin/env bash\ncase "$1" in cat-file) exit 0 ;; diff) echo .vex/fosterstack-cache.openvex.json; '
                 'for i in $(seq 1 200000); do echo "src/file-$i.go"; done ;; esac\n')
    os.chmod(os.path.join(t, "stub", "git"), 0o755)
    outp = os.path.join(t, "out")
    r = subprocess.run(["bash", "-eo", "pipefail", "-c", gstep], cwd=t, capture_output=True, text=True,
                       env=dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], BEFORE="a",
                                GITHUB_SHA="b", GITHUB_OUTPUT=outp, RUNNER_TEMP=t))
    got = open(outp).read() if os.path.exists(outp) else ""
check("SEC-169-10 a long diff with a VEX change still runs the live test", "changed=true" in got, (r.returncode, got))
# --- the fixture carries, by construction, a CVE active in two package names (advisor Oct 17: the run must not discover on its first try that the fixture lacks one):
# docs/using-our-vex.live-fixture.json pins the image and the two packages (libc6 and libc-bin, both built from glibc 2.36-9, so every glibc CVE is reported on both);
# the manifest must name exactly the digest the runner copies, and the runner checks the real image's package list against it before it pushes anything
run_text = open(os.path.join(root, "bin/vex-live-run.sh")).read()
man_path = os.path.join(root, "docs/using-our-vex.live-fixture.json")
man = json.load(open(man_path)) if os.path.exists(man_path) else {}
check("the fixture manifest exists and holds no problem against the runner", bool(man) and L.fixture_manifest_problems(man, run_text) == [], L.fixture_manifest_problems(man, run_text) if man else "missing")
check("the manifest pins libc6 and libc-bin from one source", sorted(p["name"] for p in man.get("packages", [])) == ["libc-bin", "libc6"] and len({p["source"] for p in man["packages"]}) == 1, man)
def mut(**kw):
    m = copy.deepcopy(man); m.update(kw); return m
check("OWNER-3 a manifest whose image is not the runner's digest is a problem", L.fixture_manifest_problems(mut(image="docker.io/library/debian@sha256:" + "0" * 64), run_text) != [])
check("OWNER-3 a manifest with one package is a problem", L.fixture_manifest_problems(mut(packages=man["packages"][:1]), run_text) != [])
check("OWNER-3 a manifest with two packages of two sources is a problem (a CVE of one source need not reach the other)",
      L.fixture_manifest_problems(mut(packages=[man["packages"][0], dict(man["packages"][1], source="other")]), run_text) != [])
check("OWNER-3 a manifest with the same package twice is a problem", L.fixture_manifest_problems(mut(packages=[man["packages"][0], man["packages"][0]]), run_text) != [])
check("OWNER-3 a manifest with a missing field or an extra key is a problem", L.fixture_manifest_problems(mut(packages=[dict(man["packages"][0], version=""), man["packages"][1]]), run_text) != []
      and L.fixture_manifest_problems(mut(extra=1), run_text) != [])
def stanza(name, ver, src=None, status="install ok installed"):
    return "Package: %s\nStatus: %s\nVersion: %s\n%s\n" % (name, status, ver, ("Source: %s\n" % src) if src else "")
GOOD = stanza("libc6", "2.36-9", "glibc") + "\n" + stanza("libc-bin", "2.36-9", "glibc") + "\n" + stanza("zlib1g", "1:1.2.13.dfsg-1", "zlib")
check("the real-shaped package list satisfies the manifest", L.fixture_image_problems(GOOD, man) == [], L.fixture_image_problems(GOOD, man))
for why, text in [("libc-bin missing", stanza("libc6", "2.36-9", "glibc")), ("libc6 at another version", stanza("libc6", "2.36-10", "glibc") + "\n" + stanza("libc-bin", "2.36-9", "glibc")),
                  ("libc-bin built from another source", stanza("libc6", "2.36-9", "glibc") + "\n" + stanza("libc-bin", "2.36-9", "other")),
                  ("libc-bin removed but not purged", stanza("libc6", "2.36-9", "glibc") + "\n" + stanza("libc-bin", "2.36-9", "glibc", "deinstall ok config-files")), ("an empty list", "")]:
    check("OWNER-3 an image that loses the property is refused: %s" % why, L.fixture_image_problems(text, man) != [])
check("a Source field with its version in brackets still names the source", L.fixture_image_problems(stanza("libc6", "2.36-9", "glibc (2.36-9)") + "\n" + stanza("libc-bin", "2.36-9", "glibc (2.36-9)"), man) == [])
# Codex #420 r1 (both seats): platform bound to the export, source version checked, one assignment of the image, exclusive inputs, errors reported, the manifest in the gate
check("OWNER-3 a manifest platform other than the one the runner exports is a problem", L.fixture_manifest_problems(mut(platform="linux/arm64"), run_text) != []
      and L.fixture_manifest_problems(mut(platform=None), run_text) != [])
check("OWNER-3 a second assignment of FIXTURE_SRC in the runner is a problem", L.fixture_manifest_problems(man, run_text + "\nFIXTURE_SRC=docker.io/library/debian@sha256:" + "1" * 64 + "\n") != [])
check("OWNER-3 an export of another platform than the manifest's is a problem", L.fixture_manifest_problems(man, run_text.replace("--platform linux/amd64", "--platform linux/arm64")) != [])
check("OWNER-3 a source version that differs from the manifest's is refused (glibc (9.9))",
      L.fixture_image_problems(stanza("libc6", "2.36-9", "glibc (9.9)") + "\n" + stanza("libc-bin", "2.36-9", "glibc (2.36-9)"), man) != [])
check("OWNER-3 a manifest without a source_version for a package is a problem", L.fixture_manifest_problems(mut(packages=[{k: v for k, v in man["packages"][0].items() if k != "source_version"}, man["packages"][1]]), run_text) != [])
import io, contextlib, tarfile
with tempfile.TemporaryDirectory() as _t:
    def cli(*args):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                rc = L.main(["fixture-check", "--manifest", man_path, "--run", os.path.join(root, "bin/vex-live-run.sh")] + list(args))
            except SystemExit as e:
                rc = e.code
        return rc, err.getvalue()
    good_status = os.path.join(_t, "status"); open(good_status, "w").write(GOOD)
    def mktar(name, content):
        with tarfile.open(os.path.join(_t, name), "w") as tf:
            if content is not None:
                ti = tarfile.TarInfo("var/lib/dpkg/status"); data = content.encode(); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
        return os.path.join(_t, name)
    check("fixture-check passes on a good package list given as a file and as a tar", cli("--dpkg-status", good_status)[0] == 0 and cli("--image-tar", mktar("good.tar", GOOD))[0] == 0)
    check("OWNER-3 fixture-check refuses both inputs at once (one could silently stand in for the other)", cli("--dpkg-status", good_status, "--image-tar", os.path.join(_t, "missing.tar"))[0] not in (0, None))
    rc, err = cli("--image-tar", mktar("empty.tar", None))
    check("OWNER-3 a tar without the package list is refused with a message", rc == 1 and "::error::" in err, (rc, err))
    rc, err = cli("--dpkg-status", os.path.join(_t, "nope"))
    check("OWNER-3 a missing input is refused with a message, not a crash", rc == 1 and "::error::cannot read" in err, (rc, err))
    link = os.path.join(_t, "link.tar")
    with tarfile.open(link, "w") as tf:
        ti = tarfile.TarInfo("var/lib/dpkg/status"); ti.type = tarfile.SYMTYPE; ti.linkname = "/etc/passwd"; tf.addfile(ti)
    rc, err = cli("--image-tar", link)
    check("OWNER-3 a package list that is a link in the image is refused", rc == 1 and "::error::" in err, (rc, err))
    # the main-push gate runs the live test when only the fixture manifest changed
    gate_re = re.search(r"grep -qE '([^']+)'", gstep).group(1)
    check("OWNER-3 the change gate matches the fixture manifest", re.search(gate_re, "docs/using-our-vex.live-fixture.json") is not None, gate_re)
# the runner does this check on the real image, before any push (static: the order of the lines)
i_chk, i_push = run_text.find("fixture-check"), run_text.find('push_copy "$FIXTURE_SRC"')
check("the runner exports the fixture and runs fixture-check on its package list before it pushes the fixture", 0 < i_chk < i_push and "--image-tar" in run_text, (i_chk, i_push))
# --- PR-C: the Docker Scout leg (scanner-panel rule 12; REQ-REL-010-AC6; advisor, Oct 16). Part A, the python helpers.
real_vex = json.load(open(os.path.join(root, ".vex/fosterstack-cache.openvex.json")))
DHREPO = "docker.io/fosterstack-live/cache-live-test"
sv = L.scout_vex(real_vex, images, FIX, "CVE-2023-9999", DHREPO)
sadded = [s for s in sv["statements"] if s not in real_vex["statements"]]
check("scout-vex: the shipped statements unchanged plus one not_affected statement for the fixture in the Docker Hub test repository",
      sv["statements"][:len(real_vex["statements"])] == real_vex["statements"] and len(sadded) == 1 and sadded[0]["status"] == "not_affected"
      and sadded[0]["vulnerability"]["name"] == "CVE-2023-9999"
      and sadded[0]["products"] == [{"@id": "pkg:oci/cache@%s?repository_url=%s" % (FIX, DHREPO)}], sadded)
check("scout-vex: the document keeps our author (Scout applies only statements of an author the scan names)", sv["author"] == real_vex["author"])
check("scout author pattern: the anchored, escaped author of the shipped file",
      L.scout_author_pattern(real_vex) == "^FosterStack LLC$", L.scout_author_pattern(real_vex))
check("scout author pattern: regex characters of the author are escaped",
      L.scout_author_pattern({"author": "A.B (x) [y]*"}) == r"^A\.B \(x\) \[y\]\*$", L.scout_author_pattern({"author": "A.B (x) [y]*"}))
for why, doc in (("no author", {}), ("a blank author", {"author": "  "}), ("a non-string author", {"author": 5})):
    try:
        L.scout_author_pattern(doc); got = "accepted"
    except ValueError:
        got = "refused"
    check("scout author pattern refuses %s" % why, got == "refused", got)
sh_author = subprocess.run(["bash", "-c", 'author=$(jq -er .author "$0/.vex/fosterstack-cache.openvex.json"); printf "^%s\\$" "$(printf %s "$author" | sed \'s/[][\\.*^$+?(){}|/]/\\\\&/g\')"', root],
                           capture_output=True, text=True).stdout
check("scout author pattern equals the jq and sed computation",
      L.scout_author_pattern(real_vex) == sh_author, sh_author)

# wrap-index: a single-platform image pulled as an OCI layout becomes the one-child index the attestation tool needs (the pinned fixture is a single image)
import hashlib as _h
def _dg(b): return "sha256:" + _h.sha256(b).hexdigest()
def single_layout(d, arch="amd64"):
    cfg = json.dumps({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}).encode()
    layer = b"layer-bytes"
    man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                      "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": _dg(cfg), "size": len(cfg)},
                      "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": _dg(layer), "size": len(layer)}]}).encode()
    os.makedirs(os.path.join(d, "blobs", "sha256"))
    for b in (cfg, layer, man):
        open(os.path.join(d, "blobs", "sha256", _dg(b)[7:]), "wb").write(b)
    open(os.path.join(d, "oci-layout"), "w").write('{"imageLayoutVersion":"1.0.0"}')
    open(os.path.join(d, "index.json"), "w").write(json.dumps({"schemaVersion": 2, "manifests": [{
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "digest": _dg(man), "size": len(man)}]}))
    return _dg(man)
with tempfile.TemporaryDirectory() as t:
    t = os.path.realpath(t)      # the attestation tool refuses a path through a symlink (macOS /var is one)
    lay = os.path.join(t, "layout"); os.makedirs(lay); os.chmod(lay, 0o755)
    man_dg = single_layout(lay)
    dg_index = L.wrap_index(lay)
    top = json.load(open(os.path.join(lay, "index.json")))
    d_bytes = open(os.path.join(lay, "blobs", "sha256", dg_index[7:]), "rb").read()
    d_doc = json.loads(d_bytes)
    check("wrap-index: the layout's one descriptor is an OCI image index whose blob is present and hashes to its name",
          len(top["manifests"]) == 1 and top["manifests"][0]["mediaType"] == "application/vnd.oci.image.index.v1+json"
          and top["manifests"][0]["digest"] == dg_index == _dg(d_bytes) and top["manifests"][0]["size"] == len(d_bytes), top)
    check("wrap-index: the index holds the image as its one child, with the platform read from the image's own config",
          d_doc["schemaVersion"] == 2 and d_doc["mediaType"] == "application/vnd.oci.image.index.v1+json" and len(d_doc["manifests"]) == 1
          and d_doc["manifests"][0]["digest"] == man_dg and d_doc["manifests"][0]["platform"] == {"architecture": "amd64", "os": "linux"}, d_doc)
    vpath = os.path.join(t, "vex.json"); json.dump(sv, open(vpath, "w")); os.chmod(vpath, 0o644)      # the Scout leg's own document (the shipped statements plus the fixture's)
    vi_run = subprocess.run([sys.executable, os.path.join(root, "bin/vex-index.py"), "layout", "--layout", lay, "--vex", vpath], capture_output=True, text=True)
    check("wrap-index: the real attestation tool accepts the wrapped layout and makes the final index from it", vi_run.returncode == 0, vi_run.stderr[-300:])
    check("scout-vex: the attached document passes the attestation tool's own OpenVEX check (the tool is run, never loaded into this process)", vi_run.returncode == 0, vi_run.stderr[-300:])
def _already_index(lay):
    open(os.path.join(lay, "index.json"), "w").write(json.dumps({"schemaVersion": 2, "manifests": [
        {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:" + "a" * 64, "size": 5}]}))
def _two_descriptors(lay):
    open(os.path.join(lay, "index.json"), "w").write(json.dumps({"schemaVersion": 2, "manifests": [
        {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + "a" * 64, "size": 5}] * 2}))
for why, mutate in (("a layout that already holds an index", _already_index), ("a layout with two descriptors", _two_descriptors)):
    with tempfile.TemporaryDirectory() as t:
        lay = os.path.join(t, "layout"); os.makedirs(lay); single_layout(lay); mutate(lay)
        before = open(os.path.join(lay, "index.json")).read()
        try:
            L.wrap_index(lay); got = "accepted"
        except ValueError:
            got = "refused"
        check("wrap-index refuses %s and leaves the layout alone" % why, got == "refused" and open(os.path.join(lay, "index.json")).read() == before, got)

# the Docker Hub test repository is swept through the Hub API: fixed host, bearer token from the login, no redirect, every tag deleted and proven gone
# --- the Docker Hub test repository is swept through the REGISTRY API (advisor, Oct 17: the push token is an organization access token, which the Hub's own API refuses;
#     its "Image Delete" scope is the registry endpoints'): the token service at auth.docker.io, tags/list and DELETE manifests/<digest> at registry-1.docker.io; the user and
#     the token travel only as the token service's Basic credentials
import base64, hashlib, urllib.parse
REPO_ = "fosterstack-live/cache-live-test"
REGB = "https://registry-1.docker.io/v2/" + REPO_
def dig(name): return "sha256:" + hashlib.sha256(name.encode()).hexdigest()
class RegResp(FakeResp):
    def __init__(self, body=b"", headers=None, status=200):
        super().__init__(body); self.headers, self.status = headers or {}, status
    def getcode(self): return self.status
class RegFake:
    def __init__(self, tags, same=(), fail_auth=False, refuse_delete=False, fail_delete=(), keep=(), page=2, listing=None, link=None, digest_header="ok", name=REPO_, delete_status=202):
        self.tags = {t: dig(same[0] if t in same else t) for t in tags}     # tags named in `same` share one digest
        self.calls, self.fail_auth, self.refuse_delete, self.fail_delete, self.keep, self.page = [], fail_auth, refuse_delete, set(fail_delete), set(keep), page
        self.listing, self.link, self.digest_header, self.name, self.delete_status = listing, link, digest_header, name, delete_status
    def __call__(self, req, timeout=None):
        m, u, a = req.get_method(), req.full_url, req.get_header("Authorization")
        self.calls.append((m, u, a, req.get_header("Accept")))
        if u.startswith("https://auth.docker.io/token?"):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)
            assert m == "GET" and q == {"service": ["registry.docker.io"], "scope": ["repository:%s:pull,push,delete" % REPO_]}, (m, u)
            if self.fail_auth or a != "Basic " + base64.b64encode(b"test-user:push-tok").decode(): raise urllib.error.HTTPError(u, 401, "no", {}, io.BytesIO(b""))
            return RegResp(b'{"token": "reg-1", "access_token": "reg-1"}')
        if a != "Bearer reg-1": raise urllib.error.HTTPError(u, 401, "no bearer", {}, io.BytesIO(b""))
        path = urllib.parse.urlsplit(u).path
        if m == "GET" and path == "/v2/%s/tags/list" % REPO_:
            if self.listing is not None:
                return RegResp(json.dumps(self.listing).encode(), {"Link": self.link} if self.link else {})
            names = sorted(self.tags)
            last = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query).get("last", [""])[0]
            rest = [n for n in names if n > last]
            chunk, more = rest[:self.page], len(rest) > self.page
            hdr = {"Link": '</v2/%s/tags/list?n=%d&last=%s>; rel="next"' % (REPO_, self.page, chunk[-1])} if more else {}
            return RegResp(json.dumps({"name": self.name, "tags": chunk or None}).encode(), hdr)
        if m == "HEAD" and path.startswith("/v2/%s/manifests/" % REPO_):
            t = path.rsplit("/", 1)[1]
            if t not in self.tags: raise urllib.error.HTTPError(u, 404, "no", {}, io.BytesIO(b""))
            d = {"ok": self.tags[t], "short": "sha256:abc", "path": "sha256:" + "0" * 63 + "/../x", "none": None}[self.digest_header]
            return RegResp(b"", {"Docker-Content-Digest": d} if d else {})
        if m == "DELETE" and path.startswith("/v2/%s/manifests/" % REPO_):
            d = path.rsplit("/", 1)[1]
            if self.refuse_delete: raise urllib.error.HTTPError(u, 403, "denied", {}, io.BytesIO(b""))
            if d in self.fail_delete: raise urllib.error.HTTPError(u, 500, "boom", {}, io.BytesIO(b""))
            self.tags = {t: x for t, x in self.tags.items() if x != d or t in self.keep}
            return RegResp(b"", {}, self.delete_status)
        raise urllib.error.HTTPError(u, 404, "unexpected %s %s" % (m, u), {}, io.BytesIO(b""))
def sweep_with(h): return L.hub_sweep(REPO_, "test-user", "push-tok", h)
reg = RegFake(["a", "b", "c", "d", "e"], same=("a", "b"))
sweep_with(reg)
dels = [c[1] for c in reg.calls if c[0] == "DELETE"]
check("registry sweep: one token request, the tag list read page by page, one DELETE of each distinct digest, the list read again and found empty",
      sum(1 for c in reg.calls if c[1].startswith("https://auth.docker.io/")) == 1 and sorted(dels) == sorted(REGB + "/manifests/" + d for d in {dig("a"), dig("c"), dig("d"), dig("e")})
      and reg.tags == {} and sum(1 for c in reg.calls if c[0] == "GET" and "/tags/list" in c[1]) >= 4, [(c[0], c[1][-40:]) for c in reg.calls])
check("registry sweep: only the token service and the registry are called, every call after the token request carries the bearer token and the manifest requests name the manifest types",
      all(urllib.parse.urlsplit(c[1]).hostname in ("auth.docker.io", "registry-1.docker.io") for c in reg.calls)
      and all(c[2] == "Bearer reg-1" for c in reg.calls if not c[1].startswith("https://auth.docker.io/"))
      and all("image.index" in (c[3] or "") and "manifest.v2" in (c[3] or "") for c in reg.calls if c[0] == "HEAD"), [(c[0], c[1][-40:]) for c in reg.calls][:6])
for why, h, needle in (("a refused token request", RegFake(["a"], fail_auth=True), "token"), ("a refused delete", RegFake(["a"], refuse_delete=True), "refused the registry delete"),
                       ("a failed delete", RegFake(["a", "b"], fail_delete=[dig("a")]), "delete"), ("a delete answered 200 instead of 202", RegFake(["a"], delete_status=200), "not 202"), ("a tag that is still there", RegFake(["a"], keep=["a"]), "left")):
    try:
        sweep_with(h); got, msg = "returned", ""
    except (urllib.error.HTTPError, RuntimeError, ValueError) as e:
        got, msg = "raised", str(e)
    check("registry sweep fails on %s, with a message that names it and holds neither token" % why, got == "raised" and needle in msg and "push-tok" not in msg and "reg-1" not in msg, (got, msg))
h2 = RegFake(["a", "b", "c"], fail_delete=[dig("a")])
try: sweep_with(h2)
except Exception: pass
check("registry sweep: the other tags were deleted although one delete failed", sorted(h2.tags) == ["a"], h2.tags)
for why, repo, user, tok in (("another registry path", "a/b/c", "u", "t"), ("a dot-dot", "../x", "u", "t"), ("an upper-case name", "Foo/bar", "u", "t"), ("no slash", "cache", "u", "t"),
                             ("a docker.io prefix", "docker.io/ns/name", "u", "t"), ("no user", "ns/name", "", "t"), ("no token", "ns/name", "u", ""), ("a user with a space", "ns/name", "u v", "t")):
    try:
        L.hub_sweep(repo, user, tok, RegFake([])); got = "accepted"
    except ValueError:
        got = "refused"
    check("registry sweep refuses %s" % why, got == "refused", got)

# scout-delta: the informational probe of the Build layout (never a verdict)
def gl(*ids): return {"vulnerabilities": [{"identifiers": [{"value": i}], "location": {"dependency": {"package": {"name": "p"}, "version": "1"}}} for i in ids]}
with tempfile.TemporaryDirectory() as t:
    bp, ap = os.path.join(t, "b.json"), os.path.join(t, "a.json")
    json.dump(gl("CVE-1", "CVE-2", "CVE-3"), open(bp, "w")); json.dump(gl("CVE-2", "CVE-3"), open(ap, "w"))
    r = subprocess.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "scout-delta", "--before", bp, "--after", ap], capture_output=True, text=True)
    check("scout-delta: the notice says how many findings each scan reported and which our statements dropped",
          r.returncode == 0 and "3" in r.stdout and "2" in r.stdout and "CVE-1" in r.stdout and "::notice::" in r.stdout, (r.returncode, r.stdout, r.stderr))
    json.dump(gl("CVE-1"), open(ap, "w"))
    r = subprocess.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "scout-delta", "--before", bp, "--after", os.path.join(t, "missing.json")], capture_output=True, text=True)
    check("scout-delta: an unreadable report is a notice, never a failure (information only)", r.returncode == 0 and "::notice::" in r.stdout, (r.returncode, r.stdout, r.stderr))

# scout-pick: which of OUR statements' CVEs does Scout report on the production image (the AC6 target); none is an answer, not an error
with tempfile.TemporaryDirectory() as t:
    bp, vp = os.path.join(t, "b.json"), os.path.join(t, "v.json")
    json.dump(gl("CVE-1", "CVE-2", "CVE-3"), open(bp, "w"))
    json.dump({"statements": [{"vulnerability": {"name": n}} for n in ("CVE-9", "CVE-3", "CVE-2")]}, open(vp, "w"))
    r = subprocess.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "scout-pick", "--before", bp, "--openvex", vp], capture_output=True, text=True)
    check("scout-pick: the first CVE (in order) that Scout reports and one of our statements covers", r.returncode == 0 and r.stdout.strip() == "CVE-2", (r.returncode, r.stdout, r.stderr))
    json.dump({"statements": [{"vulnerability": {"name": "CVE-9"}}]}, open(vp, "w"))
    r = subprocess.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "scout-pick", "--before", bp, "--openvex", vp], capture_output=True, text=True)
    check("scout-pick: none of ours reported is an empty answer", r.returncode == 0 and r.stdout.strip() == "", (r.returncode, r.stdout, r.stderr))
    open(bp, "w").write("not json")
    r = subprocess.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "scout-pick", "--before", bp, "--openvex", vp], capture_output=True, text=True)
    check("scout-pick: an unreadable report is an error, never 'none'", r.returncode != 0, (r.returncode, r.stdout))

# --- PR-C part D: the Scout leg's wiring. The Docker Hub test repository is a variable, its user and tokens are secrets of the live-test environment, handed to the steps that need
#     them as environment variables only; the leg's tool (Docker Scout CLI) is installed pinned by checksum like the rescan's
SCOUT_RUN_ENV = {"DH_REPO": "${{ vars.LIVE_TEST_DOCKERHUB_REPOSITORY }}", "DOCKERHUB_USERNAME": "${{ secrets.DOCKERHUB_USERNAME }}",
                 "DOCKERHUB_TEST_USERNAME": "${{ secrets.DOCKERHUB_TEST_USERNAME }}", "DOCKERHUB_TEST_PUSH_TOKEN": "${{ secrets.DOCKERHUB_TEST_PUSH_TOKEN }}", "DOCKERHUB_SCOUT_TOKEN": "${{ secrets.DOCKERHUB_SCOUT_TOKEN }}"}
SCOUT_CLEAN_ENV = {k: SCOUT_RUN_ENV[k] for k in ("DH_REPO", "DOCKERHUB_TEST_USERNAME", "DOCKERHUB_TEST_PUSH_TOKEN")}
for name, job in (("release.yml rc job", RJ), ("release.yml post-publish job", PJ), ("ci.yml", cj)):
    steps = job.get("steps") or []
    run_step = [s for s in steps if "bin/vex-live-run.sh run" in (s.get("run") or "")]
    clean_step = [s for s in steps if "bin/vex-live-run.sh cleanup" in (s.get("run") or "")]
    check("%s: the live-test step carries the Docker Hub repository and the three Docker Hub secrets as environment variables" % name,
          len(run_step) == 1 and all((run_step[0].get("env") or {}).get(k) == v for k, v in SCOUT_RUN_ENV.items()), run_step and run_step[0].get("env"))
    check("%s: the cleanup step carries the repository, the test user and the push token (not the Scout read token or the Scout user)" % name,
          len(clean_step) == 1 and all((clean_step[0].get("env") or {}).get(k) == v for k, v in SCOUT_CLEAN_ENV.items())
          and not {"DOCKERHUB_SCOUT_TOKEN", "DOCKERHUB_USERNAME"} & set(clean_step[0].get("env") or {}), clean_step and clean_step[0].get("env"))
    users = [s.get("name") for s in steps if re.search(r"secrets\.DOCKERHUB", json.dumps(s))]
    check("%s: the Docker Hub secrets appear in those two steps only, never in a command line" % name,
          sorted(users) == sorted(s.get("name") for s in run_step + clean_step) and not any("secrets." in (s.get("run") or "") for s in steps), users)
    inst = [s for s in steps if "docker-scout" in (s.get("run") or "") and "install-scanner" in (s.get("run") or "")]
    check("%s: Docker Scout is installed pinned by checksum, before the live-test step" % name,
          len(inst) == 1 and 'install -m 0755 "$RUNNER_TEMP/docker-scout" "$HOME/.docker/cli-plugins/docker-scout"' in inst[0]["run"]
          and steps.index(inst[0]) < steps.index(run_step[0]), [s.get("name") for s in inst])
    check("%s: no secrets: inherit and no secret outside the live-test steps" % name, "inherit" not in json.dumps(job) and "secrets." not in json.dumps([s for s in steps if s not in run_step + clean_step]))

# --- Codex #416 r1: the page's blocks run without the Docker Hub secrets; Docker Hub auth goes in private config files, never on a command line; strict reports; the Hub
#     path boundary and schema
SECRETS_ENV = dict(DOCKERHUB_USERNAME="hubuser-secret", DOCKERHUB_TEST_USERNAME="hubtest-user", DOCKERHUB_TEST_PUSH_TOKEN="push-tok", DOCKERHUB_SCOUT_TOKEN="scout-tok", DH_REPO="ns/name")
for section in ("verify", "scout"):
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "plan"))
        open(os.path.join(t, "plan", "00-%s.sh" % section), "w").write('env | grep -E "^(DOCKERHUB|DH_REPO)" | sort || echo NONE\n')
        open(os.path.join(t, "plan.txt"), "w").write("00-%s.sh\n" % section)
        open(os.path.join(t, "state.env"), "w").write("VER='0.3.0'\nIMAGE='x/y/cache'\n")
        r = subprocess.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "guide", "--plan", "plan.txt", "--state", "state.env", section], cwd=t,
                           env=dict(os.environ, **SECRETS_ENV), capture_output=True, text=True)
        seen = [l for l in r.stdout.split("\n") if re.match(r"(DOCKERHUB|DH_REPO)", l)]
        check("guide child (%s): none of the Docker Hub secrets or the test repository reach the page's commands" % section, r.returncode == 0 and seen == [], (r.returncode, seen, r.stderr[-200:]))

# the Hub path boundary and schema (Codex #416 r1)
LST = lambda tags, name=REPO_: {"name": name, "tags": tags}
for why, kw in (("a Link to another host", {"listing": LST(["a"]), "link": '<https://evil.example/v2/%s/tags/list?n=1&last=a>; rel="next"' % REPO_}),
                ("a Link that climbs out of the repository with dot-dot", {"listing": LST(["a"]), "link": '</v2/%s/tags/../../other/tags/list?n=1&last=a>; rel="next"' % REPO_}),
                ("a Link to another repository's tags", {"listing": LST(["a"]), "link": '</v2/other/repo/tags/list?n=1&last=a>; rel="next"'}),
                ("a Link with a query key of its own", {"listing": LST(["a"]), "link": '</v2/%s/tags/list?n=1&last=a&x=1>; rel="next"' % REPO_}),
                ("a Link with a fragment", {"listing": LST(["a"]), "link": '</v2/%s/tags/list?n=1&last=a#x>; rel="next"' % REPO_}),
                ("a Link with a user part", {"listing": LST(["a"]), "link": '<https://registry-1.docker.io@evil.example/v2/%s/tags/list?n=1&last=a>; rel="next"' % REPO_}),
                ("a Link that points back at the same page", {"listing": LST(["a"]), "link": '</v2/%s/tags/list?n=100>; rel="next"' % REPO_}),
                ("a tag name with a slash", {"listing": LST(["../../other/tags/victim"])}), ("a tag name that is dot-dot", {"listing": LST([".."])}),
                ("a tag name with a question mark", {"listing": LST(["a?b"])}), ("a tag list that is an object", {"listing": LST({})}),
                ("a tag that is not a string", {"listing": LST([5])}), ("the list of another repository", {"listing": LST(["a"], "other/repo")}),
                ("a manifest answer without a digest", {"digest_header": "none"}), ("a short digest", {"digest_header": "short"}), ("a digest that is a path", {"digest_header": "path"})):
    h = RegFake(["a"], **kw)
    try:
        sweep_with(h); got = "returned"
    except (ValueError, RuntimeError, KeyError, TypeError):
        got = "refused"
    sent = [c[1] for c in h.calls]
    check("registry sweep refuses %s and sends no request outside the repository's own registry paths" % why,
          got == "refused" and all(urllib.parse.urlsplit(u).hostname in ("auth.docker.io", "registry-1.docker.io") and ".." not in u and "evil" not in u
                                   and (u.startswith("https://auth.docker.io/") or urllib.parse.urlsplit(u).path.startswith("/v2/%s/" % REPO_)) for u in sent)
          and not any(c[0] == "DELETE" and not re.fullmatch(r"sha256:[0-9a-f]{64}", c[1].rsplit("/", 1)[1]) for c in h.calls), (got, sent[-3:]))
hp = RegFake(["a", "b", "c", "d", "e"], page=2)
sweep_with(hp)
check("registry sweep still follows the repository's own next page (relative Link)", hp.tags == {} and any("last=" in c[1] for c in hp.calls), [c[1][-40:] for c in hp.calls])

# strict reports: an unreadable or malformed Scout report is an error everywhere it is read
with tempfile.TemporaryDirectory() as t:
    vp = os.path.join(t, "v.json"); json.dump({"statements": [{"vulnerability": {"name": "CVE-2"}}]}, open(vp, "w"))
    for why, body in (("a vulnerabilities object", '{"vulnerabilities": {}}'), ("a vulnerabilities string", '{"vulnerabilities": ""}'), ("a finding without an identifier", '{"vulnerabilities": [{"identifiers": []}]}'),
                      ("a finding without a package", '{"vulnerabilities": [{"identifiers": [{"value": "CVE-2"}]}]}')):
        bp = os.path.join(t, "b.json"); open(bp, "w").write(body)
        r = subprocess.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "scout-pick", "--before", bp, "--openvex", vp], capture_output=True, text=True)
        r2 = subprocess.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "scout-valid", "--report", bp], capture_output=True, text=True)
        check("scout-pick and scout-valid refuse %s" % why, r.returncode != 0 and r2.returncode != 0, (r.returncode, r2.returncode))
    r = subprocess.run([sys.executable, os.path.join(root, "bin/vex-live-test.py"), "scout-valid", "--report", os.path.join(t, "missing.json")], capture_output=True, text=True)
    check("scout-valid refuses a missing report", r.returncode != 0, r.returncode)

# --- PR-C part B: the shell leg, with stubs (fail closed without its repository and tokens; the fixture and the production image scanned with Docker's authors
#     only and with ours; the verdict from bin/scout-selfcheck.py; pushes journaled and counted; the Docker Hub repository swept)
ENV_OK = {"DH_REPO": "fosterstack-live/cache-live-test", "DOCKERHUB_USERNAME": "hubuser-secret", "DOCKERHUB_TEST_USERNAME": "hubtest-user", "DOCKERHUB_TEST_PUSH_TOKEN": "push-tok", "DOCKERHUB_SCOUT_TOKEN": "scout-tok"}
for missing in ENV_OK:
    env = {k: v for k, v in ENV_OK.items() if k != missing}
    rc, out = sh("for v in DH_REPO DOCKERHUB_USERNAME DOCKERHUB_TEST_USERNAME DOCKERHUB_TEST_PUSH_TOKEN DOCKERHUB_SCOUT_TOKEN; do eval \"[ -n \\\"\\${$v-}\\\" ]\" || unset $v; done; scout_preflight",
                 {"crane": "echo CALLED >> calls; exit 0", "docker": "echo CALLED >> calls; exit 0"}, dict(env, **{missing: ""}))
    check("scout preflight fails closed without %s, naming it" % missing, rc != 0 and missing in out, (rc, out[-200:]))
rc, out = sh("scout_preflight", {}, ENV_OK)
check("scout preflight passes with the repository, the user and both tokens", rc == 0, (rc, out[-200:]))
for bad in ("fosterstack-live", "a/b/c", "Foo/bar", "docker.io/ns/name", "../x"):
    rc, out = sh("scout_preflight", {}, dict(ENV_OK, DH_REPO=bad))
    check("scout preflight refuses the repository name %r" % bad, rc != 0, (rc, out[-200:]))

DOCKER_LOG = r'''printf '%s\n' "$*" >> "$RUNNER_TEMP/docker.log"
case "$*" in
  "login "*) cat >/dev/null; exit 0 ;;
  *"scout cves"*) if [[ "$*" == *--vex-author* ]]; then cat "$RUNNER_TEMP/scout-after.json"; else cat "$RUNNER_TEMP/scout-before.json"; fi ;;
  *) exit 0 ;; esac'''
def gl_report(*ids):
    return json.dumps({"vulnerabilities": [{"identifiers": [{"type": "cve", "value": i}], "location": {"dependency": {"package": {"name": "libc6"}, "version": "2.36"}}} for i in ids]})
rc, out = sh('printf %s \'' + gl_report("CVE-1", "CVE-2") + '\' > "$RUNNER_TEMP/scout-before.json"; scout_scan registry://docker.io/ns/n@sha256:%s "$RUNNER_TEMP/o.json"; cat "$RUNNER_TEMP/docker.log"; cat "$RUNNER_TEMP/o.json"' % ("a" * 64),
             {"docker": DOCKER_LOG})
check("scout_scan: Docker's own authors by default (no --vex-author), the GitLab format, the registry reference, the report in the file",
      rc == 0 and "scout cves --format gitlab registry://docker.io/ns/n@sha256:%s" % ("a" * 64) in out and "--vex-author" not in out.split("\n")[0] and "CVE-1" in out, (rc, out[-300:]))
rc, out = sh('printf %s \'' + gl_report("CVE-2") + '\' > "$RUNNER_TEMP/scout-after.json"; scout_scan registry://docker.io/ns/n@sha256:%s "$RUNNER_TEMP/o.json" \'^FosterStack LLC$\'; cat "$RUNNER_TEMP/docker.log"' % ("a" * 64),
             {"docker": DOCKER_LOG})
check("scout_scan: with our author, the anchored pattern as ONE argument", rc == 0 and "--vex-author ^FosterStack LLC$ registry://docker.io/ns/n@sha256:" in out, (rc, out[-300:]))
for ref in ("local://x", "image://x", "ghcr.io/fosterstack/cache:1", "registry://x; touch pwned", ""):
    rc, out = sh('scout_scan "$1" "$RUNNER_TEMP/o.json" 2>&1; ls "$RUNNER_TEMP/docker.log" 2>&1 | grep -c docker.log || true', {"docker": DOCKER_LOG}) if False else sh('scout_scan %s "$RUNNER_TEMP/o.json"; echo rc=$?; test ! -e "$RUNNER_TEMP/docker.log"' % json.dumps(ref), {"docker": DOCKER_LOG})
    check("scout_scan refuses the reference %r before running anything" % ref, "rc=0" not in out or rc != 0, (rc, out[-200:]))
rc, out = sh('scout_scan registry://x/y@sha256:%s "$RUNNER_TEMP/o.json"' % ("a" * 64), {"docker": "exit 3"})
check("scout_scan fails when docker scout fails", rc != 0, (rc, out[-200:]))

# the informational probe of the Build layout: never fails, says what Scout did
rc, out = sh('printf %s \'' + gl_report("CVE-1", "CVE-2") + '\' > "$RUNNER_TEMP/scout-before.json"; printf %s \'' + gl_report("CVE-2") + '\' > "$RUNNER_TEMP/scout-after.json"; '
             'scout_probe "$RUNNER_TEMP/layout" \'^FosterStack LLC$\'', {"docker": DOCKER_LOG})
check("scout_probe: scans the Build layout (oci-dir://) with Docker's authors and with ours, and prints the delta", rc == 0 and "::notice::" in out and "CVE-1" in out
      and "oci-dir://" in open(os.path.join(root, "bin/vex-live-run.sh")).read(), (rc, out[-300:]))
rc, out = sh('scout_probe "$RUNNER_TEMP/layout" \'^FosterStack LLC$\'; echo rc=$?', {"docker": "exit 9"})
check("scout_probe: a failing Scout is information, never a failure of the run", rc == 0 and "rc=0" in out, (rc, out[-300:]))

# the sweep of the Docker Hub repository joins the sweep only when the repository is configured
rc, out = sh("hub_sweep() { echo HUB-SWEPT; }; sweep_dockerhub", {}, {})
check("sweep_dockerhub: without a configured repository it does nothing", rc == 0 and "HUB-SWEPT" not in out, (rc, out[-200:]))
rc, out = sh("hub_sweep() { echo HUB-SWEPT; }; sweep_dockerhub", {}, ENV_OK)
check("sweep_dockerhub: with the repository it sweeps it", rc == 0 and "HUB-SWEPT" in out, (rc, out[-200:]))
rc, out = sh("hub_sweep() { return 7; }; sweep_dockerhub", {}, ENV_OK)
check("sweep_dockerhub: a failing sweep fails", rc != 0, (rc, out[-200:]))
rc, out = sh("hub_sweep() { return 7; }; sweep_ecr() { :; }; sweep_gar() { :; }; sweep_filters() { :; }; sweep_notes() { :; }; sweep", {}, ENV_OK)
check("sweep: a failing Docker Hub sweep fails the sweep (the other families still ran)", rc != 0, (rc, out[-200:]))
rc, out = sh("hub_sweep() { echo HUB-SWEPT; }; sweep_ecr() { :; }; sweep_gar() { :; }; sweep_filters() { :; }; sweep_notes() { :; }; sweep", {}, ENV_OK)
check("sweep: the Docker Hub sweep is part of the sweep when configured", rc == 0 and "HUB-SWEPT" in out, (rc, out[-200:]))
check("hub_sweep calls the helper with the repository only (the user and the token travel in the environment, never on a command line)",
      'vex-live-test.py" hub-sweep --repository "$DH_REPO"' in open(os.path.join(root, "bin/vex-live-run.sh")).read())
# Codex-free round 1 (Opus seat A, Sonnet seat B): the CLI itself pairs the TEST user with the push token, whatever the Scout user is in the same environment
_swept, _real = [], L.hub_sweep
L.hub_sweep = lambda repo, user, tok, opener=None: _swept.append((repo, user, tok))
_saved = {k: os.environ.get(k) for k in ("DOCKERHUB_USERNAME", "DOCKERHUB_TEST_USERNAME", "DOCKERHUB_TEST_PUSH_TOKEN", "DOCKERHUB_SCOUT_TOKEN")}
os.environ.update(DOCKERHUB_USERNAME="scout-user-sentinel", DOCKERHUB_TEST_USERNAME="test-user-sentinel", DOCKERHUB_TEST_PUSH_TOKEN="push-sentinel", DOCKERHUB_SCOUT_TOKEN="scout-sentinel")
try:
    _rc = L.main(["hub-sweep", "--repository", "ns/name"])
finally:
    L.hub_sweep = _real
    for k, v in _saved.items():
        os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
check("hub-sweep (the command): logs in as DOCKERHUB_TEST_USERNAME with DOCKERHUB_TEST_PUSH_TOKEN, never the Scout user or token", _rc == 0 and _swept == [("ns/name", "test-user-sentinel", "push-sentinel")], (_rc, _swept))

# --- PR-C part C: the whole leg against stubs. A real attestation tool runs on a fixture layout the stub crane "pulls"; Scout is a stub that answers from canned reports in call
#     order (fixture before/after, production before/after, then the published tag and digest in the post-publish modes)
import shutil
FX_DIGEST_STALE = "6" * 64
LEG_CVE, OURS_CVE = "CVE-2023-9999", sorted(s["vulnerability"]["name"] for s in real_vex["statements"])[0]
with tempfile.TemporaryDirectory() as lt:
    lt = os.path.realpath(lt)
    fx_src, cand = os.path.join(lt, "fixture-src"), os.path.join(lt, "cand", "images", "production")
    os.makedirs(fx_src); fx_man = single_layout(fx_src)
    os.makedirs(cand); prod_man = single_layout(cand, "arm64")
    for d_ in (fx_src, cand):
        for base_, dirs_, files_ in os.walk(d_):
            os.chmod(base_, 0o755)
            for f_ in files_: os.chmod(os.path.join(base_, f_), 0o644)
    CRANE = r'''echo "$*" >> "$RUNNER_TEMP/crane.log"; echo "crane $*" >> "$RUNNER_TEMP/events.log"
case "$1" in
  auth) case "$2" in login) [ "$(cat)" = push-tok ] && echo "PUSH-LOGIN-OK" >> "$RUNNER_TEMP/events.log" || echo "BAD-PUSH-LOGIN" >> "$RUNNER_TEMP/events.log" ;; logout) echo "PUSH-LOGOUT" >> "$RUNNER_TEMP/events.log" ;; esac ;;
  pull) dir="${@: -1}"; cp -R "$FIXTURE_LAYOUT_SRC" "$dir"; chmod -R go-w "$dir" ;;
  push) d=$(jq -r '.manifests[0].digest' "$2/index.json"); echo "$3 $d" >> "$RUNNER_TEMP/pushed.map" ;;
  copy) echo "$3 ${2##*@}" >> "$RUNNER_TEMP/pushed.map" ;;
  digest) if [ -n "${CRANE_DIGEST_OVERRIDE:-}" ]; then echo "$CRANE_DIGEST_OVERRIDE"; else grep "^$2 " "$RUNNER_TEMP/pushed.map" | tail -1 | cut -d' ' -f2; fi ;;
esac'''
    SCOUT = r'''printf '%s\n' "$*" >> "$RUNNER_TEMP/docker.log"; echo "docker $*" >> "$RUNNER_TEMP/events.log"
case "$*" in
  "login "*) [ "$(cat)" = scout-tok ] && echo "SCOUT-LOGIN-OK" >> "$RUNNER_TEMP/events.log" || echo "BAD-SCOUT-LOGIN" >> "$RUNNER_TEMP/events.log"; exit 0 ;;
  "logout "*) echo "SCOUT-LOGOUT" >> "$RUNNER_TEMP/events.log" ;;
  *"scout cves"*) echo "SCAN-ENV push-env=${DOCKERHUB_TEST_PUSH_TOKEN:+set}" >> "$RUNNER_TEMP/events.log"; n=$(grep -c "scout cves" "$RUNNER_TEMP/docker.log"); cat "$RUNNER_TEMP/scout-$n.json" ;;
  *) exit 0 ;; esac'''
    def leg(reports, env=None, mode="rc", extra=""):
        files = "".join("printf %%s '%s' > \"$RUNNER_TEMP/scout-%d.json\"; " % (r, i + 1) for i, r in enumerate(reports))
        body = (files + 'export PUSHED_LOG="$RUNNER_TEMP/p"; : > "$PUSHED_LOG"; MODE=%s; tag=v0.3.0-rc1; ' % mode
                + 'FIXTURE_SRC=docker.io/library/debian@%s; FIX=%s; RUN=live-1-1; CVE=%s; ' % (fx_man, fx_man, LEG_CVE)
                + "echo '{\"production\": {\"index\": \"%s\", \"children\": {\"linux/amd64\": \"sha256:%s\", \"linux/arm64\": \"sha256:%s\"}}}' > images.json; " % (prod_man, "2" * 64, "3" * 64)
                + extra + "scout_leg && echo leg-rc=0 || echo leg-rc=$?; echo \"push-tok-after=${DOCKERHUB_TEST_PUSH_TOKEN-UNSET} scout-tok-after=${DOCKERHUB_SCOUT_TOKEN-UNSET}\"; cat \"$RUNNER_TEMP/crane.log\" \"$RUNNER_TEMP/docker.log\" \"$PUSHED_LOG\" \"$RUNNER_TEMP/guide.log\" 2>/dev/null || true; echo =EVENTS=; cat \"$RUNNER_TEMP/events.log\"")
        e = dict(ENV_OK, FIXTURE_LAYOUT_SRC=fx_src, CANDIDATE_DIR=os.path.join(lt, "cand"))
        e.update(env or {})
        return sh(body, {"crane": CRANE, "docker": SCOUT}, e)
    OK_FIX = [gl_report(LEG_CVE, "CVE-A", OURS_CVE), gl_report("CVE-A", OURS_CVE)]
    OK_PROD = [gl_report("CVE-B", OURS_CVE), gl_report("CVE-B")]
    rc, out = leg(["{}", "{}"] + OK_FIX + OK_PROD)    # the first two answers belong to the informational probe of the Build layout (an unreadable report there is information)
    sc = [l for l in out.split("\n") if l.startswith("scout cves")]
    check("scout leg (rc): passes when the fixture's finding shows with Docker's authors only and is gone with ours, and the same for our production image", "leg-rc=0" in out, (rc, out[-500:]))
    check("scout leg (rc): the Build layout is probed first (oci-dir://, information), then the Docker Hub test repository by digest",
          sc and sc[0].startswith("scout cves --format gitlab oci-dir://") and any("registry://docker.io/fosterstack-live/cache-live-test@sha256:" in l for l in sc[2:]), sc)
    check("scout leg (rc): each registry image is scanned twice, first with Docker's authors, then naming ours as one argument",
          [("--vex-author ^FosterStack LLC$ " in l) for l in sc[2:]] == [False, True, False, True], sc)
    ev = out.split("=EVENTS=\n", 1)[1].split("\n") if "=EVENTS=" in out else []
    def cat_of(l):
        if "PUSH-LOGIN-OK" in l: return 1
        if l.startswith("crane push") or l.startswith("crane copy"): return 2
        if "PUSH-LOGOUT" in l: return 3
        if "SCOUT-LOGIN-OK" in l: return 4
        if l.startswith("docker scout cves"): return 5
        if "SCOUT-LOGOUT" in l: return 6
        return 0
    cats = [c for c in map(cat_of, ev) if c]
    check("scout leg (rc): the push token is on the machine only for the pushes (login, pushes, logout), then the Scout token only for the scans (login, scans, logout); neither is ever on a command line",
          cats == sorted(cats) and {1, 2, 3, 4, 5, 6} <= set(cats) and "BAD-" not in out and "push-tok" not in "\n".join(ev) and "scout-tok" not in "\n".join(ev), (cats, out[-500:]))
    check("scout leg (rc): the user names are the only secret-backed values on a command line (public Docker Hub account names): the push login uses the test user, the Scout login the Scout user",
          all("hubtest-user" in l and "hubuser-secret" not in l for l in ev if "auth login" in l)
          and all("hubuser-secret" in l and "hubtest-user" not in l for l in ev if l.startswith("docker login"))
          and not any("hubuser-secret" in l or "hubtest-user" in l for l in ev if "scout cves" in l or " push " in l or " copy " in l))
    check("scout leg (rc): the push token is gone from the environment once it is logged out (a Scout scan or the page's Scout block never sees it)",
          "SCAN-ENV push-env=\n" in out and "SCAN-ENV push-env=set" not in out, out[-300:])
    for why, call in (("copy_candidate", 'copy_candidate "$RUNNER_TEMP/layout" dst/cache:x sha256:%s' % ("a" * 64)), ("push_copy", "push_copy a b")):
        rc, out2 = sh('export PUSHED_LOG=/dev/null/not-a-directory; { %s && echo rc=0; } || echo rc=1; echo crane-calls=$(cat "$RUNNER_TEMP/crane.log" 2>/dev/null | wc -l)' % call,
                      {"crane": 'echo "$*" >> "$RUNNER_TEMP/crane.log"; case "$1" in digest) echo sha256:%s ;; esac' % ("a" * 64)})
        check("%s: a journal that cannot be written stops the push before crane runs (a push nobody journaled would escape the sweep's record)" % why,
              "rc=1" in out2 and "crane-calls=0" in out2.replace(" ", ""), (rc, out2[-200:]))
    rc, out2 = leg(["{}", "{}"] + OK_FIX + OK_PROD, extra='export PUSHED_LOG=/dev/null/not-a-directory; ')
    check("scout leg (rc): an unwritable journal fails the leg with no crane push or copy", "leg-rc=0" not in out2 and "crane push" not in out2 and "crane copy" not in out2, out2[-300:])
    for why, reports, env in (("the fixture's finding still shown with our author", [OK_FIX[0], OK_FIX[0]] + OK_PROD, {}),
                              ("the fixture's finding not shown without our author", [gl_report("CVE-A"), gl_report("CVE-A")] + OK_PROD, {}),
                              ("another fixture finding lost with our author", [OK_FIX[0], gl_report(OURS_CVE)] + OK_PROD, {}),
                              ("our production image keeping the finding our statement covers", OK_FIX + [gl_report("CVE-B", OURS_CVE), gl_report("CVE-B", OURS_CVE)], {}),
                              ("a candidate that comes out of the registry at another digest", OK_FIX + OK_PROD, {"CRANE_DIGEST_OVERRIDE": "sha256:" + "0" * 64}),
                              ("an unreadable report for the fixture", ["{}", "{}", "not json", "not json"] + OK_PROD, {})):
        rc, out = leg(["{}", "{}"] + reports, env)
        check("scout leg (rc) fails on %s" % why, "leg-rc=0" not in out and "leg-rc=" in out, (rc, out[-300:]))
    rc, out = leg(["{}", "{}"] + OK_FIX + [gl_report("CVE-B"), gl_report("CVE-B")])
    check("scout leg (rc): none of our statements reported by Scout on the production image is a warning that AC6 is not shown, not a failure",
          "leg-rc=0" in out and "::warning::" in out and "REQ-REL-010-AC6" in out, (rc, out[-400:]))
    for why, reports in (("a malformed production 'before' report", OK_FIX + ['{"vulnerabilities": {}}', gl_report("CVE-B")]),
                         ("a production 'before' report that is not JSON", OK_FIX + ["not json", gl_report("CVE-B")]),
                         ("a malformed production 'after' report although no target of ours was found", OK_FIX + [gl_report("CVE-B"), '{"vulnerabilities": ""}']),
                         ("a missing production 'after' report", OK_FIX + [gl_report("CVE-B"), ""])):
        rc, out = leg(["{}", "{}"] + reports)
        check("scout leg (rc) fails on %s, never the warning path" % why, "leg-rc=0" not in out and "Docker Scout leg passed" not in out, (rc, out[-300:]))
    for missing in ENV_OK:
        rc, out = leg(["{}"], {missing: ""})
        check("scout leg fails closed without %s, before any crane or docker call" % missing, "leg-rc=0" not in out and "crane" not in out.replace("crane.log", "") and "auth login" not in out, (rc, out[-300:]))
    rc, out = leg(["{}"] * 2 + OK_FIX + OK_PROD, extra='PUSHES=49; ')
    check("scout leg: the leg's pushes count against the 50 of the run (a second push beyond 50 fails it)", "leg-rc=0" not in out and "more than 50 pushes" in out, (rc, out[-300:]))
    check("scout leg: a push that fails after the push login still logs the push token out and unsets it (it never stays in the job's Docker config)",
          "PUSH-LOGIN-OK" in out and "PUSH-LOGOUT" in out and "leg-rc=0" not in out and out.index("PUSH-LOGIN-OK") < out.index("PUSH-LOGOUT"), (rc, out[-400:]))
    check("…and the push token is gone from the environment too", "push-tok-after=UNSET" in out, (rc, out[-400:]))
    BAD_DIGEST = 'crane() { if [ "$1" = digest ] && [[ "$2" == *-production ]]; then echo sha256:' + "0" * 64 + '; else command crane "$@"; fi; }; '
    for md in ("release", "main"):
        rc, out = leg(["{}"] * 2 + OK_FIX + OK_PROD, mode=md, extra=BAD_DIGEST)
        check("scout leg (%s): a production copy that does not keep its digest fails the leg, and the push token is logged out and unset first" % md,
              "leg-rc=0" not in out and "does not keep its digest" in out and "PUSH-LOGOUT" in out and "push-tok-after=UNSET" in out, (rc, out[-400:]))
    rc, out = leg(["{}", "{}"] + OK_FIX + ['{"vulnerabilities": {}}', gl_report("CVE-B")])
    check("scout leg (rc): a failure after the Scout login logs the Scout token out and unsets it (it never stays in the job's Docker config)",
          "SCOUT-LOGIN-OK" in out and "SCOUT-LOGOUT" in out and "leg-rc=0" not in out and "scout-tok-after=UNSET" in out, (rc, out[-400:]))
    rc, out = leg(["{}", "{}"] + OK_FIX + OK_PROD)
    check("scout leg (rc): on success both tokens are also gone from the environment, with one login and one logout of each (no extra cleanup call)",
          "leg-rc=0" in out and "push-tok-after=UNSET scout-tok-after=UNSET" in out and out.count("PUSH-LOGOUT") == 1 and out.count("SCOUT-LOGOUT") == 1, (rc, out[-400:]))
    rc, out = leg(OK_FIX + OK_PROD + OK_FIX[:0] + [gl_report("CVE-B", OURS_CVE), gl_report("CVE-B"), gl_report("CVE-B", OURS_CVE), gl_report("CVE-B")], mode="release",
                  extra='tag=v0.3.0; python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" settings --state state.env "DIGEST=sha256:%s"; guide() { echo "guide $1: $(cat state.env)" >> "$RUNNER_TEMP/guide.log"; }; ' % FX_DIGEST_STALE)
    check("scout leg (release): the page's own Scout block runs as written (section scout); a release candidate never runs it", "guide scout" in out, out[-300:])
    check("scout leg (release): the page's Scout block gets OUR production digest (the Google leg leaves the fixture's in the state)", "guide scout: " in out and ("DIGEST='%s'" % prod_man) in out, out[-400:])
    rc2, out2 = leg(["{}", "{}"] + OK_FIX + OK_PROD)
    check("scout leg (rc): the page's Scout block is not run (nothing is published)", "guide scout" not in out2 and "leg-rc=0" in out2, out2[-300:])
    sc = [l for l in out.split("\n") if l.startswith("scout cves")]
    check("scout leg (release): the published index is also scanned by tag and by exact digest, with Docker's authors and with ours",
          "leg-rc=0" in out and any("registry://ghcr.io/fosterstack/cache:0.3.0" in l for l in sc) and any("registry://ghcr.io/fosterstack/cache@" + prod_man in l for l in sc)
          and not any(l.startswith("scout cves --format gitlab oci-dir://") for l in sc), (rc, sc, out[-300:]))

print("vex-live-test: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
