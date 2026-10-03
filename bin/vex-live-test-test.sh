#!/usr/bin/env bash
# proves: REQ-SCAN-012-AC1, REQ-SCAN-012-AC2, REQ-SCAN-012-AC3, REQ-SCAN-012-AC4, REQ-SCAN-012-AC5
# Scanner-panel rule 12 (owner RATIFIED Oct 2; read-back approved, advisor 0098), offline: the live test's plan runs the
# guide's command blocks byte for byte (only its settings blocks take test values); the test copy of the Inspector file
# differs from the generator's output only in the live-test tag and the test name prefix (plus exactly the fixture's
# own filters); the fixture CVE is one every service reports; at most 50 pushes; the release under test; the wiring
# (rc tags after promotion and main pushes that change the guide or the VEX files — never a schedule, never a PR — in
# the live-test environment, federated, literal regions, pinned actions, cleanup always).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 - "$root" <<'PY'
import copy, importlib.util, json, os, re, subprocess, sys, tempfile, yaml
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
check("every sh block of the guide is in the plan, in order, byte for byte", [b["text"] for b in blocks] == raw,
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
plan = L.render_settings({"VER": "0.3.0-rc.1", "DIGEST": "sha256:" + "a" * 64, "IMAGE": "x/y/cache"})
check("test settings are rendered as plain assignments, shell-quoted", plan == "VER='0.3.0-rc.1'\nDIGEST='sha256:%s'\nIMAGE='x/y/cache'\n" % ("a" * 64), plan)
for bad in ({"VER": "1; rm -rf /"}, {"VER": "1", "EVIL": "x"}):
    try:
        L.render_settings(bad); got = "accepted"
    except ValueError:
        got = "refused"
    check("render_settings refuses %r" % bad, got == "refused", got)
check("the plan names each command block by the scanner it serves",
      {b["section"] for b in blocks if b["kind"] == "command"} >= {"digest", "download", "verify", "grype", "scout", "inspector",
                                                                   "google", "inspector-remove"},
      sorted({b["section"] for b in blocks}))

# --- the test copy of the Inspector file (advisor 0098): tag + prefix, and exactly the fixture's own filters
images = {v: {"index": "sha256:" + c * 64, "children": {"linux/amd64": "sha256:" + d * 64, "linux/arm64": "sha256:" + e * 64}}
          for v, c, d, e in (("production", "1", "2", "3"), ("debug", "4", "5", "6"), ("fips", "7", "8", "9"))}
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
check("the fixture is an extra child of production in the test images map, nothing else changes",
      timages["production"]["children"].get("linux/fixture") == FIX and
      {k: v for k, v in timages.items() if k != "production"} == {k: v for k, v in images.items() if k != "production"})
shipped, test_gen = L.inspector_files(V, vex, images, FIX, "CVE-2023-9999", "v0.3.0-rc.1")
check("the generator's own file for the real statements is the shipped part", shipped == V.inspector(vex, images, "v0.3.0-rc.1"))
check("no real statement widens to the fixture's digest", all(FIX not in json.dumps(f) for f in test_gen["filters"][:len(shipped["filters"])]))
try:
    L.inspector_files(V, vex, images, FIX, "CVE-2024-0001", "v0.3.0-rc.1"); got = "accepted"
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

# --- the fixture CVE: one every service reports for the fixture, deterministic
pick = L.pick_cve({"grype": {"CVE-1": "High", "CVE-2": "Critical", "CVE-3": "Low"}, "inspector": {"CVE-1", "CVE-2", "CVE-3"},
                   "google": {"CVE-2", "CVE-3", "CVE-1"}, "scout": {"CVE-1", "CVE-2"}})
check("picks a CVE all four report, highest severity first", pick == "CVE-2", pick)
check("never one of our own CVEs", L.pick_cve({"grype": {"CVE-1": "High", "CVE-2": "Critical"}, "inspector": {"CVE-1", "CVE-2"},
                                                 "google": {"CVE-1", "CVE-2"}, "scout": {"CVE-1", "CVE-2"}}, {"CVE-2"}) == "CVE-1")
try:
    L.pick_cve({"grype": {"CVE-1": "High"}, "inspector": {"CVE-2"}, "google": {"CVE-1"}, "scout": {"CVE-1"}}); got = "picked"
except ValueError:
    got = "refused"
check("no common CVE is a failure, never a guess", got == "refused", got)

# --- the release under test on main: the newest published release that carries the rule-10 files
rels = [{"tagName": "v0.3.0", "isDraft": False, "assets": ["fosterstack-cache-v0.3.0.csaf.json"]},
        {"tagName": "v0.3.1-rc.1", "isDraft": True, "assets": ["fosterstack-cache-v0.3.1-rc.1.csaf.json"]},
        {"tagName": "v0.2.1", "isDraft": False, "assets": []}, {"tagName": "v0.10.0", "isDraft": False, "assets": []}]
check("the newest published release with the rule-10 files", L.release_under_test(rels) == "v0.3.0", L.release_under_test(rels))
check("none yet: empty", L.release_under_test(rels[2:]) is None)

# --- AC4: at most 50 pushes per run (the counter in the orchestration script)
out = subprocess.run(["bash", "-c", 'source "$0"; crane() { :; }; for i in $(seq 1 50); do push_copy a b || exit 9; done; push_copy a b && exit 7; exit 0',
                      os.path.join(root, "bin/vex-live-test.sh")], capture_output=True, text=True, env=dict(os.environ, VEX_LIVE_TEST_LIB="1"))
check("the 51st push fails the run", out.returncode == 0, (out.returncode, out.stderr[-300:]))

# --- AC1/AC3/AC4: the wiring
wf = lambda n: yaml.load(open(os.path.join(root, ".github/workflows", n)), Loader=yaml.BaseLoader)
rel, ci = wf("release.yml"), wf("ci.yml")
for name, d, job in (("release.yml", rel, rel["jobs"].get("live-test") or {}), ("ci.yml", ci, ci["jobs"].get("live-test") or {})):
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
    check("%s: cleanup runs always" % name, len(clean) == 1 and clean[0].get("if") == "always()", [s.get("name") for s in steps])
    check("%s: runs the committed orchestration" % name, "bin/vex-live-test.sh" in text)
check("release.yml: after promotion, on release-candidate tags only",
      (rel["jobs"]["live-test"].get("needs") in ("promotion", ["promotion"])) and
      rel["jobs"]["live-test"].get("if") == "contains(github.ref_name, '-rc.')", (rel["jobs"]["live-test"].get("needs"), rel["jobs"]["live-test"].get("if")))
cj = ci["jobs"]["live-test"]
check("ci.yml: on push to main only, after the change gate", cj.get("if") == "github.event_name == 'push' && needs.live-test-gate.outputs.changed == 'true'"
      and cj.get("needs") == "live-test-gate", (cj.get("if"), cj.get("needs")))
gate = "\n".join(st.get("run", "") for st in (ci["jobs"].get("live-test-gate") or {}).get("steps", []))
pat = re.search(r"grep -qE '([^']+)'", gate)
def gated(path):
    return bool(pat) and subprocess.run(["grep", "-qE", pat.group(1)], input=path + "\n", text=True).returncode == 0
check("ci.yml: the gate watches the guide, the VEX file and the live test's own code",
      all(gated(x) for x in ("docs/using-our-vex.md", ".vex/fosterstack-cache.openvex.json", "bin/vex-forms.py",
                             "bin/vex-live-test.sh", "bin/vex-live-test.py")), pat and pat.group(1))
check("ci.yml: the gate ignores unrelated changes",
      not any(gated(x) for x in ("README.md", "docs/verify-images.md", "bin/panel.py", "docs/using-our-vex.md.bak/x")))
check("ci.yml: no usable base runs the test rather than missing a change", 'echo "changed=true"' in gate.split("exit 0")[0])
for name, d in (("release.yml", rel), ("ci.yml", ci)):
    check("%s: never on a schedule" % name, "schedule" not in d["on"], d["on"])
print("vex-live-test: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
