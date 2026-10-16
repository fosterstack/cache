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

# --- release candidates (v0.3: nothing is published): the blocks the page's cannot-run list names are left out of the plan, every other block stays, in order
cr = json.load(open(os.path.join(root, "docs/using-our-vex.cannot-run.json")))
rc_blocks = L.guide_blocks(guide, skip=cr["blocks"])
check("the rc plan is the page's plan minus exactly the listed blocks, in order", [b["text"] for b in rc_blocks] == [b["text"] for b in blocks if b["text"] not in cr["blocks"]])
check("the rc plan has no digest, download, verify or published-image Grype block", not {"digest", "download", "verify", "grype"} & {b["section"] for b in rc_blocks})
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
check("a cannot-run list that skips an Inspector or Google block is refused (only digest, download, verify and the published-image Grype scan may be skipped)", got == "refused", got)

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
                   "google": {"CVE-2", "CVE-3", "CVE-1"}})
check("picks a CVE all three report, highest severity first", pick == "CVE-2", pick)
check("never one of our own CVEs", L.pick_cve({"grype": {"CVE-1": "High", "CVE-2": "Critical"}, "inspector": {"CVE-1", "CVE-2"},
                                                 "google": {"CVE-1", "CVE-2"}}, {"CVE-2"}) == "CVE-1")
try:
    L.pick_cve({"grype": {"CVE-1": "High"}, "inspector": {"CVE-2"}, "google": {"CVE-1"}}); got = "picked"
except ValueError:
    got = "refused"
check("no common CVE is a failure, never a guess", got == "refused", got)

# --- the release under test on main: the newest published release that carries the rule-10 files
rels = [{"tagName": "v0.3.0", "isDraft": False, "assets": ["fosterstack-cache-v0.3.0.csaf.json"]},
        {"tagName": "v0.3.1-rc1", "isDraft": False, "assets": ["fosterstack-cache-v0.3.1-rc1.csaf.json"]},
        {"tagName": "v0.2.1", "isDraft": False, "assets": []}, {"tagName": "v0.10.0", "isDraft": False, "assets": []}]
check("a release candidate tag is never the release under test; the newest published release with the rule-10 files is", L.release_under_test(rels) == "v0.3.0", L.release_under_test(rels))
check("none yet: empty", L.release_under_test(rels[2:]) is None)

# --- AC4: at most 50 pushes per run (the counter in the orchestration script)
out = subprocess.run(["bash", "-c", 'source "$0"; crane() { :; }; for i in $(seq 1 50); do push_copy a b || exit 9; done; push_copy a b && exit 7; exit 0',
                      os.path.join(root, "bin/vex-live-test.sh")], capture_output=True, text=True, env=dict(os.environ, VEX_LIVE_TEST_LIB="1"))
check("the 51st push fails the run", out.returncode == 0, (out.returncode, out.stderr[-300:]))

# --- the release candidate under test (v0.3: an rc ends before publishing, so its images exist only as Build's OCI layouts and digests.json): each layout is pushed to
#     the test repository and must come out at exactly the digest Build attested
# (the behavioral cases below drive bin/vex-live-test.sh with stubs; "copy_candidate" is the one place that reads a candidate)
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
    check("%s: runs the committed orchestration" % name, "bin/vex-live-test.sh" in text)
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
      all(gated(x) for x in ("docs/using-our-vex.md", ".vex/fosterstack-cache.openvex.json", "bin/vex-forms.py",
                             "bin/vex-live-test.sh", "bin/vex-live-test.py")), pat and pat.group(1))
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
# SEC-169-06: Google's assessment must be NEW and come from a note this run's load created
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

# behavioral: the shell library, with stubs
script = os.path.join(root, "bin/vex-live-test.sh")
def sh(body, stubs, env=None):
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "stub"))
        for name, code in stubs.items():
            with open(os.path.join(t, "stub", name), "w") as fh:
                fh.write("#!/usr/bin/env bash\n" + code + "\n")
            os.chmod(os.path.join(t, "stub", name), 0o755)
        e = dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], VEX_LIVE_TEST_LIB="1",
                 RUNNER_TEMP=t, ECR="1.dkr.ecr.us-east-1.amazonaws.com/fosterstack-cache-live-test",
                 GAR="us-east1-docker.pkg.dev/fosterstack-cache/cache-live-test", GITHUB_RUN_ID="1", **(env or {}))
        # the Container Analysis calls go through ca() -> the python helper (urllib, tested below); here ca() is replaced by the stub transport so the shell
        # logic around it is tested offline
        prelude = 'ca() { ca-transport "$@"; }; ' if "ca-transport" in stubs else ""
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
try:
    L.ca_request(CA, "GET", "", opener_ok); got = "accepted"
except ValueError:
    got = "refused"
check("ca: no token is refused", got == "refused", got)
# SEC-169-03: a guide block's failing command fails the run even inside a pipe
plan_ok = 'mkdir -p plan; printf "00-verify.sh\\n" > plan.txt; printf "%s\\n" "cosign verify-attestation x | jq -r . > out.json" > plan/00-verify.sh; guide verify; echo CONTINUED'
rc, out = sh(plan_ok, {"cosign": "echo '{}'; exit 42"})
check("SEC-169-03 a failed cosign inside a pipe stops the run", rc != 0 and "CONTINUED" not in out, (rc, out[-200:]))
# SEC-169-08/09: the sweep fails when it cannot list or delete, pages through notes, and empties the test repositories
OKAWS = r"""case "$*" in
  *"ecr list-images"*) echo '{"imageIds": []}' ;;
  *"inspector2 list-filters"*) echo '{"filters": []}' ;;
  *) echo '{}' ;; esac"""
OKGC = 'case "$*" in *"auth print-access-token"*) echo tok ;; *"images list"*) echo "[]" ;; esac'
OKCURL = 'echo "{}"'
rc, out = sh("sweep", {"aws": OKAWS, "gcloud": OKGC, "ca-transport": OKCURL})
check("sweep of empty test resources passes", rc == 0, out[-300:])
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
rc, out = sh("MODE=main; select_release; echo tag=${tag:-none} skip=${skip:-no}", {"gh": "echo '[]'"}, {"GITHUB_REPOSITORY": "fosterstack/cache"})
check("SEC-170-02 main mode with no release is an announced skip", rc == 0 and "::notice::" in out and "skip=yes" in out, (rc, out[-300:]))
rc, out = sh("MODE=main; select_release; echo tag=${tag:-none} skip=${skip:-no}", {"gh": "echo '[{\"tagName\":\"v0.3.0\",\"isDraft\":false,\"assets\":[\"fosterstack-cache-v0.3.0.csaf.json\"]}]'"}, {"GITHUB_REPOSITORY": "fosterstack/cache"})
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
print("vex-live-test: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
