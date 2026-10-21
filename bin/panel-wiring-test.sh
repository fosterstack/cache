#!/usr/bin/env bash
# proves: REQ-REL-010-AC1, REQ-REL-010-AC3, REQ-SCAN-001-AC1, REQ-SCAN-001-AC2, REQ-SCAN-001-AC3, REQ-SCAN-002-AC1, REQ-SCAN-004-AC1, REQ-SCAN-004-AC2, REQ-SCAN-009-AC5, REQ-REL-004-AC3
# The scanner panel's wiring in the daily rescan (scanner-panel rules 1, 2, 4, 9; ratified Oct 2): which
# scanner runs on which images (fixed in the workflow, never computed), Google only through the federation
# with repository variables, the VEX as the only exception (Grype and Scout given the file, no ignore
# options anywhere), Trivy and Snyk gone from the panel, and no audit in the rescan (the auditor judges unique findings). The
# real workflow must pass; each mutated copy must be caught.
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT  # python tempfile and mktemp dirs all live under this one, removed on exit
root=$(cd "$(dirname "$0")/.." && pwd)
export PANEL_ROOT="$root"
work=$(mktemp -d); trap 'rm -rf "$work" "$TMPDIR"' EXIT
pass=0 failn=0
judge() { python3 - "$1" <<'PY'
import re, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
jobs = d.get("jobs", {})
bad = []
def text(j): return "\n".join((s.get("run") or "") for s in jobs.get(j, {}).get("steps", []))
def uses(j): return [str(s.get("uses", "")) for s in jobs.get(j, {}).get("steps", [])]
VAR = ("production", "debug", "fips")
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google", "panel"):
    if j not in jobs:
        bad.append(f"no {j} job")
if bad:
    print("; ".join(bad)); sys.exit(1)
# rule 1: the fixed image set, written in the workflow
for j in ("panel-grype", "panel-scout", "panel-inspector"):
    t = text(j)
    if "for v in production debug fips" not in t or "for arch in amd64 arm64" not in t:
        bad.append(f"{j} does not scan the six images, fixed in the workflow")
tg = text("panel-google")
if "for v in production debug fips" not in tg or "arm64" in tg or "for arch" in tg \
        or "--override-arch amd64" not in tg or 'cand-${v}-amd64"' not in tg:
    bad.append("panel-google does not scan exactly the three variants on linux/amd64 (and never arm64)")
for j in jobs:
    # manifests/rescan are the PUBLISHED-release rescan (merged from daily-rescan.yml, consolidation 3 of 4;
    # REQ-REL-003), which runs only the scanners in .github/policy/scanners.json — neither is the scanner panel.
    # The old scanner-reports job (trivy/osv-scanner reports for the auditor) is gone: the auditor reads the panel
    if any(x in (text(j) + " ".join(uses(j))).lower() for x in ("trivy", "snyk", "osv-scanner")) and j not in ("manifests", "rescan"):
        bad.append(f"{j} runs Trivy, Snyk or OSV-Scanner")
for gone in ("scan-main", "trivy-main", "snyk-main", "scanner-reports"):
    if gone in jobs:
        bad.append(f"the retired {gone} job is still there")
# rule 2: Google through the federation, identifiers from repository variables, no secrets, no keys
gj = jobs["panel-google"]
if (gj.get("permissions") or {}).get("id-token") != "write":
    bad.append("panel-google lacks id-token: write")
auth = [s for s in gj.get("steps", []) if str(s.get("uses", "")).startswith("google-github-actions/auth@")]
w = (auth[0].get("with") or {}) if auth else {}
if not auth or w.get("workload_identity_provider") != "${{ vars.CACHE_SCANNER_PROVIDER }}" \
        or w.get("service_account") != "${{ vars.CACHE_SCANNER_SERVICE_ACCOUNT }}" or "credentials_json" in w:
    bad.append("panel-google does not authenticate through the federation with the two repository variables")
if "secrets." in str(gj) or "GOOGLE_APPLICATION_CREDENTIALS" in tg:
    bad.append("panel-google uses a secret or a key file")
# rule 4: the VEX is the only exception
if "--vex .vex/fosterstack-cache.openvex.json" not in text("panel-grype"):
    bad.append("Grype is not given the VEX file")
# REQ-REL-010 on the rescan (handoff 0521): Scout applies our statements only through an attestation in the image index, and an
# attestation lives in a registry. The vex-attach job gives each candidate index its attestation children (bin/vex-index.py) and
# pushes it to the SCRATCH package only; panel-scout scans those registry refs by exact index digest with our author.
import json, os, subprocess, tempfile
ROOT = os.environ.get("PANEL_ROOT", ".")
SCRATCH = "ghcr.io/fosterstack/cache-scout-probe"
FIXTURE_DIGEST = "sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab"
DIG = {"fixture-before": "sha256:" + "1" * 64, "fixture-ours": "sha256:" + "2" * 64, "fixture-docker": "sha256:" + "6" * 64,
       "production": "sha256:" + "3" * 64, "debug": "sha256:" + "4" * 64, "fips": "sha256:" + "5" * 64}
STUB = r"""#!/usr/bin/env bash
{ printf '%s' "$(basename "$0")"; printf ' %q' "$@"; printf '\n'; } >> "$STUB_LOG"
if [ "$(basename "$0")" = docker ] && [ "$1 $2" = "scout cves" ]; then
  ref=""; for a in "$@"; do case "$a" in registry://*) ref=$a;; esac; done
  T='{"identifiers":[{"value":"CVE-2023-4911"}],"location":{"dependency":{"package":{"name":"libc6"},"version":"2.36-9"}}}'
  O='{"identifiers":[{"value":"CVE-2099-0001"}],"location":{"dependency":{"package":{"name":"libalpha"},"version":"1.0"}}}'
  case "$ref" in
    *@sha256:2222*) case "$STUB_MODE" in
        applies) printf '{"vulnerabilities":[%s]}' "$O" ;;
        ignores) printf '{"vulnerabilities":[%s,%s]}' "$T" "$O" ;;
        drops-all) printf '{"vulnerabilities":[]}' ;;
        empty) printf '{}' ;;
      esac ;;
    *) printf '{"vulnerabilities":[%s,%s]}' "$T" "$O" ;;
  esac
elif [ "$(basename "$0")" = docker ] && [ "$1 $2" = "scout sbom" ]; then
  printf '%s' '{"artifacts":[]}'
fi
exit 0
"""
author = json.load(open(os.path.join(ROOT, ".vex/fosterstack-cache.openvex.json")))["author"]
def run_block(block, mode, failing=None):
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "stub")); os.makedirs(os.path.join(t, "attach"))
        json.dump(DIG, open(os.path.join(t, "attach", "digests.json"), "w"))
        for tool in ("docker", "skopeo", "sudo"):
            with open(os.path.join(t, "stub", tool), "w") as fh:
                fh.write("#!/usr/bin/env bash\nexit 23\n" if tool == failing else STUB)
            os.chmod(os.path.join(t, "stub", tool), 0o755)
        log = os.path.join(t, "log")
        open(log, "w").close()
        env = dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], STUB_LOG=log, STUB_MODE=mode,
                   RUNNER_TEMP=t, GITHUB_STEP_SUMMARY=os.path.join(t, "sum"), GITHUB_RUN_ID="42")
        r = subprocess.run(["bash", "-e", "-c", block], cwd=ROOT, env=env, capture_output=True, text=True)
        return r.returncode, open(log).read().splitlines()
va = jobs.get("vex-attach")
if not va:
    bad.append("no vex-attach job (the attestation children and the push to the scratch package)")
else:
    perms = va.get("permissions") or {}
    if perms != {"contents": "read", "packages": "write"} or va.get("environment") or va.get("if"):
        bad.append("vex-attach must hold exactly contents: read and packages: write, no environment, no identity token, no condition: %s" % perms)
    vneeds = va.get("needs", []); vneeds = vneeds if isinstance(vneeds, list) else [vneeds]
    if "assemble" not in vneeds or "build" not in vneeds:
        bad.append("vex-attach does not wait for the build and the assembled candidates")
    vt = text("vex-attach")
    vsteps = va.get("steps", [])
    att = [x for x in vsteps if "attach our OpenVEX to each candidate index" in (x.get("name") or "")]
    fxs = [x for x in vsteps if "self-check fixtures" in (x.get("name") or "")]
    prn = [x for x in vsteps if "prune the scratch package" in (x.get("name") or "")]
    if len(att) != 1 or len(fxs) != 1 or len(prn) != 1:
        bad.append("vex-attach lacks one of its three steps (prune; attach and push the candidates; build the self-check fixtures)")
    else:
        if not (vsteps.index(prn[0]) < vsteps.index(att[0]) and vsteps.index(prn[0]) < vsteps.index(fxs[0])):
            bad.append("the prune must run before this run's pushes (nothing it pushes can lose its version to it)")
        # the prune is strict, and confined to the scratch package: run it against a stub gh (approval condition b)
        GHSTUB = r"""#!/usr/bin/env bash
{ printf 'gh'; printf ' %q' "$@"; printf '\n'; } >> "$STUB_LOG"
case "$*" in
  *"--jq .visibility"*) echo private ;;
  *"-X DELETE"*) if [ "$STUB_MODE" = del-fail ]; then echo "HTTP 403" >&2; exit 1; fi; exit 0 ;;
  *"--paginate"*) case "$STUB_MODE" in
      list-404) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
      list-fail) echo "gh: boom (HTTP 500)" >&2; exit 1 ;;
      *) printf '11\n12\n' ;;
    esac ;;
esac
exit 0
"""
        def run_prune(mode):
            with tempfile.TemporaryDirectory() as t:
                os.makedirs(os.path.join(t, "stub"))
                with open(os.path.join(t, "stub", "gh"), "w") as fh:
                    fh.write(GHSTUB)
                os.chmod(os.path.join(t, "stub", "gh"), 0o755)
                log = os.path.join(t, "log")
                open(log, "w").close()
                env = dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], STUB_LOG=log, STUB_MODE=mode, RUNNER_TEMP=t,
                           GITHUB_STEP_SUMMARY=os.path.join(t, "sum"), GITHUB_REPOSITORY_OWNER="fosterstack", GH_TOKEN="x")
                r = subprocess.run(["bash", "-e", "-c", prn[0].get("run", "")], cwd=ROOT, env=env, capture_output=True, text=True)
                return r.returncode, open(log).read().splitlines()
        rc, calls = run_prune("ok")
        dels = [l for l in calls if "-X DELETE" in l]
        if rc != 0 or len(dels) != 2 or not all("orgs/fosterstack/packages/container/cache-scout-probe/versions/" in l for l in dels):
            bad.append("the prune does not delete the old versions of the scratch package: rc=%s %s" % (rc, calls))
        if any("packages/container/cache-scout-probe" not in l for l in calls if "api" in l):
            bad.append("the prune reaches a package other than the scratch package")
        rc, calls = run_prune("list-404")
        if rc != 0 or any("-X DELETE" in l for l in calls):
            bad.append("the prune treats a missing package as an error or deletes something (rc=%s)" % rc)
        if run_prune("list-fail")[0] == 0:
            bad.append("the prune goes green when the version listing fails")
        rc, calls = run_prune("del-fail")
        if rc == 0 or len([l for l in calls if "-X DELETE" in l]) != 2:
            bad.append("the prune goes green when a delete fails, or stops at the first failure (rc=%s)" % rc)
        for need in ("vex=.vex/fosterstack-cache.openvex.json", 'python3 bin/vex-index.py layout --layout "${d}" --vex "${vex}"',
                     'python3 bin/vex-index.py verify-layout --layout "${d}" --vex "${vex}" --base-digest "${base}"',
                     'python3 bin/release-layout.py "${d}" "${final}"', 'tag="cand-${GITHUB_RUN_ID}-${v}"', "chmod -R go-w", "skopeo copy --all",
                     '--digestfile "/tmp/attach/${v}.pushed"', '[ "${pushed}" = "${final}" ]', "for v in production debug fips"):
            if need not in att[0].get("run", ""):
                bad.append("the attach step lacks %s" % need)
        for need in ("python3 bin/vex-index.py layout --layout", "python3 bin/vex-index.py verify-layout --layout", "--base-digest",
                     ".vex/fosterstack-cache.openvex.json", "CVE-2023-4911", "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "chmod -R go-w",
                     "--digestfile", "selfcheck-before-${GITHUB_RUN_ID}", "selfcheck-ours-${GITHUB_RUN_ID}"):
            if need not in fxs[0].get("run", ""):
                bad.append("the fixture step lacks %s" % need)
    for need in ("docker login ghcr.io", "-X DELETE", "timedelta(days=14)"):
        if need not in vt:
            bad.append("vex-attach lacks %s" % need)
    # the only registry name the job writes or reads is the scratch package (plus the pinned debian fixture): never the release package
    stripped = re.sub(r"repository_url=ghcr\.io/fosterstack/cache(?![-\w])", "", vt)
    if re.search(r"ghcr\.io/fosterstack/cache(?![-\w])", stripped) or re.search(r"cache-candidates|ghcr\.io/\$\{?GITHUB_REPOSITORY", stripped):
        bad.append("vex-attach names a package other than the scratch package")
    for m in re.finditer(r"docker://(\S+)", vt):
        ref = m.group(1).strip('"\\')
        if not (ref.startswith(SCRATCH + ":") or ref == "docker.io/library/debian@" + FIXTURE_DIGEST):
            bad.append("vex-attach touches the registry reference %s" % ref)
    for m in re.finditer(re.escape(SCRATCH) + r":([^\s\")]+)", vt):
        if not re.fullmatch(r"cand-\$\{GITHUB_RUN_ID\}-\$\{v\}|\$\{tag\}|selfcheck-(before|ours)-\$\{GITHUB_RUN_ID\}", m.group(1).rstrip('"')):
            bad.append("vex-attach pushes a tag that is not an attested candidate or a self-check fixture: %s" % m.group(1))
    if re.findall(r"packages/container/([A-Za-z0-9._-]+)", vt) != ["cache-scout-probe"]:
        bad.append("vex-attach prunes or reads a package other than the scratch package")
    for st in va.get("steps", []):
        if st.get("if") or str(st.get("continue-on-error", "false")) != "false":
            bad.append("vex-attach: step %r is conditional or may fail quietly" % st.get("name"))
ps = jobs.get("panel-scout", {})
scout_steps = ps.get("steps", [])
def step(name_part):
    hit = [x for x in scout_steps if name_part in (x.get("name") or "")]
    return hit[0] if len(hit) == 1 else None
pneeds = ps.get("needs", []); pneeds = pneeds if isinstance(pneeds, list) else [pneeds]
if "vex-attach" not in pneeds:
    bad.append("panel-scout does not wait for the attested candidates")
if (ps.get("permissions") or {}) != {"contents": "read", "packages": "read"}:
    bad.append("panel-scout must hold contents: read and packages: read only")
st_text = text("panel-scout")
if re.search(r"--vex-location|local://|docker-daemon:|skopeo", st_text):
    bad.append("panel-scout reads a local image or a local VEX file (Scout applies our statements only through the index's attestation)")
sc, scan, diag = step("rule 4 self-check"), step("Docker Scout every image"), step("attestation diagnostics")
if not sc or not scan or scout_steps.index(sc) > scout_steps.index(scan):
    bad.append("no Scout self-check before the scan")
else:
    if sc.get("continue-on-error") or sc.get("if"):
        bad.append("the Scout self-check can be skipped or softened")
    AUTHOR = r"--vex-author \\\^FosterStack\\ LLC\\\$"
    for mode in ("applies",):
        rc, log = run_block(sc.get("run", ""), mode)
        scouts = [l for l in log if l.startswith("docker scout cves")]
        if rc != 0:
            bad.append("the Scout self-check fails when Scout applies our attestation")
        want = ["docker scout cves --format gitlab --vex-author \\^FosterStack\\ LLC\\$ --platform linux/amd64 registry://%s@%s" % (SCRATCH, DIG[k])
                for k in ("fixture-before", "fixture-ours")]
        if scouts != want:
            bad.append("the self-check does not scan the fixture plain and attested, by exact digest, with our author: %s" % scouts)
    for mode in ("ignores", "drops-all", "empty"):
        if run_block(sc.get("run", ""), mode)[0] == 0:
            bad.append("the Scout self-check passes when Scout %s" % mode)
    rc, log = run_block(scan.get("run", ""), "applies")
    scouts = [l for l in log if l.startswith("docker scout cves")]
    sboms = [l for l in log if l.startswith("docker scout sbom")]
    want = ["docker scout cves --format gitlab --vex-author \\^FosterStack\\ LLC\\$ --platform linux/%s registry://%s@%s" % (a, SCRATCH, DIG[v])
            for v in ("production", "debug", "fips") for a in ("amd64", "arm64")]
    wsbom = ["docker scout sbom --format json --platform linux/%s registry://%s@%s" % (a, SCRATCH, DIG[v])
             for v in ("production", "debug", "fips") for a in ("amd64", "arm64")]
    if scouts != want or sboms != wsbom:
        bad.append("Scout's scan does not run on our six attested candidates by exact digest with our author: %s" % scouts)
    if rc != 0:
        bad.append("the Scout scan step fails on a clean day")
if not diag:
    bad.append("no Scout attestation diagnostics (read-back 5a/5b)")
else:
    if diag.get("if") or diag.get("continue-on-error"):
        bad.append("the Scout diagnostics must be unconditional and contained inside the step, not continue-on-error")
    for failing in ("docker", "skopeo", "sudo"):   # a diagnostic failure never fails the step
        if run_block(diag.get("run", ""), "applies", failing)[0] != 0:
            bad.append("the diagnostics step fails the job when %s fails" % failing)
    for need in ("GITHUB_STEP_SUMMARY", "ours-amd64", "ours-arm64", "ours-noplatform", "ours-tag", "exit 0"):
        if need not in diag.get("run", ""):
            bad.append("the diagnostics lack %s" % need)
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google"):
    if re.search(r"--(ignore|only-fixed|exclude|ignore-base|only-severity|severity)\b|\.grype\.yaml|suppress", text(j)):
        bad.append(f"{j} carries an ignore or severity option")
# rule 9 (owner, Oct 3): the AI judging lives in the auditor; the rescan's panel job tallies and cannot audit
pj = jobs["panel"]
if "id-token" in (pj.get("permissions") or {}) or pj.get("environment") or re.search(r"profiles|audit|--prior", text("panel")):
    bad.append("the rescan's panel job can audit (identity, environment, profiles or history): the auditor judges unique findings")
# the tally step (one step, the verdict the auditor reads)
pj = jobs["panel"]
judge_steps = [s for s in pj.get("steps", []) if "bin/panel.py tally" in (s.get("run") or "")]
if len(judge_steps) != 1 or "if" in judge_steps[0] and "always()" not in judge_steps[0]["if"]:
    bad.append("no single step runs `bin/panel.py tally`")
if any(re.search(r"\b(schedule|workflow_run|repository_dispatch)\b", str(s)) for s in pj.get("steps", [])):
    bad.append("the panel defers audits to another workflow")
needs = pj.get("needs", [])
if sorted(needs if isinstance(needs, list) else [needs]) != ["panel-google", "panel-grype", "panel-inspector", "panel-scout"] or "always()" not in pj.get("if", ""):
    bad.append("the panel does not wait for all four scanners whatever their outcome")
# the run is daily, and nothing in the panel is switched off or allowed to fail quietly
crons = [c.get("cron", "") for c in ((d.get("on") or {}).get("schedule") or []) if isinstance(c, dict)]
if not any(re.fullmatch(r"\d{1,2} \d{1,2} \* \* \*", c.split("#")[0].strip()) for c in crons):
    bad.append("the rescan has no daily schedule")
# the exact scan commands: each architecture once, Google's package count from its request log
for j in ("panel-grype", "panel-inspector"):
    t = text(j)
    if not re.search(r"for arch in amd64 arm64; do", t) or t.count("for arch in") != 1 \
            or '--override-arch "${arch}"' not in t or 'cand-${v}-${arch}' not in t:
        bad.append(f"{j} does not load each architecture once by the loop variable")
t = text("panel-scout")      # Scout names the platform of an attested index, each architecture once
if not re.search(r"for arch in amd64 arm64; do", t) or '--platform "linux/${arch}"' not in t or "for v in production debug fips" not in t:
    bad.append("panel-scout does not scan each variant on each architecture once by the loop variables")
if "--log-http" not in tg or "bin/panel.py google-packages" not in tg or "list-vulnerabilities" not in tg:
    bad.append("panel-google does not take its package count from the request log and its findings from list-vulnerabilities")
if jobs["panel-google"].get("environment") != "agent":
    bad.append("panel-google is not in the main-only agent environment (its identity admits a scheduled main run only there)")
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google", "panel"):
    if "if" in jobs[j] and j != "panel":
        bad.append(f"{j} is conditional")
    for st in jobs[j].get("steps", []):
        cond = str(st.get("if", "")).replace(" ", "")
        if cond and not cond.startswith("${{always()") and "steps.judge" not in cond:
            bad.append(f"{j}: step {st.get('name')!r} is conditional ({st.get('if')})")
        if str(st.get("continue-on-error", "false")) != "false" and "download-artifact" not in str(st.get("uses", "")):
            bad.append(f"{j}: step {st.get('name')!r} may fail quietly")
issue = [st for st in pj.get("steps", []) if "gh issue create" in (st.get("run") or "") and "gh issue comment" in (st.get("run") or "")]
if len(issue) != 1 or "refs/heads/main" not in str(issue[0].get("if", "")) or "issue.md" not in issue[0].get("run", ""):
    bad.append("no step opens or updates the tracking issue from main with the tally's issue text")
elif re.search(r"^\s*exit 0\s*$", issue[0]["run"], re.M) or issue[0]["run"].count("exit 0") != 1:
    bad.append("the issue step can exit before filing")
js = judge_steps[0].get("run", "") if judge_steps else ""
if 'echo "rc=$?" >> "$GITHUB_OUTPUT"' not in js or not re.search(r"bin/panel\.py tally[^\n]*(\\\n[^\n]*)*\n\s*echo \"rc=\$\?\"", js):
    bad.append("the tally's exit code is not what the panel exports")
last = pj.get("steps", [])[-1] if pj.get("steps") else {}
if "steps.judge.outputs.rc != '0'" not in str(last.get("if", "")) or "exit 1" not in (last.get("run") or ""):
    bad.append("the panel's last step does not fail the run when the judge's verdict is not clean")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_() {
  local f="$work/$1.yml"
  cp "$root/.github/workflows/main-candidate-rescan.yml" "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS $1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want $2 ($out)"; fi
}
J='d["jobs"]'
step_of() { echo "[s for s in $J['$1']['steps'] if '$2' in (s.get('run') or '')][0]"; }
# Codex #168 r2 (B2): the self-check's judge compares findings (CVE, package, version), not CVE names
judge_case() {   # name want before after
  local d; d=$(mktemp -d "$work/j.XXXX"); printf '%s' "$3" > "$d/b"; printf '%s' "$4" > "$d/a"
  if python3 "$root/bin/scout-selfcheck.py" "$d/b" "$d/a" CVE-2023-4911 >/dev/null 2>&1; then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS judge-$1 → $got"; else failn=$((failn+1)); echo "FAIL judge-$1 → $got, want $2"; fi
}
F() { printf '{"identifiers":[{"value":"%s"}],"location":{"dependency":{"package":{"name":"%s"},"version":"%s"}}}' "$1" "$2" "$3"; }
T=$(F CVE-2023-4911 libc6 2.36); A=$(F CVE-1 libalpha 1.0); B=$(F CVE-1 libbeta 1.0); A2=$(F CVE-1 libalpha 2.0)
judge_case kept-exactly      ok  "{\"vulnerabilities\":[$T,$A,$B]}" "{\"vulnerabilities\":[$A,$B]}"
judge_case lost-a-package    bad "{\"vulnerabilities\":[$T,$A,$B]}" "{\"vulnerabilities\":[$A]}"
judge_case other-package     bad "{\"vulnerabilities\":[$T,$A]}"    "{\"vulnerabilities\":[$B]}"
judge_case other-version     bad "{\"vulnerabilities\":[$T,$A]}"    "{\"vulnerabilities\":[$A2]}"
judge_case gained-a-finding  bad "{\"vulnerabilities\":[$T,$A]}"    "{\"vulnerabilities\":[$A,$B]}"
judge_case target-kept       bad "{\"vulnerabilities\":[$T,$A]}"    "{\"vulnerabilities\":[$T,$A]}"
judge_case id-number         bad "{\"vulnerabilities\":[$T,$(F 123 libalpha 1.0 | sed 's/"123"/123/')]}" "{\"vulnerabilities\":[$(F 123 libalpha 1.0 | sed 's/"123"/123/')]}"
judge_case id-true           bad "{\"vulnerabilities\":[$T,$(F x libalpha 1.0 | sed 's/"x"/true/')]}" "{\"vulnerabilities\":[$(F x libalpha 1.0 | sed 's/"x"/true/')]}"
judge_case id-blank          bad "{\"vulnerabilities\":[$T,$(F ' ' libalpha 1.0)]}" "{\"vulnerabilities\":[$(F ' ' libalpha 1.0)]}"
judge_case no-location       bad "{\"vulnerabilities\":[$T,{\"identifiers\":[{\"value\":\"CVE-1\"}]}]}" "{\"vulnerabilities\":[{\"identifiers\":[{\"value\":\"CVE-1\"}]}]}"
# advisor 0106: the Scout product-form probe — one statement per candidate form, each on a different fixture CVE; it
# reports which forms Scout applied and never decides the job (the self-check does)
probe_case() {   # name want-substring before after
  local d; d=$(mktemp -d "$work/p.XXXX"); printf '%s' "$3" > "$d/b"; printf '%s' "$4" > "$d/a"
  python3 "$root/bin/scout-selfcheck.py" probe-doc "$d/b" "FosterStack LLC" "$d/v.json" >/dev/null 2>&1 || { failn=$((failn+1)); echo "FAIL probe-$1: no document"; return; }
  out=$(python3 "$root/bin/scout-selfcheck.py" probe-report "$d/b" "$d/a" "$d/v.json.map" 2>&1); rc=$?
  if [ "$rc" = 0 ] && grep -q -- "$2" <<<"$out"; then pass=$((pass+1)); echo "PASS probe-$1"; else failn=$((failn+1)); echo "FAIL probe-$1 → rc=$rc: $out"; fi
}
PB="{\"vulnerabilities\":[$(F CVE-2001-0001 a 1),$(F CVE-2001-0002 b 1),$(F CVE-2001-0003 c 1),$(F CVE-2001-0004 d 1),$(F CVE-2001-0005 e 1),$(F CVE-2001-0006 f 1),$(F CVE-2001-0007 g 1)]}"
probe_case none-applied "applied: none" "$PB" "$PB"
d0=$(mktemp -d "$work/p.XXXX"); printf '%s' "$PB" > "$d0/b"; python3 "$root/bin/scout-selfcheck.py" probe-doc "$d0/b" "FosterStack LLC" "$d0/v.json" >/dev/null
first=$(python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print(m["pkg:docker/ghcr.io/fosterstack/cache@selfcheck"])' "$d0/v.json.map")
PA=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["vulnerabilities"]=[v for v in d["vulnerabilities"] if v["identifiers"][0]["value"]!=sys.argv[2]]; print(json.dumps(d))' "$PB" "$first")
probe_case all-vanished "inconclusive" "$PB" '{"vulnerabilities":[]}'
PC=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); drop={sys.argv[2], "CVE-2001-0007"}; d["vulnerabilities"]=[v for v in d["vulnerabilities"] if v["identifiers"][0]["value"] not in drop]; print(json.dumps(d))' "$PB" "$first")
probe_case control-lost "inconclusive" "$PB" "$PC"
probe_case unc-pkg-lost "uncovered findings lost: \[\[\"CVE-2001-0007\", \"g2\"" "{\"vulnerabilities\":[$(F CVE-2001-0001 a 1),$(F CVE-2001-0002 b 1),$(F CVE-2001-0003 c 1),$(F CVE-2001-0004 d 1),$(F CVE-2001-0005 e 1),$(F CVE-2001-0006 f 1),$(F CVE-2001-0007 g 1),$(F CVE-2001-0007 g2 1)]}" "{\"vulnerabilities\":[$(F CVE-2001-0002 b 1),$(F CVE-2001-0003 c 1),$(F CVE-2001-0004 d 1),$(F CVE-2001-0005 e 1),$(F CVE-2001-0006 f 1),$(F CVE-2001-0007 g 1)]}"
probe_case gained-only "uncovered findings lost: none" "$PB" "$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["vulnerabilities"].append({"identifiers":[{"value":"CVE-2009-0009"}],"location":{"dependency":{"package":{"name":"z"},"version":"1"}}}); print(json.dumps(d))' "$PB")"
# advisor 0109: probe 3 — statements that name the finding's package (a subcomponent from Scout's own SBOM), the
# platform-qualified image, and a registry image; each form on a different CVE with exactly one package
d3=$(mktemp -d "$work/p3.XXXX")
printf '%s' "$PB" > "$d3/b"
python3 -c 'import json; print(json.dumps({"artifacts": [{"name": n, "version": "1", "purl": "pkg:deb/debian/%s@1?arch=amd64" % n} for n in "abcdefg"]}))' > "$d3/sbom"
if python3 "$root/bin/scout-selfcheck.py" probe-doc3 "$d3/b" "$d3/sbom" "FosterStack LLC" ghcr.io/fosterstack/cache selfcheck "$d3/v.json" >/dev/null 2>&1 \
   && python3 -c '
import json, sys
d = json.load(open(sys.argv[1])); m = json.load(open(sys.argv[1] + ".map")); s = d["statements"]
subs = [x for x in s if x["products"][0].get("subcomponents")]
plat = [x for x in s if "platform=linux%2Famd64" in x["products"][0]["@id"]]
assert d["author"] == "FosterStack LLC" and len({x["vulnerability"]["name"] for x in s}) == len(s) == len(m) >= 5
assert subs and all(c["@id"].startswith("pkg:deb/debian/") for x in subs for c in x["products"][0]["subcomponents"])
assert plat and any(x["products"][0]["@id"].startswith("pkg:oci/cache") for x in subs)
' "$d3/v.json"; then pass=$((pass+1)); echo "PASS probe3-document: subcomponents from the SBOM, platform forms, one CVE each"
else failn=$((failn+1)); echo "FAIL probe3-document"; fi
# probe 3 run 1 found no (name, version) match between Scout's report and its SBOM: fall back to a unique name
d3b=$(mktemp -d "$work/p3b.XXXX"); printf '%s' "$PB" > "$d3b/b"
python3 -c 'import json; print(json.dumps({"artifacts": [{"name": n, "version": "1:1-deb12u1", "purl": "pkg:deb/debian/%s@1:1-deb12u1" % n} for n in "abcdefg"]}))' > "$d3b/sbom"
if python3 "$root/bin/scout-selfcheck.py" probe-doc3 "$d3b/b" "$d3b/sbom" "FosterStack LLC" ghcr.io/fosterstack/cache selfcheck "$d3b/v.json" >/dev/null 2>&1; then
  pass=$((pass+1)); echo "PASS probe3-name-fallback"; else failn=$((failn+1)); echo "FAIL probe3-name-fallback"; fi
# advisor 0110: Scout's GitLab report puts the package purl in "name" (run 37126697443) — use it as the purl
d3c=$(mktemp -d "$work/p3c.XXXX")
python3 -c '
import json
f = lambda c, n: {"identifiers": [{"value": c}], "location": {"dependency": {"package": {"name": "pkg:deb/debian/%s@1?os_distro=bookworm" % n}, "version": "1"}}}
print(json.dumps({"vulnerabilities": [f("CVE-2001-000%d" % i, n) for i, n in enumerate("abcdefg", 1)]}))' > "$d3c/b"
echo '{"artifacts": []}' > "$d3c/sbom"
if python3 "$root/bin/scout-selfcheck.py" probe-doc3 "$d3c/b" "$d3c/sbom" "FosterStack LLC" ghcr.io/fosterstack/cache selfcheck "$d3c/v.json" >/dev/null 2>&1 \
   && grep -q '"pkg:deb/debian/a@1?os_distro=bookworm"' "$d3c/v.json"; then pass=$((pass+1)); echo "PASS probe3-name-is-purl"
else failn=$((failn+1)); echo "FAIL probe3-name-is-purl"; fi
probe_case one-applied "applied: pkg:docker/ghcr.io/fosterstack/cache@selfcheck" "$PB" "$PA"
if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); s=d["statements"]; assert d["author"]=="FosterStack LLC" and len(s)==len({x["vulnerability"]["name"] for x in s})>=5 and all(x["status"]=="not_affected" for x in s) and any(p["@id"]=="pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache" for x in s for p in x["products"])' "$d0/v.json"; then
  pass=$((pass+1)); echo "PASS probe-document: our author, one CVE per form, our published form among them"
else failn=$((failn+1)); echo "FAIL probe-document"; fi
case_ real                    ok  ""
case_ google-arm64            bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace('--override-arch amd64', '--override-arch arm64')"
case_ grype-five-images       bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('for v in production debug fips', 'for v in production debug')"
case_ computed-images         bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('for arch in amd64 arm64', 'for arch in \$ARCHES')"
case_ scanner-reports-back    bad "$J['scanner-reports'] = {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'osv-scanner scan image x'}]}"
case_ osv-in-panel            bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'] + '\\nosv-scanner scan image x'"
case_ trivy-back              bad "$J['trivy-main'] = {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'trivy image x'}]}"
case_ google-secret           bad "[s.__setitem__('with', {'credentials_json': '\${{ secrets.GCP_KEY }}'}) for s in $J['panel-google']['steps'] if str(s.get('uses','')).startswith('google-github-actions/auth@')]"
case_ google-literal-provider bad "[s['with'].__setitem__('workload_identity_provider', 'projects/1/locations/global/workloadIdentityPools/p/providers/q') for s in $J['panel-google']['steps'] if str(s.get('uses','')).startswith('google-github-actions/auth@')]"
case_ google-no-idtoken       bad "$J['panel-google']['permissions'].pop('id-token')"
case_ grype-no-vex            bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('--vex .vex/fosterstack-cache.openvex.json', '')"
case_ scout-no-author         bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace(\"--vex-author '^FosterStack LLC\$' \", '')"
case_ scout-no-selfcheck      bad "$J['panel-scout']['steps'] = [s for s in $J['panel-scout']['steps'] if 'self-check' not in (s.get('name') or '')]"
case_ scout-selfcheck-soft    bad "[s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]['continue-on-error'] = 'true'"
case_ scout-selfcheck-exit0   bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = 'exit 0\n' + s['run']"
case_ scout-selfcheck-nojudge bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('python3 bin/scout-selfcheck.py', 'true')"
case_ scout-selfcheck-same    bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('.\"fixture-ours\"', '.\"fixture-before\"')"
case_ scout-selfcheck-other-repo bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('ghcr.io/fosterstack/cache-scout-probe', 'ghcr.io/another-vendor/cache-scout-probe')"
case_ scout-scan-other-repo   bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('ghcr.io/fosterstack/cache-scout-probe', 'ghcr.io/fosterstack/cache')"
case_ scout-scan-local-vex    bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('--vex-author', '--vex-location .vex/fosterstack-cache.openvex.json --vex-author')"
case_ scout-scan-no-author    bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace(\"--vex-author '^FosterStack LLC\$' \", '')"
case_ scout-scan-wrong-digest bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('.[\$v]', '.production')"
case_ scout-no-attach-need    bad "$J['panel-scout']['needs'] = ['build', 'assemble']"
case_ scout-perms-write       bad "$J['panel-scout']['permissions']['packages'] = 'write'"
case_ scout-diag-fails        bad "s = [s for s in $J['panel-scout']['steps'] if 'diagnostics' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('exit 0', 'exit \$rc')"
case_ scout-diag-gone         bad "$J['panel-scout']['steps'] = [s for s in $J['panel-scout']['steps'] if 'diagnostics' not in (s.get('name') or '')]"
case_ attach-gone             bad "$J.pop('vex-attach')"
case_ attach-perms-id-token   bad "$J['vex-attach']['permissions']['id-token'] = 'write'"
case_ attach-perms-wide       bad "$J['vex-attach']['permissions']['contents'] = 'write'"
case_ attach-environment      bad "$J['vex-attach']['environment'] = 'agent'"
case_ attach-conditional      bad "$J['vex-attach']['if'] = \"github.ref == 'refs/heads/main'\""
case_ attach-no-assemble-need bad "$J['vex-attach']['needs'] = ['build']"
case_ attach-release-package  bad "s = $(step_of vex-attach 'vex-index.py layout'); s['run'] = s['run'].replace('docker://ghcr.io/fosterstack/cache-scout-probe:', 'docker://ghcr.io/fosterstack/cache:')"
case_ attach-candidates-package bad "s = $(step_of vex-attach 'vex-index.py layout'); s['run'] = s['run'].replace('docker://ghcr.io/fosterstack/cache-scout-probe:', 'docker://ghcr.io/fosterstack/cache-candidates:')"
case_ attach-other-tag        bad "s = $(step_of vex-attach 'vex-index.py layout'); s['run'] = s['run'].replace('tag=\"cand-\${GITHUB_RUN_ID}-\${v}\"', 'tag=\"latest\"')"
case_ attach-no-verify        bad "s = $(step_of vex-attach 'vex-index.py layout'); s['run'] = s['run'].replace('python3 bin/vex-index.py verify-layout', 'true')"
case_ attach-no-layout-check  bad "s = $(step_of vex-attach 'vex-index.py layout'); s['run'] = s['run'].replace('python3 bin/release-layout.py', 'true')"
case_ attach-no-digest-check  bad "s = $(step_of vex-attach 'vex-index.py layout'); s['run'] = s['run'].replace('[ \"\${pushed}\" = \"\${final}\" ]', 'true')"
case_ attach-other-vex        bad "s = $(step_of vex-attach 'vex-index.py layout'); s['run'] = s['run'].replace('vex=.vex/fosterstack-cache.openvex.json', 'vex=/dev/null')"
case_ attach-step-soft        bad "s = $(step_of vex-attach 'vex-index.py layout'); s['continue-on-error'] = 'true'"
case_ prune-gone              bad "$J['vex-attach']['steps'] = [s for s in $J['vex-attach']['steps'] if 'prune' not in (s.get('name') or '')]"
case_ prune-other-package     bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('packages/container/cache-scout-probe', 'packages/container/cache')"
case_ prune-forever           bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('timedelta(days=14)', 'timedelta(days=3650)')"
case_ prune-list-masked       bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('cat \"\$RUNNER_TEMP/prune.err\" >&2; echo \"::error::could not list', 'echo \"::warning::could not list').replace('exit 1\n          fi\n          n=0', 'ids=\"\"\n          fi\n          n=0')"
case_ prune-delete-soft       bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('[ \"\${failed}\" -eq 0 ] ||', 'true ||')"
case_ prune-after-pushes      bad "st = $J['vex-attach']['steps']; k = [i for i, x in enumerate(st) if 'prune' in (x.get('name') or '')][0]; st.append(st.pop(k))"
case_ fixture-extra-tag       bad "s = [s for s in $J['vex-attach']['steps'] if 'self-check fixtures' in (s.get('name') or '')][0]; s['run'] = s['run'] + '\nskopeo copy --all oci:/tmp/layout/fixture docker://ghcr.io/fosterstack/cache-scout-probe:selfcheck-docker-1\n'"
case_ fixture-no-digest-check bad "s = [s for s in $J['vex-attach']['steps'] if 'self-check fixtures' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('--digestfile /tmp/attach/ours.pushed ', '')"
case_ scout-no-vex            bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('--format gitlab', '--format sarif')"
case_ grype-only-fixed        bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('grype ', 'grype --only-fixed ', 1)"
case_ audits-elsewhere        bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'].replace('bin/panel.py tally', 'bin/panel.py collect')"
case_ google-amd64-gone        bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace('cand-\${v}-amd64', 'cand-\${v}')"
case_ no-schedule             bad "d['on'].pop('schedule')"
case_ scan-disabled           bad "s=$(step_of panel-inspector 'for v in'); s['if'] = 'false'"
case_ scan-may-fail           bad "s=$(step_of panel-grype 'for v in'); s['continue-on-error'] = 'true'"
case_ job-disabled            bad "$J['panel-scout']['if'] = 'false'"
case_ no-issue-step           bad "$J['panel']['steps'] = [s for s in $J['panel']['steps'] if 'gh issue' not in (s.get('run') or '')]"
case_ issue-from-any-branch   bad "[s.__setitem__('if', '\${{ always() }}') for s in $J['panel']['steps'] if 'gh issue' in (s.get('run') or '')]"
case_ no-final-failure        bad "$J['panel']['steps'] = $J['panel']['steps'][:-1]"
case_ yearly-schedule         bad "d['on']['schedule'][0]['cron'] = '41 7 1 1 *'"
case_ google-no-environment   bad "$J['panel-google'].pop('environment')"
case_ grype-amd64-twice       bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('for arch in amd64 arm64', 'for arch in amd64 amd64')"
case_ issue-exits-early       bad "[s.__setitem__('run', 'exit 0\n' + s['run']) for s in $J['panel']['steps'] if 'gh issue' in (s.get('run') or '')]"
case_ rc-forced-zero          bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'].replace('echo \"rc=\$?\"', 'echo \"rc=0\"')"
case_ google-no-log-http      bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace(' --log-http', '')"
case_ panel-audits             bad "$J['panel']['permissions']['id-token'] = 'write'"
case_ panel-reads-history     bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'].replace('--out', '--prior /tmp/prior/judgments.json --out')"
case_ panel-skips-on-failure  bad "$J['panel']['if'] = 'success()'"
# The auditor (auditor.yml) runs no scanner of its own: it reads the panel's verdict (handoffs 0518/0600, owner:
# "the auditor reads the four"). No Trivy, Snyk or OSV-Scanner install or token, no copy of the retired scanner reports.
aud_case() {
  local f="$work/aud-$1.yml"
  cp "$root/.github/workflows/auditor.yml" "$f"
  [ -n "$3" ] && python3 - "$f" "$3" <<'PY'
import sys
p, edit = sys.argv[1], sys.argv[2]
t = open(p).read()
old, new = edit.split("=>", 1)
assert old in t or old == "", "mutation target missing"
open(p, "w").write(t.replace(old, new) if old else t + new)
PY
  if out=$(python3 - "$f" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
bad = []
for w in ("trivy", "osv-scanner", "snyk", "SNYK_TOKEN", "rescan-scanner-reports", "--rescan-reports"):
    if w.lower() in t.lower():
        bad.append(f"auditor.yml still mentions {w}")
# Grype's name stays in comments (the panel's Grype is the rescan's job), but no executable text may name it: not an
# install, a run, a loop variable or a quoted target. Shell comments (whole-line, or after whitespace outside quotes) are dropped first.
def strip_comment(l):
    q = None; esc = False
    for k, c in enumerate(l):
        if esc: esc = False; continue                      # the character after a backslash is literal (outside single quotes)
        if c == "\\" and q != "'": esc = True
        elif q:
            if c == q: q = None
        elif c in "'\"": q = c
        elif c == "#" and (k == 0 or l[k - 1].isspace()): return l[:k]
    return l
for l in t.splitlines():
    if re.search(r"\bgrype\b", strip_comment(l), re.I):
        bad.append("auditor.yml names grype outside a comment: " + l.strip()[:60])
if "--panel-dir" not in t:
    bad.append("auditor.yml does not hand the panel evidence to the manifest")
print("; ".join(bad) or "clean"); sys.exit(1 if bad else 0)
PY
  ); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS auditor-$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL auditor-$1 → $got, want $2 ($out)"; fi
}
aud_case real           ok  ""
aud_case trivy-install  bad "=>
          ./bin/install-scanner.sh trivy
"
aud_case osv-install    bad "=>
          ./bin/install-scanner.sh osv-scanner
"
aud_case snyk-token     bad '=>
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
'
aud_case grype-install  bad "=>
          ./bin/install-scanner.sh grype
"
aud_case grype-run      bad "=>
          grype docker:x -o json > g.json
"
aud_case grype-comment  ok  "=>
          # grype is the rescan panel's job, not the auditor's
"
aud_case grype-inline-comment ok "=>
          true # grype docker:x -o json
"
aud_case grype-after-escaped-quote bad '=>
          echo "say \" # still inside the string"; grype docker:x -o json
'
aud_case grype-loop     bad "=>
          for s in grype syft; do sudo ./bin/install-scanner.sh \"\$s\"; done
"
aud_case grype-quoted   bad "=>
          grype \"docker:\${ref}\" -o json
"
aud_case grype-bare-ref bad "=>
          grype ghcr.io/fosterstack/cache:latest -o json
"
aud_case reports-download bad '=>
          gh run download "$rid" -n rescan-scanner-reports -D x
'
aud_case reports-option bad "=>
            --rescan-reports x
"
aud_case no-panel-dir   bad "--panel-dir =>--panel-evidence "
echo "panel-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
