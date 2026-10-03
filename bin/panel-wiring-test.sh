#!/usr/bin/env bash
# proves: REQ-SCAN-001-AC1, REQ-SCAN-001-AC2, REQ-SCAN-001-AC3, REQ-SCAN-002-AC1, REQ-SCAN-004-AC1, REQ-SCAN-004-AC2, REQ-SCAN-009-AC5, REQ-REL-004-AC3
# The scanner panel's wiring in the daily rescan (scanner-panel rules 1, 2, 4, 9; ratified Oct 2): which
# scanner runs on which images (fixed in the workflow, never computed), Google only through the federation
# with repository variables, the VEX as the only exception (Grype and Scout given the file, no ignore
# options anywhere), Trivy and Snyk gone from the panel, and no audit in the rescan (the auditor judges unique findings). The
# real workflow must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export PANEL_ROOT="$root"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
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
    # scanner-reports hands the auditor its inputs; manifests/rescan are the PUBLISHED-release rescan (merged from
    # daily-rescan.yml, consolidation 3 of 4; REQ-REL-003), which runs only the scanners in .github/policy/scanners.json —
    # none of the three is the scanner panel
    if any(x in (text(j) + " ".join(uses(j))).lower() for x in ("trivy", "snyk")) and j not in ("scanner-reports", "manifests", "rescan"):
        bad.append(f"{j} runs Trivy or Snyk")
for gone in ("scan-main", "trivy-main", "snyk-main"):
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
# Scout applies only statements by an author --vex-author accepts (default Docker's own; rule 4). Proven by RUNNING the
# two Scout steps of the (possibly mutated) workflow against a stub docker/skopeo (Codex #168 r1, B1/B2): the executed
# arguments, and the self-check's verdict on reports where Scout applies, ignores, over-drops or returns nothing
import json, os, subprocess, tempfile
ROOT = os.environ.get("PANEL_ROOT", ".")
FIXTURE = "docker://docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab"
STUB = r"""#!/usr/bin/env bash
{ printf '%s' "$(basename "$0")"; printf ' %q' "$@"; printf '\n'; } >> "$STUB_LOG"
if [ "$(basename "$0")" = docker ] && [ "$1 $2" = "scout cves" ]; then
  vex=""; prev=""; for a in "$@"; do [ "$prev" = --vex-location ] && vex=$a; prev=$a; done
  [ -f "$vex" ] && cp "$vex" "$STUB_LOG.vex.$(wc -l < "$STUB_LOG" | tr -d ' ')"
  n=$(jq '[.statements[].vulnerability.name] | map(select(. == "CVE-2023-4911")) | length' "$vex" 2>/dev/null || echo 0)
  case "$STUB_MODE:$n" in
    *:0|ignores:*) printf '%s' '{"vulnerabilities":[{"identifiers":[{"value":"CVE-2023-4911"}],"location":{"dependency":{"package":{"name":"libc6"},"version":"2.36-9"}}},{"identifiers":[{"value":"CVE-2099-0001"}],"location":{"dependency":{"package":{"name":"libalpha"},"version":"1.0"}}}]}' ;;
    applies:*) printf '%s' '{"vulnerabilities":[{"identifiers":[{"value":"CVE-2099-0001"}],"location":{"dependency":{"package":{"name":"libalpha"},"version":"1.0"}}}]}' ;;
    drops-all:*) printf '%s' '{"vulnerabilities":[]}' ;;
    empty:*) printf '%s' '{}' ;;
  esac
elif [ "$(basename "$0")" = docker ] && [ "$1 $2" = "scout sbom" ]; then
  printf '%s' '{"artifacts":[]}'
fi
exit 0
"""
author = json.load(open(os.path.join(ROOT, ".vex/fosterstack-cache.openvex.json")))["author"]
VEXCOPIES = []
KEEP = tempfile.mkdtemp()
scout_steps = jobs.get("panel-scout", {}).get("steps", [])
def step(name_part):
    hit = [s for s in scout_steps if name_part in (s.get("name") or "")]
    return hit[0] if len(hit) == 1 else None
def run_block(block, mode):
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "stub"))
        for tool in ("docker", "skopeo", "sudo"):
            with open(os.path.join(t, "stub", tool), "w") as fh:
                fh.write(STUB)
            os.chmod(os.path.join(t, "stub", tool), 0o755)
        log = os.path.join(t, "log")
        open(log, "w").close()
        env = dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], STUB_LOG=log, STUB_MODE=mode,
                   RUNNER_TEMP=t)
        r = subprocess.run(["bash", "-e", "-c", block], cwd=ROOT, env=env, capture_output=True, text=True)
        VEXCOPIES[:] = []
        import glob, shutil
        for x in glob.glob(log + ".vex.*"):
            keep = os.path.join(KEEP, os.path.basename(x))
            shutil.copy(x, keep)
            VEXCOPIES.append(keep)
        return r.returncode, open(log).read().splitlines()
pr = step("product-form probe")
if not pr or scout_steps.index(pr) > scout_steps.index(step("rule 4 self-check") or pr):
    bad.append("no Scout product-form probe before the self-check (advisor 0106)")
else:
    prun = pr.get("run", "")
    for need in ("./bin/scout-vex-scan.sh ghcr.io/fosterstack/cache:selfcheck", "scout-selfcheck.py probe-doc",
                 "scout-selfcheck.py probe-report", "--only-vex-affected", 'tee -a "$GITHUB_STEP_SUMMARY"'):
        if need not in prun:
            bad.append("the probe lacks %s" % need)
    if pr.get("if") != "github.event_name == 'workflow_dispatch'" or pr.get("continue-on-error"):
        bad.append("the probe must run on a manual dispatch only, without continue-on-error (Codex #170 r1, R1)")
    for failing in ("sudo", "skopeo", "mkdir", "docker"):   # Codex #170 r1, B1: a diagnostic failure never fails the step
        with tempfile.TemporaryDirectory() as t:
            os.makedirs(os.path.join(t, "stub"))
            for tool in ("docker", "skopeo", "sudo", failing):   # the others succeed; only the one under test fails
                with open(os.path.join(t, "stub", tool), "w") as fh:
                    fh.write("#!/usr/bin/env bash\nexit 23\n" if tool == failing else STUB)
                os.chmod(os.path.join(t, "stub", tool), 0o755)
            open(os.path.join(t, "log"), "w").close()
            r = subprocess.run(["bash", "-e", "-c", prun], cwd=ROOT, capture_output=True, text=True,
                               env=dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"],
                                        RUNNER_TEMP=t, GITHUB_STEP_SUMMARY=os.path.join(t, "sum"),
                                        STUB_LOG=os.path.join(t, "log"), STUB_MODE="applies"))
        if r.returncode != 0:
            bad.append("the probe step fails the job when %s fails (exit %d)" % (failing, r.returncode))
sc, scan = step("rule 4 self-check"), step("Docker Scout every image")
if not sc or not scan or scout_steps.index(sc) > scout_steps.index(scan):
    bad.append("no Scout self-check before the scan")
else:
    if sc.get("continue-on-error") or sc.get("if"):
        bad.append("the Scout self-check can be skipped or softened")
    rc, log = run_block(sc.get("run", ""), "applies")
    scouts = [l for l in log if l.startswith("docker scout cves")]
    if rc != 0:
        bad.append("the Scout self-check fails when Scout applies our statement")
    # the WHOLE argument array, only the VEX path free (Codex #168 r3, B1: an extra option in between must fail)
    want_sc = re.compile(r"docker scout cves --format gitlab --vex-location [^ ]+ --vex-author "
                         r"\\\^FosterStack\\ LLC\\\$ local://ghcr\.io/fosterstack/cache:selfcheck")
    if len(scouts) != 2 or not all(want_sc.fullmatch(l) for l in scouts):
        bad.append("the self-check does not run Scout with our author on the fixture under our name: %s" % scouts)
    # the VEX documents the self-check hands Scout: ours by author, the second covering exactly the target on our image
    try:
        docs = [json.load(open(x)) for x in sorted(VEXCOPIES, key=lambda p: int(p.rsplit(".", 1)[1]))]
    except (OSError, ValueError):
        docs = []
    want_stmt = {"vulnerability": {"name": "CVE-2023-4911"}, "status": "not_affected",
                 "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]}
    def stmt_ok(st, cve):
        return {k: st.get(k) for k in want_stmt} == dict(want_stmt, vulnerability={"name": cve})
    if len(docs) != 2 or any(d.get("author") != author for d in docs) \
            or len(docs[0].get("statements") or []) != 1 or not stmt_ok(docs[0]["statements"][0], "CVE-1999-0001") \
            or len(docs[1].get("statements") or []) != 1 or not stmt_ok(docs[1]["statements"][0], "CVE-2023-4911"):
        bad.append("the self-check's VEX documents are not ours (author, product, status, CVE): %s" % docs)
    if "skopeo copy " + FIXTURE + " docker-daemon:ghcr.io/fosterstack/cache:selfcheck" not in log:
        bad.append("the self-check does not load the pinned fixture by digest")
    for mode in ("ignores", "drops-all", "empty"):
        if run_block(sc.get("run", ""), mode)[0] == 0:
            bad.append("the Scout self-check passes when Scout %s" % mode)
    rc, log = run_block(scan.get("run", ""), "applies")
    scouts = [l for l in log if l.startswith("docker scout cves")]
    want = ["docker scout cves --format gitlab --vex-location .vex/fosterstack-cache.openvex.json --vex-author "
            "\\^FosterStack\\ LLC\\$ local://ghcr.io/fosterstack/cache:cand-%s-%s" % (v, a)
            for v in ("production", "debug", "fips") for a in ("amd64", "arm64")]
    if scouts != want:
        bad.append("Scout's scan does not run with our VEX and author on our six images: %s" % scouts)
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
for j in ("panel-grype", "panel-scout", "panel-inspector"):
    t = text(j)
    if not re.search(r"for arch in amd64 arm64; do", t) or t.count("for arch in") != 1 \
            or '--override-arch "${arch}"' not in t or 'cand-${v}-${arch}' not in t:
        bad.append(f"{j} does not load each architecture once by the loop variable")
if "--log-http" not in tg or "bin/panel.py google-packages" not in tg or "list-vulnerabilities" not in tg:
    bad.append("panel-google does not take its package count from the request log and its findings from list-vulnerabilities")
if jobs["panel-google"].get("environment") != "agent":
    bad.append("panel-google is not in the main-only agent environment (its identity admits a scheduled main run only there)")
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google", "panel"):
    if "if" in jobs[j] and j != "panel":
        bad.append(f"{j} is conditional")
    for st in jobs[j].get("steps", []):
        cond = str(st.get("if", "")).replace(" ", "")
        # the one exception: the Scout product-form probe, a manual-dispatch diagnostic that never decides the job
        # (advisor 0106; its own containment and its place before the unconditional self-check are checked below)
        diag = j == "panel-scout" and st.get("name") == "Scout product-form probe (rule 4 diagnostic, advisor 0106)" \
            and cond == "github.event_name=='workflow_dispatch'"
        if cond and not diag and not cond.startswith("${{always()") and "steps.judge" not in cond:
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
# Codex #168 r2 (B1): the helper's argument boundaries are what is checked — a mutated copy of bin/scout-vex-scan.sh in
# a scratch root must fail the real workflow's judge
helper_case() {   # name sed-expression
  local r="$work/root-$1"; mkdir -p "$r/bin" "$r/.vex"
  cp "$root/bin/scout-selfcheck.py" "$r/bin/"; cp "$root/.vex/fosterstack-cache.openvex.json" "$r/.vex/"
  sed "$2" "$root/bin/scout-vex-scan.sh" > "$r/bin/scout-vex-scan.sh"; chmod +x "$r/bin/scout-vex-scan.sh"
  cmp -s "$root/bin/scout-vex-scan.sh" "$r/bin/scout-vex-scan.sh" && { failn=$((failn+1)); echo "FAIL helper-$1: the mutation did not apply"; return; }
  if out=$(PANEL_ROOT="$r" judge "$root/.github/workflows/main-candidate-rescan.yml"); then got=ok; else got=bad; fi
  if [ "$got" = bad ]; then pass=$((pass+1)); echo "PASS helper-$1 → bad"; else failn=$((failn+1)); echo "FAIL helper-$1 → ok, want bad"; fi
}
helper_case unquoted-author 's/--vex-author "\$re"/--vex-author $re/'
helper_case merged-image    's/"\$re" "local:\/\/\$1"/"\$re local:\/\/\$1"/'
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
probe_case one-applied "applied: pkg:docker/ghcr.io/fosterstack/cache@selfcheck" "$PB" "$PA"
if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); s=d["statements"]; assert d["author"]=="FosterStack LLC" and len(s)==len({x["vulnerability"]["name"] for x in s})>=5 and all(x["status"]=="not_affected" for x in s) and any(p["@id"]=="pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache" for x in s for p in x["products"])' "$d0/v.json"; then
  pass=$((pass+1)); echo "PASS probe-document: our author, one CVE per form, our published form among them"
else failn=$((failn+1)); echo "FAIL probe-document"; fi
case_ real                    ok  ""
case_ google-arm64            bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace('--override-arch amd64', '--override-arch arm64')"
case_ grype-five-images       bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('for v in production debug fips', 'for v in production debug')"
case_ computed-images         bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('for arch in amd64 arm64', 'for arch in \$ARCHES')"
case_ trivy-back              bad "$J['trivy-main'] = {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'trivy image x'}]}"
case_ google-secret           bad "[s.__setitem__('with', {'credentials_json': '\${{ secrets.GCP_KEY }}'}) for s in $J['panel-google']['steps'] if str(s.get('uses','')).startswith('google-github-actions/auth@')]"
case_ google-literal-provider bad "[s['with'].__setitem__('workload_identity_provider', 'projects/1/locations/global/workloadIdentityPools/p/providers/q') for s in $J['panel-google']['steps'] if str(s.get('uses','')).startswith('google-github-actions/auth@')]"
case_ google-no-idtoken       bad "$J['panel-google']['permissions'].pop('id-token')"
case_ grype-no-vex            bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('--vex .vex/fosterstack-cache.openvex.json', '')"
case_ scout-no-author         bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('./bin/scout-vex-scan.sh \"\${ref}\" .vex/fosterstack-cache.openvex.json \"\${d}/cves.json\"', 'docker scout cves --format gitlab --vex-location .vex/fosterstack-cache.openvex.json \"local://\${ref}\" > \"\${d}/cves.json\"  # --vex-author ^FosterStack LLC\$')"
case_ scout-no-selfcheck      bad "$J['panel-scout']['steps'] = [s for s in $J['panel-scout']['steps'] if 'self-check' not in (s.get('name') or '')]"
case_ scout-selfcheck-soft    bad "[s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]['continue-on-error'] = 'true'"
case_ scout-selfcheck-exit0   bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = 'exit 0\n' + s['run']"
case_ scout-selfcheck-nojudge bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('python3 bin/scout-selfcheck.py', 'true')"
case_ scout-selfcheck-novex   bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('\"\$RUNNER_TEMP/selfcheck/one.json\"', '\"\$RUNNER_TEMP/selfcheck/none.json\"')"
case_ scout-other-repo        bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('ghcr.io/fosterstack/cache:cand-', 'ghcr.io/another-vendor/cache:cand-')"
case_ scout-fixture-tag       bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab', 'debian:latest') + '\n# debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab'"
case_ scout-vex-other-repo    bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('repository_url=ghcr.io/fosterstack/cache\"}]}]\' \"\$RUNNER_TEMP/selfcheck/one.json', 'repository_url=ghcr.io/another-vendor/cache\"}]}]\' \"\$RUNNER_TEMP/selfcheck/one.json')"
case_ scout-vex-affected      bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('\"CVE-2023-4911\"}, \"status\": \"not_affected\"', '\"CVE-2023-4911\"}, \"status\": \"affected\"')"
case_ scout-fixture-elsewhere bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('docker-daemon:ghcr.io/fosterstack/cache:selfcheck', 'docker-daemon:another-vendor/cache:selfcheck')"
case_ scout-sc-extra-option  bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('./bin/scout-vex-scan.sh ghcr.io/fosterstack/cache:selfcheck \"\$RUNNER_TEMP/selfcheck/one.json\" \"\$RUNNER_TEMP/selfcheck/after.json\"', 'docker scout cves --format gitlab --vex-location \"\$RUNNER_TEMP/selfcheck/one.json\" --only-vex-affected --vex-author \'^FosterStack LLC\$\' local://ghcr.io/fosterstack/cache:selfcheck > \"\$RUNNER_TEMP/selfcheck/after.json\"'); assert 'only-vex-affected' in s['run']"
case_ scout-no-vex            bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('.vex/fosterstack-cache.openvex.json \"\${d}', '/dev/null \"\${d}')"
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
echo "panel-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
