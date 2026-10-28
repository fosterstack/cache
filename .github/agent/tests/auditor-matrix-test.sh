#!/usr/bin/env bash
# proves: REQ-AUD-018-AC1, REQ-AUD-018-AC2, REQ-AUD-018-AC3, REQ-REL-012-AC4, REQ-REL-012-AC5, REQ-REL-012-AC6
# Matrix-first EFFECT-OBSERVING failing suite for the daily CVE auditor
# (.github/agent/docs/cve-auditor-matrix.md). Round-7 hardening after the second review
# pass. Fixtures are inputs only, in neutral files with no prose; the mapping from
# neutral name to scenario lives ONLY here and in fixtures/README.md (which no
# command under test may read — the mutants harness proves the suite is identical
# with the README moved away). Every effect assertion parses the whole artifact and
# checks each field the AC names by identity (the statement for the finding under
# test, not statements[0]); every case pairs a positive with a contrasting input so
# a constant writer fails one of the pair. The workflow is parsed with vendored
# PyYAML over the parsed document, never raw text. A strict harness fails a case on
# any nonzero exit; there is no run2 and no `|| true`.
#
# Neutral fixture -> scenario map:
#   scanners/grype.json trivy.json osv-image.json osv-gomod.json snyk.json  real captures
#   govulncheck/gv-01.json  reachable stream (GO-2021-0113 called; GO-2020-0015 not)
#   govulncheck/gv-02.json  imported-only stream
#   run/manifest-01.json    the run (report paths + digests only)
#   run-state/rs-01.json    clean run; rs-02.json scanner-down; rs-03.json post-classify
#   dl/log.json findings-01(no-change) findings-02(one miss) schema.json
#   poam/poam-01 below-threshold  poam-02 KEV  poam-03 critical-only  poam-04 expired
#   release/cand-01 critical cand-02 below ; iss-01 accepted iss-02 unaccepted
#            iss-03 wrong-author iss-04 review-only
#   suppression/disp-01 disposition ; set-01/ deliberately inconsistent set
#   policy/env-01 good-env env-02 non-main ; rule-01 no-bypass rule-02 bypass
#   adjudicator/scenario-01 refusal scenario ; stub/fail-on-call/fake-github doubles
# Run:  bash .github/agent/tests/auditor-matrix-test.sh   (CI: ci.yml, required 'allowlist' job)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/../../.." && pwd)"; cd "$repo"
PY=python3
F=".github/agent/fixtures"
BIN=".github/agent/bin"
WF=".github/workflows/auditor.yml"
STUB="$F/adjudicator/stub-adjudicator.py"
NOCALL="$F/adjudicator/fail-on-call.py"
GH="$F/adjudicator/fake-github-api.py"
YAML="$PY $F/testlib/yamlshape.py"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
# The run fixtures (verdicts and the manifests that name them) were written for one panel image set; the suite works on a copy adapted to the
# CURRENT set (bin/panel.py VARIANTS: main ships debug, chain-v030 drops it), so it passes with either (verdict_fixture.py).
FX="$WORK/fx"; mkdir -p "$FX"; cp -R "$F/run" "$FX/run"; export FXRUN="$FX/run"
"$PY" "$BIN/tests/verdict_fixture.py" materialize "$FXRUN" || { echo "materialize failed" >&2; exit 2; }
export TMPDIR="$WORK"   # every tempfile/mktemp a case makes lands in the cleaned-up work dir (no fixed system temp path)
LEDGER="$WORK/model.ledger"; export AUDITOR_MODEL_LEDGER="$LEDGER"
# The live delivery path merges suppressions into GITHUB_WORKSPACE (default: cwd = this checkout).
# Every case runs against a throwaway workspace instead, so the suite never rewrites the real
# .vex/.snyk/osv-scanner.toml/.auditor (REQ-AUD-18); a case needing its own sets it explicitly.
export GITHUB_WORKSPACE="$WORK/workspace"; mkdir -p "$GITHUB_WORKSPACE"; cp -R .vex "$GITHUB_WORKSPACE/" 2>/dev/null || true
MISS="__MISSING__"
pass=0; fail=0
# snapshot of the checkout: the suite must leave it exactly as it found it (final case).
REPO_STATE0="$(git status --porcelain --untracked-files=all 2>/dev/null)"
CASE=""; DESC=""
begin(){ CASE="$1"; DESC="$2"; : > "$LEDGER"; }
ok(){ echo "ok:   $CASE"; pass=$((pass+1)); }
no(){ echo "FAIL: $CASE — $DESC"; echo "        want: $1"; echo "        got:  $2"; fail=$((fail+1)); }
RC=0; OUT=""
run(){ local e="$WORK/stderr"; OUT="$("$@" 2>"$e")"; RC=$?
  if [ "$RC" -ne 0 ]; then no "the command to exit 0 and write its effect" "command absent / exit $RC: $(tail -1 "$e" 2>/dev/null)"; return 1; fi; return 0; }
# pj <file> <expr d>: read a field from a JSON file; sentinel on any failure.
pj(){ "$PY" -c 'import json,sys
try:
    d=json.load(open(sys.argv[1])); v=eval(sys.argv[2])
    sys.stdout.write("__MISSING__" if v is None else (v if isinstance(v,str) else json.dumps(v)))
except Exception: sys.stdout.write("__MISSING__")' "$1" "$2" 2>/dev/null || printf '%s' "$MISS"; }
# vf <openvexfile> <cve> <expr s>: the STATEMENT whose vulnerability.name==cve.
vf(){ "$PY" -c 'import json,sys
try:
    d=json.load(open(sys.argv[1])); s=[x for x in d.get("statements",[]) if (x.get("vulnerability") or {}).get("name")==sys.argv[2]]
    if not s: sys.stdout.write("__MISSING__")
    else:
        s=s[0]; v=eval(sys.argv[3]); sys.stdout.write("__MISSING__" if v is None else (v if isinstance(v,str) else json.dumps(v)))
except Exception: sys.stdout.write("__MISSING__")' "$1" "$2" "$3" 2>/dev/null || printf '%s' "$MISS"; }
# tree_has_vex_for <dir> <cve>: any OpenVEX statement anywhere under dir names cve.
tree_has_vex_for(){ "$PY" -c 'import json,os,sys
root,cve=sys.argv[1],sys.argv[2]; hit="no"
for dp,_,fs in os.walk(root):
    for fn in fs:
        if fn.endswith(".json"):
            try:
                d=json.load(open(os.path.join(dp,fn)))
                for st in d.get("statements",[]):
                    if (st.get("vulnerability") or {}).get("name")==cve: hit="yes"
            except Exception: pass
print(hit)' "$1" "$2" 2>/dev/null || echo no; }
# alias_set <finding-id>: every id the panel's verdict gives for that finding (the aliases each scanner reported), read from the
# manifest's verdict - never hand-typed.
alias_set(){ "$PY" -c 'import json,sys
fid=sys.argv[1]; m=json.load(open(sys.argv[2])); ids={fid}
try:
    v=json.load(open(m["panel"]["verdict"]))
    for f in v["findings"]:
        grp={f["id"]}|{a for d in f["details"].values() for a in d.get("aliases", [])}
        if fid in grp: ids|=grp
except Exception: pass
print(" ".join(sorted(ids)))' "$1" "$FX/run/manifest-01.json" 2>/dev/null; }
# tree_vex_status_set <dir> <aliases...>: sorted set of statuses across ALL VEX files
# for ANY of the aliases (empty if none).
tree_vex_status_set(){ local dir="$1"; shift; "$PY" -c 'import json,os,sys
dir=sys.argv[1]; al=set(sys.argv[2:]); st=set()
for dp,_,fs in os.walk(dir):
    for fn in fs:
        if fn.endswith(".json"):
            try:
                d=json.load(open(os.path.join(dp,fn)))
                for s in d.get("statements",[]):
                    if (s.get("vulnerability") or {}).get("name") in al: st.add(s.get("status"))
            except Exception: pass
print(",".join(sorted(x for x in st if x)))' "$dir" "$@" 2>/dev/null; }
# ignore_names_any <dir> <aliases...>: yes if any ignore file names any alias.
ignore_names_any(){ local dir="$1"; shift; local a; for a in "$@"; do
  if grep -rqF -- "$a" "$dir/ignores" "$dir/.snyk" "$dir/osv-scanner.toml" "$dir/.vex" 2>/dev/null; then echo yes; return; fi
  done; echo no; }
# sect_ids <reportfile> <n>: vuln ids under "## n" up to the next "##".
sect_ids(){ "$PY" -c 'import re,sys
try: t=open(sys.argv[1]).read()
except Exception: t=""
n=sys.argv[2]; ids=[]; cur=None
for line in t.splitlines():
    m=re.match(r"\s*#+\s*(\d+)\b",line)
    if m: cur=m.group(1); continue
    if cur==n: ids+=re.findall(r"(?:CVE-\d{4}-\d+|GO-\d{4}-\d+)",line)
print(" ".join(ids))' "$1" "$2" 2>/dev/null; }
is_json(){ "$PY" -c 'import json,sys
try: json.load(open(sys.argv[1])); print("yes")
except Exception: print("no")' "$1" 2>/dev/null || echo no; }
have(){ [ -f "$1" ]; }
ledger_empty(){ [ ! -s "$LEDGER" ]; }
ledger_n(){ grep -c . "$LEDGER" 2>/dev/null || echo 0; }
eq(){ [ "$1" = "$2" ]; }
digest="sha256:3d868b5eb908155f3784317b3dda2941df87bbbbaa4608f84881de66d9bb297b"
rs01digest="sha256:8df991b5febdf5b4a177325b8af95b6bb6c321059e1715c06cb659c659f5a4f0"

# preflight: the PyYAML-based reader must parse two real workflows and a quoted-`on`
# variant identically; else the workflow cases are meaningless. Not a scored case.
# R4: every workflow file must parse as valid YAML (this class can never land).
for w in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -e "$w" ] || continue
  $YAML load "$w" >/dev/null 2>"$WORK/yerr" || { echo "PREFLIGHT: invalid workflow YAML in $w — $(tail -1 "$WORK/yerr")" >&2; exit 2; }
done
for w in .github/workflows/main-candidate-rescan.yml "$F/testlib/workflows/quoted-on.yml"; do
  t="$($YAML shape "$w" 2>/dev/null | "$PY" -c 'import json,sys;print(",".join(sorted(json.load(sys.stdin)["triggers"])))' 2>/dev/null)"
  [ "$t" = "schedule,workflow_dispatch" ] || { echo "PREFLIGHT: PyYAML reader mis-parsed $w ($t)" >&2; exit 2; }
done

########################################################################
echo "=== REQ-AUD-1 ==="
# ---- generated panel manifests (scenarios ok, uncounted, nopanel, googlegone, partial, multi) used by the panel and the run cases ----
# The image set is panel.py's, not a literal: main ships debug, chain-v030 drops it (VARIANTS), so the fixtures name "the second
# variant's amd64 image" (DBG) and count the panel's images (NIMG), and pass with either VARIANTS.
DBG="$(python3 -c 'import sys; sys.path.insert(0, ".github/agent/bin"); from auditorlib import parsers as P; print(sorted(i for i in P.panel_images() if i.endswith("-amd64") and not i.startswith("production"))[0])')"
NIMG="$(python3 -c 'import sys; sys.path.insert(0, ".github/agent/bin"); from auditorlib import parsers as P; print(len(P.panel_images()))')"
export DBG NIMG
cat > "$WORK/mkpm.py" <<'PYEOF'
import json, os, sys
sys.path.insert(0, ".github/agent/bin")
from auditorlib import parsers as P
scenario, out = sys.argv[1], sys.argv[2]; os.makedirs(out, exist_ok=True)
pm = P._panel_module(); vp = os.path.join(out, "verdict.json")
images = {}
for im in sorted(P.panel_images()):
    exp = [s for s in P.PANEL_SCANNERS if P.panel_expected(s, im)]
    bad = [s for s in ("scout", "google") if scenario == "uncounted" and im == os.environ["DBG"] and s in exp]
    bad += [s for s in ("google",) if scenario == "googlegone" and im.endswith("-amd64") and s in exp]      # google missing on every image it is expected on
    bad += [s for s in ("google",) if scenario == "partial" and im == os.environ["DBG"] and s in exp]            # google missing on one image only
    ran = sorted(s for s in exp if s not in bad)
    images[im] = {"counts": {s: 10 for s in ran}, "did_not_run": sorted(bad), "ran": ran, "counts_for_day": len(ran) >= 3}
def f(im, vid, pkg, ver, seen, details):
    purl = "pkg:deb/debian/%s@%s?arch=%s&distro=debian-12.0" % (pkg, ver, "arm64" if pkg == "coreutils" else "amd64")    # the known-defect log keys on these exact purls
    details = {s_: dict(d_, purl=purl) for s_, d_ in details.items()}                                                      # each scanner's own package URL (handoff 0601)
    return {"image": im, "id": vid, "package": pkg, "version": ver, "seen_by": sorted(seen), "of": len(images[im]["ran"]),
            "unique": len(seen) == 1, "status": "unique" if len(seen) == 1 else "report", "purls": [purl], "details": details}
fs = [f("production-amd64", "CVE-2016-2781", "coreutils", "9.1-1", ["grype", "inspector", "scout"], {"grype": {"severity": "low"}, "inspector": {"severity": "medium"}, "scout": {}}),
      f("production-amd64", "CVE-2011-3374", "apt", "2.6.1", ["grype", "inspector", "scout"], {"grype": {"severity": "high"}, "inspector": {"severity": "critical"}, "scout": {}})]
if scenario == "multi":     # one finding the scanners rate alike, one seen by different numbers of scanners on two images
    fs += [f("production-amd64", "CVE-2099-5555", "zlib", "1.3", ["grype", "inspector"], {"grype": {"severity": "high"}, "inspector": {"severity": "high"}}),
           f("production-amd64", "CVE-2099-6666", "curl", "8.0", ["grype", "inspector", "scout"], {"grype": {"severity": "low"}, "inspector": {"severity": "low"}, "scout": {}}),
           f("production-arm64", "CVE-2099-6666", "curl", "8.0", ["grype", "inspector"], {"grype": {"severity": "low"}, "inspector": {"severity": "low"}})]
if scenario == "partial":   # a finding only google saw, on an image google did run on, while google missed another image
    fs.append(f("production-amd64", "CVE-2099-7777", "busybox", "1.36", ["google"], {"google": {"severity": "critical"}}))
d = {"images": images, "not_counted": sorted(i for i, st in images.items() if not st["counts_for_day"]),
     "scanner_failures": sorted("%s on %s" % (s, i) for i, st in images.items() for s in st["did_not_run"]),
     "findings": fs, "vex_covered": [], "issue": pm.render_issue([x for x in fs if x["status"] == "report"])}
d["unique"] = [x for x in fs if x["unique"]]
d["exit"] = 2 if (d["not_counted"] or d["scanner_failures"]) else 1
json.dump(d, open(vp, "w"))
m = json.load(open(os.path.join(os.environ["FXRUN"], "manifest-01.json")))
m["scanner_set"] = "panel"
if scenario == "nopanel":
    rep = {s: None for s in P.PANEL_SCANNERS}
    st = {s: {"ran": False, "scan_ok": False, "quorum_ok": False, "version": None, "reason": "panel-evidence has no verdict.json", "images_ran": 0, "images_expected": 0, "package_count": 0} for s in P.PANEL_SCANNERS}
    m["panel"] = {"verdict": None, "not_counted": None, "scanner_failures": None, "scanner_reports": rep, "scanner_status": st}
else:
    import importlib.util
    spec = importlib.util.spec_from_file_location("m", ".github/agent/bin/auditor-manifest.py"); M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
    m["panel"] = M.panel_block(out)
m["scanner_reports"] = m["panel"]["scanner_reports"]; m["scanner_status"] = m["panel"]["scanner_status"]
json.dump(m, open(os.path.join(out, "manifest.json"), "w"))
PYEOF
for sc in ok uncounted nopanel googlegone partial multi; do "$PY" "$WORK/mkpm.py" $sc "$WORK/pm-$sc"; done

# g2p.py <manifest.json>: turn a hand-written single-scanner manifest (scanner_reports.grype = a Grype match list, optionally
# scanner_reports.snyk-style siblings ignored) into the panel form the auditor reads: one verdict on production-amd64 holding the
# Grype matches (seen by Grype alone, so each is a unique-lineage finding as before), every scanner "ran" with 10 packages.
cat > "$WORK/g2p.py" <<'PYEOF'
import json, os, sys, importlib.util
sys.path.insert(0, ".github/agent/bin")
from auditorlib import parsers as P
pm = P._panel_module()
spec = importlib.util.spec_from_file_location("m", ".github/agent/bin/auditor-manifest.py"); M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
mp = sys.argv[1]; m = json.load(open(mp)); out = os.path.dirname(mp)
images = {}
for im in sorted(P.panel_images()):
    exp = [s for s in P.PANEL_SCANNERS if P.panel_expected(s, im)]
    images[im] = {"counts": {s: 10 for s in exp}, "did_not_run": [], "ran": sorted(exp), "counts_for_day": True}
fs, seen = [], set()
gp = (m.get("scanner_reports") or {}).get("grype")
for mt in (json.load(open(gp)).get("matches") or [] if gp else []):
    v, a = mt["vulnerability"], mt["artifact"]
    pn, pv = pm._purl_name_version(a["purl"]) if a.get("purl") else (None, None)
    name, ver = a.get("name") or pn, a.get("version") or pv or "0"
    fixv = (v.get("fix") or {}).get("versions") or []
    purl = a.get("purl") or "pkg:generic/%s@%s" % (name, ver)
    im = a.get("image") or "production-amd64"                      # a test may put one artifact on another image
    k = pm.key_of(im, v["id"], name, ver)
    if k in seen: continue
    seen.add(k)
    det = {}
    sev = (v.get("severity") or "").lower()
    if sev in ("negligible", "low", "medium", "high", "critical"): det["severity"] = sev
    if (v.get("fix") or {}).get("state") == "fixed" and fixv: det["fixed_version"] = fixv[0]
    if a.get("purl"): det["purl"] = a["purl"]                          # Grype's own package URL (handoff 0601)
    fs.append({"image": im, "id": v["id"], "package": name, "version": ver, "seen_by": ["grype"], "of": len(images[im]["ran"]), "unique": True,
               "status": "unique", "purls": [purl], "details": {"grype": det}})
sp = (m.get("scanner_reports") or {}).get("snyk")                  # a second, Snyk-shaped report becomes Google's record of the same CVE
for v in (json.load(open(sp)).get("vulnerabilities") or [] if sp else []):
    for cid in ((v.get("identifiers") or {}).get("CVE") or [v["id"]]):
        sv = (v.get("severity") or "").lower()
        hit = [f for f in fs if f["id"] == cid]
        if hit:
            f = hit[0]; f["seen_by"] = ["google", "grype"]; f["unique"] = False; f["status"] = "report"
            f["details"]["google"] = {"severity": sv} if sv in ("negligible", "low", "medium", "high", "critical") else {}
            if v.get("purl"): f["details"]["google"]["purl"] = v["purl"]
        else:
            name, ver = v.get("packageName"), (v.get("version") or (pm._purl_name_version(v["purl"])[1] if v.get("purl") else "1.0") or "1.0")
            fs.append({"image": "production-amd64", "id": cid, "package": name, "version": ver, "seen_by": ["google"], "of": 4, "unique": True,
                       "status": "unique", "purls": [v["purl"]] if v.get("purl") else [], "details": {"google": ({"purl": v["purl"]} if v.get("purl") else {})}})
reported = [f for f in fs if f["status"] == "report"]
d = {"images": images, "not_counted": [], "scanner_failures": [], "findings": fs, "vex_covered": [], "issue": pm.render_issue(reported),
     "unique": [f for f in fs if f["unique"]], "exit": 1 if reported else 0}
os.makedirs(os.path.join(out, "panel"), exist_ok=True)
json.dump(d, open(os.path.join(out, "panel", "verdict.json"), "w"))
m["scanner_set"] = "panel"; m["panel"] = M.panel_block(os.path.join(out, "panel"))
m["scanner_reports"] = m["panel"]["scanner_reports"]; m["scanner_status"] = m["panel"]["scanner_status"]
json.dump(m, open(mp, "w"))
PYEOF

begin "req1-ac1-workflow-path" "one auditor workflow at .github/workflows/auditor.yml and no other auditor workflow"
if ! have "$WF"; then no "$WF present" "absent"; else
  n="$(grep -lRi 'agent/bin/auditor' .github/workflows 2>/dev/null | wc -l | tr -d ' ')"
  a="$(ls .github/workflows/ | grep -ci auditor)"
  { eq "$a" "1"; } && ok || no "exactly one auditor workflow" "named=$a"; fi

begin "req1-ac1-triggers-exactly-schedule-and-dispatch" "on == {schedule, workflow_dispatch} exactly (parsed with PyYAML)"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  t="$(pj "$WORK/sh.json" '",".join(sorted(d["triggers"]))')"
  eq "$t" "schedule,workflow_dispatch" && ok || no "schedule,workflow_dispatch" "$t"; fi

begin "req1-ac1-no-push-pr-triggers" "no push / pull_request / pull_request_target, and the exact set holds"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  bad="$(pj "$WORK/sh.json" '",".join(sorted(set(d["triggers"]) & {"push","pull_request","pull_request_target"}))')"
  t="$(pj "$WORK/sh.json" '",".join(sorted(d["triggers"]))')"
  { [ "$t" = "schedule,workflow_dispatch" ] && [ -z "$bad" ]; } && ok || no "exact set, no push/pr" "triggers=$t forbidden=$bad"; fi

begin "req1-ac1-schedule-cron-offset" "cron is a valid 5-field expr with numeric minute 0-59, not 0/11/41"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  cronok="$(pj "$WORK/sh.json" 'str(bool(d["cron"]) and all(len(c.split())==5 and c.split()[0].isdigit() and 0<=int(c.split()[0])<=59 and c.split()[0] not in ("0","11","41") for c in d["cron"]))')"
  eq "$cronok" "True" && ok || no "valid cron minute 0-59 offset from 0/11/41" "cron=$(pj "$WORK/sh.json" 'd["cron"]')"; fi

begin "req1-ac1-dispatch-dryrun-default-true" "workflow_dispatch has a dry_run input defaulting true"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  dr="$(pj "$WORK/sh.json" 'str(d.get("dispatch_inputs",{}).get("dry_run",{}).get("default")).lower()')"
  eq "$dr" "true" && ok || no "dry_run.default true" "$dr"; fi

begin "req1-ac2-consumes-rescan-no-rescan" "consumes the same-day artifact for the candidate digest and records zero scanner calls (digest identity checked, not just a flag)"
o="$WORK/consume"; rm -rf "$o"
run "$PY" "$BIN/auditor-consume-rescan.py" --run-state "$F/run-state/rs-01.json" --out "$o" && {
  calls="$(pj "$o/scanner-calls.json" 'd.get("count")')"; reused="$(pj "$o/consumed.json" 'd.get("reused")')"; dg="$(pj "$o/consumed.json" 'd.get("digest")')"
  { eq "$calls" "0" && eq "$reused" "true" && eq "$dg" "$rs01digest"; } && ok || no "count 0, reused true, digest == the run's candidate digest" "calls=$calls reused=$reused digest=$dg"; }

begin "req1-ac3-build-parity" "a forced build asserts produced index digests EQUAL CI's (the two recorded digests must be equal, not merely a match flag)"
o="$WORK/parity"; rm -rf "$o"
run "$PY" "$BIN/auditor-build-parity.py" --run-state "$F/run-state/rs-01.json" --force-build --out "$o" && {
  ci="$(pj "$o/parity.json" 'd.get("ci_digest")')"; bd="$(pj "$o/parity.json" 'd.get("built_digest")')"; ord="$(pj "$o/parity.json" 'd.get("compared_before_scan")')"
  { [ "$ci" != "$MISS" ] && eq "$ci" "$bd" && eq "$ord" "true"; } && ok || no "ci_digest == built_digest and compared before scan" "ci=$ci built=$bd before_scan=$ord"; }

########################################################################
echo "=== REQ-AUD-2 ==="
CDIR="$WORK/classify"; rm -rf "$CDIR"
begin "req2-ac1-false-positive" "the statement FOR the FP finding is not_affected with a justification and repository_url-scoped product; no per-scanner ignore file is written (scanner-panel rule 4: the VEX is the only exception); the report places it in section 5 not 3"
run "$PY" "$BIN/auditor-classify.py" --manifest "$FX/run/manifest-01.json" --adjudicator "$STUB" --out "$CDIR" && {
  st="$(vf "$CDIR/vex/CVE-2016-2781.openvex.json" CVE-2016-2781 's["status"]')"
  ju="$(vf "$CDIR/vex/CVE-2016-2781.openvex.json" CVE-2016-2781 's.get("justification")')"
  prod="$(vf "$CDIR/vex/CVE-2016-2781.openvex.json" CVE-2016-2781 'json.dumps(s.get("products"))')"
  igsz="$( [ -e "$CDIR/ignores/grype/CVE-2016-2781.json" ] && echo written || echo none )"
  fpev="$(pj "$CDIR/evidence/CVE-2016-2781.evidence.json" 'str(bool(d.get("evidence")))')"
  s5="$(sect_ids "$CDIR/report.md" 5)"; s3="$(sect_ids "$CDIR/report.md" 3)"
  fpstat="$(tree_vex_status_set "$CDIR" $(alias_set CVE-2016-2781))"
  { eq "$fpstat" "not_affected" && eq "$st" "not_affected" && eq "$fpev" "True" && [ "$ju" != "$MISS" ] && printf '%s' "$prod" | grep -q 'repository_url=ghcr.io/fosterstack/cache' \
    && eq "$igsz" "none" \
    && printf '%s' "$s5" | grep -q 'CVE-2016-2781' && ! printf '%s' "$s3" | grep -q 'CVE-2016-2781'; } \
    && ok || no "not_affected+justification+scoped product, no ignore file, section-5 placement" "status=$st just=$ju ignore=$igsz sec5=[$s5] sec3=[$s3]"; }

begin "req2-ac2a-notpullable-and-unreachable" "the target's statement is not_affected/vulnerable_code_not_in_execute_path; the reachable sibling does NOT get a not_affected VEX; empty ledger"
o="$WORK/ac2a"; rm -rf "$o"
run "$PY" "$BIN/auditor-classify.py" --finding GO-2020-0015 --manifest "$FX/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$NOCALL" --out "$o" && {
  st="$(vf "$o/vex/GO-2020-0015.openvex.json" GO-2020-0015 's["status"]')"
  ju="$(vf "$o/vex/GO-2020-0015.openvex.json" GO-2020-0015 's.get("justification")')"
  ev="$(pj "$o/evidence/GO-2020-0015.evidence.json" '(d.get("evidence") or {}).get("source")')"
  o2="$WORK/ac2a-b"; rm -rf "$o2"; : > "$LEDGER"
  run "$PY" "$BIN/auditor-classify.py" --finding GO-2021-0113 --manifest "$FX/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$NOCALL" --out "$o2"
  reachvex="$(tree_has_vex_for "$o2" GO-2021-0113)"
  { eq "$st" "not_affected" && eq "$ju" "vulnerable_code_not_in_execute_path" && eq "$ev" "govulncheck" && eq "$reachvex" "no" && ledger_empty; } \
    && ok || no "not_affected only for the unreachable one, carrying govulncheck evidence, empty ledger" "status=$st just=$ju evidence=$ev reachable_got_vex=$reachvex ledger=$(ledger_n)"; }

begin "req2-ac2b-notpullable-and-reachable" "the reachable not-pullable branch opens an owner decision and a dated ignore with an expiry; below-threshold does not open one"
o="$WORK/ac2b"; rm -rf "$o"; ghs="$WORK/ac2b-gh.json"; rm -f "$ghs"
run "$PY" "$BIN/auditor-poam.py" --finding "$F/poam/poam-02.json" --kev "$F/kev/kev.json" --github "$GH" --state "$ghs" --adjudicator "$NOCALL" --out "$o" && {
  st="$(vf "$o/vex/CVE-2023-4911.openvex.json" CVE-2023-4911 's["status"]')"; exp="$(pj "$o/package.json" 'd.get("ignore_expiry_days")')"
  iss="$( [ -f "$ghs" ] && pj "$ghs" 'len(d["issues"])' || echo 0 )"
  { eq "$st" "affected" && eq "$exp" "30" && eq "$iss" "1"; } && ok || no "affected + 30-day + one owner issue" "status=$st expiry=$exp issues=$iss"; }

begin "req2-ac3-real-fixable" "a bump PR is opened moving the version FORWARD (to != installed) and no not_affected VEX; a not-reachable finding gets no bump"
o="$WORK/ac3"; rm -rf "$o"; ghs="$WORK/ac3-gh.json"; rm -f "$ghs"
run "$PY" "$BIN/auditor-classify.py" --finding GO-2021-0113 --manifest "$FX/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$STUB" --github "$GH" --state "$ghs" --out "$o" && {
  kind="$(pj "$o/action/GO-2021-0113.json" 'd.get("kind")')"; to="$(pj "$o/action/GO-2021-0113.json" 'd.get("to")')"
  novex="$(tree_has_vex_for "$o" GO-2021-0113)"
  from="$(pj "$o/action/GO-2021-0113.json" 'd.get("from")')"
  { eq "$kind" "bump_pr" && eq "$from" "v0.3.0" && eq "$to" "v0.3.7" && eq "$novex" "no"; } \
    && ok || no "bump_pr from the scanned version to the stream's fixed version, no not_affected VEX" "kind=$kind from=$from to=$to vex=$novex"; }

# the bump's versions come from govulncheck's own finding and stay with ONE module (cache#483 round 1)
gvmk() { "$PY" - "$1" "$2" <<'PYEOF'
import json, sys
name, body = sys.argv[1], sys.argv[2]
def fin(osv, fixed, trace): return {"finding": dict({"osv": osv, "trace": trace}, **({"fixed_version": fixed} if fixed else {}))}
out = [{"config": {"scan_level": "symbol"}}, {"SBOM": {"modules": [{"path": "example.com/reach"}, {"path": "m/v1", "version": "v1.0.0"}, {"path": "m/v2", "version": "v2.0.0"}], "roots": ["example.com/reach"]}},
       {"osv": {"id": "GO-2099-1", "aliases": ["CVE-2099-1"]}}]
call = lambda mod, ver: [{"module": mod, "version": ver, "package": mod + "/p", "function": "F"}, {"module": "example.com/reach", "package": "example.com/reach", "function": "main"}]
if name == "nofix": out += [fin("GO-2099-1", None, call("m/v2", "v2.0.0"))]
elif name == "twomods": out += [fin("GO-2099-1", None, [{"module": "m/v1", "version": "v1.0.0", "package": "m/v1/p"}]), fin("GO-2099-1", "v2.2.0", call("m/v2", "v2.0.0"))]
elif name == "bothreach": out += [fin("GO-2099-1", "v1.1.0", call("m/v1", "v1.0.0")), fin("GO-2099-1", "v2.2.0", call("m/v2", "v2.0.0"))]
open(sys.argv[2], "w").write("\n".join(json.dumps(x) for x in out) + "\n")
PYEOF
}
begin "req2-ac3b-bump-needs-a-known-fix" "a reachable Go finding whose stream names no fixed version gets NO bump action (never from/to with a null) and stays open with the reason"
gvmk nofix "$WORK/gv-nofix.jsonl"; o="$WORK/ac3b"; rm -rf "$o"
run "$PY" "$BIN/auditor-classify.py" --finding GO-2099-1 --manifest "$FX/run/manifest-01.json" --govulncheck "$WORK/gv-nofix.jsonl" --adjudicator "$NOCALL" --out "$o" && {
  act="$( [ -e "$o/action/GO-2099-1.json" ] && echo yes || echo no )"; op="$(pj "$o/status/GO-2099-1.json" 'd.get("open")')"; why="$(pj "$o/status/GO-2099-1.json" 'd.get("reason")')"
  { eq "$act" "no" && eq "$op" "true" && printf '%s' "$why" | grep -qi 'fix'; } && ok || no "no bump, open, reason names the missing fix" "action=$act open=$op reason=$why"; }

begin "req2-ac3c-bump-versions-stay-with-their-module" "one advisory affecting two modules: the bump pairs the reachable module's installed version with ITS fix (m/v2 v2.0.0 -> v2.2.0), never the other module's version; two reachable modules are ambiguous: no bump"
gvmk twomods "$WORK/gv-two.jsonl"; gvmk bothreach "$WORK/gv-both.jsonl"; o="$WORK/ac3c"; o2="$WORK/ac3d"; rm -rf "$o" "$o2"
run "$PY" "$BIN/auditor-classify.py" --finding GO-2099-1 --manifest "$FX/run/manifest-01.json" --govulncheck "$WORK/gv-two.jsonl" --adjudicator "$NOCALL" --out "$o" && {
  fr="$(pj "$o/action/GO-2099-1.json" 'd.get("from")')"; to="$(pj "$o/action/GO-2099-1.json" 'd.get("to")')"
  run "$PY" "$BIN/auditor-classify.py" --finding GO-2099-1 --manifest "$FX/run/manifest-01.json" --govulncheck "$WORK/gv-both.jsonl" --adjudicator "$NOCALL" --out "$o2"
  amb="$( [ -e "$o2/action/GO-2099-1.json" ] && echo bump || echo none )"
  { eq "$fr" "v2.0.0" && eq "$to" "v2.2.0" && eq "$amb" "none"; } && ok || no "versions stay with their module; ambiguity yields no bump" "from=$fr to=$to two_reachable=$amb"; }

begin "req2-ac3d-bump-by-the-finding-alias" "a finding named by the advisory's CVE alias (CVE-2021-38561) resolves to its reachable Go advisory and gets the same bump"
o="$WORK/ac3e"; rm -rf "$o"
run "$PY" "$BIN/auditor-classify.py" --finding CVE-2021-38561 --manifest "$FX/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$NOCALL" --out "$o" && {
  kind="$(pj "$o/action/CVE-2021-38561.json" 'd.get("kind")')"; to="$(pj "$o/action/CVE-2021-38561.json" 'd.get("to")')"
  { eq "$kind" "bump_pr" && eq "$to" "v0.3.7"; } && ok || no "alias resolves to the reachable advisory's bump" "kind=$kind to=$to"; }

begin "req2-ac4-not-reachable" "the target's statement is not_affected with the reachability justification and names the finding; a reachable finding does NOT become not_affected; empty ledger"
o="$WORK/ac4"; rm -rf "$o"
run "$PY" "$BIN/auditor-classify.py" --finding GO-2020-0015 --manifest "$FX/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$NOCALL" --out "$o" && {
  st="$(vf "$o/vex/GO-2020-0015.openvex.json" GO-2020-0015 's["status"]')"
  ju="$(vf "$o/vex/GO-2020-0015.openvex.json" GO-2020-0015 's.get("justification")')"
  ev="$(pj "$o/evidence/GO-2020-0015.evidence.json" '(d.get("evidence") or {}).get("source")')"
  o2="$WORK/ac4b"; rm -rf "$o2"; : > "$LEDGER"
  run "$PY" "$BIN/auditor-classify.py" --finding GO-2021-0113 --manifest "$FX/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$NOCALL" --out "$o2"
  reach="$(tree_has_vex_for "$o2" GO-2021-0113)"
  { eq "$st" "not_affected" && eq "$ju" "vulnerable_code_not_in_execute_path" && eq "$ev" "govulncheck" && eq "$reach" "no" && ledger_empty; } \
    && ok || no "not_affected only for unreachable, govulncheck evidence, empty ledger" "status=$st just=$ju evidence=$ev reachable_vex=$reach ledger=$(ledger_n)"; }

begin "req2-ac4-neg-no-evidence-stays-open" "a real scanned finding (GO-2020-0015 in OSV) whose govulncheck messages are removed is NOT closed: no VEX statement anywhere names it, no ignore names it, it is recorded open; empty ledger"
o="$WORK/ac4neg"; rm -rf "$o"
run "$PY" "$BIN/auditor-classify.py" --finding GO-2020-0015 --manifest "$FX/run/manifest-01.json" --govulncheck "$F/testlib/evidence-without-GO-2020-0015.json" --adjudicator "$NOCALL" --out "$o" && {
  al="$(alias_set GO-2020-0015)"
  statuses="$(tree_vex_status_set "$o" $al)"
  ig="$(ignore_names_any "$o" $al)"
  open_="$(pj "$o/status/GO-2020-0015.json" 'd.get("open")')"
  { [ -z "$statuses" ] && eq "$open_" "true" && eq "$ig" "no" && ledger_empty; } \
    && ok || no "no VEX status nor ignore for ANY alias of the finding; recorded open; empty ledger" "aliases=[$al] statuses=[$statuses] open=$open_ ignore=$ig ledger=$(ledger_n)"; }

begin "req2-ac5-belowthreshold-vex-merged-ci-green" "below threshold writes an AFFECTED VEX with an action_statement, CI stays green, section 2, no owner issue"
o="$WORK/ac5"; rm -rf "$o"; ghs="$WORK/ac5-gh.json"; rm -f "$ghs"
run "$PY" "$BIN/auditor-poam.py" --finding "$F/poam/poam-01.json" --kev "$F/kev/kev.json" --github "$GH" --state "$ghs" --adjudicator "$NOCALL" --out "$o" && {
  st="$(tree_vex_status_set "$o" $(alias_set CVE-2011-3374))"
  act="$(vf "$o/vex/CVE-2011-3374.openvex.json" CVE-2011-3374 'str(bool(s.get("action_statement")))')"
  green="$(pj "$o/decision.json" 'd.get("ci_stays_green")')"; sec="$(pj "$o/decision.json" 'd.get("report_section")')"
  iss="$( [ -f "$ghs" ] && pj "$ghs" 'len(d["issues"])' || echo 0 )"
  { eq "$st" "affected" && eq "$act" "True" && eq "$green" "true" && eq "$sec" "2" && eq "$iss" "0" && ledger_empty; } \
    && ok || no "affected+action, green, section 2, no issue, empty ledger" "status=$st action=$act green=$green section=$sec issues=$iss ledger=$(ledger_n)"; }

begin "req2-ac5b-atthreshold-also-opens-owner-issue" "KEV: affected VEX, green, at_or_above, EXACTLY one issue total (no label filter), empty ledger"
o="$WORK/ac5b"; rm -rf "$o"; ghs="$WORK/ac5b-gh.json"; rm -f "$ghs"
run "$PY" "$BIN/auditor-poam.py" --finding "$F/poam/poam-02.json" --kev "$F/kev/kev.json" --github "$GH" --state "$ghs" --adjudicator "$NOCALL" --out "$o" && {
  st="$(vf "$o/vex/CVE-2023-4911.openvex.json" CVE-2023-4911 's["status"]')"; th="$(pj "$o/decision.json" 'd.get("threshold")')"
  iss="$( [ -f "$ghs" ] && pj "$ghs" 'len(d["issues"])' || echo 0 )"
  { eq "$st" "affected" && eq "$th" "at_or_above" && eq "$iss" "1" && ledger_empty; } \
    && ok || no "affected, at_or_above, exactly one issue, empty ledger" "status=$st threshold=$th issues=$iss ledger=$(ledger_n)"; }

begin "req2-ac5b-critical-branch-alone" "Critical-only (no KEV): affected VEX, threshold critical-severity, exactly one issue, empty ledger (a swallowed spy call is caught)"
o="$WORK/ac5bc"; rm -rf "$o"; ghs="$WORK/ac5bc-gh.json"; rm -f "$ghs"
run "$PY" "$BIN/auditor-poam.py" --finding "$F/poam/poam-03.json" --kev "$F/kev/kev.json" --github "$GH" --state "$ghs" --adjudicator "$NOCALL" --out "$o" && {
  st="$(vf "$o/vex/CVE-2013-4392.openvex.json" CVE-2013-4392 's["status"]')"
  why="$(pj "$o/decision.json" 'd.get("threshold_reason")')"; iss="$( [ -f "$ghs" ] && pj "$ghs" 'len(d["issues"])' || echo 0 )"
  { eq "$st" "affected" && eq "$why" "critical-severity" && eq "$iss" "1" && ledger_empty; } \
    && ok || no "affected, critical-severity, one issue, empty ledger" "status=$st reason=$why issues=$iss ledger=$(ledger_n)"; }

begin "req2-ac5b-known-exploited-alone" "known-exploited (from scanner data), not Critical, not in KEV: at_or_above via known-exploited, one issue, empty ledger"
o="$WORK/ac5bk"; rm -rf "$o"; ghs="$WORK/ac5bk-gh.json"; rm -f "$ghs"
run "$PY" "$BIN/auditor-poam.py" --finding "$F/poam/poam-05.json" --kev "$F/kev/kev.json" --github "$GH" --state "$ghs" --adjudicator "$NOCALL" --out "$o" && {
  th="$(pj "$o/decision.json" 'd.get("threshold")')"; why="$(pj "$o/decision.json" 'd.get("threshold_reason")')"
  iss="$( [ -f "$ghs" ] && pj "$ghs" 'len(d["issues"])' || echo 0 )"
  { eq "$th" "at_or_above" && eq "$why" "known-exploited" && eq "$iss" "1" && ledger_empty; } \
    && ok || no "at_or_above via known-exploited, one issue, empty ledger" "threshold=$th reason=$why issues=$iss ledger=$(ledger_n)"; }

begin "req2-ac5c-expiry-reopens-item" "expiry with no fix DELETES the seeded VEX statement under every alias (world check) and returns the finding to section 3"
o="$WORK/ac5c"; supp="$WORK/ac5c-supp"; rm -rf "$o" "$supp"
mkdir -p "$supp/.vex"
printf '{"statements":[{"vulnerability":{"name":"CVE-2011-3374"},"status":"affected"}]}' > "$supp/.vex/fosterstack-cache.openvex.json"
run "$PY" "$BIN/auditor-poam.py" --recheck --package "$F/poam/poam-04.json" --suppression-dir "$supp" --today 2026-09-22 --out "$o" && {
  rem="$(pj "$o/recheck.json" 'd.get("ignore_removed")')"; sec="$(pj "$o/recheck.json" 'd.get("returned_to_section")')"
  anyvex="$(tree_has_vex_for "$supp" CVE-2011-3374)"
  { eq "$rem" "true" && eq "$sec" "3" && eq "$anyvex" "no"; } \
    && ok || no "seeded VEX statement deleted from the state; section 3" "removed=$rem section=$sec any_vex=$anyvex"; }

begin "req2-ac6-categories-disjoint" "classification.json finding-id set EQUALS the manifest's id set (never vacuous), each with one valid category"
run "$PY" "$BIN/auditor-classify.py" --manifest "$FX/run/manifest-01.json" --adjudicator "$STUB" --out "$CDIR" && {
  chk="$("$PY" -c 'import json,sys,re
try:
    d=json.load(open(sys.argv[1])); m=json.load(open(sys.argv[2]))
    ids=set()
    def cve(x):
        a=[x.get("id")]+x.get("aliases",[])
        for y in a:
            if re.fullmatch(r"CVE-\d{4}-\d+",y or ""): return y
        return (x.get("id") or "").replace("DEBIAN-CVE-","CVE-")
    v=json.load(open(m["panel"]["verdict"]))
    for f in v["findings"]: ids.add(cve({"id": f["id"], "aliases": [a for sc in f["details"].values() for a in sc.get("aliases", [])]}))
    got={f["id"] for f in d["findings"]}
    valid={"false_positive","not_affected_unreachable","real_fixable","risk_acceptance"}
    okc=len(d["findings"])>0 and got==ids and all(f.get("category") in valid for f in d["findings"]) and len(got)==len(d["findings"])
    print("True" if okc else "False")
except Exception: print("ERR")' "$CDIR/classification.json" "$FX/run/manifest-01.json")"
  eq "$chk" "True" && ok || no "id set equals manifest ids, one valid category each, nonempty" "$chk"; }

begin "req2-ac7-every-run-recheck" "now-pullable DELETES the seeded VEX from the state (world check) and records a bump PR in the shim ledger, section 1"
o="$WORK/ac7"; supp="$WORK/ac7-supp"; shim="$WORK/ac7.shim"; rm -rf "$o" "$supp"; rm -f "$shim"
mkdir -p "$supp/.vex"
printf '{"statements":[{"vulnerability":{"name":"CVE-2011-3374"},"status":"not_affected"}]}' > "$supp/.vex/fosterstack-cache.openvex.json"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-recheck.py" --vex "$F/suppression/disp-01.json" --suppression-dir "$supp" --now-pullable --out "$o" && {
  rem="$(pj "$o/recheck.json" 'd.get("vex_removed")')"; sec="$(pj "$o/recheck.json" 'd.get("report_section")')"
  anyvex="$(tree_has_vex_for "$supp" CVE-2011-3374)"
  bumped="$(grep -cE 'pr create .*auditor/bump' "$shim" 2>/dev/null)"; bumped="${bumped:-0}"
  { eq "$rem" "true" && eq "$sec" "1" && eq "$anyvex" "no" && [ "$bumped" -ge 1 ] 2>/dev/null; } \
    && ok || no "seeded VEX deleted from state; bump PR recorded in shim; section 1" "removed=$rem section=$sec any_vex=$anyvex bump_in_shim=$bumped"; }

########################################################################
echo "=== REQ-AUD-3 ==="
begin "req3-ac1-key-is-exact-verbatim" "an exact (scanner,id,purl) hits the right row; the same id on a different purl misses; empty ledger"
o="$WORK/dl1"; rm -rf "$o"
run "$PY" "$BIN/auditor-defectlog.py" probe --log "$F/dl/log.json" \
  --hit grype CVE-2016-2781 'pkg:deb/debian/coreutils@9.1-1?arch=arm64&distro=debian-12.0' \
  --miss grype CVE-2016-2781 'pkg:deb/debian/coreutils@9.1-1?arch=amd64&distro=debian-12.0' \
  --adjudicator "$NOCALL" --out "$o" && {
  h="$(pj "$o/probe.json" 'd.get("hit")')"; m="$(pj "$o/probe.json" 'd.get("miss")')"; row="$(pj "$o/probe.json" 'd.get("hit_disposition")')"
  { eq "$h" "true" && eq "$m" "false" && eq "$row" "false_positive" && ledger_empty; } \
    && ok || no "exact hit to the right disposition, varied-purl miss, empty ledger" "hit=$h miss=$m disposition=$row ledger=$(ledger_n)"; }

begin "req3-ac2-lookup-hit-zero-model" "the matched finding closes to the LOGGED disposition and the closed key equals the input key; empty ledger"
o="$WORK/dl2"; rm -rf "$o"
run "$PY" "$BIN/auditor-defectlog.py" run --log "$F/dl/log.json" --findings "$F/dl/findings-01.json" --adjudicator "$NOCALL" --out "$o" && {
  cid="$(pj "$o/result.json" 'd["closed"][0]["finding_id"]')"; disp="$(pj "$o/result.json" 'd["closed"][0]["disposition"]')"
  { eq "$disp" "false_positive" && printf '%s' "$cid" | grep -qE '^CVE-' && ledger_empty; } \
    && ok || no "closed to logged disposition with a real key, empty ledger" "id=$cid disposition=$disp ledger=$(ledger_n)"; }

begin "req3-ac3-nochange-zero-model-stable-hash" "valid 64-hex hash equal across two no-change runs, different for a changed set; each run exits 0 and leaves the ledger empty"
a="$WORK/nc1"; b="$WORK/nc2"; c="$WORK/nc3"; rm -rf "$a" "$b" "$c"
run "$PY" "$BIN/auditor-defectlog.py" run --log "$F/dl/log.json" --findings "$F/dl/findings-01.json" --adjudicator "$NOCALL" --out "$a" && {
  e1="$(ledger_empty && echo y || echo n)"; : > "$LEDGER"
  run "$PY" "$BIN/auditor-defectlog.py" run --log "$F/dl/log.json" --findings "$F/dl/findings-01.json" --adjudicator "$NOCALL" --out "$b" && {
    e2="$(ledger_empty && echo y || echo n)"; : > "$LEDGER"
    run "$PY" "$BIN/auditor-defectlog.py" run --log "$F/dl/log.json" --findings "$F/dl/findings-02.json" --adjudicator "$STUB" --out "$c" && {
      # a copy of the no-change findings under a DIFFERENT name: a finding-SET hash
      # is content-derived and equal; a filename hash would differ.
      cp "$F/dl/findings-01.json" "$WORK/findings-01c.json"; : > "$LEDGER"; dcp="$WORK/nc4"; rm -rf "$dcp"
      run "$PY" "$BIN/auditor-defectlog.py" run --log "$F/dl/log.json" --findings "$WORK/findings-01c.json" --adjudicator "$NOCALL" --out "$dcp" && {
        h1="$(pj "$a/result.json" 'd.get("finding_set_hash")')"; h2="$(pj "$b/result.json" 'd.get("finding_set_hash")')"; h3="$(pj "$c/result.json" 'd.get("finding_set_hash")')"; h4="$(pj "$dcp/result.json" 'd.get("finding_set_hash")')"
        valid="$(printf '%s' "$h1" | grep -Eq '^[0-9a-f]{64}$' && echo y || echo n)"
        { eq "$valid" "y" && eq "$e1" "y" && eq "$e2" "y" && eq "$h1" "$h2" && eq "$h1" "$h4" && [ "$h1" != "$h3" ] && [ "$h3" != "$MISS" ]; } \
          && ok || no "content-derived hash: stable across names, different on change, empty ledgers" "h1=$h1 h2=$h2 h3=$h3 samecopy=$h4 valid=$valid e1=$e1 e2=$e2"; }; }; }; }

begin "req3-ac4-miss-appends-row" "the miss key equals the absent purl; exactly one new key is appended and the old keys remain"
o="$WORK/dl4"; rm -rf "$o"; cp "$F/dl/log.json" "$WORK/log4.json"
before="$(pj "$F/dl/log.json" 'sum(len(x["keys"]) for x in d["defects"])')"
run "$PY" "$BIN/auditor-defectlog.py" run --log "$WORK/log4.json" --findings "$F/dl/findings-02.json" --adjudicator "$STUB" --append --out "$o" && {
  after="$(pj "$WORK/log4.json" 'sum(len(x["keys"]) for x in d["defects"])')"
  misspurl="$(pj "$o/result.json" 'd["misses"][0]["purl"]')"
  { [ "$after" != "$MISS" ] && [ "$after" -eq $((before+1)) ] 2>/dev/null && printf '%s' "$misspurl" | grep -q 'arch=amd64'; } \
    && ok || no "exactly one key appended, miss purl is the amd64 one" "before=$before after=$after misspurl=$misspurl"; }

begin "req3-ac5-second-exact-key-same-row" "from a log lacking the second key, judgment adds it to the SAME row; a later exact probe hits with an empty ledger"
o1="$WORK/dl5a"; o2="$WORK/dl5b"; rm -rf "$o1" "$o2"
"$PY" -c 'import json;d=json.load(open(".github/agent/fixtures/dl/log.json"));d["defects"][1]["keys"]=[k for k in d["defects"][1]["keys"] if k["scanner"]!="scout"];json.dump(d,open("'"$WORK"'/log5.json","w"))'
rowbefore="$(pj "$WORK/log5.json" 'max(len(x["keys"]) for x in d["defects"])')"
run "$PY" "$BIN/auditor-defectlog.py" reconcile --log "$WORK/log5.json" \
  --finding scout CVE-2011-3374 'pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.0' --manifest "$FX/run/manifest-01.json" \
  --adjudicator "$STUB" --out "$o1" && {
  used="$( [ -s "$LEDGER" ] && echo y || echo n )"; : > "$LEDGER"
  # the SAME row that already holds a CVE-2011-3374 key must now hold a scout
  # CVE-2011-3374 key (not a key on some other row, nor a WRONG finding id).
  addedright="$("$PY" -c 'import json,sys
try:
    d=json.load(open(sys.argv[1])); ok=False; purl=sys.argv[2]
    for row in d["defects"]:
        ids={k["finding_id"] for k in row["keys"]}
        if "CVE-2011-3374" in ids and any(k["scanner"]=="scout" and k["finding_id"]=="CVE-2011-3374" and k["purl"]==purl for k in row["keys"]): ok=True
    print("yes" if ok else "no")
except Exception: print("no")' "$WORK/log5.json" 'pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.0')"
  run "$PY" "$BIN/auditor-defectlog.py" probe --log "$WORK/log5.json" --hit scout CVE-2011-3374 'pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.0' --adjudicator "$NOCALL" --out "$o2" && {
    hit="$(pj "$o2/probe.json" 'd.get("hit")')"; disp="$(pj "$o2/probe.json" 'd.get("hit_disposition")')"
    { eq "$used" "y" && eq "$addedright" "yes" && eq "$hit" "true" && eq "$disp" "false_positive" && ledger_empty; } \
      && ok || no "scout CVE-2011-3374 key with the exact purl on the SAME row; later probe returns that row's disposition" "judgment=$used added_to_right_row_and_purl=$addedright hit=$hit disposition=$disp ledger=$(ledger_n)"; }; }

########################################################################
echo "=== REQ-AUD-4 ==="
begin "req4-ac1-four-suppressions-cite-vex" "the suppression CLI writes the OpenVEX (status not_affected) and NO per-scanner ignore file: the VEX is the only exception (scanner-panel rule 4)"
o="$WORK/sup"; rm -rf "$o"
run "$PY" "$BIN/auditor-suppress.py" --disposition "$F/suppression/disp-01.json" --out "$o" && {
  vst="$(vf "$o/.vex/fosterstack-cache.openvex.json" CVE-2011-3374 's["status"]')"
  extra="$(ls -A "$o" | grep -cE '^(\.snyk|osv-scanner\.toml)$')"
  { eq "$vst" "not_affected" && eq "$extra" "0"; } \
    && ok || no "VEX not_affected and no .snyk / osv-scanner.toml" "vex=$vst ignore_files=$extra"; }

begin "req4-ac2-vex-repository-url-scoped" "the AUTHORED product identifier is repository_url-scoped to ghcr.io/fosterstack/cache (parsed from the authored VEX, not a boolean)"
o="$WORK/scope"; rm -rf "$o"
run "$PY" "$BIN/auditor-vex-scope-check.py" "$F/suppression/set-01/fosterstack-cache.openvex.json" --authored-out "$o/authored.openvex.json" --out "$o/scope.json" && {
  scoped="$("$PY" -c 'import json,sys
try:
    d=json.load(open(sys.argv[1])); prods=[p.get("@id","") for s in d.get("statements",[]) for p in s.get("products",[])]
    print("yes" if prods and all("repository_url=ghcr.io/fosterstack/cache" in p for p in prods) else "no")
except Exception: print("no")' "$o/authored.openvex.json")"
  eq "$scoped" "yes" && ok || no "authored products repository_url-scoped" "scoped=$scoped"; }

begin "req4-ac1b-vex-openvex-conformant" "every VEX a real run produces validates against the vendored OpenVEX schema (evidence lives in a sidecar, not as a custom statement key)"
o="$WORK/conf"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --adjudicator "$STUB" --out "$o" && {
  conf="$("$PY" -c 'import json,sys,glob
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex
bad=[]
for f in glob.glob(sys.argv[1]+"/vex/*.openvex.json")+glob.glob(sys.argv[1]+"/.vex/*.json"):
    try: vex.validate(json.load(open(f)))
    except Exception as e: bad.append(f+": "+str(e))
print("ok" if not bad else "BAD:"+";".join(bad))' "$o")"
  ins="$( { grep -rl "_evidence\|_target_date" "$o"/vex 2>/dev/null || true; } | wc -l | tr -d ' ')"
  { eq "$conf" "ok" && eq "$ins" "0"; } && ok || no "all produced VEX OpenVEX-conformant; no _evidence/_target_date in statements" "conformance=$conf inline_custom_keys=$ins"; }

begin "req4-ac3-votes-by-lineage" "a four-scanner CVE counts 4 lineages (Grype, Scout, Inspector and Google keep their own advisory data); a grype-only CVE counts 1 (a constant fails one); empty ledger"
o="$WORK/v1"; o2="$WORK/v2"; rm -rf "$o" "$o2"
run "$PY" "$BIN/auditor-votes.py" --manifest "$FX/run/manifest-01.json" --cve CVE-2011-3374 --adjudicator "$NOCALL" --out "$o" && {
  dl="$(pj "$o/votes.json" 'd.get("distinct_lineages")')"; e1="$(ledger_empty && echo y || echo n)"; : > "$LEDGER"
  run "$PY" "$BIN/auditor-votes.py" --manifest "$FX/run/manifest-01.json" --cve CVE-2016-2781 --adjudicator "$NOCALL" --out "$o2" && {
    dl2="$(pj "$o2/votes.json" 'd.get("distinct_lineages")')"
    { eq "$dl" "4" && eq "$dl2" "1" && eq "$e1" "y" && ledger_empty; } \
      && ok || no "4 lineages for four-scanner, 1 for grype-only, empty ledger" "four=$dl one=$dl2 ledger=$(ledger_n)"; }; }

begin "req4-ac3b-no-verdict-is-unavailable-not-corroborated" "a panel manifest with no verdict gives votes.json handling 'evidence_unavailable' (no scanners, no lineages), never 'corroborated'; and a defect-log reconcile against it asks no model and says the report is unavailable"
o="$WORK/v3"; rm -rf "$o"; o2="$WORK/rc3"; rm -rf "$o2"; cp "$F/dl/log.json" "$WORK/log-nv.json"; : > "$LEDGER"
run "$PY" "$BIN/auditor-votes.py" --manifest "$WORK/pm-nopanel/manifest.json" --cve CVE-2011-3374 --adjudicator "$NOCALL" --out "$o" && {
  hd="$(pj "$o/votes.json" 'd.get("handling")')"; nl="$(pj "$o/votes.json" 'd.get("distinct_lineages")')"
  "$PY" "$BIN/auditor-defectlog.py" reconcile --log "$WORK/log-nv.json" --finding grype CVE-2011-3374 'pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.0' --manifest "$WORK/pm-nopanel/manifest.json" --adjudicator "$NOCALL" --out "$o2" >/dev/null 2>&1
  rs="$(pj "$o2/reconcile.json" 'd.get("reason")')"; ad="$(pj "$o2/reconcile.json" 'd.get("added")')"
  { eq "$hd" "evidence_unavailable" && eq "$nl" "0" && printf '%s' "$rs" | grep -qi 'unavailable' && eq "$ad" "false" && ledger_empty; } \
    && ok || no "no verdict: votes evidence_unavailable, reconcile unavailable without a model call" "handling=$hd lineages=$nl reason=$rs added=$ad ledger=$(ledger_n)"; }

begin "req4-ac3c-a-down-scanner-is-not-evidence" "with Grype and Google down (manifest-down), a CVE only Grype saw is 'evidence_unavailable' (absence from the scanners that ran is not corroboration), and a reconcile for the down scanner, or against an unreadable verdict file, asks no model"
o="$WORK/v4"; rm -rf "$o"; o2="$WORK/rc4"; o3="$WORK/rc5"; rm -rf "$o2" "$o3"; cp "$F/dl/log.json" "$WORK/log-dn.json"; : > "$LEDGER"
"$PY" -c 'import json;m=json.load(open(__import__("os").environ["FXRUN"]+"/manifest-01.json"));m["panel"]["verdict"]="/nonexistent/verdict.json";json.dump(m,open("'"$WORK"'/m-gone.json","w"))'
run "$PY" "$BIN/auditor-votes.py" --manifest "$FX/run/manifest-down.json" --cve CVE-2016-2781 --adjudicator "$NOCALL" --out "$o" && {
  hd="$(pj "$o/votes.json" 'd.get("handling")')"; sc="$(pj "$o/votes.json" 'd.get("scanners")')"
  "$PY" "$BIN/auditor-defectlog.py" reconcile --log "$WORK/log-dn.json" --finding grype CVE-2011-3374 'pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.0' --manifest "$FX/run/manifest-down.json" --adjudicator "$NOCALL" --out "$o2" >/dev/null 2>&1
  "$PY" "$BIN/auditor-defectlog.py" reconcile --log "$WORK/log-dn.json" --finding scout CVE-2011-3374 'pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.0' --manifest "$WORK/m-gone.json" --adjudicator "$NOCALL" --out "$o3" >/dev/null 2>&1
  r2="$(pj "$o2/reconcile.json" 'd.get("reason")')"; r3="$(pj "$o3/reconcile.json" 'd.get("reason")')"
  o4="$WORK/v6"; rm -rf "$o4"; "$PY" "$BIN/auditor-votes.py" --manifest "$WORK/m-gone.json" --cve CVE-2011-3374 --adjudicator "$NOCALL" --out "$o4" >/dev/null 2>&1       # reports named, verdict file gone
  hd2="$(pj "$o4/votes.json" 'd.get("handling")')"
  printf 'not a stream\n' > "$WORK/gv-junk.jsonl"; o5="$WORK/ac3f"; rm -rf "$o5"
  "$PY" "$BIN/auditor-classify.py" --finding CVE-2099-1 --manifest "$FX/run/manifest-01.json" --govulncheck "$WORK/gv-junk.jsonl" --adjudicator "$NOCALL" --out "$o5" >/dev/null 2>&1
  op="$(pj "$o5/status/CVE-2099-1.json" 'd.get("open")')"; act="$( [ -e "$o5/action/CVE-2099-1.json" ] && echo yes || echo no )"
  { eq "$hd" "evidence_unavailable" && eq "$sc" "[]" && printf '%s' "$r2" | grep -qi unavailable && printf '%s' "$r3" | grep -qi unavailable && ledger_empty \
    && eq "$hd2" "evidence_unavailable" && eq "$op" "true" && eq "$act" "no"; } \
    && ok || no "down scanner, unreadable verdict and an unparseable govulncheck stream are unavailable evidence, no model call, no bump" "handling=$hd scanners=$sc down_reason=$r2 gone_reason=$r3 gone_votes=$hd2 junk_open=$op junk_action=$act ledger=$(ledger_n)"; }

begin "req4-ac3d-a-partial-scanner-casts-no-vote" "Google missed one image (pm-partial) but its verdict still holds CVE-2099-7777: the report keeps that finding in Google's table (scan incomplete), while votes counts Google as unavailable: no scanner, handling 'evidence_unavailable'"
o="$WORK/v5"; rm -rf "$o"
run "$PY" "$BIN/auditor-votes.py" --manifest "$WORK/pm-partial/manifest.json" --cve CVE-2099-7777 --adjudicator "$NOCALL" --out "$o" && {
  hd="$(pj "$o/votes.json" 'd.get("handling")')"; sc="$(pj "$o/votes.json" 'd.get("scanners")')"
  o2="$WORK/v5r"; rm -rf "$o2"; "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-partial/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o2" >/dev/null 2>&1
  tbl="$(grep -c 'CVE-2099-7777' "$o2/reports/scanner-tables.txt" 2>/dev/null)"; tbl="${tbl:-0}"
  { eq "$hd" "evidence_unavailable" && eq "$sc" "[]" && [ "$tbl" -ge 1 ] 2>/dev/null; } \
    && ok || no "partial scanner: no vote, finding still in its table" "handling=$hd scanners=$sc table_rows=$tbl"; }

begin "req4-ac4-unique-not-autoclosed" "a grype-only CVE is unique+suspect (not auto-closed); a four-scanner CVE is not unique (a constant fails one)"
o="$WORK/u1"; o2="$WORK/u2"; rm -rf "$o" "$o2"
run "$PY" "$BIN/auditor-votes.py" --manifest "$FX/run/manifest-01.json" --cve CVE-2016-2781 --adjudicator "$NOCALL" --out "$o" && {
  u="$(pj "$o/votes.json" 'd.get("unique")')"; cl="$(pj "$o/votes.json" 'd.get("auto_closed")')"; hd="$(pj "$o/votes.json" 'd.get("handling")')"
  run "$PY" "$BIN/auditor-votes.py" --manifest "$FX/run/manifest-01.json" --cve CVE-2011-3374 --adjudicator "$NOCALL" --out "$o2" && {
    u2="$(pj "$o2/votes.json" 'd.get("unique")')"
    { eq "$u" "true" && eq "$cl" "false" && eq "$hd" "suspect_investigated" && eq "$u2" "false"; } \
      && ok || no "unique+suspect for grype-only, not-unique for four-scanner" "unique=$u closed=$cl handling=$hd four_unique=$u2"; }; }

begin "req4-ac5-consistency-check" "a VEX statement that answers no live finding is flagged stale_vex (parsed array); a clean control set yields none"
o="$WORK/c1"; o2="$WORK/c2"; rm -rf "$o" "$o2"
run "$PY" "$BIN/auditor-consistency.py" --suppression-dir "$F/suppression/set-01" --live-findings "$FX/run/manifest-01.json" --out "$o/consistency.json" && {
  types="$(pj "$o/consistency.json" '",".join(sorted({p["type"] for p in d["problems"]}))')"
  mkdir -p "$WORK/clean"
  run "$PY" "$BIN/auditor-consistency.py" --suppression-dir "$WORK/clean" --live-findings "$FX/run/manifest-01.json" --out "$o2/consistency.json" && {
    cleann="$(pj "$o2/consistency.json" 'len(d["problems"])')"
    { eq "$types" "stale_vex" && eq "$cleann" "0"; } \
      && ok || no "stale_vex flagged; clean set has none" "types=$types clean_problems=$cleann"; }; }

########################################################################
echo "=== REQ-AUD-5 ==="
begin "req5-ac1-acts-only-via-pr" "the git/gh shim ledger shows a branch-PR create for the audit lane and NO push to main / tag"
o="$WORK/pr"; rm -rf "$o"; shim="$WORK/shim.log"; rm -f "$shim"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-open-pr.py" --change vex --out "$o" && {
  shimpresent="$(have "$shim" && echo yes || echo no)"
  forbidden="$(grep -cE 'push .*(refs/heads/main|--tags|tag )' "$shim" 2>/dev/null)"; forbidden="${forbidden:-0}"
  prcreate="$(grep -cE 'pr (create|--head)|create-pull-request' "$shim" 2>/dev/null)"; prcreate="${prcreate:-0}"
  lane="$(pj "$o/pr.json" 'd.get("lane")')"
  { eq "$shimpresent" "yes" && eq "$forbidden" "0" && [ "$prcreate" -ge 1 ] 2>/dev/null && eq "$lane" "audit"; } \
    && ok || no "shim ledger present, a branch PR create, no push/tag" "shim=$shimpresent forbidden=$forbidden pr_create=$prcreate lane=$lane"; }

begin "req5-ac2-token-scope" "GITHUB_TOKEN grants pull-requests, no actions:write (read for artifact download is fine); the main ruleset has zero bypass actors"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  pr="$(pj "$WORK/sh.json" 'd.get("permissions",{}).get("pull-requests")')"
  actions="$(pj "$WORK/sh.json" 'd.get("permissions",{}).get("actions")')"
  bypass="$(pj "$F/policy/rule-01.json" 'len(d.get("bypass_actors",[]))')"
  { printf '%s' "$pr" | grep -qE 'write|read' && [ "$actions" != "write" ] && eq "$bypass" "0"; } \
    && ok || no "pull-requests present, no actions:write (read for artifact download is fine), no bypass actors" "pull_requests=$pr actions=$actions bypass=$bypass"; fi

########################################################################
echo "=== REQ-AUD-6 ==="
begin "req6-ac1-env-agent-conditional-main-no-prtarget" "environment agent (main-restricted per policy) is attached ONLY for a real adjudicator or a scheduled run — a stub dispatch attaches none; no pull_request_target; the job is not disabled with if:false"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  env_="$(pj "$WORK/sh.json" 'd.get("job_environment")')"; prt="$(pj "$WORK/sh.json" 'd.get("has_pull_request_target")')"
  onlymain="$(pj "$F/policy/env-01.json" 'str([b["name"] for b in d.get("branch_policies",[])]==["main"])')"
  # conditional: gates 'agent' on schedule OR adjudicator==real, empty otherwise (no secrets for a stub dispatch)
  cond="$(printf '%s' "$env_" | grep -qE "adjudicator == 'real'" && printf '%s' "$env_" | grep -q "schedule" && printf '%s' "$env_" | grep -q "'agent'" && printf '%s' "$env_" | grep -qE "\|\| ''" && echo yes || echo no)"
  disabled="$($YAML load "$WF" | "$PY" -c 'import json,sys
try:
    d=json.load(sys.stdin); jb=[j for j in d.get("jobs",{}).values() if isinstance(j,dict) and "agent" in str(j.get("environment") or "")]
    print("yes" if (jb and jb[0].get("if") in (False,"false","${{ false }}")) else "no")
except Exception: print("yes")')"
  { eq "$cond" "yes" && eq "$prt" "false" && eq "$onlymain" "True" && eq "$disabled" "no"; } \
    && ok || no "environment agent conditional on real/schedule, main-only, no pr_target, not if:false" "cond_agent=$cond env=[$env_] prtarget=$prt main-only=$onlymain disabled=$disabled"; fi

begin "req6-ac1-oidc-federation-no-api-key" "id-token:write + contents:read, OIDC audience via github-script into the identity-token file, no ANTHROPIC_API_KEY (all from the parsed doc, comments never count)"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  idt="$(pj "$WORK/sh.json" 'd.get("permissions",{}).get("id-token")')"; cont="$(pj "$WORK/sh.json" 'd.get("permissions",{}).get("contents")')"
  aud="$(pj "$WORK/sh.json" 'd.get("oidc_audience")')"; ghs="$(pj "$WORK/sh.json" 'd.get("uses_github_script_idtoken")')"
  tf="$(pj "$WORK/sh.json" 'd.get("sets_identity_token_file")')"; apik="$(pj "$WORK/sh.json" 'd.get("references_anthropic_api_key")')"
  { eq "$idt" "write" && eq "$cont" "read" && eq "$aud" "https://api.anthropic.com" && eq "$ghs" "true" && eq "$tf" "true" && eq "$apik" "false"; } \
    && ok || no "OIDC wired via github-script, no API key" "id-token=$idt contents=$cont audience=$aud github-script=$ghs token-file=$tf api-key=$apik"; fi

begin "req6-ac1-identifiers-are-env-secrets" "the identifiers + tokens (both auditor seats) come from secrets.* (GitHub masks them); the ONLY vars.* are the non-secret AUDITOR_SCHEDULE_MODE and AUDITOR_AUTOMERGE toggles — no secret identifier is ever a vars.*"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  # + the scanner panel's second auditor seat (scanner-panel rule 8(b), owner Oct 2): its federation identifiers and
  #   model are environment secrets too (same AC: ids only from the environment, never vars.* or a file)
  want='["ANTHROPIC_FEDERATION_RULE_ID","ANTHROPIC_ORGANIZATION_ID","ANTHROPIC_SERVICE_ACCOUNT_ID","ANTHROPIC_WORKSPACE_ID","AUDITOR_APP_ID","AUDITOR_APP_PRIVATE_KEY","AUDITOR_MODEL_FALLBACK","AUDITOR_MODEL_PRIMARY","PANEL_AUDIT_B_IDENTITY_PROVIDER_ID","PANEL_AUDIT_B_MODEL","PANEL_AUDIT_B_PROJECT_ID","PANEL_AUDIT_B_SERVICE_ACCOUNT_ID"]'
  fromsecrets="$(pj "$WORK/sh.json" 'str(sorted(d.get("secret_refs",[]))=='"$want"')')"
  # the only permitted variable is the non-secret schedule toggle; none of the secret
  # identifiers may appear as vars.* (they would not be masked)
  onlytoggle="$(pj "$WORK/sh.json" 'str(sorted(d.get("identifier_env_vars",[]))==["AUDITOR_AUTOMERGE","AUDITOR_SCHEDULE_MODE"])')"
  { eq "$fromsecrets" "True" && eq "$onlytoggle" "True"; } \
    && ok || no "identifiers via secrets.* (no SNYK_TOKEN: the auditor runs no scanner); only vars.* are AUDITOR_SCHEDULE_MODE + AUDITOR_AUTOMERGE" "from_secrets=$fromsecrets only_toggle=$onlytoggle vars=$(pj "$WORK/sh.json" 'd.get("identifier_env_vars")')"; fi

begin "req6-ac2-token-budget-in-workflow" "driving usage to the budget stops the run with tokens_used>0 up to the cap"
o="$WORK/budget"; rm -rf "$o"
run "$PY" "$BIN/auditor-loop-guard.py" --token-budget 2500 --adjudicator "$STUB" --out "$o" && {
  stopped="$(pj "$o/budget.json" 'd.get("stopped_on_budget")')"; used="$(pj "$o/budget.json" 'd.get("tokens_used")')"
  { eq "$stopped" "true" && [ "$used" != "$MISS" ] && [ "$used" -gt 0 ] 2>/dev/null && [ "$used" -le 3500 ] 2>/dev/null; } \
    && ok || no "stopped at the budget with tokens_used>0" "stopped=$stopped tokens=$used"; }

begin "req6-ac3-five-iteration-stop" "the loop makes exactly five model attempts (ledger has 5 lines) then stops and reports"
o="$WORK/loop"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-loop-guard.py" --max 5 --scenario would-loop --adjudicator "$STUB" --out "$o" && {
  n="$(ledger_n)"; stop="$(pj "$o/stop.json" 'd.get("stopped_and_reported")')"
  { eq "$stop" "true" && eq "$n" "5"; } && ok || no "exactly 5 ledger attempts and a stop report" "attempts=$n stop=$stop"; }

begin "req6-ac4-no-key-leak" "a canary is never printed to stdout OR stderr, nor written anywhere under the output tree"
o="$WORK/leak"; rm -rf "$o"; canary="sk-""ant-oat01-CANARY-$$"   # split: this suite lives under the scanned .github/agent/
run env AUDITOR_TEST_CANARY="$canary" "$PY" "$BIN/auditor-no-key-leak.py" --scan .github/agent --out "$o" && {
  inout="$(printf '%s' "$OUT" | grep -cF "$canary")"
  inerr="$(grep -cF "$canary" "$WORK/stderr" 2>/dev/null)"; inerr="${inerr:-0}"
  intree="$(grep -rlF "$canary" "$o" 2>/dev/null | wc -l | tr -d ' ')"
  reported="$(pj "$o/leak.json" 'len(d.get("leaks",[]))')"
  { eq "$inout" "0" && eq "$inerr" "0" && eq "$intree" "0" && eq "$reported" "0"; } \
    && ok || no "no canary in stdout/stderr/output tree; zero reported" "stdout=$inout stderr=$inerr tree=$intree reported=$reported"; }

########################################################################
echo "=== REQ-AUD-7 ==="
begin "req7-ac1-report-header" "the header is a rendered document (not the run-state JSON): each scanner name sits beside its version, plus the digest and the model role (no model id)"
o="$WORK/rep.md"; rm -f "$o"
run "$PY" "$BIN/auditor-report.py" --run-state "$F/run-state/rs-01.json" --out "$o" && {
  notjson="$(is_json "$o")"
  adj="$("$PY" -c 'import re,sys
t=open(sys.argv[1]).read()
pairs=[("grype","0.118.0"),("osv-scanner","2.6.0"),("trivy","0.74.0"),("snyk","1.1307.0")]
def near(a,b):
    for line in t.splitlines():
        if a in line and b in line: return True
    return False
print("yes" if all(near(a,b) for a,b in pairs) else "no")' "$o")"
  hasdig="$(grep -qF "$rs01digest" "$o" && echo yes || echo no)"
  role="$(grep -qiE 'primary|fallback' "$o" && echo yes || echo no)"
  noid="$(grep -qE 'claude-[a-z0-9.-]+' "$o" && echo no || echo yes)"
  { eq "$notjson" "no" && eq "$adj" "yes" && eq "$hasdig" "yes" && eq "$role" "yes" && eq "$noid" "yes"; } \
    && ok || no "rendered (not JSON), scanner name+version adjacency, digest, model role, no model id" "is_json=$notjson adjacency=$adj digest=$hasdig role=$role no_model_id=$noid"; }

begin "req7-ac2-scanner-down-first-line-not-clean" "the first line states trivy failed to run and a machine status sidecar exists with run_status != clean"
o="$WORK/repd.md"; rm -f "$o"; rm -f "$o.status.json"
run "$PY" "$BIN/auditor-report.py" --run-state "$F/run-state/rs-02.json" --out "$o" && {
  first="$(sed -n '1p' "$o")"
  firstok="$(printf '%s' "$first" | grep -qi trivy && printf '%s' "$first" | grep -qiE 'did not run|failed to run|could not run' && echo yes || echo no)"
  sidecar="$(have "$o.status.json" && echo present || echo none)"
  status="$(pj "$o.status.json" 'd.get("run_status")')"
  { eq "$firstok" "yes" && eq "$sidecar" "present" && [ "$status" != "clean" ] && [ "$status" != "$MISS" ]; } \
    && ok || no "first line trivy-failed and a status sidecar != clean" "first_ok=$firstok sidecar=$sidecar status=$status"; }

begin "req7-ac3-sections-populated" "the report places each finding under its section by disposition: FP in 5, real-fixable in 3 (ids in sections, not headings)"
o="$WORK/repm.md"; rm -f "$o"
run "$PY" "$BIN/auditor-report.py" --run-state "$F/run-state/rs-03.json" --out "$o" && {
  s5="$(sect_ids "$o" 5)"; s3="$(sect_ids "$o" 3)"
  { printf '%s' "$s5" | grep -q 'CVE-2016-2781' && printf '%s' "$s3" | grep -q 'GO-2021-0113' && ! printf '%s' "$s5" | grep -q 'GO-2021-0113'; } \
    && ok || no "FP id in section 5, fixable id in section 3" "sec5=[$s5] sec3=[$s3]"; }

########################################################################
echo "=== REQ-AUD-8 ==="
begin "req8-ac1-defensive-never-exploit-code" "captured prompts are non-empty and defensive, and no emitted artifact contains a prohibited/exploit marker"
o="$WORK/adj1"; rm -rf "$o"
run "$PY" "$BIN/auditor-adjudicate.py" --scenario "$F/adjudicator/scenario-01.json" --adjudicator "$STUB" --capture-prompts "$o/prompts.txt" --out "$o" && {
  nonempty="$( [ -s "$o/prompts.txt" ] && echo yes || echo no )"
  defensive="$(grep -qiE 'exploit|proof of concept|weaponi|PROHIBITED-RESPONSE' "$o/prompts.txt" 2>/dev/null && echo no || echo yes)"
  noexploit="$(grep -rqiE 'PROHIBITED-RESPONSE|exploit code|weaponi' "$o" 2>/dev/null && echo no || echo yes)"
  { eq "$nonempty" "yes" && eq "$defensive" "yes" && eq "$noexploit" "yes"; } \
    && ok || no "non-empty defensive prompts, no exploit artifact" "nonempty=$nonempty defensive=$defensive no_exploit=$noexploit"; }

begin "req8-ac2-deterministic-steps-no-model" "each deterministic step exits 0, produces its correct result, and leaves the ledger empty with the fail-on-call spy"
detok=yes
: > "$LEDGER"; dl="$WORK/det-dl"; rm -rf "$dl"
"$PY" "$BIN/auditor-defectlog.py" run --log "$F/dl/log.json" --findings "$F/dl/findings-01.json" --adjudicator "$NOCALL" --out "$dl" >/dev/null 2>&1 || detok=no
[ -s "$LEDGER" ] && detok=no
[ "$(pj "$dl/result.json" 'd["closed"][0]["disposition"]')" = "false_positive" ] || detok=no
printf '%s' "$(pj "$dl/result.json" 'd["closed"][0]["finding_id"]')" | grep -qE '^CVE-' || detok=no
: > "$LEDGER"; dv="$WORK/det-v"; rm -rf "$dv"
"$PY" "$BIN/auditor-votes.py" --manifest "$FX/run/manifest-01.json" --cve CVE-2011-3374 --adjudicator "$NOCALL" --out "$dv" >/dev/null 2>&1 || detok=no
[ -s "$LEDGER" ] && detok=no
[ "$(pj "$dv/votes.json" 'd.get("distinct_lineages")')" = "4" ] || detok=no
eq "$detok" "yes" && ok || no "each deterministic step exits 0, correct result, empty ledger" "a step errored, was wrong, or called the model"

begin "req8-ac3-fallback-order-and-logged" "the ledger shows primary,rephrase,fallback with DISTINCT model roles for the refused finding, UNASSESSABLE adjudicated three times, refusals logged; the fully-refused one reaches section 4"
o="$WORK/adj2"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-adjudicate.py" --scenario "$F/adjudicator/scenario-01.json" --adjudicator "$STUB" --out "$o" && {
  order="$(grep '^CVE-2021-44228|' "$LEDGER" | cut -d'|' -f2 | paste -sd, -)"
  roles="$(grep '^CVE-2021-44228|' "$LEDGER" | cut -d'|' -f3 | sort -u | paste -sd, -)"
  unn="$(grep -c '^UNASSESSABLE|' "$LEDGER")"
  sec4="$(pj "$o/adjudication.json" 'd["UNASSESSABLE"]["report_section"]')"
  logged="$(pj "$o/refusal-log.json" 'len(d.get("refusals",[]))')"
  { eq "$order" "primary,rephrase,fallback" && printf '%s' "$roles" | grep -q 'fallback' && eq "$unn" "3" && eq "$sec4" "4" && [ "$logged" != "$MISS" ] && [ "$logged" -ge 2 ] 2>/dev/null; } \
    && ok || no "fallback order with distinct roles, UNASSESSABLE x3, section 4, refusals logged" "order=$order roles=$roles unassessable=$unn section=$sec4 logged=$logged"; }

########################################################################
echo "=== REQ-AUD-9 ==="
begin "req9-ac1-one-owner-issue-assigned-yesno-evidence" "exactly one issue, owner-decision label, owner assignee, TITLE 'owner-decision: <id> — <package> — <threshold reason>' (R14 mail-filter prefix), and evidence id + artifact in the body"
ghs="$WORK/n1.json"; rm -f "$ghs"; o="$WORK/n1"; rm -rf "$o"
run "$PY" "$BIN/auditor-notify.py" --github "$GH" --state "$ghs" --finding "$F/poam/poam-02.json" --kev "$F/kev/kev.json" --artifact "PR#52" --out "$o" && {
  n="$(pj "$ghs" 'len(d["issues"])')"; lab="$(pj "$ghs" 'd["issues"][0]["label"]')"; asg="$(pj "$ghs" 'd["issues"][0]["assignee"]')"
  title="$(pj "$ghs" 'd["issues"][0]["title"]')"
  titleok="$("$PY" -c 'import re,sys
t=sys.argv[1]
print("yes" if re.match(r"^auditor: owner-decision: CVE-2023-4911 — libc6 — \S", t) else "no")' "$title")"
  bodyok="$("$PY" -c 'import json,sys
try:
    d=json.load(open(sys.argv[1])); i=d["issues"][0]
    body=" ".join(list(i.get("comments",[])))
    print("yes" if (len(i.get("comments",[]))>=1 and "CVE-2023-4911" in body and "PR#52" in body) else "no")
except Exception: print("no")' "$ghs")"
  { eq "$n" "1" && eq "$lab" "owner-decision" && eq "$asg" "fosterstack-admin" && eq "$titleok" "yes" && eq "$bodyok" "yes"; } \
    && ok || no "one issue, owner-decision label+assignee, titled '<id> — <package> — <reason>', evidence+artifact" "issues=$n label=$lab assignee=$asg title=[$title] titleok=$titleok body=$bodyok"; }

begin "req9-ac2-next-run-updates-not-duplicates" "the second run exits 0 and the comment count goes from exactly 1 to exactly 2 on the same single issue"
ghs="$WORK/n2.json"; rm -f "$ghs"
run "$PY" "$BIN/auditor-notify.py" --github "$GH" --state "$ghs" --finding "$F/poam/poam-02.json" --kev "$F/kev/kev.json" --out "$WORK/n2a" && {
  c1="$(pj "$ghs" 'len(d["issues"][0].get("comments",[]))')"
  run "$PY" "$BIN/auditor-notify.py" --github "$GH" --state "$ghs" --finding "$F/poam/poam-02.json" --kev "$F/kev/kev.json" --out "$WORK/n2b" && {
    n="$(pj "$ghs" 'len(d["issues"])')"; c2="$(pj "$ghs" 'len(d["issues"][0].get("comments",[]))')"
    { eq "$n" "1" && eq "$c1" "1" && eq "$c2" "2"; } \
      && ok || no "one issue, comments exactly 1 then 2" "issues=$n comments_run1=$c1 comments_run2=$c2"; }; }

begin "req9-ac3-five-named-triggers-issue-only-channel" "exactly the five named triggers, owner-decision-issue channel, never support@"
o="$WORK/trig"; rm -rf "$o"
run "$PY" "$BIN/auditor-notify.py" --list-triggers --out "$o" && {
  five="$(pj "$o/triggers.json" '",".join(d.get("triggers",[]))')"; chan="$(pj "$o/triggers.json" 'd.get("only_channel")')"
  sup="$(grep -qF 'support@' "$o/triggers.json" && echo yes || echo no)"
  # "nothing else notifies": a below-threshold (non-trigger) finding opens NO issue.
  ghn="$WORK/n3.json"; rm -f "$ghn"
  run "$PY" "$BIN/auditor-notify.py" --github "$GH" --state "$ghn" --finding "$F/poam/poam-01.json" --kev "$F/kev/kev.json" --out "$WORK/n3" && {
    nonneg="$( [ -f "$ghn" ] && pj "$ghn" 'len(d.get("issues",[]))' || echo 0 )"
    { eq "$five" "reachable-nofix-critical-kev-or-exploited,unassessed-after-fallback,five-iteration-stop,fips-module-selection-failure,behaviour-change-under-bump" && eq "$chan" "owner-decision-issue" && eq "$sup" "no" && eq "$nonneg" "0"; } \
      && ok || no "five named triggers, issue-only channel, no support@, non-trigger opens no issue" "triggers=$five channel=$chan support@=$sup nontrigger_issues=$nonneg"; }; }

########################################################################
echo "=== REQ-AUD-10 / REQ-AUD-11 ==="
begin "req10-ac1-no-bypass-path" "a failing required check blocks the merge, observed as no merge in the shim ledger"
o="$WORK/r0"; rm -rf "$o"; shim="$WORK/r0.log"; rm -f "$shim"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-rule0-check.py" --required-checks-state failing --out "$o" && {
  merged="$( [ -f "$shim" ] && grep -c 'merge' "$shim" || echo 0 )"
  blocked="$(pj "$o/rule0.json" 'd.get("merge_blocked_on_failing_checks")')"; viapr="$(pj "$o/rule0.json" 'd.get("all_changes_via_pr")')"
  { eq "$blocked" "true" && eq "$viapr" "true" && eq "$merged" "0"; } && ok || no "merge blocked, all changes via PR, no merge in shim" "blocked=$blocked via_pr=$viapr merges=$merged"; }

# REQ-AUD-11 — acceptance found by owner login AND issue number; wrong-author (identical
# comment, different author) is held; below-threshold promotes.
for spec in "hold:iss-02" "promote:iss-01" "hold:iss-04" "hold:iss-03"; do
  want="${spec%%:*}"; iss="${spec##*:}"
  case "$iss" in iss-01) nm="promote-accepted";; iss-02) nm="hold-unaccepted";; iss-03) nm="hold-wrong-author";; iss-04) nm="hold-review-only";; esac
  begin "req11-ac1-$nm" "release authorization decides $want for $iss by matching the owner login and issue number"
  o="$WORK/rz-$iss"; rm -rf "$o"
  run "$PY" "$BIN/auditor-release-authz.py" --candidate "$F/release/cand-01.json" --issues "$F/release/$iss.json" --owner fosterstack-admin --out "$o/authz.json" && {
    d="$(pj "$o/authz.json" 'd.get("decision")')"; eq "$d" "$want" && ok || no "decision $want" "decision=$d"; }
done
begin "req11-ac1-promote-below-threshold" "a below-threshold candidate promotes regardless of acceptance"
o="$WORK/rz-below"; rm -rf "$o"
run "$PY" "$BIN/auditor-release-authz.py" --candidate "$F/release/cand-02.json" --issues "$F/release/iss-02.json" --owner fosterstack-admin --out "$o/authz.json" && {
  d="$(pj "$o/authz.json" 'd.get("decision")')"; eq "$d" "promote" && ok || no "decision promote" "decision=$d"; }

########################################################################
echo "=== REQ-AUD-12 — end-to-end dry-run / real-run integration (pending owner ratification) ==="
begin "req12-ac1-dryrun-deterministic-rows-actions-status" "a dry-run over the manifest routes DETERMINISTICALLY (no model call): log FPs and the unreachable Go finding close in §5 with evidence; fixable findings sit in §3 each with an action; §6 lists the would-open PRs; accepted-items exists; the status line is AUDIT COMPLETE; zero shim creates"
o="$WORK/run1"; shim="$WORK/run1.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  s5="$(sect_ids "$o/report.md" 5)"; s3="$(sect_ids "$o/report.md" 3)"; s6="$(sed -n '/^## PRs and issues this run/,/^## 0\./p' "$o/report.md")"
  vexev="$(pj "$o/evidence/CVE-2016-2781.evidence.json" 'str(bool(d.get("evidence")))')"
  ig="$(have "$o/ignores/grype/CVE-2016-2781.json" && echo yes || echo no)"           # panel mode writes no per-scanner ignore file (rule 4)
  unrv="$(pj "$o/vex/CVE-2020-14040.openvex.json" 'd["statements"][0].get("justification")')"
  acc="$(have "$o/.auditor/accepted-items.json" && echo yes || echo no)"
  status="$(grep -c 'AUDIT COMPLETE' "$o/report.md" 2>/dev/null)"; status="${status:-0}"
  # every §3 row carries an "action:" (never a resting place)
  s3noaction="$("$PY" -c 'import re,sys
t=open(sys.argv[1]).read().splitlines(); cur=None; bad=0
for l in t:
    m=re.match(r"^## (\d+)\.",l)
    if m: cur=m.group(1); continue
    if cur=="3" and re.match(r"^(CVE|GO)-",l) and "action:" not in l: bad+=1
print(bad)' "$o/report.md")"
  # the DETERMINISTIC paths make NO model call: a log FP hit (CVE-2016-2781) and the
  # unreachable Go finding (CVE-2020-14040) must be absent from the ledger. (A unique-lineage
  # sibling may legitimately draw a single FP-suspicion call — that is the ONLY model use.)
  det2781="$(grep -c '^CVE-2016-2781|' "$LEDGER" 2>/dev/null)"; det2781="${det2781:-0}"
  det14040="$(grep -c '^CVE-2020-14040|' "$LEDGER" 2>/dev/null)"; det14040="${det14040:-0}"
  shimcreates="$(grep -cE 'pr create|issue create|gh .*create' "$shim" 2>/dev/null)"; shimcreates="${shimcreates:-0}"
  { printf '%s' "$s5" | grep -q CVE-2016-2781 && printf '%s' "$s5" | grep -q CVE-2020-14040 && printf '%s' "$s3" | grep -q CVE-2023-4911 \
    && eq "$vexev" "True" && eq "$ig" "no" && eq "$unrv" "vulnerable_code_not_in_execute_path" && eq "$acc" "yes" \
    && eq "$s3noaction" "0" && printf '%s' "$s6" | grep -qi 'would open' && [ "$status" -ge 1 ] 2>/dev/null \
    && eq "$det2781" "0" && eq "$det14040" "0" && eq "$shimcreates" "0"; } \
    && ok || no "deterministic §5/§3, every §3 row actioned, §6 would-open, AUDIT COMPLETE, deterministic paths made no model call, no shim" "s5=[$s5] s3=[$s3] s6=[$s6] vexev=$vexev ig=$ig unreach=$unrv acc=$acc s3_no_action=$s3noaction status=$status det2781=$det2781 det14040=$det14040 shim=$shimcreates"; }

begin "req12-ac2-realrun-opens-the-prs-through-the-shim" "with a delivery channel (shim), dry_run=false DELIVERS the Go bump as a DRAFT PR (go get + go mod tidy, go.mod/go.sum) recorded in the shim ledger, plus the suppression draft PR; a base rebuild is NOT a PR (defers to Dependabot)"
o="$WORK/run2"; shim="$WORK/run2.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  bump="$(grep -cE 'pr create --draft .*auditor/bump' "$shim" 2>/dev/null)"; bump="${bump:-0}"
  baserb="$(grep -cE 'auditor/base-rebuild' "$shim" 2>/dev/null)"; baserb="${baserb:-0}"
  goget="$(grep -cE '^go get ' "$shim" 2>/dev/null)"; goget="${goget:-0}"
  tidy="$(grep -cE '^go mod tidy' "$shim" 2>/dev/null)"; tidy="${tidy:-0}"
  addonly="$(grep -cE '^gh api graphql createCommitOnBranch auditor/bump-[^ ]+ -- go\.mod go\.sum$' "$shim" 2>/dev/null)"; addonly="${addonly:-0}"
  { [ "$bump" -ge 1 ] 2>/dev/null && [ "$baserb" -eq 0 ] 2>/dev/null && [ "$goget" -ge 1 ] 2>/dev/null && [ "$tidy" -ge 1 ] 2>/dev/null && [ "$addonly" -ge 1 ] 2>/dev/null; } \
    && ok || no "draft bump PR delivered via go get/tidy + a signed API commit of go.mod/go.sum only; base rebuild is not a PR" "bump=$bump base_rebuild_prs=$baserb goget=$goget tidy=$tidy signed_commit_gomod_gosum=$addonly"; }

begin "req12-ac3-workflow-invokes-the-entrypoint-with-dryrun" "the workflow's run step invokes auditor-run.py with the dispatch dry_run input"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  runs="$(pj "$WORK/sh.json" 'd.get("runs_auditor_run")')"
  eq "$runs" "true" && ok || no "run step invokes auditor-run.py with inputs.dry_run" "runs_auditor_run=$runs"; fi

begin "req3-ac3-workflow-carries-the-nochange-state" "auditor.yml (REQ-AUD-3 AC3): the state is fetched only from a successful schedule/dispatch run of THIS workflow on main, handed to the driver as --prev-state, and uploaded as its own artifact (3 days, real adjudicator on the day's candidate only); the audit trail's retention is unchanged; every action reference stays a commit digest"
if ! have "$WF"; then no "$WF present" "absent"; else
  r="$(WF="$WF" "$PY" - <<'PY'
import os, re, yaml
wf = yaml.safe_load(open(os.environ["WF"]))
steps = wf["jobs"]["audit"]["steps"]
by = {s.get("name"): s for s in steps}
f = by.get("Select and download the day's main-candidate-rescan artifacts")     # the fetch lives in this existing step: no step is inserted before the audited download exception's index
u = by.get("Upload the no-change state"); t = by.get("Upload the full audit trail")
run = next(s for s in steps if "auditor-run.py" in (s.get("run") or ""))
bad = []
r = (f or {}).get("run", "")
for need in ("--workflow auditor.yml", "--branch main", "--status completed", "--event schedule", "--event workflow_dispatch", "-n auditor-state"):
    if need not in r: bad.append("fetch lacks " + need)
if r.count("--branch main") < 3 or r.count("--status completed") < 2 or r.count("--workflow auditor.yml") < 2:
    bad.append("each auditor-state run listing must be limited to this workflow, branch main and completed runs")
if "pull_request" in r: bad.append("fetch names pull_request")
if (f or {}).get("env", {}).get("GH_TOKEN") != "${{ github.token }}": bad.append("fetch token is not the job token")
if "--prev-state" in run["run"]: bad.append("the run step's text changed (its sha256 is bound by the pin checker's download exception)")
if run.get("env", {}).get("AUDITOR_PREV_STATE") != "${{ runner.temp }}/prev-state/auditor-state.json": bad.append("run step does not set AUDITOR_PREV_STATE")
if not u: bad.append("no upload step")
else:
    w = u["with"]
    if w.get("name") != "auditor-state": bad.append("upload name")
    if w.get("retention-days") != 3: bad.append("upload retention is not 3 days")
    if not re.fullmatch(r"actions/upload-artifact@[0-9a-f]{40}", u["uses"].split(" ")[0]): bad.append("upload action not a digest")
    cond = u.get("if", "")
    for need in ("inputs.adjudicator == 'real'", "inputs.test_image == ''", "inputs.known_defect_log == '.github/agent/known-defect-log.json'"):
        if need not in cond: bad.append("upload not limited by " + need)
    if not str(w.get("path", "")).endswith("auditor-out/.auditor/auditor-state.json"): bad.append("upload path")
if "retention-days" in (t or {}).get("with", {}): bad.append("the audit trail's retention was changed")
# EVALUATE the upload condition for the runs that must / must not write the state (a schedule run has no inputs at all)
if u:
    expr = u.get("if", "").strip()
    assert expr.startswith("${{") and expr.endswith("}}"), expr
    py = expr[3:-2].strip().replace("&&", " and ").replace("||", " or ").replace("always()", "True")
    class NS(dict):
        __getattr__ = dict.get
    def ev(event, **inp):
        ns = {"github": NS(event_name=event), "inputs": NS({k: v for k, v in inp.items()})}
        return bool(eval(py, {"__builtins__": {}}, ns))
    real = dict(adjudicator="real", test_image="", known_defect_log=".github/agent/known-defect-log.json")
    for label, got, want in (("schedule (no inputs)", ev("schedule"), True), ("dispatch real, day's candidate, committed log", ev("workflow_dispatch", **real), True),
                             ("dispatch stub", ev("workflow_dispatch", **dict(real, adjudicator="stub")), False),
                             ("dispatch with a test image", ev("workflow_dispatch", **dict(real, test_image="x@sha256:1")), False),
                             ("dispatch with another defect log", ev("workflow_dispatch", **dict(real, known_defect_log="fixtures/log.json")), False)):
        if got != want: bad.append("upload condition for %s is %s, want %s" % (label, got, want))
print("ok" if not bad else "; ".join(bad))
PY
)"
  eq "$r" "ok" && ok || no "fetch/pass/upload shape" "$r"; fi
begin "req15-workflow-installs-the-pinned-go-for-the-records-step" "auditor.yml (REQ-VEND-001-AC15): the pinned Go toolchain is installed at its fixed path (bin/install-scanner.sh go) INSIDE the existing manifest step, as a warning-only step of that step (it never fails the audit), with no step added before the audited download exception's step; the 'Run the auditor' step's text is untouched; the pin checker finds nothing in the tree"
if ! have "$WF"; then no "$WF present" "absent"; else
  r="$(WF="$WF" "$PY" - <<'PY'
import hashlib, os, re, subprocess, sys, yaml
wf = yaml.safe_load(open(os.environ["WF"]))
steps = wf["jobs"]["audit"]["steps"]
bad = []
m = next((s for s in steps if "auditor-manifest.py" in (s.get("run") or "")), None)
if not m: bad.append("no manifest step")
else:
    r = m["run"]
    if not re.search(r"^\s*\./bin/install-scanner\.sh go\s*\\?\n?\s*\|\| echo \"::warning::", r, re.M): bad.append("the manifest step does not install the pinned go as a warning-only command")
    g = r.find("install-scanner.sh go")
    if g < 0 or g > r.index("auditor-manifest.py"): bad.append("the go install must be present and come before the manifest is built")
run = next(s for s in steps if "auditor-run.py" in (s.get("run") or ""))
sys.path.insert(0, ".github/agent/bin")
spec = __import__("importlib.util").util.spec_from_file_location("cap", ".github/agent/bin/check-action-pins.py"); cap = __import__("importlib.util").util.module_from_spec(spec); spec.loader.exec_module(cap)
idx = steps.index(run); sha = hashlib.sha256(run["run"].encode()).hexdigest()
if (".github/workflows/auditor.yml", "audit", idx, sha) not in cap.DOWNLOAD_EXCLUSIONS: bad.append("the 'Run the auditor' step moved or changed: its audited download exception (index %d, sha256 %s) no longer matches" % (idx, sha[:12]))
rc = subprocess.run([sys.executable, ".github/agent/bin/check-action-pins.py"], capture_output=True, text=True)
if rc.returncode != 0: bad.append("the pin checker fails the tree: " + rc.stdout[-200:])
print("ok" if not bad else "; ".join(bad))
PY
)"
  eq "$r" "ok" && ok || no "install inside the manifest step, run step untouched, pin checker clean" "$r"; fi

begin "req12-schedule-mode-unset-is-dry" "a scheduled run is DRY unless the repo variable AUDITOR_SCHEDULE_MODE is exactly 'live' (unset => dry); both the dry flag and the App-token step follow it; dispatch follows dry_run"
if ! have "$WF"; then no "$WF present" "absent"; else
  r="$(WF="$WF" "$PY" - <<'PY'
import os, re, sys
sys.path.insert(0, ".github/agent/fixtures/testlib")
import pyyaml as yaml
doc = yaml.safe_load(open(os.environ["WF"]).read()) or {}
jobs = doc.get("jobs") or {}
# the audit job by its id (the seat-probe job also runs in the agent environment); the old lookup is the fallback
job = jobs.get("audit") or next((j for j in jobs.values() if isinstance(j, dict) and j.get("environment") == "agent"), None) or (list(jobs.values())[0] if jobs else {})
steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
apptok = next((s for s in steps if s.get("id") == "app-token"), None)
runstep = next((s for s in steps if isinstance(s.get("run"), str) and "dry='${{" in s["run"]), None)
if not apptok or not runstep:
    print("BAD: could not find app-token step or dry assignment"); sys.exit()
if_expr = apptok.get("if") or ""
m = re.search(r"dry='(\$\{\{.*?\}\})'", runstep["run"])
if not m:
    print("BAD: no dry expression"); sys.exit()
dry_expr = m.group(1)

# --- minimal GitHub Actions expression evaluator (the operators these two use) ---
def tokenize(e):
    e = e.strip()
    assert e.startswith("${{") and e.endswith("}}"), e
    e = e[3:-2]
    toks, i = [], 0
    while i < len(e):
        c = e[i]
        if c.isspace(): i += 1; continue
        if c == "'":
            j = e.index("'", i+1); toks.append(("str", e[i+1:j])); i = j+1; continue
        two = e[i:i+2]
        if two in ("==","!=","&&","||"):
            toks.append(("op", two)); i += 2; continue
        if c in "()":
            toks.append(("par", c)); i += 1; continue
        j = i
        while j < len(e) and (e[j].isalnum() or e[j] in "._"): j += 1
        w = e[i:j]; i = j
        if w == "true": toks.append(("lit", True))
        elif w == "false": toks.append(("lit", False))
        else: toks.append(("name", w))
    return toks

def truthy(v): return not (v is False or v is None or v == "" or v == 0)

class P:
    def __init__(self, toks, env): self.t = toks; self.i = 0; self.env = env
    def peek(self): return self.t[self.i] if self.i < len(self.t) else (None, None)
    def eat(self): tok = self.t[self.i]; self.i += 1; return tok
    def p_or(self):
        v = self.p_and()
        while self.peek() == ("op","||"): self.eat(); r = self.p_and(); v = v if truthy(v) else r
        return v
    def p_and(self):
        v = self.p_eq()
        while self.peek() == ("op","&&"): self.eat(); r = self.p_eq(); v = r if truthy(v) else v
        return v
    def p_eq(self):
        v = self.p_prim()
        while self.peek()[0] == "op" and self.peek()[1] in ("==","!="):
            op = self.eat()[1]; r = self.p_prim(); v = (v == r) if op == "==" else (v != r)
        return v
    def p_prim(self):
        k, val = self.eat()
        if k == "par" and val == "(":
            v = self.p_or(); assert self.eat() == ("par",")"); return v
        if k == "str": return val
        if k == "lit": return val
        if k == "name": return self.env.get(val)  # unset -> None
        raise AssertionError((k, val))

def ev(expr, env): return P(tokenize(expr), env).p_or()

def norm(v):
    if v is True: return "true"
    if v is False or v is None or v == "": return "false" if v is False else str(v)
    return str(v)

cases = {
  "schedule+unset": {"github.event_name":"schedule"},
  "schedule+live":  {"github.event_name":"schedule", "vars.AUDITOR_SCHEDULE_MODE":"live"},
  "schedule+other": {"github.event_name":"schedule", "vars.AUDITOR_SCHEDULE_MODE":"on"},
  "dispatch+dryT":  {"github.event_name":"workflow_dispatch", "inputs.dry_run":True},
  "dispatch+dryF":  {"github.event_name":"workflow_dispatch", "inputs.dry_run":False},
}
res = {k: (norm(ev(dry_expr, env)), truthy(ev(if_expr, env))) for k, env in cases.items()}
want = {
  "schedule+unset": ("true", False),   # unset => dry, App token NOT minted
  "schedule+live":  ("false", True),   # live => non-dry, App token minted
  "schedule+other": ("true", False),   # anything but 'live' => dry
  "dispatch+dryT":  ("true", False),
  "dispatch+dryF":  ("false", True),
}
print("OK" if res == want else "BAD: %s (dry_expr=%s if_expr=%s)" % (res, dry_expr, if_expr))
PY
)"
  eq "$r" "OK" && ok || no "schedule dry/App-token follow AUDITOR_SCHEDULE_MODE; unset is dry" "$r"; fi

########################################################################
echo "=== REQ-AUD-12 — Round 12: honest scanner status, no empty sections, conclusion ==="

begin "req12-ac4-no-empty-sections-and-conclusion" "the report opens with a Conclusion (stub: no narrative for stub runs) and every one of the 7 sections carries a non-empty sentence — never a blank heading"
o="$WORK/r12a"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --adjudicator "$STUB" --out "$o" && {
  concl="$(grep -A2 '^## Conclusion' "$o/report.md" | grep -v '^##' | grep -v '^$' | head -1)"
  isstub="$(printf '%s' "$concl" | grep -qi 'stub: no narrative' && echo yes || echo no)"
  # every '## N. Title' heading must be followed by at least one non-blank, non-heading line
  blanks="$("$PY" -c '
import re,sys
lines=open(sys.argv[1]).read().splitlines()
bad=0
for i,l in enumerate(lines):
    if re.match(r"^## \d+\.", l):
        nxt=[x for x in lines[i+1:i+3]]
        firstnonblank=next((x for x in lines[i+1:] if x.strip()!=""), "")
        # the immediate next content line must be non-empty and not another heading
        if not firstnonblank or firstnonblank.startswith("## "): bad+=1
print(bad)' "$o/report.md")"
  before_concl="$("$PY" -c '
import sys
t=open(sys.argv[1]).read()
i=t.find("## Conclusion"); j=t.find("## 1.")
print("yes" if (0 <= i < j) else "no")' "$o/report.md")"
  { eq "$isstub" "yes" && eq "$blanks" "0" && eq "$before_concl" "yes"; } \
    && ok || no "conclusion first (stub line), zero blank sections" "conclusion_stub=$isstub blank_sections=$blanks conclusion_before_sections=$before_concl"; }

begin "req12-ac5-zero-inventory-scanner-named-incomplete-fails-job" "a scanner recorded ran:false is named under 'Did not run', the status line is AUDIT INCOMPLETE, and auditor-run EXITS NON-ZERO so the job fails (R13 item 3)"
o="$WORK/r12b"; rm -rf "$o"; : > "$LEDGER"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-down.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; rcx=$?
named="$(grep -qi 'Did not run' "$o/report.md" && grep -qi 'grype' "$o/report.md" && echo yes || echo no)"
incomplete="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"
{ eq "$named" "yes" && eq "$incomplete" "yes" && [ "$rcx" -ne 0 ] 2>/dev/null; } \
  && ok || no "grype named did-not-run, AUDIT INCOMPLETE, non-zero exit" "named=$named incomplete=$incomplete exit=$rcx"

########################################################################
echo "=== inner-loop regressions (round 1) ==="

begin "il1-sibling-not-dropped" "a CVE partly covered by a log FP does NOT close the whole group: the uncovered sibling is routed to its own row with an action, never silently dropped"
o="$WORK/il1"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  # CVE-2011-3374 must appear in §5 (log-FP, apt) AND in §2 (uncovered subset carried),
  # and every §2/§3 row it produces must carry an action.
  rows="$("$PY" -c 'import json,sys
d=json.load(open(sys.argv[1]))["findings"]
r=[x for x in d if x["id"]=="CVE-2011-3374"]
secs=sorted(x["section"] for x in r)
noact=[x for x in r if x["section"] in (2,3) and (not x.get("action") or x["action"]=="none")]
print("secs=%s rows=%d noaction=%d" % (secs, len(r), len(noact)))' "$o/classification.json")"
  s5="$(sect_ids "$o/report.md" 5)"; s2="$(sect_ids "$o/report.md" 2)"
  { printf '%s' "$rows" | grep -q 'secs=\[2, 5\]' && printf '%s' "$rows" | grep -q 'noaction=0' \
    && printf '%s' "$s5" | grep -q CVE-2011-3374 && printf '%s' "$s2" | grep -q CVE-2011-3374; } \
    && ok || no "sibling routed (§5 + §2), each actioned" "$rows s5=[$s5] s2=[$s2]"; }

begin "il3-model-id-never-in-report" "when the adjudicator errors, the Conclusion is a generic withheld line — the model id / SDK error text never reaches report.md"
o="$WORK/il3"; rm -rf "$o"; fa="$WORK/il3-fail.py"
cat > "$fa" <<'PYEOF'
import sys
sys.stderr.write("Error code: 404 model: claude-secret-codename-zzz not found\n")
sys.exit(5)
PYEOF
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --out "$o" >/dev/null 2>&1
leaked="$(grep -c 'claude-secret-codename-zzz' "$o/report.md" 2>/dev/null)"; leaked="${leaked:-0}"
withheld="$(grep -qi 'conclusion withheld' "$o/report.md" && echo yes || echo no)"
{ eq "$leaked" "0" && eq "$withheld" "yes"; } \
  && ok || no "no model id in report.md; conclusion withheld generically" "leaked=$leaked withheld=$withheld"

begin "il4-split-cve-distinct-vex-no-clobber" "a CVE that is not_affected for one package and carried for a sibling writes TWO distinct VEX files; the not_affected document is NOT overwritten by the affected one"
o="$WORK/il4"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  main_status="$(pj "$o/vex/CVE-2011-3374.openvex.json" 'd["statements"][0].get("status")')"
  sib="$(have "$o/vex/CVE-2011-3374-sibling.openvex.json" && echo yes || echo no)"
  sib_status="$(pj "$o/vex/CVE-2011-3374-sibling.openvex.json" 'd["statements"][0].get("status")')"
  { eq "$main_status" "not_affected" && eq "$sib" "yes" && eq "$sib_status" "affected"; } \
    && ok || no "not_affected VEX preserved + distinct affected sibling VEX" "main=$main_status sibling_file=$sib sibling=$sib_status"; }

########################################################################
echo "=== inner-loop regressions (round 3) ==="

begin "il5-owner-issue-deduped-across-runs" "two runs of the same at-threshold no-fix finding open ONE owner-decision issue then a comment, not two creates (REQ-AUD-9 AC2 on the live path)"
o="$WORK/il5"; shim="$WORK/il5.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$WORK/il5b" >/dev/null 2>&1
creates="$(grep -c 'issue create .*CVE-2099-9001' "$shim" 2>/dev/null)"; creates="${creates:-0}"
comments="$(grep -c 'issue comment .*CVE-2099-9001' "$shim" 2>/dev/null)"; comments="${comments:-0}"
{ eq "$creates" "1" && [ "$comments" -ge 1 ] 2>/dev/null; } \
  && ok || no "one issue create + a comment across two runs" "creates=$creates comments=$comments"

begin "dadj-1-adjudicator-unavailable-one-issue-incomplete" "when the adjudicator is UNAVAILABLE (every call errors), the run is AUDIT INCOMPLETE naming the cause, exactly ONE aggregate owner issue 'adjudicator unavailable — N findings unassessed' is opened (never one per finding), and the header names the (masked) cause (R-live fixes 1+3)"
o="$WORK/dadj1"; shim="$WORK/dadj1.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$WORK/pm-partial/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$F/adjudicator/fail-on-call.py" --out "$o" >/dev/null 2>&1
inc="$(grep -c 'AUDIT INCOMPLETE:.*adjudicator unavailable' "$o/report.md" 2>/dev/null)"; inc="${inc:-0}"
agg="$(grep -cE "issue create.*adjudicator unavailable — findings unassessed" "$shim" 2>/dev/null)"; agg="${agg:-0}"
perfinding="$(grep -c 'issue create.*unassessed-after-fallback' "$shim" 2>/dev/null)"; perfinding="${perfinding:-0}"
hdr="$(grep -c 'UNAVAILABLE' "$o/report.md" 2>/dev/null)"; hdr="${hdr:-0}"
{ [ "$inc" -ge 1 ] 2>/dev/null && eq "$agg" "1" && eq "$perfinding" "0" && [ "$hdr" -ge 1 ] 2>/dev/null; } \
  && ok || no "INCOMPLETE names cause; ONE aggregate issue; no per-finding issue; header names cause" "incomplete=$inc aggregate=$agg per_finding=$perfinding header=$hdr"

begin "dadj-2-adjudicator-error-surfaced-but-masked" "an adjudicator error is SURFACED in the report (so it is diagnosable) but any secret value and model id are MASKED — never leaked into report.md (R-live fix 1)"
o="$WORK/dadj2"; rm -rf "$o"; fa="$WORK/dadj2-fail.py"
cat > "$fa" <<'PYEOF'
import os, sys
sys.stderr.write("Error code: 401 auth failed for %s using claude-secret-zzz\n" % os.environ.get("AUDITOR_MODEL_PRIMARY", ""))
sys.exit(7)
PYEOF
AUDITOR_MODEL_PRIMARY="SENTINEL_SECRET_9137" "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-partial/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --out "$o" >/dev/null 2>&1
surfaced="$(grep -c 'UNAVAILABLE' "$o/report.md" 2>/dev/null)"; surfaced="${surfaced:-0}"
leak_secret="$(grep -c 'SENTINEL_SECRET_9137' "$o/report.md" 2>/dev/null)"; leak_secret="${leak_secret:-0}"
leak_model="$(grep -c 'claude-secret-zzz' "$o/report.md" 2>/dev/null)"; leak_model="${leak_model:-0}"
masked="$(grep -cE '<AUDITOR_MODEL_PRIMARY>|<model-id>' "$o/report.md" 2>/dev/null)"; masked="${masked:-0}"
{ [ "$surfaced" -ge 1 ] 2>/dev/null && eq "$leak_secret" "0" && eq "$leak_model" "0" && [ "$masked" -ge 1 ] 2>/dev/null; } \
  && ok || no "error surfaced; secret value + model id masked" "surfaced=$surfaced leak_secret=$leak_secret leak_model=$leak_model masked=$masked"

begin "dadj-4-owner-issue-one-per-cve-package-scopes-in-body" "an at-threshold no-fix (CVE, package) present in TWO scopes opens exactly ONE owner-decision issue whose body lists BOTH scopes — never one issue per binary/version that vendors the package (R-live fix 4)"
o="$WORK/dadj4"; shim="$WORK/dadj4.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-owner-multiscope.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
creates="$(grep -c 'issue create.*CVE-2099-7777' "$shim" 2>/dev/null)"; creates="${creates:-0}"
both="$(grep -c 'libfoo@1' "$shim" 2>/dev/null)"; both="${both:-0}"
both2="$(grep -c 'libfoo@2' "$shim" 2>/dev/null)"; both2="${both2:-0}"
scopes2="$(grep -c 'Scope(s) (2)' "$shim" 2>/dev/null)"; scopes2="${scopes2:-0}"
{ eq "$creates" "1" && [ "$both" -ge 1 ] 2>/dev/null && [ "$both2" -ge 1 ] 2>/dev/null && [ "$scopes2" -ge 1 ] 2>/dev/null; } \
  && ok || no "one issue for (CVE,package) with both scopes in the body" "creates=$creates libfoo@1=$both libfoo@2=$both2 scopes2=$scopes2"

begin "dadj-6-adjudicator-error-dedup-collapses-volatile-request-id" "repeated adjudicator failures that differ ONLY by a per-call request_id collapse to ONE recorded error (not one per finding/attempt), so the header/status is not flooded (R-live fix 1 dedup)"
o="$WORK/dadj6"; rm -rf "$o"; fa="$WORK/dadj6-fail.py"
cat > "$fa" <<'PYEOF'
import os, sys, time
# a unique request_id per invocation — without normalization these would each be "distinct"
sys.stderr.write("APIConnectionError status=503: transient upstream [request_id=req_%d_%d]\n" % (os.getpid(), time.time_ns()))
sys.exit(5)
PYEOF
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-partial/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --out "$o" >/dev/null 2>&1
# one FP-suspicion finding retries primary/rephrase/fallback => >=3 calls => >=3 unique ids;
# after dedup the report keeps exactly ONE representative request_id
ids="$(grep -oE 'req_[0-9]+_[0-9]+' "$o/report.md" 2>/dev/null | sort -u | wc -l | tr -d ' ')"; ids="${ids:-0}"
surfaced="$(grep -c 'transient upstream' "$o/report.md" 2>/dev/null)"; surfaced="${surfaced:-0}"
{ [ "$ids" = "1" ] 2>/dev/null && [ "$surfaced" -ge 1 ] 2>/dev/null; } \
  && ok || no "collapses to one representative request_id; error still surfaced" "distinct_request_ids=$ids surfaced=$surfaced"

begin "dadj-7-one-client-process-for-the-whole-run" "N adjudications go through ONE persistent adjudicator client process — started once (one identity-token exchange), reused for every finding — never a fresh subprocess/exchange per finding (jti_reused fix)"
o="$WORK/dadj7"; rm -rf "$o"; fa="$WORK/dadj7-count.py"; cnt="$WORK/dadj7.count"; rm -f "$cnt"
cat > "$fa" <<'PYEOF'
import json, sys, os
# STARTS once per process (stands in for the single identity-token exchange); REQ once per call.
open(os.environ["ADJ_COUNT"], "a").write("START\n")
if "--serve" in sys.argv:
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        json.loads(line)
        open(os.environ["ADJ_COUNT"], "a").write("REQ\n")
        sys.stdout.write(json.dumps({"refused": False, "category": "unknown", "token_usage": 1}) + "\n"); sys.stdout.flush()
else:
    json.loads(sys.stdin.read() or "{}")
    open(os.environ["ADJ_COUNT"], "a").write("REQ\n")
    json.dump({"refused": False, "category": "unknown", "token_usage": 1}, sys.stdout)
PYEOF
# manifest-owner-multiscope has two unique-lineage no-fix scopes => >=2 adjudications (+narrative)
ADJ_COUNT="$cnt" "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-owner-multiscope.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --out "$o" >/dev/null 2>&1
starts="$(grep -c START "$cnt" 2>/dev/null)"; starts="${starts:-0}"
reqs="$(grep -c REQ "$cnt" 2>/dev/null)"; reqs="${reqs:-0}"
{ eq "$starts" "1" && [ "$reqs" -ge 2 ] 2>/dev/null; } \
  && ok || no "one process start (one exchange) serving >=2 adjudications" "starts=$starts reqs=$reqs"

begin "il6-vex-consolidated-and-delivered-as-draft-pr" "a run that writes VEX consolidates it into suppressions/fosterstack-cache.openvex.json and delivers it as a single draft PR off main (R16), never a direct .vex edit"
o="$WORK/il6"; shim="$WORK/il6.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
consolidated="$(have "$o/suppressions/fosterstack-cache.openvex.json" && echo yes || echo no)"
nstmt="$(pj "$o/suppressions/fosterstack-cache.openvex.json" 'len(d.get("statements",[]))')"
draftpr="$(grep -c 'gh pr create --draft --base main --head auditor/2026-09-24-' "$shim" 2>/dev/null)"; draftpr="${draftpr:-0}"
offmain="$(grep -c 'git checkout -B auditor/2026-09-24-.* origin/main' "$shim" 2>/dev/null)"; offmain="${offmain:-0}"
{ eq "$consolidated" "yes" && [ "$nstmt" -ge 1 ] 2>/dev/null && [ "$draftpr" -ge 1 ] 2>/dev/null && [ "$offmain" -ge 1 ] 2>/dev/null; } \
  && ok || no "consolidated VEX + single draft PR off main" "consolidated=$consolidated statements=$nstmt draft_pr=$draftpr off_main=$offmain"

begin "il7-split-cve-distinct-statement-ids" "the not_affected and affected VEX documents for a split CVE carry DISTINCT statement @ids"
o="$WORK/il7"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  a="$(pj "$o/vex/CVE-2011-3374.openvex.json" 'd["statements"][0]["@id"]')"
  b="$(pj "$o/vex/CVE-2011-3374-sibling.openvex.json" 'd["statements"][0]["@id"]')"
  { [ "$a" != "$MISS" ] && [ "$b" != "$MISS" ] && [ "$a" != "$b" ]; } \
    && ok || no "distinct statement @ids" "main=$a sibling=$b"; }

begin "il8-consistency-not-blind-flags-stale-vex" "the consistency check reads the run's real consolidated suppressions and flags a stale VEX (a statement answering no live finding), so it is no longer structurally blind"
o="$WORK/il8"; supp="$WORK/il8-supp"; rm -rf "$o" "$supp"; mkdir -p "$supp"
printf '{"statements":[{"vulnerability":{"name":"CVE-1999-0001"},"status":"not_affected"}]}' > "$supp/fosterstack-cache.openvex.json"
run "$PY" "$BIN/auditor-consistency.py" --suppression-dir "$supp" --live-findings "$FX/run/manifest-01.json" --out "$o/consistency.json" && {
  stale="$(pj "$o/consistency.json" '",".join(sorted({p["type"] for p in d["problems"]}))')"
  { printf '%s' "$stale" | grep -q 'stale_vex'; } \
    && ok || no "stale_vex flagged (not blind)" "problems=$stale"; }

########################################################################
echo "=== inner-loop regressions (round 4) ==="

begin "il9-pr-branch-created-before-pr-create" "a real run creates the branch (git checkout -B ... origin/main) BEFORE gh pr create for every PR — the PR never targets a branch that was never made"
o="$WORK/il9"; shim="$WORK/il9.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
ordered="$("$PY" -c '
import sys
lines=open(sys.argv[1]).read().splitlines()
ok=True
for i,l in enumerate(lines):
    if l.startswith("gh pr create") and "--head " in l:
        br=l.split("--head ",1)[1].split()[0]
        made=any(x=="git checkout -B "+br+" origin/main" for x in lines[:i])
        if not made: ok=False
print("yes" if ok else "no")' "$shim")"
prs="$(grep -c 'gh pr create' "$shim" 2>/dev/null)"; prs="${prs:-0}"
{ eq "$ordered" "yes" && [ "$prs" -ge 1 ] 2>/dev/null; } \
  && ok || no "every pr-create is preceded by its branch checkout" "ordered=$ordered pr_count=$prs"

begin "il11-consistency-not-false-stale-on-non-cve-id" "a carried VEX for a LIVE non-CVE id (DEBIAN-CVE-*) is not false-flagged stale"
o="$WORK/il11"; supp="$WORK/il11-supp"; rm -rf "$o" "$supp"; mkdir -p "$supp"
printf '{"statements":[{"vulnerability":{"name":"DEBIAN-CVE-2011-3374"},"status":"affected"}]}' > "$supp/fosterstack-cache.openvex.json"
run "$PY" "$BIN/auditor-consistency.py" --suppression-dir "$supp" --live-findings "$FX/run/manifest-01.json" --out "$o/c.json" && {
  probs="$(pj "$o/c.json" 'len(d["problems"])')"
  { eq "$probs" "0"; } && ok || no "no false stale_vex for a live non-CVE id" "problems=$probs"; }

begin "il12-suppressions-in-force-listed-in-section5" "the in-force suppressions are listed in §5 with status tags (v2 removed the standalone §7)"
o="$WORK/il12"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  s5="$(sect_ids "$o/report.md" 5)"
  { printf '%s' "$s5" | grep -q CVE-2011-3374 && printf '%s' "$s5" | grep -q CVE-2020-14040; } \
    && ok || no "§5 lists the in-force (closed) suppressions with their status tags" "sec5=[$s5]"; }

########################################################################
echo "=== inner-loop regressions (round 5) ==="

begin "il13-pr-action-text-honest-no-channel" "a non-dry run with NO delivery channel (no shim, real gh not opted in) never falsely claims 'opened': a Go bump says it is pending an authorized step, and a base rebuild says it defers to Dependabot — never 'opened draft bump PR' (decision 2)"
o="$WORK/il13"; rm -rf "$o"; : > "$LEDGER"
# no AUDITOR_GIT_SHIM_LOG and no AUDITOR_ALLOW_REAL_GH => the safety default: deliver nothing, claim nothing
run "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  lied="$(grep -c 'opened draft bump PR' "$o/report.md" 2>/dev/null)"; lied="${lied:-0}"
  pending="$(grep -c 'bump PR pending: no authorized delivery step' "$o/report.md" 2>/dev/null)"; pending="${pending:-0}"
  defers="$(grep -c "defer to Dependabot's docker PR" "$o/report.md" 2>/dev/null)"; defers="${defers:-0}"
  { eq "$lied" "0" && [ "$pending" -ge 1 ] 2>/dev/null && [ "$defers" -ge 1 ] 2>/dev/null; } \
    && ok || no "no false 'opened'; honest pending bump + base rebuild defers to Dependabot" "opened=$lied pending=$pending defers=$defers"; }

begin "d2-1-gobump-draft-delivered-and-reported" "decision 2: with a delivery channel, a Go-module §3 bump is DELIVERED as a draft PR by the App; the row action says 'opened draft bump PR' and §6 lists it — never a false 'proposed ... delivery pending'"
o="$WORK/d2-1"; shim="$WORK/d2-1.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  opened="$(grep -c 'action: opened draft bump PR' "$o/report.md" 2>/dev/null)"; opened="${opened:-0}"
  sec6="$(grep -c 'bump PR (App):' "$o/report.md")"; sec6="${sec6:-0}"
  stale="$(grep -c 'delivery pending' "$o/report.md" 2>/dev/null)"; stale="${stale:-0}"
  { [ "$opened" -ge 1 ] 2>/dev/null && [ "$sec6" -ge 1 ] 2>/dev/null && eq "$stale" "0"; } \
    && ok || no "Go bump delivered as draft PR, listed in the PR list, no stale 'delivery pending'" "opened=$opened prlist=$sec6 stale=$stale"; }

begin "d2-2-base-rebuild-defers-to-dependabot" "decision 2: an OS-package §3 base rebuild is NOT delivered by the auditor — it defers to Dependabot's docker PR (base is digest-pinned); §6 says 'Awaiting base rebuild (deferred to Dependabot ...)' and no auditor base-rebuild PR is created"
o="$WORK/d2-2"; shim="$WORK/d2-2.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  defers="$(grep -c 'awaiting base rebuild' "$o/report.md")"; defers="${defers:-0}"
  noprs="$(grep -cE 'auditor/base-rebuild' "$shim" 2>/dev/null)"; noprs="${noprs:-0}"
  { [ "$defers" -ge 1 ] 2>/dev/null && eq "$noprs" "0"; } \
    && ok || no "base rebuild defers to Dependabot; no auditor base-rebuild PR" "awaiting=$defers base_rebuild_prs=$noprs"; }

begin "d2-3-bump-delivery-failure-marks-incomplete" "decision 2: a bump PR delivery FAILURE marks the run AUDIT INCOMPLETE and exits non-zero (never a false 'opened')"
o="$WORK/d2-3"; shim="$WORK/d2-3.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
# a delivery failure makes auditor-run exit non-zero by design; do not use run()
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_SHIM_PR_FAIL=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
rc=$?
incomplete="$(grep -c 'AUDIT INCOMPLETE' "$o/report.md" 2>/dev/null)"; incomplete="${incomplete:-0}"
failed="$(grep -c 'bump PR delivery FAILED' "$o/report.md" 2>/dev/null)"; failed="${failed:-0}"
{ [ "$rc" -ne 0 ] 2>/dev/null && [ "$incomplete" -ge 1 ] 2>/dev/null && [ "$failed" -ge 1 ] 2>/dev/null; } \
  && ok || no "delivery failure => INCOMPLETE, non-zero exit, honest FAILED line" "rc=$rc incomplete=$incomplete failed=$failed"

begin "il15-poam-row-names-real-vex-id" "a §2 POA&M (carried) row names a real VEX statement id, not the literal placeholder '(VEX)'"
o="$WORK/il15"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  poam="$(sed -n '/^## 2\./,/^## 3\./p' "$o/report.md" | grep 'carried (POA&M)')"
  realid="$(printf '%s' "$poam" | grep -c 'vex: .*stmt-')"; realid="${realid:-0}"
  placeholder="$(printf '%s' "$poam" | grep -c 'vex: (VEX)')"; placeholder="${placeholder:-0}"
  { [ "$realid" -ge 1 ] 2>/dev/null && eq "$placeholder" "0"; } \
    && ok || no "§2 POA&M row names a real vex statement id, no '(VEX)' placeholder" "real_id_rows=$realid placeholder_rows=$placeholder"; }

########################################################################
echo "=== Round 16 — App-token draft-PR delivery ==="

begin "r16-push-failure-is-incomplete" "a suppression PR push/PR failure makes the run AUDIT INCOMPLETE (non-zero exit), with the git/gh stderr in the report — never a false 'opened'"
o="$WORK/r16f"; shim="$WORK/r16f.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_SHIM_PR_FAIL=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1; rcf=$?
inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"
stderrline="$(grep -qi 'delivery FAILED' "$o/report.md" && echo yes || echo no)"
lied="$(grep -ci 'draft PR opened' "$o/report.md" 2>/dev/null)"; lied="${lied:-0}"
{ [ "$rcf" -ne 0 ] 2>/dev/null && eq "$inc" "yes" && eq "$stderrline" "yes" && eq "$lied" "0"; } \
  && ok || no "push failure -> INCOMPLETE + stderr, no false 'opened'" "exit=$rcf incomplete=$inc stderr_in_report=$stderrline false_opened=$lied"

begin "r16-nonstacked-draft-branches" "every delivery branch (suppression + each bump) is based on origin/main (non-stacked) and every delivered PR carries --draft"
o="$WORK/r16s"; shim="$WORK/r16s.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
branches="$(grep -c 'git checkout -B auditor/' "$shim" 2>/dev/null)"; branches="${branches:-0}"
offmain="$(grep -c 'git checkout -B auditor/.* origin/main' "$shim" 2>/dev/null)"; offmain="${offmain:-0}"
draft="$(grep -c 'gh pr create --draft' "$shim" 2>/dev/null)"; draft="${draft:-0}"
# at least the suppression PR + the one Go bump; every branch off origin/main; every PR a draft
{ [ "$branches" -ge 2 ] 2>/dev/null && eq "$offmain" "$branches" && eq "$draft" "$branches"; } \
  && ok || no "each branch off origin/main (non-stacked), each PR --draft" "branches=$branches off_main=$offmain draft=$draft"

begin "r16-pr-url-in-pr-list" "the delivered draft PR's URL is recorded in the 'PRs and issues this run' list"
o="$WORK/r16u"; shim="$WORK/r16u.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
url="$(sed -n '/^## PRs and issues this run/,/^## 0\./p' "$o/report.md" | grep -c '/pull/')"; url="${url:-0}"
{ [ "$url" -ge 1 ] 2>/dev/null; } && ok || no "PR URL present in the PR list" "pull_url_lines=$url"

begin "r16-no-vendor-or-model-name-in-delivery" "the delivery ACTUALLY happens (draft PR + branch in the ledger) AND no vendor/model name appears in its branch, commit, or PR text"
o="$WORK/r16n"; shim="$WORK/r16n.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
delivered="$(grep -cE 'gh pr create --draft --base main --head auditor/2026-09-24-' "$shim" 2>/dev/null)"; delivered="${delivered:-0}"
names="$(grep -iE 'git checkout -B auditor/|git commit -m|gh pr create' "$shim" | grep -ciE 'anthropic|claude|openai|codex|sonnet|opus|gpt|chatgpt')"; names="${names:-0}"
rptnames="$(sed -n '/## 6\./,/^$/p' "$o/report.md" | grep -ciE 'anthropic|claude|openai|codex|sonnet|opus|gpt|chatgpt')"; rptnames="${rptnames:-0}"
{ [ "$delivered" -ge 1 ] 2>/dev/null && eq "$names" "0" && eq "$rptnames" "0"; } \
  && ok || no "delivery occurred with no vendor/model name in branch/commit/PR or §6" "delivered=$delivered in_shim=$names in_section6=$rptnames"

########################################################################
echo "=== Round 16 corrections — issues token, test-image PR gating ==="

begin "r16-issues-use-job-token-pr-uses-app-token" "gh issue calls carry the JOB (issues) token; the signed API commit / gh pr create carry the App token (and no git commit or git push runs) — verified via fake gh/git on PATH"
o="$WORK/r16t"; rm -rf "$o"; fb="$WORK/r16t-bin"; rm -rf "$fb"; mkdir -p "$fb"; glog="$WORK/r16t-gh.log"; rm -f "$glog"
# the delivery commit is made THROUGH THE API (signed by GitHub): the fake gh answers the ref and createCommitOnBranch calls, and the fake git
# answers `status`/`rev-parse` and records every command so the case can prove no `git commit` / `git push` ran
gitlog="$WORK/r16t-git.log"; rm -f "$gitlog"
cat > "$fb/gh" <<EOF
#!/usr/bin/env bash
echo "GH_TOKEN=\${GH_TOKEN} ARGS=\$*" >> "$glog"
if [ "\$1" = "issue" ] && [ "\$2" = "list" ]; then echo "[]"; fi
if [ "\$1" = "pr" ] && [ "\$2" = "create" ]; then echo "https://github.com/OWNER/REPO/pull/1"; fi
case "\$2" in */git/ref/heads/*) echo '{"object":{"sha":"cccccccccccccccccccccccccccccccccccccccc"}}';; esac
if [ "\$1" = "api" ] && [ "\$2" = "graphql" ]; then cat >/dev/null; echo '{"data":{"createCommitOnBranch":{"commit":{"oid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","signature":{"isValid":true,"state":"VALID"}}}}}'; fi
exit 0
EOF
cat > "$fb/git" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$gitlog"
if [ "\$1" = "show" ]; then case "\$2" in *:*) echo "fatal: path '\${2#*:}' does not exist in 'origin/main'" >&2; exit 128;; esac; fi   # the delivery base holds no reviewed file yet (the first run)
if [ "\$1" = "status" ]; then printf ' M .vex/fosterstack-cache.openvex.json\\0'; fi
if [ "\$1" = "rev-parse" ]; then echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; fi
exit 0
EOF
chmod +x "$fb/gh" "$fb/git"
# the real-gh path merges suppressions into GITHUB_WORKSPACE (default: cwd = this repo) — point
# it at a throwaway copy so the suite never rewrites the real .vex/.snyk/.auditor (REQ-AUD-18).
ws="$WORK/r16t-ws"; rm -rf "$ws"; mkdir -p "$ws"; cp -R .vex "$ws/"
env PATH="$fb:$PATH" GITHUB_WORKSPACE="$ws" GITHUB_REPOSITORY=OWNER/REPO AUDITOR_ALLOW_REAL_GH=1 GH_TOKEN=APP_TOKEN_123 AUDITOR_ISSUES_TOKEN=JOB_TOKEN_456 \
  "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
issuejob="$(grep 'ARGS=issue' "$glog" | grep -c 'GH_TOKEN=JOB_TOKEN_456')"; issuejob="${issuejob:-0}"
issueapp="$(grep 'ARGS=issue' "$glog" | grep -c 'GH_TOKEN=APP_TOKEN_123')"; issueapp="${issueapp:-0}"
prapp="$(grep 'ARGS=pr create' "$glog" | grep -c 'GH_TOKEN=APP_TOKEN_123')"; prapp="${prapp:-0}"
commitapp="$(grep 'ARGS=api graphql' "$glog" | grep -c 'GH_TOKEN=APP_TOKEN_123')"; commitapp="${commitapp:-0}"
gitwrite="$(grep -cE '^(commit|push)( |$)' "$gitlog" 2>/dev/null)"; gitwrite="${gitwrite:-0}"
{ [ "$issuejob" -ge 1 ] 2>/dev/null && eq "$issueapp" "0" && [ "$prapp" -ge 1 ] 2>/dev/null && [ "$commitapp" -ge 1 ] 2>/dev/null && eq "$gitwrite" "0"; } \
  && ok || no "issue calls use job token, pr create and the signed API commit use app token, no git commit/push" "issue_job=$issuejob issue_app=$issueapp pr_app=$prapp commit_app=$commitapp git_commit_or_push=$gitwrite"

begin "r16-exactly-one-gh-token-key-in-driver-env" "the driver step's env block declares GH_TOKEN exactly once"
n="$(awk '/name: Run the auditor/{f=1} f&&/^        run:/{f=0} f&&/GH_TOKEN:/{c++} END{print c+0}' "$WF")"
eq "$n" "1" && ok || no "exactly one GH_TOKEN key in the driver env" "count=$n"

begin "r16-no-test-image-pr-in-production" "a test-image run without the proof flag opens NO PR (a VEX for an image we do not ship is not a proposal)"
o="$WORK/r16ti"; shim="$WORK/r16ti.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-testimage.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1; rc=$?
draftpr="$(grep -c 'gh pr create --draft' "$shim" 2>/dev/null)"; draftpr="${draftpr:-0}"
forced="$(grep -c '\*\*dry_run:\*\* yes' "$o/report.md" 2>/dev/null)"; forced="${forced:-0}"
noted="$(grep -qi 'Test image — nothing opened (not a shipped image)' "$o/report.md" && echo yes || echo no)"
{ eq "$draftpr" "0" && eq "$noted" "yes" && [ "$forced" -ge 1 ] 2>/dev/null && [ "$rc" -eq 0 ] 2>/dev/null; } \
  && ok || no "test image forces dry (AC9): no draft PR, noted, run not failed" "draft_prs=$draftpr forced_dry=$forced noted=$noted exit=$rc"

begin "r16-test-image-forces-dry-retires-proof-flag" "a test image ALWAYS forces dry (REQ-AUD-15 AC9): even with AUDITOR_PROOF_PR=1 it opens NO real PR — the proof-on-test-image path is retired"
o="$WORK/r16pf"; shim="$WORK/r16pf.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_PROOF_PR=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-testimage.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
realpr="$(grep -c 'gh pr create --draft' "$shim" 2>/dev/null)"; realpr="${realpr:-0}"
proofpr="$(grep -c 'proof — do not merge' "$shim" 2>/dev/null)"; proofpr="${proofpr:-0}"
forced="$(grep -c '\*\*dry_run:\*\* yes' "$o/report.md" 2>/dev/null)"; forced="${forced:-0}"
{ eq "$realpr" "0" && eq "$proofpr" "0" && [ "$forced" -ge 1 ] 2>/dev/null; } \
  && ok || no "test image dry, no real/proof PR" "real_pr=$realpr proof_pr=$proofpr forced_dry=$forced"

########################################################################
echo "=== outer-loop regressions (round 1) ==="

begin "ol1-log-fp-scoped-by-package-and-version" "a log FP for libfoo@1 closes ONLY @1 (all arches); libfoo@2 is NOT closed by the name match and is routed on its own"
o="$WORK/ol1"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-verscope.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  v1sub="$("$PY" -c 'import json,sys
d=json.load(open(sys.argv[1])); subs=[x["@id"] for s in d["statements"] for p in s["products"] for x in p.get("subcomponents",[])]
print("has1" if any("libfoo@1" in a for a in subs) else "no1", "has2" if any("libfoo@2" in a for a in subs) else "no2")' "$o/vex/CVE-2099-9001.openvex.json" 2>/dev/null)"
  secs="$("$PY" -c 'import json,sys
r=[x["section"] for x in json.load(open(sys.argv[1]))["findings"] if x["id"]=="CVE-2099-9001"]
print("sec5" if 5 in r else "-", "sec2" if 2 in r else "-")' "$o/classification.json")"
  { printf '%s' "$v1sub" | grep -q 'has1 no2' && printf '%s' "$secs" | grep -q 'sec5' && printf '%s' "$secs" | grep -q 'sec2'; } \
    && ok || no "not_affected scoped to @1 only; @2 routed separately" "subcomponents=$v1sub sections=$secs"; }

begin "ol4-refusal-after-fallback-escalates-to-owner-issue" "a finding refused through the fallback chain (real adjudicator) opens an owner-decision issue, not a silent §4"
o="$WORK/ol4"; shim="$WORK/ol4.shim"; rm -rf "$o"; rm -f "$shim"; fa="$WORK/ol4-refuse.py"
printf '#!/usr/bin/env python3\nimport json,sys\nfor line in sys.stdin:\n    sys.stdout.write(json.dumps({"refused":True})+"\\n")\n    sys.stdout.flush()\n' > "$fa"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --today 2026-09-24 --out "$o" >/dev/null 2>&1
sec4esc="$("$PY" -c 'import json,sys
r=[x for x in json.load(open(sys.argv[1]))["findings"] if x["section"]==4]
print("escalated" if r and all("escalat" in (x.get("action") or "") for x in r) else "no")' "$o/classification.json" 2>/dev/null)"
issued="$(grep -c 'issue create .*unassessed-after-fallback' "$shim" 2>/dev/null)"; issued="${issued:-0}"
{ eq "$sec4esc" "escalated" && [ "$issued" -ge 1 ] 2>/dev/null; } \
  && ok || no "§4 refusal escalates to an owner-decision issue" "sec4=$sec4esc issue=$issued"

begin "ol5-owner-issue-failure-is-incomplete" "a failed owner-decision issue create makes the run AUDIT INCOMPLETE (no false 'opened')"
o="$WORK/ol5"; shim="$WORK/ol5.shim"; rm -rf "$o"; rm -f "$shim"
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_SHIM_ISSUE_FAIL=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1; rc5=$?
inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && grep -qi 'issue(s) failed to open' "$o/report.md" && echo yes || echo no)"
{ eq "$inc" "yes" && [ "$rc5" -ne 0 ] 2>/dev/null; } && ok || no "issue failure -> INCOMPLETE + nonzero exit" "incomplete=$inc exit=$rc5"

begin "ol5b-accepted-items-records-owner-issue-ref" "accepted-items.json records the REAL owner_issue reference for an at-or-above item (the inventory is built AFTER the owner-decision emission), so the release gate never wrongly HOLDS a tag the owner authorized because owner_issue was captured as None"
o="$WORK/ol5b"; shim="$WORK/ol5b.shim"; rm -rf "$o"; rm -f "$shim"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
oiok="$("$PY" -c 'import json,sys
items=json.load(open(sys.argv[1]))["accepted_items"]
at=[i for i in items if i.get("threshold")=="at_or_above"]
print("OK" if at and all(i.get("owner_issue") for i in at) else "BAD:%r"%[(i["cve"],i.get("owner_issue")) for i in at])' "$o/.auditor/accepted-items.json" 2>/dev/null)"
{ eq "$oiok" "OK"; } && ok || no "accepted-items records the owner_issue ref for at-or-above items (not None)" "$oiok"

begin "ol7-delivery-carries-accepted-items" "the suppression delivery commits .auditor/accepted-items.json (the release gate's inventory)"
o="$WORK/ol7"; shim="$WORK/ol7.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
ai="$(grep -c 'createCommitOnBranch .*\.auditor/accepted-items.json' "$shim" 2>/dev/null)"; ai="${ai:-0}"
{ [ "$ai" -ge 1 ] 2>/dev/null; } && ok || no "delivery's signed API commit carries .auditor/accepted-items.json" "add_lines=$ai"

begin "ol9-narrative-model-name-withheld" "a narrative containing a vendor/model name is rejected; the report shows 'conclusion withheld', no name persisted"
o="$WORK/ol9"; rm -rf "$o"
na="$WORK/ol9-narr.py"
cat > "$na" <<'PYEOF'
import json,sys
def answer(req):
    if req.get("mode")=="narrative":
        return {"refused":False,"narrative":"Audit by Anthropic using claude-secret-x.","token_usage":10}
    return {"refused":False,"category":"real_fixable","token_usage":10}
if "--serve" in sys.argv:
    for line in sys.stdin:
        line=line.strip()
        if not line: continue
        sys.stdout.write(json.dumps(answer(json.loads(line)))+"\n"); sys.stdout.flush()
else:
    json.dump(answer(json.load(sys.stdin)),sys.stdout)
PYEOF
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$na" --out "$o" >/dev/null 2>&1
leaked="$(grep -ciE 'anthropic|claude-secret' "$o/report.md" 2>/dev/null)"; leaked="${leaked:-0}"
withheld="$(grep -qi 'conclusion withheld' "$o/report.md" && echo yes || echo no)"
{ eq "$leaked" "0" && eq "$withheld" "yes"; } && ok || no "model name withheld from the report" "leaked=$leaked withheld=$withheld"

########################################################################
echo "=== outer-loop regressions (round 2) ==="

begin "ol2-1-expired-supersede-acceptance-holds" "a later, expired ACCEPT supersedes an earlier longer one — the release gate HOLDS, not promote"
o="$WORK/ol21"; rm -rf "$o"
run "$PY" "$BIN/auditor-release-authz.py" --candidate "$F/release/cand-01.json" --issues "$F/release/iss-expired-super.json" --owner fosterstack-admin --today 2026-09-24 --out "$o/authz.json" && {
  d="$(pj "$o/authz.json" 'd.get("decision")')"
  eq "$d" "hold" && ok || no "hold on an expired superseding acceptance" "decision=$d"; }

begin "ol2-2-refusal-usage-charged-to-budget" "adjudicate charges token usage even for a refusal, so the budget advances and stops"
charged="$("$PY" -c '
import sys,importlib.util,tempfile,os
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
fa=tempfile.mktemp(suffix=".py"); open(fa,"w").write("import json,sys\nfor line in sys.stdin:\n    sys.stdout.write(json.dumps({\"refused\":True,\"token_usage\":100001})+\"\\n\")\n    sys.stdout.flush()\n")
st={"tokens":0}
R.adjudicate(fa,{"finding_id":"CVE-X"},st)
print(st["tokens"], st.get("calls"), st.get("stops"))' 2>/dev/null)"
{ [ "$charged" = "200002 2 1" ]; } && ok || no "refusal usage charged to the budget, and the third attempt is stopped by the budget" "tokens calls stops =$charged"

begin "ol2-3-high-outlier-excluded-quorum-holds" "one over-counting scanner is excluded as an outlier; the three agreeing scanners still form the quorum -> AUDIT COMPLETE, osv named excluded not did-not-run"
o="$WORK/ol23"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-outlier.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  complete="$(grep -qi 'AUDIT COMPLETE' "$o/report.md" && echo yes || echo no)"
  { eq "$complete" "yes"; } && ok || no "three agreeing scanners hold the quorum despite the outlier" "complete=$complete"; }

########################################################################
echo "=== outer-loop regressions (round 3) ==="

begin "ol3-1-kev-unavailable-fails-closed" "a Medium no-fix finding with an UNAVAILABLE KEV catalog is escalated to at_or_above (fail-closed), not silently below-threshold"
o="$WORK/ol31"; shim="$WORK/ol31.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-mediumnofix.json" --kev "$WORK/no-such-kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
esc="$(grep 'CVE-2099-9200' "$o/report.md" | grep -qi 'kev-unavailable' && echo at || echo no)"
issued="$(grep -c 'issue create .*CVE-2099-9200' "$shim" 2>/dev/null)"; issued="${issued:-0}"
{ eq "$esc" "at" && [ "$issued" -ge 1 ] 2>/dev/null; } \
  && ok || no "KEV-unavailable escalates the finding + owner issue" "escalated=$esc issue=$issued"

begin "ol3-2-issue-discovery-failure-incomplete" "a failed 'gh issue list' (discovery) does NOT create a duplicate; the run is AUDIT INCOMPLETE"
o="$WORK/ol32"; rm -rf "$o"; fb="$WORK/ol32-bin"; rm -rf "$fb"; mkdir -p "$fb"; glog="$WORK/ol32-gh.log"; rm -f "$glog"
cat > "$fb/gh" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$glog"
if [ "\$1" = "issue" ] && [ "\$2" = "list" ]; then echo "::error::HTTP 503" >&2; exit 1; fi
if [ "\$1" = "pr" ] && [ "\$2" = "create" ]; then echo "https://github.com/OWNER/REPO/pull/1"; fi
exit 0
EOF
cat > "$fb/git" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "show" ]; then case "$2" in *:*) echo "fatal: path '${2#*:}' does not exist in 'origin/main'" >&2; exit 128;; esac; fi   # the delivery base holds no reviewed file yet (the first run)
if [ "$1" = "rev-parse" ]; then echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; fi
exit 0
EOF
chmod +x "$fb/gh" "$fb/git"
env PATH="$fb:$PATH" AUDITOR_ALLOW_REAL_GH=1 GH_TOKEN=APP AUDITOR_ISSUES_TOKEN=JOB \
  "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1; rc=$?
inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"
created="$(grep -c 'issue create' "$glog" 2>/dev/null)"; created="${created:-0}"
{ eq "$inc" "yes" && eq "$created" "0" && [ "$rc" -ne 0 ] 2>/dev/null; } \
  && ok || no "failed discovery -> no duplicate create, INCOMPLETE" "incomplete=$inc creates=$created exit=$rc"

begin "ol3-3-gvc-module-from-sbom-modules" "parse_govulncheck derives the module from SBOM.modules, not roots[0] (a scanned subpackage)"
gv="$WORK/ol33-gvc.json"
cat > "$gv" <<'EOF'
{"config":{"scan_level":"symbol"}}
{"SBOM":{"go_version":"go1.27.0","modules":[{"path":"github.com/fosterstack/cache"},{"path":"stdlib","version":"v1.27.0"}],"roots":["github.com/fosterstack/cache/internal/blobstore"]}}
{"finding":{"osv":"GO-2099-9301","trace":[{"module":"golang.org/x/text","version":"v0.3.0"}]}}
EOF
modout="$("$PY" -c '
import sys;sys.path.insert(0,".github/agent/bin")
from auditorlib import parsers as P
g=P.parse_govulncheck(sys.argv[1]); print(g["module"])' "$gv" 2>/dev/null)"
{ eq "$modout" "github.com/fosterstack/cache"; } \
  && ok || no "module resolved from SBOM.modules" "module=$modout"

echo "=== outer-loop round 4 (Codex second-vendor) regressions ==="

begin "olr4-1-alias-union-find-one-group" "two grype matches whose ids are each other's related-vuln collapse into ONE finding group (union-find over aliases), not two"
ng="$("$PY" -c '
import sys,importlib.util
spec=importlib.util.spec_from_file_location("c",".github/agent/bin/auditor-classify.py")
C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
_m,groups=C.manifest_findings(__import__("os").environ["FXRUN"]+"/manifest-aliases.json")
print(len(groups))' 2>/dev/null)"
{ eq "$ng" "1"; } && ok || no "aliased matches form one group" "groups=$ng"

begin "olr7-2-mixed-alias-upstream-keeps-identity" "a record with explicit aliases AND a multi-CVE upstream keeps its own identity (its reachability id stays in its CVE group) while only the EXTRA upstream CVE becomes a separate distributed group"
m7res="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("c",".github/agent/bin/auditor-classify.py")
C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
_m,groups=C.manifest_findings(__import__("os").environ["FXRUN"]+"/manifest-mixed-alias-upstream.json")
g=groups.get("CVE-2099-9703",{}); has_go="GO-2099-9703" in (g.get("aliases") or set())
ok = set(groups)=={"CVE-2099-9703","CVE-2099-9704"} and has_go
print("OK" if ok else "BAD:%s go=%s"%(sorted(groups),has_go))' 2>/dev/null)"
{ eq "$m7res" "OK"; } && ok || no "mixed record keeps identity + splits only extra CVE" "$m7res"

begin "olr5-1-advisory-bundle-does-not-merge-distinct-cves" "a scanner that reports THREE distinct CVEs for one package (the converted advisory fixture) yields three separate groups, so one CVE's decision cannot dispose of another"
ng="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("c",".github/agent/bin/auditor-classify.py")
C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
_m,groups=C.manifest_findings(__import__("os").environ["FXRUN"]+"/manifest-advisory-bundle.json")
ok = len(groups)==3 and set(groups)=={"CVE-2099-7001","CVE-2099-7002","CVE-2099-7003"}
print("OK" if ok else "BAD:%s"%sorted(groups))' 2>/dev/null)"
{ eq "$ng" "OK"; } && ok || no "advisory bundle splits into distinct CVE groups" "$ng"

begin "olr4-2-vex-merge-preserves-existing" "delivering this run's suppressions MERGES into an existing reviewed .vex (keeps prior statements, bumps version), never overwrites, and writes no scanner ignore file"
mo="$WORK/olr4-merge"; rm -rf "$mo"; mkdir -p "$mo/ws/.vex" "$mo/supp"
"$PY" - "$mo" <<'PP'
import json,os,sys
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp")
old={"@context":"c","@id":"i","author":"FosterStack LLC","role":"vendor","version":6,"timestamp":"t",
 "statements":[{"@id":"s#a","vulnerability":{"name":"CVE-2024-1"},"status":"not_affected","products":[{"@id":"p"}]},
               {"@id":"s#b","vulnerability":{"name":"CVE-2024-2"},"status":"not_affected","products":[{"@id":"p"}]}]}
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
new={"@context":"c","@id":"i","author":"FosterStack LLC","role":"vendor","version":1,"timestamp":"t2",
 "statements":[{"@id":"s#c","vulnerability":{"name":"CVE-2099-9"},"status":"affected","products":[{"@id":"p"}]}]}
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
PP
mres="$("$PY" -c '
import sys,json,os,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py")
R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
m=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))
names=sorted(s["vulnerability"]["name"] for s in m["statements"])
ok = names==["CVE-2024-1","CVE-2024-2","CVE-2099-9"] and m["version"]==7 and not os.path.exists(os.path.join(ws,".snyk")) and not os.path.exists(os.path.join(ws,"osv-scanner.toml"))
print("OK" if ok else "BAD:%s v%s"%(names,m["version"]))' "$mo" 2>/dev/null)"
{ eq "$mres" "OK"; } && ok || no "merge preserves prior statements + bumps version" "$mres"

echo "=== outer-loop round 5 (Codex second-vendor) regressions ==="

begin "olr5-2-accepted-items-merged-with-vex" "a retained affected statement (survives the VEX merge, not re-assessed this run) keeps its accepted-items.json inventory entry, so release-authz is not left inconsistent"
io="$WORK/olr5-inv"; rm -rf "$io"; mkdir -p "$io/ws/.vex" "$io/ws/.auditor" "$io/supp" "$io/.auditor"
"$PY" - "$io" <<'PP'
import json,os,sys
from importlib.util import spec_from_file_location, module_from_spec
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp")
old=vex.doc("CVE-2099-9503","affected","2026-09-23T00:00:00Z",action="accepted below threshold"); old["version"]=6
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
json.dump({"accepted_items":[{"cve":"CVE-2099-9503","threshold":"below","expiry":"2026-10-23"}]},open(os.path.join(ws,".auditor","accepted-items.json"),"w"))
new=vex.doc("CVE-2099-9504","affected","2026-09-24T00:00:00Z",action="accepted below threshold")
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore:\n  CVE-2099-9504:\n    - '*':\n        reason: 'x'\n")
open(os.path.join(supp,"osv-scanner.toml"),"w").write('[[IgnoredVulns]]\nid = "CVE-2099-9504"\nreason = "x"\n')
json.dump({"accepted_items":[{"cve":"CVE-2099-9504","threshold":"below","expiry":"2026-10-24"}]},open(os.path.join(os.path.dirname(supp),".auditor","accepted-items.json"),"w"))
PP
ires="$("$PY" -c '
import json,os,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
inv=json.load(open(os.path.join(ws,".auditor","accepted-items.json")))
cves=sorted(i["cve"] for i in inv["accepted_items"])
print("OK" if cves==["CVE-2099-9503","CVE-2099-9504"] else "BAD:%s"%cves)' "$io" 2>/dev/null)"
{ eq "$ires" "OK"; } && ok || no "retained affected statement keeps its inventory entry" "$ires"

begin "olr5-3-vex-merge-keys-on-scope-not-just-id" "two statements sharing a CVE-derived @id but addressing DIFFERENT product/subcomponent scopes both survive the merge (a same-@id update never silently drops an unassessed scope)"
so="$WORK/olr5-scope"; rm -rf "$so"; mkdir -p "$so/ws/.vex" "$so/supp"
"$PY" - "$so" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex, policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp")
old=vex.doc("CVE-2099-9502","not_affected","2026-09-23T00:00:00Z",justification="vulnerable_code_not_present",subcomponents=["pkg:deb/debian/libdebug@1"])
old["version"]=6; old["statements"][0]["products"][0]["@id"]=policy.VEX_PRODUCT+"&variant=debug"
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
new=vex.doc("CVE-2099-9502","affected","2026-09-24T00:00:00Z",action="tracked",subcomponents=["pkg:deb/debian/libprod@1"])
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore: {}\n")
open(os.path.join(supp,"osv-scanner.toml"),"w").write("")
PP
sres="$("$PY" -c '
import json,os,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
m=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))
stmts=m["statements"]
debug=any("variant=debug" in p["@id"] for s in stmts for p in s["products"])
prod=any(s["status"]=="affected" for s in stmts)
print("OK" if len(stmts)==2 and debug and prod and m["version"]==7 else "BAD:n=%d debug=%s prod=%s"%(len(stmts),debug,prod))' "$so" 2>/dev/null)"
{ eq "$sres" "OK"; } && ok || no "disjoint-scope statements both survive the merge" "$sres"

echo "=== outer-loop round 6 (Codex second-vendor) regressions ==="

begin "olr6-1-inventory-merge-preserves-per-scope-obligation" "when one CVE has TWO accepted-items scopes (an at_or_above package needing owner + a below-threshold sibling), the merge keeps BOTH — it never collapses to one and drops the owner obligation (release-hold bypass)"
iso="$WORK/olr6-inv"; rm -rf "$iso"; mkdir -p "$iso/ws/.vex" "$iso/ws/.auditor" "$iso/supp" "$iso/.auditor"
"$PY" - "$iso" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp")
from auditorlib import policy
c="CVE-2099-9601"; pg="pkg:golang/example.org/libgo@v1"; po="pkg:deb/debian/libos@1"
# two package scopes = two scoped affected statements + two scoped inventory items
sg=vex.doc(c,"affected","2026-09-23T00:00:00Z",action="x",subcomponents=[pg])["statements"][0]
so=vex.doc(c,"affected","2026-09-23T00:00:00Z",action="x",subcomponents=[po])["statements"][0]
old={"@context":"c","@id":policy.VEX_BASE,"author":"FosterStack LLC","role":"vendor","version":6,"timestamp":"t","statements":[sg,so]}
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
json.dump({"accepted_items":[
  {"cve":c,"severity":"Critical","package":"libgo","threshold":"at_or_above","owner_issue":101,"vex_id":sg["@id"],"product":policy.VEX_PRODUCT,"scope_purls":[pg],"expiry":"2026-10-23"},
  {"cve":c,"severity":"Medium","package":"libos","threshold":"below","vex_id":so["@id"],"product":policy.VEX_PRODUCT,"scope_purls":[po],"expiry":"2026-10-23"}]},
  open(os.path.join(ws,".auditor","accepted-items.json"),"w"))
new=vex.doc(c,"affected","2026-09-24T00:00:00Z",action="x",subcomponents=[po])
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(supp,"osv-scanner.toml"),"w").write("")
json.dump({"accepted_items":[{"cve":c,"severity":"Medium","package":"libos","threshold":"below","vex_id":new["statements"][0]["@id"],"product":policy.VEX_PRODUCT,"scope_purls":[po],"expiry":"2026-10-24"}]},open(os.path.join(os.path.dirname(supp),".auditor","accepted-items.json"),"w"))
PP
ivres="$("$PY" -c '
import json,os,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
inv=json.load(open(os.path.join(ws,".auditor","accepted-items.json")))["accepted_items"]
scopes=sorted((i.get("package"),i.get("threshold")) for i in inv)
print("OK" if scopes==[("libgo","at_or_above"),("libos","below")] else "BAD:%s"%scopes)' "$iso" 2>/dev/null)"
{ eq "$ivres" "OK"; } && ok || no "inventory merge keeps both scopes of one CVE" "$ivres"

begin "olr6-3-scope-collision-gets-distinct-ids" "two retained statements that would share one CVE-derived @id under DIFFERENT scopes are made separately addressable (the run's statement keeps the base @id; the retained scope gets a distinct one), so no two statements share an @id"
sco="$WORK/olr6-scope"; rm -rf "$sco"; mkdir -p "$sco/ws/.vex" "$sco/supp"
"$PY" - "$sco" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex, policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp"); c="CVE-2099-9602"
old=vex.doc(c,"not_affected","2026-09-23T00:00:00Z",justification="vulnerable_code_not_present",subcomponents=["pkg:deb/debian/libdebug@1"])
old["version"]=6; old["statements"][0]["products"][0]["@id"]=policy.VEX_PRODUCT+"&variant=debug"
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
new=vex.doc(c,"affected","2026-09-24T00:00:00Z",action="tracked",subcomponents=["pkg:deb/debian/libprod@1"])
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(supp,"osv-scanner.toml"),"w").write("")
PP
scres="$("$PY" -c '
import json,os,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sys.path.insert(0,".github/agent/bin"); from auditorlib import policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
stmts=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))["statements"]
ids=[s["@id"] for s in stmts]
prods={s["products"][0]["@id"] for s in stmts}
# REQ-AUD-13 AC2: distinct scopes carry DISTINCT, unique @ids (generated from the scope)
uniq=len(ids)==len(set(ids)); two=len(stmts)==2; distinct_scopes=len(prods)==2
print("OK" if uniq and two and distinct_scopes else "BAD:%s prods=%s"%(ids,prods))' "$sco" 2>/dev/null)"
{ eq "$scres" "OK"; } && ok || no "colliding-scope statements get distinct @ids" "$scres"

echo "=== outer-loop round 7 (Codex second-vendor) regressions ==="

begin "olr7-1-inventory-keeps-distinct-owner-obligations" "two accepted-items scopes of one CVE with the SAME package AND threshold but DIFFERENT owner issues both survive the merge — a rejected obligation is never collapsed away (release-hold bypass)"
i7="$WORK/olr7-inv"; rm -rf "$i7"; mkdir -p "$i7/ws/.vex" "$i7/ws/.auditor" "$i7/supp" "$i7/.auditor"
"$PY" - "$i7" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp"); c="CVE-2099-9701"
old=vex.doc(c,"affected","2026-09-23T00:00:00Z",action="x"); old["version"]=6
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
json.dump({"accepted_items":[{"cve":c,"package":"libfoo","severity":"Critical","threshold":"at_or_above","owner_issue":101,"expiry":"2026-10-23"}]},open(os.path.join(ws,".auditor","accepted-items.json"),"w"))
new=vex.doc(c,"affected","2026-09-24T00:00:00Z",action="x")
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(supp,"osv-scanner.toml"),"w").write("")
json.dump({"accepted_items":[{"cve":c,"package":"libfoo","severity":"Critical","threshold":"at_or_above","owner_issue":102,"expiry":"2026-10-24"}]},open(os.path.join(os.path.dirname(supp),".auditor","accepted-items.json"),"w"))
PP
i7res="$("$PY" -c '
import json,os,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
inv=json.load(open(os.path.join(ws,".auditor","accepted-items.json")))["accepted_items"]
issues=sorted(i.get("owner_issue") for i in inv)
print("OK" if issues==[101,102] else "BAD:%s"%issues)' "$i7" 2>/dev/null)"
{ eq "$i7res" "OK"; } && ok || no "distinct owner obligations both preserved" "$i7res"

begin "olr7-3-reassessment-stable-no-accumulation" "reassessing a scope whose @id was suffixed on an earlier merge REPLACES it (stable @id, no accumulation, unique ids) across repeated merges"
r7="$WORK/olr7-reassess"; rm -rf "$r7"
rr="$("$PY" - "$r7" <<'PP' 2>/dev/null
import json,os,sys,shutil,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sys.path.insert(0,".github/agent/bin"); from auditorlib import vex, policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); os.makedirs(os.path.join(ws,".vex")); c="CVE-2099-9702"
def dbg(status):
    d=vex.doc(c,status,"2026-09-23T00:00:00Z",subcomponents=["pkg:deb/debian/libdebug@1"])
    d["statements"][0]["products"][0]["@id"]=policy.VEX_PRODUCT+"&variant=debug"; d["version"]=6; return d
def supp_of(doc):
    o=os.path.join(tmp,"o"); shutil.rmtree(o,ignore_errors=True); os.makedirs(os.path.join(o,"suppressions"))
    json.dump(doc,open(os.path.join(o,"suppressions","fosterstack-cache.openvex.json"),"w"))
    open(os.path.join(o,"suppressions",".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(o,"suppressions","osv-scanner.toml"),"w").write("")
    return os.path.join(o,"suppressions")
def prodsupp(status):
    o=os.path.join(tmp,"op"); shutil.rmtree(o,ignore_errors=True); os.makedirs(o)
    vex.write(o,c,status,"2026-09-24T00:00:00Z",action="x",subcomponents=["pkg:deb/debian/libprod@1"])
    supp,_=R._consolidate(o,"2026-09-24T00:00:00Z"); return supp
json.dump(dbg("not_affected"),open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
R._merge_suppressions(ws,prodsupp("affected"))
R._merge_suppressions(ws,supp_of(dbg("affected")))     # reassess debug
R._merge_suppressions(ws,prodsupp("affected"))         # repeat prod
s=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))["statements"]
ids=[x["@id"] for x in s]
print("OK" if len(s)==2 and len(ids)==len(set(ids)) else "BAD:%d %s"%(len(s),ids))
PP
)"
{ eq "$rr" "OK"; } && ok || no "reassessment stays stable (2 statements, unique ids)" "$rr"

echo "=== outer-loop round 8 (Codex second-vendor) regressions ==="

begin "olr8-2-go-unreachable-closure-is-scoped" "a Go imported-not-called closure writes not_affected SCOPED to the Go package's subcomponents, never product-wide (so it cannot suppress a sibling OS scope)"
g8="$WORK/olr8-go"; rm -rf "$g8"
gv="$g8/gvc.json"; mkdir -p "$g8"
printf '%s\n%s\n%s\n' '{"config":{"scan_level":"symbol"}}' '{"SBOM":{"roots":["example.org/lib"],"modules":[{"path":"example.org/lib","version":"v1.0.0"}]}}' '{"finding":{"osv":"GO-2099-8802","trace":[{"module":"example.org/lib","package":"example.org/lib/unused"}]}}' > "$gv"
sc8="$("$PY" -c '
import json,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=sys.argv[2]
env={"gvc":sys.argv[1],"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"2026-09-24T00:00:00Z","dry":True,"digest":"sha256:x","carried_expiry":{},"today":"2026-09-24"}
f={"scanner":"osv-scanner-gomod","finding_id":"GO-2099-8802","purl":"pkg:golang/example.org/lib@v1.0.0","aliases":["GO-2099-8802","CVE-2099-8802"],"package":"example.org/lib","fixed_version":None,"severity":"High","extra":{}}
row,_=R._dispose("CVE-2099-8802",[f],["CVE-2099-8802","GO-2099-8802"],env,[])
import glob
doc=json.load(open(glob.glob(out+"/vex/*.json")[0]))
subs=doc["statements"][0]["products"][0].get("subcomponents")
print("OK" if row["section"]==5 and subs and subs[0]["@id"]=="pkg:golang/example.org/lib@v1.0.0" else "BAD:%s subs=%s"%(row["section"],subs))' "$gv" "$g8/out" 2>/dev/null)"
{ eq "$sc8" "OK"; } && ok || no "Go closure scoped to its subcomponents" "$sc8"

begin "olr8-5-inventory-same-scope-reassessment-replaces" "a same-scope (same vex_id) reassessment REPLACES the prior obligation (changed owner_issue) instead of accumulating a stale rejected one"
i8="$WORK/olr8-inv"; rm -rf "$i8"; mkdir -p "$i8/ws/.vex" "$i8/ws/.auditor" "$i8/supp" "$i8/.auditor"
"$PY" - "$i8" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp"); c="CVE-2099-9803"
old=vex.doc(c,"affected","2026-09-23T00:00:00Z",action="x",subcomponents=["pkg:deb/debian/libfoo@1"]); old["version"]=6
vid=old["statements"][0]["@id"]
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
json.dump({"accepted_items":[{"cve":c,"package":"libfoo","threshold":"at_or_above","owner_issue":101,"vex_id":vid,"expiry":"2026-10-23"}]},open(os.path.join(ws,".auditor","accepted-items.json"),"w"))
new=vex.doc(c,"affected","2026-09-24T00:00:00Z",action="x",subcomponents=["pkg:deb/debian/libfoo@1"])
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(supp,"osv-scanner.toml"),"w").write("")
json.dump({"accepted_items":[{"cve":c,"package":"libfoo","threshold":"at_or_above","owner_issue":102,"vex_id":vid,"expiry":"2026-10-24"}]},open(os.path.join(os.path.dirname(supp),".auditor","accepted-items.json"),"w"))
PP
iv8="$("$PY" -c '
import json,os,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
inv=json.load(open(os.path.join(ws,".auditor","accepted-items.json")))["accepted_items"]
print("OK" if len(inv)==1 and inv[0]["owner_issue"]==102 else "BAD:%s"%[i.get("owner_issue") for i in inv])' "$i8" 2>/dev/null)"
{ eq "$iv8" "OK"; } && ok || no "same-scope reassessment replaces the obligation" "$iv8"

begin "olr8-6-foreign-id-preserved-and-citation-resolves" "the merge does NOT strip a foreign statement id's legitimate '~' suffix"
c8="$WORK/olr8-cite"; rm -rf "$c8"; mkdir -p "$c8/ws/.vex" "$c8/supp"
"$PY" - "$c8" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex, policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp")
old=vex.doc("CVE-2099-9805","not_affected","2026-09-23T00:00:00Z",justification="vulnerable_code_not_present")
old["statements"][0]["@id"]="https://example.org/vex#review~deadbeef"; old["version"]=6
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
new=vex.doc("CVE-2099-9806","not_affected","2026-09-24T00:00:00Z",justification="vulnerable_code_not_present")
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
PP
ci8="$("$PY" -c '
import json,os,sys,re,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
doc=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))
ids={s["@id"] for s in doc["statements"]}
foreign_kept="https://example.org/vex#review~deadbeef" in ids
print("OK" if foreign_kept and len(ids)==2 else "BAD kept=%s ids=%s"%(foreign_kept,sorted(ids)))' "$c8" 2>/dev/null)"
{ eq "$ci8" "OK"; } && ok || no "foreign id preserved + citations resolve to merged ids" "$ci8"

begin "olr8-7-configured-model-name-filtered" "the narrative filter rejects the CONFIGURED model identifier (AUDITOR_MODEL_*), not only the fixed vendor vocabulary"
nm8="$(AUDITOR_MODEL_PRIMARY=review-engine-2099 "$PY" -c '
import sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sec={n:[] for n in range(1,8)}
bad = R._narrative_ok("Audit prepared using review-engine-2099.", sec)
good = R._narrative_ok("Audit prepared deterministically.", sec)
print("OK" if (not bad) and good else "BAD bad=%s good=%s"%(bad,good))' 2>/dev/null)"
{ eq "$nm8" "OK"; } && ok || no "configured model identifier is filtered from the narrative" "$nm8"

begin "olr8-4-expired-carried-acceptance-reopens-and-removes-ignore" "a carried acceptance whose time box has passed reopens the finding to §3 on the next run and REMOVES its ignore/VEX (AC5c through the daily entrypoint), never silently renewing it"
ex8="$WORK/olr8-exp"; rm -rf "$ex8"; mkdir -p "$ex8/ws/.vex" "$ex8/ws/.auditor"
"$PY" - "$ex8" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex, policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); c="CVE-2099-9200"
# a carried, already-EXPIRED (2026-08-23) affected acceptance sits in the checkout, scoped to
# the finding's own package purl (the scope the next run will re-derive)
purl="pkg:deb/debian/libmed@1?arch=amd64&distro=debian-12.0"
old=vex.doc(c,"affected","2026-08-24T00:00:00Z",action="tracked",subcomponents=[purl])
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
json.dump({"accepted_items":[{"cve":c,"severity":"Medium","package":"libmed","threshold":"below","owner_issue":None,"vex_id":old["statements"][0]["@id"],"expiry":"2026-08-23"}]},open(os.path.join(ws,".auditor","accepted-items.json"),"w"))
PP
ex8r="$("$PY" -c '
import json,os,sys,io,contextlib,subprocess,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sys.path.insert(0,".github/agent/bin")
from unittest.mock import patch
tmp=sys.argv[1]; mp=sys.argv[2]; ws=os.path.join(tmp,"ws")
def fake(cmd,*a,**kw):
    if cmd[:2]==["git","show"]: return subprocess.CompletedProcess(cmd,128,"","fatal: path 'x' does not exist in 'origin/main'")   # the delivery base holds no reviewed file yet (the first run)
    if cmd[:3]==["git","rev-parse","origin/main"]: return subprocess.CompletedProcess(cmd,0,"a"*40+"\n","")
    if cmd[0]=="git": return subprocess.CompletedProcess(cmd,0,"","")
    if cmd[:3]==["gh","pr","list"]: return subprocess.CompletedProcess(cmd,0,"https://x.invalid/pull/1","")
    if cmd[:3]==["gh","issue","list"]: return subprocess.CompletedProcess(cmd,0,"[]","")
    if cmd[:2]==["gh","issue"]: return subprocess.CompletedProcess(cmd,0,"","")
    if cmd[:2]==["gh","label"]: return subprocess.CompletedProcess(cmd,0,"","")   # the delivery now ensures its labels (auditor-labels-test.sh)
    if cmd[0]=="gh": raise AssertionError(cmd)
    return R.subprocess.run.__wrapped__(cmd,*a,**kw) if hasattr(R.subprocess.run,"__wrapped__") else __import__("subprocess").run(cmd,*a,**kw)
import subprocess as _sp
def fake2(cmd,*a,**kw):
    if cmd[:2]==["git","show"]: return _sp.CompletedProcess(cmd,128,"","fatal: path 'x' does not exist in 'origin/main'")   # the delivery base holds no reviewed file yet (the first run)
    if cmd[:3]==["git","rev-parse","origin/main"]: return _sp.CompletedProcess(cmd,0,"a"*40+"\n","")
    if cmd and cmd[0]=="git": return _sp.CompletedProcess(cmd,0,"","")
    if cmd[:3]==["gh","pr","list"]: return _sp.CompletedProcess(cmd,0,"https://x.invalid/pull/1","")
    if cmd[:3]==["gh","issue","list"]: return _sp.CompletedProcess(cmd,0,"[]","")
    if cmd[:2]==["gh","issue"]: return _sp.CompletedProcess(cmd,0,"","")
    if cmd[:2]==["gh","label"]: return _sp.CompletedProcess(cmd,0,"","")   # the delivery now ensures its labels (auditor-labels-test.sh)
    if cmd and cmd[0]=="gh": raise AssertionError(cmd)
    return _sp.run(cmd,*a,**kw)
with patch.dict(os.environ,{"AUDITOR_ALLOW_REAL_GH":"1","GITHUB_WORKSPACE":ws}),patch.object(R.subprocess,"run",fake2),patch.object(R.cli,"ask_model",return_value={"category":"risk_acceptance","token_usage":0}),contextlib.redirect_stdout(io.StringIO()):
    R.run(mp,False,os.path.join(tmp,"out"),"2026-09-24",adjudicator="offline-probe")
cls=json.load(open(os.path.join(tmp,"out","classification.json")))["findings"]
sec=cls[0]["section"] if cls else None
inv=json.load(open(os.path.join(ws,".auditor","accepted-items.json")))["accepted_items"]
stmts=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))["statements"]
print("OK" if sec==3 and inv==[] and stmts==[] else "BAD sec=%s inv=%s stmts=%d"%(sec,len(inv),len(stmts)))' "$ex8" "$FX/run/manifest-mediumnofix.json" 2>/dev/null)"
{ eq "$ex8r" "OK"; } && ok || no "expired acceptance reopens to §3 and removes the ignore/VEX" "$ex8r"

echo "=== REQ-AUD-13 scope identity and evidence boundaries ==="

begin "req13-ac1-scope-key-definition" "a disposition's scope key is (product @id, sorted subcomponent purls); equal members => same scope (order-insensitive), any difference => distinct"
a1="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
s1={"products":[{"@id":"P","subcomponents":[{"@id":"pkg:a@1"},{"@id":"pkg:b@1"}]}]}
s2={"products":[{"@id":"P","subcomponents":[{"@id":"pkg:b@1"},{"@id":"pkg:a@1"}]}]}
s3={"products":[{"@id":"P","subcomponents":[{"@id":"pkg:a@1"}]}]}
s4={"products":[{"@id":"Q","subcomponents":[{"@id":"pkg:a@1"},{"@id":"pkg:b@1"}]}]}
ok=R._scope_key(s1)==R._scope_key(s2) and R._scope_key(s1)!=R._scope_key(s3) and R._scope_key(s1)!=R._scope_key(s4)
print("OK" if ok else "BAD")' 2>/dev/null)"
{ eq "$a1" "OK"; } && ok || no "scope key = (product, sorted subcomponents)" "$a1"

begin "req13-ac2-stable-unique-ids" "statement @id is a deterministic function of (vulnerability, scope): stable across calls, distinct scopes never collide, default scope keeps the bare stmt id"
a2="$("$PY" -c '
import sys;sys.path.insert(0,".github/agent/bin")
from auditorlib import policy
base=policy.scope_id("CVE-2099-0001")
same=policy.scope_id("CVE-2099-0001")
sc1=policy.scope_id("CVE-2099-0001",policy.VEX_PRODUCT,["pkg:deb/debian/x@1"])
sc2=policy.scope_id("CVE-2099-0001",policy.VEX_PRODUCT,["pkg:deb/debian/x@2"])
scv=policy.scope_id("CVE-2099-0001",policy.VEX_PRODUCT+"&variant=debug",["pkg:deb/debian/x@1"])
ok = base==same and base==policy.VEX_BASE+"#stmt-cve-2099-0001" and len({base,sc1,sc2,scv})==4
print("OK" if ok else "BAD:%s"%[base,sc1,sc2,scv])' 2>/dev/null)"
{ eq "$a2" "OK"; } && ok || no "scope_id deterministic + unique per scope" "$a2"

begin "req13-ac3-one-key-threaded" "two distinct scopes whose statements shared a pre-merge CVE-derived id keep DISTINCT inventory obligations after the merge; a rejected scope is never overwritten (round-9 #1)"
t3="$WORK/req13-3"; rm -rf "$t3"; mkdir -p "$t3/ws/.vex" "$t3/ws/.auditor" "$t3/supp" "$t3/.auditor"
"$PY" - "$t3" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex, policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp"); c="CVE-2099-0003"
# retained Critical debug scope (rejected owner issue 101)
old=vex.doc(c,"affected","2026-09-23T00:00:00Z",action="Critical debug carry",subcomponents=["pkg:deb/debian/libfoo@1"])
old["statements"][0]["products"][0]["@id"]=policy.VEX_PRODUCT+"&variant=debug"; old["version"]=6
vidD=old["statements"][0]["@id"]
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
json.dump({"accepted_items":[{"cve":c,"package":"libfoo","threshold":"at_or_above","owner_issue":101,"vex_id":vidD,"expiry":"2026-10-23"}]},open(os.path.join(ws,".auditor","accepted-items.json"),"w"))
# new below-threshold production scope (different version)
new=vex.doc(c,"affected","2026-09-24T00:00:00Z",action="prod carry",subcomponents=["pkg:deb/debian/libfoo@2"])
vidP=new["statements"][0]["@id"]
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(supp,"osv-scanner.toml"),"w").write("")
json.dump({"accepted_items":[{"cve":c,"package":"libfoo","threshold":"below","owner_issue":None,"vex_id":vidP,"expiry":"2026-10-24"}]},open(os.path.join(os.path.dirname(supp),".auditor","accepted-items.json"),"w"))
PP
r3="$("$PY" -c '
import json,os,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
stmts=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))["statements"]
inv=json.load(open(os.path.join(ws,".auditor","accepted-items.json")))["accepted_items"]
ids=[s["@id"] for s in stmts]
issues=sorted(str(i.get("owner_issue")) for i in inv)
# both scopes retained, distinct ids, both obligations kept incl the rejected 101, every inv vex_id resolves
ok = len(stmts)==2 and len(set(ids))==2 and issues==["101","None"] and all(i["vex_id"] in ids for i in inv)
print("OK" if ok else "BAD ids=%s issues=%s resolve=%s"%(ids,issues,[i["vex_id"] in ids for i in inv]))' "$t3" 2>/dev/null)"
{ eq "$r3" "OK"; } && ok || no "distinct scopes keep distinct obligations; pointers resolve to final ids" "$r3"

begin "req13-ac4-lineage-not-evidence" "a lineage-only bundle record never supplies fix availability/package/version/severity for another CVE's group (round-9 #3), but still counts as a lineage vote"
a4="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
real={"scanner":"grype","finding_id":"CVE-2099-0004","purl":"pkg:deb/debian/other@8.0.0","aliases":["CVE-2099-0004"],"package":"other","fixed_version":None,"severity":"Critical","extra":{}}
lineage={"scanner":"osv-scanner","finding_id":"GO-2099-0004","purl":"pkg:golang/example.org/lib@v1.0.0","aliases":["CVE-2099-0004"],"package":"example.org/lib","fixed_version":"1.0.1","severity":"Low","extra":{},"_lineage_only":True}
gf=R._group_facts("CVE-2099-0004",{"findings":[real,lineage],"aliases":["CVE-2099-0004"]})
# fix/package/installed/severity come from the REAL finding only; lineage still contributes a lineage vote
ok = gf["fixed"] is None and gf["package"]=="other" and gf["severity"]=="Critical" and len(gf["lineages"])>=1
print("OK" if ok else "BAD:%s"%gf)' 2>/dev/null)"
{ eq "$a4" "OK"; } && ok || no "lineage-only excluded from fix/package/severity evidence" "$a4"

begin "req13-ac5-go-closure-scoped-to-trace" "a Go imported-not-called closure is scoped to the trace's module+version only; a group whose only records are lineage yields NO closure (never product-wide)"
t5="$WORK/req13-5"; rm -rf "$t5"; mkdir -p "$t5"
gv5="$t5/gvc.json"
printf '%s\n%s\n%s\n' '{"config":{"scan_level":"symbol"}}' '{"SBOM":{"roots":["example.org/lib"],"modules":[{"path":"example.org/lib","version":"v1.0.0"}]}}' '{"finding":{"osv":"GO-2099-0005","trace":[{"module":"example.org/lib","version":"v1.0.0","package":"example.org/lib/x"}]}}' > "$gv5"
a5="$("$PY" -c '
import json,sys,glob,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
gv,out=sys.argv[1],sys.argv[2]
env={"gvc":gv,"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"2026-09-24T00:00:00Z","dry":True,"digest":"sha256:x","carried_expiry":{},"today":"2026-09-24"}
# two Go findings share the CVE: v1.0.0 (has the trace) and v2.0.0 (no trace)
f1={"scanner":"osv-scanner-gomod","finding_id":"GO-2099-0005","purl":"pkg:golang/example.org/lib@v1.0.0","aliases":["GO-2099-0005","CVE-2099-0005"],"package":"example.org/lib","fixed_version":None,"severity":"High","extra":{}}
f2={"scanner":"osv-scanner-gomod","finding_id":"GO-2099-0005","purl":"pkg:golang/example.org/lib@v2.0.0","aliases":["GO-2099-0005","CVE-2099-0005"],"package":"example.org/lib","fixed_version":None,"severity":"High","extra":{}}
row,_=R._dispose("CVE-2099-0005",[f1,f2],["CVE-2099-0005","GO-2099-0005"],env,[])
doc=json.load(open(glob.glob(out+"/vex/*.json")[0])) if glob.glob(out+"/vex/*.json") else {"statements":[]}
subs=[sc["@id"] for s in doc["statements"] if s["status"]=="not_affected" for sc in s["products"][0].get("subcomponents",[])]
scoped = row["section"]==5 and subs==["pkg:golang/example.org/lib@v1.0.0"]
# lineage-only-only group: no closure at all
lo={"scanner":"osv-scanner","finding_id":"DSA-1","purl":"pkg:deb/debian/lib@1","aliases":["CVE-2099-0005"],"package":"lib","fixed_version":None,"severity":"High","extra":{},"_lineage_only":True}
row2,_=R._dispose("CVE-2099-0005",[lo],["CVE-2099-0005"],dict(env,out=out+"2"),[])
import os
no_closure = row2["section"]!=5
print("OK" if scoped and no_closure else "BAD scoped_subs=%s sec2=%s"%(subs,row2["section"]))' "$gv5" "$t5/out" 2>/dev/null | tail -1)"
{ eq "$a5" "OK"; } && ok || no "Go closure scoped to trace module+version; lineage-only => no closure" "$a5"

begin "req13-ac6-expiry-original-date-per-scope" "an unchanged-scope run preserves the ORIGINAL time box (never renews it), and an expired scope removes ONLY its own statement/inventory, retaining sibling and permanent statements (round-9 #4/#5)"
a6="$("$PY" -c '
import json,os,sys,io,contextlib,subprocess,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex, policy
from unittest.mock import patch
import tempfile
tmp=tempfile.mkdtemp(); ws=os.path.join(tmp,"ws"); os.makedirs(os.path.join(ws,".vex"))
c="CVE-2099-9200"   # the finding in manifest-mediumnofix
mp=os.environ["FXRUN"]+"/manifest-mediumnofix.json"
def fake(cmd,*a,**kw):
    if cmd[:2]==["git","show"]:           # origin/main is the workspace here: each run merge writes into it and the next run delivers against what it holds
        _p=os.path.join(ws,cmd[2].split(":",1)[1])
        if os.path.isfile(_p): return subprocess.CompletedProcess(cmd,0,open(_p,"rb").read(),b"")
        return subprocess.CompletedProcess(cmd,128,"","fatal: path 'x' does not exist in 'origin/main'")   # the delivery base holds no reviewed file yet (the first run)
    if cmd[:3]==["git","rev-parse","origin/main"]: return subprocess.CompletedProcess(cmd,0,"a"*40+"\n","")
    if cmd and cmd[0]=="git": return subprocess.CompletedProcess(cmd,0,"","")
    if cmd[:3]==["gh","pr","list"]: return subprocess.CompletedProcess(cmd,0,"https://x.invalid/pull/1","")
    if cmd[:3]==["gh","issue","list"]: return subprocess.CompletedProcess(cmd,0,"[]","")
    if cmd[:2]==["gh","issue"]: return subprocess.CompletedProcess(cmd,0,"","")
    if cmd[:2]==["gh","label"]: return subprocess.CompletedProcess(cmd,0,"","")   # the delivery now ensures its labels (auditor-labels-test.sh)
    if cmd and cmd[0]=="gh": raise AssertionError(cmd)
    return subprocess.run(cmd,*a,**kw)
def go(day):
    with patch.dict(os.environ,{"AUDITOR_ALLOW_REAL_GH":"1","GITHUB_WORKSPACE":ws}),patch.object(R.subprocess,"run",fake),patch.object(R.cli,"ask_model",return_value={"category":"risk_acceptance","token_usage":0}),contextlib.redirect_stdout(io.StringIO()):
        R.run(mp,False,os.path.join(tmp,"o"+day),day,adjudicator="offline-probe")
    return json.load(open(os.path.join(ws,".auditor","accepted-items.json")))["accepted_items"]
i1=go("2026-08-24")                       # first: original expiry
exp1=i1[0]["expiry"] if i1 else None
i2=go("2026-09-10")                       # ordinary intervening run BEFORE expiry: must NOT renew
exp2=i2[0]["expiry"] if i2 else None
no_renew = exp1 is not None and exp1==exp2
# per-scope removal: add a sibling live scope + a permanent statement, expire ONLY the first scope
sib=vex.doc(c,"affected","2026-09-10T00:00:00Z",action="sibling live",subcomponents=["pkg:deb/debian/other@9"])
sib["statements"][0]["products"][0]["@id"]=policy.VEX_PRODUCT+"&variant=debug"
cur=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))
cur["statements"].append(sib["statements"][0])
perm=vex.doc("CVE-2099-7777","not_affected","2026-01-01T00:00:00Z",justification="vulnerable_code_not_present")
cur["statements"].append(perm["statements"][0]); json.dump(cur,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
i3=go("2099-01-01")                        # far future: the original scope expiry has passed
final=[s["vulnerability"]["name"] for s in json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))["statements"]]
kept_perm = "CVE-2099-7777" in final
print("OK" if no_renew and kept_perm else "BAD exp1=%s exp2=%s final=%s"%(exp1,exp2,final))' 2>/dev/null)"
{ eq "$a6" "OK"; } && ok || no "expiry original-date, no daily renewal, per-scope removal" "$a6"

echo "=== REQ-AUD-13 refactor boundary regressions (refactor-loop round 1) ==="

begin "refr1-1-scope-key-normalizes-purl-representation" "the scope key is representation-invariant: subcomponents by @id and by identifiers.purl for the same purl are the SAME scope; distinct purls are distinct"
r1="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
byid={"products":[{"@id":"P","subcomponents":[{"@id":"pkg:deb/debian/lib@1"}]}]}
bypurl={"products":[{"@id":"P","subcomponents":[{"identifiers":{"purl":"pkg:deb/debian/lib@1"}}]}]}
dup={"products":[{"@id":"P","subcomponents":[{"@id":"pkg:deb/debian/lib@1"},{"identifiers":{"purl":"pkg:deb/debian/lib@1"}}]}]}
diff={"products":[{"@id":"P","subcomponents":[{"identifiers":{"purl":"pkg:deb/debian/lib@2"}}]}]}
ok = R._scope_key(byid)==R._scope_key(bypurl)==R._scope_key(dup) and R._scope_key(byid)!=R._scope_key(diff)
print("OK" if ok else "BAD")' 2>/dev/null)"
{ eq "$r1" "OK"; } && ok || no "scope key normalizes @id / identifiers.purl and dedupes" "$r1"

begin "refr1-2-inventory-keys-on-full-scope-not-hash" "two distinct scopes that share a truncated statement-id hash keep DISTINCT inventory obligations (the rejected scope holds release); inventory keys on the full scope, not the hash"
t2="$WORK/refr1-2"; rm -rf "$t2"; mkdir -p "$t2/ws/.vex" "$t2/ws/.auditor" "$t2/supp" "$t2/.auditor"
"$PY" - "$t2" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex, policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp"); c="CVE-2099-1301"
# two distinct package scopes, each represented via identifiers.purl (exercising normalization)
a=vex.doc(c,"affected","2026-09-23T00:00:00Z",action="x",subcomponents=["pkg:deb/debian/lib@1"])["statements"][0]
b=vex.doc(c,"affected","2026-09-24T00:00:00Z",action="x",subcomponents=["pkg:deb/debian/lib@2"])["statements"][0]
old={"@context":"c","@id":policy.VEX_BASE,"author":"FosterStack LLC","role":"vendor","version":6,"timestamp":"t","statements":[a]}
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
json.dump({"accepted_items":[{"cve":c,"package":"lib","threshold":"at_or_above","owner_issue":101,"vex_id":a["@id"],"product":policy.VEX_PRODUCT,"scope_purls":["pkg:deb/debian/lib@1"],"expiry":"2026-10-23"}]},open(os.path.join(ws,".auditor","accepted-items.json"),"w"))
json.dump({"@context":"c","@id":policy.VEX_BASE,"author":"x","role":"vendor","version":1,"timestamp":"t","statements":[b]},open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(supp,"osv-scanner.toml"),"w").write("")
json.dump({"accepted_items":[{"cve":c,"package":"lib","threshold":"below","owner_issue":None,"vex_id":b["@id"],"product":policy.VEX_PRODUCT,"scope_purls":["pkg:deb/debian/lib@2"],"expiry":"2026-10-24"}]},open(os.path.join(os.path.dirname(supp),".auditor","accepted-items.json"),"w"))
PP
r2="$("$PY" -c '
import json,os,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
stmts=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))["statements"]
inv=json.load(open(os.path.join(ws,".auditor","accepted-items.json")))["accepted_items"]
issues=sorted(str(i.get("owner_issue")) for i in inv)
print("OK" if len(stmts)==2 and issues==["101","None"] else "BAD stmts=%d issues=%s"%(len(stmts),issues))' "$t2" 2>/dev/null)"
{ eq "$r2" "OK"; } && ok || no "distinct scopes keep distinct obligations under a shared hash" "$r2"

begin "refr1-3-partial-go-routes-uncovered-version" "a Go closure supported by the trace at v1 only closes v1 and ROUTES v2 (unsupported) on its own; it never drops the uncovered version or closes it product-wide"
t3="$WORK/refr1-3"; rm -rf "$t3"; mkdir -p "$t3"
gv3="$t3/gvc.json"
printf '%s\n%s\n%s\n' '{"config":{"scan_level":"symbol"}}' '{"SBOM":{"roots":["example.org/lib"],"modules":[{"path":"example.org/lib","version":"v1.0.0"}]}}' '{"finding":{"osv":"GO-2099-1302","trace":[{"module":"example.org/lib","version":"v1.0.0","package":"example.org/lib/x"}]}}' > "$gv3"
r3="$("$PY" -c '
import sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
gv,out=sys.argv[1],sys.argv[2]
env={"gvc":gv,"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"2026-09-24T00:00:00Z","dry":True,"digest":"sha256:x","carried_expiry":{},"today":"2026-09-24"}
def gm(v,sc): return {"scanner":sc,"finding_id":"GO-2099-1302","purl":"pkg:golang/example.org/lib@"+v,"aliases":["GO-2099-1302","CVE-2099-1302"],"package":"example.org/lib","fixed_version":None,"severity":"Critical","extra":{}}
# two scanner lineages per version so a no-fix version routes to POA&M without a model call
rows,_=R._dispose_split("CVE-2099-1302",[gm("v1.0.0","grype"),gm("v1.0.0","osv-scanner-gomod"),gm("v2.0.0","grype"),gm("v2.0.0","osv-scanner-gomod")],["CVE-2099-1302","GO-2099-1302"],env,[])
secs=sorted(r["section"] for r in rows)
print("OK" if secs==[2,5] else "BAD:%s"%[ (r["section"],r["disposition"]) for r in rows])' "$gv3" "$t3/out" 2>/dev/null | tail -1)"
{ eq "$r3" "OK"; } && ok || no "uncovered Go version routed (5 closed + 2 carried)" "$r3"

begin "refr1-7-reopen-on-the-deadline-day" "a carried acceptance whose time box is TODAY is expired and reopens this run (the emitted expires timestamp is start-of-day), not a day later"
r7="$("$PY" -c '
import sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sys.path.insert(0,".github/agent/bin"); from auditorlib import policy
import os,shutil,tempfile
purl="pkg:deb/debian/lib@1"; sc=((policy.VEX_PRODUCT,),(purl,))
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":os.path.join(tempfile.mkdtemp(),"out"),"ts":"2026-09-23T00:00:00Z","dry":True,"digest":"sha256:x",
     "carried_expiry":{("CVE-2099-1303",sc):"2026-09-23"},"today":"2026-09-23"}
f={"scanner":"grype","finding_id":"CVE-2099-1303","purl":purl,"aliases":["CVE-2099-1303"],"package":"lib","fixed_version":None,"severity":"Medium","extra":{}}
row,_=R._dispose("CVE-2099-1303",[f],["CVE-2099-1303"],env,[])
print("OK" if row["section"]==3 and row.get("reopened_expired")=="2026-09-23" else "BAD:%s"%(row["section"]))' 2>/dev/null)"
{ eq "$r7" "OK"; } && ok || no "deadline-day acceptance reopens (<=today)" "$r7"

echo "=== REQ-AUD-13 refactor boundary regressions (round 2) ==="

begin "refr2-1-expiry-is-per-vulnerability-and-scope" "expiring one CVE on a package scope does NOT remove a DIFFERENT CVE's live/permanent statement on the same scope, nor its inventory obligation"
t21="$WORK/refr2-1"; rm -rf "$t21"; mkdir -p "$t21/ws/.vex" "$t21/ws/.auditor" "$t21/supp" "$t21/.auditor"
"$PY" - "$t21" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex, policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp"); purl="pkg:deb/debian/lib@1"
a="CVE-2099-2001"; b="CVE-2099-2002"     # A expired; B valid — same package scope
sa=vex.doc(a,"affected","2026-08-24T00:00:00Z",action="x",subcomponents=[purl])["statements"][0]
sb=vex.doc(b,"affected","2026-08-24T00:00:00Z",action="x",subcomponents=[purl])["statements"][0]
old={"@context":"c","@id":policy.VEX_BASE,"author":"FosterStack LLC","role":"vendor","version":6,"timestamp":"t","statements":[sa,sb]}
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
json.dump({"accepted_items":[
  {"cve":a,"package":"lib","threshold":"below","vex_id":sa["@id"],"product":policy.VEX_PRODUCT,"scope_purls":[purl],"expiry":"2026-09-23"},
  {"cve":b,"package":"lib","threshold":"below","vex_id":sb["@id"],"product":policy.VEX_PRODUCT,"scope_purls":[purl],"expiry":"2026-10-20"}]},
  open(os.path.join(ws,".auditor","accepted-items.json"),"w"))
# this run re-derives B (unchanged, not expired); A is not scanned this run -> only B in supp
nb=vex.doc(b,"affected","2026-09-24T00:00:00Z",action="x",subcomponents=[purl])
json.dump(nb,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(supp,"osv-scanner.toml"),"w").write("")
# only A reopened this run (its box lapsed); pass its reopened scope to delivery
json.dump({"accepted_items":[{"cve":b,"package":"lib","threshold":"below","vex_id":nb["statements"][0]["@id"],"product":policy.VEX_PRODUCT,"scope_purls":[purl],"expiry":"2026-10-20"}]},open(os.path.join(os.path.dirname(supp),".auditor","accepted-items.json"),"w"))
json.dump({"reopened":[[a,[policy.VEX_PRODUCT],[purl]]]},open(os.path.join(os.path.dirname(supp),".auditor","reopened-expired.json"),"w"))
PP
r21="$("$PY" -c '
import json,os,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
stmts=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))["statements"]
inv=json.load(open(os.path.join(ws,".auditor","accepted-items.json")))["accepted_items"]
names=sorted(s["vulnerability"]["name"] for s in stmts); invcves=sorted(i["cve"] for i in inv)
print("OK" if names==["CVE-2099-2002"] and invcves==["CVE-2099-2002"] else "BAD stmts=%s inv=%s"%(names,invcves))' "$t21" 2>/dev/null)"
{ eq "$r21" "OK"; } && ok || no "expiring one CVE keeps a sibling CVE on the same scope" "$r21"

begin "refr2-3-sibling-package-fix-does-not-transfer" "two packages under one CVE route independently: an unfixed Critical package -> POA&M, a fixed sibling -> bump; the fix never transfers to the unfixed package"
t23="$WORK/refr2-3"; rm -rf "$t23"; mkdir -p "$t23"
r23="$("$PY" -c '
import sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=sys.argv[1]
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"2026-09-24T00:00:00Z","dry":True,"digest":"sha256:x","carried_expiry":{},"today":"2026-09-24"}
def gm(pkg,purl,fixed,sc):
    return {"scanner":sc,"finding_id":"CVE-2099-2003","purl":purl,"aliases":["CVE-2099-2003"],"package":pkg,"fixed_version":fixed,"severity":("Critical" if fixed is None else "Medium"),"extra":{}}
aaa=[gm("aaa","pkg:deb/debian/aaa@8",None,"grype"),gm("aaa","pkg:deb/debian/aaa@8",None,"osv-scanner")]
bbb=[gm("bbb","pkg:deb/debian/bbb@1","1.0.1","grype"),gm("bbb","pkg:deb/debian/bbb@1","1.0.1","osv-scanner")]
rows,_=R._dispose_split("CVE-2099-2003",aaa+bbb,["CVE-2099-2003"],env,[])
byp={r["package"]:r["section"] for r in rows}
print("OK" if byp.get("aaa")==2 and byp.get("bbb")==3 else "BAD:%s"%byp)' "$t23/out" 2>/dev/null | tail -1)"
{ eq "$r23" "OK"; } && ok || no "sibling package fix does not transfer (aaa=2, bbb=3)" "$r23"

echo "=== report items (scanner tables, db dates, quorum honesty) ==="

begin "rpt1-scanner-tables-groups-and-artifact" "after routing, each scanner gets a collapsible job-log group '<scanner> — <n> packages, <n> findings' with a fixed-width table incl a disposition (§n) column; the same text is in reports/scanner-tables.txt; a clean scanner is a one-line group"
o="$WORK/rpt1"; rm -rf "$o"
log="$(run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" 2>/dev/null; cat "$o/reports/scanner-tables.txt" 2>/dev/null)"
tf="$o/reports/scanner-tables.txt"
gr="$(grep -c '::group:: *grype — [0-9]* packages, [0-9]* findings' "$tf" 2>/dev/null || echo 0)"
hascol="$(grep -c 'vulnerability id' "$tf" 2>/dev/null || echo 0)"
hasdisp="$(grep -Ec '§[0-9]' "$tf" 2>/dev/null || echo 0)"
ends="$(grep -c '::endgroup::' "$tf" 2>/dev/null || echo 0)"
{ [ "$gr" -ge 1 ] 2>/dev/null && [ "$hascol" -ge 1 ] 2>/dev/null && [ "$hasdisp" -ge 1 ] 2>/dev/null && [ "$ends" -ge 4 ] 2>/dev/null; } \
  && ok || no "scanner-tables.txt has per-scanner groups + table + disposition column" "groups=$gr col=$hascol disp=$hasdisp ends=$ends"

begin "rpt2-no-db-date-published-never-dash" "the header never shows a bare 'db=-' (the panel's verdict carries no per-scanner database date, so the header does not print one)"
o="$WORK/rpt2"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
  nodash="$(grep -c 'db=-' "$o/report.md" 2>/dev/null)"; nodash="${nodash:-0}"
  hasscn="$(grep -c '^\*\*Scanners:\*\*' "$o/report.md" 2>/dev/null)"; hasscn="${hasscn:-0}"
  { [ "$nodash" -eq 0 ] 2>/dev/null && [ "$hasscn" -ge 1 ] 2>/dev/null; } \
    && ok || no "header has a Scanners line and never 'db=-'" "db_dash=$nodash scanners_line=$hasscn"; }


begin "rpt3-inventory-quorum-names-agreed-and-not" "the header's quorum line states the panel's rule 3 (an image counts when at least three scanners ran on it) and names the scanners that ran everywhere"
o="$WORK/rpt3b"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
  line="$(grep 'Inventory quorum:' "$o/report.md")"
  { printf '%s' "$line" | grep -q 'at least three scanners ran on it' && printf '%s' "$line" | grep -q 'ran everywhere: grype, scout, inspector, google'; } \
    && ok || no "quorum line states rule 3 and names the scanners that ran everywhere" "line=[$line]"; }


begin "rpt4-scanner-table-maps-advisory-via-router-identity" "a scanner record named by an advisory/alias id (DEBIAN-CVE-2099-7001 for CVE-2099-7001) that the router placed in a section shows that §n in the scanner table, mapped through the ROUTER's completed identity (every alias, not an independent re-canonicalization) — never a bare '-' (R1 refactor round-5 #4)"
o="$WORK/rpt4"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-advisory-bundle.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
  dsarow="$(grep 'DEBIAN-CVE-2099-7001' "$o/reports/scanner-tables.txt" 2>/dev/null | head -1)"
  mapped="$(printf '%s' "$dsarow" | grep -Eq '§[0-9]' && echo yes || echo no)"
  { eq "$mapped" "yes"; } \
    && ok || no "advisory row DEBIAN-CVE-2099-7001 shows a routed §n, not '-'" "row=[$dsarow]"; }

begin "rpt5-run-report-header-token-cost-and-role" "auditor-run.py's rendered report header carries the model ROLE and a TOKEN COST field (REQ-AUD-7 AC1), never omitted and never a model id (R1 refactor round-5 #5)"
o="$WORK/rpt5"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
  hdr="$(sed -n '/## Run header/,/^## /p' "$o/report.md")"
  hastok="$(printf '%s' "$hdr" | grep -qi 'token cost' && echo yes || echo no)"
  hasrole="$(printf '%s' "$hdr" | grep -qi '\*\*model:\*\*' && echo yes || echo no)"
  noid="$(grep -qE 'claude-[a-z0-9.-]+' "$o/report.md" && echo no || echo yes)"
  { eq "$hastok" "yes" && eq "$hasrole" "yes" && eq "$noid" "yes"; } \
    && ok || no "run header has token cost + model role, no model id" "tok=$hastok role=$hasrole no_id=$noid"; }

begin "rpt6-run-report-scanner-down-is-first-line" "when a scanner did not run, auditor-run.py's report FIRST line names it and marks the assessment NOT clean (REQ-AUD-7 AC2, R1 refactor round-5 #6)"
o="$WORK/rpt6"; rm -rf "$o"
# grype/snyk are down here -> quorum fails -> auditor-run EXITS NON-ZERO by design; do not use run()
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-down.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || true
first="$(sed -n '1p' "$o/report.md" 2>/dev/null)"
firstok="$(printf '%s' "$first" | grep -qi 'SCANNER DID NOT RUN' && echo yes || echo no)"
notclean="$(printf '%s' "$first" | grep -qi 'not clean' && echo yes || echo no)"
{ eq "$firstok" "yes" && eq "$notclean" "yes"; } \
  && ok || no "first line names a down scanner and says not clean" "first=[$first]"

echo "=== REQ-AUD-13 refactor boundary regressions (round 3) ==="
# shared env builder for direct _dispose/_dispose_split cases
r3env() { cat <<PYENV
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":"$1","ts":"2026-09-24T00:00:00Z","dry":True,"digest":"x","carried_expiry":$2,"today":"2026-09-24"}
PYENV
}

begin "refr3-2-fix-does-not-transfer-across-versions" "an unfixed version and a fixed version of the SAME package route independently (fixed -> §3 bump; unfixed -> not a §3 bump on the wrong version)"
o="$WORK/refr3-2"; rm -rf "$o"
res="$("$PY" -c '
import importlib.util,shutil
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=__import__("sys").argv[1]; shutil.rmtree(out,ignore_errors=True)
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"today":"2026-09-24"}
def mk(v,fx,sc): return {"scanner":sc,"finding_id":"CVE-2099-1703","purl":"pkg:golang/example.org/lib@"+v,"aliases":["CVE-2099-1703"],"package":"example.org/lib","fixed_version":fx,"severity":("Critical" if fx is None else "Medium"),"extra":{}}
fs=[mk("v8.0.0",None,"grype"),mk("v8.0.0",None,"osv-scanner-gomod"),mk("v1.0.0","1.0.1","grype"),mk("v1.0.0","1.0.1","osv-scanner-gomod")]
rows,_=R._dispose_split("CVE-2099-1703",fs,["CVE-2099-1703"],env,[])
byv={}
for r in rows: byv[r.get("fixed")]=r["section"]
ok = byv.get("1.0.1")==3 and byv.get(None)==2
print("OK" if ok else "BAD:%s"%[(r.get("fixed"),r["section"]) for r in rows])' "$o" 2>/dev/null | tail -1)"
{ eq "$res" "OK"; } && ok || no "fix does not transfer across versions" "$res"

begin "refr3-3-per-scope-filenames-collision-free" "two package names that sanitize to the same basename get DISTINCT VEX files (no clobber before consolidation)"
o="$WORK/refr3-3"; rm -rf "$o"
res="$("$PY" -c '
import importlib.util,glob,shutil
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=__import__("sys").argv[1]; shutil.rmtree(out,ignore_errors=True)
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"today":"2026-09-24"}
def mk(pkg,sc): return {"scanner":sc,"finding_id":"CVE-2099-1802","purl":"pkg:golang/"+pkg+"@v1.0.0","aliases":["CVE-2099-1802"],"package":pkg,"fixed_version":None,"severity":"High","extra":{}}
fs=[mk("example.org/a/b","grype"),mk("example.org/a/b","osv-scanner-gomod"),mk("example.org/a_b","grype"),mk("example.org/a_b","osv-scanner-gomod")]
R._dispose_split("CVE-2099-1802",fs,["CVE-2099-1802"],env,[])
files=[x for x in glob.glob(out+"/vex/*.json")]
print("OK" if len(files)==2 else "BAD:%d"%len(files))' "$o" 2>/dev/null | tail -1)"
{ eq "$res" "OK"; } && ok || no "distinct scopes get distinct VEX filenames" "$res"

begin "refr3-5-lineage-only-not-routed" "a lineage-only advisory record with a different package does NOT form its own disposition; only the real package finding is routed"
o="$WORK/refr3-5"; rm -rf "$o"
res="$("$PY" -c '
import importlib.util,shutil
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=__import__("sys").argv[1]; shutil.rmtree(out,ignore_errors=True)
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"today":"2026-09-24"}
bbb=[{"scanner":"grype","finding_id":"CVE-2099-1806","purl":"pkg:golang/example.org/bbb@v2","aliases":["CVE-2099-1806"],"package":"example.org/bbb","fixed_version":None,"severity":"Critical","extra":{}},
     {"scanner":"osv-scanner","finding_id":"CVE-2099-1806","purl":"pkg:golang/example.org/bbb@v2","aliases":["CVE-2099-1806"],"package":"example.org/bbb","fixed_version":None,"severity":"Critical","extra":{}}]
lin={"scanner":"osv-scanner","finding_id":"GO-2099-1805","purl":"pkg:golang/example.org/aaa@v1","aliases":["CVE-2099-1806"],"package":"example.org/aaa","fixed_version":None,"severity":"Low","extra":{},"_lineage_only":True}
rows,_=R._dispose_split("CVE-2099-1806",bbb+[lin],["CVE-2099-1806"],env,[])
pkgs=sorted(set(r["package"] for r in rows))
print("OK" if pkgs==["example.org/bbb"] else "BAD:%s"%pkgs)' "$o" 2>/dev/null | tail -1)"
{ eq "$res" "OK"; } && ok || no "lineage-only record not routed as its own disposition" "$res"

begin "refr3-6-pullable-fix-lifts-carried-suppression" "when a fix becomes pullable for a carried scope, the finding is §1 lifted and its carried statement/ignore/inventory are removed"
res="$("$PY" -c '
import importlib.util,shutil
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
import os,tempfile; OUT3=os.path.join(tempfile.mkdtemp(),"out")
purl="pkg:golang/example.org/lib@v1.0.0"; sc=((R.policy.VEX_PRODUCT,),(purl,))
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":OUT3,"ts":"t","dry":True,"digest":"x","carried_expiry":{("CVE-2099-1801",sc):"2026-10-30"},"today":"2026-09-24"}
f={"scanner":"grype","finding_id":"CVE-2099-1801","purl":purl,"aliases":["CVE-2099-1801"],"package":"example.org/lib","fixed_version":"v1.0.1","severity":"High","extra":{}}
row,_=R._dispose("CVE-2099-1801",[f],["CVE-2099-1801"],env,[])
print("OK" if row["section"]==1 and row.get("reopened_scope") else "BAD:%s"%row["section"])' 2>/dev/null | tail -1)"
{ eq "$res" "OK"; } && ok || no "pullable fix lifts the carried suppression (§1 + removal)" "$res"

echo "=== REQ-AUD-13 refactor boundary regressions (round 4) ==="

begin "refr4-2-fp-log-does-not-cross-ecosystem" "a trusted defect-log FP for a Debian package closes ONLY the Debian ecosystem at that name/version, never an independently installed PyPI dist of the same name/version (the two sit on different panel images: one finding per CVE+package+version per image)"
o="$WORK/refr4-2"; rm -rf "$o"; mkdir -p "$o"
cat > "$o/grype.json" <<'JSON'
{"matches":[
 {"vulnerability":{"id":"CVE-2099-1951","severity":"Critical"},"artifact":{"name":"requests","version":"2.28.1","type":"deb","purl":"pkg:deb/debian/requests@2.28.1"}},
 {"vulnerability":{"id":"CVE-2099-1951","severity":"Critical"},"artifact":{"name":"requests","version":"2.28.1","type":"python","purl":"pkg:pypi/requests@2.28.1","image":"production-arm64"}}
]}
JSON
cat > "$o/log.json" <<'JSON'
{"defects":[{"package":"requests","disposition":"false_positive","keys":[{"scanner":"grype","finding_id":"CVE-2099-1951","purl":"pkg:deb/debian/requests@2.28.1"}],"evidence":{"detail":"debian backport"}}]}
JSON
"$PY" - "$o" <<'PP'
import json,os,sys
m={"commit":"ab","module":"x","base_os":"debian","candidate_variant":"production","candidate_digests":{"production":"sha256:ab"},
   "scanner_reports":{"grype":os.path.join(sys.argv[1],"grype.json")},"scanner_status":{},
   "govulncheck":None,"known_defect_log":os.path.join(sys.argv[1],"log.json"),"kev_catalog":None}
json.dump(m,open(os.path.join(sys.argv[1],"manifest.json"),"w"))
PP
"$PY" "$WORK/g2p.py" "$o/manifest.json"
r2="$("$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$o/manifest.json" --adjudicator "$STUB" --out "$o/out" >/dev/null 2>&1; "$PY" -c '
import json
c=json.load(open("'"$o"'/out/classification.json"))["findings"]
secs={}
for r in c: secs.setdefault(r["section"],0); secs[r["section"]]+=1
# the deb FP closes in §5; the pypi finding must NOT be §5 (routed on its own, e.g. §2)
print("OK" if 5 in secs and any(r["section"]!=5 for r in c) else "BAD:%s"%[(r["id"],r["section"]) for r in c])' 2>/dev/null)"
{ eq "$r2" "OK"; } && ok || no "deb FP does not close a same-name PyPI dist" "$r2"

begin "refr4-3-pure-lineage-no-product-wide-acceptance" "a CVE reported ONLY via advisory lineage (no per-CVE scanner record) is surfaced §4 under investigation, not a product-wide affected acceptance"
o="$WORK/refr4-3"; rm -rf "$o"
r3="$("$PY" -c '
import importlib.util,shutil
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=__import__("sys").argv[1]; shutil.rmtree(out,ignore_errors=True)
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"carried_scopes":set(),"today":"2026-09-24"}
lin=[{"scanner":"osv-scanner","finding_id":"GO-1","purl":"pkg:golang/adv/lib@v1","aliases":["CVE-2099-3001"],"package":"adv/lib","fixed_version":None,"severity":"High","extra":{},"_lineage_only":True}]
rows,_=R._dispose_split("CVE-2099-3001",lin,["CVE-2099-3001"],env,[])
import glob
vex_files=glob.glob(out+"/vex/*.json")
print("OK" if len(rows)==1 and rows[0]["section"]==4 and not vex_files else "BAD:%s vex=%d"%(rows[0]["section"],len(vex_files)))' "$o" 2>/dev/null | tail -1)"
{ eq "$r3" "OK"; } && ok || no "pure lineage-only CVE is §4, no acceptance/VEX" "$r3"

begin "refr4-5-advisory-lineage-vote-counts-in-routing" "a real finding backed by a co-report advisory has TWO lineages and is NOT treated as unique-lineage (no model call / §4 refusal), routing to POA&M"
o="$WORK/refr4-5"; rm -rf "$o"
r5="$("$PY" -c '
import importlib.util,shutil
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=__import__("sys").argv[1]; shutil.rmtree(out,ignore_errors=True)
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"carried_scopes":set(),"today":"2026-09-24"}
bbb=[{"scanner":"grype","finding_id":"CVE-2099-3002","purl":"pkg:golang/example.org/bbb@v2","aliases":["CVE-2099-3002"],"package":"example.org/bbb","fixed_version":None,"severity":"Critical","extra":{}}]
lin={"scanner":"osv-scanner","finding_id":"GO-2","purl":"pkg:golang/adv@v1","aliases":["CVE-2099-3002"],"package":"adv","fixed_version":None,"severity":"Low","extra":{},"_lineage_only":True}
rows,_=R._dispose_split("CVE-2099-3002",bbb+[lin],["CVE-2099-3002"],env,[])
print("OK" if [r["section"] for r in rows]==[2] else "BAD:%s"%[r["section"] for r in rows])' "$o" 2>/dev/null | tail -1)"
{ eq "$r5" "OK"; } && ok || no "advisory lineage vote keeps a real finding out of unique-lineage suspicion" "$r5"

begin "refr4-4-pullable-fix-lifts-carried-reachability" "a pullable fix lifts a CARRIED reachability not_affected (which has no time box) — §1 lifted + removal — while a FRESH unreachable-with-fix still closes §5"
r4="$("$PY" -c '
import importlib.util,shutil
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
purl="pkg:golang/example.org/lib@v1.0.0"; sc=((R.policy.VEX_PRODUCT,),(purl,))
import os,tempfile; T4=tempfile.mkdtemp(); gv=os.path.join(T4,"gvc.json")
open(gv,"w").write("\n".join([
  "{\"config\":{\"scan_level\":\"symbol\"}}",
  "{\"SBOM\":{\"roots\":[\"example.org/lib\"],\"modules\":[{\"path\":\"example.org/lib\",\"version\":\"v1.0.0\"}]}}",
  "{\"finding\":{\"osv\":\"GO-2099-3004\",\"trace\":[{\"module\":\"example.org/lib\",\"version\":\"v1.0.0\",\"package\":\"example.org/lib/x\"}]}}"]))
def env(cs):
    shutil.rmtree(os.path.join(T4,"out"),ignore_errors=True)
    return {"gvc":gv,"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":os.path.join(T4,"out"),"ts":"t","dry":True,"digest":"x","carried_expiry":{},"carried_scopes":cs,"today":"2026-09-24"}
f={"scanner":"osv-scanner-gomod","finding_id":"GO-2099-3004","purl":purl,"aliases":["GO-2099-3004","CVE-2099-3004"],"package":"example.org/lib","fixed_version":"v1.0.1","severity":"High","extra":{}}
carried,_=R._dispose("CVE-2099-3004",[f],["CVE-2099-3004","GO-2099-3004"],env({("CVE-2099-3004",sc)}),[])
fresh,_=R._dispose("CVE-2099-3004",[f],["CVE-2099-3004","GO-2099-3004"],env(set()),[])
print("OK" if carried["section"]==1 and fresh["section"]==5 else "BAD carried=%s fresh=%s"%(carried["section"],fresh["section"]))' 2>/dev/null | tail -1)"
{ eq "$r4" "OK"; } && ok || no "pullable fix lifts carried reachability; fresh unreachable stays §5" "$r4"

begin "refr4-6-scanner-table-disposition-by-scope" "the scanner table maps each version row to its OWN routed section, not every section the CVE touched"
o="$WORK/refr4-6"; rm -rf "$o"; mkdir -p "$o/reports"
"$PY" - "$o" <<'PP'
import json,sys
o=sys.argv[1]
json.dump({"matches":[{"vulnerability":{"id":"CVE-9","severity":"Medium","fix":{"state":"fixed","versions":["1.0.1"]}},"artifact":{"name":"lib","version":"v1.0.0","type":"golang","purl":"pkg:golang/lib@v1.0.0"}},{"vulnerability":{"id":"CVE-9","severity":"Critical"},"artifact":{"name":"lib","version":"v8.0.0","type":"golang","purl":"pkg:golang/lib@v8.0.0"}}]},open(o+"/grype.json","w"))
json.dump({"scanner_reports":{"grype":o+"/grype.json"}},open(o+"/manifest.json","w"))
PP
"$PY" "$WORK/g2p.py" "$o/manifest.json"
r6="$("$PY" -c '
import importlib.util,json,os
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=__import__("sys").argv[1]
rows=[{"id":"CVE-9","section":3,"scope_purls":["pkg:golang/lib@v1.0.0"]},{"id":"CVE-9","section":2,"scope_purls":["pkg:golang/lib@v8.0.0"]}]
m=json.load(open(out+"/manifest.json"))
R._scanner_tables(m,rows,out)
t=open(out+"/reports/scanner-tables.txt").read().splitlines()
v1=[l for l in t if "0.0" in l and "lib" in l and "v1.0.0" in l or "1.0.0" in l][0]; v8=[l for l in t if "8.0.0" in l][0]
ok=("§3" in v1 and "§2" not in v1) and ("§2" in v8 and "§3" not in v8)
print("OK" if ok else "BAD v1=%r v8=%r"%(v1,v8))' "$o" 2>/dev/null | tail -1)"
{ eq "$r6" "OK"; } && ok || no "scanner table disposition is per-scope" "$r6"

begin "refr4-7-lifted-bump-still-surfaced" "a bump moved to §1 by an AC7 lift but NOT delivered this run still appears as pending work above the sections (§0 / PR list), not dropped"
r7="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
sections[1]=[{"id":"CVE-9","section":1,"disposition":"lifted (fix now pullable)","action":"bump PR pending: no authorized delivery step this run; prior suppression lifted","reason":"x","package":"lib","installed":"1","fixed":"1.1","severity":"High","pending_delivery":True}]
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,sections[1],sections,[],"AUDIT COMPLETE",False,"stub",{},"h","c",None,None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
s1=rep.split("## 1. Lifted")[1].split("## 2.")[0]
print("OK" if ("CVE-9" in s1 and "pending" in s1.lower()) else "BAD")' 2>/dev/null | tail -1)"
{ eq "$r7" "OK"; } && ok || no "lifted-but-undelivered bump surfaced above §1 (PR list / §0)" "$r7"
echo "=== REQ-AUD-14 — fix exists but is not pullable ==="

# shared env builder for the direct _dispose pullability tests
_req14_env() { cat <<'PYENV'
import sys,importlib.util,shutil
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sys.path.insert(0,".github/agent/bin"); from auditorlib import policy
STUB=".github/agent/fixtures/adjudicator/stub-adjudicator.py"
OSPURL="pkg:deb/debian/libopenssl@1.1.1"
CARRIERS=[{"component":"openssl","component_purl":OSPURL,"component_version":"1.1.1","carrier":"nodejs","carrier_purl":"pkg:deb/debian/nodejs@18.19.0","carrier_version":"18.19.0","how":"statically linked"}]
def mkenv(out,**kw):
    shutil.rmtree(out,ignore_errors=True)
    e={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":STUB,
       "state":{"tokens":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-25","out":out,
       "ts":"2026-09-25T00:00:00Z","dry":True,"digest":"sha256:x","carried_expiry":{},"today":"2026-09-25",
       "carried_scopes":set(),"carried_status":{},"carriers":CARRIERS,"base":{},"base_policy_held":False}
    e.update(kw); return e
def mkf(cve,purl=OSPURL,pkg="openssl",fixed="3.0.13",sev="High",scanner="grype"):
    return {"scanner":scanner,"finding_id":cve,"purl":purl,"aliases":[cve],"package":pkg,"fixed_version":fixed,"severity":sev,"extra":{}}
PYENV
}

begin "req14-ac1-carried-fix-routed-not-pullable" "a fixed finding whose vulnerable component is carried inside another artifact (per the SBOM) routes to the not-pullable class (§2, not_pullable set) — never §3, never §2A"
a1="$("$PY" -c "$(_req14_env)
env=mkenv('$WORK/req14-1',carriers=CARRIERS)
row,_=R._dispose('CVE-2099-CARRIED',[mkf('CVE-2099-CARRIED')],['CVE-2099-CARRIED'],env,[])
R.cli.close_adjudicators()
print('OK' if row['section']==2 and row.get('not_pullable')=='upstream-held' else 'BAD sec=%s np=%s'%(row['section'],row.get('not_pullable')))" 2>/dev/null | tail -1)"
{ eq "$a1" "OK"; } && ok || no "carried fix routed to §2B, not §3/§2A" "$a1"

begin "req14-ac2-carrier-evidence-from-sbom" "the disposition's evidence names the carrier, HOW it carries the component, the candidate release, and the bump attempt/result — from the SBOM/model, not opinion"
a2="$("$PY" -c "$(_req14_env)
import glob,json
env=mkenv('$WORK/req14-2',carriers=CARRIERS)
R._dispose('CVE-2099-CARRIED',[mkf('CVE-2099-CARRIED')],['CVE-2099-CARRIED'],env,[])
R.cli.close_adjudicators()
ev=json.load(open(glob.glob('$WORK/req14-2/evidence/*.json')[0]))['evidence']
good=ev.get('carrier',{}).get('carrier')=='nodejs' and 'statically' in (ev.get('carrier',{}).get('how') or ev.get('evidence',{}).get('how') or '') and 'bump_result' in ev
print('OK' if good else 'BAD:%r'%ev)" 2>/dev/null | tail -1)"
{ eq "$a2" "OK"; } && ok || no "evidence names carrier + how + bump result" "$a2"

begin "req14-ac2b-builder-extracts-carriers-from-syft" "the manifest builder extracts carrier relationships from the syft SBOM (parent carries child); the carried component's purl, the carrier, and HOW it is carried come from the SBOM, not opinion"
sy="$WORK/req14-syft.json"
cat > "$sy" <<'SYFT'
{"artifacts":[
  {"id":"a1","name":"openssl","version":"1.1.1","type":"deb","purl":"pkg:deb/debian/openssl@1.1.1"},
  {"id":"a2","name":"nodejs","version":"18.19.0","type":"binary","purl":"pkg:generic/node@18.19.0"}],
 "artifactRelationships":[{"parent":"a2","child":"a1","type":"contains"}]}
SYFT
a2b="$("$PY" -c "
import importlib.util
spec=importlib.util.spec_from_file_location('m','.github/agent/bin/auditor-manifest.py'); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
cs=M._carriers('$sy')
good=len(cs)==1 and cs[0]['component_purl']=='pkg:deb/debian/openssl@1.1.1' and cs[0]['carrier']=='nodejs' and cs[0]['how']=='bundled'
print('OK' if good else 'BAD:%r'%cs)" 2>/dev/null | tail -1)"
{ eq "$a2b" "OK"; } && ok || no "builder extracts carriers from syft SBOM" "$a2b"

begin "req14-ac3-vex-carries-evidence-and-lift-trigger" "the affected VEX's sidecar carries the evidence, a time box (target_date), and a machine-checkable lift trigger (carrier ≥ X embeds component ≥ Y)"
a3="$("$PY" -c "$(_req14_env)
import glob,json
env=mkenv('$WORK/req14-3',carriers=CARRIERS)
R._dispose('CVE-2099-CARRIED',[mkf('CVE-2099-CARRIED')],['CVE-2099-CARRIED'],env,[])
R.cli.close_adjudicators()
side=json.load(open(glob.glob('$WORK/req14-3/evidence/*.json')[0]))
doc=json.load(open(glob.glob('$WORK/req14-3/vex/*.json')[0]))
good=(doc['statements'][0]['status']=='affected' and side.get('target_date')
      and side.get('lift_trigger')=={'carrier':'nodejs','min_version':'20.11.0','component':'openssl',
                                     'component_min_version':'3.0.13'} and side.get('evidence'))
print('OK' if good else 'BAD trig=%r td=%r'%(side.get('lift_trigger'),side.get('target_date')))" 2>/dev/null | tail -1)"
{ eq "$a3" "OK"; } && ok || no "VEX affected + time box + lift trigger" "$a3"

begin "req14-ac4-recheck-lifts-and-opens-pr-on-trigger" "when the lift trigger is met (the model reports the fix is now pullable), the daily recheck LIFTS the carried statement (§1) and routes the bump — no human step"
a4="$("$PY" -c "$(_req14_env)
purl=OSPURL; sc=((policy.VEX_PRODUCT,),(purl,))
env=mkenv('$WORK/req14-4',carriers=CARRIERS,carried_scopes={('CVE-2099-LIFT',sc)},carried_status={('CVE-2099-LIFT',sc):'affected'})
row,_=R._dispose('CVE-2099-LIFT',[mkf('CVE-2099-LIFT')],['CVE-2099-LIFT'],env,[])
R.cli.close_adjudicators()
good=row['section']==1 and 'lifted' in (row.get('disposition') or '') and row.get('not_pullable') is None and 'nodejs 20.11.0' in (row.get('action') or '')
print('OK' if good else 'BAD sec=%s disp=%s np=%s act=%r'%(row['section'],row.get('disposition'),row.get('not_pullable'),row.get('action')))" 2>/dev/null | tail -1)"
{ eq "$a4" "OK"; } && ok || no "lift trigger met -> §1 lifted, no human step" "$a4"

begin "req14-ac5-row-states-the-case" "the §2 row states the exact case: 'fix exists in <component> ≥ Y; not pullable: carried by <carrier> at Y′' (upstream-held) and the policy-held variant"
a5="$("$PY" -c "$(_req14_env)
env=mkenv('$WORK/req14-5a',carriers=CARRIERS)
r1,_=R._dispose('CVE-2099-CARRIED',[mkf('CVE-2099-CARRIED')],['CVE-2099-CARRIED'],env,[])
env2=mkenv('$WORK/req14-5b',carriers=[],base={'release':'debian 12.0','repo':'debian'},base_policy_held=True)
r2,_=R._dispose('CVE-2099-POLICY',[mkf('CVE-2099-POLICY',pkg='libpolicy',purl='pkg:deb/debian/libpolicy@1.0',fixed='1.2.3-1')],['CVE-2099-POLICY'],env2,[])
R.cli.close_adjudicators()
up=('fix exists in openssl >= 3.0.13' in r1['reason'] and 'carried by nodejs at 18.19.0' in r1['reason'])
po=('policy-held' in r2['reason'] and 'lifts on base release >= debian 12.6' in r2['reason'] and r2.get('not_pullable')=='policy-held')
print('OK' if up and po else 'BAD up=%r po=%r'%(r1['reason'],r2['reason']))" 2>/dev/null | tail -1)"
{ eq "$a5" "OK"; } && ok || no "row states the exact case (upstream + policy)" "$a5"

begin "req14-production-client-answers-pullability" "the PRODUCTION adjudicator client (not just the stub) answers a pullability request with a parsed verdict (pullable/hold/lift_trigger) — the not-pullable class is reachable through the real model client (Codex round-1 blocker)"
pc="$("$PY" -c "
import importlib.util,os
os.environ['AUDITOR_MODEL_PRIMARY']='m'
spec=importlib.util.spec_from_file_location('c','.github/agent/bin/auditor-adjudicator-client.py'); C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
class B: text=('Analysis: '+'{\"pullable\": false, \"hold\": \"upstream-held\", \"component_fixed\": \"3.0.13\", '
    '\"lift_trigger\": {\"carrier\": \"nodejs\", \"min_version\": \"20.11.0\", \"component\": \"openssl\", '
    '\"component_min_version\": \"3.0.13\"}, \"candidate_release\": null}')
class Msg: content=[B()]; usage=None
class _M:
    @staticmethod
    def create(**k): return Msg()
class Client: messages=_M()
req={'kind':'pullability','finding_id':'CVE-X','component':'openssl','component_fixed':'3.0.13','carrier':{'carrier':'nodejs','carrier_version':'18.19.0'}}
ans=C._handle(req,Client())
good=(ans.get('pullable') is False and ans.get('hold')=='upstream-held'
      and (ans.get('lift_trigger') or {}).get('carrier')=='nodejs')
print('OK' if good else 'BAD:%r'%ans)" 2>/dev/null | tail -1)"
{ eq "$pc" "OK"; } && ok || no "production client answers pullability" "$pc"

begin "req14-ac6b-builder-lifecycle-from-endoflife" "the manifest builder computes the eol maintenance flags (base + carriers on LTS/EOL lines) and the base pin-lag block from endoflife.date data (best-effort producer wired, not just consumed)"
a6b="$("$PY" -c "
import importlib.util
spec=importlib.util.spec_from_file_location('m','.github/agent/bin/auditor-manifest.py'); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
DATA={'debian':[{'cycle':'12','eol':'2028-06-10','lts':'2026-06-10','latest':'12.6','latestReleaseDate':'2024-06-15'}],
      'nodejs':[{'cycle':'18','eol':'2025-04-30','lts':'2022-10-25','latest':'18.20.0','latestReleaseDate':'2024-03-26'}]}
eol,base=M._lifecycle('debian 12.0',[{'carrier':'nodejs','carrier_version':'18.19.0'}],lambda p:DATA.get(p),'2026-09-25')
st={e['carrier']:e['status'] for e in eol}
good=st.get('debian')=='maintenance' and st.get('nodejs')=='eol' and base.get('days_behind',0)>30
print('OK' if good else 'BAD eol=%r base=%r'%(eol,base))" 2>/dev/null | tail -1)"
{ eq "$a6b" "OK"; } && ok || no "builder computes eol/base from endoflife" "$a6b"

begin "req14-incomplete-verdict-no-acceptance" "a not-pullable verdict WITHOUT a machine-checkable lift trigger does NOT create a §2B accepted-risk suppression — it falls through to normal routing (Codex round-1 residual: incomplete answers must not suppress)"
iv="$("$PY" -c "$(_req14_env)
env=mkenv('$WORK/req14-vague',carriers=[{'component':'openssl','component_purl':OSPURL,'component_version':'1.1.1','carrier':'nodejs','carrier_purl':'p','carrier_version':'18','how':'x'}])
row,_=R._dispose('CVE-2099-VAGUE',[mkf('CVE-2099-VAGUE')],['CVE-2099-VAGUE'],env,[])
R.cli.close_adjudicators()
print('OK' if row.get('not_pullable') is None and row['section']!=2 else 'BAD sec=%s np=%s'%(row['section'],row.get('not_pullable')))" 2>/dev/null | tail -1)"
{ eq "$iv" "OK"; } && ok || no "incomplete not-pullable verdict does not suppress" "$iv"

begin "req14-expired-not-pullable-reopens" "an expired carried not-pullable acceptance reopens to §3 (time box lapsed), never silently re-accepted just because the fix is still not pullable (Codex round-1 residual: expiry parity)"
er="$("$PY" -c "$(_req14_env)
purl=OSPURL; sc=((policy.VEX_PRODUCT,),(purl,))
env=mkenv('$WORK/req14-exp',carriers=CARRIERS,carried_expiry={('CVE-2099-CARRIED',sc):'2026-09-01'},today='2026-09-25')
row,_=R._dispose('CVE-2099-CARRIED',[mkf('CVE-2099-CARRIED')],['CVE-2099-CARRIED'],env,[])
R.cli.close_adjudicators()
good=row['section']==3 and row.get('reopened_expired')=='2026-09-01' and row.get('not_pullable') is None
print('OK' if good else 'BAD sec=%s reopened=%s np=%s'%(row['section'],row.get('reopened_expired'),row.get('not_pullable')))" 2>/dev/null | tail -1)"
{ eq "$er" "OK"; } && ok || no "expired not-pullable acceptance reopens to §3" "$er"

begin "req14-carrier-extraction-ignores-dependency-of" "the builder does NOT treat 'dependency-of' (ordinary independently-upgradable deps) or 'ownership-by-file-overlap' as carrier relationships — only 'contains' (parent bundles child); this avoids the inverted mapping that flagged every apt dep (Sonnet round-1 blocker 2)"
cext="$("$PY" -c "
import importlib.util
spec=importlib.util.spec_from_file_location('m','.github/agent/bin/auditor-manifest.py'); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
import json,tempfile,os
d={'artifacts':[{'id':'a1','name':'dpkg','version':'1','type':'deb','purl':'pkg:deb/debian/dpkg@1'},
                {'id':'a2','name':'zlib1g','version':'1','type':'deb','purl':'pkg:deb/debian/zlib1g@1'},
                {'id':'a3','name':'openssl','version':'1.1.1','type':'deb','purl':'pkg:deb/debian/openssl@1.1.1'},
                {'id':'a4','name':'nodejs','version':'18','type':'binary','purl':'pkg:generic/node@18'}],
   'artifactRelationships':[{'parent':'a2','child':'a1','type':'dependency-of'},
                            {'parent':'a2','child':'a1','type':'ownership-by-file-overlap'},
                            {'parent':'a4','child':'a3','type':'contains'}]}
p=tempfile.mktemp(suffix='.json'); json.dump(d,open(p,'w'))
cs=M._carriers(p)
good=len(cs)==1 and cs[0]['carrier']=='nodejs' and cs[0]['component']=='openssl'
print('OK' if good else 'BAD:%r'%cs)" 2>/dev/null | tail -1)"
{ eq "$cext" "OK"; } && ok || no "only 'contains' is a carrier relationship" "$cext"

begin "req14-carrier-ignores-image-and-file-contains" "a 'contains' whose parent is the image (no purl) or whose child is a file (no purl) is NOT a carrier — only a package that bundles another vulnerable-capable package (both have purls) counts (avoids the 4831 image/file 'contains' on a real debian SBOM)"
cif="$("$PY" -c "
import importlib.util,json,tempfile
spec=importlib.util.spec_from_file_location('m','.github/agent/bin/auditor-manifest.py'); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
d={'artifacts':[{'id':'img','name':'image','type':'image'},
                {'id':'p1','name':'openssl','version':'1.1.1','type':'deb','purl':'pkg:deb/debian/openssl@1.1.1'},
                {'id':'f1','name':'/usr/bin/x','type':'file'},
                {'id':'nb','name':'nodejs','version':'18','type':'binary','purl':'pkg:generic/node@18'}],
   'artifactRelationships':[{'parent':'img','child':'p1','type':'contains'},
                            {'parent':'p1','child':'f1','type':'contains'},
                            {'parent':'nb','child':'p1','type':'contains'}]}
p=tempfile.mktemp(suffix='.json'); json.dump(d,open(p,'w'))
cs=M._carriers(p)
good=len(cs)==1 and cs[0]['carrier']=='nodejs' and cs[0]['component']=='openssl'
print('OK' if good else 'BAD:%r'%cs)" 2>/dev/null | tail -1)"
{ eq "$cif" "OK"; } && ok || no "image/file 'contains' are not carriers" "$cif"

begin "req14-base-os-from-syft-distro" "the builder reads the PINNED base release from syft's distro block (so the endoflife lookup matches the right cycle, not a hardcoded 'debian')"
bos="$("$PY" -c "
import importlib.util,json,tempfile
spec=importlib.util.spec_from_file_location('m','.github/agent/bin/auditor-manifest.py'); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
p=tempfile.mktemp(suffix='.json'); json.dump({'distro':{'id':'debian','versionID':'12.0'}},open(p,'w'))
print('OK' if M._base_os(p)=='debian 12.0' else 'BAD:%r'%M._base_os(p))" 2>/dev/null | tail -1)"
{ eq "$bos" "OK"; } && ok || no "base_os from syft distro" "$bos"

begin "req14-carried-notpullable-no-false-lift" "a scope carried as §2B not-pullable does NOT lift when the recheck cannot confirm the fix became pullable (model outage / carrier signal gone) — it re-carries the suppression, never fabricates 'lifted (fix now pullable)' (Sonnet round-1 blocker 1)"
nfl="$("$PY" -c "$(_req14_env)
purl=OSPURL; sc=((policy.VEX_PRODUCT,),(purl,))
env=mkenv('$WORK/req14-nofalselift',carriers=[],carried_scopes={('CVE-2099-CARRIED',sc)},carried_status={('CVE-2099-CARRIED',sc):'affected'},carried_not_pullable={('CVE-2099-CARRIED',sc)})
row,_=R._dispose('CVE-2099-CARRIED',[mkf('CVE-2099-CARRIED')],['CVE-2099-CARRIED'],env,[])
R.cli.close_adjudicators()
good=row['section']==2 and row.get('not_pullable') in ('upstream-held','policy-held') and 'lifted' not in (row.get('disposition') or '') and 'deferred' in (row.get('disposition') or '')
print('OK' if good else 'BAD sec=%s disp=%s'%(row['section'],row.get('disposition')))" 2>/dev/null | tail -1)"
{ eq "$nfl" "OK"; } && ok || no "carried §2B does not false-lift when unconfirmed" "$nfl"

begin "req14-deferred-recheck-keeps-threshold-and-trigger" "a deferred recheck of a carried §2B finding recomputes and PRESERVES the policy threshold + owner-decision requirement (never silently downgrades a Critical to below) and keeps the CONCRETE lift trigger (Codex round-2 P1 + P2)"
dt="$("$PY" -c "$(_req14_env)
purl=OSPURL; sc=((policy.VEX_PRODUCT,),(purl,))
trig={'carrier':'nodejs','min_version':'20.11.0','component':'openssl','component_min_version':'3.0.13'}
env=mkenv('$WORK/req14-defthr',carriers=[],carried_scopes={('CVE-2099-CRIT',sc)},
          carried_status={('CVE-2099-CRIT',sc):'affected'},carried_not_pullable={('CVE-2099-CRIT',sc)},
          carried_lift_trigger={('CVE-2099-CRIT',sc):trig})
row,_=R._dispose('CVE-2099-CRIT',[mkf('CVE-2099-CRIT',sev='Critical')],['CVE-2099-CRIT'],env,[])
R.cli.close_adjudicators()
good=(row['section']==2 and row.get('threshold')=='at_or_above' and bool(row.get('owner_issue_intent'))
      and (row.get('lift_trigger') or {}).get('carrier')=='nodejs')
print('OK' if good else 'BAD thr=%s oi=%s trig=%r'%(row.get('threshold'),bool(row.get('owner_issue_intent')),row.get('lift_trigger')))" 2>/dev/null | tail -1)"
{ eq "$dt" "OK"; } && ok || no "deferred recheck keeps threshold + owner + concrete trigger" "$dt"

begin "req14-ac6-header-flags-lts-eol-carrier" "the header flags any carrier on a maintenance-LTS or end-of-life line (endoflife.date), independent of any CVE"
a6="$("$PY" -c "
import importlib.util
spec=importlib.util.spec_from_file_location('r','.github/agent/bin/auditor-run.py'); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
st={'grype':{'ran':True,'os_package_count':6,'package_count':6,'findings':0,'version':'x','db_date':'d'}}
m={'scanner_status':st,'scanner_reports':{'grype':'x'},'candidate_digests':{},'govulncheck':None,
   'eol':[{'carrier':'nodejs','cycle':'18','status':'maintenance','eol_date':'2025-04-30'},
          {'carrier':'python','cycle':'3.7','status':'eol','eol_date':'2023-06-27'}]}
rep=R._render(m,[],{n:[] for n in range(1,8)},[],'AUDIT COMPLETE',True,'stub',{},'h','c',None,None,{'agreed':['grype'],'disagreed':[],'not_ran':[],'excluded':[]})
ml=[l for l in rep.splitlines() if 'Maintenance flags' in l]
good=ml and 'nodejs 18 is on a maintenance/LTS line' in ml[0] and 'python 3.7 is END-OF-LIFE' in ml[0]
print('OK' if good else 'BAD:%r'%ml)" 2>/dev/null | tail -1)"
{ eq "$a6" "OK"; } && ok || no "header flags LTS + EOL carriers" "$a6"

begin "req14-ac7-policy-held-base-pin-vs-carrier" "a policy-held (base-pin) hold is distinguished from upstream-held (carrier) in the row/VEX, and the header flags a base pin more than N days behind its repository's fix"
a7="$("$PY" -c "$(_req14_env)
import importlib.util,glob,json
env2=mkenv('$WORK/req14-7',carriers=[],base={'release':'debian 12.0','repo':'debian'},base_policy_held=True)
r2,_=R._dispose('CVE-2099-POLICY',[mkf('CVE-2099-POLICY',pkg='libpolicy',purl='pkg:deb/debian/libpolicy@1.0',fixed='1.2.3-1')],['CVE-2099-POLICY'],env2,[])
R.cli.close_adjudicators()
side=json.load(open(glob.glob('$WORK/req14-7/evidence/*.json')[0]))
np_ok=r2.get('not_pullable')=='policy-held' and side['evidence'].get('hold')=='policy-held'
st={'grype':{'ran':True,'os_package_count':6,'package_count':6,'findings':0,'version':'x','db_date':'d'}}
m={'scanner_status':st,'scanner_reports':{'grype':'x'},'candidate_digests':{},'govulncheck':None,
   'base':{'release':'debian 12.0','days_behind':61,'behind_threshold_days':30}}
rep=R._render(m,[],{n:[] for n in range(1,8)},[],'AUDIT COMPLETE',True,'stub',{},'h','c',None,None,{'agreed':['grype'],'disagreed':[],'not_ran':[],'excluded':[]})
hdr_ok=any('base pin debian 12.0 is 61 days behind' in l for l in rep.splitlines())
print('OK' if np_ok and hdr_ok else 'BAD np=%s hdr=%s'%(np_ok,hdr_ok))" 2>/dev/null | tail -1)"
{ eq "$a7" "OK"; } && ok || no "policy-held distinguished + base-pin-behind header flag" "$a7"

echo "=== REQ-AUD-17 — alerts and the auto-merge ramp ==="

# a crafted source producing one Critical no-fix OS finding (grype+snyk, 2 lineages) -> §2
# at-or-above POA&M -> an owner-decision issue and a non-empty §0.
_req17_src() { local d="$1"; rm -rf "$d"; mkdir -p "$d"
"$PY" - "$d" <<'PP'
import json,sys
d=sys.argv[1]
json.dump({"matches":[{"vulnerability":{"id":"CVE-2099-CRIT","severity":"Critical","fix":{"state":"not-fixed"}},"artifact":{"purl":"pkg:deb/debian/libcrit@1.0","name":"libcrit"}}]},open(d+"/grype.json","w"))
json.dump({"vulnerabilities":[{"id":"SNYK-CRIT","packageName":"libcrit","purl":"pkg:deb/debian/libcrit@1.0","severity":"critical","identifiers":{"CVE":["CVE-2099-CRIT"]}}]},open(d+"/snyk.json","w"))
st={s:{"ran":True,"os_package_count":1,"package_count":1,"findings":1,"version":"x","db_date":"d"} for s in ("grype","snyk")}
for s in ("trivy","osv-scanner","osv-scanner-gomod"): st[s]={"ran":False,"reason":"nr","os_package_count":0,"package_count":0,"findings":0,"version":None,"db_date":None}
json.dump({"defects":[]},open(d+"/log.json","w"))
json.dump({"commit":"c","candidate_digests":{"production":"sha256:x"},"base_os":"debian 12.0","module":None,"govulncheck":None,"known_defect_log":d+"/log.json","scanner_reports":{"grype":d+"/grype.json","snyk":d+"/snyk.json","trivy":None,"osv-scanner":None,"osv-scanner-gomod":None},"scanner_status":st},open(d+"/manifest.json","w"))
PP
"$PY" "$WORK/g2p.py" "$d/manifest.json"
}

begin "req17-ac1-fixed-subject-prefix-family" "every PR and issue the auditor opens leads with one fixed subject-prefix family so a single mail filter catches them all; owner-decision issues keep their 'owner-decision:' sub-prefix"
a1="$("$PY" -c "
import sys; sys.path.insert(0,'.github/agent/bin')
from auditorlib import policy
oi=policy.owner_issue_title('CVE-1','pkg','critical-severity')
good=(oi.startswith('auditor:') and 'owner-decision:' in oi
      and policy.subject('x')=='auditor: x' and policy.subject('auditor: x')=='auditor: x'
      and policy.STANDING_ISSUE_TITLE.startswith('auditor:'))
print('OK' if good else 'BAD oi=%r'%oi)" 2>/dev/null | tail -1)"
{ eq "$a1" "OK"; } && ok || no "fixed subject-prefix family on issues + PRs" "$a1"

begin "req17-ac2-standing-needs-a-human-issue" "a single standing 'needs a human' issue is commented (find-or-create) on a run whose §0 is non-empty, and closed on a run whose §0 is empty"
o="$WORK/req17-ac2"; rm -rf "$o"; sh1="$WORK/req17-ac2a.shim"; sh2="$WORK/req17-ac2b.shim"; rm -f "$sh1" "$sh2"; _req17_src "$WORK/req17-ac2-src"
# non-empty §0 (Critical owner item) -> standing issue commented/created
env AUDITOR_GIT_SHIM_LOG="$sh1" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$WORK/req17-ac2-src/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || true
open1="$(grep -c "issue create --title 'auditor: needs a human'" "$sh1" 2>/dev/null)"; open1="${open1:-0}"
# empty §0 (a clean run: no findings, quorum OK -> AUDIT COMPLETE, §0 empty) -> standing issue closed
o2="$WORK/req17-ac2c"; rm -rf "$o2"; dc="$WORK/req17-ac2-clean"; rm -rf "$dc"; mkdir -p "$dc"
"$PY" - "$dc" <<'PP'
import json,sys
d=sys.argv[1]
json.dump({"matches":[]},open(d+"/grype.json","w"))                          # zero findings
json.dump({"Results":[]},open(d+"/trivy.json","w"))
json.dump({"vulnerabilities":[],"dependencyCount":3},open(d+"/snyk.json","w"))
st={s:{"ran":True,"os_package_count":3,"package_count":3,"findings":0,"version":"x","db_date":"d"} for s in ("grype","trivy","snyk")}
for s in ("osv-scanner","osv-scanner-gomod"): st[s]={"ran":False,"reason":"nr","os_package_count":0,"package_count":0,"findings":0,"version":None,"db_date":None}
json.dump({"defects":[]},open(d+"/log.json","w"))
json.dump({"commit":"c","candidate_digests":{"production":"sha256:x"},"base_os":"debian 12.0","module":None,"govulncheck":None,"known_defect_log":d+"/log.json","scanner_reports":{"grype":d+"/grype.json","trivy":d+"/trivy.json","snyk":d+"/snyk.json","osv-scanner":None,"osv-scanner-gomod":None},"scanner_status":st},open(d+"/manifest.json","w"))
PP
"$PY" "$WORK/g2p.py" "$dc/manifest.json"
env AUDITOR_GIT_SHIM_LOG="$sh2" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$dc/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o2" >/dev/null 2>&1 || true
close2="$(grep -c "issue close --title 'auditor: needs a human'" "$sh2" 2>/dev/null)"; close2="${close2:-0}"
{ [ "$open1" -ge 1 ] 2>/dev/null && [ "$close2" -ge 1 ] 2>/dev/null; } \
  && ok || no "standing issue commented when §0 non-empty, closed when empty" "open=$open1 close=$close2"

begin "req17-ac2-standing-issue-failure-is-incomplete" "a FAILED standing-issue update (e.g. gh issue discovery errors) returns failure — it never silently reports success (Codex round-1 blocker)"
sif="$("$PY" -c '
import importlib.util
from unittest.mock import patch
import subprocess as _sp, os
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
def failing(cmd,*a,**kw):
    if cmd[:3]==["gh","issue","list"]: return _sp.CompletedProcess(cmd,1,"","connection reset")
    return _sp.CompletedProcess(cmd,0,"","")
with patch.dict(os.environ,{"AUDITOR_ALLOW_REAL_GH":"1"}),patch.object(R.subprocess,"run",failing):
    ok1,_=R._standing_issue(["owner-decision needed: CVE-X — #1"],False,[])   # non-empty
    ok2,_=R._standing_issue([],False,[])                                        # empty (close)
print("OK" if (ok1 is False and ok2 is False) else "BAD ok1=%s ok2=%s"%(ok1,ok2))' 2>/dev/null | tail -1)"
{ eq "$sif" "OK"; } && ok || no "standing-issue failure propagates (never silent success)" "$sif"

begin "req17-ac2-standing-issue-created-once-reopens" "the standing issue is CREATED ONCE: a run that finds it CLOSED reopens the SAME issue rather than creating a new one (Codex round-1 residual)"
sco="$("$PY" -c '
import importlib.util
from unittest.mock import patch
import subprocess as _sp, os
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
calls=[]
def fake(cmd,*a,**kw):
    calls.append(cmd)
    if cmd[:3]==["gh","issue","list"]:
        return _sp.CompletedProcess(cmd,0,"[{\"number\":5,\"state\":\"CLOSED\",\"title\":\"%s\"}]"%R.policy.STANDING_ISSUE_TITLE,"")
    return _sp.CompletedProcess(cmd,0,"","")
with patch.dict(os.environ,{"AUDITOR_ALLOW_REAL_GH":"1"}),patch.object(R.subprocess,"run",fake):
    ok,ref=R._standing_issue(["owner-decision needed: CVE-X — #1"],False,[])
reopened=any(c[:3]==["gh","issue","reopen"] and "5" in c for c in calls)
created=any(c[:3]==["gh","issue","create"] for c in calls)
print("OK" if (ok and reopened and not created) else "BAD ok=%s reopened=%s created=%s ref=%s"%(ok,reopened,created,ref))' 2>/dev/null | tail -1)"
{ eq "$sco" "OK"; } && ok || no "standing issue reopened (created once), not re-created" "$sco"

begin "req17-ac3-repo-var-draft-to-automerge" "the AUDITOR_AUTOMERGE repo variable flips the suppression PR from draft to auto-merge (squash); unset keeps it a draft"
o="$WORK/req17-ac3"; rm -rf "$o"; shd="$WORK/req17-ac3-draft.shim"; sha="$WORK/req17-ac3-auto.shim"; rm -f "$shd" "$sha"; _req17_src "$WORK/req17-ac3-src"
env AUDITOR_GIT_SHIM_LOG="$shd" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$WORK/req17-ac3-src/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || true
draft_draft="$(grep -c 'pr create --draft' "$shd" 2>/dev/null)"; draft_draft="${draft_draft:-0}"
draft_auto="$(grep -c 'pr merge --auto --squash' "$shd" 2>/dev/null)"; draft_auto="${draft_auto:-0}"
o2="$WORK/req17-ac3b"; rm -rf "$o2"
env AUDITOR_AUTOMERGE=on AUDITOR_GIT_SHIM_LOG="$sha" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$WORK/req17-ac3-src/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o2" >/dev/null 2>&1 || true
auto_draft="$(grep -c 'pr create --draft' "$sha" 2>/dev/null)"; auto_draft="${auto_draft:-0}"
auto_auto="$(grep -c 'pr merge --auto --squash' "$sha" 2>/dev/null)"; auto_auto="${auto_auto:-0}"
{ [ "$draft_draft" -ge 1 ] 2>/dev/null && [ "$draft_auto" -eq 0 ] 2>/dev/null && [ "$auto_draft" -eq 0 ] 2>/dev/null && [ "$auto_auto" -ge 1 ] 2>/dev/null; } \
  && ok || no "unset=draft/no-automerge; on=non-draft+automerge" "unset(draft=$draft_draft auto=$draft_auto) on(draft=$auto_draft auto=$auto_auto)"

begin "req17-ac4-records-automerge-prompt-human-only" "records the auditor delivers auto-merge when the variable is on; a change touching the versioned prompt file NEVER auto-merges (human-merged always)"
a4="$("$PY" -c "
import os,importlib.util
spec=importlib.util.spec_from_file_location('r','.github/agent/bin/auditor-run.py'); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
os.environ['AUDITOR_AUTOMERGE']='on'
records=R._automerge_allowed(['.vex/fosterstack-cache.openvex.json','.snyk','.auditor/accepted-items.json','.auditor/proposals/adjudicator-proposals.json'])
prompt=R._automerge_allowed(['.vex/fosterstack-cache.openvex.json','.github/agent/prompts/adjudicator.md'])
os.environ['AUDITOR_AUTOMERGE']='off'
off=R._automerge_allowed(['.snyk'])
print('OK' if (records is True and prompt is False and off is False) else 'BAD records=%s prompt=%s off=%s'%(records,prompt,off))" 2>/dev/null | tail -1)"
{ eq "$a4" "OK"; } && ok || no "records auto-merge; prompt file never does" "$a4"

begin "req17-ac5-owner-items-hold-release-not-merge" "an owner-decision item (Critical/KEV acceptance) holds RELEASE authorization only; it never blocks the suppression PR from being delivered/merged"
o="$WORK/req17-ac5"; rm -rf "$o"; sh="$WORK/req17-ac5.shim"; rm -f "$sh"; _req17_src "$WORK/req17-ac5-src"
env AUDITOR_AUTOMERGE=on AUDITOR_GIT_SHIM_LOG="$sh" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$WORK/req17-ac5-src/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || true
# the merge is NOT blocked by the pending owner decision: the PR is delivered + auto-merge armed
delivered="$(grep -c 'pr create' "$sh" 2>/dev/null)"; delivered="${delivered:-0}"
armed="$(grep -c 'pr merge --auto --squash' "$sh" 2>/dev/null)"; armed="${armed:-0}"
# but the RELEASE gate holds on the unaccepted at-or-above item.
az="$WORK/req17-ac5-authz"; rm -rf "$az"; mkdir -p "$az"
cp "$o/.auditor/accepted-items.json" "$az/cand.json" 2>/dev/null
hold="$("$PY" -c "
import json,sys
d=json.load(open('$az/cand.json'))
at=[i for i in d['accepted_items'] if i.get('threshold')=='at_or_above']
print('yes' if at else 'no')" 2>/dev/null)"; hold="${hold:-no}"
{ [ "$delivered" -ge 1 ] 2>/dev/null && [ "$armed" -ge 1 ] 2>/dev/null && eq "$hold" "yes"; } \
  && ok || no "PR delivered/armed; owner item recorded for release-hold (not a merge block)" "delivered=$delivered armed=$armed at_threshold_item=$hold"

echo "=== REQ-AUD-16 — auditor knowledge ==="

# shared crafted source: one PURE log-hit FP (CVE-2099-KNOWN) and one NEW unique-lineage no-fix
# finding (CVE-2099-NEW, grype-only, not in the log) — the only case that consults the model.
_req16_src() { local d="$1"; rm -rf "$d"; mkdir -p "$d"
"$PY" - "$d" <<'PP'
import json,sys
d=sys.argv[1]
json.dump({"matches":[
  {"vulnerability":{"id":"CVE-2099-KNOWN","severity":"Medium","fix":{"state":"not-fixed"}},"artifact":{"purl":"pkg:deb/debian/libknown@1.0","name":"libknown"}},
  {"vulnerability":{"id":"CVE-2099-NEW","severity":"Medium","fix":{"state":"not-fixed"}},"artifact":{"purl":"pkg:deb/debian/libnew@1.0","name":"libnew"}}
]},open(d+"/grype.json","w"))
st={"grype":{"ran":True,"os_package_count":2,"package_count":2,"findings":2,"version":"x","db_date":"d"}}
for s in ("trivy","osv-scanner","osv-scanner-gomod","snyk"): st[s]={"ran":False,"reason":"nr","os_package_count":0,"package_count":0,"findings":0,"version":None,"db_date":None}
json.dump({"defects":[{"package":"libknown","disposition":"false_positive","evidence":"debian no-DSA (minor)",
                       "keys":[{"scanner":"grype","finding_id":"CVE-2099-KNOWN","purl":"pkg:deb/debian/libknown@1.0"}]}]},open(d+"/log.json","w"))
json.dump({"commit":"c","candidate_digests":{"production":"sha256:x"},"base_os":"debian 12.0","module":None,"govulncheck":None,
           "known_defect_log":d+"/log.json",
           "scanner_reports":{"grype":d+"/grype.json","trivy":None,"osv-scanner":None,"osv-scanner-gomod":None,"snyk":None},"scanner_status":st},open(d+"/manifest.json","w"))
PP
"$PY" "$WORK/g2p.py" "$d/manifest.json"
}

begin "req16-ac1-structured-deterministic-memory" "the run's memory is the STRUCTURED records (known-defect log + VEX), not model recall: a pure log-covered finding closes with NO model call"
o="$WORK/req16-ac1"; rm -rf "$o"; : > "$LEDGER"; _req16_src "$WORK/req16-ac1-src"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/req16-ac1-src/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || true
calls="$(grep -c 'CVE-2099-KNOWN' "$LEDGER" 2>/dev/null)"; calls="${calls:-0}"
closed="$(sed -n '/^## 5\./,/^## /p' "$o/report.md" 2>/dev/null | grep -c 'CVE-2099-KNOWN')"; closed="${closed:-0}"
{ [ "$calls" -eq 0 ] 2>/dev/null && [ "$closed" -ge 1 ] 2>/dev/null; } \
  && ok || no "pure log-covered finding closes with no model call" "ledger_calls=$calls closed_in_s5=$closed"

begin "req3-ac3-driver-nochange-zero-model" "the DRIVER (REQ-AUD-3 AC3): a second run with yesterday's auditor-state makes zero model calls and keeps the same finding-set hash; a state for another finding set, a garbage state and a missing one are ignored (model calls as today)"
nl() { if [ -s "$LEDGER" ]; then wc -l < "$LEDGER" | tr -d ' '; else echo 0; fi; }
drv() { # drv OUTDIR [prev-state]
  local o="$1"; shift; local extra=(); [ -n "${1:-}" ] && extra=(--prev-state "$1")
  "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/nc-src/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" "${extra[@]}" --out "$o" >/dev/null 2>&1; }
n1="$WORK/dn1"; n2="$WORK/dn2"; n3="$WORK/dn3"; n4="$WORK/dn4"; n5="$WORK/dn5"; rm -rf "$n1" "$n2" "$n3" "$n4" "$n5"; # the same fixture with the second finding carrying an id the stub answers (a false positive): a unique-lineage, no-fix finding the model judges
eval "$(declare -f _req16_src | sed 's/CVE-2099-NEW/CVE-2016-2781/g; s/_req16_src/_nc_src/')"; _nc_src "$WORK/nc-src"
: > "$LEDGER"; drv "$n1"; calls1="$(nl)"; : > "$LEDGER"; st1="$n1/.auditor/auditor-state.json"
drv "$n2" "$st1"; calls2="$(nl)"; : > "$LEDGER"
h1="$(pj "$st1" 'd["finding_set_hash"]')"; h2="$(pj "$n2/.auditor/auditor-state.json" 'd["finding_set_hash"]')"
"$PY" -c 'import json,sys
d=json.load(open(sys.argv[1])); d["finding_set_hash"]="0"*64; json.dump(d,open(sys.argv[2],"w"))' "$st1" "$WORK/other-state.json"
drv "$n3" "$WORK/other-state.json"; calls3="$(nl)"; : > "$LEDGER"
echo '{"garbage": true' > "$WORK/bad-state.json"; drv "$n4" "$WORK/bad-state.json"; calls4="$(nl)"; : > "$LEDGER"
drv "$n5" "$WORK/missing-state.json"; calls5="$(nl)"; : > "$LEDGER"
valid="$(printf '%s' "$h1" | grep -Eq '^[0-9a-f]{64}$' && echo y || echo n)"
{ eq "$valid" "y" && [ "$calls1" -gt 0 ] && eq "$calls2" "0" && eq "$h1" "$h2" && eq "$calls3" "$calls1" && eq "$calls4" "$calls1" && eq "$calls5" "$calls1"; } \
  && ok || no "run 1 calls>0, run 2 (with state) 0 calls and the same hash, other/garbage/missing state = run 1's calls" "calls=$calls1/$calls2/$calls3/$calls4/$calls5 h1=$h1 h2=$h2 valid=$valid state=$(tr -d "\n " < "$st1" | head -c 700)"

begin "req3-ac3-driver-incomplete-run-leaves-no-usable-state" "the DRIVER (REQ-AUD-3 AC3, Fable ruling on cache#684): a run where a model call ended without a cacheable result (here: every answer is 'unknown' and the narrative is empty) writes a state with NO verdicts, pullability or narrative, so the next run repeats the same calls instead of making zero"
nl() { if [ -s "$LEDGER" ]; then wc -l < "$LEDGER" | tr -d ' '; else echo 0; fi; }
cat > "$WORK/unknown-adj.py" <<'PYA'
import json, os, sys
for line in sys.stdin:
    req = json.loads(line)
    if os.environ.get("AUDITOR_MODEL_LEDGER"):
        open(os.environ["AUDITOR_MODEL_LEDGER"], "a").write("%s|%s|%s\n" % (req.get("finding_id"), req.get("attempt"), req.get("model")))
    print(json.dumps({"refused": False, "category": "unknown", "token_usage": 1}), flush=True)
PYA
drvu() { # drvu OUTDIR [prev-state]
  local o="$1"; shift; local extra=(); [ -n "${1:-}" ] && extra=(--prev-state "$1")
  "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/nc-src/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$WORK/unknown-adj.py" "${extra[@]}" --out "$o" >/dev/null 2>&1; }
u1="$WORK/du1"; u2="$WORK/du2"; rm -rf "$u1" "$u2"
: > "$LEDGER"; drvu "$u1"; ucalls1="$(nl)"; : > "$LEDGER"; ust1="$u1/.auditor/auditor-state.json"
drvu "$u2" "$ust1"; ucalls2="$(nl)"; : > "$LEDGER"
uhollow="$(pj "$ust1" 'len(d["verdicts"])==0 and len(d["pullability"])==0 and d["narrative"] is None' 2>/dev/null)"
{ [ "$ucalls1" -gt 0 ] && eq "$ucalls2" "$ucalls1" && eq "$uhollow" "true"; } \
  && ok || no "run 1 calls>0 and leaves an empty state, run 2 repeats run 1's calls" "calls=$ucalls1/$ucalls2 hollow=$uhollow state=$(tr -d "\n " < "$ust1" 2>/dev/null | cut -c1-200)"

begin "req16-ac2-versioned-prompt-file" "the model's standing instructions are a versioned prompt FILE (public; names no vendor/model); the adjudicator client loads them from the file, not an inline string"
a2="$("$PY" -c "
import importlib.util
spec=importlib.util.spec_from_file_location('c','.github/agent/bin/auditor-adjudicator-client.py'); C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
d=C._load_prompt('disposition'); p=C._load_prompt('pullability'); n=C._load_prompt('narrative')
loaded=bool(d and p and n)
filled=C._fill(d, ask='answer', knowledge='K', context='C')
novendor=not any(w in (d+p+n).lower() for w in ('claude','anthropic','openai','gpt','gemini','bedrock'))
print('OK' if loaded and novendor and 'false_positive' in filled and '{context}' not in filled else 'BAD loaded=%s novendor=%s'%(loaded,novendor))" 2>/dev/null | tail -1)"
inline="$(grep -c 'adjudicator for our own container image. Given this' .github/agent/bin/auditor-adjudicator-client.py 2>/dev/null)"; inline="${inline:-1}"
{ eq "$a2" "OK" && [ -f ".github/agent/prompts/adjudicator.md" ] && [ "$inline" -eq 0 ] 2>/dev/null; } \
  && ok || no "prompts loaded from the versioned file; no inline copy" "$a2 inline=$inline"

begin "req16-ac3-knowledge-doc-generated" "the knowledge document is GENERATED from the structured records (deterministic; a model-proposed row is excluded), never free-written"
a3="$("$PY" -c "
import sys; sys.path.insert(0,'.github/agent/bin')
from auditorlib import knowledge as K
log={'defects':[{'package':'apt','disposition':'false_positive','keys':[{'scanner':'grype','finding_id':'CVE-2011-3374','purl':'pkg:deb/debian/apt@2.6.1'}],'evidence':'apt hardening'},
                {'package':'x','disposition':'proposed','keys':[{'scanner':'grype','finding_id':'CVE-9999-0000','purl':'p'}],'evidence':'model guess'}]}
d1=K.generate(log); d2=K.generate(log)
good=(d1==d2) and ('CVE-2011-3374' in d1) and ('apt' in d1) and ('CVE-9999-0000' not in d1)
print('OK' if good else 'BAD det=%s trusted=%s excl=%s'%(d1==d2,'CVE-2011-3374' in d1,'CVE-9999-0000' not in d1))" 2>/dev/null | tail -1)"
{ eq "$a3" "OK"; } && ok || no "knowledge doc generated, deterministic, excludes proposed rows" "$a3"

begin "req16-ac4-proposals-merge-gated" "a model-proposed defect-log entry is delivered as a PROPOSAL (with evidence), NOT applied: the live known-defect log is byte-unchanged this run and the versioned prompt file is untouched"
o="$WORK/req16-ac4"; rm -rf "$o"; : > "$LEDGER"; d4="$WORK/req16-ac4-src"; rm -rf "$d4"; mkdir -p "$d4"
"$PY" - "$d4" <<'PP'
import json,sys
d=sys.argv[1]
json.dump({"matches":[{"vulnerability":{"id":"CVE-2099-PROPOSE","severity":"Medium","fix":{"state":"not-fixed"}},"artifact":{"purl":"pkg:deb/debian/libpropose@1.0","name":"libpropose"}}]},open(d+"/grype.json","w"))
st={"grype":{"ran":True,"os_package_count":1,"package_count":1,"findings":1,"version":"x","db_date":"d"}}
for s in ("trivy","osv-scanner","osv-scanner-gomod","snyk"): st[s]={"ran":False,"reason":"nr","os_package_count":0,"package_count":0,"findings":0,"version":None,"db_date":None}
json.dump({"defects":[]},open(d+"/log.json","w"))
json.dump({"commit":"c","candidate_digests":{"production":"sha256:x"},"base_os":"debian 12.0","module":None,"govulncheck":None,
           "known_defect_log":d+"/log.json",
           "scanner_reports":{"grype":d+"/grype.json","trivy":None,"osv-scanner":None,"osv-scanner-gomod":None,"snyk":None},"scanner_status":st},open(d+"/manifest.json","w"))
PP
"$PY" "$WORK/g2p.py" "$d4/manifest.json"
cp "$d4/log.json" "$d4/log.before"
cp .github/agent/prompts/adjudicator.md "$d4/prompt.before"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$d4/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || true
prop="$(have "$o/.auditor/proposals/adjudicator-proposals.json" && echo yes || echo no)"
ev="$("$PY" -c 'import json,sys
d=json.load(open(sys.argv[1]))
print("yes" if d.get("proposals") and d["proposals"][0]["propose"].get("evidence") else "no")' "$o/.auditor/proposals/adjudicator-proposals.json" 2>/dev/null)"; ev="${ev:-no}"
logsame="$(cmp -s "$d4/log.json" "$d4/log.before" && echo yes || echo no)"
promptsame="$(cmp -s .github/agent/prompts/adjudicator.md "$d4/prompt.before" && echo yes || echo no)"
{ eq "$prop" "yes" && eq "$ev" "yes" && eq "$logsame" "yes" && eq "$promptsame" "yes"; } \
  && ok || no "proposal delivered w/ evidence; live log + prompt file unchanged" "prop=$prop ev=$ev log=$logsame prompt=$promptsame"

begin "req16-ac5-python-known-model-generalises" "cost split: a KNOWN finding (defect-log hit) makes ZERO model calls; the model is consulted ONLY to generalise the new unique-lineage no-fix suspected FP"
o="$WORK/req16-ac5"; rm -rf "$o"; : > "$LEDGER"; _req16_src "$WORK/req16-ac5-src"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/req16-ac5-src/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || true
known="$(grep -c 'CVE-2099-KNOWN' "$LEDGER" 2>/dev/null)"; known="${known:-0}"     # Python decides -> 0 calls
newc="$(grep -c 'CVE-2099-NEW' "$LEDGER" 2>/dev/null)"; newc="${newc:-0}"           # model generalises -> called
{ [ "$known" -eq 0 ] 2>/dev/null && [ "$newc" -ge 1 ] 2>/dev/null; } \
  && ok || no "known costs 0 model calls; the new suspected FP is the only one consulted" "known=$known new=$newc"

begin "req16-ac4-malformed-proposal-dropped" "a proposal without a recognized kind or without evidence is DROPPED (never forwarded): AC4 requires proposals 'with evidence'"
o="$WORK/req16-badprop"; rm -rf "$o"; : > "$LEDGER"; d="$WORK/req16-badprop-src"; rm -rf "$d"; mkdir -p "$d"
"$PY" - "$d" <<'PP'
import json,sys
d=sys.argv[1]
json.dump({"matches":[{"vulnerability":{"id":"CVE-2099-BADPROP","severity":"Medium","fix":{"state":"not-fixed"}},"artifact":{"purl":"pkg:deb/debian/libbad@1.0","name":"libbad"}}]},open(d+"/grype.json","w"))
st={"grype":{"ran":True,"os_package_count":1,"package_count":1,"findings":1,"version":"x","db_date":"d"}}
for s in ("trivy","osv-scanner","osv-scanner-gomod","snyk"): st[s]={"ran":False,"reason":"nr","os_package_count":0,"package_count":0,"findings":0,"version":None,"db_date":None}
json.dump({"defects":[]},open(d+"/log.json","w"))
json.dump({"commit":"c","candidate_digests":{"production":"sha256:x"},"base_os":"debian 12.0","module":None,"govulncheck":None,"known_defect_log":d+"/log.json","scanner_reports":{"grype":d+"/grype.json","trivy":None,"osv-scanner":None,"osv-scanner-gomod":None,"snyk":None},"scanner_status":st},open(d+"/manifest.json","w"))
PP
"$PY" "$WORK/g2p.py" "$d/manifest.json"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$d/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || true
present="$(have "$o/.auditor/proposals/adjudicator-proposals.json" && echo yes || echo no)"
ran="$(have "$o/report.md" && echo yes || echo no)"   # the run COMPLETED (guards against a crash falsely passing the absence check)
{ eq "$present" "no" && eq "$ran" "yes"; } && ok || no "malformed proposal dropped (run completed; no proposals artifact)" "proposals_present=$present ran=$ran"

begin "req16-ac4-proposals-only-run-still-delivers" "a run that produced ONLY a model proposal (no statements, no removals) still opens the draft PR so the proposal reaches audit-lane review (Codex round-1 P2)"
po="$WORK/req16-po"; rm -rf "$po"; mkdir -p "$po/.auditor/proposals" "$po/suppressions"; posh="$WORK/req16-po.shim"; rm -f "$posh"
printf '{"proposals":[{"finding_id":"CVE-X","propose":{"kind":"defect_log","evidence":"e"}}]}' > "$po/.auditor/proposals/adjudicator-proposals.json"
por="$("$PY" -c "
import importlib.util,os
spec=importlib.util.spec_from_file_location('r','.github/agent/bin/auditor-run.py'); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
os.environ['AUDITOR_GIT_SHIM_LOG']=os.path.join('$WORK','req16-po.shim')
url,err=R._deliver_suppression_pr('$po','$po/suppressions',0,'2026-09-26','deadbeef',False,[],is_test=False)
print('OK' if (url and err is None) else 'BAD url=%r err=%r'%(url,err))" 2>/dev/null | tail -1)"
prc="$(grep -c 'gh pr create --draft' "$posh" 2>/dev/null)"; prc="${prc:-0}"
{ eq "$por" "OK" && [ "$prc" -ge 1 ] 2>/dev/null; } && ok || no "proposals-only run opens the draft PR" "$por pr_create=$prc"

echo "=== REQ-AUD-15 — report structure v2 ==="

begin "req15-ac1-pr-list-at-top" "after the header and before the sections, a 'PRs and issues this run' block lists what was/would be opened"
o="$WORK/r15a"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
  pl="$(grep -nE 'PRs and issues this run' "$o/report.md" | head -1 | cut -d: -f1)"
  s0="$(grep -nE '^## 0\.' "$o/report.md" | head -1 | cut -d: -f1)"
  { [ -n "$pl" ] && [ -n "$s0" ] && [ "$pl" -lt "$s0" ] 2>/dev/null; } \
    && ok || no "PR/issue list appears before §0" "prlist=$pl sec0=$s0"; }

begin "req15-ac2-section0-needs-a-human" "§0 Needs a human is present; a run with nothing waiting says so in one sentence"
{ grep -qE '^## 0\. Needs a human' "$o/report.md" && grep -qi 'nothing needs a human this run' "$o/report.md"; } \
  && ok || no "§0 present + empty sentence" "$(grep -m1 -E '^## 0' "$o/report.md")"

begin "req15-ac8-section6-7-removed" "the old §6 (Pending) and §7 (Currently suppressed) headings are removed"
{ ! grep -qE '^## 6\.|^## 7\.' "$o/report.md" && ! grep -qi 'Currently suppressed' "$o/report.md"; } \
  && ok || no "no §6/§7 headings" "$(grep -nE '^## 6\.|^## 7\.|Currently suppressed' "$o/report.md" | head -1)"

begin "req15-ac5-section3-os-vs-sca-with-actions" "§3 splits into 3A (OS/base) and 3B (SCA/libraries)"
{ grep -qE '3A' "$o/report.md" && grep -qE '3B' "$o/report.md"; } \
  && ok || no "§3 has 3A and 3B subsections" "3A=$(grep -c '3A' "$o/report.md") 3B=$(grep -c '3B' "$o/report.md")"

begin "req15-ac7-section5-reachable-vs-fp-with-tags" "§5 splits into 5A (not reachable) / 5B (false positive) and a §5 VEX row carries a status tag"
# manifest-01 closes CVE-2011-3374 as a known-defect-log false positive -> §5B
fp="$(sed -n '/^## 5\./,/^## /p' "$o/report.md")"
{ printf '%s' "$fp" | grep -qE '5B' && printf '%s' "$fp" | grep -qE 'proposed, not delivered \(dry run\)|in force \(main\)'; } \
  && ok || no "§5 has 5B and a status tag" "$(printf '%s' "$fp" | grep -m1 CVE-2011-3374)"

begin "req15-ac9-status-tag-on-vex-rows" "on a dry candidate run every VEX-backed row is tagged 'proposed, not delivered (dry run)'"
tags="$(grep -c 'proposed, not delivered (dry run)' "$o/report.md" 2>/dev/null)"; tags="${tags:-0}"
{ [ "$tags" -ge 1 ] 2>/dev/null; } && ok || no "dry-run status tag present" "tags=$tags"

begin "req15-ac9-vex-link-only-for-in-force" "the fosterstack.com VEX link is printed ONLY for in-force rows; a proposed/not-delivered row shows the statement id without the published link (AC9)"
o2b="$WORK/r15link"; rm -rf "$o2b"
"$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-testimage.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o2b" >/dev/null 2>&1 || true
liveurl="$(grep -c 'vex: `https://fosterstack.com' "$o2b/report.md" 2>/dev/null)"; liveurl="${liveurl:-0}"
idfrag="$(grep -c 'vex: `#stmt-' "$o2b/report.md" 2>/dev/null)"; idfrag="${idfrag:-0}"
{ eq "$liveurl" "0" && [ "$idfrag" -ge 1 ] 2>/dev/null; } \
  && ok || no "no published link on proposed rows; statement id shown" "live_links=$liveurl id_fragments=$idfrag"

begin "req15-ac9-test-image-tag-and-forces-dry" "a test-image run tags every VEX row 'proposed, not delivered (test image)' regardless of main, and forces dry_run even when --dry-run false"
o2="$WORK/r15ti"; rm -rf "$o2"
"$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-testimage.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o2" >/dev/null 2>&1 || true
ti="$(grep -c 'proposed, not delivered (test image)' "$o2/report.md" 2>/dev/null)"; ti="${ti:-0}"
forced="$(grep -c '\*\*dry_run:\*\* yes' "$o2/report.md" 2>/dev/null)"; forced="${forced:-0}"
{ [ "$ti" -ge 1 ] 2>/dev/null && [ "$forced" -ge 1 ] 2>/dev/null; } \
  && ok || no "test-image tag + forced dry" "test_image_tags=$ti forced_dry=$forced"

begin "req15-ac2-section0-unassessed-owner-issue-not-threshold-gated" "§0 lists a genuinely-open owner-decision issue for a §4 unassessed-after-fallback finding even though it carries no 'threshold' (AC2; the §0 filter must not gate on threshold, which only the §2 branch sets)"
s0r="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
rr=[{"id":"CVE-UNASS","section":4,"disposition":"under investigation","action":"escalated to owner-decision issue","reason":"unassessed after fallback","package":"lib","installed":"1","fixed":None,"severity":"High","owner_issue":"#77"}]
sections[4]=rr
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,rr,sections,[],"AUDIT COMPLETE",False,"stub",{},"h","c",None,None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
s0=rep.split("## 0. Needs a human")[1].split("## 1.")[0]
print("OK" if ("CVE-UNASS" in s0 and "#77" in s0) else "BAD:%r"%s0)' 2>/dev/null | tail -1)"
{ eq "$s0r" "OK"; } && ok || no "§0 includes the unassessed owner issue (no threshold gate)" "$s0r"

begin "req15-ac9-failed-delivery-not-in-force" "a freshly-written statement whose suppression PR delivery FAILED is tagged 'proposed, not delivered', never 'in force (main)', and shows no published fosterstack.com link (AC9)"
fdr="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
row={"id":"CVE-FAIL","section":5,"disposition":"not_affected (false positive)","action":"closed","reason":"model FP","package":"lib","installed":"1","fixed":None,"severity":"High","reachability":"n/a","vex_id":"https://fosterstack.com/vex/x#stmt-abc","carried":False}
sections[5]=[row]
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,[],sections,[],"AUDIT INCOMPLETE",False,"stub",{},"h","c",None,"git push failed",{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
s5=rep.split("## 5.")[1]
good=("proposed, not delivered" in s5) and ("in force (main)" not in s5) and ("fosterstack.com" not in s5) and ("vex: `#stmt-abc`" in s5)
print("OK" if good else "BAD:%r"%s5)' 2>/dev/null | tail -1)"
{ eq "$fdr" "OK"; } && ok || no "failed delivery is not in force and drops the published link" "$fdr"

begin "req15-ac9-carried-section5-threads-carried" "the §5 (not_affected) disposition threads the carried flag like §2, so a byte-identical statement already in force on main is tagged 'in force (main)', not 'proposed (PR #N)'"
g5="$WORK/req15-carr5"; rm -rf "$g5"; mkdir -p "$g5"
gv5="$g5/gvc.json"
printf '%s\n%s\n%s\n' '{"config":{"scan_level":"symbol"}}' '{"SBOM":{"roots":["example.org/lib"],"modules":[{"path":"example.org/lib","version":"v1.0.0"}]}}' '{"finding":{"osv":"GO-2099-7701","trace":[{"module":"example.org/lib","package":"example.org/lib/unused"}]}}' > "$gv5"
c5r="$("$PY" -c '
import sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sys.path.insert(0,".github/agent/bin"); from auditorlib import policy
purl="pkg:golang/example.org/lib@v1.0.0"; sc=((policy.VEX_PRODUCT,),(purl,))
env={"gvc":sys.argv[1],"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":sys.argv[2],"ts":"2026-09-24T00:00:00Z","dry":True,"digest":"sha256:x",
     "carried_expiry":{},"today":"2026-09-24","carried_scopes":{("CVE-2099-7701",sc)},
     "carried_status":{("CVE-2099-7701",sc):"not_affected"}}
f={"scanner":"osv-scanner-gomod","finding_id":"GO-2099-7701","purl":purl,"aliases":["GO-2099-7701","CVE-2099-7701"],"package":"example.org/lib","fixed_version":None,"severity":"High","extra":{}}
row,_=R._dispose("CVE-2099-7701",[f],["CVE-2099-7701","GO-2099-7701"],env,[])
print("OK" if row["section"]==5 and row.get("carried") is True else "BAD:sec=%s carried=%s"%(row["section"],row.get("carried")))' "$gv5" "$g5/out" 2>/dev/null | tail -1)"
{ eq "$c5r" "OK"; } && ok || no "§5 threads carried (in-force, not re-proposed)" "$c5r"

begin "req15-ac5-section3-splits-by-ecosystem-not-delivery-flag" "§3 3A/3B keys on ecosystem: an OS row with no base_rebuild flag (an expired OS acceptance reopened into §3) still renders under 3A, and a Go/library row renders under 3B"
e3r="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
sections[3]=[
 {"id":"CVE-OSREOPEN","section":3,"disposition":"reopened: prior acceptance expired","action":"time box lapsed","reason":"expired","package":"libssl","installed":"1","fixed":None,"severity":"High","reachability":"n/a (OS package)","is_os":True},
 {"id":"CVE-GOLIB","section":3,"disposition":"real, fixable (we build it)","action":"bump pending","reason":"pullable","package":"example.org/lib","installed":"1","fixed":"1.1","severity":"High","reachability":"govulncheck: reachable","is_os":False}]
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,[],sections,[],"AUDIT COMPLETE",True,"stub",{},"h","c",None,None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
s3=rep.split("## 3.")[1].split("## 4.")[0]
a=s3.split("3B")[0]; b=s3.split("3B")[1]
print("OK" if ("CVE-OSREOPEN" in a and "CVE-GOLIB" in b and "CVE-GOLIB" not in a) else "BAD a=%r b=%r"%(a,b))' 2>/dev/null | tail -1)"
{ eq "$e3r" "OK"; } && ok || no "§3 3A/3B split by ecosystem, not the base_rebuild flag" "$e3r"

begin "req15-ac1-dry-owner-issue-not-double-counted" "in a dry run the PR/issue list represents a would-be owner issue exactly once (the 'would open' entry), never also as a sentinel 'owner-decision issue: … (dry)' row"
ddr="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
rr=[{"id":"CVE-POAM","section":2,"disposition":"carried (POA&M)","action":"POA&M","reason":"no fix; critical","package":"lib","installed":"1","fixed":None,"severity":"Critical","vex_id":"#stmt-z","threshold":"at_or_above","owner_issue":"dry"}]
sections[2]=rr
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
would=["gh issue create --title owner-decision-CVE-POAM --label owner-decision --assignee owner"]
rep=R._render(m,rr,sections,would,"AUDIT COMPLETE",True,"stub",{},"h","c",None,None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
pl=rep.split("## PRs and issues this run")[1].split("## 0.")[0]
dupes=pl.count("owner-decision issue: CVE-POAM (dry)")
would_n=pl.count("would open (dry run)")
print("OK" if dupes==0 and would_n>=1 else "BAD dupes=%d would=%d pl=%r"%(dupes,would_n,pl))' 2>/dev/null | tail -1)"
{ eq "$ddr" "OK"; } && ok || no "dry owner issue not double-counted in the PR list" "$ddr"

begin "req15-ac2-section0-excludes-dry-sentinel" "§0 does NOT present a dry-run sentinel owner ref as real human work (no 'owner-decision needed: … — dry'); the dry preview lives in the PR list's 'would open' (Codex/Sonnet round-2 blocker)"
sdr="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
rr=[{"id":"CVE-DRYSENT","section":2,"disposition":"carried (POA&M)","action":"POA&M","reason":"no fix","package":"lib","installed":"1","fixed":None,"severity":"Critical","vex_id":"#stmt-z","threshold":"at_or_above","owner_issue":"dry"}]
sections[2]=rr
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
would=["gh issue create --title owner-CVE-DRYSENT --label owner-decision --assignee owner"]
rep=R._render(m,rr,sections,would,"AUDIT COMPLETE",True,"stub",{},"h","c",None,None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
s0=rep.split("## 0. Needs a human")[1].split("## 1.")[0]
print("OK" if ("— dry" not in s0 and "CVE-DRYSENT" not in s0) else "BAD:%r"%s0)' 2>/dev/null | tail -1)"
{ eq "$sdr" "OK"; } && ok || no "§0 excludes the dry sentinel" "$sdr"

begin "req15-poam-row-names-real-ignores" "a §2 POA&M row names the exception it actually relies on (the VEX, the only one there is); _row_line never falls back to 'ignores: none' for an accepted-risk row (Codex round-2 blocker)"
pir="$("$PY" -c '
import sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":sys.argv[1],"ts":"2026-09-24T00:00:00Z","dry":True,"digest":"sha256:x","carried_expiry":{},"today":"2026-09-24"}
def f(sc): return {"scanner":sc,"finding_id":"CVE-2099-4141","purl":"pkg:deb/debian/lib@1","aliases":["CVE-2099-4141"],"package":"lib","fixed_version":None,"severity":"Critical","extra":{}}
row,_=R._dispose("CVE-2099-4141",[f("grype"),f("google")],["CVE-2099-4141"],env,[])
line=R._row_line(row)
good=(row["section"]==2 and row.get("ignore_files")==["vex"] and "ignores: none" not in line and "ignores: vex" in line)
print("OK" if good else "BAD sec=%s ig=%s line=%r"%(row["section"],row.get("ignore_files"),line))' "$WORK/req15-poamig" 2>/dev/null | tail -1)"
{ eq "$pir" "OK"; } && ok || no "§2 row names the VEX as its exception (not 'none')" "$pir"

begin "req15-carried-status-mismatch-not-in-force" "the display 'carried' flag is set only when THIS run writes the SAME disposition already on main: a scope published as 'affected' but re-dispositioned 'not_affected' this run (new unreachability) is NOT 'in force (main)' (Codex round-2 residual #3)"
gsm="$WORK/req15-statusmm"; rm -rf "$gsm"; mkdir -p "$gsm"
gvm="$gsm/gvc.json"
printf '%s\n%s\n%s\n' '{"config":{"scan_level":"symbol"}}' '{"SBOM":{"roots":["example.org/lib"],"modules":[{"path":"example.org/lib","version":"v1.0.0"}]}}' '{"finding":{"osv":"GO-2099-6601","trace":[{"module":"example.org/lib","package":"example.org/lib/unused"}]}}' > "$gvm"
smr="$("$PY" -c '
import sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sys.path.insert(0,".github/agent/bin"); from auditorlib import policy
purl="pkg:golang/example.org/lib@v1.0.0"; sc=((policy.VEX_PRODUCT,),(purl,))
env={"gvc":sys.argv[1],"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":sys.argv[2],"ts":"2026-09-24T00:00:00Z","dry":True,"digest":"sha256:x",
     "carried_expiry":{},"today":"2026-09-24","carried_scopes":{("CVE-2099-6601",sc)},"carried_status":{("CVE-2099-6601",sc):"affected"}}
f={"scanner":"osv-scanner-gomod","finding_id":"GO-2099-6601","purl":purl,"aliases":["GO-2099-6601","CVE-2099-6601"],"package":"example.org/lib","fixed_version":None,"severity":"High","extra":{}}
row,_=R._dispose("CVE-2099-6601",[f],["CVE-2099-6601","GO-2099-6601"],env,[])
print("OK" if row["section"]==5 and row.get("carried") is False else "BAD:sec=%s carried=%s"%(row["section"],row.get("carried")))' "$gvm" "$gsm/out" 2>/dev/null | tail -1)"
{ eq "$smr" "OK"; } && ok || no "carried display flag requires a matching published disposition" "$smr"

begin "req15-pr-list-keeps-skipped-sentinel" "the 'skipped' owner ref (a real run with gh disabled — no 'would open' line exists for it) stays visible in the PR/issue list rather than being dropped (Sonnet round-2 residual B)"
skr="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
rr=[{"id":"CVE-SKIP","section":2,"disposition":"carried (POA&M)","action":"POA&M","reason":"no fix","package":"lib","installed":"1","fixed":None,"severity":"Critical","vex_id":"#stmt-z","threshold":"at_or_above","owner_issue":"skipped"}]
sections[2]=rr
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,rr,sections,[],"AUDIT COMPLETE",False,"stub",{},"h","c",None,None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
pl=rep.split("## PRs and issues this run")[1].split("## 0.")[0]
print("OK" if "owner-decision issue: skipped — lib — CVEs: CVE-SKIP" in pl else "BAD:%r"%pl)' 2>/dev/null | tail -1)"
{ eq "$skr" "OK"; } && ok || no "PR list keeps the skipped sentinel" "$skr"

begin "req15-tag-carried-in-force-even-in-dry" "an already-in-force (carried) statement is tagged 'in force (main)' even on a dry run — a dry run changes nothing on main, so carried is checked before dry (Sonnet round-2 residual D)"
cdr="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
rr=[{"id":"CVE-CARR","section":5,"disposition":"not_affected (unreachable)","action":"closed","reason":"unreachable","package":"lib","installed":"1","fixed":None,"severity":"High","reachability":"govulncheck: unreachable","vex_id":"https://fosterstack.com/vex/x#stmt-c","carried":True}]
sections[5]=rr
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,rr,sections,[],"AUDIT COMPLETE",True,"stub",{},"h","c",None,None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
s5=rep.split("## 5.")[1]
good=("in force (main)" in s5) and ("proposed, not delivered (dry run)" not in s5) and ("vex: `https://fosterstack.com" in s5)
print("OK" if good else "BAD:%r"%s5)' 2>/dev/null | tail -1)"
{ eq "$cdr" "OK"; } && ok || no "carried row is in-force even in a dry run" "$cdr"

begin "req15-section1-tag-names-bump-pr" "a §1 lifted row's status tag names its OWN bump PR (fix_pr_url), not the suppression PR — the tag never contradicts the PR number in the row's action text (Sonnet round-2 residual C)"
s1r="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
rr=[{"id":"CVE-LIFT","section":1,"disposition":"lifted (fix now pullable)","action":"bump delivered: https://github.com/o/r/pull/55","reason":"pullable","package":"example.org/lib","installed":"1","fixed":"1.1","severity":"High","fix_pr_url":"https://github.com/o/r/pull/55"}]
sections[1]=rr
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,rr,sections,[],"AUDIT COMPLETE",False,"stub",{},"h","c","https://github.com/o/r/pull/99",None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
s1=rep.split("## 1. Lifted")[1].split("## 2.")[0]
print("OK" if ("proposed (PR #55)" in s1 and "#99" not in s1) else "BAD:%r"%s1)' 2>/dev/null | tail -1)"
{ eq "$s1r" "OK"; } && ok || no "§1 tag names the bump PR, not the suppression PR" "$s1r"

begin "req15-dry-owner-action-not-falsely-opened" "on a DRY run an at-threshold §2 POA&M row's action says the owner issue 'would open (dry run)', never 'opened/updated (issues:write)' — the row must not contradict the PR list's 'would open' (Codex round-3 blocker)"
dat="$WORK/req15-dryact"; rm -rf "$dat"; mkdir -p "$dat"
"$PY" - "$dat" <<'PP'
import json,os,sys
d=sys.argv[1]
# one Critical, no-fix OS finding reported by grype AND snyk (distinct lineages -> no FP
# suspicion -> §2 POA&M; Critical -> at/above threshold -> risk-acceptance owner issue)
json.dump({"matches":[{"vulnerability":{"id":"CVE-2099-9001","severity":"Critical","fix":{"state":"not-fixed"}},
                       "artifact":{"purl":"pkg:deb/debian/lib@1","name":"lib"}}]}, open(os.path.join(d,"grype.json"),"w"))
json.dump({"vulnerabilities":[{"id":"SNYK-LIB-1","packageName":"lib","purl":"pkg:deb/debian/lib@1",
                               "severity":"critical","identifiers":{"CVE":["CVE-2099-9001"]}}]}, open(os.path.join(d,"snyk.json"),"w"))
st={s:{"ran":True,"os_package_count":1,"package_count":1,"findings":1,"version":"x","db_date":"d"} for s in ("grype","snyk")}
for s in ("trivy","osv-scanner","osv-scanner-gomod"):
    st[s]={"ran":False,"reason":"not run in this fixture","os_package_count":0,"package_count":0,"findings":0,"version":None,"db_date":None}
man={"commit":"deadbeef","candidate_digests":{"production":"sha256:abc"},"base_os":"debian 12.0",
     "module":None,"govulncheck":None,
     "scanner_reports":{"grype":os.path.join(d,"grype.json"),"snyk":os.path.join(d,"snyk.json"),
                        "trivy":None,"osv-scanner":None,"osv-scanner-gomod":None},
     "scanner_status":st}
json.dump(man,open(os.path.join(d,"manifest.json"),"w"))
PP
"$PY" "$WORK/g2p.py" "$dat/manifest.json"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$dat/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$dat/out" >/dev/null 2>&1 || true
falseopen="$(grep -c 'opened/updated (issues:write)' "$dat/out/report.md" 2>/dev/null)"; falseopen="${falseopen:-1}"
wouldact="$(grep -c 'owner-decision issue would open (dry run)' "$dat/out/report.md" 2>/dev/null)"; wouldact="${wouldact:-0}"
poam="$(grep -c 'carried (POA&M)' "$dat/out/report.md" 2>/dev/null)"; poam="${poam:-0}"
{ eq "$falseopen" "0" && [ "$wouldact" -ge 1 ] 2>/dev/null && [ "$poam" -ge 1 ] 2>/dev/null; } \
  && ok || no "dry owner action says 'would open', never 'opened'" "false_opened=$falseopen would_action=$wouldact poam=$poam"

begin "req15-pr-list-distinct-skipped-not-collapsed" "two DISTINCT CVEs whose owner issues were 'skipped' (gh disabled) each get their own PR-list line — the shared 'skipped' sentinel does not collapse them into one (Codex round-3 P3)"
csr="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sections={n:[] for n in range(1,8)}
rr=[{"id":"CVE-AAA","section":2,"disposition":"carried (POA&M)","action":"POA&M","reason":"x","package":"a","installed":"1","fixed":None,"severity":"Critical","vex_id":"#stmt-a","threshold":"at_or_above","owner_issue":"skipped"},
    {"id":"CVE-BBB","section":2,"disposition":"carried (POA&M)","action":"POA&M","reason":"x","package":"b","installed":"1","fixed":None,"severity":"Critical","vex_id":"#stmt-b","threshold":"at_or_above","owner_issue":"skipped"}]
sections[2]=rr
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,rr,sections,[],"AUDIT COMPLETE",False,"stub",{},"h","c",None,None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
pl=rep.split("## PRs and issues this run")[1].split("## 0.")[0]
print("OK" if ("owner-decision issue: skipped — a — CVEs: CVE-AAA" in pl and "owner-decision issue: skipped — b — CVEs: CVE-BBB" in pl) else "BAD:%r"%pl)' 2>/dev/null | tail -1)"
{ eq "$csr" "OK"; } && ok || no "distinct skipped owner items each listed" "$csr"

echo "=== REQ-AUD-18 engineering hygiene ==="
begin "req18-ac1-everything-under-agent" "the layout check passes the real tree and FAILS an auditor-named path or a file referring to .github/agent/ outside it; workflows, the allowlist, the generated outputs, the two traceability files (amendment, owner Oct 2) and the patch-release classifier with its test (amendment, owner Oct 3) are the only exemptions"
LC="$repo/$BIN/auditor-layout-check.py"
git ls-files 2>/dev/null | "$PY" "$LC" >/dev/null 2>&1; real=$?
lr="$WORK/req18-ac1"; rm -rf "$lr"; mkdir -p "$lr/docs"; printf 'see .github/agent/bin/auditor-run.py\n' > "$lr/docs/notes.md"; printf 'plain\n' > "$lr/docs/other.md"
printf 'bin/auditor-new.sh\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; named=$?
printf 'docs/notes.md\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; refers=$?
mkdir -p "$lr/.auditor/proposals" "$lr/.vex"; printf '{}' > "$lr/.auditor/accepted-items.json"; printf '{"id":1}' > "$lr/.auditor/proposals/p1.json"
printf '.github/workflows/auditor.yml\nbin/check-file-allowlist.sh\n.auditor/accepted-items.json\n.auditor/proposals/p1.json\n.github/agent/tests/x.sh\ndocs/other.md\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; exempt=$?
# auditor code smuggled into the output locations (Codex round-1 blocker): a non-contract name
# under .vex/ or .auditor/, or a contract .json path that is not JSON, fails.
cp "$repo/$BIN/auditor-report.py" "$lr/.vex/auditor-helper.md"; cp "$repo/$BIN/auditor-report.py" "$lr/.auditor/proposals/p2.json"
printf '.vex/auditor-helper.md\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; smug1=$?
printf '.auditor/proposals/p2.json\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; smug2=$?
old="$(git ls-files 'bin/auditor-*' 'docs/quality/cve-auditor-*' 2>/dev/null | wc -l | tr -d ' ')"
# the REQ-AUD-18 AC1 amendment (owner, Oct 2): the two traceability files may name auditor test paths; no other
# test-evidence file may
mkdir -p "$lr/test-evidence"; for f in mappings unmapped other; do printf 'ref: .github/agent/bin/tests/test_x.py\n' > "$lr/test-evidence/$f.yaml"; done
printf 'test-evidence/mappings.yaml\ntest-evidence/unmapped.yaml\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; trace=$?
printf 'test-evidence/other.yaml\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; trace_other=$?
# the second amendment (owner, Oct 3): the patch-release classifier and its test name the auditor directory as data;
# exactly those two paths — a look-alike next to them still fails
mkdir -p "$lr/bin"; for f in patch-decide.py patch-decide-test.sh patch-decide2.py; do printf 'NEUTRAL = (".github/agent/reviews/",)\n' > "$lr/bin/$f"; done
printf 'bin/patch-decide.py\nbin/patch-decide-test.sh\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; patchx=$?
printf 'bin/patch-decide2.py\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; patch_other=$?
# a whitespace look-alike is another file: git ls-files lists it verbatim and the check reads it verbatim (Codex r1 B1)
for f in "patch-decide.py " "patch-decide-test.sh "; do printf 'NEUTRAL = (".github/agent/reviews/",)\n' > "$lr/bin/$f"; done
printf 'bin/patch-decide.py \n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; ws1=$?
printf 'bin/patch-decide-test.sh \n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; ws2=$?
mkdir -p "$lr/ bin"; printf 'NEUTRAL = (".github/agent/reviews/",)\n' > "$lr/ bin/patch-decide.py"
printf ' bin/patch-decide.py\n' | "$PY" "$LC" --root "$lr" >/dev/null 2>&1; ws3=$?
{ eq "$real" "0" && eq "$named" "1" && eq "$refers" "1" && eq "$exempt" "0" && eq "$smug1" "1" && eq "$smug2" "1" && eq "$old" "0" \
  && eq "$trace" "0" && eq "$trace_other" "1" && eq "$patchx" "0" && eq "$patch_other" "1" \
  && eq "$ws1" "1" && eq "$ws2" "1" && eq "$ws3" "1"; } \
  && ok || no "real tree clean; auditor-named / .github/agent-referring files outside it fail; only the exact output contract is exempt" "real=$real named=$named refers=$refers exempt=$exempt smuggled_vex=$smug1 smuggled_proposal=$smug2 old_paths=$old trace=$trace trace_other=$trace_other patch_classifier=$patchx patch_lookalike=$patch_other whitespace=$ws1/$ws2/$ws3"

begin "req18-ac1-suites-wired-into-required-allowlist-job" "ci.yml's required 'allowlist' job runs the layout check, the parser tests and the matrix suite from .github/agent/tests/"
hy="$(python3 - <<'HH'
import sys; sys.path.insert(0,".github/agent/fixtures/testlib")
import pyyaml as yaml  # the vendored reader — never whatever PyYAML the host happens to have
d=yaml.safe_load(open(".github/workflows/ci.yml")); j=d["jobs"]["allowlist"]
st=j["steps"]; runs=[x.get("run","") for x in st]
ok=(j.get("name")=="allowlist" and any("auditor-layout-check.py" in r for r in runs)
    and any(".github/agent/tests/auditor-matrix-test.sh" in r for r in runs)
    and any(".github/agent/tests/auditor-parser-tests.sh" in r for r in runs)
    and not any(("continue-on-error" in x) or ("if" in x) for x in st if "auditor-" in x.get("run","")))
print("OK" if ok else "BAD")
HH
)"
eq "$hy" "OK" && ok || no "layout check + suites, unconditional, in the required allowlist job" "$hy"

begin "req18-ac2-python-100pct-coverage-gate" "the required 'coverage' job runs the auditor Python gate unconditionally with the hash-pinned tool; the checker fails any uncovered statement, and any exclusion that is reasonless, stale, or hides executed code"
cg="$(python3 - <<'CC'
import sys; sys.path.insert(0,".github/agent/fixtures/testlib")
import pyyaml as yaml
j=yaml.safe_load(open(".github/workflows/ci.yml"))["jobs"]["coverage"]
g=[x for x in j["steps"] if ".github/agent/tests/coverage-gate.sh" in x.get("run","")]
ok=(j.get("name")=="coverage" and len(g)==1 and "--require-hashes" in g[0]["run"]
    and ".github/agent/coverage-requirements.txt" in g[0]["run"]
    and "if" not in g[0] and "continue-on-error" not in g[0])
print("OK" if ok else "BAD")
CC
)"
cd2="$WORK/req18-ac2"; rm -rf "$cd2"; mkdir -p "$cd2"
"$PY" - "$cd2" <<'CJ'
import json,os,sys
d=sys.argv[1]
def cov(name,ex,miss): json.dump({"files":{"m.py":{"executed_lines":ex,"missing_lines":miss}}},open(os.path.join(d,name),"w"))
cov("full.json",[1,2,3],[]); cov("gap.json",[1,2],[3]); cov("empty.json",[],[])
json.dump({"files":{"m.py":{"executed_lines":[1,2],"missing_lines":[],"excluded_lines":[3]}}},open(os.path.join(d,"pragma.json"),"w"))
for n,t in {"none.txt":"# none\n","ok.txt":"m.py:3-3  needs the real endpoint\n","wide.txt":"m.py:2-3  too wide\n",
            "stale.txt":"m.py:1-1  nothing missing here\n","noreason.txt":"m.py:3-3\n",
            "globok.txt":".github/agent/x/hidden.py  test double\n","globwide.txt":".github/agent/x/meas.py  test double\n",
            "globbed.txt":".github/agent/x/*.py  test double\n"}.items():
    open(os.path.join(d,n),"w").write(t)
open(os.path.join(d,"inv.txt"),"w").write("m.py\n")
open(os.path.join(d,"inv-omit.txt"),"w").write("m.py\n.github/agent/x/hidden.py\n")
json.dump({"files":{"m.py":{"executed_lines":[1],"missing_lines":[]},".github/agent/x/meas.py":{"executed_lines":[1],"missing_lines":[]}}},open(os.path.join(d,"measured.json"),"w"))
open(os.path.join(d,"inv-meas.txt"),"w").write("m.py\n.github/agent/x/meas.py\n")
CJ
CK="$repo/.github/agent/tests/coverage-check.py"
cc(){ ( cd "$cd2" && "$PY" "$CK" "$1" "$2" --inventory "${3:-inv.txt}" >/dev/null 2>&1 ); echo $?; }
full="$(cc full.json none.txt)"; gap="$(cc gap.json none.txt)"; excl="$(cc gap.json ok.txt)"; wide="$(cc gap.json wide.txt)"
stale="$(cc full.json stale.txt)"; noreason="$(cc gap.json noreason.txt)"; empty="$(cc empty.json none.txt)"; pragma="$(cc pragma.json none.txt)"
# a tracked file the report never mentions (e.g. dropped by a widened `omit`) fails unless a reasoned
# whole-file entry names it; an entry over a MEASURED file fails (Codex + Sonnet AC2 round-3 blocker)
omitted="$(cc full.json none.txt inv-omit.txt)"; globok="$(cc full.json globok.txt inv-omit.txt)"; globwide="$(cc measured.json globwide.txt inv-meas.txt)"
globbed="$(cc full.json globbed.txt inv-omit.txt)"   # a directory glob is refused: each file its own line (Sonnet AC2 round-4 blocker)
# end to end: the real gate config must not honour an inline "pragma: no cover" (Codex AC2 round-2 blocker)
pg="$WORK/req18-ac2-pragma"; rm -rf "$pg"; mkdir -p "$pg/bin"
printf 'def f(x):\n    if x:\n        return 1  # pragma: no cover\n    return 0\nf(0)\n' > "$pg/bin/m.py"
sed -n '/^\[run\]/,/^EOF$/p' "$repo/.github/agent/tests/coverage-gate.sh" | sed '$d' | sed "s#\$PWD/.github/agent/bin#$pg/bin#; s#\$W/.coverage#$pg/.coverage#; /^omit/d" > "$pg/rc"
if "$PY" -c 'import coverage' 2>/dev/null; then   # the gate's own job has it; the plain suite job may not
  e2e="$( cd "$pg" && export -n COVERAGE_PROCESS_START COVERAGE_RCFILE; unset COVERAGE_PROCESS_START
    COVERAGE_RCFILE="$pg/rc" "$PY" -m coverage run bin/m.py >/dev/null 2>&1 \
    && COVERAGE_RCFILE="$pg/rc" "$PY" -m coverage json -q -o "$pg/c.json" >/dev/null 2>&1 \
    && "$PY" -c 'import json,sys; f=list(json.load(open(sys.argv[1]))["files"].values())[0]; print("counted" if 3 in f["missing_lines"] and not f["excluded_lines"] else "honoured")' "$pg/c.json" \
    || echo "error")"
else e2e="no-coverage-module"; fi
{ eq "$cg" "OK" && eq "$full" "0" && eq "$gap" "1" && eq "$excl" "0" && eq "$wide" "1" && eq "$stale" "1" && eq "$noreason" "1" && eq "$empty" "1" && eq "$pragma" "1" && eq "$omitted" "1" && eq "$globok" "0" && eq "$globwide" "1" && eq "$globbed" "1" \
  && { eq "$e2e" "counted" || eq "$e2e" "no-coverage-module"; }; } \
  && ok || no "wired + full=0 gap=1 excluded=0 wide=1 stale=1 reasonless=1 empty=1 pragma=1 omitted=1 glob-ok=0 entry-over-measured=1 glob-refused=1 gate-config-counts-pragma" "wiring=$cg full=$full gap=$gap excluded=$excl wide=$wide stale=$stale reasonless=$noreason empty=$empty pragma=$pragma omitted=$omitted glob_ok=$globok glob_wide=$globwide globbed=$globbed e2e=$e2e"

begin "req18-ac2-identity-claims-logging-stubbed" "the workflow's OIDC step (run under node with a stub core + crafted token) logs EXACTLY the seven federation-rule claims — never the token, never another claim — masks and writes the token; a malformed token warns and does not throw"
ic="$WORK/req18-idc"; rm -rf "$ic"; mkdir -p "$ic/rt" "$ic/rt-bad"
python3 - "$ic/oidc.js" <<'IC'
import sys; sys.path.insert(0,".github/agent/fixtures/testlib")
import pyyaml as yaml
st=[s for j in yaml.safe_load(open(".github/workflows/auditor.yml"))["jobs"].values() for s in j.get("steps",[]) if s.get("id")=="oidc"]
open(sys.argv[1],"w").write(st[0]["with"]["script"] if len(st)==1 else "")
IC
cat > "$ic/run.js" <<'JS'
const fs = require('fs'); const src = fs.readFileSync(process.argv[2], 'utf8'); const tok = process.argv[3];
const log = {aud: null, info: [], warning: [], secret: [], exported: {}};
const core = {getIDToken: async a => { log.aud = a; return tok }, setSecret: t => log.secret.push(t),
  exportVariable: (k, v) => { log.exported[k] = v }, info: m => log.info.push(m), warning: m => log.warning.push(String(m))};
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
(async () => { await new AsyncFunction('core', 'require', src)(core, require); console.log(JSON.stringify(log)) })()
  .catch(e => { console.error(String(e)); process.exit(1) });
JS
b64(){ printf '%s' "$1" | base64 | tr -d '=\n' | tr '/+' '_-'; }
claims='{"sub":"repo:o/r:environment:agent","aud":"https://api.anthropic.com","ref":"refs/heads/main","job_workflow_ref":"o/r/.github/workflows/auditor.yml@refs/heads/main","environment":"agent","repository":"o/r","repository_owner_id":"42","jti":"XNEVERLOGX","iss":"https://token.actions.githubusercontent.com"}'
tok="$(b64 '{"alg":"RS256"}').$(b64 "$claims").SIGNATUREXYZ"
good="$(RUNNER_TEMP="$ic/rt" node "$ic/run.js" "$ic/oidc.js" "$tok" 2>&1)"; rcg=$?
bad="$(RUNNER_TEMP="$ic/rt-bad" node "$ic/run.js" "$ic/oidc.js" "not-a-jwt" 2>&1)"; rcb=$?
idv="$(python3 - "$good" "$bad" "$tok" "$ic/rt" <<'IV'
import json,sys
try:
    g=json.loads(sys.argv[1]); b=json.loads(sys.argv[2]); tok=sys.argv[3]; rt=sys.argv[4]
except Exception as e:
    print("BAD parse %s"%e); sys.exit()
want={"sub":"repo:o/r:environment:agent","aud":"https://api.anthropic.com","ref":"refs/heads/main","job_workflow_ref":"o/r/.github/workflows/auditor.yml@refs/heads/main","environment":"agent","repository":"o/r","repository_owner_id":"42"}
pre="OIDC identity claims (federation-rule inputs): "
info=[m for m in g["info"] if m.startswith(pre)]
# the COMPLETE info log is exactly that one line — nothing else may be logged (Codex AC2 round-2 residual)
logged=json.loads(info[0][len(pre):]) if len(info)==1 and len(g["info"])==1 else None
alltext=json.dumps(g["info"]+g["warning"])
fp=g["exported"].get("ANTHROPIC_IDENTITY_TOKEN_FILE")
ok=(g["aud"]=="https://api.anthropic.com" and logged==want and tok not in alltext and "SIGNATUREXYZ" not in alltext
    and "XNEVERLOGX" not in alltext and g["secret"]==[tok] and fp==rt+"/anthropic-identity-token"
    and open(fp).read()==tok and not g["warning"]
    and b["info"]==[] and len(b["warning"])==1 and "could not decode OIDC claims" in b["warning"][0] and b["secret"]==["not-a-jwt"])
print("OK" if ok else "BAD logged=%r warnings=%r bad=%r"%(logged,g["warning"],b))
IV
)"
{ eq "$rcg" "0" && eq "$rcb" "0" && eq "$idv" "OK"; } \
  && ok || no "claims logged exactly, token never; malformed token warns" "rc_good=$rcg rc_bad=$rcb verdict=$idv"

begin "req18-requirements-resolve-in-required-job" "the required allowlist job resolves both hash-pinned auditor requirement files (a lone pydantic-core bump broke the SDK install twice), and Dependabot moves pydantic + pydantic-core together"
rq="$(python3 - <<'RQ'
import sys; sys.path.insert(0,".github/agent/fixtures/testlib")
import pyyaml as yaml
j=yaml.safe_load(open(".github/workflows/ci.yml"))["jobs"]["allowlist"]
st=[x for x in j["steps"] if "--dry-run" in x.get("run","") and "--require-hashes" in x.get("run","")]
d=yaml.safe_load(open(".github/dependabot.yml"))
pip=[u for u in d["updates"] if u.get("package-ecosystem")=="pip" and u.get("directory")=="/.github/agent"]
grp=(pip[0].get("groups") or {}).get("pydantic",{}).get("patterns",[]) if len(pip)==1 else []
ok=(len(st)==1 and "adjudicator-requirements.txt" in st[0]["run"] and "coverage-requirements.txt" in st[0]["run"]
    and "if" not in st[0] and "continue-on-error" not in st[0] and sorted(grp)==["pydantic","pydantic-core"])
print("OK" if ok else "BAD")
RQ
)"
eq "$rq" "OK" && ok || no "requirements resolve step in the required job + pydantic group" "$rq"

begin "req18-ac3-no-record-requirement" "no change needs a review record in this repository: the record-judging script is gone, and the trusted verdict (judge and sweep) runs the action-pin checker, the allowlist guard, the pin-wiring judge and the scanner guard and nothing else over the head"
nr="$(python3 - <<'NR'
import os,re
gate=".github/agent/bin/auditor-review-gate.py"
src=open(".github/workflows/agent-review-gate.yml").read()
tools=("check-action-pins.py --verify-tags --git","bin/check-file-allowlist.sh","pin-wiring-test.sh","bin/scan-no-workflow-call-test.sh")
code="\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
ok=(not os.path.exists(gate) and "auditor-review-gate.py" not in src and "--subs-rev" not in src
    and all(code.count(t)==2 for t in tools) and code.count("bin/audit-record-judge.sh")==3 and "reviews/" not in src)    # the audit-record judge: the verdict job, the sweep and the record writer's last step
print("OK" if ok else "BAD")
NR
)"
eq "$nr" "OK" && ok || no "no review-record script; the verdict runs the five checks in judge and sweep" "state=$nr"

begin "req18-ac3-verdict-runs-and-propagates" "the judge and the sweep, run as written with recording stand-ins for the five checks, publish success only when the pin checker, the allowlist guard, the pin-wiring judge, the scanner guard and the passed-audit record judge ALL exit 0, call each check, and fail when any one fails"
vp="$(python3 - <<'VP'
import sys, os, subprocess, tempfile, itertools, shutil
sys.path.insert(0, ".github/agent/fixtures/testlib")
import pyyaml as yaml
d = yaml.safe_load(open(".github/workflows/agent-review-gate.yml"))
def step(job, key):
    r = [x for x in d["jobs"][job]["steps"] if key in x.get("name", "")]
    return r[0]["run"] if len(r) == 1 else None
judge_run = step("judge", "review gate and pin check")
sweep_run = step("sweep", "judge and publish every open PR")
if not judge_run or not sweep_run:
    print("BAD missing step"); sys.exit()
def sh(*a, **k): return subprocess.run(a, check=True, capture_output=True, text=True, **k).stdout.strip()
gitenv = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
              GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
root = tempfile.mkdtemp(prefix="verdict-")
try:
    src = os.path.join(root, "src"); fx = os.path.join(root, "fx")
    os.makedirs(src)
    sh("git", "-C", src, "init", "-q"); open(os.path.join(src, "f"), "w").write("x")
    subprocess.run(["git", "-C", src, "add", "-A"], check=True, env=gitenv)
    subprocess.run(["git", "-C", src, "commit", "-qm", "c", "--no-gpg-sign"], check=True, env=gitenv, capture_output=True)
    sha = sh("git", "-C", src, "rev-parse", "HEAD")
    sh("git", "-C", src, "update-ref", "refs/pull/7/head", sha)
    sh("git", "clone", "-q", src, fx)
    for rel, body in {
        ".github/agent/bin/check-action-pins.py": "import os,sys\nopen(os.environ['CALLS'],'a').write('pins\\n')\nsys.exit(int(os.environ['STUB_PINS']))\n",
        "bin/check-file-allowlist.sh": "cat >/dev/null\necho allow >> \"$CALLS\"\nexit \"$STUB_ALLOW\"\n",
        ".github/agent/tests/pin-wiring-test.sh": "echo wiring >> \"$CALLS\"\nexit \"$STUB_WIRING\"\n",
        "bin/scan-no-workflow-call-test.sh": "echo scan >> \"$CALLS\"\nexit \"$STUB_SCAN\"\n",
        "bin/audit-record-judge.sh": "echo audit >> \"$CALLS\"\nexit \"$STUB_AUDIT\"\n",
    }.items():
        f = os.path.join(fx, rel); os.makedirs(os.path.dirname(f), exist_ok=True); open(f, "w").write(body)
    os.makedirs(os.path.join(fx, ".github/agent/fixtures/testlib/pyyaml"), exist_ok=True)
    stubbin = os.path.join(root, "stubbin"); os.makedirs(stubbin)
    gh = os.path.join(stubbin, "gh")
    open(gh, "w").write('#!/bin/sh\n'
        'case "$1 $2" in\n'
        '"pr list") echo "7 %s feature owner/repo" ;;\n'
        '"api --paginate") ;;\n'   # the sweep's list of merge queue refs: none
        '"api repos/o/r/commits/%s/check-runs?check_name=auditor-review-gate") echo none ;;\n'
        '"api repos/o/r/check-runs") for a in "$@"; do case "$a" in conclusion=*) echo "$a" >> "$CALLS" ;; esac; done ;;\n'
        '*) echo "unexpected gh $*" >> "$CALLS"; exit 9 ;;\n'
        'esac\n' % (sha, sha))
    os.chmod(gh, 0o755)
    bad = []
    for pins, allow, wiring, scan, audit in itertools.product((0, 1), repeat=5):
        allpass = (pins, allow, wiring, scan, audit) == (0, 0, 0, 0, 0)
        for which, run in (("judge", judge_run), ("sweep", sweep_run)):
            calls = os.path.join(root, "calls"); out = os.path.join(root, "out"); tmp = os.path.join(root, "tmp")
            for f in (calls, out): open(f, "w").close()
            os.makedirs(tmp, exist_ok=True)
            env = dict(os.environ, CALLS=calls, GITHUB_OUTPUT=out, RUNNER_TEMP=tmp, HEAD_SHA=sha,
                       GITHUB_HEAD_REF="feature", GITHUB_BASE_REF="main", GITHUB_HEAD_REPO="owner/repo",
                       GITHUB_REPOSITORY="o/r", LIST_TOKEN="t", APP_TOKEN="t", APP_SLUG="app", DEFAULT="main", RUN_URL="u",
                       STUB_PINS=str(pins), STUB_ALLOW=str(allow), STUB_WIRING=str(wiring), STUB_SCAN=str(scan), STUB_AUDIT=str(audit),
                       PATH=stubbin + ":" + os.environ["PATH"])
            r = subprocess.run(["bash", "-c", run], cwd=fx, env=env, capture_output=True, text=True)
            c = open(calls).read().split()
            tag = "%s pins=%d allow=%d wiring=%d scan=%d audit=%d" % (which, pins, allow, wiring, scan, audit)
            if which == "judge":
                v = open(out).read().strip()
                if sorted(c) != ["allow", "audit", "pins", "scan", "wiring"]: bad.append(tag + " calls=%s" % c)
                if v != ("verdict=success" if allpass else "verdict=failure"): bad.append(tag + " out=%s" % v)
                if (r.returncode == 0) != allpass: bad.append(tag + " rc=%d" % r.returncode)
            else:
                pub = [x for x in c if x.startswith("conclusion=")]
                if pub != ["conclusion=success" if allpass else "conclusion=failure"]: bad.append(tag + " published=%s" % pub)
                if "pins" not in c or (allpass and sorted(x for x in c if not x.startswith("conclusion=")) != ["allow", "audit", "pins", "scan", "wiring"]):
                    bad.append(tag + " calls=%s" % c)
                if any("unexpected" in x for x in c): bad.append(tag + " unexpected gh call")
    print("OK" if not bad else "BAD " + "; ".join(bad[:4]))
finally:
    shutil.rmtree(root, ignore_errors=True)
VP
)"
eq "$vp" "OK" && ok || no "judge and sweep run as written publish success only when all five checks exit 0" "$vp"

begin "req18-ac3-gate-runs-from-base-on-pull-request-target" "the review gate runs on pull_request_target (default-branch workflow) incl. retargets; a secret-free JUDGE reads the PR head as data only against the checked-out default branch and rejects a moved head; a PUBLISHER holds only a checks:write token of the automation App (agent environment) and never touches PR data; a scheduled SWEEP covers PRs whose run had no App credentials (Dependabot); the auditor's own App token cannot write checks"
wg="$(python3 - <<'WG'
import sys; sys.path.insert(0,".github/agent/fixtures/testlib")
import pyyaml as yaml
src=open(".github/workflows/agent-review-gate.yml").read(); d=yaml.safe_load(src)
on=d.get("on") or d.get(True) or {}
J=d["jobs"]; j=J.get("judge",{}); p=J.get("publish",{}); w=J.get("sweep",{}); q=J.get("queue-judge",{})
runs=lambda job: "\n".join(x.get("run","") for x in job.get("steps",[]))
jr, pr, wr = runs(j), runs(p), runs(w)
co=[x for x in j.get("steps",[]) if str(x.get("uses","")).startswith("actions/checkout@")]
wco=[x for x in w.get("steps",[]) if str(x.get("uses","")).startswith("actions/checkout@")]
tok=lambda job: [x for x in job.get("steps",[]) if str(x.get("uses","")).startswith("actions/create-github-app-token@")]
main_only="github.event.pull_request.base.ref == github.event.repository.default_branch"
def scoped(t): return len(t)==1 and {k for k in (t[0].get("with") or {}) if k.startswith("permission-")}=={"permission-checks"} and t[0]["with"]["permission-checks"]=="write"
qco=[x for x in q.get("steps",[]) if str(x.get("uses","")).startswith("actions/checkout@")]
ok=(set(on)=={"pull_request_target","workflow_run","schedule","workflow_dispatch"} and "edited" in on["pull_request_target"]["types"]
    and d.get("permissions")=={} and set(J)=={"judge","publish","record","queue-judge","sweep"}
    # queue-judge: a workflow_run job (the default branch's copy), never a pull_request_target job; the agent environment;
    # fires only for a merge_group CI run; the default branch's checkout; judged by main's script; the App token is checks-only
    and on["workflow_run"].get("workflows")==["CI"] and set(on["workflow_run"].get("types",[]))=={"requested","completed"}
    and q.get("environment")=="agent" and q.get("permissions")=={"contents":"read"}
    and q.get("if")=="github.event_name == 'workflow_run' && github.event.workflow_run.event == 'merge_group'"
    and "pull_request_target" not in str(q.get("if")) and "pull_request" not in yaml.safe_dump(q.get("steps",[]))
    and len(qco)==1 and (qco[0].get("with") or {}).get("persist-credentials") is False and "ref" not in (qco[0].get("with") or {})
    and scoped(tok(q)) and "bash .github/agent/bin/queue-gate-judge.sh" in runs(q) and "checkout" not in runs(q)
    # judge: no secrets, read-only, base checkout, data-only fetch, moved-head rejection, HEAD merge-base
    and j.get("permissions")=={"contents":"read"} and "secrets." not in yaml.safe_dump(j) and main_only in str(j.get("if"))
    and len(co)==1 and (co[0].get("with") or {}).get("persist-credentials") is False and "ref" not in (co[0].get("with") or {})
    and "refs/pull/${PR}/head:refs/remotes/pr/head" in jr and '[ "$got" = "$HEAD_SHA" ] ||' in jr
    and "base.sha" not in yaml.safe_dump(j) and "auditor-review-gate.py" not in jr
    and 'check-action-pins.py --verify-tags --git "$HEAD_SHA"' in jr and "PIN_WIRING_JUDGE_GIT=\"$HEAD_SHA\"" in jr
    and "checkout" not in jr and "pip install" not in jr
    # publisher: agent-env App token (checks only), no PR data, not on cancellation
    and p.get("needs")=="judge" and p.get("environment")=="agent" and p.get("permissions")=={}
    and "!cancelled()" in str(p.get("if")) and main_only in str(p.get("if")) and scoped(tok(p))
    and "actions/checkout" not in yaml.safe_dump(p) and "refs/pull" not in pr and "git " not in pr
    and "-f name=auditor-review-gate" in pr and '-f head_sha="$HEAD_SHA"' in pr
    # sweep: schedule/dispatch only, base checkout, data-only fetch + sha check, only App-authored checks count
    and w.get("environment")=="agent" and "pull_request_target" not in str(w.get("if")) and "schedule" in str(w.get("if"))
    and len(wco)==1 and (wco[0].get("with") or {}).get("persist-credentials") is False and "ref" not in (wco[0].get("with") or {})
    and scoped(tok(w)) and 'refs/remotes/pr/${n}' in wr and '= "$sha" ] || continue' in wr
    and 'select(.app.slug == \\"${APP_SLUG}\\")' in wr and "auditor-review-gate.py" not in wr
    and 'check-action-pins.py --verify-tags --git "$sha"' in wr and "PIN_WIRING_JUDGE_GIT=\"$sha\"" in wr
    and "checkout" not in wr and "statuses" not in src)
# the auditor's own mint of the same App never includes checks
a=yaml.safe_load(open(".github/workflows/auditor.yml"))
mints=[x for jb in a["jobs"].values() for x in jb.get("steps",[]) if str(x.get("uses","")).startswith("actions/create-github-app-token@")]
ok = ok and len(mints)==1 and {k for k in mints[0]["with"] if k.startswith("permission-")}=={"permission-contents","permission-pull-requests"}
print("OK" if ok else "BAD")
WG
)"
# (the required-checks.json entry lands in a follow-up PR once the gate is proven on main:
#  pull_request_target always runs the DEFAULT branch's workflow, so it cannot be proven earlier)
eq "$wg" "OK" && ok || no "protected judge/publish/sweep gate; auditor token without checks" "workflow=$wg"

begin "req-rel-012-record-writer-job-shape-and-sweep-stale-path" "the passed-audit record writer (REQ-REL-012) is a dispatch-only job of the review gate: agent environment, a contents-only App token, the two inputs only through env, the prepare script then the committed signed-commit CLI on audit/<head> then the judge; the sweep does not run on a record dispatch; and the sweep re-judges an OLD failure when the head has a record branch and skips it when it has none"
rw="$(python3 - <<'RW'
import copy, itertools, os, shutil, subprocess, sys, tempfile
sys.path.insert(0, ".github/agent/fixtures/testlib")
import pyyaml as yaml
src = open(".github/workflows/agent-review-gate.yml").read(); d = yaml.safe_load(src)
def problems(d):
    bad = []
    on = d.get("on") or d.get(True) or {}
    inp = (on.get("workflow_dispatch") or {}).get("inputs") or {}
    if set(inp) != {"audit_pr", "audit_head"} or any(v.get("default") != "" or v.get("type") != "string" for v in inp.values()):
        bad.append("dispatch inputs")
    r = (d.get("jobs") or {}).get("record")
    if not isinstance(r, dict):
        return bad + ["no record job"]
    if r.get("if") != "github.event_name == 'workflow_dispatch' && inputs.audit_head != ''": bad.append("record if")
    if r.get("environment") != "agent" or r.get("permissions") != {"contents": "read"}: bad.append("record environment or permissions")
    if set(r) - {"name", "if", "runs-on", "timeout-minutes", "environment", "permissions", "steps"}: bad.append("record keys")
    st = r.get("steps") or []
    if len(st) != 5: return bad + ["record steps"]
    co, mint, prep, sign, judge = st
    if not str(co.get("uses", "")).startswith("actions/checkout@") or co.get("with") != {"persist-credentials": False}: bad.append("checkout")
    if not str(mint.get("uses", "")).startswith("actions/create-github-app-token@") or mint.get("id") != "app" or mint.get("with") != {
            "app-id": "${{ secrets.AUDITOR_APP_ID }}", "private-key": "${{ secrets.AUDITOR_APP_PRIVATE_KEY }}", "repositories": "cache", "permission-contents": "write", "permission-pull-requests": "read"}: bad.append("the token must be contents write and pull-requests read, nothing else")
    envs = {"GH_TOKEN": "${{ steps.app.outputs.token }}", "AUDIT_PR": "${{ inputs.audit_pr }}", "AUDIT_HEAD": "${{ inputs.audit_head }}"}
    if prep.get("env") != dict(envs, AUDIT_ACTOR="${{ github.triggering_actor }}") or prep.get("id") != "prep" or "bash bin/audit-record-prepare.sh \"$AUDIT_PR\" \"$AUDIT_HEAD\"" not in prep.get("run", "") or "set -euo pipefail" not in prep.get("run", ""): bad.append("prepare step")
    if sign.get("if") != "steps.prep.outputs.state == 'proceed'" or sign.get("env") != {"GH_TOKEN": envs["GH_TOKEN"], "AUDIT_HEAD": envs["AUDIT_HEAD"]} or sign.get("run") != 'python3 .github/agent/bin/auditor-signed-commit.py --repo "$GITHUB_REPOSITORY" --branch "audit/${AUDIT_HEAD}" --base "$AUDIT_HEAD" --prefix audit/ --message "audit record" --path audit-record': bad.append("sign step")
    if judge.get("if") != "steps.prep.outputs.state == 'proceed'" or judge.get("env") != {"GH_TOKEN": envs["GH_TOKEN"], "AUDIT_HEAD": envs["AUDIT_HEAD"]} or judge.get("run") != 'bash bin/audit-record-judge.sh "$AUDIT_HEAD" main': bad.append("judge step")
    if any("${{" in x.get("run", "") for x in st) or any(k in x for x in st for k in ("continue-on-error",)): bad.append("an expression inside a run, or continue-on-error")
    sw = d["jobs"]["sweep"]
    if sw.get("if") != "github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.audit_head == '')": bad.append("the sweep must not run on a record dispatch")
    if "format('record-{0}', inputs.audit_pr)" not in str((d.get("concurrency") or {}).get("group")): bad.append("a record dispatch needs its own concurrency group")
    return bad
ok = problems(d) == []
for name, fn in (("token widened", lambda x: x["jobs"]["record"]["steps"][1]["with"].update({"permission-pull-requests": "write"})),
                 ("input inline in a run", lambda x: x["jobs"]["record"]["steps"][2].update({"run": x["jobs"]["record"]["steps"][2]["run"].replace('"$AUDIT_PR"', "${{ inputs.audit_pr }}")})),
                 ("another prefix", lambda x: x["jobs"]["record"]["steps"][3].update({"run": x["jobs"]["record"]["steps"][3]["run"].replace("--prefix audit/", "--prefix auditor/")})),
                 ("another base", lambda x: x["jobs"]["record"]["steps"][3].update({"run": x["jobs"]["record"]["steps"][3]["run"].replace('--base "$AUDIT_HEAD"', "--base main")})),
                 ("no environment", lambda x: x["jobs"]["record"].pop("environment")),
                 ("sweep runs on record dispatch", lambda x: x["jobs"]["sweep"].update({"if": "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"})),
                 ("sign always", lambda x: x["jobs"]["record"]["steps"][3].pop("if"))):
    m = copy.deepcopy(d); fn(m)
    ok = ok and problems(m) != []
# the sweep's stale path: run the step as written with stand-ins
sweep_run = [x for x in d["jobs"]["sweep"]["steps"] if "judge and publish every open PR" in x.get("name", "")][0]["run"]
def sh(*a, **k): return subprocess.run(a, check=True, capture_output=True, text=True, **k).stdout.strip()
gitenv = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
root = tempfile.mkdtemp(prefix="stale-")
try:
    srcd = os.path.join(root, "src"); fx = os.path.join(root, "fx"); os.makedirs(srcd)
    sh("git", "-C", srcd, "init", "-q"); open(os.path.join(srcd, "f"), "w").write("x")
    subprocess.run(["git", "-C", srcd, "add", "-A"], check=True, env=gitenv)
    subprocess.run(["git", "-C", srcd, "commit", "-qm", "c", "--no-gpg-sign"], check=True, env=gitenv, capture_output=True)
    sha = sh("git", "-C", srcd, "rev-parse", "HEAD"); sh("git", "-C", srcd, "update-ref", "refs/pull/7/head", sha); sh("git", "clone", "-q", srcd, fx)
    for rel in (".github/agent/bin/check-action-pins.py", "bin/check-file-allowlist.sh", ".github/agent/tests/pin-wiring-test.sh", "bin/scan-no-workflow-call-test.sh", "bin/audit-record-judge.sh"):
        f = os.path.join(fx, rel); os.makedirs(os.path.dirname(f), exist_ok=True)
        open(f, "w").write("import sys\nopen(__import__('os').environ['CALLS'],'a').write('judged\\n')\n" if rel.endswith(".py") else "cat >/dev/null 2>&1\necho judged >> \"$CALLS\"\n")
    os.makedirs(os.path.join(fx, ".github/agent/fixtures/testlib/pyyaml"), exist_ok=True)
    stubbin = os.path.join(root, "stubbin"); os.makedirs(stubbin)
    gh = os.path.join(stubbin, "gh")
    open(gh, "w").write('#!/bin/sh\n'
        'case "$1 $2" in\n'
        '"pr list") echo "7 %s feature owner/repo" ;;\n'
        '"api --paginate") ;;\n'   # the sweep's list of merge queue refs: none
        '"api repos/o/r/commits/%s/check-runs?check_name=auditor-review-gate") echo "$STUB_LAST" ;;\n'
        '"api repos/o/r/git/ref/heads/audit/%s") [ "$STUB_REC" = 1 ] || exit 1 ;;\n'
        '"api repos/o/r/check-runs") for a in "$@"; do case "$a" in conclusion=*) echo "$a" >> "$CALLS" ;; esac; done ;;\n'
        '*) echo "unexpected gh $*" >> "$CALLS"; exit 9 ;;\n'
        'esac\n' % (sha, sha, sha))
    os.chmod(gh, 0o755)
    def run(last, rec):
        calls = os.path.join(root, "calls"); out = os.path.join(root, "out"); tmp = os.path.join(root, "tmp")
        for f in (calls, out): open(f, "w").close()
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, CALLS=calls, GITHUB_OUTPUT=out, RUNNER_TEMP=tmp, GITHUB_REPOSITORY="o/r", LIST_TOKEN="t", APP_TOKEN="t", APP_SLUG="app", DEFAULT="main", RUN_URL="u",
                   STUB_LAST=last, STUB_REC=str(rec), PATH=stubbin + ":" + os.environ["PATH"])
        subprocess.run(["bash", "-c", sweep_run], cwd=fx, env=env, capture_output=True, text=True)
        return open(calls).read().split()
    c = run("stale", 1); ok = ok and c.count("judged") == 5 and "conclusion=success" in c           # old failure + a record branch -> judged again, published
    c = run("stale", 0); ok = ok and c == []                                                          # old failure, no record -> skipped, nothing called
    c = run("success", 1); ok = ok and c == []                                                        # already green -> nothing
    c = run("failure", 0); ok = ok and c.count("judged") == 5                                         # a recent failure is judged as before
finally:
    shutil.rmtree(root, ignore_errors=True)
print("OK" if ok else "BAD")
RW
)"
eq "$rw" "OK" && ok || no "record writer job shape, mutants refused, sweep stale path" "$rw"

echo "=== report: one line per thing, render-safe (owner's test Sep 27, handoff 0004) ==="
rpt="$WORK/rpt"; rm -rf "$rpt"; mkdir -p "$rpt"
"$PY" - "$rpt" <<'RP'
import importlib.util,json,os,sys
d=sys.argv[1]
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
q={"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]}
def m(test): return {"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None,
                     "provenance":({"source":"test-image"} if test else {})}
# MANY findings, ONE action each: 30 CVEs all needing the same module bump, plus tricky identifiers
rows=[]
for i in range(30):
    rows.append({"id":"CVE-2099-%04d"%i,"section":3,"disposition":"real, fixable","action":"bump draft PR","reason":"fix exists",
                 "package":"example.org/lib","installed":"1.0","fixed":"1.1","severity":"High",
                 "fix_bump":{"module":"example.org/lib","from":"1.0","to":"1.1","cve":"CVE-2099-%04d"%i}})
rows.append({"id":"CVE-2099-9999","section":2,"disposition":"carried (POA&M)","action":"POA&M: vex #stmt-cve-2099-9999~ab12 * not_affected _x_","reason":"no fix <yet> | a~b",
             "package":"py_lib","installed":"1*2","fixed":None,"severity":"Low","vex_id":"#stmt-cve-2099-9999~ab12",
             "ignore_files":["ignores/grype/CVE-2099-9999~x.json",".snyk"]})
rows.append(dict(rows[-1], id="CVE-2099-9998", vex_id="#stmt-cve-2099-9998~cd34"))
rows.append({"id":"CVE-2099-7777","section":5,"disposition":"not_affected (unreachable)","action":"closed","reason":"unreachable",
             "package":"lib","installed":"1","fixed":None,"severity":"Low","vex_id":"#stmt-cve-2099-7777~ee","carried":True})
rows+= [dict(rows[-1]) for _ in range(2)]          # three identical rows: must collapse to one
sections={n:[] for n in range(1,8)}
for r in rows: sections[r["section"]].append(r)
def plans(test):
    w=[]
    for r in rows:
        if r.get("fix_bump"):
            fb=r["fix_bump"]
            R._plan(w,"bump PR","%s %s -> %s"%(fb["module"],fb["from"],fb["to"]),[r["id"]],note=("skipped: test image" if test else "draft"),key="auditor/bump-%s-abc"%r["id"])
    R._plan(w,"suppression PR","suppressions (3 statements)",["CVE-2099-9999","CVE-2099-9998","CVE-2099-7777"],note=("skipped: test image" if test else "draft"))
    R._plan(w,"owner-decision issue","CVE-2099-9999 — py_lib",["CVE-2099-9999"])
    R._plan(w,"owner-decision issue","CVE-2099-9999 — py_lib",["CVE-2099-9999"])   # the same issue twice: one line
    return w
for name,test in (("candidate",False),("testimage",True)):
    open(os.path.join(d,name+".md"),"w").write(R._render(m(test),rows,sections,plans(test),"AUDIT COMPLETE",True,"stub",{},"h","c",None,None,q))
# nothing actionable
open(os.path.join(d,"empty.md"),"w").write(R._render(m(False),[],{n:[] for n in range(1,8)},[],"AUDIT COMPLETE",True,"stub",{},"h","c",None,None,q))
RP
pl(){ sed -n '/^## PRs and issues this run/,/^## 0\./p' "$1" | grep '^- '; }

begin "rpt-ac1-pr-list-one-line-per-pr" "the PR list has one line per PR/issue, never one per finding; each line names its kind, its target and its CVE IDs"
c1="$(pl "$rpt/candidate.md")"
nl="$(printf '%s\n' "$c1" | grep -c .)"; bumps="$(printf '%s\n' "$c1" | grep -c 'would open (dry run): bump PR — example.org/lib 1.0 -> 1.1 — CVEs: CVE-2099-')"
supp="$(printf '%s\n' "$c1" | grep -c 'suppression PR — suppressions (3 statements) — CVEs: CVE-2099-7777, CVE-2099-9998, CVE-2099-9999')"
iss="$(printf '%s\n' "$c1" | grep -c 'owner-decision issue — CVE-2099-9999 — py_lib — CVEs: CVE-2099-9999')"
dup="$(printf '%s\n' "$c1" | sort | uniq -d | grep -c .)"
{ eq "$bumps" "30" && eq "$supp" "1" && eq "$iss" "1" && eq "$dup" "0" && eq "$nl" "32"; } \
  && ok || no "30 bump PR lines (one per branch) + 1 suppression + 1 issue, all unique" "lines=$nl bumps=$bumps supp=$supp issue=$iss dup=$dup"

begin "rpt-ac2-test-image-single-line-with-counts" "a test-image run lists ONE line: nothing opened, why, and how many findings would have produced how many PRs; a run with nothing to open says so in one line"
t1="$(pl "$rpt/testimage.md")"; e1="$(pl "$rpt/empty.md")"
{ eq "$(printf '%s\n' "$t1" | grep -c .)" "1" \
  && eq "$t1" "- Test image — nothing opened (not a shipped image); on a shipped image 33 finding(s) would have produced 31 PR(s) (30 bump target(s), 1 suppression) and 1 owner-decision issue(s)." \
  && eq "$e1" "- Nothing opened this run — dry run with no actionable findings; 0 finding(s) would have produced a PR."; } \
  && ok || no "single summary lines" "test=$t1 | empty=$e1"

begin "rpt-ac3-ac5-every-section-unique-and-render-safe" "no list section repeats a line (identical rows collapse, marked ×n) and, rendered with GitHub's cmark-gfm, no report has strikethrough, emphasis or stray bold — over the crafted reports and a real-capture run"
o="$WORK/rpt-run"; rm -rf "$o"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$FX/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
o2="$WORK/rpt-ti"; rm -rf "$o2"
"$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$FX/run/manifest-testimage.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o2" >/dev/null 2>&1
collapsed="$(grep -c 'CVE-2099-7777 .*(×3 identical rows)' "$rpt/candidate.md")"
mode=""; "$PY" -c 'import cmarkgfm' 2>/dev/null || { [ -n "${CI:-}" ] && mode="MISSING" || mode="--no-render"; }
if [ "$mode" = "MISSING" ]; then lint="cmarkgfm missing in CI"; lrc=9
else lint="$("$PY" .github/agent/tests/report-lint.py $mode "$rpt/candidate.md" "$rpt/testimage.md" "$rpt/empty.md" "$o/report.md" "$o2/report.md" 2>&1)"; lrc=$?; fi
[ "$mode" = "--no-render" ] && echo "   (render check skipped locally: cmarkgfm not installed; CI installs .github/agent/test-requirements.txt)"
{ eq "$lrc" "0" && eq "$collapsed" "1" && [ -s "$o/report.md" ] && [ -s "$o2/report.md" ]; } \
  && ok || no "unique + render-clean reports" "lint_rc=$lrc collapsed=$collapsed :: $(printf '%s' "$lint" | grep -v ': ok' | head -3 | tr '\n' ' ')"

begin "rpt-ac5-lint-catches-the-old-defects" "the lint FAILS a report with a repeated PR-list line and one with bare tildes that GitHub strikes through (so the passing case above is meaningful)"
printf '## PRs and issues this run\n\n- would open (dry run): `x`\n- would open (dry run): `x`\n' > "$WORK/rpt-dup.md"
printf '## 2. Accepted\n\nCVE-2005-2541 — tar@1.34 — vex: #stmt-cve-2005-2541~4ccc7df8bb0a7c62 — ignores: .snyk\nCVE-2007-5686 — login@1 — vex: #stmt-cve-2007-5686~c70f72f3b350d760 — ignores: .snyk\n' > "$WORK/rpt-tilde.md"
"$PY" .github/agent/tests/report-lint.py --no-render "$WORK/rpt-dup.md" >/dev/null 2>&1; d1=$?
if "$PY" -c 'import cmarkgfm' 2>/dev/null; then "$PY" .github/agent/tests/report-lint.py "$WORK/rpt-tilde.md" >/dev/null 2>&1; d2=$?; else d2="$([ -n "${CI:-}" ] && echo 9 || echo 1)"; fi
{ eq "$d1" "1" && eq "$d2" "1"; } && ok || no "lint rejects both old defects" "dup=$d1 tilde=$d2"

begin "rpt-r1-one-line-per-delivery-and-issue" "several rows feeding ONE bump branch are one line (targets and CVEs merged); a live owner issue lists EVERY CVE and target it covers; a live standing issue is listed; closing the standing issue is not an 'opening' (review round 1)"
r1="$("$PY" - <<'R1'
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
secs={n:[] for n in range(1,8)}
w=[]
for inst in ("0.16.0","0.17.3"):     # two installed versions, ONE branch
    R._plan(w,"bump PR","mod %s -> 0.22.0"%inst,["CVE-1"],note="draft",key="auditor/bump-CVE-1-abc")
R._plan(w,"standing issue","auditor: needs a human — close if open")
dry=R._pr_list(w,[],secs,True,None,None,False)
rows=[{"id":"CVE-%d"%i,"owner_issue":"https://x/issues/9","adjudicator_error":True,"package":"p%d"%i} for i in range(5)]
rows+=[{"id":"CVE-50","owner_issue":"https://x/issues/10","package":"zlib"},{"id":"CVE-50","owner_issue":"https://x/issues/10","package":"zlib1g"}]
secs[3]=[{"id":"CVE-7","fix_pr_url":"https://x/pull/3","fix_bump":{"module":"m","from":"1","to":"2"}},
         {"id":"CVE-8","fix_pr_url":"https://x/pull/3","fix_bump":{"module":"m","from":"1","to":"2"}}]
live=R._pr_list([],rows,secs,False,None,None,False,{"ref":"https://x/issues/1","needs":3})
closed=R._pr_list([],[],{n:[] for n in range(1,8)},False,None,None,False,{"ref":"https://x/issues/1","needs":0})
ok=(dry==["would open (dry run): bump PR — mod 0.16.0 -> 0.22.0; mod 0.17.3 -> 0.22.0 — CVEs: CVE-1"]
    and "owner-decision issue: https://x/issues/9 — adjudicator unavailable — CVEs: CVE-0, CVE-1, CVE-2, CVE-3, CVE-4" in live
    and "owner-decision issue: https://x/issues/10 — zlib; zlib1g — CVEs: CVE-50" in live
    and "bump PR (App): m 1 -> 2 — CVEs: CVE-7, CVE-8 — https://x/pull/3" in live
    and any(l.startswith("standing issue: auditor: needs a human — https://x/issues/1 — 3 item(s)") for l in live)
    and closed==["Nothing opened this run — no actionable findings; 0 finding(s) would have produced a PR."])
print("OK" if ok else "BAD dry=%r live=%r closed=%r"%(dry,live,closed))
R1
)"
eq "$r1" "OK" && ok || no "one line per delivery/issue with every CVE; standing listed; close not an opening" "$r1"

begin "rpt-r1-free-text-stays-one-line-and-visible" "multi-line tool stderr in a delivery error stays ONE list line (no injected heading), and a masked <model-id> in the status/conclusion stays visible (review round 1)"
r2="$(rm -rf "$WORK/rpt-r1" && mkdir -p "$WORK/rpt-r1" && "$PY" - "$WORK/rpt-r1" <<'R2'
import importlib.util,os,sys
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
err="git push: To https://github.com/o/r\n ! [rejected] a -> a (non-fast-forward)\n# a hash-led line\nhint: pull first"
rep=R._render(m,[],{n:[] for n in range(1,8)},[],"AUDIT INCOMPLETE: model call failed for <model-id>",False,"stub",{},"h",
              "Model <model-id> unavailable ~ retry","",err,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
open(os.path.join(sys.argv[1],"r.md"),"w").write(rep)
pl=rep.split("## PRs and issues this run")[1].split("## 0.")[0]
lines=[l for l in pl.splitlines() if l.strip()]
ok=(len(lines)==1 and lines[0].startswith("- suppression PR delivery FAILED") and " ↵ " in lines[0]
    and "\\<model-id>" in rep and "Model \\<model-id> unavailable \\~ retry" in rep)
print("OK" if ok else "BAD lines=%r"%lines)
R2
)"
if "$PY" -c 'import cmarkgfm' 2>/dev/null; then
  html="$("$PY" -c 'import cmarkgfm,sys; print(cmarkgfm.github_flavored_markdown_to_html(open(sys.argv[1]).read()))' "$WORK/rpt-r1/r.md")"
  vis="$(printf '%s' "$html" | grep -c '&lt;model-id&gt;')"; heads="$(printf '%s' "$html" | grep -c '<h1>a hash-led')"
else vis="$([ -n "${CI:-}" ] && echo 0 || echo 2)"; heads=0; fi
{ eq "$r2" "OK" && [ "$vis" -ge 2 ] 2>/dev/null && eq "$heads" "0"; } \
  && ok || no "stderr one line; <model-id> visible in status + conclusion" "$r2 visible=$vis injected_heading=$heads"

begin "rpt-r1-lint-catches-spilled-list-lines" "the lint FAILS a report whose list item continues onto a second physical line (the multi-line stderr shape), even when source and render agree"
printf '## PRs and issues this run\n\n- delivery FAILED: git push: To x\n# injected\nhint: y\n\n## 0. Needs a human\n' > "$WORK/rpt-spill.md"
"$PY" .github/agent/tests/report-lint.py --no-render "$WORK/rpt-spill.md" >/dev/null 2>&1; sp=$?
eq "$sp" "1" && ok || no "lint rejects a spilled list line" "rc=$sp"

begin "rpt-r2-every-surface-escaped-and-named" "the header's adjudicator field, a FAILED standing-issue ref and a conclusion opening with a block marker stay one visible escaped line; the standing issue line names its CVEs; the lint accepts a correctly rendered escaped bold status (review round 2)"
r3="$(rm -rf "$WORK/rpt-r2" && mkdir -p "$WORK/rpt-r2" && "$PY" - "$WORK/rpt-r2" <<'R3'
import importlib.util,os,sys
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
q={"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]}
state={"adj_errors":{"x":"404 model: <model-id> not found"},
       "standing_issue":{"ref":"standing comment failed: To x\n# a hash line *stars*","needs":2,"cves":["CVE-1","GHSA-aaaa-bbbb-cccc"]}}
rep=R._render(m,[],{n:[] for n in range(1,8)},[],"AUDIT INCOMPLETE: standing failed: <model-id>",False,"real",{},"h",
              "# not a heading","",None,q,state)
open(os.path.join(sys.argv[1],"r.md"),"w").write(rep)
pl=[l for l in rep.split("## PRs and issues this run")[1].split("## 0.")[0].splitlines() if l.strip()]
st_line=[l for l in pl if l.startswith("- standing issue:")]
ok=(len(st_line)==1 and st_line[0].endswith("— 2 item(s) needing a human — CVEs: CVE-1, GHSA-aaaa-bbbb-cccc")
    and "↵ # a hash line \\*stars\\*" in st_line[0] and "\\# not a heading" in rep)   # mid-line # is inert
print("OK" if ok else "BAD %r"%pl)
R3
)"
if "$PY" -c 'import cmarkgfm' 2>/dev/null; then
  "$PY" .github/agent/tests/report-lint.py "$WORK/rpt-r2/r.md" >/dev/null 2>&1; lr=$?
  hid="$("$PY" -c 'import cmarkgfm,sys; h=cmarkgfm.github_flavored_markdown_to_html(open(sys.argv[1]).read()); print(h.count("raw HTML omitted"))' "$WORK/rpt-r2/r.md")"
else lr="$([ -n "${CI:-}" ] && echo 9 || echo 0)"; hid=0; fi
{ eq "$r3" "OK" && eq "$lr" "0" && eq "$hid" "0"; } \
  && ok || no "escaped + named, lint clean, nothing hidden" "$r3 lint=$lr hidden_html=$hid"

begin "rpt-r3-standing-and-removals-name-their-cves" "the standing issue carries EVERY §0 id (dry plan and live, incl. the suppression PR's CVEs); a removal-only suppression PR names the expired scopes and their CVEs; a leading '1.' never opens a list; the lint accepts an escaped '*' inside the bold status (review round 3)"
r4="$(rm -rf "$WORK/rpt-r3" && mkdir -p "$WORK/rpt-r3/.auditor" "$WORK/rpt-r3/suppressions" && "$PY" - "$WORK/rpt-r3" <<'R4'
import importlib.util,json,os,sys
d=sys.argv[1]
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
json.dump({"reopened":[["CVE-9",["p"],["pkg:a"]],["CVE-9",["p"],["pkg:b"]],["CVE-8",["p"],["pkg:c"]]]},open(os.path.join(d,".auditor","reopened-expired.json"),"w"))
supp=os.path.join(d,"suppressions")
t,c=R._supp_target(supp,0)
w=[]; ok_std,ref=R._standing_issue(["owner-decision needed: CVE-1"],True,w,["CVE-1","CVE-9"])
dryline=R._pr_list(w,[],{n:[] for n in range(1,8)},True,None,None,False)
rows=[{"id":"CVE-1","owner_issue":"https://x/issues/2","package":"z"}]
ids=R._needs_ids(rows,{n:[] for n in range(1,8)},False,["CVE-8","CVE-9"])
st={"grype":{"ran":True,"os_package_count":6,"package_count":6,"findings":0,"version":"x","db_date":"d"}}
m={"scanner_status":st,"scanner_reports":{"grype":"x"},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,[],{n:[] for n in range(1,8)},[],"AUDIT INCOMPLETE: git fetch: * branch main -> FETCH_HEAD",False,"stub",{},"h",
              "1. first point","",None,{"agreed":["grype"],"disagreed":[],"not_ran":[],"excluded":[]})
open(os.path.join(d,"r.md"),"w").write(rep)
ok=(t=="suppressions (0 statements, 3 scope(s) removed)" and c==["CVE-8","CVE-9"]
    and dryline==["would open (dry run): standing issue — auditor: needs a human — comment (1 item(s)) — CVEs: CVE-1, CVE-9"]
    and ids==["CVE-1","CVE-8","CVE-9"] and "1\\. first point" in rep)
print("OK" if ok else "BAD t=%r c=%r dry=%r ids=%r"%(t,c,dryline,ids))
R4
)"
if "$PY" -c 'import cmarkgfm' 2>/dev/null; then "$PY" .github/agent/tests/report-lint.py "$WORK/rpt-r3/r.md" >/dev/null 2>&1; l4=$?
else l4="$([ -n "${CI:-}" ] && echo 9 || echo 0)"; fi
{ eq "$r4" "OK" && eq "$l4" "0"; } && ok || no "standing/removal CVEs named; no ordered list; escaped-star bold accepted" "$r4 lint=$l4"

begin "rpt-r4-disabled-delivery-says-not-delivered" "a live run whose delivery step is disabled lists every suppression/bump PR as NOT delivered (with why and its CVEs) — never 'no actionable findings'; a removed scope is worded neutrally (expired or lifted) (review round 4)"
r5="$(rm -rf "$WORK/rpt-r4" && mkdir -p "$WORK/rpt-r4/suppressions" "$WORK/rpt-r4/.auditor" && env -u AUDITOR_GIT_SHIM_LOG -u AUDITOR_ALLOW_REAL_GH "$PY" - "$WORK/rpt-r4" <<'R5'
import importlib.util,json,os,sys
d=sys.argv[1]
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
json.dump({"statements":[{"vulnerability":{"name":"CVE-3"}}]},open(os.path.join(d,"suppressions","fosterstack-cache.openvex.json"),"w"))
json.dump({"reopened":[["CVE-4",["p"],["pkg:x"]]]},open(os.path.join(d,".auditor","reopened-expired.json"),"w"))
w=[]
R._deliver_suppression_pr(d,os.path.join(d,"suppressions"),1,"2026-09-28","abcdef1234567890",False,w)
row={"id":"CVE-5","fix_bump":{"cve":"CVE-5","module":"m","from":"1","to":"2"}}
res=R._deliver_fix_pr(row,"2026-09-28","abcdef1234567890",False,w)
R._standing_issue(["x"],False,w,["CVE-5"])
pl=R._pr_list(w,[],{n:[] for n in range(1,8)},False,None,None,False,{"ref":"skipped","needs":1})
want=["NOT delivered (delivery disabled — no authorized delivery step): suppression PR — suppressions (1 statements, 1 scope(s) removed) — CVEs: CVE-3, CVE-4",
      "NOT delivered (delivery disabled — no authorized delivery step): bump PR — m v1 -> v2 — CVEs: CVE-5",
      "NOT delivered (delivery disabled — no authorized delivery step): standing issue — auditor: needs a human — comment (1 item(s)) — CVEs: CVE-5"]
print("OK" if (pl==want and res[2]=="pending") else "BAD %r %r"%(pl,res))
R5
)"; r5="$(printf '%s\n' "$r5" | tail -1)"
eq "$r5" "OK" && ok || no "disabled delivery listed as NOT delivered" "$r5"

begin "rpt-r5-undelivered-issues-keyed-by-issue" "with delivery disabled, the ONE adjudicator-outage issue is one line carrying every CVE, and two issues for one CVE on different packages (zlib, zlib1g) stay two lines (review round 5)"
r6="$("$PY" - <<'R6'
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
rows=[{"id":"CVE-%d"%i,"owner_issue":"skipped","adjudicator_error":True,"package":"p%d"%i} for i in range(4)]
rows+=[{"id":"CVE-50","owner_issue":"skipped","package":"zlib"},{"id":"CVE-50","owner_issue":"skipped","package":"zlib1g"}]
pl=R._pr_list([],rows,{n:[] for n in range(1,8)},False,None,None,False)
want=["owner-decision issue: skipped — adjudicator unavailable — CVEs: CVE-0, CVE-1, CVE-2, CVE-3",
      "owner-decision issue: skipped — zlib — CVEs: CVE-50","owner-decision issue: skipped — zlib1g — CVEs: CVE-50"]
print("OK" if pl==want else "BAD %r"%pl)
R6
)"
eq "$r6" "OK" && ok || no "undelivered issues keyed by issue identity" "$r6"

echo "=== LR-32: one bump PR per (module, version) target (handoff 0007, owner-ratified Sep 28) ==="
begin "lr32-one-pr-per-target-idempotent" "live-mode probe (shim, no real delivery): one CVE needing two modules -> TWO branches; two CVEs on one target -> ONE PR carrying both; 0.22.0 and v0.22.0 are one target; a second identical run changes nothing; a new CVE on a known target updates the SAME PR; the PR list lists each PR once with all its CVEs"
lr="$(rm -rf "$WORK/lr32" && mkdir -p "$WORK/lr32" && env AUDITOR_GIT_SHIM_LOG="$WORK/lr32/shim.log" "$PY" - "$WORK/lr32" <<'LR'
import importlib.util,os,sys
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
log=os.environ["AUDITOR_GIT_SHIM_LOG"]
def row(cve,mod,frm,to,sec=3): return {"id":cve,"section":sec,"action":"","fix_bump":{"cve":cve,"module":mod,"from":frm,"to":to}}
def run(rs):
    w=[]; errs=R._deliver_bumps(rs,"2026-09-28","abcdef1234567890",False,w)
    return errs
rows=[row("CVE-1","example.org/a","0.16.0","0.22.0"), row("CVE-1","example.org/b","1.0.0","1.2.0"),   # one CVE, two modules
      row("CVE-2","example.org/a","v0.17.3","v0.22.0")]                                             # same target as CVE-1/a
e1=run(rows)
L=open(log).read().splitlines()
creates=[l for l in L if l.startswith("gh pr create")]; pushes=[l for l in L if l.startswith("gh api graphql createCommitOnBranch")]; unsigned=[l for l in L if l.startswith(("git commit","git push"))]
branches=sorted({l.split(" --head ")[1].split()[0] for l in creates})
first_ok=(e1==[] and branches==["auditor/bump-example.org-a-0.22.0","auditor/bump-example.org-b-1.2.0"] and len(creates)==2 and len(pushes)==2 and not unsigned
          and any("CVE-1, CVE-2" in l for l in creates if "example.org-a" in l)
          and rows[0]["fix_pr_url"]==rows[2]["fix_pr_url"]!=rows[1]["fix_pr_url"])
n0=len(L)
e2=run([dict(r, fix_pr_url=None, action="") for r in rows])                        # identical second run
L2=open(log).read().splitlines()[n0:]
second_ok=(e2==[] and not any(l.startswith(("gh api graphql","git push","gh pr create","gh pr edit")) for l in L2)
           and sorted(l for l in L2 if l.startswith("UNCHANGED"))==["UNCHANGED auditor/bump-example.org-a-0.22.0","UNCHANGED auditor/bump-example.org-b-1.2.0"])
n1=n0+len(L2)
e3=run([dict(r, fix_pr_url=None, action="") for r in rows]+[row("CVE-3","example.org/b","1.1.0","1.2.0")])   # new CVE, known target
L3=open(log).read().splitlines()[n1:]
third_ok=(not any(l.startswith("gh pr create") for l in L3) and any(l.startswith("gh pr edit auditor/bump-example.org-b-1.2.0") for l in L3)
          and "UNCHANGED auditor/bump-example.org-a-0.22.0" in L3)
secs={n:[] for n in range(1,8)}; secs[3]=rows
pl=R._pr_list([],rows,secs,False,None,None,False)
list_ok=(len(pl)==2 and any("CVEs: CVE-1, CVE-2" in l and "SHIM-bump-example.org-a-0.22.0" in l for l in pl)
         and any(l.endswith("SHIM-bump-example.org-b-1.2.0") and "CVEs: CVE-1 " in l for l in pl))
print("OK" if (first_ok and second_ok and third_ok and list_ok) else "BAD first=%s second=%s third=%s list=%s pl=%r creates=%r"%(first_ok,second_ok,third_ok,list_ok,pl,creates))
LR
)"; lr="$(printf '%s\n' "$lr" | tail -1)"
eq "$lr" "OK" && ok || no "one PR per target, idempotent re-run, same PR updated" "$lr"

begin "panel-1-parse-panel-reads-one-scanners-findings-from-the-verdict" "the auditor reads the scanner panel's verdict.json (the rescan's own tally): parse_panel(path, scanner) returns exactly the findings that scanner reported, one record per CVE+package even when several images carry it (the images are kept), and a verdict with no findings array is a parse error, never an empty list"
pv="$WORK/panel-verdict.json"
cat > "$WORK/mkpv.py" <<'PYEOF'
import json, os, sys
sys.path.insert(0, ".github/agent/bin")
from auditorlib import parsers as P
imgs = P.panel_images()                     # the six images the panel fixes (bin/panel.py EXPECTED)
CNT = {"grype": 10, "scout": 10, "inspector": 9, "google": 9}
images = {}
for im in sorted(imgs):
    exp = [s for s in P.PANEL_SCANNERS if P.panel_expected(s, im)]
    dnr = ["google", "scout"] if im == os.environ["DBG"] else []
    dnr = [s for s in dnr if s in exp]
    ran = sorted(s for s in exp if s not in dnr)
    images[im] = {"counts": {s: CNT[s] for s in ran}, "did_not_run": sorted(dnr), "ran": ran, "counts_for_day": len(ran) >= 3}
def f(im, vid, pkg, ver, seen, purls):
    det = {s_: ({"severity": "high", "fixed_version": "9.9", "aliases": ["GHSA-aaaa-bbbb-cccc"]} if s_ == "grype" else ({"severity": "critical"} if s_ == "inspector" else {})) for s_ in seen}
    for s_ in det:
        if purls: det[s_]["purl"] = purls[0]                  # each scanner's own package URL (handoff 0601); none where the finding names none
    return {"image": im, "id": vid, "package": pkg, "version": ver, "seen_by": sorted(seen), "of": len(images[im]["ran"]),
            "unique": len(seen) == 1, "status": "unique" if len(seen) == 1 else "report", "purls": purls, "details": det}
d = {"images": images,
     "not_counted": sorted(i for i, st in images.items() if not st["counts_for_day"]),
     "scanner_failures": sorted("%s on %s" % (s, i) for i, st in images.items() for s in st["did_not_run"]),
     "findings": [f("production-amd64", "CVE-2099-0001", "openssl", "3.0.1", ["grype", "inspector", "scout"], ["pkg:apk/wolfi/openssl@3.0.1"]),
                  f("production-arm64", "CVE-2099-0001", "openssl", "3.0.1", ["grype", "inspector"], ["pkg:apk/wolfi/openssl@3.0.1"]),
                  f("production-amd64", "CVE-2099-0002", "zlib", "1.3", ["inspector"], []),
                  f("production-amd64", "CVE-2099-0003", "curl", "8.0", ["inspector", "grype"], ["pkg:apk/wolfi/curl@8.0"]),
                  f("production-arm64", "CVE-2099-0003", "curl", "8.0", ["inspector"], ["pkg:apk/wolfi/curl@8.0"])],
     "vex_covered": [{"image": "production-amd64", "scanner": "inspector", "id": "CVE-2099-0009", "package": "busybox", "version": "1.36"}]}
d["issue"] = P._panel_module().render_issue([x for x in d["findings"] if x["status"] == "report"])   # the tally's own renderer
d["unique"] = [x for x in d["findings"] if x["unique"]]
d["exit"] = 2 if (d["not_counted"] or d["scanner_failures"]) else (1 if any(x["status"] == "report" for x in d["findings"]) else 0)
json.dump(d, open(sys.argv[1], "w"), indent=1)
PYEOF
"$PY" "$WORK/mkpv.py" "$pv"
r="$(MF="$pv" "$PY" - <<'PYEOF'
import importlib.util, os, sys, json
sys.path.insert(0, ".github/agent/bin")
from auditorlib import parsers as P
g = P.parse_panel(os.environ["MF"], "grype"); i = P.parse_panel(os.environ["MF"], "inspector"); s = P.parse_panel(os.environ["MF"], "scout"); gg = P.parse_panel(os.environ["MF"], "google")
bad = os.environ["MF"] + ".bad"; json.dump({"images": {}}, open(bad, "w"))
try:
    P.parse_panel(bad, "grype"); err = "none"
except P.ParseError:
    err = "ParseError"
carried = [x for x in i if (x.get("extra") or {}).get("carried")]       # the tally's vex_covered entry for Inspector rides along flagged carried (rc-5b fix 5)
print("grype=%d inspector=%d(+%d carried) scout=%d google=%d imgs=%s err=%s scanner=%s id=%s purl=%s" % (
  len(g), len(i) - len(carried), len(carried), len(s), len(gg), ",".join(sorted(g[0]["extra"]["images"])), err, g[0]["scanner"], g[0]["finding_id"], g[0]["purl"]))
PYEOF
)"
{ eq "$r" "grype=2 inspector=3(+1 carried) scout=1 google=0 imgs=production-amd64,production-arm64 err=ParseError scanner=grype id=CVE-2099-0001 purl=pkg:apk/wolfi/openssl@3.0.1"; } && ok || no "parse_panel: grype 2 (0001 deduped over two images, 0003), inspector 3, scout 1, google 0; malformed verdict is a ParseError" "[$r]"

begin "panel-2-panel-inventory-records-a-scanner-that-missed-an-image-as-did-not-run" "from the verdict, a scanner counts as ran only if it ran on EVERY image it was expected on; one image where it did not run makes it 'did not run' (never clean), named with the image; the report path is null for it and the verdict path for the rest; the quorum rule is not recomputed here (the panel owns it)"
r="$(MF="$pv" "$PY" - <<'PYEOF'
import importlib.util, os
spec=importlib.util.spec_from_file_location("m",".github/agent/bin/auditor-manifest.py"); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
rep, st = M.panel_inventory(os.environ["MF"])
print("ran=%s null=%s ginfo=%s/%s greason=%s pkgs=%d" % (
  ",".join(s for s in M.PANEL_SCANNERS if st[s]["ran"]),
  ",".join(s for s in M.PANEL_SCANNERS if rep[s] is None),
  st["grype"]["images_ran"], st["grype"]["images_expected"],
  os.environ["DBG"] in (st["google"]["reason"] or "") and "google" in rep and rep["google"] is None,
  st["grype"]["package_count"]))
PYEOF
)"
{ eq "$r" "ran=grype,inspector null=scout,google ginfo=${NIMG}/${NIMG} greason=True pkgs=$((10 * NIMG))"; } && ok || no "panel_inventory: grype and inspector ran everywhere, scout and google missed the second variant's amd64 image (null report, reason names the image)" "[$r]"

begin "panel-3-panel-block-never-hides-a-missing-verdict" "the manifest always carries a 'panel' block: all four did-not-run (reason: no directory given) when no panel directory was given, the four scanners' status and reports when verdict.json is there, and when the directory has no verdict.json every panel scanner is recorded 'did not run' with the reason (the panel's audits cannot run, never a clean pass)"
pd="$WORK/panel-dir"; rm -rf "$pd" "$WORK/panel-empty"; mkdir -p "$pd" "$WORK/panel-empty"; cp "$pv" "$pd/verdict.json"
r="$(PD="$pd" PE="$WORK/panel-empty" "$PY" - <<'PYEOF'
import importlib.util, os
spec=importlib.util.spec_from_file_location("m",".github/agent/bin/auditor-manifest.py"); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
a = M.panel_block(None); b = M.panel_block(os.environ["PD"]); c = M.panel_block(os.environ["PE"])
print("none=%s ok=%s,%s empty=%s,%s" % (a["verdict"] is None and all(a["scanner_status"][s]["reason"] == "no panel-evidence directory was given" for s in M.PANEL_SCANNERS), b["verdict"].endswith("verdict.json"), ",".join(s for s in M.PANEL_SCANNERS if b["scanner_status"][s]["ran"]),
  all(c["scanner_reports"][s] is None for s in M.PANEL_SCANNERS), all("verdict.json" in c["scanner_status"][s]["reason"] for s in M.PANEL_SCANNERS)))
PYEOF
)"
{ eq "$r" "none=True ok=True,grype,inspector empty=True,True"; } && ok || no "panel_block: None without a directory; four statuses with a verdict; all four did-not-run (reason names verdict.json) without one" "[$r]"

begin "panel-4-malformed-or-inconsistent-verdicts-are-refused-everywhere" "rounds 1 and 2 of cache#466 (both Codex seats): a verdict that is structurally wrong, truncated or internally inconsistent never yields a clean inventory: parse_panel raises and panel_block records all four 'did not run'. Refused: no findings array, empty images, a missing image (truncated verdict), an extra unknown image, a non-object or incomplete finding, a seen_by scanner that did not run on that image, a wrong 'of' or 'unique' or 'status', a duplicate scanner in ran, a scanner in both ran and did_not_run, an unknown scanner name, a scanner listed in neither list where the rule expects it, a ran scanner with a zero, missing or boolean count, a wrong counts_for_day"
r="$(MF="$pv" WK="$WORK" "$PY" - <<'PYEOF'
import importlib.util, os, sys, json, copy
sys.path.insert(0, ".github/agent/bin")
from auditorlib import parsers as P
spec=importlib.util.spec_from_file_location("m",".github/agent/bin/auditor-manifest.py"); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
base = json.load(open(os.environ["MF"])); wk = os.environ["WK"]
M1 = {}
def case(name):
    def deco(fn):
        M1[name] = fn; return fn
    return deco
@case("nofind")
def _(d): del d["findings"]
@case("noimg")
def _(d): d["images"] = {}
@case("trunc")
def _(d): del d["images"]["fips-arm64"]
@case("extraimg")
def _(d): d["images"]["weird-amd64"] = copy.deepcopy(d["images"]["production-amd64"])
@case("null")
def _(d): d["findings"].append(None)
@case("incomplete")
def _(d): del d["findings"][0]["package"]
@case("ghost")
def _(d): d["findings"][1]["seen_by"] = ["grype", "inspector", "google"]
@case("of")
def _(d): d["findings"][0]["of"] = 3
@case("uniq")
def _(d): d["findings"][2]["unique"] = False
@case("status")
def _(d): d["findings"][2]["status"] = "report"
@case("img")
def _(d): d["findings"][0]["image"] = "nowhere-amd64"
@case("dup")
def _(d): d["images"]["production-amd64"]["ran"].append("grype")
@case("overlap")
def _(d): d["images"]["production-amd64"]["did_not_run"].append("grype")
@case("unknown")
def _(d): d["images"]["production-amd64"]["ran"].append("trivy")
@case("unlisted")
def _(d):
    st = d["images"]["production-arm64"]; st["ran"].remove("scout"); st["counts"].pop("scout")
@case("zero")
def _(d): d["images"]["production-amd64"]["counts"]["grype"] = 0
@case("nocount")
def _(d): d["images"]["production-amd64"]["counts"].pop("grype")
@case("bool")
def _(d): d["images"]["production-amd64"]["counts"]["grype"] = True
@case("cfd")
def _(d): d["images"][os.environ["DBG"]]["counts_for_day"] = True
@case("uniqlist")
def _(d): d["unique"] = []
@case("dupa")
def _(d): d["findings"].append(dict(d["findings"][0], seen_by=["grype"], unique=True, status="unique"))
@case("dupb")
def _(d): d["findings"].insert(0, dict(d["findings"][0], seen_by=["grype"], unique=True, status="unique"))
@case("exit")
def _(d): d["exit"] = 0
@case("vexempty")
def _(d): d["vex_covered"] = [{}]
@case("vexghost")
def _(d): d["vex_covered"][0]["scanner"] = "grype"
@case("vexnoimg")
def _(d): d["vex_covered"][0]["image"] = "nowhere-amd64"
@case("vexarm")
def _(d): d["vex_covered"][0].update(scanner="google", image="production-arm64")
@case("purl")
def _(d): d["findings"][0]["purls"] = ["pkg:apk/wolfi/other@3.0.1"]
@case("offloat")
def _(d): d["findings"][0]["of"] = 4.0
@case("issueempty")
def _(d): d["issue"] = ""
@case("issuestale")
def _(d): d["issue"] = "a stale issue text"
@case("nested")
def _(d): d["images"]["production-amd64"]["ran"].append({"x": 1})
@case("nodetails")
def _(d): del d["findings"][0]["details"]
@case("detghost")
def _(d): d["findings"][0]["details"]["google"] = {}
@case("detmissing")
def _(d): del d["findings"][0]["details"]["scout"]
@case("detsev")
def _(d): d["findings"][0]["details"]["grype"]["severity"] = "HIGH"
@case("detunknownkey")
def _(d): d["findings"][0]["details"]["grype"]["cvss"] = 9.8
@case("detfix")
def _(d): d["findings"][0]["details"]["grype"]["fixed_version"] = ""
@case("detalias")
def _(d): d["findings"][0]["details"]["grype"]["aliases"] = ["GHSA-aaaa-bbbb-cccc", "GHSA-aaaa-bbbb-cccc"]
@case("detkev")
def _(d): d["findings"][0]["details"]["grype"]["known_exploited"] = "yes"
@case("topextra")
def _(d): d["note"] = "x"
@case("imgextra")
def _(d): d["images"]["production-amd64"]["extra"] = 1
@case("findextra")
def _(d): d["findings"][0]["extra"] = 1
@case("vexextra")
def _(d): d["vex_covered"][0]["extra"] = 1
@case("purlsyntax")
def _(d): d["findings"][0]["purls"] = ["openssl@3.0.1"]
@case("issuewrong")
def _(d): d["issue"] = d["issue"].replace("openssl", "wrong-package")
@case("vexid")
def _(d): d["vex_covered"][0]["id"] = "CVE 1\nx"
@case("vexpkg")
def _(d): d["vex_covered"][0]["package"] = "a\x00b"
@case("vexver")
def _(d): d["vex_covered"][0]["version"] = "1\n2"
@case("purlq")
def _(d): d["findings"][0]["purls"] = ["pkg:apk/wolfi/openssl@3.0.1?broken"]
@case("purlctl")
def _(d): d["findings"][0]["purls"] = ["pkg:apk/wolfi/openssl@3.0.1?x=\x00"]
@case("uniqtype")
def _(d): d["unique"][0] = dict(d["unique"][0], unique=1, of=float(d["unique"][0]["of"]))
RAW = {"dupkey": lambda t: t[:-1] + ', "findings": []}', "dupkey2": lambda t: t[:-1] + ', "images": {}}'}
@case("dupkey")
def _(d): pass
@case("dupkey2")
def _(d): pass
@case("idspace")
def _(d): d["findings"][2]["id"] = "CVE 2099 0002"; d["unique"] = [x for x in d["findings"] if x["unique"]]
out = []
for name, fn in M1.items():
    d = copy.deepcopy(base); fn(d)
    dd = os.path.join(wk, "pv-" + name); os.makedirs(dd, exist_ok=True); vp = os.path.join(dd, "verdict.json")
    txt = json.dumps(d)
    open(vp, "w").write(RAW[name](txt) if name in RAW else txt)
    try:
        P.parse_panel(vp, "grype"); pp = "accepted"
    except P.ParseError:
        pp = "refused"
    pb = M.panel_block(dd)
    out.append("%s=%s/%s" % (name, pp, "all-down" if all(not pb["scanner_status"][s]["ran"] for s in M.PANEL_SCANNERS) else "SOME-RAN"))
print(" ".join(out))
PYEOF
)"
exp="$(for n in nofind noimg trunc extraimg null incomplete ghost of uniq status img dup overlap unknown unlisted zero nocount bool cfd uniqlist dupa dupb exit vexempty vexghost vexnoimg vexarm purl offloat issueempty issuestale nested nodetails detghost detmissing detsev detunknownkey detfix detalias detkev topextra imgextra findextra vexextra purlsyntax issuewrong vexid vexpkg vexver purlq purlctl uniqtype dupkey dupkey2 idspace; do printf '%s=refused/all-down ' "$n"; done)"
{ eq "$r" "${exp% }"; } && ok || no "every malformed, truncated or inconsistent verdict is refused by parse_panel and records all four scanners 'did not run' in panel_block" "[$r]"

begin "panel-5-corroboration-is-kept-per-image" "round 1 of cache#466 (seat B): the same CVE on two images keeps its own 'seen by N of M' and its own uniqueness per image; one image's numbers are never attached to another image"
r="$(MF="$pv" "$PY" - <<'PYEOF'
import os, sys
sys.path.insert(0, ".github/agent/bin")
from auditorlib import parsers as P
g = P.parse_panel(os.environ["MF"], "grype")[0]["extra"]["by_image"]
i = P.parse_panel(os.environ["MF"], "inspector")
z = [f for f in i if f["finding_id"] == "CVE-2099-0002"][0]["extra"]["by_image"]
c = [f for f in i if f["finding_id"] == "CVE-2099-0003"][0]["extra"]["by_image"]
g0 = P.parse_panel(os.environ["MF"], "grype")[0]; i0 = [f for f in i if f["finding_id"] == "CVE-2099-0001"][0]
print("sev=%s/%s fix=%s aliases=%s inspector_sev=%s" % (g0["severity"], g0["fixed_version"], g0["fixed_version"], ",".join(g0["aliases"]), i0["severity"]), end=" ")
print("amd64=%d/%d arm64=%d/%d unique_zlib=%s curl_amd64=%s curl_arm64=%s" % (len(g["production-amd64"]["seen_by"]), g["production-amd64"]["of"], len(g["production-arm64"]["seen_by"]), g["production-arm64"]["of"], z["production-amd64"]["unique"], c["production-amd64"]["unique"], c["production-arm64"]["unique"]))
PYEOF
)"
{ eq "$r" "sev=high/9.9 fix=9.9 aliases=CVE-2099-0001,GHSA-aaaa-bbbb-cccc inspector_sev=critical amd64=3/4 arm64=2/3 unique_zlib=True curl_amd64=False curl_arm64=True"; } && ok || no "grype's CVE-2099-0001: 3 of 4 on amd64, 2 of 3 on arm64; inspector's curl finding is not unique on amd64 and unique on arm64 (same deduplicated record)" "[$r]"

########################################################################
echo "=== 0600 option A, PR 2b-1: the auditor reads the four panel scanners ==="

begin "panel-6-classify-reads-the-four-and-writes-no-per-scanner-files" "auditor-classify on a panel manifest: the findings come from the verdict, the false positive still gets its VEX statement and section 5, and no per-scanner ignore files (ignores/<scanner>/) are written (rule 4: the VEX is the only exception)"
o="$WORK/pm-ok-classify"; rm -rf "$o"
run "$PY" "$BIN/auditor-classify.py" --manifest "$WORK/pm-ok/manifest.json" --adjudicator "$STUB" --out "$o" && {
  st="$(vf "$o/vex/CVE-2016-2781.openvex.json" CVE-2016-2781 's["status"]')"
  s5="$(sect_ids "$o/report.md" 5)"
  igdirs="$(ls -d "$o"/ignores/*/ 2>/dev/null | wc -l | tr -d ' ')"
  { eq "$st" "not_affected" && printf '%s' "$s5" | grep -q 'CVE-2016-2781' && eq "$igdirs" "0"; } \
    && ok || no "panel manifest classified: FP not_affected (log key on the panel purl) in section 5, no ignores/<scanner> dirs" "status=$st sec5=[$s5] ignoredirs=$igdirs"; }

begin "panel-7-run-takes-its-quorum-from-the-panel" "auditor-run on a panel manifest: the day is AUDIT COMPLETE only when no image is uncounted by the panel (rule 3: three scanners per image); the report names the four panel scanners, shows each scanner's severity for a finding and the highest is the one policy uses, and no old scanner (trivy, osv-scanner, snyk) is mentioned"
o="$WORK/pm-ok-run"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-ok/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  complete="$(grep -qi 'AUDIT COMPLETE' "$o/report.md" && echo yes || echo no)"
  names="$(for n in grype scout inspector google; do grep -qi "$n" "$o/report.md" && printf 'y' || printf 'n'; done)"
  old="$(grep -ciE 'trivy|osv-scanner|snyk' "$o/report.md")"
  { eq "$complete" "yes" && eq "$names" "yyyy" && eq "$old" "0"; } \
    && ok || no "panel-ok run: complete, four panel scanners named, none of the old three" "complete=$complete names=$names old_mentions=$old"; }

begin "panel-8-an-uncounted-image-or-a-missing-verdict-is-never-complete" "an image the panel did not count (fewer than three scanners ran on it), or a missing/invalid verdict, makes the day AUDIT INCOMPLETE and the report names why (the uncounted image / the missing verdict); a scanner that did not run is listed as did not run"
o="$WORK/pm-unc-run"; rm -rf "$o"; : > "$LEDGER"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-uncounted/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; {
  inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"; why="$(grep -qi "$DBG" "$o/report.md" && echo yes || echo no)"
  { eq "$inc" "yes" && eq "$why" "yes"; } && ok || no "uncounted image: incomplete and named" "incomplete=$inc names_image=$why"; }
o="$WORK/pm-nop-run"; rm -rf "$o"; : > "$LEDGER"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-nopanel/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; {
  inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"; why="$(grep -qi 'verdict' "$o/report.md" && echo yes || echo no)"
  { eq "$inc" "yes" && eq "$why" "yes"; } && ok || no "no verdict: incomplete and says so" "incomplete=$inc mentions_verdict=$why"; }

begin "panel-9-report-shows-each-scanners-severity" "for a finding the panel's scanners rate differently, the report row shows each scanner's severity (grype high, inspector critical) and policy uses the highest (critical)"
o="$WORK/pm-ok-run"
{ grep 'CVE-2011-3374' "$o/report.md" | grep -qi 'critical' && grep 'CVE-2011-3374' "$o/report.md" | grep -qi 'grype.*high\|high.*grype'; } \
  && ok || no "row for CVE-2011-3374 shows critical (highest) and grype's high" "$(grep 'CVE-2011-3374' "$o/report.md" | head -3 | cut -c1-300)"

begin "panel-10-a-panel-run-writes-and-delivers-the-vex-only" "in panel mode the run's suppression package holds the OpenVEX document and NO .snyk or osv-scanner.toml (scanner-panel rule 4: the VEX is the only exception)"
o="$WORK/pm-ok-run"
{ [ -s "$o/suppressions/fosterstack-cache.openvex.json" ] && [ ! -e "$o/suppressions/.snyk" ] && [ ! -e "$o/suppressions/osv-scanner.toml" ]; } \
  && ok || no "suppressions/ has the VEX and neither .snyk nor osv-scanner.toml" "$(ls -A "$o/suppressions" 2>&1 | tr '\n' ' ')"

begin "panel-11-a-scanner-missing-everywhere-is-never-a-complete-day" "even when every image keeps three scanners (rule 3 quorum), a panel scanner that did not run anywhere it is expected is a pipeline failure: the day is AUDIT INCOMPLETE and names it (the panel's own exit 2)"
o="$WORK/pm-gg-run"; rm -rf "$o"; : > "$LEDGER"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-googlegone/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; {
  inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"; nm="$(grep -i 'AUDIT INCOMPLETE' "$o/report.md" | grep -qi 'google' && echo yes || echo no)"
  gt="$(awk '/^::group::google/{f=1} f{print} /^::endgroup::/{if(f)exit}' "$o/reports/scanner-tables.txt")"
  tc="$(printf '%s' "$gt" | grep -qi 'clean' && echo clean || echo notclean)"; ti="$(printf '%s' "$gt" | grep -qi 'scan incomplete' && echo yes || echo no)"
  { eq "$inc" "yes" && eq "$nm" "yes" && eq "$tc" "notclean" && eq "$ti" "yes"; } && ok || no "google missing on every amd64 image: incomplete, google named, its scanner table says scan incomplete and never clean" "incomplete=$inc names_google=$nm table=[$gt]"; }

begin "panel-12-a-partial-failure-keeps-the-findings-the-scanner-did-report" "a scanner that missed one image but reported on another still contributes its findings: the finding only google saw (on production-amd64) is in the report, the day is incomplete, and the report says google did not run on the image it missed"
o="$WORK/pm-part-run"; rm -rf "$o"; : > "$LEDGER"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-partial/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; {
  fnd="$(grep -c 'CVE-2099-7777' "$o/report.md")"; inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"; why="$(grep -qi "did not run on: $DBG" "$o/report.md" && echo yes || echo no)"
  { [ "$fnd" -ge 1 ] && eq "$inc" "yes" && eq "$why" "yes"; } && ok || no "finding kept, day incomplete, partial miss named" "finding_lines=$fnd incomplete=$inc names_image=$why"; }

begin "panel-13-each-scanners-severity-is-always-shown" "a finding every scanner rates the same still shows each scanner's severity (not only when they disagree)"
o="$WORK/pm-multi-run"; rm -rf "$o"; : > "$LEDGER"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-multi/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; {
  row="$(grep '^- CVE-2099-5555 ' "$o/report.md" | head -1)"
  printf '%s' "$row" | grep -qi 'severity by scanner: grype high, inspector high' && ok || no "row for CVE-2099-5555 lists grype high, inspector high" "$row"; }

begin "panel-14-seen-by-n-of-m-is-shown-per-image" "a finding seen by 3 of 4 scanners on one image and 2 of 3 on another shows each image's own corroboration in the report row"
o="$WORK/pm-multi-run"
{ row="$(grep '^- CVE-2099-6666 ' "$o/report.md" | head -1)"; printf '%s' "$row" | grep -q 'production-amd64 3 of 4' && printf '%s' "$row" | grep -q 'production-arm64 2 of 3'; } \
  && ok || no "row for CVE-2099-6666 shows production-amd64 3 of 4 and production-arm64 2 of 3" "$(grep 'CVE-2099-6666' "$o/report.md" | head -3 | cut -c1-300)"
begin "panel-16-a-scanner-that-reported-without-a-severity-is-shown-as-not-rated" "scout saw CVE-2099-6666 but gave no severity: the row lists it as 'scout not rated' beside the severities the others gave (never dropped, never guessed)"
{ row="$(grep '^- CVE-2099-6666 ' "$o/report.md" | head -1)"; printf '%s' "$row" | grep -q 'scout not rated'; } \
  && ok || no "row for CVE-2099-6666 lists scout as not rated" "$(grep '^- CVE-2099-6666 ' "$o/report.md" | head -1 | cut -c1-300)"

begin "panel-15-completion-comes-from-the-verdict-not-from-the-manifests-copies" "a manifest whose panel summary says 'nothing uncounted, no failures' but whose verdict is missing, or whose verdict says an image is uncounted, is still AUDIT INCOMPLETE: the run derives completion from the validated verdict itself"
"$PY" - "$WORK" <<'PYEOF'
import json, sys, os, shutil
w = sys.argv[1]
src = os.path.join(w, "pm-ok", "manifest.json")
m = json.load(open(src)); m["panel"] = dict(m["panel"], verdict=None, not_counted=[], scanner_failures=[])     # contradictory: no verdict, but a clean-looking summary
os.makedirs(os.path.join(w, "pm-contra1"), exist_ok=True); json.dump(m, open(os.path.join(w, "pm-contra1", "manifest.json"), "w"))
m2 = json.load(open(os.path.join(w, "pm-uncounted", "manifest.json"))); m2["panel"] = dict(m2["panel"], not_counted=[], scanner_failures=[])   # the verdict says the second variant's amd64 image is uncounted
os.makedirs(os.path.join(w, "pm-contra2"), exist_ok=True); json.dump(m2, open(os.path.join(w, "pm-contra2", "manifest.json"), "w"))
m3 = json.load(open(src)); bad = os.path.join(w, "pm-contra3-verdict.json"); open(bad, "w").write("{not json")      # a verdict path that does not parse
m3["panel"] = dict(m3["panel"], verdict=bad, not_counted=[], scanner_failures=[])
os.makedirs(os.path.join(w, "pm-contra3"), exist_ok=True); json.dump(m3, open(os.path.join(w, "pm-contra3", "manifest.json"), "w"))
PYEOF
o="$WORK/pm-contra1-run"; rm -rf "$o"; : > "$LEDGER"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-contra1/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; i1="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"
o="$WORK/pm-contra2-run"; rm -rf "$o"; : > "$LEDGER"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-contra2/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; i2="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"; n2="$(grep -qi "$DBG" "$o/report.md" && echo yes || echo no)"
o="$WORK/pm-contra3-run"; rm -rf "$o"; : > "$LEDGER"
rc3=0; "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$WORK/pm-contra3/manifest.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || rc3=$?
i3="$( { [ "$rc3" != 0 ] && ! grep -qi 'AUDIT COMPLETE' "$o/report.md" 2>/dev/null; } && echo yes || echo no)"       # an unparseable verdict stops the run (manifest invalid), never a complete day
{ eq "$i1" "yes" && eq "$i2" "yes" && eq "$n2" "yes" && eq "$i3" "yes"; } && ok || no "contradictory manifests: no verdict, an unparseable verdict, or a verdict with an uncounted image -> incomplete (naming the image)" "null-verdict=$i1 uncounted=$i2 names_image=$n2 unparseable=$i3"

echo "=== rc-5b item 11 (R1): the lift trigger is {carrier, min_version, component, component_min_version}," \
     "checked by shape and compared on the daily recheck ==="
begin "rc5b11-trigger-tests-pass-and-each-cut-of-the-new-code-is-caught" \
  "the LiftTrigger unit tests pass on the driver, and fail on a copy with the shape check, the unmet skip or the \
version comparison cut out"
t11_ok=yes; t11_detail=""
mr="$WORK/rc5b11-mr-control"; rm -rf "$mr"; mkdir -p "$mr/.github"
cp -R .github/agent "$mr/.github/agent"; cp -R bin "$mr/bin"
( cd "$mr/.github/agent/bin/tests" && "$PY" -m unittest test_cov_run.LiftTrigger >/dev/null 2>&1 ) \
  || { t11_ok=no; t11_detail=" [the uncut copy fails the unit tests]"; }
SHAPE_OLD='    if not isinstance(t, dict) or set(t) != _LIFT_KEYS or not all(isinstance(v, str) for v in t.values()):'
CMP_OLD='    return (pad(x[0]), x[1]) >= (pad(y[0]), y[1])'
for m in "shape|$SHAPE_OLD|    if False:" "unmet-skip|and not trig_unmet:|:" "compare|$CMP_OLD|${CMP_OLD/>=/>}"; do
  IFS='|' read -r name old new <<<"$m"
  mr="$WORK/rc5b11-mr-$name"; rm -rf "$mr"; mkdir -p "$mr/.github"
  cp -R .github/agent "$mr/.github/agent"; cp -R bin "$mr/bin"
  if ! "$PY" - "$mr/.github/agent/bin/auditor-run.py" "$old" "$new" <<'PY'
import sys
src = open(sys.argv[1]).read()
if src.count(sys.argv[2]) != 1:
    sys.exit(1)
open(sys.argv[1], "w").write(src.replace(sys.argv[2], sys.argv[3]))
PY
  then t11_ok=no; t11_detail="$t11_detail [$name: mutation site not found exactly once]"; continue; fi
  if ( cd "$mr/.github/agent/bin/tests" && "$PY" -m unittest test_cov_run.LiftTrigger >/dev/null 2>&1 ); then
    t11_ok=no; t11_detail="$t11_detail [$name: the unit tests still pass]"
  fi
done
eq "$t11_ok" "yes" && ok || no "unit tests pass uncut and fail on every cut" "$t11_detail"

# rc-5b fix 14 (R13 code): every model refusal is logged to the report (finding, attempt, model role - no model identifier), a token-budget stop is listed and opens
# no owner issue (the repeated-unsettled case is rc5b-15's), and the header prints each scanner's version and database date or "not recorded by <scanner>", never a blank.
begin "rc5b-14-refusals-stop-issue-and-scanner-versions" "refusals (also a pullability or narrative one) are logged with their roles and billed, a token-budget stop opens no owner issue (the in-run iteration stop is gone: it could never fire, so the repeated-unsettled case is the run counter's), the lists show their full counts, and the header fields are escaped"
r14="$("$PY" - "$FXRUN" <<'PP' 2>&1 | tail -1
import sys,os,io,contextlib,importlib.util,tempfile,json,re,subprocess,copy
FX=sys.argv[1]; tmp=tempfile.mkdtemp()
sys.path.insert(0,".github/agent/bin")
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
def adj(usage):
    fa=tempfile.mktemp(suffix=".py"); open(fa,"w").write("import json,sys\nfor line in sys.stdin:\n    sys.stdout.write(json.dumps({\"refused\":True,\"token_usage\":%d})+\"\\n\")\n    sys.stdout.flush()\n"%usage); return fa
v0=json.load(open(FX+"/panel-mediumnofix/verdict.json"))
def manifest(nfind, name, ver="v1.2.3"):
    d=tmp+"/"+name; os.makedirs(d, exist_ok=True)
    v=copy.deepcopy(v0); f0=v["findings"][0]; fs=[]
    for i in range(nfind):
        f=copy.deepcopy(f0); f["id"]="CVE-2099-92%02d"%i; f["package"]="libmed%d"%i
        f["purls"]=["pkg:deb/debian/libmed%d@1?arch=amd64&distro=debian-12.0"%i]; f["details"]["grype"]["purl"]=f["purls"][0]; fs.append(f)
    v["findings"]=fs; v["unique"]=fs
    json.dump(v,open(d+"/verdict.json","w"))
    m=json.load(open(FX+"/manifest-mediumnofix.json"))
    for s in m["scanner_reports"]: m["scanner_reports"][s]=d+"/verdict.json"
    m["panel"]["verdict"]=d+"/verdict.json"
    for s in m["panel"]["scanner_reports"]: m["panel"]["scanner_reports"][s]=d+"/verdict.json"
    m["scanner_status"]["grype"]["version"]=ver; m["scanner_status"]["grype"]["db_date"]="2026-10-21"
    json.dump(m,open(d+"/m.json","w")); return d+"/m.json"
def run(mp, fa, dry=True, shim=None, fail=False):
    ws=tmp+"/ws"; os.makedirs(ws, exist_ok=True); os.environ["GITHUB_WORKSPACE"]=ws
    if shim: os.environ["AUDITOR_GIT_SHIM_LOG"]=shim
    else: os.environ.pop("AUDITOR_GIT_SHIM_LOG",None)
    if fail: os.environ["AUDITOR_SHIM_ISSUE_FAIL"]="1"
    else: os.environ.pop("AUDITOR_SHIM_ISSUE_FAIL",None)
    out=tempfile.mkdtemp(dir=tmp)
    with contextlib.redirect_stdout(io.StringIO()):
        R.run(mp,dry,out,"2026-09-24",adjudicator=fa)
    return open(out+"/report.md").read()
bad=[]
def line(rep,start): return [l for l in rep.split("\n") if l.startswith(start)]
name_re=re.compile(r"anthropic|claude|opus|sonnet|gpt-|AUDITOR_MODEL",re.I)
# 1: refusals and stops are listed with counts and roles, and the scanner versions are printed
rep=run(manifest(2,"two"), adj(1))
refs=line(rep,"**Model refusals:**"); vers=line(rep,"**Scanner versions:**")
if not (len(refs)==1 and refs[0].startswith("**Model refusals:** 7: ") and "(primary, primary)" in refs[0] and "CONCLUSION (narrative, primary)" in refs[0]): bad.append("refs %r"%refs)
if line(rep,"**Model stops:**"): bad.append("a stop listed without one")
rep=run(manifest(2,"two-stopped"), adj(R.policy.TOKEN_BUDGET+1))
stops=line(rep,"**Model stops:**")
if not (len(stops)==1 and stops[0].startswith("**Model stops:** 2: ") and "(token budget)" in stops[0]): bad.append("stops %r"%stops)
if not (len(vers)==1 and "grype v1.2.3, database 2026-10-21" in vers[0] and "scout not recorded by scout, database not recorded by scout" in vers[0]): bad.append("vers %r"%vers)
if "none called" in rep: bad.append("role header says none called after refused calls")
if name_re.search(rep): bad.append("a model/vendor name in the report")
# 2: a token-budget stop is section 4 with no owner issue at all
rep=run(manifest(2,"budget"), adj(R.policy.TOKEN_BUDGET+1))
if [l for l in rep.split("\n") if "owner-decision issue" in l]: bad.append("budget stop opened an issue")
if not any("(token budget)" in l for l in line(rep,"**Model stops:**")): bad.append("budget stop not listed")
# 2b: an adjudicator that ERRORS (does not refuse) is an outage, not a stop: one adjudicator-unavailable issue, no stop recorded, the run incomplete
fe=tempfile.mktemp(suffix=".py"); open(fe,"w").write("import sys\nfor line in sys.stdin:\n    sys.exit(3)\n")
rep=run(manifest(2,"errored"), fe)
if line(rep,"**Model stops:**"): bad.append("an errored finding was reported as a stop %r"%line(rep,"**Model stops:**"))
if len([l for l in rep.split("\n") if l.startswith("- would open") and "owner-decision issue" in l and "adjudicator unavailable" in l])!=1: bad.append("no single adjudicator-unavailable issue %r"%[l[:160] for l in rep.split("\n") if "owner-decision" in l or "navailable" in l][:6])
if "AUDIT INCOMPLETE" not in rep: bad.append("an adjudicator outage left the run complete")
# 3: lists show the full count and say they are capped (21 findings x 3 refusals + the narrative one = 64); stops show the full count
rep=run(manifest(21,"many"), adj(1))
refs=line(rep,"**Model refusals:**")
if not (len(refs)==1 and refs[0].startswith("**Model refusals:** 64: ") and refs[0].endswith("; ...")): bad.append("refs cap %r"%[r[:60] for r in refs])
rep=run(manifest(21,"manystop"), adj(R.policy.TOKEN_BUDGET+1))
st=line(rep,"**Model stops:**")
if not (len(st)==1 and st[0].startswith("**Model stops:** 21: ")): bad.append("stops count %r"%[x[:60] for x in st])
# 4: the adjudicator-unavailable title is stable (no count in it)
t1=R.policy.subject("owner-decision: adjudicator unavailable — findings unassessed")
src=open(".github/agent/bin/auditor-run.py").read()
if "adjudicator unavailable — %d findings" in src: bad.append("count in the unavailable title")
# 6: a pullability refusal is logged with its role and billed
st={"tokens":0}
R._pullability(adj(5),{"finding_id":"CVE-P"},st)
if not (st.get("tokens")==5 and st.get("refusals")==[{"finding_id":"CVE-P","attempt":"pullability","role":"primary"}] and "primary" in st.get("roles_used",())): bad.append("pullability refusal %r"%st)
# 7: a narrative refusal is logged and billed too
st={"tokens":0}
R._conclusion(adj(7),{n:[] for n in range(1,8)},json.load(open(manifest(1,"n"))),st)
if not (st.get("tokens")==7 and st.get("refusals")==[{"finding_id":"CONCLUSION","attempt":"narrative","role":"primary"}]): bad.append("narrative refusal %r"%st)
# 8: scanner version text is escaped in the header
rep=run(manifest(1,"esc","v`x`|[1]"), adj(1))
vers=line(rep,"**Scanner versions:**")
if not (len(vers)==1 and "v\\`x\\`\\|\\[1\\]" in vers[0]): bad.append("unescaped version %r"%vers)
print("OK" if not bad else "BAD "+"; ".join(bad))
PP
)"
eq "$r14" "OK" && ok || no "rc-5b fix 14: refusals logged and billed, one stop issue with a stable title, budget stop silent, full counts, failed delivery incomplete, header escaped" "$r14"
# rc-5b fix 15 (REQ-AUD-9 AC3, "a five-iteration stop"; register row 38 and the Sep 16 continuous-scanning rule "a five-iteration loop"; advisor reading, Oct 24): five CONSECUTIVE
# auditor runs in which the same finding is still unsettled open ONE owner-decision issue (stable title, counts in the body). The counts ride in the auditor state (the no-change day's
# artifact), a missing state is reported "counter state missing, counts restart", a corrupt state stops the run (exit 3, nothing written).
begin "rc5b-15-five-consecutive-unsettled-runs-open-one-issue" "(a finding the model refused is in its own issue and not named twice; a count dated after today stops the run before any call) a finding the model leaves unsettled in five consecutive runs is named in ONE owner-decision issue on the fifth (never the fourth), a settled finding restarts at one, a second run on the same day does not count twice, a missing state is said in the run's output, a corrupt state stops the run"
r15="$("$PY" - "$FXRUN" <<'PP' 2>&1 | tail -1
import sys,os,io,contextlib,importlib.util,tempfile,json,re,subprocess,copy
FX=sys.argv[1]; tmp=tempfile.mkdtemp()
sys.path.insert(0,".github/agent/bin")
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
fr=tempfile.mktemp(suffix=".py"); open(fr,"w").write("import json,sys\nfor line in sys.stdin:\n    sys.stdout.write(json.dumps({\"refused\":True,\"token_usage\":1})+\"\\n\")\n    sys.stdout.flush()\n")
fa=tempfile.mktemp(suffix=".py"); open(fa,"w").write("import json,sys\nfor line in sys.stdin:\n    sys.stdout.write(json.dumps({\"category\":\"under_investigation\",\"token_usage\":1})+\"\\n\")\n    sys.stdout.flush()\n")
v0=json.load(open(FX+"/panel-mediumnofix/verdict.json"))
def manifest(nfind, name):
    d=tmp+"/"+name; os.makedirs(d, exist_ok=True)
    v=copy.deepcopy(v0); f0=v["findings"][0]; fs=[]
    for i in range(nfind):
        f=copy.deepcopy(f0); f["id"]="CVE-2099-93%02d"%i; f["package"]="libuns%d"%i
        f["purls"]=["pkg:deb/debian/libuns%d@1?arch=amd64&distro=debian-12.0"%i]; f["details"]["grype"]["purl"]=f["purls"][0]; fs.append(f)
    v["findings"]=fs; v["unique"]=fs
    json.dump(v,open(d+"/verdict.json","w"))
    m=json.load(open(FX+"/manifest-mediumnofix.json"))
    for s in m["scanner_reports"]: m["scanner_reports"][s]=d+"/verdict.json"
    m["panel"]["verdict"]=d+"/verdict.json"
    for s in m["panel"]["scanner_reports"]: m["panel"]["scanner_reports"][s]=d+"/verdict.json"
    json.dump(m,open(d+"/m.json","w")); return d+"/m.json"
shim=tmp+"/shim.log"; ws=tmp+"/ws"; os.makedirs(ws); os.environ["GITHUB_WORKSPACE"]=ws; os.environ["AUDITOR_GIT_SHIM_LOG"]=shim
bad=[]
def day(n, mp, prev, adj=None):
    out=tempfile.mkdtemp(dir=tmp)
    if prev: os.environ["AUDITOR_PREV_STATE"]=prev
    else: os.environ.pop("AUDITOR_PREV_STATE",None)
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):
        R.run(mp,False,out,"2026-10-%02d"%n,adjudicator=adj or fa)
    rep=open(out+"/report.md").read(); st=json.load(open(out+"/.auditor/auditor-state.json"))
    return out+"/.auditor/auditor-state.json", rep, buf.getvalue(), st
def log_count(kind):
    t=open(shim).read() if os.path.exists(shim) else ""
    return len([l for l in t.split("\n") if l.startswith("gh issue "+kind) and "unsettled for" in l])
two=manifest(2,"two"); one=manifest(1,"one")
prev=None; marks=[]
for n in range(1,6):
    prev, rep, out, st = day(n, two, prev)
    miss=("counter state missing, counts restart" in rep, "counter state missing, counts restart" in out)
    if n==1 and miss!=(True,True): bad.append("day1 missing not reported in report and output %r"%(miss,))
    if n>1 and any(miss): bad.append("day%d reported missing"%n)
    marks.append((n, log_count("create")))
    ul=[l for l in rep.split("\n") if l.startswith("**Unsettled-run counts:**")]
    if (n==5) != bool(ul and "owner-decision issue: " in ul[0]): bad.append("day%d: the aggregate issue reference on the report line %r"%(n,ul))
    if (n==5) != ("unsettled for 5 consecutive runs" in rep.split("## 1")[0]): bad.append("day%d: the aggregate issue in the report's section 0"%n)
    if st["unsettled"].get("CVE-2099-9300",{}).get("runs")!=n: bad.append("day%d count %r"%(n,st["unsettled"]))
    if st["verdicts"] or st["pullability"] or st["narrative"] is not None: bad.append("day%d: an incomplete run left something reusable besides the counts (#684's rule) %r"%(n,{k:st[k] for k in ("verdicts","pullability","narrative")}))
if [m for m in marks if m[0]<5 and m[1]]: bad.append("issue before the fifth run %r"%marks)
if marks[-1]!=(5,1): bad.append("no single issue on the fifth run %r"%marks)
body=[l for l in open(shim).read().split("\n") if l.startswith("gh issue create") and "unsettled for" in l]
if not (len(body)==1 and "CVE-2099-9300" in body[0] and "CVE-2099-9301" in body[0] and "5" in body[0]): bad.append("issue body %r"%[b[:200] for b in body])
# the same day twice does not count twice
p5=prev
_, rep, out, st = day(5, two, p5)
if st["unsettled"]["CVE-2099-9300"]["runs"]!=5: bad.append("same day counted twice %r"%st["unsettled"])
# day six: the count is six, the SAME issue is updated (stable title): still one create; the comments are the same-day rerun and day six
prev, rep, out, st = day(6, two, p5)
if st["unsettled"]["CVE-2099-9300"]["runs"]!=6: bad.append("day6 count")
if (log_count("create"), log_count("comment"))!=(1,2): bad.append("title not stable: create/comment %r"%((log_count("create"),log_count("comment")),))
# a finding that is gone (settled) restarts at one when it comes back
prev, rep, out, st = day(7, one, prev)
if "CVE-2099-9301" in st["unsettled"]: bad.append("settled finding kept its count")
prev, rep, out, st = day(8, two, prev)
if st["unsettled"]["CVE-2099-9301"]["runs"]!=1 or st["unsettled"]["CVE-2099-9300"]["runs"]!=8: bad.append("restart %r"%st["unsettled"])
# a state that IS an auditor state with untrustworthy counts stops the run: exit 3, no report written (a file that is not an auditor state at all is the missing case: REQ-AUD-3 AC3 ignores it)
good_doc=json.load(open(prev))
good_doc["unsettled"]={"CVE-2099-9300":{"runs":0,"last":"2026-10-04"}}      # an auditor state whose counts cannot be trusted
cs=tmp+"/corrupt.json"; json.dump(good_doc,open(cs,"w"))
co=tmp+"/corrupt-out"
r=subprocess.run([sys.executable,".github/agent/bin/auditor-run.py","--dry-run","true","--manifest",one,"--adjudicator",fa,"--out",co,"--today","2026-10-09","--prev-state",cs],capture_output=True,text=True)
if r.returncode!=3 or os.path.exists(co+"/report.md"): bad.append("corrupt state: rc=%r report=%r"%(r.returncode,os.path.exists(co+"/report.md")))
# a finding the model REFUSED is already in its own owner-decision issue ("could not be assessed"): the counts advance, but the aggregate names only findings in no issue this run
prev=None; n_before=(log_count("create"), log_count("comment"))
for n in range(11,16):
    prev, rep, out, st = day(n, one, prev, fr)
if st["unsettled"].get("CVE-2099-9300",{}).get("runs")!=5: bad.append("refusal: the count stopped advancing %r"%st["unsettled"])
if (log_count("create"), log_count("comment"))!=n_before: bad.append("refusal: the aggregate issue names a finding already in an owner issue")
# a previous count dated after today stops the run before any model call or mutating call: exit 3, nothing written, the mutation ledger unchanged
fe=tempfile.mktemp(suffix=".py"); open(fe,"w").write("import sys\nsys.exit(1)\n")
fut=json.load(open(prev)); fut["unsettled"]={"CVE-2099-9300":{"runs":1,"last":"2099-01-01"}}
fs=tmp+"/future.json"; json.dump(fut,open(fs,"w"))
led=open(shim).read(); fo=tmp+"/future-out"
r=subprocess.run([sys.executable,".github/agent/bin/auditor-run.py","--manifest",one,"--adjudicator",fe,"--out",fo,"--today","2026-10-23","--prev-state",fs],capture_output=True,text=True)
if r.returncode!=3 or os.path.exists(fo+"/report.md") or open(shim).read()!=led: bad.append("future-dated count: rc=%r report=%r ledger-changed=%r"%(r.returncode,os.path.exists(fo+"/report.md"),open(shim).read()!=led))
print("OK" if not bad else "BAD "+"; ".join(bad))
PP
)"
eq "$r15" "OK" && ok || no "rc-5b fix 15: five consecutive unsettled runs open one stable-titled issue, restart on settle, say a missing state, stop on a corrupt one" "$r15"

begin "req18-suite-leaves-checkout-untouched" "the suite writes only under its temp dir: the checkout's git status is identical before and after (a case once rewrote the real .vex/.snyk/.auditor)"
REPO_STATE1="$(git status --porcelain --untracked-files=all 2>/dev/null)"
# rc-5b fix 5 (A3, Fable): a carried VEX statement that our own VEX hides from Inspector/Google (the tally's vex_covered entries) is re-judged every run; one that NO scanner reports is
# listed in the report as "not re-checkable (hidden from all scanners)", never silently kept. A vex_covered entry no carried statement matches is dropped.
r5="$("$PY" - "$FXRUN" <<'PP' 2>&1 | tail -1
import json,os,sys,io,contextlib,importlib.util,glob,tempfile,subprocess as _sp
FX=sys.argv[1]; W=tempfile.mkdtemp(); ws=W+"/ws"; os.makedirs(ws+"/.vex"); os.makedirs(ws+"/.auditor")
sys.path.insert(0,".github/agent/bin")
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
from auditorlib import vex, parsers
from unittest.mock import patch
mp=FX+"/manifest-mediumnofix.json"; m=json.load(open(mp)); d=json.load(open(m["panel"]["verdict"]))
c="CVE-2099-9400"; purl="pkg:deb/debian/libmed@1?arch=amd64&distro=debian-12.0"
json.dump(vex.doc(c,"not_affected","2026-08-24T00:00:00Z",justification="vulnerable_code_not_present",subcomponents=[purl]),open(ws+"/.vex/fosterstack-cache.openvex.json","w"))
_real_run=_sp.run                                  # saved BEFORE R.subprocess.run is patched (same module object): the fake must call the saved one, never itself
def run(cov,tag):
    d2=json.loads(json.dumps(d)); d2["vex_covered"]=cov
    vp2=W+"/verdict-"+tag+".json"; json.dump(d2,open(vp2,"w"))
    m2=json.loads(json.dumps(m)); m2["panel"]["verdict"]=vp2; mp2=W+"/m-"+tag+".json"; json.dump(m2,open(mp2,"w"))
    def fake2(cmd,*a,**kw):
        if cmd and cmd[0] in ("git","gh"): return _sp.CompletedProcess(cmd,0,"[]" if cmd[:3]==["gh","issue","list"] else "","")
        return _real_run(cmd,*a,**kw)
    out=W+"/out-"+tag
    with patch.dict(os.environ,{"AUDITOR_ALLOW_REAL_GH":"1","GITHUB_WORKSPACE":ws}),patch.object(R.subprocess,"run",fake2),patch.object(R.cli,"ask_model",return_value={"category":"risk_acceptance","token_usage":0}),contextlib.redirect_stdout(io.StringIO()):
        R.run(mp2,True,out,"2026-09-24",adjudicator="offline-probe")
    rep=open(out+"/report.md").read()
    if "consistency check did not complete" in rep: raise SystemExit("the run's consistency check did not complete")
    return os.path.exists(out+"/vex/%s.openvex.json"%c), [l for l in rep.split("\n") if "Not re-checkable" in l], vp2
cov=[{"image":"production-amd64","scanner":"inspector","id":c,"package":"libmed","version":"1"}]
rejudged,hid,vp=run(cov,"a")
recs=[r for r in parsers.parse_panel(vp,"inspector") if r["finding_id"]==c]
parsed_ok = len(recs)==1 and recs[0]["extra"].get("carried") is True and recs[0]["extra"]["images"]==["production-amd64"] and not [r for r in parsers.parse_panel(vp,"google") if r["finding_id"]==c]
rej_b,hid_b,_=run([],"b")
rej_c,hid_c,_=run([dict(cov[0],package="otherpkg")],"c")
# aliases: the carried statement is named by a GHSA id that lists the CVE the scanner reports as its alias (the panel's coverage predicate indexes both); it must resolve and not be called hidden
st2=vex.doc("GHSA-aaaa-bbbb-cccc","not_affected","2026-08-24T00:00:00Z",justification="vulnerable_code_not_present",subcomponents=[purl]); st2["statements"][0]["vulnerability"]["aliases"]=[c]
json.dump(st2,open(ws+"/.vex/fosterstack-cache.openvex.json","w"))
rej_d,hid_d,_=run(cov,"d")
print("OK" if (rejudged and not hid and parsed_ok and not rej_b and len(hid_b)==1 and c in hid_b[0] and not rej_c and len(hid_c)==1 and c in hid_c[0] and not hid_d) else "BAD rejudged=%s hid=%s parsed=%s b=%s/%s c=%s/%s d=%s/%s"%(rejudged,hid,parsed_ok,rej_b,hid_b,rej_c,hid_c,rej_d,hid_d))
PP
)"
eq "$r5" "OK" && ok || no "rc-5b fix 5: a carried statement hidden by our VEX from Inspector is re-judged (flagged carried by the parser, resolved to its scope), one no scanner reports is listed 'not re-checkable', an unmatched entry is dropped" "$r5"
# rc-5b fix 12 (R4 + R5): the production client reads the category and the refusal from the JSON answer's own keys (exact), and the driver refuses a model proposal by shape and by
# vendor/model name (the proposal, not the run).
begin "rc5b-12-client-category-is-exact-json" "the adjudicator client takes the category and the refusal from the JSON keys, exact match: 'not a false_positive' in prose is not false_positive, a word 'cannot' in prose is not a refusal, no JSON is under_investigation"
r12="$("$PY" -c "
import importlib.util,os,json
os.environ['AUDITOR_MODEL_PRIMARY']='m'
spec=importlib.util.spec_from_file_location('c','.github/agent/bin/auditor-adjudicator-client.py'); C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
def ask(text):
    class B: pass
    b=B(); b.text=text
    class Msg: content=[b]; usage=None
    class _M:
        @staticmethod
        def create(**k): return Msg()
    class Client: messages=_M()
    a=C._handle({'finding_id':'CVE-X','package':'p','kind':'disposition'},Client())
    return a.get('category'), a.get('refused')
got=[ask('{\"category\": \"false_positive\"}'), ask('This is not a false_positive; it is real_fixable.'), ask('{\"category\": \"not a false_positive\"}'),
     ask('I cannot assess this.'), ask('{\"refused\": true}'), ask('{\"category\": \"real_fixable\", \"x\": 1}'), ask('{\"category\": \"real_fixable or false_positive\"}'), ask('Example: {\"category\": \"false_positive\"} then {\"refused\": true}'), ask('{\"refused\": true, \"category\": \"real_fixable\"}'), ask('{\"refused\": true, \"refused\": false, \"category\": \"false_positive\"}'), ask('Analysis: {\"category\": \"real_fixable\"}')]
want=[('false_positive',False),('under_investigation',False),('under_investigation',False),('under_investigation',False),('under_investigation',True),('real_fixable',False),('under_investigation',False),('under_investigation',False),('under_investigation',True),('under_investigation',False),('under_investigation',False)]
print('OK' if got==want else 'BAD %r'%(got,))" 2>/dev/null | tail -1)"
eq "$r12" "OK" && ok || no "client category and refusal are read from exact JSON keys" "$r12"
begin "rc5b-12-proposals-validated-by-shape-and-name" "a model proposal is kept only with exactly the allowed keys, a known kind, string fields within the length cap and no vendor/model name; a refused proposal does not stop the run"
r12p="$("$PY" -c "
import importlib.util,os,sys
sys.path.insert(0,'.github/agent/bin')
spec=importlib.util.spec_from_file_location('r','.github/agent/bin/auditor-run.py'); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
good={'kind':'defect_log','package':'libpropose','keys':[{'scanner':'grype','finding_id':'CVE-2099-PROPOSE','purl':'pkg:deb/debian/libpropose@1.0'}],'note':'generalises from a recorded no-DSA pattern','evidence':'debian security tracker: no-DSA (minor)'}
bad=[dict(good,extra='x'), dict(good,kind='instructions'), dict(good,evidence=''), dict(good,evidence=['x']), dict(good,note=3), dict(good,package=3), dict(good,keys='x'),
     dict(good,keys=[{'scanner':'grype','finding_id':'CVE-1','purl':'p','extra':'y'}]), dict(good,keys=[{'scanner':'grype','finding_id':1,'purl':'p'}]),
     dict(good,note='proposed by Claude'), dict(good,evidence='per the gpt-5 analysis'), dict(good,package='anthropic-sdk'), dict(good,keys=[{'scanner':'grype','finding_id':'CVE-1','purl':'pkg:x/opus@1'}]),
     dict(good,note='x'*2001), None, 'x', [], {},
     {'kind':'knowledge'}, {'evidence':'e'}, {'kind':'knowledge','evidence':'e'}, dict(good,keys=[]), {k:v for k,v in good.items() if k!='keys'},
     dict(good,note='C\u04cf\u0430ude'), dict(good,note='Cl\u0410ude'), dict(good,package='Cl',note='au',evidence='de'), dict(good,note='gpt - 5'), dict(good,note='reviewed by private - model'), dict(good,package='zlib',note='aude',keys=[{'scanner':'grype','finding_id':'CVE-2099-1','purl':'pkg:generic/cl'}]), dict(good,note='caf\u00e9'), dict(good,keys=[{}]), dict(good,keys=[{'scanner':'s'}]),
     dict(good,note='\\uff23\\uff4c\\uff41\\uff55\\uff44\\uff45'), dict(good,note='Cl\\u0430ude'), dict(good,note='Cl\\u200baude'), dict(good,note='Clau',evidence='de says no'),
     dict(good,package='an',note='thropic'), dict(good,keys=[{'scanner':'grype','finding_id':'CVE-1','purl':'pkg:x/\\uff4fpus@1'}])]
ok=R._valid_proposal(good)==good and R._valid_proposal({'kind':'knowledge','evidence':'e','note':'n'})=={'kind':'knowledge','evidence':'e','note':'n'}
rej=[b for b in bad if R._valid_proposal(b) is not None]
# configured model identifiers of this run, one at a time (no minimum length), each also against the kind field
cfg_rej=[]
for k,v,prop in (('AUDITOR_MODEL_PRIMARY','secret-model-id-7',dict(good,note='uses secret-model-id-7')), ('AUDITOR_MODEL_FALLBACK','q2',dict(good,note='the q2 route')), ('AUDITOR_MODEL_FALLBACK','knowledge',{'kind':'knowledge','evidence':'e','note':'n'})):
    os.environ[k]=v
    if R._valid_proposal(prop) is not None: cfg_rej.append(v)
    del os.environ[k]
import time
os.environ['AUDITOR_MODEL_PRIMARY']='a'*13+'b'
t0=time.time(); R._valid_proposal(dict(good,keys=[{'scanner':'a','finding_id':'a','purl':'a'}]*20)); fast=time.time()-t0<2
del os.environ['AUDITOR_MODEL_PRIMARY']
print('OK' if ok and fast and not rej and not cfg_rej else 'BAD kept=%r cfg=%r ok=%s'%(rej,cfg_rej,ok))" 2>/dev/null | tail -1)"
eq "$r12p" "OK" && ok || no "_valid_proposal keeps a well-shaped proposal and refuses every mis-shaped or name-bearing one" "$r12p"
# rc-5b fix 13 (R6, Fable): a reviewed file on main that is PRESENT but unreadable or malformed is a stop (main() returns 3), never a guess: an unreadable VEX must not become "no
# statements" (the PR would delete every statement) and an unreadable accepted-items file must not renew every time box. A missing file is the first run and stays allowed.
# Every case drives main() and records every git/gh call: a stop makes NO mutating call (no issue, no PR, no git beyond reads).
cat > "$WORK/mutclass.py" <<'PP'
"""The one classifier of the matrix, in ALLOWLIST form (cache#708 ruling): a git or gh call counts as mutating unless it is listed read-only here; any other program (go, python) is not counted."""
READ_GIT = {"fetch", "show", "rev-parse", "status", "diff", "log", "ls-files", "cat-file", "merge-base", "rev-list"}
READ_GH = {("issue", "list"), ("issue", "view"), ("pr", "list"), ("pr", "view"), ("pr", "status"), ("pr", "checks"), ("label", "list"), ("auth", "status"), ("repo", "view")}
def mutating(cmd):
    if not cmd: return False
    if cmd[0] == "git": return not (len(cmd) > 1 and cmd[1] in READ_GIT)
    if cmd[0] == "gh": return not (len(cmd) > 2 and (cmd[1], cmd[2]) in READ_GH)
    return False
PP
cat > "$WORK/r6main.py" <<'PP'
import json,os,sys,io,contextlib,importlib.util,tempfile,subprocess as _sp
FX,variant=sys.argv[1],sys.argv[2]
tmp=tempfile.mkdtemp(); ws=tmp+"/ws"; os.makedirs(ws+"/.vex"); os.makedirs(ws+"/.auditor")
sys.path.insert(0,".github/agent/bin")
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
from auditorlib import vex
from unittest.mock import patch
c="CVE-2099-9300"; purl="pkg:deb/debian/libmed@1?arch=amd64&distro=debian-12.0"
old=vex.doc(c,"affected","2026-08-24T00:00:00Z",action="tracked",subcomponents=[purl])
vp=ws+"/.vex/fosterstack-cache.openvex.json"; ap=ws+"/.auditor/accepted-items.json"
good_items={"accepted_items":[{"cve":c,"severity":"Medium","package":"libmed","threshold":"below","owner_issue":None,"vex_id":old["statements"][0]["@id"],"expiry":"2026-12-31"}]}
def write_good():
    json.dump(old,open(vp,"w")); json.dump(good_items,open(ap,"w"))
write_good()
corrupt_at="start"; reopened_body="{bad"
if variant=="vex-malformed": open(vp,"w").write("{not json")
elif variant=="vex-notobject": open(vp,"w").write("[]")
elif variant=="vex-empty-object": open(vp,"w").write("{}")
elif variant=="vex-null-statements": json.dump(dict(old,statements=None),open(vp,"w"))
elif variant=="vex-no-statements": json.dump({k:v for k,v in old.items() if k!="statements"},open(vp,"w"))
elif variant=="vex-empty-list": json.dump(dict(old,statements=[]),open(vp,"w"))
elif variant=="items-empty-object": open(ap,"w").write("{}")
elif variant=="items-null-list": json.dump({"accepted_items":None},open(ap,"w"))
elif variant=="items-empty-list": json.dump({"accepted_items":[]},open(ap,"w"))
elif variant=="vex-null-statement": json.dump(dict(old,statements=[None]),open(vp,"w"))
elif variant=="items-malformed": open(ap,"w").write("{not json")
elif variant=="items-notobject": open(ap,"w").write("[]")
elif variant=="items-null-entry": json.dump({"accepted_items":[good_items["accepted_items"][0],None]},open(ap,"w"))
elif variant=="items-scalar-entry": json.dump({"accepted_items":[3]},open(ap,"w"))
elif variant=="items-bad-fields": json.dump({"accepted_items":[{"cve":"CVE-A","expiry":"2026-01-01","scope_purls":["p"],"not_pullable":True},{"cve":"CVE-B","expiry":"2026-01-01","scope_purls":5}]},open(ap,"w"))
elif variant=="items-mixed-expiry": json.dump({"accepted_items":[dict(good_items["accepted_items"][0],expiry=5),dict(good_items["accepted_items"][0],expiry="2026-12-31")]},open(ap,"w"))
elif variant=="vex-bad-vulnerability": json.dump(dict(old,statements=[dict(old["statements"][0],vulnerability="x")]),open(vp,"w"))
elif variant=="vex-dir": os.remove(vp); os.mkdir(vp)
elif variant=="items-dir": os.remove(ap); os.mkdir(ap)
elif variant=="items-bad-at-delivery": corrupt_at="delivery"
elif variant=="delivery-base-vex-empty": corrupt_at="delivery-vex"
elif variant=="delivery-base-items-keyless": corrupt_at="delivery-items"
elif variant=="missing": os.remove(vp); os.remove(ap)
elif variant=="vex-parent-noaccess": os.chmod(ws+"/.vex",0)          # EACCES on the parent: lstat of the file fails, which is not "absent"
elif variant=="reopened-bad-at-delivery": corrupt_at="reopened"
elif variant=="reopened-empty-at-delivery": corrupt_at="reopened"; reopened_body="{}"
elif variant=="reopened-nokey-at-delivery": corrupt_at="reopened"; reopened_body='{"other": []}'
calls=[]
def fake(cmd,*a,**kw):
    calls.append(list(cmd))
    if cmd and cmd[0]=="git":
        _led=tmp+"/out/.auditor/reopened-expired.json"
        if corrupt_at=="reopened" and os.path.exists(_led) and open(_led).read()!=reopened_body:      # the first git call after the run wrote its ledger: the file is damaged now (the base check ran before it existed)
            open(_led,"w").write(reopened_body)
        if cmd[1:2]==["fetch"]:      # the delivery base turns bad / the run's own ledger is damaged AFTER the run wrote it, before any checkout (the first moment the delivery looks)
            if corrupt_at=="delivery": open(ap,"w").write("{bad")
            if corrupt_at=="delivery-vex": open(vp,"w").write("{}")
            if corrupt_at=="delivery-items": open(ap,"w").write('{"other": []}')
            pass
        if cmd[1:3]==["rev-parse","origin/main"]: return _sp.CompletedProcess(cmd,0,"a"*40+"\n","")
        if cmd[1:2]==["show"] and len(cmd)>2 and (cmd[2].startswith("origin/main:") or cmd[2].startswith("a"*40+":")):      # origin/main is the workspace's own reviewed files here
            _rel=cmd[2].split(":",1)[1]; _p=ws+"/"+_rel
            if os.path.isfile(_p): return _sp.CompletedProcess(cmd,0,open(_p).read(),"")
            return _sp.CompletedProcess(cmd,128,"","fatal: path '%s' does not exist in 'origin/main'"%_rel)
        return _sp.CompletedProcess(cmd,0,"","")
    if cmd and cmd[0]=="gh": return _sp.CompletedProcess(cmd,0,"[]" if cmd[:3]==["gh","issue","list"] else "","")
    return _sp.run(cmd,*a,**kw)
mp=FX+"/manifest-mediumnofix.json"
if variant in ("defectlog-dangling","defectlog-keyless"):      # a PRESENT defect log the run cannot use: a dangling symlink, or {} (cache#701 r2): a stop before any mutating call
    _m=json.load(open(mp)); _dl=tmp+"/known-defect-log.json"
    if variant=="defectlog-dangling": os.symlink(tmp+"/nowhere",_dl)
    else: open(_dl,"w").write("{}")
    _m["known_defect_log"]=_dl; mp=FX+"/manifest-dl-"+variant+".json"; json.dump(_m,open(mp,"w"))
R.cli.ARGS[:]=["--manifest",mp,"--out",tmp+"/out","--dry-run","false","--today","2026-09-24","--adjudicator","offline-probe"]
with patch.dict(os.environ,{"AUDITOR_ALLOW_REAL_GH":"1","GITHUB_WORKSPACE":ws}),patch.object(R.subprocess,"run",fake),patch.object(R.cli,"ask_model",return_value={"category":"risk_acceptance","token_usage":0}),contextlib.redirect_stdout(io.StringIO()):
    try: rc=R.main()
    except Exception as e: rc="EXC %s"%type(e).__name__
try: os.chmod(ws+"/.vex",0o755)
except OSError: pass
import mutclass; mut=[x for x in calls if mutclass.mutating(x)]   # the shared allowlist-form classifier
print("rc=%s mutating=%d%s"%(rc,len(mut)," (checked at delivery)" if corrupt_at=="delivery" else ""))
PP
cat > "$WORK/r7main.py" <<'PP'
# an owner-escalating finding whose per-finding VEX the run wrote damaged: the stop (exit 3) must come before the owner-decision issue is created (cache#701 ruling F3/B3)
import json,os,sys,io,contextlib,importlib.util,tempfile,subprocess as _sp
FX,variant=sys.argv[1],sys.argv[2]
tmp=tempfile.mkdtemp(); ws=tmp+"/ws"; os.makedirs(ws+"/.vex"); os.makedirs(ws+"/.auditor")
sys.path.insert(0,".github/agent/bin")
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
from auditorlib import vex
from unittest.mock import patch
_orig=vex.write
def dmg_write(*a,**kw):
    p=_orig(*a,**kw)
    if variant=="finding-vex-empty-object": open(p,"w").write("{}")
    elif variant=="finding-vex-invalid-statement": json.dump({"statements":[{}]},open(p,"w"))
    return p
fetches=[0]; revfail=[0]
calls=[]
def fake(cmd,*a,**kw):
    calls.append(list(cmd))
    if cmd and cmd[0]=="git":
        if cmd[1:2]==["fetch"]:
            fetches[0]+=1
            if variant=="fetch-fails-then-bad-base" and fetches[0]==1: return _sp.CompletedProcess(cmd,1,"","network error")
        if cmd[1:3]==["rev-parse","origin/main"]:
            if variant=="revparse-fails-then-bad-base" and not revfail[0]:
                revfail[0]=1; return _sp.CompletedProcess(cmd,1,"","bad ref")
            return _sp.CompletedProcess(cmd,0,"a"*40+"\n","")
        if cmd[1:2]==["show"]:
            _rel=cmd[2].split(":",1)[1]
            if variant.endswith("-then-bad-base") and _rel.startswith(".vex/"): return _sp.CompletedProcess(cmd,0,"{}","")        # a damaged base, visible only to a SECOND acquisition
            if variant=="base-vex-empty" and _rel.startswith(".vex/"): return _sp.CompletedProcess(cmd,0,"{}","")
            if variant=="base-items-keyless" and _rel.startswith(".auditor/"): return _sp.CompletedProcess(cmd,0,'{"other": []}',"")
            return _sp.CompletedProcess(cmd,128,"","fatal: path 'x' does not exist in 'origin/main'")
        return _sp.CompletedProcess(cmd,0,"","")
    if cmd and cmd[0]=="gh": return _sp.CompletedProcess(cmd,0,"[]" if cmd[:3]==["gh","issue","list"] else "","")
    return _sp.run(cmd,*a,**kw)
R.cli.ARGS[:]=["--manifest",FX+"/manifest-ownerissue.json","--out",tmp+"/out","--dry-run","false","--today","2026-09-24","--adjudicator","offline-probe"]
with patch.dict(os.environ,{"AUDITOR_ALLOW_REAL_GH":"1","GITHUB_WORKSPACE":ws}),patch.object(R.subprocess,"run",fake),patch.object(vex,"write",dmg_write),patch.object(R.cli,"ask_model",return_value={"category":"risk_acceptance","token_usage":0}),contextlib.redirect_stdout(io.StringIO()):
    try: rc=R.main()
    except Exception as e: rc="EXC %s"%type(e).__name__
issues=[x for x in calls if x[:3]==["gh","issue","create"]]
import mutclass; mut=[x for x in calls if mutclass.mutating(x)]   # the shared allowlist-form classifier
print("rc=%s fetches=%d"%(rc,fetches[0]) if variant.endswith("-then-bad-base") else "rc=%s issues=%d mutating=%d"%(rc,len(issues),len(mut)))
PP
begin "rc5b-13-reviewed-inputs-stop-the-run" "a reviewed or run-written input that is present but unreadable or mis-shaped stops the run (exit 3) with no mutating call; a missing one is the first run"
is_root=0; [ "$(id -u)" = 0 ] && is_root=1
for variant in defectlog-dangling defectlog-keyless vex-malformed vex-notobject vex-null-statement vex-empty-object vex-null-statements vex-no-statements items-empty-object items-null-list items-malformed items-notobject items-null-entry items-scalar-entry items-bad-fields items-mixed-expiry vex-bad-vulnerability vex-dir items-dir; do
  r6="$("$PY" "$WORK/r6main.py" "$FXRUN" "$variant" 2>/dev/null | tail -1)"
  eq "$r6" "rc=3 mutating=0" && ok || no "an unreadable or malformed reviewed input ($variant) stops the run: main() returns 3 and makes no mutating git/gh call" "$r6"
done
if [ "$is_root" = 0 ]; then
  r6="$("$PY" "$WORK/r6main.py" "$FXRUN" vex-parent-noaccess 2>/dev/null | tail -1)"
  eq "$r6" "rc=3 mutating=0" && ok || no "an unreadable PARENT folder of a reviewed file (EACCES on lstat) is a stop, not 'absent'" "$r6"
else ok; fi
r6="$("$PY" "$WORK/r6main.py" "$FXRUN" reopened-bad-at-delivery 2>/dev/null | tail -1)"
eq "$r6" "rc=3 mutating=0" && ok || no "a reopened-expired.json this run wrote that does not parse stops the run (exit 3) at every reader, nothing delivered" "$r6"
for variant in reopened-empty-at-delivery reopened-nokey-at-delivery; do
  r6="$("$PY" "$WORK/r6main.py" "$FXRUN" "$variant" 2>/dev/null | tail -1)"
  eq "$r6" "rc=3 mutating=0" && ok || no "a reopened-expired.json this run wrote that is {} or lacks its reopened list ($variant) stops the run (exit 3), nothing delivered" "$r6"
done
r6g="$("$PY" - <<'PP' 2>&1 | tail -1
import os,sys,tempfile,importlib.util
sys.path.insert(0,".github/agent/bin")
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
t=tempfile.mkdtemp(); os.makedirs(t+"/vex")
open(t+"/vex/CVE-2099-1.openvex.json","w").write("{bad")
try: R._consolidate(t,"2026-09-24T00:00:00Z"); print("RAN")
except R.ReviewedInputInvalid: print("STOP")
PP
)"
eq "$r6g" "STOP" && ok || no "a per-finding VEX file this run wrote that does not parse stops _consolidate instead of producing 'statements: []'" "$r6g"
r6="$("$PY" "$WORK/r6main.py" "$FXRUN" items-bad-at-delivery 2>/dev/null | tail -1)"
case "$r6" in rc=3\ mutating=0*) ok ;; *) no "a reviewed input that stops parsing only in the delivery checkout also stops the run (exit 3), not an ordinary staging error" "$r6" ;; esac
for variant in vex-empty-list items-empty-list; do   # an empty list is a valid file: the run proceeds (it is not the stop of a missing key)
  r6e="$("$PY" "$WORK/r6main.py" "$FXRUN" "$variant" 2>/dev/null | tail -1)"
  case "$r6e" in rc=3*|"rc=EXC"*|"") no "a published VEX with statements: [] / accepted-items with accepted_items: [] ($variant) is valid and does not stop the run" "$r6e" ;; *) ok ;; esac
done
r6m="$("$PY" "$WORK/r6main.py" "$FXRUN" missing 2>/dev/null | tail -1)"
case "$r6m" in rc=3*|"rc=EXC"*|"") no "a MISSING VEX and accepted-items file is the first run and does not stop" "$r6m" ;; *) ok ;; esac
for variant in delivery-base-vex-empty delivery-base-items-keyless; do
  r6="$("$PY" "$WORK/r6main.py" "$FXRUN" "$variant" 2>/dev/null | tail -1)"
  eq "$r6" "rc=3 mutating=0" && ok || no "a delivery base whose reviewed file is {} or lacks its list ($variant) stops the run (exit 3) BEFORE git checkout: the delivery base is read with git show, the workspace is not touched" "$r6"
done
r7="$("$PY" "$WORK/r7main.py" "$FXRUN" control 2>/dev/null | tail -1)"
case "$r7" in "rc=3 "*|"rc=EXC"*|"") no "control: an owner-escalating finding with intact per-finding VEX runs and opens its owner-decision issue (so the stop cases below are not vacuous)" "$r7" ;; *"issues=0 "*) no "control: no owner-decision issue was opened, the stop cases below prove nothing" "$r7" ;; *) ok ;; esac
for variant in base-vex-empty base-items-keyless; do
  r7="$("$PY" "$WORK/r7main.py" "$FXRUN" "$variant" 2>/dev/null | tail -1)"
  eq "$r7" "rc=3 issues=0 mutating=0" && ok || no "an owner-escalating finding AND a damaged delivery base ($variant) stops the run (exit 3) before the owner-decision issue: the base is fetched and validated once, before the first issue" "$r7"
done
for variant in fetch-fails-then-bad-base revparse-fails-then-bad-base; do
  r7="$("$PY" "$WORK/r7main.py" "$FXRUN" "$variant" 2>/dev/null | tail -1)"
  eq "$r7" "rc=1 fetches=1" && ok || no "a base fetch or resolution that fails before the first owner issue is handed to the delivery, which reports it (rc=1) and acquires the base ONCE: no second fetch can find a damaged base after the issue exists ($variant)" "$r7"
done
for variant in finding-vex-empty-object finding-vex-invalid-statement; do
  r7="$("$PY" "$WORK/r7main.py" "$FXRUN" "$variant" 2>/dev/null | tail -1)"
  eq "$r7" "rc=3 issues=0 mutating=0" && ok || no "an owner-escalating finding whose per-finding VEX is damaged ($variant) stops the run (exit 3) BEFORE the owner-decision issue is created: no gh issue, no checkout, no push" "$r7"
done
while read -r want cmdline; do
  got="$("$PY" -c 'import sys; sys.path.insert(0, sys.argv[1]); import mutclass; print(int(mutclass.mutating(sys.argv[2:])))' "$WORK" $cmdline)"
  eq "$got" "$want" && ok || no "the matrix classifier counts '$cmdline' as mutating=$want (allowlist form: read-only commands are listed, everything else counts)" "$got"
done <<'LIST'
1 gh issue create --title t
1 gh issue comment 1 --body b
1 gh issue close 1
1 gh issue reopen 1
1 gh issue edit 1
1 gh label create x
1 gh pr create --base main
1 gh pr merge 1
1 gh pr comment 1
1 gh pr edit 1
1 gh pr close 1
1 gh pr ready 1
1 gh api graphql
1 gh release create v1
1 git checkout -B b origin/main
1 git push origin b
1 git commit -m x
1 git reset --hard
1 git add x
1 git rebase main
1 git symbolic-ref HEAD refs/heads/x
0 git fetch origin main
0 git show origin/main:x
0 git rev-parse origin/main
0 git status --porcelain
0 gh issue list
0 gh pr list
0 go get x
LIST
eq "$REPO_STATE1" "$REPO_STATE0" && ok || no "checkout untouched by the suite" "$(printf '%s' "$REPO_STATE1" | tr '\n' ' ')"

echo "----"
echo "auditor-matrix: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
