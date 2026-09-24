#!/usr/bin/env bash
# Matrix-first EFFECT-OBSERVING failing suite for the daily CVE auditor
# (docs/quality/cve-auditor-matrix.md). Round-7 hardening after the second review
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
# Run on demand:  bash bin/auditor-matrix-test.sh   (never wired into CI)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"; cd "$repo"
PY=python3
F=".github/agent/fixtures"
BIN=".github/agent/bin"
WF=".github/workflows/auditor.yml"
STUB="$F/adjudicator/stub-adjudicator.py"
NOCALL="$F/adjudicator/fail-on-call.py"
GH="$F/adjudicator/fake-github-api.py"
YAML="$PY $F/testlib/yamlshape.py"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
LEDGER="$WORK/model.ledger"; export AUDITOR_MODEL_LEDGER="$LEDGER"
MISS="__MISSING__"
pass=0; fail=0
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
# alias_set <finding-id>: every id the SCANNER REPORTS give for that finding (OSV
# aliases, Grype relatedVulnerabilities), read from the manifest — never hand-typed.
alias_set(){ "$PY" -c 'import json,sys,re
fid=sys.argv[1]; m=json.load(open(sys.argv[2])); ids={fid}
def add(x):
    if x: ids.add(x)
try:
    for k in ("osv-scanner","osv-scanner-gomod"):
        for r in json.load(open(m["scanner_reports"][k]))["results"]:
            for p in r.get("packages",[]):
                for v in p.get("vulnerabilities",[]):
                    grp=set([v["id"]]+v.get("aliases",[]))
                    if fid in grp:
                        for a in grp: add(a)
                for g in p.get("groups",[]):
                    if fid in g.get("ids",[]):
                        for a in g["ids"]: add(a)
    g=json.load(open(m["scanner_reports"]["grype"]))
    for mt in g["matches"]:
        rel=[mt["vulnerability"]["id"]]+[r.get("id") for r in mt.get("relatedVulnerabilities",[])]
        if fid in rel:
            for a in rel: add(a)
except Exception: pass
print(" ".join(sorted(ids)))' "$1" "$F/run/manifest-01.json" 2>/dev/null; }
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
for w in .github/workflows/main-candidate-rescan.yml .github/workflows/daily-rescan.yml "$F/testlib/workflows/quoted-on.yml"; do
  t="$($YAML shape "$w" 2>/dev/null | "$PY" -c 'import json,sys;print(",".join(sorted(json.load(sys.stdin)["triggers"])))' 2>/dev/null)"
  [ "$t" = "schedule,workflow_dispatch" ] || { echo "PREFLIGHT: PyYAML reader mis-parsed $w ($t)" >&2; exit 2; }
done

########################################################################
echo "=== REQ-AUD-1 ==="
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
begin "req2-ac1-false-positive" "the statement FOR the FP finding is not_affected with a justification and repository_url-scoped product; a non-empty grype ignore cites the VEX; the report places it in section 5 not 3"
run "$PY" "$BIN/auditor-classify.py" --manifest "$F/run/manifest-01.json" --adjudicator "$STUB" --out "$CDIR" && {
  st="$(vf "$CDIR/vex/CVE-2016-2781.openvex.json" CVE-2016-2781 's["status"]')"
  ju="$(vf "$CDIR/vex/CVE-2016-2781.openvex.json" CVE-2016-2781 's.get("justification")')"
  prod="$(vf "$CDIR/vex/CVE-2016-2781.openvex.json" CVE-2016-2781 'json.dumps(s.get("products"))')"
  igsz="$( [ -s "$CDIR/ignores/grype/CVE-2016-2781.json" ] && echo nonempty || echo empty )"
  igcite="$(pj "$CDIR/ignores/grype/CVE-2016-2781.json" 'd.get("vex")')"
  fpev="$(pj "$CDIR/evidence/CVE-2016-2781.evidence.json" 'str(bool(d.get("evidence")))')"
  s5="$(sect_ids "$CDIR/report.md" 5)"; s3="$(sect_ids "$CDIR/report.md" 3)"
  fpstat="$(tree_vex_status_set "$CDIR" $(alias_set CVE-2016-2781))"
  { eq "$fpstat" "not_affected" && eq "$st" "not_affected" && eq "$fpev" "True" && [ "$ju" != "$MISS" ] && printf '%s' "$prod" | grep -q 'repository_url=ghcr.io/fosterstack/cache' \
    && eq "$igsz" "nonempty" && [ "$igcite" != "$MISS" ] \
    && printf '%s' "$s5" | grep -q 'CVE-2016-2781' && ! printf '%s' "$s3" | grep -q 'CVE-2016-2781'; } \
    && ok || no "not_affected+justification+scoped product, ignore cites VEX, section-5 placement" "status=$st just=$ju ignore=$igsz cite=$igcite sec5=[$s5] sec3=[$s3]"; }

begin "req2-ac2a-notpullable-and-unreachable" "the target's statement is not_affected/vulnerable_code_not_in_execute_path; the reachable sibling does NOT get a not_affected VEX; empty ledger"
o="$WORK/ac2a"; rm -rf "$o"
run "$PY" "$BIN/auditor-classify.py" --finding GO-2020-0015 --manifest "$F/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$NOCALL" --out "$o" && {
  st="$(vf "$o/vex/GO-2020-0015.openvex.json" GO-2020-0015 's["status"]')"
  ju="$(vf "$o/vex/GO-2020-0015.openvex.json" GO-2020-0015 's.get("justification")')"
  ev="$(pj "$o/evidence/GO-2020-0015.evidence.json" '(d.get("evidence") or {}).get("source")')"
  o2="$WORK/ac2a-b"; rm -rf "$o2"; : > "$LEDGER"
  run "$PY" "$BIN/auditor-classify.py" --finding GO-2021-0113 --manifest "$F/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$NOCALL" --out "$o2"
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
run "$PY" "$BIN/auditor-classify.py" --finding GO-2021-0113 --manifest "$F/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$STUB" --github "$GH" --state "$ghs" --out "$o" && {
  kind="$(pj "$o/action/GO-2021-0113.json" 'd.get("kind")')"; to="$(pj "$o/action/GO-2021-0113.json" 'd.get("to")')"
  novex="$(tree_has_vex_for "$o" GO-2021-0113)"
  { eq "$kind" "bump_pr" && [ "$to" != "$MISS" ] && [ "$to" != "0.3.0" ] && eq "$novex" "no"; } \
    && ok || no "bump_pr forward, no not_affected VEX" "kind=$kind to=$to vex=$novex"; }

begin "req2-ac4-not-reachable" "the target's statement is not_affected with the reachability justification and names the finding; a reachable finding does NOT become not_affected; empty ledger"
o="$WORK/ac4"; rm -rf "$o"
run "$PY" "$BIN/auditor-classify.py" --finding GO-2020-0015 --manifest "$F/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$NOCALL" --out "$o" && {
  st="$(vf "$o/vex/GO-2020-0015.openvex.json" GO-2020-0015 's["status"]')"
  ju="$(vf "$o/vex/GO-2020-0015.openvex.json" GO-2020-0015 's.get("justification")')"
  ev="$(pj "$o/evidence/GO-2020-0015.evidence.json" '(d.get("evidence") or {}).get("source")')"
  o2="$WORK/ac4b"; rm -rf "$o2"; : > "$LEDGER"
  run "$PY" "$BIN/auditor-classify.py" --finding GO-2021-0113 --manifest "$F/run/manifest-01.json" --govulncheck "$F/govulncheck/gv-01.json" --adjudicator "$NOCALL" --out "$o2"
  reach="$(tree_has_vex_for "$o2" GO-2021-0113)"
  { eq "$st" "not_affected" && eq "$ju" "vulnerable_code_not_in_execute_path" && eq "$ev" "govulncheck" && eq "$reach" "no" && ledger_empty; } \
    && ok || no "not_affected only for unreachable, govulncheck evidence, empty ledger" "status=$st just=$ju evidence=$ev reachable_vex=$reach ledger=$(ledger_n)"; }

begin "req2-ac4-neg-no-evidence-stays-open" "a real scanned finding (GO-2020-0015 in OSV) whose govulncheck messages are removed is NOT closed: no VEX statement anywhere names it, no ignore names it, it is recorded open; empty ledger"
o="$WORK/ac4neg"; rm -rf "$o"
run "$PY" "$BIN/auditor-classify.py" --finding GO-2020-0015 --manifest "$F/run/manifest-01.json" --govulncheck "$F/testlib/evidence-without-GO-2020-0015.json" --adjudicator "$NOCALL" --out "$o" && {
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

begin "req2-ac5c-expiry-reopens-item" "expiry with no fix DELETES the seeded ignore and VEX under every alias (world check) and returns the finding to section 3"
o="$WORK/ac5c"; supp="$WORK/ac5c-supp"; rm -rf "$o" "$supp"
mkdir -p "$supp/ignores/grype" "$supp/.vex"
echo '{"id":"CVE-2011-3374","vex":"stmt","expiry":"2026-08-23"}' > "$supp/ignores/grype/CVE-2011-3374.json"
printf '{"statements":[{"vulnerability":{"name":"CVE-2011-3374"},"status":"affected"}]}' > "$supp/.vex/fosterstack-cache.openvex.json"
run "$PY" "$BIN/auditor-poam.py" --recheck --package "$F/poam/poam-04.json" --suppression-dir "$supp" --today 2026-09-22 --out "$o" && {
  rem="$(pj "$o/recheck.json" 'd.get("ignore_removed")')"; sec="$(pj "$o/recheck.json" 'd.get("returned_to_section")')"
  anyign="$(ignore_names_any "$supp" $(alias_set CVE-2011-3374))"; anyvex="$(tree_has_vex_for "$supp" CVE-2011-3374)"
  { eq "$rem" "true" && eq "$sec" "3" && eq "$anyign" "no" && eq "$anyvex" "no"; } \
    && ok || no "seeded ignore AND VEX deleted from the state under every alias; section 3" "removed=$rem section=$sec any_ignore=$anyign any_vex=$anyvex"; }

begin "req2-ac6-categories-disjoint" "classification.json finding-id set EQUALS the manifest's id set (never vacuous), each with one valid category"
run "$PY" "$BIN/auditor-classify.py" --manifest "$F/run/manifest-01.json" --adjudicator "$STUB" --out "$CDIR" && {
  chk="$("$PY" -c 'import json,sys,re
try:
    d=json.load(open(sys.argv[1])); m=json.load(open(sys.argv[2]))
    ids=set()
    def cve(x):
        a=[x.get("id")]+x.get("aliases",[])
        for y in a:
            if re.fullmatch(r"CVE-\d{4}-\d+",y or ""): return y
        return (x.get("id") or "").replace("DEBIAN-CVE-","CVE-")
    g=json.load(open(m["scanner_reports"]["grype"]))
    for mt in g["matches"]: ids.add(mt["vulnerability"]["id"])
    t=json.load(open(m["scanner_reports"]["trivy"]))
    for r in t["Results"]:
        for v in r.get("Vulnerabilities",[]): ids.add(v["VulnerabilityID"])
    for k in ("osv-scanner","osv-scanner-gomod"):
        o=json.load(open(m["scanner_reports"][k]))
        for r in o["results"]:
            for p in r.get("packages",[]):
                for v in p.get("vulnerabilities",[]): ids.add(cve(v))
    got={f["id"] for f in d["findings"]}
    valid={"false_positive","not_affected_unreachable","real_fixable","risk_acceptance"}
    okc=len(d["findings"])>0 and got==ids and all(f.get("category") in valid for f in d["findings"]) and len(got)==len(d["findings"])
    print("True" if okc else "False")
except Exception: print("ERR")' "$CDIR/classification.json" "$F/run/manifest-01.json")"
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
"$PY" -c 'import json;d=json.load(open(".github/agent/fixtures/dl/log.json"));d["defects"][1]["keys"]=[k for k in d["defects"][1]["keys"] if k["scanner"]!="trivy"];json.dump(d,open("'"$WORK"'/log5.json","w"))'
rowbefore="$(pj "$WORK/log5.json" 'max(len(x["keys"]) for x in d["defects"])')"
run "$PY" "$BIN/auditor-defectlog.py" reconcile --log "$WORK/log5.json" \
  --finding trivy CVE-2011-3374 'pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.0' --manifest "$F/run/manifest-01.json" \
  --adjudicator "$STUB" --out "$o1" && {
  used="$( [ -s "$LEDGER" ] && echo y || echo n )"; : > "$LEDGER"
  # the SAME row that already holds a CVE-2011-3374 key must now hold a trivy
  # CVE-2011-3374 key (not a key on some other row, nor a WRONG finding id).
  addedright="$("$PY" -c 'import json,sys
try:
    d=json.load(open(sys.argv[1])); ok=False; purl=sys.argv[2]
    for row in d["defects"]:
        ids={k["finding_id"] for k in row["keys"]}
        if "CVE-2011-3374" in ids and any(k["scanner"]=="trivy" and k["finding_id"]=="CVE-2011-3374" and k["purl"]==purl for k in row["keys"]): ok=True
    print("yes" if ok else "no")
except Exception: print("no")' "$WORK/log5.json" 'pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.0')"
  run "$PY" "$BIN/auditor-defectlog.py" probe --log "$WORK/log5.json" --hit trivy CVE-2011-3374 'pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12.0' --adjudicator "$NOCALL" --out "$o2" && {
    hit="$(pj "$o2/probe.json" 'd.get("hit")')"; disp="$(pj "$o2/probe.json" 'd.get("hit_disposition")')"
    { eq "$used" "y" && eq "$addedright" "yes" && eq "$hit" "true" && eq "$disp" "false_positive" && ledger_empty; } \
      && ok || no "trivy CVE-2011-3374 key with the exact purl on the SAME row; later probe returns that row's disposition" "judgment=$used added_to_right_row_and_purl=$addedright hit=$hit disposition=$disp ledger=$(ledger_n)"; }; }

########################################################################
echo "=== REQ-AUD-4 ==="
begin "req4-ac1-four-suppressions-cite-vex" "OpenVEX status not_affected; the .snyk has an entry with a real expires field and the VEX id; the OSV ignore has an id+reason and the VEX id"
o="$WORK/sup"; rm -rf "$o"
run "$PY" "$BIN/auditor-suppress.py" --disposition "$F/suppression/disp-01.json" --out "$o" && {
  vid="stmt-cve-2011-3374"
  vst="$(vf "$o/.vex/fosterstack-cache.openvex.json" CVE-2011-3374 's["status"]')"
  snykok="$("$PY" -c 'import sys
try: import yaml
except Exception:
    sys.path.insert(0,".github/agent/fixtures/testlib"); import pyyaml as yaml
try:
    d=yaml.safe_load(open(sys.argv[1]).read()) or {}
    ig=d.get("ignore",{}); ok=False
    for k,v in ig.items():
        for e in v:
            for sel,body in e.items():
                if body.get("expires") and "stmt-cve-2011-3374" in str(body.get("vex","")): ok=True
    print("yes" if ok else "no")
except Exception: print("no")' "$o/.snyk")"
  osvok="$(grep -qF 'stmt-cve-2011-3374' "$o/osv-scanner.toml" 2>/dev/null && grep -qiE 'reason' "$o/osv-scanner.toml" && grep -qF 'CVE-2011-3374' "$o/osv-scanner.toml" && echo yes || echo no)"
  { eq "$vst" "not_affected" && eq "$snykok" "yes" && eq "$osvok" "yes"; } \
    && ok || no "VEX not_affected + real .snyk expiry/vex + OSV id/reason/vex" "vex=$vst snyk=$snykok osv=$osvok"; }

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
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --adjudicator "$STUB" --out "$o" && {
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

begin "req4-ac3-votes-by-lineage" "a four-scanner CVE counts 3 lineages; a grype-only CVE counts 1 (a constant fails one); empty ledger"
o="$WORK/v1"; o2="$WORK/v2"; rm -rf "$o" "$o2"
run "$PY" "$BIN/auditor-votes.py" --manifest "$F/run/manifest-01.json" --cve CVE-2011-3374 --adjudicator "$NOCALL" --out "$o" && {
  dl="$(pj "$o/votes.json" 'd.get("distinct_lineages")')"; e1="$(ledger_empty && echo y || echo n)"; : > "$LEDGER"
  run "$PY" "$BIN/auditor-votes.py" --manifest "$F/run/manifest-01.json" --cve CVE-2016-2781 --adjudicator "$NOCALL" --out "$o2" && {
    dl2="$(pj "$o2/votes.json" 'd.get("distinct_lineages")')"
    { eq "$dl" "3" && eq "$dl2" "1" && eq "$e1" "y" && ledger_empty; } \
      && ok || no "3 lineages for four-scanner, 1 for grype-only, empty ledger" "four=$dl one=$dl2 ledger=$(ledger_n)"; }; }

begin "req4-ac4-unique-not-autoclosed" "a grype-only CVE is unique+suspect (not auto-closed); a four-scanner CVE is not unique (a constant fails one)"
o="$WORK/u1"; o2="$WORK/u2"; rm -rf "$o" "$o2"
run "$PY" "$BIN/auditor-votes.py" --manifest "$F/run/manifest-01.json" --cve CVE-2016-2781 --adjudicator "$NOCALL" --out "$o" && {
  u="$(pj "$o/votes.json" 'd.get("unique")')"; cl="$(pj "$o/votes.json" 'd.get("auto_closed")')"; hd="$(pj "$o/votes.json" 'd.get("handling")')"
  run "$PY" "$BIN/auditor-votes.py" --manifest "$F/run/manifest-01.json" --cve CVE-2011-3374 --adjudicator "$NOCALL" --out "$o2" && {
    u2="$(pj "$o2/votes.json" 'd.get("unique")')"
    { eq "$u" "true" && eq "$cl" "false" && eq "$hd" "suspect_investigated" && eq "$u2" "false"; } \
      && ok || no "unique+suspect for grype-only, not-unique for four-scanner" "unique=$u closed=$cl handling=$hd four_unique=$u2"; }; }

begin "req4-ac5-consistency-check" "the inconsistent set yields the exact problem types (parsed array); a clean control set yields none"
o="$WORK/c1"; o2="$WORK/c2"; rm -rf "$o" "$o2"
run "$PY" "$BIN/auditor-consistency.py" --suppression-dir "$F/suppression/set-01" --live-findings "$F/run/manifest-01.json" --out "$o/consistency.json" && {
  types="$(pj "$o/consistency.json" '",".join(sorted({p["type"] for p in d["problems"]}))')"
  mkdir -p "$WORK/clean"
  run "$PY" "$BIN/auditor-consistency.py" --suppression-dir "$WORK/clean" --live-findings "$F/run/manifest-01.json" --out "$o2/consistency.json" && {
    cleann="$(pj "$o2/consistency.json" 'len(d["problems"])')"
    { printf '%s' "$types" | grep -q 'stale_vex' && printf '%s' "$types" | grep -q 'tool_only_ignore' && eq "$cleann" "0"; } \
      && ok || no "stale_vex+tool_only_ignore flagged; clean set has none" "types=$types clean_problems=$cleann"; }; }

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
begin "req6-ac1-env-agent-main-no-prtarget" "environment agent (restricted to main per policy), no pull_request_target, the job is not disabled with if:false"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  env_="$(pj "$WORK/sh.json" 'd.get("job_environment")')"; prt="$(pj "$WORK/sh.json" 'd.get("has_pull_request_target")')"
  onlymain="$(pj "$F/policy/env-01.json" 'str([b["name"] for b in d.get("branch_policies",[])]==["main"])')"
  disabled="$($YAML load "$WF" | "$PY" -c 'import json,sys
try:
    d=json.load(sys.stdin); jb=[j for j in d.get("jobs",{}).values() if isinstance(j,dict) and j.get("environment")=="agent"]
    print("yes" if (jb and jb[0].get("if") in (False,"false","${{ false }}")) else "no")
except Exception: print("yes")')"
  { eq "$env_" "agent" && eq "$prt" "false" && eq "$onlymain" "True" && eq "$disabled" "no"; } \
    && ok || no "environment agent, main-only, no pr_target, not if:false" "env=$env_ prtarget=$prt main-only=$onlymain disabled=$disabled"; fi

begin "req6-ac1-oidc-federation-no-api-key" "id-token:write + contents:read, OIDC audience via github-script into the identity-token file, no ANTHROPIC_API_KEY (all from the parsed doc, comments never count)"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  idt="$(pj "$WORK/sh.json" 'd.get("permissions",{}).get("id-token")')"; cont="$(pj "$WORK/sh.json" 'd.get("permissions",{}).get("contents")')"
  aud="$(pj "$WORK/sh.json" 'd.get("oidc_audience")')"; ghs="$(pj "$WORK/sh.json" 'd.get("uses_github_script_idtoken")')"
  tf="$(pj "$WORK/sh.json" 'd.get("sets_identity_token_file")')"; apik="$(pj "$WORK/sh.json" 'd.get("references_anthropic_api_key")')"
  { eq "$idt" "write" && eq "$cont" "read" && eq "$aud" "https://api.anthropic.com" && eq "$ghs" "true" && eq "$tf" "true" && eq "$apik" "false"; } \
    && ok || no "OIDC wired via github-script, no API key" "id-token=$idt contents=$cont audience=$aud github-script=$ghs token-file=$tf api-key=$apik"; fi

begin "req6-ac1-identifiers-are-env-secrets" "the six identifiers come from secrets.* (GitHub masks them); NO vars.* reference anywhere in the workflow"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  want='["ANTHROPIC_FEDERATION_RULE_ID","ANTHROPIC_ORGANIZATION_ID","ANTHROPIC_SERVICE_ACCOUNT_ID","ANTHROPIC_WORKSPACE_ID","AUDITOR_APP_ID","AUDITOR_APP_PRIVATE_KEY","AUDITOR_MODEL_FALLBACK","AUDITOR_MODEL_PRIMARY","SNYK_TOKEN"]'
  fromsecrets="$(pj "$WORK/sh.json" 'str(sorted(d.get("secret_refs",[]))=='"$want"')')"
  novars="$(pj "$WORK/sh.json" 'd.get("references_vars")')"
  { eq "$fromsecrets" "True" && eq "$novars" "false"; } \
    && ok || no "the identifiers + SNYK_TOKEN via secrets.*, no vars.* anywhere" "from_secrets=$fromsecrets references_vars=$novars secrets=$(pj "$WORK/sh.json" 'd.get("secret_refs")')"; fi

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
o="$WORK/leak"; rm -rf "$o"; canary="sk-ant-oat01-CANARY-$$"
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
"$PY" "$BIN/auditor-votes.py" --manifest "$F/run/manifest-01.json" --cve CVE-2011-3374 --adjudicator "$NOCALL" --out "$dv" >/dev/null 2>&1 || detok=no
[ -s "$LEDGER" ] && detok=no
[ "$(pj "$dv/votes.json" 'd.get("distinct_lineages")')" = "3" ] || detok=no
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
print("yes" if re.match(r"^owner-decision: CVE-2023-4911 — libc6 — \S", t) else "no")' "$title")"
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
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  s5="$(sect_ids "$o/report.md" 5)"; s3="$(sect_ids "$o/report.md" 3)"; s6="$(sect_ids "$o/report.md" 6)"
  vexev="$(pj "$o/evidence/CVE-2016-2781.evidence.json" 'str(bool(d.get("evidence")))')"
  ig="$(have "$o/ignores/grype/CVE-2016-2781.json" && echo yes || echo no)"
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
    && eq "$vexev" "True" && eq "$ig" "yes" && eq "$unrv" "vulnerable_code_not_in_execute_path" && eq "$acc" "yes" \
    && eq "$s3noaction" "0" && printf '%s' "$s6" | grep -q CVE-2023-4911 && [ "$status" -ge 1 ] 2>/dev/null \
    && eq "$det2781" "0" && eq "$det14040" "0" && eq "$shimcreates" "0"; } \
    && ok || no "deterministic §5/§3, every §3 row actioned, §6 would-open, AUDIT COMPLETE, deterministic paths made no model call, no shim" "s5=[$s5] s3=[$s3] s6=[$s6] vexev=$vexev ig=$ig unreach=$unrv acc=$acc s3_no_action=$s3noaction status=$status det2781=$det2781 det14040=$det14040 shim=$shimcreates"; }

begin "req12-ac2-realrun-opens-the-prs-through-the-shim" "the same run with dry_run=false records the bump/base-rebuild PR creates in the shim ledger"
o="$WORK/run2"; shim="$WORK/run2.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  prs="$(grep -cE 'pr create .*auditor/(bump|base-rebuild)' "$shim" 2>/dev/null)"; prs="${prs:-0}"
  { [ "$prs" -ge 1 ] 2>/dev/null; } && ok || no "bump/base-rebuild PR creates recorded in the shim ledger" "pr_creates=$prs"; }

begin "req12-ac3-workflow-invokes-the-entrypoint-with-dryrun" "the workflow's run step invokes auditor-run.py with the dispatch dry_run input"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  runs="$(pj "$WORK/sh.json" 'd.get("runs_auditor_run")')"
  eq "$runs" "true" && ok || no "run step invokes auditor-run.py with inputs.dry_run" "runs_auditor_run=$runs"; fi

########################################################################
echo "=== REQ-AUD-12 — Round 12: honest scanner status, no empty sections, conclusion ==="

begin "req12-ac4-no-empty-sections-and-conclusion" "the report opens with a Conclusion (stub: no narrative for stub runs) and every one of the 7 sections carries a non-empty sentence — never a blank heading"
o="$WORK/r12a"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --adjudicator "$STUB" --out "$o" && {
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
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-down.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; rcx=$?
named="$(grep -qi 'Did not run' "$o/report.md" && grep -qi 'grype' "$o/report.md" && echo yes || echo no)"
incomplete="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"
{ eq "$named" "yes" && eq "$incomplete" "yes" && [ "$rcx" -ne 0 ] 2>/dev/null; } \
  && ok || no "grype named did-not-run, AUDIT INCOMPLETE, non-zero exit" "named=$named incomplete=$incomplete exit=$rcx"

########################################################################
echo "=== inner-loop regressions (round 1) ==="

begin "il1-sibling-not-dropped" "a CVE partly covered by a log FP does NOT close the whole group: the uncovered sibling is routed to its own row with an action, never silently dropped"
o="$WORK/il1"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
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

begin "il2-zero-package-scanner-not-quorum" "image scanners recorded ran:true but package_count 0 do NOT count toward quorum: the run is AUDIT INCOMPLETE and exits non-zero"
o="$WORK/il2"; rm -rf "$o"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-zeropkg.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1; rcz=$?
inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"
quorum="$(grep -qi 'quorum 0/4' "$o/report.md" && echo yes || echo no)"
{ eq "$inc" "yes" && eq "$quorum" "yes" && [ "$rcz" -ne 0 ] 2>/dev/null; } \
  && ok || no "AUDIT INCOMPLETE, quorum 0/4, non-zero exit" "incomplete=$inc quorum=$quorum exit=$rcz"

begin "il3-model-id-never-in-report" "when the adjudicator errors, the Conclusion is a generic withheld line — the model id / SDK error text never reaches report.md"
o="$WORK/il3"; rm -rf "$o"; fa="$WORK/il3-fail.py"
cat > "$fa" <<'PYEOF'
import sys
sys.stderr.write("Error code: 404 model: claude-secret-codename-zzz not found\n")
sys.exit(5)
PYEOF
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --out "$o" >/dev/null 2>&1
leaked="$(grep -c 'claude-secret-codename-zzz' "$o/report.md" 2>/dev/null)"; leaked="${leaked:-0}"
withheld="$(grep -qi 'conclusion withheld' "$o/report.md" && echo yes || echo no)"
{ eq "$leaked" "0" && eq "$withheld" "yes"; } \
  && ok || no "no model id in report.md; conclusion withheld generically" "leaked=$leaked withheld=$withheld"

begin "il4-split-cve-distinct-vex-no-clobber" "a CVE that is not_affected for one package and carried for a sibling writes TWO distinct VEX files; the not_affected document is NOT overwritten by the affected one"
o="$WORK/il4"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  main_status="$(pj "$o/vex/CVE-2011-3374.openvex.json" 'd["statements"][0].get("status")')"
  sib="$(have "$o/vex/CVE-2011-3374-sibling.openvex.json" && echo yes || echo no)"
  sib_status="$(pj "$o/vex/CVE-2011-3374-sibling.openvex.json" 'd["statements"][0].get("status")')"
  { eq "$main_status" "not_affected" && eq "$sib" "yes" && eq "$sib_status" "affected"; } \
    && ok || no "not_affected VEX preserved + distinct affected sibling VEX" "main=$main_status sibling_file=$sib sibling=$sib_status"; }

########################################################################
echo "=== inner-loop regressions (round 3) ==="

begin "il5-owner-issue-deduped-across-runs" "two runs of the same at-threshold no-fix finding open ONE owner-decision issue then a comment, not two creates (REQ-AUD-9 AC2 on the live path)"
o="$WORK/il5"; shim="$WORK/il5.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$WORK/il5b" >/dev/null 2>&1
creates="$(grep -c 'issue create .*CVE-2099-9001' "$shim" 2>/dev/null)"; creates="${creates:-0}"
comments="$(grep -c 'issue comment .*CVE-2099-9001' "$shim" 2>/dev/null)"; comments="${comments:-0}"
{ eq "$creates" "1" && [ "$comments" -ge 1 ] 2>/dev/null; } \
  && ok || no "one issue create + a comment across two runs" "creates=$creates comments=$comments"

begin "il6-vex-consolidated-and-delivered-as-draft-pr" "a run that writes VEX consolidates it into suppressions/fosterstack-cache.openvex.json and delivers it as a single draft PR off main (R16), never a direct .vex edit"
o="$WORK/il6"; shim="$WORK/il6.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
consolidated="$(have "$o/suppressions/fosterstack-cache.openvex.json" && echo yes || echo no)"
nstmt="$(pj "$o/suppressions/fosterstack-cache.openvex.json" 'len(d.get("statements",[]))')"
draftpr="$(grep -c 'gh pr create --draft --base main --head auditor/2026-09-24-' "$shim" 2>/dev/null)"; draftpr="${draftpr:-0}"
offmain="$(grep -c 'git checkout -B auditor/2026-09-24-.* origin/main' "$shim" 2>/dev/null)"; offmain="${offmain:-0}"
{ eq "$consolidated" "yes" && [ "$nstmt" -ge 1 ] 2>/dev/null && [ "$draftpr" -ge 1 ] 2>/dev/null && [ "$offmain" -ge 1 ] 2>/dev/null; } \
  && ok || no "consolidated VEX + single draft PR off main" "consolidated=$consolidated statements=$nstmt draft_pr=$draftpr off_main=$offmain"

begin "il7-split-cve-distinct-statement-ids" "the not_affected and affected VEX documents for a split CVE carry DISTINCT statement @ids"
o="$WORK/il7"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  a="$(pj "$o/vex/CVE-2011-3374.openvex.json" 'd["statements"][0]["@id"]')"
  b="$(pj "$o/vex/CVE-2011-3374-sibling.openvex.json" 'd["statements"][0]["@id"]')"
  { [ "$a" != "$MISS" ] && [ "$b" != "$MISS" ] && [ "$a" != "$b" ]; } \
    && ok || no "distinct statement @ids" "main=$a sibling=$b"; }

begin "il8-consistency-not-blind-flags-stale-vex" "the consistency check reads the run's real consolidated suppressions and flags a stale VEX (a statement answering no live finding), so it is no longer structurally blind"
o="$WORK/il8"; supp="$WORK/il8-supp"; rm -rf "$o" "$supp"; mkdir -p "$supp"
printf '{"statements":[{"vulnerability":{"name":"CVE-1999-0001"},"status":"not_affected"}]}' > "$supp/fosterstack-cache.openvex.json"
run "$PY" "$BIN/auditor-consistency.py" --suppression-dir "$supp" --live-findings "$F/run/manifest-01.json" --out "$o/consistency.json" && {
  stale="$(pj "$o/consistency.json" '",".join(sorted({p["type"] for p in d["problems"]}))')"
  { printf '%s' "$stale" | grep -q 'stale_vex'; } \
    && ok || no "stale_vex flagged (not blind)" "problems=$stale"; }

########################################################################
echo "=== inner-loop regressions (round 4) ==="

begin "il9-pr-branch-created-before-pr-create" "a real run creates the branch (git checkout -b) BEFORE gh pr create for every PR — the PR never targets a branch that was never made"
o="$WORK/il9"; shim="$WORK/il9.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
ordered="$("$PY" -c '
import sys
lines=open(sys.argv[1]).read().splitlines()
ok=True
for i,l in enumerate(lines):
    if l.startswith("gh pr create --head "):
        br=l.split("--head ",1)[1].split()[0]
        made=any(x=="git checkout -b "+br for x in lines[:i])
        if not made: ok=False
print("yes" if ok else "no")' "$shim")"
prs="$(grep -c 'gh pr create --head' "$shim" 2>/dev/null)"; prs="${prs:-0}"
{ eq "$ordered" "yes" && [ "$prs" -ge 1 ] 2>/dev/null; } \
  && ok || no "every pr-create is preceded by its branch checkout" "ordered=$ordered pr_count=$prs"

begin "il10-consolidated-suppression-files-dedup-by-cve" "consolidated .snyk / osv-scanner.toml carry exactly ONE entry per CVE even when a CVE is split across two dispositions (no duplicate keys/blocks)"
o="$WORK/il10"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  snykn="$(grep -c 'CVE-2011-3374:' "$o/suppressions/.snyk" 2>/dev/null)"; snykn="${snykn:-0}"
  tomln="$(grep -c 'id = "CVE-2011-3374"' "$o/suppressions/osv-scanner.toml" 2>/dev/null)"; tomln="${tomln:-0}"
  yamlok="$("$PY" -c 'import sys
sys.path.insert(0,".github/agent/fixtures/testlib")
try: import yaml
except Exception: import pyyaml as yaml
d=yaml.safe_load(open(sys.argv[1]).read()) or {}
print("yes" if len(d.get("ignore",{}))>=1 else "no")' "$o/suppressions/.snyk")"
  { eq "$snykn" "1" && eq "$tomln" "1" && eq "$yamlok" "yes"; } \
    && ok || no "one .snyk key + one toml block per CVE" "snyk_keys=$snykn toml_blocks=$tomln yaml_parses=$yamlok"; }

begin "il11-consistency-not-false-stale-on-non-cve-id" "a carried VEX for a LIVE non-CVE id (DEBIAN-CVE-*) is not false-flagged stale"
o="$WORK/il11"; supp="$WORK/il11-supp"; rm -rf "$o" "$supp"; mkdir -p "$supp"
printf '{"statements":[{"vulnerability":{"name":"DEBIAN-CVE-2011-3374"},"status":"affected"}]}' > "$supp/fosterstack-cache.openvex.json"
run "$PY" "$BIN/auditor-consistency.py" --suppression-dir "$supp" --live-findings "$F/run/manifest-01.json" --out "$o/c.json" && {
  probs="$(pj "$o/c.json" 'len(d["problems"])')"
  { eq "$probs" "0"; } && ok || no "no false stale_vex for a live non-CVE id" "problems=$probs"; }

begin "il12-section7-lists-suppressions-in-force" "§7 lists the suppressions actually in force this run, not a blanket 'no suppressions'"
o="$WORK/il12"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  s7="$(sect_ids "$o/report.md" 7)"
  blanket="$(sed -n '/## 7\./,/^$/p' "$o/report.md" | grep -qi 'No suppressions are in force' && echo yes || echo no)"
  { printf '%s' "$s7" | grep -q CVE-2011-3374 && printf '%s' "$s7" | grep -q CVE-2020-14040 && eq "$blanket" "no"; } \
    && ok || no "§7 lists in-force suppressions, not the empty sentence" "sec7=[$s7] blanket_empty=$blanket"; }

########################################################################
echo "=== inner-loop regressions (round 5) ==="

begin "il13-pr-action-text-honest-proposed" "a real run's §3 rows say 'proposed ... PR', never a false 'opened' — the driver does not deliver PRs itself"
o="$WORK/il13"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  lied="$(grep -cE 'action: opened (bump|base-rebuild) PR' "$o/report.md" 2>/dev/null)"; lied="${lied:-0}"
  proposed="$(grep -cE 'action: proposed (bump|base-rebuild) PR' "$o/report.md" 2>/dev/null)"; proposed="${proposed:-0}"
  { eq "$lied" "0" && [ "$proposed" -ge 1 ] 2>/dev/null; } \
    && ok || no "no false 'opened', at least one honest 'proposed'" "opened=$lied proposed=$proposed"; }

begin "il14-consolidated-ignore-cites-all-statement-ids" "a split CVE's consolidated ignore cites BOTH statement ids (the sibling id is not orphaned)"
o="$WORK/il14"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  both="$(grep -A2 'CVE-2011-3374:' "$o/suppressions/.snyk" | grep -c 'stmt-cve-2011-3374-sibling')"; both="${both:-0}"
  base="$(grep -A2 'CVE-2011-3374:' "$o/suppressions/.snyk" | grep -c 'stmt-cve-2011-3374 ')"; base="${base:-0}"
  { [ "$both" -ge 1 ] 2>/dev/null; } \
    && ok || no "both statement ids cited in the consolidated ignore" "sibling_id_cited=$both"; }

begin "il15-section7-poam-row-names-real-vex-id" "a §7 POA&M (carried) row names a real VEX statement id, not the literal placeholder '(VEX)'"
o="$WORK/il15"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  poam7="$(sed -n '/## 7\./,/^$/p' "$o/report.md" | grep 'carried (POA&M)')"
  realid="$(printf '%s' "$poam7" | grep -c 'suppression in force (http')"; realid="${realid:-0}"
  placeholder="$(printf '%s' "$poam7" | grep -c 'suppression in force (VEX)')"; placeholder="${placeholder:-0}"
  { [ "$realid" -ge 1 ] 2>/dev/null && eq "$placeholder" "0"; } \
    && ok || no "§7 POA&M row names a real vex id, no '(VEX)' placeholder" "real_id_rows=$realid placeholder_rows=$placeholder"; }

########################################################################
echo "=== Round 16 — App-token draft-PR delivery ==="

begin "r16-push-failure-is-incomplete" "a suppression PR push/PR failure makes the run AUDIT INCOMPLETE (non-zero exit), with the git/gh stderr in the report — never a false 'opened'"
o="$WORK/r16f"; shim="$WORK/r16f.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_SHIM_PR_FAIL=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1; rcf=$?
inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"
stderrline="$(sed -n '/## 6\./,/^$/p' "$o/report.md" | grep -qi 'delivery FAILED' && echo yes || echo no)"
lied="$(grep -ci 'draft PR opened' "$o/report.md" 2>/dev/null)"; lied="${lied:-0}"
{ [ "$rcf" -ne 0 ] 2>/dev/null && eq "$inc" "yes" && eq "$stderrline" "yes" && eq "$lied" "0"; } \
  && ok || no "push failure -> INCOMPLETE + stderr, no false 'opened'" "exit=$rcf incomplete=$inc stderr_in_report=$stderrline false_opened=$lied"

begin "r16-single-nonstacked-draft-branch" "delivery opens exactly ONE branch, based on origin/main (non-stacked), with the --draft flag"
o="$WORK/r16s"; shim="$WORK/r16s.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
branches="$(grep -c 'git checkout -B auditor/' "$shim" 2>/dev/null)"; branches="${branches:-0}"
offmain="$(grep -c 'git checkout -B auditor/.* origin/main' "$shim" 2>/dev/null)"; offmain="${offmain:-0}"
draft="$(grep -c 'gh pr create --draft' "$shim" 2>/dev/null)"; draft="${draft:-0}"
{ eq "$branches" "1" && eq "$offmain" "1" && eq "$draft" "1"; } \
  && ok || no "one branch off origin/main, one draft PR" "branches=$branches off_main=$offmain draft=$draft"

begin "r16-pr-url-in-section6" "the delivered draft PR's URL is recorded in report §6"
o="$WORK/r16u"; shim="$WORK/r16u.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
url="$(sed -n '/## 6\./,/^$/p' "$o/report.md" | grep -c '/pull/')"; url="${url:-0}"
{ [ "$url" -ge 1 ] 2>/dev/null; } && ok || no "PR URL present in §6" "pull_url_lines=$url"

begin "r16-no-vendor-or-model-name-in-delivery" "no vendor/model name appears in the delivery branch, commit, or PR text"
o="$WORK/r16n"; shim="$WORK/r16n.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
names="$(grep -iE 'git checkout -B auditor/|git commit -m|gh pr create' "$shim" | grep -ciE 'anthropic|claude|openai|codex|sonnet|opus|gpt|chatgpt')"; names="${names:-0}"
rptnames="$(sed -n '/## 6\./,/^$/p' "$o/report.md" | grep -ciE 'anthropic|claude|openai|codex|sonnet|opus|gpt|chatgpt')"; rptnames="${rptnames:-0}"
{ eq "$names" "0" && eq "$rptnames" "0"; } \
  && ok || no "no vendor/model name in branch/commit/PR or §6" "in_shim=$names in_section6=$rptnames"

########################################################################
echo "=== Round 16 corrections — issues token, test-image PR gating ==="

begin "r16-issues-use-job-token-pr-uses-app-token" "gh issue calls carry the JOB (issues) token; git push / gh pr create carry the App token — verified via fake gh/git on PATH"
o="$WORK/r16t"; rm -rf "$o"; fb="$WORK/r16t-bin"; rm -rf "$fb"; mkdir -p "$fb"; glog="$WORK/r16t-gh.log"; rm -f "$glog"
cat > "$fb/gh" <<EOF
#!/usr/bin/env bash
echo "GH_TOKEN=\${GH_TOKEN} ARGS=\$*" >> "$glog"
if [ "\$1" = "issue" ] && [ "\$2" = "list" ]; then echo "[]"; fi
if [ "\$1" = "pr" ] && [ "\$2" = "create" ]; then echo "https://github.com/OWNER/REPO/pull/1"; fi
exit 0
EOF
cat > "$fb/git" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$fb/gh" "$fb/git"
env PATH="$fb:$PATH" AUDITOR_ALLOW_REAL_GH=1 GH_TOKEN=APP_TOKEN_123 AUDITOR_ISSUES_TOKEN=JOB_TOKEN_456 \
  "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
issuejob="$(grep 'ARGS=issue' "$glog" | grep -c 'GH_TOKEN=JOB_TOKEN_456')"; issuejob="${issuejob:-0}"
issueapp="$(grep 'ARGS=issue' "$glog" | grep -c 'GH_TOKEN=APP_TOKEN_123')"; issueapp="${issueapp:-0}"
prapp="$(grep 'ARGS=pr create' "$glog" | grep -c 'GH_TOKEN=APP_TOKEN_123')"; prapp="${prapp:-0}"
{ [ "$issuejob" -ge 1 ] 2>/dev/null && eq "$issueapp" "0" && [ "$prapp" -ge 1 ] 2>/dev/null; } \
  && ok || no "issue calls use job token, pr create uses app token" "issue_job=$issuejob issue_app=$issueapp pr_app=$prapp"

begin "r16-exactly-one-gh-token-key-in-driver-env" "the driver step's env block declares GH_TOKEN exactly once"
n="$(awk '/name: Run the auditor/{f=1} f&&/^        run:/{f=0} f&&/GH_TOKEN:/{c++} END{print c+0}' "$WF")"
eq "$n" "1" && ok || no "exactly one GH_TOKEN key in the driver env" "count=$n"

begin "r16-no-test-image-pr-in-production" "a test-image run without the proof flag opens NO PR (a VEX for an image we do not ship is not a proposal)"
o="$WORK/r16ti"; shim="$WORK/r16ti.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-testimage.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1; rc=$?
draftpr="$(grep -c 'gh pr create --draft' "$shim" 2>/dev/null)"; draftpr="${draftpr:-0}"
noted="$(sed -n '/## 6\./,/^$/p' "$o/report.md" | grep -qi 'test-image run: no PR' && echo yes || echo no)"
{ eq "$draftpr" "0" && eq "$noted" "yes" && [ "$rc" -eq 0 ] 2>/dev/null; } \
  && ok || no "no suppression draft PR for a test-image production run; noted; run not failed" "draft_prs=$draftpr noted=$noted exit=$rc"

begin "r16-proof-flag-allows-prefixed-test-image-pr" "with AUDITOR_PROOF_PR=1 a test-image run opens one draft PR whose title is prefixed 'proof — do not merge'"
o="$WORK/r16pf"; shim="$WORK/r16pf.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_PROOF_PR=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-testimage.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
prefixed="$(grep -c "gh pr create --draft --base main --head auditor/proof-.* --title 'proof — do not merge:" "$shim" 2>/dev/null)"; prefixed="${prefixed:-0}"
{ [ "$prefixed" -ge 1 ] 2>/dev/null; } && ok || no "proof draft PR with the 'proof — do not merge' prefix" "prefixed_pr=$prefixed"

echo "----"
echo "auditor-matrix: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
