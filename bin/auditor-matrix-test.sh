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

begin "req6-ac1-identifiers-are-env-secrets" "the six identifiers + tokens come from secrets.* (GitHub masks them); the ONLY vars.* is the non-secret AUDITOR_SCHEDULE_MODE toggle — no secret identifier is ever a vars.*"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  want='["ANTHROPIC_FEDERATION_RULE_ID","ANTHROPIC_ORGANIZATION_ID","ANTHROPIC_SERVICE_ACCOUNT_ID","ANTHROPIC_WORKSPACE_ID","AUDITOR_APP_ID","AUDITOR_APP_PRIVATE_KEY","AUDITOR_MODEL_FALLBACK","AUDITOR_MODEL_PRIMARY","SNYK_TOKEN"]'
  fromsecrets="$(pj "$WORK/sh.json" 'str(sorted(d.get("secret_refs",[]))=='"$want"')')"
  # the only permitted variable is the non-secret schedule toggle; none of the secret
  # identifiers may appear as vars.* (they would not be masked)
  onlytoggle="$(pj "$WORK/sh.json" 'str(sorted(d.get("identifier_env_vars",[]))==["AUDITOR_SCHEDULE_MODE"])')"
  { eq "$fromsecrets" "True" && eq "$onlytoggle" "True"; } \
    && ok || no "identifiers+SNYK_TOKEN via secrets.*; only vars.* is AUDITOR_SCHEDULE_MODE" "from_secrets=$fromsecrets only_toggle=$onlytoggle vars=$(pj "$WORK/sh.json" 'd.get("identifier_env_vars")')"; fi

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
  s5="$(sect_ids "$o/report.md" 5)"; s3="$(sect_ids "$o/report.md" 3)"; s6="$(sed -n '/^## PRs and issues this run/,/^## 0\./p' "$o/report.md")"
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
    && eq "$s3noaction" "0" && printf '%s' "$s6" | grep -qi 'would open' && [ "$status" -ge 1 ] 2>/dev/null \
    && eq "$det2781" "0" && eq "$det14040" "0" && eq "$shimcreates" "0"; } \
    && ok || no "deterministic §5/§3, every §3 row actioned, §6 would-open, AUDIT COMPLETE, deterministic paths made no model call, no shim" "s5=[$s5] s3=[$s3] s6=[$s6] vexev=$vexev ig=$ig unreach=$unrv acc=$acc s3_no_action=$s3noaction status=$status det2781=$det2781 det14040=$det14040 shim=$shimcreates"; }

begin "req12-ac2-realrun-opens-the-prs-through-the-shim" "with a delivery channel (shim), dry_run=false DELIVERS the Go bump as a DRAFT PR (go get + go mod tidy, go.mod/go.sum) recorded in the shim ledger, plus the suppression draft PR; a base rebuild is NOT a PR (defers to Dependabot)"
o="$WORK/run2"; shim="$WORK/run2.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  bump="$(grep -cE 'pr create --draft .*auditor/bump' "$shim" 2>/dev/null)"; bump="${bump:-0}"
  baserb="$(grep -cE 'auditor/base-rebuild' "$shim" 2>/dev/null)"; baserb="${baserb:-0}"
  goget="$(grep -cE '^go get ' "$shim" 2>/dev/null)"; goget="${goget:-0}"
  tidy="$(grep -cE '^go mod tidy' "$shim" 2>/dev/null)"; tidy="${tidy:-0}"
  addonly="$(grep -cE '^git add go\.mod go\.sum$' "$shim" 2>/dev/null)"; addonly="${addonly:-0}"
  { [ "$bump" -ge 1 ] 2>/dev/null && [ "$baserb" -eq 0 ] 2>/dev/null && [ "$goget" -ge 1 ] 2>/dev/null && [ "$tidy" -ge 1 ] 2>/dev/null && [ "$addonly" -ge 1 ] 2>/dev/null; } \
    && ok || no "draft bump PR delivered via go get/tidy + go.mod/go.sum only; base rebuild is not a PR" "bump=$bump base_rebuild_prs=$baserb goget=$goget tidy=$tidy add_gomod_gosum=$addonly"; }

begin "req12-ac3-workflow-invokes-the-entrypoint-with-dryrun" "the workflow's run step invokes auditor-run.py with the dispatch dry_run input"
if ! have "$WF"; then no "$WF present" "absent"; else
  $YAML shape "$WF" > "$WORK/sh.json"
  runs="$(pj "$WORK/sh.json" 'd.get("runs_auditor_run")')"
  eq "$runs" "true" && ok || no "run step invokes auditor-run.py with inputs.dry_run" "runs_auditor_run=$runs"; fi

begin "req12-schedule-mode-unset-is-dry" "a scheduled run is DRY unless the repo variable AUDITOR_SCHEDULE_MODE is exactly 'live' (unset => dry); both the dry flag and the App-token step follow it; dispatch follows dry_run"
if ! have "$WF"; then no "$WF present" "absent"; else
  r="$(WF="$WF" "$PY" - <<'PY'
import os, re, sys
sys.path.insert(0, ".github/agent/fixtures/testlib")
import pyyaml as yaml
doc = yaml.safe_load(open(os.environ["WF"]).read()) or {}
jobs = doc.get("jobs") or {}
job = next((j for j in jobs.values() if isinstance(j, dict) and j.get("environment") == "agent"), None) or (list(jobs.values())[0] if jobs else {})
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
quorum="$(grep -qiE '0 of 4 inventoried the OS layer' "$o/report.md" && grep -qi 'OS counts:' "$o/report.md" && echo yes || echo no)"
{ eq "$inc" "yes" && eq "$quorum" "yes" && [ "$rcz" -ne 0 ] 2>/dev/null; } \
  && ok || no "AUDIT INCOMPLETE, 0 of 4 inventoried OS + per-scanner counts, non-zero exit" "incomplete=$inc quorum=$quorum exit=$rcz"

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

begin "dadj-1-adjudicator-unavailable-one-issue-incomplete" "when the adjudicator is UNAVAILABLE (every call errors), the run is AUDIT INCOMPLETE naming the cause, exactly ONE aggregate owner issue 'adjudicator unavailable — N findings unassessed' is opened (never one per finding), and the header names the (masked) cause (R-live fixes 1+3)"
o="$WORK/dadj1"; shim="$WORK/dadj1.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$F/adjudicator/fail-on-call.py" --out "$o" >/dev/null 2>&1
inc="$(grep -c 'AUDIT INCOMPLETE:.*adjudicator unavailable' "$o/report.md" 2>/dev/null)"; inc="${inc:-0}"
agg="$(grep -cE "issue create.*adjudicator unavailable — [0-9]+ findings unassessed" "$shim" 2>/dev/null)"; agg="${agg:-0}"
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
AUDITOR_MODEL_PRIMARY="SENTINEL_SECRET_9137" "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --out "$o" >/dev/null 2>&1
surfaced="$(grep -c 'UNAVAILABLE' "$o/report.md" 2>/dev/null)"; surfaced="${surfaced:-0}"
leak_secret="$(grep -c 'SENTINEL_SECRET_9137' "$o/report.md" 2>/dev/null)"; leak_secret="${leak_secret:-0}"
leak_model="$(grep -c 'claude-secret-zzz' "$o/report.md" 2>/dev/null)"; leak_model="${leak_model:-0}"
masked="$(grep -cE '<AUDITOR_MODEL_PRIMARY>|<model-id>' "$o/report.md" 2>/dev/null)"; masked="${masked:-0}"
{ [ "$surfaced" -ge 1 ] 2>/dev/null && eq "$leak_secret" "0" && eq "$leak_model" "0" && [ "$masked" -ge 1 ] 2>/dev/null; } \
  && ok || no "error surfaced; secret value + model id masked" "surfaced=$surfaced leak_secret=$leak_secret leak_model=$leak_model masked=$masked"

begin "dadj-3-quorum-status-shows-per-scanner-os-counts" "the OS-package quorum line shows the per-scanner OS counts it compared, names 0-OS scanners as 'did not inventory OS' (abstain, not a disagreeing vote), and never claims '4/4 agreeing' against disparate counts (R-live fix 2)"
o="$WORK/dadj3"; rm -rf "$o"
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-osquorum.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
counts="$(grep -c 'OS counts: grype(0), trivy(53), osv-scanner(0), snyk(53)' "$o/report.md" 2>/dev/null)"; counts="${counts:-0}"
abstain="$(grep -c 'did not inventory OS: grype, osv-scanner' "$o/report.md" 2>/dev/null)"; abstain="${abstain:-0}"
inv2="$(grep -c '2 of 4 inventoried the OS layer' "$o/report.md" 2>/dev/null)"; inv2="${inv2:-0}"
notfour="$(grep -cE '4/4 (agreeing|\(need)' "$o/report.md" 2>/dev/null)"; notfour="${notfour:-0}"
{ [ "$counts" -ge 1 ] 2>/dev/null && [ "$abstain" -ge 1 ] 2>/dev/null && [ "$inv2" -ge 1 ] 2>/dev/null && eq "$notfour" "0"; } \
  && ok || no "quorum shows compared per-scanner OS counts; 0-OS scanners abstain; no false 4/4" "counts=$counts abstain=$abstain inv2=$inv2 false_4of4=$notfour"

begin "dadj-4-owner-issue-one-per-cve-package-scopes-in-body" "an at-threshold no-fix (CVE, package) present in TWO scopes opens exactly ONE owner-decision issue whose body lists BOTH scopes — never one issue per binary/version that vendors the package (R-live fix 4)"
o="$WORK/dadj4"; shim="$WORK/dadj4.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-owner-multiscope.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
creates="$(grep -c 'issue create.*CVE-2099-7777' "$shim" 2>/dev/null)"; creates="${creates:-0}"
both="$(grep -c 'libfoo@1' "$shim" 2>/dev/null)"; both="${both:-0}"
both2="$(grep -c 'libfoo@2' "$shim" 2>/dev/null)"; both2="${both2:-0}"
scopes2="$(grep -c 'Scope(s) (2)' "$shim" 2>/dev/null)"; scopes2="${scopes2:-0}"
{ eq "$creates" "1" && [ "$both" -ge 1 ] 2>/dev/null && [ "$both2" -ge 1 ] 2>/dev/null && [ "$scopes2" -ge 1 ] 2>/dev/null; } \
  && ok || no "one issue for (CVE,package) with both scopes in the body" "creates=$creates libfoo@1=$both libfoo@2=$both2 scopes2=$scopes2"

begin "dadj-5-grype-counts-apk-and-rpm-os-packages" "grype's OS-package inventory counts apk (Alpine) and rpm, not just deb — an Alpine image inventories its OS layer, so the quorum does not fail on every Alpine base (R-live: apk count)"
gr="$WORK/grype-alpine.json"
cat > "$gr" <<'JSON'
{"matches":[
 {"artifact":{"name":"musl","version":"1.2.4","type":"apk","purl":"pkg:apk/alpine/musl@1.2.4"}},
 {"artifact":{"name":"busybox","version":"1.36","type":"apk","purl":"pkg:apk/alpine/busybox@1.36"}},
 {"artifact":{"name":"openssl","version":"3.1","type":"apk","purl":"pkg:apk/alpine/openssl@3.1"}},
 {"artifact":{"name":"leftpad","version":"1.0","type":"npm","purl":"pkg:npm/leftpad@1.0"}}
],"descriptor":{"name":"grype","version":"0.118.0","db":{"status":{"from":"x_2026-09-25T00:00:00Z_x"}}}}
JSON
r="$(MF="$gr" "$PY" - <<'PYEOF'
import importlib.util, os
spec=importlib.util.spec_from_file_location("m",".github/agent/bin/auditor-manifest.py"); M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
total, osp, db, findings = M._inv_grype(os.environ["MF"])
print("os=%d apk_type=%s apk_purl=%s rpm=%s deb=%s npm=%s" % (
  osp, M._is_os_pkg({"type":"apk"}), M._is_os_pkg({"purl":"pkg:apk/alpine/x@1"}),
  M._is_os_pkg({"type":"rpm"}), M._is_os_pkg({"type":"deb"}),
  M._is_os_pkg({"type":"npm","purl":"pkg:npm/x@1"})))
PYEOF
)"
osc="$(printf '%s' "$r" | grep -oE 'os=[0-9]+' | cut -d= -f2)"; osc="${osc:-0}"
apkt="$(printf '%s' "$r" | grep -oE 'apk_type=[A-Za-z]+' | cut -d= -f2)"
rpm="$(printf '%s' "$r" | grep -oE 'rpm=[A-Za-z]+' | cut -d= -f2)"
npm="$(printf '%s' "$r" | grep -oE 'npm=[A-Za-z]+' | cut -d= -f2)"
{ [ "$osc" = "3" ] 2>/dev/null && eq "$apkt" "True" && eq "$rpm" "True" && eq "$npm" "False"; } \
  && ok || no "grype counts 3 apk OS packages; apk+rpm are OS, npm is not" "[$r]"

begin "dadj-6-adjudicator-error-dedup-collapses-volatile-request-id" "repeated adjudicator failures that differ ONLY by a per-call request_id collapse to ONE recorded error (not one per finding/attempt), so the header/status is not flooded (R-live fix 1 dedup)"
o="$WORK/dadj6"; rm -rf "$o"; fa="$WORK/dadj6-fail.py"
cat > "$fa" <<'PYEOF'
import os, sys, time
# a unique request_id per invocation — without normalization these would each be "distinct"
sys.stderr.write("APIConnectionError status=503: transient upstream [request_id=req_%d_%d]\n" % (os.getpid(), time.time_ns()))
sys.exit(5)
PYEOF
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --out "$o" >/dev/null 2>&1
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
ADJ_COUNT="$cnt" "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-owner-multiscope.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --out "$o" >/dev/null 2>&1
starts="$(grep -c START "$cnt" 2>/dev/null)"; starts="${starts:-0}"
reqs="$(grep -c REQ "$cnt" 2>/dev/null)"; reqs="${reqs:-0}"
{ eq "$starts" "1" && [ "$reqs" -ge 2 ] 2>/dev/null; } \
  && ok || no "one process start (one exchange) serving >=2 adjudications" "starts=$starts reqs=$reqs"

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

begin "il9-pr-branch-created-before-pr-create" "a real run creates the branch (git checkout -B ... origin/main) BEFORE gh pr create for every PR — the PR never targets a branch that was never made"
o="$WORK/il9"; shim="$WORK/il9.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
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

begin "il12-suppressions-in-force-listed-in-section5" "the in-force suppressions are listed in §5 with status tags (v2 removed the standalone §7)"
o="$WORK/il12"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  s5="$(sect_ids "$o/report.md" 5)"
  { printf '%s' "$s5" | grep -q CVE-2011-3374 && printf '%s' "$s5" | grep -q CVE-2020-14040; } \
    && ok || no "§5 lists the in-force (closed) suppressions with their status tags" "sec5=[$s5]"; }

########################################################################
echo "=== inner-loop regressions (round 5) ==="

begin "il13-pr-action-text-honest-no-channel" "a non-dry run with NO delivery channel (no shim, real gh not opted in) never falsely claims 'opened': a Go bump says it is pending an authorized step, and a base rebuild says it defers to Dependabot — never 'opened draft bump PR' (decision 2)"
o="$WORK/il13"; rm -rf "$o"; : > "$LEDGER"
# no AUDITOR_GIT_SHIM_LOG and no AUDITOR_ALLOW_REAL_GH => the safety default: deliver nothing, claim nothing
run "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  lied="$(grep -c 'opened draft bump PR' "$o/report.md" 2>/dev/null)"; lied="${lied:-0}"
  pending="$(grep -c 'bump PR pending: no authorized delivery step' "$o/report.md" 2>/dev/null)"; pending="${pending:-0}"
  defers="$(grep -c "defer to Dependabot's docker PR" "$o/report.md" 2>/dev/null)"; defers="${defers:-0}"
  { eq "$lied" "0" && [ "$pending" -ge 1 ] 2>/dev/null && [ "$defers" -ge 1 ] 2>/dev/null; } \
    && ok || no "no false 'opened'; honest pending bump + base rebuild defers to Dependabot" "opened=$lied pending=$pending defers=$defers"; }

begin "d2-1-gobump-draft-delivered-and-reported" "decision 2: with a delivery channel, a Go-module §3 bump is DELIVERED as a draft PR by the App; the row action says 'opened draft bump PR' and §6 lists it — never a false 'proposed ... delivery pending'"
o="$WORK/d2-1"; shim="$WORK/d2-1.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  opened="$(grep -c 'action: opened draft bump PR' "$o/report.md" 2>/dev/null)"; opened="${opened:-0}"
  sec6="$(grep -c 'Bump draft PR (App):' "$o/report.md")"; sec6="${sec6:-0}"
  stale="$(grep -c 'delivery pending' "$o/report.md" 2>/dev/null)"; stale="${stale:-0}"
  { [ "$opened" -ge 1 ] 2>/dev/null && [ "$sec6" -ge 1 ] 2>/dev/null && eq "$stale" "0"; } \
    && ok || no "Go bump delivered as draft PR, listed in the PR list, no stale 'delivery pending'" "opened=$opened prlist=$sec6 stale=$stale"; }

begin "d2-2-base-rebuild-defers-to-dependabot" "decision 2: an OS-package §3 base rebuild is NOT delivered by the auditor — it defers to Dependabot's docker PR (base is digest-pinned); §6 says 'Awaiting base rebuild (deferred to Dependabot ...)' and no auditor base-rebuild PR is created"
o="$WORK/d2-2"; shim="$WORK/d2-2.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
run env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  defers="$(grep -c 'awaiting base rebuild' "$o/report.md")"; defers="${defers:-0}"
  noprs="$(grep -cE 'auditor/base-rebuild' "$shim" 2>/dev/null)"; noprs="${noprs:-0}"
  { [ "$defers" -ge 1 ] 2>/dev/null && eq "$noprs" "0"; } \
    && ok || no "base rebuild defers to Dependabot; no auditor base-rebuild PR" "awaiting=$defers base_rebuild_prs=$noprs"; }

begin "d2-3-bump-delivery-failure-marks-incomplete" "decision 2: a bump PR delivery FAILURE marks the run AUDIT INCOMPLETE and exits non-zero (never a false 'opened')"
o="$WORK/d2-3"; shim="$WORK/d2-3.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
# a delivery failure makes auditor-run exit non-zero by design; do not use run()
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_SHIM_PR_FAIL=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1
rc=$?
incomplete="$(grep -c 'AUDIT INCOMPLETE' "$o/report.md" 2>/dev/null)"; incomplete="${incomplete:-0}"
failed="$(grep -c 'bump PR delivery FAILED' "$o/report.md" 2>/dev/null)"; failed="${failed:-0}"
{ [ "$rc" -ne 0 ] 2>/dev/null && [ "$incomplete" -ge 1 ] 2>/dev/null && [ "$failed" -ge 1 ] 2>/dev/null; } \
  && ok || no "delivery failure => INCOMPLETE, non-zero exit, honest FAILED line" "rc=$rc incomplete=$incomplete failed=$failed"

begin "il14-consolidated-ignore-cites-all-statement-ids" "a split CVE's consolidated ignore cites BOTH statement ids (the sibling id is not orphaned)"
o="$WORK/il14"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  # the split CVE's two dispositions each get a distinct scope-derived @id (REQ-AUD-13 AC2);
  # the consolidated ignore must cite BOTH (neither orphaned)
  both="$(grep -A2 'CVE-2011-3374:' "$o/suppressions/.snyk" | grep -oE 'stmt-cve-2011-3374~[a-f0-9]+' | sort -u | wc -l | tr -d ' ')"; both="${both:-0}"
  { [ "$both" -ge 2 ] 2>/dev/null; } \
    && ok || no "both statement ids cited in the consolidated ignore" "distinct_ids_cited=$both"; }

begin "il15-poam-row-names-real-vex-id" "a §2 POA&M (carried) row names a real VEX statement id, not the literal placeholder '(VEX)'"
o="$WORK/il15"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  poam="$(sed -n '/^## 2\./,/^## 3\./p' "$o/report.md" | grep 'carried (POA&M)')"
  realid="$(printf '%s' "$poam" | grep -c 'vex: .*stmt-')"; realid="${realid:-0}"
  placeholder="$(printf '%s' "$poam" | grep -c 'vex: (VEX)')"; placeholder="${placeholder:-0}"
  { [ "$realid" -ge 1 ] 2>/dev/null && eq "$placeholder" "0"; } \
    && ok || no "§2 POA&M row names a real vex statement id, no '(VEX)' placeholder" "real_id_rows=$realid placeholder_rows=$placeholder"; }

########################################################################
echo "=== Round 16 — App-token draft-PR delivery ==="

begin "r16-push-failure-is-incomplete" "a suppression PR push/PR failure makes the run AUDIT INCOMPLETE (non-zero exit), with the git/gh stderr in the report — never a false 'opened'"
o="$WORK/r16f"; shim="$WORK/r16f.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_SHIM_PR_FAIL=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1; rcf=$?
inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && echo yes || echo no)"
stderrline="$(grep -qi 'delivery FAILED' "$o/report.md" && echo yes || echo no)"
lied="$(grep -ci 'draft PR opened' "$o/report.md" 2>/dev/null)"; lied="${lied:-0}"
{ [ "$rcf" -ne 0 ] 2>/dev/null && eq "$inc" "yes" && eq "$stderrline" "yes" && eq "$lied" "0"; } \
  && ok || no "push failure -> INCOMPLETE + stderr, no false 'opened'" "exit=$rcf incomplete=$inc stderr_in_report=$stderrline false_opened=$lied"

begin "r16-nonstacked-draft-branches" "every delivery branch (suppression + each bump) is based on origin/main (non-stacked) and every delivered PR carries --draft"
o="$WORK/r16s"; shim="$WORK/r16s.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
branches="$(grep -c 'git checkout -B auditor/' "$shim" 2>/dev/null)"; branches="${branches:-0}"
offmain="$(grep -c 'git checkout -B auditor/.* origin/main' "$shim" 2>/dev/null)"; offmain="${offmain:-0}"
draft="$(grep -c 'gh pr create --draft' "$shim" 2>/dev/null)"; draft="${draft:-0}"
# at least the suppression PR + the one Go bump; every branch off origin/main; every PR a draft
{ [ "$branches" -ge 2 ] 2>/dev/null && eq "$offmain" "$branches" && eq "$draft" "$branches"; } \
  && ok || no "each branch off origin/main (non-stacked), each PR --draft" "branches=$branches off_main=$offmain draft=$draft"

begin "r16-pr-url-in-pr-list" "the delivered draft PR's URL is recorded in the 'PRs and issues this run' list"
o="$WORK/r16u"; shim="$WORK/r16u.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
url="$(sed -n '/^## PRs and issues this run/,/^## 0\./p' "$o/report.md" | grep -c '/pull/')"; url="${url:-0}"
{ [ "$url" -ge 1 ] 2>/dev/null; } && ok || no "PR URL present in the PR list" "pull_url_lines=$url"

begin "r16-no-vendor-or-model-name-in-delivery" "the delivery ACTUALLY happens (draft PR + branch in the ledger) AND no vendor/model name appears in its branch, commit, or PR text"
o="$WORK/r16n"; shim="$WORK/r16n.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
delivered="$(grep -cE 'gh pr create --draft --base main --head auditor/2026-09-24-' "$shim" 2>/dev/null)"; delivered="${delivered:-0}"
names="$(grep -iE 'git checkout -B auditor/|git commit -m|gh pr create' "$shim" | grep -ciE 'anthropic|claude|openai|codex|sonnet|opus|gpt|chatgpt')"; names="${names:-0}"
rptnames="$(sed -n '/## 6\./,/^$/p' "$o/report.md" | grep -ciE 'anthropic|claude|openai|codex|sonnet|opus|gpt|chatgpt')"; rptnames="${rptnames:-0}"
{ [ "$delivered" -ge 1 ] 2>/dev/null && eq "$names" "0" && eq "$rptnames" "0"; } \
  && ok || no "delivery occurred with no vendor/model name in branch/commit/PR or §6" "delivered=$delivered in_shim=$names in_section6=$rptnames"

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
forced="$(grep -c '\*\*dry_run:\*\* yes' "$o/report.md" 2>/dev/null)"; forced="${forced:-0}"
noted="$(grep -qi 'test-image run: no PR' "$o/report.md" && echo yes || echo no)"
{ eq "$draftpr" "0" && eq "$noted" "yes" && [ "$forced" -ge 1 ] 2>/dev/null && [ "$rc" -eq 0 ] 2>/dev/null; } \
  && ok || no "test image forces dry (AC9): no draft PR, noted, run not failed" "draft_prs=$draftpr forced_dry=$forced noted=$noted exit=$rc"

begin "r16-test-image-forces-dry-retires-proof-flag" "a test image ALWAYS forces dry (REQ-AUD-15 AC9): even with AUDITOR_PROOF_PR=1 it opens NO real PR — the proof-on-test-image path is retired"
o="$WORK/r16pf"; shim="$WORK/r16pf.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_PROOF_PR=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-testimage.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
realpr="$(grep -c 'gh pr create --draft' "$shim" 2>/dev/null)"; realpr="${realpr:-0}"
proofpr="$(grep -c 'proof — do not merge' "$shim" 2>/dev/null)"; proofpr="${proofpr:-0}"
forced="$(grep -c '\*\*dry_run:\*\* yes' "$o/report.md" 2>/dev/null)"; forced="${forced:-0}"
{ eq "$realpr" "0" && eq "$proofpr" "0" && [ "$forced" -ge 1 ] 2>/dev/null; } \
  && ok || no "test image dry, no real/proof PR" "real_pr=$realpr proof_pr=$proofpr forced_dry=$forced"

########################################################################
echo "=== outer-loop regressions (round 1) ==="

begin "ol1-log-fp-scoped-by-package-and-version" "a log FP for libfoo@1 closes ONLY @1 (all arches); libfoo@2 is NOT closed by the name match and is routed on its own"
o="$WORK/ol1"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-verscope.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
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
printf '#!/usr/bin/env python3\nimport json,sys\njson.dump({"refused":True},sys.stdout)\n' > "$fa"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$fa" --today 2026-09-24 --out "$o" >/dev/null 2>&1
sec4esc="$("$PY" -c 'import json,sys
r=[x for x in json.load(open(sys.argv[1]))["findings"] if x["section"]==4]
print("escalated" if r and all("escalat" in (x.get("action") or "") for x in r) else "no")' "$o/classification.json" 2>/dev/null)"
issued="$(grep -c 'issue create .*unassessed-after-fallback' "$shim" 2>/dev/null)"; issued="${issued:-0}"
{ eq "$sec4esc" "escalated" && [ "$issued" -ge 1 ] 2>/dev/null; } \
  && ok || no "§4 refusal escalates to an owner-decision issue" "sec4=$sec4esc issue=$issued"

begin "ol5-owner-issue-failure-is-incomplete" "a failed owner-decision issue create makes the run AUDIT INCOMPLETE (no false 'opened')"
o="$WORK/ol5"; shim="$WORK/ol5.shim"; rm -rf "$o"; rm -f "$shim"
env AUDITOR_GIT_SHIM_LOG="$shim" AUDITOR_SHIM_ISSUE_FAIL=1 "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1; rc5=$?
inc="$(grep -qi 'AUDIT INCOMPLETE' "$o/report.md" && grep -qi 'issue(s) failed to open' "$o/report.md" && echo yes || echo no)"
{ eq "$inc" "yes" && [ "$rc5" -ne 0 ] 2>/dev/null; } && ok || no "issue failure -> INCOMPLETE + nonzero exit" "incomplete=$inc exit=$rc5"

begin "ol6-consolidated-snyk-carries-expiry" "the consolidated .snyk for a carried (affected) CVE includes an expires field (time box survives consolidation)"
o="$WORK/ol6"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" && {
  exp="$(grep -c 'expires:' "$o/suppressions/.snyk" 2>/dev/null)"; exp="${exp:-0}"
  { [ "$exp" -ge 1 ] 2>/dev/null; } && ok || no ".snyk carries expires for the carried CVE" "expires_lines=$exp"; }

begin "ol7-delivery-carries-accepted-items" "the suppression delivery commits .auditor/accepted-items.json (the release gate's inventory)"
o="$WORK/ol7"; shim="$WORK/ol7.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
ai="$(grep -c 'git add .*\.auditor/accepted-items.json' "$shim" 2>/dev/null)"; ai="${ai:-0}"
{ [ "$ai" -ge 1 ] 2>/dev/null; } && ok || no "delivery git-adds .auditor/accepted-items.json" "add_lines=$ai"

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
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$na" --out "$o" >/dev/null 2>&1
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
fa=tempfile.mktemp(suffix=".py"); open(fa,"w").write("import json,sys\njson.dump({\"refused\":True,\"token_usage\":100001},sys.stdout)\n")
st={"tokens":0,"iters":0}
R.adjudicate(fa,{"finding_id":"CVE-X"},st)
print(st["tokens"])' 2>/dev/null)"
{ [ "$charged" -ge 100001 ] 2>/dev/null; } && ok || no "refusal usage charged to the budget" "tokens=$charged"

begin "ol2-3-high-outlier-excluded-quorum-holds" "one over-counting scanner is excluded as an outlier; the three agreeing scanners still form the quorum -> AUDIT COMPLETE, osv named excluded not did-not-run"
o="$WORK/ol23"; rm -rf "$o"; : > "$LEDGER"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-outlier.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" && {
  complete="$(grep -qi 'AUDIT COMPLETE' "$o/report.md" && echo yes || echo no)"
  { eq "$complete" "yes"; } && ok || no "three agreeing scanners hold the quorum despite the outlier" "complete=$complete"; }

########################################################################
echo "=== outer-loop regressions (round 3) ==="

begin "ol3-1-kev-unavailable-fails-closed" "a Medium no-fix finding with an UNAVAILABLE KEV catalog is escalated to at_or_above (fail-closed), not silently below-threshold"
o="$WORK/ol31"; shim="$WORK/ol31.shim"; rm -rf "$o"; rm -f "$shim"; : > "$LEDGER"
env AUDITOR_GIT_SHIM_LOG="$shim" "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-mediumnofix.json" --kev "$WORK/no-such-kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1
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
exit 0
EOF
chmod +x "$fb/gh" "$fb/git"
env PATH="$fb:$PATH" AUDITOR_ALLOW_REAL_GH=1 GH_TOKEN=APP AUDITOR_ISSUES_TOKEN=JOB \
  "$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-ownerissue.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --today 2026-09-24 --out "$o" >/dev/null 2>&1; rc=$?
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
_m,groups=C.manifest_findings(".github/agent/fixtures/run/manifest-aliases.json")
print(len(groups))' 2>/dev/null)"
{ eq "$ng" "1"; } && ok || no "aliased matches form one group" "groups=$ng"

begin "olr4-2-vex-merge-preserves-existing" "delivering this run's suppressions MERGES into an existing reviewed .vex (keeps prior statements, bumps version), never overwrites"
mo="$WORK/olr4-merge"; rm -rf "$mo"; mkdir -p "$mo/ws/.vex" "$mo/supp"
"$PY" - "$mo" <<'PP'
import json,os,sys
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp")
old={"@context":"c","@id":"i","author":"FosterStack LLC","role":"vendor","version":6,"timestamp":"t",
 "statements":[{"@id":"s#a","vulnerability":{"name":"CVE-2024-1"},"status":"not_affected","products":[{"@id":"p"}]},
               {"@id":"s#b","vulnerability":{"name":"CVE-2024-2"},"status":"not_affected","products":[{"@id":"p"}]}]}
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
open(os.path.join(ws,".snyk"),"w").write("version: v1.5.0\nignore:\n  CVE-2024-1:\n    - '*':\n        reason: reviewed\n")
open(os.path.join(ws,"osv-scanner.toml"),"w").write('[[IgnoredVulns]]\nid = "CVE-2024-1"\nreason = "reviewed"\n')
new={"@context":"c","@id":"i","author":"FosterStack LLC","role":"vendor","version":1,"timestamp":"t2",
 "statements":[{"@id":"s#c","vulnerability":{"name":"CVE-2099-9"},"status":"affected","products":[{"@id":"p"}]}]}
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore:\n  CVE-2099-9:\n    - '*':\n        reason: 'affected'\n")
open(os.path.join(supp,"osv-scanner.toml"),"w").write('[[IgnoredVulns]]\nid = "CVE-2099-9"\nreason = "affected"\n')
PP
mres="$("$PY" -c '
import sys,json,os,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py")
R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
m=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))
names=sorted(s["vulnerability"]["name"] for s in m["statements"])
snyk=open(os.path.join(ws,".snyk")).read()
ok = names==["CVE-2024-1","CVE-2024-2","CVE-2099-9"] and m["version"]==7 and "CVE-2024-1" in snyk and "CVE-2099-9" in snyk
print("OK" if ok else "BAD:%s v%s"%(names,m["version"]))' "$mo" 2>/dev/null)"
{ eq "$mres" "OK"; } && ok || no "merge preserves prior statements + bumps version" "$mres"

echo "=== outer-loop round 5 (Codex second-vendor) regressions ==="

begin "olr5-1-advisory-bundle-does-not-merge-distinct-cves" "an OSV distro advisory (DSA) that co-reports THREE distinct CVEs yields three separate groups (the bundle is lineage, never identity), so one CVE's decision cannot dispose of another"
ng="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("c",".github/agent/bin/auditor-classify.py")
C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
_m,groups=C.manifest_findings(".github/agent/fixtures/run/manifest-advisory-bundle.json")
ok = len(groups)==3 and set(groups)=={"CVE-2099-7001","CVE-2099-7002","CVE-2099-7003"} and all(any(f["finding_id"]=="DSA-9999-1" for f in g["findings"]) for g in groups.values())
print("OK" if ok else "BAD:%s"%sorted(groups))' 2>/dev/null)"
{ eq "$ng" "OK"; } && ok || no "advisory bundle splits into distinct CVE groups" "$ng"

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

begin "olr6-2-osv-aliases-are-identity-not-a-bundle" "an OSV record whose own aliases list two CVE ids (explicit equivalence, no upstream/groups) stays ONE identity — never split into a bundle — so its reachability id is retained"
ares="$("$PY" -c '
import sys;sys.path.insert(0,".github/agent/bin")
from auditorlib import parsers as P
f=P.parse_osv(".github/agent/fixtures/scanners/osv-true-aliases.json")[0]
al=sorted(f["aliases"]); b=f.get("extra",{}).get("bundle_cves")
print("OK" if al==["CVE-2099-9603","CVE-2099-9604","GO-2099-9603"] and b is None else "BAD:%s/%s"%(al,b))' 2>/dev/null)"
{ eq "$ares" "OK"; } && ok || no "record aliases treated as identity, not bundle" "$ares"

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

begin "olr7-2-mixed-alias-upstream-keeps-identity" "a record with explicit aliases AND a multi-CVE upstream keeps its own identity (its reachability id stays in its CVE group) while only the EXTRA upstream CVE becomes a separate distributed group"
m7res="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("c",".github/agent/bin/auditor-classify.py")
C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
_m,groups=C.manifest_findings(".github/agent/fixtures/run/manifest-mixed-alias-upstream.json")
g=groups.get("CVE-2099-9703",{}); has_go="GO-2099-9703" in (g.get("aliases") or set())
ok = set(groups)=={"CVE-2099-9703","CVE-2099-9704"} and has_go
print("OK" if ok else "BAD:%s go=%s"%(sorted(groups),has_go))' 2>/dev/null)"
{ eq "$m7res" "OK"; } && ok || no "mixed record keeps identity + splits only extra CVE" "$m7res"

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

begin "olr8-1-bundle-lineage-not-fp-evidence" "a bundle finding distributed to another CVE's group is marked lineage-only, so an advisory's own defect-log FP cannot close a DIFFERENT bundled CVE"
b8="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("c",".github/agent/bin/auditor-classify.py")
C=importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
_m,groups=C.manifest_findings(".github/agent/fixtures/run/manifest-mixed-alias-upstream.json")
own=groups.get("CVE-2099-9703",{}).get("findings",[]); ext=groups.get("CVE-2099-9704",{}).get("findings",[])
own_ok = own and not any(f.get("_lineage_only") for f in own)
ext_ok = ext and all(f.get("_lineage_only") for f in ext)
print("OK" if own_ok and ext_ok else "BAD own=%s ext=%s"%([f.get("_lineage_only") for f in own],[f.get("_lineage_only") for f in ext]))' 2>/dev/null)"
{ eq "$b8" "OK"; } && ok || no "distributed bundle finding is lineage-only" "$b8"

begin "olr8-2-go-unreachable-closure-is-scoped" "a Go imported-not-called closure writes not_affected SCOPED to the Go package's subcomponents, never product-wide (so it cannot suppress a sibling OS scope)"
g8="$WORK/olr8-go"; rm -rf "$g8"
gv="$g8/gvc.json"; mkdir -p "$g8"
printf '%s\n%s\n%s\n' '{"config":{"scan_level":"symbol"}}' '{"SBOM":{"roots":["example.org/lib"],"modules":[{"path":"example.org/lib","version":"v1.0.0"}]}}' '{"finding":{"osv":"GO-2099-8802","trace":[{"module":"example.org/lib","package":"example.org/lib/unused"}]}}' > "$gv"
sc8="$("$PY" -c '
import json,sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=sys.argv[2]
env={"gvc":sys.argv[1],"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},
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

begin "olr8-6-foreign-id-preserved-and-citation-resolves" "the merge does NOT strip a foreign statement id's legitimate '~' suffix, and the regenerated .snyk cites a real merged statement id"
c8="$WORK/olr8-cite"; rm -rf "$c8"; mkdir -p "$c8/ws/.vex" "$c8/supp"
"$PY" - "$c8" <<'PP'
import json,os,sys
sys.path.insert(0,".github/agent/bin")
from auditorlib import vex, policy
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws"); supp=os.path.join(tmp,"supp")
old=vex.doc("CVE-2099-9805","not_affected","2026-09-23T00:00:00Z",justification="vulnerable_code_not_present")
old["statements"][0]["@id"]="https://example.org/vex#review~deadbeef"; old["version"]=6
json.dump(old,open(os.path.join(ws,".vex","fosterstack-cache.openvex.json"),"w"))
open(os.path.join(ws,".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(ws,"osv-scanner.toml"),"w").write("")
new=vex.doc("CVE-2099-9806","not_affected","2026-09-24T00:00:00Z",justification="vulnerable_code_not_present")
json.dump(new,open(os.path.join(supp,"fosterstack-cache.openvex.json"),"w"))
open(os.path.join(supp,".snyk"),"w").write("version: v1.5.0\nignore: {}\n"); open(os.path.join(supp,"osv-scanner.toml"),"w").write("")
PP
ci8="$("$PY" -c '
import json,os,sys,re,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
tmp=sys.argv[1]; ws=os.path.join(tmp,"ws")
R._merge_suppressions(ws, os.path.join(tmp,"supp"))
doc=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))
ids={s["@id"] for s in doc["statements"]}
foreign_kept="https://example.org/vex#review~deadbeef" in ids
snyk=open(os.path.join(ws,".snyk")).read()
cited=set(re.findall(r"vex: \x27([^\x27]+)\x27",snyk))
resolve=cited and cited <= ids
print("OK" if foreign_kept and resolve else "BAD kept=%s cited=%s"%(foreign_kept,cited))' "$c8" 2>/dev/null)"
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
    if cmd[0]=="git": return subprocess.CompletedProcess(cmd,0,"","")
    if cmd[:3]==["gh","pr","list"]: return subprocess.CompletedProcess(cmd,0,"https://x.invalid/pull/1","")
    if cmd[0]=="gh": raise AssertionError(cmd)
    return R.subprocess.run.__wrapped__(cmd,*a,**kw) if hasattr(R.subprocess.run,"__wrapped__") else __import__("subprocess").run(cmd,*a,**kw)
import subprocess as _sp
def fake2(cmd,*a,**kw):
    if cmd and cmd[0]=="git": return _sp.CompletedProcess(cmd,0,"","")
    if cmd[:3]==["gh","pr","list"]: return _sp.CompletedProcess(cmd,0,"https://x.invalid/pull/1","")
    if cmd and cmd[0]=="gh": raise AssertionError(cmd)
    return _sp.run(cmd,*a,**kw)
with patch.dict(os.environ,{"AUDITOR_ALLOW_REAL_GH":"1","GITHUB_WORKSPACE":ws}),patch.object(R.subprocess,"run",fake2),patch.object(R.cli,"ask_model",return_value={"category":"risk_acceptance","token_usage":0}),contextlib.redirect_stdout(io.StringIO()):
    R.run(mp,False,os.path.join(tmp,"out"),"2026-09-24",adjudicator="offline-probe")
cls=json.load(open(os.path.join(tmp,"out","classification.json")))["findings"]
sec=cls[0]["section"] if cls else None
inv=json.load(open(os.path.join(ws,".auditor","accepted-items.json")))["accepted_items"]
stmts=json.load(open(os.path.join(ws,".vex","fosterstack-cache.openvex.json")))["statements"]
print("OK" if sec==3 and inv==[] and stmts==[] else "BAD sec=%s inv=%s stmts=%d"%(sec,len(inv),len(stmts)))' "$ex8" "$F/run/manifest-mediumnofix.json" 2>/dev/null)"
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
env={"gvc":gv,"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},
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
mp=".github/agent/fixtures/run/manifest-mediumnofix.json"
def fake(cmd,*a,**kw):
    if cmd and cmd[0]=="git": return subprocess.CompletedProcess(cmd,0,"","")
    if cmd[:3]==["gh","pr","list"]: return subprocess.CompletedProcess(cmd,0,"https://x.invalid/pull/1","")
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
env={"gvc":gv,"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},
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
purl="pkg:deb/debian/lib@1"; sc=((policy.VEX_PRODUCT,),(purl,))
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":"/tmp/refr1-7out","ts":"2026-09-23T00:00:00Z","dry":True,"digest":"sha256:x",
     "carried_expiry":{("CVE-2099-1303",sc):"2026-09-23"},"today":"2026-09-23"}
import os,shutil; shutil.rmtree("/tmp/refr1-7out",ignore_errors=True)
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
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},
     "kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"2026-09-24T00:00:00Z","dry":True,"digest":"sha256:x","carried_expiry":{},"today":"2026-09-24"}
def gm(pkg,purl,fixed,sc):
    return {"scanner":sc,"finding_id":"CVE-2099-2003","purl":purl,"aliases":["CVE-2099-2003"],"package":pkg,"fixed_version":fixed,"severity":("Critical" if fixed is None else "Medium"),"extra":{}}
aaa=[gm("aaa","pkg:deb/debian/aaa@8",None,"grype"),gm("aaa","pkg:deb/debian/aaa@8",None,"osv-scanner")]
bbb=[gm("bbb","pkg:deb/debian/bbb@1","1.0.1","grype"),gm("bbb","pkg:deb/debian/bbb@1","1.0.1","osv-scanner")]
rows,_=R._dispose_split("CVE-2099-2003",aaa+bbb,["CVE-2099-2003"],env,[])
byp={r["package"]:r["section"] for r in rows}
print("OK" if byp.get("aaa")==2 and byp.get("bbb")==3 else "BAD:%s"%byp)' "$t23/out" 2>/dev/null | tail -1)"
{ eq "$r23" "OK"; } && ok || no "sibling package fix does not transfer (aaa=2, bbb=3)" "$r23"

begin "refr2-4-per-scope-deadlines-in-ignores" "two live scopes of one CVE with different deadlines each keep their OWN expiry in the Snyk selector, never a sibling's"
t24="$WORK/refr2-4"; rm -rf "$t24"; mkdir -p "$t24"
r24="$("$PY" -c '
import sys,importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
sys.path.insert(0,".github/agent/bin"); from auditorlib import vex
c="CVE-2099-2004"; p1="pkg:deb/debian/lib@1"; p2="pkg:golang/example.org/lib@v1.0.0"
s1=vex.doc(c,"affected","t",action="x",subcomponents=[p1])["statements"][0]
s2=vex.doc(c,"affected","t",action="x",subcomponents=[p2])["statements"][0]
exp={(c,p1):"2026-09-30",(c,p2):"2026-10-20"}
snyk,toml=R._ignores_from_statements([s1,s2],exp)
import re
# each selector keeps its own expiry
ok = "- \x27"+p1+"\x27" in snyk and "- \x27"+p2+"\x27" in snyk and "2026-09-30" in snyk and "2026-10-20" in snyk
# the p1 block must carry 09-30 (not 10-20): check the p1 selector is followed by 09-30 before p2
i1=snyk.find(p1); i2=snyk.find(p2); seg=snyk[min(i1,i2):]
print("OK" if ok else "BAD")' 2>/dev/null)"
{ eq "$r24" "OK"; } && ok || no "per-scope deadlines in Snyk selectors" "$r24"

echo "=== report items (scanner tables, db dates, quorum honesty) ==="

begin "rpt1-scanner-tables-groups-and-artifact" "after routing, each scanner gets a collapsible job-log group '<scanner> — <n> packages, <n> findings' with a fixed-width table incl a disposition (§n) column; the same text is in reports/scanner-tables.txt; a clean scanner is a one-line group"
o="$WORK/rpt1"; rm -rf "$o"
log="$(run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" 2>/dev/null; cat "$o/reports/scanner-tables.txt" 2>/dev/null)"
tf="$o/reports/scanner-tables.txt"
gr="$(grep -c '::group:: *grype — [0-9]* packages, [0-9]* findings' "$tf" 2>/dev/null || echo 0)"
hascol="$(grep -c 'vulnerability id' "$tf" 2>/dev/null || echo 0)"
hasdisp="$(grep -Ec '§[0-9]' "$tf" 2>/dev/null || echo 0)"
ends="$(grep -c '::endgroup::' "$tf" 2>/dev/null || echo 0)"
{ [ "$gr" -ge 1 ] 2>/dev/null && [ "$hascol" -ge 1 ] 2>/dev/null && [ "$hasdisp" -ge 1 ] 2>/dev/null && [ "$ends" -ge 4 ] 2>/dev/null; } \
  && ok || no "scanner-tables.txt has per-scanner groups + table + disposition column" "groups=$gr col=$hascol disp=$hasdisp ends=$ends"

begin "rpt2-no-db-date-published-never-dash" "a scanner that publishes no database date shows 'no db date published' in the header, never a bare 'db=-'"
o="$WORK/rpt2"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
  nodash="$(grep -c 'db=-' "$o/report.md" 2>/dev/null)"; nodash="${nodash:-0}"
  nopub="$(grep -c 'no db date published' "$o/report.md" 2>/dev/null)"; nopub="${nopub:-0}"
  { [ "$nodash" -eq 0 ] 2>/dev/null && [ "$nopub" -ge 1 ] 2>/dev/null; } \
    && ok || no "header says 'no db date published', never 'db=-'" "db_dash=$nodash no_db_published=$nopub"; }

begin "rpt3-inventory-quorum-names-agreed-and-not" "the header names which scanners' OS inventories agreed (with counts) and which did not inventory"
o="$WORK/rpt3b"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
  line="$(grep 'Inventory quorum:' "$o/report.md")"
  { printf '%s' "$line" | grep -q 'agreed on OS packages:' && printf '%s' "$line" | grep -Eq 'grype\([0-9]+\)'; } \
    && ok || no "quorum line names agreed scanners with OS counts" "line=[$line]"; }

begin "rpt4-scanner-table-maps-advisory-via-router-identity" "an advisory/alias scanner record (a DSA co-reporting CVEs) that the router placed in a section shows that §n in the scanner table, mapped through the ROUTER's completed identity (every alias, not an independent re-canonicalization) — never a bare '-' (R1 refactor round-5 #4)"
o="$WORK/rpt4"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-advisory-bundle.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
  dsarow="$(grep 'DSA-9999-1' "$o/reports/scanner-tables.txt" 2>/dev/null | head -1)"
  mapped="$(printf '%s' "$dsarow" | grep -Eq '§[0-9]' && echo yes || echo no)"
  { eq "$mapped" "yes"; } \
    && ok || no "advisory row DSA-9999-1 shows a routed §n, not '-'" "row=[$dsarow]"; }

begin "rpt5-run-report-header-token-cost-and-role" "auditor-run.py's rendered report header carries the model ROLE and a TOKEN COST field (REQ-AUD-7 AC1), never omitted and never a model id (R1 refactor round-5 #5)"
o="$WORK/rpt5"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
  hdr="$(sed -n '/## Run header/,/^## /p' "$o/report.md")"
  hastok="$(printf '%s' "$hdr" | grep -qi 'token cost' && echo yes || echo no)"
  hasrole="$(printf '%s' "$hdr" | grep -qi '\*\*model:\*\*' && echo yes || echo no)"
  noid="$(grep -qE 'claude-[a-z0-9.-]+' "$o/report.md" && echo no || echo yes)"
  { eq "$hastok" "yes" && eq "$hasrole" "yes" && eq "$noid" "yes"; } \
    && ok || no "run header has token cost + model role, no model id" "tok=$hastok role=$hasrole no_id=$noid"; }

begin "rpt6-run-report-scanner-down-is-first-line" "when a scanner did not run, auditor-run.py's report FIRST line names it and marks the assessment NOT clean (REQ-AUD-7 AC2, R1 refactor round-5 #6)"
o="$WORK/rpt6"; rm -rf "$o"
# grype/snyk are down here -> quorum fails -> auditor-run EXITS NON-ZERO by design; do not use run()
"$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-down.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 || true
first="$(sed -n '1p' "$o/report.md" 2>/dev/null)"
firstok="$(printf '%s' "$first" | grep -qi 'SCANNER DID NOT RUN' && echo yes || echo no)"
notclean="$(printf '%s' "$first" | grep -qi 'not clean' && echo yes || echo no)"
{ eq "$firstok" "yes" && eq "$notclean" "yes"; } \
  && ok || no "first line names a down scanner and says not clean" "first=[$first]"

echo "=== REQ-AUD-13 refactor boundary regressions (round 3) ==="
# shared env builder for direct _dispose/_dispose_split cases
r3env() { cat <<PYENV
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":"$1","ts":"2026-09-24T00:00:00Z","dry":True,"digest":"x","carried_expiry":$2,"today":"2026-09-24"}
PYENV
}

begin "refr3-2-fix-does-not-transfer-across-versions" "an unfixed version and a fixed version of the SAME package route independently (fixed -> §3 bump; unfixed -> not a §3 bump on the wrong version)"
o="$WORK/refr3-2"; rm -rf "$o"
res="$("$PY" -c '
import importlib.util,shutil
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=__import__("sys").argv[1]; shutil.rmtree(out,ignore_errors=True)
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"today":"2026-09-24"}
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
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"today":"2026-09-24"}
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
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"today":"2026-09-24"}
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
shutil.rmtree("/tmp/refr3-6",ignore_errors=True)
purl="pkg:golang/example.org/lib@v1.0.0"; sc=((R.policy.VEX_PRODUCT,),(purl,))
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":"/tmp/refr3-6","ts":"t","dry":True,"digest":"x","carried_expiry":{("CVE-2099-1801",sc):"2026-10-30"},"today":"2026-09-24"}
f={"scanner":"grype","finding_id":"CVE-2099-1801","purl":purl,"aliases":["CVE-2099-1801"],"package":"example.org/lib","fixed_version":"v1.0.1","severity":"High","extra":{}}
row,_=R._dispose("CVE-2099-1801",[f],["CVE-2099-1801"],env,[])
print("OK" if row["section"]==1 and row.get("reopened_scope") else "BAD:%s"%row["section"])' 2>/dev/null | tail -1)"
{ eq "$res" "OK"; } && ok || no "pullable fix lifts the carried suppression (§1 + removal)" "$res"

begin "refr3-4-permanent-scope-keeps-no-deadline" "a permanent not_affected scope does not acquire a temporary sibling's expiry via a CVE-wide fallback"
res="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
import sys; sys.path.insert(0,".github/agent/bin"); from auditorlib import vex
c="CVE-2099-1807"
perm=vex.doc(c,"not_affected","t",justification="vulnerable_code_not_present",subcomponents=["pkg:deb/debian/perm@1"])["statements"][0]
tmp=vex.doc(c,"affected","t",action="x",subcomponents=["pkg:deb/debian/temp@1"])["statements"][0]
snyk,_t=R._ignores_from_statements([perm,tmp],{(c,"pkg:deb/debian/temp@1"):"2026-09-30"})
seg=snyk.split("perm@1")[1].split("temp@1")[0]
print("OK" if "expires" not in seg and "2026-09-30" in snyk else "BAD")' 2>/dev/null | tail -1)"
{ eq "$res" "OK"; } && ok || no "permanent scope keeps no deadline" "$res"

echo "=== REQ-AUD-13 refactor boundary regressions (round 4) ==="

begin "refr4-2-fp-log-does-not-cross-ecosystem" "a trusted defect-log FP for a Debian package closes ONLY the Debian ecosystem at that name/version, never an independently installed PyPI dist of the same name/version"
o="$WORK/refr4-2"; rm -rf "$o"; mkdir -p "$o"
cat > "$o/grype.json" <<'EOF'
{"matches":[
 {"vulnerability":{"id":"CVE-2099-1951","severity":"Critical"},"artifact":{"name":"requests","version":"2.28.1","type":"deb","purl":"pkg:deb/debian/requests@2.28.1"}},
 {"vulnerability":{"id":"CVE-2099-1951","severity":"Critical"},"artifact":{"name":"requests","version":"2.28.1","type":"python","purl":"pkg:pypi/requests@2.28.1"}}
],"source":{"type":"image"},"distro":{"name":"debian","version":"12.0"},"descriptor":{"name":"grype","version":"0.118.0","db":{"status":{"from":"x_2026-09-22T00:00:00Z_x"}}}}
EOF
cat > "$o/log.json" <<'EOF'
{"defects":[{"package":"requests","disposition":"false_positive","keys":[{"scanner":"grype","finding_id":"CVE-2099-1951","purl":"pkg:deb/debian/requests@2.28.1"}],"evidence":{"detail":"debian backport"}}]}
EOF
"$PY" - "$o" <<'PP'
import json,os,sys
m={"commit":"ab","module":"x","base_os":"debian","candidate_variant":"production","candidate_digests":{"production":"sha256:ab"},
   "scanner_reports":{"grype":os.path.join(sys.argv[1],"grype.json"),"trivy":None,"osv-scanner":None,"osv-scanner-gomod":None,"snyk":None},
   "scanner_status":{s:{"ran":True,"scan_ok":True,"quorum_ok":True,"version":"x","reason":"ok","package_count":2,"os_package_count":1,"db_date":"2026-09-22","findings":2} for s in ("grype","trivy","osv-scanner","snyk")},
   "govulncheck":None,"known_defect_log":os.path.join(sys.argv[1],"log.json"),"kev_catalog":None}
m["scanner_status"]["osv-scanner-gomod"]={"ran":True,"version":"x","reason":"ok","package_count":None}
json.dump(m,open(os.path.join(sys.argv[1],"manifest.json"),"w"))
PP
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
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"carried_scopes":set(),"today":"2026-09-24"}
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
env={"gvc":None,"module":None,"gvc_usable":False,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":out,"ts":"t","dry":True,"digest":"x","carried_expiry":{},"carried_scopes":set(),"today":"2026-09-24"}
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
gv="/tmp/refr4-4-gvc.json"
open(gv,"w").write("\n".join([
  "{\"config\":{\"scan_level\":\"symbol\"}}",
  "{\"SBOM\":{\"roots\":[\"example.org/lib\"],\"modules\":[{\"path\":\"example.org/lib\",\"version\":\"v1.0.0\"}]}}",
  "{\"finding\":{\"osv\":\"GO-2099-3004\",\"trace\":[{\"module\":\"example.org/lib\",\"version\":\"v1.0.0\",\"package\":\"example.org/lib/x\"}]}}"]))
def env(cs):
    shutil.rmtree("/tmp/refr4-4out",ignore_errors=True)
    return {"gvc":gv,"module":"example.org/lib","gvc_usable":True,"idx":{},"logpath":None,"adjudicator":"stub","state":{"tokens":0,"iters":0},"kev_ids":set(),"kev_ok":True,"exp":"2026-10-24","out":"/tmp/refr4-4out","ts":"t","dry":True,"digest":"x","carried_expiry":{},"carried_scopes":cs,"today":"2026-09-24"}
f={"scanner":"osv-scanner-gomod","finding_id":"GO-2099-3004","purl":purl,"aliases":["GO-2099-3004","CVE-2099-3004"],"package":"example.org/lib","fixed_version":"v1.0.1","severity":"High","extra":{}}
carried,_=R._dispose("CVE-2099-3004",[f],["CVE-2099-3004","GO-2099-3004"],env({("CVE-2099-3004",sc)}),[])
fresh,_=R._dispose("CVE-2099-3004",[f],["CVE-2099-3004","GO-2099-3004"],env(set()),[])
print("OK" if carried["section"]==1 and fresh["section"]==5 else "BAD carried=%s fresh=%s"%(carried["section"],fresh["section"]))' 2>/dev/null | tail -1)"
{ eq "$r4" "OK"; } && ok || no "pullable fix lifts carried reachability; fresh unreachable stays §5" "$r4"

begin "refr4-6-scanner-table-disposition-by-scope" "the scanner table maps each version row to its OWN routed section, not every section the CVE touched"
o="$WORK/refr4-6"; rm -rf "$o"; mkdir -p "$o/reports"
r6="$("$PY" -c '
import importlib.util,json,os
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out=__import__("sys").argv[1]
rows=[{"id":"CVE-9","section":3,"scope_purls":["pkg:golang/lib@v1.0.0"]},{"id":"CVE-9","section":2,"scope_purls":["pkg:golang/lib@v8.0.0"]}]
grype={"matches":[{"vulnerability":{"id":"CVE-9","severity":"Medium","fix":{"state":"fixed","versions":["1.0.1"]}},"artifact":{"name":"lib","version":"v1.0.0","type":"golang","purl":"pkg:golang/lib@v1.0.0"}},{"vulnerability":{"id":"CVE-9","severity":"Critical"},"artifact":{"name":"lib","version":"v8.0.0","type":"golang","purl":"pkg:golang/lib@v8.0.0"}}]}
json.dump(grype,open(out+"/grype.json","w"))
m={"scanner_reports":{"grype":out+"/grype.json"},"scanner_status":{"grype":{"ran":True,"package_count":2,"findings":2}}}
R._scanner_tables(m,rows,out)
t=open(out+"/reports/scanner-tables.txt").read().splitlines()
v1=[l for l in t if "v1.0.0" in l][0]; v8=[l for l in t if "v8.0.0" in l][0]
ok=("§3" in v1 and "§2" not in v1) and ("§2" in v8 and "§3" not in v8)
print("OK" if ok else "BAD v1=%r v8=%r"%(v1,v8))' "$o" 2>/dev/null | tail -1)"
{ eq "$r6" "OK"; } && ok || no "scanner table disposition is per-scope" "$r6"

begin "refr4-8-quorum-header-matches-agreement-decision" "the Inventory-quorum header uses the run's numerical agreement: when the ran scanners' OS counts do NOT agree, none is labelled agreed"
r8="$("$PY" -c '
import importlib.util
spec=importlib.util.spec_from_file_location("r",".github/agent/bin/auditor-run.py"); R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
qi={"agreed":[],"disagreed":["grype","trivy","osv-scanner","snyk"],"not_ran":[],"excluded":[]}
st={s:{"ran":True,"os_package_count":(100 if s=="snyk" else 10),"package_count":10,"findings":0,"version":"x","db_date":None} for s in ("grype","trivy","osv-scanner","snyk")}
m={"scanner_status":st,"scanner_reports":{s:"x" for s in st},"candidate_digests":{},"govulncheck":None}
rep=R._render(m,[],{n:[] for n in range(1,8)},[],"AUDIT INCOMPLETE",True,"stub",{},"h","c",None,None,qi)
ql=[l for l in rep.splitlines() if "Inventory quorum:" in l][0]
print("OK" if "agreed on OS packages: none" in ql else "BAD:%s"%ql)' 2>/dev/null | tail -1)"
{ eq "$r8" "OK"; } && ok || no "quorum header reflects the numerical agreement decision" "$r8"

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
echo "=== REQ-AUD-15 — report structure v2 ==="

begin "req15-ac1-pr-list-at-top" "after the header and before the sections, a 'PRs and issues this run' block lists what was/would be opened"
o="$WORK/r15a"; rm -rf "$o"
run "$PY" "$BIN/auditor-run.py" --dry-run true --manifest "$F/run/manifest-01.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o" >/dev/null 2>&1 && {
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

begin "req15-ac9-test-image-tag-and-forces-dry" "a test-image run tags every VEX row 'proposed, not delivered (test image)' regardless of main, and forces dry_run even when --dry-run false"
o2="$WORK/r15ti"; rm -rf "$o2"
"$PY" "$BIN/auditor-run.py" --dry-run false --manifest "$F/run/manifest-testimage.json" --kev "$F/kev/kev.json" --adjudicator "$STUB" --out "$o2" >/dev/null 2>&1 || true
ti="$(grep -c 'proposed, not delivered (test image)' "$o2/report.md" 2>/dev/null)"; ti="${ti:-0}"
forced="$(grep -c '\*\*dry_run:\*\* yes' "$o2/report.md" 2>/dev/null)"; forced="${forced:-0}"
{ [ "$ti" -ge 1 ] 2>/dev/null && [ "$forced" -ge 1 ] 2>/dev/null; } \
  && ok || no "test-image tag + forced dry" "test_image_tags=$ti forced_dry=$forced"

echo "----"
echo "auditor-matrix: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
