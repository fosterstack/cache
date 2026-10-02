#!/usr/bin/env bash
# proves: REQ-REL-008-AC3
# The ratified workflow consolidation (owner, Oct 2), mutation into go-freshness: the mutation job runs weekly on its
# own schedule and the freshness check daily on its own, each guarded by the schedule that fired, a dispatch runs
# both, mutation.yml is gone, the docs link points to go-freshness.yml. The real workflow must pass; each mutated
# copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" "$root" <<'PY'
import os, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
crons = [c.get("cron") for c in (d.get("on") or {}).get("schedule") or []]
daily, weekly = "23 6 * * *", "43 6 * * 1"
if sorted(crons) != sorted([daily, weekly]):
    bad.append("schedules are not exactly the daily freshness cron and the weekly mutation cron: %s" % crons)
if "workflow_dispatch" not in (d.get("on") or {}):
    bad.append("no workflow_dispatch")
jobs = d.get("jobs") or {}
m, c = jobs.get("mutation"), jobs.get("check")
if not m or m.get("name") != "mutation":
    bad.append("no mutation job named mutation")
if not c:
    bad.append("no freshness check job")
if m and c:
    mi, ci = str(m.get("if", "")).replace(" ", ""), str(c.get("if", "")).replace(" ", "")
    if "github.event.schedule=='%s'" % weekly.replace(" ", "") not in mi or "github.event_name=='workflow_dispatch'" not in mi:
        bad.append("the mutation job is not guarded to the weekly schedule (or dispatch)")
    if "github.event.schedule=='%s'" % daily.replace(" ", "") not in ci or "github.event_name=='workflow_dispatch'" not in ci:
        bad.append("the freshness check is not guarded to the daily schedule (or dispatch)")
    if not any("gremlins" in (s.get("run") or "") for s in m.get("steps") or []):
        bad.append("the mutation job does not run gremlins")
if os.path.exists(os.path.join(root, ".github/workflows/mutation.yml")):
    bad.append("mutation.yml still exists")
doc = open(os.path.join(root, "docs/quality/mutation.md")).read()
if "workflows/go-freshness.yml" not in doc or "workflows/mutation.yml" in doc:
    bad.append("docs/quality/mutation.md does not link to go-freshness.yml")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_() {
  local f="$work/$1.yml"
  cp "$root/.github/workflows/go-freshness.yml" "$f"
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
case_ real                    ok  ""
case_ mutation-daily          bad "d['on']['schedule'] = [{'cron': '23 6 * * *'}]"
case_ mutation-unguarded      bad "$J['mutation'].pop('if')"
case_ check-unguarded         bad "$J['check'].pop('if')"
case_ no-dispatch             bad "d['on'].pop('workflow_dispatch')"
case_ mutation-renamed        bad "$J['mutation']['name'] = 'mutation testing'"
case_ no-gremlins             bad "$J['mutation']['steps'] = [s for s in $J['mutation']['steps'] if 'gremlins' not in (s.get('run') or '')]"
case_ guards-swapped           bad "a, b = $J['mutation']['if'], $J['check']['if']; $J['mutation']['if'], $J['check']['if'] = b, a"
echo "workflow-consolidation: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
