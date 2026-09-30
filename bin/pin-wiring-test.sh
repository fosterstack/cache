#!/usr/bin/env bash
# proves: REQ-REL-005-AC1 — the hygiene check runs the pin checker on every pull request and every push
# to main, and nothing can skip it or swallow its failure (register row 78).
# The real hygiene.yml must pass; each mutated copy must be caught.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0

judge() { python3 - "$1" <<'PY'
import sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)   # every scalar a string, as GitHub reads it
bad = []
on = d.get("on", {})
if "pull_request" not in on:
    bad.append("not triggered on pull_request")
push = on.get("push") if isinstance(on, dict) else None
if not isinstance(push, dict) or push.get("branches") != ["main"]:
    bad.append("not triggered on push to main")
job = d.get("jobs", {}).get("allowlist", {})
for k in ("if", "continue-on-error"):
    if k in job:
        bad.append(f"the allowlist job has `{k}`")
want = {"bash .github/agent/tests/check-action-pins-test.sh", "python3 .github/agent/bin/check-action-pins.py --verify-tags ."}
seen = set()
for st in job.get("steps", []):
    run = (st.get("run") or "").strip()
    if run in want:
        seen.add(run)
        for k in ("if", "continue-on-error"):
            if k in st:
                bad.append(f"the step `{run}` has `{k}`")
for w in sorted(want - seen):
    bad.append(f"no step runs `{w}`")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}

case_() {  # case_ <name> <expect ok|bad> <python edit of the parsed copy, or empty>
  local f="$work/$1.yml"
  cp "$here/.github/workflows/hygiene.yml" "$f"
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

steps='d["jobs"]["allowlist"]["steps"]'
pick='[s for s in '"$steps"' if (s.get("run") or "").startswith("python3 .github/agent/bin/check-action-pins.py")][0]'
case_ the-real-hygiene      ok  ""
case_ step-removed          bad "$steps[:] = [s for s in $steps if not (s.get('run') or '').startswith('python3 .github/agent/bin/check-action-pins.py')]"
case_ step-if-false         bad "$pick['if'] = 'false'"
case_ step-continue         bad "$pick['continue-on-error'] = 'true'"
case_ step-weakened         bad "$pick['run'] = 'python3 .github/agent/bin/check-action-pins.py . || true'"
case_ job-if-false          bad "d['jobs']['allowlist']['if'] = 'false'"
case_ no-pull-request       bad "d['on'].pop('pull_request')"
case_ push-not-main         bad "d['on']['push']['branches'] = ['release']"
case_ cases-step-removed    bad "$steps[:] = [s for s in $steps if (s.get('run') or '').strip() != 'bash .github/agent/tests/check-action-pins-test.sh']"

echo "pin-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
