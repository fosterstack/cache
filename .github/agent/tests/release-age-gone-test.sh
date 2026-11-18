#!/usr/bin/env bash
# proves: REQ-SUP-001-AC1, REQ-SUP-001-AC2
# The owner's ruling of Nov 11 2026 removed the release-age hold: a pull request never waits for a version to age, and the pin scan measures no time. Proved on the
# tracked files, with nothing run: (a) pin-age-check.py and (b) pin-audit.py hold none of the words of the removed hold, (c) the tag observer is gone and no tracked
# file refers to it, (d) Dependabot carries no cooldown and one entry per ecosystem and directory, the context and the job pin-age stay, the pin-age job runs no
# re-run, no run listing and no publication-time lookup, and no workflow holds actions: write.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
cd "$root"
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
py() { python3 -I - "$@"; }

# a, b: the two programs hold none of the words of the removed hold (this test names them, so it is not read)
for f in .github/agent/supply-chain/pin-age-check.py .github/agent/supply-chain/pin-audit.py; do
  for w in MIN_DAYS min-days rerun_held observations-out cosign-verify tag_observer; do
    rc=0; grep -qF -- "$w" "$f" || rc=$?
    if [ "$rc" -eq 1 ]; then ok "$f does not contain $w"
    elif [ "$rc" -eq 0 ]; then bad "$f does not contain $w ($(grep -nF -- "$w" "$f" | head -2 | cut -c1-100 | tr '\n' '|'))"
    else bad "$f can be read"; fi
  done
done

# c: the tag observer is gone, and no tracked file refers to it
f=.github/agent/supply-chain/tag_observer.py
if [ ! -e "$f" ] && ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then ok "$f does not exist"; else bad "$f does not exist"; fi
self=.github/agent/tests/release-age-gone-test.sh
git ls-files -z | grep -zvxF -- "$self" >"$work/files" || true
: >"$work/hits"
while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  rc=0; grep -IHnF -- 'tag_observer' "$f" >>"$work/hits" || rc=$?
  [ "$rc" -le 1 ] || { echo "FAIL cannot read $f"; exit 1; }
done <"$work/files"
if [ ! -s "$work/hits" ]; then ok "no tracked file refers to tag_observer"; else bad "no tracked file refers to tag_observer ($(wc -l <"$work/hits") lines, first: $(head -3 "$work/hits" | cut -c1-120 | tr '\n' '|'))"; fi

# d: dependabot.yml has no cooldown key anywhere and one entry per ecosystem and directory
py .github/dependabot.yml >"$work/dep" 2>&1 <<'PY' && ok "dependabot.yml: no cooldown key anywhere, one entry per ecosystem and directory" || { bad "dependabot.yml: no cooldown key anywhere, one entry per ecosystem and directory"; sed 's/^/     /' "$work/dep"; }
import collections, sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
def has(o):
    if isinstance(o, dict): return "cooldown" in o or any(has(v) for v in o.values())
    if isinstance(o, list): return any(has(v) for v in o)
    return False
if has(d): sys.exit("a cooldown key is present")
c = collections.Counter()
for u in d["updates"]:
    dirs = u["directories"] if "directories" in u else [u.get("directory", "/")]
    for x in dirs: c[(u["package-ecosystem"], x)] += 1
dup = sorted(k for k, n in c.items() if n > 1)
if dup: sys.exit("more than one entry for %r" % (dup,))
PY

# d (REQ-SUP-001-AC1): the github-actions, pip and tools/govulncheck gomod entries are there (the last weekly), the root gomod entry keeps its weekly schedule and its one minor-patch group, no docker entry
py .github/dependabot.yml >"$work/ac1" 2>&1 <<'PY' && ok "dependabot.yml: github-actions, pip and govulncheck entries present, root gomod unchanged, no docker entry" || { bad "dependabot.yml: github-actions, pip and govulncheck entries present, root gomod unchanged, no docker entry"; sed 's/^/     /' "$work/ac1"; }
import sys, yaml
u = {(e["package-ecosystem"], e["directory"]): e for e in yaml.safe_load(open(sys.argv[1]))["updates"]}
for k in [("github-actions", "/"), ("pip", "/.github/agent"), ("gomod", "/tools/govulncheck")]:
    if k not in u: sys.exit("no entry for %r" % (k,))
if u[("gomod", "/tools/govulncheck")]["schedule"] != {"interval": "weekly"}: sys.exit("govulncheck entry is not weekly")
r = u.get(("gomod", "/"))
if not r or r["schedule"] != {"interval": "weekly"} or r.get("groups") != {"gomod-minor-patch": {"patterns": ["*"], "update-types": ["minor", "patch"]}}: sys.exit("root gomod entry changed")
if any(k[0] == "docker" for k in u): sys.exit("a docker entry exists")
PY

# d: the context pin-age and the job pin-age stay
py .github/policy/required-checks.json >"$work/rc" 2>&1 <<'PY' && ok "required-checks.json still names the context pin-age" || { bad "required-checks.json still names the context pin-age"; sed 's/^/     /' "$work/rc"; }
import json, sys
def ctx(o):
    if isinstance(o, dict): return ([o["context"]] if isinstance(o.get("context"), str) else []) + [c for v in o.values() for c in ctx(v)]
    if isinstance(o, list): return [c for v in o for c in ctx(v)]
    return []
if "pin-age" not in ctx(json.load(open(sys.argv[1]))): sys.exit("no context pin-age")
PY
py .github/workflows/supply-chain.yml >"$work/sc" 2>&1 <<'PY' && ok "supply-chain.yml still has the job pin-age" || { bad "supply-chain.yml still has the job pin-age"; sed 's/^/     /' "$work/sc"; }
import sys, yaml
j = yaml.safe_load(open(sys.argv[1]))["jobs"]
if "pin-age" not in j and not any(isinstance(v, dict) and v.get("name") == "pin-age" for v in j.values()): sys.exit("no job pin-age")
PY
py .github/workflows/supply-chain.yml >"$work/sc2" 2>&1 <<'PY' && ok "the pin-age job runs no re-run, no run listing and no publication-time lookup" || { bad "the pin-age job runs no re-run, no run listing and no publication-time lookup"; sed 's/^/     /' "$work/sc2"; }
import re, sys, yaml
j = yaml.safe_load(open(sys.argv[1]))["jobs"]
job = j.get("pin-age") or next((v for v in j.values() if isinstance(v, dict) and v.get("name") == "pin-age"), None)
if job is None: sys.exit("no job pin-age")
m = re.search(r"gh run|/rerun|published_at|--now|first.seen|tag_observer", yaml.dump(job))
if m: sys.exit("found: " + m.group(0))
PY

# d: no workflow holds actions: write, at the top or in a job
py >"$work/aw" 2>&1 <<'PY' && ok "no workflow holds actions: write, at the top or in any job" || { bad "no workflow holds actions: write, at the top or in any job"; sed 's/^/     /' "$work/aw"; }
import glob, sys, yaml
found = []
def w(p): return (isinstance(p, dict) and p.get("actions") == "write") or p == "write-all"
for path in sorted(glob.glob(".github/workflows/*.y*ml")):
    d = yaml.safe_load(open(path)) or {}
    if w(d.get("permissions")): found.append(path + " (workflow)")
    for n, job in (d.get("jobs") or {}).items():
        if isinstance(job, dict) and w(job.get("permissions")): found.append("%s job %s" % (path, n))
if found: sys.exit("actions: write in " + ", ".join(found))
PY

echo "$pass passed, $failn failed"
[ "$failn" -eq 0 ]
