#!/usr/bin/env bash
# proves: REQ-SUP-001-AC30, REQ-SUP-001-AC32, REQ-SUP-001-AC33
# The owner's ruling of Nov 11 2026 removed the release-age wait. Proved on the tracked files: no text of the old wait
# is left, Dependabot carries no cooldown and one
# entry per ecosystem root, the context pin-age stays while the job behind it measures nothing, no job holds actions:
# write, and the tag observer is gone.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
cd "$root"
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

# Files that may keep the phrases, each with its reason:
#   this test                      names the phrases it forbids.
#   docs/quality/traceability.md   is GENERATED from requirements.yaml (its first lines say so), so it repeats that
#   file.
#   vendor/                        is third-party Go source (time-window prose in prometheus), not ours; go.sum/go.mod
#   hold no prose.
# No CHANGELOG or release-history file is tracked (checked by the name test below), so none is excluded.
if git ls-files | grep -qiE '(^|/)(CHANGELOG|HISTORY|NEWS)'; then bad "a changelog-style file is tracked: add it to \
the exclusions with a reason"; else ok "no changelog-style file needs excluding"; fi
if head -5 docs/quality/traceability.md | grep -q 'GENERATED'; then ok "docs/quality/traceability.md is generated (so \
excluded)"; else bad "docs/quality/traceability.md is generated (so excluded)"; fi

self=.github/agent/tests/release-age-gone-test.sh
git ls-files -z | grep -zvE \
    "^(vendor/|$self\$|docs/quality/traceability\.md\$)" >"$work/files"
# The hold's own phrases only (not 'cooldown' or '7-day', which the Wolfi no-wait rule 48 also uses). This test's own
# file name contains 'release-age': (?!-gone-test) skips it.
# grep exits 1 for no match and 2 for an error: an unreadable file fails the test. Symlinks and submodules (not
# regular files) are skipped.
phrases='release[ -]age(?!-gone-test)|\bage hold\b|held pull request|rerun-held'
: >"$work/hits"
while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  rc=0; grep -IHniP -- "$phrases" "$f" >>"$work/hits" || rc=$?
  [ "$rc" -le 1 ] || { echo "FAIL cannot read $f"; exit 1; }
done <"$work/files"
if [ ! -s "$work/hits" ]; then ok "no tracked file names the release-age wait"; else bad "no tracked file names the \
release-age wait ($(wc -l <"$work/hits") lines, first: $(head -3 "$work/hits" | cut -c1-140 | tr '\n' '|'))"; fi
: >"$work/hits"
while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  rc=0; grep -IHnE 'tag_observer' "$f" >>"$work/hits" || rc=$?
  [ "$rc" -le 1 ] || { echo "FAIL cannot read $f"; exit 1; }
done <"$work/files"
if [ ! -s "$work/hits" ]; then ok "nothing refers to tag_observer"; else bad "nothing refers to tag_observer \
($(wc -l <"$work/hits") lines)"; fi

# the tag observer is gone
f=.github/agent/supply-chain/tag_observer.py
if [ ! -e "$f" ] && ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then ok "$f does not exist"; else bad "$f \
does not exist"; fi

py() { python3 -I - "$@"; }
# AC32: dependabot.yml
py .github/dependabot.yml >"$work/dep" 2>&1 <<'PY' && ok "dependabot.yml: no cooldown key anywhere, one entry per \
ecosystem and directory" || { bad "dependabot.yml: no cooldown key anywhere, one entry per ecosystem and directory"; \
    sed 's/^/     /' "$work/dep"; }
import sys, yaml, collections
d = yaml.safe_load(open(sys.argv[1]))
def has(o):
    if isinstance(o, dict): return "cooldown" in o or any(has(v) for v in o.values())
    if isinstance(o, list): return any(has(v) for v in o)
    return False
if has(d): sys.exit("a cooldown key is present")
ups = d["updates"]
c = collections.Counter(
    (u["package-ecosystem"], u.get("directory", u.get("directories") and tuple(u["directories"]))) for u in ups)
dup = [k for k, n in c.items() if n > 1]
if dup: sys.exit("duplicate entries: %r" % dup)
PY

# AC33: the context stays; the job stays and measures nothing; no actions: write anywhere
if grep -q '"context": "pin-age"' .github/policy/required-checks.json; then ok "required-checks.json still has the \
context pin-age"; else bad "required-checks.json still has the context pin-age"; fi
py .github/workflows/supply-chain.yml >"$work/sc" 2>&1 <<'PY' && ok "supply-chain.yml still has the pin-age job" || { \
    bad "supply-chain.yml still has the pin-age job"; sed 's/^/     /' "$work/sc"; }
import sys, yaml
j = yaml.safe_load(open(sys.argv[1]))["jobs"]
if "pin-age" not in j and not any(v.get("name") == "pin-age" for v in j.values()): sys.exit("no job named pin-age")
PY
# The one holder is release.yml job decide (bin/release-patch-wiring-test.sh pins the same exception). The checker
# takes a workflow folder, so the mutant cases below can run it on edited copies.
cat >"$work/holders.py" <<'PY'
import glob, os, sys, yaml
bad = []
for p in sorted(glob.glob(os.path.join(sys.argv[1], "*.y*ml"))):
    d = yaml.safe_load(open(p)) or {}
    def w(perm): return isinstance(perm, dict) and perm.get("actions") == "write" or perm == "write-all"
    if w(d.get("permissions")): bad.append(os.path.basename(p) + " (workflow)")
    for n, j in (d.get("jobs") or {}).items():
        if isinstance(j, dict) and w(j.get("permissions")) and (os.path.basename(p), n) != ("release.yml", "decide"):
            bad.append("%s job %s" % (os.path.basename(p), n))
if bad: sys.exit("actions: write in " + ", ".join(bad))
PY
if python3 -I "$work/holders.py" .github/workflows >"$work/aw" 2>&1; then ok "actions: write is held by release.yml \
job decide alone"; else bad "actions: write is held by release.yml job decide alone"; sed 's/^/     /' "$work/aw"; fi

# mutant: edit a copy of the workflows with $1 (python, sees dict w of file name -> parsed yaml), expect refusal
mutant_refused() {
  local name=$1 edit=$2 dir="$work/mut-$1"
  mkdir "$dir"; cp .github/workflows/*.y*ml "$dir"/
  python3 -I - "$dir" <<PY
import glob, os, sys, yaml
w = {}
for p in glob.glob(os.path.join(sys.argv[1], "*.y*ml")):
    w[os.path.basename(p)] = yaml.safe_load(open(p))
$edit
for n, d in w.items():
    yaml.safe_dump(d, open(os.path.join(sys.argv[1], n), "w"))
PY
  if python3 -I "$work/holders.py" "$dir" >/dev/null 2>&1; then bad "mutant $name: actions: write is still refused"; \
  else ok "mutant $name: actions: write is still refused"; fi
}
mutant_refused other-job-in-release "w['release.yml']['jobs']['patch-notes']['permissions'] = {'actions': 'write'}"
mutant_refused other-file-job "j = w['supply-chain.yml']['jobs']; j[next(iter(j))]['permissions'] = {'actions': 'write'}"
mutant_refused decide-in-other-file "w['supply-chain.yml']['jobs']['decide'] = {'permissions': {'actions': 'write'}}"
mutant_refused release-workflow-level "w['release.yml']['permissions'] = {'actions': 'write'}"
# the pin-age job's steps run no re-run of runs and no timing of versions
py .github/workflows/supply-chain.yml >"$work/sc2" 2>&1 <<'PY' && ok "the pin-age job runs no re-run, no run listing \
and no publication-time lookup" || { bad "the pin-age job runs no re-run, no run listing and no publication-time \
lookup"; sed 's/^/     /' "$work/sc2"; }
import sys, yaml, re
j = yaml.safe_load(open(sys.argv[1]))["jobs"]
job = j.get("pin-age") or next((v for v in j.values() if v.get("name") == "pin-age"), None)
if job is None: sys.exit("no pin-age job")
t = yaml.dump(job)
m = re.search(r"run rerun|gh run |/rerun|published_at|--now|first.seen|tag_observer", t)
if m: sys.exit("found: " + m.group(0))
PY

echo "$pass passed, $failn failed"
[ "$failn" -eq 0 ]
