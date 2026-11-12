#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC6
# The marker-only pull request gate (slice 4b-6; orchestrator ruling Oct 13: AC6 "whose CI verifies"). bin/marker-pr-gate.py judges a pull request that commits the rc-proof
# marker: it must change exactly the marker file and test-evidence/known-red.json, and the second must differ from the base only by the removal of the one KR-CUTOVER
# entry; the run the marker names must be this repository's release.yml, a push of the marker's rc tag, at that tag's commit, completed with success; its artifacts are
# downloaded into the layout `chain-verify.py rc-proof` reads, and that command (the BASE branch's copy, never the head's) gives the gate's exit status. A pull request that
# touches no marker is not this job's business and passes without a read. The job in ci.yml takes the gate and the verifier from a base checkout and holds three read permissions.
# LIMIT, in plain words: this gate stops a marker PR that carries anything else or names a run that does not verify; a PR that also rewrites the gate's own job in ci.yml is
# stopped by the existing workflow-change rule (both reviews plus the owner's merge), not by this job.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
GATE="$root/bin/marker-pr-gate.py"
TAG=v0.3.0-rc1; RUN=424242; REPO=fosterstack/cache

mkbase() { # mkbase DIR: a base checkout with a stub verifier that logs its arguments and exits with MG_VERIFY_RC
  local d=$1; rm -rf "$d"; mkdir -p "$d/bin" "$d/.github/policy" "$d/test-evidence"
  cat > "$d/bin/chain-verify.py" <<'PY'
import os, sys
a = sys.argv[1:]
open(os.environ["MG_LOG"], "a").write("verify " + " ".join(a) + "\n")
rec = a[a.index("--records") + 1]
need = ["witness-build/build-collection.json", "witness-build/digests.json", "witness-build/items.json", "provenance/provenance.json", "provenance/provenance.rekor.json",
        "witness-rebuild/rebuild-collection.json", "witness-check/witness-scanners/scanners-collection.json", "witness-check/witness-acceptance/acceptance-collection.json",
        "witness-check/witness-runtime/runtime-collection.json", "witness-check/witness-arm64/arm64-collection.json", "hostile-results/hostile-results.json"]
miss = [n for n in need if not os.path.isfile(os.path.join(rec, n))]
extra = []
for dp, dn, fn in os.walk(os.path.join(rec, "witness-check")):
    for f in fn:
        extra.append(os.path.relpath(os.path.join(dp, f), os.path.join(rec, "witness-check")))
if miss:
    sys.stderr.write("refused at marker: missing %s\n" % miss); sys.exit(1)
if sorted(extra) != ["witness-acceptance/acceptance-collection.json", "witness-arm64/arm64-collection.json", "witness-runtime/runtime-collection.json", "witness-scanners/scanners-collection.json"]:
    sys.stderr.write("refused at check: an extra or misplaced Check record %s\n" % extra); sys.exit(1)
sys.exit(int(os.environ.get("MG_VERIFY_RC", "0")))
PY
  printf '{"x":1}\n' > "$d/.github/policy/release-policy.template.json"
  python3 - "$d/test-evidence/known-red.json" <<'PY'
import json, sys
json.dump({"entries": [{"id": "KR-CUTOVER", "suite": "s", "case": "c", "reason": "r", "green_by": "g"},
                       {"id": "KR-OTHER", "suite": "s2", "case": "c2", "reason": "r2", "green_by": "g2"}]}, open(sys.argv[1], "w"), indent=1, sort_keys=True)
PY
}
mkhead() { # mkhead DIR BASE: a head checkout: a git repository with the rc tag, the marker, and known-red.json without KR-CUTOVER
  local d=$1 b=$2; rm -rf "$d"; mkdir -p "$d/.github/policy" "$d/test-evidence" "$d/bin"
  cp "$b/test-evidence/known-red.json" "$d/test-evidence/known-red.json"
  python3 - "$d/test-evidence/known-red.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["entries"] = [e for e in d["entries"] if e["id"] != "KR-CUTOVER"]
json.dump(d, open(p, "w"), indent=1, sort_keys=True)
PY
  printf 'import sys\nsys.exit(0)\n' > "$d/bin/chain-verify.py"      # a head's own verifier: must never be the one that runs
  git -C "$d" init -q -b main
  git -C "$d" -c user.name=t -c user.email=t@t -c commit.gpgsign=false add -A
  git -C "$d" -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm rc
  git -C "$d" tag "$TAG"
  python3 - "$d/.github/policy/rc-proof.json" "$RUN" <<'PY'
import json, sys
keys = ["build", "sign", "rekor", "rebuild", "scanners", "acceptance", "runtime", "arm64", "hostile_verdict"]
json.dump({"rc_tag": "v0.3.0-rc1", "run_id": sys.argv[2], "chain_sha256": "a" * 64, "records": {k: "b" * 64 for k in keys}}, open(sys.argv[1], "w"))
PY
}
mkbin() { # mkbin DIR: a fake gh on PATH: `gh api repos/R/actions/runs/ID` prints $MG_RUN; `gh run download` makes each artifact's directory with a file
  mkdir -p "$1"
  cat > "$1/gh" <<'SH'
#!/bin/sh
echo "gh $*" >> "$MG_LOG"
case "$1 $2" in
  "api repos/"*) [ -z "${MG_API_FAIL:-}" ] || exit 1; cat "$MG_RUN" ;;
  "run download")
    name=""; dir=""
    while [ $# -gt 0 ]; do case "$1" in -n) name=$2; shift ;; -D) dir=$2; shift ;; esac; shift; done
    [ "$name" != "${MG_DL_FAIL:-}" ] || exit 1
    mkdir -p "$dir"
    case "$name" in
      witness-build) echo "{}" > "$dir/build-collection.json" ;;
      digests) echo "{}" > "$dir/digests.json" ;;
      items) echo "{}" > "$dir/items.json" ;;
      provenance) echo "{}" > "$dir/provenance.json"; echo "{}" > "$dir/provenance.rekor.json" ;;
      witness-rebuild) echo "{}" > "$dir/rebuild-collection.json" ;;
      witness-check) for s in scanners acceptance runtime; do mkdir -p "$dir/witness-$s"; echo "{}" > "$dir/witness-$s/$s-collection.json"; done ;;
      witness-check-arm64) echo "{}" > "$dir/arm64-collection.json" ;;
      hostile-results) echo "{}" > "$dir/hostile-results.json" ;;
    esac ;;
  *) exit 3 ;;
esac
SH
  chmod +x "$1/gh"
}
rungood() { python3 - "$1" "$2" <<'PY'
import json, sys
json.dump({"id": 424242, "status": "completed", "conclusion": "success", "event": "push", "head_branch": "v0.3.0-rc1", "head_sha": sys.argv[2],
           "path": ".github/workflows/release.yml", "repository": {"full_name": "fosterstack/cache"}, "run_attempt": 1}, open(sys.argv[1], "w"))
PY
}
mkbase "$work/base"; mkhead "$work/head" "$work/base"; mkbin "$work/bin"
HEADSHA=$(git -C "$work/head" rev-parse "$TAG^{commit}")
rungood "$work/run.json" "$HEADSHA"
files() { python3 -c 'import json,sys; [print(json.dumps(a)) for a in sys.argv[1:]]' "$@" > "$work/files.txt"; }
MARK=.github/policy/rc-proof.json; KRF=test-evidence/known-red.json
gate() { # gate LABEL WANT_RC WORD [ENV=V ...]: run the gate with the fake gh first on PATH; WORD must be in the first line of stderr for a refusal
  local label=$1 want=$2 word=$3; shift 3
  : > "$work/log"; local rc=0
  env "$@" PATH="$work/bin:$PATH" MG_LOG="$work/log" MG_RUN="${MG_RUN_FILE:-$work/run.json}" GH_TOKEN=x python3 -I -B "$GATE" --base-dir "${BASE_DIR:-$work/base}" --head-dir "${HEAD_DIR:-$work/head}" \
      --files "$work/files.txt" --repository "$REPO" > "$work/out" 2> "$work/err" || rc=$?
  local first; first=$(head -n 1 "$work/err")
  if [ "$rc" = "$want" ] && ! grep -q Traceback "$work/err" && { [ "$want" = 0 ] || grep -F -q -- "$word" <<< "$first"; }; then ok "$label"
  else bad "$label (exit $rc, wanted $want${word:+ with '$word'}: $first | $(head -c 160 "$work/out"))"; fi
}
nlog() { grep -c "^$1" "$work/log" 2> /dev/null || true; }

# ---- not a marker pull request: nothing is read ----
files bin/other.sh docs/a.md
gate "a pull request that does not touch the marker passes without reading anything" 0 ""
[ "$(nlog gh)" = 0 ] && [ "$(nlog verify)" = 0 ] && ok "not applicable: no API call and no verifier run" || bad "not applicable: the gate read something ($(cat "$work/log" | head -c 100))"
# ---- the file set ----
files $MARK $KRF
gate "the marker plus the removal of KR-CUTOVER, with a verifying run, passes" 0 ""
[ "$(nlog verify)" = 1 ] && grep -q "^verify rc-proof " "$work/log" && grep -F -q -- "--marker $work/head/$MARK" "$work/log" && grep -F -q -- "--repository $REPO" "$work/log" \
  && ok "the verifier ran once, as rc-proof, on the head's marker" || bad "the verifier call is not the one rc-proof call on the head's marker: $(grep '^verify' "$work/log" | head -c 300)"
grep -F -q "$work/base/bin/chain-verify.py" "$work/log" || true
files $MARK $KRF .github/workflows/ci.yml
gate "the marker plus the removal plus an edit of ci.yml is refused, naming the file" 1 ".github/workflows/ci.yml"
files $MARK $KRF bin/chain-verify.py
gate "the marker plus the removal plus an edit of the verifier is refused" 1 "bin/chain-verify.py"
files $MARK
gate "the marker alone (no removal of KR-CUTOVER) is refused" 1 "known-red.json"
files $KRF
gate "the removal alone (no marker) is not a marker pull request: the known-red list is not this gate's business" 0 ""
# ---- the known-red change is exactly one entry ----
cp "$work/head/$KRF" "$work/keep.json"
python3 - "$work/head/$KRF" "$work/base/$KRF" <<'PY'
import json, sys
h, b = sys.argv[1:3]
d = json.load(open(h)); d["entries"] = []            # KR-OTHER removed too
json.dump(d, open(h, "w"))
PY
files $MARK $KRF
gate "the removal of KR-CUTOVER and of another entry is refused" 1 "KR-OTHER"
cp "$work/base/$KRF" "$work/head/$KRF"
gate "a known-red.json that still holds KR-CUTOVER is refused" 1 "KR-CUTOVER"
python3 - "$work/head/$KRF" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["entries"] = [e for e in d["entries"] if e["id"] != "KR-CUTOVER"]
d["entries"][0]["reason"] = "reworded"; json.dump(d, open(p, "w"))
PY
gate "the removal with another entry edited is refused" 1 "KR-OTHER"
python3 - "$work/head/$KRF" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["entries"][0]["reason"] = "r2"; d["entries"].append({"id": "KR-NEW", "suite": "s", "case": "c", "reason": "r", "green_by": "g"}); json.dump(d, open(p, "w"))
PY
gate "the removal with a new entry added is refused" 1 "KR-NEW"
cp "$work/keep.json" "$work/head/$KRF"
# ---- the whole document, and the file names exactly as the API gave them ----
python3 - "$work/head/$KRF" "$work/keep.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[2])); d["_note"] = "edited"; json.dump(d, open(sys.argv[1], "w"))
PY
files $MARK $KRF; gate "the removal plus an edited _note is refused" 1 "_note"
python3 - "$work/head/$KRF" "$work/keep.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[2])); d["extra_field"] = 1; json.dump(d, open(sys.argv[1], "w"))
PY
gate "the removal plus a new top-level field is refused" 1 "extra_field"
cp "$work/keep.json" "$work/head/$KRF"
files "$MARK" "$KRF" " "; gate "a file whose name is one space is refused" 1 " "
files "$MARK " "$MARK" "$KRF"; gate "a space-padded marker path is a different file and is refused" 1 "$MARK "
files "$MARK" "$KRF" "a
b"; gate "a file name with a newline in it is refused as an extra file" 1 "a"
printf '%s\n%s\n' ".github/policy/rc-proof.json" '"test-evidence/known-red.json"' > "$work/files.txt"
gate "a file list line that is not a JSON string is refused" 1 "not a JSON string"
files $MARK $KRF
# ---- the run the marker names ----
runmut() { python3 - "$work/run.json" "$work/run-bad.json" "$1" "$2" <<'PY'
import json, sys
src, dst, key, val = sys.argv[1:5]
d = json.load(open(src))
if key == "repository": d["repository"] = {"full_name": val}
else: d[key] = None if val == "NONE" else val
json.dump(d, open(dst, "w"))
PY
}
for spec in "repository:evil/cache:repository" "event:workflow_dispatch:event" "head_branch:v0.3.0-rc2:head_branch" "head_sha:$(printf 'c%.0s' $(seq 40)):head_sha" "conclusion:failure:conclusion" "status:in_progress:status" "path:.github/workflows/ci.yml:path"; do
  k=${spec%%:*}; r=${spec#*:}; v=${r%:*}; w=${r##*:}
  runmut "$k" "$v"; MG_RUN_FILE="$work/run-bad.json" gate "a run whose $k is $v is refused" 1 "$w"
done
unset MG_RUN_FILE
gate "an API read that fails is refused" 1 "run" MG_API_FAIL=1
for art in witness-build digests items provenance witness-rebuild witness-check witness-check-arm64 hostile-results; do
  gate "a missing artifact ($art) is refused and the verifier is not run" 1 "$art" MG_DL_FAIL=$art
  [ "$(nlog verify)" = 0 ] || bad "the verifier ran although $art could not be downloaded"
done
gate "a verifier that refuses gives the gate's exit status (never swallowed)" 1 "rc-proof" MG_VERIFY_RC=1
# ---- which code runs ----
grep -q "^verify" "$work/log" || true
: > "$work/log"; gate "the head's own bin/chain-verify.py is never the one that runs (the base's copy is)" 0 ""
if grep -q "^verify" "$work/log"; then ok "the base's verifier stub logged the call (the head's copy exits 0 silently and logs nothing)"; else bad "the verifier call was not made by the base's copy"; fi
printf '{not json' > "$work/head/$MARK"; files $MARK $KRF
gate "an unreadable marker is refused" 1 "marker"
rungood "$work/run.json" "$HEADSHA"
files; : > "$work/files.txt"
gate "an empty file list (the API gave nothing) is refused, never read as 'no marker'" 1 "file list"

# ---- the job in ci.yml: a judge of its text, with mutations ----
python3 - "$root/.github/workflows/ci.yml" "$work" <<'PY'
import copy, json, sys, yaml
src, work = sys.argv[1:3]
d = yaml.safe_load(open(src))
def judge(wf):
    bad = []
    on = wf.get(True, wf.get("on"))
    if "pull_request_target" in (on if isinstance(on, dict) else {}):
        bad.append("pull_request_target is used")
    job = (wf.get("jobs") or {}).get("marker-gate")
    if not isinstance(job, dict):
        return ["no marker-gate job"]
    if set(job) - {"name", "runs-on", "if", "permissions", "steps"}:
        bad.append("job keys beyond name, runs-on, if, permissions, steps: %s" % sorted(set(job) - {"name", "runs-on", "if", "permissions", "steps"}))
    if job.get("name") != "marker-gate" or job.get("runs-on") != "ubuntu-latest":
        bad.append("the job's name or runner is not marker-gate on ubuntu-latest: %r %r" % (job.get("name"), job.get("runs-on")))
    if job.get("if") != "github.event_name == 'pull_request'":
        bad.append("the job is not exactly the pull_request job: %r" % job.get("if"))
    if job.get("permissions") != {"contents": "read", "actions": "read", "pull-requests": "read"}:
        bad.append("permissions are not exactly three reads: %r" % job.get("permissions"))
    st = job.get("steps") or []
    if len(st) != 3:
        return bad + ["the job has %d steps, not three (head checkout, base checkout, the gate)" % len(st)]
    pin = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    h, b, g = st
    if not str(h.get("uses", "")).startswith(pin) or h.get("with") != {"path": "head", "fetch-depth": 0, "persist-credentials": False} or set(h) - {"uses", "with"}:
        bad.append("the first step is not the pinned head checkout at path head with full history and no credential: %r" % h)
    if not str(b.get("uses", "")).startswith(pin) or b.get("with") != {"ref": "${{ github.event.pull_request.base.sha }}", "path": "base", "persist-credentials": False} or set(b) - {"uses", "with"}:
        bad.append("the second step is not the pinned checkout of the BASE sha at path base with no credential: %r" % b)
    if set(g) - {"name", "env", "run"}:
        bad.append("the gate step has keys beyond name, env, run: %s" % sorted(set(g) - {"name", "env", "run"}))
    if g.get("env") != {"GH_TOKEN": "${{ github.token }}", "PR_NUMBER": "${{ github.event.pull_request.number }}"}:
        bad.append("the gate step's env is not exactly the job token and the PR number: %r" % g.get("env"))
    lines = [l.strip() for l in str(g.get("run") or "").splitlines() if l.strip() and not l.strip().startswith("#")]
    want = ['set -euo pipefail',
            'gh api --paginate "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/files" --jq \'.[] | .filename | @json\' > changed.txt',
            'python3 -I -B base/bin/marker-pr-gate.py --base-dir base --head-dir head --files changed.txt --repository "$GITHUB_REPOSITORY"']
    if lines != want:
        bad.append("the gate step's commands are not exactly the three reviewed lines: %r" % lines)
    return bad
errs = judge(d)
print("REAL", errs)
open(work + "/judge-real", "w").write("ok" if not errs else "; ".join(errs))
def mut(name, fn, word):
    c = copy.deepcopy(d); fn(c); r = judge(c)
    open(work + "/judge-" + name, "w").write(("caught " if any(word in x for x in r) else "MISSED ") + "; ".join(r)[:200])
mut("noperm", lambda c: c["jobs"]["marker-gate"]["permissions"].update({"id-token": "write"}), "permissions")
mut("headref", lambda c: c["jobs"]["marker-gate"]["steps"][1]["with"].update({"ref": "${{ github.event.pull_request.head.sha }}"}), "BASE sha")
mut("swallow", lambda c: c["jobs"]["marker-gate"]["steps"][2].update({"run": c["jobs"]["marker-gate"]["steps"][2]["run"] + "\n|| true"}), "three reviewed lines")
mut("coe", lambda c: c["jobs"]["marker-gate"]["steps"][2].update({"continue-on-error": True}), "keys beyond")
mut("cond", lambda c: c["jobs"]["marker-gate"].update({"if": "always()"}), "pull_request job")
mut("headscript", lambda c: c["jobs"]["marker-gate"]["steps"][2].update({"run": c["jobs"]["marker-gate"]["steps"][2]["run"].replace("base/bin/marker-pr-gate.py", "head/bin/marker-pr-gate.py")}), "three reviewed lines")
mut("nojob", lambda c: c["jobs"].pop("marker-gate"), "no marker-gate job")
mut("prt", lambda c: c.__setitem__(True, {"pull_request_target": None}), "pull_request_target")
mut("runner", lambda c: c["jobs"]["marker-gate"].update({"runs-on": "self-hosted"}), "runner")
mut("rename", lambda c: c["jobs"]["marker-gate"].update({"name": "marker-check"}), "runner")
mut("secret", lambda c: c["jobs"]["marker-gate"]["steps"][2]["env"].update({"X": "${{ secrets.Y }}"}), "env")
PY
if [ "$(cat "$work/judge-real" 2> /dev/null)" = ok ]; then ok "the marker-gate job in ci.yml is exactly the reviewed one (two pinned checkouts, base sha, three reads, three lines)"; else bad "the marker-gate job in ci.yml: $(cat "$work/judge-real" 2> /dev/null | head -c 300)"; fi
for m in noperm headref swallow coe cond headscript nojob prt runner rename secret; do
  case "$(cat "$work/judge-$m" 2> /dev/null)" in caught*) ok "the job judge catches: $m" ;; *) bad "the job judge missed: $m ($(cat "$work/judge-$m" 2> /dev/null | head -c 120))" ;; esac
done
EXPECT=51
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
