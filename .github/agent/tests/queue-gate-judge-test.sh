#!/usr/bin/env bash
# proves: REQ-DEP-005-AC3
# Offline suite for .github/agent/bin/queue-gate-judge.sh (cache#542): the judge the review gate runs, from the default
# branch's copy, over a merge queue's head commit. It must fail closed.
#   queue-gate-judge.sh HEAD_SHA REF    exit 0 only when every check holds, exit 1 for any refusal (never 126/127)
# The suite builds a git repository as the current directory: the script under test, stubs at the literal paths of the
# programs it calls, and commits made with commit-tree. A `gh` on PATH is a stub, so the network is never touched.
# What it cannot show is GitHub's side: the payload shapes, which workflow copy runs, the token scopes.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
sut="$repo/.github/agent/bin/queue-gate-judge.sh"
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
pass=0; fail=0
ok()  { echo "ok: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
export GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" GIT_COMMITTER_DATE="2026-01-01T00:00:00Z"
root="$w/root"
git init -q "$root"
g() { git -C "$root" "$@"; }
tree="$(g hash-object -t tree -w --stdin </dev/null)"
mk() { # mk MESSAGE [PARENT...]: an empty-tree commit; prints its sha
  local m=$1; shift; local a=(); for p in "$@"; do a+=(-p "$p"); done
  g commit-tree "$tree" "${a[@]}" -m "$m"
}
M0="$(mk base)"; g update-ref refs/remotes/origin/main "$M0"
P1="$(mk pr1 "$M0")"; P2="$(mk pr2 "$M0")"; P3="$(mk pr3 "$M0")"
G1="$(mk 'merge pr1' "$M0" "$P1")"                # two-parent merge
G2="$(mk 'merge pr2' "$G1" "$P2")"                # the group head: two merges on top of main
S1="$(mk 'squash pr1' "$M0")"                     # a squash or rebase shape: one parent
GS="$(mk 'merge pr2' "$S1" "$P2")"                # a merge on top of a squashed commit
GO="$(mk 'octopus' "$G1" "$P2" "$P3")"            # three parents
GT="$(mk 'merge pr2' "$GO" "$P2")"                # an octopus below the head
GL="$(mk 'linear on top' "$G2")"                  # a one-parent commit at the head
UR="$(mk 'unrelated root')"                       # history that never meets main
UG="$(mk 'merge pr1' "$UR" "$P1")"

mkdir -p "$root/bin" "$root/.github/agent/bin" "$root/.github/agent/tests" "$root/.github/agent/fixtures/testlib/pyyaml"
[ -f "$sut" ] && cp "$sut" "$root/.github/agent/bin/queue-gate-judge.sh"
cat > "$root/bin/audit-record-judge.sh" <<'EOF'
#!/usr/bin/env bash
echo "$1 $2" >> "$QG_LOG"
f="$QG_RC/$1"; [ -f "$f" ] && exit "$(cat "$f")"; exit 0
EOF
cat > "$root/.github/agent/bin/check-action-pins.py" <<'EOF'
import os, sys
open(os.environ["QG_MAIN_LOG"], "a").write("pins " + " ".join(sys.argv[1:]) + "\n")
f = os.path.join(os.environ["QG_MRC"], "pins")
sys.exit(int(open(f).read()) if os.path.exists(f) else 0)
EOF
cat > "$root/bin/check-file-allowlist.sh" <<'EOF'
cat >/dev/null
echo "allow $GITHUB_BASE_REF $ALLOWLIST_NUL $ALLOWLIST_HEAD_REV queue=${GITHUB_QUEUE_REF-unset}" >> "$QG_MAIN_LOG"
exit "$(cat "$QG_MRC/allow" 2>/dev/null || echo 0)"
EOF
cat > "$root/.github/agent/tests/pin-wiring-test.sh" <<'EOF'
echo "wiring $PIN_WIRING_JUDGE_GIT yaml=$([ -e "${PYTHONPATH:-/nonexistent}/yaml" ] && echo 1 || echo 0)" \
  >> "$QG_MAIN_LOG"
exit "$(cat "$QG_MRC/wiring" 2>/dev/null || echo 0)"
EOF
cat > "$root/bin/scan-no-workflow-call-test.sh" <<'EOF'
echo "scan $SCAN_GUARD_JUDGE_GIT yaml=$([ -e "${PYTHONPATH:-/nonexistent}/yaml" ] && echo 1 || echo 0)" \
  >> "$QG_MAIN_LOG"
exit "$(cat "$QG_MRC/scan" 2>/dev/null || echo 0)"
EOF
chmod +x "$root/bin/audit-record-judge.sh"
mkdir -p "$w/gh-down"
cat > "$w/gh-down/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh: HTTP 500: server error" >&2; exit 1
EOF
chmod +x "$w/gh-down/gh"
variant() { # variant NAME: a copy of the fixture repository to damage; prints its path
  rm -rf "$w/v-$1"; cp -a "$root" "$w/v-$1"; echo "$w/v-$1"
}

# exec_sut HEAD [ENV=VAL...]: the judge under a clean environment; cwd is $ROOT (default: the fixture repository)
exec_sut() {
  local head=$1; shift
  LAST_OUT="$(cd "${ROOT:-$root}" && env -i PATH="$PATH" HOME="$w" TMPDIR="$w" GH_TOKEN=x GITHUB_REPOSITORY=o/r \
    QG_LOG="$w/log" QG_RC="$w/rc" QG_MAIN_LOG="$w/mainlog" QG_MRC="$w/mrc" "$@" \
    bash .github/agent/bin/queue-gate-judge.sh "$head" "${QREF_ARG-gh-readonly-queue/main/pr-12-$head}" 2>&1)"
  LAST_RC=$?
}
reset() { rm -rf "$w/rc" "$w/mrc"; mkdir -p "$w/rc" "$w/mrc"; : > "$w/log"; : > "$w/mainlog"; ROOT=; }
verdict() { # verdict NAME WANT_RC: the judge's exit code must be exactly WANT_RC
  [ "$LAST_RC" -eq "$2" ] && ok "$1" || bad "$1 (rc $LAST_RC, want $2; $(tr '\n' ' ' <<<"$LAST_OUT" | cut -c1-120))"
}
run() { # run NAME WANT_RC HEAD [ENV=VAL...]: a fresh state for each case
  local name=$1 want=$2 head=$3; shift 3
  reset; exec_sut "$head" "$@"; verdict "$name" "$want"
}
refused_early() { # refused_early NAME HEAD: exit 1 and no record judge was reached
  reset; exec_sut "$2"; verdict "$1" 1
  [ -s "$w/log" ] && bad "$1: the record judge was reached" || ok "$1: the record judge was not reached"
}
need() { # need NAME PATTERN FILE: the file must hold a line matching the pattern
  grep -qE "$2" "$3" && ok "$1" || bad "$1 (no /$2/ in $3)"
}

[ -f "$sut" ] && ok ".github/agent/bin/queue-gate-judge.sh exists" \
  || bad ".github/agent/bin/queue-gate-judge.sh does not exist"

run "a two-merge group on main, every record good, main's judges good -> exit 0" 0 "$G2"
need "each pull request head (second parent) went to the record judge with base main (pr1)" "^$P1 main\$" "$w/log"
need "each pull request head (second parent) went to the record judge with base main (pr2)" "^$P2 main\$" "$w/log"
need "main's pin checker ran over the queue head (--verify-tags --git)" "^pins --verify-tags --git $G2\$" "$w/mainlog"
need "main's allowlist guard ran over the queue head (NUL list, head rev, base main) and was given the queue ref" \
  "^allow main 1 $G2 queue=gh-readonly-queue/main/pr-12-$G2\$" "$w/mainlog"
need "main's pin-wiring judge ran over the queue head, with the yaml shim" "^wiring $G2 yaml=1\$" "$w/mainlog"
need "main's scanner guard ran over the queue head, with the yaml shim" "^scan $G2 yaml=1\$" "$w/mainlog"
run "a one-merge group is good too" 0 "$G1"

refused_early "empty sha" ""
refused_early "uppercase sha" "$(tr a-f A-F <<<"$G2")"
refused_early "short sha (39 hex)" "${G2:0:39}"
refused_early "41-char sha" "${G2}a"
refused_early "non-hex sha (injection-shaped)" 'x;touch /tmp/pwn'
refused_early "sha with a trailing newline" "$G2"$'\n'
reset; exec_sut ""; verdict "no argument at all -> refused" 1
QREF_ARG= refused_early "no queue ref -> refused" "$G2"
unset QREF_ARG

reset; exec_sut "$GS"
verdict "a group commit with ONE parent (squash or rebase shape) at the bottom -> refused" 1
grep -q "queue merge method MERGE" <<<"$LAST_OUT" && ok "the one-parent refusal names the queue merge method MERGE" \
  || bad "the one-parent refusal does not name the queue merge method MERGE ($LAST_OUT)"
run "a group commit with ONE parent at the head -> refused" 1 "$GL"
run "a group commit with THREE parents below the head -> refused" 1 "$GT"
run "a group commit with THREE parents at the head -> refused" 1 "$GO"
run "history that never meets main (a parentless commit below the head) -> refused" 1 "$UG"
run "an empty group (the head is main's tip itself) -> refused" 1 "$M0"
NOSUCH="$(printf '1%.0s' $(seq 40))"
run "a head that is not in the repository -> refused" 1 "$NOSUCH"
reset; ROOT="$(variant nobase)"; git -C "$ROOT" update-ref -d refs/remotes/origin/main; exec_sut "$G2"
verdict "no remote-tracking ref for main -> refused" 1

run_rc() { # run_rc NAME WANT_RC PR_SHA RC: the record judge answers RC for that head
  reset; echo "$4" > "$w/rc/$3"; exec_sut "$G2"; verdict "$1" "$2"
}
run_rc "one pull request head whose record judge exits 1 (no passing record) -> refused" 1 "$P1" 1
run_rc "the other pull request head's record judge exits 1 -> refused" 1 "$P2" 1
run_rc "a record judge exiting 3 (GitHub API error) -> refused" 1 "$P1" 3
run_rc "a record judge exiting 2 -> refused" 1 "$P2" 2
run_rc "a record judge exiting 127 -> refused" 1 "$P1" 127
reset; echo 1 > "$w/rc/$P2"; exec_sut "$G2"
[ -s "$w/mainlog" ] && bad "main's judges ran after a missing record" \
  || ok "main's judges did not run after a missing record"

reset; ROOT="$(variant norecord)"; rm -f "$ROOT/bin/audit-record-judge.sh"; exec_sut "$G2"
verdict "a record judge that is missing from the tree -> refused" 1
reset; ROOT="$(variant dirrecord)"; rm -f "$ROOT/bin/audit-record-judge.sh"; mkdir "$ROOT/bin/audit-record-judge.sh"
exec_sut "$G2"; verdict "a record judge that is a directory -> refused" 1
reset; ROOT="$(variant nowiring)"; rm -f "$ROOT/.github/agent/tests/pin-wiring-test.sh"; exec_sut "$G2"
verdict "a main judge (pin-wiring) missing from the tree -> refused" 1
run_main() { # run_main NAME JUDGE: that one main judge exits 1, every record good
  reset; echo 1 > "$w/mrc/$2"; exec_sut "$G2"; verdict "$1" 1
}
run_main "main's pin checker failing over the head, every record good -> refused" pins
run_main "main's allowlist guard failing over the head -> refused" allow
run_main "main's pin-wiring judge failing over the head -> refused" wiring
run_main "main's scanner guard failing over the head -> refused" scan

# The real record judge (bin/audit-record-judge.sh and audit-record.py, with main's writers policy) against a fake
# GitHub that holds a valid record for every pull request head: that case must pass. Then one input at a time is
# varied, and each refusal must print its own reason, so an unrelated failure cannot satisfy it.
mkdir -p "$w/gh-up"
cat > "$w/gh-up/gh" <<'EOF'
#!/usr/bin/env bash
exec python3 - "$@" <<'PY'
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("ar", "bin/audit-record.py")
ar = importlib.util.module_from_spec(spec); spec.loader.exec_module(ar)
writer = json.load(open(os.environ["QG_WRITERS"]))["writers"][0]   # the repo's own copy, not the tree under test
who = {"type": "Bot", "login": writer["login"], "id": writer["id"]}
url = sys.argv[2]
ref_url, commit_url = "repos/o/r/git/ref/heads/audit/", "repos/o/r/commits/"
if url.startswith(ref_url):
    head = url[len(ref_url):]
    if head == os.environ.get("QG_NOREC"):
        sys.stderr.write("gh: HTTP 404: Not Found\n"); sys.exit(1)
    print(json.dumps({"ref": "refs/heads/audit/" + head, "object": {"type": "commit", "sha": head[::-1]}}))
elif url.startswith(commit_url):
    rec = url[len(commit_url):]
    print(json.dumps({"sha": rec, "parents": [{"sha": rec[::-1]}],
                      "files": [{"filename": ar.RECORD_FILE, "status": "added"}],
                      "commit": {"message": ar.RECORD_MESSAGE, "verification": {"verified": True, "reason": "valid"}},
                      "author": who, "committer": who}))
else:
    sys.stderr.write("gh: unexpected " + url + "\n"); sys.exit(1)
PY
EOF
chmod +x "$w/gh-up/gh"
QGW="QG_WRITERS=$repo/.github/policy/audit-writers.json"
reset; ROOT="$(variant realrecord)"
cp "$repo/bin/audit-record-judge.sh" "$repo/bin/audit-record.py" "$ROOT/bin/"
mkdir -p "$ROOT/.github/policy"; cp "$repo/.github/policy/audit-writers.json" "$ROOT/.github/policy/"
exec_sut "$G2" PATH="$w/gh-up:$PATH" "$QGW"
verdict "a valid record for every pull request head (the real record judge) -> accepted" 0
said() {
  grep -qF -- "$2" <<<"$LAST_OUT" && ok "$1" || bad "$1 (not in: $(tr '\n' ' ' <<<"$LAST_OUT" | cut -c1-160))"
}
exec_sut "$G2" PATH="$w/gh-up:$PATH" "$QGW" QG_NOREC="$P2"
verdict "one pull request head with no record branch -> refused" 1
said "the missing record is named" "there is no branch audit/$P2"
exec_sut "$G2" PATH="$w/gh-down:$PATH"
verdict "GitHub API unreadable (gh errors, the real record judge) -> refused" 1
said "the API error is named" "GitHub API error"
exec_sut "$G2" PATH="$w/gh-up:$PATH" "$QGW" GITHUB_REPOSITORY=
verdict "no repository name in the environment (real record judge) -> refused" 1
said "the missing repository name is named" "GITHUB_REPOSITORY is not owner/name"
rm -f "$ROOT/.github/policy/audit-writers.json"; exec_sut "$G2" PATH="$w/gh-up:$PATH" "$QGW"
verdict "the writers policy missing from the tree (real record judge) -> refused" 1
said "the missing policy is named" "writers policy"

# the script reads git objects only
if [ -f "$sut" ]; then
  grep -qE 'git[[:space:]]+(checkout|switch|worktree|merge|pull)\b|\beval\b' "$sut" \
    && bad "the judge checks nothing out and evals nothing" || ok "the judge checks nothing out and evals nothing"
  grep -qE 'set -[a-z]*u' "$sut" && ok "the judge runs with set -u" || bad "the judge runs with set -u"
else
  bad "the judge checks nothing out and evals nothing (no script)"; bad "the judge runs with set -u (no script)"
fi

# the repo's pin checker, run over a tree holding the script and a workflow step that runs it, names no program by a
# variable (the gate workflow itself is not in this tree; its "missing" line is the one finding allowed)
pt="$w/pintree"; rm -rf "$pt"
mkdir -p "$pt/.github/workflows" "$pt/.github/agent/bin" "$pt/.github/agent/tests" "$pt/bin"
cat > "$pt/.github/workflows/queue.yml" <<'EOF'
name: queue
on: workflow_dispatch
permissions: {}
jobs:
  judge:
    runs-on: ubuntu-latest
    steps:
      - run: bash .github/agent/bin/queue-gate-judge.sh "$HEAD_SHA"
EOF
if [ -f "$sut" ]; then
  cp "$sut" "$pt/.github/agent/bin/"
  cp "$repo/.github/agent/bin/check-action-pins.py" "$pt/.github/agent/bin/"
  cp "$repo/.github/agent/tests/pin-wiring-test.sh" "$pt/.github/agent/tests/"
  cp "$repo/bin/audit-record-judge.sh" "$repo/bin/audit-record.py" "$repo/bin/check-file-allowlist.sh" \
     "$repo/bin/scan-no-workflow-call-test.sh" "$pt/bin/"
  pins_out="$(cd "$pt" && python3 -I "$repo/.github/agent/bin/check-action-pins.py" . 2>&1)"
  pins_find="$(grep -vE '^check-action-pins:|^\.github/workflows/agent-review-gate\.yml: missing' <<<"$pins_out")"
  if [ -z "$pins_find" ]; then ok "the repo's pin checker finds nothing in the script (no program named by a variable)"
  else bad "the repo's pin checker refuses the script: $(head -c 300 <<<"$pins_find" | tr '\n' ' ')"; fi
else
  bad "the repo's pin checker finds nothing in the script (no script)"
fi

echo "----"
echo "queue-gate-judge: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
