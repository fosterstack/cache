#!/usr/bin/env bash
# proves: REQ-DEP-005-AC3
# Offline fixture and mutation suite for bin/queue-gate-judge.sh (cache#542): the judge that the review gate runs, from
# the default branch's copy, over a merge queue's temporary branch, and that must fail closed. (The AC name AC3 is
# added to requirements.yaml later by the lead; it does not exist there yet.)
#
# THE CONTRACT this suite pins (the coder writes bin/queue-gate-judge.sh to it):
#   bin/queue-gate-judge.sh HEAD_SHA REF
#     HEAD_SHA  the queue head (workflow_run.head_sha): exactly 40 lower-case hex.
#     REF       the queue ref (workflow_run.head_branch): exactly ^gh-readonly-queue/main/pr-[0-9]+-[0-9a-f]{40}$
#   Exit 0 only when ALL hold: both arguments valid; the objects of HEAD_SHA are readable; the first-parent history
#   from HEAD_SHA down to (not including) the group's base has at least one commit and EVERY such commit is a
#   two-parent merge (a squash or rebase shape, one parent, or an octopus, three or more, fails); every second
#   parent of those commits (the pull request heads) has a passed-audit record (the record judge exits 0 for it);
#   and main's five judges pass over HEAD_SHA. Anything else exits non-zero and never 0: 1 for a refusal, 3 when
#   the record judge reports a GitHub API error (the audit-record-judge.sh exit-3 meaning). 126 and 127 (a missing
#   command leaking out) are not acceptable verdicts here.
#   Nothing is checked out and nothing of the group is executed: git objects are read only.
# Environment (the test seams; production sets only the first two):
#   GH_TOKEN, GITHUB_REPOSITORY   passed through to the record judge
#   QUEUE_GATE_GIT_DIR            the git directory holding the group's objects (default: the current repository's)
#   QUEUE_GATE_BASE_REF           the ref naming the default branch's tip, the group's base (default
#                                 refs/remotes/origin/main); the walk is `rev-list --first-parent BASE..HEAD`
#   QUEUE_GATE_RECORD_JUDGE       the record judge, called as `$QUEUE_GATE_RECORD_JUDGE PR_HEAD_SHA main`
#                                 (default: bin/audit-record-judge.sh beside the script)
#   QUEUE_GATE_MAIN_JUDGES        one command that runs main's five judges (check-action-pins --git,
#                                 check-file-allowlist, pin-wiring, scanner guard, and the record set) over a sha,
#                                 called as `$QUEUE_GATE_MAIN_JUDGES HEAD_SHA`; any non-zero exit fails the verdict
#                                 (default: the real commands, in the script)
#   A `gh` on PATH is what the default record judge uses; the suite puts a stub there, so the network is never touched.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sut="$here/queue-gate-judge.sh"
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
pass=0; fail=0
ok()  { echo "ok: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
export GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" GIT_COMMITTER_DATE="2026-01-01T00:00:00Z"
g() { git --git-dir="$w/repo.git" "$@"; }
git init -q --bare "$w/repo.git"
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
REF="gh-readonly-queue/main/pr-12-$G2"

# stubs: the record judge answers per head from files; the main judges from one file
cat > "$w/record-judge" <<'EOF'
#!/usr/bin/env bash
echo "$1 $2" >> "$QG_LOG"
f="$QG_RC/$1"; [ -f "$f" ] && exit "$(cat "$f")"; exit 0
EOF
cat > "$w/main-judges" <<'EOF'
#!/usr/bin/env bash
echo "$1" >> "$QG_MAIN_LOG"
exit "$(cat "$QG_MAIN_RC" 2>/dev/null || echo 0)"
EOF
chmod +x "$w/record-judge" "$w/main-judges"
mkdir -p "$w/gh-down"
cat > "$w/gh-down/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh: HTTP 500: server error" >&2; exit 1
EOF
chmod +x "$w/gh-down/gh"

# exec_sut HEAD REF [ENV=VAL...]: the judge under a clean environment with the stubs; sets LAST_RC and LAST_OUT
exec_sut() {
  local head=$1 ref=$2; shift 2
  LAST_OUT="$(cd "$w" && env -i PATH="$PATH" HOME="$w" GH_TOKEN=x GITHUB_REPOSITORY=o/r \
    QUEUE_GATE_GIT_DIR="$w/repo.git" QUEUE_GATE_RECORD_JUDGE="$w/record-judge" \
    QUEUE_GATE_MAIN_JUDGES="$w/main-judges" QG_LOG="$w/log" QG_RC="$w/rc" \
    QG_MAIN_LOG="$w/mainlog" QG_MAIN_RC="$w/main.rc" "$@" bash "$sut" "$head" "$ref" 2>&1)"
  LAST_RC=$?
}
verdict() { # verdict NAME WANT(0|nz|3): judge LAST_RC against the contract
  local name=$1 want=$2 why
  why="rc $LAST_RC, want $want; $(tr '\n' ' ' <<<"$LAST_OUT" | cut -c1-120)"
  case "$want" in
    0) [ "$LAST_RC" -eq 0 ] && ok "$name" || bad "$name ($why)" ;;
    3) [ "$LAST_RC" -eq 3 ] && ok "$name" || bad "$name ($why)" ;;
    nz) if [ "$LAST_RC" -ge 1 ] && [ "$LAST_RC" -le 3 ]; then ok "$name"; else bad "$name ($why)"; fi ;;
  esac
}
reset() { rm -rf "$w/rc"; mkdir -p "$w/rc"; : > "$w/log"; : > "$w/mainlog"; rm -f "$w/main.rc"; }
run() { # run NAME WANT HEAD REF [ENV=VAL...]: a fresh state for each case
  local name=$1 want=$2 head=$3 ref=$4; shift 4
  reset; exec_sut "$head" "$ref" "$@"; verdict "$name" "$want"
}
need() { # need NAME PATTERN FILE: the file must hold a line matching the pattern
  grep -qE "$2" "$3" && ok "$1" || bad "$1 (no /$2/ in $3)"
}

[ -f "$sut" ] && ok "bin/queue-gate-judge.sh exists" || bad "bin/queue-gate-judge.sh does not exist"

# the good case first: if this fails, every refusal below is only a missing script, not a verdict
run "a two-merge group on main, every record good, main's judges good -> exit 0" 0 "$G2" "$REF"
need "each pull request head (second parent) went to the record judge with base main (pr1)" "^$P1 main\$" "$w/log"
need "each pull request head (second parent) went to the record judge with base main (pr2)" "^$P2 main\$" "$w/log"
need "main's judges ran over the queue head" "^$G2\$" "$w/mainlog"
run "a one-merge group is good too" 0 "$G1" "gh-readonly-queue/main/pr-3-$G1"

# argument validation
run "empty sha -> refused" nz "" "$REF"
run "uppercase sha -> refused" nz "$(tr a-f A-F <<<"$G2")" "$REF"
run "short sha (39 hex) -> refused" nz "${G2:0:39}" "$REF"
run "41-char sha -> refused" nz "${G2}a" "$REF"
run "non-hex sha (injection-shaped) -> refused" nz 'x;touch /tmp/pwn' "$REF"
run "ref with an extra path segment -> refused" nz "$G2" "gh-readonly-queue/main/pr-12-$G2/extra"
run "ref with a leading path segment -> refused" nz "$G2" "x/gh-readonly-queue/main/pr-12-$G2"
run "ref for another base branch -> refused" nz "$G2" "gh-readonly-queue/chain-v030/pr-12-$G2"
run "ref with a 39-hex tail -> refused" nz "$G2" "gh-readonly-queue/main/pr-12-${G2:0:39}"
run "ref with a 41-hex tail -> refused" nz "$G2" "gh-readonly-queue/main/pr-12-${G2}a"
run "ref with an uppercase tail -> refused" nz "$G2" "gh-readonly-queue/main/pr-12-$(tr a-f A-F <<<"$G2")"
run "ref with no pull request number -> refused" nz "$G2" "gh-readonly-queue/main/pr--$G2"
run "ref with a non-numeric pull request number -> refused" nz "$G2" "gh-readonly-queue/main/pr-1x-$G2"
run "ref with a trailing newline -> refused" nz "$G2" "$REF"$'\n'
run "an empty ref -> refused" nz "$G2" ""
run "a plain branch name -> refused" nz "$G2" "main"
if [ -f "$sut" ] && [ ! -s "$w/log" ]; then ok "a refused argument never reached the record judge"
else bad "a refused argument never reached the record judge"; fi

# the shape of the group
run "a group commit with ONE parent (squash or rebase shape) at the bottom -> refused" nz "$GS" \
  "gh-readonly-queue/main/pr-12-$GS"
run "a group commit with ONE parent at the head -> refused" nz "$GL" "gh-readonly-queue/main/pr-12-$GL"
run "a group commit with THREE parents below the head -> refused" nz "$GT" "gh-readonly-queue/main/pr-12-$GT"
run "a group commit with THREE parents at the head -> refused" nz "$GO" "gh-readonly-queue/main/pr-12-$GO"
run "an empty group (the head is main's tip itself) -> refused" nz "$M0" "gh-readonly-queue/main/pr-12-$M0"
NOSUCH="$(printf '1%.0s' $(seq 40))"
run "a head that is not in the repository -> refused" nz "$NOSUCH" "gh-readonly-queue/main/pr-12-$NOSUCH"
run "a base ref that does not exist -> refused" nz "$G2" "$REF" QUEUE_GATE_BASE_REF=refs/remotes/origin/nope

# the records
run_rc() { # run_rc NAME WANT PR_SHA RC: the record judge answers RC for that head
  reset; echo "$4" > "$w/rc/$3"; exec_sut "$G2" "$REF"; verdict "$1" "$2"
}
run_rc "one pull request head whose record judge exits 1 (no passing record), the other good -> refused" nz "$P1" 1
run_rc "the other pull request head's record judge exits 1 -> refused" nz "$P2" 1
run_rc "one pull request head whose record judge exits 3 (GitHub API error) -> refused, exit 3" 3 "$P1" 3
run_rc "the other head's record judge exits 3 -> refused, exit 3" 3 "$P2" 3
run_rc "a record judge exiting 2 (any other non-zero) -> refused" nz "$P2" 2
run_rc "a record judge exiting 127 -> refused" nz "$P1" 127

# the judges themselves
run "a judge stub that is missing -> refused" nz "$G2" "$REF" QUEUE_GATE_RECORD_JUDGE="$w/no-such-judge"
run "a record judge that is not executable -> refused" nz "$G2" "$REF" QUEUE_GATE_RECORD_JUDGE="$w/main.rc"
run "main's judges missing -> refused" nz "$G2" "$REF" QUEUE_GATE_MAIN_JUDGES="$w/no-such-main-judges"
reset; echo 1 > "$w/main.rc"; exec_sut "$G2" "$REF"
verdict "main's judges failing over the head, every record good -> refused" nz

# GitHub API unreadable: the real record judge with a gh that always errors (HTTP 500) exits 3, so does the verdict
reset; exec_sut "$G2" "$REF" PATH="$w/gh-down:$PATH" QUEUE_GATE_RECORD_JUDGE="$here/audit-record-judge.sh"
verdict "GitHub API unreadable (gh errors, the real record judge) -> refused" nz
reset; exec_sut "$G2" "$REF" PATH="$w/gh-down:$PATH" QUEUE_GATE_RECORD_JUDGE="$here/audit-record-judge.sh" \
  GH_TOKEN= GITHUB_REPOSITORY=
verdict "no token and no repository name in the environment (real record judge) -> refused" nz

# text-level: the script reads git objects only
if [ -f "$sut" ]; then
  if grep -qE 'git[[:space:]]+(checkout|switch|worktree|merge|pull)\b|\beval\b' "$sut"; then
    bad "the judge checks nothing out and evals nothing"
  else ok "the judge checks nothing out and evals nothing"; fi
  grep -qE 'set -[a-z]*u' "$sut" && ok "the judge runs with set -u" || bad "the judge runs with set -u"
else
  bad "the judge checks nothing out and evals nothing (no script)"; bad "the judge runs with set -u (no script)"
fi

echo "----"
echo "queue-gate-judge: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
