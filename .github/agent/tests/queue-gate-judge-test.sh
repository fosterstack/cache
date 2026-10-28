#!/usr/bin/env bash
# proves: REQ-DEP-005-AC3
# Offline fixture and mutation suite for .github/agent/bin/queue-gate-judge.sh (cache#542): the judge that the review
# gate runs, from
# the default branch's copy, over a merge queue's temporary branch, and that must fail closed. (The AC name AC3 is
# added to requirements.yaml later by the lead; it does not exist there yet.)
#
# THE CONTRACT this suite pins (the coder writes .github/agent/bin/queue-gate-judge.sh to it):
#   .github/agent/bin/queue-gate-judge.sh HEAD_SHA REF
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
# Programs: the script names NO program through a variable (the repo's pin checker refuses that). It runs from the
#   repository root (the current directory, as the workflows run it) and calls, as literal command lines, the same
#   ones the judge job of agent-review-gate.yml runs:
#     bash bin/audit-record-judge.sh PR_HEAD_SHA main                       (once per second parent)
#     python3 -I .github/agent/bin/check-action-pins.py --verify-tags --git HEAD_SHA
#     git ls-tree -r -z --name-only HEAD_SHA | GITHUB_BASE_REF=main ALLOWLIST_NUL=1 ALLOWLIST_HEAD_REV=HEAD_SHA
#         bash bin/check-file-allowlist.sh
#     PYTHONPATH=<dir holding yaml -> .github/agent/fixtures/testlib/pyyaml> PIN_WIRING_JUDGE_GIT=HEAD_SHA
#         bash .github/agent/tests/pin-wiring-test.sh
#     PYTHONPATH=<same> SCAN_GUARD_JUDGE_GIT=HEAD_SHA bash bin/scan-no-workflow-call-test.sh
#   The suite builds a fixture tree in a temp dir (.github/agent/bin/queue-gate-judge.sh copied in, STUBS at those
#   literal paths) and
#   runs the script with that tree as the current directory. A missing judge file is a refusal (exit 1), never 126/127.
# Environment: GH_TOKEN, GITHUB_REPOSITORY go to the record judge. Two test seams, both plain VALUES used as data:
#   QUEUE_GATE_GIT_DIR            the git directory holding the group's objects (default: the current repository's)
#   QUEUE_GATE_BASE_REF           the ref naming the default branch's tip, the group's base (default
#                                 refs/remotes/origin/main); the walk is `rev-list --first-parent BASE..HEAD`
#   There is no seam that names a program. A `gh` on PATH is what the real record judge uses; the suite puts a stub
#   there, so the network is never touched.
# The suite also runs the repo's pin checker over a tree holding the script and a workflow step that runs it: no
# finding.
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

# the fixture tree: the script under test and STUBS at the literal paths it calls, run with the tree as cwd
root="$w/root"
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
echo "allow $GITHUB_BASE_REF $ALLOWLIST_NUL $ALLOWLIST_HEAD_REV" >> "$QG_MAIN_LOG"
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
variant() { # variant NAME: a copy of the fixture tree to damage; prints its path
  rm -rf "$w/v-$1"; cp -a "$root" "$w/v-$1"; echo "$w/v-$1"
}

# exec_sut HEAD REF [ENV=VAL...]: the judge under a clean environment, cwd = the fixture tree ($ROOT, default $root)
exec_sut() {
  local head=$1 ref=$2; shift 2
  LAST_OUT="$(cd "${ROOT:-$root}" && env -i PATH="$PATH" HOME="$w" GH_TOKEN=x GITHUB_REPOSITORY=o/r \
    QUEUE_GATE_GIT_DIR="$w/repo.git" QG_LOG="$w/log" QG_RC="$w/rc" \
    QG_MAIN_LOG="$w/mainlog" QG_MRC="$w/mrc" "$@" bash .github/agent/bin/queue-gate-judge.sh "$head" "$ref" 2>&1)"
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
reset() { rm -rf "$w/rc" "$w/mrc"; mkdir -p "$w/rc" "$w/mrc"; : > "$w/log"; : > "$w/mainlog"; ROOT=; }
run() { # run NAME WANT HEAD REF [ENV=VAL...]: a fresh state for each case
  local name=$1 want=$2 head=$3 ref=$4; shift 4
  reset; exec_sut "$head" "$ref" "$@"; verdict "$name" "$want"
}
need() { # need NAME PATTERN FILE: the file must hold a line matching the pattern
  grep -qE "$2" "$3" && ok "$1" || bad "$1 (no /$2/ in $3)"
}

[ -f "$sut" ] && ok ".github/agent/bin/queue-gate-judge.sh exists" \
  || bad ".github/agent/bin/queue-gate-judge.sh does not exist"

# the good case first: if this fails, every refusal below is only a missing script, not a verdict
run "a two-merge group on main, every record good, main's judges good -> exit 0" 0 "$G2" "$REF"
need "each pull request head (second parent) went to the record judge with base main (pr1)" "^$P1 main\$" "$w/log"
need "each pull request head (second parent) went to the record judge with base main (pr2)" "^$P2 main\$" "$w/log"
need "main's pin checker ran over the queue head (--verify-tags --git)" "^pins --verify-tags --git $G2\$" "$w/mainlog"
need "main's allowlist guard ran over the queue head (NUL list, head rev, base main)" "^allow main 1 $G2\$" "$w/mainlog"
need "main's pin-wiring judge ran over the queue head, with the yaml shim" "^wiring $G2 yaml=1\$" "$w/mainlog"
need "main's scanner guard ran over the queue head, with the yaml shim" "^scan $G2 yaml=1\$" "$w/mainlog"
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
reset; ROOT="$(variant norecord)"; rm -f "$ROOT/bin/audit-record-judge.sh"; exec_sut "$G2" "$REF"
verdict "a record judge that is missing from the tree -> refused" nz
reset; ROOT="$(variant dirrecord)"; rm -f "$ROOT/bin/audit-record-judge.sh"; mkdir "$ROOT/bin/audit-record-judge.sh"
exec_sut "$G2" "$REF"; verdict "a record judge that is not a file (a directory) -> refused, not 126" nz
reset; ROOT="$(variant nowiring)"; rm -f "$ROOT/.github/agent/tests/pin-wiring-test.sh"; exec_sut "$G2" "$REF"
verdict "a main judge (pin-wiring) missing from the tree -> refused" nz
run_main() { # run_main NAME JUDGE: that one main judge exits 1, every record good
  reset; echo 1 > "$w/mrc/$2"; exec_sut "$G2" "$REF"; verdict "$1" nz
}
run_main "main's pin checker failing over the head, every record good -> refused" pins
run_main "main's allowlist guard failing over the head -> refused" allow
run_main "main's pin-wiring judge failing over the head -> refused" wiring
run_main "main's scanner guard failing over the head -> refused" scan

# GitHub API unreadable: the real record judge with a gh that always errors (HTTP 500) exits 3, so does the verdict
reset; ROOT="$(variant realrecord)"
cp "$repo/bin/audit-record-judge.sh" "$repo/bin/audit-record.py" "$ROOT/bin/"
exec_sut "$G2" "$REF" PATH="$w/gh-down:$PATH"
verdict "GitHub API unreadable (gh errors, the real record judge) -> refused" nz
exec_sut "$G2" "$REF" PATH="$w/gh-down:$PATH" GH_TOKEN= GITHUB_REPOSITORY=
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

# the script names no program through a variable: the repo's own pin checker, run over a tree holding the script, the
# files it calls (the real ones) and a workflow step that runs it, finds nothing (the gate workflow itself is not in
# this tree; its "missing" line is the one finding allowed)
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
      - run: bash .github/agent/bin/queue-gate-judge.sh "$HEAD_SHA" "$HEAD_BRANCH"
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
