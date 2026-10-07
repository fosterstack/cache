#!/usr/bin/env bash
# Regression tests for bin/check-file-allowlist.sh — in particular the branch
# scoping of the daily CVE auditor's suppression outputs (.snyk,
# osv-scanner.toml, .auditor/accepted-items.json): allowed only on the auditor/
# lane and on main, blocked on any other branch, and never a hole through which
# private-side content can reach this PUBLIC repo.
# Known limit (by design): a PR that changes ALLOW_PATTERNS / SUPPRESSION_PATTERNS in the script cannot pass
# this check before merge on its own account, because the trusted gate judges it with main's copy of the script.
set -uo pipefail
cd "$(dirname "$0")/.."
SCRIPT=./bin/check-file-allowlist.sh

pass=0; fail=0
gp() { echo "ok:   $1"; pass=$((pass+1)); }
gf() { echo "FAIL: $1 — $2"; fail=$((fail+1)); }
# run <expect pass|fail> <branch-env> <description> <paths...>
run() {
  local expect="$1"; local ref="$2"; local desc="$3"; shift 3
  local out rc
  out="$(printf '%s\n' "$@" | GITHUB_HEAD_REF="$ref" GITHUB_REF_NAME="" GITHUB_REPOSITORY=o/r GITHUB_HEAD_REPO="${HEADREPO-o/r}" "$SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
# same, but drive GITHUB_REF_NAME (the push path) instead of a PR head ref
run_ref() {
  local expect="$1"; local ref="$2"; local desc="$3"; shift 3
  local out rc
  out="$(printf '%s\n' "$@" | GITHUB_HEAD_REF="" GITHUB_REF_NAME="$ref" "$SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}

SUPP=(".snyk" "osv-scanner.toml" ".auditor/accepted-items.json"
      # REQ-AUD-16: the generated knowledge doc (AC3) and merge-gated proposals (AC4) the auditor
      # carries in its own suppression PR.
      ".auditor/knowledge.md" ".auditor/proposals/adjudicator-proposals.json")

# GITHUB_HEAD_REF is only a branch NAME: auditor/* on a pull_request is the auditor lane only when the
# head repository IS this repository (GITHUB_HEAD_REPO == GITHUB_REPOSITORY). `main` is special only on
# a push event, never as a PR head. A fork can name its branch anything.
HEADREPO=fork/r
run fail "auditor/zzz" "FORK PR from auditor/zzz: suppression outputs blocked" "${SUPP[@]}"
run fail "main"        "FORK PR from main: suppression outputs blocked"        "${SUPP[@]}"
HEADREPO=
run fail "auditor/zzz" "PR with the head repo empty: fails closed"             "${SUPP[@]}"
HEADREPO=o/r
run fail "main"        "same-repo PR from a branch named main: not special (only a push to main is)" "${SUPP[@]}"
unset HEADREPO
run pass "auditor/zzz" "same-repo PR from auditor/zzz: allowed as today" "${SUPP[@]}"
( printf '%s\n' .snyk | GITHUB_HEAD_REF=auditor/zzz GITHUB_REF_NAME="" GITHUB_REPOSITORY=o/r "$SCRIPT" >/dev/null 2>&1 ) \
  && { echo "FAIL: head-repo variable unset on a PR event must fail closed"; fail=$((fail+1)); } \
  || { echo "ok:   head-repo variable unset on a PR event fails closed"; pass=$((pass+1)); }

# The auditor lane may introduce/change its suppression outputs.
run pass "auditor/2026-09-24-abc123"      "auditor/ PR head: suppression outputs allowed"      "${SUPP[@]}"
run pass "auditor/proof-2026-09-24-abc12" "auditor/ proof PR head: suppression outputs allowed" "${SUPP[@]}"
# The merged state on main keeps them (scanners read them; release-authz reads the inventory).
run_ref pass "main" "push to main: suppression outputs allowed" "${SUPP[@]}"
# No other branch may add or edit a suppression (can't slip one past a scanner via a feature PR).
run fail "feature/x"        "feature PR head: suppression outputs blocked"      "${SUPP[@]}"
run fail "renovate/deps"    "bot PR head: suppression outputs blocked"          "${SUPP[@]}"
run fail "auditorX/nope"    "look-alike prefix (not auditor/): blocked"         ".snyk"
# The private-content guard is intact even on the auditor lane.
run fail "auditor/2026-09-24-abc123" "auditor/ lane does NOT open a hole for ops/brief content" "ops/runbook.md"
run fail "auditor/2026-09-24-abc123" "auditor/ lane does NOT allow arbitrary root files"        "secrets.txt"
# Ordinary product files still pass regardless of branch.
run pass "feature/x" "product Go source still allowed off the auditor lane" "internal/cache/store.go"

# --- Unchanged-suppression rule (non-auditor, non-main branches) -------------------------------
# CI checks the WHOLE tree, so a suppression file already on main is in the tree of every PR. The rule
# is "a feature PR cannot ADD or CHANGE a suppression", not "cannot contain one": on any other branch
# a suppression path passes only if it exists at the merge base with the base branch and is identical
# there (content and mode). Base = $GITHUB_BASE_REF, else origin/main. Unresolvable => fail closed.
ABS_SCRIPT="$(pwd)/bin/check-file-allowlist.sh"
TMPROOT="$(mktemp -d)"; trap 'rm -rf "$TMPROOT"' EXIT
g() { git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }
# mkrepo <dir>: a repo whose origin/main holds .auditor/panel-state.json and .snyk, on branch feature/x
mkrepo() {
  local d="$1"
  rm -rf "$d"; mkdir -p "$d/.auditor"; ( cd "$d" && g init -q -b main . \
    && echo '{"a":1}' > .auditor/panel-state.json && echo 'ignore: {}' > .snyk && echo 'package x' > internal.go \
    && g add -A && g commit -q -m base \
    && g update-ref refs/remotes/origin/main HEAD && g checkout -q -b feature/x )
}
# trun <expect> <desc> <dir> <head-ref> <base-ref-or-empty> <paths...> : run the script inside <dir>
trun() {
  local expect="$1" desc="$2" dir="$3" head="$4" base="$5"; shift 5
  local out rc
  out="$(cd "$dir" && printf '%s\n' "$@" | GITHUB_HEAD_REF="$head" GITHUB_REF_NAME="" GITHUB_BASE_REF="$base" GITHUB_REPOSITORY=o/r GITHUB_HEAD_REPO="${HEADREPO-o/r}" "$ABS_SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
PS=.auditor/panel-state.json
R="$TMPROOT/r"

mkrepo "$R"
trun pass "feature: suppression files untouched since the merge base are allowed" "$R" feature/x "" "$PS" .snyk
# an unrelated commit on the feature branch does not disturb them
( cd "$R" && mkdir -p internal && echo 'package y' > internal/other.go && g add -A && g commit -q -m other )
trun pass "feature: unrelated commit, suppression files still untouched" "$R" feature/x "" "$PS" .snyk internal/other.go

( cd "$R" && echo '{"a":2}' > $PS && g commit -qam edit )
trun fail "feature: edited suppression file is blocked" "$R" feature/x "" "$PS"
trun pass "feature: the other, untouched suppression file is still allowed" "$R" feature/x "" .snyk

mkrepo "$R"; ( cd "$R" && echo 'x' > osv-scanner.toml && g add -A && g commit -q -m add )
trun fail "feature: newly added suppression file (not on main) is blocked" "$R" feature/x "" osv-scanner.toml

mkrepo "$R"; ( cd "$R" && g rm -q .snyk && g commit -qm del && echo 'ignore: {}' > .snyk && g add .snyk && g commit -qm readd )
trun pass "feature: deleted then re-added with identical content is allowed" "$R" feature/x "" .snyk
mkrepo "$R"; ( cd "$R" && g rm -q .snyk && g commit -qm del && echo 'ignore: {evil: 1}' > .snyk && g add .snyk && g commit -qm readd )
trun fail "feature: deleted then re-added with different content is blocked" "$R" feature/x "" .snyk

mkrepo "$R"; ( cd "$R" && chmod +x .snyk && g add .snyk && g commit -qm mode )
trun fail "feature: mode change only is blocked" "$R" feature/x "" .snyk

mkrepo "$R"; ( cd "$R" && g update-ref -d refs/remotes/origin/main )
trun fail "feature: base ref missing fails closed" "$R" feature/x "" "$PS"
trun pass "feature: base ref missing, non-suppression files unaffected" "$R" feature/x "" internal/x.go
mkrepo "$R"
trun fail "feature: GITHUB_BASE_REF naming a ref that does not exist fails closed" "$R" feature/x "nope" "$PS"
trun fail "feature: GITHUB_BASE_REF with option-like value fails closed" "$R" feature/x "--help" "$PS"
# GITHUB_BASE_REF honoured: origin/rel differs from origin/main
( cd "$R" && g checkout -q -b rel && echo '{"a":9}' > $PS && g commit -qam rel && g update-ref refs/remotes/origin/rel HEAD && g checkout -q feature/x )
trun pass "feature: base ref defaults to origin/main (unchanged vs main)" "$R" feature/x "" "$PS"
( cd "$R" && g checkout -q -b feat2 refs/remotes/origin/rel )
trun pass "feature: GITHUB_BASE_REF=rel honoured (unchanged vs rel)" "$R" feat2 rel "$PS"
trun fail "feature: with default base, the same file differs from origin/main" "$R" feat2 "" "$PS"
( cd "$R" && g checkout -q feature/x )

# unrelated history: no merge base => fail closed
mkrepo "$R"; ( cd "$R" && g checkout -q --orphan lone && g rm -rqf . && mkdir -p .auditor && echo '{"a":1}' > $PS && g add -A && g commit -qm lone )
trun fail "feature: no merge base with the base ref fails closed" "$R" lone "" "$PS"

# a shallow clone cannot resolve the merge base => fail closed
mkrepo "$R"; ( cd "$R" && mkdir -p internal && echo 'package z' > internal/z.go && g add -A && g commit -qm z )
SH="$TMPROOT/sh"; rm -rf "$SH"; g clone -q --depth 1 "file://$R" "$SH" 2>/dev/null
BASESHA="$(cd "$R" && git rev-parse HEAD~1)"
( cd "$SH" && g fetch -q --depth 1 origin "$BASESHA":refs/remotes/origin/main )
trun fail "feature: shallow clone without a resolvable merge base fails closed" "$SH" feature/x "" "$PS"

# move / copy of a suppression file to another suppression-pattern path: the new path is not at the
# merge base, so it is a change (judged on the PR's own changes, not on the tree). The old path of a
# move is deleted and is simply not listed, so it is not an error.
mkrepo "$R"; ( cd "$R" && mkdir -p .auditor/proposals && echo '{"p":1}' > .auditor/proposals/a.json && g add -A && g commit -qm a && g update-ref refs/remotes/origin/main HEAD )
( cd "$R" && g mv .auditor/proposals/a.json .auditor/proposals/b.json && g commit -qm mv )
trun fail "feature: move of a suppression file to another suppression path is blocked" "$R" feature/x "" .auditor/proposals/b.json
trun pass "feature: the deleted old path of a move is not listed and not an error" "$R" feature/x "" "$PS" .snyk
mkrepo "$R"; ( cd "$R" && mkdir -p .auditor/proposals && echo '{"p":1}' > .auditor/proposals/a.json && g add -A && g commit -qm a && g update-ref refs/remotes/origin/main HEAD \
  && cp .auditor/proposals/a.json .auditor/proposals/b.json && g add -A && g commit -qm cp )
trun fail "feature: copy of a suppression file to another suppression path is blocked" "$R" feature/x "" .auditor/proposals/a.json .auditor/proposals/b.json
mkrepo "$R"; ( cd "$R" && cp .snyk osv-scanner.toml && g add -A && g commit -qm cp )
trun fail "feature: .snyk content copied to osv-scanner.toml is blocked" "$R" feature/x "" .snyk osv-scanner.toml

mkrepo "$R"; ( cd "$R" && echo '{"a":5}' > $PS && g commit -qam edit )
HEADREPO=fork/r
trun fail "fork PR from auditor/x with an edited suppression file is blocked" "$R" auditor/x "" "$PS"
trun fail "fork PR from main with an edited suppression file is blocked" "$R" main "" "$PS"
unset HEADREPO

# judging a COMMIT instead of the checkout (the trusted review gate runs main's copy of this script over a
# PR head it only has as git objects): ALLOWLIST_HEAD_REV=<full sha> replaces HEAD and the index. The
# checkout (HEAD) is main here, and must not leak into the verdict.
revrun() {  # revrun <expect> <desc> <rev> <paths...>   (cwd $R, checked out on main)
  local expect="$1" desc="$2" rev="$3"; shift 3
  local out rc
  out="$(cd "$R" && printf '%s\n' "$@" | GITHUB_HEAD_REF=feature/x GITHUB_REF_NAME="" GITHUB_BASE_REF=main GITHUB_REPOSITORY=o/r GITHUB_HEAD_REPO=o/r ALLOWLIST_HEAD_REV="$rev" "$ABS_SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
mkrepo "$R"; ( cd "$R" && echo 'package q' > q.go && g add -A && g commit -qm same )
SAME="$(cd "$R" && git rev-parse HEAD)"
( cd "$R" && echo '{"a":6}' > $PS && echo x > osv-scanner.toml && g add -A && g commit -qm chg )
CHG="$(cd "$R" && git rev-parse HEAD)"
( cd "$R" && g checkout -q main )
revrun pass "rev: untouched suppression files at the PR head pass (checkout is main)" "$SAME" "$PS" .snyk
revrun fail "rev: edited suppression file at the PR head is blocked" "$CHG" "$PS"
revrun fail "rev: new suppression file at the PR head is blocked" "$CHG" osv-scanner.toml
revrun pass "rev: the other untouched file at that head still passes" "$CHG" .snyk
revrun fail "rev: a rev that is not a full hex sha fails closed" "main" "$PS"
revrun fail "rev: a hex sha that is not a commit fails closed" "0000000000000000000000000000000000000000" "$PS"
revrun fail "rev: an option-like rev fails closed" "--help" "$PS"
revrun fail "rev: private content is still blocked" "$SAME" ops/runbook.md

# criss-cross history: two merge bases; the file must be unchanged against EVERY one of them
mkrepo "$R"
( cd "$R" && g checkout -q -b A1 main && echo '{"a":7}' > $PS && g commit -qam a1 \
  && g checkout -q -b B1 main && echo b > other-b.go && g add -A && g commit -qm b1 \
  && g checkout -q -b A2 A1 && g merge -q --no-edit B1 \
  && g checkout -q -b B2 B1 && g merge -q --no-edit A1 \
  && g update-ref refs/remotes/origin/main B2 && g checkout -q A2 )
[ "$(cd "$R" && git merge-base --all HEAD origin/main | wc -l | tr -d ' ')" = 2 ] && gp "criss-cross fixture really has two merge bases" || gf "criss-cross fixture" "expected two merge bases"
# whichever base git would pick alone, one of the two bases has the other content: ensure the single-base pick
# is the base whose content EQUALS the head's, so only checking every base can block
PICK="$(cd "$R" && git merge-base HEAD origin/main)"
( cd "$R" && git cat-file -p "$PICK:$PS" | cmp -s - "$PS" ) && gp "criss-cross: the single-base pick equals the head (only --all can block)" || gf "criss-cross pick" "pick differs from head; reorder the fixture"
trun fail "criss-cross: file equal to one merge base but not the other is blocked" "$R" feature/x "" "$PS"
trun pass "criss-cross: a file identical in every merge base is allowed" "$R" feature/x "" .snyk

# NUL-delimited input (ALLOWLIST_NUL=1, for `git ls-tree -z`): a path containing a newline is ONE path, not two
# allowed ones; without the variable the line-oriented behaviour is unchanged
nul() {  # nul <expect> <desc> <env NUL value or empty> <printf format> <args...>
  local expect="$1" desc="$2" nulv="$3" fmt="$4"; shift 4
  local out rc
  out="$(printf "$fmt" "$@" | GITHUB_HEAD_REF=feature/x GITHUB_REF_NAME="" GITHUB_REPOSITORY=o/r ALLOWLIST_NUL="$nulv" "$SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
nul pass "nul: ordinary NUL-delimited list passes" 1 'internal/a.go\0README.md\0'
nul pass "nul: last record without a terminator passes" 1 'internal/a.go\0README.md'
nul fail "nul: one path with an embedded newline is one (blocked) path" 1 'internal/a.go\nREADME.md\0'
nul pass "no ALLOWLIST_NUL: the same bytes split on newlines as before" "" 'internal/a.go\nREADME.md\n'
nul fail "nul: a disallowed path in the list is blocked" 1 'internal/a.go\0ops/runbook.md\0'

# git pathspecs are literal (GIT_LITERAL_PATHSPECS=1): the script's own git calls never glob a path
mkdir -p "$TMPROOT/shim"
cat > "$TMPROOT/shim/git" <<EOS
#!/bin/sh
echo "\${GIT_LITERAL_PATHSPECS:-unset}" >> "$TMPROOT/literal.log"
exec $(command -v git) "\$@"
EOS
chmod +x "$TMPROOT/shim/git"
mkrepo "$R"; : > "$TMPROOT/literal.log"
( cd "$R" && printf '%s\n' "$PS" | PATH="$TMPROOT/shim:$PATH" GITHUB_HEAD_REF=feature/x GITHUB_REPOSITORY=o/r "$ABS_SCRIPT" >/dev/null 2>&1 )
if [ -s "$TMPROOT/literal.log" ] && ! grep -qv '^1$' "$TMPROOT/literal.log"; then gp "every git call runs with GIT_LITERAL_PATHSPECS=1"; else gf "literal pathspecs" "log: $(sort -u "$TMPROOT/literal.log" | tr '\n' ' ')"; fi

# other branches keep today's behaviour
mkrepo "$R"; ( cd "$R" && echo '{"a":3}' > $PS && g commit -qam edit )
trun pass "auditor/x branch: edited suppression file allowed (unchanged behaviour)" "$R" auditor/x "" "$PS"
trun fail "main as PR head is not the feature rule: private content still blocked" "$R" auditor/x "" ops/runbook.md
( cd "$R" && out="$(printf '%s\n' "$PS" | GITHUB_HEAD_REF="" GITHUB_REF_NAME=main "$ABS_SCRIPT" 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] ) && gp "push to main: edited suppression file allowed (unchanged behaviour)" || gf "push to main allowed" "rc!=0"
trun fail "feature: non-suppression unlisted file still blocked" "$R" feature/x "" ops/runbook.md
trun fail "feature: edited suppression plus unlisted file reports failure" "$R" feature/x "" "$PS" secrets.txt
# pre-commit usage: no env at all, local branch name, staged change compared with the merge base
mkrepo "$R"
( cd "$R" && printf '%s\n' "$PS" .snyk | env -u GITHUB_HEAD_REF -u GITHUB_REF_NAME -u GITHUB_BASE_REF -u GITHUB_REPOSITORY -u GITHUB_HEAD_REPO "$ABS_SCRIPT" >/dev/null 2>&1 ) \
  && gp "pre-commit usage (no env, local feature branch): untouched suppression files pass" || gf "pre-commit untouched" "rc!=0"
( cd "$R" && echo '{"a":4}' > $PS && g add $PS && printf '%s\n' "$PS" | env -u GITHUB_HEAD_REF -u GITHUB_REF_NAME -u GITHUB_BASE_REF -u GITHUB_REPOSITORY -u GITHUB_HEAD_REPO "$ABS_SCRIPT" >/dev/null 2>&1 ) \
  && gf "pre-commit staged edit" "should have been blocked" || gp "pre-commit usage: staged edit of a suppression file is blocked"

# The reserved-branch guard: only the delivery App may push the auditor/* lane (the allowlist
# relaxes suppression paths there), so a dev branch can never use it to slip a suppression past.
GUARD=.github/workflows/reserved-branch-guard.yml
if [ -f "$GUARD" ]; then
  gp "reserved-branch guard workflow present"
  if grep -qE "auditor/\*\*" "$GUARD" && grep -qE "^\s*push:" "$GUARD"; then
    gp "guard triggers on push to auditor/*"
  else gf "guard triggers on push to auditor/*" "missing push:auditor/** trigger"; fi
  if grep -q "fosterstack-automation" "$GUARD" && grep -qE "exit 1" "$GUARD"; then
    gp "guard rejects any pusher that is not the delivery App"
  else gf "guard gates on the App actor and fails closed" "missing App-actor check / exit 1"; fi
else
  gf "reserved-branch guard workflow present" "$GUARD missing"
fi

echo "----"
echo "check-file-allowlist: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
