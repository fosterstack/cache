#!/usr/bin/env bash
# proves: REQ-REL-004-AC4
# proves: REQ-REL-004-AC8
# Regression for bin/go-bump-open-pr.sh (audit R03; owner Oct 2, advisor 0052/0055; signed commits, advisor 0623): the PR-open decision must
# distinguish open / merged / closed-not-merged / orphaned-branch / fresh, RECOVER an orphaned branch by creating the
# PR, and open it only as a DRAFT. A fresh bump never runs `git commit`: the branch is pushed at the commit the job started from, the one
# commit is made through the API (createCommitOnBranch, signed for the App's token), the API is asked whether it is verified, and a commit
# that is not verified, an API call that fails or an id that is not a commit id deletes the branch and opens no PR (REQ-REL-004-AC8). gh and git
# are STRICT mocks (Codex #157 r1): every call is recorded, the exact call sequence and exit status are asserted per path, both modules' go
# directives are checked, the commit request the API receives is checked byte for byte, and any call outside the allowed set fails the case.
# Mutants of the script (ready + auto-merge appended; a denied create; a git commit; an unchecked verification) must be caught. The last
# section is the repository-wide guard: nothing outside the tests may run git commit, git commit-tree or git merge.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
pass=0; fail=0
B=chore/go-1.27.0
BASE=0123456789abcdef0123456789abcdef01234567
OID=89abcdef0123456789abcdef0123456789abcdef
LIST="gh pr list --head $B --base main --state all --json number,state,mergedAt"
LSR="git ls-remote --exit-code --heads origin $B"
CREATE="gh pr create --draft --base main --head $B --title chore(go): bump toolchain 1.26.6 -> 1.27.0 --body <body> --label dependencies"
REVP="git rev-parse HEAD"
PUSH="git push origin ${BASE}:refs/heads/${B}"
COMMIT="gh api graphql --input <input> -q .data.createCommitOnBranch.commit.oid"
VERIFY="gh api repos/{owner}/{repo}/commits/${OID} -q .commit.verification.verified"
DEL="git push origin --delete ${B}"
FRESH_OK="$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$VERIFY"

# run_case name sut prs branch_exists create_rc want_rc want_calls want_directive(new|old) [graphql ok|fail|badoid] [verified true|false|fail] [check_input 0|1]
run_case() {
  local name="$1" sut="$2" prs="$3" branch_exists="$4" create_rc="$5" want_rc="$6" want_calls="$7" want_dir="$8"
  local gql="${9:-ok}" ver="${10:-true}" chk="${11:-0}"
  local work; work="$(mktemp -d)"
  printf 'module x\n\ngo 1.26.6\n' > "$work/go.mod"
  mkdir -p "$work/tools/requirements"; printf 'module x/t\n\ngo 1.26.6\n' > "$work/tools/requirements/go.mod"
  mkdir -p "$work/bin"; local log="$work/calls"; : > "$log"
  cat > "$work/bin/gh" <<GH
#!/usr/bin/env bash
args=(); skip=0; inp=0
for a in "\$@"; do
  if [ \$inp = 1 ]; then cp "\$a" "${work}/input.json"; args+=("<input>"); inp=0; continue; fi
  if [ \$skip = 1 ]; then args+=("<body>"); skip=0; continue; fi
  [ "\$a" = --body ] && skip=1; [ "\$a" = --input ] && inp=1; args+=("\$a")
done
echo "gh \${args[*]}" >> "${log}"
case "\$1 \$2" in
  "pr list") printf '%s' '${prs}' ;;
  "pr create") [ "${create_rc}" = 0 ] && echo "https://example/pr/1"; exit ${create_rc} ;;
  "api graphql") case "${gql}" in ok) echo ${OID} ;; badoid) echo "not-an-oid" ;; fail) echo "HTTP 502" >&2; exit 1 ;; esac ;;
  "api repos/{owner}/{repo}/commits/${OID}") case "${ver}" in true) echo true ;; false) echo false ;; fail) exit 1 ;; esac ;;
  *) echo "UNEXPECTED gh \$*" >> "${log}"; exit 0 ;;
esac
GH
  cat > "$work/bin/git" <<GIT
#!/usr/bin/env bash
echo "git \$*" >> "${log}"
case "\$1" in
  ls-remote) [ "${branch_exists}" = 1 ] && exit 0 || exit 2 ;;
  rev-parse) echo ${BASE} ;;
  push) exit 0 ;;
  *) echo "UNEXPECTED git \$*" >> "${log}"; exit 0 ;;
esac
GIT
  chmod +x "$work/bin/gh" "$work/bin/git"
  local out rc
  out="$(cd "$work" && PATH="$work/bin:$PATH" AUDITOR_APP_SLUG=fosterstack-auditor bash "$sut" 1.26.6 1.27.0 2>&1)"; rc=$?
  local got; got="$(cat "$log")"
  local want="$want_calls"
  local dir_root dir_tools; dir_root=$(awk '/^go /{print $2}' "$work/go.mod"); dir_tools=$(awk '/^go /{print $2}' "$work/tools/requirements/go.mod")
  local wd=1.27.0; [ "$want_dir" = old ] && wd=1.26.6
  local why=""
  [ "$rc" = "$want_rc" ] || why+=" rc=$rc want $want_rc;"
  [ "$got" = "$want" ] || why+=" calls differ;"
  grep -q UNEXPECTED <<<"$got" && why+=" an unexpected call;"
  # a bump that never reached a created PR may leave the working tree bumped; only a fresh success has a fixed expectation
  [ "$want_dir" = skip ] || { [ "$dir_root" = "$wd" ] && [ "$dir_tools" = "$wd" ] || why+=" go directives $dir_root/$dir_tools want $wd;"; }
  if [ "$chk" = 1 ]; then
    # the request the API receives: this branch, this base, no deletions, exactly the two bumped files' bytes, a headline, no author override
    jq -e --arg b "$B" --arg base "$BASE" --arg r "$(base64 < "$work/go.mod" | tr -d '\n')" --arg t "$(base64 < "$work/tools/requirements/go.mod" | tr -d '\n')" '
      .variables.input as $i
      | $i.branch.branchName == $b and $i.expectedHeadOid == $base
        and ($i.message.headline | startswith("chore(go): bump toolchain 1.26.6 -> 1.27.0"))
        and (($i.fileChanges | keys) == ["additions"])
        and ($i.fileChanges.additions | map(.path) | sort) == ["go.mod", "tools/requirements/go.mod"]
        and ($i.fileChanges.additions | map({(.path): .contents}) | add) == {"go.mod": $r, "tools/requirements/go.mod": $t}
        and ($i | has("author") | not)' "$work/input.json" >/dev/null 2>&1 || why+=" the commit request is not exactly the two bumped files;"
  fi
  rm -rf "$work"
  if [ -z "$why" ]; then echo "ok: ${name}"; pass=$((pass+1)); return 0; fi
  echo "FAIL: ${name}:${why}"; diff <(echo "$want") <(echo "$got") | sed 's/^/    /'; echo "$out" | sed 's/^/    | /'; fail=$((fail+1)); return 1
}
SUT="$here/go-bump-open-pr.sh"
run_case "open PR -> dedup, nothing else"           "$SUT" '[{"number":42,"state":"OPEN","mergedAt":null}]' 1 0 0 "$LIST" old
run_case "merged PR -> landed, nothing else"        "$SUT" '[{"number":40,"state":"MERGED","mergedAt":"2026-09-01T00:00:00Z"}]' 1 0 0 "$LIST" old
run_case "closed-not-merged -> respected"           "$SUT" '[{"number":41,"state":"CLOSED","mergedAt":null}]' 1 0 0 "$LIST" old
run_case "orphaned branch -> draft PR, no push, no commit" "$SUT" '[]' 1 0 0 "$LIST"$'\n'"$LSR"$'\n'"$CREATE" old
run_case "fresh -> both modules bumped, one API commit verified, draft PR (REQ-REL-004-AC8)" \
                                                     "$SUT" '[]' 0 0 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE" new ok true 1
run_case "a denied create fails the run (42)"        "$SUT" '[]' 1 42 42 "$LIST"$'\n'"$LSR"$'\n'"$CREATE" old
run_case "AC8: a commit the API does not report verified -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL" skip ok false
run_case "AC8: the verification question failing -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL" skip ok fail
run_case "AC8: the commit API failing -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$DEL" skip fail
run_case "AC8: an id that is not a commit id -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$DEL" skip badoid

# the harness must catch these mutants of the script (each counted as a pass only when it is caught)
mut="$(mktemp)"; trap 'rm -f "$mut"' EXIT
mutant() {
  local name="$1"; shift
  if run_case "$@" >/dev/null 2>&1; then echo "FAIL: mutant not caught: $name"; fail=$((fail+1)); pass=$((pass-1))
  else echo "ok: mutant caught: $name"; pass=$((pass+1)); fail=$((fail-1)); fi
}
FRESH_CASE=('[]' 0 0 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE" new ok true 1)
{ cat "$SUT"; printf '\ngh pr ready "$branch"\ngh pr merge --squash --auto "$branch"\n'; } > "$mut"
mutant "draft readied and auto-merge armed" "draft readied and auto-merge armed" "$mut" "${FRESH_CASE[@]}"
sed 's/gh pr create --draft /gh pr create /' "$SUT" > "$mut"
mutant "not a draft" "not a draft" "$mut" '[]' 1 0 0 "$LIST"$'\n'"$LSR"$'\n'"$CREATE" old
sed 's/--label dependencies$/--label dependencies || true/' "$SUT" > "$mut"; grep -q 'dependencies || true' "$mut" || { echo "FAIL: mutant not built"; fail=$((fail+1)); }
mutant "a denied create swallowed" "a denied create swallowed" "$mut" '[]' 1 42 42 "$LIST"$'\n'"$LSR"$'\n'"$CREATE" old
sed 's#for f in go.mod tools/requirements/go.mod; do#for f in go.mod; do#' "$SUT" > "$mut"
mutant "only one module bumped" "only one module bumped" "$mut" "${FRESH_CASE[@]}"
{ cat "$SUT"; printf '\ngit commit -q -m x\n'; } > "$mut"
mutant "a git commit added" "a git commit added" "$mut" "${FRESH_CASE[@]}"
sed 's/\[ "\$ver" = true \]/true/' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (verification)"; fail=$((fail+1)); }
mutant "the verification result ignored" "the verification result ignored" "$mut" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL" skip ok false
sed 's/ --delete / /' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (delete)"; fail=$((fail+1)); }
mutant "the branch is left behind on failure" "the branch is left behind on failure" "$mut" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL" skip ok false
sed 's/expectedHeadOid/expectedHead/' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (lease)"; fail=$((fail+1)); }
mutant "the commit is not leased on the base" "the commit is not leased on the base" "$mut" "${FRESH_CASE[@]}"

# AC8, the repository guard: no workflow, composite action or script outside the tests makes a commit with git (git commit, git commit-tree, git merge).
# Every PR-opening bot makes its commit through the API instead, so GitHub signs it. A match is allowed only in the exact (file, line) rows below,
# each a test fixture that builds a throwaway repository and never runs in a job that pushes.
GUARD_RE='(^|[^[:alnum:]_.-])git([[:space:]]+(-[^[:space:]]+([[:space:]]+[^[:space:]]+)?[[:space:]]+)*)(commit|commit-tree|merge|cherry-pick|rebase|am|revert|pull)([[:space:]]|$|["'"'"')])'
guard_scan() {   # guard_scan <repo root>: print "file:line:text" for each commit-making git call outside tests and not allowed
  ( cd "$1" && git ls-files -z -- bin .github 'tools' 2>/dev/null | tr '\0' '\n' \
    | grep -v -E '(^|/)(tests?|testdata|fixtures)/|-test\.(sh|py)$|_test\.(py|go)$|(^|/)test_[^/]*\.py$|^\.github/agent/fixtures/' \
    | while IFS= read -r f; do [ -f "$f" ] && grep -n -E "$GUARD_RE" "$f" | grep -v -E '^[0-9]+:[[:space:]]*#' | sed "s#^#$f:#"; done )
}
guard_allowed() {   # each allowed row: file<TAB>exact text of the line (a fixture inside a library the tests source)
  case "$1" in
    ".github/agent/bin/auditor-open-pr.py:"*'shim("git commit -m auditor:%s" % change)') return 0 ;;   # a ledger line the test harness reads; no git runs
    ".github/agent/bin/auditorlib/signed_commit.py:"*"over the %d-byte limit of createCommitOnBranch; the commit cannot be made through the API (and a git commit would be unsigned)"*) return 0 ;;   # an error message
    "bin/melange-apko-lib.sh:"*"GIT_COMMITTER_EMAIL=t@example.test GIT_COMMITTER_DATE=\"\$ISO\" GIT_AUTHOR_DATE=\"\$ISO\" git commit -q -m fixture ) >/dev/null 2>&1") return 0 ;;
  esac
  return 1
}
bad_lines=""
while IFS= read -r hit; do [ -n "$hit" ] || continue; guard_allowed "$hit" || bad_lines+="${hit}"$'\n'; done < <(guard_scan "$root")
if [ -z "$bad_lines" ]; then echo "ok: no workflow or script outside the tests makes a commit with git (AC8)"; pass=$((pass+1))
else echo "FAIL: a commit-making git call outside the tests:"; printf '%s' "$bad_lines" | sed 's/^/    /'; fail=$((fail+1)); fi
# the guard must catch each form, in a throwaway repository
g="$(mktemp -d)"; ( cd "$g" && git init -q && mkdir -p bin .github/workflows && printf 'x\n' > bin/a.sh ) >/dev/null 2>&1
guard_catches() {   # guard_catches <name> <file> <line>
  ( cd "$g" && printf '%s\n' "$3" > "$2" && git add -A >/dev/null 2>&1 ); local n; n="$(guard_scan "$g" | wc -l | tr -d ' ')"
  if [ "$n" -ge 1 ]; then echo "ok: guard catches ${1}"; pass=$((pass+1)); else echo "FAIL: guard misses ${1}"; fail=$((fail+1)); fi
}
guard_catches "git commit in a script"            bin/a.sh '  git commit -q -m x'
guard_catches "git commit-tree"                   bin/a.sh 'sha=$(git commit-tree "$tree" -p HEAD -m x)'
guard_catches "git merge"                         bin/a.sh 'git merge origin/main'
guard_catches "git -c option before commit"       bin/a.sh 'git -c user.name=x commit -m y'
guard_catches "git commit in a workflow step"     .github/workflows/w.yml '        run: git commit -am bump && git push'
guard_catches "git commit in single quotes"       bin/a.sh "bash -c 'git commit -m x'"
( cd "$g" && printf '# git commit is not run here\ngit status\n' > bin/a.sh && rm -f .github/workflows/w.yml && git add -A >/dev/null 2>&1 )
[ "$(guard_scan "$g" | wc -l | tr -d ' ')" = 0 ] && { echo "ok: guard ignores a comment and other git calls"; pass=$((pass+1)); } || { echo "FAIL: guard flags a comment or another git call"; fail=$((fail+1)); }
rm -rf "$g"

echo "----"
echo "go-bump-open-pr: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
