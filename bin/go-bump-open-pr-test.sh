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
OTHER=fedcba9876543210fedcba9876543210fedcba98
RIVAL=00112233445566778899aabbccddeeff00112233
LIST="gh pr list --head $B --base main --state all --json number,state,mergedAt,comments"
LSR="git ls-remote --exit-code --heads origin $B"
CREATE="gh pr create --draft --base main --head $B --title chore(go): bump toolchain 1.26.6 -> 1.27.0 --body <body> --label dependencies"
REVP="git rev-parse HEAD"
LSREM="git ls-remote origin refs/heads/${B}"
INFOQ='[.parents[0].sha, .commit.message] | @tsv'
INFO_O="gh api repos/{owner}/{repo}/commits/${OID} -q ${INFOQ}"
INFO_X="gh api repos/{owner}/{repo}/commits/${OTHER} -q ${INFOQ}"
INFO_R="gh api repos/{owner}/{repo}/commits/${RIVAL} -q ${INFOQ}"
PUSH="git push origin ${BASE}:refs/heads/${B}"
COMMIT="gh api graphql --input <input> -q .data.createCommitOnBranch.commit.oid"
VERIFY="gh api repos/{owner}/{repo}/commits/${OID} -q .commit.verification.verified"
DEL_B="git push origin :refs/heads/${B} --force-with-lease=refs/heads/${B}:${BASE}"   # cleanup before the API made a commit: leased on the pushed base
DEL_O="git push origin :refs/heads/${B} --force-with-lease=refs/heads/${B}:${OID}"    # cleanup after it: leased on the API's commit
TIPV="gh api repos/{owner}/{repo}/commits/${B} -q [.sha, .commit.verification.verified, (.commit.message | split(\"\\n\")[0])] | @tsv"
PRVIEW="gh pr view https://example/pr/1 --json headRefOid -q .headRefOid"
PRCLOSE="gh pr close https://example/pr/1 --comment closed by go-bump-open-pr.sh: the branch moved after its commit was verified"
FRESH_OK="$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$VERIFY"

# run_case name sut prs branch_exists create_rc want_rc want_calls want_directive(new|old|skip) [graphql ok|fail|badoid] [verified true|false|fail] [check_input 0|1] [orphan tip true|false|null|empty|fail|basehead] [versions "cur latest"] [delete fails 0|1] [text the output must contain] [remote tip when cleanup starts base|oid|other|rival|empty] [pr head after create match|differ] [pr close fails 0|1]
run_case() {
  local name="$1" sut="$2" prs="$3" branch_exists="$4" create_rc="$5" want_rc="$6" want_calls="$7" want_dir="$8"
  local gql="${9:-ok}" ver="${10:-true}" chk="${11:-0}" tip="${12:-true}" vers="${13:-1.26.6 1.27.0}" delfail="${14:-0}" must="${15:-}" rtip="${16:-base}" headmode="${17:-match}" closefail="${18:-0}"
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
  "api repos/{owner}/{repo}/commits/${OID}"|"api repos/{owner}/{repo}/commits/${OTHER}"|"api repos/{owner}/{repo}/commits/${RIVAL}") case "\$*" in
      *parents*) case "\$2" in
          *${OID}) printf '%s\t%s\\\\n\\\\n%s\n' ${BASE} 'chore(go): bump toolchain 1.26.6 -> 1.27.0' 'go-bump-run: 4242-1' ;;
          *${RIVAL}) printf '%s\t%s\\\\n\\\\n%s\n' ${BASE} 'chore(go): bump toolchain 1.26.6 -> 1.27.0' 'go-bump-run: 9999-1' ;;
          *) printf '%s\t%s\n' ${OID} 'someone elses commit' ;; esac ;;
      *) case "${ver}" in true) echo true ;; false) echo false ;; fail) exit 1 ;; esac ;; esac ;;
  "api repos/{owner}/{repo}/commits/${B}") case "${tip}" in true) printf '%s\ttrue\tchore(go): bump toolchain 1.26.6 -> 1.27.0\n' ${OID} ;; false) printf '%s\tfalse\tchore(go): bump toolchain 1.26.6 -> 1.27.0\n' ${OID} ;; null) printf '%s\tnull\tchore(go): bump toolchain 1.26.6 -> 1.27.0\n' ${OID} ;; basehead) printf '%s\ttrue\tMerge pull request\n' ${OID} ;; empty) echo ;; fail) exit 1 ;; esac ;;
  "pr view") case "${headmode}" in match) echo ${OID} ;; differ) echo ${OTHER} ;; esac ;;
  "pr close") exit ${closefail} ;;
  *) echo "UNEXPECTED gh \$*" >> "${log}"; exit 0 ;;
esac
GH
  cat > "$work/bin/git" <<GIT
#!/usr/bin/env bash
echo "git \$*" >> "${log}"
case "\$1" in
  ls-remote) case "\$*" in *--exit-code*) [ "${branch_exists}" = 1 ] && exit 0 || exit 2 ;; *) case "${rtip}" in base) printf '%s\trefs/heads/${B}\n' ${BASE} ;; oid) printf '%s\trefs/heads/${B}\n' ${OID} ;; rival) printf '%s\trefs/heads/${B}\n' ${RIVAL} ;; other) printf '%s\trefs/heads/${B}\n' ${OTHER} ;; empty) ;; esac ;; esac ;;
  rev-parse) echo ${BASE} ;;
  push) case "\$*" in *" :refs/heads/"*) exit ${delfail} ;; esac; exit 0 ;;
  *) echo "UNEXPECTED git \$*" >> "${log}"; exit 0 ;;
esac
GIT
  chmod +x "$work/bin/gh" "$work/bin/git"
  local out rc
  out="$(cd "$work" && PATH="$work/bin:$PATH" AUDITOR_APP_SLUG=fosterstack-auditor GITHUB_RUN_ID=4242 GITHUB_RUN_ATTEMPT=1 GO_BUMP_CLOSE_WAIT=0 bash "$sut" $vers 2>&1)"; rc=$?
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
  [ -z "$must" ] || grep -qF -- "$must" <<<"$out" || why+=" the output lacks '${must}';"
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
run_case "orphaned branch with a verified tip -> draft PR, no push, no commit" "$SUT" '[]' 1 0 0 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE"$'\n'"$PRVIEW" old ok true 0 true
run_case "AC8: orphaned branch with an unverified tip -> exit 1, no PR, nothing deleted or committed" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 false
run_case "AC8: orphaned branch whose tip cannot be checked -> exit 1, no PR, nothing deleted" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 fail
run_case "AC8: an answer that is neither true nor false (null) -> exit 1, nothing deleted" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 null
run_case "AC8: a verified tip that is not a bump commit (the base a failed run pushed) -> exit 1, no PR, nothing deleted" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 basehead
run_case "AC8: an empty answer -> exit 1, nothing deleted" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 empty
run_case "AC8: a version that is not a Go version is refused before any call (injection)" \
                                                     "$SUT" '[]' 0 0 2 "" old ok true 0 true '1.26.6/g;s/^module .*/module evil/;s/x 1.27.0'
run_case "AC8: a latest that is not a Go version is refused before any call" \
                                                     "$SUT" '[]' 0 0 2 "" old ok true 0 true '1.26.6 1.27.0;rm'
run_case "fresh -> both modules bumped, one API commit verified, draft PR (REQ-REL-004-AC8)" \
                                                     "$SUT" '[]' 0 0 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE"$'\n'"$PRVIEW" new ok true 1
run_case "a denied create fails the run (42)"        "$SUT" '[]' 1 42 42 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE" old ok true 0 true
run_case "AC8: a commit the API does not report verified -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok false
run_case "AC8: the verification question failing -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok fail
run_case "AC8: the commit API failing -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$DEL_B" skip fail
run_case "AC8: a cleanup that fails says the branch remains, and still exits 1 with no PR" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok false 0 true '1.26.6 1.27.0' 1 'remove it by hand'
run_case "AC8: the API made the commit but its answer was lost -> the remote tip is ours (parent and headline), the leased delete uses it" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$INFO_O"$'\n'"$DEL_O" skip fail true 0 true '1.26.6 1.27.0' 0 '' oid
run_case "AC8: the remote tip is someone else's commit -> left in place, said so, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$INFO_X" skip fail true 0 true '1.26.6 1.27.0' 0 'leaving it' other
run_case "AC8: the remote tip cannot be read -> left in place, said so, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM" skip fail true 0 true '1.26.6 1.27.0' 0 'leaving it' empty
run_case "AC8: the remote tip is another run's commit (same parent and headline, other run marker) -> left in place" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$INFO_R" skip fail true 0 true '1.26.6 1.27.0' 0 'leaving it' rival
run_case "AC8: the branch moved after the commit was verified -> the PR is closed, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE"$'\n'"$PRVIEW"$'\n'"$PRCLOSE" new ok true 0 true '1.26.6 1.27.0' 0 'closing it' base differ
run_case "AC8: a pull request that cannot be closed is retried three times and reported (close it by hand), exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE"$'\n'"$PRVIEW"$'\n'"$PRCLOSE"$'\n'"$PRCLOSE"$'\n'"$PRCLOSE" new ok true 0 true '1.26.6 1.27.0' 0 'close it by hand' base differ 1
run_case "AC8: a pull request this script closed itself is not a human's decline -> recovery goes on" \
                                                     "$SUT" '[{"number":41,"state":"CLOSED","mergedAt":null,"comments":[{"body":"closed by go-bump-open-pr.sh: the branch moved after its commit was verified"}]}]' 1 0 0 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE"$'\n'"$PRVIEW" old ok true 0 true
run_case "a closed pull request with someone else's comment is still a decline" \
                                                     "$SUT" '[{"number":41,"state":"CLOSED","mergedAt":null,"comments":[{"body":"not now"}]}]' 1 0 0 "$LIST" old
run_case "AC8: an orphan's branch moved after its tip was verified -> the PR is closed, exit 1" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE"$'\n'"$PRVIEW"$'\n'"$PRCLOSE" old ok true 0 true '1.26.6 1.27.0' 0 'closing it' base differ
run_case "AC8: an id that is not a commit id -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$DEL_B" skip badoid

# the harness must catch these mutants of the script (each counted as a pass only when it is caught)
mut="$(mktemp)"; trap 'rm -f "$mut"' EXIT
mutant() {
  local name="$1"; shift
  if run_case "$@" >/dev/null 2>&1; then echo "FAIL: mutant not caught: $name"; fail=$((fail+1)); pass=$((pass-1))
  else echo "ok: mutant caught: $name"; pass=$((pass+1)); fail=$((fail-1)); fi
}
FRESH_CASE=('[]' 0 0 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE"$'\n'"$PRVIEW" new ok true 1)
{ cat "$SUT"; printf '\ngh pr ready "$branch"\ngh pr merge --squash --auto "$branch"\n'; } > "$mut"
mutant "draft readied and auto-merge armed" "draft readied and auto-merge armed" "$mut" "${FRESH_CASE[@]}"
sed 's/gh pr create --draft /gh pr create /' "$SUT" > "$mut"
mutant "not a draft" "not a draft" "$mut" '[]' 1 0 0 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE"$'\n'"$PRVIEW" old ok true 0 true
sed 's/--label dependencies$/--label dependencies || true/' "$SUT" > "$mut"; grep -q 'dependencies || true' "$mut" || { echo "FAIL: mutant not built"; fail=$((fail+1)); }
mutant "a denied create swallowed" "a denied create swallowed" "$mut" '[]' 1 42 42 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE" old ok true 0 true
sed 's#for f in go.mod tools/requirements/go.mod; do#for f in go.mod; do#' "$SUT" > "$mut"
mutant "only one module bumped" "only one module bumped" "$mut" "${FRESH_CASE[@]}"
{ cat "$SUT"; printf '\ngit commit -q -m x\n'; } > "$mut"
mutant "a git commit added" "a git commit added" "$mut" "${FRESH_CASE[@]}"
sed 's/\[ "\$ver" = true \]/true/' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (verification)"; fail=$((fail+1)); }
mutant "the verification result ignored" "the verification result ignored" "$mut" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok false
sed 's/ --force-with-lease="[^"]*"//' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (lease on the delete)"; fail=$((fail+1)); }
mutant "the cleanup delete is not leased" "the cleanup delete is not leased" "$mut" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok false
sed 's/expectedHeadOid/expectedHead/' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (lease)"; fail=$((fail+1)); }
mutant "the commit is not leased on the base" "the commit is not leased on the base" "$mut" "${FRESH_CASE[@]}"

sed 's/\[ "\$tip_ver" = true \]/true/' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (tip)"; fail=$((fail+1)); }
mutant "the orphan's tip verification ignored" "the orphan's tip verification ignored" "$mut" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 false
{ cat "$SUT"; printf '\ngit push origin --delete "$branch"\n'; } > "$mut"
mutant "a branch deleted" "a branch deleted" "$mut" '[]' 1 0 0 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE"$'\n'"$PRVIEW" old ok true 0 true
sed 's/exit 2; }/true; }/' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (grammar)"; fail=$((fail+1)); }
mutant "the version grammar loosened" "the version grammar loosened" "$mut" '[]' 0 0 2 "" old ok true 0 true '1.26.6 1.27.0;rm'

sed 's/owned="\$oid"/true/' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (owned)"; fail=$((fail+1)); }
mutant "the lease stays on the pushed base after the API commit" "the lease stays on the pushed base after the API commit" "$mut" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok false
sed 's/ \\$//; s/ *|| echo "::error::could not remove[^;]*$/ || true/' "$SUT" > "$mut"
sed -i.bak 's/|| echo "::error::could not remove.*$/|| true/' "$mut"; rm -f "$mut.bak"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (cleanup failure silent)"; fail=$((fail+1)); }
mutant "a failed cleanup is silent" "a failed cleanup is silent" "$mut" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok false 0 true '1.26.6 1.27.0' 1 'remove it by hand'

sed 's/\[ "\$info" = "\$(printf [^)]*)" \] || return 1/true/' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (ownership)"; fail=$((fail+1)); }
mutant "any tip is taken as ours" "any tip is taken as ours" "$mut" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$INFO_X" skip fail true 0 true '1.26.6 1.27.0' 0 'leaving it' other

sed 's/\[ "\$head_now" != "\$expected_head" \]/false/' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (head check)"; fail=$((fail+1)); }
mutant "the PR head is not compared with the verified commit" "the PR head is not compared with the verified commit" "$mut" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE"$'\n'"$PRVIEW"$'\n'"$PRCLOSE" new ok true 0 true '1.26.6 1.27.0' 0 'closing it' base differ
awk '/^    \[ "\$info" = /{print "    [ \"${info%%$\x27\\t\x27*}\" = \"$base\" ] || return 1"; next}1' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (marker)"; fail=$((fail+1)); }
mutant "ownership without the run marker" "ownership without the run marker" "$mut" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$INFO_R" skip fail true 0 true '1.26.6 1.27.0' 0 'leaving it' rival

sed 's/ \&\& \[ "\$tip_head" = "\$headline" \]//' "$SUT" > "$mut"; cmp -s "$SUT" "$mut" && { echo "FAIL: mutant not built (headline)"; fail=$((fail+1)); }
mutant "an orphan tip that is not a bump commit is taken" "an orphan tip that is not a bump commit is taken" "$mut" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 basehead

# AC8, the repository guard, in the plain forms only (advisor ruling, the same scope as the owner's pin-checker ruling of Oct 3): no workflow, composite
# action or script outside the tests runs git commit, git commit-tree or git merge, written out as a shell command (options allowed, quoted or after ;
# and &&) or as a Python argument list ("git", "commit"). A deliberately disguised form (an alias, --config-env, split or concatenated words, escaped
# quotes, redirections spread through the command, git fast-import) is information, not a blocker: main's signed-commits rule stops an unsigned commit
# from merging whatever wrote it, and the bump path itself is proved by the cases above. An exception is the sha256 of the file and the WHOLE line, so
# nothing else on that line can run: a test fixture inside a library the tests source, a ledger string the harness reads, error messages and prose.
GUARD_PY='
import hashlib, os, re, subprocess, sys
CMDS = "(?:commit|commit-tree|merge)"
SHELL_RE = re.compile(r"""(?<![\w.-])(?:[\w./-]*/)?["\x27]?git["\x27]?(?:\s+(?:-\S+(?:\s+\S+)?\s+)*)["\x27]?""" + CMDS + r"""["\x27]?(?![\w-])""")
LIST_RE = re.compile(r"""["\x27](?:[^"\x27]*/)?git["\x27]\s*,\s*(?:["\x27][^"\x27]*["\x27]\s*,\s*)*["\x27]""" + CMDS + r"""["\x27]""")
# every tracked file is read except the tests, the prose and the data (docs, markdown, json, the vendored tree, the evidence and the root requirements)
SKIP = re.compile(r"(^|/)(tests?|testdata|fixtures)/|^(docs|vendor|test-evidence|requirements)/|-test\.(sh|py)$|_test\.(py|go)$|(^|/)test_[^/]*\.py$|\.(md|json|txt|sum|mod|png|svg|gz|lock|pub)$|^\.github/agent/fixtures/")
ALLOWED = set(sys.argv[2:])      # sha256 of "file\nwhole line, stripped"
root = sys.argv[1]
files = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True, check=True).stdout.split("\0")
for f in files:
    if not f or SKIP.search(f) or not os.path.isfile(os.path.join(root, f)) or os.path.islink(os.path.join(root, f)):
        continue
    try:
        lines = open(os.path.join(root, f), encoding="utf-8").read().split("\n")
    except (UnicodeDecodeError, OSError):
        continue
    whole = "\n".join(lines)
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith("#") or not (SHELL_RE.search(s) or LIST_RE.search(s)):
            continue
        if hashlib.sha256((f + "\n" + s).encode()).hexdigest() in ALLOWED:
            continue
        print("%s:%d:%s" % (f, n, s[:160]))
    for m in LIST_RE.finditer(whole):           # an argument list spread over lines
        if "\n" in m.group(0):
            print("%s:%d:%s" % (f, whole.count("\n", 0, m.start()) + 1, " ".join(m.group(0).split())[:160]))
'
guard_scan() { python3 -I -c "$GUARD_PY" "$@"; }   # guard_scan <repo root> [allowed sha256 ...]
ALLOW=(93abf67cf317408498df34dd65e1f7af0ddef77dc3be75c3e22107424f6575b9 4ecf328cb07ea2e678cec7c6bda8aaf5d45a4569d93a92439cc0e65caf40425f 214234061c415ef2a41afd9c51fe8503b0645b31679d08fb6a06f7ddce85ffb0 5268fb8e50f332bb34b20260158a11e3169918db862866888a14e63996042130 809e4cd3d001b8f260e59002af8ee8c4bc14a7b0aee7a746bdf1a45fe260894d 2449244a68f1430fd2adeda5e9baf812b46470c590b9e77a9b60b2db11fd950f 7c3e3df9b151afb150c82b8a64eb67d69d60c0c2ccbf0b9ac97f54624218f818)
bad_lines="$(guard_scan "$root" "${ALLOW[@]}")" || bad_lines="the guard itself failed"
if [ -z "$bad_lines" ]; then echo "ok: no workflow or script outside the tests makes a commit with git (AC8, plain forms)"; pass=$((pass+1))
else echo "FAIL: a commit-making git call outside the tests:"; printf '%s\n' "$bad_lines" | sed 's/^/    /'; fail=$((fail+1)); fi
# the guard must catch each plain form on its own, in a throwaway repository
g="$(mktemp -d)"; ( cd "$g" && git init -q && mkdir -p bin .github/workflows .githooks tools/requirements ) >/dev/null 2>&1
guard_in() {   # guard_in <file> <content>: the number of hits when the repository holds only that file
  ( cd "$g" && git rm -q -r -f --cached . >/dev/null 2>&1; rm -f bin/* .github/workflows/* .githooks/* tools/requirements/*; printf '%b' "$2" > "$1" && git add -A >/dev/null 2>&1 ); guard_scan "$g" "${@:3}" | wc -l | tr -d ' '
}
guard_catches() { local n; n="$(guard_in "$2" "$3")"; if [ "$n" -ge 1 ]; then echo "ok: guard catches ${1}"; pass=$((pass+1)); else echo "FAIL: guard misses ${1}"; fail=$((fail+1)); fi; }
guard_passes()  { local n; n="$(guard_in "$2" "$3")"; if [ "$n" = 0 ]; then echo "ok: guard lets through ${1}"; pass=$((pass+1)); else echo "FAIL: guard flags ${1}"; fail=$((fail+1)); fi; }
guard_catches "git commit in a script"            bin/a.sh '  git commit -q -m x\n'
guard_catches "git commit-tree"                   bin/a.sh 'sha=$(git commit-tree "$tree" -p HEAD -m x)\n'
guard_catches "git merge"                         bin/a.sh 'git merge origin/main\n'
guard_catches "git -c option before commit"       bin/a.sh 'git -c user.name=x commit -m y\n'
guard_catches "git commit in a workflow step"     .github/workflows/w.yml '        run: git commit -am bump && git push\n'
guard_catches "git commit in single quotes"       bin/a.sh "bash -c 'git commit -m x'\n"
guard_catches "git commit followed by a semicolon" bin/a.sh 'git commit;\n'
guard_catches "git commit joined with &&"         bin/a.sh 'git commit&&git push\n'
guard_catches "git by absolute path"              bin/a.sh '/usr/bin/git commit -m x\n'
guard_catches "git behind command"                bin/a.sh 'command git commit -m x\n'
guard_catches "a Python argument list"            bin/a.py 'subprocess.run(["git", "commit", "-m", "x"])\n'
guard_catches "a Python tuple of arguments"       bin/a.py 'subprocess.run(("git", "commit", "-m", "x"))\n'
guard_catches "a Python list spread over lines"   bin/a.py 'subprocess.run([\n    "git",\n    "commit",\n    "-m", "x"\n])\n'
guard_catches "a script outside bin and .github"  .githooks/pre-commit 'git commit -m x\n'
guard_catches "a script in a requirements module" tools/requirements/probe.sh 'git commit -m x\n'
guard_passes  "a comment and other git calls"     bin/a.sh '# git commit is not run here\ngit status\ngit push origin --delete b\ngit push origin :refs/heads/x\ngit rev-parse HEAD\n'
guard_passes  "a word that only contains the name" bin/a.sh 'echo digit commit; mygit commit\n'
# an exception is the exact whole line: the same line with anything executable around it is still caught
L="$(grep -h -F 'over the %d-byte limit of createCommitOnBranch; the commit cannot' "$root/.github/agent/bin/auditorlib/signed_commit.py" | head -1)"; L="${L#"${L%%[![:space:]]*}"}"
sig="$(printf '%s\n%s' "bin/a.py" "$L" | shasum -a 256 | cut -d' ' -f1)"
n="$(guard_in bin/a.py "${L//\\/\\\\}"'\n' "$sig")"; [ "$n" = 0 ] && { echo "ok: an exception row passes exactly its own line"; pass=$((pass+1)); } || { echo "FAIL: an exception row does not pass its own line ($n)"; fail=$((fail+1)); }
n="$(guard_in bin/a.py "subprocess.run(['git','commit']); ${L//\\/\\\\}"'\n' "$sig")"; [ "$n" -ge 1 ] && { echo "ok: an executable prefix on an excepted line is caught"; pass=$((pass+1)); } || { echo "FAIL: an executable prefix on an excepted line passes"; fail=$((fail+1)); }
n="$(guard_in bin/a.py "${L//\\/\\\\}"'; git commit -m x\n' "$sig")"; [ "$n" -ge 1 ] && { echo "ok: an executable suffix on an excepted line is caught"; pass=$((pass+1)); } || { echo "FAIL: an executable suffix on an excepted line passes"; fail=$((fail+1)); }
rm -rf "$g"

echo "----"
echo "go-bump-open-pr: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
