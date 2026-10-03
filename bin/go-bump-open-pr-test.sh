#!/usr/bin/env bash
# proves: REQ-REL-004-AC4
# Regression for bin/go-bump-open-pr.sh (audit R03; owner Oct 2, advisor 0052/0055): the PR-open decision must
# distinguish open / merged / closed-not-merged / orphaned-branch / fresh, RECOVER an orphaned branch by creating the
# PR, and open it only as a DRAFT committed as the App's bot. gh and git are STRICT mocks (Codex #157 r1): every call
# is recorded, the exact call sequence and exit status are asserted per path, both modules' go directives are checked,
# and any call outside the allowed set (pr ready, pr merge, auth, api, …) fails the case. Mutants of the script (ready
# + auto-merge appended; a denied create) must be caught.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
pass=0; fail=0
B=chore/go-1.27.0
LIST="gh pr list --head $B --base main --state all --json number,state,mergedAt"
LSR="git ls-remote --exit-code --heads origin $B"
CREATE="gh pr create --draft --base main --head $B --title chore(go): bump toolchain 1.26.6 -> 1.27.0 --body <body> --label dependencies"
FRESH_GIT=$'git config user.name SLUG[bot]\ngit config user.email SLUG[bot]@users.noreply.github.com\ngit checkout -b '"$B"$'\ngit add go.mod tools/requirements/go.mod\ngit commit -q -m chore(go): bump toolchain 1.26.6 -> 1.27.0\ngit push -u origin '"$B"

# run_case name sut prs branch_exists create_rc slug want_rc want_calls want_directive(new|old)
run_case() {
  local name="$1" sut="$2" prs="$3" branch_exists="$4" create_rc="$5" slug="$6" want_rc="$7" want_calls="$8" want_dir="$9"
  local work; work="$(mktemp -d)"
  printf 'module x\n\ngo 1.26.6\n' > "$work/go.mod"
  mkdir -p "$work/tools/requirements"; printf 'module x/t\n\ngo 1.26.6\n' > "$work/tools/requirements/go.mod"
  mkdir -p "$work/bin"; local log="$work/calls"; : > "$log"
  cat > "$work/bin/gh" <<GH
#!/usr/bin/env bash
args=(); skip=0
for a in "\$@"; do if [ \$skip = 1 ]; then args+=("<body>"); skip=0; continue; fi; [ "\$a" = --body ] && skip=1; args+=("\$a"); done
echo "gh \${args[*]}" >> "${log}"
case "\$1 \$2" in
  "pr list") printf '%s' '${prs}' ;;
  "pr create") [ "${create_rc}" = 0 ] && echo "https://example/pr/1"; exit ${create_rc} ;;
  *) echo "UNEXPECTED gh \$*" >> "${log}"; exit 0 ;;
esac
GH
  cat > "$work/bin/git" <<GIT
#!/usr/bin/env bash
echo "git \$*" >> "${log}"
case "\$1" in
  ls-remote) [ "${branch_exists}" = 1 ] && exit 0 || exit 2 ;;
  config|checkout|add|commit|push) exit 0 ;;
  *) echo "UNEXPECTED git \$*" >> "${log}"; exit 0 ;;
esac
GIT
  chmod +x "$work/bin/gh" "$work/bin/git"
  local out rc
  out="$(cd "$work" && PATH="$work/bin:$PATH" AUDITOR_APP_SLUG="$slug" bash "$sut" 1.26.6 1.27.0 2>&1)"; rc=$?
  local got; got="$(cat "$log")"
  local want="${want_calls//SLUG/${slug:-github-actions}}"
  local dir_root dir_tools; dir_root=$(awk '/^go /{print $2}' "$work/go.mod"); dir_tools=$(awk '/^go /{print $2}' "$work/tools/requirements/go.mod")
  local wd=1.26.6; [ "$want_dir" = new ] && wd=1.27.0
  local why=""
  [ "$rc" = "$want_rc" ] || why+=" rc=$rc want $want_rc;"
  [ "$got" = "$want" ] || why+=" calls differ;"
  grep -q UNEXPECTED <<<"$got" && why+=" an unexpected call;"
  [ "$dir_root" = "$wd" ] && [ "$dir_tools" = "$wd" ] || why+=" go directives $dir_root/$dir_tools want $wd;"
  rm -rf "$work"
  if [ -z "$why" ]; then echo "ok: ${name}"; pass=$((pass+1)); return 0; fi
  echo "FAIL: ${name}:${why}"; diff <(echo "$want") <(echo "$got") | sed 's/^/    /'; echo "$out" | sed 's/^/    | /'; fail=$((fail+1)); return 1
}
SUT="$here/go-bump-open-pr.sh"
run_case "open PR -> dedup, nothing else"           "$SUT" '[{"number":42,"state":"OPEN","mergedAt":null}]' 1 0 "" 0 "$LIST" old
run_case "merged PR -> landed, nothing else"        "$SUT" '[{"number":40,"state":"MERGED","mergedAt":"2026-09-01T00:00:00Z"}]' 1 0 "" 0 "$LIST" old
run_case "closed-not-merged -> respected"           "$SUT" '[{"number":41,"state":"CLOSED","mergedAt":null}]' 1 0 "" 0 "$LIST" old
run_case "orphaned branch -> draft PR, no push"     "$SUT" '[]' 1 0 "" 0 "$LIST"$'\n'"$LSR"$'\n'"$CREATE" old
run_case "fresh -> both modules bumped, pushed, draft PR as the App's bot" \
                                                     "$SUT" '[]' 0 0 fosterstack-auditor 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_GIT"$'\n'"$CREATE" new
run_case "fresh without the App -> the Actions bot"  "$SUT" '[]' 0 0 "" 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_GIT"$'\n'"$CREATE" new
run_case "a denied create fails the run (42)"        "$SUT" '[]' 1 42 "" 42 "$LIST"$'\n'"$LSR"$'\n'"$CREATE" old

# the harness must catch these mutants of the script (each counted as a pass only when it is caught)
mut="$(mktemp)"; trap 'rm -f "$mut"' EXIT
mutant() {
  local name="$1"; shift
  if run_case "$@" >/dev/null 2>&1; then echo "FAIL: mutant not caught: $name"; fail=$((fail+1)); pass=$((pass-1))
  else echo "ok: mutant caught: $name"; pass=$((pass+1)); fail=$((fail-1)); fi
}
{ cat "$SUT"; printf '\ngh pr ready "$branch"\ngh pr merge --squash --auto "$branch"\n'; } > "$mut"
mutant "draft readied and auto-merge armed" "draft readied and auto-merge armed" "$mut" '[]' 0 0 fosterstack-auditor 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_GIT"$'\n'"$CREATE" new
sed 's/gh pr create --draft /gh pr create /' "$SUT" > "$mut"
mutant "not a draft" "not a draft" "$mut" '[]' 1 0 "" 0 "$LIST"$'\n'"$LSR"$'\n'"$CREATE" old
sed 's/--label dependencies$/--label dependencies || true/' "$SUT" > "$mut"; grep -q 'dependencies || true' "$mut" || { echo "FAIL: mutant not built"; fail=$((fail+1)); }
mutant "a denied create swallowed" "a denied create swallowed" "$mut" '[]' 1 42 "" 42 "$LIST"$'\n'"$LSR"$'\n'"$CREATE" old
sed 's#for f in go.mod tools/requirements/go.mod; do#for f in go.mod; do#' "$SUT" > "$mut"
mutant "only one module bumped" "only one module bumped" "$mut" '[]' 0 0 "" 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_GIT"$'\n'"$CREATE" new

echo "----"
echo "go-bump-open-pr: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
