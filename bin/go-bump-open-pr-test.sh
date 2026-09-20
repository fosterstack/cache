#!/usr/bin/env bash
# Regression for bin/go-bump-open-pr.sh (audit R03): the PR-open decision must
# distinguish open / merged / closed-not-merged / orphaned-branch / fresh, and
# must RECOVER an orphaned branch (push-success then create-failure) by creating
# the PR — never treat "branch exists" as "PR exists". gh and git are mocked.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sut="${here}/go-bump-open-pr.sh"
pass=0; fail=0

run_case() { # name PRS_JSON BRANCH_EXISTS(0/1) expect_regex expect_create(y/n) expect_push(y/n)
  local name="$1" prs="$2" branch_exists="$3" re="$4" want_create="$5" want_push="$6"
  local work; work="$(mktemp -d)"
  # dummy modules so the fresh path's sed/grep operate on real files
  printf 'module x\n\ngo 1.26.6\n' > "$work/go.mod"
  mkdir -p "$work/tools/requirements"; printf 'module x/t\n\ngo 1.26.6\n' > "$work/tools/requirements/go.mod"
  # stubs
  mkdir -p "$work/bin"; local marker="$work/calls"; : > "$marker"
  cat > "$work/bin/gh" <<GH
#!/usr/bin/env bash
case "\$*" in
  *"pr list"*) printf '%s' '${prs}';;
  *"pr create"*) echo create >> "${marker}"; echo "https://example/pr/1";;
  *) : ;;
esac
GH
  cat > "$work/bin/git" <<GIT
#!/usr/bin/env bash
case "\$*" in
  *"ls-remote --exit-code --heads"*) [ "${branch_exists}" = "1" ] && exit 0 || exit 2;;
  *push*) echo push >> "${marker}";;
  *) : ;;
esac
exit 0
GIT
  chmod +x "$work/bin/gh" "$work/bin/git"
  local out rc
  out="$(cd "$work" && PATH="$work/bin:$PATH" bash "$sut" 1.26.6 1.27.0 2>&1)"; rc=$?
  local created=n pushed=n
  grep -q create "$marker" && created=y
  grep -q push "$marker" && pushed=y
  local ok=1
  grep -qiE "$re" <<<"$out" || { ok=0; }
  [ "$created" = "$want_create" ] || ok=0
  [ "$pushed" = "$want_push" ] || ok=0
  if [ "$ok" = 1 ]; then echo "ok: ${name}"; pass=$((pass+1));
  else echo "FAIL: ${name} (rc=${rc} create=${created}/${want_create} push=${pushed}/${want_push})"; echo "$out"|sed 's/^/    /'; fail=$((fail+1)); fi
  rm -rf "$work"
}

run_case "open PR -> dedup, no create"                 '[{"number":42,"state":"OPEN","mergedAt":null}]'            1 "already open"        n n
run_case "merged PR -> landed, no create"              '[{"number":40,"state":"MERGED","mergedAt":"2026-09-01T00:00:00Z"}]' 1 "already merged"    n n
run_case "closed-not-merged -> respect, no create"     '[{"number":41,"state":"CLOSED","mergedAt":null}]'          1 "closed without merging" n n
run_case "orphaned branch -> recover, create no push"  '[]'                                                        1 "orphaned"            y n
run_case "fresh -> bump, push, create"                 '[]'                                                        0 "bumping the go directive" y y

echo "----"
echo "go-bump-open-pr: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
