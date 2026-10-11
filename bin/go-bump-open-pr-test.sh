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
FRESH_GIT=$'git config user.name SLUG[bot]\ngit config user.email SLUG[bot]@users.noreply.github.com\ngit checkout -b '"$B"$'\ngit add go.mod tools/requirements/go.mod bin/install-scanner.sh\ngit commit -q -m chore(go): bump toolchain 1.26.6 -> 1.27.0\ngit push -u origin '"$B"

# run_case name sut prs branch_exists create_rc slug want_rc want_calls want_directive(new|old)
run_case() {
  local name="$1" sut="$2" prs="$3" branch_exists="$4" create_rc="$5" slug="$6" want_rc="$7" want_calls="$8" want_dir="$9"
  local work; work="$(mktemp -d)"
  printf 'module x\n\ngo 1.26.6\n' > "$work/go.mod"
  mkdir -p "$work/tools/requirements"; printf 'module x/t\n\ngo 1.26.6\n' > "$work/tools/requirements/go.mod"
  mkdir -p "$work/bin"; local log="$work/calls"; : > "$log"
  # the installer's Go pin (Codex B r4 F2): GO_VER and both per-arch checksums, bumped together with the go directives
  printf '#!/usr/bin/env bash\nGO_VER=1.26.6\ncase x in\n  go:x86_64|go:amd64) SUM=%s ;;\n  go:aarch64|go:arm64) SUM=%s ;;\nesac\n' "$(printf 'a%.0s' $(seq 64))" "$(printf 'b%.0s' $(seq 64))" > "$work/bin/install-scanner.sh"
  # go.dev, over HTTPS: the published list (mode=json) and the two linux tarballs, served by a mock curl; BUMP_CURL=down|mismatch|nolist|badhex breaks it
  local amd arm; amd=$(printf 'go1.27.0 amd64 tarball' | sha256sum | cut -d' ' -f1); arm=$(printf 'go1.27.0 arm64 tarball' | sha256sum | cut -d' ' -f1)
  [ "${BUMP_CURL:-ok}" = mismatch ] && amd=$(printf 'c%.0s' $(seq 64))
  [ "${BUMP_CURL:-ok}" = badhex ] && arm=notahash
  local list='[{"version":"go1.27.0","files":[{"filename":"go1.27.0.linux-amd64.tar.gz","os":"linux","arch":"amd64","kind":"archive","sha256":"'$amd'"},{"filename":"go1.27.0.linux-arm64.tar.gz","os":"linux","arch":"arm64","kind":"archive","sha256":"'$arm'"}]}]'
  [ "${BUMP_CURL:-ok}" = nolist ] && list='[{"version":"go1.26.6","files":[]}]'
  cat > "$work/bin/curl" <<CURL
#!/usr/bin/env bash
[ "${BUMP_CURL:-ok}" = down ] && exit 7
url=""; out=""; while [ \$# -gt 0 ]; do case "\$1" in -o) out="\$2"; shift ;; https://*) url="\$1" ;; esac; shift; done
case "\$url" in
  https://go.dev/dl/?mode=json*) printf '%s' '${list}' ;;
  https://go.dev/dl/go1.27.0.linux-amd64.tar.gz) printf 'go1.27.0 amd64 tarball' > "\$out" ;;
  https://go.dev/dl/go1.27.0.linux-arm64.tar.gz) printf 'go1.27.0 arm64 tarball' > "\$out" ;;
  *) echo "UNEXPECTED curl \$url" >> "${log}"; exit 22 ;;
esac
CURL
  chmod +x "$work/bin/curl"
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
  local why="" want_amd want_arm have_ver have_amd have_arm
  want_amd=$(printf 'go1.27.0 amd64 tarball' | sha256sum | cut -d' ' -f1); want_arm=$(printf 'go1.27.0 arm64 tarball' | sha256sum | cut -d' ' -f1)
  have_ver=$(sed -n 's/^GO_VER=//p' "$work/bin/install-scanner.sh")
  have_amd=$(sed -n 's/.*go:x86_64|go:amd64) SUM=\([0-9a-f]*\) ;;/\1/p' "$work/bin/install-scanner.sh"); have_arm=$(sed -n 's/.*go:aarch64|go:arm64) SUM=\([0-9a-f]*\) ;;/\1/p' "$work/bin/install-scanner.sh")
  if [ "$want_dir" = new ]; then
    [ "$have_ver" = 1.27.0 ] && [ "$have_amd" = "$want_amd" ] && [ "$have_arm" = "$want_arm" ] || why+=" installer pin ${have_ver}/${have_amd:0:8}/${have_arm:0:8} not the bumped version and the sha256 of the downloaded tarballs;"
  else
    [ "$have_ver" = 1.26.6 ] && [ "$have_amd" = "$(printf 'a%.0s' $(seq 64))" ] && [ "$have_arm" = "$(printf 'b%.0s' $(seq 64))" ] || why+=" installer pin changed although nothing was bumped;"
  fi
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

# the checksums come from go.dev's published list over HTTPS and are checked against the downloaded tarballs; any doubt fails closed BEFORE a branch exists
BUMP_CURL=down run_case "go.dev unreachable -> fails closed, nothing changed or pushed" "$SUT" '[]' 0 0 "" 1 "$LIST"$'\n'"$LSR" old
BUMP_CURL=mismatch run_case "a tarball that is not the published checksum -> fails closed" "$SUT" '[]' 0 0 "" 1 "$LIST"$'\n'"$LSR" old
BUMP_CURL=nolist run_case "a version go.dev does not publish -> fails closed" "$SUT" '[]' 0 0 "" 1 "$LIST"$'\n'"$LSR" old
BUMP_CURL=badhex run_case "a published checksum that is not 64 hex -> fails closed" "$SUT" '[]' 0 0 "" 1 "$LIST"$'\n'"$LSR" old
# a standing consistency check (every run, not only on a bump): go.mod's toolchain version, tools/requirements/go.mod's and the installer's pin agree
root="$(cd "$here/.." && pwd)"
gv() { awk '$1 == "toolchain" && $2 ~ /^go[0-9]/ {sub(/^go/, "", $2); t = $2} $1 == "go" && g == "" {g = $2} END {print (t != "" ? t : g)}' "$1"; }
a=$(gv "$root/go.mod"); b=$(gv "$root/tools/requirements/go.mod"); c=$(sed -n 's/^GO_VER=\([0-9.]*\).*/\1/p' "$root/bin/install-scanner.sh" | head -1)
if [ -n "$a" ] && [ "$a" = "$b" ] && [ "$a" = "$c" ]; then echo "ok: go.mod ($a), tools/requirements/go.mod ($b) and the installer's GO_VER ($c) agree"; pass=$((pass+1))
else echo "FAIL: go.mod '$a', tools/requirements/go.mod '$b' and bin/install-scanner.sh GO_VER '$c' disagree (a Go bump must change all three)"; fail=$((fail+1)); fi
# the pull request shows the three changes side by side
if grep -q 'bin/install-scanner.sh' "$SUT" && grep -q 'GO_VER' "$SUT" && grep -q 'sha256' "$SUT" && grep -Eq 'linux-(amd64|\$\{?arch)' "$SUT"; then echo "ok: the bump script names the installer pin and checksums in the PR body"; pass=$((pass+1))
else echo "FAIL: the bump script does not describe the installer pin in the PR body"; fail=$((fail+1)); fi

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

sed 's#^  bump_installer.*#  true#' "$SUT" > "$mut"
mutant "installer pin left behind" "installer pin left behind" "$mut" '[]' 0 0 "" 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_GIT"$'\n'"$CREATE" new

echo "----"
echo "go-bump-open-pr: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
