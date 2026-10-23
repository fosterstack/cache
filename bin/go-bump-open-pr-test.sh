#!/usr/bin/env bash
# proves: REQ-REL-004-AC4
# Regression for bin/go-bump-open-pr.sh (audit R03; owner Oct 2, advisor 0052/0055): the PR-open decision must
# distinguish open / merged / closed-not-merged / orphaned-branch / fresh, RECOVER an orphaned branch by creating the
# PR, and open it only as a DRAFT committed as the App's bot. gh and git are STRICT mocks (Codex #157 r1): every call
# is recorded, the exact call sequence and exit status are asserted per path, both modules' go directives are checked,
# and any call outside the allowed set (pr ready, pr merge, auth, api, …) fails the case. Mutants of the script (ready
# + auto-merge appended; a denied create) must be caught.
set -uo pipefail
# the name of the fake download program that the mocks put on PATH
FAKE_FETCH_TOOL=curl
here="$(cd "$(dirname "$0")" && pwd)"
pass=0; fail=0
B=chore/go-1.27.0
LIST="gh pr list --head $B --base main --state all --json number,state,mergedAt"
LSR="git ls-remote --exit-code --heads origin $B"
CREATE="gh pr create --draft --base main --head $B --title chore(go): bump toolchain 1.26.6 -> 1.27.0 --body <body> --label dependencies"
FRESH_GIT=$'git config user.name SLUG[bot]\ngit config user.email SLUG[bot]@users.noreply.github.com\ngit checkout -b '"$B"$'\ngit add go.mod tools/requirements/go.mod bin/install-scanner.sh .github/policy/chain-scripts.json build/melange.yaml.tmpl bin/gen-recipes.py build/melange.yaml build/melange-fips.yaml\ngit commit -q -m chore(go): bump toolchain 1.26.6 -> 1.27.0\ngit push -u origin '"$B"

# run_case name sut prs branch_exists create_rc slug want_rc want_calls want_directive(new|old)
run_case() {
  local name="$1" sut="$2" prs="$3" branch_exists="$4" create_rc="$5" slug="$6" want_rc="$7" want_calls="$8" want_dir="$9"
  local work; work="$(mktemp -d)"
  printf 'module x\n\ngo 1.26.6\n' > "$work/go.mod"
  mkdir -p "$work/tools/requirements"; printf 'module x/t\n\ngo 1.26.6\n' > "$work/tools/requirements/go.mod"
  mkdir -p "$work/bin"; local log="$work/calls"; : > "$log"
  # the installer's Go pin (Codex B r4 F2): GO_VER and both per-arch checksums, bumped together with the go directives
  printf '#!/usr/bin/env bash\nGO_VER=1.26.6\ncase x in\n  go:x86_64|go:amd64) SUM=%s ;;\n  go:aarch64|go:arm64) SUM=%s ;;\nesac\n' "$(printf 'a%.0s' $(seq 64))" "$(printf 'b%.0s' $(seq 64))" > "$work/bin/install-scanner.sh"
  # the policy row of the installer (.github/policy/chain-scripts.json): its sha256 must follow the installer's bytes in the same commit (Codex A r5 #3)
  mkdir -p "$work/.github/policy"
  python3 - "$work" <<'PY'
import hashlib, json, sys
w = sys.argv[1]
h = hashlib.sha256(open(w + "/bin/install-scanner.sh", "rb").read()).hexdigest()
json.dump({"scripts": [{"path": "bin/other.sh", "sha256": "0" * 64}, {"path": "bin/install-scanner.sh", "sha256": h, "tools": ["go"]}]}, open(w + "/.github/policy/chain-scripts.json", "w"), indent=2)
open(w + "/.github/policy/chain-scripts.json", "a").write("\n")
PY
  # the recipe template, its generator and the two generated recipes (rc-3 item 6): copies of the real files with the Go pin moved back to 1.26.6, the template's
  # pin and the recipes regenerated, so the work tree is self-consistent before the bump; BUMP_TMPL=drift leaves the template at another Go version
  root_real="$(cd "$here/.." && pwd)"
  mkdir -p "$work/build/locks"; cp "$root_real"/build/locks/* "$work/build/locks/"; cp "$root_real/bin/gen-recipes.py" "$work/bin/"
  sed -E 's#(go\.dev/dl/go)[0-9.]+(\.linux-)#\11.26.6\2#' "$root_real/build/melange.yaml.tmpl" > "$work/build/melange.yaml.tmpl"
  [ "${BUMP_TMPL:-ok}" = drift ] && sed -i.bak -E 's#(go\.dev/dl/go)1\.26\.6#\11.26.5#' "$work/build/melange.yaml.tmpl" && rm -f "$work/build/melange.yaml.tmpl.bak"
  [ "${BUMP_TMPL:-ok}" = split ] && python3 - "$work/build/melange.yaml.tmpl" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
open(sys.argv[1], "w").write(re.sub(r"(uri: https://go\.dev/dl/go1\.26\.6\.linux-amd64\.tar\.gz\n)", r"\1      # the checksum follows\n", t, count=1))
PY
  python3 - "$work" <<'PY'
import hashlib, re, sys
w = sys.argv[1]
h = hashlib.sha256(open(w + "/build/melange.yaml.tmpl", "rb").read()).hexdigest()
g = open(w + "/bin/gen-recipes.py").read()
open(w + "/bin/gen-recipes.py", "w").write(re.sub(r'^TEMPLATE_SHA256 = "[0-9a-f]{64}"', 'TEMPLATE_SHA256 = "' + h + '"', g, count=1, flags=re.M))
PY
  ( cd "$work" && python3 bin/gen-recipes.py --write >/dev/null 2>&1 )
  [ "${BUMP_TMPL:-ok}" = pinbad ] && sed -i.bak "s/^TEMPLATE_SHA256 = \"[0-9a-f]\{64\}\"/TEMPLATE_SHA256 = \"$(printf 'f%.0s' $(seq 64))\"/" "$work/bin/gen-recipes.py" && rm -f "$work/bin/gen-recipes.py.bak"
  # go.dev, over HTTPS: the published list (mode=json) and the two linux tarballs, served by a mock download program; BUMP_CURL=down|mismatch|nolist|badhex breaks it
  local amd arm; amd=$(printf 'go1.27.0 amd64 tarball' | sha256sum | cut -d' ' -f1); arm=$(printf 'go1.27.0 arm64 tarball' | sha256sum | cut -d' ' -f1)
  [ "${BUMP_CURL:-ok}" = mismatch ] && amd=$(printf 'c%.0s' $(seq 64))
  [ "${BUMP_CURL:-ok}" = badhex ] && arm=notahash
  local list='[{"version":"go1.27.0","files":[{"filename":"go1.27.0.linux-amd64.tar.gz","os":"linux","arch":"amd64","kind":"archive","sha256":"'$amd'"},{"filename":"go1.27.0.linux-arm64.tar.gz","os":"linux","arch":"arm64","kind":"archive","sha256":"'$arm'"}]}]'
  [ "${BUMP_CURL:-ok}" = nolist ] && list='[{"version":"go1.26.6","files":[]}]'
  cat > "$work/bin/$FAKE_FETCH_TOOL" <<CURL
#!/usr/bin/env bash
[ "${BUMP_CURL:-ok}" = down ] && exit 7
req=""; out=""; while [ \$# -gt 0 ]; do case "\$1" in -o) out="\$2"; shift ;; https://*) req="\$1" ;; esac; shift; done
case "\$req" in
  https://go.dev/dl/?mode=json*) if [ -n "\$out" ]; then printf '%s' '${list}' > "\$out"; else printf '%s' '${list}'; fi ;;
  https://go.dev/dl/go1.27.0.linux-amd64.tar.gz) printf 'go1.27.0 amd64 tarball' > "\$out" ;;
  https://go.dev/dl/go1.27.0.linux-arm64.tar.gz) printf 'go1.27.0 arm64 tarball' > "\$out" ;;
  *) echo "UNEXPECTED fetch \$req" >> "${log}"; exit 22 ;;
esac
CURL
  chmod +x "$work/bin/$FAKE_FETCH_TOOL"
  cat > "$work/bin/gh" <<GH
#!/usr/bin/env bash
args=(); skip=0
for a in "\$@"; do if [ \$skip = 1 ]; then args+=("<body>"); printf '%s' "\$a" > "${log}.body"; skip=0; continue; fi; [ "\$a" = --body ] && skip=1; args+=("\$a"); done
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
  local want_row have_row
  want_row=$(sha256sum "$work/bin/install-scanner.sh" | cut -d' ' -f1)
  have_row=$(python3 -c 'import json,sys; print([r["sha256"] for r in json.load(open(sys.argv[1]))["scripts"] if r["path"]=="bin/install-scanner.sh"][0])' "$work/.github/policy/chain-scripts.json")
  [ "$have_row" = "$want_row" ] || why+=" the installer's row in chain-scripts.json is ${have_row:0:8}, the installer's sha256 is ${want_row:0:8} (they move together, in the same commit);"
  if [ "$want_dir" = new ]; then
    [ "$have_ver" = 1.27.0 ] && [ "$have_amd" = "$want_amd" ] && [ "$have_arm" = "$want_arm" ] || why+=" installer pin ${have_ver}/${have_amd:0:8}/${have_arm:0:8} not the bumped version and the sha256 of the downloaded tarballs;"
  else
    [ "$have_ver" = 1.26.6 ] && [ "$have_amd" = "$(printf 'a%.0s' $(seq 64))" ] && [ "$have_arm" = "$(printf 'b%.0s' $(seq 64))" ] || why+=" installer pin changed although nothing was bumped;"
  fi
  [ "$rc" = "$want_rc" ] || why+=" rc=$rc want $want_rc;"
  [ "$got" = "$want" ] || why+=" calls differ;"
  grep -q UNEXPECTED <<<"$got" && why+=" an unexpected call;"
  [ "$dir_root" = "$wd" ] && [ "$dir_tools" = "$wd" ] || why+=" go directives $dir_root/$dir_tools want $wd;"
  # rc-3 item 6: the recipe template's two go.dev pins move with the bump, TEMPLATE_SHA256 follows the template's bytes, the generated recipes are regenerated
  local t_uri_a t_uri_r t_sum_a t_sum_r t_pin t_real
  t_uri_a=$(grep -c "go.dev/dl/go${wd}.linux-amd64.tar.gz" "$work/build/melange.yaml.tmpl"); t_uri_r=$(grep -c "go.dev/dl/go${wd}.linux-arm64.tar.gz" "$work/build/melange.yaml.tmpl")
  t_sum_a=$(grep -c "expected-sha256: ${want_amd}" "$work/build/melange.yaml.tmpl"); t_sum_r=$(grep -c "expected-sha256: ${want_arm}" "$work/build/melange.yaml.tmpl")
  t_pin=$(sed -n 's/^TEMPLATE_SHA256 = "\([0-9a-f]*\)".*/\1/p' "$work/bin/gen-recipes.py"); t_real=$(sha256sum "$work/build/melange.yaml.tmpl" | cut -d' ' -f1)
  if [ "$want_dir" = new ]; then
    [ "$t_uri_a" = 1 ] && [ "$t_uri_r" = 1 ] && [ "$t_sum_a" = 1 ] && [ "$t_sum_r" = 1 ] || why+=" the template's go.dev pins are not the bumped uri and the downloaded sha256 ($t_uri_a/$t_uri_r/$t_sum_a/$t_sum_r);"
    [ "$t_pin" = "$t_real" ] || why+=" TEMPLATE_SHA256 ${t_pin:0:8} is not the template's sha256 ${t_real:0:8};"
    ( cd "$work" && python3 bin/gen-recipes.py --check >/dev/null 2>&1 ) || why+=" gen-recipes.py --check fails after the bump (the recipes are not regenerated);"
    grep -q "go${wd}.linux-amd64" "$work/build/melange.yaml" && grep -q "go${wd}.linux-arm64" "$work/build/melange-fips.yaml" || why+=" a generated recipe still pins the old Go;"
  else
    [ "$t_sum_a" = 0 ] && ! grep -q "go1.27.0" "$work/build/melange.yaml.tmpl" || why+=" the template changed although nothing was bumped;"
  fi
  # the body names every step this change does not do itself (the archive push) and the files that moved
  if [ -f "$log.body" ]; then
    for need in build/melange.yaml.tmpl TEMPLATE_SHA256 bin/gen-recipes.py build/melange.yaml build/melange-fips.yaml build/archive.json "go/go1.27.0.linux-amd64.tar.gz" "go/go1.27.0.linux-arm64.tar.gz" "not part of this pull request"; do
      grep -qF -- "$need" "$log.body" || why+=" the PR body does not name '$need';"
    done
  fi
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
BUMP_TMPL=drift run_case "a template not pinned at the current Go -> fails closed, nothing changed or pushed" "$SUT" '[]' 0 0 "" 1 "$LIST"$'\n'"$LSR" old
BUMP_TMPL=split run_case "a template whose uri and sha256 lines are apart -> fails closed before any file changes" "$SUT" '[]' 0 0 "" 1 "$LIST"$'\n'"$LSR" old
BUMP_TMPL=pinbad run_case "a template that no longer equals its pin -> fails closed (a bump re-pins reviewed bytes only)" "$SUT" '[]' 0 0 "" 1 "$LIST"$'\n'"$LSR" old
# the Go versions are plain release numbers: anything else is refused before a single call (they go into file names, a pattern and the template)
vout=$(cd "$(mktemp -d)" && bash "$SUT" '1.26.6' '1.27.0; rm -rf x' 2>&1); vrc=$?
if [ "$vrc" = 2 ] && grep -q 'must look like' <<<"$vout"; then echo "ok: a Go version that is not a plain release number is refused (exit 2) before any call"; pass=$((pass+1)); else echo "FAIL: a malformed version was not refused (rc=$vrc): ${vout:0:200}"; fail=$((fail+1)); fi
# every interpreter this script starts runs without the App token and without site or working-directory imports
loose=$(grep -n 'python3' "$SUT" | grep -v 'env -u GH_TOKEN /usr/bin/python3 -I -B' | grep -v '^[0-9]*:[[:space:]]*#' || true)
if [ -z "$loose" ]; then echo "ok: every python3 the bump script starts is 'env -u GH_TOKEN /usr/bin/python3 -I -B'"; pass=$((pass+1)); else echo "FAIL: a python3 call without the token removed or isolated mode: $loose"; fail=$((fail+1)); fi
# a standing consistency check (every run, not only on a bump): go.mod's toolchain version, tools/requirements/go.mod's and the installer's pin agree
root="$(cd "$here/.." && pwd)"
gv() { awk '$1 == "toolchain" && $2 ~ /^go[0-9]/ {sub(/^go/, "", $2); t = $2} $1 == "go" && g == "" {g = $2} END {print (t != "" ? t : g)}' "$1"; }
a=$(gv "$root/go.mod"); b=$(gv "$root/tools/requirements/go.mod"); c=$(sed -n 's/^GO_VER=\([0-9.]*\).*/\1/p' "$root/bin/install-scanner.sh" | head -1)
d=$(sed -n 's#^ *uri: https://go\.dev/dl/go\([0-9.]*\)\.linux-amd64\.tar\.gz$#\1#p' "$root/build/melange.yaml.tmpl" | head -1); e=$(sed -n 's#^ *uri: https://go\.dev/dl/go\([0-9.]*\)\.linux-arm64\.tar\.gz$#\1#p' "$root/build/melange.yaml.tmpl" | head -1)
ts_a=$(sed -n '/linux-amd64\.tar\.gz$/{n;s/^ *expected-sha256: //p;}' "$root/build/melange.yaml.tmpl" | head -1); ts_r=$(sed -n '/linux-arm64\.tar\.gz$/{n;s/^ *expected-sha256: //p;}' "$root/build/melange.yaml.tmpl" | head -1)
is_a=$(sed -n 's/.*go:x86_64|go:amd64) SUM=\([0-9a-f]*\) ;;/\1/p' "$root/bin/install-scanner.sh" | head -1); is_r=$(sed -n 's/.*go:aarch64|go:arm64) SUM=\([0-9a-f]*\) ;;/\1/p' "$root/bin/install-scanner.sh" | head -1)
if [ -n "$ts_a" ] && [ "$ts_a" = "$is_a" ] && [ -n "$ts_r" ] && [ "$ts_r" = "$is_r" ]; then echo "ok: the template's two expected-sha256 values equal the installer's two sums"; pass=$((pass+1)); else echo "FAIL: the template's expected-sha256 values '$ts_a' '$ts_r' differ from the installer's '$is_a' '$is_r'"; fail=$((fail+1)); fi
if [ -n "$a" ] && [ "$a" = "$b" ] && [ "$a" = "$c" ] && [ "$a" = "$d" ] && [ "$a" = "$e" ]; then echo "ok: go.mod ($a), tools/requirements/go.mod ($b), the installer's GO_VER ($c) and the recipe template's two go.dev pins ($d, $e) agree"; pass=$((pass+1))
else echo "FAIL: go.mod '$a', tools/requirements/go.mod '$b', bin/install-scanner.sh GO_VER '$c' and the recipe template's pins '$d'/'$e' disagree (a Go bump must change all of them)"; fail=$((fail+1)); fi
# the pull request shows the three changes side by side
if grep -q 'bin/install-scanner.sh' "$SUT" && grep -q 'GO_VER' "$SUT" && grep -q 'sha256' "$SUT" && grep -Eq 'linux-(amd64|\$\{?arch)' "$SUT"; then echo "ok: the bump script names the installer pin and checksums in the PR body"; pass=$((pass+1))
else echo "FAIL: the bump script does not describe the installer pin in the PR body"; fail=$((fail+1)); fi

# END TO END (Codex A r5 #3, B F2): a proposed bump, made by the script's real code path in a copy of the REAL files with a fake go.dev, leaves every
# check that reads the pin green: the policy validator (load_scripts), the installer test and the go-freshness wiring test
e2e="$(mktemp -d)"; rm -rf "$e2e"; mkdir -p "$e2e/bin" "$e2e/tools/requirements" "$e2e/tools/govulncheck" "$e2e/.github/policy" "$e2e/.github/workflows" "$e2e/fake"
root="$(cd "$here/.." && pwd)"
cp "$root/go.mod" "$e2e/go.mod"; cp "$root/tools/requirements/go.mod" "$e2e/tools/requirements/go.mod"
cp "$root/tools/govulncheck/go.mod" "$root/tools/govulncheck/go.sum" "$e2e/tools/govulncheck/"      # the installer test reads the govulncheck pin (ruling G)
cp "$root/.github/policy/chain-scripts.json" "$e2e/.github/policy/"; cp "$root"/.github/workflows/*.yml "$e2e/.github/workflows/"
mkdir -p "$e2e/build/locks"; cp "$root/build/melange.yaml.tmpl" "$root/build/melange.yaml" "$root/build/melange-fips.yaml" "$e2e/build/"; cp "$root"/build/locks/* "$e2e/build/locks/"
cp "$root"/bin/*.sh "$root"/bin/*.py "$e2e/bin/" 2> /dev/null; cp "$root/bin/chain-test-signers.json" "$e2e/bin/" 2> /dev/null
cur=$(sed -n 's/^GO_VER=\([0-9.]*\).*/\1/p' "$e2e/bin/install-scanner.sh" | head -1); new="9.${cur#*.}"
t_amd=$(printf 'e2e amd64' | sha256sum | cut -d' ' -f1); t_arm=$(printf 'e2e arm64' | sha256sum | cut -d' ' -f1)
cat > "$e2e/fake/$FAKE_FETCH_TOOL" <<CURL
#!/usr/bin/env bash
req=""; out=""; while [ \$# -gt 0 ]; do case "\$1" in -o) out="\$2"; shift ;; https://*) req="\$1" ;; esac; shift; done
case "\$req" in
  https://go.dev/dl/?mode=json*) printf '%s' '[{"version":"go${new}","files":[{"filename":"go${new}.linux-amd64.tar.gz","sha256":"${t_amd}"},{"filename":"go${new}.linux-arm64.tar.gz","sha256":"${t_arm}"}]}]' > "\$out" ;;
  https://go.dev/dl/go${new}.linux-amd64.tar.gz) printf 'e2e amd64' > "\$out" ;;
  https://go.dev/dl/go${new}.linux-arm64.tar.gz) printf 'e2e arm64' > "\$out" ;;
  *) exit 22 ;;
esac
CURL
printf '#!/usr/bin/env bash\ncase "$1 $2" in "pr list") echo "[]" ;; *) : ;; esac\n' > "$e2e/fake/gh"
printf '#!/usr/bin/env bash\ncase "$1" in ls-remote) exit 2 ;; *) exit 0 ;; esac\n' > "$e2e/fake/git"
chmod +x "$e2e/fake/"*
( cd "$e2e" && sed -i.bak -E "s/^go [0-9.]+\$/go ${cur}/" go.mod && PATH="$e2e/fake:$PATH" bash "$SUT" "$cur" "$new" > "$e2e/bump.out" 2>&1 ) || { echo "FAIL: e2e: the bump script failed: $(tail -3 "$e2e/bump.out")"; fail=$((fail+1)); }
e2e_check() { # e2e_check LABEL CMD...
  local label=$1; shift; local o rc=0; o=$( cd "$e2e" && "$@" 2>&1 ) || rc=$?
  if [ "$rc" = 0 ]; then echo "ok: e2e bump ${cur} -> ${new}: ${label}"; pass=$((pass+1)); else echo "FAIL: e2e bump: ${label}: ${o:0:300}"; fail=$((fail+1)); fi; }
e2e_check "the policy validator (load_scripts) accepts the bumped installer's row" python3 -c '
import importlib.util, sys
s = importlib.util.spec_from_file_location("cts", "bin/chain-test-signers.py"); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
rows, errs, names = m.load_scripts(".")
bad = [e for e in errs if "install-scanner" in e]
sys.exit(1 if bad else 0) if not bad else (print(bad), sys.exit(1))'
e2e_check "the template's pins moved, TEMPLATE_SHA256 follows it and the recipes are regenerated (gen-recipes.py --check)" python3 bin/gen-recipes.py --check
e2e_check "the template pins the new tarballs" bash -c 'grep -q "go.dev/dl/go'"${new}"'.linux-amd64.tar.gz" build/melange.yaml.tmpl && grep -q "expected-sha256: '"${t_arm}"'" build/melange.yaml.tmpl'
e2e_check "bin/chain-install-witness-test.sh passes on the bumped tree" bash bin/chain-install-witness-test.sh
e2e_check "bin/go-freshness-wiring-test.sh passes on the bumped tree" bash bin/go-freshness-wiring-test.sh
e2e_check "bin/install-scanner-test.sh passes on the bumped tree" bash bin/install-scanner-test.sh
rm -rf "$e2e"

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

sed 's#^  bump_template$#  true#' "$SUT" > "$mut"
mutant "template pins left behind" "template pins left behind" "$mut" '[]' 0 0 "" 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_GIT"$'\n'"$CREATE" new
sed 's#^  *env -u GH_TOKEN /usr/bin/python3 -I -B bin/gen-recipes.py --write.*#  true#' "$SUT" > "$mut"
mutant "recipes not regenerated" "recipes not regenerated" "$mut" '[]' 0 0 "" 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_GIT"$'\n'"$CREATE" new

# the action-pin checker reads this script when go-freshness.yml runs it: a variable at command position (a test `[[ .. && "$V" =~ .. ]]` reads as one) is a finding on every PR
pins_out=$(cd "$here/.." && python3 .github/agent/bin/check-action-pins.py 2>&1) && pins_rc=0 || pins_rc=$?
if [ "$pins_rc" = 0 ] && grep -q ' 0 finding(s)' <<<"$pins_out"; then echo "ok: the pin checker reads the bump script with no finding"; pass=$((pass+1)); else echo "FAIL: the pin checker has a finding over the repository: ${pins_out: -300}"; fail=$((fail+1)); fi

echo "----"
echo "go-bump-open-pr: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
