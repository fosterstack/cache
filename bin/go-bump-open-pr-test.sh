#!/usr/bin/env bash
# proves: REQ-REL-004-AC4
# proves: REQ-REL-004-AC9
# Regression for bin/go-bump-open-pr.sh (audit R03; owner Oct 2, advisor 0052/0055; signed commits, advisor 0623): the PR-open decision must
# distinguish open / merged / closed-not-merged / orphaned-branch / fresh, RECOVER an orphaned branch by creating the
# PR, and open it only as a DRAFT. A fresh bump never runs `git commit`: the branch is pushed at the commit the job started from, the one
# commit is made through the API (createCommitOnBranch, signed for the App's token), the API is asked whether it is verified, and a commit
# that is not verified, an API call that fails or an id that is not a commit id deletes the branch and opens no PR (REQ-REL-004-AC9). gh and git
# are STRICT mocks (Codex #157 r1): every call is recorded, the exact call sequence and exit status are asserted per path, both modules' go
# directives are checked, the commit request the API receives is checked byte for byte, and any call outside the allowed set fails the case.
# Mutants of the script (ready + auto-merge appended; a denied create; a git commit; an unchecked verification) must be caught. The last
# section is the repository-wide guard: nothing outside the tests may run git commit, git commit-tree or git merge.
set -uo pipefail
# the name of the fake download program that the mocks put on PATH
FAKE_FETCH_TOOL=curl
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

# run_case name sut prs branch_exists create_rc want_rc want_calls want_directive(new|old|skip) [graphql ok|fail|badoid] [verified true|false|fail] [check_input 0|1] [orphan tip true|false|null|empty|fail|basehead] [versions "cur latest"] [delete fails 0|1] [text the output must contain] [remote tip when cleanup starts base|oid|other|rival|empty|lsfail] [pr head after create match|differ] [pr close fails 0|1] [branch push fails 0|1]
run_case() {
  local name="$1" sut="$2" prs="$3" branch_exists="$4" create_rc="$5" want_rc="$6" want_calls="$7" want_dir="$8"
  local gql="${9:-ok}" ver="${10:-true}" chk="${11:-0}" tip="${12:-true}" vers="${13:-1.26.6 1.27.0}" delfail="${14:-0}" must="${15:-}" rtip="${16:-base}" headmode="${17:-match}" closefail="${18:-0}" pushfail="${19:-0}"
  local work; work="$(mktemp -d)"
  printf 'module x\n\ngo 1.26.6\n' > "$work/go.mod"
  mkdir -p "$work/tools/requirements"; printf 'module x/t\n\ngo 1.26.6\n' > "$work/tools/requirements/go.mod"
  mkdir -p "$work/bin"; local log="$work/calls"; : > "$log"
  # the installer's Go pin (Codex B r4 F2): GO_VER and both per-arch checksums, bumped together with the go directives
  printf '#!/usr/bin/env bash\nGO_VER=1.26.6\ncase x in\n  go:x86_64|go:amd64) SUM=%s ;;\n  go:aarch64|go:arm64) SUM=%s ;;\nesac\n' "$(printf 'a%.0s' $(seq 64))" "$(printf 'b%.0s' $(seq 64))" > "$work/bin/install-scanner.sh"
  # the policy row of the installer (.github/policy/chain-scripts.json): its sha256 must follow the installer's bytes in the same commit (Codex A r5 #3)
  mkdir -p "$work/.github/policy"
  python3 - "$work" <<'PY'
import hashlib, json, os, sys
w = sys.argv[1]
h = hashlib.sha256(open(w + "/bin/install-scanner.sh", "rb").read()).hexdigest()
rows = [{"path": "bin/other.sh", "sha256": "0" * 64}, {"path": "bin/install-scanner.sh", "sha256": h, "tools": ["go"]}]
if os.environ.get("BUMP_POLICYPAD") == "1":      # the real policy is 150 KB: its base64 is over Linux's 128 KiB limit for ONE argument, so the request must not pass it through argv
    rows += [{"path": "bin/pad%d.sh" % n, "sha256": "%064x" % n, "reason": "x" * 400} for n in range(400)]
json.dump({"scripts": rows}, open(w + "/.github/policy/chain-scripts.json", "w"), indent=2)
open(w + "/.github/policy/chain-scripts.json", "a").write("\n")
PY
  # the recipe template, its generator and the two generated recipes (rc-3 item 6): copies of the real files with the Go pin moved back to 1.26.6, the template's
  # pin and the recipes regenerated, so the work tree is self-consistent before the bump; BUMP_TMPL=drift leaves the template at another Go version
  root_real="$(cd "$here/.." && pwd)"
  mkdir -p "$work/build/locks"; cp "$root_real"/build/locks/* "$work/build/locks/"; cp "$root_real/bin/gen-recipes.py" "$work/bin/"
  cp "$root_real/build/melange-baselayout.yaml.tmpl" "$root_real/build/melange-baselayout.yaml" "$work/build/"   # the generator reads the base-layout template too (0710)
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
  # an encoder that fails on demand (BUMP_B64=fail): the request must not be made from an empty file
  local realb64; realb64="$(command -v base64)"
  printf '#!/usr/bin/env bash\n[ "${BUMP_B64:-ok}" = fail ] && exit 74\nexec %s "$@"\n' "$realb64" > "$work/bin/base64"; chmod +x "$work/bin/base64"
  cat > "$work/bin/gh" <<GH
#!/usr/bin/env bash
args=(); skip=0; inp=0
for a in "\$@"; do
  if [ \$inp = 1 ]; then cp "\$a" "${work}/input.json"; args+=("<input>"); inp=0; continue; fi
  if [ \$skip = 1 ]; then args+=("<body>"); printf '%s' "\$a" > "${log}.body"; skip=0; continue; fi
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
  ls-remote) case "\$*" in *--exit-code*) [ "${branch_exists}" = 1 ] && exit 0 || exit 2 ;; *) case "${rtip}" in base) printf '%s\trefs/heads/${B}\n' ${BASE} ;; oid) printf '%s\trefs/heads/${B}\n' ${OID} ;; rival) printf '%s\trefs/heads/${B}\n' ${RIVAL} ;; other) printf '%s\trefs/heads/${B}\n' ${OTHER} ;; empty) ;; lsfail) exit 1 ;; esac ;; esac ;;
  rev-parse) echo ${BASE} ;;
  push) case "\$*" in *" :refs/heads/"*) exit ${delfail} ;; esac; exit ${pushfail} ;;
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
  elif [ "$want_dir" != skip ]; then
    [ "$have_ver" = 1.26.6 ] && [ "$have_amd" = "$(printf 'a%.0s' $(seq 64))" ] && [ "$have_arm" = "$(printf 'b%.0s' $(seq 64))" ] || why+=" installer pin changed although nothing was bumped;"
  fi
  [ "$rc" = "$want_rc" ] || why+=" rc=$rc want $want_rc;"
  [ "$got" = "$want" ] || why+=" calls differ;"
  grep -q UNEXPECTED <<<"$got" && why+=" an unexpected call;"
  # a bump that never reached a created PR may leave the working tree bumped; only a fresh success has a fixed expectation
  [ "$want_dir" = skip ] || { [ "$dir_root" = "$wd" ] && [ "$dir_tools" = "$wd" ] || why+=" go directives $dir_root/$dir_tools want $wd;"; }
  [ -z "$must" ] || grep -qF -- "$must" <<<"$out" || why+=" the output lacks '${must}';"
  if [ "$want_dir" != skip ]; then
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
  fi
  # the body names every step this change does not do itself (the archive push) and the files that moved
  if [ -f "$log.body" ]; then
    for need in build/melange.yaml.tmpl TEMPLATE_SHA256 bin/gen-recipes.py build/melange.yaml build/melange-fips.yaml build/archive.json "go/go1.27.0.linux-amd64.tar.gz" "go/go1.27.0.linux-arm64.tar.gz" "not part of this pull request"; do
      grep -qF -- "$need" "$log.body" || why+=" the PR body does not name '$need';"
    done
  fi
  if [ "$chk" = 1 ]; then
    # the request the API receives: this branch, this base, no deletions, exactly the eight bumped files' bytes (the two go.mod files, the installer and its policy row), a headline, no author override
    # the expected encodings go to files and into jq by --rawfile: a padded policy file is far over one argument's size limit on Linux
    mkdir -p "$work/exp"
    base64 < "$work/go.mod" | tr -d '\n' > "$work/exp/r"; base64 < "$work/tools/requirements/go.mod" | tr -d '\n' > "$work/exp/t"
    base64 < "$work/bin/install-scanner.sh" | tr -d '\n' > "$work/exp/ins"; base64 < "$work/.github/policy/chain-scripts.json" | tr -d '\n' > "$work/exp/pol"
    base64 < "$work/build/melange.yaml.tmpl" | tr -d '\n' > "$work/exp/mm"; base64 < "$work/bin/gen-recipes.py" | tr -d '\n' > "$work/exp/gg"
    base64 < "$work/build/melange.yaml" | tr -d '\n' > "$work/exp/yy"; base64 < "$work/build/melange-fips.yaml" | tr -d '\n' > "$work/exp/zz"
    jq -e --arg b "$B" --arg base "$BASE" --rawfile r "$work/exp/r" --rawfile t "$work/exp/t" --rawfile ins "$work/exp/ins" --rawfile pol "$work/exp/pol" \
          --rawfile mm "$work/exp/mm" --rawfile gg "$work/exp/gg" --rawfile yy "$work/exp/yy" --rawfile zz "$work/exp/zz" '
      .variables.input as $i
      | $i.branch.branchName == $b and $i.expectedHeadOid == $base
        and ($i.message.headline | startswith("chore(go): bump toolchain 1.26.6 -> 1.27.0"))
        and (($i.fileChanges | keys) == ["additions"])
        and ($i.fileChanges.additions | map(.path) | sort) == [".github/policy/chain-scripts.json", "bin/gen-recipes.py", "bin/install-scanner.sh", "build/melange-fips.yaml", "build/melange.yaml", "build/melange.yaml.tmpl", "go.mod", "tools/requirements/go.mod"]
        and ($i.fileChanges.additions | map({(.path): .contents}) | add) == {"go.mod": $r, "tools/requirements/go.mod": $t, "bin/install-scanner.sh": $ins, ".github/policy/chain-scripts.json": $pol, "build/melange.yaml.tmpl": $mm, "bin/gen-recipes.py": $gg, "build/melange.yaml": $yy, "build/melange-fips.yaml": $zz}
        and ($i | has("author") | not)' "$work/input.json" >/dev/null 2>&1 || why+=" the commit request is not exactly the eight bumped files (the two go.mod files, the installer, its policy row, the recipe template, its generator and the two generated recipes);"
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
run_case "AC9: orphaned branch with an unverified tip -> exit 1, no PR, nothing deleted or committed" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 false
run_case "AC9: orphaned branch whose tip cannot be checked -> exit 1, no PR, nothing deleted" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 fail
run_case "AC9: an answer that is neither true nor false (null) -> exit 1, nothing deleted" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 null
run_case "AC9: a verified tip that is not a bump commit (the base a failed run pushed) -> exit 1, no PR, nothing deleted" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 basehead
run_case "AC9: an empty answer -> exit 1, nothing deleted" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV" old ok true 0 empty
run_case "AC9: a version that is not a Go version is refused before any call (injection)" \
                                                     "$SUT" '[]' 0 0 2 "" old ok true 0 true '1.26.6/g;s/^module .*/module evil/;s/x 1.27.0'
run_case "AC9: a latest that is not a Go version is refused before any call" \
                                                     "$SUT" '[]' 0 0 2 "" old ok true 0 true '1.26.6 1.27.0;rm'
run_case "fresh -> both modules bumped, one API commit verified, draft PR (REQ-REL-004-AC9)" \
                                                     "$SUT" '[]' 0 0 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE"$'\n'"$PRVIEW" new ok true 1
run_case "a denied create fails the run (42)"        "$SUT" '[]' 1 42 42 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE" old ok true 0 true
run_case "AC9: a commit the API does not report verified -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok false
run_case "AC9: the verification question failing -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok fail
run_case "AC9: the commit API failing -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$DEL_B" skip fail
run_case "AC9: a cleanup that fails says the branch remains, and still exits 1 with no PR" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$DEL_O" skip ok false 0 true '1.26.6 1.27.0' 1 'remove it by hand'
run_case "AC9: the API made the commit but its answer was lost -> the remote tip is ours (parent and headline), the leased delete uses it" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$INFO_O"$'\n'"$DEL_O" skip fail true 0 true '1.26.6 1.27.0' 0 '' oid
run_case "AC9: the remote tip is someone else's commit -> left in place, said so, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$INFO_X" skip fail true 0 true '1.26.6 1.27.0' 0 'leaving it' other
run_case "AC9: the remote tip cannot be read -> left in place, said so, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM" skip fail true 0 true '1.26.6 1.27.0' 0 'leaving it' lsfail
run_case "AC9: after a failed API commit the branch is not on the remote -> nothing to remove, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM" skip fail true 0 true '1.26.6 1.27.0' 0 'nothing to remove' empty
run_case "AC9: a branch push whose answer was lost but made the branch at the base -> leased delete, exit 1, no PR" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$LSREM"$'\n'"$DEL_B" skip ok true 0 true '1.26.6 1.27.0' 0 'the push of' base match 0 1
run_case "AC9: a branch push that failed and left nothing -> exit 1, nothing to remove, no PR" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$LSREM" skip ok true 0 true '1.26.6 1.27.0' 0 'nothing to remove' empty match 0 1
run_case "AC9: the remote tip is another run's commit (same parent and headline, other run marker) -> left in place" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$INFO_R" skip fail true 0 true '1.26.6 1.27.0' 0 'leaving it' rival
run_case "AC9: the branch moved after the commit was verified -> the PR is closed, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE"$'\n'"$PRVIEW"$'\n'"$PRCLOSE" new ok true 0 true '1.26.6 1.27.0' 0 'closing it' base differ
run_case "AC9: a pull request that cannot be closed is retried three times and reported (close it by hand), exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE"$'\n'"$PRVIEW"$'\n'"$PRCLOSE"$'\n'"$PRCLOSE"$'\n'"$PRCLOSE" new ok true 0 true '1.26.6 1.27.0' 0 'close it by hand' base differ 1
run_case "AC9: a pull request this script closed itself is not a human's decline -> recovery goes on" \
                                                     "$SUT" '[{"number":41,"state":"CLOSED","mergedAt":null,"comments":[{"body":"closed by go-bump-open-pr.sh: the branch moved after its commit was verified"}]}]' 1 0 0 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE"$'\n'"$PRVIEW" old ok true 0 true
run_case "a closed pull request with someone else's comment is still a decline" \
                                                     "$SUT" '[{"number":41,"state":"CLOSED","mergedAt":null,"comments":[{"body":"not now"}]}]' 1 0 0 "$LIST" old
run_case "AC9: an orphan's branch moved after its tip was verified -> the PR is closed, exit 1" \
                                                     "$SUT" '[]' 1 0 1 "$LIST"$'\n'"$LSR"$'\n'"$TIPV"$'\n'"$CREATE"$'\n'"$PRVIEW"$'\n'"$PRCLOSE" old ok true 0 true '1.26.6 1.27.0' 0 'closing it' base differ
run_case "AC9: an id that is not a commit id -> branch deleted, no PR, exit 1" \
                                                     "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP"$'\n'"$PUSH"$'\n'"$COMMIT"$'\n'"$LSREM"$'\n'"$DEL_B" skip badoid

# the checksums come from go.dev's published list over HTTPS and are checked against the downloaded tarballs; any doubt fails closed BEFORE a branch exists
BUMP_CURL=down run_case "go.dev unreachable -> fails closed, nothing changed or pushed" "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR" old
BUMP_CURL=mismatch run_case "a tarball that is not the published checksum -> fails closed" "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR" old
BUMP_CURL=nolist run_case "a version go.dev does not publish -> fails closed" "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR" old
BUMP_CURL=badhex run_case "a published checksum that is not 64 hex -> fails closed" "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR" old
BUMP_TMPL=drift run_case "a template not pinned at the current Go -> fails closed, nothing changed or pushed" "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR" old
BUMP_TMPL=split run_case "a template whose uri and sha256 lines are apart -> fails closed before any file changes" "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR" old
BUMP_TMPL=pinbad run_case "a template that no longer equals its pin -> fails closed (a bump re-pins reviewed bytes only)" "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR" old
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
mkdir -p "$e2e/build/locks"; cp "$root/build/melange.yaml.tmpl" "$root/build/melange.yaml" "$root/build/melange-fips.yaml" "$root/build/melange-baselayout.yaml.tmpl" "$root/build/melange-baselayout.yaml" "$e2e/build/"; cp "$root"/build/locks/* "$e2e/build/locks/"
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
printf '#!/usr/bin/env bash\ncase "$1 $2" in "pr list") echo "[]" ;; "api graphql") echo 1111111111111111111111111111111111111111 ;; "pr view") echo 1111111111111111111111111111111111111111 ;; "api repos/{owner}/{repo}/commits/1111111111111111111111111111111111111111") echo true ;; *) : ;; esac\n' > "$e2e/fake/gh"
printf '#!/usr/bin/env bash\ncase "$1" in ls-remote) exit 2 ;; rev-parse) echo 0123456789abcdef0123456789abcdef01234567 ;; *) exit 0 ;; esac\n' > "$e2e/fake/git"
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
FRESH_CASE=('[]' 0 0 0 "$LIST"$'\n'"$LSR"$'\n'"$FRESH_OK"$'\n'"$CREATE"$'\n'"$PRVIEW" new ok true 1)
# round 1 of take 30 (Codex sol B1/B2): the request is built from FILES (jq --rawfile), never from an argument (the real policy's base64 is over Linux's 128 KiB limit for one argument), and an encoder
# that fails stops the bump before anything is pushed (no empty installer in a signed commit)
BUMP_POLICYPAD=1 run_case "a 200 KB policy file -> the request still carries the eight files exactly (built from files, not arguments)" "$SUT" "${FRESH_CASE[@]}"
BUMP_B64=fail run_case "an encoder that fails -> nothing pushed, no API commit, no PR, exit 1" "$SUT" '[]' 0 0 1 "$LIST"$'\n'"$LSR"$'\n'"$REVP" skip
if grep -Eq -- '--arg +[A-Za-z_]+ +"\$\((base64|cat)' "$SUT"; then echo "FAIL: the bump script passes file contents through jq --arg"; fail=$((fail+1)); else echo "ok: the bump script passes no file contents through jq --arg"; pass=$((pass+1)); fi
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

# AC9, the repository guard, in the plain forms only (advisor ruling, the same scope as the owner's pin-checker ruling of Oct 3): no workflow, composite
# action or script outside the tests runs git commit, git commit-tree or git merge, written out as a shell command (options allowed, quoted or after ;
# and &&) or as a Python argument list ("git", "commit"). A deliberately disguised form (an alias, --config-env, split or concatenated words, escaped
# quotes, redirections spread through the command, git fast-import) is information, not a blocker: main's signed-commits rule stops an unsigned commit
# from merging whatever wrote it, and the bump path itself is proved by the cases above. An exception is the sha256 of the file and the WHOLE line, so
# nothing else on that line can run: a test fixture inside a library the tests source, a ledger string the harness reads, error messages and prose.
GUARD_PY='
import hashlib, os, re, subprocess, sys
CMDS = "(?:commit|commit-tree|merge)"
WORD = r"""(?:"[^"]*"|\x27[^\x27]*\x27|[^\s"\x27]+)"""      # an ordinary shell word, quoted or not (quotes around the whole word)
OPT = r"""["\x27]?-[^\s"\x27]*["\x27]?(?:\s+""" + WORD + r""")?"""     # an option and, when it has one, its value: -c "user.name=Build Bot"
SHELL_RE = re.compile(r"""(?<![\w.-])(?:[\w./-]*/)?["\x27]?git["\x27]?(?:\s+""" + OPT + r""")*\s+["\x27]?""" + CMDS + r"""["\x27]?(?![\w-])""")
LIST_RE = re.compile(r"""["\x27](?:[^"\x27]*/)?git["\x27]\s*,\s*(?:["\x27][^"\x27]*["\x27]\s*,\s*)*["\x27]""" + CMDS + r"""["\x27]""")
# every tracked file is read except the tests, the prose and the data (docs, markdown, json, the evidence and the root requirements)
SKIP = re.compile(r"(^|/)(tests?|testdata|fixtures)/|^(docs|test-evidence|requirements)/|-test\.(sh|py)$|_test\.(py|go)$|(^|/)test_[^/]*\.py$|\.(md|json|txt|sum|mod|png|svg|gz|lock|pub)$")
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
ALLOW=(93abf67cf317408498df34dd65e1f7af0ddef77dc3be75c3e22107424f6575b9 4ecf328cb07ea2e678cec7c6bda8aaf5d45a4569d93a92439cc0e65caf40425f 214234061c415ef2a41afd9c51fe8503b0645b31679d08fb6a06f7ddce85ffb0 5268fb8e50f332bb34b20260158a11e3169918db862866888a14e63996042130 809e4cd3d001b8f260e59002af8ee8c4bc14a7b0aee7a746bdf1a45fe260894d 2449244a68f1430fd2adeda5e9baf812b46470c590b9e77a9b60b2db11fd950f 7c3e3df9b151afb150c82b8a64eb67d69d60c0c2ccbf0b9ac97f54624218f818 933049755c9dd2e918eccd8dd86a093de078ec3c7d82a817b3e5aef6bb6c36e6)
bad_lines="$(guard_scan "$root" "${ALLOW[@]}")" || bad_lines="the guard itself failed"
if [ -z "$bad_lines" ]; then echo "ok: no workflow or script outside the tests makes a commit with git (AC9, plain forms)"; pass=$((pass+1))
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
guard_catches "a quoted option value with a space"  bin/a.sh "git -c 'user.name=Build Bot' commit -m x\\n"
guard_catches "a double-quoted option value with a space" bin/a.sh 'git -c "user.name=Build Bot" commit -m x\n'
guard_catches "a quoted option name"              bin/a.sh 'git "-c" user.name=Bot commit -m x\n'
guard_catches "a quoted directory with a space before merge" bin/a.sh 'git -C "my repo" merge topic\n'
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
L='raise CommitError("signed commit: %s is %d bytes, over the %d-byte limit of createCommitOnBranch; the commit cannot be made through the API (and a git commit would be unsigned)"'   # a copy of the one excepted line (the repo-wide scan below still reads the real file)
sig="$(printf '%s\n%s' "bin/a.py" "$L" | shasum -a 256 | cut -d' ' -f1)"
n="$(guard_in bin/a.py "${L//\\/\\\\}"'\n' "$sig")"; [ "$n" = 0 ] && { echo "ok: an exception row passes exactly its own line"; pass=$((pass+1)); } || { echo "FAIL: an exception row does not pass its own line ($n)"; fail=$((fail+1)); }
n="$(guard_in bin/a.py "subprocess.run(['git','commit']); ${L//\\/\\\\}"'\n' "$sig")"; [ "$n" -ge 1 ] && { echo "ok: an executable prefix on an excepted line is caught"; pass=$((pass+1)); } || { echo "FAIL: an executable prefix on an excepted line passes"; fail=$((fail+1)); }
n="$(guard_in bin/a.py "${L//\\/\\\\}"'; git commit -m x\n' "$sig")"; [ "$n" -ge 1 ] && { echo "ok: an executable suffix on an excepted line is caught"; pass=$((pass+1)); } || { echo "FAIL: an executable suffix on an excepted line passes"; fail=$((fail+1)); }
rm -rf "$g"

sed 's#^  bump_installer$#  true#' "$SUT" > "$mut"
mutant "installer pin left behind" "installer pin left behind" "$mut" "${FRESH_CASE[@]}"

sed 's#^  bump_template$#  true#' "$SUT" > "$mut"
mutant "template pins left behind" "template pins left behind" "$mut" "${FRESH_CASE[@]}"
sed 's#^  *env -u GH_TOKEN /usr/bin/python3 -I -B bin/gen-recipes.py --write.*#  true#' "$SUT" > "$mut"
mutant "recipes not regenerated" "recipes not regenerated" "$mut" "${FRESH_CASE[@]}"

echo "----"
echo "go-bump-open-pr: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
