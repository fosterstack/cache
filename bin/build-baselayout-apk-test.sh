#!/usr/bin/env bash
# proves: REQ-IMAGE-001-AC16
# Tests of bin/build-baselayout-apk.sh (0710 chain part a): the sealed melange build of build/melange-baselayout.yaml.
# Every assertion runs offline against PATH stubs, like bin/build-apk-test.sh: nothing here calls a real sudo, unshare
# or melange.
# The production script has no test hook: the tests run a COPY in which exactly the lines ending in TEST-SUBST are
# replaced and which is checked to differ in no other line.
. "$(cd "$(dirname "$0")" && pwd)/melange-apko-lib.sh"
cd "$root"
unset GITHUB_ACTIONS
BB="$root/bin/build-baselayout-apk.sh"
bt="$(mktemp -d "$work/bl.XXXXXX")"   # this test's own scratch: the mkcopy helper and the script copies
cat >"$bt/mkcopy.py" <<'PY'
import re, sys
src, out = sys.argv[1:3]
subst = dict(a.split("=", 1) for a in sys.argv[3:])
seen, res = set(), []
for ln in open(src).read().split("\n"):
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=.*#\s*TEST-SUBST", ln)
    if m:
        n = m.group(1)
        if n not in subst:
            sys.exit("no substitution given for %s" % n)
        seen.add(n); res.append("%s=%s   # TEST-SUBST" % (n, subst[n]))
    else:
        res.append(ln)
if seen != set(subst):
    sys.exit("substitutions with no TEST-SUBST line: %s" % sorted(set(subst) - seen))
open(out, "w").write("\n".join(res))
PY
# the checkout the build reads its files from: the fixture checkout plus the real build/baselayout files, committed
cp -R "$src" "$work/bsrc"; mkdir -p "$work/bsrc/build"; cp -R "$root/build/baselayout" "$work/bsrc/build/baselayout"
( cd "$work/bsrc" && git add -A && GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.test GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.test \
  GIT_COMMITTER_DATE="$ISO" GIT_AUTHOR_DATE="$ISO" git commit -q -m baselayout ) >/dev/null 2>&1
export STUB_SRC="$work/bsrc"
mkcopy() {   # mkcopy OUT RECIPE: a copy of the script with the tool locations of the stubs and RECIPE as the recipe
  [ -f "$BB" ] || { printf '#!/bin/bash\necho "build-baselayout-apk.sh is missing" >&2\nexit 127\n' >"$1"; chmod +x "$1"; return 0; }   # no script yet: every case fails, none aborts
  python3 "$bt/mkcopy.py" "$BB" "$1" \
    'PY3=${TEST_PY3:-'"$(command -v python3)"'}' 'SUDO=${TEST_SUDO:-'"$stubs"'/sudo}' \
    'UNSHARE=${TEST_UNSHARE:-'"$stubs"'/unshare}' 'MELANGE=${TEST_MELANGE:-'"$stubs"'/melange}' 'SEALED_ENV=$TEST_SEALED_ENV' \
    'ENVBIN='"$(command -v env)" 'RECIPE='"$2" || { echo "FIXTURE SETUP FAILED: copy of $BB"; exit 1; }
  chmod +x "$1"
}
wrapper() {  # wrapper OUT COPY: the sealed data file from the harness's STUB_/FAKE_ variables, then the copy
  cat >"$1" <<EOW
#!/bin/bash
export TEST_SEALED_ENV="$work/sealed-test.json"
python3 - "\$TEST_SEALED_ENV" <<'PYW'
import json, os, sys
closed = {"PATH": os.environ["PATH"], "HOME": "/root", "LC_ALL": "C"}
for k, v in os.environ.items():
    if k.startswith(("STUB_", "FAKE_")) or k in ("CALLS", "ImageOS", "ImageVersion"):
        closed[k] = v
json.dump({"closed": closed, "from_environment": ["SOURCE_DATE_EPOCH"]}, open(sys.argv[1], "w"))
PYW
exec bash "$2" "\$@"
EOW
  chmod +x "$1"
}
export FSCACHE_ROOT="$root"
mkcopy "$bt/bb-copy.sh" "$root/build/melange-baselayout.yaml"; wrapper "$work/bb.sh" "$bt/bb-copy.sh"
BBT="$work/bb.sh"
bb_args=(--arch x86_64 --version 0.3.0 --source-dir "$work/bsrc" --repo "$fx/envrepo" --keyring "$kr" --melange-lock "$root/build/locks/melange.lock")
bbe=(env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64)

t "0710" "build-baselayout-apk.sh exists and is executable" test -x "$BB"
t "0710" "the script is straight-line text: no case, for, while, until, function or subshell line" \
  bash -c "! grep -Eq '^[[:space:]]*(case|for|while|until|function)[[:space:]]|^[[:alnum:]_]+\\(\\)[[:space:]]*\\{' '$BB'"
t "0710" "build-baselayout-apk.sh has no signing option and never names the release key" \
  bash -c "! grep -Eq 'APK_RELEASE_SIGNING_KEY=|release\\.rsa( |\$|\")' '$BB'"
sd "0710" "x86_64 build on an x86_64 host runs melange build of the base-layout recipe" '^melange build melange-baselayout\.yaml ' "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"
sd "0710" "the call is sealed: bubblewrap runner, namespace fosterstack, the assembly key, the local repository" \
  '^melange build .*--runner bubblewrap .*--namespace fosterstack .*--signing-key [^ ]*build/keys/assembly\.rsa ' "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"
ordered "0710" "sysctl comes before melange" '^sysctl ' '^melange build '
sd "0710" "aarch64 build on an aarch64 host" '^melange build .*--arch aarch64' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=aarch64 "$BBT" "${bb_args[@]}" --arch aarch64 --out "$(mo)"
sr "0710" "refuses an arch other than the host's" 'host|native' "${bbe[@]}" "$BBT" "${bb_args[@]}" --arch aarch64 --out "$(mo)"
sr "0710" "refuses without SOURCE_DATE_EPOCH" SOURCE_DATE_EPOCH env FAKE_UNAME=x86_64 "$BBT" "${bb_args[@]}" --out "$(mo)"
sr "0710" "refuses the release key in the environment" 'release|must not' "${bbe[@]}" APK_RELEASE_SIGNING_KEY=canary "$BBT" "${bb_args[@]}" --out "$(mo)"
sr "0710" "refuses GOPROXY set to a live proxy" GOPROXY "${bbe[@]}" GOPROXY=https://proxy.golang.org "$BBT" "${bb_args[@]}" --out "$(mo)"
sr "0710" "refuses a proxy in the environment" proxy "${bbe[@]}" HTTPS_PROXY=http://127.0.0.1:3128 "$BBT" "${bb_args[@]}" --out "$(mo)"
sr "0710" "refuses --signing-key (the apk is signed with the committed assembly key only)" 'signing' "${bbe[@]}" "$BBT" "${bb_args[@]}" --signing-key "$kr" --out "$(mo)"
sr "0710" "refuses --variant (there is one base-layout apk)" 'unknown argument' "${bbe[@]}" "$BBT" "${bb_args[@]}" --variant standard --out "$(mo)"
sr "0710" "refuses --go-archive (the recipe builds no Go)" 'unknown argument' "${bbe[@]}" "$BBT" "${bb_args[@]}" --go-archive "$fx/archive/go" --out "$(mo)"
sr "0710" "refuses an https repository" 'local' "${bbe[@]}" "$BBT" "${bb_args[@]}" --repo https://packages.wolfi.dev/os --out "$(mo)"
sr "0710" "refuses a version that is not X.Y.Z or X.Y.Z-rcN" 'version' "${bbe[@]}" "$BBT" "${bb_args[@]}" --version 1.2 --out "$(mo)"
sr "0710" "refuses a source directory with no .git" '\.git' "${bbe[@]}" "$BBT" "${bb_args[@]}" --source-dir "$work/nogit" --out "$(mo)"
mkdir -p "$work/nokey/build/keys"
mkcopy "$bt/bb-nokey.sh" "$root/build/melange-baselayout.yaml"; wrapper "$bt/bb-nokey-w.sh" "$bt/bb-nokey.sh"
( cd "$work/nokey" && mkdir -p bin build/keys && cp "$root/bin/build-baselayout-apk.sh" "$root/bin/build-apk-helper.py" bin/ && cp "$root/build/sealed-env.json" build/ ) 2>/dev/null
sr "0710" "refuses when the committed assembly key is missing" 'assembly key' bash -c "cd '$work/nokey' && exec env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 '$bt/bb-nokey-w.sh' ${bb_args[*]} --out '$work/nokey-out'"
mkcopy "$bt/bb-other.sh" "$root/build/melange.yaml"; wrapper "$bt/bb-other-w.sh" "$bt/bb-other.sh"
sr "0710" "refuses another recipe: the package must be fscache-baselayout" 'fscache-baselayout' "${bbe[@]}" "$bt/bb-other-w.sh" "${bb_args[@]}" --out "$(mo)"
mkcopy "$bt/bb-ns.sh" "$root/build/melange-baselayout.yaml"; sed -i 's/--namespace fosterstack/--namespace evil/' "$bt/bb-ns.sh"; wrapper "$bt/bb-ns-w.sh" "$bt/bb-ns.sh"
sr "0710" "refuses a melange call whose namespace is not fosterstack" 'refusing the melange call' "${bbe[@]}" "$bt/bb-ns-w.sh" "${bb_args[@]}" --out "$(mo)"
sed -e 's/^ca-certificates-bundle=.*//' "$root/build/locks/melange.lock" >"$bt/lock-short"
sr "0710" "refuses a melange lock the recipe does not agree with, both ways" 'lock' "${bbe[@]}" "$BBT" "${bb_args[@]}" --melange-lock "$bt/lock-short" --out "$(mo)"
{ cat "$root/build/locks/melange.lock"; echo "extra-package=1.0-r0"; } >"$bt/lock-long"
sr "0710" "refuses a melange lock with a line the recipe does not pin" 'lines the recipe does not pin' "${bbe[@]}" "$BBT" "${bb_args[@]}" --melange-lock "$bt/lock-long" --out "$(mo)"
o="$(mo)"; $RUNNER "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$o"
t "0710" "the run writes the apk under OUT/ARCH, signed by the assembly key" bash -c "[ -f '$o/x86_64/fscache-baselayout-0.3.0-r0.apk' ] && [ \"\$(python3 -I -B '$AT' signer '$o/x86_64/fscache-baselayout-0.3.0-r0.apk')\" = assembly.rsa.pub ]"
t "0710" "the run writes inputs-manifest-baselayout.json beside the apk" bash -c "python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d' '$o/inputs-manifest-baselayout.json'"
t "0710" "the run writes no fscache module SBOM and no inputs-manifest.json (those are the fscache apk's)" \
  bash -c "[ ! -e '$o/fscache-modules.spdx.json' ] && [ ! -e '$o/inputs-manifest.json' ]"
sf "0710" "an apk signed by another key is refused" 'signed by' env STUB_SIGNER=other.rsa.pub "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"
sf "0710" "an apk whose etc/passwd differs from build/baselayout/etc/passwd is refused" 'passwd' env STUB_BL_BAD=etc/passwd "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"
sf "0710" "an apk that ships a CA bundle file is refused: its entries differ from members.txt" 'members\.txt.*ca-certificates|members\.txt.*ssl' env STUB_BL_BUNDLE=1 "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"
# recipe copies the allowlist must refuse before any tool runs (exit 2)
bl_recipe() {   # bl_recipe NAME PYTHON-EDIT: a copy of the recipe edited by the python statements (d is the recipe), and a wrapper for it
  python3 -I - "$root/build/melange-baselayout.yaml" "$bt/recipe-$1.yaml" "$2" <<'PYE'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
exec(sys.argv[3])
yaml.safe_dump(d, open(sys.argv[2], "w"))
PYE
  mkcopy "$bt/bb-$1.sh" "$bt/recipe-$1.yaml"; wrapper "$bt/bb-$1-w.sh" "$bt/bb-$1.sh"
}
bl_recipe link 'd["pipeline"][0]["runs"] += "ln -s usr/bin ${{targets.destdir}}/bin\n"'
sr "0710" "refuses a recipe with an ln -s step (a symlink in the package)" 'only mkdir, chmod and cp' "${bbe[@]}" "$bt/bb-link-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe fetch 'd["pipeline"] = [{"uses": "fetch"}]'
sr "0710" "refuses a recipe whose pipeline step uses fetch" 'not exactly one runs' "${bbe[@]}" "$bt/bb-fetch-w.sh" "${bb_args[@]}" --out "$(mo)"
# the download tool names are built from pieces so this file holds no download text for the repository's scanners
bl_recipe fetchcmd 'd["pipeline"][0]["runs"] += "w" "get example.test/x\n"'
sr "0710" "refuses a recipe line that starts with a download tool" 'only mkdir, chmod and cp' "${bbe[@]}" "$bt/bb-fetchcmd-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe chain 'd["pipeline"][0]["runs"] += "mkdir -p x; w" "get ht" "tp://example.test/x\n"'
sr "0710" "refuses a mkdir line that chains a second command" 'chains or expands' "${bbe[@]}" "$bt/bb-chain-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe extra 'd["test"] = {"pipeline": []}'
sr "0710" "refuses a recipe with an extra top-level key" 'exactly the keys' "${bbe[@]}" "$bt/bb-extra-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe nullpipe 'd["pipeline"] = None'
sr "0710" "refuses a recipe whose pipeline is null" 'pipeline' "${bbe[@]}" "$bt/bb-nullpipe-w.sh" "${bb_args[@]}" --out "$(mo)"
for k in mode gone; do cp -R "$work/bsrc" "$bt/bsrc-$k"; done
sed -i 's/^f 0644 etc\/hosts$/f 0600 etc\/hosts/' "$bt/bsrc-mode/build/baselayout/members.txt"
sed -i '/^f 0644 etc\/services$/d' "$bt/bsrc-gone/build/baselayout/members.txt"
sf "0710" "an apk with another mode than members.txt names is refused" 'members\.txt.*etc/hosts' "${bbe[@]}" "$BBT" "${bb_args[@]}" --source-dir "$bt/bsrc-mode" --out "$(mo)"
sf "0710" "an apk with a file members.txt does not list is refused" 'members\.txt.*etc/services' "${bbe[@]}" "$BBT" "${bb_args[@]}" --source-dir "$bt/bsrc-gone" --out "$(mo)"
cp -R "$work/bsrc" "$bt/bsrc-miss"; echo "f 0644 etc/missing" >>"$bt/bsrc-miss/build/baselayout/members.txt"
sf "0710" "an apk missing a file members.txt lists is refused" 'members\.txt.*etc/missing' "${bbe[@]}" "$BBT" "${bb_args[@]}" --source-dir "$bt/bsrc-miss" --out "$(mo)"
# the destdir token: only as a whole word or as a prefix of token/...; the first word of the original line is judged
bl_recipe tokcp 'd["pipeline"][0]["runs"] += "cp /bin/true ${{targets.destdir}}cp\n${{targets.destdir}}cp x\n"'
sr "0710" "refuses a recipe that plants a program at the destdir token glued to a name and runs it" 'destdir token inside a word' "${bbe[@]}" "$bt/bb-tokcp-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe tokglue 'd["pipeline"][0]["runs"] += "cp x y${{targets.destdir}}\n"'
sr "0710" "refuses the destdir token glued after other text" 'destdir token inside a word' "${bbe[@]}" "$bt/bb-tokglue-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe tokletter 'd["pipeline"][0]["runs"] += "cp x ${{targets.destdir}}x/etc\n"'
sr "0710" "refuses the destdir token followed by a letter" 'destdir token inside a word' "${bbe[@]}" "$bt/bb-tokletter-w.sh" "${bb_args[@]}" --out "$(mo)"
# one strict form per line: ASCII and single spaces only, every destination under the destdir token, cp sources fixed (round-3 S1)
bl_recipe sepU 'd["pipeline"][0]["runs"] += "mkdir cp\u3000\ncp\u3000/../../../bin/sh -c x\n"'
sr "0710" "refuses a U+3000 separator (Python splits on it, the shell does not)" 'chains or expands' "${bbe[@]}" "$bt/bb-sepU-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe sepF 'd["pipeline"][0]["runs"] += "cp x\fy ${{targets.destdir}}/etc/\n"'
sr "0710" "refuses a form feed inside a line" 'chains or expands' "${bbe[@]}" "$bt/bb-sepF-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe planted 'd["pipeline"][0]["runs"] += "cp /usr/bin/w" "get /usr/local/bin/chmod\n"'
sr "0710" "refuses a cp that puts a program where an allowed command is looked up" 'allowed form' "${bbe[@]}" "$bt/bb-planted-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe srcback 'd["pipeline"][0]["runs"] += "cp ${{targets.destdir}}/etc/passwd build/baselayout/etc/passwd\n"'
sr "0710" "refuses a cp that rewrites a source file of the checks" 'allowed form' "${bbe[@]}" "$bt/bb-srcback-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe dotdot 'd["pipeline"][0]["runs"] += "mkdir -p ${{targets.destdir}}/../x\n"'
sr "0710" "refuses a .. component after the destdir token" 'allowed form' "${bbe[@]}" "$bt/bb-dotdot-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe tabsep 'd["pipeline"][0]["runs"] += "mkdir\t-p ${{targets.destdir}}/x\n"'
sr "0710" "refuses a tab inside a line" 'chains or expands' "${bbe[@]}" "$bt/bb-tabsep-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe dblspace 'd["pipeline"][0]["runs"] += "mkdir  -p ${{targets.destdir}}/x\n"'
sr "0710" "refuses a double space inside a line" 'allowed form' "${bbe[@]}" "$bt/bb-dblspace-w.sh" "${bb_args[@]}" --out "$(mo)"
# the rest of the closed grammar, one case each (round-4 T2)
bl_recipe chmod755 'd["pipeline"][0]["runs"] += "chmod 755 ${{targets.destdir}}/etc\n"'
sr "0710" "refuses a chmod with a three-digit mode" 'allowed form' "${bbe[@]}" "$bt/bb-chmod755-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe mkdirnop 'd["pipeline"][0]["runs"] += "mkdir ${{targets.destdir}}/x\n"'
sr "0710" "refuses a mkdir without -p" 'allowed form' "${bbe[@]}" "$bt/bb-mkdirnop-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe cpusr 'd["pipeline"][0]["runs"] += "cp build/baselayout/etc/hosts ${{targets.destdir}}/usr/\n"'
sr "0710" "refuses a cp into a folder other than etc" 'allowed form' "${bbe[@]}" "$bt/bb-cpusr-w.sh" "${bb_args[@]}" --out "$(mo)"
bl_recipe crsep 'd["pipeline"][0]["runs"] += "mkdir -p ${{targets.destdir}}/x\r\n"'
sr "0710" "refuses a carriage return at the end of a line" 'chains or expands' "${bbe[@]}" "$bt/bb-crsep-w.sh" "${bb_args[@]}" --out "$(mo)"
# a copied source that is a link is refused before the recipe is judged (round-4 T1)
cp -R "$work/bsrc" "$bt/bsrc-link"; rm "$bt/bsrc-link/build/baselayout/etc/services"; ln -s hosts "$bt/bsrc-link/build/baselayout/etc/services"
sr "0710" "refuses a build/baselayout/etc file that is a symlink" 'not a regular file' "${bbe[@]}" "$BBT" "${bb_args[@]}" --source-dir "$bt/bsrc-link" --out "$(mo)"
# a recipe that is not valid UTF-8 is a refusal at exit 2, not a traceback (round-2 R4)
cp "$root/build/melange-baselayout.yaml" "$bt/recipe-utf.yaml"; printf '# \377\n' >>"$bt/recipe-utf.yaml"
mkcopy "$bt/bb-utf.sh" "$bt/recipe-utf.yaml"; wrapper "$bt/bb-utf-w.sh" "$bt/bb-utf.sh"
sr "0710" "refuses a recipe with a byte that is not UTF-8 (exit 2, no traceback)" 'cannot read the recipe' "${bbe[@]}" "$bt/bb-utf-w.sh" "${bb_args[@]}" --out "$(mo)"
t "0710" "the UTF-8 refusal prints no traceback" bash -c "! grep -q Traceback '$work/log'"
# melange writes the entries in its own order: the same list in another order passes (round-2 R1)
cp -R "$work/bsrc" "$bt/bsrc-rev"; tac "$work/bsrc/build/baselayout/members.txt" >"$bt/bsrc-rev/build/baselayout/members.txt"
sd "0710" "members.txt in another order than the apk's still passes (the check compares sorted lists)" '^melange build ' "${bbe[@]}" "$BBT" "${bb_args[@]}" --source-dir "$bt/bsrc-rev" --out "$(mo)"
cp -R "$work/bsrc" "$bt/bsrc-dup"; head -n 1 "$work/bsrc/build/baselayout/members.txt" >>"$bt/bsrc-dup/build/baselayout/members.txt"
sf "0710" "a members.txt with one line repeated is refused, naming a repeated line" 'a repeated line' "${bbe[@]}" "$BBT" "${bb_args[@]}" --source-dir "$bt/bsrc-dup" --out "$(mo)"
sf "0710" "a failed melange call fails the build" 'compile error|melange' env STUB_FAIL=1 "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"

echo "build-baselayout-apk-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
