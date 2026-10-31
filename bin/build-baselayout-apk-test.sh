#!/usr/bin/env bash
# proves: REQ-IMAGE-001-AC16
# Tests of bin/build-baselayout-apk.sh (0710 chain part a): the sealed melange build of build/melange-baselayout.yaml. Every
# assertion runs offline against PATH stubs, like bin/build-apk-test.sh: nothing here calls a real sudo, unshare or melange.
# The production script has no test hook: the tests run a COPY in which exactly the lines ending in TEST-SUBST are replaced
# and which is checked to differ in no other line.
. "$(cd "$(dirname "$0")" && pwd)/melange-apko-lib.sh"
cd "$root"
unset GITHUB_ACTIONS
BB="$root/bin/build-baselayout-apk.sh"
cat >"$work/mkcopy.py" <<'PY'
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
  python3 "$work/mkcopy.py" "$BB" "$1" \
    'PY3=${TEST_PY3:-'"$(command -v python3)"'}' 'GIT=${TEST_GIT:-'"$(command -v git)"'}' 'SUDO=${TEST_SUDO:-'"$stubs"'/sudo}' \
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
mkcopy "$work/bb-copy.sh" "$root/build/melange-baselayout.yaml"; wrapper "$work/bb.sh" "$work/bb-copy.sh"
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
mkcopy "$work/bb-nokey.sh" "$root/build/melange-baselayout.yaml"; wrapper "$work/bb-nokey-w.sh" "$work/bb-nokey.sh"
( cd "$work/nokey" && mkdir -p bin build/keys && cp "$root/bin/build-baselayout-apk.sh" "$root/bin/build-apk-helper.py" bin/ && cp "$root/build/sealed-env.json" build/ ) 2>/dev/null
sr "0710" "refuses when the committed assembly key is missing" 'assembly key' bash -c "cd '$work/nokey' && exec env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 '$work/bb-nokey-w.sh' ${bb_args[*]} --out '$work/nokey-out'"
mkcopy "$work/bb-other.sh" "$root/build/melange.yaml"; wrapper "$work/bb-other-w.sh" "$work/bb-other.sh"
sr "0710" "refuses another recipe: the package must be fscache-baselayout" 'fscache-baselayout' "${bbe[@]}" "$work/bb-other-w.sh" "${bb_args[@]}" --out "$(mo)"
mkcopy "$work/bb-ns.sh" "$root/build/melange-baselayout.yaml"; sed -i 's/--namespace fosterstack/--namespace evil/' "$work/bb-ns.sh"; wrapper "$work/bb-ns-w.sh" "$work/bb-ns.sh"
sr "0710" "refuses a melange call whose namespace is not fosterstack" 'refusing the melange call' "${bbe[@]}" "$work/bb-ns-w.sh" "${bb_args[@]}" --out "$(mo)"
sed -e 's/^ca-certificates-bundle=.*//' "$root/build/locks/melange.lock" >"$work/lock-short"
sr "0710" "refuses a melange lock the recipe does not agree with, both ways" 'lock' "${bbe[@]}" "$BBT" "${bb_args[@]}" --melange-lock "$work/lock-short" --out "$(mo)"
o="$(mo)"; $RUNNER "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$o"
t "0710" "the run writes the apk under OUT/ARCH, signed by the assembly key" bash -c "[ -f '$o/x86_64/fscache-baselayout-0.3.0-r0.apk' ] && [ \"\$(python3 -I -B '$AT' signer '$o/x86_64/fscache-baselayout-0.3.0-r0.apk')\" = assembly.rsa.pub ]"
t "0710" "the run writes inputs-manifest-baselayout.json beside the apk" bash -c "python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d' '$o/inputs-manifest-baselayout.json'"
t "0710" "the run writes no fscache module SBOM and no inputs-manifest.json (those are the fscache apk's)" \
  bash -c "[ ! -e '$o/fscache-modules.spdx.json' ] && [ ! -e '$o/inputs-manifest.json' ]"
sf "0710" "an apk signed by another key is refused" 'signed by' env STUB_SIGNER=other.rsa.pub "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"
sf "0710" "an apk whose etc/passwd differs from build/baselayout/etc/passwd is refused" 'passwd' env STUB_BL_BAD=etc/passwd "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"
sf "0710" "an apk that ships a CA bundle file is refused" 'CA bundle|ca-certificates' env STUB_BL_BUNDLE=1 "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"
sf "0710" "a failed melange call fails the build" 'compile error|melange' env STUB_FAIL=1 "${bbe[@]}" "$BBT" "${bb_args[@]}" --out "$(mo)"

echo "build-baselayout-apk-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
