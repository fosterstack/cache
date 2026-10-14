#!/usr/bin/env bash
# proves: REQ-BUILDAPK-001-AC1, REQ-BUILDAPK-001-AC2, REQ-BUILDAPK-001-AC3, REQ-BUILDAPK-001-AC4, REQ-BUILDAPK-001-AC5, REQ-BUILDAPK-001-AC6, REQ-BUILDAPK-001-AC7, REQ-BUILDAPK-001-AC8
# Tests of the PR: melange recipes, the apk build driver, release signing and the key files.
# Split mechanically from the original suite: the sections between the markers are copied byte for byte, the harness is
# bin/melange-apko-lib.sh. Every assertion runs offline against PATH stubs; nothing here calls a real sudo, sysctl,
# unshare, melange or apko (the harness refuses to run on a non-Linux host unless the stubs are in front).
. "$(cd "$(dirname "$0")" && pwd)/melange-apko-lib.sh"
cd "$root"   # the driver runs from the repository root only (it names its helpers by literal repo-relative paths)
# The production scripts have NO test hook (REQ-BUILDAPK-001-AC3): the tests below run COPIES of bin/build-apk.sh and bin/release-sign-apks.sh in
# which exactly the lines ending in TEST-SUBST are replaced (tool locations, the sealed data file, the recipes, the keys directory) and which are
# checked to differ in no other line. The copies take their stubs and per-call settings from TEST_* variables and a sealed environment the
# wrapper writes from the harness's STUB_/FAKE_ variables: that is the harness's business, never the production script's.
cat >"$work/mkcopy.py" <<'PY'
import re, sys
src, out = sys.argv[1:3]
subst = dict(a.split("=", 1) for a in sys.argv[3:])
lines = open(src).read().split("\n")
seen, res = set(), []
for ln in lines:
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
printf '#!/bin/sh\nif command -v sha256sum >/dev/null 2>&1; then exec sha256sum "$@"; else exec shasum -a 256 "$@"; fi\n' >"$work/sha256sum"; chmod +x "$work/sha256sum"   # the copy's SHA256SUM (macOS has shasum only)
python3 "$work/mkcopy.py" "$root/bin/build-apk.sh" "$work/ba-copy.sh" \
  'PY3=${TEST_PY3:-'"$(command -v python3)"'}' 'GIT=${TEST_GIT:-'"$(command -v git)"'}' 'SUDO=${TEST_SUDO:-'"$stubs"'/sudo}' \
  'UNSHARE=${TEST_UNSHARE:-'"$stubs"'/unshare}' 'MELANGE=${TEST_MELANGE:-'"$stubs"'/melange}' 'SEALED_ENV=$TEST_SEALED_ENV' \
  'GO_TOOL=${TEST_GO:-'"$stubs"'/go}' 'SHA256SUM=${TEST_SHA256SUM:-'"$work"'/sha256sum}' 'ENVBIN='"$(command -v env)" \
  'RECIPE_STANDARD=${TEST_RECIPE:-$PWD/build/melange.yaml}' 'RECIPE_FIPS=${TEST_RECIPE:-$PWD/build/melange-fips.yaml}' || { echo "FIXTURE SETUP FAILED: build-apk copy"; exit 1; }
cat >"$work/ba.sh" <<EOF
#!/bin/bash
# the test wrapper of bin/build-apk.sh: --recipe X becomes TEST_RECIPE, the harness's STUB_/FAKE_ variables become entries of a sealed data file
args=(); while [ \$# -gt 0 ]; do case "\$1" in --recipe) export TEST_RECIPE="\$2"; shift 2;; *) args+=("\$1"); shift;; esac; done
export TEST_SEALED_ENV="$work/sealed-test.json"
python3 - "\$TEST_SEALED_ENV" <<'PYW'
import json, os, sys
closed = {"PATH": os.environ["PATH"], "HOME": "/root", "LC_ALL": "C"}
for k, v in os.environ.items():
    if k.startswith(("STUB_", "FAKE_")) or k in ("CALLS", "ImageOS", "ImageVersion"):
        closed[k] = v
json.dump({"closed": closed, "from_environment": ["SOURCE_DATE_EPOCH"]}, open(sys.argv[1], "w"))
PYW
exec bash "$work/ba-copy.sh" "\${args[@]}"
EOF
chmod +x "$work/ba.sh"; BA_PROD=$BA; BA="$work/ba.sh"
export FSCACHE_ROOT="$root"   # lib.mkapk signs a fixture apk with the committed (non-secret) assembly key found here
mkdir -p "$work/keysfx"
python3 "$work/mkcopy.py" "$root/bin/release-sign-apks.sh" "$work/rs-copy.sh" \
  'here='"$root"'/bin' 'root='"$root" 'PY3=${TEST_PY3:-'"$(command -v python3)"'}' 'OPENSSL='"$(command -v openssl)" 'MELANGE=${TEST_MELANGE:-'"$stubs"'/melange}' 'KEYS_DIR='"$work"'/keysfx' \
  || { echo "FIXTURE SETUP FAILED: release-sign copy"; exit 1; }
chmod +x "$work/rs-copy.sh" "$work/ba-copy.sh"
# ---- begin verbatim sections ----
# ---- P4 review round 1 (Opus): setup added after the mechanical split --------------------------------------------------------------
rev=$(git -C "$src" rev-parse HEAD)
sb=$(mktemp -d "$work/sbom-rev.XXXXXX")   # this file's own scratch, made by mktemp: each fixture SBOM gains its revision line in a copy, then replaces the original
for f in "$fx"/sbom/*.txt; do grep -q 'vcs.revision' "$f" || { cp "$f" "$sb/x" && printf '\tbuild\tvcs.revision=%s\n' "$rev" >>"$sb/x" && mv "$sb/x" "$f"; }; done
python3 - "$work" "$fx/pair" <<'P'
import sys
sys.path.insert(0, sys.argv[1]); import lib
files = {"usr/bin/fscache": b"binA", "usr/share/x": b"same"}
lib.mkapk(sys.argv[2] + "/ctrl-post-install.apk", "fscache", "0.3.0-r0", files, control={".post-install": b"#!/bin/sh\necho evil\n"})
P
# (setup copied from a section of another PR's file)
pr="$fx/pair"
# ===== rule 11 12 13 15 24: the melange recipes (static) =========================================================
M="$root/build/melange.yaml" MF="$root/build/melange-fips.yaml"
t "rule 11" "melange.yaml: package fscache, version @VERSION@, epoch 0, license" y mel-name "$M" fscache
t "rule 11" "melange-fips.yaml: package fscache-fips" y mel-name "$MF" fscache-fips
t "rule 11" "melange.yaml builds ./cmd/fscache with -trimpath into usr/bin/fscache, no FROM" y mel-build "$M"
t "rule 11" "melange-fips.yaml builds ./cmd/fscache with -trimpath, no FROM" y mel-build "$MF"
t "rule 12" "melange.yaml: GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=0 GOTOOLCHAIN=local, no -mod=mod, no downloads" y mel-env "$M"
t "rule 12" "melange-fips.yaml: the same environment" y mel-env "$MF"
t "rule 12" "melange.yaml: Go from go.dev, one sha256-pinned fetch per arch, no Wolfi go apk, the fetch tool present, go.mod go <= archived Go" y mel-go "$M"   # fetch.yaml:4-6 (needs the fetch tool), :78-80 (a checksum is required), :85-90 (cache lookup), :108-111 (verification)
t "rule 12" "melange-fips.yaml: the same Go pins" y mel-go "$MF"
t "rule 12" "melange.yaml: each go.dev fetch step runs only on its own architecture (if: build.arch)" y mel-fetch-arch "$M"
t "rule 12" "melange-fips.yaml: the same" y mel-fetch-arch "$MF"
t "rule 12" "melange.yaml: /usr/local/go is created before the first fetch (tar -C needs it)" y mel-fetch-dir "$M"
t "rule 12" "melange-fips.yaml: the same" y mel-fetch-dir "$MF"
t "rule 24" "melange.yaml: the fetched Go tarball is deleted (it would leave the tree modified)" y mel-fetch-delete "$M"
t "rule 24" "melange-fips.yaml: the same" y mel-fetch-delete "$MF"
t "rule 13" "melange.yaml has no GOFIPS140 anywhere" y mel-fips "$M" standard
t "rule 13" "melange-fips.yaml sets GOFIPS140=v1.0.0" y mel-fips "$MF" fips
t "rule 13" "melange-fips.yaml proves the built binary records GOFIPS140=v1.0.0-c2097c7c (go version -m)" y mel-fipsproof "$MF"   # melange pkg/sca/sca.go:732 recognises exactly v1.0.0-c2097c7c
t "rule 21" "bin/gen-recipes.py --check passes on the committed pair: both recipes are exactly the generator's output from build/melange.yaml.tmpl, so they differ only in name, description and the two FIPS lines" python3 "$root/bin/gen-recipes.py" --check
rm -rf "$work/pin"; mkdir -p "$work/pin"; cp "$root/build/melange.yaml.tmpl" "$work/pin/t.tmpl"; cp "$root/build/melange.yaml" "$work/pin/a.yaml"; cp "$root/build/melange-fips.yaml" "$work/pin/b.yaml"; printf '#' >>"$work/pin/t.tmpl"
fails "rule 21" "bin/gen-recipes.py: a ONE-BYTE edit of a copy of the REAL template fails --check naming the pin (the constant TEMPLATE_SHA256 in the generator)" 'update TEMPLATE_SHA256 in the same reviewed change' python3 "$root/bin/gen-recipes.py" --template "$work/pin/t.tmpl" --regular "$work/pin/a.yaml" --fips "$work/pin/b.yaml" --check
t "rule 21" "the committed template carries the review checklist at its top (the human and the reviewer pass)" bash -c "grep -q 'TEMPLATE CHECKLIST' '$root/build/melange.yaml.tmpl' && grep -q 'NEGATIVE EXAMPLES' '$root/build/melange.yaml.tmpl'"
t "rule 15" "melange.yaml build environment: no repositories or keyring of its own beyond local paths, only the go.dev fetch uri" y mel-local "$M"
t "rule 15" "melange-fips.yaml: the same" y mel-local "$MF"
t "rule 15" "melange.yaml build packages pinned name=version incl. git, busybox, ca-certificates-bundle, the fetch tool" y mel-pinned "$M"
t "rule 15" "melange-fips.yaml build packages pinned" y mel-pinned "$MF"
t "rule 24" "melange.yaml: refs recreated, git present, safe.directory, caches under /tmp, excludes, no -buildvcs=false" y mel-stamp "$M"
t "rule 24" "melange-fips.yaml: the same four fixes" y mel-stamp "$MF"
t "rule 24" "melange.yaml reads go version -m and fails on (devel) or modified" y mel-proof "$M"
t "rule 24" "melange-fips.yaml reads go version -m and fails on (devel) or modified" y mel-proof "$MF"
t "rule 20" "melange.yaml writes go version -m to usr/share/fscache/buildinfo.txt in the apk (input of the module SBOM)" y mel-buildinfo "$M"
t "rule 20" "melange-fips.yaml writes the same file" y mel-buildinfo "$MF"

# ===== build-apk.sh: interface, refusals ===============================================================================
ba_args=(--variant standard --arch x86_64 --version 0.3.0 --source-dir "$src" --repo "$fx/envrepo" --keyring "$kr"
  --go-archive "$fx/archive/go" --melange-lock "$fx/melange.lock" --recipe "$fx/melange.yaml")
bae=(env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64)
t "rule 38a" "build-apk.sh exists and is executable" test -x "$BA"
sd "rule 11" "x86_64 build on an x86_64 host runs melange build" '^melange build ' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sd "rule 11" "aarch64 build on an aarch64 host runs melange build" '^melange build .*--arch aarch64' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=aarch64 "$BA" "${ba_args[@]}" --arch aarch64 --out "$(mo)"
sr "rule 11" "refuses an arch other than the host's (native runner, no emulation): aarch64 on x86_64" 'host|native' "${bae[@]}" "$BA" "${ba_args[@]}" --arch aarch64 --out "$(mo)"
sr "rule 11" "refuses x86_64 on an aarch64 host" 'host|native' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=aarch64 "$BA" "${ba_args[@]}" --out "$(mo)"
sr "rule 11" "refuses an arch that is not an apk arch name (amd64)" 'arch' "${bae[@]}" "$BA" "${ba_args[@]}" --arch amd64 --out "$(mo)"
sr "rule 31" "refuses without SOURCE_DATE_EPOCH" SOURCE_DATE_EPOCH env FAKE_UNAME=x86_64 "$BA" "${ba_args[@]}" --out "$(mo)"
sr "rule 31" "refuses a non-numeric SOURCE_DATE_EPOCH" SOURCE_DATE_EPOCH env SOURCE_DATE_EPOCH=yesterday FAKE_UNAME=x86_64 "$BA" "${ba_args[@]}" --out "$(mo)"
sr "rule 17" "refuses --signing-key (the driver takes no key)" 'signing' "${bae[@]}" "$BA" "${ba_args[@]}" --signing-key "$fx/keyring/assembly.rsa.pub" --out "$(mo)"
sr "rule 23" "refuses a run that holds the release key (APK_RELEASE_SIGNING_KEY in the environment)" 'release|must not' "${bae[@]}" APK_RELEASE_SIGNING_KEY=canary "$BA" "${ba_args[@]}" --out "$(mo)"
sr "rule 38a" "refuses GOPROXY set to a live proxy" GOPROXY "${bae[@]}" GOPROXY=https://proxy.golang.org "$BA" "${ba_args[@]}" --out "$(mo)"
sr "rule 38a" "refuses a proxy in the environment" proxy "${bae[@]}" HTTPS_PROXY=http://127.0.0.1:3128 "$BA" "${ba_args[@]}" --out "$(mo)"
sr "rule 15" "refuses an https repository" 'local' "${bae[@]}" "$BA" "${ba_args[@]}" --repo https://packages.wolfi.dev/os --out "$(mo)"
sr "rule 15" "refuses a file:// repository" 'local' "${bae[@]}" "$BA" "${ba_args[@]}" --repo "file://$fx/envrepo" --out "$(mo)"
sr "rule 15" "refuses a repository directory that does not exist" 'repo' "${bae[@]}" "$BA" "${ba_args[@]}" --repo "$work/nope" --out "$(mo)"
sr "rule 15" "refuses a cache as the only input (--apk-cache-dir, no --repo)" 'repo' "${bae[@]}" "$BA" --variant standard --arch x86_64 --version 0.3.0 --source-dir "$src" --keyring "$kr" --go-archive "$fx/archive/go" --melange-lock "$fx/melange.lock" --recipe "$fx/melange.yaml" --apk-cache-dir "$work/cache" --out "$(mo)"
sr "rule 19" "refuses a missing keyring" 'keyring' "${bae[@]}" "$BA" "${ba_args[@]}" --keyring "$work/nokey" --out "$(mo)"
sr "rule 38a" "refuses when vendor/ is deleted" 'vendor' bash -c "d=\$(mktemp -d -p '$work'); cp -R '$src/.' \$d/; rm -rf \$d/vendor; env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 '$BA' ${ba_args[*]} --source-dir \$d --out $(mo)"
sr "rule 24" "refuses a source dir without .git (the stamp would say (devel))" 'git' bash -c "d=\$(mktemp -d -p '$work'); cp -R '$src/.' \$d/; rm -rf \$d/.git; env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 '$BA' ${ba_args[*]} --source-dir \$d --out $(mo)"
for v in v0.3.0 0.3 '(devel)' 0.3.0-rc.1; do
  sr "rule 24" "refuses version '$v' (X.Y.Z, X.Y.Z-rcN or the snapshot version only)" 'version' "${bae[@]}" "$BA" "${ba_args[@]}" --version "$v" --out "$(mo)"; done
sr "rule 12" "refuses when the archive has no Go tarball for the host arch" 'go' "${bae[@]}" "$BA" "${ba_args[@]}" --go-archive "$work/empty-go" --out "$(mo)"
mkdir -p "$work/badgo"; echo tampered >"$work/badgo/go1.27.2.linux-amd64.tar.gz"; echo tampered >"$work/badgo/go1.27.2.linux-arm64.tar.gz"
sr "rule 12" "refuses a Go tarball whose sha256 differs from the recipe pin" 'checksum|sha256' "${bae[@]}" "$BA" "${ba_args[@]}" --go-archive "$work/badgo" --out "$(mo)"
printf 'busybox=1.37.0-r5\ngit=2.50.1-r0\n' >"$work/short.lock"
sr "rule 15" "refuses when the recipe's pinned environment differs from the melange lock" 'lock' "${bae[@]}" "$BA" "${ba_args[@]}" --melange-lock "$work/short.lock" --out "$(mo)"
# near-miss locks: every lock line is LONGER than the pin that wants it (a suffix, then a prefix); a substring match would accept them, a whole-line match must not
sed 's/$/9/' "$fx/melange.lock" >"$work/near-suffix.lock"; sed 's/^/x/' "$fx/melange.lock" >"$work/near-prefix.lock"
sed 's/\./x/' "$fx/melange.lock" >"$work/near-dot.lock"   # a dot replaced by another character: a regex match (grep -x without -F) would accept it
printf 'extra-package=1.0-r0\n' | cat "$fx/melange.lock" - >"$work/extra.lock"
sr "rule 15" "refuses a melange lock with a line the recipe does not pin (both ways)" 'both ways|do not pin|does not pin' "${bae[@]}" "$BA" "${ba_args[@]}" --melange-lock "$work/extra.lock" --out "$(mo)"
for nl in near-suffix near-prefix near-dot; do
  sr "rule 15" "refuses a melange lock whose lines only CONTAIN the recipe's pins ($nl): whole-line match, message 'does not have it'" 'does not have it' "${bae[@]}" "$BA" "${ba_args[@]}" --melange-lock "$work/$nl.lock" --out "$(mo)"
done

# ===== build-apk.sh: the melange call (rules 12 16 17 19 20 22 31 38a) ==================================================
sd "rule 38a" "the sysctl change is done with sudo" '^sudo sysctl -w kernel\.apparmor_restrict_unprivileged_userns=0' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
ordered "rule 38a" "sysctl first, then the sealed melange call" '^sudo sysctl -w kernel\.apparmor_restrict_unprivileged_userns=0' '^sudo .*unshare -n .*melange build '
sd "rule 38a" "melange runs directly under sudo unshare -n (the network cut at the kernel)" '^sudo .*unshare -n .*melange build ' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sn "rule 38a" "no docker, podman, kubectl, --privileged or container image anywhere in the calls" 'docker|podman|kubectl|--privileged|cgr\.dev|@sha256' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sd "rule 38a" "melange uses the bubblewrap runner" '^melange build .*--runner bubblewrap' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"   # melange pkg/cli/build.go:68, pkg/container/bubblewrap_runner.go:43
sn "rule 38a" "no network address in the melange call, no proxy" '://|[Pp][Rr][Oo][Xx][Yy]' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sd "rule 12" "the Go tarball is pre-seeded in the cache dir as sha256:<hex> (melange --cache-dir, fetch finds it offline)" "^melange build .*--cache-dir " "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"   # build.go:1028-1040 mounts it at /var/cache/melange; pipelines/fetch.yaml:85-90
gohex=$(python3 -c "import hashlib;print(hashlib.sha256(open('$fx/archive/go/go1.27.2.linux-amd64.tar.gz','rb').read()).hexdigest())")
sd "rule 12" "the cache dir held sha256:<hex of the amd64 tarball> when melange ran" "^ENV CACHE=.*sha256:$gohex" "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sd "rule 15" "melange gets the archive repository (--repository-append) and the Wolfi key (--keyring-append)" "^melange build .*--repository-append $fx/envrepo .*--keyring-append $kr|^melange build .*--keyring-append $kr .*--repository-append $fx/envrepo" "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"   # pkg/cli/build.go:69-70
sd "rule 22" "melange signs with the committed assembly key" '^melange build .*--signing-key [^ ]*build/keys/assembly\.rsa( |$)' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"   # pkg/cli/build.go:55
sn "rule 17" "melange is never given any other signing key" '--signing-key [^ ]*(release|signing\.rsa|melange\.rsa)' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sd "rule 31" "melange gets --build-date from SOURCE_DATE_EPOCH ($SDE)" "^melange build .*--build-date $ISO" "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"   # build.go:47; SOURCE_DATE_EPOCH wins, build.go:279
sd "rule 31" "melange also sees SOURCE_DATE_EPOCH in its environment after sudo's env reset" "^ENV SDE=$SDE" "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sd "rule 31" "second SOURCE_DATE_EPOCH value (0) gives --build-date 1970-01-01T00:00:00Z" '^melange build .*--build-date 1970-01-01T00:00:00Z' env SOURCE_DATE_EPOCH=0 FAKE_UNAME=x86_64 "$BA" "${ba_args[@]}" --out "$(mo)"
sn "rule 19" "no --ignore-signatures / --allow-untrusted / --insecure in any call" 'ignore-signatures|allow-untrusted|--insecure' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sn "rule 20" "melange's own SBOM is not disabled" 'disable-sbom|sbom=false|--sbom[ =]false' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sn "rule 31" "the recipe is passed to melange as a bare file name (cwd = the render dir): a temp path would enter the apk's own SBOM and break byte-reproducibility" '^melange build [^ ]*/[^ ]*\.yaml' "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"   # real-run finding Oct 9: the SBOM name/SPDXID held /tmp/tmp.XXXX/render/melange.yaml
sn "rule 23" "no token, secret or key variable reaches melange's environment" '^ENV SECRETS=[1-9]' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 GITHUB_TOKEN=canary-token ACTIONS_ID_TOKEN_REQUEST_TOKEN=canary "$BA" "${ba_args[@]}" --out "$(mo)"
sd "rule 11" "the fips variant is built from the fips recipe" '^melange build .*melange-fips\.yaml|^melange build .*melange-fips[^ ]*\.yaml' "${bae[@]}" "$BA" "${ba_args[@]}" --variant fips --recipe "$fx/melange-fips.yaml" --out "$(mo)"
t "rule 11" "build-apk.sh picks build/melange.yaml for standard and build/melange-fips.yaml for fips by default" bash -c "grep -q 'build/melange.yaml\|melange\.yaml' '$BA_PROD' && grep -q 'melange-fips.yaml' '$BA_PROD'"
# rendering
rd="$work/render"; mkdir -p "$rd"
t "rule 11" "--render-dir writes the recipe with the version, no @VERSION@ left" bash -c "
  env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 PATH='$stubs':\$PATH CALLS='$CALLS' STUB_LIB='$work/lib.py' '$BA' ${ba_args[*]} --render-dir '$rd' --out $(mo) >/dev/null 2>&1; f=\$(ls '$rd'/*.yaml | head -1); test -n \"\$f\" && grep -Eq '^ *version: *\"?0\\.3\\.0\"?\$' \$f && ! grep -q @VERSION@ \$f"
# outputs
o1=$(mo); run_s "${bae[@]}" "$BA" "${ba_args[@]}" --out "$o1"
t "rule 11" "the build leaves the apk in OUT/<arch>/ with an index" bash -c "test -f '$o1/x86_64/fscache-0.3.0-r0.apk' && test -f '$o1/x86_64/APKINDEX.tar.gz'"
t "rule 22" "the apk built by Build is signed with the assembly key (apk-tool signer)" bash -c "test \"\$(python3 '$AT' signer '$o1/x86_64/fscache-0.3.0-r0.apk')\" = assembly.rsa.pub"
sf "rule 22" "a build whose apk carries any other signer is refused" 'signer|assembly' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_SIGNER=release.rsa.pub "$BA" "${ba_args[@]}" --out "$(mo)"
t "rule 20" "the Go module list SBOM is written next to the apk, with the vendored modules" bash -c "python3 - '$o1/fscache-modules.spdx.json' <<'P'
import json, sys
d = json.load(open(sys.argv[1])); n = {(p['name'], p.get('versionInfo')) for p in d['packages']}
assert ('github.com/example/x', 'v1.0.0') in n, n
P"
t "rule 15" "OUT/inputs-manifest.json is written" test -s "$o1/inputs-manifest.json"
cp "$o1/inputs-manifest.json" "$work/o1-inputs-manifest.json"   # a copy under $work: the cases below run the next line against variants of it
# the manifest compared as parsed JSON, each pin as a whole value (Codex B round 1, pull request 297: a substring grep accepted r50 for r5 and any character
# for a dot). Both lists must equal the melange lock the build was given, entry for entry; a repeated key is refused (a later copy would win).
cat >"$work/inputs-manifest-check.py" <<'P'
import json, sys   # no assert statement: python3 -O or PYTHONOPTIMIZE would skip it and pass
def once(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        sys.exit("a repeated key: %r" % (pairs,))
    return dict(pairs)
lock = sorted(l.strip() for l in open(sys.argv[2]) if l.strip())
if "busybox=1.37.0-r5" not in lock:
    sys.exit("the melange lock is not the fixture's: %r" % lock)
d = json.load(open(sys.argv[1]), object_pairs_hook=once)
if d != {"apk_environment": lock, "melange_lock": lock}:
    sys.exit("the manifest is not exactly the melange lock in both lists: %r" % (d,))
P
t "rule 15" "the inputs manifest holds exactly the melange lock and the environment read back from the apk (parsed JSON, whole values)" python3 "$work/inputs-manifest-check.py" "$work/o1-inputs-manifest.json" "$fx/melange.lock"
# ---- Codex B round 1 on pull request 297 (LOW): the manifest assertion above must hold the pins EXACTLY. Each case below runs that rule 15 line AS WRITTEN
# (found in this file by the manifest path it reads) with $work pointing at a scratch dir that holds a variant of the REAL manifest of this build. Every
# variant is made from the manifest's own lists by position (no package is named here): first = the first entry of each list, last = the last one.
cat >"$work/im-variant.py" <<'P'
import json, sys
src, dst, case = sys.argv[1:4]
d = json.load(open(src)); L = d["melange_lock"]
both = lambda f: {k: f(list(v)) for k, v in d.items()}
def edit(i, g): return lambda l: l[:i % len(l)] + [g(l[i % len(l)])] + l[i % len(l) + 1:]
out = {
    "exact": lambda: json.dumps(d, indent=1, sort_keys=True),
    "exact-compact": lambda: json.dumps(d, separators=(",", ":"), sort_keys=True),
    "codex-repro": lambda: json.dumps({"melange": [L[0] + "0", L[-1] + "1"]}, separators=(",", ":")),
    "first-suffix-0": lambda: json.dumps(both(edit(0, lambda e: e + "0")), indent=1, sort_keys=True),
    "last-suffix-1": lambda: json.dumps(both(edit(-1, lambda e: e + "1")), indent=1, sort_keys=True),
    "first-dot-to-x": lambda: json.dumps(both(edit(0, lambda e: e.replace(".", "x", 1))), indent=1, sort_keys=True),
    "first-prefix-x": lambda: json.dumps(both(edit(0, lambda e: "x" + e)), indent=1, sort_keys=True),
    "first-as-last-suffix-0": lambda: json.dumps(both(lambda l: l[1:] + [l[0] + "0"]), indent=1, sort_keys=True),
    "first-missing": lambda: json.dumps(both(lambda l: l[1:]), indent=1, sort_keys=True),
    "last-missing": lambda: json.dumps(both(lambda l: l[:-1]), indent=1, sort_keys=True),
    "env-only-first-suffix-0": lambda: json.dumps(dict(d, apk_environment=edit(0, lambda e: e + "0")(list(d["apk_environment"]))), indent=1, sort_keys=True),
    "empty": lambda: "",
    "repeated-key": lambda: '{"apk_environment": %s, "melange_lock": %s, "melange_lock": %s}' % (json.dumps(d["apk_environment"]), json.dumps(edit(0, lambda e: e + "0")(list(L))), json.dumps(L)),
}[case]()
open(dst, "w").write(out)
P
im_line=$(grep -E '^t "rule 15" .*"\$work/o1-inputs-manifest\.json"' "$root/bin/build-apk-test.sh")
imc() {   # imc RULE TITLE WANT CASE: the rule 15 manifest line, run as written against variant CASE; WANT pass (exit 0) or fail (non-zero)
  local d r=0; d=$(mktemp -d "$work/imc.XXXXXX"); python3 "$work/im-variant.py" "$work/o1-inputs-manifest.json" "$d/o1-inputs-manifest.json" "$4" || { bad "$1" "$2 (variant $4 not made)"; return; }
  cp "$work"/inputs-manifest-check.py "$d/" 2>/dev/null
  work="$d" fx="$fx" bash -c 't() { shift 2; "$@"; }; '"$im_line" </dev/null >/dev/null 2>&1 || r=$?
  if { [ "$3" = pass ] && [ $r -eq 0 ]; } || { [ "$3" = fail ] && [ $r -ne 0 ]; }; then ok; else bad "$1" "$2 (exit $r, wanted $3)"; fi; }
t "rule 15" "exactly one rule 15 line reads the manifest copy (the line the cases below run)" test "$(printf '%s\n' "$im_line" | grep -c .)" -eq 1
imc "rule 15" "manifest assertion: the real manifest passes" pass exact
imc "rule 15" "manifest assertion: the same data as compact JSON passes (the values are compared, not the layout)" pass exact-compact
imc "rule 15" "manifest assertion: the Codex repro (one list, the first pin with 0 appended, the last with 1 appended, compact) fails" fail codex-repro
imc "rule 15" "manifest assertion: the first pin with a digit appended (r5 -> r50) fails" fail first-suffix-0
imc "rule 15" "manifest assertion: the last pin with a digit appended (r0 -> r01) fails" fail last-suffix-1
imc "rule 15" "manifest assertion: a dot of the first pin replaced by another character fails" fail first-dot-to-x
imc "rule 15" "manifest assertion: the first pin with a character in front (xNAME) fails" fail first-prefix-x
imc "rule 15" "manifest assertion: the first pin moved to the end of its list with 0 appended fails" fail first-as-last-suffix-0
imc "rule 15" "manifest assertion: the first pin missing fails" fail first-missing
imc "rule 15" "manifest assertion: the last pin missing fails" fail last-missing
imc "rule 15" "manifest assertion: the apk environment alone holding the first pin with 0 appended fails" fail env-only-first-suffix-0
imc "rule 15" "manifest assertion: an empty manifest fails" fail empty
imc "rule 15" "manifest assertion: a repeated key whose first copy holds the first pin with 0 appended fails (a later copy must not win)" fail repeated-key
# post-build checks of the stamp and the FIPS record
sf "rule 24" "a binary that says (devel) is refused before hand-off" 'devel' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$fx/sbom/devel.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
sf "rule 24" "a binary built from a dirty tree (vcs.modified=true) is refused" 'modified|dirty' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$fx/sbom/dirty.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
sf "rule 20" "a module list that does not match the binary (extra dependency) fails the build" 'example\.org/evil|module|mismatch' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$fx/sbom/extra.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
sf "rule 13" "the fips variant is refused when its binary does not record GOFIPS140=v1.0.0-c2097c7c" 'GOFIPS140|c2097c7c' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$fx/sbom/nofips.txt" "$BA" "${ba_args[@]}" --variant fips --recipe "$fx/melange-fips.yaml" --out "$(mo)"
sd "rule 13" "the fips variant passes when the binary records GOFIPS140=v1.0.0-c2097c7c" '^melange build ' "${bae[@]}" "$BA" "${ba_args[@]}" --variant fips --recipe "$fx/melange-fips.yaml" --out "$(mo)"
printf '\tbuild\tGOFIPS140=v1.0.0-c2097c7c\n' >"$work/stdfips.txt"; cat "$fx/sbom/ok.txt" "$work/stdfips.txt" >"$work/std-with-fips.txt"
sf "rule 13" "the standard variant is refused when its binary records any GOFIPS140" 'GOFIPS140' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/std-with-fips.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
sr "rule 24" "--print-source-date-epoch refuses a dir with no git history" 'git' "$BA" --print-source-date-epoch --source-dir "$work"
so "rule 31" "--print-source-date-epoch gives the commit time of the source dir" "^$SDE\$" "$BA" --print-source-date-epoch --source-dir "$src"
# determinism of the driver (same inputs, same bytes)
oa=$(mo); ob=$(mo); run_s "${bae[@]}" "$BA" "${ba_args[@]}" --out "$oa"; run_s "${bae[@]}" "$BA" "${ba_args[@]}" --out "$ob"
t "rule 31" "two builds of the same inputs give the same apk bytes and the same module SBOM" bash -c "cmp '$oa/x86_64/fscache-0.3.0-r0.apk' '$ob/x86_64/fscache-0.3.0-r0.apk' && cmp '$oa/fscache-modules.spdx.json' '$ob/fscache-modules.spdx.json'"

# release signing: compare Build's and Rebuild's apks, then sign with the stored key
mkdir -p "$work/rsA/x86_64" "$work/rsB/x86_64" "$work/rsC/x86_64"
cp "$pr/a.apk" "$work/rsA/x86_64/fscache-0.3.0-r0.apk"; cp "$pr/a.apk" "$work/rsB/x86_64/fscache-0.3.0-r0.apk"; cp "$pr/c.apk" "$work/rsC/x86_64/fscache-0.3.0-r0.apk"
mkrsa() { openssl genrsa 2048 2>/dev/null >"$1.raw"; if grep -q 'BEGIN PRIVATE KEY' "$1.raw"; then openssl rsa -traditional -in "$1.raw" -out "$1" 2>/dev/null; else mv "$1.raw" "$1"; fi; rm -f "$1.raw"; }
mkrsa "$work/release.rsa"
# release signing compares the key's public half with build/keys/release.rsa.pub: tests use a fixture keys dir (test mode only; recorded in the script's own test-mode gate)
mkdir -p "$work/keysfx"; cp "$root/build/keys/assembly.rsa" "$root/build/keys/assembly.rsa.pub" "$work/keysfx/"; openssl rsa -in "$work/release.rsa" -pubout -out "$work/keysfx/release.rsa.pub" 2>/dev/null
RS_REAL=$RS; RS="$work/rs-copy.sh"
sd "rule 22" "release signing: same contents in Build and Rebuild -> melange sign with the release key" "^melange sign .*--signing-key [^ ]*/key/release\.rsa .*fscache-0\.3\.0-r0\.apk" "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/release.rsa"   # pkg/cli/sign.go:159-174
run_s "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsC" --key "$work/release.rsa"
if [ "$(rc)" != 0 ] && [ "$(rc)" != 127 ] && ! grep -Eq '^melange sign' "$CALLS" && grep -q 'fscache-0.3.0-r0.apk' "$work/log"; then ok; else bad "rule 22" "release signing: contents differ between Build and Rebuild -> refused, nothing signed, apk named"; fi
mkdir -p "$work/rsD"; sr "rule 22" "release signing: a Rebuild directory with no counterpart apk is refused" 'rebuild|missing|counterpart' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsD" --key "$work/release.rsa"
sr "rule 22" "release signing refuses the assembly key (nothing a customer trusts is signed with it)" 'assembly' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$root/build/keys/assembly.rsa"

# ===== rule 17 18: key policy ===========================================================================================
t "rule 17" "build-apk.sh names the committed assembly key (build/keys/assembly.rsa) as the only key it signs with" bash -c "test -f '$BA_PROD' && grep -q 'build/keys/assembly.rsa' '$BA_PROD'"
t "rule 22" "build/keys/assembly.rsa and assembly.rsa.pub start with the NON-SECRET header line, then a PEM block" bash -c "for f in assembly.rsa assembly.rsa.pub; do p='$root/build/keys/'\$f; test -f \$p && head -1 \$p | grep -Fq 'NON-SECRET assembly key, public by design, ratified rule 22; signs nothing a customer trusts' && grep -q -- '-----BEGIN ' \$p || exit 1; done"
t "rule 22" "the assembly key pair and the public release key are committed" bash -c "test -s '$root/build/keys/assembly.rsa' && test -s '$root/build/keys/assembly.rsa.pub' && test -s '$root/build/keys/release.rsa.pub'"
t "rule 15" "build/locks/melange.lock holds name=version lines equal to the recipe's environment" bash -c "python3 - '$root' <<'P'
import sys, yaml
r = sys.argv[1]; want = sorted(yaml.safe_load(open(r + '/build/melange.yaml'))['environment']['contents']['packages'])
got = sorted(l.strip() for l in open(r + '/build/locks/melange.lock') if l.strip())
assert want == got, (want, got)
P"

# ===== rule 40 (advisor reading): a network attempt inside the sealed call is exit 4 ====================================
# se <rule> <desc> <exit> <keyword> <cmd...>: exit status exactly <exit> and the message names the reason
se() { local ac=$1 d=$2 want=$3 kw=$4; shift 4; $RUNNER "$@"; if [ "$(rc)" = "$want" ] && grep -Eqi -- "$kw" "$work/log"; then ok; else bad "$ac" "$d (exit $(rc), wanted $want naming '$kw')"; fi; }
# sx <rule> <desc> <rc-test> <cmd...>: exit status satisfies the test ('ne4' = non-zero, not 4, not 127)
sx() { local ac=$1 d=$2 m=$3; shift 3; $RUNNER "$@"; local r; r=$(rc); if [ "$r" != 0 ] && [ "$r" != 4 ] && [ "$r" != 127 ] && toolrun; then ok; else bad "$ac" "$d (exit $r)"; fi; }
t "rule 40" "bin/net-probe.py exists, connects a socket and exits with the connect errno" bash -c "test -f '$NP' && grep -q 'connect' '$NP' && grep -Eqi 'errno' '$NP'"
bne=(env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64)
se "rule 40" "[advisor reading] build-apk.sh: melange attempts a connection in the sealed namespace -> exit 4, names the network attempt" 4 'network attempt' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_NETATTEMPT=1 "$BA" "${ba_args[@]}" --out "$(mo)"
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_NETATTEMPT=1 "$BA" "${ba_args[@]}" --out "$(mo)"
if [ "$(rc)" = 4 ] && grep -Eq '^sudo .*unshare -n .*net-probe\.py' "$CALLS"; then ok; else bad "rule 40" "[advisor reading] the probe is called as sudo ... unshare -n ... net-probe.py (same namespace setup)"; fi
ordered "rule 40" "[advisor reading] the probe runs after the failed melange call, not before" '^melange build ' '^unshare -n .*net-probe\.py'
sx "rule 40" "[advisor reading] build-apk.sh: a tool that fails for another reason is non-zero but not 4" ne4 env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_FAIL=1 "$BA" "${ba_args[@]}" --out "$(mo)"
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_FAIL=1 "$BA" "${ba_args[@]}" --out "$(mo)"
if [ "$(rc)" != 0 ] && [ "$(rc)" != 127 ] && grep -q '^melange build ' "$CALLS" && ! grep -q 'net-probe' "$CALLS"; then ok; else bad "rule 40" "an ordinary failure (no network text) does not run the probe"; fi
sx "rule 40" "[advisor reading] build-apk.sh: network text but the probe says the namespace is NOT sealed (leaky) -> non-zero, not 4" ne4 env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_NETATTEMPT=1 STUB_UNSHARE_LEAKY=1 "$BA" "${ba_args[@]}" --out "$(mo)"
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 "$BA" "${ba_args[@]}" --out "$(mo)"
if [ "$(rc)" = 0 ] && ! grep -q 'net-probe' "$CALLS"; then ok; else bad "rule 40" "build-apk.sh: a tool that succeeds -> exit 0 and no probe"; fi
# ---- P4 review round 1 (Opus): B1-B4 and residuals R2, R7, R8, plus the rc versions (tests first) -----------------------------------
# B1 (rule 22): the apk Build made and the apk Rebuild made must agree in the CONTROL section too (melange sign signs the whole control)
mkdir -p "$work/rsE/x86_64" "$work/rsF/x86_64"
cp "$fx/pair/ctrl-post-install.apk" "$work/rsE/x86_64/fscache-0.3.0-r0.apk"; cp "$fx/pair/a.apk" "$work/rsF/x86_64/fscache-0.3.0-r0.apk"
run_s "$RS" --build-dir "$work/rsE" --rebuild-dir "$work/rsF" --key "$work/release.rsa"
t "rule 22" "release signing: Build's apk has an extra .post-install (same data) -> refused, apk named, nothing signed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'fscache-0.3.0-r0.apk' '$work/log' && ! grep -q '^melange sign' '$CALLS'"
run_s "$RS" --build-dir "$work/rsF" --rebuild-dir "$work/rsE" --key "$work/release.rsa"
t "rule 22" "release signing: the same difference the other way round (Rebuild has the extra script) is refused too" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q '^melange sign' '$CALLS'"
# R7: a symlinked apk, or an apk only one side has, is refused (fail closed), nothing signed
mkdir -p "$work/rsG/x86_64" "$work/rsH/x86_64"; cp "$fx/pair/a.apk" "$work/rsG/x86_64/fscache-0.3.0-r0.apk"; cp "$fx/pair/b.apk" "$work/rsH/x86_64/fscache-0.3.0-r0.apk"
cp "$fx/pair/a.apk" "$work/rsH/x86_64/fscache-extra-0.3.0-r0.apk"
sr "rule 22" "release signing: an apk only Rebuild has is refused (exit 2, named)" 'extra|counterpart' "$RS" --build-dir "$work/rsG" --rebuild-dir "$work/rsH" --key "$work/release.rsa"
mkdir -p "$work/rsI/x86_64" "$work/rsJ/x86_64"; cp "$fx/pair/a.apk" "$work/rsJ/x86_64/fscache-0.3.0-r0.apk"; ln -s "$fx/pair/a.apk" "$work/rsI/x86_64/fscache-0.3.0-r0.apk"
sr "rule 22" "release signing: a symlinked apk in Build is refused (exit 2, names the symlink)" 'symlink|not a regular file' "$RS" --build-dir "$work/rsI" --rebuild-dir "$work/rsJ" --key "$work/release.rsa"
mkdir -p "$work/rsN1/x86_64" "$work/rsN2/x86_64"; cp "$fx/pair/a.apk" "$work/rsN1/x86_64/fscache-0.3.0-r0.apk"; cp "$fx/pair/a.apk" "$work/rsN2/x86_64/fscache-0.3.0-r0.apk"
nlname=$(printf 'x86_64/evil\nname.apk'); mkdir -p "$work/rsN1/x86_64"; : >"$work/rsN1/$nlname"; : >"$work/rsN2/$nlname"
sr "rule 22" "release signing: an apk whose NAME holds a newline is refused (exit 2, names the control character), never split into two names" 'control|newline|name' "$RS" --build-dir "$work/rsN1" --rebuild-dir "$work/rsN2" --key "$work/release.rsa"
# B3 (rules 22, 17): the assembly key is recognised by its PUBLIC half, not by its bytes or its file name
cp "$root/build/keys/assembly.rsa" "$work/asm-newline.rsa"; printf '\n' >>"$work/asm-newline.rsa"
sed 1d "$root/build/keys/assembly.rsa" >"$work/asm-noheader.rsa"
cp "$root/build/keys/assembly.rsa" "$work/release.rsa.looks-innocent"
sr "rule 22" "release signing refuses the assembly key plus a trailing newline" 'assembly' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/asm-newline.rsa"
sr "rule 22" "release signing refuses the assembly key without its NON-SECRET header line" 'assembly' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/asm-noheader.rsa"
sr "rule 22" "release signing refuses the assembly key under an innocent file name" 'assembly' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/release.rsa.looks-innocent"
echo "not a key at all" >"$work/notakey.rsa"
sr "rule 22" "release signing refuses a file that is not an RSA private key (cannot compare, so it does not sign)" 'key' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/notakey.rsa"
# B4 (AC8): the third key file is public only
t "rule 22" "no file under build/keys holds a private key except the committed non-secret assembly.rsa" bash -c "test \"\$(grep -rl 'PRIVATE KEY' '$root/build/keys' | sort)\" = '$root/build/keys/assembly.rsa'"
# B2 (rule 24): the Go stamp must say exactly v<version> for the main module and the source HEAD as the revision
python3 - "$fx/sbom/ok.txt" "$work" "$rev" <<'P'
import sys
ok = open(sys.argv[1]).read(); w = sys.argv[2]; rev = sys.argv[3]
mod = "\tmod\tgithub.com/fosterstack/cache\tv0.3.0\n"; assert mod in ok
def w_(name, text): open(w + "/" + name, "w").write(text)
w_("bi-pseudo.txt", ok.replace(mod, "\tmod\tgithub.com/fosterstack/cache\tv0.0.0-20261009182853-5261470e877e\n"))
w_("bi-v029.txt", ok.replace(mod, "\tmod\tgithub.com/fosterstack/cache\tv0.2.9\n"))
w_("bi-foreign-rev.txt", ok.replace(rev, "0123456789abcdef0123456789abcdef01234567"))
w_("bi-no-rev.txt", "".join(l for l in ok.splitlines(True) if "vcs.revision" not in l))
w_("bi-rc.txt", ok.replace(mod, "\tmod\tgithub.com/fosterstack/cache\tv0.3.0-rc1\n"))
w_("bi-snap.txt", ok.replace(mod, "\tmod\tgithub.com/fosterstack/cache\tv0.0.0-rc.1\n"))
P
sf "rule 24" "a binary whose main module version is a pseudo-version is refused, naming the version" 'version' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-pseudo.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
sf "rule 24" "a binary stamped v0.2.9 for --version 0.3.0 (a foreign tag) is refused, naming the version" 'version' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-v029.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
sf "rule 24" "a binary whose vcs.revision differs from the source HEAD is refused, naming the revision" 'revision' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-foreign-rev.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
sf "rule 24" "a binary with no vcs.revision at all is refused (it cannot be tied to the source), naming the revision" 'revision' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-no-rev.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
# versions (handoff 0393 ruling 3; advisor Oct 12): X.Y.Z, X.Y.Z-rcN (N digits, no leading zero, no dot) and the one fixed
# snapshot version 0.0.0-rc.1, nothing else; the apk version is X.Y.Z_rcN, the Go stamp v<version>
sd "rule 24" "0.3.0-rc1 is accepted (the stamp says v0.3.0-rc1) and melange runs" '^melange build ' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-rc.txt" "$BA" "${ba_args[@]}" --version 0.3.0-rc1 --out "$(mo)"
orc=$(mo); run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-rc.txt" "$BA" "${ba_args[@]}" --version 0.3.0-rc1 --out "$orc"
t "rule 24" "0.3.0-rc1 maps to the apk version 0.3.0_rc1: the apk is OUT/x86_64/fscache-0.3.0_rc1-r0.apk" test -f "$orc/x86_64/fscache-0.3.0_rc1-r0.apk"
rrc="$work/render-rc"; mkdir -p "$rrc"; run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-rc.txt" "$BA" "${ba_args[@]}" --version 0.3.0-rc1 --render-dir "$rrc" --out "$(mo)"
t "rule 24" "the rendered recipe for 0.3.0-rc1 says version \"0.3.0_rc1\"" bash -c "grep -Eq '^ *version: *\"0\\.3\\.0_rc1\"\$' '$rrc/melange.yaml' && ! grep -q '@VERSION@' '$rrc/melange.yaml'"
t "rule 24" "a final release version 0.3.0 keeps the version 0.3.0 (no suffix)" bash -c "test -f '$o1/x86_64/fscache-0.3.0-r0.apk'"
sf "rule 24" "an rc build whose stamp says v0.3.0 (the final tag) is refused" 'version' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 "$BA" "${ba_args[@]}" --version 0.3.0-rc1 --out "$(mo)"
# the fixed snapshot version (REQ-CHAIN-004-AC12): dotted, accepted only as exactly 0.0.0-rc.1, apk version 0.0.0_rc1
sd "rule 24" "the snapshot version 0.0.0-rc.1 is accepted (the stamp says v0.0.0-rc.1) and melange runs" '^melange build ' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-snap.txt" "$BA" "${ba_args[@]}" --version 0.0.0-rc.1 --out "$(mo)"
osn=$(mo); run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-snap.txt" "$BA" "${ba_args[@]}" --version 0.0.0-rc.1 --out "$osn"
t "rule 24" "0.0.0-rc.1 maps to the apk version 0.0.0_rc1: the apk is OUT/x86_64/fscache-0.0.0_rc1-r0.apk" test -f "$osn/x86_64/fscache-0.0.0_rc1-r0.apk"
for v in 0.3 v0.3.0 0.3.0-rc 0.3.0-rc.1 0.3.0-rc01 0.3.0-rc0 0.3.0-rc1.2 0.3.0-rc1-x 0.3.0-RC1 0.3.0-beta1 0.3.0_rc1 0.0.0-rc.2 0.0.0-rc.01 0.0.0-rc.1.2 1.0.0-rc.1 01.2.3 0.3.0+x \
         "" "(devel)" " 0.3.0" "0.3.0 " $'0.3.0\n' $'0.3.0-rc1\n' $'\n0.3.0'; do
  sr "rule 24" "refuses version '$v' (only X.Y.Z, X.Y.Z-rcN or 0.0.0-rc.1)" 'version' "${bae[@]}" "$BA" "${ba_args[@]}" --version "$v" --out "$(mo)"; done
# R2 (rule 40): a name-resolution failure inside the sealed call is a network attempt (exit 4), like ENETUNREACH
se "rule 40" "build-apk.sh: 'Temporary failure in name resolution' from melange in the sealed namespace -> exit 4 (the probe confirms)" 4 'network attempt' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_NETATTEMPT=1 STUB_NETTEXT="Resolving go.dev... failed: Temporary failure in name resolution." "$BA" "${ba_args[@]}" --out "$(mo)"
# R8 (rule 38a): only the exact value GOPROXY=off (or unset) passes
for g in direct "off,direct" "direct,off" OFF "off " "" "file:///x" "https://proxy.golang.org,off"; do
  sr "rule 38a" "refuses GOPROXY='$g' (only the exact value off is accepted)" GOPROXY "${bae[@]}" "GOPROXY=$g" "$BA" "${ba_args[@]}" --out "$(mo)"; done
sd "rule 38a" "GOPROXY=off exactly is accepted" '^melange build ' "${bae[@]}" GOPROXY=off "$BA" "${ba_args[@]}" --out "$(mo)"

# ---- P4 review round 1 (Sonnet): AC7 with four apks (two variants x two architectures): every pair is compared and every apk is signed ------------
mk4() { rm -rf "$1"; for a in x86_64 aarch64; do mkdir -p "$1/$a"; for n in fscache fscache-fips; do cp "$fx/pair/a.apk" "$1/$a/$n-0.3.0-r0.apk"; done; done; }
mk4 "$work/r4A"; mk4 "$work/r4B"
run_s "$RS" --build-dir "$work/r4A" --rebuild-dir "$work/r4B" --key "$work/release.rsa"
t "rule 22" "release signing: four identical pairs -> exit 0 and melange sign runs for each of the four apks" bash -c "test \"\$(cat '$work/rc')\" = 0 && test \"\$(grep -c '^melange sign' '$CALLS')\" = 4"
mk4 "$work/r4A"; mk4 "$work/r4B"; cp "$fx/pair/ctrl-post-install.apk" "$work/r4B/aarch64/fscache-fips-0.3.0-r0.apk"
run_s "$RS" --build-dir "$work/r4A" --rebuild-dir "$work/r4B" --key "$work/release.rsa"
t "rule 22" "release signing: only the SECOND apk in order differs (control) -> exit 1 naming it, and not one of the four is signed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'fscache-fips-0.3.0-r0.apk' '$work/log' && ! grep -q '^melange sign' '$CALLS'"
mk4 "$work/r4A"; mk4 "$work/r4B"; cp "$fx/pair/ctrl-post-install.apk" "$work/r4B/x86_64/fscache-fips-0.3.0-r0.apk"
run_s "$RS" --build-dir "$work/r4A" --rebuild-dir "$work/r4B" --key "$work/release.rsa"
t "rule 22" "release signing: only the LAST apk differs -> exit 1, nothing signed" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q '^melange sign' '$CALLS'"
mk4 "$work/r4A"; mk4 "$work/r4B"; rm "$work/r4B/aarch64/fscache-fips-0.3.0-r0.apk"
run_s "$RS" --build-dir "$work/r4A" --rebuild-dir "$work/r4B" --key "$work/release.rsa"
t "rule 22" "release signing: the second apk is missing in Rebuild -> refused (exit 2), nothing signed (not just the first)" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -q '^melange sign' '$CALLS'"

# a symlink that is not itself an apk (a directory link next to the real directory) is refused too
mkdir -p "$work/rsK/x86_64" "$work/rsL/x86_64"; cp "$fx/pair/a.apk" "$work/rsK/x86_64/fscache-0.3.0-r0.apk"; cp "$fx/pair/b.apk" "$work/rsL/x86_64/fscache-0.3.0-r0.apk"; ln -s x86_64 "$work/rsK/aarch64"
sr "rule 22" "release signing: a directory symlink inside Build is refused (exit 2, names the symlink), nothing signed" 'symlink' "$RS" --build-dir "$work/rsK" --rebuild-dir "$work/rsL" --key "$work/release.rsa"

# ---- P4 round 2 (Opus + Sonnet): the key guard reads the key the way melange does, and more (tests first) -----------------------------------------
rsa_der() { sed -n '/-----BEGIN RSA PRIVATE KEY-----/,/-----END RSA PRIVATE KEY-----/p' "$1" | sed '1d;$d' | tr -d '\n'; }
cp "$work/release.rsa" "$work/fresh.rsa"; asm_b64=$(sed -n '/-----BEGIN RSA PRIVATE KEY-----/,/-----END RSA PRIVATE KEY-----/p' "$root/build/keys/assembly.rsa" | sed '1d;$d')
rk="$RS --build-dir $work/rsA --rebuild-dir $work/rsB"
keyrefuse() { # <desc> <keyword> <key file>
  sr "rule 22" "release signing: $1" "$2" "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$3"; }
{ printf -- '-----BEGIN X KEY-----\n%s\n-----END X KEY-----\n' "$asm_b64"; cat "$work/fresh.rsa"; } >"$work/key-dual.rsa"
keyrefuse "a file with two PEM blocks (the assembly key under another label, then a fresh key) is refused: melange would read the FIRST block" 'block|label|exactly one' "$work/key-dual.rsa"
{ cat "$work/fresh.rsa"; cat "$root/build/keys/assembly.rsa"; } >"$work/key-trailing.rsa"
keyrefuse "a fresh key followed by the assembly key (a trailing second block) is refused" 'block|exactly one' "$work/key-trailing.rsa"
printf -- '-----BEGIN X KEY-----\n%s\n-----END X KEY-----\n' "$(sed '1d;$d' "$work/fresh.rsa")" >"$work/key-xlabel.rsa"
keyrefuse "a single block with the label X KEY is refused (only RSA PRIVATE KEY is accepted)" 'label' "$work/key-xlabel.rsa"
openssl pkey -in "$work/fresh.rsa" -out "$work/key-pkcs8.rsa" 2>/dev/null
keyrefuse "a PKCS#8 PRIVATE KEY block is refused (melange parses PKCS#1 only)" 'label' "$work/key-pkcs8.rsa"
awk '{printf "%s\r\n", $0}' "$work/fresh.rsa" >"$work/crlf-copy-of-key.pem"
keyrefuse "a key file with CRLF line endings is refused" 'has carriage returns \(CRLF line endings\)' "$work/crlf-copy-of-key.pem"
openssl genrsa -aes256 -passout pass:secret -out "$work/key-enc.rsa" 2048 2>/dev/null
keyrefuse "an encrypted key is refused (it fails, it does not prompt)" 'label|encrypted|header' "$work/key-enc.rsa"
mkdir -p "$work/lead"; { echo "this line is not PEM"; cat "$work/fresh.rsa"; } >"$work/lead/release.rsa"
cp "$pr/a.apk" "$work/rsA/x86_64/fscache-0.3.0-r0.apk"; cp "$pr/a.apk" "$work/rsB/x86_64/fscache-0.3.0-r0.apk"   # rsA was signed in place by an earlier test
sd "rule 22" "a leading text line before the single RSA PRIVATE KEY block is fine (the assembly key itself has one) and the fresh key signs" '^melange sign' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/lead/release.rsa"
{ echo "# header"; cat "$root/build/keys/assembly.rsa" | sed 1d; } >"$work/key-asm-lead.rsa"
keyrefuse "the assembly key behind a different leading line is still the assembly key" 'assembly' "$work/key-asm-lead.rsa"
# the signature name decides which public key verifies the apk: the key file must be named release.rsa, and the signed apk is checked
mkrsa "$work/other-name.rsa"
keyrefuse "a key file not named release.rsa is refused (melange would name the signature after the file; the committed public key is release.rsa.pub)" 'release\.rsa' "$work/other-name.rsa"
mk4 "$work/r4A"; mk4 "$work/r4B"
run_s "$RS" --build-dir "$work/r4A" --rebuild-dir "$work/r4B" --key "$work/release.rsa"
t "rule 22" "release signing: after signing, every apk's signer is release.rsa.pub" bash -c "test \"\$(cat '$work/rc')\" = 0 && cd '$work/r4A' && for f in \$(find . -name '*.apk' | sort); do test \"\$(python3 '$AT' signer \$f)\" = release.rsa.pub || exit 1; done"
mk4 "$work/r4A"; mk4 "$work/r4B"
run_s env STUB_SIGN_FAIL_AT=3 "$RS" --build-dir "$work/r4A" --rebuild-dir "$work/r4B" --key "$work/release.rsa"
t "rule 22" "release signing: when the third of four signatures fails the run fails (exit 1) and NO apk in Build was changed (no mixed directory)" bash -c "test \"\$(cat '$work/rc')\" = 1 && cd '$work/r4A' && for f in \$(find . -name '*.apk' | sort); do test \"\$(python3 '$AT' signer \$f)\" = assembly.rsa.pub || exit 1; done"
# a directory or a FIFO named *.apk is not skipped silently
mkdir -p "$work/rsM/x86_64" "$work/rsN/x86_64"; cp "$fx/pair/a.apk" "$work/rsM/x86_64/fscache-0.3.0-r0.apk"; cp "$fx/pair/b.apk" "$work/rsN/x86_64/fscache-0.3.0-r0.apk"; mkdir "$work/rsM/x86_64/dir.apk"
sr "rule 22" "release signing: a directory named x.apk in Build is refused (exit 2)" 'regular file' "$RS" --build-dir "$work/rsM" --rebuild-dir "$work/rsN" --key "$work/release.rsa"
rm -rf "$work/rsM/x86_64/dir.apk"; mkfifo "$work/rsM/x86_64/fifo.apk"
sr "rule 22" "release signing: a FIFO named x.apk in Build is refused (exit 2)" 'regular file' "$RS" --build-dir "$work/rsM" --rebuild-dir "$work/rsN" --key "$work/release.rsa"
# every proxy variable, lower and upper case
for pv in http_proxy https_proxy all_proxy ALL_PROXY HTTP_PROXY; do
  sr "rule 38a" "refuses $pv in the environment" proxy "${bae[@]}" "$pv=http://127.0.0.1:3128" "$BA" "${ba_args[@]}" --out "$(mo)"; done
# the stamp: exact version, not a prefix; exact FIPS module, not a prefix
python3 - "$fx/sbom/ok.txt" "$work" "$rev" <<'P'
import sys
ok = open(sys.argv[1]).read(); w = sys.argv[2]
mod = "\tmod\tgithub.com/fosterstack/cache\tv0.3.0\n"; assert mod in ok
def w_(n, t): open(w + "/" + n, "w").write(t)
w_("bi-rc-for-final.txt", ok.replace(mod, "\tmod\tgithub.com/fosterstack/cache\tv0.3.0-rc1\n"))
w_("bi-dirty.txt", ok.replace(mod, "\tmod\tgithub.com/fosterstack/cache\tv0.3.0+dirty\n"))
w_("bi-rc-pseudo.txt", ok.replace(mod, "\tmod\tgithub.com/fosterstack/cache\tv0.3.0-rc1.0.20261009182853-5261470e877e\n"))
w_("bi-fips-prefix.txt", ok + "\tbuild\tGOFIPS140=v1.0.0-c2097c7cX\n")
w_("bi-fips-other.txt", ok + "\tbuild\tGOFIPS140=v1.1.0-deadbeef\n")
w_("bi-fips-two.txt", ok + "\tbuild\tGOFIPS140=v1.0.0-c2097c7c\n\tbuild\tGOFIPS140=v1.1.0-deadbeef\n")
P
for f in rc-for-final dirty; do
  sf "rule 24" "--version 0.3.0 with a binary stamped from $f is refused (the match is exact, not a prefix)" 'version' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-$f.txt" "$BA" "${ba_args[@]}" --out "$(mo)"; done
sf "rule 24" "--version 0.3.0-rc1 with a pseudo-version v0.3.0-rc1.0.<date>-<hash> is refused" 'version' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-rc-pseudo.txt" "$BA" "${ba_args[@]}" --version 0.3.0-rc1 --out "$(mo)"
for f in fips-prefix fips-other fips-two; do
  sf "rule 13" "the fips variant is refused when the binary records another module ($f), the match is exact" 'GOFIPS140' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$work/bi-$f.txt" "$BA" "${ba_args[@]}" --variant fips --recipe "$fx/melange-fips.yaml" --out "$(mo)"; done
# leading zeros: X.Y.Z are plain decimal numbers
for v in 01.2.3 1.02.3 1.2.03 00.0.0; do
  sr "rule 24" "refuses --version $v (leading zero)" 'version' "${bae[@]}" "$BA" "${ba_args[@]}" --version "$v" --out "$(mo)"; done
# buildinfo.txt is tied to the packaged binary: when a Go toolchain is on PATH, `go version -m` of usr/bin/fscache must say the same (first line aside)
printf '%s\n' "/some/path/usr/bin/fscache: go1.27.2" >"$work/govm-ok.txt"; tail -n +2 "$fx/sbom/ok.txt" >>"$work/govm-ok.txt"
sd "rule 20" "the packaged binary's go version -m equals buildinfo.txt (first line aside) -> accepted, and go was asked about the binary" '^go version -m ' "${bae[@]}" STUB_BUILDINFO="$fx/sbom/ok.txt" STUB_GOVM_FILE="$work/govm-ok.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
{ cat "$work/govm-ok.txt"; printf '\tdep\texample.org/smuggled\tv1.0.0\n'; } >"$work/govm-bad.txt"
sf "rule 20" "a buildinfo.txt that differs from go version -m of the packaged binary is refused, naming buildinfo" 'buildinfo' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$fx/sbom/ok.txt" STUB_GOVM_FILE="$work/govm-bad.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
so "rule 20" "with no Go toolchain the check is skipped with a visible note (not silently)" 'not verified|no Go toolchain' env -u GITHUB_ACTIONS "${bae[@]}" "$BA" "${ba_args[@]}" --out "$(mo)"
sf "rule 20" "in CI (GITHUB_ACTIONS set) a missing Go toolchain is a named failure, not a skip" 'no Go toolchain on PATH in CI' env GITHUB_ACTIONS=true SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 "$BA" "${ba_args[@]}" --out "$(mo)"

sr "rule 31" "build-apk refuses a SOURCE_DATE_EPOCH too large to be a date (exit 2)" SOURCE_DATE_EPOCH env SOURCE_DATE_EPOCH=99999999999999999999 FAKE_UNAME=x86_64 "$BA" "${ba_args[@]}" --out "$(mo)"
# ---- P4 round 3 (Sonnet): the replace phase fails CLOSED, the post-sign signer check, a failing go, probe exit codes --------------------------------
# the replace phase: a .new file that cannot be written must stop the run and leave Build's directory exactly as it was
for pos in 1 2 4; do
  mk4 "$work/r5A"; mk4 "$work/r5B"; before=$(cd "$work/r5A" && find . -type f | sort | xargs shasum -a 256 | shasum -a 256)
  first=$(cd "$work/r5A" && find . -name '*.apk' | sort | sed -n "${pos}p")
  : >"$work/r5A/$first.new"; chmod 400 "$work/r5A/$first.new"
  run_s "$RS" --build-dir "$work/r5A" --rebuild-dir "$work/r5B" --key "$work/release.rsa"
  chmod 600 "$work/r5A/$first.new"; rm -f "$work/r5A/$first.new"
  t "rule 22" "release signing: the replace phase failing at apk $pos of 4 (a read-only .new file) exits non-zero and says so, never 'signed 4'" bash -c "test \"\$(cat '$work/rc')\" != 0 && ! grep -q '^signed 4' '$work/log'"
  t "rule 22" "...apk $pos: Build's directory is byte-identical to before (not one apk was replaced)" bash -c "test \"\$(cd '$work/r5A' && find . -type f | sort | xargs shasum -a 256 | shasum -a 256)\" = '$before'"
done
mk4 "$work/r5A"; mk4 "$work/r5B"
run_s env STUB_SIGN_AS=assembly.rsa.pub "$RS" --build-dir "$work/r5A" --rebuild-dir "$work/r5B" --key "$work/release.rsa"
t "rule 22" "release signing: if melange signs with the wrong key name the post-sign signer check refuses (exit 1) and nothing in Build changed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'not release.rsa.pub' '$work/log' && cd '$work/r5A' && for f in \$(find . -name '*.apk'); do test \"\$(python3 '$AT' signer \$f)\" = assembly.rsa.pub || exit 1; done"
# a go on PATH that FAILS is not 'no toolchain': the check cannot be done, so the build is refused
sf "rule 20" "a go on PATH that fails on the packaged binary refuses the build (it is not 'no toolchain'), naming go" 'go version' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_GO_FAILS=1 "$BA" "${ba_args[@]}" --out "$(mo)"
# the probe: any exit but 101 is a leak (exit 1, never 4)
for prc in 0 1 110 111; do
  run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_NETATTEMPT=1 STUB_PROBE_RC=$prc "$BA" "${ba_args[@]}" --out "$(mo)"
  t "rule 40" "build-apk: network text but the probe exits $prc (not 101) -> exit 1, never 4" test "$(rc)" = 1
done
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_FAIL=1 STUB_PROBE_RC=101 "$BA" "${ba_args[@]}" --out "$(mo)"
t "rule 40" "build-apk: a failure WITHOUT any network text is exit 1 even though the probe would say 101 (a network attempt needs both the text and the probe; the probe is not run)" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q 'net-probe' '$CALLS'"

# ---- P4 round 3 (Opus + Sonnet): the key must be THE release key, the inputs are copied before any check, signers are checked early ---------------------
freshrs() { cp "$pr/a.apk" "$work/rsA/x86_64/fscache-0.3.0-r0.apk"; cp "$pr/a.apk" "$work/rsB/x86_64/fscache-0.3.0-r0.apk"; }   # earlier tests signed rsA in place
freshrs
sr "rule 22" "release signing with the committed placeholder public key refuses every key (no release until a human commits the real public half), saying the committed release public key is not a readable key yet" 'not a readable public key' "$RS_REAL" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/release.rsa"
sr "rule 22" "release-sign-apks.sh has no --keys-dir: another keys directory cannot be named by any call, test mode or not" 'unknown argument' "$RS_REAL" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/release.rsa" --keys-dir "$work/keysfx"
mkdir -p "$work/other"; mkrsa "$work/other/release.rsa"
freshrs
sr "rule 22" "a valid RSA key named release.rsa whose public half is not build/keys/release.rsa.pub is refused (it is not the stored key)" 'does not match' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/other/release.rsa"
run_s "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsB" --key "$work/release.rsa"
t "rule 22" "melange is given a PRIVATE COPY of the key and of the apks (nothing read twice from a path another process could swap): a signing call exists, its key is not the original path, it is the copy under a private key/ directory, its apk is not Build's path" bash -c "
  l=\$(grep '^melange sign' '$CALLS' | head -n 1)
  [ -n \"\$l\" ] \
    && ! printf '%s' \"\$l\" | grep -q -- '--signing-key $work/release.rsa ' \
    && printf '%s' \"\$l\" | grep -Eq -- '--signing-key [^ ]*/key/release.rsa ' \
    && ! printf '%s' \"\$l\" | grep -q '$work/rsA'"
mkdir -p "$work/rsR1/x86_64" "$work/rsR2/x86_64"; cp "$pr/b.apk" "$work/rsR1/x86_64/fscache-0.3.0-r0.apk"; cp "$pr/a.apk" "$work/rsR2/x86_64/fscache-0.3.0-r0.apk"
sr "rule 22" "release signing: a Build apk already signed by anything but assembly.rsa.pub is refused early, naming the signer" 'assembly\.rsa\.pub' "$RS" --build-dir "$work/rsR1" --rebuild-dir "$work/rsR2" --key "$work/release.rsa"
sr "rule 22" "release signing: a Rebuild apk signed by anything but assembly.rsa.pub is refused early" 'assembly\.rsa\.pub' "$RS" --build-dir "$work/rsR2" --rebuild-dir "$work/rsR1" --key "$work/release.rsa"
# a go on PATH is run with the toolchain pinned to local and the user's go env ignored
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_GOVM_FILE="$work/govm.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
t "rule 20" "go version -m is run with GOTOOLCHAIN=local, GOFLAGS empty and GOENV=off" bash -c "grep -q 'GOTOOLCHAIN=local GOFLAGS= GOENV=off' '$CALLS.goenv'"
# the epoch: digits that are not a date, and a CRLF fixture that is not named like the message
sr "rule 31" "SOURCE_DATE_EPOCH=999999999999 (12 digits, not a date) is refused naming SOURCE_DATE_EPOCH" 'SOURCE_DATE_EPOCH' env SOURCE_DATE_EPOCH=999999999999 FAKE_UNAME=x86_64 "$BA" "${ba_args[@]}" --out "$(mo)"
# the network classifier needs BOTH the text and the probe
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_FAIL=1 STUB_NETTEXT="lookup example: no such host" STUB_PROBE_RC=0 "$BA" "${ba_args[@]}" --out "$(mo)"
t "rule 40" "build-apk: 'no such host' from a failure whose probe exits 0 is exit 1 (text alone never gives 4; both text and probe exit 101 are required)" test "$(rc)" = 1

# staging failures (the directory of a later apk cannot be written): nothing in Build changes, no .new file is left behind
if [ "$(id -u)" != 0 ]; then
  for d in aarch64 x86_64; do
    mk4 "$work/r6A"; mk4 "$work/r6B"; before=$(cd "$work/r6A" && find . -type f | sort | xargs shasum -a 256 | shasum -a 256)
    chmod 500 "$work/r6A/$d"
    run_s "$RS" --build-dir "$work/r6A" --rebuild-dir "$work/r6B" --key "$work/release.rsa"
    chmod 700 "$work/r6A/$d"
    t "rule 22" "release signing: the $d directory of Build cannot be written (staging fails) -> non-zero, never 'signed 4'" bash -c "test \"\$(cat '$work/rc')\" != 0 && ! grep -q '^signed 4' '$work/log'"
    t "rule 22" "...$d: Build's directory is byte-identical and no .new file is left behind" bash -c "test \"\$(cd '$work/r6A' && find . -type f | sort | xargs shasum -a 256 | shasum -a 256)\" = '$before' && test -z \"\$(find '$work/r6A' -name '*.new')\""
  done
fi

# ---- snapshot-4 round 4 (Sonnet/Opus P4) ----------------------------------------------------------------------------------------------------------------------
sr "rule 11" "build-apk.sh has no --recipe: the committed recipe is the only one a production call uses, test mode or not" 'unknown argument' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 "$BA_PROD" "${ba_args[@]}" --out "$(mo)"
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_ENV_EXTRA=bash=5.2-r0 "$BA" "${ba_args[@]}" --out "$(mo)"
t "rule 15" "a package in the apk's build environment that is not in the melange lock fails the build (the inputs manifest cannot be made)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'bash' '$work/log'"
{ printf '%s\n' "/some/path/usr/bin/fscache: go1.99.0"; tail -n +2 "$fx/sbom/ok.txt"; } >"$work/govm-toolchain.txt"
sf "rule 20" "the Go toolchain version in buildinfo.txt must equal the one go version -m reports for the packaged binary (the first line, minus the file path)" 'toolchain|go1' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_BUILDINFO="$fx/sbom/ok.txt" STUB_GOVM_FILE="$work/govm-toolchain.txt" "$BA" "${ba_args[@]}" --out "$(mo)"
# many symlinks in Build: a named refusal (exit 2), never a silent SIGPIPE exit 141
mk4 "$work/r7A"; mk4 "$work/r7B"; python3 -c "import os,sys; [os.symlink('x', '%s/link%d' % (sys.argv[1], i)) for i in range(30000)]" "$work/r7A"
run_s "$RS" --build-dir "$work/r7A" --rebuild-dir "$work/r7B" --key "$work/release.rsa"
t "rule 22" "release signing: many symlinks in Build give exit 2 and a message naming a symlink (not exit 141 with no message)" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -qi symlink '$work/log'"
# the committed assembly key pair matches, and the release public key file is deliberately NOT a key until a human commits the real one
t "rule 22" "build/keys/assembly.rsa.pub is the public half of build/keys/assembly.rsa (a matching pair; both outputs non-empty)" bash -c "a=\$(openssl rsa -in '$root/build/keys/assembly.rsa' -pubout 2>/dev/null); b=\$(openssl rsa -pubin -in '$root/build/keys/assembly.rsa.pub' -pubout 2>/dev/null); test -n \"\$a\" && test \"\$a\" = \"\$b\""
t "rule 22" "build/keys/release.rsa.pub is a placeholder that is NOT a key (no PEM block of any kind): nobody holds a private half of it" bash -c "! grep -q -- '-----BEGIN' '$root/build/keys/release.rsa.pub' && grep -q PLACEHOLDER '$root/build/keys/release.rsa.pub'"

# no key-shaped block of ANY label under build/keys, except in the committed non-secret assembly pair (assembly.rsa and its public half assembly.rsa.pub)
cat >"$work/keyscan.py" <<'P'
import base64, hashlib, os, re, subprocess, sys, tempfile
def _tlv(b, i, end):
    if i + 2 > end: raise ValueError("truncated")
    tag, l = b[i], b[i + 1]
    if l < 0x80: n, h = l, 2
    elif l == 0x80 or l > 0x84: raise ValueError("indefinite or oversized length")
    else:
        k = l & 0x7F
        if i + 2 + k > end: raise ValueError("truncated length")
        n, h = int.from_bytes(b[i + 2:i + 2 + k], "big"), 2 + k
    if i + h + n > end: raise ValueError("content past the end")
    return tag, i + h, i + h + n
def _children(b, s, e):
    out = []
    while s < e:
        t, cs, ce = _tlv(b, s, e); out.append((t, cs, ce)); s = ce
    return out
def der_rsa_private(b):
    """exactly ONE PKCS#1 RSAPrivateKey and nothing after it: SEQUENCE { INTEGER version 0, then eight INTEGERs }"""
    t, s, e = _tlv(b, 0, len(b))
    if t != 0x30 or e != len(b): raise ValueError("not one SEQUENCE spanning the whole block (trailing bytes, or a second object)")
    ch = _children(b, s, e)
    if len(ch) != 9 or any(c[0] != 0x02 for c in ch) or b[ch[0][1]:ch[0][2]] != b"\x00": raise ValueError("not a PKCS#1 RSAPrivateKey (version 0 and eight INTEGERs)")
def der_rsa_public(b):
    """exactly ONE SubjectPublicKeyInfo of rsaEncryption and nothing after it"""
    t, s, e = _tlv(b, 0, len(b))
    if t != 0x30 or e != len(b): raise ValueError("not one SEQUENCE spanning the whole block (trailing bytes, or a second object)")
    ch = _children(b, s, e)
    if len(ch) != 2 or ch[0][0] != 0x30 or ch[1][0] != 0x03: raise ValueError("not a SubjectPublicKeyInfo")
    alg = _children(b, ch[0][1], ch[0][2])
    if len(alg) != 2 or b[alg[0][1]:alg[0][2]] != bytes.fromhex("2a864886f70d010101") or alg[0][0] != 0x06 or alg[1][0] != 0x05 or alg[1][1] != alg[1][2]: raise ValueError("not rsaEncryption with NULL parameters")
    bits = b[ch[1][1]:ch[1][2]]
    if not bits or bits[0] != 0: raise ValueError("bit string with unused bits")
    inner = bits[1:]
    t2, s2, e2 = _tlv(inner, 0, len(inner))
    k = _children(inner, s2, e2)
    if t2 != 0x30 or e2 != len(inner) or len(k) != 2 or any(c[0] != 0x02 for c in k): raise ValueError("not RSAPublicKey (two INTEGERs) spanning the bit string")
d = sys.argv[1]; bad = []
PLACEHOLDER_SHA = "b648f51442289101a7f294c8c1e528ee79337927f65f43c041d2f6621d28ca3b"   # the committed placeholder; committing the real release public key edits this line and the placeholder test
B64 = re.compile(rb"[A-Za-z0-9+/]{1,76}={0,2}")
HEADER = re.compile(rb"NON-SECRET assembly key[ -~]{0,160}")
FILES = {"assembly.rsa": b"RSA PRIVATE KEY", "assembly.rsa.pub": b"PUBLIC KEY", "release.rsa.pub": None}
seen = set()
for root_, dirs, files in os.walk(d):
    for f in files + dirs:
        pth = os.path.join(root_, f); rel = os.path.relpath(pth, d)
        if os.path.islink(pth): bad.append(rel + " (a symlink)"); continue
        if os.path.isdir(pth): bad.append(rel + " (a directory)"); continue
        seen.add(rel)
        if rel not in FILES: bad.append(rel + " (not one of the three allowed files)"); continue
        raw = open(pth, "rb").read()
        if len(raw) > 8192: bad.append(rel + " (larger than 8 KiB)"); continue
        if any(c >= 0x80 for c in raw) or b"\r" in raw or b"\0" in raw: bad.append(rel + " (not plain ASCII text: a high byte, a NUL or a carriage return)"); continue
        label = FILES[rel]
        if label is None and hashlib.sha256(raw).hexdigest() == PLACEHOLDER_SHA:
            continue   # the committed placeholder, byte for byte
        if label is None: label = b"PUBLIC KEY"   # the real release public key: exactly one public key block that OpenSSL parses
        # line by line: [one NON-SECRET header line] BEGIN, base64 lines, END, end of file. Nothing else.
        lines = raw.split(b"\n")
        if lines[-1] != b"": bad.append(rel + " (no final newline)"); continue
        lines = lines[:-1]
        if rel != "release.rsa.pub":
            if not lines or not HEADER.fullmatch(lines[0]): bad.append(rel + " (the NON-SECRET header line is required as the first line)"); continue
            lines = lines[1:]
        beg, end = b"-----BEGIN " + label + b"-----", b"-----END " + label + b"-----"
        if len(lines) < 3 or lines[0] != beg or lines[-1] != end or not all(B64.fullmatch(l) for l in lines[1:-1]):
            bad.append(rel + " (every line must be the expected armour, a base64 line, or the one NON-SECRET header line; the %s block is expected exactly once)" % label.decode()); continue
        try:
            raw_der = base64.b64decode(b"".join(lines[1:-1]), validate=True)
            (der_rsa_private if label == b"RSA PRIVATE KEY" else der_rsa_public)(raw_der)   # exactly ONE complete key of the expected type, nothing after it
        except Exception as ex:
            bad.append(rel + " (the block is not exactly one %s: %s)" % (label.decode(), ex)); continue
        if rel == "release.rsa.pub":
            r = subprocess.run(["openssl", "rsa", "-pubin", "-in", pth, "-noout"], capture_output=True)
            if r.returncode != 0: bad.append(rel + " (not a public key that OpenSSL parses)")
for need in FILES:
    if need not in seen: bad.append(need + " (missing)")
if bad: print("key files: " + "; ".join(bad), file=sys.stderr); sys.exit(1)
P
t "rule 22" "no key-shaped block of any label under build/keys except in assembly.rsa and assembly.rsa.pub (the committed non-secret pair)" python3 "$work/keyscan.py" "$root/build/keys"
kmut() { rm -rf "$work/km-$1"; cp -R "$root/build/keys" "$work/km-$1"; }
B1='-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----'
kmut pub; printf -- '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' >>"$work/km-pub/release.rsa.pub"
kmut newfile; printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n' >"$work/km-newfile/x"
kmut second; printf -- "$B1\n" >>"$work/km-second/assembly.rsa"
kmut secondpub; printf -- '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' >>"$work/km-secondpub/assembly.rsa.pub"
kmut space; printf -- '-----BEGIN RSA PRIVATE KEY----- \nAAAA\n-----END RSA PRIVATE KEY----- \n' >>"$work/km-space/assembly.rsa"
kmut crlf; printf -- '-----BEGIN RSA PRIVATE KEY-----\r\nAAAA\r\n-----END RSA PRIVATE KEY-----\r\n' >>"$work/km-crlf/assembly.rsa"
kmut tab; printf -- '-----BEGIN PUBLIC KEY-----\t\nAAAA\n-----END PUBLIC KEY-----\t\n' >>"$work/km-tab/assembly.rsa.pub"
kmut label; printf -- '-----BEGIN KEY-----\nAAAA\n-----END KEY-----\n' >"$work/km-label/x"
kmut lower; printf -- '-----begin rsa private key-----\nAAAA\n-----end rsa private key-----\n' >"$work/km-lower/y"
kmut link; ln -s assembly.rsa "$work/km-link/z"
kmut dir; mkdir "$work/km-dir/sub"
kmut bin; head -c 100 /dev/urandom | tr -d '\0' | head -c 50 >"$work/km-bin/release.rsa.pub"; printf '\377\376' >>"$work/km-bin/release.rsa.pub"
kmut big; head -c 9000 /dev/zero | tr '\0' 'a' >"$work/km-big/release.rsa.pub"
kmut b64; printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' >>"$work/km-b64/release.rsa.pub"
kmut jwk; printf '{"kty":"RSA","d":"AAAA"}\n' >>"$work/km-jwk/assembly.rsa.pub"
kmut putty; printf 'PuTTY-User-Key-File-3: ssh-rsa\n' >>"$work/km-putty/assembly.rsa.pub"
kmut utf16; printf 'PLACEHOLDER' | iconv -f UTF-8 -t UTF-16LE >"$work/km-utf16/release.rsa.pub"
kmut hdr2; printf 'NON-SECRET second header\n' | cat - "$work/km-hdr2/assembly.rsa.pub" >"$work/km-hdr2/x" && mv "$work/km-hdr2/x" "$work/km-hdr2/assembly.rsa.pub"
kmut nonl; printf %s "$(cat "$work/km-nonl/assembly.rsa.pub")" >"$work/km-nonl/assembly.rsa.pub"
declare -A KMSG=([pub]='every line must be' [newfile]='not one of the three' [second]='every line must be' [secondpub]='every line must be' [space]='every line must be' [crlf]='plain ASCII' [tab]='every line must be' [label]='not one of the three' [lower]='not one of the three' [link]='symlink' [dir]='directory' [bin]='plain ASCII' [big]='8 KiB' [b64]='every line must be|openssl|OpenSSL' [jwk]='every line must be' [putty]='every line must be' [utf16]='plain ASCII' [hdr2]='header line is required|every line must be' [nonl]='final newline')
for m in pub newfile second secondpub space crlf tab label lower link dir bin big b64 jwk putty utf16 hdr2 nonl; do
  fails "rule 22" "...the mutant '$m' (a key-shaped or oddly shaped file/block under build/keys) is caught by its own rule" "${KMSG[$m]}" python3 "$work/keyscan.py" "$work/km-$m"
done
kmut realrel; openssl genrsa 2048 2>/dev/null | openssl rsa -pubout 2>/dev/null >"$work/km-realrel/release.rsa.pub"
t "rule 22" "a real release public key (one PUBLIC KEY block OpenSSL parses) is ACCEPTED in release.rsa.pub once a human commits it" python3 "$work/keyscan.py" "$work/km-realrel"
kmut garbage; printf -- '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' >"$work/km-garbage/release.rsa.pub"
fails "rule 22" "...a PUBLIC KEY block that OpenSSL cannot parse is refused" 'not exactly one PUBLIC KEY' python3 "$work/keyscan.py" "$work/km-garbage"
t "rule 22" "the committed assembly public half has the pinned fingerprint (an accidental swap of the pair fails; rotating the assembly key edits this pin)" bash -c "test \"\$(shasum -a 256 '$root/build/keys/assembly.rsa.pub' | cut -d' ' -f1)\" = 87fbcae7d56920b718980d702c0fefa8a4959a018955088df6f38b886e24deb5"



# ---- Codex security-final on P4 (review round 9): exactly ONE complete key of the expected type per block, in the key scan and in the signer's key reader --------
mkrsa "$work/dk1.rsa"; mkrsa "$work/dk2.rsa"; mkdir -p "$work/der"
python3 - "$work" <<'P'
import base64, subprocess, sys, textwrap
w = sys.argv[1]
def der_of(path):
    pem = open(path).read().split("\n"); return base64.b64decode("".join(l for l in pem if l and not l.startswith("-----")))
def pem(label, b): return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(textwrap.wrap(base64.b64encode(b).decode(), 64)), label)
d1, d2 = der_of(w + "/dk1.rsa"), der_of(w + "/dk2.rsa")
pub = subprocess.run(["openssl", "rsa", "-in", w + "/dk1.rsa", "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
p8 = subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", w + "/dk1.rsa", "-outform", "DER"], capture_output=True, check=True).stdout
out = {
    "ok-private": pem("RSA PRIVATE KEY", d1),
    "two-private": pem("RSA PRIVATE KEY", d1 + d2),                 # two DER keys under one armour
    "pkcs8-relabelled": pem("RSA PRIVATE KEY", p8),                  # PKCS#8 relabelled as a PKCS#1 block
    "trailing-private": pem("RSA PRIVATE KEY", d1 + b"\x00\x01\x02"),
    "ok-public": pem("PUBLIC KEY", pub),
    "private-as-public": pem("PUBLIC KEY", d1),                      # a private DER relabelled PUBLIC KEY
    "spki-plus-private": pem("PUBLIC KEY", pub + d1),                # an SPKI followed by a private DER
    "trailing-public": pem("PUBLIC KEY", pub + b"\x00"),
}
for k, v in out.items(): open("%s/der/%s.pem" % (w, k), "w").write(v)
P
# the key scan: a real-shaped release public key is accepted, each probe is refused by the one-complete-key rule
for pr in ok-public; do kmut "der-$pr"; cp "$work/der/$pr.pem" "$work/km-der-$pr/release.rsa.pub"; t "rule 22" "key scan: a single complete SPKI in release.rsa.pub is accepted" python3 "$work/keyscan.py" "$work/km-der-$pr"; done
for pr in private-as-public spki-plus-private trailing-public; do kmut "der-$pr"; cp "$work/der/$pr.pem" "$work/km-der-$pr/release.rsa.pub"; fails "rule 22" "key scan: release.rsa.pub as '$pr' is refused (exactly one complete public key)" 'not exactly one PUBLIC KEY' python3 "$work/keyscan.py" "$work/km-der-$pr"; done
for pr in two-private pkcs8-relabelled trailing-private; do kmut "der-$pr"; { head -n 1 "$root/build/keys/assembly.rsa"; cat "$work/der/$pr.pem"; } >"$work/km-der-$pr/assembly.rsa"; fails "rule 22" "key scan: assembly.rsa as '$pr' is refused (exactly one complete private key)" 'not exactly one RSA PRIVATE KEY' python3 "$work/keyscan.py" "$work/km-der-$pr"; done
kmut hdr-pub; tail -n +2 "$root/build/keys/assembly.rsa.pub" >"$work/km-hdr-pub/assembly.rsa.pub"
fails "rule 22" "key scan: assembly.rsa.pub without its NON-SECRET header line is refused by its own message" 'header line is required' python3 "$work/keyscan.py" "$work/km-hdr-pub"
kmut hdr-priv; tail -n +2 "$root/build/keys/assembly.rsa" >"$work/km-hdr-priv/assembly.rsa"
fails "rule 22" "key scan: assembly.rsa without its NON-SECRET header line is refused by its own message" 'header line is required' python3 "$work/keyscan.py" "$work/km-hdr-priv"
# the signer's key reader: the same probes as --key
for pr in two-private pkcs8-relabelled trailing-private; do
  mkdir -p "$work/dk-$pr"; cp "$work/der/$pr.pem" "$work/dk-$pr/release.rsa"
  sr "rule 22" "release signing: --key as '$pr' is refused (exactly one complete PKCS#1 key)" 'exactly one PKCS#1|not a readable|PEM label' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsC" --key "$work/dk-$pr/release.rsa"
done
ln -s "$work/release.rsa" "$work/dk-link-release.rsa"; mkdir -p "$work/dk-link"; ln -s "$work/release.rsa" "$work/dk-link/release.rsa"
sr "rule 22" "release signing: a --key that is a symlink named release.rsa is refused before any copy" 'symlink' "$RS" --build-dir "$work/rsA" --rebuild-dir "$work/rsC" --key "$work/dk-link/release.rsa"

# ---- Codex security-final on P4: no echoed credential, network text beyond DNS, an explicit environment for the privileged call ---------------------------------
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 GOPROXY=https://user:CANARY-9f3a@proxy.example "$BA" "${ba_args[@]}" --out "$(mo)"
t "rule 38a" "a GOPROXY with a credential is refused WITHOUT printing it (no canary in the output)" bash -c "test \"\$(cat '$work/rc')\" != 0 && grep -q 'GOPROXY' '$work/log' && ! grep -q 'CANARY-9f3a' '$work/log' && ! grep -q 'CANARY-9f3a' '$CALLS'"
for phrase in "dial tcp: lookup go.dev on 10.0.0.1:53: no such host" "Resolving go.dev... failed: Temporary failure in name resolution." "connect: Network is unreachable"; do
  se "rule 40" "build-apk.sh: the melange text '$phrase' in the sealed namespace -> exit 4 (the probe confirms)" 4 'network attempt' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_NETATTEMPT=1 STUB_NETTEXT="$phrase" "$BA" "${ba_args[@]}" --out "$(mo)"
done
# residual (Codex round 9 finding 3, accepted by the advisor Oct 10): the classification of an ordinary failure against a network attempt relies on a narrow stderr match;
# 'Connection refused', 'No route to host' and 'Operation not permitted' are NOT classified as network attempts (the wide pattern over-matched ordinary failures such as bwrap EPERM)
# the overlap, stated exactly (round 2 of PR 341): a message that ALSO carries 'dial tcp' (Go's dialer) IS probed, whatever follows it: the classifier is
# the word list in the AC, not the cause of the failure
for phrase in "dial tcp 192.0.2.1:443: connect: connection refused" "dial tcp 192.0.2.1:443: connect: no route to host"; do
  se "rule 40" "build-apk.sh: '$phrase' carries the word dial tcp: it is probed (exit 4 when the probe confirms), the overlap of the AC5 word list and a refused/no-route cause" 4 'network attempt' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_NETATTEMPT=1 STUB_NETTEXT="$phrase" "$BA" "${ba_args[@]}" --out "$(mo)"
done
for phrase in "bwrap: Operation not permitted" "connect: Connection refused" "connect: No route to host"; do
  sx "rule 40" "build-apk.sh: '$phrase' is an ordinary failure, not a confirmed network attempt (non-zero, not 4): the documented residual" ne4 env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_NETATTEMPT=1 STUB_NETTEXT="$phrase" "$BA" "${ba_args[@]}" --out "$(mo)"
done
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 GITHUB_TOKEN=canary-token HTTPS_PROXY= GOFLAGS=-mod=mod "$BA" "${ba_args[@]}" --out "$(mo)"
t "rule 23" "the privileged melange call gets EXACTLY HOME LC_ALL PATH SOURCE_DATE_EPOCH (an explicit env -i list; the stub adds nothing and test-only control variables are filtered out of the comparison)" bash -c "grep -Eq '^sudo [^ ]*env -i ' '$CALLS' && grep '^ENVNAMES=' '$CALLS' | head -1 | grep -qx 'ENVNAMES=HOME LC_ALL PATH SOURCE_DATE_EPOCH '"
t "rule 23" "...and the call line names no variable but those four (plus test-mode stub controls)" bash -c "grep -E '^sudo [^ ]*env -i ' '$CALLS' | head -1 | tr ' ' '\n' | grep -E '^[A-Za-z_]+=' | cut -d= -f1 | grep -Ev '^(STUB_|FAKE_|CALLS|ImageOS|ImageVersion)' | sort | tr '\n' ' ' | grep -qx 'HOME LC_ALL PATH SOURCE_DATE_EPOCH '"

# ---- byte identity and the output listing (handoff 0393 ruling 4, advisor Oct 12; red first) ----------------------------------------
# The chain builds standard and fips into ONE --out, so the fips files carry the -fips suffix (chain_items.py: modules SBOM and
# inputs manifest per variant), and Build and Rebuild (and the two architecture jobs) must produce identical bytes for them.
oidA=$(mo); oidB=$(mo); ofA=$(mo); ofB=$(mo)
run_s "${bae[@]}" "$BA" "${ba_args[@]}" --out "$oidA"
run_s "${bae[@]}" "$BA" "${ba_args[@]}" --out "$oidB"
run_s "${bae[@]}" "$BA" "${ba_args[@]}" --variant fips --recipe "$fx/melange-fips.yaml" --out "$ofA"
run_s "${bae[@]}" "$BA" "${ba_args[@]}" --variant fips --recipe "$fx/melange-fips.yaml" --out "$ofB"
oid_cmp() { python3 - "$1" "$2" "$3" <<'P'
import os, sys
a, b, want = sys.argv[1], sys.argv[2], set(sys.argv[3].split(","))
def walk(d):
    out = {}
    for root, dirs, files in os.walk(d):
        for n in dirs + files:
            p = os.path.join(root, n); rel = os.path.relpath(p, d)
            assert not n.startswith("."), "dotfile " + rel
            assert not os.path.islink(p), "symlink " + rel
        for n in files:
            p = os.path.join(root, n); out[os.path.relpath(p, d)] = open(p, "rb").read()
    return out
x, y = walk(a), walk(b)
assert set(x) == want, ("files under --out are not exactly the named ones", sorted(x))
assert set(x) == set(y), (sorted(x), sorted(y))
for k in sorted(x):
    assert x[k] == y[k], "not byte-identical between two runs: " + k
P
}
t "rule 31" "two standard builds with the same inputs and SOURCE_DATE_EPOCH write exactly the named files under --out (no dotfile, no symlink, no temp file), byte-identical" oid_cmp "$oidA" "$oidB" "x86_64/fscache-0.3.0-r0.apk,x86_64/APKINDEX.tar.gz,fscache-modules.spdx.json,inputs-manifest.json"
t "rule 31" "two fips builds write exactly the named -fips files under --out, byte-identical" oid_cmp "$ofA" "$ofB" "x86_64/fscache-fips-0.3.0-r0.apk,x86_64/APKINDEX.tar.gz,fscache-modules-fips.spdx.json,inputs-manifest-fips.json"
oidC=$(mo); run_s "${bae[@]}" "$BA" "${ba_args[@]}" --out "$oidC"; run_s "${bae[@]}" "$BA" "${ba_args[@]}" --variant fips --recipe "$fx/melange-fips.yaml" --out "$oidC"
t "rule 31" "standard then fips into ONE --out (the chain's call order): both variants' files are present and neither overwrote the other's" bash -c "cd '$oidC' && test -f fscache-modules.spdx.json && test -f fscache-modules-fips.spdx.json && test -f inputs-manifest.json && test -f inputs-manifest-fips.json && cmp -s fscache-modules.spdx.json '$oidA/fscache-modules.spdx.json' && cmp -s inputs-manifest.json '$oidA/inputs-manifest.json'"
# ---- end verbatim sections ----
# ===== the restructure for the release chain's script judge (advisor ruling Oct 12, handoff 0393; REQ-CHAIN-001-AC1) ==========
# Structure facts, each a plain text or run check of the committed files (the judge itself lives in the chain tree, not here):
# a thin bash entry that names only literal repo-relative listed scripts, the sealed environment as committed data, the inline
# Python in a listed helper, no assignment of a protected name, run from the repository root only.
HP="$root/bin/build-apk-helper.py" SE="$root/build/sealed-env.json"
t "chain" "the entry has a shebang and mode 100755" bash -c "head -n 1 '$BA_PROD' | grep -q '^#!/usr/bin/env bash\$' && test -x '$BA_PROD'"
t "chain" "the entry assigns none of the protected names (PATH, BASH_ENV, ENV, LD_*, PYTHON*, NODE_OPTIONS, IFS, CDPATH, PROMPT_COMMAND, PS4, SHELLOPTS, BASHOPTS): the judge's own pattern finds no assignment anywhere in the text, comments included" python3 - "$BA_PROD" <<'P'
import re, sys
t = open(sys.argv[1]).read()
rx = re.compile(r"(?<![\w$])(?:(?:export|local|readonly|typeset)\s+|declare\s+(?:-\w+\s+)?)?(PATH|BASH_ENV|ENV|LD_[A-Z0-9_]+|PYTHON[A-Z0-9_]*|NODE_OPTIONS|IFS|CDPATH|PROMPT_COMMAND|PS4|SHELLOPTS|BASHOPTS)\+?=")
m = rx.search(t)
sys.exit("assigns %s at offset %d" % (m.group(1), m.start()) if m else 0)
P
t "chain" "the entry mentions none of the protected names outside a pure \$NAME read (comments and strings included)" python3 - "$BA_PROD" <<'P'
import re, sys
t = open(sys.argv[1]).read()
phrase = "no Go toolchain on PATH in CI"   # the one message an existing case fixes by name; the row lists it as an env_mentions entry
assert t.count(phrase) == 1, "the CI message is the one allowed mention"
t = t.replace(phrase, "")
rx = re.compile(r"(?<![A-Za-z0-9_])(PATH|BASH_ENV|ENV|LD_[A-Za-z0-9_]+|PYTHON[A-Za-z0-9_]*|NODE_OPTIONS|IFS|SHELLOPTS|BASHOPTS|CDPATH|GLOBIGNORE|PS4|PROMPT_COMMAND)(?![A-Za-z0-9_])")
bad = [m.group(1) for m in rx.finditer(t) if not (t[max(0, m.start() - 1):m.start()] == "$" or (t[max(0, m.start() - 2):m.start()] == "${" and t[m.end():m.end() + 1] == "}"))]
sys.exit("mentions %s" % sorted(set(bad)) if bad else 0)
P
t "chain" "no python3 -c, no python3 - (stdin), no here-document: the inline Python lives in the listed helper" python3 - "$BA_PROD" <<'P'
import re, sys
t = open(sys.argv[1]).read()
bad = re.findall(r"python3?\s+-c\b|python3?\s+-(?:\s|$)|<<-?\s*['\"]?[A-Za-z_]", t)
sys.exit("found %r" % bad if bad else 0)
P
t "chain" "every interpreter call is handed a literal repo-relative listed file (no variable path, no command substitution)" python3 - "$BA_PROD" "$root" <<'P'
import os, re, sys
t, root = open(sys.argv[1]).read(), sys.argv[2]
bad, seen = [], []
for m in re.finditer(r"(?m)^[^#\n]*?(?<![\w./-])(?:python3?|bash|sh|\"\$PY3\"(?:\s+-[IB])*)\s+(\S+)", t):
    w = m.group(1)
    seen.append(w)
    if not re.fullmatch(r"bin/[A-Za-z0-9._-]+\.(?:py|sh)", w) or not os.path.isfile(os.path.join(root, w)):
        bad.append(w)
need = {"bin/apk-tool.py", "bin/go-module-sbom.py", "bin/net-probe.py", "bin/build-apk-helper.py"}
sys.exit("bad %r" % bad if bad else ("missing calls %r" % sorted(need - set(seen)) if need - set(seen) else 0))
P
t "chain" "no command word is built by substitution or an absolute path, and no \$here or \$root remains" python3 - "$BA_PROD" <<'P'
import re, sys
t = open(sys.argv[1]).read()
bad = re.findall(r"(?m)^\s*(?:\$\(|`|/)\S*|\$here\b|\$root\b|\$\{here\}|\$\{root\}", t)
sys.exit("found %r" % bad if bad else 0)
P
t "chain" "run from anywhere but the repository root: refused, exit 2, naming the repository root, no tool run" bash -c "
  : >'$CALLS'; cd '$work' && env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 PATH='$stubs':\$PATH CALLS='$CALLS' STUB_LIB='$work/lib.py' \
    '$BA' ${ba_args[*]} --out $(mo) >'$work/elsewhere.log' 2>&1 </dev/null; r=\$?
  test \$r = 2 && grep -qi 'repository root' '$work/elsewhere.log' && ! grep -Eq '^(melange|sudo|sysctl|unshare) ' '$CALLS'"
t "chain" "a missing melange is a named failure (exit 1) saying the chain installs it, and neither the script nor its output names bin/install-build-tools.sh (the row's runs lists only what the script runs)" bash -c "
  nm='$work/stubs-nomelange'; rm -rf \"\$nm\"; mkdir -p \"\$nm\"; for f in '$stubs'/*; do case \$(basename \$f) in melange) ;; *) cp -p \$f \"\$nm/\";; esac; done
  : >'$CALLS'; env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 PATH=\"\$nm\":\$PATH CALLS='$CALLS' STUB_LIB='$work/lib.py' TEST_MELANGE=\"\$nm/melange\" \
    '$BA' ${ba_args[*]} --out $(mo) >'$work/nomelange.log' 2>&1 </dev/null; r=\$?
  test \$r = 1 && grep -qi 'melange is not installed (the chain installs it before this step)' '$work/nomelange.log' \
    && ! grep -q 'install-build-tools' '$work/nomelange.log' && ! grep -q 'install-build-tools' '$BA_PROD'"
t "chain" "the sealed environment is committed data: exactly the rule 23 list (a closed PATH, HOME=/root, LC_ALL=C, SOURCE_DATE_EPOCH from the environment), nothing else" python3 - "$SE" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
want_env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LC_ALL": "C"}
assert d["closed"] == want_env, d["closed"]
assert d["from_environment"] == ["SOURCE_DATE_EPOCH"], d["from_environment"]
assert set(d) == {"closed", "from_environment"}, sorted(d)   # no test_mode_* key: nothing but these two is read
P
t "chain" "the helper's sealed-env prints exactly the four closed entries, NUL-separated, whatever STUB_/FAKE_ variables or FSCACHE_TEST_MODE the caller has" bash -c "
  env SOURCE_DATE_EPOCH=$SDE STUB_X=1 FAKE_X=1 python3 '$HP' sealed-env '$SE' | python3 -c \"
import sys
v = sys.stdin.buffer.read().split(b'\\0')
assert v[-1] == b'', v
assert v[:-1] == [b'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', b'HOME=/root', b'LC_ALL=C', b'SOURCE_DATE_EPOCH=$SDE'], v\""
t "chain" "the helper's build-date turns SOURCE_DATE_EPOCH into the ISO time and refuses a non-date (exit 1)" bash -c "
  test \"\$(python3 '$HP' build-date 1789952380)\" = 2026-09-21T00:59:40Z && test \"\$(python3 '$HP' build-date 0)\" = 1970-01-01T00:00:00Z \
  && ! python3 '$HP' build-date yesterday >/dev/null 2>&1"
t "chain" "the helper's recipe-facts reads the package name, this architecture's Go tarball and pin and the pinned environment from the committed recipe" bash -c "
  python3 '$HP' recipe-facts '$root/build/melange.yaml' amd64 '$work/facts.txt' && grep -q '^name=fscache\$' '$work/facts.txt' && grep -Eq '^file=go[0-9.]+\.linux-amd64\.tar\.gz\$' '$work/facts.txt' \
  && grep -Eq '^sha=[0-9a-f]{64}\$' '$work/facts.txt' && grep -q '^pin=busybox=' '$work/facts.txt'"

# ===== round 1 of the review of PR 341: real signature verification, no test hook in the production scripts ====================================
# apk-tool.py verify: the signature member's BYTES are checked against a public key, the name alone is never a verdict (REQ-BUILDAPK-001-AC4, AC7)
AKEY="$root/build/keys/assembly.rsa" APUB="$root/build/keys/assembly.rsa.pub"
openssl genrsa -out "$work/other.rsa" 2048 2>/dev/null; openssl rsa -in "$work/other.rsa" -pubout -out "$work/other.rsa.pub" 2>/dev/null
python3 - "$work" "$AKEY" "$work/other.rsa" <<'P'
import sys
sys.path.insert(0, sys.argv[1]); import lib
w, akey, okey = sys.argv[1:4]
f = {"usr/bin/fscache": b"bin"}
lib.mkapk(w + "/v/good.apk", "fscache", "0.3.0-r0", f, signkey=akey)                       # RSA (sha1), signed with the committed assembly key
lib.mkapk(w + "/v/good256.apk", "fscache", "0.3.0-r0", f, sigalg="RSA256", signkey=akey)   # RSA256
lib.mkapk(w + "/v/other.apk", "fscache", "0.3.0-r0", f, signkey=okey)                      # signed by ANOTHER key but named assembly.rsa.pub
lib.mkapk(w + "/v/unsigned.apk", "fscache", "0.3.0-r0", f, signer=None)
import os
os.environ["STUB_FAKE_SIG"] = "1"
lib.mkapk(w + "/v/fake.apk", "fscache", "0.3.0-r0", f)                                     # the member name is right, the bytes are text
# a good signature over a DIFFERENT control section: the signature stream of good.apk in front of the control and data of another package
g = open(w + "/v/good.apk", "rb").read()
os.environ.pop("STUB_FAKE_SIG")
lib.mkapk(w + "/v/evil-src.apk", "evil", "6.6.6-r0", f, signer=None)
e = open(w + "/v/evil-src.apk", "rb").read()
import zlib
def first_stream_len(b):
    d = zlib.decompressobj(31); d.decompress(b); return len(b) - len(d.unused_data)
open(w + "/v/swapped.apk", "wb").write(g[:first_stream_len(g)] + e)
P
vf() { python3 "$root/bin/apk-tool.py" verify "$@"; }
t "rule 22" "apk-tool verify: an apk signed with the committed assembly key verifies against assembly.rsa.pub (RSA, sha1) and prints the name" bash -c "test \"\$(python3 '$root/bin/apk-tool.py' verify '$work/v/good.apk' '$APUB')\" = verified:assembly.rsa.pub"
t "rule 22" "apk-tool verify: the RSA256 (sha256) form verifies too" bash -c "python3 '$root/bin/apk-tool.py' verify '$work/v/good256.apk' '$APUB' >/dev/null"
fails "rule 22" "apk-tool verify: an apk signed by another key under the assembly key's NAME does not verify (exit 1)" 'does not verify' python3 "$root/bin/apk-tool.py" verify "$work/v/other.apk" "$APUB"
fails "rule 22" "apk-tool verify: a member named .SIGN.RSA.assembly.rsa.pub holding text is not a signature (exit 1)" 'does not verify' python3 "$root/bin/apk-tool.py" verify "$work/v/fake.apk" "$APUB"
fails "rule 22" "apk-tool verify: a good signature in front of another package's control section does not verify" 'does not verify' python3 "$root/bin/apk-tool.py" verify "$work/v/swapped.apk" "$APUB"
fails "rule 22" "apk-tool verify: an unsigned apk has nothing to verify (exit 1)" 'unsigned|nothing to verify' python3 "$root/bin/apk-tool.py" verify "$work/v/unsigned.apk" "$APUB"
fails "rule 22" "apk-tool verify: the right apk against the wrong public key does not verify" 'does not verify' python3 "$root/bin/apk-tool.py" verify "$work/v/good.apk" "$work/other.rsa.pub"
# the drivers verify, not read names
run_s env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_FAKE_SIG=1 "$BA" "${ba_args[@]}" --out "$(mo)"
t "rule 22" "build-apk.sh: a build whose apk carries the right signature NAME over bytes that are not a signature is refused (exit 1) naming the verification" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'does not verify' '$work/log'"
t "rule 22" "build-apk.sh: the same build with the real signature passes (the control for the refusal above)" bash -c "run() { env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 PATH='$stubs':\$PATH CALLS='$CALLS' STUB_LIB='$work/lib.py' '$BA' ${ba_args[*]} --out $(mo) >'$work/ctl.log' 2>&1 </dev/null; }; run && ! grep -qi 'does not verify' '$work/ctl.log'"
# release signing: both sides and the result are verified
python3 - "$work" <<'P'
import os, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w = sys.argv[1]
for side in ("fkA", "fkB"):
    os.makedirs("%s/%s/x86_64" % (w, side), exist_ok=True)
os.environ["STUB_FAKE_SIG"] = "1"
lib.mkapk(w + "/fkA/x86_64/fscache-0.3.0-r0.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"bin"})
os.environ.pop("STUB_FAKE_SIG")
lib.mkapk(w + "/fkB/x86_64/fscache-0.3.0-r0.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"bin"})
for side in ("fkC", "fkD"):   # a good pair, for the release-signing run whose signing tool leaves a bad signature
    lib.mkapk("%s/%s/x86_64/fscache-0.3.0-r0.apk" % (w, side), "fscache", "0.3.0-r0", {"usr/bin/fscache": b"bin"})
P
sr "rule 22" "release signing: a Build apk with the assembly NAME over a fake signature is refused (exit 2, nothing signed): the name is not a signature" 'does not verify' "$RS" --build-dir "$work/fkA" --rebuild-dir "$work/fkB" --key "$work/release.rsa"
run_s env STUB_FAKE_SIG=1 "$RS" --build-dir "$work/fkC" --rebuild-dir "$work/fkD" --key "$work/release.rsa"
t "rule 22" "release signing: a signing tool that leaves a signature that does not verify against release.rsa.pub is refused after signing (exit 1), nothing replaced" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'does not verify' '$work/log'"
# no test hook in the production scripts, and the test copies differ from them only on the TEST-SUBST lines
t "rule 11" "production bin/build-apk.sh, bin/release-sign-apks.sh and bin/build-apk-helper.py hold no test hook: no FSCACHE_TEST_MODE, no --recipe, no --keys-dir, no STUB_/FAKE_ name, no test_mode" bash -c "! grep -En 'FSCACHE_TEST_MODE|--recipe|--keys-dir|STUB_|FAKE_|test_mode' '$BA_PROD' '$RS_REAL' '$HP' | grep -v '^[^:]*:[0-9]*:#'"
t "rule 11" "the test copy of build-apk.sh differs from the production file in the TEST-SUBST lines only" python3 - "$BA_PROD" "$work/ba-copy.sh" <<'P'
import re, sys
a, b = open(sys.argv[1]).read().split("\n"), open(sys.argv[2]).read().split("\n")
assert len(a) == len(b), (len(a), len(b))
sub = re.compile(r"#\s*TEST-SUBST")
diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
assert diff and all(sub.search(a[i]) and sub.search(b[i]) for i in diff), [a[i] for i in diff if not sub.search(a[i])]
P
t "rule 22" "the test copy of release-sign-apks.sh differs from the production file in the TEST-SUBST lines only" python3 - "$RS_REAL" "$work/rs-copy.sh" <<'P'
import re, sys
a, b = open(sys.argv[1]).read().split("\n"), open(sys.argv[2]).read().split("\n")
assert len(a) == len(b), (len(a), len(b))
sub = re.compile(r"#\s*TEST-SUBST")
diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
assert diff and all(sub.search(a[i]) and sub.search(b[i]) for i in diff), [a[i] for i in diff if not sub.search(a[i])]
P
t "rule 23" "production sealed environment: FAKE_SIGNING_KEY, STUB_RELEASE_TOKEN and FSCACHE_TEST_MODE in the caller's environment never reach the melange call" bash -c "
  env SOURCE_DATE_EPOCH=$SDE FSCACHE_TEST_MODE=1 FAKE_SIGNING_KEY=canary STUB_RELEASE_TOKEN=canary python3 '$HP' sealed-env '$SE' | python3 -c \"
import sys
v = sys.stdin.buffer.read().split(b'\\0')
assert not any(b'canary' in x or b'TEST_MODE' in x for x in v), v\""



# ---- round 2 of the review of PR 341: tools by fixed path, isolated interpreters, the data stream bound to the signature ----------------------------------------
hp="$work/hostile-bin"; mkdir -p "$hp"
printf '#!/bin/sh\necho "Verified OK"; exit 0\n' >"$hp/openssl"; chmod +x "$hp/openssl"
t "rule 22" "apk-tool verify: an openssl placed first on the caller's search path that answers 'Verified OK' is never run: a fake signature still does not verify" bash -c "
  ! env PATH='$hp':\$PATH python3 '$root/bin/apk-tool.py' verify '$work/v/fake.apk' '$APUB' >/dev/null 2>&1"
t "rule 22" "apk-tool verify: a changed data stream (its sha256 no longer the datahash the signed control section names) does not verify, though the control signature is intact" python3 - "$work" "$root" "$AKEY" "$APUB" <<'P'
import subprocess, sys, zlib
w, root, akey, apub = sys.argv[1:5]
g = open(w + "/v/good.apk", "rb").read()
d = zlib.decompressobj(31); d.decompress(g); n1 = len(g) - len(d.unused_data)            # end of the signature stream
d2 = zlib.decompressobj(31); d2.decompress(g[n1:]); n2 = n1 + (len(g) - n1 - len(d2.unused_data))   # end of the control stream
sys.path.insert(0, w); import lib
data = lib.gz(lib.tarb([("usr/bin/fscache", b"EVIL")]))
open(w + "/v/payload.apk", "wb").write(g[:n2] + data)
r = subprocess.run([sys.executable, root + "/bin/apk-tool.py", "verify", w + "/v/payload.apk", apub], capture_output=True, text=True)
assert r.returncode == 1 and "datahash" in r.stderr, (r.returncode, r.stderr)
P
t "rule 23" "every python3 call of build-apk.sh and release-sign-apks.sh runs isolated (-I): PYTHONPATH, user site and startup files of the caller are never read" python3 - "$BA_PROD" "$RS_REAL" <<'P'
import re, sys
bad = []
for p in sys.argv[1:]:
    for n, ln in enumerate(open(p).read().split("\n"), 1):
        if ln.lstrip().startswith("#"): continue
        for m in re.finditer(r"\"\$PY3\"(.{0,12})", ln):
            if not re.match(r"\s+-I\s+-B\b", m.group(1)): bad.append("%s:%d" % (p, n))
sys.exit("PY3 calls without -I: %r" % bad if bad else 0)
P
cat >"$work/toolscan.py" <<'PY'
import re, sys
# toolscan.py FILE WORD...: fail closed. A shell lexer with quote removal (m'elang'e is the word melange) and a stack for command
# substitution: $( ... ) and backticks are code at any nesting depth, also inside double quotes. Any word equal to a tool word, in code, is refused:
# the production scripts name every tool by variable, so a bare word is never legal. Quoted text is one word (a message is never a tool word).
def words(s):
    out, cur, st, i = [], "", ["code"], 0          # st: "code" | "dq" | "sq" | "sub" (a $( ... ) opened from dq or code, returns to what is beneath)
    def flush():
        nonlocal cur
        if cur: out.append(cur)
        cur = ""
    while i < len(s):
        c, m = s[i], st[-1]
        if m == "sq":
            if c == "'": st.pop()
            else: cur += c
        elif m == "dq":
            if s.startswith("$(", i): flush(); st.append("sub"); i += 1
            elif c == "`": flush(); st.append("bt")
            elif c == "\\" and i + 1 < len(s): cur += s[i + 1]; i += 1
            elif c == '"': st.pop()
            else: cur += c
        else:                                        # code, sub, bt: all are code
            if c == "'": st.append("sq")
            elif c == '"': st.append("dq")
            elif s.startswith("$(", i): flush(); st.append("sub"); i += 1
            elif c == "`":
                flush()
                if m == "bt": st.pop()
                else: st.append("bt")
            elif c == ")" and m == "sub": flush(); st.pop()
            elif c == "\\" and i + 1 < len(s): cur += s[i + 1]; i += 1
            elif c == "#" and not cur: break
            elif c in " \t;&|()<>{}=$": flush()
            else: cur += c
        i += 1
    flush()
    return out
bad = []
for n, ln in enumerate(open(sys.argv[1]).read().split("\n"), 1):
    if "TEST-SUBST" in ln: continue
    ws = words(ln.strip())
    bad += ["%s:%d %s" % (sys.argv[1], n, w) for w in sys.argv[2:] if w in ws]
sys.exit("bare tool words: %r" % bad if bad else 0)
PY
t "rule 23" "no bare tool in the security steps: build-apk.sh names sha256sum, go, env, sudo, unshare, melange, git, python3, openssl and shasum by variable (also as the operand of env, sudo or unshare)" python3 "$work/toolscan.py" "$BA_PROD" sha256sum go env sudo unshare melange git python3 openssl shasum
t "rule 23" "release-sign-apks.sh names openssl, melange and python3 by variable" python3 "$work/toolscan.py" "$RS_REAL" openssl melange python3
python3 - "$BA_PROD" "$work" <<'PY'
import sys
src = open(sys.argv[1]).read()
open(sys.argv[2] + "/mut-go.sh", "w").write(src.replace('"$GO_TOOL" version -m', 'go version -m'))
open(sys.argv[2] + "/mut-env.sh", "w").write(src.replace('"$SUDO" "$ENVBIN" -i', '"$SUDO" env -i'))
open(sys.argv[2] + "/mut-sum.sh", "w").write(src.replace('got=$("$SHA256SUM" ', 'got=$(sha256sum '))
open(sys.argv[2] + "/mut-melange.sh", "w").write(src.replace('"$UNSHARE" -n "$melange_bin"', '"$UNSHARE" -n melange'))
open(sys.argv[2] + "/mut-timeout.sh", "w").write(src.replace('"$GO_TOOL" version -m', 'timeout 30 go version -m'))
open(sys.argv[2] + "/mut-quote.sh", "w").write(src.replace('"$UNSHARE" -n "$melange_bin"', '"$UNSHARE" -n m\'elang\'e'))
open(sys.argv[2] + "/mut-nest.sh", "w").write(src.replace('gov=$("$ENVBIN" GOTOOLCHAIN=local', 'gov=$(true $(printf x); go version -m "$tmp/fscache.bin"; "$ENVBIN" GOTOOLCHAIN=local', 1))
open(sys.argv[2] + "/mut-nestq.sh", "w").write(src.replace('"$UNSHARE" -n "$melange_bin"', '"$UNSHARE" -n "$(true $(printf x); melange --version)"'))
open(sys.argv[2] + "/mut-chain.sh", "w").write(src.replace('"$SUDO" "$ENVBIN" -i', '"$SUDO" nice -n 5 "$ENVBIN" -u X env -i'))
PY
for m in mut-go mut-env mut-sum mut-melange mut-timeout mut-quote mut-nest mut-nestq mut-chain; do
  t "rule 23" "the mutant $m differs from the production script" bash -c "! cmp -s '$BA_PROD' '$work/$m.sh'"
  t "rule 23" "the tool-path assertion bites: the mutant $m (a bare tool where the fixed one is) is refused" bash -c "! python3 '$work/toolscan.py' '$work/$m.sh' sha256sum go env sudo unshare melange git python3 openssl shasum >/dev/null 2>&1"
done

echo "build-apk-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
