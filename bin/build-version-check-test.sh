#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC7
# bin/build-version-check.py (--binary PATH | --apk-dir DIR --variant standard|fips) --tag TAG --sha SHA, with a fake `go version -m`.
# Exit 0 only for module version == the tag and vcs.revision == SHA and not modified; otherwise exit 1 naming
# `version` / `revision` / `modified` / `devel`. With --apk-dir the checker finds the variant's one apk and extracts usr/bin/fscache with apk-tool.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
BV="$root/bin/build-version-check.py"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
FB="$W/fakebin"; mkdir -p "$FB"
SHA=0123456789abcdef0123456789abcdef01234567
bi() { printf '%s\n' "$1: go1.27.2" "	path	github.com/fosterstack/cache/cmd/fscache" "	mod	github.com/fosterstack/cache	$2	" \
    "	build	-ldflags=\"-s -w\"" "	build	vcs=git" "	build	vcs.revision=$3" "	build	vcs.modified=$4";
}
# REQ-CHAIN-004-AC7 (release-candidate review, build area): the version check reads the buildinfo with the pinned toolchain at its fixed path
# and a closed environment, never a `go` found on PATH. The production file holds the path as one TEST-SUBST line; the cases run a copy that
# differs from it in that line only and points it at a recording wrapper.
VCGO="$W/vcgo/go"; mkdir -p "$W/vcgo"
cat > "$VCGO" <<EOF
#!/bin/bash
{ echo "WHICH-GO pinned \$*"; for v in GOTOOLCHAIN GOFLAGS GOENV GOROOT GOPROXY GOPATH GOMODCACHE GOEXPERIMENT; do echo "ENV \$v=\${!v-unset}"; done; } >> "$W/vcgo.log"
/bin/cat "$W/buildinfo.txt"
EOF
chmod +x "$VCGO"
cat > "$FB/go" <<EOF
#!/usr/bin/env bash
echo "WHICH-GO runner-path \$*" >> "$W/vcgo.log"
cat "$W/buildinfo.txt"
EOF
chmod +x "$FB/go"
mkvcopy() { # mkvcopy OUT GOPATH: a copy of the production file whose TEST-SUBST line points at GOPATH, differing from it in no other line
  python3 - "$BV" "$1" "$2" <<'PY'
import re, sys
src, out, gopath = sys.argv[1:4]
lines = open(src).read().split("\n"); res = []; n = 0
for ln in lines:
    if re.match(r"^GO_TOOL = .*#\s*TEST-SUBST\s*$", ln):
        res.append('GO_TOOL = "%s"  # TEST-SUBST' % gopath); n += 1
    else:
        res.append(ln)
if n != 1:
    sys.exit("expected exactly one GO_TOOL line marked TEST-SUBST in %s, found %d" % (src, n))
open(out, "w").write("\n".join(res))
PY
}
if mkvcopy "$W/bvc.py" "$VCGO" 2> "$W/mkvcopy.err"; then
  BVR=$BV; BV="$W/bvc.py"
  ok "AC7 the version check holds its go as one TEST-SUBST line (the cases run a copy that differs in that line only)"
else
  bad "AC7 the version check holds its go as one TEST-SUBST line: $(head -c 150 "$W/mkvcopy.err" 2> /dev/null)"; BVR=$BV
fi
hostile() { # env settings a hostile or sloppy runner could carry into the check
  GOTOOLCHAIN=go1.99.9 GOFLAGS=-mod=mod GOENV=/nonexistent/env GOROOT=/nonexistent/goroot GOPROXY=https://evil.invalid GOPATH=/nonexistent/gopath \
    GOMODCACHE=/nonexistent/mod GOEXPERIMENT=evil "$@"
}
vc() { # vc ok|refuse LABEL WORD VERSION REV MODIFIED [TAG]
  local want=$1 label=$2 word=$3 ver=$4 rev=$5 mod=$6 tag=${7:-v0.3.0} rc=0
  bi out/fscache "$ver" "$rev" "$mod" > "$W/buildinfo.txt"; : > "$W/fscache"
  PATH="$FB:$PATH" FAKE_BUILDINFO="$W/buildinfo.txt" python3 "$BV" --binary "$W/fscache" --tag "$tag" --sha "$SHA" > "$W/vc.out" 2> "$W/vc.err" || rc=$?
  if grep -q Traceback "$W/vc.err"; then bad "$label -> a Python traceback is a crash, not a refusal"; return; fi
  if [ "$want" = ok ]; then [ "$rc" = 0 ] && ok "$label" || bad "$label -> exit $rc: $(head -c 150 "$W/vc.err")"
  else [ "$rc" = 1 ] && grep -Fqi -- "$word" "$W/vc.err" && ok "$label" || bad "$label -> exit $rc, wanted 1 naming '$word': $(head -c 150 "$W/vc.err")"; fi
}
vc ok     "AC7 the embedded version is the tag and the revision is the tagged commit" "" v0.3.0 "$SHA" false
vc refuse "AC7 (devel) is refused (rule 24)" devel "(devel)" "$SHA" false
vc refuse "AC7 a different version than the tag is refused" version v0.3.1 "$SHA" false
vc refuse "AC7 a different revision is refused" revision v0.3.0 fedcba9876543210fedcba9876543210fedcba98 false
vc refuse "AC7 a missing revision is refused" revision v0.3.0 "" false
vc refuse "AC7 a modified-tree marker is refused" modified v0.3.0 "$SHA" true
vc refuse "AC7 a pseudo-version is refused" version v0.3.1-0.20261009120000-0123456789ab "$SHA" false
vc refuse "AC7 the tag with a prefix of the version is refused (v0.3.0-rc.1 vs v0.3.0)" version v0.3.0-rc.1 "$SHA" false
vc ok     "AC7 a release candidate tag matches its own version" "" v0.3.1-rc.2 "$SHA" false v0.3.1-rc.2
vc refuse "AC7 an upper-case revision of the same commit is not accepted as equal" revision v0.3.0 "$(printf '%s' "$SHA" | tr a-f A-F)" false
# buildinfo shapes `go version -m` really prints: a dep line carrying the tag, no vcs lines at all
# (-buildvcs=false), a second mod line
vcf() { # vcf ok|refuse LABEL WORD  (buildinfo text on stdin)
  local want=$1 label=$2 word=$3 rc=0
  cat > "$W/buildinfo.txt"; : > "$W/fscache"
  PATH="$FB:$PATH" FAKE_BUILDINFO="$W/buildinfo.txt" python3 "$BV" --binary "$W/fscache" --tag v0.3.0 --sha "$SHA" > "$W/vc.out" 2> "$W/vc.err" || rc=$?
  if grep -q Traceback "$W/vc.err"; then bad "$label -> a Python traceback is a crash, not a refusal"; return; fi
  if [ "$want" = ok ]; then [ "$rc" = 0 ] && ok "$label" || bad "$label -> exit $rc: $(head -c 150 "$W/vc.err")"
  else [ "$rc" = 1 ] && grep -Fqi -- "$word" "$W/vc.err" && ok "$label" || bad "$label -> exit $rc, wanted 1 naming '$word': $(head -c 150 "$W/vc.err")"; fi
}
vcf refuse \
  "AC7 a DEP line carrying the tag does not make the module version the tag (only the main module's mod line counts)" \
  version < <(
  printf '%s\n' "out/fscache: go1.27.2" "	path	github.com/fosterstack/cache/cmd/fscache" \
    "	mod	github.com/fosterstack/cache	v0.3.1	" \
    "	dep	example.com/other	v0.3.0	h1:abc=" "	build	vcs.revision=$SHA" "	build	vcs.modified=false")
vcf refuse \
  "AC7 no vcs lines at all (built with -buildvcs=false) is refused: the revision cannot be proven" revision < <(
  printf '%s\n' "out/fscache: go1.27.2" "	path	github.com/fosterstack/cache/cmd/fscache" \
    "	mod	github.com/fosterstack/cache	v0.3.0	" \
    "	build	-buildvcs=false")
vcf refuse "AC7 a second mod line is ambiguous and refused" mod < <(
  printf '%s\n' "out/fscache: go1.27.2" "	path	github.com/fosterstack/cache/cmd/fscache" \
    "	mod	github.com/fosterstack/cache	v0.3.0	" \
    "	mod	github.com/evil/cache	v0.3.0	" "	build	vcs.revision=$SHA" "	build	vcs.modified=false")
vcf refuse "AC7 two vcs.revision lines are ambiguous and refused" revision < <(
  printf '%s\n' "out/fscache: go1.27.2" "	path	github.com/fosterstack/cache/cmd/fscache" \
    "	mod	github.com/fosterstack/cache	v0.3.0	" \
    "	build	vcs.revision=$SHA" "	build	vcs.modified=false" \
    "	build	vcs.revision=fedcba9876543210fedcba9876543210fedcba98")
vcf ok "AC7 a dep line that also says v0.3.0 is not an obstacle when the main module and the revision are right" "" < <(
  printf '%s\n' "out/fscache: go1.27.2" "	path	github.com/fosterstack/cache/cmd/fscache" \
    "	mod	github.com/fosterstack/cache	v0.3.0	" \
    "	build	vcs.revision=$SHA" "	build	vcs.modified=false" "	dep	example.com/other	v0.3.0	h1:abc=")
# the apk directory form: the checker finds the variant's apk itself, extracts the binary with apk-tool, then checks as --binary does
mkdir -p "$W/vcwd/bin";
printf '%s\n' '#!/usr/bin/env python3' 'import os, sys' \
    'open(os.environ.get("FAKE_LOG", "/dev/null"), "a").write("apk-tool " + " ".join(sys.argv[1:]) + "\n")' 'sys.stdout.write("BINARY")' > \
    "$W/vcwd/bin/apk-tool.py"
vca() { # vca ok|refuse LABEL WORD VARIANT TAG VERSION APK...   (APK: the file names in the apk directory)
  local want=$1 label=$2 word=$3 variant=$4 tag=$5 ver=$6 rc=0; shift 6
  rm -rf "$W/apkd"; mkdir -p "$W/apkd"; for n in "$@"; do : > "$W/apkd/$n"; done; : > "$W/vc.log"
  bi out/fscache "$ver" "$SHA" false > "$W/buildinfo.txt"
  (cd "$W/vcwd" && PATH="$FB:$PATH" FAKE_LOG="$W/vc.log" FAKE_BUILDINFO="$W/buildinfo.txt" python3 "$BV" --apk-dir "$W/apkd" --variant "$variant" \
      --tag "$tag" --sha "$SHA" > "$W/vc.out" 2> "$W/vc.err") || rc=$?
  if grep -q Traceback "$W/vc.err"; then bad "$label -> a Python traceback is a crash, not a refusal"; return; fi
  if [ "$want" = ok ];
  then [ "$rc" = 0 ] && grep -Fq -- "apk-tool cat $W/apkd/$word" "$W/vc.log" && ok "$label" || bad \
      "$label -> exit $rc, apk-tool log '$(head -c 120 "$W/vc.log")', stderr $(head -c 120 "$W/vc.err")"
  else [ "$rc" = 1 ] && grep -Fqi -- "$word" "$W/vc.err" && ok "$label" || bad "$label -> exit $rc, wanted 1 naming '$word': $(head -c 150 "$W/vc.err")"; fi
}
vca ok "AC7 apk directory: the standard apk is found by its variant and its binary is checked" fscache-0.3.0-r0.apk standard v0.3.0 v0.3.0 \
    fscache-0.3.0-r0.apk fscache-fips-0.3.0-r0.apk
vca ok "AC7 apk directory: the fips apk is found by its variant (not the standard one)" fscache-fips-0.3.0-r0.apk fips v0.3.0 v0.3.0 \
    fscache-0.3.0-r0.apk fscache-fips-0.3.0-r0.apk
vca ok \
    "AC7 apk directory: a release candidate's apk (fscache-0.3.0_rc1-r0.apk, PROPOSED) is found and its embedded version v0.3.0-rc.1 matches the tag" \
    fscache-0.3.0_rc1-r0.apk standard v0.3.0-rc.1 v0.3.0-rc.1 fscache-0.3.0_rc1-r0.apk fscache-fips-0.3.0_rc1-r0.apk
vca refuse "AC7 apk directory: two standard apks are ambiguous and refused" apk standard v0.3.0 v0.3.0 fscache-0.3.0-r0.apk fscache-0.3.1-r0.apk
vca refuse "AC7 apk directory: no fips apk is refused" apk fips v0.3.0 v0.3.0 fscache-0.3.0-r0.apk
vca refuse "AC7 apk directory: a binary whose version is not the tag is refused (the check after the extraction is the same)" version standard v0.3.0 \
    v0.3.1 fscache-0.3.0-r0.apk
rc=0
(cd "$W/vcwd" && PATH="$FB:$PATH" python3 "$BV" --apk-dir "$W/apkd" --binary "$W/fscache" --variant standard --tag v0.3.0 --sha "$SHA" > /dev/null 2> \
    "$W/vc.err") || rc=$?
if [ "$rc" = 2 ]; then
  ok "AC7 both --binary and --apk-dir is a usage error (exit 2)"
else
  bad "AC7 both options -> exit $rc, wanted 2"
fi
# the fixed path and the closed environment (the cases above ran through the wrapper at the substituted path, with a runner `go` on PATH)
bi out/fscache v0.3.0 "$SHA" false > "$W/buildinfo.txt"; : > "$W/fscache"; : > "$W/vcgo.log"; rc=0
hostile env PATH="$FB:$PATH" python3 "$BV" --binary "$W/fscache" --tag v0.3.0 --sha "$SHA" > /dev/null 2> "$W/vc.err" || rc=$?
[ "$rc" = 0 ] && grep -q 'WHICH-GO pinned version -m' "$W/vcgo.log" && ! grep -q 'runner-path' "$W/vcgo.log" \
  && ok "AC7 the buildinfo is read by the go at the fixed path, never the runner's go on PATH" \
  || bad "AC7 fixed go path -> exit $rc, log: $(head -c 200 "$W/vcgo.log")"
for want in GOTOOLCHAIN=local GOFLAGS= GOENV=off GOROOT=unset GOPROXY=unset GOPATH=unset GOMODCACHE=unset GOEXPERIMENT=unset; do
  grep -qxF "ENV $want" "$W/vcgo.log" && ok "AC7 the go call's environment has $want (closed: nothing inherited)" || bad "AC7 the go call's environment lacks $want: $(grep '^ENV' "$W/vcgo.log" | tr '\n' ' ')"
done
mkvcopy "$W/bvc-absent.py" "$W/no-such-go"; rc=0; : > "$W/vcgo.log"
PATH="$FB:$PATH" python3 "$W/bvc-absent.py" --binary "$W/fscache" --tag v0.3.0 --sha "$SHA" \
  > /dev/null 2> "$W/vc.err" || rc=$?
[ "$rc" = 1 ] && grep -Fq "buildinfo" "$W/vc.err" && ! grep -q 'runner-path' "$W/vcgo.log" \
  && ok "AC7 an absent go at the fixed path is a refusal, and PATH is not consulted" \
  || bad "AC7 absent go -> exit $rc, stderr $(head -c 150 "$W/vc.err"), log $(head -c 100 "$W/vcgo.log")"
grep -Eq '^GO_TOOL = "/usr/local/bin/fscache-go/bin/go"  # TEST-SUBST$' "$BVR" \
  && ok "AC7 the production file names the pinned toolchain's fixed path" \
  || bad "AC7 the production file does not name /usr/local/bin/fscache-go/bin/go"
! grep -Eq 'subprocess\.run\(\[ *"go"' "$BVR" \
  && ok "AC7 the production file never runs go by its bare name" \
  || bad "AC7 the production file runs go by its bare name"
echo "build-version-check: $pass passed, $failn failed"
[ "$failn" = 0 ]
