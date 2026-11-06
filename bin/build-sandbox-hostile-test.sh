#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC5
# Offline half of the sandbox wall probe (sandboxed-build rules 3, 5 and 6; sibling of bin/chain-hostile-test.sh, the
# static half of the hostile Build step). bin/chain-sandbox-probe.sh renders six test-only recipes
# (build/probe/*.yaml.tmpl), runs each through the same sealed melange call as the apk build and judges by melange's
# exit status alone: every attempt recipe is `if <attempt>; then exit 1; fi`, so a wall is held only when melange
# exits 0. Here melange, unshare and sudo are stubs and the probe runs as a COPY in which exactly the lines ending in
# TEST-SUBST are replaced (no other line may differ): this test proves the verdicts, the sealed shape and the
# leak-freeness of the probe; the walls themselves are proved by the signed release-candidate run.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'chmod -R u+w "$work" 2> /dev/null; rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); }
bad() { failn=$((failn + 1)); echo "FAIL [$1] $2"; }
t() { local ac=$1 d=$2; shift 2; if "$@" > "$work/out" 2>&1; then ok; else bad "$ac" "$d"; fi; }
# exits <rule> <desc> <status> <cmd...>: the command exits with exactly that status (its output is kept in $work/o)
exits() {
  local ac=$1 d=$2 want=$3; shift 3; "$@" > "$work/o" 2>&1; local r=$?
  if [ "$r" = "$want" ]; then ok; else bad "$ac" "$d (exit $r, wanted $want)"; fi
}

PROBE="$root/bin/chain-sandbox-probe.sh"
WALLS="read-record write-record read-keydir read-token network"
mkdir -p "$work/bin" "$work/rt" "$work/tmp"
# The fixture checkout the probe runs in: the committed bin/ and build/ by link, a Witness record and an archive of
# its own.
co="$work/co"; mkdir -p "$co/witness-apk" "$co/archive/keys"
ln -s "$root/bin" "$co/bin"; ln -s "$root/build" "$co/build"
printf '{"record": "fixture"}\n' > "$co/witness-apk/apk-collection.local.json"
: > "$co/archive/keys/wolfi-signing.rsa.pub"
SENT_TOKEN="SENTINEL-TOKEN-$$-4d1c"
# The stubs. melange logs its call and exits with the status the case set for the recipe it was given (one file per
# wall).
# The control also leaves a folder it makes unwritable (what a root-run melange leaves under --out-dir). A stub step can
# change the record, or print words. The sealed call runs under env -i, so the stubs hold their paths themselves.
cat > "$work/bin/melange" << STUB
#!/usr/bin/env bash
recipe=\$2
echo "melange \$*" >> "$work/calls"
wall=\${recipe#probe-}; wall=\${wall%.yaml}
rc=\$(cat "$work/rc/\$wall" 2> /dev/null || echo 1)
if [ "\$wall" = control ]; then
  out=\$(printf '%s\n' "\$@" | sed -n '/^--out-dir\$/{n;p;}')
  mkdir -p "\$out/x"; echo f > "\$out/x/f"; chmod 0555 "\$out/x"
  echo "listing of the sandbox view"
fi
[ "\$wall" != write-record ] || [ ! -f "$work/mutate" ] || echo forged >> "$co/witness-apk/apk-collection.local.json"
[ ! -f "$work/says" ] || echo "the attempt worked"
exit "\$rc"
STUB
printf '#!/usr/bin/env bash\nshift\nexec "$@"\n' > "$work/bin/unshare"
# sudo stub: root can remove what the runner cannot, so `sudo rm` first makes the operands writable
cat > "$work/bin/sudo" << 'STUB'
#!/usr/bin/env bash
if [ "$1" = rm ]; then for a in "${@:3}"; do chmod -R u+w "$a" 2> /dev/null; done; fi
exec "$@"
STUB
# python3 stub: the net probe (unshare -n python3 bin/net-probe.py) answers the status the case set; any other use is
# the real python3
cat > "$work/bin/python3" << STUB
#!/usr/bin/env bash
case "\$*" in *net-probe.py*) exit \$(cat "$work/netrc" 2> /dev/null || echo 101);; esac
exec /usr/bin/python3 "\$@"
STUB
chmod +x "$work/bin/"*
# a copy of the probe whose TEST-SUBST lines name the stubs and the fixture; the second argument is an optional extra
# sed expression
mkprobe() { # mkprobe OUT [sed expression]
  [ -f "$PROBE" ] || return 1
  sed -e "s#^PY3=[^ ]*#PY3=$work/bin/python3#; s#^SUDO=[^ ]*#SUDO=$work/bin/sudo#" \
    -e "s#^UNSHARE=[^ ]*#UNSHARE=$work/bin/unshare#" \
    -e "s#^MELANGE=[^ ]*#MELANGE=$work/bin/melange#; s#^REPO=[^ ]*#REPO=$co/archive#" \
    -e "s#^KEYRING=[^ ]*#KEYRING=$co/archive/keys/wolfi-signing.rsa.pub#" \
    -e "s#^RECORD=[^ ]*#RECORD=$co/witness-apk/apk-collection.local.json#" \
    ${2:+-e "$2"} "$PROBE" > "$1" && chmod +x "$1"
}
runprobe() { # runprobe COPY : from the fixture checkout, tmp folders under $work, a sentinel token in the environment
  (cd "$co" && TMPDIR="$work/tmp" RUNNER_TEMP="$work/rt" GH_TOKEN="$SENT_TOKEN" \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN="$SENT_TOKEN" bash "$1")
}
# setrc N: every wall stub exits N (0 = the recipe ran to its end and denied the attempt = held), the control exits 0
setrc() {
  local w; rm -rf "$work/rc" "$work/mutate" "$work/says"; mkdir -p "$work/rc"; echo 101 > "$work/netrc"
  for w in $WALLS; do echo "${1:-0}" > "$work/rc/$w"; done; echo 0 > "$work/rc/control"; : > "$work/calls"
}

t "AC5" "the probe and the six templates exist, the script is valid shell" \
  bash -c "[ -f '$PROBE' ] && bash -n '$PROBE' && [ \$(ls '$root/build/probe/'*.yaml.tmpl | wc -l) = 6 ]"
mkprobe "$work/probe.sh"
# only the TEST-SUBST lines differ between the probe and its copy (the method of the apk build's own test)
t "AC5" "the copy differs from the probe in TEST-SUBST lines only" python3 - "$PROBE" "$work/probe.sh" << 'PY'
import sys
a, b = open(sys.argv[1]).read().split("\n"), open(sys.argv[2]).read().split("\n")
assert len(a) == len(b), (len(a), len(b))
d = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
assert d and all("TEST-SUBST" in a[i] for i in d), d
PY
t "AC5" "no line of the probe or of this test is over 120 columns" \
  bash -c "! awk 'length>120' '$PROBE' '$root/bin/build-sandbox-hostile-test.sh' | grep -q ."
# the templates: one attempt each in the form `if <attempt>; then exit 1; fi`, a busybox-pinned environment, no key
# and no upload
t "AC5" "every template is one step, pinned to the busybox row, with no signing, upload or key" \
  python3 - "$root" << 'PY'
import glob, re, sys
for f in glob.glob(sys.argv[1] + "/build/probe/*.yaml.tmpl"):
    s = open(f).read()
    assert "@BUSYBOX@" in s and s.count("  - runs: |") == 1, f
    assert not re.search(r"cosign|upload|sign|key\.pem|fetch", re.sub(r"^#.*$", "", s, flags=re.M)), f
    if not f.endswith("control.yaml.tmpl"):
        body = s.split("  - runs: |\n")[1]
        joined = body.replace("\\\n", "")
        assert all(re.fullmatch(r"      if .*; then exit 1; fi", l) for l in joined.splitlines() if l.strip()), f
PY
t "AC5" "each attempt names its wall: the record (host path, copy), key folder, token names, address" \
  python3 - "$root" << 'PY'
import sys
d = sys.argv[1] + "/build/probe/"
want = {"read-record": ["cat @RECORD@", "/home/build/witness-apk/apk-collection.local.json"],
        "write-record": [">> @RECORD@"],
        "read-keydir": ["@KEYDIR@/dummy"],
        "read-token": ["ACTIONS_ID_TOKEN_REQUEST|ACTIONS_RUNTIME_TOKEN|GH_TOKEN|GITHUB_TOKEN", "cut -d = -f 1"],
        "network": ["192.0.2.1:9", "/proc/net/route"]}
for k, v in want.items():
    for x in v: assert x in open(d + k + ".yaml.tmpl").read(), (k, x)
PY
t "AC5" "the control reads the route table the network wall depends on" \
  grep -q 'cat /proc/net/route' "$root/build/probe/control.yaml.tmpl"
# the six templates are bound by hash: a template-only change must change a hash here (the hashes are data, no
# template text)
HASHES="277db462b97327e3cbc0731850f96c951f6fb64b81538930b588c851faa7fac3  build/probe/control.yaml.tmpl
6a8c80b624b77ebb004ef2528260bbfdae119e3aab290435d8c4b71e4096d3fc  build/probe/read-record.yaml.tmpl
8cbe432aa1741f9903fb2bd8419a0c27288270a056a4a4b855a43673b92f4bdb  build/probe/write-record.yaml.tmpl
32d50e8b55421866d20bbc620e8b7dd0fc7d8d3646eac82ee4467220e9083e9e  build/probe/read-keydir.yaml.tmpl
9f365493701556423ef2622e76a46e414191acb745c1e56ffb8f6247bdf36208  build/probe/read-token.yaml.tmpl
b7e43370bc58dfdeb3ad3c140c0651a523c6624e20f14e8169d562e9d843c095  build/probe/network.yaml.tmpl"
t "AC5" "the six templates equal the hashes bound in this test" \
  bash -c "cd '$root' && printf '%s\\n' \"\$0\" | sha256sum -c --quiet -" "$HASHES"

# the verdicts: melange's exit status decides, a wall is held only when melange exits 0, never by the words a step
# printed
setrc 0
exits "AC5" "every wall stub exits 0 (denied), the control passes, the net probe says sealed: exit 0" \
  0 runprobe "$work/probe.sh"
t "AC5" "melange ran the control first, then the five walls, once each" \
  bash -c "[ \$(grep -c '^melange build probe-' '$work/calls') = 6 ] && head -1 '$work/calls' | grep -q probe-control"
t "AC5" "the control's listing reaches the step log" grep -q "listing of the sandbox view" "$work/o"
t "AC5" "every melange call carries --source-dir <tmp>/src (an empty folder) and never the checkout" \
  bash -c "! grep -q -e '--source-dir $co' '$work/calls' &&
    [ \$(grep -c -e '--source-dir [^ ]*/src ' '$work/calls') = 6 ]"
for w in $WALLS; do
  setrc 0; echo 1 > "$work/rc/$w"
  exits "AC5" "the $w stub exits 1 (the attempt succeeded or the recipe did not run to its end): not held, exit 4" \
    4 runprobe "$work/probe.sh"
  t "AC5" "...and the output names $w as not held" grep -q "wall not held: $w" "$work/o"
done
setrc 0; echo 137 > "$work/rc/read-record"
exits "AC5" "melange killed (exit 137) on a wall is not held (exit 4), never 'all walls held'" \
  4 runprobe "$work/probe.sh"
setrc 0; touch "$work/says"
exits "AC5" "every wall stub exits 0 and prints 'the attempt worked': held (exit 0), the words are never read" \
  0 runprobe "$work/probe.sh"
setrc 1; touch "$work/says"
exits "AC5" "a stub that prints that it refused but exits 1 is not held (exit 4)" 4 runprobe "$work/probe.sh"
setrc 0; touch "$work/mutate"
exits "AC5" "a wall stub exits 0 but the record changed: the sha256 differs, exit 4" 4 runprobe "$work/probe.sh"
t "AC5" "...naming the record" grep -q "write-record" "$work/o"
setrc 0; echo 0 > "$work/netrc"
exits "AC5" "a namespace made with unshare -n that is not sealed (net probe exit 0): exit 4" 4 runprobe "$work/probe.sh"
setrc 0; echo 1 > "$work/rc/control"
exits "AC5" "a failed control is a probe error (exit 1), never held" 1 runprobe "$work/probe.sh"
t "AC5" "...and no wall was judged: melange ran only the control" \
  bash -c "[ \$(grep -c '^melange build' '$work/calls') = 1 ]"
setrc 0; echo 127 > "$work/rc/read-token"
exits "AC5" "melange not found (exit 127) on a wall is a probe error (exit 1)" 1 runprobe "$work/probe.sh"
setrc 0; echo 126 > "$work/rc/network"
exits "AC5" "melange not executable (exit 126) is a probe error (exit 1)" 1 runprobe "$work/probe.sh"
setrc 0; mv "$co/witness-apk/apk-collection.local.json" "$work/rec.saved"
exits "AC5" "a missing Witness record is a refusal (exit 2)" 2 runprobe "$work/probe.sh"
mv "$work/rec.saved" "$co/witness-apk/apk-collection.local.json"

# the sealed shape, judged by the pinned helper before melange runs: each mutant is refused (exit 2) and melange never
# runs
for m in "no-namespace:s/ --namespace fosterstack//" "no-runner:s/ --runner bubblewrap//" \
         "docker:s/--runner bubblewrap/--runner docker/" \
         "no-unshare-n:s# -n \"\$MELANGE\"# \"\$MELANGE\"#" "no-env-i:s#\"\$ENVBIN\" -i #\"\$ENVBIN\" #"; do
  name=${m%%:*}; expr=${m#*:}
  mkprobe "$work/probe-$name.sh" "$expr"; setrc 0
  exits "AC5" "sealed-call mutant $name is refused before melange runs (exit 2)" 2 runprobe "$work/probe-$name.sh"
  t "AC5" "...and melange never ran ($name)" bash -c "[ ! -s '$work/calls' ]"
done

# nothing left behind (also what a root-run melange leaves), nothing signed, no secret printed
setrc 0; ls -R "$co" > "$work/co-before"; runprobe "$work/probe.sh" > "$work/transcript" 2>&1; echo $? > "$work/rc.last"
t "AC5" "a run that leaves an unwritable folder under --out-dir still exits 0" grep -qx 0 "$work/rc.last"
t "AC5" "the probe's temporary folder and the stand-in key folder are gone after a run" \
  bash -c "[ -z \"\$(ls -A '$work/tmp')\" ] && [ -z \"\$(ls -A '$work/rt')\" ]"
t "AC5" "the workspace listing is unchanged" bash -c "ls -R '$co' | cmp -s - '$work/co-before'"
setrc 0; echo 1 > "$work/rc/read-token"
runprobe "$work/probe.sh" > "$work/transcript" 2>&1
t "AC5" "with the token wall open, the transcript and the temporary folders hold no token or sealed item value" \
  bash -c "! grep -rq -e '$SENT_TOKEN' -e 'SOURCE_DATE_EPOCH=0' -e 'LC_ALL=C' '$work/transcript' '$work/tmp' '$work/rt'"
setrc 1
runprobe "$work/probe.sh" > "$work/transcript2" 2>&1
t "AC5" "the folders are also gone after a run with open walls" \
  bash -c "[ -z \"\$(ls -A '$work/tmp')\" ] && [ -z \"\$(ls -A '$work/rt')\" ]"
setrc 0
exits "AC5" "RUNNER_TEMP unset is a refusal (exit 2) that leaves no temporary folder" \
  2 bash -c "cd '$co' && env -u RUNNER_TEMP TMPDIR='$work/tmp' bash '$work/probe.sh'"
t "AC5" "...and the temporary folder is empty" bash -c "[ -z \"\$(ls -A '$work/tmp')\" ]"

echo "build-sandbox-hostile-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
