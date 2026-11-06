#!/usr/bin/env bash
# proves: REQ-ARCHIVE-001-AC1, REQ-ARCHIVE-001-AC2, REQ-ARCHIVE-001-AC3, REQ-ARCHIVE-001-AC4, REQ-ARCHIVE-001-AC5, REQ-ARCHIVE-001-AC6, REQ-ARCHIVE-001-AC7, REQ-ARCHIVE-001-AC8, REQ-ARCHIVE-001-AC9
# Tests of the archive tooling: bin/archive-push.sh, bin/archive-pull.sh, bin/archive-verify.py (REQ-ARCHIVE-001; rules 26, 27, 29, 30, 38a, 38b, 44).
# Offline: crane is a stub that serves a directory registry and records its argv; nothing here touches a network. The production scripts
# name every tool by its literal fixed path at the call; the suite runs a COPY in which each occurrence of one of the four fixed paths is replaced, one
# for one, by a dispatcher, and checks that the copy differs from the production file in nothing else. The scripts run from the repository root.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root" || exit 1   # the scripts name their helper as bin/archive-verify.py: they run from the repository root, as in production
work=$(mktemp -d) && [ -d "$work" ] || { echo "archive-test: cannot create a scratch directory" >&2; exit 1; }; trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "${work:?}"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL [$1] $2"; true; }
t() { local ac=$1 d=$2; shift 2; if "$@" >"$work/out" 2>&1; then ok; else bad "$ac" "$d"; fi; }
PUSH="$root/bin/archive-push.sh" PULL="$root/bin/archive-pull.sh" VER="$root/bin/archive-verify.py"
REPO=ghcr.io/fosterstack/cache-archive
export STUB_CALLS="$work/calls" STUB_REG="$work/reg"; : >"$STUB_CALLS"

# ---- the crane stub and the dispatchers --------------------------------------------------------------------------------------------
mkdir -p "$work/tools"
cat >"$work/tools/crane" <<'STUB'
#!/bin/bash
echo "crane $*" >>"$STUB_CALLS"
case "$1" in
  push)
    d=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1] + "/index.json"))["manifests"][0]["digest"])' "$2") || exit 1
    hex=${d#sha256:}; mkdir -p "$STUB_REG"; rm -rf "${STUB_REG:?}/${hex:?}"; cp -R "$2" "$STUB_REG/$hex"
    if [ -n "${STUB_PUSH_PRINT:-}" ]; then echo "$STUB_PUSH_PRINT"; else echo "${3%@*}@$d"; fi;;
  pull)
    [ "$2" = --format ] && [ "$3" = oci ] || exit 64
    hex=${4#*@sha256:}
    [ -d "$STUB_REG/$hex" ] || { echo "MANIFEST_UNKNOWN" >&2; exit 1; }
    if [ -n "${STUB_PULL_DIE:-}" ]; then mkdir -p "$5"; echo half >"$5/index.json"; exit 1; fi
    cp -R "$STUB_REG/$hex" "$5";;
  *) exit 64;;
esac
STUB
cat >"$work/tools/crane-fail" <<'STUB'
#!/bin/bash
echo "denied" >&2; exit 1
STUB
chmod +x "$work/tools/crane" "$work/tools/crane-fail"
for t_ in python3 mktemp rm; do printf '#!/bin/bash\nexec %s "$@"\n' "$t_" >"$work/tools/$t_"; chmod +x "$work/tools/$t_"; done
mkcopy() {   # mkcopy DIR [FILE OLD NEW]: a copy of the three production files with each occurrence of a fixed tool path replaced by its dispatcher; optionally one mutation
  local d=$1; mkdir -p "$d"
  python3 - "$root/bin" "$d" "$work/tools" "${2:-}" "${3:-}" "${4:-}" <<'P'
import os, re, sys
src, dst, tools, mfile, old, new = sys.argv[1:7]
paths = {"/usr/bin/python3": "python3", "/usr/local/bin/crane": "crane", "/usr/bin/mktemp": "mktemp", "/bin/rm": "rm"}
for f in ("archive-push.sh", "archive-pull.sh", "archive-verify.py"):
    s = open(src + "/" + f).read()
    for path, n in paths.items():
        s = re.sub(r"(?<![\w./-])%s(?![\w.-])" % re.escape(path), lambda m, n=n: tools + "/" + n, s)
    if f == mfile:
        assert s.count(old) == 1, (f, old, s.count(old))
        s = s.replace(old, new)
    open(dst + "/" + f, "w").write(s); os.chmod(dst + "/" + f, 0o755)
P
}

# ---- fixtures --------------------------------------------------------------------------------------------------------------------
mkfx() {   # mkfx DIR: a small archive in the refresh job's layout (keys, per-arch apks, index/)
  rm -rf "${1:?}"; mkdir -p "$1/keys" "$1/x86_64/index" "$1/aarch64/index"
  printf 'index-arm\n' >"$1/aarch64/index/APKINDEX-2222222222222222222222222222222222222222222222222222222222222222.tar.gz"
  printf 'PUBLIC KEY\n' >"$1/keys/wolfi-signing.rsa.pub"
  printf 'apk-a-x86\n' >"$1/x86_64/tzdata-2026b-r0.apk"; printf 'apk-b-x86\n' >"$1/x86_64/busybox-1.37.0-r5.apk"
  printf 'apk-a-arm\n' >"$1/aarch64/tzdata-2026b-r0.apk"
  printf 'index-x86\n' >"$1/x86_64/index/APKINDEX-1111111111111111111111111111111111111111111111111111111111111111.tar.gz"
  : >"$1/aarch64/empty-1.0-r0.apk"   # an empty file is still a file
}
cat >"$work/lib.py" <<'PY'
import hashlib, json, os, sys
def listing(d):
    out = []
    for r, ds, fs in os.walk(d):
        for f in fs:
            p = os.path.join(r, f); out.append({"name": os.path.relpath(p, d), "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()})
    return sorted(out, key=lambda e: e["name"])
cmd = sys.argv[1]
if cmd == "pointer":      # lib.py pointer DIR DIGEST: print a pointer for DIR naming artifact DIGEST
    print(json.dumps({"schema": 1, "artifact": "ghcr.io/fosterstack/cache-archive@" + sys.argv[3], "files": listing(sys.argv[2])}, indent=1))
elif cmd == "tree":       # lib.py tree DIR: a hash of names and bytes
    print(hashlib.sha256(json.dumps(listing(sys.argv[2])).encode()).hexdigest())
elif cmd == "edit":       # lib.py edit FILE KEY=JSON...: set (or DELETE) top-level keys of a JSON file
    d = json.load(open(sys.argv[2]))
    for kv in sys.argv[3:]:
        k, v = kv.split("=", 1)
        if v == "DELETE": d.pop(k, None)
        else: d[k] = json.loads(v)
    json.dump(d, open(sys.argv[2], "w"), indent=1)
elif cmd == "blob":       # lib.py blob LAYOUT NAME: the path of the layer blob whose annotated title is NAME
    l = sys.argv[2]; idx = json.load(open(l + "/index.json")); mh = idx["manifests"][0]["digest"].split(":")[1]
    m = json.load(open(l + "/blobs/sha256/" + mh))
    print([l + "/blobs/sha256/" + x["digest"].split(":")[1] for x in m["layers"] if x["annotations"]["org.opencontainers.image.title"] == sys.argv[3]][0])
PY
LIB="python3 $work/lib.py"
fx="$work/fx"; mkfx "$fx"
rc() { cat "$work/rc"; }
run() { "$@" >"$work/o" 2>"$work/e"; echo $? >"$work/rc"; cat "$work/o" "$work/e" >"$work/log"; }
reset() { rm -rf "${STUB_REG:?}" "$work/o" "$work/e"; : >"$STUB_CALLS"; }
leftover() { ls "$1".partial.* >/dev/null 2>&1; }
CP="$work/cp"; mkcopy "$CP"
P_PUSH="$CP/archive-push.sh" P_PULL="$CP/archive-pull.sh" P_VER="$CP/archive-verify.py"
# a real pushed artifact and its pointer
reset; run "$P_PUSH" --dir "$fx"; DIGEST=$(cat "$work/o"); PUSH_RC=$(rc); cp "$STUB_CALLS" "$work/push-calls"
$LIB pointer "$fx" "$DIGEST" >"$work/ptr.json"
LAYOUT="$STUB_REG/${DIGEST#sha256:}"; cp -R "$LAYOUT" "$work/layout-keep"

# ===== AC1: push packs one layer per file, with annotations, pushes by digest and prints the digest ====================================
t AC1 "push exits 0 and prints exactly one line, the artifact digest sha256:<64 hex>" bash -c "test '$PUSH_RC' = 0 && grep -Eq '^sha256:[0-9a-f]{64}\$' '$work/o' && test \"\$(wc -l <'$work/o')\" -eq 1"
t AC1 "push calls crane push once, with the layout and the repository by digest (no tag), and no other crane command" bash -c "test \"\$(grep -c '^crane ' '$work/push-calls')\" -eq 1 && grep -Eq '^crane push [^ ]+/layout $REPO@$DIGEST\$' '$work/push-calls'"
t AC1 "the artifact has one layer per regular file, named by relative path, each annotated with name, version and sha256 (the layer's own digest)" python3 - "$work/layout-keep" "$fx" <<'P'
import hashlib, json, os, sys
l, fx = sys.argv[1:3]
m = json.load(open(l + "/blobs/sha256/" + json.load(open(l + "/index.json"))["manifests"][0]["digest"].split(":")[1]))
want = {}
for r, ds, fs in os.walk(fx):
    for f in fs: want[os.path.relpath(os.path.join(r, f), fx)] = hashlib.sha256(open(os.path.join(r, f), "rb").read()).hexdigest()
got = {}
for L in m["layers"]:
    a = L["annotations"]; n = a["org.opencontainers.image.title"]
    assert "org.fosterstack.cache-archive.version" in a, a
    assert a["org.fosterstack.cache-archive.sha256"] == L["digest"].split(":")[1], a
    got[n] = a["org.fosterstack.cache-archive.sha256"]
assert got == want, (got, want)
assert len(m["layers"]) == len(want)
v = {x["annotations"]["org.opencontainers.image.title"]: x["annotations"]["org.fosterstack.cache-archive.version"] for x in m["layers"]}
assert v["x86_64/tzdata-2026b-r0.apk"] == "2026b-r0" and v["x86_64/busybox-1.37.0-r5.apk"] == "1.37.0-r5", v
P
t AC1 "the printed digest is the manifest's: the blob it names is the manifest and hashes to it" python3 - "$work/layout-keep" "$DIGEST" <<'P'
import hashlib, sys
l, d = sys.argv[1:3]
assert hashlib.sha256(open(l + "/blobs/sha256/" + d.split(":")[1], "rb").read()).hexdigest() == d.split(":")[1]
P
reset; run "$P_PUSH" --dir "$fx"
t AC1 "push is deterministic: the same directory gives the same digest" bash -c "test \"\$(cat '$work/o')\" = '$DIGEST'"
cp -R "$fx" "$work/fx2"; touch -t 200001010000 "$work/fx2/keys/wolfi-signing.rsa.pub"; reset; run "$P_PUSH" --dir "$work/fx2"
t AC1 "push does not depend on file times" bash -c "test \"\$(cat '$work/o')\" = '$DIGEST'"

# ===== AC2: push refuses what it cannot represent, and checks the digest crane reports =============================================
mkfx "$work/fs"; ln -s ../keys/wolfi-signing.rsa.pub "$work/fs/x86_64/APKINDEX.tar.gz"
reset; run "$P_PUSH" --dir "$work/fs"
t AC2 "a symlink in the directory is refused (exit 2, names it), crane is not called" bash -c "test '$(rc)' = 2 && grep -q APKINDEX.tar.gz '$work/log' && ! test -s '$STUB_CALLS'"
mkdir -p "$work/empty"; reset; run "$P_PUSH" --dir "$work/empty"
t AC2 "an empty directory is refused (exit 2), crane is not called" bash -c "test '$(rc)' = 2 && ! test -s '$STUB_CALLS'"
reset; run "$P_PUSH" --dir "$work/nonexistent"
t AC2 "a missing directory is refused (exit 2)" bash -c "test '$(rc)' = 2"
mkfx "$work/fn"; printf x >"$work/fn/x86_64/bad name.apk"
reset; run "$P_PUSH" --dir "$work/fn"
t AC2 "a file name with a space is refused (exit 2), crane is not called" bash -c "test '$(rc)' = 2 && ! test -s '$STUB_CALLS'"
mkfx "$work/fn2"; printf x >"$work/fn2/x86_64/.hidden"
reset; run "$P_PUSH" --dir "$work/fn2"
t AC2 "a file name starting with a dot is refused (exit 2)" bash -c "test '$(rc)' = 2"
reset; run "$P_PUSH"
t AC2 "no --dir is refused (exit 2)" bash -c "test '$(rc)' = 2"
ZERO=sha256:$(printf '0%.0s' $(seq 64))
det_push_digest() { reset; run env STUB_PUSH_PRINT="$REPO@$ZERO" "$1/archive-push.sh" --dir "$fx"; [ "$(rc)" = 1 ] && ! test -s "$work/o" && grep -q "$ZERO" "$work/e"; }
t AC2 "crane reporting another digest than the one computed: exit 1, nothing on stdout, the message names the reported digest" det_push_digest "$CP"
mkcopy "$work/cpf"; python3 - "$work/cpf/archive-push.sh" "$work/tools/crane-fail" <<'P'
import re, sys
s = open(sys.argv[1]).read(); s = re.sub(r"[^\s\"'(=]+/tools/crane(?![\w-])", sys.argv[2], s); open(sys.argv[1], "w").write(s)
P
reset; run "$work/cpf/archive-push.sh" --dir "$fx"
t AC2 "a crane push that fails: exit 1, nothing on stdout" bash -c "test '$(rc)' = 1 && ! test -s '$work/o'"

# ===== AC3: the pointer ============================================================================================================
badptr() {   # badptr DESC KEY=JSON...: an edited pointer is refused by verify (exit 2) and by pull (exit 2, crane not called, nothing written)
  local d=$1; shift; cp "$work/ptr.json" "$work/p.json"; $LIB edit "$work/p.json" "$@"
  reset; run python3 -I -B "$P_VER" verify --pointer "$work/p.json" --dir "$fx"; local a; a=$(rc)
  reset; rm -rf "${work:?}/o-bad"; run "$P_PULL" --pointer "$work/p.json" --out "$work/o-bad"; local b; b=$(rc)
  if [ "$a" = 2 ] && [ "$b" = 2 ] && ! test -s "$STUB_CALLS" && ! test -e "$work/o-bad"; then ok; else bad AC3 "pointer refused (verify exit $a, pull exit $b): $d"; fi
}
A64=$(printf 'a%.0s' $(seq 64))
t AC3 "the pointer for the fixture verifies against the directory (exit 0)" python3 -I -B "$P_VER" verify --pointer "$work/ptr.json" --dir "$fx"
t AC3 "the pointer has exactly the keys schema, artifact and files; schema is 1; each file has exactly name and sha256" python3 - "$work/ptr.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1])); assert sorted(d) == ["artifact", "files", "schema"] and d["schema"] == 1
assert all(sorted(f) == ["name", "sha256"] for f in d["files"])
P
badptr "schema 2" 'schema=2'
badptr "schema as a string" 'schema="1"'
badptr "an extra key" 'extra=1'
badptr "no files key" 'files=DELETE'
badptr "artifact by tag" 'artifact="ghcr.io/fosterstack/cache-archive:latest"'
badptr "artifact in another repository" "artifact=\"ghcr.io/other/cache-archive@$DIGEST\""
badptr "artifact in another registry" "artifact=\"docker.io/fosterstack/cache-archive@$DIGEST\""
badptr "artifact with an upper-case digest" "artifact=\"$REPO@sha256:$(printf 'A%.0s' $(seq 64))\""
badptr "artifact with a short digest" "artifact=\"$REPO@sha256:abcd\""
badptr "artifact with a tag and a digest" "artifact=\"$REPO:v1@$DIGEST\""
badptr "files not a list" 'files={"a":"b"}'
badptr "files empty" 'files=[]'
badptr "a file sha256 that is not 64 lower-case hex" 'files=[{"name":"keys/wolfi-signing.rsa.pub","sha256":"xyz"}]'
badptr "a traversal name" 'files=[{"name":"../x","sha256":"'$A64'"}]'
badptr "an absolute name" 'files=[{"name":"/etc/passwd","sha256":"'$A64'"}]'
badptr "a duplicate name" 'files=[{"name":"a","sha256":"'$A64'"},{"name":"a","sha256":"'$A64'"}]'
badptr "names out of order" 'files=[{"name":"b","sha256":"'$A64'"},{"name":"a","sha256":"'$A64'"}]'
printf '{not json' >"$work/p.json"; reset; run python3 -I -B "$P_VER" verify --pointer "$work/p.json" --dir "$fx"
D_MP="sha256:$(printf 'c%.0s' $(seq 1 64))"
t AC3 "make-pointer writes a pointer for a directory and a digest that pointer-check and verify (with --pushed-digest) accept" bash -c "python3 -I -B '$P_VER' make-pointer --dir '$fx' --digest $D_MP --out '$work/mp.json' && python3 -I -B '$P_VER' pointer-check --pointer '$work/mp.json' && python3 -I -B '$P_VER' verify --pointer '$work/mp.json' --dir '$fx' --pushed-digest $D_MP && python3 -I -B '$P_VER' artifact --pointer '$work/mp.json' | grep -q '@$D_MP\$'"
t AC3 "make-pointer is deterministic: the same directory and digest give the same bytes" bash -c "python3 -I -B '$P_VER' make-pointer --dir '$fx' --digest $D_MP --out '$work/mp2.json' && cmp '$work/mp.json' '$work/mp2.json'"
t AC3 "make-pointer refuses a digest that is not sha256:<64 hex> (exit 2) and writes nothing" bash -c "rm -f '$work/mp3.json'; ! python3 -I -B '$P_VER' make-pointer --dir '$fx' --digest sha256:XYZ --out '$work/mp3.json' 2>/dev/null; test ! -e '$work/mp3.json'"
rm -rf "$work/mpd"; cp -R "$fx" "$work/mpd"; ln -s keys "$work/mpd/linkdir"
t AC3 "make-pointer refuses a directory holding a symlink (exit 1, names it) and writes nothing" bash -c "rm -f '$work/mp4.json'; python3 -I -B '$P_VER' make-pointer --dir '$work/mpd' --digest $D_MP --out '$work/mp4.json' >'$work/mp4.log' 2>&1; test \$? = 1 && grep -q linkdir '$work/mp4.log' && test ! -e '$work/mp4.json'"
t AC3 "a pointer that is not JSON is refused (exit 2)" bash -c "test '$(rc)' = 2"
reset; run python3 -I -B "$P_VER" verify --pointer "$work/none.json" --dir "$fx"
t AC3 "a missing pointer file is refused (exit 2)" bash -c "test '$(rc)' = 2"
t AC3 "the committed build/archive.json, when present, is a valid pointer" bash -c "test ! -e '$root/build/archive.json' || python3 -I -B '$P_VER' pointer-check --pointer '$root/build/archive.json'"

# ===== AC4: pull by digest, only the committed one ==================================================================================
reset; run "$P_PUSH" --dir "$fx"; : >"$STUB_CALLS"; rm -rf "${work:?}/out1"
run "$P_PULL" --pointer "$work/ptr.json" --out "$work/out1"
t AC4 "pull of the committed digest exits 0 and the output directory holds exactly the pointer's files" bash -c "test '$(rc)' = 0 && test \"\$($LIB tree '$work/out1')\" = \"\$($LIB tree '$fx')\""
t AC4 "pull calls crane once: crane pull --format oci <repo>@<committed digest> (by digest, never a tag), and no other crane command" bash -c "test \"\$(grep -c '^crane ' '$STUB_CALLS')\" -eq 1 && grep -Eq '^crane pull --format oci $REPO@$DIGEST [^ ]+/layout\$' '$STUB_CALLS'"
rm -rf "${work:?}/out1"; reset; run "$P_PUSH" --dir "$fx"; : >"$STUB_CALLS"
run "$P_PULL" --pointer "$work/ptr.json" --out "$work/out1" --digest "$DIGEST"
t AC4 "--digest equal to the committed one is accepted" bash -c "test '$(rc)' = 0"
WRONG=sha256:$(printf 'b%.0s' $(seq 64))
det_wrong_digest() {   # 0 when the scripts in $1 refuse a digest other than the committed one before any crane call
  local b=$1; reset; run "$b/archive-push.sh" --dir "$fx"; : >"$STUB_CALLS"; rm -rf "${work:?}/o-wd"
  run "$b/archive-pull.sh" --pointer "$work/ptr.json" --out "$work/o-wd" --digest "$WRONG"
  [ "$(rc)" = 2 ] && ! grep -q '^crane pull' "$STUB_CALLS" && [ ! -e "$work/o-wd" ]
}
t AC4 "a --digest other than the committed one is refused (exit 2) before crane runs, nothing is written" det_wrong_digest "$CP"
rm -rf "${work:?}/o-t"; reset; run "$P_PULL" --pointer "$work/ptr.json" --out "$work/o-t"
t AC4 "an artifact that is not in the registry: exit 1, nothing at the output path, no partial directory beside it" bash -c "test '$(rc)' = 1 && ! test -e '$work/o-t' && ! ls '$work'/o-t.partial.* >/dev/null 2>&1"
reset; run "$P_PULL" --pointer "$work/ptr.json" --out "$work/o-tag" --digest "latest"
t AC4 "--digest that is not sha256:<64 hex> (a tag) is refused (exit 2)" bash -c "test '$(rc)' = 2"
rm -rf "${work:?}/o-empty"; reset; run "$P_PULL" --pointer "$work/ptr.json" --out "$work/o-empty" --digest ""
t AC4 "an explicit empty --digest is refused (exit 2) before crane runs, nothing is written (a supplied value is never treated as omitted)" bash -c "test '$(rc)' = 2 && ! test -e '$work/o-empty' && ! test -s '$STUB_CALLS'"

# ===== AC5: verify: no missing, extra or altered file ===============================================================================
vrun() { run python3 -I -B "$1/archive-verify.py" verify --pointer "$work/ptr.json" --dir "$2"; }
det_altered() { rm -rf "${work:?}/d"; cp -R "$fx" "$work/d"; printf 'X' >>"$work/d/x86_64/tzdata-2026b-r0.apk"; vrun "$1" "$work/d"; [ "$(rc)" = 1 ] && grep -q 'x86_64/tzdata-2026b-r0.apk' "$work/log"; }
det_missing() { rm -rf "${work:?}/d"; cp -R "$fx" "$work/d"; rm "$work/d/keys/wolfi-signing.rsa.pub"; vrun "$1" "$work/d"; [ "$(rc)" = 1 ] && grep -q 'keys/wolfi-signing.rsa.pub' "$work/log"; }
det_extra() { rm -rf "${work:?}/d"; cp -R "$fx" "$work/d"; printf 'x' >"$work/d/x86_64/evil-1.0-r0.apk"; vrun "$1" "$work/d"; [ "$(rc)" = 1 ] && grep -q 'x86_64/evil-1.0-r0.apk' "$work/log"; }
vrun "$CP" "$fx"
t AC5 "an intact directory verifies (exit 0)" bash -c "test '$(rc)' = 0"
t AC5 "an altered file is refused (exit 1) naming it" det_altered "$CP"
t AC5 "a missing file is refused (exit 1) naming it" det_missing "$CP"
t AC5 "an extra file is refused (exit 1) naming it" det_extra "$CP"
rm -rf "${work:?}/d"; cp -R "$fx" "$work/d"; ln -s keys "$work/d/linkdir"; vrun "$CP" "$work/d"
t AC5 "a symlink in the directory is an extra entry: refused (exit 1) naming it" bash -c "test '$(rc)' = 1 && grep -q linkdir '$work/log'"
rm -rf "${work:?}/d"; cp -R "$fx" "$work/d"; mkdir -p "$work/d/x86_64/stray"; vrun "$CP" "$work/d"
t AC5 "an extra empty directory is refused (exit 1) naming it" bash -c "test '$(rc)' = 1 && grep -q stray '$work/log'"
rm -rf "${work:?}/d"; cp -R "$fx" "$work/d"; rm "$work/d/x86_64/tzdata-2026b-r0.apk"; ln -s ../keys/wolfi-signing.rsa.pub "$work/d/x86_64/tzdata-2026b-r0.apk"; vrun "$CP" "$work/d"
t AC5 "a symlink in place of a listed file is refused (exit 1)" bash -c "test '$(rc)' = 1"
vrun "$CP" "$work/nonexistent"
t AC5 "a missing directory is refused (never exit 0)" bash -c "test '$(rc)' != 0"

# ===== AC6: pull stages, verifies, and leaves nothing half-done ======================================================================
det_half() {   # 0 when verify refuses a directory holding only some of the files and pull will not write into or over it
  rm -rf "${work:?}/h"; mkdir -p "$work/h/keys"; cp "$fx/keys/wolfi-signing.rsa.pub" "$work/h/keys/"
  vrun "$1" "$work/h"; [ "$(rc)" = 1 ] || return 1
  grep -q 'x86_64/tzdata-2026b-r0.apk' "$work/log" || return 1
  reset; run "$1/archive-push.sh" --dir "$fx"; : >"$STUB_CALLS"; local before; before=$($LIB tree "$work/h")
  run "$1/archive-pull.sh" --pointer "$work/ptr.json" --out "$work/h"
  [ "$(rc)" != 0 ] && [ "$($LIB tree "$work/h")" = "$before" ] && ! grep -q '^crane pull' "$STUB_CALLS"
}
t AC6 "a half-pulled directory is refused by verify, and pull will not write into or over it (non-zero, the directory untouched, crane not called)" det_half "$CP"
pullbad() {   # pullbad DESC: the registry content was edited by the caller; pull must fail (exit 1) with nothing left
  rm -rf "${work:?}/o-x"; : >"$STUB_CALLS"; run "$P_PULL" --pointer "$work/ptr.json" --out "$work/o-x"
  if [ "$(rc)" = 1 ] && [ ! -e "$work/o-x" ] && ! leftover "$work/o-x"; then ok; else bad AC6 "pull refused with nothing left: $1 (rc $(rc))"; fi
}
fresh() { reset; run "$P_PUSH" --dir "$fx"; LAYOUT="$STUB_REG/${DIGEST#sha256:}"; }
fresh; printf 'tampered' >"$($LIB blob "$LAYOUT" x86_64/tzdata-2026b-r0.apk)"; pullbad "a layer's bytes changed under its digest name"
fresh; rm "$($LIB blob "$LAYOUT" keys/wolfi-signing.rsa.pub)"; pullbad "a layer blob missing from the layout"
fresh; python3 - "$LAYOUT/index.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1])); d["manifests"][0]["digest"] = "sha256:" + "c" * 64; json.dump(d, open(sys.argv[1], "w"))
P
pullbad "index.json names another manifest than the committed digest"
fresh; python3 - "$LAYOUT/index.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1])); d["manifests"].append(d["manifests"][0]); json.dump(d, open(sys.argv[1], "w"))
P
pullbad "index.json with two manifests"
fresh; printf ' ' >>"$LAYOUT/blobs/sha256/${DIGEST#sha256:}"; pullbad "the manifest bytes do not hash to the committed digest"
# artifacts that are honest about themselves but differ from the pointer
mkfx "$work/fe"; printf 'extra' >"$work/fe/x86_64/extra-1.0-r0.apk"
reset; run "$P_PUSH" --dir "$work/fe"; DIG_E=$(cat "$work/o")
$LIB pointer "$fx" "$DIG_E" >"$work/p-extra.json"; : >"$STUB_CALLS"; rm -rf "${work:?}/o-e"
run "$P_PULL" --pointer "$work/p-extra.json" --out "$work/o-e"
t AC6 "an artifact with a file the pointer does not list is refused (exit 1) naming it, nothing left" bash -c "test '$(rc)' = 1 && grep -q extra-1.0-r0.apk '$work/log' && ! test -e '$work/o-e' && ! ls '$work'/o-e.partial.* >/dev/null 2>&1"
mkfx "$work/fm"; rm "$work/fm/x86_64/busybox-1.37.0-r5.apk"
reset; run "$P_PUSH" --dir "$work/fm"; DIG_M=$(cat "$work/o")
$LIB pointer "$fx" "$DIG_M" >"$work/p-miss.json"; : >"$STUB_CALLS"; rm -rf "${work:?}/o-m"
run "$P_PULL" --pointer "$work/p-miss.json" --out "$work/o-m"
t AC6 "an artifact lacking a file the pointer lists is refused (exit 1) naming it, nothing left" bash -c "test '$(rc)' = 1 && grep -q busybox-1.37.0-r5.apk '$work/log' && ! test -e '$work/o-m' && ! ls '$work'/o-m.partial.* >/dev/null 2>&1"
mkfx "$work/fa"; printf 'other bytes' >"$work/fa/x86_64/tzdata-2026b-r0.apk"
reset; run "$P_PUSH" --dir "$work/fa"; DIG_A=$(cat "$work/o")
$LIB pointer "$fx" "$DIG_A" >"$work/p-alt.json"; : >"$STUB_CALLS"; rm -rf "${work:?}/o-a"
run "$P_PULL" --pointer "$work/p-alt.json" --out "$work/o-a"
t AC6 "an artifact whose file differs from the pointer's sha256 is refused (exit 1) naming it, nothing left" bash -c "test '$(rc)' = 1 && grep -q tzdata-2026b-r0.apk '$work/log' && ! test -e '$work/o-a' && ! ls '$work'/o-a.partial.* >/dev/null 2>&1"
fresh; : >"$STUB_CALLS"; rm -rf "${work:?}/o-d"; run env STUB_PULL_DIE=1 "$P_PULL" --pointer "$work/ptr.json" --out "$work/o-d"
t AC6 "crane dying half-way: exit 1, nothing at the output path, no partial directory left beside it" bash -c "test '$(rc)' = 1 && ! test -e '$work/o-d' && ! ls '$work'/o-d.partial.* >/dev/null 2>&1"
fresh; mkdir -p "$work/o-exist"; run "$P_PULL" --pointer "$work/ptr.json" --out "$work/o-exist"
t AC6 "an existing output path (even an empty directory) is refused (exit 2)" bash -c "test '$(rc)' = 2"
rm -rf "${work:?}/o-ok"; fresh; run "$P_PULL" --pointer "$work/ptr.json" --out "$work/o-ok"
t AC6 "after a good pull the directory verifies against the pointer and no partial directory is left beside it" bash -c "test '$(rc)' = 0 && python3 -I -B '$P_VER' verify --pointer '$work/ptr.json' --dir '$work/o-ok' && ! ls '$work'/o-ok.partial.* >/dev/null 2>&1"
t AC6 "the pulled files are plain files (no symlink, no executable bit)" bash -c "! find '$work/o-ok' -type l | grep -q . && ! find '$work/o-ok' -type f -perm -u+x | grep -q ."

# ===== AC7: the committed pointer must name the pushed digest =======================================================================
det_pushed() {   # 0 when verify --pushed-digest refuses a pointer that names another digest, and accepts the matching one
  run python3 -I -B "$1/archive-verify.py" verify --pointer "$work/ptr.json" --dir "$fx" --pushed-digest "$DIGEST"; [ "$(rc)" = 0 ] || return 1
  run python3 -I -B "$1/archive-verify.py" verify --pointer "$work/ptr.json" --dir "$fx" --pushed-digest "$WRONG"; [ "$(rc)" = 1 ] && grep -q "$WRONG" "$work/log"
}
t AC7 "verify --pushed-digest: a pointer naming the pushed digest passes; a pointer naming another digest is refused (exit 1) naming it" det_pushed "$CP"
run python3 -I -B "$P_VER" verify --pointer "$work/ptr.json" --dir "$fx" --pushed-digest "latest"
t AC7 "--pushed-digest that is not sha256:<64 hex> is refused (exit 2)" bash -c "test '$(rc)' = 2"
reset; run "$P_PUSH" --dir "$fx"; PUSHED=$(cat "$work/o")
t AC7 "the digest push printed is the one the pointer names (the flow the refresh job runs)" python3 -I -B "$P_VER" verify --pointer "$work/ptr.json" --dir "$fx" --pushed-digest "$PUSHED"

# ===== AC8: the push is the only writer; the pull runs outside the sealed call; nothing secret ======================================
t AC8 "archive-pull.sh and archive-verify.py never name a crane write (push, copy, cp, tag, delete, append, mutate)" bash -c "! grep -En '(crane|CRANE\"?) +\"?(push|copy|cp|tag|delete|append|mutate)' '$PULL' '$VER'"
t AC8 "archive-push.sh calls crane only as push" bash -c "grep -q '/usr/local/bin/crane push ' '$PUSH' && test \"\$(grep -v '^ *#' '$PUSH' | grep -c '/usr/local/bin/crane')\" -eq \"\$(grep -v '^ *#' '$PUSH' | grep -c '/usr/local/bin/crane push ')\""
t AC8 "none of the three names sudo, unshare, melange, apko, docker or a network client (the pull runs before and outside the sealed call)" bash -c "! grep -Ewn 'sudo|unshare|melange|apko|docker|ssh|nc' '$PUSH' '$PULL' '$VER' | grep -Ev '^[^:]*:[0-9]+:[[:space:]]*#'"
t AC8 "none of the three names a token, password, secret, login or credential variable (the push uses the workflow's own credential, which crane finds itself)" bash -c "! grep -Eiwn 'token|password|secret|login|GITHUB_TOKEN|GH_TOKEN|DOCKER_CONFIG|insecure' '$PUSH' '$PULL' '$VER' | grep -Ev '^[^:]*:[0-9]+:[[:space:]]*#'"
cat >"$work/vars.py" <<'PY'
import re, sys
# closed list of caller variables: every $NAME the shell scripts read must be assigned in the script itself
bad = []
for p in sys.argv[1:]:
    s = open(p).read(); code = "\n".join(l for l in s.split("\n") if not l.lstrip().startswith("#"))
    assigned = set(re.findall(r"(?:^|[\s;(])(?:local\s+|declare\s+)?([A-Za-z_][A-Za-z0-9_]*)=", code)) | set(re.findall(r"\bfor\s+([A-Za-z_]\w*)\s+in\b", code)) | set(re.findall(r"\bread\s+(?:-\w+\s+)*([A-Za-z_]\w*)", code))
    for m in re.finditer(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", code):
        if m.group(1) not in assigned and m.group(1) != "BASH_SOURCE": bad.append("%s: $%s" % (p, m.group(1)))
sys.exit("variables of the caller read: %r" % sorted(set(bad)) if bad else 0)
PY
t AC8 "the shell scripts read no variable they do not set themselves (BASH_SOURCE aside)" python3 "$work/vars.py" "$PUSH" "$PULL"
t AC8 "archive-verify.py reads no environment variable" bash -c "! grep -En 'environ|getenv' '$VER'"
mkdir -p "$work/evil"; printf 'raise SystemExit("hostile hashlib")\n' >"$work/evil/hashlib.py"
reset; run env CRANE=/bin/false PY3=/bin/false MKTEMP=/bin/false RM=/bin/false REPO=evil/x PYTHONPATH="$work/evil" PYTHONSTARTUP="$work/evil/hashlib.py" PYTHONOPTIMIZE=1 "$P_PUSH" --dir "$fx"
t AC8 "a hostile caller environment (CRANE, PY3, REPO, PYTHONPATH, PYTHONSTARTUP) does not change the digest push prints" bash -c "test '$(rc)' = 0 && test \"\$(cat '$work/o')\" = '$DIGEST'"

# ===== AC9: tool paths, isolated interpreters, no test hook, the copy differs only on TEST-SUBST lines (NEW, PROPOSED) ======================
cat >"$work/toolscan.py" <<'PY'
import re, sys
# toolscan.py FILE WORD...: fail closed. A shell lexer with quote removal (cr'an'e is the word crane) and a stack for command
# substitution: $( ... ) and backticks are code at any nesting depth, also inside double quotes. Any word equal to a tool word, in code, is refused:
# the production scripts name every tool by variable, so a bare word is never legal. Quoted text is one word (a message is never a tool word).
def words(s):
    out, cur, st, i = [], "", ["code"], 0
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
        else:
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
TOOLS="crane python3 python mktemp rm mv cp cat dirname readlink sha256sum shasum openssl git gh tar gzip find sed awk env"
t AC9 "no bare tool word in archive-push.sh (every tool is named by a variable holding a fixed path)" python3 "$work/toolscan.py" "$PUSH" $TOOLS
t AC9 "no bare tool word in archive-pull.sh" python3 "$work/toolscan.py" "$PULL" $TOOLS
t AC9 "each shell script names its tools by their literal fixed absolute path at the call (python3, mktemp, rm and crane) and no variable holds a program" python3 - "$PUSH" "$PULL" <<'P'
import re, sys
for p in sys.argv[1:]:
    s = open(p).read()
    for want in ("/usr/bin/python3", "/usr/bin/mktemp", "/bin/rm", "/usr/local/bin/crane"): assert want in s, (p, want)
    assert not re.search(r"(?m)^(PY3|CRANE|MKTEMP|RM)=", s), p
    assert not re.search(r"\"\$\{?(PY3|CRANE|MKTEMP|RM)\}?\"", s), p
P
t AC9 "every python3 call is python3 -I -B" python3 - "$PUSH" "$PULL" <<'P'
import re, sys
n = 0
for p in sys.argv[1:]:
    for ln in open(p).read().split("\n"):
        if ln.lstrip().startswith("#"): continue
        for m in re.finditer(r"/usr/bin/python3(.{0,12})", ln):
            n += 1; assert re.match(r"\s+-I\s+-B\b", m.group(1)), (p, ln)
assert n >= 3, n
P
t AC9 "archive-verify.py runs no subprocess and opens no socket (hashlib, json, os, re, signal, sys only)" bash -c "! grep -Eq '^ *(import|from) +(subprocess|socket|urllib|http|ssl|shutil|tempfile|ctypes|requests)' '$VER' && grep -Eq '^import' '$VER'"
t AC9 "no test hook: neither script mentions a test mode or a TEST_ or ARCHIVE_ variable" bash -c "! grep -v TEST-SUBST '$PUSH' '$PULL' '$VER' | grep -En 'TEST_MODE|FSCACHE_TEST|ARCHIVE_[A-Z]+|TEST_[A-Z]+'"
t AC9 "the copy the suite runs differs from each production file ONLY in occurrences of the four fixed paths, each replaced one for one by the dispatcher of that tool (any other byte difference fails)" python3 - "$root/bin" "$CP" "$work/tools" <<'P'
import re, sys
paths = {"python3": "/usr/bin/python3", "crane": "/usr/local/bin/crane", "mktemp": "/usr/bin/mktemp", "rm": "/bin/rm"}
pa = re.compile(r"(?<![\w./-])(%s)(?![\w.-])" % "|".join(re.escape(p) for p in paths.values()))
pb = re.compile(r"(?<![\w./-])%s/(%s)(?![\w.-])" % (re.escape(sys.argv[3]), "|".join(paths)))
for f in ("archive-push.sh", "archive-pull.sh", "archive-verify.py"):
    a = open(sys.argv[1] + "/" + f).read(); b = open(sys.argv[2] + "/" + f).read()
    fa = pa.findall(a); fb = pb.findall(b)
    assert [paths[n] for n in fb] == fa, (f, fa, fb)
    assert pb.sub(lambda m: paths[m.group(1)], b) == a, f
P
t AC9 "each shell script names its helper by the literal path bin/archive-verify.py (run from the repository root): no variable, no substitution, no directory lookup" python3 - "$PUSH" "$PULL" <<'P'
import re, sys
for p in sys.argv[1:]:
    s = open(p).read()
    assert "VERIFY" not in s and "$(cd" not in s and "BASH_SOURCE" not in s, p
    rows = [r for r in s.split("\n") if "archive-verify.py" in r and not r.lstrip().startswith("#")]
    assert rows and all("bin/archive-verify.py" in r and "/usr/bin/python3 -I -B bin/archive-verify.py" in r for r in rows), (p, rows)
P
t AC9 "the shell scripts set -euo pipefail" bash -c "grep -q '^set -euo pipefail' '$PUSH' && grep -q '^set -euo pipefail' '$PULL'"

# ---- the refresh layout's APKINDEX.tar.gz is a regular-file COPY of its index/APKINDEX-<sha256>.tar.gz (advisor 0425): the same bytes under two names ----
mkfx "$work/fc"
for a in x86_64 aarch64; do cp "$work/fc/$a/index/"APKINDEX-*.tar.gz "$work/fc/$a/APKINDEX.tar.gz"; done
reset; run "$P_PUSH" --dir "$work/fc"; cdig=$(cat "$work/o"); cpush=$(rc)
$LIB pointer "$work/fc" "$cdig" >"$work/cptr.json"; rm -rf "${work:?}/o-c"; : >"$STUB_CALLS"; run "$P_PULL" --pointer "$work/cptr.json" --out "$work/o-c"; cpull=$(rc)
run python3 -I -B "$CP/archive-verify.py" verify --pointer "$work/cptr.json" --dir "$work/o-c"; cver=$(rc)
t AC1 "a directory holding the pointer copy and its index file (the same sha256 under two names) pushes, pulls and verifies (exit 0 each), byte for byte" bash -c "test '$cpush' = 0 && test '$cpull' = 0 && test '$cver' = 0 && test \"\$($LIB tree '$work/o-c')\" = \"\$($LIB tree '$work/fc')\" && cmp '$work/o-c/x86_64/APKINDEX.tar.gz' '$work/o-c/x86_64/index/APKINDEX-1111111111111111111111111111111111111111111111111111111111111111.tar.gz' && test -z \"\$(find '$work/o-c' -type l)\" && test \"\$(grep -c '\"sha256\": \"$(shasum -a 256 "$work/fc/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1)\"' '$work/cptr.json')\" = 2"
fresh
# ---- mutants: every check the ACs name is removed in turn, and the suite's detectors must notice ------------------------------------
mut() {   # mut NAME FILE OLD NEW DETECTOR: the mutated copy differs from the original, and the detector (which passes on the real copy) fails on it
  local n=$1 f=$2 old=$3 new=$4 det=$5 d="$work/mut-$1"
  if ! mkcopy "$d" "$f" "$old" "$new" 2>"$work/mkerr"; then bad AC9 "mutant $n could not be built: $(tail -1 "$work/mkerr")"; return; fi
  if cmp -s "$d/$f" "$CP/$f"; then bad AC9 "mutant $n equals the original"; return; fi
  if "$det" "$d" >/dev/null 2>&1; then bad AC9 "mutant $n (check removed) is NOT noticed by $det"; else ok; fi
}
mut push-digest-unchecked archive-push.sh '[ "$out" = "$ref" ] || die' 'true || die' det_push_digest
mut wrong-digest-accepted archive-pull.sh '[ "$want" != "$have" ]' 'false' det_wrong_digest
mut altered-unchecked archive-verify.py 'altered = sorted(n for n in want if n in have and have[n] != want[n])' 'altered = []' det_altered
mut missing-unchecked archive-verify.py 'missing = sorted(set(want) - set(have))' 'missing = []' det_missing
mut extra-unchecked archive-verify.py 'extra = sorted(set(have) - set(want))' 'extra = []' det_extra
mut half-pull-overwrites archive-pull.sh '[ ! -e "$out" ] && [ ! -L "$out" ]' 'true' det_half
mut half-pull-missing archive-verify.py 'missing = sorted(set(want) - set(have))' 'missing = []' det_half
mut pushed-digest-unchecked archive-verify.py 'if pushed is not None and pushed != digest:' 'if False:' det_pushed
for spec in "m-crane|archive-push.sh|$work/tools/crane push \"\$tmp/layout\"|crane push \"\$tmp/layout\"" \
            "m-crane-q|archive-pull.sh|$work/tools/crane pull --format oci|cr'an'e pull --format oci" \
            "m-mktemp|archive-pull.sh|$work/tools/mktemp -d|mktemp -d" \
            "m-rm|archive-push.sh|$work/tools/rm -rf \"\$tmp\"|rm -rf \"\$tmp\"" \
            "m-nest|archive-pull.sh|$work/tools/crane pull --format oci|\"\$(true \$(printf x); crane pull)\" --format oci"; do
  IFS='|' read -r n f old new <<<"$spec"
  if ! mkcopy "$work/mt-$n" "$f" "$old" "$new" 2>"$work/mkerr"; then bad AC9 "tool mutant $n: $(tail -1 "$work/mkerr")"; continue; fi
  if cmp -s "$work/mt-$n/$f" "$CP/$f"; then bad AC9 "tool mutant $n equals the original"; continue; fi
  if python3 "$work/toolscan.py" "$work/mt-$n/$f" $TOOLS >/dev/null 2>&1; then bad AC9 "the tool-path scan misses the mutant $n"; else ok; fi
done
mkcopy "$work/mt-py" archive-pull.sh "$work/tools/python3 -I -B bin/archive-verify.py unpack" "$work/tools/python3 bin/archive-verify.py unpack"
t AC9 "the -I -B assertion bites: a python3 call without them is found" bash -c "grep -v '^ *#' '$work/mt-py/archive-pull.sh' | grep -Eq 'tools/python3 +[^-]'"

# ---- round 1 of the second review: strict syntax (fullmatch) and extraction cleanup -----------------------------------------------
t AC3 "names, digests and artifact references with a trailing newline are refused (the validators use fullmatch, never a $ that accepts a position before a final newline)" python3 - "$VER" <<'P'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("av", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert m.safe_name("x86_64/pkg-1.0-r0.apk"), "fixture"
assert not m.safe_name("x86_64/pkg-1.0-r0.apk\n"), "a name with a trailing newline was accepted"
assert not m.HEX.fullmatch("a" * 64 + "\n") and m.HEX.fullmatch("a" * 64)
assert not m.ARTIFACT.fullmatch("ghcr.io/fosterstack/cache-archive@sha256:" + "a" * 64 + "\n")
P
t AC6 "an extraction that fails after the first file leaves no <out>.stage and no <out> behind" python3 - "$VER" "$work/ptr.json" "$work/layout-keep" "$work/o-stagefail" <<'P'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("av", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ptr, layout, out = sys.argv[2:5]
n = [0]; real = os.chmod
def flaky(p, mode, *a, **k):
    n[0] += 1
    if n[0] == 2: raise OSError("disk full (injected)")
    return real(p, mode, *a, **k)
os.chmod = flaky
try:
    m.cmd_unpack({"--pointer": ptr, "--layout": layout, "--out": out})
except BaseException:
    pass
else:
    raise SystemExit("the injected failure did not stop the extraction")
assert n[0] >= 2, "the injection point was never reached"
assert not os.path.lexists(out + ".stage"), "the stage directory was left behind"
assert not os.path.lexists(out), "a partial output was left behind"
P
for SIG in SIGTERM SIGINT; do
t AC6 "$SIG during the extraction (after the first file) leaves no <out>.stage and no <out> behind, and the process exits through SystemExit" python3 - "$VER" "$work/ptr.json" "$work/layout-keep" "$work/o-sig-$SIG" "$SIG" <<'P'
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("av", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ptr, layout, out, name = sys.argv[2:6]
n = [0]; real = os.chmod
def interrupted(p, mode, *a, **k):
    n[0] += 1
    if n[0] == 2: os.kill(os.getpid(), getattr(signal, name))   # a real signal, delivered to this process in the middle of the extraction
    return real(p, mode, *a, **k)
os.chmod = interrupted
try:
    m.cmd_unpack({"--pointer": ptr, "--layout": layout, "--out": out})
except SystemExit as e:
    assert e.code not in (0, None), "the interrupted extraction exited as a success"
else:
    raise SystemExit("the signal did not stop the extraction")
assert n[0] >= 2, "the injection point was never reached"
assert not os.path.lexists(out + ".stage"), "the stage directory was left behind"
assert not os.path.lexists(out), "a partial output was left behind"
P
done
t AC6 "a SECOND signal during the cleanup does not stop it: no <out>.stage and no <out> are left" python3 - "$VER" "$work/ptr.json" "$work/layout-keep" "$work/o-sig-twice" <<'P'
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("av", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ptr, layout, out = sys.argv[2:5]
n = [0]; real_chmod, real_unlink = os.chmod, os.unlink
def second(p, *a, **k):
    os.kill(os.getpid(), signal.SIGTERM)   # the second signal, in the middle of the cleanup
    return real_unlink(p, *a, **k)
def first(p, mode, *a, **k):
    n[0] += 1
    if n[0] == 2:
        os.unlink = second
        os.kill(os.getpid(), signal.SIGINT)   # the first signal, during the extraction
    return real_chmod(p, mode, *a, **k)
os.chmod = first
try:
    m.cmd_unpack({"--pointer": ptr, "--layout": layout, "--out": out})
except SystemExit:
    pass
else:
    raise SystemExit("the signal did not stop the extraction")
os.unlink = real_unlink
assert n[0] >= 2, "the injection point was never reached"
assert not os.path.lexists(out + ".stage"), "a second signal left the stage directory behind"
assert not os.path.lexists(out), "a partial output was left behind"
P
echo "archive-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
