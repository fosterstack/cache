#!/usr/bin/env bash
# proves: REQ-IMAGE-001-AC14
# Tests for 0710 item 1: the images carry our own base-layout package and no CA bundle
# (ops/docs/ratify/2026-10-28-no-ca-bundle-in-images.md, rule 1). Offline: no apko and no melange run here. The recipe's own
# install steps are run into a temporary folder, so the package's file list is real; the real apk and image listing are
# proved by the build on the runner (not run by this script).
set -uo pipefail
cd "$(dirname "$0")/.."
pass=0; fail=0
ok() { echo "ok:   $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }
chk() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

REC=build/melange-baselayout.yaml
chk "the recipe exists and is named fscache-baselayout with no dependencies and no provides" python3 -I - <<'PY'
import yaml
r = yaml.safe_load(open("build/melange-baselayout.yaml"))
assert r["package"]["name"] == "fscache-baselayout" and r["package"]["version"] == "@VERSION@"
assert "dependencies" not in r["package"] and "provides" not in str(r["package"]), r["package"]
assert "subpackages" not in r and "update" not in r
PY
chk "its build environment is exactly the pinned list of build/locks/melange.lock" python3 -I - <<'PY'
import yaml
r = yaml.safe_load(open("build/melange-baselayout.yaml"))
lock = [l for l in open("build/locks/melange.lock").read().split("\n") if l]
assert r["environment"]["contents"]["packages"] == lock
PY
chk "no recipe step fetches, builds Go or names a network address" python3 -I - <<'PY'
import yaml
r = yaml.safe_load(open("build/melange-baselayout.yaml"))
for st in r["pipeline"]:
    assert set(st) == {"runs"}, st
    for w in ("http:", "https:", "wget", "curl", "git ", "go build", "apk add"):
        assert w not in st["runs"], w
PY
chk "build/baselayout holds exactly the files the recipe copies, and no others" python3 -I - <<'PY'
import os, re
rec = open("build/melange-baselayout.yaml").read()
named = set(re.findall(r"build/baselayout/(etc/[a-z.-]+)", rec))
have = {os.path.join("etc", n) for n in os.listdir("build/baselayout/etc")}
assert named == have, (named ^ have)
assert sorted(os.listdir("build/baselayout")) == ["etc", "members.txt"]   # members.txt: the entry list the build checks the apk against
PY
chk "os-release is Wolfi's own file byte for byte (scanners identify the OS from it)" \
  bash -c '[ "$(sha256sum build/baselayout/etc/os-release | cut -d" " -f1)" = 8209665b39efdb89514d7cadc50b7ffc3e64dff2cd05736cb04ea078a1a9a24a ]'
chk "passwd and group hold only root and nobody, with no shell path" python3 -I - <<'PY'
pw = open("build/baselayout/etc/passwd").read().splitlines()
assert [l.split(":")[0] for l in pw] == ["root", "nobody"], pw
assert all(l.endswith(":/sbin/nologin") for l in pw), pw
gr = open("build/baselayout/etc/group").read().splitlines()
assert [l.split(":")[0] for l in gr] == ["root", "nogroup", "nobody"], gr
PY
chk "no file of the package names a shell: no /bin/sh, /bin/ash or /etc/shells" bash -c '! grep -rEq "/bin/(a?sh|bash)|/etc/shells" build/baselayout build/melange-baselayout.yaml'

# the recipe's steps run into a folder: the real file list of the package
dest="$tmp/dest"; mkdir -p "$dest"
python3 -I - "$dest" >"$tmp/steps.sh" <<'PY'
import sys, yaml
r = yaml.safe_load(open("build/melange-baselayout.yaml"))
for st in r["pipeline"]:
    print(st["runs"].replace("${{targets.destdir}}", sys.argv[1]))
PY
if bash -e "$tmp/steps.sh" >"$tmp/steps.out" 2>&1; then ok "the recipe's install steps run"; else bad "the recipe's install steps run: $(cat "$tmp/steps.out")"; fi
chk "the package tree holds no symlink and no hard link, and has the layout modes and files" python3 -I - "$dest" <<'PY'
import os, stat, sys
d = sys.argv[1]
def mode(p): return stat.S_IMODE(os.lstat(os.path.join(d, p)).st_mode)
assert not [r for r, ds, fs in os.walk(d) for n in ds + fs if os.path.islink(os.path.join(r, n))], "a symlink"
assert not [f for r, _, fs in os.walk(d) for f in fs if os.lstat(os.path.join(r, f)).st_nlink > 1], "a hard link"
assert mode("tmp") == 0o1777 and mode("var/tmp") == 0o1777 and mode("root") == 0o700
for p in ("dev", "proc", "sys", "run", "home", "etc", "usr/bin", "usr/lib"):
    assert os.path.isdir(os.path.join(d, p)) and not os.path.islink(os.path.join(d, p)), p
for f in ("group", "hosts", "nsswitch.conf", "os-release", "passwd", "protocols", "services"):
    assert mode("etc/" + f) == 0o644, f
files = sorted(os.path.relpath(os.path.join(r, f), d) for r, _, fs in os.walk(d) for f in fs)
assert files == ["etc/" + f for f in ("group", "hosts", "nsswitch.conf", "os-release", "passwd", "protocols", "services")], files
PY
chk "no file under /etc/ssl/certs and nothing named ca-certificates in the package" bash -c '! find "$0" -path "*etc/ssl*" -o -iname "*ca-cert*" | grep -q .' "$dest"

for v in apko apko-fips; do
  chk "build/$v.yaml names our base layout, tzdata and the program, and no CA bundle" python3 -I - "$v" <<'PY'
import sys, yaml
v = sys.argv[1]
c = yaml.safe_load(open("build/%s.yaml" % v))
pk = c["contents"]["packages"]
prog = "fscache-fips" if v == "apko-fips" else "fscache"
assert pk == ["fscache-baselayout=@FSCACHE_VERSION@-r0", "tzdata", prog + "=@FSCACHE_VERSION@-r0"], pk
assert "ca-cert" not in open("build/%s.yaml" % v).read().split("contents:")[1]
PY
  chk "build/locks/$v.base.lock.json holds tzdata only: no Wolfi baselayout, no CA bundle" python3 -I - "$v" <<'PY'
import json, sys
d = json.load(open("build/locks/%s.base.lock.json" % sys.argv[1]))
names = [(p["name"], p["architecture"]) for p in d["contents"]["packages"]]
assert names == [("tzdata", "x86_64"), ("tzdata", "aarch64")], names
assert "ca-cert" not in json.dumps(d)
PY
done
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
