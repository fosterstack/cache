#!/usr/bin/env bash
# proves: REQ-REL-004-AC1 — the gate scans each image child of the layout from its own blobs, no Docker daemon
# bin/layout-archive.sh turns the linux/ARCH image of an OCI layout into a docker-save tar a scanner can read.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
tool="$here/bin/layout-archive.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }

# A layout with one index, two children (amd64, arm64), each with its own config and the one shared layer.
python3 - "$work/layout" <<'PY'
import hashlib, json, os, sys
root = sys.argv[1]
os.makedirs(root + "/blobs/sha256")
def blob(data):
    h = hashlib.sha256(data).hexdigest()
    open(root + "/blobs/sha256/" + h, "wb").write(data)
    return "sha256:" + h
layer = blob(b"layer bytes")
kids = []
for arch in ("amd64", "arm64"):
    config = blob(json.dumps({"architecture": arch, "os": "linux"}).encode())
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": config},
                           "layers": [{"digest": layer}]}).encode()
    kids.append({"digest": blob(manifest), "platform": {"os": "linux", "architecture": arch}})
    open(root + "-" + arch, "w").write("child %s config %s" % (kids[-1]["digest"], config))
index = blob(json.dumps({"schemaVersion": 2, "manifests": kids}).encode())
json.dump({"schemaVersion": 2, "manifests": [{"digest": index}]}, open(root + "/index.json", "w"))
open(root + "/manifest.json", "w").write("a stray file at the layout root")
PY

tag=ghcr.io/fosterstack/cache:cand-production-amd64
out=$(bash "$tool" "$work/layout" amd64 "$work/amd64.tar" "$tag")
members=$(tar -tf "$work/amd64.tar" | tr '\n' ' ')
first="$(tar -tf "$work/amd64.tar" | head -1)"
[ "$first" = manifest.json ] && ok "manifest.json comes first" || bad "manifest.json first"
[ "$(tar -tf "$work/amd64.tar" | wc -l | tr -d ' ')" = 3 ] && ok "three members: manifest, config, one layer" \
  || bad "members: $members"
tar -xOf "$work/amd64.tar" manifest.json > "$work/m.json"
[ "$(jq -r '.[0].RepoTags[0]' "$work/m.json")" = "$tag" ] && ok "the image name is the tag given" || bad "RepoTags"
config=$(jq -r '.[0].Config' "$work/m.json")
want=$(cat "$work/layout-amd64")
[ "$out" = "$want" ] && ok "the child and config digests are printed" || bad "output: $out, wanted $want"
[ "sha256:${config#blobs/sha256/}" = "${want##* }" ] && ok "the config is the amd64 child's own" || bad "config $config"
n="$(tar -tf "$work/amd64.tar" | grep -c '^manifest.json$')"
[ "$n" = 1 ] \
  && ok "the layout's stray root manifest.json is not in the tar" || bad "stray manifest.json"
bash "$tool" "$work/layout" arm64 "$work/arm64.tar" "${tag%amd64}arm64" > /dev/null
cmp -s "$work/amd64.tar" "$work/arm64.tar" && bad "arm64 tar equals amd64" || ok "each architecture gets its own tar"

refused() {  # <label> <layout dir> <arch>: exit 1, a message naming the problem, no tar
  rm -f "$work/x.tar"
  if msg=$(bash "$tool" "$2" "$3" "$work/x.tar" "$tag" 2>&1); then bad "$1: accepted"
  elif [ -e "$work/x.tar" ]; then bad "$1: a tar was left"
  elif ! printf '%s' "$msg" | grep -q 'layout-archive'; then bad "$1: no message: $msg"
  else ok "$1 is refused"; fi
}
refused "an architecture the index does not hold" "$work/layout" s390x
cp -R "$work/layout" "$work/twice"
python3 - "$work/twice" <<'PY'
import json, sys
root = sys.argv[1]
idx = json.load(open(root + "/index.json"))["manifests"][0]["digest"].split(":")[1]
p = root + "/blobs/sha256/" + idx
d = json.load(open(p))
d["manifests"].append(dict(d["manifests"][0]))
json.dump(d, open(p, "w"))
PY
refused "two children for one architecture" "$work/twice" amd64
cp -R "$work/layout" "$work/traversal"
python3 - "$work/traversal" <<'PY'
import json, sys
root = sys.argv[1]
idx = json.load(open(root + "/index.json"))["manifests"][0]["digest"].split(":")[1]
p = root + "/blobs/sha256/" + idx
d = json.load(open(p))
kid = d["manifests"][0]["digest"].split(":")[1]
m = json.load(open(root + "/blobs/sha256/" + kid))
m["layers"][0]["digest"] = "sha256:../../../etc/passwd"
json.dump(m, open(root + "/blobs/sha256/" + kid, "w"))
PY
refused "a layer digest that is not sha256:<64 hex>" "$work/traversal" amd64
refused "a layout with no index" "$work/missing" amd64

echo "layout-archive: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
