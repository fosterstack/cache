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

# A layout builder: one index, two children (amd64, arm64), each with its own config and the one shared layer. Every
# digest is the hash of its bytes, so a refusal below is the check under test and not a stale-digest accident.
cat > "$work/mk.py" <<'PY'
import hashlib, json, os, sys
root, variant = sys.argv[1], sys.argv[2]
os.makedirs(root + "/blobs/sha256")
def blob(data):
    h = hashlib.sha256(data).hexdigest()
    open(root + "/blobs/sha256/" + h, "wb").write(data)
    return "sha256:" + h
layer = blob(b"layer bytes")
kids = []
for arch in ("amd64", "arm64"):
    config = blob(json.dumps({"architecture": arch, "os": "linux"}).encode())
    layers = [{"digest": layer}]
    if variant == "traversal-layer" and arch == "amd64":
        layers = [{"digest": "sha256:../../../etc/passwd"}]
    if variant == "empty-layer-digest" and arch == "amd64":
        layers.append({"digest": ""})
    if variant == "layers-not-a-list" and arch == "amd64":
        layers = "x"
    if variant == "layers-an-object" and arch == "amd64":
        layers = {"a": {"digest": layer}}
    if variant == "two-digests-in-one" and arch == "amd64":
        layers = [{"digest": layer + "\n" + layer}]
    if variant == "repeated-layer" and arch == "amd64":
        layers = [{"digest": layer}, {"digest": layer}]
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": config}, "layers": layers}).encode()
    kids.append({"digest": blob(manifest), "platform": {"os": "linux", "architecture": arch}})
    open(root + "-" + arch, "w").write("child %s config %s" % (kids[-1]["digest"], config))
if variant == "two-children":
    kids.append(dict(kids[0]))
index = blob(json.dumps({"schemaVersion": 2, "manifests": kids}).encode())
roots = [{"digest": index}]
if variant == "two-roots":
    roots.append(dict(roots[0]))
if variant == "bad-index-digest":
    roots = [{"digest": "sha256:../../../etc/passwd"}]
json.dump({"schemaVersion": 2, "manifests": roots}, open(root + "/index.json", "w"))
open(root + "/manifest.json", "w").write("a stray file at the layout root")
if variant == "repeated-layer":   # a second name for the same inode must not become a tar link to itself
    os.link(root + "/blobs/sha256/" + layer[7:], root + "/layer-alias")
    os.chmod(root + "/blobs/sha256/" + layer[7:], 0o444)   # a read-only source must not break the second copy
if variant == "wrong-bytes":
    open(root + "/blobs/sha256/" + layer[7:], "wb").write(b"not the layer")
if variant == "symlink-layer":   # the target hashes to the digest, so only a regular-file check can refuse it
    p = root + "/blobs/sha256/" + layer[7:]
    os.rename(p, root + "/layer-target")
    os.symlink("../../layer-target", p)
PY
python3 "$work/mk.py" "$work/layout" ok

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

refused() {  # <label> <layout dir> <arch> [text the message must hold]: exit 1, a message naming the problem, no tar
  rm -f "$work/x.tar"
  if msg=$(bash "$tool" "$2" "$3" "$work/x.tar" "$tag" 2>&1); then bad "$1: accepted"
  elif [ -e "$work/x.tar" ]; then bad "$1: a tar was left"
  elif ! printf '%s' "$msg" | grep -q "layout-archive.*${4:-}"; then bad "$1: no message naming it: $msg"
  else ok "$1 is refused"; fi
}
refused "an architecture the index does not hold" "$work/layout" s390x
for v in two-children traversal-layer two-roots wrong-bytes bad-index-digest empty-layer-digest layers-not-a-list \
  symlink-layer layers-an-object two-digests-in-one repeated-layer; do
  python3 "$work/mk.py" "$work/$v" "$v"
done
refused "two children for one architecture" "$work/two-children" amd64 "single linux"
refused "a layer digest that is not sha256:<64 hex>" "$work/traversal-layer" amd64 "must be sha256"
refused "an index.json with two roots" "$work/two-roots" amd64 "exactly one"
refused "a blob whose bytes are not its digest" "$work/wrong-bytes" amd64 "does not match"
refused "an index digest that is not sha256:<64 hex>" "$work/bad-index-digest" amd64 "not a sha256"
refused "a layer with an empty digest" "$work/empty-layer-digest" amd64 "must be sha256"
refused "layers that are not a list" "$work/layers-not-a-list" amd64 "layers"
refused "a blob that is a symlink" "$work/symlink-layer" amd64 "regular file"
refused "layers that are an object" "$work/layers-an-object" amd64 "layers"
refused "one layer digest holding two" "$work/two-digests-in-one" amd64 "must be sha256"
bash "$tool" "$work/repeated-layer" amd64 "$work/rep.tar" "$tag" > /dev/null
[ "$(tar -tf "$work/rep.tar" | wc -l | tr -d ' ')" = 3 ] && ok "a layer listed twice is one member of the tar" \
  || bad "repeated layer members: $(tar -tf "$work/rep.tar" | tr '\n' ' ')"
tar -xOf "$work/rep.tar" manifest.json | jq -e '.[0].Layers | length == 2' > /dev/null \
  && ok "and stays listed twice in the manifest" || bad "repeated layer manifest"
rm -rf "$work/rep"; mkdir "$work/rep"; tar -xf "$work/rep.tar" -C "$work/rep" && ok "the tar extracts" || bad "extract"
refused "a layout with no index" "$work/missing" amd64

echo "layout-archive: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
