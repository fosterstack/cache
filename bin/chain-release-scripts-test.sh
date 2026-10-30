#!/usr/bin/env bash
# proves: REQ-CHAIN-006-AC7, REQ-CHAIN-007-AC4, REQ-CHAIN-007-AC5, REQ-CHAIN-007-AC6, REQ-CHAIN-007-AC7, REQ-CHAIN-007-AC8, REQ-CHAIN-007-AC9, REQ-CHAIN-007-AC10, REQ-CHAIN-007-AC14, REQ-CHAIN-007-AC17, REQ-CHAIN-007-AC19, REQ-CHAIN-007-AC20, REQ-CHAIN-007-AC21, REQ-CHAIN-005-AC4
# RED until PR 4 is implemented (bin/release-verify.sh, release-apks.sh, release-publish.sh, release-sign.sh, release-assets.sh, release-postverify.sh/.py do not exist): step 4.
#
# Release, behaviour half (v0.3.0 rules 5, 17, 29, 53b, 56, 57, 64, 69, 71; advisor rulings of Oct 9: rc tags like finals, the release policy
# signed with cosign so it is in Rekor, signatures in both registries). Every script is run in a throw-away tree with FAKE tools first on PATH
# (crane over a directory "registry", cosign, gh, melange, and fakes of bin/chain-verify.py, bin/apk-tool.py and bin/vendor-provenance.py); no
# network, no real credential, no real key. Credentials are SENTINEL strings: they must reach only the tool that needs them and never appear in
# any output, any file the script writes or any command line (stdin is allowed). Runs on ubuntu-24.04 or macOS with bash, python3, jq.
# RELEASE_BIN can point at another directory of scripts (used to prove the cases satisfiable against a throw-away reference; default bin/).
#
# FIXED paths the scripts read and write (PROPOSED, they are what the stage's downloads and uploads would carry; the scripts take no arguments
# because the stage runs them as `bash bin/witnessed.sh STEP bin/STEP.sh`):
#   in : Build's REAL interface (REQ-CHAIN-007-AC17, the fixed table; Build is the reviewed source of truth): witness-build/digests.json with the keys
#        image-production, image-fips, apk-standard-amd64, apk-standard-arm64, apk-fips-amd64, apk-fips-arm64 (bin/chain_items.py digests_of),
#        witness-build/build-collection.json, witness-rebuild/..., witness-check/..., provenance/provenance.json, images/<variant>/ (an OCI layout directory) + images/<variant>.digest,
#        images/<variant>.full.lock.json and images/<variant>-sbom/sbom.json, apks/<runner>/<apk arch>/fscache[-fips]-0.3.0-r0.apk (the artifacts
#        apk-ubuntu-24.04 -> x86_64 and apk-ubuntu-24.04-arm -> aarch64), rapks/<runner>/... (Rebuild's, same layout), dist/*, policy.json
#   out: release-apks/<apk arch>/*.apk, release-evidence/ (bundles, vendor-evidence.json, release-policy.bundle)
# Registries: ghcr.io/fosterstack/cache and docker.io/fosterstack/cache; tags 0.3.0 and 0.3.0-fips (a final release also floating tags: PROPOSED).
# The fake tools' command lines are PROPOSED/UNVERIFIED: crane push of an OCI tarball, melange sign --key FILE, cosign sign-blob --bundle.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export RELEASE_BIN="${RELEASE_BIN:-$root/bin}"
python3 - "$@" <<'PY'
import hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile
BIN = os.environ["RELEASE_BIN"]
SENT = {"APK_RELEASE_SIGNING_KEY": "SENTINEL-APK-KEY-7f3a", "DOCKERHUB_USERNAME": "sentinel-user-91", "DOCKERHUB_TOKEN": "SENTINEL-HUB-TOKEN-5c2e", "GH_TOKEN": "SENTINEL-GH-TOKEN-b814"}
passn, failn = 0, 0
def ok(l): global passn; passn += 1; print("ok   " + l)
def bad(l): global failn; failn += 1; print("FAIL " + l)
LAST = [0]   # the exit code of the last script run: a missing script (127) fails every check that follows, so nothing passes vacuously
def check(c, l, why=""):
    if LAST[0] == 127: bad(l + " -> the script does not exist")
    else: ok(l) if c else bad(l + (" -> " + why if why else ""))
FAKES = {
 "crane": r'''#!/usr/bin/env bash
echo "crane $*" >> "$LOG"
case "$1" in
  auth) cat > /dev/null; mkdir -p "$REG/.login"; : > "$REG/.login/$3"
        d="${DOCKER_CONFIG:-$HOME/.docker}"; mkdir -p "$d"; echo "login $3" >> "$d/config.json"; echo "$d" >> "$LOG.dockercfg" ;;
  push) host=${3%%/*}; [ -e "$REG/.login/$host" ] || { echo "UNAUTHORIZED $host" >&2; exit 1; }
        # PROPOSED/UNVERIFIED layout (cache-3f / #299): images/<variant>/ is an OCI image layout DIRECTORY. MEASURED with crane 0.22.1: pushing a
        # docker-format tarball re-creates the manifest (the digest changes), pushing an OCI layout directory keeps the digest. A tarball is refused here.
        [ -d "$2" ] && [ -f "$2/oci-layout" ] && [ -f "$2/index.json" ] || { echo "crane: $2 is not an OCI image layout directory" >&2; exit 1; }
        d=$(cat "${2}.digest"); p="$REG/${3/://}"; mkdir -p "$(dirname "$p")"
        [ "${REG_CORRUPT:-}" = "$host" ] && d="sha256:$(printf 'f%.0s' $(seq 64))"; echo "$d" > "$p" ;;
  digest) p="$REG/${2/://}"; [ -e "$p" ] && cat "$p" || { echo "NAME_UNKNOWN $2" >&2; exit 1; } ;;
  ls) [ -z "${LS_FAIL:-}" ] || { echo "connection refused" >&2; exit 1; }
      [ -d "$REG/$2" ] || { echo "NAME_UNKNOWN $2" >&2; exit 1; }
      # LS_RACE_AFTER=N: after answering the Nth listing, a concurrent publication of the higher release 0.3.1 completes in both registries
      # (its exact tags, :0 and :latest, all at another digest): the interleaving of release review R3 (Oct 22)
      n=$(( $(cat "$REG/.lsn" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$REG/.lsn"; out=$(ls "$REG/$2")
      if [ "${LS_RACE_AFTER:-}" = "$n" ]; then
        for h in ghcr.io docker.io; do d="$REG/$h/fosterstack/cache"; mkdir -p "$d"; for x in 0.3.1 0.3.1-fips 0 latest; do echo "sha256:$(printf '8%.0s' $(seq 64))" > "$d/$x"; done; done
      fi
      printf '%s\n' "$out" ;;
  *) echo "crane: unexpected $1" >&2; exit 2 ;;
esac''',
 "cosign": r'''#!/usr/bin/env bash
echo "cosign $*" >> "$LOG"
echo "$PWD" >> "$LOG.cwd"
if [ -n "${FAKE_NEEDFILES:-}" ]; then for a in "$@"; do case "$a" in *.json|*.bundle|*.txt) [ -f "$a" ] || { echo "open $a: no such file or directory" >&2; exit 1; };; esac; done; fi
[ -z "${COSIGN_FAIL:-}" ] || { echo "cosign failed" >&2; exit 1; }
[ -z "${COSIGN_FAIL_ON:-}" ] || case "$*" in *"$COSIGN_FAIL_ON"*) echo "cosign failed" >&2; exit 1;; esac
if [ "$1" = login ]; then cat > /dev/null; d="${DOCKER_CONFIG:-$HOME/.docker}"; mkdir -p "$d"; echo "login $*" >> "$d/config.json"; echo "$d" >> "$LOG.dockercfg"; fi
[ "$1" != attest ] || [ -z "${COSIGN_ATTEST_FAIL_ON:-}" ] || case "$*" in *"$COSIGN_ATTEST_FAIL_ON"*) echo "cosign attest failed" >&2; exit 1;; esac
if [ "$1" = sign-blob ]; then
  while [ $# -gt 0 ]; do [ "$1" = --bundle ] && b=$2; shift; done
  if [ -n "${COSIGN_NOREKOR:-}" ] && [ "$(basename "$b")" = "${COSIGN_NOREKOR}" ]; then echo '{"verificationMaterial":{"tlogEntries":[]}}' > "$b"
  else echo '{"verificationMaterial":{"tlogEntries":[{"logIndex":"1"}]}}' > "$b"; fi
fi''',
 "git": r'''#!/usr/bin/env bash
# release-assets reads the release tag's object (cat-file tag); release-sign asks for the admitted commit's committer date (log -1 --format=%ct)
if [ "$1 $2" = "cat-file tag" ]; then
  echo "git $*" >> "$LOG"
  # the tag object of the release tag: TAG_OBJECT names a file; no such file = the tag cannot be read
  if [ -n "${TAG_OBJECT:-}" ] && [ -f "$TAG_OBJECT" ]; then cat "$TAG_OBJECT"; else echo "fatal: not a valid tag" >&2; exit 128; fi
  exit 0
fi
echo "git $*" >> "$LOG.git"
[ "$1 $2 $3" = "log -1 --format=%ct" ] || { echo "git: unexpected $*" >&2; exit 2; }
[ -z "${GIT_FAIL:-}" ] || { echo "fatal: bad object $4" >&2; exit 128; }
printf '%s\n' "${GIT_EPOCH-1760000000}"''',
 "gh": r'''#!/usr/bin/env bash
echo "gh $*" >> "$LOG"
[ -z "${GH_FAIL:-}" ] || { echo "gh failed" >&2; exit 1; }
[ -z "${GH_FAIL_ON:-}" ] || case "$*" in *"$GH_FAIL_ON"*) echo "gh failed" >&2; exit 1;; esac
[ -z "${GH_VIEW_ERR:-}" ] || [ "$1 $2" != "release view" ] || { echo "$GH_VIEW_ERR" >&2; exit 1; }
if [ "$1 $2" = "release create" ] || [ "$1 $2" = "release edit" ]; then a=("$@"); for i in "${!a[@]}"; do
  [ "${a[$i]}" = --notes-file ] && cp "${a[$((i+1))]}" "$LOG.notes"; [ "${a[$i]}" = --notes ] && printf %s "${a[$((i+1))]}" > "$LOG.notes"; done; fi
pub="$LOG.published"
if [ "$1 $2" = "release upload" ]; then shift 3; mkdir -p "$pub"; for f in "$@"; do cp "$f" "$pub/"; done
elif [ "$1 $2" = "release download" ]; then d=; while [ $# -gt 0 ]; do [ "$1" = -D ] && d=$2; shift; done; mkdir -p "$d"; cp "$pub"/* "$d"/ 2>/dev/null || true
  [ -z "${GH_DROP:-}" ] || rm -f "$d/$GH_DROP"; [ -z "${GH_ALTER:-}" ] || printf x >> "$d/$GH_ALTER"; fi''',
 "bin/vex-forms.py": r'''import json, os, sys
a = sys.argv[1:]
open(os.environ["LOG"], "a").write("vex-forms %s\n" % " ".join(a))
if os.environ.get("VEXFORMS_FAIL"): print("vex-forms: image digests missing", file=sys.stderr); sys.exit(1)
ver = a[a.index("--version") + 1]; out = a[a.index("--out-dir") + 1]
json.load(open(a[a.index("--images") + 1]))
open(os.path.join(out, "fosterstack-cache-%s.csaf.json" % ver), "w").write("{}"); open(os.path.join(out, "fosterstack-cache-%s.inspector-filters.json" % ver), "w").write("{}")''',
 "melange": r'''#!/usr/bin/env bash
echo "melange $*" >> "$LOG"
[ -z "${MELANGE_FAIL:-}" ] || exit 1
[ "$1" = sign ] || exit 2
shift; [ "$1" = --signing-key ] && key=$2 && shift 2
echo "mode=$(stat -c %a "$key" 2>/dev/null || stat -f %Lp "$key") content=$(cat "$key")" >> "$LOG.key"; echo "$key" > "$LOG.keypath"
signer="$(basename "$key").pub"   # MEASURED with melange v0.61.2: the signer is named after the key FILE (k.rsa -> k.rsa.pub)
for a in "$@"; do [ -n "${MELANGE_BREAK:-}" ] || sed -i.bak "s/^signer: .*/signer: $signer/" "$a"; rm -f "$a.bak"; done''',
 "bin/apk-tool.py": r'''import hashlib, sys
cmd, f = sys.argv[1], sys.argv[2]
lines = open(f).read().split("\n")
if cmd == "digest": print("sha256:" + hashlib.sha256(lines[2].split(": ", 1)[1].encode()).hexdigest())
elif cmd == "signer": print(lines[1].split(": ", 1)[1])
elif cmd == "same": sys.exit(0 if open(f).read().split("\n")[2:] == open(sys.argv[3]).read().split("\n")[2:] else 1)
else: sys.exit(2)''',
 "bin/release-sign-apks.sh": r'''#!/usr/bin/env bash
# a model of cache's bin/release-sign-apks.sh (P4, measured; the owner's rule of Oct 21 2026 took --rebuild-dir away): --build-dir A --key K; the key is copied to a
# private file NAMED release.rsa (melange names the signer after the key file); each apk of A is re-signed in place with `melange sign --signing-key`
echo "release-sign-apks $*" >> "$LOG"
set -euo pipefail
while [ $# -gt 0 ]; do case $1 in --build-dir) a=$2;; --key) k=$2;; *) echo "release-sign-apks.sh: unknown argument: $1" >&2; exit 2;; esac; shift 2; done
[ "$(basename "$k")" = release.rsa ] || { echo "release-sign-apks.sh: the key file must be named release.rsa" >&2; exit 2; }   # measured: line 123 of cache's script
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT; umask 077; cp "$k" "$t/release.rsa"
for f in "$a"/*/*.apk; do melange sign --signing-key "$t/release.rsa" "$f"; done''',
 "bin/vendor-provenance.py": r'''import json, os, sys
open(os.environ["LOG"], "a").write("vendor-provenance %s\n" % " ".join(sys.argv[1:]))
if os.environ.get("EVIDENCE_FAIL"): sys.exit(1)
out = sys.argv[sys.argv.index("--out") + 1]; os.makedirs(out, exist_ok=True)
json.dump({"mode": "vendor"}, open(os.path.join(out, "vendor-evidence.json"), "w"))''',
 "bin/chain-verify.py": r'''import os, sys
a = sys.argv[1:]
open(os.environ["LOG"], "a").write("chain-verify %s\n" % " ".join(a))
if a[0] == "policy":
    if os.environ.get("POLICY_FAIL"): print("refused at release: policy", file=sys.stderr); sys.exit(1)
    open(a[a.index("--out") + 1], "w").write("{}"); sys.exit(0)
if a[0] == "bind-items":     # items.json (and, with --product, admission-baseline.json) must be a product of Build's record: modelled as the two files existing
    prev = "baseline" if "--product" in a else "items"
    if "--product" in a and a[a.index("--product") + 1] != "admission-baseline.json": print("refused at build: product: only admission-baseline.json", file=sys.stderr); sys.exit(1)
    if os.environ.get("FAIL_STAGE") == prev: print("refused at build: %s: %s is not the file Build's record holds" % (prev, prev), file=sys.stderr); sys.exit(1)
    for f in (a[a.index("--record") + 1], a[a.index("--items") + 1]):
        if not os.path.exists(f): print("refused at build: missing %s" % f, file=sys.stderr); sys.exit(1)
    sys.exit(0)
if a[0] == "bind-check":     # ruling G: check-results/govulncheck.json must be a product of Check's verified scanners record: modelled as the files existing
    if os.environ.get("FAIL_STAGE") == "govulncheck": print("refused at check: govulncheck.json: it is not the file Check's record holds", file=sys.stderr); sys.exit(1)
    for f in (a[a.index("--record") + 1], a[a.index("--file") + 1], a[a.index("--digests") + 1]):
        if not os.path.exists(f): print("refused at check: missing %s" % f, file=sys.stderr); sys.exit(1)
    if a[a.index("--product") + 1] != "check-results/govulncheck.json": print("refused at check: product: only check-results/govulncheck.json", file=sys.stderr); sys.exit(1)
    sys.exit(0)
if a[0] == "check-list":     # exactly four records, one per slot
    d = a[a.index("--dir") + 1]
    if os.environ.get("FAIL_STAGE") == "check": print("refused at check: a record is invalid", file=sys.stderr); sys.exit(1)
    for n in ("scanners", "acceptance", "runtime", "arm64"):
        if not os.path.exists(os.path.join(d, "witness-" + n, n + "-collection.json")): print("refused at check: missing the %s record" % n, file=sys.stderr); sys.exit(1)
    sys.exit(0)
if a[0] == "apk-compare":    # the comparison job's result file: modelled as the file and the digest list existing
    if os.environ.get("FAIL_STAGE") == "apkcompare": print("refused at rebuild: apk-compare: the result is not a pass", file=sys.stderr); sys.exit(1)
    for f in (a[a.index("--file") + 1], a[a.index("--digests") + 1]):
        if not os.path.exists(f): print("refused at rebuild: apk-compare: missing %s" % f, file=sys.stderr); sys.exit(1)
    sys.exit(0)
prev = a[a.index("--previous") + 1]; rec = a[a.index("--record") + 1]
if not os.path.exists(rec): print("refused at %s: missing record %s" % (prev, rec), file=sys.stderr); sys.exit(1)
if os.environ.get("FAIL_STAGE") == prev: print("refused at %s: the record is invalid" % prev, file=sys.stderr); sys.exit(1)''',
}
def make_layout(root, variant):
    """A real OCI image layout directory (round 1, Codex A B4): every blob is named by its sha256, the index blob holds the two linux child
    manifests, index.json holds the one descriptor. Returns the index digest."""
    blobs = os.path.join(root, "blobs", "sha256"); os.makedirs(blobs)
    def put(data):
        h = hashlib.sha256(data).hexdigest(); open(os.path.join(blobs, h), "wb").write(data); return {"digest": "sha256:" + h, "size": len(data)}
    kids = []
    for arch in ("amd64", "arm64"):
        cfg = put(("config %s %s" % (variant, arch)).encode()); lay = put(("layer %s %s" % (variant, arch)).encode())
        m = put(json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "config": dict(cfg, mediaType="application/vnd.oci.image.config.v1+json"),
                            "layers": [dict(lay, mediaType="application/vnd.oci.image.layer.v1.tar+gzip")]}, sort_keys=True).encode())
        kids.append(dict(m, mediaType="application/vnd.oci.image.manifest.v1+json", platform={"architecture": arch, "os": "linux"}))
    idx = put(json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": kids}, sort_keys=True).encode())
    open(os.path.join(root, "oci-layout"), "w").write('{"imageLayoutVersion":"1.0.0"}')
    json.dump({"schemaVersion": 2, "manifests": [dict(idx, mediaType="application/vnd.oci.image.index.v1+json")]}, open(os.path.join(root, "index.json"), "w"))
    return idx["digest"]
LAYOUTS = tempfile.mkdtemp()
DIG = {"image-" + v: make_layout(os.path.join(LAYOUTS, v), v) for v in ("production", "fips")}
def apk_data(variant, arch): return "data-%s-%s" % (variant, arch)
# REQ-CHAIN-007-AC17, the fixed Build interface table: artifact (runner) -> apk architecture directory -> short name; variant -> file name
RUNNERS = (("ubuntu-24.04", "x86_64", "amd64"), ("ubuntu-24.04-arm", "aarch64", "arm64"))
APKS = (("standard", "fscache-0.3.0-r0.apk"), ("fips", "fscache-fips-0.3.0-r0.apk"))
def adm(t, tag, base, **over):
    """witness-build/admission-baseline.json as Build's assemble job writes it (REQ-CHAIN-007-AC19): the tag, the commit and the baseline admission chose."""
    d = {"tag": tag, "sha": "c" * 40, "baseline_version": base, "baseline": "requirements/releases/%s.yaml" % base}
    d.update(over)
    json.dump(d, open(os.path.join(t, "witness-build/admission-baseline.json"), "w"))
def tree(extra_env=None):
    t = tempfile.mkdtemp(); fb = os.path.join(t, ".fakebin"); os.makedirs(fb); os.makedirs(os.path.join(t, "bin")); os.makedirs(os.path.join(t, "reg"))
    for n, body in FAKES.items():
        if n.startswith("bin/"):
            open(os.path.join(t, n), "w").write(body)
        else:
            open(os.path.join(fb, n), "w").write(body); os.chmod(os.path.join(fb, n), 0o755)
    for s in ("release-verify", "release-apks", "release-publish", "release-sign", "release-assets", "release-postverify"):
        src = os.path.join(BIN, s + ".sh")
        if os.path.exists(src): shutil.copy(src, os.path.join(t, "bin", s + ".sh"))
    for extra in ("release-postverify.py", "release-metadata.py", "release-layout.py"):
        if os.path.exists(os.path.join(BIN, extra)): shutil.copy(os.path.join(BIN, extra), os.path.join(t, "bin", extra))
    os.makedirs(os.path.join(t, ".vex")); open(os.path.join(t, ".vex/fosterstack-cache.openvex.json"), "w").write("{}")
    os.makedirs(os.path.join(t, "requirements/releases")); os.makedirs(os.path.join(t, "test-evidence"))
    for tg in ("v0.3.0", "v0.3.1"): open(os.path.join(t, "requirements/releases/%s.yaml" % tg), "w").write("baseline " + tg + "\n")
    open(os.path.join(t, "test-evidence/mappings.yaml"), "w").write("evidence\n")
    digs = dict(DIG)
    for top in ("apks",):                              # Build's apk-<runner> artifacts, downloaded to apks/<runner>; Rebuild's apks never reach Release (the owner's rule of Oct 21 2026)
        for runner, archdir, short in RUNNERS:
            d = os.path.join(t, top, runner, archdir); os.makedirs(d)
            for variant, name in APKS:
                open(os.path.join(d, name), "w").write("apk\nsigner: assembly.rsa.pub\ndata: %s\n" % apk_data(variant, short))
                digs["apk-%s-%s" % (variant, short)] = "sha256:" + hashlib.sha256(apk_data(variant, short).encode()).hexdigest()
    for v in ("production", "fips"):
        os.makedirs(os.path.join(t, "images", v + "-sbom"), exist_ok=True)
        shutil.copytree(os.path.join(LAYOUTS, v), os.path.join(t, "images", v))
        open(os.path.join(t, "images", v + ".digest"), "w").write(DIG["image-" + v] + "\n")
        open(os.path.join(t, "images", v + ".manifests"), "w").write("amd64 sha256:" + "1" * 64 + "\narm64 sha256:" + "2" * 64 + "\n")
        open(os.path.join(t, "images", v + ".full.lock.json"), "w").write("lock " + v); open(os.path.join(t, "images", v + "-sbom", "sbom.json"), "w").write("sbom " + v)
    for d in ("witness-build", "witness-rebuild", "witness-check", "provenance", "dist", "check-results", "apk-compare"):
        os.makedirs(os.path.join(t, d), exist_ok=True)
    open(os.path.join(t, "apk-compare/apk-compare.json"), "w").write("{}")   # the comparison job's result file (modelled as existing; chain-verify apk-compare judges it)
    open(os.path.join(t, "check-results/govulncheck.json"), "w").write('{"config":{"scanner_name":"govulncheck"}}\n')   # Check's product (ruling G), bound by release-verify
    for k in ("archive-linux-amd64", "archive-linux-arm64", "archive-fips-linux-amd64", "archive-fips-linux-arm64"): digs[k] = "sha256:" + hashlib.sha256(k.encode()).hexdigest()
    json.dump(digs, open(os.path.join(t, "witness-build/digests.json"), "w"))
    items = {}
    for v in ("production", "fips"):
        items.update({"image-" + v: DIG["image-" + v], "lock-" + v: "sha256:" + hashlib.sha256(("lock " + v).encode()).hexdigest(), "sbom-" + v: "sha256:" + hashlib.sha256(("sbom " + v).encode()).hexdigest(),
                      "image-%s-manifest-amd64" % v: "sha256:" + "1" * 64, "image-%s-manifest-arm64" % v: "sha256:" + "2" * 64})
    json.dump(items, open(os.path.join(t, "witness-build/items.json"), "w"))
    adm(t, "v0.3.0", "v0.3.0")
    for f in ["provenance/provenance.rekor.json", "provenance/provenance.bundle.json"]:      # Sign's three files (REQ-CHAIN-007-AC9: attached to the release; provenance.json is below)
        open(os.path.join(t, f), "w").write("{}")
    for f in ["witness-build/build-collection.json", "witness-rebuild/rebuild-collection.json", "provenance/provenance.json"] + ["witness-check/witness-%s/%s-collection.json" % (n, n) for n in ("scanners", "acceptance", "runtime", "arm64")]:
        os.makedirs(os.path.dirname(os.path.join(t, f)), exist_ok=True); open(os.path.join(t, f), "w").write("{}")
    for k, n in (("archive-linux-amd64", "fscache_0.3.0_linux_amd64.tar.gz"), ("archive-linux-arm64", "fscache_0.3.0_linux_arm64.tar.gz"),      # the four Linux archives Build uploaded as `dist` (REQ-CHAIN-007-AC21: checksums.txt is NOT among them; release-sign.sh makes it)
                 ("archive-fips-linux-amd64", "fscache-fips_0.3.0_linux_amd64.tar.gz"), ("archive-fips-linux-arm64", "fscache-fips_0.3.0_linux_arm64.tar.gz")):
        open(os.path.join(t, "dist", n), "wb").write(k.encode())
    os.makedirs(os.path.join(t, "docs"), exist_ok=True); open(os.path.join(t, "docs/verify-release.cannot-run.json"), "w").write("[]")
    os.makedirs(os.path.join(t, "release-published"), exist_ok=True)   # what release-assets.sh downloads the published release into (gh release download -D release-published)
    open(os.path.join(t, "dependency-provenance.json"), "w").write("{}"); open(os.path.join(t, "policy.json"), "w").write("{}")
    return t
def run(t, script, env=None, creds=None, tag="v0.3.0"):
    path = os.path.join(t, "bin", script + ".sh")
    if not os.path.exists(path): LAST[0] = 127; return 127, "", "the script " + script + ".sh does not exist"
    ver = tag[1:]
    dist = os.path.join(t, "dist")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", ver) and ver != "0.3.0" and os.path.isdir(dist):      # the four archives carry the version of the tag the run is for (their digests are by item, not by name)
        for n in os.listdir(dist):
            if "_0.3.0_linux_" in n and not os.path.exists(os.path.join(dist, n.replace("_0.3.0_", "_%s_" % ver))): os.rename(os.path.join(dist, n), os.path.join(dist, n.replace("_0.3.0_", "_%s_" % ver)))
    LAST[0] = 0
    e = {"PATH": os.path.join(t, ".fakebin") + ":" + os.environ["PATH"], "HOME": t, "LOG": os.path.join(t, "calls.log"), "REG": os.path.join(t, "reg"), "GITHUB_REF_NAME": tag, "GITHUB_SHA": "c" * 40, "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "fosterstack/cache", "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW_REF": "fosterstack/cache/.github/workflows/release.yml@refs/tags/" + tag}
    e.update({k: SENT[k] for k in (creds or [])}); e.update(env or {})
    r = subprocess.run(["bash", path], cwd=t, env=e, capture_output=True, text=True)
    LAST[0] = r.returncode if r.returncode == 127 else 0
    return r.returncode, r.stdout, r.stderr
def log(t):
    p = os.path.join(t, "calls.log"); return open(p).read().split("\n") if os.path.exists(p) else []
def tree_text(t):
    out = ""
    for dp, dn, fn in os.walk(t):
        for f in fn:
            if f in ("calls.log.key", "calls.log.keypath"): continue   # the fake signer's own capture of the key file it was handed
            try: out += open(os.path.join(dp, f), errors="replace").read()
            except Exception: pass
    return out
def first(s): return s.strip().split("\n")[0] if s.strip() else ""
# ---- AC4/AC5: release-verify.sh ------------------------------------------------------------------------------------------------------
STAGES = ["build", "items", "baseline", "sign", "rebuild", "apkcompare", "check", "govulncheck"]     # items: bind-items (REQ-CHAIN-007-AC16); baseline: bind-items --product admission-baseline.json (AC19, ruling B); check: the list verifier of the four Check records
def stage_of(c): return c.split("--previous ")[1].split()[0] if "--previous" in c else (("baseline" if "--product admission-baseline.json" in c else "items") if c.startswith("chain-verify bind-items") else "govulncheck" if c.startswith("chain-verify bind-check") else "check" if c.startswith("chain-verify check-list") else "apkcompare" if c.startswith("chain-verify apk-compare") else None)
t = tree(); rc, so, se = run(t, "release-verify")
calls = [l for l in log(t) if l.startswith("chain-verify")]
check(rc == 0, "AC5 a good v0.3.0 passes", se)
check([stage_of(c) for c in calls if stage_of(c)] == STAGES and calls and calls[0].startswith("chain-verify policy make"), "AC4 the policy is made first, then build, sign, rebuild, check are verified in that order", str(calls))
check(all("--digests witness-build/digests.json" in c for c in calls if stage_of(c) and stage_of(c) not in ("items", "baseline")) and any("--tag v0.3.0" in c for c in calls if "policy" in c), "AC4 every record is checked against the same digest list and the policy is made for the tag")
# REQ-CHAIN-007-AC14 (advisor 0383/0386): a release candidate is exactly ^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$ (case-sensitive, anchored; leading zeros as for vX.Y.Z); the old -rc.N form is gone
for tag in ("v0.3.0-rc1", "v10.20.30-rc12", "v01.02.03-rc01"):
    t = tree(); rc, so, se = run(t, "release-verify", tag=tag); check(rc == 0, "AC14 the release candidate %s passes release-verify exactly like a final" % tag, se)
for tag in ("v0.3", "v0.3.0-rc", "v0.3.0-rc.1", "v0.3.0-rc.x", "v0.3.0-rc1x", "v0.3.0-rc1.2", "v0.3.0-RC1", "v0.3.0-Rc1", "v0.3.0rc1", "v0.rc1.3.0", "rc1", "v0.3.0-1rc1", "v0.3.0-rc-1", "v0.3.0-beta.1", "v0.3.0.1", "0.3.0", "main", "refs/heads/x", "v0.3.0-rc1\n", "v0.3.0\n", ""):
    t = tree(); rc, so, se = run(t, "release-verify", tag=tag)
    check(rc != 0 and first(se).startswith("refused at tag") and not [l for l in log(t) if l.startswith("chain-verify")], "AC5 the tag %r is refused first, naming the tag, before any verification" % tag, "rc=%s %s" % (rc, first(se)))
for s in STAGES:
    t = tree(); rc, so, se = run(t, "release-verify", env={"FAIL_STAGE": s})
    after = STAGES[STAGES.index(s) + 1:]
    seen = " ".join(l for l in log(t) if l.startswith("chain-verify"))
    check(rc != 0 and first(se).startswith("refused at " + ("build" if s in ("items", "baseline") else "check" if s == "govulncheck" else "rebuild" if s == "apkcompare" else s) + ":") and not any(("--previous " + a in seen) or (a == "check" and "check-list" in seen) or (a == "items" and "bind-items" in seen) or (a == "baseline" and "--product admission-baseline.json" in seen) or (a == "govulncheck" and "bind-check" in seen) or (a == "apkcompare" and "apk-compare" in seen) for a in after), "AC5 an invalid %s record stops release at %s and no later record is checked" % (s, s), "rc=%s %s" % (rc, first(se)))
    t = tree(); rec = {"build": "witness-build/build-collection.json", "sign": "provenance/provenance.json", "rebuild": "witness-rebuild/rebuild-collection.json", "check": "witness-check/witness-arm64/arm64-collection.json", "items": "witness-build/items.json", "baseline": "witness-build/admission-baseline.json", "govulncheck": "check-results/govulncheck.json", "apkcompare": "apk-compare/apk-compare.json"}[s]
    os.remove(os.path.join(t, rec)); rc, so, se = run(t, "release-verify")
    check(rc != 0 and "refused at " + ("build" if s in ("items", "baseline") else "check" if s == "govulncheck" else "rebuild" if s == "apkcompare" else s) in first(se) and "missing" in first(se), "AC5 a missing %s record stops release, naming it" % s, "rc=%s %s" % (rc, first(se)))
# rule 58 (PR 3 made Check verify Build's record only): Release does not rely on Check having verified Sign; it verifies Sign's provenance itself, whatever Check's four records say
t = tree(); rc, so, se = run(t, "release-verify", env={"FAIL_STAGE": "sign"}); seen = [l for l in log(t) if "--previous sign" in l]
check(rc != 0 and first(se).startswith("refused at sign:") and len(seen) == 1 and "provenance/provenance.json" in seen[0] and "--rekor-stub provenance/provenance.rekor.json" in seen[0], "AC4 (rule 58) Release verifies Sign's provenance and its Rekor entry itself; four valid Check records do not stand in for it", "rc=%s %s" % (rc, first(se)))
t = tree(); os.remove(os.path.join(t, "provenance/provenance.json")); rc, so, se = run(t, "release-verify")
check(rc != 0 and "refused at sign" in first(se) and [l for l in log(t) if "check-list" in l] == [] , "AC4 (rule 58) without Sign's provenance the release stops at sign, before the Check records are looked at", "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-verify", env={"POLICY_FAIL": "1"}); check(rc != 0 and not [l for l in log(t) if stage_of(l)], "AC5 a policy that cannot be made stops release before any record is checked")
t = tree(); rc, so, se = run(t, "release-verify", creds=list(SENT))
check(rc == 0 and not [l for l in log(t) if l.split(" ")[0] in ("crane", "cosign", "gh", "melange")], "AC5 the verify script calls no registry, signing or release tool")
# ---- AC6: release-apks.sh (maps Build's names through the fixed table, checks the four attested digests, then calls cache's release-sign-apks.sh) ---------------
KEY = ["APK_RELEASE_SIGNING_KEY"]
ALLAPKS = [(archdir, name) for _r, archdir, _s in RUNNERS for _v, name in APKS]
def signers(t):
    return [subprocess.run(["python3", os.path.join(t, "bin/apk-tool.py"), "signer", os.path.join(t, "release-apks", a, n)], capture_output=True, text=True).stdout.strip()
            for a, n in ALLAPKS if os.path.exists(os.path.join(t, "release-apks", a, n))]
t = tree(); rc, so, se = run(t, "release-apks", creds=KEY)
check(rc == 0 and signers(t) == ["release.rsa.pub"] * 4, "AC6 all four apks (standard and fips, x86_64 and aarch64) come out signed by the release key, laid out as release-apks/<apk arch>/<file>", "rc=%s %s %s" % (rc, signers(t), first(se)))
cs = [l for l in log(t) if l.startswith("release-sign-apks")]
check(len(cs) == 1 and "--build-dir" in cs[0] and "--rebuild-dir" not in cs[0] and "--key" in cs[0] and not [l for l in log(t) if l.startswith("melange") and "release-sign" not in l and "--signing-key" not in l], "AC6 cache's bin/release-sign-apks.sh is called once with --build-dir --rebuild-dir --key (Release does not call melange itself)", str(cs))
check(len([l for l in log(t) if l.startswith("melange")]) == 4 and all("--signing-key" in l for l in log(t) if l.startswith("melange")), "AC6 melange is reached only through that script, with --signing-key (measured: --key is not a melange flag)")
kp = open(os.path.join(t, "calls.log.keypath")).read().strip() if os.path.exists(os.path.join(t, "calls.log.keypath")) else ""
kl = open(os.path.join(t, "calls.log.key")).read() if os.path.exists(os.path.join(t, "calls.log.key")) else ""
check("mode=600" in kl and ("content=" + SENT["APK_RELEASE_SIGNING_KEY"]) in kl, "AC6 the key reached the signer as a private (0600) file holding the key", kl)
check(kp != "" and os.path.basename(kp) == "release.rsa" and not os.path.exists(kp), "AC6 the signer's key file is named release.rsa (melange names the signer after the key file) and is removed after the run", kp)
check(SENT["APK_RELEASE_SIGNING_KEY"] not in "\n".join(log(t)) + so + se, "AC6 the key is never on a command line, in the output or in a log")
check(not any(SENT["APK_RELEASE_SIGNING_KEY"] in open(os.path.join(dp, f), errors="replace").read() for dp, dn, fn in os.walk(os.path.join(t, "release-apks")) for f in fn) and not os.path.exists(os.path.join(t, "release-evidence")), "AC6 the key is in no output file")
for label, env in (("missing", {}), ("empty", {"APK_RELEASE_SIGNING_KEY": ""})):
    t = tree(); rc, so, se = run(t, "release-apks", env=env)
    check(rc == 2 and "APK_RELEASE_SIGNING_KEY" in se and not [l for l in log(t) if l.startswith(("melange", "release-sign-apks"))], "AC6 a %s key is refused at once with exit 2, naming the variable, before any signing" % label, "rc=%s %s" % (rc, first(se)))
for key in ("apk-standard-amd64", "apk-standard-arm64", "apk-fips-amd64", "apk-fips-arm64"):   # each row of the digest table is tested
    t = tree(); d = json.load(open(os.path.join(t, "witness-build/digests.json"))); d[key] = "sha256:" + "0" * 64; json.dump(d, open(os.path.join(t, "witness-build/digests.json"), "w"))
    rc, so, se = run(t, "release-apks", creds=KEY)
    check(rc != 0 and "differs" in se and not [l for l in log(t) if l.startswith(("melange", "release-sign-apks"))] and not os.path.exists(os.path.join(t, "release-apks")), "AC6 the attested digest %s not matching its apk stops before anything is signed" % key, "rc=%s %s" % (rc, first(se)))
t = tree(); d = json.load(open(os.path.join(t, "witness-build/digests.json"))); del d["apk-fips-arm64"]; json.dump(d, open(os.path.join(t, "witness-build/digests.json"), "w"))
rc, so, se = run(t, "release-apks", creds=KEY); check(rc != 0 and "apk-fips-arm64" in se and not log(t), "AC6 a missing attested digest key is refused, naming it")
t = tree(); os.makedirs(os.path.join(t, "rapks/ubuntu-24.04-arm/aarch64")); open(os.path.join(t, "rapks/ubuntu-24.04-arm/aarch64/fscache-fips-0.3.0-r0.apk"), "w").write("apk\nsigner: assembly.rsa.pub\ndata: other\n")
rc, so, se = run(t, "release-apks", creds=KEY)
check(rc == 0 and signers(t) == ["release.rsa.pub"] * 4 and "rapks" not in " ".join(log(t)), "AC6 Rebuild's apks are never read by release-apks (a differing file under rapks/ changes nothing: the comparison is the compare job's, in a job without the key)", "rc=%s %s" % (rc, first(se)))
RA = open(os.path.join(BIN, "release-apks.sh")).read()
check("rapks" not in RA and "rebuild-dir" not in RA and "release-apks-rebuild" not in RA, "AC6 release-apks.sh names neither rapks/ nor --rebuild-dir nor a rebuild staging directory")
t = tree(); rc, so, se = run(t, "release-apks", creds=KEY, env={"MELANGE_BREAK": "1"})
check(rc != 0 and "release" in se.lower() and "signed" in se.lower(), "AC6 an apk the signer left signed by another key is refused ('not signed by the release key')", "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-apks", creds=KEY, env={"MELANGE_FAIL": "1"}); kp = open(os.path.join(t, "calls.log.keypath")).read().strip() if os.path.exists(os.path.join(t, "calls.log.keypath")) else ""
check(rc != 0, "AC6 a failing signer fails the script"); check(not os.path.exists(os.path.join(t, "calls.log.keypath")) or not os.path.exists(kp), "AC6 the key file is removed on a failing run too")
t = tree(); shutil.rmtree(os.path.join(t, "apks")); os.makedirs(os.path.join(t, "apks")); rc, so, se = run(t, "release-apks", creds=KEY)
check(rc != 0 and "no apk" in se.lower(), "AC6 no apks to sign is an error, not a success")
t = tree(); os.remove(os.path.join(t, "apks/ubuntu-24.04-arm/aarch64/fscache-0.3.0-r0.apk")); rc, so, se = run(t, "release-apks", creds=KEY)
check(rc != 0 and "no apk" in se.lower() and "aarch64" in se, "AC6 one missing apk (the artifact table row for aarch64) is an error naming the architecture")
t = tree(); shutil.copy(os.path.join(t, "apks/ubuntu-24.04/x86_64/fscache-0.3.0-r0.apk"), os.path.join(t, "apks/ubuntu-24.04/x86_64/fscache-9.9.9-r0.apk")); rc, so, se = run(t, "release-apks", creds=KEY)
check(rc != 0 and "exactly one" in se, "AC6 two standard apks in one architecture directory are refused (Build attests exactly one)")
for tag in ("v0.3.0-rc1", "v0.3.0-rc.1", "main"):
    t = tree(); rc, so, se = run(t, "release-apks", creds=KEY, tag=tag); check(rc != 0 and "tag" in se and not log(t), "AC14 release-apks refuses the tag %r (only a final vX.Y.Z reaches it; a release candidate never signs)" % tag, "rc=%s %s" % (rc, first(se)))
# ---- AC7: release-publish.sh -------------------------------------------------------------------------------------------------------------
REG = ["DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "GH_TOKEN"]
def pushes(t): return [l.split(" ") for l in log(t) if l.startswith("crane push")]
t = tree(); rc, so, se = run(t, "release-publish", creds=REG); P = pushes(t)
check(rc == 0, "AC7 a good v0.3.0 publishes", se)
need = {(h, tag) for h in ("ghcr.io", "docker.io") for tag in ("0.3.0", "0.3.0-fips")}
got = {(p[3].split("/")[0], p[3].split(":")[1]) for p in P}
check(need <= got, "AC7 both variants are pushed to ghcr.io and the Docker Hub mirror with their version tags", str(sorted(got)))
check(bool(P) and all(p[2].startswith("images/") for p in P) and not [l for l in log(t) if re.match(r"crane (copy|pull)", l)], "AC7 the bytes pushed are the ones Build handed over (images/<variant>.tar), nothing is pulled or rebuilt")
check(bool(P) and P[0][3].startswith("ghcr.io/"), "AC7 ghcr.io comes first")
check(bool(P) and all(os.path.exists(os.path.join(t, "reg", p[3].replace(":", "/", 1))) and open(os.path.join(t, "reg", p[3].replace(":", "/", 1))).read().strip() == DIG["image-production" if "fips" not in p[3] else "image-fips"] for p in P), "AC7 the registry shows the attested index digest for every tag pushed")
check(any(l.startswith("crane digest") for l in log(t)), "AC7 each registry is read back")
check(SENT["DOCKERHUB_TOKEN"] not in "\n".join(log(t)) + so + se and SENT["GH_TOKEN"] not in "\n".join(log(t)) + so + se, "AC7 the credentials go in by standard input, never on a command line or in output")
for tag in ("v0.3.0-rc1", "v0.3.0-rc.1", "v0.3.0-RC1", "v0.3.0-beta.1", "main"):
    t = tree(); rc, so, se = run(t, "release-publish", creds=REG, tag=tag)
    check(rc != 0 and "tag" in se and not pushes(t) and not log(t), "AC14 release-publish refuses the tag %r: a release candidate never publishes, no login, no push, no floating tag" % tag, "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-publish", creds=REG, env={"REG_CORRUPT": "docker.io"})
check(rc != 0 and "differ" in se and DIG["image-production"] in se and "docker.io" in se, "AC7 a registry that shows another digest blocks release, naming the image and both digests", "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-publish", creds=REG, env={"REG_CORRUPT": "ghcr.io"}); h = [p[3].split("/")[0] for p in pushes(t)]
check(rc != 0 and "docker.io" not in h, "AC7 a mismatch at ghcr.io stops everything: nothing is pushed to the mirror afterwards", str(h))
t = tree(); os.makedirs(os.path.join(t, "reg/ghcr.io/fosterstack/cache"), exist_ok=True); open(os.path.join(t, "reg/ghcr.io/fosterstack/cache/0.3.0"), "w").write("sha256:" + "9" * 64)
rc, so, se = run(t, "release-publish", creds=REG)
check(rc != 0 and "already" in se.lower() and not pushes(t), "AC7 a target tag that already shows another digest is refused before anything is pushed")
t = tree(); os.makedirs(os.path.join(t, "reg/ghcr.io/fosterstack/cache"), exist_ok=True); open(os.path.join(t, "reg/ghcr.io/fosterstack/cache/0.3.0"), "w").write(DIG["image-production"])
rc, so, se = run(t, "release-publish", creds=REG); check(rc == 0, "AC7 a rerun on a tag that already shows the attested digest passes", se)
t = tree(); open(os.path.join(t, "images/fips.digest"), "w").write("sha256:" + "c" * 64 + "\n"); rc, so, se = run(t, "release-publish", creds=REG)
check(rc != 0 and not pushes(t), "AC7 an image whose own digest is not the attested one is refused before any push")
for miss in ("DOCKERHUB_TOKEN", "DOCKERHUB_USERNAME", "GH_TOKEN"):
    t = tree(); rc, so, se = run(t, "release-publish", creds=[c for c in REG if c != miss])
    check(rc == 2 and miss in se and not pushes(t), "AC7 a missing %s is refused with exit 2, naming it, before any push" % miss, "rc=%s %s" % (rc, first(se)))
# ---- REQ-REL-009-AC11 (Codex B1 on the old stage-promote.yml, which moved :latest on every release): the floating tags of a FINAL release --------
# AC11: ":X.Y to itself every time, :X and :latest only when it is the highest released version, on GHCR and the Docker Hub mirror alike, by digest".
# The released versions are the plain X.Y.Z tags of ghcr.io/fosterstack/cache (rc tags, -fips tags and the floating tags themselves are not versions).
# NOT in AC11 and so not built: floating tags of the -fips image (it gets its exact tag only), and any flag. The registry fake lists tags with `crane ls`.
def seed(t, tags, hosts=("ghcr.io", "docker.io"), dig="7"):
    for host in hosts:
        d = os.path.join(t, "reg", host, "fosterstack", "cache"); os.makedirs(d, exist_ok=True)
        for x in tags: open(os.path.join(d, x), "w").write("sha256:" + dig * 64)
def float_run(tag, tags, env=None, creds=REG):
    t = tree()
    if tags is not None: seed(t, tags)
    rc, so, se = run(t, "release-publish", creds=creds, env=env, tag=tag)
    return t, rc, so, se
def tagset(t): return {(p[3].split("/")[0], p[3].split(":")[1]) for p in pushes(t)}
def want(*tags): return {(h, x) for h in ("ghcr.io", "docker.io") for x in tags}
t, rc, so, se = float_run("v0.3.0", ["0.2.2", "0.2.1", "latest", "0.2"]); got = tagset(t)
check(rc == 0 and got == want("0.3.0", "0.3.0-fips", "0.3", "0", "latest"), "AC11 the highest released version moves :X.Y, :X and :latest (production image), the -fips image gets its exact tag only, in both registries", "rc=%s %s %s" % (rc, sorted(got), first(se)))
t, rc, so, se = float_run("v0.3.1", ["0.3.0", "0.4.0", "0.4", "0", "latest"]); got = tagset(t)
check(rc == 0 and got == want("0.3.1", "0.3.1-fips", "0.3"), "AC11 a patch of an older line moves :X.Y only: 0.4.0 is higher, so neither :0 nor :latest moves (the Codex B1 finding: the old stage moved :latest always)", "rc=%s %s %s" % (rc, sorted(got), first(se)))
t, rc, so, se = float_run("v0.3.0", ["1.0.0", "1.0", "1", "latest"]); got = tagset(t)
check(rc == 0 and "latest" not in {x for _, x in got} and "0" not in {x for _, x in got} and ("ghcr.io", "0.3") in got, "AC11 :latest is never moved by a version lower than a released one (1.0.0 exists)", str(sorted(got)))
t, rc, so, se = float_run("v0.3.0", ["0.4.0-rc.1", "0.2.0-fips", "latest", "0.3", "0", "9.9.9-fips", "1.0.0-rc.2", "v9.9.9", "latest-fips"]); got = tagset(t)
check(rc == 0 and got == want("0.3.0", "0.3.0-fips", "0.3", "0", "latest"), "AC11 only plain X.Y.Z tags are released versions: rc tags, -fips tags, floating tags and malformed tags do not block :latest", "rc=%s %s %s" % (rc, sorted(got), first(se)))
t, rc, so, se = float_run("v0.3.0", None); got = tagset(t)
check(rc == 0 and got == want("0.3.0", "0.3.0-fips", "0.3", "0", "latest"), "AC11 a repository with no tag yet (NAME_UNKNOWN) means this is the highest version", "rc=%s %s %s" % (rc, sorted(got), first(se)))
t, rc, so, se = float_run("v0.3.0", ["0.2.2"], env={"LS_FAIL": "1"})
check(rc != 0 and not pushes(t) and "ghcr.io" in se and "list" in se.lower(), "AC11 a tag list that cannot be read stops the release before any push (it never guesses that this is the highest)", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = float_run("v0.3.0", ["0.2.2"], env={"REG_CORRUPT": "docker.io"})
check(rc != 0 and "differ" in se and "docker.io" in se, "AC11 a floating tag is read back like an exact one (a mirror that shows another digest blocks the release)", "rc=%s %s" % (rc, first(se)))
for tag in ("v0.3.0-rc1", "v10.20.30-rc7"):
    t, rc, so, se = float_run(tag, ["0.2.2"])
    check(rc != 0 and not pushes(t), "AC14 the release candidate %s moves no floating tag and pushes nothing" % tag, "rc=%s" % rc)
t, rc, so, se = float_run(tag, ["0.2.2"]); x = {y for _, y in tagset(t)}
t, rc, so, se = float_run("v0.3.0", ["0.2.2"]); L = [l for l in log(t) if l.startswith("crane push")]
check(L and all(re.search(r" images/(production|fips) ", l + " ") for l in L) and not [l for l in log(t) if l.startswith("crane tag")], "AC11 floating tags are pushed from the same attested bytes, nothing is retagged from a registry")
# ---- release review R3 (Oct 22): :0 and :latest were decided once from the first `crane ls`; a concurrent publication of a higher release between that
# listing and the floating pushes was rolled back (0.3.1 published, then a resumed 0.3.0 moved :0/:latest back to 0.3.0's digest, and the digest read-back passed).
# The highest version is now decided again right before the floating tags are pushed, and the END STATE of both registries is checked after every final run. The remaining
# window (a publication that completes between that last listing and the push) is closed by the release job's concurrency group (release.yml; asserted in bin/chain-build-wiring-test.sh).
HIGHER = "sha256:" + "8" * 64
def regtag(t, host, tag):
    p = os.path.join(t, "reg", host, "fosterstack", "cache", tag)
    return open(p).read().strip() if os.path.exists(p) else None
def again(t, tag="v0.3.0", env=None): return run(t, "release-publish", creds=REG, env=env, tag=tag)
t, rc, so, se = float_run("v0.3.0", ["0.2.2"], env={"LS_RACE_AFTER": "1"})
check(rc != 0 and all(regtag(t, h, x) == HIGHER for h in ("ghcr.io", "docker.io") for x in ("0", "latest")) and ("ghcr.io", "latest") not in tagset(t) and ("docker.io", "0") not in tagset(t) and "0.3.1" in se,
      "R3 a higher release that appears after the first listing keeps :0 and :latest (neither is moved back to 0.3.0) in both registries; :0.3 (always moved, ratified) now differs from the line's highest, so the end-state check fails naming 0.3.1", "rc=%s 0=%s latest=%s pushed=%s %s" % (rc, regtag(t, "ghcr.io", "0"), regtag(t, "docker.io", "latest"), sorted(tagset(t)), first(se)))
t, rc, so, se = float_run("v0.3.0", ["0.2.2"], env={"LS_RACE_AFTER": "2"})
check(rc != 0 and "0.3.1" in se, "R3 a higher release that completes after the last listing but before the floating push: the end-state check fails the step naming 0.3.1", "rc=%s %s" % (rc, first(se)))
# audit ruling, Oct 22: a RETRY must not go green over a rolled-back state. The end state of every final run is checked in BOTH registries (the highest plain X.Y.Z on
# ghcr exists on each registry with ghcr's digest; :latest and :<major> equal it; :X.Y equals the line's highest); digests are compared, nothing is retagged.
t, rc, so, se = float_run("v0.3.0", ["0.2.2"], env={"LS_RACE_AFTER": "2"}); rc2, so2, se2 = again(t)
check(rc != 0 and rc2 != 0 and "0.3.1" in se2, "R3 re-running 0.3.0 on the registry the race-2 run left behind (ghcr :0/:latest rolled back) fails naming 0.3.1 instead of passing", "rc=%s rc2=%s %s" % (rc, rc2, first(se2)))
t, rc, so, se = float_run("v0.3.0", ["0.2.2"], env={"LS_RACE_AFTER": "3"}); rc2, so2, se2 = again(t)
check(rc != 0 and rc2 != 0 and "docker.io" in se2 and "0.3.1" in se2, "R3 re-running 0.3.0 after the race-3 run (the mirror rolled back, ghcr correct) fails naming the mirror and 0.3.1", "rc=%s rc2=%s %s" % (rc, rc2, first(se2)))
t = tree(); seed(t, ["0.3.1", "0.3", "0", "latest"], hosts=("ghcr.io",), dig="8"); seed(t, ["0.3.1"], hosts=("docker.io",), dig="8"); seed(t, ["0", "latest", "0.3"], hosts=("docker.io",), dig="7")
rc, so, se = run(t, "release-publish", creds=REG, tag="v0.3.0")
check(rc != 0 and "docker.io" in se and "0.3.1" in se, "R3 a mirror holding stale :0/:latest (no race, ghcr correct at the higher release) fails the older release's run naming the mirror and 0.3.1", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = float_run("v0.3.0", ["0.3.1", "0.3.1-fips", "0.3", "0", "latest"])
check(rc != 0 and ("ghcr.io", "0.3") in tagset(t) and ("ghcr.io", "latest") not in tagset(t) and "0.3.1" in se and "0.3" in se, "R3 a resumed older patch of the same line still moves :0.3 (the owner's 'always move :X.Y') but the step fails naming the line's highest, 0.3.1: the rollback is never silent", "rc=%s %s %s" % (rc, sorted(tagset(t)), first(se)))
t, rc, so, se = float_run("v0.3.0", ["0.2.2"], env={"LS_RACE_AFTER": "9"}); got = tagset(t)
check(rc == 0 and got == want("0.3.0", "0.3.0-fips", "0.3", "0", "latest"), "R3 no concurrent publication: unchanged, the highest release moves :0 and :latest", "rc=%s %s" % (rc, sorted(got)))
t = tree(); import shutil as _sh; _sh.rmtree(os.path.join(t, "images/production")); open(os.path.join(t, "images/production"), "w").write("a tarball, not a layout directory")
rc, so, se = run(t, "release-publish", creds=REG); check(rc != 0 and "production" in se and not pushes(t), "AC7 an image that is not an OCI layout directory (a tarball) is refused before any push, naming it", "rc=%s %s" % (rc, first(se)))
# round 1 (Codex B R1): a signing run that leaves one of the four apks of the attested list missing is refused (no empty glob skips validation)
for top in ("apks",):
    t = tree(); os.remove(os.path.join(t, top, "ubuntu-24.04-arm/aarch64/fscache-fips-0.3.0-r0.apk"))
    rc, so, se = run(t, "release-apks", creds=KEY)
    check(rc != 0 and "fips" in se and "aarch64" in se, "AC6 R1 the %s tree missing the arm64 -fips apk is refused naming the apk (an empty glob does not skip it)" % top, "rc=%s %s" % (rc, first(se)))
# round 1 (Codex A F2): a registry login lives in a private DOCKER_CONFIG of the step and is gone when the step ends, success or failure
def login_gone(t, what):
    home_cfg = os.path.join(t, ".docker")
    f = os.path.join(t, "calls.log.dockercfg"); used = open(f).read().split() if os.path.exists(f) else []
    check(bool(used) and home_cfg not in used and not os.path.exists(home_cfg), "AC10 F2 %s: the login is not in the runner's shared ~/.docker" % what, "used=%s" % used)
    check(all(not os.path.exists(d) for d in used) and bool(used), "AC10 F2 %s: the private configuration directory is removed when the step ends" % what, "left=%s" % [d for d in used if os.path.exists(d)])
t = tree(); rc, so, se = run(t, "release-publish", creds=REG); login_gone(t, "release-publish (success)")
t = tree(); rc, so, se = run(t, "release-publish", creds=REG, env={"REG_CORRUPT": "docker.io"}); login_gone(t, "release-publish (a registry mismatch stops it)")
t = tree(); rc, so, se = run(t, "release-sign", creds=REG); login_gone(t, "release-sign")
# round 3 (Codex A): a failed mktemp stops the step before any login (an empty DOCKER_CONFIG would fall back to ~/.docker)
for s_ in ("release-publish", "release-sign"):
    t = tree(); fb = os.path.join(t, ".fakebin"); open(os.path.join(fb, "mktemp"), "w").write("#!/usr/bin/env bash\nexit 1\n"); os.chmod(os.path.join(fb, "mktemp"), 0o755)
    rc, so, se = run(t, s_, creds=REG)
    check(rc != 0 and not [l for l in log(t) if "auth login" in l or l.startswith("cosign login") or "push" in l or l.startswith("cosign sign")], "AC10 F2b %s: a failed mktemp stops the step before any login or push" % s_, "rc=%s %s" % (rc, first(se)))
# round 1 (Codex A B4): the layout's CONTENT is the attested image before anything is logged in or pushed
def layout_refused(t, what, word):
    rc, so, se = run(t, "release-publish", creds=REG)
    check(rc != 0 and word in se and not pushes(t) and not [l for l in log(t) if "auth login" in l], "AC7 B4 " + what + " is refused before any login or push", "rc=%s %s pushes=%s" % (rc, first(se), pushes(t)))
def blobs_of(t, v): d = os.path.join(t, "images", v, "blobs/sha256"); return d, sorted(os.listdir(d))
t = tree(); d, bl = blobs_of(t, "production"); open(os.path.join(d, bl[0]), "ab").write(b"x")
layout_refused(t, "a layout blob whose bytes no longer hash to its name", "production")
t = tree(); d, bl = blobs_of(t, "fips"); os.remove(os.path.join(d, bl[0])); layout_refused(t, "a layout with a blob missing", "fips")
t = tree(); ix = os.path.join(t, "images/fips/index.json"); j = json.load(open(ix)); j["manifests"][0]["digest"] = "sha256:" + "d" * 64; json.dump(j, open(ix, "w"))
layout_refused(t, "an index.json whose descriptor is not the attested digest (the sidecar still says it is)", "fips")
t = tree(); ix = os.path.join(t, "images/production/index.json"); j = json.load(open(ix)); j["manifests"].append(dict(j["manifests"][0])); json.dump(j, open(ix, "w"))
layout_refused(t, "an index.json with two descriptors", "production")
t = tree(); d, bl = blobs_of(t, "production"); idx_hex = DIG["image-production"].split(":")[1]
kid = [b for b in bl if b != idx_hex][0]; os.remove(os.path.join(d, kid)); open(os.path.join(d, kid), "wb").write(b"swapped")
layout_refused(t, "a child blob replaced under its name", "production")
t = tree(); os.remove(os.path.join(t, "images/fips/index.json")); rc, so, se = run(t, "release-publish", creds=REG)
check(rc != 0 and "fips" in se and not pushes(t), "AC7 a layout directory without index.json is refused before any push", "rc=%s %s" % (rc, first(se)))
# ---- AC8: release-sign.sh -------------------------------------------------------------------------------------------------------------------
def signs(t): return [l for l in log(t) if l.startswith("cosign")]
t = tree(); os.makedirs(os.path.join(t, "reg"), exist_ok=True); rc, so, se = run(t, "release-sign", creds=REG); L = log(t)
check(rc == 0, "AC8 a good run signs", se)
check(L and L[0].startswith("vendor-provenance evidence --out"), "AC8 the dependency evidence is produced first (bin/vendor-provenance.py evidence --out DIR)", str(L[:1]))
# ruling G (advisor Oct 12; cache-ce's PROPOSED interface `evidence --out DIR --provenance FILE --govulncheck FILE --date EPOCH`): the dependency list is the tag checkout's own
# file, the govulncheck stream is Check's product (bound by release-verify), the date is the admitted commit's committer date from git; each one in the one fixed call
EV = "vendor-provenance evidence --out release-evidence --provenance dependency-provenance.json --govulncheck check-results/govulncheck.json --date 1760000000"
check(L and L[0] == EV, "G the evidence call is exactly `evidence --out release-evidence --provenance dependency-provenance.json --govulncheck check-results/govulncheck.json --date EPOCH`", str(L[:1]))
gl = open(os.path.join(t, "calls.log.git")).read().strip().split("\n") if os.path.exists(os.path.join(t, "calls.log.git")) else []
check(gl == ["git log -1 --format=%ct " + "c" * 40], "G the date is `git log -1 --format=%ct $GITHUB_SHA` (the admitted tag commit's committer date) and git is used for nothing else", str(gl))
for label, mutate, env in (("is missing", lambda t: os.remove(os.path.join(t, "check-results/govulncheck.json")), {}),
                           ("is a symlink", lambda t: (os.remove(os.path.join(t, "check-results/govulncheck.json")), os.symlink("/etc/hosts", os.path.join(t, "check-results/govulncheck.json"))), {}),
                           ("is empty", lambda t: open(os.path.join(t, "check-results/govulncheck.json"), "w").close(), {}),
                           ("(dependency-provenance.json) is missing", lambda t: os.remove(os.path.join(t, "dependency-provenance.json")), {}),
                           ("(dependency-provenance.json) is empty", lambda t: open(os.path.join(t, "dependency-provenance.json"), "w").close(), {}),
                           ("(dependency-provenance.json) is a symlink", lambda t: (os.remove(os.path.join(t, "dependency-provenance.json")), os.symlink("/etc/hosts", os.path.join(t, "dependency-provenance.json"))), {})):
    tg = tree(); mutate(tg); rc, so, se = run(tg, "release-sign", creds=REG)
    check(rc != 0 and not [l for l in log(tg) if l.startswith(("vendor-provenance", "cosign"))], "G the file Release hands the evidence step %s: nothing is produced or signed" % label, "rc=%s %s" % (rc, first(se)))
for label, env in (("not a number", {"GIT_EPOCH": "yesterday"}), ("empty", {"GIT_EPOCH": ""}), ("negative", {"GIT_EPOCH": "-5"}), ("git failing", {"GIT_FAIL": "1"}), ("two lines", {"GIT_EPOCH": "1760000000\n1760000001"})):
    tg = tree(); rc, so, se = run(tg, "release-sign", creds=REG, env=env)
    check(rc != 0 and not [l for l in log(tg) if l.startswith(("vendor-provenance", "cosign"))], "G a commit date that is %s stops before the evidence step and any signature" % label, "rc=%s %s" % (rc, first(se)))
imgs = [l for l in L if l.startswith("cosign sign ")]
check({(re.search(r"(ghcr\.io|docker\.io)/fosterstack/cache@(sha256:\w+)", l).groups()) for l in imgs} == {(h, d) for h in ("ghcr.io", "docker.io") for d in DIG.values()}, "AC8 each published image digest is signed in BOTH registries", str(imgs))
# REQ-CHAIN-007-AC8 (advisor ruling H, Oct 12): the release manifest stays attached to each public image digest as an OCI referrer (as on v0.2.x), type
# https://fosterstack.com/attestations/release-manifest/v1; the GHCR referrer is required, the Docker Hub mirror is best-effort with a loud warning
ATT = "cosign attest --yes --signing-config .github/policy/cosign-signing-config.json --predicate release-metadata/release-manifest.json --type https://fosterstack.com/attestations/release-manifest/v1 "
atts = [l for l in L if l.startswith("cosign attest ")]
want_refs = sorted("%s/fosterstack/cache@%s" % (h, d) for h in ("ghcr.io", "docker.io") for d in DIG.values())
check(sorted(l[len(ATT):] for l in atts if l.startswith(ATT)) == want_refs and len(atts) == 4, "AC8 the release manifest is attested on each public digest in both registries, with exactly the pinned flags and type (four attestations)", str(atts))
last_sign = max((i for i, l in enumerate(L) if l.startswith("cosign sign ")), default=-1); first_att = next((i for i, l in enumerate(L) if l.startswith("cosign attest ")), -2)
check(last_sign >= 0 and first_att > last_sign, "AC8 the manifest attestations come AFTER the image signatures (nothing is attached to an unsigned image)", "sign %s attest %s" % (last_sign, first_att))
mfile = os.path.join(t, "release-metadata/release-manifest.json"); lf2 = os.path.join(t, "release-metadata/release-files.sha256")
check(os.path.exists(mfile) and ("%s  release-manifest.json" % hashlib.sha256(open(mfile, "rb").read()).hexdigest()) in open(lf2).read(), "AC8 the attested predicate is the manifest release-files.sha256 lists (made from Build's verified material, not another file)")
t5 = tree(); rc5, so5, se5 = run(t5, "release-sign", creds=REG, env={"COSIGN_ATTEST_FAIL_ON": "docker.io/"})
check(rc5 == 0 and "docker.io" in so5 + se5 and "::warning::" in so5 and len([l for l in log(t5) if l.startswith("cosign attest ")]) == 4 and any(l.startswith("cosign sign-blob") for l in log(t5)),
      "AC8 a Docker Hub mirror referrer that cannot be attached is a loud warning, never a silent skip, and the run continues (GHCR is authoritative)", "rc=%s %s" % (rc5, first(se5)))
t5 = tree(); rc5, so5, se5 = run(t5, "release-sign", creds=REG, env={"COSIGN_ATTEST_FAIL_ON": "ghcr.io/"})
check(rc5 != 0 and not any(l.startswith("cosign sign-blob") for l in log(t5)), "AC8 a GHCR referrer that cannot be attached stops the run before any file is signed", "rc=%s %s" % (rc5, first(se5)))
blobs = " ".join(l for l in L if l.startswith("cosign sign-blob"))
for f in ("production.sbom.json", "fips.sbom.json", "production.full.lock.json", "fips.full.lock.json", "vendor-evidence.json", "dependency-list.json", "checksums.txt", "policy.json"):
    check(f in blobs, "AC8 %s is signed with a bundle" % f)
check(all("--bundle" in l for l in L if l.startswith("cosign sign-blob")), "AC8 every signed file gets a bundle")
# REQ-CHAIN-007-AC21 (advisor reading Oct 16, Astra R3): release-sign.sh makes dist/checksums.txt itself, from the four archives Build recorded, before its first signature
t21 = tree(); rc21, so21, se21 = run(t21, "release-sign", creds=REG)
ARC21 = sorted((("fscache_0.3.0_linux_amd64.tar.gz", b"archive-linux-amd64"), ("fscache_0.3.0_linux_arm64.tar.gz", b"archive-linux-arm64"),
                ("fscache-fips_0.3.0_linux_amd64.tar.gz", b"archive-fips-linux-amd64"), ("fscache-fips_0.3.0_linux_arm64.tar.gz", b"archive-fips-linux-arm64")), key=lambda x: x[0].encode())
cs21 = os.path.join(t21, "dist/checksums.txt")
check(rc21 == 0 and os.path.exists(cs21) and open(cs21).read() == "".join("%s  %s\n" % (hashlib.sha256(c).hexdigest(), n) for n, c in ARC21),
      "AC21 release-sign makes dist/checksums.txt from the four archives (the test did not make it), in byte order, and signs that file", "rc=%s %s" % (rc21, first(se21)))
tp = tree(); victim = os.path.join(tp, "dist/fscache_0.3.0_linux_amd64.tar.gz"); vb = open(victim, "rb").read()
os.symlink(victim, os.path.join(tp, "dist/checksums.txt.part")); rcp, sop, sep = run(tp, "release-sign", creds=REG)
check(rcp == 0 and open(victim, "rb").read() == vb and not os.path.islink(os.path.join(tp, "dist/checksums.txt")),
      "AC21 round 1: a symlink planted at dist/checksums.txt.part does not make release-sign overwrite an archive or sign a symlink", "rc=%s %s" % (rcp, first(sep)))
for label, mutate in (("a missing archive", lambda t: os.remove(os.path.join(t, "dist/fscache_0.3.0_linux_arm64.tar.gz"))),
                      ("an archive that is not the recorded bytes", lambda t: open(os.path.join(t, "dist/fscache_0.3.0_linux_amd64.tar.gz"), "wb").write(b"other")),
                      ("an extra archive", lambda t: open(os.path.join(t, "dist/fscache_0.3.0_linux_riscv.tar.gz"), "wb").write(b"x"))):
    tg = tree(); mutate(tg); rc, so, se = run(tg, "release-sign", creds=REG)
    check(rc != 0 and not os.path.exists(os.path.join(tg, "dist/checksums.txt")) and not [l for l in log(tg) if l.startswith(("vendor-provenance", "cosign"))],
          "AC21 %s stops release-sign before any signature and no checksums.txt is made" % label, "rc=%s %s" % (rc, first(se)))
check(not re.search(r"tlog-upload=false|insecure-ignore-tlog|--no-tlog", "\n".join(L)), "AC8 the transparency log is never turned off")
check("witness-build" not in blobs and "witness-rebuild" not in blobs and "witness-check" not in blobs, "AC8 the Witness records are not signed again (they are extra evidence)")
for f in ("policy.json", "vendor-evidence.json", "production.sbom.json", "fips.sbom.json", "production.full.lock.json", "fips.full.lock.json", "dependency-list.json", "checksums.txt", "release-files.sha256"):
    name = {"policy.json": "release-policy.bundle"}.get(f, f + ".bundle")
    t = tree(); rc, so, se = run(t, "release-sign", creds=REG, env={"COSIGN_NOREKOR": name})
    check(rc != 0 and "rekor" in se.lower() and name in se, "AC8 a bundle with no Rekor entry (%s) fails the script, naming the file" % name, "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-sign", creds=REG, env={"EVIDENCE_FAIL": "1"}); check(rc != 0 and not signs(t), "AC8 failing evidence stops everything before anything is signed")
t = tree(); rc, so, se = run(t, "release-sign", creds=REG, env={"COSIGN_FAIL": "1"}); check(rc != 0 and len(signs(t)) == 1, "AC8 a failing cosign (it fails at login, the first call) stops at the first call")
# the signature itself fails (the login passes): the failing `cosign sign` is the only one made, and no attestation and no blob signature follows it
t = tree(); rc, so, se = run(t, "release-sign", creds=REG, env={"COSIGN_FAIL_ON": "sign --yes"})
Lf = log(t)
check(rc != 0 and len([l for l in Lf if l.startswith("cosign sign ")]) == 1 and not any(l.startswith(("cosign attest ", "cosign sign-blob")) for l in Lf),
      "AC8 a failing image signature stops at the first one: no attestation and no file is signed after it", "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-sign", creds=REG); check(rc == 0 and os.path.exists(os.path.join(t, "release-evidence")), "AC8 the bundles and the evidence land in release-evidence/")
# AC13: the four metadata files and the signed list are made in release-sign, before the first signature, from Build's verified digests only
t = tree(); rc, so, se = run(t, "release-sign", creds=REG); L = log(t)
vf = [l for l in L if l.startswith("vex-forms")]
check(rc == 0 and len(vf) == 1 and "--openvex .vex/fosterstack-cache.openvex.json" in vf[0] and "--images release-metadata/vex-images.json" in vf[0] and "--version v0.3.0" in vf[0] and "--out-dir release-metadata" in vf[0], "AC13 bin/vex-forms.py makes the CSAF and inspector-filters files from the one OpenVEX file and the image digests of release-metadata/vex-images.json", str(vf))
check(sorted(os.listdir(os.path.join(t, "release-metadata"))) == sorted(["release-manifest.json", "fosterstack-cache.openvex.json", "fosterstack-cache-v0.3.0.csaf.json", "fosterstack-cache-v0.3.0.inspector-filters.json", "release-files.sha256", "vex-images.json"]) if os.path.isdir(os.path.join(t, "release-metadata")) else False, "AC13 release-metadata/ holds the four files, release-files.sha256 and the vex input", str(os.listdir(t)))
lf = os.path.join(t, "release-metadata/release-files.sha256")
check(os.path.exists(lf) and [x.split("  ")[1] for x in open(lf).read().split("\n") if x] == ["release-manifest.json", "fosterstack-cache.openvex.json", "fosterstack-cache-v0.3.0.csaf.json", "fosterstack-cache-v0.3.0.inspector-filters.json"], "AC13 release-files.sha256 lists exactly the four files in order")
mj = json.load(open(os.path.join(t, "release-metadata/release-manifest.json"))) if os.path.exists(os.path.join(t, "release-metadata/release-manifest.json")) else {}
check([x.get("file") for x in mj.get("vex", [])] == ["fosterstack-cache.openvex.json", "fosterstack-cache-v0.3.0.inspector-filters.json", "fosterstack-cache-v0.3.0.csaf.json"] and all(x.get("sha256") == hashlib.sha256(open(os.path.join(t, "release-metadata", x["file"]), "rb").read()).hexdigest() for x in mj.get("vex", [])), "AC13 the VEX and CSAF files are generated BEFORE the manifest, and the manifest records their sha256", str(mj.get("vex")))
vi = json.load(open(os.path.join(t, "release-metadata/vex-images.json"))) if os.path.exists(os.path.join(t, "release-metadata/vex-images.json")) else {}
check(sorted(vi) == ["fips", "production"] and sorted(vi["production"]) == ["children", "index"] and sorted(vi["production"]["children"]) == ["linux/amd64", "linux/arm64"] and "debug" not in vi, "AC13 the vex-forms input is exactly {production: {index, children {linux/amd64, linux/arm64}}, fips: {...}}, no debug key", str(vi))
t2 = tree(); os.remove(os.path.join(t2, "witness-build/items.json")); rc2, so2, se2 = run(t2, "release-sign", creds=REG); check(rc2 != 0 and "items.json" in se2 and not signs(t2), "AC13 without Build's verified items Release does not check the digests it publishes in the VEX forms: it stops before anything is signed", "rc=%s %s" % (rc2, first(se2)))
check(mj.get("requirements_baseline", {}).get("path") == "requirements/releases/v0.3.0.yaml" and mj.get("requirements_baseline", {}).get("sha256") == hashlib.sha256(b"baseline v0.3.0\n").hexdigest() and mj.get("test_evidence", {}).get("path") == "test-evidence/mappings.yaml", "AC19 the manifest records the requirements baseline of the tag and the test-evidence hash (REL-009-AC13 note)", str({k: mj.get(k) for k in ("requirements_baseline", "test_evidence")}))
t2 = tree(); os.remove(os.path.join(t2, "requirements/releases/v0.3.0.yaml")); rc2, so2, se2 = run(t2, "release-sign", creds=REG)
check(rc2 != 0 and "v0.3.0.yaml" in se2 and not signs(t2), "AC19 a tag with no baseline file stops before anything is signed, naming it", "rc=%s %s" % (rc2, first(se2)))
# AC19 (advisor ruling B, Oct 12): a CI patch tag has no requirements/releases/<tag>.yaml of its own; the manifest records the baseline admission chose, read from
# Build's VERIFIED admission-baseline.json (bound to Build's record by release-verify), never one Release picks itself
t3 = tree(); os.remove(os.path.join(t3, "requirements/releases/v0.3.1.yaml")); adm(t3, "v0.3.1", "v0.3.0")
rc3, so3, se3 = run(t3, "release-sign", creds=REG, tag="v0.3.1")
mj3 = json.load(open(os.path.join(t3, "release-metadata/release-manifest.json"))) if os.path.exists(os.path.join(t3, "release-metadata/release-manifest.json")) else {}
check(rc3 == 0 and mj3.get("requirements_baseline", {}).get("version") == "v0.3.0" and mj3.get("requirements_baseline", {}).get("path") == "requirements/releases/v0.3.0.yaml"
      and mj3.get("requirements_baseline", {}).get("sha256") == hashlib.sha256(b"baseline v0.3.0\n").hexdigest(), "AC19 a CI patch tag with no requirements/releases/<tag>.yaml produces a manifest that records admission's baseline", "rc=%s %s" % (rc3, first(se3)))
for label, mk, word in (
    ("a missing admission-baseline.json", lambda t: os.remove(os.path.join(t, "witness-build/admission-baseline.json")), "admission-baseline.json"),
    ("a file for another tag (forged: the owner tag's baseline reused)", lambda t: adm(t, "v0.3.0", "v0.3.0"), "tag"),
    ("a file for another commit", lambda t: adm(t, "v0.3.1", "v0.3.0", sha="d" * 40), "commit"),
    ("a baseline version that is not vX.Y.Z", lambda t: adm(t, "v0.3.1", "../v0.3.0", baseline="requirements/releases/../v0.3.0.yaml"), "baseline"),
    ("a baseline path that is not the version's file", lambda t: adm(t, "v0.3.1", "v0.3.0", baseline="requirements/releases/v0.2.0.yaml"), "baseline"),
    ("a baseline newer than the tag", lambda t: adm(t, "v0.3.1", "v0.3.2"), "baseline"),
    ("an extra key", lambda t: adm(t, "v0.3.1", "v0.3.0", evidence="x"), "admission-baseline.json"),
    ("a symlink", lambda t: (os.remove(os.path.join(t, "witness-build/admission-baseline.json")), os.symlink("items.json", os.path.join(t, "witness-build/admission-baseline.json"))), "admission-baseline.json"),
    ("a file that is not JSON", lambda t: open(os.path.join(t, "witness-build/admission-baseline.json"), "w").write("{nope"), "admission-baseline.json")):
    t4 = tree(); os.remove(os.path.join(t4, "requirements/releases/v0.3.1.yaml")); adm(t4, "v0.3.1", "v0.3.0"); mk(t4)
    rc4, so4, se4 = run(t4, "release-sign", creds=REG, tag="v0.3.1")
    check(rc4 != 0 and word in se4 and not signs(t4) and not os.path.exists(os.path.join(t4, "release-metadata/release-manifest.json")), "AC19 %s is refused before anything is signed, naming it" % label, "rc=%s %s" % (rc4, first(se4)))
first_sig = next((i for i, l in enumerate(L) if l.startswith("cosign")), 99)
check(L.index(vf[0]) < first_sig if vf else False, "AC13 the metadata is made before the first signature")
check(any(l.startswith("cosign sign-blob") and "release-files.sha256.bundle" in l and l.endswith("release-metadata/release-files.sha256") for l in L), "AC13 release-files.sha256 is signed keyless with a bundle in release-evidence/", str([l for l in L if "release-files" in l]))
t = tree(); rc, so, se = run(t, "release-sign", creds=REG, env={"COSIGN_NOREKOR": "release-files.sha256.bundle"}); check(rc != 0 and "rekor" in se.lower() and "release-files.sha256" in se, "AC13 a release-files bundle with no Rekor entry fails, naming it", "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-sign", creds=REG, env={"VEXFORMS_FAIL": "1"}); check(rc != 0 and not signs(t), "AC13 failing VEX generation stops everything before anything is signed")
t = tree(); open(os.path.join(t, "images/fips.manifests"), "w").write("amd64 sha256:" + "1" * 64 + "\n"); rc, so, se = run(t, "release-sign", creds=REG); check(rc != 0 and "fips.manifests" in se and not signs(t), "AC13 an images/<variant>.manifests that is not complete stops before anything is signed")
for tag in ("v0.3.0-rc1", "v0.3.0-rc.1", "main"):
    t = tree(); rc, so, se = run(t, "release-sign", creds=REG, tag=tag); check(rc != 0 and "tag" in se and not log(t), "AC14 release-sign refuses the tag %r" % tag, "rc=%s %s" % (rc, first(se)))
# ---- AC9: release-assets.sh ----------------------------------------------------------------------------------------------------------------------
def full_assets():
    t = tree(); rc_, so_, se_ = run(t, "release-sign", creds=REG)
    os.makedirs(os.path.join(t, "release-apks/x86_64")); os.makedirs(os.path.join(t, "release-apks/aarch64"))
    for arch in ("x86_64", "aarch64"):
        for name in ("fscache-0.3.0-r0.apk", "fscache-fips-0.3.0-r0.apk"): open(os.path.join(t, "release-apks", arch, name), "w").write(arch + name)
    # the four Linux archives Build recorded (its digests.json holds sha256 of the item name as each archive's bytes)
    arcs = (("fscache_0.3.0_linux_amd64.tar.gz", b"archive-linux-amd64"), ("fscache_0.3.0_linux_arm64.tar.gz", b"archive-linux-arm64"),
            ("fscache-fips_0.3.0_linux_amd64.tar.gz", b"archive-fips-linux-amd64"), ("fscache-fips_0.3.0_linux_arm64.tar.gz", b"archive-fips-linux-arm64"))
    for n, c in arcs: open(os.path.join(t, "dist", n), "wb").write(c)
    return t
t = full_assets(); rc, so, se = run(t, "release-assets", creds=["GH_TOKEN"]); L = " ".join(log(t))
check(rc == 0, "AC9 a good run attaches the assets", se)
for what in ("release upload v0.3.0", "release-upload/amd64-fscache-0.3.0-r0.apk", "release-upload/arm64-fscache-fips-0.3.0-r0.apk", "release-upload/production.sbom.json ", "release-upload/fips.sbom.json ", "release-upload/production.full.lock.json ", "release-upload/fips.full.lock.json ",
             "release-upload/fscache_0.3.0_linux_amd64.tar.gz", "release-upload/checksums.txt ", "release-upload/checksums.txt.bundle", "release-upload/release-policy.bundle", "release-upload/policy.json", "release-upload/vendor-evidence.json", "release-upload/build-collection.json", "release-upload/rebuild-collection.json", "release-upload/scanners-collection.json", "release-upload/acceptance-collection.json", "release-upload/runtime-collection.json", "release-upload/arm64-collection.json", "release-upload/provenance.json", "release-upload/provenance.rekor.json", "release-upload/provenance.bundle.json"):
    check(what in L + " ", "AC9 %s is attached to the release (the apks under their architecture, the sboms and locks under their variant: names that differ)" % what.strip())
for pf in ("provenance.json", "provenance.rekor.json", "provenance.bundle.json"):     # Sign's provenance is part of every release: a run without one stops before the upload, naming it
    tp = full_assets(); os.remove(os.path.join(tp, "provenance", pf)); rcp, sop, sep = run(tp, "release-assets", creds=["GH_TOKEN"])
    check(rcp != 0 and pf in sep and not [l for l in log(tp) if l.startswith("gh release upload")], "AC9 without Sign's %s the release is not published: nothing is uploaded, the file is named" % pf, "rc=%s %s" % (rcp, first(sep)))
t2 = full_assets(); rc2, so2, se2 = run(t2, "release-assets", creds=["GH_TOKEN"], env={"GH_VIEW_ERR": "release not found"})
check(rc2 == 0 and [l for l in log(t2) if l.startswith("gh release create")] and all(l.endswith("--verify-tag") for l in log(t2) if l.startswith("gh release create")), "AC9 a missing release is created, public, only with --verify-tag", se2)
check(not [l for l in log(t2) if "--draft" in l or "release edit" in l or "--notes-from-tag" in l], "AC9 no undraft and no gh-generated notes")
# round 1 (Codex A F5, B B4; advisor ruling 2): a patch tag's generated notes are the release's notes; any other tag keeps the fixed evidence text
FIXED = "Evidence: see docs/verify-release.md for the verification commands of this release."
def notes_of(t): p = os.path.join(t, "calls.log.notes"); return open(p).read() if os.path.exists(p) else None
check(notes_of(t2) == FIXED, "AC9 R-notes an owner's tag (no readable generated notes) is released with the fixed evidence text", repr(notes_of(t2)))
GEN = ("object 0123\ntype commit\ntag v0.3.0\ntagger fosterstack release <release@users.noreply.github.com> 1 +0000\n\n"
       "## v0.3.0 \u2014 patch release\n\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n- no change\n"
       "-----BEGIN SIGNED MESSAGE-----\nMIIabc\n-----END SIGNED MESSAGE-----\n")
t6 = full_assets(); open(os.path.join(t6, "tagobj"), "w").write(GEN)
rc6, so6, se6 = run(t6, "release-assets", creds=["GH_TOKEN"], env={"TAG_OBJECT": os.path.join(t6, "tagobj")})
ed = [l for l in log(t6) if l.startswith("gh release edit")]
check(rc6 == 0 and len(ed) == 1 and "--notes-file" in ed[0] and (notes_of(t6) or "").startswith("## v0.3.0") and not [l for l in log(t6) if l.startswith("gh release create")],
      "AC8 an existing release gets the generated patch tag's notes too (one edit, no creation)", "rc=%s %s notes=%r" % (rc6, ed, notes_of(t6)))
t6 = full_assets(); rc6, so6, se6 = run(t6, "release-assets", creds=["GH_TOKEN"])
check(rc6 == 0 and not [l for l in log(t6) if l.startswith("gh release edit")], "AC8 an existing release of a tag with no generated notes is not edited")
t3 = full_assets(); open(os.path.join(t3, "tagobj"), "w").write(GEN)
rc3, so3, se3 = run(t3, "release-assets", creds=["GH_TOKEN"], env={"GH_VIEW_ERR": "release not found", "TAG_OBJECT": os.path.join(t3, "tagobj")})
n3 = notes_of(t3)
check(rc3 == 0 and n3 is not None and n3.startswith("## v0.3.0") and "### VEX" in n3 and "MIIabc" not in n3 and "BEGIN" not in n3, "AC8 the generated patch tag's notes are the release's notes (signature block dropped)", "rc=%s %r %s" % (rc3, n3, first(se3)))
t3 = full_assets(); open(os.path.join(t3, "tagobj"), "w").write(GEN.replace("tagger fosterstack release <release@users.noreply.github.com>", "tagger Someone Else <x@example.com>"))
rc3, so3, se3 = run(t3, "release-assets", creds=["GH_TOKEN"], env={"GH_VIEW_ERR": "release not found", "TAG_OBJECT": os.path.join(t3, "tagobj")})
check(rc3 == 0 and notes_of(t3) == FIXED, "AC8 a tag message from another tagger is not taken as notes: the fixed text", repr(notes_of(t3)))
# R3 (Codex B): only a definite 'release not found' creates; any other failure of the view stops before creation and upload
for err in ("HTTP 401: Bad credentials", "HTTP 502: Bad Gateway", "dial tcp: connection refused"):
    t4 = full_assets(); rc4, so4, se4 = run(t4, "release-assets", creds=["GH_TOKEN"], env={"GH_VIEW_ERR": err})
    check(rc4 != 0 and not [l for l in log(t4) if l.startswith("gh release create") or l.startswith("gh release upload")], "AC9 R3 a failed release view (%s) is not 'no release': nothing is created or uploaded" % err, "rc=%s %s" % (rc4, first(se4)))

t = full_assets(); rc, so, se = run(t, "release-assets", creds=["GH_TOKEN"]); L = " ".join(log(t))
check(rc == 0 and "release-upload/release-files.sha256 " in L + " " and "release-upload/release-manifest.json" in L and "release-upload/release-files.sha256.bundle" in L, "AC13 the four metadata files, release-files.sha256 and its bundle are attached", "rc=%s %s" % (rc, first(se)))
t = full_assets(); os.remove(os.path.join(t, "release-evidence/release-files.sha256.bundle")); rc, so, se = run(t, "release-assets", creds=["GH_TOKEN"])
check(rc != 0 and "release-files.sha256.bundle" in se and not [l for l in log(t) if l.startswith("gh release upload")], "AC13 the coverage gate runs BEFORE the upload: a release without the signed list is refused, nothing is uploaded", "rc=%s %s" % (rc, first(se)))
t = full_assets(); os.makedirs(os.path.join(t, "release-evidence"), exist_ok=True); open(os.path.join(t, "release-evidence/stray.json"), "w").write("{}"); rc, so, se = run(t, "release-assets", creds=["GH_TOKEN"])
check(rc != 0 and "stray.json" in se and not [l for l in log(t) if l.startswith("gh release upload")], "AC13 an asset covered by nothing stops the release before the upload, naming it", "rc=%s %s" % (rc, first(se)))
t = full_assets(); rc, so, se = run(t, "release-assets", creds=["GH_TOKEN"], env={"GH_DROP": "release-files.sha256.bundle"})
check(rc != 0 and "release-files.sha256.bundle" in se, "AC13 the gate runs again AFTER publishing, on what the release stores: a missing asset fails the run", "rc=%s %s" % (rc, first(se)))
t = full_assets(); rc, so, se = run(t, "release-assets", creds=["GH_TOKEN"], env={"GH_ALTER": "release-manifest.json"})
check(rc != 0 and "release-manifest.json" in se, "AC13 the gate after publishing catches a stored file that differs from the staged one", "rc=%s %s" % (rc, first(se)))
for tag in ("v0.3.0-rc1", "v0.3.0-rc.1", "main"):
    t3 = tree(); rc3, so3, se3 = run(t3, "release-assets", creds=["GH_TOKEN"], tag=tag); check(rc3 != 0 and "tag" in se3 and not log(t3), "AC14 release-assets refuses the tag %r" % tag, "rc=%s %s" % (rc3, first(se3)))
check(not [l for l in log(t) if re.search(r"release create(?!.*--verify-tag)|git (?!cat-file tag )", l)], "AC9 no release is created without --verify-tag and no tag is made")
check(SENT["GH_TOKEN"] not in L + so + se, "AC9 the token is never on a command line or in output")
# round 1 (Codex A B3): the archives are Build's bytes and the set is complete before anything is uploaded
def refused_before_upload(t, what, word, **kw):
    rc, so, se = run(t, "release-assets", creds=["GH_TOKEN"], **kw)
    check(rc != 0 and word in se and not any(l.startswith("gh release") for l in log(t)), "AC9 B3 " + what + " is refused before any release is created or uploaded", "rc=%s %s calls=%s" % (rc, first(se), [l for l in log(t) if l.startswith("gh")][:2]))
def resum(t):      # checksums.txt of whatever archives dist holds (a replaced archive is "covered" by a list that agrees with it)
    ds = os.path.join(t, "dist"); open(os.path.join(ds, "checksums.txt"), "w").write("".join(
        "%s  %s\n" % (hashlib.sha256(open(os.path.join(ds, n), "rb").read()).hexdigest(), n) for n in sorted(os.listdir(ds)) if n.endswith(".tar.gz")))
t = full_assets(); open(os.path.join(t, "dist/fscache_0.3.0_linux_amd64.tar.gz"), "wb").write(b"replacement archive"); resum(t)
refused_before_upload(t, "an archive whose bytes are not Build's (its checksums.txt agrees with the replacement)", "archive-linux-amd64")
t = full_assets(); os.remove(os.path.join(t, "dist/fscache-fips_0.3.0_linux_arm64.tar.gz")); resum(t); refused_before_upload(t, "a missing -fips arm64 archive", "archive-fips-linux-arm64")
t = full_assets(); open(os.path.join(t, "dist/fscache_0.3.0_linux_ppc64.tar.gz"), "wb").write(b"x"); resum(t); refused_before_upload(t, "a fifth archive Build did not record", "ppc64")
t = full_assets(); shutil.rmtree(os.path.join(t, "release-apks/aarch64")); refused_before_upload(t, "no apk of the arm64 architecture", "aarch64")
t = full_assets(); os.remove(os.path.join(t, "release-apks/aarch64/fscache-fips-0.3.0-r0.apk")); refused_before_upload(t, "no -fips apk of the arm64 architecture (one apk of four is missing)", "fips")
t = full_assets(); os.remove(os.path.join(t, "release-apks/x86_64/fscache-0.3.0-r0.apk")); refused_before_upload(t, "no standard apk of the amd64 architecture (one apk of four is missing)", "x86_64")
for n in ("scanners", "acceptance", "runtime", "arm64"):
    t = full_assets(); os.remove(os.path.join(t, "witness-check/witness-%s/%s-collection.json" % (n, n))); refused_before_upload(t, "the Check record %s missing (the four named records are attached)" % n, n)
t = full_assets(); shutil.rmtree(os.path.join(t, "release-apks/x86_64")); refused_before_upload(t, "no apk of the amd64 architecture", "x86_64")
t = full_assets(); shutil.rmtree(os.path.join(t, "witness-check")); refused_before_upload(t, "no Check record to attach", "witness-check")
# F4 (Codex A): an explicit evidence inventory; a second file under a release name, or a name outside the inventory, stops before anything is staged
t5 = full_assets(); open(os.path.join(t5, "witness-build/policy.json"), "w").write("REPLACED POLICY"); refused_before_upload(t5, "an extra witness-build/policy.json (it would replace the signed policy)", "policy.json")
t5 = full_assets(); open(os.path.join(t5, "witness-rebuild/verdict.json"), "w").write("{}")
rc5, so5, se5 = run(t5, "release-assets", creds=["GH_TOKEN"], env={"GH_VIEW_ERR": "release not found"})
check(rc5 == 0 and not os.path.exists(os.path.join(t5, "release-upload/verdict.json")), "AC9 R3b Rebuild's own verdict.json beside its record is allowed and is not attached (the inventory names what is attached)", "rc=%s %s" % (rc5, first(se5)))
t5 = full_assets(); open(os.path.join(t5, "witness-rebuild/extra.json"), "w").write("{}"); refused_before_upload(t5, "a file of Rebuild's record directory outside the inventory", "extra.json")
t5 = full_assets(); open(os.path.join(t5, "release-evidence/build-collection.json"), "w").write("{}"); refused_before_upload(t5, "a second source for the release name build-collection.json", "build-collection.json")
t5 = full_assets(); open(os.path.join(t5, "witness-check/witness-scanners/stray.json"), "w").write("{}"); refused_before_upload(t5, "a stray file beside a Check record", "stray.json")
t = tree(); rc, so, se = run(t, "release-assets"); check(rc == 2 and "GH_TOKEN" in se and not log(t), "AC9 a missing GH_TOKEN is refused with exit 2, naming it")
# ---- REQ-CHAIN-006-AC7 (rule 79 amended, owner Oct 10): the post-publish verification, release-postverify.sh -----------------------------------
# PROPOSED interface: it reads docs/verify-release.cannot-run.json ([{command, reason}], the one exact-text list Check also reads), runs each
# listed command with <IMAGE_REF> / <IMAGE_REF_FIPS> = ghcr.io/fosterstack/cache@ the image-production / image-fips digest of
# witness-build/digests.json, <TAG> = $GITHUB_REF_NAME, <IDENTITY> = https://github.com/$GITHUB_REPOSITORY/.github/workflows/stage-sign.yml@refs/tags/<TAG>.
# Every command is judged BEFORE any is run (a verify form only, a placeholder it cannot fill is refused): a refusal runs nothing. A command
# that fails fails the script (exit non-zero, naming the command) after all have run. The step holds GH_TOKEN (read) and no registry credential.
ISS = "https://token.actions.githubusercontent.com"
IDQ = "--certificate-identity <IDENTITY> --certificate-oidc-issuer " + ISS
PV1 = "cosign verify <IMAGE_REF> " + IDQ
PV2 = "cosign verify <IMAGE_REF_FIPS> " + IDQ
PV3 = "gh attestation verify oci://<IMAGE_REF> --owner fosterstack"
PV4 = "cosign verify-blob --certificate-identity https://github.com/fosterstack/cache/.github/workflows/stage-sign.yml@refs/tags/<TAG> --certificate-oidc-issuer " + ISS + " --bundle b.json x.txt"
def pv(rows, env=None, raw=None, tag="v0.3.0", digs=None):
    t = tree(); os.makedirs(os.path.join(t, "docs"), exist_ok=True)
    lp = os.path.join(t, "docs/verify-release.cannot-run.json")
    if rows is None and raw is None: os.remove(lp)
    if raw is not None: open(lp, "w").write(raw)
    elif rows is not None: json.dump([{"command": c, "reason": "needs the image in a registry"} for c in rows], open(lp, "w"))
    if digs is not None: json.dump(digs, open(os.path.join(t, "witness-build/digests.json"), "w"))
    e = {"GITHUB_REPOSITORY": "fosterstack/cache"}; e.update(env or {})
    rc, so, se = run(t, "release-postverify", env=e, creds=["GH_TOKEN"], tag=tag)
    return t, rc, so, se
def calls(t): return [l for l in log(t) if l.startswith(("cosign ", "gh "))]
REGS = ["ghcr.io/fosterstack/cache", "docker.io/fosterstack/cache"]   # the two repositories are constants of the script (identical digests in both)
def refs(key): return [r + "@" + DIG[key] for r in REGS]
SID = "https://github.com/fosterstack/cache/.github/workflows/stage-sign.yml@refs/tags/v0.3.0"
t, rc, so, se = pv([PV1, PV2, PV3, PV4]); C = calls(t)
P, F = refs("image-production"), refs("image-fips")
check(rc == 0, "AC7 post-publish: a good list of four commands passes in both registries", se)
check(len(C) == 7, "AC7 post-publish: the three image commands run twice and the verify-blob (no image placeholder) once: seven runs, not eight", str(len(C)))
mk = lambda ref: "cosign verify %s --certificate-identity %s --certificate-oidc-issuer %s" % (ref, SID, ISS)
check(C[:1] == [mk(P[0])] and mk(P[1]) in C, "AC7 post-publish: <IMAGE_REF> is the repository@digest, once per registry (ghcr.io first, then docker.io), with the SAME digest", str(C[:2]))
check(any(c.startswith("cosign verify " + F[0] + " ") for c in C) and any(c.startswith("cosign verify " + F[1] + " ") for c in C), "AC7 post-publish: <IMAGE_REF_FIPS> is substituted in both registries with the one -fips digest", str(C))
check(all(("gh attestation verify oci://%s --owner fosterstack" % r) in C for r in P), "AC7 post-publish: <IMAGE_REF> inside oci:// is substituted per registry", str(C))
check(len([c for c in C if c.startswith("cosign verify-blob")]) == 1 and "refs/tags/v0.3.0 " in [c for c in C if c.startswith("cosign verify-blob")][0] and not re.search(r"<[A-Z_]+>", "\n".join(C)), "AC7 post-publish: a command with no image placeholder runs once; <TAG> is the release tag; no placeholder is left in any command run", str(C))
for tag in ("v0.3.0-rc1", "v0.3.0-rc.1"):
    t, rc, so, se = pv([PV1], tag=tag); check(rc != 0 and not calls(t), "AC14 post-publish: the tag %r is refused, nothing runs (a release candidate publishes nothing to verify)" % tag, "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pv([]); check(rc == 0 and not calls(t), "AC7 post-publish: an empty list runs nothing and passes")
t, rc, so, se = pv([PV1, PV3], env={"GH_FAIL": "1"}); C = calls(t)
t2, rc2, so2, se2 = pv([PV1, PV3], env={"GH_FAIL_ON": "docker.io"})
check(rc2 != 0 and len(calls(t2)) == 4 and "::error::" in se2 and "docker.io/fosterstack/cache" in [l for l in se2.split("\n") if l.startswith("::error::")][0] and "gh attestation verify" in [l for l in se2.split("\n") if l.startswith("::error::")][0] and "ghcr.io" not in [l for l in se2.split("\n") if l.startswith("::error::")][0], "AC7 post-publish: a command that fails only against docker.io fails the run, and the ::error:: line names docker.io and the command", "rc=%s %s" % (rc2, se2[:300]))
t2, rc2, so2, se2 = pv([PV1, PV3], env={"COSIGN_FAIL_ON": "ghcr.io"})
check(rc2 != 0 and len(calls(t2)) == 4 and "ghcr.io/fosterstack/cache" in [l for l in se2.split("\n") if l.startswith("::error::")][0], "AC7 post-publish: a command that fails only against ghcr.io fails the run (the docker.io pass still runs), the ::error:: line names ghcr.io", "rc=%s %s" % (rc2, se2[:300]))
t2, rc2, so2, se2 = pv([PV1, PV2, PV3], env={"GH_FAIL": "1", "COSIGN_FAIL_ON": "docker.io"})
check(rc2 != 0 and len([l for l in se2.split("\n") if l.startswith("::error::")]) == 4, "AC7 post-publish: every failed run (registry x command) gets its own ::error:: line: 2 gh + 2 cosign on docker.io = 4", se2[:300])
check(rc != 0 and len(C) == 4 and "post-publish verification failed" in se and "gh attestation verify" in se, "AC7 post-publish: a failing command fails the script (exit non-zero), the others still run, and the failure names the command", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pv([PV1, PV2], env={"COSIGN_FAIL": "1"}); check(rc != 0 and "post-publish verification failed" in se, "AC7 post-publish: a failing cosign verify fails the script")
t, rc, so, se = pv(None); check(rc != 0 and "verify-release.cannot-run.json" in se and not calls(t), "AC7 post-publish: a missing list file fails the script, naming it, and runs nothing")
for raw, what in (("[{\"command\": ", "unparsable JSON"), ("{\"command\": \"x\"}", "an object, not a list"), ("[\"cosign verify x\"]", "a row that is not {command, reason}"),
                  ("[{\"command\": \"cosign verify <IMAGE_REF>\"}]", "a row with no reason"), ("[{\"command\": \"cosign verify <IMAGE_REF>\", \"reason\": \"\"}]", "a row with an empty reason")):
    t, rc, so, se = pv(None, raw=raw); check(rc != 0 and "verify-release.cannot-run.json" in se and not calls(t), "AC7 post-publish: %s fails the script and runs nothing" % what, "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pv([PV1, PV1]); check(rc != 0 and "twice" in se and not calls(t), "AC7 post-publish: a command listed twice is refused and nothing runs")
for bad_cmd, what in (("curl -sS https://example.com/x", "curl"), ("cosign sign <IMAGE_REF>", "cosign sign"), ("cosign verify <IMAGE_REF>; id", "a ; after a verify"), ("cosign verify <IMAGE_REF> | sh", "a pipe into sh"),
                      ("cosign verify <IMAGE_REF> $(id)", "a command substitution"), ("cosign verify <IMAGE_REF> `id`", "a backquote"), ("cosign verify <IMAGE_REF> > /tmp/x", "a redirect"),
                      ("rm -rf .", "rm"), ("gh release delete v0.3.0", "gh release delete"), ("gh api -X DELETE repos/x/y", "gh api"), ("jq -n 1", "jq alone"), ("cosign verify --key $COSIGN_KEY <IMAGE_REF>", "a $ outside single quotes"),
                      ("cosign verify <IMAGE_REF>\nprintf LOCAL_MARKER", "a newline after a verify (bash runs it as a second command)"), ("cosign verify <IMAGE_REF>\rprintf LOCAL_MARKER", "a carriage return after a verify"),
                      ("cosign verify <IMAGE_REF> --certificate-identity \\'x${HOME}y\\'", "a backslash-escaped quote before a $"),
                      ("cosign verify <IMAGE_REF> # '\nprintf LOCAL_MARKER", "a comment holding a quote, then a newline and a second command"), ("cosign verify <IMAGE_REF> #\nprintf LOCAL_MARKER", "a comment, then a newline and a second command")):
    t, rc, so, se = pv([PV1, bad_cmd, PV2]); check(rc != 0 and "not an allowed verify form" in se and not calls(t), "AC7 post-publish: %s is refused (not an allowed verify form) and NOTHING runs, not even the good commands before it" % what, "rc=%s calls=%s %s" % (rc, calls(t), first(se)))
t, rc, so, se = pv([PV1, "cosign verify <IMAGE_REF> --certificate-identity <DIGEST> --certificate-oidc-issuer " + ISS]); check(rc != 0 and "<DIGEST>" in se and not calls(t), "AC7 post-publish: a command with a placeholder the step cannot fill is refused, never run literally, and nothing runs")
t, rc, so, se = pv([PV1 + " --extra <TAGS>"]); check(rc != 0 and "<TAGS>" in se and not calls(t), "AC7 post-publish: a misspelt placeholder is refused, never run literally")
digs = {"image-production": DIG["image-production"], "apk-amd64": "sha256:" + "c" * 64}
t, rc, so, se = pv([PV2], digs=digs); check(rc != 0 and "image-fips" in se and not calls(t), "AC7 post-publish: <IMAGE_REF_FIPS> with no image-fips digest in the digest list is refused")
t, rc, so, se = pv([PV1], digs={"image-production": "sha256:zz"}); check(rc != 0 and not calls(t), "AC7 post-publish: a malformed image digest is refused")
fipsbad = {"image-production": DIG["image-production"], "image-fips": "sha256:" + "B" * 64}
for dg, what in ((digs, "no image-fips digest"), (fipsbad, "an upper-case (not lower-case hex) -fips digest"), ({"image-fips": DIG["image-fips"]}, "no image-production digest"),
                 ({"image-production": DIG["image-production"], "image-fips": "sha256:" + "b" * 63}, "a short -fips digest"), ({"image-production": "sha256:zz", "image-fips": DIG["image-fips"]}, "a malformed production digest"),
                 ({"image-production": 5, "image-fips": DIG["image-fips"]}, "a non-string production digest")):
    t, rc, so, se = pv([PV3], digs=dg); check(rc != 0 and "digest" in se and not calls(t), "AC7 post-publish: %s runs nothing even when no command uses it" % what, "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pv([PV4], digs=digs); check(rc != 0 and not calls(t), "AC7 post-publish: a bad digest list runs nothing, also for a command with no image placeholder")
t, rc, so, se = pv([PV1, PV2], digs=dict(DIG, repository="evil.example/x", repositories=["evil.example/x"]))
check(rc == 0 and len(calls(t)) == 4 and not [c for c in calls(t) if "evil" in c], "AC7 post-publish: a repository named in the digest list is ignored (the two repositories are constants)", str(calls(t)))
t, rc, so, se = pv([PV1], env={"RELEASE_REPOSITORY": "evil.example/x", "REPOSITORY": "evil.example/x", "IMAGE_REPOSITORY": "evil.example/x", "CANDIDATE_REPOSITORY": "evil.example/x"})
check(rc == 0 and len(calls(t)) == 2 and not [c for c in calls(t) if "evil" in c], "AC7 post-publish: no environment variable can name a repository", str(calls(t)))
t, rc, so, se = pv(None, raw=json.dumps([{"command": PV1, "reason": "r", "repository": "evil.example/x"}])); check(rc != 0 and not calls(t), "AC7 post-publish: a list row with a repository key is refused (a third repository cannot be injected through the list)")
for lit in ("evil.example/x/cache@" + DIG["image-production"], "docker.io/library/alpine@sha256:" + "d" * 64, "ghcr.io/fosterstack/cache@" + DIG["image-production"], "oci://evil.example/x/cache@" + DIG["image-production"], "quay.io/x/y:latest"):
    t, rc, so, se = pv([PV1, "cosign verify " + lit + " " + IDQ.replace("<IDENTITY>", "<IDENTITY>")]); check(rc != 0 and "repository" in se and not calls(t), "AC7 post-publish: a literal image reference (%s) in a listed command is refused and nothing runs: only the two constant repositories, through the placeholders" % lit[:28], "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pv([PV4.replace("x.txt", "dir/x.txt")]); check(rc == 0 and len(calls(t)) == 1, "AC7 post-publish: a file path with a slash is not an image reference and runs once")
for tag in ("main", "v0.3", "0.3.0", "v0.3.0-RC1", ""):
    t, rc, so, se = pv([PV1], tag=tag); check(rc != 0 and not calls(t), "AC7 post-publish: the tag %r is refused, nothing runs" % tag, "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pv([PV1], env={"GITHUB_REPOSITORY": ""}); check(rc != 0 and not calls(t), "AC7 post-publish: no GITHUB_REPOSITORY means <IDENTITY> cannot be filled: refused when a command uses it")
t, rc, so, se = pv([PV1, PV3]); L = "\n".join(log(t))
check(rc == 0 and not re.search(r"crane|docker login|auth login|\bpush\b", L) and SENT["GH_TOKEN"] not in L + so + se, "AC7 post-publish: no registry login or push, and the read token is never on a command line or in output")
# ---- REQ-CHAIN-007-AC20 (advisor ruling B, Oct 15): the commands run from the downloaded assets; a jq-only command only after a verify of the same file --------------
PBF = "cosign verify-blob-attestation --bundle provenance.bundle.json --type https://slsa.dev/provenance/v1 --check-claims=false " + IDQ
PJ = "jq -e '.ok == true' provenance.bundle.json"
def pva(rows, assets=None, nodir=False, key=None, **kw):
    """pv with files in release-published/ (assets: name -> text), or the directory removed; key: the text of the
    verified release key file release-key.verified.pub (None: no such file)."""
    t = tree()
    if key is not None: open(os.path.join(t, "release-key.verified.pub"), "w").write(key)
    rp = os.path.join(t, "release-published")
    if nodir: shutil.rmtree(rp)
    else:
        for n, c in (assets or {}).items(): open(os.path.join(rp, n), "w").write(c)
    os.makedirs(os.path.join(t, "docs"), exist_ok=True)
    json.dump([{"command": c, "reason": "needs a release file"} for c in rows], open(os.path.join(t, "docs/verify-release.cannot-run.json"), "w"))
    e = {"GITHUB_REPOSITORY": "fosterstack/cache"}; e.update(kw.get("env") or {})
    rc, so, se = run(t, "release-postverify", env=e, creds=["GH_TOKEN"])
    return t, rc, so, se
OK = '{"ok": true}'
t, rc, so, se = pva([PBF], assets={"provenance.bundle.json": OK})
cwds = open(os.path.join(t, "calls.log.cwd")).read().split() if os.path.exists(os.path.join(t, "calls.log.cwd")) else []
check(rc == 0 and cwds and all(os.path.realpath(c) == os.path.realpath(os.path.join(t, "release-published")) for c in cwds), "AC20 post-publish: a listed command runs with release-published/ as its working directory", "rc=%s cwds=%s %s" % (rc, cwds, first(se)))
t, rc, so, se = pva([PV1], nodir=True); check(rc != 0 and not calls(t) and "release-published" in se, "AC20 post-publish: a missing release-published/ fails the run before anything runs, naming it", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PBF, PV1], env={"FAKE_NEEDFILES": "1"}); check(rc != 0 and len(calls(t)) == 3 and "post-publish verification failed" in se and "provenance.bundle.json" in se, "AC20 post-publish: a command naming a file absent from release-published/ fails the run, the others still run", "rc=%s calls=%d %s" % (rc, len(calls(t)), first(se)))
t, rc, so, se = pva([PBF, PJ], assets={"provenance.bundle.json": OK}); check(rc == 0 and len(calls(t)) == 1, "AC20 post-publish: a jq-only command after a verify of the same file runs and passes (jq read the file)", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PBF, PJ], assets={"provenance.bundle.json": '{"ok": false}'}); check(rc != 0 and "post-publish verification failed" in se and PJ in se, "AC20 post-publish: the jq-only command really runs on the file: a false filter fails the run, naming it", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PJ], assets={"provenance.bundle.json": OK}); check(rc != 0 and not calls(t) and "earlier" in se, "AC20 post-publish: a jq-only command with no earlier verify is refused and nothing runs", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PJ, PBF], assets={"provenance.bundle.json": OK}); check(rc != 0 and not calls(t) and "earlier" in se, "AC20 post-publish: a jq-only command listed BEFORE its verify is refused and nothing runs", "rc=%s %s" % (rc, first(se)))
# F13: <RELEASE_KEY> is filled only with the path of the verified key file; nothing else, and the run refuses without it
PUB = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexample\n-----END PUBLIC KEY-----\n"
PK = "cosign verify-blob --key <RELEASE_KEY> --bundle provenance.bundle.json provenance.bundle.json"
t, rc, so, se = pva([PK], assets={"provenance.bundle.json": OK}, key=PUB)
kc = [c for c in calls(t) if "--key" in c]
check(rc == 0 and len(kc) == 1 and os.path.join(t, "release-key.verified.pub") in kc[0] and "<RELEASE_KEY>" not in kc[0],
      "F13 post-publish: <RELEASE_KEY> is filled with the verified key file", "rc=%s %s %s" % (rc, kc, first(se)))
t, rc, so, se = pva([PK], assets={"provenance.bundle.json": OK})
check(rc != 0 and not calls(t) and "release-key.verified.pub" in se,
      "F13 post-publish: with no verified key file nothing runs and the run names the file", "rc=%s %s" % (rc, first(se)))
for label, text in (("an awskms reference", "awskms:///alias/example\n"),
                    ("a private key", "-----BEGIN PRIV" + "ATE KEY-----\nabc\n-----END PRIV" + "ATE KEY-----\n"),  # joined: no tracked file may hold the marker
                    ("an empty file", "")):
    t, rc, so, se = pva([PK], assets={"provenance.bundle.json": OK}, key=text)
    check(rc != 0 and not calls(t), "F13 post-publish: %s is not a verified public key: nothing runs" % label, "rc=%s %s" % (rc, first(se)))
OTHER = PBF.replace("provenance.bundle.json", "other.bundle.json")
t, rc, so, se = pva([OTHER, PJ], assets={"provenance.bundle.json": OK, "other.bundle.json": OK}); check(rc != 0 and not calls(t) and "provenance.bundle.json" in se, "AC20 post-publish: a verify of a DIFFERENT file does not license the jq-only command: refused, nothing runs", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PBF, PJ], assets={"provenance.bundle.json": OK}, env={"COSIGN_FAIL_ON": "provenance.bundle.json"}); E = [l for l in se.split("\n") if l.startswith("::error::")]
check(rc != 0 and len(E) == 2 and "did not pass" in se, "AC20 post-publish: when the earlier verify failed the jq-only command is not run and fails the run (two ::error:: lines)", "rc=%s %s" % (rc, se[:300]))
for bad_cmd, what in (("jq -e '.ok == true'", "no file operand (it would read stdin)"), ("jq -e --slurpfile o other.json '.ok' provenance.bundle.json", "--slurpfile (reads another file)"),
                      ("jq -e -f prog.jq provenance.bundle.json", "-f (loads a program from a file)"), ("jq -e -L /tmp '.ok' provenance.bundle.json", "-L (a module directory)"),
                      ("jq -e '.ok' provenance.bundle.json other.json", "a second file that no earlier verify names"), ("jq -e '.ok' ../provenance.bundle.json", "a file spelled differently from the verify's"),
                      ("jq -n 1", "jq -n alone")):
    t, rc, so, se = pva([PBF, bad_cmd], assets={"provenance.bundle.json": OK, "other.json": OK}); check(rc != 0 and not calls(t), "AC20 post-publish: a jq-only command with %s is refused and nothing runs" % what, "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PBF, "jq -c '.ok' provenance.bundle.json | jq -e '. == true'"], assets={"provenance.bundle.json": OK}); check(rc == 0, "AC20 post-publish: a jq pipe whose first jq reads a verified file is accepted (the later jq reads the pipe)", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([]); check(rc == 0 and not calls(t), "AC20 post-publish: an empty list runs nothing and passes with the assets directory present")
# round 1 (both seats): the grammar is CLOSED, so none of these reads a file nothing verified
for bad_cmd, what in (("jq -ef unverified.jq provenance.bundle.json", "combined short options (-ef loads a program file)"), ("jq -er '.ok' provenance.bundle.json", "combined short options (-er)"),
                      ("jq -L. '.ok' provenance.bundle.json", "an attached module path (-L.)"), ("jq --run-tests unverified.jq provenance.bundle.json", "--run-tests"),
                      ("jq -e '.ok' -- -unverified.json provenance.bundle.json", "a -- before a dash-prefixed file"), ("jq --exit-status 'import \"other\" as $x {\"search\":\".\"}; $x::x[0].ok' provenance.bundle.json", "an import inside the filter"),
                      ("jq -e 'include \"other\"; .ok' provenance.bundle.json", "an include inside the filter"), ("jq -e 'input_filename' provenance.bundle.json", "input_filename (not an allowed builtin)"),
                      ("jq -e '$ENV.HOME' provenance.bundle.json", "$ENV"), ("jq -e 'env.HOME' provenance.bundle.json", "env"), ("jq -e '[inputs]' provenance.bundle.json", "inputs"),
                      ("jq -e 'debug' provenance.bundle.json", "debug"), ("jq -e '\"\\(.ok)\"' provenance.bundle.json", "a string interpolation"),
                      ("jq -e '.ok # c' provenance.bundle.json", "a comment"), ("jq -e '@sh \"x\"' provenance.bundle.json", "the @sh format"),
                      ("jq -e '.ok' provenance.*", "a glob in the file operand"), ("jq -e '.ok' provenance.bundle.js{on,}", "a brace in the file operand"),
                      ("jq -e '.ok' $HOME/provenance.bundle.json", "a $ in the file operand"), ("jq -e '.ok' ./provenance.bundle.json", "a ./ in the file operand"),
                      ("jq -e '.ok' sub/provenance.bundle.json", "a slash in the file operand"), ("jq -e '.ok' <TAG>.bundle.json", "a placeholder in the file operand"),
                      ("jq -e '.ok' PH_TAG.bundle.json", "a name spelled like the placeholder form"), ("jq -e --arg ref '.ok' provenance.bundle.json", "--arg with no value"),
                      ("jq -e '.ok' provenance.bundle.json | jq -ef x.jq", "a later pipe segment with a program file"),
                      ("jq -e '.ok' provenance.bundle.json > out.json", "a redirect"), ("jq -e '.ok' provenance.bundle.json; id", "a ; after it")):
    t, rc, so, se = pva([PBF, bad_cmd], assets={"provenance.bundle.json": OK, "unverified.jq": ".ok", "other.json": OK, "-unverified.json": OK}); check(rc != 0 and not calls(t), "AC20 round 1: %s is refused and nothing runs" % what, "rc=%s %s" % (rc, first(se)))
# a verify command's FLAG VALUES (an identity, an issuer, a type) never license a file; only a file flag's value and a positional do
VID = "cosign verify-blob --certificate-identity provenance.bundle.json --certificate-oidc-issuer " + ISS + " --bundle b.json x.txt"
t, rc, so, se = pva([VID, PJ], assets={"provenance.bundle.json": OK, "b.json": OK, "x.txt": "x"}); check(rc != 0 and not calls(t) and "earlier" in se, "AC20 round 1: a jq operand equal to a verify's --certificate-identity value is NOT licensed (refused, nothing runs)", "rc=%s %s" % (rc, first(se)))
VT = "cosign verify-blob-attestation --type provenance.bundle.json --bundle b.json --certificate-identity <IDENTITY> --certificate-oidc-issuer " + ISS
t, rc, so, se = pva([VT, PJ], assets={"provenance.bundle.json": OK, "b.json": OK}); check(rc != 0 and not calls(t), "AC20 round 1: a verify's --type value does not license a file", "rc=%s %s" % (rc, first(se)))
VP = "cosign verify-blob --certificate-identity <IDENTITY> --certificate-oidc-issuer " + ISS + " --bundle b.json provenance.bundle.json"
t, rc, so, se = pva([VP, PJ], assets={"provenance.bundle.json": OK, "b.json": OK}); check(rc == 0, "AC20 round 1: a verify's positional blob operand licenses the jq read of that file", "rc=%s %s" % (rc, first(se)))
VB = "cosign verify-blob --certificate-identity <IDENTITY> --certificate-oidc-issuer " + ISS + " --bundle=provenance.bundle.json x.txt"
t, rc, so, se = pva([VB, PJ], assets={"provenance.bundle.json": OK, "x.txt": "x"}); check(rc == 0, "AC20 round 1: a --bundle=FILE value licenses the file", "rc=%s %s" % (rc, first(se)))
VU = "cosign verify-blob --insecure-flag provenance.bundle.json x.txt"
t, rc, so, se = pva([VU, PJ], assets={"provenance.bundle.json": OK, "x.txt": "x"}); check(rc != 0 and not calls(t), "AC20 round 1: the word after an unknown flag is taken as its value and licenses nothing (fail closed)", "rc=%s %s" % (rc, first(se)))
# the page's own two jq commands (docs/verify-release.md section 3, cache#360) are in the grammar
J1 = "jq -e --arg ref '<IMAGE_REF>' '.dsseEnvelope.payload | @base64d | fromjson | .predicateType == \"https://slsa.dev/provenance/v1\" and any(.subject[]; .name == \"image-production\" and (.digest.sha256 as $d | $ref | endswith(\"@sha256:\" + $d)))' provenance.bundle.json"
J2 = "jq -r '.dsseEnvelope.payload | @base64d | fromjson | .subject[] | .name + \" sha256:\" + .digest.sha256' provenance.bundle.json"
PROV = json.dumps({"dsseEnvelope": {"payload": __import__("base64").b64encode(json.dumps({"predicateType": "https://slsa.dev/provenance/v1", "subject": [{"name": "image-production", "digest": {"sha256": DIG["image-production"].split(":")[1]}}, {"name": "image-fips", "digest": {"sha256": DIG["image-fips"].split(":")[1]}}]}).encode()).decode()}})
t, rc, so, se = pva([PBF, J1, J2], assets={"provenance.bundle.json": PROV}); check(rc == 0 and len(calls(t)) == 1, "AC20 round 1: the guide's two real jq commands are accepted and PASS on a provenance of the right shape (the image commands' placeholder is filled per registry)", "rc=%s %s" % (rc, se[:300]))
FIPSONLY = json.dumps({"dsseEnvelope": {"payload": __import__("base64").b64encode(json.dumps({"predicateType": "https://slsa.dev/provenance/v1", "subject": [{"name": "image-fips", "digest": {"sha256": DIG["image-production"].split(":")[1]}}]}).encode()).decode()}})
t, rc, so, se = pva([PBF, J1], assets={"provenance.bundle.json": FIPSONLY}); check(rc != 0 and "post-publish verification failed" in se, "AC20 round 1: the production digest check fails when the matching digest sits under another subject name", "rc=%s %s" % (rc, se[:200]))
# round 2 (seat B): the shell never sees a jq-only command, and a placeholder is never a file name
t, rc, so, se = pva([PBF, "jq -e --arg x {safe,--rawfile,hidden,other.json} '.ok' provenance.bundle.json"], assets={"provenance.bundle.json": OK, "other.json": '{"unverified":true}'})
check(rc == 0, "AC20 round 2: a brace in an --arg value is passed to jq as TEXT (no shell expands it into an extra option), and the command runs", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PBF, "jq -e --arg x '~' '.ok' provenance.bundle.json"], assets={"provenance.bundle.json": OK}); check(rc == 0, "AC20 round 2: a tilde in an --arg value is text, not a home directory", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PBF.replace("provenance.bundle.json", "<TAG>.bundle.json"), "jq -e '.ok' PH_TAG.bundle.json"], assets={"v0.3.0.bundle.json": '{"ok":false}', "PH_TAG.bundle.json": OK})
check(rc != 0 and not calls(t), "AC20 round 2: a verify of <TAG>.bundle.json does not license a jq read of a file literally named PH_TAG.bundle.json (refused, nothing runs)", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PBF.replace("provenance.bundle.json", "<TAG>.bundle.json"), "jq -e '.ok' v0.3.0.bundle.json"], assets={"v0.3.0.bundle.json": OK}); check(rc != 0 and not calls(t), "AC20 round 2: a verify of <TAG>.bundle.json does not license the substituted name either (fail closed)", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PBF, "jq -e --arg ref 'ghcr.io/x/y@sha256:" + "a" * 64 + "' '.ok' provenance.bundle.json"], assets={"provenance.bundle.json": OK}); check(rc == 0, "AC20 round 2: a repository-looking --arg VALUE to jq is text and is not refused as a repository literal (jq opens no network)", "rc=%s %s" % (rc, first(se)))
t, rc, so, se = pva([PBF, "jq -e 'any(.[]; endswith(\"@sha256:abc\"))' provenance.bundle.json"], assets={"provenance.bundle.json": '[{"a":1}]'}.copy() | {"provenance.bundle.json": '["x@sha256:abc"]'}); check(rc == 0, "AC20 round 2: @sha256: inside a jq filter string is not a repository operand", "rc=%s %s" % (rc, first(se)))
# an EMPTY list still requires the assets directory (nothing is skipped by listing nothing)
t, rc, so, se = pva([], nodir=True); check(rc != 0 and "release-published" in se, "AC20 round 1: an empty list with no release-published/ fails (the directory is required whatever the list holds)", "rc=%s %s" % (rc, first(se)))
# ---- the command judge answers as it did before the plain rewrite (owner rule 6, Oct 24) -------------------------
# The judge's five seams run over a fixed corpus (the guide's commands, each with one odd snippet put at every word
# edge and quote): the sha256 of all their answers, messages included, must not change. The hash was taken from the
# code of base commit 5916cbc4, before the rewrite.
src = open(os.path.join(BIN, "release-postverify.py")).read().rstrip()
src = src[:-len("main()")] if src.endswith("\nmain()") else src
judge = {"__name__": "judge"}
exec(compile(src, "release-postverify.py", "exec"), judge)
BASES = [PV1, PV2, PV3, PV4, PBF, PJ, J1, J2, VID, VT, VP, VB, VU, "jq -r --arg ref 'a b' '.a | .b' f.json",
         "jq -c '.ok' f.json | jq -e '. == true'", PBF + " | jq -e '.ok' x.json",
         "cosign verify-attestation --key k.pub <IMAGE_REF_FIPS>"]
SNIPS = ["`", "$", "$(id)", "${X}", "#", "\n", "\r", "\\", "\\$", "'", '"', ";", "&", "&&", ">", "<", "(", ")", "|",
         " | ", " || ", "ghcr.io/x/y", "docker.io/o/r@sha256:aa", "oci://ghcr.io/o/r", "<IMAGE_REF>", "<X>", "<tag>",
         "jq", "-e", "--arg a b", "--from-file", "-L.", "-f f", "/etc/passwd", "../x", "*", "{a,b}", "~", "@sh",
         "@base64d", "input", "env", "$ENV", "limit(1;.)", "\\(1)", "import", "$__loc__", "getpath", "''", '""', "-",
         "--", "x://y", "a.b/c", "PH_X", "\u2039X\u203a", ""]
def edges(c):
    spaces = {i + 1 for i, ch in enumerate(c) if ch == " "}
    quotes = {i for i, ch in enumerate(c) if ch in "'\"|"}
    return sorted({0, len(c)} | spaces | quotes)
CORPUS = BASES + [b[:i] + sn + b[i:] for b in BASES for sn in SNIPS for i in edges(b)]
def verdict(c):
    j = judge
    answers = (j["form_error"](c), j["form_error"](c, jq_only=True), j["all_jq"](c), j["jq_files"](c),
               sorted(j["verify_files"](c)))
    return repr(answers)
digest = hashlib.sha256("\n".join(verdict(c) for c in CORPUS).encode()).hexdigest()
check(digest == "d8c38764f45d912a00a98e1072c42f75685d0f4ce8e4ca15b97709ad1010ae0d",
      "owner rule 6: the judge answers the same on %d commands (form_error, all_jq, jq_files, verify_files)"
      % len(CORPUS), digest)
t, rc, so, se = pva([PBF, "jq -e '.ok \u00e9' provenance.bundle.json"], assets={"provenance.bundle.json": OK})
check(rc != 0 and not calls(t) and "Traceback" not in se and "closed grammar" in se,
      "owner rule 6: a letter outside ASCII in a jq filter is a refusal, not a crash", first(se))
# ---- AC10: no script prints a credential, anywhere ---------------------------------------------------------------------------------------------
for s, creds in (("release-verify", []), ("release-apks", KEY), ("release-publish", REG), ("release-sign", REG), ("release-assets", ["GH_TOKEN"]), ("release-postverify", ["GH_TOKEN"])):
    t = full_assets() if s == "release-assets" else tree(); rc, so, se = run(t, s, creds=creds)
    blob = so + se + tree_text(t)
    leaked = [k for k, v in SENT.items() if k != "DOCKERHUB_USERNAME" and v in blob]   # the user name is not a secret
    check(rc == 0 and not leaked, "AC10 %s with sentinels in the environment: none in any output or file afterwards" % s, "rc=%s leaked=%s %s" % (rc, leaked, first(se)))
print("pass=%d fail=%d" % (passn, failn))
EXPECT = int(os.environ.get("EXPECT_CASES", "401"))
if EXPECT and passn + failn != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (passn + failn, EXPECT)); sys.exit(1)
sys.exit(1 if failn else 0)
PY
