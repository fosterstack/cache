"""Test infrastructure (not product code): a throw-away repository tree with FAKE cache scripts and a FAKE chain-verify.py, used by
bin/chain-build-wiring-test.sh (and bin/chain-rebuild-test.sh) to RUN the four stage scripts bin/build-stage-KIND.sh and check what
they do. The fakes log their argv; every fake output is a pure function of its inputs, so an expected result can be computed here
independently of the implementation under test.

  mktree DIR KIND SCRIPT [ITEMS_MODE]   build DIR for the stage script KIND (apk|assemble|rebuild-apk|rebuild-assemble) with SCRIPT as bin/build-stage-KIND.sh.
                                        ITEMS_MODE oracle (default): the fake chain-verify.py computes items-apk / items-merge with the ORACLE below;
                                        real: it forwards them to the repository's REAL bin/chain-verify.py (env REAL_CV), so the implementation is
                                        judged against the oracle.
  expect DIR KIND FILE                  print the expected digests.json or items.json (FILE digests|items) for DIR, computed by the ORACLE from the
                                        files the fakes wrote, never from anything the implementation produced.

THE ORACLE IS THE ITEMS CONTRACT (PROPOSED/UNVERIFIED: no cache test fixes the layout of the apkindex / inputs-manifest / binary / SBOM
items; cache-3f's interface note fixes the apk digest, the index digest and the manifests):
  digests.json (Sign's only input; PR 1's schema, names [a-z0-9-]+, values sha256:<64 lower-case hex>):
      image-production, image-fips                       = out/<variant>.digest  (the OCI index digest, cache-3f UPDATE I4)
      apk-<standard|fips>-<amd64|arm64>                  = sha256: + sha256(the apk bytes)  (the fakes' `apk-tool.py digest` is that)
  items.json (Rebuild's comparison, bin/chain-rebuild-test.sh REQUIRED list), 25 items:
      apk-<v>-<x86_64|aarch64>, apkindex-<arch>, binary-<v>-<arch> (sha256 of the extracted binary), modules-sbom-<v>, inputs-manifest-<v>
      (taken from the x86_64 fragment; the aarch64 fragment must hold the same value), lock-<production|fips> (sha256 of out/<v>.full.lock.json),
      image-<variant> (out/<variant>.digest), image-<variant>-manifest-<amd64|arm64> (out/<variant>.manifests), sbom-<variant> (sha256 of the
      sbom file under out/<variant>-sbom/), archive-checksums (sha256 of the sorted `<sha256>  <relative path>` listing of the archive dir).
"""
import hashlib, json, os, shutil, stat, subprocess, sys

RUNNERS = [("ubuntu-24.04", "x86_64", "amd64"), ("ubuntu-24.04-arm", "aarch64", "arm64")]
VERSION = "0.3.0"
V2 = {"standard": "fscache-%s-r0.apk" % VERSION, "fips": "fscache-fips-%s-r0.apk" % VERSION}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def write(path, data, mode=None):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "wb" if isinstance(data, bytes) else "w").write(data)
    if mode: os.chmod(path, mode)


def apk_bytes(variant, arch, sde="1700000000"):
    return ("apk|%s|%s|%s" % (variant, arch, sde)).encode()


# ---- the oracle -----------------------------------------------------------------------------------------------------------------
def frag(outdir, arch):
    """items-apk: the items one native apk job contributes (names carry the architecture where the thing does)."""
    items = {}
    for v in ("standard", "fips"):
        apk = open("%s/%s/%s" % (outdir, arch, V2[v]), "rb").read()
        items["apk-%s-%s" % (v, arch)] = "sha256:" + sha(apk)
        items["binary-%s-%s" % (v, arch)] = "sha256:" + sha(b"BIN|" + V2[v].encode())
        sb = "fscache-modules.spdx.json" if v == "standard" else "fscache-modules-fips.spdx.json"
        im = "inputs-manifest.json" if v == "standard" else "inputs-manifest-fips.json"
        items["modules-sbom-" + v] = "sha256:" + sha(open("%s/%s" % (outdir, sb), "rb").read())
        items["inputs-manifest-" + v] = "sha256:" + sha(open("%s/%s" % (outdir, im), "rb").read())
    items["apkindex-" + arch] = "sha256:" + sha(open("%s/%s/APKINDEX.tar.gz" % (outdir, arch), "rb").read())
    return {"arch": arch, "items": items}


def merge(frags, images, archive):
    items = {}
    for f in frags:
        for k, v in f["items"].items():
            if k in items and items[k] != v:
                raise SystemExit("refused at build: digest: the architectures disagree on %s" % k)
            items[k] = v
    for v in ("production", "fips"):
        items["image-" + v] = open("%s/%s.digest" % (images, v)).read().strip()
        for line in open("%s/%s.manifests" % (images, v)).read().split("\n"):
            if line.strip():
                a, d = line.split()
                items["image-%s-manifest-%s" % (v, a)] = d
        items["lock-" + v] = "sha256:" + sha(open("%s/%s.full.lock.json" % (images, v), "rb").read())
        sbd = "%s/%s-sbom" % (images, v)
        items["sbom-" + v] = "sha256:" + sha(open("%s/%s" % (sbd, sorted(os.listdir(sbd))[0]), "rb").read())
    lst = []
    for root, _, files in os.walk(archive):
        for f in files:
            p = os.path.join(root, f); lst.append("%s  %s" % (sha(open(p, "rb").read()), os.path.relpath(p, archive)))
    items["archive-checksums"] = "sha256:" + sha("\n".join(sorted(lst)).encode())
    return items


def digests_from(frags, images):
    d = {}
    for v in ("production", "fips"):
        d["image-" + v] = open("%s/%s.digest" % (images, v)).read().strip()
    for f in frags:
        arch = {"x86_64": "amd64", "aarch64": "arm64"}[f["arch"]]
        for v in ("standard", "fips"):
            d["apk-%s-%s" % (v, arch)] = f["items"]["apk-%s-%s" % (v, f["arch"])]
    return d


# ---- the fakes ---------------------------------------------------------------------------------------------------------------------
FAKE_ADMIT = '''#!/usr/bin/env python3
import os, sys
open("calls.log", "a").write("admit\\n")
sys.exit(int(os.environ.get("FAKE_ADMIT_RC", "0")))
'''
FAKE_VERSION = '''#!/usr/bin/env python3
import os, sys
open("calls.log", "a").write("version " + " ".join(sys.argv[1:]) + "\\n")
sys.exit(int(os.environ.get("FAKE_VERSION_RC", "0")))
'''
FAKE_ARCHIVES = '''#!/usr/bin/env python3
import os, sys
open("calls.log", "a").write("archives " + " ".join(sys.argv[1:]) + "\\n")
os.makedirs("dist", exist_ok=True); open("dist/fscache.tar.gz", "w").write("dist")
'''
FAKE_APKTOOL = '''#!/usr/bin/env python3
import hashlib, sys, os
a = sys.argv[1:]
if a[0] == "digest":
    sys.stdout.write("sha256:" + hashlib.sha256(open(a[1], "rb").read()).hexdigest() + "\\n")
elif a[0] == "cat":
    sys.stdout.write("BIN|" + os.path.basename(a[1]))
'''
FAKE_BUILD_APK = '''#!/usr/bin/env bash
if [ "${1:-}" = --print-source-date-epoch ]; then
  [ "${FAKE_SDE_RC:-0}" = 0 ] || exit "$FAKE_SDE_RC"
  echo 1700000000; exit 0
fi
echo "apk $* SDE=${SOURCE_DATE_EPOCH:-unset}" >> calls.log
env | sort > "env-apk.txt"
var=standard; arch=x86_64; out=out; ver=0.3.0
while [ $# -gt 0 ]; do case "$1" in --variant) var=$2;; --arch) arch=$2;; --out) out=$2;; --version) ver=$2;; esac; shift; done
[ "${FAKE_APK_RC:-0}" = 0 ] || exit "$FAKE_APK_RC"
mkdir -p "$out/$arch"
if [ "$var" = fips ]; then n="fscache-fips-$ver-r0.apk"; sb=fscache-modules-fips.spdx.json; im=inputs-manifest-fips.json; else n="fscache-$ver-r0.apk"; sb=fscache-modules.spdx.json; im=inputs-manifest.json; fi
printf 'apk|%s|%s|%s' "$var" "$arch" "${SOURCE_DATE_EPOCH:-unset}" > "$out/$arch/$n"
printf 'idx|%s' "$arch" > "$out/$arch/APKINDEX.tar.gz"
printf 'sbom|%s' "$var" > "$out/$sb"; printf 'inputs|%s' "$var" > "$out/$im"
'''
FAKE_ASSEMBLE = '''#!/usr/bin/env bash
echo "image $* SDE=${SOURCE_DATE_EPOCH:-unset}" >> calls.log
var=production; out=out; mr=; kr=
while [ $# -gt 0 ]; do case "$1" in --variant) var=$2;; --out) out=$2;; --melange-repo) mr=$2;; --keyring-dir) kr=$2;; esac; shift; done
[ -d "$mr/x86_64" ] && [ -d "$mr/aarch64" ] && [ -f "$kr/wolfi-signing.rsa.pub" ] && [ -f "$kr/assembly.rsa.pub" ] || { echo "refusal: repo or keyring incomplete" >&2; exit 2; }
[ "${FAKE_IMAGE_RC:-0}" = 0 ] || exit "$FAKE_IMAGE_RC"
mkdir -p "$out/$var-sbom"
d=$(printf '%s' "image-$var" | shasum -a 256 | cut -d' ' -f1)
echo "sha256:$d" > "$out/$var.digest"
printf 'amd64 sha256:%s\\narm64 sha256:%s\\n' "$(printf '%s' "m-amd64-$var" | shasum -a 256 | cut -d' ' -f1)" "$(printf '%s' "m-arm64-$var" | shasum -a 256 | cut -d' ' -f1)" > "$out/$var.manifests"
printf 'tar|%s' "$var" > "$out/$var.tar"; printf 'lock|%s' "$var" > "$out/$var.full.lock.json"; printf 'sbom|%s' "$var" > "$out/$var-sbom/sbom.json"
'''
FAKE_CV = '''#!/usr/bin/env python3
import hashlib, json, os, subprocess, sys
sys.path.insert(0, os.environ["HARNESS_DIR"])
import importlib.util
spec = importlib.util.spec_from_file_location("h", os.environ["HARNESS_DIR"] + "/chain-test-harness.py"); h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
a = sys.argv[1:]
open("calls.log", "a").write("verify " + " ".join(a) + "\\n")
def arg(n): return a[a.index(n) + 1]
rc = int(os.environ.get("FAKE_VERIFY_RC", "0"))
c = a[0]
if c == "policy":
    open("policy.json", "w").write("{}"); sys.exit(0)
if c in ("verify", "stage-start"):
    sys.stderr.write("refused at %s: identity (fake)\\n" % (a[a.index("--stage") + 1] if "--stage" in a else "build")) if rc else None
    sys.exit(rc)
if c == "bind":
    f, n = arg("--file"), arg("--as")
    want = open(".bind/" + f.replace("/", "_")).read().strip()
    if want != hashlib.sha256(open(f, "rb").read()).hexdigest():
        sys.stderr.write("refused at build: digest: %s is not the product the record holds\\n" % n); sys.exit(1)
    sys.exit(0)
if c in ("items-apk", "items-merge") and os.environ.get("ITEMS_MODE") == "real":
    os.execv(sys.executable, [sys.executable, os.environ["REAL_CV"]] + a)
if c == "items-apk":
    json.dump(h.frag(arg("--out-dir"), arg("--arch")), open(arg("--result"), "w"))
    sys.exit(0)
if c == "items-merge":
    frs = [json.load(open(a[i + 1])) for i, x in enumerate(a) if x == "--fragment"]
    items = h.merge(frs, arg("--images"), arg("--archive"))
    json.dump(items, open(arg("--items"), "w"), sort_keys=True, indent=1)
    if "--digests" in a: json.dump(h.digests_from(frs, arg("--images")), open(arg("--digests"), "w"), sort_keys=True, indent=1)
    sys.exit(0)
if c == "rebuild-compare":
    os.makedirs(os.path.dirname(arg("--out")) or ".", exist_ok=True)
    e, x = json.load(open(arg("--expected"))), json.load(open(arg("--actual")))
    diff = sorted(k for k in set(e) | set(x) if e.get(k) != x.get(k))
    json.dump({"equal": not diff, "differs": diff}, open(arg("--out"), "w"))
    if diff: sys.stderr.write("refused at rebuild: differs: %s\\n" % " ".join(diff)); sys.exit(1)
    sys.exit(0)
sys.exit(2)
'''


def images(out):
    """A mirror of the fake assemble-image.sh outputs (the oracle needs them before the script has run, for Rebuild's expected items)."""
    for v in ("production", "fips"):
        write("%s/%s.digest" % (out, v), "sha256:" + sha(("image-" + v).encode()) + "\n")
        write("%s/%s.manifests" % (out, v), "amd64 sha256:%s\narm64 sha256:%s\n" % (sha(("m-amd64-" + v).encode()), sha(("m-arm64-" + v).encode())))
        write("%s/%s.full.lock.json" % (out, v), "lock|" + v)
        write("%s/%s-sbom/sbom.json" % (out, v), "sbom|" + v)


def mktree(d, kind, script, mode="oracle"):
    shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    here = os.path.dirname(os.path.abspath(__file__))
    for name, body in (("build-admit.py", FAKE_ADMIT), ("build-version-check.py", FAKE_VERSION), ("build-archives.py", FAKE_ARCHIVES),
                       ("apk-tool.py", FAKE_APKTOOL), ("build-apk.sh", FAKE_BUILD_APK), ("assemble-image.sh", FAKE_ASSEMBLE),
                       ("chain-verify.py", FAKE_CV)):
        write(d + "/bin/" + name, body, 0o755)
    shutil.copy(script, d + "/bin/build-stage-%s.sh" % kind); os.chmod(d + "/bin/build-stage-%s.sh" % kind, 0o755)
    # the archive, the keys, the policy template
    for f, c in (("archive/keys/wolfi-signing.rsa.pub", "w"), ("archive/go/go.tar.gz", "g"), ("archive/x86_64/pkg-1.apk", "p1"), ("archive/aarch64/pkg-1.apk", "p2"),
                 ("build/keys/assembly.rsa.pub", "a"), ("build/locks/melange.lock", "l"), (".github/policy/release-policy.template.json", "{}")):
        write(d + "/" + f, c)
    kinds_asm = kind in ("assemble", "rebuild-assemble")
    pre = "apk-in" if kind == "assemble" else "rapk-in"
    rpre = "witness-apk-in" if kind == "assemble" else "witness-rapk-in"
    rec = "apk-collection.json" if kind == "assemble" else "rapk-collection.json"
    if kinds_asm:
        for r, arch, _ in RUNNERS:
            src = "%s/_src/%s/out" % (d, r)
            for v in ("standard", "fips"):
                write("%s/%s/%s" % (src, arch, V2[v]), apk_bytes(v, arch))
                write("%s/fscache-modules%s.spdx.json" % (src, "" if v == "standard" else "-fips"), "sbom|" + v)
                write("%s/inputs-manifest%s.json" % (src, "" if v == "standard" else "-fips"), "inputs|" + v)
            write("%s/%s/APKINDEX.tar.gz" % (src, arch), "idx|" + arch)
            fr = frag(src, arch)
            for v in ("standard", "fips"):
                for fn in (V2[v], ):
                    write("%s/%s/%s/%s" % (d, pre, r, "%s/%s" % (arch, fn)), open("%s/%s/%s" % (src, arch, fn), "rb").read())
            write("%s/%s/%s/%s/APKINDEX.tar.gz" % (d, pre, r, arch), open("%s/%s/APKINDEX.tar.gz" % (src, arch), "rb").read())
            json.dump(fr, open("%s/%s/%s/items-apk.json" % (d, pre, r), "w"))
            write("%s/%s/%s/%s" % (d, rpre, r, rec), "{}")
            # what each record "holds": the sha256 of every file the stage binds to it (bind is keyed by the file path)
            for rel in ("%s/%s" % (arch, V2["standard"]), "%s/%s" % (arch, V2["fips"]), "%s/APKINDEX.tar.gz" % arch, "items-apk.json"):
                p_ = "%s/%s/%s" % (pre, r, rel)
                write("%s/.bind/%s" % (d, p_.replace("/", "_")), sha(open("%s/%s" % (d, p_), "rb").read()))
        shutil.rmtree(d + "/_src")
    if kind in ("rebuild-apk", "rebuild-assemble"):
        write(d + "/witness-build/build-collection.json", "{}")
        write(d + "/build-in/digests.json", "{}")
        write(d + "/build-in/items.json", "{}")
    if kind == "rebuild-assemble":
        images(d + "/_exp")
        frs = [json.load(open("%s/%s/%s/items-apk.json" % (d, pre, r))) for r, a, _ in RUNNERS]
        json.dump(merge(frs, d + "/_exp", d + "/archive"), open(d + "/build-in/items.json", "w"), sort_keys=True, indent=1)
        shutil.rmtree(d + "/_exp")
    write(d + "/calls.log", "")
    # the fake chain-verify.py reads its expectations for bind by the --as name of the RUNNER's file; give it a resolver for both
    write(d + "/.mode", mode)
    return d


def expect(d, kind, which):
    pre = "apk-in" if kind == "assemble" else "rapk-in"
    frs = [json.load(open("%s/%s/%s/items-apk.json" % (d, pre, r))) for r, a, _ in RUNNERS]
    if which == "digests":
        return digests_from(frs, d + "/out")
    return merge(frs, d + "/out", d + "/archive")


if __name__ == "__main__":
    c = sys.argv[1]
    if c == "mktree":
        mktree(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) > 5 else "oracle")
    elif c == "expect":
        print(json.dumps(expect(sys.argv[2], sys.argv[3], sys.argv[4]), sort_keys=True))
