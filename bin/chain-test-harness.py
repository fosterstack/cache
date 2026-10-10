"""Test infrastructure (not product code): a throw-away repository tree with FAKE cache scripts and a FAKE chain-verify.py, so
bin/chain-build-wiring-test.sh can RUN the four stage scripts bin/build-stage-KIND.sh and check what they do. The fakes log their argv.
The expected results are computed here by the ORACLE, from the inputs of the tree, never from anything the implementation wrote.

  python3 chain-test-harness.py mktree DIR KIND SCRIPT [MODE [TAG]]     MODE oracle (default) | real (items-apk and items-merge go to the
                                                                        repository's REAL bin/chain-verify.py, env REAL_CV); TAG v0.3.0 | v0.3.0-rc.1
  python3 chain-test-harness.py expect DIR KIND digests|items [TAG]     the oracle's digests.json / items.json for that tree
  python3 chain-test-harness.py fragment ARCH TAG | apkname VARIANT TAG   the oracle's items-apk fragment; the apk file name (PROPOSED, cache-3f)

THE FAKE APK (PROPOSED/UNVERIFIED, cache is still changing which sections `apk-tool.py digest` covers): a text file whose first line is the
SIGNATURE (`SIG:<key>`) and whose rest is the control and data sections. `apk-tool.py digest` is sha256 of the rest, so it differs from the
whole-file sha256 and ignores the signature (the same apk re-signed with another key has the same digest; one changed byte elsewhere changes it).
THE VERSION (PROPOSED/UNVERIFIED, cache-3f): the stage passes --version = the tag minus the leading v (0.3.0, or 0.3.0-rc.1); the cache driver
accepts X.Y.Z and X.Y.Z-rc.N and names the apk fscache-0.3.0-r0.apk (final) or fscache-0.3.0_rc1-r0.apk (rc); the fips apk is fscache-fips-....
THE ITEMS (PROPOSED/UNVERIFIED layout; cache-3f's note fixes the apk digest, the image index digest and the manifests):
  digests.json (Sign's only input, PR 1's schema): image-production, image-fips, apk-<standard|fips>-<amd64|arm64>, and the four Linux archives
      archive-linux-<amd64|arm64>, archive-fips-linux-<amd64|arm64> (the goreleaser names fscache_<ver>_linux_<arch>.tar.gz, fscache-fips_...).
  items.json (Rebuild's comparison, bin/chain-rebuild-test.sh REQUIRED): those archives and the apks (named by x86_64|aarch64), apkindex-<arch>,
      binary-<variant>-<arch> (sha256 of `apk-tool.py cat APK usr/bin/fscache`), modules-sbom-<variant>, inputs-manifest-<variant>, lock-<image>, image-<image>,
      image-<image>-manifest-<amd64|arm64>,
      sbom-<image>, archive-checksums.
"""
import hashlib, json, os, re, shutil, sys

RUNNERS = [("ubuntu-24.04", "x86_64", "amd64"), ("ubuntu-24.04-arm", "aarch64", "arm64")]
SDE = "1700000000"
IMAGES = ("production", "fips")
VARIANT_OF = {"production": "standard", "fips": "fips"}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def pkgver(tag):
    """PROPOSED (cache-3f): 0.3.0 for v0.3.0, 0.3.0_rc1 for v0.3.0-rc.1."""
    return re.sub(r"-rc\.(\d+)$", r"_rc\1", tag[1:])


def apk_name(variant, tag):
    return ("fscache-%s-r0.apk" if variant == "standard" else "fscache-fips-%s-r0.apk") % pkgver(tag)


def apk_bytes(variant, arch, tag, key="assembly"):
    return ("SIG:%s\napk|%s|%s|%s|%s" % (key, variant, arch, SDE, pkgver(tag))).encode()


def apk_digest(b):
    return "sha256:" + sha(b.split(b"\n", 1)[1])        # the signature line is not part of the digest


def apk_binary(b):
    """What `apk-tool.py cat APK usr/bin/fscache` prints: bytes derived from the apk's content, never from its signature line."""
    return b"BIN\n" + b.split(b"\n", 1)[1]


def write(path, data, mode=None):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "wb" if isinstance(data, bytes) else "w").write(data)
    if mode: os.chmod(path, mode)


# ---- the oracle -------------------------------------------------------------------------------------------------------------------
def out_files(arch, tag):
    """What one native apk job leaves in out/: {path under out: bytes}."""
    f = {"%s/APKINDEX.tar.gz" % arch: ("idx|" + arch).encode(), "items-apk.json": b""}
    for v in ("standard", "fips"):
        f["%s/%s" % (arch, apk_name(v, tag))] = apk_bytes(v, arch, tag)
        s = "" if v == "standard" else "-fips"
        f["fscache-modules%s.spdx.json" % s] = ("sbom|" + v).encode()
        f["inputs-manifest%s.json" % s] = ("inputs|" + v).encode()
    return f


def fragment(arch, tag):
    items = {}
    for v in ("standard", "fips"):
        items["apk-%s-%s" % (v, arch)] = apk_digest(apk_bytes(v, arch, tag))
        items["binary-%s-%s" % (v, arch)] = "sha256:" + sha(apk_binary(apk_bytes(v, arch, tag)))
        items["modules-sbom-" + v] = "sha256:" + sha(("sbom|" + v).encode())
        items["inputs-manifest-" + v] = "sha256:" + sha(("inputs|" + v).encode())
    items["apkindex-" + arch] = "sha256:" + sha(("idx|" + arch).encode())
    return {"arch": arch, "items": items}


def image_outputs(image, tag):
    """What assemble-image.sh writes for an image: a pure function of the apks it was given (both architectures) and the build date."""
    body = "|".join(apk_bytes(VARIANT_OF[image], a, tag).decode().split("\n", 1)[1] for _, a, _ in RUNNERS)
    digest = "sha256:" + sha(("image|%s|%s|%s" % (image, SDE, body)).encode())
    manifests = ["%s sha256:%s" % (g, sha(("m-%s|%s|%s" % (g, image, body)).encode())) for _, _, g in RUNNERS]
    return {"digest": digest, "manifests": manifests, "lock": ("lock|" + image).encode(), "sbom": ("sbom|" + image).encode()}


def archive_files(tag):
    """{item name: (file name in dist, bytes)} for the four Linux archives (goreleaser's names; --version is the tag minus v)."""
    ver, out = tag[1:], {}
    for _, _, g in RUNNERS:
        out["archive-linux-" + g] = ("fscache_%s_linux_%s.tar.gz" % (ver, g), ("tar|std|%s|%s" % (g, ver)).encode())
        out["archive-fips-linux-" + g] = ("fscache-fips_%s_linux_%s.tar.gz" % (ver, g), ("tar|fips|%s|%s" % (g, ver)).encode())
    return out


def merge(frags, images, archives, archive_dir):
    """The items.json an honest items-merge writes. images: {image: image_outputs}; archives: {item: bytes}."""
    items = {}
    for f in frags:
        for k, v in f["items"].items():
            if k in items and items[k] != v:
                raise SystemExit("refused at build: digest: %s" % k)
            items[k] = v
    for image, o in images.items():
        items["image-" + image] = o["digest"]
        for line in o["manifests"]:
            g, d = line.split()
            items["image-%s-manifest-%s" % (image, g)] = d
        items["lock-" + image] = "sha256:" + sha(o["lock"])
        items["sbom-" + image] = "sha256:" + sha(o["sbom"])
    for k, b in archives.items():
        items[k] = "sha256:" + sha(b)
    listing = []
    for root, _, files in os.walk(archive_dir):
        for f in files:
            p = os.path.join(root, f); listing.append("%s  %s" % (sha(open(p, "rb").read()), os.path.relpath(p, archive_dir)))
    items["archive-checksums"] = "sha256:" + sha("\n".join(sorted(listing)).encode())
    return items


def digests_of(items):
    """digests.json: the images, the apks (named by amd64/arm64) and the archives; each equal to the same item of items.json."""
    d = {k: v for k, v in items.items() if k in ("image-production", "image-fips") or k.startswith(("archive-linux", "archive-fips-linux"))}
    for v in ("standard", "fips"):
        for _, a, g in RUNNERS:
            d["apk-%s-%s" % (v, g)] = items["apk-%s-%s" % (v, a)]
    return d


def expected(d, kind, which, tag):
    pre = "apk" if kind in ("assemble", "snapshot-assemble") else "rapk"
    frags = [json.load(open("%s/%s/%s/items-apk.json" % (d, pre, r))) for r, _, _ in RUNNERS]
    items = merge(frags, {i: image_outputs(i, tag) for i in IMAGES}, {k: b for k, (_, b) in archive_files(tag).items()}, d + "/archive")
    return digests_of(items) if which == "digests" else items


# ---- the fakes: what the real cache scripts and chain-verify.py would do, reduced to what a stage script can observe ----------------
FAKE_ADMIT = '''#!/usr/bin/env python3
import os, subprocess, sys
open("calls.log", "a").write("admit gh=%s\\n" % ("yes" if os.environ.get("GH_TOKEN") else "no"))
subprocess.run(["gh", "api", "repos/fosterstack/cache/commits/0123/check-runs"])      # the admission reads (GET only); the fake gh logs the call to gh.log
sys.exit(int(os.environ.get("FAKE_ADMIT_RC", "0")))
'''
FAKE_GH = '''#!/usr/bin/env bash
echo "gh $*" >> gh.log
'''
FAKE_VERSION_CHECK = '''#!/usr/bin/env python3
import glob, os, sys
a = sys.argv[1:]
d, v = a[a.index("--apk-dir") + 1], a[a.index("--variant") + 1]
pattern = "fscache-fips-*-r0.apk" if v == "fips" else "fscache-[0-9]*-r0.apk"
found = sorted(os.path.basename(p) for p in glob.glob(os.path.join(d, pattern)))
open("calls.log", "a").write("version %s %s\\n" % (v, ",".join(found)))
sys.exit(int(os.environ.get("FAKE_VERSION_RC", "0")) or (0 if len(found) == 1 else 1))
'''
FAKE_GIT = '''#!/usr/bin/env bash
echo "git $*" >> calls.log
case "${1:-} ${2:-}" in
  "tag --points-at") [ -z "${FAKE_TAGS_AT_HEAD:-}" ] || printf '%s\\n' $FAKE_TAGS_AT_HEAD ;;
  "tag --force") ;;
  *) echo "fake git: not expected: $*" >&2; exit 2 ;;
esac
'''
FAKE_APKTOOL = '''#!/usr/bin/env python3
import hashlib, sys
a = sys.argv[1:]
body = open(a[1], "rb").read().split(b"\\n", 1)[1]
if a[0] == "digest":
    sys.stdout.write("sha256:" + hashlib.sha256(body).hexdigest() + "\\n")
elif a[0] == "cat" and a[2] == "usr/bin/fscache":
    sys.stdout.buffer.write(b"BIN\\n" + body)
'''
FAKE_BUILD_APK = '''#!/usr/bin/env bash
if [ "${1:-}" = --print-source-date-epoch ]; then
  [ "${FAKE_SDE_RC:-0}" = 0 ] || exit "$FAKE_SDE_RC"
  echo 1700000000; exit 0
fi
echo "apk $* SDE=${SOURCE_DATE_EPOCH:-unset}" >> calls.log
env | sort > env-apk.txt
# cache's driver refuses the release signing key and --signing-key (rule 23, exit 2 [F]): Build never holds it
[ -z "${APK_RELEASE_SIGNING_KEY:-}" ] || { echo "refusal: APK_RELEASE_SIGNING_KEY" >&2; exit 2; }
case " $* " in *" --signing-key "*) echo "refusal: --signing-key" >&2; exit 2;; esac
variant=standard; arch=x86_64; out=out; version=0.3.0
while [ $# -gt 0 ]; do
  case "$1" in --variant) variant=$2;; --arch) arch=$2;; --out) out=$2;; --version) version=$2;; esac
  shift
done
# cache's driver accepts X.Y.Z and X.Y.Z-rc.N only (PROPOSED, cache-3f); the apk package version maps -rc.N to _rcN
[[ "$version" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+(-rc\\.[0-9]+)?$ ]] || { echo "refusal: version $version" >&2; exit 2; }
[ "${FAKE_APK_RC:-0}" = 0 ] || exit "$FAKE_APK_RC"
pk=$(printf '%s' "$version" | sed -E 's/-rc\\.([0-9]+)$/_rc\\1/')
mkdir -p "$out/$arch"
if [ "$variant" = fips ]; then name="fscache-fips-$pk-r0.apk"; suffix=-fips; else name="fscache-$pk-r0.apk"; suffix=; fi
printf 'SIG:assembly\\napk|%s|%s|%s|%s' "$variant" "$arch" "${SOURCE_DATE_EPOCH:-unset}" "$pk" > "$out/$arch/$name"
printf 'idx|%s' "$arch" > "$out/$arch/APKINDEX.tar.gz"
printf 'sbom|%s' "$variant" > "$out/fscache-modules$suffix.spdx.json"
printf 'inputs|%s' "$variant" > "$out/inputs-manifest$suffix.json"
'''
FAKE_ASSEMBLE = '''#!/usr/bin/env python3
import glob, hashlib, os, sys
a = sys.argv[1:]
open("calls.log", "a").write("image %s SDE=%s\\n" % (" ".join(a), os.environ.get("SOURCE_DATE_EPOCH", "unset")))
def arg(n): return a[a.index(n) + 1]
image, out, repo, keys = arg("--variant"), arg("--out"), arg("--melange-repo"), arg("--keyring-dir")
if not (os.path.isdir(repo + "/x86_64") and os.path.isdir(repo + "/aarch64")
        and os.path.isfile(keys + "/wolfi-signing.rsa.pub") and os.path.isfile(keys + "/assembly.rsa.pub")):
    sys.stderr.write("refusal: repo or keyring incomplete\\n"); sys.exit(2)
if os.environ.get("FAKE_IMAGE_RC", "0") != "0": sys.exit(int(os.environ["FAKE_IMAGE_RC"]))
pattern = "fscache-fips-*-r0.apk" if image == "fips" else "fscache-[0-9]*-r0.apk"
body = "|".join(open(p).read().split("\\n", 1)[1] for arch in ("x86_64", "aarch64") for p in sorted(glob.glob("%s/%s/%s" % (repo, arch, pattern))))
sde = os.environ.get("SOURCE_DATE_EPOCH", "unset")
h = lambda s: hashlib.sha256(s.encode()).hexdigest()
os.makedirs(out + "/" + image + "-sbom", exist_ok=True)
open("%s/%s.digest" % (out, image), "w").write("sha256:%s\\n" % h("image|%s|%s|%s" % (image, sde, body)))
open("%s/%s.manifests" % (out, image), "w").write("amd64 sha256:%s\\narm64 sha256:%s\\n"
        % (h("m-amd64|%s|%s" % (image, body)), h("m-arm64|%s|%s" % (image, body))))
open("%s/%s.tar" % (out, image), "w").write("tar|" + image)
open("%s/%s.full.lock.json" % (out, image), "w").write("lock|" + image)
open("%s/%s-sbom/sbom.json" % (out, image), "w").write("sbom|" + image)
'''
FAKE_ARCHIVES = '''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
version, out = a[a.index("--version") + 1], a[a.index("--out") + 1]
open("calls.log", "a").write("archives %s SDE=%s\\n" % (" ".join(a), os.environ.get("SOURCE_DATE_EPOCH", "unset")))
os.makedirs(out, exist_ok=True)
for std, name in (("std", "fscache"), ("fips", "fscache-fips")):
    for g in ("amd64", "arm64"):
        open("%s/%s_%s_linux_%s.tar.gz" % (out, name, version, g), "w").write("tar|%s|%s|%s" % (std, g, version))
'''
FAKE_CV = '''#!/usr/bin/env python3
import hashlib, importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("h", os.environ["HARNESS_DIR"] + "/chain-test-harness.py")
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
a = sys.argv[1:]
open("calls.log", "a").write("verify " + " ".join(a) + "\\n")
def arg(n): return a[a.index(n) + 1]
rc, cmd = int(os.environ.get("FAKE_VERIFY_RC", "0")), a[0]
if cmd == "policy":
    open("policy.json", "w").write("{}"); sys.exit(0)
if cmd in ("verify", "stage-start"):
    if rc: sys.stderr.write("refused at build: identity (fake)\\n")
    sys.exit(rc)
if cmd == "bind":       # every file under --dir must be a product of the record: the harness wrote the table .bind/<path with / as _>
    bad = []
    for root, _, files in os.walk(arg("--dir")):
        for f in files:
            p = os.path.join(root, f); table = ".bind/" + p.replace("/", "_")
            if not os.path.exists(table) or open(table).read().strip() != hashlib.sha256(open(p, "rb").read()).hexdigest(): bad.append(p)
    if bad: sys.stderr.write("refused at build: digest: %s\\n" % " ".join(bad)); sys.exit(1)
    sys.exit(0)
if cmd in ("items-apk", "items-merge") and os.environ.get("ITEMS_MODE") == "real":
    os.execv(sys.executable, [sys.executable, os.environ["REAL_CV"]] + a)
if cmd == "items-apk":
    json.dump(h.fragment(os.path.basename(arg("--out-dir").rstrip("/")), os.environ["TAG"]), open(arg("--result"), "w"))
    sys.exit(0)
if cmd == "items-merge":
    frags = [json.load(open(a[i + 1])) for i, x in enumerate(a) if x == "--fragment"]
    img, tag = arg("--images"), "v" + arg("--version")
    images = {i: {"digest": open("%s/%s.digest" % (img, i)).read().strip(),
                  "manifests": [l for l in open("%s/%s.manifests" % (img, i)).read().split("\\n") if l.strip()],
                  "lock": open("%s/%s.full.lock.json" % (img, i), "rb").read(), "sbom": open("%s/%s-sbom/sbom.json" % (img, i), "rb").read()} for i in h.IMAGES}
    archives = {k: open("%s/%s" % (arg("--archives"), n), "rb").read() for k, (n, _) in h.archive_files(tag).items()}
    items = h.merge(frags, images, archives, arg("--archive"))
    json.dump(items, open(arg("--items"), "w"), sort_keys=True, indent=1)
    if "--digests" in a: json.dump(h.digests_of(items), open(arg("--digests"), "w"), sort_keys=True, indent=1)
    sys.exit(0)
if cmd == "rebuild-compare":
    os.makedirs(os.path.dirname(arg("--out")) or ".", exist_ok=True)
    expected, actual = json.load(open(arg("--expected"))), json.load(open(arg("--actual")))
    def status(k):
        if k not in expected: return "unexpected"
        if k not in actual: return "missing-actual"
        return "same" if expected[k] == actual[k] else "differs"
    items = [{"name": k, "expected": expected.get(k), "actual": actual.get(k), "status": status(k)} for k in sorted(set(expected) | set(actual))]
    differ = [i["name"] for i in items if i["status"] != "same"]
    if "--snapshot" in a:         # the agreed snapshot verdict: verdict, the two image index digests, every differing item
        row = {i["name"]: i for i in items}
        images = [{"image": n, "build_digest": row["image-" + n]["expected"], "rebuild_digest": row["image-" + n]["actual"],
                   "equal": row["image-" + n]["status"] == "same"} for n in ("production", "fips")]
        json.dump({"verdict": "differs" if differ else "identical", "images": images, "items_differing": differ}, open(arg("--out"), "w"))
    else:
        json.dump({"equal": not differ, "items": items}, open(arg("--out"), "w"))     # the CLI contract of bin/chain-rebuild-test.sh
    if differ: sys.stderr.write("refused at rebuild: differs: %s\\n" % " ".join(differ)); sys.exit(1)
    sys.exit(0)
sys.exit(2)
'''


def mktree(d, kind, script, mode="oracle", tag="v0.3.0"):
    shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    for name, body in (("build-admit.py", FAKE_ADMIT), ("build-version-check.py", FAKE_VERSION_CHECK), ("build-archives.py", FAKE_ARCHIVES),
                       ("apk-tool.py", FAKE_APKTOOL), ("git", FAKE_GIT), ("gh", FAKE_GH), ("build-apk.sh", FAKE_BUILD_APK),
                       ("assemble-image.sh", FAKE_ASSEMBLE), ("chain-verify.py", FAKE_CV)):
        write(d + "/bin/" + name, body, 0o755)
    shutil.copy(script, d + "/bin/build-stage-%s.sh" % kind); os.chmod(d + "/bin/build-stage-%s.sh" % kind, 0o755)
    for f, c in (("archive/keys/wolfi-signing.rsa.pub", "w"), ("archive/go/go.tar.gz", "g"),
                 ("archive/x86_64/pkg-1.apk", "p1"), ("archive/aarch64/pkg-1.apk", "p2"),
                 ("build/keys/assembly.rsa.pub", "a"), ("build/locks/melange.lock", "l"), (".github/policy/release-policy.template.json", "{}")):
        write(d + "/" + f, c)
    pre, rec, step = ("apk", "rec-apk", "apk") if kind == "assemble" else ("rapk", "rec-rapk", "rapk")
    if kind == "snapshot-assemble":
        pre, rec, step = "apk", "rec-apk", "snapshot-apk"      # a snapshot record is named snapshot-apk and sits next to the same artifacts
    if kind == "snapshot-rebuild-assemble":
        pre, rec, step = "rapk", "rec-rapk", "snapshot-rapk"
    if kind in ("assemble", "rebuild-assemble", "snapshot-assemble", "snapshot-rebuild-assemble"):
        for r, arch, _ in RUNNERS:                   # the downloaded artifacts, laid out as upload-artifact rooted at `out` lays them out
            files = out_files(arch, tag)
            files["items-apk.json"] = json.dumps(fragment(arch, tag)).encode()
            for rel, b in files.items():
                write("%s/%s/%s/%s" % (d, pre, r, rel), b)
                write("%s/.bind/%s" % (d, ("%s/%s/%s" % (pre, r, rel)).replace("/", "_")), sha(b))
            write("%s/%s/%s/%s-collection.json" % (d, rec, r, step), "{}")
    if kind in ("rebuild-apk", "rebuild-assemble"):
        write(d + "/witness-build/build-collection.json", "{}")
        write(d + "/build-in/digests.json", "{}")
    if kind in ("snapshot-rebuild-apk", "snapshot-rebuild-assemble"):
        write(d + "/witness-build/snapshot-build-collection.json", "{}")
        write(d + "/build-in/digests.json", "{}")
    if kind in ("rebuild-assemble", "snapshot-rebuild-assemble"):
        write(d + "/build-in/items.json", json.dumps(expected(d, kind, "items", tag), sort_keys=True, indent=1))
    write(d + "/calls.log", "")
    return d


if __name__ == "__main__":
    c = sys.argv[1]
    if c == "mktree":
        mktree(sys.argv[2], sys.argv[3], sys.argv[4], *sys.argv[5:7])
    elif c == "fragment":                                       # fragment ARCH TAG: the oracle's items-apk fragment
        print(json.dumps(fragment(sys.argv[2], sys.argv[3]), sort_keys=True))
    elif c == "apkname":                                        # apkname VARIANT TAG: standard|fips, v0.3.0|v0.3.0-rc.1
        print(apk_name(sys.argv[2], sys.argv[3]))
    elif c == "expect":
        print(json.dumps(expected(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) > 5 else "v0.3.0"), sort_keys=True))
