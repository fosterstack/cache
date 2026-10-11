#!/usr/bin/env bash
# proves: REQ-CHAIN-007-AC13
# RED until bin/release-metadata.py exists (REQ-CHAIN-007-AC13, advisor 0386 item 2; owner Oct 10: v0.3.0 matches CISA secure by design): step 4.
#
# The four release metadata files and their signed list. bin/release-metadata.py has four subcommands, all offline and deterministic (no clock, no network):
#   images    --digests D --images-dir I --out F   the image digests for bin/vex-forms.py, ONLY from Build's verified digests.json and images/<variant>.digest/.manifests
#   manifest  --digests D --images-dir I --version V --commit SHA --ci-url U --workflow W --out F   release-manifest.json (keeps `.images[].variant` and `.images[].digest`,
#             the shape the REQ-REL-004 rescan reads)
#   list      --version V --dir DIR --out F        release-files.sha256: the sha256 of exactly the four files, in this order: release-manifest.json, the OpenVEX file,
#             the CSAF file, the inspector-filters file (the form of cache's change under handoff 0362, PR #276)
#   gate      --dir DIR                            every file of the release assets directory is covered: in checksums.txt, in release-files.sha256, a bundle of a covered
#             or listed file, or a file with its own bundle; a listed file missing, an extra line, an altered hash or an uncovered asset is refused
# Every refusal exits 1 with a message that names the file or the key. Runs on ubuntu-24.04 or macOS with bash and python3.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export METADATA_BIN="${METADATA_BIN:-$root/bin}"
python3 - <<'PY'
import hashlib, json, os, shutil, subprocess, sys, tempfile
BIN = os.environ["METADATA_BIN"]
passn = failn = 0
def ok(l): global passn; passn += 1; print("ok   " + l)
def bad(l): global failn; failn += 1; print("FAIL " + l)
def check(c, l, why=""): ok(l) if c else bad(l + (" -> " + why if why else ""))
def run(*a, cwd=None):
    p = os.path.join(BIN, "release-metadata.py")
    if not os.path.exists(p): return 127, "", "bin/release-metadata.py does not exist"
    r = subprocess.run(["python3", p] + list(a), capture_output=True, text=True, cwd=cwd); return r.returncode, r.stdout, r.stderr
def sha(b): return "sha256:" + hashlib.sha256(b).hexdigest()
IP, IF = sha(b"index-production"), sha(b"index-fips")
KIDS = {"production": {"amd64": sha(b"kp-amd64"), "arm64": sha(b"kp-arm64")}, "fips": {"amd64": sha(b"kf-amd64"), "arm64": sha(b"kf-arm64")}}
def tree():
    t = tempfile.mkdtemp(); os.makedirs(t + "/witness-build"); os.makedirs(t + "/images")
    d = {"image-production": IP, "image-fips": IF, "archive-linux-amd64": sha(b"a1"), "archive-linux-arm64": sha(b"a2"), "archive-fips-linux-amd64": sha(b"a3"), "archive-fips-linux-arm64": sha(b"a4"),
         "apk-standard-amd64": sha(b"p1"), "apk-standard-arm64": sha(b"p2"), "apk-fips-amd64": sha(b"p3"), "apk-fips-arm64": sha(b"p4")}
    json.dump(d, open(t + "/witness-build/digests.json", "w"))
    for v, idx in (("production", IP), ("fips", IF)):
        open("%s/images/%s.digest" % (t, v), "w").write(idx + "\n")
        open("%s/images/%s.manifests" % (t, v), "w").write("".join("%s %s\n" % (a, h) for a, h in KIDS[v].items()))
    return t, d
def setd(t, d): json.dump(d, open(t + "/witness-build/digests.json", "w"))
V = "v0.3.0"
# ---- images: the digests for vex-forms.py -------------------------------------------------------------------------------------------------
t, d = tree(); out = t + "/vex-images.json"; rc, so, se = run("images", "--digests", t + "/witness-build/digests.json", "--images-dir", t + "/images", "--out", out)
doc = json.load(open(out)) if os.path.exists(out) else {}
check(rc == 0 and doc == {v: {"index": i, "children": {"linux/amd64": KIDS[v]["amd64"], "linux/arm64": KIDS[v]["arm64"]}} for v, i in (("production", IP), ("fips", IF))}, "images: exactly the two variants, index from Build's verified digests.json and the children from images/<variant>.manifests", "rc=%s %s" % (rc, se[:200]))
def img(label, mutate, word):
    t, d = tree(); mutate(t, d); rc, so, se = run("images", "--digests", t + "/witness-build/digests.json", "--images-dir", t + "/images", "--out", t + "/o.json")
    check(rc == 1 and word in se and not os.path.exists(t + "/o.json"), "images: " + label, "rc=%s %s" % (rc, se[:200]))
img("a third variant key (image-debug) in the digest list is refused", lambda t, d: (d.update({"image-debug": sha(b"x")}), setd(t, d)), "image-debug")
img("a missing image-fips key is refused", lambda t, d: (d.pop("image-fips"), setd(t, d)), "image-fips")
img("a value that is not sha256:<64 lower-case hex> is refused", lambda t, d: (d.update({"image-production": "sha256:ZZ"}), setd(t, d)), "image-production")
img("an images/<variant>.digest that is not the attested one is refused (not in Build's verified set)", lambda t, d: open(t + "/images/fips.digest", "w").write(sha(b"other") + "\n"), "fips")
img("a child digest line repeated is refused", lambda t, d: open(t + "/images/production.manifests", "a").write("amd64 " + sha(b"zz") + "\n"), "production.manifests")
img("a missing architecture line is refused", lambda t, d: open(t + "/images/fips.manifests", "w").write("amd64 " + KIDS["fips"]["amd64"] + "\n"), "fips.manifests")
img("an unknown architecture line is refused", lambda t, d: open(t + "/images/fips.manifests", "a").write("riscv64 " + sha(b"r") + "\n"), "fips.manifests")
img("a malformed child digest is refused", lambda t, d: open(t + "/images/fips.manifests", "w").write("amd64 sha256:zz\narm64 " + KIDS["fips"]["arm64"] + "\n"), "fips.manifests")
img("a missing images/<variant>.manifests file is refused", lambda t, d: os.remove(t + "/images/production.manifests"), "production.manifests")
# ---- manifest: deterministic, the rescan's shape ------------------------------------------------------------------------------------------
def manifest(t, out, version=V, commit="a" * 40, extra=()):
    return run("manifest", "--digests", t + "/witness-build/digests.json", "--images-dir", t + "/images", "--version", version, "--commit", commit,
               "--ci-url", "https://github.com/fosterstack/cache/actions/runs/1/attempts/1", "--workflow", "fosterstack/cache/.github/workflows/release.yml@refs/tags/v0.3.0", "--out", out, *extra)
t, d = tree(); m1, m2 = t + "/m1.json", t + "/m2.json"; rc, so, se = manifest(t, m1); rc2, _, _ = manifest(t, m2)
mj = json.load(open(m1)) if os.path.exists(m1) else {}
check(rc == 0 and rc2 == 0 and open(m1, "rb").read() == open(m2, "rb").read(), "manifest: two runs give the same bytes (no clock, no random value)", se[:200])
check([(i.get("variant"), i.get("digest")) for i in mj.get("images", [])] == [("production", IP), ("fips", IF)] and all(any(r.endswith("@" + i["digest"]) for r in i["refs"]) for i in mj.get("images", [])), "manifest: `.images[].variant` and `.images[].digest` keep the shape the rescan reads, with both registry references", str(mj.get("images")))
check(mj.get("version") == V and mj.get("commit") == "a" * 40 and "generated_at" not in json.dumps(mj) and mj.get("run", {}).get("url", "").startswith("https://github.com/"), "manifest: version, commit and run recorded; no generated_at")
check({a["name"]: a["digest"] for a in mj.get("archives", [])} == {k: v for k, v in d.items() if k.startswith("archive-")} and {a["name"]: a["digest"] for a in mj.get("apks", [])} == {k: v for k, v in d.items() if k.startswith("apk-")}, "manifest: archives and apks are exactly Build's attested digests")
for label, ver, com in (("a version that is not vX.Y.Z", "v0.3", "a" * 40), ("a release candidate (no release is made for one)", "v0.3.0-rc1", "a" * 40), ("a commit that is not 40 hex", V, "abc")):
    t, d = tree(); rc, so, se = manifest(t, t + "/m.json", ver, com); check(rc == 1 and not os.path.exists(t + "/m.json"), "manifest: " + label + " is refused", "rc=%s %s" % (rc, se[:160]))
t, d = tree(); d.pop("apk-fips-arm64"); setd(t, d); rc, so, se = manifest(t, t + "/m.json"); check(rc == 1 and "apk-fips-arm64" in se, "manifest: a digest list without one of the four apks is refused, naming it", se[:160])
# ---- list: release-files.sha256 ---------------------------------------------------------------------------------------------------------
NAMES = lambda v: ["release-manifest.json", "fosterstack-cache.openvex.json", "fosterstack-cache-%s.csaf.json" % v, "fosterstack-cache-%s.inspector-filters.json" % v]
def assets():
    a = tempfile.mkdtemp()
    for n in NAMES(V): open(os.path.join(a, n), "w").write("content of " + n)
    return a
a = assets(); out = a + "/release-files.sha256"; rc, so, se = run("list", "--version", V, "--dir", a, "--out", out)
want = "".join("%s  %s\n" % (hashlib.sha256(open(os.path.join(a, n), "rb").read()).hexdigest(), n) for n in NAMES(V))
check(rc == 0 and open(out).read() == want, "list: exactly the four files in this order, `<sha256>  <name>`, the form `sha256sum -c` reads", "rc=%s %s" % (rc, se[:160]))
for n in NAMES(V):
    a = assets(); os.remove(os.path.join(a, n)); rc, so, se = run("list", "--version", V, "--dir", a, "--out", a + "/l"); check(rc == 1 and n in se and not os.path.exists(a + "/l"), "list: a missing %s is refused, naming it" % n, se[:160])
a = assets(); os.remove(os.path.join(a, NAMES(V)[0])); os.symlink(os.path.join(a, NAMES(V)[1]), os.path.join(a, NAMES(V)[0])); rc, so, se = run("list", "--version", V, "--dir", a, "--out", a + "/l"); check(rc == 1 and "symlink" in se, "list: a symlink in place of a file is refused")
a = assets(); open(os.path.join(a, NAMES(V)[2]), "w").write(""); rc, so, se = run("list", "--version", V, "--dir", a, "--out", a + "/l"); check(rc == 1 and "empty" in se, "list: an empty file is refused")
a = assets(); rc, so, se = run("list", "--version", "v0.3.0-rc1", "--dir", a, "--out", a + "/l"); check(rc == 1, "list: a release candidate has no list")
# ---- gate: every asset is covered ----------------------------------------------------------------------------------------------------------
def release_dir():
    a = assets(); run("list", "--version", V, "--dir", a, "--out", a + "/release-files.sha256")
    open(a + "/release-files.sha256.bundle", "w").write("{}")
    for n, c in (("fscache_0.3.0_linux_amd64.tar.gz", b"A"), ("fscache_0.3.0_linux_arm64.tar.gz", b"B")): open(os.path.join(a, n), "wb").write(c)
    open(a + "/checksums.txt", "w").write("".join("%s  %s\n" % (hashlib.sha256(open(os.path.join(a, n), "rb").read()).hexdigest(), n) for n in ("fscache_0.3.0_linux_amd64.tar.gz", "fscache_0.3.0_linux_arm64.tar.gz")))
    open(a + "/checksums.txt.bundle", "w").write("{}")
    open(a + "/production.sbom.json", "w").write("{}"); open(a + "/production.sbom.json.bundle", "w").write("{}")
    open(a + "/policy.json", "w").write("{}"); open(a + "/release-policy.bundle", "w").write("{}")
    open(a + "/build-collection.json", "w").write("{}")
    return a
def gate(label, mutate, word=None):
    a = release_dir(); mutate(a); rc, so, se = run("gate", "--dir", a)
    if word is None: check(rc == 0, "gate: " + label, "rc=%s %s" % (rc, se[:200]))
    else: check(rc == 1 and word in se, "gate: " + label, "rc=%s %s" % (rc, se[:200]))
gate("a complete release directory passes", lambda a: None)
gate("an asset in neither checksums.txt nor release-files.sha256 nor with a bundle is refused, naming it", lambda a: open(a + "/stray.txt", "w").write("x"), "stray.txt")
gate("a bundle whose signed file is not an asset is refused", lambda a: open(a + "/ghost.json.bundle", "w").write("{}"), "ghost.json.bundle")
gate("a file listed in checksums.txt that is not an asset is refused", lambda a: open(a + "/checksums.txt", "a").write("%s  gone.tar.gz\n" % ("0" * 64)), "gone.tar.gz")
gate("an archive whose bytes differ from checksums.txt is refused", lambda a: open(a + "/fscache_0.3.0_linux_amd64.tar.gz", "wb").write(b"tampered"), "fscache_0.3.0_linux_amd64.tar.gz")
gate("a metadata file altered after the list was made is refused", lambda a: open(a + "/release-manifest.json", "a").write("x"), "release-manifest.json")
gate("an extra line in release-files.sha256 is refused", lambda a: open(a + "/release-files.sha256", "a").write("%s  extra.json\n" % ("0" * 64)), "extra")
gate("an empty release-files.sha256 is refused", lambda a: open(a + "/release-files.sha256", "w").write(""), "release-files.sha256")
gate("a missing release-files.sha256.bundle is refused (v0.3.0 is not released without the four files signed)", lambda a: os.remove(a + "/release-files.sha256.bundle"), "release-files.sha256.bundle")
gate("a missing metadata file is refused", lambda a: os.remove(a + "/fosterstack-cache.openvex.json"), "fosterstack-cache.openvex.json")
gate("a missing checksums.txt.bundle is refused", lambda a: os.remove(a + "/checksums.txt.bundle"), "checksums.txt.bundle")
gate("a file with its own bundle (the SBOM) is covered by it", lambda a: None)
gate("an SBOM whose bundle is gone is refused", lambda a: os.remove(a + "/production.sbom.json.bundle"), "production.sbom.json")
gate("a symlink among the assets is refused", lambda a: os.symlink(a + "/checksums.txt", a + "/link.txt"), "link.txt")
print("pass=%d fail=%d" % (passn, failn))
EXPECT = int(os.environ.get("EXPECT_CASES", "40"))
if EXPECT and passn + failn != EXPECT: print("FAIL case count %d != expected %d" % (passn + failn, EXPECT)); sys.exit(1)
sys.exit(1 if failn else 0)
PY
