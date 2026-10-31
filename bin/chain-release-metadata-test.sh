#!/usr/bin/env bash
# proves: REQ-CHAIN-007-AC19, REQ-CHAIN-007-AC21
# RED until bin/release-metadata.py exists (REQ-CHAIN-007-AC13, advisor 0386 item 2; owner Oct 10: v0.3.0 matches CISA secure by design): step 4.
#
# The four release metadata files and their signed list. bin/release-metadata.py has four subcommands, all offline and deterministic (no clock, no network):
#   images    --digests D --images-dir I --items ITEMS --out F   the image digests for bin/vex-forms.py, ONLY from Build's verified digests.json and images/<variant>.digest/.manifests
#   manifest  --digests D --images-dir I --items ITEMS --modules-dir DIR --vex-dir DIR --version V --commit SHA
#             --ci-url U --workflow W --out F   release-manifest.json (keeps `.images[].variant` and `.images[].digest`,
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
MODULE_SBOMS = (("standard", "fscache-modules.spdx.json"), ("fips", "fscache-modules-fips.spdx.json"))
def module_sbom(variant): return "module sbom " + variant
def tree():
    t = tempfile.mkdtemp(); os.makedirs(t + "/witness-build"); os.makedirs(t + "/images")
    d = {"image-production": IP, "image-fips": IF, "archive-linux-amd64": sha(b"a1"), "archive-linux-arm64": sha(b"a2"), "archive-fips-linux-amd64": sha(b"a3"), "archive-fips-linux-arm64": sha(b"a4"),
         "apk-standard-amd64": sha(b"p1"), "apk-standard-arm64": sha(b"p2"), "apk-fips-amd64": sha(b"p3"), "apk-fips-arm64": sha(b"p4")}
    json.dump(d, open(t + "/witness-build/digests.json", "w"))
    items = {}
    for v, idx in (("production", IP), ("fips", IF)):
        open("%s/images/%s.digest" % (t, v), "w").write(idx + "\n")
        open("%s/images/%s.manifests" % (t, v), "w").write("".join("%s %s\n" % (a, h) for a, h in KIDS[v].items()))
        os.makedirs("%s/images/%s-sbom" % (t, v)); open("%s/images/%s.full.lock.json" % (t, v), "w").write("lock " + v); open("%s/images/%s-sbom/sbom.json" % (t, v), "w").write("sbom " + v)
        items.update({"image-" + v: idx, "lock-" + v: sha(b"lock " + v.encode()), "sbom-" + v: sha(b"sbom " + v.encode())})
        items.update({"image-%s-manifest-%s" % (v, a): h for a, h in KIDS[v].items()})
    os.makedirs(t + "/modules")
    for variant, name in MODULE_SBOMS:
        open(os.path.join(t, "modules", name), "w").write(module_sbom(variant))
        items["modules-sbom-" + variant] = sha(module_sbom(variant).encode())
    json.dump(items, open(t + "/witness-build/items.json", "w"))
    return t, d
def setd(t, d): json.dump(d, open(t + "/witness-build/digests.json", "w"))
V = "v0.3.0"
# ---- images: the digests for vex-forms.py -------------------------------------------------------------------------------------------------
t, d = tree(); out = t + "/vex-images.json"; rc, so, se = run("images", "--digests", t + "/witness-build/digests.json", "--images-dir", t + "/images", "--items", t + "/witness-build/items.json", "--out", out)
doc = json.load(open(out)) if os.path.exists(out) else {}
check(rc == 0 and doc == {v: {"index": i, "children": {"linux/amd64": KIDS[v]["amd64"], "linux/arm64": KIDS[v]["arm64"]}} for v, i in (("production", IP), ("fips", IF))}, "images: exactly the two variants, index from Build's verified digests.json and the children from images/<variant>.manifests", "rc=%s %s" % (rc, se[:200]))
def img(label, mutate, word):
    t, d = tree(); mutate(t, d); rc, so, se = run("images", "--digests", t + "/witness-build/digests.json", "--images-dir", t + "/images", "--items", t + "/witness-build/items.json", "--out", t + "/o.json")
    check(rc == 1 and word in se and not os.path.exists(t + "/o.json"), "images: " + label, "rc=%s %s" % (rc, se[:200]))
img("a third variant key (image-debug) in the digest list is refused", lambda t, d: (d.update({"image-debug": sha(b"x")}), setd(t, d)), "image-debug")
# round 1 (Codex A F7): the digest list is a closed table (image-*, apk-VARIANT-ARCH, archive-*linux-ARCH): a name outside it is refused
img("a digest name outside the table (outside-table) is refused", lambda t, d: (d.update({"outside-table": sha(b"x")}), setd(t, d)), "outside-table")
img("an apk name for a variant or architecture not in the table is refused", lambda t, d: (d.update({"apk-debug-amd64": sha(b"x")}), setd(t, d)), "apk-debug-amd64")
img("an archive name for an architecture not in the table is refused", lambda t, d: (d.update({"archive-linux-ppc64": sha(b"x")}), setd(t, d)), "archive-linux-ppc64")
img("a missing image-fips key is refused", lambda t, d: (d.pop("image-fips"), setd(t, d)), "image-fips")
img("a value that is not sha256:<64 lower-case hex> is refused", lambda t, d: (d.update({"image-production": "sha256:ZZ"}), setd(t, d)), "image-production")
img("an images/<variant>.digest that is not the attested one is refused (not in Build's verified set)", lambda t, d: open(t + "/images/fips.digest", "w").write(sha(b"other") + "\n"), "fips")
img("a child digest line repeated is refused", lambda t, d: open(t + "/images/production.manifests", "a").write("amd64 " + sha(b"zz") + "\n"), "production.manifests")
img("a missing architecture line is refused", lambda t, d: open(t + "/images/fips.manifests", "w").write("amd64 " + KIDS["fips"]["amd64"] + "\n"), "fips.manifests")
img("an unknown architecture line is refused", lambda t, d: open(t + "/images/fips.manifests", "a").write("riscv64 " + sha(b"r") + "\n"), "fips.manifests")
img("a malformed child digest is refused", lambda t, d: open(t + "/images/fips.manifests", "w").write("amd64 sha256:zz\narm64 " + KIDS["fips"]["arm64"] + "\n"), "fips.manifests")
img("a missing images/<variant>.manifests file is refused", lambda t, d: os.remove(t + "/images/production.manifests"), "production.manifests")
def items_of(t): return json.load(open(t + "/witness-build/items.json"))
def setitems(t, it): json.dump(it, open(t + "/witness-build/items.json", "w"))
img("a child digest that is not Build's verified item image-fips-manifest-arm64 is refused", lambda t, d: setitems(t, dict(items_of(t), **{"image-fips-manifest-arm64": sha(b"other")})), "image-fips-manifest-arm64")
img("a child digest with no verified item is refused", lambda t, d: setitems(t, {k: v for k, v in items_of(t).items() if k != "image-production-manifest-amd64"}), "image-production-manifest-amd64")
img("an index that differs from Build's verified item image-production is refused", lambda t, d: setitems(t, dict(items_of(t), **{"image-production": sha(b"other")})), "image-production")
img("a lock file whose hash is not Build's verified item lock-production is refused", lambda t, d: open(t + "/images/production.full.lock.json", "w").write("tampered"), "lock-production")
img("an SBOM whose hash is not Build's verified item sbom-fips is refused", lambda t, d: open(t + "/images/fips-sbom/sbom.json", "w").write("tampered"), "sbom-fips")
img("a missing items file is refused", lambda t, d: os.remove(t + "/witness-build/items.json"), "items.json")
# ---- manifest: deterministic, the rescan's shape ------------------------------------------------------------------------------------------
def vexdir(t, version=V):
    v = t + "/vex"; os.makedirs(v, exist_ok=True)
    for n in ("fosterstack-cache.openvex.json", "fosterstack-cache-%s.csaf.json" % version, "fosterstack-cache-%s.inspector-filters.json" % version): open(os.path.join(v, n), "w").write("content of " + n)
    return v
def repo(t, base=V):
    r = t + "/repo"; os.makedirs(r + "/requirements/releases", exist_ok=True); os.makedirs(r + "/test-evidence", exist_ok=True)
    open("%s/requirements/releases/%s.yaml" % (r, base), "w").write("baseline of " + base + "\n"); open(r + "/test-evidence/mappings.yaml", "w").write("evidence\n")
    return r
def manifest(t, out, version=V, commit="a" * 40, extra=(), base=None, root=None):
    return run("manifest", "--digests", t + "/witness-build/digests.json", "--images-dir", t + "/images",
               "--items", t + "/witness-build/items.json", "--modules-dir", t + "/modules",
               "--vex-dir", vexdir(t, version),
               "--version", version, "--commit", commit, "--baseline-version", base or version,
               "--repo-root", root or repo(t, base or version),
               "--ci-url", "https://github.com/fosterstack/cache/actions/runs/1/attempts/1", "--workflow", "fosterstack/cache/.github/workflows/release.yml@refs/tags/v0.3.0", "--out", out, *extra)
t, d = tree(); m1, m2 = t + "/m1.json", t + "/m2.json"; rc, so, se = manifest(t, m1); rc2, _, _ = manifest(t, m2)
mj = json.load(open(m1)) if os.path.exists(m1) else {}
check(rc == 0 and rc2 == 0 and open(m1, "rb").read() == open(m2, "rb").read(), "manifest: two runs give the same bytes (no clock, no random value)", se[:200])
check([(i.get("variant"), i.get("digest")) for i in mj.get("images", [])] == [("production", IP), ("fips", IF)] and all(sorted(i["refs"]) == sorted(["ghcr.io/fosterstack/cache@" + i["digest"], "docker.io/fosterstack/cache@" + i["digest"]]) for i in mj.get("images", [])), "manifest: `.images[].variant` and `.images[].digest` keep the shape the rescan reads, with both registry references", str(mj.get("images")))
check(mj.get("version") == V and mj.get("commit") == "a" * 40 and "generated_at" not in json.dumps(mj) and mj.get("run", {}).get("url", "").startswith("https://github.com/"), "manifest: version, commit and run recorded; no generated_at")
check({a["name"]: a["digest"] for a in mj.get("archives", [])} == {k: v for k, v in d.items() if k.startswith("archive-")} and {a["name"]: a["digest"] for a in mj.get("apks", [])} == {k: v for k, v in d.items() if k.startswith("apk-")}, "manifest: archives and apks are exactly Build's attested digests")
hexs = lambda n: hashlib.sha256(open(t + "/vex/" + n, "rb").read()).hexdigest()
check([(x.get("form"), x.get("file"), x.get("sha256")) for x in mj.get("vex", [])] == [("openvex", "fosterstack-cache.openvex.json", hexs("fosterstack-cache.openvex.json")), ("inspector-suppression-rules", "fosterstack-cache-%s.inspector-filters.json" % V, hexs("fosterstack-cache-%s.inspector-filters.json" % V)), ("csaf-2.0-vex", "fosterstack-cache-%s.csaf.json" % V, hexs("fosterstack-cache-%s.csaf.json" % V))], "manifest: records the sha256 of the OpenVEX, inspector-filters and CSAF files it was made after (generated before the manifest)", str(mj.get("vex")))
for n in ("fosterstack-cache.openvex.json", "fosterstack-cache-%s.csaf.json" % V, "fosterstack-cache-%s.inspector-filters.json" % V):
    t, d = tree(); rc, so, se = manifest(t, t + "/m.json"); os.remove(t + "/vex/" + n)
    rc, so, se = run("manifest", "--digests", t + "/witness-build/digests.json", "--images-dir", t + "/images",
                     "--items", t + "/witness-build/items.json", "--modules-dir", t + "/modules",
                     "--vex-dir", t + "/vex",
                     "--version", V, "--commit", "a" * 40, "--baseline-version", V, "--repo-root", t + "/repo",
                     "--ci-url", "u", "--workflow", "w", "--out", t + "/m2.json")
    check(rc == 1 and n in se and not os.path.exists(t + "/m2.json"), "manifest: a missing %s (not generated before the manifest) is refused, naming it" % n, se[:160])
for label, ver, com in (("a version that is not vX.Y.Z", "v0.3", "a" * 40), ("a release candidate (no release is made for one)", "v0.3.0-rc1", "a" * 40), ("a commit that is not 40 hex", V, "abc")):
    t, d = tree(); rc, so, se = manifest(t, t + "/m.json", ver, com); check(rc == 1 and not os.path.exists(t + "/m.json"), "manifest: " + label + " is refused", "rc=%s %s" % (rc, se[:160]))
t, d = tree(); d.pop("apk-fips-arm64"); setd(t, d); rc, so, se = manifest(t, t + "/m.json"); check(rc == 1 and "apk-fips-arm64" in se, "manifest: a digest list without one of the four apks is refused, naming it", se[:160])
t, d = tree(); rc, so, se = manifest(t, t + "/m.json")
mj = json.load(open(t + "/m.json")) if rc == 0 else {}
want = [{"name": name, "digest": sha(module_sbom(variant).encode())} for variant, name in MODULE_SBOMS]
check(mj.get("module_sboms") == want, "manifest: names both Go module SBOMs with Build's items.json digests", se[:160])
def module_sbom_refused(label, name, change, also=""):
    t, d = tree(); change(t)
    rc, so, se = manifest(t, t + "/m.json")
    check(rc == 1 and name in se and also in se and not os.path.exists(t + "/m.json"), "manifest: " + label, se[:160])
def make_symlink(t, name):
    path = t + "/modules/" + name
    os.rename(path, t + "/real-" + name)
    os.symlink(t + "/real-" + name, path)
for variant, name in MODULE_SBOMS:
    module_sbom_refused("a %s that differs from Build's item is refused, naming it" % name, name,
                        lambda t: open(t + "/modules/" + name, "w").write("changed"))
    module_sbom_refused("a missing %s is refused, naming it" % name, name, lambda t: os.remove(t + "/modules/" + name))
    module_sbom_refused("a %s that is a symlink to Build's bytes is refused, naming it" % name, name,
                        lambda t: make_symlink(t, name), also="not a regular file")
    module_sbom_refused("a %s that is a directory is refused, naming it" % name, name,
                        lambda t: (os.remove(t + "/modules/" + name), os.mkdir(t + "/modules/" + name)),
                        also="not a regular file")
    module_sbom_refused("no Build item modules-sbom-%s is refused, naming the file and the item" % variant, name,
                        lambda t: setitems(t, {k: v for k, v in items_of(t).items() if k != "modules-sbom-" + variant}),
                        also="modules-sbom-" + variant)
# ---- the baseline travels with the manifest (REQ-REL-009-AC13 note; AC19): requirements/releases/<baseline>.yaml and test-evidence/mappings.yaml, by sha256 ----------------
t, d = tree(); rc, so, se = manifest(t, t + "/m.json"); mj = json.load(open(t + "/m.json")) if os.path.exists(t + "/m.json") else {}
hx = lambda f: hashlib.sha256(open(f, "rb").read()).hexdigest()
check(mj.get("requirements_baseline") == {"path": "requirements/releases/%s.yaml" % V, "version": V, "sha256": hx(t + "/repo/requirements/releases/%s.yaml" % V)}, "baseline: the manifest records the baseline file admission chose (path, version, sha256)", str(mj.get("requirements_baseline")))
check(mj.get("test_evidence") == {"path": "test-evidence/mappings.yaml", "sha256": hx(t + "/repo/test-evidence/mappings.yaml")}, "baseline: the manifest records the test-evidence hash", str(mj.get("test_evidence")))
t, d = tree(); rc, so, se = manifest(t, t + "/m.json", base="v0.2.9"); mj = json.load(open(t + "/m.json")) if rc == 0 else {}
check(rc == 0 and mj.get("requirements_baseline", {}).get("version") == "v0.2.9" and mj["requirements_baseline"]["path"] == "requirements/releases/v0.2.9.yaml", "baseline: a CI patch's baseline is another version's file (admission's choice), recorded as that", se[:160])
t, d = tree(); r = repo(t); os.remove(r + "/requirements/releases/%s.yaml" % V); rc, so, se = manifest(t, t + "/m.json", root=r)
check(rc == 1 and "requirements/releases/%s.yaml" % V in se and not os.path.exists(t + "/m.json"), "baseline: a missing baseline file is refused, naming it", se[:160])
t, d = tree(); r = repo(t); os.remove(r + "/test-evidence/mappings.yaml"); rc, so, se = manifest(t, t + "/m.json", root=r)
check(rc == 1 and "mappings.yaml" in se, "baseline: missing test evidence is refused, naming it", se[:160])
for bad_base in ("main", "0.3.0", "v0.3", "../v0.3.0", "v0.3.0/x", ""):
    t, d = tree(); r = repo(t)
    rc, so, se = run("manifest", "--digests", t + "/witness-build/digests.json", "--images-dir", t + "/images",
                     "--items", t + "/witness-build/items.json", "--modules-dir", t + "/modules",
                     "--vex-dir", vexdir(t),
                     "--version", V, "--commit", "a" * 40, "--baseline-version", bad_base, "--repo-root", r,
                     "--ci-url", "u", "--workflow", "w", "--out", t + "/m.json")
    check(rc == 1 and not os.path.exists(t + "/m.json"), "baseline: the version %r is not vX.Y.Z and is refused" % bad_base, se[:120])
t, d = tree(); r = repo(t); f = r + "/requirements/releases/%s.yaml" % V; os.remove(f); os.symlink(r + "/test-evidence/mappings.yaml", f); rc, so, se = manifest(t, t + "/m.json", root=r)
check(rc == 1 and "symlink" in se, "baseline: a symlinked baseline file is refused", se[:120])
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
    for n in ("provenance.json", "provenance.rekor.json", "provenance.bundle.json"): open(os.path.join(a, n), "w").write("{}")      # Sign's three files (REQ-CHAIN-007-AC9, AC19)
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
gate("a module SBOM with no bundle is refused, naming it",
     lambda a: open(a + "/fscache-modules.spdx.json", "w").write("{}"), "fscache-modules.spdx.json")
def with_module_sbom(a):
    open(a + "/fscache-modules.spdx.json", "w").write("{}")
    open(a + "/fscache-modules.spdx.json.bundle", "w").write("{}")
gate("a module SBOM with its bundle passes", with_module_sbom)
gate("an extra line in release-files.sha256 is refused", lambda a: open(a + "/release-files.sha256", "a").write("%s  extra.json\n" % ("0" * 64)), "extra")
# Codex 4b-2 r1 (A B3): the exact four-line format; a blank line anywhere (leading, between entries, or more than the one final newline) is an extra line
def _sums_edit(f):
    def w(a):
        t = open(a + "/release-files.sha256").read(); open(a + "/release-files.sha256", "w").write(f(t))
    return w
gate("a blank line before the first entry of release-files.sha256 is refused", _sums_edit(lambda t: "\n" + t), "blank")
gate("a blank line between entries of release-files.sha256 is refused", _sums_edit(lambda t: t.replace("\n", "\n\n", 1)), "blank")
gate("a second newline at the end of release-files.sha256 is refused", _sums_edit(lambda t: t + "\n"), "blank")
gate("a blank line in checksums.txt is refused", lambda a: open(a + "/checksums.txt", "a").write("\n"), "blank")
gate("an empty release-files.sha256 is refused", lambda a: open(a + "/release-files.sha256", "w").write(""), "release-files.sha256")
gate("a missing release-files.sha256.bundle is refused (v0.3.0 is not released without the four files signed)", lambda a: os.remove(a + "/release-files.sha256.bundle"), "release-files.sha256.bundle")
gate("a missing metadata file is refused", lambda a: os.remove(a + "/fosterstack-cache.openvex.json"), "fosterstack-cache.openvex.json")
gate("a missing checksums.txt.bundle is refused", lambda a: os.remove(a + "/checksums.txt.bundle"), "checksums.txt.bundle")
gate("a file with its own bundle (the SBOM) is covered by it", lambda a: None)
for n in ("provenance.json", "provenance.rekor.json", "provenance.bundle.json"):
    gate("a release without Sign's %s is refused, naming it (Sign's provenance is part of every release)" % n, lambda a, n=n: os.remove(os.path.join(a, n)), n)
gate("an SBOM whose bundle is gone is refused", lambda a: os.remove(a + "/production.sbom.json.bundle"), "production.sbom.json")
gate("a symlink among the assets is refused", lambda a: os.symlink(a + "/checksums.txt", a + "/link.txt"), "link.txt")
# ---- tag-notes: the release tag's generated notes (REQ-REL-009-AC8), the same decision as bin/patch-decide.py tag_notes ----------------------------
import importlib.util
spec = importlib.util.spec_from_file_location("patch_decide", os.path.join(BIN, "patch-decide.py")); PD = importlib.util.module_from_spec(spec); spec.loader.exec_module(PD)
GEN = ("object 0123\ntype commit\ntag v0.3.1\ntagger fosterstack release <release@users.noreply.github.com> 1 +0000\n\n"
       "## v0.3.1 \u2014 patch release\n\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n- no change\n"
       "-----BEGIN SIGNED MESSAGE-----\nMIIabc\n-----END SIGNED MESSAGE-----\n")
cases = [("a generated patch tag", GEN, "v0.3.1"),
         ("an owner's tag", "object 1\ntype commit\ntag v0.3.1\ntagger o <o@x> 1 +0000\n\nv0.3.1\n", "v0.3.1"),
         ("another tagger", GEN.replace("fosterstack release <release@users.noreply.github.com>", "Someone <s@x>"), "v0.3.1"),
         ("a heading for another version", GEN.replace("## v0.3.1 \u2014", "## v0.3.2 \u2014"), "v0.3.1"),
         ("an ssh signature, not gitsign", GEN.replace("SIGNED MESSAGE-----", "SSH SIGNATURE-----"), "v0.3.1"),
         ("two signature blocks", GEN + "-----BEGIN SIGNED MESSAGE-----\nfake\n-----END SIGNED MESSAGE-----\n", "v0.3.1"),
         ("no signature block", GEN.split("-----BEGIN")[0], "v0.3.1"),
         ("the right tag object for another release tag", GEN, "v0.3.2")]
for what, raw, tag in cases:
    obj = os.path.join(tempfile.mkdtemp(), "tag.txt"); open(obj, "w").write(raw)
    r = subprocess.run(["python3", os.path.join(BIN, "release-metadata.py"), "tag-notes", "--tag", tag, "--object", obj], capture_output=True, text=True)
    try: pd = PD.tag_notes(raw) if tag == "v0.3.1" else None
    except ValueError: pd = None          # since cache#300 patch-decide REFUSES a tag message with a refused form (two signature blocks): the release keeps its fixed text, as for "no notes"
    same = (r.returncode == 0 and pd is not None and r.stdout.strip() == pd.strip()) or (r.returncode == 1 and pd is None and r.stdout == "")
    check(same, "tag-notes: %s gives what patch-decide's tag_notes gives (notes, or none)" % what, "rc=%s out=%r pd=%r" % (r.returncode, r.stdout[:60], (pd or "")[:60]))
print("pass=%d fail=%d" % (passn, failn))
EXPECT = int(os.environ.get("EXPECT_CASES", "73"))
# ---- the accepted AC text of advisor rulings B, C and E (Oct 12): requirements.yaml says what the code now does ----------------------------------------------------------
import yaml
REQS = {r["id"]: r for r in yaml.safe_load(open(os.path.join(BIN, "..", "requirements", "requirements.yaml")))["requirements"]}
def ac(rid, n): return next(a for a in REQS[rid]["acceptance_criteria"] if a["id"] == "%s-AC%d" % (rid, n))
t4, t7 = ac("REQ-CHAIN-004", 2)["then"], ac("REQ-CHAIN-007", 9)["then"]
t19 = ac("REQ-CHAIN-007", 19)["then"]
check("the command wrapped in timeout -k 20 540 (a bound on a hung command, with a kill-after of 20 seconds)" in t4 and "wrapped in timeout 540," not in t4,
      "text: REQ-CHAIN-004-AC2 says timeout -k 20 540 (E item A)")
n4, n7 = REQS["REQ-CHAIN-004"]["notes"], REQS["REQ-CHAIN-007"]["notes"]
check("wrapped in timeout -k 20 540." in n4 and "wrapped in timeout 540." not in n4 and "with timeout -k 20 540 inside it" in n7 and "with timeout 540 inside it" not in n7
      and "Release has six such steps (release-verify, release-apks, release-publish, release-sign, release-assets, release-postverify)" in n7 and "Release has five such steps" not in n7,
      "text: the REQ-CHAIN-004 and REQ-CHAIN-007 notes say timeout -k 20 540 and six Release steps (E item B)")
t1 = ac("REQ-CHAIN-007", 1)["then"]
check("and nothing else in the step except an `env` block of exactly the credential names AC2 and AC15 give that step and, for every step after release-verify, the one condition" in t1,
      "text: REQ-CHAIN-007-AC1 says the witnessed steps carry an env block of the credentials AC2 and AC15 name (accepted Oct 13)")
check("the release notes are posted here only from the notes carried in the generated patch tag's message (REQ-REL-009-AC8; the changelog is the patch-notes job's)" in t7 and "release notes are not posted here" not in t7,
      "text: REQ-CHAIN-007-AC9 agrees with REQ-REL-009-AC8 (the notes are posted by release-assets from the generated tag's message; Codex 4b-2 r1 B2)")
check("release-files.sha256 with its bundle and the four metadata files (AC19), Sign's provenance (provenance.json, provenance.rekor.json, provenance.bundle.json, as named files of the release) and the Witness records of Build, Rebuild and Check to the release" in t7,
      "text: REQ-CHAIN-007-AC9 attaches Sign's three provenance files (ruling C)")
check("Build's digests.json, items.json or admission-baseline.json (products of Build's signed record) or Sign's provenance.json, provenance.rekor.json and provenance.bundle.json (the record the Sign stage signed; the bundle carries its signature)" in t19
      and "Build's admission-baseline.json" in t19 and "never a version Release chooses itself" in t19 and "the baseline admission chose for a CI patch)" not in t19,
      "text: REQ-CHAIN-007-AC19 covers admission-baseline.json and Sign's provenance and takes the baseline from Build's verified file (rulings B and C)")
# ---- REQ-CHAIN-007-AC21 (advisor reading Oct 16, Astra R3): checksums writes dist/checksums.txt from the four archives Build recorded ----------------------------------
ARCS = (("archive-fips-linux-amd64", "fscache-fips_0.3.0_linux_amd64.tar.gz"), ("archive-fips-linux-arm64", "fscache-fips_0.3.0_linux_arm64.tar.gz"),
        ("archive-linux-amd64", "fscache_0.3.0_linux_amd64.tar.gz"), ("archive-linux-arm64", "fscache_0.3.0_linux_arm64.tar.gz"))
def ck_tree():
    t = tempfile.mkdtemp(); os.makedirs(t + "/dist"); os.makedirs(t + "/witness-build")
    for item, name in ARCS: open(os.path.join(t, "dist", name), "wb").write(item.encode())
    json.dump({item: sha(item.encode()) for item, _ in ARCS}, open(t + "/witness-build/digests.json", "w"))
    return t
def ck_run(t, version="0.3.0"):
    return run("checksums", "--version", version, "--dist", t + "/dist", "--digests", t + "/witness-build/digests.json", "--out", t + "/dist/checksums.txt")
WANT = "".join("%s  %s\n" % (hashlib.sha256(i.encode()).hexdigest(), n) for i, n in sorted(ARCS, key=lambda x: x[1].encode()))
t = ck_tree(); r = ck_run(t)
check(r[0] == 0 and open(t + "/dist/checksums.txt").read() == WANT and WANT.count("\n") == 4 and "  " in WANT.split("\n")[0] and WANT.endswith("\n"),
      "AC21 checksums writes one `<sha256>  <name>` line per archive, in byte order of the names, two spaces, a final newline, and nothing else", "rc=%s %s" % (r[0], r[2][:120]))
t = ck_tree(); open(t + "/dist/checksums.txt", "w").write("stale\n"); r = ck_run(t)
check(r[0] == 0 and open(t + "/dist/checksums.txt").read() == WANT and sorted(os.listdir(t + "/dist")) == sorted([n for _, n in ARCS] + ["checksums.txt"]),
      "AC21 an earlier checksums.txt is replaced, not extended, and no temporary file is left in dist", "rc=%s %s" % (r[0], sorted(os.listdir(t + "/dist"))))
for label, mutate, word in (("a missing archive", lambda d: os.remove(d + "/" + ARCS[2][1]), ARCS[2][0]),
                            ("an extra archive", lambda d: open(d + "/fscache_0.3.0_linux_riscv.tar.gz", "wb").write(b"x"), "riscv"),
                            ("an archive that is not the recorded bytes", lambda d: open(d + "/" + ARCS[0][1], "wb").write(b"other"), ARCS[0][0]),
                            ("a symlinked archive", lambda d: (os.remove(d + "/" + ARCS[1][1]), os.symlink("/etc/hosts", d + "/" + ARCS[1][1])), ARCS[1][1])):
    t = ck_tree(); mutate(t + "/dist"); r = ck_run(t)
    check(r[0] == 1 and word in r[2] and not os.path.exists(t + "/dist/checksums.txt"), "AC21 %s is refused (exit 1, naming it) and no checksums.txt is written" % label, "rc=%s %s" % (r[0], r[2][:140]))
for bad_v in ("0.3.0-rc1", "v0.3.0", "0.3", ""):
    t = ck_tree(); r = ck_run(t, bad_v)
    check(r[0] == 1 and not os.path.exists(t + "/dist/checksums.txt"), "AC21 the version %r is refused: only X.Y.Z, and nothing is written" % bad_v, "rc=%s %s" % (r[0], r[2][:100]))
# round 1 (Codex seat B, a reproduced blocker): the temporary file is never a path someone else can pre-place. A planted symlink checksums.txt.part must not make the
# command write through it (it overwrote an archive after the archives were checked), and a stale regular .part is replaced, never extended or kept
t = ck_tree(); victim = t + "/dist/" + ARCS[0][1]; before = open(victim, "rb").read()
os.symlink(victim, t + "/dist/checksums.txt.part"); r = ck_run(t)
check(r[0] == 0 and open(victim, "rb").read() == before and not os.path.islink(t + "/dist/checksums.txt") and open(t + "/dist/checksums.txt").read() == WANT
      and not os.path.lexists(t + "/dist/checksums.txt.part"),
      "AC21 a planted symlink at checksums.txt.part is not written through: the archive keeps its bytes, checksums.txt is a regular file with the right lines, no .part is left", "rc=%s %s" % (r[0], r[2][:140]))
t = ck_tree(); open(t + "/dist/checksums.txt.part", "w").write("stale part\n"); r = ck_run(t)
check(r[0] == 0 and open(t + "/dist/checksums.txt").read() == WANT and not os.path.lexists(t + "/dist/checksums.txt.part"),
      "AC21 a stale regular checksums.txt.part is replaced, not kept or extended", "rc=%s" % r[0])
t = ck_tree(); os.mkdir(t + "/dist/checksums.txt.part"); r = ck_run(t)
check(r[0] == 1 and not os.path.exists(t + "/dist/checksums.txt"), "AC21 a directory at checksums.txt.part is a refusal (exit 1), and nothing is written", "rc=%s %s" % (r[0], r[2][:120]))
t21 = ac("REQ-CHAIN-007", 21)["then"]
check("bind-archives" not in t21 and "bin/release-metadata.py checksums" in t21 and "no test creates the file it signs" in t21,
      "text: REQ-CHAIN-007-AC21 names only the checksums command (it makes the archive check itself) and says no test creates the signed file")
# rc-2 signing review R6 (wording stale since the Oct 21 rule): the texts, comments and the reason say what the scripts do
t6, t10 = ac("REQ-CHAIN-007", 6)["then"], ac("REQ-CHAIN-007", 10)["then"]
check("--rebuild-dir" not in t6 and "compares Build's and Rebuild's" not in t6 and "release-sign-apks.sh --build-dir B --key K" in t6 and "release-compare.sh" in t6,
      "text: REQ-CHAIN-007-AC6 runs release-sign-apks.sh with --build-dir and --key only; the comparison is release-compare.sh's")
check("release-sign: cosign, git, jq and python3" in t10, "text: REQ-CHAIN-007-AC10 lists git among release-sign's tools")
b7 = ac("REQ-BUILDAPK-001", 7)["then"]
check("Build and Rebuild apk" not in b7 and "PROPOSED" not in b7 and "counterpart in Rebuild" not in b7 and "same control AND data sections" not in b7 and "--rebuild-dir" in b7 and "unknown argument" in b7 and "release-compare.sh" in b7,
      "text: REQ-BUILDAPK-001-AC7 signs Build's apks only; a --rebuild-dir is an unknown argument; the comparison is release-compare.sh's")
CS = {r["path"]: r for r in json.load(open(os.path.join(BIN, "..", ".github", "policy", "chain-scripts.json")))["scripts"]}
check("Build/Rebuild comparison" not in CS["bin/release-apks.sh"]["reason"] and "release-compare" in CS["bin/release-apks.sh"]["reason"],
      "text: chain-scripts.json's release-apks reason does not claim the Build/Rebuild comparison and names release-compare.sh")
check("--rebuild-dir" not in open(os.path.join(BIN, "melange-apko-lib.sh")).read(), "text: melange-apko-lib.sh no longer shows release-sign-apks.sh with --rebuild-dir")
check("TODO (PR 2" not in open(os.path.join(BIN, "release-verify.sh")).read(), "text: release-verify.sh has no TODO for the rc tag grammar it already accepts")
check("docs/apk-signing-key.md" not in open(os.path.join(BIN, "..", "build", "keys", "release.rsa.pub")).read(), "text: release.rsa.pub does not point at a document that does not exist")
print("pass=%d fail=%d" % (passn, failn))
EXPECT = int(os.environ.get("EXPECT_CASES", "120"))
if EXPECT and passn + failn != EXPECT: print("FAIL case count %d != expected %d" % (passn + failn, EXPECT)); sys.exit(1)
sys.exit(1 if failn else 0)
PY
