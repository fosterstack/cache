#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC3, REQ-CHAIN-004-AC9, REQ-CHAIN-005-AC1 — the assemble job binds every file it uses to the verified record (rule 58); digests.json and items.json are what an honest merge writes; Rebuild binds the same way
# Written before the bind, items-apk and items-merge subcommands existed (tests before implementation, step 4); they are bin/chain_items.py now.
#
# The REAL chain-verify.py subcommands that bin/chain-test-harness.py only fakes. Needs: python3, ubuntu-24.04 or macOS. No network, no keys.
# Records are DSSE envelopes built here (the shape of bin/chain-rebuild-test.sh): `bind` and `items-*` never check a signature, because the
# `verify` line that runs right before `bind` in the stage script does that (the script order is pinned in bin/chain-build-wiring-test.sh).
# Every command runs from the repository root of a throw-away tree with RELATIVE paths, as the stage scripts do.
#
# THE CLI THIS TEST ASSUMES (the implementer matches it; anything else is a change to this header first):
#   chain-verify.py bind --step apk|rapk --record REC.json --dir DIR --as PREFIX      (--dir and --as are relative paths)
#     REC.json   the Witness collection of the apk matrix job (step apk, Build) or of the Rebuild apk job (step rapk). Its Statement holds product
#                subjects https://witness.dev/attestations/product/v0.1/file:PREFIX/<path relative to DIR> with digests {sha256, gitoid...}.
#                Witness runs from the repo root, so the artifact DIR is the job's `out` and PREFIX is out (in-toto-witness
#                docs/tutorials/artifact-policy.md:58-70).
#     exit 0 only when EVERY regular file under DIR is the product the record holds under PREFIX/<its path> with the same sha256, and the record
#     holds no product under PREFIX/ that has no file in DIR. Exit 1, first stderr line `refused at <build|rebuild>: <cause>: <paths>` (the paths
#     it names, space separated, as PREFIX/<path>), cause one of
#       digest   a file's sha256 differs from the product's; a file has no product; a product has no file; two products for one name;
#                a subject of another kind (material) for the name does not count; a product with no sha256 key
#       step     the record's collection name is not the --step (an apk record of Rebuild given to Build, and the reverse)
#       empty    DIR holds no file
#       symlink  DIR holds a symbolic link, to a file or to a directory, dangling or not (what it points at is not what the record covers)
#       hidden   DIR holds a file or directory whose name starts with a dot. upload-artifact leaves hidden files out of an artifact by default, so a
#                dotfile in out/ would be a product with no file after the upload: refused here instead of relied on
#       record   the file is not a DSSE envelope of a Witness collection
#     Exit 2 (usage, never a pass): an unreadable record, a missing option, --dir or --as absolute or holding `..`, an unknown --step.
#   chain-verify.py items-apk --out-dir out/ARCH --result FILE
#     reads the apks in out/ARCH by their names (fscache-VERSION-r0.apk for standard, fscache-fips-VERSION-r0.apk for fips; exactly one each) and
#     writes the fragment {"arch","items"}. The apk item is `python3 bin/apk-tool.py digest APK`, run from the working directory (cache's tool, by
#     name: the sections it covers are cache's to change; this test only needs it to differ from the whole-file sha256 and to ignore the signature).
#     The binary item is the sha256 of the stdout of `python3 bin/apk-tool.py cat APK usr/bin/fscache`. The modules SBOM and the inputs manifest
#     items are read from out/ (the parent of --out-dir), and the index item from out/ARCH/APKINDEX.tar.gz. A file or directory whose name starts
#     with a dot under out/ is refused (exit 1, cause hidden), like bind.
#   chain-verify.py items-merge --fragment F... --images DIR --archives DIR --version V --archive DIR [--digests FILE] --items FILE
#     merges the fragments and adds the image, manifest, lock and SBOM items from DIR (the files assemble-image.sh writes), the archive items from
#     --archives (the four Linux archives, goreleaser's names) and archive-checksums from --archive; writes --items and (optionally) --digests.
#     Exit 1 with nothing written, first line `refused at build: <cause>: <names>`: digest (two fragments naming one item with different values),
#     arch (the fragments are not exactly one for x86_64 and one for aarch64: a missing or a doubled architecture is named), missing (an input file
#     is missing), unexpected (a fragment names an item the committed list does not have).
# PROPOSED/UNVERIFIED: the items layout (bin/chain-test-harness.py documents the oracle) and the file names of the archives.
exec python3 - "$(cd "$(dirname "$0")/.." && pwd)" <<'PY'
import atexit, base64, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile

root = sys.argv[1]
CV = root + "/bin/chain-verify.py"
spec = importlib.util.spec_from_file_location("h", root + "/bin/chain-test-harness.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
work = tempfile.mkdtemp()
atexit.register(shutil.rmtree, work, ignore_errors=True)      # a failing or aborted run leaves nothing in TMPDIR
passed = failed = 0
PRODUCT = "https://witness.dev/attestations/product/v0.1/file:"
MATERIAL = "https://witness.dev/attestations/material/v0.1/file:"
FILES = {"x86_64/fscache-0.3.0-r0.apk": b"SIG:assembly\napk-x", "x86_64/APKINDEX.tar.gz": b"index", "items-apk.json": b"{}"}


def check(label, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("ok   " + label)
    else:
        failed += 1
        print("FAIL %s %s" % (label, detail))


def run(args, cwd):
    if not os.path.exists(CV):
        return 127, "", "bin/chain-verify.py does not exist (RED)"
    try:
        p = subprocess.run([sys.executable, CV] + args, capture_output=True, text=True, cwd=cwd, timeout=60)
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after 60 seconds"
    return p.returncode, p.stdout, p.stderr


def record(path, subjects, name="apk"):
    statement = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
                 "subject": subjects, "predicate": {"name": name, "attestations": []}}
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    json.dump({"payloadType": "application/vnd.in-toto+json", "payload": payload, "signatures": []}, open(path, "w"))


def subject(name, data, kind=PRODUCT, sha_key=True):
    digest = {"gitoid:sha1": "gitoid:blob:sha1:" + "0" * 40}
    if sha_key:
        digest["sha256"] = hashlib.sha256(data).hexdigest()
    return {"name": kind + name, "digest": digest}


def tree(name, files=FILES):
    """A throw-away repository root with the artifact in dir/ and the record in rec.json."""
    d = "%s/%s" % (work, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d + "/dir")
    for rel, data in files.items():
        os.makedirs(os.path.dirname("%s/dir/%s" % (d, rel)), exist_ok=True)
        open("%s/dir/%s" % (d, rel), "wb").write(data)
    return d


def good_subjects(files=FILES):
    return [subject("out/" + rel, data) for rel, data in files.items()]


def bind(label, d, want_rc, cause=None, names=None, step="apk", **override):
    """Run bind from the root d with relative paths, and judge the exit code, the first line and the exact set of paths it names."""
    args = {"--step": step, "--record": "rec.json", "--dir": "dir", "--as": "out"}
    args.update({"--" + k: v for k, v in override.items()})
    rc, out, err = run(["bind"] + [x for kv in args.items() for x in kv], d)
    first = err.split("\n", 1)[0]
    ok = rc == want_rc and "Traceback" not in err
    if want_rc == 1:
        ok = ok and first.startswith("refused at %s: %s: " % ("build" if step == "apk" else "rebuild", cause))
        ok = ok and (names is None or set(first.split(": ", 2)[2].split()) == set(names))
    check(label, ok, "exit %s, first line %r" % (rc, first[:160]))


check("bin/chain-verify.py exists", os.path.exists(CV), "(RED: not implemented yet; every case below needs it)")
# ---- bind ----------------------------------------------------------------------------------------------------------------------------
APK, INDEX, FRAG = "out/x86_64/fscache-0.3.0-r0.apk", "out/x86_64/APKINDEX.tar.gz", "out/items-apk.json"
d = tree("ok")
record(d + "/rec.json", good_subjects())
bind("bind: every file is the product the record holds", d, 0)

d = tree("flip")
record(d + "/rec.json", good_subjects())
open(d + "/dir/x86_64/fscache-0.3.0-r0.apk", "ab").write(b"x")
bind("bind: one changed byte in a file is refused and names it", d, 1, "digest", [APK])

d = tree("nosubject")
record(d + "/rec.json", [s for s in good_subjects() if not s["name"].endswith("items-apk.json")])
bind("bind: a file with no product in the record is refused", d, 1, "digest", [FRAG])

d = tree("nofile")
record(d + "/rec.json", good_subjects() + [subject("out/x86_64/extra.apk", b"e")])
bind("bind: a product with no file in the artifact is refused", d, 1, "digest", ["out/x86_64/extra.apk"])

d = tree("material")
record(d + "/rec.json", [subject("out/" + r, b, MATERIAL if r == "items-apk.json" else PRODUCT) for r, b in FILES.items()])
bind("bind: a material subject of the right name is not the product", d, 1, "digest", [FRAG])

d = tree("two")
record(d + "/rec.json", good_subjects() + [subject("out/items-apk.json", b"other")])
bind("bind: two products for one name are refused", d, 1, "digest", [FRAG])

d = tree("bak")
record(d + "/rec.json", [subject("out/" + r + (".bak" if r == "items-apk.json" else ""), b) for r, b in FILES.items()])
bind("bind: a product named items-apk.json.bak does not cover items-apk.json", d, 1, "digest", [FRAG, FRAG + ".bak"])

d = tree("nosha")
record(d + "/rec.json", [subject("out/" + r, b, sha_key=(r != "items-apk.json")) for r, b in FILES.items()])
bind("bind: a product with a gitoid digest and no sha256 is refused", d, 1, "digest", [FRAG])

d = tree("wrongstep")
record(d + "/rec.json", good_subjects(), name="rapk")
bind("bind: a Rebuild apk record (step rapk) given to Build (--step apk) is refused", d, 1, "step", ["rapk"])
d = tree("wrongstep2")
record(d + "/rec.json", good_subjects(), name="apk")
bind("bind: a Build apk record given to Rebuild (--step rapk) is refused", d, 1, "step", ["apk"], step="rapk")
d = tree("rapk")
record(d + "/rec.json", good_subjects(), name="rapk")
bind("bind: the Rebuild step accepts its own record", d, 0, step="rapk")

d = tree("prefix")
record(d + "/rec.json", [subject("other/" + r, b) for r, b in FILES.items()])
bind("bind: the same bytes under another prefix are not the files of --as out", d, 1, "digest", [APK, INDEX, FRAG])

d = tree("empty", {})
record(d + "/rec.json", good_subjects())
bind("bind: an empty artifact directory is refused", d, 1, "empty")

d = tree("link")
record(d + "/rec.json", good_subjects())
os.symlink("/etc/passwd", d + "/dir/x86_64/link")
bind("bind: a symbolic link to a file is refused", d, 1, "symlink", ["out/x86_64/link"])
d = tree("dirlink")
record(d + "/rec.json", good_subjects())
os.symlink("/etc", d + "/dir/x86_64/etc")
bind("bind: a symbolic link to a directory is refused (it is not walked into)", d, 1, "symlink", ["out/x86_64/etc"])
d = tree("dangling")
record(d + "/rec.json", good_subjects())
os.symlink("/nonexistent/target", d + "/dir/x86_64/gone")
bind("bind: a dangling symbolic link is refused", d, 1, "symlink", ["out/x86_64/gone"])

HIDDEN = dict(FILES, **{".secret": b"s"})
d = tree("hidden", HIDDEN)
record(d + "/rec.json", good_subjects(HIDDEN))
bind("bind: a dotfile in the artifact is refused even when the record holds it (upload-artifact would drop it)", d, 1, "hidden", ["out/.secret"])
HIDDIR = dict(FILES, **{"x86_64/.cache/x": b"s"})
d = tree("hiddendir", HIDDIR)
record(d + "/rec.json", good_subjects(HIDDIR))
bind("bind: a dot directory in the artifact is refused", d, 1, "hidden", ["out/x86_64/.cache"])

d = tree("bare")
json.dump({"_type": "x", "predicate": {}}, open(d + "/rec.json", "w"))
bind("bind: a record that is not a DSSE envelope is refused", d, 1, "record")
d = tree("unreadable")
bind("bind: an unreadable record is a usage error, never a pass", d, 2)
d = tree("abs")
record(d + "/rec.json", good_subjects())
bind("bind: an absolute --as is a usage error", d, 2, **{"as": "/out"})
d = tree("absdir")
record(d + "/rec.json", good_subjects())
bind("bind: an absolute --dir is a usage error", d, 2, dir=d + "/dir")
d = tree("dots")
record(d + "/rec.json", good_subjects())
bind("bind: a --dir holding .. is a usage error", d, 2, dir="dir/../dir")
d = tree("step")
record(d + "/rec.json", good_subjects())
bind("bind: an unknown --step is a usage error", d, 2, step="build")


# ---- items-apk: the apk digest is cache's `apk-tool.py digest`, not the whole-file sha256 ---------------------------------------------------
def apk_tree(name, tag="v0.3.0", key="assembly", edit=None):
    """A throw-away root with out/x86_64 laid out as the apk job leaves it, and the fake apk-tool in bin/."""
    d = "%s/%s" % (work, name)
    shutil.rmtree(d, ignore_errors=True)
    for rel, data in h.out_files("x86_64", tag).items():
        if rel.endswith(".apk"):
            data = h.apk_bytes("fips" if "fips" in rel else "standard", "x86_64", tag, key)
        h.write("%s/out/%s" % (d, rel), data)
    h.write(d + "/bin/apk-tool.py", h.FAKE_APKTOOL, 0o755)
    if edit:
        edit(d)
    return d


def fragment_of(d):
    rc, out, err = run(["items-apk", "--out-dir", "out/x86_64", "--result", "frag.json"], d)
    return rc, (json.load(open(d + "/frag.json")) if rc == 0 and os.path.exists(d + "/frag.json") else None), err


def flip_a_byte(d):
    open(d + "/out/x86_64/fscache-0.3.0-r0.apk", "ab").write(b"!")


def add_second_apk(d):
    h.write(d + "/out/x86_64/fscache-0.3.1-r0.apk", h.apk_bytes("standard", "x86_64", "v0.3.1"))


def add_dotfile(d):
    h.write(d + "/out/.cache/x", b"s")


d1 = apk_tree("apk1")
rc, frag1, err = fragment_of(d1)
whole = hashlib.sha256(open(d1 + "/out/x86_64/fscache-0.3.0-r0.apk", "rb").read()).hexdigest()
check("items-apk: the items are exactly the oracle's (apk by apk-tool digest, binary by apk-tool cat), and the apk item is not the whole-file sha256",
      rc == 0 and frag1 == h.fragment("x86_64", "v0.3.0") and frag1["items"]["apk-standard-x86_64"] != "sha256:" + whole, "exit %s %s" % (rc, err[:120]))
rc, frag2, err = fragment_of(apk_tree("apk2", key="release"))
check("items-apk: the same apk re-signed with another key has the same apk and binary items (the signature is not covered)",
      rc == 0 and frag1 and frag2 and frag1["items"] == frag2["items"], "exit %s" % rc)
rc, frag3, err = fragment_of(apk_tree("apk3", edit=flip_a_byte))
check("items-apk: one changed byte outside the signature changes the apk and the binary item",
      rc == 0 and frag1 and frag3 and all(frag1["items"][k] != frag3["items"][k] for k in ("apk-standard-x86_64", "binary-standard-x86_64")), "exit %s" % rc)
rc, frag4, err = fragment_of(apk_tree("apk4", tag="v0.3.0-rc.1"))
check("items-apk: a release candidate's apk (fscache-0.3.0_rc1-r0.apk, PROPOSED) is found by its variant",
      rc == 0 and frag4 == h.fragment("x86_64", "v0.3.0-rc.1"), "exit %s %s" % (rc, err[:120]))
rc, frag5, err = fragment_of(apk_tree("apk5", edit=add_second_apk))
check("items-apk: two standard apks in one directory are refused (exactly one per variant)",
      rc == 1 and err.startswith("refused at build"), "exit %s %s" % (rc, err[:100]))
rc, frag6, err = fragment_of(apk_tree("apk6", edit=add_dotfile))
check("items-apk: a dot directory under out/ is refused (upload-artifact would drop it)",
      rc == 1 and err.startswith("refused at build: hidden: "), "exit %s %s" % (rc, err[:100]))


# ---- items-merge ---------------------------------------------------------------------------------------------------------------------------
def merge_tree(name, tag="v0.3.0"):
    d = "%s/%s" % (work, name)
    shutil.rmtree(d, ignore_errors=True)
    for runner, arch, _ in h.RUNNERS:
        h.write("%s/apk/%s/items-apk.json" % (d, runner), json.dumps(h.fragment(arch, tag)))
    for image in h.IMAGES:
        o = h.image_outputs(image, tag)
        h.write("%s/out/%s.digest" % (d, image), o["digest"] + "\n")
        h.write("%s/out/%s.manifests" % (d, image), "\n".join(o["manifests"]) + "\n")
        h.write("%s/out/%s.full.lock.json" % (d, image), o["lock"])
        h.write("%s/out/%s-sbom/sbom.json" % (d, image), o["sbom"])
    for _, (file, data) in h.archive_files(tag).items():
        h.write("%s/dist/%s" % (d, file), data)
    h.write(d + "/archive/keys/wolfi-signing.rsa.pub", "w")
    h.write(d + "/archive/x86_64/pkg-1.apk", "p1")
    return d


def do_merge(d, fragments=None, tag="v0.3.0"):
    fragments = fragments or ["apk/%s/items-apk.json" % runner for runner, _, _ in h.RUNNERS]
    args = ["items-merge"] + [x for f in fragments for x in ("--fragment", f)]
    args += ["--images", "out", "--archives", "dist", "--version", tag[1:], "--archive", "archive", "--digests", "digests.json", "--items", "items.json"]
    return run(args, d)


def refused(label, d, result, cause, name=None):
    rc, out, err = result
    first = err.split("\n", 1)[0]
    written = [f for f in ("items.json", "digests.json") if os.path.exists(d + "/" + f)]
    ok = rc == 1 and first.startswith("refused at build: %s: " % cause) and (name is None or name in first.split()) and not written and "Traceback" not in err
    check(label, ok, "exit %s, first line %r, files written: %s" % (rc, first[:120], written))


d = merge_tree("m1")
rc, out, err = do_merge(d)
expected_items, expected_digests = h.expected(d, "assemble", "items", "v0.3.0"), h.expected(d, "assemble", "digests", "v0.3.0")
got_items = json.load(open(d + "/items.json")) if os.path.exists(d + "/items.json") else None
got_digests = json.load(open(d + "/digests.json")) if os.path.exists(d + "/digests.json") else None
check("items-merge: items.json is exactly the oracle's 29 items",
      rc == 0 and got_items == expected_items and len(expected_items) == 29, "exit %s %s" % (rc, err[:120]))
check("items-merge: digests.json is exactly the oracle's: 2 images, 4 apks, 4 archives, each equal to its item",
      rc == 0 and got_digests == expected_digests and len(expected_digests) == 10, "exit %s" % rc)


def edit_fragment(d, runner, edit):
    path = "%s/apk/%s/items-apk.json" % (d, runner)
    fragment = json.load(open(path))
    edit(fragment)
    h.write(path, json.dumps(fragment))


d = merge_tree("m2")
edit_fragment(d, "ubuntu-24.04-arm", lambda f: f["items"].update({"modules-sbom-standard": "sha256:" + "0" * 64}))
refused("items-merge: two fragments with different values for one item are refused and nothing is written", d, do_merge(d), "digest", "modules-sbom-standard")
d = merge_tree("m3")
edit_fragment(d, "ubuntu-24.04", lambda f: f["items"].update({"unlisted-item": "sha256:" + "0" * 64}))
refused("items-merge: an item that is not on the committed list is refused", d, do_merge(d), "unexpected", "unlisted-item")
d = merge_tree("m4")
os.remove(d + "/out/fips.manifests")
refused("items-merge: a missing image file is refused", d, do_merge(d), "missing", "fips.manifests")
d = merge_tree("m5")
os.remove(d + "/dist/" + h.archive_files("v0.3.0")["archive-fips-linux-arm64"][0])
refused("items-merge: a missing archive is refused", d, do_merge(d), "missing", "archive-fips-linux-arm64")
d = merge_tree("m6")
refused("items-merge: the same architecture twice (aarch64 missing) is refused and the missing architecture is named", d,
        do_merge(d, ["apk/ubuntu-24.04/items-apk.json"] * 2), "arch", "aarch64")
d = merge_tree("m6b")
refused("items-merge: one architecture only (aarch64 missing) is refused and named", d, do_merge(d, ["apk/ubuntu-24.04/items-apk.json"]), "arch", "aarch64")
d = merge_tree("m7", "v0.3.0-rc.1")
rc, out, err = do_merge(d, tag="v0.3.0-rc.1")
check("items-merge: a release candidate's files merge to the oracle's items (PROPOSED names)",
      rc == 0 and os.path.exists(d + "/items.json") and json.load(open(d + "/items.json")) == h.expected(d, "assemble", "items", "v0.3.0-rc.1"),
      "exit %s %s" % (rc, err[:100]))

shutil.rmtree(work, ignore_errors=True)
EXPECT = 40
print("pass=%d fail=%d" % (passed, failed))
if passed + failed != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (passed + failed, EXPECT))
    sys.exit(1)
sys.exit(1 if failed else 0)
PY
