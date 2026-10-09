#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC3 (the assemble job binds every file it uses to the verified record: rule 58), REQ-CHAIN-004-AC9 (digests.json and
#         items.json are what an honest merge writes), REQ-CHAIN-005-AC1 (Rebuild binds the same way)
# RED until bin/chain-verify.py has the bind, items-apk and items-merge subcommands (tests before implementation, step 4).
#
# The REAL chain-verify.py subcommands that bin/chain-test-harness.py only fakes. Needs: python3, ubuntu-24.04 or macOS. No network, no keys.
# Records are DSSE envelopes built here (the shape of bin/chain-rebuild-test.sh): `bind` and `items-*` never check a signature, because the
# `verify` line that runs right before `bind` in the stage script does that (the script order is pinned in bin/chain-build-wiring-test.sh).
#
# THE CLI THIS TEST ASSUMES (the implementer matches it; anything else is a change to this header first):
#   chain-verify.py bind --step apk|rapk --record REC.json --dir DIR --as PREFIX
#     REC.json   the Witness collection of the apk matrix job (step apk, Build) or of the Rebuild apk job (step rapk); its Statement holds
#                product subjects https://witness.dev/attestations/product/v0.1/file:PREFIX/<path relative to DIR> with digests {sha256, gitoid...}
#                (Witness runs from the repo root, so the artifact DIR is the job's `out` and PREFIX is out: in-toto-witness docs/tutorials/artifact-policy.md:58-70).
#     exit 0 only when EVERY regular file under DIR is the product the record holds under PREFIX/<its path> with the same sha256, and the record
#     holds no product under PREFIX/ that has no file in DIR. Exit 1, first stderr line `refused at <build|rebuild>: <cause>: <paths>` (the paths
#     it names, space separated, as PREFIX/<path>), cause one of
#       digest   a file's sha256 differs from the product's; a file has no product; a product has no file; two products for one name;
#                a subject of another kind (material) for the name does not count; a product with no sha256 key
#       step     the record's collection name is not the --step (an apk record of Rebuild given to Build, and the reverse)
#       empty    DIR holds no file
#       symlink  DIR holds a symbolic link (what it points at is not what the record covers)
#       record   the file is not a DSSE envelope of a Witness collection
#     Exit 2 (usage, never a pass): an unreadable record, a missing option, --dir or --as absolute or holding `..`, an unknown --step.
#   chain-verify.py items-apk --out-dir DIR/out/ARCH --result FILE
#     reads the apks under DIR/out/ARCH by their names (fscache-VERSION-r0.apk for standard, fscache-fips-VERSION-r0.apk for fips; exactly one each)
#     and writes the fragment {"arch","items"}; the apk item is `python3 bin/apk-tool.py digest APK` run from the working directory (cache's tool,
#     by name: the sections it covers are cache's to change; this test only needs it to differ from the whole-file sha256 and to ignore the signature).
#   chain-verify.py items-merge --fragment F... --images DIR --archives DIR --version V --archive DIR [--digests FILE] --items FILE
#     merges the fragments (two fragments naming one item with different values is a refusal: exit 1 `refused at build: digest: <item>`, nothing
#     written), adds the image, manifest, lock and SBOM items from DIR (the files assemble-image.sh writes), the archive items from --archives (the four
#     Linux archives, goreleaser's names) and archive-checksums from --archive, writes --items and (optionally) --digests. Exit 1 when an input file
#     is missing ("missing") or a fragment names an item the committed list does not have ("unexpected"), with nothing written.
# PROPOSED/UNVERIFIED: the items layout (bin/chain-test-harness.py documents the oracle) and the file names of the archives.
exec python3 - "$(cd "$(dirname "$0")/.." && pwd)" <<'PY'
import base64, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile
root = sys.argv[1]
CV = root + "/bin/chain-verify.py"
spec = importlib.util.spec_from_file_location("h", root + "/bin/chain-test-harness.py"); h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
work = tempfile.mkdtemp()
passed = failed = 0


def check(label, ok, detail=""):
    global passed, failed
    if ok: passed += 1; print("ok   " + label)
    else: failed += 1; print("FAIL %s %s" % (label, detail))


def run(args, cwd=None):
    if not os.path.exists(CV):
        return 127, "", "bin/chain-verify.py does not exist (RED)"
    p = subprocess.run([sys.executable, CV] + args, capture_output=True, text=True, cwd=cwd)
    return p.returncode, p.stdout, p.stderr


PRODUCT = "https://witness.dev/attestations/product/v0.1/file:"
MATERIAL = "https://witness.dev/attestations/material/v0.1/file:"


def record(path, subjects, name="apk"):
    st = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
          "subject": subjects, "predicate": {"name": name, "attestations": []}}
    env = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(st).encode()).decode(), "signatures": []}
    json.dump(env, open(path, "w"))


def subject(name, data, kind=PRODUCT, sha_key=True):
    d = {"gitoid:sha1": "gitoid:blob:sha1:" + "0" * 40}
    if sha_key: d["sha256"] = hashlib.sha256(data).hexdigest()
    return {"name": kind + name, "digest": d}


FILES = {"x86_64/fscache-0.3.0-r0.apk": b"SIG:assembly\napk-x", "x86_64/APKINDEX.tar.gz": b"index", "items-apk.json": b"{}"}


def tree(name, files=FILES):
    d = "%s/%s" % (work, name); shutil.rmtree(d, ignore_errors=True)
    for rel, b in files.items():
        p = "%s/dir/%s" % (d, rel); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "wb").write(b)
    return d


def good_subjects(files=FILES):
    return [subject("out/" + rel, b) for rel, b in files.items()]


def bind(label, d, want_rc, cause=None, names=None, step="apk", extra=None):
    """Run bind in tree d (record at d/rec.json) and judge exit code, first line, and the exact set of paths named."""
    args = ["bind", "--step", step, "--record", d + "/rec.json", "--dir", d + "/dir", "--as", "out"]
    for k, v in (extra or {}).items():
        args[args.index(k) + 1] = v
    rc, out, err = run(args)
    first = err.split("\n", 1)[0]
    ok = rc == want_rc and "Traceback" not in err
    if want_rc == 1:
        ok = ok and first.startswith("refused at %s: %s: " % ("build" if step == "apk" else "rebuild", cause))
        ok = ok and (names is None or set(first.split(": ", 2)[2].split()) == set(names))
    check(label, ok, "exit %s, first line %r" % (rc, first[:160]))


check("bin/chain-verify.py exists", os.path.exists(CV), "(RED: not implemented yet; every case below needs it)")
# ---- bind ------------------------------------------------------------------------------------------------------------------------------
d = tree("ok"); record(d + "/rec.json", good_subjects()); bind("bind: every file is the product the record holds", d, 0)

d = tree("flip"); record(d + "/rec.json", good_subjects()); open(d + "/dir/x86_64/fscache-0.3.0-r0.apk", "ab").write(b"x")
bind("bind: one changed byte in a file is refused and names it", d, 1, "digest", ["out/x86_64/fscache-0.3.0-r0.apk"])

d = tree("nosubject"); record(d + "/rec.json", [s for s in good_subjects() if not s["name"].endswith("items-apk.json")])
bind("bind: a file with no product in the record is refused", d, 1, "digest", ["out/items-apk.json"])

d = tree("nofile"); record(d + "/rec.json", good_subjects() + [subject("out/x86_64/extra.apk", b"e")])
bind("bind: a product with no file in the artifact is refused", d, 1, "digest", ["out/x86_64/extra.apk"])

d = tree("material"); record(d + "/rec.json", [subject("out/" + r, b, MATERIAL if r == "items-apk.json" else PRODUCT) for r, b in FILES.items()])
bind("bind: a material subject of the right name is not the product", d, 1, "digest", ["out/items-apk.json"])

d = tree("two"); record(d + "/rec.json", good_subjects() + [subject("out/items-apk.json", b"other")])
bind("bind: two products for one name are refused", d, 1, "digest", ["out/items-apk.json"])

d = tree("bak"); record(d + "/rec.json", [subject("out/" + r + (".bak" if r == "items-apk.json" else ""), b) for r, b in FILES.items()])
bind("bind: a product named items-apk.json.bak does not cover items-apk.json", d, 1, "digest", ["out/items-apk.json", "out/items-apk.json.bak"])

d = tree("nosha"); record(d + "/rec.json", [subject("out/" + r, b, sha_key=(r != "items-apk.json")) for r, b in FILES.items()])
bind("bind: a product with a gitoid digest and no sha256 is refused", d, 1, "digest", ["out/items-apk.json"])

d = tree("wrongstep"); record(d + "/rec.json", good_subjects(), name="rapk")
bind("bind: a Rebuild apk record (step rapk) given to Build (--step apk) is refused", d, 1, "step", ["rapk"])
d = tree("wrongstep2"); record(d + "/rec.json", good_subjects(), name="apk")
bind("bind: a Build apk record given to Rebuild (--step rapk) is refused", d, 1, "step", ["apk"], step="rapk")
d = tree("rapk"); record(d + "/rec.json", good_subjects(), name="rapk"); bind("bind: the Rebuild step accepts its own record", d, 0, step="rapk")

d = tree("prefix"); record(d + "/rec.json", [subject("other/" + r, b) for r, b in FILES.items()])
bind("bind: the same bytes under another prefix are not the files of --as out", d, 1, "digest",
     ["out/x86_64/fscache-0.3.0-r0.apk", "out/x86_64/APKINDEX.tar.gz", "out/items-apk.json"])

d = tree("empty", {}); os.makedirs(d + "/dir"); record(d + "/rec.json", good_subjects())
bind("bind: an empty artifact directory is refused", d, 1, "empty", None)
d = tree("link"); record(d + "/rec.json", good_subjects()); os.symlink("/etc/passwd", d + "/dir/x86_64/link")
bind("bind: a symbolic link in the artifact is refused", d, 1, "symlink", ["out/x86_64/link"])
d = tree("bare"); json.dump({"_type": "x", "predicate": {}}, open(d + "/rec.json", "w")); bind("bind: a record that is not a DSSE envelope is refused", d, 1, "record", None)
d = tree("unreadable"); bind("bind: an unreadable record is a usage error, never a pass", d, 2)
d = tree("abs"); record(d + "/rec.json", good_subjects()); bind("bind: an absolute --as is a usage error", d, 2, extra={"--as": "/out"})
d = tree("dots"); record(d + "/rec.json", good_subjects()); bind("bind: a --dir holding .. is a usage error", d, 2, extra={"--dir": d + "/dir/../dir"})
d = tree("step"); record(d + "/rec.json", good_subjects()); bind("bind: an unknown --step is a usage error", d, 2, step="build")

# ---- items-apk: the apk digest is cache's `apk-tool.py digest`, not the whole-file sha256 --------------------------------------------------
def apk_tree(name, tag="v0.3.0", key="assembly", edit=None):
    d = "%s/%s" % (work, name); shutil.rmtree(d, ignore_errors=True)
    for rel, b in h.out_files("x86_64", tag).items():
        if rel.endswith(".apk"): b = h.apk_bytes("standard" if "fips" not in rel else "fips", "x86_64", tag, key)
        h.write("%s/out/%s" % (d, rel), b)
    h.write(d + "/bin/apk-tool.py", h.FAKE_APKTOOL, 0o755)
    if edit: edit(d)
    return d


def fragment_of(d):
    rc, out, err = run(["items-apk", "--out-dir", d + "/out/x86_64", "--result", d + "/frag.json"], cwd=d)
    return rc, (json.load(open(d + "/frag.json")) if rc == 0 and os.path.exists(d + "/frag.json") else None), err


d1 = apk_tree("apk1"); rc, f1, err = fragment_of(d1)
whole = hashlib.sha256(open(d1 + "/out/x86_64/fscache-0.3.0-r0.apk", "rb").read()).hexdigest()
check("items-apk: the apk item is the oracle's apk-tool digest, and it is not the whole-file sha256",
      rc == 0 and f1 == h.fragment("x86_64", "v0.3.0") and f1["items"]["apk-standard-x86_64"] != "sha256:" + whole, "exit %s %s" % (rc, err[:120]))
d2 = apk_tree("apk2", key="release"); rc, f2, err = fragment_of(d2)
check("items-apk: the same apk re-signed with another key has the same item (the signature is not covered)",
      rc == 0 and f1 and f2 and f1["items"]["apk-standard-x86_64"] == f2["items"]["apk-standard-x86_64"], "exit %s" % rc)
def flip(d):
    p = d + "/out/x86_64/fscache-0.3.0-r0.apk"; open(p, "ab").write(b"!")
d3 = apk_tree("apk3", edit=flip); rc, f3, err = fragment_of(d3)
check("items-apk: one changed byte outside the signature changes the item", rc == 0 and f1 and f3 and f1["items"]["apk-standard-x86_64"] != f3["items"]["apk-standard-x86_64"], "exit %s" % rc)
d4 = apk_tree("apk4", tag="v0.3.0-rc.1"); rc, f4, err = fragment_of(d4)
check("items-apk: a release candidate's apk (fscache-0.3.0_rc1-r0.apk, PROPOSED) is found by its variant", rc == 0 and f4 == h.fragment("x86_64", "v0.3.0-rc.1"), "exit %s %s" % (rc, err[:120]))
def two(d):
    h.write(d + "/out/x86_64/fscache-0.3.1-r0.apk", h.apk_bytes("standard", "x86_64", "v0.3.1"))
d5 = apk_tree("apk5", edit=two); rc, f5, err = fragment_of(d5)
check("items-apk: two standard apks in one directory are refused (exactly one per variant)", rc == 1 and err.startswith("refused at build"), "exit %s %s" % (rc, err[:100]))

# ---- items-merge ------------------------------------------------------------------------------------------------------------------------
def merge_tree(name, tag="v0.3.0"):
    d = "%s/%s" % (work, name); shutil.rmtree(d, ignore_errors=True)
    for r, a, g in h.RUNNERS:
        h.write("%s/apk/%s/items-apk.json" % (d, r), json.dumps(h.fragment(a, tag)))
    for i in h.IMAGES:
        o = h.image_outputs(i, tag)
        h.write("%s/out/%s.digest" % (d, i), o["digest"] + "\n"); h.write("%s/out/%s.manifests" % (d, i), "\n".join(o["manifests"]) + "\n")
        h.write("%s/out/%s.full.lock.json" % (d, i), o["lock"]); h.write("%s/out/%s-sbom/sbom.json" % (d, i), o["sbom"])
    for k, (n, b) in h.archive_files(tag).items():
        h.write("%s/dist/%s" % (d, n), b)
    h.write(d + "/archive/keys/wolfi-signing.rsa.pub", "w"); h.write(d + "/archive/x86_64/pkg-1.apk", "p1")
    return d


def do_merge(d, frags=None, tag="v0.3.0"):
    frags = frags or ["apk/%s/items-apk.json" % r for r, _, _ in h.RUNNERS]
    args = ["items-merge"] + [x for f in frags for x in ("--fragment", d + "/" + f)] + ["--images", d + "/out", "--archives", d + "/dist", "--version", tag[1:], "--archive", d + "/archive",
            "--digests", d + "/digests.json", "--items", d + "/items.json"]
    return run(args)


def refused(label, d, rc_err, word, item=None):
    rc, out, err = rc_err
    first = err.split("\n", 1)[0]
    ok = rc == 1 and first.startswith("refused at build: %s: " % word) and (item is None or item in first.split()) \
        and not os.path.exists(d + "/items.json") and not os.path.exists(d + "/digests.json") and "Traceback" not in err
    check(label, ok, "exit %s, first line %r, files written: %s" % (rc, first[:120], [f for f in ("items.json", "digests.json") if os.path.exists(d + "/" + f)]))


d = merge_tree("m1"); rc, out, err = do_merge(d)
exp_items, exp_dig = h.expected(d, "assemble", "items", "v0.3.0"), h.expected(d, "assemble", "digests", "v0.3.0")
got_items = json.load(open(d + "/items.json")) if os.path.exists(d + "/items.json") else None
got_dig = json.load(open(d + "/digests.json")) if os.path.exists(d + "/digests.json") else None
check("items-merge: items.json is exactly the oracle's 29 items", rc == 0 and got_items == exp_items and len(exp_items) == 29, "exit %s %s" % (rc, err[:120]))
check("items-merge: digests.json is exactly the oracle's: 2 images, 4 apks, 4 archives, each equal to its item", rc == 0 and got_dig == exp_dig and len(exp_dig) == 10, "exit %s" % rc)

d = merge_tree("m2"); fr = json.load(open(d + "/apk/ubuntu-24.04-arm/items-apk.json")); fr["items"]["modules-sbom-standard"] = "sha256:" + "0" * 64
h.write(d + "/apk/ubuntu-24.04-arm/items-apk.json", json.dumps(fr)); refused("items-merge: two fragments with different values for one item are refused and nothing is written", d, do_merge(d), "digest", "modules-sbom-standard")
d = merge_tree("m3"); fr = json.load(open(d + "/apk/ubuntu-24.04/items-apk.json")); fr["items"]["unlisted-item"] = "sha256:" + "0" * 64
h.write(d + "/apk/ubuntu-24.04/items-apk.json", json.dumps(fr)); refused("items-merge: an item that is not on the committed list is refused", d, do_merge(d), "unexpected", "unlisted-item")
d = merge_tree("m4"); os.remove(d + "/out/fips.manifests"); refused("items-merge: a missing image file is refused", d, do_merge(d), "missing", "fips.manifests")
d = merge_tree("m5"); os.remove(d + "/dist/" + h.archive_files("v0.3.0")["archive-fips-linux-arm64"][0]); refused("items-merge: a missing archive is refused", d, do_merge(d), "missing", "archive-fips-linux-arm64")
d = merge_tree("m6"); refused("items-merge: the same fragment twice (one architecture missing) is refused", d, do_merge(d, ["apk/ubuntu-24.04/items-apk.json"] * 2), "digest")
d = merge_tree("m7", "v0.3.0-rc.1"); rc, out, err = do_merge(d, tag="v0.3.0-rc.1")
check("items-merge: a release candidate's files merge to the oracle's items (PROPOSED names)", rc == 0 and os.path.exists(d + "/items.json") and json.load(open(d + "/items.json")) == h.expected(d, "assemble", "items", "v0.3.0-rc.1"), "exit %s %s" % (rc, err[:100]))

shutil.rmtree(work, ignore_errors=True)
EXPECT = 33
print("pass=%d fail=%d" % (passed, failed))
if passed + failed != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (passed + failed, EXPECT)); sys.exit(1)
sys.exit(1 if failed else 0)
PY
