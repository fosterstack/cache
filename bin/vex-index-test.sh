#!/usr/bin/env bash
# proves: REQ-REL-010-AC1, REQ-REL-010-AC2, REQ-REL-010-AC3, REQ-REL-010-AC4
#
# Tests for bin/vex-index.py, the tool that derives the FINAL image index from the built index and the
# release's VEX file (REQ-REL-010). The tool is driven through its command line only (compute, verify,
# push). Everything runs offline: the push cases talk to a fake distribution registry that this file starts
# on 127.0.0.1 (ephemeral port) and that records every request.
#
# The expected bytes are computed here, by an independent re-statement of the canonical form (ref_compute),
# and one fixture carries hand-checked golden digests, so a tool that is self-consistent but serialises
# differently fails.
#
# VEX_INDEX=/path/to/tool.py runs the same tests against another copy of the tool (default bin/vex-index.py).
# Needs python3 (stdlib only). Exit status is non-zero when any case fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT
export VEX_INDEX="${VEX_INDEX:-$ROOT/bin/vex-index.py}"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

cat >"$T/harness.py" <<'PYEOF'
import ast, base64, hashlib, http.server, json, os, random, re, shutil, socket, subprocess, sys
import tempfile, threading, time, urllib.parse

ROOT = os.environ["ROOT"]
TOOL = os.environ["VEX_INDEX"]
TMP = tempfile.mkdtemp(prefix="vexidx-cases-")
USER, SECRET = "ci-user", "s3cr3t-T0KEN-value-9f2c"
PRED = "https://openvex.dev/ns/v0.2.0"
OCI_IDX = "application/vnd.oci.image.index.v1+json"
OCI_MAN = "application/vnd.oci.image.manifest.v1+json"
OCI_CFG = "application/vnd.oci.image.config.v1+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_MAN = "application/vnd.docker.distribution.manifest.v2+json"
STMT_TYPE = "https://in-toto.io/Statement/v0.1"
SUBJECT_NAME = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class Fail(Exception):
    pass


def ok(cond, msg="assertion failed"):
    if not cond:
        raise Fail(msg)


def short(x):
    s = repr(x)
    return s if len(s) < 300 else s[:300] + "...<%d chars>" % len(s)


def eq(a, b, msg):
    if a != b:
        raise Fail("%s: got %s want %s" % (msg, short(a), short(b)))


CASES = []


def case(tag, name):
    def deco(f):
        CASES.append((tag, name, f, None))
        return f
    return deco


def param(tag, name, items):
    def deco(f):
        for label, arg in items:
            CASES.append((tag, "%s [%s]" % (name, label), f, arg))
        return f
    return deco


# ------------------------------------------------------------------ plumbing
def sb():
    return tempfile.mkdtemp(dir=TMP)


def wr(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def rd(path):
    with open(path, "rb") as f:
        return f.read()


class R:
    def __init__(self, rc, out, err):
        self.rc, self.out, self.err = rc, out, err


def base_env():
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("FSCACHE_") or k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy") or k == "PYTHONHASHSEED":
            del e[k]
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    return e


def run(args, env=None, cwd=None, replace_env=False, timeout=90):
    if not os.path.isfile(TOOL):
        raise Fail("the tool %s does not exist" % TOOL)
    if replace_env:
        e = {"PATH": os.environ["PATH"]}
        for k in ("MUT", "MUT_BASE"):
            if k in os.environ:
                e[k] = os.environ[k]
    else:
        e = base_env()
    for k, v in (env or {}).items():
        if v is None:
            e.pop(k, None)
        else:
            e[k] = v
    try:
        p = subprocess.run([sys.executable, TOOL] + list(args), env=e, cwd=cwd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Fail("the tool did not finish within %ds" % timeout)
    return R(p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"))


def tree(d):
    out = {}
    for base, dirs, files in os.walk(d):
        for n in dirs:
            p = os.path.join(base, n)
            if os.path.islink(p):
                out[os.path.relpath(p, d) + "@link"] = os.readlink(p)
            else:
                out[os.path.relpath(p, d) + "/"] = b""
        for n in files:
            p = os.path.join(base, n)
            out[os.path.relpath(p, d)] = rd(p) if not os.path.islink(p) else os.readlink(p).encode()
    return out


# ------------------------------------------------------------------ independent canonical form
def cj(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def dg(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def hx(d):
    return d.split(":", 1)[1]


def ref_att(pdigest, vex_obj):
    stmt = cj({"_type": STMT_TYPE, "predicateType": PRED,
               "subject": [{"name": SUBJECT_NAME, "digest": {"sha256": hx(pdigest)}}], "predicate": vex_obj})
    layer = {"mediaType": "application/vnd.in-toto+json", "digest": dg(stmt), "size": len(stmt),
             "annotations": {"in-toto.io/predicate-type": PRED}}
    cfg = cj({"architecture": "unknown", "created": "1970-01-01T00:00:00Z", "os": "unknown",
              "rootfs": {"diff_ids": [dg(stmt)], "type": "layers"}})
    cdesc = {"mediaType": OCI_CFG, "digest": dg(cfg), "size": len(cfg)}
    man = cj({"schemaVersion": 2, "mediaType": OCI_MAN, "config": cdesc, "layers": [layer]})
    desc = {"mediaType": OCI_MAN, "digest": dg(man), "size": len(man),
            "annotations": {"vnd.docker.reference.digest": pdigest, "vnd.docker.reference.type": "attestation-manifest"},
            "platform": {"architecture": "unknown", "os": "unknown"}}
    return desc, {"stmt": stmt, "cfg": cfg, "man": man}


def pkey(e):
    p = e["platform"]
    return "%s/%s" % (p["os"], p["architecture"]) + ("/" + p["variant"] if p.get("variant") else "")


def ref_compute(db, vb):
    d = json.loads(db.decode("utf-8"))
    vex = json.loads(vb.decode("utf-8"))
    descs, blobs, plats = [], {}, {}
    for e in d["manifests"]:
        if e["platform"]["os"] == "unknown":
            continue
        desc, parts = ref_att(e["digest"], vex)
        descs.append(desc)
        for b in parts.values():
            blobs[hx(dg(b))] = b
        plats[pkey(e)] = {"platform_digest": e["digest"], "attestation_digest": desc["digest"]}
    f = dict(d)
    f["manifests"] = list(d["manifests"]) + descs
    fb = cj(f)
    result = {"base_digest": dg(db), "final_digest": dg(fb), "platforms": plats, "vex_sha256": hashlib.sha256(vb).hexdigest()}
    return fb, blobs, result


def norm_result(r):
    r = json.loads(json.dumps(r))
    v = r.get("vex_sha256")
    if isinstance(v, str) and v.startswith("sha256:"):
        r["vex_sha256"] = v[7:]
    return r


# ------------------------------------------------------------------ fixtures
def mk_child(arch, variant=None, mt=OCI_MAN, os_="linux"):
    seed = "%s/%s/%s" % (os_, arch, variant)
    cfg = cj({"architecture": arch, "os": os_, "config": {"Entrypoint": ["/fscache"]},
              "rootfs": {"type": "layers", "diff_ids": [dg(("layer:" + seed).encode())]}})
    layer = ("layer-bytes:" + seed + ":" + "x" * 300).encode()
    man = {"schemaVersion": 2, "mediaType": mt,
           "config": {"mediaType": OCI_CFG if mt == OCI_MAN else "application/vnd.docker.container.image.v1+json",
                      "digest": dg(cfg), "size": len(cfg)},
           "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": dg(layer), "size": len(layer)}]}
    b = json.dumps(man, indent=2).encode()
    return {"bytes": b, "digest": dg(b), "size": len(b), "mt": mt, "arch": arch, "variant": variant, "os": os_,
            "blobs": {dg(cfg): cfg, dg(layer): layer}}


def desc_of(ch):
    p = {"architecture": ch["arch"], "os": ch["os"]}
    if ch["variant"]:
        p["variant"] = ch["variant"]
    return {"mediaType": ch["mt"], "digest": ch["digest"], "size": ch["size"], "platform": p}


class FX:
    pass


def mk_fx(kind="oci", plats=(("amd64", None), ("arm64", None)), indent=2, no_mt=False, extra_top=None,
          unknown=False, extra_entry=None):
    f = FX()
    cmt = OCI_MAN if kind == "oci" else DOCKER_MAN
    f.children = [mk_child(a, v, cmt) for a, v in plats]
    entries = [desc_of(c) for c in f.children]
    if extra_entry:
        for e in entries:
            e.update(json.loads(json.dumps(extra_entry)))
    if unknown:
        junk = ("not-an-image:" + "u" * 40).encode()
        entries.append({"mediaType": OCI_MAN, "digest": dg(junk), "size": len(junk),
                        "platform": {"architecture": "unknown", "os": "unknown"}})
    obj = {"schemaVersion": 2}
    if not no_mt:
        obj["mediaType"] = OCI_IDX if kind == "oci" else DOCKER_LIST
    obj["manifests"] = entries
    if extra_top:
        obj.update(extra_top)
    f.obj = obj
    f.bytes = json.dumps(obj, indent=indent).encode("utf-8") + b"\n" if indent else json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return f


VEX_REAL = rd(os.path.join(ROOT, ".vex", "fosterstack-cache.openvex.json")) if os.path.isfile(os.path.join(ROOT, ".vex", "fosterstack-cache.openvex.json")) else None
VEX_MIN = ('{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"Example Co",'
           '"timestamp":"2026-01-01T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2000-0001"},'
           '"products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}],"status":"not_affected",'
           '"justification":"component_not_present","impact_statement":"naïve — ok"}]}').encode("utf-8")


def vex_real():
    if VEX_REAL is None:
        raise Fail("the repository's VEX file .vex/fosterstack-cache.openvex.json is missing")
    return VEX_REAL


def reindent_json(b, indent=4, reverse=False):
    o = json.loads(b.decode("utf-8"))

    def rev(x):
        if isinstance(x, dict):
            return {k: rev(x[k]) for k in reversed(list(x))}
        if isinstance(x, list):
            return [rev(i) for i in x]
        return x
    if reverse:
        o = rev(o)
    return json.dumps(o, indent=indent, ensure_ascii=False).encode("utf-8")


EXTRAS = dict(extra_top={"annotations": {"org.opencontainers.image.description": "Café — résumé \U0001F680"}},
              extra_entry={"annotations": {"com.example.note": "käse"}})

FIXTURES = {
    "oci-2-platform": lambda: mk_fx(),
    "oci-compact-no-indent": lambda: mk_fx(indent=None),
    "docker-manifest-list": lambda: mk_fx(kind="docker"),
    "arm-v7-variant": lambda: mk_fx(plats=(("amd64", None), ("arm64", "v8"), ("arm", "v7"))),
    "unknown-unknown-entry": lambda: mk_fx(unknown=True),
    "no-mediaType": lambda: mk_fx(no_mt=True),
    "single-platform": lambda: mk_fx(plats=(("amd64", None),)),
    "extra-fields-and-non-ascii": lambda: mk_fx(**EXTRAS),
}


# ------------------------------------------------------------------ compute helpers
def do_compute(db, vb, out=None, env=None, cwd=None, replace_env=False, s=None):
    s = s or sb()
    i = wr(os.path.join(s, "in", "index.json"), db)
    v = wr(os.path.join(s, "in", "vex.json"), vb)
    out = out or os.path.join(s, "out")
    r = run(["compute", "--index", i, "--vex", v, "--out-dir", out], env=env, cwd=cwd, replace_env=replace_env)
    r.dir, r.s, r.index, r.vex = out, s, i, v
    return r


def expected_tree(db, vb):
    fb, blobs, result = ref_compute(db, vb)
    t = {"index.json": fb}
    for h, b in blobs.items():
        t["blobs/sha256/" + h] = b
    return t, result, fb


def check_matches_ref(db, vb, r):
    ok(r.rc == 0, "compute failed rc=%d: %s" % (r.rc, r.err.strip()[:300]))
    exp, result, fb = expected_tree(db, vb)
    eq(r.out, dg(fb) + "\n", "stdout must be exactly the final digest and a newline")
    got = tree(r.dir)
    rj = got.pop("result.json", None)
    ok(rj is not None, "result.json missing")
    for k in list(got):
        if k.endswith("/"):
            del got[k]
    eq(sorted(got), sorted(exp), "the set of files written")
    for k in exp:
        ok(got[k] == exp[k], "file %s differs from the independently computed bytes" % k)
    eq(norm_result(json.loads(rj)), result, "result.json")
    ok(dg(got["index.json"]) == r.out.strip(), "stdout digest is not the digest of index.json")


# ------------------------------------------------------------------ hand-checked golden values
# golden values: derived by hand with printf and shasum from the canonical text in the spec, not with this file's code
GOLD_AMD64 = "sha256:2d91865d212d533a3907e00dda39543d517da46982daafbd03576a8afa818fef"  # sha256 of the text gold-amd64
GOLD_ARM64 = "sha256:883a34ed8c170ccfacf0a2c511412183f48d22bf5dae8394520158b9bf843aed"  # sha256 of the text gold-arm64


def gold_index():
    return ('{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":['
            '{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1234,'
            '"platform":{"architecture":"amd64","os":"linux"}},'
            '{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1235,'
            '"platform":{"architecture":"arm64","os":"linux"}}]}\n' % (GOLD_AMD64, GOLD_ARM64)).encode()


GOLD = {
    "final_digest": "sha256:eb882dab43f2e8542abd14fb070fab3b89cd9baedca8f3f02a8659af6d566358",
    "amd64_statement": "sha256:e0c1737d74409e862ff3ddb3e348e51f80d7933f05fa4a2a76fdbcf07103c24d",
    "amd64_config": "sha256:493b0bb1f5216f705c436388bf8db6a9c5f371b25cf955f69a76b66b6b1720fb",
    "amd64_attestation": "sha256:6cc387fc7d6e31be56b07ed106c596e7be58be94907eba4e6e65c54b284949c0",
}


@case("AC1", "hand-checked golden digests for a fixed index and a fixed VEX (a different but self-consistent serialisation fails)")
def _():
    r = do_compute(gold_index(), VEX_MIN)
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:300])
    eq(r.out, GOLD["final_digest"] + "\n", "final digest")
    res = json.loads(rd(os.path.join(r.dir, "result.json")))
    eq(res["platforms"]["linux/amd64"]["attestation_digest"], GOLD["amd64_attestation"], "amd64 attestation manifest digest")
    blobs = os.listdir(os.path.join(r.dir, "blobs", "sha256"))
    for want in (GOLD["amd64_statement"], GOLD["amd64_config"], GOLD["amd64_attestation"]):
        ok(hx(want) in blobs, "golden blob %s was not written" % want)


# ------------------------------------------------------------------ AC1: exact output, determinism, purity
@param("AC1", "compute output equals the independently computed canonical bytes", list(FIXTURES.items()))
def _(mk):
    fx = mk()
    check_matches_ref(fx.bytes, vex_real(), do_compute(fx.bytes, vex_real()))


@case("AC1", "the same inputs give byte-identical output trees, even a second apart (no clock in the output)")
def _():
    fx = FIXTURES["extra-fields-and-non-ascii"]()
    a = do_compute(fx.bytes, vex_real())
    time.sleep(1.2)
    b = do_compute(fx.bytes, vex_real())
    ok(a.rc == 0 and b.rc == 0, "compute failed")
    eq(tree(a.dir), tree(b.dir), "output tree of the second run")
    eq(a.out, b.out, "stdout")


ENVS = [
    ("PYTHONHASHSEED=0", {"PYTHONHASHSEED": "0"}), ("PYTHONHASHSEED=1", {"PYTHONHASHSEED": "1"}),
    ("PYTHONHASHSEED=4294967295", {"PYTHONHASHSEED": "4294967295"}), ("PYTHONHASHSEED=random", {"PYTHONHASHSEED": "random"}),
    ("LC_ALL=C", {"LC_ALL": "C", "LANG": "C"}), ("LC_ALL=C.UTF-8", {"LC_ALL": "C.UTF-8"}),
    ("LC_ALL=en_US.UTF-8", {"LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"}),
    ("LC_ALL=tr_TR.UTF-8", {"LC_ALL": "tr_TR.UTF-8", "LANG": "tr_TR.UTF-8"}),
    ("TZ=Pacific/Kiritimati", {"TZ": "Pacific/Kiritimati"}), ("TZ=America/St_Johns", {"TZ": "America/St_Johns"}),
    ("PYTHONIOENCODING=ascii PYTHONUTF8=0", {"PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0"}),
    ("PYTHONUTF8=1", {"PYTHONUTF8": "1"}),
    ("PYTHONOPTIMIZE=1", {"PYTHONOPTIMIZE": "1"}),
    ("umask-independent HOME unset", {"HOME": None}),
]
BASE_TREE = {}


def base_tree():
    if "t" not in BASE_TREE:
        fx = FIXTURES["extra-fields-and-non-ascii"]()
        BASE_TREE["fx"] = fx
        r = do_compute(fx.bytes, vex_real())
        ok(r.rc == 0, "baseline compute failed: " + r.err.strip()[:200])
        BASE_TREE["t"] = tree(r.dir)
    return BASE_TREE["fx"], BASE_TREE["t"]


@param("AC1", "output is identical under a different process environment", ENVS)
def _(env):
    fx, t = base_tree()
    r = do_compute(fx.bytes, vex_real(), env=env)
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:200])
    eq(tree(r.dir), t, "output tree")


@case("AC1", "output is identical with an empty environment (nothing but PATH)")
def _():
    fx, t = base_tree()
    r = do_compute(fx.bytes, vex_real(), replace_env=True)
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:200])
    eq(tree(r.dir), t, "output tree")


@case("AC1", "output is identical from another working directory with relative paths")
def _():
    fx, t = base_tree()
    s = sb()
    w = os.path.join(s, "somewhere", "else")
    wr(os.path.join(w, "d.json"), fx.bytes)
    wr(os.path.join(w, "v.json"), vex_real())
    r = run(["compute", "--index", "d.json", "--vex", "v.json", "--out-dir", "o"], cwd=w)
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:200])
    eq(tree(os.path.join(w, "o")), t, "output tree")


@case("AC1", "output does not depend on the inputs' modification times")
def _():
    fx, t = base_tree()
    for stamp in (1, 2000000000):
        s = sb()
        i = wr(os.path.join(s, "i.json"), fx.bytes)
        v = wr(os.path.join(s, "v.json"), vex_real())
        for p in (i, v):
            os.utime(p, (stamp, stamp))
        r = run(["compute", "--index", i, "--vex", v, "--out-dir", os.path.join(s, "o")])
        ok(r.rc == 0, "compute failed")
        eq(tree(os.path.join(s, "o")), t, "output tree for mtime %d" % stamp)


@case("AC1", "reordering and re-indenting the index's keys and whitespace changes neither F nor any blob (only base_digest follows the raw bytes)")
def _():
    fx, t = base_tree()
    d2 = reindent_json(fx.bytes, indent=7, reverse=True) + b"\n\n"
    ok(d2 != fx.bytes, "fixture not different")
    r = do_compute(d2, vex_real())
    ok(r.rc == 0, "compute failed")
    got = tree(r.dir)
    for k in t:
        if k != "result.json":
            ok(got.get(k) == t[k], "%s changed when only the index's key order/whitespace changed" % k)
    a, b = json.loads(t["result.json"]), json.loads(got["result.json"])
    eq(b["base_digest"], dg(d2), "base_digest must be the digest of the raw index bytes")
    ok(b["base_digest"] != a["base_digest"], "base_digest should follow the raw bytes")
    a.pop("base_digest"), b.pop("base_digest")
    eq(b, a, "the rest of result.json")


@case("AC1", "reordering and re-indenting the VEX file's keys changes nothing in F or the blobs (the predicate is canonicalised)")
def _():
    fx, t = base_tree()
    v2 = reindent_json(vex_real(), indent=1, reverse=True) + b"\n"
    ok(v2 != vex_real(), "fixture not different")
    r = do_compute(fx.bytes, v2)
    ok(r.rc == 0, "compute failed")
    got = tree(r.dir)
    for k in t:
        if k != "result.json":
            ok(got.get(k) == t[k], "%s changed when only the VEX's key order/whitespace changed" % k)
    res = norm_result(json.loads(got["result.json"]))
    eq(res["vex_sha256"], hashlib.sha256(v2).hexdigest(), "vex_sha256 is the digest of the VEX file's bytes")


@case("AC1", "changing the VEX content changes every attestation digest and F, and no platform digest")
def _():
    fx = FIXTURES["arm-v7-variant"]()
    a = do_compute(fx.bytes, vex_real())
    vex = json.loads(vex_real().decode("utf-8"))
    vex["version"] += 1
    b = do_compute(fx.bytes, json.dumps(vex).encode("utf-8"))
    ok(a.rc == 0 and b.rc == 0, "compute failed")
    ra, rb = json.loads(rd(os.path.join(a.dir, "result.json"))), json.loads(rd(os.path.join(b.dir, "result.json")))
    ok(ra["final_digest"] != rb["final_digest"], "F did not change")
    eq(sorted(ra["platforms"]), sorted(rb["platforms"]), "platform keys")
    for k in ra["platforms"]:
        eq(ra["platforms"][k]["platform_digest"], rb["platforms"][k]["platform_digest"], "platform digest " + k)
        ok(ra["platforms"][k]["attestation_digest"] != rb["platforms"][k]["attestation_digest"], "attestation digest of %s did not change" % k)
    check_matches_ref(fx.bytes, json.dumps(vex).encode("utf-8"), b)


@case("AC1", "the order of the index's entries matters: swapping two platforms changes F and the order the attestations are appended in")
def _():
    fx = mk_fx()
    sw = dict(fx.obj)
    sw["manifests"] = list(reversed(fx.obj["manifests"]))
    db2 = json.dumps(sw, indent=2).encode()
    a, b = do_compute(fx.bytes, VEX_MIN), do_compute(db2, VEX_MIN)
    ok(a.rc == 0 and b.rc == 0, "compute failed")
    ok(a.out != b.out, "F did not change with the entry order")
    check_matches_ref(db2, VEX_MIN, b)
    fo = json.loads(rd(os.path.join(b.dir, "index.json")))
    refs = [e["annotations"]["vnd.docker.reference.digest"] for e in fo["manifests"][2:]]
    eq(refs, [e["digest"] for e in sw["manifests"]], "attestations follow the index's own order")


@case("AC1", "the tool uses only the standard library (no third-party imports)")
def _():
    if not os.path.isfile(TOOL):
        raise Fail("the tool does not exist")
    tree_ = ast.parse(rd(TOOL).decode("utf-8"))
    names = set()
    for n in ast.walk(tree_):
        if isinstance(n, ast.Import):
            names |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            ok(n.level == 0, "relative import")
            names.add((n.module or "").split(".")[0])
    std = getattr(sys, "stdlib_module_names", None)
    ok(std is not None, "python too old to list the standard library")
    bad = sorted(n for n in names if n not in std)
    ok(not bad, "non-standard imports: %s" % bad)


@case("AC1", "compute and verify are offline: with an unreachable proxy configured and no network access they still succeed")
def _():
    fx = mk_fx()
    env = {"http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
           "HTTPS_PROXY": "http://127.0.0.1:9", "FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET}
    r = do_compute(fx.bytes, vex_real(), env=env)
    check_matches_ref(fx.bytes, vex_real(), r)


# ------------------------------------------------------------------ AC2: refuse and write nothing
_CONTROL = {}


def control_ok():
    if "c" not in _CONTROL:
        fx = mk_fx()
        r = do_compute(fx.bytes, vex_real())
        _CONTROL["c"] = (r.rc, r.err)
    ok(_CONTROL["c"][0] == 0, "positive control failed (a refusal test would be vacuous): " + _CONTROL["c"][1].strip()[:200])


def assert_refused(db, vb, label=""):
    control_ok()
    for pre in (False, True):
        s = sb()
        out = os.path.join(s, "out")
        if pre:
            os.mkdir(out)
        r = do_compute(db, vb, out=out, s=s)
        ok(r.rc != 0, "accepted (rc 0): %s" % label)
        ok(r.err.strip() != "", "refused without a reason on stderr")
        ok("sha256:" not in r.out, "printed a digest although it refused")
        if pre:
            eq(os.listdir(out), [], "the pre-existing empty out-dir must stay empty")
        else:
            ok(not os.path.lexists(out), "the out-dir was created although the tool refused")
        eq(tree(os.path.join(s, "in")), {"index.json": db, "vex.json": vb}, "inputs")


def bad_index(f):
    fx = mk_fx(unknown=True)
    o = json.loads(json.dumps(fx.obj))
    f(o)
    return json.dumps(o, indent=2).encode()


def raw_dup_index():
    fx = mk_fx()
    s = json.dumps(fx.obj)
    return s.replace('"schemaVersion": 2', '"schemaVersion": 2, "schemaVersion": 2').encode()


H64 = "ab" * 32
D_BAD = {
    "not json": b"this is not json\n", "empty file": b"", "whitespace only": b"  \n",
    "json array": b"[]", "json string": b'"x"', "json null": b"null",
    "invalid utf-8": b'{"manifests":[{"digest":"\xff\xfe"}]}',
    "duplicate top-level key": raw_dup_index(),
    "NaN number": b'{"schemaVersion":2,"manifests":[{"digest":"sha256:%s","size":NaN,"platform":{"architecture":"amd64","os":"linux"}}]}' % H64.encode(),
    "deeply nested": b"[" * 100000 + b"]" * 100000,
    "no manifests key": bad_index(lambda o: o.pop("manifests")),
    "manifests is an object": bad_index(lambda o: o.update(manifests={"a": 1})),
    "manifests is a string": bad_index(lambda o: o.update(manifests="abc")),
    "manifests is null": bad_index(lambda o: o.update(manifests=None)),
    "manifests is empty": bad_index(lambda o: o.update(manifests=[])),
    "entry is a string": bad_index(lambda o: o["manifests"].insert(1, "sha256:" + H64)),
    "entry is a number": bad_index(lambda o: o["manifests"].insert(1, 7)),
    "entry is null": bad_index(lambda o: o["manifests"].insert(1, None)),
    "entry is a list": bad_index(lambda o: o["manifests"].insert(1, [o["manifests"][0]])),
    "entry without digest": bad_index(lambda o: o["manifests"][0].pop("digest")),
    "entry without size": bad_index(lambda o: o["manifests"][0].pop("size")),
    "digest is a number": bad_index(lambda o: o["manifests"][0].update(digest=5)),
    "digest is null": bad_index(lambda o: o["manifests"][0].update(digest=None)),
    "digest is a list": bad_index(lambda o: o["manifests"][0].update(digest=["sha256:" + H64])),
    "digest sha1": bad_index(lambda o: o["manifests"][0].update(digest="sha1:" + "ab" * 20)),
    "digest sha512 length": bad_index(lambda o: o["manifests"][0].update(digest="sha512:" + "ab" * 64)),
    "digest without algorithm": bad_index(lambda o: o["manifests"][0].update(digest=H64)),
    "digest 63 hex": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + H64[:-1])),
    "digest 65 hex": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + H64 + "a")),
    "digest upper-case hex": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + H64.upper())),
    "digest not hex": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + "zz" * 32)),
    "digest with trailing newline": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + H64 + "\n")),
    "digest with leading space": bad_index(lambda o: o["manifests"][0].update(digest=" sha256:" + H64)),
    "digest path traversal": bad_index(lambda o: o["manifests"][0].update(digest="sha256:../../../../../../../../../tmp/evil/xxxxxxxxxxxxxxx")),
    "digest path traversal 64 chars": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + "../" * 21 + "x")),
    "digest with slash": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + "ab/" + H64[3:])),
    "digest with NUL": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + H64[:-1] + "\u0000")),
    "size huge": bad_index(lambda o: o["manifests"][0].update(size=10 ** 30)),
    "size 2**63": bad_index(lambda o: o["manifests"][0].update(size=2 ** 63)),
    "size negative": bad_index(lambda o: o["manifests"][0].update(size=-1)),
    "size boolean": bad_index(lambda o: o["manifests"][0].update(size=True)),
    "size string": bad_index(lambda o: o["manifests"][0].update(size="1234")),
    "size float": bad_index(lambda o: o["manifests"][0].update(size=1.5)),
    "size null": bad_index(lambda o: o["manifests"][0].update(size=None)),
    "size float exponent": bad_index(lambda o: o["manifests"][0].update(size=1e30)),
    "platform missing": bad_index(lambda o: o["manifests"][0].pop("platform")),
    "platform is a string": bad_index(lambda o: o["manifests"][0].update(platform="linux/amd64")),
    "platform os missing": bad_index(lambda o: o["manifests"][0]["platform"].pop("os")),
    "platform os empty": bad_index(lambda o: o["manifests"][0]["platform"].update(os="")),
    "platform os is a number": bad_index(lambda o: o["manifests"][0]["platform"].update(os=3)),
    "platform architecture missing": bad_index(lambda o: o["manifests"][0]["platform"].pop("architecture")),
    "platform variant is a number": bad_index(lambda o: o["manifests"][0]["platform"].update(variant=7)),
    "duplicate platform": bad_index(lambda o: o["manifests"].insert(1, dict(o["manifests"][0], digest="sha256:" + H64))),
    "duplicate platform digest on two platforms": bad_index(lambda o: o["manifests"][1].update(digest=o["manifests"][0]["digest"])),
    "no platform at all (only unknown/unknown)": bad_index(lambda o: o.update(manifests=[o["manifests"][-1]])),
    "already final: attestation child present": bad_index(
        lambda o: o["manifests"].append({"mediaType": OCI_MAN, "digest": "sha256:" + H64, "size": 480,
                                         "annotations": {"vnd.docker.reference.digest": o["manifests"][0]["digest"],
                                                         "vnd.docker.reference.type": "attestation-manifest"},
                                         "platform": {"architecture": "unknown", "os": "unknown"}})),
    "already final: attestation child, odd annotation set": bad_index(
        lambda o: o["manifests"].append({"mediaType": OCI_MAN, "digest": "sha256:" + H64, "size": 480,
                                         "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
                                         "platform": {"architecture": "unknown", "os": "unknown"}})),
    "annotations is a list": bad_index(lambda o: o["manifests"][0].update(annotations=["x"])),
}


@param("AC2", "malformed or hostile index is refused and nothing is written", sorted(D_BAD.items()))
def _(db):
    assert_refused(db, vex_real(), "index")


def final_of(fx, vb):
    return ref_compute(fx.bytes, vb)[0]


@case("AC2", "an index that is already final (a complete output of the tool) is refused")
def _():
    fx = mk_fx()
    assert_refused(final_of(fx, vex_real()), vex_real(), "already final")


V_BAD = {
    "empty file": b"", "whitespace only": b" \n", "not json": b"statements: []",
    "json array": b"[]", "json string": b'"x"', "json null": b"null", "json number": b"7",
    "object without @context": b'{"statements":[{"status":"not_affected"}]}',
    "object without statements": b'{"@context":"https://openvex.dev/ns/v0.2.0"}',
    "empty object": b"{}",
    "statements is an object": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":{"a":1}}',
    "statements is a string": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":"none"}',
    "statements is null": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":null}',
    "duplicate key": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":[],"statements":[{"a":1}]}',
    "NaN": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"x":NaN}]}',
    "Infinity": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"x":Infinity}]}',
    "invalid utf-8": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"x":"\xff"}]}',
    "truncated": VEX_MIN[:-5],
}


@param("AC2", "a VEX that is not an OpenVEX document is refused and nothing is written", sorted(V_BAD.items()))
def _(vb):
    assert_refused(mk_fx().bytes, vb, "vex")


@case("AC2", "a missing index file or a directory in its place is refused")
def _():
    control_ok()
    s = sb()
    v = wr(os.path.join(s, "v.json"), VEX_MIN)
    for idx in (os.path.join(s, "nope.json"), s):
        out = os.path.join(s, "o-" + str(abs(hash(idx)) % 1000))
        r = run(["compute", "--index", idx, "--vex", v, "--out-dir", out])
        ok(r.rc != 0 and r.err.strip() != "", "accepted %s" % idx)
        ok(not os.path.lexists(out), "created the out-dir")


@case("AC2", "a missing VEX file is refused")
def _():
    control_ok()
    s = sb()
    i = wr(os.path.join(s, "i.json"), mk_fx().bytes)
    out = os.path.join(s, "o")
    r = run(["compute", "--index", i, "--vex", os.path.join(s, "nope.json"), "--out-dir", out])
    ok(r.rc != 0 and r.err.strip() != "", "accepted a missing VEX")
    ok(not os.path.lexists(out), "created the out-dir")


def out_dir_case(setup):
    control_ok()
    s = sb()
    fx = mk_fx()
    i = wr(os.path.join(s, "i.json"), fx.bytes)
    v = wr(os.path.join(s, "v.json"), VEX_MIN)
    out, watch = setup(s)
    before = tree(s)
    r = run(["compute", "--index", i, "--vex", v, "--out-dir", out])
    ok(r.rc != 0 and r.err.strip() != "", "accepted the out-dir (rc %d)" % r.rc)
    ok("sha256:" not in r.out, "printed a digest")
    eq(tree(s), before, "everything under the sandbox (nothing may be written, not even through the link)")
    for w in watch:
        eq(os.listdir(w), [], "watched directory")


def _setup_nonempty_file(s):
    d = os.path.join(s, "out"); wr(os.path.join(d, "keep.txt"), b"mine"); return d, []


def _setup_nonempty_subdir(s):
    d = os.path.join(s, "out"); os.makedirs(os.path.join(d, "sub")); return d, []


def _setup_nonempty_dot(s):
    d = os.path.join(s, "out"); wr(os.path.join(d, ".hidden"), b""); return d, []


def _setup_symlink(s):
    t = os.path.join(s, "target"); os.mkdir(t)
    l = os.path.join(s, "out"); os.symlink(t, l); return l, [t]


def _setup_dangling(s):
    l = os.path.join(s, "out"); os.symlink(os.path.join(s, "does-not-exist"), l); return l, []


def _setup_regular_file(s):
    p = wr(os.path.join(s, "out"), b"a file"); return p, []


def _setup_symlink_to_file(s):
    p = wr(os.path.join(s, "real"), b"a file"); l = os.path.join(s, "out"); os.symlink(p, l); return l, []


@param("AC2", "an unusable out-dir is refused without touching anything", [
    ("non-empty (a file)", _setup_nonempty_file), ("non-empty (a subdirectory)", _setup_nonempty_subdir),
    ("non-empty (a dotfile)", _setup_nonempty_dot), ("a symlink to an empty directory", _setup_symlink),
    ("a dangling symlink", _setup_dangling), ("a regular file", _setup_regular_file),
    ("a symlink to a file", _setup_symlink_to_file)])
def _(setup):
    out_dir_case(setup)


@case("AC2", "a successful compute writes only inside the out-dir and leaves its inputs and the surroundings untouched")
def _():
    s = sb()
    fx = mk_fx()
    wr(os.path.join(s, "neighbour.txt"), b"n")
    i = wr(os.path.join(s, "i.json"), fx.bytes)
    v = wr(os.path.join(s, "v.json"), vex_real())
    cwd = os.path.join(s, "cwd"); os.mkdir(cwd)
    before = tree(s)
    r = run(["compute", "--index", i, "--vex", v, "--out-dir", os.path.join(s, "out")], cwd=cwd)
    ok(r.rc == 0, "compute failed")
    after = tree(s)
    for k, val in after.items():
        if k == "out" or k.startswith("out/") or k.startswith("out@"):
            continue
        ok(k in before and before[k] == val, "%s was changed or created outside the out-dir" % k)
    for k in before:
        ok(k in after, "%s vanished" % k)
    ok(not os.listdir(cwd), "wrote into the working directory")


@case("AC2", "an existing empty out-dir is accepted and used")
def _():
    s = sb()
    out = os.path.join(s, "out"); os.mkdir(out)
    fx = mk_fx()
    check_matches_ref(fx.bytes, vex_real(), do_compute(fx.bytes, vex_real(), out=out, s=s))


@case("AC2", "the same out-dir cannot be reused: a second compute into it is refused and leaves the first result intact")
def _():
    fx = mk_fx()
    a = do_compute(fx.bytes, vex_real())
    ok(a.rc == 0, "compute failed")
    before = tree(a.dir)
    r = run(["compute", "--index", a.index, "--vex", a.vex, "--out-dir", a.dir])
    ok(r.rc != 0 and r.err.strip() != "", "accepted a non-empty out-dir")
    eq(tree(a.dir), before, "out-dir after the refused second run")


# ------------------------------------------------------------------ AC3: the shape of the final index
def fobj_of(fx, vb):
    fb, blobs, result = ref_compute(fx.bytes, vb)
    return json.loads(fb), blobs, result


@param("AC3", "the final index has exactly one attestation child per platform naming that platform's digest, in the exact canonical shape", list(FIXTURES.items()))
def _(mk):
    fx = mk()
    r = do_compute(fx.bytes, vex_real())
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:200])
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    d = json.loads(fx.bytes.decode("utf-8"))
    n = len(d["manifests"])
    plats = [e for e in d["manifests"] if e["platform"]["os"] != "unknown"]
    eq(len(f["manifests"]), n + len(plats), "number of entries")
    eq(f["manifests"][:n], d["manifests"], "the original entries, untouched and in order")
    eq({k: v for k, v in f.items() if k != "manifests"}, {k: v for k, v in d.items() if k != "manifests"}, "the other top-level fields (a missing mediaType stays missing)")
    for e, p in zip(f["manifests"][n:], plats):
        eq(sorted(e), ["annotations", "digest", "mediaType", "platform", "size"], "attestation descriptor keys")
        eq(e["mediaType"], OCI_MAN, "attestation mediaType")
        eq(e["platform"], {"architecture": "unknown", "os": "unknown"}, "attestation platform")
        eq(e["annotations"], {"vnd.docker.reference.digest": p["digest"], "vnd.docker.reference.type": "attestation-manifest"}, "annotations")
        ok(isinstance(e["size"], int) and not isinstance(e["size"], bool), "size type")
        ok(DIGEST_RE.match(e["digest"]), "digest form")
    refs = [e["annotations"]["vnd.docker.reference.digest"] for e in f["manifests"][n:]]
    eq(len(set(refs)), len(refs), "one attestation per platform digest")
    eq(sorted(refs), sorted(p["digest"] for p in plats), "every platform, and only the platforms")
    for e in f["manifests"][:n]:
        ok("vnd.docker.reference.type" not in (e.get("annotations") or {}), "an original entry gained attestation annotations")


@case("AC3", "removing the attestation children from F gives back the built index's entries, field for field")
def _():
    fx = mk_fx(unknown=True, **EXTRAS)
    r = do_compute(fx.bytes, vex_real())
    ok(r.rc == 0, "compute failed")
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    f["manifests"] = [e for e in f["manifests"] if (e.get("annotations") or {}).get("vnd.docker.reference.type") != "attestation-manifest"]
    eq(f, json.loads(fx.bytes.decode("utf-8")), "F minus attestation children")


@param("AC3", "the attestation manifest, config, layer and statement have exactly the ratified shape", [("oci-2-platform", "oci-2-platform"), ("arm-v7-variant", "arm-v7-variant"), ("docker-manifest-list", "docker-manifest-list")])
def _(name):
    fx = FIXTURES[name]()
    vb = vex_real()
    r = do_compute(fx.bytes, vb)
    ok(r.rc == 0, "compute failed")
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    vex = json.loads(vb.decode("utf-8"))
    bdir = os.path.join(r.dir, "blobs", "sha256")
    seen = set()
    for e in f["manifests"]:
        a = e.get("annotations") or {}
        if a.get("vnd.docker.reference.type") != "attestation-manifest":
            continue
        pd = a["vnd.docker.reference.digest"]
        mb = rd(os.path.join(bdir, hx(e["digest"])))
        eq(dg(mb), e["digest"], "attestation manifest digest")
        eq(len(mb), e["size"], "attestation manifest size")
        m = json.loads(mb)
        eq(sorted(m), ["config", "layers", "mediaType", "schemaVersion"], "manifest keys")
        eq((m["schemaVersion"], m["mediaType"]), (2, OCI_MAN), "manifest versions")
        eq(sorted(m["config"]), ["digest", "mediaType", "size"], "config descriptor keys")
        eq(m["config"]["mediaType"], OCI_CFG, "config mediaType")
        eq(len(m["layers"]), 1, "layer count")
        L = m["layers"][0]
        eq(sorted(L), ["annotations", "digest", "mediaType", "size"], "layer descriptor keys")
        eq(L["mediaType"], "application/vnd.in-toto+json", "layer mediaType")
        eq(L["annotations"], {"in-toto.io/predicate-type": PRED}, "layer annotations")
        cb, sbts = rd(os.path.join(bdir, hx(m["config"]["digest"]))), rd(os.path.join(bdir, hx(L["digest"])))
        eq((dg(cb), len(cb)), (m["config"]["digest"], m["config"]["size"]), "config blob digest/size")
        eq((dg(sbts), len(sbts)), (L["digest"], L["size"]), "layer blob digest/size")
        eq(cb, cj({"architecture": "unknown", "created": "1970-01-01T00:00:00Z", "os": "unknown",
                   "rootfs": {"diff_ids": [L["digest"]], "type": "layers"}}), "config blob bytes")
        st = json.loads(sbts.decode("utf-8"))
        eq(sorted(st), ["_type", "predicate", "predicateType", "subject"], "statement keys")
        eq(st["_type"], STMT_TYPE, "statement _type")
        eq(st["predicateType"], PRED, "predicateType")
        eq(st["subject"], [{"name": SUBJECT_NAME, "digest": {"sha256": hx(pd)}}], "subject is the platform digest")
        eq(st["predicate"], vex, "predicate is the VEX file's content")
        eq(sbts, cj(st), "statement bytes are canonical (sorted keys, compact, raw UTF-8, no trailing newline)")
        ok(not sbts.endswith(b"\n"), "trailing newline")
        seen.add(pd)
    ok(len(seen) >= 1, "no attestation found")


@param("AC3", "no digest of the built index or of the final index appears inside any attestation blob, and each statement names only its own platform", [("oci-2-platform", "oci-2-platform"), ("arm-v7-variant", "arm-v7-variant"), ("docker-manifest-list", "docker-manifest-list")])
def _(name):
    fx = FIXTURES[name]()
    r = do_compute(fx.bytes, vex_real())
    ok(r.rc == 0, "compute failed")
    fb = rd(os.path.join(r.dir, "index.json"))
    f = json.loads(fb)
    forbidden = {"built index (raw bytes)": hashlib.sha256(fx.bytes).hexdigest(),
                 "built index (canonical form)": hashlib.sha256(cj(json.loads(fx.bytes.decode()))).hexdigest(),
                 "final index": hashlib.sha256(fb).hexdigest()}
    bdir = os.path.join(r.dir, "blobs", "sha256")
    for n in os.listdir(bdir):
        b = rd(os.path.join(bdir, n))
        for what, h in forbidden.items():
            ok(h.encode() not in b and ("sha256:" + h).encode() not in b, "the digest of the %s appears inside blob %s" % (what, n))
    plats = {e["digest"] for e in f["manifests"] if not (e.get("annotations") or {}).get("vnd.docker.reference.type")}
    for e in f["manifests"]:
        a = e.get("annotations") or {}
        if a.get("vnd.docker.reference.type") != "attestation-manifest":
            continue
        m = json.loads(rd(os.path.join(bdir, hx(e["digest"]))))
        stb = rd(os.path.join(bdir, hx(m["layers"][0]["digest"])))
        mine = hx(a["vnd.docker.reference.digest"])
        for p in plats:
            if hx(p) != mine:
                ok(hx(p).encode() not in stb, "a statement names another platform's digest")


@case("AC3", "result.json has exactly the ratified keys and agrees with the output")
def _():
    fx = mk_fx(plats=(("amd64", None), ("arm64", "v8"), ("arm", "v7")), unknown=True)
    r = do_compute(fx.bytes, vex_real())
    ok(r.rc == 0, "compute failed")
    res = json.loads(rd(os.path.join(r.dir, "result.json")))
    eq(sorted(res), ["base_digest", "final_digest", "platforms", "vex_sha256"], "result.json keys")
    eq(res["base_digest"], dg(fx.bytes), "base_digest")
    eq(res["final_digest"], r.out.strip(), "final_digest")
    eq(norm_result(res), norm_result(ref_compute(fx.bytes, vex_real())[2]), "whole result")
    eq(sorted(res["platforms"]), ["linux/amd64", "linux/arm/v7", "linux/arm64/v8"], "platform keys: os/arch[/variant], the unknown entry excluded")
    for v in res["platforms"].values():
        eq(sorted(v), ["attestation_digest", "platform_digest"], "platform entry keys")
    ok(res["vex_sha256"] in (hashlib.sha256(vex_real()).hexdigest(), "sha256:" + hashlib.sha256(vex_real()).hexdigest()), "vex_sha256")


# ---- verify
def verify(f_bytes, vb, base=None, blobs=None, s=None):
    s = s or sb()
    fp = wr(os.path.join(s, "final.json"), f_bytes)
    vp = wr(os.path.join(s, "vex.json"), vb)
    args = ["verify", "--final", fp, "--vex", vp]
    if base is not None:
        args += ["--base", wr(os.path.join(s, "base.json"), base) if isinstance(base, bytes) else base]
    if blobs is not None:
        args += ["--blobs", blobs]
    before = tree(s)
    r = run(args)
    eq(tree(s), before, "verify must not write anything")
    return r


def blob_dir_from(fx, vb):
    s = sb()
    bd = os.path.join(s, "blobs", "sha256")
    for h, b in ref_compute(fx.bytes, vb)[1].items():
        wr(os.path.join(bd, h), b)
    return os.path.join(s, "blobs")


_VCTL = {}


def verify_control():
    if "c" not in _VCTL:
        fx = mk_fx()
        r = verify(final_of(fx, VEX_MIN), VEX_MIN)
        _VCTL["c"] = (r.rc, r.err)
    ok(_VCTL["c"][0] == 0, "positive control failed (a negative test would be vacuous): " + _VCTL["c"][1].strip()[:200])


@param("AC3", "verify accepts a correct final index", [("alone", 0), ("with --base (the built index file)", 1), ("with --base in other key order and whitespace", 2), ("with --blobs", 3), ("with --base and --blobs", 4), ("with the VEX in other key order, with --blobs", 5)])
def _(mode):
    fx = mk_fx(plats=(("amd64", None), ("arm64", "v8"), ("arm", "v7")), unknown=True, **EXTRAS)
    vb = vex_real()
    fb = final_of(fx, vb)
    kw = {}
    if mode in (1, 4):
        kw["base"] = fx.bytes
    if mode == 2:
        kw["base"] = reindent_json(fx.bytes, 5, reverse=True)
    if mode in (3, 4, 5):
        kw["blobs"] = blob_dir_from(fx, vb)
    if mode == 5:
        vb = reindent_json(vb, 3, reverse=True)
    r = verify(fb, vb, **kw)
    ok(r.rc == 0, "rejected a correct final index: " + r.err.strip()[:300])


@case("AC3", "verify accepts the tool's own compute output with its blobs")
def _():
    fx = mk_fx()
    c = do_compute(fx.bytes, vex_real())
    ok(c.rc == 0, "compute failed")
    r = verify(rd(os.path.join(c.dir, "index.json")), vex_real(), base=c.index, blobs=os.path.join(c.dir, "blobs"))
    ok(r.rc == 0, "rejected the tool's own output: " + r.err.strip()[:300])


def _mut(f):
    def go(fx, fo, blobs):
        fo = json.loads(json.dumps(fo))
        f(fo, fx)
        return cj(fo)
    return go


def _n(fo, fx):
    return len(fx.obj["manifests"])


def _fake_att(fo, fx, ref, **kw):
    e = json.loads(json.dumps(fo["manifests"][_n(fo, fx)]))
    e["annotations"]["vnd.docker.reference.digest"] = ref
    e["digest"] = "sha256:" + hashlib.sha256(ref.encode()).hexdigest()
    e.update(kw)
    return e


VERIFY_BAD = {
    "an attestation child is missing for one platform": lambda fo, fx: fo["manifests"].pop(),
    "all attestation children are missing (the built index itself)": lambda fo, fx: fo.update(manifests=fo["manifests"][:_n(fo, fx)]),
    "an attestation child without a platform (names an unknown digest)": lambda fo, fx: fo["manifests"].append(_fake_att(fo, fx, "sha256:" + "cd" * 32)),
    "an attestation child naming the built index's digest": lambda fo, fx: fo["manifests"].append(_fake_att(fo, fx, dg(fx.bytes))),
    "two attestation children for one platform": lambda fo, fx: fo["manifests"].append(_fake_att(fo, fx, fo["manifests"][0]["digest"])),
    "an extra annotation key": lambda fo, fx: fo["manifests"][_n(fo, fx)]["annotations"].update(extra="x"),
    "a missing annotation key (no reference.digest)": lambda fo, fx: fo["manifests"][_n(fo, fx)]["annotations"].pop("vnd.docker.reference.digest"),
    "reference.type is not attestation-manifest": lambda fo, fx: fo["manifests"][_n(fo, fx)]["annotations"].update({"vnd.docker.reference.type": "sbom"}),
    "reference.digest is malformed": lambda fo, fx: fo["manifests"][_n(fo, fx)]["annotations"].update({"vnd.docker.reference.digest": "sha256:xyz"}),
    "reference.digest names the other platform twice": lambda fo, fx: fo["manifests"][_n(fo, fx)]["annotations"].update({"vnd.docker.reference.digest": fo["manifests"][1]["digest"]}),
    "the attestation's platform is not unknown/unknown": lambda fo, fx: fo["manifests"][_n(fo, fx)].update(platform={"architecture": "amd64", "os": "linux"}),
    "the attestation's mediaType is not an OCI manifest": lambda fo, fx: fo["manifests"][_n(fo, fx)].update(mediaType=DOCKER_MAN),
    "the attestation digest is malformed": lambda fo, fx: fo["manifests"][_n(fo, fx)].update(digest="sha256:abc"),
    "a platform digest changed (its attestation now names a stranger)": lambda fo, fx: fo["manifests"][0].update(digest="sha256:" + "ee" * 32),
    "the attestation size is not a number": lambda fo, fx: fo["manifests"][_n(fo, fx)].update(size="480"),
}


@param("AC3", "verify rejects a final index that is not exactly the tool's shape, with a reason", sorted(VERIFY_BAD.items()))
def _(f):
    verify_control()
    fx = mk_fx()
    fo = json.loads(final_of(fx, VEX_MIN))
    f(fo, fx)
    r = verify(cj(fo), VEX_MIN)
    ok(r.rc != 0, "accepted a bad final index")
    ok(r.err.strip() != "", "no reason on stderr")


@param("AC3", "verify rejects an unreadable final index", [("not JSON", b"nope"), ("empty", b""), ("array", b"[]"), ("the built index (no attestations)", mk_fx().bytes)])
def _(b):
    verify_control()
    r = verify(b, VEX_MIN)
    ok(r.rc != 0 and r.err.strip() != "", "accepted")


@case("AC3", "verify rejects a final index with a duplicate platform or an invalid VEX")
def _():
    verify_control()
    fx = mk_fx()
    fo = json.loads(final_of(fx, VEX_MIN))
    fo["manifests"].insert(1, dict(fo["manifests"][0]))
    r = verify(cj(fo), VEX_MIN)
    ok(r.rc != 0, "accepted a duplicate platform")
    r = verify(final_of(fx, VEX_MIN), b'{"statements":[]}')
    ok(r.rc != 0, "accepted a VEX that is not OpenVEX")


def _base_swapped(fx):
    o = json.loads(json.dumps(fx.obj)); o["manifests"].reverse(); return json.dumps(o).encode()


def _base_digest_changed(fx):
    o = json.loads(json.dumps(fx.obj)); o["manifests"][0]["digest"] = "sha256:" + "11" * 32; return json.dumps(o).encode()


def _base_extra_platform(fx):
    o = json.loads(json.dumps(fx.obj)); o["manifests"].append(desc_of(mk_child("s390x"))); return json.dumps(o).encode()


def _base_extra_field(fx):
    o = json.loads(json.dumps(fx.obj)); o["manifests"][0]["annotations"] = {"a": "b"}; return json.dumps(o).encode()


def _base_other_top(fx):
    o = json.loads(json.dumps(fx.obj)); o["annotations"] = {"a": "b"}; return json.dumps(o).encode()


@param("AC3", "verify --base rejects a final index whose entries minus attestations differ from the built index", [
    ("entries in another order", _base_swapped), ("one platform digest differs", _base_digest_changed),
    ("the base has one more platform", _base_extra_platform), ("one entry has an extra field", _base_extra_field),
    ("a top-level field differs", _base_other_top), ("the base is not JSON", lambda fx: b"garbage")])
def _(f):
    verify_control()
    fx = mk_fx()
    r = verify(final_of(fx, VEX_MIN), VEX_MIN, base=f(fx))
    ok(r.rc != 0 and r.err.strip() != "", "accepted a base that is not the final index's origin")


@case("AC3", "verify --base rejects a missing base file")
def _():
    verify_control()
    fx = mk_fx()
    r = verify(final_of(fx, VEX_MIN), VEX_MIN, base="/nonexistent/base.json")
    ok(r.rc != 0 and r.err.strip() != "", "accepted a missing base file")


def _blob_remove(bd, fx, vb):
    os.unlink(os.path.join(bd, "sha256", sorted(os.listdir(os.path.join(bd, "sha256")))[0]))


def _blob_flip(which):
    def f(bd, fx, vb):
        fo = json.loads(final_of(fx, vb))
        h = list(ref_compute(fx.bytes, vb)[1])
        key = {"layer": 0, "config": 1, "manifest": 2}[which]
        a = [e for e in fo["manifests"] if (e.get("annotations") or {}).get("vnd.docker.reference.type")][0]
        man = json.loads(rd(os.path.join(bd, "sha256", hx(a["digest"]))))
        target = {"layer": man["layers"][0]["digest"], "config": man["config"]["digest"], "manifest": a["digest"]}[which]
        p = os.path.join(bd, "sha256", hx(target))
        b = bytearray(rd(p)); b[len(b) // 2] ^= 1; wr(p, bytes(b))
    return f


def _blob_swap_subject(bd, fx, vb):
    fo = json.loads(final_of(fx, vb))
    a = [e for e in fo["manifests"] if (e.get("annotations") or {}).get("vnd.docker.reference.type")][0]
    man = json.loads(rd(os.path.join(bd, "sha256", hx(a["digest"]))))
    p = os.path.join(bd, "sha256", hx(man["layers"][0]["digest"]))
    st = json.loads(rd(p)); st["subject"][0]["digest"]["sha256"] = hashlib.sha256(fx.bytes).hexdigest(); wr(p, cj(st))


def _blob_empty(bd, fx, vb):
    shutil.rmtree(os.path.join(bd, "sha256")); os.makedirs(os.path.join(bd, "sha256"))


@param("AC3", "verify --blobs rejects missing or tampered blobs", [
    ("a blob is missing", _blob_remove), ("a layer blob has a flipped bit", _blob_flip("layer")),
    ("a config blob has a flipped bit", _blob_flip("config")), ("an attestation manifest blob has a flipped bit", _blob_flip("manifest")),
    ("a statement's subject was swapped for the built index's digest", _blob_swap_subject), ("the blob directory is empty", _blob_empty)])
def _(f):
    verify_control()
    fx = mk_fx()
    vb = vex_real()
    bd = blob_dir_from(fx, vb)
    f(bd, fx, vb)
    r = verify(final_of(fx, vb), vb, blobs=bd)
    ok(r.rc != 0 and r.err.strip() != "", "accepted tampered blobs")


@case("AC3", "verify --blobs rejects a VEX that is not the one the final index was computed from")
def _():
    verify_control()
    fx = mk_fx()
    bd = blob_dir_from(fx, VEX_MIN)
    v2 = json.loads(VEX_MIN.decode("utf-8")); v2["version"] = 2
    r = verify(final_of(fx, VEX_MIN), json.dumps(v2).encode("utf-8"), blobs=bd)
    ok(r.rc != 0 and r.err.strip() != "", "accepted a different VEX")


@case("AC3", "verify --blobs rejects a final index whose attestation digests were computed from another VEX")
def _():
    verify_control()
    fx = mk_fx()
    v2 = json.loads(VEX_MIN.decode("utf-8")); v2["version"] = 2
    v2b = json.dumps(v2).encode("utf-8")
    r = verify(final_of(fx, v2b), VEX_MIN, blobs=blob_dir_from(fx, v2b))
    ok(r.rc != 0 and r.err.strip() != "", "accepted attestations of another VEX")


# ------------------------------------------------------------------ fake registry
class Reg:
    def __init__(self, repo="fosterstack/cache", token=False, rewrite=False, lie=False, fail_after=None,
                 realm=None, redirect_readback=False, loc_abs=False, fail_manifest_put=False):
        self.repo, self.token_mode, self.rewrite, self.lie = repo, token, rewrite, lie
        self.fail_after, self.realm, self.redirect_readback, self.loc_abs = fail_after, realm, redirect_readback, loc_abs
        self.blobs, self.mans, self.log, self.tag_writes = set(), {}, [], []
        self.mutating_ok = 0
        self.lock = threading.Lock()
        self.bearer = "issued-bearer-6b1d0e77a2c94f"
        reg = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def handle_any(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                u = urllib.parse.urlsplit(self.path)
                ent = {"method": self.command, "path": u.path, "query": u.query, "auth": self.headers.get("Authorization"),
                       "ctype": self.headers.get("Content-Type"), "body": body, "status": None}
                with reg.lock:
                    st, hd, rb = reg.respond(self.command, u, urllib.parse.parse_qs(u.query), body, ent)
                    ent["status"] = st
                    reg.log.append(ent)
                self.send_response(st)
                hd = dict(hd)
                hd["Content-Length"] = str(len(rb))
                for k, v in hd.items():
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(rb)

            do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = handle_any

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        self.host = "127.0.0.1:%d" % self.port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def seed(self, children):
        for c in children:
            self.mans[c["digest"]] = (c["bytes"], c["mt"])
            self.blobs.update(c["blobs"])

    def respond(self, m, u, q, body, ent):
        p = u.path
        if p == "/token":
            if ent["auth"] == "Basic " + base64.b64encode(("%s:%s" % (USER, SECRET)).encode()).decode():
                return 200, {"Content-Type": "application/json"}, json.dumps({"token": self.bearer, "expires_in": 300}).encode()
            return 401, {}, b'{"errors":[{"code":"UNAUTHORIZED"}]}'
        if self.token_mode and ent["auth"] != "Bearer " + self.bearer:
            chal = 'Bearer realm="%s",service="fake-registry",scope="repository:%s:pull,push"' % (self.realm or "http://127.0.0.1:%d/token" % self.port, self.repo)
            return 401, {"WWW-Authenticate": chal}, b'{"errors":[{"code":"UNAUTHORIZED"}]}'
        if p in ("/v2/", "/v2"):
            return 200, {}, b"{}"
        pre = "/v2/%s/" % self.repo
        if not p.startswith(pre):
            return 404, {}, b'{"errors":[{"code":"NAME_UNKNOWN"}]}'
        rest = p[len(pre):]
        mutating = m in ("POST", "PUT", "PATCH", "DELETE")
        if mutating and self.fail_after is not None and self.mutating_ok >= self.fail_after:
            return 500, {}, b'{"errors":[{"code":"UNKNOWN"}]}'
        st, hd, rb = self.route(m, rest, q, body, ent)
        if mutating and st < 300:
            self.mutating_ok += 1
        return st, hd, rb

    def route(self, m, rest, q, body, ent):
        err = lambda c, code: (c, {}, json.dumps({"errors": [{"code": code}]}).encode())
        if rest == "blobs/uploads/" and m == "POST":
            loc = "/v2/%s/blobs/uploads/%s?_state=st8-%d" % (self.repo, "u%d" % len(self.log), len(self.log))
            if self.loc_abs:
                loc = "http://127.0.0.1:%d%s" % (self.port, loc)
            return 202, {"Location": loc}, b""
        if rest.startswith("blobs/uploads/") and m == "PUT":
            if not q.get("_state"):
                return err(400, "BLOB_UPLOAD_INVALID")
            d = (q.get("digest") or [""])[0]
            if not DIGEST_RE.match(d) or dg(body) != d:
                return err(400, "DIGEST_INVALID")
            self.blobs.add(d)
            return 201, {"Docker-Content-Digest": d}, b""
        if rest.startswith("blobs/") and m in ("HEAD", "GET"):
            d = rest[6:]
            if d in self.blobs:
                return 200, {"Docker-Content-Digest": d}, b"x" * 0
            return err(404, "BLOB_UNKNOWN")
        if rest.startswith("manifests/"):
            ref = rest[10:]
            if m == "PUT":
                if not DIGEST_RE.match(ref):
                    self.tag_writes.append(ref)
                    self.mans[ref] = (body, ent["ctype"])
                    return 201, {}, b""
                if dg(body) != ref:
                    return err(400, "DIGEST_INVALID")
                try:
                    o = json.loads(body)
                except Exception:
                    return err(400, "MANIFEST_INVALID")
                if o.get("mediaType") and ent["ctype"] != o["mediaType"]:
                    return err(415, "MANIFEST_INVALID")
                for c in o.get("manifests") or []:
                    if c["digest"] not in self.mans:
                        return err(400, "MANIFEST_UNKNOWN")
                if "layers" in o:
                    for c in [o["config"]] + o["layers"]:
                        if c["digest"] not in self.blobs:
                            return err(400, "MANIFEST_BLOB_UNKNOWN")
                self.mans[ref] = (body, ent["ctype"])
                return 201, {"Docker-Content-Digest": ref}, b""
            if m in ("GET", "HEAD"):
                if ref not in self.mans:
                    return err(404, "MANIFEST_UNKNOWN")
                b, ct = self.mans[ref]
                hd = {"Content-Type": ct or "application/octet-stream", "Docker-Content-Digest": ref}
                if m == "GET" and b"\"manifests\"" in b:
                    if self.redirect_readback:
                        return 307, {"Location": "http://registry.example.test/cdn/" + hx(ref)}, b""
                    if self.rewrite:
                        nb = json.dumps(json.loads(b), indent=1).encode()
                        hd["Docker-Content-Digest"] = ref if self.lie else dg(nb)
                        return 200, hd, nb
                return 200, hd, b
        return err(404, "UNSUPPORTED")


class Sink:
    """a stand-in proxy that records anything sent towards a non-local host; it answers 502."""
    def __init__(self):
        self.log = []
        sink = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def any(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                sink.log.append({"method": self.command, "path": self.path, "auth": self.headers.get("Authorization"), "host": self.headers.get("Host")})
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_HEAD = do_POST = do_PUT = do_CONNECT = do_DELETE = do_PATCH = any

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def env(self):
        return {"http_proxy": self.url, "https_proxy": self.url, "HTTP_PROXY": self.url, "HTTPS_PROXY": self.url,
                "no_proxy": "127.0.0.1,localhost", "NO_PROXY": "127.0.0.1,localhost"}


class PD:
    pass


def make_dir(fx, vb, s=None):
    s = s or sb()
    pd = PD()
    fb, blobs, result = ref_compute(fx.bytes, vb)
    pd.path = os.path.join(s, "dir")
    wr(os.path.join(pd.path, "index.json"), fb)
    for h, b in blobs.items():
        wr(os.path.join(pd.path, "blobs", "sha256", h), b)
    wr(os.path.join(pd.path, "result.json"), cj(result) + b"\n")
    pd.fb, pd.blobs, pd.result, pd.fx = fb, blobs, result, fx
    fo = json.loads(fb)
    pd.atts = [e for e in fo["manifests"] if (e.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest"]
    pd.plat_digests = [e["digest"] for e in fo["manifests"] if e not in pd.atts]
    pd.upload = set()
    for e in pd.atts:
        m = json.loads(blobs[hx(e["digest"])])
        pd.upload |= {m["config"]["digest"], m["layers"][0]["digest"]}
    pd.f_digest = dg(fb)
    pd.f_media = fo.get("mediaType")
    pd.att_digests = {e["digest"] for e in pd.atts}
    return pd


def push(reg, pd, extra=(), env=None, creds=True, repo=None, registry=None, replace_env=False):
    e = {}
    if creds:
        e = {"FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET}
    e.update(env or {})
    r = run(["push", "--registry", registry or reg.host, "--repository", repo or reg.repo, "--dir", pd.path] + list(extra), env=e, replace_env=replace_env)
    for secret in (SECRET, getattr(reg, "bearer", "") if reg else ""):
        if secret:
            ok(secret not in r.out and secret not in r.err, "a credential or token was printed")
    return r


def muts(reg):
    return [x for x in reg.log if x["method"] in ("POST", "PUT", "PATCH", "DELETE")]


def okmuts(reg):
    return [x for x in muts(reg) if x["status"] < 300]


def push_world(**kw):
    fx = kw.pop("fx", None) or mk_fx()
    reg = Reg(**{k: v for k, v in kw.items() if k not in ("vb", "seed_skip", "preblobs")})
    vb = kw.get("vb") or vex_real()
    seed = [c for i, c in enumerate(fx.children) if i not in (kw.get("seed_skip") or ())]
    reg.seed(seed)
    pd = make_dir(fx, vb)
    for d in kw.get("preblobs") or ():
        reg.blobs.add(d)
    return reg, pd


def assert_clean_push(reg, pd, r, skip_blobs=()):
    ok(r.rc == 0, "push failed rc=%d: %s" % (r.rc, r.err.strip()[:300]))
    eq(reg.tag_writes, [], "tags written")
    eq([x["method"] for x in reg.log if x["method"] not in ("GET", "HEAD", "POST", "PUT")], [], "unexpected methods")
    for x in reg.log:
        ok(x["path"] in ("/v2/", "/v2", "/token") or x["path"].startswith("/v2/%s/" % reg.repo), "request outside the repository: " + x["path"])
    puts_blob = [x for x in reg.log if x["method"] == "PUT" and "/blobs/uploads/" in x["path"] and x["status"] < 300]
    got_blobs = {dict(urllib.parse.parse_qsl(x["query"]))["digest"] for x in puts_blob}
    eq(got_blobs, set(pd.upload) - set(skip_blobs), "the set of blobs uploaded")
    eq(len(puts_blob), len(got_blobs), "a blob was uploaded twice")
    man_puts = [x for x in reg.log if x["method"] == "PUT" and "/manifests/" in x["path"] and x["status"] < 300]
    refs = [x["path"].rsplit("/", 1)[1] for x in man_puts]
    eq(set(refs), pd.att_digests | {pd.f_digest}, "the set of manifests pushed (the attestation manifests and F, by digest)")
    eq(refs.count(pd.f_digest), 1, "F pushed once")
    eq(refs[-1], pd.f_digest, "F is the last manifest pushed")
    eq(okmuts(reg)[-1]["path"].rsplit("/", 1)[-1], pd.f_digest, "the last write of the push is F")
    for x in man_puts:
        ref = x["path"].rsplit("/", 1)[1]
        ok(dg(x["body"]) == ref, "manifest body does not match its digest in the path")
        if ref == pd.f_digest:
            eq(x["body"], pd.fb, "F's bytes")
            if pd.f_media:
                eq(x["ctype"], pd.f_media, "F's Content-Type")
        else:
            eq(x["body"], pd.blobs[hx(ref)], "attestation manifest bytes")
            eq(x["ctype"], OCI_MAN, "attestation manifest Content-Type")
    idx_f = [i for i, x in enumerate(reg.log) if x["method"] == "PUT" and x["path"].endswith("/manifests/" + pd.f_digest) and x["status"] < 300][0]
    for c in pd.plat_digests:
        ok(any(x["method"] in ("HEAD", "GET") and x["path"].endswith("/manifests/" + c) and x["status"] == 200 for x in reg.log[:idx_f]), "child %s was not verified before F was written" % c)
    for a in pd.att_digests:
        ok(any(x["path"].endswith("/manifests/" + a) and x["method"] == "PUT" for x in reg.log[:idx_f]), "attestation manifest %s not pushed before F" % a)
    for x in reg.log[:idx_f]:
        if x["method"] == "PUT" and "/blobs/uploads/" in x["path"]:
            pass
    last_blob = max([i for i, x in enumerate(reg.log) if "/blobs/uploads/" in x["path"]] or [-1])
    first_man = min(i for i, x in enumerate(reg.log) if x["method"] == "PUT" and "/manifests/" in x["path"])
    ok(last_blob < first_man or not puts_blob, "a manifest was pushed before all blobs were")
    ok(any(x["method"] == "GET" and x["path"].endswith("/manifests/" + pd.f_digest) for x in reg.log[idx_f + 1:]), "no read-back of F by digest after the write")
    eq(reg.mans[pd.f_digest][0], pd.fb, "stored F")


def assert_not_written(reg, pd, r, why):
    ok(r.rc != 0, "push succeeded: " + why)
    ok(pd.f_digest not in reg.mans, "F is stored in the registry: " + why)
    ok(not any(x["method"] == "PUT" and x["path"].endswith("/manifests/" + pd.f_digest) and x["status"] < 300 for x in reg.log), "F was accepted: " + why)
    eq(reg.tag_writes, [], "tags written")
    ok(pd.f_digest not in r.out, "stdout claims F's digest although the push failed")


_PCTL = {}


def push_control():
    if "c" not in _PCTL:
        reg, pd = push_world()
        try:
            r = push(reg, pd)
            _PCTL["c"] = (r.rc, r.err)
        finally:
            reg.close()
    ok(_PCTL["c"][0] == 0, "positive control failed (a push refusal test would be vacuous): " + _PCTL["c"][1].strip()[:200])


# ------------------------------------------------------------------ AC4
@case("AC4", "a normal push writes exactly the blobs and manifests of DIR by digest, children first and F last, and reads F back")
def _():
    reg, pd = push_world()
    try:
        assert_clean_push(reg, pd, push(reg, pd))
    finally:
        reg.close()


@case("AC4", "a push to a registry that answers uploads with an absolute Location works the same")
def _():
    reg, pd = push_world(loc_abs=True)
    try:
        assert_clean_push(reg, pd, push(reg, pd))
    finally:
        reg.close()


@param("AC4", "a push of other index kinds keeps each manifest's own Content-Type", [("docker manifest list", "docker-manifest-list"), ("arm v7 variant", "arm-v7-variant"), ("no top-level mediaType", "no-mediaType"), ("unknown/unknown entry", "unknown-unknown-entry")])
def _(name):
    fx = FIXTURES[name]()
    reg, pd = push_world(fx=fx)
    if name == "unknown-unknown-entry":
        junk = [e for e in fx.obj["manifests"] if e["platform"]["os"] == "unknown"][0]
        reg.mans[junk["digest"]] = (b"x", OCI_MAN)
    if name == "no-mediaType":
        pass
    try:
        r = push(reg, pd)
        if name == "no-mediaType":
            ok(r.rc == 0, "push failed: " + r.err.strip()[:200])
            eq(reg.tag_writes, [], "tags")
            ok(pd.f_digest in reg.mans, "F not stored")
        else:
            assert_clean_push(reg, pd, r)
    finally:
        reg.close()


@case("AC4", "the push is idempotent: a second push uploads no blob again and still writes only by digest")
def _():
    reg, pd = push_world()
    try:
        assert_clean_push(reg, pd, push(reg, pd))
        n = len(reg.log)
        r = push(reg, pd)
        ok(r.rc == 0, "second push failed: " + r.err.strip()[:200])
        second = reg.log[n:]
        ok(not any(x["method"] == "POST" for x in second), "uploaded a blob that already exists")
        ok(not any(x["method"] == "PUT" and "/blobs/" in x["path"] for x in second), "uploaded a blob that already exists")
        eq(reg.tag_writes, [], "tags")
    finally:
        reg.close()


@case("AC4", "blobs the registry already has are skipped (HEAD), the others are uploaded")
def _():
    fx = mk_fx()
    pd0 = make_dir(fx, vex_real())
    pre = sorted(pd0.upload)[:1]
    reg, pd = push_world(fx=fx, preblobs=pre)
    try:
        assert_clean_push(reg, pd, push(reg, pd), skip_blobs=pre)
        ok(any(x["method"] == "HEAD" and x["path"].endswith("/blobs/" + pre[0]) for x in reg.log), "did not HEAD the existing blob")
    finally:
        reg.close()


@case("AC4", "end to end: the tool's own compute output pushes cleanly")
def _():
    fx = mk_fx()
    c = do_compute(fx.bytes, vex_real())
    ok(c.rc == 0, "compute failed")
    reg = Reg()
    reg.seed(fx.children)
    pd = make_dir(fx, vex_real())
    pd.path = c.dir
    try:
        assert_clean_push(reg, pd, push(reg, pd))
    finally:
        reg.close()


@case("AC4", "token flow: Basic credentials go only to the token endpoint, the registry sees only the Bearer token")
def _():
    reg, pd = push_world(token=True)
    try:
        r = push(reg, pd)
        assert_clean_push(reg, pd, r)
        toks = [x for x in reg.log if x["path"] == "/token"]
        ok(toks, "never asked the token endpoint")
        want = "Basic " + base64.b64encode(("%s:%s" % (USER, SECRET)).encode()).decode()
        for t in toks:
            eq(t["auth"], want, "credentials at the token endpoint")
            q = urllib.parse.parse_qs(t["query"])
            eq(q.get("service"), ["fake-registry"], "token request service")
            ok(any("repository:%s:" % reg.repo in s and "push" in s for s in q.get("scope", [])), "token request scope: %r" % q.get("scope"))
        for x in reg.log:
            if x["path"] != "/token":
                ok(x["auth"] is None or x["auth"] == "Bearer " + reg.bearer, "the registry received %r" % (x["auth"] and x["auth"][:12]))
        ok(any(x["auth"] == "Bearer " + reg.bearer for x in reg.log), "never used the token")
    finally:
        reg.close()


@param("AC4", "token flow with bad or missing credentials fails closed and stores nothing", [("wrong token", {"FSCACHE_REGISTRY_TOKEN": "nope-nope"}), ("wrong user", {"FSCACHE_REGISTRY_USER": "mallory"}), ("no credentials", "none")])
def _(e):
    push_control()
    reg, pd = push_world(token=True)
    try:
        r = push(reg, pd, env=None if e == "none" else e, creds=(e != "none"))
        assert_not_written(reg, pd, r, "bad credentials")
        eq(okmuts(reg), [], "something was written without valid credentials")
    finally:
        reg.close()


@case("AC4", "the registry rewrites the stored manifest: the read-back digest differs and the push fails")
def _():
    push_control()
    reg, pd = push_world(rewrite=True)
    try:
        r = push(reg, pd)
        ok(r.rc != 0, "accepted a registry that stored different bytes")
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        reg.close()


@case("AC4", "a registry that rewrites the manifest but reports the expected digest in its header still fails (the tool hashes the bytes itself)")
def _():
    push_control()
    reg, pd = push_world(rewrite=True, lie=True)
    try:
        r = push(reg, pd)
        ok(r.rc != 0, "trusted a registry's digest header")
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        reg.close()


@param("AC4", "a child manifest missing from the repository fails the push before F is written", [("the arm64 platform manifest is absent", (1,)), ("the amd64 platform manifest is absent", (0,)), ("every platform manifest is absent", (0, 1))])
def _(skip):
    push_control()
    reg, pd = push_world(seed_skip=skip)
    try:
        r = push(reg, pd)
        assert_not_written(reg, pd, r, "missing child")
        ok(any(x["method"] in ("HEAD", "GET") and "/manifests/" in x["path"] and x["status"] == 404 for x in reg.log), "never looked for the child")
    finally:
        reg.close()


@param("AC4", "a registry that fails with 500 part-way: non-zero exit, F never stored, nothing claimed", [("after %d writes" % n, n) for n in (0, 1, 2, 3, 5, 7, 8, 9, 10)])
def _(n):
    push_control()
    reg, pd = push_world(fail_after=n)
    try:
        r = push(reg, pd)
        assert_not_written(reg, pd, r, "500 after %d writes" % n)
    finally:
        reg.close()


@case("AC4", "a registry that rejects only the final manifest write: non-zero exit, nothing claimed")
def _():
    push_control()
    reg, pd = push_world()
    orig = reg.route

    def route(m, rest, q, body, ent):
        if m == "PUT" and rest == "manifests/" + pd.f_digest:
            return 500, {}, b"{}"
        return orig(m, rest, q, body, ent)
    reg.route = route
    try:
        r = push(reg, pd)
        assert_not_written(reg, pd, r, "F rejected")
    finally:
        reg.close()


@case("AC4", "an unreachable registry fails and claims nothing")
def _():
    push_control()
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    pd = make_dir(mk_fx(), vex_real())
    r = run(["push", "--registry", "127.0.0.1:%d" % port, "--repository", "fosterstack/cache", "--dir", pd.path],
            env={"FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET})
    ok(r.rc != 0 and pd.f_digest not in r.out, "claimed a push to nothing")


def dir_tamper_cases():
    def rm_att_manifest(pd):
        os.unlink(os.path.join(pd.path, "blobs", "sha256", hx(sorted(pd.att_digests)[0])))

    def rm_config(pd):
        os.unlink(os.path.join(pd.path, "blobs", "sha256", hx(sorted(d for d in pd.upload if json.loads(pd.blobs[hx(sorted(pd.att_digests)[0])])["config"]["digest"] == d)[0])))

    def rm_layer(pd):
        os.unlink(os.path.join(pd.path, "blobs", "sha256", hx(sorted(pd.upload)[0])))

    def rm_all_blobs(pd):
        shutil.rmtree(os.path.join(pd.path, "blobs"))

    def index_whitespace(pd):
        p = os.path.join(pd.path, "index.json"); wr(p, rd(p) + b"\n")

    def index_reserialised(pd):
        p = os.path.join(pd.path, "index.json"); wr(p, json.dumps(json.loads(rd(p)), indent=2).encode())

    def result_final_changed(pd):
        p = os.path.join(pd.path, "result.json"); o = json.loads(rd(p)); o["final_digest"] = "sha256:" + "00" * 32; wr(p, cj(o))

    def result_missing(pd):
        os.unlink(os.path.join(pd.path, "result.json"))

    def index_missing(pd):
        os.unlink(os.path.join(pd.path, "index.json"))

    def blob_tampered(pd):
        p = os.path.join(pd.path, "blobs", "sha256", hx(sorted(pd.upload)[0])); b = bytearray(rd(p)); b[0] ^= 1; wr(p, bytes(b))

    def att_manifest_tampered(pd):
        p = os.path.join(pd.path, "blobs", "sha256", hx(sorted(pd.att_digests)[0])); wr(p, rd(p) + b" ")

    def blob_symlink(pd):
        p = os.path.join(pd.path, "blobs", "sha256", hx(sorted(pd.upload)[0])); b = rd(p); os.unlink(p)
        tgt = os.path.join(os.path.dirname(pd.path), "elsewhere"); wr(tgt, b); os.symlink(tgt, p)

    def index_not_json(pd):
        wr(os.path.join(pd.path, "index.json"), b"{")

    return [("an attestation manifest is missing locally", rm_att_manifest), ("a config blob is missing locally", rm_config),
            ("a layer blob is missing locally", rm_layer), ("the blobs directory is missing", rm_all_blobs),
            ("index.json has a trailing newline (its digest no longer equals result.json's)", index_whitespace),
            ("index.json was re-serialised", index_reserialised), ("result.json's final_digest differs from F", result_final_changed),
            ("result.json is missing", result_missing), ("index.json is missing", index_missing),
            ("a blob's content does not match its digest", blob_tampered), ("an attestation manifest does not match its digest", att_manifest_tampered),
            ("a blob is a symlink out of DIR", blob_symlink), ("index.json is not JSON", index_not_json)]


@param("AC4", "a DIR that is incomplete, inconsistent or tampered is refused before anything is written", dir_tamper_cases())
def _(f):
    push_control()
    reg, pd = push_world()
    f(pd)
    try:
        r = push(reg, pd)
        assert_not_written(reg, pd, r, "bad DIR")
        eq(muts(reg), [], "something was sent to the registry although DIR is not consistent")
        ok(r.err.strip() != "", "no reason on stderr")
    finally:
        reg.close()


@case("AC4", "--base-digest that does not match result.json's base_digest is refused before anything is written; a matching one is accepted")
def _():
    push_control()
    reg, pd = push_world()
    try:
        r = push(reg, pd, extra=["--base-digest", "sha256:" + "12" * 32])
        assert_not_written(reg, pd, r, "wrong base digest")
        eq(muts(reg), [], "something was written")
        r = push(reg, pd, extra=["--base-digest", pd.result["base_digest"]])
        assert_clean_push(reg, pd, r)
    finally:
        reg.close()


@param("AC4", "an invalid repository name is refused before any request", [(n, n) for n in ("../evil", "a//b", "A/B", "a b", "a?x=1", "a/../../v2", "", "-a", "a/%2e%2e/b", "a#b", "a\nb")])
def _(name):
    push_control()
    reg, pd = push_world()
    try:
        r = run(["push", "--registry", reg.host, "--repository", name, "--dir", pd.path],
                env={"FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET})
        ok(r.rc != 0, "accepted repository %r" % name)
        eq(reg.log, [], "a request was made for an invalid repository name")
    finally:
        reg.close()


@case("AC4", "a nested repository name is accepted and every request stays under it")
def _():
    reg, pd = push_world(repo="org/team/cache")
    try:
        assert_clean_push(reg, pd, push(reg, pd))
    finally:
        reg.close()


NONLOCAL_REFUSED_UNSEEN = ["http://registry.example.test", "http://registry.example.test:5000", "http://127.0.0.1", "https://registry.example.test",
                           "127.0.0.1@registry.example.test", "localhost@registry.example.test:80", "user:pw@registry.example.test", "registry.example.test/path",
                           "", "registry.example.test?x=1", "127.0.0.1:99999999"]


@param("AC4", "a registry that is not a bare host is refused before any connection (the proxy stand-in sees nothing, and no credential leaves)", [(h or "empty", h) for h in NONLOCAL_REFUSED_UNSEEN])
def _(h):
    push_control()
    sink = Sink()
    pd = make_dir(mk_fx(), vex_real())
    try:
        r = run(["push", "--registry", h, "--repository", "fosterstack/cache", "--dir", pd.path],
                env=dict(sink.env(), FSCACHE_REGISTRY_USER=USER, FSCACHE_REGISTRY_TOKEN=SECRET))
        ok(r.rc != 0, "accepted registry %r" % h)
        eq(sink.log, [], "something was sent towards %r" % h)
        ok(SECRET not in r.out and SECRET not in r.err, "a credential was printed")
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        sink.close()


NONLOCAL_HOSTS = ["registry.example.test", "registry.example.test:5000", "localhost.example.test", "127.0.0.1.example.test", "localhost.example.test:5000", "10.255.255.1:5000", "[::2]:5000"]


@param("AC4", "a non-local host is never spoken to over plain http and never sees credentials", [(h, h) for h in NONLOCAL_HOSTS])
def _(h):
    push_control()
    sink = Sink()
    pd = make_dir(mk_fx(), vex_real())
    try:
        r = run(["push", "--registry", h, "--repository", "fosterstack/cache", "--dir", pd.path],
                env=dict(sink.env(), FSCACHE_REGISTRY_USER=USER, FSCACHE_REGISTRY_TOKEN=SECRET), timeout=60)
        ok(r.rc != 0, "the push to an unreachable non-local host succeeded")
        for x in sink.log:
            ok(x["method"] == "CONNECT", "a plain %s request for a non-local host went out: %s" % (x["method"], x["path"]))
            ok(x["auth"] is None, "credentials were sent")
        ok(SECRET not in r.out and SECRET not in r.err, "a credential was printed")
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        sink.close()


REALMS = ["http://registry.example.test/token", "http://127.0.0.1@registry.example.test/token", "http://127.0.0.1.example.test/token",
          "http://localhost.example.test/token", "https://registry.example.test/token", "ftp://127.0.0.1/token", "//registry.example.test/token"]


@param("AC4", "a token realm that is not https or a local host is refused and no credential is sent anywhere", [(x, x) for x in REALMS])
def _(realm):
    push_control()
    sink = Sink()
    reg, pd = push_world(token=True, realm=realm)
    try:
        r = push(reg, pd, env=sink.env())
        ok(r.rc != 0, "pushed using a hostile token realm")
        ok(pd.f_digest not in reg.mans and okmuts(reg) == [], "something was written")
        for x in sink.log:
            ok(x["method"] == "CONNECT" and x["auth"] is None, "a plain request or credential reached %s" % x["path"])
        for x in reg.log:
            ok(x["auth"] is None or x["auth"].startswith("Bearer "), "Basic credentials reached the registry")
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        sink.close()
        reg.close()


@case("AC4", "a redirect away from the registry is never followed with the bearer token")
def _():
    push_control()
    sink = Sink()
    reg, pd = push_world(token=True, redirect_readback=True)
    try:
        r = push(reg, pd, env=sink.env())
        ok(r.rc != 0, "accepted a read-back that was redirected away")
        for x in sink.log:
            ok(x["auth"] is None, "an Authorization header followed the redirect")
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        sink.close()
        reg.close()


@case("AC4", "the push never writes a tag, whatever the options (a tag write would be visible to the registry)")
def _():
    for extra in ([], ["--base-digest", None]):
        reg, pd = push_world()
        try:
            ex = [pd.result["base_digest"] if x is None else x for x in extra]
            r = push(reg, pd, extra=ex)
            ok(r.rc == 0, "push failed")
            eq(reg.tag_writes, [], "tags written")
            for x in reg.log:
                if "/manifests/" in x["path"] and x["method"] != "GET" and x["method"] != "HEAD":
                    ok(DIGEST_RE.match(x["path"].rsplit("/", 1)[1]), "manifest write by something that is not a digest")
        finally:
            reg.close()


@case("AC4", "credentials are never printed, also with the registry failing")
def _():
    for kw in ({}, {"fail_after": 2}, {"rewrite": True}, {"token": True}):
        reg, pd = push_world(**kw)
        try:
            r = push(reg, pd)
            ok(SECRET not in r.out + r.err, "credential printed")
        finally:
            reg.close()


def main():
    only = os.environ.get("ONLY")
    passed, failed, fails = 0, 0, []
    for tag, name, f, arg in CASES:
        if only and only not in name:
            continue
        try:
            f() if arg is None else f(arg)
            passed += 1
            print("ok   [%s] %s" % (tag, name))
        except Fail as e:
            failed += 1
            fails.append((tag, name))
            print("FAIL [%s] %s: %s" % (tag, name, str(e)[:400]))
        except Exception as e:
            failed += 1
            fails.append((tag, name))
            print("FAIL [%s] %s: harness/tool error %s: %s" % (tag, name, type(e).__name__, str(e)[:300]))
    print("")
    by = {}
    for tag, name, f, arg in CASES:
        by[tag] = by.get(tag, 0) + 1
    print("cases by AC: " + ", ".join("%s=%d" % (k, by[k]) for k in sorted(by)))
    print("%d passed, %d failed, %d cases" % (passed, failed, passed + failed))
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(1 if failed else 0)


main()
PYEOF

python3 "$T/harness.py"
