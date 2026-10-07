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
# Needs python3 (standard library only) and, for the https cases, the openssl command. Exit status is non-zero when any case fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT
export VEX_INDEX="${VEX_INDEX:-$ROOT/bin/vex-index.py}"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

cat >"$T/harness.py" <<'PYEOF'
import ast, base64, hashlib, http.server, json, os, random, re, shutil, socket, subprocess, sys
import atexit, gzip, io, select, tarfile, socketserver, ssl, tempfile, threading, time, urllib.parse

ROOT = os.environ["ROOT"]
TOOL = os.environ["VEX_INDEX"]
TMP = tempfile.mkdtemp(prefix="vexidx-cases-")
atexit.register(shutil.rmtree, TMP, True)
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


NETGUARD = os.path.join(TMP, "netguard")
os.makedirs(NETGUARD)
with open(os.path.join(NETGUARD, "sitecustomize.py"), "w") as _f:
    _f.write("""import os, socket
_log = os.environ.get("VEXIDX_NETLOG")
_mode = os.environ.get("VEXIDX_NETMODE", "block")
if _log:
    def _rec(kind, target):
        with open(_log, "a") as f:
            f.write("%s %s\\n" % (kind, target))
    _connect, _connect_ex = socket.socket.connect, socket.socket.connect_ex
    _gai, _ghbn, _ghbne = socket.getaddrinfo, socket.gethostbyname, socket.gethostbyname_ex
    def connect(self, addr):
        if self.family != getattr(socket, "AF_UNIX", -1):
            _rec("connect", addr)
            if _mode == "block":
                raise OSError("network access blocked by the test")
        return _connect(self, addr)
    def connect_ex(self, addr):
        if self.family != getattr(socket, "AF_UNIX", -1):
            _rec("connect_ex", addr)
            if _mode == "block":
                return 111
        return _connect_ex(self, addr)
    def gai(host, *a, **k):
        _rec("resolve", host)
        if _mode == "block":
            raise OSError("name resolution blocked by the test")
        return _gai(host, *a, **k)
    def ghbn(host):
        _rec("resolve", host)
        if _mode == "block":
            raise OSError("name resolution blocked by the test")
        return _ghbn(host)
    def ghbne(host):
        _rec("resolve", host)
        if _mode == "block":
            raise OSError("name resolution blocked by the test")
        return _ghbne(host)
    _sendto, _sendmsg = socket.socket.sendto, socket.socket.sendmsg
    def sendto(self, *a):
        _rec("sendto", a[-1])
        if _mode == "block":
            raise OSError("network access blocked by the test")
        return _sendto(self, *a)
    def sendmsg(self, buffers, ancdata=(), flags=0, address=None):
        if address is not None:
            _rec("sendmsg", address)
            if _mode == "block":
                raise OSError("network access blocked by the test")
        return _sendmsg(self, buffers, ancdata, flags, address) if address is not None else _sendmsg(self, buffers, ancdata, flags)
    socket.socket.sendto, socket.socket.sendmsg = sendto, sendmsg
    socket.socket.connect, socket.socket.connect_ex = connect, connect_ex
    socket.getaddrinfo, socket.gethostbyname, socket.gethostbyname_ex = gai, ghbn, ghbne
""")


STUBS = os.path.join(NETGUARD, "bin")
os.makedirs(STUBS)
for _n in ("curl", "wget", "nc", "ncat", "ssh", "scp", "sftp", "git", "telnet", "ftp", "gh"):
    with open(os.path.join(STUBS, _n), "w") as _f:
        _f.write('#!/bin/sh\necho "exec %s" >> "$VEXIDX_NETLOG"\nexit 1\n' % _n)
    os.chmod(os.path.join(STUBS, _n), 0o755)


def run(args, env=None, cwd=None, replace_env=False, timeout=90, net=None):
    """net: None = block for compute/verify (any attempt fails the case), "observe" = record only, "off" = no guard"""
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
    mode = net or ("block" if args and args[0] in ("compute", "verify") else "off")
    netlog = None
    auto_cwd = cwd is None
    if auto_cwd:
        cwd = tempfile.mkdtemp(dir=TMP, prefix="cwd-")
    tdir = tempfile.mkdtemp(dir=TMP, prefix="tmpdir-")
    e["TMPDIR"] = tdir
    if mode != "off":
        e["PATH"] = STUBS + os.pathsep + e.get("PATH", "")
        fd, netlog = tempfile.mkstemp(dir=TMP, prefix="netlog-")
        os.close(fd)
        e["PYTHONPATH"] = NETGUARD + (os.pathsep + e["PYTHONPATH"] if e.get("PYTHONPATH") else "")
        e["VEXIDX_NETLOG"], e["VEXIDX_NETMODE"] = netlog, mode
    try:
        p = subprocess.run([sys.executable, TOOL] + list(args), env=e, cwd=cwd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Fail("the tool did not finish within %ds" % timeout)
    r = R(p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"))
    r.net = open(netlog).read().splitlines() if netlog else []
    stray = (os.listdir(cwd) if auto_cwd else []) + os.listdir(tdir)
    if stray:
        raise Fail("the tool left files in its working directory or TMPDIR: %s" % stray[:5])
    if mode == "block" and r.net:
        raise Fail("the tool attempted network access (%s): %s" % (args[0], r.net[:3]))
    return r


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
def mini_tar(seed):
    """a minimal valid tar archive (one small executable file), byte-for-byte reproducible"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        body = ("#!/fscache " + seed + "\n").encode()
        ti = tarfile.TarInfo("fscache")
        ti.size, ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = len(body), 0, 0o755, 0, 0, "", ""
        t.addfile(ti, io.BytesIO(body))
    return buf.getvalue()


def mk_child(arch, variant=None, mt=OCI_MAN, os_="linux"):
    seed = "%s/%s/%s" % (os_, arch, variant)
    cfg = cj({"architecture": arch, "os": os_, "config": {"Entrypoint": ["/fscache"]},
              "rootfs": {"type": "layers", "diff_ids": [dg(mini_tar(seed))]}})
    raw_layer = mini_tar(seed)
    layer = gzip.compress(raw_layer, mtime=0)
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
    cmt = OCI_MAN if kind == "oci" else DOCKER_MAN  # kinds: oci, docker-children (OCI index with docker v2 children), docker (a manifest list: refused as input)
    f.children = [mk_child(a, v, cmt) for a, v in plats]
    entries = [desc_of(c) for c in f.children]
    if extra_entry:
        for e, ch in zip(entries, f.children):
            e.update(json.loads(json.dumps(extra_entry(ch) if callable(extra_entry) else extra_entry)))
    f.junk = None
    if unknown:
        junk = json.dumps({"schemaVersion": 2, "mediaType": OCI_MAN, "config": {"mediaType": OCI_CFG, "digest": "sha256:" + "5" * 64, "size": 7}, "layers": []}).encode()
        f.junk = junk
        entries.append({"mediaType": OCI_MAN, "digest": dg(junk), "size": len(junk),
                        "platform": {"architecture": "unknown", "os": "unknown"}})
    obj = {"schemaVersion": 2}
    if not no_mt:
        obj["mediaType"] = DOCKER_LIST if kind == "docker" else OCI_IDX
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

UNKNOWN_FIELDS = dict(
    extra_top={"artifactType": "application/vnd.example.index+json", "annotations": {"org.example.k": "v", "org.opencontainers.image.created": "2026-10-01T00:00:00Z"},
               "subject": {"mediaType": OCI_MAN, "digest": "sha256:" + "9" * 64, "size": 10}, "x-extension": {"a": [1, 2, {"b": None, "c": True}], "n": 9007199254740992, "neg": -9007199254740992}},
    extra_entry=lambda ch: {"artifactType": "application/vnd.example.image+json", "urls": ["https://example.test/blob"],
                            "data": base64.b64encode(ch["bytes"]).decode(),  # embedded data equals the referenced content, as OCI requires
                            "annotations": {"org.example.entry": "e"}, "x-ext": {"deep": [[1], [2]], "t": False}})
FIXTURES = {
    "oci-2-platform": lambda: mk_fx(),
    "oci-compact-no-indent": lambda: mk_fx(indent=None),
    "oci-index-with-docker-v2-children": lambda: mk_fx(kind="docker-children"),
    "arm-v7-variant": lambda: mk_fx(plats=(("amd64", None), ("arm64", "v8"), ("arm", "v7"))),
    "unknown-unknown-entry": lambda: mk_fx(unknown=True),
    "single-platform": lambda: mk_fx(plats=(("amd64", None),)),
    "extra-fields-and-non-ascii": lambda: mk_fx(**EXTRAS),
    "unknown-fields-on-entries-and-index": lambda: mk_fx(**UNKNOWN_FIELDS),
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


HOSTILE = {"GITHUB_REPOSITORY": "evil-org/evil-repo", "GITHUB_SHA": "0" * 40, "GITHUB_REF": "refs/tags/v9.9.9", "GITHUB_ACTIONS": "true",
           "CI": "true", "SOURCE_DATE_EPOCH": "1234567890", "USER": "mallory", "LOGNAME": "mallory", "HOSTNAME": "build-box-7",
           "RUNNER_NAME": "r1", "RUNNER_OS": "Linux", "BUILDKITE": "true", "GITLAB_CI": "true", "TZ": "Asia/Kolkata"}
ENVS = [
    ("PYTHONHASHSEED=0", {"PYTHONHASHSEED": "0"}), ("PYTHONHASHSEED=1", {"PYTHONHASHSEED": "1"}),
    ("PYTHONHASHSEED=4294967295", {"PYTHONHASHSEED": "4294967295"}), ("PYTHONHASHSEED=random", {"PYTHONHASHSEED": "random"}),
    ("LC_ALL=C", {"LC_ALL": "C", "LANG": "C"}), ("LC_ALL=C.UTF-8", {"LC_ALL": "C.UTF-8"}),
    ("LC_ALL=POSIX LC_CTYPE=bogus", {"LC_ALL": "POSIX", "LC_CTYPE": "xx_XX.bogus", "LANG": "xx_XX.bogus"}),
    ("TZ=Pacific/Kiritimati", {"TZ": "Pacific/Kiritimati"}), ("TZ=America/St_Johns", {"TZ": "America/St_Johns"}),
    ("PYTHONIOENCODING=ascii PYTHONUTF8=0", {"PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0"}),
    ("PYTHONUTF8=1", {"PYTHONUTF8": "1"}),
    ("PYTHONOPTIMIZE=1", {"PYTHONOPTIMIZE": "1"}),
    ("HOME unset", {"HOME": None}),
    ("hostile CI environment (GITHUB_*, CI, SOURCE_DATE_EPOCH, USER, HOSTNAME, RUNNER_*)", HOSTILE),
    ("GITHUB_REPOSITORY alone", {"GITHUB_REPOSITORY": "someone/else"}),
    ("SOURCE_DATE_EPOCH alone", {"SOURCE_DATE_EPOCH": "86400"}),
    ("USER and HOSTNAME alone", {"USER": "x", "HOSTNAME": "y"}),
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


GH_NAMES = ["GITHUB_ACTION", "GITHUB_ACTIONS", "GITHUB_ACTOR", "GITHUB_API_URL", "GITHUB_BASE_REF", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH",
            "GITHUB_HEAD_REF", "GITHUB_JOB", "GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_REF_TYPE", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER",
            "GITHUB_RETENTION_DAYS", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_ID", "GITHUB_RUN_NUMBER", "GITHUB_SERVER_URL", "GITHUB_SHA",
            "GITHUB_WORKFLOW", "GITHUB_WORKSPACE", "RUNNER_ARCH", "RUNNER_NAME", "RUNNER_OS", "RUNNER_TEMP", "RUNNER_TOOL_CACHE", "CI",
            "SOURCE_DATE_EPOCH", "USER", "HOSTNAME", "LOGNAME", "TZ", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_CACHE_URL", "BUILDKITE", "GITLAB_CI",
            "JENKINS_URL", "TRAVIS", "CIRCLECI", "DOCKER_HOST", "NO_COLOR", "TERM"]
GH_FILES = ["GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY", "GITHUB_STATE"]


def hostile_long(s, variant):
    e = {n: ("hostile-%s-%s" % (variant, n)) for n in GH_NAMES}
    e["SOURCE_DATE_EPOCH"] = "%d" % (1000000000 + variant * 777)
    e["GITHUB_RUN_ID"] = "%d" % (9000000 + variant)
    e["TZ"] = ("Asia/Kolkata", "Pacific/Auckland", "America/Sao_Paulo")[variant % 3]
    e["GITHUB_EVENT_PATH"] = os.path.join(s, "event-%d.json" % variant)
    wr(e["GITHUB_EVENT_PATH"], b'{"repository":{"full_name":"evil/evil"}}')
    e["HOME"] = os.path.join(s, "home-%d" % variant)
    for n in GH_FILES:
        e[n] = os.path.join(s, "gh-%s-%d" % (n, variant))
    return e


DECOMPOSED = "cafe\u0301 A\u030a \u00e9 \u2014 \U0001F680"  # decomposed e+acute and A+ring next to precomposed e-acute: normalising would change the bytes


def vex_na():
    o = base_vex_obj()
    o["author"] = "Jos\u00e9 " + DECOMPOSED
    o["statements"][0]["impact_statement"] = "na\u00efve " + DECOMPOSED
    o["statements"][0]["status_notes"] = "\u65e5\u672c\u8a9e"
    return json.dumps(o, ensure_ascii=False).encode("utf-8")


@case("AC1", "strings are never Unicode-normalised: decomposed and precomposed forms in the index and the VEX are preserved byte for byte in F and in the statement")
def _():
    fx = mk_fx(extra_top={"annotations": {"org.example.k": DECOMPOSED}})
    vb = vex_na()
    r = do_compute(fx.bytes, vb)
    check_matches_ref(fx.bytes, vb, r)
    fb = rd(os.path.join(r.dir, "index.json"))
    ok(DECOMPOSED.encode("utf-8") in fb, "F does not carry the decomposed string unchanged")
    stmts = [rd(os.path.join(r.dir, "blobs", "sha256", n)) for n in os.listdir(os.path.join(r.dir, "blobs", "sha256"))]
    ok(any(DECOMPOSED.encode("utf-8") in b for b in stmts), "the statement does not carry the decomposed string unchanged")


NA_ENVS = [("LC_ALL=C PYTHONUTF8=0 PYTHONCOERCECLOCALE=0 PYTHONIOENCODING=ascii", {"LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0", "PYTHONIOENCODING": "ascii"}),
           ("LANG unset, LC_ALL=POSIX, PYTHONCOERCECLOCALE=0", {"LANG": None, "LC_ALL": "POSIX", "PYTHONCOERCECLOCALE": "0", "PYTHONUTF8": "0"}),
           ("PYTHONUTF8=1", {"PYTHONUTF8": "1"})]


@param("AC1", "a non-ASCII VEX and index compute and verify identically under an ASCII-only locale and encoding (no UnicodeEncodeError, no locale-dependent output)", NA_ENVS)
def _(env):
    fx = mk_fx(**EXTRAS)
    vb = vex_na()
    base = do_compute(fx.bytes, vb)
    ok(base.rc == 0, "baseline compute failed")
    r = do_compute(fx.bytes, vb, env=env)
    ok(r.rc == 0, "compute failed under %s: %s" % (list(env), r.err.strip()[:200]))
    eq(tree(r.dir), tree(base.dir), "output tree")
    v = verify(rd(os.path.join(r.dir, "index.json")), vb, base=fx.bytes, blobs=os.path.join(r.dir, "blobs"), env=env)
    ok(v.rc == 0, "verify failed under the ASCII locale: " + v.err.strip()[:200])


@param("AC1", "output is identical under a long hostile CI environment (every GITHUB_*, RUNNER_*, CI, SOURCE_DATE_EPOCH, USER, HOSTNAME, HOME, LOGNAME, TZ ... set to hostile values), and no GITHUB_OUTPUT/ENV/PATH/STEP_SUMMARY file is touched", [("values A", 1), ("values B", 2), ("values C", 3)])
def _(v):
    fx, t = base_tree()
    s = sb()
    env = hostile_long(s, v)
    r = do_compute(fx.bytes, vex_real(), env=env, s=s)
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:200])
    eq(tree(r.dir), t, "output tree")
    for n in GH_FILES:
        ok(not os.path.lexists(env[n]), "the tool wrote to $%s" % n)
    ok(not os.path.lexists(env["HOME"]), "the tool created $HOME")
    good = final_of(fx, vex_real())
    vr = verify(good, vex_real(), env=env)
    ok(vr.rc == 0, "verify rejected a good final index under the hostile environment")
    bad = json.loads(good); bad["manifests"].pop()
    vr = verify(cj(bad), vex_real(), env=env)
    ok(vr.rc != 0, "verify accepted a bad final index under the hostile environment")


@case("AC1", "output is identical with every environment variable unset (only PATH), for compute and verify")
def _():
    fx, t = base_tree()
    r = do_compute(fx.bytes, vex_real(), replace_env=True)
    ok(r.rc == 0, "compute failed")
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


@case("AC1", "the network guard works (positive control: it records and blocks a connection, a name lookup and an http request)")
def _():
    ok(os.path.isfile(TOOL), "the tool does not exist")
    for code in ("import socket; socket.create_connection(('127.0.0.1', 9))",
                 "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9/', timeout=2)",
                 "import socket; socket.getaddrinfo('registry.example.test', 443)",
                 "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('127.0.0.1', 9))",
                 "import subprocess; subprocess.run(['curl', '-s', 'http://127.0.0.1:9/'])"):
        fd, lg = tempfile.mkstemp(dir=TMP); os.close(fd)
        e = dict(base_env(), PYTHONPATH=NETGUARD, VEXIDX_NETLOG=lg, VEXIDX_NETMODE="block", PATH=STUBS + os.pathsep + os.environ["PATH"])
        p = subprocess.run([sys.executable, "-c", code], env=e, capture_output=True)
        ok(p.returncode != 0 or "subprocess" in code, "the guard did not block: " + code)
        ok(open(lg).read().strip() != "", "the guard did not record: " + code)


@case("AC1", "compute and verify make no network attempt at all (every compute and verify run in this file is guarded; here also with registry credentials and proxies configured)")
def _():
    fx = mk_fx()
    env = {"http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
           "HTTPS_PROXY": "http://127.0.0.1:9", "FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET}
    r = do_compute(fx.bytes, vex_real(), env=env)
    check_matches_ref(fx.bytes, vex_real(), r)
    v = run(["verify", "--final", os.path.join(r.dir, "index.json"), "--vex", r.vex, "--base", r.index, "--blobs", os.path.join(r.dir, "blobs")], env=env)
    ok(v.rc == 0, "verify failed: " + v.err.strip()[:200])
    eq(v.net, [], "network attempts by verify")


@case("AC1", "verify gives the same verdict under a hostile CI environment (accepts a good final index, rejects a bad one)")
def _():
    fx = mk_fx()
    good = final_of(fx, vex_real())
    r = verify(good, vex_real(), env=HOSTILE)
    ok(r.rc == 0, "rejected a good final index under a hostile environment: " + r.err.strip()[:200])
    bad = json.loads(good); bad["manifests"].pop()
    r = verify(cj(bad), vex_real(), env=HOSTILE)
    ok(r.rc != 0, "accepted a bad final index under a hostile environment")


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
        ok("Traceback" not in r.err, "a Python traceback instead of a plain reason: " + r.err.strip()[-200:])
        ok("sha256:" not in r.out, "printed a digest although it refused")
        if pre:
            eq(os.listdir(out), [], "the pre-existing empty out-dir must stay empty")
        else:
            ok(not os.path.lexists(out), "the out-dir was created although the tool refused")
        eq(tree(os.path.join(s, "in")), {"index.json": db, "vex.json": vb}, "inputs")
        eq(sorted(os.listdir(s)), sorted(["in"] + (["out"] if pre else [])), "files created next to the out-dir by a refusal (e.g. <out>.tmp)")


def nest(levels):
    x = 1
    for _ in range(levels):
        x = [x]
    return x


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
    "a UTF-8 byte-order mark in front of a valid index": b"\xef\xbb\xbf" + mk_fx().bytes,
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
    "digest of Arabic-Indic digits": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + "\u0660" * 64)),
    "digest of full-width hex": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + "\uff41" * 64)),
    "digest mixing one full-width digit": bad_index(lambda o: o["manifests"][0].update(digest="sha256:" + "\uff11" + H64[1:])),
    "digest whose algorithm uses a long s": bad_index(lambda o: o["manifests"][0].update(digest="\u017fha256:" + H64)),
    "digest whose algorithm uses a Cyrillic a": bad_index(lambda o: o["manifests"][0].update(digest="sh\u0430256:" + H64)),
    "size is a string of full-width digits": bad_index(lambda o: o["manifests"][0].update(size="\uff11\uff12\uff13\uff14")),
    "size is a string of Arabic-Indic digits": bad_index(lambda o: o["manifests"][0].update(size="\u0661\u0662\u0663")),
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

    "a Docker manifest list is not an OCI index": bad_index(lambda o: (o.update(mediaType=DOCKER_LIST),)),
    "mediaType missing": bad_index(lambda o: o.pop("mediaType")),
    "mediaType is a number": bad_index(lambda o: o.update(mediaType=7)),
    "mediaType is another string": bad_index(lambda o: o.update(mediaType="application/json")),
    "mediaType is an OCI image manifest": bad_index(lambda o: o.update(mediaType=OCI_MAN)),
    "mediaType differs in case": bad_index(lambda o: o.update(mediaType=OCI_IDX.upper())),
    "schemaVersion missing": bad_index(lambda o: o.pop("schemaVersion")),
    "schemaVersion 1": bad_index(lambda o: o.update(schemaVersion=1)),
    "schemaVersion 3": bad_index(lambda o: o.update(schemaVersion=3)),
    "schemaVersion is the string 2": bad_index(lambda o: o.update(schemaVersion="2")),
    "schemaVersion is 2.0": bad_index(lambda o: o.update(schemaVersion=2.0)),
    "schemaVersion is true": bad_index(lambda o: o.update(schemaVersion=True)),
    "child mediaType missing": bad_index(lambda o: o["manifests"][0].pop("mediaType")),
    "child mediaType is a number": bad_index(lambda o: o["manifests"][0].update(mediaType=7)),
    "child mediaType is text/plain": bad_index(lambda o: o["manifests"][0].update(mediaType="text/plain")),
    "child is a nested OCI index": bad_index(lambda o: o["manifests"][0].update(mediaType=OCI_IDX)),
    "child is a Docker manifest list": bad_index(lambda o: o["manifests"][0].update(mediaType=DOCKER_LIST)),
    "size just over 2**31": bad_index(lambda o: o["manifests"][0].update(size=2 ** 31 + 1)),
    "size zero": bad_index(lambda o: o["manifests"][0].update(size=0)),
    "size 1e999 (infinity)": bad_index(lambda o: o["manifests"][0].update(size="@@1e999@@")),
    "size -1e999": bad_index(lambda o: o["manifests"][0].update(size="@@-1e999@@")),
    "size Infinity literal": bad_index(lambda o: o["manifests"][0].update(size="@@Infinity@@")),
    "lone surrogate in an annotation": bad_index(lambda o: o["manifests"][0].update(annotations={"k": "##D800##"})),
    "lone surrogate in a key": bad_index(lambda o: o.update({"##DC00##": 1})),
    "a float in an unknown top-level field": bad_index(lambda o: o.update(x="@@1.5@@")),
    "a float 1.0 in an unknown top-level field": bad_index(lambda o: o.update(x="@@1.0@@")),
    "a float in an unknown entry field": bad_index(lambda o: o["manifests"][0].update(x="@@1e2@@")),
    "a float -0.0 in an entry annotation": bad_index(lambda o: o["manifests"][0].update(annotations={"k": "@@-0.0@@"})),
    "NaN in an unknown entry field": bad_index(lambda o: o["manifests"][0].update(x="@@NaN@@")),
    "Infinity in an unknown top-level field": bad_index(lambda o: o.update(x="@@Infinity@@")),
    "an integer beyond 2**53 in an unknown field": bad_index(lambda o: o["manifests"][0].update(x=2 ** 53 + 1)),
    "metadata nested deeper than 32 inside an otherwise valid index": bad_index(lambda o: o.update(x=nest(32))),
}
for _k, _v in list(D_BAD.items()):
    if b'"@@' in _v:
        D_BAD[_k] = re.sub(rb'"@@(.*?)@@"', rb"\1", _v)
    D_BAD[_k] = D_BAD[_k].replace(b"##D800##", b"\\ud800").replace(b"##DC00##", b"\\udc00")


@param("AC2", "malformed or hostile index is refused and nothing is written", sorted(D_BAD.items()))
def _(db):
    assert_refused(db, vex_real(), "index")


def final_of(fx, vb):
    return ref_compute(fx.bytes, vb)[0]


@case("AC2", "an index that is already final (a complete output of the tool) is refused")
def _():
    fx = mk_fx()
    assert_refused(final_of(fx, vex_real()), vex_real(), "already final")


def vex_with(f, base=None):
    o = json.loads((base or VEX_MIN).decode("utf-8"))
    f(o)
    return json.dumps(o).encode("utf-8")


V_BAD = {
    "empty file": b"", "whitespace only": b" \n", "not json": b"statements: []",
    "json array": b"[]", "json string": b'"x"', "json null": b"null", "json number": b"7",
    "object without @context": b'{"statements":[{"status":"not_affected"}]}',
    "object without statements": b'{"@context":"https://openvex.dev/ns/v0.2.0"}',
    "empty object": b"{}",
    "statements is an object": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":{"a":1}}',
    "statements is a string": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":"none"}',
    "statements is null": b'{"@context":"https://openvex.dev/ns/v0.2.0","statements":null}',
    "duplicate key": VEX_MIN.replace(b'"version":1,', b'"version":1,"version":1,'),
    "NaN": vex_with(lambda o: o.update(version="@@NaN@@")),
    "Infinity": vex_with(lambda o: o.update(version="@@Infinity@@")),
    "invalid utf-8": VEX_MIN.replace("na\u00efve".encode("utf-8"), b"na\xffve"),
    "truncated": VEX_MIN[:-5],
    "a UTF-8 byte-order mark in front of a valid VEX": b"\xef\xbb\xbf" + VEX_MIN,
}


V_BAD.update({
    "@context is null": vex_with(lambda o: o.update({"@context": None})),
    "@context is a number": vex_with(lambda o: o.update({"@context": 7})),
    "@context is not an openvex.dev URL": vex_with(lambda o: o.update({"@context": "https://example.test/ns/v0.2.0"})),
    "@context is a list": vex_with(lambda o: o.update({"@context": ["https://openvex.dev/ns/v0.2.0"]})),
    "@id missing": vex_with(lambda o: o.pop("@id")),
    "@id is a number": vex_with(lambda o: o.update({"@id": 5})),
    "author missing": vex_with(lambda o: o.pop("author")),
    "author is a list": vex_with(lambda o: o.update(author=["a"])),
    "timestamp missing": vex_with(lambda o: o.pop("timestamp")),
    "timestamp is a number": vex_with(lambda o: o.update(timestamp=1760000000)),
    "version missing": vex_with(lambda o: o.pop("version")),
    "version 0": vex_with(lambda o: o.update(version=0)),
    "version is a string": vex_with(lambda o: o.update(version="1")),
    "version is a string of full-width digits": vex_with(lambda o: o.update(version="\uff11")),
    "version is true": vex_with(lambda o: o.update(version=True)),
    "version is 1.5": vex_with(lambda o: o.update(version=1.5)),
    "statements is empty": vex_with(lambda o: o.update(statements=[])),
    "a statement is a number": vex_with(lambda o: o["statements"].append(7)),
    "a statement is null": vex_with(lambda o: o["statements"].append(None)),
    "a statement is a list": vex_with(lambda o: o["statements"].append([])),
    "a statement has no vulnerability": vex_with(lambda o: o["statements"][0].pop("vulnerability")),
    "vulnerability is an object without name": vex_with(lambda o: o["statements"][0].update(vulnerability={"@id": "x"})),
    "vulnerability name is a number": vex_with(lambda o: o["statements"][0].update(vulnerability={"name": 5})),
    "vulnerability is a list": vex_with(lambda o: o["statements"][0].update(vulnerability=["CVE-2000-0001"])),
    "a statement has no products": vex_with(lambda o: o["statements"][0].pop("products")),
    "products is an object": vex_with(lambda o: o["statements"][0].update(products={})),
    "a statement has no status": vex_with(lambda o: o["statements"][0].pop("status")),
    "status is not an OpenVEX status": vex_with(lambda o: o["statements"][0].update(status="fine")),
    "status is a number": vex_with(lambda o: o["statements"][0].update(status=1)),
    "number 1e999": vex_with(lambda o: o.update(version="@@1e999@@")),
    "number -1e999": vex_with(lambda o: o.update(version="@@-1e999@@")),
    "number -Infinity literal": vex_with(lambda o: o.update(version="@@-Infinity@@")),
    "lone surrogate (high)": vex_with(lambda o: o["statements"][0].update(impact_statement="a##D800##b")),
    "lone surrogate (low)": vex_with(lambda o: o["statements"][0].update(impact_statement="a##DC00##b")),
    # (a lone surrogate in a key cannot be isolated in a VEX: any key the schema does not define is refused anyway)
    "@context with a bogus suffix": vex_with(lambda o: o.update({"@context": "https://openvex.dev/ns/v0.2.0x"})),
    "@context without a version": vex_with(lambda o: o.update({"@context": "https://openvex.dev/ns"})),
    "@context of v0.1.0": vex_with(lambda o: o.update({"@context": "https://openvex.dev/ns/v0.1.0"})),
    "@context with a prefix attack": vex_with(lambda o: o.update({"@context": "https://openvex.dev/ns/v0.2.0.evil.test/"})),
    "timestamp is yesterday": vex_with(lambda o: o.update(timestamp="yesterday")),
    "timestamp is a date only": vex_with(lambda o: o.update(timestamp="2026-09-20")),
    "timestamp has no T": vex_with(lambda o: o.update(timestamp="2026-09-20 09:00:00Z")),
    "timestamp has no zone": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:00")),
    "timestamp is not a calendar date": vex_with(lambda o: o.update(timestamp="2026-13-45T00:00:00Z")),
    "timestamp is empty": vex_with(lambda o: o.update(timestamp="")),
    "timestamp is not a calendar date (Feb 30)": vex_with(lambda o: o.update(timestamp="2026-02-30T00:00:00Z")),
    "timestamp with hour 24": vex_with(lambda o: o.update(timestamp="2026-09-20T24:00:00Z")),
    "timestamp with minute 60": vex_with(lambda o: o.update(timestamp="2026-09-20T09:60:00Z")),
    "timestamp with second 61": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:61Z")),
    "timestamp with a dot and no fraction digits": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:00.Z")),
    "timestamp with a trailing newline": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:00Z\n")),
    "timestamp with a trailing zero-width space": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:00Z\u200b")),
    "timestamp with full-width year digits": vex_with(lambda o: o.update(timestamp="\uff12\uff10\uff12\uff16-09-20T09:00:00Z")),
    "vulnerability is a plain string (v0.2.0 needs an object)": vex_with(lambda o: o["statements"][0].update(vulnerability="CVE-2000-0001")),
    "vulnerability name is empty": vex_with(lambda o: o["statements"][0].update(vulnerability={"name": ""})),
    "products is empty": vex_with(lambda o: o["statements"][0].update(products=[])),
    "a product is a string": vex_with(lambda o: o["statements"][0].update(products=["pkg:oci/cache"])),
    "a product is a number": vex_with(lambda o: o["statements"][0].update(products=[7])),
    "a product without @id": vex_with(lambda o: o["statements"][0].update(products=[{"identifiers": {}}])),
    "a product with an empty @id": vex_with(lambda o: o["statements"][0].update(products=[{"@id": ""}])),
    "a product @id that is a number": vex_with(lambda o: o["statements"][0].update(products=[{"@id": 5}])),
    "not_affected without justification or impact_statement": vex_with(lambda o: (o["statements"][0].pop("justification"), o["statements"][0].pop("impact_statement"))),
    "not_affected with empty justification and impact_statement": vex_with(lambda o: o["statements"][0].update(justification="", impact_statement="")),
    "affected without an action_statement": vex_with(lambda o: o["statements"][0].update(status="affected")),
    "affected with an empty action_statement": vex_with(lambda o: o["statements"][0].update(status="affected", action_statement="")),
    "a float 1.0": vex_with(lambda o: o.update(version="@@1.0@@")),
    "a float 1e2": vex_with(lambda o: o.update(version="@@1e2@@")),
    "a float 3.5": vex_with(lambda o: o.update(version="@@3.5@@")),
    "a float -0.0": vex_with(lambda o: o.update(version="@@-0.0@@")),
    "an integer beyond 2**53": vex_with(lambda o: o.update(version=2 ** 53 + 1)),
    "a statement version beyond 2**53": vex_with(lambda o: o["statements"][0].update(version=2 ** 53 + 1)),
    "a huge integer": vex_with(lambda o: o.update(version=10 ** 40)),
    "justification is not in the schema's enum": vex_with(lambda o: o["statements"][0].update(justification="made_up")),
    "justification not in the enum, no impact_statement": vex_with(lambda o: (o["statements"][0].update(justification="made_up"), o["statements"][0].pop("impact_statement"))),
    "justification in the wrong case": vex_with(lambda o: o["statements"][0].update(justification="Component_Not_Present")),
    "justification is a number": vex_with(lambda o: o["statements"][0].update(justification=3)),
    "status in the wrong case (Not_Affected)": vex_with(lambda o: o["statements"][0].update(status="Not_Affected")),
    "status in upper case": vex_with(lambda o: o["statements"][0].update(status="NOT_AFFECTED")),
    "timestamp offset without a colon (+0400)": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:00+0400")),
    "timestamp offset +99:99": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:00+99:99")),
    "timestamp offset +24:00": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:00+24:00")),
    "timestamp offset +12:60": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:00+12:60")),
    "timestamp offset is only an hour (+04)": vex_with(lambda o: o.update(timestamp="2026-09-20T09:00:00+04")),
    "document last_updated is yesterday": vex_with(lambda o: o.update(last_updated="yesterday")),
    "statement timestamp is yesterday": vex_with(lambda o: o["statements"][0].update(timestamp="yesterday")),
    "statement timestamp offset +99:99": vex_with(lambda o: o["statements"][0].update(timestamp="2026-09-20T09:00:00+99:99")),
    "statement timestamp is a date only": vex_with(lambda o: o["statements"][0].update(timestamp="2026-09-20")),
    "statement timestamp is a number": vex_with(lambda o: o["statements"][0].update(timestamp=5)),
    "statement last_updated is invalid": vex_with(lambda o: o["statements"][0].update(last_updated="2026-13-01T00:00:00Z")),
    "subcomponents is not a list": vex_with(lambda o: o["statements"][0]["products"][0].update(subcomponents={"@id": "x"})),
    "a subcomponent is a number": vex_with(lambda o: o["statements"][0]["products"][0].update(subcomponents=[7])),
    "a subcomponent is a string": vex_with(lambda o: o["statements"][0]["products"][0].update(subcomponents=["pkg:generic/busybox@1.37.0"])),
    "a subcomponent without @id or identifiers": vex_with(lambda o: o["statements"][0]["products"][0].update(subcomponents=[{"name": "busybox"}])),
    "a subcomponent with an empty @id": vex_with(lambda o: o["statements"][0]["products"][0].update(subcomponents=[{"@id": ""}])),
    "a subcomponent whose own subcomponents are bad": vex_with(lambda o: o["statements"][0]["products"][0].update(subcomponents=[{"@id": "a", "subcomponents": [7]}])),
    "identifiers value is a number": vex_with(lambda o: o["statements"][0]["products"][0].update(identifiers={"purl": 7})),
    "identifiers value is empty": vex_with(lambda o: o["statements"][0]["products"][0].update(identifiers={"purl": ""})),
    "identifiers is a list": vex_with(lambda o: o["statements"][0]["products"][0].update(identifiers=["pkg:oci/cache"])),
    "identifiers is a string": vex_with(lambda o: o["statements"][0]["products"][0].update(identifiers="pkg:oci/cache")),
    "identifiers value is null": vex_with(lambda o: o["statements"][0]["products"][0].update(identifiers={"purl": None})),
    "a product with only an empty identifiers object": vex_with(lambda o: o["statements"][0].update(products=[{"identifiers": {}}])),
    "a subcomponent identifiers value is a number": vex_with(lambda o: o["statements"][0]["products"][0].update(subcomponents=[{"identifiers": {"purl": 3}}])),
    "nested deeper than 32 (and an unknown property)": vex_with(lambda o: o["statements"][0].update(x=nest(31))),
    "larger than 1 MiB": vex_with(lambda o: o["statements"][0].update(impact_statement="y" * (2 ** 20))),
})
for _k, _v in list(V_BAD.items()):
    if b'"@@' in _v:
        V_BAD[_k] = re.sub(rb'"@@(.*?)@@"', rb"\1", _v)
    V_BAD[_k] = V_BAD[_k].replace(b"##D800##", b"\\ud800").replace(b"##DC00##", b"\\udc00")


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


@case("AC2", "the removed --repository-name option is refused (the subject name is a constant) and nothing is written")
def _():
    control_ok()
    s = sb()
    i = wr(os.path.join(s, "i.json"), mk_fx().bytes)
    v = wr(os.path.join(s, "v.json"), VEX_MIN)
    out = os.path.join(s, "o")
    r = run(["compute", "--index", i, "--vex", v, "--out-dir", out, "--repository-name", "other"])
    ok(r.rc != 0 and r.err.strip() != "", "accepted --repository-name")
    ok(not os.path.lexists(out), "created the out-dir")


@case("AC2", "boundaries that are valid are accepted: size 2**31, integers at +-2**53, the four statuses with what each requires")
def _():
    fx = mk_fx()
    o = json.loads(json.dumps(fx.obj)); o["manifests"][0]["size"] = 2 ** 31
    db = json.dumps(o).encode()
    check_matches_ref(db, VEX_MIN, do_compute(db, VEX_MIN))
    vb = vex_with(lambda x: (x.update(version=2 ** 53), x["statements"][0].update(version=2 ** 53)))
    check_matches_ref(fx.bytes, vb, do_compute(fx.bytes, vb))
    for st, extra in (("not_affected", {}), ("affected", {"action_statement": "upgrade"}), ("fixed", {}), ("under_investigation", {})):
        vb = vex_with(lambda x: (x["statements"][0].update(status=st, **extra), [x["statements"][0].pop(k) for k in ("justification", "impact_statement")] if st != "not_affected" else None))
        check_matches_ref(fx.bytes, vb, do_compute(fx.bytes, vb))
    vb = vex_with(lambda x: x["statements"][0].update(status="not_affected", justification="component_not_present", impact_statement=None) or x["statements"][0].pop("impact_statement"))
    check_matches_ref(fx.bytes, vb, do_compute(fx.bytes, vb))
    vb = vex_with(lambda x: x["statements"][0].pop("justification"))
    check_matches_ref(fx.bytes, vb, do_compute(fx.bytes, vb))


def fx_with_len(target, mode):
    def mk(n):
        return mk_fx(extra_top={"annotations": {"k": "a" * n}}, indent=None)
    if mode == "D":
        return mk(target - len(mk(0).bytes))
    return mk(target - len(ref_compute(mk(0).bytes, VEX_MIN)[0]))


@case("AC2", "compute, verify and the final index agree at the D limit with RETAINED content: a valid annotation making D exactly 1 MiB computes, its F (larger than 1 MiB) verifies; D + 1 byte is refused")
def _():
    control_ok()
    fx = fx_with_len(2 ** 20, "D")
    eq(len(fx.bytes), 2 ** 20, "fixture size")
    r = do_compute(fx.bytes, VEX_MIN)
    check_matches_ref(fx.bytes, VEX_MIN, r)
    ok(len(rd(os.path.join(r.dir, "index.json"))) > 2 ** 20, "fixture: F should exceed 1 MiB")
    v = verify(rd(os.path.join(r.dir, "index.json")), VEX_MIN, base=fx.bytes, blobs=os.path.join(r.dir, "blobs"))
    ok(v.rc == 0, "verify refused a final index computed from a valid D at the limit: " + v.err.strip()[:200])
    over = fx_with_len(2 ** 20 + 1, "D")
    eq(len(over.bytes), 2 ** 20 + 1, "fixture size")
    assert_refused(over.bytes, VEX_MIN, "D over 1 MiB (retained content)")


@param("AC3", "the final index limit is 2 MiB of raw bytes: exactly 2 MiB verifies, 2 MiB + 1 is refused", [("exactly 2 MiB", True), ("2 MiB + 1", False)])
def _(good):
    verify_control()
    fx = fx_with_len(2 ** 21 + (0 if good else 1), "F")
    path, fb = build_custom(fx, VEX_MIN)
    eq(len(fb), 2 ** 21 + (0 if good else 1), "fixture size")
    r = verify(fb, VEX_MIN, blobs=os.path.join(path, "blobs"))
    ok((r.rc == 0) == good, "verify %s a final index of %d bytes: %s" % ("refused" if good else "accepted", len(fb), r.err.strip()[:150]))


@case("AC2", "valid OpenVEX forms are accepted: a product identified only by identifiers, subcomponents, every justification, timestamps with Z and valid offsets and fractions, statement timestamps")
def _():
    fx = mk_fx()
    cases = [
        lambda o: o["statements"][0].update(products=[{"identifiers": {"purl": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}}]),
        lambda o: o["statements"][0].update(products=[{"@id": "a", "identifiers": {"purl": "pkg:x", "cpe23": "cpe:2.3:a:x"}, "subcomponents": [{"@id": "b"}, {"identifiers": {"purl": "pkg:y"}, "hashes": {"sha-256": "ab"}}]}]),
        lambda o: o.update(timestamp="2026-09-20T09:00:00Z"), lambda o: o.update(timestamp="2026-09-20T09:00:00.123456+05:30"),
        lambda o: o.update(timestamp="2016-12-31T23:59:60Z"),                    # a leap second
        lambda o: o.update(timestamp="2016-12-31T23:59:60.5-23:59"),
        lambda o: o.update(timestamp="2026-09-20t09:00:00z"),                    # lower-case t and z are allowed by RFC 3339
        lambda o: o.update(timestamp="2026-09-20t09:00:00.1+05:30"),
        lambda o: o["statements"][0].update(timestamp="2016-12-31T23:59:60Z", last_updated="2026-09-20t09:00:00z", action_statement_timestamp="2026-09-20T09:00:00.000000001Z"),
        lambda o: o.update(timestamp="2026-09-20T09:00:00-23:59"), lambda o: o.update(timestamp="2026-09-20T09:00:00+23:59", last_updated="2026-09-21T00:00:00Z"),
        lambda o: o["statements"][0].update(timestamp="2026-09-07T12:00:00-04:00", last_updated="2026-09-08T12:00:00Z"),
    ] + [(lambda j: (lambda o: o["statements"][0].update(justification=j)))(j) for j in ("component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist")]
    for f in cases:
        vb = vex_with(f)
        check_matches_ref(fx.bytes, vb, do_compute(fx.bytes, vb))


@case("AC2", "positive control: the repository's real VEX file (.vex/fosterstack-cache.openvex.json) passes the strict OpenVEX validation and contains no float")
def _():
    o = json.loads(vex_real().decode("utf-8"))

    def floats(x):
        if isinstance(x, float):
            return True
        if isinstance(x, dict):
            return any(floats(v) for v in x.values())
        if isinstance(x, list):
            return any(floats(v) for v in x)
        return False
    ok(not floats(o), "the real VEX file has a float, so the no-float ruling needs revisiting")
    fx = mk_fx()
    check_matches_ref(fx.bytes, vex_real(), do_compute(fx.bytes, vex_real()))


@case("AC2", "a VEX that mentions the built index's digest is refused by compute (verify would refuse its output) and nothing is written")
def _():
    fx = mk_fx()
    vb = vex_with(lambda o: o["statements"][0].update(impact_statement="see " + dg(fx.bytes)))
    assert_refused(fx.bytes, vb, "VEX naming the built index")


@param("AC2", "a half-unknown platform (unknown/amd64, linux/unknown) is refused; unknown/unknown is passed through", [("unknown/amd64", ("unknown", "amd64")), ("linux/unknown", ("linux", "unknown")), ("unknown/arm64/v8", ("unknown", "arm64"))])
def _(osarch):
    fx = mk_fx()
    o = json.loads(json.dumps(fx.obj))
    o["manifests"].append(dict(desc_of(mk_child("s390x")), platform={"os": osarch[0], "architecture": osarch[1]}))
    assert_refused(json.dumps(o).encode(), VEX_MIN, "half-unknown platform")


def idx_exact(n_bytes, plats=2):
    fx = mk_fx(plats=tuple(("arch%d" % i, None) for i in range(plats)))
    b = json.dumps(fx.obj, separators=(",", ":")).encode()
    return fx, b + b" " * (n_bytes - len(b)) if n_bytes >= len(b) else b


@case("AC2", "bounds, with positive controls at each limit: 64 platforms ok / 65 refused; VEX of exactly 1 MiB ok / 1 MiB + 1 refused; nesting depth 32 ok / 33 refused; index of exactly 1 MiB ok / 1 MiB + 1 refused; clean refusal writes nothing")
def _():
    control_ok()
    # platforms
    for n, good in ((64, True), (65, False)):
        ch = [mk_child("arch%d" % i) for i in range(n)]
        db = json.dumps({"schemaVersion": 2, "mediaType": OCI_IDX, "manifests": [desc_of(c) for c in ch]}).encode()
        if good:
            check_matches_ref(db, VEX_MIN, do_compute(db, VEX_MIN))
        else:
            assert_refused(db, VEX_MIN, "65 platforms")
    # vex bytes
    base = vex_with(lambda o: None)
    for extra, good in ((0, True), (1, False)):
        vb = base + b" " * (2 ** 20 - len(base) + extra)
        ok(len(vb) == 2 ** 20 + extra, "fixture size")
        fx = mk_fx()
        if good:
            check_matches_ref(fx.bytes, vb, do_compute(fx.bytes, vb))
        else:
            assert_refused(fx.bytes, vb, "VEX over 1 MiB")
    # index bytes
    for extra, good in ((0, True), (1, False)):
        fx = mk_fx()
        b = json.dumps(fx.obj, separators=(",", ":")).encode()
        db = b + b" " * (2 ** 20 - len(b) + extra)
        if good:
            check_matches_ref(db, VEX_MIN, do_compute(db, VEX_MIN))
        else:
            assert_refused(db, VEX_MIN, "index over 1 MiB")
    # index depth (VEX depth cannot reach the limit: the schema allowlist bounds it at 8): root(1) > nested lists
    for lv, good in ((31, True), (32, False)):
        fx = mk_fx(extra_top={"x": nest(lv)})
        if good:
            check_matches_ref(fx.bytes, VEX_MIN, do_compute(fx.bytes, VEX_MIN))
        else:
            assert_refused(fx.bytes, VEX_MIN, "index nesting too deep")


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


@case("AC3", "unknown fields on the index and its entries (artifactType, urls, data, annotations, subject, nested extension data, integers at 2**53) are preserved in F exactly and verify --base accepts the result")
def _():
    fx = FIXTURES["unknown-fields-on-entries-and-index"]()
    r = do_compute(fx.bytes, vex_real())
    check_matches_ref(fx.bytes, vex_real(), r)
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    d = json.loads(fx.bytes.decode("utf-8"))
    for k in ("artifactType", "annotations", "subject", "x-extension"):
        eq(f[k], d[k], "top-level " + k)
    for a, b in zip(f["manifests"][:2], d["manifests"]):
        eq(a, b, "an original entry with its unknown fields")
        for k in ("artifactType", "urls", "data", "annotations", "x-ext"):
            ok(k in a, "dropped field " + k)
    v = verify(rd(os.path.join(r.dir, "index.json")), vex_real(), base=fx.bytes, blobs=os.path.join(r.dir, "blobs"))
    ok(v.rc == 0, "verify rejected: " + v.err.strip()[:200])


@case("AC3", "removing the attestation children from F gives back the built index's entries, field for field")
def _():
    fx = mk_fx(unknown=True, **EXTRAS)
    r = do_compute(fx.bytes, vex_real())
    ok(r.rc == 0, "compute failed")
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    f["manifests"] = [e for e in f["manifests"] if (e.get("annotations") or {}).get("vnd.docker.reference.type") != "attestation-manifest"]
    eq(f, json.loads(fx.bytes.decode("utf-8")), "F minus attestation children")


@param("AC3", "the attestation manifest, config, layer and statement have exactly the ratified shape", [("oci-2-platform", "oci-2-platform"), ("arm-v7-variant", "arm-v7-variant"), ("oci-index-with-docker-v2-children", "oci-index-with-docker-v2-children")])
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


@param("AC3", "no digest of the built index or of the final index appears inside any attestation blob, and each statement names only its own platform", [("oci-2-platform", "oci-2-platform"), ("arm-v7-variant", "arm-v7-variant"), ("oci-index-with-docker-v2-children", "oci-index-with-docker-v2-children")])
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
def verify(f_bytes, vb, base=None, blobs=None, s=None, env=None, final_path=None):
    s = s or sb()
    fp = wr(os.path.join(s, "final.json"), f_bytes)
    vp = wr(os.path.join(s, "vex.json"), vb)
    args = ["verify", "--final", fp, "--vex", vp]
    if base is not None:
        args += ["--base", wr(os.path.join(s, "base.json"), base) if isinstance(base, bytes) else base]
    if blobs is not None:
        args += ["--blobs", blobs]
    watch = {s}
    if blobs is not None:
        watch |= {blobs, os.path.dirname(os.path.abspath(blobs))}
    if base is not None and not isinstance(base, bytes) and os.path.isfile(base):
        watch.add(os.path.dirname(os.path.abspath(base)))
    before = {w: tree(w) for w in watch if os.path.isdir(w)}
    r = run(args, env=env)
    for w, t in before.items():
        eq(tree(w), t, "verify must not write anything (checked: the inputs' directory, the --blobs tree and its parent, the --base file's directory)")
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
    "attestation children in a different order than the platforms": lambda fo, fx: fo["manifests"].__setitem__(slice(_n(fo, fx), None), list(reversed(fo["manifests"][_n(fo, fx):]))),
    "an attestation child placed before the original entries": lambda fo, fx: fo["manifests"].insert(0, fo["manifests"].pop()),
    "an original entry moved after the attestations": lambda fo, fx: fo["manifests"].append(fo["manifests"].pop(0)),
    "the final index is not an OCI index (mediaType is a Docker manifest list)": lambda fo, fx: fo.update(mediaType=DOCKER_LIST),
    "the final index has schemaVersion 1": lambda fo, fx: fo.update(schemaVersion=1),
    "the attestation descriptor has an extra key": lambda fo, fx: fo["manifests"][_n(fo, fx)].update(urls=["http://x"]),
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
    ok("Traceback" not in r.err, "a traceback instead of a plain reason")


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


@case("AC3", "verify --base given a digest (not a file) is refused: the built index's bytes cannot be recovered from F, so it fails closed")
def _():
    verify_control()
    fx = mk_fx()
    r = verify(final_of(fx, VEX_MIN), VEX_MIN, base=dg(fx.bytes))
    ok(r.rc != 0 and r.err.strip() != "", "accepted a digest as --base")


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


# ------------------------------------------------------------------ DIRs whose digests were refreshed after tampering
def build_custom(fx, vb, edits=None, fedit=None, s=None, extra=None, only=0, fraw=None):
    """writes a DIR (index.json, result.json, blobs/sha256/*) built stage by stage with every digest and size
    re-derived after each edit, so only structure (never a stale hash) can reveal the tampering."""
    s = s or sb()
    vex = json.loads(vb.decode("utf-8"))
    d = json.loads(fx.bytes.decode("utf-8"))
    base = dg(fx.bytes)
    plat_digests = [e["digest"] for e in d["manifests"] if e["platform"]["os"] != "unknown"]
    descs, blobs, plats, pi = [], {}, {}, 0
    for e in d["manifests"]:
        if e["platform"]["os"] == "unknown":
            continue
        ed = edits if (edits and (only is None or pi == only)) else {}
        pi += 1
        ctx = {"base": base, "pdigest": e["digest"], "other": [x for x in plat_digests if x != e["digest"]][0] if len(plat_digests) > 1 else "sha256:" + "77" * 32, "vex": vex}
        ap = lambda k, o: ed[k](o, ctx) if k in ed else None
        stmt = {"_type": STMT_TYPE, "predicateType": PRED, "subject": [{"name": SUBJECT_NAME, "digest": {"sha256": hx(e["digest"])}}], "predicate": json.loads(json.dumps(vex))}
        ap("stmt", stmt)
        sb_ = ed["stmt_raw"](stmt) if "stmt_raw" in ed else cj(stmt)
        layer = {"mediaType": "application/vnd.in-toto+json", "digest": dg(sb_), "size": len(sb_), "annotations": {"in-toto.io/predicate-type": PRED}}
        ap("layer", layer)
        cfg = {"architecture": "unknown", "created": "1970-01-01T00:00:00Z", "os": "unknown", "rootfs": {"diff_ids": [layer["digest"]], "type": "layers"}}
        ap("cfg", cfg)
        cb = cj(cfg)
        cdesc = {"mediaType": OCI_CFG, "digest": dg(cb), "size": len(cb)}
        ap("cdesc", cdesc)
        man = {"schemaVersion": 2, "mediaType": OCI_MAN, "config": cdesc, "layers": [layer]}
        ap("man", man)
        mb = cj(man)
        desc = {"mediaType": OCI_MAN, "digest": dg(mb), "size": len(mb),
                "annotations": {"vnd.docker.reference.digest": e["digest"], "vnd.docker.reference.type": "attestation-manifest"},
                "platform": {"architecture": "unknown", "os": "unknown"}}
        ap("desc", desc)
        descs.append(desc)
        for b in (sb_, cb, mb):
            blobs[hx(dg(b))] = b
        plats[pkey(e)] = {"platform_digest": e["digest"], "attestation_digest": desc["digest"]}
    f = dict(d)
    f["manifests"] = list(d["manifests"]) + descs
    if fedit:
        fedit(f)
    fb = fraw(f) if fraw else cj(f)
    result = {"base_digest": base, "final_digest": dg(fb), "platforms": plats, "vex_sha256": hashlib.sha256(vb).hexdigest()}
    path = os.path.join(s, "dir")
    wr(os.path.join(path, "index.json"), fb)
    for h, b in blobs.items():
        wr(os.path.join(path, "blobs", "sha256", h), b)
    wr(os.path.join(path, "result.json"), cj(result) + b"\n")
    if extra:
        extra(path)
    return path, fb


def _sub(f):
    return {"stmt": f}


def _subject_digest(key):
    def f(o, c):
        o["subject"][0]["digest"]["sha256"] = hx(c[key]) if key in c else key
    return f


def _fed(f):
    return (None, f)


STRUCT = {
    "the statement names the built index's digest as its subject": ({"stmt": _subject_digest("base")}, None),
    "the statement names another platform's digest": ({"stmt": _subject_digest("other")}, None),
    "the statement subject has another name": ({"stmt": lambda o, c: o["subject"][0].update(name="pkg:oci/other?repository_url=example.test/x")}, None),
    "the statement has two subjects": ({"stmt": lambda o, c: o["subject"].append(dict(o["subject"][0]))}, None),
    "the statement has an extra top-level key": ({"stmt": lambda o, c: o.update(extra=1)}, None),
    "the statement predicateType differs": ({"stmt": lambda o, c: o.update(predicateType="https://example.test/p")}, None),
    "the statement _type differs": ({"stmt": lambda o, c: o.update(_type="https://in-toto.io/Statement/v1")}, None),
    "the statement is indented (not canonical)": ({"stmt_raw": lambda o: json.dumps(o, indent=1).encode()}, None),
    "the statement has a trailing newline": ({"stmt_raw": lambda o: cj(o) + b"\n"}, None),
    "the statement uses ascii escapes (not canonical)": ({"stmt_raw": lambda o: json.dumps(o, sort_keys=True, separators=(",", ":")).encode()}, None),
    "the statement predicate is not an OpenVEX document": ({"stmt": lambda o, c: o.update(predicate={"statements": []})}, None),
    "the statement predicate embeds the built index's digest (in every statement)": ({"stmt": lambda o, c: o["predicate"]["statements"][0].update(status_notes=c["base"])}, None, None),
    "the layer descriptor mediaType differs": ({"layer": lambda o, c: o.update(mediaType="application/json")}, None),
    "the layer annotation is missing": ({"layer": lambda o, c: o.pop("annotations")}, None),
    "the layer annotation has an extra key": ({"layer": lambda o, c: o["annotations"].update(extra="x")}, None),
    "the layer annotations carry the built index's digest": ({"layer": lambda o, c: o["annotations"].update(src=c["base"])}, None),
    "the layer descriptor size is false": ({"layer": lambda o, c: o.update(size=o["size"] + 1)}, None),
    "the config has an extra key": ({"cfg": lambda o, c: o.update(extra=1)}, None),
    "the config created differs": ({"cfg": lambda o, c: o.update(created="2026-10-06T00:00:00Z")}, None),
    "the config diff_ids do not name the layer": ({"cfg": lambda o, c: o["rootfs"].update(diff_ids=["sha256:" + "00" * 32])}, None),
    "the config os is linux": ({"cfg": lambda o, c: o.update(os="linux")}, None),
    "the config descriptor mediaType differs": ({"cdesc": lambda o, c: o.update(mediaType="application/json")}, None),
    "the config descriptor has an extra key": ({"cdesc": lambda o, c: o.update(annotations={"a": "b"})}, None),
    "the config descriptor size is false": ({"cdesc": lambda o, c: o.update(size=o["size"] + 1)}, None),
    "the attestation manifest has an extra key": ({"man": lambda o, c: o.update(annotations={"a": "b"})}, None),
    "the attestation manifest has schemaVersion 1": ({"man": lambda o, c: o.update(schemaVersion=1)}, None),
    "the attestation manifest mediaType differs": ({"man": lambda o, c: o.update(mediaType=DOCKER_MAN)}, None),
    "the attestation manifest has two layers": ({"man": lambda o, c: o["layers"].append(dict(o["layers"][0]))}, None),
    "the attestation manifest has no layers": ({"man": lambda o, c: o.update(layers=[])}, None),
    "the attestation descriptor size is false": ({"desc": lambda o, c: o.update(size=o["size"] + 1)}, None),
    "the attestation descriptor has an extra annotation": ({"desc": lambda o, c: o["annotations"].update(extra="x")}, None),
    "the attestation descriptor platform is linux/amd64": ({"desc": lambda o, c: o.update(platform={"architecture": "amd64", "os": "linux"})}, None),
    "every attestation child is removed (and result.json refreshed)": (None, lambda f: f.update(manifests=[e for e in f["manifests"] if not (e.get("annotations") or {}).get("vnd.docker.reference.type")])),
    "one attestation child is removed (and result.json refreshed)": (None, lambda f: f["manifests"].pop()),
    "one attestation child is duplicated": (None, lambda f: f["manifests"].append(dict(f["manifests"][-1]))),
    "the attestation children are reordered": (None, lambda f: f["manifests"].__setitem__(slice(-2, None), [f["manifests"][-1], f["manifests"][-2]])),
    "an attestation child comes before the original entries": (None, lambda f: f["manifests"].insert(0, f["manifests"].pop())),
}
# edits that only a comparison with the VEX file can see (verify has the VEX; push does not)
VERIFY_ONLY = {
    "every statement carries another valid OpenVEX document (consistent among themselves, not the VEX file)": ({"stmt": lambda o, c: o["predicate"].update(version=o["predicate"]["version"] + 1)}, None, None),
}
# the first platform's statement differs from the second's: push (which has no VEX file) must see it too
STRUCT["the first platform's statement carries another valid OpenVEX document than the second's"] = ({"stmt": lambda o, c: o["predicate"].update(version=o["predicate"]["version"] + 1)}, None)

PRED_BAD = {
    "justification not in the enum": lambda p: p["statements"][0].update(justification="made_up"),
    "status Not_Affected": lambda p: p["statements"][0].update(status="Not_Affected"),
    "document timestamp +0400": lambda p: p.update(timestamp="2026-09-20T09:00:00+0400"),
    "document timestamp +99:99": lambda p: p.update(timestamp="2026-09-20T09:00:00+99:99"),
    "statement timestamp yesterday": lambda p: p["statements"][0].update(timestamp="yesterday"),
    "subcomponents [7]": lambda p: p["statements"][1]["products"][0].update(subcomponents=[7]),
    "identifiers value 7": lambda p: p["statements"][1]["products"][0].update(identifiers={"purl": 7}),
    "a product without @id or identifiers": lambda p: p["statements"][0].update(products=[{"name": "x"}]),
    "@context bogus suffix": lambda p: p.update({"@context": "https://openvex.dev/ns/v0.2.0x"}),
    "a float in the predicate": lambda p: p["statements"][0].update(version=1.5),
}
for _label, _fn in PRED_BAD.items():
    STRUCT["rehashed predicate invalid in every statement: " + _label] = ({"stmt": (lambda f: lambda o, c: f(o["predicate"]))(_fn)}, None, None)

# ---- the embedded OpenVEX v0.2.0 allowlist: every property the schema defines, with its type; nothing else
CTX = "https://openvex.dev/ns/v0.2.0"
TS_OK = "2026-09-20T09:00:00Z"
HASHES = ("md5", "sha1", "sha-256", "sha-384", "sha-512", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "blake2s-256", "blake2b-256", "blake2b-512")  # the 12 names of the published schema (blake2b-384 is not among them)


def base_vex_obj():
    return {"@context": CTX, "@id": "https://example.test/vex/1", "author": "Example Co", "timestamp": TS_OK, "version": 1,
            "statements": [{"vulnerability": {"name": "CVE-2000-0001"},
                            "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "identifiers": {"purl": "pkg:oci/cache"}, "hashes": {"sha-256": "ab"},
                                          "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0", "identifiers": {"purl": "pkg:generic/busybox@1.37.0"}, "hashes": {"sha-256": "cd"}}]}],
                            "status": "not_affected", "justification": "component_not_present", "impact_statement": "not present"}]}


BASE_VEX = json.dumps(base_vex_obj()).encode()
PATHS = {
    "doc": lambda o: o, "statement": lambda o: o["statements"][0], "vuln": lambda o: o["statements"][0]["vulnerability"],
    "product": lambda o: o["statements"][0]["products"][0], "sub": lambda o: o["statements"][0]["products"][0]["subcomponents"][0],
    "product.identifiers": lambda o: o["statements"][0]["products"][0]["identifiers"], "sub.identifiers": lambda o: o["statements"][0]["products"][0]["subcomponents"][0]["identifiers"],
    "product.hashes": lambda o: o["statements"][0]["products"][0]["hashes"], "sub.hashes": lambda o: o["statements"][0]["products"][0]["subcomponents"][0]["hashes"],
}
UNICODE_TS = ["\uff12\uff10\uff12\uff16-09-20T09:00:00Z",            # full-width year digits
              "2026-\u0660\u0669-20T09:00:00Z",                       # Arabic-Indic month digits
              "2026-09-20T09:00:00+\uff10\uff14:\uff10\uff10",        # full-width offset digits
              "2026-09-20T09:00:00.\u0665Z",                           # Arabic-Indic fraction digit
              "2026-09-20T\u0660\u0669:00:00Z",                       # Arabic-Indic hour
              "2026-09-20T09:00:\u0966\u0966Z"]                       # Devanagari seconds
S_WRONG, TS_WRONG, INT_WRONG = [7, None, ["x"], {"a": "b"}, True], ["yesterday", 5, None, "2026-09-20", "2026-09-20T09:00:00+0400", "2026-02-30T00:00:00Z", "2026-09-20T24:00:00Z", "2026-09-20T09:00:00Z\n"] + UNICODE_TS, [0, "1", 1.5, True, None, -1]
OBJ_WRONG = [[], "x", None, 7, True, [["a"]]]
IDENT_WRONG = OBJ_WRONG + [{}, {"purl": 7}, {"unknown": "x"}, {"purl": ""}, {"purl": ["x"]}, {"purl": None}]
HASH_WRONG = OBJ_WRONG + [{"sha-256": 7}, {"unknown": "x"}, {"md5": ""}, {"md5": ["x"]}, {"blake2b-384": "ab"}]
LIST_WRONG = ["x", {"a": 1}, None, 7, True, [["nested"]], {}]
SP = []


def _add(path, key, valid, wrongs):
    SP.append((path, key, valid, wrongs))


_add("doc", "@context", CTX, [7, None, "https://openvex.dev/ns/v0.1.0"])
_add("doc", "@id", "urn:uuid:1", [7, None])
_add("doc", "author", "Author", [7, None])
_add("doc", "role", "vendor", S_WRONG)
_add("doc", "timestamp", "2026-09-20T09:00:00.5-04:00", TS_WRONG)
_add("doc", "last_updated", "2026-09-21T00:00:00Z", TS_WRONG)
_add("doc", "version", 2, INT_WRONG)
_add("doc", "tooling", "tool 1.0", S_WRONG)


def _stmt():
    return base_vex_obj()["statements"][0]


def _stmt2():
    o = _stmt()
    o["vulnerability"]["name"] = "CVE-2000-0009"
    return o


_add("doc", "statements", [_stmt(), _stmt2()], LIST_WRONG + [[], [7], [None], [[_stmt()]], [_stmt(), _stmt()], [_stmt(), _stmt2(), _stmt()],
                                                         [_stmt(), dict(reversed(list(_stmt().items())))]])
for _k in ("@id", "supplier", "status_notes", "impact_statement", "action_statement"):
    _add("statement", _k, "text", S_WRONG)
_add("statement", "version", 3, INT_WRONG)
_add("statement", "timestamp", TS_OK, TS_WRONG)
_add("statement", "last_updated", TS_OK, TS_WRONG)
_add("statement", "action_statement_timestamp", TS_OK, TS_WRONG)
_add("statement", "status", "fixed", ["fine", "Fixed", 7, None, ""])
_add("statement", "justification", "inline_mitigations_already_exist", ["made_up", 7, None, "", "Component_Not_Present"])
_add("statement", "vulnerability", {"name": "CVE-2000-0002", "@id": "https://x/CVE-2000-0002"}, ["CVE-2000-0002", 7, None, [], {}, True, [["x"]], [{"name": "x"}]])
_add("statement", "products", [{"@id": "pkg:a"}], LIST_WRONG + [[], [7], [{}], [None], [[{"@id": "a"}]], [{"@id": "p"}, {"@id": "p"}], [{"@id": "p", "identifiers": {"purl": "x"}}, {"identifiers": {"purl": "x"}, "@id": "p"}]])
_add("vuln", "@id", "https://example.test/CVE-1", S_WRONG)
_add("vuln", "name", "CVE-2000-0003", [7, None, "", ["x"]])
_add("vuln", "description", "text", S_WRONG)
_add("vuln", "aliases", ["GHSA-aaaa-bbbb-cccc", "GO-2024-0001"], LIST_WRONG + [[7], [""], [None], ["ok", 3], [["a"]], [{"a": 1}], ["A", "A"], ["GHSA-aaaa-bbbb-cccc", "x", "GHSA-aaaa-bbbb-cccc"]])
_add("product", "@id", "pkg:other", [7, None, ""])
_add("product", "identifiers", {"purl": "pkg:p", "cpe22": "cpe:/a:x", "cpe23": "cpe:2.3:a:x"}, IDENT_WRONG)
_add("product", "hashes", {"sha-256": "ab", "md5": "cd"}, HASH_WRONG)
_add("product", "subcomponents", [{"@id": "pkg:s1"}, {"identifiers": {"purl": "pkg:s2"}}], LIST_WRONG + [[7], [{"x": 1}], [{}], [None], [[{"@id": "a"}]], [{"@id": "s"}, {"@id": "s"}], [{"@id": "s", "identifiers": {"purl": "x"}}, {"identifiers": {"purl": "x"}, "@id": "s"}]])
_add("sub", "@id", "pkg:other-sub", [7, None, ""])
_add("sub", "identifiers", {"purl": "pkg:p"}, IDENT_WRONG)
_add("sub", "hashes", {"sha-256": "ab"}, HASH_WRONG)
for _lvl in ("product.identifiers", "sub.identifiers"):
    for _k in ("purl", "cpe22", "cpe23"):
        _add(_lvl, _k, "value", [7, None, "", ["x"]])
for _k in HASHES:
    _add("product.hashes", _k, "ab12", [7, None, "", ["x"]])
for _k in ("md5", "sha-256", "blake2b-512"):
    _add("sub.hashes", _k, "ab12", [7, None, "", ["x"]])


def _stmt_other_products():
    o = _stmt()
    o["products"] = [{"@id": "pkg:oci/other"}]
    return o


_EXTRA_OK = [("doc.statements = two statements differing only in products (not duplicates)", ("doc", "statements", [_stmt(), _stmt_other_products()])),
             ("doc.statements = two statements differing only in status_notes", ("doc", "statements", [_stmt(), dict(_stmt(), status_notes="n")])),
("product.hashes = {} (the schema has no minimum)", ("product", "hashes", {})), ("statement.products = two different products", ("statement", "products", [{"@id": "p1"}, {"@id": "p2"}])),
             ("vuln.aliases = [] (allowed)", ("vuln", "aliases", [])), ("vuln.aliases = A and a (distinct)", ("vuln", "aliases", ["A", "a"])),
             ("product.subcomponents = [] (allowed)", ("product", "subcomponents", []))]


def set_prop(o, path, key, val):
    PATHS[path](o)[key] = val
    return o


def schema_vex(path, key, val):
    return json.dumps(set_prop(base_vex_obj(), path, key, val)).encode()


SCHEMA_REJECT = [("%s.%s = %r" % (pa, k, w), (pa, k, w)) for pa, k, v, ws in SP for w in ws]  # every wrong value, no truncation
SCHEMA_REHASH = [("%s.%s = %r" % (pa, k, w), (pa, k, w)) for pa, k, v, ws in SP for w in ([ws[0], ws[-1]] if len(ws) > 1 else ws)]
SCHEMA_OK = [("%s.%s" % (pa, k), (pa, k, v)) for pa, k, v, ws in SP] + _EXTRA_OK
# properties that the prose spec or other tools mention but the published JSON schema's closed objects lack
NOT_IN_SCHEMA = [("product", "supplier", "Supplier"), ("sub", "supplier", "Supplier"), ("product.hashes", "blake2b-384", "ab12"), ("sub.hashes", "blake2b-384", "ab12"),
                 ("sub", "subcomponents", [{"@id": "nested"}])]
SCHEMA_UNKNOWN = ([(pa, (pa, "x-unknown", "value")) for pa in PATHS] + [(pa + " (nested object)", (pa, "extension", {"a": 1})) for pa in PATHS]
                  + [("%s.%s (defined elsewhere, not here)" % (a, b), (a, b, c)) for a, b, c in NOT_IN_SCHEMA])
SCHEMA_REHASH_ALL = (SCHEMA_REHASH + [("%s.x-unknown" % pa, (pa, "x-unknown", "value")) for pa in PATHS]
                     + [("%s.%s (not in the schema)" % (a, b), (a, b, c)) for a, b, c in NOT_IN_SCHEMA])


@case("AC2", "positive control: the base document used by the schema cases is valid, and so is a document carrying every allowlisted property at once")
def _():
    fx = mk_fx()
    check_matches_ref(fx.bytes, BASE_VEX, do_compute(fx.bytes, BASE_VEX))
    o = base_vex_obj()
    for pa, k, v, ws in SP:
        if pa in ("doc", "statement", "vuln", "product", "sub") and k not in ("status", "justification", "statements", "products", "vulnerability", "subcomponents", "@context", "identifiers", "hashes"):
            PATHS[pa](o)[k] = v
    vb = json.dumps(o).encode()
    check_matches_ref(fx.bytes, vb, do_compute(fx.bytes, vb))


@param("AC2", "every allowlisted OpenVEX v0.2.0 property accepts a valid value (positive control with it set)", SCHEMA_OK)
def _(arg):
    fx = mk_fx()
    vb = schema_vex(*arg)
    check_matches_ref(fx.bytes, vb, do_compute(fx.bytes, vb))


@param("AC2", "every allowlisted OpenVEX v0.2.0 property rejects a value of the wrong type (isolated; refused by compute, nothing written)", SCHEMA_REJECT)
def _(arg):
    assert_refused(mk_fx().bytes, schema_vex(*arg), "wrong type")


@param("AC2", "a property the OpenVEX v0.2.0 schema does not define at that level (document, statement, vulnerability, product, subcomponent, identifiers, hashes) is refused", SCHEMA_UNKNOWN)
def _(arg):
    assert_refused(mk_fx().bytes, schema_vex(*arg), "unknown property")


def schema_edit(arg):
    pa, k, val = arg
    return {"stmt": lambda o, c: set_prop(o["predicate"], pa, k, json.loads(json.dumps(val)))}


@param("AC3", "verify --blobs rejects an attestation whose predicate has a wrong-typed OpenVEX property or an unknown one, with every digest refreshed", SCHEMA_REHASH_ALL)
def _(arg):
    verify_control()
    fx = mk_fx()
    path, fb = build_custom(fx, BASE_VEX, schema_edit(arg), None, only=None)
    r = verify(fb, BASE_VEX, base=fx.bytes, blobs=os.path.join(path, "blobs"))
    ok(r.rc != 0 and r.err.strip() != "" and "Traceback" not in r.err, "accepted an attestation with an invalid predicate")


@case("AC3", "positive control: attestations built from the schema base document verify --blobs")
def _():
    verify_control()
    fx = mk_fx()
    path, fb = build_custom(fx, BASE_VEX, None, None)
    r = verify(fb, BASE_VEX, base=fx.bytes, blobs=os.path.join(path, "blobs"))
    ok(r.rc == 0, "rejected: " + r.err.strip()[:200])


FINAL_RAW = {
    "index.json is indented": lambda f: json.dumps(f, indent=2, sort_keys=True).encode(),
    "index.json has a trailing newline": lambda f: cj(f) + b"\n",
    "index.json keys are not sorted": lambda f: json.dumps(f, separators=(",", ":")).encode(),
    "index.json is compact but escapes non-ASCII": lambda f: json.dumps(f, sort_keys=True, separators=(",", ":")).encode() + b"",
    "index.json has spaces after separators": lambda f: json.dumps(f, sort_keys=True).encode(),
    "index.json is preceded by a space": lambda f: b" " + cj(f),
}


def struct_dir(edits, fedit, vb=None, fx=None, only=0, fraw=None):
    return build_custom(fx or mk_fx(), vb or vex_real(), edits, fedit, only=only, fraw=fraw)


@case("AC3", "positive control: a DIR built stage by stage with refreshed digests and no edit is accepted by verify --blobs")
def _():
    fx = mk_fx()
    path, fb = struct_dir(None, None, fx=fx)
    eq(rd(os.path.join(path, "index.json")), ref_compute(fx.bytes, vex_real())[0], "the builder's F")
    r = verify(rd(os.path.join(path, "index.json")), vex_real(), base=fx.bytes, blobs=os.path.join(path, "blobs"))
    ok(r.rc == 0, "rejected a correct DIR: " + r.err.strip()[:200])


@param("AC3", "verify --blobs rejects a structurally wrong final index or attestation even when every digest and size was refreshed to match", sorted(list(STRUCT.items()) + list(VERIFY_ONLY.items())))
def _(spec):
    verify_control()
    fx = mk_fx()
    path, fb = struct_dir(spec[0], spec[1], fx=fx, only=(spec[2] if len(spec) > 2 else 0))
    r = verify(rd(os.path.join(path, "index.json")), vex_real(), base=fx.bytes, blobs=os.path.join(path, "blobs"))
    ok(r.rc != 0, "accepted a structurally wrong final index")
    ok(r.err.strip() != "" and "Traceback" not in r.err, "no plain reason: " + r.err.strip()[-200:])


@param("AC3", "verify rejects final-index bytes that are not exactly the canonical serialisation even when result.json and every digest were refreshed (with and without --blobs)", sorted(("%s (%s)" % (k, "with --blobs" if w else "alone"), (k, w)) for k in FINAL_RAW for w in (True, False)))
def _(arg):
    verify_control()
    k, with_blobs = arg
    fx = mk_fx(**EXTRAS)
    path, fb = struct_dir(None, None, fx=fx, fraw=FINAL_RAW[k])
    ok(fb != ref_compute(fx.bytes, vex_real())[0], "fixture: the serialisation is the canonical one")
    r = verify(rd(os.path.join(path, "index.json")), vex_real(), base=fx.bytes, blobs=os.path.join(path, "blobs") if with_blobs else None)
    ok(r.rc != 0, "accepted a non-canonical final index")
    ok(r.err.strip() != "" and "Traceback" not in r.err, "no plain reason")


@case("AC3", "verify --blobs rejects a rehashed statement whose subject names the built index, even with no --base given")
def _():
    verify_control()
    fx = mk_fx()
    path, fb = struct_dir({"stmt": _subject_digest("base")}, None, fx=fx)
    r = verify(rd(os.path.join(path, "index.json")), vex_real(), blobs=os.path.join(path, "blobs"))
    ok(r.rc != 0, "accepted")


# ------------------------------------------------------------------ TLS material (for the https cases)
_TLS = {}
TLS_NAMES = ["registry.example.test", "auth.example.test", "registry-1.docker.io", "auth.docker.io", "docker.io"]


def tls():
    """(CA bundle that the tool is told to trust, the good server context)"""
    if "m" not in _TLS:
        d = os.path.join(TMP, "tls")
        os.makedirs(d)
        ctxs = {}
        for name, sans in (("good", TLS_NAMES), ("wrong", ["wrong.example.test"]), ("untrusted", TLS_NAMES)):
            cnf = os.path.join(d, name + ".cnf")
            with open(cnf, "w") as f:
                f.write("[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=%s\n[v3]\nsubjectAltName=%s\n" % (sans[0], ",".join("DNS:" + n for n in sans)))
            p = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-keyout", os.path.join(d, name + ".key"),
                                "-out", os.path.join(d, name + ".pem"), "-config", cnf], capture_output=True)
            if p.returncode != 0:
                raise Fail("cannot generate the test certificate with openssl: " + p.stderr.decode()[-200:])
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(os.path.join(d, name + ".pem"), os.path.join(d, name + ".key"))
            ctxs[name] = ctx
        bundle = os.path.join(d, "bundle.pem")
        with open(bundle, "wb") as f:  # the tool trusts "good" and "wrong" (a valid certificate for the wrong host); never "untrusted"
            f.write(rd(os.path.join(d, "good.pem")) + rd(os.path.join(d, "wrong.pem")))
        _TLS["m"] = (bundle, ctxs["good"])
        _TLS["ctx"] = ctxs
    return _TLS["m"]


def tls_ctx(name):
    tls()
    return _TLS["ctx"][name]


# ------------------------------------------------------------------ fake registry
class Srv(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, ctx=None):
        super().__init__(addr, handler)
        self.ctx = ctx

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.ctx:
            sock = self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def handle_error(self, request, client_address):
        pass


class Reg:
    """a distribution-style registry that records every request. strict (default): upload sessions are owned (an
    invented session or another session's state is a 404), manifest Accept negotiation is enforced, a manifest
    whose children or blobs are unknown is refused. lenient: stores any manifest (so only the tool's own checks
    can keep a broken index out)."""

    def __init__(self, repo="fosterstack/cache", token=False, basic=False, rewrite=False, lie=False, fail_after=None,
                 realm=None, redirect_on=(), redirect_to="http://registry.example.test/elsewhere", loc_base=None,
                 lenient=False, readback="ok", att_head_404=False, child_head_500=False, token_key="token",
                 use_tls=False, public=None, alt_uploads=False, token_redirect_to=None, stall_on=(), hdr_case="exact", redirect_status=307, token_redirect_status=302, challenge_scope=None, bearer_rejected=False,
                 put_blob_status=None, head_blob_status=None, blob_gone_after_put=False, token_drip=False, cert="good"):
        self.repo, self.token_mode, self.basic_mode, self.rewrite, self.lie = repo, token, basic, rewrite, lie
        self.fail_after, self.realm, self.redirect_on, self.redirect_to, self.loc_base = fail_after, realm, set(redirect_on), redirect_to, loc_base
        self.lenient, self.readback, self.att_head_404, self.child_head_500, self.token_key = lenient, readback, att_head_404, child_head_500, token_key
        self.use_tls, self.alt_uploads, self.token_redirect_to, self.stall_on = use_tls, alt_uploads, token_redirect_to, set(stall_on)
        self.release = threading.Event()
        self.redirect_status, self.token_redirect_status = redirect_status, token_redirect_status
        self.challenge_scope, self.bearer_rejected = challenge_scope, bearer_rejected
        self.bearer_pull = "issued-pull-only-3c9a51e0d7b2"
        self.hdr_case, self.put_blob_status, self.head_blob_status, self.blob_gone_after_put, self.token_drip = hdr_case, put_blob_status, head_blob_status, blob_gone_after_put, token_drip
        self.uploaded = set()
        self.blobs, self.mans, self.log, self.tag_writes, self.sessions = set(), {}, [], [], {}
        self.children, self.att_set = set(), set()
        self.mutating_ok, self.counter = 0, 0
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
                ent = {"headers": {k.lower(): v for k, v in self.headers.items()}, "method": self.command, "path": u.path, "query": u.query, "auth": self.headers.get("Authorization"),
                       "ctype": self.headers.get("Content-Type"), "accept": self.headers.get("Accept"), "host": self.headers.get("Host"),
                       "body": body, "status": None}
                with reg.lock:
                    st, hd, rb = reg.respond(self.command, u, urllib.parse.parse_qs(u.query), body, ent)
                    ent["status"] = st
                    reg.log.append(ent)
                hd = dict(hd)
                trunc = hd.pop("_truncate", False)
                drip = hd.pop("_drip", False)
                fn = {"exact": lambda k: k, "lower": str.lower, "upper": str.upper, "title": lambda k: "-".join(w.capitalize() for w in k.split("-"))}[reg.hdr_case]
                hd = {(fn(k) if k != "Content-Length" else k): v for k, v in hd.items()}
                hd = {k: (v.encode("utf-8").decode("latin-1") if k.lower() == "www-authenticate" else v) for k, v in hd.items()}  # a challenge carries its UTF-8 bytes as written
                self.send_response(st)
                hd["Content-Length"] = str(len(rb))
                for k, v in hd.items():
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    if drip:
                        self.close_connection = True
                        try:
                            for i in range(len(rb)):
                                if reg.release.wait(1.0):
                                    break
                                self.wfile.write(rb[i:i + 1])
                                self.wfile.flush()
                        except OSError:
                            pass
                    elif trunc:
                        self.wfile.write(rb[:len(rb) // 2])
                        self.wfile.flush()
                        self.close_connection = True
                        try:
                            self.connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    else:
                        self.wfile.write(rb)

            do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = handle_any

        ctx = tls_ctx(cert) if use_tls else None
        self.srv = Srv(("127.0.0.1", 0), H, ctx)
        self.port = self.srv.server_address[1]
        self.public = public
        self.host = public if public else "127.0.0.1:%d" % self.port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.release.set()
        self.srv.shutdown()
        self.srv.server_close()

    def stall(self):
        self.release.wait()  # only teardown (close) ends a stall: nothing but the client's own deadline can end the request
        return 500, {}, b"{}"

    def seed(self, children):
        for c in children:
            self.mans[c["digest"]] = (c["bytes"], c["mt"])
            self.blobs.update(c["blobs"])
            self.children.add(c["digest"])

    def respond(self, m, u, q, body, ent):
        p = u.path
        if p == "/token":
            if "token" in self.stall_on:
                return self.stall()
            if self.token_redirect_to:
                return self.token_redirect_status, {"Location": self.token_redirect_to}, b""
            if ent["auth"] == "Basic " + base64.b64encode(("%s:%s" % (USER, SECRET)).encode()).decode():
                hd = {"Content-Type": "application/json"}
                if self.token_drip:
                    hd["_drip"] = True
                return 200, hd, json.dumps({self.token_key: (self.bearer if "push" in (q.get("scope") or [""])[0] else self.bearer_pull), "expires_in": 300}).encode()
            return 401, {}, b'{"errors":[{"code":"UNAUTHORIZED"}]}'
        if self.token_mode:
            have = "push" if ent["auth"] == "Bearer " + self.bearer else ("pull" if ent["auth"] == "Bearer " + self.bearer_pull else None)
            need_push = m in ("POST", "PUT", "PATCH", "DELETE")
            if have is not None and self.bearer_rejected:
                return 401, {"WWW-Authenticate": 'Basic realm="fake-registry"'}, b'{"errors":[{"code":"UNAUTHORIZED"}]}'
            if have is None or (need_push and have == "pull"):
                scheme = "https" if self.use_tls else "http"
                chal = 'Bearer realm="%s",service="fake-registry",scope="repository:%s:%s"' % (
                    self.realm or "%s://%s/token" % (scheme, self.host), self.repo, self.challenge_scope or ("pull,push" if need_push else "pull"))
                return 401, {"WWW-Authenticate": chal}, b'{"errors":[{"code":"UNAUTHORIZED"}]}'
        if self.basic_mode and ent["auth"] != "Basic " + base64.b64encode(("%s:%s" % (USER, SECRET)).encode()).decode():
            return 401, {"WWW-Authenticate": 'Basic realm="fake-registry"'}, b'{"errors":[{"code":"UNAUTHORIZED"}]}'
        if p in ("/v2/", "/v2"):
            return 200, {}, b"{}"
        if p.startswith("/upload-service/") and m == "PUT" and self.alt_uploads:
            if "put_blob" in self.stall_on:
                return self.stall()
            if self.fail_after is not None and self.mutating_ok >= self.fail_after:
                return 500, {}, b"{}"
            st, hd, rb = self.upload_put(p[len("/upload-service/"):], q, body, ent)
            if st < 300:
                self.mutating_ok += 1
            return st, hd, rb
        pre = "/v2/%s/" % self.repo
        if not p.startswith(pre):
            return 404, {}, b'{"errors":[{"code":"NAME_UNKNOWN"}]}'
        rest = p[len(pre):]
        mutating = m in ("POST", "PUT", "PATCH", "DELETE")
        kind = None
        if rest.startswith("blobs/uploads/"):
            kind = "post" if m == "POST" else "put_blob"
        elif rest.startswith("blobs/"):
            kind = "head_blob"
        elif rest.startswith("manifests/"):
            kind = {"HEAD": "head_man", "PUT": "put_man", "GET": "get_man"}.get(m)
        if kind in self.stall_on:
            return self.stall()
        if kind in self.redirect_on:
            return self.redirect_status, {"Location": self.redirect_to}, b""
        if mutating and self.fail_after is not None and self.mutating_ok >= self.fail_after:
            return 500, {}, b'{"errors":[{"code":"UNKNOWN"}]}'
        st, hd, rb = self.route(m, rest, q, body, ent)
        if mutating and st < 300:
            self.mutating_ok += 1
        return st, hd, rb

    def upload_put(self, sid, q, body, ent):
        err = lambda c, code: (c, {}, json.dumps({"errors": [{"code": code}]}).encode())
        if sid not in self.sessions or (q.get("_state") or [""])[0] != self.sessions[sid]:
            return err(404, "BLOB_UPLOAD_UNKNOWN")
        if self.put_blob_status:
            return err(self.put_blob_status, "DENIED")
        if ent["ctype"] != "application/octet-stream":
            return err(415, "BLOB_UPLOAD_INVALID")
        d = (q.get("digest") or [""])[0]
        if not DIGEST_RE.match(d) or dg(body) != d:
            return err(400, "DIGEST_INVALID")
        del self.sessions[sid]
        self.blobs.add(d)
        self.uploaded.add(d)
        return 201, {"Docker-Content-Digest": d}, b""

    def route(self, m, rest, q, body, ent):
        err = lambda c, code: (c, {}, json.dumps({"errors": [{"code": code}]}).encode())
        if rest == "blobs/uploads/" and m == "POST":
            self.counter += 1
            sid, state = "sess%d" % self.counter, "state-%d-%s" % (self.counter, hashlib.sha256(str(self.counter).encode()).hexdigest()[:12])
            self.sessions[sid] = state
            loc = "/v2/%s/blobs/uploads/%s?_state=%s" % (self.repo, sid, state)
            if self.alt_uploads:
                loc = "/upload-service/%s?_state=%s" % (sid, state)
            if self.loc_base:
                loc = self.loc_base + loc
            return 202, {"Location": loc}, b""
        if rest.startswith("blobs/uploads/") and m == "PUT":
            if self.alt_uploads:
                return err(404, "BLOB_UPLOAD_UNKNOWN")
            return self.upload_put(rest[len("blobs/uploads/"):], q, body, ent)
        if rest.startswith("blobs/") and m in ("HEAD", "GET"):
            d = rest[6:]
            if self.head_blob_status:
                return err(self.head_blob_status, "DENIED")
            if self.blob_gone_after_put and d in self.uploaded:
                return err(404, "BLOB_UNKNOWN")
            if d in self.blobs:
                return 200, {"Docker-Content-Digest": d}, b""
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
                if not self.lenient:
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
                if self.att_head_404 and ref in self.att_set:
                    return err(404, "MANIFEST_UNKNOWN")
                if self.child_head_500 and ref in self.children:
                    return err(500, "UNKNOWN")
                acc = [x.split(";")[0].strip() for x in (ent["accept"] or "").split(",") if x.strip()]
                if ct not in acc and "*/*" not in acc:
                    return err(404, "MANIFEST_UNKNOWN")
                hd = {"Content-Type": ct or "application/octet-stream", "Docker-Content-Digest": ref}
                if m == "GET" and b"\"manifests\"" in b:
                    if self.readback == "404":
                        return err(404, "MANIFEST_UNKNOWN")
                    if self.readback == "500":
                        return err(500, "UNKNOWN")
                    if self.readback == "truncate":
                        hd["_truncate"] = True
                        return 200, hd, b
                    if self.readback == "drip":
                        hd["_drip"] = True
                        return 200, hd, b
                    if self.readback == "ct-nbsp":
                        hd["Content-Type"] = hd["Content-Type"] + "\xa0"
                        return 200, hd, b
                    if self.readback == "ct-ws-ok":
                        hd["Content-Type"] = " " + hd["Content-Type"] + " ; charset=utf-8 "
                        return 200, hd, b
                    if self.readback == "wrongct":
                        hd["Content-Type"] = "text/plain"
                        return 200, hd, b
                    if self.readback == "empty":
                        return 200, hd, b""
                    if self.rewrite in ("trail-nl", "trail-space", "case-swap", "last-byte"):
                        if self.rewrite == "trail-nl":
                            nb = b + b"\n"
                        elif self.rewrite == "trail-space":
                            nb = b + b" "
                        elif self.rewrite == "last-byte":
                            nb = b[:-1] + (b"]" if b[-1:] != b"]" else b"}")
                        else:
                            hexpos = [i for i in range(len(b)) if b[i:i + 1] in b"abcdef" and b[max(0, i - 8):i].count(b"sha256:") == 0 and b[i - 1:i] in b"0123456789abcdef"]
                            i = [j for j in range(b.rfind(b"sha256:") + 7, len(b)) if b[j:j + 1] in b"abcdef"][0]
                            nb = b[:i] + b[i:i + 1].upper() + b[i + 1:]
                        hd["Docker-Content-Digest"] = ref
                        return 200, hd, nb
                    if self.rewrite in ("samelen", "samelen-mid", "samelen-end"):
                        occ = [i for i in range(len(b)) if b.startswith(b"sha256:", i)]
                        i = {"samelen": occ[0], "samelen-mid": min(occ, key=lambda o: abs(o - len(b) // 2)), "samelen-end": occ[-1] + 56}[self.rewrite] + 7
                        nb = b[:i] + (b"0" if b[i:i + 1] != b"0" else b"1") + b[i + 1:]
                        hd["Docker-Content-Digest"] = ref
                        return 200, hd, nb
                    if self.rewrite:
                        nb = json.dumps(json.loads(b), indent=1).encode()
                        hd["Docker-Content-Digest"] = ref if self.lie else dg(nb)
                        return 200, hd, nb
                return 200, hd, b
        return err(404, "UNSUPPORTED")


class Proxy:
    """a stand-in HTTP proxy. Without routes it answers 502 to everything and records it. With routes
    {"host:port": local backend port} a CONNECT to a routed name is tunnelled to the local backend (so https
    names can be served by this file's TLS registries); anything else is a 502."""

    def __init__(self, routes=None):
        self.log, self.routes = [], dict(routes or {})
        proxy = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                conn = self.request
                data = b""
                while b"\r\n\r\n" not in data:
                    c = conn.recv(65536)
                    if not c:
                        return
                    data += c
                head, _, rest = data.partition(b"\r\n\r\n")
                lines = head.decode("latin1").split("\r\n")
                method, target = lines[0].split(" ")[:2]
                hdrs = {}
                for l in lines[1:]:
                    if ":" in l:
                        k, v = l.split(":", 1)
                        hdrs[k.strip().lower()] = v.strip()
                ent = {"method": method, "path": target, "auth": hdrs.get("authorization"), "host": hdrs.get("host")}
                proxy.log.append(ent)
                if method == "CONNECT" and target in proxy.routes:
                    up = socket.create_connection(("127.0.0.1", proxy.routes[target]))
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    if rest:
                        up.sendall(rest)
                    socks = [conn, up]
                    try:
                        while True:
                            r, _, _ = select.select(socks, [], [], 30)
                            if not r:
                                break
                            done = False
                            for s_ in r:
                                chunk = s_.recv(65536)
                                if not chunk:
                                    done = True
                                    break
                                (up if s_ is conn else conn).sendall(chunk)
                            if done:
                                break
                    finally:
                        up.close()
                    return
                n = int(hdrs.get("content-length") or 0)
                while len(rest) < n:
                    c = conn.recv(65536)
                    if not c:
                        break
                    rest += c
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

        class S(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

            def handle_error(self, request, client_address):
                pass

        self.srv = S(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def env(self, trust=False):
        e = {"http_proxy": self.url, "https_proxy": self.url, "HTTP_PROXY": self.url, "HTTPS_PROXY": self.url,
             "no_proxy": "127.0.0.1,localhost", "NO_PROXY": "127.0.0.1,localhost"}
        if trust:
            e["SSL_CERT_FILE"] = tls()[0]
        return e


Sink = Proxy


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
    return finish_pd(pd, fx, fb, blobs, result)


def finish_pd(pd, fx, fb, blobs, result):
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


def custom_pd(fx, vb, edits=None, fedit=None, extra=None, fraw=None, only=0):
    path, fb = build_custom(fx, vb, edits, fedit, extra=extra, fraw=fraw, only=only)
    pd = PD()
    pd.path = path
    _, blobs, result = ref_compute(fx.bytes, vb)
    result = json.loads(rd(os.path.join(path, "result.json")))
    blobs = {n: rd(os.path.join(path, "blobs", "sha256", n)) for n in os.listdir(os.path.join(path, "blobs", "sha256"))}
    try:
        return finish_pd(pd, fx, fb, blobs, result)
    except Exception:
        pd.fb, pd.f_digest, pd.result, pd.att_digests, pd.plat_digests, pd.upload, pd.blobs, pd.fx = fb, dg(fb), result, set(), [], set(), blobs, fx
        pd.f_media = OCI_IDX
        return pd


def secrets_in(text, reg):
    b64 = base64.b64encode(("%s:%s" % (USER, SECRET)).encode()).decode()
    bad = [SECRET, b64, "%s:%s" % (USER, SECRET), b64.rstrip("=")]
    if reg is not None and getattr(reg, "bearer", None):
        bad.append(reg.bearer)
        bad.append(reg.bearer_pull)
    return [x for x in bad if x and x in text]


def push(reg, pd, extra=(), env=None, creds=True, repo=None, registry=None, net=None, timeout=90):
    e = {}
    if creds:
        e = {"FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET}
    e.update(env or {})
    parent = os.path.dirname(pd.path)
    before = tree(parent)
    r = run(["push", "--registry", registry or reg.host, "--repository", repo or (reg.repo if reg else "fosterstack/cache"), "--dir", pd.path] + list(extra), env=e, net=net, timeout=timeout)
    eq(tree(parent), before, "push must not create or change anything in or next to DIR (e.g. <DIR>.pushed, token files)")
    leaked = secrets_in(r.out + "\n" + r.err, reg)
    ok(not leaked, "a credential or token (possibly base64-encoded) was printed: %d item(s)" % len(leaked))
    if reg is not None and hasattr(reg, "log") and not any(k in (env or {}) for k in ("FSCACHE_REGISTRY_USER", "FSCACHE_REGISTRY_TOKEN")) and creds:
        assert_no_credential_leak(reg)
    return r


def assert_no_credential_leak(reg):
    """no request's URL, query, headers or body carries the secret, its base64 or a bearer token, except the one
    Basic Authorization header at the token endpoint (and a Bearer Authorization header at the registry)"""
    b64 = base64.b64encode(("%s:%s" % (USER, SECRET)).encode()).decode()
    secrets = [SECRET, b64, b64.rstrip("="), "%s:%s" % (USER, SECRET)]
    tokens = [reg.bearer, reg.bearer_pull]
    for x in reg.log:
        hdrs = x["headers"]
        auth = hdrs.get("authorization")
        rest = (x["path"] + "?" + x["query"]).encode() + x["body"] + "".join("%s:%s;" % (k, v) for k, v in hdrs.items() if k != "authorization").encode()
        for sec in secrets + tokens:
            ok(sec.encode() not in rest, "a credential or token travelled in the URL, query, body or a header other than Authorization (%s %s)" % (x["method"], x["path"]))
        if auth is None:
            continue
        if x["path"] == "/token":
            eq(auth, "Basic " + b64, "the token endpoint's Authorization")
        elif auth.startswith("Bearer "):
            ok(auth[7:] in tokens, "an unknown bearer was sent")
        else:
            ok(reg.basic_mode and auth == "Basic " + b64, "Basic credentials sent to the registry (%s %s)" % (x["method"], x["path"]))


def muts(reg):
    return [x for x in reg.log if x["method"] in ("POST", "PUT", "PATCH", "DELETE")]


def okmuts(reg):
    return [x for x in muts(reg) if x["status"] < 300]


def push_world(**kw):
    fx = kw.pop("fx", None) or mk_fx()
    vb = kw.pop("vb", None) or vex_real()
    seed_skip = kw.pop("seed_skip", None) or ()
    preblobs = kw.pop("preblobs", None) or ()
    pd_builder = kw.pop("pd", None)
    reg = Reg(**kw)
    reg.seed([c for i, c in enumerate(fx.children) if i not in seed_skip])
    if fx.junk is not None:
        junk = [e for e in fx.obj["manifests"] if e["platform"]["os"] == "unknown"][0]
        reg.mans[junk["digest"]] = (fx.junk, OCI_MAN)
        reg.children.add(junk["digest"])
    pd = pd_builder(fx, vb) if pd_builder else make_dir(fx, vb)
    reg.att_set = set(pd.att_digests)
    for d in preblobs:
        reg.blobs.add(d)
    return reg, pd


def h_has_oci(accept):
    return accept is not None and OCI_IDX in accept and OCI_MAN in accept and DOCKER_MAN in accept


def assert_clean_push(reg, pd, r, skip_blobs=()):
    ok(r.rc == 0, "push failed rc=%d: %s" % (r.rc, r.err.strip()[:300]))
    eq(reg.tag_writes, [], "tags written")
    eq([x["method"] for x in reg.log if x["method"] not in ("GET", "HEAD", "POST", "PUT")], [], "unexpected methods")
    for x in reg.log:
        ok(x["path"] in ("/v2/", "/v2", "/token") or x["path"].startswith("/v2/%s/" % reg.repo) or (reg.alt_uploads and x["path"].startswith("/upload-service/")), "request outside the repository: " + x["path"])
        if "/manifests/" in x["path"] and x["method"] in ("HEAD", "GET"):
            ok(h_has_oci(x["accept"]), "manifest %s sent without an Accept for the OCI index, OCI manifest and Docker v2 manifest types" % x["method"])
    puts_blob = [x for x in reg.log if x["method"] == "PUT" and ("/blobs/uploads/" in x["path"] or x["path"].startswith("/upload-service/")) and x["status"] < 300]
    got_blobs = {dict(urllib.parse.parse_qsl(x["query"]))["digest"] for x in puts_blob}
    for x in puts_blob:
        eq(x["ctype"], "application/octet-stream", "Content-Type of a blob PUT")
    eq(got_blobs, set(pd.upload) - set(skip_blobs), "the set of blobs uploaded")
    eq(len(puts_blob), len(got_blobs), "a blob was uploaded twice")
    ok(not [x for x in reg.log if x["path"].endswith("/blobs/uploads/") and x["method"] == "POST"][len(got_blobs):], "an upload session was opened for nothing")
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
            eq(x["ctype"], pd.f_media, "F's Content-Type")
        else:
            eq(x["body"], pd.blobs[hx(ref)], "attestation manifest bytes")
            eq(x["ctype"], OCI_MAN, "attestation manifest Content-Type")
    idx_f = [i for i, x in enumerate(reg.log) if x["method"] == "PUT" and x["path"].endswith("/manifests/" + pd.f_digest) and x["status"] < 300][0]
    for c in pd.plat_digests:
        ok(any(x["method"] in ("HEAD", "GET") and x["path"].endswith("/manifests/" + c) and x["status"] == 200 for x in reg.log[:idx_f]), "child %s was not verified before F was written" % c)
    for a in pd.att_digests:
        put_i = [i for i, x in enumerate(reg.log) if x["method"] == "PUT" and x["path"].endswith("/manifests/" + a)][0]
        ok(any(x["method"] in ("HEAD", "GET") and x["path"].endswith("/manifests/" + a) and x["status"] == 200 for x in reg.log[put_i + 1:idx_f]),
           "attestation manifest %s was not re-checked (HEAD) after its PUT and before F" % a)
    first_man = min(i for i, x in enumerate(reg.log) if x["method"] == "PUT" and "/manifests/" in x["path"])
    for bd in got_blobs:
        put_i = [i for i, x in enumerate(reg.log) if x["method"] == "PUT" and dict(urllib.parse.parse_qsl(x["query"])).get("digest") == bd][0]
        ok(any(x["method"] == "HEAD" and x["path"].endswith("/blobs/" + bd) and x["status"] == 200 for x in reg.log[put_i + 1:first_man]),
           "blob %s was not re-checked (HEAD 200) after its upload and before any manifest was pushed" % bd)
    last_blob = max([i for i, x in enumerate(reg.log) if "/blobs/uploads/" in x["path"]] or [-1])
    ok(last_blob < first_man or not puts_blob, "a manifest was pushed before all blobs were")
    ok(any(x["method"] == "GET" and x["path"].endswith("/manifests/" + pd.f_digest) and x["status"] == 200 for x in reg.log[idx_f + 1:]), "no successful read-back of F by digest after the write")
    eq(reg.mans[pd.f_digest][0], pd.fb, "stored F")


def f_puts(reg, pd):
    return [x for x in reg.log if x["method"] == "PUT" and x["path"].endswith("/manifests/" + pd.f_digest)]


def assert_no_f_attempt(reg, pd, r, why):
    """the push failed and F was never even offered to the registry"""
    ok(r.rc != 0, "push succeeded: " + why)
    eq(len(f_puts(reg, pd)), 0, "attempts to PUT F after a failed pre-check (" + why + ")")
    ok(pd.f_digest not in reg.mans, "F is stored in the registry: " + why)
    eq(reg.tag_writes, [], "tags written")
    ok(pd.f_digest not in r.out, "stdout claims F's digest although the push failed")
    ok("Traceback" not in r.err, "a traceback instead of a plain reason")


def assert_failed_no_claim(reg, pd, r, why):
    """the push failed after (or while) F was offered: non-zero, no digest reported as success"""
    ok(r.rc != 0, "push succeeded: " + why)
    eq(reg.tag_writes, [], "tags written")
    ok(pd.f_digest not in r.out, "stdout reports F's digest although the push failed: " + why)
    ok("Traceback" not in r.err, "a traceback instead of a plain reason")


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


def with_world(f, **kw):
    reg, pd = push_world(**kw)
    try:
        return f(reg, pd)
    finally:
        reg.close()


# ------------------------------------------------------------------ AC4: plain-http (localhost) registry
@case("AC4", "a normal push writes exactly the blobs and manifests of DIR by digest, children first and F last, and reads F back")
def _():
    def go(reg, pd):
        assert_clean_push(reg, pd, push(reg, pd))
    with_world(go)


@case("AC4", "the same push against a lenient registry (no child validation) is just as clean")
def _():
    def go(reg, pd):
        assert_clean_push(reg, pd, push(reg, pd))
    with_world(go, lenient=True)


@case("AC4", "an upload Location on the registry's own origin, given as an absolute URL, works")
def _():
    reg, pd = push_world()
    reg.loc_base = "http://%s" % reg.host
    try:
        assert_clean_push(reg, pd, push(reg, pd))
    finally:
        reg.close()


@param("AC4", "a push of other index shapes", [("arm v7 variant", "arm-v7-variant"), ("unknown/unknown entry with its real bytes seeded", "unknown-unknown-entry"), ("extra fields and non-ASCII annotations", "extra-fields-and-non-ascii"), ("single platform", "single-platform"), ("OCI index with Docker v2 children (the tool must advertise the Docker v2 manifest type)", "oci-index-with-docker-v2-children")])
def _(name):
    fx = FIXTURES[name]()

    def go(reg, pd):
        assert_clean_push(reg, pd, push(reg, pd))
    with_world(go, fx=fx)


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
    pd0 = make_dir(mk_fx(), vex_real())
    pre = sorted(pd0.upload)[:1]
    fx = mk_fx()
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
    reg.att_set = set(pd.att_digests)
    try:
        assert_clean_push(reg, pd, push(reg, pd))
    finally:
        reg.close()


@case("AC4", "the registry's upload sessions are honoured: an invented session is a 404 and the push fails (the strict fake owns its sessions)")
def _():
    reg, pd = push_world()
    try:
        assert_clean_push(reg, pd, push(reg, pd))
        ok(len(reg.sessions) == 0, "sessions left open")
    finally:
        reg.close()


@case("AC4", "token flow: Basic credentials go only to the token endpoint, the registry sees only the Bearer token")
def _():
    def go(reg, pd):
        r = push(reg, pd)
        assert_clean_push(reg, pd, r)
        toks = [x for x in reg.log if x["path"] == "/token"]
        ok(toks, "never asked the token endpoint")
        want = "Basic " + base64.b64encode(("%s:%s" % (USER, SECRET)).encode()).decode()
        for t in toks:
            eq(t["auth"], want, "credentials at the token endpoint")
            q = urllib.parse.parse_qs(t["query"])
            eq(q.get("service"), ["fake-registry"], "token request service")
            eq(q.get("scope"), ["repository:%s:pull,push" % reg.repo], "the token request's scope (the tool always asks for pull,push itself)")
        for x in reg.log:
            if x["path"] != "/token":
                ok(x["auth"] is None or x["auth"] == "Bearer " + reg.bearer, "the registry received %r" % (x["auth"] and x["auth"][:12]))
        ok(any(x["auth"] == "Bearer " + reg.bearer for x in reg.log), "never used the token")
    with_world(go, token=True)


@case("AC4", "a token endpoint that answers with access_token (not token) is accepted")
def _():
    def go(reg, pd):
        assert_clean_push(reg, pd, push(reg, pd))
    with_world(go, token=True, token_key="access_token")


@param("AC4", "token flow with bad or missing credentials fails closed and stores nothing", [("wrong token", {"FSCACHE_REGISTRY_TOKEN": "nope-nope"}), ("wrong user", {"FSCACHE_REGISTRY_USER": "mallory"}), ("no credentials", "none")])
def _(e):
    push_control()

    def go(reg, pd):
        r = push(reg, pd, env=None if e == "none" else e, creds=(e != "none"))
        assert_no_f_attempt(reg, pd, r, "bad credentials")
        eq(okmuts(reg), [], "something was written without valid credentials")
    with_world(go, token=True)


# ---- failures the push must notice, with a strict and a lenient registry
LENIENCY = [("strict registry", False), ("lenient registry", True)]


@param("AC4", "the registry rewrites the stored manifest (also reporting the expected digest in its header): the read-back differs and the push fails", [(a + (" / header lies" if lie else ""), (len_, lie)) for a, len_ in LENIENCY for lie in (False, True)])
def _(arg):
    push_control()

    def go(reg, pd):
        assert_failed_no_claim(reg, pd, push(reg, pd), "rewritten manifest")
    with_world(go, rewrite=True, lenient=arg[0], lie=arg[1])


@param("AC4", "a read-back that fails after F was written (GET 404, 500, a truncated body, an empty body, a wrong Content-Type) makes the push fail with no digest reported", [(m_, m_) for m_ in ("404", "500", "truncate", "empty", "wrongct", "ct-nbsp")])
def _(mode):
    push_control()

    def go(reg, pd):
        r = push(reg, pd)
        ok(len(f_puts(reg, pd)) >= 1, "the failure was not after F's PUT (fixture)")
        assert_failed_no_claim(reg, pd, r, "read-back " + mode)
        ok(any(x["method"] == "GET" and x["path"].endswith("/manifests/" + pd.f_digest) for x in reg.log), "no read-back was attempted")
    with_world(go, readback=mode)


@param("AC4", "a child manifest missing from the repository: no PUT of F is even attempted (strict and lenient registry)", [("%s: %s" % (nm, a), (skip, len_)) for nm, skip in (("arm64 absent", (1,)), ("amd64 absent", (0,)), ("both absent", (0, 1))) for a, len_ in LENIENCY])
def _(arg):
    push_control()

    def go(reg, pd):
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "missing child")
        ok(any(x["method"] in ("HEAD", "GET") and "/manifests/" in x["path"] and x["status"] == 404 for x in reg.log), "never looked for the child")
    with_world(go, seed_skip=arg[0], lenient=arg[1])


@param("AC4", "an attestation manifest that is not there when re-checked after its PUT (HEAD 404) stops everything before F", LENIENCY)
def _(len_):
    push_control()

    def go(reg, pd):
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "attestation manifest HEAD 404 after its PUT")
        ok(any(x["method"] == "PUT" and "/manifests/" in x["path"] for x in reg.log), "fixture: the attestation manifests were not even pushed")
    with_world(go, att_head_404=True, lenient=len_)


@param("AC4", "a platform child whose HEAD answers 500 stops everything before F", LENIENCY)
def _(len_):
    push_control()

    def go(reg, pd):
        assert_no_f_attempt(reg, pd, push(reg, pd), "child HEAD 500")
    with_world(go, child_head_500=True, lenient=len_)


@param("AC4", "a registry that fails with 500 part-way: non-zero exit, F never offered unless it was the failing write, nothing claimed", [("%s after %d writes" % (a, n), (n, len_)) for n in (0, 1, 2, 3, 5, 7, 8, 9, 10) for a, len_ in LENIENCY])
def _(arg):
    push_control()
    n, len_ = arg

    def go(reg, pd):
        r = push(reg, pd)
        if n < 10:
            assert_no_f_attempt(reg, pd, r, "500 after %d writes" % n)
        else:
            assert_failed_no_claim(reg, pd, r, "F rejected")
            ok(pd.f_digest not in reg.mans, "F is stored")
    with_world(go, fail_after=n, lenient=len_)


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
        assert_failed_no_claim(reg, pd, push(reg, pd), "F rejected")
        ok(pd.f_digest not in reg.mans, "F is stored")
    finally:
        reg.close()


@case("AC4", "an unreachable registry fails and claims nothing")
def _():
    push_control()
    s_ = socket.socket()
    s_.bind(("127.0.0.1", 0))  # bound but never listening: connections are refused, and the port cannot be reused meanwhile
    try:
        pd = make_dir(mk_fx(), vex_real())
        r = run(["push", "--registry", "127.0.0.1:%d" % s_.getsockname()[1], "--repository", "fosterstack/cache", "--dir", pd.path],
                env={"FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET})
        ok(r.rc != 0 and pd.f_digest not in r.out, "claimed a push to nothing")
        ok("Traceback" not in r.err, "a traceback")
    finally:
        s_.close()


# ---- the credentials never leak, on any path
SECRET_PATHS = [
    ("token + 500 mid-push", dict(token=True, fail_after=2)), ("token + 500 on the first write", dict(token=True, fail_after=0)),
    ("token + rewritten manifest", dict(token=True, rewrite=True)), ("token + missing child", dict(token=True, seed_skip=(1,))),
    ("token + read-back 404", dict(token=True, readback="404")), ("token + read-back truncated", dict(token=True, readback="truncate")),
    ("token + attestation HEAD 404", dict(token=True, att_head_404=True, lenient=True)),
    ("token + redirect on upload start", dict(token=True, redirect_on={"post"})), ("token + hostile upload Location", dict(token=True, loc_base="http://registry.example.test")),
    ("basic challenge + 500 mid-push", dict(basic=True, fail_after=3)), ("no auth + 500", dict(fail_after=1)),
]


@param("AC4", "no credential (plain, base64-encoded as Basic, or the issued bearer token) is ever printed, on any failure path", SECRET_PATHS)
def _(kw):
    push_control()
    sink = Proxy()
    reg, pd = push_world(**kw)
    try:
        r = push(reg, pd, env=sink.env())
        ok(r.rc != 0, "the push unexpectedly succeeded")
        ok(not secrets_in(r.out + r.err, reg), "credential printed")
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
                if "/manifests/" in x["path"] and x["method"] not in ("GET", "HEAD"):
                    ok(DIGEST_RE.match(x["path"].rsplit("/", 1)[1]), "manifest write by something that is not a digest")
        finally:
            reg.close()


# ---- DIR validation before anything is written
def dir_tamper_cases():
    def blobp(pd, d):
        return os.path.join(pd.path, "blobs", "sha256", hx(d))

    def rm_att_manifest(pd):
        os.unlink(blobp(pd, sorted(pd.att_digests)[0]))

    def rm_config(pd):
        m = json.loads(pd.blobs[hx(sorted(pd.att_digests)[0])])
        os.unlink(blobp(pd, m["config"]["digest"]))

    def rm_layer(pd):
        m = json.loads(pd.blobs[hx(sorted(pd.att_digests)[0])])
        os.unlink(blobp(pd, m["layers"][0]["digest"]))

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

    def result_bad_base(pd):
        p = os.path.join(pd.path, "result.json"); o = json.loads(rd(p)); o["base_digest"] = "nope"; wr(p, cj(o))

    def index_missing(pd):
        os.unlink(os.path.join(pd.path, "index.json"))

    def blob_tampered(pd):
        m = json.loads(pd.blobs[hx(sorted(pd.att_digests)[0])])
        p = blobp(pd, m["layers"][0]["digest"]); b = bytearray(rd(p)); b[0] ^= 1; wr(p, bytes(b))

    def att_manifest_tampered(pd):
        p = blobp(pd, sorted(pd.att_digests)[0]); wr(p, rd(p) + b" ")

    def blob_symlink(pd):
        m = json.loads(pd.blobs[hx(sorted(pd.att_digests)[0])])
        p = blobp(pd, m["layers"][0]["digest"]); b = rd(p); os.unlink(p)
        tgt = os.path.join(os.path.dirname(pd.path), "elsewhere"); wr(tgt, b); os.symlink(tgt, p)

    def index_not_json(pd):
        wr(os.path.join(pd.path, "index.json"), b"{")

    def extra_root(pd):
        wr(os.path.join(pd.path, "stray.txt"), b"hello")

    def extra_unreferenced_blob(pd):
        b = b"an unreferenced blob"; wr(os.path.join(pd.path, "blobs", "sha256", hashlib.sha256(b).hexdigest()), b)

    def extra_other_algorithm(pd):
        wr(os.path.join(pd.path, "blobs", "sha512", "ab" * 64), b"x")

    def extra_dir(pd):
        os.makedirs(os.path.join(pd.path, "blobs", "sha256", "nested"))

    def extra_symlink(pd):
        os.symlink("/etc/hostname", os.path.join(pd.path, "link"))

    def extra_hidden_root(pd):
        wr(os.path.join(pd.path, ".hidden"), b"x")

    def extra_hidden_blobs(pd):
        wr(os.path.join(pd.path, "blobs", "sha256", ".DS_Store"), b"x")

    def extra_empty_file_named_like_blob(pd):
        wr(os.path.join(pd.path, "blobs", "sha256", "0" * 64), b"")

    return [("an attestation manifest is missing locally", rm_att_manifest), ("a config blob is missing locally", rm_config),
            ("a layer blob is missing locally", rm_layer), ("the blobs directory is missing", rm_all_blobs),
            ("index.json has a trailing newline (its digest no longer equals result.json's)", index_whitespace),
            ("index.json was re-serialised", index_reserialised), ("result.json's final_digest differs from F", result_final_changed),
            ("result.json is missing", result_missing), ("result.json's base_digest is not a digest", result_bad_base), ("index.json is missing", index_missing),
            ("a blob's content does not match its digest", blob_tampered), ("an attestation manifest does not match its digest", att_manifest_tampered),
            ("a blob is a symlink out of DIR", blob_symlink), ("index.json is not JSON", index_not_json),
            ("an extra file in DIR", extra_root), ("an unreferenced blob in blobs/sha256", extra_unreferenced_blob),
            ("a blobs/sha512 directory", extra_other_algorithm), ("a directory inside blobs/sha256", extra_dir), ("a symlink in DIR", extra_symlink), ("a hidden dotfile in DIR", extra_hidden_root), ("a hidden dotfile in blobs/sha256", extra_hidden_blobs),
            ("an empty file named like a blob", extra_empty_file_named_like_blob)]


@param("AC4", "a DIR that is incomplete, inconsistent, tampered or has extra files is refused before anything is sent", dir_tamper_cases())
def _(f):
    push_control()
    reg, pd = push_world()
    f(pd)
    try:
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "bad DIR")
        eq(reg.log, [], "a request was made although DIR is not consistent")
        ok(r.err.strip() != "", "no reason on stderr")
    finally:
        reg.close()


@param("AC4", "a structurally wrong final index or attestation is refused before anything is sent, even when every digest, size and result.json was refreshed", sorted(STRUCT.items()))
def _(spec):
    push_control()
    fx = mk_fx()
    reg, pd = push_world(fx=fx, pd=lambda fx_, vb: custom_pd(fx_, vb, spec[0], spec[1], only=(spec[2] if len(spec) > 2 else 0)))
    try:
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "structurally wrong DIR")
        eq(reg.log, [], "a request was made although DIR is not a valid final index")
        ok(r.err.strip() != "", "no reason on stderr")
    finally:
        reg.close()


@case("AC4", "positive control: a stage-by-stage rebuilt DIR with no edit pushes cleanly")
def _():
    fx = mk_fx()
    reg, pd = push_world(fx=fx, pd=lambda fx_, vb: custom_pd(fx_, vb))
    try:
        assert_clean_push(reg, pd, push(reg, pd))
    finally:
        reg.close()


@case("AC4", "--base-digest that does not match result.json's base_digest is refused before anything is sent; a matching one is accepted")
def _():
    push_control()
    reg, pd = push_world()
    try:
        r = push(reg, pd, extra=["--base-digest", "sha256:" + "12" * 32])
        assert_no_f_attempt(reg, pd, r, "wrong base digest")
        eq(reg.log, [], "a request was made")
        r = push(reg, pd, extra=["--base-digest", pd.result["base_digest"]])
        assert_clean_push(reg, pd, r)
    finally:
        reg.close()


@param("AC4", "an invalid repository name is refused before any request", [(n, n) for n in ("../evil", "a//b", "A/B", "a b", "a?x=1", "a/../../v2", "", "-a", "a/%2e%2e/b", "a#b", "a\nb",
                                                                         "fosterstack/cach\u0435", "foster\uff53tack/cache", "fosterstack/cache\u0661", "fosterstack/caf\u00e9", "fosterstack/ca\u212a", "\u017fhared/cache", "fosterstack/cache\u2060")])
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
    def go(reg, pd):
        assert_clean_push(reg, pd, push(reg, pd))
    with_world(go, repo="org/team/cache")


# ---- where the tool may connect and what it may send there
def only_via_proxy(r, proxy):
    for line in r.net:
        kind, _, target = line.partition(" ")
        ok(kind != "exec", "the tool ran an external network program: " + line)
        if kind == "resolve":
            ok(target in ("127.0.0.1", "'127.0.0.1'"), "the tool resolved a name itself instead of going through the proxy: " + line)
        else:
            ok(("127.0.0.1', %d" % proxy.port) in target, "the tool connected somewhere other than the proxy: " + line)


NONLOCAL_REFUSED_UNSEEN = ["registry.\u0435xample.test", "regist\u0433y.example.test", "registry.example.test:\uff15\uff10\uff10\uff10", "127.0.0.1:\u0668\u0660\u0668\u0660",
                           "l\u043ecalhost", "\uff11\uff12\uff17.0.0.1", "127.0.0.\u0661", "doc\u212aer.io", "registry-1.docker.io\u2060", "registry.example.test\u3002", "registry\uff0eexample.test",
                           "http://registry.example.test", "http://registry.example.test:5000", "http://127.0.0.1", "https://registry.example.test",
                           "127.0.0.1@registry.example.test", "localhost@registry.example.test:80", "user:pw@registry.example.test", "registry.example.test/path",
                           "", "registry.example.test?x=1", "127.0.0.1:99999999"]


@param("AC4", "a registry that is not a bare host is refused before any connection (not even a name lookup), with and without credentials", [("%s %s" % (h or "empty", c_), (h, c_ == "with credentials")) for h in NONLOCAL_REFUSED_UNSEEN for c_ in ("with credentials", "without credentials")])
def _(arg):
    h, with_creds = arg
    push_control()
    sink = Proxy()
    pd = make_dir(mk_fx(), vex_real())
    try:
        r = run(["push", "--registry", h, "--repository", "fosterstack/cache", "--dir", pd.path],
                env=dict(sink.env(), **({"FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET} if with_creds else {})), net="observe")
        ok(r.rc != 0, "accepted registry %r" % h)
        eq(sink.log, [], "something was sent towards %r" % h)
        eq(r.net, [], "the tool touched the network for %r" % h)
        ok(not secrets_in(r.out + r.err, None), "a credential was printed")
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        sink.close()


NONLOCAL_HOSTS = ["registry.example.test", "registry.example.test:5000", "localhost.example.test", "127.0.0.1.example.test", "localhost.example.test:5000", "10.255.255.1:5000", "[::2]:5000"]


@param("AC4", "a non-local host is never spoken to over plain http (with or without credentials), never resolved directly, and never sees credentials", [("%s %s" % (h, c_), (h, c_ == "with credentials")) for h in NONLOCAL_HOSTS for c_ in ("with credentials", "anonymous")])
def _(arg):
    h, with_creds = arg
    push_control()
    sink = Proxy()
    pd = make_dir(mk_fx(), vex_real())
    try:
        r = run(["push", "--registry", h, "--repository", "fosterstack/cache", "--dir", pd.path],
                env=dict(sink.env(), **({"FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET} if with_creds else {})), timeout=60, net="observe")
        ok(r.rc != 0, "the push to an unreachable non-local host succeeded")
        for x in sink.log:
            ok(x["method"] == "CONNECT", "a plain %s request for a non-local host went out: %s" % (x["method"], x["path"]))
            ok(x["auth"] is None, "credentials were sent")
        only_via_proxy(r, sink)
        ok(not secrets_in(r.out + r.err, None), "a credential was printed")
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        sink.close()


def watchers():
    other = Reg()           # another origin on localhost: must never be contacted
    sink = Proxy()          # stands for any non-local host: must never be contacted
    return other, sink


def assert_untouched(other, sink, r, reg, pd, why):
    ok(r.rc != 0, "the push succeeded: " + why)
    eq(other.log, [], "a request reached the other local origin (" + why + ")")
    eq([x for x in sink.log], [], "a request reached a non-local host (" + why + ")")
    ok(pd.f_digest not in reg.mans, "F stored: " + why)
    eq(f_puts(reg, pd), [], "an F PUT was attempted")
    ok("Traceback" not in r.err, "a traceback instead of a plain reason")


REALMS = ["http://127.0.0.1:@@PORT@@/token", "http://registry.example.test/token", "http://127.0.0.1@registry.example.test/token", "http://127.0.0.1.example.test/token",
          "http://localhost.example.test/token", "https://registry.example.test/token", "ftp://127.0.0.1/token", "//registry.example.test/token",
          "http://localhost:@@PORT@@/token", "http://127.0.0.1:@@PORT@@@registry.example.test/token", "https://auth.docker.io/token"]


@param("AC4", "a token realm outside the registry's own host (not https, another host, another local name, userinfo tricks) is refused before any credential or request goes there", [(x, x) for x in REALMS])
def _(realm):
    push_control()
    other, sink = watchers()
    realm = realm.replace("@@PORT@@", str(other.port))
    reg, pd = push_world(token=True, realm=realm)
    try:
        r = push(reg, pd, env=sink.env())
        assert_untouched(other, sink, r, reg, pd, "realm " + realm)
        for x in reg.log:
            ok(x["auth"] is None or x["auth"].startswith("Bearer "), "Basic credentials reached the registry")
        eq(okmuts(reg), [], "something was written")
    finally:
        other.close(); sink.close(); reg.close()


LOCS = ["http://registry.example.test", "http://127.0.0.1:@@PORT@@", "http://localhost:@@PORT@@", "https://127.0.0.1:@@PORT@@",
        "http://@@HOST@@@registry.example.test", "//registry.example.test", "http://registry.example.test:80"]


@param("AC4", "an upload Location on another origin is refused before the blob or any credential is sent there", [(x, x) for x in LOCS])
def _(loc):
    push_control()
    other, sink = watchers()
    reg, pd = push_world(token=True)
    reg.loc_base = loc.replace("@@PORT@@", str(other.port)).replace("@@HOST@@", reg.host)
    try:
        r = push(reg, pd, env=sink.env())
        assert_untouched(other, sink, r, reg, pd, "Location " + reg.loc_base)
        eq([x for x in reg.log if x["method"] == "PUT" and "/blobs/uploads/" in x["path"]], [], "a blob was PUT to the registry's upload URL")
    finally:
        other.close(); sink.close(); reg.close()


@case("AC4", "an upload Location on the same origin under a really different path prefix (/upload-service/..., not /v2/<repo>/blobs/uploads/) is followed as issued")
def _():
    def go(reg, pd):
        assert_clean_push(reg, pd, push(reg, pd))
    with_world(go, token=True, alt_uploads=True)


REDIRECT_KINDS = ["head_blob", "post", "put_blob", "head_man", "put_man", "get_man"]


REDIRECT_STATUSES = (301, 302, 303, 307, 308)
TARGETS = ("evil", "local", "same")
GRID = [("%d on %s -> %s" % (st, k, tg), (st, k, tg)) for st in REDIRECT_STATUSES for k in REDIRECT_KINDS for tg in TARGETS]


@param("AC4", "the FULL grid: every 3xx status (301, 302, 303, 307, 308) x every kind of registry request x every target (another host, another local origin, the same origin) is refused with zero destination requests and no credential forwarded", GRID)
def _(arg):
    push_control()
    status, kind, target = arg
    other, sink = watchers()
    to = {"evil": "http://registry.example.test/elsewhere", "local": "http://127.0.0.1:%d/v2/x/blobs/uploads/" % other.port, "same": "/v2/fosterstack/cache/blobs/elsewhere"}[target]
    reg, pd = push_world(token=True, redirect_on={kind}, redirect_to=to, redirect_status=status)
    try:
        r = push(reg, pd, env=sink.env())
        ok(r.rc != 0, "pushed although the registry answered %d" % status)
        eq(other.log, [], "the redirect was followed to the other origin")
        eq(sink.log, [], "the redirect was followed to a non-local host")
        ok(not any(x["path"].endswith("/elsewhere") for x in reg.log), "the same-origin redirect was followed")
        ok(pd.f_digest not in r.out, "claimed success")
        ok("Traceback" not in r.err, "a traceback")
    finally:
        other.close(); sink.close(); reg.close()


@param("AC4", "every 3xx status from the token endpoint is refused: zero destination requests and no credential forwarded (to another host, another local origin, the same origin)", [("%d -> %s" % (st, t_), (st, t_)) for st in REDIRECT_STATUSES for t_ in ("evil host", "other local origin", "same origin")])
def _(arg):
    push_control()
    status, target = arg
    other, sink = watchers()
    to = {"evil host": "http://registry.example.test/token", "other local origin": "http://127.0.0.1:%d/token" % other.port, "same origin": "/token-elsewhere"}[target]
    reg, pd = push_world(token=True, token_redirect_to=to, token_redirect_status=status)
    try:
        r = push(reg, pd, env=sink.env())
        assert_untouched(other, sink, r, reg, pd, "token %d to %s" % (status, target))
        ok(not any(x["path"] == "/token-elsewhere" for x in reg.log), "the same-origin token redirect was followed")
    finally:
        other.close(); sink.close(); reg.close()


@param("AC4", "https: every 3xx status from the token endpoint towards plain http is refused (no connection to the destination, no credential)", [(str(st), st) for st in REDIRECT_STATUSES])
def _(status):
    push_control()
    reg, pd, prox = tls_world(token=True, token_redirect_to="http://registry.example.test/token", token_redirect_status=status)
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "pushed")
        eq([x for x in prox.log if x["method"] != "CONNECT"], [], "a plain http request went out")
        eq([x for x in reg.log if x["path"] == "/token" and x["host"] != "registry.example.test"], [], "token request elsewhere")
        eq(f_puts(reg, pd), [], "F attempted")
    finally:
        reg.close(); prox.close()


@param("AC4", "https: every 3xx status x every kind of registry request, redirected towards plain http, is refused with no plain request and no connection to port 80", [("%d on %s" % (st, k), (st, k)) for st in REDIRECT_STATUSES for k in REDIRECT_KINDS])
def _(arg):
    status, kind = arg
    push_control()
    reg, pd, prox = tls_world(token=True, redirect_on={kind}, redirect_to="http://registry.example.test/upload", redirect_status=status)
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "pushed")
        eq([x for x in prox.log if x["method"] != "CONNECT"], [], "a plain http request went out")
        ok("registry.example.test:80" not in [x["path"] for x in prox.log], "a connection to port 80 was attempted")
        ok(not any(x["path"] == "/upload" for x in reg.log), "the redirect was followed")
    finally:
        reg.close(); prox.close()


@param("AC4", "the push validates attestations before any request: a wrong-typed or unknown OpenVEX property in a refreshed predicate is refused with zero requests", SCHEMA_REHASH_ALL)
def _(arg):
    push_control()
    fx = mk_fx()
    reg, pd = push_world(fx=fx, vb=BASE_VEX, pd=lambda fx_, vb: custom_pd(fx_, vb, schema_edit(arg), None, only=None))
    try:
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "invalid predicate")
        eq(reg.log, [], "a request was made although the predicate is not valid OpenVEX v0.2.0")
        ok(r.err.strip() != "", "no reason on stderr")
    finally:
        reg.close()


@case("AC4", "positive control: attestations built from the schema base document push cleanly")
def _():
    fx = mk_fx()
    reg, pd = push_world(fx=fx, vb=BASE_VEX, pd=lambda fx_, vb: custom_pd(fx_, vb))
    try:
        assert_clean_push(reg, pd, push(reg, pd))
    finally:
        reg.close()


# ---- https: a real TLS handshake through a tunnelling proxy that maps the test names to local registries
def tls_world(**kw):
    host = kw.pop("host", "registry.example.test")
    reg, pd = push_world(use_tls=True, public=host, **kw)
    routes = {"%s:443" % n: reg.port for n in TLS_NAMES}
    prox = Proxy(routes)
    return reg, pd, prox


def tls_push(reg, pd, prox, trust=True, **kw):
    return push(reg, pd, env=prox.env(trust=trust), net="observe", **kw)


@case("AC4", "https with a token realm on the registry's own host: a full clean push over a verified TLS connection")
def _():
    reg, pd, prox = tls_world(token=True)
    try:
        r = tls_push(reg, pd, prox)
        assert_clean_push(reg, pd, r)
        ok(all(x["method"] == "CONNECT" for x in prox.log), "something other than a tunnel went through the proxy")
        only_via_proxy(r, prox)
        want = "Basic " + base64.b64encode(("%s:%s" % (USER, SECRET)).encode()).decode()
        for x in reg.log:
            ok((x["path"] == "/token" and x["auth"] == want) or (x["path"] != "/token" and x["auth"] in (None, "Bearer " + reg.bearer)), "wrong Authorization for " + x["path"])
    finally:
        reg.close(); prox.close()


@case("AC4", "https with a registry that challenges for Basic: the Basic credentials work over TLS")
def _():
    reg, pd, prox = tls_world(basic=True)
    try:
        r = tls_push(reg, pd, prox)
        assert_clean_push(reg, pd, r)
        ok(any(x["auth"] and x["auth"].startswith("Basic ") for x in reg.log), "Basic credentials were never used")
    finally:
        reg.close(); prox.close()


@case("AC4", "the Docker Hub pair: registry-1.docker.io with a realm on auth.docker.io is accepted")
def _():
    reg, pd, prox = tls_world(host="registry-1.docker.io", token=True, realm="https://auth.docker.io/token")
    try:
        assert_clean_push(reg, pd, tls_push(reg, pd, prox))
    finally:
        reg.close(); prox.close()


@param("AC4", "https with a token realm on a different host (auth.example.test, or auth.docker.io for a non-Docker registry) is refused before any credential is sent", [("auth.example.test", ("registry.example.test", "https://auth.example.test/token")), ("auth.docker.io for a non-Docker registry", ("registry.example.test", "https://auth.docker.io/token")), ("auth.example.test for Docker Hub", ("registry-1.docker.io", "https://auth.example.test/token"))])
def _(arg):
    push_control()
    reg, pd, prox = tls_world(host=arg[0], token=True, realm=arg[1])
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "pushed using a realm on another host")
        eq([x for x in reg.log if x["path"] == "/token"], [], "the token endpoint was contacted")
        eq([x for x in reg.log if x["auth"] and x["auth"].startswith("Basic")], [], "Basic credentials were sent")
        eq(f_puts(reg, pd), [], "F attempted")
        ok(not any("auth." in x["path"] and x["path"].startswith("auth") for x in prox.log), "tunnel to the realm host")
        ok("auth.example.test:443" not in [x["path"] for x in prox.log] and "auth.docker.io:443" not in [x["path"] for x in prox.log], "the tool even connected to the other realm host")
    finally:
        reg.close(); prox.close()


@case("AC4", "TLS certificates are verified: against an untrusted certificate the push fails and the registry sees no request")
def _():
    push_control()
    reg, pd, prox = tls_world(token=True)
    try:
        r = tls_push(reg, pd, prox, trust=False)
        ok(r.rc != 0, "pushed over a connection whose certificate was not trusted")
        eq(reg.log, [], "a request was served over an unverified TLS connection")
    finally:
        reg.close(); prox.close()


@case("AC4", "https: an upload Location on another host (another tunnelled name) is refused and nothing is sent there")
def _():
    push_control()
    reg, pd, prox = tls_world(token=True)
    reg.loc_base = "https://auth.example.test"
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "followed a Location on another host")
        eq([x for x in reg.log if x["method"] == "PUT" and "/blobs/uploads/" in x["path"]], [], "a blob was PUT")
        ok(not any(x["path"] == "auth.example.test:443" for x in prox.log), "the tool connected to the other host")
        eq(f_puts(reg, pd), [], "F attempted")
    finally:
        reg.close(); prox.close()


@case("AC4", "https: TLS failure paths keep credentials out of every output")
def _():
    push_control()
    reg, pd, prox = tls_world(token=True, fail_after=2)
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "pushed despite the failures")
        assert_failed_no_claim(reg, pd, r, "tls 500")
    finally:
        reg.close(); prox.close()


@param("AC4", "final-index bytes that are not exactly canonical are refused before anything is sent, even when result.json and every digest were refreshed", sorted(FINAL_RAW.items()))
def _(f):
    push_control()
    fx = mk_fx(**EXTRAS)
    reg, pd = push_world(fx=fx, pd=lambda fx_, vb: custom_pd(fx_, vb, None, None, fraw=f))
    try:
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "non-canonical index.json")
        eq(reg.log, [], "a request was made although index.json is not canonical")
        ok(r.err.strip() != "", "no reason on stderr")
    finally:
        reg.close()


@param("AC4", "a token endpoint that answers 302 is never followed: no request reaches the destination and no credential is forwarded", [(t, t) for t in ("evil host", "other local origin", "same origin")])
def _(target):
    push_control()
    other, sink = watchers()
    to = {"evil host": "http://registry.example.test/token", "other local origin": "http://127.0.0.1:%d/token" % other.port, "same origin": "/token-elsewhere"}[target]
    reg, pd = push_world(token=True, token_redirect_to=to)
    try:
        r = push(reg, pd, env=sink.env())
        assert_untouched(other, sink, r, reg, pd, "token redirect to " + target)
        ok(not any(x["path"] == "/token-elsewhere" for x in reg.log), "the same-origin token redirect was followed")
        eq(okmuts(reg), [], "something was written")
    finally:
        other.close(); sink.close(); reg.close()


@case("AC4", "https: a token endpoint that answers 302 towards another tunnelled host is not followed (no connection to it, no credential)")
def _():
    push_control()
    reg, pd, prox = tls_world(token=True, token_redirect_to="https://auth.example.test/token")
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "pushed")
        ok("auth.example.test:443" not in [x["path"] for x in prox.log], "the redirect was followed")
        eq([x for x in reg.log if x["path"] == "/token" and x["host"] != "registry.example.test"], [], "token request on another host")
        eq(f_puts(reg, pd), [], "F attempted")
    finally:
        reg.close(); prox.close()


@case("AC4", "https: a challenge naming an HTTP realm on the same host is refused (no plain request, no token fetch, no credential)")
def _():
    push_control()
    reg, pd, prox = tls_world(token=True, realm="http://registry.example.test/token")
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "pushed using an http realm")
        eq([x for x in prox.log if x["method"] != "CONNECT"], [], "a plain http request went out")
        ok("registry.example.test:80" not in [x["path"] for x in prox.log], "a connection to port 80 was attempted")
        eq([x for x in reg.log if x["path"] == "/token"], [], "the token endpoint was contacted")
        eq([x for x in reg.log if x["auth"] and x["auth"].startswith("Basic")], [], "Basic credentials were sent")
        eq(f_puts(reg, pd), [], "F attempted")
    finally:
        reg.close(); prox.close()


LOOKALIKES = [("registry-1.docker.io", "https://auth.doc\u212aer.io/token"), ("registry-1.docker.io", "https://auth.docker.io\u3002/token"), ("registry-1.docker.io", "https://\uff41uth.docker.io/token"),
              ("registry.example.test", "https://registry.\u0435xample.test/token"), ("registry.example.test", "https://registry.example.test:\uff14\uff14\uff13/token"),
              ("registry.example.test", "https://registry.example.test:8443/token"), ("registry-1.docker.io", "https://auth.docker.io:8443/token"),
              ("registry.example.test", "https://registry.example.test.attacker.test/token"), ("registry.example.test", "https://evil-registry.example.test/token"),
              ("registry.example.test", "https://registry.example.test./token"), ("registry.example.test", "https://registry.example.test@attacker.test/token"),
              ("registry.example.test", "https://registry.example.test:443@attacker.test/token"), ("registry.example.test", "https://attacker.test/registry.example.test"),
              ("registry.example.test", "https://registry.example.testx/token"), ("registry-1.docker.io", "https://auth.docker.io.attacker.test/token"),
              ("registry-1.docker.io", "https://xauth.docker.io/token"), ("registry-1.docker.io", "https://docker.io.attacker.test/token"),
              ("registry-1.docker.io", "https://auth.docker.io@attacker.test/token"), ("registry-1.docker.io", "https://auth.docker.iox/token")]


@param("AC4", "over https, a token realm that merely resembles the registry's host or auth.docker.io (suffix, prefix, trailing dot, userinfo) is refused before any connection to it", [("%s -> %s" % a, a) for a in LOOKALIKES])
def _(arg):
    push_control()
    reg, pd, prox = tls_world(host=arg[0], token=True, realm=arg[1])
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "pushed using a lookalike realm")
        eq([x["path"] for x in prox.log if x["path"] != "%s:443" % arg[0]], [], "the tool connected to a host other than the registry")
        eq([x for x in reg.log if x["path"] == "/token"], [], "the token endpoint was contacted")
        eq([x for x in reg.log if x["auth"] and x["auth"].startswith("Basic")], [], "Basic credentials were sent")
        eq(f_puts(reg, pd), [], "F attempted")
    finally:
        reg.close(); prox.close()


@param("AC4", "anonymous (no credentials) pushes over https: a challenge naming an http realm, another host, another port or a lookalike is refused before any connection", [("http realm on the same host", ("registry.example.test", "http://registry.example.test/token")), ("another host", ("registry.example.test", "https://auth.example.test/token")), ("lookalike suffix", ("registry.example.test", "https://registry.example.test.attacker.test/token")), ("lookalike docker", ("registry-1.docker.io", "https://auth.docker.io.attacker.test/token")), ("another port", ("registry.example.test", "https://registry.example.test:8443/token"))])
def _(arg):
    push_control()
    reg, pd, prox = tls_world(host=arg[0], token=True, realm=arg[1])
    try:
        r = tls_push(reg, pd, prox, creds=False)
        ok(r.rc != 0, "pushed")
        eq([x for x in prox.log if x["method"] != "CONNECT"], [], "a plain http request went out")
        eq([x["path"] for x in prox.log if x["path"] != "%s:443" % arg[0]], [], "the tool connected to another host or port")
        eq([x for x in reg.log if x["path"] == "/token"], [], "the token endpoint was contacted")
        eq(f_puts(reg, pd), [], "F attempted")
    finally:
        reg.close(); prox.close()


@case("AC4", "https: an upload Location that downgrades the scheme to http on the same host is refused (no plain request, no blob sent)")
def _():
    push_control()
    reg, pd, prox = tls_world(token=True)
    reg.loc_base = "http://registry.example.test"
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "followed a downgraded Location")
        eq([x for x in prox.log if x["method"] != "CONNECT"], [], "a plain http request went out")
        eq([x for x in reg.log if x["method"] == "PUT" and ("/blobs/uploads/" in x["path"] or x["path"].startswith("/upload-service/"))], [], "a blob was PUT")
        eq(f_puts(reg, pd), [], "F attempted")
    finally:
        reg.close(); prox.close()


STALLS = ["head_blob", "post", "put_blob", "head_man", "put_man", "get_man", "token"]


@param("AC4", "a registry that stops answering makes the push fail within a bounded time (FSCACHE_REGISTRY_TIMEOUT, here 2 s) on every kind of request, with no digest claimed", [(k, k) for k in STALLS])
def _(kind):
    push_control()
    reg, pd = push_world(stall_on={kind}, token=(kind == "token"))
    try:
        t0 = time.time()
        r = push(reg, pd, env={"FSCACHE_REGISTRY_TIMEOUT": "2"}, timeout=20)
        took = time.time() - t0
        ok(r.rc != 0, "the push succeeded against a stalled registry")
        ok(took < 15, "the push took %.1f s to give up (timeout 2 s)" % took)
        ok(pd.f_digest not in r.out, "claimed success")
        ok("Traceback" not in r.err, "a traceback")
        if kind != "get_man":
            ok(pd.f_digest not in reg.mans, "F stored")
    finally:
        reg.close()


@case("AC4", "a server that accepts the connection and never reads or answers also makes the push fail within a bounded time")
def _():
    push_control()
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(8)
    try:
        pd = make_dir(mk_fx(), vex_real())
        t0 = time.time()
        r = run(["push", "--registry", "127.0.0.1:%d" % ls.getsockname()[1], "--repository", "fosterstack/cache", "--dir", pd.path],
                env={"FSCACHE_REGISTRY_USER": USER, "FSCACHE_REGISTRY_TOKEN": SECRET, "FSCACHE_REGISTRY_TIMEOUT": "2"}, timeout=20)
        ok(r.rc != 0 and pd.f_digest not in r.out, "claimed success")
        ok(time.time() - t0 < 15, "gave up too slowly")
    finally:
        ls.close()


# ------------------------------------------------------------------ round 3 additions
HDR_CASES = ["lower", "upper", "title"]


@param("AC4", "HTTP header names are case-insensitive: Bearer and Basic challenges, upload Location, Content-Type and Docker-Content-Digest in lower, upper and title case all work", [("%s / %s" % (m_, c_), (m_, c_)) for m_ in ("bearer", "basic", "none") for c_ in HDR_CASES])
def _(arg):
    mode, case_ = arg

    def go(reg, pd):
        assert_clean_push(reg, pd, push(reg, pd))
    with_world(go, token=(mode == "bearer"), basic=(mode == "basic"), hdr_case=case_)


@param("AC4", "a blob PUT that is refused (400, 403, 404, 500) stops the push before any manifest is written", [("%s on a %s registry" % (c_, a_), (c_, l_)) for c_ in (400, 403, 404, 500) for a_, l_ in LENIENCY])
def _(arg):
    push_control()
    code, len_ = arg

    def go(reg, pd):
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "blob PUT %d" % code)
        eq([x for x in reg.log if x["method"] == "PUT" and "/manifests/" in x["path"]], [], "a manifest was pushed after a failed blob upload")
    with_world(go, put_blob_status=code, lenient=len_)


@param("AC4", "a blob HEAD that answers 500, 403 or 401 is never taken to mean 'exists': nothing is pushed on top of it", [("%s on a %s registry" % (c_, a_), (c_, l_)) for c_ in (500, 403, 401) for a_, l_ in LENIENCY])
def _(arg):
    push_control()
    code, len_ = arg

    def go(reg, pd):
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "blob HEAD %d" % code)
        eq([x for x in reg.log if x["method"] == "PUT" and "/manifests/" in x["path"]], [], "a manifest was pushed")
    with_world(go, head_blob_status=code, lenient=len_)


@param("AC4", "a blob that is not there when re-checked after its upload (HEAD 404 after PUT) stops the push before any manifest PUT", LENIENCY)
def _(len_):
    push_control()

    def go(reg, pd):
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "blob gone after upload")
        eq([x for x in reg.log if x["method"] == "PUT" and "/manifests/" in x["path"]], [], "a manifest was pushed although a blob could not be confirmed")
        ok(any(x["method"] == "HEAD" and "/blobs/sha256:" in x["path"] and x["status"] == 404 for x in reg.log), "fixture: no blob HEAD 404")
    with_world(go, blob_gone_after_put=True, lenient=len_)


@param("AC4", "a response that trickles one byte per second is cut off by the TOTAL per-request deadline (FSCACHE_REGISTRY_TIMEOUT=2), not just a per-read timeout", [("read-back body", {"readback": "drip"}), ("token response", {"token": True, "token_drip": True})])
def _(kw):
    push_control()
    reg, pd = push_world(**kw)
    try:
        t0 = time.time()
        r = push(reg, pd, env={"FSCACHE_REGISTRY_TIMEOUT": "2"}, timeout=40)
        took = time.time() - t0
        ok(r.rc != 0, "the push succeeded from a trickling registry")
        ok(took < 15, "the tool waited %.1f s for a trickling response (deadline 2 s)" % took)
        ok(pd.f_digest not in r.out, "claimed success")
        ok("Traceback" not in r.err, "a traceback")
    finally:
        reg.close()


def documented_timeout():
    r = run(["push", "--help"], net="off")
    ok(r.rc == 0, "push --help failed")
    text = " ".join(r.out.split())
    m = re.search(r"FSCACHE_REGISTRY_TIMEOUT.{0,200}?default[: ]+(\d+)", text)
    ok(m is not None, "push --help does not document FSCACHE_REGISTRY_TIMEOUT with a default in seconds")
    n = int(m.group(1))
    ok(1 <= n <= 60, "the documented default timeout is %d s (must be between 1 and 60)" % n)
    return n


@case("AC4", "push --help documents FSCACHE_REGISTRY_TIMEOUT and its default, a number of seconds no greater than 60")
def _():
    documented_timeout()


@case("AC4", "the documented default timeout is really applied: with no FSCACHE_REGISTRY_TIMEOUT a stalled registry makes the push fail within the documented time")
def _():
    push_control()
    n = documented_timeout()
    reg, pd = push_world(stall_on={"post"})
    try:
        t0 = time.time()
        r = push(reg, pd, timeout=n + 40)
        took = time.time() - t0
        ok(r.rc != 0, "the push succeeded")
        ok(took < n + 15, "gave up after %.1f s (documented default %d s)" % (took, n))
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        reg.close()


@case("AC4", "compute -> push consistency at the D limit with retained content: a D of exactly 1 MiB computes and its F (above 1 MiB) pushes cleanly")
def _():
    fx = fx_with_len(2 ** 20, "D")
    c = do_compute(fx.bytes, VEX_MIN)
    check_matches_ref(fx.bytes, VEX_MIN, c)
    reg = Reg()
    reg.seed(fx.children)
    pd = make_dir(fx, VEX_MIN)
    pd.path = c.dir
    reg.att_set = set(pd.att_digests)
    try:
        assert_clean_push(reg, pd, push(reg, pd))
    finally:
        reg.close()


@param("AC4", "the final index limit for push is 2 MiB of raw bytes: exactly 2 MiB is pushed, 2 MiB + 1 is refused before any request", [("exactly 2 MiB", True), ("2 MiB + 1", False)])
def _(good):
    push_control()
    fx = fx_with_len(2 ** 21 + (0 if good else 1), "F")
    reg, pd = push_world(fx=fx, vb=VEX_MIN, pd=lambda fx_, vb: custom_pd(fx_, vb))
    try:
        eq(len(pd.fb), 2 ** 21 + (0 if good else 1), "fixture size")
        r = push(reg, pd)
        if good:
            assert_clean_push(reg, pd, r)
        else:
            assert_no_f_attempt(reg, pd, r, "F over 2 MiB")
            eq(reg.log, [], "a request was made")
    finally:
        reg.close()


@case("AC4", "https: a trusted certificate for the WRONG host (hostname verification) is refused: the registry sees no request")
def _():
    push_control()
    reg, pd, prox = tls_world(token=True, cert="wrong")
    try:
        r = tls_push(reg, pd, prox)
        ok(r.rc != 0, "pushed over a certificate for another host")
        eq(reg.log, [], "a request was served over a connection whose certificate names another host")
    finally:
        reg.close(); prox.close()


def docker_world(token_cert):
    a, pd = push_world(use_tls=True, public="registry-1.docker.io", token=True, realm="https://auth.docker.io/token")
    b = Reg(use_tls=True, public="auth.docker.io", cert=token_cert)
    b.bearer, b.bearer_pull = a.bearer, a.bearer_pull
    prox = Proxy({"registry-1.docker.io:443": a.port, "auth.docker.io:443": b.port})
    return a, b, pd, prox


@case("AC4", "positive control: the Docker Hub pair with a separate, trusted, correctly named token server pushes cleanly (a distinct authentication origin over TLS)")
def _():
    a, b, pd, prox = docker_world("good")
    try:
        r = push(a, pd, env=prox.env(trust=True), net="observe")
        assert_clean_push(a, pd, r)
        want = "Basic " + base64.b64encode(("%s:%s" % (USER, SECRET)).encode()).decode()
        ok(b.log and all(x["path"] == "/token" and x["auth"] == want for x in b.log), "the token server saw something other than the token request")
        eq([x for x in a.log if x["auth"] and x["auth"].startswith("Basic")], [], "Basic credentials reached the registry")
    finally:
        a.close(); b.close(); prox.close()


@param("AC4", "the token endpoint behind a trusted registry presents a certificate for the wrong host, or an untrusted one: no authenticated request reaches it and nothing is pushed", [("trusted certificate for the wrong host", "wrong"), ("untrusted certificate", "untrusted")])
def _(cert):
    push_control()
    a, b, pd, prox = docker_world(cert)
    try:
        r = push(a, pd, env=prox.env(trust=True), net="observe")
        ok(r.rc != 0, "pushed using a token endpoint with a bad certificate")
        eq(b.log, [], "a request (with credentials) was served to the token endpoint")
        eq([x for x in a.log if x["auth"] and x["auth"].startswith("Basic")], [], "Basic credentials reached the registry")
        eq(f_puts(a, pd), [], "F attempted")
        eq(okmuts(a), [], "something was written")
    finally:
        a.close(); b.close(); prox.close()


@case("AC4", "https: an explicit default port in the realm (https://registry.example.test:443/token) is the same origin and works")
def _():
    reg, pd, prox = tls_world(token=True, realm="https://registry.example.test:443/token")
    try:
        assert_clean_push(reg, pd, tls_push(reg, pd, prox))
    finally:
        reg.close(); prox.close()


@case("AC4", "a symlinked DIR itself is refused before any request")
def _():
    push_control()
    reg, pd = push_world()
    link = pd.path + "-link"
    os.symlink(pd.path, link)
    real = pd.path
    pd.path = link
    try:
        r = push(reg, pd)
        assert_no_f_attempt(reg, pd, r, "symlinked DIR")
        eq(reg.log, [], "a request was made through a symlinked DIR")
        ok(r.err.strip() != "", "no reason on stderr")
    finally:
        pd.path = real
        reg.close()


@param("AC4", "the tool always asks for the token scope repository:<repo>:pull,push itself, whatever the challenge says (a method-scoped registry issues pull-only tokens for a pull request and 401s a POST/PUT on one)", [("method-scoped challenges", "method"), ("a challenge that always names pull", "pull")])
def _(chal):
    push_control()
    chal = None if chal == "method" else chal

    def go(reg, pd):
        r = push(reg, pd)
        assert_clean_push(reg, pd, r)
        scopes = [dict(urllib.parse.parse_qsl(x["query"])).get("scope") for x in reg.log if x["path"] == "/token"]
        ok(scopes and all(s_ == "repository:%s:pull,push" % reg.repo for s_ in scopes), "token scopes asked: %r" % scopes)
        ok(not any(x["auth"] == "Bearer " + reg.bearer_pull for x in reg.log), "a pull-only token was used")
    with_world(go, token=True, challenge_scope=chal)


@case("AC4", "after a bearer 401 the tool never falls back to Basic credentials against the registry (the registry rejects every bearer and offers a Basic challenge)")
def _():
    push_control()
    reg, pd = push_world(token=True, bearer_rejected=True)
    try:
        r = push(reg, pd)
        ok(r.rc != 0, "pushed")
        eq([x for x in reg.log if x["path"] != "/token" and x["auth"] and x["auth"].startswith("Basic")], [], "Basic credentials were sent to the registry after a bearer 401")
        eq(okmuts(reg), [], "something was written")
        ok(pd.f_digest not in r.out, "claimed success")
    finally:
        reg.close()


@param("AC4", "a read-back that is the correct body plus a trailing newline or space, differs only in the case of a hex letter, or differs only in the final byte (header always claiming the right digest) fails the push: the FULL bytes are compared", [("plus a trailing newline", "trail-nl"), ("plus a trailing space", "trail-space"), ("a hex letter in upper case", "case-swap"), ("only the final byte differs", "last-byte")])
def _(mode):
    push_control()
    reg, pd = push_world(rewrite=mode, lie=True)
    try:
        r = push(reg, pd)
        assert_failed_no_claim(reg, pd, r, "full-bytes read-back " + mode)
        ok(any(x["method"] == "GET" and x["path"].endswith("/manifests/" + pd.f_digest) for x in reg.log), "no read-back attempted")
    finally:
        reg.close()


@param("AC4", "a read-back that differs by ONE flipped hex character (same length, header claiming the right digest) fails the push, wherever the flip is: near the start, in the middle, in the very last digest of F", [("near the start", "samelen"), ("in the middle", "samelen-mid"), ("the last hex character of the last digest", "samelen-end")])
def _(mode):
    push_control()
    reg, pd = push_world(rewrite=mode, lie=True)
    try:
        r = push(reg, pd)
        assert_failed_no_claim(reg, pd, r, "same-length rewrite " + mode)
        ok(any(x["method"] == "GET" and x["path"].endswith("/manifests/" + pd.f_digest) for x in reg.log), "no read-back attempted")
    finally:
        reg.close()


@case("AC4", "HTTP whitespace around a Content-Type is only space and tab: spaces and a parameter are accepted on the read-back")
def _():
    def go(reg, pd):
        assert_clean_push(reg, pd, push(reg, pd))
    with_world(go, readback="ct-ws-ok")


def main():
    only = os.environ.get("ONLY")
    passed, failed, fails, selected = 0, 0, [], 0
    for tag, name, f, arg in CASES:
        if only and only not in name:
            continue
        selected += 1
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
        if failed and os.environ.get("VEXIDX_FAILFAST"):
            break
    print("")
    by = {}
    for tag, name, f, arg in CASES:
        by[tag] = by.get(tag, 0) + 1
    print("cases by AC: " + ", ".join("%s=%d" % (k, by[k]) for k in sorted(by)))
    print("%d passed, %d failed, %d cases" % (passed, failed, passed + failed))
    if selected == 0:
        print("FAIL: no case was selected")
        sys.exit(1)
    sys.exit(1 if failed else 0)


main()
PYEOF

python3 "$T/harness.py"
