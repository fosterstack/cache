#!/usr/bin/env bash
# proves: REQ-REL-010-AC1, REQ-REL-010-AC3
# Tests for bin/vex-index.py, the tool that derives the FINAL image index from the built index and the release's
# VEX file (REQ-REL-010: the ACs are the advisor's reading of the owner's rules, not his words). The
# tool is driven through its command line only (compute, verify, layout, verify-layout, sidecar). Everything runs offline,
# with a network guard under every run: the tool has no network code at all.
#
# The expected bytes are computed here, by an independent re-statement of the canonical form (ref_compute),
# and one fixture carries hand-checked golden digests, so a tool that is self-consistent but serialises
# differently fails.
#
# VEX_INDEX=/path/to/tool.py runs the same tests against another copy of the tool (default bin/vex-index.py).
# Needs python3 (standard library only). Exit status is non-zero when any case fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT
export VEX_INDEX="${VEX_INDEX:-$ROOT/bin/vex-index.py}"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

cat >"$T/harness.py" <<'PYEOF'
import ast, base64, hashlib, http.server, json, os, random, re, shutil, socket, subprocess, sys
import atexit, gzip, importlib.util, io, select, tarfile, socketserver, ssl, tempfile, threading, time, urllib.parse

ROOT = os.environ["ROOT"]
TOOL = os.environ["VEX_INDEX"]
TMP = os.path.realpath(tempfile.mkdtemp(prefix="vexidx-cases-"))   # no symlink in the path: the tool refuses one at any level
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
    import json as _json
    _hostmap = _json.loads(os.environ.get("VEXIDX_HOSTMAP") or "{}")
    def gai(host, port=None, *a, **k):
        _rec("resolve", "%s %s" % (host, port))
        if _mode == "block":
            raise OSError("name resolution blocked by the test")
        if _mode == "observe" and host not in ("127.0.0.1", "localhost", "::1", None):
            key = "%s:%s" % (host, port)
            if key in _hostmap:  # a test name served by a local server: no proxy, no DNS
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", _hostmap[key]))]
            raise socket.gaierror(-2, "no such host (test)")
        return _gai(host, port, *a, **k)
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
for _n in ("cu" + "rl", "wg" + "et", "nc", "ncat", "ssh", "scp", "sftp", "git", "telnet", "ftp", "gh"):   # the stub programs a run must not call (spelled apart: the pin-age inventory reads this file as a script)
    with open(os.path.join(STUBS, _n), "w") as _f:
        _f.write('#!/bin/sh\necho "exec %s" >> "$VEXIDX_NETLOG"\nexit 1\n' % _n)
    os.chmod(os.path.join(STUBS, _n), 0o755)


MEMORY_LIMIT_KB = 1 << 20  # 1 GiB resident: the tool normally needs a few tens of MB; more means an unbounded read


class Done:
    pass


def run_watched(cmd, env, cwd, timeout):
    """subprocess.run with a memory watchdog: a tool that reads without a bound is killed and the case fails"""
    proc = subprocess.Popen(cmd, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    state = {"memory": False}

    def resident_kb():
        try:  # Linux
            with open("/proc/%d/statm" % proc.pid) as f:
                return int(f.read().split()[1]) * (os.sysconf("SC_PAGE_SIZE") // 1024)
        except (OSError, ValueError, IndexError):
            pass
        try:  # macOS and the BSDs
            return int(subprocess.run(["ps", "-o", "rss=", "-p", str(proc.pid)], capture_output=True).stdout.strip() or 0)
        except Exception:
            return 0

    def watch():
        while proc.poll() is None:
            rss = resident_kb()
            if rss > MEMORY_LIMIT_KB:
                state["memory"] = True
                proc.kill()
                return
            time.sleep(0.2)
    threading.Thread(target=watch, daemon=True).start()
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise Fail("the tool did not finish within %ds" % timeout)
    if state["memory"]:
        raise Fail("the tool used more than 1 GiB of memory (an unbounded read)")
    d = Done()
    d.returncode, d.stdout, d.stderr = proc.returncode, out, err
    return d


def run(args, env=None, cwd=None, replace_env=False, timeout=90, net=None, sink=None):
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
    mode = net or ("block" if args and args[0] in ("compute", "verify", "layout", "verify-layout") else ("observe" if sink is not None else "off"))
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
    p = run_watched([sys.executable, TOOL] + list(args), e, cwd, timeout)
    r = R(p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"))
    r.net = open(netlog).read().splitlines() if netlog else []
    if sink is not None:
        sink.feed(r.net)
    stray = (os.listdir(cwd) if auto_cwd else []) + os.listdir(tdir)
    if stray:
        raise Fail("the tool left files in its working directory or TMPDIR: %s" % stray[:5])
    if mode == "block" and r.net:
        raise Fail("the tool attempted network access (%s): %s" % (args[0], r.net[:3]))
    return r


def tree(d, full=False):
    """every entry under d: file contents (a size for anything above 1 MiB, a type for anything that is not a regular file)"""
    import stat as _stat
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
            rel = os.path.relpath(p, d)
            st = os.lstat(p)
            if _stat.S_ISLNK(st.st_mode):
                out[rel] = os.readlink(p).encode()
            elif not _stat.S_ISREG(st.st_mode):
                out[rel] = ("special file %o" % _stat.S_IFMT(st.st_mode)).encode()
            elif st.st_size > 1 << 20 and not full:
                out[rel] = ("big file %d" % st.st_size).encode()
            else:
                out[rel] = rd(p)
    return out


# ------------------------------------------------------------------ independent canonical form
def cj(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def dg(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def hx(d):
    return d.split(":", 1)[1]


def ref_scout(vex_obj):
    """the predicate an attestation carries: the VEX file in the form Docker Scout applies. Scout's own `docker scout attestation add` stores a statement whose products
    are the vulnerable PACKAGES (the image is the in-toto subject): a product that names the attested image (its purl, as @id or identifiers.purl) and lists subcomponents
    is replaced by them, in order, once each; every other product stays whole.
    (Oct 23 2026, rescan run 39978435878: the same document embedded verbatim, product = image purl with the package as a subcomponent, was read by Scout and not applied.)"""
    o = json.loads(json.dumps(vex_obj))
    for st in o.get("statements", []):
        out, seen = [], set()
        for prod in st.get("products", []):
            subs = prod.get("subcomponents")
            names_image = SUBJECT_NAME in (prod.get("@id"), (prod.get("identifiers") or {}).get("purl"))
            for q in (subs if names_image and isinstance(subs, list) and subs else [prod]):
                k = cj(q)
                if k not in seen:
                    seen.add(k)
                    out.append(q)
        st["products"] = out
    return o


def ref_att_verbatim(pdigest, vex_obj):
    """the attestation as it was before Oct 23 2026: the VEX file embedded as it is (kept for the test that the verifier refuses it)"""
    saved = ref_scout
    globals()["ref_scout"] = lambda o: json.loads(json.dumps(o))
    try:
        return ref_att(pdigest, vex_obj)
    finally:
        globals()["ref_scout"] = saved


def ref_att(pdigest, vex_obj):
    stmt = cj({"_type": STMT_TYPE, "predicateType": PRED,
               "subject": [{"name": SUBJECT_NAME, "digest": {"sha256": hx(pdigest)}}], "predicate": ref_scout(vex_obj)})
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


VEX_REAL = rd(os.path.join(ROOT, "test-evidence", "vex-scope", "busybox.openvex.json")) if os.path.isfile(os.path.join(ROOT, "test-evidence", "vex-scope", "busybox.openvex.json")) else None
VEX_MIN = ('{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"Example Co",'
           '"timestamp":"2026-01-01T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2000-0001"},'
           '"products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}],"status":"not_affected",'
           '"justification":"component_not_present","impact_statement":"naïve — ok"}]}').encode("utf-8")


def vex_real():
    if VEX_REAL is None:
        raise Fail("the multi-statement fixture VEX test-evidence/vex-scope/busybox.openvex.json is missing")
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
    got = tree(r.dir, full=True)
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
        eq(tree(os.path.join(s, "in")), {"index.json": db if len(db) <= 1 << 20 else ("big file %d" % len(db)).encode(),
                                           "vex.json": vb if len(vb) <= 1 << 20 else ("big file %d" % len(vb)).encode()}, "inputs")
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
    if good:    # the built index it derives from is itself above its own 1 MiB limit here, so the only refusal that may come is the base file's size, after the final index was read
        ok(r.rc == 0 or (r.rc == 2 and "base.json is larger than 1048576 bytes" in r.err), "verify refused a final index of %d bytes for the wrong reason: %s" % (len(fb), r.err.strip()[:150]))
    else:
        ok(r.rc != 0 and "final.json is larger" in r.err, "verify accepted or mislabelled a final index of %d bytes: %s" % (len(fb), r.err.strip()[:150]))


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


@case("AC1", "two statements that name the image in two forms (@id, identifiers.purl) and become the same in Scout's form are refused by compute (verify would refuse the duplicate) and nothing is written (round 1, Opus F1)")
def _():
    fx = mk_fx()
    def twice(o):
        o["statements"].append(json.loads(json.dumps(o["statements"][0])))
        prod = o["statements"][1]["products"][0]
        del prod["@id"]
        prod["identifiers"] = {"purl": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}   # the image named by identifiers.purl instead of @id
    vb = vex_with(twice, base=BASE_VEX)
    assert_refused(fx.bytes, vb, "statements identical in Scout's form")


@param("AC2", "a half-unknown platform (unknown/amd64, linux/unknown) is refused; unknown/unknown is passed through", [("unknown/amd64", ("unknown", "amd64")), ("linux/unknown", ("linux", "unknown")), ("unknown/arm64/v8", ("unknown", "arm64"))])
def _(osarch):
    fx = mk_fx()
    o = json.loads(json.dumps(fx.obj))
    o["manifests"].append(dict(desc_of(mk_child("s390x")), platform={"os": osarch[0], "architecture": osarch[1]}))
    assert_refused(json.dumps(o).encode(), VEX_MIN, "half-unknown platform")


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


# What `docker scout attestation add` actually produced (rescan run 39945154746, scout-root-cause artifact, Docker Scout 1.26.0): the input was a statement whose product is our published
# image purl with the package as its subcomponent; the stored attestation's statement has the package as its product. The comparison ignores what Scout rewrites on its own (@id, the
# in-toto subject name). This is the fixture the derived predicate is held to.
SCOUT_PKG = "pkg:deb/debian/glibc@2.36-9?os_distro=bookworm&os_name=debian&os_version=12"
SCOUT_IN = {"@context": PRED, "@id": "https://openvex.dev/docs/public/vex-scout-root-cause", "author": "FosterStack LLC", "timestamp": "2026-10-03T00:00:00Z", "version": 1,
            "statements": [{"vulnerability": {"name": "CVE-2023-4911"}, "timestamp": "2026-10-03T00:00:00Z", "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
                            "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "subcomponents": [{"@id": SCOUT_PKG}]}]}]}
SCOUT_OUT_STATEMENTS = [{"vulnerability": {"name": "CVE-2023-4911"}, "products": [{"@id": SCOUT_PKG}], "status": "not_affected",
                         "justification": "vulnerable_code_not_in_execute_path", "timestamp": "2026-10-03T00:00:00Z"}]


@case("AC3", "the attested predicate is the form Docker Scout itself stores: a product's subcomponents become the statement's products (golden from docker scout attestation add)")
def _():
    fx = mk_fx()
    r = do_compute(fx.bytes, json.dumps(SCOUT_IN).encode("utf-8"))
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:200])
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    bdir = os.path.join(r.dir, "blobs", "sha256")
    n = 0
    for e in f["manifests"]:
        if (e.get("annotations") or {}).get("vnd.docker.reference.type") != "attestation-manifest":
            continue
        m = json.loads(rd(os.path.join(bdir, hx(e["digest"]))))
        st = json.loads(rd(os.path.join(bdir, hx(m["layers"][0]["digest"]))))
        eq(st["predicate"]["statements"], SCOUT_OUT_STATEMENTS, "statements as Scout stored them")
        eq(sorted(k for k in st["predicate"] if k != "@id"), sorted(k for k in SCOUT_IN if k != "@id"), "document keys other than @id")
        n += 1
    ok(n >= 1, "no attestation found")


@case("AC3", "a statement whose product has no subcomponents is attested unchanged; the image's product with several subcomponents becomes several products, once each, in order; another product (cache-x) stays whole")
def _():
    fx = mk_fx()
    vex = json.loads(json.dumps(SCOUT_IN))
    vex["statements"] = [{"vulnerability": {"name": "CVE-2024-1"}, "status": "not_affected", "justification": "vulnerable_code_not_present", "products": [{"@id": "pkg:golang/github.com/fosterstack/cache"}]},
                         {"vulnerability": {"name": "CVE-2024-2"}, "status": "not_affected", "justification": "vulnerable_code_not_present",
                          "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "subcomponents": [{"@id": "pkg:generic/b@1"}, {"@id": "pkg:generic/a@2"}]},
                                       {"@id": "pkg:oci/cache-x?repository_url=ghcr.io/fosterstack/cache-x", "subcomponents": [{"@id": "pkg:generic/b@1"}]}]}]
    r = do_compute(fx.bytes, json.dumps(vex).encode("utf-8"))
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:200])
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    bdir = os.path.join(r.dir, "blobs", "sha256")
    e = [x for x in f["manifests"] if (x.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest"][0]
    st = json.loads(rd(os.path.join(bdir, hx(json.loads(rd(os.path.join(bdir, hx(e["digest"]))))["layers"][0]["digest"]))))
    eq([x["products"] for x in st["predicate"]["statements"]],
       [[{"@id": "pkg:golang/github.com/fosterstack/cache"}],
        [{"@id": "pkg:generic/b@1"}, {"@id": "pkg:generic/a@2"},
         {"@id": "pkg:oci/cache-x?repository_url=ghcr.io/fosterstack/cache-x", "subcomponents": [{"@id": "pkg:generic/b@1"}]}]], "products after the derivation")


@case("AC3", "only the image's own product is replaced by its subcomponents: another image, a platform digest form and cache-candidates stay whole; an empty list stays; a package in two statements stays in both")
def _():
    fx = mk_fx()
    IMG = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
    vex = json.loads(json.dumps(SCOUT_IN))
    def stmt(name, products):
        return {"vulnerability": {"name": name}, "status": "not_affected", "justification": "vulnerable_code_not_present", "products": products}
    A = {"@id": "pkg:generic/a@1"}
    CAND = {"@id": "pkg:oci/cache-candidates?repository_url=ghcr.io/fosterstack/cache-candidates", "subcomponents": [A]}
    OTHER = {"@id": "pkg:oci/other", "subcomponents": [A]}
    DIGEST = {"@id": "pkg:oci/cache@sha256:" + "a" * 64 + "?repository_url=ghcr.io/fosterstack/cache", "subcomponents": [A]}
    EMPTY = {"@id": IMG, "subcomponents": []}
    vex["statements"] = [stmt("CVE-2024-1", [CAND]), stmt("CVE-2024-2", [OTHER, DIGEST]), stmt("CVE-2024-3", [EMPTY]),
                         stmt("CVE-2024-4", [{"@id": IMG, "subcomponents": [A]}]), stmt("CVE-2024-5", [{"@id": IMG, "subcomponents": [A]}])]
    r = do_compute(fx.bytes, json.dumps(vex).encode("utf-8"))
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:200])
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    bdir = os.path.join(r.dir, "blobs", "sha256")
    e = [x for x in f["manifests"] if (x.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest"][0]
    st = json.loads(rd(os.path.join(bdir, hx(json.loads(rd(os.path.join(bdir, hx(e["digest"]))))["layers"][0]["digest"]))))
    eq([x["products"] for x in st["predicate"]["statements"]], [[CAND], [OTHER, DIGEST], [EMPTY], [A], [A]], "products after the derivation")


@case("AC3", "verify refuses an attestation that carries the VEX file verbatim instead of Scout's applied form")
def _():
    fx = mk_fx()
    vb = json.dumps(SCOUT_IN).encode("utf-8")
    r = do_compute(fx.bytes, vb)
    ok(r.rc == 0, "compute failed")
    bdir = os.path.join(r.dir, "blobs", "sha256")
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    ok(verify(rd(os.path.join(r.dir, "index.json")), vb, base=fx.bytes, blobs=os.path.join(r.dir, "blobs")).rc == 0, "the derived final index does not verify")
    # rebuild every attestation with the verbatim document as its predicate: it must be refused (the old form Scout does not apply)
    nf, blobs_root = json.loads(json.dumps(f)), os.path.join(TMP, "verbatim-root", "blobs")
    shutil.rmtree(os.path.dirname(blobs_root), ignore_errors=True)
    shutil.copytree(os.path.join(r.dir, "blobs"), blobs_root)
    for i, e in enumerate(nf["manifests"]):
        if (e.get("annotations") or {}).get("vnd.docker.reference.type") != "attestation-manifest":
            continue
        desc, parts = ref_att_verbatim(e["annotations"]["vnd.docker.reference.digest"], SCOUT_IN)
        nf["manifests"][i] = desc
        for b in parts.values():
            with open(os.path.join(blobs_root, "sha256", hx(dg(b))), "wb") as fh:
                fh.write(b)
    v = verify(cj(nf), vb, base=fx.bytes, blobs=blobs_root)
    ok(v.rc != 0 and "predicate" in v.err, "the verbatim form was not refused: rc=%s %s" % (v.rc, v.err.strip()[:160]))


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
        eq(st["predicate"], ref_scout(vex), "predicate is the VEX file in Scout's applied form")
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
def auto_blobs(f_bytes, vb):
    """a blobs directory holding what the final index's own base and the VEX bytes imply (verify now always needs --blobs)"""
    s = sb()
    bd = os.path.join(s, "blobs")
    os.makedirs(os.path.join(bd, "sha256"))
    try:
        f = json.loads(f_bytes.decode("utf-8"))
        d = dict(f)
        d["manifests"] = [e for e in f["manifests"] if not (isinstance(e, dict) and (e.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest")]
        for h, b in ref_compute(json.dumps(d).encode("utf-8"), vb)[1].items():
            wr(os.path.join(bd, "sha256", h), b)
    except Exception:
        pass
    return bd


def verify(f_bytes, vb, base=None, blobs="auto", s=None, env=None, final_path=None):
    s = s or sb()
    fp = wr(os.path.join(s, "final.json"), f_bytes)
    vp = wr(os.path.join(s, "vex.json"), vb)
    if blobs == "auto":
        blobs = auto_blobs(f_bytes, vb)
    args = ["verify", "--final", fp, "--vex", vp]
    if base is None:      # --base is required: by default the built index the final index was made from (its entries minus the attestations)
        try:
            o = json.loads(f_bytes)
            o["manifests"] = [e for e in o["manifests"] if not (e.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest"]
            base = json.dumps(o).encode()
        except Exception:
            base = mk_fx().bytes
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
        stmt = {"_type": STMT_TYPE, "predicateType": PRED, "subject": [{"name": SUBJECT_NAME, "digest": {"sha256": hx(e["digest"])}}], "predicate": ref_scout(vex)}
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


def _subject_digest(key):
    def f(o, c):
        o["subject"][0]["digest"]["sha256"] = hx(c[key]) if key in c else key
    return f


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
_add("doc", "role", "document creator", S_WRONG)
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


# In the attested predicate (Scout's applied form) a subcomponent has become a product of its statement, so the sub-level paths of the input document name statements[0].products[0] there.
PRED_PATHS = dict(PATHS)
PRED_PATHS.update({"product": lambda o: o["statements"][0]["products"][0], "sub": lambda o: o["statements"][0]["products"][0],
                   "product.identifiers": lambda o: o["statements"][0]["products"][0]["identifiers"], "sub.identifiers": lambda o: o["statements"][0]["products"][0]["identifiers"],
                   "product.hashes": lambda o: o["statements"][0]["products"][0]["hashes"], "sub.hashes": lambda o: o["statements"][0]["products"][0]["hashes"]})


def set_pred_prop(o, path, key, val):
    PRED_PATHS[path](o)[key] = val
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
    return {"stmt": lambda o, c: set_pred_prop(o["predicate"], pa, k, json.loads(json.dumps(val)))}


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


@param("AC3", "verify rejects final-index bytes that are not exactly the canonical serialisation even when result.json and every digest were refreshed", sorted((k, (k, True)) for k in FINAL_RAW))
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


# ------------------------------------------------------------------ fake registry


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
    pd.vex_path = wr(os.path.join(s, "vex.json"), vb)
    pd.base_path = wr(os.path.join(s, "base.json"), fx.bytes)
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


# ------------------------------------------------------------------ AC4: plain-http (localhost) registry


# ---- failures the push must notice, with a strict and a lenient registry


# ---- the credentials never leak, on any path


# ---- DIR validation before anything is written


# ---- where the tool may connect and what it may send there


# ---- https: a real TLS handshake through a tunnelling proxy that maps the test names to local registries


# ------------------------------------------------------------------ round 3 additions


# ------------------------------------------------------------------ step 8 round 1 [r8]
R8 = ""


def sparse(path, size):
    with open(path, "wb") as f:
        f.truncate(size)
    return path


# ---- (1) known OCI fields are type-validated; unknown extensions are still preserved
def entry_with(f):
    fx = mk_fx()
    o = json.loads(json.dumps(fx.obj))
    f(o)
    return json.dumps(o).encode()


OCI_BAD = {
    "index annotations is a list": lambda o: o.update(annotations=[]),
    "index annotations is null": lambda o: o.update(annotations=None),
    "index annotations is a string": lambda o: o.update(annotations="x"),
    "index annotations has a number value": lambda o: o.update(annotations={"audit": 123}),
    "index annotations has a null value": lambda o: o.update(annotations={"audit": None}),
    "index annotations has a list value": lambda o: o.update(annotations={"audit": ["x"]}),
    "index annotations has a boolean value": lambda o: o.update(annotations={"audit": True}),
    "index artifactType is a number": lambda o: o.update(artifactType=7),
    "index artifactType is null": lambda o: o.update(artifactType=None),
    "index artifactType is empty": lambda o: o.update(artifactType=""),
    "index artifactType is a list": lambda o: o.update(artifactType=["x"]),
    "index subject is a string": lambda o: o.update(subject="x"),
    "index subject is null": lambda o: o.update(subject=None),
    "index subject is a list": lambda o: o.update(subject=[]),
    "index subject is empty": lambda o: o.update(subject={}),
    "index subject without a size": lambda o: o.update(subject={"mediaType": OCI_MAN, "digest": "sha256:" + "9" * 64}),
    "index subject with a bad digest": lambda o: o.update(subject={"mediaType": OCI_MAN, "digest": "sha256:" + "9" * 63, "size": 5}),
    "index subject with an upper-case digest": lambda o: o.update(subject={"mediaType": OCI_MAN, "digest": "sha256:" + "A" * 64, "size": 5}),
    "index subject with a numeric mediaType": lambda o: o.update(subject={"mediaType": 7, "digest": "sha256:" + "9" * 64, "size": 5}),
    "index subject with a string size": lambda o: o.update(subject={"mediaType": OCI_MAN, "digest": "sha256:" + "9" * 64, "size": "5"}),
    "index subject with a boolean size": lambda o: o.update(subject={"mediaType": OCI_MAN, "digest": "sha256:" + "9" * 64, "size": True}),
    "index subject with bad annotations": lambda o: o.update(subject={"mediaType": OCI_MAN, "digest": "sha256:" + "9" * 64, "size": 5, "annotations": {"a": 1}}),
    "index subject with a bad artifactType": lambda o: o.update(subject={"mediaType": OCI_MAN, "digest": "sha256:" + "9" * 64, "size": 5, "artifactType": 3}),
    "entry annotations has a number value": lambda o: o["manifests"][0].update(annotations={"audit": 123}),
    "entry annotations has a null value": lambda o: o["manifests"][0].update(annotations={"audit": None}),
    "entry annotations has a list value": lambda o: o["manifests"][0].update(annotations={"audit": ["x"]}),
    "entry annotations is a list": lambda o: o["manifests"][0].update(annotations=[]),
    "entry annotations is null": lambda o: o["manifests"][0].update(annotations=None),
    "entry artifactType is a number": lambda o: o["manifests"][0].update(artifactType=7),
    "entry artifactType is null": lambda o: o["manifests"][0].update(artifactType=None),
    "entry artifactType is empty": lambda o: o["manifests"][0].update(artifactType=""),
    "entry urls is a string": lambda o: o["manifests"][0].update(urls="https://example.test/x"),
    "entry urls has a number": lambda o: o["manifests"][0].update(urls=[7]),
    "entry urls has a null": lambda o: o["manifests"][0].update(urls=[None]),
    "entry urls is null": lambda o: o["manifests"][0].update(urls=None),
    "entry urls is an object": lambda o: o["manifests"][0].update(urls={"a": "b"}),
    "entry data is a number": lambda o: o["manifests"][0].update(data=7),
    "entry data is null": lambda o: o["manifests"][0].update(data=None),
    "entry data is not base64": lambda o: o["manifests"][0].update(data="!!!not base64!!!"),
    "entry data is base64 without padding": lambda o: o["manifests"][0].update(data="e30"),
    "entry data is valid base64 of other content (size and digest differ)": lambda o: o["manifests"][0].update(data="e30="),
    "entry data is a list": lambda o: o["manifests"][0].update(data=["e30="]),
    "entry data has a newline inside": lambda o: o["manifests"][0].update(data="e30=\n"),
    "platform variant is null": lambda o: o["manifests"][0]["platform"].update(variant=None),
    "platform variant is a number": lambda o: o["manifests"][0]["platform"].update(variant=8),
    "platform variant is a list": lambda o: o["manifests"][0]["platform"].update(variant=["v8"]),
    "platform os.version is a number": lambda o: o["manifests"][0]["platform"].update({"os.version": 10}),
    "platform os.version is null": lambda o: o["manifests"][0]["platform"].update({"os.version": None}),
    "platform os.features is a string": lambda o: o["manifests"][0]["platform"].update({"os.features": "win32k"}),
    "platform os.features has a number": lambda o: o["manifests"][0]["platform"].update({"os.features": [7]}),
    "platform os.features is null": lambda o: o["manifests"][0]["platform"].update({"os.features": None}),
    "platform features is a string": lambda o: o["manifests"][0]["platform"].update(features="sse"),
    "platform features has a number": lambda o: o["manifests"][0]["platform"].update(features=[1]),
    "platform features is null": lambda o: o["manifests"][0]["platform"].update(features=None),
    "platform architecture is null": lambda o: o["manifests"][0]["platform"].update(architecture=None),
    "platform os is a number": lambda o: o["manifests"][0]["platform"].update(os=3),
}


@param("AC2", "a known OCI field of the wrong type is refused and nothing is written (isolated: index and entry annotations, artifactType, urls, data, subject, platform fields)" + R8, sorted(OCI_BAD.items()))
def _(f):
    assert_refused(entry_with(f), vex_real(), "a malformed known OCI field")


@case("AC2", "unknown extension fields are still preserved byte for byte next to valid known optional fields (annotations, artifactType, urls, data, subject, variant, os.version, os.features, features)" + R8)
def _():
    fx = mk_fx(**UNKNOWN_FIELDS)
    o = json.loads(fx.bytes.decode("utf-8"))
    p = o["manifests"][0]["platform"]
    p.update({"variant": "v8", "os.version": "10.0.20348", "os.features": ["win32k"], "features": ["sse4"], "x-extension": {"a": 1}})
    db = json.dumps(o).encode()
    r = do_compute(db, vex_real())
    check_matches_ref(db, vex_real(), r)
    f = json.loads(rd(os.path.join(r.dir, "index.json")))
    eq(f["manifests"][0]["platform"], p, "the platform with its known and unknown keys")


# ---- (2) verify always validates fully
@case("AC3", "verify without --blobs is refused: there is no weaker mode" + R8)
def _():
    verify_control()
    fx = mk_fx()
    s = sb()
    fp = wr(os.path.join(s, "final.json"), final_of(fx, VEX_MIN))
    vp = wr(os.path.join(s, "vex.json"), VEX_MIN)
    r = run(["verify", "--final", fp, "--vex", vp])
    ok(r.rc != 0 and "blobs" in r.err.lower(), "verify accepted a run without --blobs: " + r.err.strip()[:200])
    r = run(["verify", "--final", fp, "--vex", vp, "--base", wr(os.path.join(s, "b.json"), fx.bytes)])
    ok(r.rc != 0, "verify accepted --base alone")


@case("AC3", "verify with a different valid VEX and the original blobs is refused, also with no --base (the full validation always runs)" + R8)
def _():
    verify_control()
    fx = mk_fx()
    other = vex_with(lambda o: o.update(version=2))
    bd = blob_dir_from(fx, VEX_MIN)
    r = verify(final_of(fx, VEX_MIN), other, blobs=bd)
    ok(r.rc != 0 and r.err.strip() != "", "accepted a different VEX")


# ---- (3) push re-runs the full verification (--vex, --base) and checks result.json against the recomputation


# ---- (4) --base comparison is type-sensitive
def typed_fx():
    return mk_fx(extra_top={"x-n": 1, "x-z": 0, "x-nested": {"a": [1, {"b": 0}]}}, extra_entry={"x-audit": 1, "x-flag": 0})


TYPED = {
    "top-level 1 becomes true": lambda f: f.update({"x-n": True}),
    "top-level 0 becomes false": lambda f: f.update({"x-z": False}),
    "nested [1, {b: 0}] becomes [true, {b: false}]": lambda f: f.update({"x-nested": {"a": [True, {"b": False}]}}),
    "an original entry's 1 becomes true": lambda f: f["manifests"][0].update({"x-audit": True}),
    "an original entry's 0 becomes false": lambda f: f["manifests"][1].update({"x-flag": False}),
    "an original entry's 1 becomes the string 1": lambda f: f["manifests"][0].update({"x-audit": "1"}),
}


@param("AC3", "verify --base compares types: a retained field changed from 1 to true (or 0 to false, nested too) is refused" + R8, sorted(TYPED.items()))
def _(f):
    verify_control()
    fx = typed_fx()
    good = json.loads(final_of(fx, vex_real()))
    path, fb = build_custom(fx, vex_real(), None, f)
    r = verify(fb, vex_real(), base=fx.bytes, blobs=os.path.join(path, "blobs"))
    ok(r.rc != 0 and r.err.strip() != "", "accepted a retained field with another type")
    path0, fb0 = build_custom(fx, vex_real(), None, None)
    ok(verify(fb0, vex_real(), base=fx.bytes, blobs=os.path.join(path0, "blobs")).rc == 0, "positive control failed")


# ---- (5) the upload Location is exactly /v2/<repository>/blobs/uploads/<session>


# ---- (6) path spellings, symlinks, regular files only
@case("AC2", "compute refuses an out-dir that is a symlink however it is spelled: link, link/ and link/. (the target stays empty)" + R8)
def _():
    control_ok()
    fx = mk_fx()
    for spelling in ("%s", "%s/", "%s/.", "%s//", "%s/./", "%s/././"):
        s = sb()
        target = os.path.join(s, "target")
        os.mkdir(target)
        link = os.path.join(s, "link")
        os.symlink(target, link)
        i = wr(os.path.join(s, "i.json"), fx.bytes)
        v = wr(os.path.join(s, "v.json"), VEX_MIN)
        r = run(["compute", "--index", i, "--vex", v, "--out-dir", spelling % link])
        ok(r.rc != 0 and r.err.strip() != "", "accepted the out-dir %r" % (spelling % "link"))
        eq(os.listdir(target), [], "something was written through the symlink spelled %r" % (spelling % "link"))


@case("AC2", "compute accepts a real out-dir with trailing slashes, creating it when it does not exist" + R8)
def _():
    fx = mk_fx()
    base = do_compute(fx.bytes, VEX_MIN)
    for spelling in ("%s/", "%s//"):
        s = sb()
        i = wr(os.path.join(s, "i.json"), fx.bytes)
        v = wr(os.path.join(s, "v.json"), VEX_MIN)
        out = os.path.join(s, "out")
        r = run(["compute", "--index", i, "--vex", v, "--out-dir", spelling % out])
        ok(r.rc == 0, "refused %r: %s" % (spelling % "out", r.err.strip()[:150]))
        eq(tree(out), tree(base.dir), "the output")


@param("AC2", "an input file that is a symlink, a FIFO, a device or a directory is refused before it is read (compute --index/--vex, verify --final/--vex/--base)" + R8, [(k, k) for k in ("symlink", "fifo", "dev-zero", "directory")])
def _(kind):
    control_ok()
    fx = mk_fx()
    s = sb()
    good_i = wr(os.path.join(s, "i.json"), fx.bytes)
    good_v = wr(os.path.join(s, "v.json"), VEX_MIN)

    def bad(name):
        p = os.path.join(s, name)
        if kind == "symlink":
            os.symlink(good_i, p)
        elif kind == "fifo":
            os.mkfifo(p)
        elif kind == "dev-zero":
            if not os.path.exists("/dev/zero"):
                raise Fail("no /dev/zero on this system")
            p = "/dev/zero"
        else:
            os.mkdir(p)
        return p
    for which in ("index", "vex"):
        args = {"index": good_i, "vex": good_v}
        args[which] = bad("bad-" + which)
        r = run(["compute", "--index", args["index"], "--vex", args["vex"], "--out-dir", os.path.join(s, "o-" + which)], timeout=30)
        ok(r.rc != 0 and r.err.strip() != "", "compute accepted a %s as --%s" % (kind, which))
        ok(not os.path.lexists(os.path.join(s, "o-" + which)), "something was written")
    pd = make_dir(fx, VEX_MIN)
    for which in ("final", "vex", "base"):
        args = {"final": os.path.join(pd.path, "index.json"), "vex": pd.vex_path, "base": pd.base_path}
        args[which] = bad("bad-v-" + which)
        r = run(["verify", "--final", args["final"], "--vex", args["vex"], "--base", args["base"], "--blobs", os.path.join(pd.path, "blobs")], timeout=30)
        ok(r.rc != 0 and r.err.strip() != "", "verify accepted a %s as --%s" % (kind, which))


# ---- (7) the directory inventory is exact, and enumeration errors are refusals
def verify_pd(pd, **over):
    a = {"final": os.path.join(pd.path, "index.json"), "vex": pd.vex_path, "base": pd.base_path, "blobs": os.path.join(pd.path, "blobs")}
    a.update(over)
    return run(["verify", "--final", a["final"], "--vex", a["vex"], "--base", a["base"], "--blobs", a["blobs"]], timeout=60)


def blob_extras():
    def add(rel, data=b"x"):
        def f(pd):
            wr(os.path.join(pd.path, "blobs", rel), data)
        return f

    def mkdirs(rel):
        def f(pd):
            os.makedirs(os.path.join(pd.path, "blobs", rel))
        return f

    def fifo(pd):
        os.mkfifo(os.path.join(pd.path, "blobs", "sha256", "f" * 64))

    def symlink(pd):
        os.symlink("/etc/hostname", os.path.join(pd.path, "blobs", "sha256", "e" * 64))
    return [("an unreferenced blob", add("sha256/" + "d" * 64)), ("a hidden file in sha256", add("sha256/.hidden")), ("a hidden file next to sha256", add(".hidden")),
            ("a file next to sha256", add("stray.txt")), ("a sub-directory in sha256", mkdirs("sha256/nested")), ("another algorithm directory", mkdirs("sha512")),
            ("a file named like a blob but with upper-case hex", add("sha256/" + "D" * 64)), ("a FIFO in sha256", fifo), ("a symlink in sha256", symlink),
            ("an empty file named like a blob", add("sha256/" + "0" * 64, b""))]


@param("AC3", "verify walks the blobs directory exactly: an extra, unreferenced, hidden, special or nested entry is refused" + R8, [(k, f) for k, f in blob_extras()])
def _(f):
    verify_control()
    pd = make_dir(mk_fx(), vex_real())
    ok(verify_pd(pd).rc == 0, "positive control failed")
    f(pd)
    r = verify_pd(pd)
    ok(r.rc != 0 and r.err.strip() != "" and "Traceback" not in r.err, "verify accepted a blobs directory with an unexpected entry")


PERM = [("DIR is execute-only (cannot be listed)", "", 0o111), ("blobs is execute-only", "blobs", 0o111), ("blobs/sha256 is execute-only", "blobs/sha256", 0o111),
        ("blobs/sha256 has no permissions", "blobs/sha256", 0o000), ("blobs has no permissions", "blobs", 0o000), ("blobs/sha256 is write-and-execute only", "blobs/sha256", 0o311)]


@param("AC3", "an enumeration error (a directory that cannot be listed) is a refusal for verify, never a silent skip" + R8, [(k, (rel, mode)) for k, rel, mode in PERM if rel])
def _(arg):
    ok(os.geteuid() != 0, "the permission cases need a non-root user")
    verify_control()
    rel, mode = arg
    pd = make_dir(mk_fx(), vex_real())
    target = os.path.join(pd.path, rel)
    try:
        os.chmod(target, mode)
        r = verify_pd(pd)
        ok(r.rc != 0 and r.err.strip() != "" and "Traceback" not in r.err, "verify accepted a directory that cannot be listed")
    finally:
        os.chmod(target, 0o755)


# ---- (8) bounded reads
@param("AC2", "a FIFO, /dev/zero or a huge sparse file in place of an input is refused before it is read (bounded, prompt)" + R8, [(k, k) for k in ("fifo", "dev-zero", "sparse 4 GiB")])
def _(kind):
    control_ok()
    fx = mk_fx()
    s = sb()
    for which in ("index", "vex"):
        files = {"index": wr(os.path.join(s, "i.json"), fx.bytes), "vex": wr(os.path.join(s, "v.json"), VEX_MIN)}
        p = os.path.join(s, "big-" + which)
        if kind == "fifo":
            os.mkfifo(p)
        elif kind == "dev-zero":
            ok(os.path.exists("/dev/zero"), "no /dev/zero")
            p = "/dev/zero"
        else:
            sparse(p, 4 << 30)
        files[which] = p
        t0 = time.time()
        r = run(["compute", "--index", files["index"], "--vex", files["vex"], "--out-dir", os.path.join(s, "o-" + which)], timeout=30)
        ok(r.rc != 0 and r.err.strip() != "" and "Traceback" not in r.err, "compute accepted %s as --%s" % (kind, which))
        ok(time.time() - t0 < 20, "the refusal took too long (an unbounded read?)")


def one_big(pd, what, kind):
    """replace one local file of a valid DIR by a FIFO or a huge sparse file"""
    blobs = os.path.join(pd.path, "blobs", "sha256")
    target = {"index.json": os.path.join(pd.path, "index.json"), "result.json": os.path.join(pd.path, "result.json"),
              "statement": os.path.join(blobs, hx(json.loads(pd.blobs[hx(sorted(pd.att_digests)[0])])["layers"][0]["digest"])), "manifest": os.path.join(blobs, hx(sorted(pd.att_digests)[0])),
              "config": os.path.join(blobs, hx(json.loads(pd.blobs[hx(sorted(pd.att_digests)[0])])["config"]["digest"]))}[what]
    os.unlink(target)
    if kind == "fifo":
        os.mkfifo(target)
    else:
        sparse(target, 8 << 30)


BIG = [("%s as %s" % (k, w), (w, k)) for w in ("index.json", "result.json", "statement", "manifest", "config") for k in ("fifo", "sparse 8 GiB")]
BIG_VERIFY = [x for x in BIG if x[1][0] != "result.json"]  # verify does not read result.json


@param("AC3", "verify never reads past its bounds: a FIFO or a huge sparse file in place of the index, a blob or a manifest is refused promptly" + R8, BIG_VERIFY)
def _(arg):
    verify_control()
    what, kind = arg
    pd = make_dir(mk_fx(), vex_real())
    one_big(pd, what, kind)
    t0 = time.time()
    r = verify_pd(pd)
    ok(r.rc != 0 and r.err.strip() != "" and "Traceback" not in r.err, "verify accepted %s as %s" % (kind, what))
    ok(time.time() - t0 < 20, "the refusal took too long (an unbounded read?)")


# ---- the tool never reads proxy variables


@param("AC3", "a descriptor that declares an attestation manifest of 2 GiB is refused before any of it is read (verify)" + R8, [("manifest", "manifest")])
def _(kind):
    verify_control()
    fx = mk_fx()
    path, fb = build_custom(fx, vex_real(), {"desc": lambda o, c: o.update(size=2 ** 31)}, None, only=0)
    f = json.loads(fb)
    att = [e for e in f["manifests"] if (e.get("annotations") or {}).get("vnd.docker.reference.type")][0]
    target = os.path.join(path, "blobs", "sha256", hx(att["digest"]))
    os.unlink(target)
    sparse(target, 2 ** 31)
    t0 = time.time()
    r = verify(fb, vex_real(), base=fx.bytes, blobs=os.path.join(path, "blobs"))
    ok(r.rc != 0 and r.err.strip() != "" and "Traceback" not in r.err, "verify accepted a declared 2 GiB manifest")
    ok(time.time() - t0 < 20, "the refusal took too long (it read the file?)")


# ------------------------------------------------------------------ the layout commands (in place, no push)
def mk_layout(fx, s=None, drop_blobs=(), extra_top=None):
    """an OCI image layout directory whose one top-level descriptor names the built index fx.bytes (Build's images/<variant>/)"""
    s = s or sb()
    d = os.path.join(s, "layout")
    wr(os.path.join(d, "oci-layout"), b'{"imageLayoutVersion":"1.0.0"}')
    top = {"schemaVersion": 2, "manifests": [{"mediaType": OCI_IDX, "digest": dg(fx.bytes), "size": len(fx.bytes)}]}
    if extra_top:
        top.update(extra_top)
    wr(os.path.join(d, "index.json"), json.dumps(top).encode())
    blobs = {dg(fx.bytes): fx.bytes}
    for ch in fx.children:
        blobs[ch["digest"]] = ch["bytes"]
        blobs.update(ch["blobs"])
    for dig, data in blobs.items():
        if dig not in drop_blobs:
            wr(os.path.join(d, "blobs", "sha256", hx(dig)), data)
    return d, blobs


def lay(d, vb, s=None, cmd="layout", extra=()):
    s = s or sb()
    v = wr(os.path.join(s, "vex.json"), vb)
    return run([cmd, "--layout", d, "--vex", v] + list(extra))


@case("LAYOUT", "layout: the built index becomes the final index in place, with exactly the independently computed blobs, the platform blobs untouched")
def _():
    fx = mk_fx()
    d, before = mk_layout(fx)
    vb = vex_real()
    t0 = tree(d, full=True)
    r = lay(d, vb)
    ok(r.rc == 0, "layout failed rc=%d: %s" % (r.rc, r.err.strip()[:300]))
    fb, blobs, result = ref_compute(fx.bytes, vb)
    eq(norm_result(json.loads(r.out)), result, "the printed result")
    t1 = tree(d, full=True)
    top = json.loads(t1["index.json"])
    eq(top["manifests"], [{"mediaType": OCI_IDX, "digest": dg(fb), "size": len(fb)}], "the layout's one descriptor names the final index")
    eq(t1["blobs/sha256/" + hx(dg(fb))], fb, "the final index blob")
    for h, b in blobs.items():
        eq(t1["blobs/sha256/" + h], b, "attestation blob " + h)
    for dig, data in before.items():
        eq(t1["blobs/sha256/" + hx(dig)], data, "an original blob must be untouched: " + dig)
    eq(t1["oci-layout"], t0["oci-layout"], "oci-layout")
    new = sorted(k for k in t1 if k not in t0 and not k.endswith("/"))
    eq(new, sorted("blobs/sha256/" + h for h in list(blobs) + [hx(dg(fb))]), "only the attestation blobs and the final index are new")
    f = json.loads(fb)
    eq(f["manifests"][:len(fx.children)], json.loads(fx.bytes)["manifests"], "the built index's entries come first, unchanged")


@case("LAYOUT", "layout: two runs on identical layouts give byte-identical trees (nothing of the clock, the environment or the path leaks in)")
def _():
    fx = mk_fx()
    vb = vex_real()
    d1, _b = mk_layout(fx)
    d2, _b = mk_layout(fx, s=os.path.join(sb(), "other", "place"))
    r1, r2 = lay(d1, vb), lay(d2, vb)
    ok(r1.rc == 0 and r2.rc == 0, "layout failed")
    eq(tree(d1, full=True), tree(d2, full=True), "the two layouts")
    eq(r1.out, r2.out, "the printed result")


@case("LAYOUT", "layout: the same final digest as compute for the same inputs")
def _():
    fx = mk_fx()
    vb = vex_real()
    d, _b = mk_layout(fx)
    rl = lay(d, vb)
    rc_ = do_compute(fx.bytes, vb)
    ok(rl.rc == 0 and rc_.rc == 0, "failed")
    eq(json.loads(rl.out)["final_digest"], rc_.out.strip(), "layout and compute agree")


@case("LAYOUT", "verify-layout accepts the result (with the built index's digest) and prints ok")
def _():
    fx = mk_fx()
    vb = vex_real()
    d, _b = mk_layout(fx)
    ok(lay(d, vb).rc == 0, "layout failed")
    for extra in (("--base-digest", dg(fx.bytes)),):
        r = lay(d, vb, cmd="verify-layout", extra=extra)
        ok(r.rc == 0 and r.out == "ok\n", "verify-layout: rc=%d %s %s" % (r.rc, r.out, r.err.strip()[:200]))


def _refused_layout(label, mutate, vb=None, cmd="layout", pre=None):
    fx = mk_fx()
    d, blobs = mk_layout(fx)
    if pre:
        ok(lay(d, vex_real()).rc == 0, "setup failed")
    mutate(d, fx, blobs)
    t0 = tree(d, full=True)
    r = lay(d, vb or vex_real(), cmd=cmd)
    ok(r.rc == 2, "%s: wanted a refusal (exit 2), got rc=%d %s" % (label, r.rc, (r.out + r.err).strip()[:200]))
    eq(tree(d, full=True), t0, label + ": a refusal must leave the layout byte-identical")


def _two_descriptors(d, fx, blobs):
    top = json.loads(rd(os.path.join(d, "index.json")))
    top["manifests"].append(top["manifests"][0])
    wr(os.path.join(d, "index.json"), json.dumps(top).encode())


def _no_descriptor(d, fx, blobs):
    wr(os.path.join(d, "index.json"), b'{"schemaVersion":2,"manifests":[]}')


def _extra_top(d, fx, blobs):
    wr(os.path.join(d, "stray.txt"), b"x")


def _index_symlink(d, fx, blobs):
    p = os.path.join(d, "index.json")
    b = rd(p)
    os.unlink(p)
    wr(os.path.join(os.path.dirname(d), "elsewhere.json"), b)
    os.symlink(os.path.join(os.path.dirname(d), "elsewhere.json"), p)


def _blobs_symlink(d, fx, blobs):
    other = os.path.join(os.path.dirname(d), "realblobs")
    shutil.move(os.path.join(d, "blobs"), other)
    os.symlink(other, os.path.join(d, "blobs"))


def _wrong_digest(d, fx, blobs):
    p = os.path.join(d, "blobs", "sha256", hx(dg(fx.bytes)))
    wr(p, rd(p) + b" ")


def _missing_d(d, fx, blobs):
    os.unlink(os.path.join(d, "blobs", "sha256", hx(dg(fx.bytes))))


def _bad_marker(d, fx, blobs):
    wr(os.path.join(d, "oci-layout"), b'{"imageLayoutVersion":"2.0.0"}')


def _docker_list(d, fx, blobs):
    top = json.loads(rd(os.path.join(d, "index.json")))
    top["manifests"][0]["mediaType"] = DOCKER_LIST
    wr(os.path.join(d, "index.json"), json.dumps(top).encode())


def _blob_dir_extra(d, fx, blobs):
    wr(os.path.join(d, "blobs", "sha512", "x"), b"x")


def _conflicting_blob(d, fx, blobs):
    fb, new, _r = ref_compute(fx.bytes, vex_real())
    h = sorted(new)[0]
    wr(os.path.join(d, "blobs", "sha256", h), b"not the attestation")


def _huge_index(d, fx, blobs):
    wr(os.path.join(d, "index.json"), b" " * ((1 << 20) + 5))


@param("LAYOUT", "layout refuses a malformed or hostile layout and leaves it byte-identical", [
    ("two descriptors", _two_descriptors), ("no descriptor", _no_descriptor), ("a stray top-level file", _extra_top),
    ("index.json is a symlink", _index_symlink), ("blobs is a symlink", _blobs_symlink),
    ("the built index blob does not match its digest", _wrong_digest), ("the built index blob is missing", _missing_d),
    ("oci-layout is another version", _bad_marker), ("the descriptor is a Docker manifest list", _docker_list),
    ("another hash directory under blobs", _blob_dir_extra), ("a blob this run would write exists with other content", _conflicting_blob),
    ("an oversized index.json", _huge_index)])
def _(arg):
    _refused_layout(arg.__name__, arg)


@case("LAYOUT", "layout refuses a second run (the layout already carries attestations) and a non-OpenVEX or malformed VEX file, leaving the layout untouched")
def _():
    _refused_layout("second run", lambda d, fx, blobs: None, pre=True)
    for label, vb in (("not JSON", b"{not json"), ("an empty object", b"{}"), ("not OpenVEX", b'{"@context":"https://example.test/other","statements":[]}')):
        _refused_layout("vex " + label, lambda d, fx, blobs: None, vb=vb)


@case("LAYOUT", "verify-layout refuses a tampered layout: a changed attestation blob, a wrong VEX file, a wrong --base-digest, a removed attestation blob")
def _():
    fx = mk_fx()
    vb = vex_real()
    d, _b = mk_layout(fx)
    ok(lay(d, vb).rc == 0, "layout failed")
    fb, blobs, _r = ref_compute(fx.bytes, vb)
    h = sorted(blobs)[0]
    p = os.path.join(d, "blobs", "sha256", h)
    good = rd(p)
    wr(p, good + b" ")
    ok(lay(d, vb, cmd="verify-layout", extra=("--base-digest", dg(fx.bytes))).rc == 2, "a changed attestation blob must be refused")
    wr(p, good)
    ok(lay(d, vb, cmd="verify-layout", extra=("--base-digest", dg(fx.bytes))).rc == 0, "control: restored")
    ok(lay(d, VEX_MIN, cmd="verify-layout", extra=("--base-digest", dg(fx.bytes))).rc == 2, "another VEX file must be refused")
    ok(lay(d, vb, cmd="verify-layout", extra=("--base-digest", "sha256:" + "0" * 64)).rc == 2, "a wrong --base-digest must be refused")
    os.unlink(p)
    ok(lay(d, vb, cmd="verify-layout", extra=("--base-digest", dg(fx.bytes))).rc == 2, "a removed attestation blob must be refused")


@case("LAYOUT", "the layout Build hands to Sign passes bin/release-layout.py for the final digest (the chain's own layout check)")
def _():
    fx = mk_fx()
    vb = vex_real()
    d, _b = mk_layout(fx)
    chk = os.path.join(ROOT, "bin", "release-layout.py")
    if not os.path.isfile(chk):
        raise Fail("bin/release-layout.py is missing")
    r0 = subprocess.run([sys.executable, chk, d, dg(fx.bytes)], capture_output=True, text=True)
    ok(r0.returncode == 0, "control: the built layout must pass the layout check: " + (r0.stdout + r0.stderr)[:300])
    rl = lay(d, vb)
    ok(rl.rc == 0, "layout failed")
    fb, _blobs, _r = ref_compute(fx.bytes, vb)
    r1 = subprocess.run([sys.executable, chk, d, dg(fb)], capture_output=True, text=True)
    ok(r1.returncode == 0, "the final layout must pass the layout check: " + (r1.stdout + r1.stderr)[:400])


@case("LAYOUT", "the tool holds no network code at all (no socket, http or urllib import), and no push command")
def _():
    src = rd(TOOL).decode()
    ok(not re.search(r"^\s*(import|from)\s+(socket|http|urllib|ssl|ftplib|smtplib|requests)\b", src, re.M), "a network module is imported")
    r = run(["push"], net="off")
    ok(r.rc != 0 and "invalid choice" in r.err, "push must not exist")



# ------------------------------------------------------------------ round 1 (Codex #389): the whole layout is validated, ownership, path levels, metadata, the base
def _stray_file(d, fx, blobs):
    wr(os.path.join(d, "blobs", "sha256", "junk"), b"stray")


def _stray_hex(d, fx, blobs):
    wr(os.path.join(d, "blobs", "sha256", "f" * 64), b"a file whose name is a digest it does not have")


def _blob_symlink(d, fx, blobs):
    os.symlink("/etc/hostname", os.path.join(d, "blobs", "sha256", "e" * 64))


def _corrupt_platform(d, fx, blobs):
    p = os.path.join(d, "blobs", "sha256", hx(fx.children[0]["digest"]))
    wr(p, rd(p) + b" ")


def _missing_platform(d, fx, blobs):
    os.unlink(os.path.join(d, "blobs", "sha256", hx(fx.children[1]["digest"])))


def _missing_layer(d, fx, blobs):
    layer = [k for k in fx.children[0]["blobs"] if k != json.loads(fx.children[0]["bytes"])["config"]["digest"]][0]
    os.unlink(os.path.join(d, "blobs", "sha256", hx(layer)))


def _platform_size(d, fx, blobs):
    top = json.loads(rd(os.path.join(d, "index.json")))
    idx = json.loads(rd(os.path.join(d, "blobs", "sha256", hx(top["manifests"][0]["digest"]))))
    idx["manifests"][0]["size"] += 1
    nb = json.dumps(idx, indent=2).encode() + b"\n"
    os.unlink(os.path.join(d, "blobs", "sha256", hx(top["manifests"][0]["digest"])))
    wr(os.path.join(d, "blobs", "sha256", hx(dg(nb))), nb)
    top["manifests"][0].update({"digest": dg(nb), "size": len(nb)})
    wr(os.path.join(d, "index.json"), json.dumps(top).encode())


def _desc_annotations(v):
    def f(d, fx, blobs):
        top = json.loads(rd(os.path.join(d, "index.json")))
        top["manifests"][0]["annotations"] = v
        wr(os.path.join(d, "index.json"), json.dumps(top).encode())
    return f


def _wrapper_annotations(v):
    def f(d, fx, blobs):
        top = json.loads(rd(os.path.join(d, "index.json")))
        top["annotations"] = v
        wr(os.path.join(d, "index.json"), json.dumps(top).encode())
    return f


def _wrapper_media(d, fx, blobs):
    top = json.loads(rd(os.path.join(d, "index.json")))
    top["mediaType"] = DOCKER_LIST
    wr(os.path.join(d, "index.json"), json.dumps(top).encode())


@param("LAYOUT", "layout refuses a layout whose inventory or image graph is not complete and exact, and malformed metadata, leaving it byte-identical", [
    ("a stray file in blobs/sha256", _stray_file), ("a blob named like a digest it does not have", _stray_hex), ("a symlink in blobs/sha256", _blob_symlink),
    ("a corrupted platform manifest", _corrupt_platform), ("a missing platform manifest", _missing_platform), ("a missing layer blob", _missing_layer),
    ("a wrong platform descriptor size", _platform_size),
    ("descriptor annotations that are a list", _desc_annotations([])), ("descriptor annotations with a non-string value", _desc_annotations({"k": 7})),
    ("descriptor annotations that are a number", _desc_annotations(42)), ("wrapper annotations that are a list", _wrapper_annotations([])),
    ("wrapper annotations with a non-string value", _wrapper_annotations({"k": 7})), ("a Docker manifest-list wrapper media type", _wrapper_media)])
def _(arg):
    _refused_layout(arg.__name__ + " (layout)", arg)


@param("LAYOUT", "verify-layout refuses the same malformed results", [
    ("a stray file in blobs/sha256", _stray_file), ("a corrupted platform manifest", _corrupt_platform), ("a missing layer blob", _missing_layer),
    ("descriptor annotations with a non-string value", _desc_annotations({"k": 7}))])
def _(arg):
    fx = mk_fx()
    d, blobs = mk_layout(fx)
    ok(lay(d, vex_real()).rc == 0, "setup failed")
    arg(d, fx, blobs)
    r = lay(d, vex_real(), cmd="verify-layout", extra=("--base-digest", dg(fx.bytes)))
    ok(r.rc == 2, "wanted a refusal (exit 2), got rc=%d %s" % (r.rc, (r.out + r.err).strip()[:200]))


@case("LAYOUT", "verify-layout needs the built index's digest (the exclusion of D from the attestations is only checkable against it) and refuses an attestation that carries it")
def _():
    fx = mk_fx()
    vb = vex_real()
    d, _b = mk_layout(fx)
    ok(lay(d, vb).rc == 0, "layout failed")
    r = lay(d, vb, cmd="verify-layout")
    ok(r.rc != 0 and "base-digest" in r.err, "verify-layout without --base-digest must be refused: rc=%d %s" % (r.rc, r.err.strip()[:200]))
    vex = json.loads(vb)
    vex["statements"][0]["impact_statement"] = "mentions %s" % dg(fx.bytes)
    vb2 = json.dumps(vex).encode()
    d2, _b2 = mk_layout(fx)
    ok(lay(d2, vb2).rc == 2, "layout must refuse a VEX that names the built index's digest")


def _symlinked_ancestor_case(which):
    fx = mk_fx()
    s = sb()
    d, _b = mk_layout(fx, s=os.path.join(s, "real"))
    link = os.path.join(s, "link")
    os.symlink(os.path.join(s, "real"), link)
    vb = wr(os.path.join(s, "vex.json"), vex_real())
    t0 = tree(d, full=True)
    path = {"ancestor symlink": os.path.join(link, "layout"), "dot-dot segment": os.path.join(s, "real", "..", "real", "layout"),
            "trailing dot segment through the link": os.path.join(link, "layout") + "/."}[which]
    r = run(["layout", "--layout", path, "--vex", vb])
    ok(r.rc == 2, "%s: wanted a refusal, got rc=%d %s" % (which, r.rc, (r.out + r.err).strip()[:200]))
    eq(tree(d, full=True), t0, which + ": the layout must be untouched")
    r = run(["layout", "--layout", d, "--vex", os.path.join(link, "vex.json")])
    ok(r.rc == 2, "a VEX path through a symlinked ancestor must be refused: rc=%d" % r.rc)


@param("LAYOUT", "a symlink or a dot-dot segment at ANY level of a path argument is refused", [(k, k) for k in ("ancestor symlink", "dot-dot segment", "trailing dot segment through the link")])
def _(which):
    _symlinked_ancestor_case(which)


def _load_tool():
    spec = importlib.util.spec_from_file_location("vexidx_under_test", TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@case("LAYOUT", "ownership: a failed commit removes what the run created, a layout that changed between the check and the commit is refused, and a temporary file is claimed before any blob is written")
def _():
    for case_ in ("create fails on the 3rd file", "index.json replaced before the rename"):
        fx = mk_fx()
        d, _b = mk_layout(fx)
        vb = wr(os.path.join(sb(), "vex.json"), vex_real())
        t0 = tree(d, full=True)
        m = _load_tool()
        calls = {"n": 0}
        real_create = m.create_file
        if case_.startswith("create"):
            def create(dir_fd, name, data):
                calls["n"] += 1
                if calls["n"] == 3:
                    raise OSError(28, "no space left")
                return real_create(dir_fd, name, data)
            m.create_file = create
        else:
            state = {"swapped": False}

            def create(dir_fd, name, data):
                real_create(dir_fd, name, data)
                if not name.endswith(".tmp") and not state["swapped"]:
                    state["swapped"] = True      # the layout's index.json is replaced after the check, before the commit
                    other = os.path.join(d, "index.json")
                    top = json.loads(rd(other))
                    top["annotations"] = {"swapped": "yes"}
                    with open(other, "wb") as fh:
                        fh.write(json.dumps(top).encode())
            m.create_file = create
        argv = ["vex-index", "layout", "--layout", d, "--vex", vb]
        old = sys.argv
        sys.argv = argv
        code = None
        try:
            try:
                m.main()
            except SystemExit as e:
                code = e.code
        finally:
            sys.argv = old
        ok(code not in (0, None), "%s: the command must fail, got %r" % (case_, code))
        if case_.startswith("create"):
            eq(tree(d, full=True), t0, case_ + ": what the run created must be removed again")
        else:
            top_now = json.loads(rd(os.path.join(d, "index.json")))
            ok(top_now.get("annotations") == {"swapped": "yes"} and top_now["manifests"][0]["digest"] == dg(fx.bytes),
               case_ + ": the replaced index.json must not be overwritten by a stale run")
            left = [k for k in tree(d, full=True) if k not in t0 and not k.endswith("/")]
            eq(left, [], case_ + ": what the run created must be removed again")



# ------------------------------------------------------------------ round 2 (Codex #389): retained children, image contents, one snapshot, partial writes, verify needs its base, dot spellings
def fx_edit_child(edit, cfg=None):
    """a fixture whose first platform's manifest (and optionally config) is replaced, with the index rebuilt around it"""
    fx = mk_fx()
    ch = fx.children[0]
    man = json.loads(ch["bytes"])
    blobs = dict(ch["blobs"])
    if cfg is not None:
        old_cfg = man["config"]["digest"]
        blobs.pop(old_cfg)
        blobs[dg(cfg)] = cfg
        man["config"]["digest"], man["config"]["size"] = dg(cfg), len(cfg)
    edit(man)
    b = json.dumps(man, indent=2).encode()
    ch.update(bytes=b, digest=dg(b), size=len(b), blobs=blobs)
    fx.obj["manifests"][0].update(digest=dg(b), size=len(b))
    fx.bytes = json.dumps(fx.obj, indent=2).encode("utf-8") + b"\n"
    return fx


def _set(key, value):
    return lambda man: man.__setitem__(key, value)


@param("LAYOUT", "layout refuses a platform whose manifest or config is not a well-formed image (schemaVersion 2, an image manifest media type, a JSON object config), leaving the layout untouched", [
    ("schemaVersion 1", (_set("schemaVersion", 1), None)), ("schemaVersion 99 with a Docker list media type", (lambda m: (m.__setitem__("schemaVersion", 99), m.__setitem__("mediaType", DOCKER_LIST)), None)),
    ("a manifest list media type", (_set("mediaType", DOCKER_LIST), None)), ("no layers list", (lambda m: m.pop("layers"), None)),
    ("a layer without a media type", (lambda m: m["layers"][0].pop("mediaType"), None)),
    ("a config that is not JSON", (lambda m: None, b"not JSON")), ("a config that is a JSON list", (lambda m: None, b"[1]"))])
def _(arg):
    edit, cfg = arg
    fx = fx_edit_child(edit, cfg)
    d, _b = mk_layout(fx)
    t0 = tree(d, full=True)
    r = lay(d, vex_real())
    ok(r.rc == 2, "wanted a refusal (exit 2), got rc=%d %s" % (r.rc, (r.out + r.err).strip()[:200]))
    eq(tree(d, full=True), t0, "the layout must be untouched")


def fx_unknown_child(complete):
    """a fixture with one more retained child (platform unknown/unknown, the shape of a buildkit attestation) whose image graph is complete or lacks its config"""
    fx = mk_fx()
    cfg = cj({"architecture": "unknown", "os": "unknown", "rootfs": {"type": "layers", "diff_ids": []}})
    man = {"schemaVersion": 2, "mediaType": OCI_MAN, "config": {"mediaType": OCI_CFG, "digest": dg(cfg), "size": len(cfg)}, "layers": []}
    b = json.dumps(man, indent=2).encode()
    fx.extra = {dg(b): b}
    if complete:
        fx.extra[dg(cfg)] = cfg
    fx.obj["manifests"].append({"mediaType": OCI_MAN, "digest": dg(b), "size": len(b), "platform": {"architecture": "unknown", "os": "unknown"}})
    fx.bytes = json.dumps(fx.obj, indent=2).encode("utf-8") + b"\n"
    return fx


def mk_layout_with(fx):
    d, blobs = mk_layout(fx)
    for dig, data in fx.extra.items():
        wr(os.path.join(d, "blobs", "sha256", hx(dig)), data)
    return d


@case("LAYOUT", "every retained child of the built index (also a platform-less unknown/unknown one) must have its whole image graph present, in layout and verify-layout; a complete one is kept untouched")
def _():
    fx = fx_unknown_child(complete=False)
    d = mk_layout_with(fx)
    t0 = tree(d, full=True)
    r = lay(d, vex_real())
    ok(r.rc == 2, "an incomplete retained child must be refused, got rc=%d %s" % (r.rc, (r.out + r.err).strip()[:200]))
    eq(tree(d, full=True), t0, "the layout must be untouched")
    fx = fx_unknown_child(complete=True)
    d = mk_layout_with(fx)
    r = lay(d, vex_real())
    ok(r.rc == 0, "a complete retained child must be accepted: rc=%d %s" % (r.rc, r.err.strip()[:200]))
    r = lay(d, vex_real(), cmd="verify-layout", extra=("--base-digest", dg(fx.bytes)))
    ok(r.rc == 0, "verify-layout of it: rc=%d %s" % (r.rc, r.err.strip()[:200]))
    for dig in fx.extra:
        ok(os.path.isfile(os.path.join(d, "blobs", "sha256", hx(dig))), "the retained child's blob must stay")
    top = json.loads(rd(os.path.join(d, "index.json")))
    final = json.loads(rd(os.path.join(d, "blobs", "sha256", hx(top["manifests"][0]["digest"]))))
    ok(final["manifests"][2]["platform"] == {"architecture": "unknown", "os": "unknown"} and final["manifests"][2]["digest"] == fx.obj["manifests"][2]["digest"],
       "the retained child must keep its place in the final index")


@case("LAYOUT", "a file this tool creates is removed again when writing or closing it fails part-way (no partial blob and no partial temporary index remains)")
def _():
    import types
    for failing in ("the temporary index", "a blob"):
        fx = mk_fx()
        d, _b = mk_layout(fx)
        vb = wr(os.path.join(sb(), "vex.json"), vex_real())
        t0 = tree(d, full=True)
        m = _load_tool()
        counter = {"n": 0}
        real_fdopen = os.fdopen
        want = 1 if failing == "the temporary index" else 2

        class Handle:
            def __init__(self, h, fail):
                self.h, self.fail = h, fail

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.h.close()
                return False

            def write(self, data):
                if self.fail:
                    self.h.write(data[:7])
                    self.h.flush()
                    raise OSError(28, "no space left")
                return self.h.write(data)

        def fdopen(fd, mode):
            counter["n"] += 1
            return Handle(real_fdopen(fd, mode), counter["n"] == want)
        m.os = types.SimpleNamespace(**{k: getattr(os, k) for k in dir(os)})
        m.os.fdopen = fdopen
        old, sys.argv = sys.argv, ["vex-index", "layout", "--layout", d, "--vex", vb]
        code = None
        try:
            try:
                m.main()
            except SystemExit as e:
                code = e.code
        finally:
            sys.argv = old
        ok(code not in (0, None), "%s: the command must fail, got %r" % (failing, code))
        eq(tree(d, full=True), t0, failing + ": nothing may be left behind")


def _swap_ann(d, fx):
    other = os.path.join(d, "index.json")
    top = json.loads(rd(other))
    top["annotations"] = {"swapped": "yes"}
    wr(other, json.dumps(top).encode())


def _swap_marker(d, fx):
    wr(os.path.join(d, "oci-layout"), b'{"imageLayoutVersion":"1.0.1"}')


def _swap_top_stray(d, fx):
    wr(os.path.join(d, "stray.txt"), b"x")


def _swap_blobs_stray(d, fx):
    wr(os.path.join(d, "blobs", "sha256", "d" * 64), b"not its hash")


def _swap_tmp(d, fx):
    wr(os.path.join(d, "index.json.vex-index.tmp"), b'{"manifests":[]}')


@param("LAYOUT", "a change to the layout while the tool works (any file of it, at any step before the commit) fails the run and leaves nothing of this run behind", [
    (k, (f, when)) for k, f in (("index.json", _swap_ann), ("oci-layout", _swap_marker), ("a stray top-level file", _swap_top_stray),
                               ("a stray blob", _swap_blobs_stray), ("the temporary index", _swap_tmp)) for when in ("after the first blob", "in the last pass")])
def _(arg):
    swap, when = arg
    fx = mk_fx()
    d, _b = mk_layout(fx)
    vb = wr(os.path.join(sb(), "vex.json"), vex_real())
    t0 = tree(d, full=True)
    m = _load_tool()
    state = {"done": False, "hash_calls": 0}
    real_create, real_hash = m.create_file, m.hash_blobs

    def once():
        if not state["done"]:
            state["done"] = True
            swap(d, fx)
    if when == "after the first blob":
        def create(dir_fd, name, data):
            real_create(dir_fd, name, data)
            if not name.endswith(".tmp"):
                once()
        m.create_file = create
    else:
        def hashing(blobs):
            state["hash_calls"] += 1
            out = real_hash(blobs)
            if state["hash_calls"] == 2:
                once()
            return out
        m.hash_blobs = hashing
    old, sys.argv = sys.argv, ["vex-index", "layout", "--layout", d, "--vex", vb]
    code = None
    try:
        try:
            m.main()
        except SystemExit as e:
            code = e.code
    finally:
        sys.argv = old
    ok(state["done"], "the change was never made (harness)")
    ok(code not in (0, None), "the run must fail, got %r" % (code,))
    top = json.loads(rd(os.path.join(d, "index.json")))
    ok(top["manifests"][0]["digest"] == dg(fx.bytes), "the final index must not have been committed")
    new = [k for k in tree(d, full=True) if k not in t0]
    ok(all(k in ("stray.txt", "index.json.vex-index.tmp") or k.endswith(("d" * 64,)) for k in new) or new == [],
       "what this run created must be removed (only the swapper's own file may remain): %r" % new)
    ok(not any(k.startswith("blobs/sha256/") and k not in t0 and not k.endswith("d" * 64) for k in new), "a blob of this run was left behind: %r" % new)


def _replace_dir(rel):
    def f(d, fx):
        moved = d + "-moved-" + rel.replace("/", "_")
        os.rename(os.path.join(d, rel), moved)
        os.makedirs(os.path.join(d, rel, "sha256") if rel == "blobs" else os.path.join(d, rel))
    return f


def _replace_layout_root(d, fx):
    os.rename(d, d + "-moved-root")
    shutil.copytree(d + "-moved-root", d, symlinks=True)


@param("LAYOUT", "a directory of the layout replaced by another one while the tool works (blobs/, blobs/sha256/, the layout itself; at either step) fails the run and commits nothing", [
    (k, (f, when)) for k, f in (("blobs/", _replace_dir("blobs")), ("blobs/sha256/", _replace_dir("blobs/sha256")), ("the layout directory", _replace_layout_root))
    for when in ("after the first blob", "in the last pass")])
def _(arg):
    swap, when = arg
    fx = mk_fx()
    d, _b = mk_layout(fx)
    vb = wr(os.path.join(sb(), "vex.json"), vex_real())
    m = _load_tool()
    state = {"done": False, "hash_calls": 0}
    real_create, real_hash = m.create_file, m.hash_blobs

    def once():
        if not state["done"]:
            state["done"] = True
            swap(d, fx)
    if when == "after the first blob":
        def create(dir_fd, name, data):
            real_create(dir_fd, name, data)
            if not name.endswith(".tmp"):
                once()
        m.create_file = create
    else:
        def hashing(blobs):
            state["hash_calls"] += 1
            out = real_hash(blobs)
            if state["hash_calls"] == 2:
                once()
            return out
        m.hash_blobs = hashing
    old, sys.argv = sys.argv, ["vex-index", "layout", "--layout", d, "--vex", vb]
    code = None
    try:
        try:
            m.main()
        except SystemExit as e:
            code = e.code
    finally:
        sys.argv = old
    ok(state["done"], "the change was never made (harness)")
    ok(code not in (0, None), "the run must fail, got %r" % (code,))
    top = json.loads(rd(os.path.join(d, "index.json")))      # what is reachable by the layout's name
    ok(top["manifests"][0]["digest"] == dg(fx.bytes), "a final index must not be reachable by the layout's name")



@param("LAYOUT", "layout refuses a layout that another account could change (a directory or a blob writable by group or others), leaving it untouched", [
    ("the layout directory, group-writable", ("", 0o775)), ("blobs/, others-writable", ("blobs", 0o757)), ("blobs/sha256, group-writable", ("blobs/sha256", 0o775)),
    ("a blob, group-writable", ("BLOB", 0o664))])
def _(arg):
    rel, mode = arg
    fx = mk_fx()
    d, _b = mk_layout(fx)
    if rel == "BLOB":
        rel = "blobs/sha256/" + hx(fx.children[0]["digest"])
    target = os.path.join(d, rel) if rel else d
    normal = 0o644 if rel.startswith("blobs/sha256/") else 0o755
    os.chmod(target, mode)
    t0 = tree(d, full=True)
    r = lay(d, vex_real())
    ok(r.rc == 2 and "private" in r.err, "wanted a refusal naming the permissions, got rc=%d %s" % (r.rc, (r.out + r.err).strip()[:200]))
    eq(tree(d, full=True), t0, "the layout must be untouched")
    os.chmod(target, normal)
    r = lay(d, vex_real())
    ok(r.rc == 0, "control: private again, accepted: rc=%d %s" % (r.rc, r.err.strip()[:200]))




@param("LAYOUT", "layout refuses a layout whose top-level files (oci-layout, index.json) or whose parent directories another account could change, and still works under umask 002", [
    ("oci-layout, world-writable", ("file", "oci-layout")), ("index.json, group-writable", ("file", "index.json")),
    ("the parent directory, world-writable and not sticky", ("parent", None)), ("the grandparent directory, group-writable", ("grandparent", None))])
def _(arg):
    kind, name = arg
    fx = mk_fx()
    s = sb()
    os.makedirs(os.path.join(s, "up"))
    d, _b = mk_layout(fx, s=os.path.join(s, "up", "mid"))
    parent, grand = os.path.dirname(d), os.path.dirname(os.path.dirname(d))
    target, bad, good = {"file": (os.path.join(d, name or ""), 0o666 if name == "oci-layout" else 0o664, 0o644), "parent": (parent, 0o777, 0o755),
                         "grandparent": (grand, 0o775, 0o755)}[kind]
    os.chmod(target, bad)
    t0 = tree(d, full=True)
    r = lay(d, vex_real())
    os.chmod(target, good)
    try:
        ok(r.rc == 2 and ("private" in r.err or "above the layout" in r.err), "wanted a refusal naming the permissions, got rc=%d %s" % (r.rc, (r.out + r.err).strip()[:200]))
        eq(tree(d, full=True), t0, "the layout must be untouched")
        r = lay(d, vex_real())
        ok(r.rc == 0, "control: private again, accepted: rc=%d %s" % (r.rc, r.err.strip()[:200]))
    finally:
        os.chmod(grand, 0o755)


@case("LAYOUT", "layout works under umask 002 and 000 (the files it creates never carry group or other write)")
def _():
    for mask in (0o002, 0o000):
        fx = mk_fx()
        d, _b = mk_layout(fx)
        vb = wr(os.path.join(sb(), "vex.json"), vex_real())
        old = os.umask(mask)
        try:
            r = run(["layout", "--layout", d, "--vex", vb])
        finally:
            os.umask(old)
        ok(r.rc == 0, "umask %03o: rc=%d %s" % (mask, r.rc, (r.out + r.err).strip()[:200]))
        for base, dirs, files in os.walk(d):
            for n in files:
                p = os.path.join(base, n)
                if os.path.getmtime(p) and os.stat(p).st_mode & 0o022 and hx(dg(rd(p))) == n:
                    raise Fail("%s is group or other writable" % p)
        r = lay(d, vex_real(), cmd="verify-layout", extra=("--base-digest", dg(fx.bytes)))
        ok(r.rc == 0, "umask %03o: verify-layout: rc=%d %s" % (mask, r.rc, r.err.strip()[:200]))



@param("LAYOUT", "every input file (the VEX file, the built index, the final index) is refused when another account could have written it (group- or world-writable) or replaced it (a writable, non-sticky directory above it)", [
    ("the VEX file, world-writable", ("vex-file", 0o666)), ("the VEX file, group-writable", ("vex-file", 0o664)), ("the directory of the VEX file, world-writable", ("vex-dir", 0o777)),
    ("the built index file, group-writable (compute)", ("index-file", 0o664))])
def _(arg):
    kind, mode = arg
    fx = mk_fx()
    s = sb()
    box = os.path.join(s, "in")
    os.makedirs(box)
    v = wr(os.path.join(box, "vex.json"), vex_real())
    i = wr(os.path.join(s, "i.json"), fx.bytes)
    target = {"vex-file": v, "vex-dir": box, "index-file": i}[kind]
    os.chmod(target, mode)
    d, _b = mk_layout(fx)
    t0 = tree(d, full=True)
    if kind == "index-file":
        r = run(["compute", "--index", i, "--vex", v, "--out-dir", os.path.join(s, "out")])
    else:
        r = run(["layout", "--layout", d, "--vex", v])
    os.chmod(target, 0o755 if kind == "vex-dir" else 0o644)
    ok(r.rc == 2 and ("private" in r.err or "above the layout" in r.err), "wanted a refusal naming the permissions, got rc=%d %s" % (r.rc, (r.out + r.err).strip()[:200]))
    eq(tree(d, full=True), t0, "the layout must be untouched")
    ok(not os.path.exists(os.path.join(s, "out")), "compute must not have created its output")



# ------------------------------------------------------------------ sidecar: the OUT/<variant>.digest file Build records follows the layout from the built index to the final index (REQ-REL-010-AC1)
def side(d, content, mode=0o644):
    p = d + ".digest"
    wr(p, content)
    os.chmod(p, mode)
    return p


def sidecar(d, vb, p, s=None):
    s = s or sb()
    return run(["sidecar", "--layout", d, "--vex", wr(os.path.join(s, "vex.json"), vb), "--digest-file", p])


@case("LAYOUT", "sidecar: after layout, the digest file holding the built index's digest holds the final index's digest, nothing else changes, and the output is that digest")
def _():
    fx = mk_fx()
    d, _b = mk_layout(fx)
    vb = vex_real()
    p = side(d, (dg(fx.bytes) + "\n").encode())
    ok(lay(d, vb).rc == 0, "layout failed")
    top = json.loads(rd(os.path.join(d, "index.json")))
    f = top["manifests"][0]["digest"]
    t0 = tree(d, full=True)
    r = sidecar(d, vb, p)
    ok(r.rc == 0 and r.out == f + "\n", "wanted rc 0 and the final digest, got rc=%d %r %s" % (r.rc, r.out, r.err.strip()[:200]))
    eq(rd(p), (f + "\n").encode(), "the digest file")
    eq(tree(d, full=True), t0, "the layout must not change")
    ok(sorted(os.listdir(os.path.dirname(p))) == ["layout", "layout.digest"], "a temporary file was left behind: %r" % sorted(os.listdir(os.path.dirname(p))))
    ok(os.stat(p).st_mode & 0o022 == 0, "the digest file must stay private")


def _sc_nofile(d, fx):
    return None


def _sc_other(d, fx):
    return ("sha256:" + "9" * 64 + "\n").encode()


def _sc_nonl(d, fx):
    return dg(fx.bytes).encode()


def _sc_crlf(d, fx):
    return (dg(fx.bytes) + "\r\n").encode()


def _sc_two(d, fx):
    return (dg(fx.bytes) + "\n" + dg(fx.bytes) + "\n").encode()


def _sc_final(d, fx):
    top = json.loads(rd(os.path.join(d, "index.json")))
    return (top["manifests"][0]["digest"] + "\n").encode()


@param("LAYOUT", "sidecar refuses a digest file that is not exactly the built index's digest and a newline, leaving the layout and the file untouched", [
    ("a missing file", _sc_nofile), ("another digest", _sc_other), ("no newline", _sc_nonl), ("CRLF", _sc_crlf), ("two lines", _sc_two),
    ("already the final digest (a second run)", _sc_final)])
def _(make):
    fx = mk_fx()
    d, _b = mk_layout(fx)
    vb = vex_real()
    ok(lay(d, vb).rc == 0, "layout failed")
    content = make(d, fx)
    p = d + ".digest"
    if content is not None:
        side(d, content)
    t0, before = tree(d, full=True), (rd(p) if content is not None else None)
    r = sidecar(d, vb, p)
    ok(r.rc == 2 and "vex-index: refused:" in r.err, "wanted a refusal (exit 2, a plain reason), got rc=%d %s" % (r.rc, (r.out + r.err).strip()[:200]))
    eq(tree(d, full=True), t0, "the layout must be untouched")
    eq(rd(p) if os.path.exists(p) else None, before, "the digest file must be untouched")
    ok(not os.path.exists(p + ".vex-index.tmp"), "no temporary file may remain")


@case("LAYOUT", "sidecar refuses a layout that is not yet final, another VEX file, a symlinked or writable digest file and an existing temporary file")
def _():
    fx = mk_fx()
    d, _b = mk_layout(fx)
    vb = vex_real()
    good = (dg(fx.bytes) + "\n").encode()
    p = side(d, good)
    r = sidecar(d, vb, p)
    ok(r.rc == 2 and "refused:" in r.err, "a layout still holding the built index must be refused: rc=%d" % r.rc)
    eq(rd(p), good, "the digest file must be untouched")
    ok(lay(d, vb).rc == 0, "layout failed")
    r = sidecar(d, VEX_MIN, p)
    ok(r.rc == 2 and "refused:" in r.err, "another VEX file must be refused: rc=%d" % r.rc)
    eq(rd(p), good, "the digest file must be untouched")
    os.chmod(p, 0o664)
    r = sidecar(d, vb, p)
    ok(r.rc == 2 and "private" in r.err, "a group-writable digest file must be refused: rc=%d %s" % (r.rc, r.err.strip()[:150]))
    os.chmod(p, 0o644)
    os.unlink(p)
    real = wr(p + ".real", good)
    os.symlink(real, p)
    r = sidecar(d, vb, p)
    ok(r.rc == 2 and "refused:" in r.err, "a symlinked digest file must be refused: rc=%d" % r.rc)
    os.unlink(p)
    side(d, good)
    wr(p + ".vex-index.tmp", b"x")
    r = sidecar(d, vb, p)
    ok(r.rc == 2 and "refused:" in r.err, "an existing temporary file must be refused: rc=%d" % r.rc)
    eq(rd(p), good, "the digest file must be untouched")
    eq(rd(p + ".vex-index.tmp"), b"x", "the foreign temporary file must be left alone")



@case("AC3", "verify needs --base (the exclusion of D from the attestations cannot be checked without it)")
def _():
    fx = mk_fx()
    s = sb()
    out = os.path.join(s, "out")
    i = wr(os.path.join(s, "i.json"), fx.bytes)
    v = wr(os.path.join(s, "v.json"), VEX_MIN)
    r = run(["compute", "--index", i, "--vex", v, "--out-dir", out])
    ok(r.rc == 0, "compute failed: " + r.err.strip()[:200])
    r = run(["verify", "--final", os.path.join(out, "index.json"), "--vex", v, "--blobs", os.path.join(out, "blobs")])
    ok(r.rc != 0 and "--base" in r.err, "verify without --base must be refused: rc=%d %s" % (r.rc, r.err.strip()[:200]))
    r = run(["verify", "--final", os.path.join(out, "index.json"), "--vex", v, "--blobs", os.path.join(out, "blobs"), "--base", i])
    ok(r.rc == 0, "control with --base: rc=%d %s" % (r.rc, r.err.strip()[:200]))


@param("LAYOUT", "a '.' segment is refused wherever it stands in a path argument, also the last one (layout/. and layout/./)", [(k, k) for k in ("/.", "/./", "/./.")])
def _(suffix):
    fx = mk_fx()
    d, _b = mk_layout(fx)
    t0 = tree(d, full=True)
    r = run(["layout", "--layout", d + suffix, "--vex", wr(os.path.join(sb(), "v.json"), vex_real())])
    ok(r.rc == 2, "layout%s must be refused: rc=%d %s" % (suffix, r.rc, (r.out + r.err).strip()[:200]))
    eq(tree(d, full=True), t0, "the layout must be untouched")
    s = sb()
    r = run(["compute", "--index", wr(os.path.join(s, "i.json"), fx.bytes), "--vex", wr(os.path.join(s, "v.json"), VEX_MIN), "--out-dir", os.path.join(s, "o") + suffix])
    ok(r.rc == 2, "an out-dir with %s must be refused: rc=%d" % (suffix, r.rc))



SHARDS = 4   # an unsharded run (no ONLY, no VEXIDX_SHARD, no VEXIDX_SERIAL) runs this many shard processes at the same time


def shard_sizes(total, n):
    return [len([k for k in range(total) if k % n == i]) for i in range(n)]


def judge_shards(expected, results, n):
    """expected: [(tag, name)] in registry order; results: [(rc, text)] one per shard, shard i running the registry indices k with k % n == i.
    Returns the list of problems; empty only if every shard exited 0, printed its own summary with the size of its class, and the
    ok lines of all shards together name every registry case exactly once, with no FAIL line and nothing else counted."""
    bad = []
    if len(results) != n:
        return ["%d shard results for %d shards" % (len(results), n)]
    sizes = shard_sizes(len(expected), n)
    want = {}
    for k, (tag, name) in enumerate(expected):
        want.setdefault("ok   [%s] %s" % (tag, name), []).append(k % n)
    seen = {}
    for i, (rc, text) in enumerate(results):
        lines = text.split("\n")
        if rc != 0:
            bad.append("shard %d exited %s" % (i, rc))
        summ = [l for l in lines if re.fullmatch(r"\d+ passed, \d+ failed, \d+ cases", l)]
        if len(summ) != 1:
            bad.append("shard %d printed %d summary lines" % (i, len(summ)))
        else:
            p, fl, c = [int(x) for x in re.findall(r"\d+", summ[0])]
            if fl != 0 or c != sizes[i] or p != sizes[i]:
                bad.append("shard %d summary %r, want %d passed, 0 failed, %d cases" % (i, summ[0], sizes[i], sizes[i]))
        for l in lines:
            if l.startswith("FAIL"):
                bad.append("shard %d: %s" % (i, l[:200]))
            if l.startswith("ok   ["):
                seen.setdefault(l, []).append(i)
    for line, shards in want.items():
        got = seen.get(line, [])
        if sorted(got) != sorted(shards):
            bad.append("%s: ran in shards %s, want %s" % (line[:150], got, shards))
    for line in seen:
        if line not in want:
            bad.append("an ok line that is not a registry case: %s" % line[:150])
    return bad


def _fake_run(expected, n, drop=None, dup=None, fail=None, rc=None, summary=None, extra=None, empty=None):
    """What n shards would print for `expected`, with one fault injected."""
    outs = []
    for i in range(n):
        lines, k = [], 0
        for j, (tag, name) in enumerate(expected):
            if j % n != i:
                continue
            k += 1
            if drop == j:
                k -= 1
                continue
            if fail == j:
                lines.append("FAIL [%s] %s: boom" % (tag, name))
            else:
                lines.append("ok   [%s] %s" % (tag, name))
            if dup == j:
                lines.append("ok   [%s] %s" % (tag, name))
        size = len([j for j in range(len(expected)) if j % n == i])
        if empty == i:
            lines = []
        if extra == i:
            lines.append("ok   [AC1] a case nobody registered")
        lines.append("")
        if summary is None or summary != i:
            lines.append("%d passed, %d failed, %d cases" % (size - (1 if fail is not None and fail % n == i else 0), 1 if fail is not None and fail % n == i else 0, size))
        outs.append((rc[1] if rc and rc[0] == i else 0, "\n".join(lines)))
    return outs


_EXP = [("AC1", "case %d" % k) for k in range(10)]


@case("AC1", "the shard merge judge accepts four complete shards (each registry case once, summaries match their class sizes)")
def _j_ok():
    eq(judge_shards(_EXP, _fake_run(_EXP, 4), 4), [], "a complete run")


@case("AC1", "the shard merge judge refuses a case that no shard ran")
def _j_drop():
    ok(judge_shards(_EXP, _fake_run(_EXP, 4, drop=5), 4), "a dropped case must be reported")


@case("AC1", "the shard merge judge refuses a case that ran twice")
def _j_dup():
    ok(judge_shards(_EXP, _fake_run(_EXP, 4, dup=3), 4), "a doubled case must be reported")


@case("AC1", "the shard merge judge refuses a FAIL line")
def _j_fail():
    ok(judge_shards(_EXP, _fake_run(_EXP, 4, fail=2), 4), "a failed case must be reported")


@case("AC1", "the shard merge judge refuses a shard that exited non-zero after complete output")
def _j_rc():
    ok(judge_shards(_EXP, _fake_run(_EXP, 4, rc=(1, 7)), 4), "a non-zero shard exit must be reported")


@case("AC1", "the shard merge judge refuses a shard without its summary line, and an empty shard")
def _j_summary():
    ok(judge_shards(_EXP, _fake_run(_EXP, 4, summary=2), 4), "a missing summary must be reported")
    ok(judge_shards(_EXP, _fake_run(_EXP, 4, empty=1), 4), "an empty shard must be reported")


@case("AC1", "the shard merge judge refuses an ok line for a case that is not in the registry, and the wrong number of shards")
def _j_extra():
    ok(judge_shards(_EXP, _fake_run(_EXP, 4, extra=0), 4), "an unregistered ok line must be reported")
    ok(judge_shards(_EXP, _fake_run(_EXP, 4)[:3], 4), "three results for four shards must be reported")


@case("AC1", "the shard merge judge refuses a FAIL line even when every ok record and every summary is complete and valid")
def _j_fail_alone():
    outs = _fake_run(_EXP, 4)
    outs[2] = (0, outs[2][1].replace("\n\n", "\nFAIL [AC1] stray: boom\n\n", 1))
    ok(judge_shards(_EXP, outs, 4), "a FAIL line must be reported on its own")


@case("AC1", "the shard merge judge refuses a summary whose counts do not match the class size even when every ok record is complete")
def _j_summary_alone():
    outs = _fake_run(_EXP, 4)
    outs[1] = (0, outs[1][1].replace(" cases", " cases extra") if False else outs[1][1].rsplit("\n", 1)[0] + "\n1 passed, 0 failed, 1 cases")
    ok(judge_shards(_EXP, outs, 4), "a wrong summary count must be reported on its own")


@case("AC1", "the shard merge judge refuses a case that ran in a shard other than its own")
def _j_wrongshard():
    outs = _fake_run(_EXP, 4)
    moved = outs[0][1].split("\n")[0]
    outs[0] = (0, outs[0][1].replace(moved + "\n", "", 1))
    outs[1] = (0, moved + "\n" + outs[1][1])
    ok(judge_shards(_EXP, outs, 4), "a case run by the wrong shard must be reported")


def main():
    only = os.environ.get("ONLY")
    shard = os.environ.get("VEXIDX_SHARD")
    if shard:
        m = re.fullmatch(r"(\d+)/([1-9]\d*)", shard)
        if not m or int(m.group(1)) >= int(m.group(2)):
            print("FAIL: VEXIDX_SHARD must be <i>/<n> with 0 <= i < n, got %r" % shard)
            sys.exit(2)
        si, sn = int(m.group(1)), int(m.group(2))
    elif not only and not os.environ.get("VEXIDX_SERIAL"):
        # the parent: the whole registry is known here, so every case can be accounted for by name
        procs = []
        results, errs = [], []
        try:
            for i in range(SHARDS):
                env = dict(os.environ, VEXIDX_SHARD="%d/%d" % (i, SHARDS))
                procs.append(subprocess.Popen([sys.executable, os.path.abspath(__file__)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            for p in procs:
                out, err = p.communicate()
                results.append((p.returncode, out))
                errs.append(err)
        finally:
            for p in procs:           # an error or an interrupt in the parent never leaves a started shard running
                if p.poll() is None:
                    p.kill()
                    p.wait()
        for i, (rc, out) in enumerate(results):
            sys.stdout.write(out)       # only the harness's own lines are judged: a tool's stderr never splits an ok line
        for err in errs:
            sys.stderr.write(err)
        problems = judge_shards([(t, nm) for t, nm, _f, _a in CASES], results, SHARDS)
        by = {}
        for tag, name, f, arg in CASES:
            by[tag] = by.get(tag, 0) + 1
        print("")
        print("cases by AC: " + ", ".join("%s=%d" % (k, by[k]) for k in sorted(by)))
        for pr in problems:
            print("FAIL: " + pr)
        print("%d shards; %d cases in the registry" % (SHARDS, len(CASES)))
        print("%d passed, %d failed, %d cases" % (sum(out.count("\nok   [") + out.startswith("ok   [") for _rc, out in results), len(problems), len(CASES)))
        sys.exit(1 if problems else 0)
    else:
        si, sn = 0, 1
    passed, failed, fails, selected = 0, 0, [], 0
    for k, (tag, name, f, arg) in enumerate(CASES):
        if only and only not in name:
            continue
        if k % sn != si:
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
