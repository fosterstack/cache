#!/usr/bin/env python3
"""The records step of the vendored tree's provenance (REQ-VEND-001-AC15): the one step that reads the network, through the Go toolchain.

  vendor-provenance-records.py --vendor-dir DIR --go-sum FILE --licenses FILE [--recorded-origins FILE] --out-dir DIR

For every module of DIR/modules.txt it asks `go mod download -json`, run in an empty scratch module with the toolchain's own checksum-database
check on (no opt-out, nothing read from the caller's environment), for the module's hash and Origin, and writes into --out-dir (which must not
exist) the three files `bin/vendor-provenance.py build` reads: sumdb.json, origins.json and licenses.json. The licences are copied from the
committed, reviewed --licenses file, and a module the toolchain reports no Origin for must be covered by the committed, reviewed
--recorded-origins file (which `build` then applies, so origins.json holds only what the toolchain verified); nothing is detected or invented. It never writes dependency-provenance.json itself.
Exit codes: 0 done | 2 refused (naming the module and the cause; nothing is written) | 1 internal.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

# the build's own toolchain at its fixed install path (checksum-pinned by the scanner installer), never a go found by name
GO_TOOL = "/usr/local/bin/fscache-go/bin/go"  # TEST-SUBST
LOG = "sum.golang.org"
H1 = re.compile(r"h1:[A-Za-z0-9+/]{43}=")
COMMIT = re.compile(r"[0-9a-f]{40}")
OUT_FILES = ("sumdb.json", "origins.json", "licenses.json")


def _load_vp():
    """bin/vendor-provenance.py beside this file, for its readers and its recorded-origins rules (it stays free of the network)"""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor-provenance.py")
    spec = importlib.util.spec_from_file_location("vendor_provenance", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vp = _load_vp()
Refused = vp.Refused
refuse = vp.refuse


def go_env(scratch):
    """a closed environment: only these variables, no workspace file (GOWORK=off: a parent directory's go.work could answer from its own checksums), the checksum database on at its default, nothing that opens a module to an opt-out"""
    return {"GOTOOLCHAIN": "local", "GOFLAGS": "", "GOENV": "off", "GOWORK": "off", "GOSUMDB": LOG, "GOPROXY": "https://proxy.golang.org",
            "GOPATH": os.path.join(scratch, "gopath"), "GOMODCACHE": os.path.join(scratch, "gopath", "pkg", "mod"),
            "GOCACHE": os.path.join(scratch, "gocache"), "HOME": os.path.join(scratch, "home"), "TMPDIR": scratch}


def run_go(modules, scratch):
    work = os.path.join(scratch, "work")
    os.makedirs(work)
    for d in ("home", "gopath", "gocache"):
        os.makedirs(os.path.join(scratch, d))
    with open(os.path.join(work, "go.mod"), "w", encoding="utf-8") as fh:
        fh.write("module scratch.invalid/records\n\ngo 1.24\n")
    args = [GO_TOOL, "mod", "download", "-json"] + ["%s@%s" % m for m in modules]
    try:
        r = subprocess.run(args, cwd=work, env=go_env(scratch), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as e:
        refuse("cannot run the Go toolchain %s: %s" % (GO_TOOL, e))
    return r


def parse_stream(raw):
    out, dec, text, i = [], json.JSONDecoder(), raw.decode("utf-8", "replace"), 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return out
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError as e:
            refuse("the toolchain's answer is not JSON: %s" % e)
        if not isinstance(obj, dict):
            refuse("the toolchain's answer holds a value that is not an object")
        out.append(obj)


def origin_of(key, version, obj):
    """the origin the toolchain verified, or None when it reports none (the reviewed recorded-origins file may then supply it)"""
    org = obj.get("Origin")
    if org is None or org == {}:
        return None
    if not isinstance(org, dict):
        refuse("module %s: the origin is not an object" % key)
    if org.get("VCS") != "git":
        refuse("module %s: the origin's VCS is %r, git is required" % (key, org.get("VCS")))
    url = org.get("URL")
    if not isinstance(url, str) or not url.startswith("https://") or len(url) <= len("https://"):
        refuse("module %s: the origin url is not an https address" % key)
    if vp.PSEUDO.search(version):
        commit, m = org.get("Hash"), vp.PSEUDO.search(version)
        if not (isinstance(commit, str) and COMMIT.fullmatch(commit)):
            refuse("module %s: the origin commit is not 40 hex characters" % key)
        if not commit.startswith(m.group("rev")):
            refuse("module %s: the origin commit does not match the pseudo-version's hash prefix %s" % (key, m.group("rev")))
        return {"url": url, "commit": commit}
    if org.get("Ref") != "refs/tags/" + version:
        refuse("module %s: the origin ref %r does not name the tag %s" % (key, org.get("Ref"), version))
    return {"url": url, "tag": version}


def produce(a):
    want = vp.modules_txt(a["--vendor-dir"])
    sums = vp.go_sum(a["--go-sum"])
    licences = vp.load_json(vp.read_regular(a["--licenses"], "licenses"), "licenses")
    if not isinstance(licences, dict):
        refuse("licenses is not an object")
    ordered = sorted(want)
    for p, v in ordered:
        if p.startswith("-") or v.startswith("-"):
            refuse("module %s@%s: a path or version beginning with '-' would be read as an option by the toolchain" % (p, v))
    scratch = tempfile.mkdtemp(prefix="vendor-records-")
    try:
        r = run_go(ordered, scratch)
        answers = parse_stream(r.stdout)
        by = {}
        for obj in answers:
            k = "%s@%s" % (obj.get("Path"), obj.get("Version"))
            if k in by:
                refuse("module %s appears more than once in the toolchain's answer" % k)
            by[k] = obj
        for k in sorted(by):
            if tuple(k.split("@", 1)) not in want:
                refuse("module %s is in the toolchain's answer but not in vendor/modules.txt" % k)
        sumdb, origins, lic = {}, {}, {}
        for p, v in ordered:
            key = "%s@%s" % (p, v)
            obj = by.get(key)
            if obj is None:
                refuse("module %s: not reported by the toolchain (not downloaded or verified)" % key)
            if obj.get("Error"):
                refuse("module %s: the toolchain could not verify it: %s" % (key, obj["Error"]))
            h = obj.get("Sum")
            if not isinstance(h, str) or not H1.fullmatch(h):
                refuse("module %s: the toolchain gave no Sum hash" % key)
            if h != sums.get((p, v)):
                refuse("module %s: the verified hash differs from go.sum" % key)
            sumdb[key] = {"hash": h, "included": True, "log": LOG}
            org = origin_of(key, v, obj)
            if org is not None:
                origins[key] = org
            l = licences.get(key)
            if not isinstance(l, str) or not l:
                refuse("module %s: no licence in the reviewed licenses file" % key)
            lic[key] = l
        if r.returncode != 0:
            refuse("the Go toolchain exited %d: %s" % (r.returncode, r.stderr.decode("utf-8", "replace").strip()[:300]))
        missing = [("%s@%s" % m) for m in ordered if ("%s@%s" % m) not in origins]
        if missing:
            if "--recorded-origins" not in a:
                refuse("module %s: the toolchain reports no origin and no recorded-origins file was given" % missing[0])
            rec = vp.recorded_origins(a["--recorded-origins"], want, origins)
            for key in missing:
                if key not in rec:
                    refuse("module %s: the toolchain reports no origin and the recorded-origins file has none" % key)
            # origins.json keeps only what the toolchain verified: `build` itself applies the reviewed file to the modules that have no origin here
        return {"sumdb.json": sumdb, "origins.json": origins, "licenses.json": lic}
    finally:
        for root, dirs, files in os.walk(scratch):
            for n in dirs + files:
                try:
                    os.chmod(os.path.join(root, n), 0o700)
                except OSError:
                    pass
        shutil.rmtree(scratch, ignore_errors=True)


def main(argv):
    a = vp.parse_args(argv, ["--vendor-dir", "--go-sum", "--licenses", "--out-dir"], ["--recorded-origins"])
    out_dir = a["--out-dir"]
    if os.path.lexists(out_dir):
        refuse("--out-dir %s already exists" % out_dir)
    files = produce(a)
    os.mkdir(out_dir)                  # nothing is written unless every module resolved
    for name in OUT_FILES:
        with open(os.path.join(out_dir, name), "x", encoding="utf-8") as fh:
            fh.write(json.dumps(files[name], indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Refused as e:
        sys.stderr.write("vendor-provenance-records: %s\n" % e)
        sys.exit(2)
