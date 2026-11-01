# shellcheck shell=bash
# rules covered (ratified 2026-10-09): rule 11-24 (Building the package), rule 25-38 (Building the image), rule 38a 38b 39-43 (Sealed-off
# build), rule 44-49 (Keeping inputs fresh), and the parts of rule 72 and 73 that touch our build, of the RATIFIED v0.3.0 rules
# v2 (ops/docs/ratify/2026-10-09-v030-rules.md, owner "ratify all", Oct 9 2026). The requirements are in requirements/requirements.yaml
# and each per-PR test file carries its own "proves:" header. Each assertion is tagged with the rule number it serves ("rule N").
#
# STATUS: the harness of the per-PR test files bin/*-test.sh (each sources this file); the files named below exist. The suite is offline: no network, no
# docker, no real melange or apko, no sudo. Where the real tool would run, the tools (melange, apko, sudo, unshare, sysctl,
# uname, curl, git, gh) are replaced by STUBS on PATH that record their argv in a call log; the suite asserts the flags and the
# order of the calls. Static rules are asserted on the file they live in (recipe, apko config, lock file, driver script,
# workflow job, doc). Cases that need the real tools on a real runner are listed at the bottom (NOT TESTABLE HERE).
#
# ALLOWLIST (bin/check-file-allowlist.sh lists bin files one by one and has no build/ pattern; the allowlist change is its own PR):
#   build/melange.yaml  build/melange-fips.yaml  build/apko.yaml  build/apko-fips.yaml
#   build/locks/apko.base.lock.json  build/locks/apko-fips.base.lock.json  build/locks/melange.lock
#   build/keys/assembly.rsa  build/keys/assembly.rsa.pub  build/keys/release.rsa.pub
#   docs/apk-signing-key.md  (the existing docs pattern matches it)
#   bin/build-apk.sh  bin/assemble-image.sh  bin/apko-lock.sh  bin/apk-tool.py  bin/gen-recipes.py  bin/go-module-sbom.py  bin/oci-digest.py  bin/net-probe.py
#   bin/install-build-tools.sh  bin/release-sign-apks.sh  bin/sealed-proof.sh  bin/lock-proof.sh  bin/refresh-inputs.sh
#   bin/melange-apko-test.sh
# EDITED, not created: .github/workflows/go-freshness.yml (two new JOBS, no new workflow file: standing rule "no workflow
# sprawl"). bin/go-freshness-wiring-test.sh pins the set of jobs that may touch the agent environment: if the refresh job uses
# the auditor App token, that test's ALLOWED list needs ("go-freshness.yml", "refresh") added in the same PR.
#
# ARCHIVE layout the suite assumes (the "archive", rule 12/15/29):
#   ARCHIVE/<arch>/<name>-<ver>.apk + ARCHIVE/<arch>/APKINDEX.tar.gz   (arch: x86_64 aarch64)
#   ARCHIVE/keys/wolfi-signing.rsa.pub     ARCHIVE/go/go<ver>.linux-<amd64|arm64>.tar.gz
# apko config paths (fixed, so the lock names the same literal paths in Build and Rebuild, rule 31):
#   repositories ["/work/archive", "/work/melange-repo"]; keyring ["/work/keyring/wolfi-signing.rsa.pub",
#   "/work/keyring/assembly.rsa.pub"]. The driver makes /work/* visible only through `sudo` calls (stubbed here).
#
# INTERFACES (the names below are the ones the scripts implement). Exit 0 ok; exit 2 = refusal naming the reason on stderr;
# a repeated flag: the LAST one wins.
#  I1 build/melange.yaml (package fscache) and build/melange-fips.yaml (package fscache-fips); package.version "@VERSION@",
#     epoch 0. Build environment: only name=version pins, no go package, no repositories/keyring of its own (the driver passes
#     --repository-append and --keyring-append). Go comes from `uses: fetch` steps (one per arch, go.dev uri,
#     expected-sha256), found offline in the cache dir. The build writes `go version -m /usr/bin/fscache` to
#     usr/share/fscache/buildinfo.txt inside the apk.
#  I2 build/apko.yaml (fscache) and build/apko-fips.yaml (fscache-fips); the fscache line is "fscache=@FSCACHE_VERSION@-r0".
#  I3 bin/build-apk.sh --variant standard|fips --arch x86_64|aarch64 --version X.Y.Z --source-dir DIR --repo DIR --keyring FILE
#        --go-archive DIR --melange-lock FILE --out DIR [--recipe FILE] [--render-dir DIR] [--apk-cache-dir DIR]
#     and  --print-source-date-epoch --source-dir DIR.  Env required: SOURCE_DATE_EPOCH (digits). Refused: --signing-key,
#     RELEASE_KMS_KEY_REF in the environment, GOPROXY other than off, HTTP(S)_PROXY. It runs, in this order,
#       sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
#       sudo [env SOURCE_DATE_EPOCH=..] unshare -n melange build ... (the only network cut; melange called directly on the VM)
#     signs with the committed assembly key build/keys/assembly.rsa, then writes OUT/<arch>/*.apk, OUT/fscache-modules.spdx.json
#     and OUT/inputs-manifest.json.
#  I4 bin/assemble-image.sh --variant production|fips --version X.Y.Z --archive DIR --melange-repo DIR --keyring-dir DIR
#        --out DIR [--apko-config FILE] [--base-lock FILE] [--render-dir DIR]. Env: SOURCE_DATE_EPOCH. Order: verify the base
#     lock against the archive -> sudo unshare -n apko lock (full lock) -> compare base vs full -> verify full -> sudo unshare -n
#     apko build --offline --lockfile FULL --sbom-path DIR. OUT gets <variant>.full.lock.json, <variant>/ (the image as an OCI layout
#     DIRECTORY: oci-layout, index.json, blobs/sha256/<hex>; no tarball, advisor 0393), <variant>.digest (ONE line sha256:<hex>: the OCI
#     INDEX digest), <variant>.manifests (one line `<arch> sha256:<hex>` per per-arch manifest: amd64, arm64) and <variant>-sbom/sbom.json.
#     --version is X.Y.Z, X.Y.Z-rcN or 0.0.0-rc.1; it runs from the repository root only (exit 2 elsewhere).
#  I4b CHANGED/NEW (advisor): bin/oci-digest.py TAR  reads the OCI layout tarball: oci-layout, index.json -> index blob, per-arch
#     manifest blobs under blobs/sha256/; every blob must hash to its name. Prints `index sha256:<hex>` then `<arch> sha256:<hex>`
#     lines; exit 1 naming the file/blob on a missing index.json or a blob whose hash differs.
#  I3b NEW (advisor reading, rule 40): exit codes of build-apk.sh and assemble-image.sh: 0 ok, 2 named refusal, 4 = "a network
#     attempt was made inside the sealed call". Detection: the sealed tool exited non-zero AND its stderr shows ENETUNREACH / network
#     is unreachable / dial tcp / no such host AND a probe run in the same setup, `sudo unshare -n python3 bin/net-probe.py`, exits
#     101 (ENETUNREACH: the namespace has no route, so the attempt was real). bin/net-probe.py connects to 192.0.2.1:9 and exits
#     with the connect errno (0 = connected). Probe not 101 -> the namespace is not sealed: non-zero, not 4. Other failures: 1.
#     Also new: bin/oci-digest.py and bin/net-probe.py (allowlist).
#  I5 bin/apko-lock.sh   compare BASE FULL --apk NAME   arch-check LOCK
#                        verify-archive --lock L --archive DIR [--melange-repo DIR]   evidence --lock L --archive DIR --out DIR
#                        (evidence writes OUT/archive-checksums.txt in sha256sum format, relative to ARCHIVE, plus OUT/*.lock.json)
#  I6 bin/apk-tool.py    digest APK | same A B | signer APK | cat APK MEMBER | binary-check APK FILE
#                        | inputs-manifest --apk APK --melange-lock FILE --out FILE
#  I7 bin/gen-recipes.py --template T --regular A --fips B --check|--write   bin/go-module-sbom.py --modules vendor/modules.txt --provenance dependency-provenance.json --buildinfo F --out F
#     (SBOM = the modules the binary embeds; every embedded path@version must be in BOTH vendor/modules.txt and
#     dependency-provenance.json {"modules":[{"path":..,"version":..}]}: SUBSET, not equality; vendored-but-unbuilt modules are in the
#     dependency list, not the SBOM)
#     bin/install-build-tools.sh melange|apko [DEST]   bin/release-sign-apks.sh --build-dir A --key K
#  I8 bin/sealed-proof.sh and bin/lock-proof.sh (the real-run proofs of rules 36, 39-42; see the groups below)
#  I9 bin/refresh-inputs.sh refresh --repo-dir D --archive D   |   fips-module --go-root D --repo-dir D
#     and two jobs in .github/workflows/go-freshness.yml: `refresh` (daily) and `fips-module` (weekly). refresh makes three locks
#     with `apko lock --output ...` (the melange-environment config and its output file are named *melange*, the fips ones *fips*);
#     it writes build/locks/*, archives new packages by digest into ARCHIVE/<arch>/ (curl), verifies them, rewrites lock urls to
#     /work/archive/..., then git checkout -b refresh/..., commit, push that branch, gh pr create. Exit 3 = Wolfi key changed.
# ---------------------------------------------------------------------------------------------------------------
# RULE -> ASSERTION GROUP (the rules are the ratified v0.3.0 rules; the groups below say where each is asserted)
#  11  recipes build fscache from source (the recipes are the only build input), native arch only (driver refuses a foreign arch)
#  12  Go from go.dev: fetch steps with checksums, no Wolfi go apk, GOTOOLCHAIN=local, go.mod go line <= archived Go, tarball
#      pre-seeded from the archive into the cache dir, tamper/missing refused
#  13  FIPS recipe: GOFIPS140 set to the version of the id build/locks/fips-module.txt names, and a proof that the binary records that id; standard recipe has no GOFIPS140
#  14  binary in the archive == binary in the apk (apk-tool binary-check)
#  15  inputs manifest = our melange lock + the .melange.yaml environment read back from the apk; recipe pinned == lock
#  16  melange/apko installer: checksum pin per tool and arch, verified before extraction, no container digest
#  17  build-apk.sh takes no --signing-key and refuses a release key in the environment; only the assembly key is passed
#  18  docs/apk-signing-key.md (yearly rotation, leak procedure, public key, disclosure timing) and the committed keys
#  19  no --ignore-signatures / --allow-untrusted anywhere; keys appended on every tool call
#  20  apk SBOM by melange, image SBOM by apko --sbom-path, Go module list by go-module-sbom.py; no scanner in the path
#  21  gen-recipes.py: both recipes are generated from one template; they differ only in name, description and the FIPS lines
#  22  assembly-key signing; apk-tool digest/same/signer; release-sign-apks.sh compares then signs with the release key
#  23  Build holds no key: no secret in the melange environment; a release key in the environment is refused
#  24  version stamp recipe steps (the draft's four fixes), post-build buildinfo check refuses (devel)/dirty
#  25-27 apko configs, pre-flight on the base lock, missing package / missing index refuse with no fallback
#  28  tampered archived package refused at the lock checksum; the build always passes --lockfile
#  29  evidence: lock + checksum list of every archived package, the indexes, the Wolfi key (and the Go tarballs)
#  30  rebuild from the archive alone: apko build --offline --lockfile under unshare -n, digest file
#  31  SOURCE_DATE_EPOCH in both tools, --build-date, same inputs -> same full lock and digest
#  32  refresh job compares the live Wolfi key (see 46)
#  33  one apko build per variant for both archs; arch-check fails when per-arch versions differ
#  34  -fips image has no shell      36  lock-proof.sh (four failing-first cases)      37  two lock files and their compare
#  38  user 65532 and its home      38a melange hermetic       38b apko hermetic       39-42 sealed-proof.sh
#  43  NOT TESTABLE HERE (a report, no gate)
#  44-49 refresh job and bin/refresh-inputs.sh (re-lock, dependabot silent, key change stops, gone version noted, no 7-day wait,
#      PR only)       72  build-side FIPS checks (buildinfo of the -fips apk)       73  weekly certified-module check
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL [$1] $2"; [ -n "${MA_DEBUG:-}" ] && { echo "  --- rc=$(cat "$work/rc" 2>/dev/null) log:"; tail -5 "$work/log" 2>/dev/null | sed "s/^/  | /"; echo "  --- calls:"; tail -4 "$CALLS" 2>/dev/null | cut -c1-200 | sed "s/^/  | /"; }; true; }
# t <rule> <desc> <cmd...>: passes when the command exits 0
t() { local ac=$1 d=$2; shift 2; if "$@" >"$work/out" 2>&1; then ok; else bad "$ac" "$d"; fi; }

BA="$root/bin/build-apk.sh" AI="$root/bin/assemble-image.sh" LK="$root/bin/apko-lock.sh" AT="$root/bin/apk-tool.py"
GR="$root/bin/gen-recipes.py" GS="$root/bin/go-module-sbom.py" IT="$root/bin/install-build-tools.sh"
OD="$root/bin/oci-digest.py" NP="$root/bin/net-probe.py"
RS="$root/bin/release-sign-apks.sh" SP="$root/bin/sealed-proof.sh" LP="$root/bin/lock-proof.sh" RF="$root/bin/refresh-inputs.sh"
WF="$root/.github/workflows/go-freshness.yml"
SDE=1789952380 ISO=2026-09-21T00:59:40Z
CALLS="$work/calls"; : >"$CALLS"
fx="$work/fx"; stubs="$work/stubs"; stubs2="$work/stubs2"; mkdir -p "$stubs" "$stubs2"

# ---------- python library: fixtures, stub back-ends, mutations ------------------------------------------------------
cat >"$work/lib.py" <<'PY'
import base64, gzip, hashlib, io, json, os, re, shutil, subprocess, sys, tarfile, zlib
import yaml
ARCHS = ["x86_64", "aarch64"]
BASE = [("wolfi-baselayout", "20230201-r5"), ("ca-certificates-bundle", "20260101-r0"), ("tzdata", "2026a-r0")]
ENVPK = [("busybox", "1.37.0-r5"), ("git", "2.50.1-r0"), ("wget", "1.25.0-r0"), ("ca-certificates-bundle", "20260102-r0")]
def tarb(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.GNU_FORMAT) as t:
        for n, d in members:
            i = tarfile.TarInfo(n); i.size = len(d); i.mtime = 0; i.mode = 0o644
            t.addfile(i, io.BytesIO(d))
    return b.getvalue()
def gz(b):
    o = io.BytesIO()
    with gzip.GzipFile(fileobj=o, mode="wb", mtime=0) as g: g.write(b)
    return o.getvalue()
def realsig(ctrl, keyfile, alg):
    """an RSA signature over the compressed control stream, exactly what apk and melange make (openssl dgst -sha1|-sha256 -sign): the committed assembly
    key is non-secret by design (rule 22), a test release key is generated by the suite"""
    import tempfile
    pem = open(keyfile).read(); pem = pem[pem.index("-----BEGIN"):]
    with tempfile.TemporaryDirectory() as d:
        open(d + "/k", "w").write(pem); open(d + "/c", "wb").write(ctrl)
        return subprocess.run(["openssl", "dgst", "-" + alg, "-sign", d + "/k", d + "/c"], capture_output=True, check=True).stdout
def mkapk(path, name, ver, files, control=None, signer="assembly.rsa.pub", sigalg="RSA", datahash=None, signkey=None):
    data = gz(tarb(sorted(files.items())))
    dh = datahash or hashlib.sha256(data).hexdigest()   # a real apk's .PKGINFO carries the sha256 of its data stream
    ctl = [(".PKGINFO", ("pkgname = %s\npkgver = %s\ndatahash = %s\n" % (name, ver, dh)).encode())] + sorted((control or {}).items())
    ctrl = gz(tarb(ctl))
    # a signature is REAL when the committed assembly key (or a given key) signs it: the drivers verify signatures, not names. STUB_FAKE_SIG=1 makes the
    # stand-in bytes instead (the regression for "a name is not a signature")
    key = signkey or ((os.environ.get("FSCACHE_ROOT", "") + "/build/keys/assembly.rsa") if signer == "assembly.rsa.pub" else None)
    if signer and key and os.path.exists(key) and not os.environ.get("STUB_FAKE_SIG"):
        sigbytes = realsig(ctrl, key, "sha256" if sigalg == "RSA256" else "sha1")
    else:
        sigbytes = ("sig-%s-%s" % (signer, name)).encode()
    sig = gz(tarb([(".SIGN." + sigalg + "." + signer, sigbytes)])) if signer else b""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").write(sig + ctrl + data)
    return sig, ctrl, data
def b64(x): return base64.b64encode(x).decode()
def entry(name, ver, arch, url, parts):
    sig, ctrl, data = parts
    e = {"name": name, "url": url, "version": ver, "architecture": arch,
         "control": {"range": "bytes=%d-%d" % (len(sig), len(sig) + len(ctrl) - 1), "checksum": "sha1-" + b64(hashlib.sha1(ctrl).digest())},
         "data": {"range": "bytes=%d-%d" % (len(sig) + len(ctrl), len(sig) + len(ctrl) + len(data) - 1), "checksum": "sha256-" + b64(hashlib.sha256(data).digest())},
         "checksum": "Q1" + b64(hashlib.sha1(ctrl).digest())}
    e["signature"] = {"range": "bytes=0-%d" % (len(sig) - 1), "checksum": "sha1-" + b64(hashlib.sha1(sig).digest())} if sig else {"range": "", "checksum": ""}
    return e
def lockdoc(entries, cfgsum, repos):
    return {"version": "v1", "config": {"name": "apko.yaml", "checksum": cfgsum},
            "contents": {"keyring": [{"name": "work/keyring/wolfi-signing.rsa.pub", "url": "/work/keyring/wolfi-signing.rsa.pub", "content": "-----BEGIN PUBLIC KEY-----\nfixture\n"}],
                         "build_repositories": [], "runtime_repositories": [],
                         "repositories": [{"name": r.split("://")[-1] + "/" + a, "url": r + "/" + a + "/APKINDEX.tar.gz", "architecture": a} for r in repos for a in ARCHS],
                         "packages": entries}}
def wj(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(doc, open(path, "w"), indent=1, sort_keys=True)
CFG = """contents:
  repositories:
    - /work/archive
    - /work/melange-repo
  keyring:
    - /work/keyring/wolfi-signing.rsa.pub
    - /work/keyring/assembly.rsa.pub
  packages:
    - wolfi-baselayout
    - ca-certificates-bundle
    - tzdata
    - %(fs)s=@FSCACHE_VERSION@-r0
accounts:
  groups:
    - groupname: nonroot
      gid: 65532
  users:
    - username: nonroot
      uid: 65532
      gid: 65532
      homedir: /home/nonroot
  run-as: 65532
paths:
  - path: /home/nonroot
    type: directory
    uid: 65532
    gid: 65532
    permissions: 0o755
work-dir: /home/nonroot
entrypoint:
  command: /usr/bin/fscache
archs:
  - x86_64
  - aarch64
"""
def recipe(fx, sums):   # the fixture TEMPLATE (placeholders), like build/melange.yaml.tmpl
    return """package:
  name: @NAME@
  version: "@VERSION@"
  epoch: 0
  description: @DESCRIPTION@
  copyright:
    - license: Apache-2.0
environment:
  contents:
    packages:
@PACKAGES@
  environment:
    GOTOOLCHAIN: local
    GOFLAGS: -mod=vendor
    GOPROXY: "off"
    CGO_ENABLED: "0"
pipeline:
  - uses: fetch
    with:
      uri: https://go.dev/dl/go1.27.2.linux-amd64.tar.gz
      expected-sha256: %(s1)s
      directory: /usr/local/go
  - uses: fetch
    with:
      uri: https://go.dev/dl/go1.27.2.linux-arm64.tar.gz
      expected-sha256: %(s2)s
      directory: /usr/local/go
  - runs: |
      mkdir -p .git/refs/heads .git/refs/tags
      git config --global --add safe.directory "$PWD"
      printf '.melange*\\n.config\\n.gitconfig\\n' >> .git/info/exclude
  - runs: |
      export PATH=/usr/local/go/bin:$PATH
      export GOPATH=/tmp/gopath GOCACHE=/tmp/gocache
@FIPS_EXPORT@
      go build -trimpath -o ${{targets.destdir}}/usr/bin/fscache ./cmd/fscache
@FIPS_PROOF@
  - runs: |
      export PATH=/usr/local/go/bin:$PATH
      mkdir -p ${{targets.destdir}}/usr/share/fscache
      go version -m ${{targets.destdir}}/usr/bin/fscache > ${{targets.destdir}}/usr/share/fscache/buildinfo.txt
  - runs: |
      if grep -Eq '\\(devel\\)|vcs.modified=true' ${{targets.destdir}}/usr/share/fscache/buildinfo.txt; then cat ${{targets.destdir}}/usr/share/fscache/buildinfo.txt; echo 'the binary says (devel) or vcs.modified=true' >&2; exit 1; fi
""" % dict(s1=sums[0], s2=sums[1])
def fixtures(fx):
    P = {}
    for a in ARCHS:
        for n, v in BASE + [("tzdata", "2026b-r0")]:
            d = "live" if v == "2026b-r0" else "archive"
            P[(n, v, a)] = mkapk("%s/%s/%s/%s-%s.apk" % (fx, d, a, n, v), n, v, {"usr/share/%s/data" % n: ("%s-%s-%s" % (n, v, a)).encode()}, signer="wolfi-signing.rsa.pub")
        open("%s/archive/%s/APKINDEX.tar.gz" % (fx, a), "wb").write(b"index-" + a.encode())
        for n, v in ENVPK:
            P[("env", n, v, a)] = mkapk("%s/envrepo/%s/%s-%s.apk" % (fx, a, n, v), n, v, {"usr/share/%s/data" % n: ("%s-%s" % (n, a)).encode()}, signer="wolfi-signing.rsa.pub")
        open("%s/envrepo/%s/APKINDEX.tar.gz" % (fx, a), "wb").write(b"envrepo-index-" + a.encode())
        for n, mel in (("fscache", "melrepo"), ("fscache-fips", "melrepo-fips")):
            P[(n, "0.3.0-r0", a)] = mkapk("%s/%s/%s/%s-0.3.0-r0.apk" % (fx, mel, a, n), n, "0.3.0-r0", {"usr/bin/fscache": ("bin-%s-%s" % (n, a)).encode()})
            open("%s/%s/%s/APKINDEX.tar.gz" % (fx, mel, a), "wb").write(b"index-" + a.encode())
    os.makedirs(fx + "/archive/keys", exist_ok=True)
    open(fx + "/archive/keys/wolfi-signing.rsa.pub", "w").write("-----BEGIN PUBLIC KEY-----\nwolfi-fixture\n-----END PUBLIC KEY-----\n")
    os.makedirs(fx + "/keyring", exist_ok=True)
    open(fx + "/keyring/wolfi-signing.rsa.pub", "w").write(open(fx + "/archive/keys/wolfi-signing.rsa.pub").read())
    open(fx + "/keyring/assembly.rsa.pub", "w").write("-----BEGIN PUBLIC KEY-----\nassembly-fixture\n-----END PUBLIC KEY-----\n")
    os.makedirs(fx + "/archive/go", exist_ok=True)
    sums = []
    for g in ("amd64", "arm64"):
        p = "%s/archive/go/go1.27.2.linux-%s.tar.gz" % (fx, g)
        open(p, "wb").write(("fake-go-" + g).encode()); sums.append(hashlib.sha256(open(p, "rb").read()).hexdigest())
    def ent(n, v, a, pre): return entry(n, v, a, "%s/%s/%s-%s.apk" % (pre, a, n, v), P[(n, v, a)])
    base = [ent(n, v, a, "/work/archive") for a in ARCHS for n, v in BASE]
    wj(fx + "/base.lock.json", lockdoc(base, "cfg-base", ["/work/archive"]))
    wj(fx + "/base-fips.lock.json", lockdoc(base, "cfg-base-fips", ["/work/archive"]))
    for fs, out in (("fscache", "full"), ("fscache-fips", "full-fips")):
        ents = [ent(n, v, a, "/mnt/other/archive") for a in ARCHS for n, v in reversed(BASE)] + [ent(fs, "0.3.0-r0", a, "/work/melange-repo") for a in ARCHS]
        wj("%s/%s.lock.json" % (fx, out), lockdoc(ents, "cfg-full-" + fs, ["/work/archive", "/work/melange-repo"]))
    live = [ent(n, v, a, "https://packages.wolfi.dev/os") for a in ARCHS for n, v in BASE]
    wj(fx + "/live-same.lock.json", lockdoc(live, "live", ["https://packages.wolfi.dev/os"]))
    new = [ent(n, "2026b-r0" if n == "tzdata" else v, a, "https://packages.wolfi.dev/os") for a in ARCHS for n, v in BASE]
    wj(fx + "/live-new.lock.json", lockdoc(new, "live", ["https://packages.wolfi.dev/os"]))
    envl = [entry(n, v, a, "https://packages.wolfi.dev/os/%s/%s-%s.apk" % (a, n, v), P[("env", n, v, a)]) for a in ARCHS for n, v in ENVPK]
    wj(fx + "/live-mel.lock.json", lockdoc(envl, "live-mel", ["https://packages.wolfi.dev/os"]))
    for ar in ARCHS:   # real-run additions Oct 9: a build-tool closure that grows (zlib), and the live signed index per arch
        P[("zlib", "1.3.2-r0", ar)] = mkapk("%s/live/%s/zlib-1.3.2-r0.apk" % (fx, ar), "zlib", "1.3.2-r0", {"usr/lib/libz": ("zlib-" + ar).encode()}, signer="wolfi-signing.rsa.pub")
        open("%s/live/%s/APKINDEX.tar.gz" % (fx, ar), "wb").write(b"index-live-" + ar.encode())
    envl2 = envl + [entry("zlib", "1.3.2-r0", ar, "https://packages.wolfi.dev/os/%s/zlib-1.3.2-r0.apk" % ar, P[("zlib", "1.3.2-r0", ar)]) for ar in ARCHS]
    wj(fx + "/live-mel-new.lock.json", lockdoc(envl2, "live-mel", ["https://packages.wolfi.dev/os"]))
    open(fx + "/melange.lock", "w").write("".join(sorted("%s=%s\n" % p for p in ENVPK)))
    open(fx + "/apko.yaml", "w").write(CFG % dict(fs="fscache")); open(fx + "/apko-fips.yaml", "w").write(CFG % dict(fs="fscache-fips"))
    open(fx + "/fips-module.txt", "w").write("v1.0.0-c2097c7c\n")
    open(fx + "/melange.yaml.tmpl", "w").write(recipe(fx, sums))
    # the generator has no test switch: the fixtures run a copy of it whose TEMPLATE_SHA256 line (the only line marked TEST-SUBST) holds the fixture template's own pin
    src = open(os.path.join(os.environ["FSCACHE_ROOT"], "bin/gen-recipes.py")).read().split("\n")
    pin = hashlib.sha256(open(fx + "/melange.yaml.tmpl", "rb").read()).hexdigest()
    hit = [i for i, ln in enumerate(src) if re.match(r'^TEMPLATE_SHA256 = "[0-9a-f]{64}"\s+# TEST-SUBST', ln)]
    assert len(hit) == 1, "bin/gen-recipes.py must hold exactly one TEMPLATE_SHA256 line marked TEST-SUBST (found %d)" % len(hit)
    src[hit[0]] = 'TEMPLATE_SHA256 = "%s"   # TEST-SUBST' % pin
    open(fx + "/gen-recipes.py", "w").write("\n".join(src))
    subprocess.run([sys.executable, fx + "/gen-recipes.py", "--template", fx + "/melange.yaml.tmpl", "--regular", fx + "/melange.yaml", "--fips", fx + "/melange-fips.yaml", "--melange-lock", fx + "/melange.lock", "--fips-module", fx + "/fips-module.txt", "--write"], check=True)
    # a repo tree for the refresh job
    r = fx + "/repo"
    os.makedirs(r + "/build/locks", exist_ok=True)
    for f in ("apko.yaml", "apko-fips.yaml", "melange.yaml", "melange-fips.yaml"): shutil.copy(fx + "/" + f, r + "/build/" + f)
    shutil.copy(fx + "/base.lock.json", r + "/build/locks/apko.base.lock.json"); shutil.copy(fx + "/base-fips.lock.json", r + "/build/locks/apko-fips.base.lock.json")
    shutil.copy(fx + "/melange.lock", r + "/build/locks/melange.lock"); shutil.copy(fx + "/fips-module.txt", r + "/build/locks/fips-module.txt"); shutil.copy(fx + "/melange.yaml.tmpl", r + "/build/melange.yaml.tmpl")
    # apks for tools
    pr = fx + "/pair"
    mkapk(pr + "/a.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"binA", "usr/share/x": b"same"})
    mkapk(pr + "/b.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"binA", "usr/share/x": b"same"}, signer="release.rsa.pub")
    mkapk(pr + "/c.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"binC", "usr/share/x": b"same"})
    mkapk(pr + "/rsa256.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"binA", "usr/share/x": b"same"}, sigalg="RSA256")   # real melange writes .SIGN.RSA256.<key> (real-run finding Oct 9)
    mkapk(pr + "/unsigned.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"binA", "usr/share/x": b"same"}, signer=None)
    open(pr + "/binA", "wb").write(b"binA"); open(pr + "/binC", "wb").write(b"binC")
    envy = lambda pk: yaml.safe_dump({"package": {"name": "fscache"}, "environment": {"contents": {"packages": pk}}})
    mkapk(pr + "/inputs.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"binA"}, control={".melange.yaml": envy(["%s=%s" % p for p in ENVPK]).encode()})
    mkapk(pr + "/inputs-bad.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"binA"}, control={".melange.yaml": envy(["%s=%s" % p for p in ENVPK] + ["bash=5.2-r0"]).encode()})
    mkapk(pr + "/nobin.apk", "fscache", "0.3.0-r0", {"usr/share/x": b"same"})
    sb = fx + "/sbom"; os.makedirs(sb, exist_ok=True)
    open(sb + "/modules.txt", "w").write("# github.com/example/x v1.0.0\n## explicit; go 1.20\ngithub.com/example/x\n# golang.org/x/sys v0.30.0\n## explicit; go 1.18\ngolang.org/x/sys/unix\n# example.org/unbuilt v2.0.0\n## explicit; go 1.20\nexample.org/unbuilt\n")
    head = "/usr/bin/fscache: go1.27.2\n\tpath\tgithub.com/fosterstack/cache/cmd/fscache\n\tmod\tgithub.com/fosterstack/cache\tv0.3.0\n"
    dep = "\tdep\tgithub.com/example/x\tv1.0.0\n\tdep\tgolang.org/x/sys\tv0.30.0\n"
    tail = "\tbuild\t-trimpath=true\n\tbuild\tvcs.modified=false\n"
    prov = lambda ms: json.dumps({"modules": [{"path": p, "version": v} for p, v in ms]})
    open(sb + "/prov-unbuilt.json", "w").write(prov([("github.com/example/x", "v1.0.0"), ("golang.org/x/sys", "v0.30.0"), ("example.org/unbuilt", "v2.0.0")]))
    open(sb + "/ok.txt", "w").write(head + dep + tail)
    open(sb + "/extra.txt", "w").write(head + dep + "\tdep\texample.org/evil\tv9.9.9\n" + tail)
    open(sb + "/ver.txt", "w").write(head + dep.replace("v0.30.0", "v0.31.0") + tail)
    open(sb + "/provenance.json", "w").write(prov([("github.com/example/x", "v1.0.0"), ("golang.org/x/sys", "v0.30.0")]))
    open(sb + "/provenance-nosys.json", "w").write(prov([("github.com/example/x", "v1.0.0")]))
    open(sb + "/missing.txt", "w").write(head + "\tdep\tgithub.com/example/x\tv1.0.0\n" + tail)
    open(sb + "/devel.txt", "w").write(head.replace("v0.3.0", "(devel)") + dep + tail)
    open(sb + "/dirty.txt", "w").write(head + dep + "\tbuild\tvcs.modified=true\n")
    os.makedirs(fx + "/oci", exist_ok=True); open(fx + "/oci/lock", "w").write("lock")
    stuboci(fx + "/oci/good.tar", fx + "/oci/lock", "", "1")
    stuboci(fx + "/oci/tampered.tar", fx + "/oci/lock", "", "1", tamper=True)
    stuboci(fx + "/oci/noindex.tar", fx + "/oci/lock", "", "1", noindex=True)
    stubapkotar(fx + "/oci/apko.tar"); stubapkotar(fx + "/oci/apko-tampered.tar", tamper=True)
    open(sb + "/nofips.txt", "w").write(head + dep + tail)
def mutate(src, dst, op, arg=""):
    d = json.load(open(src)); pk = d["contents"]["packages"]
    if op == "datasum":
        for e in pk:
            if e["name"] == arg: e["data"]["checksum"] = "sha256-AAAA"
    elif op == "extra": pk.append(dict(pk[0], name=arg))
    elif op == "drop": d["contents"]["packages"] = [e for e in pk if e["name"] != arg]
    elif op == "dropone": d["contents"]["packages"] = [e for e in pk if not (e["name"] == arg and e["architecture"] == "aarch64")]
    elif op == "archver":
        for e in pk:
            if e["name"] == "tzdata" and e["architecture"] == "aarch64": e["version"] = "2026b-r0"
    elif op == "urls-only":
        for e in pk: e["url"] = "https://elsewhere.example/" + e["name"]
        d["config"]["checksum"] = "other"
    json.dump(d, open(dst, "w"), indent=1, sort_keys=True)
def edit(src, dst, old, new):
    t = open(src).read(); assert old in t, old; open(dst, "w").write(t.replace(old, new, 1))
def flipdigest(src, dst):
    t = open(src).read(); m = re.search(r"[0-9a-f]{64}", t); h = m.group(0); c = "0" if h[0] != "0" else "1"
    open(dst, "w").write(t[:m.start()] + c + h[1:] + t[m.end():])
def stubsign(path, signame, key=None):
    raw = open(path, "rb").read(); parts = split(raw)
    has_sig = any(n.startswith(".SIGN.") for n in [m.name for m in tarfile.open(fileobj=io.BytesIO(parts[0][1])).getmembers()])
    rest = b"".join(p[0] for p in (parts[1:] if has_sig else parts))
    ctrl = (parts[1:] if has_sig else parts)[0][0]
    sigbytes = realsig(ctrl, key, "sha256") if key and os.path.exists(key) and not os.environ.get("STUB_FAKE_SIG") else b"stub-signature"
    open(path, "wb").write(gz(tarb([(".SIGN.RSA256." + signame, sigbytes)])) + rest)
def tamper(path):
    b = bytearray(open(path, "rb").read()); b[len(b) - 12] ^= 0xFF; open(path, "wb").write(bytes(b))
def split(raw):
    out = []
    while raw:
        d = zlib.decompressobj(31); data = d.decompress(raw); used = len(raw) - len(d.unused_data)
        out.append((raw[:used], data)); raw = d.unused_data
    return out
def stubbuild(recipe_path, out, arch, cache):
    d = yaml.safe_load(open(recipe_path)); pkg = d["package"]; name = pkg["name"]; ver = str(pkg["version"])
    goarch = {"x86_64": "amd64", "aarch64": "arm64"}[arch]
    for s in d.get("pipeline", []):
        if s.get("uses") == "fetch" and ("linux-" + goarch) in s["with"]["uri"]:
            f = os.path.join(cache, "sha256:" + str(s["with"]["expected-sha256"]))
            if not os.path.isfile(f): sys.exit("stub melange: fetch %s would need the network: not pre-seeded in the cache dir" % s["with"]["uri"])
            if hashlib.sha256(open(f, "rb").read()).hexdigest() != s["with"]["expected-sha256"]: sys.exit("stub melange: fetch checksum mismatch")
    bi = os.environ.get("STUB_BUILDINFO")
    if bi: text = open(bi).read()
    else:
        text = ("/usr/bin/fscache: go1.27.2\n\tpath\tgithub.com/fosterstack/cache/cmd/fscache\n\tmod\tgithub.com/fosterstack/cache\tv0.3.0\n"
                "\tdep\tgithub.com/example/x\tv1.0.0\n\tdep\tgolang.org/x/sys\tv0.30.0\n\tbuild\t-trimpath=true\n\tbuild\tvcs.revision=" + subprocess.run(["git", "-C", os.environ.get("STUB_SRC", "."), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip() + "\n\tbuild\tvcs.modified=false\n")
        if name.endswith("-fips"): text += "\tbuild\tGOFIPS140=v1.0.0-c2097c7c\n"
    files = {"usr/bin/fscache": ("fscache-binary %s %s %s" % (name, arch, os.environ.get("STUB_SALT", ""))).encode(), "usr/share/fscache/buildinfo.txt": text.encode()}
    envd = d.get("environment", {})
    if os.environ.get("STUB_ENV_EXTRA"): envd = {"contents": {"packages": list(envd.get("contents", {}).get("packages", [])) + [os.environ["STUB_ENV_EXTRA"]]}}   # a package melange used that is not in the lock
    ctl = {".melange.yaml": yaml.safe_dump({"package": {"name": name}, "environment": envd}).encode()}
    mkapk("%s/%s/%s-%s-r0.apk" % (out, arch, name, ver), name, ver + "-r0", files, control=ctl, signer=os.environ.get("STUB_SIGNER", "assembly.rsa.pub"), signkey=os.environ.get("STUB_SIGNKEY") or None)
    open("%s/%s/APKINDEX.tar.gz" % (out, arch), "wb").write(b"index")
def stuboci(out, lockfile, salt, sde, tamper=False, noindex=False):
    seed = hashlib.sha256(open(lockfile, "rb").read()).hexdigest() + salt + sde
    if os.environ.get("STUB_OCI_REAL"): return stubapkotar(out, tamper, seed=seed)   # the tar real apko writes (the layout the script must unpack)
    H = lambda b: hashlib.sha256(b).hexdigest()
    blobs, mans = [], []
    for arch in ("amd64", "arm64"):
        cfg = json.dumps({"architecture": arch, "os": "linux", "seed": seed}, sort_keys=True).encode()
        layer = ("layer-bytes-%s-%s" % (arch, seed)).encode()   # a non-empty layer: an assembler that drops layers would no longer pass
        man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                          "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + H(cfg), "size": len(cfg)},
                          "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + H(layer), "size": len(layer)}]}, sort_keys=True).encode()
        blobs += [(H(cfg), cfg), (H(layer), layer), (H(man), man)]
        mans.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + H(man), "size": len(man), "platform": {"architecture": arch, "os": "linux"}})
    idx = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": mans}, sort_keys=True).encode()
    blobs.append((H(idx), idx))
    top = json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:" + H(idx), "size": len(idx)}]}, sort_keys=True).encode()
    members = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')] + ([] if noindex else [("index.json", top)])
    for i, (h, b) in enumerate(blobs):
        members.append(("blobs/sha256/" + h, b + b"X" if tamper and i == 2 else b))   # tamper: a manifest blob whose bytes no longer hash to its name
    open(out, "wb").write(tarb(members))
def stubapkotar(out, tamper=False, seed=""):
    # the shape real apko v1.4.6 writes (real-run finding Oct 9): blobs are top-level members named sha256:<hex>, index.json is the
    # multi-arch index itself (it lists the per-arch manifests), manifest.json is the docker-style list, and there is no oci-layout
    H = lambda b: hashlib.sha256(b).hexdigest()
    members, mans = [], []
    for arch in ("amd64", "arm64"):
        cfg = json.dumps(dict({"architecture": arch, "os": "linux"}, **({"seed": seed} if seed else {})), sort_keys=True).encode()
        layer = ("layer-bytes-%s-%s" % (arch, seed)).encode()
        man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                          "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + H(cfg), "size": len(cfg)},
                          "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + H(layer), "size": len(layer)}]}, sort_keys=True).encode()
        members += [("sha256:" + H(cfg), cfg), ("sha256:" + H(layer), layer), ("sha256:" + H(man), man + b"X" if tamper and arch == "arm64" else man)]
        mans.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + H(man), "size": len(man), "platform": {"architecture": arch, "os": "linux"}})
    idx = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": mans}).encode()
    members += [("manifest.json", b"[]"), ("index.json", idx)]
    open(out, "wb").write(tarb(members))
def lockshape(path, variant):
    d = json.load(open(path)); assert d["version"] == "v1"
    pk = d["contents"]["packages"]; assert pk, "no packages"
    names = {e["name"] for e in pk}
    assert {"wolfi-baselayout", "ca-certificates-bundle", "tzdata"} <= names, sorted(names)
    assert not any(n.startswith("fscache") for n in names), "base lock holds our apk"
    for a in ARCHS: assert any(e["architecture"] == a for e in pk), a
    seen = {}
    for e in pk: seen.setdefault(e["name"], {}).setdefault(e["architecture"], []).append(e["version"])
    for n, by in sorted(seen.items()):   # every package is locked for BOTH architectures, once each, at one version
        assert sorted(by) == sorted(ARCHS), (n, sorted(by))
        assert all(len(v) == 1 for v in by.values()), (n, by)
        assert len({v[0] for v in by.values()}) == 1, (n, by)
    for e in pk:
        assert e["control"]["checksum"].startswith("sha1-") and e["data"]["checksum"].startswith("sha256-") and e["checksum"].startswith("Q1"), e["name"]
        assert e["url"].startswith("/work/archive/"), e["url"]
    assert not [r for r in d["contents"]["repositories"] if "://" in r["url"]]
    assert d["contents"]["keyring"] and all(k.get("content") for k in d["contents"]["keyring"])
if __name__ == "__main__":
    c, a = sys.argv[1], sys.argv[2:]
    {"edit": lambda: edit(*a), "flipdigest": lambda: flipdigest(*a), "fixtures": lambda: fixtures(*a), "mutate": lambda: mutate(*a), "tamper": lambda: tamper(*a),
     "stubbuild": lambda: stubbuild(*a), "stubsign": lambda: stubsign(*a), "stuboci": lambda: stuboci(a[0], a[1], a[2], a[3], bool(os.environ.get("STUB_OCI_TAMPER")), bool(os.environ.get("STUB_OCI_NOINDEX"))), "lockshape": lambda: lockshape(*a)}[c]()
PY

# ---------- static checker (yaml/json/md on the file a rule lives in) ---------------------------------------------------
cat >"$work/chk.py" <<'PY'
import glob, json, os, re, sys, yaml
mode, path = sys.argv[1], sys.argv[2]
arg = sys.argv[3] if len(sys.argv) > 3 else ""
root = os.environ.get("ROOT", ".")
def text(): return open(path).read()
def load(): return yaml.safe_load(open(path))
def pk(c): return [str(p) for p in (c.get("contents") or {}).get("packages", [])]
def names(c): return {p.split("=")[0] for p in pk(c)}
def pipe(d): return "\n".join(str(s.get("runs", "")) for s in d.get("pipeline", []))
def kv(blob, k, v): return re.search(r"%s\s*[=:]\s*[\"']?%s[\"']?(\s|$)" % (re.escape(k), re.escape(v)), blob)
PINNED = r"[a-z0-9.+_-]+=\d[\w.+~-]*"
def fipsmod():
    """the module id the FIPS recipe must use: the one build/locks/fips-module.txt names (FIPS_LOCK names another lock file in a test), read as one line
    vMAJOR.MINOR.PATCH-<8 lower-case hex> and a plain newline, the grammar the driver and the daily refresh read it with; anything else fails"""
    f = os.environ.get("FIPS_LOCK") or os.path.join(root, "build/locks/fips-module.txt")
    raw = open(f, "rb").read().decode("ascii")
    num = r"(?:0|[1-9][0-9]*)"
    assert raw.endswith("\n") and raw.count("\n") == 1 and re.fullmatch(r"v%s\.%s\.%s-[0-9a-f]{8}" % (num, num, num), raw[:-1]), "%s is not one module id line" % f
    return raw[:-1]
if mode == "mel-name":
    d = load(); assert d["package"]["name"] == arg, d["package"]["name"]
    assert d["package"]["version"] == "@VERSION@" and int(d["package"]["epoch"]) == 0 and d["package"].get("copyright")
elif mode == "mel-build":
    d = load(); p = pipe(d)
    assert "go build" in p and "./cmd/fscache" in p and "-trimpath" in p and "/usr/bin/fscache" in p and "${{targets.destdir}}" in p
    assert not re.search(r"^\s*FROM\s", text(), re.M)
elif mode == "mel-env":
    b = text()
    for k, v in (("GOFLAGS", "-mod=vendor"), ("GOPROXY", "off"), ("CGO_ENABLED", "0"), ("GOTOOLCHAIN", "local")): assert kv(b, k, v), k
    for x in ("-mod=mod", "-mod=readonly", "go mod download", "go get ", "curl ", "GOPROXY=http", "GOSUMDB=off"): assert x not in b, x
elif mode == "mel-fips":
    b = text()
    if arg == "fips":
        v = fipsmod().split("-")[0]
        assert kv(b, "GOFIPS140", v), "fips recipe does not set GOFIPS140=%s (the version of the module build/locks/fips-module.txt names)" % v
    else: assert "GOFIPS140" not in b, "standard recipe mentions GOFIPS140"
elif mode == "mel-fipsproof":
    m = fipsmod(); p = pipe(load()); assert "go version -m" in p and re.search(r"GOFIPS140=%s(['\"\s]|$)" % re.escape(m), p), "no proof of the recorded %s" % m   # the id ends at a quote, whitespace or the end: a longer id with this one as its prefix is another module
elif mode == "mel-go":
    d = load(); ps = pk(d["environment"])
    assert not any(re.match(r"go([-=.]|$)", p) for p in ps), "a Wolfi go package is installed"
    fetch = [s for s in d["pipeline"] if s.get("uses") == "fetch" and "go.dev" in str(s.get("with", {}).get("uri", ""))]
    assert len(fetch) >= 2, "need one go.dev fetch per arch"
    sums, arches, vers = set(), set(), set()
    for s in fetch:
        w = s["with"]; m = re.fullmatch(r"https://go\.dev/dl/go(\d+\.\d+(?:\.\d+)?)\.linux-(amd64|arm64)\.tar\.gz", w["uri"]); assert m, w["uri"]
        assert re.fullmatch(r"[0-9a-f]{64}", str(w.get("expected-sha256", ""))), "no sha256 pin"
        assert "expected-none" not in w, "checksum skipped"
        sums.add(w["expected-sha256"]); arches.add(m.group(2)); vers.add(m.group(1))
    assert arches == {"amd64", "arm64"} and len(sums) == 2 and len(vers) == 1, (arches, len(sums), vers)
    assert "wget" in names(d["environment"]), "fetch needs wget in the environment (pipelines/fetch.yaml:4-6)"
    mod = re.search(r"^go (\d+(?:\.\d+)*)", open(os.path.join(root, "go.mod")).read(), re.M).group(1)
    key = lambda s: [int(x) for x in s.split(".")] + [0] * (3 - len(s.split(".")))
    assert key(mod) <= key(vers.pop()), "go.mod needs a newer Go than the archived one: " + mod
elif mode == "mel-fetch-arch":
    # real-run finding (Oct 9): melange runs every pipeline step, so each go.dev fetch needs an `if` on its own architecture
    d = load(); want = {"amd64": "x86_64", "arm64": "aarch64"}
    for s in d["pipeline"]:
        if s.get("uses") == "fetch" and "go.dev" in str(s["with"]["uri"]):
            g = re.search(r"linux-(amd64|arm64)", s["with"]["uri"]).group(1)
            assert want[g] in str(s.get("if", "")) and "build.arch" in str(s.get("if", "")), "fetch for " + g + " has no if on build.arch == " + want[g]
elif mode == "mel-fetch-dir":
    # real-run finding (Oct 9): fetch runs `tar -C <directory>`, which must exist; a step before the first fetch creates it
    steps = load()["pipeline"]; first = next(i for i, x in enumerate(steps) if x.get("uses") == "fetch")
    assert any("mkdir -p /usr/local/go" in str(x.get("runs", "")) for x in steps[:first]), "no step creates /usr/local/go before the first fetch"
elif mode == "mel-fetch-delete":
    # real-run finding (Oct 9): fetch leaves the tarball in the source tree, which makes the Go stamp say vcs.modified=true
    for st in load()["pipeline"]:
        if st.get("uses") == "fetch" and "go.dev" in str(st["with"]["uri"]):
            assert str(st["with"].get("delete")).lower() == "true", "the Go tarball is left in the source tree: " + st["with"]["uri"]
elif mode == "mel-local":
    d = load(); b = text()
    for l in b.splitlines():
        if "://" in l: assert re.search(r"go\.dev/dl/|github\.com/fosterstack", l), "network address in recipe: " + l.strip()
    assert "packages.wolfi.dev" not in b and "cgr.dev" not in b
    c = d["environment"].get("contents", {})
    for k in ("repositories", "keyring"): assert all(str(x).startswith("/") for x in c.get(k, [])), k
elif mode == "mel-pinned":
    d = load(); ps = pk(d["environment"]); assert ps
    for p in ps: assert re.fullmatch(PINNED, p), "not pinned: " + p
    for need in ("git", "busybox", "ca-certificates-bundle", "wget"): assert need in names(d["environment"]), need
elif mode == "mel-stamp":
    d = load(); p = pipe(d)
    assert re.search(r"mkdir -p \.git/refs/heads \.git/refs/tags", p), "refs not recreated"
    assert re.search(r"git config --global --add safe\.directory", p)
    assert re.search(r"GOPATH=/tmp/\S+", p) and re.search(r"GOCACHE=/tmp/\S+", p)
    assert ".git/info/exclude" in p and ".melange" in p and ".gitconfig" in p and "-buildvcs=false" not in text()
    assert "git" in names(d["environment"])
elif mode == "mel-proof":
    p = pipe(load()); assert "go version -m" in p and "devel" in p and re.search(r"modified|dirty", p)
elif mode == "mel-buildinfo":
    p = pipe(load()); assert "usr/share/fscache/buildinfo.txt" in p and "go version -m" in p
elif mode == "apko-pkgs":
    d = load(); fs = "fscache-fips" if arg == "fips" else "fscache"
    assert names(d) == {"wolfi-baselayout", "ca-certificates-bundle", "tzdata", fs}, sorted(names(d))
    assert f"{fs}=@FSCACHE_VERSION@-r0" in pk(d)
    for p in pk(d): assert re.fullmatch(PINNED, p) or p == f"{fs}=@FSCACHE_VERSION@-r0" or "=" not in p, p
    assert "baseimage" not in text().lower() and "include" not in d and "debug" not in text().lower()
elif mode == "apko-repos":
    c = load()["contents"]; assert c["repositories"] == ["/work/archive", "/work/melange-repo"], c["repositories"]
    assert "://" not in text() and "wolfi.dev" not in text()
elif mode == "apko-keys":
    k = load()["contents"]["keyring"]; assert all(x.startswith("/") for x in k)
    assert any(x.endswith("wolfi-signing.rsa.pub") for x in k) and any(x.endswith("assembly.rsa.pub") for x in k), k
elif mode == "apko-archs":
    assert set(load()["archs"]) == {"x86_64", "aarch64"}
elif mode == "apko-user":
    d = load(); a = d["accounts"]
    assert any(g["gid"] == 65532 for g in a["groups"])
    us = [u for u in a["users"] if u["uid"] == 65532]; assert us and us[0]["gid"] == 65532 and us[0]["homedir"] == "/home/nonroot"
    assert str(a["run-as"]) in ("65532", "nonroot")
    ph = [x for x in d["paths"] if x["path"] == "/home/nonroot"]
    assert ph and ph[0]["type"] == "directory" and ph[0]["uid"] == 65532 and ph[0]["gid"] == 65532
    assert d["work-dir"] == "/home/nonroot" and d["entrypoint"]["command"] == "/usr/bin/fscache"
elif mode == "apko-noshell":
    d = load(); assert not (names(d) & {"busybox", "bash", "sh", "dash", "zsh", "ash", "wolfi-base"})
    e = d.get("entrypoint", {}); assert "shell-fragment" not in e and "/sh" not in str(e.get("command", ""))
    assert not re.search(r"/(bin|busybox)/(ba)?sh", text())
elif mode == "dependabot":
    d = load()
    for u in d["updates"]:
        assert not re.search(r"apko|melange|apk|lock|/build/locks", json.dumps(u), re.I), u
        assert u["directory"] in ("/", "/.github/agent", "/tools/govulncheck"), u["directory"]   # /tools/govulncheck: the Check stage's pinned Go source scanner is its own module (advisor Oct 12, ruling G); it is not an apk, apko, melange or lock-file entry
elif mode == "wf":
    d = load(); on = d.get(True) or d.get("on"); jobs = d["jobs"]; j = jobs[arg]; blob = json.dumps(j)
    if arg == "refresh":
        assert "bin/refresh-inputs.sh refresh" in blob and "23 6 * * *" in str(j.get("if", "")), "daily job"
        assert not re.search(r"pr merge|--admin|auto-merge|--auto|--no-verify|skip ci", blob, re.I)
        assert not re.search(r"git push[^\"]*\bmain\b", blob)
    else:
        assert "bin/refresh-inputs.sh fips-module" in blob
        crons = [s["cron"] for s in on["schedule"] if s["cron"].split()[4] != "*"]
        assert crons and any(c in str(j.get("if", "")) for c in crons), "weekly schedule"
    for st in j.get("steps", []):
        if "uses" in st: assert re.search(r"@[0-9a-f]{40}$", st["uses"]), "action not pinned by digest: " + st["uses"]
elif mode == "doc-key":
    b = text().lower()
    assert re.search(r"yearly|every year|annual|12 months", b) and re.search(r"suspect[^.]{0,40}(leak|compromise)|(leak|compromise)[^.]{0,40}suspect", b) and re.search(r"at once|immediately", b)
    assert "build/keys/release.rsa.pub" in b and "public key" in b and re.search(r"first (chain )?release", b) and "placeholder" in b
    assert re.search(r"non-secret|not secret", b) and "assembly" in b and re.search(r"nothing a customer trusts", b)
    assert "BEGIN PUBLIC KEY" in open(os.path.join(root, "build/keys/assembly.rsa.pub")).read()
    assert "-----BEGIN" not in open(os.path.join(root, "build/keys/release.rsa.pub")).read(), "release.rsa.pub is a placeholder (no PEM block) until the real public half is committed"
    assert os.path.isfile(os.path.join(root, "build/keys/assembly.rsa"))
elif mode == "pins":
    b = text()
    for tool in ("melange", "apko"):
        assert re.search(r"releases/download/v\d+\.\d+\.\d+/%s_\d" % tool, b), tool + " version pin (a literal release address, REQ-SUP-001-AC18)"
    assert len(set(re.findall(r"\b[0-9a-f]{64}\b", b))) >= 4, "four checksums (two tools x two arches)"
    assert "cgr.dev" not in b and not re.search(r"docker (run|pull)|@sha256:", b)
    i = min(b.find(x) for x in ("sha256sum", "shasum -a 256") if x in b); j = b.find("tar ")
    assert 0 <= i < j, "checksum must be verified before the archive is extracted"
PY
y() { ROOT="$root" python3 "$work/chk.py" "$@"; }
# nogrep <rule> <desc> <regex> <file...>: every file must exist and none may match
nogrep() { local ac=$1 d=$2 re=$3; shift 3; local f; for f in "$@"; do [ -f "$f" ] || { bad "$ac" "$d (missing $f)"; return; }; done
  if grep -Eqi -- "$re" "$@"; then bad "$ac" "$d"; else ok; fi; }
# fails <rule> <desc> <keyword> <cmd...>: the command must EXIT NON-ZERO (not 126/127: a missing tool is not a refusal) and its output must name the reason
fails() { local ac=$1 d=$2 kw=$3; shift 3; "$@" >"$work/o" 2>&1; local r=$?; if [ $r -ne 0 ] && [ $r -ne 126 ] && [ $r -ne 127 ] && grep -Eqi -- "$kw" "$work/o"; then ok; else bad "$ac" "$d (exit $r, wanted failure naming '$kw')"; fi; }
yesgrep() { local ac=$1 d=$2 re=$3 f=$4; if [ -f "$f" ] && grep -Eq -- "$re" "$f"; then ok; else bad "$ac" "$d"; fi; }

# ---------- stubs: the tools record their argv in $CALLS ----------------------------------------------------------------
cat >"$stubs/uname" <<'EOF'
#!/bin/sh
case "$1" in -m) echo "${FAKE_UNAME:-x86_64}";; *) echo "${FAKE_OS:-Linux}";; esac
EOF
cat >"$stubs/sudo" <<'EOF'
#!/bin/bash
echo "sudo $*" >>"$CALLS"
keep=0
while [ $# -gt 0 ]; do case "$1" in -E|--preserve-env) keep=1; shift;; -u) shift 2;; -n|-H|-S) shift;; --) shift; break;; *) break;; esac; done
resolves() { case "$1" in */*) [ -f "$1" ] && [ -x "$1" ];; *) type -P "$1" >/dev/null 2>&1;; esac; }   # as exec would: a bare name by the search path only, a name with a slash as a path
[ -z "${1:-}" ] || resolves "$1" || { echo "sudo: $1: command not found" >&2; exit 127; }   # before any log-only success below: an operand that does not resolve is never a silent success
[ "${1:-}" = mkdir ] && [ "${2:-}" != -p ] && [ -n "${STUB_SUDO_FAIL_MKDIR:-}" ] && { echo "stub sudo: mkdir failed (exists)" >&2; exit 1; }
if [ "${1:-}" = ln ] && [ -n "${STUB_LN_FAIL_AT:-}" ]; then
  n=$(cat "$CALLS.ln" 2>/dev/null || echo 0); n=$((n+1)); echo $n >"$CALLS.ln"
  [ "$n" = "$STUB_LN_FAIL_AT" ] && { echo "stub sudo: ln: File exists" >&2; exit 1; }
fi
case "$(basename "${1:-}")" in env|unshare|sysctl|melange|apko|bash) ;; *) exit 0;; esac   # ln, mkdir, mount...: logged, never run (the drivers name their tools by path)
if [ $keep = 1 ]; then exec "$@"; fi
if [ "${1:-}" = env ] && [ "${2:-}" = -i ]; then exec "$@"; fi   # an EXPLICIT environment (env -i ...) is the whole environment: the stub adds nothing
pass=(); while IFS= read -r l; do pass+=("$l"); done < <(env | grep -E '^(STUB_|FAKE_|CALLS=|ImageOS=|ImageVersion=)')
exec env -i PATH="$PATH" "${pass[@]}" "$@"     # sudo's env_reset: only what the driver passes on survives
EOF
cat >"$stubs/unshare" <<'EOF'
#!/bin/bash
echo "unshare $*" >>"$CALLS"
while [ $# -gt 0 ]; do case "$1" in -*) shift;; *) break;; esac; done
case "$*" in *net-probe.py*) { case "$1" in */*) [ -f "$1" ] && [ -x "$1" ];; *) type -P "$1" >/dev/null 2>&1;; esac; } || { echo "unshare: failed to execute $1: No such file or directory" >&2; exit 127; }   # the probe really resolves the program it is asked to run
  if [ -n "${STUB_PROBE_RC:-}" ]; then exit "$STUB_PROBE_RC"; elif [ -n "${STUB_UNSHARE_LEAKY:-}" ]; then exit 0; else exit 101; fi;; esac   # the stub plays the kernel: no route in a sealed namespace = ENETUNREACH (101)
[ -n "${STUB_UNSHARE_LEAKY:-}" ] || export FAKE_SEALED=1
exec "$@"
EOF
cat >"$stubs/sysctl" <<'EOF'
#!/bin/bash
echo "sysctl $*" >>"$CALLS"
EOF
cat >"$stubs/melange" <<'EOF'
#!/bin/bash
echo "melange $*" >>"$CALLS"
sub=${1:-}; shift
if [ "$sub" = sign ]; then   # the stub signs by rewriting the signature stream: .SIGN.RSA256.<basename of the key>.pub (what melange names it)
  key= apk=; while [ $# -gt 0 ]; do case $1 in --signing-key) key=$2; shift 2;; -*) shift;; *) apk=$1; shift;; esac; done
  if [ -n "${STUB_SIGN_FAIL_AT:-}" ] && [ "$(grep -c '^melange sign' "$CALLS")" = "$STUB_SIGN_FAIL_AT" ]; then echo "stub melange sign: failed" >&2; exit 1; fi
  python3 "$STUB_LIB" stubsign "$apk" "${STUB_SIGN_AS:-$(basename "$key").pub}" "$key"; exit $?
fi
[ "$sub" = build ] || exit 0
if [ -n "${STUB_NETATTEMPT:-}" ]; then python3 - <<'P'
import errno, os, sys
print(os.environ.get("STUB_NETTEXT") or ("dial tcp 192.0.2.1:443: connect: " + os.strerror(errno.ENETUNREACH) + " (ENETUNREACH)"), file=sys.stderr); sys.exit(errno.ENETUNREACH)   # a stub that attempted socket.connect in the netless namespace
P
exit $?; fi
[ -n "${STUB_FAIL:-}" ] && { echo "stub: compile error: undefined: foo" >&2; exit 1; }
arch= out=./packages cache= src= recipe= repoapp=
while [ $# -gt 0 ]; do case $1 in
  --arch) arch=$2; shift 2;; --out-dir) out=$2; shift 2;; --cache-dir) cache=$2; shift 2;; --source-dir) src=$2; shift 2;;
  --signing-key) STUB_SIGNKEY=$2; shift 2;;
  --repository-append) repoapp=$2; shift 2;;
  --runner|--keyring-append|--build-date|--workspace-dir|--apk-cache-dir|-k|-r|--env-file|--vars-file|--namespace) shift 2;;
  -*) shift;; *) recipe=$1; shift;; esac; done
echo "ENV SDE=${SOURCE_DATE_EPOCH-unset}" >>"$CALLS"
[ -n "${STUB_LOCKED_CACHE:-}" ] && [ -n "$cache" ] && { mkdir -p "$cache/x/y" && : >"$cache/x/y/f" && chmod 500 "$cache/x/y" "$cache/x"; }   # a tree the invoking user cannot remove (the cleanup fallback)
echo "ENV CACHE=$( [ -n "$cache" ] && ls "$cache" 2>/dev/null | tr '\n' ' ')" >>"$CALLS"
echo "ENV SECRETS=$(env | grep -Ec '(TOKEN|SECRET|PRIVATE|SIGNING_KEY)')" >>"$CALLS"
echo "ENVNAMES=$(env | cut -d= -f1 | grep -Ev '^(STUB_|FAKE_|CALLS$|ImageOS$|ImageVersion$|PWD$|SHLVL$|_$|OLDPWD$)' | sort | tr '\n' ' ')" >>"$CALLS"
[ -d "$src/vendor" ] || { echo "stub melange: go build: no vendor directory" >&2; exit 1; }
if [ -n "${STUB_REQUIRE_REPO:-}" ] && [ -n "$repoapp" ]; then   # like melange: every pinned environment package must be selectable from the repository it was given
  while IFS= read -r pin; do
    [ -f "$repoapp/$arch/${pin%%=*}-${pin#*=}.apk" ] || { echo "ERROR: unable to select packages:" >&2; echo "  ${pin%%=*}-${pin#*=} (no such package):" >&2; exit 1; }
  done < <(sed -n 's/^ *- \([A-Za-z0-9._+-]*=[A-Za-z0-9._+~-]*\) *$/\1/p' "$recipe")
fi
STUB_SIGNKEY="${STUB_SIGNKEY:-}" STUB_SRC="$src" python3 "$STUB_LIB" stubbuild "$recipe" "$out" "$arch" "$cache"
EOF
cat >"$stubs/apko" <<'EOF'
#!/bin/bash
echo "apko $*" >>"$CALLS"
sub=${1:-}; shift
cfg= out= lockf= sbom= tar=; pos=()
while [ $# -gt 0 ]; do case $1 in
  --output) out=$2; shift 2;; --lockfile) lockf=$2; shift 2;; --sbom-path) sbom=$2; shift 2;; --cache-dir) cachedir=$2; shift 2;;
  --arch|--keyring-append|-k|--repository-append|-r|-b|--build-repository-append|--include-paths|--build-date|--sbom-formats|-p|--annotations|--format) shift 2;;
  -*) shift;; *) pos+=("$1"); shift;; esac; done
cfg=${pos[0]:-}
if [ -n "${STUB_NETATTEMPT:-}" ]; then python3 - <<'P'
import errno, os, sys
print(os.environ.get("STUB_NETTEXT") or ("dial tcp 192.0.2.1:443: connect: " + os.strerror(errno.ENETUNREACH) + " (ENETUNREACH)"), file=sys.stderr); sys.exit(errno.ENETUNREACH)   # a stub that attempted socket.connect in the netless namespace
P
exit $?; fi
[ -n "${STUB_FAIL:-}" ] && { echo "stub: compile error: undefined: foo" >&2; exit 1; }
echo "ENV SDE=${SOURCE_DATE_EPOCH-unset}" >>"$CALLS"
if [ -n "${STUB_LOCKED_CACHE:-}" ] && [ -n "${cachedir:-}" ]; then mkdir -p "$cachedir/x/y" && : >"$cachedir/x/y/f" && chmod 500 "$cachedir/x/y" "$cachedir/x"; fi   # a cache written by "root": the invoking user cannot remove it
[ "$sub" = lock ] || [ "$sub" = build ] && { [ -f "$cfg" ] || { echo "stub apko: config $cfg not found from $PWD" >&2; exit 1; }; }
if grep -Eq 'https?://' "$cfg" 2>/dev/null; then echo "stub apko: network is unreachable" >&2; exit 1; fi
case $sub in
  lock) case "$cfg $out" in *host-tools*) s=${STUB_LOCK_HOST:-${STUB_LOCK_MEL:-}}; cp "$cfg" "$CALLS.hostcfg";; *melange*) s=${STUB_LOCK_MEL:-};; *fips*) s=${STUB_LOCK_FIPS:-};; *) s=${STUB_LOCK:-};; esac
        [ -n "$out" ] && [ -f "$s" ] || { echo "stub apko lock: nothing to write" >&2; exit 1; }; cp "$s" "$out";;
  build) [ -f "$lockf" ] || { echo "stub apko build: no lock file" >&2; exit 1; }
        [ -z "${STUB_CAPTURE_LOCK:-}" ] || cp "$lockf" "$STUB_CAPTURE_LOCK"   # what the build was actually given (opt-in: the tests compare it with the generated lock)
        python3 "$STUB_LIB" stuboci "${pos[2]:-/dev/null}" "$lockf" "${STUB_SALT:-}" "${SOURCE_DATE_EPOCH-unset}"
        [ -n "$sbom" ] && { [ -d "$sbom" ] || { echo "stub apko: --sbom-path $sbom is not an existing directory (real apko renames into it, build.go: moving sbom)" >&2; exit 1; }; echo '{"spdxVersion":"SPDX-2.3"}' >"$sbom/sbom-spdx.json"; };;   # real-run finding Oct 9: the directory must already exist
esac
exit 0
EOF
cat >"$stubs/curl" <<'EOF'
#!/bin/bash
echo "curl $*" >>"$CALLS"
out= url=
while [ $# -gt 0 ]; do case $1 in -o|--output|-[a-zA-Z]*o) out=$2; shift 2;; -*) shift;; *) url=$1; shift;; esac; done
b=${url##*/}; rest=${url%/*}; a=${rest##*/}
if [ "$b" = wolfi-signing.rsa.pub ] && [ -n "${STUB_LIVE_KEY:-}" ]; then src=$STUB_LIVE_KEY
elif [ -n "${STUB_CURL_DIR:-}" ] && [ -f "$STUB_CURL_DIR/$a/$b" ]; then src=$STUB_CURL_DIR/$a/$b
elif [ -n "${STUB_CURL_BOGUS:-}" ]; then [ -n "$out" ] && printf bogus >"$out" || printf bogus; exit 0
else echo "stub curl: 22 $url" >&2; exit 22; fi
if [ -n "$out" ]; then cp "$src" "$out"; else cat "$src"; fi
EOF
for g in git gh; do cat >"$stubs2/$g" <<EOF
#!/bin/bash
echo "$g \$*" >>"\$CALLS"
[ "$g" = gh ] && case "\$*" in "pr list"*) echo '[]';; esac
[ "$g" = git ] && case "\$*" in *"rev-parse HEAD"*) echo cafe0123;; esac
[ "$g" = gh ] && { case "\$*" in "api graphql"*) [ -z "\${GH_STUB_API_FAIL:-}" ] || { echo "gh: HTTP 502" >&2; exit 1; }; _in=; _p=; for _a in "\$@"; do [ "\$_p" = --input ] && _in=\$_a; _p=\$_a; done; [ -z "\$_in" ] || cp "\$_in" "\$CALLS.graphql"; echo abcdef0123456789abcdef0123456789abcdef01; exit 0;; "api repos/"*"/commits/"*) echo "\${GH_STUB_VERIFIED:-true}"; exit 0;; esac }
exit 0
EOF
done
cp "$stubs2/gh" "$stubs/gh"
cat >"$stubs/go" <<'EOF'
#!/bin/bash
echo "go $*" >>"$CALLS"
echo "GOTOOLCHAIN=${GOTOOLCHAIN:-} GOFLAGS=${GOFLAGS-unset} GOENV=${GOENV:-}" >>"$CALLS.goenv"
[ -z "${STUB_GO_FAILS:-}" ] || { echo "go: not a Go binary" >&2; exit 1; }
[ -n "${STUB_GOVM_FILE:-}" ] || exit 127   # no toolchain unless a test says what `go version -m` prints
case "$1 $2" in "version -m") cat "$STUB_GOVM_FILE";; *) exit 2;; esac
EOF
chmod +x "$stubs"/* "$stubs2"/*

# ---------- host guard (owner, Oct 9: nothing we run may ask the Mac for admin rights) ---------------------------------------------
# On a non-Linux host a REAL sudo, sysctl, unshare, melange or apko must never be reachable from a script under test. Every script
# runs with $stubs first on PATH; this checks that those five names resolve to the stubs there, and refuses (exit 2) otherwise.
guard_stubs() { # guard_stubs <stubs-dir>: 0 if sudo sysctl unshare melange apko all resolve inside <stubs-dir> with that dir first on PATH
  local d=$1 c r
  for c in sudo sysctl unshare melange apko; do r=$(PATH="$d:$PATH" command -v "$c" 2>/dev/null) || return 1; case $r in "$d"/*) ;; *) return 1;; esac; done
  return 0
}
if [ "$(uname -s)" != Linux ]; then
  guard_stubs "$stubs" || { echo "melange-apko-test: refusing to run on $(uname -s): sudo/sysctl/unshare/melange/apko do not resolve to the stubs" >&2; exit 2; }
fi

# ---------- fixtures ---------------------------------------------------------------------------------------------------
mkdir -p "$fx"/{archive,live,envrepo,melrepo,melrepo-fips,pair,repo/build}
FSCACHE_ROOT="$root" python3 "$work/lib.py" fixtures "$fx" >"$work/fixtures.log" 2>&1 || { echo "FIXTURE SETUP FAILED"; cat "$work/fixtures.log"; exit 1; }
src="$work/src"; mkdir -p "$src/vendor" "$src/cmd/fscache"
cp "$fx/sbom/modules.txt" "$src/vendor/modules.txt"; echo "module github.com/fosterstack/cache" >"$src/go.mod"; echo "package main" >"$src/cmd/fscache/main.go"; cp "$fx/sbom/prov-unbuilt.json" "$src/dependency-provenance.json"
( cd "$src" && git init -q . && git add -A && GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.test GIT_COMMITTER_NAME=t \
  GIT_COMMITTER_EMAIL=t@example.test GIT_COMMITTER_DATE="$ISO" GIT_AUTHOR_DATE="$ISO" git commit -q -m fixture ) >/dev/null 2>&1
kr="$fx/keyring/wolfi-signing.rsa.pub"

run_s() { : >"$CALLS"; PATH="$stubs:$PATH" CALLS="$CALLS" STUB_LIB="$work/lib.py" "$@" >"$work/log" 2>&1 </dev/null; echo $? >"$work/rc"; }
run_s2() { : >"$CALLS"; PATH="$stubs2:$stubs:$PATH" CALLS="$CALLS" STUB_LIB="$work/lib.py" "$@" >"$work/log" 2>&1 </dev/null; echo $? >"$work/rc"; }   # adds a git stub: used for the refresh job only

# ---------- restricted search path (REQ-BUILDAPK-001-AC9; reusable by any script test that must prove "no bare tool name") ---------------
# restricted_path_dir DEST NAME...: DEST becomes a directory holding ONLY symlinks to the named programs, each resolved with `command -v`
# on the current search path (so the same call works on a Mac and on a Linux runner). A script run with PATH=DEST can reach exactly those
# programs by bare name and nothing else: a tool that is not listed is "not found", whatever way the script spells its name.
restricted_path_dir() {
  local d=$1 n p; shift; rm -rf "$d"; mkdir -p "$d" || return 1
  for n in "$@"; do
    p=$(command -v "$n" 2>/dev/null) || p=
    case $p in /*) [ -x "$p" ] || p=;; *) p=;; esac
    [ -n "$p" ] || { echo "restricted_path_dir: no program $n on this machine" >&2; return 1; }
    ln -s "$p" "$d/$n" || return 1
  done
}
# restricted_stub_copy SRC DEST TOOLPATH: a copy of the stub SRC whose OWN dependencies (env, python3, ls, chmod) are shell functions calling them by
# absolute path (python3 runs with TOOLPATH, which also holds openssl for the harness library), and whose `exec env -i` is by absolute path.
# Every command the SCRIPT supplies to the stub (exec "$@") is resolved under the search path the stub was started with, which is the
# script's own restricted one: no stub restores a wider path, and nothing depends on how the script spells the operand.
restricted_stub_copy() {
  local src=$1 dest=$2 tp=$3 e p l c body; e=$(command -v env) && p=$(command -v python3) && l=$(command -v ls) && c=$(command -v chmod) || return 1
  body=$(tail -n +2 "$src"); body=${body//exec env -i/exec $(printf %q "$e") -i}
  { head -n 1 "$src"; printf 'env() { %q "$@"; }\npython3() { PATH=%q %q "$@"; }\nls() { %q "$@"; }\nchmod() { %q "$@"; }\n' "$e" "$tp" "$p" "$l" "$c"; printf '%s\n' "$body"; } >"$dest"
  chmod +x "$dest"
}
RUNNER=run_s
rc() { cat "$work/rc"; }
toolrun() { grep -Eq '^(melange (build|sign)|apko (build|lock))' "$CALLS"; }
mo() { mktemp -d "$work/out.XXXXXX"; }
# sd <rule> <desc> <call-log regex> <cmd...>: exit 0 and the call log matches
sd() { local ac=$1 d=$2 re=$3; shift 3; $RUNNER "$@"; if [ "$(rc)" = 0 ] && grep -Eq -- "$re" "$CALLS"; then ok; else bad "$ac" "$d (exit $(rc))"; fi; }
# sn <rule> <desc> <call-log regex> <cmd...>: exit 0, a tool really ran, and the regex does NOT match the call log
sn() { local ac=$1 d=$2 re=$3; shift 3; $RUNNER "$@"; if [ "$(rc)" = 0 ] && toolrun && ! grep -Eq -- "$re" "$CALLS"; then ok; else bad "$ac" "$d (exit $(rc), or no tool call, or pattern present)"; fi; }
# so <rule> <desc> <output regex> <cmd...>: exit 0 and stdout/stderr matches
so() { local ac=$1 d=$2 re=$3; shift 3; $RUNNER "$@"; if [ "$(rc)" = 0 ] && grep -Eq -- "$re" "$work/log"; then ok; else bad "$ac" "$d (exit $(rc))"; fi; }
# sr <rule> <desc> <keyword> <cmd...>: refusal = exit 2, names the reason, and no tool was run
sr() { local ac=$1 d=$2 kw=$3; shift 3; $RUNNER "$@"; if [ "$(rc)" = 2 ] && grep -Eqi -- "$kw" "$work/log" && ! toolrun; then ok; else bad "$ac" "$d (exit $(rc), wanted 2 naming '$kw', no tool call)"; fi; }
# srb <rule> <desc> <keyword> <cmd...>: refusal AFTER the lock step: exit 2, names the reason, and apko build never ran
srb() { local ac=$1 d=$2 kw=$3; shift 3; $RUNNER "$@"; if [ "$(rc)" = 2 ] && grep -Eqi -- "$kw" "$work/log" && grep -q '^apko lock ' "$CALLS" && ! grep -q '^apko build ' "$CALLS"; then ok; else bad "$ac" "$d (exit $(rc), wanted 2 naming '$kw', apko lock run, apko build not run)"; fi; }
# sf <rule> <desc> <keyword> <cmd...>: failure = non-zero exit and the message names the reason
sf() { local ac=$1 d=$2 kw=$3; shift 3; $RUNNER "$@"; if [ "$(rc)" != 0 ] && [ "$(rc)" != 127 ] && grep -Eqi -- "$kw" "$work/log"; then ok; else bad "$ac" "$d (exit $(rc), wanted non-zero naming '$kw')"; fi; }
# ordered <rule> <desc> <re1> <re2>: after the last run, the first re1 line comes before the first re2 line
ordered() { local ac=$1 d=$2; local a b; a=$(grep -nE -- "$3" "$CALLS" | head -1 | cut -d: -f1); b=$(grep -nE -- "$4" "$CALLS" | head -1 | cut -d: -f1)
  if [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; then ok; else bad "$ac" "$d"; fi; }

