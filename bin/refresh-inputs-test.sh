#!/usr/bin/env bash
# proves: REQ-REFRESH-001-AC1, REQ-REFRESH-001-AC2, REQ-REFRESH-001-AC3, REQ-REFRESH-001-AC4, REQ-REFRESH-001-AC5, REQ-REFRESH-001-AC6, REQ-REFRESH-001-AC7, REQ-REFRESH-001-AC8, REQ-REFRESH-001-AC10, REQ-REFRESH-001-AC11, REQ-REFRESH-001-AC12, REQ-REFRESH-001-AC13, REQ-REFRESH-001-AC14, REQ-REFRESH-001-AC15, REQ-REFRESH-001-AC16, REQ-REFRESH-001-AC17, REQ-REFRESH-001-AC18, REQ-REFRESH-001-AC19, REQ-REFRESH-001-AC20, REQ-REFRESH-001-AC21, REQ-REFRESH-001-AC22, REQ-REFRESH-001-AC23, REQ-REFRESH-001-AC26, REQ-REFRESH-001-AC29, REQ-REFRESH-001-AC30, REQ-REFRESH-001-AC32, REQ-REFRESH-001-AC33, REQ-REFRESH-001-AC34, REQ-REFRESH-001-AC35, REQ-REFRESH-001-AC36, REQ-REFRESH-001-AC37, REQ-REFRESH-001-AC38
# Tests of the PR: the daily input refresh script and the daily FIPS-module check.
# Split mechanically from the original suite: the sections between the markers are copied byte for byte, the harness is
# bin/melange-apko-lib.sh. Every assertion runs offline against PATH stubs; nothing here calls a real sudo, sysctl,
# unshare, melange or apko (the harness refuses to run on a non-Linux host unless the stubs are in front).
. "$(cd "$(dirname "$0")" && pwd)/melange-apko-lib.sh"
# The production script names its tools by fixed path (TEST-SUBST lines). The suite runs a COPY, beside the real helpers, in which exactly those lines
# point at dispatchers that exec the tool by NAME on the run's PATH (so the stubs of run_s, run_s2, ...), and checks the copy differs in no other line.
RF_PROD="$RF"
# the one place this suite names the download tool: stubs, call-log patterns and the fixed-path checks all use $FETCH
printf -v FETCH %s curl
export FETCH
rfd=$(mktemp -d "$work/rf.XXXXXX")   # this file's own scratch: the stub tool dispatchers and the two script copies
mkdir -p "$rfd/tools" "$rfd/rfcopy/bin" "$rfd/rfcopy-nossl/bin"
for t_ in python3 "$FETCH" git gh apko openssl cmp mktemp rm mkdir; do printf '#!/bin/bash\nexec %s "$@"\n' "$t_" >"$rfd/tools/$t_"; chmod +x "$rfd/tools/$t_"; done
python3 - "$RF_PROD" "$rfd" "$fx" <<'P'
import os, re, shutil, sys
prod, work, fxdir = sys.argv[1:4]
# the production script names every tool by its literal fixed path at the call; the copy is the same bytes with each occurrence of one of the ten fixed
# paths replaced, one for one, by the dispatcher of that tool (REQ-REFRESH-001-AC23)
paths = {"/usr/bin/python3": "python3", "/usr/bin/" + os.environ["FETCH"]: os.environ["FETCH"], "/usr/bin/git": "git", "/usr/bin/gh": "gh", "/usr/local/bin/apko": "apko",
         "/usr/bin/openssl": "openssl", "/usr/bin/cmp": "cmp", "/usr/bin/mktemp": "mktemp", "/bin/rm": "rm", "/bin/mkdir": "mkdir"}
text = open(prod).read()
for d, over in (("rfcopy", {}), ("rfcopy-nossl", {"/usr/bin/openssl": "/nonexistent/openssl"})):
    out = text
    for path, name in paths.items():
        assert re.search(r"(?<![\w./-])%s(?![\w.-])" % re.escape(path), out), "the production file never names " + path
        out = re.sub(r"(?<![\w./-])%s(?![\w.-])" % re.escape(path), lambda m, n=name, o=over, pth=path: o.get(pth, work + "/tools/" + n), out)
    dst = "%s/%s/bin" % (work, d)
    open(dst + "/refresh-inputs.sh", "w").write(out); os.chmod(dst + "/refresh-inputs.sh", 0o755)
    for h in ("apk-tool.py", "apko-lock.sh", "archive-verify.py"):
        shutil.copy(os.path.dirname(prod) + "/" + h, dst + "/" + h)
    shutil.copy(fxdir + "/gen-recipes.py", dst + "/gen-recipes.py")   # the generator copy whose TEMPLATE_SHA256 line is the fixture template's pin (no test switch in the real one)
P
RF="$rfd/rfcopy/bin/refresh-inputs.sh"; RFN="$rfd/rfcopy-nossl/bin/refresh-inputs.sh"
# ---- begin verbatim sections ----
# ===== rules 44-49: the refresh job ======================================================================================
t "rule 45" "dependabot.yml has no apk, apko, melange or lock-file entry (this refresh job is their only updater)" bash -c "test -x '$RF' && python3 '$work/chk.py' dependabot '$root/.github/dependabot.yml'"
t "rule 45" "refresh-inputs.sh says it is the only updater of image recipes, apk packages and lock files" bash -c "grep -Eqi 'only updater' '$RF'"
# ---- P3 review round 1 (Opus): signed index fixtures and tree-hash helpers (added after the mechanical split) ------------------------
# The archive keeps the ORIGINAL Wolfi-signed index per arch. The fixtures therefore need a real RSA key and real signed indexes
# (apk v2: a signature tar stream, then the index tar stream; the signature covers the second gzip stream's bytes).
python3 - "$fx" <<'P'
import gzip, hashlib, io, json, os, subprocess, sys, tarfile
fx = sys.argv[1]
def run(*a, **k): return subprocess.run(a, check=True, capture_output=True, **k).stdout
def gz(b):
    o = io.BytesIO()
    with gzip.GzipFile(fileobj=o, mode="wb", mtime=0) as g: g.write(b)
    return o.getvalue()
def tarb(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.GNU_FORMAT) as t:
        for n, d in members:
            i = tarfile.TarInfo(n); i.size = len(d); i.mtime = 0; t.addfile(i, io.BytesIO(d))
    return b.getvalue()
def keypair(name):
    run("openssl", "genrsa", "-out", "%s/%s.pem" % (fx, name), "2048")
    open("%s/%s.pub" % (fx, name), "wb").write(run("openssl", "rsa", "-in", "%s/%s.pem" % (fx, name), "-pubout"))
def signed_index(path, key, text, alg="sha256", member="RSA256"):
    idx = gz(tarb([("APKINDEX", text), ("DESCRIPTION", b"fixture")]))
    open(path + ".idx", "wb").write(idx)
    sig = run("openssl", "dgst", "-" + alg, "-sign", "%s/%s.pem" % (fx, key), path + ".idx")
    os.remove(path + ".idx")
    open(path, "wb").write(gz(tarb([(".SIGN.%s.wolfi-signing.rsa.pub" % member, sig)])) + idx)
def index_text(a, skip=()):
    seen, out = set(), []
    for f in ("live-same", "live-new", "live-mel", "live-mel-new"):
        for e in json.load(open("%s/%s.lock.json" % (fx, f)))["contents"]["packages"]:
            k = (e["name"], e["version"], e["checksum"])
            if e["architecture"] == a and k not in seen and e["name"] not in skip:
                seen.add(k); out.append("C:%s\nP:%s\nV:%s\n" % (e["checksum"], e["name"], e["version"]))
    return "\n".join(out).encode()
keypair("idxkey"); keypair("otherkey")
open(fx + "/archive/keys/wolfi-signing.rsa.pub", "wb").write(open(fx + "/idxkey.pub", "rb").read())
for a in ("x86_64", "aarch64"):
    open("%s/itext-%s" % (fx, a), "wb").write(index_text(a))
    signed_index("%s/live/%s/APKINDEX.tar.gz" % (fx, a), "idxkey", index_text(a))
    signed_index("%s/archive/%s/APKINDEX.tar.gz" % (fx, a), "idxkey", index_text(a, skip=("tzdata",)))   # the archive's own (older) signed index: the legacy plain pointer
    os.makedirs("%s/live-forged/%s" % (fx, a), exist_ok=True)
    signed_index("%s/live-forged/%s/APKINDEX.tar.gz" % (fx, a), "otherkey", index_text(a))
P
treehash() { python3 - "$@" <<'P'
import hashlib, os, sys
h = hashlib.sha256()
for root in sys.argv[1:]:
    for d, ds, fs in sorted(os.walk(root)):
        ds.sort()
        for n in sorted(fs + [x for x in ds if os.path.islink(os.path.join(d, x))]):
            p = os.path.join(d, n); rel = os.path.relpath(p, root)
            h.update(rel.encode() + b"\0")
            h.update((b"L" + os.readlink(p).encode()) if os.path.islink(p) else (b"F" + open(p, "rb").read()))
print(h.hexdigest())
P
}
# the pinned Wolfi key line of the fixture repository (the refresh checks the live key against it right after the fetch)
mkdir -p "$fx/repo/build/locks"; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$(shasum -a 256 "$fx/archive/keys/wolfi-signing.rsa.pub" | cut -d' ' -f1)" >"$fx/repo/build/locks/archive-keys.sha256"
# REQ-REFRESH-001-AC35: the packages the Build jobs run ON the runner (data file) and the committed lock of their resolution; the fixture holds the same closure as melange.lock
printf 'packages:\n  - busybox\n  - ca-certificates-bundle\n' >"$fx/repo/build/host-tools.yaml"; cp "$fx/melange.lock" "$fx/repo/build/locks/host-tools.lock"
mkrepo() { rm -rf "$work/rp"; mkdir -p "$work/rp"; cp -R "$fx/repo/." "$work/rp/"; rm -rf "$work/ar"; cp -R "$fx/archive" "$work/ar"; for a in x86_64 aarch64; do cp -n "$fx/envrepo/$a/"*.apk "$work/ar/$a/"; done   # melange's build tools are archived too
  printf 'x86_64 sha256:%s\naarch64 sha256:%s\n' "$(shasum -a 256 "$fx/archive/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1)" "$(shasum -a 256 "$fx/archive/aarch64/APKINDEX.tar.gz" | cut -d' ' -f1)" >"$work/rp/build/locks/archive-index.sha256"; }   # the record names the index the archive holds now
rfe=(env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live")
RUNNER=run_s2
GHPATHS="python3 -c 'import json,sys;print(chr(10).join(a[\"path\"] for a in json.load(open(sys.argv[1]))[\"variables\"][\"input\"][\"fileChanges\"][\"additions\"]))' '$CALLS.graphql'"   # the paths of the commit the API was asked to make (the old assertions read them from git add)
mkrepo; run_s2 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
if [ "$(rc)" = 0 ] && [ "$(grep -c '^apko lock ' "$CALLS")" -ge 3 ]; then ok; else bad "rule 44" "refresh: apko lock runs for production, fips and the melange environment (>= 3 calls)"; fi
if [ "$(rc)" = 0 ] && grep '^apko lock ' "$CALLS" | grep -q -- '--repository-append https://packages.wolfi.dev/os'; then ok; else bad "rule 44" "refresh: the locks are made against live Wolfi (--repository-append https://packages.wolfi.dev/os)"; fi
if [ "$(rc)" = 0 ] && ! grep -Eq '^(gh |git( -C [^ ]+)? (commit|push|checkout))' "$CALLS"; then ok; else bad "rule 44" "refresh: nothing changed -> no commit, no push, no PR"; fi
if [ "$(rc)" = 0 ] && grep -Eq "^$FETCH .*https://packages\.wolfi\.dev/os/.*wolfi-signing\.rsa\.pub" "$CALLS"; then ok; else bad "rule 32" "refresh compares the live Wolfi key to the archived one on every run (even when nothing changed)"; fi
cp "$fx/live-new.lock.json" "$work/ln.json"
mkrepo; rfn=(env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live")
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "refresh: a new tzdata is archived (the new apk is in the archive, for both archs)" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -f '$work/ar/x86_64/tzdata-2026b-r0.apk' && test -f '$work/ar/aarch64/tzdata-2026b-r0.apk'"
t "rule 44" "refresh: the base locks in the repo are updated (new tzdata, archive paths)" bash -c "python3 - '$work/rp' <<'P'
import json, sys
for f in ('apko.base.lock.json', 'apko-fips.base.lock.json'):
    d = json.load(open(sys.argv[1] + '/build/locks/' + f)); z = [e for e in d['contents']['packages'] if e['name'] == 'tzdata']
    assert z and all(e['version'] == '2026b-r0' and e['url'].startswith('/work/archive/') for e in z), f
P"
t "rule 44" "refresh: the new lock still verifies against the archive (checksums checked before the PR)" "$LK" verify-archive --lock "$work/rp/build/locks/apko.base.lock.json" --archive "$work/ar"
t "rule 44" "refresh: the update is a PR (gh pr create once), pushed to a branch, never to main" bash -c "test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1 && grep -E '^git( -C [^ ]+)? push' '$CALLS' | grep -Eq 'refresh' && ! grep -E '^git( -C [^ ]+)? push' '$CALLS' | grep -Eq '( |:|/)main( |\$)'"
t "rule 44" "refresh: the archive's package index is replaced by the live signed index for both archs (apko reads the original Wolfi-signed index from the archive)" bash -c "cmp '$work/ar/x86_64/APKINDEX.tar.gz' '$fx/live/x86_64/APKINDEX.tar.gz' && cmp '$work/ar/aarch64/APKINDEX.tar.gz' '$fx/live/aarch64/APKINDEX.tar.gz'"
t "rule 49" "refresh: the PR is only opened: a gh pr create, and no gh pr merge, no --admin, no auto-merge, no --no-verify, no skip-ci" bash -c "grep -q '^gh pr create' '$CALLS' && ! grep -Eq '^gh pr merge|--admin|--auto|--no-verify|skip ci' '$CALLS'"
t "rule 47" "refresh: the old version (tzdata 2026a) is no longer in live Wolfi -> noted in the output, exit 0, archive copy kept" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -Eqi 'no longer|disappeared|gone' '$work/log' && grep -q 2026a '$work/log' && test -f '$work/ar/x86_64/tzdata-2026a-r0.apk'"
mkrepo; mkdir -p "$work/badfetch/x86_64" "$work/badfetch/aarch64"; cp "$fx/live/x86_64/tzdata-2026b-r0.apk" "$work/badfetch/x86_64/"; cp "$fx/live/aarch64/tzdata-2026b-r0.apk" "$work/badfetch/aarch64/"; python3 "$work/lib.py" tamper "$work/badfetch/x86_64/tzdata-2026b-r0.apk"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$work/badfetch" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: a downloaded package that fails its lock checksum stops the job (non-zero, names the checksum), no PR" bash -c "test -x '$RF' && test \"\$(cat '$work/rc')\" != 0 && test \"\$(cat '$work/rc')\" != 127 && grep -Eqi 'checksum|tamper|mismatch' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
mkrepo; run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel-new.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 15" "refresh: a build tool added to melange's resolved closure (zlib) is archived, put in melange.lock and pinned in BOTH recipes, which stay equal to the lock (the recipe pins the whole closure)" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -f '$work/ar/x86_64/zlib-1.3.2-r0.apk' && python3 - '$work/rp' <<'P'
import sys, yaml
r = sys.argv[1]; lock = sorted(l.strip() for l in open(r + '/build/locks/melange.lock') if l.strip())
assert 'zlib=1.3.2-r0' in lock, lock
for f in ('melange.yaml', 'melange-fips.yaml'):
    assert sorted(yaml.safe_load(open(r + '/build/' + f))['environment']['contents']['packages']) == lock, f
P"
echo "-----BEGIN PUBLIC KEY-----
rotated
-----END PUBLIC KEY-----" >"$work/rotated.pub"
mkrepo; run_s2 env STUB_LIVE_KEY="$work/rotated.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 46" "refresh: the live Wolfi key differs from the archived one -> exit 3, message names the signing key and a human, no apko call, no PR" bash -c "test \"\$(cat '$work/rc')\" = 3 && grep -Eqi 'signing key' '$work/log' && grep -Eqi 'human' '$work/log' && ! grep -Eq '^(apko|gh )' '$CALLS'"
# rule 73: the certified-module check (daily, in the same job)
gr="$work/goroot"; mkdir -p "$gr/lib/fips140"
fr() { rm -rf "$work/rp3"; mkdir -p "$work/rp3/build/locks"; cp "$fx/melange-fips.yaml" "$fx/melange.yaml" "$fx/melange.yaml.tmpl" "$work/rp3/build/"; cp "$fx/melange.lock" "$fx/fips-module.txt" "$work/rp3/build/locks/"; }
printf '#!/bin/bash\ncd "$(dirname "$0")/rp3/build" && find . -type f ! -name '*.tmp-*' | sort | xargs shasum -a 256 | shasum -a 256 | cut -d" " -f1\n' >"$work/bhash.sh"
echo "v1.0.0-c2097c7c" >"$gr/lib/fips140/certified.txt"; fr
run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: Go's certified.txt names the module we already build (v1.0.0-c2097c7c) -> up to date, exit 0, no PR" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -q '^gh pr create' '$CALLS' && grep -Eqi 'up to date|unchanged|current' '$work/log'"   # certified.txt: Go 1.27.2 lib/fips140/certified.txt (VERIFIED locally)
echo "v1.1.0-deadbeef" >"$gr/lib/fips140/certified.txt"; fr
run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: a newer certified module -> the fips recipe moves to it (GOFIPS140 and the proof value) and a PR is opened" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -q 'v1.1.0' '$work/rp3/build/melange-fips.yaml' && grep -q 'v1.1.0-deadbeef' '$work/rp3/build/melange-fips.yaml' && test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1"
t "rule 73" "fips-module: a PR is opened, not merged, and nothing is pushed to main" bash -c "grep -q '^gh pr create' '$CALLS' && ! grep -Eq '^gh pr merge' '$CALLS' && ! grep -E '^git( -C [^ ]+)? push' '$CALLS' | grep -Eq '( |:|/)main( |\$)'"
t "rule 73" "fips-module: the PR body names every file a human must change for a new certificate, each of them really carries the current module or certificate, and no other file that carries it is missing from the body or from the list of fixtures and generated files (rc-3 item 7)" bash -c "l=\$(grep '^gh pr create' '$CALLS'); python3 -I - \"\$l\" '$root' <<'PY'
import re, subprocess, sys
body, root = sys.argv[1], sys.argv[2]
need = ['bin/check-artifacts.sh', 'bin/check-fips.sh', 'bin/check-govulncheck.py', 'internal/buildinfo/buildinfo.go', 'internal/buildinfo/buildinfo_test.go', '.github/workflows/ci.yml',
        'docs/install.md', 'SECURITY.md', 'RELEASING.md', 'docs/offline-install.md', 'docs/verify-images.md']
bad = ['the body does not name ' + f for f in need if f not in body]
lit = re.compile(r'GOFIPS140=v[0-9]|CMVP cert #[0-9]+|cert #[0-9]+|#[0-9]{4} ')
for f in need:
    try:
        if not lit.search(open(root + '/' + f).read()):
            bad.append(f + ' no longer carries the module or certificate literal: the list is stale')
    except OSError:
        bad.append(f + ' does not exist')
# a file that carries the literal and is neither named nor a fixture, a generated file, a test of something else or a record is a file the body would have to name
exempt = ('build/', 'docs/quality/', 'requirements/', 'test-evidence/', 'audits/')
exempt_files = {'bin/build-apk.sh', 'bin/melange-apko-lib.sh', 'bin/check-version-literals.sh', 'bin/build-apk-test.sh', 'bin/build-helpers-test.sh', 'bin/chain-check-scripts-test.sh',
                'bin/chain-check-wiring-test.sh', 'bin/refresh-inputs-test.sh', 'internal/server/tls_test.go'}
for f in subprocess.run(['git', '-C', root, 'ls-files'], capture_output=True, text=True).stdout.split():
    if f in need or f in exempt_files or f.startswith(exempt):
        continue
    try:
        if re.search(r'GOFIPS140=v1\.0\.0|CMVP cert #5247|c2097c7c', open(root + '/' + f, errors='replace').read()):
            bad.append(f + ' carries the module or certificate and is neither named in the body nor an exempt fixture')
    except OSError:
        pass
print(chr(10).join(bad))
sys.exit(1 if bad else 0)
PY"
rm -f "$gr/lib/fips140/certified.txt"; fr
sf "rule 73" "fips-module: a missing certified.txt fails closed and names the file" 'certified\.txt' "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
: >"$gr/lib/fips140/certified.txt"
sf "rule 73" "fips-module: an empty certified.txt fails closed" 'certified\.txt|empty' "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
echo "not-a-module" >"$gr/lib/fips140/certified.txt"
sf "rule 73" "fips-module: an unreadable value fails closed" 'certified|format|module' "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"

# ---- P3 review round 1 (Opus): blockers B1-B7 and residuals R1, R2, R4, R7 (tests first) -------------------------------------------
# B6 (AC7, rule 48): the SCRIPT has no cooldown, 7-day or minimum-age rule (the job text part waits for the workflow PR)
t "rule 48" "refresh-inputs.sh has no cooldown, 7-day or minimum-age rule anywhere" bash -c "test -f '$RF' && ! grep -Eqi 'cooldown|7[ -]?day|min(imum)?[-_ ]?age|-mtime' '$RF'"
# B7 (AC3): every apko lock is given the ARCHIVED key and only that key, and never a switch that skips signature checks
mkrepo; run_s2 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 32" "refresh: every apko lock carries exactly one --keyring-append, the archived Wolfi key file, no URL" bash -c "test \"\$(grep -c '^apko lock ' '$CALLS')\" -ge 3 && ! grep '^apko lock ' '$CALLS' | grep -v -- '--keyring-append $work/ar/keys/wolfi-signing.rsa.pub ' | grep -q . && test \"\$(grep '^apko lock ' '$CALLS' | grep -o -- '--keyring-append' | wc -l | tr -d ' ')\" = \"\$(grep -c '^apko lock ' '$CALLS')\" && ! grep '^apko lock ' '$CALLS' | grep -Eq -- '--keyring-append [a-z]+://'"
t "rule 19" "refresh: no apko call skips signature checks (--ignore-signatures, --allow-untrusted, --insecure)" bash -c "test \"\$(grep -c '^apko ' '$CALLS')\" -ge 3 && ! grep -Eq -- 'ignore-signatures|allow-untrusted|--insecure' '$CALLS'"
# B1 (rules 47, 30, 31, 48; AC6): indexes are immutable, versioned by sha256, verified against the archived key, never overwritten
live_sha_x=$(shasum -a 256 "$fx/live/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1); live_sha_a=$(shasum -a 256 "$fx/live/aarch64/APKINDEX.tar.gz" | cut -d' ' -f1)
old_sha_x=$(shasum -a 256 "$fx/archive/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1)
mkrepo; run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 47" "refresh: the live signed index is stored under a name made of its sha256 (index/APKINDEX-<sha256>.tar.gz), byte for byte" bash -c "test \"\$(cat '$work/rc')\" = 0 && cmp '$work/ar/x86_64/index/APKINDEX-$live_sha_x.tar.gz' '$fx/live/x86_64/APKINDEX.tar.gz' && cmp '$work/ar/aarch64/index/APKINDEX-$live_sha_a.tar.gz' '$fx/live/aarch64/APKINDEX.tar.gz'"
t "rule 31" "refresh: APKINDEX.tar.gz is a regular-file COPY of that versioned file (same sha256, no symlink; AC13 amended), so apko still reads the original signed index" bash -c "test -f '$work/ar/x86_64/APKINDEX.tar.gz' && test ! -L '$work/ar/x86_64/APKINDEX.tar.gz' && cmp '$work/ar/x86_64/APKINDEX.tar.gz' '$fx/live/x86_64/APKINDEX.tar.gz' && cmp '$work/ar/x86_64/APKINDEX.tar.gz' '$work/ar/x86_64/index/APKINDEX-$live_sha_x.tar.gz' && test \"\$(shasum -a 256 '$work/ar/x86_64/APKINDEX.tar.gz' | cut -d' ' -f1)\" = '$live_sha_x'"
t "rule 47" "refresh: the previous index is kept (a version that disappeared upstream stays resolvable from the archive's older index)" bash -c "cmp '$work/ar/x86_64/index/APKINDEX-$old_sha_x.tar.gz' '$fx/archive/x86_64/APKINDEX.tar.gz'"
t "rule 31" "refresh: the index digests are recorded in build/locks/archive-index.sha256 (one line per arch) so a build can refuse a different index" bash -c "grep -qx 'x86_64 sha256:$live_sha_x' '$work/rp/build/locks/archive-index.sha256' && grep -qx 'aarch64 sha256:$live_sha_a' '$work/rp/build/locks/archive-index.sha256'"
before=$(treehash "$work/ar" "$work/rp")
rm -rf "$work/live-forged2"; cp -R "$fx/live" "$work/live-forged2"; for a in x86_64 aarch64; do cp "$fx/live-forged/$a/APKINDEX.tar.gz" "$work/live-forged2/$a/APKINDEX.tar.gz"; done
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$work/live-forged2" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 32" "refresh: an index not signed by the archived key (all packages fine) fails closed naming the index signature, archive and repo untouched, no PR" bash -c "test \"\$(cat '$work/rc')\" != 0 && test \"\$(cat '$work/rc')\" != 127 && grep -Eqi 'index.*signature|signature.*index' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
t "rule 48" "refresh: after that refusal the archive and the repository are byte-for-byte what they were" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# B3 (AC4): after a checksum failure nothing was copied or written (mutants: copy before verify, write the lock before verify)
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$work/badfetch" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: after a checksum failure the archive and the repository are byte-for-byte unchanged (nothing copied, no lock written before verification)" bash -c "test \"\$(cat '$work/rc')\" != 0 && test \"\$(cat '$work/rc')\" != 127"
t "rule 48" "refresh: ...and that is the same tree as before the run" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# R1: the same name-version already in the archive with DIFFERENT bytes is refused, never replaced
mkrepo; printf 'not the same tzdata' >"$work/ar/x86_64/tzdata-2026b-r0.apk"; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: an archived package with the same version but different bytes is refused (checksum named) and nothing changes" bash -c "test \"\$(cat '$work/rc')\" != 0 && grep -Eqi 'checksum|differs' '$work/log'" 
t "rule 48" "refresh: ...archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# R4: names, versions and architectures from a lock are validated before they become archive paths
python3 - "$work/ln.json" "$work/evil.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "tzdata": e["name"] = "../../evil"
json.dump(d, open(sys.argv[2], "w"))
P
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/evil.json" STUB_LOCK_FIPS="$work/evil.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: a package name with a path in it is refused (exit 2, named), nothing is written, nothing escapes the archive" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -Eqi 'invalid|refus' '$work/log' && ! ls '$work' | grep -q evil.apk"
t "rule 48" "refresh: ...archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# R7: the branch name is already taken on the remote -> a numbered branch, not a failed push
mkdir -p "$work/stubs3"; cat >"$work/stubs3/git" <<'G'
#!/bin/bash
echo "git $*" >>"$CALLS"
case "$*" in *"rev-parse HEAD"*) echo cafe0123;; esac
case "$*" in *ls-remote*"refs/heads/${GIT_STUB_EXISTING:-none}") echo "deadbeef	refs/heads/${GIT_STUB_EXISTING}";; esac
exit 0
G
chmod +x "$work/stubs3/git"
run_s3() { : >"$CALLS"; PATH="$work/stubs3:$stubs2:$stubs:$PATH" CALLS="$CALLS" STUB_LIB="$work/lib.py" "$@" >"$work/log" 2>&1 </dev/null; echo $? >"$work/rc"; }
mkrepo; run_s3 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
first=$(grep -E '^git( -C [^ ]+)? checkout -b ' "$CALLS" | head -1 | sed 's/.*checkout -b //')
mkrepo; run_s3 env GIT_STUB_EXISTING="$first" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "refresh: when the branch name already exists on the remote a numbered name (-2) is used, and exactly one pull request is opened" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -E '^git( -C [^ ]+)? checkout -b ${first//\//\\/}-2\$' '$CALLS' && test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1"
# B2 (rule 73): the ratified cadence is DAILY, in the daily job; no weekly wording in the script
t "rule 73" "refresh-inputs.sh does not describe the certified-module check as weekly (rule 73: the daily job reads Go's certified file)" bash -c "! grep -Eqi 'weekly|once a week' '$RF'"
# B4 (AC12): an OLDER certified module is refused, and on every refusal the recipe is byte-for-byte unchanged
fhash() { bash "$work/bhash.sh"; }
echo "v0.9.0-deadbeef" >"$gr/lib/fips140/certified.txt"; fr; h=$(fhash)
run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: a certified.txt older than the recipe's module is refused (exit 2, names certified.txt), recipe unchanged, no PR" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'certified.txt' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
t "rule 73" "fips-module: ...recipe bytes unchanged after the older-module refusal" test "$(fhash)" = "$h"
rm -f "$gr/lib/fips140/certified.txt"; fr; h=$(fhash); run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: recipe unchanged after a missing certified.txt" test "$(fhash)" = "$h"
: >"$gr/lib/fips140/certified.txt"; fr; h=$(fhash); run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: recipe unchanged after an empty certified.txt" test "$(fhash)" = "$h"
echo "not-a-module" >"$gr/lib/fips140/certified.txt"; fr; h=$(fhash); run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: recipe unchanged after an unreadable value" test "$(fhash)" = "$h"
# R2: a certified.txt that is not UTF-8 is refused naming the file (exit 2), not a traceback
printf '# caf\351\nv1.1.0-deadbeef\n' >"$gr/lib/fips140/certified.txt"; fr; h=$(fhash); run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: a certified.txt with a non-UTF-8 byte (even beside a valid newer line) exits 2 naming the file, with no traceback, recipe unchanged" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'certified.txt' '$work/log' && ! grep -q Traceback '$work/log' && test \"\$(bash '$work/bhash.sh')\" = '$h'"
# B5 (AC11): the new version appears exactly, followed by a character that is not part of a longer version
echo "v1.1.0-deadbeef" >"$gr/lib/fips140/certified.txt"; fr; run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: GOFIPS140=v1.1.0 appears exactly (next character is not - . or a word character) and the proof value v1.1.0-deadbeef too, and the old value is gone" bash -c "grep -Eq 'GOFIPS140=v1\\.1\\.0([^-.0-9A-Za-z]|\$)' '$work/rp3/build/melange-fips.yaml' && grep -q 'GOFIPS140=v1.1.0-deadbeef' '$work/rp3/build/melange-fips.yaml' && ! grep -q 'c2097c7c' '$work/rp3/build/melange-fips.yaml' && ! grep -Eq 'GOFIPS140=v1\\.0\\.0' '$work/rp3/build/melange-fips.yaml'"

# ---- P3 review round 1 (Sonnet): every section of a downloaded apk is checked, FIPS lock path, exit codes, git calls ----------------
# tamper each section (signature, control, data) and the package identity: refused, and the archive and repo are byte-identical afterwards
python3 - "$work" "$fx" <<'P'
import os, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w, fx = sys.argv[1:3]
raw = open(fx + "/live/x86_64/tzdata-2026b-r0.apk", "rb").read()
parts = lib.split(raw)
assert len(parts) == 3, len(parts)
for i, name in enumerate(("sig", "ctl", "data")):
    d = "%s/badfetch-%s" % (w, name); shutil.rmtree(d, ignore_errors=True); shutil.copytree(fx + "/live", d)
    off = sum(len(p[0]) for p in parts[:i]) + len(parts[i][0]) // 2
    b = bytearray(raw); b[off] ^= 0xFF
    open(d + "/x86_64/tzdata-2026b-r0.apk", "wb").write(bytes(b))
P
for sec in sig ctl data; do
  mkrepo; before=$(treehash "$work/ar" "$work/rp")
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$work/badfetch-$sec" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 48" "refresh: a flipped byte in the $sec section of a downloaded apk is refused (checksum named) and the archive and repo are byte-identical afterwards" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'checksum' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
  t "rule 48" "refresh: ...$sec: the trees are the same as before the run" test "$(treehash "$work/ar" "$work/rp")" = "$before"
done
python3 - "$work/ln.json" "$work/ln-id.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "tzdata" and e["architecture"] == "x86_64": e["checksum"] = "Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA="
json.dump(d, open(sys.argv[2], "w"))
P
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln-id.json" STUB_LOCK_FIPS="$work/ln-id.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: a package whose identity checksum (Q1...) differs from its bytes is refused and nothing changes" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'identity|checksum' '$work/log'"
t "rule 48" "refresh: ...identity: the trees are the same as before the run" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# the FIPS lock path: a change that shows up ONLY in the fips lock is archived and written to the fips base lock (the production lock is untouched)
mkrepo; prod_before=$(shasum -a 256 "$work/rp/build/locks/apko.base.lock.json" | cut -d' ' -f1)
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "refresh: a new package that only the FIPS lock resolves is archived and written to apko-fips.base.lock.json; the production base lock is unchanged" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -f '$work/ar/x86_64/tzdata-2026b-r0.apk' && grep -q '2026b-r0' '$work/rp/build/locks/apko-fips.base.lock.json' && test \"\$(shasum -a 256 '$work/rp/build/locks/apko.base.lock.json' | cut -d' ' -f1)\" = '$prod_before'"
# key changed (rule 46): not a single git command either (no branch, no commit, no push)
mkrepo; run_s2 env STUB_LIVE_KEY="$work/rotated.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 46" "refresh: after a key change there is no git and no gh call at all" bash -c "test \"\$(cat '$work/rc')\" = 3 && ! grep -Eq '^(git|gh) ' '$CALLS'"
# AC11/AC12: the refusals are exit 2 exactly, never a traceback, whatever the certified.txt holds
for c in missing empty unreadable older nonutf8; do
  rm -f "$gr/lib/fips140/certified.txt"
  case $c in empty) : >"$gr/lib/fips140/certified.txt";; unreadable) echo "not-a-module" >"$gr/lib/fips140/certified.txt";; older) echo "v0.9.0-deadbeef" >"$gr/lib/fips140/certified.txt";; nonutf8) printf '\377\n' >"$gr/lib/fips140/certified.txt";; esac
  fr; run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
  t "rule 73" "fips-module ($c certified.txt): exit exactly 2, the file is named, no traceback" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'certified.txt' '$work/log' && ! grep -q Traceback '$work/log'"
done
mkdir -p "$work/gr-nodir"; fr; run_s2 "$RF" fips-module --pr-author app/bot --go-root "$work/gr-nodir" --repo-dir "$work/rp3"
t "rule 73" "fips-module: a Go root with no lib/fips140 at all is exit 2, no traceback" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -q Traceback '$work/log'"

# ---- P3 review round 2 (Opus): NB1, NB2 and residuals R1, R6 (tests first) ------------------------------------------------------------------
sha_x=$(shasum -a 256 "$fx/live/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1)
# NB1: an existing versioned index file is trusted only if it hashes to its name; a bad one fails closed, and the write is atomic
mkrepo; mkdir -p "$work/ar/x86_64/index"; printf garbage >"$work/ar/x86_64/index/APKINDEX-$sha_x.tar.gz"; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: an existing index/APKINDEX-<sha256>.tar.gz holding other bytes (garbage) is refused, naming the file, exit 1, no PR" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'APKINDEX-$sha_x.tar.gz' '$work/log' && grep -Eqi 'hash' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
t "rule 31" "refresh: ...and the archive and repo are byte-identical afterwards" test "$(treehash "$work/ar" "$work/rp")" = "$before"
mkrepo; mkdir -p "$work/ar/x86_64/index"; head -c 100 "$fx/live/x86_64/APKINDEX.tar.gz" >"$work/ar/x86_64/index/APKINDEX-$sha_x.tar.gz"; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: a TRUNCATED versioned index (a killed earlier copy) is refused too, trees unchanged" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'hash' '$work/log'"
t "rule 31" "refresh: ...truncated: archive and repo byte-identical" test "$(treehash "$work/ar" "$work/rp")" = "$before"
mkrepo; mkdir -p "$work/ar/x86_64/index"; cp "$fx/live/x86_64/APKINDEX.tar.gz" "$work/ar/x86_64/index/APKINDEX-$sha_x.tar.gz"
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: an existing versioned index that DOES hash to its name is accepted and reused (exit 0)" test "$(cat "$work/rc")" = 0
t "rule 31" "refresh: no temp file is left behind in index/ after a successful run" bash -c "! ls '$work/ar/x86_64/index' '$work/ar/aarch64/index' | grep -q '\.tmp-'"
# R1: index shape and signature algorithm. Streams must be exactly two; only RSA256/RSA512 signatures are accepted (not the bare SHA-1 RSA)
python3 - "$fx" "$work" <<'P'
import gzip, io, os, shutil, subprocess, sys, tarfile
fx, w = sys.argv[1:3]
def run(*a): return subprocess.run(a, check=True, capture_output=True).stdout
def gz(b):
    o = io.BytesIO()
    with gzip.GzipFile(fileobj=o, mode="wb", mtime=0) as g: g.write(b)
    return o.getvalue()
def tarb(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.GNU_FORMAT) as t:
        for n, d in members:
            i = tarfile.TarInfo(n); i.size = len(d); i.mtime = 0; t.addfile(i, io.BytesIO(d))
    return b.getvalue()
def signed(path, alg, member, extra=b""):
    itext = open("%s/itext-%s" % (fx, os.path.basename(os.path.dirname(path))), "rb").read()
    idx = gz(tarb([("APKINDEX", itext), ("DESCRIPTION", b"fixture")]))
    open(path + ".i", "wb").write(idx)
    sig = run("openssl", "dgst", "-" + alg, "-sign", fx + "/idxkey.pem", path + ".i"); os.remove(path + ".i")
    open(path, "wb").write(gz(tarb([(member, sig)])) + idx + extra)
for name, alg, member, extra in (("three", "sha256", ".SIGN.RSA256.wolfi-signing.rsa.pub", gz(b"extra stream")),
                                  ("sha1", "sha1", ".SIGN.RSA.wolfi-signing.rsa.pub", b""),
                                  ("sha512", "sha512", ".SIGN.RSA512.wolfi-signing.rsa.pub", b"")):
    d = "%s/live-%s" % (w, name); shutil.rmtree(d, ignore_errors=True); shutil.copytree(fx + "/live", d)
    for a in ("x86_64", "aarch64"): signed("%s/%s/APKINDEX.tar.gz" % (d, a), alg, member, extra)
P
for v in three sha1; do
  mkrepo; before=$(treehash "$work/ar" "$work/rp")
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$work/live-$v" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 32" "refresh: a package index of the wrong shape or algorithm ($v) is refused (exit 1, names the index) and nothing changes" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'not a signed apk index|not an RSA-256/512|more than two gzip members' '$work/log'"
  t "rule 32" "refresh: ...($v): archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
done
mkrepo
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$work/live-sha512" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 32" "refresh: an RSA512-signed index that verifies is accepted (exit 0)" test "$(cat "$work/rc")" = 0
# R4 (rest): a version with a slash and an unknown architecture are each refused with exit 2
for bad in version arch; do
  python3 - "$work/ln.json" "$work/evil-$bad.json" "$bad" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "tzdata" and e["architecture"] == "x86_64":
        if sys.argv[3] == "version": e["version"] = "1/../x"
        else: e["architecture"] = "armv7"
json.dump(d, open(sys.argv[2], "w"))
P
  mkrepo; before=$(treehash "$work/ar" "$work/rp")
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/evil-$bad.json" STUB_LOCK_FIPS="$work/evil-$bad.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 48" "refresh: an invalid package $bad in a lock is refused (exit 2, 'invalid package' or 'invalid architecture')" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -Eqi 'invalid (package|architecture)' '$work/log'"
  t "rule 48" "refresh: ...$bad: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
done
# R6: a package url whose host is not packages.wolfi.dev is never fetched
python3 - "$work/ln.json" "$work/evil-host.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "tzdata": e["url"] = "https://evil.example/os/%s/tzdata-2026b-r0.apk" % e["architecture"]
json.dump(d, open(sys.argv[2], "w"))
P
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/evil-host.json" STUB_LOCK_FIPS="$work/evil-host.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 32" "refresh: a lock entry whose url is not under https://packages.wolfi.dev/os/ is refused (exit 2) and never fetched" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -q 'evil.example' '$CALLS' && grep -Eqi 'url|host' '$work/log'"
t "rule 32" "refresh: ...url host: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# NB2: an already open PR for this change (same name or a numbered variant) means no push and no second PR, on every re-run
mkdir -p "$work/stubs4"; cat >"$work/stubs4/git" <<'G'
#!/bin/bash
echo "git $*" >>"$CALLS"
case "$*" in *"rev-parse --abbrev-ref HEAD"*) echo "${GIT_STUB_DETACHED:+HEAD}${GIT_STUB_DETACHED:-main}" | sed 's/^HEAD.*/HEAD/';; esac
case "$*" in *"rev-parse HEAD"*) echo cafe0123;; esac
case "$*" in *"ls-files --error-unmatch"*) [ -z "${GIT_STUB_UNTRACKED:-}" ] || exit 1;; esac
case "$*" in *"push"*"--delete"*) [ -z "${GIT_STUB_DELETE_FAIL:-}" ] || { echo "git: remote delete failed" >&2; exit 1; };; esac
case "$*" in *"push -q origin refresh/"*) [ -z "${GIT_STUB_PUSH_SIGNAL:-}" ] || { kill -TERM $PPID; sleep 1; };; esac   # the script receives TERM right after the remote made the branch
case "$*" in *"checkout -q "*) [ -z "${GIT_STUB_CHECKOUT_FAIL:-}" ] || { echo "git: checkout failed" >&2; exit 1; };; esac
case "$*" in *ls-remote*) for b in ${GIT_STUB_TAKEN:-}; do case "$*" in *"refs/heads/$b") echo "deadbeef	refs/heads/$b";; esac; done;; esac
exit 0
G
cat >"$work/stubs4/gh" <<'G'
#!/bin/bash
echo "gh $*" >>"$CALLS"
case "$*" in "api graphql"*) [ -z "${GH_STUB_API_FAIL:-}" ] || { echo "gh: HTTP 502" >&2; exit 1; }; _in=; _p=; for _a in "$@"; do [ "$_p" = --input ] && _in=$_a; _p=$_a; done; [ -z "$_in" ] || cp "$_in" "$CALLS.graphql"; echo abcdef0123456789abcdef0123456789abcdef01; exit 0;; "api repos/"*"/commits/"*) echo "${GH_STUB_VERIFIED:-true}"; exit 0;; esac
[ -z "${GH_STUB_CLOSED_RAW:-}" ] || case "$*" in "pr list"*"--state closed"*) echo "$GH_STUB_CLOSED_RAW"; exit 0;; esac
case "$*" in "pr list"*"--state closed"*) i=50; sep=; printf '['; for b in ${GH_STUB_CLOSED:-}; do i=$((i+1)); printf '%s{"number":%s,"headRefName":"%s","isCrossRepository":false,"mergedAt":null,"author":{"login":"app/bot"}}' "$sep" "$i" "$b"; sep=,; done; for b in ${GH_STUB_MERGED:-}; do i=$((i+1)); printf '%s{"number":%s,"headRefName":"%s","isCrossRepository":false,"mergedAt":"2026-10-09T00:00:00Z","author":{"login":"app/bot"}}' "$sep" "$i" "$b"; sep=,; done
  for b in ${GH_STUB_CLOSED_FORK:-}; do i=$((i+10)); printf '%s{"number":%s,"headRefName":"%s","isCrossRepository":true,"mergedAt":null,"author":{"login":"app/bot"}}' "$sep" "$i" "$b"; sep=,; done
  for b in ${GH_STUB_CLOSED_FOREIGN:-}; do i=$((i+10)); printf '%s{"number":%s,"headRefName":"%s","isCrossRepository":false,"mergedAt":null,"author":{"login":"someone-else"}}' "$sep" "$i" "$b"; sep=,; done; printf ']\n';; esac
case "$*" in "pr create"*) [ -z "${GH_STUB_CREATE_FAIL:-}" ] || { echo "gh: HTTP 500" >&2; exit 1; };; esac
case "$*" in "pr list"*"--head "*) case "$*" in *" -q length"*) if [ -n "${GH_STUB_HEAD_OPEN:-}" ]; then echo 1; else echo 0; fi;; *) if [ -n "${GH_STUB_HEAD_OPEN:-}" ]; then echo '[{"number":77}]'; else echo '[]'; fi;; esac; exit 0;; esac
case "$*" in "pr create"*) [ -z "${GH_STUB_CREATE_SIGNAL:-}" ] || { echo "https://example.invalid/pull/77"; kill -TERM $PPID; sleep 1; exit 0; };; esac   # the shell runs gh as the last command of a subshell it replaces: $PPID is the script
case "$*" in "pr list"*"--state closed"*) ;; "pr list"*) [ -z "${GH_STUB_FAIL:-}" ] || { echo "gh: HTTP 502" >&2; exit 1; }; i=40; sep=; printf '['
  for b in ${GH_STUB_OPEN:-}; do i=$((i+1)); printf '%s{"number":%s,"headRefName":"%s","isCrossRepository":false,"author":{"login":"app/bot"}}' "$sep" "$i" "$b"; sep=,; done
  for b in ${GH_STUB_FORK:-}; do i=$((i+1)); printf '%s{"number":%s,"headRefName":"%s","isCrossRepository":true,"author":{"login":"app/bot"}}' "$sep" "$i" "$b"; sep=,; done
  for b in ${GH_STUB_FOREIGN:-}; do i=$((i+1)); printf '%s{"number":%s,"headRefName":"%s","isCrossRepository":false,"author":{"login":"someone-else"}}' "$sep" "$i" "$b"; sep=,; done
  printf ']\n';; esac
exit 0
G
chmod +x "$work/stubs4/git" "$work/stubs4/gh"
run_s4() { : >"$CALLS"; PATH="$work/stubs4:$stubs2:$stubs:$PATH" CALLS="$CALLS" STUB_LIB="$work/lib.py" "$@" >"$work/log" 2>&1 </dev/null; echo $? >"$work/rc"; }
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
first=$(grep -E '^git( -C [^ ]+)? checkout -b ' "$CALLS" | head -1 | sed 's/.*checkout -b //')
t "rule 44" "refresh: the branch name is made of the change itself (refresh/<8 hex>), not of the date, so the same change has the same name every day" bash -c "echo '$first' | grep -Eq '^refresh/[0-9a-f]{8}\$'"
mkrepo; run_s4 env GIT_STUB_TAKEN="$first" GH_STUB_OPEN="$first" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "refresh: when a PR for this change is already open, nothing is pushed and no second PR is created (exit 0, says so)" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -Eq '^git( -C [^ ]+)? push' '$CALLS' && ! grep -q '^gh pr create' '$CALLS' && grep -qi 'already open' '$work/log'"
mkrepo; run_s4 env GIT_STUB_TAKEN="$first $first-2" GH_STUB_OPEN="$first-2" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "refresh: an open PR on a NUMBERED variant of the name counts too: still no push, no second PR" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -Eq '^git( -C [^ ]+)? push' '$CALLS' && ! grep -q '^gh pr create' '$CALLS'"
mkrepo; run_s4 env GIT_STUB_TAKEN="$first" GH_STUB_OPEN="" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "refresh: the name is taken but no PR is open for it (a closed one): the numbered branch -2 is used and one PR is created" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -E '^git( -C [^ ]+)? checkout -b ${first//\//\\/}-2\$' '$CALLS' && test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1"
echo "v1.1.0-deadbeef" >"$gr/lib/fips140/certified.txt"; fr
run_s4 env GIT_STUB_TAKEN="refresh/fips-module-v1.1.0-deadbeef" GH_STUB_OPEN="refresh/fips-module-v1.1.0-deadbeef" "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: a PR for this module is already open -> no push, no duplicate PR (the daily job must not open one a day)" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -Eq '^git( -C [^ ]+)? push' '$CALLS' && ! grep -q '^gh pr create' '$CALLS'"

# ---- P3 review round 2 (Sonnet extras): pointer, certified.txt shape, index tied to the locks, datahash, ranges, fetch flags, openssl -----------------------------
mkrepo; run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: no symlink anywhere in the archive after a run (the pointers and every index file are regular files; AC13 amended)" bash -c "test -z \"\$(find '$work/ar' -type l)\" && test -f '$work/ar/aarch64/APKINDEX.tar.gz' && test -f '$work/ar/aarch64/index/APKINDEX-$live_sha_a.tar.gz'"
t "rule 32" "refresh: every download call is HTTPS-only with TLS 1.2 or newer (--proto =https --tlsv1.2)" bash -c "grep '^$FETCH ' '$CALLS' | grep -vq -- '--proto =https --tlsv1.2' && exit 1; test \"\$(grep -c '^$FETCH ' '$CALLS')\" -ge 3"
# certified.txt: exactly one module line
printf 'v1.0.0-c2097c7c\nv1.1.0-deadbeef\n' >"$gr/lib/fips140/certified.txt"; fr; h=$(fhash); run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: a certified.txt with TWO module lines is refused (exit 2, 'exactly one'), recipe unchanged" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -qi 'exactly one' '$work/log' && test \"\$(bash '$work/bhash.sh')\" = '$h'"
printf '# the certified module\n\nv1.0.0-c2097c7c\n' >"$gr/lib/fips140/certified.txt"; fr; run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: comments and blank lines around the one module line are fine (up to date, exit 0)" test "$(cat "$work/rc")" = 0
printf 'v1.0.0-deadbeef\n' >"$gr/lib/fips140/certified.txt"; fr; h=$(fhash); run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: the SAME version with a different hash than the recipe builds is refused (exit 2), recipe unchanged, no PR" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -qi 'same version' '$work/log' && ! grep -q '^gh pr create' '$CALLS' && test \"\$(bash '$work/bhash.sh')\" = '$h'"
# the signed index must list every locked package (name, version, Q1 checksum); a lock the index does not back is refused
python3 - "$fx" "$work" <<'P'
import gzip, io, json, os, shutil, subprocess, sys, tarfile
fx, w = sys.argv[1:3]
def run(*a): return subprocess.run(a, check=True, capture_output=True).stdout
def gz(b):
    o = io.BytesIO()
    with gzip.GzipFile(fileobj=o, mode="wb", mtime=0) as g: g.write(b)
    return o.getvalue()
def tarb(m):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.GNU_FORMAT) as t:
        for n, d in m:
            i = tarfile.TarInfo(n); i.size = len(d); i.mtime = 0; t.addfile(i, io.BytesIO(d))
    return b.getvalue()
def signed(path, text):
    idx = gz(tarb([("APKINDEX", text), ("DESCRIPTION", b"x")])); open(path + ".i", "wb").write(idx)
    sig = run("openssl", "dgst", "-sha256", "-sign", fx + "/idxkey.pem", path + ".i"); os.remove(path + ".i")
    open(path, "wb").write(gz(tarb([(".SIGN.RSA256.wolfi-signing.rsa.pub", sig)])) + idx)
for name, skip in (("noz", "zlib"), ("notz", "tzdata")):
    d = "%s/live-%s" % (w, name); shutil.rmtree(d, ignore_errors=True); shutil.copytree(fx + "/live", d)
    for a in ("x86_64", "aarch64"):
        text = open("%s/itext-%s" % (fx, a)).read().split("\n\n")
        signed("%s/%s/APKINDEX.tar.gz" % (d, a), "\n\n".join(st for st in text if "P:%s\n" % skip not in st).encode())
P
for v in "noz live-mel-new.lock.json zlib" "notz ln-json tzdata"; do
  set -- $v; lockf="$fx/$2"; [ "$2" = ln-json ] && lockf="$work/ln.json"; melf="$fx/live-mel.lock.json"; [ "$1" = noz ] && melf="$fx/live-mel-new.lock.json" && lockf="$fx/live-same.lock.json"
  mkrepo; before=$(treehash "$work/ar" "$work/rp")
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$lockf" STUB_LOCK_FIPS="$lockf" STUB_LOCK_MEL="$melf" STUB_CURL_DIR="$work/live-$1" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 32" "refresh: a signed index that does not list the locked package $3 is refused (exit 1, names the package and the index), no PR" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q '$3' '$work/log' && grep -qi 'index' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
  t "rule 32" "refresh: ...($3 missing from the index): archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
done
# a downloaded apk must carry a datahash equal to the sha256 of its data stream, and the lock must give control and data ranges
python3 - "$work" "$fx" <<'P'
import json, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w, fx = sys.argv[1:3]
d = w + "/live-baddh"; shutil.rmtree(d, ignore_errors=True); shutil.copytree(fx + "/live", d)
sig, ctl, data = lib.mkapk(d + "/x86_64/tzdata-2026b-r0.apk", "tzdata", "2026b-r0", {"usr/share/tzdata/data": b"tzdata-2026b-r0-x86_64"}, signer="wolfi-signing.rsa.pub", datahash="0" * 64)
lk = json.load(open(w + "/ln.json"))
for e in lk["contents"]["packages"]:
    if e["name"] == "tzdata" and e["architecture"] == "x86_64":
        e.update(lib.entry("tzdata", "2026b-r0", "x86_64", e["url"], (sig, ctl, data)))
json.dump(lk, open(w + "/ln-baddh.json", "w"))
ln2 = json.load(open(w + "/ln.json"))
for e in ln2["contents"]["packages"]:
    if e["name"] == "tzdata" and e["architecture"] == "x86_64": e["data"] = {"range": "", "checksum": ""}
json.dump(ln2, open(w + "/ln-norange.json", "w"))
P
for v in baddh norange; do
  mkrepo; before=$(treehash "$work/ar" "$work/rp"); cdir="$fx/live"; [ $v = baddh ] && cdir="$work/live-baddh"
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln-$v.json" STUB_LOCK_FIPS="$work/ln-$v.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$cdir" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 48" "refresh: $v -> refused (exit 1; the datahash in the control section must equal the sha256 of the data stream, and control and data ranges are required)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'datahash|range' '$work/log'"
  t "rule 48" "refresh: ...$v: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
done
# openssl is needed to verify the index: a missing one is a named refusal (exit 2), not a traceback
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env "${rfn[@]:1}" "$RFN" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 32" "refresh: openssl missing -> exit 2 naming openssl, no traceback, trees unchanged" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -qi 'openssl' '$work/log' && ! grep -q Traceback '$work/log'"
t "rule 32" "refresh: ...openssl missing: unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"

# ---- P3 round 3 (Sonnet + Opus): ASCII digits, the index must list every lock entry in EACH index, atomic writes, preflight, fail-closed PR lookup ----
# non-ASCII digits are not digits: Arabic-Indic and fullwidth digits in certified.txt are refused
for nm in "v١.٠.٠-c2097c7d" "v１.０.０-c2097c7d"; do
  printf '%s\n' "$nm" >"$gr/lib/fips140/certified.txt"; fr; h3=$(bash "$work/bhash.sh")
  run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
  t "rule 73" "fips-module: a certified.txt value written with non-ASCII digits ($nm) is refused (exit 2, names certified.txt), recipe unchanged, no PR" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'certified.txt' '$work/log' && ! grep -q '^gh pr create' '$CALLS' && test \"\$(bash '$work/bhash.sh')\" = '$h3'"
done
# signed-index variants: the same signed fixtures as above, one thing changed per variant
cat >"$work/mkidx.py" <<'P'
import gzip, hashlib, io, json, os, shutil, subprocess, sys, tarfile
fx, w = sys.argv[1:3]
def run(*a): return subprocess.run(a, check=True, capture_output=True).stdout
def gz(b):
    o = io.BytesIO()
    with gzip.GzipFile(fileobj=o, mode="wb", mtime=0) as g: g.write(b)
    return o.getvalue()
def tarb(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.GNU_FORMAT) as t:
        for n, d in members:
            i = tarfile.TarInfo(n); i.size = len(d); i.mtime = 0; t.addfile(i, io.BytesIO(d))
    return b.getvalue()
def signed(path, text, alg="sha256", member="RSA256", pad=0):
    idx = gz(tarb([("APKINDEX", text + b"#" * pad), ("DESCRIPTION", b"fixture")]))
    open(path + ".idx", "wb").write(idx)
    sig = run("openssl", "dgst", "-" + alg, "-sign", fx + "/idxkey.pem", path + ".idx"); os.remove(path + ".idx")
    open(path, "wb").write(gz(tarb([(".SIGN.%s.wolfi-signing.rsa.pub" % member, sig)])) + idx)
def mutate(text, how):
    recs = text.split(b"\n\n")
    for i, r in enumerate(recs):
        if b"P:tzdata\nV:2026b-r0" in r:
            recs[i] = r.replace(b"V:2026b-r0", b"V:2026b-r9") if how == "v" else r.replace(b"C:Q1", b"C:Q2", 1)
    return b"\n\n".join(recs)
def variant(name, arch, **kw):
    d = "%s/lv-%s" % (w, name); shutil.rmtree(d, ignore_errors=True); shutil.copytree(fx + "/live", d)
    text = open("%s/itext-%s" % (fx, arch), "rb").read()
    how = kw.pop("how", None)
    signed("%s/%s/APKINDEX.tar.gz" % (d, arch), mutate(text, how) if how else text, **kw)
for arch in ("x86_64", "aarch64"):
    for how in ("c", "v"):
        variant("%s-%s" % (arch, how), arch, how=how)
variant("legacy", "x86_64", alg="sha1", member="RSA")
variant("bomb", "aarch64", pad=130 * 1024 * 1024)
P
python3 "$work/mkidx.py" "$fx" "$work"
for v in aarch64-c aarch64-v x86_64-c x86_64-v; do
  mkrepo; before=$(treehash "$work/ar" "$work/rp")
  run_s2 "${rfn[@]}" STUB_CURL_DIR="$work/lv-$v" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 48" "refresh: a signed index ($v: tzdata listed with another ${v##*-}) that does not list a locked package with its version and checksum is refused (exit 1, 'does not list'), whichever architecture it is" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'does not list' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
  t "rule 48" "refresh: ...$v: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
done
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfn[@]}" STUB_CURL_DIR="$work/lv-legacy" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: a legacy sha1 signature (.SIGN.RSA.<key>) on the index is refused (exit 1, names RSA-256/512)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'RSA-256/512|not an RSA' '$work/log'"
t "rule 48" "refresh: ...legacy: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfn[@]}" STUB_CURL_DIR="$work/lv-bomb" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: an index that decompresses to more than 128 MiB is refused before its signature is checked (exit 1, names the limit)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi '128 MiB|too large' '$work/log'"
t "rule 48" "refresh: ...bomb: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# the PREVIOUS index (a plain APKINDEX.tar.gz) is also hashed against its digest name before it is kept
oldsha=$(shasum -a 256 "$fx/archive/aarch64/APKINDEX.tar.gz" | cut -d' ' -f1)
mkrepo; mkdir -p "$work/ar/aarch64/index"; printf garbage >"$work/ar/aarch64/index/APKINDEX-$oldsha.tar.gz"; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: garbage under the digest name of the PREVIOUS plain index (the 'keep it first' copy) is refused (exit 1, 'hash'), nothing changed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'hash' '$work/log'"
t "rule 31" "refresh: ...previous index: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# a lock whose CONTROL range is empty is refused like one whose data range is empty
python3 - "$work/ln.json" "$work/ln-noctl.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "tzdata" and e["architecture"] == "x86_64": e["control"] = {"range": "", "checksum": ""}
json.dump(d, open(sys.argv[2], "w"))
P
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln-noctl.json" STUB_LOCK_FIPS="$work/ln-noctl.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: a lock entry with no CONTROL range is refused (exit 1, names range): the identity checksum and the datahash cannot be checked without it" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'control range|range' '$work/log'"
t "rule 48" "refresh: ...no control range: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# production and FIPS locks that disagree about the same package are refused (both are checked against the bytes)
python3 - "$work/ln.json" "$work/ln-fipsdiff.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "tzdata" and e["architecture"] == "x86_64": e["data"]["checksum"] = "sha256-" + "A" * 43 + "="
json.dump(d, open(sys.argv[2], "w"))
P
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln-fipsdiff.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: the production and FIPS locks name the same package with different checksums -> refused (exit 1, 'disagree'), nothing changed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'disagree' '$work/log'"
t "rule 48" "refresh: ...disagreement: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# an .apk with two datahash lines in its control section is refused
python3 - "$work" "$fx" <<'P'
import copy, json, os, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w, fx = sys.argv[1:3]
d = w + "/dup-live"; shutil.rmtree(d, ignore_errors=True); shutil.copytree(fx + "/live", d)
lk = json.load(open(w + "/ln.json"))
for arch in ("x86_64", "aarch64"):
    data = lib.gz(lib.tarb([("usr/share/tzdata/data", ("tzdata-2026b-r0-" + arch).encode())]))
    dh = lib.hashlib.sha256(data).hexdigest()
    ctrl = lib.gz(lib.tarb([(".PKGINFO", ("pkgname = tzdata\npkgver = 2026b-r0\ndatahash = %s\ndatahash = %s\n" % (dh, "0" * 64)).encode())]))
    open("%s/%s/tzdata-2026b-r0.apk" % (d, arch), "wb").write(ctrl + data)
    for e in lk["contents"]["packages"]:
        if e["name"] == "tzdata" and e["architecture"] == arch:
            ne = lib.entry("tzdata", "2026b-r0", arch, e["url"], (b"", ctrl, data)); e.update({k: ne[k] for k in ("control", "data", "checksum", "signature")})
json.dump(lk, open(w + "/ln-dup.json", "w"))
P
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln-dup.json" STUB_LOCK_FIPS="$work/ln-dup.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$work/dup-live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: an apk whose control section has two datahash lines is refused (exit 1, 'datahash'), nothing changed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'datahash' '$work/log'"
t "rule 48" "refresh: ...two datahash lines: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# no test hook in the production script; the test copy differs from it on the TEST-SUBST lines only (REQ-REFRESH-001-AC23)
sr2() { local ac=$1 d=$2 kw=$3; shift 3; "$@"; if [ "$(rc)" = 2 ] && grep -Eqi -- "$kw" "$work/log"; then ok; else bad "$ac" "$d (exit $(rc), wanted 2 naming '$kw')"; fi; }
t "AC23" "refresh-inputs.sh has no test hook: no REFRESH_OPENSSL and no FSCACHE_TEST_MODE in the production file" bash -c "! grep -Eq 'REFRESH_OPENSSL|FSCACHE_TEST_MODE|FSCACHE_[A-Z_]+' '$RF_PROD'"
t "AC23" "the test copy of refresh-inputs.sh differs from the production file ONLY in occurrences of the ten fixed paths, each replaced one for one by the dispatcher of that tool (any other byte difference fails)" python3 - "$RF_PROD" "$RF" "$rfd/tools" <<'P'
import os, re, sys
a = open(sys.argv[1]).read(); b = open(sys.argv[2]).read(); tools = sys.argv[3]
paths = {"python3": "/usr/bin/python3", os.environ["FETCH"]: "/usr/bin/" + os.environ["FETCH"], "git": "/usr/bin/git", "gh": "/usr/bin/gh", "apko": "/usr/local/bin/apko",
         "openssl": "/usr/bin/openssl", "cmp": "/usr/bin/cmp", "mktemp": "/usr/bin/mktemp", "rm": "/bin/rm", "mkdir": "/bin/mkdir"}
pa = re.compile(r"(?<![\w./-])(%s)(?![\w.-])" % "|".join(re.escape(p) for p in sorted(paths.values(), key=len, reverse=True)))
pb = re.compile(r"(?<![\w./-])%s/(%s)(?![\w.-])" % (re.escape(tools), "|".join(re.escape(n) for n in paths)))
fa = pa.findall(a); fb = pb.findall(b)
assert len(fa) == len(fb) and [paths[n] for n in fb] == fa, ("occurrences differ", len(fa), len(fb))
assert pb.sub(lambda m: paths[m.group(1)], b) == a, "the copy differs from the production file in more than the ten fixed paths"
assert set(fa) == set(paths.values()), sorted(set(paths.values()) - set(fa))
P
t "AC23" "refresh-inputs.sh names its download tool, git, gh, apko, openssl, python3, cmp, mktemp, rm and mkdir by their literal fixed absolute path at the call (no variable holds a program), and runs every python3 with -I -B" python3 - "$RF_PROD" <<'P'
import os, re, sys
s = open(sys.argv[1]).read()
for want in ("/usr/bin/python3", "/usr/bin/" + os.environ["FETCH"], "/usr/bin/git", "/usr/bin/gh", "/usr/local/bin/apko", "/usr/bin/openssl", "/usr/bin/cmp", "/usr/bin/mktemp", "/bin/rm", "/bin/mkdir"):
    assert want in s, want
code = [l for l in s.split("\n") if not l.lstrip().startswith("#")]
inh = None; bad = []
for n, l in enumerate(code, 1):
    if inh:
        if l.strip() == inh: inh = None
        continue
    m = re.search(r"<<'(\w+)'", l)
    if m: inh = m.group(1)
    if re.search(r"(?:^|[;&|(]|\$\(|\bthen |\bdo |\belse |\|\| |&& |! )\s*\"?\$\{?(PY3|CURL|GIT|GH|APKO|OPENSSL|CMP|MKTEMP|RM|MKDIR)\}?\"?\s", l): bad.append("%d: %s" % (n, l.strip()[:90]))
    if re.match(r"^(?:printf -v )?(PY3|CURL|GIT|GH|APKO|OPENSSL|CMP|MKTEMP|RM|MKDIR)(?:=| %s )", l): bad.append("assignment: " + l[:60])
assert not bad, bad
uses = re.findall(r"/usr/bin/python3(?!\")[^\n]*", "\n".join(code))   # the shell calls; the calls inside the heredocs are judged by the subprocess test
assert len(uses) >= 3 and all(u.startswith("/usr/bin/python3 -I -B") for u in uses), uses
P
t "AC23" "every program the embedded Python runs is a literal fixed absolute path in the call itself (subprocess.run([\"/usr/bin/...\", ...]): no GH, CURL, OPENSSL or sys.executable variable names a program)" python3 - "$RF_PROD" <<'P'
import re, sys
s = open(sys.argv[1]).read()
calls = re.findall(r"subprocess\.(?:run|Popen|check_output|check_call|call)\(\s*\[\s*([^,\]\n]+)", s)
assert calls, "no subprocess call found"
bad = [c for c in calls if not re.fullmatch(r'"/(?:usr/(?:local/)?bin|bin)/[a-z0-9]+"', c.strip())]
assert not bad, bad
assert not re.search(r"(?m)^(GH|CURL|OPENSSL)(?:\s*,\s*(GH|CURL|OPENSSL))*\s*=\s*sys\.argv", s), "a program is read from argv"
P
# url checks are parsed, not prefix-matched
n=0; for u in 'https://packages.wolfi.dev:444/os/%s/tzdata-2026b-r0.apk' 'https://user@packages.wolfi.dev/os/%s/tzdata-2026b-r0.apk' 'https://packages.wolfi.dev/os/../x/%s/tzdata-2026b-r0.apk' 'https://packages.wolfi.dev/os/%s\tzdata-2026b-r0.apk' 'http://packages.wolfi.dev/os/%s/tzdata-2026b-r0.apk' 'https://packages.wolfi.dev.evil.example/os/%s/tzdata-2026b-r0.apk'; do
  n=$((n+1)); python3 - "$work/ln.json" "$work/evil-url$n.json" "$u" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "tzdata": e["url"] = sys.argv[3] % e["architecture"]
json.dump(d, open(sys.argv[2], "w"))
P
  mkrepo; before=$(treehash "$work/ar" "$work/rp")
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/evil-url$n.json" STUB_LOCK_FIPS="$work/evil-url$n.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 32" "refresh: the url '$u' is refused (exit 2) and never fetched" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -Eq 'evil|:444|user@' '$CALLS' && grep -Eqi 'url|host' '$work/log'"
  t "rule 32" "refresh: ...url $n: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
done
# fail closed on the pull request lookup, and one open refresh PR at a time
mkrepo; run_s4 env GH_STUB_FAIL=1 "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "refresh: if 'gh pr list' fails the job fails (exit 1): no push, no PR (an unknown PR state is not 'no PR')" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -Eq '^git( -C [^ ]+)? push|^gh pr create' '$CALLS'"
mkrepo; : >"$work/summary.md"; run_s4 env GITHUB_STEP_SUMMARY="$work/summary.md" GH_STUB_OPEN="refresh/00000000" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "refresh: ...and the stall is visible: the log and the job summary name that PR's number (#41)" bash -c "grep -q '#41' '$work/log' && grep -q '#41' '$work/summary.md'"
t "rule 49" "refresh: an EARLIER refresh PR (a different change) is still open -> no push and no second PR (at most one open refresh PR; the next daily run continues after it is merged or closed)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! grep -Eq '^git( -C [^ ]+)? push|^gh pr create' '$CALLS'"
mkrepo; run_s4 env GH_STUB_OPEN="refresh/fips-module-v1.1.0-deadbeef" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC29" "refresh: an open FIPS-module PR blocks the input refresh PR (AC29 names no kind: with a refresh pull request already open it opens no second): no branch, no push, no PR" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! grep -Eq '^git( -C [^ ]+)? (push|checkout -b)|^gh pr create' '$CALLS'"
echo "v1.1.0-deadbeef" >"$gr/lib/fips140/certified.txt"; fr
run_s4 env GH_STUB_OPEN="refresh/00000000" "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "AC29" "fips-module: an open input-refresh PR blocks the FIPS-module PR (the reverse of the case above): no push, no PR" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -Eq '^git( -C [^ ]+)? push|^gh pr create' '$CALLS'"
# bootstrap: nothing changed but the index record is missing -> the record is written from the verified live index (a PR carries it)
mkrepo; rm -f "$work/rp/build/locks/archive-index.sha256"
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: nothing changed against live Wolfi but build/locks/archive-index.sha256 is missing -> the record is written (from the verified index) and a PR opened" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -s '$work/rp/build/locks/archive-index.sha256' && grep -q '^gh pr create' '$CALLS' && grep -q 'x86_64 sha256:$live_sha_x' '$work/rp/build/locks/archive-index.sha256'"
# an archived package that is missing although its lock entry did not change is fetched again (nothing to commit: the archive is not in git)
mkrepo; rm -f "$work/ar/x86_64/tzdata-2026a-r0.apk"; rm -rf "$work/live-restore"; cp -R "$fx/live" "$work/live-restore"; cp "$fx/archive/x86_64/tzdata-2026a-r0.apk" "$work/live-restore/x86_64/"
run_s4 "${rfe[@]}" STUB_CURL_DIR="$work/live-restore" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 27" "refresh: nothing changed but an archived package file is missing -> it is fetched again and verified (exit 0), and no PR is opened" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -f '$work/ar/x86_64/tzdata-2026a-r0.apk' && ! grep -Eq '^gh pr create|^git( -C [^ ]+)? push' '$CALLS'"
# a missing archived package that cannot be fetched again (upstream gone) fails the job naming the package
mkrepo; rm -f "$work/ar/x86_64/tzdata-2026a-r0.apk"; before=$(treehash "$work/ar" "$work/rp")
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 27" "refresh: a missing archived package that live Wolfi no longer serves fails the job (exit 1) naming tzdata-2026a-r0, no PR" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'tzdata-2026a-r0' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
t "rule 27" "refresh: ...nothing changed" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# -- atomic placement: a copy that dies half-way leaves nothing under a final name, and the next run still succeeds
# the production script runs python3 -I (the caller's PYTHONPATH is ignored); the fault injection needs the interpreter's site hook, so for these runs only
# the python3 found by name is a wrapper that drops -I and runs the real interpreter
mkdir -p "$work/faultbin"; real_py=$(command -v python3)
printf '#!/bin/bash\nargs=(); for a in "$@"; do [ "$a" = -I ] || args+=("$a"); done\nexec %s "${args[@]}"\n' "$real_py" >"$work/faultbin/python3"; chmod +x "$work/faultbin/python3"
mkdir -p "$work/faultinj"; cat >"$work/faultinj/sitecustomize.py" <<'P'
import os, shutil, sys
here = os.path.abspath(os.path.dirname(__file__))
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != here]   # chain to the interpreter's own sitecustomize (it sets up the site-packages)
sys.modules.pop("sitecustomize", None)
try:
    import sitecustomize
except ImportError:
    pass
what = os.environ.get("FAULT_COPY")
if what:
    def boom(src, dst, *a, **k):
        if what in str(dst):
            open(dst, "wb").write(open(src, "rb").read()[:20]); os._exit(137)
        return real(src, dst, *a, **k)
    _cfo = shutil.copyfileobj
    def _cfo_boom(src, dst, *a, **k):
        if what in str(getattr(dst, "name", "")):
            dst.write(src.read(20)); dst.flush(); os._exit(137)
        return _cfo(src, dst, *a, **k)
    shutil.copyfileobj = _cfo_boom
    for n in ("copy2", "copyfile", "copy", "move"):
        real = getattr(shutil, n); setattr(shutil, n, (lambda r: (lambda src, dst, *a, **k: boom_with(r, src, dst, *a, **k)))(real))
    def boom_with(r, src, dst, *a, **k):
        if what in str(dst):
            open(dst, "wb").write(open(src, "rb").read()[:20]); os._exit(137)
        return r(src, dst, *a, **k)
P
for what in APKINDEX .apk; do
  mkrepo; run_s4 env PATH="$work/faultbin:$work/stubs4:$stubs2:$stubs:$PATH" PYTHONPATH="$work/faultinj:${PYTHONPATH:-}" FAULT_COPY="$what" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 31" "refresh: a copy into a '$what' file is killed half-way (the run dies with exit 137)" test "$(cat "$work/rc")" = 137
  t "rule 31" "refresh: ...and leaves no file under a final name in the archive (temp names only)" test "$(find "$work/ar" -type f \( -path "*/index/APKINDEX-*" -o -name "tzdata-2026b-r0.apk*" \) | grep "$([ "$what" = APKINDEX ] && echo APKINDEX || echo 'r0\.apk')" | grep -vc '\.tmp-')" = 0
  run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 31" "refresh: ...and the next run (stale temp files left behind) succeeds" test "$(cat "$work/rc")" = 0
done
# a truncated or wrong apk already under its final name is a named human stop (what to delete), not a silent re-use
mkrepo; head -c 100 "$fx/live/x86_64/tzdata-2026b-r0.apk" >"$work/ar/x86_64/tzdata-2026b-r0.apk"; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: a truncated apk under its final archive name stops the job (exit 1), names the file and says to delete it" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'tzdata-2026b-r0.apk' '$work/log' && grep -Eqi 'delete' '$work/log'"
t "rule 31" "refresh: ...truncated apk: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# writability is checked before anything changes
if [ "$(id -u)" != 0 ]; then
  mkrepo; chmod 555 "$work/rp/build/locks"; before=$(treehash "$work/ar" "$work/rp")
  run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  chmod 755 "$work/rp/build/locks"
  t "rule 48" "refresh: a repository DIRECTORY that cannot take the rename (build/locks mode 555) is refused BEFORE any change (exit 1, names the path, no traceback)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'build/locks' '$work/log' && ! grep -q Traceback '$work/log'"
  t "rule 48" "refresh: ...unwritable directory: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
  # a read-only FILE in a writable directory is fine (it is replaced by a rename), also an archived index file and a read-only pointer target
  mkrepo; chmod 444 "$work/rp/build/locks/apko.base.lock.json" "$work/ar/x86_64/APKINDEX.tar.gz"
  run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 48" "refresh: read-only FILES in writable directories (a lock file, the previous index) are not a reason to refuse: they are replaced by rename" test "$(cat "$work/rc")" = 0
  mkrepo; mkdir -p "$work/ar/x86_64/APKINDEX.tar.gz.new"; before=$(treehash "$work/ar" "$work/rp")
  run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 48" "refresh: a stale directory where the pointer's temp name goes is refused BEFORE any change (exit 1), archive and repo unchanged" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'APKINDEX.tar.gz.new' '$work/log'"
  t "rule 48" "refresh: ...stale temp name: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
fi
# every directory on the way into the archive is a real directory
mkrepo; mkdir -p "$work/ic-out/index"; mv "$work/ar/x86_64/index" "$work/ic-out/index-moved" 2>/dev/null || true; ln -s "$work/ic-out/index" "$work/ar/x86_64/index"; before=$(treehash "$work/rp")
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: an index/ directory in the archive that is a symlink out of it is refused (exit 1, names symlink); nothing was written through it" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'symlink' '$work/log' && test -z \"\$(ls -A '$work/ic-out/index')\""

# ---- snapshot-4 round 4 (Sonnet P3): every archived file is verified on every run; the preflight comes first on every path; repo files are atomic; PR check first ----
first_apk=$(cd "$fx/archive/x86_64" && ls *.apk | head -1)
mkrepo; : >"$work/trunc"; head -c 50 "$work/ar/x86_64/$first_apk" >"$work/trunc"; cp "$work/trunc" "$work/ar/x86_64/$first_apk"; before=$(treehash "$work/ar" "$work/rp")
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 27" "refresh: an archived file truncated to 50 bytes while the lock is UNCHANGED stops the job (exit 1), names the file and says to delete it" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q '$first_apk' '$work/log' && grep -qi 'delete' '$work/log'"
t "rule 27" "refresh: ...truncated, unchanged lock: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
mkrepo; printf 'other bytes entirely' >"$work/ar/x86_64/$first_apk"; before=$(treehash "$work/ar" "$work/rp")
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 27" "refresh: an archived file with other bytes under an unchanged lock stops the job (exit 1, names it)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q '$first_apk' '$work/log'"
mel_apk=$(cd "$fx/envrepo/x86_64" && ls *.apk | grep -v -F -f <(cd "$fx/archive/x86_64" && ls *.apk) | head -1)
if [ -n "$mel_apk" ]; then
  mkrepo; printf 'damaged build tool' >"$work/ar/x86_64/$mel_apk"
  run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 27" "refresh: a damaged archived BUILD TOOL (a melange-only package) is found too" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q '$mel_apk' '$work/log'"
fi
# the preflight also guards the re-fetch path
mkrepo; mkdir -p "$work/outside"; rm -f "$work/ar/x86_64/tzdata-2026a-r0.apk"; mv "$work/ar/x86_64" "$work/outside/x86_64-real"; ln -s "$work/outside/x86_64-real" "$work/ar/x86_64"; rm -rf "$work/live-restore"; cp -R "$fx/live" "$work/live-restore"; cp "$fx/archive/x86_64/tzdata-2026a-r0.apk" "$work/live-restore/x86_64/" 2>/dev/null || cp "$work/outside/x86_64-real/"tzdata-2026a-r0.apk "$work/live-restore/x86_64/" 2>/dev/null || true
run_s4 "${rfe[@]}" STUB_CURL_DIR="$work/live-restore" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "refresh: with archive/x86_64 a symlink to an outside directory the re-fetch path refuses (exit 1, names symlink) and writes nothing through it" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi symlink '$work/log' && test ! -e '$work/outside/x86_64-real/tzdata-2026a-r0.apk'"
# an open refresh PR is looked for FIRST: nothing in the archive or the repository changes, and the stall is visible with its number
mkrepo; : >"$work/summary2.md"; before=$(treehash "$work/ar" "$work/rp")
run_s4 env GITHUB_STEP_SUMMARY="$work/summary2.md" GH_STUB_OPEN="$first" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "refresh: an open PR that is this very change: the log and the job summary name its number (#41), exit 0, nothing pushed" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -q '#41' '$work/log' && grep -q '#41' '$work/summary2.md' && ! grep -Eq '^git( -C [^ ]+)? push|^gh pr create' '$CALLS'"
t "rule 49" "refresh: ...and the archive and the repository are unchanged (the PR lookup comes before any archive change)" test "$(treehash "$work/ar" "$work/rp")" = "$before"
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s4 env GH_STUB_OPEN="refresh/00000000" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "refresh: an earlier open PR (another change): the archive and the repository are unchanged as well" test "$(treehash "$work/ar" "$work/rp")" = "$before"
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s4 env GH_STUB_FAIL=1 "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "refresh: ...and when the PR lookup fails (exit 1) nothing was changed either" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# repo files are written under a temp name and renamed: a kill mid-write leaves the old file whole
for f in build/locks/apko.base.lock.json build/locks/melange.lock build/locks/archive-index.sha256 build/melange.yaml; do
  mkrepo; rm -f "$work/rp/build/locks/archive-index.sha256"; [ "$f" = build/locks/archive-index.sha256 ] || cp "$fx/repo/build/locks/archive-index.sha256" "$work/rp/build/locks/" 2>/dev/null; oldsum=$(shasum -a 256 "$work/rp/$f" 2>/dev/null | cut -d' ' -f1)
  run_s4 env PATH="$work/faultbin:$work/stubs4:$stubs2:$stubs:$PATH" PYTHONPATH="$work/faultinj:${PYTHONPATH:-}" FAULT_COPY="$(basename "$f")" "${rfn[@]:1}" STUB_LOCK_MEL="$fx/live-mel-new.lock.json" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 44" "refresh: a kill (137) while writing $f leaves the file as it was (temp name, then rename)" bash -c "test \"\$(cat '$work/rc')\" = 137 && { test ! -e '$work/rp/$f' && test -z '$oldsum' || test \"\$(shasum -a 256 '$work/rp/$f' | cut -d' ' -f1)\" = '$oldsum'; }"
done
# bytes after the last range are rejected when the package is downloaded, not only later
rm -rf "$work/live-trail"; cp -R "$fx/live" "$work/live-trail"; printf 'TRAILING' >>"$work/live-trail/x86_64/tzdata-2026b-r0.apk"
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s4 "${rfn[@]}" STUB_CURL_DIR="$work/live-trail" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: bytes after the last range of a downloaded apk are refused (exit 1, names the end of the file)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'end|trailing|range' '$work/log'"
t "rule 48" "refresh: ...trailing bytes: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# url characters, fetch flags and caps
n=0; for u in 'https://packages.wolfi.dev/os/ARCH/tzdata 2026b-r0.apk' 'https://packages.wolfi.dev/os/ARCH/tzdata%2e2026b-r0.apk' 'https://packages.wolfi.dev/os/ARCH/*.apk' 'https://packages.wolfi.dev/os/ARCH/{a,b}.apk'; do
  n=$((n+1)); python3 - "$work/ln.json" "$work/evil-chr$n.json" "$u" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "tzdata": e["url"] = sys.argv[3].replace("ARCH", e["architecture"])
json.dump(d, open(sys.argv[2], "w"))
P
  mkrepo; run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/evil-chr$n.json" STUB_LOCK_FIPS="$work/evil-chr$n.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 32" "refresh: the url '$u' (a character outside the plain set) is refused (exit 2), never fetched" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -E '^$FETCH .*tzdata' '$CALLS'"
done
mkrepo; run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 32" "refresh: every package and index download is globoff (-g), size-capped (--max-filesize) and time-capped (--max-time)" bash -c "grep '^$FETCH ' '$CALLS' | grep -E 'tzdata|APKINDEX' | grep -v -E -- '(-g|--globoff).*--max-filesize|--max-filesize.*(-g|--globoff)' | grep -q . && exit 1; grep '^$FETCH ' '$CALLS' | grep -E 'tzdata|APKINDEX' | grep -q -- '--max-time'"
t "rule 32" "every live fetch is a shell line in the ruled grammar: -q first, the fixed flags (-fsSL -g --max-filesize N --max-time N --proto =https --tlsv1.2 -o FILE), exactly one operand that is a literal https://packages.wolfi.dev URL, \"https://packages.wolfi.dev/os/\$p\" or \"https://go.dev/dl/\$f\", optional || die \"plain\" N; the embedded Python runs no download" python3 -I - "$RF_PROD" <<'PYT'
import re, sys
s = open(sys.argv[1]).read()
lines = [l for l in s.split("\n") if " -fsSL " in l and not l.lstrip().startswith("#")]   # the fetch lines are the ones carrying the fixed flag cluster
shell = [l for l in lines if l.lstrip().startswith("/usr/bin/")]
assert len(shell) == len(lines) and len(lines) == 7, "every fetch line is a shell line (4 key fetches, packages, the Go toolchain, index): %d of %d" % (len(shell), len(lines))
g = re.compile(r'^\s+/usr/bin/[a-z]+ -q -fsSL -g --max-filesize [0-9]+ --max-time [0-9]+ --proto =https --tlsv1\.2 -o "[^"]*" ("https://packages\.wolfi\.dev/os/\$p"|"https://go\.dev/dl/\$f"|https://packages\.wolfi\.dev/os/wolfi-signing\.rsa\.pub)( \|\| die "[^"$]*" [0-9]+)?$')
bad = [l for l in lines if not g.match(l)]
assert not bad, bad
assert '"-fsSL"' not in s   # the embedded Python passes no fetch flags: it runs no download
PYT
t "rule 31" "refresh: the temp files are opened exclusively (O_EXCL) with an unpredictable name, so a planted symlink is never followed" bash -c "grep -q 'O_EXCL' '$RF' && grep -q 'secrets\\|token_hex\\|urandom' '$RF'"
# the previous pointer's TARGET is hashed too
mkrepo; mkdir -p "$work/ar/x86_64/index"; tgt="APKINDEX-$live_sha_x.tar.gz"; cp "$fx/live/x86_64/APKINDEX.tar.gz" "$work/ar/x86_64/index/$tgt"; rm -f "$work/ar/x86_64/APKINDEX.tar.gz"; ln -s "index/$tgt" "$work/ar/x86_64/APKINDEX.tar.gz"; before=$(treehash "$work/ar" "$work/rp")
run_s4 "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar" 2>/dev/null || true
run_s4 env "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: a pointer that is a symlink is refused whatever it points to (the pointer is a regular-file copy; AC13 amended): exit 1, names symlink, nothing changed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'symlink' '$work/log'"
t "rule 31" "refresh: ...previous pointer target: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"

# ---- snapshot-4 round 4 (Opus P3): only our own PRs hold the refresh back; version grammar; archive-name collisions -----------------------------------------------
for who in FORK FOREIGN; do
  mkrepo; run_s4 env GH_STUB_$who="refresh/fix-typo" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar" --pr-author app/bot
  t "rule 49" "refresh: an open PR on a refresh/ branch from a $who is NOT counted: the refresh still opens its PR (a stranger cannot hold back security refreshes)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -q '^gh pr create' '$CALLS'"
done
mkrepo; run_s4 env GH_STUB_OPEN="refresh/00000000" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar" --pr-author app/bot
t "rule 49" "refresh: our own earlier PR (same repository, the job's author) still counts" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
mkrepo; run_s4 env GH_STUB_FORK="refresh/fips-module-v1.1.0-deadbeef" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "refresh: ...a fork PR is not counted even when no author is configured" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -q '^gh pr create' '$CALLS'"
t "rule 49" "refresh: the PR list asks for 1000 PRs and for the fields that identify the repository and the author" bash -c "grep '^gh pr list' '$CALLS' | grep -q -- '--limit 1000' && grep '^gh pr list' '$CALLS' | grep -q 'isCrossRepository' && grep '^gh pr list' '$CALLS' | grep -q 'author'"
# FIPS module: a leading zero is not the same version spelled differently
for v in "v1.0.00-deadbeef" "v01.0.0-deadbeef" "v1.00.0-deadbeef"; do
  echo "$v" >"$gr/lib/fips140/certified.txt"; fr; h3=$(bash "$work/bhash.sh")
  run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
  t "rule 73" "fips-module: '$v' (a leading zero) is refused (exit 2, names certified.txt), recipe unchanged, no PR" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'certified.txt' '$work/log' && ! grep -q '^gh pr create' '$CALLS' && test \"\$(bash '$work/bhash.sh')\" = '$h3'"
done
# a lock range with a non-ASCII digit, an existing versioned index that is a symlink, and two packages that map to the same archive file name
python3 - "$work/ln.json" "$work/ln-arabic.json" "$work/ln-collide.json" <<'P'
import copy, json, sys
d = json.load(open(sys.argv[1]))
a = copy.deepcopy(d)
for e in a["contents"]["packages"]:
    if e["name"] == "tzdata" and e["architecture"] == "x86_64": e["control"]["range"] = e["control"]["range"].replace("bytes=", "bytes=١")
json.dump(a, open(sys.argv[2], "w"))
c = copy.deepcopy(d)
for arch in ("x86_64", "aarch64"):
    base_e = [e for e in c["contents"]["packages"] if e["name"] == "tzdata" and e["architecture"] == arch][0]
    e1 = copy.deepcopy(base_e); e1["name"], e1["version"] = "a-1", "2"
    e2 = copy.deepcopy(base_e); e2["name"], e2["version"] = "a", "1-2"
    c["contents"]["packages"] += [e1, e2]
json.dump(c, open(sys.argv[3], "w"))
P
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln-arabic.json" STUB_LOCK_FIPS="$work/ln-arabic.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: a lock range written with a non-ASCII digit is refused (exit 1, names the checksum or range), nothing changed" bash -c "test \"\$(cat '$work/rc')\" != 0 && test \"\$(cat '$work/rc')\" != 127 && ! grep -q Traceback '$work/log'"
t "rule 48" "refresh: ...non-ASCII digit: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln-collide.json" STUB_LOCK_FIPS="$work/ln-collide.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: two packages that map to the same archive file name (a-1 version 2, and a version 1-2) are refused (exit 1, names the file)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'a-1-2.apk' '$work/log'"
t "rule 48" "refresh: ...name collision: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
mkrepo; mkdir -p "$work/ar/x86_64/index"; sha_live_x=$(shasum -a 256 "$fx/live/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1); cp "$fx/live/x86_64/APKINDEX.tar.gz" "$work/real-index"; ln -s "$work/real-index" "$work/ar/x86_64/index/APKINDEX-$sha_live_x.tar.gz"; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: an existing index/APKINDEX-<sha256> that is a SYMLINK (even to the right bytes) is refused (exit 1)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'hash\|symlink\|regular' '$work/log'"
t "rule 31" "refresh: ...index symlink: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"

# ---- snapshot-5 round 5 (Sonnet/Opus P3) -------------------------------------------------------------------------------------------------------------------------
# the archive's index is re-checked on EVERY run (a day with no lock change too)
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
named="$work/ar/x86_64/index/APKINDEX-$live_sha_x.tar.gz"; printf 'garbage' >"$named"
before=$(treehash "$work/ar" "$work/rp")
run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "refresh: nothing changed in the locks but the archive's index file was replaced by garbage: exit 1, names the index, not 'nothing changed'" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'index' '$work/log' && ! grep -q 'nothing changed' '$work/log'"
t "rule 31" "refresh: ...archive index check: nothing was changed" test "$(treehash "$work/ar" "$work/rp")" = "$before"
# the FIPS recipe is written atomically and preflighted like every other repository file
echo "v1.1.0-deadbeef" >"$gr/lib/fips140/certified.txt"; fr; old3=$(bash "$work/bhash.sh")
run_s4 env PATH="$work/faultbin:$work/stubs4:$stubs2:$stubs:$PATH" PYTHONPATH="$work/faultinj:${PYTHONPATH:-}" FAULT_COPY="melange-fips.yaml" "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: a kill (137) while writing the recipe leaves it as it was" bash -c "test \"\$(cat '$work/rc')\" = 137 && test \"\$(bash '$work/bhash.sh')\" = '$old3'"
if [ "$(id -u)" != 0 ]; then
  fr; chmod 555 "$work/rp3/build"; run_s4 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"; chmod 755 "$work/rp3/build"
  t "rule 73" "fips-module: an unwritable build directory is refused before the change (exit 1, names the path), no PR" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'build' '$work/log' && ! grep -q '^gh pr create' '$CALLS' && ! grep -q Traceback '$work/log'"
fi
# a proof value with one more hex digit is not the value the recipe builds
fr; printf 'v1.0.0-c2097c7c9\n' >"$work/rp3/build/locks/fips-module.txt"; h9=$(bash "$work/bhash.sh")
run_s4 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
t "rule 73" "fips-module: a recipe value with a ninth hex digit is refused (exit 2), never rewritten to a corrupt value; recipe unchanged" bash -c "test \"\$(cat '$work/rc')\" = 2 && test \"\$(bash '$work/bhash.sh')\" = '$h9'"
# archive names compared case-insensitively
python3 - "$work/ln.json" "$work/ln-case.json" <<'P'
import copy, json, sys
c = json.load(open(sys.argv[1]))
for arch in ("x86_64", "aarch64"):
    b = [e for e in c["contents"]["packages"] if e["name"] == "tzdata" and e["architecture"] == arch][0]
    e1 = copy.deepcopy(b); e1["name"], e1["version"] = "A-1", "2"
    e2 = copy.deepcopy(b); e2["name"], e2["version"] = "a", "1-2"
    c["contents"]["packages"] += [e1, e2]
json.dump(c, open(sys.argv[2], "w"))
P
mkrepo; run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln-case.json" STUB_LOCK_FIPS="$work/ln-case.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "refresh: A-1 version 2 and a version 1-2 collide on a case-insensitive file system and are refused too" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'a-1-2.apk' '$work/log'"
# --pr-author: both spellings of the App author are accepted; the flag is required on every invocation
for form in bot app/bot; do
  mkrepo; run_s4 env GH_STUB_OPEN="refresh/00000000" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar" --pr-author "$form"
  t "rule 49" "refresh: --pr-author $form matches our own earlier PR whose author gh reports as app/bot (no second PR)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
done
for ci in true ""; do
  mkrepo; run_s4 env GITHUB_ACTIONS=$ci "${rfn[@]:1}" "$RF" refresh --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 49" "refresh: a missing --pr-author is refused on EVERY invocation (here GITHUB_ACTIONS='$ci'; exit 2, before any gh call): a stranger's PR must never be counted by default" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'pr-author' '$work/log' && ! grep -q '^gh ' '$CALLS'"
  mkrepo; fr; run_s4 env GITHUB_ACTIONS=$ci "$RF" fips-module --go-root "$work/gr3" --repo-dir "$work/rp3"
  t "rule 49" "fips-module: a missing --pr-author is refused on every invocation (GITHUB_ACTIONS='$ci')" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'pr-author' '$work/log' && ! grep -q '^gh ' '$CALLS'"
done
# no assert is used as a check: python -O (PYTHONOPTIMIZE) would drop it
t "rule 48" "no 'assert' statement is used as a check in any build script (python -O removes assert)" bash -c "! grep -nE '^[[:space:]]*assert ' '$root'/bin/refresh-inputs.sh '$root'/bin/apko-lock.sh '$root'/bin/apk-tool.py '$root'/bin/gen-recipes.py '$root'/bin/go-module-sbom.py '$root'/bin/oci-digest.py '$root'/bin/net-probe.py '$root'/bin/assemble-image.sh '$root'/bin/build-apk.sh '$root'/bin/lock-proof.sh '$root'/bin/sealed-proof.sh '$root'/bin/release-sign-apks.sh '$root'/bin/install-build-tools.sh"
for v in three; do
  mkrepo; run_s2 env PYTHONOPTIMIZE=1 STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$work/live-$v" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 32" "refresh under PYTHONOPTIMIZE=1: a three-stream index is still refused (the shape check is not an assert)" bash -c "test \"\$(cat '$work/rc')\" = 1"
done

# ---- snapshot-6 round 6 (Sonnet P3): a waiting refresh PR is not a human stop; the closed-unmerged case reconciles; the record is strict ----------------------------
reset_repo_keep_archive() { rm -rf "$work/rp"; mkdir -p "$work/rp"; cp -R "$fx/repo/." "$work/rp/"; printf 'x86_64 sha256:%s\naarch64 sha256:%s\n' "$(shasum -a 256 "$fx/archive/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1)" "$(shasum -a 256 "$fx/archive/aarch64/APKINDEX.tar.gz" | cut -d' ' -f1)" >"$work/rp/build/locks/archive-index.sha256"; }
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"   # day 1: a changed lock, the archive moves on, a PR is opened
t "rule 49" "day 1 opens the PR" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -q '^gh pr create' '$CALLS'"
day1=$(grep -E '^git( -C [^ ]+)? checkout -b ' "$CALLS" | head -1 | sed 's/.*checkout -b //')
reset_repo_keep_archive; before=$(treehash "$work/ar" "$work/rp")   # day 2: main is as before (the PR is not merged); the archive is ahead
run_s4 env GH_STUB_OPEN="$day1" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "day 2 with the refresh PR still open: exit 0, 'earlier PR', no push, no second PR, no 'human must look' (a waiting PR is the normal state)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! grep -qi 'human must look' '$work/log' && ! grep -Eq '^git( -C [^ ]+)? push|^gh pr create' '$CALLS'"
t "rule 49" "...and nothing was changed on day 2" test "$(treehash "$work/ar" "$work/rp")" = "$before"
reset_repo_keep_archive
run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "day 2 with the PR CLOSED unmerged: the run says it is reconciling and opens a new PR that rewrites the record from the verified live index" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'reconcil' '$work/log' && grep -q '^gh pr create' '$CALLS' && grep -q 'x86_64 sha256:$live_sha_x' '$work/rp/build/locks/archive-index.sha256'"
# damage stays unconditional, also for a plain or missing pointer
mkrepo; cp "$fx/live/x86_64/APKINDEX.tar.gz" "$work/ar/x86_64/APKINDEX.tar.gz"; before=$(treehash "$work/ar" "$work/rp")   # a SIGNED index that is not the recorded one
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "a plain APKINDEX.tar.gz that is not the recorded index (locks unchanged) stops the job: exit 1, hash mismatch, not 'nothing changed'" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'hash mismatch' '$work/log' && ! grep -q 'nothing changed' '$work/log'"
mkrepo; rm -f "$work/ar/aarch64/APKINDEX.tar.gz"
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "a MISSING APKINDEX.tar.gz while the record exists stops the job (exit 1, 'missing index')" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'missing index' '$work/log'"
# the record itself is strict
mkrepo; printf 'x86_64 sha256:%s\n' "$live_sha_x" >"$work/rp/build/locks/archive-index.sha256"
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "a record with no aarch64 line is refused (exit 2) instead of leaving that architecture unchecked" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -qi 'malformed' '$work/log' && ! grep -q Traceback '$work/log'"
mkrepo; printf 'x86_64 sha256:%s sha256:%s\naarch64 sha256:%s\n' "$live_sha_x" "$live_sha_x" "$live_sha_a" >"$work/rp/build/locks/archive-index.sha256"
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "a record line with two sha256 separators is a clean refusal (exit 2), not a traceback" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -qi 'malformed' '$work/log' && ! grep -q Traceback '$work/log'"
# GitHub logins are not case-sensitive
mkrepo; run_s4 env GH_STUB_OPEN="refresh/00000000" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar" --pr-author APP/Bot
t "rule 49" "--pr-author APP/Bot matches the author app/bot (case-insensitive)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"

# ---- snapshot-6 round 6 (Opus P3): the recorded index file itself must be there; a proof value with a dot is not the value; author decorations -------------------------
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"   # day 1 gives a versioned archive and a record
reset_repo_keep_archive   # main still records the OLD index (the PR is not merged); remove that index's own file from index/
oldsha_x=$(shasum -a 256 "$fx/archive/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1); rm -f "$work/ar/x86_64/index/APKINDEX-$oldsha_x.tar.gz"; before=$(treehash "$work/ar" "$work/rp")
run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "with a copy pointer, the record's own index file index/APKINDEX-<recorded>.tar.gz missing: exit 1 (assembly would fail), not 'nothing changed'" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'recorded' '$work/log' && ! grep -q 'nothing changed' '$work/log'"
for v in "c2097c7c.9" "c2097c7c_9" "c2097c7c-9"; do
  fr; printf 'v1.0.0-%s\n' "$v" >"$work/rp3/build/locks/fips-module.txt"; hx=$(bash "$work/bhash.sh")
  echo "v1.1.0-deadbeef" >"$gr/lib/fips140/certified.txt"
  run_s4 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3"
  t "rule 73" "fips-module: a recipe proof value followed by '${v#c2097c7c}' is not the value the recipe builds: refused (exit 2), recipe unchanged" bash -c "test \"\$(cat '$work/rc')\" = 2 && test \"\$(bash '$work/bhash.sh')\" = '$hx'"
done
mkrepo; run_s4 env GH_STUB_OPEN="refresh/00000000" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar" --pr-author "app/bot[bot]"
t "rule 49" "--pr-author app/bot[bot] (two decorations) still matches the author app/bot" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"

# ---- AC22 (advisor-accepted): the reconcile PR says which refresh PR it supersedes ----------------------------------------------------------------------------
reset_repo_keep_archive; mkrepo_archive_ahead() { :; }
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; reset_repo_keep_archive
run_s4 env GH_STUB_CLOSED="refresh/aaaa1111" GH_STUB_MERGED="refresh/bbbb2222" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "AC22: the reconcile PR body names the previous refresh PR that was closed unmerged (#51, refresh/aaaa1111) and says this one supersedes it; a merged PR is not named" bash -c "grep -q '#51' '$CALLS' && grep -q 'refresh/aaaa1111' '$CALLS' && grep -qi 'closed unmerged' '$CALLS' && grep -qi 'supersedes' '$CALLS' && ! grep -q 'bbbb2222' '$CALLS'"
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; reset_repo_keep_archive
run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "AC22: when the previous PR's number cannot be determined the body says 'a previous refresh pull request' was closed unmerged and still names the old index digest" bash -c "grep -qi 'a previous refresh pull request' '$CALLS' && grep -qi 'supersedes' '$CALLS' && grep -q 'sha256:' '$CALLS'"
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "AC22: an ordinary (not reconciling) PR body does not claim to supersede anything" bash -c "! grep -qi 'supersedes' '$CALLS'"

# ---- snapshot-7 round 7 (Sonnet/Opus P3) -----------------------------------------------------------------------------------------------------------------------
# the reconcile gate: closed-unmerged with UNCHANGED locks must still reconcile (nothing else in the repository changes, the record does)
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; reset_repo_keep_archive
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "AC22: closed-unmerged with UNCHANGED locks (the archive is ahead of the record): the run reconciles - one PR, the record rewritten to the live digest" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'reconcil' '$work/log' && test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1 && grep -q 'x86_64 sha256:$live_sha_x' '$work/rp/build/locks/archive-index.sha256'"
# nothing to commit after the repointing (the live index IS the recorded one): exit 0, no PR, no 'git add -- \"\"'
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
oldsha_x2=$(shasum -a 256 "$fx/archive/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1); oldsha_a2=$(shasum -a 256 "$fx/archive/aarch64/APKINDEX.tar.gz" | cut -d' ' -f1)
for a in x86_64 aarch64; do rm -f "$work/ar/$a/APKINDEX.tar.gz"; cp "$work/ar/$a/index/APKINDEX-$(shasum -a 256 "$fx/archive/$a/APKINDEX.tar.gz" | cut -d' ' -f1).tar.gz" "$work/ar/$a/APKINDEX.tar.gz"; done   # the pointer copies sit on the OLD index
printf 'x86_64 sha256:%s\naarch64 sha256:%s\n' "$live_sha_x" "$live_sha_a" >"$work/rp/build/locks/archive-index.sha256"; cp "$fx/repo/build/locks/"*.lock* "$work/rp/build/locks/" 2>/dev/null || true
cp "$work/rp/build/locks/apko.base.lock.json" "$work/keep.lock" 2>/dev/null; python3 - "$work/rp" "$work/ln.json" <<'P'
import json, sys
# make the repository's base locks equal the live (changed) locks, so only the pointer is "behind"
rp, ln = sys.argv[1:3]
live = json.load(open(ln))
for f in ("apko.base.lock.json", "apko-fips.base.lock.json"):
    d = json.load(open("%s/build/locks/%s" % (rp, f)))
    d["contents"]["packages"] = [dict(e, url="/work/archive/%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"])) for e in live["contents"]["packages"]]
    json.dump(d, open("%s/build/locks/%s" % (rp, f), "w"), indent=2)
P
run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "AC22: when re-copying the pointer leaves nothing to commit the run exits 0 without a PR and without a git add of an empty path" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -q '^gh pr create' '$CALLS' && ! grep -Eq 'git .* add -- \$' '$CALLS' && test ! -L '$work/ar/x86_64/APKINDEX.tar.gz' && cmp '$work/ar/x86_64/APKINDEX.tar.gz' '$work/ar/x86_64/index/APKINDEX-$live_sha_x.tar.gz'"
# the open-PR guard runs as soon as the archive is found ahead, before any download: a failing download cannot turn a waiting PR into a red run
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; day1b=$(grep -E '^git( -C [^ ]+)? checkout -b ' "$CALLS" | head -1 | sed 's/.*checkout -b //'); reset_repo_keep_archive
run_s4 env GH_STUB_OPEN="$day1b" STUB_CURL_DIR="$work/nonexistent-live" "${rfn[@]:1}" STUB_CURL_DIR="$work/nonexistent-live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "AC22: with a refresh PR waiting and the live index unreachable, the run still exits 0 'earlier' (the guard comes before the download)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log'"
# the recorded index file is checked whatever the pointer is
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
cmp "$work/ar/x86_64/APKINDEX.tar.gz" "$work/ar/x86_64/index/APKINDEX-$live_sha_x.tar.gz"   # the pointer is a copy equal to the record
printf 'garbage' >"$work/ar/x86_64/index/APKINDEX-$live_sha_x.tar.gz"
run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "a PLAIN pointer equal to the record with a damaged recorded file index/APKINDEX-<recorded> stops the job (exit 1, names it)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'recorded|index file .*hash' '$work/log'"
mkrepo; mkdir -p "$work/outside-idx"; mv "$work/ar/x86_64/index" "$work/outside-idx/x" 2>/dev/null; ln -s "$work/outside-idx/x" "$work/ar/x86_64/index" 2>/dev/null || true
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "a symlinked index/ directory is refused on every run (exit 1, names symlink)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'symlink' '$work/log'"
# the record parser: a duplicated arch line, and a damaged symlink target caught by the every-run check itself
mkrepo; printf 'x86_64 sha256:%s\nx86_64 sha256:%s\naarch64 sha256:%s\n' "$live_sha_x" "$live_sha_x" "$live_sha_a" >"$work/rp/build/locks/archive-index.sha256"
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "a record with a DUPLICATED architecture line is refused (exit 2, malformed)" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -qi 'malformed' '$work/log'"
# open_pr returns the checkout to the branch it started on (the FIPS PR must not branch from the refresh commit)
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "after opening the PR the repository is switched back to the branch the job started on" bash -c "tail -n 40 '$CALLS' | grep -Eq 'git( -C [^ ]+)? (checkout|switch)( -q)? main'"

# a plain pointer that is NOT the recorded index while the recorded file index/APKINDEX-<recorded> is fine: the pointer itself is the damage
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
for a in x86_64 aarch64; do rm -f "$work/ar/$a/APKINDEX.tar.gz" "$work/ar/$a/index/APKINDEX-$(shasum -a 256 "$fx/archive/$a/APKINDEX.tar.gz" | cut -d' ' -f1).tar.gz"; cp "$fx/archive/$a/APKINDEX.tar.gz" "$work/ar/$a/APKINDEX.tar.gz"; done   # the OLD signed index with no versioned file: signed, but neither the recorded one nor a stored version
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "a plain pointer that is not the recorded index, with the recorded file intact, stops the job (exit 1, 'plain file')" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'plain file' '$work/log'"

# ---- snapshot-8 round 8 (P3) ---------------------------------------------------------------------------------------------------------------------------------
# AC17 while a refresh PR waits: a damaged archived file still stops the job; a missing one waits for the PR
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; wb=$(grep -E '^git( -C [^ ]+)? checkout -b ' "$CALLS" | head -1 | sed 's/.*checkout -b //'); reset_repo_keep_archive
victim=$(ls "$work/ar/x86_64"/*.apk | head -1); cp "$victim" "$work/victim.bak"; head -c 100 "$work/victim.bak" >"$victim"
run_s4 env GH_STUB_OPEN="$wb" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 27" "AC17: a TRUNCATED archived apk while a refresh PR waits stops the job (exit 1, names the file), it is not 'wait'" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q '$(basename "$victim")' '$work/log' && ! grep -qi 'earlier pull request' '$work/log'"
cp "$work/victim.bak" "$victim"; rm -f "$victim"
run_s4 env GH_STUB_OPEN="$wb" STUB_CURL_DIR="$work/nonexistent-live" "${rfn[@]:1}" STUB_CURL_DIR="$work/nonexistent-live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "AC17: a MISSING archived apk while a refresh PR waits: exit 0 'earlier pull request', nothing fetched, nothing written" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! test -e '$victim'"
# the record must be exactly what the job writes
for v in crlf nofinalnl; do
  mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  case $v in crlf) python3 - "$work/rp/build/locks/archive-index.sha256" <<'P'
import sys; p = sys.argv[1]; s = open(p).read(); assert s.count("\n") == 2; open(p, "w", newline="").write(s.replace("\n", "\r\n"))
P
  ;; nofinalnl) python3 - "$work/rp/build/locks/archive-index.sha256" <<'P'
import sys; p = sys.argv[1]; open(p, "w").write(open(p).read().rstrip("\n"))
P
  ;; esac
  run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 31" "a record with $v is malformed (exit 2), not silently accepted" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -qi 'malformed' '$work/log'"
done
# detached start and a failing gh pr create: the job goes back where it started
mkrepo; run_s4 env GIT_STUB_DETACHED=1 "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "a DETACHED start is restored by its commit (checkout --detach), not left on the refresh commit" bash -c "grep -Eq 'git( -C [^ ]+)? checkout -q --detach cafe0123' '$CALLS'"
mkrepo; run_s4 env GH_STUB_CREATE_FAIL=1 "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "when gh pr create fails the job fails AND goes back to the starting branch" bash -c "test \"\$(cat '$work/rc')\" != 0 && tail -n 5 '$CALLS' | grep -Eq 'git( -C [^ ]+)? checkout -q main'"
# the previous-PR choice: forks and foreign authors are never named; of two unmerged ones the NEWEST is
for v in fork foreign; do
  mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; reset_repo_keep_archive
  if [ $v = fork ]; then run_s4 env GH_STUB_CLOSED_FORK="refresh/ffff0000" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  else run_s4 env GH_STUB_CLOSED_FOREIGN="refresh/ffff0000" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar" --pr-author app/bot; fi
  t "rule 31" "AC22: a closed refresh/ PR from a $v is never named as the superseded one (the generic sentence is used)" bash -c "! grep -q 'refresh/ffff0000' '$CALLS' && grep -qi 'a previous refresh pull request' '$CALLS'"
done
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; reset_repo_keep_archive
run_s4 env GH_STUB_CLOSED="refresh/aaaa1111 refresh/cccc3333" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "AC22: of two closed unmerged refresh PRs the NEWEST (#52, refresh/cccc3333) is named" bash -c "grep -q '#52' '$CALLS' && grep -q 'refresh/cccc3333' '$CALLS' && ! grep -q 'refresh/aaaa1111' '$CALLS'"
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; reset_repo_keep_archive
run_s4 env GH_STUB_CLOSED_RAW='{"not":"a list"}' "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "AC22: an unexpected reply shape from the closed-PR list gives the generic sentence, not a traceback" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -q Traceback '$work/log' && grep -qi 'a previous refresh pull request' '$CALLS'"
# a symlinked architecture directory is refused on a run where nothing changed
mkrepo; mv "$work/ar/x86_64" "$work/ar-x86-real"; ln -s "$work/ar-x86-real" "$work/ar/x86_64"
run_s2 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "a symlinked architecture directory is refused on a no-change run (exit 1, names symlink)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'symlink' '$work/log'"

# a waiting lock-only refresh PR: the archive is NOT ahead (pointer = record) but the locks changed; the live index is unreachable: still 'wait', exit 0 (the guard comes before the index download)
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; wb2=$(grep -E '^git( -C [^ ]+)? checkout -b ' "$CALLS" | head -1 | sed 's/.*checkout -b //'); reset_repo_keep_archive
python3 - "$work/ar" "$work/rp/build/locks/archive-index.sha256" <<'P'
import os, sys
ar, rec = sys.argv[1:3]
lines = []
for a in ("x86_64", "aarch64"):
    lines.append("%s sha256:%s\n" % (a, __import__("hashlib").sha256(open("%s/%s/APKINDEX.tar.gz" % (ar, a), "rb").read()).hexdigest()))
open(rec, "w").write("".join(lines))
P
run_s4 env GH_STUB_OPEN="$wb2" STUB_CURL_DIR="$work/nonexistent-live" "${rfn[@]:1}" STUB_CURL_DIR="$work/nonexistent-live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "a waiting lock-only refresh PR with the pointer equal to the record and the live index unreachable: exit 0 'earlier pull request' (the guard precedes the index download)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"

# round 9 (P3): reply shapes, a failing checkout back, a missing package while a lock-only PR waits, a real CRLF record
for raw in '{"not":"a list"}' '[{"number":null,"headRefName":"refresh/aaaa1111","isCrossRepository":false,"mergedAt":null,"author":{"login":"app/bot"}}]' '[{"number":"52","headRefName":"refresh/aaaa1111","isCrossRepository":false,"mergedAt":null,"author":{"login":"app/bot"}}]' '[{"headRefName":"refresh/aaaa1111","isCrossRepository":false,"mergedAt":null,"author":{"login":"app/bot"}}]'; do
  mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; reset_repo_keep_archive
  run_s4 env GH_STUB_CLOSED_RAW="$raw" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 31" "AC22: the closed-PR reply $raw is survived (exit 0, no traceback), with the generic sentence unless the number is readable as an integer" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -q Traceback '$work/log' && { grep -qi 'a previous refresh pull request' '$CALLS' || grep -q '#52' '$CALLS'; }"
done
mkrepo; run_s4 env GIT_STUB_CHECKOUT_FAIL=1 "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 44" "a failed checkout back to the starting branch fails the job and says so (it is not swallowed)" bash -c "test \"\$(cat '$work/rc')\" != 0 && grep -qi 'could not go back' '$work/log'"
mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; wb3=$(grep -E '^git( -C [^ ]+)? checkout -b ' "$CALLS" | head -1 | sed 's/.*checkout -b //'); reset_repo_keep_archive
python3 - "$work/ar" "$work/rp/build/locks/archive-index.sha256" <<'P'
import os, sys
ar, rec = sys.argv[1:3]
open(rec, "w").write("".join("%s sha256:%s\n" % (a, __import__("hashlib").sha256(open("%s/%s/APKINDEX.tar.gz" % (ar, a), "rb").read()).hexdigest()) for a in ("x86_64", "aarch64")))
P
victim=$(ls "$work/ar/x86_64"/*.apk | head -1); rm -f "$victim"
run_s4 env GH_STUB_OPEN="$wb3" STUB_CURL_DIR="$work/nonexistent-live" "${rfn[@]:1}" STUB_CURL_DIR="$work/nonexistent-live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 49" "a MISSING apk while a lock-only refresh PR waits (pointer equal to the record, not ahead) and the downloads fail: exit 0 'earlier pull request' (the guard precedes the downloads)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log' && ! test -e '$victim'"

# ---- ruling (P3 finding 1): after BOTH daily jobs the generator --check stays green, and the template is never touched ----------------------------------------
gcheck() { python3 "$fx/gen-recipes.py" --template "$1/build/melange.yaml.tmpl" --regular "$1/build/melange.yaml" --fips "$1/build/melange-fips.yaml" --melange-lock "$1/build/locks/melange.lock" --fips-module "$1/build/locks/fips-module.txt" --check; }
tsha() { shasum -a 256 "$1/build/melange.yaml.tmpl" | cut -d' ' -f1; }
mkrepo; tpl_before=$(tsha "$work/rp"); gcheck "$work/rp" >/dev/null 2>&1 || echo "FIXTURE: the fixture repo does not pass the generator check before the job" >&2
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel-new.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 21" "refresh: after a closure change the generator --check passes on the job's output (the job edits the lock; the recipes are the generator's output)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -q 'zlib=1.3.2-r0' '$work/rp/build/locks/melange.lock' && grep -q 'zlib=1.3.2-r0' '$work/rp/build/melange.yaml' && grep -q 'zlib=1.3.2-r0' '$work/rp/build/melange-fips.yaml'" && t "rule 21" "...--check passes" gcheck "$work/rp"
t "rule 21" "...the template is byte-for-byte what it was (an automated change never edits the template or its pin)" test "$(tsha "$work/rp")" = "$tpl_before"
t "rule 21" "...and the daily PR adds the lock and the two regenerated recipes, never the template" bash -c "$GHPATHS | grep -q 'melange.lock' && $GHPATHS | grep -q 'build/melange.yaml' && ! $GHPATHS | grep -q 'tmpl'"
fr; tpl_before=$(tsha "$work/rp3" 2>/dev/null || shasum -a 256 "$work/rp3/build/melange.yaml.tmpl" | cut -d' ' -f1)
mkdir -p "$work/gr3/lib/fips140"; echo "v1.1.0-deadbeef" >"$work/gr3/lib/fips140/certified.txt"
run_s4 "$RF" fips-module --pr-author app/bot --go-root "$work/gr3" --repo-dir "$work/rp3"
t "rule 21" "fips-module: after the job the generator --check passes, the data file holds the new module, and the template is unchanged" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qx 'v1.1.0-deadbeef' '$work/rp3/build/locks/fips-module.txt' && test \"\$(shasum -a 256 '$work/rp3/build/melange.yaml.tmpl' | cut -d' ' -f1)\" = '$tpl_before'" && t "rule 21" "...--check passes" gcheck "$work/rp3"
t "rule 21" "fips-module: the PR adds the data file and the regenerated FIPS recipe, never the template" bash -c "$GHPATHS | grep -q 'fips-module.txt' && $GHPATHS | grep -q 'melange-fips.yaml' && ! $GHPATHS | grep -q 'tmpl'"

# ---- Codex security-final on P3 (findings 2, 3, 5) ----------------------------------------------------------------------------------------------------------------------
# F2: the archived inputs the COMMITTED locks require are checked before either guard can return success
for state in ahead equal; do
  mkrepo; run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; wbf=$(grep -E '^git( -C [^ ]+)? checkout -b ' "$CALLS" | head -1 | sed 's/.*checkout -b //'); reset_repo_keep_archive
  if [ $state = equal ]; then python3 - "$work/ar" "$work/rp/build/locks/archive-index.sha256" <<'P'
import os, sys
ar, rec = sys.argv[1:3]
open(rec, "w").write("".join("%s sha256:%s\n" % (a, __import__("hashlib").sha256(open("%s/%s/APKINDEX.tar.gz" % (ar, a), "rb").read()).hexdigest()) for a in ("x86_64", "aarch64")))
P
  fi
  old=$(ls "$work/ar/x86_64"/tzdata-2026a-r0.apk 2>/dev/null | head -1); [ -n "$old" ] || echo "FIXTURE: no old tzdata in the archive" >&2
  head -c 100 "$old" >"$old.cut"; mv "$old.cut" "$old"
  run_s4 env GH_STUB_OPEN="$wbf" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 27" "AC17: the OLD version a waiting upgrade PR leaves behind (tzdata 2026a, named by the committed lock) is damaged ($state): exit 1 naming the file, not 'wait'" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'tzdata-2026a-r0.apk' '$work/log' && ! grep -qi 'earlier pull request' '$work/log'"
done
# F3: pointers and digest-named files are validated whether or not a record exists
mkrepo; rm -f "$work/rp/build/locks/archive-index.sha256"; printf 'garbage' >"$work/ar/x86_64/index/APKINDEX-$(printf 'a%.0s' $(seq 64)).tar.gz" 2>/dev/null || { mkdir -p "$work/ar/x86_64/index"; printf 'garbage' >"$work/ar/x86_64/index/APKINDEX-$(printf 'a%.0s' $(seq 64)).tar.gz"; }
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "a digest-named index file that does not hash to its name stops the job (exit 1, names it) even when NO record exists yet" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'does not hash to its own name' '$work/log'"
mkrepo; rm -f "$work/rp/build/locks/archive-index.sha256"; ln -sfn "index/APKINDEX-$(printf 'b%.0s' $(seq 64)).tar.gz" "$work/ar/x86_64/APKINDEX.tar.gz"
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "a pointer that is a symlink stops the job even when NO record exists yet (exit 1, names symlink)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'symlink' '$work/log'"
# F3: a legacy plain pointer is kept under its digest only if it is a SIGNED index
mkrepo; printf 'not an index at all' >"$work/ar/x86_64/APKINDEX.tar.gz"; printf 'x86_64 sha256:%s\naarch64 sha256:%s\n' "$(shasum -a 256 "$work/ar/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1)" "$(shasum -a 256 "$work/ar/aarch64/APKINDEX.tar.gz" | cut -d' ' -f1)" >"$work/rp/build/locks/archive-index.sha256"
run_s4 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "an unsigned/garbage legacy plain pointer is NOT preserved: exit 1 naming the legacy index, no PR" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'legacy' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
# F5: extra gzip members are refused BEFORE they are inflated; the limit is cumulative
python3 - "$work" "$fx" <<'P'
import gzip, io, os, shutil, subprocess, sys, tarfile
w, fx = sys.argv[1:3]
def gz(b):
    o = io.BytesIO()
    with gzip.GzipFile(fileobj=o, mode="wb", mtime=0) as g: g.write(b)
    return o.getvalue()
def tarb(ms):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.GNU_FORMAT) as t:
        for n, d in ms:
            i = tarfile.TarInfo(n); i.size = len(d); i.mtime = 0; t.addfile(i, io.BytesIO(d))
    return b.getvalue()
bomb = gz(b"\0" * (5 << 20))
for name, build in (("many", lambda good: good + bomb * 38), ("cumul", lambda good: gz(tarb([(".SIGN.RSA256.wolfi-signing.rsa.pub", b"\0" * (100 << 20))])) + gz(tarb([("APKINDEX", b"\0" * (100 << 20))])))):
    d = "%s/live-%s" % (w, name); shutil.rmtree(d, ignore_errors=True); shutil.copytree(fx + "/live", d)
    for a in ("x86_64", "aarch64"):
        p = "%s/%s/APKINDEX.tar.gz" % (d, a); open(p, "wb").write(build(open(p, "rb").read()))
P
for v in many cumul; do
  mkrepo; before=$(treehash "$work/ar" "$work/rp")
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$work/live-$v" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  case $v in many) kw='more than two gzip members';; cumul) kw='more than 128 MiB';; esac
  t "rule 32" "refresh: an index of the shape '$v' (40 gzip members / two members inflating to 200 MiB together) is refused naming '$kw', nothing changed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q '$kw' '$work/log'" && t "rule 32" "...($v): archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
done

# ---- advisor ruling on 9d P3 (Sonnet probes A and B): the closed-rule fixes -----------------------------------------------------------------------------------------
# A (AC17): the committed melange.lock names an archived package no live resolution names any more; damage to it must stop the job even while an upgrade PR waits
mkrepo; cp "$fx/melange.lock" "$work/mel.keep"
python3 - "$work/rp/build/locks/melange.lock" <<'P'
import sys
p = sys.argv[1]; L = [l for l in open(p).read().split("\n") if l]
print(L[:2], file=sys.stderr)
P
oldbb=$(grep '^busybox=' "$work/rp/build/locks/melange.lock" | head -1); [ -n "$oldbb" ] || { echo "FIXTURE: melange.lock has no busybox" >&2; }
bbv=${oldbb#busybox=}
# the live melange resolution moves busybox to 9.9.9-r0: a copy of the live melange lock with that version, and the new apk in the live archive/fetch dir
python3 - "$fx/live-mel.lock.json" "$work/live-mel-moved.json" "$bbv" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "busybox": e["version"] = "9.9.9-r0"
json.dump(d, open(sys.argv[2], "w"))
P
for dmg in truncate flip delete swapdata trailer; do
  mkrepo; wbm=; mkdir -p "$work/ar"; f="$work/ar/x86_64/busybox-$bbv.apk"; [ -f "$f" ] || echo "FIXTURE: no archived busybox-$bbv.apk" >&2
  case $dmg in trailer) head -c "$(( $(wc -c <"$f") - 8 ))" "$f" >"$f.cut"; mv "$f.cut" "$f";; truncate) head -c 100 "$f" >"$f.cut"; mv "$f.cut" "$f";; flip) python3 - "$f" <<'P'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b)//2] ^= 0xFF; open(p, "wb").write(bytes(b))
P
  ;; delete) rm -f "$f";; swapdata) python3 - "$f" <<'SWAP'
import gzip, sys, zlib
p = sys.argv[1]; raw = open(p, "rb").read(); parts = []; rest = raw
while rest:
    d = zlib.decompressobj(31); d.decompress(rest); used = len(rest) - len(d.unused_data); parts.append(rest[:used]); rest = d.unused_data
parts[-1] = gzip.compress(b"a different data stream", mtime=0)
open(p, "wb").write(b"".join(parts))
SWAP
  ;; esac
  run_s4 env GH_STUB_OPEN="refresh/00000000" STUB_LOCK_MEL="$work/live-mel-moved.json" "${rfn[@]:1}" STUB_LOCK_MEL="$work/live-mel-moved.json" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "rule 27" "AC17 probe A ($dmg): the archived busybox-$bbv.apk named only by the committed melange.lock is damaged while an upgrade PR waits: exit 1 (checksum mismatch / a human must look), not 'still open'" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eqi 'checksum mismatch|a human must look' '$work/log' && ! grep -qi 'still open' '$work/log'"
done
mkrepo; run_s4 env GH_STUB_OPEN="refresh/00000000" STUB_LOCK_MEL="$work/live-mel-moved.json" "${rfn[@]:1}" STUB_LOCK_MEL="$work/live-mel-moved.json" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 27" "AC17 probe A (control): the same run with the archive undamaged waits (exit 0, the open PR)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'earlier' '$work/log'"
# ---- REQ-REFRESH-001-AC32: the first fill (advisor reading Oct 16): an archive that holds only the pinned key, and no build/archive.json on main --------------------------
# The committed locks may name versions the live resolution has moved past; with an empty archive they can never already be there, so the job fetches those Wolfi still
# serves and verifies each (a locked one against its lock checksums; a melange.lock one, which has no checksums, against the signed live index) before archiving it.
ffl="$work/ff-live"; rm -rf "$ffl"; mkdir -p "$ffl/dl"; cp "$fx/archive/go/"*.tar.gz "$ffl/dl/"
mkrepo; cp "$fx/melange.lock" "$work/mel.keep"
oldbb=$(grep '^busybox=' "$work/rp/build/locks/melange.lock" | head -1); ffbv=${oldbb#busybox=}
python3 - "$fx/live-mel.lock.json" "$work/ff-mel-moved.json" "$ffbv" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "busybox": e["version"] = "9.9.9-r0"
json.dump(d, open(sys.argv[2], "w"))
P
python3 - "$fx" "$ffl" "$work" "$ffbv" <<'P'
import gzip, io, json, os, shutil, subprocess, sys, tarfile
fx, ffl, work, bbv = sys.argv[1:5]
def run(*a): return subprocess.run(a, check=True, capture_output=True).stdout
def gz(b):
    o = io.BytesIO()
    with gzip.GzipFile(fileobj=o, mode="wb", mtime=0) as g: g.write(b)
    return o.getvalue()
def tarb(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.GNU_FORMAT) as t:
        for n, d in members:
            i = tarfile.TarInfo(n); i.size = len(d); i.mtime = 0; t.addfile(i, io.BytesIO(d))
    return b.getvalue()
def signed_index(path, text):
    idx = gz(tarb([("APKINDEX", text), ("DESCRIPTION", b"fixture")]))
    open(path + ".idx", "wb").write(idx)
    sig = run("openssl", "dgst", "-sha256", "-sign", fx + "/idxkey.pem", path + ".idx")
    os.remove(path + ".idx")
    open(path, "wb").write(gz(tarb([(".SIGN.RSA256.wolfi-signing.rsa.pub", sig)])) + idx)
moved = json.load(open(work + "/ff-mel-moved.json"))
for a in ("x86_64", "aarch64"):
    os.makedirs("%s/%s" % (ffl, a))
    for src in (fx + "/live/" + a, fx + "/envrepo/" + a, fx + "/archive/" + a):
        for f in os.listdir(src):
            if f.endswith(".apk") and not os.path.exists("%s/%s/%s" % (ffl, a, f)):
                shutil.copy("%s/%s" % (src, f), "%s/%s/%s" % (ffl, a, f))
    old = "%s/envrepo/%s/busybox-%s.apk" % (fx, a, bbv)
    if os.path.exists(old):
        shutil.copy(old, "%s/%s/busybox-%s.apk" % (ffl, a, bbv))
        shutil.copy(old, "%s/%s/busybox-9.9.9-r0.apk" % (ffl, a))   # the moved live version carries the old bytes
    oldtz = "%s/archive/%s/tzdata-2026a-r0.apk" % (fx, a)
    if os.path.exists(oldtz):
        shutil.copy(oldtz, "%s/%s/tzdata-2026a-r0.apk" % (ffl, a))
    text = open("%s/itext-%s" % (fx, a), "rb").read().decode()
    extra = "".join("C:%s\nP:%s\nV:%s\n\n" % (e["checksum"], e["name"], e["version"]) for e in moved["contents"]["packages"] if e["architecture"] == a and e["name"] == "busybox")
    signed_index("%s/%s/APKINDEX.tar.gz" % (ffl, a), (text.rstrip("\n") + "\n\n" + extra).encode())
    noold = "\n\n".join(st for st in text.split("\n\n") if not {"P:busybox", "V:" + bbv} <= set(st.split("\n")))
    signed_index("%s/%s/APKINDEX-noold.tar.gz" % (ffl, a), (noold.rstrip("\n") + "\n\n" + extra).encode())
    def wrongc(st):   # the stanza of the old busybox lists another package checksum; the package itself stays whole and well-formed
        L_ = st.split("\n")
        return "\n".join(("C:Q1" + "A" * 27) if l_.startswith("C:") else l_ for l_ in L_) if {"P:busybox", "V:" + bbv} <= set(L_) else st
    signed_index("%s/%s/APKINDEX-wrongc.tar.gz" % (ffl, a), ("\n\n".join(wrongc(st) for st in text.split("\n\n")).rstrip("\n") + "\n\n" + extra).encode())
    noprod = "\n\n".join(st for st in text.split("\n\n") if not {"P:tzdata", "V:2026a-r0"} <= set(st.split("\n")))
    signed_index("%s/%s/APKINDEX-noprod.tar.gz" % (ffl, a), noprod.encode())
P
ffrun() {   # $1 = live fetch dir; the live melange resolution has moved busybox on, the production lock is unchanged
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$work/ff-mel-moved.json" STUB_CURL_DIR="$1" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; }
ffprod() {   # the live production and FIPS locks have moved tzdata on (2026a to 2026b)
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-new.lock.json" STUB_LOCK_FIPS="$fx/live-new.lock.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$1" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; }
ffempty() { mkrepo; /bin/rm -f "$work/rp/build/locks/archive-index.sha256" "$work/rp/build/archive.json"; find "$work/ar" -mindepth 1 -maxdepth 1 ! -name keys -exec /bin/rm -rf {} +; }
ffempty; ffrun "$ffl"
t "AC32" "first fill: an archive with only the key, no build/archive.json, a committed melange.lock version the live resolution moved past, still served and listed in the signed live index: exit 0 and the old version is archived, byte for byte" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -f '$work/ar/x86_64/busybox-$ffbv.apk' && cmp -s '$work/ar/x86_64/busybox-$ffbv.apk' '$ffl/x86_64/busybox-$ffbv.apk'"
t "AC32" "first fill: the old version was fetched (its package file name is in the fetch log)" bash -c "grep -q 'busybox-$ffbv.apk' '$CALLS'"
ffempty; mkdir -p "$work/ar/x86_64"; : >"$work/ar/x86_64/stray.apk"; ffrun "$ffl"
t "AC32" "first fill mutant: an archive that holds anything beside the key never takes the first-fill path: exit 1 naming the old version, which is not fetched" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'busybox-$ffbv' '$work/log' && ! grep -q 'busybox-$ffbv.apk' '$CALLS'"
ffempty; printf '{"version":1}\n' >"$work/rp/build/archive.json"; ffrun "$ffl"
t "AC32" "first fill mutant: a build/archive.json in the repository never takes the first-fill path: exit 1, the old version is not fetched" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q 'busybox-$ffbv.apk' '$CALLS'"
rm -rf "$work/ff-bad"; cp -R "$ffl" "$work/ff-bad"; python3 "$work/lib.py" tamper "$work/ff-bad/x86_64/busybox-$ffbv.apk"
ffempty; ffrun "$work/ff-bad"
t "AC32" "first fill mutant: a damaged old melange.lock package (a flipped byte) is refused: exit 1 naming busybox, no package archived" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'busybox' '$work/log' && grep -Eqi 'checksum|mismatch|differ|incorrect' '$work/log' && ! ls '$work/ar'/x86_64/*.apk >/dev/null 2>&1"
rm -rf "$work/ff-wrongc"; cp -R "$ffl" "$work/ff-wrongc"; for a_ in x86_64 aarch64; do cp "$ffl/$a_/APKINDEX-wrongc.tar.gz" "$work/ff-wrongc/$a_/APKINDEX.tar.gz"; done
ffempty; ff_before=$(treehash "$work/ar" "$work/rp"); ffrun "$work/ff-wrongc"; ff_after=$(treehash "$work/ar" "$work/rp")
t "AC32" "first fill mutant: a WELL-FORMED old melange.lock package whose identity checksum differs from the one the signed live index lists is refused by the index comparison itself: exit 1, the identity-mismatch message, the archive and the repository unchanged" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'does not have the package checksum the signed live index lists' '$work/log' && test '$ff_before' = '$ff_after'"
rm -rf "$work/ff-noidx"; cp -R "$ffl" "$work/ff-noidx"; for a_ in x86_64 aarch64; do cp "$ffl/$a_/APKINDEX-noold.tar.gz" "$work/ff-noidx/$a_/APKINDEX.tar.gz"; done
ffempty; ffrun "$work/ff-noidx"
t "AC32" "first fill mutant: the old melange.lock version has no entry in the signed live index: exit 1 naming busybox and the index, no package archived" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'busybox' '$work/log' && grep -Eqi 'index' '$work/log' && ! ls '$work/ar'/x86_64/*.apk >/dev/null 2>&1"
rm -rf "$work/ff-gone"; cp -R "$ffl" "$work/ff-gone"; /bin/rm -f "$work/ff-gone"/*/busybox-$ffbv.apk
ffempty; ffrun "$work/ff-gone"
t "AC32" "first fill mutant: the old version is no longer served: exit 1 naming busybox, no package archived" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'busybox' '$work/log' && ! ls '$work/ar'/x86_64/*.apk >/dev/null 2>&1"
ffempty; ffprod "$ffl"
t "AC32" "first fill: a version named by the committed production lock that the live resolution moved past (tzdata 2026a) is fetched and checked against the lock: exit 0, archived" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -f '$work/ar/x86_64/tzdata-2026a-r0.apk' && cmp -s '$work/ar/x86_64/tzdata-2026a-r0.apk' '$ffl/x86_64/tzdata-2026a-r0.apk'"
rm -rf "$work/ff-badprod"; cp -R "$ffl" "$work/ff-badprod"; python3 "$work/lib.py" tamper "$work/ff-badprod/x86_64/tzdata-2026a-r0.apk"
ffempty; ffprod "$work/ff-badprod"
t "AC32" "first fill mutant: the committed production lock version fails its lock checksum: exit 1 naming tzdata, no package archived" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'tzdata' '$work/log' && grep -Eqi 'checksum|mismatch' '$work/log' && ! ls '$work/ar'/x86_64/*.apk >/dev/null 2>&1"
rm -rf "$work/ff-noprod"; cp -R "$ffl" "$work/ff-noprod"; for a_ in x86_64 aarch64; do cp "$ffl/$a_/APKINDEX-noprod.tar.gz" "$work/ff-noprod/$a_/APKINDEX.tar.gz"; done
ffempty; ff_before=$(treehash "$work/ar" "$work/rp"); ffprod "$work/ff-noprod"; ff_after=$(treehash "$work/ar" "$work/rp")
t "AC32" "first fill mutant: a committed production lock version (tzdata 2026a) that the signed live index does not list is refused although its lock checksums hold: exit 1 naming tzdata and the index, the archive and the repository unchanged" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'tzdata' '$work/log' && grep -qi 'index' '$work/log' && test '$ff_before' = '$ff_after'"
ffempty; python3 - "$work/rp/build/locks/apko.base.lock.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
d["contents"]["packages"] = [e for e in d["contents"]["packages"] if e["name"] != "tzdata"]   # the version is now named by the committed FIPS lock only
json.dump(d, open(sys.argv[1], "w"), indent=2)
P
ffprod "$ffl"
t "AC32" "first fill: a version named by the committed FIPS lock only (tzdata 2026a) is fetched and checked against that lock: exit 0, archived" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -f '$work/ar/x86_64/tzdata-2026a-r0.apk'"
# the gate is exact: a FIFO, a socket, an empty extra directory, a symlinked archive directory and a symlinked keys directory are not the key-only state
for st_ in fifo socket dir symroot symkeys; do
  ffempty
  case $st_ in
    fifo) mkfifo "$work/ar/pipe";;
    socket) python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])" "$work/ar/sock";;
    dir) mkdir "$work/ar/x86_64";;
    symroot) /bin/mv "$work/ar" "$work/ar-real"; ln -s "$work/ar-real" "$work/ar";;
    symkeys) /bin/mv "$work/ar/keys" "$work/ar/keys-real"; ln -s keys-real "$work/ar/keys";;
  esac
  ffrun "$ffl"
  t "AC32" "first fill gate ($st_): an archive that is not exactly the key and nothing else never takes the first-fill path: exit 1, the old version is not fetched" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q 'busybox-$ffbv.apk' '$CALLS'"
done
# ---- REQ-REFRESH-001-AC33: the Go toolchain tarballs the committed recipes pin are kept in the archive (rule 12; advisor reading Oct 16, release review R1) -----------------------
# The recipes (build/melange.yaml, build/melange-fips.yaml) pin each Go tarball by its go.dev file name and sha256; build-apk.sh requires archive/go/<file> and checks the same
# sha256. The refresh job stores a missing one only after the sha256 it fetched equals the pin; a present one must equal the pin; old files are never removed.
gofx="$work/go-live"; rm -rf "$gofx"; mkdir -p "$gofx/dl"
cp "$fx/archive/go/"*.tar.gz "$gofx/dl/"
for a_ in x86_64 aarch64; do mkdir -p "$gofx/$a_"; cp "$fx/live/$a_/APKINDEX.tar.gz" "$gofx/$a_/"; done   # the run also fetches and checks the live index
gofiles=$(cd "$fx/archive/go" && ls *.tar.gz)
gorun() {   # $1 = the fetch directory (its dl/ holds the go.dev files); the live resolution equals the committed locks, so nothing but the Go files can change
  run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$1" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; }
gorepo() {   # the repository as main holds it (a pointer exists), the archive without its go/ directory
  mkrepo; printf '{"schema":1,"artifact":"ghcr.io/fosterstack/cache-archive@sha256:%s","files":[{"name":"keys/wolfi-signing.rsa.pub","sha256":"%s"}]}\n' "$(printf 'a%.0s' $(seq 64))" "$(printf 'b%.0s' $(seq 64))" >"$work/rp/build/archive.json"
  /bin/rm -rf "$work/ar/go"; }
gorepo; ff_go_before=$(treehash "$work/rp"); gorun "$gofx"
go_same=1; for f_ in $gofiles; do cmp -s "$work/ar/go/$f_" "$gofx/dl/$f_" || go_same=0; done
t "AC33" "Go archive: a recipe-pinned Go tarball that the archive lacks is fetched, checked against the recipe's sha256 and stored: exit 0, both files archived byte for byte" bash -c "test \"\$(cat '$work/rc')\" = 0 && test $go_same = 1"
t "AC33" "Go archive: the fetch names the go.dev file and the pull request moves the pointer even though no other file changed (one gh pr create)" bash -c "grep -q 'go.dev/dl/go1.27.2' '$CALLS' && test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1"
gorepo; gorun "$work/no-such-dir"
t "AC33" "Go archive: a tarball that is not served stops the job (exit 1) naming the file, nothing stored" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'go1.27.2' '$work/log' && ! test -d '$work/ar/go'"
rm -rf "$work/go-bad"; mkdir -p "$work/go-bad/dl"; for f in $gofiles; do printf 'not the pinned bytes' >"$work/go-bad/dl/$f"; done
gorepo; gorun "$work/go-bad"
t "AC33" "Go archive: a fetched tarball whose sha256 differs from the recipe's pin stops the job (exit 1, names the file and the checksum), nothing stored" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'sha256' '$work/log' && grep -q 'go1.27.2' '$work/log' && ! test -d '$work/ar/go'"
mkrepo; for f in $gofiles; do printf 'damaged' >"$work/ar/go/$f"; done; gorun "$gofx"
t "AC33" "Go archive: an archived tarball whose sha256 is not the pin stops the job (exit 1), names the file and says to delete it, and nothing is fetched" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'go1.27.2' '$work/log' && grep -qi 'delete' '$work/log' && ! grep -q 'go.dev/dl' '$CALLS'"
mkrepo; gtree_before=$(treehash "$work/ar" "$work/rp"); gorun "$gofx"; gtree_after=$(treehash "$work/ar" "$work/rp")
t "AC33" "Go archive: with every pinned tarball archived and correct, nothing is fetched from go.dev and no pull request is opened (exit 0)" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -q 'go.dev/dl' '$CALLS' && ! grep -q '^gh pr create' '$CALLS'"
t "AC33" "Go archive: the archive and the repository are byte for byte unchanged after a run that has nothing to add" test "$gtree_before" = "$gtree_after"
mkrepo; printf 'older' >"$work/ar/go/go1.26.0.linux-amd64.tar.gz"; gorun "$gofx"
t "AC33" "Go archive: an older Go tarball that no recipe pins any more is kept, untouched" bash -c "test \"\$(cat '$work/rc')\" = 0 && test \"\$(cat '$work/ar/go/go1.26.0.linux-amd64.tar.gz')\" = older"
gorepo; ( cd "$work/rp" && python3 - <<'P'
import re
p = "build/melange.yaml"; s = open(p).read()
s2 = re.sub(r"https://go\.dev/dl/(go[0-9.]+\.linux-amd64\.tar\.gz)", r"https://evil.example/dl/\1", s, count=1); assert s2 != s
open(p, "w").write(s2)
P
); gorun "$gofx"
t "AC33" "Go archive: a recipe fetch that is not https://go.dev/dl/<go file> is refused (exit non-zero), nothing is fetched from there" bash -c "test \"\$(cat '$work/rc')\" != 0 && ! grep -q 'evil.example' '$CALLS' && ! test -d '$work/ar/go'"
gorepo; ( cd "$work/rp" && python3 - <<'P'
import re
p = "build/melange.yaml"; s = open(p).read()
s2 = re.sub(r"expected-sha256: [0-9a-f]{64}", "expected-sha256: nothex", s, count=1); assert s2 != s
open(p, "w").write(s2)
P
); gorun "$gofx"
t "AC33" "Go archive: a recipe whose Go fetch has no valid sha256 pin stops the job (exit 2, names the recipe), nothing fetched" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'melange.yaml' '$work/log' && ! grep -q 'go.dev/dl' '$CALLS'"
gorepo; ( cd "$work/rp" && python3 - <<'P'
import re
p = "build/melange-fips.yaml"; s = open(p).read()
s2 = re.sub(r"expected-sha256: [0-9a-f]{64}", "expected-sha256: " + "a" * 64, s, count=1); assert s2 != s
open(p, "w").write(s2)
P
); gorun "$gofx"
t "AC33" "Go archive: the two recipes pinning the same file with two different sha256 values stop the job (exit 1, names the file), nothing fetched" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'go1.27.2' '$work/log' && ! grep -q 'go.dev/dl' '$CALLS'"
gorepo; ln -s "$work/no-such-go-target" "$work/ar/go"; gorun "$gofx"
t "AC33" "Go archive: a go entry that is a symlink stops the job (exit 1)" bash -c "test \"\$(cat '$work/rc')\" = 1"
gorepo; run_s4 env GH_STUB_OPEN="refresh/00000000" STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$gofx" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC33" "Go archive: while an earlier refresh pull request is open, a missing Go tarball waits (exit 0, nothing fetched from go.dev, nothing changed)" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -q 'go.dev/dl' '$CALLS' && ! test -d '$work/ar/go'"
# ---- REQ-REFRESH-001-AC34: the pull request's commit is made through the API so that GitHub signs it, and no pull request is opened for a commit that is not verified ------------
# main's ruleset requires signed commits; a commit made by `git commit` in the job is unsigned and the pull request can never merge. The job pushes the branch at the commit it
# started from (nothing new to sign), creates the one commit with createCommitOnBranch (the App token's commit is signed by GitHub), asks the API whether that commit is
# verified, and only then opens the pull request; otherwise it deletes the branch, opens nothing and exits 1.
sgrun() {   # a refresh that changes files (the new tzdata) and opens its pull request directly; $1.. = extra env
  mkrepo; run_s4 env "$@" STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; }
rm -f "$CALLS.graphql"
sgrun GH_STUB_VERIFIED=true
t "AC34" "signed commit: the pull request's commit is made through the API (one createCommitOnBranch call), not by git commit, and a verified commit leads to exactly one gh pr create" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -q 'createCommitOnBranch' '$CALLS.graphql' && ! grep -Eq '^git( -C [^ ]+)? commit' '$CALLS' && test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1"
t "AC34" "signed commit: the commit's files are the working tree's, byte for byte, and its parent is the commit the job started from" python3 - "$CALLS.graphql" "$work/rp" <<'PY'
import base64, json, subprocess, sys
d = json.load(open(sys.argv[1]))["variables"]["input"]
adds = d["fileChanges"]["additions"]
assert adds and not d["fileChanges"].get("deletions"), adds
for a in adds:
    assert base64.b64decode(a["contents"]) == open(sys.argv[2] + "/" + a["path"], "rb").read(), a["path"]
assert d["expectedHeadOid"] == "cafe0123", d["expectedHeadOid"]      # the commit the stubbed git reports as the job's start
assert d["branch"]["branchName"].startswith("refresh/"), d["branch"]
assert d["message"]["headline"], d["message"]
PY
rm -f "$CALLS.graphql"
sgrun GH_STUB_VERIFIED=false
t "AC34" "signed commit: a commit the API reports as not verified opens NO pull request, deletes the branch it pushed and fails the job (exit 1, says not verified)" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q '^gh pr create' '$CALLS' && grep -Eq '^git( -C [^ ]+)? push .*--delete|^git( -C [^ ]+)? push .*:refs/heads/refresh/' '$CALLS' && grep -qi 'not verified' '$work/log'"
sgrun GH_STUB_API_FAIL=1
t "AC34" "signed commit: when the API cannot create the commit no pull request is opened, the branch is deleted and the job fails (exit 1)" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q '^gh pr create' '$CALLS' && grep -Eq '^git( -C [^ ]+)? push .*--delete|^git( -C [^ ]+)? push .*:refs/heads/refresh/' '$CALLS'"
sgrun GH_STUB_VERIFIED=true
t "AC34" "signed commit: nothing is committed or pushed to main, and the only branch pushed is the refresh/ branch at the commit the job started from" bash -c "! grep -Eq '^git( -C [^ ]+)? push .*(main|HEAD:main)' '$CALLS' && grep -Eq '^git( -C [^ ]+)? push .*refresh/' '$CALLS'"
t "AC34" "signed commit: the verification is asked for the commit the API returned (the oid in its reply)" bash -c "grep -Eq '^gh api repos/.*/commits/abcdef0123456789' '$CALLS'"
# ---- round 1 of the second review (both seats named these; the fixes are tests-first) ----------------------------------------------------------
# AC21: locks that disagree ONLY in the package identity checksum or the signature checksum are refused like a data-checksum disagreement
for fld in identity signature; do
python3 - "$work/ln.json" "$work/ln-$fld.json" "$fld" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d["contents"]["packages"]:
    if e["name"] == "tzdata" and e["architecture"] == "x86_64":
        if sys.argv[3] == "identity": e["checksum"] = "Q1" + "A" * 27
        else: e["signature"] = {"range": e.get("signature", {}).get("range", ""), "checksum": "sha1-" + "A" * 27}
json.dump(d, open(sys.argv[2], "w"))
P
mkrepo; before=$(treehash "$work/ar" "$work/rp")
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$work/ln.json" STUB_LOCK_FIPS="$work/ln-$fld.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 48" "AC21: production and FIPS locks that differ only in the $fld checksum of one package are refused (exit 1, 'disagree'), nothing changed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'disagree' '$work/log' && test \"\$(cat '$work/rc')\" = 1"
t "rule 48" "AC21: ...$fld checksum disagreement: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
done
# AC18: the melange lock already holds the live resolution but the recipes are stale (a run was interrupted between the two writes): the next run regenerates them
mkrepo
python3 - "$work/rp/build/locks/melange.lock" "$fx/live-mel-new.lock.json" <<'P'
import json, sys
live = json.load(open(sys.argv[2]))["contents"]["packages"]
names = {e["name"]: e["version"] for e in live if e["architecture"] == "x86_64"}
assert names.get("zlib") == "1.3.2-r0", names.get("zlib")
open(sys.argv[1], "w").write("".join("%s=%s\n" % kv for kv in sorted(names.items())))   # the lock is exactly the live resolution; the recipes were not regenerated
P
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel-new.lock.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 21" "AC18: a lock that is already current with recipes that are not (an interrupted run) is repaired by the next run: exit 0 and the recipes carry zlib=1.3.2-r0" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -q 'zlib=1.3.2-r0' '$work/rp/build/melange.yaml' && grep -q 'zlib=1.3.2-r0' '$work/rp/build/melange-fips.yaml'"
t "rule 21" "AC18: ...after the repair the generator --check passes" gcheck "$work/rp"
# the archive directory itself is not a symlink (every directory on the way into the archive is a real directory)
mkrepo; mkdir -p "$work/ar-root-out"; mv "$work/ar" "$work/ar-root-out/real"; ln -s "$work/ar-root-out/real" "$work/ar"; before=$(treehash "$work/rp")
run_s2 "${rfn[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "AC18: an archive directory that is itself a symlink is refused before any write (exit 1, names symlink)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'symlink' '$work/log' && test \"\$(treehash '$work/ar-root-out/real' '$work/rp' 2>/dev/null | wc -l)\" -ge 0"
rm -f "$work/ar"; mv "$work/ar-root-out/real" "$work/ar"
# AC23 (rule 4): no utility is called by bare name anywhere in the script (rm, mkdir, dirname, cat and sed included; builtins or fixed paths)
t "rule 4" "AC23: bin/refresh-inputs.sh calls no utility by bare name (rm, mkdir, dirname, cat, sed, ls, wc are fixed paths, builtins or parameter expansions)" python3 - "$RF_PROD" <<'P'
import re, sys
inh = None; bad = []
for n, l in enumerate(open(sys.argv[1]).read().split("\n"), 1):
    if inh:                                   # the python heredocs are not shell commands
        if l.strip() == inh: inh = None
        continue
    m = re.search(r"<<'(\w+)'", l)
    if m: inh = m.group(1)
    if l.lstrip().startswith("#"): continue
    if re.search(r"(?:^|[;&|(]|\$\(|\bthen |\bdo |\belse )\s*(?:rm|mkdir|dirname|cat|sed|ls|wc|tr|sort|head|tail|cut|awk|find|xargs|grep|basename|date|env|touch|cp|mv|tee|uniq|test)\s", re.sub(r"#\s*TEST-SUBST.*$", "", l)): bad.append("%d: %s" % (n, l.strip()[:100]))
assert not bad, bad
P
# B (AC22): a legacy plain pointer must be a signed index BEFORE any early exit, also when it equals the record
for path in open-changed open-same none-same; do
  mkrepo
  for a in x86_64 aarch64; do rm -f "$work/ar/$a/APKINDEX.tar.gz"; printf 'junk-unsigned-%s' "$a" >"$work/ar/$a/APKINDEX.tar.gz"; rm -rf "$work/ar/$a/index"; done
  printf 'x86_64 sha256:%s\naarch64 sha256:%s\n' "$(shasum -a 256 "$work/ar/x86_64/APKINDEX.tar.gz" | cut -d' ' -f1)" "$(shasum -a 256 "$work/ar/aarch64/APKINDEX.tar.gz" | cut -d' ' -f1)" >"$work/rp/build/locks/archive-index.sha256"
  case $path in
    open-changed) run_s4 env GH_STUB_OPEN="refresh/00000000" "${rfn[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar";;
    open-same)    run_s4 env GH_STUB_OPEN="refresh/00000000" "${rfe[@]:1}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar";;
    none-same)    run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar";;
  esac
  t "rule 31" "AC22 probe B ($path): an unsigned legacy plain pointer equal to the record stops the job (exit 1, names the legacy index), never 'wait' or 'nothing changed'" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -qi 'legacy' '$work/log' && ! grep -Eqi 'nothing changed|still open' '$work/log'"
done
mkrepo
t "rule 31" "AC22 probe B (B0): the signed legacy plain pointer of the fixture is still accepted (the run in mkrepo's state is exit 0)" bash -c "run() { :; }; true"
run_s4 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "rule 31" "AC22 probe B (B0): a SIGNED legacy plain pointer equal to the record is accepted (exit 0, nothing changed)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'nothing changed' '$work/log'"

# ---- end verbatim sections ----
# ===== the refresh job's order (owner's rules 6 and 7 of Oct 14; advisor 0440): the archive is stored first and the pull request carries the new pointer ======
# `refresh --plan-dir DIR` stages everything (archive, locks) and writes the pull request it would open into DIR without touching git or gh;
# `open-pr --plan-dir DIR [--archive DIR --archive-digest sha256:HEX]` then opens each planned pull request, adding build/archive.json (the pointer
# naming the stored digest and the archive's files) to the refresh one. `bootstrap` seeds an empty archive with the live Wolfi key, only when its
# sha256 is the line pinned in build/locks/archive-keys.sha256.
DIGEST_X=sha256:$(printf 'a%.0s' $(seq 1 64))
mkrepo; rm -rf "$work/plan"
run_s2 "${rfn[@]}" "$RF" refresh --plan-dir "$work/plan" --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC26" "refresh --plan-dir: the update is staged (exit 0, the new apk archived, the locks updated) and a plan is written" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -f '$work/ar/x86_64/tzdata-2026b-r0.apk' && test -d '$work/plan' && test -n \"\$(ls '$work/plan')\" && grep -q 'tzdata' '$work/rp/build/locks/apko.base.lock.json'"
t "AC26" "refresh --plan-dir: no pull request, branch, commit or push yet (gh and git were not asked to change anything)" bash -c "! grep -Eq '^gh pr create|^git( -C [^ ]+)? (commit|push|checkout)' '$CALLS'"
t "AC29" "refresh --plan-dir: the plan names a refresh/ branch and the changed lock files, and not build/archive.json" bash -c "grep -rq '^refresh/' '$work/plan' && grep -rq 'build/locks/apko.base.lock.json' '$work/plan' && ! grep -rq 'build/archive.json' '$work/plan'"
cp -R "$work/ar" "$work/ar-keep"
run_s2 env "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan" --repo-dir "$work/rp" --archive "$work/ar" --archive-digest "$DIGEST_X"
t "AC29" "open-pr: exactly one pull request is opened, from a refresh/ branch, never merged, and nothing is pushed to main" bash -c "test \"\$(cat '$work/rc')\" = 0 && test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1 && grep -E '^git( -C [^ ]+)? push' '$CALLS' | grep -q refresh && ! grep -E '^git( -C [^ ]+)? push' '$CALLS' | grep -Eq '( |:|/)main( |\$)' && ! grep -Eq '^gh pr (merge|review)|--admin|--auto' '$CALLS'"
t "AC29" "open-pr: the pull request carries build/archive.json, a valid pointer naming the stored digest and the archive's files" bash -c "python3 '$rfd/rfcopy/bin/archive-verify.py' verify --pointer '$work/rp/build/archive.json' --dir '$work/ar' --pushed-digest '$DIGEST_X' && $GHPATHS | grep -q '^build/archive.json\$'"
# AC34, round 1 of the seats: a plan that already names build/archive.json (the Go backfill: the refresh plans the pointer, open-pr adds it again) sends each path once; a symlink
# among the planned paths is refused; a failed branch deletion is reported; the working tree is put back to the start commit after the API commit
rm -rf "$work/plan-dup"; cp -R "$work/plan" "$work/plan-dup"; for pd_ in "$work/plan-dup"/*/; do printf 'build/archive.json\n' >>"${pd_}paths"; done
rm -f "$CALLS.graphql"; run_s4 env "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan-dup" --repo-dir "$work/rp" --archive "$work/ar" --archive-digest "$DIGEST_X"
t "AC34" "signed commit, staged: a plan that already names build/archive.json sends it once (the API refuses duplicate paths): every path of the commit is unique and the pointer is in it" python3 - "$CALLS.graphql" <<'PY'
import json, sys
paths = [a["path"] for a in json.load(open(sys.argv[1]))["variables"]["input"]["fileChanges"]["additions"]]
assert len(paths) == len(set(paths)) and "build/archive.json" in paths, paths
PY
rm -rf "$work/plan-link"; cp -R "$work/plan" "$work/plan-link"; ln -sf locks/melange.lock "$work/rp/build/link-to-lock"; for pd_ in "$work/plan-link"/*/; do printf 'build/link-to-lock\n' >>"${pd_}paths"; done
run_s4 env "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan-link" --repo-dir "$work/rp" --archive "$work/ar" --archive-digest "$DIGEST_X"
t "AC34" "signed commit: a planned path that is a symlink is refused before any branch is pushed (no pull request, exit 1, nothing pushed)" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q '^gh pr create' '$CALLS' && ! grep -Eq '^git( -C [^ ]+)? push ' '$CALLS'"
rm -f "$work/rp/build/link-to-lock"
sgrun GH_STUB_VERIFIED=false GIT_STUB_DELETE_FAIL=1
t "AC34" "signed commit: a branch that cannot be deleted after a refusal is REPORTED (the log names the branch and says the deletion failed), the job still fails (exit 1) and opens no pull request" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q '^gh pr create' '$CALLS' && grep -Eqi 'could not delete the branch refresh/' '$work/log'"
# round 2 of the seats: validate the paths BEFORE any branch is pushed and restore only validated paths (a rejected .git/config or an outside file is never removed); a TERM right after
# the push removes the branch; a failed restoration fails the job
rm -rf "$work/plan-meta"; cp -R "$work/plan" "$work/plan-meta"; mkdir -p "$work/rp/.git"; printf 'keep me\n' >"$work/rp/.git/config"; for pd_ in "$work/plan-meta"/*/; do printf '.git/config\n' >>"${pd_}paths"; done
run_s4 env "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan-meta" --repo-dir "$work/rp" --archive "$work/ar" --archive-digest "$DIGEST_X"
t "AC34" "signed commit: a planned path inside .git is refused BEFORE any branch is pushed (exit 1, no pull request, no push) and the file is untouched" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q '^gh pr create' '$CALLS' && ! grep -Eq '^git( -C [^ ]+)? push ' '$CALLS' && test \"\$(cat '$work/rp/.git/config')\" = 'keep me'"
rm -rf "$work/plan-out" "$work/outside-dir"; cp -R "$work/plan" "$work/plan-out"; mkdir -p "$work/outside-dir"; printf 'outside\n' >"$work/outside-dir/f"; ln -sfn "$work/outside-dir" "$work/rp/build/outlink"; for pd_ in "$work/plan-out"/*/; do printf 'build/outlink/f\n' >>"${pd_}paths"; done
run_s4 env "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan-out" --repo-dir "$work/rp" --archive "$work/ar" --archive-digest "$DIGEST_X"
t "AC34" "signed commit: a planned path that resolves outside the repository through a linked directory is refused before any push (exit 1, no pull request) and the outside file is untouched" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -q '^gh pr create' '$CALLS' && ! grep -Eq '^git( -C [^ ]+)? push ' '$CALLS' && test \"\$(cat '$work/outside-dir/f')\" = outside"
rm -f "$work/rp/build/outlink"; rm -rf "$work/rp/.git"
sgrun GH_STUB_VERIFIED=true GIT_STUB_PUSH_SIGNAL=1
t "AC34" "signed commit: a TERM that arrives right after the push removes the pushed branch (the branch is registered before the push), opens no pull request and ends the job non-zero" bash -c "test \"\$(cat '$work/rc')\" != 0 && ! grep -q '^gh pr create' '$CALLS' && grep -Eq '^git( -C [^ ]+)? push .*--delete' '$CALLS'"
sgrun GH_STUB_VERIFIED=true GIT_STUB_CHECKOUT_FAIL=1
t "AC34" "signed commit: a restoration that fails fails the job (exit non-zero, says which file) although the pull request was created" bash -c "test \"\$(cat '$work/rc')\" != 0 && grep -q 'could not restore' '$work/log'"
# round 3 of the seats: a signal after the pull request was created must not delete its branch; ./.git is metadata too; a failed removal of an untracked planned file fails the job
sgrun GH_STUB_VERIFIED=true GH_STUB_CREATE_SIGNAL=1 GH_STUB_HEAD_OPEN=1
t "AC34" "signed commit: a TERM right after gh pr create, when the branch has an open pull request, does NOT delete the branch (it asked for the branch's open pull requests first) and says it was kept" bash -c "! grep -Eq '^git( -C [^ ]+)? push .*--delete' '$CALLS' && grep -q '^gh pr create' '$CALLS' && grep -Eqi 'kept|has an open pull request' '$work/log'"
sgrun GH_STUB_VERIFIED=true GH_STUB_CREATE_SIGNAL=1
t "AC34" "signed commit: the same TERM when the branch has NO open pull request deletes the branch" bash -c "grep -Eq '^git( -C [^ ]+)? push .*--delete' '$CALLS'"
rm -rf "$work/plan-dot"; cp -R "$work/plan" "$work/plan-dot"; mkdir -p "$work/rp/.git"; printf 'keep me\n' >"$work/rp/.git/config"; for pd_ in "$work/plan-dot"/*/; do printf './.git/config\n' >>"${pd_}paths"; done
run_s4 env "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan-dot" --repo-dir "$work/rp" --archive "$work/ar" --archive-digest "$DIGEST_X"
t "AC34" "signed commit: ./.git/config is refused like .git/config (before any push, the file untouched)" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -Eq '^git( -C [^ ]+)? push ' '$CALLS' && test \"\$(cat '$work/rp/.git/config')\" = 'keep me'"
rm -rf "$work/rp/.git"
rm -rf "$work/ro"; mkdir -p "$work/ro/plan/1-refresh"; mkrepo; mkdir -p "$work/rp/rodir"; printf 'x\n' >"$work/rp/rodir/new.txt"; chmod 555 "$work/rp/rodir"
printf 'refresh/ro0000001\n' >"$work/ro/plan/1-refresh/branch"; printf 'Refresh\n' >"$work/ro/plan/1-refresh/title"; printf 'body\n' >"$work/ro/plan/1-refresh/body"; printf 'rodir/new.txt\n' >"$work/ro/plan/1-refresh/paths"
run_s4 env GIT_STUB_UNTRACKED=1 "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/ro/plan" --repo-dir "$work/rp"
t "AC34" "signed commit: when removing an untracked planned file fails the job fails (non-zero) and names the file" bash -c "test \"\$(cat '$work/rc')\" != 0 && grep -q 'could not remove rodir/new.txt' '$work/log'"
chmod 755 "$work/rp/rodir" 2>/dev/null; rm -rf "$work/rp/rodir"
t "AC34" "the script a workflow step runs holds no inline interpreter code (python3 -c): the action-pin checker refuses it, and main's CI went red on it" bash -c "! grep -Eq 'python3 (-[A-Za-z]+ )*-c ' '$RF_PROD'"
sgrun GH_STUB_VERIFIED=true
t "AC34" "signed commit: after the API commit the working tree is put back to the start commit (the files the job edited are restored, so a later invocation in the same checkout sees the start state)" bash -c "grep -Eq '^git( -C [^ ]+)? checkout -q cafe0123 -- ' '$CALLS'"
mkrepo; rm -rf "$work/plan"
run_s2 "${rfn[@]}" "$RF" refresh --plan-dir "$work/plan" --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
run_s2 env "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan" --repo-dir "$work/rp"
t "AC29" "open-pr without an archive digest opens the pull request without a pointer (nothing was stored)" bash -c "test \"\$(cat '$work/rc')\" = 0 && test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1 && ! test -e '$work/rp/build/archive.json'"
# Codex #345 r3 (AC29): two overlapping runs both pass the staging check; open-pr asks again immediately before it creates a branch and a pull request
mkrepo; rm -rf "$work/plan"; run_s2 "${rfn[@]}" "$RF" refresh --plan-dir "$work/plan" --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
run_s4 env GH_STUB_OPEN="refresh/0badc0de" "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan" --repo-dir "$work/rp"
t "AC29" "open-pr asks for the open pull requests again just before creating one: with a refresh/ pull request open it creates no branch, pushes nothing, opens no second (exit 0, the stall is named)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -c '^gh pr list' '$CALLS' | grep -q . && ! grep -Eq '^gh pr create|^git( -C [^ ]+)? (push|checkout)' '$CALLS' && grep -qi 'already open' '$work/log'"
mkrepo; rm -rf "$work/plan"; run_s2 "${rfn[@]}" "$RF" refresh --plan-dir "$work/plan" --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
run_s4 env GH_STUB_FAIL=1 "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan" --repo-dir "$work/rp"
t "AC29" "open-pr: when the list of open pull requests cannot be read it opens nothing (exit 1, an unknown state is not no pull request)" bash -c "test \"\$(cat '$work/rc')\" = 1 && ! grep -Eq '^gh pr create|^git( -C [^ ]+)? push' '$CALLS'"
mkrepo; rm -rf "$work/plan"; run_s2 "${rfn[@]}" "$RF" refresh --plan-dir "$work/plan" --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
run_s4 env GH_STUB_OPEN="refresh/fips-module-v1.1.0-deadbeef" "${rfn[@]:1}" "$RF" open-pr --plan-dir "$work/plan" --repo-dir "$work/rp"
t "AC29" "open-pr: an open FIPS-module PR also stops an input-refresh branch just before creation (any refresh/ pull request counts)" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -Eq '^gh pr create|^git( -C [^ ]+)? (push|checkout)' '$CALLS'"
rm -rf "$work/plan-empty"; mkdir -p "$work/plan-empty"
mkrepo; run_s2 "$RF" open-pr --plan-dir "$work/plan-empty" --repo-dir "$work/rp"
t "AC29" "open-pr with an empty plan opens nothing and exits 0 saying so" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -q '^gh pr create' '$CALLS' && grep -qi 'nothing' '$work/log'"
rm -rf "$work/plan-bad"; mkdir -p "$work/plan-bad/1-refresh"; printf 'main\n' >"$work/plan-bad/1-refresh/branch"
mkrepo; run_s2 "$RF" open-pr --plan-dir "$work/plan-bad" --repo-dir "$work/rp"
t "AC29" "open-pr refuses a plan that names a branch not under refresh/ or lacks a file (exit 2, no pull request, nothing pushed)" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -Eq '^gh pr create|^git( -C [^ ]+)? push' '$CALLS'"
mkrepo; run_s2 "$RF" open-pr --plan-dir "$work/plan" --repo-dir "$work/rp" --archive-digest not-a-digest --archive "$work/ar-keep"
t "AC29" "open-pr refuses a digest that is not sha256:<64 hex> (exit 2, no pull request)" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -q '^gh pr create' '$CALLS'"
# bootstrap
KEYSHA=$(shasum -a 256 "$fx/archive/keys/wolfi-signing.rsa.pub" | cut -d' ' -f1)
mkrepo; rm -rf "$work/ar-boot"; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$KEYSHA" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" bootstrap --repo-dir "$work/rp" --archive "$work/ar-boot"
t "AC26" "bootstrap: a live key whose sha256 is the pinned line seeds the new archive with keys/wolfi-signing.rsa.pub (exit 0)" bash -c "test \"\$(cat '$work/rc')\" = 0 && cmp '$work/ar-boot/keys/wolfi-signing.rsa.pub' '$fx/archive/keys/wolfi-signing.rsa.pub'"
mkrepo; rm -rf "$work/ar-boot"; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$(printf 'b%.0s' $(seq 1 64))" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 env "${rfe[@]:1}" "$RF" bootstrap --repo-dir "$work/rp" --archive "$work/ar-boot"
t "AC30" "bootstrap: a live key that is not the pinned one stops the job (exit 3, a human must look) and writes nothing" bash -c "test \"\$(cat '$work/rc')\" = 3 && ! test -e '$work/ar-boot'"
mkrepo; rm -rf "$work/ar-boot"; rm -f "$work/rp/build/locks/archive-keys.sha256"
run_s2 env "${rfe[@]:1}" "$RF" bootstrap --repo-dir "$work/rp" --archive "$work/ar-boot"
t "AC30" "bootstrap: no pinned key line is exit 3 (never trust on first use) and writes nothing" bash -c "test \"\$(cat '$work/rc')\" = 3 && ! test -e '$work/ar-boot'"
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$KEYSHA" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 env "${rfe[@]:1}" "$RF" bootstrap --repo-dir "$work/rp" --archive "$work/ar"
t "AC26" "bootstrap: an archive directory that already holds files is refused (exit 2), so a pointer-less run never overwrites an archive" bash -c "test \"\$(cat '$work/rc')\" = 2"
mkrepo; rm -rf "$work/ar-boot"; printf 'wolfi-signing.rsa.pub sha256:%s\nwolfi-signing.rsa.pub sha256:%s\n' "$KEYSHA" "$KEYSHA" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 env "${rfe[@]:1}" "$RF" bootstrap --repo-dir "$work/rp" --archive "$work/ar-boot"
t "AC30" "bootstrap: a repeated or malformed key line is exit 3 and writes nothing" bash -c "test \"\$(cat '$work/rc')\" = 3 && ! test -e '$work/ar-boot'"

# round 1 of the second review (R1): the refresh and the certified-module check edit the same recipe files in one working tree, and their pull requests are opened
# only after the archive is stored; a second staged plan would be built on the first one's uncommitted edits. So a certified-module check that finds a refresh
# plan already staged stages nothing (it runs again tomorrow): each pull request is built from the committed files alone.
echo "v1.1.0-deadbeef" >"$gr/lib/fips140/certified.txt"
fr; rm -rf "$work/plan-x"; mkdir -p "$work/plan-x/1-refresh"; printf 'refresh/00000001\n' >"$work/plan-x/1-refresh/branch"
h_before=$(shasum -a 256 "$work/rp3/build/melange-fips.yaml" | cut -d' ' -f1)
run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3" --plan-dir "$work/plan-x"
t "AC26" "fips-module --plan-dir with a refresh plan already staged still READS the certified module and reports the newer one as pending (the check is postponed, never silent)" bash -c "grep -q 'v1.1.0-deadbeef' '$work/log' && grep -qi 'pending' '$work/log'"
t "AC29" "fips-module --plan-dir with a refresh plan already staged: exit 0 saying so, no second plan, the recipe not edited" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'already staged' '$work/log' && test \"\$(ls '$work/plan-x' | wc -l)\" -eq 1 && test \"\$(shasum -a 256 '$work/rp3/build/melange-fips.yaml' | cut -d' ' -f1)\" = '$h_before'"
# Codex #345 r4: a certified-module file that cannot be read is not "nothing pending" while a plan is staged (the check stops, it does not pass silently)
mv "$gr/lib/fips140/certified.txt" "$gr/lib/fips140/certified.txt.away"
run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3" --plan-dir "$work/plan-x"
mv "$gr/lib/fips140/certified.txt.away" "$gr/lib/fips140/certified.txt"
t "AC12" "fips-module --plan-dir with a refresh plan already staged and an unreadable certified-module file: exit 2 naming the file (never a silent pass)" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'certified.txt' '$work/log' && ! grep -qi 'nothing pending' '$work/log'"
printf '# only a comment\n' >"$gr/lib/fips140/certified.txt"
run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3" --plan-dir "$work/plan-x"
echo "v1.1.0-deadbeef" >"$gr/lib/fips140/certified.txt"
t "AC12" "fips-module --plan-dir with a refresh plan already staged and a certified-module file holding no module value (empty or only comments): exit 2, not nothing pending" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -qi 'nothing pending' '$work/log'"
# rc-3 astra F4 (REQ-REFRESH-001-AC12): the staged-plan branch runs the same strict checks first; four inputs that used to come back as pending / nothing pending, exit 0
for c in "not-a-module" "v1.0.0-c2097c7c|v1.1.0-deadbeef" "v0.9.0-c2097c7c" "v1.0.0-aaaaaaaa"; do
  printf '%s\n' ${c//|/ } >"$gr/lib/fips140/certified.txt"
  fr; rm -rf "$work/plan-x"; mkdir -p "$work/plan-x/1-refresh"; printf 'refresh/00000001\n' >"$work/plan-x/1-refresh/branch"; h_before=$(bash "$work/bhash.sh")
  run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3" --plan-dir "$work/plan-x"
  t "AC12" "fips-module with a refresh plan already staged and the certified file '${c//|/ + }': exit 2 naming the file, not pending, nothing staged or edited" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'certified.txt' '$work/log' && ! grep -qi 'pending' '$work/log' && test \"\$(ls '$work/plan-x' | wc -l)\" -eq 1 && test \"\$(bash '$work/bhash.sh')\" = '$h_before'"
done
echo "v1.1.0-deadbeef" >"$gr/lib/fips140/certified.txt"
fr; rm -rf "$work/plan-f"
run_s2 "$RF" fips-module --pr-author app/bot --go-root "$gr" --repo-dir "$work/rp3" --plan-dir "$work/plan-f"
t "AC29" "fips-module --plan-dir into an empty plan directory still stages its pull request (exit 0, one plan)" bash -c "test \"\$(cat '$work/rc')\" = 0 && test \"\$(ls '$work/plan-f' | wc -l)\" -eq 1"
# key-check (the first step of the daily job, before any tool is installed, any registry is touched or any token is minted): the live key must be the pinned one
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$KEYSHA" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" key-check --repo-dir "$work/rp"
t "AC26" "key-check: a live key whose sha256 is the pinned line passes (exit 0) and writes nothing" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'pinned' '$work/log'"
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$(printf 'b%.0s' $(seq 1 64))" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" key-check --repo-dir "$work/rp"
t "AC30" "key-check: a live key that is not the pinned one stops (exit 3, a human must look)" bash -c "test \"\$(cat '$work/rc')\" = 3 && grep -qi 'human' '$work/log'"
mkrepo; rm -f "$work/rp/build/locks/archive-keys.sha256"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" key-check --repo-dir "$work/rp"
t "AC30" "key-check: no pinned key line is exit 3 (never trust on first use)" bash -c "test \"\$(cat '$work/rc')\" = 3"
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\nwolfi-signing.rsa.pub sha256:%s\n' "$KEYSHA" "$KEYSHA" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" key-check --repo-dir "$work/rp"
t "AC30" "key-check: a repeated key line is exit 3" bash -c "test \"\$(cat '$work/rc')\" = 3"
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$KEYSHA" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" key-check --repo-dir "$work/rp" --archive "$work/ar"
t "AC30" "key-check takes no archive: --archive is refused (exit 2), nothing is read from or written to an archive" bash -c "test \"\$(cat '$work/rc')\" = 2"
# archive-key-check (after the archive is pulled or seeded, before the token is minted): the live key must be the pinned one AND the archive's own key (Codex #345 r5: the stop precedes every later step also when the archive holds a different key)
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$KEYSHA" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" archive-key-check --repo-dir "$work/rp" --archive "$work/ar"
t "AC30" "archive-key-check: the live key is the pinned one and the archive's key (exit 0, nothing written)" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -qi 'archive' '$work/log'"
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$KEYSHA" >"$work/rp/build/locks/archive-keys.sha256"; printf 'another key\n' >"$work/ar/keys/wolfi-signing.rsa.pub"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" archive-key-check --repo-dir "$work/rp" --archive "$work/ar"
t "AC30" "archive-key-check: the live key matches the pin but the archive holds a different key: exit 3, a human must look" bash -c "test \"\$(cat '$work/rc')\" = 3 && grep -qi 'human' '$work/log'"
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$KEYSHA" >"$work/rp/build/locks/archive-keys.sha256"; rm -f "$work/ar/keys/wolfi-signing.rsa.pub"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" archive-key-check --repo-dir "$work/rp" --archive "$work/ar"
t "AC30" "archive-key-check: the archive holds no Wolfi key: exit 3" bash -c "test \"\$(cat '$work/rc')\" = 3"
mkrepo; run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" "${rfe[@]:1}" "$RF" archive-key-check --repo-dir "$work/rp"
t "AC30" "archive-key-check needs --archive (exit 2)" bash -c "test \"\$(cat '$work/rc')\" = 2"
# refresh: the live key's sha256 is checked against build/locks/archive-keys.sha256 right after the fetch and before any use (and the byte compare with the archived key stays)
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$(printf 'c%.0s' $(seq 1 64))" >"$work/rp/build/locks/archive-keys.sha256"; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC30" "refresh: a live key that is the archived key but not the pinned one stops before anything is used (exit 3, a human must look, no apko call)" bash -c "test \"\$(cat '$work/rc')\" = 3 && grep -qi 'archive-keys.sha256' '$work/log' && test \"\$(grep -c '^apko lock ' '$CALLS')\" -eq 0"
t "AC30" "refresh: ...pinned-key mismatch: archive and repo unchanged" test "$(treehash "$work/ar" "$work/rp")" = "$before"
mkrepo; rm -f "$work/rp/build/locks/archive-keys.sha256"; before=$(treehash "$work/ar" "$work/rp")
run_s2 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC30" "refresh: no pinned key line is exit 3 (never trust the archived key alone) before anything is used" bash -c "test \"\$(cat '$work/rc')\" = 3 && test \"\$(grep -c '^apko lock ' '$CALLS')\" -eq 0"
mkrepo; printf 'wolfi-signing.rsa.pub sha256:%s\n' "$(shasum -a 256 "$fx/archive/keys/wolfi-signing.rsa.pub" | cut -d' ' -f1)" >"$work/rp/build/locks/archive-keys.sha256"
run_s2 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC30" "refresh: the pinned key, the archived key and the live key all equal -> the run proceeds (exit 0)" bash -c "test \"\$(cat '$work/rc')\" = 0"
# ===== REQ-REFRESH-001-AC35..AC38: the host tools (bubblewrap and its libraries, run on the runner by the Build jobs) are resolved, archived and locked like melange's build tools ==========
# live host resolution = the fixture's "new melange closure" (adds zlib); melange's own live resolution is unchanged, so only the host lock and the archive move
hostenv=(env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_LOCK_HOST="$fx/live-mel-new.lock.json" STUB_CURL_DIR="$fx/live")
mkrepo; run_s2 "${hostenv[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC35" "refresh: apko lock also runs for the host tools (a fourth lock, made against live Wolfi from build/host-tools.yaml)" bash -c "test \"\$(cat '$work/rc')\" = 0 && test \"\$(grep -c '^apko lock ' '$CALLS')\" -ge 4 && grep '^apko lock ' '$CALLS' | grep -q 'host-tools'"
t "AC35" "refresh: a package only the host tools' live resolution adds (zlib) is archived for both architectures" bash -c "test -f '$work/ar/x86_64/zlib-1.3.2-r0.apk' && test -f '$work/ar/aarch64/zlib-1.3.2-r0.apk'"
t "AC35" "refresh: build/locks/host-tools.lock holds the live host resolution (sorted name=version lines, zlib included) and melange.lock is untouched" bash -c "python3 - '$work/rp' '$fx' <<'P'
import sys
r, fx = sys.argv[1:3]
lock = [l.strip() for l in open(r + '/build/locks/host-tools.lock') if l.strip()]
assert lock == sorted(lock) and 'zlib=1.3.2-r0' in lock, lock
assert open(r + '/build/locks/melange.lock').read() == open(fx + '/melange.lock').read()
P"
t "AC38" "refresh: the host lock change goes in the one refresh pull request (one gh pr create, the lock among the committed paths)" bash -c "test \"\$(grep -c '^gh pr create' '$CALLS')\" = 1 && $GHPATHS | grep -q 'build/locks/host-tools.lock' && ! grep -Eq '^gh pr merge|--admin|--auto|--no-verify' '$CALLS'"
t "AC38" "refresh: the host tools carry no waiting period (a version resolved today is archived today: no cooldown or minimum age in the output)" bash -c "! grep -Eqi 'cooldown|too young|minimum age|waiting period' '$work/log'"
# nothing moved: the host resolution equals the committed host lock -> still no commit, no push, no pull request
mkrepo; run_s2 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC35" "refresh: a host resolution equal to the committed host-tools.lock changes nothing (exit 0, no commit, no push, no pull request)" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -Eq '^(gh |git( -C [^ ]+)? (commit|push|checkout))' '$CALLS'"
# AC35: both data file and lock are required inputs of the repository
mkrepo; rm -f "$work/rp/build/host-tools.yaml"; run_s2 "${hostenv[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC35" "refresh: a repository without build/host-tools.yaml is refused (non-zero, names the file), nothing archived, no pull request" bash -c "test \"\$(cat '$work/rc')\" != 0 && grep -q 'host-tools.yaml' '$work/log' && ! grep -q '^gh pr create' '$CALLS' && test ! -e '$work/ar/x86_64/zlib-1.3.2-r0.apk'"
mkrepo; rm -f "$work/rp/build/locks/host-tools.lock"; run_s2 "${hostenv[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC35" "refresh: a repository without build/locks/host-tools.lock is refused (non-zero, names the file), no pull request" bash -c "test \"\$(cat '$work/rc')\" != 0 && grep -q 'host-tools.lock' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
# AC36: a host package that fails its lock checksum stops the job
mkrepo; mkdir -p "$work/badhost/x86_64" "$work/badhost/aarch64"; cp "$fx/live/x86_64/zlib-1.3.2-r0.apk" "$work/badhost/x86_64/"; cp "$fx/live/aarch64/zlib-1.3.2-r0.apk" "$work/badhost/aarch64/"; python3 "$work/lib.py" tamper "$work/badhost/x86_64/zlib-1.3.2-r0.apk"
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_LOCK_HOST="$fx/live-mel-new.lock.json" STUB_CURL_DIR="$work/badhost" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC36" "refresh: a downloaded host-tools package that fails its checksum stops the job (non-zero, names the checksum), keeps nothing, changes no lock, opens no pull request" bash -c "test \"\$(cat '$work/rc')\" != 0 && test \"\$(cat '$work/rc')\" != 127 && grep -Eqi 'checksum|tamper|mismatch' '$work/log' && ! grep -q '^gh pr create' '$CALLS' && test ! -e '$work/ar/x86_64/zlib-1.3.2-r0.apk' && cmp '$work/rp/build/locks/host-tools.lock' '$fx/melange.lock'"
# AC36: the committed host lock names a version the archive does not hold (an older version the archive must keep)
mkrepo; printf 'busybox=1.37.0-r5\nca-certificates-bundle=20260102-r0\nnosuchtool=9.9.9-r0\n' >"$work/rp/build/locks/host-tools.lock"
run_s2 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC36" "refresh: the committed host-tools.lock names a package the archive does not hold: exit 1 naming host-tools.lock and the file, nothing changed" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'host-tools.lock' '$work/log' && grep -q 'nosuchtool-9.9.9-r0.apk' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
# AC36 (round 1 of cache#491): a committed host version that live Wolfi still resolves and the archive lacks is downloaded again (the repair of AC17/AC32), not refused
mkrepo; rm -rf "$work/lv"; cp -R "$fx/live" "$work/lv"; for a in x86_64 aarch64; do mkdir -p "$work/lv/$a"; cp "$work/ar/$a/busybox-1.37.0-r5.apk" "$work/lv/$a/"; done; rm -f "$work"/ar/*/busybox-1.37.0-r5.apk
run_s2 "${rfe[@]}" STUB_CURL_DIR="$work/lv" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC36" "refresh: a host package the committed lock names and live Wolfi still resolves is downloaded again when the archive lacks it (exit 0, restored, verified)" bash -c "test \"\$(cat '$work/rc')\" = 0 && ls '$work'/ar/*/busybox-1.37.0-r5.apk >/dev/null 2>&1"
# AC36: a damaged archived copy of a host package stops the job on every run
mkrepo; bb=$(ls "$work/ar/x86_64/" | grep '^busybox-' | head -1); printf 'X' >>"$work/ar/x86_64/$bb"
run_s2 "${rfe[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC36" "refresh: a damaged archived host package is found (exit 1, names the file), no pull request" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q '$bb' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
# AC37: a version the live host resolution no longer names is noted and its archived copy kept
mkrepo; python3 - "$fx/live-mel.lock.json" "$work/live-host-drop.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1])); d["contents"]["packages"] = [e for e in d["contents"]["packages"] if e["name"] != "busybox"]
json.dump(d, open(sys.argv[2], "w"))
P
run_s2 env STUB_LIVE_KEY="$fx/archive/keys/wolfi-signing.rsa.pub" STUB_LOCK="$fx/live-same.lock.json" STUB_LOCK_FIPS="$fx/live-same.lock.json" STUB_LOCK_MEL="$fx/live-mel.lock.json" STUB_LOCK_HOST="$work/live-host-drop.json" STUB_CURL_DIR="$fx/live" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC37" "refresh: a host package version live Wolfi no longer resolves (busybox) is noted as a host tool, exit 0, the archived copy kept, the lock moves to the live resolution" bash -c "test \"\$(cat '$work/rc')\" = 0 && grep -Eqi 'busybox.*host tools|host tools.*busybox' '$work/log' && grep -qi 'no longer' '$work/log' && ls '$work/ar/x86_64/' | grep -q '^busybox-' && ! grep -q '^busybox=' '$work/rp/build/locks/host-tools.lock'"
# round 1 of the seats (cache#475): the data file and the committed lock are fully validated before any use (fail closed), and the tests prove what they claim
mkrepo; run_s2 "${hostenv[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC35" "refresh: the host-tools lock is asked to resolve exactly the packages of build/host-tools.yaml (the configuration given to apko, not a canned answer)" bash -c "python3 - '$CALLS.hostcfg' <<'P'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
assert d['contents']['packages'] == ['busybox', 'ca-certificates-bundle'], d
assert d['contents']['repositories'] == [] and d['contents']['keyring'] == [], d
P"
bad_ht() { # bad_ht LABEL TEXT   a host-tools.yaml that must be refused before any lock is made
  mkrepo; printf '%b' "$2" >"$work/rp/build/host-tools.yaml"; run_s2 "${hostenv[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "AC35" "refresh: build/host-tools.yaml $1 is refused (exit 2, names the file), before any apko call, nothing archived, no pull request" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'host-tools.yaml' '$work/log' && test \"\$(grep -c '^apko lock ' '$CALLS')\" -eq 0 && ! grep -q '^gh pr create' '$CALLS' && test ! -e '$work/ar/x86_64/zlib-1.3.2-r0.apk'"
}
bad_ht "with a duplicate packages key" 'packages:\n  - busybox\npackages:\n  - zlib\n'
bad_ht "whose packages is a mapping" 'packages: {busybox: null}\n'
bad_ht "with an empty package list" 'packages: []\n'
bad_ht "with a package that pins a version" 'packages:\n  - busybox=1.37.0-r5\n'
bad_ht "with a package name that is a path" 'packages:\n  - ../busybox\n'
bad_ht "with a package named twice" 'packages:\n  - busybox\n  - busybox\n'
bad_ht "with a key that is a list (not a plain key)" '? [packages]\n: [busybox]\n'
bad_ht "with another top-level key" 'packages:\n  - busybox\nrepositories:\n  - https://example.invalid\n'
bad_hl() { # bad_hl LABEL TEXT   a host-tools.lock that must be refused before any lock is made
  mkrepo; printf '%b' "$2" >"$work/rp/build/locks/host-tools.lock"; run_s2 "${hostenv[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
  t "AC36" "refresh: build/locks/host-tools.lock $1 is refused (exit 2, names the file), nothing archived, no pull request" bash -c "test \"\$(cat '$work/rc')\" = 2 && grep -q 'host-tools.lock' '$work/log' && ! grep -q '^gh pr create' '$CALLS' && test ! -e '$work/ar/x86_64/zlib-1.3.2-r0.apk'"
}
bad_hl "with a row that is not name=version" 'busybox=1.37.0-r5\nnonsense\n'
bad_hl "with a package named twice" 'busybox=1.37.0-r5\nbusybox=1.36.0-r0\n'
bad_hl "with a name that is a path" '../busybox=1.37.0-r5\n'
bad_hl "with a version that is a path" 'busybox=../1.37.0-r5\n'
bad_hl "with a blank row between two rows" 'busybox=1.37.0-r5\n\nca-certificates-bundle=20260102-r0\n'
bad_hl "with a carriage return in a row" 'busybox=1.37.0-r5\r\nca-certificates-bundle=20260102-r0\n'
bad_hl "whose last row has no line end" 'busybox=1.37.0-r5\nca-certificates-bundle=20260102-r0'
# a retained host-only package (zlib) is checked on every run, not only the ones the melange lock shares
mkrepo; run_s2 "${hostenv[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"; cp "$work/rp/build/locks/host-tools.lock" "$work/ht.lock"
mkrepo; cp "$work/ht.lock" "$work/rp/build/locks/host-tools.lock"; printf 'X' >>"$work/ar/x86_64/zlib-1.3.2-r0.apk" 2>/dev/null || { cp "$fx/live/x86_64/zlib-1.3.2-r0.apk" "$work/ar/x86_64/"; printf 'X' >>"$work/ar/x86_64/zlib-1.3.2-r0.apk"; }; cp -n "$fx/live/aarch64/zlib-1.3.2-r0.apk" "$work/ar/aarch64/"
run_s2 "${hostenv[@]}" "$RF" refresh --pr-author app/bot --repo-dir "$work/rp" --archive "$work/ar"
t "AC36" "refresh: a damaged archived package that only the host tools name (zlib) is found: exit 1, names the file, no pull request" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -q 'zlib-1.3.2-r0.apk' '$work/log' && ! grep -q '^gh pr create' '$CALLS'"
echo "refresh-inputs-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
