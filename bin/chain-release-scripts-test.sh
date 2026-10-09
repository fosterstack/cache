#!/usr/bin/env bash
# proves: REQ-CHAIN-007-AC5, REQ-CHAIN-007-AC6, REQ-CHAIN-007-AC7, REQ-CHAIN-007-AC8, REQ-CHAIN-007-AC9, REQ-CHAIN-007-AC10
# RED until PR 4 is implemented (bin/release-verify.sh, release-apks.sh, release-publish.sh, release-sign.sh, release-assets.sh do not exist): step 4.
#
# Release, behaviour half (v0.3.0 rules 5, 17, 29, 53b, 56, 57, 64, 69, 71; advisor rulings of Oct 9: rc tags like finals, the release policy
# signed with cosign so it is in Rekor, signatures in both registries). Every script is run in a throw-away tree with FAKE tools first on PATH
# (crane over a directory "registry", cosign, gh, melange, and fakes of bin/chain-verify.py, bin/apk-tool.py and bin/vendor-provenance.py); no
# network, no real credential, no real key. Credentials are SENTINEL strings: they must reach only the tool that needs them and never appear in
# any output, any file the script writes or any command line (stdin is allowed). Runs on ubuntu-24.04 or macOS with bash, python3, jq.
# RELEASE_BIN can point at another directory of scripts (used to prove the cases satisfiable against a throw-away reference; default bin/).
#
# FIXED paths the scripts read and write (PROPOSED, they are what the stage's downloads and uploads would carry; the scripts take no arguments
# because the stage runs them as `bash bin/witnessed.sh STEP bin/STEP.sh`):
#   in : witness-build/digests.json {"image-production","image-fips","apk-amd64","apk-arm64": "sha256:..."} (PR 1's schema), witness-build/build-collection.json,
#        witness-rebuild/..., witness-check/..., provenance/provenance.json, images/<variant>.tar + images/<variant>.digest (cache's OCI index digest),
#        apks/<arch>/fscache-0.3.0-r0.apk (Build's), sboms/*.json, locks/*.json, dist/*, policy.json (made by release-verify.sh)
#   out: release-apks/<arch>/*.apk, release-evidence/ (bundles, vendor-evidence.json, release-policy.bundle)
# Registries: ghcr.io/fosterstack/cache and docker.io/fosterstack/cache; tags 0.3.0 and 0.3.0-fips (a final release also floating tags: PROPOSED).
# The fake tools' command lines are PROPOSED/UNVERIFIED: crane push of an OCI tarball, melange sign --key FILE, cosign sign-blob --bundle.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export RELEASE_BIN="${RELEASE_BIN:-$root/bin}"
python3 - "$@" <<'PY'
import hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile
BIN = os.environ["RELEASE_BIN"]
SENT = {"APK_RELEASE_SIGNING_KEY": "SENTINEL-APK-KEY-7f3a", "DOCKERHUB_USERNAME": "sentinel-user-91", "DOCKERHUB_TOKEN": "SENTINEL-HUB-TOKEN-5c2e", "GH_TOKEN": "SENTINEL-GH-TOKEN-b814"}
passn, failn = 0, 0
def ok(l): global passn; passn += 1; print("ok   " + l)
def bad(l): global failn; failn += 1; print("FAIL " + l)
LAST = [0]   # the exit code of the last script run: a missing script (127) fails every check that follows, so nothing passes vacuously
def check(c, l, why=""):
    if LAST[0] == 127: bad(l + " -> the script does not exist")
    else: ok(l) if c else bad(l + (" -> " + why if why else ""))
FAKES = {
 "crane": r'''#!/usr/bin/env bash
echo "crane $*" >> "$LOG"
case "$1" in
  auth) cat > /dev/null; mkdir -p "$REG/.login"; : > "$REG/.login/$3" ;;
  push) host=${3%%/*}; [ -e "$REG/.login/$host" ] || { echo "UNAUTHORIZED $host" >&2; exit 1; }
        d=$(cat "${2%.tar}.digest"); p="$REG/${3/://}"; mkdir -p "$(dirname "$p")"
        [ "${REG_CORRUPT:-}" = "$host" ] && d="sha256:$(printf 'f%.0s' $(seq 64))"; echo "$d" > "$p" ;;
  digest) p="$REG/${2/://}"; [ -e "$p" ] && cat "$p" || { echo "NAME_UNKNOWN $2" >&2; exit 1; } ;;
  *) echo "crane: unexpected $1" >&2; exit 2 ;;
esac''',
 "cosign": r'''#!/usr/bin/env bash
echo "cosign $*" >> "$LOG"
[ -z "${COSIGN_FAIL:-}" ] || { echo "cosign failed" >&2; exit 1; }
if [ "$1" = sign-blob ]; then
  while [ $# -gt 0 ]; do [ "$1" = --bundle ] && b=$2; shift; done
  if [ -n "${COSIGN_NOREKOR:-}" ] && [ "$(basename "$b")" = "${COSIGN_NOREKOR}" ]; then echo '{"verificationMaterial":{"tlogEntries":[]}}' > "$b"
  else echo '{"verificationMaterial":{"tlogEntries":[{"logIndex":"1"}]}}' > "$b"; fi
fi''',
 "gh": r'''#!/usr/bin/env bash
echo "gh $*" >> "$LOG"''',
 "melange": r'''#!/usr/bin/env bash
echo "melange $*" >> "$LOG"
[ -z "${MELANGE_FAIL:-}" ] || exit 1
[ "$1" = sign ] || exit 2
shift; [ "$1" = --key ] && key=$2 && shift 2
echo "mode=$(stat -c %a "$key" 2>/dev/null || stat -f %Lp "$key") content=$(cat "$key")" >> "$LOG.key"; echo "$key" > "$LOG.keypath"
for a in "$@"; do [ -n "${MELANGE_BREAK:-}" ] || sed -i.bak 's/^signer: .*/signer: release.rsa.pub/' "$a"; rm -f "$a.bak"; done''',
 "bin/apk-tool.py": r'''import hashlib, sys
cmd, f = sys.argv[1], sys.argv[2]
lines = open(f).read().split("\n")
if cmd == "digest": print("sha256:" + hashlib.sha256(lines[2].split(": ", 1)[1].encode()).hexdigest())
elif cmd == "signer": print(lines[1].split(": ", 1)[1])
else: sys.exit(2)''',
 "bin/vendor-provenance.py": r'''import json, os, sys
open(os.environ["LOG"], "a").write("vendor-provenance %s\n" % " ".join(sys.argv[1:]))
if os.environ.get("EVIDENCE_FAIL"): sys.exit(1)
out = sys.argv[sys.argv.index("--out") + 1]; os.makedirs(out, exist_ok=True)
json.dump({"mode": "vendor"}, open(os.path.join(out, "vendor-evidence.json"), "w"))''',
 "bin/chain-verify.py": r'''import os, sys
a = sys.argv[1:]
open(os.environ["LOG"], "a").write("chain-verify %s\n" % " ".join(a))
if a[0] == "policy":
    if os.environ.get("POLICY_FAIL"): print("refused at release: policy", file=sys.stderr); sys.exit(1)
    open(a[a.index("--out") + 1], "w").write("{}"); sys.exit(0)
prev = a[a.index("--previous") + 1]; rec = a[a.index("--record") + 1]
if not os.path.exists(rec): print("refused at %s: missing record %s" % (prev, rec), file=sys.stderr); sys.exit(1)
if os.environ.get("FAIL_STAGE") == prev: print("refused at %s: the record is invalid" % prev, file=sys.stderr); sys.exit(1)''',
}
DIG = {"image-production": "sha256:" + "a" * 64, "image-fips": "sha256:" + "b" * 64}
def apk_data(arch): return "data-" + arch
def tree(extra_env=None):
    t = tempfile.mkdtemp(); fb = os.path.join(t, ".fakebin"); os.makedirs(fb); os.makedirs(os.path.join(t, "bin")); os.makedirs(os.path.join(t, "reg"))
    for n, body in FAKES.items():
        if n.startswith("bin/"):
            open(os.path.join(t, n), "w").write(body)
        else:
            open(os.path.join(fb, n), "w").write(body); os.chmod(os.path.join(fb, n), 0o755)
    for s in ("release-verify", "release-apks", "release-publish", "release-sign", "release-assets"):
        src = os.path.join(BIN, s + ".sh")
        if os.path.exists(src): shutil.copy(src, os.path.join(t, "bin", s + ".sh"))
    digs = dict(DIG)
    for arch in ("amd64", "arm64"):
        d = os.path.join(t, "apks", arch); os.makedirs(d)
        open(os.path.join(d, "fscache-0.3.0-r0.apk"), "w").write("apk\nsigner: assembly.rsa.pub\ndata: %s\n" % apk_data(arch))
        digs["apk-" + arch] = "sha256:" + hashlib.sha256(apk_data(arch).encode()).hexdigest()
    for v in ("production", "fips"):
        os.makedirs(os.path.join(t, "images"), exist_ok=True)
        open(os.path.join(t, "images", v + ".tar"), "w").write("tar-" + v)
        open(os.path.join(t, "images", v + ".digest"), "w").write(DIG["image-" + v] + "\n")
    for d in ("witness-build", "witness-rebuild", "witness-check", "provenance", "sboms", "locks", "dist"):
        os.makedirs(os.path.join(t, d), exist_ok=True)
    json.dump(digs, open(os.path.join(t, "witness-build/digests.json"), "w"))
    for f in ("witness-build/build-collection.json", "witness-rebuild/rebuild-collection.json", "witness-check/check-collection.json", "provenance/provenance.json",
              "sboms/production.spdx.json", "sboms/fips.spdx.json", "locks/production.full.lock.json", "locks/fips.full.lock.json", "dist/checksums.txt"):
        open(os.path.join(t, f), "w").write("{}")
    open(os.path.join(t, "dependency-provenance.json"), "w").write("{}"); open(os.path.join(t, "policy.json"), "w").write("{}")
    return t
def run(t, script, env=None, creds=None, tag="v0.3.0"):
    path = os.path.join(t, "bin", script + ".sh")
    if not os.path.exists(path): LAST[0] = 127; return 127, "", "the script " + script + ".sh does not exist"
    LAST[0] = 0
    e = {"PATH": os.path.join(t, ".fakebin") + ":" + os.environ["PATH"], "HOME": t, "LOG": os.path.join(t, "calls.log"), "REG": os.path.join(t, "reg"), "GITHUB_REF_NAME": tag}
    e.update({k: SENT[k] for k in (creds or [])}); e.update(env or {})
    r = subprocess.run(["bash", path], cwd=t, env=e, capture_output=True, text=True)
    LAST[0] = r.returncode if r.returncode == 127 else 0
    return r.returncode, r.stdout, r.stderr
def log(t):
    p = os.path.join(t, "calls.log"); return open(p).read().split("\n") if os.path.exists(p) else []
def tree_text(t):
    out = ""
    for dp, dn, fn in os.walk(t):
        for f in fn:
            if f in ("calls.log.key", "calls.log.keypath"): continue   # the fake signer's own capture of the key file it was handed
            try: out += open(os.path.join(dp, f), errors="replace").read()
            except Exception: pass
    return out
def first(s): return s.strip().split("\n")[0] if s.strip() else ""
# ---- AC4/AC5: release-verify.sh ------------------------------------------------------------------------------------------------------
STAGES = ["build", "sign", "rebuild", "check"]
t = tree(); rc, so, se = run(t, "release-verify")
calls = [l for l in log(t) if l.startswith("chain-verify")]
check(rc == 0, "AC5 a good v0.3.0 passes", se)
check([c.split("--previous ")[1].split()[0] for c in calls if "--previous" in c] == STAGES and calls and calls[0].startswith("chain-verify policy make"), "AC4 the policy is made first, then build, sign, rebuild, check are verified in that order", str(calls))
check(all("--digests witness-build/digests.json" in c for c in calls if "--previous" in c) and any("--tag v0.3.0" in c for c in calls if "policy" in c), "AC4 every record is checked against the same digest list and the policy is made for the tag")
t = tree(); rc, so, se = run(t, "release-verify", tag="v0.3.0-rc.1"); check(rc == 0, "AC5 a release candidate v0.3.0-rc.1 passes exactly like a final", se)
for tag in ("v0.3", "v0.3.0-rc", "v0.3.0-rc.x", "v0.3.0-rc.1.2", "v0.3.0-beta.1", "v0.3.0.1", "0.3.0", "main", "refs/heads/x", "v0.3.0-rc.1\n", ""):
    t = tree(); rc, so, se = run(t, "release-verify", tag=tag)
    check(rc != 0 and first(se).startswith("refused at tag") and not [l for l in log(t) if l.startswith("chain-verify")], "AC5 the tag %r is refused first, naming the tag, before any verification" % tag, "rc=%s %s" % (rc, first(se)))
for s in STAGES:
    t = tree(); rc, so, se = run(t, "release-verify", env={"FAIL_STAGE": s})
    after = STAGES[STAGES.index(s) + 1:]
    seen = " ".join(l for l in log(t) if l.startswith("chain-verify"))
    check(rc != 0 and first(se).startswith("refused at " + s + ":") and not any("--previous " + a in seen for a in after), "AC5 an invalid %s record stops release at %s and no later record is checked" % (s, s), "rc=%s %s" % (rc, first(se)))
    t = tree(); rec = {"build": "witness-build/build-collection.json", "sign": "provenance/provenance.json", "rebuild": "witness-rebuild/rebuild-collection.json", "check": "witness-check/check-collection.json"}[s]
    os.remove(os.path.join(t, rec)); rc, so, se = run(t, "release-verify")
    check(rc != 0 and "refused at " + s in first(se) and "missing" in first(se), "AC5 a missing %s record stops release, naming it" % s, "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-verify", env={"POLICY_FAIL": "1"}); check(rc != 0 and not [l for l in log(t) if "--previous" in l], "AC5 a policy that cannot be made stops release before any record is checked")
t = tree(); rc, so, se = run(t, "release-verify", creds=list(SENT))
check(rc == 0 and not [l for l in log(t) if l.split(" ")[0] in ("crane", "cosign", "gh", "melange")], "AC5 the verify script calls no registry, signing or release tool")
# ---- AC6: release-apks.sh --------------------------------------------------------------------------------------------------------------
KEY = ["APK_RELEASE_SIGNING_KEY"]
t = tree(); rc, so, se = run(t, "release-apks", creds=KEY)
signed = [subprocess.run(["python3", os.path.join(t, "bin/apk-tool.py"), "signer", p], capture_output=True, text=True).stdout.strip()
          for p in (os.path.join(t, "release-apks", a, "fscache-0.3.0-r0.apk") for a in ("amd64", "arm64")) if os.path.exists(p)]
check(rc == 0 and signed == ["release.rsa.pub", "release.rsa.pub"], "AC6 both apks come out signed by the release key", "rc=%s %s %s" % (rc, signed, first(se)))
kp = open(os.path.join(t, "calls.log.keypath")).read().strip() if os.path.exists(os.path.join(t, "calls.log.keypath")) else ""
kl = open(os.path.join(t, "calls.log.key")).read() if os.path.exists(os.path.join(t, "calls.log.key")) else ""
check("mode=600" in kl and ("content=" + SENT["APK_RELEASE_SIGNING_KEY"]) in kl, "AC6 the key was handed to the signer as a private (0600) file holding the key", kl)
check(kp != "" and not os.path.exists(kp), "AC6 the key file is removed after the run")
check(SENT["APK_RELEASE_SIGNING_KEY"] not in "\n".join(log(t)) + so + se, "AC6 the key is never on a command line, in the output or in a log")
check(not any(SENT["APK_RELEASE_SIGNING_KEY"] in open(os.path.join(dp, f), errors="replace").read() for dp, dn, fn in os.walk(os.path.join(t, "release-apks")) for f in fn) and not os.path.exists(os.path.join(t, "release-evidence")), "AC6 the key is in no output file")
for label, env in (("missing", {}), ("empty", {"APK_RELEASE_SIGNING_KEY": ""})):
    t = tree(); rc, so, se = run(t, "release-apks", env=env)
    check(rc == 2 and "APK_RELEASE_SIGNING_KEY" in se and not [l for l in log(t) if l.startswith("melange")], "AC6 a %s key is refused at once with exit 2, naming the variable, before any signing" % label, "rc=%s %s" % (rc, first(se)))
t = tree(); d = json.load(open(os.path.join(t, "witness-build/digests.json"))); d["apk-arm64"] = "sha256:" + "0" * 64; json.dump(d, open(os.path.join(t, "witness-build/digests.json"), "w"))
rc, so, se = run(t, "release-apks", creds=KEY)
check(rc != 0 and "differ" in se and not [l for l in log(t) if l.startswith("melange")] and not os.path.exists(os.path.join(t, "release-apks")), "AC6 an apk whose contents are not the attested ones is refused before anything is signed, naming it", "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-apks", creds=KEY, env={"MELANGE_BREAK": "1"})
check(rc != 0 and "release" in se.lower() and "signed" in se.lower(), "AC6 an apk the signer left signed by the assembly key is refused ('not signed by the release key')", "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-apks", creds=KEY, env={"MELANGE_FAIL": "1"}); kp = open(os.path.join(t, "calls.log.keypath")).read().strip() if os.path.exists(os.path.join(t, "calls.log.keypath")) else ""
check(rc != 0, "AC6 a failing signer fails the script"); check(not os.path.exists(os.path.join(t, "calls.log.keypath")) or not os.path.exists(kp), "AC6 the key file is removed on a failing run too")
t = tree(); shutil.rmtree(os.path.join(t, "apks")); os.makedirs(os.path.join(t, "apks")); rc, so, se = run(t, "release-apks", creds=KEY)
check(rc != 0 and "no apk" in se.lower(), "AC6 no apks to sign is an error, not a success")
# ---- AC7: release-publish.sh -------------------------------------------------------------------------------------------------------------
REG = ["DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "GH_TOKEN"]
def pushes(t): return [l.split(" ") for l in log(t) if l.startswith("crane push")]
t = tree(); rc, so, se = run(t, "release-publish", creds=REG); P = pushes(t)
check(rc == 0, "AC7 a good v0.3.0 publishes", se)
need = {(h, tag) for h in ("ghcr.io", "docker.io") for tag in ("0.3.0", "0.3.0-fips")}
got = {(p[3].split("/")[0], p[3].split(":")[1]) for p in P}
check(need <= got, "AC7 both variants are pushed to ghcr.io and the Docker Hub mirror with their version tags", str(sorted(got)))
check(bool(P) and all(p[2].startswith("images/") for p in P) and not [l for l in log(t) if re.match(r"crane (copy|pull)", l)], "AC7 the bytes pushed are the ones Build handed over (images/<variant>.tar), nothing is pulled or rebuilt")
check(bool(P) and P[0][3].startswith("ghcr.io/"), "AC7 ghcr.io comes first")
check(bool(P) and all(os.path.exists(os.path.join(t, "reg", p[3].replace(":", "/", 1))) and open(os.path.join(t, "reg", p[3].replace(":", "/", 1))).read().strip() == DIG["image-production" if "fips" not in p[3] else "image-fips"] for p in P), "AC7 the registry shows the attested index digest for every tag pushed")
check(any(l.startswith("crane digest") for l in log(t)), "AC7 each registry is read back")
check(SENT["DOCKERHUB_TOKEN"] not in "\n".join(log(t)) + so + se and SENT["GH_TOKEN"] not in "\n".join(log(t)) + so + se, "AC7 the credentials go in by standard input, never on a command line or in output")
t = tree(); rc, so, se = run(t, "release-publish", creds=REG, tag="v0.3.0-rc.1"); P = pushes(t)
check(rc == 0 and {(p[3].split("/")[0], p[3].split(":")[1]) for p in P} == {(h, v) for h in ("ghcr.io", "docker.io") for v in ("0.3.0-rc.1", "0.3.0-rc.1-fips")}, "AC7 a release candidate gets its exact tags only, no floating tag", str(sorted({p[3] for p in P})))
t = tree(); rc, so, se = run(t, "release-publish", creds=REG, env={"REG_CORRUPT": "docker.io"})
check(rc != 0 and "differ" in se and DIG["image-production"] in se and "docker.io" in se, "AC7 a registry that shows another digest blocks release, naming the image and both digests", "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-publish", creds=REG, env={"REG_CORRUPT": "ghcr.io"}); h = [p[3].split("/")[0] for p in pushes(t)]
check(rc != 0 and "docker.io" not in h, "AC7 a mismatch at ghcr.io stops everything: nothing is pushed to the mirror afterwards", str(h))
t = tree(); os.makedirs(os.path.join(t, "reg/ghcr.io/fosterstack/cache"), exist_ok=True); open(os.path.join(t, "reg/ghcr.io/fosterstack/cache/0.3.0"), "w").write("sha256:" + "9" * 64)
rc, so, se = run(t, "release-publish", creds=REG)
check(rc != 0 and "already" in se.lower() and not pushes(t), "AC7 a target tag that already shows another digest is refused before anything is pushed")
t = tree(); os.makedirs(os.path.join(t, "reg/ghcr.io/fosterstack/cache"), exist_ok=True); open(os.path.join(t, "reg/ghcr.io/fosterstack/cache/0.3.0"), "w").write(DIG["image-production"])
rc, so, se = run(t, "release-publish", creds=REG); check(rc == 0, "AC7 a rerun on a tag that already shows the attested digest passes", se)
t = tree(); open(os.path.join(t, "images/fips.digest"), "w").write("sha256:" + "c" * 64 + "\n"); rc, so, se = run(t, "release-publish", creds=REG)
check(rc != 0 and not pushes(t), "AC7 an image whose own digest is not the attested one is refused before any push")
for miss in ("DOCKERHUB_TOKEN", "DOCKERHUB_USERNAME", "GH_TOKEN"):
    t = tree(); rc, so, se = run(t, "release-publish", creds=[c for c in REG if c != miss])
    check(rc == 2 and miss in se and not pushes(t), "AC7 a missing %s is refused with exit 2, naming it, before any push" % miss, "rc=%s %s" % (rc, first(se)))
# ---- AC8: release-sign.sh -------------------------------------------------------------------------------------------------------------------
def signs(t): return [l for l in log(t) if l.startswith("cosign")]
t = tree(); os.makedirs(os.path.join(t, "reg"), exist_ok=True); rc, so, se = run(t, "release-sign", creds=REG); L = log(t)
check(rc == 0, "AC8 a good run signs", se)
check(L and L[0].startswith("vendor-provenance evidence --out"), "AC8 the dependency evidence is produced first (bin/vendor-provenance.py evidence --out DIR)", str(L[:1]))
imgs = [l for l in L if l.startswith("cosign sign ")]
check({(re.search(r"(ghcr\.io|docker\.io)/fosterstack/cache@(sha256:\w+)", l).groups()) for l in imgs} == {(h, d) for h in ("ghcr.io", "docker.io") for d in DIG.values()}, "AC8 each published image digest is signed in BOTH registries", str(imgs))
blobs = " ".join(l for l in L if l.startswith("cosign sign-blob"))
for f in ("production.spdx.json", "fips.spdx.json", "production.full.lock.json", "fips.full.lock.json", "vendor-evidence.json", "dependency-provenance.json", "policy.json"):
    check(f in blobs, "AC8 %s is signed with a bundle" % f)
check(all("--bundle" in l for l in L if l.startswith("cosign sign-blob")), "AC8 every signed file gets a bundle")
check(not re.search(r"tlog-upload=false|insecure-ignore-tlog|--no-tlog", "\n".join(L)), "AC8 the transparency log is never turned off")
check("witness-build" not in blobs and "witness-rebuild" not in blobs and "witness-check" not in blobs, "AC8 the Witness records are not signed again (they are extra evidence)")
for f in ("policy.json", "vendor-evidence.json", "production.spdx.json"):
    name = {"policy.json": "release-policy.bundle"}.get(f, f + ".bundle")
    t = tree(); rc, so, se = run(t, "release-sign", creds=REG, env={"COSIGN_NOREKOR": name})
    check(rc != 0 and "rekor" in se.lower() and name.split(".bundle")[0].split(".")[0] in se, "AC8 a bundle with no Rekor entry (%s) fails the script, naming the file" % name, "rc=%s %s" % (rc, first(se)))
t = tree(); rc, so, se = run(t, "release-sign", creds=REG, env={"EVIDENCE_FAIL": "1"}); check(rc != 0 and not signs(t), "AC8 failing evidence stops everything before anything is signed")
t = tree(); rc, so, se = run(t, "release-sign", creds=REG, env={"COSIGN_FAIL": "1"}); check(rc != 0 and len(signs(t)) == 1, "AC8 a failing signature stops at the first one")
t = tree(); rc, so, se = run(t, "release-sign", creds=REG); check(rc == 0 and os.path.exists(os.path.join(t, "release-evidence")), "AC8 the bundles and the evidence land in release-evidence/")
# ---- AC9: release-assets.sh ----------------------------------------------------------------------------------------------------------------------
t = tree(); os.makedirs(os.path.join(t, "release-apks/amd64")); os.makedirs(os.path.join(t, "release-evidence")); open(os.path.join(t, "release-apks/amd64/a.apk"), "w").write("x"); open(os.path.join(t, "release-evidence/e.json"), "w").write("{}")
rc, so, se = run(t, "release-assets", creds=["GH_TOKEN"]); L = " ".join(log(t))
check(rc == 0, "AC9 a good run attaches the assets", se)
for what in ("release upload v0.3.0", "release-apks", "dist", "sboms", "locks", "release-evidence", "witness-build", "witness-rebuild", "witness-check"):
    check(what in L, "AC9 %s is attached to the release" % what)
check(not [l for l in log(t) if re.search(r"release create(?!.*--verify-tag)|git |tag ", l)], "AC9 no release is created without --verify-tag and no tag is made")
check(SENT["GH_TOKEN"] not in L + so + se, "AC9 the token is never on a command line or in output")
t = tree(); rc, so, se = run(t, "release-assets"); check(rc == 2 and "GH_TOKEN" in se and not log(t), "AC9 a missing GH_TOKEN is refused with exit 2, naming it")
# ---- AC10: no script prints a credential, anywhere ---------------------------------------------------------------------------------------------
for s, creds in (("release-verify", []), ("release-apks", KEY), ("release-publish", REG), ("release-sign", REG), ("release-assets", ["GH_TOKEN"])):
    t = tree(); rc, so, se = run(t, s, creds=creds)
    blob = so + se + tree_text(t)
    leaked = [k for k, v in SENT.items() if k != "DOCKERHUB_USERNAME" and v in blob]   # the user name is not a secret
    check(rc == 0 and not leaked, "AC10 %s with sentinels in the environment: none in any output or file afterwards" % s, "rc=%s leaked=%s %s" % (rc, leaked, first(se)))
print("pass=%d fail=%d" % (passn, failn))
EXPECT = int(os.environ.get("EXPECT_CASES", "90"))
if EXPECT and passn + failn != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (passn + failn, EXPECT)); sys.exit(1)
sys.exit(1 if failn else 0)
PY
