#!/usr/bin/env bash
# proves: REQ-REL-009-AC6, REQ-REL-009-AC13
# Which signer source admission accepts for a release tag (automatic patch releases rule 3; advisor 0057): the owner's
# SSH signature (allowed-signers) on any tag; the release.yml-on-main gitsign identity on a PATCH tag only (vX.Y.Z,
# Z >= 1, the previous patch vX.Y.(Z-1) already released); an unsigned tag, any other signature format, an ambiguous
# tag object, or the CI identity on a minor, major or rc tag is refused. The route only picks the verifier; the
# verifier (git verify-tag against allowed-signers, or gitsign verify-tag with the identity pinned) still has to pass.
# The second half reads stage-admission.yml: the policy comes from protected main, and gitsign verify-tag pins the
# exact identity, issuer, repository, ref and the tagged commit.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/.." && pwd)
python3 - "$here/admission-tag-signer.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ts", sys.argv[1]); T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
HEAD = "object 0123\ntype commit\ntag v0.2.2\ntagger x <x> 1 +0000\n\nautomatic patch release v0.2.2\n"
SSH = HEAD + "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n"
X509 = HEAD + "-----BEGIN SIGNED MESSAGE-----\nMIIF\n-----END SIGNED MESSAGE-----\n"
PGP = HEAD + "-----BEGIN PGP SIGNATURE-----\niQ\n-----END PGP SIGNATURE-----\n"
for obj, want in [(SSH, "ssh"), (X509, "x509"), (PGP, "pgp"), (HEAD, "none"),
                  (HEAD + "-----BEGIN SSH SIGNATURE-----\nA\n-----END SSH SIGNATURE-----\n-----BEGIN SIGNED MESSAGE-----\nB\n-----END SIGNED MESSAGE-----\n", "ambiguous"),
                  (HEAD.replace("automatic patch release v0.2.2", "notes quoting -----BEGIN SIGNED MESSAGE----- inline") , "none"),
                  # Codex #163 r1 B03: a PEM-style block that is not a signature (release notes quoting a key or a
                  # certificate example) is message text; the owner's signature after it still routes to ssh
                  (HEAD + "-----BEGIN EXAMPLE-----\nmessage text\n-----END EXAMPLE-----\n" + SSH[len(HEAD):], "ssh"),
                  (HEAD + "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n" + X509[len(HEAD):], "x509"),
                  # a second SIGNATURE-labelled block anywhere is still ambiguous (git would read the first as the signature)
                  (HEAD + "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\nmore\n" + SSH[len(HEAD):], "ambiguous"),
                  (HEAD + "-----BEGIN EXAMPLE-----\nmessage text\n-----END EXAMPLE-----\n", "none")]:
    got = T.kind(obj)
    check("kind -> %s" % want, got == want, got)
REL = ["v0.1.0", "v0.2.0", "v0.2.1"]
for tag, obj, tags, want, why in [
    ("v0.2.2", X509, REL, "gitsign", "the CI identity on the next patch"),
    ("v0.3.0", X509, REL, "refuse", "the CI identity on a minor tag"),
    ("v1.0.0", X509, REL, "refuse", "the CI identity on a major tag"),
    ("v0.2.3", X509, REL, "refuse", "the CI identity skipping a patch (v0.2.2 not released)"),
    ("v0.2.2-rc.1", X509, REL, "refuse", "the CI identity on an rc"),
    ("v0.4.1", X509, REL, "refuse", "the CI identity on a line with no owner release"),
    ("v0.2.2", SSH, REL, "ssh", "the owner on a patch"),
    ("v0.3.0", SSH, REL, "ssh", "the owner on a minor"),
    ("v0.2.2", HEAD, REL, "refuse", "an unsigned tag (the App pushed it unsigned)"),
    ("v0.2.2", PGP, REL, "refuse", "a PGP signature"),
    ("v0.2.2", SSH + "-----BEGIN SIGNED MESSAGE-----\nB\n-----END SIGNED MESSAGE-----\n", REL, "refuse", "two signatures"),
    ("v0.2.1", X509, REL, "refuse", "the CI identity re-signing an existing tag"),
]:
    got = T.route(tag, obj, tags)
    check("route: %s -> %s" % (why, want), got[0] == want, got)
import hashlib, json, os, tempfile, io, contextlib
d = tempfile.mkdtemp(); o = os.path.join(d, "obj"); open(o, "w").write(X509); t = os.path.join(d, "tags"); open(t, "w").write("\n".join(REL) + "\n")
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = T.main(["route", "--tag", "v0.2.2", "--tag-object", o, "--tags", t])
check("CLI prints the route first", rc == 0 and buf.getvalue().split()[0] == "gitsign", buf.getvalue())

# --- REQ-REL-009-AC13 (owner RATIFIED, Oct 2): which approved ACs baseline a CI patch uses
REQ = b"requirements: [the approved ACs]\n"
H = hashlib.sha256(REQ).hexdigest()
ACS = [{"id": "REQ-X-001-AC1", "method": "acceptance", "phase": "candidate"}]
def bl(v, approved=True, sha=H, on="2026-09-29", acs=ACS, fixed="a" * 40):
    return {"version": v, "approved": approved, "approved_on": on, "requirements_sha256": sha,
            "release_blocking_acs": acs, "fixed_at": fixed}
for tag, bls, req, want, why in [
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], REQ, "v0.2.1", "v0.2.2 uses v0.2.1's baseline"),
    ("v0.2.3", [bl("v0.2.0"), bl("v0.2.1")], REQ, "v0.2.1", "the latest approved of its line, even two patches back"),
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], REQ + b"x", None, "requirements changed since the baseline: no cut"),
    ("v0.2.2", [bl("v0.2.0", sha=H), bl("v0.2.1", sha="0" * 64)], REQ, None, "the LATEST baseline must match; never an older one"),
    # Codex #163 r1 B02: the latest OWNER-APPROVED baseline (an unapproved newer one is skipped, never a blocker)
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", approved=False)], REQ, "v0.2.0", "an unapproved newer baseline is skipped: the latest approved is used"),
    ("v0.2.2", [bl("v0.2.1", approved=False)], REQ, None, "no approved baseline on the line: no cut, it waits for the owner"),
    ("v0.2.2", [bl("v0.2.0", sha="0" * 64), bl("v0.2.1", approved="true")], REQ, None, "approved must be boolean true"),
    ("v0.2.2", [bl("v0.2.0", sha="0" * 64), bl("v0.2.1", on="soon")], REQ, None, "approved_on must be a real date"),
    ("v0.2.2", [bl("v0.1.9"), bl("v0.3.0")], REQ, None, "no baseline on its own X.Y line"),
    ("v0.2.2", [bl("v0.2.1"), bl("v0.2.4")], REQ, "v0.2.1", "a baseline above the tag is never used"),
    # Codex #163 pin pass B03: the content admission requires is checked here too, and a malformed latest approved
    # baseline is no patch — never a fallback to an older one
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", acs=[])], REQ, None, "an empty release_blocking_acs: no patch, no fallback"),
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", acs=None)], REQ, None, "no release_blocking_acs list"),
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", fixed="main")], REQ, None, "fixed_at is not a full commit id"),
    ("v0.3.0", [bl("v0.2.1")], REQ, None, "a minor is not a CI patch"),
    ("v0.2.2", [dict(bl("v0.2.1"), version="v0.2.0")], REQ, None, "a file whose version is not its name is ignored"),
]:
    got = T.baseline(tag, {b["version"] if "name" not in b else b["name"]: b for b in bls} if why != "a file whose version is not its name is ignored" else {"v0.2.1": bls[0]}, req)
    check("baseline: %s -> %s" % (why, want), got[0] == want, got)
rd = os.path.join(d, "releases"); os.makedirs(rd)
for v in ("v0.2.0", "v0.2.1"):
    open(os.path.join(rd, v + ".yaml"), "w").write("version: %s\napproved: true\napproved_on: 2026-09-29\nrequirements_sha256: %s\n"
        "fixed_at: %s\nrelease_blocking_acs:\n  - {id: REQ-X-001-AC1, method: acceptance, phase: candidate}\n" % (v, H, "a" * 40))
open(os.path.join(rd, "README.md"), "w").write("not a baseline\n")
rq = os.path.join(d, "req.yaml"); open(rq, "wb").write(REQ)
for req_bytes, want in ((REQ, "use v0.2.1"), (REQ + b"x", "no")):
    open(rq, "wb").write(req_bytes)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = T.main(["baseline", "--tag", "v0.2.2", "--owner-baselines", rd, "--requirements", rq])
    check("baseline CLI -> %s" % want, rc == 0 and buf.getvalue().startswith(want + (" " if want == "no" else "")), buf.getvalue())
# --- Codex #163 r1 B01: a baseline counts only from an owner-signed release tag, read from that tag's own tree
import subprocess, tempfile
def run(*a, cwd=None, inp=None):
    return subprocess.run(list(a), cwd=cwd, input=inp, capture_output=True, text=True,
                          env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t",
                                   GIT_COMMITTER_EMAIL="t@x", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null"))
g = tempfile.mkdtemp(); keys = tempfile.mkdtemp()
for k in ("owner", "other"):
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", k, "-f", os.path.join(keys, k))
allowed = os.path.join(keys, "allowed_signers")
open(allowed, "w").write("owner@x " + open(os.path.join(keys, "owner.pub")).read())
run("git", "init", "-q", "-b", "main", cwd=g)
def commit_baselines(vs, approved=True, req=REQ):
    os.makedirs(os.path.join(g, "requirements", "releases"), exist_ok=True)
    open(os.path.join(g, "requirements", "requirements.yaml"), "wb").write(req)
    for v in vs:
        open(os.path.join(g, "requirements", "releases", v + ".yaml"), "w").write(
            "version: %s\napproved: %s\napproved_on: 2026-09-29\nrequirements_sha256: %s\nfixed_at: %s\n"
            "release_blocking_acs:\n  - {id: REQ-X-001-AC1, method: acceptance, phase: candidate}\n"
            % (v, "true" if approved else "false", hashlib.sha256(req).hexdigest(), "a" * 40))
    run("git", "add", "-A", cwd=g); run("git", "commit", "-qm", "c", cwd=g)
def tag(v, key=None):
    if key:
        run("git", "-c", "gpg.format=ssh", "-c", "user.signingkey=" + os.path.join(keys, key), "tag", "-s", "-m", v, v, cwd=g)
    else:
        run("git", "tag", "-a", "-m", v, v, cwd=g)
commit_baselines(["v0.2.0"]); tag("v0.2.0", "owner")
commit_baselines(["v0.2.0", "v0.2.1"]); tag("v0.2.1", "other")            # signed by a key not in allowed_signers
commit_baselines(["v0.2.0", "v0.2.1", "v0.2.3"]); tag("v0.2.3")           # annotated, unsigned
commit_baselines(["v0.2.0", "v0.2.1", "v0.2.3", "v0.2.4"]); run("git", "tag", "v0.2.4", cwd=g)   # lightweight
commit_baselines(["v0.2.0", "v0.2.1", "v0.2.3", "v0.2.4", "v0.2.5"])     # the tagged commit's own, self-approved
out = os.path.join(g, "owner-baselines")
rc = T.main(["owner-baselines", "--tag", "v0.2.5", "--repo", g, "--allowed-signers", allowed, "--out", out])
got = sorted(os.listdir(out)) if os.path.isdir(out) else None
check("B01 only owner-SSH-signed tags of the line, below the tag, supply a baseline (v0.2.0)", rc == 0 and got == ["v0.2.0.yaml"], got)
check("B01 the baseline is read from the owner tag's own tree", open(os.path.join(out, "v0.2.0.yaml")).read().startswith("version: v0.2.0"))
v, why = T.baseline("v0.2.5", T._load_baselines(out), open(os.path.join(g, "requirements", "requirements.yaml"), "rb").read())
check("B01 the tagged commit's self-approved baselines are never used: v0.2.5 -> v0.2.0", v == "v0.2.0", (v, why))
commit_baselines(["v0.2.0"], req=REQ + b"edited")
rc = T.main(["owner-baselines", "--tag", "v0.2.6", "--repo", g, "--allowed-signers", allowed, "--out", out + "2"])
v, why = T.baseline("v0.2.6", T._load_baselines(out + "2"), open(os.path.join(g, "requirements", "requirements.yaml"), "rb").read())
check("B01 requirements changed since the owner's baseline: no patch", v is None and "changed" in why, (v, why))
try:
    T.main(["baseline", "--tag", "v0.2.2", "--releases-dir", rd, "--requirements", rq]); got = "accepted"
except SystemExit:
    got = "refused"
check("B01 the old --releases-dir (a directory of any origin) is gone", got == "refused", got)
print("admission-tag-signer: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY

# --- stage-admission.yml wiring
pass=0; failn=0; work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
judge() { python3 - "$1" <<'PY'
import re, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
steps = d["jobs"]["admit"]["steps"]
bad = []
pol = next((s for s in steps if "fetch policy from protected main" in s.get("name", "")), {})
for f in ("bin/admission-tag-signer.py", "bin/install-scanner.sh"):
    if "git show origin/main:%s" % f not in pol.get("run", ""):
        bad.append("%s is not read from protected main" % f)
sig = [s for s in steps if s.get("id") == "tagsig"]
run = sig[0].get("run", "") if sig else ""
if "/tmp/policy/admission-tag-signer.py" not in run or "/tmp/policy/install-scanner.sh gitsign" not in run:
    bad.append("the route or the gitsign install does not come from the policy copy")
if re.search(r"(^|[\s;(])(\./)?bin/", run):
    bad.append("the signature step runs a script from the tagged commit")
want = ["--certificate-identity https://github.com/fosterstack/cache/.github/workflows/release.yml@refs/heads/main",
        "--certificate-oidc-issuer https://token.actions.githubusercontent.com",
        "--certificate-github-workflow-repository fosterstack/cache",
        "--certificate-github-workflow-ref refs/heads/main",
        '--certificate-github-workflow-sha "${GITHUB_SHA}"']
flat = re.sub(r"\s*\\\n\s*", " ", run)
for w in want:
    if w not in flat:
        bad.append("gitsign verify-tag does not pin: %s" % w)
if "regexp" in run or "insecure" in run:
    bad.append("a loose gitsign flag appears")
if "gitsign verify-tag" not in run or 'git verify-tag "${GITHUB_REF_NAME}"' not in run:
    bad.append("one of the two verifiers is missing")
if not re.search(r'case "\$\{route\}" in\s+ssh\)', run) or not re.search(r"gitsign\)", run) or not re.search(r"\*\)\s*echo \"::error::", run):
    bad.append("the route does not pick exactly one verifier and refuse otherwise")
base = [s for s in steps if "baseline" in s.get("name", "") and "APPROVED" in s.get("name", "")]
brun = base[0].get("run", "") if base else ""
# Codex #163 r1 B01: the keyless path's baselines come only from owner-signed tags (verified against main's allowed
# signers by main's copy of the script), and the tagged commit's copy of the chosen baseline must equal the owner's
if "/tmp/policy/admission-tag-signer.py owner-baselines" not in brun or "--allowed-signers /tmp/policy/allowed_signers" not in brun \
        or 'git ls-tree --name-only "${GITHUB_SHA}" requirements/releases/' in brun or "--owner-baselines" not in brun:
    bad.append("the keyless path's baselines do not come only from owner-signed tags")
if 'cmp -s' not in brun or 'git show "${BASE}:${f}"' not in brun:
    bad.append("the tagged commit's copy of the chosen baseline is not checked against the owner tag's")
if '/tmp/policy/admission-tag-signer.py baseline' not in brun or "steps.tagsig.outputs.method" not in str(base[0].get("env", {})) if base else True:
    bad.append("the keyless path does not take its baseline from the policy's baseline rule (REQ-REL-009-AC13)")
if 'release-workflow-keyless' not in brun or 'BASE="${GITHUB_REF_NAME}"' not in brun:
    bad.append("owner-signed tags no longer need their own baseline, or the keyless branch is missing")
if 'verify-freeze "${BASE}"' not in brun or "d.get('version') != base" not in brun:
    bad.append("the chosen baseline is not verified and approval-checked")
adm = [s for s in steps if s.get("id") == "admission"]
if not adm or "baseline_version" not in adm[0].get("run", "") or "BASELINE" not in str(adm[0].get("env", {})):
    bad.append("admission.json does not record the baseline used")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_() {
  local f="$work/$1.yml"
  cp "$root/.github/workflows/stage-admission.yml" "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
S = d["jobs"]["admit"]["steps"]
sig = [s for s in S if s.get("id") == "tagsig"][0]
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge "$f" 2>&1); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS wiring:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL wiring:$1 → $got, want $2 ($out)"; fi
}
case_ real               ok  ""
case_ identity-regexp    bad "sig['run'] = sig['run'].replace('--certificate-identity ', '--certificate-identity-regexp ')"
case_ any-issuer         bad "sig['run'] = sig['run'].replace('--certificate-oidc-issuer https://token.actions.githubusercontent.com', '--certificate-oidc-issuer-regexp .*')"
case_ any-commit         bad "sig['run'] = sig['run'].replace('--certificate-github-workflow-sha \"\${GITHUB_SHA}\"', '')"
case_ any-branch         bad "sig['run'] = sig['run'].replace('release.yml@refs/heads/main', 'release.yml@refs/heads/dev')"
case_ route-from-tag     bad "sig['run'] = sig['run'].replace('/tmp/policy/admission-tag-signer.py', 'bin/admission-tag-signer.py')"
case_ gitsign-from-tag   bad "sig['run'] = sig['run'].replace('/tmp/policy/install-scanner.sh gitsign', './bin/install-scanner.sh gitsign')"
case_ keyless-own-baseline bad "B = [s for s in S if 'APPROVED' in s.get('name','')][0]; B['run'] = B['run'].replace('/tmp/policy/admission-tag-signer.py baseline', 'echo')"
case_ owner-borrows       bad "B = [s for s in S if 'APPROVED' in s.get('name','')][0]; B['run'] = B['run'].replace('BASE=\"\${GITHUB_REF_NAME}\"', 'BASE=v0.2.1')"
case_ unverified-base     bad "B = [s for s in S if 'APPROVED' in s.get('name','')][0]; B['run'] = B['run'].replace('verify-freeze \"\${BASE}\"', 'verify-freeze \"\${GITHUB_REF_NAME}\"')"
case_ unrecorded-base     bad "A = [s for s in S if s.get('id') == 'admission'][0]; A['run'] = A['run'].replace('baseline_version', 'unused')"
case_ baselines-from-commit bad "B = [s for s in S if 'APPROVED' in s.get('name','')][0]; B['run'] = B['run'].replace('owner-baselines', 'owner-baselinez')"
case_ any-signer-baselines bad "B = [s for s in S if 'APPROVED' in s.get('name','')][0]; B['run'] = B['run'].replace('--allowed-signers /tmp/policy/allowed_signers', '--allowed-signers allowed_signers')"
case_ copy-unchecked      bad "B = [s for s in S if 'APPROVED' in s.get('name','')][0]; B['run'] = B['run'].replace('cmp -s', 'true')"
case_ no-refuse-default  bad "sig['run'] = sig['run'].replace('*) echo \"::error::', '*) echo \"::notice::')"
echo "admission-tag-signer wiring: $pass passed, $failn failed"
[ "$failn" = 0 ]
