#!/usr/bin/env bash
# proves: REQ-REL-010-AC5
#
# The release chain builds, tests, signs and promotes the FINAL image index F (the built index D plus one attestation
# child per platform carrying the release's VEX), never D. This file pins the six clauses of REQ-REL-010 AC5:
#   1 stage-image's assemble job turns D into F (inspect, compute, verify, push; release mode only) before anything is
#     attested, and records F, never D, as the digests the job outputs, the image-build predicate and the provenance name
#   2 stage-reproducibility recomputes F offline from the rebuilt archive and requires the pushed F
#   3 no later stage derives or names a pre-attestation digest
#   4 PR mode and scan.yml are untouched (no F, nothing pushed)
#   5 a rerun recomputes the same F and the push is idempotent
#   6 only committed paths: python3 bin/vex-index.py, no new action, tool or workflow file, permissions unchanged,
#     every action reference a digest
#
# Two kinds of case. Structural cases read the workflow YAML. Behavioural cases EXTRACT the run: text of the real steps,
# rewrite /tmp/ and ghcr.io to a sandbox and a fake registry on 127.0.0.1, and execute them in order under a PATH with a
# recording docker stub and a recording python3 shim in front of the REAL bin/vex-index.py and real jq/tar/git. Nothing
# here edits or imitates the workflow: if a step is missing or wrong the extracted script is missing or wrong.
#
# AC5_ROOT=/path/to/tree runs the same cases against another copy of the repository (default: this one).
# AC5_ONLY=<clause digit or name fragment> runs a subset. Needs python3 with PyYAML, jq, tar, git.
# Exit status is non-zero when any case fails.
set -euo pipefail

ROOT="${AC5_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export ROOT
T="$(mktemp -d)"
export T
trap 'rm -rf "$T"' EXIT

cat >"$T/cases.py" <<'PYEOF'
import base64, hashlib, http.server, io, json, os, re, shlex, shutil, socketserver, subprocess, sys, tarfile, tempfile, threading
import urllib.parse
import yaml

ROOT = os.environ["ROOT"]
TMP = os.environ["T"]
WF = os.path.join(ROOT, ".github", "workflows")
VEX_PATH = ".vex/fosterstack-cache.openvex.json"
VARIANTS = ("production", "debug", "fips")
OCI_IDX = "application/vnd.oci.image.index.v1+json"
OCI_MAN = "application/vnd.oci.image.manifest.v1+json"
OWNER = "fosterowner"
TOKEN = "ghs_Tok3n-for-the-fake-registry-7c41"
ATTEST_TYPE = "attestation-manifest"
CHAIN = ["release.yml", "stage-admission.yml", "stage-build.yml", "stage-image.yml", "stage-reproducibility.yml",
         "stage-verify.yml", "stage-acceptance-artifacts.yml", "stage-acceptance-egress.yml", "stage-acceptance-k8s.yml",
         "stage-acceptance-predicate.yml", "stage-authorize.yml", "stage-promote.yml"]
DOWNSTREAM = ["release.yml", "stage-verify.yml", "stage-acceptance-artifacts.yml", "stage-acceptance-egress.yml",
              "stage-acceptance-k8s.yml", "stage-acceptance-predicate.yml", "stage-authorize.yml", "stage-promote.yml"]
# the workflow files that exist today: a new workflow file needs the owner's ratification (no workflow sprawl, Oct 3)
KNOWN_WORKFLOWS = {
    "acceptance.yml", "agent-review-gate.yml", "auditor.yml", "ci.yml", "codeql.yml", "dependabot-auto-merge.yml",
    "dependabot-reviewer.yml", "go-freshness.yml", "main-candidate-rescan.yml", "release.yml", "reserved-branch-guard.yml",
    "scan.yml", "scorecard.yml", "stage-acceptance-artifacts.yml", "stage-acceptance-egress.yml", "stage-acceptance-k8s.yml",
    "stage-acceptance-predicate.yml", "stage-admission.yml", "stage-authorize.yml", "stage-build.yml", "stage-image.yml",
    "stage-promote.yml", "stage-reproducibility.yml", "stage-verify.yml", "supply-chain.yml"}


class Fail(Exception):
    pass


def ok(cond, msg="assertion failed"):
    if not cond:
        raise Fail(msg)


def eq(got, want, msg):
    if got != want:
        raise Fail("%s: got %r want %r" % (msg, str(got)[:300], str(want)[:300]))


CASES = []


def case(tag, name):
    def deco(f):
        CASES.append((tag, name, f))
        return f
    return deco


# ---------------------------------------------------------------- reading the workflows
def wf_text(name):
    with open(os.path.join(WF, name), encoding="utf-8") as f:
        return f.read()


def wf(name):
    return yaml.load(wf_text(name), Loader=yaml.BaseLoader)


def steps_of(name, job):
    return (wf(name)["jobs"][job].get("steps")) or []


def norm(s):
    return re.sub(r"\s+", "", re.sub(r"\$\{\{(.*?)\}\}", r"\1", s or ""))


def run_of(step):
    return step.get("run") or ""


def joined(run):
    return re.sub(r"\\\n\s*", " ", run)


def is_release_only(step):
    return norm(step.get("if")) == "inputs.mode=='release'"


def eligible(step, mode):
    """does GitHub run this step in this mode (the conditions this chain uses: inputs.mode and inputs.upload-oci)"""
    cond = step.get("if")
    if cond is None:
        return True
    e = re.sub(r"^\s*\$\{\{(.*)\}\}\s*$", r"\1", cond.strip(), flags=re.S)
    e = e.replace("inputs.mode", repr(mode)).replace("inputs.upload-oci", "False").replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"!(?!=)", " not ", e)
    try:
        return bool(eval(e, {"__builtins__": {}}, {}))
    except Exception:
        raise Fail("cannot evaluate the step condition %r" % cond)


def vex_calls(run):
    """[(subcommand, {option: value}, logical line)] for every `python3 bin/vex-index.py <sub> ...` in a run: block"""
    out = []
    for line in joined(run).split("\n"):
        if "vex-index.py" not in line or line.strip().startswith("#"):
            continue
        t = re.sub(r"\$\{\{(.*?)\}\}", lambda m: "EXPR[" + norm(m.group(1)) + "]", line)
        try:
            toks = shlex.split(t, comments=True)
        except ValueError:
            raise Fail("a vex-index.py line cannot be tokenised: %r" % line)
        ix = [i for i, x in enumerate(toks) if x.endswith("vex-index.py")]
        ok(ix, "vex-index.py is named but not as a command: %r" % line)
        i = ix[0]
        ok(i >= 1 and re.search(r"(^|[=(`])python3$", toks[i - 1]), "the tool must be run as `python3 bin/vex-index.py` (clause 6): %r" % line)
        ok(toks[i] == "bin/vex-index.py", "the tool path must be exactly bin/vex-index.py: %r" % toks[i])
        sub = toks[i + 1] if i + 1 < len(toks) else ""
        opts, j = {}, i + 2
        while j < len(toks):
            x = toks[j]
            if x.startswith("--"):
                if "=" in x:
                    k, v = x.split("=", 1)
                    opts[k] = v
                    j += 1
                else:
                    opts[x] = toks[j + 1].rstrip(")") if j + 1 < len(toks) else ""
                    j += 2
            else:
                j += 1
        out.append((sub, opts, line))
    return out


def position(steps, pred):
    return [i for i, s in enumerate(steps) if pred(s)]


def is_attest(s):
    return (s.get("uses") or "").startswith(("actions/attest@", "actions/attest-build-provenance@", "actions/attest-sbom@"))


def vex_steps(steps):
    return position(steps, lambda s: "vex-index.py" in run_of(s))


# ================================================================ clause 1: stage-image structure
def assemble():
    return steps_of("stage-image.yml", "assemble")


def build_idx(steps):
    ix = position(steps, lambda s: "buildx build" in run_of(s))
    eq(len(ix), 1, "steps that run buildx build in assemble")
    return ix[0]


def final_index_steps():
    st = assemble()
    ix = vex_steps(st)
    ok(ix, "no step in stage-image's assemble job runs bin/vex-index.py")
    return st, ix


def calls_in_order():
    st, ix = final_index_steps()
    return st, [(i, c) for i in ix for c in vex_calls(run_of(st[i]))]


@case("1", "assemble has final-index step(s) that run bin/vex-index.py, in release mode only")
def _():
    st, ix = final_index_steps()
    for i in ix:
        ok(is_release_only(st[i]), "step %r is not guarded by exactly `inputs.mode == 'release'`: %r" % (st[i].get("name"), st[i].get("if")))


@case("1", "the final-index steps come after the build/push loop")
def _():
    st, ix = final_index_steps()
    ok(min(ix) > build_idx(st), "a vex-index step runs before the build step")


@case("1", "the final-index steps come before the image-build predicate is written and before every attest step")
def _():
    st, ix = final_index_steps()
    last = max(ix)
    pred = position(st, lambda s: "image-build-predicate" in run_of(s) and "index_digests" in run_of(s))
    ok(pred, "no step writes the image-build predicate")
    for p in pred:
        ok(last < p, "a vex-index step runs after the predicate is written (step %d)" % p)
    att = position(st, is_attest)
    ok(len(att) >= 2, "the image-build predicate and the provenance attest steps are missing")
    for a in att:
        ok(last < a, "a vex-index step runs after an attest step (%s)" % st[a].get("uses"))


@case("1", "compute, verify and push each run exactly once, in that order")
def _():
    st, seq = calls_in_order()
    eq([c[0] for _, c in seq], ["compute", "verify", "push"], "the vex-index subcommands in order")


@case("1", "compute: --index, --out-dir and the committed VEX file (--vex .vex/fosterstack-cache.openvex.json)")
def _():
    _, seq = calls_in_order()
    sub, o, line = [c for _, c in seq if c[0] == "compute"][0]
    for k in ("--index", "--out-dir"):
        ok(o.get(k), "compute has no %s" % k)
    eq(o.get("--vex"), VEX_PATH, "compute --vex")


@case("1", "verify: --final, --vex (the same file), --base and --blobs (the full check)")
def _():
    _, seq = calls_in_order()
    sub, o, line = [c for _, c in seq if c[0] == "verify"][0]
    for k in ("--final", "--base", "--blobs"):
        ok(o.get(k), "verify has no %s (verify must be the full check)" % k)
    eq(o.get("--vex"), VEX_PATH, "verify --vex")
    ok(o["--final"].endswith("/index.json"), "verify --final is not the computed index.json: %r" % o["--final"])


@case("1", "push: --registry ghcr.io, --repository <owner>/cache-candidates, --dir, --vex (the same file), --base")
def _():
    _, seq = calls_in_order()
    sub, o, line = [c for _, c in seq if c[0] == "push"][0]
    eq(o.get("--registry"), "ghcr.io", "push --registry")
    rep = o.get("--repository") or ""
    ok("github.repository_owner" in rep and rep.endswith("/cache-candidates"), "push --repository is %r" % rep)
    for k in ("--dir", "--base"):
        ok(o.get(k), "push has no %s" % k)
    eq(o.get("--vex"), VEX_PATH, "push --vex")


@case("1", "the three calls agree: one --index/--base file, one out dir, verify reads that dir's index.json and blobs")
def _():
    _, seq = calls_in_order()
    c = {s: o for _, (s, o, _l) in seq}
    ok(set(c) == {"compute", "verify", "push"}, "compute, verify and push are all required")
    eq(c["verify"].get("--base"), c["compute"].get("--index"), "verify --base vs compute --index")
    eq(c["push"].get("--base"), c["compute"].get("--index"), "push --base vs compute --index")
    eq(c["push"].get("--dir"), c["compute"].get("--out-dir"), "push --dir vs compute --out-dir")
    eq(c["verify"].get("--final"), c["compute"].get("--out-dir", "?") + "/index.json", "verify --final")
    eq(c["verify"].get("--blobs"), c["compute"].get("--out-dir", "?") + "/blobs", "verify --blobs")


@case("1", "the built index's bytes come from the registry: imagetools inspect --raw of cache-candidates@D, to a file, before compute")
def _():
    st, ix = final_index_steps()
    text = "\n".join(joined(run_of(st[i])) for i in ix)
    m = re.search(r"imagetools\s+inspect\s+--raw[^\n]*@[^\n]*", text)
    ok(m and "cache-candidates" in text, "no `docker buildx imagetools inspect --raw <...cache-candidates>@<D>` in the final-index steps")
    ok(m.start() < text.index("vex-index.py"), "the index is inspected after compute already ran")
    ok(re.search(r">\s*\S+", m.group(0)), "the inspected bytes are not written to a file: %r" % m.group(0))


@case("1", "the push step carries FSCACHE_REGISTRY_USER and FSCACHE_REGISTRY_TOKEN from the job's own token, nothing hard-coded")
def _():
    st, ix = final_index_steps()
    holders = [i for i in ix if "vex-index.py push" in joined(run_of(st[i]))]
    eq(len(holders), 1, "steps holding the push call")
    env = st[holders[0]].get("env") or {}
    for k in ("FSCACHE_REGISTRY_USER", "FSCACHE_REGISTRY_TOKEN"):
        ok(k in env, "the push step has no %s" % k)
    ok(norm(env["FSCACHE_REGISTRY_TOKEN"]) in ("github.token", "secrets.GITHUB_TOKEN"), "token is %r" % env["FSCACHE_REGISTRY_TOKEN"])
    ok(re.fullmatch(r"\$\{\{\s*[a-z.]+\s*\}\}", env["FSCACHE_REGISTRY_USER"].strip()), "user is %r" % env["FSCACHE_REGISTRY_USER"])


@case("1", "fail closed: no continue-on-error, no `|| true`, no `set +e`, set -e and pipefail in each final-index step")
def _():
    job = wf("stage-image.yml")["jobs"]["assemble"]
    ok(norm(job.get("continue-on-error")) in ("", "false"), "the assemble job continues on error")
    st, ix = final_index_steps()
    for i in ix:
        s, r = st[i], run_of(st[i])
        ok(norm(s.get("continue-on-error")) in ("", "false"), "step %r has continue-on-error" % s.get("name"))
        ok("shell" not in s, "step %r overrides the shell" % s.get("name"))
        ok(not re.search(r"\|\|\s*(true|:|exit\s+0|echo)|set\s+\+e|;\s*true\b|\bif\s+!", r), "step %r swallows a failure" % s.get("name"))
        ok(re.search(r"set\s+-[a-z]*e[a-z]*\b", r) and "pipefail" in r, "step %r lacks set -euo pipefail" % s.get("name"))
        for sub, o, line in vex_calls(r):
            ok("||" not in line and not re.match(r"\s*!", line), "a vex-index command can fail silently: %r" % line)


@case("1", "digests are recorded in release mode only by a step after the push, and the job output reads that step")
def _():
    st, ix = final_index_steps()
    last = max(ix)
    writers = position(st, lambda s: "GITHUB_OUTPUT" in run_of(s) and re.search(r"digests=", run_of(s)))
    ok(writers, "no step writes the digests output")
    rel = [w for w in writers if eligible(st[w], "release")]
    ok(rel, "no release-mode step writes the digests output")
    for w in rel:
        ok(w >= last, "step %r writes digests in release mode before the push (it can only know D)" % st[w].get("name"))
    out = wf("stage-image.yml")["jobs"]["assemble"]["outputs"]["digests"]
    ids = re.findall(r"steps\.([A-Za-z0-9_-]+)\.outputs\.digests", out)
    ok(ids, "the job output digests names no step: %r" % out)
    ok(any(st[w].get("id") in ids for w in rel), "the job output does not read the release-mode writer")
    for sid in ids:
        w = [x for x in writers if st[x].get("id") == sid]
        ok(w, "the job output reads step %r which does not write digests" % sid)
        ok(not eligible(st[w[0]], "release") or w[0] >= last, "the job output reads D through step %r in release mode" % sid)


@case("1", "no step before the push writes any step output in release mode (D never reaches an output)")
def _():
    st, ix = final_index_steps()
    for s in st[:min(ix)]:
        ok(not ("GITHUB_OUTPUT" in run_of(s) and eligible(s, "release")), "step %r (before the final index exists) writes a step output in release mode" % s.get("name"))


@case("1", "nothing after the push reads the build metadata (containerimage.digest or the --metadata-file JSON)")
def _():
    st, ix = final_index_steps()
    for s in st[max(ix) + 1:]:
        r = run_of(s)
        ok("containerimage" not in r and "--metadata-file" not in r and not re.search(r'/tmp/\$\{?v\}?\.json', r),
           "step %r reads the pre-attestation build metadata" % s.get("name"))


@case("1", "no artifact upload runs in release mode (D is in no artifact)")
def _():
    n = 0
    for s in assemble():
        if (s.get("uses") or "").startswith("actions/upload-artifact"):
            n += 1
            ok(not eligible(s, "release"), "upload-artifact runs in release mode")
    ok(n == 1, "expected the PR-mode upload step")


@case("1", "the image-build predicate and the provenance attest steps run in release mode only, over a subject-checksums file")
def _():
    att = [s for s in assemble() if is_attest(s)]
    ok(len(att) == 2, "expected the image-build and provenance attest steps, found %d" % len(att))
    for s in att:
        ok(is_release_only(s), "attest step %r is not release-only" % s.get("uses"))
        ok((s.get("with") or {}).get("subject-checksums"), "attest step has no subject-checksums")


# ================================================================ clause 2: stage-reproducibility structure
def repro_steps():
    return steps_of("stage-reproducibility.yml", "reproduce")


@case("2", "reproducibility runs `python3 bin/vex-index.py compute` with --index, --out-dir and the committed VEX")
def _():
    st = repro_steps()
    ix = vex_steps(st)
    ok(ix, "stage-reproducibility.yml never runs bin/vex-index.py")
    cs = [c for i in ix for c in vex_calls(run_of(st[i]))]
    ok("compute" in [c[0] for c in cs], "no compute call: %s" % [c[0] for c in cs])
    sub, o, line = [c for c in cs if c[0] == "compute"][0]
    ok(o.get("--index") and o.get("--out-dir"), "compute needs --index and --out-dir: %s" % o)
    eq(o.get("--vex"), VEX_PATH, "reproducibility compute --vex")


@case("2", "reproducibility never pushes (offline, read-only token) and never reads the registry for the index bytes")
def _():
    st = repro_steps()
    ok(vex_steps(st), "stage-reproducibility.yml never runs bin/vex-index.py")
    for i in vex_steps(st):
        for sub, o, line in vex_calls(run_of(st[i])):
            ok(sub != "push", "stage-reproducibility pushes")
        ok("imagetools" not in run_of(st[i]) and "crane" not in run_of(st[i]), "the rebuilt index bytes must come from the local archive, not the registry")
    ok("packages: write" not in wf_text("stage-reproducibility.yml"), "stage-reproducibility asks for packages: write")


@case("2", "reproducibility reads neither containerimage.digest nor a build metadata file: F is compared, not D")
def _():
    t = wf_text("stage-reproducibility.yml")
    ok("containerimage.digest" not in t, "stage-reproducibility.yml still reads containerimage.digest")
    ok("--metadata-file" not in t, "stage-reproducibility.yml still writes a build metadata file")
    ok("local_d" not in t, "the local_d == pushed_d comparison is still there")


@case("2", "reproducibility still rebuilds to a local OCI archive (type=oci, no push) from the verified dist")
def _():
    t = wf_text("stage-reproducibility.yml")
    ok("type=oci,dest=" in t and "buildx build" in t, "the local rebuild is gone")
    ok("push=true" not in t and "push-by-digest" not in t, "the rebuild pushes")


@case("2", "the reproducibility predicate and its subjects come from inputs.digests (which are F)")
def _():
    st = repro_steps()
    ok(any("repro-subjects" in run_of(s) and "inputs.digests" in run_of(s) for s in st), "subjects not from inputs.digests")
    ok(any("repro-predicate" in run_of(s) and "inputs.digests" in run_of(s) for s in st), "predicate not from inputs.digests")


# ================================================================ clause 3: nothing downstream names a pre-attestation digest
@case("3", "containerimage.digest and --metadata-file appear in no workflow except stage-image.yml's build step")
def _():
    for name in sorted(os.listdir(WF)):
        if name == "stage-image.yml" or not name.endswith((".yml", ".yaml")):
            continue
        t = wf_text(name)
        ok("containerimage.digest" not in t, "%s reads containerimage.digest" % name)
        if name != "main-candidate-rescan.yml":   # builds main's candidate from source, outside the release chain
            ok("--metadata-file" not in t, "%s writes a build metadata file" % name)
    st = assemble()
    for i, s in enumerate(st):
        if "containerimage.digest" in run_of(s):
            ok(i == build_idx(st), "step %r reads containerimage.digest outside the build step" % s.get("name"))


@case("3", "no downstream stage derives a digest (inspect/crane/skopeo/docker inspect) of a candidate: they consume inputs.digests")
def _():
    for name in DOWNSTREAM + ["scan.yml"]:
        t = wf_text(name)
        ok("RepoDigests" not in t and "skopeo inspect" not in t and not re.search(r"docker\s+(image\s+)?inspect[^\n]*(Digest|\.Id\b)", t), "%s derives a digest from a local image" % name)
        ok(not re.search(r"imagetools\s+inspect(?![^\n]*--raw)", t), "%s asks imagetools for a digest" % name)
        ok(not re.search(r"crane digest[^\n]*cache-candidates", t), "%s resolves a candidate's digest by name" % name)
        ok("--format" not in "\n".join(l for l in t.split("\n") if "imagetools" in l), "%s formats an imagetools digest" % name)


@case("3", "every release.yml stage that takes the digests takes needs.image.outputs.digests; the image is used by those digests")
def _():
    d = wf("release.yml")["jobs"]
    ok((d["image"].get("uses") or "").endswith("stage-image.yml") and d["image"]["with"]["mode"] == "release", "release.yml's image job changed")
    n = 0
    for jn, j in d.items():
        w = j.get("with") or {}
        if "digests" in w:
            n += 1
            eq(norm(w["digests"]), "needs.image.outputs.digests", "release.yml job %s digests" % jn)
        if "image-ref" in w:
            ok("fromJSON(needs.image.outputs.digests)" in norm(w["image-ref"]) and "cache-candidates@" in w["image-ref"], "image-ref of %s" % jn)
    ok(n >= 6, "release.yml passes the digests to only %d stages" % n)


@case("3", "only stage-image.yml writes a `digests` output: no other stage re-derives and re-emits them")
def _():
    for name in sorted(os.listdir(WF)):
        if name in ("stage-image.yml", "scan.yml") or not name.endswith(".yml"):
            continue
        ok(not re.search(r'echo\s+"?digests=', wf_text(name)), "%s writes a digests output" % name)


@case("3", "every consumer of an index's .manifests[] excludes the attestation children (they are not platforms)")
def _():
    n = 0
    for name in CHAIN + ["scan.yml"]:
        for line in joined(wf_text(name)).split("\n"):
            if ".manifests[]" in line:
                n += 1
                ok(re.search(r'select\([^)]*(platform\.os\s*(==|!=)|vnd\.docker\.reference\.type)', line),
                   "%s: .manifests[] without excluding the attestation children: %s" % (name, line.strip()[:160]))
    ok(n >= 4, "expected the existing consumers, found %d" % n)


@case("3", "the image-build predicate lists only the platform manifests (attestation children excluded in its jq)")
def _():
    pred = [s for s in assemble() if "platform_manifests" in run_of(s)]
    ok(pred, "no predicate-writing step")
    for s in pred:
        for line in joined(run_of(s)).split("\n"):
            if ".manifests[]" in line:
                ok(re.search(r'select\([^)]*(platform\.os\s*(==|!=)|vnd\.docker\.reference\.type)', line), "the predicate's platform list includes attestation children: %s" % line.strip()[:160])


@case("3", "the verification stages still compare the signed index_digests with the consumed digests")
def _():
    for name in ("stage-authorize.yml", "stage-promote.yml"):
        ok("index_digests" in wf_text(name) and "inputs.digests" in wf_text(name), "%s no longer compares index_digests with inputs.digests" % name)


# ================================================================ clause 4: PR mode and scan.yml untouched
@case("4", "scan.yml never runs the final-index tool; it calls stage-image in pr mode only")
def _():
    ok("vex-index" not in wf_text("scan.yml"), "scan.yml runs the final-index tool")
    n = 0
    for jn, j in wf("scan.yml")["jobs"].items():
        if (j.get("uses") or "").endswith("stage-image.yml"):
            n += 1
            eq(j["with"]["mode"], "pr", "scan.yml %s mode" % jn)
    ok(n == 2, "scan.yml's two assemblies changed (%d)" % n)


@case("4", "stage-image's PR mode still builds local type=oci archives, uploads them as before, never logs in or runs the tool")
def _():
    ok("type=oci,dest=/tmp/${v}.oci,rewrite-timestamp=true" in wf_text("stage-image.yml"), "the PR-mode local OCI output changed")
    st = assemble()
    up = [s for s in st if (s.get("uses") or "").startswith("actions/upload-artifact")]
    eq(len(up), 1, "upload steps")
    eq(norm(up[0].get("if")), "inputs.mode=='pr'&&inputs.upload-oci", "the upload-oci condition")
    n = 0
    for s in st:
        if "vex-index.py" in run_of(s) or "docker login" in run_of(s):
            n += 1
            ok(is_release_only(s), "step %r runs in PR mode" % s.get("name"))
    ok(n >= 2, "no final-index step found")


# ================================================================ clause 6: committed paths only
@case("6", "every bin/ path the changed steps run is a committed file, and the tool is run as `python3 bin/vex-index.py`")
def _():
    n = 0
    for name, job in (("stage-image.yml", "assemble"), ("stage-reproducibility.yml", "reproduce")):
        for s in steps_of(name, job):
            for sub, o, line in vex_calls(run_of(s)):
                n += 1
                ok(sub in ("compute", "verify", "push"), "unknown subcommand %r" % sub)
            for m in re.finditer(r"(?<![\w/.-])(bin/[A-Za-z0-9_./-]+)", run_of(s)):
                ok(os.path.isfile(os.path.join(ROOT, m.group(1))), "%s names %s, which is not a committed file" % (name, m.group(1)))
    ok(n >= 4, "expected compute, verify, push and the reproducibility compute; found %d vex-index calls" % n)


@case("6", "no new tool is fetched or installed by the changed workflows")
def _():
    bad = re.compile(r"\b(curl|wget|pip3?\s+install|npm\s+(i|install)|apt(-get)?\s+install|go\s+install|brew\s+install|cosign|crane|oras|regctl|skopeo|sudo)\b")
    ok(vex_steps(assemble()) and vex_steps(repro_steps()), "the changed steps are missing")
    for name, job in (("stage-image.yml", "assemble"), ("stage-reproducibility.yml", "reproduce")):
        for s in steps_of(name, job):
            r = "\n".join(l for l in run_of(s).split("\n") if not l.strip().startswith("#"))
            ok(not bad.search(r), "%s step %r installs or runs a new tool: %s" % (name, s.get("name"), bad.search(r)))


@case("6", "stage-image and stage-reproducibility use no new action: the same set as before, every one a commit digest with a version")
def _():
    want = {"stage-image.yml": {"actions/checkout", "actions/download-artifact", "docker/setup-buildx-action", "actions/upload-artifact",
                                "actions/attest", "actions/attest-build-provenance"},
            "stage-reproducibility.yml": {"actions/checkout", "actions/download-artifact", "docker/setup-buildx-action", "actions/attest"}}
    for name, w in want.items():
        got = set()
        for m in re.finditer(r"^\s*-?\s*uses:\s*(\S+)(.*)$", wf_text(name), re.M):
            ref, rest = m.group(1), m.group(2)
            ok(re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref) and re.match(r"\s*# v\d", rest), "%s: %s is not a digest with a version comment" % (name, ref))
            got.add(ref.split("@")[0])
        eq(got, w, "%s actions" % name)
    ok(vex_steps(assemble()) and vex_steps(repro_steps()), "the changed steps are missing")


@case("6", "permissions are unchanged: assemble keeps contents read, packages write, id-token write, attestations write; reproduce packages read")
def _():
    eq(wf("stage-image.yml")["permissions"], {"contents": "read"}, "stage-image workflow permissions")
    eq(wf("stage-image.yml")["jobs"]["assemble"]["permissions"],
       {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"}, "assemble permissions")
    eq(wf("stage-reproducibility.yml")["permissions"], {"contents": "read"}, "stage-reproducibility workflow permissions")
    eq(wf("stage-reproducibility.yml")["jobs"]["reproduce"]["permissions"],
       {"contents": "read", "packages": "read", "id-token": "write", "attestations": "write"}, "reproduce permissions")
    ok(vex_steps(assemble()) and vex_steps(repro_steps()), "the changed steps are missing")


@case("6", "no new workflow file: the set of workflow files is the one that exists today")
def _():
    have = {n for n in os.listdir(WF) if not n.startswith(".")}
    eq(sorted(have - KNOWN_WORKFLOWS), [], "new workflow files (need the owner's ratification)")
    eq(sorted(KNOWN_WORKFLOWS - have), [], "workflow files that vanished")
    ok(vex_steps(assemble()), "the changed steps are missing")


@case("6", "check-action-pins reports 0 findings on the tree")
def _():
    r = subprocess.run([sys.executable, os.path.join(ROOT, ".github/agent/bin/check-action-pins.py"), ROOT], capture_output=True, text=True, timeout=300)
    ok(r.returncode == 0 and re.search(r"\b0 finding", r.stdout + r.stderr), "check-action-pins: rc=%s %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    ok(vex_steps(assemble()), "the changed steps are missing")


# ================================================================ behaviour: fixtures, fake registry, stubs
def sha(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def hexof(d):
    return d.split(":", 1)[1]


def jb(o):
    return (json.dumps(o, indent=2) + "\n").encode()


def mk_variant(v, tag=""):
    kids = []
    for arch in ("amd64", "arm64"):
        m = jb({"schemaVersion": 2, "mediaType": OCI_MAN, "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + "0" * 64, "size": 2},
                "layers": [], "annotations": {"fixture": "%s/%s/%s" % (v, arch, tag)}})
        kids.append({"bytes": m, "digest": sha(m), "arch": arch})
    idx = jb({"schemaVersion": 2, "mediaType": OCI_IDX,
              "manifests": [{"mediaType": OCI_MAN, "digest": k["digest"], "size": len(k["bytes"]), "platform": {"architecture": k["arch"], "os": "linux"}} for k in kids]})
    return {"kids": kids, "index": idx, "digest": sha(idx)}


class Reg:
    """a distribution registry on 127.0.0.1: reads are open, writes need Basic auth with TOKEN (a 401 challenge first);
    it records every request. fail_after=N: the (N+1)th write answers 500."""

    def __init__(self, fail_after=None):
        self.blobs, self.mans, self.log, self.fail_after, self.writes_ok = set(), {}, [], fail_after, 0
        self.lock = threading.Lock()
        reg = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def any(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                u = urllib.parse.urlsplit(self.path)
                with reg.lock:
                    st, hd, rb = reg.respond(self.command, u, urllib.parse.parse_qs(u.query), body, self.headers)
                    reg.log.append({"m": self.command, "p": u.path, "q": u.query, "st": st, "auth": self.headers.get("Authorization"), "len": len(body)})
                self.send_response(st)
                hd = dict(hd)
                hd["Content-Length"] = str(len(rb))
                for k, v in hd.items():
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(rb)

            do_GET = do_HEAD = do_POST = do_PUT = any

        class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.srv = S(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def seed(self, var):
        for k in var["kids"]:
            self.mans[k["digest"]] = (k["bytes"], OCI_MAN)
        self.mans[var["digest"]] = (var["index"], OCI_IDX)

    def auth_ok(self, a):
        if not a or not a.startswith("Basic "):
            return False
        try:
            user, tok = base64.b64decode(a[6:]).decode().split(":", 1)
        except Exception:
            return False
        return tok == TOKEN and user != ""

    def respond(self, m, u, q, body, headers):
        p = u.path
        err = lambda c: (c, {}, b'{"errors":[]}')
        if p in ("/v2/", "/v2"):
            return 200, {}, b"{}"
        mp = re.match(r"^/v2/%s/cache-candidates/(.*)$" % OWNER, p)
        if not mp:
            return err(404)
        rest = mp.group(1)
        if m in ("POST", "PUT", "PATCH", "DELETE"):
            if not self.auth_ok(headers.get("Authorization")):
                return 401, {"WWW-Authenticate": 'Basic realm="fake"'}, b""
            if self.fail_after is not None and self.writes_ok >= self.fail_after:
                return 500, {}, b"{}"
            self.writes_ok += 1
        if rest == "blobs/uploads/" and m == "POST":
            return 202, {"Location": "/v2/%s/cache-candidates/blobs/uploads/s%d?_state=st%d" % (OWNER, len(self.log), len(self.log))}, b""
        if rest.startswith("blobs/uploads/") and m == "PUT":
            d = (q.get("digest") or [""])[0]
            if sha(body) != d:
                return err(400)
            self.blobs.add(d)
            return 201, {"Docker-Content-Digest": d}, b""
        if rest.startswith("blobs/") and m in ("HEAD", "GET"):
            return (200, {"Docker-Content-Digest": rest[6:]}, b"") if rest[6:] in self.blobs else err(404)
        if rest.startswith("manifests/"):
            ref = rest[10:]
            if m == "PUT":
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", ref) or sha(body) != ref:
                    return err(400)     # a tag write, or a wrong digest
                self.mans[ref] = (body, headers.get("Content-Type"))
                return 201, {"Docker-Content-Digest": ref}, b""
            if ref in self.mans:
                b, ct = self.mans[ref]
                return 200, {"Content-Type": ct, "Docker-Content-Digest": ref}, b
            return err(404)
        return err(404)


DOCKER_STUB = r'''#!%(py)s
import json, os, sys, tarfile, io, urllib.request
a = sys.argv[1:]
with open(os.environ["CALLS"], "a") as f:
    f.write("docker " + " ".join(a) + "\n")
fx = os.environ["FX"]
if a[:1] == ["login"]:
    sys.stdin.read(); sys.exit(0)
if a[:2] == ["buildx", "version"]:
    print("github.com/docker/buildx v0.0.0-stub"); sys.exit(0)
if a[:2] == ["buildx", "build"]:
    var = None; meta = None; out = ""
    for i, x in enumerate(a):
        if x == "-f": var = a[i + 1].split(".", 1)[1]
        if x == "--metadata-file": meta = a[i + 1]
        if x == "--output": out = a[i + 1]
    d = open(os.path.join(fx, var + ".digest")).read().strip()
    raw = open(os.path.join(fx, var + ".index"), "rb").read()
    if "type=oci" in out:
        dest = [p.split("=", 1)[1] for p in out.split(",") if p.startswith("dest=")][0]
        with tarfile.open(dest, "w") as t:
            def add(name, data):
                ti = tarfile.TarInfo(name); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
            add("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
            add("index.json", json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": d, "size": len(raw)}]}).encode())
            add("blobs/sha256/" + d.split(":")[1], raw)
            for k in sorted(os.listdir(os.path.join(fx, var + ".kids"))):
                add("blobs/sha256/" + k, open(os.path.join(fx, var + ".kids", k), "rb").read())
    if meta:
        json.dump({"containerimage.digest": d, "image.name": "stub"}, open(meta, "w"))
    sys.exit(0)
if a[:3] == ["buildx", "imagetools", "inspect"] and "--raw" in a:
    ref = a[-1]
    if os.environ.get("NO_REGISTRY"):
        print("stub: the registry is offline", file=sys.stderr); sys.exit(97)
    repo, _, dg = ref.partition("@")
    path = repo.split("/", 1)[1]
    try:
        r = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%%s/v2/%%s/manifests/%%s" %% (os.environ["REG_PORT"], path, dg), headers={"Accept": "application/vnd.oci.image.index.v1+json"}))
    except Exception as e:
        print("stub: inspect failed: %%s" %% e, file=sys.stderr); sys.exit(1)
    sys.stdout.buffer.write(r.read()); sys.exit(0)
print("stub docker: unsupported call %%r" %% (a,), file=sys.stderr); sys.exit(99)
'''

PY_SHIM = '''#!/bin/sh
echo "python3 $*" >> "$CALLS"
exec "%s" "$@"
'''


def expand(text, ctx):
    def rep(m):
        e = norm(m.group(1))
        if e not in ctx:
            raise Fail("a step uses the expression ${{ %s }}, which this test does not know how to provide" % m.group(1).strip())
        return ctx[e]
    return re.sub(r"\$\{\{(.*?)\}\}", rep, text)


class Box:
    pass


def make_box(reg, variants_fx, vex_bytes=None, with_registry=True):
    """a sandbox: a git repo with the committed tool, the VEX and the Dockerfiles; /tmp replaced by box/t; stubs on PATH"""
    b = Box()
    b.dir = tempfile.mkdtemp(dir=TMP)
    b.repo, b.t, b.fx, b.bin = (os.path.join(b.dir, x) for x in ("repo", "t", "fx", "shim"))
    for d in (b.repo, b.t, b.fx, b.bin, os.path.join(b.repo, "bin"), os.path.join(b.repo, ".vex"), os.path.join(b.repo, "build", "docker"), os.path.join(b.t, "imgctx")):
        os.makedirs(d)
    shutil.copy(os.path.join(ROOT, "bin", "vex-index.py"), os.path.join(b.repo, "bin", "vex-index.py"))
    if vex_bytes is None:
        with open(os.path.join(ROOT, VEX_PATH), "rb") as f:
            vex_bytes = f.read()
    with open(os.path.join(b.repo, VEX_PATH), "wb") as f:
        f.write(vex_bytes)
    for n in os.listdir(os.path.join(ROOT, "build", "docker")):
        shutil.copy(os.path.join(ROOT, "build", "docker", n), os.path.join(b.repo, "build", "docker", n))
        shutil.copy(os.path.join(ROOT, "build", "docker", n), os.path.join(b.t, "imgctx", n))
    for arch in ("amd64", "arm64"):
        os.makedirs(os.path.join(b.t, "imgctx", "binaries", arch))
        for n in ("fscache", "fscache-fips"):
            with open(os.path.join(b.t, "imgctx", "binaries", arch, n), "wb") as f:
                f.write(("binary %s %s\n" % (arch, n)).encode())
    g = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(g + ["init", "-q", "-b", "main"], cwd=b.repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=b.repo, check=True)
    subprocess.run(g + ["commit", "-qm", "c"], cwd=b.repo, check=True, env=dict(os.environ, GIT_COMMITTER_DATE="2026-01-01T00:00:00Z", GIT_AUTHOR_DATE="2026-01-01T00:00:00Z"))
    b.sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=b.repo, capture_output=True, text=True).stdout.strip()
    for v, var in variants_fx.items():
        with open(os.path.join(b.fx, v + ".digest"), "w") as f:
            f.write(var["digest"])
        with open(os.path.join(b.fx, v + ".index"), "wb") as f:
            f.write(var["index"])
        os.makedirs(os.path.join(b.fx, v + ".kids"))
        for k in var["kids"]:
            with open(os.path.join(b.fx, v + ".kids", hexof(k["digest"])), "wb") as f:
                f.write(k["bytes"])
    b.calls = os.path.join(b.dir, "calls.log")
    open(b.calls, "w").close()
    with open(os.path.join(b.bin, "docker"), "w") as f:
        f.write(DOCKER_STUB % {"py": sys.executable})
    with open(os.path.join(b.bin, "python3"), "w") as f:
        f.write(PY_SHIM % sys.executable)
    for n in ("docker", "python3"):
        os.chmod(os.path.join(b.bin, n), 0o755)
    b.reg, b.with_registry = reg, with_registry
    return b


def rewrite(script, b):
    s = re.sub(r"(?<![\w/.$-])/tmp/", b.t + "/", script)
    return s.replace("ghcr.io", "127.0.0.1:%d" % b.reg.port)


def run_steps(b, steps, mode, extra_ctx=None, start_after_uses=None):
    """execute the run: steps of a job in order (those whose condition holds in this mode), after the last step that
    `uses` start_after_uses (a uses: step is recorded, never run; the attest ones are listed in .attest). returns an object with the step results"""
    ctx = {"github.repository_owner": OWNER, "github.repository": OWNER + "/cache", "github.actor": "ci-actor", "github.token": TOKEN,
           "secrets.GITHUB_TOKEN": TOKEN, "github.sha": b.sha, "inputs.mode": mode, "github.workspace": b.repo}
    ctx.update(extra_ctx or {})
    res = Box()
    res.outputs, res.results, res.attest, res.log, res.failed = {}, [], [], "", None
    start = 0
    if start_after_uses:
        ix = [i for i, s in enumerate(steps) if (s.get("uses") or "").startswith(start_after_uses)]
        ok(ix, "no step uses %s" % start_after_uses)
        start = ix[-1] + 1
    for i, s in enumerate(steps):
        if i < start or not eligible(s, mode):
            continue
        if s.get("uses"):
            if is_attest(s):
                res.attest.append(s)
            continue
        if "run" not in s:
            continue
        out_file = os.path.join(b.dir, "out-%d" % i)
        open(out_file, "w").close()
        env = dict(os.environ)
        for k in list(env):
            if k.startswith(("FSCACHE_", "GITHUB_", "NO_REGISTRY")) or k.lower() in ("http_proxy", "https_proxy", "all_proxy"):
                del env[k]
        env.update({"PATH": b.bin + os.pathsep + env["PATH"], "CALLS": b.calls, "FX": b.fx, "REG_PORT": str(b.reg.port),
                    "GITHUB_OUTPUT": out_file, "GITHUB_SHA": b.sha, "GITHUB_REPOSITORY": OWNER + "/cache", "GITHUB_WORKSPACE": b.repo,
                    "GITHUB_ACTOR": "ci-actor", "PYTHONDONTWRITEBYTECODE": "1", "HOME": b.dir})
        if not b.with_registry:
            env["NO_REGISTRY"] = "1"
        for k, v in (s.get("env") or {}).items():
            env[k] = expand(v, ctx)
        script = os.path.join(b.dir, "step-%d.sh" % i)
        with open(script, "w") as f:
            f.write(rewrite(expand(s["run"], ctx), b))
        p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", script], cwd=b.repo, env=env, capture_output=True, text=True, timeout=240)
        res.log += p.stdout + p.stderr
        res.results.append((s.get("name"), p.returncode))
        outs = {}
        with open(out_file) as f:
            for line in f.read().split("\n"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    outs[k] = v
        if s.get("id"):
            res.outputs[s["id"]] = outs
        if p.returncode != 0:
            res.failed = (s.get("name"), p.returncode, p.stdout + p.stderr)
            return res
    return res


def job_output(job, name, res):
    e = re.sub(r"^\s*\$\{\{(.*)\}\}\s*$", r"\1", job["outputs"][name].strip(), flags=re.S)
    e = re.sub(r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", lambda m: repr(res.outputs.get(m.group(1), {}).get(m.group(2), "")), e)
    e = e.replace("&&", " and ").replace("||", " or ")
    return eval(e, {"__builtins__": {}}, {})


def calls(b):
    with open(b.calls) as f:
        return [l.rstrip("\n") for l in f if l.strip()]


def indep_final(var, vex_bytes=None):
    """F computed independently by the committed tool from D's bytes and the committed VEX"""
    d = tempfile.mkdtemp(dir=TMP)
    idx, out, vp = os.path.join(d, "index.json"), os.path.join(d, "out"), os.path.join(d, "vex.json")
    with open(idx, "wb") as f:
        f.write(var["index"])
    with open(vp, "wb") as f:
        f.write(vex_bytes if vex_bytes is not None else open(os.path.join(ROOT, VEX_PATH), "rb").read())
    r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "vex-index.py"), "compute", "--index", idx, "--vex", vp, "--out-dir", out], capture_output=True, text=True)
    ok(r.returncode == 0, "the reference compute failed: %s" % r.stderr)
    return r.stdout.strip()


def fixtures(tag=""):
    return {v: mk_variant(v, tag) for v in VARIANTS}


def attest_files(b, res, key):
    out = []
    for s in res.attest:
        p = (s.get("with") or {}).get(key)
        if p is None and key == "predicate-path" and s["uses"].startswith("actions/attest-build-provenance@"):
            continue   # the provenance action builds its own predicate over the same subjects
        ok(p, "attest step %r has no %s" % (s.get("uses"), key))
        out.append(rewrite(expand(p, {"github.repository_owner": OWNER, "inputs.mode": "release"}), b))
    return out


def read_json(path):
    ok(os.path.isfile(path), "the attest input %s was never written" % os.path.basename(path))
    with open(path) as f:
        return json.load(f)


def read_lines(path):
    ok(os.path.isfile(path), "the attest input %s was never written" % os.path.basename(path))
    with open(path) as f:
        return [l for l in f.read().split("\n") if l.strip()]


# ---------------------------------------------------------------- release-mode assemble, executed
_CACHE = {}


def assemble_run(mode="release", reg=None, fx=None, fail_after=None):
    reg = reg or Reg(fail_after=fail_after)
    fx = fx or fixtures()
    for var in fx.values():
        reg.seed(var)
    b = make_box(reg, fx)
    res = run_steps(b, assemble(), mode, start_after_uses="docker/setup-buildx-action")
    res.box, res.fx, res.reg = b, fx, reg
    res.job = wf("stage-image.yml")["jobs"]["assemble"]
    return res


def released():
    if "rel" not in _CACHE:
        _CACHE["rel"] = assemble_run()
    return _CACHE["rel"]


def need_ok(res):
    ok(res.failed is None, ("a step failed: %s exit %s: %s" % (res.failed[0], res.failed[1], res.failed[2][-600:])) if res.failed else "")


def want_final(r):
    return {v: indep_final(r.fx[v]) for v in VARIANTS}


def need_final(r):
    """the positive control for the rerun cases: the run succeeded AND recorded F (not D)"""
    need_ok(r)
    eq(json.loads(job_output(r.job, "digests", r)), want_final(r), "the run's digests output (F for every variant)")


@case("1", "e2e: every run step of assemble, in release mode, succeeds up to the first attest step")
def _():
    r = released()
    need_ok(r)
    ok(len(r.attest) == 2, "the run did not reach the two attest steps (%d)" % len(r.attest))


@case("1", "e2e: the job output digests is F for every variant, F is not D, and F is what the tool computes from D and the VEX")
def _():
    r = released()
    need_ok(r)
    got = json.loads(job_output(r.job, "digests", r))
    eq(got, want_final(r), "job output digests")
    for v in VARIANTS:
        ok(got[v] != r.fx[v]["digest"], "%s: the output is still D" % v)


@case("1", "e2e: per variant the calls are build, inspect D, compute, verify, push; no tool call before the builds end")
def _():
    r = released()
    need_ok(r)
    cs = calls(r.box)
    builds = [i for i, c in enumerate(cs) if c.startswith("docker buildx build")]
    eq(len(builds), 3, "buildx build calls")
    pos = lambda sub: [i for i, c in enumerate(cs) if c.startswith("python3 bin/vex-index.py " + sub)]
    comp, ver, push = pos("compute"), pos("verify"), pos("push")
    eq((len(comp), len(ver), len(push)), (3, 3, 3), "compute/verify/push calls (one per variant)")
    ok(min(comp) > max(builds), "compute ran before the last build")
    for v, c, vr, p in zip(VARIANTS, comp, ver, push):
        ok(c < vr < p, "%s: compute, verify, push are out of order" % v)
        d = r.fx[v]["digest"]
        ok(any("imagetools inspect --raw" in cs[i] and cs[i].endswith("cache-candidates@" + d) and i < c for i in range(len(cs))), "%s: D not inspected before its compute" % v)


@case("1", "e2e: the image-build predicate names F (index_digests), lists exactly the platform manifests, no attestation child")
def _():
    r = released()
    need_ok(r)
    pred = read_json(attest_files(r.box, r, "predicate-path")[0])
    eq(pred["index_digests"], want_final(r), "predicate index_digests")
    got = {e["variant"]: sorted(x["digest"] for x in e["platforms"]) for e in pred["platform_manifests"]}
    eq(got, {v: sorted(k["digest"] for k in r.fx[v]["kids"]) for v in VARIANTS}, "predicate platform manifests (children without the attestation entries)")
    for e in pred["platform_manifests"]:
        eq(sorted(x["platform"] for x in e["platforms"]), ["linux/amd64", "linux/arm64"], "platforms of %s" % e["variant"])


@case("1", "e2e: every attest step's subjects are F (hex) for the three variants, named as before")
def _():
    r = released()
    need_ok(r)
    want = want_final(r)
    for path in attest_files(r.box, r, "subject-checksums"):
        eq(sorted(read_lines(path)), sorted("%s  cache-candidates-%s" % (hexof(want[v]), v) for v in VARIANTS), "subjects in %s" % os.path.basename(path))


@case("1", "e2e: D appears in no attest input, no step output and no job output (it is only ever read)")
def _():
    r = released()
    need_ok(r)
    ds = [r.fx[v]["digest"] for v in VARIANTS]
    texts = []
    for key in ("predicate-path", "subject-checksums"):
        for path in attest_files(r.box, r, key):
            ok(os.path.isfile(path), "the attest input %s was never written" % os.path.basename(path))
            with open(path) as f:
                texts.append((path, f.read()))
    texts += [("output of " + sid, json.dumps(o)) for sid, o in r.outputs.items()]
    texts.append(("job output", job_output(r.job, "digests", r)))
    for name, t in texts:
        for d in ds:
            ok(d not in t and hexof(d) not in t, "D (%s...) appears in %s" % (d[:19], os.path.basename(name)))


@case("1", "e2e: the registry ends with F per variant: the two platform children plus one attestation child each, by digest, never a tag")
def _():
    r = released()
    need_ok(r)
    for v in VARIANTS:
        f = indep_final(r.fx[v])
        ok(f in r.reg.mans, "%s: F is not in the registry" % v)
        body, ct = r.reg.mans[f]
        eq(ct, OCI_IDX, "F's media type")
        ms = json.loads(body)["manifests"]
        eq(len(ms), 4, "children of F")
        eq(sorted(m["digest"] for m in ms if (m.get("annotations") or {}).get("vnd.docker.reference.type") != ATTEST_TYPE),
           sorted(k["digest"] for k in r.fx[v]["kids"]), "F's platform children are D's")
        eq(len([m for m in ms if (m.get("annotations") or {}).get("vnd.docker.reference.type") == ATTEST_TYPE]), 2, "attestation children")
    for e in r.reg.log:
        if e["m"] == "PUT" and "/manifests/" in e["p"]:
            ok(re.search(r"/manifests/sha256:[0-9a-f]{64}$", e["p"]), "a manifest was written by tag: %s" % e["p"])
        ok(not (e["m"] in ("PUT", "POST") and any(r.fx[v]["digest"] in e["p"] for v in VARIANTS)), "D was written to the registry: %s" % e["p"])


@case("1", "e2e: the registry token is the job's token (Basic auth on writes) and never appears in a step's output")
def _():
    r = released()
    need_ok(r)
    writes = [e for e in r.reg.log if e["m"] in ("PUT", "POST") and e["st"] < 300]
    ok(writes, "nothing was written")
    for e in writes:
        ok(e["auth"] and base64.b64decode(e["auth"][6:]).decode().split(":", 1)[1] == TOKEN, "a write was not authenticated with the job token")
    ok(TOKEN not in r.log, "the registry token is printed in a step's output")


@case("1", "e2e: a refused push fails the step, records no F and never reaches an attest step (fail closed)")
def _():
    r = assemble_run(fail_after=2)
    ok(r.failed is not None, "the assemble steps passed although the registry refused writes")
    ok(not r.attest, "the run reached an attest step after a failed push")
    ok(len(r.reg.log) > 0, "the push never reached the registry")
    for o in r.outputs.values():
        for v in VARIANTS:
            ok(indep_final(r.fx[v]) not in json.dumps(o), "F was recorded although its push failed")


# ---------------------------------------------------------------- clause 4, executed: PR mode
@case("4", "e2e: in PR mode the job output is D, nothing is pushed, and no login, inspect or vex-index call happens")
def _():
    reg, fx = Reg(), fixtures()
    b = make_box(reg, fx)
    res = run_steps(b, assemble(), "pr", start_after_uses="docker/setup-buildx-action")
    need_ok(res)
    got = json.loads(job_output(wf("stage-image.yml")["jobs"]["assemble"], "digests", res))
    eq(got, {v: fx[v]["digest"] for v in VARIANTS}, "PR-mode digests are D (no final index in PR mode)")
    eq(reg.log, [], "registry requests in PR mode")
    cs = calls(b)
    builds = [c for c in cs if c.startswith("docker buildx build")]
    eq(len(builds), 3, "PR-mode builds")
    for c in builds:
        ok("type=oci,dest=" in c and "push=true" not in c, "a PR-mode build is not a local archive: %s" % c)
    for c in cs:
        ok(c in builds or not any(w in c for w in ("imagetools", "login", "vex-index")), "PR mode ran: %s" % c)


# ---------------------------------------------------------------- clause 5: reruns
@case("5", "rerun: the same inputs on a fresh runner give the same F and output, with no blob re-upload and no registry change")
def _():
    reg, fx = Reg(), fixtures()
    r1 = assemble_run(reg=reg, fx=fx)
    need_final(r1)
    before = (set(reg.blobs), dict(reg.mans))
    n1 = len(reg.log)
    r2 = assemble_run(reg=reg, fx=fx)
    need_final(r2)
    eq(job_output(r2.job, "digests", r2), job_output(r1.job, "digests", r1), "the rerun's digests output")
    eq((set(reg.blobs), dict(reg.mans)), before, "registry content after the rerun")
    second = [e for e in reg.log[n1:] if e["auth"]]   # the unauthenticated first try of a write is only the registry's 401 challenge
    ok(not [e for e in second if e["m"] == "POST"], "the rerun started a blob upload (HEAD-before-PUT should skip existing blobs)")
    ok(not [e for e in second if e["m"] == "PUT" and "/blobs/" in e["p"]], "the rerun re-uploaded a blob")
    ok([e for e in second if e["m"] == "PUT"], "the rerun wrote no manifest at all (the final index must be re-put by digest)")
    for e in second:
        if e["m"] == "PUT":
            ok(re.search(r"/manifests/sha256:[0-9a-f]{64}$", e["p"]) and e["st"] in (200, 201), "a rerun manifest write is not an idempotent write by digest: %s %s" % (e["p"], e["st"]))


@case("5", "rerun: after a push that died half-way, a fresh run completes and records the same F")
def _():
    reg, fx = Reg(fail_after=3), fixtures()
    r1 = assemble_run(reg=reg, fx=fx)
    ok(r1.failed is not None, "the first run should fail when the registry stops accepting writes")
    ok(len(reg.log) > 0, "the first run never reached the registry")
    reg.fail_after = None
    r2 = assemble_run(reg=reg, fx=fx)
    need_final(r2)


@case("5", "rerun: two independent runs (separate runners, separate registries) compute the same F")
def _():
    fx = fixtures()
    a, c = assemble_run(fx=fx), assemble_run(fx=fx)
    need_final(a)
    need_final(c)
    eq(job_output(a.job, "digests", a), job_output(c.job, "digests", c), "digests of two independent runs")


# ================================================================ clause 2, executed: the reproducibility steps
def repro_run(digests, rebuilt, vex_bytes=None):
    """run stage-reproducibility's steps after the buildx setup against a rebuild that yields `rebuilt`; no registry"""
    reg = Reg()
    b = make_box(reg, rebuilt, vex_bytes=vex_bytes, with_registry=False)
    res = run_steps(b, repro_steps(), "release", extra_ctx={"inputs.digests": json.dumps(digests, separators=(",", ":"))}, start_after_uses="docker/setup-buildx-action")
    res.box, res.reg = b, reg
    return res


def repro_inputs():
    fx = fixtures()
    return fx, {v: indep_final(fx[v]) for v in VARIANTS}


def repro_control(fx, F):
    """a refusal only counts when the same step PASSES for the faithful rebuild of the same pushed F"""
    r = repro_run(F, fx)
    need_ok(r)
    ok(len(r.attest) == 1, "the control run did not reach the reproducibility attest step")


@case("2", "e2e: pushed F and a faithful rebuild: passes offline; the subjects and predicate name F, not D")
def _():
    fx, F = repro_inputs()
    r = repro_run(F, fx)
    need_ok(r)
    ok(len(r.attest) == 1, "the run did not reach the reproducibility attest step")
    eq(r.reg.log, [], "registry requests (the recomputation must be offline)")
    cs = calls(r.box)
    ok(any(c.startswith("python3 bin/vex-index.py compute") for c in cs), "the final index was not recomputed")
    for c in cs:
        ok("imagetools" not in c and not c.startswith("python3 bin/vex-index.py push"), "an online call during the reproducibility rebuild: %s" % c)
    lines = sorted(read_lines(attest_files(r.box, r, "subject-checksums")[0]))
    eq(lines, sorted("%s  cache-candidates-%s" % (hexof(F[v]), v) for v in VARIANTS), "reproducibility subjects")
    pred = read_json(attest_files(r.box, r, "predicate-path")[0])
    eq(pred["index_digests"], F, "reproducibility predicate index_digests")
    for t in (json.dumps(pred), json.dumps(lines)):
        for v in VARIANTS:
            ok(fx[v]["digest"] not in t and hexof(fx[v]["digest"]) not in t, "D appears in the reproducibility attest inputs")


@case("2", "e2e: the pushed digests are D (a pre-attestation digest): the step refuses")
def _():
    fx, F = repro_inputs()
    repro_control(fx, F)
    r = repro_run({v: fx[v]["digest"] for v in VARIANTS}, fx)
    ok(r.failed is not None, "the reproducibility step accepted D as the pushed digest")
    ok(not r.attest, "the run reached the attest step with D")


@case("2", "e2e: a rebuild that differs from the pushed one (a different index) is refused")
def _():
    fx, F = repro_inputs()
    repro_control(fx, F)
    other = dict(fx)
    other["fips"] = mk_variant("fips", "rebuilt-differently")
    r = repro_run(F, other)
    ok(r.failed is not None, "a non-reproducible rebuild passed")
    ok(not r.attest, "the run reached the attest step")


@case("2", "e2e: any one variant's pushed F differing is refused (every variant is compared, not only the first)")
def _():
    for bad in VARIANTS:
        fx, F = repro_inputs()
        repro_control(fx, F)
        F = dict(F)
        F[bad] = "sha256:" + "1" * 64
        r = repro_run(F, fx)
        ok(r.failed is not None, "a wrong pushed digest for %s passed" % bad)


@case("2", "e2e: a different VEX at the rebuild than at the push gives a different F, which is refused")
def _():
    fx, F = repro_inputs()
    repro_control(fx, F)
    v = json.loads(open(os.path.join(ROOT, VEX_PATH), "rb").read())
    v["version"] = int(v.get("version", 1)) + 1
    r = repro_run(F, fx, vex_bytes=json.dumps(v, indent=2).encode())
    ok(r.failed is not None, "the rebuild used a VEX that differs from the pushed one and still passed")


@case("2", "e2e: the rebuilt index bytes are the archive's: an archive whose index differs from the pushed one is refused")
def _():
    fx, F = repro_inputs()
    repro_control(fx, F)
    tampered = {v: dict(fx[v], index=fx[v]["index"].replace(b"linux", b"linuy")) for v in VARIANTS}
    r = repro_run(F, tampered)
    ok(r.failed is not None, "a tampered archive index passed")


def main():
    only = os.environ.get("AC5_ONLY")
    passed = failed = 0
    by = {}
    for tag, name, f in CASES:
        by[tag] = by.get(tag, 0) + 1
        if only and only not in name and only != tag:
            continue
        try:
            f()
            passed += 1
            print("ok   [AC5/%s] %s" % (tag, name))
        except Fail as e:
            failed += 1
            print("FAIL [AC5/%s] %s: %s" % (tag, name, str(e)[:500]))
        except Exception as e:
            failed += 1
            print("FAIL [AC5/%s] %s: harness/tool error %s: %s" % (tag, name, type(e).__name__, str(e)[:300]))
    print("")
    print("cases by clause: " + ", ".join("%s=%d" % (k, by[k]) for k in sorted(by)))
    print("%d passed, %d failed, %d cases" % (passed, failed, passed + failed))
    sys.exit(1 if failed else 0)


main()
PYEOF

python3 "$T/cases.py"
