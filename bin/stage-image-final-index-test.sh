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
    m = 0
    for jn, j in wf("main-candidate-rescan.yml")["jobs"].items():
        if (j.get("uses") or "").endswith("stage-image.yml"):
            m += 1
            eq(j["with"]["mode"], "pr", "main-candidate-rescan.yml %s mode" % jn)
    ok(m == 1, "main-candidate-rescan.yml's assembly changed (%d)" % m)


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


def mk_variant(v, tag="", bad=False):
    kids = []
    for arch in (() if bad else ("amd64", "arm64")):
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
    def need(cond, msg):
        if not cond:
            print("stub docker: " + msg, file=sys.stderr); sys.exit(1)
    need("--platform" in a and a[a.index("--platform") + 1] == "linux/amd64,linux/arm64", "build is not for linux/amd64,linux/arm64")
    need("--provenance=false" in a and "--sbom=false" in a, "provenance/sbom exporters are not off")
    need("rewrite-timestamp=true" in out, "the output does not rewrite timestamps")
    need(os.environ.get("SOURCE_DATE_EPOCH", "").isdigit(), "SOURCE_DATE_EPOCH is not the commit time")
    if "type=image" in out:
        need("push-by-digest=true" in out and "push=true" in out and "name=127.0.0.1:%%s/fosterowner/cache-candidates" %% os.environ["REG_PORT"] in out.split(",") or "name=127.0.0.1:%%s/fosterowner/cache-candidates" %% os.environ["REG_PORT"] in out, "release output is not push-by-digest to the candidates package: " + out)
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
    if repo.split("/", 1)[0] != "127.0.0.1:" + os.environ["REG_PORT"]:
        print("stub: inspect of a registry other than ghcr.io: " + repo, file=sys.stderr); sys.exit(1)
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
rc=0
"%s" "$@" || rc=$?
if [ "$rc" = 0 ] && [ "${2:-}" = compute ] && [ -n "${TAMPER_COMPUTE_N:-}" ]; then
  n=$(grep -c '^python3 bin/vex-index.py compute' "$CALLS" || true)
  if [ "$n" = "$TAMPER_COMPUTE_N" ]; then
    out=""; prev=""
    for x in "$@"; do if [ "$prev" = --out-dir ]; then out=$x; fi; prev=$x; done
    printf ' ' >> "$out/index.json"
  fi
fi
exit $rc
'''

GH_STUB = '''#!%(py)s
import os, sys
a = sys.argv[1:]
with open(os.environ["CALLS"], "a") as f:
    f.write("gh " + " ".join(a) + "\\n")
if a[:2] == ["attestation", "verify"]:
    def opt(n):
        return a[a.index(n) + 1] if n in a[:-1] else None
    oci = a[2].startswith("oci://")
    want = {"--repo": os.environ["GH_EXPECT_REPO"],
            "--predicate-type": "https://fosterstack.com/attestations/" + ("image-build" if oci else "build") + "/v1",
            "--signer-workflow": os.environ["GH_EXPECT_REPO"] + "/.github/workflows/" + ("stage-image.yml" if oci else "stage-build.yml")}
    for k, v in want.items():
        if opt(k) != v:
            print("stub gh: %%s is %%r, expected %%r" %% (k, opt(k), v), file=sys.stderr); sys.exit(1)
    att = os.environ.get("GH_ATTESTED")
    if att is not None and a[2].startswith("oci://") and a[2].split("@")[-1] not in att.split(","):
        print("stub gh: no attestation for " + a[2], file=sys.stderr); sys.exit(1)
    sys.exit(0)
print("stub gh: unsupported call %%r" %% (a,), file=sys.stderr); sys.exit(99)
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
    with open(os.path.join(b.bin, "gh"), "w") as f:
        f.write(GH_STUB % {"py": sys.executable})
    for n in ("docker", "python3", "gh"):
        os.chmod(os.path.join(b.bin, n), 0o755)
    # the verified build archives the stages unpack (the signed-predicate check is the gh stub's)
    dist = os.path.join(b.repo, "dist")
    os.makedirs(dist)
    sums = []
    for stem, binary in (("fscache", "fscache"), ("fscache-fips", "fscache-fips")):
        for arch in ("amd64", "arm64"):
            name = "%s_1.0.0_linux_%s.tar.gz" % (stem, arch)
            with tarfile.open(os.path.join(dist, name), "w:gz") as t:
                body = ("binary %s %s\n" % (arch, binary)).encode()
                ti = tarfile.TarInfo(binary)
                ti.size = len(body)
                t.addfile(ti, io.BytesIO(body))
            sums.append("%s  %s" % (hashlib.sha256(open(os.path.join(dist, name), "rb").read()).hexdigest(), name))
    b.checksums = "\n".join(sums)
    b.extra_env = {}
    b.reg, b.with_registry = reg, with_registry
    return b


def rewrite(script, b):
    s = re.sub(r"(?<![\w/.$-])/tmp/", b.t + "/", script)
    return s.replace("ghcr.io", "127.0.0.1:%d" % b.reg.port)


STEP_KEYS = {"name", "id", "if", "uses", "with", "run", "env", "working-directory", "shell", "continue-on-error"}
ALLOWED_WITH = {"actions/checkout": set(), "actions/download-artifact": {"name", "path"}, "docker/setup-buildx-action": {"driver-opts"},
                "actions/upload-artifact": {"name", "path", "if-no-files-found", "retention-days"}}
MODELLED_ACTIONS = ("actions/checkout@", "actions/download-artifact@", "docker/setup-buildx-action@", "actions/upload-artifact@")


def reject_unmodelled_settings(workflow_name, job_name):
    """the harness runs the job's steps itself: a setting it does not model is refused loudly, never ignored"""
    d = wf(workflow_name)
    job = d["jobs"][job_name]
    for where, o in (("workflow", d), ("job", job)):
        for k in ("defaults", "container", "services", "strategy", "timeout-minutes"):
            ok(k not in o, "%s %s of %s uses %r, which this test does not model" % (where, job_name, workflow_name, k))
    for st in job.get("steps") or []:
        extra = set(st) - STEP_KEYS
        ok(not extra, "step %r uses the setting(s) %s, which this test does not model" % (st.get("name"), sorted(extra)))


def run_steps(b, steps, mode, extra_ctx=None):
    """execute a job's steps in order, honouring each step's if, working-directory, shell (bash only) and continue-on-error.
    A uses: step is never run: the attest ones are recorded with their inputs read AT THAT MOMENT (res.snaps), other
    actions must be ones this test knows are inert here. returns an object with the step results"""
    ctx = {"github.repository_owner": OWNER, "github.repository": OWNER + "/cache", "github.actor": "ci-actor", "github.token": TOKEN,
           "secrets.GITHUB_TOKEN": TOKEN, "github.sha": b.sha, "inputs.mode": mode, "github.workspace": b.repo,
           "inputs.dist-artifact": "dist", "inputs.expected-checksums": b.checksums}
    ctx.update(extra_ctx or {})
    res = Box()
    res.outputs, res.results, res.attest, res.snaps, res.uploads, res.ignored, res.log, res.failed = {}, [], [], [], [], [], "", None
    for i, s in enumerate(steps):
        extra = set(s) - STEP_KEYS
        ok(not extra, "step %r uses the setting(s) %s, which this test does not model" % (s.get("name"), sorted(extra)))
        if not eligible(s, mode):
            continue
        if s.get("uses"):
            if is_attest(s):
                res.attest.append(s)
                w = s.get("with") or {}
                bad_in = set(w) - ({"subject-checksums", "predicate-type", "predicate-path"} if s["uses"].startswith("actions/attest@") else {"subject-checksums"})
                ok(not bad_in, "attest step %s is given the input(s) %s, which this test does not model" % (s["uses"].split("@")[0], sorted(bad_in)))
                snap = {"uses": s["uses"]}
                for key in ("subject-checksums", "predicate-path"):
                    if key in w:
                        path = rewrite(expand(w[key], ctx), b)
                        snap[key] = open(path).read() if os.path.isfile(path) else None
                res.snaps.append(snap)
            else:
                ok(s["uses"].startswith(MODELLED_ACTIONS), "step uses %s, which this test does not model" % s["uses"])
                allowed = ALLOWED_WITH[s["uses"].split("@")[0]]
                extra_in = set(s.get("with") or {}) - allowed
                ok(not extra_in, "step %s is given the input(s) %s, which this test does not model (the harness runs this repository's commit)" % (s["uses"].split("@")[0], sorted(extra_in)))
                if s["uses"].startswith("actions/upload-artifact@"):
                    res.uploads.append(s)
            continue
        if "run" not in s:
            continue
        shell = s.get("shell")
        ok(shell in (None, "bash"), "step %r sets shell %r, which this test does not model" % (s.get("name"), shell))
        cwd = b.repo
        if s.get("working-directory"):
            cwd = os.path.normpath(os.path.join(b.repo, rewrite(expand(s["working-directory"], ctx), b)))
            ok(os.path.isdir(cwd), "step %r: working-directory %r does not exist" % (s.get("name"), s["working-directory"]))
        out_file = os.path.join(b.dir, "out-%d" % i)
        open(out_file, "w").close()
        env = dict(os.environ)
        for k in list(env):
            if k.startswith(("FSCACHE_", "GITHUB_", "NO_REGISTRY", "GH_", "TAMPER_")) or k.lower() in ("http_proxy", "https_proxy", "all_proxy"):
                del env[k]
        env.update({"PATH": b.bin + os.pathsep + env["PATH"], "CALLS": b.calls, "FX": b.fx, "REG_PORT": str(b.reg.port),
                    "GITHUB_OUTPUT": out_file, "GITHUB_SHA": b.sha, "GITHUB_REPOSITORY": OWNER + "/cache", "GITHUB_WORKSPACE": b.repo,
                    "GITHUB_ACTOR": "ci-actor", "PYTHONDONTWRITEBYTECODE": "1", "HOME": b.dir, "GH_EXPECT_REPO": OWNER + "/cache"})
        env.update(getattr(b, "extra_env", {}))
        if not b.with_registry:
            env["NO_REGISTRY"] = "1"
        for k, v in (s.get("env") or {}).items():
            env[k] = expand(v, ctx)
        script = os.path.join(b.dir, "step-%d.sh" % i)
        with open(script, "w") as f:
            f.write(rewrite(expand(s["run"], ctx), b))
        p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", script], cwd=cwd, env=env, capture_output=True, text=True, timeout=240)
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
            if norm(expand(s.get("continue-on-error", ""), ctx)) == "true":
                res.ignored.append(s.get("name"))      # GitHub goes on to the next step
                continue
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


def snap_of(res, prefix):
    m = [x for x in res.snaps if x["uses"].startswith(prefix)]
    eq(len(m), 1, "attest steps %s reached" % prefix)
    return m[0]


def snap_lines(snap):
    ok(snap.get("subject-checksums") is not None, "the subject file did not exist when %s was reached" % snap["uses"])
    return [l for l in snap["subject-checksums"].split("\n") if l.strip()]


def snap_pred(snap):
    ok(snap.get("predicate-path") is not None, "the predicate file did not exist when %s was reached" % snap["uses"])
    return json.loads(snap["predicate-path"])


# ---------------------------------------------------------------- release-mode assemble, executed
_CACHE = {}


def assemble_run(mode="release", reg=None, fx=None, fail_after=None, extra_env=None):
    reg = reg or Reg(fail_after=fail_after)
    fx = fx or fixtures()
    for var in fx.values():
        reg.seed(var)
    b = make_box(reg, fx)
    b.extra_env.update(extra_env or {})
    reject_unmodelled_settings("stage-image.yml", "assemble")
    res = run_steps(b, assemble(), mode)
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
    pred = snap_pred(snap_of(r, "actions/attest@"))
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
    ok(len(r.snaps) == 2, "expected the image-build and the provenance attest steps, reached %d" % len(r.snaps))
    for sn in r.snaps:
        eq(sorted(snap_lines(sn)), sorted("%s  cache-candidates-%s" % (hexof(want[v]), v) for v in VARIANTS), "subjects when %s was reached" % sn["uses"])


@case("1", "e2e: D appears in no attest input, no step output and no job output (it is only ever read)")
def _():
    r = released()
    need_ok(r)
    ds = [r.fx[v]["digest"] for v in VARIANTS]
    texts = []
    ok(len(r.snaps) == 2, "expected two attest steps, reached %d" % len(r.snaps))
    for sn in r.snaps:
        for key in ("predicate-path", "subject-checksums"):
            if key in sn:
                ok(sn[key] is not None, "the %s of %s did not exist when it was reached" % (key, sn["uses"]))
                texts.append((sn["uses"] + " " + key, sn[key]))
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
    reject_unmodelled_settings("stage-image.yml", "assemble")
    res = run_steps(b, assemble(), "pr")
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
def repro_run(digests, rebuilt, vex_bytes=None, gh_attested=None):
    """run stage-reproducibility's steps after the buildx setup against a rebuild that yields `rebuilt`; no registry"""
    reg = Reg()
    b = make_box(reg, rebuilt, vex_bytes=vex_bytes, with_registry=False)
    if gh_attested is not None:
        b.extra_env["GH_ATTESTED"] = ",".join(gh_attested)
    reject_unmodelled_settings("stage-reproducibility.yml", "reproduce")
    res = run_steps(b, repro_steps(), "release", extra_ctx={"inputs.digests": json.dumps(digests, separators=(",", ":"))})
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
    lines = sorted(snap_lines(snap_of(r, "actions/attest@")))
    eq(lines, sorted("%s  cache-candidates-%s" % (hexof(F[v]), v) for v in VARIANTS), "reproducibility subjects")
    pred = snap_pred(snap_of(r, "actions/attest@"))
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



# ================================================================ review round 1: operands, failure semantics, snapshots
# The downstream chain is frozen: every workflow after (and around) the image stage must be exactly what it was before this
# change, comparing the PARSED structure so comments and whitespace do not count. Per file: every top-level key (name, on,
# permissions, env, ...), every job key (needs, with, env, permissions, outputs, if, ...) and every step (id, name, uses,
# with, env, if, shell, ..., and its run text as ordered, comment-free, whitespace-collapsed lines) is hashed on its own,
# so a differing path is named. Nothing here selects by keyword: a workflow-level env, an inserted line, a reordered step or
# a changed `needs:` all differ. Regenerate deliberately with AC5_DUMP_GOLDEN=1 (prints the JSON for the tree in AC5_ROOT).
FROZEN_FILES = ["release.yml", "acceptance.yml", "scan.yml", "main-candidate-rescan.yml", "stage-build.yml", "stage-admission.yml", "stage-verify.yml",
                "stage-acceptance-artifacts.yml", "stage-acceptance-egress.yml", "stage-acceptance-k8s.yml", "stage-acceptance-predicate.yml",
                "stage-authorize.yml", "stage-promote.yml"]
OPERAND_FILES = FROZEN_FILES
USES_FILES = ["stage-image.yml", "stage-reproducibility.yml"]
GOLDEN = json.loads(r'''{
"frozen": {
"acceptance.yml": {
"jobs.acceptance-gradle.name": "23a3dc9bff291b16",
"jobs.acceptance-gradle.outputs": "8b1e58a66c03ac2a",
"jobs.acceptance-gradle.permissions": "18654c780b72f615",
"jobs.acceptance-gradle.runs-on": "a89f3a1c7e4302eb",
"jobs.acceptance-gradle.steps.count": 25,
"jobs.acceptance-gradle.steps[0]": "3ef4af68ef144f12",
"jobs.acceptance-gradle.steps[10]": "3614c4fe094b451b",
"jobs.acceptance-gradle.steps[11]": "094e9554209e0db5",
"jobs.acceptance-gradle.steps[12]": "212c3998b2a79a9a",
"jobs.acceptance-gradle.steps[13]": "fbdccd81b85b43ff",
"jobs.acceptance-gradle.steps[14]": "163a68e293d8a48f",
"jobs.acceptance-gradle.steps[15]": "087a33195a99f8f9",
"jobs.acceptance-gradle.steps[16]": "1af6b9b111880d69",
"jobs.acceptance-gradle.steps[17]": "50827b5ac6dbe452",
"jobs.acceptance-gradle.steps[18]": "3ca18eed61c6f9e0",
"jobs.acceptance-gradle.steps[19]": "d4358467364b8425",
"jobs.acceptance-gradle.steps[1]": "c70238c510acbaa9",
"jobs.acceptance-gradle.steps[20]": "877cd6f38bc7eb94",
"jobs.acceptance-gradle.steps[21]": "6e7211c3a3cfc002",
"jobs.acceptance-gradle.steps[22]": "82e936d9aadece1e",
"jobs.acceptance-gradle.steps[23]": "5108c20b252a4ac8",
"jobs.acceptance-gradle.steps[24]": "63df53aea9e05567",
"jobs.acceptance-gradle.steps[2]": "d2476c6c32ee1429",
"jobs.acceptance-gradle.steps[3]": "1a8439b8a778b22d",
"jobs.acceptance-gradle.steps[4]": "c3f6b1c6dd05fe7c",
"jobs.acceptance-gradle.steps[5]": "76353e3179ad982c",
"jobs.acceptance-gradle.steps[6]": "67ea749c806b4169",
"jobs.acceptance-gradle.steps[7]": "d9cc2c7d883c81ac",
"jobs.acceptance-gradle.steps[8]": "d42fe1c84ec7b20d",
"jobs.acceptance-gradle.steps[9]": "48d098b6e42c7d27",
"jobs.acceptance-maven.env": "d7bfa22e06d22809",
"jobs.acceptance-maven.name": "36f8ef6d53438101",
"jobs.acceptance-maven.outputs": "8b1e58a66c03ac2a",
"jobs.acceptance-maven.permissions": "18654c780b72f615",
"jobs.acceptance-maven.runs-on": "a89f3a1c7e4302eb",
"jobs.acceptance-maven.steps.count": 21,
"jobs.acceptance-maven.steps[0]": "3ef4af68ef144f12",
"jobs.acceptance-maven.steps[10]": "276325b844adec19",
"jobs.acceptance-maven.steps[11]": "89ca8fcf5dbfb20a",
"jobs.acceptance-maven.steps[12]": "7cd8b7f28db6d35c",
"jobs.acceptance-maven.steps[13]": "294078d9c13e9cf9",
"jobs.acceptance-maven.steps[14]": "a259dae98dec1197",
"jobs.acceptance-maven.steps[15]": "ed30f97a9ba95b68",
"jobs.acceptance-maven.steps[16]": "5a51a9d0f5a7d556",
"jobs.acceptance-maven.steps[17]": "f014b9874bbd6a87",
"jobs.acceptance-maven.steps[18]": "44bfdf0b6005e2d3",
"jobs.acceptance-maven.steps[19]": "1856f4d199fbf52b",
"jobs.acceptance-maven.steps[1]": "c70238c510acbaa9",
"jobs.acceptance-maven.steps[20]": "1a98893a09b3adf5",
"jobs.acceptance-maven.steps[2]": "1612dfc67c3ce955",
"jobs.acceptance-maven.steps[3]": "1611370468166a1b",
"jobs.acceptance-maven.steps[4]": "44b5bdd4014c8baf",
"jobs.acceptance-maven.steps[5]": "a2f420a7b8cfbde1",
"jobs.acceptance-maven.steps[6]": "1ca8df4269a9dc7b",
"jobs.acceptance-maven.steps[7]": "902ec3973bf2ce3f",
"jobs.acceptance-maven.steps[8]": "62a6659c452fd4c8",
"jobs.acceptance-maven.steps[9]": "3214858ca5f22326",
"jobs.acceptance-maven.strategy": "8a9e42e1b368bb26",
"top.name": "c580c13796ee26eb",
"top.on": "c9393c97066efb94",
"top.permissions": "d8d6aceb1abc4199"
},
"main-candidate-rescan.yml": {
"jobs.assemble.needs": "e99adbe058517220",
"jobs.assemble.permissions": "44d3feb81dacebd3",
"jobs.assemble.steps.count": 0,
"jobs.assemble.uses": "91e9f8c5c2b736cf",
"jobs.assemble.with": "51efba0b020dd8b2",
"jobs.build.permissions": "a58f4623360a36d1",
"jobs.build.steps.count": 0,
"jobs.build.uses": "612d49c728b7f0f8",
"jobs.build.with": "59e1274e29ef1d5b",
"jobs.manifests.name": "a29233c1d979ae45",
"jobs.manifests.outputs": "15a5d7c4573bbe83",
"jobs.manifests.runs-on": "a89f3a1c7e4302eb",
"jobs.manifests.steps.count": 2,
"jobs.manifests.steps[0]": "8957e1c08310d968",
"jobs.manifests.steps[1]": "985c85e2f7851eec",
"jobs.panel-google.environment": "7649b444a37e5ea5",
"jobs.panel-google.name": "d1e4ec7902cc017c",
"jobs.panel-google.needs": "7f4f0bf77f49c743",
"jobs.panel-google.permissions": "d57abeeb8232850a",
"jobs.panel-google.runs-on": "a89f3a1c7e4302eb",
"jobs.panel-google.steps.count": 6,
"jobs.panel-google.steps[0]": "8957e1c08310d968",
"jobs.panel-google.steps[1]": "0f32fe39075f8c34",
"jobs.panel-google.steps[2]": "3302c7616ee3c6f3",
"jobs.panel-google.steps[3]": "538df9844fecac28",
"jobs.panel-google.steps[4]": "37fd2f5c383cf7e7",
"jobs.panel-google.steps[5]": "a6772f043bca00b0",
"jobs.panel-grype.name": "265d1350e1bd696d",
"jobs.panel-grype.needs": "7f4f0bf77f49c743",
"jobs.panel-grype.permissions": "d8d6aceb1abc4199",
"jobs.panel-grype.runs-on": "a89f3a1c7e4302eb",
"jobs.panel-grype.steps.count": 5,
"jobs.panel-grype.steps[0]": "8957e1c08310d968",
"jobs.panel-grype.steps[1]": "0f32fe39075f8c34",
"jobs.panel-grype.steps[2]": "b5df81c7da967fc8",
"jobs.panel-grype.steps[3]": "62666c9c4cdbad27",
"jobs.panel-grype.steps[4]": "62b740e6ec42cb56",
"jobs.panel-inspector.env": "2674324ee0e35ee3",
"jobs.panel-inspector.name": "6bf5f254676b7fc6",
"jobs.panel-inspector.needs": "7f4f0bf77f49c743",
"jobs.panel-inspector.permissions": "d57abeeb8232850a",
"jobs.panel-inspector.runs-on": "a89f3a1c7e4302eb",
"jobs.panel-inspector.steps.count": 6,
"jobs.panel-inspector.steps[0]": "8957e1c08310d968",
"jobs.panel-inspector.steps[1]": "0f32fe39075f8c34",
"jobs.panel-inspector.steps[2]": "41b30b4b2810341f",
"jobs.panel-inspector.steps[3]": "3f3a7adb472a1081",
"jobs.panel-inspector.steps[4]": "f2baee09f7d2450b",
"jobs.panel-inspector.steps[5]": "c980ae1f4b9037cc",
"jobs.panel-scout.environment": "7649b444a37e5ea5",
"jobs.panel-scout.name": "b46cb3154bf24bbc",
"jobs.panel-scout.needs": "7f4f0bf77f49c743",
"jobs.panel-scout.permissions": "d8d6aceb1abc4199",
"jobs.panel-scout.runs-on": "a89f3a1c7e4302eb",
"jobs.panel-scout.steps.count": 8,
"jobs.panel-scout.steps[0]": "8957e1c08310d968",
"jobs.panel-scout.steps[1]": "0f32fe39075f8c34",
"jobs.panel-scout.steps[2]": "f1306bd40de9dd12",
"jobs.panel-scout.steps[3]": "96becc0fa388cb3b",
"jobs.panel-scout.steps[4]": "2429e8a319db709e",
"jobs.panel-scout.steps[5]": "90fdc8c650d19508",
"jobs.panel-scout.steps[6]": "487d99e43b00e430",
"jobs.panel-scout.steps[7]": "4e49ba4920668dfd",
"jobs.panel.if": "98a106d9c58360f1",
"jobs.panel.name": "2a40c5f398fa68ad",
"jobs.panel.needs": "525b9f81d4755d44",
"jobs.panel.permissions": "0686420875052835",
"jobs.panel.runs-on": "a89f3a1c7e4302eb",
"jobs.panel.steps.count": 6,
"jobs.panel.steps[0]": "8957e1c08310d968",
"jobs.panel.steps[1]": "b1134ef9ccb437ac",
"jobs.panel.steps[2]": "e35a6419125d4fff",
"jobs.panel.steps[3]": "73db4d92d7cb6d20",
"jobs.panel.steps[4]": "be61f8bd87662be7",
"jobs.panel.steps[5]": "f9e849a2c1c3034a",
"jobs.rescan.env": "2dc65141eca35963",
"jobs.rescan.if": "b0cd8dac63cbbdd0",
"jobs.rescan.name": "d9cf1a8aa9d84a79",
"jobs.rescan.needs": "bb01830be8645f79",
"jobs.rescan.permissions": "af5cc6f35813e232",
"jobs.rescan.runs-on": "a89f3a1c7e4302eb",
"jobs.rescan.steps.count": 12,
"jobs.rescan.steps[0]": "8957e1c08310d968",
"jobs.rescan.steps[10]": "9fd724db29c92c2b",
"jobs.rescan.steps[11]": "cec06aac54eed85e",
"jobs.rescan.steps[1]": "d609c3b40a723124",
"jobs.rescan.steps[2]": "886a9788af28b148",
"jobs.rescan.steps[3]": "07bb8b0fe1ad9c44",
"jobs.rescan.steps[4]": "10412d0f8e1aeb31",
"jobs.rescan.steps[5]": "e373256576be2fc3",
"jobs.rescan.steps[6]": "cd1057760f2e9cca",
"jobs.rescan.steps[7]": "94119dc5bcae858f",
"jobs.rescan.steps[8]": "03429d20415fdb5e",
"jobs.rescan.steps[9]": "fa0dd7edbcca43aa",
"jobs.rescan.strategy": "1d0c1e003cf5b573",
"jobs.scanner-reports.name": "96be70aa1bf1ee5e",
"jobs.scanner-reports.needs": "7f4f0bf77f49c743",
"jobs.scanner-reports.permissions": "d8d6aceb1abc4199",
"jobs.scanner-reports.runs-on": "a89f3a1c7e4302eb",
"jobs.scanner-reports.steps.count": 5,
"jobs.scanner-reports.steps[0]": "3ef4af68ef144f12",
"jobs.scanner-reports.steps[1]": "0f32fe39075f8c34",
"jobs.scanner-reports.steps[2]": "effcafb706c80b6d",
"jobs.scanner-reports.steps[3]": "5d79aa7d6978f70e",
"jobs.scanner-reports.steps[4]": "005446768edb73f3",
"jobs.scout-root-cause.environment": "7649b444a37e5ea5",
"jobs.scout-root-cause.if": "ad899c23175d269d",
"jobs.scout-root-cause.permissions": "005c397eb9ccf2cc",
"jobs.scout-root-cause.runs-on": "a89f3a1c7e4302eb",
"jobs.scout-root-cause.steps.count": 6,
"jobs.scout-root-cause.steps[0]": "8957e1c08310d968",
"jobs.scout-root-cause.steps[1]": "6dd648dfe0bbe447",
"jobs.scout-root-cause.steps[2]": "b1cf6840369446ba",
"jobs.scout-root-cause.steps[3]": "6fa3381d7476e810",
"jobs.scout-root-cause.steps[4]": "6c94475b7a30282d",
"jobs.scout-root-cause.steps[5]": "9b38e435afed093c",
"top.name": "38fb41b896e2a732",
"top.on": "15f364a1ddc3bc40",
"top.permissions": "d8d6aceb1abc4199"
},
"release.yml": {
"jobs.acceptance-artifacts.needs": "1361140fdb53b92f",
"jobs.acceptance-artifacts.steps.count": 0,
"jobs.acceptance-artifacts.uses": "5e7ec7f9bae4ecec",
"jobs.acceptance-artifacts.with": "d5d9e13051f0690d",
"jobs.acceptance-egress.needs": "2501eac43efb839a",
"jobs.acceptance-egress.steps.count": 0,
"jobs.acceptance-egress.uses": "758d25b9a062517a",
"jobs.acceptance-egress.with": "2193a3390d9d8b13",
"jobs.acceptance-k8s.needs": "2501eac43efb839a",
"jobs.acceptance-k8s.steps.count": 0,
"jobs.acceptance-k8s.uses": "c93006cb1590e279",
"jobs.acceptance-k8s.with": "2193a3390d9d8b13",
"jobs.acceptance-predicate.needs": "acb7ff19f0da1e18",
"jobs.acceptance-predicate.steps.count": 0,
"jobs.acceptance-predicate.uses": "e46020ec58177ed9",
"jobs.acceptance-predicate.with": "10236a20911962d6",
"jobs.acceptance.needs": "2501eac43efb839a",
"jobs.acceptance.steps.count": 0,
"jobs.acceptance.uses": "1afeb4fbb0a126e2",
"jobs.acceptance.with": "46bcedddd4c460d8",
"jobs.admission.if": "46e2c472c1004009",
"jobs.admission.steps.count": 0,
"jobs.admission.uses": "e51f437c9f1288f5",
"jobs.authorization.needs": "17264518e74142d8",
"jobs.authorization.permissions": "8e5c77369a33e598",
"jobs.authorization.steps.count": 0,
"jobs.authorization.uses": "021eb2d6709c7174",
"jobs.authorization.with": "940793587f830830",
"jobs.build.needs": "5f37bb96609f12de",
"jobs.build.steps.count": 0,
"jobs.build.uses": "612d49c728b7f0f8",
"jobs.build.with": "308f822e38ca2f15",
"jobs.decide.concurrency": "7fc08e23cf0769fd",
"jobs.decide.environment": "7649b444a37e5ea5",
"jobs.decide.if": "603459310599b3b7",
"jobs.decide.outputs": "9c9943d569f1d57e",
"jobs.decide.permissions": "a932f4e82ff3f335",
"jobs.decide.runs-on": "a89f3a1c7e4302eb",
"jobs.decide.steps.count": 12,
"jobs.decide.steps[0]": "405acc47f6d0fdb0",
"jobs.decide.steps[10]": "549db2db1d1cdb44",
"jobs.decide.steps[11]": "3cafecd8014332ed",
"jobs.decide.steps[1]": "d4dba7735cf5575a",
"jobs.decide.steps[2]": "ad4b469f047263da",
"jobs.decide.steps[3]": "cdbf1fc0231a0857",
"jobs.decide.steps[4]": "3b0b5132ec379661",
"jobs.decide.steps[5]": "b05756de5bf1883c",
"jobs.decide.steps[6]": "edad9d5d8522b05f",
"jobs.decide.steps[7]": "755264d42b3df77d",
"jobs.decide.steps[8]": "a52163122165a228",
"jobs.decide.steps[9]": "9e8d226ef867f3cc",
"jobs.image.needs": "e99adbe058517220",
"jobs.image.steps.count": 0,
"jobs.image.uses": "91e9f8c5c2b736cf",
"jobs.image.with": "c8f85ee377f4fe90",
"jobs.patch-failed.if": "bdb1dc1e59c352b9",
"jobs.patch-failed.needs": "e7853d113646fe91",
"jobs.patch-failed.permissions": "0686420875052835",
"jobs.patch-failed.runs-on": "a89f3a1c7e4302eb",
"jobs.patch-failed.steps.count": 1,
"jobs.patch-failed.steps[0]": "a18eea554dd13958",
"jobs.patch-notes.environment": "7649b444a37e5ea5",
"jobs.patch-notes.if": "3a0ac5a04a0f6ea7",
"jobs.patch-notes.needs": "a63a25a2e30fb6b0",
"jobs.patch-notes.permissions": "d8d6aceb1abc4199",
"jobs.patch-notes.runs-on": "a89f3a1c7e4302eb",
"jobs.patch-notes.steps.count": 3,
"jobs.patch-notes.steps[0]": "59132c244ea7912d",
"jobs.patch-notes.steps[1]": "0de3c4c2d9cd6964",
"jobs.patch-notes.steps[2]": "5cdfc1b55ef23071",
"jobs.promotion.needs": "edb5532eeccc2adb",
"jobs.promotion.secrets": "d95aec779901c62f",
"jobs.promotion.steps.count": 0,
"jobs.promotion.uses": "5c9686e5c5cd9146",
"jobs.promotion.with": "a0647ff48307496b",
"jobs.reproducibility.needs": "88545b52a8a2c580",
"jobs.reproducibility.steps.count": 0,
"jobs.reproducibility.uses": "c73e5f049aeae937",
"jobs.reproducibility.with": "b839b9d24c6e9bdd",
"jobs.scans.needs": "1361140fdb53b92f",
"jobs.scans.secrets": "d95aec779901c62f",
"jobs.scans.steps.count": 0,
"jobs.scans.uses": "1074bf1f116b9091",
"jobs.scans.with": "b839b9d24c6e9bdd",
"top.name": "3c449ba17a333bf2",
"top.on": "20b8867dfc7f2d40",
"top.permissions": "c3736a8a5205afc6"
},
"scan.yml": {
"jobs.artifact-acceptance.needs": "e99adbe058517220",
"jobs.artifact-acceptance.permissions": "18654c780b72f615",
"jobs.artifact-acceptance.steps.count": 0,
"jobs.artifact-acceptance.uses": "5e7ec7f9bae4ecec",
"jobs.artifact-acceptance.with": "1ee90f8fe516b2a1",
"jobs.assemble-b.needs": "e99adbe058517220",
"jobs.assemble-b.permissions": "44d3feb81dacebd3",
"jobs.assemble-b.steps.count": 0,
"jobs.assemble-b.uses": "91e9f8c5c2b736cf",
"jobs.assemble-b.with": "fda673c810c68fc3",
"jobs.assemble.needs": "e99adbe058517220",
"jobs.assemble.permissions": "44d3feb81dacebd3",
"jobs.assemble.steps.count": 0,
"jobs.assemble.uses": "91e9f8c5c2b736cf",
"jobs.assemble.with": "51efba0b020dd8b2",
"jobs.build.permissions": "44d3feb81dacebd3",
"jobs.build.steps.count": 0,
"jobs.build.uses": "612d49c728b7f0f8",
"jobs.build.with": "59e1274e29ef1d5b",
"jobs.reproducibility.name": "449cc089476fcc90",
"jobs.reproducibility.needs": "6908d8b28fc4232f",
"jobs.reproducibility.runs-on": "a89f3a1c7e4302eb",
"jobs.reproducibility.steps.count": 1,
"jobs.reproducibility.steps[0]": "bea4fb17b1e60124",
"jobs.scan.if": "3e7f2749e07c18b0",
"jobs.scan.name": "dfa11b56dbf9f8b9",
"jobs.scan.needs": "68ed86cd694e4db9",
"jobs.scan.runs-on": "a89f3a1c7e4302eb",
"jobs.scan.steps.count": 1,
"jobs.scan.steps[0]": "4040805d5cbd33af",
"jobs.scanner.env": "2674324ee0e35ee3",
"jobs.scanner.name": "7b3cf0fe0620cac4",
"jobs.scanner.needs": "8c6d724718083163",
"jobs.scanner.permissions": "d57abeeb8232850a",
"jobs.scanner.runs-on": "a89f3a1c7e4302eb",
"jobs.scanner.steps.count": 10,
"jobs.scanner.steps[0]": "3ef4af68ef144f12",
"jobs.scanner.steps[1]": "0f32fe39075f8c34",
"jobs.scanner.steps[2]": "fc76684a18e22bae",
"jobs.scanner.steps[3]": "8a77a82691c0cfe5",
"jobs.scanner.steps[4]": "5329637f72722ca4",
"jobs.scanner.steps[5]": "e5231dd405a24d41",
"jobs.scanner.steps[6]": "1e00f670bcb2fdfe",
"jobs.scanner.steps[7]": "d5a1e28dfdca6c93",
"jobs.scanner.steps[8]": "1541be82ccce3270",
"jobs.scanner.steps[9]": "fc3c321ff1ce05dc",
"jobs.scanner.strategy": "2c049e5b9ca29b43",
"jobs.scanners.name": "d1d26c67d18bd05d",
"jobs.scanners.outputs": "90d7299c6d63a2ad",
"jobs.scanners.runs-on": "a89f3a1c7e4302eb",
"jobs.scanners.steps.count": 2,
"jobs.scanners.steps[0]": "3ef4af68ef144f12",
"jobs.scanners.steps[1]": "2037c706a503c3fc",
"top.name": "dfa11b56dbf9f8b9",
"top.on": "6663e3ac06317422",
"top.permissions": "d8d6aceb1abc4199"
},
"stage-acceptance-artifacts.yml": {
"jobs.artifacts.name": "6f1976ed2d6afc32",
"jobs.artifacts.outputs": "8b1e58a66c03ac2a",
"jobs.artifacts.permissions": "18654c780b72f615",
"jobs.artifacts.runs-on": "a89f3a1c7e4302eb",
"jobs.artifacts.steps.count": 12,
"jobs.artifacts.steps[0]": "3ef4af68ef144f12",
"jobs.artifacts.steps[10]": "9637d3669e4f68c0",
"jobs.artifacts.steps[11]": "f6410d4414c23ae4",
"jobs.artifacts.steps[1]": "57f1cabf57203fb4",
"jobs.artifacts.steps[2]": "a44d81947f6b8f80",
"jobs.artifacts.steps[3]": "ecab8fbc1b639469",
"jobs.artifacts.steps[4]": "e30abc31e064335b",
"jobs.artifacts.steps[5]": "a794550f69805671",
"jobs.artifacts.steps[6]": "1c8ee0e3d8d52388",
"jobs.artifacts.steps[7]": "29358ced7a6f1e29",
"jobs.artifacts.steps[8]": "0fa66a19d6213eb5",
"jobs.artifacts.steps[9]": "48ee6f2d41370b3c",
"top.name": "0616fc9e325d6dff",
"top.on": "c52eb6cc51b16dc1",
"top.permissions": "d8d6aceb1abc4199"
},
"stage-acceptance-egress.yml": {
"jobs.egress.name": "76e36b2a4330d95c",
"jobs.egress.outputs": "8b1e58a66c03ac2a",
"jobs.egress.permissions": "18654c780b72f615",
"jobs.egress.runs-on": "a89f3a1c7e4302eb",
"jobs.egress.steps.count": 5,
"jobs.egress.steps[0]": "3ef4af68ef144f12",
"jobs.egress.steps[1]": "e24d34535a4cf1e8",
"jobs.egress.steps[2]": "6084bebf287add70",
"jobs.egress.steps[3]": "0766e743a10104ff",
"jobs.egress.steps[4]": "6091c60bd80aafa1",
"top.name": "2abf953f2edb26ea",
"top.on": "07f4896caa755b58",
"top.permissions": "d8d6aceb1abc4199"
},
"stage-acceptance-k8s.yml": {
"jobs.k8s.env": "b8babae2b57311f9",
"jobs.k8s.name": "be0364ec9dbbcac3",
"jobs.k8s.outputs": "8b1e58a66c03ac2a",
"jobs.k8s.permissions": "18654c780b72f615",
"jobs.k8s.runs-on": "a89f3a1c7e4302eb",
"jobs.k8s.steps.count": 12,
"jobs.k8s.steps[0]": "3ef4af68ef144f12",
"jobs.k8s.steps[10]": "9bcc697eed299c6d",
"jobs.k8s.steps[11]": "b09439deb0a7257b",
"jobs.k8s.steps[1]": "b6b067d5a265d705",
"jobs.k8s.steps[2]": "68076c4610b5da09",
"jobs.k8s.steps[3]": "70743d508bba054f",
"jobs.k8s.steps[4]": "c1ca53d68e4c3eea",
"jobs.k8s.steps[5]": "1a120d514c08102b",
"jobs.k8s.steps[6]": "cc3f4858d18bba3a",
"jobs.k8s.steps[7]": "d310681d14b1b981",
"jobs.k8s.steps[8]": "b68a07c69d3b35ef",
"jobs.k8s.steps[9]": "54f9e7344c6f954d",
"top.name": "a3b9c45d305de91f",
"top.on": "2b910c6cd256ccde",
"top.permissions": "d8d6aceb1abc4199"
},
"stage-acceptance-predicate.yml": {
"jobs.predicate.name": "97de9e168a3a6647",
"jobs.predicate.permissions": "a58f4623360a36d1",
"jobs.predicate.runs-on": "a89f3a1c7e4302eb",
"jobs.predicate.steps.count": 4,
"jobs.predicate.steps[0]": "3ef4af68ef144f12",
"jobs.predicate.steps[1]": "366e785c7e9a6d2d",
"jobs.predicate.steps[2]": "253a4f10b3d3ad8c",
"jobs.predicate.steps[3]": "c6aae01330555b5d",
"top.name": "700ae035d9e2bb42",
"top.on": "5a6a6fb0a519399f",
"top.permissions": "d8d6aceb1abc4199"
},
"stage-admission.yml": {
"jobs.admit.name": "e37ea08f87ebbce8",
"jobs.admit.outputs": "dc2fecb5804741af",
"jobs.admit.permissions": "0c9caca5f30ec892",
"jobs.admit.runs-on": "a89f3a1c7e4302eb",
"jobs.admit.steps.count": 12,
"jobs.admit.steps[0]": "d292ab413501d660",
"jobs.admit.steps[10]": "4e9990b4a75aa083",
"jobs.admit.steps[11]": "57218db4a5f17666",
"jobs.admit.steps[1]": "60a60c83e9bff43f",
"jobs.admit.steps[2]": "16d7bcf6b46cf429",
"jobs.admit.steps[3]": "1fca1bdbf21a4536",
"jobs.admit.steps[4]": "4f3d642dcba12d44",
"jobs.admit.steps[5]": "9226348f0bf17821",
"jobs.admit.steps[6]": "d186d874d52652a5",
"jobs.admit.steps[7]": "f46c4bbdbd908b44",
"jobs.admit.steps[8]": "ca3b02ea0431f572",
"jobs.admit.steps[9]": "28d49e1c553cfce3",
"top.name": "5390a18a2739b7ef",
"top.on": "07531aef4834d817",
"top.permissions": "d8d6aceb1abc4199"
},
"stage-authorize.yml": {
"jobs.authorize.name": "79c59cc844b66519",
"jobs.authorize.permissions": "8e5c77369a33e598",
"jobs.authorize.runs-on": "a89f3a1c7e4302eb",
"jobs.authorize.steps.count": 8,
"jobs.authorize.steps[0]": "3ef4af68ef144f12",
"jobs.authorize.steps[1]": "cc0f804abf38bf35",
"jobs.authorize.steps[2]": "0d813cf063d8303c",
"jobs.authorize.steps[3]": "57f1cabf57203fb4",
"jobs.authorize.steps[4]": "63615e5bf73c9b54",
"jobs.authorize.steps[5]": "bb69d37c6afd25d2",
"jobs.authorize.steps[6]": "905cd7666102fcbf",
"jobs.authorize.steps[7]": "09d65d16a3fdcfe2",
"top.name": "cea41a53c00ebfa6",
"top.on": "d12871460d43fce6",
"top.permissions": "d8d6aceb1abc4199"
},
"stage-build.yml": {
"jobs.build.name": "e99adbe058517220",
"jobs.build.outputs": "d7231708e5647d78",
"jobs.build.permissions": "a58f4623360a36d1",
"jobs.build.runs-on": "a89f3a1c7e4302eb",
"jobs.build.steps.count": 15,
"jobs.build.steps[0]": "1c1d5bf429b27922",
"jobs.build.steps[10]": "3fefd27521f4973c",
"jobs.build.steps[11]": "0a2c4c8d9b9bbe90",
"jobs.build.steps[12]": "b6a114fe2746adea",
"jobs.build.steps[13]": "0f150936233012ed",
"jobs.build.steps[14]": "0bf2acb4e5ca56da",
"jobs.build.steps[1]": "0e69d46560bd89d4",
"jobs.build.steps[2]": "fec793d07f7d1b53",
"jobs.build.steps[3]": "cdcb4b6289ffc116",
"jobs.build.steps[4]": "3ed22b5d5858d04d",
"jobs.build.steps[5]": "e4ecd157ce7b0fe9",
"jobs.build.steps[6]": "a6ef0d48fc1b5a0d",
"jobs.build.steps[7]": "ee4dae14f34be291",
"jobs.build.steps[8]": "c2d664bc8c2b46ca",
"jobs.build.steps[9]": "4e9f9344da340ebe",
"top.name": "2b6fe62b1d5c299c",
"top.on": "ab08dc6f50d5a414",
"top.permissions": "d8d6aceb1abc4199"
},
"stage-promote.yml": {
"jobs.promote.environment": "847dbd914599c4e1",
"jobs.promote.name": "a024ceafdf8c85ad",
"jobs.promote.permissions": "ed59b26f6e3e67da",
"jobs.promote.runs-on": "a89f3a1c7e4302eb",
"jobs.promote.steps.count": 22,
"jobs.promote.steps[0]": "3ef4af68ef144f12",
"jobs.promote.steps[10]": "2bf3afdf2da759ed",
"jobs.promote.steps[11]": "dc6236c80a3f0689",
"jobs.promote.steps[12]": "93a16819d531b6a8",
"jobs.promote.steps[13]": "f0900e4ffdaa0a73",
"jobs.promote.steps[14]": "ccb44bb3ba9cc7f2",
"jobs.promote.steps[15]": "fac9490a7cb9b1bc",
"jobs.promote.steps[16]": "1e4a3ea031628054",
"jobs.promote.steps[17]": "35703128bb876093",
"jobs.promote.steps[18]": "7aef989eb40f143f",
"jobs.promote.steps[19]": "ca6b9e4c554ba256",
"jobs.promote.steps[1]": "d6479879773e5b1c",
"jobs.promote.steps[20]": "65c8d8bb21d287d2",
"jobs.promote.steps[21]": "8956bf01e2eea365",
"jobs.promote.steps[2]": "0232af291ba9f7f5",
"jobs.promote.steps[3]": "57f1cabf57203fb4",
"jobs.promote.steps[4]": "d68ee85b757afd48",
"jobs.promote.steps[5]": "3ed22b5d5858d04d",
"jobs.promote.steps[6]": "d5c32347fc17c3a0",
"jobs.promote.steps[7]": "551ed8755e63be20",
"jobs.promote.steps[8]": "c46b1ebe2fb53c77",
"jobs.promote.steps[9]": "60c3dbf00df8f31a",
"top.name": "e24c0972b5fa826f",
"top.on": "5392e22b77352f82",
"top.permissions": "d8d6aceb1abc4199"
},
"stage-verify.yml": {
"jobs.scan.name": "7b3cf0fe0620cac4",
"jobs.scan.needs": "11f30e0adce9adf1",
"jobs.scan.permissions": "da98527d1c6a9e9a",
"jobs.scan.runs-on": "a89f3a1c7e4302eb",
"jobs.scan.steps.count": 12,
"jobs.scan.steps[0]": "3ef4af68ef144f12",
"jobs.scan.steps[10]": "1a9575ee3bca4948",
"jobs.scan.steps[11]": "71a52a55fec1d9d5",
"jobs.scan.steps[1]": "cc0f804abf38bf35",
"jobs.scan.steps[2]": "836b790867ae1acd",
"jobs.scan.steps[3]": "97f0e819166d9a87",
"jobs.scan.steps[4]": "2f27b22bf7eaaa02",
"jobs.scan.steps[5]": "db2c738bad035a7a",
"jobs.scan.steps[6]": "16b0a6464fd7e084",
"jobs.scan.steps[7]": "50350b2e378cfc05",
"jobs.scan.steps[8]": "4081ed8a3ee43119",
"jobs.scan.steps[9]": "576fb65c881a30be",
"jobs.scan.strategy": "2c049e5b9ca29b43",
"jobs.scanners.name": "d1d26c67d18bd05d",
"jobs.scanners.outputs": "90d7299c6d63a2ad",
"jobs.scanners.runs-on": "a89f3a1c7e4302eb",
"jobs.scanners.steps.count": 2,
"jobs.scanners.steps[0]": "3ef4af68ef144f12",
"jobs.scanners.steps[1]": "7eb9a4751712b199",
"top.name": "445403c915078570",
"top.on": "e17ac4129c9453bb",
"top.permissions": "d8d6aceb1abc4199"
}
},
"uses": {
"stage-image.yml": [
[
"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
null
],
[
"actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
{
"name": "${{ inputs.dist-artifact }}",
"path": "dist/"
}
],
[
"docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069",
{
"driver-opts": "image=moby/buildkit:buildx-stable-1@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
}
],
[
"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
{
"if-no-files-found": "error",
"name": "oci-candidate",
"path": "/tmp/*.oci",
"retention-days": "1"
}
],
[
"actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
{
"predicate-path": "/tmp/image-build-predicate.json",
"predicate-type": "https://fosterstack.com/attestations/image-build/v1",
"subject-checksums": "/tmp/image-subjects.txt"
}
],
[
"actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
{
"subject-checksums": "/tmp/image-subjects.txt"
}
]
],
"stage-reproducibility.yml": [
[
"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
null
],
[
"actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
{
"name": "${{ inputs.dist-artifact }}",
"path": "dist/"
}
],
[
"docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069",
{
"driver-opts": "image=moby/buildkit:buildx-stable-1@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
}
],
[
"actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
{
"predicate-path": "/tmp/repro-predicate.json",
"predicate-type": "https://fosterstack.com/attestations/reproducibility/v1",
"subject-checksums": "/tmp/repro-subjects.txt"
}
]
]
}
}
''')


def nz(o, key=None):
    if isinstance(o, dict):
        return {k: nz(v, k) for k, v in sorted(o.items())}
    if isinstance(o, list):
        return [nz(x) for x in o]
    if isinstance(o, str):
        if key == "run":
            return [re.sub(r"\s+", " ", l).strip() for l in joined(o).split("\n") if l.strip() and not l.strip().startswith("#")]
        return re.sub(r"\s+", " ", o).strip()
    return o


def h(o):
    return hashlib.sha256(json.dumps(nz(o), sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def frozen_paths(name):
    d = wf(name)
    out = {}
    for k, v in d.items():
        if k != "jobs":
            out["top.%s" % k] = h(v)
    for jn, j in (d.get("jobs") or {}).items():
        for k, v in j.items():
            if k != "steps":
                out["jobs.%s.%s" % (jn, k)] = h(v)
        steps = j.get("steps") or []
        out["jobs.%s.steps.count" % jn] = len(steps)
        for i, st in enumerate(steps):
            out["jobs.%s.steps[%d]" % (jn, i)] = h(st)
    return out


def uses_pins(name):
    return [[st["uses"], nz(st.get("with"))] for j in wf(name)["jobs"].values() for st in (j.get("steps") or []) if st.get("uses")]


@case("3", "frozen: every downstream workflow is exactly what it was before this change (parsed structure: env at every level, ids, order, scripts)")
def _():
    for name in FROZEN_FILES:
        got, want = frozen_paths(name), GOLDEN["frozen"][name]
        if got != want:
            diff = sorted(k for k in set(got) | set(want) if got.get(k) != want.get(k))
            raise Fail("%s differs from the frozen golden at %s" % (name, diff[:6]))


@case("3", "frozen: no workflow outside the frozen set and the two image stages changed behaviour towards the release chain")
def _():
    known = set(FROZEN_FILES) | set(USES_FILES)
    for name in sorted(os.listdir(WF)):
        if name in known or not name.endswith(".yml"):
            continue
        d = wf(name)
        for jn, j in (d.get("jobs") or {}).items():
            ok(not re.search(r"stage-[a-z-]+\.yml", j.get("uses") or ""), "%s job %s calls a stage workflow outside the frozen set" % (name, jn))
            ok("needs.image" not in json.dumps(j) and "inputs.digests" not in json.dumps(j), "%s job %s reads the image stage's digests" % (name, jn))


@case("2", "pins: stage-image and stage-reproducibility use every action exactly as before (checkout takes no inputs: the release commit, this repository)")
def _():
    for name in USES_FILES:
        eq(uses_pins(name), GOLDEN["uses"][name], "%s action references and inputs" % name)
        for j in wf(name)["jobs"].values():
            for st in j["steps"]:
                if (st.get("uses") or "").startswith("actions/checkout@"):
                    ok("with" not in st, "checkout in %s takes inputs: %s" % (name, st.get("with")))


@case("2", "the attestation verifications name this repository and the signing workflow of the stage that made the statement")
def _():
    for name, job in (("stage-reproducibility.yml", "reproduce"), ("stage-image.yml", "assemble")):
        text = "\n".join(joined(run_of(s)) for s in steps_of(name, job) if "gh attestation verify" in run_of(s))
        ok(text.count("--repo \"${GITHUB_REPOSITORY}\"") == text.count("gh attestation verify") >= 1, "%s: a verification does not name --repo \"${GITHUB_REPOSITORY}\"" % name)
        for m in re.finditer(r"--signer-workflow\s+(\S+)", text):
            ok(m.group(1) in ('"${GITHUB_REPOSITORY}/.github/workflows/stage-image.yml"', '"${GITHUB_REPOSITORY}/.github/workflows/stage-build.yml"'), "%s: signer %s" % (name, m.group(1)))
        ok(text.count("--signer-workflow") == text.count("gh attestation verify"), "%s: a verification without a signer workflow" % name)


@case("3", "operands: stage-image's workflow_call output digests is exactly the assemble job's output, and release.yml reads only it")
def _():
    d = wf("stage-image.yml")
    eq(norm(d["on"]["workflow_call"]["outputs"]["digests"]["value"]), "jobs.assemble.outputs.digests", "stage-image workflow_call outputs.digests.value")
    eq(list(d["on"]["workflow_call"]["outputs"]), ["digests"], "stage-image workflow_call outputs")
    r = wf("release.yml")["jobs"]
    for jn, j in r.items():
        for k, v in (j.get("with") or {}).items():
            if "needs.image" in v:
                ok(norm(v) in ("needs.image.outputs.digests", "ghcr.io/${{github.repository_owner}}/cache-candidates@${{fromJSON(needs.image.outputs.digests).production}}".replace("${{", "").replace("}}", "")), "release.yml %s.%s reads %r" % (jn, k, v))


@case("3", "operands: no workflow outside the traversal calls the stage workflows, reads the image job's outputs or consumes inputs.digests")
def _():
    for name in sorted(os.listdir(WF)):
        if name in OPERAND_FILES or name in ("stage-image.yml", "stage-reproducibility.yml", "stage-build.yml", "stage-admission.yml") or not name.endswith(".yml"):
            continue
        d = wf(name)
        for jn, j in (d.get("jobs") or {}).items():
            ok(not re.search(r"stage-(image|reproducibility)\.yml", j.get("uses") or ""), "%s job %s calls an image-stage workflow outside the checked set" % (name, jn))
            ok("needs.image" not in json.dumps(j) and "inputs.digests" not in json.dumps(j), "%s job %s reads the image stage's digests outside the checked set" % (name, jn))


@case("3", "frozen: every reusable-workflow call of release.yml, acceptance.yml and scan.yml is among the frozen jobs")
def _():
    for name in ("release.yml", "acceptance.yml", "scan.yml", "main-candidate-rescan.yml"):
        for jn, j in wf(name)["jobs"].items():
            if j.get("uses"):
                for k in ("uses", "with", "needs"):
                    ok(k not in j or "jobs.%s.%s" % (jn, k) in GOLDEN["frozen"][name], "%s: call %s.%s is not frozen" % (name, jn, k))


# ---------------------------------------------------------------- reproducibility: nothing may weaken it
@case("2", "reproducibility steps carry no continue-on-error, if, working-directory, shell or timeout; the job only the keys it has today")
def _():
    d = wf("stage-reproducibility.yml")
    job = d["jobs"]["reproduce"]
    eq(sorted(job), ["name", "permissions", "runs-on", "steps"], "reproduce job keys")
    eq(sorted(d), sorted(["name", "on", "permissions", "jobs"]), "workflow keys")
    for st in job["steps"]:
        extra = set(st) - {"name", "id", "uses", "with", "run", "env"}
        ok(not extra, "step %r carries %s" % (st.get("name"), sorted(extra)))
        r = run_of(st)
        ok(not re.search(r"\|\|\s*(true|:|exit\s+0|echo)|set\s+\+e|;\s*true\b|\bcontinue\b", r), "step %r swallows a failure" % st.get("name"))
    ok(vex_steps(job["steps"]), "the changed steps are missing")


@case("2", "reproducibility still verifies the image-build attestation of every pushed digest (gh attestation verify on inputs.digests)")
def _():
    st = repro_steps()
    ver = [s for s in st if "gh attestation verify" in run_of(s) and "image-build/v1" in run_of(s)]
    eq(len(ver), 1, "steps verifying the image-build attestation")
    r = run_of(ver[0])
    ok("inputs.digests" in r and "oci://" in r and "https://fosterstack.com/attestations/image-build/v1" in r and "stage-image.yml" in r and "--repo" in r, "the verification no longer checks inputs.digests against stage-image's signature")
    ok(vex_steps(st), "the changed steps are missing")


@case("2", "e2e: the image-build attestation is verified for the pushed F of every variant, before anything is rebuilt")
def _():
    fx, F = repro_inputs()
    r = repro_run(F, fx)
    need_ok(r)
    cs = calls(r.box)
    for v in VARIANTS:
        hit = [i for i, c in enumerate(cs) if c.startswith("gh attestation verify oci://") and c.split()[3].endswith("cache-candidates@" + F[v]) and "image-build/v1" in c and "stage-image.yml" in c]
        ok(hit, "%s: the image-build attestation of F was never verified" % v)
        build = [i for i, c in enumerate(cs) if c.startswith("docker buildx build")]
        ok(hit[0] < min(build), "%s: verified after the rebuild started" % v)


@case("2", "e2e: a variant whose F carries no image-build attestation stops the reproducibility stage")
def _():
    fx, F = repro_inputs()
    repro_control(fx, F)
    for bad in VARIANTS:
        r = repro_run(F, fx, gh_attested=[F[v] for v in VARIANTS if v != bad])
        ok(r.failed is not None, "a missing attestation for %s did not stop the stage" % bad)
        ok(not r.attest, "the stage reached its attest step with an unattested %s" % bad)


@case("2", "e2e: a missing, empty or null pushed digest for any variant fails the stage")
def _():
    fx, F = repro_inputs()
    repro_control(fx, F)
    for v in VARIANTS:
        for how in ("missing", "empty", "null"):
            d = dict(F)
            if how == "missing":
                del d[v]
            else:
                d[v] = "" if how == "empty" else None
            r = repro_run(d, fx)
            ok(r.failed is not None, "%s pushed digest for %s did not fail the stage" % (how, v))
            ok(not r.attest, "the stage reached its attest step with a %s digest for %s" % (how, v))


# ---------------------------------------------------------------- attest inputs, read when the attest step is reached
@case("1", "e2e: each attest step's inputs are F at the moment it is reached (the image-build predicate, the provenance and the reproducibility ones)")
def _():
    r = released()
    need_ok(r)
    ok(len(r.snaps) == 2 and r.snaps[0]["uses"].startswith("actions/attest@") and r.snaps[1]["uses"].startswith("actions/attest-build-provenance@"), "the two attest steps were not reached in order: %s" % [x["uses"][:30] for x in r.snaps])
    want = want_final(r)
    for sn in r.snaps:
        eq(sorted(snap_lines(sn)), sorted("%s  cache-candidates-%s" % (hexof(want[v]), v) for v in VARIANTS), "subjects of %s when reached" % sn["uses"][:30])
    eq(snap_pred(r.snaps[0])["index_digests"], want, "the image-build predicate when reached")


@case("H", "harness: an attest step's input files are read when the step is reached, not afterwards")
def _():
    reg, fx = Reg(), fixtures()
    b = make_box(reg, fx)
    steps = [{"name": "a", "run": "echo first > /tmp/subj.txt"},
             {"name": "s", "uses": "actions/attest@" + "0" * 40, "with": {"subject-checksums": "/tmp/subj.txt"}},
             {"name": "b", "run": "echo second > /tmp/subj.txt"}]
    r = run_steps(b, steps, "release")
    need_ok(r)
    eq(r.snaps[0]["subject-checksums"], "first\n", "the snapshot")
    with open(os.path.join(b.t, "subj.txt")) as f:
        eq(f.read(), "second\n", "the file at the end")


@case("H", "harness: continue-on-error, working-directory and if are honoured; shell, defaults and unknown settings are refused loudly")
def _():
    reg, fx = Reg(), fixtures()
    b = make_box(reg, fx)
    steps = [{"name": "fails", "run": "exit 3", "continue-on-error": "true"},
             {"name": "after", "run": "pwd > /tmp/where.txt", "working-directory": "bin"},
             {"name": "skipped", "if": "inputs.mode == 'pr'", "run": "exit 9"}]
    r = run_steps(b, steps, "release")
    need_ok(r)
    eq(r.ignored, ["fails"], "ignored failures")
    with open(os.path.join(b.t, "where.txt")) as f:
        ok(f.read().strip().endswith("/repo/bin"), "working-directory not honoured")
    r2 = run_steps(make_box(reg, fx), [{"name": "x", "run": "exit 3"}, {"name": "y", "run": "true"}], "release")
    ok(r2.failed is not None and len(r2.results) == 1, "a failing step did not stop the job")
    for bad in ({"name": "x", "run": "true", "shell": "sh"}, {"name": "x", "run": "true", "timeout-minutes": "1"}, {"name": "x", "run": "true", "bogus": "1"}):
        try:
            run_steps(make_box(reg, fx), [bad], "release")
        except Fail:
            continue
        raise Fail("the harness ran a step with an unmodelled setting: %s" % bad)


# ---------------------------------------------------------------- the final-index step: failure semantics, late failures, login target
@case("1", "the final-index commands are bare commands: no &&, ||, ;, & or negation around vex-index, set -euo pipefail present")
def _():
    st, ix = final_index_steps()
    for i in ix:
        ok(re.search(r"set\s+-[a-z]*e[a-z]*u?[a-z]*\b", run_of(st[i])) and "pipefail" in run_of(st[i]), "step %r lacks set -euo pipefail" % st[i].get("name"))
        for sub, o, line in vex_calls(run_of(st[i])):
            unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", line)
            ok(not re.search(r"&&|\|\||;|(?<![&|])&(?!&)|\bif\b|\bwhile\b|\buntil\b", unquoted) and not re.match(r"\s*!", unquoted),
               "a vex-index command is chained or conditional (a failure can be skipped): %r" % line)


def no_digests_output(res):
    for sid, o in res.outputs.items():
        ok("digests" not in o, "step %r recorded a digests output although the stage failed" % sid)


@case("1", "e2e: a final-index computation that refuses the LAST variant fails the stage and records nothing")
def _():
    fx = fixtures()
    fx["fips"] = mk_variant("fips", bad=True)
    r = assemble_run(fx=fx)
    ok(r.failed is not None, "the stage passed although compute refused the fips index")
    ok(not r.attest, "an attest step was reached")
    no_digests_output(r)


@case("1", "e2e: a final index that fails verification for the LAST variant fails the stage and records nothing")
def _():
    r = assemble_run(extra_env={"TAMPER_COMPUTE_N": "3"})
    ok(r.failed is not None, "the stage passed although the third computed index was corrupted")
    ok(not r.attest, "an attest step was reached")
    no_digests_output(r)


@case("1", "e2e: a push that fails on its very last write fails the stage and records nothing")
def _():
    base = released()
    need_ok(base)
    w = base.reg.writes_ok
    ok(w >= 6, "expected writes for three variants, saw %d" % w)
    r = assemble_run(fail_after=w - 1)
    ok(r.failed is not None, "the stage passed although the registry refused the final write")
    ok(not r.attest, "an attest step was reached")
    no_digests_output(r)


@case("1", "e2e: the registry login is to ghcr.io and nothing else, and no artifact is uploaded in release mode")
def _():
    r = released()
    need_ok(r)
    host = "127.0.0.1:%d" % r.reg.port
    logins = [c for c in calls(r.box) if c.startswith("docker login")]
    ok(logins, "no registry login happened")
    for c in logins:
        eq(c.split()[2], host, "the login target of: " + c)
    eq(r.uploads, [], "uploaded artifacts in release mode")


@case("2", "e2e: the reproducibility stage's login is to ghcr.io too, and every step it declares ran")
def _():
    fx, F = repro_inputs()
    r = repro_run(F, fx)
    need_ok(r)
    host = "127.0.0.1:%d" % r.reg.port
    for c in [c for c in calls(r.box) if c.startswith("docker login")]:
        eq(c.split()[2], host, "the login target of: " + c)
    eq(len(r.results), len([s for s in repro_steps() if "run" in s]), "run steps executed")


def main():
    if os.environ.get("AC5_DUMP_GOLDEN"):
        print(json.dumps({"frozen": {n: frozen_paths(n) for n in FROZEN_FILES}, "uses": {n: uses_pins(n) for n in USES_FILES}}, indent=0, sort_keys=True))
        sys.exit(0)
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
