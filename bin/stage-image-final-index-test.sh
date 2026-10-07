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
                snap = {"uses": s["uses"]}
                for key in ("subject-checksums", "predicate-path"):
                    if key in w:
                        path = rewrite(expand(w[key], ctx), b)
                        snap[key] = open(path).read() if os.path.isfile(path) else None
                res.snaps.append(snap)
            else:
                ok(s["uses"].startswith(MODELLED_ACTIONS), "step uses %s, which this test does not model" % s["uses"])
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
                    "GITHUB_ACTOR": "ci-actor", "PYTHONDONTWRITEBYTECODE": "1", "HOME": b.dir})
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
# Golden digest operands of every consumer and signing boundary downstream of the image stage, extracted from the workflows
# as they were before this change (the final-index change may not touch them). Every logical line of a run: block, every
# env/with/output value and every reusable-workflow call input that mentions a digest, an image reference or a command that
# can name one (crane, cosign, imagetools, docker pull/run/inspect, skopeo, ...). A changed operand, a new line that names
# one and a removed line all differ from the golden, wherever in the stage they are and however the command is spelt.
OPERAND_TOKEN = re.compile(r"(?i)digest|crane|cosign|imagetools|docker\s+(pull|inspect|image|run|tag|push|save|load)|repodigests|skopeo|oras|regctl|cache-candidates|sha256:|containerimage|image[-_]?ref")
OPERAND_FILES = ["release.yml", "acceptance.yml", "scan.yml", "stage-verify.yml", "stage-acceptance-artifacts.yml", "stage-acceptance-egress.yml",
                 "stage-acceptance-k8s.yml", "stage-acceptance-predicate.yml", "stage-authorize.yml", "stage-promote.yml", "main-candidate-rescan.yml"]
GOLDEN_OPERANDS = json.loads(r'''{
"acceptance.yml": [
"acceptance-gradle.run: docker run -d --name fscache-acc -p 127.0.0.1:18095:8080 \"${IMAGE_REF}\"",
"acceptance-gradle.run: docker run -d --name fscache-capped -e FSCACHE_MAX_BYTES=49152 -p 127.0.0.1:18096:8080 \"${IMAGE_REF}\"",
"acceptance-gradle.step.env.IMAGE_REF: ${{ inputs.image-ref }}",
"acceptance-gradle.step.env.IMAGE_REF: ${{ inputs.image-ref }}",
"acceptance-maven.run: docker run -d --name fscache-mvn-acc -p 127.0.0.1:18098:8080 -e FSCACHE_USERNAME=mvn -e FSCACHE_PASSWORD=acceptance-secret \"${IMAGE_REF}\"",
"acceptance-maven.run: docker run -d --name fscache-mvn-capped -e FSCACHE_MAX_BYTES=262144 -e FSCACHE_USERNAME=mvn -e FSCACHE_PASSWORD=acceptance-secret -p 127.0.0.1:18099:8080 \"${IMAGE_REF}\"",
"acceptance-maven.run: echo \"lib sha256: a=${lib_a} b=${lib_b}\"",
"acceptance-maven.step.env.IMAGE_REF: ${{ inputs.image-ref }}",
"acceptance-maven.step.env.IMAGE_REF: ${{ inputs.image-ref }}"
],
"main-candidate-rescan.yml": [
"assemble.uses: ./.github/workflows/stage-image.yml",
"build.uses: ./.github/workflows/stage-build.yml",
"manifests.run: TARGET_SHAPE='all(.[]; (.release | test(\"^v[0-9]+[.][0-9]+[.][0-9]+(-rc[.][0-9]+)?$\")) and (.variant | test(\"^[a-z0-9][a-z0-9-]{0,31}$\")) and (.digest | test(\"^sha256:[0-9a-f]{64}$\")) and (.scanner | test(\"^[a-z0-9][a-z0-9-]{0,31}$\")))'",
"manifests.run: jq -e \"$TARGET_SHAPE\" <<<\"$targets\" > /dev/null || { echo \"::error::a rescan target has a malformed release, variant, digest or scanner - refusing to emit the matrix\" >&2; exit 1; }",
"manifests.run: {release: $r.version, variant: $img.variant, digest: $img.digest, scanner: $s, source: \"legacy-inventory\"}' .github/policy/legacy-releases.json >> /tmp/targets.jsonl",
"manifests.run: {release: $tag, variant: $img.variant, digest: $img.digest, scanner: $s, source: \"release-manifest\"}' \"/tmp/m-${tag}.json\" >> /tmp/targets.jsonl",
"panel-google.run: gcloud artifacts docker images list-vulnerabilities \"$(jq -r '.response.scan' \"${d}/scan.json\")\" --format=json > \"${d}/vulns.json\" || rm -f \"${d}/packages.json\"",
"panel-google.run: if gcloud artifacts docker images scan \"${ref}\" --additional-package-types=GO --format=json --log-http > \"${d}/scan.json\" 2> \"${d}/http.log\"; then",
"panel-google.run: skopeo copy --override-arch amd64 --override-os linux \"oci-archive:/tmp/oci/${v}.oci\" \"docker-daemon:${ref}\" || continue",
"panel-google.run: sudo apt-get update -qq && sudo apt-get install -y -qq skopeo",
"panel-grype.run: skopeo copy --override-arch \"${arch}\" --override-os linux \"oci-archive:/tmp/oci/${v}.oci\" \"docker-daemon:${ref}\" || continue",
"panel-grype.run: sudo apt-get update -qq && sudo apt-get install -y -qq skopeo",
"panel-inspector.run: skopeo copy --override-arch \"${arch}\" --override-os linux \"oci-archive:/tmp/oci/${v}.oci\" \"docker-daemon:${ref}\" || continue",
"panel-inspector.run: sudo apt-get update -qq && sudo apt-get install -y -qq skopeo",
"panel-scout.run: docker image rm ghcr.io/fosterstack/cache:selfcheck >/dev/null",
"panel-scout.run: python3 bin/scout-selfcheck.py probe-doc3 \"$RUNNER_TEMP/probe/before-r.json\" \"$RUNNER_TEMP/probe/sbom-r.json\" \"$author\" docker.io/library/debian sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab \"$RUNNER_TEMP/probe/forms3r.json\"",
"panel-scout.run: reg=registry://docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab",
"panel-scout.run: skopeo copy --override-arch \"${arch}\" --override-os linux \"oci-archive:/tmp/oci/${v}.oci\" \"docker-daemon:${ref}\" || continue",
"panel-scout.run: skopeo copy docker://docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab docker-daemon:ghcr.io/fosterstack/cache:selfcheck",
"panel-scout.run: skopeo copy docker://docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab docker-daemon:ghcr.io/fosterstack/cache:selfcheck",
"panel-scout.run: sudo apt-get install -y -qq skopeo",
"panel-scout.run: sudo apt-get update -qq && sudo apt-get install -y -qq skopeo",
"rescan.env.TARGET_DIGEST: ${{ matrix.target.digest }}",
"rescan.run: if ! docker buildx imagetools inspect --raw \"$ref\" > /tmp/index.json 2>/tmp/inspect.err; then",
"rescan.run: python3 bin/rescan-statement.py statement --scanner \"$TARGET_SCANNER\" --children /tmp/children-scanned.jsonl --meta /tmp/scanner-meta --vex .vex/fosterstack-cache.openvex.json --scope-file /tmp/scan-scope.json --release \"$TARGET_RELEASE\" --variant \"$TARGET_VARIANT\" --digest \"$TARGET_DIGEST\" --image-ref \"ghcr.io/${GITHUB_REPOSITORY_OWNER}/cache@${TARGET_DIGEST}\" --scanned-at \"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\" --raw-out /tmp/findings-raw.json --out /tmp/rescan-statement.json --github-output \"$GITHUB_OUTPUT\"",
"rescan.run: ref=\"ghcr.io/${GITHUB_REPOSITORY_OWNER}/cache@${TARGET_DIGEST}\"",
"rescan.step.with.script: const t = ${{ toJSON(matrix.target) }}; const short = t.digest.replace('sha256:', '').slice(0, 12); const title = `Daily rescan: findings in ${t.release} ${t.variant} @${short} (${t.scanner})`; const runUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`; const body = `The daily rescan found new findings.\\n\\n- release: \\`${t.release}\\`\\n- variant: \\`${t.variant}\\`\\n- digest: \\`${t.digest}\\`\\n- scanner: \\`${t.scanner}\\`\\n- statement artifact: \\`rescan-${t.release}-${t.variant}-${t.scanner}\\` on ${runUrl}\\n\\nThese bytes have not changed since release \u2014 this is a newly-disclosed CVE against previously-shipped code, the case the 24-48h response SLA targets. Per policy: if an upstream fix exists, ship the version bump; if not, publish a VEX statement and mitigation.`; const { data: existing } = await github.rest.issues.listForRepo({ owner: context.repo.owner, repo: context.repo.repo, state: 'open', labels: 'daily-rescan', }); const match = existing.find(i => i.title === title); if (match) { await github.rest.issues.createComment({ owner: context.repo.owner, repo: context.repo.repo, issue_number: match.number, body }); } else { // issues.create fails (422) when a label does not exist, and a lost tracking issue is a lost finding: make sure both // labels exist first. An existing label is left as it is (a 422 here is fine); any other failure shows up in the create below. // The values are policy.LABELS', and a test pins them equal. for (const [name, description, color] of [['daily-rescan', \"The daily rescan's tracking issue\", '0E8A16'], ['security', 'Security finding', 'D93F0B']]) { try { await github.rest.issues.createLabel({ owner: context.repo.owner, repo: context.repo.repo, name, description, color }); } catch (e) { /* exists, or the create below reports it */ } } await github.rest.issues.create({ owner: context.repo.owner, repo: context.repo.repo, title, body, labels: ['daily-rescan', 'security'] }); }",
"scanner-reports.run: : > /tmp/reports/candidate-digests.json",
"scanner-reports.run: command -v skopeo >/dev/null 2>&1 || sudo apt-get update -qq && sudo apt-get install -y -qq skopeo || true",
"scanner-reports.run: d = subprocess.run([\"skopeo\", \"inspect\", \"--format\", \"{{.Digest}}\", \"docker-daemon:%s\" % ref],",
"scanner-reports.run: json.dump(digs, open(\"/tmp/reports/candidate-digests.json\", \"w\"), indent=1)",
"scanner-reports.run: print(\"recorded digests:\", digs)",
"scanner-reports.run: subprocess.run([\"skopeo\", \"copy\", \"oci-archive:%s\" % oci, \"docker-daemon:%s\" % ref], check=False)",
"scout-root-cause.run: sudo apt-get update -qq && sudo apt-get install -y -qq skopeo"
],
"release.yml": [
"acceptance-artifacts.uses: ./.github/workflows/stage-acceptance-artifacts.yml",
"acceptance-artifacts.with.digests: ${{ needs.image.outputs.digests }}",
"acceptance-egress.uses: ./.github/workflows/stage-acceptance-egress.yml",
"acceptance-egress.with.digests: ${{ needs.image.outputs.digests }}",
"acceptance-k8s.uses: ./.github/workflows/stage-acceptance-k8s.yml",
"acceptance-k8s.with.digests: ${{ needs.image.outputs.digests }}",
"acceptance-predicate.uses: ./.github/workflows/stage-acceptance-predicate.yml",
"acceptance-predicate.with.digests: ${{ needs.image.outputs.digests }}",
"acceptance.uses: ./.github/workflows/acceptance.yml",
"acceptance.with.image-ref: ghcr.io/${{ github.repository_owner }}/cache-candidates@${{ fromJSON(needs.image.outputs.digests).production }}",
"admission.uses: ./.github/workflows/stage-admission.yml",
"authorization.uses: ./.github/workflows/stage-authorize.yml",
"authorization.with.digests: ${{ needs.image.outputs.digests }}",
"build.uses: ./.github/workflows/stage-build.yml",
"decide.run: if bases=$(grep -h -o -E '^FROM [^ ]+@sha256:[0-9a-f]{64}' build/docker/Dockerfile.* | awk '{print $2}' | sort -u) && [ -n \"$bases\" ]; then",
"image.uses: ./.github/workflows/stage-image.yml",
"promotion.uses: ./.github/workflows/stage-promote.yml",
"promotion.with.digests: ${{ needs.image.outputs.digests }}",
"reproducibility.uses: ./.github/workflows/stage-reproducibility.yml",
"reproducibility.with.digests: ${{ needs.image.outputs.digests }}",
"scans.uses: ./.github/workflows/stage-verify.yml",
"scans.with.digests: ${{ needs.image.outputs.digests }}"
],
"scan.yml": [
"artifact-acceptance.uses: ./.github/workflows/stage-acceptance-artifacts.yml",
"assemble-b.uses: ./.github/workflows/stage-image.yml",
"assemble.uses: ./.github/workflows/stage-image.yml",
"build.uses: ./.github/workflows/stage-build.yml",
"reproducibility.run: a='${{ needs.assemble.outputs.digests }}'",
"reproducibility.run: b='${{ needs.assemble-b.outputs.digests }}'",
"reproducibility.run: echo \"::error::assembly A produced no digest for ${v}\" >&2; exit 1",
"scanner.run: skopeo copy --override-arch \"${arch}\" --override-os linux \"oci-archive:/tmp/oci/${v}.oci\" \"docker-daemon:${ref}\"",
"scanner.run: sudo apt-get update -qq && sudo apt-get install -y -qq skopeo"
],
"stage-acceptance-artifacts.yml": [
"artifacts.run: [ -n \"$d\" ] && [ \"$d\" != \"null\" ] || { echo \"::error::candidates mode with no digest for ${v}\" >&2; exit 1; }",
"artifacts.run: childd=$(docker buildx imagetools inspect --raw \"${repo}@${d}\" | jq -r '.manifests[] | select(.platform.os==\"linux\" and .platform.architecture==\"arm64\") | .digest')",
"artifacts.run: cpid=$(docker inspect -f '{{.State.Pid}}' fa-prod)",
"artifacts.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"artifacts.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"artifacts.run: docker pull -q \"${repo}@${childd}\"",
"artifacts.run: docker pull -q \"${repo}@${d}\"",
"artifacts.run: docker run --pull=never -d --name fa-debugrun -p 127.0.0.1:19012:8080 localhost/fa-debug",
"artifacts.run: docker run --pull=never -d --name fa-fipsrun -p 127.0.0.1:19011:8080 -e FSCACHE_USERNAME=acc -e FSCACHE_PASSWORD=accpw localhost/fa-fips",
"artifacts.run: docker run --pull=never -d --name fa-prod -p 127.0.0.1:19010:8080 localhost/fa-production",
"artifacts.run: docker run -d --name \"fa-arm64-$v\" --platform linux/arm64 $authargs -p \"127.0.0.1:${port}:8080\" \"${repo}@${childd}\"",
"artifacts.run: docker tag \"${repo}@${d}\" \"localhost/fa-${v}\"",
"artifacts.run: if docker run --pull=never --rm --entrypoint /bin/sh localhost/fa-debug -c true 2>/dev/null; then",
"artifacts.run: if docker run --pull=never --rm --entrypoint /busybox/sh localhost/fa-fips -c true 2>/dev/null; then",
"artifacts.run: if docker run --pull=never --rm --entrypoint /busybox/sh localhost/fa-production -c true 2>/dev/null; then",
"artifacts.run: out=$(docker run --pull=never --rm --entrypoint /busybox/sh localhost/fa-debug -c 'echo shell-ok')",
"artifacts.run: repo=\"ghcr.io/${{ github.repository_owner }}/cache-candidates\"",
"artifacts.run: repo=\"ghcr.io/${{ github.repository_owner }}/cache-candidates\"",
"artifacts.step.with.image: tonistiigi/binfmt:latest@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
],
"stage-acceptance-egress.yml": [
"egress.run: ALPINE=alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
"egress.run: DISTROLESS=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab",
"egress.run: NETSHOOT=nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b",
"egress.run: OWN_IP6=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' \"fscache-net-${label}\")",
"egress.run: OWN_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \"fscache-net-${label}\")",
"egress.run: d=$(jq -r '.production' <<<\"${DIGESTS}\")",
"egress.run: docker pull -q \"ghcr.io/${{ github.repository_owner }}/cache-candidates@${d}\"",
"egress.run: docker run --rm --net \"container:fscache-net-ctldenied\" --cap-add SYS_PTRACE \"$NETSHOOT\" sh -c 'command -v strace >/dev/null 2>&1 || { echo \"MISSING-STRACE\" >&2; exit 3; }; strace -f -e trace=connect nc -w 2 203.0.113.7 80' > /tmp/ctldenied.strace 2>&1 || true",
"egress.run: docker run --rm -v \"$TRACE_BIN\":/out -e V=\"$STRACE_VER\" -e SUM=\"$STRACE_SHA256\" \"$ALPINE\" sh -euc '",
"egress.run: docker run --rm -v /tmp:/caps \"$NETSHOOT\" tshark -r /caps/ctldenied.pcap -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 203.0.113.7' -T fields -e frame.number 2>/dev/null > /tmp/ctldenied.leak || true",
"egress.run: docker run -d --name \"fscache-cand-${label}\" --net \"container:fscache-net-${label}\" --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --security-opt apparmor=unconfined -v \"$TRACE_BIN\":/trace:ro -v \"$TRACE_OUT\":/out --entrypoint /trace/strace \"$REF\" -f -e trace=network -yy -qq -o \"/out/${label}.strace\" \"$CANDIDATE_ENTRYPOINT\" >/dev/null",
"egress.run: docker run -d --name \"fscache-net-${label}\" --network \"$net\" \"$NETSHOOT\" sleep infinity >/dev/null",
"egress.run: docker run -d --name \"fscache-tap-${label}\" --net \"container:fscache-net-${label}\" -v /tmp:/caps \"$NETSHOOT\" tcpdump -i any -n -U -w \"/caps/${label}.pcap\" >/dev/null",
"egress.run: echo \"REF=ghcr.io/${{ github.repository_owner }}/cache-candidates@${d}\" >> \"$GITHUB_ENV\"",
"egress.run: if ! docker run --rm -v \"$TRACE_BIN\":/trace:ro --entrypoint /trace/strace \"$DISTROLESS\" -V > /tmp/strace.ver 2>&1; then",
"egress.run: if ! docker run --rm -v /tmp:/caps \"$NETSHOOT\" tshark -r \"/caps/${base}\" -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e tcp.dstport -E separator='|' 2>/dev/null | sed 's/^/TCP|/' > \"/tmp/${label}.synraw\"; then",
"egress.run: if ! docker run --rm -v /tmp:/caps \"$NETSHOOT\" tshark -r \"/caps/${base}\" -Y 'udp && !(udp.port == 53)' -T fields -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e udp.dstport -E separator='|' 2>/dev/null | sed 's/^/UDP|/' > \"/tmp/${label}.udpraw\"; then",
"egress.run: if ! docker run --rm -v /tmp:/caps \"$NETSHOOT\" tshark -r \"/caps/${base}\" -Y 'udp.port == 53 || tcp.port == 53' -T fields -e frame.number > \"/tmp/${label}.dnsraw\" 2>/dev/null; then",
"egress.run: if ! total=$(docker run --rm -v /tmp:/caps \"$NETSHOOT\" tshark -r \"/caps/${base}\" -T fields -e frame.number 2>/dev/null | wc -l); then",
"egress.step.env.DIGESTS: ${{ inputs.digests }}"
],
"stage-acceptance-k8s.yml": [
"k8s.env.CLIENT_IMAGE: curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69",
"k8s.run: d=$(jq -r '.production' <<<\"${DIGESTS}\")",
"k8s.run: docker pull -q \"$CLIENT_IMAGE\"",
"k8s.run: docker pull -q \"$ref\"",
"k8s.run: docker tag \"$CLIENT_IMAGE\" \"$CLIENT_LOCAL\"",
"k8s.run: docker tag \"$ref\" fscache-candidate:accept",
"k8s.run: ref=\"ghcr.io/${{ github.repository_owner }}/cache-candidates@${d}\"",
"k8s.step.env.DIGESTS: ${{ inputs.digests }}"
],
"stage-acceptance-predicate.yml": [
"predicate.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"predicate.run: echo \"${d#sha256:} cache-candidates-${v}\"",
"predicate.run: jq -n --arg sha \"${GITHUB_SHA}\" --argjson digests '${{ inputs.digests }}' --slurpfile results /tmp/ac-results.json '{sha: $sha, index_digests: $digests, ac_results: $results[0]}' > /tmp/acceptance-predicate.json"
],
"stage-authorize.yml": [
"authorize.run: [ -n \"$d\" ] && [ \"$d\" != \"null\" ] || { echo \"::error::no digest for ${v}\" >&2; exit 1; }",
"authorize.run: agot=$(jq -r --arg v \"$v\" '.[0].verificationResult.statement.predicate.index_digests[$v] // empty' <<<\"$acc\")",
"authorize.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"authorize.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"authorize.run: echo \"${d#sha256:} cache-candidates-${v}\"",
"authorize.run: got=$(jq -r --arg v \"$v\" '.[0].verificationResult.statement.predicate.index_digests[$v] // empty' <<<\"$ib\")",
"authorize.run: jq -s -n --arg tag \"${GITHUB_REF_NAME}\" --arg sha \"${GITHUB_SHA}\" --argjson digests '${{ inputs.digests }}' --slurpfile statements /tmp/verified-statements.jsonl '{",
"authorize.run: out=$(gh attestation verify \"$1\" --repo \"${GITHUB_REPOSITORY}\" --predicate-type \"$2\" --signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/$3\" --source-digest \"${GITHUB_SHA}\" --source-ref \"${GITHUB_REF}\" --format json) || { echo \"::error::graph verification failed: $4 ($2 by $3 on $1) - certificate source/signer must bind ${GITHUB_SHA} @ ${GITHUB_REF}\" >&2; exit 1; }",
"authorize.run: out=$(gh attestation verify /tmp/admission/admission.json --repo \"${GITHUB_REPOSITORY}\" --predicate-type https://fosterstack.com/attestations/source-admission/v1 --signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/stage-admission.yml\" --source-digest \"${GITHUB_SHA}\" --source-ref \"${GITHUB_REF}\" --format json)",
"authorize.run: repo=\"ghcr.io/${{ github.repository_owner }}/cache-candidates\"",
"authorize.run: rgot=$(jq -r --arg v \"$v\" '.[0].verificationResult.statement.predicate.index_digests[$v] // empty' <<<\"$repro\")",
"authorize.run: sgot=$(jq -r --arg v \"$v\" '.[0].verificationResult.statement.predicate.index_digests[$v] // empty' <<<\"$sc\")",
"authorize.run: statement: (\"digests approved for \" + $tag),",
"authorize.run: tag: $tag, sha: $sha, index_digests: $digests,",
"authorize.run: | .digest.gitCommit // empty ]"
],
"stage-promote.yml": [
"promote.run: GOTOOLCHAIN=local go install github.com/google/go-containerregistry/cmd/crane@v0.22.1",
"promote.run: [ \"$auth_digest\" = \"$d\" ] || { echo \"::error::authorization ${v} digest ${auth_digest} != promoting ${d}\" >&2; exit 1; }",
"promote.run: [ \"$got\" = \"$d\" ] || { echo \"::error::post-copy digest mismatch at ${dst}:${check}: ${got} != ${d}\" >&2; exit 1; }",
"promote.run: auth_digest=$(jq -r --arg v \"$v\" '.[0].verificationResult.statement.predicate.index_digests[$v] // empty' \"/tmp/auth-${v}.json\")",
"promote.run: cosign attest --yes --predicate /tmp/release-manifest.json --type https://fosterstack.com/attestations/release-manifest/v1 \"${ghcr}@${d}\"",
"promote.run: cosign attest --yes --predicate /tmp/release-manifest.json --type https://fosterstack.com/attestations/release-manifest/v1 \"${hub}@${d}\" || echo \"::warning::could not attach the manifest referrer on ${hub}@${d} \u2014 GHCR referrer is authoritative\"",
"promote.run: cosign sign --yes \"${ghcr}@${d}\"",
"promote.run: cosign sign --yes \"${hub}@${d}\"",
"promote.run: cosign sign-blob --yes dist/checksums.txt --bundle /tmp/checksums.txt.bundle",
"promote.run: cosign verify \"${reg}@${d}\" \"${idflags[@]}\" >/dev/null || { echo \"::error::anonymous cosign verify failed for ${reg}@${d}\" >&2; exit 1; }",
"promote.run: cosign verify-blob dist/checksums.txt --bundle /tmp/checksums.txt.bundle \"${idflags[@]}\" || { echo \"::error::anonymous checksums-bundle verification failed\" >&2; exit 1; }",
"promote.run: crane copy \"${src}@${d}\" \"${dst}:${t}\"",
"promote.run: crane tag \"${dst}:${t}\" \"${f}\"",
"promote.run: d0=$(jq -r '.production' <<<'${{ inputs.digests }}')",
"promote.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<\"${DIGESTS}\")",
"promote.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"promote.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"promote.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"promote.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"promote.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"promote.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"promote.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"promote.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"promote.run: echo \"${d#sha256:} cache-${v}\"",
"promote.run: echo \"${v} -> ${dst}:${t} (+${f}) at ${d} \u2014 digest equality asserted\"",
"promote.run: echo \"::error::cosign verify accepted a WRONG repository identity\" >&2; exit 1",
"promote.run: echo \"::error::cosign verify accepted a same-repo WRONG workflow identity (stage-image.yml) - the signer pin is too loose\" >&2; exit 1",
"promote.run: echo \"::error::cosign verify accepted stage-promote.yml at a branch ref - the release-ref pin is too loose\" >&2; exit 1",
"promote.run: echo \"See release-manifest.json for the full evidence bundle: image digests (GHCR canonical, Docker Hub mirror \u2014 identical digests), archive checksums, requirements baseline, per-AC acceptance results, and the Rekor log index of every verified statement in the release chain.\" >> /tmp/notes.md",
"promote.run: echo \"anonymous cosign image + checksums verification passed; negative controls rejected\"",
"promote.run: echo \"anonymous pulls resolve the promoted digests for every versioned and floating tag at both registries\"",
"promote.run: echo \"authorization verified for ${v} (tag, source, digest bound)\"",
"promote.run: gh attestation verify \"oci://${ghcr}@${d}\" --repo \"${GITHUB_REPOSITORY}\" --predicate-type https://fosterstack.com/attestations/release-authorization/v1 --signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/stage-authorize.yml\" --source-digest \"${GITHUB_SHA}\" --source-ref \"${GITHUB_REF}\" >/dev/null",
"promote.run: gh attestation verify \"oci://${repo}@${d}\" --repo \"${GITHUB_REPOSITORY}\" --predicate-type https://fosterstack.com/attestations/release-authorization/v1 --signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/stage-authorize.yml\" --source-digest \"${GITHUB_SHA}\" --source-ref \"${GITHUB_REF}\" --format json > \"/tmp/auth-${v}.json\"",
"promote.run: gh attestation verify \"oci://ghcr.io/${{ github.repository_owner }}/cache-candidates@$(jq -r '.production' <<<'${{ inputs.digests }}')\" --repo \"${GITHUB_REPOSITORY}\" --predicate-type https://fosterstack.com/attestations/acceptance/v1 --signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/stage-acceptance-predicate.yml\" --source-digest \"${GITHUB_SHA}\" --source-ref \"${GITHUB_REF}\" --format json | jq '.[0].verificationResult.statement.predicate.ac_results' > /tmp/ac-results.json",
"promote.run: got=$(crane digest \"${dst}:${check}\")",
"promote.run: got=$(crane digest \"${reg}:${t}\")",
"promote.run: if cosign verify \"${ghcr}@${d0}\" --certificate-identity-regexp \"^https://github\\.com/${GITHUB_REPOSITORY}/\\.github/workflows/stage-image\\.yml@\" --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' >/dev/null 2>&1; then",
"promote.run: if cosign verify \"${ghcr}@${d0}\" --certificate-identity-regexp \"^https://github\\.com/${GITHUB_REPOSITORY}/\\.github/workflows/stage-promote\\.yml@refs/heads/\" --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' >/dev/null 2>&1; then",
"promote.run: if cosign verify \"${ghcr}@${d0}\" --certificate-identity-regexp '^https://github\\.com/attacker/' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' >/dev/null 2>&1; then",
"promote.run: if cosign verify-blob /tmp/checksums.corrupt --bundle /tmp/checksums.txt.bundle \"${idflags[@]}\" >/dev/null 2>&1; then",
"promote.run: images: ($digests | to_entries | map({variant: .key, digest: .value,",
"promote.run: jq -R -s '[split(\"\\n\")[] | select(length > 0) | split(\" \") | {sha256: .[0], name: .[1]}]' /tmp/expected-checksums.txt > /tmp/archives.json",
"promote.run: jq -n --arg tag \"${GITHUB_REF_NAME}\" --arg sha \"${GITHUB_SHA}\" --argjson digests '${{ inputs.digests }}' '{",
"promote.run: jq -n --arg version \"$ver\" --arg sha \"${GITHUB_SHA}\" --arg generated \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" --arg run \"${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}\" --arg workflow \"${GITHUB_WORKFLOW_REF}\" --arg ghcr \"$ghcr\" --arg hub \"$hub\" --arg repofull \"${GITHUB_REPOSITORY}\" --arg ref \"${GITHUB_REF}\" --arg baseline \"requirements/releases/${base}.yaml\" --arg baseline_sha \"$(sha256sum \"requirements/releases/${base}.yaml\" | cut -d' ' -f1)\" --arg evidence_sha \"$(sha256sum test-evidence/mappings.yaml | cut -d' ' -f1)\" --arg vex_openvex_sha \"$(sha256sum /tmp/vex/fosterstack-cache.openvex.json | cut -d' ' -f1)\" --arg vex_inspector_sha \"$(sha256sum \"/tmp/vex/fosterstack-cache-${ver}.inspector-filters.json\" | cut -d' ' -f1)\" --arg vex_csaf_sha \"$(sha256sum \"/tmp/vex/fosterstack-cache-${ver}.csaf.json\" | cut -d' ' -f1)\" --argjson digests '${{ inputs.digests }}' --slurpfile archives /tmp/archives.json --slurpfile acs /tmp/ac-results.json --slurpfile statements /tmp/verified.json '{",
"promote.run: kids=$(crane manifest \"${src}@${d}\" | jq -c '[.manifests[] | select(.platform.os == \"linux\") | {key: (\"linux/\" + .platform.architecture), value: .digest}] | from_entries')",
"promote.run: note: \"Publication-phase ACs (REQ-REL-001-AC1, REQ-REL-002-AC1) are recorded in a SEPARATE signed publication attestation (predicate_type below) over these same image digests, tag, and commit, produced after the anonymous customer-verification and every-tag anonymous-pull checks pass. This manifest is assembled and signed BEFORE those checks, so its ac_results shows them deferred; the durable pass record is the publication attestation. This manifest is not mutated after signing.\",",
"promote.run: repo=\"ghcr.io/${{ github.repository_owner }}/cache-candidates\"",
"promote.run: requirements_baseline: {path: $baseline, sha256: $baseline_sha},",
"promote.run: src=\"ghcr.io/${{ github.repository_owner }}/cache-candidates\"",
"promote.run: src=\"ghcr.io/${{ github.repository_owner }}/cache-candidates\"",
"promote.run: tag: $tag, sha: $sha, index_digests: $digests,",
"promote.run: test_evidence: {path: \"test-evidence/mappings.yaml\", sha256: $evidence_sha},",
"promote.run: verify: (\"gh attestation verify oci://<image>@<digest> --repo \" + $repofull + \" --predicate-type https://fosterstack.com/attestations/publication/v1 --signer-workflow \" + $repofull + \"/.github/workflows/stage-promote.yml --source-digest \" + $sha + \" --source-ref \" + $ref)",
"promote.run: vex: [{file: \"fosterstack-cache.openvex.json\", form: \"openvex\", sha256: $vex_openvex_sha},",
"promote.run: {ac: \"REQ-REL-001-AC1\", result: \"pass\", evidence: \"anonymous cosign image verification + checksums-bundle verify-blob, wrong-signer and corrupt-bundle negatives rejected\"},",
"promote.run: {ac: \"REQ-REL-002-AC1\", result: \"pass\", evidence: \"anonymous crane digest of every versioned and floating tag at ghcr.io and docker.io resolves the promoted digest\"}",
"promote.run: {file: (\"fosterstack-cache-\" + $version + \".csaf.json\"), form: \"csaf-2.0-vex\", sha256: $vex_csaf_sha}],",
"promote.run: {file: (\"fosterstack-cache-\" + $version + \".inspector-filters.json\"), form: \"inspector-suppression-rules\", sha256: $vex_inspector_sha},",
"promote.step.env.COSIGN_EXPERIMENTAL: 0",
"promote.step.env.DIGESTS: ${{ inputs.digests }}"
],
"stage-verify.yml": [
"scan.run: [ -n \"$d\" ] && [ \"$d\" != \"null\" ] || { echo \"::error::no digest for ${v}\" >&2; exit 1; }",
"scan.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"scan.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"scan.run: d=$(jq -r --arg v \"$v\" '.[$v]' <<<'${{ inputs.digests }}')",
"scan.run: docker buildx imagetools inspect --raw \"${repo}@${d}\" | jq -r --arg v \"$v\" --arg repo \"$repo\" '.manifests[] | select(.platform.os != \"unknown\") | \"\\($v)\\t\\(.platform.os)/\\(.platform.architecture)\\t\\($repo)@\\(.digest)\"' >> /tmp/scan-targets.txt",
"scan.run: echo \"${d#sha256:} cache-candidates-${v}\"",
"scan.run: jq -n --arg scanner '${{ matrix.scanner }}' --arg version \"$ver\" --arg db \"$db\" --arg sha \"${GITHUB_SHA}\" --arg vex \"$(sha256sum .vex/fosterstack-cache.openvex.json | cut -d' ' -f1)\" --argjson digests '${{ inputs.digests }}' --rawfile scanned /tmp/scanned-subjects.txt '{",
"scan.run: repo=\"ghcr.io/${{ github.repository_owner }}/cache-candidates\"",
"scan.run: repo=\"ghcr.io/${{ github.repository_owner }}/cache-candidates\"",
"scan.run: sha: $sha, index_digests: $digests,",
"scan.run: vex_document_sha256: $vex,",
"scan.run: while IFS=$'\\t' read -r _ _ ref; do docker pull -q \"$ref\" >/dev/null; done < /tmp/scan-targets.txt"
]
}''')


def operand_lines(name):
    d = wf(name)
    out = []

    def add(k, v):
        if isinstance(v, str) and (OPERAND_TOKEN.search(v) or OPERAND_TOKEN.search(k)):
            out.append("%s: %s" % (k, re.sub(r"\s+", " ", v).strip()))
    for k, v in (((d.get("on") or {}).get("workflow_call") or {}).get("outputs") or {}).items():
        add("workflow_call.outputs.%s" % k, v.get("value", ""))
    for jn, j in (d.get("jobs") or {}).items():
        for k, v in (j.get("outputs") or {}).items():
            add("%s.outputs.%s" % (jn, k), v)
        for k, v in (j.get("with") or {}).items():
            add("%s.with.%s" % (jn, k), v)
        for k, v in (j.get("env") or {}).items():
            add("%s.env.%s" % (jn, k), v)
        if j.get("uses"):
            out.append("%s.uses: %s" % (jn, j["uses"]))
        for st in j.get("steps") or []:
            for k, v in (st.get("with") or {}).items():
                add("%s.step.with.%s" % (jn, k), v)
            for k, v in (st.get("env") or {}).items():
                add("%s.step.env.%s" % (jn, k), v)
            for l in joined(st.get("run") or "").split("\n"):
                l = re.sub(r"\s+", " ", l).strip()
                if l and not l.startswith("#") and OPERAND_TOKEN.search(l):
                    out.append("%s.run: %s" % (jn, l))
    return sorted(out)


@case("3", "operands: every downstream consumer and signing boundary takes exactly the digest operands it took before (golden, per workflow)")
def _():
    for name in OPERAND_FILES:
        got, want = operand_lines(name), GOLDEN_OPERANDS[name]
        if got != want:
            extra = [x for x in got if x not in want]
            gone = [x for x in want if x not in got]
            raise Fail("%s: digest operands differ from the golden; added/changed %s; removed %s" % (name, [x[:140] for x in extra[:3]], [x[:140] for x in gone[:3]]))


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


@case("3", "operands: every reusable-workflow call input of release.yml, acceptance.yml and scan.yml is in the golden (the digests, image-ref and artifact inputs)")
def _():
    for name in ("release.yml", "acceptance.yml", "scan.yml"):
        calls_ = [jn for jn, j in wf(name)["jobs"].items() if j.get("uses")]
        for jn in calls_:
            ok(any(l.startswith("%s.uses:" % jn) for l in GOLDEN_OPERANDS[name]), "%s: call %s is not in the golden operands" % (name, jn))


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
