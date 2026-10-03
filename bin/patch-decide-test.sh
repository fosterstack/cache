#!/usr/bin/env bash
# proves: REQ-REL-009-AC1, REQ-REL-009-AC2, REQ-REL-009-AC4, REQ-REL-009-AC8, REQ-REL-009-AC11
# The automatic patch-release decision (owner RATIFIED Oct 2; advisor read-backs 0051/0055/0056), offline: commits are
# classified fix-class / neutral / not patch-clean by the files they change (a patch-fix label admits a source change);
# the next tag is vX.Y.(Z+1); the daily rule cuts at most once a day; release notes list each fix and name no vendor or
# model; floating tags move :X.Y always and :X / :latest only for the highest version.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
python3 - "$here/patch-decide.py" <<'PY'
import importlib.util, re, sys
spec = importlib.util.spec_from_file_location("pd", sys.argv[1]); P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)

def c(sha, files, labels=(), diffs=None):
    """diffs: {path: the commit's changed lines ("-old" / "+new")}"""
    return {"sha": sha, "files": list(files), "labels": list(labels), "diffs": dict(diffs or {})}
BUMP = {"go.mod": " require (\n-\tgolang.org/x/sys v0.46.0\n+\tgolang.org/x/sys v0.47.0\n )\n",
        "go.sum": "-golang.org/x/sys v0.46.0 h1:a=\n+golang.org/x/sys v0.47.0 h1:b=\n"}
NEWMOD = {"go.mod": "+\tgithub.com/evil/new v1.0.0\n"}
DIGEST = {"build/docker/Dockerfile.production": "-FROM gcr.io/distroless/static@sha256:" + "a" * 64 + "\n+FROM gcr.io/distroless/static@sha256:" + "b" * 64 + "\n"}
RUNLINE = {"build/docker/Dockerfile.production": "+RUN echo hi\n"}
# --- AC1: classification by changed files
for files, diff, want in [
    (["go.mod", "go.sum"], BUMP, "fix"),
    (["go.mod"], NEWMOD, "dirty"),                           # a new module is not a version-pin fix
    (["build/docker/Dockerfile.production"], DIGEST, "fix"), # the base-image digest pin only
    (["build/docker/Dockerfile.production"], RUNLINE, "dirty"),
    ([".vex/fosterstack-cache.openvex.json"], {}, "fix"),
    ([".snyk", "osv-scanner.toml", ".auditor/accepted-items.json"], {}, "fix"),
    ([".github/workflows/ci.yml", "docs/x.md", "requirements/requirements.yaml", "test-evidence/mappings.yaml"], {}, "neutral"),
    (["internal/cache/store_test.go", "bin/x-test.sh"], {}, "neutral"),
    (["internal/cache/store.go"], {}, "dirty"),
    (["go.mod", "internal/cache/store.go"], BUMP, "dirty"),
]:
    got = P.classify(c("a", files, diffs=diff))[0]
    check("classify %s -> %s" % (files, want), got == want, got)
check("a source change is admitted only with the patch-fix label", P.classify(c("a", ["internal/cache/store.go"], ["patch-fix"]))[0] == "fix")
ok, why = P.patch_clean([c("a", ["go.mod"], diffs=BUMP), c("b", ["docs/x.md"])])
check("fix + neutral commits are patch-clean", ok and why == [], why)
ok, why = P.patch_clean([c("a", ["go.mod"], diffs=BUMP), c("b2c3d4e", ["internal/cache/store.go"])])
check("a non-fix commit makes main not patch-clean, named with why", not ok and why and "b2c3d4e" in why[0] and "internal/cache/store.go" in why[0], why)
ok, why = P.patch_clean([c("n", ["docs/x.md"])])
check("neutral-only commits ship no bytes: nothing to cut", not ok and why == [] and not P.ships_bytes([c("n", ["docs/x.md"])]), (ok, why))
# --- AC2: the next version
check("next patch after the highest tag", P.next_patch(["v0.2.0", "v0.2.1", "v0.1.9"]) == "v0.2.2", P.next_patch(["v0.2.0", "v0.2.1"]))
check("a pre-release or suffixed tag is ignored", P.next_patch(["v0.2.1", "v0.3.0-rc1", "v0.2.1+build5"]) == "v0.2.2")
check("no release yet -> no patch (minor/major are the owner's)", P.next_patch([]) is None)
check("a patch never bumps minor or major", P.next_patch(["v1.9.9"]) == "v1.9.10")
# --- AC4: at most one daily patch
check("daily: shipped bytes ahead, none today -> cut", P.daily_cut(ships=True, cut_today=False) is True)
check("daily: already cut today -> no second", P.daily_cut(ships=True, cut_today=True) is False)
check("daily: nothing shipped -> no cut", P.daily_cut(ships=False, cut_today=False) is False)
# --- AC8: release notes
fixes = [{"cve": "CVE-2099-0001", "package": "golang.org/x/sys", "old": "v0.46.0", "new": "v0.47.0", "severity": "high",
          "variants": ["production", "debug", "fips"]}]
vex = [{"cve": "CVE-2099-0002", "status": "not_affected", "change": "added"}]
notes = P.notes("v0.2.2", fixes, vex)
for want in ("CVE-2099-0001", "golang.org/x/sys", "v0.46.0", "v0.47.0", "high", "production, debug, fips",
             "CVE-2099-0002", "not_affected", "No behavior change"):
    check("notes carry %r" % want, want in notes, notes)
leak = P.notes("v0.2.2", [dict(fixes[0], package="claude-sdk")], [])
check("notes name no vendor or model", "claude" not in leak.lower(), leak)
# --- AC11: floating tags
check("highest version: :X.Y, :X and :latest move", P.floating("v0.2.2", ["v0.2.1", "v0.1.9"]) == ["0.2", "0", "latest"])
check("an older line: only :X.Y moves", P.floating("v0.1.10", ["v0.2.1", "v0.1.9"]) == ["0.1"])
check("same major, lower minor: :X does not move", P.floating("v1.2.5", ["v1.3.0", "v1.2.4"]) == ["1.2"])

# --- Codex #158 r1 (B01-B06)
A64, B64 = "a" * 64, "b" * 64
# B01: a changed go.mod or Dockerfile without diff evidence is never fix-class
check("B01 go.mod without a diff -> not patch-clean", P.classify(c("x", ["go.mod"]))[0] == "dirty")
check("B01 go.mod with an empty diff -> not patch-clean", P.classify(c("x", ["go.mod"], diffs={"go.mod": ""}))[0] == "dirty")
check("B01 Dockerfile without a diff -> not patch-clean", P.classify(c("x", ["build/docker/Dockerfile.production"]))[0] == "dirty")
# B02: only require-version changes (with context) and the go/toolchain line; never replace, exclude or a checksum rewrite
REQ_CTX = {"go.mod": " module x\n \n require (\n-\tgolang.org/x/sys v0.46.0\n+\tgolang.org/x/sys v0.47.0\n )\n"}
check("B02 a require-block version bump with context is a fix", P.classify(c("x", ["go.mod"], diffs=REQ_CTX))[0] == "fix")
GO_LINE = {"go.mod": " module x\n \n-go 1.26.6\n+go 1.27.1\n"}
check("B02 the go directive line moving is a fix (toolchain CVE fixes)", P.classify(c("x", ["go.mod"], diffs=GO_LINE))[0] == "fix")
REPL = {"go.mod": " replace (\n-\texample.org/original v1.0.0 => example.org/trusted v1.0.0\n+\texample.org/original v1.0.0 => example.org/replacement v1.0.0\n )\n"}
check("B02 a replace target change is not patch-clean", P.classify(c("x", ["go.mod"], diffs=REPL))[0] == "dirty")
EXCL = {"go.mod": " exclude (\n-\texample.org/m v1.0.0\n+\texample.org/m v1.1.0\n )\n"}
check("B02 an exclude-block change is not patch-clean", P.classify(c("x", ["go.mod"], diffs=EXCL))[0] == "dirty")
NOCTX = {"go.mod": "-\texample.org/m v1.0.0\n+\texample.org/m v1.1.0\n"}
check("B02 a block line without context (block unknown) fails closed", P.classify(c("x", ["go.mod"], diffs=NOCTX))[0] == "dirty")
SUMONLY = {"go.sum": "-example.org/m v1.0.0 h1:" + "a" * 43 + "=\n+example.org/m v1.0.0 h1:" + "b" * 43 + "=\n"}
check("B02 a go.sum checksum rewrite of the same version is not patch-clean", P.classify(c("x", ["go.sum"], diffs=SUMONLY))[0] == "dirty")
BUMP_CTX = {"go.mod": REQ_CTX["go.mod"], "go.sum": "-golang.org/x/sys v0.46.0 h1:a=\n-golang.org/x/sys v0.46.0/go.mod h1:b=\n+golang.org/x/sys v0.47.0 h1:c=\n+golang.org/x/sys v0.47.0/go.mod h1:d=\n"}
check("B02 go.mod + go.sum moving one module's version together is a fix", P.classify(c("x", ["go.mod", "go.sum"], diffs=BUMP_CTX))[0] == "fix")
# B03: a Dockerfile change is fix-class only when each FROM keeps its image, tag, alias and flags and only the digest moves
def df(old, new):
    return {"build/docker/Dockerfile.production": "-" + old + "\n+" + new + "\n"}
ok_df = df("FROM gcr.io/distroless/static:nonroot@sha256:%s AS runtime" % A64, "FROM gcr.io/distroless/static:nonroot@sha256:%s AS runtime" % B64)
check("B03 the same image, tag and alias with a new digest is a fix", P.classify(c("x", ["build/docker/Dockerfile.production"], diffs=ok_df))[0] == "fix")
for name, old, new in [
    ("a different image", "FROM gcr.io/distroless/static@sha256:" + A64, "FROM example.org/different-os@sha256:" + B64),
    ("a renamed stage", "FROM gcr.io/distroless/static@sha256:%s AS runtime" % A64, "FROM gcr.io/distroless/static@sha256:%s AS replaced" % B64),
    ("a changed tag", "FROM gcr.io/distroless/static:nonroot@sha256:" + A64, "FROM gcr.io/distroless/static:debug@sha256:" + B64),
]:
    check("B03 %s is not patch-clean" % name, P.classify(c("x", ["build/docker/Dockerfile.production"], diffs=df(old, new)))[0] == "dirty")
added = {"build/docker/Dockerfile.production": "+FROM example.org/new-final@sha256:" + B64 + "\n"}
check("B03 an added stage is not patch-clean", P.classify(c("x", ["build/docker/Dockerfile.production"], diffs=added))[0] == "dirty")
# B04: the release chain's build workflows shape the shipped image: never neutral
for f in (".github/workflows/stage-image.yml", ".github/workflows/stage-build.yml", ".github/workflows/release.yml",
          ".goreleaser.yaml"):
    check("B04 %s is not neutral" % f, P.classify(c("x", [f]))[0] == "dirty")
check("B04 other workflows stay neutral", P.classify(c("x", [".github/workflows/ci.yml"]))[0] == "neutral")
# B05: a released prerelease above the patch keeps :X and :latest where they are
check("B05 a higher released rc keeps :X and :latest", P.floating("v0.2.2", ["v2.0.0-rc.1"]) == ["0.2"], P.floating("v0.2.2", ["v2.0.0-rc.1"]))
check("B05 a lower rc does not", P.floating("v0.2.2", ["v0.2.1", "v0.2.2-rc.1"]) == ["0.2", "0", "latest"], P.floating("v0.2.2", ["v0.2.1", "v0.2.2-rc.1"]))
check("B05 the final release outranks its own rc", P.floating("v1.0.0", ["v1.0.0-rc.2"]) == ["1.0", "1", "latest"])
# B06: no vendor or model names, the wider set
txt = P.notes("v0.2.2", [], [{"cve": "CVE-2099-0001", "status": "fixed", "change": "confirmed by Meta Llama, Mistral, Grok, DeepSeek, Qwen and Copilot"}])
check("B06 notes name no vendor or model (wider set)", not re.search(r"(?i)meta|llama|mistral|grok|deepseek|qwen|copilot", txt), txt)
check("B06 ordinary words survive (metadata, opusculum?)", "metadata" in P._clean("the release metadata"), P._clean("the release metadata"))
print("patch-decide: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
