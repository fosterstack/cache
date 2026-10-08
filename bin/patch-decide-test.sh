#!/usr/bin/env bash
# proves: REQ-REL-009-AC1, REQ-REL-009-AC2, REQ-REL-009-AC3, REQ-REL-009-AC4, REQ-REL-009-AC8, REQ-REL-009-AC11, REQ-REL-009-AC14, REQ-REL-009-AC15
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
    (["cmd/fscache/main_test.go"], {}, "dirty"),                            # a test is executable (AC1, owner Oct 3)
    (["bin/panel-test.sh"], {}, "dirty"),
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
# --- Sonnet #158 r2 (NEW-01, NEW-02)
for f in (".github/workflows/acceptance-gradle.yml", ".github/workflows/acceptance-maven.yml",
          ".github/workflows/acceptance.yml", ".github/workflows/some-new-workflow.yml"):
    check("NEW-01 %s (in the release chain, or not reviewed as neutral) is not neutral" % f, P.classify(c("x", [f]))[0] == "dirty")
for f in (".github/workflows/ci.yml", ".github/workflows/codeql.yml", ".github/workflows/auditor.yml"):
    check("NEW-01 %s (reviewed as outside the release) stays neutral" % f, P.classify(c("x", [f]))[0] == "neutral")
for name in ("o3", "o1-mini", "o4-mini", "Sonnet", "Opus", "Haiku", "Bard"):
    out = P._clean("confirmed by %s today" % name)
    check("NEW-02 %s is redacted" % name, name.lower() not in out.lower(), out)
check("NEW-02 an o-series pattern inside other words survives (go3, so3)", P._clean("go3 so3") == "go3 so3", P._clean("go3 so3"))
# --- Codex #158 phase-2 r2 (B02, B03, B04, B06 still open)
TWO_HUNKS = ("@@ -3,7 +3,7 @@\n go 1.26.6\n \n require (\n-\texample.org/r0 v1.0.0\n+\texample.org/r0 v1.0.1\n \texample.org/r1 v1.0.0\n"
             "@@ -24,7 +24,7 @@\n \texample.org/e3 v1.0.0\n-\texample.org/e6 v1.0.0\n+\texample.org/e6 v1.0.1\n \texample.org/e7 v1.0.0\n")
check("B02 a second hunk does not inherit the first hunk's require block", P.classify(c("x", ["go.mod"], diffs={"go.mod": TWO_HUNKS}))[0] == "dirty")
GO_ONLY_SUM = {"go.mod": " module x\n \n-go 1.26.6\n+go 1.26.7\n", "go.sum": "-example.org/unchanged v1.0.0 h1:" + "a" * 43 + "=\n"}
check("B02 a go-directive move does not explain a go.sum change", P.classify(c("x", ["go.mod", "go.sum"], diffs=GO_ONLY_SUM))[0] == "dirty")
OTHER_MOD = {"go.mod": REQ_CTX["go.mod"], "go.sum": "-golang.org/x/sys v0.46.0 h1:a=\n+golang.org/x/sys v0.47.0 h1:c=\n+example.org/other v9.9.9 h1:z=\n"}
check("B02 go.sum lines for a module whose version did not move are not patch-clean", P.classify(c("x", ["go.mod", "go.sum"], diffs=OTHER_MOD))[0] == "dirty")
MOVED = ("@@ -1,4 +1,4 @@\n FROM example.org/base:stable@sha256:%s AS build\n-FROM example.org/base:stable@sha256:%s AS runtime\n"
         " USER 65532\n+FROM example.org/base:stable@sha256:%s AS runtime\n COPY fscache /usr/local/bin/fscache\n") % (A64, A64, B64)
check("B03 a FROM moved past another instruction is not patch-clean", P.classify(c("x", ["build/docker/Dockerfile.production"], diffs={"build/docker/Dockerfile.production": MOVED}))[0] == "dirty")
for f in (".github/agent/bin/auditor-release-authz.py", ".github/policy/scanners.json", ".github/policy/allowed_signers",
          ".github/actions/x/action.yml"):
    check("B04 %s (read by the release chain, or not reviewed) is not neutral" % f, P.classify(c("x", [f]))[0] == "dirty")
for f in (".github/dependabot.yml", ".github/CODEOWNERS", ".github/agent/reviews/abc.json"):
    check("B04 %s stays neutral" % f, P.classify(c("x", [f]))[0] == "neutral")
for f in (".github/agent/tests/x.sh", ".github/agent/bin/tests/test_x.py"):   # tests: neutral only when listed (0107)
    check("0107 an unlisted %s is not neutral" % f, P.classify(c("x", [f]))[0] == "dirty")
for name in ("Google Gemini", "Microsoft Copilot", "Amazon Bedrock", "Azure OpenAI", "xAI Grok"):
    out = P._clean("confirmed by %s" % name)
    check("B06 %s is fully redacted" % name, all(w.lower() not in out.lower() for w in name.split()), out)
# Sonnet #158 r3 (NEW-BLOCKER-1): a vendor named alone is redacted too (rule 5: no vendor OR model names); a module
# path or domain that merely contains the word stays readable (google.golang.org/protobuf)
for name in ("Google", "Microsoft", "Amazon", "AWS", "Azure", "xAI", "x.ai", "Meta"):
    out = P._clean("confirmed by %s." % name)
    check("NEW-BLOCKER-1 %s alone is redacted" % name, out == "confirmed by <redacted>.", out)
for kept in ("google.golang.org/protobuf v1.36.9", "cloud.google.com/go/storage", "github.com/aws/aws-sdk-go-v2"):
    check("NEW-BLOCKER-1 the module path %s stays readable" % kept, P._clean(kept) == kept, P._clean(kept))
# Sonnet #159 r2 (BLOCKER-1): a name split by - _ or . is the same name
for s_ in ("internal/open-ai-client.go", "internal/open_ai_client.go", "internal/co_here.go", "internal/deep-seek.go",
           "x-ai-sdk", "chat-gpt", "mis_tral", "open.ai"):
    out = P._clean("confirmed by " + s_)
    check("BLOCKER-1 %s is redacted" % s_, not re.search(r"(?i)open.?ai|co.?here|deep.?seek|x.?ai|chat.?gpt|mis.?tral", out), out)
# Sonnet #158 r3b (NEW-BLOCKER-2): a vendor named alone is redacted wherever it stands — hyphen or slash next to it too;
# only a whole token that is a lowercase domain or module path stays (fail closed)
for s_ in ("an AWS-reported CVE", "a Google-disclosed vulnerability", "Microsoft-patched upstream",
           "jointly disclosed by Google/Microsoft", "affects AWS/Azure/GCP deployments", "(per Amazon)", "Azure, AWS; Google:"):
    out = P._clean(s_)
    check("NEW-BLOCKER-2 %r is redacted" % s_, not re.search(r"(?i)aws|google|microsoft|azure|amazon", out), out)
for kept in ("github.com/aws/aws-sdk-go-v2 v1.30.0", "bump google.golang.org/grpc to v1.70.0", "cloud.google.com/go/storage,",
             "sigs.k8s.io/x and github.com/azure/azure-sdk-for-go"):
    out = P._clean(kept)
    check("NEW-BLOCKER-2 module path stays readable: %r" % kept, out == kept, out)
# Sonnet #158 r3c (NEW-BLOCKER-3): only a WHOLE lowercase token is a module path; a capitalized vendor segment anywhere in it
# makes the token not a module path, so every vendor name in it is redacted (fail closed)
for s_ in ("see github.com/foo/AWS-tool for the fix", "tracked at status.example.com/Azure-outage", "sigs.k8s.io/Google-report",
           "github.com/example/Microsoft-compat-shim v2", "confirmed by Google.com"):
    out = P._clean(s_)
    check("NEW-BLOCKER-3 %r is redacted" % s_, not re.search(r"AWS|Azure|Google|Microsoft", out), out)
check("NEW-BLOCKER-3 a module path with a capitalized vendor segment is redacted throughout",
      P._clean("github.com/Azure/azure-sdk-for-go") == "github.com/<redacted>/<redacted>-sdk-for-go", P._clean("github.com/Azure/azure-sdk-for-go"))
# Codex #158 phase-2 r3 (NEW-BLOCKER-4): every name takes the separators, Meta and the platform qualifiers too
for s_ in ("confirmed by Me-ta", "confirmed by Me_ta", "confirmed by M.e.t.a", "confirmed by Me-ta Llama",
           "internal/me-ta-client.go", "internal/me_ta_client.go", "confirmed by Git-Hub Copilot", "confirmed by Goo-gle Gemini"):
    out = P._clean(s_)
    check("NEW-BLOCKER-4 %r is redacted" % s_, not re.search(r"(?i)m\W?e\W?t\W?a|git\W?hub|goo\W?gle|llama|copilot|gemini", out), out)
check("NEW-BLOCKER-4 ordinary words survive (metadata, metal)", P._clean("metadata metal") == "metadata metal", P._clean("metadata metal"))
# --- AC3: a push that removes a critical/high finding of the latest release cuts at once
REL = [  # the latest release's findings (grype on the published image): id, package, installed, fixed, severity, type
    {"id": "CVE-2099-1", "package": "golang.org/x/net", "installed": "v0.30.0", "fixed": "v0.33.0", "severity": "High", "type": "go-module"},
    {"id": "CVE-2099-2", "package": "stdlib", "installed": "go1.26.5", "fixed": "go1.26.6", "severity": "Critical", "type": "go-module"},
    {"id": "CVE-2099-3", "package": "libssl3", "installed": "3.0.15-1", "fixed": "3.0.16-1", "severity": "High", "type": "deb"},
    {"id": "CVE-2099-4", "package": "golang.org/x/text", "installed": "v0.20.0", "fixed": "v0.21.0", "severity": "Medium", "type": "go-module"},
]
HEAD = {"go": {"golang.org/x/net": "v0.33.0", "stdlib": "go1.26.5", "golang.org/x/text": "v0.21.0"},
        "base_findings": [{"id": "CVE-2099-3", "package": "libssl3"}]}       # the new base image still has it
got = P.removed_critical_high(REL, HEAD)
check("a critical/high go-module finding fixed at HEAD is removed", [f["id"] for f in got] == ["CVE-2099-1"], got)
check("a medium finding never triggers the at-once cut", "CVE-2099-4" not in [f["id"] for f in got])
got = P.removed_critical_high(REL, {"go": {"stdlib": "go1.26.6", "golang.org/x/net": "v0.30.0"}, "base_findings": []})
check("the toolchain (stdlib) and a deb package gone from the new base image are removed",
      sorted(f["id"] for f in got) == ["CVE-2099-2", "CVE-2099-3"], got)
got = P.removed_critical_high(REL, {"go": {"golang.org/x/net": "v0.31.0"}, "base_findings": [{"id": "CVE-2099-3", "package": "libssl3"}]})
check("a bump short of the fixed version, or a module whose HEAD version is unknown, removes nothing", got == [], got)
check("no fixed version known -> never counted as removed", P.removed_critical_high(
      [dict(REL[0], fixed="")], {"go": {"golang.org/x/net": "v9.9.9"}, "base_findings": []}) == [])
check("an unreadable new base image never counts as removing a deb finding", P.removed_critical_high(
      [REL[2]], {"go": {}, "base_findings": None}) == [])
# --- the decision the workflow acts on
FIX = [c("f1", ["go.mod"], diffs=BUMP)]
D = P.decide("push", FIX, ["v0.2.1"], cut_today=False, removed=[REL[0]])
check("push + patch-clean + a removed critical/high finding -> cut v0.2.2 now", D["cut"] and D["version"] == "v0.2.2", D)
D = P.decide("push", FIX, ["v0.2.1"], cut_today=True, removed=[REL[0]])
check("a critical/high fix cuts even after a patch today", D["cut"], D)
D = P.decide("push", FIX, ["v0.2.1"], cut_today=False, removed=[])
check("push without a removed critical/high finding -> wait for the daily run", not D["cut"] and D["reason"] == "no critical or high finding removed", D)
D = P.decide("schedule", FIX, ["v0.2.1"], cut_today=False, removed=[])
check("daily + patch-clean + shipped bytes -> cut", D["cut"] and D["version"] == "v0.2.2", D)
D = P.decide("schedule", FIX, ["v0.2.1"], cut_today=True, removed=[])
check("daily, already cut today -> no second", not D["cut"], D)
D = P.decide("schedule", FIX + [c("bad1234", ["internal/x.go"])], ["v0.2.1"], cut_today=False, removed=[])
check("not patch-clean -> no cut, the commits named for the standing issue", not D["cut"] and D["not_clean"] and "bad1234" in D["not_clean"][0], D)
D = P.decide("push", FIX + [c("bad1234", ["internal/x.go"])], ["v0.2.1"], cut_today=False, removed=[REL[0]])
check("not patch-clean blocks even a critical/high cut (a fix-only release is rule 1)", not D["cut"] and D["not_clean"], D)
D = P.decide("schedule", [c("d", ["docs/x.md"])], ["v0.2.1"], cut_today=False, removed=[])
check("nothing shipped since the tag -> no cut, no issue", not D["cut"] and not D["not_clean"], D)
D = P.decide("schedule", FIX, [], cut_today=False, removed=[])
check("no release yet -> no cut (the first release is the owner's)", not D["cut"], D)
# --- the command the workflow runs, over a real git repository
import json, os, subprocess, tempfile
def g(repo, *a):
    subprocess.run(["git", "-C", repo] + list(a), check=True, capture_output=True,
                   env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x"))
repo = tempfile.mkdtemp()
g(repo, "init", "-q", "-b", "main")
open(os.path.join(repo, "go.mod"), "w").write("module x\n\nrequire golang.org/x/sys v0.46.0\n")
os.makedirs(os.path.join(repo, "docs"))
g(repo, "add", "-A"); g(repo, "commit", "-q", "-m", "base"); g(repo, "tag", "v0.2.1")
open(os.path.join(repo, "go.mod"), "w").write("module x\n\nrequire golang.org/x/sys v0.47.0\n")
g(repo, "commit", "-qam", "bump")
open(os.path.join(repo, "docs", "a.md"), "w").write("doc\n")
g(repo, "add", "-A"); g(repo, "commit", "-q", "-m", "doc")
out = os.path.join(repo, "decision.json")
RL = os.path.join(repo, "released.json"); json.dump(["v0.2.1"], open(RL, "w"))
import io, contextlib
with contextlib.redirect_stdout(io.StringIO()):
    P.main(["decide", "--event", "schedule", "--repo", repo, "--cut-today", "false", "--released", RL, "--out", out])
D = json.load(open(out))
check("the command reads the real history since v0.2.1 and cuts v0.2.2", D["cut"] and D["version"] == "v0.2.2" and D["since"] == "v0.2.1", D)
open(os.path.join(repo, "main.go"), "w").write("package main\n")
g(repo, "add", "-A"); g(repo, "commit", "-q", "-m", "feature")
with contextlib.redirect_stdout(io.StringIO()) as so:
    P.main(["decide", "--event", "schedule", "--repo", repo, "--cut-today", "false", "--released", RL, "--out", out])
D = json.load(open(out))
check("a feature commit makes it not patch-clean, named", not D["cut"] and "main.go" in D["not_clean"][0], D)
sha = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
lab = os.path.join(repo, "labels.json"); json.dump({sha: ["patch-fix"]}, open(lab, "w"))
with contextlib.redirect_stdout(io.StringIO()):
    P.main(["decide", "--event", "workflow_dispatch", "--repo", repo, "--cut-today", "false", "--released", RL, "--labels", lab, "--out", out])
check("the patch-fix label on that PR admits it", json.load(open(out))["cut"], json.load(open(out)))
# Sonnet #159 r1: decision.json feeds the public "main is not patch-clean" issue, so it is redacted as stdout is
os.makedirs(os.path.join(repo, "internal"), exist_ok=True)
open(os.path.join(repo, "internal", "openai-adapter.go"), "w").write("package internal\n")
g(repo, "add", "-A"); g(repo, "commit", "-q", "-m", "adapter")
with contextlib.redirect_stdout(io.StringIO()):
    P.main(["decide", "--event", "schedule", "--repo", repo, "--cut-today", "false", "--released", RL, "--out", out])
raw = open(out).read()
check("decision.json names no vendor or model (the issue body reads it)", "openai" not in raw.lower() and "<redacted>" in raw, raw)
# --- `removed`: from grype's JSON for the release and the new base image, and HEAD's go.mod
def gm(id_, name, ver, fix, sev, typ):
    return {"vulnerability": {"id": id_, "severity": sev, "fix": {"versions": [fix] if fix else []}},
            "artifact": {"name": name, "version": ver, "type": typ}}
rel = os.path.join(repo, "rel.json"); json.dump({"matches": [
    gm("CVE-2099-1", "golang.org/x/net", "v0.30.0", "0.33.0", "High", "go-module"),
    gm("CVE-2099-2", "stdlib", "go1.26.5", "1.26.6", "Critical", "go-module"),
    gm("CVE-2099-3", "libssl3", "3.0.15-1", "3.0.16-1", "High", "deb")]}, open(rel, "w"))
gomod = os.path.join(repo, "head.mod"); open(gomod, "w").write("module x\n\ngo 1.26.6\n\nrequire (\n\tgolang.org/x/net v0.33.0\n)\n")
base = os.path.join(repo, "base.json"); json.dump({"matches": [gm("CVE-2099-3", "libssl3", "3.0.15-1", "3.0.16-1", "High", "deb")]}, open(base, "w"))
rem = os.path.join(repo, "removed.json")
P.main(["removed", "--release-grype", rel, "--gomod", gomod, "--base-grype", base, "--out", rem])
check("removed: the go module and the toolchain fixed at HEAD; the deb finding still in the new base stays",
      sorted(f["id"] for f in json.load(open(rem))) == ["CVE-2099-1", "CVE-2099-2"], json.load(open(rem)))
P.main(["removed", "--release-grype", rel, "--gomod", gomod, "--out", rem])
check("removed: no base scan -> no deb finding counts as removed", "CVE-2099-3" not in [f["id"] for f in json.load(open(rem))])
# gather_commits hands the classifier full context, so a require-block bump is judged (and a replace-block edit refused)
blk = tempfile.mkdtemp()
g(blk, "init", "-q", "-b", "main")
open(os.path.join(blk, "go.mod"), "w").write("module x\n\nrequire (\n\tgolang.org/x/sys v0.46.0\n)\n\nreplace (\n\tex.org/a v1.0.0 => ex.org/b v1.0.0\n)\n")
g(blk, "add", "-A"); g(blk, "commit", "-q", "-m", "base"); g(blk, "tag", "v0.2.1")
open(os.path.join(blk, "go.mod"), "w").write("module x\n\nrequire (\n\tgolang.org/x/sys v0.47.0\n)\n\nreplace (\n\tex.org/a v1.0.0 => ex.org/b v1.0.0\n)\n")
g(blk, "commit", "-qam", "bump")
cs = P.gather_commits("v0.2.1", blk)
check("gather: a require-block bump in a real repo is fix-class", [P.classify(x)[0] for x in cs] == ["fix"], [P.classify(x) for x in cs])
open(os.path.join(blk, "go.mod"), "w").write("module x\n\nrequire (\n\tgolang.org/x/sys v0.47.0\n)\n\nreplace (\n\tex.org/a v1.0.0 => ex.org/evil v1.0.0\n)\n")
g(blk, "commit", "-qam", "repl")
cs = P.gather_commits("v0.2.1", blk)
check("gather: a replace-block edit in a real repo is not patch-clean", [P.classify(x)[0] for x in cs] == ["fix", "dirty"], [P.classify(x) for x in cs])

# --- `ready` (advisor 0063; rules 2, 4, 7): a cut waits until the tagged commit's push-scoped required checks have
# finished, judged exactly as admission judges them (a success from the pinned app; pull_request-scoped checks are
# admission's to read on the merged PR head, never here)
REQ = {"required_checks": [{"context": "test", "integration_id": 15368, "scope": "push"},
                           {"context": "scan", "integration_id": 15368, "scope": "push"},
                           {"context": "dependency-review", "integration_id": 15368, "scope": "pull_request"}]}
def run(name, status="completed", conclusion="success", app=15368):
    return {"name": name, "status": status, "conclusion": conclusion if status == "completed" else None, "app_id": app}
for runs, want, why in [
    ([run("test"), run("scan")], "ready", "every push-scoped check green from the pinned app"),
    ([run("test"), run("scan", "in_progress")], "wait", "one still running"),
    ([run("test")], "wait", "one not created yet"),
    ([run("test"), run("scan", conclusion="failure")], "no", "one finished red"),
    ([run("test"), run("scan", conclusion="cancelled")], "no", "one cancelled"),
    ([run("test"), run("scan", app=999)], "wait", "a green run from another app does not count"),
    ([run("test"), run("scan", conclusion="failure"), run("scan")], "ready", "a green re-run counts, as admission takes any green"),
    ([run("test"), run("scan", conclusion="failure"), run("scan", "queued")], "wait", "red, but a re-run is queued"),
    ([run("test"), run("scan", conclusion="neutral")], "no", "neutral is not success"),
]:
    got = P.ready(REQ, runs)
    check("ready: %s -> %s" % (why, want), got[0] == want, got)
check("ready: names what it waits on", "scan" in P.ready(REQ, [run("test")])[1])
pol = os.path.join(repo, "req.json"); json.dump(REQ, open(pol, "w"))
cr = os.path.join(repo, "runs.json"); json.dump([run("test"), run("scan")], open(cr, "w"))
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = P.main(["ready", "--required", pol, "--check-runs", cr])
check("ready CLI: prints the verdict first", rc == 0 and buf.getvalue().split()[0] == "ready", buf.getvalue())
# a queued decide run recomputes the version from the tags its own checkout sees (advisor 0063): after an earlier run
# pushed v0.2.2, the next one cuts v0.2.3, never a second v0.2.2
check("a queued run after v0.2.2 was cut computes v0.2.3", P.decide("push", FIX, ["v0.2.1", "v0.2.2"], cut_today=True,
      removed=[REL[0]])["version"] == "v0.2.3")
# --- Codex #159 r1 (B1, B2, B4, B5, B6)
# B1: a prerelease or pseudo-version is below its release; a fix listed for several release streams counts only in the
# installed version's own stream (or when the installed version is at or past every listed fix)
for have, want, ok in [("v1.2.3-rc.1", ["1.2.3"], False), ("v1.2.3-0.20261001000000-aaaaaaaaaaaa", ["1.2.3"], False),
                       ("v1.2.3", ["1.2.3"], True), ("v1.2.4-rc.1", ["1.2.3"], True), ("go1.26rc1", ["1.26.0"], False),
                       ("go1.26.5", ["1.25.11", "1.26.6"], False), ("go1.26.6", ["1.25.11", "1.26.6"], True),
                       ("go1.25.11", ["1.26.6", "1.25.11"], True), ("go1.27.0", ["1.25.11", "1.26.6"], True),
                       ("go1.24.9", ["1.25.11", "1.26.6"], False), ("v1.2.3", "1.2.3", True), ("v1.2.2", "1.2.3", False)]:
    check("B1 %s fixes %s: %s" % (have, want, ok), P._at_least(have, want) == ok, P._at_least(have, want))
MULTI = [{"id": "CVE-2099-9", "package": "stdlib", "installed": "go1.26.5", "fixed": ["1.25.11", "1.26.6"],
          "severity": "High", "type": "go-module"}]
check("B1 an unchanged go1.26.5 is not 'fixed' by a fix for the 1.25 stream",
      P.removed_critical_high(MULTI, {"go": {"stdlib": "go1.26.5"}, "base_findings": []}) == [])
check("B1 grype_findings keeps every fix version", P.grype_findings({"matches": [{"vulnerability": {"id": "x", "severity": "High",
      "fix": {"versions": ["1.25.11", "1.26.6"]}}, "artifact": {"name": "stdlib", "version": "go1.26.5", "type": "go-module"}}]})[0]["fixed"]
      == ["1.25.11", "1.26.6"])
# B2: a scan document without a matches list is not a clean scan
for doc in ({}, {"matches": None}, None, [], {"matches": "x"}):
    try:
        P.grype_findings(doc); got = "accepted"
    except ValueError:
        got = "refused"
    check("B2 grype_findings refuses %r" % (doc,), got == "refused", got)
check("B2 an empty matches list is a clean scan", P.grype_findings({"matches": []}) == [])
bad = os.path.join(repo, "bad.json"); json.dump({}, open(bad, "w"))
rem2 = os.path.join(repo, "removed2.json")
P.main(["removed", "--release-grype", rel, "--gomod", gomod, "--base-grype", bad, "--out", rem2])
check("B2 a malformed base scan is no base scan (no deb finding counts as removed)", "CVE-2099-3" not in [f["id"] for f in json.load(open(rem2))])
rc = P.main(["removed", "--release-grype", bad, "--gomod", gomod, "--out", os.path.join(repo, "removed3.json")])
check("B2 a malformed release scan is an error, not an empty release", rc != 0 and not os.path.exists(os.path.join(repo, "removed3.json")))
D = P.decide("push", FIX, ["v0.2.1"], cut_today=False, removed=None)
check("B2 push with the release scan unknown: no at-once cut, and the reason says so", not D["cut"] and "could not be scanned" in D["reason"], D)
# B4: a failed (unreleased) tag is a used version number, never the baseline: the next run releases what it held
rel4 = tempfile.mkdtemp()
g(rel4, "init", "-q", "-b", "main")
open(os.path.join(rel4, "go.mod"), "w").write("module x\n\nrequire golang.org/x/sys v0.46.0\n")
g(rel4, "add", "-A"); g(rel4, "commit", "-q", "-m", "base"); g(rel4, "tag", "v0.2.1")
open(os.path.join(rel4, "go.mod"), "w").write("module x\n\nrequire golang.org/x/sys v0.47.0\n")
g(rel4, "commit", "-qam", "bump"); g(rel4, "tag", "v0.2.2")          # its release run failed: no published release
rl = os.path.join(rel4, "released.json"); json.dump(["v0.2.1"], open(rl, "w"))
o4 = os.path.join(rel4, "d.json")
with contextlib.redirect_stdout(io.StringIO()):
    P.main(["decide", "--event", "schedule", "--repo", rel4, "--cut-today", "false", "--released", rl, "--out", o4])
D = json.load(open(o4))
check("B4 the next daily run after a failed v0.2.2 cuts v0.2.3 from the last release v0.2.1", D["cut"] and D["version"] == "v0.2.3" and D["since"] == "v0.2.1", D)
try:
    with contextlib.redirect_stderr(io.StringIO()):
        P.main(["decide", "--event", "schedule", "--repo", rel4, "--cut-today", "false", "--out", o4]); got = "ran"
except SystemExit:
    got = "refused"
check("B4 decide needs the published releases (never falls back to the latest tag)", got == "refused", got)
# B5: a vendor name inside an identifier is redacted too
for s_ in ("internal/providerOpenAI.go", "internal/myClaudeClient.go", "x/useGeminiAPI.go", "pkg/providerMeta.go"):
    out = P._clean(s_)
    check("B5 %s is redacted" % s_, not re.search(r"(?i)openai|claude|gemini|meta\.go", out), out)
check("B5 ordinary words survive (metadata, so3)", P._clean("metadata so3") == "metadata so3", P._clean("metadata so3"))
# B6: a policy admission would reject is never "ready"
for pol_, why in [({}, "no required_checks"), ({"required_checks": None}, "required_checks null"),
                  ({"required_checks": [{"context": "test", "integration_id": 15368, "scope": "typo"}]}, "an unknown scope"),
                  ({"required_checks": [{"integration_id": 15368}]}, "no context"),
                  ({"required_checks": [{"context": "test"}]}, "no integration_id")]:
    got = P.ready(pol_, [run("test")])
    check("B6 ready refuses a policy with %s" % why, got[0] == "no" and "policy" in got[1], got)
json.dump([], open(rl, "w"))
with contextlib.redirect_stdout(io.StringIO()):
    P.main(["decide", "--event", "schedule", "--repo", rel4, "--cut-today", "false", "--released", rl, "--out", o4])
D = json.load(open(o4))
check("B4 tags but no published release: no cut, the first release is the owner's", not D["cut"] and "first release" in D["reason"], D)
for s_, want in (("internal/providerGoogle.go", "internal/provider<redacted>.go"), ("laws draws jaws", "laws draws jaws"),
                 ("useAzureClient", "use<redacted>Client")):
    check("B5 camelCase vendor %r" % s_, P._clean(s_) == want, P._clean(s_))
# Codex #159 pin pass B01: a null scope is "push", as admission's `.scope // "push"` reads it
NUL = {"required_checks": [{"context": "test", "integration_id": 15368, "scope": None},
                           {"context": "scan", "integration_id": 15368, "scope": "push"}]}
check("B01 a null-scoped check is push-scoped: absent -> wait, never ready", P.ready(NUL, [run("scan")])[0] == "wait", P.ready(NUL, [run("scan")]))
check("B01 a null-scoped check green -> ready", P.ready(NUL, [run("scan"), run("test")])[0] == "ready")
check("B01 scope 'pusH' is a policy error", P.ready({"required_checks": [{"context": "t", "integration_id": 1, "scope": "pusH"}]}, [])[0] == "no")
# handoff 0092 (advisor reading, AC text unchanged): patch-clean is measured from the same baseline — a failed or
# unpublished minor tag with a feature in it can never ride out as a patch
m5 = tempfile.mkdtemp()
g(m5, "init", "-q", "-b", "main")
open(os.path.join(m5, "go.mod"), "w").write("module x\n\nrequire golang.org/x/sys v0.46.0\n")
g(m5, "add", "-A"); g(m5, "commit", "-q", "-m", "base"); g(m5, "tag", "v0.2.1")
open(os.path.join(m5, "main.go"), "w").write("package main\n")
g(m5, "add", "-A"); g(m5, "commit", "-q", "-m", "feature"); g(m5, "tag", "v0.3.0")     # the owner's minor; its release failed
open(os.path.join(m5, "go.mod"), "w").write("module x\n\nrequire golang.org/x/sys v0.47.0\n")
g(m5, "commit", "-qam", "bump")
r5 = os.path.join(m5, "released.json"); json.dump(["v0.2.1"], open(r5, "w")); o5 = os.path.join(m5, "d.json")
with contextlib.redirect_stdout(io.StringIO()):
    P.main(["decide", "--event", "schedule", "--repo", m5, "--cut-today", "false", "--released", r5, "--out", o5])
D = json.load(open(o5))
check("0092 a failed minor tag's feature is measured from the published baseline: not patch-clean, no cut",
      not D["cut"] and D["since"] == "v0.2.1" and any("main.go" in w for w in D["not_clean"]), D)
# Codex #159 r2: each scan is validated on its own, records included (B2); scope 0 is not push (B6)
for doc, why in [({"matches": [{}]}, "a match without vulnerability or artifact"),
                 ({"matches": [{"vulnerability": {"id": "CVE-1"}, "artifact": {}}]}, "a match without package or version"),
                 ({"matches": {}}, "matches as an object")]:
    try:
        P.grype_findings(doc); got = "accepted"
    except ValueError:
        got = "refused"
    check("B2 grype_findings refuses %s" % why, got == "refused", got)
v1 = os.path.join(repo, "v1.json"); json.dump({"matches": []}, open(v1, "w"))
v2 = os.path.join(repo, "v2.json"); json.dump({"matches": {}}, open(v2, "w"))
rc = P.main(["removed", "--release-grype", v1, "--release-grype", v2, "--gomod", gomod, "--out", os.path.join(repo, "rm4.json")])
check("B2 one malformed release variant among valid ones makes the release unusable", rc != 0)
rc = P.main(["removed", "--release-grype", rel, "--gomod", gomod, "--base-grype", v1, "--base-grype", v2, "--out", os.path.join(repo, "rm5.json")])
check("B2 one malformed base scan makes the base unknown (no deb finding removed), the Go removals stand",
      rc == 0 and sorted(f["id"] for f in json.load(open(os.path.join(repo, "rm5.json")))) == ["CVE-2099-1", "CVE-2099-2"])
# Codex #159 r3 (NEW-1): nested fields of the wrong type are refused through the handled path, never a crash
M = lambda v, a: {"matches": [{"vulnerability": v, "artifact": a}]}
OKV, OKA = {"id": "CVE-2099-3", "severity": "High"}, {"name": "libssl3", "version": "3.0.15-1", "type": "deb"}
for doc, why in [(M(dict(OKV, fix={"versions": 1}), OKA), "fix.versions as a number"),
                 (M(dict(OKV, fix=["1"]), OKA), "fix as a list"),
                 (M(["x"], OKA), "vulnerability as a list"), (M(OKV, ["x"]), "artifact as a list"),
                 (M(dict(OKV, fix={"versions": [1]}), OKA), "a fix version that is not a string"),
                 (M(dict(OKV, severity=3), OKA), "severity as a number"),
                 (M(OKV, dict(OKA, type=["deb"])), "artifact type as a list"),
                 ({"matches": ["x"]}, "a match that is not an object")]:
    try:
        P.grype_findings(doc); got = "accepted"
    except ValueError:
        got = "refused"
    except Exception as e:
        got = "crashed: %r" % e
    check("NEW-1 grype_findings refuses %s" % why, got == "refused", got)
v3 = os.path.join(repo, "v3.json"); json.dump(M(dict(OKV, fix={"versions": 1}), OKA), open(v3, "w"))
try:
    rc = P.main(["removed", "--release-grype", rel, "--gomod", gomod, "--base-grype", v3, "--out", os.path.join(repo, "rm6.json")])
except Exception as e:
    rc = "crashed: %r" % e
check("NEW-1 a base scan with a malformed nested field leaves only the deb inference unknown; the Go removals stand",
      rc == 0 and sorted(f["id"] for f in json.load(open(os.path.join(repo, "rm6.json")))) == ["CVE-2099-1", "CVE-2099-2"], rc)
check("B6 scope 0 is a policy error, never push", P.ready({"required_checks": [{"context": "test", "integration_id": 15368, "scope": 0}]}, [run("test")])[0] == "no")
check("B6 scope '' is a policy error", P.ready({"required_checks": [{"context": "test", "integration_id": 15368, "scope": ""}]}, [run("test")])[0] == "no")
# REQ-REL-009 AC1, owner RATIFIED Oct 3 (item h, advisor 0123): patch-neutral means non-executable data only — docs/,
# requirements/, test-evidence/ data and the reviewed .github files; an executable test never counts
for f, want in [("bin/panel-test.sh", "dirty"), ("bin/brand-new-test.sh", "dirty"), ("cmd/fscache/main_test.go", "dirty"),
                (".github/agent/tests/auditor-matrix-test.sh", "dirty"), (".github/agent/bin/tests/test_x.py", "dirty"),
                ("docs/tool.py", "dirty"), ("test-evidence/gate", "dirty"), ("requirements/x.lua", "dirty"),
                (".vex/gate.sh", "dirty"), (".vex/fosterstack-cache.openvex.json", "fix"), (".auditor/accepted-items.json", "fix"),
                ("docs/a.md", "neutral"), ("requirements/requirements.yaml", "neutral"), ("test-evidence/mappings.yaml", "neutral"),
                (".github/CODEOWNERS", "neutral"), (".github/agent/reviews/x.json", "neutral")]:
    got = P.classify(c("q", [f], diffs={f: "+x\n"}))
    check("AC1(h) %s classifies %s" % (f, want), got[0] == want, got)
check("AC1(h) a test's reason says it is executable", "executable" in P.classify(c("r", ["bin/panel-test.sh"], diffs={"bin/panel-test.sh": "+x\n"}))[1])
check("AC1(h) a test-only change is not patch-clean (it waits for a normal release or a patch-fix label)",
      P.patch_clean([c("t1", ["bin/panel-test.sh"], diffs={"bin/panel-test.sh": "+x\n"})])[0] is False)
check("AC1(h) a patch-fix label still admits it", P.classify(c("t2", ["bin/panel-test.sh"], ["patch-fix"], diffs={"bin/panel-test.sh": "+x\n"}))[0] == "fix")
check("AC1(h) no allowlist, no scan: the classifier keeps neither", not hasattr(P, "NEUTRAL_TESTS") and not hasattr(P, "neutral_tests"))
dep = tempfile.mkdtemp()
g(dep, "init", "-q", "-b", "main")
open(os.path.join(dep, "go.mod"), "w").write("module x\n\nrequire golang.org/x/sys v0.46.0\n")
g(dep, "add", "-A"); g(dep, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base"); g(dep, "tag", "v0.1.0")
open(os.path.join(dep, "go.mod"), "w").write("module x\n\nrequire golang.org/x/sys v0.47.0\n")
g(dep, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "bump")
check("AC1(h) a dependency-only bump stays patch-clean", P.patch_clean(P.gather_commits("v0.1.0", cwd=dep)) == (True, []))
ci_text = open(os.path.join(os.path.dirname(sys.argv[1]), "..", ".github/workflows/ci.yml")).read()
check("CI guard: ci.yml runs nothing release-like (no release/stage workflow, no release environment, no tag push, no promotion)",
      not re.search(r"uses:\s*\./\.github/workflows/(release|stage-)|environment:\s*release\b|git\s+push\s+[^\n]*\bv\d|gh\s+release\s+(create|edit|upload)|cosign\s+(sign|attest)\b", ci_text))
# advisor 0130: behavior changes judged unable to affect supported clients, from docs/next-release-notes.md
NRN = """# Notes for the next release

Behavior changes since the last release, carried into its notes.

- Go 1.27: a request with more than 500 header values is rejected with 431 before it
  reaches the cache (owner accepted; advisor 0115).
- Second change, one line (advisor 0130).
"""
ents = P.behavior_entries(NRN)
check("0130 entries parsed, continuation lines joined", ents == [
    "Go 1.27: a request with more than 500 header values is rejected with 431 before it reaches the cache (owner accepted; advisor 0115).",
    "Second change, one line (advisor 0130)."], ents)
check("0130 an empty file has no entries", P.behavior_entries("# Notes for the next release\n\nBehavior changes since the last release, carried into its notes.\n") == [])
for bad in ["- A change nobody judged.\n", "- A change (owner said so).\n", "- A change (advisor 15).\n"]:
    try:
        P.behavior_entries(bad); raised = False
    except ValueError:
        raised = True
    check("0130 an entry without a cited handoff is refused: %r" % bad, raised)
nb = P.notes("v0.2.2", fixes, vex, behavior=ents)
check("0130 notes list behavior changes under their heading", "### Behavior changes\n- Go 1.27: a request" in nb, nb)
check("0130 with behavior changes the no-behavior-change line is dropped", "No behavior change" not in nb, nb)
check("0130 without them the no-behavior-change line stays", "No behavior change" in P.notes("v0.2.2", fixes, vex, behavior=[]))
check("0130 behavior entries are cleaned of vendor names too", "Gemini" not in P.notes("v0.2.2", [], [], behavior=["Gemini x (advisor 0130)."]))
# --- AC8 wired (advisor 0135): the notes are built from the scans, the VEX diff and docs/next-release-notes.md
rel_v = {"": [{"id": "CVE-2099-1", "package": "golang.org/x/net", "installed": "v0.30.0", "fixed": "v0.33.0", "severity": "High", "type": "go-module"},
              {"id": "CVE-2099-2", "package": "golang.org/x/text", "installed": "v0.20.0", "fixed": "v0.21.0", "severity": "Low", "type": "go-module"},
              {"id": "CVE-2099-3", "package": "golang.org/x/sys", "installed": "v0.40.0", "fixed": "v0.50.0", "severity": "Medium", "type": "go-module"}],
         "fips": [{"id": "CVE-2099-1", "package": "golang.org/x/net", "installed": "v0.30.0", "fixed": "v0.33.0", "severity": "High", "type": "go-module"}],
         "debug": [{"id": "CVE-2099-4", "package": "libc6", "installed": "2.36-9", "fixed": "2.36-10", "severity": "Medium", "type": "deb"}]}
fx = P.fixed_findings(rel_v, {"go": {"golang.org/x/net": "v0.33.0", "golang.org/x/text": "v0.22.0", "golang.org/x/sys": "v0.41.0"}, "base_findings": []})
check("AC8w every severity a release fixes is a note (low too), merged across variants",
      [(f["cve"], f["old"], f["new"], f["severity"], f["variants"]) for f in fx] == [
          ("CVE-2099-1", "v0.30.0", "v0.33.0", "High", ["default", "fips"]),
          ("CVE-2099-2", "v0.20.0", "v0.22.0", "Low", ["default"]),
          ("CVE-2099-4", "2.36-9", "2.36-10", "Medium", ["debug"])], fx)
check("AC8w a finding HEAD does not fix is not a note", all(f["cve"] != "CVE-2099-3" for f in fx))
check("AC8w no base evidence: no deb fix is claimed", all(f["cve"] != "CVE-2099-4" for f in P.fixed_findings(rel_v, {"go": {}, "base_findings": None})))
def vdoc(*st):
    return {"statements": [{"vulnerability": {"name": n}, "status": stt, "products": [{"@id": "pkg:oci/cache"}]} for n, stt in st]}
vc = P.vex_changes(vdoc(("CVE-1", "under_investigation"), ("CVE-2", "not_affected"), ("CVE-9", "not_affected")),
                   vdoc(("CVE-1", "not_affected"), ("CVE-2", "not_affected"), ("CVE-3", "affected")))
check("AC8w VEX: added, changed and removed statements, unchanged ones left out", vc == [
    {"cve": "CVE-1", "status": "not_affected", "change": "changed from under_investigation"},
    {"cve": "CVE-3", "status": "affected", "change": "added"},
    {"cve": "CVE-9", "status": "not_affected", "change": "removed"}], vc)
check("AC8w VEX: no old document (first patch) lists every statement as added",
      [v["change"] for v in P.vex_changes(None, vdoc(("CVE-1", "affected")))] == ["added"])
pub = "## v0.2.2 — patch release\n\n### Behavior changes\n- Go 1.27: a request with more than 500 header values is rejected with 431 before it reaches the cache (owner accepted; advisor 0115).\n"
check("0135 an entry an earlier patch published is not published again (tag message or CHANGELOG.md)",
      P.unpublished(ents, pub) == ["Second change, one line (advisor 0130)."], P.unpublished(ents, pub))
check("0135 nothing published yet: every entry stays", P.unpublished(ents, "") == ents)
tagraw = ("object 0123\ntype commit\ntag v0.2.2\ntagger fosterstack release <release@users.noreply.github.com> 1 +0000\n\n" + pub
          + "-----BEGIN SIGNED MESSAGE-----\nMIIabc\n-----END SIGNED MESSAGE-----\n")
check("AC8w tag-notes: a generated patch tag's message is its notes, the signature dropped", P.tag_notes(tagraw) == pub, P.tag_notes(tagraw))
check("AC8w tag-notes: an owner's tag message is not taken as notes",
      P.tag_notes("object 1\ntype commit\ntag v0.3.0\ntagger o <o@x> 1 +0000\n\nv0.3.0\n") is None)
check("AC8w tag-notes: a look-alike heading for another version is refused",
      P.tag_notes(tagraw.replace("tag v0.2.2", "tag v0.2.3")) is None)
cl, nn = P.changelog(pub, "# Changelog\n\n## v0.2.1 — patch release\n\nold\n", NRN)
check("AC8w changelog: the notes go on top, newest first", cl.startswith("# Changelog\n\n## v0.2.2 — patch release\n") and cl.index("v0.2.2") < cl.index("v0.2.1"), cl)
check("0130 changelog: the published entry leaves next-release-notes, an unpublished one stays",
      "Go 1.27" not in nn and "Second change, one line (advisor 0130)." in nn and nn.startswith("# Notes for the next release"), nn)
cl0, _ = P.changelog(pub, None, NRN)
check("AC8w changelog: a missing CHANGELOG.md is created with its heading", cl0.startswith("# Changelog\n\n## v0.2.2"), cl0)
nts = P.notes("v0.2.2", fx, vc, behavior=["Gemini helper changed (advisor 0130)."])
check("AC8w/row 48 the built notes name no vendor or model", not re.search(r"(?i)gemini|claude|openai", nts), nts)
# the signed tag keeps the notes' markdown headings: git tag's default cleanup would strip every '#' line
tg = tempfile.mkdtemp(); g(tg, "init", "-q", "-b", "main"); open(os.path.join(tg, "f"), "w").write("x")
g(tg, "add", "-A"); g(tg, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "c")
open(os.path.join(tg, "n.md"), "w").write(pub)
g(tg, "-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "--cleanup=verbatim", "-F", os.path.join(tg, "n.md"), "v0.2.2")
subprocess.run(["git", "-C", tg, "tag", "-a", "--cleanup=verbatim", "-F", os.path.join(tg, "n.md"), "v0.2.3"], check=True,
               env=dict(os.environ, GIT_COMMITTER_NAME="fosterstack release", GIT_COMMITTER_EMAIL="release@users.noreply.github.com"))
raw_ = subprocess.run(["git", "cat-file", "tag", "v0.2.3"], cwd=tg, capture_output=True, text=True).stdout
check("AC8w the tag made with --cleanup=verbatim keeps the notes' headings",
      P.tag_notes(raw_.replace("tag v0.2.3", "tag v0.2.2") + "-----BEGIN SIGNED MESSAGE-----\nx\n-----END SIGNED MESSAGE-----\n") == pub)
# Sonnet #159 r2, BLOCKER-1: only the release workflow's own patch tag carries notes — its tagger and a gitsign (x509)
# signature; an owner's tag (SSH-signed, any message) or an unsigned one never does; what is posted is always redacted
check("B1 an owner's SSH-signed tag shaped like a patch tag carries no notes",
      P.tag_notes(tagraw.replace("tagger fosterstack release <release@users.noreply.github.com>", "tagger Owner <o@x>")
                  .replace("SIGNED MESSAGE", "SSH SIGNATURE")) is None)
check("B1 the release tagger with an SSH signature carries no notes", P.tag_notes(tagraw.replace("SIGNED MESSAGE", "SSH SIGNATURE")) is None)
check("B1 an unsigned tag carries no notes", P.tag_notes(tagraw.split("-----BEGIN")[0]) is None)
# Sonnet #159 r2b (BLOCKER-1 reopened): the real signature is always the LAST such block in a genuine `git cat-file
# tag` (git appends it after the full message); splitting on the FIRST occurrence lets an attacker-embedded fake
# "-----BEGIN SIGNED MESSAGE-----" block earlier in the message pass as if it were the real one
raw2 = ("object 0123\ntype commit\ntag v0.2.2\ntagger fosterstack release <release@users.noreply.github.com> 1 +0000\n\n"
        + pub.replace("### Behavior changes", "-----BEGIN SIGNED MESSAGE-----\nAAAA\n-----END SIGNED MESSAGE-----\n\n### Behavior changes")
        + "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n")
check("B1 (r2b) a fake signature block embedded earlier in the message does not stand in for the real, LAST one",
      P.tag_notes(raw2) is None, P.tag_notes(raw2))
# Codex #159 fresh r2d: more than one signature-shaped block anywhere, in either order, is never a genuine tag —
# ssh-keygen's own signature check does not require the signature to be the object's literal last bytes, so "the real
# signature is last" alone is not fail-closed against a hand-crafted object with trailing bytes appended after it
fake_ = "-----BEGIN SIGNED MESSAGE-----\nAAAA\n-----END SIGNED MESSAGE-----\n"
real_sig_ = tagraw[tagraw.index("-----BEGIN SIGNED MESSAGE-----"):]
raw_after = tagraw[:tagraw.index("-----BEGIN SIGNED MESSAGE-----")] + real_sig_ + fake_
check("B1 (fresh r2d) a second signature-shaped block appended AFTER the real one is refused, not read as notes",
      P.tag_notes(raw_after) is None, P.tag_notes(raw_after))
check("B1 (fresh r2d) exactly one signature block, genuinely last, is still read", P.tag_notes(tagraw) == pub)
check("B1 (r2b) the real signature is still read when it is genuinely the last block", P.tag_notes(tagraw) == pub)
check("B1 another tagger with a gitsign signature carries no notes",
      P.tag_notes(tagraw.replace("fosterstack release <release@users.noreply.github.com>", "fosterstack release <x@evil>")) is None)
leak_ = P.tag_notes(tagraw.replace("### Behavior changes", "Thanks to OpenAI Codex and the Anthropic Claude team.\n\n### Behavior changes"))
check("B1 the notes a tag carries are redacted before they are posted", leak_ and not re.search(r"(?i)openai|codex|anthropic|claude", leak_), leak_)
cl_, _ = P.changelog("## v0.2.2 — patch release\n\nGemini helper\n", None, "")
check("B1 the changelog redacts what it is given", "Gemini" not in cl_, cl_)
# the notes CLI end to end: scans per variant, the VEX pair, the next-release file, the published guard
cd_ = tempfile.mkdtemp(); J_ = lambda n, o: (json.dump(o, open(os.path.join(cd_, n), "w")), os.path.join(cd_, n))[1]
gr = lambda fs: {"matches": [{"vulnerability": {"id": f["id"], "severity": f["severity"], "fix": {"versions": [f["fixed"]]}},
                              "artifact": {"name": f["package"], "version": f["installed"], "type": f["type"]}} for f in fs]}
open(os.path.join(cd_, "go.mod"), "w").write("module x\n\nrequire golang.org/x/net v0.33.0\n")
open(os.path.join(cd_, "nrn.md"), "w").write(NRN); open(os.path.join(cd_, "pub.txt"), "w").write(pub)
args = ["notes", "--version", "v0.2.3", "--variant-grype", "=" + J_("r.json", gr(rel_v[""])), "--variant-grype",
        "fips=" + J_("f.json", gr(rel_v["fips"])), "--gomod", os.path.join(cd_, "go.mod"), "--vex-old", J_("o.json", vdoc(("CVE-1", "affected"))),
        "--vex-new", J_("n.json", vdoc(("CVE-1", "not_affected"))), "--next-notes", os.path.join(cd_, "nrn.md"),
        "--published", os.path.join(cd_, "pub.txt"), "--out", os.path.join(cd_, "notes.md")]
rc = P.main(args); out_ = open(os.path.join(cd_, "notes.md")).read() if rc == 0 else ""
check("AC8w CLI notes: heading, the fix with its variants, the VEX change, only the unpublished entry",
      rc == 0 and out_.startswith("## v0.2.3 — patch release\n") and "CVE-2099-1 in golang.org/x/net: v0.30.0 → v0.33.0 (severity High; variants: default, fips)" in out_
      and "CVE-1: not_affected (changed from affected)" in out_ and "- Second change, one line (advisor 0130)." in out_ and "Go 1.27" not in out_, out_)
open(os.path.join(cd_, "nrn.md"), "w").write("- uncited change\n")
check("0130 CLI notes: an uncited entry refuses the notes (exit 2, so no tag)", P.main(args) == 2)
os.remove(os.path.join(cd_, "nrn.md"))
check("0130 CLI notes: no next-release-notes file means no behavior entries, not a refusal",
      P.main(args) == 0 and "No behavior change" in open(os.path.join(cd_, "notes.md")).read())
open(os.path.join(cd_, "n2.md"), "w").write(pub)
P.main(["changelog", "--notes", os.path.join(cd_, "n2.md"), "--changelog", os.path.join(cd_, "CL.md"), "--next-notes", os.path.join(cd_, "nrn.md")])
check("0130 CLI changelog: no next-release-notes file is not created", not os.path.exists(os.path.join(cd_, "nrn.md"))
      and open(os.path.join(cd_, "CL.md")).read().startswith("# Changelog\n\n## v0.2.2"))
# Sonnet #158 r2: the citation is enforced where the notes are made (SEC-2); a vendor name split by the line wrap or a
# space is refused, not redacted (SEC-1)
for bad_b in (["Some change nobody judged."], ["A change (owner said so)."]):
    try:
        P.notes("v0.2.2", [], [], behavior=bad_b); raised = False
    except ValueError:
        raised = True
    check("SEC-2 notes() refuses an uncited behavior entry %r" % bad_b[0], raised)
for split in ("- Goo\n  gle now rejects long headers (advisor 0130).\n", "- Op enAI client changed (advisor 0130).\n",
              "- the Clau de helper (advisor 0130).\n"):
    try:
        P.behavior_entries(split); raised = False
    except ValueError:
        raised = True
    check("SEC-1 a vendor name split by whitespace is refused: %r" % split, raised)
for split in ("- G o o g l e rejects long headers (advisor 0130).\n", "- the D e e p S e e k path (advisor 0130).\n",
              "- An thro pic changed (advisor 0130).\n", "- C\n  l a u\n  de helper (advisor 0130).\n"):
    try:
        P.behavior_entries(split); raised = False
    except ValueError:
        raised = True
    check("SEC-1 (Sonnet r2b) a name split into three or more pieces is refused: %r" % split, raised)
check("SEC-1 the real entries still pass (Go 1.27; metadata; to 1.2)", len(P.behavior_entries(NRN)) == 2 and
      P.behavior_entries("- metadata handling for a meta tag moved to 1.2 (advisor 0130).\n") != [])
# Codex #159 AC1(h) r1, B01: data is not executable — a changed file Git records as executable or as a symlink, or whose
# added content starts a script (#!), is never neutral or fix-class; B02: a reviewed workflow by its full path only
sh_ = "+#!/bin/sh\n+test 1 = 1 && printf AC1_EXECUTED\n"
for f in ("docs/gate.md", "requirements/gate.yaml", "test-evidence/gate.json", ".github/agent/docs/gate.txt",
          ".github/agent/reviews/gate.csv", ".github/CODEOWNERS", ".vex/gate.txt", ".auditor/gate.json", ".snyk", "osv-scanner.toml"):
    got = P.classify(c("x", [f], diffs={f: sh_}))
    check("B01 a script under a data name is dirty: %s" % f, got[0] == "dirty" and "executable" in got[1], got)
    for mode in ("100755", "120000"):
        got = P.classify(dict(c("x", [f], diffs={f: "+data\n"}), modes={f: mode}))
        check("B01 mode %s is dirty: %s" % (mode, f), got[0] == "dirty" and "executable" in got[1], got)
check("B01 an ordinary data file stays neutral", P.classify(dict(c("x", ["docs/a.md"], diffs={"docs/a.md": "+# heading\n"}), modes={"docs/a.md": "100644"}))[0] == "neutral")
check("B01 a deleted file (mode 000000) is not executable", P.classify(dict(c("x", ["docs/a.md"], diffs={"docs/a.md": "-x\n"}), modes={"docs/a.md": "000000"}))[0] == "neutral")
check("B01 a markdown line starting '#!' only after other text is data", P.classify(c("x", ["docs/a.md"], diffs={"docs/a.md": " intro\n+see #!/bin/sh in text\n"}))[0] == "neutral")
md = tempfile.mkdtemp(); g(md, "init", "-q", "-b", "main"); os.makedirs(os.path.join(md, "docs"))
open(os.path.join(md, "docs", "x.md"), "w").write("x\n"); g(md, "add", "-A"); g(md, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "b"); g(md, "tag", "v0.1.0")
os.chmod(os.path.join(md, "docs", "x.md"), 0o755); g(md, "-c", "core.fileMode=true", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "chmod")
gc = P.gather_commits("v0.1.0", cwd=md)
check("B01 gather_commits records each file's new mode; a mode-only chmod +x is dirty",
      gc and gc[0].get("modes", {}).get("docs/x.md") == "100755" and P.classify(gc[0])[0] == "dirty", gc)
for f, want in ((".github/workflows/unreviewed/ci.yml", "dirty"), (".github/workflows/sub/auditor.yml", "dirty"), (".github/workflows/ci.yml", "neutral")):
    got = P.classify(c("x", [f], diffs={f: "+note: data\n"}))
    check("B02 %s is %s (reviewed workflows by full path)" % (f, want), got[0] == want, got)
# neutral-path commits carry the data they commit: a neutral path is neutral only when the committed content is data
def nc(f, body=None, mode="100644", old_mode=None, labels=()):
    body = body if body is not None else ("{}\n" if f.endswith(".json") else "# notes\n")
    d = dict(c("n", [f], labels=labels, diffs={f: "".join("+%s\n" % l for l in body.split("\n")[:-1])} if mode != "000000" else {f: ""}), modes={f: mode})
    if old_mode:
        d["old_modes"] = {f: old_mode}
    return d
# --- REQ-REL-009-AC14 / AC15 (advisor 0254, 0257): a VEX-only range cuts an ordinary patch whose notes say so; the auditor's
# other work (panel state, knowledge, proposals) cuts nothing by itself
VEXF = ".vex/fosterstack-cache.openvex.json"
VEX_FORMS = [".vex/fosterstack-cache.csaf.json", ".vex/fosterstack-cache.inspector.json"]   # generated forms live beside it
VEXC = c("v1", [VEXF])
check("AC14 a range whose only change is the VEX file is fix-class", P.classify(VEXC)[0] == "fix", P.classify(VEXC))
check("AC14 the generated forms beside it are fix-class too", all(P.classify(c("f", [f]))[0] == "fix" for f in VEX_FORMS))
check("AC14 the VEX-only range is patch-clean and ships bytes", P.patch_clean([VEXC]) == (True, []) and P.ships_bytes([VEXC]), P.patch_clean([VEXC]))
check("AC14 the next tag is the next patch", P.next_patch(["v0.2.1", "v0.2.0"]) == "v0.2.2")
D = P.decide("schedule", [VEXC], ["v0.2.1"], cut_today=False, removed=None)
check("AC14 the daily run cuts it as vX.Y.(Z+1)", D["cut"] and D["version"] == "v0.2.2" and not D["not_clean"], D)
D = P.decide("schedule", [VEXC], ["v0.2.1"], cut_today=True, removed=None)
check("AC14 a second patch the same day waits", not D["cut"] and "already cut today" in D["reason"], D)
D = P.decide("schedule", [VEXC, c("v2", VEX_FORMS)], ["v0.2.1"], cut_today=False, removed=None)
check("AC14 the VEX and its generated forms together are still one clean patch", D["cut"], D)
D = P.decide("schedule", [VEXC, c("d1", ["internal/cache/store.go"])], ["v0.2.1"], cut_today=False, removed=None)
check("AC14 a VEX change beside a dirty commit is not patch-clean (named, no cut)", not D["cut"] and D["not_clean"] and "internal/cache/store.go" in D["not_clean"][0], D)
vex_old = {"statements": [{"vulnerability": {"name": "CVE-2099-0001"}, "status": "affected"},
                          {"vulnerability": {"name": "CVE-2099-0002"}, "status": "not_affected"},
                          {"vulnerability": {"name": "CVE-2099-0004"}, "status": "not_affected"}]}
vex_new = {"statements": [{"vulnerability": {"name": "CVE-2099-0001"}, "status": "fixed"},
                          {"vulnerability": {"name": "CVE-2099-0002"}, "status": "not_affected"},
                          {"vulnerability": {"name": "CVE-2099-0003"}, "status": "not_affected"}]}
ch = P.vex_changes(vex_old, vex_new)
txt = P.notes("v0.2.2", [], ch)
for cve in ("CVE-2099-0001", "CVE-2099-0003", "CVE-2099-0004"):
    check("AC14 the notes name the changed statement %s" % cve, cve in txt, txt)
check("AC14 an unchanged statement is not listed", "CVE-2099-0002" not in txt, txt)
check("AC14 the notes of a patch whose only fixes are VEX changes say VEX-only", "VEX-only" in txt, txt)
txt2 = P.notes("v0.2.2", fixes, ch)
check("AC14 a patch that also fixes a package does not say VEX-only", "VEX-only" not in txt2, txt2)
check("AC14 a patch with no VEX change does not say VEX-only", "VEX-only" not in P.notes("v0.2.2", fixes, []) and "VEX-only" not in P.notes("v0.2.2", [], []), "")
check("AC14 the VEX-only notes name no vendor or model", not re.search(r"(?i)claude|openai|gemini|codex|sonnet|opus|anthropic", P.notes("v0.2.2", [], [dict(ch[0], cve="CVE-2099-0001 confirmed by Claude")])), "")
# the command, over a real history: only the VEX file changed since the tag
vr = tempfile.mkdtemp()
g(vr, "init", "-q", "-b", "main")
os.makedirs(os.path.join(vr, ".vex")); os.makedirs(os.path.join(vr, ".auditor", "proposals"))
open(os.path.join(vr, "main.go"), "w").write("package main\n")
open(os.path.join(vr, VEXF), "w").write(json.dumps(vex_old) + "\n")
g(vr, "add", "-A"); g(vr, "commit", "-q", "-m", "base"); g(vr, "tag", "v0.2.1")
vaux = tempfile.mkdtemp()   # the command's own files live outside the history under test
vrl = os.path.join(vaux, "released.json"); json.dump(["v0.2.1"], open(vrl, "w"))
vout = os.path.join(vaux, "decision.json")
def decide_in(repo_, cut_today="false"):
    with contextlib.redirect_stdout(io.StringIO()):
        P.main(["decide", "--event", "schedule", "--repo", repo_, "--cut-today", cut_today, "--released", vrl, "--out", vout])
    return json.load(open(vout))
# AC15 first: the auditor's own work alone
for rel, body in ((".auditor/panel-state.json", "{}\n"), (".auditor/knowledge.md", "# knowledge\n"), (".auditor/proposals/p1.json", "[]\n")):
    open(os.path.join(vr, rel), "w").write(body)
    g(vr, "add", "-A"); g(vr, "commit", "-q", "-m", "auditor " + rel)
    D = decide_in(vr)
    check("AC15 %s alone cuts no release (git history)" % rel, not D["cut"] and not D["not_clean"], D)
check("AC15 auditor work classifies neutral, one by one",
      all(P.classify(nc(f))[0] == "neutral" for f in (".auditor/panel-state.json", ".auditor/knowledge.md", ".auditor/proposals/p1.json", ".auditor/proposals/adjudicator-proposals.json")),
      [P.classify(nc(f)) for f in (".auditor/panel-state.json", ".auditor/knowledge.md", ".auditor/proposals/p1.json")])
check("AC15 a range of only auditor work ships no bytes", not P.ships_bytes([nc(".auditor/panel-state.json"), nc(".auditor/knowledge.md"), nc(".auditor/proposals/p1.json")]))
D = P.decide("schedule", [nc(".auditor/panel-state.json"), nc(".auditor/knowledge.md")], ["v0.2.1"], cut_today=False, removed=None)
check("AC15 decide: nothing shipped, no cut, no issue", not D["cut"] and not D["not_clean"] and "nothing shipped" in D["reason"], D)
check("AC15 the suppression file .auditor/accepted-items.json stays fix-class", P.classify(c("a", [".auditor/accepted-items.json"]))[0] == "fix")
check("AC15 an auditor script is never data: still not patch-clean", P.classify(c("a", [".auditor/run.sh"]))[0] == "dirty")
D = P.decide("schedule", [nc(".auditor/panel-state.json"), VEXC], ["v0.2.1"], cut_today=False, removed=None)
check("AC15 auditor work beside a VEX change does not block that patch", D["cut"] and not D["not_clean"], D)
open(os.path.join(vr, VEXF), "w").write(json.dumps(vex_new) + "\n")
g(vr, "add", "-A"); g(vr, "commit", "-q", "-m", "vex")
D = decide_in(vr)
check("AC14 the real history (auditor work, then a VEX-only commit) cuts v0.2.2", D["cut"] and D["version"] == "v0.2.2" and not D["not_clean"], D)
D = decide_in(vr, cut_today="true")
check("AC14 the real history, a patch already cut today: waits", not D["cut"] and "already cut today" in D["reason"], D)
open(os.path.join(vr, "main.go"), "w").write("package main\n// changed\n")
g(vr, "add", "-A"); g(vr, "commit", "-q", "-m", "dirty")
D = decide_in(vr)
check("AC14 the real history with a dirty commit after the VEX change: not patch-clean", not D["cut"] and D["not_clean"] and "main.go" in D["not_clean"][0], D)
# the notes command, end to end, from the VEX at the tag and at HEAD
vn_old, vn_new = os.path.join(vaux, "old.vex"), os.path.join(vaux, "new.vex")
json.dump(vex_old, open(vn_old, "w")); json.dump(vex_new, open(vn_new, "w"))
scan = os.path.join(vaux, "scan.json"); json.dump({"matches": []}, open(scan, "w"))
gomod = os.path.join(vaux, "go.mod"); open(gomod, "w").write("module x\n\nrequire golang.org/x/sys v0.47.0\n")
pub = os.path.join(vaux, "published.txt"); open(pub, "w").write("")
nout = os.path.join(vaux, "notes.md")
with contextlib.redirect_stdout(io.StringIO()):
    rc = P.main(["notes", "--version", "v0.2.2", "--variant-grype", "=" + scan, "--gomod", gomod, "--vex-old", vn_old, "--vex-new", vn_new,
                 "--next-notes", os.path.join(vaux, "none.md"), "--published", pub, "--out", nout])
ntxt = open(nout).read() if rc == 0 else ""
check("AC14 the notes command: each changed statement named and VEX-only said", rc == 0 and all(x in ntxt for x in ("CVE-2099-0001", "CVE-2099-0003", "CVE-2099-0004", "VEX-only")), (rc, ntxt))
# --- step 6 round 1 (REQ-REL-009-AC14, AC15): what "a changed statement" is, when the notes say VEX-only, which auditor and .vex
# files are neutral
def stmt(cve, status="not_affected", products=("pkg:oci/cache",), **extra):
    d = {"vulnerability": {"name": cve}, "products": [{"@id": x} for x in products], "status": status}
    d.update(extra)
    return d
def vdoc2(stmts, **meta):
    d = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.test/vex", "author": "A", "timestamp": "2026-01-01T00:00:00Z", "version": 1, "statements": list(stmts)}
    d.update(meta)
    return d
def vex_section(text):
    sec = text.split("### VEX", 1)[1]
    return sec.split("\n\n", 1)[0] if "\n\n" in sec else sec
def vnotes(old, new, fixes_=(), behavior=()):
    return P.notes("v0.2.2", list(fixes_), P.vex_changes(old, new), behavior=list(behavior))
BASE_S = stmt("CVE-2099-0100", justification="component_not_present", impact_statement="not shipped")
for field, newval in (("justification", "vulnerable_code_not_present"), ("impact_statement", "different words"), ("action_statement", "upgrade"),
                      ("status_notes", "re-checked"), ("timestamp", "2026-02-02T00:00:00Z")):
    old = vdoc2([BASE_S]); chg = dict(BASE_S); chg[field] = newval
    sec = vex_section(vnotes(old, vdoc2([chg])))
    check("AC14 a changed %s alone is a changed statement: named with the field" % field, "CVE-2099-0100" in sec and field in sec and "no change" not in sec, sec)
sec = vex_section(vnotes(vdoc2([BASE_S]), vdoc2([stmt("CVE-2099-0100", products=("pkg:oci/cache", "pkg:oci/cache-fips"), justification="component_not_present", impact_statement="not shipped")])))
check("AC14 a changed product set is a changed statement", "CVE-2099-0100" in sec and "no change" not in sec, sec)
sec = vex_section(vnotes(vdoc2([BASE_S]), vdoc2([BASE_S, stmt("CVE-2099-0101")])))
check("AC14 an added statement is named", "CVE-2099-0101" in sec and "CVE-2099-0100" not in sec, sec)
sec = vex_section(vnotes(vdoc2([BASE_S, stmt("CVE-2099-0101")]), vdoc2([BASE_S])))
check("AC14 a removed statement is named", "CVE-2099-0101" in sec and "removed" in sec, sec)
A1, B1 = stmt("CVE-2099-0200", products=("pkg:oci/cache",), justification="component_not_present"), stmt("CVE-2099-0200", products=("pkg:golang/example.org/m",), justification="component_not_present")
B2 = dict(B1, justification="vulnerable_code_not_present")
for order, (o, n) in {"same order": ([A1, B1], [A1, B2]), "new order reversed": ([A1, B1], [B2, A1]), "old order reversed": ([B1, A1], [A1, B2])}.items():
    sec = vex_section(vnotes(vdoc2(o), vdoc2(n)))
    check("AC14 two statements for one vulnerability, only the second changed (%s): reported" % order, "CVE-2099-0200" in sec and "justification" in sec and "no change" not in sec, sec)
    check("AC14 ... and exactly one statement is reported (%s)" % order, sec.count("CVE-2099-0200") == 1, sec)
for order, (o, n) in {"reordered": ([A1, B1], [B1, A1])}.items():
    check("AC14 statements merely reordered are no statement change", P.vex_changes(vdoc2(o), vdoc2(n)) == [], P.vex_changes(vdoc2(o), vdoc2(n)))
for meta, label in (({"version": 2}, "version"), ({"timestamp": "2026-03-03T00:00:00Z"}, "timestamp")):
    sec = vex_section(vnotes(vdoc2([BASE_S]), vdoc2([BASE_S], **meta)))
    check("AC14 a document %s change alone is a VEX change, noted as document metadata" % label, "document metadata" in sec and "no change" not in sec, sec)
FX_ = [{"cve": "CVE-2099-0001", "package": "golang.org/x/sys", "old": "v0.46.0", "new": "v0.47.0", "severity": "high", "variants": ["production"]}]
CH_ = [{"cve": "CVE-2099-0005", "status": "not_affected", "change": "added"}]
BEH_ = ["a change no supported client can see (advisor 0130)"]
check("AC14 VEX changes alone: VEX-only", "VEX-only" in P.notes("v0.2.2", [], CH_), "")
check("AC14 VEX changes with a package fix: not VEX-only", "VEX-only" not in P.notes("v0.2.2", FX_, CH_), "")
check("AC14 VEX changes with behavior entries and no fixes: not VEX-only", "VEX-only" not in P.notes("v0.2.2", [], CH_, behavior=BEH_), P.notes("v0.2.2", [], CH_, behavior=BEH_))
check("AC14 no VEX change and no fix: not VEX-only", "VEX-only" not in P.notes("v0.2.2", [], []), "")
# the command: VEX alone, VEX + behavior entries, a reordering-only VEX change, an identical VEX
def notes_cli(old_doc, new_doc, nn=None, old_raw=None, new_raw=None):
    po, pn = os.path.join(vaux, "o.vex"), os.path.join(vaux, "n.vex")
    open(po, "w").write(old_raw if old_raw is not None else json.dumps(old_doc))
    open(pn, "w").write(new_raw if new_raw is not None else json.dumps(new_doc))
    nnp = os.path.join(vaux, "nn.md")
    if nn is None:
        nnp = os.path.join(vaux, "no-such-notes.md")
    else:
        open(nnp, "w").write(nn)
    with contextlib.redirect_stdout(io.StringIO()):
        rc_ = P.main(["notes", "--version", "v0.2.2", "--variant-grype", "=" + scan, "--gomod", gomod, "--vex-old", po, "--vex-new", pn,
                      "--next-notes", nnp, "--published", pub, "--out", nout])
    return open(nout).read() if rc_ == 0 else "RC=%d" % rc_
t1 = notes_cli(vdoc2([BASE_S]), vdoc2([dict(BASE_S, justification="vulnerable_code_not_present")]))
check("AC14 CLI: a statement changed in justification only: named, VEX-only", "CVE-2099-0100" in t1 and "justification" in t1 and "VEX-only" in t1, t1)
t2 = notes_cli(vdoc2([BASE_S]), vdoc2([dict(BASE_S, justification="vulnerable_code_not_present")]), nn="- a change no supported client can see (advisor 0130)\n")
check("AC14 CLI: the same VEX change beside a behavior entry: not VEX-only, the entry listed", "VEX-only" not in t2 and "advisor 0130" in t2 and "CVE-2099-0100" in t2, t2)
t3 = notes_cli(vdoc2([A1, B1]), vdoc2([B1, A1]))
check("AC14 CLI: a VEX file that only reorders its statements still ships: VEX-only (no statement change)", "VEX-only (no statement change)" in t3, t3)
t3b = notes_cli(None, None, old_raw=json.dumps(vdoc2([A1, B1])), new_raw=json.dumps(vdoc2([A1, B1]), indent=1))
check("AC14 CLI: a VEX file that only changes its bytes (formatting) still ships: VEX-only (no statement change)", "VEX-only (no statement change)" in t3b, t3b)
t4 = notes_cli(vdoc2([A1]), vdoc2([A1]), old_raw=json.dumps(vdoc2([A1])), new_raw=json.dumps(vdoc2([A1])))
check("AC14 CLI: an identical VEX file is no VEX change and not VEX-only", "VEX-only" not in t4 and "RC=" not in t4, t4)
t5 = notes_cli(vdoc2([BASE_S]), vdoc2([BASE_S], version=2))
check("AC14 CLI: a document version change alone: document metadata, VEX-only", "document metadata" in t5 and "VEX-only" in t5, t5)
# AC15: the neutral auditor set is exactly three names; the neutral .vex file is only its README
for f in (".auditor/panel-state.json", ".auditor/knowledge.md", ".auditor/proposals/p1.json", ".auditor/proposals/adjudicator-proposals.json", ".vex/README.md"):
    check("AC15 %s is neutral" % f, P.classify(nc(f))[0] == "neutral", P.classify(nc(f)))
for f, want in ((".auditor/accepted-items.json", "fix"), (".auditor/gate.json", "fix"), (".auditor/notes.md", "fix"), (".auditor/proposals/sub/x.json", "fix"),
                (".auditor/proposals/README.md", "fix"), (".vex/fosterstack-cache.openvex.json", "fix"), (".vex/other.json", "fix"), (".vex/sub/README.md", "fix"),
                (".auditor/proposals/hook.sh", "dirty"), (".auditor/run.sh", "dirty"), (".auditor/proposals/p_test.go", "dirty"), (".auditor/proposals/test_p.py", "dirty"),
                (".auditor/panel-state.sh", "dirty")):
    check("AC15 %s keeps its classification: %s" % (f, want), P.classify(c("n", [f]))[0] == want, P.classify(c("n", [f])))
for f in (".auditor/panel-state.json", ".auditor/knowledge.md", ".auditor/proposals/p1.json", ".vex/README.md"):
    for mode in ("100755", "120000"):
        got = P.classify(dict(c("n", [f], diffs={f: "+x\n"}), modes={f: mode}))
        check("AC15 %s with mode %s is dirty" % (f, mode), got[0] == "dirty", got)
    got = P.classify(c("n", [f], diffs={f: "+#!/bin/sh\n+echo x\n"}))
    check("AC15 %s carrying a script is dirty" % f, got[0] == "dirty", got)
check("AC15 a range of README-only .vex changes ships no bytes", not P.ships_bytes([nc(".vex/README.md")]))
D = P.decide("schedule", [nc(".vex/README.md")], ["v0.2.1"], cut_today=False, removed=None)
check("AC15 a .vex README edit alone cuts no patch", not D["cut"] and not D["not_clean"], D)
D = P.decide("schedule", [nc(".vex/README.md"), VEXC], ["v0.2.1"], cut_today=False, removed=None)
check("AC15 a .vex README edit beside the VEX file does not block that patch", D["cut"], D)
D = P.decide("schedule", [c("a", [".auditor/proposals/hook.sh"]), VEXC], ["v0.2.1"], cut_today=False, removed=None)
check("AC15 a script under .auditor/proposals beside a VEX change blocks the patch (named)", not D["cut"] and D["not_clean"] and ".auditor/proposals/hook.sh" in D["not_clean"][0], D)
# --- step 6 round 2 (REQ-REL-009-AC14): statements sharing a vulnerability are told apart by their product set; the
# bytes-only note never appears beside a behavior entry or a fix
PA, PB, PC = "pkg:oci/cache", "pkg:golang/example.org/m", "pkg:deb/debian/libx"
SA = stmt("CVE-2099-0300", products=(PA,), justification="component_not_present")
SB = stmt("CVE-2099-0300", products=(PB,), justification="component_not_present")
def lines_for(text, cve="CVE-2099-0300"):
    return [l for l in vex_section(text).split("\n") if cve in l]
SA2, SB2 = dict(SA, justification="vulnerable_code_not_present"), dict(SB, justification="vulnerable_code_not_present")
for label, (o, n), want_in, want_out in (
        ("the first statement changes", ([SA, SB], [SA2, SB]), [PA], [PB]),
        ("the second statement changes", ([SA, SB], [SA, SB2]), [PB], [PA]),
        ("the second changes and the order flips", ([SA, SB], [SB2, SA]), [PB], [PA])):
    ls = lines_for(vnotes(vdoc2(o), vdoc2(n)))
    check("AC14 %s: one line, naming that statement's products only" % label,
          len(ls) == 1 and all(x in ls[0] for x in want_in) and not any(x in ls[0] for x in want_out), ls)
ls = lines_for(vnotes(vdoc2([SA, SB]), vdoc2([SA2, SB2])))
check("AC14 both statements change: two lines, one per product set",
      len(ls) == 2 and sum(PA in l for l in ls) == 1 and sum(PB in l for l in ls) == 1 and all("justification" in l for l in ls), ls)
SC = stmt("CVE-2099-0300", products=(PC,), justification="component_not_present")
ls = lines_for(vnotes(vdoc2([SA, SB]), vdoc2([SA, SB, SC])))
check("AC14 a third statement for the vulnerability is added: its product named", len(ls) == 1 and PC in ls[0] and "added" in ls[0] and PA not in ls[0], ls)
ls = lines_for(vnotes(vdoc2([SA, SB, SC]), vdoc2([SA, SC])))
check("AC14 one of two statements removed: its product named", len(ls) == 1 and PB in ls[0] and "removed" in ls[0] and PA not in ls[0], ls)
SM1 = stmt("CVE-2099-0400", products=(PA, PB), justification="component_not_present")
SM2 = stmt("CVE-2099-0400", products=(PB, PA), justification="component_not_present")
check("AC14 a product list in another order is no change", P.vex_changes(vdoc2([SM1]), vdoc2([SM2])) == [], P.vex_changes(vdoc2([SM1]), vdoc2([SM2])))
check("AC14 two statements whose product lists are reordered are no change", P.vex_changes(vdoc2([SM1, SA]), vdoc2([SA, SM2])) == [], "")
SM3 = stmt("CVE-2099-0400", products=(PA, PC), justification="component_not_present")
ls = lines_for(vnotes(vdoc2([SM1]), vdoc2([SM3])), "CVE-2099-0400")
check("AC14 a changed product list names the members added and removed", len(ls) == 1 and "+" + PC in ls[0] and "-" + PB in ls[0] and PA not in ls[0].split("products", 1)[-1], ls)
# bytes-only changes beside behavior entries and fixes (the command)
BEH_TXT = "- a change no supported client can see (advisor 0130)\n"
def notes_cli2(old_raw, new_raw, nn=None, fixes_scan=False):
    po, pn = os.path.join(vaux, "o2.vex"), os.path.join(vaux, "n2.vex")
    open(po, "w").write(old_raw); open(pn, "w").write(new_raw)
    nnp = os.path.join(vaux, "nn2.md") if nn is not None else os.path.join(vaux, "no-such2.md")
    if nn is not None: open(nnp, "w").write(nn)
    sc = scan
    if fixes_scan:
        sc = os.path.join(vaux, "scanfix.json")
        json.dump({"matches": [{"vulnerability": {"id": "CVE-2099-1", "severity": "High", "fix": {"versions": ["v0.33.0"]}},
                                "artifact": {"name": "golang.org/x/net", "version": "v0.30.0", "type": "go-module"}}]}, open(sc, "w"))
        open(os.path.join(vaux, "go2.mod"), "w").write("module x\n\nrequire golang.org/x/net v0.33.0\n")
    with contextlib.redirect_stdout(io.StringIO()):
        rc_ = P.main(["notes", "--version", "v0.2.2", "--variant-grype", "=" + sc, "--gomod", os.path.join(vaux, "go2.mod") if fixes_scan else gomod,
                      "--vex-old", po, "--vex-new", pn, "--next-notes", nnp, "--published", pub, "--out", nout])
    return open(nout).read() if rc_ == 0 else "RC=%d" % rc_
V1 = vdoc2([SA, SB])
for label, (o, n) in (("formatting only", (json.dumps(V1), json.dumps(V1, indent=1))), ("statements reordered", (json.dumps(V1), json.dumps(vdoc2([SB, SA])))),
                      ("a product list reordered", (json.dumps(vdoc2([SM1])), json.dumps(vdoc2([SM2]))))):
    t = notes_cli2(o, n, nn=BEH_TXT)
    check("AC14 CLI: %s beside a behavior entry: the entry, no VEX-only" % label, "advisor 0130" in t and "VEX-only" not in t and "RC=" not in t, t)
    t = notes_cli2(o, n, fixes_scan=True)
    check("AC14 CLI: %s beside a package fix: the fix, no VEX-only" % label, "CVE-2099-1" in t and "VEX-only" not in t and "RC=" not in t, t)
    t = notes_cli2(o, n)
    check("AC14 CLI: %s alone: VEX-only (no statement change)" % label, "VEX-only (no statement change)" in t, t)
# --- step 6 round 3 (REQ-REL-009-AC14): several statements with the SAME vulnerability and the SAME product set
TA = stmt("CVE-2099-0500", products=(PA,), justification="component_not_present", timestamp="2026-01-01T00:00:00Z")
TB = stmt("CVE-2099-0500", products=(PA,), justification="component_not_present", timestamp="2026-02-02T00:00:00Z")
check("AC14 same-vulnerability same-product statements swapped in the file are no change", P.vex_changes(vdoc2([TA, TB]), vdoc2([TB, TA])) == [], P.vex_changes(vdoc2([TA, TB]), vdoc2([TB, TA])))
check("AC14 ... and unchanged in place are no change", P.vex_changes(vdoc2([TA, TB]), vdoc2([TA, TB])) == [])
TA2 = dict(TA, justification="vulnerable_code_not_present")
for label, (o, n) in {"in place": ([TA, TB], [TA2, TB]), "swapped": ([TA, TB], [TB, TA2]), "old swapped": ([TB, TA], [TA2, TB]), "both swapped": ([TB, TA], [TB, TA2])}.items():
    chg = P.vex_changes(vdoc2(o), vdoc2(n))
    check("AC14 one of two identical-key statements changes (%s): exactly that one is reported, with its field" % label,
          len(chg) == 1 and "justification" in chg[0]["change"] and "timestamp" not in chg[0]["change"], chg)
t = notes_cli2(json.dumps(vdoc2([TA, TB])), json.dumps(vdoc2([TB, TA])))
check("AC14 CLI: identical-key statements swapped: VEX-only (no statement change)", "VEX-only (no statement change)" in t and "CVE-2099-0500" not in t, t)
t = notes_cli2(json.dumps(vdoc2([TA, TB])), json.dumps(vdoc2([TB, TA2])))
check("AC14 CLI: one of the swapped identical-key statements changed: named once, VEX-only", t.count("CVE-2099-0500") == 1 and "VEX-only" in t and "no statement change" not in t, t)
t = notes_cli2(json.dumps(vdoc2([TA, TB])), json.dumps(vdoc2([TB, TA])), nn=BEH_TXT)
check("AC14 CLI: identical-key statements swapped beside a behavior entry: no VEX-only", "advisor 0130" in t and "VEX-only" not in t, t)
# --- step 6 round 5 (REQ-REL-009-AC14): removing an optional field of a surviving statement is a changed statement
RF = stmt("CVE-2099-0600", justification="component_not_present", impact_statement="not shipped", action_statement="none", status_notes="n", timestamp="2026-01-01T00:00:00Z")
for fld in ("impact_statement", "action_statement", "status_notes", "timestamp", "justification"):
    gone = {k: v for k, v in RF.items() if k != fld}
    chg = P.vex_changes(vdoc2([RF]), vdoc2([gone]))
    check("AC14 removing %s from a surviving statement is a change that names the field" % fld, len(chg) == 1 and fld in chg[0]["change"] and "CVE-2099-0600" in chg[0]["cve"], chg)
    chg = P.vex_changes(vdoc2([gone]), vdoc2([RF]))
    check("AC14 adding %s to a surviving statement is a change that names the field" % fld, len(chg) == 1 and fld in chg[0]["change"], chg)
gone = {k: v for k, v in RF.items() if k != "impact_statement"}
t = notes_cli2(json.dumps(vdoc2([RF])), json.dumps(vdoc2([gone])))
check("AC14 CLI: an optional field removed: the statement is named, VEX-only, not 'no statement change'",
      "CVE-2099-0600" in t and "impact_statement" in t and "VEX-only" in t and "no statement change" not in t, t)
t = notes_cli2(json.dumps(vdoc2([RF])), json.dumps(vdoc2([gone])), nn=BEH_TXT)
check("AC14 CLI: an optional field removed beside a behavior entry: the statement named, no VEX-only", "CVE-2099-0600" in t and "VEX-only" not in t and "advisor 0130" in t, t)
# --- step 8 round 1 (REQ-REL-009-AC14, AC15): data validation of the neutral paths, old modes, renames; metadata-only wording; subcomponents; redaction
def put_(r_, files):
    for path, (content, mode) in files.items():
        full = os.path.join(r_, path); os.makedirs(os.path.dirname(full), exist_ok=True)
        if os.path.lexists(full): os.remove(full)
        if mode == "120000": os.symlink(content, full)
        else:
            open(full, "w").write(content); os.chmod(full, 0o755 if mode == "100755" else 0o644)
def mv_(r_, a, b):
    os.makedirs(os.path.dirname(os.path.join(r_, b)), exist_ok=True); g(r_, "mv", a, b)
def gitrepo(base):
    r_ = tempfile.mkdtemp(); g(r_, "init", "-q", "-b", "main"); put_(r_, base)
    g(r_, "add", "-A"); g(r_, "commit", "-q", "-m", "base"); g(r_, "tag", "v0.1.0"); return r_
def verdict_(base, act, labels=()):
    r_ = gitrepo(base); act(r_); g(r_, "add", "-A"); g(r_, "commit", "-q", "-m", "range")
    cs_ = P.gather_commits("v0.1.0", cwd=r_, labels=lambda sha: list(labels))
    return P.classify(cs_[-1]), cs_[-1]
KN, PS, PJ, RD = ".auditor/knowledge.md", ".auditor/panel-state.json", ".auditor/proposals/p.json", ".vex/README.md"
BASE0 = {"docs/keep.md": ("x\n", "100644")}
def verdict_new(path, content, mode="100644"):
    return verdict_(BASE0, lambda r_: put_(r_, {path: (content, mode)}))[0][0]
for path, good in ((PS, '{"a": 1}\n'), (PS, "[1, 2]\n"), (PJ, '{"a": 1}\n'), (PJ, "[]\n"), (KN, "# knowledge\ntext\n"), (RD, "# readme\n")):
    check("AC15 git: a new %s with data content is neutral" % path, verdict_new(path, good) == "neutral", verdict_new(path, good))
for path in (PS, PJ):
    for bad in ("{", "3\n", '"str"\n', "null\n", "", "print('x')\n", "#!/bin/sh\necho x\n"):
        check("AC15 git: a new %s holding %r is not data: dirty" % (path, bad[:12]), verdict_new(path, bad) == "dirty", verdict_new(path, bad))
for path in (KN, RD):
    check("AC15 git: a new %s starting with a shebang line is dirty" % path, verdict_new(path, "#!/bin/sh\necho x\n") == "dirty")
    check("AC15 git: a new %s with a NUL byte is dirty" % path, verdict_new(path, "text\0binary\n") == "dirty")
    base = dict(BASE0, **{path: ("#!/bin/sh\nold body\n", "100644")})
    got = verdict_(base, lambda r_, path=path: put_(r_, {path: ("#!/bin/sh\nnew body\n", "100644")}))[0][0]
    check("AC15 git: %s whose first line is an unchanged shebang and whose body is edited is dirty" % path, got == "dirty", got)
    base = dict(BASE0, **{path: ("plain\nold body\n", "100644")})
    got = verdict_(base, lambda r_, path=path: put_(r_, {path: ("plain\nnew body\n", "100644")}))[0][0]
    check("AC15 git: an ordinary edit of %s is neutral" % path, got == "neutral", got)
    got = verdict_(base, lambda r_, path=path: put_(r_, {path: ("#!/bin/sh\nplain\nnew body\n", "100644")}))[0][0]
    check("AC15 git: an edit of %s that makes line 1 a shebang is dirty" % path, got == "dirty", got)
for path in (PS, PJ, KN, RD):
    good = '{"a": 1}\n' if path.endswith(".json") else "text\n"
    for mode in ("100755", "120000"):
        got = verdict_new(path, good if mode == "100755" else "docs/keep.md", mode)
        check("AC15 git: a new %s with mode %s is dirty" % (path, mode), got == "dirty", got)
        base = dict(BASE0, **{path: (good if mode == "100755" else "docs/keep.md", mode)})
        got = verdict_(base, lambda r_, path=path: (os.remove(os.path.join(r_, path))))[0][0]
        check("AC15 git: deleting %s whose old mode was %s is dirty" % (path, mode), got == "dirty", got)
    base = dict(BASE0, **{path: (good, "100755")})
    got = verdict_(base, lambda r_, path=path: os.chmod(os.path.join(r_, path), 0o644))[0][0]
    check("AC15 git: taking the executable bit off %s is not a clean data change: dirty" % path, got == "dirty", got)
    base = dict(BASE0, **{path: (good, "100755")})
    got = verdict_(base, lambda r_, path=path: (put_(r_, {path: (good + ("\n" if path.endswith(".json") else "more text\n"), "100644")})))[0][0]
    check("AC15 git: an executable %s turned into a data file with new content in one commit is dirty (its old mode)" % path, got == "dirty", got)
    base = dict(BASE0, **{path: (good, "100644")})
    got = verdict_(base, lambda r_, path=path: os.remove(os.path.join(r_, path)))[0][0]
    check("AC15 git: deleting an ordinary %s is neutral" % path, got == "neutral", got)
check("AC15 git: renaming an executable neutral-named file away is dirty",
      verdict_(dict(BASE0, **{KN: ("x\n", "100755")}), lambda r_: mv_(r_, KN, "docs/y.md"))[0][0] == "dirty")
check("AC15 git: renaming source code onto a neutral path is dirty (the deleted source shows)",
      verdict_(dict(BASE0, **{"internal/cache/store.go": ("package cache\n", "100644")}), lambda r_: mv_(r_, "internal/cache/store.go", KN))[0][0] == "dirty")
check("AC15 git: renaming the production Dockerfile onto a proposals path is dirty",
      verdict_(dict(BASE0, **{"build/docker/Dockerfile.production": ("FROM x@sha256:" + "a" * 64 + "\nCOPY a b\n", "100644")}),
               lambda r_: mv_(r_, "build/docker/Dockerfile.production", PJ))[0][0] == "dirty")
check("AC15 git: renaming a docs file onto a neutral path is neutral",
      verdict_(dict(BASE0, **{"docs/a.md": ("text\n", "100644")}), lambda r_: mv_(r_, "docs/a.md", KN))[0][0] == "neutral")
rn_commit = verdict_(dict(BASE0, **{"internal/cache/store.go": ("package cache\n", "100644")}), lambda r_: mv_(r_, "internal/cache/store.go", KN))[1]
check("AC15 gather_commits lists the deleted source of a rename", "internal/cache/store.go" in rn_commit["files"] and KN in rn_commit["files"], rn_commit["files"])
check("AC15 gather_commits records the old mode of every path", rn_commit.get("old_modes", {}).get("internal/cache/store.go") == "100644", rn_commit.get("old_modes"))
# the patch-fix label never makes a non-data neutral path fix-class
for mode in ("120000", "100755"):
    d_ = nc(PS, mode=mode, labels=("patch-fix",))
    check("AC15 the patch-fix label does not clear a mode-%s change at a neutral path" % mode, P.classify(d_)[0] == "dirty", P.classify(d_))
    got = verdict_(BASE0, lambda r_, mode=mode: put_(r_, {KN: ("docs/keep.md" if mode == "120000" else "x\n", mode)}), labels=("patch-fix",))[0][0]
    check("AC15 git: the label does not clear a mode-%s new neutral file" % mode, got == "dirty", got)
check("AC15 unit: a neutral path without a mode is not proven data: dirty", P.classify(dict(c("n", [PS], diffs={PS: "+{}"}), modes={}))[0] == "dirty")
check("AC15 unit: mode 100664 is not 100644: dirty", P.classify(nc(PS, mode="100664"))[0] == "dirty")
check("AC15 unit: a deletion whose old mode is unknown is dirty (fail closed)", P.classify(nc(PS, mode="000000"))[0] == "dirty")
check("AC15 unit: a deletion of an ordinary file is neutral", P.classify(nc(PS, mode="000000", old_mode="100644"))[0] == "neutral")
D = P.decide("schedule", [verdict_(dict(BASE0, **{KN: ("#!/bin/sh\nold\n", "100644")}), lambda r_: put_(r_, {KN: ("#!/bin/sh\nnew\n", "100644")}))[1], VEXC], ["v0.2.1"], cut_today=False, removed=None)
check("AC15 an edited script named like a neutral file beside a VEX change blocks the patch", not D["cut"] and D["not_clean"], D)
# metadata-only and mixed VEX changes
MD_OLD, MD_NEW = vdoc2([BASE_S]), vdoc2([BASE_S], version=2, timestamp="2026-05-05T00:00:00Z")
ch = P.vex_changes(MD_OLD, MD_NEW)
txt = P.notes("v0.2.2", [], ch)
check("AC14 a metadata-only change: document metadata and VEX-only (no statement change), not 'changes VEX statements'",
      "document metadata" in txt and "VEX-only (no statement change)" in txt and "changes VEX statements" not in txt, txt)
txt = P.notes("v0.2.2", [], P.vex_changes(MD_OLD, vdoc2([dict(BASE_S, justification="vulnerable_code_not_present")], version=2)))
check("AC14 metadata and a statement change together: says statements, notes the metadata, not 'no statement change'",
      "changes VEX statements" in txt and "document metadata" in txt and "no statement change" not in txt, txt)
t = notes_cli2(json.dumps(MD_OLD), json.dumps(MD_NEW))
check("AC14 CLI: a metadata-only change: document metadata and VEX-only (no statement change)", "document metadata" in t and "VEX-only (no statement change)" in t and "changes VEX statements" not in t, t)
t = notes_cli2(json.dumps(MD_OLD), json.dumps(vdoc2([dict(BASE_S, justification="vulnerable_code_not_present")], version=2)))
check("AC14 CLI: metadata and a statement change: says statements", "changes VEX statements" in t and "document metadata" in t and "no statement change" not in t, t)
t = notes_cli2(json.dumps(MD_OLD), json.dumps(MD_NEW), nn=BEH_TXT)
check("AC14 CLI: a metadata-only change beside a behavior entry: no VEX-only", "VEX-only" not in t and "advisor 0130" in t, t)
# a product's subcomponents
def prod(pid, *subs):
    p_ = {"@id": pid}
    if subs: p_["subcomponents"] = [{"@id": x} for x in subs]
    return p_
def pstmt(*products, **extra):
    d = {"vulnerability": {"name": "CVE-2099-0700"}, "products": list(products), "status": "not_affected", "justification": "component_not_present"}
    d.update(extra); return d
ch = P.vex_changes(vdoc2([pstmt(prod(PA, "pkg:golang/x"))]), vdoc2([pstmt(prod(PA, "pkg:golang/y"))]))
line = [l for l in vex_section(P.notes("v0.2.2", [], ch)).split("\n") if "CVE-2099-0700" in l]
check("AC14 a subcomponent-only change names the members added and removed", len(line) == 1 and "pkg:golang/y" in line[0] and "pkg:golang/x" in line[0] and "+" in line[0] and "-" in line[0], line)
check("AC14 subcomponents in another order are no change", P.vex_changes(vdoc2([pstmt(prod(PA, "pkg:golang/x", "pkg:golang/y"))]), vdoc2([pstmt(prod(PA, "pkg:golang/y", "pkg:golang/x"))])) == [], "")
t = notes_cli2(json.dumps(vdoc2([pstmt(prod(PA, "pkg:golang/x"))])), json.dumps(vdoc2([pstmt(prod(PA, "pkg:golang/y"))])))
check("AC14 CLI: a subcomponent-only change names the members", "pkg:golang/y" in t and "pkg:golang/x" in t, t)
# redaction keeps product identifiers readable
INTACT = ["pkg:golang/google.golang.org/grpc@v1.2.0", "pkg:maven/com.google.guava/guava@32.1.0", "pkg:golang/github.com/aws/aws-sdk-go-v2", "google.golang.org/grpc", "pkg:golang/cloud.google.com/go/storage"]
for ident in INTACT:
    for tmpl in ("%s", "[%s]", "CVE-1 [%s, pkg:oci/cache]: x", "(%s)", "see %s."):
        out_ = P._clean(tmpl % ident)
        check("redaction: %s stays readable in %r" % (ident, tmpl), ident in out_, out_)
SA_, SB_ = stmt("CVE-2099-0800", products=("pkg:golang/google.golang.org/grpc@v1.2.0",)), stmt("CVE-2099-0800", products=("pkg:maven/com.google.guava/guava@32.1.0",))
txt = P.notes("v0.2.2", [], P.vex_changes(vdoc2([SA_, SB_]), vdoc2([dict(SA_, justification="x"), SB_])))
check("redaction: the notes keep the product identity of an ambiguous statement intact", "pkg:golang/google.golang.org/grpc@v1.2.0" in txt, txt)
for secret in ("confirmed by Google", "reported by Bedrock", "thanks Claude", "see [github.com/Azure/azure-sdk-for-go]", "pkg:golang/github.com/Azure/azure-sdk-for-go", "Meta Llama"):
    out_ = P._clean(secret)
    check("redaction: %r is still redacted" % secret, "<redacted>" in out_ and not re.search(r"(?i)claude|bedrock|llama|(?<![a-z])google(?![.\w])|(?<![a-z/])azure", out_.replace("azure-sdk-for-go", "")), out_)
print("patch-decide: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
