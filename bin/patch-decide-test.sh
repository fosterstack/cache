#!/usr/bin/env bash
# proves: REQ-REL-009-AC1, REQ-REL-009-AC2, REQ-REL-009-AC3, REQ-REL-009-AC4, REQ-REL-009-AC8, REQ-REL-009-AC11
# The automatic patch-release decision (owner RATIFIED Oct 2; advisor read-backs 0051/0055/0056), offline: commits are
# classified fix-class / neutral / not patch-clean by the files they change (a patch-fix label admits a source change);
# the next tag is vX.Y.(Z+1); the daily rule cuts at most once a day; release notes list each fix and name no vendor or
# model; floating tags move :X.Y always and :X / :latest only for the highest version.
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT  # python tempfile and mktemp dirs all live under this one, removed on exit
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
# AC8 (handoff 0389 (d); rule 0254 "names the statements that changed"): a statement changed in any field, not only its
# status, is a changed statement; the notes name the CVE and which fields changed; two statements for one CVE stay two
VS = {"vulnerability": {"name": "CVE-7"}, "status": "not_affected", "justification": "component_not_present",
      "impact_statement": "absent", "action_statement": "none", "status_notes": "n1",
      "products": [{"@id": "pkg:oci/cache?tag=debug"}]}
def vs(drop=(), **kw):
    s = json.loads(json.dumps(VS)); s.update(kw)
    for k in drop:
        s.pop(k)
    return s
def vd(*st):
    return {"statements": list(st)}
for field, val in (("products", [{"@id": "pkg:oci/cache@sha256:" + "d" * 64}]), ("justification", "vulnerable_code_not_present"),
                   ("impact_statement", "absent, rechecked"), ("action_statement", "none, rechecked"), ("status_notes", "n2")):
    vc_ = P.vex_changes(vd(VS), vd(vs(**{field: val})))
    check("AC8 VEX: a %s-only change is a changed statement naming the field" % field,
          len(vc_) == 1 and vc_[0]["cve"] == "CVE-7" and vc_[0]["change"] == "changed: %s" % field, vc_)
    nt_ = P.notes("v0.2.3", [], vc_)
    check("AC8 VEX notes: a %s-only change is listed, not 'no change'" % field,
          "- no change" not in nt_ and "- CVE-7: not_affected (changed: %s)" % field in nt_, nt_)
vc_ = P.vex_changes(vd(VS), vd(vs(drop=("status_notes",), status="affected", justification="")))
check("AC8 VEX: a status change with other fields names the old status and every other field (a dropped field too)",
      [v["change"] for v in vc_] == ["changed from not_affected; also justification, status_notes"], vc_)
check("AC8 VEX: an unchanged statement is left out", P.vex_changes(vd(VS), vd(vs())) == [])
check("AC8 VEX: a reordered statement list is no change", P.vex_changes(vd(VS, vs(vulnerability={"name": "CVE-8"})),
      vd(vs(vulnerability={"name": "CVE-8"}), VS)) == [])
D1, D2 = [{"@id": "pkg:oci/cache@sha256:" + "1" * 64}], [{"@id": "pkg:oci/cache@sha256:" + "2" * 64}]
two = vd(vs(products=D1), vs(products=D2, status_notes="for v0.2.2"))
vc_ = P.vex_changes(vd(VS), two)
check("AC8 VEX: one statement split into two for one CVE does not collapse: the old one removed, both new ones added",
      sorted((v["change"], " ".join(v.get("products", []))) for v in vc_) == [
          ("added", D1[0]["@id"]), ("added", D2[0]["@id"]), ("removed", VS["products"][0]["@id"])], vc_)
vc_ = P.vex_changes(two, vd(vs(products=D1), vs(products=D2, status_notes="for v0.2.2, rechecked")))
check("AC8 VEX: one CVE, two statements, only one changed: exactly that one is named, by its products",
      len(vc_) == 1 and vc_[0]["change"] == "changed: status_notes" and vc_[0].get("products") == [D2[0]["@id"]], vc_)
nt_ = P.notes("v0.2.3", [], vc_)
check("AC8 VEX notes: a CVE with several statements names the statement's products",
      # r4 (A R3-5): '@' is never bare, so the purl prints as its quoted literal
      "- CVE-7 [`\"%s\"`]: not_affected (changed: status_notes)" % D2[0]["@id"] in nt_ and "1" * 64 not in nt_, nt_)
vc_ = P.vex_changes(two, vd(vs(products=D1)))
check("AC8 VEX: one of two statements for a CVE removed is named as removed, by its products",
      len(vc_) == 1 and vc_[0]["change"] == "removed" and vc_[0].get("products") == [D2[0]["@id"]], vc_)
vc_ = P.vex_changes(vd(vs(products=D1)), two)
check("AC8 VEX: a second statement added for a CVE is named as added, by its products",
      len(vc_) == 1 and vc_[0]["change"] == "added" and vc_[0].get("products") == [D2[0]["@id"]], vc_)
vc_ = P.vex_changes(vd(VS), vd(vs(timestamp="2026-10-11T00:00:00Z")))
check("AC8 VEX: a change to any other statement field is named too (fail closed)",
      [v["change"] for v in vc_] == ["changed: timestamp"], vc_)
# AC8 (advisor ruling on 0389 (d), the reading of rule 0254 "every change to our published VEX"): a change only to
# document-level fields is still a VEX change; the notes say which document fields changed, never "no change"
def vdd(st=(VS,), **kw):
    d = {"@id": "https://example.invalid/vex", "author": "a", "timestamp": "t1", "version": 6, "statements": list(st)}
    d.update(kw); return d
def vex_part(n):
    return n.split("### VEX\n", 1)[1].split("\n\n", 1)[0]
for label, kw, want in (("document-version-only", {"version": 7}, "version"), ("timestamp-only", {"timestamp": "t2"}, "timestamp"),
                        ("version and timestamp together", {"version": 7, "timestamp": "t2"}, "timestamp, version")):
    nt_ = P.notes("v0.2.3", [], P.vex_changes(vdd(), vdd(**kw)))
    check("AC8 VEX doc: a %s change prints the document-fields line, not 'no change'" % label,
          vex_part(nt_) == "- document fields changed (%s); no statement changed" % want, vex_part(nt_))
nt_ = P.notes("v0.2.3", [], P.vex_changes(vdd(), vdd(st=(vs(status_notes="n2"),), version=7)))
check("AC8 VEX doc: a statement change and a document change: the statement line and the document-fields line",
      vex_part(nt_) == "- CVE-7: not_affected (changed: status_notes)\n- document fields changed (version)", vex_part(nt_))
nt_ = P.notes("v0.2.3", [], P.vex_changes(vdd(), vdd(author="b")))
check("AC8 VEX doc: any document field is named (author)", vex_part(nt_) == "- document fields changed (author); no statement changed", vex_part(nt_))
check("AC8 VEX doc: nothing changed is still 'no change'", vex_part(P.notes("v0.2.3", [], P.vex_changes(vdd(), vdd()))) == "- no change")
check("AC8 VEX doc: a reordered statement list with the same document is still 'no change'",
      vex_part(P.notes("v0.2.3", [], P.vex_changes(vdd(st=(VS, vs(vulnerability={"name": "CVE-8"}))),
                                                    vdd(st=(vs(vulnerability={"name": "CVE-8"}), VS))))) == "- no change")
real_ = json.load(open(os.path.join(os.path.dirname(sys.argv[1]), "..", ".vex", "fosterstack-cache.openvex.json")))
bump_ = json.loads(json.dumps(real_)); bump_["version"] = real_["version"] + 1
check("AC8 VEX doc: the real OpenVEX file with only its version bumped (6 -> 7 today) prints the document-fields line",
      vex_part(P.notes("v0.2.3", [], P.vex_changes(real_, bump_))) == "- document fields changed (version); no statement changed")
check("AC8 VEX doc: the real OpenVEX file unchanged is 'no change'",
      vex_part(P.notes("v0.2.3", [], P.vex_changes(real_, json.loads(json.dumps(real_))))) == "- no change")
# AC8 (rule 0254 "names the statements that changed"; Codex #300 r1: A1-A3, B F1-F4): statements of one CVE that share a
# product scope, order-independent fail-closed pairing, each statement named by its own @id or its position, malformed
# input refused or named neutrally
import itertools
def vlines(nt):
    return vex_part(nt).splitlines()
def no_pos(vc):
    """only the numeric position in a positional label varies with input order; an identifier label is kept (Codex #300
    r2, B: the permutation checks keep stable statement identities)"""
    return [dict(e, statement=re.sub(r"^statement \d+ of the (old|new) document$", r"statement N of the \1 document", e["statement"]))
            if "statement" in e else e for e in vc]
PC = "pkg:oci/cache"
def sub(*ids):
    return [{"@id": PC, "subcomponents": [{"@id": i} for i in ids]}]
BB1, BB2 = "pkg:apk/busybox@1", "pkg:apk/busybox@2"
SA, SB = vs(products=sub(BB1), status_notes="A"), vs(products=sub(BB2), status_notes="B")
vc_ = P.vex_changes(vd(SA, SB), vd(vs(products=sub(BB1), status_notes="A2"), SB))
check("AC8 VEX dup-scope (A1): one product @id, two subcomponents, only the first changed: exactly one changed entry",
      len(vc_) == 1 and vc_[0]["change"] == "changed: status_notes", vc_)
nt_ = P.notes("v0.2.3", [], vc_)
check("AC8 VEX notes dup-scope (A1): the line names that statement's subcomponent and its position, not the other's",
      len(vlines(nt_)) == 1 and BB1 in vlines(nt_)[0] and BB2 not in nt_ and "statement 1 of the new document" in nt_, vex_part(nt_))
SAi, SBi = vs(products=[{"@id": PC}], status_notes="a", **{"@id": "urn:statement:a"}), vs(products=[{"@id": PC}], status_notes="b", **{"@id": "urn:statement:b"})
nt_ = P.notes("v0.2.3", [], P.vex_changes(vd(SAi, SBi), vd(dict(SAi, status_notes="a2"), SBi)))
check("AC8 VEX notes dup-scope (B F2): statements with their own @id: the line names the changed one's @id only",
      len(vlines(nt_)) == 1 and "urn:statement:a" in nt_ and "urn:statement:b" not in nt_ and "(changed: status_notes)" in nt_, vex_part(nt_))
NA, NB = vs(drop=("products",), status_notes="A"), vs(drop=("products",), status_notes="B")
nt_ = P.notes("v0.2.3", [], P.vex_changes(vd(dict(NA, **{"@id": "urn:s:1"}), dict(NB, **{"@id": "urn:s:2"})),
                                          vd(dict(NA, **{"@id": "urn:s:1"}), dict(NB, status_notes="B2", **{"@id": "urn:s:2"}))))
check("AC8 VEX notes: no products, two statements: the changed one is named by its @id",
      len(vlines(nt_)) == 1 and "urn:s:2" in nt_ and "urn:s:1" not in nt_, vex_part(nt_))
vc_ = P.vex_changes(vd(NA, NB), vd(NA, dict(NB, status_notes="B2")))
nt_ = P.notes("v0.2.3", [], vc_)
check("AC8 VEX notes: no products and no @id, two statements, one changed: nothing identifies it, so removed + added, "
      "each named by its position (Codex #300 r2, A3: an absent scope is no identity)",
      sorted(v["change"] for v in vc_) == ["added", "removed"] and "statement 2 of the new document" in nt_
      and "statement 2 of the old document" in nt_, vex_part(nt_))
# A2 / B F1: pairing never guesses between statements that share a scope
Sa, Sb = vs(products=[{"@id": PC}], status_notes="a"), vs(products=[{"@id": PC}], status_notes="b")
check("AC8 VEX reorder control (A2): two statements, one CVE, one product scope, order swapped: no change",
      P.vex_changes(vd(Sa, Sb), vd(Sb, Sa)) == [], P.vex_changes(vd(Sa, Sb), vd(Sb, Sa)))
check("AC8 VEX doc reorder control (A2): the same with the document: 'no change'",
      vex_part(P.notes("v0.2.3", [], P.vex_changes(vdd(st=(Sa, Sb)), vdd(st=(Sb, Sa))))) == "- no change")
vc_ = P.vex_changes(vd(Sa, Sb), vd(Sb))
check("AC8 VEX dup-scope (B F1): {a,b} -> {b} is one removed statement, nothing changed",
      [v["change"] for v in vc_] == ["removed"] and "statement 1 of the old document" in vc_[0].get("statement", ""), vc_)
vc_ = P.vex_changes(vd(Sa), vd(Sb, Sa))
check("AC8 VEX dup-scope (B F1): {a} -> {b,a} is one added statement, nothing changed",
      [v["change"] for v in vc_] == ["added"] and "statement 1 of the new document" in vc_[0].get("statement", ""), vc_)
vc_ = P.vex_changes(vd(Sa, Sb), vd(dict(Sa, status_notes="a2"), dict(Sb, status_notes="b2")))
check("AC8 VEX dup-scope: both changed and nothing tells them apart: removed + added, never a guessed 'changed'",
      sorted(v["change"] for v in vc_) == ["added", "added", "removed", "removed"], vc_)
vc_ = P.vex_changes(vd(dict(Sa, **{"@id": "urn:x"}), dict(Sb, **{"@id": "urn:y"})), vd(Sb, Sa))
check("AC8 VEX dup-scope (A2): @id on the old side only, order swapped: no invented change (removed + added)",
      sorted(v["change"] for v in vc_) == ["added", "added", "removed", "removed"], vc_)
vc_ = P.vex_changes(vd(dict(Sa, **{"@id": "urn:x"}), dict(Sb, **{"@id": "urn:y"})),
                    vd(dict(Sb, status_notes="b2", **{"@id": "urn:y"}), dict(Sa, **{"@id": "urn:x"})))
check("AC8 VEX dup-scope: an @id on both sides pairs its statement whatever the order",
      [v["change"] for v in vc_] == ["changed: status_notes"] and "urn:y" in vc_[0].get("statement", ""), vc_)
vc_ = P.vex_changes(vd(dict(VS, **{"@id": "urn:x"})), vd(VS))
# r4 (A R3-5): '@' is never bare (a mention of the user "id" otherwise), so the field name prints as its quoted literal
AT_ = lambda f: '`"%s"`' % f if f.startswith("@") else f
check("AC8 VEX: @id dropped from the only statement of a CVE: 'changed: @id'", [v["change"] for v in vc_] == ["changed: " + AT_("@id")], vc_)
vc_ = P.vex_changes(vd(vs(products=D1, **{"@id": "urn:x"}), vs(products=D2)), vd(vs(products=D2), vs(products=D1)))
check("AC8 VEX: @id on one side only, distinct scopes: paired by its unique scope, 'changed: @id'",
      [v["change"] for v in vc_] == ["changed: " + AT_("@id")] and vc_[0].get("products") == [D1[0]["@id"]], vc_)
# B F3: output order does not follow input order
F3 = (vs(products=sub("urn:a"), status="fixed"), vs(products=sub("urn:b"), status="under_investigation"))
check("AC8 VEX order (B F3): first patch, one scope, two subcomponents: the same entries in the same order either way",
      no_pos(P.vex_changes(None, vd(*F3))) == no_pos(P.vex_changes(None, vd(*reversed(F3)))) and len(P.vex_changes(None, vd(*F3))) == 2,
      (P.vex_changes(None, vd(*F3)), P.vex_changes(None, vd(*reversed(F3)))))
cases_ = [((Sa, Sb), (Sb,)), ((Sa,), (Sb, Sa)), ((Sa, Sb), (dict(Sa, status_notes="a2"), dict(Sb, status_notes="b2"))),
          ((SA, SB, VS), (vs(products=sub(BB1), status_notes="A2"), SB)), (F3, (F3[0], dict(F3[1], status="affected"))),
          ((dict(Sa, **{"@id": "urn:x"}), Sb, vs(products=D1)), (Sb, dict(Sa, status_notes="z", **{"@id": "urn:x"}), vs(products=D2)))]
for i_, (o_, n_) in enumerate(cases_):
    outs_ = {json.dumps(no_pos(P.vex_changes(vd(*po), vd(*pn)))) for po in itertools.permutations(o_) for pn in itertools.permutations(n_)}
    check("AC8 VEX order: case %d gives one result for every order of either list" % i_, len(outs_) == 1, outs_)
# A test strength: every top-level statement field, one by one; nested changes
FULL = vs(**{"@id": "urn:s", "version": 1, "timestamp": "t1", "last_updated": "t1", "supplier": "s",
             "action_statement_timestamp": "t1", "x-extension": {"k": 1}})
for field, val in (("@id", "urn:s2"), ("version", 2), ("timestamp", "t2"), ("last_updated", "t2"), ("supplier", "s2"),
                   ("action_statement_timestamp", "t2"), ("justification", "inline_mitigations_already_exist"),
                   ("impact_statement", "x"), ("action_statement", "y"), ("status_notes", "z"),
                   ("products", [{"@id": PC + "2"}]), ("vulnerability", {"name": "CVE-7", "description": "d"}),
                   ("version", True), ("version", 1.0), ("x-extension", "e"), ("x-extension", {"k": True}),
                   ("x-extension", {"k": 1.0}), ("x-extension", {"k": [1]})):
    for label, o_, n_ in (("changed", FULL, dict(FULL, **{field: val})), ("dropped", FULL, {k: v for k, v in FULL.items() if k != field}),
                          ("added", {k: v for k, v in FULL.items() if k != field}, FULL)):
        # skip only a case that is the same JSON (1 == True in Python, never in JSON: Codex #300 r2, A7/B)
        if json.dumps(o_, sort_keys=True) == json.dumps(n_, sort_keys=True) or (field == "vulnerability" and label != "changed"):
            continue
        vc_ = P.vex_changes(vd(o_), vd(n_))
        check("AC8 VEX field %s %s (%r): 'changed: %s'" % (field, label, val, field) if label == "changed" else
              "AC8 VEX field %s %s: 'changed: %s'" % (field, label, field), [v["change"] for v in vc_] == ["changed: " + AT_(field)], vc_)
vc_ = P.vex_changes(vd(FULL), vd(dict(FULL, status="affected")))
check("AC8 VEX field status changed: 'changed from <old>'", [v["change"] for v in vc_] == ["changed from not_affected"], vc_)
for label, n_ in (("vulnerability.description", dict(FULL, vulnerability={"name": "CVE-7", "description": "new"})),
                  ("vulnerability.aliases", dict(FULL, vulnerability={"name": "CVE-7", "aliases": ["GHSA-x"]})),
                  ("vulnerability.@id", dict(FULL, vulnerability={"name": "CVE-7", "@id": "https://nvd/x"})),
                  ("products subcomponent", dict(FULL, products=[{"@id": FULL["products"][0]["@id"], "subcomponents": [{"@id": BB1}]}]))):
    want_ = "products" if label.startswith("products") else "vulnerability"
    vc_ = P.vex_changes(vd(FULL), vd(n_))
    check("AC8 VEX nested %s change: 'changed: %s'" % (label, want_), [v["change"] for v in vc_] == ["changed: " + want_], vc_)
    vc_ = P.vex_changes(vd(FULL, vs(products=D1)), vd(vs(products=D1), n_))
    check("AC8 VEX nested %s change beside another statement: one changed entry (paired by its own @id)" % label,
          [v["change"] for v in vc_] == ["changed: " + want_], vc_)
    o_, n_ = {k: v for k, v in FULL.items() if k != "@id"}, {k: v for k, v in n_.items() if k != "@id"}
    vc_ = P.vex_changes(vd(o_, vs(products=D1)), vd(vs(products=D1), n_))
    check("AC8 VEX nested %s change beside another statement, no @id: %s" % (label, "one changed entry (its scope is unique)"
          if want_ == "vulnerability" else "removed + added (its scope changed: nothing pairs it)"),
          sorted(v["change"] for v in vc_) == (["changed: " + want_] if want_ == "vulnerability" else ["added", "removed"]), vc_)
# every document field, one by one, changed / dropped / added (type-sensitive: 1 -> true is a change)
DOC = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.invalid/vex", "author": "a", "role": "r",
       "timestamp": "t1", "last_updated": "t1", "version": 1, "tooling": "t", "statements": [VS]}
for field in ("@context", "@id", "author", "role", "timestamp", "last_updated", "version", "tooling"):
    for label, o_, n_ in (("changed", DOC, dict(DOC, **{field: "changed-value"})), ("dropped", DOC, {k: v for k, v in DOC.items() if k != field}),
                          ("added", {k: v for k, v in DOC.items() if k != field}, DOC)):
        got_ = vex_part(P.notes("v0.2.3", [], P.vex_changes(o_, n_)))
        check("AC8 VEX doc field %s %s: one document-fields line naming it" % (field, label),
              got_ == "- document fields changed (%s); no statement changed" % AT_(field), got_)
got_ = vex_part(P.notes("v0.2.3", [], P.vex_changes(DOC, dict(DOC, version=True))))
check("AC8 VEX doc: version 1 -> true is a change (type-sensitive)", got_ == "- document fields changed (version); no statement changed", got_)
got_ = vex_part(P.notes("v0.2.3", [], P.vex_changes(DOC, dict(DOC, **{"x-extension": {"k": 1}}))))
check("AC8 VEX doc: an extension field added is named", got_ == "- document fields changed (x-extension); no statement changed", got_)
# A3: malformed products are never iterated into the notes; the statement is unpairable and named neutrally
for bad in ("pkg:oci/a", 5, [1, 2], ["pkg:oci/a"], [{"x": 1}], [{"@id": 5}], [{"@id": PC, "subcomponents": "xy"}],
            [{"@id": PC, "subcomponents": [3]}], {"@id": PC},
            # an identifiers form the schema does not allow (Codex #300 r2, A5: the allowed forms are read, below)
            [{"identifiers": {}}], [{"identifiers": "pkg:oci/a"}], [{"identifiers": {"purl": 5}}], [{"identifiers": {"x": "y"}}],
            [{"@id": PC, "subcomponents": [{"identifiers": {}}]}], [{"@id": PC, "subcomponents": [{"identifiers": ["x", "y"]}]}]):
    o_, n_ = vs(products=bad, status_notes="n1"), vs(products=bad, status_notes="n2")
    try:
        vc_ = P.vex_changes(vd(o_, vs(products=D1)), vd(n_, vs(products=D1)))
        nt_ = P.notes("v0.2.3", [], vc_)
        vc1_ = P.vex_changes(vd(o_), vd(n_))
        same_ = P.vex_changes(vd(o_), vd(json.loads(json.dumps(o_))))
    except Exception as e:      # noqa: BLE001 -- the finding is that it raised
        vc_ = vc1_ = same_ = None; nt_ = repr(e)
    check("AC8 VEX malformed products %r: unpairable (removed + added), named 'products unreadable', never iterated" % (bad,),
          vc_ is not None and sorted(v["change"] for v in vc_) == ["added", "removed"]
          and all("[products unreadable]" in l for l in vlines(nt_)) and "pkg:oci/a, " not in nt_ and "'p'" not in nt_
          and "p, k, g" not in nt_ and "x, y" not in nt_, nt_)
    check("AC8 VEX malformed products %r, the only statement of its CVE: removed + added, not paired" % (bad,),
          vc1_ is not None and sorted(v["change"] for v in vc1_) == ["added", "removed"], vc1_)
    check("AC8 VEX malformed products %r, identical on both sides: no change" % (bad,), same_ == [], same_)
# B F4: a malformed document is refused (ValueError: no notes, no patch), never 'no change' or an unhandled error
for label, o_, n_ in (("new root a list", {"statements": []}, [1]), ("old root a list", [], vd(VS)), ("old root empty list", [], vd()),
                      ("old without statements", {}, vd()), ("new without statements", vd(), {}),
                      ("statements not a list", vd(), {"statements": {}}), ("a statement not an object", vd(VS), {"statements": [1]}),
                      ("a statement without vulnerability", vd(VS), {"statements": [{"status": "affected"}]}),
                      ("a vulnerability name not a string", vd(VS), vd(vs(vulnerability={"name": 5}))),
                      # the status the notes print is read-checked too (Codex #300 r2, A6)
                      ("a status not a string", vd(VS), vd(vs(status=5))), ("a status outside OpenVEX", vd(VS), vd(vs(status="bogus"))),
                      ("a statement without status", vd(VS), vd(vs(drop=("status",)))),
                      ("an old statement with a numeric status", vd(vs(status=1)), vd(VS)),
                      ("new document missing", vd(VS), None)):
    try:
        P.vex_changes(o_, n_); got_ = "accepted"
    except ValueError as e:
        got_ = "ValueError"
    except Exception as e:      # noqa: BLE001
        got_ = "%s: %s" % (type(e).__name__, e)
    check("AC8 VEX malformed document (%s): refused with ValueError" % label, got_ == "ValueError", got_)
# AC8 (rule 0254 "names the statements that changed"; Codex #300 r2): every line of the FINAL notes names exactly one
# statement, after redaction too; @id pairs only when unique in each whole document; an absent or empty scope is no
# identity; subcomponent order is not scope; the schema's identifiers forms are read
def distinct(nt):
    ls = vlines(nt)
    return len(ls) == len(set(ls))
for a_, b_ in (("urn:statement:claude-a", "urn:statement:claude-b"), ("urn:claude", "urn:gemini")):
    S1, S2 = (vs(products=[{"@id": PC}], status="fixed", status_notes=n, **{"@id": i}) for i, n in ((a_, "a"), (b_, "b")))
    nt_ = P.notes("v0.2.3", [], P.vex_changes(vd(S1, S2), vd(dict(S1, status_notes="a2"), dict(S2, status_notes="b2"))))
    check("AC8 VEX notes redaction (A1/B): @ids %s / %s that redact alike: two distinct lines, each named by its position" % (a_, b_),
          len(vlines(nt_)) == 2 and distinct(nt_) and "statement 1 of the new document" in nt_ and "statement 2 of the new document" in nt_
          and not re.search(r"(?i)claude|gemini", nt_), vex_part(nt_))
nt_ = P.notes("v0.2.3", [], P.vex_changes(vd(), vd(vs(vulnerability={"name": "CVE-claude-1"}, status="fixed"),
                                                     vs(vulnerability={"name": "CVE-claude-2"}, status="fixed"))))
check("AC8 VEX notes redaction: two CVE names that redact alike: two distinct lines, each named by its position",
      len(vlines(nt_)) == 2 and distinct(nt_) and "statement 1 of the new document" in nt_ and "claude" not in nt_.lower(), vex_part(nt_))
nt_ = P.notes("v0.2.3", [], P.vex_changes(vd(SAi, SBi), vd(dict(SAi, status_notes="a2"), dict(SBi, status_notes="b2"))))
check("AC8 VEX notes redaction control: @ids that survive redaction still name their statements",
      # r3 (B3): ":statement:" has an emoji shortcode's shape, so the @id prints as a quoted literal
      distinct(nt_) and 'statement `"urn:statement:a"`' in nt_ and 'statement `"urn:statement:b"`' in nt_ and "of the new document" not in nt_, vex_part(nt_))
X_ = {"@id": "urn:x"}
vc_ = P.vex_changes(vd(vs(products=[{"@id": "pkg:a"}], status_notes="u", **X_), vs(products=[{"@id": "pkg:b"}], status_notes="old", **X_)),
                    vd(vs(products=[{"@id": "pkg:a"}], status_notes="u", **X_), vs(products=[{"@id": "pkg:c"}], status_notes="new", **X_)))
check("AC8 VEX dup-@id (A2): an @id held twice in the whole document never pairs, even when unique among the rest: removed + added",
      sorted(v["change"] for v in vc_) == ["added", "removed"], vc_)
vc_ = P.vex_changes(vd(vs(products=[{"@id": "pkg:b"}], status_notes="old", **X_), vs(vulnerability={"name": "CVE-8"}, **X_)),
                    vd(vs(products=[{"@id": "pkg:c"}], status_notes="new", **X_), vs(products=[{"@id": "pkg:d"}])))
check("AC8 VEX dup-@id (A2): an @id held twice across CVEs in the old document does not pair: removed + added",
      sorted(v["change"] for v in vc_ if v["cve"] == "CVE-7") == ["added", "added", "removed"], vc_)
for label, empty in (("absent", None), ("empty", [])):
    U_ = vs(drop=("products",)) if empty is None else vs(products=empty)
    vc_ = P.vex_changes(vd(vs(products=D1), dict(U_, status_notes="u1")), vd(vs(products=D1), dict(U_, status_notes="u2")))
    check("AC8 VEX %s scope (A3): beside an unchanged scoped statement, an unscoped one with new notes is removed + added" % label,
          sorted(v["change"] for v in vc_) == ["added", "removed"], vc_)
    vc_ = P.vex_changes(vd(dict(U_, status_notes="u1")), vd(dict(U_, status_notes="u2")))
    check("AC8 VEX %s scope: the only statement of its CVE still pairs (the CVE identifies it)" % label,
          [v["change"] for v in vc_] == ["changed: status_notes"], vc_)
vc_ = P.vex_changes(vd(vs(products=sub("urn:a", "urn:b")), vs(products=D1)), vd(vs(products=sub("urn:b", "urn:a")), vs(products=D1)))
check("AC8 VEX subcomponent order (A4): [a,b] -> [b,a] beside another statement, no @id: one 'changed: products'",
      [v["change"] for v in vc_] == ["changed: products"], vc_)
vc_ = P.vex_changes(vd(vs(products=sub("urn:a", "urn:b"), status="fixed", status_notes="a"),
                       vs(products=sub("urn:b", "urn:a"), status="under_investigation", status_notes="b")),
                    vd(vs(products=sub("urn:b", "urn:a"), status="fixed", status_notes="a2"),
                       vs(products=sub("urn:a", "urn:b"), status="under_investigation", status_notes="b2")))
check("AC8 VEX subcomponent order (A4/B): two statements of one unordered scope, both changed: two removed + two added, never guessed",
      sorted(v["change"] for v in vc_) == ["added", "added", "removed", "removed"], vc_)
IDP = [{"identifiers": {"purl": PC}}]
vc_ = P.vex_changes(vd(vs(products=IDP, **{"@id": "urn:statement:a"})), vd(vs(products=IDP, status_notes="n2", **{"@id": "urn:statement:a"})))
check("AC8 VEX identifiers (A5/B): a product named by identifiers.purl, the only statement: 'changed: status_notes'",
      [v["change"] for v in vc_] == ["changed: status_notes"] and not any(v.get("products_unreadable") for v in vc_), vc_)
for label, prods in (("identifiers.purl", IDP), ("identifiers.cpe23", [{"identifiers": {"cpe23": "cpe:2.3:a:fs:cache:1:*:*:*:*:*:*:*"}}]),
                     ("identifiers.cpe22", [{"identifiers": {"cpe22": "cpe:/a:fs:cache:1"}}]),
                     ("a subcomponent's identifiers", [{"@id": PC, "subcomponents": [{"identifiers": {"purl": BB1}}]}])):
    vc_ = P.vex_changes(vd(vs(products=prods), vs(products=D1)), vd(vs(products=prods, status_notes="n2"), vs(products=D1)))
    nt_ = P.notes("v0.2.3", [], vc_)
    want_ = list(prods[0].get("identifiers", {}).values()) or [BB1]
    check("AC8 VEX identifiers (A5): %s beside another statement, no @id: one changed line naming it, never 'unreadable'" % label,
          [v["change"] for v in vc_] == ["changed: status_notes"] and "unreadable" not in nt_ and want_[0] in nt_, vex_part(nt_))
# B: order independence keeps identifier labels; equal products and status tie on content, not input order
TA, TB = (vs(products=[{"@id": PC}], status="fixed", status_notes="t", **{"@id": i}) for i in ("urn:s:a", "urn:s:b"))
check("AC8 VEX order (B): first patch, equal products and status, @ids urn:s:a / urn:s:b: one order either way",
      P.vex_changes(None, vd(TA, TB)) == P.vex_changes(None, vd(TB, TA)) and len(P.vex_changes(None, vd(TA, TB))) == 2,
      (P.vex_changes(None, vd(TA, TB)), P.vex_changes(None, vd(TB, TA))))
R1, R2 = (vs(products=[{"@id": PC}], status="fixed", status_notes=n, **{"@id": i}) for i, n in (("urn:claude-a", "a"), ("urn:claude-b", "b")))
for i_, (o_, n_) in enumerate((((TA, TB), (dict(TB, status_notes="t2"), TA)),
                               ((R1, R2), (dict(R1, status_notes="a2"), dict(R2, status_notes="b2"))),
                               ((vs(products=sub("urn:a", "urn:b")), vs(products=D1)), (vs(products=D1), vs(products=sub("urn:b", "urn:a")))),
                               ((vs(products=IDP, status_notes="i"), Sa), (Sa, vs(products=IDP, status_notes="i2"))))):
    outs_ = {json.dumps(no_pos(P.vex_changes(vd(*po), vd(*pn)))) for po in itertools.permutations(o_) for pn in itertools.permutations(n_)}
    nts_ = [P.notes("v0.2.3", [], P.vex_changes(vd(*po), vd(*pn))) for po in itertools.permutations(o_) for pn in itertools.permutations(n_)]
    check("AC8 VEX order (B): round-2 case %d gives one result for every order, identifier labels kept, final lines distinct" % i_,
          len(outs_) == 1 and all(distinct(x) for x in nts_), outs_)
# AC8 (rule 0254 "names the statements that changed"; Codex #300 r3: A1-A3, B1-B3 and the test gaps): every published
# statement is exactly one line; a value the document supplies prints bare only when nothing renders it differently, else
# as a quoted JSON literal in a code span; an @id label never shares a namespace with a position label; an empty
# vulnerability name (the schema allows it) is read and named by position; redaction is line-local
import collections, itertools, random, unicodedata
CTRL_CATS = ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn")
def no_ctrl(t):
    return all(ch == "\n" or unicodedata.category(ch) not in CTRL_CATS for ch in t)
CSPAN = re.compile(r"`[^`]*`")
def inert(line):
    """outside code spans nothing CommonMark, GFM or GitHub renders differently: no entity, HTML (the old '<redacted>'
    marker included: it parses as a tag and shows nothing, Codex #300 r4 B), escape, emphasis, strike, image, math, pipe,
    heading, emoji shortcode, autolink (www., '//', any 'scheme:' form but pkg:/urn:/cpe:, an e-mail address), mention
    ('@' anywhere), issue reference ('#', GH-, GHSA-) or commit-SHA-like run (Codex #300 r4: A R3-5, B low)"""
    rest = CSPAN.sub("C", line)
    return not (re.search(r"[&<>\\*~!$|`#@]", rest) or re.search(r":[A-Za-z0-9_+-]+:", rest) or "//" in rest
                or re.search(r"(?i)www\.", rest) or re.search(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])", rest)
                or re.search(r"(?i)(?<![A-Za-z0-9])gh(sa)?-", rest)
                or any(m.group(1).lower() not in ("pkg", "urn", "cpe")
                       for m in re.finditer(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*):(?=\S)", rest))
                or re.search(r"(?<![A-Za-z0-9])[0-9a-fA-F]{7,}(?![A-Za-z0-9])", rest))
def lit_val(s):
    """a printed value: a code span holds one JSON string; anything else that starts with a backtick reads as nothing"""
    if not s.startswith("`"):
        return s
    try:
        v = json.loads(s[1:-1])
    except ValueError:
        return object()
    return v if isinstance(v, str) else object()
LINE_GRAMMAR = re.compile(r"- (?P<name>\x00+|[^\s\x00\[\]]+?)(?: \[(?P<prods>[^\[\]]*)\])?: "
                          r"(?P<status>not_affected|affected|fixed|under_investigation) \((?P<change>(?:(?! — ).)*)\)"
                          r"(?: — statement (?P<label>.+))?")
def parse_line(line):
    """r6 (B F3): a statement line read by its whole grammar, nothing left over — '- NAME[ [PRODUCTS]]: STATUS (CHANGE)
    [ — statement LABEL]', code spans masked; {group: original text} or None. The name is one bare token or one code span"""
    shape = CSPAN.sub(lambda m_: "\x00" * len(m_.group(0)), line)
    m = LINE_GRAMMAR.fullmatch(shape)
    if not m:
        return None
    out = {k: (line[m.start(k):m.end(k)] if m.group(k) is not None else None) for k in ("name", "prods", "status", "change", "label")}
    if "\x00" in m.group("name") and not CSPAN.fullmatch(out["name"]):
        return None
    return out
def resolve(line, o_doc, n_doc):
    """(side, position) of the one source statement a FINAL notes line names, or a string saying why it names none. r6
    (B F3): the line must parse whole; its CVE name is the exact printed form of the named statement's own name (a
    redacted name only where the source name is one the redactor changes, tok_is)"""
    p = parse_line(line)
    if p is None:
        return "unparsed: %r" % line
    side = "old" if p["change"] == "removed" else "new"
    doc = o_doc if side == "old" else n_doc
    sts = (doc or {}).get("statements", [])
    name, label = p["name"], p["label"]
    if label:
        pm = re.fullmatch(r"(\d+) of the (old|new) document", label)
        if pm:
            if pm.group(2) != side:
                return "position names the other document: %r" % line
            hits = [int(pm.group(1)) - 1]
        else:
            hits = [i for i, s in enumerate(sts) if isinstance(s.get("@id"), str) and tok_is(label, s["@id"])]
    elif "<redacted>" not in name and "(redacted)" not in name:
        hits = [i for i, s in enumerate(sts) if tok_is(name, s["vulnerability"]["name"], before_colon=True)]
    else:
        return "no label and a redacted name: %r" % line
    if len(hits) != 1 or not 0 <= hits[0] < len(sts):
        return "names %d statements: %r" % (len(hits), line)
    st = sts[hits[0]]
    if not tok_is(name, st["vulnerability"]["name"], before_colon=True) or st["status"] != p["status"]:
        return "names a statement of another CVE or status: %r" % line
    return (side, hits[0] + 1)
REDACTED = ("<redacted>", "(redacted)")
def canon_(x):
    return json.dumps(x, sort_keys=True)
def spans_split(text, sep):
    """text split at sep outside code spans, each piece's code spans put back"""
    spans_ = CSPAN.findall(text)
    out = []
    for piece in CSPAN.sub("\x00", text).split(sep):
        while "\x00" in piece:
            piece = piece.replace("\x00", spans_.pop(0), 1)
        out.append(piece)
    return out
def field_diff(a, b):
    return sorted(k for k in set(a) | set(b) if k not in a or k not in b or canon_(a[k]) != canon_(b[k]))
def span_of(v):
    """the documented quoted form of a value: its JSON string (ASCII, backtick escaped; r6, B F4: a hyphen followed by four
    more written \\u002d, so no run of five hyphens — a signature-block delimiter — is ever printed) in a code span"""
    return "`%s`" % re.sub(r"-(?=----)", r"\\u002d", json.dumps(v, ensure_ascii=True).replace("`", "\\u0060"))
def bare_ok(v, before_colon=False):
    """the oracle's own bare-form rule (r6, A (c)): a letter, then letters, digits and - . _ / only, after at most one
    pkg: / urn: / cpe: prefix, and inert (with the ':' the notes print after a CVE name)"""
    return (re.fullmatch(r"(?:(?:pkg|urn|cpe):)?[A-Za-z][A-Za-z0-9._/-]*", v) is not None
            and inert(v + (":" if before_colon else "")))
def tok_is(tok, v, before_colon=False):
    """Codex #300 r5 (A R4-3, B F2); r6 (A (c), B F3): a printed token names the source value v only as the ONE printed
    form the documents call for — bare when the value passes the oracle's own bare rule, else exactly its quoted form —
    after redaction (lossy only where the SOURCE value is one the redactor changes): a GitHub-active value printed bare,
    another JSON spelling, or a marker where the source needs none is refused"""
    return tok == P._clean_md(v if bare_ok(v, before_colon) else span_of(v))
def bij(xs, ys, eq):
    """xs and ys pair one to one under eq (a multiset match, order aside)"""
    if len(xs) != len(ys):
        return False
    if not xs:
        return True
    return any(eq(xs[0], y) and bij(xs[1:], ys[:j] + ys[j + 1:], eq) for j, y in enumerate(ys))
def label_is(text, vals):
    """a printed component label (its values joined by ' ') names exactly the values vals (an @id, or the identifiers);
    a redaction that spans two values of one label (the redactor reads 'google gpt' as one name) is allowed only when the
    source values joined are text the redactor changes, and the label is exactly a printed form of them, redacted"""
    if bij(spans_split(text, " "), list(vals), tok_is):
        return True
    return "(redacted)" in text and any(
        P._clean(" ".join(perm)) != " ".join(perm)
        and text == P._clean_md(" ".join(v if bare_ok(v) else span_of(v) for v in perm))
        for perm in itertools.permutations(vals))
def names_fields(text, fields):
    """the printed field list names exactly these fields (decoded from bare text or JSON code spans, order aside); a
    redacted field is matched against a source field the redactor changes, every visible one exactly (r5)"""
    return bij(spans_split(text, ", "), list(fields), tok_is)
def claim_fits(change, o, n):
    """the change a 'changed' line claims is exactly the difference between old statement o and new statement n"""
    fields = field_diff(o, n)
    if not fields or o["vulnerability"]["name"] != n["vulnerability"]["name"]:
        return False
    if "status" in fields:
        m_ = re.fullmatch(r"changed from (\w+)(?:; also (.*))?", change, re.S)
        others = [k for k in fields if k != "status"]
        return bool(m_) and m_.group(1) == o["status"] and (names_fields(m_.group(2), others) if others else m_.group(2) is None)
    return change.startswith("changed: ") and names_fields(change[len("changed: "):], fields)
def comp_values(c):
    """the identifying strings of one product or subcomponent: its @id, else its identifiers' values"""
    if isinstance(c.get("@id"), str):
        return [c["@id"]]
    return list(c.get("identifiers", {}).values())
def comp_ok(c):
    """a product or subcomponent the notes can name (OpenVEX: a string @id, or identifiers holding only purl / cpe23 /
    cpe22 strings)"""
    if not isinstance(c, dict) or ("@id" in c and not isinstance(c["@id"], str)):
        return False
    if "identifiers" in c:
        idf = c["identifiers"]
        if not isinstance(idf, dict) or not idf or not all(k in ("purl", "cpe23", "cpe22") and isinstance(x, str) for k, x in idf.items()):
            return False
    return isinstance(c.get("@id"), str) or "identifiers" in c
def readable(st):
    ps = st.get("products", [])
    return isinstance(ps, list) and all(comp_ok(p) and isinstance(p.get("subcomponents", []), list)
                                        and all(comp_ok(s) for s in p.get("subcomponents", [])) for p in ps)
def top_split(text, sep):
    """text split at sep outside code spans and outside parentheses"""
    spans_ = CSPAN.findall(text)
    shape, out, depth, cur, i = CSPAN.sub("\x00", text), [], 0, "", 0
    while i < len(shape):
        if depth == 0 and shape.startswith(sep, i):
            out.append(cur); cur = ""; i += len(sep); continue
        depth += {"(": 1, ")": -1}.get(shape[i], 0)
        cur += shape[i]; i += 1
    out.append(cur)
    res = []
    for piece in out:
        while "\x00" in piece:
            piece = piece.replace("\x00", spans_.pop(0), 1)
        res.append(piece)
    return res
def group_is(text, p):
    """one printed product group 'LABEL' or 'LABEL (subcomponents: S, ...)' names exactly product p with exactly its
    subcomponents (r5, A R4-3 / B F2: products and subcomponents compare as groups, never flattened)"""
    pieces = spans_split(text, " (subcomponents: ")
    subs = p.get("subcomponents", [])
    if len(pieces) == 1:
        return not subs and label_is(pieces[0], comp_values(p))
    if len(pieces) != 2 or not pieces[1].endswith(")") or not subs:
        return False
    return label_is(pieces[0], comp_values(p)) and bij(top_split(pieces[1][:-1], ", "), list(subs),
                                                       lambda t, s: label_is(t, comp_values(s)))
def products_fit(line, st, several):
    """the product list a line prints is exactly the one the documents call for (r5, A R4-3): '[products unreadable]'
    when the statement's products cannot be read; else, when its CVE has several statements in either document and it
    has products, every product with its own subcomponents; else no list at all"""
    p_ = parse_line(line)                   # r6 (B F3): the list the whole-line grammar reads, never a partial match
    if p_ is None:
        return False
    text = p_["prods"]
    if not readable(st):
        return text == "products unreadable"
    if not several or not st.get("products"):
        return text is None
    return text is not None and bij(top_split(text, ", "), list(st["products"]), group_is)
def several_of(o_doc, n_doc):
    """the CVE names that have more than one statement in either document"""
    out = set()
    for d in (o_doc or {}, n_doc):
        cnt = collections.Counter(s["vulnerability"]["name"] for s in d.get("statements", []))
        out |= {k for k, n in cnt.items() if n > 1}
    return out
def structure(nt, fixes=(), behavior=()):
    """r5 (A R4-3 low, B F1): the whole notes, not only up to the first blank line: exactly the heading, the Fixes section
    (the fix lines, or the one 'none' line), the VEX section and the behavior section (the entries, or the one
    no-behavior-change paragraph); anything else anywhere — a forged line after a blank line included — is refused.
    r6 (A (c), B F3): fixes and behavior are the SOURCE inputs handed to notes() (lists; a count is refused): each fix
    line and behavior entry must be exactly its own input in the documented printed form (one line, cleaned as free
    text), in order — a swapped, duplicated or replaced line is refused"""
    fixes, behavior = list(fixes), list(behavior)
    want_f = [P._clean_free(P._oneline("- %s in %s: %s → %s (severity %s; variants: %s)" % (
        f["cve"], f["package"], f["old"], f["new"], f["severity"], ", ".join(f.get("variants") or []))))
        for f in fixes] or ["- none (dependency or VEX maintenance only)"]
    want_b = ["### Behavior changes"] + [P._clean_free("- %s" % P._oneline(b)) for b in behavior] if behavior \
        else ["No behavior change: this release contains fixes only."]
    if not nt.endswith("\n"):
        return "no final newline"
    secs = nt[:-1].split("\n\n")
    if len(secs) != 4:
        return "%d sections, want 4" % len(secs)
    if not re.fullmatch(r"## \S+ — patch release", secs[0]):
        return "heading: %r" % secs[0]
    if secs[1].split("\n") != ["### Fixes"] + want_f:
        return "fixes section: %r" % secs[1]
    vl = secs[2].split("\n")
    if vl[0] != "### VEX" or len(vl) < 2 or not all(l.startswith("- ") for l in vl[1:]):
        return "VEX section: %r" % secs[2]
    if secs[3].split("\n") != want_b:
        return "behavior section: %r" % secs[3]
    return None
def diff_problems(nt, o_doc, n_doc):
    """Codex #300 r4 (A low, B medium): an oracle built from the two documents alone, not from vex_changes. Identical
    statements are interchangeable, so per identical class the surplus on each side is what must be reported: the lines
    naming new statements (changed or added) name exactly the new surplus; the removed lines name part of the old
    surplus; every changed line pairs with a distinct remaining old statement of its CVE whose difference is exactly the
    change it claims, and that pairing uses up the old surplus (so the line count follows from the documents); every line
    naming products names exactly that statement's; the document-fields line names exactly the changed document fields;
    '- no change' only when nothing changed"""
    olds, news = (o_doc or {}).get("statements", []), n_doc.get("statements", [])
    co, cn = collections.Counter(map(canon_, olds)), collections.Counter(map(canon_, news))
    surplus_new, surplus_old = cn - co, co - cn
    probs = []
    lines = vlines(nt)
    doc_ls = [l for l in lines if l.startswith("- document fields changed (")]
    st_ls = [l for l in lines if l not in doc_ls and l != "- no change"]
    named, changed = [], []
    sev = several_of(o_doc, n_doc)
    for l in st_ls:
        r_ = resolve(l, o_doc, n_doc)
        if not isinstance(r_, tuple):
            probs.append(r_); continue
        side, pos = r_
        st = (olds if side == "old" else news)[pos - 1]
        if not products_fit(l, st, st["vulnerability"]["name"] in sev):
            probs.append("products disagree: %r" % l)
        change = parse_line(l)["change"]    # r6: the change the whole-line grammar reads
        named.append((side, pos, change, l))
        if side == "new" and change != "added":
            changed.append((st, change, l))
    if collections.Counter(canon_(news[p - 1]) for s_, p, _, _ in named if s_ == "new") != surplus_new:
        probs.append("the new-side lines do not name exactly the new statements no identical old one accounts for")
    removed_ = collections.Counter(canon_(olds[p - 1]) for s_, p, _, _ in named if s_ == "old")
    if removed_ - surplus_old:
        probs.append("a removed line names an old statement an identical new one accounts for")
    left = list((surplus_old - removed_).elements())
    def pair(i, avail):
        if i == len(changed):
            return not avail
        st, change, _ = changed[i]
        return any(claim_fits(change, json.loads(a), st) and pair(i + 1, avail[:j] + avail[j + 1:]) for j, a in enumerate(avail))
    if not pair(0, left):
        probs.append("the changed lines do not pair one-to-one with the remaining old statements by their claimed change: %r"
                     % [c_[2] for c_ in changed])
    want_doc = [] if o_doc is None else field_diff({k: v for k, v in o_doc.items() if k != "statements"},
                                                    {k: v for k, v in n_doc.items() if k != "statements"})
    if want_doc:
        m_ = re.fullmatch(r"- document fields changed \((.*)\)(; no statement changed)?", doc_ls[0]) if len(doc_ls) == 1 else None
        if not m_ or not names_fields(m_.group(1), want_doc) or bool(m_.group(2)) != (not st_ls):
            probs.append("document-fields line wrong: %r, want %r" % (doc_ls, want_doc))
    elif doc_ls:
        probs.append("a document-fields line with no document change: %r" % doc_ls)
    if ("- no change" in lines) != (not st_ls and not want_doc) or ("- no change" in lines and len(lines) != 1):
        probs.append("'- no change' wrong")
    return probs
def resolves(nt, o_doc, n_doc, fixes=(), behavior=()):
    """the notes have exactly their four sections and nothing else (r6: fixes and behavior are the fix records and
    behavior entries the caller handed notes(), compared line by line); every statement line of the final VEX section names exactly one
    statement, no two lines name the same one, and the section agrees with diff_problems' independent reading of the
    documents"""
    got = [resolve(l, o_doc, n_doc) for l in vlines(nt) if not l.startswith("- document fields changed (") and l != "- no change"]
    probs = diff_problems(nt, o_doc, n_doc)
    shape_ = structure(nt, fixes, behavior)
    if shape_:
        probs.append("notes structure: " + shape_)
    return all(isinstance(x, tuple) for x in got) and len(set(got)) == len(got) and not probs, got + probs
# A1: a line break (any control character) in a name, @id, product, field name or document field never makes two lines
F1, F2 = "CVE-A\n- forged: fixed (added)", "CVE-B\n- forged: fixed (added)"
nt_ = P.notes("v0.2.3", [], P.vex_changes(None, vd(vs(vulnerability={"name": F1}), vs(vulnerability={"name": F2}))))
check("AC8 VEX one line (r3, A1): two names carrying '\\n- forged: fixed (added)' print one quoted line each, no forged line",
      vlines(nt_) == ['- `"CVE-A\\n- forged: fixed (added)"`: not_affected (added)',
                      '- `"CVE-B\\n- forged: fixed (added)"`: not_affected (added)'], vex_part(nt_))
CTRLS = ["\n", "\r", "\r\n", "\x00", "\x0b", "\x0c", "\x1b", "\x1c", "\x1f", "\x7f", "\x80", "\x85", "\x9b", "\x9f",
         " ", " ", "​", "‮", "﻿", "\ud800", "\U000e0001"]
for ch in CTRLS:
    o_ = dict(vd(vs(**{"@id": "urn:a" + ch})), version=1)
    n_ = dict(vd(vs(status_notes="c", **{"@id": "urn:a" + ch, "x" + ch: 1}),
                 vs(vulnerability={"name": "CVE-1" + ch}, products=[{"@id": PC + ch, "subcomponents": [{"@id": "s" + ch}]}]),
                 vs(vulnerability={"name": "CVE-1" + ch}, products=[{"identifiers": {"purl": "pkg:x" + ch}}])),
              **{"version": 1, "d" + ch: 1})
    fx_ = [{"cve": "CVE-9" + ch, "package": "p" + ch, "old": "v1" + ch, "new": "v2" + ch, "severity": "high" + ch, "variants": ["v" + ch]}]
    try:
        nt_ = P.notes("v0.2.3", fx_, P.vex_changes(o_, n_), behavior=["A change" + ch + " here (advisor 0130)."])
        enc_ = nt_.encode("utf-8") is not None
    except Exception as e:      # noqa: BLE001 -- the finding is that it raised
        nt_, enc_ = repr(e), False
    secs_ = nt_.split("\n\n")
    check("AC8 VEX one line (r3, A1): %r in every printed value: one line per fix, statement, document line and behavior entry, "
          "no control character, UTF-8 writable" % ch,
          enc_ and no_ctrl(nt_) and len(vlines(nt_)) == 4 and all(l.startswith("- ") for l in vlines(nt_))
          and len(secs_) == 4 and secs_[1].count("\n") == 1 and secs_[3].count("\n") == 2
          and resolves(nt_, o_, n_, fixes=fx_, behavior=["A change" + ch + " here (advisor 0130)."])[0], nt_)
# A2 / B2: an @id shaped like a position label never reads as one
U7 = vs(products=[{"@id": PC}], status="fixed", status_notes="u")
C7 = vs(products=[{"@id": PC}], status="fixed", status_notes="c", **{"@id": "1 of the new document"})
o_, n_ = vd(U7, C7), vd(U7, dict(C7, status_notes="c2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX label namespaces (r3, A2): an @id '1 of the new document' on statement 2 prints as a quoted @id, never as position 1",
      vlines(nt_) == ['- CVE-7 [pkg:oci/cache]: fixed (changed: status_notes) — statement `"1 of the new document"`']
      and resolves(nt_, o_, n_) == (True, [("new", 2)]), (vex_part(nt_), resolves(nt_, o_, n_)))
P1 = vs(products=[{"@id": PC}], status="fixed", status_notes="a", impact_statement="a", **{"@id": "2 of the new document"})
P2 = vs(products=[{"@id": PC}], status="fixed", status_notes="b", impact_statement="a")
o_, n_ = vd(P1, P2), vd(dict(P1, status_notes="a2"), dict(P2, impact_statement="b2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX label namespaces (r3, B2): @id '2 of the new document' on statement 1 and a changed statement 2: each line maps "
      "back to the statement that changed in that way",
      vlines(nt_) == ['- CVE-7 [pkg:oci/cache]: fixed (changed: impact_statement) — statement 2 of the new document',
                      '- CVE-7 [pkg:oci/cache]: fixed (changed: status_notes) — statement `"2 of the new document"`']
      and resolves(nt_, o_, n_) == (True, [("new", 2), ("new", 1)]), (vex_part(nt_), resolves(nt_, o_, n_)))
o_, n_ = vd(P1, P2), vd(dict(P1, status_notes="a2"), dict(P2, status_notes="b2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX label namespaces (r3, B low): the same field changed in both: two distinct lines naming two statements",
      distinct(nt_) and resolves(nt_, o_, n_)[0] and sorted(resolves(nt_, o_, n_)[1]) == [("new", 1), ("new", 2)], (vex_part(nt_), resolves(nt_, o_, n_)))
# A3 / B qualification: an empty vulnerability name is schema-valid (no minLength): read, quoted, named by position
for label, o_, n_, want in (
        ("first patch", None, vd(vs(vulnerability={"name": ""})), ['- `""`: not_affected (added) — statement 1 of the new document']),
        ("changed", vd(vs(vulnerability={"name": ""})), vd(vs(vulnerability={"name": ""}, status_notes="n2")),
         ['- `""`: not_affected (changed: status_notes) — statement 1 of the new document']),
        ("removed beside another", vd(VS, vs(vulnerability={"name": ""})), vd(VS), ['- `""`: not_affected (removed) — statement 2 of the old document'])):
    try:
        nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_)); got_ = vlines(nt_)
    except Exception as e:      # noqa: BLE001
        got_ = repr(e)
    check("AC8 VEX empty name (r3, A3): %s: read, printed as \"\", named by position" % label, got_ == want, got_)
SCHEMA_DOC = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.invalid/vex", "author": "a",
              "timestamp": "2026-10-11T00:00:00Z", "version": 1,
              "statements": [{"vulnerability": {"name": ""}, "status": "fixed", "products": [{"@id": PC}]}]}
try:
    got_ = P.vex_changes(None, SCHEMA_DOC)
except Exception as e:      # noqa: BLE001
    got_ = repr(e)
check("AC8 VEX empty name (r3, B qualification): a complete schema-valid document with name \"\" is accepted",
      isinstance(got_, list) and [v["change"] for v in got_] == ["added"], got_)
# B1: redaction never consumes a line break: B's reproducer over the FINAL notes() output
Q1, Q2 = (vs(products=[{"@id": PC}], status="fixed", **{"@id": i}) for i in ("urn:chat", "urn:other"))
o_ = vd(Q1, Q2)
n_ = vd(dict(Q1, status_notes="updated"), Q2, vs(vulnerability={"name": "gpt"}, products=[{"@id": PC}], status="fixed", **{"@id": "urn:new"}))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX line-local redaction (r3, B1): 'urn:chat' then a CVE named 'gpt': two lines, the first keeps its @id",
      vlines(nt_) == ["- CVE-7 [pkg:oci/cache]: fixed (changed: status_notes) — statement urn:chat",
                      "- (redacted): fixed (added) — statement 3 of the new document"]
      and resolves(nt_, o_, n_) == (True, [("new", 1), ("new", 3)]), (vex_part(nt_), resolves(nt_, o_, n_)))
raw_ = "## v0.2.2 — patch release\n\n### VEX\n- CVE-1: fixed (changed: x) — statement urn:chat\n- gpt: fixed (added)\n"
cl_, _ = P.changelog(raw_, None, "")
check("AC8 VEX line-local redaction (r3, B1): the changelog cleans line by line, never across a line break "
      "(r5: the redacted line is written escaped, A R4-4)",
      "— statement urn:chat\n- \\(redacted\\)\\: fixed \\(added\\)\n" in cl_, cl_)
tr_ = ("object 0123\ntype commit\ntag v0.2.2\ntagger fosterstack release <release@users.noreply.github.com> 1 +0000\n\n" + raw_
       + "-----BEGIN SIGNED MESSAGE-----\nMIIabc\n-----END SIGNED MESSAGE-----\n")
check("AC8 VEX line-local redaction (r3, B1): a patch tag's notes are cleaned line by line too",
      "— statement urn:chat\n- \\(redacted\\)\\: fixed \\(added\\)\n" in (P.tag_notes(tr_) or ""), P.tag_notes(tr_))
# B3: Markdown and GitHub rendering never make two values read alike, hide a value or add a line
E1, E2 = (vs(products=[{"@id": PC}], status="fixed", status_notes="old", **{"@id": i}) for i in ("urn:s:a", "urn:s:&#97;"))
o_, n_ = vd(E1, E2), vd(dict(E1, status_notes="new"), dict(E2, status_notes="new"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX rendering (r3, B3): @ids urn:s:a and urn:s:&#97; print as quoted literals that render apart",
      vlines(nt_) == ['- CVE-7 [pkg:oci/cache]: fixed (changed: status_notes) — statement `"urn:s:&#97;"`',
                      '- CVE-7 [pkg:oci/cache]: fixed (changed: status_notes) — statement `"urn:s:a"`']
      and all(inert(l) for l in vlines(nt_)) and resolves(nt_, o_, n_)[0], vex_part(nt_))
nt_ = P.notes("v0.2.3", [], P.vex_changes(vd(VS), vd(vs(**{"\n- no change\n": 1}), vs(vulnerability={"name": "<!-- CVE-7 -->"}))))
check("AC8 VEX rendering (r3, B3): an HTML-comment name and a field name carrying '\\n- no change\\n' print quoted, one line each",
      vlines(nt_) == ['- `"<!-- CVE-7 -->"`: not_affected (added)', '- CVE-7: not_affected (changed: `"\\n- no change\\n"`)'], vex_part(nt_))
MD = ["a*b*", "a_b_", "_a_", "a__b", "~~a~~", "[a](b)", "![a](b)", "a\\*", "`a`", "``", "a|b", "$a$", "#1", "&amp;", "&#97;",
      "<b>x</b>", "<!--", "a:+1:", "a:thumbsup:", "x:a", "https://x.example", "www.x.example", "a@b.c",
      "0123456789abcdef0123456789abcdef01234567", "deadbeef", "a b", " a", "a ", "\\u0041", "é", "1. a", "- a", "> a", "= a"]
bad_ = []
for v_ in MD:
    o_ = vd(vs(products=[{"@id": PC}], status_notes="o", **{"@id": "urn:a"}), vs(products=[{"@id": PC}], **{"@id": "urn:b"}))
    for n_ in (vd(vs(products=[{"@id": PC}], status_notes="n", **{"@id": v_, v_: 1}), vs(products=[{"@id": PC}], **{"@id": "urn:b"})),
               vd(vs(vulnerability={"name": v_}, products=[{"@id": v_, "subcomponents": [{"@id": v_}]}]), vs(vulnerability={"name": v_})),
               vd(vs(products=[{"identifiers": {"purl": v_, "cpe23": v_}}]), vs(products=[{"@id": PC}]))):
        nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
        if not all(inert(l) for l in vlines(nt_)) or not resolves(nt_, o_, n_)[0] or not distinct(nt_):
            bad_.append((v_, vex_part(nt_)))
check("AC8 VEX rendering (r3, B3): %d Markdown/GitHub-active values as @id, name, product, subcomponent, identifier and field "
      "name: every line inert outside its code spans and naming one statement" % len(MD), bad_ == [], bad_)
nt_ = P.notes("v0.2.3", [], P.vex_changes(None, vd(vs(vulnerability={"name": "CVE:x"}), vs(vulnerability={"name": "CVE:thumbsup"}))))
check("AC8 VEX rendering (r3, B3): a name ending ':word' is quoted (the ': ' after it would close an emoji shortcode)",
      all(inert(l) for l in vlines(nt_)) and '- `"CVE:x"`: not_affected (added)' in vlines(nt_), vex_part(nt_))
# B test gaps: the new side's whole-document @id count; the relabel loop and its fail-closed end, over the FINAL lines
o_ = vd(vs(products=[{"@id": "pkg:a"}], **X_), vs(products=D1))
n_ = vd(vs(products=[{"@id": "pkg:b"}], **X_), vs(products=D1), vs(vulnerability={"name": "CVE-8"}, **X_))
vc_ = P.vex_changes(o_, n_)
check("AC8 VEX dup-@id (r3, B gap): an @id held twice across CVEs in the NEW document does not pair: removed + added",
      sorted((v["cve"], v["change"]) for v in vc_) == [("CVE-7", "added"), ("CVE-7", "removed"), ("CVE-8", "added")], vc_)
real_clean_ = P._clean
try:
    # a redactor stronger than today's (any future name list): it makes three whole lines read alike, never a part alone
    P._clean = lambda s: re.sub(r"^- CVE-\d+", "- CVE-N", real_clean_(s))
    try:
        got_ = vlines(P.notes("v0.2.3", [], P.vex_changes(None, vd(*(vs(vulnerability={"name": "CVE-%d" % i}) for i in (1, 2, 3))))))
    except Exception as e:      # noqa: BLE001
        got_ = repr(e)
    check("AC8 VEX relabel (r3, B gap): three FINAL lines that read alike are each relabelled by position",
          got_ == ["- CVE-N: not_affected (added) — statement %d of the new document" % i for i in (1, 2, 3)], got_)
    # names and labels intact, only the change text redacted alike: the relabel loop alone tells the two lines apart
    P._clean = lambda s: re.sub(r"\((added|removed)\)", "(-)", real_clean_(s))
    try:
        got_ = vlines(P.notes("v0.2.3", [], P.vex_changes(vd(vs(products=5)), vd(vs(products=5, status_notes="n2")))))
    except Exception as e:      # noqa: BLE001
        got_ = repr(e)
    check("AC8 VEX relabel (r3, B gap): removed + added lines that read alike only after redaction: each relabelled by position",
          got_ == ["- CVE-7 [products unreadable]: not_affected (-) — statement 1 of the new document",
                   "- CVE-7 [products unreadable]: not_affected (-) — statement 1 of the old document"], got_)
    P._clean = lambda s: re.sub(r"\d+ of the (old|new) document", "N of the document", re.sub(r"^- CVE-\d+", "- CVE-N", real_clean_(s)))
    try:
        got_ = vlines(P.notes("v0.2.3", [], P.vex_changes(None, vd(*(vs(vulnerability={"name": "CVE-%d" % i}) for i in (1, 2))))))
    except ValueError:
        got_ = "ValueError"
    except Exception as e:      # noqa: BLE001
        got_ = repr(e)
    check("AC8 VEX relabel (r3, fail closed): when even positions read alike after redaction: refused (ValueError), nothing published",
          got_ == "ValueError", got_)
    # the lines stay distinct but one loses its only label: refused too (the final check, not only notes()' duplicate check)
    P._clean = lambda s: re.sub(r"\d+ of the (old|new) document", "N of the document", re.sub(r"^- CVE-1\b", "- CVE-X", real_clean_(s)))
    try:
        got_ = vlines(P.notes("v0.2.3", [], P.vex_changes(None, vd(*(vs(vulnerability={"name": "CVE-%d" % i}) for i in (1, 2))))))
    except ValueError:
        got_ = "ValueError"
    except Exception as e:      # noqa: BLE001
        got_ = repr(e)
    check("AC8 VEX relabel (r3, fail closed): a distinct line whose name and position label redaction both changed: refused (ValueError)",
          got_ == "ValueError", got_)
finally:
    P._clean = real_clean_
for fake_ in ([{"cve": "CVE-1", "status": "fixed", "change": "added"}] * 2,
              [{"cve": "CVE-1\n- x", "status": "fixed", "change": "added"}]):
    try:
        got_ = vlines(P.notes("v0.2.3", [], fake_))
        got_ = "accepted" if len(got_) == len(set(got_)) == len(fake_) else got_
    except ValueError:
        got_ = "ValueError"
    check("AC8 VEX notes guard (r3): entries handed to notes() print one distinct line each or are refused: %r" % (fake_,),
          got_ in ("ValueError", "accepted"), got_)
# the property: random names, @ids, products and field names with control characters, Markdown, vendor names and
# position-shaped text; every published statement is exactly one line naming exactly one statement
PIECES = ["CVE-7", "CVE-8", "urn:s:a", "a", "1 of the new document", "2 of the old document", "\n", "\r\n", "\x00", "\x1b[31m",
          "\x7f", "\x85", "\x9b", " ", " ", "​", "‮", "\ud800", "`", "&#97;", "<!--", "*", "_", "~~", "[x]",
          "\\", "#", "|", ":+1:", " ", "- forged: fixed (added)", "chat", "gpt", "claude", "google", "é", "—", "statement "]
rng_ = random.Random(300)
def rname(lo=0):
    return "".join(rng_.choice(PIECES) for _ in range(rng_.randint(lo, 3)))
def rstmt(names):
    s = {"vulnerability": {"name": rng_.choice(names)}, "status": rng_.choice(P.VEX_STATUS), "status_notes": rng_.choice("ab")}
    k = rng_.randrange(4)
    if k == 0:
        s["products"] = [{"@id": rname(1)}]
    elif k == 1:
        s["products"] = [{"@id": rname(1), "subcomponents": [{"@id": rname(1)}]}, {"identifiers": {"purl": rname(1)}}]
    elif k == 2:
        s["products"] = []
    if rng_.random() < 0.6:
        s["@id"] = rname(1)
    if rng_.random() < 0.3:
        s[rname()] = 1
    return s
prop_bad, prop_n, mutants_, mut_missed = [], 0, 0, []
for it_ in range(400):
    names_ = [rname() for _ in range(rng_.randint(1, 3))]
    o_ = {"statements": [rstmt(names_) for _ in range(rng_.randint(0, 4))]}
    n_ = {"statements": []}
    for s in list(o_["statements"]):
        r_ = rng_.random()
        if r_ < 0.5:
            n_["statements"].append(json.loads(json.dumps(s)))
        elif r_ < 0.8:
            t_ = json.loads(json.dumps(s)); t_[rng_.choice(["status_notes", "impact_statement", rname()])] = rname(); n_["statements"].append(t_)
            if rng_.random() < 0.5:     # r4 (B medium): an unchanged statement of the same CVE and status beside it
                twin_ = dict(json.loads(json.dumps(s)), products=[{"@id": rname(1)}], status_notes=rng_.choice("ab"))
                twin_.pop("@id", None)
                o_["statements"].append(twin_); n_["statements"].append(json.loads(json.dumps(twin_)))
    n_["statements"] += [rstmt(names_) for _ in range(rng_.randint(0, 2))]
    rng_.shuffle(n_["statements"])
    if rng_.random() < 0.2:
        n_[rname(1)] = 1
    try:
        vc_ = P.vex_changes(o_, n_)
        nt_ = P.notes("v0.2.3", [], vc_)
        nt_.encode("utf-8")
    except Exception as e:      # noqa: BLE001
        prop_bad.append((it_, "raised %r" % e)); continue
    prop_n += len(vc_)
    ls_ = vlines(nt_)
    ok_, why_ = resolves(nt_, o_, n_)
    # r4 (B medium): the line count comes from the documents (diff_problems), not from vc_
    if not (no_ctrl(nt_) and len(set(ls_)) == len(ls_) and all(l.startswith("- ") and inert(l) for l in ls_) and ok_):
        prop_bad.append((it_, ls_, why_))
    # r4 (B medium, the reviewer's mutation): a position label redirected to any other statement of that side with the
    # same CVE name and status is refused by the oracle
    for li_, l in enumerate(ls_):
        pm_ = re.search(r" — statement (\d+) of the (old|new) document$", l)
        if not pm_:
            continue
        sts_ = (o_ if pm_.group(2) == "old" else n_)["statements"]
        me_ = sts_[int(pm_.group(1)) - 1]
        for j_, other_ in enumerate(sts_, 1):
            if (j_ == int(pm_.group(1)) or other_["vulnerability"]["name"] != me_["vulnerability"]["name"]
                    or other_["status"] != me_["status"] or canon_(other_) == canon_(me_)):
                continue                # an identical statement is interchangeable: naming either is right
            mut_ = l[:pm_.start(1)] + str(j_) + l[pm_.end(1):]
            mutants_ += 1
            if resolves(nt_.replace(l + "\n", mut_ + "\n", 1), o_, n_)[0]:
                mut_missed.append((it_, l, mut_))
check("AC8 VEX property (r3): 400 random document pairs (%d entries): every published statement is exactly one line, inert, "
      "distinct and naming exactly one statement" % prop_n, prop_bad == [] and prop_n > 400, prop_bad[:3])
check("AC8 VEX property (r4, B medium): %d mutants that move a position label to another statement of the same CVE and "
      "status: every one refused by the document-built oracle" % mutants_, mutants_ > 50 and mut_missed == [], mut_missed[:3])
# r4 (A low, B medium): the oracle itself refuses a line naming an unchanged statement, a wrong statement or a wrong field
o_ = vd(vs(products=[{"@id": "pkg:a"}], status="fixed", vulnerability={"name": "CVE-7"}),
        vs(products=[{"@id": "pkg:b"}], status="fixed", vulnerability={"name": "CVE-7"}))
n_ = vd(o_["statements"][0], dict(o_["statements"][1], status_notes="n2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
fab_ = "- CVE-7 [pkg:b]: fixed (changed: status_notes) — statement 1 of the new document"
check("AC8 VEX oracle (r4, B medium): the true notes resolve; B's fabricated line naming the unchanged statement 1 is refused",
      resolves(nt_, o_, n_) == (True, [("new", 2)]) and not resolves(nt_.replace(vlines(nt_)[0], fab_), o_, n_)[0],
      (vex_part(nt_), resolves(nt_.replace(vlines(nt_)[0], fab_), o_, n_)))
o_ = vd(vs(vulnerability={"name": "CVE-1"}, status="fixed"), vs(vulnerability={"name": "CVE-2"}, status="fixed"))
n_ = vd(dict(o_["statements"][0], status_notes="n2"), o_["statements"][1])
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
for fab_ in ("- CVE-2: fixed (changed: status_notes)", "- CVE-1: fixed (changed: impact_statement)",
             "- CVE-1: fixed (changed from affected)", "- CVE-1: fixed (added)", "- CVE-1 [pkg:zzz]: fixed (changed: status_notes)"):
    check("AC8 VEX oracle (r4, A low): true notes resolve; fabricated %r is refused" % fab_,
          resolves(nt_, o_, n_)[0] and vlines(nt_) == ["- CVE-1: fixed (changed: status_notes)"]
          and not resolves(nt_.replace(vlines(nt_)[0], fab_), o_, n_)[0], resolves(nt_.replace(vlines(nt_)[0], fab_), o_, n_))
check("AC8 VEX oracle (r4): a dropped line and an extra '- no change' are refused",
      not resolves(nt_.replace(vlines(nt_)[0] + "\n", ""), o_, n_)[0]
      and not resolves(nt_.replace(vlines(nt_)[0], "- no change"), o_, n_)[0])
# r5 (A R4-3 low, B F1 medium): the oracle reads the WHOLE notes; a line inserted after a blank line is refused
SA_, SB_ = vs(products=[{"@id": "pkg:a"}], status="fixed"), vs(products=[{"@id": "pkg:b"}], status="fixed")
o_, n_ = vd(SA_, SB_), vd(SA_, dict(SB_, status_notes="n2"))
for beh_ in ([], ["A change (advisor 0130)."]):
    nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_), behavior=beh_)
    l_ = vlines(nt_)[0]
    ok_ = resolves(nt_, o_, n_, behavior=beh_)
    check("AC8 VEX oracle (r5, B F1): the true notes (behavior entries: %d) resolve" % len(beh_), ok_ == (True, [("new", 2)]), ok_)
    for what_, ins_ in (("a forged bullet", "- CVE-FORGED: fixed (added)"), ("a duplicate statement bullet", l_),
                        ("an extra '- no change'", "- no change")):
        bad_nt_ = nt_.replace(l_ + "\n", l_ + "\n\n" + ins_ + "\n", 1)
        check("AC8 VEX oracle (r5, B F1): %s after a blank line below the VEX bullet is refused (behavior entries: %d)" % (what_, len(beh_)),
              bad_nt_ != nt_ and not resolves(bad_nt_, o_, n_, behavior=beh_)[0], resolves(bad_nt_, o_, n_, behavior=beh_))
    for where_, bad_nt_ in (("at the end", nt_ + "\n- CVE-FORGED: fixed (added)\n"), ("at the end, no blank", nt_ + "- CVE-FORGED: fixed (added)\n"),
                            ("in the Fixes section", nt_.replace("### Fixes\n", "### Fixes\n- CVE-FORGED: fixed (added)\n", 1)),
                            ("as a section of its own", nt_.replace("\n\n### VEX", "\n\n- CVE-FORGED: fixed (added)\n\n### VEX", 1))):
        check("AC8 VEX oracle (r5, B F1): a forged line %s is refused (behavior entries: %d)" % (where_, len(beh_)),
              bad_nt_ != nt_ and not resolves(bad_nt_, o_, n_, behavior=beh_)[0], resolves(bad_nt_, o_, n_, behavior=beh_))
# r5 (A R4-3 medium): a line with no product list where the documents call for one, and one with a list where they do not
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX oracle (r5, A R4-3): the true line names its products",
      vlines(nt_) == ["- CVE-7 [pkg:b]: fixed (changed: status_notes) — statement 2 of the new document"], vex_part(nt_))
for fab_ in ("- CVE-7: fixed (changed: status_notes) — statement 2 of the new document",
             "- CVE-7 [pkg:b, pkg:a]: fixed (changed: status_notes) — statement 2 of the new document",
             "- CVE-7 [products unreadable]: fixed (changed: status_notes) — statement 2 of the new document"):
    check("AC8 VEX oracle (r5, A R4-3): fabricated %r is refused" % fab_, not resolves(nt_.replace(vlines(nt_)[0], fab_), o_, n_)[0],
          resolves(nt_.replace(vlines(nt_)[0], fab_), o_, n_))
o1_, n1_ = vd(VS), vd(vs(status_notes="n2"))
nt1_ = P.notes("v0.2.3", [], P.vex_changes(o1_, n1_))
check("AC8 VEX oracle (r5, A R4-3): a CVE with one statement prints no list, and a fabricated list is refused",
      vlines(nt1_) == ["- CVE-7: not_affected (changed: status_notes)"] and resolves(nt1_, o1_, n1_)[0]
      and not resolves(nt1_.replace("- CVE-7: ", "- CVE-7 [pkg:oci/cache?tag=debug]: "), o1_, n1_)[0], vex_part(nt1_))
# r5 (A R4-3, B F2): products and their subcomponents compare as groups
GA_ = vs(products=[{"@id": "pkg:a", "subcomponents": [{"@id": "pkg:sa"}]}, {"@id": "pkg:b", "subcomponents": [{"@id": "pkg:sb"}]}], status="fixed")
GB_ = vs(products=[{"@id": "pkg:a", "subcomponents": [{"@id": "pkg:b"}]}], status="fixed", impact_statement="other")
o_, n_ = vd(GA_, GB_), vd(dict(GA_, status_notes="n2"), dict(GB_, status_notes="n2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
ls_ = vlines(nt_)
check("AC8 VEX oracle (r5): the true product groups print and resolve",
      "[pkg:a (subcomponents: pkg:sa), pkg:b (subcomponents: pkg:sb)]" in nt_ and "[pkg:a (subcomponents: pkg:b)]" in nt_
      and resolves(nt_, o_, n_)[0], (vex_part(nt_), resolves(nt_, o_, n_)))
for true_, fab_ in (("[pkg:a (subcomponents: pkg:sa), pkg:b (subcomponents: pkg:sb)]", "[pkg:a (subcomponents: pkg:sb), pkg:b (subcomponents: pkg:sa)]"),
                    ("[pkg:a (subcomponents: pkg:sa), pkg:b (subcomponents: pkg:sb)]", "[pkg:a, pkg:sa, pkg:b, pkg:sb]"),
                    ("[pkg:a (subcomponents: pkg:sa), pkg:b (subcomponents: pkg:sb)]", "[pkg:a (subcomponents: pkg:sa, pkg:b, pkg:sb)]"),
                    ("[pkg:a (subcomponents: pkg:b)]", "[pkg:b (subcomponents: pkg:a)]"),
                    ("[pkg:a (subcomponents: pkg:b)]", "[pkg:a, pkg:b]"),
                    ("[pkg:a (subcomponents: pkg:b)]", "[pkg:a]")):
    check("AC8 VEX oracle (r5, A R4-3 / B F2): %s fabricated as %s is refused" % (true_, fab_),
          true_ in nt_ and not resolves(nt_.replace(true_, fab_, 1), o_, n_)[0], resolves(nt_.replace(true_, fab_, 1), o_, n_))
# r5 (A R4-3, B F2): a redacted field or product is allowed only where the SOURCE value is one the redactor changes;
# every visible one is compared exactly
o_, n_ = vd(VS), vd(vs(status_notes="n2", gpt=1))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX oracle (r5, A R4-3): a field 'gpt' and status_notes print '(redacted), status_notes' and resolve",
      vlines(nt_) == ["- CVE-7: not_affected (changed: (redacted), status_notes)"] and resolves(nt_, o_, n_)[0], vex_part(nt_))
check("AC8 VEX oracle (r5, A R4-3): the visible field beside a redacted one is still compared (impact_statement for status_notes refused)",
      not resolves(nt_.replace("(redacted), status_notes", "(redacted), impact_statement"), o_, n_)[0])
o_, n_ = vd(VS), vd(vs(status_notes="n2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX oracle (r5, B F2): 'changed: (redacted)' for a real, unredacted status_notes change is refused",
      resolves(nt_, o_, n_)[0] and not resolves(nt_.replace("changed: status_notes", "changed: (redacted)"), o_, n_)[0])
RA_, RB_ = vs(products=[{"@id": "pkg:gpt"}], status="fixed"), vs(products=[{"@id": "pkg:b"}], status="fixed")
o_, n_ = vd(RA_, RB_), vd(dict(RA_, status_notes="n2"), dict(RB_, status_notes="n2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX oracle (r5): a redacted product resolves; the same marker on a product the redactor leaves alone is refused",
      "[pkg:(redacted)]" in nt_ and "[pkg:b]" in nt_ and resolves(nt_, o_, n_)[0]
      and not resolves(nt_.replace("[pkg:b]", "[pkg:(redacted)]"), o_, n_)[0]
      and not resolves(nt_.replace("[pkg:(redacted)]", "[(redacted)]"), o_, n_)[0]
      and not resolves(nt_.replace("[pkg:(redacted)]", "[pkg:b]"), o_, n_)[0], (vex_part(nt_), resolves(nt_, o_, n_)))
# r4 (A R3-4, B low): redaction never consumes ANY line boundary str.splitlines() knows; each is written back as LF
TERMS = ["\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
for t_ in TERMS:
    raw_ = "## v0.2.2 — patch release\n\n### VEX\n- CVE-1: fixed (changed: x) — statement urn:chat" + t_ + "- gpt: fixed (added)\n"
    want_ = "— statement urn:chat\n- \\(redacted\\)\\: fixed \\(added\\)\n"      # r5: the redacted line escaped (A R4-4)
    got_ = P._clean_lines("urn:chat" + t_ + "- gpt: fixed (added)")
    check("AC8 line-local redaction (r4, A R3-4): %r between two lines: both kept, the boundary written as LF" % t_,
          got_ == "urn:chat\n- \\(redacted\\)\\: fixed \\(added\\)", got_)
    cl_, _ = P.changelog(raw_, None, "")
    check("AC8 line-local redaction (r4, A R3-4): the changelog splits at %r too" % t_, want_ in cl_ and t_ not in cl_.replace("\n", ""), cl_)
    tr_ = ("object 0123\ntype commit\ntag v0.2.2\ntagger fosterstack release <release@users.noreply.github.com> 1 +0000\n\n" + raw_
           + "-----BEGIN SIGNED MESSAGE-----\nMIIabc\n-----END SIGNED MESSAGE-----\n")
    got_ = P.tag_notes(tr_) or ""
    check("AC8 line-local redaction (r4, A R3-4): a patch tag's notes split at %r too" % t_, want_ in got_ and t_ not in got_.replace("\n", ""), got_)
check("AC8 line-local redaction (r4): a trailing boundary and an empty text keep their shape",
      P._clean_lines("a\n") == "a\n" and P._clean_lines("") == "" and P._clean_lines("a\n\nb") == "a\n\nb", P._clean_lines("a\n"))
# r4 (A R3-5, B low): a value prints bare only in a form GitHub cannot autolink, mention, reference or emoji-expand
for v_ in ("@octocat", "GH-26", "gh-26", "GHSA-abcd-efgh-ijkl", "mailto:foo@bar.baz", "a@b.c", "xmpp:a@b.c", "foo:bar",
           "x:a", "octo/repo#12", "octo/repo@abc1234", "abc1234", "a-deadbeef", "0123456789abcdef" * 4, "x:smile:", "http://x",
           "pkg://x", "user@host", "@id", "1abc", "", "a b", "a?b=c"):
    got_ = P._lit(v_)
    check("AC8 VEX bare form (r4, A R3-5): %r prints as a quoted JSON literal in a code span" % v_,
          got_.startswith('`"') and got_.endswith('"`') and json.loads(got_[1:-1]) == v_, got_)
for v_ in ("CVE-2024-1234", "pkg:oci/cache", "urn:chat", "cpe:x", "a_b", "x.y/z", "CVE-7"):
    check("AC8 VEX bare form (r4): %r stays bare" % v_, P._lit(v_) == v_, P._lit(v_))
check("AC8 VEX bare form (r4): a CVE name before ':' never closes an emoji shortcode", P._lit("urn:x", before_colon=True).startswith("`"))
for v_ in ("@octocat", "GH-26", "mailto:foo@bar.baz", "a@b.c"):
    nt_ = P.notes("v0.2.3", [], P.vex_changes(None, vd(vs(vulnerability={"name": v_}))))
    check("AC8 VEX rendering (r4, A R3-5): a vulnerability named %r prints quoted, every line inert" % v_,
          vlines(nt_) == ['- `%s`: not_affected (added)' % json.dumps(v_)] and all(inert(l) for l in vlines(nt_)), vex_part(nt_))
o_ = vd(vs(products=[{"@id": PC}], status_notes="o", **{"@id": "urn:a"}))
n_ = vd(vs(products=[{"@id": PC}], status_notes="o", **{"@id": "urn:b"}))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX rendering (r4): the field name '@id' prints quoted (a mention of the user 'id' otherwise)",
      vlines(nt_) == ['- CVE-7: not_affected (changed: `"@id"`)'] and resolves(nt_, o_, n_)[0], vex_part(nt_))
# r4 (B low): the redaction marker in the notes, changelog and tag notes is visible text, not an HTML tag
nt_ = P.notes("v0.2.3", [], P.vex_changes(vdd(), vdd(st=(VS, vs(vulnerability={"name": "gpt"}, status="fixed")), gpt=1)))
check("AC8 VEX redaction marker (r4, B low): a name and a document field 'gpt' print '(redacted)', never '<redacted>'",
      vlines(nt_) == ["- (redacted): fixed (added) — statement 2 of the new document", "- document fields changed ((redacted))"]
      and "<redacted>" not in nt_ and all(inert(l) for l in vlines(nt_)), vex_part(nt_))
old_ = "## v0.2.2 — patch release\n\n### VEX\n- <redacted>: fixed (added)\n"
check("AC8 VEX redaction marker (r4, B low; r5 escaped, A R4-4): an older tag's '<redacted>' is shown as '(redacted)' in the changelog",
      "- \\(redacted\\)\\: fixed \\(added\\)\n" in P.changelog(old_, None, "")[0], P.changelog(old_, None, "")[0])
ent_ = ["A gpt-assisted fix (advisor 0130)."]
pub_old_ = "- %s\n" % P._clean(ent_[0])
check("0135 + r4: an entry published under either marker is not published again",
      "<redacted>" in pub_old_ and P.unpublished(ent_, pub_old_) == []
      and P.unpublished(ent_, pub_old_.replace("<redacted>", "(redacted)")) == []
      and P.unpublished(ent_, "") == ent_, (pub_old_, P.unpublished(ent_, pub_old_.replace("<redacted>", "(redacted)"))))
# r4 (B, ordering): entries sort by the document's own values, not by how they print (a quoted value sorts as itself)
vc_ = P.vex_changes(None, vd(vs(products=[{"@id": "pkg:z z"}]), vs(products=[{"@id": "pkg:a"}]), vs(products=[{"@id": "pkg:b@1"}])))
nt_ = P.notes("v0.2.3", [], vc_)
check("AC8 VEX order (r4, B): products pkg:a, pkg:b@1, pkg:z z sort by value whatever their printed form; entries keep the raw products",
      [v.get("products") for v in vc_] == [["pkg:a"], ["pkg:b@1"], ["pkg:z z"]]
      and [l.split(" [", 1)[1].split("]:", 1)[0] for l in vlines(nt_)] == ["pkg:a", '`"pkg:b@1"`', '`"pkg:z z"`'], (vc_, vex_part(nt_)))
vc_ = P.vex_changes(None, vd(vs(products=[{"@id": "pkg:z z"}, {"@id": "pkg:a"}, {"@id": "pkg:b@1"}]), vs()))
check("AC8 VEX order (r4, B): one statement's products print in the order of their values, not of their printed forms",
      vc_[0].get("products") == ["pkg:a", "pkg:b@1", "pkg:z z"]
      and vlines(P.notes("v0.2.3", [], vc_))[0].startswith('- CVE-7 [pkg:a, `"pkg:b@1"`, `"pkg:z z"`]: '), (vc_, vlines(P.notes("v0.2.3", [], vc_))))
# r5 (B F4): entries sort by the raw change (kind, field names), products with equal labels by their source content;
# how a value prints never reorders anything
T1_ = vs(products=[{"@id": "pkg:a"}], status="fixed", **{"@id": "urn:x"})
T2_ = vs(products=[{"@id": "pkg:a", "identifiers": {"purl": "pkg:a"}}], status="fixed")
ls_ = vlines(P.notes("v0.2.3", [], P.vex_changes(vd(T1_, T2_), vd(dict(T1_, **{"@id": "urn:y"}), dict(T2_, A=1)))))
check("AC8 VEX order (r5, B F4): equal product labels: 'changed: @id' sorts before 'changed: A' as the raw names do ('@' < 'A')",
      len(ls_) == 2 and '(changed: `"@id"`)' in ls_[0] and "(changed: A)" in ls_[1], ls_)
vc_ = P.vex_changes(None, vd(vs(products=[{"identifiers": {"purl": "a b"}}, {"identifiers": {"purl": "a", "cpe23": "b"}}]), vs()))
check("AC8 VEX order (r5, B F4): two products with the same raw label 'a b' order by their source content, not their printed form",
      vc_[0].get("products") == ["a b", "a b"] and '[a b, `"a b"`]: ' in vlines(P.notes("v0.2.3", [], vc_))[0], vlines(P.notes("v0.2.3", [], vc_)))
# r5 (A R4-4, B F3): the redaction marker stays visible beside any Markdown in free text (behavior entries, fix lines, a tag's
# own text): a line holding a marker is written with every ASCII punctuation character backslash-escaped, so no link,
# image, HTML, comment or other construct can take the marker as its own; a line without a marker is unchanged
PUNCT_ = r"!-/:-@\[-`{-~"
def esc_line(l):
    body = l[2:] if l.startswith("- ") else l
    return re.fullmatch(r"(?:\\[%s]|[^%s])*" % (PUNCT_, PUNCT_), body) is not None and "\\(redacted\\)" in body
def mktag(tag, body):
    return ("object 0123\ntype commit\ntag %s\ntagger fosterstack release <release@users.noreply.github.com> 1 +0000\n\n" % tag + body
            + "-----BEGIN SIGNED MESSAGE-----\nMIIabc\n-----END SIGNED MESSAGE-----\n")
nt_ = P.notes("v0.2.3", [], [], behavior=["[click]gpt (advisor 0130)."])
check("AC8 redaction marker (r5, A R4-4 / B F3): '[click]gpt' in a behavior entry prints '\\[click\\]\\(redacted\\)', never a link",
      "- \\[click\\]\\(redacted\\) \\(advisor 0130\\)\\.\n" in nt_ and "](redacted)" not in nt_, nt_)
BEH_ = ["[click]gpt (advisor 0130).", "![x](gpt) (advisor 0130).", "<gpt> (advisor 0130).", "[a](https://gpt.example) (advisor 0130).",
        "<!-- gpt --> (advisor 0130).", "[x][gpt] and `gpt` (advisor 0130).", "gpt in google.golang.org/protobuf (advisor 0130)."]
FX_ = [{"cve": "CVE-1", "package": "[click]gpt", "old": "v1", "new": "v2", "severity": "high", "variants": ["default"]}]
nt_ = P.notes("v0.2.3", FX_, [], behavior=BEH_)
secs_ = nt_.split("\n\n")
check("AC8 redaction marker (r5): every fix line and behavior entry holding a marker is fully escaped and shows '(redacted)'",
      len(secs_) == 4 and all(esc_line(l) for l in secs_[1].split("\n")[1:] + secs_[3].rstrip("\n").split("\n")[1:])
      and "<redacted>" not in nt_, nt_)
check("AC8 redaction marker (r5): an unredacted line keeps its Markdown as written",
      "- Go 1.27 [see](https://example.invalid) (advisor 0130).\n" in P.notes("v0.2.3", [], [], behavior=["Go 1.27 [see](https://example.invalid) (advisor 0130)."]))
old_tag_ = ("## v0.2.2 — patch release\n\n### Fixes\n- CVE-1 in [click]<redacted>: v1 → v2 (severity high; variants: default)\n\n### VEX\n"
            "- no change\n\n### Behavior changes\n- [click]<redacted> (advisor 0130).\n")
got_ = P.tag_notes(mktag("v0.2.2", old_tag_)) or ""
check("AC8 redaction marker (r5): an older tag's '[click]<redacted>' is shown escaped in its notes and the changelog, never as a link",
      "- \\[click\\]\\(redacted\\) \\(advisor 0130\\)\\.\n" in got_ and "\\[click\\]\\(redacted\\)\\:" in got_ and "](redacted)" not in got_
      and "- \\[click\\]\\(redacted\\) \\(advisor 0130\\)\\.\n" in P.changelog(old_tag_, None, "")[0], got_)
check("AC8 redaction marker (r5): the escaped form is stable: a tag of the notes reads back as the notes byte for byte",
      P.tag_notes(mktag("v0.2.3", nt_)) == nt_, P.tag_notes(mktag("v0.2.3", nt_)))
cl1_, nn1_ = P.changelog(nt_, None, "- [click]gpt (advisor 0130).\n- Another change (advisor 0131).\n")
check("0130 + r5: a published entry holding a marker leaves next-release-notes; an unpublished one stays",
      nn1_ == "- Another change (advisor 0131).\n", nn1_)
check("0135 + r5: an entry holding a marker is not published again (escaped form, older '<redacted>' form, round-4 form)",
      P.unpublished(["[click]gpt (advisor 0130)."], nt_) == []
      and P.unpublished(["[click]gpt (advisor 0130)."], "- [click]<redacted> (advisor 0130).\n") == []
      and P.unpublished(["[click]gpt (advisor 0130)."], "- [click](redacted) (advisor 0130).\n") == []
      and P.unpublished(["[click]gpt (advisor 0130)."], "") == ["[click]gpt (advisor 0130)."])
# r5 (B low): a generated tag's heading ends in LF and nothing else: CR, CRLF, VT, FF, FS, GS, RS, NEL, LS or PS after it is
# refused (as in round 3)
for t_ in TERMS:
    body_ = "## v0.2.2 — patch release" + t_ + "\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n- no change\n"
    check("AC8 tag-notes heading (r5, B low): %r after the heading is refused" % t_, P.tag_notes(mktag("v0.2.2", body_)) is None,
          P.tag_notes(mktag("v0.2.2", body_)))
check("AC8 tag-notes heading (r5): the generated LF heading is still read",
      P.tag_notes(mktag("v0.2.2", "## v0.2.2 — patch release\n\n### VEX\n- no change\n")) == "## v0.2.2 — patch release\n\n### VEX\n- no change\n")
# r5 (A R4-1, B low): the changelog's existing history is copied unchanged, never rewritten; a history this code would not
# have written (a line boundary other than LF, a vendor name, an unescaped marker) is refused, nothing written (fail closed)
HIST_ = "# Changelog\n\n## v0.2.1 — patch release\n\n### VEX\n- (redacted): fixed (added) — statement 2 of the new document\n"
cl_, _ = P.changelog(nt_, HIST_, "")
check("AC8 changelog history (r5): a clean history is copied byte for byte below the new notes",
      cl_.endswith("\n" + HIST_[len("# Changelog\n\n"):]) and cl_.startswith("# Changelog\n\n## v0.2.3"), cl_)
check("AC8 changelog history (r5): the changelog this code writes is clean history for the next one",
      P.changelog(nt_.replace("v0.2.3", "v0.2.4"), cl_, "")[0].endswith(cl_[len("# Changelog\n\n"):]))
for what_, h_ in (("a CR line end", HIST_.replace("\n### VEX", "\r\n### VEX")), ("A's CR then a vendor line", HIST_ + "x\r- gpt: fixed (added)\n"),
                  ("a vendor name", HIST_ + "- gpt helper\n"), ("an older '<redacted>' marker", HIST_ + "- <redacted>: fixed (added)\n"),
                  ("U+2028", HIST_ + "a b\n"), ("NEL", HIST_ + "a\x85b\n")):
    try:
        P.changelog(nt_, h_, ""); got_ = "accepted"
    except ValueError:
        got_ = "ValueError"
    check("AC8 changelog history (r5): a history with %s is refused, not rewritten" % what_, got_ == "ValueError", got_)
cd5_ = tempfile.mkdtemp()
open(os.path.join(cd5_, "n.md"), "w").write(nt_)
open(os.path.join(cd5_, "CL.md"), "w", newline="").write(HIST_ + "- gpt helper\n")
open(os.path.join(cd5_, "nn.md"), "w").write("- [click]gpt (advisor 0130).\n")
rc_ = P.main(["changelog", "--notes", os.path.join(cd5_, "n.md"), "--changelog", os.path.join(cd5_, "CL.md"), "--next-notes", os.path.join(cd5_, "nn.md")])
check("AC8 CLI changelog (r5): an unclean history exits 2 and writes nothing",
      rc_ == 2 and open(os.path.join(cd5_, "CL.md"), newline="").read() == HIST_ + "- gpt helper\n"
      and open(os.path.join(cd5_, "nn.md")).read() == "- [click]gpt (advisor 0130).\n", rc_)
import shutil; shutil.rmtree(cd5_)
# r6 (Codex #300 r6: A R5-1 / B F1, B F2, A R5-5, A (d) / B F6, B F4's newly admitted channels, A (c) / B F3)
# R5-1 / F1: the marker in EVERY historical form — origin/main's '<redacted>', round 4's '(redacted)', the escaped
# '\(redacted\)' and '\<redacted\>', any case — is never taken into link, image, HTML, comment, autolink or code syntax
# in free text: a line holding it is either one with nothing that can form such syntax around it, or fully escaped
MARK_ = re.compile(r"(?i)redacted")
def shown(l):
    """the line shows every marker as text (the test's own reading): its body (after '- ' or a heading's '#... ') is
    fully escaped, or outside code spans holds no character that starts a link, image, HTML, autolink, entity, escape,
    code, footnote, table or math construct ('[' only as the one ' [...]: ' product list; no '//' or 'www.')"""
    m_ = re.match(r"- |#{1,6} ", l)
    body = l[m_.end():] if m_ else l
    if re.fullmatch(r"(?:\\[%s]|[^%s])*" % (PUNCT_, PUNCT_), body):
        return True
    rest = CSPAN.sub("C", body)
    return ("``" not in body and not re.search(r"[!\"#$%&'*+<=>?@\\^`{|}~]|//|(?i:www)\.|(?<![A-Za-z0-9])_(?![A-Za-z0-9])", rest)
            and re.fullmatch(r"[^\[\]]*(?: \[[^\[\]]*\]: [^\[\]]*)?", rest) is not None)
LEG_ = ["[click](redacted) (advisor 0130).", "[click](\\(redacted\\)) (advisor 0130).", "[click](\\<redacted\\>) (advisor 0130).",
        "[click](<redacted>) (advisor 0130).", "[click](REDACTED) (advisor 0130).", "![x](redacted)", "[x](/u \"(redacted)\")",
        "<a title=\"(redacted)\">x</a>", "<!-- (redacted) -->", "[x][(redacted)]", "<https://x.example/(redacted)>",
        "https://x.example/(redacted)", "www.x.example/(redacted)", "`(redacted)` and [y](redacted)", "[x]: (redacted)",
        "&#40;redacted&#41; [a](b)", "(redacted)[^1]", "| (redacted) |", "$(redacted)$", "*(redacted)*", "_(redacted)_",
        "\\[click\\](redacted)", "[click]\\(redacted\\)", "(redacted)\\"]
bad_ = []
for l_ in LEG_:
    for x_ in (l_, "- " + l_, "## " + l_):
        y_ = P._clean_free(x_)
        if not (shown(y_) and MARK_.search(y_) and P._clean_free(y_) == y_):
            bad_.append((x_, y_))
check("AC8 redaction marker (r6, A R5-1 / B F1): %d free-text lines carrying the marker in every historical form inside "
      "link, image, HTML, comment, autolink, code, footnote, table, math or emphasis syntax: each shows it as text, stably"
      % (3 * len(LEG_)), bad_ == [], bad_[:4])
check("AC8 redaction marker (r6, A R5-1 / B F1): A's and B's round-4 line '- [click](redacted) (advisor 0130).' is written escaped",
      P._clean_free("- [click](redacted) (advisor 0130).") == "- \\[click\\]\\(redacted\\) \\(advisor 0130\\)\\.",
      P._clean_free("- [click](redacted) (advisor 0130)."))
for l_ in ("- (redacted): fixed (added) — statement 2 of the new document", "- CVE-7 [pkg:(redacted)]: fixed (changed: status_notes)",
           "- document fields changed ((redacted))", "- CVE-7: not_affected (changed: (redacted), status_notes)",
           '- `"(redacted)"`: fixed (added) — statement 1 of the new document'):
    check("AC8 redaction marker (r6): a VEX line the notes print with the visible marker reads back unchanged: %r" % l_,
          P._clean_free(l_) == l_, P._clean_free(l_))
R4T_ = ("## v0.2.2 — patch release\n\n### Fixes\n- CVE-1 in [click](redacted): v1 → v2 (severity high; variants: default)\n\n### VEX\n"
        "- (redacted): fixed (added) — statement 2 of the new document\n\n### Behavior changes\n- [click](redacted) (advisor 0130).\n")
got_ = P.tag_notes(mktag("v0.2.2", R4T_)) or ""
check("AC8 redaction marker (r6, B F1): a round-4 tag's '[click](redacted)' (fix line and behavior entry) reads escaped, its VEX line unchanged",
      "](redacted)" not in got_ and "- \\[click\\]\\(redacted\\) \\(advisor 0130\\)\\.\n" in got_
      and "\\[click\\]\\(redacted\\)\\: v1" in got_ and "- (redacted): fixed (added) — statement 2 of the new document\n" in got_, got_)
try:
    cl_, nn_ = P.changelog(R4T_, None, "- [click]gpt (advisor 0130).\n- Another change (advisor 0131).\n")
except ValueError as e:
    cl_, nn_ = repr(e), None
check("0130 + r6 (B F1): a round-4 tag's '[click](redacted)' entry is shown escaped in the changelog and leaves next-release-notes",
      "](redacted)" not in cl_ and nn_ == "- Another change (advisor 0131).\n", (cl_, nn_))
try:
    _, nn_ = P.changelog(R4T_.replace("- [click](redacted) (advisor 0130).", "- (redacted) helper updated (advisor 0130)."), None,
                         "- gpt helper updated (advisor 0130).\n")
except ValueError as e:
    nn_ = repr(e)
check("0130 + r6 (B F1): an entry a round-4 tag published as '(redacted) helper updated' leaves next-release-notes too", nn_ == "", nn_)
try:
    P.changelog(nt_, HIST_ + "- [click](redacted) (advisor 0130).\n", ""); got_ = "accepted"
except ValueError:
    got_ = "ValueError"
check("AC8 changelog history (r6, A R5-1): a history whose '(redacted)' a link takes is refused, not rewritten", got_ == "ValueError", got_)
# idempotence and visibility over random free text built from markers in every form, Markdown, names and escapes
FREE_P_ = ["gpt", "google", "google.com", "(redacted)", "<redacted>", "\\(redacted\\)", "\\<redacted\\>", "REDACTED", "redacted",
           "[", "]", "(", ")", "<", ">", "!", "`", "\\", "*", "_", "&#97;", ".", " ", "a", "- ", "#", ":", "//", "www.", "\"",
           "(advisor 0130)", "x", "~", "|", "$", "@", "—"]
rng6_ = random.Random(306)
bad_, n_marked = [], 0
for _ in range(6000):
    x_ = "".join(rng6_.choice(FREE_P_) for _ in range(rng6_.randint(1, 9)))
    y_ = P._clean_free(x_)
    if P._clean_free(y_) != y_ or "\n" in y_:
        bad_.append(("not stable", x_, y_))
    if MARK_.search(y_):
        n_marked += 1
        if not shown(y_):
            bad_.append(("marker not shown", x_, y_))
check("AC8 redaction marker (r6): 6000 random free-text lines (%d holding a marker): cleaning twice changes nothing and "
      "every marker is shown as text" % n_marked, bad_ == [] and n_marked > 2000, bad_[:4])
# F2: one line's escaping cannot protect it from a construct another line opens: a text holding the marker is refused
# unless every line is blank, a '- ' bullet, an ATX heading or the no-behavior-change line (no line can open a block or
# continue a construct across lines then)
CTX_ = [("B's HTML comment", "<!--\ngpt\n-->\n"), ("an HTML comment around a bullet", "<!--\n- gpt helper (advisor 0130).\n-->\n"),
        ("a raw HTML block", "<details>\n\n- gpt\n\n</details>\n"), ("a fenced block", "```mermaid\n- gpt\n```\n"),
        ("a link title over lines", "- [a](/u \"\nx gpt\n\")\n"), ("a reference definition", "[x]:\n- gpt\n"),
        ("an indented line", "    - gpt\n"), ("a block quote", "> a\n- gpt\n"), ("a paragraph line", "text\n- gpt\n"),
        ("a legacy marker in a comment", "<!--\n- (redacted) helper (advisor 0130).\n-->\n")]
for what_, ctx_ in CTX_:
    body_ = "## v0.2.3 — patch release\n\n" + ctx_
    got_ = P.tag_notes(mktag("v0.2.3", body_))
    try:
        P.changelog(body_, None, ""); cl_ = "accepted"
    except ValueError:
        cl_ = "ValueError"
    try:
        P.changelog(P.notes("v0.2.3", [], []), "# Changelog\n\n## v0.2.2 — patch release\n\n" + ctx_.replace("gpt", "(redacted)"), ""); hi_ = "accepted"
    except ValueError:
        hi_ = "ValueError"
    check("AC8 redaction marker (r6, B F2): %s beside a marker line: the tag carries no notes, the changelog refuses it as "
          "notes and as history" % what_, got_ is None and cl_ == "ValueError" and hi_ == "ValueError", (got_, cl_, hi_))
try:
    P.changelog("## v0.2.3 — patch release\n\n<!--\n", HIST_, ""); got_ = "accepted"
except ValueError:
    got_ = "ValueError"
check("AC8 redaction marker (r6, B F2): new notes opening a comment above a history holding the marker are refused (the "
      "changelog is judged whole)", got_ == "ValueError", got_)
mf_ = "## v0.2.3 — patch release\n\n<!--\nnote\n-->\n"
check("AC8 redaction marker (r6, B F2): a text with no marker keeps its Markdown as written (no new refusal)",
      P.tag_notes(mktag("v0.2.3", mf_)) == mf_, P.tag_notes(mktag("v0.2.3", mf_)))
# A R5-5: the history after the title and its one blank line is copied byte for byte (its own spacing kept)
H4_ = "# Changelog\n\n\n\n## v0.2.1 — patch release\n\nold\n"
cl_, _ = P.changelog(P.notes("v0.2.3", [], []), H4_, "")
check("AC8 changelog history (r6, A R5-5): extra blank lines after the title are kept, not reduced",
      cl_.endswith("\n" + H4_[len("# Changelog\n\n"):]), cl_)
# A (d) / B F6: a line without the marker is never read as this cleaner's escaped output: '\.' in it is not unescaped
# to make a name a module path or a domain (redacted as before round 5)
for x_ in ("google\\.com", "aws\\.com", "google\\.golang\\.org\\/protobuf \\(advisor 0130\\)\\."):
    y_ = P._clean_free(x_)
    check("AC8 redaction (r6, A (d) / B F6): %r without a marker is redacted as before round 5" % x_,
          MARK_.search(y_) and not re.search(r"(?i)google|aws", y_) and P._clean_free(y_) == y_, y_)
check("AC8 redaction (r6, B F6): an escaped line without a marker or a name is unchanged", P._clean_free("a\\.b \\(c\\)") == "a\\.b \\(c\\)")
# B F4 (the channels this PR newly prints: a product, an @id, a field name; the name too, now printed by _lit): a value
# holding a signature-block delimiter never makes the tag of the notes unreadable
SIG_ = "-----BEGIN NOTE-----"
for what_, o_, n_ in (("a vulnerability name", None, vd(vs(vulnerability={"name": SIG_}))),
                      ("a product @id", None, vd(vs(products=[{"@id": SIG_}]), vs(products=[{"@id": PC}]))),
                      ("a statement @id", None, vd(vs(products=[{"@id": PC}], **{"@id": SIG_}), vs(products=[{"@id": "pkg:b"}]))),
                      ("a field name", vd(VS), vd(vs(**{SIG_: 1}))), ("a long run of hyphens", None, vd(vs(vulnerability={"name": "------BEGIN X"})))):
    nt6_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
    check("AC8 VEX signature delimiter (r6, B F4): %s holding %r: no five-hyphen run printed, the tag of the notes reads back"
          % (what_, SIG_), "-----" not in nt6_ and P.tag_notes(mktag("v0.2.3", nt6_)) == nt6_ and resolves(nt6_, o_, n_)[0],
          (vex_part(nt6_), resolves(nt6_, o_, n_)))
# a tag of random generated notes reads back byte for byte (every VEX line a fixed point of the free-text cleaner)
bad_ = []
for it_ in range(300):
    names_ = [rname() for _ in range(rng6_.randint(1, 3))]
    o_ = {"statements": [rstmt(names_) for _ in range(rng6_.randint(0, 3))]}
    n_ = {"statements": [rstmt(names_) for _ in range(rng6_.randint(0, 3))]}
    try:
        nt6_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_), behavior=["%s (advisor 0130)." % rname(1).replace("\n", " ")])
    except ValueError:
        continue
    if P.tag_notes(mktag("v0.2.3", nt6_)) != nt6_:
        bad_.append((it_, nt6_))
check("AC8 tag round trip (r6): a tag of 300 random generated notes reads back byte for byte", bad_ == [], bad_[:2])
# A (c), B F3: the oracle refuses a GitHub-active value printed bare, another spelling of a value, a redacted CVE name the
# source does not call for, unparsed product text, and fix or behavior lines that are not their own inputs
o_ = vd(vs(products=[{"@id": "@octocat"}], status="fixed"), vs(products=[{"@id": "pkg:b"}], status="fixed"))
n_ = vd(dict(o_["statements"][0], status_notes="n2"), o_["statements"][1])
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX oracle (r6, A (c)): the true '@octocat' line resolves; the same value printed bare is refused",
      '[`"@octocat"`]' in nt_ and resolves(nt_, o_, n_)[0] and not resolves(nt_.replace('`"@octocat"`', "@octocat"), o_, n_)[0],
      (vex_part(nt_), resolves(nt_.replace('`"@octocat"`', "@octocat"), o_, n_)))
o_, n_ = vd(vs(vulnerability={"name": "CVE-1"}, status="fixed")), vd(vs(vulnerability={"name": "CVE-1"}, status="fixed", status_notes="new"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
for fab_ in ("- CVE-(redacted): fixed (changed: status_notes) — statement 1 of the new document",
             "- CVE-1 [pkg:wrong](redacted): fixed (changed: status_notes)", '- `"CVE-1"`: fixed (changed: status_notes)',
             '- `"\\u0043VE-1"`: fixed (changed: status_notes)', "- CVE-1: fixed (changed: status_notes) and more",
             "- CVE-1: fixed (changed: `\"status_notes\"`)"):
    check("AC8 VEX oracle (r6, B F3): true '- CVE-1: fixed (changed: status_notes)' resolves; fabricated %r is refused" % fab_,
          vlines(nt_) == ["- CVE-1: fixed (changed: status_notes)"] and resolves(nt_, o_, n_)[0]
          and not resolves(nt_.replace(vlines(nt_)[0], fab_), o_, n_)[0], resolves(nt_.replace(vlines(nt_)[0], fab_), o_, n_))
FXS_ = [{"cve": "CVE-9", "package": "p", "old": "v1", "new": "v2", "severity": "high", "variants": ["default"]}]
BEHS_ = ["First change (advisor 0130).", "Second change (advisor 0131)."]
nt_ = P.notes("v0.2.3", FXS_, P.vex_changes(o_, n_), behavior=BEHS_)
fx_l_, b1_, b2_ = "- CVE-9 in p: v1 → v2 (severity high; variants: default)", "- First change (advisor 0130).", "- Second change (advisor 0131)."
swap_ = nt_.replace(fx_l_, "\x01").replace(b1_, fx_l_).replace("\x01", b1_)
check("AC8 VEX oracle (r6, A (c) / B F3): the true notes resolve against their fix and behavior inputs; a fix line swapped "
      "with a behavior entry, a duplicated entry and a count passed for the inputs are refused",
      resolves(nt_, o_, n_, fixes=FXS_, behavior=BEHS_)[0] and swap_ != nt_
      and not resolves(swap_, o_, n_, fixes=FXS_, behavior=BEHS_)[0]
      and not resolves(nt_.replace(b2_, b1_), o_, n_, fixes=FXS_, behavior=BEHS_)[0]
      and not resolves(nt_, o_, n_, fixes=FXS_, behavior=BEHS_[::-1])[0], resolves(swap_, o_, n_, fixes=FXS_, behavior=BEHS_))
try:
    resolves(nt_, o_, n_, fixes=1, behavior=2); got_ = "accepted"
except TypeError:
    got_ = "TypeError"
check("AC8 VEX oracle (r6): a count in place of the inputs is not accepted", got_ == "TypeError", got_)
pub ="## v0.2.2 — patch release\n\n### Behavior changes\n- Go 1.27: a request with more than 500 header values is rejected with 431 before it reaches the cache (owner accepted; advisor 0115).\n"
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
os.remove(os.path.join(cd_, "notes.md"))
args_null_ = [x if x != os.path.join(cd_, "o.json") else J_("null.json", None) for x in args]
check("AC8 CLI notes (Codex #300 r2, B): a --vex-old file holding JSON null is refused (exit 2, no notes), never 'every statement added'",
      P.main(args_null_) == 2 and not os.path.exists(os.path.join(cd_, "notes.md")))
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
print("patch-decide: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
