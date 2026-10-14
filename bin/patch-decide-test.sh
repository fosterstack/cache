#!/usr/bin/env bash
# proves: REQ-REL-009-AC1, REQ-REL-009-AC2, REQ-REL-009-AC3, REQ-REL-009-AC4, REQ-REL-009-AC8, REQ-REL-009-AC11, REQ-CHAIN-001-AC6
# Rules 61 and 65 (advisor Oct 12): there is no Dockerfile; the base inputs are the committed apko base locks, the melange lock and the archive records listed in
# .github/policy/base-inputs.json (one list, read by the decide job and by this script); a change in them is the "base input changed" signal, fix-class.
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
    return {"sha": sha, "files": list(files), "labels": list(labels), "diffs": dict(diffs or {}), "modes": {f: "100644" for f in files}}   # git always gives a mode
BUMP = {"go.mod": " require (\n-\tgolang.org/x/sys v0.46.0\n+\tgolang.org/x/sys v0.47.0\n )\n",
        "go.sum": "-golang.org/x/sys v0.46.0 h1:a=\n+golang.org/x/sys v0.47.0 h1:b=\n"}
NEWMOD = {"go.mod": "+\tgithub.com/evil/new v1.0.0\n"}
LOCK = {"build/locks/apko.base.lock.json": '-    "version": "1.2.3-r0"\n+    "version": "1.2.4-r0"\n'}
BASE_INPUTS = ["build/locks/apko.base.lock.json", "build/locks/apko-fips.base.lock.json", "build/locks/melange.lock", "build/locks/archive-keys.sha256",
               "build/locks/archive-index.sha256", "build/locks/fips-module.txt"]
# --- AC1: classification by changed files
for files, diff, want in [
    (["go.mod", "go.sum"], BUMP, "fix"),
    (["go.mod"], NEWMOD, "dirty"),                           # a new module is not a version-pin fix
    (["build/locks/apko.base.lock.json"], LOCK, "fix"),      # a base lock moved: the "base input changed" signal (rules 61, 65)
    (BASE_INPUTS, {}, "fix"),                                # the daily refresh PR changes exactly these
    (["build/apko.yaml"], {}, "dirty"),                      # a recipe is a build input, not a base signal
    (["build/docker/Dockerfile.production"], {}, "dirty"),   # there is no Dockerfile any more: a file by that name is shipped configuration, not a base signal
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
check("B01 a base lock without a diff is fix-class (the whole file is the signal; no line parsing)", P.classify(c("x", ["build/locks/melange.lock"]))[0] == "fix")
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
# B03 (rules 61, 65): the base inputs are the committed locks and records of .github/policy/base-inputs.json and nothing else
for f in BASE_INPUTS:
    check("B03 %s alone is a fix (a base input moved)" % f, P.classify(c("x", [f], diffs={f: "-a\n+b\n"}))[0] == "fix")
for name, f in [("a backup of a lock", "build/locks/apko.base.lock.json.bak"), ("another file of the directory", "build/locks/other.json"),
                ("a lock of another directory", "locks/apko.base.lock.json"), ("a recipe", "build/melange.yaml"), ("the fips recipe", "build/apko-fips.yaml"),
                ("the melange template", "build/melange.yaml.tmpl")]:
    check("B03 %s (%s) is no base signal: not patch-clean" % (f, name), P.classify(c("x", [f], diffs={f: "-a\n+b\n"}))[0] == "dirty")
for mode, what in (("100755", "executable"), ("120000", "a symlink"), ("000000", "deleted")):
    cm = {"sha": "x", "files": [BASE_INPUTS[0]], "labels": [], "diffs": {BASE_INPUTS[0]: "-a\n+b\n"}, "modes": {BASE_INPUTS[0]: mode}}
    check("B03 a base lock that is %s is not a refresh: not patch-clean" % what, P.classify(cm)[0] == "dirty")
check("B03 the list itself is read by the release chain: changing it is not patch-clean (a patch cannot widen its own signal)",
      P.classify(c("x", [".github/policy/base-inputs.json"], diffs={".github/policy/base-inputs.json": "+x\n"}))[0] == "dirty")
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
check("B03 a file named like the removed Dockerfile with a moved FROM is not a base signal: not patch-clean", P.classify(c("x", ["build/docker/Dockerfile.production"], diffs={"build/docker/Dockerfile.production": MOVED}))[0] == "dirty")
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
# --- rules 61 and 65: the base inputs are ONE committed list, read by the decide job and by this script (advisor Oct 12)
real_list = os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), "..", ".github", "policy", "base-inputs.json")
check("the committed list names exactly the base locks, the melange lock, the archive records and the fips module record (cache-ce's names)",
      sorted(P.load_base_inputs(real_list)) == sorted(BASE_INPUTS), P.load_base_inputs(real_list) if os.path.exists(real_list) else "no file")
bi = tempfile.mkdtemp()
def bil(obj, raw=None):
    f = os.path.join(bi, "l%d.json" % len(os.listdir(bi)))
    open(f, "w").write(raw if raw is not None else json.dumps(obj))
    return f
def refused(f):
    try:
        P.load_base_inputs(f)
    except ValueError:
        return True
    return False
check("B07 a list file that is not there is refused (no patch decision on an unreadable list)", refused(os.path.join(bi, "absent.json")))
for what, f in [("not JSON", bil(None, raw="{")), ("no base_inputs key", bil({"x": []})), ("an empty list", bil({"base_inputs": []})),
                ("a duplicate", bil({"base_inputs": ["a/b", "a/b"]})), ("an absolute path", bil({"base_inputs": ["/etc/passwd"]})),
                ("a parent segment", bil({"base_inputs": ["build/../x"]})), ("a glob", bil({"base_inputs": ["build/locks/*"]})),
                ("a directory", bil({"base_inputs": ["build/locks/"]})), ("a non-string", bil({"base_inputs": [1]})),
                ("a backslash", bil({"base_inputs": ["build\\locks"]})), ("a leading dot segment", bil({"base_inputs": ["./build/locks/a"]}))]:
    check("B07 a list with %s is refused (fail closed)" % what, refused(f))
check("B07 a well-formed list is read", P.load_base_inputs(bil({"base_inputs": ["build/locks/a.lock"]})) == ["build/locks/a.lock"])
# classification follows the list handed in, not a copy kept in the code
L2 = P.load_base_inputs(bil({"base_inputs": ["locks/only.txt"]}))
check("B07 the classifier reads the list it is given (a path in it is fix-class, a real lock not in it is not)",
      P.classify(c("x", ["locks/only.txt"]), base_inputs=L2)[0] == "fix" and P.classify(c("x", ["build/locks/melange.lock"]), base_inputs=L2)[0] == "dirty")
# base-moved: the decide job's read of the same list since the latest release
bm = tempfile.mkdtemp(); g(bm, "init", "-q", "-b", "main")
os.makedirs(os.path.join(bm, "build", "locks")); open(os.path.join(bm, "build/locks/melange.lock"), "w").write("1\n"); open(os.path.join(bm, "build/locks/apko.base.lock.json"), "w").write("1\n")
g(bm, "add", "build"); g(bm, "commit", "-q", "-m", "locks"); g(bm, "tag", "v0.2.1")
lst = bil({"base_inputs": ["build/locks/apko.base.lock.json", "build/locks/melange.lock", "build/locks/not-there.txt"]})
def bmoved(*extra):
    r = subprocess.run([sys.executable, sys.argv[1], "base-moved", "--base-inputs", lst, "--since", "v0.2.1", "--repo", bm] + list(extra), capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr
rc_, so_, se_ = bmoved()
check("base-moved: nothing moved since the release is said so", rc_ == 0 and "no base input moved since v0.2.1" in so_, (rc_, so_, se_))
open(os.path.join(bm, "build/locks/melange.lock"), "w").write("2\n"); os.makedirs(os.path.join(bm, "docs")); open(os.path.join(bm, "docs/x.md"), "w").write("x\n")
g(bm, "add", "build", "docs"); g(bm, "commit", "-q", "-m", "refresh")
rc_, so_, se_ = bmoved()
check("base-moved: a moved lock is named, an unrelated file is not", rc_ == 0 and "build/locks/melange.lock" in so_ and "docs/x.md" not in so_ and "apko.base" not in so_, (rc_, so_, se_))
rc_, so_, se_ = subprocess.run([sys.executable, sys.argv[1], "base-moved", "--base-inputs", os.path.join(bi, "absent.json"), "--since", "v0.2.1", "--repo", bm],
                               capture_output=True, text=True).returncode, "", ""
check("base-moved: an unreadable list is exit 2 (the job stops; no fallback)", rc_ == 2, rc_)
rc_ = subprocess.run([sys.executable, sys.argv[1], "base-moved", "--base-inputs", lst, "--since", "v9.9.9", "--repo", bm], capture_output=True, text=True).returncode
check("base-moved: a release that is not a tag here is exit 2, never 'nothing moved'", rc_ == 2, rc_)
dd = tempfile.mkdtemp(); outd = os.path.join(dd, "d.json")
RLd = os.path.join(dd, "rel.json"); json.dump(["v0.2.1"], open(RLd, "w"))
rc_ = subprocess.run([sys.executable, sys.argv[1], "decide", "--event", "schedule", "--repo", bm, "--cut-today", "false", "--released", RLd,
                      "--base-inputs", lst, "--out", outd], capture_output=True, text=True)
dec_ = json.load(open(outd)) if os.path.exists(outd) else {}
check("decide: a moved base lock (and a neutral file) is a patch-clean fix that cuts v0.2.2", rc_.returncode == 0 and dec_.get("cut") and dec_.get("version") == "v0.2.2" and dec_.get("not_clean") == [], (rc_.returncode, rc_.stdout, rc_.stderr, dec_))
os.remove(outd)
rc_ = subprocess.run([sys.executable, sys.argv[1], "decide", "--event", "schedule", "--repo", bm, "--cut-today", "false", "--released", RLd,
                      "--base-inputs", os.path.join(bi, "absent.json"), "--out", outd], capture_output=True, text=True)
check("decide: an unreadable base list is exit 2 and no decision file", rc_.returncode == 2 and not os.path.exists(outd), (rc_.returncode, rc_.stderr))
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
# round 1 (Codex A, R2): the statement's scope and fields are compared, not only the CVE's status
def sdoc(*st):
    return {"statements": [dict({"vulnerability": {"name": n}, "status": stt, "products": [{"@id": pid}]}, **extra) for n, stt, pid, extra in st]}
A_ = "pkg:oci/cache@sha256:" + "a" * 64; B_ = "pkg:oci/cache@sha256:" + "b" * 64
vs = P.vex_changes(sdoc(("CVE-1", "not_affected", A_, {})), sdoc(("CVE-1", "not_affected", B_, {})))
check("R2 VEX: the same CVE and status for another product is a removed and an added statement, naming the scope",
      sorted((v["change"], v.get("scope")) for v in vs) == [("added", B_), ("removed", A_)], vs)
vj = P.vex_changes(sdoc(("CVE-1", "not_affected", A_, {"justification": "vulnerable_code_not_present"})),
                   sdoc(("CVE-1", "not_affected", A_, {"justification": "component_not_present"})))
check("R2 VEX: a changed justification is a change", [v["change"] for v in vj] == ["changed justification"], vj)
vi = P.vex_changes(sdoc(("CVE-1", "not_affected", A_, {"impact_statement": "x"})), sdoc(("CVE-1", "not_affected", A_, {"impact_statement": "y"})))
check("R2 VEX: a changed impact statement is a change", [v["change"] for v in vi] == ["changed impact statement"], vi)
vm = P.vex_changes(sdoc(("CVE-1", "not_affected", A_, {}), ("CVE-1", "affected", B_, {})), sdoc(("CVE-1", "not_affected", A_, {}), ("CVE-1", "not_affected", B_, {})))
check("R2 VEX: two statements for one CVE are both kept (one does not overwrite the other)",
      [(v["change"], v.get("scope")) for v in vm] == [("changed from affected", B_)], vm)
def adoc(assoc):   # one statement whose products each carry subcomponents: assoc = {product: [subcomponent, ...]}
    return {"statements": [{"vulnerability": {"name": "CVE-1"}, "status": "affected",
                            "products": [{"@id": p, "subcomponents": [{"@id": c} for c in cs]} for p, cs in assoc.items()]}]}
vsw = P.vex_changes(adoc({"P": ["A"], "Q": ["B"]}), adoc({"P": ["B"], "Q": ["A"]}))
check("R2 VEX: moving subcomponents between products is a scope change (the product and its subcomponents stay associated)", vsw != [], vsw)
vco = P.vex_changes(adoc({"P": ["urn:a,urn:b"]}), adoc({"P": ["urn:a", "urn:b"]}))
check("R2 VEX: one component id that contains a comma is not two components", vco != [], vco)
vdual = P.vex_changes({"statements": adoc({"P": ["a,b"]})["statements"] + adoc({"P": ["a", "b"]})["statements"]},
                      {"statements": [dict(s_, status="not_affected") for s_ in adoc({"P": ["a,b"]})["statements"] + adoc({"P": ["a", "b"]})["statements"]]})
check("R2 VEX: two scopes that differ only by how ids are split are displayed as two different scopes", len(vdual) == 2 and vdual[0]["scope"] != vdual[1]["scope"], vdual)
vu = P.vex_changes(sdoc(("CVE-1", "not_affected", A_, {})), sdoc(("CVE-1", "not_affected", A_, {})))
check("R2 VEX: an identical statement is no change", vu == [], vu)
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
# Codex 4b-4 r1 (A B3, B B2): a rename of a listed base input is the deletion of its source and the addition of a destination; rename detection must not hide the
# deletion (the classifier and base-moved both read the history without it)
rn = tempfile.mkdtemp(); g(rn, "init", "-q", "-b", "main"); os.makedirs(os.path.join(rn, "build/locks")); os.makedirs(os.path.join(rn, "docs"))
open(os.path.join(rn, "build/locks/melange.lock"), "w").write("lock content that is long enough to be recognised as a rename %s\n" % ("x" * 200))
open(os.path.join(rn, "build/locks/apko.base.lock.json"), "w").write("1\n")
g(rn, "add", "-A"); g(rn, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "locks"); g(rn, "tag", "v0.2.1")
g(rn, "mv", "build/locks/melange.lock", "docs/retired-lock.json"); g(rn, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "rename a base input away")
rlist = bil({"base_inputs": ["build/locks/apko.base.lock.json", "build/locks/melange.lock"]})
gcr = P.gather_commits("v0.2.1", cwd=rn)
got = P.classify(gcr[0], base_inputs=P.load_base_inputs(rlist)) if gcr else None
check("B3 a listed base input renamed to a data file is a deletion: the commit is not patch-clean", gcr and gcr[0].get("modes", {}).get("build/locks/melange.lock") == "000000" and got and got[0] == "dirty", (gcr, got))
r = subprocess.run([sys.executable, sys.argv[1], "base-moved", "--base-inputs", rlist, "--since", "v0.2.1", "--repo", rn], capture_output=True, text=True)
check("B3 base-moved names the listed source of a rename away, not only a destination", r.returncode == 0 and "build/locks/melange.lock" in r.stdout, (r.returncode, r.stdout, r.stderr))
rn2 = tempfile.mkdtemp(); g(rn2, "init", "-q", "-b", "main"); os.makedirs(os.path.join(rn2, "build/locks"))
open(os.path.join(rn2, "build/locks/melange.lock"), "w").write("lock content that is long enough to be recognised as a rename %s\n" % ("y" * 200))
g(rn2, "add", "-A"); g(rn2, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "locks"); g(rn2, "tag", "v0.2.1")
g(rn2, "mv", "build/locks/melange.lock", "build/locks/apko.base.lock.json"); g(rn2, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "rename between two listed inputs")
r = subprocess.run([sys.executable, sys.argv[1], "base-moved", "--base-inputs", rlist, "--since", "v0.2.1", "--repo", rn2], capture_output=True, text=True)
check("B3 a rename between two listed base inputs names both the source and the destination in base-moved", r.returncode == 0 and "build/locks/melange.lock" in r.stdout and "build/locks/apko.base.lock.json" in r.stdout, (r.returncode, r.stdout, r.stderr))
# Codex 4b-4 r2 (A M1, B R2): the patch-fix label upgrades a not-clean commit, but it never upgrades a deleted, executable or symlinked base input (a base input
# removed is an image change, not "no behavior change"), and a base input with no mode evidence is not a refresh
for mode in ("000000", "100755", "120000"):
    got = P.classify(dict(c("x", ["build/locks/melange.lock"], labels=["patch-fix"]), modes={"build/locks/melange.lock": mode}), base_inputs=P.load_base_inputs(rlist))
    check("M1 a labelled commit that makes the base input %s is still dirty" % mode, got[0] == "dirty", got)
got = P.classify({"sha": "x", "files": ["build/locks/melange.lock"], "labels": [], "diffs": {}, "modes": {}}, base_inputs=P.load_base_inputs(rlist))
check("M1 a base input with no mode evidence is dirty, never a refresh", got[0] == "dirty" and "mode" in got[1], got)
got = P.classify(dict(c("x", ["build/locks/melange.lock", "docs/a.md"], labels=["patch-fix"]), modes={"build/locks/melange.lock": "100644", "docs/a.md": "100644"}), base_inputs=P.load_base_inputs(rlist))
check("M1 an ordinary refresh with its mode stays fix-class", got[0] == "fix", got)
got = P.classify(dict(c("x", ["bin/x.sh"], labels=["patch-fix"], diffs={"bin/x.sh": "+echo\n"}), modes={"bin/x.sh": "100644"}), base_inputs=P.load_base_inputs(rlist))
check("M1 the label still upgrades a not-clean commit that touches no base input (the owner's override is unchanged)", got[0] == "fix", got)
# a merge commit is read against its first parent (the same three reads), so a base input refreshed on a side branch is judged with its mode
mg = tempfile.mkdtemp(); g(mg, "init", "-q", "-b", "main"); os.makedirs(os.path.join(mg, "build/locks"))
open(os.path.join(mg, "build/locks/melange.lock"), "w").write("1\n"); g(mg, "add", "-A"); g(mg, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base"); g(mg, "tag", "v0.2.1")
g(mg, "checkout", "-q", "-b", "side"); open(os.path.join(mg, "build/locks/melange.lock"), "w").write("2\n"); g(mg, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "refresh on a side branch")
g(mg, "checkout", "-q", "main"); open(os.path.join(mg, "docs.md"), "w").write("d\n"); g(mg, "add", "-A"); g(mg, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "main moves")
g(mg, "-c", "user.name=t", "-c", "user.email=t@t", "merge", "-q", "--no-ff", "-m", "merge side", "side")
gm = P.gather_commits("v0.2.1", cwd=mg)
msha = subprocess.run(["git", "-C", mg, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
mrec = [x for x in gm if x["sha"] == msha]
# the merge's own record: it changes the lock relative to its first parent? no: the first parent (main) did not have the side branch's refresh, so the merge brings it in
check("M1 the merge commit is its own record, with its changed path, its mode and its classification (read against the first parent)",
      len(mrec) == 1 and mrec[0]["files"] == ["build/locks/melange.lock"] and mrec[0]["modes"] == {"build/locks/melange.lock": "100644"}
      and P.classify(mrec[0], base_inputs=P.load_base_inputs(rlist))[0] == "fix", (msha, mrec))
# --- AC3 (immediate cut): the images of the latest release are the ones that exist for its version (v0.3.0 dropped the debug variant)
import subprocess
def variants(ver):
    r = subprocess.run([sys.executable, sys.argv[1], "variants", "--version", ver], capture_output=True, text=True); return r.returncode, r.stdout.split()
for ver, want in (("0.2.2", ["0.2.2", "0.2.2-debug", "0.2.2-fips"]), ("0.1.0", ["0.1.0", "0.1.0-debug", "0.1.0-fips"]), ("0.3.0", ["0.3.0", "0.3.0-fips"]), ("0.3.1", ["0.3.1", "0.3.1-fips"]),
                  ("0.10.0", ["0.10.0", "0.10.0-fips"]), ("1.0.0", ["1.0.0", "1.0.0-fips"]), ("0.2.10", ["0.2.10", "0.2.10-debug", "0.2.10-fips"])):
    rc, got = variants(ver); check("AC3 the images scanned for release %s are exactly %s" % (ver, want), rc == 0 and got == want, (rc, got))
for bad in ("v0.3.0", "0.3", "0.3.0-rc1", "", "0.3.0 -debug", "x.y.z"):
    rc, got = variants(bad); check("AC3 a version that is not X.Y.Z (%r) is refused and prints nothing" % bad, rc != 0 and got == [], (rc, got))
# --- REQ-CHAIN-001-AC6 (advisor Oct 12): the decide job refuses, naming the marker, unless .github/policy/rc-proof.json validates for the commit being tagged
import shutil
rp = tempfile.mkdtemp(prefix="rcproof-")
bindir = os.path.dirname(os.path.abspath(sys.argv[1]))
def rg(*a): return subprocess.run(["git", "-C", rp, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"] + list(a), check=True, capture_output=True, text=True).stdout.strip()
rg("init", "-q", "-b", "main")
for d in (".github/workflows", ".github/policy", "bin"): os.makedirs(os.path.join(rp, d))
open(os.path.join(rp, ".github/workflows/release.yml"), "w").write("name: Release\n")
if os.path.exists(os.path.join(bindir, "chain-bytes-sha.py")): shutil.copy(os.path.join(bindir, "chain-bytes-sha.py"), os.path.join(rp, "bin/chain-bytes-sha.py"))
else: open(os.path.join(rp, "bin/chain-bytes-sha.py"), "w").write("x\n")
open(os.path.join(rp, ".github/policy/chain-scripts.json"), "w").write('{"scripts":[{"path":"bin/chain-bytes-sha.py"}]}\n')
rg("add", "-A"); rg("commit", "-q", "-m", "chain"); rg("tag", "v0.3.0-rc1"); rc_commit = rg("rev-parse", "HEAD")
bs = subprocess.run([sys.executable, os.path.join(bindir, "chain-bytes-sha.py"), "sha", "--commit", rc_commit, "--repo", rp], capture_output=True, text=True).stdout.strip() or "0" * 64
keys = ["build", "sign", "rekor", "rebuild", "scanners", "acceptance", "runtime", "arm64", "hostile_verdict"]
good = {"rc_tag": "v0.3.0-rc1", "run_id": "1234567890", "chain_sha256": bs, "records": {k: "0" * 64 for k in keys}}
marker = os.path.join(rp, ".github/policy/rc-proof.json")
def put(m): open(marker, "w").write(m if isinstance(m, str) else json.dumps(m))
put(good); rg("add", "-A"); rg("commit", "-q", "-m", "marker"); head = rg("rev-parse", "HEAD")
def rcp(commit=None, mpath=None, extra=()):
    r = subprocess.run([sys.executable, sys.argv[1], "rc-proof", "--marker", mpath or marker, "--commit", commit or head, "--repo", rp] + list(extra), capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr
rc, msg = rcp(); check("AC6 decide: a marker for the bytes of the commit, with an rc tag that is an ancestor, lets the decision proceed (exit 0)", rc == 0, (rc, msg))
rc, msg = rcp(mpath=os.path.join(rp, "no-such-marker.json"))
check("AC6 decide: a missing marker is refused (exit 1), naming the marker, never skipped", rc == 1 and "marker" in msg and "missing" in msg, (rc, msg))
put("{not json"); rc, msg = rcp(); check("AC6 decide: an unreadable marker is refused", rc == 1 and "marker" in msg, (rc, msg)); put(good)
open(os.path.join(rp, ".github/workflows/release.yml"), "a").write("# edited\n"); rg("add", "-A"); rg("commit", "-q", "-m", "edit"); edited = rg("rev-parse", "HEAD")
rc, msg = rcp(edited); check("AC6 decide: a marker for other bytes (a chain file changed since the proof) is refused, naming the bytes", rc == 1 and "marker" in msg and "bytes" in msg, (rc, msg))
rg("checkout", "-q", "-b", "side", rc_commit); rg("commit", "-q", "--allow-empty", "-m", "side"); rg("tag", "v0.3.0-rc2"); rg("checkout", "-q", "main")
put(dict(good, rc_tag="v0.3.0-rc2")); rc, msg = rcp(head)
check("AC6 decide: an rc tag that is not an ancestor of the commit is refused", rc == 1 and "ancestor" in msg, (rc, msg)); put(good)
put(dict(good, rc_tag="v0.3.0")); rc, msg = rcp(head); check("AC6 decide: a final tag as the rc tag is refused", rc == 1 and "rc_tag" in msg, (rc, msg)); put(good)
rc, msg = rcp(); check("AC6 decide: the check does not change the repository (the marker file is unchanged)", rc == 0 and json.load(open(marker)) == good, (rc, msg))
check("AC6 decide: the subcommand refuses without a commit (usage, never a default)", subprocess.run([sys.executable, sys.argv[1], "rc-proof", "--marker", marker], capture_output=True).returncode == 2)
shutil.rmtree(rp, ignore_errors=True)
print("patch-decide: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
