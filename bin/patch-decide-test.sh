#!/usr/bin/env bash
# proves: REQ-REL-009-AC1, REQ-REL-009-AC2, REQ-REL-009-AC3, REQ-REL-009-AC4, REQ-REL-009-AC8, REQ-REL-009-AC11, REQ-REL-009-AC14, REQ-REL-009-AC15, REQ-CHAIN-001-AC6
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
# r10 (advisor decision Oct 11): notes() checks its whole text, a VEX line too, for the refused forms (a hand-built 'change'
# text holding one is refused); the names ride in a changed field's name
txt = P.notes("v0.2.2", [], P.vex_changes({"statements": [{"vulnerability": {"name": "CVE-2099-0001"}, "status": "fixed"}]},
                                          {"statements": [{"vulnerability": {"name": "CVE-2099-0001"}, "status": "fixed",
                                                           "confirmed by Meta Llama, Mistral, Grok, DeepSeek, Qwen and Copilot": 1}]}))
try:
    P.notes("v0.2.2", [], [{"cve": "CVE-2099-0001", "status": "fixed", "change": "confirmed <b>by</b> Meta Llama"}]); got = "accepted"
except ValueError:
    got = "ValueError"
check("r10: a hand-built VEX change holding a refused form is refused by notes() (no VEX exemption)", got == "ValueError", got)
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
check("R2 VEX: the same CVE and status for another product is a change, not lost (main's AC8 form: the changed field is named, products)",
      [(v["cve"], v["change"]) for v in vs] == [("CVE-1", "changed: products")], vs)
vj = P.vex_changes(sdoc(("CVE-1", "not_affected", A_, {"justification": "vulnerable_code_not_present"})),
                   sdoc(("CVE-1", "not_affected", A_, {"justification": "component_not_present"})))
check("R2 VEX: a changed justification is a change (main's AC8 form)", [v["change"] for v in vj] == ["changed: justification"], vj)
vi = P.vex_changes(sdoc(("CVE-1", "not_affected", A_, {"impact_statement": "x"})), sdoc(("CVE-1", "not_affected", A_, {"impact_statement": "y"})))
check("R2 VEX: a changed impact statement is a change (main's AC8 form)", [v["change"] for v in vi] == ["changed: impact_statement"], vi)
vm = P.vex_changes(sdoc(("CVE-1", "not_affected", A_, {}), ("CVE-1", "affected", B_, {})), sdoc(("CVE-1", "not_affected", A_, {}), ("CVE-1", "not_affected", B_, {})))
check("R2 VEX: two statements for one CVE are both kept (one does not overwrite the other): the changed one is named with its product",
      [(v["change"], v.get("products")) for v in vm] == [("changed from affected", [B_])], vm)
def adoc(assoc):   # one statement whose products each carry subcomponents: assoc = {product: [subcomponent, ...]}
    return {"statements": [{"vulnerability": {"name": "CVE-1"}, "status": "affected",
                            "products": [{"@id": p, "subcomponents": [{"@id": c} for c in cs]} for p, cs in assoc.items()]}]}
vsw = P.vex_changes(adoc({"P": ["A"], "Q": ["B"]}), adoc({"P": ["B"], "Q": ["A"]}))
check("R2 VEX: moving subcomponents between products is a scope change (the product and its subcomponents stay associated)", vsw != [], vsw)
vco = P.vex_changes(adoc({"P": ["urn:a,urn:b"]}), adoc({"P": ["urn:a", "urn:b"]}))
check("R2 VEX: one component id that contains a comma is not two components", vco != [], vco)
vdual = P.vex_changes({"statements": adoc({"P": ["a,b"]})["statements"] + adoc({"P": ["a", "b"]})["statements"]},
                      {"statements": [dict(s_, status="not_affected") for s_ in adoc({"P": ["a,b"]})["statements"] + adoc({"P": ["a", "b"]})["statements"]]})
check("R2 VEX: two scopes that differ only by how ids are split are displayed as two different scopes", len(vdual) == 2 and vdual[0]["products_shown"] != vdual[1]["products_shown"], vdual)
vu = P.vex_changes(sdoc(("CVE-1", "not_affected", A_, {})), sdoc(("CVE-1", "not_affected", A_, {})))
check("R2 VEX: an identical statement is no change", vu == [], vu)
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
def vshown(l):
    """r10 (advisor decision Oct 11: no VEX exemption, one printer): notes() prints every line, a VEX line too, by
    _clean_free, so a line holding the redaction marker is in the escape-whole-line form; it SHOWS its text unescaped,
    which is exactly the VEX line as _clean_md wrote it before (the checks below read the shown text)"""
    pre = "- " if l.startswith("- ") else ""
    body = l[len(pre):]
    if "\\" in body and P.ESCAPED.match(body) and "\\(redacted\\)" in body:
        return pre + P.UNESC.sub(r"\1", body)
    return l
def vex_part(n):
    return "\n".join(vshown(l) for l in n.split("### VEX\n", 1)[1].split("\n\n", 1)[0].split("\n"))
def vrep(nt, a, b):
    """r10: nt with a replaced by b in the SHOWN text of its VEX lines, each changed line printed back as notes() prints
    every line (_clean_free): a mutant in the form the notes would carry it"""
    head_, rest_ = nt.split("### VEX\n", 1)
    sec_, tail_ = rest_.split("\n\n", 1)
    return head_ + "### VEX\n" + "\n".join(P._clean_free(vshown(l).replace(a, b)) if a in vshown(l) else l
                                           for l in sec_.split("\n")) + "\n\n" + tail_
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
    more written \\u002d, so no run of five hyphens — a signature-block delimiter — is ever printed; r10, advisor decision
    Oct 11: '<' and '&' written \\u003c and \\u0026, so no printed value holds a refused form) in a code span; r11
    (Codex #300 r10, B 1): the value is redacted as text (_clean_md) BEFORE it is encoded, so an escape never hides a name"""
    return "`%s`" % re.sub(r"-(?=----)", r"\\u002d", json.dumps(P._clean_md(v), ensure_ascii=True).replace("`", "\\u0060")
                           .replace("<", "\\u003c").replace("&", "\\u0026"))
def bare_ok(v, before_colon=False):
    """the oracle's own bare-form rule (r6, A (c)): a letter, then letters, digits and - . _ / only, after at most one
    pkg: / urn: / cpe: prefix, and inert (with the ':' the notes print after a CVE name); r8 (r7 B F4): no run of five
    hyphens (a space printed after it would complete '-----BEGIN ')"""
    return (re.fullmatch(r"(?:(?:pkg|urn|cpe):)?[A-Za-z][A-Za-z0-9._/-]*", v) is not None and "-----" not in v
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
    # r9 (Codex #300 r8, B F6): a 'changed' line pairs an old and a new statement only by an identity the pairing rules
    # support, read here from the documents alone: (a) the CVE has exactly one statement on each side; (b) the same @id,
    # held once in each WHOLE document (and so once among the CVE's unmatched statements); (c) the same non-empty product
    # scope (subcomponent order ignored), held once on each side among the CVE's unmatched statements that (b) leaves. A
    # pairing that only the claimed field differences single out is a guess, refused.
    def scope_(s):
        ps = s.get("products", [])
        if not readable(s) or not ps:
            return None
        return tuple(sorted(canon_(dict(p, subcomponents=sorted(p["subcomponents"], key=canon_)) if "subcomponents" in p else p)
                            for p in ps))
    def whole_ids(doc):
        return collections.Counter(s["@id"] for s in (doc or {}).get("statements", []) if isinstance(s.get("@id"), str))
    ids_o, ids_n = whole_ids(o_doc), whole_ids(n_doc)
    def own(s, ids):
        return s["@id"] if isinstance(s.get("@id"), str) and ids[s["@id"]] == 1 else None
    def supported(o, n):
        cve = n["vulnerability"]["name"]
        if not (readable(o) and readable(n)):
            return False
        if sum(s["vulnerability"]["name"] == cve for s in olds) == 1 and sum(s["vulnerability"]["name"] == cve for s in news) == 1:
            return True
        if own(o, ids_o) is not None and own(o, ids_o) == own(n, ids_n):
            return True
        un_o = [json.loads(s) for s in surplus_old.elements() if json.loads(s)["vulnerability"]["name"] == cve and readable(json.loads(s))]
        un_n = [json.loads(s) for s in surplus_new.elements() if json.loads(s)["vulnerability"]["name"] == cve and readable(json.loads(s))]
        idpaired = ({own(s, ids_o) for s in un_o} & {own(s, ids_n) for s in un_n}) - {None}
        rest_o = [s for s in un_o if own(s, ids_o) not in idpaired]
        rest_n = [s for s in un_n if own(s, ids_n) not in idpaired]
        k = scope_(o)
        return (k is not None and k == scope_(n) and o in rest_o and n in rest_n
                and sum(scope_(s) == k for s in rest_o) == 1 and sum(scope_(s) == k for s in rest_n) == 1)
    def pairings(i, avail):
        """how many one-to-one pairings of the changed lines with the remaining old statements fit (counted up to 2)"""
        if i == len(changed):
            return 0 if avail else 1
        st, change, _ = changed[i]
        n_ = 0
        for j, a in enumerate(avail):
            if n_ >= 2:
                break
            if claim_fits(change, json.loads(a), st) and supported(json.loads(a), st):
                n_ += pairings(i + 1, avail[:j] + avail[j + 1:])
        return min(n_, 2)
    np_ = pairings(0, left)
    if np_ == 0:
        probs.append("the changed lines do not pair one-to-one with the remaining old statements by their claimed change: %r"
                     % [c_[2] for c_ in changed])
    elif np_ > 1 and len({canon_(json.loads(a)) for a in left}) > 1:
        # r8 (Codex #300 r7, A low): 'changed' claims that fit more than one pairing of distinct old statements are a
        # guess the documents do not decide; production prints removed + added then, and the oracle refuses the guess
        probs.append("the changed lines guess a pairing the documents do not decide: %r" % [c_[2] for c_ in changed])
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
      vlines(nt_) == ['- CVE-7 [pkg:oci/cache]: fixed (changed: status_notes) — statement `"urn:s:\\u0026#97;"`',
                      '- CVE-7 [pkg:oci/cache]: fixed (changed: status_notes) — statement `"urn:s:a"`']
      and all(inert(l) for l in vlines(nt_)) and resolves(nt_, o_, n_)[0], vex_part(nt_))
nt_ = P.notes("v0.2.3", [], P.vex_changes(vd(VS), vd(vs(**{"\n- no change\n": 1}), vs(vulnerability={"name": "<!-- CVE-7 -->"}))))
check("AC8 VEX rendering (r3, B3): an HTML-comment name and a field name carrying '\\n- no change\\n' print quoted, one line each",
      vlines(nt_) == ['- `"\\u003c!-- CVE-7 -->"`: not_affected (added)', '- CVE-7: not_affected (changed: `"\\n- no change\\n"`)'], vex_part(nt_))
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
    P._clean = lambda s: re.sub(r"^(- )?CVE-\d+", r"\1CVE-N", real_clean_(s))     # r10: _clean_free hands the body without '- '
    try:
        got_ = vlines(P.notes("v0.2.3", [], P.vex_changes(None, vd(*(vs(vulnerability={"name": "CVE-%d" % i}) for i in (1, 2, 3))))))
    except Exception as e:      # noqa: BLE001
        got_ = repr(e)
    check("AC8 VEX relabel (r3, B gap): three FINAL lines that read alike are each relabelled by position",
          got_ == ["- CVE-N: not_affected (added) — statement %d of the new document" % i for i in (1, 2, 3)], got_)
    # names and labels intact, only the change text redacted alike: the relabel loop alone tells the two lines apart (r9:
    # the redactor writes '(added)' for both, a form inside the VEX line grammar notes() checks its lines against)
    P._clean = lambda s: re.sub(r"\((added|removed)\)", "(added)", real_clean_(s))
    try:
        got_ = vlines(P.notes("v0.2.3", [], P.vex_changes(vd(vs(products=5)), vd(vs(products=5, status_notes="n2")))))
    except Exception as e:      # noqa: BLE001
        got_ = repr(e)
    check("AC8 VEX relabel (r3, B gap): removed + added lines that read alike only after redaction: each relabelled by position",
          got_ == ["- CVE-7 [products unreadable]: not_affected (added) — statement 1 of the new document",
                   "- CVE-7 [products unreadable]: not_affected (added) — statement 1 of the old document"], got_)
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
    for li_, l in enumerate(nt_.split("### VEX\n", 1)[1].split("\n\n", 1)[0].split("\n")):     # r10: the printed lines
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
      not resolves(vrep(nt_, "(redacted), status_notes", "(redacted), impact_statement"), o_, n_)[0])
o_, n_ = vd(VS), vd(vs(status_notes="n2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX oracle (r5, B F2): 'changed: (redacted)' for a real, unredacted status_notes change is refused",
      resolves(nt_, o_, n_)[0] and not resolves(vrep(nt_, "changed: status_notes", "changed: (redacted)"), o_, n_)[0])
RA_, RB_ = vs(products=[{"@id": "pkg:gpt"}], status="fixed"), vs(products=[{"@id": "pkg:b"}], status="fixed")
o_, n_ = vd(RA_, RB_), vd(dict(RA_, status_notes="n2"), dict(RB_, status_notes="n2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_))
check("AC8 VEX oracle (r5): a redacted product resolves; the same marker on a product the redactor leaves alone is refused",
      "[pkg:(redacted)]" in vex_part(nt_) and "[pkg:b]" in vex_part(nt_) and resolves(nt_, o_, n_)[0]
      and not resolves(vrep(nt_, "[pkg:b]", "[pkg:(redacted)]"), o_, n_)[0]
      and not resolves(vrep(nt_, "[pkg:(redacted)]", "[(redacted)]"), o_, n_)[0]
      and not resolves(vrep(nt_, "[pkg:(redacted)]", "[pkg:b]"), o_, n_)[0], (vex_part(nt_), resolves(nt_, o_, n_)))
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
def _r9_refuses(f, *a):
    try:
        f(*a)
    except ValueError:
        return True
    return False
check("AC14 (r9; was r4/r5 'an older tag's <redacted> shown escaped'): '- <redacted>: fixed (added)' under a '### VEX' heading "
      "the generator does not write there, outside the VEX line grammar, is refused as changelog input",
      _r9_refuses(P.changelog, old_, None, ""))
ent_ = ["A gpt-assisted fix (advisor 0130)."]
# r8 (REQ-REL-009-AC14, advisor step 5): the historical forms are cut back; an entry is published only as the line
# notes() prints for it (no published text ever held another marker form: no CHANGELOG.md on main, no v* tag says 'redacted')
check("0135 + r8: an entry is not published again once the line notes() prints for it was published (whole line)",
      P.unpublished(ent_, P._entry_line(ent_[0]) + "\n") == [] and P.unpublished(ent_, "") == ent_,
      P.unpublished(ent_, P._entry_line(ent_[0]) + "\n"))
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
# r8: '<gpt>' and '<!-- gpt -->' left this list: a '<' before a letter or '!' is refused in a source (REQ-REL-009-AC14)
BEH_ = ["[click]gpt (advisor 0130).", "![x](gpt) (advisor 0130).", "[a](https://gpt.example) (advisor 0130).",
        "[x][gpt] and `gpt` (advisor 0130).", "gpt in google.golang.org/protobuf (advisor 0130)."]
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
def refused(f, *a, **k):
    """'ValueError: <message>' when f refuses, else what it returned"""
    try:
        return f(*a, **k)
    except ValueError as e:
        return "ValueError: %s" % e
got_, cl_ = refused(P.tag_notes, mktag("v0.2.2", old_tag_)), refused(P.changelog, old_tag_, None, "")
check("AC14 (r8; was r5 'older tag shown escaped'): a fix line or behavior entry holding '<redacted>' outside a VEX section is "
      "refused in a tag's notes and as changelog input, never shown",
      str(got_).startswith("ValueError") and str(cl_).startswith("ValueError"), (got_, cl_))
check("AC8 redaction marker (r5): the escaped form is stable: a tag of the notes reads back as the notes byte for byte",
      P.tag_notes(mktag("v0.2.3", nt_)) == nt_, P.tag_notes(mktag("v0.2.3", nt_)))
cl1_, nn1_ = P.changelog(nt_, None, "- [click]gpt (advisor 0130).\n- Another change (advisor 0131).\n")
check("0130 + r5: a published entry holding a marker leaves next-release-notes; an unpublished one stays",
      nn1_ == "- Another change (advisor 0131).\n", nn1_)
check("0135 + r5 (r8: the escaped form only, the older forms cut back): an entry holding a marker is not published again",
      P.unpublished(["[click]gpt (advisor 0130)."], nt_) == []
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
HIST_ = "# Changelog\n\n## v0.2.1 — patch release\n\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n- \\(redacted\\)\\: fixed \\(added\\) — statement 2 of the new document\n"
cl_, _ = P.changelog(nt_, HIST_, "")     # r10: a VEX line holding the marker is in the escape-whole-line form (no exemption)
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
# r8 (advisor step 5): the historical forms ('<redacted>', '\<redacted\>', any case) are cut back: no published text ever
# held one, and '<' before a letter is refused in a source (REQ-REL-009-AC14). The escape-whole-line rule stays: a free-text
# line holding the marker '(redacted)' (or '\(redacted\)', how it renders after one escape) is fully escaped, stably.
def has_mark(s):
    """the marker as written, or as it renders after one escape, in s or in s read unescaped"""
    u = re.sub(r"\\([%s])" % PUNCT_, r"\1", s)
    return any(m in t for m in ("(redacted)", "\\(redacted\\)") for t in (s, u))
def esc_all(l):
    """the body (after '- ' or a heading's '#... ') is fully escaped and, read unescaped, holds the marker"""
    m_ = re.match(r"- |#{1,6} ", l)
    body = l[m_.end():] if m_ else l
    return (re.fullmatch(r"(?:\\[%s]|[^%s])*" % (PUNCT_, PUNCT_), body) is not None
            and any(m in re.sub(r"\\([%s])" % PUNCT_, r"\1", body) for m in ("(redacted)", "\\(redacted\\)")))
LEG_ = ["[click](redacted) (advisor 0130).", "[click](\\(redacted\\)) (advisor 0130).", "[click](gpt) (advisor 0130).",
        "![x](redacted)", "[x](/u \"(redacted)\")", "[x][(redacted)]", "https://x.example/(redacted)", "www.x.example/(redacted)",
        "`(redacted)` and [y](redacted)", "(redacted)[^1]", "| (redacted) |", "$(redacted)$", "*(redacted)*", "_(redacted)_",
        "\\[click\\](redacted)", "[click]\\(redacted\\)", "(redacted)\\", "[x](gpt \"t\")", "`gpt`"]
bad_ = []
for l_ in LEG_:
    for x_ in (l_, "- " + l_, "## " + l_):
        y_ = P._clean_free(x_)
        if not (esc_all(y_) and P._clean_free(y_) == y_):
            bad_.append((x_, y_))
check("AC8 escape-whole-line (r6, A R5-1 / B F1; r8 the current marker only): %d free-text lines carrying the marker inside "
      "link, image, code, footnote, table, math or emphasis syntax: each is fully escaped, stably" % (3 * len(LEG_)), bad_ == [], bad_[:4])
check("AC8 redaction marker (r6, A R5-1 / B F1): A's and B's round-4 line '- [click](redacted) (advisor 0130).' is written escaped",
      P._clean_free("- [click](redacted) (advisor 0130).") == "- \\[click\\]\\(redacted\\) \\(advisor 0130\\)\\.",
      P._clean_free("- [click](redacted) (advisor 0130)."))
for l_ in ("- (redacted): fixed (added) — statement 2 of the new document", "- CVE-7 [pkg:(redacted)]: fixed (changed: status_notes)",
           "- document fields changed ((redacted))", "- CVE-7: not_affected (changed: (redacted), status_notes)",
           '- `"(redacted)"`: fixed (added) — statement 1 of the new document'):
    # r10 (advisor decision Oct 11: no VEX exemption): a VEX line holding the marker is printed in the escape-whole-line
    # form like any line, and that form reads back unchanged; the bare form is not what the notes print and reads escaped
    blk_ = "## v0.2.3 — patch release\n\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n%s\n" % P._clean_free(l_)
    raw_ = "## v0.2.3 — patch release\n\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n%s\n" % l_
    check("AC8 redaction marker (r10; was r6/r8): a VEX line holding the marker is printed escaped, reads back unchanged and "
          "shows the marker: %r" % l_, P._clean_free(l_) != l_ and vshown(P._clean_free(l_)) == l_ and P._clean_lines(blk_) == blk_
          and P.tag_notes(mktag("v0.2.3", blk_)) == blk_ and P._clean_lines(raw_) == blk_, P._clean_lines(blk_))
R4T_ = ("## v0.2.2 — patch release\n\n### Fixes\n- CVE-1 in [click](redacted): v1 → v2 (severity high; variants: default)\n\n### VEX\n"
        "- (redacted): fixed (added) — statement 2 of the new document\n\n### Behavior changes\n- [click](redacted) (advisor 0130).\n")
got_ = P.tag_notes(mktag("v0.2.2", R4T_)) or ""
check("AC8 redaction marker (r6, B F1; r10 no VEX exemption): a round-4 tag's '[click](redacted)' (fix line and behavior entry) "
      "reads escaped, its VEX line too", "](redacted)" not in got_ and "- \\[click\\]\\(redacted\\) \\(advisor 0130\\)\\.\n" in got_
      and "\\[click\\]\\(redacted\\)\\: v1" in got_ and "- \\(redacted\\)\\: fixed \\(added\\) — statement 2 of the new document\n" in got_, got_)
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
    # r8: the line sits under a Behavior changes heading (a free-text line); a bullet run on from the VEX section is a VEX
    # line, exempt by advisor step 5 (1) and trusted as reviewed history
    P.changelog(nt_, HIST_ + "\n### Behavior changes\n- [click](redacted) (advisor 0130).\n", ""); got_ = "accepted"
except ValueError:
    got_ = "ValueError"
check("AC8 changelog history (r6, A R5-1): a history whose '(redacted)' a link takes is refused, not rewritten", got_ == "ValueError", got_)
# idempotence and visibility over random free text built from the marker, Markdown, names and escapes (r8: the legacy forms
# '<redacted>', '\<redacted\>' and any case left the generator; a marker-bearing line is fully escaped)
FREE_P_ = ["gpt", "google", "google.com", "(redacted)", "\\(redacted\\)", "notredacted",
           "[", "]", "(", ")", "<", ">", "!", "`", "\\", "*", "_", "&#97;", ".", " ", "a", "- ", "#", ":", "//", "www.", "\"",
           "(advisor 0130)", "x", "~", "|", "$", "@", "—"]
rng6_ = random.Random(306)
bad_, n_marked = [], 0
for _ in range(6000):
    x_ = "".join(rng6_.choice(FREE_P_) for _ in range(rng6_.randint(1, 9)))
    y_ = P._clean_free(x_)
    if P._clean_free(y_) != y_ or "\n" in y_:
        bad_.append(("not stable", x_, y_))
    if has_mark(y_):
        n_marked += 1
        if not esc_all(y_):
            bad_.append(("marker line not fully escaped", x_, y_))
check("AC8 escape-whole-line (r6; r8): 6000 random free-text lines (%d holding a marker): cleaning twice changes nothing and "
      "every marker-bearing line is fully escaped" % n_marked, bad_ == [] and n_marked > 1500, bad_[:4])
# F2 (r6) / r8: the _shaped() machinery is cut back (advisor step 5). A context that opens a construct with a refused form
# ('<' before a letter, '/', '!' or '?'; a reference-definition shape) is refused wherever it stands (REQ-REL-009-AC14): a
# tag's notes (tag-notes exits 2), the changelog's new notes and its history. A context with no refused form is not
# refused as notes; its marker line is still written fully escaped, and a history holding an unescaped marker is still
# refused as not clean.
CTX_ = [("B's HTML comment", "<!--\ngpt\n-->\n", True), ("an HTML comment around a bullet", "<!--\n- gpt helper (advisor 0130).\n-->\n", True),
        ("a raw HTML block", "<details>\n\n- gpt\n\n</details>\n", True), ("a fenced block", "```mermaid\n- gpt\n```\n", False),
        ("a link title over lines", "- [a](/u \"\nx gpt\n\")\n", True), ("a reference definition", "[x]:\n- gpt\n", True),
        ("an indented line", "    - gpt\n", False), ("a block quote", "> a\n- gpt\n", False), ("a paragraph line", "text\n- gpt\n", False),
        ("a marker in a comment", "<!--\n- (redacted) helper (advisor 0130).\n-->\n", True)]
for what_, ctx_, refuse_ in CTX_:
    body_ = "## v0.2.3 — patch release\n\n" + ctx_
    got_ = refused(P.tag_notes, mktag("v0.2.3", body_))
    cl_ = refused(P.changelog, body_, None, "")
    hi_ = refused(P.changelog, P.notes("v0.2.3", [], []), "# Changelog\n\n## v0.2.2 — patch release\n\n" + ctx_.replace("gpt", "(redacted)"), "")
    if refuse_:
        check("AC14 (r6 B F2; r8; r9 B F5: a marker line continuing the line above): %s: refused in the tag's notes, as the changelog's notes and as history" % what_,
              all(isinstance(x, str) and x.startswith("ValueError") for x in (got_, cl_, hi_)), (got_, cl_, hi_))
    else:
        check("AC8 escape-whole-line (r6 B F2; r8): %s holds no refused form: the marker line is written escaped in the tag's notes "
              "and the changelog; as unescaped history it is refused (not clean)" % what_,
              isinstance(got_, str) and "\\(redacted\\)" in got_ and "\\(redacted\\)" in cl_[0]
              and str(hi_).startswith("ValueError"), (got_, cl_, hi_))
got_ = refused(P.changelog, "## v0.2.3 — patch release\n\n<!--\n", HIST_, "")
check("AC14 (r6 B F2; r8): new notes opening a comment above a history are refused", str(got_).startswith("ValueError"), got_)
mf_ = "## v0.2.3 — patch release\n\n<!--\nnote\n-->\n"
got_ = refused(P.tag_notes, mktag("v0.2.3", mf_))
check("AC14 (r8; was r6 'a text with no marker keeps its Markdown'): a comment in a tag's notes is refused with or without a marker",
      str(got_).startswith("ValueError"), got_)
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
# B F4 (r7, B): a bare value next to a space the formatter prints ('CVE-1-----BEGIN' then ' [') never forms a delimiter
for what_, o_, n_ in (("a CVE name before a product list", None, vd(vs(vulnerability={"name": "CVE-1-----BEGIN"}, products=[{"@id": "pkg:a"}]),
                                                                    vs(vulnerability={"name": "CVE-1-----BEGIN"}, products=[{"@id": "pkg:b"}]))),
                      ("a product before its subcomponents", None, vd(vs(products=[{"@id": "pkg:generic/a-----BEGIN", "subcomponents": [{"@id": "pkg:s"}]}]),
                                                                        vs(products=[{"@id": PC}]))),
                      ("an identifier before another", None, vd(vs(products=[{"identifiers": {"purl": "pkg:a-----BEGIN", "cpe23": "cpe:x"}}]),
                                                                  vs(products=[{"@id": PC}])))):
    nt6_ = refused(P.notes, "v0.2.3", [], P.vex_changes(o_, n_))
    check("AC8 VEX signature delimiter (r7 B F4; r8): %s holding a bare-looking five-hyphen run: no '-----BEGIN ' printed, the tag of "
          "the notes reads back" % what_, isinstance(nt6_, str) and not nt6_.startswith("ValueError") and "-----BEGIN " not in nt6_
          and P.tag_notes(mktag("v0.2.3", nt6_)) == nt6_ and resolves(nt6_, o_, n_)[0], nt6_)
# a tag of random generated notes reads back byte for byte (every VEX line a fixed point of the free-text cleaner)
def ac14_hit(l):
    """the test's own reading of REQ-REL-009-AC14's four line forms (with the widening the implementation documents: a
    reference-definition shape after any list or quote markers and indentation, and a label left open at the line end)"""
    return bool(any(c == "<" and i + 1 < len(l) and (l[i + 1] in "/!?" or l[i + 1].isalpha()) for i, c in enumerate(l))
                or re.match(r"(?:[ \t]*(?:>|(?:[-+*]|\d{1,9}[.)])(?=[ \t]|$)))*[ \t]*\[(?:[^\]\\]|\\.)*(?:\]:|$)", l)
                or re.search(r"&(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);", l) or "-----BEGIN " in l)
bad_, made_, refusals_ = [], 0, []
for it_ in range(300):
    names_ = [rname() for _ in range(rng6_.randint(1, 3))]
    o_ = {"statements": [rstmt(names_) for _ in range(rng6_.randint(0, 3))]}
    n_ = {"statements": [rstmt(names_) for _ in range(rng6_.randint(0, 3))]}
    beh_ = "%s (advisor 0130)." % rname(1).replace("\n", " ")
    try:
        nt6_ = P.notes("v0.2.3", [], P.vex_changes(o_, n_), behavior=[beh_])
    except ValueError as e:
        # r8 (B T1): a refusal is counted and must be one REQ-REL-009-AC14 names for the behavior entry (the PIECES hold
        # '<!--', '&#97;' and '[x]'); any other refusal is a failure
        if ac14_hit("- " + P._oneline(beh_)):
            refusals_.append(it_)
        else:
            bad_.append((it_, "refused: %s" % e))
        continue
    made_ += 1
    if P.tag_notes(mktag("v0.2.3", nt6_)) != nt6_:
        bad_.append((it_, nt6_))
check("AC8 tag round trip (r6; r8 B T1): a tag of every generated note of 300 random inputs reads back byte for byte; every input "
      "is generated or refused for a refused form (generated: %d, refused: %d)" % (made_, len(refusals_)),
      bad_ == [] and made_ + len(refusals_) == 300 and made_ >= 150, bad_[:2])
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
check("B1 (fresh r2d; r9 A (c) / B F4) a second signature-shaped block appended AFTER the real one is refused, not read as notes "
      "(a generated tag's notes region holding '-----BEGIN ': ValueError, exit 2)",
      str(refused(P.tag_notes, raw_after)).startswith("ValueError"), refused(P.tag_notes, raw_after))
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
# ===== REQ-REL-009-AC14 (advisor step 5, Oct 11; owner rule 5 engineering AC): the notes sources are refused outright,
# never decoded, escaped or rewritten, when a line holds (1) '<' before a letter (any Unicode letter), '/', '!' or '?';
# (2) a link-reference-definition shape; (3) a character reference; (4) '-----BEGIN '; and (5) two entries whose published
# lines are the same line are refused before any entry is dropped as published or cleared; file:line in the message,
# exit 2, nothing written. VEX section lines (printed through _lit) are exempt; --published is not a source.
import io, contextlib, shutil
r8_ = tempfile.mkdtemp()
def r8p(name, text=None, raw=False):
    p_ = os.path.join(r8_, name)
    if text is not None:
        open(p_, "w", newline="" if raw else None).write(text)
    return p_
def cli(argv, stdin=None):
    """(exit code, stderr, stdout) of P.main(argv)"""
    err_, out_, old_in = io.StringIO(), io.StringIO(), sys.stdin
    try:
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        with contextlib.redirect_stderr(err_), contextlib.redirect_stdout(out_):
            try:
                rc_ = P.main(argv)
            except SystemExit as e:
                rc_ = e.code
            except Exception as e:      # noqa: BLE001 -- the finding is that it raised
                rc_ = "raised %r" % e
    finally:
        sys.stdin = old_in
    return rc_, err_.getvalue(), out_.getvalue()
LAST_STDOUT = [""]    # r9 (B F7): the stdout of the last notes_cli / changelog_cli run
R8_FIND = [{"id": "CVE-2099-1", "package": "golang.org/x/net", "installed": "v0.30.0", "fixed": "v0.33.0", "severity": "High", "type": "go-module"}]
def notes_cli(nrn=None, finds=None, gomod="module x\n\nrequire golang.org/x/net v0.33.0\n", published="", variant="", base=None, extra=()):
    """run `notes` on fresh files; (rc, stderr, the out file's text or None, the paths)"""
    out_ = r8p("notes.md")
    if os.path.exists(out_):
        os.remove(out_)
    nn_ = r8p("next-release-notes.md", nrn if nrn is not None else "# Notes\n")
    scan_ = r8p("scan.json", json.dumps(gr(finds if finds is not None else R8_FIND), indent=1))
    argv = ["notes", "--version", "v0.2.3", "--variant-grype", variant + "=" + scan_, "--gomod", r8p("go.mod", gomod),
            "--vex-old", r8p("o.json", json.dumps(vdoc(("CVE-1", "affected")))), "--vex-new", r8p("n.json", json.dumps(vdoc(("CVE-1", "not_affected")))),
            "--next-notes", nn_, "--published", r8p("pub.txt", published), "--out", out_] + list(extra)
    if base is not None:
        argv += ["--base-grype", r8p("base.json", json.dumps(gr(base)))]
    rc_, err_, sout_ = cli(argv)
    LAST_STDOUT[0] = sout_
    return rc_, err_, (open(out_).read() if os.path.exists(out_) else None), {"nn": nn_, "scan": scan_, "out": out_, "gomod": r8p("go.mod")}
def refused_at(rc_, err_, out_, where_):
    """exit 2, nothing written, nothing on stdout (r9, B F7), the message names where_ ('file:line' or 'file ... key path')"""
    return rc_ == 2 and out_ is None and where_ in err_ and LAST_STDOUT[0] == ""
# R14-1 the '<' opener
for s_ in ("<b>", "</x", "<!--", "<?php", "<http://a>", "<redacted>", "<é", "<Ж"):
    rc_, err_, out_, p_ = notes_cli("# Notes\n\n- a %s b (advisor 0130).\n" % s_)
    check("AC14 R14-1: an entry holding %r is refused (exit 2, no notes, file:line)" % s_, refused_at(rc_, err_, out_, p_["nn"] + ":3:"), (rc_, err_))
for s_ in ("a < b", "<3", "<=", "x <\n  y", "1<2"):
    rc_, err_, out_, p_ = notes_cli("# Notes\n\n- %s (advisor 0130).\n" % s_)
    check("AC14 R14-1: %r is not refused" % s_, rc_ == 0 and out_ is not None, (rc_, err_))
# R14-2 the reference-definition shape (on a file line, inside an entry after its bullet, and after list or quote markers)
for nrn_, n_ in (("# Notes\n[x]: /u\n", 2), ("# Notes\n   [x]: /u\n", 2), ("# Notes\n[]: y\n", 2), ("- a\n  [x]: /u (advisor 0130).\n", 2),
                 ("# Notes\n\n- [x]: y (advisor 0130).\n", 3), ("# Notes\n\n-  [x]: y (advisor 0130).\n", 3),
                 ("# Notes\n    [x]: /u\n", 2), ("# Notes\n- - [x]: /u (advisor 0130).\n", 2), ("# Notes\n> [x]: /u\n", 2),
                 ("# Notes\n1. [x]: /u\n", 2), ("# Notes\n\n- [x\n  ]: /u (advisor 0130).\n", 3), ("# Notes\n[a\\]b]: /u\n", 2)):
    rc_, err_, out_, p_ = notes_cli(nrn_)
    check("AC14 R14-2: a reference-definition shape is refused: %r (line %d)" % (nrn_, n_), refused_at(rc_, err_, out_, p_["nn"] + ":%d:" % n_), (rc_, err_))
for s_ in ("a [x]: y", "[x] y", "\\[x]: y"):
    rc_, err_, out_, p_ = notes_cli("# Notes\n\n- %s (advisor 0130).\n" % s_)
    check("AC14 R14-2: %r is not refused" % s_, rc_ == 0 and out_ is not None, (rc_, err_))
# R14-3 character references, any length, real entity names or not
for s_ in ("&#97;", "&#x61;", "&#X61;", "&amp;", "&bogus;", "&#99999999;"):
    rc_, err_, out_, p_ = notes_cli("# Notes\n\n- a %s b (advisor 0130).\n" % s_)
    check("AC14 R14-3: %r is refused" % s_, refused_at(rc_, err_, out_, p_["nn"] + ":3:"), (rc_, err_))
for s_ in ("a & b", "&;", "&#;", "AT&T", "&x"):
    rc_, err_, out_, p_ = notes_cli("# Notes\n\n- %s (advisor 0130).\n" % s_)
    check("AC14 R14-3: %r is not refused" % s_, rc_ == 0 and out_ is not None, (rc_, err_))
# R14-4 the signature delimiter: an entry, an entry whose continuation joins it, a fix field (R14-5), the history (R14-6)
for nrn_, n_ in (("# Notes\n\n- a -----BEGIN x (advisor 0130).\n", 3), ("# Notes\n\n- a -----BEGIN\n  x (advisor 0130).\n", 3)):
    rc_, err_, out_, p_ = notes_cli(nrn_)
    check("AC14 R14-4: '-----BEGIN ' in an entry (%r) is refused" % nrn_, refused_at(rc_, err_, out_, p_["nn"] + ":%d:" % n_), (rc_, err_))
for s_ in ("----BEGIN x", "-----BEGINX"):
    rc_, err_, out_, p_ = notes_cli("# Notes\n\n- a %s (advisor 0130).\n" % s_)
    check("AC14 R14-4: %r is not refused" % s_, rc_ == 0 and out_ is not None, (rc_, err_))
# R14-5 fix sources: each field of a printed fix record, by scan file and JSON key path; the composed line; go.mod; a variant
for key_, path_ in (("id", "matches[0].vulnerability.id"), ("package", "matches[0].artifact.name"),
                    ("installed", "matches[0].artifact.version"), ("severity", "matches[0].vulnerability.severity")):
    for t_ in ("<b>", "[x]:", "&amp;", "-----BEGIN x"):
        f_ = {"id": "CVE-2099-4", "package": "libc6", "installed": "2.36-9", "fixed": "2.36-10", "severity": "Medium", "type": "deb"}
        f_[key_] = "[x]: y" if t_ == "[x]:" else "v %s" % t_
        rc_, err_, out_, p_ = notes_cli(finds=[f_], base=[])
        check("AC14 R14-5: %r in a scan's %s is refused, named by file and key path" % (t_, path_),
              rc_ == 2 and out_ is None and p_["scan"] in err_ and path_ in err_, (rc_, err_))
f_ = dict(R8_FIND[0], id="CVE-1-----BEGIN")
rc_, err_, out_, p_ = notes_cli(finds=[f_])
check("AC14 R14-5: a CVE id 'CVE-1-----BEGIN' forms '-----BEGIN ' in the composed fix line: refused, named by file and record",
      rc_ == 2 and out_ is None and p_["scan"] in err_ and "matches[0]" in err_, (rc_, err_))
rc_, err_, out_, p_ = notes_cli(gomod="module x\n\nrequire golang.org/x/net v0.34.0+a-----BEGIN\n")
check("AC14 R14-5: a go.mod version forming '-----BEGIN ' in the fix line is refused, named by go.mod:line",
      rc_ == 2 and out_ is None and p_["gomod"] + ":3:" in err_, (rc_, err_))
deb_ = [{"id": "CVE-2099-4", "package": "libc6", "installed": "2.36-9", "fixed": "2.36-10&amp;", "severity": "Medium", "type": "deb"}]
rc_, err_, out_, p_ = notes_cli(finds=deb_, base=[])
check("AC14 R14-5: a deb fix version holding a character reference is refused, named by file and key path",
      rc_ == 2 and out_ is None and p_["scan"] in err_ and "matches[0].vulnerability.fix.versions[0]" in err_, (rc_, err_))
rc_, err_, out_, p_ = notes_cli(variant="<b>")
check("AC14 R14-5: a variant name holding '<b>' is refused", rc_ == 2 and out_ is None and "--variant-grype" in err_, (rc_, err_))
unfixed_ = R8_FIND + [{"id": "CVE <b>", "package": "a&amp;", "installed": "v1", "fixed": "v9", "severity": "x", "type": "go-module"}]
rc_, err_, out_, p_ = notes_cli(finds=unfixed_)
check("AC14 R14-5: a finding HEAD does not fix is not printed and not refused", rc_ == 0 and "CVE <b>" not in (out_ or ""), (rc_, err_))
# R14-6 changelog inputs: each form in the new notes' behavior or fix line and in a history line: exit 2, nothing changed
GOOD_NT = P.notes("v0.2.3", fixes, vex, behavior=["Second change (advisor 0130)."])
HIST6 = "# Changelog\n\n## v0.2.2 — patch release\n\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n- no change\n\nNo behavior change: this release contains fixes only.\n"
NN6 = "# Notes\n\n- Second change (advisor 0130).\n- Third change (advisor 0131).\n"
def changelog_cli(nt, hist, nn):
    n_, c_, x_ = r8p("cl-notes.md", nt), r8p("CHANGELOG.md", hist, raw=True), r8p("cl-nn.md", nn)
    if hist is None and os.path.exists(c_):
        os.remove(c_)
    rc_, err_, sout_ = cli(["changelog", "--notes", n_, "--changelog", c_, "--next-notes", x_])
    LAST_STDOUT[0] = sout_
    return rc_, err_, (open(c_, newline="").read() if os.path.exists(c_) else None), open(x_).read(), {"notes": n_, "cl": c_, "nn": x_}
check("AC14 R14-6 control: clean inputs pass", changelog_cli(GOOD_NT, HIST6, NN6)[0] == 0)
for t_ in ("<b>", "[x]: y", "&amp;", "-----BEGIN x"):
    for where_, nt_, hist_, nn_, key_, n_ in (
            ("the new notes' behavior line", GOOD_NT.replace("- Second change (advisor 0130).", "- %s (advisor 0130)." % t_), HIST6, NN6, "notes", 10),
            ("the new notes' fix line", GOOD_NT.replace("- CVE-2099-0001 in", "- %s in" % t_), HIST6, NN6, "notes", 4),
            ("a history behavior line", GOOD_NT, HIST6.replace("No behavior change: this release contains fixes only.",
                                                               "### Behavior changes\n- %s (advisor 0129)." % t_), NN6, "cl", 12),
            ("a next-release-notes line", GOOD_NT, HIST6, NN6 + "- %s (advisor 0132).\n" % t_, "nn", 5)):
        rc_, err_, cl_, nnout_, p_ = changelog_cli(nt_, hist_, nn_)
        check("AC14 R14-6: %r in %s: exit 2, CHANGELOG.md and next-release-notes.md unchanged, file:line named, no stdout" % (t_, where_),
              rc_ == 2 and LAST_STDOUT[0] == "" and cl_ == hist_ and nnout_ == nn_ and "%s:%d:" % (p_[key_], n_) in err_, (rc_, err_))
rc_, err_, cl_, nnout_, p_ = changelog_cli(GOOD_NT.replace("- Second change (advisor 0130).", "- <b> (advisor 0130)."), None, NN6)
check("AC14 R14-6: with no CHANGELOG.md, a refusal creates none", rc_ == 2 and cl_ is None and nnout_ == NN6, (rc_, err_))
# R14-7 (r10, advisor decision Oct 11: no VEX exemption): values printed through _lit hold no refused form ('<' and '&'
# written \u003c and \u0026), so they pass notes, tag-notes and changelog unchanged; the raw text in a behavior line is refused
o7_, n7_ = vd(VS), vd(VS, vs(vulnerability={"name": "<b>"}), vs(vulnerability={"name": "&amp;"}), vs(vulnerability={"name": "[x]: y"}))
nt7_ = refused(P.notes, "v0.2.3", [], P.vex_changes(o7_, n7_))
check("AC14 R14-7 (r10): VEX values '<b>', '&amp;', '[x]: y' print quoted, JSON-escaped, and pass notes, tag-notes and changelog",
      isinstance(nt7_, str) and '`"\\u003cb>"`' in nt7_ and '`"\\u0026amp;"`' in nt7_ and '`"[x]: y"`' in nt7_
      and P.tag_notes(mktag("v0.2.3", nt7_)) == nt7_ and P.changelog(nt7_, None, "")[0] == "# Changelog\n\n" + nt7_, nt7_)
rc_, err_, out_, p_ = notes_cli("# Notes\n\n- `\"<b>\"` (advisor 0130).\n")
check("AC14 R14-7: the same text as a behavior entry is refused", refused_at(rc_, err_, out_, p_["nn"] + ":3:"), (rc_, err_))
mv_ = nt7_.replace("No behavior change: this release contains fixes only.", "### Behavior changes\n- `\"<b>\"` (advisor 0130).")
check("AC14 R14-7: the same text moved to a behavior line of the changelog's notes or a tag's notes is refused",
      str(refused(P.changelog, mv_, None, "")).startswith("ValueError") and str(refused(P.tag_notes, mktag("v0.2.3", mv_))).startswith("ValueError"))
# R14-8 collisions: two entries (or fix records) whose published lines are the same line, refused before any is dropped
rc_, err_, out_, p_ = notes_cli("# Notes\n\n- gpt helper (advisor 0130).\n- claude helper (advisor 0130).\n")
check("AC14 R14-8: two entries that redact to the same published line are refused, both lines named",
      refused_at(rc_, err_, out_, p_["nn"] + ":3:") and p_["nn"] + ":4:" in err_, (rc_, err_))
rc_, err_, out_, p_ = notes_cli("# Notes\n\n- Same change (advisor 0130).\n- Other (advisor 0131).\n- Same change (advisor 0130).\n")
check("AC14 R14-8: two identical bullets are refused", refused_at(rc_, err_, out_, p_["nn"] + ":3:") and p_["nn"] + ":5:" in err_, (rc_, err_))
rc_, err_, out_, p_ = notes_cli("# Notes\n\n- gpt helper (advisor 0130).\n- claude helper (advisor 0130).\n",
                                published="## v0.2.2 — patch release\n\n### Behavior changes\n" + P._entry_line("gpt helper (advisor 0130).") + "\n")
check("AC14 R14-8: one of the two already published: still refused, never one silently dropped", refused_at(rc_, err_, out_, ":4:"), (rc_, err_))
fx8_ = [dict(fixes[0], package="gpt.example/x"), dict(fixes[0], package="claude.example/x")]
check("AC14 R14-8: two fix records printing the same line are refused", str(refused(P.notes, "v0.2.3", fx8_, [])).startswith("ValueError"))
nn8_ = "# Notes\n\n- gpt helper (advisor 0130).\n- claude helper (advisor 0130).\n"
rc_, err_, cl_, nnout_, p_ = changelog_cli(P.notes("v0.2.3", [], [], behavior=["gpt helper (advisor 0130)."]), HIST6, nn8_)
check("AC14 R14-8: the changelog refuses colliding next-release-notes entries before clearing any (exit 2, nothing written)",
      rc_ == 2 and cl_ == HIST6 and nnout_ == nn8_ and p_["nn"] + ":3:" in err_ and p_["nn"] + ":4:" in err_, (rc_, err_))
# R14-9 'already published' by whole line (only trailing whitespace ignored, both sides), never a substring
check("AC14 R14-9: a line that only contains the entry's line does not publish it",
      P.unpublished(["x (advisor 0130)."], "- foo - x (advisor 0130).\n") == ["x (advisor 0130)."])
check("AC14 R14-9: the entry's own line publishes it, trailing space or tab ignored on either side",
      P.unpublished(["x (advisor 0130)."], "- x (advisor 0130). \t\n") == [] and P.unpublished(["x (advisor 0130).  "], "- x (advisor 0130).\n") == [])
rc_, err_, out_, p_ = notes_cli("# Notes\n\n- x (advisor 0130).\t\n- y (advisor 0131).\n", published="## v0.2.2 — patch release\n\n- x (advisor 0130). \n")
check("AC14 R14-9: through the CLI, an entry with a trailing tab in next-release-notes is published by its line with a trailing space",
      rc_ == 0 and "- x (advisor 0130)." not in (out_ or "") and "- y (advisor 0131)." in (out_ or ""), (rc_, err_, out_))
check("AC14 R14-9: interior or leading whitespace differs: not published (shown, never dropped)",
      P.unpublished(["x  y (advisor 0130)."], "- x y (advisor 0130).\n") == ["x  y (advisor 0130)."]
      and P.unpublished(["x (advisor 0130)."], " - x (advisor 0130).\n") == ["x (advisor 0130)."])
_, nn9_ = P.changelog("## v0.2.3 — patch release\n\n### Behavior changes\n- foo - x (advisor 0130).\n", None, "- x (advisor 0130).\n")
check("AC14 R14-9: the changelog keeps an entry whose line the notes only contain", nn9_ == "- x (advisor 0130).\n", nn9_)
_, nn9_ = P.changelog("## v0.2.3 — patch release\n\n### Behavior changes\n- x (advisor 0130). \n", None, "- x (advisor 0130).\t\n- y (advisor 0131).\n")
check("AC14 R14-9: the changelog clears an entry whose whole line the notes published, trailing whitespace ignored",
      nn9_ == "- y (advisor 0131).\n", nn9_)
# R14-10 no false refusal: the real docs/next-release-notes.md, the fixtures
real_nn_ = open(os.path.join(os.path.dirname(sys.argv[1]), "..", "docs", "next-release-notes.md")).read()
rc_, err_, out_, p_ = notes_cli(real_nn_)
check("AC14 R14-10: the real docs/next-release-notes.md passes (Go 1.27 entry printed)", rc_ == 0 and "- Go 1.27: a request" in (out_ or ""), (rc_, err_))
rc_, err_, out_, p_ = notes_cli(NRN)
check("AC14 R14-10: the NRN fixture passes", rc_ == 0 and out_ is not None, (rc_, err_))
rc_, err_, sout_ = cli(["tag-notes"], stdin=tagraw)
check("AC14 R14-10: the tagraw fixture's notes are read (exit 0)", rc_ == 0 and sout_ == pub, (rc_, err_))
# R14-11 message hygiene: a refusal message never prints a vendor name
rc_, err_, out_, p_ = notes_cli("# Notes\n\n- gpt <b> claude helper (advisor 0130).\n")
check("AC14 R14-11: a refusal for an entry holding a vendor name prints no name", rc_ == 2 and out_ is None
      and not re.search(r"(?i)gpt|claude", err_), err_)
# tag-notes: a refused form in a generated patch tag's notes exits 2 (like notes and changelog); another tag exits 1 as before
rc_, err_, sout_ = cli(["tag-notes"], stdin=mktag("v0.2.3", "## v0.2.3 — patch release\n\n### Behavior changes\n- <!-- (advisor 0130).\n"))
check("AC14 tag-notes: a refused form exits 2 with the line named, nothing printed", rc_ == 2 and sout_ == "" and ":4:" in err_, (rc_, err_))
rc_, _, _ = cli(["tag-notes"], stdin="object 1\ntype commit\ntag v0.3.0\ntagger o <o@x> 1 +0000\n\nv0.3.0\n")
check("AC14 tag-notes: an owner's tag still exits 1 (no notes, not a refusal)", rc_ == 1, rc_)
# property: no refused form outside a VEX section can reach the published text (notes, a tag's notes, the changelog)
TRIG_P = ["<b", "</", "<!--", "<?", "<é", "[x]:", "&amp;", "&#97;", "&#x61;", "-----BEGIN ", "-----"]
SAFE_P = ["[x]", " [", "BEGIN ", "<", "&", "[", "]", ":", " ", "a", "gpt", "- ", "> ", "1. ", "\\", "`", "(redacted)", "-"]
rngp_ = random.Random(1414)
def rpiece():
    return rngp_.choice(TRIG_P if rngp_.random() < 0.12 else SAFE_P)
bad_, made_, ref_ = [], 0, 0
for it_ in range(1500):
    ents_ = ["".join(rpiece() for _ in range(rngp_.randint(1, 6))) + " (advisor %04d)." % i for i in range(rngp_.randint(1, 3))]
    pkg_ = "".join(rpiece() for _ in range(rngp_.randint(1, 4)))
    try:
        nt_ = P.notes("v0.2.3", [dict(fixes[0], package=pkg_)], [], behavior=ents_)
    except ValueError:
        ref_ += 1
        continue
    made_ += 1
    outs_ = [nt_, P.tag_notes(mktag("v0.2.3", nt_)) or "", P.changelog(nt_, None, "")[0]]
    for o_ in outs_:
        for l_ in o_.split("\n"):
            if ac14_hit(l_):
                bad_.append((it_, l_))
check("AC14 property: 1500 random notes from fix and entry text built of the refused forms (%d generated, %d refused): no line "
      "of the notes, the tag's notes or the changelog holds a refused form" % (made_, ref_), bad_ == [] and made_ > 100 and ref_ > 100, bad_[:3])
# ===== round 7 findings (Codex #300 r7): each is refused or inert under REQ-REL-009-AC14 and the escape-whole-line rule
A1_ = ["<!-- (advisor 0130).", "gpt helper (advisor 0131)."]
A1_BODY = "## v0.2.3 — patch release\n\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n- no change\n\n### Behavior changes\n- <!-- (advisor 0130).\n- \\(redacted\\) helper \\(advisor 0131\\)\\.\n"
rc_, err_, out_, p_ = notes_cli("# Notes\n\n- <!-- (advisor 0130).\n- gpt helper (advisor 0131).\n")
check("r7 A High / B F3: '- <!-- (advisor 0130).' before another entry: refused by notes() and the CLI (exit 2, line 3), by tag-notes "
      "and by the changelog", str(refused(P.notes, "v0.2.3", [], [], behavior=A1_)).startswith("ValueError")
      and refused_at(rc_, err_, out_, p_["nn"] + ":3:") and str(refused(P.tag_notes, mktag("v0.2.3", A1_BODY))).startswith("ValueError")
      and str(refused(P.changelog, A1_BODY, None, "")).startswith("ValueError"), (rc_, err_))
for l_ in ("-  [(redacted)]: /url", "-  [x]: (redacted)"):
    body_ = "## v0.2.3 — patch release\n\n" + l_ + "\n"
    check("r7 A medium / B F1: %r is refused in a tag's notes, as the changelog's notes and as history" % l_,
          str(refused(P.tag_notes, mktag("v0.2.3", body_))).startswith("ValueError")
          and str(refused(P.changelog, body_, None, "")).startswith("ValueError")
          and str(refused(P.changelog, GOOD_NT, "# Changelog\n\n" + body_, "")).startswith("ValueError"))
check("r7 A medium: notes() refuses the behavior entry ' [redacted]: /url (advisor 0130)'",
      str(refused(P.notes, "v0.2.3", [], [], behavior=[" [redacted]: /url (advisor 0130)"])).startswith("ValueError"))
nt_ = P.notes("v0.2.3", [], [], behavior=["Update gpt (advisor 0130). Follow-up (advisor 0131)."])
_, nn_ = P.changelog(nt_, None, "- Update gpt (advisor 0130).\n")
check("r7 A medium: an entry whose line is only a prefix of a published line stays in next-release-notes",
      nn_ == "- Update gpt (advisor 0130).\n" and P.unpublished(["Update gpt (advisor 0130)."], nt_) == ["Update gpt (advisor 0130)."], nn_)
ntf_ = P.notes("v0.2.3", [], P.vex_changes({"statements": []}, {"statements": [], "x-note- gpt helper (advisor 0130).": 1}))
_, nn_ = P.changelog(ntf_, None, "- gpt helper (advisor 0130).\n")
check("r7 B F2: a VEX field name holding an entry's text neither publishes nor clears the entry",
      P.unpublished(["gpt helper (advisor 0130)."], ntf_) == ["gpt helper (advisor 0130)."] and nn_ == "- gpt helper (advisor 0130).\n", (ntf_, nn_))
nr_ = "## v0.2.3 — patch release\n\nThis record is notredacted.\nNext line.\n"
check("r7 A medium: 'notredacted' is not the marker: two prose lines in a tag's notes read back unchanged; as history they are kept",
      P.tag_notes(mktag("v0.2.3", nr_)) == nr_ and P.changelog(GOOD_NT, "# Changelog\n\n" + nr_, "")[0].endswith(nr_), P.tag_notes(mktag("v0.2.3", nr_)))
y_ = P._clean_free("google\\.notredacted")
check("r7 A medium: a marker-free escaped 'google\\.notredacted' is never read as escaped output: the name is redacted",
      "google" not in y_.lower() and P._clean_free(y_) == y_, y_)
# r7 A low (test oracle): two same-CVE, same-product statements both changed: production prints removed + added; the oracle
# refuses fabricated 'changed' lines that guess the pairing
a7o_ = vd(vs(products=[{"@id": PC}], status_notes="a"), vs(products=[{"@id": PC}], status_notes="b"))
a7n_ = vd(vs(products=[{"@id": PC}], status_notes="a2"), vs(products=[{"@id": PC}], status_notes="b2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(a7o_, a7n_))
ls_ = vlines(nt_)
fab_ = [l.replace("(added)", "(changed: status_notes)") for l in ls_ if "(added)" in l]
fnt_ = nt_.replace("\n".join(ls_), "\n".join(fab_))
check("r7 A low: true removed + added lines resolve; fabricated 'changed: status_notes' lines guessing the pairing are refused",
      resolves(nt_, a7o_, a7n_)[0] and len(fab_) == 2 and fnt_ != nt_ and not resolves(fnt_, a7o_, a7n_)[0], (vex_part(nt_), vex_part(fnt_)))
# ===== round 8 findings (Codex #300 r8; fixed in round 9): each is refused, or no longer falsely refused, under
# REQ-REL-009-AC14 (refuse, don't decode)
def M(id_, pkg, ver, sev="Medium", fixv=(), typ="deb"):
    """one raw grype match"""
    return {"vulnerability": {"id": id_, "severity": sev, "fix": {"versions": list(fixv)}},
            "artifact": {"name": pkg, "version": ver, "type": typ}}
def notes_cli2(scans, nrn="# Notes\n", gomod="module x\n\nrequire golang.org/x/net v0.33.0\n", base=None, published="", sentinel=None):
    """run `notes` on raw grype documents, one per variant ({variant: document}); sentinel: the --out file exists before
    the run holding this text. (rc, stderr, the out file's text or None, the paths: one per variant, nn, gomod, out)"""
    out_ = r8p("notes2.md")
    if os.path.exists(out_):
        os.remove(out_)
    if sentinel is not None:
        open(out_, "w").write(sentinel)
    argv, paths = ["notes", "--version", "v0.2.3"], {}
    for v_, d_ in sorted(scans.items()):
        paths[v_] = r8p("scan2-%d.json" % len(paths), json.dumps(d_, indent=1))
        argv += ["--variant-grype", v_ + "=" + paths[v_]]
    argv += ["--gomod", r8p("go2.mod", gomod), "--vex-old", r8p("o.json", json.dumps(vdoc(("CVE-1", "affected")))),
             "--vex-new", r8p("n.json", json.dumps(vdoc(("CVE-1", "not_affected")))), "--next-notes", r8p("nn2.md", nrn),
             "--published", r8p("pub2.txt", published), "--out", out_]
    if base is not None:
        argv += ["--base-grype", r8p("base2.json", json.dumps({"matches": base}))]
    rc_, err_, sout_ = cli(argv)
    LAST_STDOUT[0] = sout_
    paths.update(nn=r8p("nn2.md"), gomod=r8p("go2.mod"), out=out_)
    return rc_, err_, (open(out_).read() if os.path.exists(out_) else None), paths
def is_ve(x):
    return str(x).startswith("ValueError")
GEN_ = P.notes("v0.2.2", [], [])
GEN_B = P.notes("v0.2.3", [], [], behavior=["x (advisor 0130)."])
# R9-1 (A High / B F1): a VEX section line is exempt only when it is an exact member of the grammar notes() prints for a
# VEX line (each quoted value exactly _lit's form), under a '### VEX' heading at the place the generator writes it
A_HIST = "# Changelog\n\n## v0.2.2 — patch release\n\n### VEX\n- <!--\n\n### Behavior changes\n- Important fix (advisor 0130).\n"
A_HIST2 = "# Changelog\n\n" + GEN_.replace("- no change", "- <!--").replace(
    "No behavior change: this release contains fixes only.", "### Behavior changes\n- Important fix (advisor 0130).")
for what_, h_, n_ in (("A's history (no Fixes section)", A_HIST, 6), ("A's line in a generated-shape history", A_HIST2, 9)):
    rc_, err_, cl_, nnout_, p_ = changelog_cli(GOOD_NT, h_, "- Important fix (advisor 0130).\n")
    check("r9 A High: %s with '- <!--' after '### VEX' is refused (exit 2, line %d named, nothing written, no stdout)" % (what_, n_),
          rc_ == 2 and cl_ == h_ and nnout_ == "- Important fix (advisor 0130).\n" and "%s:%d:" % (p_["cl"], n_) in err_
          and LAST_STDOUT[0] == "", (rc_, err_))
for l_ in ("- <!--", "- [x]: /url", "- &amp;", "- -----BEGIN injected"):
    body_ = GEN_B.replace("- no change", l_)
    tag_rc, tag_err, tag_out = cli(["tag-notes"], stdin=mktag("v0.2.3", body_))
    check("r9 B F1: %r in place of a generated VEX line is refused as the changelog's notes, as history and in a tag's notes "
          "(exit 2, line 7 named, nothing printed)" % l_,
          is_ve(refused(P.changelog, body_, None, "")) and is_ve(refused(P.changelog, GOOD_NT, "# Changelog\n\n" + body_, ""))
          and tag_rc == 2 and tag_out == "" and ":7:" in tag_err, (refused(P.changelog, body_, None, ""), tag_rc, tag_err))
for what_, body_ in (("no Fixes section before it", "## v0.2.3 — patch release\n\n### VEX\n- `\"<b>\"`: fixed (added)\n"),
                     ("a second '### VEX' after the behavior section",
                      GEN_B + "\n### VEX\n- `\"<b>\"`: fixed (added)\n"),
                     ("a heading that is not the generated one", GEN_B.replace("## v0.2.3 — patch release", "## v0.2.3 — release")
                      .replace("- no change", "- `\"<b>\"`: fixed (added)"))):
    check("r9 A High: a '### VEX' heading with %s is not the generated one: its '<b>' line is refused (changelog notes and history)" % what_,
          is_ve(refused(P.changelog, body_, None, "")) and is_ve(refused(P.changelog, GOOD_NT, "# Changelog\n\n" + body_, "")),
          refused(P.changelog, body_, None, ""))
# R9-2 (A medium / B F3): the fix source is the match that produced the fix (the first FIXED match in reading order:
# variants sorted, document order), the same selection fixed_findings prints from
rc_, err_, out_, p_ = notes_cli2({"": {"matches": [M("CVE-2099-5", "libx", "<b>"), M("CVE-2099-5", "libx", "1", fixv=["2"])]}}, base=[])
check("r9 A medium / B F3: matches[0] unfixed (version '<b>'), matches[1] fixed and clean: the notes are written from matches[1]",
      rc_ == 0 and "- CVE-2099-5 in libx: 1 → " in (out_ or ""), (rc_, err_))
rc_, err_, out_, p_ = notes_cli2({"": {"matches": [M("CVE-2099-5", "libx", "1"), M("CVE-2099-5", "libx", "1", sev="&amp;", fixv=["2"])]}}, base=[])
check("r9 A medium / B F3: matches[0] unfixed and clean, matches[1] fixed with '&amp;': refused, named matches[1] by key path",
      refused_at(rc_, err_, out_, p_[""] + ":matches[1].vulnerability.severity"), (rc_, err_))
rc_, err_, out_, p_ = notes_cli2({"": {"matches": [M("CVE-2099-6", "golang.org/x/net", "<b>", fixv=["v9.0.0"], typ="go-module"),
                                                   M("CVE-2099-6", "golang.org/x/net", "v0.30.0", fixv=["v0.33.0"], typ="go-module")]}})
check("r9 A medium: a Go module: an unfixed first match does not block the fixed second", rc_ == 0 and "v0.30.0 → v0.33.0" in (out_ or ""), (rc_, err_))
rc_, err_, out_, p_ = notes_cli2({"": {"matches": [M("CVE-2099-5", "libx", "1")]},
                                  "fips": {"matches": [M("CVE-2099-5", "libx", "1", sev="<b>", fixv=["2"])]}}, base=[])
check("r9 A medium: an unfixed match in the default scan, the fixed one in fips holding '<b>': named by the fips scan",
      refused_at(rc_, err_, out_, p_["fips"] + ":matches[0].vulnerability.severity"), (rc_, err_))
# R9-3 (B medium / A (b)): ONE collision set across every published line (fix, behavior, VEX); a fix record is named by
# its scan file and key path
FXC_ = [{"cve": "CVE-1", "package": "pkg", "old": "1", "new": "2", "severity": "Low", "variants": ["(advisor 0130"]}]
check("r9 B medium / A (b): a fix line and a behavior entry printing the same bullet are refused",
      is_ve(refused(P.notes, "v0.2.3", FXC_, [], behavior=["CVE-1 in pkg: 1 → 2 (severity Low; variants: (advisor 0130)"])),
      refused(P.notes, "v0.2.3", FXC_, [], behavior=["CVE-1 in pkg: 1 → 2 (severity Low; variants: (advisor 0130)"]))
check("r9 B medium: a VEX line and a behavior entry printing the same bullet are refused",
      is_ve(refused(P.notes, "v0.2.3", [], [{"cve": "CVE-1", "status": "fixed", "change": "added", "statement": "statement x (advisor 0130)"}],
                    behavior=["CVE-1: fixed (added) — statement x (advisor 0130)"])))
rc_, err_, out_, p_ = notes_cli2({"(advisor 0130": {"matches": [M("CVE-2099-1", "golang.org/x/net", "v0.30.0", sev="High", fixv=["v0.33.0"], typ="go-module")]}},
                                 nrn="# Notes\n\n- CVE-2099-1 in golang.org/x/net: v0.30.0 → v0.33.0 (severity High; variants: (advisor 0130)\n")
check("r9 B medium: through the CLI, a fix line and an entry colliding are refused, the scan key path and file:line both named",
      refused_at(rc_, err_, out_, p_["(advisor 0130"] + ":matches[0]:") and p_["nn"] + ":3:" in err_, (rc_, err_))
rc_, err_, out_, p_ = notes_cli2({"": {"matches": [M("CVE-2099-7", "gpt.helper", "1", fixv=["2"]), M("CVE-2099-7", "claude.helper", "1", fixv=["2"])]}}, base=[])
check("r9 B F3: two fix records printing the same line are refused, both named by scan file and key path",
      refused_at(rc_, err_, out_, p_[""] + ":matches[0]:") and p_[""] + ":matches[1]:" in err_, (rc_, err_))
# R9-4 (A (c) / B F4): '-----BEGIN ' in the notes region of a generated tag exits 2 naming the line; a tag that is not
# ours still exits 1
for l_ in ("- -----BEGIN BAD", "- -----BEGIN injected (advisor 0130)."):
    rc_, err_, sout_ = cli(["tag-notes"], stdin=mktag("v0.2.3", GEN_B.replace("- x (advisor 0130).", l_)))
    check("r9 A (c) / B F4: %r in a generated tag's notes: exit 2, line 10 named, nothing printed" % l_,
          rc_ == 2 and sout_ == "" and "tag message:10:" in err_, (rc_, err_, sout_))
for what_, raw_ in (("an owner's tag", mktag("v0.2.3", GEN_B.replace("- x (advisor 0130).", "- -----BEGIN BAD")).replace(
                        "fosterstack release <release@users.noreply.github.com>", "Owner <o@x>")),
                    ("an SSH signature last", mktag("v0.2.3", GEN_B.replace("- x (advisor 0130).", "- -----BEGIN BAD")).replace(
                        "SIGNED MESSAGE", "SSH SIGNATURE")),
                    ("another version's heading", mktag("v0.2.4", GEN_B.replace("- x (advisor 0130).", "- -----BEGIN BAD")))):
    rc_, err_, sout_ = cli(["tag-notes"], stdin=raw_)
    check("r9 A (c): %s holding a second '-----BEGIN ' is not ours: exit 1 as before" % what_, rc_ == 1 and sout_ == "", (rc_, err_))
# R9-5 (B F2): every line of a source value is checked before it is made one line
for key_, path_ in (("installed", "matches[0].artifact.version"), ("id", "matches[0].vulnerability.id"), ("severity", "matches[0].vulnerability.severity")):
    m_ = M("CVE-2099-8", "liby", "1", fixv=["2"])
    if key_ == "installed":
        m_["artifact"]["version"] = "safe\n[x]: /url"
    elif key_ == "id":
        m_["vulnerability"]["id"] = "CVE-2099-8\n[x]: /url"
    else:
        m_["vulnerability"]["severity"] = "Low\n[x]: /url"
    rc_, err_, out_, p_ = notes_cli2({"": {"matches": [m_]}}, base=[])
    check("r9 B F2: a scan value whose second line is a reference definition (%s) is refused, named by key path" % path_,
          refused_at(rc_, err_, out_, p_[""] + ":" + path_), (rc_, err_))
rc_, err_, out_, p_ = notes_cli2({"a\n[x]: y": {"matches": [M("CVE-2099-8", "liby", "1", fixv=["2"])]}}, base=[])
check("r9 B F2: a variant name whose second line is a reference definition is refused", refused_at(rc_, err_, out_, "--variant-grype"), (rc_, err_))
check("r9 B F2: notes() refuses a fix field and a behavior entry whose second line is a reference definition",
      is_ve(refused(P.notes, "v0.2.3", [dict(fixes[0], old="v1\n[x]: y")], []))
      and is_ve(refused(P.notes, "v0.2.3", [], [], behavior=["a\n[x]: /u (advisor 0130)."])))
rc_, err_, out_, p_ = notes_cli(gomod="module x\n\nrequire golang.org/x/net v0.33.0 // <b>\n")
check("r9 B F2: the go.mod line a fix is read from is checked whole (a comment holding '<b>'), named go.mod:3",
      refused_at(rc_, err_, out_, p_["gomod"] + ":3:"), (rc_, err_))
# R9-6 (B F5): a marker line that continues the line above (a link title, a code span or any construct spanning lines
# could take it) is refused in a tag's notes and the changelog; a marker line after a blank line or a heading is read
F5_ = "## v0.2.3 — patch release\n\n- [a](/url \"\nx gpt\n\")\n"
check("r9 B F5: B's link title over lines is refused in a tag's notes and as the changelog's notes",
      is_ve(refused(P.tag_notes, mktag("v0.2.3", F5_))) and is_ve(refused(P.changelog, F5_, None, "")),
      (refused(P.tag_notes, mktag("v0.2.3", F5_)), refused(P.changelog, F5_, None, "")))
F5H_ = "# Changelog\n\n" + GEN_.replace("No behavior change: this release contains fixes only.",
                                       "### Behavior changes\n- [a](/url \"\nx \\(redacted\\)\n\")")
check("r9 B F5: the escaped marker line inside a link title is refused as history", is_ve(refused(P.changelog, GOOD_NT, F5H_, "")))
# R9-7 (B F6, the oracle): a 'changed' pairing no identity supports is a guess: refused
F6b_ = vs(drop=("products", "justification", "impact_statement", "action_statement", "status_notes"))
f6o_ = vd(dict(F6b_, status_notes="a"), dict(F6b_, status_notes="a", impact_statement="b"))
f6n_ = vd(dict(F6b_, status_notes="a2"), dict(F6b_, status_notes="a", impact_statement="b2"))
nt_ = P.notes("v0.2.3", [], P.vex_changes(f6o_, f6n_))
fab_ = "- CVE-7: not_affected (changed: status_notes) — statement 1 of the new document\n- CVE-7: not_affected (changed: impact_statement) — statement 2 of the new document"
fnt_ = nt_.replace("\n".join(vlines(nt_)), fab_)
check("r9 B F6: the true removed + added lines resolve; 'changed' lines whose pairing only the field differences single out are refused",
      resolves(nt_, f6o_, f6n_)[0] and fnt_ != nt_ and not resolves(fnt_, f6o_, f6n_)[0], (vex_part(nt_), resolves(fnt_, f6o_, f6n_)))
# R9-8 (B F7): a refusal prints nothing on stdout and leaves a pre-existing --out file as it was; the helpers see stdout
rc_, err_, out_, p_ = notes_cli2({"": {"matches": [M("CVE-2099-5", "libx", "1", sev="<b>", fixv=["2"])]}}, base=[], sentinel="SENTINEL\n")
check("r9 B F7: a notes refusal leaves a pre-existing --out file byte for byte and prints nothing on stdout",
      rc_ == 2 and out_ == "SENTINEL\n" and LAST_STDOUT[0] == "", (rc_, out_, LAST_STDOUT[0]))
orig_main_ = P.main
def noisy_main_(argv=None):
    rc = orig_main_(argv)
    if rc == 2:
        print("UNEXPECTED REFUSAL STDOUT")
    return rc
P.main = noisy_main_
try:
    rc_, err_, out_, p_ = notes_cli("# Notes\n\n- <b> (advisor 0130).\n")
    caught_n = not refused_at(rc_, err_, out_, p_["nn"] + ":3:")
    changelog_cli(GOOD_NT.replace("- Second change (advisor 0130).", "- <b> (advisor 0130)."), HIST6, NN6)
    caught_c = LAST_STDOUT[0] != ""
finally:
    P.main = orig_main_
check("r9 B F7: a main() that prints on a refusal is caught by the notes and changelog helpers", caught_n and caught_c, (caught_n, caught_c))
# ===== round 9 self-review: neighbour mutants of each round-8 family, each refused (or, for selection, judged on the
# match that produced the fix)
# family 1, VEX-section forgeries: a line or heading near the generated VEX section that is not exactly what notes()
# prints is not exempt; each is refused as the changelog's notes, as history, and in a tag's notes (exit 2)
VEXM_ = [("trailing text after a quoted value", GEN_B.replace("- no change", '- `"<b>"`: fixed (added) <!--')),
         ("a bare product holding '<'", GEN_B.replace("- no change", "- CVE-1 [<b>]: fixed (added)")),
         ("a bare field name holding '<'", GEN_B.replace("- no change", "- CVE-1: fixed (changed: <b>)")),
         ("a statement label opening a comment", GEN_B.replace("- no change", "- CVE-1: fixed (added) — statement <!--")),
         ("a document-fields line with a character reference", GEN_B.replace("- no change", "- document fields changed (&amp;)")),
         ("'- no change' with text after it", GEN_B.replace("- no change", "- no change &amp;")),
         ("a status outside OpenVEX's four", GEN_B.replace("- no change", '- `"<b>"`: bogus (added)')),
         ("a code span with a space inside", GEN_B.replace("- no change", '- `"<b>" `: fixed (added)')),
         ("a quoted value not in _lit's spelling ('\\/')", GEN_B.replace("- no change", '- `"<b\\/"`: fixed (added)')),
         ("a quoted value holding '-----BEGIN '", GEN_B.replace("- no change", '- `"-----BEGIN x"`: fixed (added)')),
         ("a VEX line after a blank line in the section", GEN_B.replace("- no change", '- no change\n\n- `"<b>"`: fixed (added)')),
         ("'### VEX ' with a trailing space", GEN_B.replace("### VEX\n- no change", '### VEX \n- `"<b>"`: fixed (added)')),
         ("a Fixes section holding a prose line", GEN_B.replace("- none (dependency or VEX maintenance only)",
                                                                "- none (dependency or VEX maintenance only)\ntext").replace("- no change", '- `"<b>"`: fixed (added)')),
         ("a Fixes section with no bullet", GEN_B.replace("- none (dependency or VEX maintenance only)\n", "").replace("- no change", '- `"<b>"`: fixed (added)'))]
for what_, body_ in VEXM_:
    trc_, terr_, tout_ = cli(["tag-notes"], stdin=mktag("v0.2.3", body_))
    check("r9 self-review VEX forgery: %s is refused as the changelog's notes, as history and in a tag's notes (exit 2, no stdout)" % what_,
          is_ve(refused(P.changelog, body_, None, "")) and is_ve(refused(P.changelog, GOOD_NT, "# Changelog\n\n" + body_, ""))
          and trc_ == 2 and tout_ == "", (refused(P.changelog, body_, None, ""), trc_, terr_))
nt_ = P.notes("v0.2.3", [], P.vex_changes(vd(VS), vd(VS, vs(vulnerability={"name": "<b>"}), vs(vulnerability={"name": "-----BEGIN x"}),
                                                     vs(vulnerability={"name": "gpt <x>"}))))
check("r9 self-review VEX forgery control (r10: printed \\u003c, no refused form on any line): generated VEX lines from '<b>', "
      "a five-hyphen run and a redacted '<x>' pass notes, tag-notes and changelog unchanged", P.tag_notes(mktag("v0.2.3", nt_)) == nt_ and P.changelog(nt_, None, "")[0] == "# Changelog\n\n" + nt_
      and all(P._refused_form(l) is None for l in nt_.splitlines()), vex_part(nt_))
# family 2, collision sets: any two published lines that are the same line — fix, behavior or VEX, after redaction and
# escaping, from the API or the CLI — are refused, both named
FX1_ = {"cve": "CVE-1", "package": "pkg", "old": "1", "new": "2", "severity": "Low", "variants": ["(advisor 0130"]}
ENT1_ = "CVE-1 in pkg: 1 → 2 (severity Low; variants: (advisor 0130)"
COLL_ = [("two identical fix records", [FX1_, dict(FX1_)], []),
         ("two fix records alike after redaction", [dict(FX1_, package="gpt"), dict(FX1_, package="claude")], []),
         ("a fix line and an entry", [FX1_], [ENT1_]),
         ("a fix line and an entry alike after redaction", [dict(FX1_, package="gpt")], [ENT1_.replace("pkg", "claude")]),
         ("a fix line and an entry alike after escaping", [dict(FX1_, package="[click]gpt")], [ENT1_.replace("pkg", "[click]claude")]),
         ("two identical entries", [], ["Same (advisor 0130).", "Same (advisor 0130)."]),
         ("two entries alike after redaction", [], ["gpt helper (advisor 0130).", "claude helper (advisor 0130)."])]
for what_, fx_, beh_ in COLL_:
    check("r9 self-review collision: %s is refused by notes()" % what_, is_ve(refused(P.notes, "v0.2.3", fx_, [], behavior=beh_)),
          refused(P.notes, "v0.2.3", fx_, [], behavior=beh_))
GO1_ = {"(advisor 0130": {"matches": [M("CVE-2099-1", "golang.org/x/net", "v0.30.0", sev="High", fixv=["v0.33.0"], typ="go-module")]}}
ENT_GO = "CVE-2099-1 in golang.org/x/net: v0.30.0 → v0.33.0 (severity High; variants: (advisor 0130)"
rc_, err_, out_, p_ = notes_cli2(GO1_, nrn="# Notes\n\n- %s\n" % ENT_GO.replace("(severity", "\n  (severity"))
check("r9 self-review collision: an entry over two lines joining to a fix line: refused, the key path and the entry line named",
      refused_at(rc_, err_, out_, p_["(advisor 0130"] + ":matches[0]:") and p_["nn"] + ":3:" in err_, (rc_, err_))
rc_, err_, out_, p_ = notes_cli2(GO1_, nrn="# Notes\n\n- %s\n" % ENT_GO, published="## v0.2.2 — patch release\n\n- %s\n" % ENT_GO)
check("r9 self-review collision: a fix line and an entry already published: still refused before the entry is dropped",
      refused_at(rc_, err_, out_, p_["nn"] + ":3:"), (rc_, err_))
rc_, err_, out_, p_ = notes_cli2(GO1_, nrn="# Notes\n\n- Same (advisor 0130).  \n- Same (advisor 0130).\n")
check("r9 self-review collision: two entries differing by trailing spaces: refused, both lines named",
      refused_at(rc_, err_, out_, p_["nn"] + ":3:") and p_["nn"] + ":4:" in err_, (rc_, err_))
# family 3, selection: the source judged is the match that produced the printed record (the first fixed match, variants
# sorted, document order), never an unfixed or later one
SELM_ = [("deb: unfixed '<b>' first, fixed clean second", {"": {"matches": [M("C-1", "l", "<b>"), M("C-1", "l", "1", fixv=["2"])]}}, None),
         ("deb: unfixed clean first, fixed '&amp;' second", {"": {"matches": [M("C-1", "l", "1"), M("C-1", "l", "1", sev="&amp;", fixv=["2"])]}}, ("", 1)),
         ("go: unfixed '<b>' first, fixed clean second", {"": {"matches": [M("C-1", "golang.org/x/net", "<b>", fixv=["v9.0.0"], typ="go-module"),
                                                                           M("C-1", "golang.org/x/net", "v0.30.0", fixv=["v0.33.0"], typ="go-module")]}}, None),
         ("go: unfixed clean first, fixed '<b>' second", {"": {"matches": [M("C-1", "golang.org/x/net", "v0.30.0", fixv=["v9.0.0"], typ="go-module"),
                                                                           M("C-1", "golang.org/x/net", "v0.30.0", sev="<b>", fixv=["v0.33.0"], typ="go-module")]}}, ("", 1)),
         ("unfixed '<b>' in the default scan, fixed clean in fips", {"": {"matches": [M("C-1", "l", "<b>")]},
                                                                      "fips": {"matches": [M("C-1", "l", "1", fixv=["2"])]}}, None),
         ("unfixed clean in the default scan, fixed '<b>' in fips", {"": {"matches": [M("C-1", "l", "1")]},
                                                                      "fips": {"matches": [M("C-1", "l", "1", sev="<b>", fixv=["2"])]}}, ("fips", 0)),
         ("both fixed, the first holding '<b>'", {"": {"matches": [M("C-1", "l", "<b>", fixv=["2"]), M("C-1", "l", "1", fixv=["2"])]}}, ("", 0)),
         ("another CVE's unfixed '<b>' before the fix", {"": {"matches": [M("C-9", "l", "<b>"), M("C-1", "l", "1", fixv=["2"])]}}, None),
         ("the sorted-first variant fixed with '<b>', a later one clean", {"zz": {"matches": [M("C-1", "l", "1", fixv=["2"])]},
                                                                          "aa": {"matches": [M("C-1", "l", "1", sev="<b>", fixv=["2"])]}}, ("aa", 0)),
         ("the sorted-first variant fixed clean, a later one unfixed '<b>'", {"aa": {"matches": [M("C-1", "l", "1", fixv=["2"])]},
                                                                            "zz": {"matches": [M("C-1", "l", "<b>")]}}, None)]
for what_, scans_, want_ in SELM_:
    rc_, err_, out_, p_ = notes_cli2(scans_, base=[])
    if want_ is None:
        ok_ = rc_ == 0 and out_ is not None and "<b>" not in out_
    else:
        ok_ = refused_at(rc_, err_, out_, "%s:matches[%d]" % (p_[want_[0]], want_[1]))
    check("r9 self-review selection: %s: %s" % (what_, "written" if want_ is None else "refused, named matches[%d] of that scan" % want_[1]),
          ok_, (rc_, err_))
rngs_ = random.Random(909)
bad_ = []
for it_ in range(300):
    docs_, rel_ = {}, {}
    for v_ in rngs_.sample(["", "fips", "debug"], rngs_.randint(1, 3)):
        ms_ = [M("C-%d" % rngs_.randint(1, 2), "golang.org/x/net", rngs_.choice(["v0.30.0", "v0.31.0", "v0.32.0"]),
                 sev=rngs_.choice(["Low", "High"]), fixv=[rngs_.choice(["v0.33.0", "v9.0.0"])], typ="go-module") for _ in range(rngs_.randint(1, 4))]
        docs_[v_] = ("scan-%s" % v_, {"matches": ms_})
        rel_[v_] = P.grype_findings(docs_[v_][1])
    head_ = {"go": {"golang.org/x/net": "v0.33.0"}, "base_findings": []}
    fx_ = P.fixed_findings(rel_, head_)
    locs_ = P.check_fix_sources(fx_, docs_, "go.mod", "module x\n\nrequire golang.org/x/net v0.33.0\n", head_)
    for f_, loc_ in zip(fx_, locs_):
        m_ = re.match(r"scan-(\w*):matches\[(\d+)\]:", loc_)
        src_ = docs_[m_.group(1)][1]["matches"][int(m_.group(2))]
        if (src_["artifact"]["version"], src_["vulnerability"]["severity"], src_["vulnerability"]["id"]) != (f_["old"], f_["severity"], f_["cve"]) \
                or src_["vulnerability"]["fix"]["versions"] != ["v0.33.0"]:
            bad_.append((it_, f_, loc_))
check("r9 self-review selection property: 300 random multi-variant scans: every record's judged source is a fixed match whose "
      "values are exactly the printed ones", bad_ == [], bad_[:2])
# family 4, exit codes: a generated tag's notes region holding a refused form exits 2 naming the line; a tag that is not
# ours exits 1; notes and changelog refusals exit 2 with nothing on stdout
SIGB_ = "-----BEGIN SIGNED MESSAGE-----\nMIIabc\n-----END SIGNED MESSAGE-----\n"
EXM_ = [("a behavior line", mktag("v0.2.3", GEN_B.replace("- x (advisor 0130).", "- a -----BEGIN b (advisor 0130).")), 2, ":10:"),
        ("the Fixes line", mktag("v0.2.3", GEN_B.replace("- none (dependency or VEX maintenance only)", "- -----BEGIN x")), 2, ":4:"),
        ("a VEX line", mktag("v0.2.3", GEN_B.replace("- no change", "- -----BEGIN x")), 2, ":7:"),
        ("a prose line", mktag("v0.2.3", GEN_B + "\nsee -----BEGIN x\n"), 2, ":12:"),
        ("a whole second signed block before the real one", mktag("v0.2.3", GEN_B + "\n" + SIGB_), 2, ":12:"),
        ("a second signed block after the real one", mktag("v0.2.3", GEN_B) + SIGB_, 2, ":11:"),
        ("'<b>' in a behavior line", mktag("v0.2.3", GEN_B.replace("- x (advisor 0130).", "- <b> (advisor 0130).")), 2, ":10:"),
        ("a marker line continuing the line above", mktag("v0.2.3", GEN_B + "\n[a](/u \"\nx gpt\n\")\n"), 2, ":13:"),
        ("an owner's tag with two delimiters", (mktag("v0.2.3", GEN_B) + SIGB_).replace("fosterstack release <release@users.noreply.github.com>", "O <o@x>"), 1, None),
        ("the release tagger with an SSH signature last", (mktag("v0.2.3", GEN_B.replace("- x (advisor 0130).", "- -----BEGIN x")))
         .replace("SIGNED MESSAGE", "SSH SIGNATURE"), 1, None),
        ("another version's heading with a delimiter", mktag("v0.2.4", GEN_B.replace("- x (advisor 0130).", "- -----BEGIN x")), 1, None),
        ("no signature at all", mktag("v0.2.3", GEN_B).split("-----BEGIN")[0], 1, None)]
for what_, raw_, want_rc, line_ in EXM_:
    rc_, err_, sout_ = cli(["tag-notes"], stdin=raw_)
    check("r9 self-review exit code: tag-notes, %s: exit %d%s, nothing printed" % (what_, want_rc, ", " + line_ + " named" if line_ else ""),
          rc_ == want_rc and sout_ == "" and (line_ is None or "tag message" + line_ in err_), (rc_, err_, sout_))
rc_, err_, out_, p_ = notes_cli2({"": {"matches": [M("C-1", "l", "1", sev="<b>", fixv=["2"])]}}, base=[])
check("r9 self-review exit code: a notes refusal exits 2, nothing on stdout, no file", refused_at(rc_, err_, out_, p_[""]), (rc_, err_))
rc_, err_, cl_, nnout_, p_ = changelog_cli(GEN_B.replace("- no change", "- <!--"), HIST6, NN6)
check("r9 self-review exit code: a changelog refusal exits 2, nothing on stdout, both files unchanged",
      rc_ == 2 and LAST_STDOUT[0] == "" and cl_ == HIST6 and nnout_ == NN6, (rc_, err_))
# ===== round 9 findings (Codex #300 r9; fixed in round 10 per the advisor decision of Oct 11): (a)(2) a generated VEX line
# is never refused by its own validators (round trip); (2) go.mod is read by a strict parser of its grammar, and the fix
# check judges the very require line the version came from; B (4) two published bullets in one release block of a reader
# input are refused (REQ-REL-009-AC14 (5))
# R10-1 (A (a)(2) / B 3): a CVE name whose printed form changes before the colon (urn:, pkg:, cpe:) is not falsely refused
for name_ in ("urn:x", "pkg:abc", "cpe:a"):
    t_ = refused(P.notes, "v0.2.3", [], P.vex_changes(None, {"statements": [{"vulnerability": {"name": name_}, "status": "fixed"}]}))
    ok_ = not is_ve(t_) and ('- `"%s"`: fixed (added)\n' % name_) in t_
    if ok_:
        tn_ = refused(P.tag_notes, mktag("v0.2.3", t_))
        cl_ = refused(P.changelog, t_, None, "")
        t2_ = P.notes("v0.2.4", [], [])
        cl2_ = refused(P.changelog, t2_, cl_[0], "") if not is_ve(cl_) else cl_
        ok_ = tn_ == t_ and not is_ve(cl_) and not is_ve(cl2_)
    check("r10 A (a)(2) / B 3: the VEX name %r prints and reads back: notes, the tag, the changelog's notes and history" % name_,
          ok_, t_)
# R10-2 the round trip, a property: for 500 random VEX documents vex_changes accepts, notes() prints them (never refused by
# its own validators), and its text passes every reader: the tag's notes byte for byte, the changelog's notes, the history
rng_ = random.Random(1010)
ALPH_ = ["a", "Z", "0", "9", ".", "-", "_", "/", ":", " ", "<", "&", ";", "#", "[", "]", "`", "\"", "\\", "*", "é", " ", "!", "(", ")"]
PREF_ = ["", "", "urn:", "pkg:", "cpe:", "CVE-2099-", "GHSA-", "gpt-", "-----", "http://"]
def rname_():
    return rng_.choice(PREF_) + "".join(rng_.choice(ALPH_) for _ in range(rng_.randint(0, 6)))
def rstmt_():
    s_ = {"vulnerability": {"name": rname_()}, "status": rng_.choice(P.VEX_STATUS)}
    if rng_.random() < 0.5:
        s_["products"] = [{"@id": rname_()} if rng_.random() < 0.7 else {"identifiers": {"purl": rname_()}}
                          for _ in range(rng_.randint(1, 2))]
    if rng_.random() < 0.3:
        s_["@id"] = rname_()
    if rng_.random() < 0.3:
        s_[rng_.choice(["justification", "impact_statement", rname_() or "x"])] = rname_()
    return s_
bad_, made_ = [], 0
for it_ in range(500):
    new_ = {"statements": [rstmt_() for _ in range(rng_.randint(1, 3))]}
    old_ = None if rng_.random() < 0.3 else {"statements": [rstmt_() for _ in range(rng_.randint(0, 2))] + new_["statements"][:1]}
    if old_ is not None and rng_.random() < 0.3:
        old_["version"], new_["version"] = 1, 2
    try:
        vc_ = P.vex_changes(old_, new_)
    except ValueError:
        continue            # a document vex_changes refuses is not printed
    t_ = refused(P.notes, "v0.2.3", [], vc_)
    if is_ve(t_):
        bad_.append((it_, "notes refused its own lines", t_, new_)); continue
    made_ += 1
    tn_, cl_ = refused(P.tag_notes, mktag("v0.2.3", t_)), refused(P.changelog, t_, None, "")
    cl2_ = refused(P.changelog, P.notes("v0.2.4", [], []), cl_[0], "") if not is_ve(cl_) else cl_
    if tn_ != t_ or is_ve(cl_) or is_ve(cl2_):
        bad_.append((it_, tn_ if tn_ != t_ else (cl_ if is_ve(cl_) else cl2_), t_))
check("r10 round trip property: 500 random VEX documents: every one notes() is handed prints, and its text reads back as the "
      "tag's notes byte for byte, as the changelog's notes and as history (%d printed)" % made_, bad_ == [] and made_ > 200, bad_[:2])
# R10-3 (decision (2); A (a)(3) / B 1): go.mod is parsed (its grammar: blocks, single-line directives, '//' comments); the
# version comes from the parsed require directives only, and the fix check reads that same require line, whole
rc_, err_, out_, p_ = notes_cli(gomod="module example.org/test\n// golang.org/x/net v0.33.0\nrequire golang.org/x/net v0.33.0 // <b>\n")
check("r10 B 1: a comment line naming the module above the require line is not the source: the require line holding '<b>' "
      "is refused, named go.mod:3", refused_at(rc_, err_, out_, p_["gomod"] + ":3:"), (rc_, err_))
rc_, err_, out_, p_ = notes_cli(gomod="module example.org/test\n// golang.org/x/net v0.33.0 <b>\nrequire golang.org/x/net v0.33.0\n")
check("r10 B 1: '<b>' in a comment line that is not the require line is not a source: the notes are written",
      rc_ == 0 and "v0.30.0 → v0.33.0" in (out_ or ""), (rc_, err_))
rc_, err_, out_, p_ = notes_cli(gomod="module x\n\nrequire golang.org/x/net v0.33.0\n\nreplace (\n\tgolang.org/x/net v0.33.0 => ../net // <b>\n)\n")
check("r10 A (a)(3): a replace line is not a require: the version and the line judged are the require's (notes written)",
      rc_ == 0 and "v0.30.0 → v0.33.0" in (out_ or ""), (rc_, err_))
gv_ = P.gomod_versions("module x\n\nrequire golang.org/x/net v0.30.0\n\nreplace (\n\tgolang.org/x/net v0.33.0 => ../net\n)\n")
check("r10 A (a)(3): gomod_versions reads the require, never a replace line's left side", gv_.get("golang.org/x/net") == "v0.30.0", gv_)
gv_ = P.gomod_versions("module x\n\nexclude golang.org/x/net v0.33.0\nretract v1.0.0\n")
check("r10: an exclude or retract line gives no version", "golang.org/x/net" not in gv_, gv_)
rc_, err_, out_, p_ = notes_cli(gomod="module x\n\ngo 1.26.6\n\nrequire (\n\tgolang.org/x/sys v0.47.0\n\tgolang.org/x/net v0.33.0 // <b>\n)\n")
check("r10: a require inside a block holding '<b>' is refused, named by its own line go.mod:7",
      refused_at(rc_, err_, out_, p_["gomod"] + ":7:"), (rc_, err_))
rc_, err_, out_, p_ = notes_cli(gomod="module x\n\nrequire golang.org/x/net v0.33.0 //indirect\n")
check("r10: a '//' comment with no space after the version is a comment: the notes are written", rc_ == 0, (rc_, err_))
for gm_, n_, why_ in (("module x\n/* c */\nrequire golang.org/x/net v0.33.0\n", 2, "a /* */ comment"),
                      ("module x\nrequire golang.org/x/net v0.33.0 /* c */\n", 2, "a /* */ comment after a require"),
                      ('module x\nrequire "golang.org/x/net" v0.33.0\n', 2, "a quoted module path"),
                      ("module x\nrequire (\n\tgolang.org/x/net v0.33.0\n", 2, "a block never closed"),
                      ("module x\n)\n", 2, "a ')' outside a block"),
                      ("module x\nrequire golang.org/x/net v0.33.0\nrequire golang.org/x/net v0.34.0\n", 3, "a module required twice"),
                      ("module x\nrequire golang.org/x/net v0.33.0 extra\n", 2, "a require with three words"),
                      ("module x\nrequire golang.org/x/net 0.33.0\n", 2, "a version without its v"),
                      ("module x\nrequire (golang.org/x/net v0.33.0)\n", 2, "a block on one line"),
                      ("module x\nrequire golang.org/x/net\x0bv0.33.0\n", 2, "a vertical tab between the words"),
                      ("module x\nrequire golang.org/x/net v0.33.0  \n", 2, "a line separator"),
                      ("module x\nrequire (\n\trequire golang.org/x/net v0.33.0\n)\n", 3, "a directive inside a block"),
                      ("module x\nrequire (\n)\nrequire (\n\tgolang.org/x/net v0.33.0\n\tgolang.org/x/net v0.33.0\n)\n", 6, "a module twice in blocks")):
    rc_, err_, out_, p_ = notes_cli(gomod=gm_)
    check("r10: go.mod the parser cannot read (%s): refused, named go.mod:%d, nothing written" % (why_, n_),
          refused_at(rc_, err_, out_, p_["gomod"] + ":%d:" % n_), (rc_, err_))
bad_gm_ = r8p("bad.mod", "module x\nrequire (\n")
rc_, err_, sout_ = cli(["removed", "--release-grype", r8p("rel-r10.json", json.dumps({"matches": []})), "--gomod", bad_gm_,
                        "--out", r8p("rm-r10.json")])
check("r10: removed with a go.mod the parser cannot read exits 2 (the workflow reads it as unknown: no at-once cut)",
      rc_ == 2 and bad_gm_ + ":2:" in err_, (rc_, err_))
ROOT_ = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[1])))
for f_ in ("go.mod", "tools/requirements/go.mod"):
    txt_ = open(os.path.join(ROOT_, f_)).read()
    pg_, gv_ = refused(getattr(P, "parse_gomod", lambda *a: {"require": {}}), txt_, f_), refused(P.gomod_versions, txt_)
    lines_ = txt_.splitlines()
    ok_ = not is_ve(pg_) and not is_ve(gv_) and pg_["require"] and all(
        re.match(r"^(require\s+)?%s\s+%s(\s|$)" % (re.escape(m_), re.escape(v_)), lines_[n_ - 1].strip())
        and gv_[m_] == v_ for m_, (v_, n_) in pg_["require"].items())
    check("r10: the repository's %s parses; each require's version and line are the ones the file holds" % f_, ok_, (pg_, gv_))
pg_ = getattr(P, "parse_gomod", lambda *a: {"go": None})(open(os.path.join(ROOT_, "go.mod")).read())
check("r10: the go directive of go.mod is read with its line (stdlib)", pg_["go"] is not None and P.gomod_versions(
    open(os.path.join(ROOT_, "go.mod")).read())["stdlib"] == "go" + pg_["go"][0], pg_["go"])
# R10-4 (B 4): two bullets that publish the same line in one release block of a reader input are refused, both named; the
# same bullet in two release blocks is a legitimate repetition
DUP_ = GEN_B.replace("- x (advisor 0130).\n", "- x (advisor 0130).\n- x (advisor 0130).\n")
rc_, err_, sout_ = cli(["tag-notes"], stdin=mktag("v0.2.3", DUP_))
check("r10 B 4: a generated tag's notes with one behavior bullet twice: exit 2, lines 10 and 11 named, nothing printed",
      rc_ == 2 and sout_ == "" and "tag message:10:" in err_ and "tag message:11:" in err_, (rc_, err_, sout_))
rc_, err_, cl_, nnout_, p_ = changelog_cli(DUP_, HIST6, "# Notes\n\n- x (advisor 0130).\n")
check("r10 B 4: the changelog's notes with one behavior bullet twice: exit 2, both lines named, CHANGELOG.md and "
      "next-release-notes.md unchanged", rc_ == 2 and LAST_STDOUT[0] == "" and cl_ == HIST6 and nnout_ == "# Notes\n\n- x (advisor 0130).\n"
      and p_["notes"] + ":10:" in err_ and p_["notes"] + ":11:" in err_, (rc_, err_))
HDUP_ = "# Changelog\n\n" + DUP_
rc_, err_, cl_, nnout_, p_ = changelog_cli(P.notes("v0.2.4", [], []), HDUP_, NN6)
check("r10 B 4: history with one bullet twice in one release block: exit 2, both lines named, nothing written",
      rc_ == 2 and cl_ == HDUP_ and nnout_ == NN6 and p_["cl"] + ":12:" in err_ and p_["cl"] + ":13:" in err_, (rc_, err_))
HTWO_ = "# Changelog\n\n" + GEN_B + "\n" + P.notes("v0.2.2", [], [], behavior=["x (advisor 0130)."])
rc_, err_, cl_, nnout_, p_ = changelog_cli(P.notes("v0.2.4", [], [], behavior=["x (advisor 0130)."]), HTWO_, NN6)
check("r10 B 4: the same bullet in separate release blocks (new notes and two history releases) is not refused",
      rc_ == 0, (rc_, err_))
# R10-5 (advisor decision (1), option A): no VEX-line exemption. _lit writes '<' and '&' as JSON escapes (\u003c, \u0026),
# so no generated VEX line holds a refused form; notes() checks its whole text; every reader refuses every line
for name_ in ("<b>x", "&amp;", "[x]: y", "-----BEGIN x"):
    t_ = refused(P.notes, "v0.2.3", [], P.vex_changes(None, {"statements": [{"vulnerability": {"name": name_}, "status": "fixed"}]}))
    lit_ = P._lit(name_, before_colon=True)
    ok_ = not is_ve(t_) and all(P._refused_form(l_) is None for l_ in t_.splitlines()) and ("- %s: fixed (added)\n" % lit_) in t_ \
        and json.loads(lit_[1:-1]) == name_
    if ok_:
        rc_, err_, sout_ = cli(["tag-notes"], stdin=mktag("v0.2.3", t_))
        rc2_, err2_, cl_, nnout_, p_ = changelog_cli(sout_, None, "# Notes\n")
        rc3_, err3_, cl3_, _, _ = changelog_cli(P.notes("v0.2.4", [], []), cl_, "# Notes\n") if rc2_ == 0 else (rc2_, err2_, None, None, None)
        ok_ = rc_ == 0 and sout_ == t_ and rc2_ == 0 and rc3_ == 0 and lit_ in (cl3_ or "")
    check("r10 cut: a statement named %r prints JSON-escaped (%s), holds no refused form, and goes notes -> tag-notes -> "
          "changelog (notes, then history) with exit 0" % (name_, P._lit(name_, before_colon=True)), ok_, (t_, locals().get("err_")))
check("r10 cut: _lit writes '<' and '&' as \\u003c and \\u0026 (the same JSON string)",
      P._lit("<b>&") == '`"\\u003cb>\\u0026"`' and json.loads(P._lit("<b>&")[1:-1]) == "<b>&", P._lit("<b>&"))
FORGE_ = [GEN_B.replace("- no change", "- `\"<b>\"`: fixed (added)"), GEN_B.replace("- no change", "- CVE-1: fixed (changed: `\"&amp;\"`)"),
          GEN_B.replace("- no change", "- CVE-1: fixed (changed: `\"<b>\"`)")]
for f_ in FORGE_:
    rc_, err_, sout_ = cli(["tag-notes"], stdin=mktag("v0.2.3", f_))
    rc2_, err2_, cl_, nnout_, p_ = changelog_cli(f_, HIST6, NN6)
    rc3_, err3_, cl3_, nn3_, p3_ = changelog_cli(P.notes("v0.2.4", [], []), "# Changelog\n\n" + f_, NN6)
    check("r10 cut: a hand-forged VEX line %r under '### VEX' is refused by every reader: the tag's notes (line 7), the "
          "changelog's notes and the history, exit 2, nothing written" % f_.splitlines()[6],
          rc_ == 2 and sout_ == "" and "tag message:7:" in err_ and rc2_ == 2 and cl_ == HIST6 and p_["notes"] + ":7:" in err2_
          and rc3_ == 2 and cl3_ == "# Changelog\n\n" + f_ and p3_["cl"] + ":9:" in err3_, (rc_, err_, rc2_, err2_, rc3_, err3_))
    check("r10 cut: the same forged line in docs/next-release-notes.md is refused", is_ve(refused(P.behavior_entries, f_)),
          refused(P.behavior_entries, f_))
check("r10 cut: the exemption code is gone (no _vex_flags, _vex_stmt, _vex_head)",
      not any(hasattr(P, n_) for n_ in ("_vex_flags", "_vex_stmt", "_vex_head")))
# ===== r11 (final verification at ac7e9b0, advisor micro-verification; Codex #300 r10: A 1 Medium + 2 Low, B 4 Medium)
# R11-1 (A Medium / B Medium 2): the duplicate check reads the CLEANED, PUBLISHED line (_clean_free), the source line numbers
# kept: two bullets of one release block that publish the same line once cleaned are refused before anything is written
for what_, body_, n1_, n2_ in (
        ("'- gpt' and '- claude'", GEN_B.replace("- x (advisor 0130).\n", "- gpt\n- claude\n"), 10, 11),
        ("'- CVE-1: fixed (changed: (redacted))' and its escaped spelling",
         GEN_B.replace("- no change\n", "- CVE-1: fixed (changed: (redacted))\n- CVE\\-1\\: fixed \\(changed\\: \\(redacted\\)\\)\n"), 7, 8),
        ("two differently named behavior bullets", GEN_B.replace("- x (advisor 0130).\n", "- gpt (advisor 0130).\n- claude (advisor 0130).\n"), 10, 11)):
    rc_, err_, sout_ = cli(["tag-notes"], stdin=mktag("v0.2.3", body_))
    check("r11 R11-1: a generated tag's notes with %s in one release block: exit 2, lines %d and %d named, nothing printed"
          % (what_, n1_, n2_), rc_ == 2 and sout_ == "" and "tag message:%d:" % n1_ in err_ and "tag message:%d:" % n2_ in err_,
          (rc_, err_, sout_))
    NNP_ = "# Notes\n\n- gpt (advisor 0130).\n"
    rc_, err_, cl_, nnout_, p_ = changelog_cli(body_, HIST6, NNP_)
    check("r11 R11-1: the changelog's notes with %s: exit 2, both lines named, CHANGELOG.md and the pending entry unchanged"
          % what_, rc_ == 2 and LAST_STDOUT[0] == "" and cl_ == HIST6 and nnout_ == NNP_
          and p_["notes"] + ":%d:" % n1_ in err_ and p_["notes"] + ":%d:" % n2_ in err_, (rc_, err_))
    H_ = "# Changelog\n\n" + body_
    rc_, err_, cl_, nnout_, p_ = changelog_cli(P.notes("v0.2.4", [], []), H_, NN6)
    check("r11 R11-1: the history with %s: exit 2, both lines named, nothing written" % what_,
          rc_ == 2 and cl_ == H_ and nnout_ == NN6 and p_["cl"] + ":%d:" % (n1_ + 2) in err_ and p_["cl"] + ":%d:" % (n2_ + 2) in err_,
          (rc_, err_))
OKB_ = GEN_B.replace("- x (advisor 0130).\n", "- gpt x (advisor 0130).\n- gpt y (advisor 0130).\n")
rc_, err_, sout_ = cli(["tag-notes"], stdin=mktag("v0.2.3", OKB_))
check("r11 R11-1 control: two bullets that publish different lines once cleaned are read (exit 0)", rc_ == 0, (rc_, err_))
check("r11 R11-1 control: a raw refused form is still refused on the raw bullet (raw check kept)",
      is_ve(refused(P.tag_notes, mktag("v0.2.3", GEN_B.replace("- x (advisor 0130).", "- <b>gpt (advisor 0130).")))))
# R11-2 (B Medium 1): a document value is redacted BEFORE its JSON encoding: a name right after a character the quoted form
# escapes ('<' -> <, '&' -> &, '`' -> `, '\n' -> \n, a control or non-ASCII character -> \uXXXX) is still
# redacted, and a statement whose name redaction changes is named by its position. Oracle: every value the redactor
# changes when read decoded (that is, as plain text) must lose the name in the printed line
NAMES_ = ("google", "gemini", "claude", "gpt", "openai", "anthropic", "o1", "aws", "Meta", "copilot")
PRE_ = ("<", "&", "`", "\n", "\t", "\x00", "é", " ", "\"", "\\", "-----")
bad_, seen_ = [], 0
for nm_ in NAMES_:
    for pre_ in PRE_:
        v_ = pre_ + nm_
        if P._clean(v_) == v_:
            continue                # not a name as plain text either ('éo1' is one word): nothing to redact
        seen_ += 1
        t_ = refused(P.notes, "v0.2.3", [], P.vex_changes(None, {"statements": [{"vulnerability": {"name": v_}, "status": "fixed"}]}))
        vl_ = [l_ for l_ in str(t_).splitlines() if "fixed" in l_]
        if is_ve(t_) or len(vl_) != 1 or nm_.lower() in vl_[0].lower() or not vl_[0].endswith("statement 1 of the new document"):
            bad_.append((v_, t_))
            continue
        tn_ = refused(P.tag_notes, mktag("v0.2.3", t_))
        cl_ = refused(P.changelog, t_, None, "")
        if tn_ != t_ or is_ve(cl_) or is_ve(refused(P.changelog, P.notes("v0.2.4", [], []), cl_[0], "")):
            bad_.append((v_, "round trip", tn_, cl_))
check("r11 R11-2: a vendor or model name right after an escaped character (%d cases) is redacted in the printed VEX line, "
      "the statement named by its position, and the notes read back as tag, changelog notes and history" % seen_,
      bad_ == [] and seen_ >= len(NAMES_) * len(PRE_) - 1, bad_[:3])
two_ = {"statements": [{"@id": "<google", "vulnerability": {"name": "CVE-5"}, "status": "fixed", "products": [{"@id": "&aws"}]},
                       {"@id": "&o1", "vulnerability": {"name": "CVE-5"}, "status": "affected", "products": [{"@id": "pkg:a"}]}]}
t_ = refused(P.notes, "v0.2.3", [], P.vex_changes(None, two_))
vl_ = [l_ for l_ in str(t_).splitlines() if "CVE" in l_]
check("r11 R11-2: @id labels '<google' / '&o1' and a product '&aws' are redacted; the two statements are named by "
      "position, on distinct lines", not is_ve(t_) and len(vl_) == 2 and len(set(vl_)) == 2
      and not any(w_ in t_.lower() for w_ in ("google", "o1", "aws"))
      and all(re.search(r"statement [12] of the new document$", l_) for l_ in vl_), t_)
od_ = {"statements": [{"vulnerability": {"name": "CVE-6"}, "status": "fixed", "<Google": 1}], "&o2": 1}
nd_ = {"statements": [{"vulnerability": {"name": "CVE-6"}, "status": "fixed", "<Google": 2}], "&o2": 2}
t_ = refused(P.notes, "v0.2.3", [], P.vex_changes(od_, nd_))
check("r11 R11-2: field names '<Google' (statement) and '&o2' (document) are redacted in the printed lines",
      not is_ve(t_) and "google" not in t_.lower() and "o2" not in t_.lower() and P.tag_notes(mktag("v0.2.3", t_)) == t_, t_)
check("r11 R11-2 control: a value without a name still prints its exact JSON string",
      json.loads(P._lit("<b>&x", before_colon=True)[1:-1]) == "<b>&x", P._lit("<b>&x"))
# R11-3 (B Medium 3 / A Low 2): go.mod versions validated as Go validates them (golang.org/x/mod/semver; the go directive
# per modfile's GoVersionRE); supported directives checked; anything else refused naming go.mod:line
pg_ = getattr(P, "parse_gomod")
def gm_refused(text_, n_):
    r_ = refused(pg_, text_, "go.mod")
    return is_ve(r_) and ("go.mod:%d:" % n_) in r_
for v_ in ("v0.34.0-..", "v0.34.0-", "v0.34.0-a..b", "v0.34.0-a.", "v0.34.0-01", "v0.34.0-1.02", "v0.34.0+", "v0.34.0+a..b",
           "v01.2.3", "v1.02.3", "v1.2.03", "v1.2", "v1", "v1.2.3-α", "v1.2.3-a_b", "v١.2.3", "v1.2.3-١",
           "V1.2.3", "v1.2.3.4"):
    check("r11 R11-3: require with version %r is refused, naming go.mod:2" % v_,
          gm_refused("module x\nrequire golang.org/x/net %s\n" % v_, 2), refused(pg_, "module x\nrequire golang.org/x/net %s\n" % v_))
for v_ in ("v1.2.3", "v0.0.0", "v1.2.3-0", "v1.2.3-rc.1", "v0.0.0-20191010083416-a7dc8b61c822", "v1.2.3-x.01a", "v2.0.0+incompatible",
           "v1.2.3-a-b", "v1.2.3+build.5", "v10.20.30"):
    r_ = refused(pg_, "module x\nrequire golang.org/x/net %s\n" % v_)
    check("r11 R11-3: require with version %r is read" % v_, not is_ve(r_) and r_["require"]["golang.org/x/net"] == (v_, 2), r_)
for gv_ in ("0.1", "1", "1.", "1.21.", "01.21", "1.021", "1.21.01", "1.21rc", "1.21-rc1", "v1.21", "go1.21", "1.2١", "1.21RC1", "1.21.0.0"):
    check("r11 R11-3: 'go %s' is refused, naming go.mod:2" % gv_, gm_refused("module x\ngo %s\n" % gv_, 2), refused(pg_, "module x\ngo %s\n" % gv_))
for gv_ in ("1.21", "1.21.0", "1.21rc1", "1.27.2", "1.0", "2.0.1"):
    r_ = refused(pg_, "module x\ngo %s\n" % gv_)
    check("r11 R11-3: 'go %s' is read" % gv_, not is_ve(r_) and r_["go"] == (gv_, 2), r_)
for txt_, n_, why_ in (
        ("module x\ntoolchain 1.21.0\n", 2, "a toolchain without 'go'"), ("module x\ntoolchain go0.1\n", 2, "toolchain go0.1"),
        ("module x\ntoolchain\n", 2, "toolchain with no name"), ("module x\ntoolchain go1.21.0 x\n", 2, "toolchain with two words"),
        ("module x\ntoolchain go1.21.0\ntoolchain go1.21.1\n", 3, "toolchain twice"),
        ("module\n", 1, "module with no path"), ("module a b\n", 1, "module with two words"), ("module a\nmodule b\n", 2, "module twice"),
        ("module (\n\ta\n)\n", 1, "a module block"),
        ("module x\nreplace nonsense\n", 2, "replace nonsense"), ("module x\nreplace a =>\n", 2, "replace with no new path"),
        ("module x\nreplace => ./b\n", 2, "replace with no old path"), ("module x\nreplace a b => ./c\n", 2, "replace old version not a version"),
        ("module x\nreplace a => b.example/c\n", 2, "a module replacement without a version"),
        ("module x\nreplace a v1.0.0 => b.example/c v1\n", 2, "a replacement version not a version"),
        ("module x\nreplace a => ./x v1.0.0\n", 2, "a directory replacement with a version"),
        ("module x\nreplace a => ./x => ./y\n", 2, "replace with two arrows"),
        ("module x\nreplace (\n\tnonsense\n)\n", 3, "replace nonsense in a block"),
        ("module x\nexclude a\n", 2, "exclude without a version"), ("module x\nexclude a 1.0.0\n", 2, "exclude with a bad version"),
        ("module x\nretract\n", 2, "retract with nothing"), ("module x\nretract x\n", 2, "retract a non-version"),
        ("module x\nretract [v1.0.0 v1.0.5]\n", 2, "retract an interval without a comma"),
        ("module x\nretract [v1.0.0, x]\n", 2, "retract an interval with a non-version"),
        ("module x\nretract v1.0.0, v1.0.1\n", 2, "retract with a comma outside an interval"),
        ("module x\ngodebug panicnil\n", 2, "godebug without '='"), ("module x\ngodebug a=1 b=2\n", 2, "godebug with two words"),
        ("module x\ntool\n", 2, "tool with no path"), ("module x\ntool a b\n", 2, "tool with two words"),
        ("module x\nignore\n", 2, "ignore with no path"), ("module x\nfrobnicate a\n", 2, "an unknown directive"),
        ("module x\nfrobnicate (\n)\n", 2, "an unknown block")):
    check("r11 R11-3: %s is refused, naming go.mod:%d" % (why_, n_), gm_refused(txt_, n_), refused(pg_, txt_))
for txt_, why_ in (
        ("module x\ntoolchain go1.21.0\n", "toolchain go1.21.0"), ("module x\ntoolchain default\n", "toolchain default"),
        ("module x\ntoolchain go1.21rc1\n", "toolchain go1.21rc1"),
        ("module x\nreplace a => ./x\n", "a directory replacement"), ("module x\nreplace a v1.0.0 => ../x\n", "a versioned directory replacement"),
        ("module x\nreplace a => /abs/x\n", "a rooted directory replacement"),
        ("module x\nreplace a => b.example/c v1.0.0\n", "a module replacement"),
        ("module x\nreplace a v1.0.0 => b.example/c v1.2.0\n", "a versioned module replacement"),
        ("module x\nreplace (\n\ta => ./x\n\tb v1.0.0 => c.example/d v1.0.1\n)\n", "a replace block"),
        ("module x\nexclude a v1.0.0\n", "exclude"), ("module x\nexclude (\n\ta v1.0.0\n)\n", "an exclude block"),
        ("module x\nretract v1.0.0\n", "retract a version"), ("module x\nretract [v1.0.0, v1.0.5]\n", "retract an interval"),
        ("module x\nretract (\n\tv1.0.0 // why\n\t[v1.1.0, v1.2.0]\n)\n", "a retract block"),
        ("module x\ngodebug panicnil=1\n", "godebug"), ("module x\ngodebug (\n\tdefault=go1.21\n\tpanicnil=1\n)\n", "a godebug block"),
        ("module x\ntool golang.org/x/tools/cmd/stringer\n", "tool"), ("module x\nignore ./node_modules\n", "ignore")):
    r_ = refused(pg_, txt_)
    check("r11 R11-3: %s is read" % why_, not is_ve(r_), r_)
GM_BAD_ = "module example.org/test\nrequire golang.org/x/net v0.34.0-..// indirect\n"
rm_out_ = r8p("rm-r11.json")
if os.path.exists(rm_out_):
    os.remove(rm_out_)
rc_, err_, sout_ = cli(["removed", "--release-grype", r8p("rel-r11.json", json.dumps(gr(R8_FIND))), "--gomod", r8p("bad11.mod", GM_BAD_),
                        "--out", rm_out_])
check("r11 R11-3: removed with 'v0.34.0-..// indirect' exits 2 naming go.mod:2, no output written",
      rc_ == 2 and r8p("bad11.mod") + ":2:" in err_ and not os.path.exists(rm_out_), (rc_, err_))
if os.path.exists(rm_out_):
    os.remove(rm_out_)
rc_, err_, out_, p_ = notes_cli(gomod=GM_BAD_)
check("r11 R11-3: notes with 'v0.34.0-..// indirect' exits 2 naming go.mod:2, nothing written",
      refused_at(rc_, err_, out_, p_["gomod"] + ":2:"), (rc_, err_))
fx_ = [{"cve": "CVE-2099-1", "package": "golang.org/x/net", "old": "v0.30.0", "new": "v0.34.0-..", "severity": "High", "variants": ["default"]}]
r_ = refused(P.check_fix_sources, fx_, {"": ("scan.json", gr(R8_FIND))}, "go.mod", GM_BAD_, {"go": {"golang.org/x/net": "v0.34.0-.."}})
check("r11 R11-3: check_fix_sources refuses that go.mod, naming go.mod:2", is_ve(r_) and "go.mod:2:" in r_, r_)
for txt_, n_ in (("module x\ngo 0.1\n", 2), ("module x\nreplace nonsense\n", 2)):
    rc_, err_, sout_ = cli(["removed", "--release-grype", r8p("rel-r11.json"), "--gomod", r8p("bad11b.mod", txt_), "--out", rm_out_])
    check("r11 R11-3: removed with %r exits 2 naming go.mod:%d, no output" % (txt_, n_),
          rc_ == 2 and r8p("bad11b.mod") + ":%d:" % n_ in err_ and not os.path.exists(rm_out_), (rc_, err_))
    if os.path.exists(rm_out_):
        os.remove(rm_out_)
# R11-4 (B Medium 4 / A Low 3): 'stdlib' is reserved for the toolchain: a require (or any module path) named stdlib is
# refused naming its line; check_fix_sources compares the stdlib fix with the go directive it names
STD_ = "module x\ngo 1.27rc1\nrequire stdlib v1.28.0 // <b>\nreplace stdlib => ./local\n"
check("r11 R11-4: 'require stdlib v1.28.0' is refused, naming go.mod:3", gm_refused(STD_, 3), refused(pg_, STD_))
check("r11 R11-4: 'require stdlib v1.28.0' alone is refused, naming go.mod:2", gm_refused("module x\nrequire stdlib v1.28.0\n", 2))
check("r11 R11-4: 'require (\\n\\tstdlib v1.28.0\\n)' is refused, naming go.mod:3", gm_refused("module x\nrequire (\n\tstdlib v1.28.0\n)\n", 3))
for txt_, n_ in (("module x\nreplace stdlib => ./local\n", 2), ("module x\nexclude stdlib v1.0.0\n", 2), ("module stdlib\n", 1)):
    check("r11 R11-4: the reserved name in %r is refused, naming go.mod:%d" % (txt_, n_), gm_refused(txt_, n_), refused(pg_, txt_))
STDF_ = [{"id": "CVE-2099-7", "package": "stdlib", "installed": "go1.27.0", "fixed": "1.27.1", "severity": "High", "type": "go-module"}]
rc_, err_, sout_ = cli(["removed", "--release-grype", r8p("rel-std.json", json.dumps(gr(STDF_))), "--gomod", r8p("std.mod", STD_),
                        "--out", rm_out_])
check("r11 R11-4: removed with the stdlib requirement exits 2 naming go.mod:3, no output",
      rc_ == 2 and r8p("std.mod") + ":3:" in err_ and not os.path.exists(rm_out_), (rc_, err_))
if os.path.exists(rm_out_):
    os.remove(rm_out_)
rc_, err_, out_, p_ = notes_cli(gomod=STD_, finds=STDF_)
check("r11 R11-4: notes with the stdlib requirement exits 2 naming go.mod:3, nothing written",
      refused_at(rc_, err_, out_, p_["gomod"] + ":3:"), (rc_, err_))
sfx_ = [{"cve": "CVE-2099-7", "package": "stdlib", "old": "go1.27.0", "new": "go1.27.2", "severity": "High", "variants": ["default"]}]
r_ = refused(P.check_fix_sources, sfx_, {"": ("scan.json", gr(STDF_))}, "go.mod", "module x\ngo 1.26.0\n", {"go": {"stdlib": "go1.27.2"}})
check("r11 R11-4: check_fix_sources refuses a stdlib fix go1.27.2 against 'go 1.26.0' (the direct-call invariant)", is_ve(r_), r_)
r_ = refused(P.check_fix_sources, sfx_, {"": ("scan.json", gr(STDF_))}, "go.mod", "module x\ngo 1.27.2\n", {"go": {"stdlib": "go1.27.2"}})
check("r11 R11-4 control: a stdlib fix go1.27.2 against 'go 1.27.2' is judged on go.mod:2", r_ == ["scan.json:matches[0]: go.mod:2:"], r_)
# R11-5 (A compat risk; advisor: keep refusing, a documented limit): a quoted module path stays refused (fail closed)
rc_, err_, sout_ = cli(["removed", "--release-grype", r8p("rel-r11.json"), "--gomod", r8p("q.mod", 'module x\nrequire "golang.org/x/net" v0.33.0\n'),
                        "--out", rm_out_])
check("r11 R11-5: a quoted require path is refused by removed (exit 2, go.mod:2, no output): a documented limit",
      rc_ == 2 and r8p("q.mod") + ":2:" in err_ and not os.path.exists(rm_out_), (rc_, err_))
# ===== r12 (micro-verification at cba7d4c, advisor NARROW CUT; Codex #300 b11, B item 2: the literal marker conversion lost
# statement identity). A VEX value that literally holds a redaction-marker form ('<redacted>', '(redacted)', '\(redacted\)',
# '\<redacted\>', their JSON, HTML-entity and backslash escaped spellings, any case; r13: percent-encoded,
# fullwidth and nested spellings are cut, see CUT_) is REFUSED before any
# redaction (ValueError naming the statement and the field; exit 2, nothing written); the conversion of a literal marker in a
# value is deleted; vendor-name redaction and the position fallbacks are unchanged (REQ-REL-009-AC8, AC14)
# r13 (Codex #300 b12, B Medium: a nested spelling passed the decoder; advisor CUT, Oct 12): the decoding is deleted. The
# refusal covers exactly the forms the printer and the readers recognise, each read ONE way, never nested or iterated:
# the marker as written ('<redacted>', '(redacted)', '\<redacted\>', '\(redacted\)', any case); read once with the Markdown
# backslash escapes undone (what _marked and _clean_free read); read once as a JSON string body (the printer's quoted form:
# <, >, (, ) in any hex case, \\ for a backslash); read once with HTML character references decoded
# (&lt; &gt; &lpar; &rpar;, decimal and hex references). Each delimiter of the marker may be spelled in any one family.
WORDS13_ = ["redacted", "REDACTED", "ReDacted"]
SPELL13_ = {
    "as written": {"<": ["<"], ">": [">"], "(": ["("], ")": [")"]},
    "backslash": {"<": ["<", "\\<"], ">": [">", "\\>"], "(": ["(", "\\("], ")": [")", "\\)"]},
    "json": {"<": ["<", "\\u003c", "\\u003C"], ">": [">", "\\u003e", "\\u003E"], "(": ["(", "\\u0028"], ")": [")", "\\u0029"]},
    "html": {"<": ["<", "&lt;", "&LT;", "&lt", "&#60;", "&#060;", "&#x3c;", "&#X3C;", "&#x003c;"],
             ">": [">", "&gt;", "&GT;", "&gt", "&#62;", "&#x3e;", "&#X3E;"],
             "(": ["(", "&lpar;", "&#40;", "&#x28;"], ")": [")", "&rpar;", "&#41;", "&#x29;"]}}
RECOGNISED_ = sorted({o_ + w_ + c_ for fam_ in SPELL13_.values() for a_, b_ in (("<", ">"), ("(", ")"))
                      for o_ in fam_[a_] for c_ in fam_[b_] for w_ in WORDS13_}
                     | {"\\\\%s%s\\\\%s" % (a_, w_, b_) for a_, b_ in (("<", ">"), ("(", ")")) for w_ in WORDS13_})
# the forms only the deleted decoding read: percent-encoded, compatibility (fullwidth), nested or iterated, the dropped
# \x / \U code escapes, two families mixed in one marker, and the 64-pass limit: NOT refused, printed quoted as before
CUT_ = ["%3Credacted%3E", "%3credacted%3e", "%28redacted%29", "%3CREDACTED%3E", "\uff1credacted\uff1e", "\uff08redacted\uff09",
        "\uff1cREDACTED\uff1e", "&amp;lt;redacted&amp;gt;", "&amp;#60;redacted&amp;#62;", "\\\\u003credacted\\\\u003e",
        "\\u0026lt;redacted\\u0026gt;", "%253Credacted%253E", "&#37;3Credacted&#37;3E", "\\u00253Credacted\\u00253E",
        "%EF%BC\\x259Credacted%EF%BC\\x259E", "%EF%BC\\u00259Credacted%EF%BC\\u00259E",
        "%EF%BC\\U000000259Credacted%EF%BC\\U000000259E", "%EF%BC\\x2588redacted%EF%BC\\x2589", "\\x3credacted\\x3e",
        "\\U0000003credacted\\U0000003e", "\\u003credacted&gt;", "&lt;redacted\\u003e", "&#xff1c;redacted&#xff1e;",
        "\\uff1credacted\\uff1e", "&" + "amp;" * 64, "&" + "amp;" * 64 + "lt;redacted&gt;"]
FORMS_ = RECOGNISED_
def vex_cli(old_doc, new_doc):
    """run `notes` with these VEX documents; (rc, stderr, the out file's text or None)"""
    out_ = r8p("notes12.md")
    if os.path.exists(out_):
        os.remove(out_)
    argv = ["notes", "--version", "v0.2.3", "--variant-grype", "=" + r8p("scan12.json", json.dumps(gr(R8_FIND))),
            "--gomod", r8p("go12.mod", "module x\n\nrequire golang.org/x/net v0.33.0\n"),
            "--vex-new", r8p("n12.json", json.dumps(new_doc)), "--next-notes", r8p("nn12.md", "# Notes\n"),
            "--published", r8p("pub12.txt", ""), "--out", out_]
    if old_doc is not None:
        argv += ["--vex-old", r8p("o12.json", json.dumps(old_doc))]
    rc_, err_, sout_ = cli(argv)
    return rc_, err_, (open(out_).read() if os.path.exists(out_) else None), sout_
# R12-1 B's exact reproducer: two statements of CVE-1 with @id '<redacted>' and '(redacted)'; the first one's status changes
import copy
old_ = {"statements": [{"@id": "<redacted>", "vulnerability": {"name": "CVE-1"}, "status": "affected"},
                       {"@id": "(redacted)", "vulnerability": {"name": "CVE-1"}, "status": "fixed"}]}
new_ = copy.deepcopy(old_)
new_["statements"][0]["status"] = "fixed"
r_ = refused(P.vex_changes, old_, new_)
check("r12 R12-1 (B item 2 reproducer): vex_changes refuses @id '<redacted>' / '(redacted)', naming the statement and @id",
      is_ve(r_) and "statement 1" in r_ and "@id" in r_ and "marker" in r_, r_)
rc_, err_, out_, sout_ = vex_cli(old_, new_)
check("r12 R12-1: notes with B's reproducer exits 2, nothing written, nothing on stdout, the statement and field named",
      rc_ == 2 and out_ is None and sout_ == "" and "statement 1" in err_ and "@id" in err_ and "no notes, no patch" in err_,
      (rc_, err_, out_))
for nm_ in ("<redacted>", "(redacted)"):
    d_ = {"statements": [{"vulnerability": {"name": nm_}, "status": "affected"}, {"vulnerability": {"name": "CVE-2"}, "status": "fixed"}]}
    rc_, err_, out_, sout_ = vex_cli(None, d_)
    check("r12 R12-1: a vulnerability name %r is refused (exit 2, nothing written, statement 1 and vulnerability.name named)" % nm_,
          rc_ == 2 and out_ is None and "statement 1" in err_ and "vulnerability.name" in err_, (rc_, err_))
# R12-2 every marker form in every field (both documents), named by statement and field; the printer refuses it too
def put_(form, field):
    """a document holding form in field (statement 2 for a statement field; the document itself for a document field)"""
    s_ = {"vulnerability": {"name": "CVE-3"}, "status": "fixed", "products": [{"@id": "pkg:a"}]}
    if field == "vulnerability.name":
        s_["vulnerability"]["name"] = form
    elif field == "@id":
        s_["@id"] = form
    elif field == "products[1].@id":
        s_["products"] = [{"@id": form}]
    elif field == "products[1].subcomponents[1].@id":
        s_["products"] = [{"@id": "pkg:a", "subcomponents": [{"@id": form}]}]
    elif field.startswith("products[1].identifiers."):
        s_["products"] = [{"identifiers": {field.rsplit(".", 1)[1]: form}}]
    elif field == "a field name":
        s_[form] = 1
    d_ = {"statements": [{"vulnerability": {"name": "CVE-2"}, "status": "fixed"}, s_]}
    if field == "a document field name":
        d_[form] = 1
    return d_
FIELDS_ = ["vulnerability.name", "@id", "products[1].@id", "products[1].subcomponents[1].@id", "products[1].identifiers.purl",
           "products[1].identifiers.cpe23", "products[1].identifiers.cpe22", "a field name", "a document field name"]
bad_, n_ = [], 0
for f_ in FORMS_:
    for emb_ in ("%s", "pkg:x%sy", "%sgpt", "CVE-1 %s"):
        v_ = emb_ % f_
        for fl_ in FIELDS_:
            for side_ in ("new", "old"):
                n_ += 1
                d_ = put_(v_, fl_)
                r_ = refused(P.vex_changes, d_, put_("ok", fl_)) if side_ == "old" else refused(P.vex_changes, None, d_)
                want_ = ("VEX %s document: " % side_) + ("a document field name" if fl_ == "a document field name"
                                                         else "statement 2: %s" % fl_)
                if not (is_ve(r_) and want_ in r_ and "marker" in r_):
                    bad_.append((v_, fl_, side_, r_))
        r_ = refused(P._lit, v_)
        if not is_ve(r_):
            bad_.append((v_, "_lit", r_))
        for vc_ in ([{"cve": v_, "status": "fixed", "change": "added"}], [{"document": [v_]}]):
            r_ = refused(P.notes, "v0.2.3", [], vc_)
            if not is_ve(r_):
                bad_.append((v_, "notes", r_))
check("r12 R12-2: every marker form (%d forms, 4 embeddings) in every field (%d) of either document is refused, naming the "
      "document, the statement and the field (%d cases); the printer (_lit) and notes() refuse it too"
      % (len(FORMS_), len(FIELDS_), n_), bad_ == [] and n_ == len(FORMS_) * 4 * len(FIELDS_) * 2, bad_[:3])
for f_ in ["<redacted>", "(redacted)", "\\(redacted\\)", "\\<redacted\\>", "<REDACTED>", "(Redacted)"]:
    rc_, err_, out_, sout_ = vex_cli(None, put_(f_, "products[1].subcomponents[1].@id"))
    check("r12 R12-2: notes with %r as a subcomponent @id exits 2, nothing written, named" % f_,
          rc_ == 2 and out_ is None and sout_ == "" and "statement 2: products[1].subcomponents[1].@id" in err_, (rc_, err_))
# R12-3 the deleted conversion: no VEX value is ever rewritten into the marker by the printer except where the code writes
# the redaction of a vendor or model name; values that are not marker forms print exactly as before (the pre-cut printer)
def old_lit_(v, before_colon=False):
    v = str(v)
    if P.BARE.match(v) and not P.NOT_BARE.search(v + (":" if before_colon else "")):
        return v
    return span_of(v)
TOK_ = ["gpt", "google", "aws", "o1", "Claude", "<", ">", "(", ")", "redacted", "redact", "ed", "&", ";", "lt", "\\", "u003c",
        "-", "a", "é", " ", "`", "%", "3C", "#", "x", ".", "/", ":"]
rng12_ = random.Random(1212)
bad_, acc_, ref_ = [], 0, 0
for _ in range(4000):
    v_ = "".join(rng12_.choice(TOK_) for _ in range(rng12_.randint(0, 7)))
    if rng12_.random() < 0.15:
        i_ = rng12_.randint(0, len(v_))
        v_ = v_[:i_] + rng12_.choice(FORMS_) + v_[i_:]
    elif rng12_.random() < 0.12:                     # r13: a cut form prints exactly as the pre-cut printer printed it
        i_ = rng12_.randint(0, len(v_))
        v_ = v_[:i_] + rng12_.choice(CUT_) + v_[i_:]
    for bc_ in (False, True):
        r_ = refused(P._lit, v_, before_colon=bc_)
        if is_ve(r_):
            ref_ += 1
            continue
        acc_ += 1
        if r_ != old_lit_(v_, bc_) or any(m_ in v_.lower() for m_ in ("<redacted>", "(redacted)")):
            bad_.append((v_, bc_, r_, old_lit_(v_, bc_)))
check("r12 R12-3: 4000 random values (%d printed, %d refused): every printed value is byte-identical to the pre-cut printer "
      "(vendor and model names redacted as before), and none holding a literal marker is printed" % (acc_, ref_),
      bad_ == [] and acc_ > 4000 and ref_ > 600, bad_[:3])
check("r12 R12-3: a vendor name is still redacted to the visible marker in a quoted value ('<google' -> \"\\u003c(redacted)\")",
      P._lit("<google") == '`"\\u003c(redacted)"`' and P._lit("x gpt") == '`"x (redacted)"`', (P._lit("<google"), P._lit("x gpt")))
check("r12 R12-3: 'redacted' alone, 'redacted>' and '<redacted' are not marker forms: printed as before",
      all(P._lit(v_) == old_lit_(v_) for v_ in ("redacted", "redacted>", "<redacted", "(redacted", "redacted)", "<redacted)")),
      [P._lit(v_) for v_ in ("redacted", "<redacted)")])
# R12-4 the multi-statement fixture document (the retired real one): the notes are byte-identical to the pre-cut printer's in every scenario
REAL12_ = json.load(open(os.path.join(os.path.dirname(sys.argv[1]), "..", "test-evidence", "vex-scope", "busybox.openvex.json")))
def real_scenarios_():
    out_ = [P.notes("v0.2.3", [], P.vex_changes(None, REAL12_))]
    for i_ in range(len(REAL12_["statements"])):
        o_ = copy.deepcopy(REAL12_); s_ = o_["statements"][i_]
        s_["status"] = "affected" if s_["status"] != "affected" else "fixed"
        out_.append(P.notes("v0.2.3", [], P.vex_changes(o_, REAL12_)))
        o_ = copy.deepcopy(REAL12_); del o_["statements"][i_]
        out_.append(P.notes("v0.2.3", [], P.vex_changes(o_, REAL12_)))
        o_ = copy.deepcopy(REAL12_); o_["statements"][i_]["impact_statement"] = "x"; o_["version"] = 0
        out_.append(P.notes("v0.2.3", [], P.vex_changes(o_, REAL12_)))
    return out_
now_ = refused(real_scenarios_)
real_lit_ = P._lit
P._lit = old_lit_
try:
    was_ = refused(real_scenarios_)
finally:
    P._lit = real_lit_
check("r12 R12-4: the multi-statement fixture document's notes (%d scenarios) are byte-identical to the pre-cut printer's"
      % (len(now_) if isinstance(now_, list) else 0), isinstance(now_, list) and now_ == was_ and len(now_) > 4, (now_, was_))
# R12-5 the round trip property with marker forms: random documents whose printed values sometimes hold a marker form are
# refused exactly then (naming the statement or document field); every other one prints and reads back as before
rng13_ = random.Random(1313)
def rn12_(hit_):
    v_ = rng13_.choice(PREF_) + "".join(rng13_.choice(ALPH_) for _ in range(rng13_.randint(0, 6)))
    if rng13_.random() < 0.06:
        i_ = rng13_.randint(0, len(v_))
        v_ = v_[:i_] + " " + rng13_.choice(FORMS_) + " " + v_[i_:]   # r13: set apart, so no neighbour respells it
        hit_.append(v_)
    elif rng13_.random() < 0.04:                     # r13: a cut form is an ordinary value: printed, read back
        i_ = rng13_.randint(0, len(v_))
        v_ = v_[:i_] + " " + rng13_.choice(CUT_) + " " + v_[i_:]
    return v_
def rs12_(hit_):
    s_ = {"vulnerability": {"name": rn12_(hit_)}, "status": rng13_.choice(P.VEX_STATUS)}
    if rng13_.random() < 0.5:
        s_["products"] = [{"@id": rn12_(hit_)} if rng13_.random() < 0.7 else {"identifiers": {"purl": rn12_(hit_)}}
                          for _ in range(rng13_.randint(1, 2))]
    if rng13_.random() < 0.3:
        s_["@id"] = rn12_(hit_)
    if rng13_.random() < 0.3:
        s_[rn12_(hit_) or "x"] = "v"
    return s_
bad_, made_, refd_ = [], 0, 0
for it_ in range(500):
    hit_ = []
    new_ = {"statements": [rs12_(hit_) for _ in range(rng13_.randint(1, 3))]}
    old_ = None if rng13_.random() < 0.3 else {"statements": [rs12_(hit_) for _ in range(rng13_.randint(0, 2))] + new_["statements"][:1]}
    vc_ = refused(P.vex_changes, old_, new_)
    if hit_:
        refd_ += 1
        if not (is_ve(vc_) and "marker" in vc_ and re.search(r"VEX (old|new) document: statement \d+: ", vc_)):
            bad_.append((it_, "a marker form not refused", hit_, vc_))
        continue
    if is_ve(vc_):
        if "marker" in vc_:                      # r13: no other value (a cut form included) is a marker form
            bad_.append((it_, "a value that is not a recognised marker form refused", vc_))
        continue
    t_ = refused(P.notes, "v0.2.3", [], vc_)
    if is_ve(t_):
        bad_.append((it_, "notes refused its own lines", t_)); continue
    made_ += 1
    tn_, cl_ = refused(P.tag_notes, mktag("v0.2.3", t_)), refused(P.changelog, t_, None, "")
    if tn_ != t_ or is_ve(cl_):
        bad_.append((it_, tn_, cl_))
check("r12 R12-5: 500 random VEX documents (%d holding a marker form, %d printed): a marker form in any printed value is "
      "refused naming its statement; every other document prints and reads back as the tag's notes and changelog"
      % (refd_, made_), bad_ == [] and refd_ > 50 and made_ > 200, bad_[:2])
# ===== r13 (Codex #300 b12, B Medium; advisor CUT, Oct 12): the decoding is deleted; the refusal covers the recognised forms
# only (RECOGNISED_ above, refused in every field by R12-2); every cut form is an ordinary value: not refused, printed quoted
check("r13 R13-1: the recognised forms are derived per family (%d spellings: as written, backslash, JSON, HTML; any case)"
      % len(RECOGNISED_), len(RECOGNISED_) > 250 and "\\(redacted\\)" in RECOGNISED_ and "&#x3c;REDACTED&gt" in RECOGNISED_
      and "\\u0028ReDacted)" in RECOGNISED_ and "\\\\(redacted\\\\)" in RECOGNISED_, len(RECOGNISED_))
bad_, n_ = [], 0
for f_ in CUT_:
    for emb_ in ("%s", "pkg:x%sy", "%sgpt", "CVE-1 %s"):
        v_ = emb_ % f_
        for fl_ in FIELDS_:
            for side_ in ("new", "old"):
                n_ += 1
                d_ = put_(v_, fl_)
                r_ = refused(P.vex_changes, d_, put_("ok", fl_)) if side_ == "old" else refused(P.vex_changes, None, d_)
                if is_ve(r_):
                    bad_.append((v_, fl_, side_, r_))
        for bc_ in (False, True):
            r_ = refused(P._lit, v_, before_colon=bc_)
            if r_ != old_lit_(v_, bc_) or not r_.startswith("`"):
                bad_.append((v_, "_lit", bc_, r_, old_lit_(v_, bc_)))
        t_ = refused(P.notes, "v0.2.3", [], [{"cve": v_, "status": "fixed", "change": "added"}])
        if is_ve(t_) or (P._lit(v_, before_colon=True) not in t_ and "gpt" not in v_) \
                or refused(P.tag_notes, mktag("v0.2.3", t_)) != t_ or is_ve(refused(P.changelog, t_, None, "")):
            bad_.append((v_, "notes", t_))
check("r13 R13-2: every cut form (%d: percent-encoded, fullwidth, nested, \\x / \\U escapes, mixed families, the 64-pass "
      "limit, B's '%%EF%%BC\\x259Credacted...'), 4 embeddings, in every field of either document (%d cases) is NOT refused; "
      "the printer quotes it byte-identical to the pre-cut printer; the notes print it and read back" % (len(CUT_), n_),
      bad_ == [] and n_ == len(CUT_) * 4 * len(FIELDS_) * 2, bad_[:3])
B12_ = "%EF%BC\\x259Credacted%EF%BC\\x259E"
rc_, err_, out_, sout_ = vex_cli(None, {"statements": [{"vulnerability": {"name": B12_}, "status": "fixed"}]})
check("r13 R13-2: B's b12 document (vulnerability name %r) is not refused: exit 0, the notes print it quoted" % B12_,
      rc_ == 0 and out_ is not None and P._lit(B12_, before_colon=True) == '`"%EF%BC\\\\x259Credacted%EF%BC\\\\x259E"`'
      and P._lit(B12_, before_colon=True) in out_, (rc_, err_, out_))
for f_ in ("&lt;redacted&gt;", "\\u003credacted>", "\\(redacted\\)", "&#40;REDACTED&#41;", "\\\\<redacted\\\\>"):
    rc_, err_, out_, sout_ = vex_cli(None, put_(f_, "products[1].identifiers.purl"))
    check("r13 R13-3: notes with the recognised form %r as an identifier exits 2, nothing written, named" % f_,
          rc_ == 2 and out_ is None and sout_ == "" and "statement 2: products[1].identifiers.purl" in err_, (rc_, err_))
def names_(c):
    """every global name a function's code uses, nested generator code included"""
    out = set(c.co_names)
    for k in c.co_consts:
        if hasattr(k, "co_names"):
            out |= names_(k)
    return out


# ===== r14 (Codex #300 b13, B Medium; advisor (c), Oct 12): the readers recognise exactly what the refusal refuses: one
# definition of the readings (_readings) used by _marker_form and _marked; the own-form check (_own_form) reads a line once
bad_, n_ = [], 0
for a_ in ("", "\\", "\\\\", "\\\\\\"):
    for b_ in ("", "\\", "\\\\", "\\\\\\"):
        for c_ in ("(redacted)", "(REDACTED)", "<redacted>"):
            seed_ = "%s%s%s%s" % (a_, c_[:1], c_[1:-1], b_ + c_[-1])
            v1_ = P._clean_free(seed_)
            for t_ in (seed_, v1_, P._clean_free(v1_)):
                n_ += 1
                if (P._marked(t_) or P._own_form(t_)) and not P._marker_form(t_):
                    bad_.append((seed_, t_))
check("r14 R14-1: every string a reader recognises as the marker or as its own form is refused by _marker_form (%d "
      "seeds and their cleaned forms, B's b13 seed '(redacted\\)' among them)" % n_, bad_ == [] and n_ > 90, bad_[:3])
b13_ = P._clean_free("(redacted\\)")
check("r14 R14-2: B's b13 value %r is not read as the printer's own form and is covered or not recognised" % b13_,
      not P._own_form(b13_) and (not P._marked(b13_) or P._marker_form(b13_)), b13_)
check("r14 R14-3: the refusal and the readers share one definition of the readings (_readings)",
      names_(P._marker_form.__code__) >= {"_readings"} and names_(P._marked.__code__) >= {"_readings"}
      and "_own_form" in names_(P._clean_free.__code__), None)
shutil.rmtree(r8_)
# --- REQ-REL-009-AC15 (advisor 0254, 0257; text approved in #212): the auditor's own data and .vex/README.md are neutral, only as data
def ac15_():
    # neutral-path commits carry the data they commit: a neutral path is neutral only when the committed content is data
    def nc(f, body=None, mode="100644", old_mode=None, labels=()):
        body = body if body is not None else ("{}\n" if f.endswith(".json") else "# notes\n")
        d = dict(c("n", [f], labels=labels, diffs={f: "".join("+%s\n" % l for l in body.split("\n")[:-1])} if mode != "000000" else {f: ""}), modes={f: mode})
        old_mode = old_mode or ("100644" if mode != "000000" else None)
        if old_mode:
            d["old_modes"] = {f: old_mode}
        d["contents"] = {f: {"old": None if old_mode in (None, "000000") else "# notes\n", "new": None if mode == "000000" else body}}
        return d
    VEXF = ".vex/fosterstack-cache.openvex.json"
    VEXC = c("v1", [VEXF])
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
        for bad in ("#!/bin/sh\necho x\n",):
            check("AC15 git: a new %s holding %r is not data: dirty" % (path, bad[:12]), verdict_new(path, bad) == "dirty", verdict_new(path, bad))
        for odd in ("{", "3\n", "null\n", "", "print('x')\n"):
            check("AC15 git: a new %s holding %r is data (AC15 names scripts, executables and shebang lines, not content shapes): neutral" % (path, odd[:12]), verdict_new(path, odd) == "neutral", verdict_new(path, odd))
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
    SHEBANG_SCRIPT = "#!/bin/sh\necho run\n"
    PY_NO_SHEBANG = "import os\nprint(os.getcwd())\n\ndef main():\n    pass\n"
    for path in (KN, RD):
        got = verdict_new(path, PY_NO_SHEBANG)
        check("AC15 git: %s holding script-looking text without any shebang line is data (neutral, documented rule)" % path, got == "neutral", got)
        for label, body in (("a shebang after a comment line", "# a comment\n#!/bin/sh\necho x\n"), ("a shebang in the middle", "intro\ntext\n#!/usr/bin/env python3\nmore\n"),
                            ("a shebang on the last line", "text\n#!/bin/sh")):
            got = verdict_new(path, body)
            check("AC15 git: a new %s with %s is dirty" % (path, label), got == "dirty", got)
        base = dict(BASE0, **{path: (SHEBANG_SCRIPT, "100644")})
        got = verdict_(base, lambda r_, path=path: os.remove(os.path.join(r_, path)))[0][0]
        check("AC15 git: deleting %s whose removed lines hold a shebang line is dirty" % path, got == "dirty", got)
        got = verdict_(base, lambda r_, path=path: put_(r_, {path: ("ordinary text now\nnothing else\n", "100644")}))[0][0]
        check("AC15 git: replacing the shebang script %s by ordinary text is dirty (the removed lines held a shebang)" % path, got == "dirty", got)
        got = verdict_(base, lambda r_, path=path: put_(r_, {path: ("ordinary text now\nnothing else\n", "100644")}), labels=("patch-fix",))[0][0]
        check("AC15 git: the patch-fix label does not clear the replacement of the shebang script %s" % path, got == "dirty", got)
        got = verdict_(base, lambda r_, path=path: os.remove(os.path.join(r_, path)), labels=("patch-fix",))[0][0]
        check("AC15 git: the patch-fix label does not clear the deletion of the shebang script %s" % path, got == "dirty", got)
        got = verdict_(dict(BASE0, **{path: (PY_NO_SHEBANG, "100644")}), lambda r_, path=path: os.remove(os.path.join(r_, path)))[0][0]
        check("AC15 git: deleting a text file with script-looking lines but no shebang is neutral", got == "neutral", got)
        big = "#!/bin/sh\n" + "".join("line %d\n" % i for i in range(150000))
        bigger = big.replace("line 140000\n", "line 140000 edited\n")
        got = verdict_(dict(BASE0, **{path: (big, "100644")}), lambda r_, path=path: put_(r_, {path: (bigger, "100644")}))[0][0]
        check("AC15 git: %s of 150k lines with an unchanged shebang first line, edited far from line 1, is dirty" % path, got == "dirty", got)
        bigt = "plain\n" + "".join("line %d\n" % i for i in range(150000))
        got = verdict_(dict(BASE0, **{path: (bigt, "100644")}), lambda r_, path=path: put_(r_, {path: (bigt.replace("line 140000\n", "line 140000 edited\n"), "100644")}))[0][0]
        check("AC15 git: the same 150k-line file without a shebang is neutral", got == "neutral", got)
    D = P.decide("schedule", [verdict_(dict(BASE0, **{KN: (SHEBANG_SCRIPT, "100644")}), lambda r_: os.remove(os.path.join(r_, KN)))[1], VEXC], ["v0.2.1"], cut_today=False, removed=None)
    check("AC15 a deleted shebang script named like a neutral file beside a VEX change blocks the patch", not D["cut"] and D["not_clean"], D)
    # fail closed on missing evidence about the OLD file (Codex #425 r1, seat B, P2): a neutral path is data only when its old and new file types are known and every blob that exists was read
    check("AC15 unit: a replacement without the old file type is dirty", P.classify(dict(nc(PS), old_modes={}))[0] == "dirty")
    check("AC15 unit: a replacement whose old file type is a submodule (160000) is dirty", P.classify(nc(PS, old_mode="160000"))[0] == "dirty")
    check("AC15 unit: a deletion with an unreadable or missing old file type is dirty even with the label", P.classify(nc(PS, mode="000000", labels=("patch-fix",)))[0] == "dirty")
    cd_ = dict(nc(KN), contents={KN: {"old": None, "new": "text\n"}})
    check("AC15 unit: a replacement whose old blob was not read is dirty", P.classify(cd_)[0] == "dirty", P.classify(cd_))
    cd_ = dict(nc(KN, mode="000000", old_mode="100644"), contents={KN: {"old": None, "new": None}})
    check("AC15 unit: a deletion whose old blob was not read is dirty", P.classify(cd_)[0] == "dirty", P.classify(cd_))
    cd_ = dict(nc(KN), contents={KN: {"old": "\0unreadable", "new": "text\n"}})
    check("AC15 unit: an old blob that failed to read (not text) is dirty", P.classify(cd_)[0] == "dirty", P.classify(cd_))
    cd_ = dict(nc(KN, mode="000000", old_mode="100644"), contents={KN: {"old": "plain\n", "new": None}})
    check("AC15 unit: a deletion of a text file whose old blob was read is neutral", P.classify(cd_)[0] == "neutral", P.classify(cd_))
    cd_ = dict(nc(KN, old_mode="000000"), contents={KN: {"old": None, "new": ""}})
    check("AC15 unit: a new empty Markdown file is data: neutral", P.classify(cd_)[0] == "neutral", P.classify(cd_))
    D = P.decide("schedule", [nc(PS, body="null\n"), c("a", [".auditor/accepted-items.json"])], ["v0.2.1"], cut_today=False, removed=None)
    check("AC15 a JSON value that is not an object beside an accepted-items fix does not block the patch", D["cut"] and not D["not_clean"], D)
    # the classifier asks for whole-blob evidence itself (Codex #425 r2, both seats): a record without `contents` is not proven data
    check("AC15 unit: a replacement record without blob contents is dirty", P.classify({k: v for k, v in nc(KN).items() if k != "contents"})[0] == "dirty")
    check("AC15 unit: a deletion record without blob contents is dirty", P.classify({k: v for k, v in nc(KN, mode="000000", old_mode="100644").items() if k != "contents"})[0] == "dirty")
    check("AC15 unit: a contents record without the old side is dirty", P.classify(dict(nc(KN), contents={KN: {"new": "text\n"}}))[0] == "dirty")
    D = P.decide("schedule", [{k: v for k, v in nc(KN, mode="000000", old_mode="100644").items() if k != "contents"}, c("a", [".auditor/accepted-items.json"])], ["v0.2.1"], cut_today=False, removed=None)
    check("AC15 a deletion record without blob contents beside a fix blocks the patch", not D["cut"] and D["not_clean"], D)
    # the VEX statement file under .vex/ is NOT neutral (advisor 0254/0257 read-back): a change to it is a fix and cuts a patch; only .vex/README.md is data
    check("AC15 a change to the VEX statement file is a fix, never neutral", P.classify(nc(VEXF))[0] != "neutral" and P.classify(c("v", [VEXF]))[0] == "fix", [P.classify(nc(VEXF)), P.classify(c("v", [VEXF]))])
    check("AC15 a change to the VEX statement file ships bytes and cuts a patch", P.ships_bytes([VEXC]) and P.decide("schedule", [VEXC], ["v0.2.1"], cut_today=False, removed=None)["cut"])
    check("AC15 a change to the VEX statement file with the patch-fix label is still fix, not neutral", P.classify(nc(VEXF, labels=("patch-fix",)))[0] == "fix", P.classify(nc(VEXF, labels=("patch-fix",))))

ac15_()
print("patch-decide: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
