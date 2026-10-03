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
for f in (".github/dependabot.yml", ".github/CODEOWNERS", ".github/agent/reviews/abc.json", ".github/agent/tests/x.sh",
          ".github/agent/bin/tests/test_x.py"):
    check("B04 %s stays neutral" % f, P.classify(c("x", [f]))[0] == "neutral")
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
print("patch-decide: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
