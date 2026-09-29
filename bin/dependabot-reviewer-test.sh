#!/usr/bin/env bash
# Offline suite for bin/dependabot-reviewer.py (register row 75). Pure functions only:
# `gather` and `read` need gh / the model and are never called here; release_notes is
# exercised with `_gh_json` stubbed. Real Dependabot PR bodies from this repository are in
# test-evidence/dependabot-reviewer/ (#99 single major whose notes quote upstream's own
# bumps; #91 major whose commit list names certifi 2020->2024; #124 a four-member group;
# #90 a patch). The rest are written in Dependabot's own format.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
export REVIEWER_PY="$here/dependabot-reviewer.py" FIX="$repo/test-evidence/dependabot-reviewer"
python3 - <<'PY'
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("reviewer", os.environ["REVIEWER_PY"])
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
FIX = os.environ["FIX"]
passed = failed = 0

def check(name, cond, detail=""):
    global passed, failed
    if cond:
        print("ok: " + name); passed += 1
    else:
        print("FAIL: %s %s" % (name, detail)); failed += 1

def real(n):
    d = json.load(open(os.path.join(FIX, "pr-%d.json" % n)))
    return r.parse_updates(d["title"], d["body"])

def triples(u):
    return [(x["name"], x["from"], x["to"], x["major"]) for x in u]

# --- updates: real bodies
u = real(99)
check("real #99: exactly checkout 4->7, major (upstream's own bumps in the notes ignored)",
      triples(u) == [("actions/checkout", "4", "7", True)], triples(u))
u = real(91)
check("real #91: only setup-python 5.6.0->7.0.0 (certifi in the commit list ignored)",
      triples(u) == [("actions/setup-python", "5.6.0", "7.0.0", True)], triples(u))
u = real(124)
check("real #124 group: four codeql-action members, none major",
      len(u) == 4 and all(x["name"].startswith("github/codeql-action/") and not x["major"] for x in u), triples(u))
u = real(90)
check("real #90 patch: setup-java 6.0.0->6.0.1, not major",
      triples(u) == [("actions/setup-java", "6.0.0", "6.0.1", False)], triples(u))

# --- updates: Dependabot-format bodies
grouped = ("Bumps the actions group with 2 updates: [actions/cache](https://github.com/actions/cache) "
           "and [actions/setup-node](https://github.com/actions/setup-node).\n\n"
           "Updates `actions/cache` from 4.2.0 to 5.0.1\n<details>\n<summary>Release notes</summary>\n"
           "<blockquote>Bump foo/bar from 1 to 9</blockquote>\n</details>\n\n"
           "Updates `actions/setup-node` from 4.1.0 to 4.4.0\n<details>\n<summary>Commits</summary>\n"
           "<ul><li>Bumps [x/y](https://e) from 2 to 3.</li></ul>\n</details>\n")
u = r.parse_updates("Build(deps): bump the actions group with 2 updates", grouped)
check("group: one major + one minor, nothing from inside <details>",
      triples(u) == [("actions/cache", "4.2.0", "5.0.1", True), ("actions/setup-node", "4.1.0", "4.4.0", False)], triples(u))
u = r.parse_updates("Build(deps): bump golang from `3f3c01a` to `9e8d7c6`",
                    "Bumps golang from `3f3c01a` to `9e8d7c6`.\n\n---\n")
check("docker digest bump (digits-first digests) is NOT major",
      len(u) == 1 and u[0]["major"] is False and u[0]["from"] == "3f3c01a", triples(u))
u = r.parse_updates("", "Bumps golang from `sha256:abcdef0123456789` to `sha256:0123456789abcdef`.\n")
check("sha256:-prefixed digest bump is NOT major", len(u) == 1 and u[0]["major"] is False, triples(u))
u = r.parse_updates("Build(deps): bump golang.org/x/net from 0.21.0 to 0.22.0",
                    "Bumps [golang.org/x/net](https://github.com/golang/net) from 0.21.0 to 0.22.0.\n<details></details>")
check("gomod 0.x minor is NOT major", triples(u) == [("golang.org/x/net", "0.21.0", "0.22.0", False)], triples(u))
u = r.parse_updates("Build(deps): bump actions/setup-go from 5 to 7", "")
check("title-only fallback (empty body)", triples(u) == [("actions/setup-go", "5", "7", True)], triples(u))
u = r.parse_updates("Build(deps): bump actions/setup-go from 5 to 7", None)
check("title-only fallback (null body)", triples(u) == [("actions/setup-go", "5", "7", True)], triples(u))
check("is_major: v1.2.3 -> v2.0.0", r.is_major("v1.2.3", "v2.0.0") is True)
check("is_major: 0.21.0 -> 0.22.0 is not", r.is_major("0.21.0", "0.22.0") is False)
check("is_major: unparseable is not", r.is_major("latest", "stable") is False)

# --- release-note range (floating major pins) and release_notes with _gh_json stubbed
V = r._vertuple
got = [t for t in ("v4.2.0", "v5.0.0", "v6.1.0", "v7.0.0", "v7.0.1", "v8.0.0") if r.in_range(V(t), V("4"), V("7"))]
check("range 4 -> 7 = every 5.x..7.x, no 4.x, no 8", got == ["v5.0.0", "v6.1.0", "v7.0.0", "v7.0.1"], got)
got = [t for t in ("v5.6.0", "v5.6.1", "v6.0.0", "v7.0.0", "v7.0.1") if r.in_range(V(t), V("5.6.0"), V("7.0.0"))]
check("range 5.6.0 -> 7.0.0 is exact", got == ["v5.6.1", "v6.0.0", "v7.0.0"], got)
r._gh_json = lambda args: [{"tag_name": "v7.0.0", "name": "seven", "body": "removed input foo"},
                           {"tag_name": "v4.3.0", "name": "old", "body": "not ours"},
                           {"tag_name": "v5.0.0", "name": "five", "body": "node24"}]
text, n = r.release_notes("actions/checkout", "4", "7")
check("release_notes: in-range releases oldest first, counted",
      n == 2 and text.index("v5.0.0") < text.index("v7.0.0") and "v4.3.0" not in text, (n, text))
r._gh_json = lambda args: None
text, n = r.release_notes("actions/checkout", "4", "7")
check("release_notes: none found is said, count 0", n == 0 and "no upstream release notes found" in text, (n, text))
text, n = r.release_notes("golang", "`3f3c01a`", "`9e8d7c6`")
check("release_notes: non-GitHub dependency is said, count 0", n == 0 and "not a GitHub-hosted" in text, (n, text))

# --- normalize_findings: errors, never a pass
f, e = r.normalize_findings({"findings": [{"severity": "critical", "title": "x"}]})
check("unknown severity is an error", f is None and "unknown severity" in e, (f, e))
f, e = r.normalize_findings({"verdict": "fine"})
check("missing findings list is an error", f is None and e, (f, e))
f, e = r.normalize_findings(None)
check("unparseable answer is an error", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": ["just a string"]})
check("non-object finding is an error", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "noise", "title": "n"}, {"severity": "Breaks-Us", "title": "b"},
                                          {"severity": "check", "title": "c"}]})
check("valid answer ranked breaks-us, check, noise (case-insensitive)",
      e is None and [x["severity"] for x in f] == ["breaks-us", "check", "noise"], (f, e))
f, e = r.normalize_findings(r.parse_answer('```json\n{"findings": []}\n```'))
check("one object in one code fence = read, nothing found", e is None and f == [], (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": []}'))
check("bare object = read, nothing found", e is None and f == [], (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [], "unfinished": {"findings": []}'))
check("truncated answer is an error, not an inner object (round-1 P1)", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": []}\n{"findings": [{"severity": "breaks-us", "title": "x"}]}'))
check("two objects is an error, never the first one only", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('Here you go:\n{"findings": []}'))
check("prose around the object is an error", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "claude-opus-9 says critical", "title": "x"}]})
check("the unknown-severity error text is masked", f is None and "claude-" not in e, e)
check("mask: plain vendor and model names", r.mask("As Claude (Anthropic), like GPT-4o or Gemini") ==
      "As <model> (<model>), like <model> or <model>", r.mask("As Claude (Anthropic), like GPT-4o or Gemini"))

# --- usage: a workflow hit comes with its whole step (inputs included); others as is
wf = ["jobs:", "  a:", "    steps:", "      - name: get", "        uses: actions/checkout@v4", "        with:",
      "          fetch-depth: 0", "          persist-credentials: false", "", "      - run: echo next"]
check("step_context: from the `- ` to the step's end, inputs included", r.step_context(wf, 4) == (3, 7), r.step_context(wf, 4))
txt = r.usage_blocks([".github/workflows/x.yml:5:        uses: actions/checkout@v4", "go.mod:3:require x v1"],
                     lambda p: wf)
check("usage_blocks: numbered step with fetch-depth and persist-credentials; non-workflow hit kept",
      ".github/workflows/x.yml:7:           fetch-depth: 0" in txt and "persist-credentials" in txt
      and "echo next" not in txt and "go.mod:3:require x v1" in txt, txt)
txt = r.usage_blocks([".github/workflows/x.yml:5:  uses: a", ".github/workflows/x.yml:7:  fetch-depth: 0"], lambda p: wf)
check("usage_blocks: two hits in one step print it once", txt.count("uses: actions/checkout@v4") == 1, txt)

# --- mask: no model id or configured identifier reaches a finding
os.environ["AUDITOR_MODEL_PRIMARY"] = "some-private-model-7"
f, e = r.normalize_findings({"findings": [{"severity": "check", "title": "as claude-opus-9-9 I think",
                                           "why": "some-private-model-7 says so; Bearer abcdefghij"}]})
check("mask: model ids and bearer tokens redacted in findings",
      e is None and "claude-" not in json.dumps(f) and "some-private-model-7" not in json.dumps(f)
      and "abcdefghij" not in json.dumps(f) and "<model-id>" in f[0]["title"], f)

# --- decide: mechanical
clean = lambda n: {"reader": n, "findings": [{"severity": "check", "title": "t"}], "error": None}
brk = {"reader": "B", "findings": [{"severity": "breaks-us", "title": "removed foo"}], "error": None}
err = {"reader": "B", "findings": None, "error": "model-call step failed"}
d = r.decide([clean("A"), clean("B")])
check("decide: both clean -> merge", d["decision"] == "merge" and d["breaks_us"] == [], d)
d = r.decide([clean("A"), brk])
check("decide: one breaks-us -> hold, attributed", d["decision"] == "hold" and d["breaks_us"][0]["reader"] == "B", d)
d = r.decide([clean("A"), err])
check("decide: one reader errored -> error", d["decision"] == "error" and "model-call" in d["reason"], d)
d = r.decide([brk, err])
check("decide: breaks-us + an error -> error (no check, retry)", d["decision"] == "error", d)
d = r.decide([clean("A")] + [{"reader": "B", "findings": None, "error": None}])
check("decide: a reader with no findings and no error -> error", d["decision"] == "error", d)
check("decide: no readers -> error", r.decide([])["decision"] == "error")

print("----")
print("dependabot-reviewer: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
py_rc=$?

# ============================================================================ the act step
# The committed "gather, read twice, decide, act" step, run as written under GitHub's default
# `bash -e`, with: a recording `gh` (per-scenario failures), a stub token endpoint (`curl`), the
# committed required-check guard fed a matching or drifted ruleset, and a fake SDK module that
# returns each reader's canned answer. Asserts WHAT is called, in WHAT order, and whether a check
# goes up — the round-1 paths (malformed answer, failed diff, re-hold with auto-merge armed,
# partial failures, -e aborting the loop, guard drift).
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
pass=0; fail=0
python3 - "$repo/.github/workflows/dependabot-reviewer.yml" "$w/act.sh" <<'PY'
import sys, yaml
steps = yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"]
run = [s["run"] for s in steps if s.get("id") == "act"]
assert len(run) == 1, "act step not found"
open(sys.argv[2], "w").write(run[0])
PY
mkdir -p "$w/bin" "$w/py/anthropic"
cat > "$w/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "$GH_LOG"
fails() { case " ${FAIL:-} " in *" $1 "*) exit 1 ;; esac; }
case "$1 $2" in
  "api repos/o/r/contents/.github/policy/required-checks.json?ref=main") base64 < "$LIST" | tr -d '\n' ;;
  "api repos/o/r/check-runs") fails check ;;
  "api "*) exit 1 ;;                                   # upstream releases: none available
  "pr diff") fails diff; printf -- '--- a/.github/workflows/x.yml\n+++ b/.github/workflows/x.yml\n-      - uses: a/b@v4\n+      - uses: a/b@v7\n' ;;
  "pr merge") if [ "$3" = "--disable-auto" ]; then fails disarm; else fails merge; fi ;;
  "pr view") fails view; echo "${ARMED:-false}" ;;
  "issue list") fails issuelist; echo '[]' ;;
  "issue create") fails issue; echo "https://example.invalid/issues/5" ;;
  "issue edit") fails issue ;;
esac
EOF
cat > "$w/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo '{"value":"header.eyJzdWIiOiJ4In0.sig"}'
EOF
cat > "$w/py/anthropic/__init__.py" <<'EOF'
import os
class _Block:
    def __init__(self, t): self.text = t
class _Msg:
    def __init__(self, t): self.content = [_Block(t)]
class _Messages:
    def create(self, model, max_tokens, messages):
        if model == "boom":
            raise RuntimeError("connection reset")
        return _Msg(os.environ["ANSWER_" + model])
class Anthropic:
    def __init__(self): self.messages = _Messages()
EOF
chmod +x "$w/bin/gh" "$w/bin/curl"
jq '[{"type":"required_status_checks","parameters":{"required_status_checks":[.required_checks[]|{context,integration_id}]}}]' \
  "$repo/.github/policy/required-checks.json" > "$w/rules-match.json"
jq '(.[0].parameters.required_status_checks) |= .[1:]' "$w/rules-match.json" > "$w/rules-drift.json"
CLEAN='{"findings": [{"severity": "check", "title": "node24 runtime", "release_note": "v5: node24", "our_line": ".github/workflows/x.yml:3", "why": "runtime"}]}'
BREAKS='{"findings": [{"severity": "breaks-us", "title": "input removed", "release_note": "v7: removed foo", "our_line": ".github/workflows/x.yml:3", "why": "we pass foo"}]}'
TRUNC='{"findings": [], "unfinished": {"findings": []}'

act() { # name; env: A B (answers), PRS, FAIL, ARMED, RULES
  local W="$w/run"; rm -rf "$W"; mkdir -p "$W/work"; : > "$w/gh.log"
  : > "$W/work/candidates.txt"
  for n in ${PRS:-99}; do
    echo "$n abcdef1234567$n" >> "$W/work/candidates.txt"
    echo '[{"name":"a/b","from":"4","to":"7","major":true}]' > "$W/work/updates-$n.json"
  done
  (cd "$repo" && env PATH="$w/bin:$PATH" PYTHONPATH="$w/py" GH_LOG="$w/gh.log" LIST="$repo/.github/policy/required-checks.json" \
     GUARD_RULES_JSON="${RULES:-$w/rules-match.json}" FAIL="${FAIL:-}" ARMED="${ARMED:-false}" \
     GITHUB_REPOSITORY=o/r RUNNER_TEMP="$W" GITHUB_STEP_SUMMARY="$W/summary" GITHUB_OUTPUT="$W/output" \
     RUN_URL=https://example.invalid/run ANTHROPIC_IDENTITY_TOKEN_FILE="$W/token" \
     ACTIONS_ID_TOKEN_REQUEST_TOKEN=t ACTIONS_ID_TOKEN_REQUEST_URL="https://example.invalid/oidc?x=1" \
     AUDITOR_MODEL_PRIMARY=ma AUDITOR_MODEL_FALLBACK="${MB:-mb}" ANSWER_ma="$A" ANSWER_mb="$B" \
     GH_TOKEN=job CHECKS_TOKEN=chk MERGE_TOKEN=mrg \
     bash --noprofile --norc -e -o pipefail "$w/act.sh") > "$w/act.out" 2>&1
  echo $? > "$w/act.rc"
}
expect() { # name; then grep -E assertions on the gh log: +regex must appear, -regex must not
  local name="$1" ok=1; shift
  for a in "$@"; do
    case "$a" in
      +*) grep -qE -- "${a:1}" "$w/gh.log" || ok=0 ;;
      -*) grep -qE -- "${a:1}" "$w/gh.log" && ok=0 ;;
      ORDER:*) local x="${a#ORDER:}" y; y="${x#*>}"; x="${x%%>*}"
               [ "$(grep -nE -- "$x" "$w/gh.log" | head -1 | cut -d: -f1)" -lt "$(grep -nE -- "$y" "$w/gh.log" | head -1 | cut -d: -f1)" ] 2>/dev/null || ok=0 ;;
      ERRORED=*) grep -qx "errored=${a#ERRORED=}" "$w/run/output" || ok=0 ;;
    esac
  done
  if [ "$ok" = 1 ]; then echo "ok: act: $name"; pass=$((pass+1))
  else echo "FAIL: act: $name"; sed 's/^/    gh: /' "$w/gh.log"; tail -15 "$w/act.out" | sed 's/^/    out: /'; fail=$((fail+1)); fi
}
CHK='check-runs'; SUCCESS='conclusion=success'; FAILURE='conclusion=failure'

A="$CLEAN" B="$CLEAN" act; expect "both clean -> arm auto-merge, THEN the success check" \
  "+pr merge --auto --squash 99" "+$CHK" "ORDER:pr merge --auto>$CHK" ERRORED=0
grep -q -- "-f conclusion=success" "$w/gh.log" && { echo "ok: act: the check says success"; pass=$((pass+1)); } || { echo "FAIL: act: success conclusion"; fail=$((fail+1)); }
A="$CLEAN" B="$TRUNC" act; expect "a truncated answer -> no merge, no check (round-1 P1)" "-pr merge" "-$CHK" ERRORED=1
A="$CLEAN" B="$CLEAN" FAIL="diff" act; expect "diff cannot be fetched -> no reader, no merge, no check (round-1 P1)" "-pr merge" "-$CHK" ERRORED=1
A="$CLEAN" B="$BREAKS" ARMED=true act; expect "re-hold with auto-merge armed -> disarm, issue, THEN failure check (round-1 P1)" \
  "+pr merge --disable-auto 99" "+issue create" "+$CHK" "-pr merge --auto --squash" "ORDER:disable-auto>issue create" "ORDER:issue create>$CHK" ERRORED=0
grep -q -- "-f conclusion=failure" "$w/gh.log" && { echo "ok: act: the check says failure"; pass=$((pass+1)); } || { echo "FAIL: act: failure conclusion"; fail=$((fail+1)); }
A="$CLEAN" B="$BREAKS" ARMED=false act; expect "hold, not armed -> no disarm call, issue, failure check" "-disable-auto" "+issue create" "+$CHK" ERRORED=0
A="$CLEAN" B="$BREAKS" FAIL="issue" act; expect "held issue cannot be created -> no check; retry (round-1 P1)" "-$CHK" ERRORED=1
A="$CLEAN" B="$BREAKS" ARMED=true FAIL="disarm" act; expect "auto-merge cannot be disarmed -> no issue, no check" "-issue create" "-$CHK" ERRORED=1
A="$CLEAN" B="$CLEAN" FAIL="merge" act; expect "auto-merge cannot be armed -> no success check; retry (round-1 P1)" "-$CHK" ERRORED=1
A="$CLEAN" B="$CLEAN" RULES="$w/rules-drift.json" act; expect "required-check drift -> no major armed, no check (Sonnet round 1)" "-pr merge" "-$CHK" ERRORED=1
A="$CLEAN" B="$CLEAN" MB=boom act; expect "a reader raises -> no merge, no check" "-pr merge" "-$CHK" ERRORED=1
A="$CLEAN" B="$BREAKS" PRS="99 100" FAIL="issuelist" act; expect "issue lookup fails on #99 -> #100 still reviewed, errored counted (bash -e, round 1)" \
  "+pr diff 100" ERRORED=2
A="$CLEAN" B='{"findings": [{"severity": "breaks-us", "title": "as claude-opus-9 I see", "release_note": "n", "our_line": "l", "why": "Anthropic says"}]}' act
if grep -rqiE "claude|anthropic" "$w/run/work/pr-99/issue.md" "$w/run/work/pr-99/decision.json" "$w/run/work/pr-99/reader-AUDITOR_MODEL_FALLBACK.json"; then
  echo "FAIL: act: a model/vendor name reached the issue or the evidence"; fail=$((fail+1))
else echo "ok: act: no model/vendor name in the issue or the evidence"; pass=$((pass+1)); fi
grep -q "reader A" "$w/run/work/pr-99/issue.md" && grep -q "reader B" "$w/run/work/pr-99/issue.md" && grep -q "release note: n" "$w/run/work/pr-99/issue.md" \
  && { echo "ok: act: the issue carries both readers' findings, attributed, with release notes"; pass=$((pass+1)); } \
  || { echo "FAIL: act: issue content"; sed 's/^/    /' "$w/run/work/pr-99/issue.md"; fail=$((fail+1)); }

echo "----"
echo "dependabot-reviewer act step: ${pass} passed, ${fail} failed"
[ "$py_rc" -eq 0 ] && [ "$fail" -eq 0 ]
