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
check("unknown severity is an error", f is None and "no known severity" in e, (f, e))
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
check("the unknown-severity error never echoes the value", f is None and "claude" not in e.lower() and "opus" not in e.lower(), e)
os.environ["AUDITOR_MODEL_FALLBACK"] = "Secret-Model-X"
f, e = r.normalize_findings({"findings": [{"severity": "SECRET-MODEL-X", "title": "x"}]})
check("a configured identifier in a transformed severity never reaches the error", f is None and "secret-model-x" not in e.lower(), e)
f, e = r.normalize_findings({"findings": [{"severity": 3, "title": "x"}]})
check("a non-string severity is an error", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [], "error": "I could not complete this review: the bundle was too long."}'))
check("an extra top-level field (a declared failure) is an error, never a clean answer (round-3 P1)", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [], "more_findings": [{"severity": "breaks-us", "title": "x"}]}'))
check("a second findings-like list is an error (round-3 P1)", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "check", "title": "t", "verdict": "safe to merge"}]})
check("a finding with a field outside the schema is an error", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "check", "title": "t", "why": {"error": "I could not complete the review"}}]})
check("a non-text field value is an error, never stringified (round-4 P1)", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "noise", "title": ["a"]}]})
check("a list-valued field is an error", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [{"severity": "breaks-us", "title": "x"}], "findings": []}'))
check("duplicate findings key is an error, never the later empty list (round-2 P1)", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [{"severity": "breaks-us", "severity": "noise", "title": "x"}]}'))
check("duplicate severity key is an error (round-2 P1)", f is None and e, (f, e))
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

# --- answer_of: how the answer ended (first live run: every primary answer cut off mid-JSON)
class B:
    def __init__(self, t, x=""): self.type, self.text = t, x
class U:
    output_tokens = 2048
class M:
    def __init__(self, blocks, stop, usage=True): self.content, self.stop_reason, self.usage = blocks, stop, (U() if usage else None)
t, m, e = r.answer_of(M([B("text", '{"findings": [{"severity": "check", "title": "Action internals upgraded to ')], "max_tokens"))
check("answer_of: cut off at the token limit is an explicit error (live run 36640316796)",
      e and "token limit" in e and m["stop_reason"] == "max_tokens" and m["output_tokens"] == 2048, (e, m))
t, m, e = r.answer_of(M([B("thinking")], "max_tokens"))
check("answer_of: reasoning only, no text, at the limit -> the token-limit error", e and "token limit" in e, (e, m))
t, m, e = r.answer_of(M([B("thinking")], "end_turn"))
check("answer_of: no text block -> 'no text', block types recorded", e and "no text" in e and m["blocks"] == ["thinking"], (e, m))
t, m, e = r.answer_of(M([B("thinking"), B("text", '{"findings": []}')], "end_turn", usage=False))
check("answer_of: reasoning then a complete answer -> the text only, no error", e is None and t == '{"findings": []}', (t, e))
check("the reader budget is well above the 2048 that cut every answer", r.MAX_TOKENS >= 16000, r.MAX_TOKENS)

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
  "api repos/fosterstack/ops/dispatches") fails dispatch ;;
  "api repos/o/r/commits/shaA/check-runs?check_name=dependabot-reviewer") echo success ;;   # cancellation cleanup lookups
  "api repos/o/r/commits/shaB/check-runs?check_name=dependabot-reviewer") echo none ;;
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
        m = _Msg(os.environ["ANSWER_" + model])
        if model == "cut":
            m.stop_reason = "max_tokens"
        return m
    def stream(self, model, max_tokens, messages):   # the reader streams (no non-streaming ceiling)
        outer = self
        class _S:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def get_final_message(self): return outer.create(model, max_tokens, messages)
        return _S()
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
    echo "$n abcdef1234567$n ${PRIOR:-none}" >> "$W/work/candidates.txt"
    echo '[{"name":"a/b","from":"4","to":"7","major":true}]' > "$W/work/updates-$n.json"
  done
  (cd "$repo" && env PATH="$w/bin:$PATH" PYTHONPATH="$w/py" GH_LOG="$w/gh.log" LIST="$repo/.github/policy/required-checks.json" \
     GUARD_RULES_JSON="${RULES:-$w/rules-match.json}" FAIL="${FAIL:-}" ARMED="${ARMED:-false}" \
     GITHUB_REPOSITORY=o/r RUNNER_TEMP="$W" GITHUB_STEP_SUMMARY="$W/summary" GITHUB_OUTPUT="$W/output" \
     RUN_URL=https://example.invalid/run ANTHROPIC_IDENTITY_TOKEN_FILE="$W/token" \
     ACTIONS_ID_TOKEN_REQUEST_TOKEN=t ACTIONS_ID_TOKEN_REQUEST_URL="https://example.invalid/oidc?x=1" \
     AUDITOR_MODEL_PRIMARY=ma AUDITOR_MODEL_FALLBACK="${MB:-mb}" ANSWER_ma="$A" ANSWER_mb="$B" \
     GH_TOKEN=job CHECKS_TOKEN=chk MERGE_TOKEN=mrg DISPATCH_TOKEN="${DT-ops}" \
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

# --- row 76: a completed hold dispatches the fixer (best effort)
A="$CLEAN" B="$BREAKS" act; expect "hold -> issue, failure check, THEN the fixer dispatch with issue and PR (row 76)" \
  "+api repos/fosterstack/ops/dispatches -f event_type=fix-held-bump -f client_payload\[issue\]=5 -f client_payload\[pr\]=99 -f client_payload\[repo\]=o/r" \
  "ORDER:$CHK>ops/dispatches" ERRORED=0
A="$CLEAN" B="$BREAKS" FAIL="dispatch" act; expect "the dispatch fails -> the hold still stands: issue, failure check, not unfinished" "+issue create" "+$CHK" ERRORED=0
grep -q "fixer dispatch (fix-held-bump, issue #5): the dispatch call failed" "$w/act.out" \
  && { echo "ok: act: a failed dispatch is a warning naming the issue"; pass=$((pass+1)); } || { echo "FAIL: act: dispatch warning"; fail=$((fail+1)); }
A="$CLEAN" B="$BREAKS" DT="" act; expect "no ops token (App not on ops) -> no dispatch call, hold stands" "-ops/dispatches" "+$CHK" ERRORED=0
A="$CLEAN" B="$CLEAN" act; expect "a merge never dispatches the fixer" "-ops/dispatches"
out=$(bash "$here/dispatch-fixer.sh" fix-something 5 2>&1); rc=$?
[ "$rc" = 1 ] && grep -q "unknown event type" <<<"$out" && { echo "ok: dispatch-fixer: unknown event type refused"; pass=$((pass+1)); } || { echo "FAIL: unknown event"; fail=$((fail+1)); }
out=$(DISPATCH_TOKEN=t bash "$here/dispatch-fixer.sh" fix-held-bump "" 2>&1); rc=$?
[ "$rc" = 1 ] && grep -q "no issue number" <<<"$out" && { echo "ok: dispatch-fixer: no issue number refused"; pass=$((pass+1)); } || { echo "FAIL: no issue"; fail=$((fail+1)); }
python3 - "$repo/.github/workflows/hygiene.yml" "$w/drift-dispatch.sh" <<'PY5'
import sys, yaml
j = yaml.safe_load(open(sys.argv[1]))["jobs"]["drift-fixer-dispatch"]
assert "push" in j["if"] and "refs/heads/main" in j["if"] and j["environment"] == "agent"
open(sys.argv[2], "w").write([s for s in j["steps"] if s.get("name") == "dispatch"][0]["run"])
PY5
for mode in ok dispatch; do
  : > "$w/gh.log"
  (cd "$repo" && env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" FAIL="$([ $mode = dispatch ] && echo dispatch)" DISPATCH_TOKEN=ops ISSUE=12 GITHUB_REPOSITORY=o/r \
     bash --noprofile --norc -e -o pipefail "$w/drift-dispatch.sh") >/dev/null 2>&1; rc=$?
  if [ "$rc" = 0 ] && grep -q "ops/dispatches -f event_type=fix-required-check-drift -f client_payload\[issue\]=12 -f client_payload\[pr\]= " "$w/gh.log"; then
    echo "ok: hygiene drift dispatch ($mode): fix-required-check-drift for issue 12, step never fails"; pass=$((pass+1))
  else echo "FAIL: hygiene drift dispatch ($mode) rc=$rc"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); fi
done

# --- round 2
A="$CLEAN" B="$CLEAN" ARMED=true FAIL="check" act; expect "armed but the success check fails -> counted unfinished, auto-merge turned back off (round-2)" \
  "+pr merge --auto --squash 99" "+pr merge --disable-auto 99" ERRORED=1
A="$CLEAN" B="$BREAKS" FAIL="check" act; expect "held but the failure check fails -> counted unfinished (round-2)" "+issue create" ERRORED=1
A="$CLEAN" B="$CLEAN" MB=boom ARMED=true PRIOR=success act; expect "forced re-review errors over an old success -> disarm + neutral check (round-2 P1)" \
  "+pr merge --disable-auto 99" "+check-runs" "-pr merge --auto" ERRORED=1
grep -q -- "-f conclusion=neutral" "$w/gh.log" && { echo "ok: act: the superseding check is neutral"; pass=$((pass+1)); } || { echo "FAIL: act: neutral check"; fail=$((fail+1)); }
A="$CLEAN" B="$BREAKS" ARMED=true FAIL="disarm" PRIOR=success act; expect "forced re-hold whose disarm fails -> neutral check, no failure verdict (round-2 P1)" \
  "+check-runs" "-issue create" ERRORED=1
grep -q -- "-f conclusion=neutral" "$w/gh.log" && ! grep -q -- "-f conclusion=failure" "$w/gh.log" \
  && { echo "ok: act: only a neutral check after a failed disarm"; pass=$((pass+1)); } || { echo "FAIL: act: neutral-only"; fail=$((fail+1)); }
A="$CLEAN" B="$CLEAN" MB=boom act; expect "first-time reader error -> NO check at all (row 75)" "-check-runs" ERRORED=1
ANSWER_cut="$CLEAN" A="$CLEAN" B="$CLEAN" MB=cut act; expect "a complete-looking answer that stopped at the token limit -> error, no merge (live run)" "-pr merge" "-check-runs" ERRORED=1
grep -q '"stop_reason": "max_tokens"' "$w/run/work/pr-99/reader-AUDITOR_MODEL_FALLBACK.json" && grep -q "token limit" "$w/run/work/pr-99/reader-AUDITOR_MODEL_FALLBACK.json" \
  && { echo "ok: act: the evidence records the stop reason and says 'token limit'"; pass=$((pass+1)); } || { echo "FAIL: act: stop reason in evidence"; fail=$((fail+1)); }
A="$CLEAN" B="$CLEAN" ARMED=true FAIL="check" act
grep -c "check-runs" "$w/gh.log" | grep -qx 2 && grep -q -- "-f conclusion=neutral" "$w/gh.log" \
  && { echo "ok: act: a success write that errored is superseded by neutral (lost response, round-3 P1)"; pass=$((pass+1)); } \
  || { echo "FAIL: act: lost-response neutral"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); }
A="$CLEAN" B='{"findings": [], "error": "I could not complete this review."}' act; expect "a reader declaring failure in an extra field -> no merge, no check (round-3 P1)" "-pr merge" "-check-runs" ERRORED=1
python3 - "$repo/.github/workflows/dependabot-reviewer.yml" <<'PY3' && { echo "ok: conditions: productive steps are cancellation-aware; act needs the merge token; evidence cannot fail the job (round 3)"; pass=$((pass+1)); } || { echo "FAIL: conditions"; fail=$((fail+1)); }
import sys, yaml
st = {s.get("id"): s for s in yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"]}
ok = all("!cancelled()" in st[i]["if"] and "always()" not in st[i]["if"] for i in ("mint", "sdk", "act"))
ok = ok and "steps.app-merge.outcome == 'success'" in st["act"]["if"]
up = [s for s in yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"] if s.get("name", "").startswith("upload the evidence")][0]
sys.exit(0 if ok and up.get("continue-on-error") is True else 1)
PY3

A="$CLEAN" B="$CLEAN" act
[ ! -s "$w/run/work/armed-unpublished.txt" ] && { echo "ok: act: after arm + published check the cancellation ledger is empty"; pass=$((pass+1)); } \
  || { echo "FAIL: act: ledger not cleared"; cat "$w/run/work/armed-unpublished.txt"; fail=$((fail+1)); }
python3 - "$repo/.github/workflows/dependabot-reviewer.yml" "$w/cancel.sh" <<'PY4'
import sys, yaml
st = [s for s in yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"] if s.get("name", "").startswith("on cancellation")]
assert len(st) == 1 and st[0]["if"] == "cancelled()"
open(sys.argv[2], "w").write(st[0]["run"])
PY4
mkdir -p "$w/cx/work"; printf '99 shaA\n100 shaB\n101 shaC\n' > "$w/cx/work/armed-unpublished.txt"; : > "$w/gh.log"
(env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" RUNNER_TEMP="$w/cx" GITHUB_REPOSITORY=o/r APP_TOKEN=a APP_SLUG=s RUN_URL=https://example.invalid/run \
   bash --noprofile --norc -e -o pipefail "$w/cancel.sh") >/dev/null 2>&1
! grep -q "pr merge --disable-auto 99" "$w/gh.log" && grep -q "pr merge --disable-auto 100" "$w/gh.log" && grep -q "pr merge --disable-auto 101" "$w/gh.log" \
  && { echo "ok: cancellation: disarms arms with no success on the head (none, lookup failed); keeps one whose success landed (rounds 5-6)"; pass=$((pass+1)); } \
  || { echo "FAIL: cancellation cleanup"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); }
grep -q -- "check-runs -f name=dependabot-reviewer -f head_sha=shaC .*conclusion=neutral" "$w/gh.log" \
  && ! grep -q -- "head_sha=shaB" "$w/gh.log" \
  && [ "$(grep -n 'head_sha=shaC' "$w/gh.log" | cut -d: -f1)" -lt "$(grep -n 'disable-auto 101' "$w/gh.log" | cut -d: -f1)" ] \
  && { echo "ok: cancellation: a failed lookup posts neutral FIRST, then disarms, so the head is retried (round-7 P1)"; pass=$((pass+1)); } \
  || { echo "FAIL: cancellation: neutral on unknown"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); }

# ============================================================================ candidates step
python3 - "$repo/.github/workflows/dependabot-reviewer.yml" "$w/cand.sh" "$w/streak.sh" <<'PY2'
import sys, yaml
steps = yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"]
c = [s["run"] for s in steps if s.get("id") == "candidates"]
k = [s["run"] for s in steps if s.get("name", "").startswith("three unfinished runs in a row")]
assert len(c) == 1 and len(k) == 1
open(sys.argv[2], "w").write(c[0]); open(sys.argv[3], "w").write(k[0])
PY2
jq -n --slurpfile a "$FIX/pr-99.json" --slurpfile b "$FIX/pr-90.json" --slurpfile c "$FIX/pr-91.json" \
  '[($a[0] + {number: 99, headRefOid: "sha99"}), ($b[0] + {number: 90, headRefOid: "sha90"}), ($c[0] + {number: 91, headRefOid: "sha91"})]' > "$w/prs.json"
cat > "$w/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "$GH_LOG"
case "$1 $2" in
  "pr list") cat "$PRS_JSON" ;;
  "api repos/o/r/commits/sha99/check-runs?check_name=dependabot-reviewer") [ "${LOOKUP99:-}" = fail ] && exit 1; echo "${PRIOR99:-none}" ;;
  "api repos/o/r/commits/sha91/check-runs?check_name=dependabot-reviewer") echo "${PRIOR91:-none}" ;;
  "api repos/o/r/check-runs") [ "${NEUTRALFAIL:-}" = 1 ] && exit 1; : ;;
  "pr view") echo "${ARMED99:-false}" ;;
  "pr merge") [ "${DISARMFAIL:-}" = 1 ] && exit 1; : ;;
  "run list") [ "${RUNLIST:-}" = fail ] && exit 1
              f=; while [ $# -gt 0 ]; do [ "$1" = --jq ] && f="$2"; shift; done
              jq -c "${f:-.}" <<<"${HISTORY:-[]}" ;;
  "issue list") echo '[]' ;;
  "issue create"|"issue comment") ;;
esac
EOF
chmod +x "$w/bin/gh"
cand() { # expected-candidates expected-rc; env PRIOR99 PRIOR91 LOOKUP99 FORCE
  local W="$w/cand"; rm -rf "$W"; mkdir -p "$W"; : > "$w/gh.log"
  (cd "$repo" && env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" PRS_JSON="$w/prs.json" GITHUB_REPOSITORY=o/r RUNNER_TEMP="$W" \
     GITHUB_OUTPUT="$W/output" APP_TOKEN=a APP_SLUG=fosterstack-automation MERGE_TOKEN=m RUN_URL=https://example.invalid/run \
     ONLY_PR="${ONLY:-}" FORCE="${FORCE:-false}" \
     bash --noprofile --norc -e -o pipefail "$w/cand.sh") > "$w/cand.out" 2>&1; local rc=$?
  local got; got=$(cut -d' ' -f1,3 "$W/work/candidates.txt" 2>/dev/null | tr '\n' ',')
  if [ "$got" = "$1" ] && [ "$rc" = "$2" ]; then echo "ok: candidates: $3"; pass=$((pass+1))
  else echo "FAIL: candidates: $3 (got '$got' rc $rc)"; sed 's/^/    /' "$w/cand.out" | tail -8; fail=$((fail+1)); fi
}
cand "99 none,91 none," 0 "real bodies: majors #99 and #91 selected, patch #90 not"
PRIOR99=success cand "91 none," 0 "a success verdict is not reviewed again"
PRIOR99=failure PRIOR91=neutral cand "91 neutral," 0 "failure is a verdict; neutral means retry"
PRIOR99=success FORCE=true cand "99 neutral,91 none," 0 "force: old verdict invalidated up front (disarm + neutral), reviewed from neutral (round-3 P1)"
grep -q "pr merge --disable-auto 99" "$w/gh.log" && grep -q -- "-f conclusion=neutral" "$w/gh.log" \
  && { echo "ok: candidates: the forced invalidation happened before any later step"; pass=$((pass+1)); } || { echo "FAIL: candidates: forced invalidation calls"; fail=$((fail+1)); }
PRIOR99=success FORCE=true NEUTRALFAIL=1 cand "91 none," 1 "force: neutral cannot be posted -> skipped, step fails (round-3 P1)"
PRIOR99=success FORCE=true DISARMFAIL=1 ARMED99=true cand "" 1 "force: auto-merge cannot be turned off -> skipped, step fails (the stub shows #91 armed too: skipped as well)"
PRIOR99=success ARMED99=false cand "91 none," 0 "a success verdict whose PR someone disarmed is left alone (no re-arm, round-4 P1)"
ARMED99=true cand "99 none,91 none," 0 "armed with no verdict (cancelled mid-act) -> disarmed BEFORE review (round-4 P1)"
grep -q "pr merge --disable-auto 99" "$w/gh.log" && { echo "ok: candidates: the unsupported arm was turned off up front"; pass=$((pass+1)); } || { echo "FAIL: candidates: up-front disarm"; fail=$((fail+1)); }
cand "99 none,91 none," 0 "not armed, no verdict -> no disarm call"
grep -q "disable-auto" "$w/gh.log" && { echo "FAIL: candidates: needless disarm"; fail=$((fail+1)); } || { echo "ok: candidates: no needless disarm"; pass=$((pass+1)); }
ARMED99=true DISARMFAIL=1 cand "" 1 "armed with no verdict and the disarm fails -> skipped, step fails"
LOOKUP99=fail cand "91 none," 1 "a failed check lookup skips that PR and FAILS the step (round-2 P2)"
ONLY=90 cand "" 0 "pr=90 (a patch) selects nothing"

# ============================================================================ streak step
streak() { # history rc-expect want-issue name
  : > "$w/gh.log"
  (cd "$repo" && env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" HISTORY="$1" RUNLIST="${RUNLIST:-}" GITHUB_RUN_ID=500 \
     RUNNER_TEMP="$w" RUN_URL=https://example.invalid/run bash --noprofile --norc -e -o pipefail "$w/streak.sh") > "$w/streak.out" 2>&1; local rc=$?
  local issued=no; grep -q "^gh issue create" "$w/gh.log" && issued=yes
  if [ "$rc" = 0 ] && [ "$issued" = "$2" ]; then echo "ok: streak: $3"; pass=$((pass+1))
  else echo "FAIL: streak: $3 (rc $rc, issued $issued)"; sed 's/^/    /' "$w/streak.out"; fail=$((fail+1)); fi
}
streak '[{"databaseId":500,"conclusion":"failure"},{"databaseId":499,"conclusion":"failure"},{"databaseId":498,"conclusion":"failure"}]' yes "third failure in a row opens the issue"
streak '[{"databaseId":499,"conclusion":"failure"},{"databaseId":498,"conclusion":"success"}]' no "a success in between resets it"
streak '[{"databaseId":499,"conclusion":"failure"}]' no "only two runs so far: no issue"
RUNLIST=fail streak '[]' no "history unreadable: nothing decided, step does not fail"

echo "----"
echo "dependabot-reviewer act step: ${pass} passed, ${fail} failed"
[ "$py_rc" -eq 0 ] && [ "$fail" -eq 0 ]
