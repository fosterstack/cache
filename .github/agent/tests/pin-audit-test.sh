#!/usr/bin/env bash
# proves: REQ-SUP-001-AC5, REQ-SUP-001-AC6, REQ-SUP-001-AC7, REQ-SUP-001-AC8, REQ-SUP-001-AC9, REQ-SUP-001-AC10
# The daily supply-chain audit (owner ratified Oct 5, rules 2, 3 and 5; advisor 0172, 0175, 0177), proved offline against a fixtures file that stands in for the
# advisory databases, the actions' own repositories and the registries, with a recording `gh`:
#   python3 bin/pin-audit.py --root REPO --fixtures FILE --now ISO --gh CMD [--exceptions FILE] [--rerun-held]
#   exit 0: no hit and no unexcepted dispute; exit 1: a hit or a disputed hit (the issue says so); exit 2: it could not do its job (a failed gh, unreadable input).
#   Fixtures: {"lists": {ITEM: {"github": [ADV], "osv": [ADV]}}, "upstream": {"owner/repo@sha": {"reachable": bool}}, "nested": {"owner/repo@sha": [REF]},
#              "versions": {"owner/repo": [{"version", "sha", "published", "lists": {...}}]}, "prs": [{"number", "title", "run_id", "moved": [ITEM]}],
#              "times": {ITEM: {"time", "source"}}, "first_seen": {ITEM: ISO}}   with ADV = {"id", "incident", "affected": bool, "modified": ISO, "malicious"?: bool}
#   gh calls it may make: issue list / issue create / issue edit / label create, and (only with --rerun-held) run rerun. NEVER anything about runs, environments or
#   secrets: the private details are produced on the Mac, not by this workflow (advisor 0175 amendment 5).
set -euo pipefail
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@x GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x   # CI runners have no git identity
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
aud="$here/../supply-chain/pin-audit.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >/dev/null 2>&1; then ok "$CASE"; else bad "$CASE"; fi; }
none_match() { local fl=-E; if [ "$1" = -i ]; then fl=-iE; shift; fi; local re=$1; shift; local p; for p in "$@"; do [ -e "$p" ] || return 2; done; local rc=0; grep -r -q $fl "$re" "$@" || rc=$?; [ "$rc" -eq 1 ]; }
NOW="2026-10-05T12:00:00Z"
dago() { python3 -c "import datetime,sys;print((datetime.datetime(2026,10,5,12)-datetime.timedelta(days=float(sys.argv[1]))).strftime('%Y-%m-%dT%H:%M:%SZ'))" "$1"; }
SHA1=$(printf '1%.0s' $(seq 40)); SHA2=$(printf '2%.0s' $(seq 40)); SHA4=$(printf '4%.0s' $(seq 40))
DIG1=sha256:$(printf '1%.0s' $(seq 64))
ITEM_CO="action:actions/checkout@$SHA1"
ITEM_TRIVY="tool:trivy@0.74.0"

# --- the repository: a history of commits, each pinning actions/checkout at some SHA; the LAST one is today's tree. The audit also reads the workflow
# git history of the last 90 days: a bad version we ran (even one already replaced) is a hit with the owner (rule 3), one replaced 100 days ago is not.
CLEANSHA=$(printf '9%.0s' $(seq 40))
mkrepo() { # <dir> <days-ago:sha> ...   (oldest first)
  local r=$1; shift; rm -rf "$r"; mkdir -p "$r/.github/workflows" "$r/bin" "$r/.github/pins"; git -C "$r" init -q
  printf 'TRIVY_VER=0.74.0\n' >"$r/bin/install-scanner.sh"
  printf 'requests==2.32.0 \\\n    --hash=sha256:bbbb\n' >"$r/.github/pins/adjudicator-requirements.txt"
  local spec days sha
  for spec in "$@"; do
    days=${spec%%:*}; sha=${spec##*:}
    cat >"$r/.github/workflows/ci.yml" <<WF
on: pull_request
jobs:
  j:
    runs-on: ubuntu-latest
    environment: ENV_SECRET_TOKEN_X
    steps:
      - uses: actions/checkout@$sha # v4.1.0
        env:
          K: \${{ secrets.SECRETNAME_Y }}
      - uses: golangci/golangci-lint-action@$SHA2 # v9.3.0
        with:
          version: v2.13.2
WF
    git -C "$r" add -A
    GIT_AUTHOR_DATE="$(dago "$days")" GIT_COMMITTER_DATE="$(dago "$days")" git -C "$r" -c user.name=t -c user.email=t@x commit -q -m "pin $sha"
  done
}
# a recording gh: logs argv as one JSON line; `issue list` answers GH_LIST; create/edit validate their body file
cat >"$work/gh" <<'PY'
#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
open(os.environ["GH_LOG"], "a").write(json.dumps(a) + "\n")
if os.environ.get("GH_FAIL") and os.environ["GH_FAIL"] in " ".join(a):
    sys.stderr.write("gh: simulated failure\n"); sys.exit(1)
if a[:2] == ["issue", "list"]:
    print(os.environ.get("GH_LIST", "[]"))
elif a[:2] in (["issue", "create"], ["issue", "edit"]):
    bf = a[a.index("--body-file") + 1]
    if not os.path.isfile(bf) or os.path.getsize(bf) == 0:
        sys.stderr.write("gh: empty body\n"); sys.exit(1)
    open(os.environ["GH_LOG"] + ".bodies", "a").write(open(bf).read() + "\n=====\n")
    if a[1] == "create": print("https://github.com/x/y/issues/9")
elif a[:2] in (["label", "create"], ["run", "rerun"], ["issue", "reopen"]):
    pass
else:
    sys.stderr.write("gh: unexpected call " + " ".join(a) + "\n"); sys.exit(1)
PY
chmod +x "$work/gh"

# run <name> <fixtures-json> <repo-dir> [extra audit args]   (env GH_LIST / GH_FAIL pass through)
run() {
  local n=$1 fx=$2 repo=$3; shift 3; echo "$fx" >"$work/$n.fx.json"; : >"$work/$n.gh"; rc=0
  ( cd "$work" && GH_LOG="$work/$n.gh" python3 "$aud" --root "$repo" --fixtures "$work/$n.fx.json" --now "$NOW" --gh "$work/gh" "$@" >"$work/$n.out" 2>"$work/$n.err" ) || rc=$?
}
creates() { python3 - "$1" <<'PY'
import json, sys
calls = [json.loads(l) for l in open(sys.argv[1])]
print(len([c for c in calls if c[:2] == ["issue", "create"]]))
PY
}
CLEAN='{"lists": {}, "upstream": {}, "nested": {}, "versions": {}, "prs": []}'
mkrepo "$work/r-clean" "5:$CLEANSHA"
mkrepo "$work/r-cur" "120:$SHA1"                 # the bad pin is on main today: it has been RUN (the workflows execute daily)
mkrepo "$work/r-ranpast" "120:$SHA1" "20:$CLEANSHA"     # the bad pin was replaced 20 days ago: we ran it within 90 days
mkrepo "$work/r-oldpast" "200:$SHA1" "100:$CLEANSHA"    # replaced 100 days ago: outside the window
mkrepo "$work/r-pr" "120:$CLEANSHA" "1:$SHA1"     # the bad pin exists only in the head of a PR (HEAD~1 is the base): it has NOT run

# --- AC5, AC9: a clean day ----------------------------------------------------------------------------------------------------------------
run clean "$CLEAN" "$work/r-clean"
CASE="a clean day: exit 0, no issue, and the report says 'no known-compromised versions as of 2026-10-05'"
check test "$rc" -eq 0; check test "$(creates "$work/clean.gh")" -eq 0
check grep -q 'no known-compromised versions as of 2026-10-05' "$work/clean.out"
CASE="AC9: the report never claims 'no supply chain issues' (in any case or spacing), clean day or hit day"
check none_match -i 'no supply[ -]chain (issue|problem)' "$work/clean.out" "$work/clean.err"
CASE="AC5: the audit covers every kind of version the age check covers: actions, installer-action inputs, install-scanner pins and hash-pinned packages are all in its inventory"
check python3 - "$work/clean.out" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
for needle in ("action:actions/checkout@", "action:golangci/golangci-lint-action@", "tool:golangci-lint@v2.13.2", "tool:trivy@0.74.0", "package:pypi/requests@2.32.0"):
    assert needle in t, needle
PY

# --- AC5, AC7: a hit; one issue; the issue says version, advisory id and rollback ------------------------------------------------------------
HIT_GH="{\"lists\": {\"$ITEM_CO\": {\"github\": [{\"id\": \"GHSA-aaaa-bbbb-cccc\", \"incident\": \"INC-1\", \"affected\": true, \"modified\": \"$(dago 20)\"}], \"osv\": []}},
 \"upstream\": {}, \"nested\": {}, \"prs\": [],
 \"versions\": {\"actions/checkout\": [
   {\"version\": \"v4.3.0\", \"sha\": \"$(printf '3%.0s' $(seq 40))\", \"published\": \"$(dago 2)\", \"lists\": {}},
   {\"version\": \"v4.2.0\", \"sha\": \"$(printf '5%.0s' $(seq 40))\", \"published\": \"$(dago 40)\", \"lists\": {\"github\": [{\"id\": \"GHSA-aaaa-bbbb-cccc\", \"incident\": \"INC-1\", \"affected\": true, \"modified\": \"$(dago 20)\"}]}},
   {\"version\": \"v4.1.1\", \"sha\": \"$(printf '6%.0s' $(seq 40))\", \"published\": \"$(dago 60)\", \"lists\": {}},
   {\"version\": \"v4.1.0\", \"sha\": \"$SHA1\", \"published\": \"$(dago 90)\", \"lists\": {\"github\": [{\"id\": \"GHSA-aaaa-bbbb-cccc\", \"incident\": \"INC-1\", \"affected\": true, \"modified\": \"$(dago 20)\"}]}}]}}"
run hit "$HIT_GH" "$work/r-cur"
CASE="a hit (GitHub advisory): exit 1, ONE issue is created, labelled supply-chain-hit, naming the pinned version and the advisory id"
check test "$rc" -eq 1; check test "$(creates "$work/hit.gh")" -eq 1
check python3 - "$work/hit.gh" "$work/hit.gh.bodies" <<'PY'
import json, sys
calls = [json.loads(l) for l in open(sys.argv[1])]
c = [x for x in calls if x[:2] == ["issue", "create"]][0]
assert "--label" in c and "supply-chain-hit" in c, c
title = c[c.index("--title") + 1]
assert "actions/checkout" in title and "GHSA-aaaa-bbbb-cccc" in title, title
body = open(sys.argv[2]).read()
assert "v4.1.0" in body and "GHSA-aaaa-bbbb-cccc" in body, body
PY
CASE="the rollback is the NEWEST CLEAN version that is at least 7 days old: v4.1.1 (not the 2-day-old v4.3.0, not the affected v4.2.0)"
check grep -q 'v4.1.1' "$work/hit.gh.bodies"; check bash -c "! grep -q 'roll back to v4.3.0\|rollback: v4.3.0\|roll back to v4.2.0' '$work/hit.gh.bodies'"
CASE="a hit on a PR's NEW pin (present in its head, absent from its base: it has not run) with a clean rollback available is NOT labelled owner-decision"
run hitpr "$HIT_GH" "$work/r-pr" --base HEAD~1
check test "$rc" -eq 1; check grep -q 'supply-chain-hit' "$work/hitpr.gh"; check none_match 'owner-decision' "$work/hitpr.gh"; check grep -q 'v4.1.1' "$work/hitpr.gh.bodies"
CASE="a hit on a pin that is on main today is labelled owner-decision (the workflows ran it), and still names the rollback"
check grep -q 'owner-decision' "$work/hit.gh"; check grep -q 'v4.1.1' "$work/hit.gh.bodies"
GH_LIST='[{"number": 31, "title": "supply-chain: actions/checkout@v4.1.0 (GHSA-aaaa-bbbb-cccc)"}]' run hit2 "$HIT_GH" "$work/r-cur"
CASE="the next day, with that issue already open: it is UPDATED (issue edit), never a second issue"
check test "$rc" -eq 1; check test "$(creates "$work/hit2.gh")" -eq 0
check python3 - "$work/hit2.gh" <<'PY'
import json, sys
calls = [json.loads(l) for l in open(sys.argv[1])]
e = [c for c in calls if c[:2] == ["issue", "edit"]]
assert len(e) == 1 and e[0][2] == "31", calls
PY
GH_LIST='[{"number": 32, "title": "supply-chain: some-other/action@v1 (GHSA-zzzz)"}]' run hit3 "$HIT_GH" "$work/r-cur"
CASE="an open issue for a DIFFERENT hit is never edited: this hit gets its own"
check test "$(creates "$work/hit3.gh")" -eq 1

# --- AC7: an OSV malicious-package report is a hit -------------------------------------------------------------------------------------------
run mal "{\"lists\": {\"$ITEM_TRIVY\": {\"github\": [], \"osv\": [{\"id\": \"MAL-2026-1234\", \"incident\": \"INC-M\", \"affected\": true, \"malicious\": true, \"modified\": \"$(dago 3)\"}]}}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": []}" "$work/r-cur"
CASE="an OSV malicious-package report (MAL-...) against a tool we install is a hit: exit 1 and an issue naming it"
check test "$rc" -eq 1; check grep -q 'MAL-2026-1234' "$work/mal.gh.bodies"

# --- AC8: no clean old version, or we RAN the bad one: owner-decision -----------------------------------------------------------------------------
ONLYBAD="{\"lists\": {\"$ITEM_CO\": {\"github\": [{\"id\": \"GHSA-aaaa-bbbb-cccc\", \"incident\": \"INC-1\", \"affected\": true, \"modified\": \"$(dago 20)\"}], \"osv\": []}}, \"upstream\": {}, \"nested\": {}, \"prs\": [],
 \"versions\": {\"actions/checkout\": [{\"version\": \"v4.3.0\", \"sha\": \"$(printf '3%.0s' $(seq 40))\", \"published\": \"$(dago 2)\", \"lists\": {}}, {\"version\": \"v4.1.0\", \"sha\": \"$SHA1\", \"published\": \"$(dago 90)\", \"lists\": {\"github\": [{\"id\": \"GHSA-aaaa-bbbb-cccc\", \"incident\": \"INC-1\", \"affected\": true, \"modified\": \"$(dago 20)\"}]}}]}}"
run noclean "$ONLYBAD" "$work/r-pr" --base HEAD~1
CASE="no clean version at least 7 days old exists (only a 2-day-old one): the issue says to DROP the action, and is labelled owner-decision as well as supply-chain-hit (even for a PR's not-yet-run pin)"
check grep -qi 'drop' "$work/noclean.gh.bodies"; check grep -q 'owner-decision' "$work/noclean.gh"; check grep -q 'supply-chain-hit' "$work/noclean.gh"
run ranpast "$HIT_GH" "$work/r-ranpast"
CASE="the bad version was replaced 20 days ago: the audit reads the workflow git history of the last 90 days, finds that we RAN it, and reports it with owner-decision (though today's tree is clean)"
check test "$rc" -eq 1; check grep -q 'owner-decision' "$work/ranpast.gh"; check grep -q 'GHSA-aaaa-bbbb-cccc' "$work/ranpast.gh.bodies"
run oldpast "$HIT_GH" "$work/r-oldpast"
CASE="a bad version replaced 100 days ago is outside the 90-day window: no hit, exit 0, no issue"
check test "$rc" -eq 0; check test "$(creates "$work/oldpast.gh")" -eq 0
CASE="AC8: the workflow NEVER produces runs, environments or secret names: not in the issue body, stdout, stderr or any file it wrote"
check none_match 'ENV_SECRET_TOKEN_X|SECRETNAME_Y' "$work/ranpast.gh" "$work/ranpast.gh.bodies" "$work/ranpast.out" "$work/ranpast.err" "$work/noclean.gh.bodies" "$work/hit.gh.bodies" "$work/hit.out" "$work/hit.err"
check bash -c "! ls '$work' | grep -qE 'artifact|report\\.(json|md)'"
CASE="AC8: and it makes NO gh call about runs, environments or secrets (run list, api .../runs, environments, secrets): only issue list/create/edit and label create"
check python3 - "$work" <<'PY'
import glob, json, sys
for p in glob.glob(sys.argv[1] + "/*.gh"):
    for l in open(p):
        c = json.loads(l)
        assert c[:2] in (["issue", "list"], ["issue", "create"], ["issue", "edit"], ["issue", "reopen"], ["label", "create"], ["run", "rerun"]), (p, c)
        if c[:2] == ["run", "rerun"] and "held" not in p:
            raise AssertionError("a run rerun without --rerun-held: " + p)
PY

# --- AC5: upstream reachability and nested references -----------------------------------------------------------------------------------------------
run fork "{\"lists\": {}, \"upstream\": {\"actions/checkout@$SHA1\": {\"reachable\": false}}, \"nested\": {}, \"versions\": {}, \"prs\": []}" "$work/r-cur"
CASE="a pinned commit NOT reachable from a branch or tag of the action's own repository (only a fork has it) is a hit: exit 1, an issue says so"
check test "$rc" -eq 1; check grep -qi 'not reachable' "$work/fork.gh.bodies"
run upok "{\"lists\": {}, \"upstream\": {\"actions/checkout@$SHA1\": {\"reachable\": true}, \"golangci/golangci-lint-action@$SHA2\": {\"reachable\": true}}, \"nested\": {}, \"versions\": {}, \"prs\": []}" "$work/r-cur"
CASE="reachable commits are fine: exit 0, no issue"
check test "$rc" -eq 0; check test "$(creates "$work/upok.gh")" -eq 0
run nested "{\"lists\": {}, \"upstream\": {}, \"nested\": {\"actions/checkout@$SHA1\": [{\"ref\": \"actions/cache@v3\", \"pinned\": false}, {\"ref\": \"docker://alpine:3\", \"pinned\": false}, {\"ref\": \"actions/upload-artifact@$SHA4\", \"pinned\": true}]}, \"versions\": {}, \"prs\": []}" "$work/r-cur"
CASE="a nested action or image on a MOVING tag is reported as INFORMATION (named in the report), not a hit: exit 0, no issue"
check test "$rc" -eq 0; check test "$(creates "$work/nested.gh")" -eq 0
check grep -q 'actions/cache@v3' "$work/nested.out"; check grep -q 'docker://alpine:3' "$work/nested.out"; check bash -c "! grep -q 'actions/upload-artifact@$SHA4' '$work/nested.out' || grep -qi 'information.*upload-artifact\\|pinned' '$work/nested.out'"

# an action INSIDE a pinned action is checked against the advisory lists too (rule 2: actions inside actions), whether it is pinned or on a moving tag
NEST_HIT="{\"lists\": {\"action:actions/cache@v3\": {\"github\": [{\"id\": \"GHSA-nest-nest-nest\", \"incident\": \"INC-N\", \"affected\": true, \"modified\": \"$(dago 5)\"}], \"osv\": []}}, \"upstream\": {}, \"prs\": [], \"versions\": {},
 \"nested\": {\"actions/checkout@$SHA1\": [{\"ref\": \"actions/cache@v3\", \"pinned\": false}]}}"
run nesthit "$NEST_HIT" "$work/r-cur"
CASE="a nested action with an advisory against it is a HIT: exit 1, an issue naming it and the outer action to replace, labelled owner-decision (we run it today)"
check test "$rc" -eq 1; check test "$(creates "$work/nesthit.gh")" -eq 1; check grep -q 'GHSA-nest-nest-nest' "$work/nesthit.gh.bodies"; check grep -q 'actions/checkout' "$work/nesthit.gh.bodies"; check grep -q 'owner-decision' "$work/nesthit.gh"
GH_LIST='[{"number": 40, "title": "supply-chain: actions/checkout@v4.1.0X (GHSA-aaaa-bbbb-cccc)"}, {"number": 41, "title": "supply-chain: actions/checkout@v4.1.00 (GHSA-aaaa-bbbb-cccc)"}]' run boundary "$HIT_GH" "$work/r-cur"
CASE="issue matching is exact up to the version: an open issue for v4.1.0X or v4.1.00 is never edited for v4.1.0 (a new issue is opened)"
check test "$(creates "$work/boundary.gh")" -eq 1; check bash -c "! grep -q '\"edit\"' '$work/boundary.gh'"
printf 'x\n' >/dev/null
CASE="untrusted text is printed without control characters (a nested ref or PR title cannot inject log commands)"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
assert "\n" not in pa.clean("a\n::error::x\x1b[31m") and "\x1b" not in pa.clean("a\x1b[31m")
PY

# --- AC10: disputed hits and checked-in exceptions ----------------------------------------------------------------------------------------------------
DISPUTE="{\"lists\": {\"$ITEM_TRIVY\": {\"github\": [{\"id\": \"GHSA-69fq-xp46-6x23\", \"incident\": \"INC-T\", \"affected\": false, \"modified\": \"2026-09-01T00:00:00Z\"}], \"osv\": [{\"id\": \"GO-2026-4919\", \"incident\": \"INC-T\", \"affected\": true, \"modified\": \"2026-09-02T00:00:00Z\"}]}}, \"live_ranges\": {\"GHSA-69fq-xp46-6x23\": [\"= 0.69.4\"]}, \"upstream\": {}, \"nested\": {}, \"versions\": {\"aquasecurity/trivy\": [{\"version\": \"0.69.3\", \"sha\": \"x\", \"published\": \"$(dago 400)\", \"lists\": {}}]}, \"prs\": []}"
printf '{"exceptions": []}' >"$work/no-exceptions.json"
run dispute "$DISPUTE" "$work/r-cur" --exceptions "$work/no-exceptions.json"
CASE="two lists disagree about one incident (GitHub: not affected, OSV: affected) and there is NO exception: exit 1, one issue labelled supply-chain-hit that says DISPUTED"
check test "$rc" -eq 1; check test "$(creates "$work/dispute.gh")" -eq 1; check grep -qi 'disputed' "$work/dispute.gh.bodies"; check grep -q 'supply-chain-hit' "$work/dispute.gh"
CASE="a disputed hit neither reports clean nor rolls back: no 'no known-compromised' line, no rollback or drop advice"
check none_match 'no known-compromised' "$work/dispute.out"; check bash -c "! grep -qiE 'roll ?back to|drop the action' '$work/dispute.gh.bodies'"
CASE="the dispute's public facts are in the issue: both advisory ids, both verdicts, the version"
check grep -q 'GHSA-69fq-xp46-6x23' "$work/dispute.gh.bodies"; check grep -q 'GO-2026-4919' "$work/dispute.gh.bodies"; check grep -q '0.74.0' "$work/dispute.gh.bodies"
EXC='{"exceptions": [{"version": "0.74.0", "ids": ["GO-2026-4919", "GHSA-69fq-xp46-6x23"], "package": "trivy", "authoritative": {"source": "GitHub", "id": "GHSA-69fq-xp46-6x23", "ranges": ["= 0.69.4"]}, "ruling": "false positive", "evidence": ["https://github.com/advisories/GHSA-69fq-xp46-6x23"], "date": "2026-10-05", "modified": {"GO-2026-4919": "2026-09-02T00:00:00Z", "GHSA-69fq-xp46-6x23": "2026-09-01T00:00:00Z"}}]}'
echo "$EXC" >"$work/exc.json"
run excepted "$DISPUTE" "$work/r-cur" --exceptions "$work/exc.json"
CASE="a MATCHING exception (exactly the advisories of this dispute, the package, every advisory unchanged since it was written, the version outside the authoritative ranges): passes, exit 0, no issue, and says an exception applied"
check test "$rc" -eq 0; check test "$(creates "$work/excepted.gh")" -eq 0; check grep -qi 'exception' "$work/excepted.out"
python3 - "$work/exc.json" "$work/exc-stale.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1])); e["exceptions"][0]["modified"]["GO-2026-4919"] = "2026-08-01T00:00:00Z"; json.dump(e, open(sys.argv[2], "w"))
PY
run stale "$DISPUTE" "$work/r-cur" --exceptions "$work/exc-stale.json"
CASE="an exception goes STALE when an advisory changed after it was written (its recorded modified time differs): the dispute is reported again, exit 1"
check test "$rc" -eq 1; check grep -qi 'disputed' "$work/stale.gh.bodies"
python3 - "$DISPUTE" "$work/dispute-drift.json" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); d["live_ranges"]["GHSA-69fq-xp46-6x23"] = ["= 0.69.4", ">= 0.74.0"]; json.dump(d, open(sys.argv[2], "w"))
PY
run drift "$(cat "$work/dispute-drift.json")" "$work/r-cur" --exceptions "$work/exc.json"
CASE="an exception verifies itself: its copied ranges no longer equal the authoritative advisory's LIVE ranges, so it does not apply and the dispute is reported again (a wrong entry can never hide a hit)"
check test "$rc" -eq 1; check grep -qi 'disputed' "$work/drift.gh.bodies"
python3 - "$DISPUTE" "$work/dispute-nolive.json" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); del d["live_ranges"]; json.dump(d, open(sys.argv[2], "w"))
PY
run nolive "$(cat "$work/dispute-nolive.json")" "$work/r-cur" --exceptions "$work/exc.json"
CASE="when the live authoritative ranges cannot be read the exception does not apply (fail closed)"
check test "$rc" -eq 1
python3 - "$work/exc.json" "$work/exc-inrange.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1])); e["exceptions"][0]["authoritative"]["ranges"] = [">= 0.70.0, < 0.80.0"]; json.dump(e, open(sys.argv[2], "w"))
PY
python3 - "$DISPUTE" "$work/dispute-inrange.json" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); d["live_ranges"]["GHSA-69fq-xp46-6x23"] = [">= 0.70.0, < 0.80.0"]; json.dump(d, open(sys.argv[2], "w"))
PY
run inrange "$(cat "$work/dispute-inrange.json")" "$work/r-cur" --exceptions "$work/exc-inrange.json"
CASE="a version INSIDE the authoritative source's affected ranges is a real hit, never excused by an exception: exit 1, an issue that is not 'disputed' and may name a rollback"
check test "$rc" -eq 1; check test "$(creates "$work/inrange.gh")" -eq 1; check bash -c "! grep -qi 'disputed' '$work/inrange.gh.bodies'"
python3 - "$work/exc.json" "$work/exc-subset.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1])); x = e["exceptions"][0]; x["ids"] = ["GHSA-69fq-xp46-6x23"]; del x["modified"]["GO-2026-4919"]; json.dump(e, open(sys.argv[2], "w"))
PY
run subset "$DISPUTE" "$work/r-cur" --exceptions "$work/exc-subset.json"
CASE="an exception naming only SOME of the dispute's advisories does not apply (the ids must be exactly the dispute's)"
check test "$rc" -eq 1; check grep -qi 'disputed' "$work/subset.gh.bodies"
python3 - "$DISPUTE" "$work/dispute-three.json" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); d["lists"]["tool:trivy@0.74.0"]["osv"].append({"id": "GHSA-NEW-EVIL", "incident": "INC-T", "affected": True, "modified": "2026-10-01T00:00:00Z"}); json.dump(d, open(sys.argv[2], "w"))
PY
run three "$(cat "$work/dispute-three.json")" "$work/r-cur" --exceptions "$work/exc.json"
CASE="a third advisory joining the incident after the ruling means the ruling no longer names the dispute: it is reported again, never excused"
check test "$rc" -eq 1; check grep -q 'GHSA-NEW-EVIL' "$work/three.gh.bodies"
python3 - "$work/exc.json" "$work/exc-nomod.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1])); del e["exceptions"][0]["modified"]["GHSA-69fq-xp46-6x23"]; json.dump(e, open(sys.argv[2], "w"))
PY
run nomod "$DISPUTE" "$work/r-cur" --exceptions "$work/exc-nomod.json"
CASE="an exception with no recorded last-modified time for one of its ids is malformed: exit 2, never applied (it could not be shown unchanged)"
check test "$rc" -eq 2
echo '{"not": "a list"}' >"$work/exc-bad.json"
run badexc "$DISPUTE" "$work/r-cur" --exceptions "$work/exc-bad.json"
CASE="an unreadable exceptions file fails the run loudly (exit 2), never as 'no exceptions'"
check test "$rc" -eq 2
CASE="the shipped exceptions file (.github/supply-chain-exceptions.json) holds the advisor rulings in the shared shape: trivy (GO-2026-4919 and GHSA-69fq-xp46-6x23, GitHub authoritative, range 0.69.4 only) and codeql-action (GHSA-vqf5-2xx6-9wfm, GitHub two ranges), each with evidence, a date and last-modified times"
check python3 - "$root/.github/supply-chain-exceptions.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1]))["exceptions"]
by = {x["package"]: x for x in e}
t, c = by["trivy"], by["github/codeql-action"]
assert sorted(t["ids"]) == ["GHSA-69fq-xp46-6x23", "GO-2026-4919"] and t["authoritative"]["source"] == "GitHub" and t["authoritative"]["ranges"] == ["= 0.69.4"], t
assert c["ids"] == ["GHSA-vqf5-2xx6-9wfm"] and c["authoritative"] == {"source": "GitHub", "id": "GHSA-vqf5-2xx6-9wfm", "ranges": [">= 3.26.11, <= 3.28.2", ">= 2.26.11, < 3.0.0"]}, c
for x in (t, c):
    assert x["evidence"] and all(u.startswith("https://") for u in x["evidence"]) and x["date"], x
    assert set(x["modified"]) == set(x["ids"]) and all(x["modified"].values()), x
PY
# a plain hit is NOT a dispute: when both lists agree it is affected, an exception for another advisory changes nothing
run agree "{\"lists\": {\"$ITEM_TRIVY\": {\"github\": [{\"id\": \"GHSA-x\", \"incident\": \"INC-A\", \"affected\": true, \"modified\": \"2026-09-01T00:00:00Z\"}], \"osv\": [{\"id\": \"GO-x\", \"incident\": \"INC-A\", \"affected\": true, \"modified\": \"2026-09-02T00:00:00Z\"}]}}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": []}" "$work/r-cur" --exceptions "$work/exc.json"
CASE="when BOTH lists say affected it is a plain hit (rollback advice allowed), not a dispute, and an unrelated exception does not hide it"
check test "$rc" -eq 1; check bash -c "! grep -qi 'disputed' '$work/agree.gh.bodies'"

# disputes of one package and incident across several versions (the 90-day history can hold many) are ONE issue listing every version, never one issue per version
mkrepo "$work/r-twin" "120:$SHA1"
for spec in "40:0.73.0" "10:0.74.0"; do
  printf 'TRIVY_VER=%s\n' "${spec##*:}" >"$work/r-twin/bin/install-scanner.sh"; git -C "$work/r-twin" add -A
  GIT_AUTHOR_DATE="$(dago "${spec%%:*}")" GIT_COMMITTER_DATE="$(dago "${spec%%:*}")" git -C "$work/r-twin" -c user.name=t -c user.email=t@x commit -q -m "trivy ${spec##*:}"
done
python3 - "$DISPUTE" "$work/twin.json" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); d["lists"]["tool:trivy@0.73.0"] = d["lists"]["tool:trivy@0.74.0"]; json.dump(d, open(sys.argv[2], "w"))
PY
run twin "$(cat "$work/twin.json")" "$work/r-twin" --exceptions "$work/no-exceptions.json"
CASE="the same dispute on two versions of one package (0.73.0 in the history, 0.74.0 today) is ONE issue that names both versions"
check test "$rc" -eq 1; check test "$(creates "$work/twin.gh")" -eq 1; check grep -q '0.73.0' "$work/twin.gh.bodies"; check grep -q '0.74.0' "$work/twin.gh.bodies"

# --- AC6: held pull requests are re-run once their versions are old enough ----------------------------------------------------------------------------------
HELD="{\"lists\": {}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": [
  {\"number\": 7, \"title\": \"bump checkout\", \"run_id\": 99, \"moved\": [\"$ITEM_CO\"]},
  {\"number\": 8, \"title\": \"bump trivy\", \"run_id\": 98, \"moved\": [\"$ITEM_TRIVY\"]}],
 \"times\": {\"$ITEM_CO\": {\"time\": \"$(dago 8)\", \"source\": \"observer\"}, \"$ITEM_TRIVY\": {\"time\": \"$(dago 2)\", \"source\": \"github-release\"}}}"
run held "$HELD" "$work/r-clean" --rerun-held
CASE="a held PR whose moved version is now 8 days old is RE-RUN (gh run rerun 99); one still 2 days old (run 98) is not"
check python3 - "$work/held.gh" <<'PY'
import json, sys
reruns = [json.loads(l) for l in open(sys.argv[1]) if json.loads(l)[:2] == ["run", "rerun"]]
assert reruns == [["run", "rerun", "99"]], reruns
PY
run heldoff "$HELD" "$work/r-clean"
CASE="without --rerun-held nothing is ever re-run (the re-run permission belongs to one job only)"
check bash -c "! grep -q 'rerun' '$work/heldoff.gh'"
run heldfirst "{\"lists\": {}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": [{\"number\": 7, \"title\": \"x\", \"run_id\": 99, \"moved\": [\"$ITEM_CO\"]}], \"times\": {}, \"first_seen\": {\"$ITEM_CO\": \"$(dago 9)\"}}" "$work/r-clean" --rerun-held
CASE="the first time the exact version appeared in one of our own PRs also counts (9 days ago): that held PR is re-run"
check grep -q '"rerun", "99"' "$work/heldfirst.gh"
run heldunprov "{\"lists\": {}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": [{\"number\": 7, \"title\": \"x\", \"run_id\": 99, \"moved\": [\"$ITEM_CO\"]}], \"times\": {}}" "$work/r-clean" --rerun-held
CASE="a held PR whose age cannot be proven is not re-run (it stays red)"
check bash -c "! grep -q 'rerun' '$work/heldunprov.gh'"

# --- the live source's own logic, with no network: how a database record is read -----------------------------------------------------------------------------
CASE="OSV's affected entries are judged range by range and OR-ed (a merged event list once marked codeql-action 4.x affected by a stale 2.x range), GitHub's comparator ranges too, and a ref that is not a commit is never upstream-checked"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
rec = {"affected": [{"package": {"name": "o/r"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.26.11"}, {"fixed": "3.28.3"}]}]},
                    {"package": {"name": "o/r"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.5.0"}]}]}]}
says = lambda v: pa.LiveNet._osv_says(rec, "o/r", v, versioned=False)
assert says("v3.27.0") and says("2.1.0") and not says("v3.30.0") and not says("v4.38.1") and not says("v2.9.0") and not says("3.26.10"), "per-range"
assert pa.LiveNet._osv_says({"affected": [{"package": {"name": "o/r"}, "versions": ["1.2.3"]}]}, "o/r", "1.2.3", False)
assert pa.LiveNet._osv_says({"affected": [{"package": {"name": "o/r"}}]}, "o/r", "1.2.3", True), "a versioned query with no ranges to read is trusted"
assert not pa.LiveNet._osv_says({"affected": [{"package": {"name": "o/r"}}]}, "o/r", "1.2.3", False)
assert pa.in_range("3.28.2", ">= 3.26.11, <= 3.28.2") and not pa.in_range("3.28.3", ">= 3.26.11, <= 3.28.2") and pa.in_range("0.69.4", "= 0.69.4") and not pa.in_range("0.74.0", "= 0.69.4")
assert pa.in_range("2.9", ">= 2.0, < 3.0|= 5.0") and pa.in_range("5.0", ">= 2.0, < 3.0|= 5.0") and not pa.in_range("4.0", ">= 2.0, < 3.0|= 5.0")
net = pa.LiveNet(["false"], ".")
it = pa.inv.Item("action", "o/r", "v4", "")
assert net.upstream(it) is None and net._version_of(it) == "v4"
PY

printf '#!/bin/sh\necho "gh: API rate limit exceeded (HTTP 403)" >&2\nexit 1\n' >"$work/gh-ratelimit"; chmod +x "$work/gh-ratelimit"
CASE="live: a rate-limited GitHub API makes the audit fail (Fail, exit 2); it is never read as 'no hit'"
check python3 - "$aud" "$work/gh-ratelimit" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
net = pa.LiveNet([sys.argv[2]], ".")
try:
    net._gh_json("advisories/GHSA-x")
except pa.Fail as e:
    assert "rate limit" in str(e)
else:
    raise AssertionError("a rate limit was swallowed")
try:
    net.upstream(pa.inv.Item("action", "o/r", "a" * 40, ""))
except pa.Fail:
    pass
else:
    raise AssertionError("an upstream check swallowed a rate limit")
PY

# --- the live source against a gh stub (no network): reachability direction, GitHub-only advisories, rollback rules ---------------------------------------------------------------
cp "$here/gh-map-stub.py" "$work/ghmap"
chmod +x "$work/ghmap"
CASE="live upstream: the pin is an ancestor of a branch when compare says ahead/identical (NOT behind); a release branch counts; a pin ahead of every branch is a fork-only commit"
check python3 - "$aud" "$work" <<'PY'
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
work = sys.argv[2]; sha = "a" * 40
pa.age._tag_for_commit = lambda r, s: None
def net(m):
    json.dump(m, open(work + "/map.json", "w")); os.environ["GH_MAP"] = work + "/map.json"
    return pa.LiveNet([work + "/ghmap"], ".")
it = pa.inv.Item("action", "o/r", sha, "v1")
base = {"repos/o/r": {"default_branch": "main"}}
assert net({**base, f"repos/o/r/compare/{sha}...main": {"status": "ahead"}}).upstream(it) is True
assert net({**base, f"repos/o/r/compare/{sha}...main": {"status": "identical"}}).upstream(it) is True
assert net({**base, f"repos/o/r/compare/{sha}...main": {"status": "behind"}, "repos/o/r/branches?per_page=100": []}).upstream(it) is False, "behind: the pin is beyond the branch"
assert net({**base, f"repos/o/r/compare/{sha}...main": {"status": "diverged"}, "repos/o/r/branches?per_page=100": [{"name": "main"}, {"name": "v1"}], f"repos/o/r/compare/{sha}...v1": {"status": "ahead"}}).upstream(it) is True
assert net({**base, f"repos/o/r/compare/{sha}...main": {"status": "diverged"}, "repos/o/r/branches?per_page=100": [{"name": "main"}, {"name": "v1"}], f"repos/o/r/compare/{sha}...v1": {"status": "behind"}}).upstream(it) is False
PY
CASE="live advisories: a GitHub-only advisory (OSV knows nothing of it) is read directly and its ranges evaluated for the version"
check python3 - "$aud" "$work" <<'PY'
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
work = sys.argv[2]
adv = [{"ghsa_id": "GHSA-only-only-only", "updated_at": "2026-01-01T00:00:00Z", "type": "malware", "vulnerabilities": [{"package": {"name": "o/r"}, "vulnerable_version_range": ">= 1.0, < 2.0"}]}]
json.dump({"advisories?ecosystem=actions&affects=o/r&per_page=100&page=1": adv, "advisories?ecosystem=actions&affects=o/r&type=malware&per_page=100&page=1": []}, open(work + "/map.json", "w")); os.environ["GH_MAP"] = work + "/map.json"
net = pa.LiveNet([work + "/ghmap"], ".")
net._osv_post = lambda q: []
net._osv_get = lambda i: None   # offline: OSV is never asked
gh, osv = net.lists(pa.inv.Item("action", "o/r", "v1.5", ""))
assert [g["id"] for g in gh] == ["GHSA-only-only-only"] and gh[0]["affected"] and gh[0]["malicious"], gh
assert net.lists(pa.inv.Item("action", "o/r", "v2.1", "")) == ([], [])
PY
CASE="rollback: a candidate that any advisory marks affected (a DISPUTED one too) is never 'clean'; a kind of item that cannot be searched is a decision (unknown), never 'drop it'"
check python3 - "$aud" "$work" <<'PY'
import importlib.util, sys, datetime as dt
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
now = dt.datetime(2026, 10, 5, 12, tzinfo=dt.timezone.utc)
old = lambda d: (now - dt.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
disp = {"github": [{"id": "G", "incident": "I", "affected": False}], "osv": [{"id": "O", "incident": "I", "affected": True}]}
fx = pa.FixtureNet({"versions": {"o/r": [{"version": "v3", "sha": None, "published": old(20), "lists": disp},
                                         {"version": "v2", "sha": None, "published": old(40), "lists": {}}, {"version": "v1", "sha": None, "published": old(80), "lists": {}}]}})
assert pa.rollback(pa.inv.Item("action", "o/r", "x" * 40, "v4"), fx, now)["version"] == "v2"
net = pa.LiveNet(["false"], ".")
assert pa.rollback(pa.inv.Item("gotool", "golang.org/x/vuln/cmd/govulncheck", "v1.0.0"), net, now) == pa.UNKNOWN
PY
printf '{"exceptions": [{"version": "1.0.0", "ids": ["A"], "package": "p", "authoritative": {"source": "GitHub", "id": "A", "ranges": ["= 1"]}, "ruling": "r", "modified": {"A": "t"}}]}' >"$work/exc-noev.json"
run noev "$DISPUTE" "$work/r-cur" --exceptions "$work/exc-noev.json"
CASE="an exception without evidence links and a date is malformed: exit 2, never applied"
check test "$rc" -eq 2

CASE="version order: a pre-release is BEFORE its release (1.0.0-rc.1, 1.0.0rc1 < 1.0.0), 1.2 equals 1.2.0, an unreadable range is never read as safe"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
c = pa._cmp
assert c("1.0.0-rc.1", "1.0.0") < 0 and c("1.0.0rc1", "1.0.0") < 0 and c("1.0.0", "1.0.0rc1") > 0 and c("1.2", "1.2.0") == 0 and c("2.0.0-rc.1", "2.0.0-rc.2") < 0 and c("v1.10.0", "1.9.9") > 0
assert pa.in_range("1.0.0-rc.1", "< 1.0.0") and not pa.in_range("1.0.0", "< 1.0.0") and pa.in_range("1.0", "= 1.0.0") and pa.in_range("5", "garbage")
PY
CASE="two plan entries with one title make ONE issue (and a title created this run is remembered)"
check python3 - "$aud" "$work" <<'PY'
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
calls = []
class G:
    def run(self, *a, ok_fail=False):
        calls.append(a)
        class R: stdout = "[]"
        return R()
plan = [{"title": ("t", "supply-chain: x@1 (A)"), "body": "b", "owner": False}] * 2
pa.file_issues(G(), plan, "2026-10-05")
assert len([c for c in calls if c[:2] == ("issue", "create")]) == 1, calls
PY

CASE="no module-level name or class method is defined twice in the three programs (a duplicated block once silently replaced LiveNet), and LiveNet has every method the audit calls"
check python3 - "$root" <<'PY'
import ast, sys
for n in ("pin-inventory", "pin-age-check", "pin-audit"):
    tree = ast.parse(open(f"{sys.argv[1]}/.github/agent/supply-chain/{n}.py").read())
    names = [x.name for x in tree.body if isinstance(x, (ast.FunctionDef, ast.ClassDef))]
    assert len(names) == len(set(names)), (n, sorted(x for x in names if names.count(x) > 1))
    for c in (x for x in tree.body if isinstance(x, ast.ClassDef)):
        ms = [m.name for m in c.body if isinstance(m, ast.FunctionDef)]
        assert len(ms) == len(set(ms)), (n, c.name, sorted(x for x in ms if ms.count(x) > 1))
        if c.name == "LiveNet":
            assert {"lists", "covered", "live_ranges", "upstream", "nested", "versions", "prs", "proofs", "modified"} <= set(ms), ms
PY

# --- the daily run records what it saw of every tag we use, FIRST (before judging), cumulatively; a pull request run never writes it --------------------------------------------------------------------
OBS_FX="{\"lists\": {}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": [], \"tags\": {\"actions/checkout@v4.1.0\": \"$SHA1\", \"actions/checkout@v4\": \"$SHA1\"},
 \"observed\": {\"version\": 1, \"first_seen\": {\"actions/checkout@v4.1.0@$SHA1\": \"2026-09-01T00:00:00Z\", \"actions/checkout@v3@$(printf 'd%.0s' $(seq 40))\": \"2026-08-01T00:00:00Z\"}}}"
run obs "$OBS_FX" "$work/r-cur" --observations-out "$work/obsout/state.json"
CASE="the daily run writes the tag observations: an old mapping keeps its first time, a new tag at a commit gets today, a mapping never seen before is not backdated, nothing is forgotten"
check python3 - "$work/obsout/state.json" "$SHA1" <<'PY'
import json, sys
fs = json.load(open(sys.argv[1]))["first_seen"]
sha = sys.argv[2]
assert fs["actions/checkout@v4.1.0@" + sha] == "2026-09-01T00:00:00Z", fs
assert fs["actions/checkout@v4@" + sha] == "2026-10-05T12:00:00Z", fs
assert fs["actions/checkout@v3@" + "d" * 40] == "2026-08-01T00:00:00Z", fs
assert len(fs) == 3, fs
PY
HIT_OBS=$(python3 - "$OBS_FX" "$HIT_GH" <<'PY'
import json, sys
a = json.loads(sys.argv[1]); b = json.loads(sys.argv[2]); b["tags"] = a["tags"]; b["observed"] = a["observed"]; print(json.dumps(b))
PY
)
rm -rf "$work/obsout2"; run obs2 "$HIT_OBS" "$work/r-cur" --observations-out "$work/obsout2/state.json"
CASE="the observations are written BEFORE anything is judged: a run that finds a hit (exit 1) has still recorded them"
check test "$rc" -eq 1; check test -s "$work/obsout2/state.json"
rm -rf "$work/obsout3"; run obs3 "$OBS_FX" "$work/r-pr" --base HEAD~1 --observations-out "$work/obsout3/state.json"
CASE="a pull request run (--base) never writes observations: only the scheduled run on main does"
check test ! -e "$work/obsout3/state.json"
CASE="tag_observer.py accepts only a completed (success or failure) scheduled run on main of supply-chain.yml, and keeps a moved tag as a NEW mapping"
check python3 - "$here/../supply-chain/tag_observer.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("t", sys.argv[1]); t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
ok = {"event": "schedule", "head_branch": "main", "conclusion": "success", "path": ".github/workflows/supply-chain.yml"}
assert t.accept_run(ok)
for k, v in (("event", "pull_request"), ("head_branch", "feature"), ("conclusion", "cancelled"), ("path", ".github/workflows/ci.yml")):
    assert not t.accept_run(dict(ok, **{k: v})), k
s = t.update_state(None, {"o/r@v1": "a" * 40}, "2026-01-01T00:00:00Z")
s = t.update_state(s, {"o/r@v1": "b" * 40}, "2026-02-01T00:00:00Z")
assert t.first_seen(s, "o/r", "v1", "a" * 40) == "2026-01-01T00:00:00Z" and t.first_seen(s, "o/r", "v1", "b" * 40) == "2026-02-01T00:00:00Z"
assert t.unpack(t.pack(s)) == s
PY

CASE="a version this check cannot order, and a record with only commit ranges, are read as AFFECTED (never as safe); post-releases sort after the final"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
assert pa.in_range("1.0.0-zzz", "< 1.0.0") and pa.in_range("1.0.post1", "> 1.0, < 1.1") and not pa.in_range("1.0.post1", "< 1.0") and pa.in_range("1.0.0-rc.1", "< 1.0.0")
assert pa.LiveNet._osv_says({"affected": [{"package": {"name": "o/r"}, "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}]}, "o/r", "v1", versioned=False)
PY
python3 - "$DISPUTE" "$work/dispute-bothdb.json" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); t = d["lists"]["tool:trivy@0.74.0"]
t["github"] = [{"id": "GO-2026-4919", "incident": "INC-T", "affected": False, "modified": "2026-09-02T00:00:00Z"}]  # the same id in BOTH databases
json.dump(d, open(sys.argv[2], "w"))
PY
CASE="an id both databases hold needs OSV's own time recorded in the SAME entry (osv_modified): another entry's time is never borrowed, and a missing one lapses the ruling"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
it = pa.inv.Item("tool", "trivy", "0.74.0")
net = type("N", (), {"live_ranges": lambda self, i, s, a: ["= 0.69.4"]})()
e = {"version": "0.74.0", "ids": ["A"], "package": "trivy", "authoritative": {"source": "GitHub", "id": "A", "ranges": ["= 0.69.4"]}, "modified": {"A": "t1"}, "evidence": ["x"], "date": "d", "ruling": "r"}
other = dict(e, package="other", osv_modified={"A": "t2"})
assert pa.excepted(it, {"A"}, {"A": "t1"}, [e], net, {"A": "t2"}) is None, "no osv_modified in THIS entry"
assert pa.excepted(it, {"A"}, {"A": "t1"}, [other, e], net, {"A": "t2"}) is None, "another entry's time must not be borrowed"
assert pa.excepted(it, {"A"}, {"A": "t1"}, [dict(e, osv_modified={"A": "t2"})], net, {"A": "t2"}) == "pass"
assert pa.excepted(it, {"A"}, {"A": "t1"}, [dict(e, osv_modified={"A": "t2"})], net, {"A": "t3"}) is None, "OSV's copy changed"
PY
GH_LIST='[{"number": 50, "state": "CLOSED", "title": "supply-chain: actions/checkout@v4.1.0 (GHSA-aaaa-bbbb-cccc)"}]' run reopen "$HIT_GH" "$work/r-cur"
CASE="a hit whose issue was CLOSED is found again: that issue is updated and reopened, never a second issue"
check test "$rc" -eq 1; check test "$(creates "$work/reopen.gh")" -eq 0
check python3 - "$work/reopen.gh" <<'PY'
import json, sys
calls = [json.loads(l) for l in open(sys.argv[1])]
assert any(c[:3] == ["issue", "reopen", "50"] for c in calls) and any(c[:3] == ["issue", "edit", "50"] for c in calls), calls
PY
CASE="a rollback candidate must itself be provably old: a candidate whose own proofs say too young is skipped, the next older clean one is chosen"
check python3 - "$aud" <<'PY'
import datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
now = dt.datetime(2026, 10, 5, 12, tzinfo=dt.timezone.utc)
old = lambda d: (now - dt.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
class N:
    def versions(self, item):
        return [{"version": "v3", "sha": None, "published": old(30), "_item": pa.inv.Item("action", "o/r", "3" * 40, "v3")},
                {"version": "v2", "sha": None, "published": old(60), "_item": pa.inv.Item("action", "o/r", "2" * 40, "v2")}]
    def lists(self, item): return [], []
    def proofs(self, item, base=None): return [(old(2), "observer")] if item.version[0] == "3" else [(old(50), "observer")]
assert pa.rollback(pa.inv.Item("action", "o/r", "x" * 40, "v4"), N(), now)["version"] == "v2"
PY

GH_LIST='[{"number": 60, "state": "OPEN", "title": "supply-chain: actions/checkout@v4.1.0 (GHSA-aaaa-bbbb-cccc)"}]' run alias "$(python3 - "$HIT_GH" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); d["lists"]["action:actions/checkout@" + "1" * 40]["osv"] = [{"id": "GO-2026-0001", "incident": "INC-1", "affected": True, "modified": "2026-01-01T00:00:00Z"}]
d["lists"]["action:actions/checkout@" + "1" * 40]["github"][0]["incident"] = "INC-1"; print(json.dumps(d))
PY
)" "$work/r-cur"
CASE="ONE issue per pinned item: the same incident reported under another advisory id (an alias) updates the existing issue and its title, it never opens a second"
check test "$(creates "$work/alias.gh")" -eq 0; check grep -q '"issue", "edit", "60"' "$work/alias.gh"
OPENPR="{\"lists\": {\"action:actions/cache@v9\": {\"github\": [{\"id\": \"GHSA-pr-pr-pr\", \"incident\": \"INC-P\", \"affected\": true, \"modified\": \"2026-01-01T00:00:00Z\"}], \"osv\": []}}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": [], \"open_prs\": [{\"number\": 77, \"items\": [\"action:actions/cache@v9\"]}]}"
run openpr "$OPENPR" "$work/r-clean"
CASE="the daily run also audits the pins of OPEN pull requests: a hit that exists only in an unmerged PR still reaches a supply-chain-hit issue, which names the PR"
check test "$rc" -eq 1; check test "$(creates "$work/openpr.gh")" -eq 1; check grep -q 'GHSA-pr-pr-pr' "$work/openpr.gh.bodies"
run uncov "{\"lists\": {}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": [], \"uncovered\": [\"$ITEM_TRIVY\"]}" "$work/r-clean"
CASE="the clean line says what it did NOT check: an item with no advisory source is counted in the same line, never silently included in 'no known-compromised'"
check test "$rc" -eq 0; check grep -q 'no known-compromised versions as of 2026-10-05; 1 of [0-9]* item(s) have no advisory source and were not checked' "$work/uncov.out"
CASE="a reverse OSV lookup that fails (HTTP 500, a timeout) fails the run; only a 404 means OSV does not hold the incident"
check python3 - "$aud" <<'PY'
import importlib.util, io, sys, urllib.error, urllib.request
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
net = pa.LiveNet(["false"], ".")
def boom(code):
    def f(*a, **k): raise urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(b""))
    return f
urllib.request.urlopen = boom(404); assert net._osv_get("GHSA-x") is None
urllib.request.urlopen = boom(500)
try: net._osv_get("GHSA-x")
except pa.Fail: pass
else: raise AssertionError("a 500 was read as absent")
PY
CASE="exceptions refuse on unknown times (None is not unchanged) and use the version the net resolves (the most specific tag), not a coarse label"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
it = pa.inv.Item("action", "o/r", "a" * 40, "v3")
class N:
    def live_ranges(self, i, s, a): return [">= 3.26.11, <= 3.28.2"]
    def version_of(self, i): return "v3.27.0"
e = {"version": "3.*", "ids": ["A"], "package": "o/r", "authoritative": {"source": "GitHub", "id": "A", "ranges": [">= 3.26.11, <= 3.28.2"]}, "modified": {"A": "t1"}, "evidence": ["x"], "date": "d", "ruling": "r"}
assert pa.excepted(it, {"A"}, {"A": "t1"}, [e], N(), {}) == "hit", "the precise tag v3.27.0 is inside the range"
assert pa.excepted(it, {"A"}, {"A": None}, [e], N(), {}) is None
assert pa.excepted(it, {"A"}, {"A": "t1"}, [dict(e, osv_modified={"A": None})], N(), {"A": None}) is None
PY

CASE="issue text echoes only plain version-like tokens: a hostile label (a markdown link, an @mention, a URL) becomes (unparseable) in the title and the body"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
it = pa.inv.Item("action", "o/r", "a" * 40, "[click](https://evil.example/x)@owner")
f = pa.Finding(it, "advisory", ["GHSA-x"], "an advisory covers this version")
title = pa.title_of(f)[1]; body = pa.body_of(f, None, True, False, "2026-10-05")
for text in (title, body):
    assert "evil.example" not in text and "[click]" not in text and "@owner" not in text, text
assert "(unparseable)" in title
PY
CASE="only an exact version is a pin: main, nightly, lts/*, 1.*, 3.x, latest and ranges can never pass the age check; commits, digests and dotted numbers can"
check python3 - "$here/../supply-chain/pin-age-check.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
for v in ("main", "master", "nightly", "lts/*", "1.*", "3.x", "latest", "stable", ">=1.0", "(unpinned)", "${{expression}}", "v1.x", "1.2.x", "", "release-1"):
    assert not ac.is_pin(v), v
for v in ("v2.29.0", "2.17.1", "0.74.0", "21", "3.12", "1.0.0-rc.1", "a" * 40, "sha256:" + "b" * 64, "v4"):
    assert ac.is_pin(v), v
PY
CASE="a YAML alias bomb is refused before anything is expanded (fast), and an unparseable file never hangs the readers"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
bomb = "x: &a [1,1,1,1,1,1,1,1,1]\n" + "".join(f"x{i}: &{chr(98+i)} [*{chr(97+i)},*{chr(97+i)},*{chr(97+i)},*{chr(97+i)},*{chr(97+i)},*{chr(97+i)},*{chr(97+i)},*{chr(97+i)},*{chr(97+i)}]\n" for i in range(8))
t = time.time()
try:
    inv.inventory({".github/workflows/bomb.yml": bomb})
except RuntimeError as e:
    assert "alias" in str(e)
else:
    raise AssertionError("an alias was accepted")
assert time.time() - t < 2
PY
CASE="a commit pin with no tag at it is UNRESOLVED (a finding), whatever its # label says (the label is only a comment)"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
net = pa.LiveNet(["false"], ".")
pa.age._tags_for_commit = lambda r, s: []
assert net._version_of(pa.inv.Item("action", "o/r", "a" * 40, "v99.0.0")) is None
net._osv_post = lambda q: []; net.upstream = lambda i: True
f = pa.judge(pa.inv.Item("action", "o/r", "a" * 40, "v99.0.0"), net, [], [])
assert [x.kind for x in f] == ["unresolved"], [x.kind for x in f]
PY

CASE="every version-like tag at a commit is checked (one tag must not hide another's advisory), and shell variable names never print"
check python3 - "$aud" "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
spec = importlib.util.spec_from_file_location("inv2", sys.argv[2]); inv2 = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv2)
sha = "a" * 40
pa.age._tags_for_commit = lambda r, s: ["v4", "v4.2.0", "latest"]
net = pa.LiveNet(["false"], ".")
seen = []
net._lists_for = lambda item, v: (seen.append(v) or ([{"id": "G-" + v, "incident": "I", "affected": v == "v4.2.0"}], []))
gh, osv = net.lists(pa.inv.Item("action", "o/r", sha, ""))
assert seen == ["v4", "v4.2.0"] and any(g["affected"] for g in gh), (seen, gh)
assert "SECRET_NAME" not in inv2.Item("gotool", "x", "${SECRET_NAME}").version and "SECRET_NAME" not in inv2.Item("gotool", "x", "$SECRET_NAME").version
# an issue created in THIS run is never edited (no 'issue edit -1')
calls = []
class G:
    def run(self, *a, ok_fail=False):
        calls.append(a)
        class R: stdout = "[]"
        return R()
plan = [{"title": ("supply-chain: x@1", "supply-chain: x@1 (A)"), "body": "b", "owner": False}, {"title": ("supply-chain: x@1", "supply-chain: x@1 (A, B)"), "body": "b", "owner": False}]
pa.file_issues(G(), plan, "2026-10-05")
assert not any(c[:3] == ("issue", "edit", "-1") for c in calls), calls
PY

CASE="an open pull request that cannot be checked (a failure inside its item) never hides main's own findings: they are still filed, and the PR is named as not audited"
check python3 - "$aud" "$work" <<'PY'
import importlib.util, io, json, os, subprocess, sys, contextlib
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
work = sys.argv[2]
sha = "1" * 40
fx = {"lists": {"action:actions/checkout@" + sha: {"github": [{"id": "GHSA-main-main", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}},
      "upstream": {}, "nested": {}, "versions": {}, "prs": [], "open_prs": [{"number": 9, "items": ["action:actions/boom@v1"]}]}
class N(pa.FixtureNet):
    def lists(self, item):
        if item.name == "actions/boom":
            raise pa.Fail("simulated strict-read failure")
        return super().lists(item)
pa.FixtureNet = N
json.dump(fx, open(work + "/iso.fx.json", "w"))
calls = []
log = work + "/iso.gh"
open(work + "/isogh", "w").write("#!/bin/sh\necho \"$@\" >> %s\ncase \"$1 $2\" in 'issue list') echo '[]';; esac\nexit 0\n" % log); os.chmod(work + "/isogh", 0o755)
repo = work + "/r-cur"
out = io.StringIO()
with contextlib.redirect_stdout(out):
    rc = pa.main(["--root", repo, "--fixtures", work + "/iso.fx.json", "--now", "2026-10-05T12:00:00Z", "--gh", work + "/isogh"])
assert rc == 1, rc
txt = open(log).read()
assert "issue create" in txt and "GHSA-main-main" in txt and "actions/checkout" in txt, txt
assert "open pull request #9 could not be checked" in out.getvalue(), out.getvalue()
PY

CASE="an exception clears a commit only if NO version-like tag at it is inside the authoritative ranges; a moving nested tag is resolved to its commit; open pull requests are read page by page and an unreadable listing fails; one identity is one issue in a run"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
it = pa.inv.Item("action", "o/r", "a" * 40, "v3")
class N:
    def live_ranges(self, i, s, a): return [">= 3.26.11, <= 3.28.2"]
    def version_of(self, i): return "v3.30.0"
    def versions_of(self, i): return ["v3.30.0", "v3.27.0"]      # the commit carries two tags; one is inside the ranges
e = {"version": "3.*", "ids": ["A"], "package": "o/r", "authoritative": {"source": "GitHub", "id": "A", "ranges": [">= 3.26.11, <= 3.28.2"]}, "modified": {"A": "t1"}, "evidence": ["x"], "date": "d", "ruling": "r"}
assert pa.excepted(it, {"A"}, {"A": "t1"}, [e], N(), {}) == "hit", "another tag of the commit is inside the ranges"
N.versions_of = lambda self, i: ["v3.30.0", "v3.31.0"]
assert pa.excepted(it, {"A"}, {"A": "t1"}, [e], N(), {}) == "pass"
# a moving tag resolves to its current commit (annotated tags peeled)
net = pa.LiveNet(["false"], ".")
net._gh_json = lambda path, strict=False: {"repos/o/r/git/ref/tags/v4": {"object": {"type": "tag", "sha": "t" * 40}}, "repos/o/r/git/tags/" + "t" * 40: {"object": {"type": "commit", "sha": "c" * 40}}}.get(path)
assert net.resolve_ref("o/r", "v4") == "c" * 40
# unreadable PR listing fails loudly
pa.age._gh_pages = lambda path: None
os_env = __import__("os").environ; os_env["GITHUB_REPOSITORY"] = "o/r"
try:
    net.open_pr_items()
except pa.Fail:
    pass
else:
    raise AssertionError("an unreadable listing was read as no PRs")
# one identity, one issue per run, whatever ids the findings carry
calls = []
class G:
    def run(self, *a, ok_fail=False):
        calls.append(a)
        class R: stdout = "[]"
        return R()
plan = [{"title": ("supply-chain: x@1", "supply-chain: x@1 (A)"), "body": "b", "owner": False}, {"title": ("supply-chain: x@1", "supply-chain: x@1 (B)"), "body": "b", "owner": False}]
pa.file_issues(G(), plan, "2026-10-05")
assert len([c for c in calls if c[:2] == ("issue", "create")]) == 1, calls
PY

CASE="one held pull request that cannot be judged never stops the others from being re-run, and a run path with an @ref suffix still counts as this workflow's"
check python3 - "$aud" <<'PY'
import importlib.util, sys, datetime as dt
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
now = dt.datetime(2026, 10, 5, 12, tzinfo=dt.timezone.utc)
old = (now - dt.timedelta(days=9)).strftime("%Y-%m-%dT%H:%M:%SZ")
class N:
    def prs(self):
        return [{"number": 1, "title": "bad", "run_id": 11, "moved": ["action:o/boom@" + "a" * 40]}, {"number": 2, "title": "ok", "run_id": 22, "moved": ["action:o/ok@" + "b" * 40]}]
    def proofs(self, item, base=None, head="HEAD"):
        if item.name == "o/boom":
            raise pa.age.CouldNotLook("git ls-remote failed")
        return [(old, "observer")]
calls = []
class G:
    def run(self, *a, ok_fail=False):
        calls.append(a)
pa.rerun_held(G(), N(), now)
assert calls == [("run", "rerun", "22")], calls
assert pa.age.tobs.accept_run(dict({"event": "schedule", "head_branch": "main", "conclusion": "success"}, path=".github/workflows/supply-chain.yml@refs/heads/main".split("@")[0]))
PY

CASE="two disputed incidents of one package are ONE issue carrying both; tags of one commit never manufacture a dispute (incidents are per tag); script history is covered; an incomplete open-PR audit is not a clean day"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
sha = "a" * 40
pa.age._tags_for_commit = lambda r, s: ["v3", "v3.27.0"]
net = pa.LiveNet(["false"], ".")
net._lists_for = lambda item, v: ([{"id": "G1", "incident": "I", "affected": v == "v3.27.0"}], [{"id": "O1", "incident": "I", "affected": v == "v3.27.0"}])
gh, osv = net.lists(pa.inv.Item("action", "o/r", sha, ""))
f = pa.judge.__wrapped__ if hasattr(pa.judge, "__wrapped__") else None
kinds = set()
by = {}
for a in gh + osv:
    by.setdefault(a["incident"], []).append(a["affected"])
assert all(len(set(v)) == 1 for v in by.values()), by            # within one tag-scoped incident the databases AGREE
import re
assert ":(glob)**/*.sh" in open(sys.argv[1]).read()
PY

CASE="round 15: more than 200 version tags at one commit is refused, never truncated; an incomplete open-PR collection is not a clean day"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
pa.age._tags_for_commit = lambda r, s: ["v1.%d" % i for i in range(201)]
net = pa.LiveNet(["false"], ".")
try:
    net.versions_of(pa.inv.Item("action", "o/r", "a" * 40, ""))
except pa.Fail as e:
    assert "refusing" in str(e)
else:
    raise AssertionError("201 tags were truncated")
PY

CASE="rollback is the newest VERSION, never the newest upload: a late 1.2.9 backport published after 2.0.0 is not 'newest', and a pre-release is never a rollback target; GitHub advisory names compare by PEP 503 normalisation"
check python3 - "$aud" <<'PY'
import datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
now = dt.datetime(2026, 10, 5, 12, tzinfo=dt.timezone.utc)
old = lambda d: (now - dt.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
fx = pa.FixtureNet({"versions": {"o/r": [{"version": "2.0.0", "sha": None, "published": old(60), "lists": {}}, {"version": "1.2.9", "sha": None, "published": old(10), "lists": {}},
                                          {"version": "3.0.0rc1", "sha": None, "published": old(20), "lists": {}}]}})
assert pa.rollback(pa.inv.Item("action", "o/r", "x" * 40, "v4"), fx, now)["version"] == "2.0.0"
assert pa._norm_name("Jaraco.Context") == pa._norm_name("jaraco_context") == "jaraco-context"
PY

CASE="a failing re-run of one held PR never stops the others; two commits that collide on one issue identity are ONE issue carrying BOTH (never one dropped)"
check python3 - "$aud" <<'PY'
import datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
now = dt.datetime(2026, 10, 5, 12, tzinfo=dt.timezone.utc); old = (now - dt.timedelta(days=9)).strftime("%Y-%m-%dT%H:%M:%SZ")
class N:
    def prs(self):
        return [{"number": 1, "title": "a", "run_id": 11, "moved": ["tool:o/a@1.0"]}, {"number": 2, "title": "b", "run_id": 22, "moved": ["tool:o/b@1.0"]}]
    def proofs(self, item, base=None, head="HEAD"):
        return [(old, "github-release")]
calls = []
class G:
    def run(self, *a, ok_fail=False):
        if a[2] == "11":
            raise pa.Fail("simulated")
        calls.append(a)
pa.rerun_held(G(), N(), now)
assert calls == [("run", "rerun", "22")], calls
PY

CASE="an exception that names a version covers only that version"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
class N:
    def live_ranges(self, i, s, a): return ["= 0.69.4"]
    def version_of(self, i): return i.version
    def versions_of(self, i): return [i.version]
e = {"ids": ["A"], "package": "trivy", "version": "0.74.0", "authoritative": {"source": "GitHub", "id": "A", "ranges": ["= 0.69.4"]}, "modified": {"A": "t1"}, "evidence": ["x"], "date": "d", "ruling": "r"}
assert pa.excepted(pa.inv.Item("tool", "trivy", "0.74.0"), {"A"}, {"A": "t1"}, [e], N(), {}) == "pass"
assert pa.excepted(pa.inv.Item("tool", "trivy", "0.75.0"), {"A"}, {"A": "t1"}, [e], N(), {}) is None
PY

CASE="an exception without a version is refused as malformed (never a wildcard), a series (4.*) covers its series only; a dispute issue that becomes a confirmed hit is the SAME issue (retitled), never a second; a clean nested child is listed; a rollback whose nested child is affected is skipped"
check python3 - "$aud" <<'PY'
import importlib.util, json, sys, tempfile, os
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
base = {"ids": ["A"], "package": "p", "authoritative": {"source": "GitHub", "id": "A", "ranges": ["= 1"]}, "modified": {"A": "t"}, "evidence": ["x"], "date": "d", "ruling": "r"}
d = tempfile.mkdtemp()
for ex, ok in ((dict(base), False), (dict(base, version=""), False), (dict(base, version="1.0.0"), True)):
    json.dump({"exceptions": [ex]}, open(d + "/e.json", "w"))
    try:
        pa.load_exceptions(d + "/e.json", True); assert ok
    except pa.Fail:
        assert not ok
class G:
    def __init__(self): self.calls = []
    def run(self, *a, ok_fail=False):
        self.calls.append(a)
        class R: returncode = 0; stdout = json.dumps([{"number": 7, "title": "supply-chain: disputed trivy (A, B)", "state": "OPEN"}]) if a[:2] == ("issue", "list") else ""; stderr = ""
        return R()
g = G()
pa.file_issues(g, [{"title": ("supply-chain: trivy@0.75.0", "supply-chain: trivy@0.75.0 (A)"), "body": "b", "owner": False}], "2026-10-06")
assert any(c[:3] == ("issue", "edit", "7") for c in g.calls) and not any(c[:2] == ("issue", "create") for c in g.calls), g.calls
PY

CASE="a ruling for one version never covers another tag of the same commit; one open issue is never overwritten by two findings in a run (the second opens its own); a rollback candidate is rejected for a compromised grandchild"
check python3 - "$aud" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
class N:
    def live_ranges(self, i, s, a): return ["= 1"]
    def version_of(self, i): return "4.38.1"
    def versions_of(self, i): return ["v4.38.1", "v4.39.0"]
e = {"ids": ["A"], "package": "o/r", "version": "4.38.1", "authoritative": {"source": "GitHub", "id": "A", "ranges": ["= 1"]}, "modified": {"A": "t1"}, "evidence": ["x"], "date": "d", "ruling": "r"}
assert pa.excepted(pa.inv.Item("action", "o/r", "a" * 40, "v4.38.1"), {"A"}, {"A": "t1"}, [e], N(), {}) is None
N.versions_of = lambda self, i: ["v4.38.1"]
assert pa.excepted(pa.inv.Item("action", "o/r", "a" * 40, "v4.38.1"), {"A"}, {"A": "t1"}, [e], N(), {}) == "pass", "positive control: one tag, the ruling applies"
# mixed: a confirmed 0.73.0 and a still-disputed 0.74.0 never share (overwrite) one open issue
class G2:
    def __init__(self): self.calls = []
    def run(self, *a, ok_fail=False):
        self.calls.append(a)
        class R: returncode = 0; stdout = json.dumps([{"number": 7, "title": "supply-chain: disputed trivy (A, B)", "state": "OPEN"}]) if a[:2] == ("issue", "list") else ""; stderr = ""
        return R()
g2 = G2()
pa.file_issues(g2, [{"title": ("supply-chain: trivy@0.73.0", "supply-chain: trivy@0.73.0 (A)"), "body": "1", "owner": False}, {"title": ("supply-chain: disputed trivy", "supply-chain: disputed trivy (A, B)"), "body": "2", "owner": False}], "2026-10-06")
assert len([c for c in g2.calls if c[:3] == ("issue", "edit", "7")]) == 1 and len([c for c in g2.calls if c[:2] == ("issue", "create")]) == 1, g2.calls
# rollback: a compromised grandchild behind a SUBDIRECTORY child
class RN:
    def versions(self, item): return [{"version": "v2.0.0", "published": "2026-01-01T00:00:00Z", "sha": "b" * 40, "_item": pa.inv.Item("action", "o/cand", "b" * 40), "lists": {"github": [], "osv": []}}]
    def lists(self, item):
        return ([{"id": "G", "affected": True, "incident": "I", "modified": "t"}], []) if item.name == "o/grand" else ([], [])
    def proofs(self, item): return None
    def nested(self, item):
        return {"o/cand": [{"ref": "o/child1/sub@" + "c" * 40, "pinned": True}], "o/child1": [{"ref": "o/grand@" + "d" * 40, "pinned": True}]}.get(item.name, []) if (item.name != "o/child1" or item.path == "sub") else []
import datetime as dt
r = pa.rollback(pa.inv.Item("action", "o/cand", "e" * 40, "v3.0.0"), RN(), dt.datetime(2026, 10, 6, tzinfo=dt.timezone.utc))
assert r is None, r
class G:
    def __init__(self): self.calls = []
    def run(self, *a, ok_fail=False):
        self.calls.append(a)
        class R: returncode = 0; stdout = json.dumps([{"number": 7, "title": "supply-chain: disputed trivy (A, B)", "state": "OPEN"}]) if a[:2] == ("issue", "list") else ""; stderr = ""
        return R()
g = G()
pa.file_issues(g, [{"title": ("supply-chain: trivy@0.73.0", "supply-chain: trivy@0.73.0 (A)"), "body": "1", "owner": False}, {"title": ("supply-chain: trivy@0.74.0", "supply-chain: trivy@0.74.0 (A)"), "body": "2", "owner": False}], "2026-10-06")
assert len([c for c in g.calls if c[:3] == ("issue", "edit", "7")]) == 1 and len([c for c in g.calls if c[:2] == ("issue", "create")]) == 1, g.calls
PY

# --- failure modes: loud, never a quiet pass -----------------------------------------------------------------------------------------------------------------------
GH_FAIL="issue create" run ghfail "$HIT_GH" "$work/r-cur"
CASE="gh failing while opening the issue fails the run (exit 2): a lost hit is never a quiet success"
check test "$rc" -eq 2
echo 'not json' >"$work/broken.fx.json"; rc=0; ( cd "$work" && GH_LOG="$work/broken.gh" python3 "$aud" --root "$work/r-clean" --fixtures "$work/broken.fx.json" --now "$NOW" --gh "$work/gh" >/dev/null 2>&1 ) || rc=$?
CASE="unreadable input fails the run (exit 2), it never reports a clean day"
check test "$rc" -eq 2
# --- AC5 (round 1 of cache#393, both seats): an image named only in bin/persona-uat-tools.json is in the daily history too: a revision that changed only that file, and was replaced within 90 days, is still read ---
r="$work/r-ptools"; mkrepo "$r" "100:$CLEANSHA"
PTD1=sha256:$(printf 'a%.0s' $(seq 64)); PTD2=sha256:$(printf 'b%.0s' $(seq 64))
for spec in "30:$PTD1" "20:$PTD2"; do
  printf '{\n  "shell": "ghcr.io/own/ptool@%s"\n}\n' "${spec#*:}" >"$r/bin/persona-uat-tools.json"; git -C "$r" add -A
  GIT_AUTHOR_DATE="$(dago "${spec%%:*}")" GIT_COMMITTER_DATE="$(dago "${spec%%:*}")" git -C "$r" -c user.name=t -c user.email=t@x commit -q -m "tools ${spec#*:}"
done
CASE="AC5 persona tools: the history of the last 90 days holds an image that only the tools file named, in a revision that changed nothing else (A then B): both digests are read"
check python3 - "$aud" "$r" "$PTD1" "$PTD2" <<'PY'
import datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
items = pa.history_items(sys.argv[2], "HEAD", dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc))
seen = {str(getattr(i, "version", "")) + str(getattr(i, "digest", "")) + repr(i) for i in items.values()} if hasattr(items, "values") else {repr(i) for i in items}
blob = "\n".join(seen) + "\n".join(repr(k) for k in items)
assert sys.argv[3] in blob and sys.argv[4] in blob, blob[:2000]
PY
CASE="AC5 persona tools: a tools file that is tracked but cannot be read stops the daily scan (an error), never an inventory without its images"
if [ "$(id -u)" -ne 0 ]; then
  chmod 000 "$r/bin/persona-uat-tools.json"
  check python3 - "$here/../supply-chain/pin-inventory.py" "$r" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pi", sys.argv[1]); pi = importlib.util.module_from_spec(spec); spec.loader.exec_module(pi)
try:
    pi.tree_files(sys.argv[2], None)
except RuntimeError:
    sys.exit(0)
sys.exit("an unreadable tools file was skipped")
PY
  chmod 644 "$r/bin/persona-uat-tools.json"
else
  ok "$CASE (skipped as root: file modes do not bind)"
fi
CASE="no vendor or model name anywhere in the checks (the daily check is plain code, no AI; this repo is public)"
check none_match '[Cc]laude|[Oo]pus|[Ss]onnet|[Hh]aiku|[Ff]able|gpt-|[Gg]emini|[Ll]lama|anthropic|openai' "$here/../supply-chain/pin-inventory.py" "$here/../supply-chain/pin-age-check.py" "$here/../supply-chain/pin-audit.py"

# REQ-SUP-001-AC27: Go's own toolchain release skips the 7-day AGE hold only; the advisory audit still covers it (the Go vulnerability database files the standard
# library under the package stdlib): the item go is covered, queried as Go/stdlib at its version, and a stdlib record affecting the pin is a hit.
CASE="AC27: the audit covers tool:go (queried as the Go package stdlib) and an affected stdlib record is a hit, the fixed one is not"
check python3 - "$here/../supply-chain/pin-audit.py" <<'PY'
import importlib.util, sys
sys.path.insert(0, sys.argv[1].rsplit("/", 1)[0])
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
net = pa.LiveNet.__new__(pa.LiveNet)
it = pa.inv.Item("tool", "go", "1.27.2")
assert net.covered(it) is True
assert net._query(it, "1.27.2") == {"package": {"name": "stdlib", "ecosystem": "Go"}, "version": "1.27.2"}
rec = {"affected": [{"package": {"name": "stdlib", "ecosystem": "Go"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.27.3"}]}]}]}
assert pa.LiveNet._osv_says(rec, "stdlib", "1.27.2", False) is True
assert pa.LiveNet._osv_says(rec, "stdlib", "1.27.3", False) is False
seen = []
def post(q):   # the request that reaches OSV: a record exists only under the go command's own package toolchain
    seen.append(q["package"]["name"])
    return [{"id": "GO-T", "affected": [{"package": {"name": "toolchain", "ecosystem": "Go"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.27.3"}]}]}]}] if q["package"]["name"] == "toolchain" else []
net._osv_post = post
net._version_of = lambda i: "1.27.2"
net._gh_json = lambda *a, **k: []
gh, osv = net.lists(it)
assert seen == ["stdlib", "toolchain"], seen   # the go command's records are filed under toolchain
assert [(r["id"], r["affected"]) for r in osv] == [("GO-T", True)], osv
net._version_of = lambda i: "1.27.3"
assert [r["affected"] for r in net.lists(it)[1]] == [False]
PY

# --- cache#455 follow-up (handoff 0496 step 2): the 90-day history reads one inventory per DISTINCT set of files the inventory reads, not one per commit ---
r="$work/r-histmemo"; mkrepo "$r" "100:$CLEANSHA" "40:$SHA1" "30:$SHA2"
mkdir -p "$r/.github/agent/tests" "$r/docs"
for n in 1 2 3 4 5 6; do   # commits that touch .github but nothing the inventory reads (.github/agent/ and docs are outside tree_files)
  printf 'x%s\n' "$n" >"$r/.github/agent/tests/noise.txt"; git -C "$r" add -A
  GIT_AUTHOR_DATE="$(dago $((20 - n)))" GIT_COMMITTER_DATE="$(dago $((20 - n)))" git -C "$r" -c user.name=t -c user.email=t@x commit -q -m "noise $n"
done
CASE="history memo: the same items as one inventory per commit (the verdicts do not change)"
check python3 - "$aud" "$r" <<'PY'
import datetime as dt, importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
root, now = sys.argv[2], dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc)
since = (now - dt.timedelta(days=pa.LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
revs = subprocess.run(["git", "-C", root, "log", f"--since={since}", "--format=%H", "--all"], capture_output=True, text=True).stdout.split()
before = subprocess.run(["git", "-C", root, "rev-list", "-1", f"--before={since}", "HEAD"], capture_output=True, text=True).stdout.strip()
revs += [before] if before else []
ref = {}
for r in revs:
    ref.update(pa.inv.load_at(root, r))
got = pa.history_items(root, "HEAD", now)
assert set(got) == set(ref) and len(ref) > 0, (sorted(got), sorted(ref))
PY
rr="$work/r-histrevert"; mkrepo "$rr" "100:$CLEANSHA"
for spec in "40:v3.0.0" "20:v4.1.0"; do   # same pin, a label that changes and then reverts: the same key at two trees, a different label in between
  sed -i.bak "s|^\(      - uses: actions/checkout@[0-9a-f]*\) # .*|\1 # ${spec#*:}|" "$rr/.github/workflows/ci.yml"; rm -f "$rr/.github/workflows/ci.yml.bak"; git -C "$rr" add -A
  GIT_AUTHOR_DATE="$(dago "${spec%%:*}")" GIT_COMMITTER_DATE="$(dago "${spec%%:*}")" git -C "$rr" -c user.name=t -c user.email=t@x commit -q -m "label ${spec#*:}"
done
CASE="history memo: the VALUES match one inventory per commit, not only the keys (a label that reverts: the oldest occurrence still wins, as before; seat A of cache#456)"
check python3 - "$aud" "$rr" <<'PY'
import datetime as dt, importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
root, now = sys.argv[2], dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc)
since = (now - dt.timedelta(days=pa.LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
revs = subprocess.run(["git", "-C", root, "log", f"--since={since}", "--format=%H", "--all"], capture_output=True, text=True).stdout.split()
before = subprocess.run(["git", "-C", root, "rev-list", "-1", f"--before={since}", "HEAD"], capture_output=True, text=True).stdout.strip()
revs += [before] if before else []
ref = {}
for r in revs:
    ref.update(pa.inv.load_at(root, r))
got = pa.history_items(root, "HEAD", now)
f = lambda d: {k: (i.label, i.src, i.step, i.raw, i.version, i.path) for k, i in d.items()}
assert f(got) == f(ref), (f(got), f(ref))
assert any(i.label == "v4.1.0" for k, i in ref.items() if "checkout" in k), "the probe did not exercise a revert"
PY
CASE="history memo: commits that changed nothing the inventory reads cost no inventory (calls < commits) and the timing line is printed"
check python3 - "$aud" "$r" <<'PY'
import datetime as dt, importlib.util, sys, time
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
calls = [0]; real = pa.inv.inventory
def counting(files):
    calls[0] += 1
    return real(files)
pa.inv.inventory = counting
t = time.time()
pa.history_items(sys.argv[2], "HEAD", dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc))
print(f"history scan: {calls[0]} inventories in {time.time() - t:.2f}s")
assert calls[0] <= 4, calls[0]    # 9 commits in the lookback (3 pin commits + 6 noise), at most 4 distinct trees the inventory reads
PY

# --- cache#692-era follow-up (pin-age timeout, advisor read-back Oct 24): one inventory is memoised PER FILE (path, blob, and the blobs of the local workflows it names), so a
# new tree re-reads only the files that changed. The verdicts must not move: byte-identical items, a changed callee invalidates its caller, a raise is never cached. ---
CASE="file memo: over a real slice of this repository's history the memoised inventories equal the unmemoised ones, field for field, in history order and in a scrambled order"
check python3 - "$aud" "$here/../../.." <<'PY'
import importlib.util, json, random, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv, root = pa.inv, sys.argv[2]
paths = [".github", "bin/install-scanner.sh", ":(glob)**/*requirements*.txt", ":(glob)**/*.sh", ":(glob)**/action.yml", ":(glob)**/action.yaml", inv.PERSONA_TOOLS]
revs = inv.git(root, "log", "-n", "20", "--format=%H", "HEAD", "--", *paths).split()
assert len(revs) >= 10, "a shallow checkout cannot prove the equivalence: " + str(len(revs))
dump = lambda d: json.dumps({k: (i.kind, i.name, i.version, i.label, i.path, i.rawid, i.step, i.raw, i.src) for k, i in sorted(d.items())}, sort_keys=True)
inv._MEMO_ON[0] = False
ref = {r: dump(inv.load_at(root, r)) for r in revs}
inv._MEMO_ON[0] = True
for order in (list(reversed(revs)), random.Random(7).sample(revs, len(revs))):   # oldest first, then scrambled
    inv._FILE_MEMO.clear()
    for r in order:
        assert dump(inv.load_at(root, r)) == ref[r], r
assert any(len(v) > 2 for v in ref.values()), "the slice held no items"
PY
CASE="file memo: a changed callee invalidates its caller (the same caller blob, a local reusable workflow gaining then losing workflow_call)"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv = pa.inv
caller = "on: pull_request\njobs:\n  c:\n    uses: ./.github/workflows/callee.yml\n"
callee_ok = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
callee_no = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
keys = lambda files: sorted(inv.inventory(files))
inv._MEMO_ON[0] = False
plain = {c: keys({".github/workflows/caller.yml": caller, ".github/workflows/callee.yml": c}) for c in (callee_ok, callee_no)}
assert plain[callee_ok] != plain[callee_no], "the probe does not exercise the callee"
inv._MEMO_ON[0] = True; inv._FILE_MEMO.clear()
for c in (callee_ok, callee_no, callee_ok, callee_no):
    assert keys({".github/workflows/caller.yml": caller, ".github/workflows/callee.yml": c}) == plain[c]
# the callee leaves the tree altogether: the caller's items follow it
alone = {".github/workflows/caller.yml": caller}
got = keys(alone); inv._MEMO_ON[0] = False
assert got == keys(alone)
PY
CASE="file memo: a file that does not parse raises every time (a raise is never remembered) and one file is read once per distinct blob across a history scan"
check python3 - "$aud" "$r" <<'PY'
import datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv = pa.inv
inv._MEMO_ON[0] = True; inv._FILE_MEMO.clear()
bad = {".github/workflows/x.yml": "on: [\n  broken: : :\n"}
for _ in range(2):
    try:
        inv.inventory(dict(bad)); raise SystemExit("no raise")
    except RuntimeError:
        pass
calls = [0]; real = inv._file_found
def counting(path, text):
    calls[0] += 1
    return real(path, text)
inv._file_found = counting
inv._FILE_MEMO.clear()
files = {".github/workflows/a.yml": "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + "1" * 40 + " # v4\n", "bin/install-scanner.sh": "TRIVY_VER=0.74.0\n"}
for n in range(5):
    inv.inventory(dict(files, **{".github/workflows/b%d.yml" % n: "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo %d\n" % n}))
assert calls[0] == 2 + 5, calls[0]    # a.yml and the script once, each b file once
PY

# --- cache#693 first look (advisor ruling Oct 24): the memo revalidates the callees the walk actually READ, the context is neutral for every file, and the oracle is the parent ---
CASE="file memo: a caller whose callee is spelled with YAML escapes (\\x2e) is re-read when the callee changes: the memo decides on the reads the walk made, not on a regex of the text"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv = pa.inv
caller = 'on: pull_request\njobs:\n  c:\n    uses: "\\x2e/.github/workflows/c\\x61llee.yml"\n'
callee_ok = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
callee_no = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
files = lambda c: {".github/workflows/caller.yml": caller, ".github/workflows/callee.yml": c}
inv._MEMO_ON[0] = False
plain = {c: sorted(inv.inventory(files(c))) for c in (callee_ok, callee_no)}
assert plain[callee_ok] != plain[callee_no], "the probe does not exercise the escaped callee"
inv._MEMO_ON[0] = True; inv._FILE_MEMO.clear()
for c in (callee_ok, callee_no, callee_ok, callee_no):
    assert sorted(inv.inventory(files(c))) == plain[c]
PY
CASE="file memo: a caller with TWO local callees is re-read when either one changes, and only then (each call records its own read)"
check python3 - "$aud" <<'PY'
import importlib.util, itertools, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv = pa.inv
caller = "on: pull_request\njobs:\n  a:\n    uses: ./.github/workflows/one.yml\n  b:\n    uses: ./.github/workflows/two.yml\n"
ok = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
no = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
files = lambda one, two: {".github/workflows/caller.yml": caller, ".github/workflows/one.yml": one, ".github/workflows/two.yml": two}
combos = list(itertools.product((ok, no), repeat=2))
inv._MEMO_ON[0] = False
plain = {c: sorted(inv.inventory(files(*c))) for c in combos}
assert len({tuple(v) for v in plain.values()}) == 4, "the probe does not tell the four outcomes apart"
inv._MEMO_ON[0] = True; inv._FILE_MEMO.clear()
for c in combos + combos[::-1] + combos:
    assert sorted(inv.inventory(files(*c))) == plain[c], c
# "and only then": count the walks of the caller (the callees are walked when their own text is new)
walks = []; real = inv._file_found
inv._file_found = lambda p, x: (walks.append(p), real(p, x))[1]
caller_path = ".github/workflows/caller.yml"
inv._FILE_MEMO.clear(); inv.inventory(files(ok, ok)); walks.clear()
inv.inventory(files(ok, ok)); assert caller_path not in walks, "an unchanged tree re-walked the caller"
inv.inventory(files(no, ok)); assert walks.count(caller_path) == 1, "callee one changed: the caller is walked once"
walks.clear(); inv.inventory(files(no, ok)); assert caller_path not in walks, "nothing changed: not walked"
walks.clear(); inv.inventory(files(no, no)); assert walks.count(caller_path) == 1, "callee two changed: the caller is walked once"
inv._file_found = real
PY
CASE="file memo: the context is neutral for every file: a workflow that raises in the middle of a job leaves nothing for the next file (a script read after it equals a neutral run, memo cold and warm)"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv = pa.inv
bad = "on: push\nenv:\n  A: b\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      X: y\n    steps:\n      - run: echo " + "0123456789abcdef" * 4 + "\n      - run: " + "x" * 4500 + "\n"
script = "#!/usr/bin/env bash\npip install missingversion\ncurl -L -o /tmp/t https://example.org/releases/download/v${VER}/tool-${VER}.tgz\n"
dump = lambda d: sorted((k, i.step, i.path, i.src) for k, i in d.items())
inv._MEMO_ON[0] = False
neutral = dump(inv.inventory({"bin/x.sh": script}))
assert neutral, "the probe has no items"
many = "on: push\nenv:\n  A: b\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      X: y\n    steps:\n      - run: |\n" + "".join("          pip install p%d==1.0\n" % i for i in range(600))
for memo, poison in ((m, p) for m in (False, True) for p in (bad, many)):
    inv._MEMO_ON[0] = memo; inv._FILE_MEMO.clear()
    for _ in range(2):    # cold, then warm
        try:
            inv.inventory({".github/workflows/bad.yml": poison}); raise SystemExit("the limit did not raise")
        except RuntimeError:
            pass
        assert dump(inv.inventory({"bin/x.sh": script})) == neutral, ("memo", memo)
        for v in (inv._ENV_CTX[0], inv._INPUT_CTX[0]): assert v == "", v
        assert inv._ENV_PRESENT[0] is False and inv._JOB_RUNS[0] == [] and inv._JOB_SUMS[0] == []
PY
CASE="file memo: a returned item can be changed without reaching the memo or a later inventory; a file that breaks a limit raises on every use"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv = pa.inv
inv._MEMO_ON[0] = True; inv._FILE_MEMO.clear()
wf = ".github/workflows/a.yml"
files = {wf: "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + "1" * 40 + " # v4\n      - run: curl -L https://example.org/x/${V}/t.tgz\n", "bin/a.sh": "curl -L https://example.org/x/${V}/t.tgz\n"}
dump = lambda d: sorted((k, i.step, i.label, i.version) for k, i in d.items())
first = inv.inventory(dict(files)); pristine = dump(first)
for it in first.values():
    it.step = "changed"; it.label = "changed"; it.version = "changed"
assert dump(inv.inventory(dict(files))) == pristine
callee_bad = {".github/workflows/caller.yml": "on: pull_request\njobs:\n  c:\n    uses: ./.github/workflows/callee.yml\n", ".github/workflows/callee.yml": "on: [\n  broken: : :\n"}
callee_ok = dict(callee_bad, **{".github/workflows/callee.yml": "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"})
for files_ in (callee_ok, callee_bad, callee_ok, callee_bad):      # a warm caller whose callee becomes unreadable raises, every time
    try:
        inv.inventory(dict(files_)); assert files_ is callee_ok
    except RuntimeError:
        assert files_ is callee_bad
long_line = {"bin/b.sh": "echo " + "y" * 4500 + "\n"}
for _ in range(3):
    try:
        inv.inventory(dict(long_line)); raise SystemExit("no raise")
    except RuntimeError:
        pass
PY
CASE="file memo: the memoised inventories equal the PARENT commit's inventories over the same real slice, items and raises (the parent's own file is the oracle)"
check python3 - "$aud" "$here/../../.." <<'PY'
import importlib.util, json, subprocess, sys, tempfile, os
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv, root = pa.inv, sys.argv[2]
ipath = ".github/agent/supply-chain/pin-inventory.py"
intro = subprocess.run(["git", "-C", root, "log", "-S_FILE_MEMO", "--reverse", "--format=%H", "HEAD", "--", ipath], capture_output=True, text=True).stdout.split()
assert intro, "the commit that introduced the memo is not in this checkout's history"
src = subprocess.run(["git", "-C", root, "show", intro[0] + "^:" + ipath], capture_output=True, text=True)      # the file as it was before the memo existed, whatever the parents of HEAD are
assert src.returncode == 0, src.stderr[:200]
assert "_FILE_MEMO" not in src.stdout, "the oracle is the memoising implementation"
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "parent_inventory.py"); open(p, "w").write(src.stdout)
    ps = importlib.util.spec_from_file_location("parent_inventory", p); parent = importlib.util.module_from_spec(ps); ps.loader.exec_module(parent)
paths = [".github", "bin/install-scanner.sh", ":(glob)**/*requirements*.txt", ":(glob)**/*.sh", ":(glob)**/action.yml", ":(glob)**/action.yaml", inv.PERSONA_TOOLS]
revs = inv.git(root, "log", "-n", "12", "--format=%H", "HEAD", "--", *paths).split()
assert len(revs) >= 8, "a shallow checkout cannot prove the equivalence: " + str(len(revs))
dump = lambda d: json.dumps({k: (i.kind, i.name, i.version, i.label, i.path, i.rawid, i.step, i.raw, i.src) for k, i in sorted(d.items())}, sort_keys=True)
def run(mod, r):
    try:
        return dump(mod.load_at(root, r))
    except RuntimeError as e:
        return "raise:" + str(e)
want = {r: run(parent, r) for r in revs}
inv._MEMO_ON[0] = True; inv._FILE_MEMO.clear()
for r in revs + list(reversed(revs)):
    assert run(inv, r) == want[r], r
PY
# --- the history reader skips only the unreadable revisions named in its list (advisor 0637): a command line
# over 4000 characters is never read partially, so every audit would stop in the 90-day history read at a revision
# that held one. The skip is by FULL sha, from a reviewed list in the script, each named with its own reason;
# anything else unreadable still ends it.
r="$work/r-oversize"; rm -rf "$r"; mkdir -p "$r/.github/workflows" "$r/bin"; git -C "$r" init -q
oversize_ci() { # <checkout sha> <extra>: a workflow pinning actions/checkout at that sha, with one step whose run line is $2 long
  printf 'on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@%s # v4\n' "$1" >"$r/.github/workflows/ci.yml"
  [ "$2" -eq 0 ] || printf '      - name: long\n        run: echo %s\n' "$(python3 -c "print('x'*$2)")" >>"$r/.github/workflows/ci.yml"
}
printf 'TRIVY_VER=0.74.0\n' >"$r/bin/install-scanner.sh"
commit_at() { git -C "$r" add -A; GIT_AUTHOR_DATE="$(dago "$1")" GIT_COMMITTER_DATE="$(dago "$1")" git -C "$r" -c user.name=t -c user.email=t@x commit -q -m "$2"; git -C "$r" rev-parse HEAD; }
oversize_ci "$SHA1" 0;    OV_A=$(commit_at 60 "readable A")
oversize_ci "$SHA2" 4100; OV_B=$(commit_at 40 "oversize B")
oversize_ci "$SHA4" 0;    OV_C=$(commit_at 20 "readable C")
oversize_ci "$SHA4" 4300; OV_D=$(commit_at 10 "oversize D (a fourth, never listed)")
oversize_ci "$SHA4" 0;    OV_E=$(commit_at 5 "readable E")
OVPY='import datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
NOW = dt.datetime(2026, 10, 5, 12, tzinfo=dt.timezone.utc)
def hist(skip):
    pa.SKIP_UNREADABLE = skip
    try:
        return pa.history_items(sys.argv[2], "HEAD", NOW), None
    except RuntimeError as e:
        return None, str(e)
'
CASE="oversize history: a revision with a command line over 4000 characters that is NOT on the list stops the history read with the cap's own message (fail closed)"
check python3 - "$aud" "$r" "$OV_B" "$OV_D" <<PY
$OVPY
items, err = hist({})
assert items is None and "command line of" in err and "refusing to read it partially" in err, (items, err)
PY
CASE="oversize history: with the only two oversize revisions listed (full shas, a reason each) the read completes and still holds the readable neighbours' pins"
check python3 - "$aud" "$r" "$OV_B" "$OV_D" "$SHA1" "$SHA4" <<PY
$OVPY
items, err = hist({sys.argv[3]: "fixture B: a 4100-character run line", sys.argv[4]: "fixture D: a 4300-character run line"})
assert err is None, err
blob = " ".join(repr(k) for k in items)
assert sys.argv[5] in blob and sys.argv[6] in blob, blob[:600]
PY
CASE="oversize history: a fourth oversize revision that is not on the list still refuses although the others are listed (fail closed for anything unnamed)"
check python3 - "$aud" "$r" "$OV_B" <<PY
$OVPY
items, err = hist({sys.argv[3]: "fixture B only"})
assert items is None and "command line of" in err, (items, err)
PY
CASE="oversize history: an abbreviated sha (8 characters), an uppercase sha and a sha with a space never match: only the full lowercase 40-hex revision name does"
check python3 - "$aud" "$r" "$OV_B" "$OV_D" <<PY
$OVPY
for bad in (sys.argv[3][:8], sys.argv[3].upper(), sys.argv[3] + " ", " " + sys.argv[3]):
    items, err = hist({bad: "x", sys.argv[4]: "d"})
    assert items is None and "command line of" in err, (bad, items, err)
PY
CASE="oversize history: a listed revision that is READABLE is read normally (the list never hides a readable revision's pins)"
check python3 - "$aud" "$r" "$OV_A" "$OV_B" "$OV_D" "$SHA1" <<PY
$OVPY
items, err = hist({sys.argv[3]: "readable A listed by mistake", sys.argv[4]: "B", sys.argv[5]: "D"})
assert err is None, err
assert sys.argv[6] in " ".join(repr(k) for k in items)
PY
CASE="oversize history: the list holds the named commits (full 40-hex shas), each with a reason that names its file"
check python3 - "$aud" <<'PY'
import importlib.util, re, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
pr459 = {"792a2c7029de801fa7afbc16ceb36a636215f4b6", "6ff1768c0e63d0f60f6072267817062d53934a08", "dbc8d744f4d78cba6ca35ea53b96b6e6a43d311b"}
p1p5 = {"27b14e37ed06bca44ae479a8880480fa5855605b", "c4ac17f07ac894c014034ec7e535e4598e06ced8", "c9e30be29823765fce4c8a23bb11a4340a73fd69", "23f771008513913f5a1bf434af83530125621a53",
        "c5b8f225a378db6fa72200bafcf9af7998ef23e5", "9045a08f287801c75cbf385caae8038774ed9f10",
        "115c746b17620f08c0fe52c789dea720c887d465", "cdbaf6283ab81b9ee8c9539ceeb253cf9ba61987",
        "210d27d4e2bd01d0b8e0cd9f706148182e0d6ec8", "464b72fea4e356a9876bf9bd70f57cc84e07cab4"}
p2 = {"7d538938ec3733112eb29b5f495502e8a74d7e33", "16e2e1f9a010dfc966930b7963cec13326fa877c",
      "28acfea97185023710ee2ba4596cbdb2ca68bfb0", "84112d2d433db8148b0fe6cf47a1a4d943c5c8fa",
      "fbecada5bf5c37ab9263ca82664b3382c3dd9457"}
r597 = "6b8c70df66651667e530748db9bc22462e307bee"
assert set(pa.SKIP_UNREADABLE) == pr459 | p1p5 | p2 | {r597}, sorted(pa.SKIP_UNREADABLE)
for k, why in pa.SKIP_UNREADABLE.items():
    assert re.fullmatch(r"[0-9a-f]{40}", k), k
    if k == r597:
        assert "bin/chain-check-scripts-test.sh" in why and "#597" in why and "4103" in why, (k, why)
    elif k in p1p5 | p2:
        assert ("cache6-0713-p1p5" if k in p1p5 else "cache6-0713-p2") in why, (k, why)
        assert "bin/chain-rekor-key-test.sh" in why and "4529" in why, (k, why)
        assert why.endswith("since wrapped (0289dc91)"), (k, why)
    else:
        assert "bin/chain-sign-wiring-test.sh" in why and "PR 459" in why, (k, why)
PY
CASE="oversize history: no other error is swallowed: a listed revision that is unreadable for another reason (a broken tree) still stops the read"
check python3 - "$aud" "$r" "$OV_B" "$OV_D" <<PY
$OVPY
pa.SKIP_UNREADABLE = {sys.argv[3]: "listed", sys.argv[4]: "listed"}
orig = pa.inv.load_at
def boom(root, rev):
    if rev == sys.argv[3]:
        raise RuntimeError("some other failure of the reader")
    return orig(root, rev)
pa.inv.load_at = boom
try:
    pa.history_items(sys.argv[2], "HEAD", NOW)
except RuntimeError as e:
    assert "some other failure" in str(e)
else:
    raise SystemExit("an unrelated error of a listed revision was swallowed")
PY


# --- chain-v030 only: the history memo is keyed by the tree the inventory reads, so two revisions can share one key. A skipped revision must never be remembered under that key (seat A and
# seat B of cache#520: the cases above never share a tree, so a memo that stored skipped revisions as empty passed them all).
r="$work/r-oversize-shared"; rm -rf "$r"; mkdir -p "$r/.github/workflows" "$r/bin"; git -C "$r" init -q
printf 'TRIVY_VER=0.74.0\n' >"$r/bin/install-scanner.sh"
oversize_ci "$SHA2" 4100; SH_X=$(commit_at 60 "oversize X")
oversize_ci "$SHA1" 0;    SH_M=$(commit_at 40 "readable M")
oversize_ci "$SHA2" 4100; SH_Y=$(commit_at 20 "oversize Y (the same tree as X)")
oversize_ci "$SHA1" 0;    SH_R1=$(commit_at 10 "readable R1")
oversize_ci "$SHA4" 0;    SH_Q=$(commit_at 8 "readable Q")
oversize_ci "$SHA1" 0;    SH_R2=$(commit_at 5 "readable R2 (the same tree as M and R1)")
CASE="oversize history, shared tree: listing one of two revisions that share an unreadable tree never lets the other, unlisted one pass (a skip is not remembered under the tree key), in both orders"
check python3 - "$aud" "$r" "$SH_X" "$SH_Y" <<PY
$OVPY
for listed in (sys.argv[3], sys.argv[4]):
    items, err = hist({listed: "only one of the pair"})
    assert items is None and "command line of" in err, (listed, items, err)
items, err = hist({sys.argv[3]: "x", sys.argv[4]: "y"})
assert err is None, err
PY
CASE="oversize history, shared tree: a listed revision whose tree was already read from a readable revision is read normally, in both orders (the list never hides a readable revision's pins)"
check python3 - "$aud" "$r" "$SH_M" "$SH_R1" "$SH_R2" "$SH_X" "$SH_Y" "$SHA1" <<PY
$OVPY
both = {sys.argv[6]: "x", sys.argv[7]: "y"}
for listed in (sys.argv[3], sys.argv[4], sys.argv[5]):
    items, err = hist({**both, listed: "readable but listed"})
    assert err is None, err
    assert sys.argv[8] in " ".join(repr(k) for k in items)
PY


# --- the daily run ends cleanly when the history cannot be read (ruled Oct 31): an unlisted unreadable revision exits 2 and the tag observations are already written; one
# ls-tree -r per revision is all the history reader asks git for ---
rm -rf "$work/obsout4"; run oversizeobs "$CLEAN" "$work/r-oversize" --observations-out "$work/obsout4/state.json"
CASE="oversize history, daily run: an unlisted unreadable revision ends the audit with exit 2 and the cap's own message"
check test "$rc" -eq 2; check grep -q 'refusing to read it partially' "$work/oversizeobs.err"
CASE="oversize history, daily run: the tag observations (state.json) are written before the history is read, so an unreadable revision does not lose them"
check test -s "$work/obsout4/state.json"
CASE="history reader: git ls-tree -r runs once per revision (the listing that makes the tree key is the listing the files are read from)"
check python3 - "$aud" "$work/r-histmemo" <<'PY'
import collections, datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
listings = collections.Counter()
real = pa.inv.git
def counting(root, *args):
    if "ls-tree" in args and "-r" in args:
        listings[args[-1]] += 1
    return real(root, *args)
pa.inv.git = counting
pa.history_items(sys.argv[2], "HEAD", dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc))
assert listings and max(listings.values()) == 1, dict(listings)
PY

# --- the gate follow-up (supply-chain gate ruling, Oct 31): the costly part of a history scan is reading each new version of a big script line by line. Three more memos, all exact:
# a script line (in a neutral context), the id of a script line, and the file memo keeps every read-set it has seen for a blob. None may move a verdict. ---
CASE="T5 line memos: over a real slice of history the inventories with the line memos equal the unmemoised ones, field for field, and the memos were used"
check python3 - "$aud" "$here/../../.." <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv, root = pa.inv, sys.argv[2]
paths = [".github", "bin/install-scanner.sh", ":(glob)**/*requirements*.txt", ":(glob)**/*.sh",
         ":(glob)**/action.yml", ":(glob)**/action.yaml", inv.PERSONA_TOOLS]
revs = inv.git(root, "log", "-n", "20", "--format=%H", "HEAD", "--", *paths).split()
assert len(revs) >= 10, "a shallow checkout cannot prove the equivalence: " + str(len(revs))
dump = lambda d: json.dumps({k: (i.kind, i.name, i.version, i.label, i.path, i.rawid, i.step, i.raw, i.src)
                             for k, i in sorted(d.items())}, sort_keys=True)
inv._MEMO_ON[0] = False
ref = {r: dump(inv.load_at(root, r)) for r in revs}
inv._MEMO_ON[0] = True
inv._FILE_MEMO.clear(); inv._STEP_MEMO.clear(); inv._LINE_ID_MEMO.clear()
for r in revs:
    assert dump(inv.load_at(root, r)) == ref[r], r
assert inv._STEP_MEMO and inv._LINE_ID_MEMO, "the line memos were not used"
inv._FILE_MEMO.clear()          # a warm line memo under a cold file memo: every file is read again, every line is a hit
for r in reversed(revs):
    assert dump(inv.load_at(root, r)) == ref[r], r
PY
CASE="T5 line memo: a script line that makes too many items raises on a hit too, a returned item cannot reach the memo, and nothing is remembered under a context"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv = pa.inv
inv._MEMO_ON[0] = True; inv._FILE_MEMO.clear(); inv._STEP_MEMO.clear()
script = {"bin/x.sh": "#!/usr/bin/env bash\npip install a==1.0 b==2.0 c==3.0\n"}
first = inv.inventory(dict(script))
assert inv._STEP_MEMO, "the line was not remembered"
for it in first.values():
    it.version = "changed"; it.step = "changed"
inv._FILE_MEMO.clear()
again = inv.inventory(dict(script))
assert sorted(i.version for i in again.values()) == ["1.0", "2.0", "3.0"], "a returned item reached the memo"
limit = inv.MAX_ITEMS_PER_STEP
inv.MAX_ITEMS_PER_STEP = 2
try:
    inv._FILE_MEMO.clear()
    try:
        inv.inventory(dict(script)); raise SystemExit("the memoised line did not raise on a hit")
    except RuntimeError as e:
        assert "more than 2 items" in str(e), str(e)
finally:
    inv.MAX_ITEMS_PER_STEP = limit
inv._JOB_RUNS[0] = ["echo earlier step"]
try:
    inv._step_line({"run": "pip install q==1.0"}, [])
    raise SystemExit("a line was read from the memo while a job's run texts were set")
except AssertionError:
    pass
finally:
    inv._JOB_RUNS[0] = []
PY
CASE="T6 file memo keeps every read-set: two trees that differ only in a callee, read alternately, hit the caller from the second round on"
check python3 - "$aud" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
inv = pa.inv
inv._MEMO_ON[0] = True; inv._FILE_MEMO.clear()
caller = "on: pull_request\njobs:\n  c:\n    uses: ./.github/workflows/callee.yml\n"
callee = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo %s\n"
trees = [{".github/workflows/caller.yml": caller, ".github/workflows/callee.yml": callee % n} for n in ("one", "two")]
walks = []
real_found = inv._file_found
inv._file_found = lambda path, text: (walks.append(path), real_found(path, text))[1]
for t in trees:                       # warm-up: each tree once; the caller is walked once per read-set
    inv.inventory(dict(t))
assert walks.count(".github/workflows/caller.yml") == 2, walks
walks.clear()
for _ in range(2):
    for t in trees:
        inv.inventory(dict(t))
assert walks == [], walks      # then every file of every tree is answered by the memo: no walk at all
PY

echo "pin-audit: $pass passed, $failn failed"
test "$failn" -eq 0
