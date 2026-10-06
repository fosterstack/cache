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
root=$(cd "$(dirname "$0")/.." && pwd)
aud="$root/bin/pin-audit.py"
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
elif a[:2] in (["label", "create"], ["run", "rerun"]):
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
        assert c[:2] in (["issue", "list"], ["issue", "create"], ["issue", "edit"], ["label", "create"], ["run", "rerun"]), (p, c)
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

# --- AC10: disputed hits and checked-in exceptions ----------------------------------------------------------------------------------------------------
DISPUTE="{\"lists\": {\"$ITEM_TRIVY\": {\"github\": [{\"id\": \"GHSA-69fq-xp46-6x23\", \"incident\": \"INC-T\", \"affected\": false, \"modified\": \"2026-09-01T00:00:00Z\"}], \"osv\": [{\"id\": \"GO-2026-4919\", \"incident\": \"INC-T\", \"affected\": true, \"modified\": \"2026-09-02T00:00:00Z\"}]}}, \"upstream\": {}, \"nested\": {}, \"versions\": {\"aquasecurity/trivy\": [{\"version\": \"0.69.3\", \"sha\": \"x\", \"published\": \"$(dago 400)\", \"lists\": {}}]}, \"prs\": []}"
printf '{"exceptions": []}' >"$work/no-exceptions.json"
run dispute "$DISPUTE" "$work/r-cur" --exceptions "$work/no-exceptions.json"
CASE="two lists disagree about one incident (GitHub: not affected, OSV: affected) and there is NO exception: exit 1, one issue labelled supply-chain-hit that says DISPUTED"
check test "$rc" -eq 1; check test "$(creates "$work/dispute.gh")" -eq 1; check grep -qi 'disputed' "$work/dispute.gh.bodies"; check grep -q 'supply-chain-hit' "$work/dispute.gh"
CASE="a disputed hit neither reports clean nor rolls back: no 'no known-compromised' line, no rollback or drop advice"
check none_match 'no known-compromised' "$work/dispute.out"; check bash -c "! grep -qiE 'roll ?back to|drop the action' '$work/dispute.gh.bodies'"
CASE="the dispute's public facts are in the issue: both advisory ids, both verdicts, the version"
check grep -q 'GHSA-69fq-xp46-6x23' "$work/dispute.gh.bodies"; check grep -q 'GO-2026-4919' "$work/dispute.gh.bodies"; check grep -q '0.74.0' "$work/dispute.gh.bodies"
EXC='{"exceptions": [{"ids": ["GO-2026-4919", "GHSA-69fq-xp46-6x23"], "package": "trivy", "version": "0.74.0", "evidence": ["https://github.com/advisories/GHSA-69fq-xp46-6x23"], "date": "2026-10-05", "modified": {"GO-2026-4919": "2026-09-02T00:00:00Z", "GHSA-69fq-xp46-6x23": "2026-09-01T00:00:00Z"}}]}'
echo "$EXC" >"$work/exc.json"
run excepted "$DISPUTE" "$work/r-cur" --exceptions "$work/exc.json"
CASE="a MATCHING exception (same advisories, package, version, and both advisories unchanged since it was written): passes, exit 0, no issue, and says an exception applied"
check test "$rc" -eq 0; check test "$(creates "$work/excepted.gh")" -eq 0; check grep -qi 'exception' "$work/excepted.out"
python3 - "$work/exc.json" "$work/exc-stale.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1])); e["exceptions"][0]["modified"]["GO-2026-4919"] = "2026-08-01T00:00:00Z"; json.dump(e, open(sys.argv[2], "w"))
PY
run stale "$DISPUTE" "$work/r-cur" --exceptions "$work/exc-stale.json"
CASE="an exception goes STALE when an advisory changed after it was written (its recorded modified time differs): the dispute is reported again, exit 1"
check test "$rc" -eq 1; check grep -qi 'disputed' "$work/stale.gh.bodies"
python3 - "$work/exc.json" "$work/exc-otherver.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1])); e["exceptions"][0]["version"] = "0.74.1"; json.dump(e, open(sys.argv[2], "w"))
PY
run otherver "$DISPUTE" "$work/r-cur" --exceptions "$work/exc-otherver.json"
CASE="an exception for a different version of the same package does not apply"
check test "$rc" -eq 1
python3 - "$work/exc.json" "$work/exc-nomod.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1])); del e["exceptions"][0]["modified"]["GHSA-69fq-xp46-6x23"]; json.dump(e, open(sys.argv[2], "w"))
PY
run nomod "$DISPUTE" "$work/r-cur" --exceptions "$work/exc-nomod.json"
CASE="an exception with no recorded last-modified time for one of its advisories cannot be shown unchanged, so it does not apply"
check test "$rc" -eq 1
echo '{"not": "a list"}' >"$work/exc-bad.json"
run badexc "$DISPUTE" "$work/r-cur" --exceptions "$work/exc-bad.json"
CASE="an unreadable exceptions file fails the run loudly (exit 2), never as 'no exceptions'"
check test "$rc" -eq 2
CASE="the shipped exceptions file (.github/supply-chain-exceptions.json) holds the first ruling: OSV GO-2026-4919 against trivy 0.74.0 is a false positive, in the same format as ops (an "exceptions" list of ids, package, version, evidence, date and each advisory's last-modified time)"
check python3 - "$root/.github/supply-chain-exceptions.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1]))["exceptions"]
m = [x for x in e if x["package"] == "trivy" and x["version"] == "0.74.0"]
assert len(m) == 1, e
x = m[0]
assert sorted(x["ids"]) == ["GHSA-69fq-xp46-6x23", "GO-2026-4919"], x
assert x["evidence"] and all(u.startswith("https://") for u in x["evidence"]) and x["date"]
assert set(x["modified"]) == {"GO-2026-4919", "GHSA-69fq-xp46-6x23"} and all(x["modified"].values()), x
PY
# a plain hit is NOT a dispute: when both lists agree it is affected, an exception for another advisory changes nothing
run agree "{\"lists\": {\"$ITEM_TRIVY\": {\"github\": [{\"id\": \"GHSA-x\", \"incident\": \"INC-A\", \"affected\": true, \"modified\": \"2026-09-01T00:00:00Z\"}], \"osv\": [{\"id\": \"GO-x\", \"incident\": \"INC-A\", \"affected\": true, \"modified\": \"2026-09-02T00:00:00Z\"}]}}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": []}" "$work/r-cur" --exceptions "$work/exc.json"
CASE="when BOTH lists say affected it is a plain hit (rollback advice allowed), not a dispute, and an unrelated exception does not hide it"
check test "$rc" -eq 1; check bash -c "! grep -qi 'disputed' '$work/agree.gh.bodies'"

# --- AC6: held pull requests are re-run once their versions are old enough ----------------------------------------------------------------------------------
HELD="{\"lists\": {}, \"upstream\": {}, \"nested\": {}, \"versions\": {}, \"prs\": [
  {\"number\": 7, \"title\": \"bump checkout\", \"run_id\": 99, \"moved\": [\"$ITEM_CO\"]},
  {\"number\": 8, \"title\": \"bump trivy\", \"run_id\": 98, \"moved\": [\"$ITEM_TRIVY\"]}],
 \"times\": {\"$ITEM_CO\": {\"time\": \"$(dago 8)\", \"source\": \"github-release\"}, \"$ITEM_TRIVY\": {\"time\": \"$(dago 2)\", \"source\": \"github-release\"}}}"
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

# --- failure modes: loud, never a quiet pass -----------------------------------------------------------------------------------------------------------------------
GH_FAIL="issue create" run ghfail "$HIT_GH" "$work/r-cur"
CASE="gh failing while opening the issue fails the run (exit 2): a lost hit is never a quiet success"
check test "$rc" -eq 2
echo 'not json' >"$work/broken.fx.json"; rc=0; ( cd "$work" && GH_LOG="$work/broken.gh" python3 "$aud" --root "$work/r-clean" --fixtures "$work/broken.fx.json" --now "$NOW" --gh "$work/gh" >/dev/null 2>&1 ) || rc=$?
CASE="unreadable input fails the run (exit 2), it never reports a clean day"
check test "$rc" -eq 2
CASE="no vendor or model name anywhere in the checks (the daily check is plain code, no AI; this repo is public)"
check none_match '[Cc]laude|[Oo]pus|[Ss]onnet|[Hh]aiku|[Ff]able|gpt-|[Gg]emini|[Ll]lama|anthropic|openai' "$root/bin/pin-inventory.py" "$root/bin/pin-age-check.py" "$root/bin/pin-audit.py"

echo "pin-audit: $pass passed, $failn failed"
test "$failn" -eq 0
