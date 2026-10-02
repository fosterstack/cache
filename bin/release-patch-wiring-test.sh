#!/usr/bin/env bash
# proves: REQ-REL-009-AC3, REQ-REL-009-AC5, REQ-REL-009-AC10
# Automatic patch releases in release.yml (owner RATIFIED Oct 2; advisor 0051/0055/0056/0057), PR B:
# - push to main and a daily schedule run ONLY the decide job; the release chain starts only on a v* tag (admission is
#   guarded to tags, every other stage needs it);
# - decide runs on main only, in the main-only agent environment, with its own token read-only plus id-token (gitsign)
#   and issues (the standing "not patch-clean" issue); the critical/high comparison scans the release and the new base;
# - the tag is signed keylessly by gitsign (pinned by checksum, no key) under release.yml's identity and pushed with the
#   auditor App's token (exactly the auditor's scope), which reaches only the push step;
# - a failed patch-tag run opens one issue and is never retried.
# The real workflow must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" <<'PY'
import re, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
bad = []
on = d.get("on") or {}
if (on.get("push") or {}).get("tags") != ["v*"] or (on.get("push") or {}).get("branches") != ["main"]:
    bad.append("push must cover v* tags (the chain) and main (decide): %s" % on.get("push"))
if not any(re.fullmatch(r"\d{1,2} \d{1,2} \* \* \*", c.get("cron", "")) for c in on.get("schedule") or []):
    bad.append("no daily schedule")
jobs = d.get("jobs") or {}
adm = jobs.get("admission") or {}
if adm.get("if", "").replace(" ", "") != "${{startsWith(github.ref,'refs/tags/v')}}":
    bad.append("admission is not guarded to v* tags: %s" % adm.get("if"))
chain = [j for j in jobs if j not in ("admission", "decide", "patch-failed")]
for j in chain:
    if "if" in jobs[j] or not jobs[j].get("needs"):
        bad.append("chain job %s does not hang off admission unconditionally" % j)
dec = jobs.get("decide") or {}
if dec.get("if", "").replace(" ", "") != "${{github.ref=='refs/heads/main'}}":
    bad.append("decide does not run on main only: %s" % dec.get("if"))
if dec.get("concurrency") != {"group": "patch-decide", "cancel-in-progress": "false"}:
    bad.append("decide runs are not serialized (a push and the daily run could both cut)")
if dec.get("environment") != "agent":
    bad.append("decide is not in the main-only agent environment")
if dec.get("permissions") != {"contents": "read", "id-token": "write", "issues": "write"}:
    bad.append("decide's own token is not contents read + id-token + issues: %s" % dec.get("permissions"))
steps = dec.get("steps") or []
text = "\n".join(s.get("run") or "" for s in steps)
if "bin/install-scanner.sh gitsign" not in text:
    bad.append("gitsign is not installed through the pinned, checksum-verified installer")
if "tag -s" not in text or "gpg.format=x509" not in text or "gpg.x509.program=gitsign" not in text:
    bad.append("the tag is not signed with gitsign (x509)")
if re.search(r"(?i)private[-_ ]key|cosign.key|signingkey\s+\S+\.(pem|key)", text):
    bad.append("a stored signing key appears")
mint = [s for s in steps if str(s.get("uses", "")).startswith("actions/create-github-app-token@")]
want = {"app-id": "${{ secrets.AUDITOR_APP_ID }}", "private-key": "${{ secrets.AUDITOR_APP_PRIVATE_KEY }}",
        "repositories": "cache", "permission-contents": "write"}
if len(mint) != 1 or mint[0].get("with") != want:
    bad.append("the App token is not minted with exactly contents write on cache: %s" % [m.get("with") for m in mint])
users = [s.get("name") for s in steps if "steps.app-token.outputs.token" in str(s)]
if users != ["push the signed tag (the App transports it)"]:
    bad.append("the App token reaches a step other than the tag push: %s" % users)
if "patch-decide.py removed" not in text or "grype" not in text:
    bad.append("the critical/high comparison does not scan the release and the new base image")
co = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
if not co or (co[0].get("with") or {}).get("persist-credentials") != "false":
    bad.append("decide's checkout keeps a credential")
fail = jobs.get("patch-failed") or {}
if "failure()" not in fail.get("if", "") or "refs/tags/v" not in fail.get("if", "") or fail.get("permissions") != {"contents": "read", "issues": "write"}:
    bad.append("no failure-issue job for tag runs: %s" % fail.get("if"))
if "gh issue create" not in "\n".join(s.get("run") or "" for s in fail.get("steps") or []):
    bad.append("the failure job opens no issue")
if re.search(r"gh run rerun|rerun-failed|/rerun\b|actions/runs/\S+/rerun", yaml.safe_dump(d), re.I):
    bad.append("a retry path exists")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_() {
  local f="$work/$1.yml"
  cp "$root/.github/workflows/release.yml" "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS $1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want $2 ($out)"; fi
}
J='d["jobs"]'; D="$J['decide']"
case_ real                    ok  ""
case_ chain-on-main           bad "$J['admission'].pop('if')"
case_ decide-anywhere         bad "$D['if'] = '\${{ always() }}'"
case_ decide-no-env           bad "$D.pop('environment')"
case_ decide-writes           bad "$D['permissions']['contents'] = 'write'"
case_ app-widened             bad "[s['with'].__setitem__('permission-pull-requests', 'write') for s in $D['steps'] if str(s.get('uses','')).startswith('actions/create-github-app-token@')]"
case_ token-to-decide-step    bad "[s.setdefault('env', {}).__setitem__('GH_TOKEN', '\${{ steps.app-token.outputs.token }}') for s in $D['steps'] if 'patch-decide.py decide' in (s.get('run') or '')]"
case_ unsigned-tag            bad "[s.__setitem__('run', s['run'].replace('tag -s', 'tag -a')) for s in $D['steps'] if 'tag -s' in (s.get('run') or '')]"
case_ a-rerun-path            bad "$J['patch-failed']['steps'][0]['run'] += '\\ngh run rerun \$GITHUB_RUN_ID'"
case_ gitsign-unpinned        bad "[s.__setitem__('run', s['run'].replace('bin/install-scanner.sh gitsign', 'go install github.com/sigstore/gitsign@latest')) for s in $D['steps'] if 'install-scanner.sh gitsign' in (s.get('run') or '')]"
case_ no-failure-issue        bad "$J.pop('patch-failed')"
case_ decide-concurrent       bad "$D.pop('concurrency')"
case_ no-schedule             bad "d['on'].pop('schedule')"
echo "release-patch-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
