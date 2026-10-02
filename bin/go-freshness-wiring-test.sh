#!/usr/bin/env bash
# proves: REQ-REL-004-AC4
# go-freshness.yml opens its bump PR with the auditor App's token (owner, Oct 2; advisor 0055): the check job's own token
# is read-only; it runs in the main-only agent environment; the App token is minted with exactly the auditor's scope
# (repositories: cache; contents and pull-requests write; nothing else) and only the bump step uses it; the checkout
# keeps no credential. The mutation job gets none of it. The real workflow must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" <<'PY'
import sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
bad = []
c = (d.get("jobs") or {}).get("check") or {}
m = (d.get("jobs") or {}).get("mutation") or {}
if c.get("permissions") != {"contents": "read"}:
    bad.append("the check job's own token is not read-only: %s" % c.get("permissions"))
if c.get("environment") != "agent":
    bad.append("the check job is not in the main-only agent environment")
steps = c.get("steps") or []
mint = [s for s in steps if str(s.get("uses", "")).startswith("actions/create-github-app-token@")]
want = {"app-id": "${{ secrets.AUDITOR_APP_ID }}", "private-key": "${{ secrets.AUDITOR_APP_PRIVATE_KEY }}",
        "repositories": "cache", "permission-contents": "write", "permission-pull-requests": "write"}
if len(mint) != 1 or mint[0].get("with") != want or mint[0].get("id") != "app-token":
    bad.append("the App token is not minted exactly as the auditor scopes it: %s" % [s.get("with") for s in mint])
users = [s for s in steps if "steps.app-token.outputs.token" in str(s)]
if [s.get("name") for s in users] != ["open (or recover) the bump PR"]:
    bad.append("the App token reaches a step other than the bump step: %s" % [s.get("name") for s in users])
co = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
if not co or (co[0].get("with") or {}).get("persist-credentials") != "false":
    bad.append("the checkout keeps a credential")
if m.get("environment") or "app-token" in str(m) or (m.get("permissions") or {}) != {"contents": "read"}:
    bad.append("the mutation job gets the environment, the App token or more than read")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_() {
  local f="$work/$1.yml"
  cp "$root/.github/workflows/go-freshness.yml" "$f"
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
C='d["jobs"]["check"]'
MINT="[s for s in $C['steps'] if str(s.get('uses','')).startswith('actions/create-github-app-token@')][0]"
case_ real                   ok  ""
case_ job-token-writes       bad "$C['permissions']['contents'] = 'write'"
case_ no-environment         bad "$C.pop('environment')"
case_ app-widened-checks     bad "$MINT['with']['permission-checks'] = 'write'"
case_ app-all-repos          bad "$MINT['with'].pop('repositories')"
case_ token-to-compare-step  bad "[s.setdefault('env', {}).__setitem__('GH_TOKEN', '\${{ steps.app-token.outputs.token }}') for s in $C['steps'] if s.get('id') == 'cmp']"
case_ checkout-keeps-cred    bad "[s.setdefault('with', {}).__setitem__('persist-credentials', 'true') for s in $C['steps'] if str(s.get('uses','')).startswith('actions/checkout@')]"
case_ mutation-in-agent      bad "d['jobs']['mutation']['environment'] = 'agent'"
echo "go-freshness-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
