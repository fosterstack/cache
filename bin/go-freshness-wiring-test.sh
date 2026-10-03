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
judge() { python3 - "$1" "${2:-$root}" <<'PY'
import glob, hashlib, json, os, re, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
tree = sys.argv[2]
bad = []
# Codex #157 r2 (SEC-157-02 A): the pin also binds what the privileged step EXECUTES — the bump script's bytes.
REVIEWED_BUMP_SCRIPT = "9b233929890d339ab12c454d331bbcdf0458428b47637d0544bf48543f802f84"
got_script = hashlib.sha256(open(os.path.join(tree, "bin/go-bump-open-pr.sh"), "rb").read()).hexdigest()
if got_script != REVIEWED_BUMP_SCRIPT:
    bad.append("bin/go-bump-open-pr.sh (run with the App token) differs from its reviewed form (%s)" % got_script[:12])
# (SEC-157-02 B): repository-wide, the jobs that may reach the agent environment, the App's secrets, the token action,
# every secret (toJSON) or inherited secrets are exactly these; a new consumer must come through review and be listed.
ALLOWED = {("agent-review-gate.yml", "publish"), ("agent-review-gate.yml", "sweep"), ("auditor.yml", "audit"),
           ("auditor.yml", "panel-probe"), ("dependabot-reviewer.yml", "review"), ("go-freshness.yml", "check"),
           ("hygiene.yml", "drift-fixer-dispatch"), ("main-candidate-rescan.yml", "panel-scout"),
           ("main-candidate-rescan.yml", "panel-google"), ("release.yml", "scans"), ("release.yml", "promotion")}
found = set()
for f in sorted(glob.glob(os.path.join(tree, ".github/workflows/*.y*ml"))):
    name = os.path.basename(f)
    w = d if name == "go-freshness.yml" else yaml.load(open(f), Loader=yaml.BaseLoader)   # the judged copy
    # conservative (Codex #157 r3/r4): environment names are case-insensitive and an expression-valued one may be agent;
    # expressions are case-insensitive and allow whitespace
    # (toJson, SECRETS[...]); a workflow-level env/defaults reaches every job, so each job is judged with it
    def text_of(o):     # the raw strings (keys and values): json.dumps would escape tabs/newlines past \s* (r5)
        if isinstance(o, dict):
            return " ".join(text_of(k) + " " + text_of(v) for k, v in o.items())
        if isinstance(o, list):
            return " ".join(text_of(x) for x in o)
        return str(o)
    wf_text = " " + text_of({k: (w or {}).get(k) for k in ("env", "defaults")})
    for j, v in ((w or {}).get("jobs") or {}).items():
        t = text_of(v) + wf_text + " " + json.dumps(v)
        env = v.get("environment")
        env_name = env.get("name") if isinstance(env, dict) else env
        if (isinstance(env_name, str) and env_name.strip().lower() == "agent") or (isinstance(env_name, str) and "${{" in env_name) \
                or re.search(r"(?i)auditor_app", t) or "create-github-app-token" in t \
                or re.search(r"(?i)tojson\s*\(\s*secrets\s*\)", t) or re.search(r"(?i)secrets\s*\[", t) \
                or v.get("secrets") == "inherit":
            found.add((name, j))
if found != ALLOWED:
    bad.append("the App's credential consumers changed: added %s, removed %s" % (sorted(found - ALLOWED), sorted(ALLOWED - found)))
# Codex #157 r1: properties alone let a widened App token (INPUT_PERMISSION-* in an env), another token consumer, a
# transformed-token print, a secrets export or a gutted bump step through. The privileged job is pinned WHOLE to its
# reviewed form (action pins masked, so a Dependabot bump of a pinned action does not trip it): any change to it —
# a step, an env, a command, an output — must come back through review and update this digest.
REVIEWED_CHECK_JOB = "67b87d4f0075780cd32572597bb6d515ee807f7ce6febb9c8d50dc1e99d79d40"
def mask(o):
    if isinstance(o, dict): return {k: mask(v) for k, v in o.items()}
    if isinstance(o, list): return [mask(v) for v in o]
    return re.sub(r"@[0-9a-f]{40}$", "@<pin>", o) if isinstance(o, str) else o
jobs = d.get("jobs") or {}
got = hashlib.sha256(json.dumps(mask(jobs.get("check") or {}), sort_keys=True).encode()).hexdigest()
if got != REVIEWED_CHECK_JOB:
    bad.append("the privileged check job differs from its reviewed form (%s)" % got[:12])
if sorted(jobs) != ["check", "mutation"]:
    bad.append("jobs other than check and mutation: %s" % sorted(jobs))
if d.get("env") or d.get("defaults"):
    bad.append("a workflow-level env/defaults reaches the privileged job")
for j, v in jobs.items():
    if j == "check":
        continue
    t = json.dumps(v)
    if "secrets" in t or "app-token" in t or "create-github-app-token" in t or v.get("environment") or "check" in str(v.get("needs", "")):
        bad.append("job %s touches secrets, the App token, the environment or the check job's outputs" % j)
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
  local f="$work/$1.yml" t="${4:-$root}"
  cp "$root/.github/workflows/go-freshness.yml" "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge "$f" "$t"); then got=ok; else got=bad; fi
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
# Codex #157 r1's surviving mutations
case_ input-env-widens       bad "$MINT.setdefault('env', {})['INPUT_PERMISSION-checks'] = 'write'"
case_ token-alt-spelling     bad "$C['steps'].append({'name': 'x', 'env': {'T': \"\${{ steps['app-token'].outputs.token }}\"}, 'run': 'true'})"
case_ second-checkout-cred   bad "$C['steps'].append({'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', 'with': {'token': '\${{ steps.app-token.outputs.token }}', 'persist-credentials': 'true'}})"
case_ token-printed          bad "[s.__setitem__('run', s['run'] + 'printf %s \"\$GH_TOKEN\" | od -An -tx1\\n') for s in $C['steps'] if 'go-bump-open-pr.sh' in (s.get('run') or '')]"
case_ another-agent-job      bad "d['jobs']['x'] = {'runs-on': 'ubuntu-latest', 'environment': 'agent', 'steps': [{'uses': 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1', 'with': {'permission-checks': 'write'}}]}"
case_ secrets-to-json        bad "$C.setdefault('env', {})['AGENT_SECRETS'] = '\${{ toJSON(secrets) }}'"
case_ key-through-outputs    bad "$C['outputs'] = {'k': '\${{ secrets.AUDITOR_APP_PRIVATE_KEY }}'}; d['jobs']['mutation']['needs'] = 'check'"
case_ bump-gutted            bad "[s.__setitem__('run', ':') for s in $C['steps'] if 'go-bump-open-pr.sh' in (s.get('run') or '')]"
case_ github-env-write       bad "[s.__setitem__('run', s['run'] + 'echo INPUT_PERMISSION-checks=write >> \"\$GITHUB_ENV\"\\n') for s in $C['steps'] if s.get('id') == 'cmp']"
case_ workflow-env           bad "d['env'] = {'INPUT_PERMISSION-checks': 'write'}"
# Codex #157 r2 (SEC-157-02): a token print inside the executed script; a sidecar workflow minting the App token
mk_tree() { local t="$work/tree-$1"; mkdir -p "$t/bin" "$t/.github/workflows"; cp "$root"/.github/workflows/*.yml "$t/.github/workflows/"; cp "$root/bin/go-bump-open-pr.sh" "$t/bin/"; echo "$t"; }
t=$(mk_tree script-leak); printf '\nprintf %%s "$GH_TOKEN" | od -An -tx1\n' >> "$t/bin/go-bump-open-pr.sh"
case_ script-token-print     bad "" "$t"
t=$(mk_tree sidecar); printf 'on: workflow_dispatch\njobs:\n  x:\n    runs-on: ubuntu-latest\n    environment: agent\n    steps:\n      - uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1\n        with:\n          app-id: ${{ secrets.AUDITOR_APP_ID }}\n          permission-checks: write\n' > "$t/.github/workflows/probe-sidecar.yml"
case_ sidecar-workflow       bad "" "$t"
t=$(mk_tree tojson); printf 'on: push\njobs:\n  y:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        env:\n          S: ${{ toJSON(secrets) }}\n' > "$t/.github/workflows/dump.yml"
case_ secrets-dump-elsewhere bad "" "$t"
# Codex #157 r3 (SEC-157-02 B): an expression-valued environment with toJson (any case); a workflow-level secret env
t=$(mk_tree expr-env); printf 'on: workflow_dispatch\njobs:\n  x:\n    runs-on: ubuntu-latest\n    environment:\n      name: ${{ '"'"'agent'"'"' }}\n    steps:\n      - run: echo hi\n        env:\n          S: ${{ toJson(secrets) }}\n' > "$t/.github/workflows/probe-sidecar.yml"
case_ expr-env-tojson        bad "" "$t"
t=$(mk_tree wf-env-secret); printf 'on: workflow_dispatch\nenv:\n  K: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}\njobs:\n  x:\n    runs-on: ubuntu-latest\n    environment: ${{ '"'"'agent'"'"' }}\n    steps:\n      - run: echo hi\n' > "$t/.github/workflows/probe-sidecar2.yml"
case_ workflow-env-secret    bad "" "$t"
t=$(mk_tree secrets-index); printf 'on: push\njobs:\n  y:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        env:\n          K: ${{ SECRETS['"'"'AUDITOR_APP_ID'"'"'] }}\n' > "$t/.github/workflows/idx.yml"
case_ secrets-index-upper    bad "" "$t"
# Codex #157 r4 (SEC-157-02 B, round 5): environment names are case-insensitive; expression functions allow whitespace
t=$(mk_tree env-upper); printf 'on: workflow_dispatch\njobs:\n  x:\n    runs-on: ubuntu-latest\n    environment: AGENT\n    steps:\n      - run: echo hi\n        env:\n          S: ${{ toJson (secrets) }}\n' > "$t/.github/workflows/probe-sidecar.yml"
case_ env-name-upper         bad "" "$t"
t=$(mk_tree env-mixed); printf 'on: workflow_dispatch\njobs:\n  x:\n    runs-on: ubuntu-latest\n    environment:\n      name: AgEnT\n    steps:\n      - run: echo hi\n' > "$t/.github/workflows/probe-sidecar.yml"
case_ env-name-mapped-mixed  bad "" "$t"
t=$(mk_tree tojson-space); printf 'on: push\njobs:\n  y:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        env:\n          S: ${{ toJSON  (  secrets  ) }}\n' > "$t/.github/workflows/dump2.yml"
case_ tojson-whitespace      bad "" "$t"
# Codex #157 r5 (pass 5b): a tab or a newline inside the expression (json.dumps escaped them past the match)
t=$(mk_tree tojson-tab); printf 'on: push\njobs:\n  y:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        env:\n          S: "${{ toJson\t(secrets) }}"\n' > "$t/.github/workflows/dump3.yml"
case_ tojson-tab             bad "" "$t"
t=$(mk_tree tojson-newline); printf 'on: push\njobs:\n  y:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        env:\n          S: |-\n            ${{ toJson\n            (secrets) }}\n' > "$t/.github/workflows/dump4.yml"
case_ tojson-newline         bad "" "$t"
echo "go-freshness-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
