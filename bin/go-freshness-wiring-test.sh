#!/usr/bin/env bash
# proves: REQ-REL-004-AC4
# proves: REQ-REFRESH-001-AC24
# proves: REQ-REFRESH-001-AC25
# proves: REQ-REFRESH-001-AC26
# proves: REQ-REFRESH-001-AC27
# proves: REQ-REFRESH-001-AC28
# proves: REQ-REFRESH-001-AC29
# proves: REQ-REFRESH-001-AC30
# proves: REQ-REFRESH-001-AC31
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
REVIEWED_BUMP_SCRIPT = "2f1e4a49909da5af5e1e6db4e47f0134d2e7e7e98336bad5343dbaebfb5baf3c"
got_script = hashlib.sha256(open(os.path.join(tree, "bin/go-bump-open-pr.sh"), "rb").read()).hexdigest()
if got_script != REVIEWED_BUMP_SCRIPT:
    bad.append("bin/go-bump-open-pr.sh (run with the App token) differs from its reviewed form (%s)" % got_script[:12])
# (SEC-157-02 B): repository-wide, the jobs that may reach the agent environment, the App's secrets, the token action,
# every secret (toJSON) or inherited secrets are exactly these; a new consumer must come through review and be listed.
ALLOWED = {("agent-review-gate.yml", "publish"), ("agent-review-gate.yml", "sweep"), ("agent-review-gate.yml", "record"), ("auditor.yml", "audit"),
           ("auditor.yml", "panel-probe"), ("dependabot-reviewer.yml", "review"), ("go-freshness.yml", "check"), ("go-freshness.yml", "refresh"),
           ("main-candidate-rescan.yml", "panel-scout"),
           ("main-candidate-rescan.yml", "panel-google"),  # the release.yml promotion job (scans) is gone: Check holds no secret (PR 3), Release is the release job (PR 4)
           # the Scout root-cause round (#176): the agent environment for its own Docker Hub token, same reason as
           # panel-scout/panel-google above; it never mints or uses the auditor App's token
           ("main-candidate-rescan.yml", "scout-root-cause"), ("main-candidate-rescan.yml", "scout-older-versions"),
           # automatic patch releases (REQ-REL-009, PR B/#159): decide is main-only + gitsign (id-token) AND mints
           # the auditor App's token (contents write only) to push the signed tag; patch-notes mints the same App's
           # token (contents + pull-requests) to open the changelog PR after that tag — both deliberate, reviewed
           # consumers of that credential (Sonnet #158 r3, REL-DECIDE-01: the earlier comment wrongly said decide
           # never touches the App's secrets)
           ("release.yml", "decide"), ("release.yml", "patch-notes"),
           # the records sweep (handoff 0681): mints the auditor App's token (contents write, this repository) to add
           # the vendored tree and provenance records to a dependency-bump branch; the agent environment keeps it
           # on main
           ("dependabot-reviewer.yml", "vendor-records")}
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
if sorted(jobs) not in (["check", "mutation", "refresh"], ["check", "mutation", "persona-uat", "refresh"]):      # persona-uat's PRESENCE is persona-uat-wiring-test.sh's job
    bad.append("jobs other than check, mutation, refresh and persona-uat: %s" % sorted(jobs))
if d.get("env") or d.get("defaults"):
    bad.append("a workflow-level env/defaults reaches the privileged job")
for j, v in jobs.items():
    if j in ("check", "refresh"):
        continue
    if j == "persona-uat":
        # REQ-UAT-001's weekly job (its exact shape is pinned by persona-uat-wiring-test.sh): its own environment and the model identity secrets ONLY;
        # never the App token, never the privileged check job's environment, outputs or secrets
        t = json.dumps(v)
        allowed = {"ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID",
                   "PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL"}      # the model ids are environment secrets (advisor 0233)
        used = set(re.findall(r"secrets\.([A-Za-z0-9_]+)", t))
        if used - allowed or "app-token" in t or "create-github-app-token" in t or v.get("environment") != "persona-uat" or "check" in str(v.get("needs", "")):
            bad.append("the persona-uat job touches more than its own environment and the model identity secrets (%s)" % sorted(used - allowed))
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
# ---- the refresh job (REQ-REFRESH-001-AC24 to AC30; owner's rules 4 to 9 of Oct 14)
r = jobs.get("refresh") or {}
rsteps = r.get("steps") or []
rnames = [s.get("name") for s in rsteps]
if r.get("environment") != "agent":
    bad.append("AC28: the refresh job is not in the main-only agent environment")
if r.get("permissions") != {"contents": "read", "packages": "write"}:
    bad.append("AC28: the refresh job's own token is not contents: read plus packages: write: %s" % r.get("permissions"))
if d.get("permissions") != {"contents": "read"}:
    bad.append("AC28: the top-level permissions are not contents: read")
cond = str(r.get("if", ""))
if re.sub(r"\s+", " ", cond).strip() != "${{ github.ref == 'refs/heads/main' && (github.event_name == 'workflow_dispatch' || github.event.schedule == '23 6 * * *') }}":
    bad.append("AC25: the refresh job's condition is not main plus schedule or dispatch: %s" % cond)
trig = d.get("on") or d.get(True) or {}
sched = trig.get("schedule") if isinstance(trig, dict) else None
if not isinstance(sched, list) or {"cron": "23 6 * * *"} not in sched:
    bad.append("AC25: the schedule the refresh job runs on (cron 23 6 * * *) is missing from the triggers: %s" % sched)
conc = r.get("concurrency")
if not isinstance(conc, dict) or conc.get("group") != "refresh-inputs" or str(conc.get("cancel-in-progress")).lower() != "false" or sorted(conc) != ["cancel-in-progress", "group"]:
    bad.append("AC29: the refresh jobs are not serialized (concurrency group refresh-inputs, cancel-in-progress false): %s" % r.get("concurrency"))
if [x.get("name") for x in rsteps if str(x.get("continue-on-error", "false")).lower() not in ("false", "")] or str(r.get("continue-on-error", "false")).lower() != "false":
    bad.append("AC30: a refresh step or the job is allowed to continue on error (a stop must stop the later steps)")
if sorted(trig) != ["schedule", "workflow_dispatch"]:
    bad.append("AC25: go-freshness.yml triggers are not schedule and workflow_dispatch only: %s" % sorted(trig))
wf = sorted(os.path.basename(f) for f in glob.glob(os.path.join(tree, ".github/workflows/*.y*ml")))
if "go-freshness.yml" not in wf or any(n.startswith("refresh") for n in wf):
    bad.append("AC24: a refresh workflow file exists beside go-freshness.yml: %s" % wf)
rmint = [s for s in rsteps if str(s.get("uses", "")).startswith("actions/create-github-app-token@")]
if len(rmint) != 1 or rmint[0].get("with") != want or rmint[0].get("id") != "app-token":
    bad.append("AC28: the refresh job does not mint the App token exactly as the check job does: %s" % [s.get("with") for s in rmint])
rusers = [s.get("name") for s in rsteps if "steps.app-token.outputs.token" in str(s)]
if rusers != ["refresh the inputs (stage the pull request)", "check for a newer certified crypto module", "open the pull requests"]:
    bad.append("AC28: the App token reaches steps other than the three refresh steps: %s" % rusers)
KEYCHK = "check the live Wolfi key against the pinned one"
ARCHKEY = "check the live Wolfi key against the pulled archive"
BOOT_NAME = "bootstrap the archive from the pinned Wolfi key"
PULL_NAME = "pull the archive by its recorded digest"
_names = [n for n in rnames if n]
if ARCHKEY not in rnames or not (rnames.index(ARCHKEY) > max(rnames.index(n) for n in ("pull the archive by its recorded digest", "bootstrap the archive from the pinned Wolfi key") if n in rnames)) \
        or [x for x in rsteps if str(x.get("uses", "")).startswith("actions/create-github-app-token@")] and rnames.index(ARCHKEY) > next(k for k, x in enumerate(rsteps) if str(x.get("uses", "")).startswith("actions/create-github-app-token@")):
    bad.append("AC30: the live key is not compared with the pulled archive's key after the archive is pulled or seeded and before the token is minted")
elif "./bin/refresh-inputs.sh archive-key-check " not in "".join(str(x.get("run", "")) for x in rsteps if x.get("name") == ARCHKEY) or any(x.get("if") for x in rsteps if x.get("name") == ARCHKEY):
    bad.append("AC30: the archive key check step does not call refresh-inputs.sh archive-key-check, or carries an if")
for x in rsteps:
    if x.get("name") not in (BOOT_NAME, PULL_NAME) and re.search(r"(always|failure|cancelled)\s*\(", str(x.get("if", "")), re.I):
        bad.append("AC30: the refresh step %r runs after a failure (%s); a stop must stop every later step" % (x.get("name"), x.get("if")))
if len(rnames) < 2 or rnames[1] != KEYCHK if rnames else True:
    bad.append("AC26/AC30: the live key is not checked against the pinned one in the first step after the checkout (before tool installation, registry login, archive retrieval and token minting)")
elif "./bin/refresh-inputs.sh key-check " not in "".join(str(x.get("run", "")) for x in rsteps if x.get("name") == KEYCHK) or any(x.get("if") for x in rsteps if x.get("name") == KEYCHK):
    bad.append("AC26/AC30: the key check step does not call refresh-inputs.sh key-check, or carries an if")
ORDER = ["pull the archive by its recorded digest", "refresh the inputs (stage the pull request)",
         "check for a newer certified crypto module", "store the archive when something changed", "open the pull requests"]
BOOT = "bootstrap the archive from the pined Wolfi key".replace("pined", "pinned")
pos = [rnames.index(n) if n in rnames else -1 for n in ORDER]
if -1 in pos or pos != sorted(pos):
    bad.append("AC26: the refresh steps are missing or out of the ratified order: %s" % [n for n in rnames])
def run_of(n):
    return "".join(str(s.get("run", "")) for s in rsteps if s.get("name") == n)
if not re.search(r"(^|\s)\./bin/archive-pull\.sh --pointer build/archive\.json --out ", run_of(ORDER[0])):
    bad.append("AC27: the archive is not pulled by the committed pointer with bin/archive-pull.sh")
if "./bin/refresh-inputs.sh refresh " not in run_of(ORDER[1]) or "./bin/refresh-inputs.sh fips-module " not in run_of(ORDER[2]) \
        or "--plan-dir" not in run_of(ORDER[1]) or "--plan-dir" not in run_of(ORDER[2]):
    bad.append("AC26: the refresh steps do not call refresh-inputs.sh refresh and fips-module with --plan-dir (the pull request is opened after the archive is stored)")
# rc-3 R5: the certified-module check asks about OUR toolchain, so it reads the checksum-pinned one (bin/install-scanner.sh go), never the floating setup-go
GO_NAME = "install the pinned Go toolchain"
GO_ROOT = "/usr/local/bin/fscache-go"
if GO_NAME not in rnames or ORDER[2] not in rnames or rnames.index(GO_NAME) > rnames.index(ORDER[2]) or rnames.index(GO_NAME) < 2:
    bad.append("AC26: the pinned Go toolchain is not installed (after the key check, before the certified-module check)")
elif run_of(GO_NAME).strip().splitlines() != ["set -euo pipefail", "./bin/install-scanner.sh go"] or any(x.get("if") for x in rsteps if x.get("name") == GO_NAME):
    bad.append("AC26: the pinned Go toolchain step does not run bin/install-scanner.sh go unconditionally")
if not re.search(r"--go-root " + re.escape(GO_ROOT) + r"(\s|$)", run_of(ORDER[2])) or "go env" in run_of(ORDER[2]):
    bad.append("AC26: the certified-module check does not read the pinned toolchain (--go-root %s), or asks `go env`" % GO_ROOT)
if [x for x in rsteps if str(x.get("uses", "")).startswith("actions/setup-go@")]:
    bad.append("AC26: the refresh job installs a floating Go with setup-go; the toolchain it reads is the pinned one")
if "./bin/refresh-inputs.sh open-pr " not in run_of(ORDER[4]) or "--plan-dir" not in run_of(ORDER[4]):
    bad.append("AC29: the pull requests are not opened by refresh-inputs.sh open-pr from the plan")
boot = [s for s in rsteps if s.get("name") == BOOT]
pull = [s for s in rsteps if s.get("name") == ORDER[0]]
if len(boot) != 1 or "./bin/refresh-inputs.sh bootstrap " not in str(boot[0].get("run", "")) or "hashFiles('build/archive.json') == ''" not in str(boot[0].get("if", "")):
    bad.append("AC26: the bootstrap step is missing, or runs when build/archive.json exists")
if len(pull) != 1 or "hashFiles('build/archive.json') != ''" not in str(pull[0].get("if", "")):
    bad.append("AC27: the pull step does not run exactly when build/archive.json exists")
if rnames.index(BOOT) > rnames.index(ORDER[1]) if BOOT in rnames and ORDER[1] in rnames else True:
    bad.append("AC26: the bootstrap step does not come before the refresh step")
if not re.search(r'if \[ "\$after" = "\$\(cat "\$RUNNER_TEMP/archive\.before"\)" \]; then\n[^\n]*\n\s*else\n\s*digest=\$\(\./bin/archive-push\.sh --dir "\$RUNNER_TEMP/archive"\)\n', run_of(ORDER[3])) \
        or [x for x in rsteps if x.get("name") == ORDER[3] and x.get("if")]:
    bad.append("AC27: the archive is not stored by bin/archive-push.sh only when something changed (the push is on the else branch of the unchanged-digest comparison)")
for f in sorted(glob.glob(os.path.join(tree, ".github/workflows/*.y*ml"))):
    txt = open(f).read()
    if "archive-push.sh" in txt and os.path.basename(f) != "go-freshness.yml":
        bad.append("AC27: %s calls archive-push.sh" % os.path.basename(f))
    if os.path.basename(f) == "go-freshness.yml":
        for jn, jv in jobs.items():
            if jn != "refresh" and "archive-push.sh" in json.dumps(jv):
                bad.append("AC27: job %s calls archive-push.sh" % jn)
rtext = json.dumps(r)
if re.search(r"gh\s+pr\s+(merge|review|approve)|--auto\b|git\s+push[^\"]*\bmain\b|--admin", rtext):
    bad.append("AC29: the refresh job merges, approves or pushes to main")
if rsteps and (rsteps[0].get("with") or {}).get("persist-credentials") != "false":
    bad.append("AC28: the refresh checkout keeps a credential")
# AC31: every action reference in the refresh job is a commit digest with a tag comment (read from the file text: the loader drops comments)
# the judged copy may have been re-dumped (comments gone), so: a digest in the judged copy, and the tag comment in the tree's own file
for label, path, need_comment in (("judged copy", sys.argv[1], False), ("tree file", os.path.join(tree, ".github/workflows/go-freshness.yml"), True)):
    inref = False
    for line in open(path).read().splitlines():
        if re.match(r"^  refresh:", line): inref = True; continue
        if inref and re.match(r"^  [A-Za-z0-9_-]+:", line): inref = False
        if inref and re.search(r"^\s*-?\s*uses:", line):
            pat = r"uses:\s*\S+@[0-9a-f]{40}(\s+#\s*\S+)" + ("" if need_comment else "?") + r"\s*$"
            if not re.search(pat, line):
                bad.append("AC31: an action reference in the refresh job (%s) is not a commit digest with a tag comment: %s" % (label, line.strip()))
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
# Codex #345 r3 (AC31): a copy that changes the meaning of AC25 or AC27 while keeping the words the old judge looked for
R='d["jobs"]["refresh"]'
case_ refresh-ref-inverted   bad "$R['if'] = $R['if'].replace(\"github.ref == 'refs/heads/main'\", \"github.ref != 'refs/heads/main'\")"
case_ refresh-or-instead-and bad "$R['if'] = $R['if'].replace(\"' && (\", \"' || (\")"
case_ store-unconditional    bad "[s.__setitem__('run', 'set -euo pipefail\\n./bin/archive-push.sh --dir \"\$RUNNER_TEMP/archive\" # changed\\n') for s in $R['steps'] if s.get('name') == 'store the archive when something changed']"
case_ store-if-inverted      bad "[s.__setitem__('run', s['run'].replace('if [ \"\$after\" = ', 'if [ \"\$after\" != ')) for s in $R['steps'] if s.get('name') == 'store the archive when something changed']"
# Codex #345 r4: overlapping runs, the daily schedule itself, and a stop that is allowed to continue
case_ archive-keycheck-removed bad "$R['steps'] = [s for s in $R['steps'] if s.get('name') != 'check the live Wolfi key against the pulled archive']"
case_ archive-keycheck-if      bad "[s.__setitem__('if', '\${{ always() }}') for s in $R['steps'] if s.get('name') == 'check the live Wolfi key against the pulled archive']"
case_ archive-keycheck-late    bad "$R['steps'].append($R['steps'].pop([k for k, s in enumerate($R['steps']) if s.get('name') == 'check the live Wolfi key against the pulled archive'][0]))"
case_ later-step-always        bad "[s.__setitem__('if', '\${{ always() }}') for s in $R['steps'] if s.get('name') == 'check for a newer certified crypto module']"
case_ later-step-failure-space bad "[s.__setitem__('if', '\${{ failure () }}') for s in $R['steps'] if s.get('name') == 'check for a newer certified crypto module']"
case_ later-step-always-upper  bad "[s.__setitem__('if', '\${{ ALWAYS() }}') for s in $R['steps'] if s.get('name') == 'check for a newer certified crypto module']"
case_ refresh-no-concurrency  bad "$R.pop('concurrency', None)"
case_ refresh-cancel-in-prog  bad "$R['concurrency'] = {'group': 'refresh-inputs', 'cancel-in-progress': True}"
case_ refresh-other-group     bad "$R['concurrency'] = {'group': 'refresh-inputs-' + '\${{ github.run_id }}', 'cancel-in-progress': False}"
case_ schedule-emptied        bad "d['on']['schedule'] = []"
case_ schedule-other-cron     bad "d['on']['schedule'] = [{'cron': '23 6 * * 1'}]"
case_ keycheck-continues      bad "[s.__setitem__('continue-on-error', True) for s in $R['steps'] if s.get('name') == 'check the live Wolfi key against the pinned one']"
case_ any-refresh-step-continues bad "$R['steps'][-1]['continue-on-error'] = True"
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
# the refresh job (AC24 to AC31)
R='d["jobs"]["refresh"]'
RSTEP="[s for s in %s['steps'] if s.get('name') == '%s'][0]"
case_ refresh-wrong-env       bad "$R['environment'] = 'other'"
case_ refresh-writes-contents bad "$R['permissions']['contents'] = 'write'"
case_ refresh-more-perms      bad "$R['permissions']['id-token'] = 'write'"
case_ refresh-on-pr-ref       bad "$R['if'] = \"\${{ github.event_name == 'pull_request' || github.event_name == 'workflow_dispatch' || github.event.schedule == 'x' }}\""
case_ refresh-pull-request-trigger bad "d['on']['pull_request'] = {}"
case_ refresh-token-too-wide  bad "[s['with'].__setitem__('permission-packages', 'write') for s in $R['steps'] if str(s.get('uses','')).startswith('actions/create-github-app-token@')]"
case_ refresh-token-extra-step bad "$R['steps'].append({'name': 'x', 'env': {'GH_TOKEN': '\${{ steps.app-token.outputs.token }}'}, 'run': 'true'})"
case_ refresh-order-swapped   bad "a = $R['steps']; n = [s.get('name') for s in a]; i = n.index('pull the archive by its recorded digest'); j = n.index('refresh the inputs (stage the pull request)'); a[i], a[j] = a[j], a[i]"
case_ refresh-pull-by-tag     bad "[s.__setitem__('run', 'crane pull ghcr.io/x/archive:latest out') for s in $R['steps'] if s.get('name') == 'pull the archive by its recorded digest']"
case_ refresh-bootstrap-always bad "[s.pop('if', None) for s in $R['steps'] if s.get('name') == 'bootstrap the archive from the pinned Wolfi key']"
case_ refresh-keycheck-removed bad "$R['steps'][:] = [s for s in $R['steps'] if s.get('name') != 'check the live Wolfi key against the pinned one']"
case_ refresh-go-root-floating bad "[s.__setitem__('run', s['run'].replace('/usr/local/bin/fscache-go', '\$(go env GOROOT)')) for s in $R['steps'] if s.get('name') == 'check for a newer certified crypto module']"
case_ refresh-pinned-go-or-true bad "[s.__setitem__('run', s['run'].rstrip() + ' || true\\n') for s in $R['steps'] if s.get('name') == 'install the pinned Go toolchain']"
case_ refresh-go-root-lookalike bad "[s.__setitem__('run', s['run'].replace('/usr/local/bin/fscache-go', '/usr/local/bin/fscache-go2')) for s in $R['steps'] if s.get('name') == 'check for a newer certified crypto module']"
case_ refresh-pinned-go-removed bad "$R['steps'][:] = [s for s in $R['steps'] if s.get('name') != 'install the pinned Go toolchain']"
case_ refresh-pinned-go-late bad "a = $R['steps']; n = [s.get('name') for s in a]; a.insert(n.index('check for a newer certified crypto module') + 1, a.pop(n.index('install the pinned Go toolchain')))"
case_ refresh-setup-go-back bad "$R['steps'].insert(2, {'uses': 'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e', 'with': {'go-version': '1.27'}})"
case_ refresh-pinned-go-unlisted-install bad "[s.__setitem__('run', 'tar -xzf \"\$RUNNER_TEMP/go.tgz\" -C /usr/local/bin') for s in $R['steps'] if s.get('name') == 'install the pinned Go toolchain']"
case_ refresh-keycheck-late bad "a = $R['steps']; n = [s.get('name') for s in a]; i = n.index('check the live Wolfi key against the pinned one'); a.insert(n.index('pull the archive by its recorded digest'), a.pop(i))"
case_ refresh-keycheck-if bad "[s.__setitem__('if', 'always()') for s in $R['steps'] if s.get('name') == 'check the live Wolfi key against the pinned one']"
case_ refresh-bootstrap-removed bad "$R['steps'][:] = [s for s in $R['steps'] if s.get('name') != 'bootstrap the archive from the pinned Wolfi key']"
case_ refresh-pr-before-store bad "a = $R['steps']; n = [s.get('name') for s in a]; i = n.index('store the archive when something changed'); j = n.index('open the pull requests'); a[i], a[j] = a[j], a[i]"
case_ refresh-opens-in-refresh bad "[s.__setitem__('run', s['run'].replace(' --plan-dir', '')) for s in $R['steps'] if s.get('name') == 'refresh the inputs (stage the pull request)']"
case_ refresh-push-always     bad "[s.__setitem__('run', './bin/archive-push.sh --dir \"\$RUNNER_TEMP/archive\"') for s in $R['steps'] if s.get('name') == 'store the archive when something changed']"
case_ refresh-merges          bad "[s.__setitem__('run', s['run'] + 'gh pr merge --auto --squash\\n') for s in $R['steps'] if s.get('name') == 'refresh the inputs (stage the pull request)']"
case_ refresh-job-removed     bad "$R.clear(); d['jobs'].pop('refresh')"
case_ refresh-push-in-check   bad "[s.__setitem__('run', s['run'] + './bin/archive-push.sh --dir x\\n') for s in $C['steps'] if s.get('id') == 'cmp']"
case_ refresh-checkout-cred   bad "$R['steps'][0].setdefault('with', {})['persist-credentials'] = 'true'"
t=$(mk_tree refresh-file); printf 'on: workflow_dispatch\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n' > "$t/.github/workflows/refresh.yml"
case_ refresh-workflow-added  bad "" "$t"
t=$(mk_tree refresh-push-elsewhere); printf 'on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./bin/archive-push.sh --dir x\n' > "$t/.github/workflows/other.yml"
case_ archive-push-other-workflow bad "" "$t"
# an action reference that is a tag, not a digest, in the refresh job (the file text is judged, so write it into the copy)
cp "$root/.github/workflows/go-freshness.yml" "$work/tagpin.yml"; python3 - "$work/tagpin.yml" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
i = s.index("\n  refresh:")
head, tail = s[:i], s[i:]
tail = re.sub(r"(uses: actions/checkout@)[0-9a-f]{40}(\s+# v[0-9.]+)", r"\1v7", tail, count=1)
open(p, "w").write(head + tail)
PY
if out=$(judge "$work/tagpin.yml" "$root"); then got=ok; else got=bad; fi
if [ "$got" = bad ]; then pass=$((pass+1)); echo "PASS refresh-action-by-tag → bad ($out)"; else failn=$((failn+1)); echo "FAIL refresh-action-by-tag → ok"; fi
echo "go-freshness-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
