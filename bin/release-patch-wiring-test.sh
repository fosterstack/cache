#!/usr/bin/env bash
# proves: REQ-REL-009-AC3, REQ-REL-009-AC5, REQ-REL-009-AC8, REQ-REL-009-AC10, REQ-REL-009-AC13
# Automatic patch releases in release.yml (owner RATIFIED Oct 2; advisor 0051/0055/0056/0057), PR B:
# - push to main and a daily schedule run ONLY the decide job; the release chain starts only on a v* tag (admission is
#   guarded to tags, every other stage needs it);
# - decide runs on main only, in the main-only agent environment, with its own token read-only plus id-token (gitsign)
#   and issues (the standing "not patch-clean" issue); the critical/high comparison scans the release and the new base;
# - the tag is signed keylessly by gitsign (pinned by checksum, no key) under release.yml's identity and pushed with the
#   auditor App's token (exactly the auditor's scope), which reaches only the push step;
# - a failed patch-tag run opens one issue and is never retried;
# - AC8 wired (advisor 0135): the notes are built before signing and are the signed tag's message; a separate job opens
#   the changelog-and-clear PR (auto-merge on green) with its own App token; stage-promote posts a patch tag's notes.
# The real workflow must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export WIRING_ROOT="$root"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { ROOT="$root" python3 - "$1" "${2:-$root/.github/workflows/stage-promote.yml}" <<'PY'
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
chain = [j for j in jobs if j not in ("admission", "decide", "patch-failed", "patch-notes")]
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
if dec.get("permissions") != {"contents": "read", "checks": "read", "id-token": "write", "issues": "write"}:
    bad.append("decide's own token is not contents read + checks read + id-token + issues: %s" % dec.get("permissions"))
if d.get("concurrency"):
    bad.append("a workflow-level concurrency group would serialize the tag chain with decide (it must be decide's own)")
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
# advisor 0063: before signing, wait (bounded) for the tagged commit's push-scoped required checks, judged as admission
# judges them; sign, mint and push only when they are ready
names = [s.get("name") for s in steps]
# REQ-REL-009-AC13 (owner RATIFIED Oct 2): decide pre-checks the baseline admission will require — the same rule
# (bin/admission-tag-signer.py baseline) on the same files — and waits/cuts only when it holds
pre = [s for s in steps if s.get("id") == "basecheck"]
# advisor 0093: the pre-check reads baselines the way admission does — only from owner-SSH-signed tags, verified against
# protected main's allowed signers — never from the checkout's requirements/releases/
prun = pre[0].get("run") or "" if pre else ""
if "bin/admission-tag-signer.py owner-baselines" not in prun or "git show origin/main:.github/policy/allowed_signers" not in prun \
        or "--releases-dir" in prun or "--owner-baselines" not in prun:
    bad.append("decide's pre-check does not read baselines only from owner-signed tags (as admission does)")
if len(pre) != 1 or "bin/admission-tag-signer.py baseline" not in (pre[0].get("run") or "") or \
        "steps.decide.outputs.cut == 'true'" not in pre[0].get("if", "") or \
        "--requirements requirements/requirements.yaml" not in (pre[0].get("run") or ""):
    bad.append("decide does not pre-check the ACs baseline with admission's rule")
wait = [s for s in steps if s.get("id") == "checks"]
if len(wait) != 1 or "patch-decide.py ready" not in (wait[0].get("run") or "") or \
        not (wait[0].get("timeout-minutes") or "").isdigit() or int(wait[0]["timeout-minutes"]) > 70 or \
        "steps.basecheck.outputs.ok == 'true'" not in wait[0].get("if", "") or \
        "check-runs?filter=latest" not in (wait[0].get("run") or ""):
    bad.append("no bounded wait for the tagged commit's required checks (patch-decide.py ready) before a cut")
gated = [s.get("name") or s.get("id") for s in steps
         if ("tag -s" in (s.get("run") or "") or s.get("id") == "app-token" or "git push" in (s.get("run") or ""))]
ungated = [g for g, st in zip(gated, [s for s in steps if (s.get("name") or s.get("id")) in gated])
           if "steps.checks.outputs.ready == 'true'" not in st.get("if", "")]
if len(gated) != 3 or ungated:
    bad.append("signing, the App token or the push does not wait for ready: %s" % (ungated or gated))
if wait and gated and names.index(wait[0].get("name")) > min(names.index(g) for g in gated if g in names):
    bad.append("the wait comes after signing")
co = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
if not co or (co[0].get("with") or {}).get("fetch-depth") != "0":
    bad.append("decide's checkout is shallow (a queued run must see every tag, including the earlier run's)")
if not co or (co[0].get("with") or {}).get("persist-credentials") != "false":
    bad.append("decide's checkout keeps a credential")
fail = jobs.get("patch-failed") or {}
if "failure()" not in fail.get("if", "") or "refs/tags/v" not in fail.get("if", "") or fail.get("permissions") != {"contents": "read", "issues": "write"}:
    bad.append("no failure-issue job for tag runs: %s" % fail.get("if"))
if "gh issue create" not in "\n".join(s.get("run") or "" for s in fail.get("steps") or []):
    bad.append("the failure job opens no issue")
if re.search(r"gh run rerun|rerun-failed|/rerun\b|actions/runs/\S+/rerun", yaml.safe_dump(d), re.I):
    bad.append("a retry path exists")
# Codex #159 r1: the failure issue names its repository (B3); the baseline is the latest PUBLISHED release, so a failed
# tag is retried by the next run (B4); an unscannable release is "unknown", never an empty release (B2); ready reads
# the required checks from protected main, as admission does (B6)
fenv = {k: v for s in fail.get("steps") or [] for k, v in (s.get("env") or {}).items()}
if fenv.get("GH_REPO") != "${{ github.repository }}":
    bad.append("the failure job's gh has no repository (GH_REPO)")
dstep = [s for s in steps if "patch-decide.py decide" in (s.get("run") or "")]
facts = [s for s in steps if s.get("id") == "facts"]
if not dstep or '--released "$RUNNER_TEMP/released.json"' not in dstep[0]["run"] or not facts or \
        "gh release list --exclude-drafts" not in facts[0]["run"] or "released.json" not in facts[0]["run"]:
    bad.append("decide's baseline is not the latest published release")
scan = [s for s in steps if "patch-decide.py removed" in (s.get("run") or "")]
if not scan or "&& rel+=" in scan[0]["run"] or "removed-unknown" not in scan[0]["run"] or \
        not dstep or "--removed-unknown" not in dstep[0]["run"]:
    bad.append("an unscannable release image is not reported as unknown")
if not wait or "git show origin/main:.github/policy/required-checks.json" not in (wait[0].get("run") or "") or \
        "--required .github/policy/" in (wait[0].get("run") or ""):
    bad.append("ready does not read the required checks from protected main")
elif wait[0]["run"].index("git show origin/main:") < wait[0]["run"].index("while "):
    bad.append("ready reads the policy once, not on each pass of the wait (a change on main during the wait is missed)")
# Codex #159 r2: each scan file goes to the decision on its own (no jq aggregation that hides a malformed one); a base
# scan failure is the base's alone (NEW-1)
if scan and ("jq -s" in scan[0]["run"] or "base_ok" not in scan[0]["run"] or "--release-grype" not in scan[0]["run"]):
    bad.append("the scans are aggregated before validation, or a base failure is read as a release failure")
# AC8 wired (advisor 0135)
nstep = [s for s in steps if "patch-decide.py notes" in (s.get("run") or "")]
sign = [s for s in steps if "tag -s" in (s.get("run") or "")]
if len(nstep) != 1 or "steps.decide.outputs.cut == 'true'" not in nstep[0].get("if", "") or not sign or \
        names.index(nstep[0].get("name")) > names.index(sign[0].get("name")):
    bad.append("the notes are not built (on a cut) before signing")
elif "--next-notes docs/next-release-notes.md" not in nstep[0]["run"] or "--published" not in nstep[0]["run"] or \
        "removed-unknown" not in nstep[0]["run"]:
    bad.append("the notes step skips the next-release entries, the published guard, or an unscannable release")
# Sonnet #159 r2 B1: tag-notes trusts only decide's own tagger; the workflow's git identity is exactly RELEASE_TAGGER
import os as _os
_pd = open(_os.path.join(_os.environ["ROOT"], "bin", "patch-decide.py")).read()
_who = re.search(r'RELEASE_TAGGER = "([^"<]+) <([^>]+)>"', _pd)
if not _who or not sign or 'git config user.name "%s"' % _who.group(1) not in sign[0]["run"] or \
        'git config user.email "%s"' % _who.group(2) not in sign[0]["run"]:
    bad.append("decide's git identity is not the tagger tag-notes trusts (RELEASE_TAGGER)")
if sign and ("--cleanup=verbatim" not in sign[0]["run"] or '-F "$RUNNER_TEMP/notes.md"' not in sign[0]["run"]):
    bad.append("the signed tag does not carry the notes verbatim")
if scan and "event_name" in scan[0].get("if", ""):
    bad.append("the release is scanned on push only: a daily patch's notes would list no fixes")
push = [s for s in steps if "git push" in (s.get("run") or "")]
if (dec.get("outputs") or {}).get("tagged") != "${{ steps.push.outputs.tagged }}" or not push or \
        push[0].get("id") != "push" or "tagged=true" not in push[0]["run"]:
    bad.append("decide does not say that it tagged")
pn = jobs.get("patch-notes") or {}
if pn.get("needs") != "decide" or pn.get("if", "").replace(" ", "") != "${{needs.decide.outputs.tagged=='true'}}":
    bad.append("the notes PR job does not run exactly when decide tagged")
for ref in set(re.findall(r"needs\.decide\.outputs\.([\w-]+)", yaml.safe_dump(pn))):
    if ref not in (dec.get("outputs") or {}):
        bad.append("the notes PR job reads decide output %s, which decide does not export" % ref)
if pn.get("permissions") != {"contents": "read"}:
    bad.append("the notes PR job's own token is not contents read: %s" % pn.get("permissions"))
psteps = pn.get("steps") or []
ptext = "\n".join(l for s in psteps for l in (s.get("run") or "").splitlines() if not l.lstrip().startswith("#"))   # comments are not commands
pmint = [s for s in psteps if str(s.get("uses", "")).startswith("actions/create-github-app-token@")]
if len(pmint) != 1 or pmint[0].get("with") != dict(want, **{"permission-pull-requests": "write"}):
    bad.append("the notes PR job's App token is not exactly contents + pull-requests write on cache")
for w in ("patch-decide.py tag-notes", "patch-decide.py changelog", "gh pr create", "gh pr merge --auto --squash"):
    if w not in ptext:
        bad.append("the notes PR job lacks %s" % w)
# advisor 0210: main requires signed commits, so the notes commit is made through the API (GitHub signs it), never by git in the runner
if re.search(r"\bgit\s+(commit|push|switch|checkout\s+-b|add|config|branch|tag|merge|rebase|reset)\b|gh auth setup-git|credential", ptext):
    bad.append("the notes PR job commits, pushes or configures git itself (an unsigned commit): it must use auditor-signed-commit.py")
cstep = [s for s in psteps if "gh pr create" in (s.get("run") or "")]
crun = "\n".join(l for l in (cstep[0].get("run") or "").splitlines() if not l.lstrip().startswith("#")) if len(cstep) == 1 else ""
cenv = cstep[0].get("env") or {} if len(cstep) == 1 else {}
if len(cstep) != 1 or cenv != {"GH_TOKEN": "${{ steps.app-token.outputs.token }}", "VERSION": "${{ needs.decide.outputs.version }}"}:
    bad.append("the notes PR step does not run with exactly the App token and the version: %s" % cenv)
if crun.count("auditor-signed-commit.py") != 1 or crun.count("--prefix") != 1 or crun.count("--branch ") != 1 or crun.count('--base "$base"') != 1:
    bad.append("the notes PR step does not call auditor-signed-commit.py exactly once with one prefix, one branch, one base")
# the script's directory is captured, not spelled: the layout rule (REQ-AUD-18 AC1) keeps files outside the auditor's tree from naming it
_call = re.search(r'^( *)python3 (\S+)/auditor-signed-commit\.py --repo "\$GITHUB_REPOSITORY" --branch "\$branch" --base "\$base" '
                  r'--prefix patch-notes/ \\\n +--message "Release notes for \$\{VERSION\}: [^"\n]*" "\$\{paths\[@\]\}"$', crun, re.M)
if not _call:
    bad.append("the signed-commit call is not the exact pinned call (repo, branch $branch, base $base, prefix patch-notes/, message, paths)")
if _call and not (_call.group(2).startswith(".github/") and _call.group(2).endswith("/bin") and _call.group(2).count("/") == 2 and
                  _os.path.isfile(_os.path.join(_os.environ["ROOT"], _call.group(2), "auditor-signed-commit.py"))):
    bad.append("the signed-commit script is not the committed one under the auditor's bin directory: %s" % _call.group(2))
for want_line in ('branch="patch-notes/${VERSION}"', 'base=$(git rev-parse HEAD)', 'paths=(--path docs/quality/releases/CHANGELOG.md)',
                  '[ ! -f docs/next-release-notes.md ] || paths+=(--path docs/next-release-notes.md)'):
    if want_line not in [l.strip() for l in crun.splitlines()]:
        bad.append("the notes PR step lacks the line: %s" % want_line)
_order = [crun.find(k) for k in ("patch-decide.py tag-notes", "patch-decide.py changelog", 'base=$(git rev-parse HEAD)', "auditor-signed-commit.py", "gh pr create", "gh pr merge --auto --squash")]
if min(_order) < 0 or _order != sorted(_order):
    bad.append("the notes PR step is out of order (notes, changelog, base, signed commit, PR, auto-merge)")
if _call and crun.find('base=$(git rev-parse HEAD)') > crun.find("auditor-signed-commit.py"):
    bad.append("the base is derived after the commit")
if '--head "$branch"' not in crun or "gh pr merge --auto --squash \"$branch\"" not in crun:
    bad.append("the PR is not made from, and auto-merged for, the API-made branch")
for st in psteps:
    u = str(st.get("uses", ""))
    if u and not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u):
        bad.append("an action in the notes PR job is not a commit digest: %s" % u)
pco = [s for s in psteps if str(s.get("uses", "")).startswith("actions/checkout@")]
if not pco or (pco[0].get("with") or {}).get("persist-credentials") != "false" or (pco[0].get("with") or {}).get("ref") != "main":
    bad.append("the notes PR job's checkout is not main without a credential")
sp = yaml.load(open(sys.argv[2]), Loader=yaml.BaseLoader)
create = [st for j in sp["jobs"].values() for st in j.get("steps") or [] if "gh release create" in (st.get("run") or "")]
if len(create) != 1 or "patch-decide.py tag-notes" not in create[0]["run"] or "--notes-file" not in create[0]["run"]:
    bad.append("stage-promote does not post a patch tag's notes")
# REQ-REL-009-AC13 downstream (found while wiring rule 10): admission's chosen baseline reaches every stage that reads a
# baseline — the acceptance predicate and the release manifest — instead of each assuming requirements/releases/<tag>.yaml
for job in ("acceptance-predicate", "promotion"):
    j = jobs.get(job) or {}
    if (j.get("with") or {}).get("baseline-version") != "${{ needs.admission.outputs.baseline }}" or "admission" not in (j.get("needs") or []):
        bad.append("%s does not receive admission's baseline" % job)
# Codex #163 pin pass B01: authorization checks acceptance against the baseline the SIGNED admission predicate names, not
# the tag's own file (a CI patch has none); B03: decide's pre-check refuses what admission refuses — the checkout's copy of
# the chosen baseline must equal the owner tag's, as admission's cmp requires
import os
auth = open(os.path.join(os.environ["WIRING_ROOT"], ".github/workflows/stage-authorize.yml")).read()
if "predicate.baseline_version" not in auth or 'authorize-acceptance-check.py "${adm_base}"' not in auth \
        or 'authorize-acceptance-check.py "${GITHUB_REF_NAME}"' in auth:
    bad.append("authorization does not check acceptance against admission's baseline")
# Codex #163 r2 B04: the baseline's shape check accepts exactly admission's tag grammar (owner rc tags included)
shape = re.search(r'\[\[ "\$adm_base" =~ (\S+) \]\]', auth)
if not shape or not all(bool(re.fullmatch(shape.group(1), v)) == want for v, want in
                        (("v0.2.2", True), ("v0.3.0-rc.1", True), ("v0.2.2;x", False), ("0.2.2", False), ("v0.2", False))):
    bad.append("authorization's baseline shape check is not admission's tag grammar (vX.Y.Z[-rc.N])")
if pre and ("cmp -s" not in prun or 'git show "${base}:requirements/releases/${base}.yaml"' not in prun):
    bad.append("decide's pre-check does not require the checkout's copy of the baseline to equal the owner tag's")
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
case_ precheck-copy-unchecked bad "[s.__setitem__('run', s['run'].replace('cmp -s', 'true')) for s in $D['steps'] if s.get('id') == 'basecheck']"
case_ precheck-own-files     bad "[s.__setitem__('run', s['run'].replace('owner-baselines --tag', 'owner-baselinez --tag')) for s in $D['steps'] if s.get('id') == 'basecheck']"
case_ precheck-local-signers bad "[s.__setitem__('run', s['run'].replace('git show origin/main:.github/policy/allowed_signers', 'cat .github/policy/allowed_signers')) for s in $D['steps'] if s.get('id') == 'basecheck']"
case_ no-baseline-check       bad "$D['steps'] = [s for s in $D['steps'] if s.get('id') != 'basecheck']"
case_ wait-ignores-baseline   bad "[s.__setitem__('if', \"\${{ steps.decide.outputs.cut == 'true' }}\") for s in $D['steps'] if s.get('id') == 'checks']"
case_ no-check-wait           bad "$D['steps'] = [s for s in $D['steps'] if s.get('id') != 'checks']"
case_ wait-other-query        bad "[s.__setitem__('run', s['run'].replace('filter=latest', 'filter=all')) for s in $D['steps'] if s.get('id') == 'checks']"
case_ wait-unbounded          bad "[s.pop('timeout-minutes') for s in $D['steps'] if s.get('id') == 'checks']"
case_ sign-not-ready          bad "[s.__setitem__('if', \"\${{ steps.decide.outputs.cut == 'true' }}\") for s in $D['steps'] if 'tag -s' in (s.get('run') or '')]"
case_ push-not-ready          bad "[s.__setitem__('if', \"\${{ steps.decide.outputs.cut == 'true' }}\") for s in $D['steps'] if 'git push' in (s.get('run') or '')]"
case_ workflow-concurrency    bad "d['concurrency'] = {'group': 'release', 'cancel-in-progress': 'false'}"
case_ shallow-checkout        bad "[s['with'].pop('fetch-depth') for s in $D['steps'] if str(s.get('uses','')).startswith('actions/checkout@')]"
case_ predicate-own-baseline  bad "$J['acceptance-predicate']['with'].pop('baseline-version')"
case_ promotion-own-baseline  bad "$J['promotion']['with']['baseline-version'] = '\${{ github.ref_name }}'"
case_ no-schedule             bad "d['on'].pop('schedule')"
case_ scan-aggregated         bad "[s.__setitem__('run', s['run'].replace('base_ok', 'ok')) for s in $D['steps'] if 'patch-decide.py removed' in (s.get('run') or '')]"
case_ policy-read-once        bad "[s.__setitem__('run', 'git show origin/main:.github/policy/required-checks.json > x\n' + s['run'].replace('git show origin/main:', 'git show HEAD:')) for s in $D['steps'] if s.get('id') == 'checks']"
case_ fail-no-repo            bad "[s['env'].pop('GH_REPO') for s in $J['patch-failed']['steps']]"
case_ baseline-latest-tag     bad "[s.__setitem__('run', s['run'].replace('--released ', '--x ')) for s in $D['steps'] if 'patch-decide.py decide' in (s.get('run') or '')]"
case_ scan-failure-dropped    bad "[s.__setitem__('run', s['run'].replace('removed-unknown', 'removed-x')) for s in $D['steps'] if 'patch-decide.py removed' in (s.get('run') or '')]"
case_ ready-checkout-policy   bad "[s.__setitem__('run', s['run'].replace('git show origin/main:', 'git show HEAD:')) for s in $D['steps'] if s.get('id') == 'checks']"
N="$J['patch-notes']"
case_ notes-after-sign        bad "st=$D['steps']; i=[k for k,x in enumerate(st) if 'patch-decide.py notes' in (x.get('run') or '')][0]; st.append(st.pop(i))"
case_ tag-default-cleanup     bad "[s.__setitem__('run', s['run'].replace('--cleanup=verbatim ', '')) for s in $D['steps'] if 'tag -s' in (s.get('run') or '')]"
case_ scan-push-only          bad "[s.__setitem__('if', \"\${{ github.event_name == 'push' && steps.facts.outputs.since != '' }}\") for s in $D['steps'] if 'patch-decide.py removed' in (s.get('run') or '')]"
case_ notes-no-guard          bad "[s.__setitem__('run', s['run'].replace('--published', '--x')) for s in $D['steps'] if 'patch-decide.py notes' in (s.get('run') or '')]"
case_ notes-unknown-scan      bad "[s.__setitem__('run', s['run'].replace('removed-unknown', 'x')) for s in $D['steps'] if 'patch-decide.py notes' in (s.get('run') or '')]"
case_ notes-job-wide-token    bad "[s['with'].__setitem__('permission-issues', 'write') for s in $N['steps'] if str(s.get('uses','')).startswith('actions/create-github-app-token@')]"
case_ notes-job-pushes-main   bad "[s.__setitem__('run', s['run'] + '\ngit push origin HEAD:main') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-job-no-automerge  bad "[s.__setitem__('run', s['run'].replace('gh pr merge --auto --squash', 'true')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-version-unexported bad "$D['outputs'].pop('version')"
case_ tagger-drift            bad "[s.__setitem__('run', s['run'].replace('fosterstack release', 'someone else')) for s in $D['steps'] if 'tag -s' in (s.get('run') or '')]"
case_ notes-job-git-push      bad "[s.__setitem__('run', s['run'].replace('auditor-signed-commit.py', 'git push origin \"\$branch\" #')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-job-git-commit    bad "[s.__setitem__('run', s['run'].replace('base=\$(git rev-parse HEAD)', 'git commit -qm x; base=\$(git rev-parse HEAD)')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-job-git-switch    bad "[s.__setitem__('run', s['run'].replace('branch=\"patch-notes/', 'git switch -c x; branch=\"patch-notes/')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-job-setup-git     bad "[s.__setitem__('run', 'gh auth setup-git\n' + s['run']) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-other-script      bad "[s.__setitem__('run', s['run'].replace('auditor-signed-commit.py', 'x/auditor-signed-commit.py', 1)) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-no-prefix         bad "[s.__setitem__('run', s['run'].replace(' --prefix patch-notes/', '')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-other-prefix      bad "[s.__setitem__('run', s['run'].replace('--prefix patch-notes/', '--prefix auditor/')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-two-prefixes      bad "[s.__setitem__('run', s['run'].replace('--prefix patch-notes/', '--prefix patch-notes/ --prefix auditor/')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-other-branch      bad "[s.__setitem__('run', s['run'].replace('branch=\"patch-notes/\${VERSION}\"', 'branch=\"auditor/notes\"')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-branch-flag-main  bad "[s.__setitem__('run', s['run'].replace('--branch \"\$branch\"', '--branch main')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-base-from-origin  bad "[s.__setitem__('run', s['run'].replace('base=\$(git rev-parse HEAD)', 'base=\$GITHUB_SHA')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-base-after-commit bad "[s.__setitem__('run', s['run'].replace('base=\$(git rev-parse HEAD)\n', '').replace('gh pr create', 'base=\$(git rev-parse HEAD)\n          gh pr create', 1)) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-path-dropped      bad "[s.__setitem__('run', s['run'].replace('paths=(--path docs/quality/releases/CHANGELOG.md)', 'paths=()')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-token-dropped     bad "[s['env'].pop('GH_TOKEN') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-token-widened     bad "[s['env'].__setitem__('GH_TOKEN', '\${{ secrets.GITHUB_TOKEN }}') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-job-more-perms    bad "$N['permissions']['pull-requests'] = 'write'"
case_ notes-job-contents-write bad "$N['permissions']['contents'] = 'write'"
case_ notes-action-unpinned   bad "[s.__setitem__('uses', s['uses'].split('@')[0] + '@v7') for s in $N['steps'] if str(s.get('uses','')).startswith('actions/checkout@')]"
case_ notes-extra-action-tag  bad "$N['steps'].append({'name': 'x', 'uses': 'actions/cache@v4'})"
case_ notes-pr-not-from-branch bad "[s.__setitem__('run', s['run'].replace('--head \"\$branch\"', '--head x')) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ notes-job-always        bad "$N.__setitem__('if', '\${{ always() }}')"
sp="$work/sp.yml"; sed 's/patch-decide.py tag-notes/true/' "$root/.github/workflows/stage-promote.yml" > "$sp"
if out=$(judge "$root/.github/workflows/release.yml" "$sp"); then failn=$((failn+1)); echo "FAIL stage-promote-fixed-notes → ok, want bad"
else pass=$((pass+1)); echo "PASS stage-promote-fixed-notes → bad ($out)"; fi
# the stages themselves read the baseline they are given (empty = the tag's own baseline, as for owner-signed tags)
stages_out=$(python3 - "$root" <<'PY'
import os, sys, yaml
root = sys.argv[1]
bad = []
adm = yaml.load(open(os.path.join(root, ".github/workflows/stage-admission.yml")), Loader=yaml.BaseLoader)
if (adm["on"]["workflow_call"].get("outputs") or {}).get("baseline", {}).get("value") != "${{ jobs.admit.outputs.baseline }}" \
        or adm["jobs"]["admit"]["outputs"].get("baseline") != "${{ steps.baseline.outputs.version }}":
    bad.append("stage-admission does not output the baseline it used")
for f, needle in (("stage-acceptance-predicate.yml", 'frozen_path = f"requirements/releases/{base}.yaml"'),
                  ("stage-promote.yml", '--arg baseline "requirements/releases/${base}.yaml"')):
    d = yaml.load(open(os.path.join(root, ".github/workflows", f)), Loader=yaml.BaseLoader)
    inp = d["on"]["workflow_call"]["inputs"].get("baseline-version") or {}
    text = open(os.path.join(root, ".github/workflows", f)).read()
    if inp.get("default") != "" or needle not in text or "inputs.baseline-version" not in text:
        bad.append("%s does not read the baseline it is given" % f)
print("; ".join(bad) or "ok")
PY
)
if [ "$stages_out" = ok ]; then pass=$((pass+1)); echo "PASS stages-read-baseline → ok"; else failn=$((failn+1)); echo "FAIL stages-read-baseline ($stages_out)"; fi
echo "release-patch-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
