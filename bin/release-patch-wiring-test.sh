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
# PR 2 of the v0.3.0 chain: admission is no longer a job (it is the first step of Build's apk job, bin/build-admit.py), so the chain is guarded by the
# ONE gate G on build and sign: a v* tag PUSH or a dry-run dispatch (bin/chain-build-wiring-test.sh judges the whole graph)
if "admission" in jobs:
    bad.append("release.yml still has an admission job (admission is Build's first step now)")
GATE = "${{(github.event_name=='push'&&startsWith(github.ref,'refs/tags/v'))||inputs.dry-run==true}}"
for g in ("build", "sign"):
    if (jobs.get(g) or {}).get("if", "").replace(" ", "") != GATE:
        bad.append("%s is not guarded by the gate G (a v* tag push or a dry run): %s" % (g, (jobs.get(g) or {}).get("if")))
# the dry run's own jobs (sign, hostile-*) hang off the Sign boundary; they are judged by bin/chain-hostile-test.sh. The OLD downstream jobs (scans,
# acceptance*, authorization, promotion; replaced by PRs 3 and 4) are skipped in a dry run and need a chain job.
chain = [j for j in jobs if j not in ("decide", "patch-failed", "patch-notes", "build", "sign", "rebuild", "hostile-verify", "hostile-verdict")]
for j in chain:
    if jobs[j].get("if", "").replace(" ", "") not in ("", "${{!inputs.dry-run}}") or not jobs[j].get("needs"):
        bad.append("chain job %s is not skipped in a dry run or hangs off nothing" % j)
dec = jobs.get("decide") or {}
if dec.get("if", "").replace(" ", "") != "${{github.ref=='refs/heads/main'&&github.event_name!='workflow_dispatch'&&!inputs.dry-run}}":
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
if pn.get("needs") != "decide" or pn.get("if", "").replace(" ", "") != "${{needs.decide.outputs.tagged=='true'&&!inputs.dry-run}}":
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
# review of #191 B2: git is allowed ONLY as the three exact read-only commands the step already uses; every other word `git` (global options,
# command/env wrappers, a quoted "git", an absolute path) is a refusal, as is a GIT_* variable, a credential helper or a gh credential setup
_GIT_ALLOWED = ('git fetch --no-tags origin "+refs/tags/${VERSION}:refs/tags/${VERSION}"',
                'git cat-file tag "$VERSION" | python3 bin/patch-decide.py tag-notes > "$RUNNER_TEMP/notes.md"',
                'base=$(git rev-parse HEAD)')
_plines = [l.strip() for l in ptext.splitlines()]
for _g in _GIT_ALLOWED:
    if _plines.count(_g) != 1:
        bad.append("the notes PR job lacks the allowed read-only git line exactly once: %s" % _g)
_rest = "\n".join(l for l in _plines if l not in _GIT_ALLOWED)
if re.search(r"(?i)\bgit\b|\bGIT_|gh\s+auth\b|credential", _rest):
    bad.append("the notes PR job runs git (or sets up credentials) beyond its three read-only commands: it must commit through auditor-signed-commit.py")
# review of #191 B2: the branch, the base and the paths are each assigned once, and nothing can reassign or run constructed text
_assign = lambda name: re.findall(r"(?m)(?:^|[;&|(]|\s)(?:(?:export|declare|typeset|local|readonly)\s+(?:-\w+\s+)*)?" + name + r"\+?=", ptext)
if len(_assign("branch")) != 1 or len(_assign("base")) != 1 or len(re.findall(r"(?m)(?:^|\s)paths=", ptext)) != 1 or \
        len(re.findall(r"(?m)(?:^|\s)paths\+=", ptext)) != 1:
    bad.append("the branch, the base or the paths are assigned more than once (or not at all) in the notes PR job")
if re.search(r"(?<![\w-])(eval|source|exec|unset|mapfile|readarray)\b|(?<![\w-])(ba|da|z)?sh\s+-\w*c\b|^\s*\.\s|printf\s+-v\b|\bread\s+(-\w+\s+)*(branch|base|paths)\b|\bfor\s+(branch|base|paths)\b", ptext, re.M):
    bad.append("the notes PR job evaluates constructed text or rewrites its variables (eval, source, exec, unset, sh -c, printf -v, read, for)")
cstep = [s for s in psteps if "gh pr create" in (s.get("run") or "")]
crun = "\n".join(l for l in (cstep[0].get("run") or "").splitlines() if not l.lstrip().startswith("#")) if len(cstep) == 1 else ""
cenv = cstep[0].get("env") or {} if len(cstep) == 1 else {}
if len(cstep) != 1 or cenv != {"GH_TOKEN": "${{ steps.app-token.outputs.token }}", "VERSION": "${{ needs.decide.outputs.version }}"}:
    bad.append("the notes PR step does not run with exactly the App token and the version: %s" % cenv)
if crun.count("auditor-signed-commit.py") != 1 or crun.count("--prefix") != 1 or crun.count("--branch ") != 1 or crun.count('--base "$base"') != 1:
    bad.append("the notes PR step does not call auditor-signed-commit.py exactly once with one prefix, one branch, one base")
# the script's directory is captured, not spelled: the layout rule (REQ-AUD-18 AC1) keeps files outside the auditor's tree from naming it
_call = re.search(r'^( *)oid=\$\(python3 (\S+)/auditor-signed-commit\.py --repo "\$GITHUB_REPOSITORY" --branch "\$branch" --base "\$base" '
                  r'--prefix patch-notes/ \\\n +--message "Release notes for \$\{VERSION\}: [^"\n]*" "\$\{paths\[@\]\}"\)$', crun, re.M)
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
# review of #191 round 2 (B2/B3): the notes step is closed by an EXACT whitelist of its lines (comments and blank lines dropped, whitespace
# normalised), so no other assignment form (indexed, +=, nameref, ${x:=}, read, declare) and no other PR selection can be added. The signed-commit
# call's directory is normalised to @CLI@ (the agent-owned test binds it; the layout rule keeps that directory's name out of this file).
_EXPECTED = r"""set -euo pipefail
git fetch --no-tags origin "+refs/tags/${VERSION}:refs/tags/${VERSION}"
git cat-file tag "$VERSION" | python3 bin/patch-decide.py tag-notes > "$RUNNER_TEMP/notes.md"
python3 bin/patch-decide.py changelog --notes "$RUNNER_TEMP/notes.md" --changelog docs/quality/releases/CHANGELOG.md \
--next-notes docs/next-release-notes.md
branch="patch-notes/${VERSION}"
base=$(git rev-parse HEAD)
paths=(--path docs/quality/releases/CHANGELOG.md)
[ ! -f docs/next-release-notes.md ] || paths+=(--path docs/next-release-notes.md)
oid=$(python3 @CLI@ --repo "$GITHUB_REPOSITORY" --branch "$branch" --base "$base" --prefix patch-notes/ \
--message "Release notes for ${VERSION}: docs/quality/releases/CHANGELOG.md, next-release-notes cleared" "${paths[@]}")
own='[.[] | select(.isCrossRepository == false)]'
count=$(gh pr list --head "$branch" --base main --state open --json number,headRefOid,isCrossRepository --jq "$own | length")
[ "$count" -le 1 ] || { echo "more than one open PR from $branch into main; refusing" >&2; exit 1; }
if [ "$count" -eq 0 ]; then
gh pr create --base main --head "$branch" --title "Release notes for ${VERSION}" \
--body "Generated after the ${VERSION} patch tag (REQ-REL-009 AC8; advisor 0130/0135): its notes on top of docs/quality/releases/CHANGELOG.md, the published entries removed from docs/next-release-notes.md."
fi
number=$(gh pr list --head "$branch" --base main --state open --json number,headRefOid,isCrossRepository --jq "$own | .[0].number")
head=$(gh pr list --head "$branch" --base main --state open --json number,headRefOid,isCrossRepository --jq "$own | .[0].headRefOid")
[[ "$number" =~ ^[0-9]+$ ]] || { echo "no open PR from $branch into main; refusing" >&2; exit 1; }
[ "$head" = "$oid" ] || { echo "the open PR's head is not the commit this job made; refusing" >&2; exit 1; }
gh pr merge --auto --squash --match-head-commit "$oid" "$number"
state=$(gh pr view "$number" --json mergeStateStatus --jq .mergeStateStatus) || state=unknown
if [ "$state" = "BEHIND" ]; then
gh pr update-branch "$number" || true
fi
"""
_got = [re.sub(r"python3 \.github/[a-z]+/bin/auditor-signed-commit\.py", "python3 @CLI@", " ".join(l.split()))
        for l in crun.splitlines() if l.strip()]
if _got != _EXPECTED.splitlines():
    _extra = [l for l in _got if l not in _EXPECTED.splitlines()]
    _lost = [l for l in _EXPECTED.splitlines() if l not in _got]
    bad.append("the notes PR step is not exactly the reviewed text (extra: %s; missing: %s; order or count differs: %s)"
               % (_extra[:2], _lost[:2], not (_extra or _lost)))
if len([st for st in psteps if st.get("run")]) != 1:
    bad.append("the notes PR job has a run step other than the reviewed one")
# review of #191 round 3 (execution context): the whole job and its steps are pinned, not only the run text. A `shell:` (it runs BEFORE the run
# body with the step's token), a working-directory, a job env (BASH_ENV, PATH, ENV), defaults.run, a container or service, continue-on-error, an
# extra step key, or a workflow-level env / defaults would all change what the whitelisted lines mean. Action digests are checked separately.
_JOB = {"needs": "decide", "if": "${{ needs.decide.outputs.tagged == 'true' && !inputs.dry-run }}", "runs-on": "ubuntu-latest", "environment": "agent",
        "permissions": {"contents": "read"}}
if {k: v for k, v in pn.items() if k != "steps"} != _JOB:
    bad.append("the notes PR job is not exactly the reviewed job (keys, env, defaults, container, services, environment): %s" % sorted(pn))
def _shape(st):
    st = dict(st)
    if "uses" in st:
        st["uses"] = st["uses"].split("@")[0]
    if "run" in st:
        st["run"] = "<RUN>"
    return st
_STEPS = [{"uses": "actions/checkout", "with": {"ref": "main", "persist-credentials": "false"}},
          {"name": "mint the auditor App's token (contents + pull requests on cache only)", "id": "app-token", "uses": "actions/create-github-app-token",
           "with": dict(want, **{"permission-pull-requests": "write"})},
          {"name": "the changelog-and-clear PR (auto-merge on green)", "env": {"GH_TOKEN": "${{ steps.app-token.outputs.token }}",
                                                                              "VERSION": "${{ needs.decide.outputs.version }}"}, "run": "<RUN>"}]
if [_shape(st) for st in psteps] != _STEPS:
    bad.append("the notes PR job's steps are not exactly the reviewed ones (keys such as shell, working-directory, if, continue-on-error, env, uses)")
if set(d) - {"name", "on", "permissions", "jobs"}:
    bad.append("the workflow has top-level keys (env, defaults, concurrency ...) beyond the reviewed ones: %s" % sorted(d))
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
# PR 2 moved admission into Build, so these two OLD jobs no longer NEED an admission job; they keep the baseline expression until PRs 3 and 4 (Check,
# Release) replace them and read the baseline from Build's admission evidence. The `needs` half of this check is the deviation listed in PR 2's report.
for job in ("acceptance-predicate", "promotion"):
    j = jobs.get(job) or {}
    if (j.get("with") or {}).get("baseline-version") != "${{ needs.admission.outputs.baseline }}":
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
case_ chain-on-main           bad "$J['build'].pop('if')"
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
# review of #191 B2: mutate the notes step's text by replacing OLD with NEW once (passed through the environment, so no quoting games)
mutrun() { MO="$2" MN="$3" case_ "$1" bad "[s.__setitem__('run', s['run'].replace(__import__('os').environ['MO'], __import__('os').environ['MN'], 1)) for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"; }
BASE='base=$(git rev-parse HEAD)'
mutrun git-global-c-commit     "$BASE" "git -c user.name=x commit -qm x; $BASE"
mutrun git-C-push              "$BASE" "git -C . push origin HEAD:main; $BASE"
mutrun git-no-pager-commit     "$BASE" "git --no-pager commit -qm x; $BASE"
mutrun git-command-push        "$BASE" "command git push origin HEAD:main; $BASE"
mutrun git-env-push            "$BASE" "env git push origin HEAD:main; $BASE"
mutrun git-quoted-push         "$BASE" "\"git\" push origin HEAD:main; $BASE"
mutrun git-abs-path-push       "$BASE" "/usr/bin/git push origin HEAD:main; $BASE"
mutrun git-own-line-push       "$BASE" $'git -C . push origin HEAD:main\n'"$BASE"
mutrun git-env-var             "$BASE" "GIT_DIR=/x $BASE"
mutrun git-extra-read          "$BASE" "git log -1; $BASE"
mutrun git-fetch-widened       'git fetch --no-tags origin' 'git fetch origin'
mutrun gh-credential-setup     "$BASE" "gh auth setup-git; $BASE"
mutrun branch-reassigned       'gh pr create' 'branch="patch-notes/other"; gh pr create'
mutrun branch-exported         'gh pr create' 'export branch=main; gh pr create'
mutrun branch-declared         'gh pr create' 'declare -x branch=main; gh pr create'
mutrun branch-appended         'gh pr create' 'branch+=x; gh pr create'
mutrun base-reassigned         'gh pr create' 'base=$GITHUB_SHA; gh pr create'
mutrun paths-reassigned        'gh pr create' 'paths=(--path x); gh pr create'
mutrun paths-appended-twice    'gh pr create' 'paths+=(--path x); gh pr create'
mutrun eval-in-step            "$BASE" "eval \"branch=main\"; $BASE"
mutrun source-in-step          "$BASE" "source ./x.sh; $BASE"
mutrun bash-c-in-step          "$BASE" "bash -c 'x'; $BASE"
mutrun printf-v-branch         "$BASE" "printf -v branch main; $BASE"
mutrun read-branch             "$BASE" "read -r branch <<< main; $BASE"
PRL='gh pr list --head "$branch" --base main'
MRG='gh pr merge --auto --squash --match-head-commit "$oid" "$number"'
mutrun pr-list-no-base         "$PRL" 'gh pr list --head "$branch"'
mutrun pr-list-other-base      "$PRL" 'gh pr list --head "$branch" --base release'
mutrun pr-create-other-base    'gh pr create --base main' 'gh pr create --base release'
mutrun pr-merge-by-branch      "$MRG" 'gh pr merge --auto --squash --match-head-commit "$oid" "$branch"'
mutrun pr-merge-no-auto        "$MRG" 'gh pr merge --squash --match-head-commit "$oid" "$number"'
mutrun pr-merge-no-match-head  "$MRG" 'gh pr merge --auto --squash "$number"'
mutrun pr-merge-wrong-oid      "$MRG" 'gh pr merge --auto --squash --match-head-commit "$base" "$number"'
mutrun pr-merge-head-var       "$MRG" 'gh pr merge --auto --squash --match-head-commit "$head" "$number"'
mutrun pr-fork-allowed         '.isCrossRepository == false' '.isCrossRepository == true'
mutrun pr-no-fork-filter       'select(.isCrossRepository == false)' 'select(true)'
mutrun pr-head-check-dropped   '[ "$head" = "$oid" ] ||' 'true ||'
mutrun pr-head-check-inverted  '[ "$head" = "$oid" ]' '[ "$head" != "$oid" ]'
mutrun pr-oid-not-captured     'oid=$(python3' 'python3'
mutrun update-branch-dropped   'gh pr update-branch "$number" || true' 'true'
mutrun update-branch-fatal     'gh pr update-branch "$number" || true' 'gh pr update-branch "$number"'
mutrun update-branch-by-branch 'gh pr update-branch "$number"' 'gh pr update-branch "$branch"'
mutrun update-branch-always    'if [ "$state" = "BEHIND" ]; then' 'if true; then'
mutrun update-branch-other-state '"BEHIND"' '"DIRTY"'
mutrun update-branch-state-unread 'state=$(gh pr view "$number" --json mergeStateStatus --jq .mergeStateStatus) || state=unknown' 'state=BEHIND'
mutrun update-branch-state-fatal 'state=$(gh pr view "$number" --json mergeStateStatus --jq .mergeStateStatus) || state=unknown' 'state=$(gh pr view "$number" --json mergeStateStatus --jq .mergeStateStatus)'
mutrun update-branch-other-pr  'gh pr view "$number" --json' 'gh pr view "$branch" --json'
mutrun update-branch-before-merge "$MRG" $'gh pr update-branch "$number"\n'"$MRG"
mutrun pr-count-unchecked      '[ "$count" -le 1 ] ||' 'true ||'
mutrun pr-number-unchecked     '[[ "$number" =~ ^[0-9]+$ ]] ||' 'true ||'
mutrun pr-second-element       '.[0].number' '.[1].number'
mutrun pr-always-create        '[ "$count" -eq 0 ]' 'true'
mutrun pr-state-all            '--state open' '--state all'
mutrun idx-branch              "$MRG" $'branch[0]="patch-notes/other"\n'"$MRG"
mutrun idx-paths               "$MRG" $'paths[1]=x\n'"$MRG"
mutrun idx-base                "$MRG" $'base[0]=x\n'"$MRG"
mutrun assoc-branch            "$MRG" $'declare -A branch=([a]=b)\n'"$MRG"
mutrun read-into-branch        "$MRG" $'read -r unused branch <<< x\n'"$MRG"
mutrun read-anything           "$MRG" $'read x\n'"$MRG"
mutrun plus-equals-branch      "$MRG" $'branch+=x\n'"$MRG"
mutrun plus-equals-base        "$MRG" $'base+=x\n'"$MRG"
mutrun nameref                 "$MRG" $'declare -n branch=other\n'"$MRG"
mutrun default-assign-colon    "$MRG" $': "${branch:=x}"\n'"$MRG"
mutrun default-assign-plain    "$MRG" $': "${branch=x}"\n'"$MRG"
mutrun extra-line-anywhere     "$MRG" $'true\n'"$MRG"
mutrun extra-gh-call           "$MRG" $'gh api -X DELETE repos/o/r/git/refs/heads/main\n'"$MRG"
mutrun line-reordered          'set -euo pipefail' $'base=x\nset -euo pipefail'
mutrun whitespace-only-ok-not  'set -euo pipefail' 'set -eo pipefail'
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
case_ ctx-step-shell          bad "[s.__setitem__('shell', 'bash -c \"gh auth setup-git; bash {0}\"') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ ctx-step-shell-plain    bad "[s.__setitem__('shell', 'bash') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ ctx-step-workdir        bad "[s.__setitem__('working-directory', 'docs') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ ctx-step-continue       bad "[s.__setitem__('continue-on-error', 'true') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ ctx-step-if             bad "[s.__setitem__('if', '\${{ always() }}') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ ctx-step-env-bashenv    bad "[s['env'].__setitem__('BASH_ENV', 'bin/prep.sh') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ ctx-step-env-path       bad "[s['env'].__setitem__('PATH', '/tmp/evil') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ ctx-step-timeout        bad "[s.__setitem__('timeout-minutes', '1') for s in $N['steps'] if 'gh pr create' in (s.get('run') or '')]"
case_ ctx-job-env-bashenv     bad "$N['env'] = {'BASH_ENV': 'bin/prep.sh'}"
case_ ctx-job-env-path        bad "$N['env'] = {'PATH': '/tmp/evil:\$PATH'}"
case_ ctx-job-defaults-shell  bad "$N['defaults'] = {'run': {'shell': 'bash -c \"x; bash {0}\"'}}"
case_ ctx-job-defaults-wd     bad "$N['defaults'] = {'run': {'working-directory': 'docs'}}"
case_ ctx-job-container       bad "$N['container'] = 'alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667'"
case_ ctx-job-services        bad "$N['services'] = {'x': {'image': 'alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667'}}"
case_ ctx-job-continue        bad "$N['continue-on-error'] = 'true'"
case_ ctx-job-environment     bad "$N['environment'] = 'release'"
case_ ctx-job-no-environment  bad "$N.pop('environment')"
case_ ctx-job-timeout         bad "$N['timeout-minutes'] = '1'"
case_ ctx-job-runs-on         bad "$N['runs-on'] = 'self-hosted'"
case_ ctx-job-needs           bad "$N['needs'] = ['decide', 'admission']"
case_ ctx-step-added-action   bad "$N['steps'].insert(1, {'name': 'x', 'uses': 'actions/cache@3d3c42e5aac5ba805825da76410c181273ba90b1'})"
case_ ctx-step-added-run      bad "$N['steps'].insert(2, {'name': 'x', 'run': 'true'})"
case_ ctx-step-reordered      bad "$N['steps'].reverse()"
case_ ctx-checkout-persist    bad "[s['with'].__setitem__('persist-credentials', 'true') for s in $N['steps'] if str(s.get('uses','')).startswith('actions/checkout@')]"
case_ ctx-wf-env              bad "d['env'] = {'BASH_ENV': 'bin/prep.sh'}"
case_ ctx-wf-defaults         bad "d['defaults'] = {'run': {'shell': 'bash -c \"x; bash {0}\"'}}"
case_ notes-job-always        bad "$N.__setitem__('if', '\${{ always() }}')"
sp="$work/sp.yml"; sed 's/patch-decide.py tag-notes/true/' "$root/.github/workflows/stage-promote.yml" > "$sp"
if out=$(judge "$root/.github/workflows/release.yml" "$sp"); then failn=$((failn+1)); echo "FAIL stage-promote-fixed-notes → ok, want bad"
else pass=$((pass+1)); echo "PASS stage-promote-fixed-notes → bad ($out)"; fi
# the stages themselves read the baseline they are given (empty = the tag's own baseline, as for owner-signed tags)
stages_out=$(python3 - "$root" <<'PY'
import os, sys, yaml
root = sys.argv[1]
bad = []
if "baseline_version" not in open(os.path.join(root, "bin/build-admit.py")).read():
    bad.append("bin/build-admit.py does not write the baseline it used into the admission evidence")
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
