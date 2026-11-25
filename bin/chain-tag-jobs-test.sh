#!/usr/bin/env bash
# proves: REQ-REL-009-AC5, REQ-REL-009-AC6, REQ-REL-009-AC2, REQ-REL-009-AC3, REQ-REL-009-AC4, REQ-REL-009-AC8
# The structure of the automatic patch release's tag jobs (rules: ops docs/ratify/2026-10-02-automatic-patch-releases.md, 2026-10-28-kms-signing-key-and-one-step-build.md).
# Static, except for one step that is run in a scratch repository: no network, no secrets, no keys, nothing is run on GitHub. The judge (bin/chain-tag-jobs-judge.py) reads release.yml and
# the two policy lists and answers with a list of faults. Every case mutates a COPY of the real file and must be refused; the unmutated real tree must pass.
#
#   release.yml is the one release workflow: there is no stage-sign.yml and no stage split. A job that needs the release signing key is a job of release.yml (sign, sign-rebuild, sign-check
#   and sign-tag, in the environment sign). It runs on a push of a v* tag (the chain), on a push to main and the daily schedule '47 9 * * *' (only the four tag jobs below), on
#   workflow_dispatch, and on workflow_call from scan.yml and main-candidate-rescan.yml in snapshot mode. The four tag jobs, in this order of `needs`:
#     decide           decides only: no key, no push right (no contents: write, no id-token, no App token), no tag made, signed or pushed, no keyless signing tool named. Its job output
#                      `tag` is the tag due (vX.Y.Z, the next patch) or empty. It runs decide, the ACs-baseline pre-check, the
#                      required-checks wait and the notes, and uploads the tag request (the tag and its notes) as an artifact for sign-tag.
#     sign-tag         needs exactly decide, environment sign, permissions exactly contents read and id-token write, runs-on ubuntu-24.04, if exactly `needs.decide.outputs.tag != ''`; no job-level env,
#                      secrets, uses, container or services. Its steps are judged by the shared step checks (bin/chain-test-signers.py stage_grammar) and by the exact run: texts of the judge: checkout,
#                      one download of the tag request, the aws CLI install, `bin/tag-sign-prepare.sh`, `bash bin/tag-sign-kms.sh` (the one step with the federation literals), `bin/tag-sign.py assemble`,
#                      one upload (the signed tag object cut downloads).
#     cut              (environment agent, which holds the App secrets) the only job that pushes a tag: contents write through the auditor GitHub App's installation token, no key, no id-token; needs
#                      decide and sign-tag (no status function in its if); downloads the signed tag object, checks that it is signed before it pushes the tag ref, and never runs `git tag`.
#     patch-notes      the changelog PR after the tag exists: needs decide and cut; its own App token for pull requests; bin/patch-decide.py tag-notes then changelog.
#   concurrency        ONE workflow-level group, cancel-in-progress false: 'patch-release' for release.yml's OWN push or schedule run on refs/heads/main only, github.run_id for every other run
#                      (a tag push, a dispatch, a snapshot call: there github.ref and github.event_name are the CALLER's). The group expression is evaluated here for each kind of run.
#   policy             id-token-jobs.json lists release.yml:sign-tag exactly once and no stage-sign.yml row; decide, cut and patch-notes are not listed; chain-scripts.json rows of the four tag
#                      scripts carry no sha256.
# Needs: bash, git, python3 + PyYAML.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL PyYAML is required (apt: python3-yaml)"; exit 1; }
cp "$root/bin/chain-tag-jobs-judge.py" "$work/judge.py"
# ---- the tree the judge reads: the REAL files, copied ----------------------------------------------------------------------------------
mkdir -p "$work/good/.github/workflows" "$work/good/.github/policy" "$work/good/bin"
cp "$root/.github/workflows/release.yml" "$work/good/.github/workflows/release.yml"
cp "$root/.github/policy/id-token-jobs.json" "$root/.github/policy/chain-scripts.json" "$work/good/.github/policy/"
cp "$root/bin/tag-sign.py" "$work/good/bin/tag-sign.py"
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
out=$(python3 "$work/judge.py" "$work/good" 2>&1) && ok "fixture: the copy of the real tag jobs passes the judge" || bad "fixture: the copy of the real files is refused: $out"
# mutant LABEL FILE REGEX REPLACEMENT WORD : the judge must refuse the mutated copy and its message must contain WORD
mut() {
  local label=$1 file=$2 rx=$3 rep=$4 word=$5 d="$work/m$((pass + failn))"
  rm -rf "$d"; cp -r "$work/good" "$d"
  if ! python3 -I - "$d/$file" "$rx" "$rep" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
n = re.sub(sys.argv[2], lambda m: m.expand(sys.argv[3].replace("\\n", "\n")), t, count=1, flags=re.S)
if n == t: sys.exit(1)
open(sys.argv[1], "w").write(n)
PY
  then bad "mutation did not apply: $label"; return; fi
  local o rc=0; o=$(python3 "$work/judge.py" "$d" 2>&1) || rc=$?
  if [ "$rc" = 1 ] && grep -Fq -- "$word" <<< "$o"; then ok "$label (caught: ${o:0:70})"; else bad "$label -> rc=$rc, wanted a refusal naming '$word': ${o:0:160}"; fi
}
R=.github/workflows/release.yml
# decide: decides only
mut "decide holds contents write"                 $R '(  decide:.*?      contents: )read'                       '\1write'                                   'decide holds no key'
mut "decide holds id-token"                       $R '(  decide:.*?      issues: write[^\n]*\n)'                '\1      id-token: write\n'                   'decide holds no key'
mut "decide holds packages write"                 $R '(  decide:.*?      issues: write[^\n]*\n)'                '\1      packages: write\n'                   'decide holds no key'
mut "decide mints the App token"                  $R '(  decide:.*?    steps:\n)'                               '\1      - uses: actions/create-github-app-token@0123456789abcdef0123456789abcdef01234567\n        with:\n          app-id: x\n' 'decides only'
mut "decide pushes a tag"                         $R '(      - name: decide \(bin/patch-decide.py\)\n)'         '      - run: git push origin refs/tags/v9.9.9\n\1' 'decides only'
mut "decide signs a tag with a keyless tool"      $R '(      - name: decide \(bin/patch-decide.py\)\n)'         '      - run: gitsign sign x\n\1'            'decides only'
mut "decide names the release key"                $R '(      - name: decide \(bin/patch-decide.py\)\n)'         '      - run: echo awskms:///alias/fosterstack-release-signing\n\1' 'decides only'
mut "decide has no tag output"                    $R '(  decide:.*?)    outputs:\n      tag: [^\n]*\n'          '\1'                                        'output `tag`'
mut "decide runs on every branch"                 $R "(  decide:\n    if: )[^\n]*"                              "\\1\${{ github.event_name != 'workflow_dispatch' }}" 'main only'
mut "decide does not decide"                      $R 'patch-decide.py decide --event'                           'patch-decide.py dicide --event'            'fix-only decision'
mut "decide does not wait for the required checks" $R 'patch-decide.py ready'                                   'patch-decide.py reedy'                     'required checks'
mut "decide writes no notes"                      $R 'patch-decide.py notes --version'                          'patch-decide.py n0tes --version'           'generated notes'
mut "decide uploads no tag request"               $R '      - name: upload the tag request\n.*?          if-no-files-found: error\n' '' 'upload exactly one artifact'
mut "decide uploads the request under another name" $R '(      - name: upload the tag request\n.*?          name: )tag-request' '\1other'                          'must download the one artifact decide uploads'
mut "the push trigger is gone"                    $R '    branches:\n      - main\n'                           ''                                          'push to main'
mut "the daily schedule is another time"          $R "47 9 \* \* \*"                                              '13 5 * * *'                                'daily schedule'
# sign-tag: its own job-level keys (the steps are judged below by the shared checks and the exact run: texts)
mut "sign-tag does not wait for decide"           $R '(  sign-tag:\n    needs: )decide'                         '\1[decide, cut]'                           'sign-tag must need exactly decide'
mut "sign-tag runs whatever decide said"          $R "(  sign-tag:\n.*?    if: )[^\n]*"                         "\\1true"                                   'sign-tag must carry exactly'
mut "sign-tag runs after a failed decide"         $R "(  sign-tag:\n.*?    if: )[^\n]*"                         "\\1\${{ always() && needs.decide.outputs.tag != '' }}" 'sign-tag must carry exactly'
mut "sign-tag holds contents write"               $R '(  sign-tag:.*?      contents: )read'                     '\1write'                                   'exactly contents read and id-token write'
mut "sign-tag holds no id-token"                  $R '(  sign-tag:.*?permissions:\n      contents: read\n)      id-token: write\n' '\1'                     'exactly contents read and id-token write'
mut "sign-tag holds packages write"               $R '(  sign-tag:.*?      id-token: write\n)'                  '\1      packages: write\n'                   'exactly contents read and id-token write'
mut "sign-tag has no environment"                 $R '(  sign-tag:.*?    runs-on: ubuntu-24.04\n)    environment: sign\n' '\1'                          'environment sign'
mut "sign-tag runs in another environment"        $R '(  sign-tag:.*?    environment: )sign'                    '\1agent'                                   'environment sign'
mut "sign-tag runs on another runner"             $R '(  sign-tag:\n.*?    runs-on: )ubuntu-24.04'              '\1ubuntu-latest'                           'ubuntu-24.04'
mut "sign-tag has a job-level env"                $R '(?m)(^  sign-tag:\n)'                                     '\1    env:\n      X: y\n'                      'plain job'
mut "sign-tag inherits the secrets"               $R '(?m)(^  sign-tag:\n)'                                     '\1    secrets: inherit\n'                  'plain job'
mut "sign-tag calls a reusable workflow"          $R '(?m)(^  sign-tag:\n)'                                     '\1    uses: ./.github/workflows/other.yml\n' 'plain job'
mut "sign-tag runs in a container"                $R '(?m)(^  sign-tag:\n)'                                     '\1    container: x\n'                      'plain job'
mut "sign-tag has services"                       $R '(?m)(^  sign-tag:\n)'                                     '\1    services:\n      a:\n        image: x\n' 'plain job'
mut "sign-tag continues on error"                 $R '(?m)(^  sign-tag:\n)'                                     '\1    continue-on-error: true\n'           'plain job'
mut "sign-tag uses a stored credential"           $R '(          RELEASE_KMS_KEY_REF: [^\n]*\n)'               '\1          AWS_SECRET_ACCESS_KEY: ${{ secrets.K }}\n' 'names a stored credential'
mut "sign-tag signs keyless"                      $R '(      - name: put the signature into the tag object\n)'  '      - run: cosign sign --identity-token x y\n\1' 'keyless'
mut "sign-tag names a second key"                 $R '(          name: signed-tag\n          path: tag-work/tag.signed\n)' '\1          x: alias/other-key\n' 'one release key'
mut "sign-tag has another key reference"         $R 'awskms:///alias/fosterstack-release-signing'               'awskms:///alias/other-key'                 'release key'
mut "sign-tag has another role"                   $R 'role/fosterstack-cache-release-signing'                   'role/other-role'                           'release role, region and key reference'
mut "sign-tag pushes"                             $R '(      - name: put the signature into the tag object\n)'  '      - run: git push origin HEAD\n\1'      'push'
mut "sign-tag skips the kms call"                 $R '      - name: sign the digest with the release key\n.*?(      - name: put the signature)' '\1'            'steps must be exactly'
mut "sign-tag skips the aws CLI"                  $R '      - name: install the pinned aws CLI\n        run: [^\n]*\n\n' ''                                    'steps must be exactly'
mut "sign-tag assembles before it signs"         $R '(      - name: sign the digest with the release key\n.*?)(      - name: put the signature into the tag object\n        run: [^\n]*\n\n)' '\2\1' 'steps must be exactly'
mut "sign-tag prepare runs another command"       $R '(      - name: make the tag object and the digest to sign\n        run: )[^\n]*'  '\1bash bin/tag-sign-prepare.sh --tagger Someone' 'steps must be exactly'
mut "sign-tag gains a step"                       $R '(      - name: make the tag object and the digest to sign\n)' '      - run: echo hi\n\1'                  'steps must be exactly'
mut "sign-tag uploads nothing"                    $R '      - uses: actions/upload-artifact@[^\n]*\n        with:\n          name: signed-tag\n          path: tag-work/tag.signed\n' '' 'steps must be exactly'
mut "sign-tag downloads another artifact than decide uploads" $R '(  sign-tag:.*?          name: )tag-request'   '\1other'                                   'must download the one artifact decide uploads'
mut "sign-tag checkout keeps credentials"         $R '(  sign-tag:.*?          persist-credentials: )false'     '\1true'                                    'persist-credentials: false'
mut "sign-tag uses an unpinned action"            $R '(  sign-tag:.*?      - uses: )actions/checkout@[^\n]*'     '\1actions/checkout@v4'                     'only pinned'
mut "a step of sign-tag puts an expression into its script" $R '(        run: )bash bin/tag-sign-kms.sh'        '\1bash bin/tag-sign-kms.sh ${{ github.sha }}' 'expression'
# cut: the only job that pushes a tag, with the App token, after sign-tag
mut "cut does not wait for sign-tag"              $R '(  cut:\n    needs: )\[decide, sign-tag\]'                '\1[decide]'                                'must need decide and sign-tag'
mut "cut runs after a failed sign-tag"            $R "(  cut:\n    needs: \[decide, sign-tag\]\n    if: )[^\n]*"  "\\1\${{ always() && needs.decide.outputs.tag != '' }}" 'no status function'
mut "cut runs whatever decide said"               $R "(  cut:\n    needs: \[decide, sign-tag\]\n    if: )[^\n]*"  "\\1true"                                   'non-empty'
mut "cut has no environment (the App's secrets would be empty)" $R '(  cut:.*?    runs-on: ubuntu-latest\n)    environment: agent\n' '\1'      'environment: agent'
mut "cut runs in another environment"             $R '(  cut:.*?    environment: )agent'                    '\1release'                                 'environment: agent'
mut "patch-notes has no environment"              $R '(  patch-notes:.*?    runs-on: ubuntu-latest\n)    environment: agent\n' '\1'                  'environment: agent'
mut "cut holds contents write on its own token"   $R '(  cut:.*?      contents: )read'                          '\1write'                                   'cut holds no key'
mut "cut holds id-token"                          $R '(  cut:.*?    permissions:\n      contents: read\n)'     '\1      id-token: write\n'                   'cut holds no key'
mut "cut names the release key"                   $R '(          TAG: \$\{\{ needs.decide.outputs.tag \}\}\n)' '\1          RELEASE_KMS_KEY_REF: x\n'           'cut names a key'
mut "cut pushes with GITHUB_TOKEN"                $R '          GH_TOKEN: \$\{\{ steps.app-token.outputs.token \}\}' '          GH_TOKEN: ${{ github.token }}'        'must use the App token'
mut "cut's App token has no contents write"       $R '          permission-contents: write\n(\n      - name: verify)' '          permission-pull-requests: write\n\1' 'permission-contents: write'
mut "cut's App token also writes pull requests"   $R '(          repositories: cache\n          permission-contents: write\n)(\n      - name: verify)' '\1          permission-pull-requests: write\n\2' 'no other permission'
mut "cut uses other secrets"                      $R '(  cut:.*?          repositories: cache\n)'               '\1          x: ${{ secrets.OTHER }}\n'           'secrets must be exactly'
mut "cut makes the tag itself"                    $R '(          git remote set-url)'                          '          git tag -s "$TAG"\n\1'               'makes a tag object itself'
mut "cut does not check the signature"           $R '          # the object is the tag decide asked for[^\n]*\n.*?          git -c gpg.ssh.allowedSignersFile=[^\n]*\n' '' 'is signed'
mut "cut keeps only a comment that names the signature check (the verify-tag line is deleted)" $R '          git -c gpg.ssh.allowedSignersFile=[^\n]*verify-tag "\$TAG"\n' '' 'is signed'
mut "cut checks the signature after the push"     $R '          # the object is the tag decide asked for[^\n]*\n(.*?)(          git -c gpg.ssh[^\n]*\n)(          git remote set-url[^\n]*\n          git push origin[^\n]*\n)' '\1\3\2' 'is signed'
mut "cut pushes a branch, not a tag ref"          $R '          git push origin "refs/tags/\$TAG"'            '          git push origin HEAD:main'           'refs/tags/'
mut "cut puts the tag into its script"            $R '          git push origin "refs/tags/\$TAG"'            '          git push origin "refs/tags/${{ needs.decide.outputs.tag }}"' 'no expression'
mut "cut downloads nothing"                       $R '(  cut:.*?)      - uses: actions/download-artifact@[^\n]*\n        with:\n          name: signed-tag\n          path: signed-tag\n\n' '\1' 'download exactly one'
mut "cut downloads another artifact than sign-tag uploads" $R '(  cut:.*?          name: )signed-tag\n          path: signed-tag' '\1other\n          path: signed-tag' 'must be the artifact cut downloads'
# patch-notes
mut "patch-notes does not wait for cut"           $R '(  patch-notes:\n    needs: )\[decide, cut\]'          '\1[decide]'                                'must need decide and cut'
mut "patch-notes runs whatever decide said"       $R "(  patch-notes:\n    needs: \[decide, cut\]\n    if: )[^\n]*" "\\1true"                                'naming needs.decide.outputs.tag'
mut "patch-notes has no tag-notes step"           $R 'patch-decide.py tag-notes'                                'patch-decide.py tag-n0tes'                 'tag-notes'
mut "patch-notes has no changelog step"           $R 'patch-decide.py changelog'                                'patch-decide.py changel0g'                 'changelog'
mut "patch-notes has no pull request token"       $R '          permission-pull-requests: write\n'             ''                                          'permission-pull-requests'
mut "patch-notes holds id-token"                  $R '(  patch-notes:.*?    permissions:\n      contents: read\n)' '\1      id-token: write\n'                 'patch-notes holds no id-token'
mut "another job runs the tag signer"             $R '(  patch-notes:.*?        run: \|\n          set -euo pipefail\n)' '\1          python3 bin/tag-sign.py prepare\n' 'only release.yml'
# ---- the policy lists (rules 6 and 7), judged by the tag jobs judge and by the checks below ----------------------------------------------
cat > "$work/policy.py" <<'PY'
import json, os, sys
r = sys.argv[1]
bad = []
ip = os.path.join(r, ".github/policy/id-token-jobs.json")
rows = [(e.get("workflow"), e.get("job")) for e in json.load(open(ip)).get("jobs") or []]
if rows.count(("release.yml", "sign-tag")) != 1: bad.append("id-token-jobs.json must list release.yml:sign-tag exactly once")
if [w for w, _ in rows if w == "stage-sign.yml"]: bad.append("id-token-jobs.json has a stage-sign.yml row: that file does not exist any more")
for n in ("decide", "cut", "patch-notes"):
    if ("release.yml", n) in rows: bad.append("id-token-jobs.json lists release.yml:%s, which holds no id-token" % n)
cs = json.load(open(os.path.join(r, ".github/policy/chain-scripts.json")))
for p in ("bin/tag-sign.py", "bin/tag-sign-prepare.sh", "bin/tag-sign-kms.sh", "bin/patch-decide.py"):
    hit = [e for e in cs.get("scripts") or [] if e.get("path") == p]
    if len(hit) != 1: bad.append("chain-scripts.json must list %s once" % p)
    elif "sha256" in hit[0]: bad.append("chain-scripts.json row %s carries a sha256: nothing on this base checks one" % p)
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
out=$(python3 -I "$work/policy.py" "$work/good" 2>&1) && ok "the real policy lists: release.yml:sign-tag once, no stage-sign.yml row, no decide, cut or patch-notes row, no sha256 on the four tag scripts" || bad "the real policy lists: $out"
pmut() { # pmut LABEL FILE PYTHON-STATEMENT WORD : the mutated copy must be refused by the policy checks (WORD in the message); judge too when JUDGED=1
  local label=$1 file=$2 code=$3 word=$4 d="$work/p$((pass + failn))"
  rm -rf "$d"; cp -r "$work/good" "$d"
  python3 -I - "$d/$file" "$code" <<'PY' || { bad "mutation did not apply: $label"; return; }
import json, sys
p = sys.argv[1]; j = json.load(open(p)); before = json.dumps(j)
exec(sys.argv[2])
assert json.dumps(j) != before
json.dump(j, open(p, "w"), indent=1)
PY
  local o rc=0; o=$(python3 -I "$work/policy.py" "$d" 2>&1) || rc=$?
  if [ "$rc" = 1 ] && grep -Fq -- "$word" <<< "$o"; then ok "$label (caught: ${o:0:70})"; else bad "$label -> rc=$rc, wanted a refusal naming '$word': ${o:0:160}"; fi
  if [ "${JUDGED:-0}" = 1 ]; then rc=0; o=$(python3 "$work/judge.py" "$d" 2>&1) || rc=$?
    if [ "$rc" = 1 ] && grep -Fq -- "$word" <<< "$o"; then ok "$label: the tag jobs judge refuses it too"; else bad "$label: the tag jobs judge -> rc=$rc: ${o:0:160}"; fi; fi
}
ID=.github/policy/id-token-jobs.json CS=.github/policy/chain-scripts.json
JUDGED=1 pmut "id-token-jobs.json lacks release.yml sign-tag"  $ID 'j["jobs"] = [e for e in j["jobs"] if (e["workflow"], e["job"]) != ("release.yml", "sign-tag")]' 'release.yml:sign-tag'
JUDGED=1 pmut "id-token-jobs.json lists release.yml sign-tag twice" $ID 'j["jobs"].append({"workflow": "release.yml", "job": "sign-tag", "reason": "x"})' 'release.yml:sign-tag'
JUDGED=1 pmut "id-token-jobs.json lists cut"                   $ID 'j["jobs"].append({"workflow": "release.yml", "job": "cut", "reason": "x"})' 'release.yml:cut'
JUDGED=1 pmut "id-token-jobs.json lists decide"                $ID 'j["jobs"].append({"workflow": "release.yml", "job": "decide", "reason": "x"})' 'release.yml:decide'
JUDGED=1 pmut "id-token-jobs.json lists patch-notes"           $ID 'j["jobs"].append({"workflow": "release.yml", "job": "patch-notes", "reason": "x"})' 'release.yml:patch-notes'
pmut "id-token-jobs.json keeps a stage-sign.yml row"           $ID 'j["jobs"].append({"workflow": "stage-sign.yml", "job": "sign-tag", "reason": "x"})' 'stage-sign.yml row'
for s in bin/tag-sign.py bin/tag-sign-prepare.sh bin/tag-sign-kms.sh bin/patch-decide.py; do
  pmut "chain-scripts.json row of $s carries a sha256" $CS 'next(e for e in j["scripts"] if e["path"] == "'"$s"'")["sha256"] = "0" * 64' "carries a sha256"
done
pmut "chain-scripts.json lacks bin/tag-sign-kms.sh"            $CS 'j["scripts"] = [e for e in j["scripts"] if e["path"] != "bin/tag-sign-kms.sh"]' 'bin/tag-sign-kms.sh once'
# ---- sign-tag is the one job that holds the KMS identity: the shared stage checks (chain-test-signers.py stage_grammar) and the exact run: texts of the judge BOTH apply ---
cat > "$work/shared.py" <<'PY'
import copy, importlib.util, os, sys
root = sys.argv[1]
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
cts = load("cts", root + "/bin/chain-test-signers.py"); tj = load("tj", root + "/bin/chain-tag-jobs-judge.py")
rows, errs, names = cts.load_scripts(root)
RP = ".github/workflows/release.yml"
base = cts.yload(open(os.path.join(root, RP)).read())
def shared(d):
    """the faults of sign-tag from the shared step checks alone (the tag jobs judge's own lines left out)"""
    e, _ = cts.stage_grammar("release.yml", d, rows, names, RP)
    return [x for x in e if "sign-tag" in x and "the tag jobs judge" not in x]
def judge(d): return tj.sign_tag_errors(d["jobs"])
S0, J0 = shared(base), judge(base)
print("OK the real release.yml's sign-tag has no fault from the shared step checks and none from the tag jobs judge" if not (S0 or J0 or errs)
      else "FAIL the real sign-tag is refused: %s" % (errs + S0 + J0)[:2])
def steps(d): return d["jobs"]["sign-tag"]["steps"]
def by(d, k): return next(s for s in steps(d) if k in str(s.get("run", "")) or k in str(s.get("uses", "")))
CASES = []
def case(who, label):
    def deco(f): CASES.append((who, label, f)); return f
    return deco
# who: S = the shared step checks must refuse it, J = the judge's exact run: texts and job keys must refuse it
@case("S", "a checkout of another ref (with: ref)")
def _(d): by(d, "actions/checkout")["with"]["ref"] = "refs/heads/other"
@case("S", "an unlisted python command in a run: line")
def _(d): by(d, "tag-sign.py assemble")["run"] += "\npython3 -I -B bin/unlisted-tool.py"
@case("S", "an unlisted python3 -c step")
def _(d): steps(d).insert(-1, {"name": "x", "run": "python3 -c 'import os; os.system(\"id\")'"})
@case("S", "BASH_ENV set in the kms step's env")
def _(d): by(d, "tag-sign-kms.sh")["env"]["BASH_ENV"] = "/tmp/x"
@case("S", "BASH_ENV set in the assemble step's env")
def _(d): by(d, "tag-sign.py assemble").setdefault("env", {})["BASH_ENV"] = "/tmp/x"
@case("S", "an env name outside the closed list")
def _(d): by(d, "tag-sign-kms.sh")["env"]["UNLISTED_NAME"] = "x"
@case("S", "the federation literal AWS_REGION on the assemble step (allowed only on the step that runs bin/tag-sign-kms.sh)")
def _(d): by(d, "tag-sign.py assemble").setdefault("env", {})["AWS_REGION"] = "us-east-1"
@case("S", "the federation literal AWS_ROLE_ARN on the prepare step")
def _(d): by(d, "tag-sign-prepare").setdefault("env", {})["AWS_ROLE_ARN"] = "arn:aws:iam::821302803867:role/fosterstack-cache-release-signing"
@case("S", "the federation literal RELEASE_KMS_KEY_REF on the checkout step")
def _(d): by(d, "actions/checkout").setdefault("env", {})["RELEASE_KMS_KEY_REF"] = "awskms:///alias/fosterstack-release-signing"
@case("S", "another value for AWS_REGION on the kms step")
def _(d): by(d, "tag-sign-kms.sh")["env"]["AWS_REGION"] = "eu-west-1"
@case("J", "a changed run: line (prepare with an argument)")
def _(d): by(d, "tag-sign-prepare")["run"] = "bash bin/tag-sign-prepare.sh --x"
@case("J", "a changed run: line (the aws CLI install of another tool)")
def _(d): by(d, "install-scanner")["run"] = "bash bin/install-scanner.sh grype"
@case("J", "a step added")
def _(d): steps(d).insert(2, {"name": "x", "run": "echo hi"})
@case("J", "a step dropped (the aws CLI install)")
def _(d): steps(d).remove(by(d, "install-scanner"))
@case("J", "a step dropped (the upload)")
def _(d): steps(d).pop()
@case("J", "two steps swapped (assemble before the kms call)")
def _(d): s = steps(d); i, j = s.index(by(d, "tag-sign-kms.sh")), s.index(by(d, "tag-sign.py assemble")); s[i], s[j] = s[j], s[i]
@case("S", "continue-on-error on a step")
def _(d): by(d, "tag-sign-prepare")["continue-on-error"] = "true"
@case("B", "continue-on-error on the job")
def _(d): d["jobs"]["sign-tag"]["continue-on-error"] = "true"
@case("B", "a job-level env")
def _(d): d["jobs"]["sign-tag"]["env"] = {"A": "b"}
@case("B", "job-level secrets")
def _(d): d["jobs"]["sign-tag"]["secrets"] = "inherit"
@case("B", "a job-level uses")
def _(d): d["jobs"]["sign-tag"]["uses"] = "./.github/workflows/x.yml"
@case("B", "a job-level container")
def _(d): d["jobs"]["sign-tag"]["container"] = "x"
@case("B", "job-level services")
def _(d): d["jobs"]["sign-tag"]["services"] = {"a": {"image": "x"}}
@case("B", "an unpinned action")
def _(d): by(d, "actions/checkout")["uses"] = "actions/checkout@v4"
@case("J", "contents write")
def _(d): d["jobs"]["sign-tag"]["permissions"]["contents"] = "write"
@case("J", "no id-token")
def _(d): del d["jobs"]["sign-tag"]["permissions"]["id-token"]
@case("J", "needs more than decide")
def _(d): d["jobs"]["sign-tag"]["needs"] = ["decide", "cut"]
@case("J", "another environment")
def _(d): d["jobs"]["sign-tag"]["environment"] = "agent"
@case("J", "another runner (runs-on ubuntu-latest)")
def _(d): d["jobs"]["sign-tag"]["runs-on"] = "ubuntu-latest"
@case("J", "another runner (runs-on ubuntu-22.04)")
def _(d): d["jobs"]["sign-tag"]["runs-on"] = "ubuntu-22.04"
@case("J", "another if")
def _(d): d["jobs"]["sign-tag"]["if"] = "true"
for who, label, f in CASES:
    d = copy.deepcopy(base); f(d)
    s, j = shared(d), judge(d)
    for kind, got, name in (("S", s, "the shared step checks"), ("J", j, "the tag jobs judge")):
        need = who in (kind, "B")
        if need:
            print(("OK sign-tag with %s is refused by %s (%s)" % (label, name, got[0][:70])) if got else "FAIL sign-tag with %s passes %s" % (label, name))
    both = [x for x in s + j]
    if not both: print("FAIL sign-tag with %s passes every judge" % label)
PY
while IFS= read -r l; do case "$l" in OK\ *) ok "${l#OK }";; *) bad "${l#FAIL }";; esac; done < <(python3 -I "$work/shared.py" "$root" 2>&1)
# ---- the ONE workflow-level concurrency group, evaluated for each kind of run (a second run must not decide the version the first has not pushed) ---------------------
cat > "$work/group.py" <<'PY'
import re, sys, yaml
REPO = "fosterstack/cache"
class N:
    """a context: a missing name reads as null (empty), as in a workflow expression"""
    def __init__(s, d): s._d = d
    def __getattr__(s, k):
        v = s._d.get(k.replace("_", "-") if k.replace("_", "-") in s._d else k, "")
        return N(v) if isinstance(v, dict) else v
def evaluate(expr, github, inputs):
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", expr.strip(), re.S)
    e = m.group(1) if m else expr
    parts = re.split(r"('(?:[^']|'')*')", e)
    for i in range(0, len(parts), 2):
        p = parts[i].replace("&&", " and ").replace("||", " or ").replace("inputs.dry-run", "inputs.dry_run")
        p = re.sub(r"!(?!=)", " not ", p)
        parts[i] = re.sub(r"\btrue\b", "True", re.sub(r"\bfalse\b", "False", p))
    code = "".join(parts)
    env = {"github": N(github), "inputs": N(inputs), "startsWith": lambda a, b: str(a).lower().startswith(str(b).lower()),
           "format": lambda f, *a: f.format(*a), "contains": lambda a, b: str(b) in str(a)}
    return eval(code, {"__builtins__": {}}, env)
def run(event, ref, wf, mode=None, dry=None, run_id="4711"):
    gh = {"event_name": event, "ref": ref, "workflow_ref": "%s/.github/workflows/%s@%s" % (REPO, wf, ref), "repository": REPO, "run_id": run_id}
    ins = {}
    if mode is not None: ins["mode"] = mode
    if dry is not None: ins["dry-run"] = dry
    return gh, ins
P, R = "patch-release", "4711"
SCEN = [
    ("release.yml's own push to main", run("push", "refs/heads/main", "release.yml"), P),
    ("release.yml's own daily schedule on main", run("schedule", "refs/heads/main", "release.yml"), P),
    ("a v* tag push (the chain)", run("push", "refs/tags/v0.3.1", "release.yml"), R),
    ("a dispatch on main", run("workflow_dispatch", "refs/heads/main", "release.yml", dry=False), R),
    ("a dry run on main", run("workflow_dispatch", "refs/heads/main", "release.yml", dry=True), R),
    ("a dry run on a branch", run("workflow_dispatch", "refs/heads/feature", "release.yml", dry=True), R),
    ("a snapshot call from scan.yml on a main push (github.ref and event_name are the caller's)", run("push", "refs/heads/main", "scan.yml", mode="snapshot"), R),
    ("a snapshot call from main-candidate-rescan.yml on the schedule", run("schedule", "refs/heads/main", "main-candidate-rescan.yml", mode="snapshot"), R),
    ("a snapshot call whose workflow_ref reads release.yml (only the mode tells it apart)", run("push", "refs/heads/main", "release.yml", mode="snapshot"), R),
    ("a main push of another workflow in release mode (only workflow_ref tells it apart)", run("push", "refs/heads/main", "scan.yml", mode="release"), R),
    ("a main push of release.yml of another repository", ({"event_name": "push", "ref": "refs/heads/main", "workflow_ref": "other/repo/.github/workflows/release.yml@refs/heads/main", "repository": REPO, "run_id": R}, {}), R),
]
def errors(text):
    d = yaml.safe_load(text); jobs = d.get("jobs") or {}; e = []
    top = d.get("concurrency")
    if not isinstance(top, dict): return ["the workflow has no concurrency group of its own: decide, sign-tag and cut must run under ONE group"]
    if top.get("cancel-in-progress") is not False: e.append("cancel-in-progress must be false (a decided version is never cancelled): %r" % top.get("cancel-in-progress"))
    for label, (gh, ins), want in SCEN:
        try: got = str(evaluate(str(top.get("group", "")), gh, ins))
        except Exception as ex: got = "error %s" % type(ex).__name__
        if got != want: e.append("the group of %s is %r, wanted %r" % (label, got, want))
    for jn, j in jobs.items():
        if "concurrency" in (j or {}) and jn not in ("release", "live-test-release"):
            e.append("the job %s has a concurrency group of its own, which splits the one group" % jn)
    if (jobs.get("release") or {}).get("concurrency", {}).get("group") != "release-publish": e.append("the release job must keep its own group release-publish")
    reads = [jn for jn, j in jobs.items() for st in (j.get("steps") or []) if re.search(r"git for-each-ref [^\n]*refs/tags/v\*|git tag (-l|--list)\b|ls-remote [^\n]*--tags", str(st.get("run", "")))]
    if "decide" not in reads: e.append("decide does not read the tag list")
    if [r for r in reads if r not in ("decide", "sign-tag", "cut")]: e.append("the tag list is read outside the group: %s" % sorted(set(reads)))
    return e
real = open(sys.argv[1]).read()
e = errors(real)
print("OK the real release.yml's group is 'patch-release' for its own push and schedule runs on main and github.run_id for the %d other kinds of run" % (len(SCEN) - 2) if not e
      else "FAIL the real release.yml: %s" % "; ".join(x[:140] for x in e))
m = re.search(r"^concurrency:\n  group: ([^\n]*)\n  cancel-in-progress: false\n", real, re.M)
if not m: print("FAIL the real release.yml has no workflow-level concurrency block with the group and cancel-in-progress false"); sys.exit(0)
GRP, EXPR = m.group(0), m.group(1)
print("OK there is exactly one workflow-level concurrency block" if len(re.findall(r"^concurrency:", real, re.M)) == 1 else "FAIL more than one workflow-level concurrency block")
SNAP, WFR = "inputs.mode != 'snapshot' && ", " && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository))"
EVT = "(github.event_name == 'push' || github.event_name == 'schedule')"
assert SNAP in EXPR and WFR in EXPR and EVT in EXPR and "github.ref == 'refs/heads/main'" in EXPR, EXPR
def with_group(g): return real.replace(GRP, "concurrency:\n  group: %s\n  cancel-in-progress: false\n" % g)
muts = (("a group without the snapshot conjunct", with_group(EXPR.replace(SNAP, ""))),
        ("a group without the workflow_ref conjunct", with_group(EXPR.replace(WFR, ""))),
        ("a group without the event conjunct (a dispatch on main joins it)", with_group(EXPR.replace(" && " + EVT, ""))),
        ("a group without the main conjunct (every ref joins it)", with_group(EXPR.replace(" && github.ref == 'refs/heads/main'", ""))),
        ("a constant group", with_group("patch-release")),
        ("a group that is always the run", with_group("${{ github.run_id }}")),
        ("a group that cancels", real.replace(GRP, GRP.replace("cancel-in-progress: false", "cancel-in-progress: true"))),
        ("no group at all", real.replace(GRP, "")),
        ("decide with a group of its own", real.replace("  decide:\n", "  decide:\n    concurrency:\n      group: patch-decide\n", 1)),
        ("sign-tag with a group of its own", real.replace("  sign-tag:\n", "  sign-tag:\n    concurrency:\n      group: other\n", 1)),
        ("cut with a group of its own", real.replace("\n  cut:\n", "\n  cut:\n    concurrency:\n      group: other\n", 1)),
        ("the release job with another group", real.replace("group: release-publish", "group: other", 1)),
        ("the tag list read in another job", real.replace("  patch-notes:\n", "  patch-notes:\n    env:\n      X: y\n", 1).replace("          git fetch --no-tags origin \"+refs/tags/${VERSION}:refs/tags/${VERSION}\"", "          git tag -l\n          git fetch --no-tags origin \"+refs/tags/${VERSION}:refs/tags/${VERSION}\"", 1)))
for label, t in muts:
    me = errors(t)
    print(("OK %s is refused (%s)" % (label, me[0][:90])) if t != real and me else "FAIL %s passes the group judge (or did not apply)" % label)
PY
while IFS= read -r l; do case "$l" in OK\ *) ok "${l#OK }";; *) bad "${l#FAIL }";; esac; done < <(python3 -I "$work/group.py" "$root/.github/workflows/release.yml" 2>&1)
# ---- REQ-REL-009-AC3: what release.yml's decide job passes to bin/patch-decide.py (the workflow text) ------------------
cat > "$work/decide-text.py" <<'PY'
import re, sys, yaml
d = yaml.safe_load(open(sys.argv[1] + "/.github/workflows/release.yml"))
steps = d["jobs"]["decide"]["steps"]
def run_of(i): return next(s for s in steps if s.get("id") == i)["run"]
def report(c, m): print(("OK " if c else "FAIL ") + m)
chk = run_of("checks"); ready = re.search(r"patch-decide\.py ready[^\n]*", chk).group(0)
report(re.search(r"git show origin/main:\.github/policy/required-checks\.json\s*>", chk) is not None, "AC3 the checks step reads required-checks.json from origin/main in each wait round")
report(0 < chk.find("while ") < chk.find("git fetch") < chk.find("required-checks.json") < chk.find("patch-decide.py ready"), "AC3 the policy file is read inside the wait loop, after the fetch of main")
report(len(re.findall(r"--required ", ready)) == 1, "AC3 patch-decide.py ready is given --required once, the policy file: %s" % ready)
fd = run_of("facts") + "\n" + run_of("decide")
g = re.search(r"[^\n]*gh run list[^\n]*(?:\\\n[^\n]*)*", fd)
report(g is not None and all(w in re.sub(r"\\\n\s*", " ", g.group(0)) for w in ("--workflow release.yml", "--branch", "--limit 1", "--json conclusion")), "AC3 the facts and decide steps gather the newest release run of each tag with gh run list --workflow release.yml --branch TAG --limit 1 --json conclusion")
report(g is not None and "||" not in g.group(0) and "set -euo pipefail" in run_of("facts" if "gh run list" in run_of("facts") else "decide"), "AC3 a failed gh run list fails the step (set -e, no || after it)")
dec = re.search(r"patch-decide\.py decide[^\n]*(?:\\\n[^\n]*)*", run_of("decide")).group(0)
report("--runs " in dec, "AC3 patch-decide.py decide is passed --runs FILE")
PY
while IFS= read -r l; do case "$l" in OK\ *) ok "${l#OK }";; *) bad "${l#FAIL }";; esac; done < <(python3 -I "$work/decide-text.py" "$root" 2>&1)
# ---- the real repository ------------------------------------------------------------------------------------------------------------
out=$(python3 "$work/judge.py" "$root" 2>&1) && ok "the real release.yml and policy lists carry the tag jobs as the rules say" || {
  n=0; while IFS= read -r l; do n=$((n + 1)); bad "real repository: $l"; done < <(tr ';' '\n' <<< "$out" | sed 's/^ //'); [ "$n" -gt 0 ] || bad "real repository: $out"; }
out=$(python3 -I "$work/policy.py" "$root" 2>&1) && ok "the real policy lists hold rules 6 and 7" || bad "real repository: $out"
echo "pass=$pass fail=$failn"
[ "$failn" = 0 ]
