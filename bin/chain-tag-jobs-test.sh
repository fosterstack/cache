#!/usr/bin/env bash
# proves: REQ-REL-009-AC5, REQ-REL-009-AC6, REQ-REL-009-AC2, REQ-REL-009-AC3, REQ-REL-009-AC4, REQ-REL-009-AC8
# The structure of the automatic patch release's tag jobs (rules: ops docs/ratify/2026-10-02-automatic-patch-releases.md, 2026-10-28-kms-signing-key-and-one-step-build.md).
# Static: no network, no secrets, no keys, nothing is run on GitHub. A judge reads release.yml, stage-sign.yml and the two policy lists and answers with a list of
# faults; it is FIRST proven on a known-good fixture tree and on mutated copies (a judge that cannot fail shows nothing), then applied to the real repository.
#
#   release.yml        on: push to main and to v* tags, and the daily schedule '47 9 * * *'. Jobs, in this order of `needs`:
#     decide           decides only: no key, no push right (no contents: write, no id-token, no App token), no tag made, signed or pushed, no keyless signing tool named. Its job output
#                      `tag` is the tag due (vX.Y.Z, the next patch) or empty. It runs rc-proof, decide, the ACs-baseline pre-check, the required-checks wait and the notes, and
#                      uploads the tag request (the tag and its notes) as an artifact for sign-tag.
#     sign-tag         the call of stage-sign.yml with stage: tag; permissions exactly contents read and id-token write; needs decide; runs only when decide's `tag` is non-empty.
#     cut              (environment agent, which holds the App secrets) the only job that pushes a tag: contents write through the auditor GitHub App's installation token (actions/create-github-app-token, AUDITOR_APP_ID and
#                      AUDITOR_APP_PRIVATE_KEY), no key, no id-token; needs decide and sign-tag (no status function in its if: it runs only after sign-tag succeeded); downloads the signed tag
#                      object sign-tag uploaded, checks that it is signed (git verify-tag, or its SSH SIGNATURE block) before it pushes the tag ref, and never runs `git tag`.
#     patch-notes      the changelog PR after the tag exists: needs decide and cut; its own App token for pull requests; bin/patch-decide.py tag-notes then changelog.
#   stage-sign.yml     the job sign-tag (if: inputs.stage == 'tag'), permissions exactly contents read and id-token write, no secret and no push, with these steps: checkout, one download of the
#                      artifact decide uploaded, the aws CLI install, `bin/tag-sign.py prepare`, `bin/with-aws-token.sh kms-sign` with exactly the release role, region and key reference
#                      (awskms:///alias/fosterstack-release-signing) as step env, `bin/tag-sign.py assemble`, one upload (the signed tag object cut downloads).
#   policy             id-token-jobs.json lists release.yml:sign-tag and stage-sign.yml:sign-tag (and no tag job else); chain-scripts.json lists bin/tag-sign.py with its sha256.
# Needs: bash, python3 + PyYAML.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL PyYAML is required (apt: python3-yaml)"; exit 1; }
cat > "$work/judge.py" <<'PY'
import hashlib, json, os, re, sys, yaml

SHA = r"[0-9a-f]{40}"
ROLE = "arn:aws:iam::821302803867:role/fosterstack-cache-release-signing"
KEY_REF = "awskms:///alias/fosterstack-release-signing"
TAGGER = "fosterstack release <release@users.noreply.github.com>"
APP_TOKEN = re.compile(r"actions/create-github-app-token@%s( #.*)?" % SHA)
STATUS_FN = re.compile(r"\b(always|failure|cancelled|success)\s*\(")
# what no job that holds no key may name: a key, a role, a keyless signing tool
KEY_WORDS = re.compile(r"AWS_ROLE_ARN|AWS_REGION|RELEASE_KMS_KEY_REF|kms-sign|with-aws-token|awskms|arn:aws|fulcio|gitsign|smimesign|keyless|identity-token|cosign (sign|attest)|ssh-keygen -Y sign|ACTIONS_ID_TOKEN", re.I)
TAG_MAKERS = re.compile(r"git\s+tag\b|git\s+push\b|git/(refs|tags)|create-release|gh release create|tag -s\b")
SIGN_TAG_BAD = re.compile(r"secrets\.|GITHUB_TOKEN|github\.token|git\s+push\b|git\s+tag\b|\bgh\s|fulcio|gitsign|smimesign|keyless|identity-token|cosign (sign|attest)|AWS_ACCESS_KEY|AWS_SECRET|AWS_SESSION|contents:\s*write", re.I)


def load(path):
    return yaml.safe_load(open(path)) or {}


def steps_of(j):
    return j.get("steps") or []


def run_text(j):
    return "\n".join(str(s.get("run", "")) for s in steps_of(j))


def blob(j):
    return json.dumps(j, sort_keys=False)


def needs_of(j):
    n = j.get("needs", [])
    return {n} if isinstance(n, str) else set(n)


def uploads(j):
    return [((s.get("with") or {}).get("name")) for s in steps_of(j) if str(s.get("uses", "")).startswith("actions/upload-artifact@")]


def downloads(j):
    return [((s.get("with") or {}).get("name")) for s in steps_of(j) if str(s.get("uses", "")).startswith("actions/download-artifact@")]


def no_write(perm, allow=()):
    """a permissions mapping that grants no write beyond `allow`"""
    return isinstance(perm, dict) and not any(v == "write" and k not in allow for k, v in perm.items())


def judge(r):
    bad = []
    rp, sp = os.path.join(r, ".github/workflows/release.yml"), os.path.join(r, ".github/workflows/stage-sign.yml")
    if not (os.path.exists(rp) and os.path.exists(sp)):
        return ["release.yml or stage-sign.yml is missing"]
    rd, sd = load(rp), load(sp)
    jobs, sjobs = rd.get("jobs") or {}, sd.get("jobs") or {}
    on = rd.get("on", rd.get(True)) or {}
    push = (on.get("push") or {}) if isinstance(on, dict) else {}
    if "main" not in (push.get("branches") or []) or "v*" not in (push.get("tags") or []):
        bad.append("release.yml must run on a push to main (decide) and to v* tags (the chain): on.push needs branches [main] and tags [v*]")
    cron = [e.get("cron") for e in (on.get("schedule") or [])] if isinstance(on, dict) else []
    if cron != ["47 9 * * *"]:
        bad.append("release.yml must run on the daily schedule '47 9 * * *' (after the rescan and the auditor), found %s" % cron)
    for n in ("decide", "sign-tag", "cut", "patch-notes"):
        if n not in jobs:
            bad.append("release.yml has no job %s" % n)
    if "sign-tag" not in sjobs:
        bad.append("stage-sign.yml has no job sign-tag")
    if bad:
        return bad
    # ---- decide: decides only
    d = jobs["decide"]
    if "refs/heads/main" not in str(d.get("if", "")):
        bad.append("decide must run on main only (its if names refs/heads/main), found %r" % d.get("if"))
    perm = d.get("permissions")
    if not isinstance(perm, dict) or "id-token" in perm or perm.get("contents") == "write" or not no_write(perm, allow=("issues",)):
        bad.append("decide holds no key and no push right: permissions must grant no contents write, no id-token and no write but issues (the standing issue): %s" % perm)
    if KEY_WORDS.search(blob(d)) or TAG_MAKERS.search(blob(d)) or "create-github-app-token" in blob(d) or re.search(r"AUDITOR_APP|secrets\.", blob(d)):
        bad.append("decide names a key, a role, an App token, a secret or a keyless tool, or creates, signs or pushes a tag: it decides only")
    if "tag" not in (d.get("outputs") or {}):
        bad.append("decide must have the job output `tag` (the tag due, vX.Y.Z, or empty)")
    rt = run_text(d)
    for needle, what in (("patch-decide.py rc-proof", "the rc-proof marker (REQ-CHAIN-001-AC6)"), ("patch-decide.py decide", "the fix-only decision"),
                         ("admission-tag-signer.py baseline", "the ACs baseline pre-check"), ("patch-decide.py ready", "the required checks of the tagged commit"),
                         ("patch-decide.py notes", "the generated notes")):
        if needle not in rt:
            bad.append("decide does not run %s (%s)" % (needle, what))
    dup = [n for n in uploads(d) if n]
    if len(dup) != 1:
        bad.append("decide must upload exactly one artifact (the tag request: tag and notes) for sign-tag, found %s" % dup)
    # ---- sign-tag call
    c = jobs["sign-tag"]
    if c.get("uses") != "./.github/workflows/stage-sign.yml" or (c.get("with") or {}).get("stage") != "tag":
        bad.append("sign-tag must call ./.github/workflows/stage-sign.yml with stage: tag")
    if "decide" not in needs_of(c):
        bad.append("sign-tag must need decide")
    if "needs.decide.outputs.tag" not in str(c.get("if", "")) or STATUS_FN.search(str(c.get("if", ""))):
        bad.append("sign-tag must run only when decide's output tag is non-empty (an if naming needs.decide.outputs.tag, no status function), found %r" % c.get("if"))
    if c.get("permissions") != {"contents": "read", "id-token": "write"}:
        bad.append("sign-tag's permissions must be exactly contents read and id-token write (no contents write, no push): %s" % c.get("permissions"))
    if "secrets" in c or "environment" in c:
        bad.append("sign-tag passes secrets or an environment: the release key is reached through federation only")
    # ---- cut: the only job that pushes a tag
    u = jobs["cut"]
    if u.get("environment") != "agent":
        bad.append("cut must name environment: agent (the auditor App's secrets live in that main-only environment), found %r" % u.get("environment"))
    cp = u.get("permissions")
    if not isinstance(cp, dict) or "id-token" in cp or cp.get("contents") == "write" or not no_write(cp):
        bad.append("cut holds no key: no id-token, and its GITHUB_TOKEN no write (the push uses the App token): %s" % cp)
    if not {"decide", "sign-tag"} <= needs_of(u):
        bad.append("cut must need decide and sign-tag (it never pushes an unsigned tag and runs only after the signing job succeeded)")
    cif = str(u.get("if", ""))
    if "needs.decide.outputs.tag" not in cif or STATUS_FN.search(cif):
        bad.append("cut must run only when decide's output tag is non-empty, with no status function in its if (a status function lets it run after sign-tag failed or was skipped), found %r" % u.get("if"))
    cb = blob(u)
    if KEY_WORDS.search(cb) or re.search(r"git\s+tag\b|create-release|gh release create|git/tags", cb):
        bad.append("cut names a key, a role, a keyless tool, or makes a tag object itself (git tag, the tags API, a release): it pushes the signed tag object it downloaded and nothing else")
    sec = set(re.findall(r"secrets\.(\w+)", cb))
    if sec != {"AUDITOR_APP_ID", "AUDITOR_APP_PRIVATE_KEY"}:
        bad.append("cut's secrets must be exactly AUDITOR_APP_ID and AUDITOR_APP_PRIVATE_KEY (the auditor App's installation token: a tag pushed with GITHUB_TOKEN starts no workflow run), found %s" % sorted(sec))
    app = [s for s in steps_of(u) if APP_TOKEN.fullmatch(str(s.get("uses", "")))]
    if len(app) != 1:
        bad.append("cut needs exactly one pinned actions/create-github-app-token step, found %d" % len(app))
    else:
        w = app[0].get("with") or {}
        if w.get("app-id") != "${{ secrets.AUDITOR_APP_ID }}" or w.get("private-key") != "${{ secrets.AUDITOR_APP_PRIVATE_KEY }}" or w.get("permission-contents") != "write" \
                or any(k.startswith("permission-") and k != "permission-contents" for k in w):
            bad.append("cut's App token must be minted from AUDITOR_APP_ID and AUDITOR_APP_PRIVATE_KEY with permission-contents: write and no other permission: %s" % w)
        sid = app[0].get("id")
        others = blob({"steps": [s for s in steps_of(u) if s is not app[0]]})
        if not sid or ("steps.%s.outputs.token" % sid) not in others:
            bad.append("cut's push must use the App token (steps.<id>.outputs.token of the create-github-app-token step)")
    pushes = [i for i, s in enumerate(steps_of(u)) if re.search(r"git\s+push\b", str(s.get("run", "")))]
    if len(pushes) != 1:
        bad.append("cut must push the tag in exactly one step (git push), found %d" % len(pushes))
    else:
        ps = steps_of(u)[pushes[0]]
        if not re.search(r"git\s+push[^\n]*refs/tags/", str(ps.get("run"))) or "${{" in str(ps.get("run")):
            bad.append("cut's push command must push a refs/tags/ ref and put no expression in the script (the tag reaches it through env)")
        before = "\n".join(str(s.get("run", "")) for s in steps_of(u)[:pushes[0]]) + "\n" + str(ps.get("run")).split("git push")[0]
        if not re.search(r"verify-tag|SSH SIGNATURE", before):
            bad.append("cut must check that the tag object is signed (git verify-tag or its SSH SIGNATURE block) before the push step: it never pushes an unsigned tag")
    if len(downloads(u)) != 1:
        bad.append("cut must download exactly one artifact, the signed tag object, found %s" % downloads(u))
    # ---- patch-notes
    pn = jobs["patch-notes"]
    if not {"decide", "cut"} <= needs_of(pn):
        bad.append("patch-notes must need decide and cut (the tag it reads must exist)")
    if "needs.decide.outputs.tag" not in str(pn.get("if", "")):
        bad.append("patch-notes must run only when a tag was cut (an if naming needs.decide.outputs.tag), found %r" % pn.get("if"))
    if pn.get("environment") != "agent":
        bad.append("patch-notes must name environment: agent (the auditor App's secrets live there), found %r" % pn.get("environment"))
    pp = pn.get("permissions")
    if not isinstance(pp, dict) or "id-token" in pp or pp.get("contents") == "write" or not no_write(pp):
        bad.append("patch-notes holds no id-token and no write of its own token: %s" % pp)
    prt = run_text(pn)
    if "patch-decide.py tag-notes" not in prt or "patch-decide.py changelog" not in prt:
        bad.append("patch-notes must read the tag's notes (patch-decide.py tag-notes) and write the changelog (patch-decide.py changelog)")
    papp = [s for s in steps_of(pn) if APP_TOKEN.fullmatch(str(s.get("uses", "")))]
    if len(papp) != 1 or (papp[0].get("with") or {}).get("permission-pull-requests") != "write":
        bad.append("patch-notes needs its own pinned App token with permission-pull-requests: write")
    # ---- stage-sign.yml: the tag stage
    s = sjobs["sign-tag"]
    if s.get("if") != "${{ inputs.stage == 'tag' }}":
        bad.append("sign-tag must carry exactly `if: ${{ inputs.stage == 'tag' }}`, found %r" % s.get("if"))
    for n, j in sjobs.items():
        if n != "sign-tag" and "tag'" in str(j.get("if", "")):
            bad.append("job %s of stage-sign.yml also runs for the tag stage: only sign-tag signs a tag" % n)
    if s.get("permissions") != {"contents": "read", "id-token": "write"}:
        bad.append("stage-sign.yml sign-tag's permissions must be exactly contents read and id-token write: %s" % s.get("permissions"))
    if any(k in s for k in ("needs", "env", "secrets", "environment", "container", "services", "uses")):
        bad.append("sign-tag has needs, env, secrets, an environment, a container, services or uses: it is a plain job")
    sb = blob(s)
    if SIGN_TAG_BAD.search(sb):
        bad.append("sign-tag names a stored credential, the job token, a push, a tag command or a keyless tool: %s" % SIGN_TAG_BAD.search(sb).group(0))
    if len(re.findall(r"alias/[A-Za-z0-9_-]+", sb)) > 1 or ("alias/" in sb and KEY_REF not in sb):
        bad.append("sign-tag may name only the one release key %s" % KEY_REF)
    sst = steps_of(s)
    for st in sst:
        u_ = str(st.get("uses", ""))
        if u_ and not re.fullmatch(r"actions/(checkout|download-artifact|upload-artifact)@%s( #.*)?" % SHA, u_):
            bad.append("sign-tag uses %r: only pinned actions/checkout, download-artifact and upload-artifact" % u_)
        if u_.startswith("actions/checkout@") and (st.get("with") or {}).get("persist-credentials") is not False:
            bad.append("sign-tag's checkout must say persist-credentials: false")
    runs = [str(st.get("run", "")) for st in sst if "run" in st]
    kinds = []
    for st in sst:
        r_ = str(st.get("run", ""))
        if "uses" in st:
            kinds.append(str(st["uses"]).split("@")[0].split("/")[1])
        elif re.fullmatch(r"\s*bash bin/install-scanner\.sh aws-cli\s*", r_):
            kinds.append("aws")
        elif "bin/tag-sign.py prepare" in r_:
            kinds.append("prepare")
        elif re.match(r"\s*bash bin/with-aws-token\.sh kms-sign\b", r_):
            kinds.append("kms")
        elif "bin/tag-sign.py assemble" in r_:
            kinds.append("assemble")
        else:
            kinds.append("other:" + r_[:40])
    if kinds != ["checkout", "download-artifact", "aws", "prepare", "kms", "assemble", "upload-artifact"]:
        bad.append("sign-tag's steps must be exactly: checkout, download of the tag request, install of the aws CLI (bash bin/install-scanner.sh aws-cli), tag-sign.py prepare, "
                   "bash bin/with-aws-token.sh kms-sign, tag-sign.py assemble, one upload; found %s" % kinds)
    for st in sst:
        r_ = str(st.get("run", ""))
        if "bin/tag-sign.py prepare" in r_:
            for a in ("--tag", "--commit", "--notes", "--tagger", "--time", "--object", "--digest"):
                if a not in r_:
                    bad.append("the prepare step passes no %s" % a)
            if TAGGER not in r_:
                bad.append("the prepare step's tagger must be the release tagger '%s' (the one bin/patch-decide.py tag-notes reads)" % TAGGER)
        if "bin/tag-sign.py assemble" in r_:
            for a in ("--object", "--signature", "--signer-file", "--out"):
                if a not in r_:
                    bad.append("the assemble step passes no %s" % a)
        if re.match(r"\s*bash bin/with-aws-token\.sh kms-sign\b", r_):
            if "--digest" not in r_:
                bad.append("the kms-sign step signs no --digest (the sha256 of the sshsig signed-data blob)")
            if st.get("env") != {"AWS_ROLE_ARN": ROLE, "AWS_REGION": "us-east-1", "RELEASE_KMS_KEY_REF": KEY_REF}:
                bad.append("the kms-sign step's env must be exactly the release role, region and key reference as literals: %s" % st.get("env"))
        if "${{" in r_ and "tag-sign" in r_:
            bad.append("a tag-sign.py step puts an expression into its script (use env)")
    # the artifact hand-offs: decide -> sign-tag -> cut, by name
    dn, un = [n for n in uploads(d) if n], uploads(s)
    if len(downloads(s)) != 1 or downloads(s)[0] not in dn:
        bad.append("sign-tag must download the one artifact decide uploads (%s), found %s" % (dn, downloads(s)))
    if len(un) != 1 or downloads(u) != un:
        bad.append("sign-tag's one upload (%s) must be the artifact cut downloads (%s)" % (un, downloads(u)))
    # ---- no other workflow or job runs the tag signer
    wd = os.path.join(r, ".github/workflows")
    for f in sorted(os.listdir(wd)):
        if not f.endswith((".yml", ".yaml")):
            continue
        for n, j in (load(os.path.join(wd, f)).get("jobs") or {}).items():
            if "tag-sign.py" in blob(j) and (f, n) != ("stage-sign.yml", "sign-tag"):
                bad.append("%s:%s runs bin/tag-sign.py: only stage-sign.yml's sign-tag signs a tag" % (f, n))
    # ---- the judges' lists
    ip = os.path.join(r, ".github/policy/id-token-jobs.json")
    listed = [(e.get("workflow"), e.get("job")) for e in (json.load(open(ip)).get("jobs") or [])] if os.path.exists(ip) else []
    for want in (("release.yml", "sign-tag"), ("stage-sign.yml", "sign-tag")):
        if listed.count(want) != 1:
            bad.append("id-token-jobs.json must list %s:%s exactly once" % want)
    for n in ("decide", "cut", "patch-notes"):
        if ("release.yml", n) in listed:
            bad.append("id-token-jobs.json lists release.yml:%s, which holds no id-token" % n)
    cs = os.path.join(r, ".github/policy/chain-scripts.json")
    ts = os.path.join(r, "bin/tag-sign.py")
    rows = [e for e in (json.load(open(cs)).get("scripts") or []) if e.get("path") == "bin/tag-sign.py"] if os.path.exists(cs) else []
    if not os.path.exists(ts):
        bad.append("bin/tag-sign.py does not exist")
    elif len(rows) != 1 or rows[0].get("sha256") != hashlib.sha256(open(ts, "rb").read()).hexdigest():
        bad.append("chain-scripts.json must list bin/tag-sign.py once, with the script's own sha256")
    return bad


if __name__ == "__main__":
    bad = judge(sys.argv[1])
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
PY
# ---- a known-good fixture tree ----------------------------------------------------------------------------------------------------
python3 - "$work" <<'PY'
import hashlib, json, os, sys
w = sys.argv[1] + "/good"
for d in (".github/workflows", ".github/policy", "bin"):
    os.makedirs(os.path.join(w, d))
H = "0123456789abcdef0123456789abcdef01234567"
CHK = "actions/checkout@%s # v7.0.1" % H
UP = "actions/upload-artifact@%s # v7.0.2" % H
DN = "actions/download-artifact@%s # v8.0.2" % H
APP = "actions/create-github-app-token@%s # v3.3.0" % H
open(w + "/.github/workflows/release.yml", "w").write("""name: Release
on:
  push:
    tags:
      - "v*"
    branches:
      - main
  schedule:
    - cron: '47 9 * * *'
  workflow_dispatch:
permissions:
  contents: read
jobs:
  decide:
    if: ${{ github.ref == 'refs/heads/main' && github.event_name != 'workflow_dispatch' }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: read
      issues: write
    outputs:
      tag: ${{ steps.decide.outputs.tag }}
    steps:
      - uses: %(CHK)s
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: rc-proof
        run: python3 bin/patch-decide.py rc-proof --marker .github/policy/rc-proof.json --commit "$GITHUB_SHA"
      - name: ACs baseline
        run: python3 bin/admission-tag-signer.py baseline --tag "$VERSION" --owner-baselines b --requirements requirements/requirements.yaml
      - name: required checks
        run: python3 bin/patch-decide.py ready --required r.json --check-runs c.json
      - name: notes
        run: python3 bin/patch-decide.py notes --version "$VERSION" --out tag-request/notes.md
      - name: decide
        id: decide
        run: python3 bin/patch-decide.py decide --event "$GITHUB_EVENT_NAME" --out d.json
      - uses: %(UP)s
        with:
          name: tag-request
          path: tag-request
  sign-tag:
    needs: decide
    if: ${{ needs.decide.outputs.tag != '' }}
    permissions:
      contents: read
      id-token: write
    uses: ./.github/workflows/stage-sign.yml
    with:
      stage: tag
      digests: '{}'
  cut:
    needs: [decide, sign-tag]
    if: ${{ needs.decide.outputs.tag != '' }}
    runs-on: ubuntu-latest
    environment: agent
    permissions:
      contents: read
    steps:
      - uses: %(CHK)s
        with:
          persist-credentials: false
      - uses: %(DN)s
        with:
          name: signed-tag
          path: signed-tag
      - name: mint the auditor App's token
        id: app-token
        uses: %(APP)s
        with:
          app-id: ${{ secrets.AUDITOR_APP_ID }}
          private-key: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}
          repositories: cache
          permission-contents: write
      - name: verify the signed tag, then push it
        env:
          TAG: ${{ needs.decide.outputs.tag }}
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
        run: |
          set -euo pipefail
          id=$(git hash-object -t tag -w signed-tag/tag.signed)
          git update-ref "refs/tags/$TAG" "$id"
          git -c gpg.ssh.allowedSignersFile=.github/policy/release_tag_signer verify-tag "$TAG"
          git push origin "refs/tags/$TAG"
  patch-notes:
    needs: [decide, cut]
    if: ${{ needs.decide.outputs.tag != '' }}
    runs-on: ubuntu-latest
    environment: agent
    permissions:
      contents: read
    steps:
      - uses: %(CHK)s
        with:
          persist-credentials: false
      - id: app-token
        uses: %(APP)s
        with:
          app-id: ${{ secrets.AUDITOR_APP_ID }}
          private-key: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}
          permission-contents: write
          permission-pull-requests: write
      - run: |
          git cat-file tag "$VERSION" | python3 bin/patch-decide.py tag-notes > notes.md
          python3 bin/patch-decide.py changelog --notes notes.md --changelog docs/quality/releases/CHANGELOG.md --next-notes docs/next-release-notes.md
""" % dict(CHK=CHK, UP=UP, DN=DN, APP=APP))
open(w + "/.github/workflows/stage-sign.yml", "w").write("""name: 'Stage: sign'
on:
  workflow_call:
    inputs:
      digests:
        required: true
        type: string
      stage:
        required: true
        type: string
permissions:
  contents: read
jobs:
  sign:
    if: ${{ inputs.stage == 'build' }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo build
  sign-check:
    if: ${{ inputs.stage == 'check' }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo check
  sign-tag:
    if: ${{ inputs.stage == 'tag' }}
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: %(CHK)s
        with:
          persist-credentials: false
      - uses: %(DN)s
        with:
          name: tag-request
          path: tag-request
      - name: install the aws CLI (pinned by checksum)
        run: bash bin/install-scanner.sh aws-cli
      - name: the tag object and the digest the key signs
        run: python3 -I -B bin/tag-sign.py prepare --tag "$(cat tag-request/tag)" --commit "$GITHUB_SHA" --notes tag-request/notes.md --tagger 'fosterstack release <release@users.noreply.github.com>' --time "$(date +%%s)" --object tag.obj --digest tag.digest
      - name: sign the digest with the release key
        env:
          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing
          AWS_REGION: us-east-1
          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing
        run: bash bin/with-aws-token.sh kms-sign --key-ref "$RELEASE_KMS_KEY_REF" --digest "$(cat tag.digest)" --out tag.sig --bundle tag.bundle
      - name: assemble the signed tag object
        run: python3 -I -B bin/tag-sign.py assemble --object tag.obj --signature tag.sig --signer-file .github/policy/release_tag_signer --out signed-tag/tag.signed
      - uses: %(UP)s
        with:
          name: signed-tag
          path: signed-tag
""" % dict(CHK=CHK, UP=UP, DN=DN))
open(w + "/bin/tag-sign.py", "w").write("#!/usr/bin/env python3\n# fixture\n")
sha = hashlib.sha256(open(w + "/bin/tag-sign.py", "rb").read()).hexdigest()
json.dump({"scripts": [{"path": "bin/tag-sign.py", "sha256": sha}]}, open(w + "/.github/policy/chain-scripts.json", "w"))
json.dump({"jobs": [{"workflow": "release.yml", "job": "sign"}, {"workflow": "release.yml", "job": "sign-tag"}, {"workflow": "stage-sign.yml", "job": "sign-tag"}]},
          open(w + "/.github/policy/id-token-jobs.json", "w"))
PY
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
out=$(python3 "$work/judge.py" "$work/good" 2>&1) && ok "fixture: the known-good tag jobs pass the judge" || bad "fixture: known-good fixture refused: $out"
# mutant LABEL FILE REGEX REPLACEMENT WORD : the judge must refuse the mutated tree and its message must contain WORD
mut() {
  local label=$1 file=$2 rx=$3 rep=$4 word=$5 d="$work/m$((pass + failn))"
  rm -rf "$d"; cp -r "$work/good" "$d"
  if ! python3 - "$d/$file" "$rx" "$rep" <<'PY'
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
R=.github/workflows/release.yml S=.github/workflows/stage-sign.yml
# decide: decides only
mut "decide holds contents write"                 $R '(  decide:.*?      contents: )read'                       '\1write'                                   'decide holds no key'
mut "decide holds id-token"                       $R '(  decide:.*?      issues: write\n)'                      '\1      id-token: write\n'                   'decide holds no key'
mut "decide holds packages write"                 $R '(  decide:.*?      issues: write\n)'                      '\1      packages: write\n'                   'decide holds no key'
mut "decide mints the App token"                  $R '(  decide:.*?    steps:\n)'                               '\1      - uses: actions/create-github-app-token@0123456789abcdef0123456789abcdef01234567\n        with:\n          app-id: x\n' 'decides only'
mut "decide pushes a tag"                         $R '(      - name: decide\n        id: decide\n        run: )'    '      - run: git push origin refs/tags/v9.9.9\n\1' 'decides only'
mut "decide signs a tag with a keyless tool"      $R '(      - name: decide\n        id: decide\n        run: )'    '      - run: gitsign sign x\n\1'            'decides only'
mut "decide names the release key"                $R '(      - name: decide\n        id: decide\n        run: )'    '      - run: echo awskms:///alias/fosterstack-release-signing\n\1' 'decides only'
mut "decide has no tag output"                    $R '    outputs:\n      tag: [^\n]*\n'                       ''                                          'output `tag`'
mut "decide runs on every branch"                 $R "(  decide:\n    if: )[^\n]*"                              "\\1\${{ github.event_name != 'workflow_dispatch' }}" 'main only'
mut "decide does not check the rc-proof marker"   $R '      - name: rc-proof\n        run: [^\n]*\n'            ''                                          'rc-proof'
mut "decide does not decide"                      $R '      - name: decide\n        id: decide\n        run: [^\n]*\n' '      - name: decide\n        id: decide\n        run: echo\n' 'fix-only decision'
mut "decide does not check the ACs baseline"      $R '      - name: ACs baseline\n        run: [^\n]*\n'          ''                                          'ACs baseline'
mut "decide does not wait for the required checks" $R '      - name: required checks\n        run: [^\n]*\n'        ''                                          'required checks'
mut "decide writes no notes"                      $R '      - name: notes\n        run: [^\n]*\n'               ''                                          'generated notes'
mut "decide uploads no tag request"               $R '      - uses: actions/upload-artifact@[^\n]*\n        with:\n          name: tag-request\n          path: tag-request\n' '' 'upload exactly one artifact'
mut "the push trigger is gone"                    $R '    branches:\n      - main\n'                           ''                                          'push to main'
mut "the daily schedule is another time"          $R "47 9 \* \* \*"                                              '13 5 * * *'                                'daily schedule'
# sign-tag call
mut "sign-tag does not wait for decide"           $R '(  sign-tag:\n    needs: )decide'                         '\1[]'                                      'sign-tag must need decide'
mut "sign-tag runs whatever decide said"          $R "(  sign-tag:\n.*?    if: )[^\n]*"                         "\\1true"                                   'non-empty'
mut "sign-tag holds contents write"               $R '(  sign-tag:.*?      contents: )read'                     '\1write'                                   'exactly contents read and id-token write'
mut "sign-tag holds no id-token"                  $R '(  sign-tag:.*?permissions:\n      contents: read\n)      id-token: write\n' '\1'                     'exactly contents read and id-token write'
mut "sign-tag holds packages write"               $R '(  sign-tag:.*?      id-token: write\n)'                  '\1      packages: write\n'                   'exactly contents read and id-token write'
mut "sign-tag calls another stage"                $R '      stage: tag'                                         '      stage: check'                        'stage: tag'
mut "sign-tag inherits the secrets"               $R '(  sign-tag:\n)'                                          '\1    secrets: inherit\n'                  'passes secrets'
# cut: the only job that pushes a tag, with the App token, after sign-tag
mut "cut does not wait for sign-tag"              $R '(  cut:\n    needs: )\[decide, sign-tag\]'                '\1[decide]'                                'must need decide and sign-tag'
mut "cut runs after a failed sign-tag"            $R "(  cut:\n    needs: \[decide, sign-tag\]\n    if: )[^\n]*"  "\\1\${{ always() && needs.decide.outputs.tag != '' }}" 'no status function'
mut "cut runs whatever decide said"               $R "(  cut:\n    needs: \[decide, sign-tag\]\n    if: )[^\n]*"  "\\1true"                                   'non-empty'
mut "cut has no environment (the App's secrets would be empty)" $R '(  cut:.*?    runs-on: ubuntu-latest\n)    environment: agent\n' '\1' 'environment: agent'
mut "cut runs in another environment"             $R '(  cut:.*?    environment: )agent'                    '\1release'                                 'environment: agent'
mut "patch-notes has no environment"              $R '(  patch-notes:.*?    runs-on: ubuntu-latest\n)    environment: agent\n' '\1' 'environment: agent'
mut "sign-tag runs in an environment"             $R '(  sign-tag:\n)'                                   '\1    environment: agent\n'                'passes secrets or an environment'
mut "cut holds contents write on its own token"   $R '(  cut:.*?      contents: )read'                          '\1write'                                   'cut holds no key'
mut "cut holds id-token"                          $R '(  cut:.*?    permissions:\n      contents: read\n)'     '\1      id-token: write\n'                   'cut holds no key'
mut "cut names the release key"                   $R '(          TAG: \$\{\{ needs.decide.outputs.tag \}\}\n)' '\1          RELEASE_KMS_KEY_REF: x\n'           'cut names a key'
mut "cut pushes with GITHUB_TOKEN"                $R '          GH_TOKEN: \$\{\{ steps.app-token.outputs.token \}\}' '          GH_TOKEN: ${{ github.token }}'        'must use the App token'
mut "cut's App token has no contents write"       $R '          permission-contents: write\n(      - name: verify)' '          permission-pull-requests: write\n\1' 'permission-contents: write'
mut "cut's App token also writes pull requests"   $R '(          repositories: cache\n          permission-contents: write\n)(      - name: verify)' '\1          permission-pull-requests: write\n\2' 'no other permission'
mut "cut uses other secrets"                      $R '(          repositories: cache\n)'                       '\1          x: ${{ secrets.OTHER }}\n'           'secrets must be exactly'
mut "cut makes the tag itself"                    $R '(          git push origin)'                            '          git tag -s "$TAG"\n\1'               'makes a tag object itself'
mut "cut does not check the signature"            $R '          git -c gpg.ssh.allowedSignersFile=[^\n]*\n'    ''                                          'is signed'
mut "cut checks the signature after the push"     $R '(          git -c gpg.ssh[^\n]*\n)(          git push origin[^\n]*\n)' '\2\1'                         'is signed'
mut "cut pushes a branch, not a tag ref"          $R '          git push origin "refs/tags/\$TAG"'            '          git push origin HEAD:main'           'refs/tags/'
mut "cut puts the tag into its script"            $R '          git push origin "refs/tags/\$TAG"'            '          git push origin "refs/tags/${{ needs.decide.outputs.tag }}"' 'no expression'
mut "cut downloads nothing"                       $R '      - uses: actions/download-artifact@[^\n]*\n        with:\n          name: signed-tag\n          path: signed-tag\n' '' 'download exactly one'
mut "cut downloads another artifact than sign-tag uploads" $R '(          name: )signed-tag\n          path: signed-tag\n      - name: mint'  '\1other\n          path: signed-tag\n      - name: mint' 'must be the artifact cut downloads'
# patch-notes
mut "patch-notes does not wait for cut"           $R '(  patch-notes:\n    needs: )\[decide, cut\]'          '\1[decide]'                                'must need decide and cut'
mut "patch-notes has no tag-notes step"           $R 'git cat-file tag "\$VERSION" \| python3 bin/patch-decide.py tag-notes > notes.md\n' '' 'tag-notes'
mut "patch-notes has no pull request token"       $R '          permission-pull-requests: write\n'             ''                                          'permission-pull-requests'
# stage-sign.yml: the tag stage
mut "stage-sign sign-tag runs for another stage"  $S "(  sign-tag:\n    if: )[^\n]*"                           "\\1\${{ inputs.stage != 'build' }}"       'inputs.stage'
mut "stage-sign sign also runs for the tag stage" $S "(  sign:\n    if: )[^\n]*"                               "\\1\${{ inputs.stage == 'build' || inputs.stage == 'tag' }}" 'also runs for the tag stage'
mut "stage-sign sign-tag holds contents write"    $S '(  sign-tag:.*?      contents: )read'                     '\1write'                                   'permissions must be exactly'
mut "stage-sign sign-tag holds no id-token"       $S '(  sign-tag:.*?      contents: read\n)      id-token: write\n' '\1'                                 'permissions must be exactly'
mut "stage-sign sign-tag has a needs"             $S '(  sign-tag:\n)'                                          '\1    needs: sign\n'                       'plain job'
mut "stage-sign sign-tag uses a stored credential" $S '(          AWS_REGION: us-east-1\n)'                    '\1          AWS_SECRET_ACCESS_KEY: ${{ secrets.K }}\n' 'names a stored credential'
mut "stage-sign sign-tag signs keyless"           $S '(      - name: assemble the signed tag object\n)'         '      - run: cosign sign --identity-token x y\n\1' 'keyless'
mut "stage-sign sign-tag names a second key"      $S '(          name: signed-tag\n)'                          '\1          x: alias/other-key\n'                'one release key'
mut "stage-sign sign-tag has another key reference" $S 'awskms:///alias/fosterstack-release-signing'            'awskms:///alias/other-key'                 'release key'
mut "stage-sign sign-tag has another role"        $S 'role/fosterstack-cache-release-signing'                   'role/other-role'                           'release role, region and key reference'
mut "stage-sign sign-tag pushes"                  $S '(      - name: assemble the signed tag object\n)'         '      - run: git push origin HEAD\n\1'      'push'
mut "stage-sign sign-tag skips the kms call"      $S '      - name: sign the digest with the release key\n.*?(      - name: assemble)' '\1'                      'kms-sign'
mut "stage-sign sign-tag skips the aws CLI"       $S '      - name: install the aws CLI[^\n]*\n        run: [^\n]*\n' ''                                      'steps must be exactly'
mut "stage-sign sign-tag assembles before it signs" $S '(      - name: sign the digest with the release key\n.*?)(      - name: assemble the signed tag object\n        run: [^\n]*\n)' '\2\1' 'steps must be exactly'
mut "stage-sign sign-tag signs another tagger's tag" $S "fosterstack release <release@users.noreply.github.com>" 'Someone <s@example.com>'                 'release tagger'
mut "stage-sign sign-tag uploads nothing"         $S '      - uses: actions/upload-artifact@[^\n]*\n        with:\n          name: signed-tag\n          path: signed-tag\n' '' 'steps must be exactly'
mut "stage-sign sign-tag downloads another artifact than decide uploads" $S '(          name: )tag-request\n          path: tag-request\n' '\1other\n          path: tag-request\n' 'must download the one artifact decide uploads'
mut "stage-sign sign-tag checkout keeps credentials" $S '          persist-credentials: false'                      '          persist-credentials: true'            'persist-credentials: false'
mut "stage-sign sign-tag uses an unpinned action" $S '(      - uses: )actions/checkout@[^\n]*'                    '\1actions/checkout@v4'                     'only pinned'
mut "another job runs the tag signer"             $R '(  patch-notes:.*?      - run: \|\n)'                     '\1          python3 bin/tag-sign.py prepare\n'    'only stage-sign.yml'
# the policy lists
mut "id-token-jobs.json lacks release.yml sign-tag" .github/policy/id-token-jobs.json ', \{"workflow": "release.yml", "job": "sign-tag"\}' '' 'release.yml:sign-tag'
mut "id-token-jobs.json lacks stage-sign.yml sign-tag" .github/policy/id-token-jobs.json ', \{"workflow": "stage-sign.yml", "job": "sign-tag"\}' '' 'stage-sign.yml:sign-tag'
mut "id-token-jobs.json lists cut"                .github/policy/id-token-jobs.json '\{"workflow": "release.yml", "job": "sign"\}' '{"workflow": "release.yml", "job": "cut"}' 'release.yml:cut'
mut "chain-scripts.json holds another sha256 for tag-sign.py" .github/policy/chain-scripts.json '"sha256": "[0-9a-f]{8}' '"sha256": "00000000' 'chain-scripts.json'
# ---- the real repository ------------------------------------------------------------------------------------------------------------
out=$(python3 "$work/judge.py" "$root" 2>&1) && ok "the real release.yml, stage-sign.yml and policy lists carry the tag jobs as the rules say" || {
  n=0; while IFS= read -r l; do n=$((n + 1)); bad "real repository: $l"; done < <(tr ';' '\n' <<< "$out" | sed 's/^ //'); [ "$n" -gt 0 ] || bad "real repository: $out"; }
echo "pass=$pass fail=$failn"
[ "$failn" = 0 ]
