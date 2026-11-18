import hashlib, json, os, re, sys, yaml

SHA = r"[0-9a-f]{40}"
ROLE = "arn:aws:iam::821302803867:role/fosterstack-cache-release-signing"
KEY_REF = "awskms:///alias/fosterstack-release-signing"
TAGGER = "fosterstack release <release@users.noreply.github.com>"
APP_TOKEN = re.compile(r"actions/create-github-app-token@%s( #.*)?" % SHA)
KMS_RUN = "bash bin/tag-sign-kms.sh"
# the run: lines of sign-tag, each exactly (the workflow is judged against these texts, so no other command can ride in a step)
RUN_KINDS = {
    "bash bin/install-scanner.sh aws-cli": "aws",
    "bash bin/tag-sign-prepare.sh": "prepare",
    KMS_RUN: "kms",
    "python3 -I bin/tag-sign.py assemble --object tag-work/tag.object --signature tag-work/tag.sig "
    "--signer-file .github/policy/release_tag_signer --out tag-work/tag.signed": "assemble",
}
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


def sign_tag_errors(sjobs):
    """the faults of job sign-tag of stage-sign.yml read alone: the one judge of this job, also called by chain-test-signers.py stage_grammar"""
    bad = []
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
        if u_.startswith("actions/checkout@") and (st.get("with") or {}).get("persist-credentials") not in (False, "false"):
            bad.append("sign-tag's checkout must say persist-credentials: false")
    runs = [str(st.get("run", "")) for st in sst if "run" in st]
    kinds = []
    for st in sst:
        r_ = st.get("run")
        if "uses" in st:
            kinds.append(str(st["uses"]).split("@")[0].split("/")[1])
        else:
            kinds.append(RUN_KINDS.get(r_, "other:" + str(r_)[:40]))
    if kinds != ["checkout", "download-artifact", "aws", "prepare", "kms", "assemble", "upload-artifact"]:
        bad.append("sign-tag's steps must be exactly: checkout, download of the tag request, install of the aws CLI (bash bin/install-scanner.sh aws-cli), tag-sign.py prepare, "
                   "bash bin/tag-sign-kms.sh, tag-sign.py assemble, one upload; found %s" % kinds)
    for st in sst:
        if st.get("run") == KMS_RUN and st.get("env") != {"AWS_ROLE_ARN": ROLE, "AWS_REGION": "us-east-1", "RELEASE_KMS_KEY_REF": KEY_REF}:
            bad.append("the kms-sign step's env must be exactly the release role, region and key reference as literals: %s" % st.get("env"))
        if "${{" in str(st.get("run", "")):
            bad.append("a sign-tag step puts an expression into its script (use env)")
    return bad


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
    bad += sign_tag_errors(sjobs)
    s = sjobs["sign-tag"]
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
